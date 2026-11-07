// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! `gorse exposure` — if this laptop were compromised, what could an
//! attacker reach?
//!
//! Pipeline: discover credentials (read-only, metadata only) → optionally
//! verify identities and permissions with read-only provider queries →
//! assemble a permission graph with declared infrastructure → search for
//! multi-hop paths from the laptop → score → report.

pub mod config;
pub mod discover;
pub mod parsers;
mod register;
pub mod report;
pub mod verify;

use config::Declarations;
pub use discover::CoverageFailure;
use discover::{Context, Discovered};
use hedgehog_taint::authority::graph::PathOutcome;
use hedgehog_taint::authority::graph::{EdgeKind, NodeId, NodeKind, PermissionGraph};
use hedgehog_taint::authority::scoring::{
    self, ExposureFinding, ExposureSummary, PathSummary, Severity,
};
use hedgehog_taint::authority::{eip7702, psbt, Assurance, Persistence};
use hedgehog_taint::tier::Tier;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
pub use verify::{Verification, VerificationStatus};

/// Everything the reports need.
pub struct ExposureReport {
    pub findings: Vec<ExposureFinding>,
    pub summary: ExposureSummary,
    pub graph: PermissionGraph,
    pub laptop: NodeId,
    /// Compromised-laptop simulation: the strongest thing reachable at each
    /// node, using only edges that exist, without exercising any of them.
    pub reachable: Vec<PathSummary>,
    pub blockchain: Vec<BlockchainFinding>,
    pub notes: Vec<String>,
    pub verified: bool,
    pub declarations_path: PathBuf,
    pub declarations_loaded: bool,
    /// The verified-report stamp. Present only for a `--verify` run made
    /// under a Pro or Team licence; never carries secret material.
    pub attestation: Option<Attestation>,
    /// Known credential locations that exist but could not be read or
    /// parsed. A non-empty list
    /// means the findings may be missing something: the check is
    /// incomplete, not clean.
    pub coverage_failures: Vec<CoverageFailure>,
    /// `coverage_failures` is not empty. Change detection never treats an
    /// incomplete run as a new baseline or reports its gaps as resolved.
    pub incomplete: bool,
    /// Per finding, in the same order as `findings`: which discovery
    /// procedure found it and what the provider check said.
    pub finding_meta: Vec<FindingMeta>,
    /// Discovery procedures that ran to completion (ids from
    /// [`discover::SOURCES`]).
    pub sources_assessed: Vec<String>,
    /// Procedures that did not run to completion, with why.
    pub sources_unavailable: Vec<(String, String)>,
    /// Set when the run was recorded in the history (`--record`): the
    /// comparison with the last complete run. Its lost coverage is already
    /// folded into `coverage_failures` and `incomplete`.
    pub record: Option<RecordInfo>,
}

/// What recording a run in the history added to its report.
#[derive(Debug, Clone)]
pub struct RecordInfo {
    /// RFC 3339 UTC time the run was recorded.
    pub recorded_at: String,
    /// `manual` or `scheduled`.
    pub trigger: String,
    /// The comparison with the baseline, including previous findings this
    /// run did not assess.
    pub changes: crate::schedule::Changes,
}

/// Where and how to record a run while finishing its report.
pub struct RecordTarget<'a> {
    /// The exposure state directory (history, status.json, schedule.json).
    pub exposure_dir: &'a Path,
    pub trigger: crate::schedule::Trigger,
    /// Send a desktop notification when something is new or worse.
    pub notify: bool,
}

/// Finish a report so text, JSON and HTML all render the same final
/// document, in this order:
///
/// 1. when recording, compare the run with the history; a source the
///    baseline assessed and this run did not adds a coverage failure,
///    makes the run incomplete and lists the previous findings as not
///    assessed;
/// 2. stamp it (`attestor`, verified runs only), computing the checksum
///    last, over the report as it will be emitted;
/// 3. when recording, store exactly that document in the history.
///
/// Returns the rendered JSON (the emitted document) and the recording
/// error, if any. A recording failure leaves the report unrecorded, never
/// fails the check.
pub fn finalize(
    report: &mut ExposureReport,
    record: Option<RecordTarget<'_>>,
    attestor: Option<&Attestor>,
) -> (serde_json::Value, Option<String>) {
    let mut error = None;
    let pending = record.as_ref().and_then(|target| {
        match crate::schedule::begin_record(
            target.exposure_dir,
            &report::render_json(report),
            target.trigger,
        ) {
            Ok(p) => Some(p),
            Err(e) => {
                error = Some(e);
                None
            }
        }
    });
    if let Some(p) = &pending {
        report
            .coverage_failures
            .extend(p.changes.unassessed_failures.iter().cloned());
        report.incomplete |= p.changes.incomplete || !report.coverage_failures.is_empty();
        report.record = Some(RecordInfo {
            recorded_at: p.at.clone(),
            trigger: p.trigger.label().to_string(),
            changes: p.changes.clone(),
        });
    }
    if let Some(attestor) = attestor {
        attest(report, attestor);
    }
    let mut value = report::render_json(report);
    if let (Some(p), Some(target)) = (pending, record) {
        if let Err(e) = crate::schedule::finish_record(p, &value, target.notify) {
            // The run is not in the history: it must not claim to be
            // recorded, so `recorded_at` and `trigger` go. The comparison
            // stays: previous findings this run did not assess are still
            // not assessed, and the run is still incomplete. Say why, and
            // recompute the checksum over the document actually emitted.
            if let Some(info) = report.record.as_mut() {
                info.recorded_at.clear();
                info.trigger.clear();
            }
            report
                .notes
                .push(format!("this run could not be saved to history: {e}"));
            value = unrecorded_json(report);
            error = Some(e);
        }
    } else if let Some(e) = &error {
        report
            .notes
            .push(format!("this run could not be saved to history: {e}"));
        restamp(report);
        value = report::render_json(report);
    }
    (value, error)
}

/// The emitted document of a run whose recording failed after the
/// comparison was made: the report with its `changes` but without
/// `recorded_at` and `trigger`, the checksum recomputed over exactly that.
fn unrecorded_json(report: &mut ExposureReport) -> serde_json::Value {
    let render = |report: &ExposureReport| {
        let mut value = report::render_json(report);
        if let Some(object) = value.as_object_mut() {
            object.remove("recorded_at");
            object.remove("trigger");
        }
        value
    };
    if report.attestation.is_some() {
        let digest = digest_of_json(render(report));
        if let Some(stamp) = report.attestation.as_mut() {
            stamp.digest = digest;
        }
    }
    render(report)
}

/// Recompute the checksum of an already stamped report after a late
/// change, keeping the holder, machine and time.
fn restamp(report: &mut ExposureReport) {
    if report.attestation.is_none() {
        return;
    }
    let digest = report_digest(report);
    if let Some(stamp) = report.attestation.as_mut() {
        stamp.digest = digest;
    }
}

/// What the report knows about a finding beyond the scored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingMeta {
    /// Stable id of the discovery procedure that found it.
    pub source: String,
    pub verification: Verification,
}

/// How many findings each verification outcome covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerificationCounts {
    pub identity_confirmed: usize,
    pub permission_confirmed: usize,
    pub local_config: usize,
    pub failed: usize,
    pub unsupported: usize,
    pub not_attempted: usize,
}

impl ExposureReport {
    pub fn verification_counts(&self) -> VerificationCounts {
        let mut c = VerificationCounts::default();
        for m in &self.finding_meta {
            match m.verification.status {
                VerificationStatus::IdentityConfirmed => c.identity_confirmed += 1,
                VerificationStatus::PermissionConfirmed => c.permission_confirmed += 1,
                VerificationStatus::LocalConfig => c.local_config += 1,
                VerificationStatus::Failed => c.failed += 1,
                VerificationStatus::Unsupported => c.unsupported += 1,
                VerificationStatus::NotAttempted => c.not_attempted += 1,
            }
        }
        c
    }
}

/// The verified-report stamp: who ran the verification, on which machine,
/// when, and a checksum of the report together with those three fields.
///
/// The checksum detects accidental or careless edits to the findings or to
/// the stamp. It is not a cryptographic signature: anyone can recompute it
/// after editing, so it does not prove who produced the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Licence holder (the email on the lease).
    pub holder: String,
    /// Gorse's machine fingerprint for the laptop that was checked.
    pub machine: String,
    /// RFC 3339 UTC time the verified run completed.
    pub verified_at: String,
    /// `sha256:` + hex SHA-256 checksum of the report and its stamp; see
    /// [`report_digest`] for exactly what it covers.
    pub digest: String,
}

/// Who a verified run is attributed to: taken from the active lease by the
/// caller (CLI or MCP) once the Pro gate has passed.
#[derive(Debug, Clone)]
pub struct Attestor {
    pub holder: String,
    pub machine: String,
}

/// The message shown when `--verify` is requested without a Pro or Team
/// licence. Exact wording is user-facing and tested.
pub const VERIFY_REQUIRES_PRO: &str = "Remote verification is part of Gorse Pro. Get a key at https://www.gorse.is/pricing then run `gorse activate <key>`. The report without --verify is free and unchanged.";

/// `--verify` is a Pro feature. Everything else in the exposure check is
/// free; only the remote, read-only permission confirmation and the stamp
/// that comes with it need a licence.
pub fn verify_allowed(tier: Tier) -> Result<(), String> {
    if tier >= Tier::Pro {
        Ok(())
    } else {
        Err(VERIFY_REQUIRES_PRO.to_string())
    }
}

/// Integrity checksum of the report and its stamp: `sha256:` + hex SHA-256
/// of the compact JSON from [`report::render_json`] (the document exactly as
/// emitted, including `changes`, `recorded_at` and `trigger` for a recorded
/// run) with the top-level `generated_at` member and the
/// `attestation.digest` member removed. It is computed last, once every
/// other field is in place (see [`finalize`]).
/// `attestation.holder`, `attestation.machine` and `attestation.verified_at`
/// stay in, so editing any of them changes the checksum. serde_json sorts
/// object keys, so the compact form is canonical and a reader can recompute
/// it from the JSON report alone with the same recipe. `generated_at` is
/// excluded because it is the clock at render time, not part of what was
/// found or stamped.
///
/// This is a checksum, not a signature: it catches accidental or careless
/// edits and nothing more.
pub fn report_digest(report: &ExposureReport) -> String {
    digest_of_json(report::render_json(report))
}

/// The recipe behind [`report_digest`], applied to an already rendered JSON
/// document. Shared with the tests so the documented recipe is the one used.
pub fn digest_of_json(mut body: serde_json::Value) -> String {
    if let Some(object) = body.as_object_mut() {
        object.remove("generated_at");
        // Set later by `gorse schedule accept-baseline`, a local decision
        // about the history, not part of the check result.
        object.remove("accepted_by_user");
        if let Some(stamp) = object
            .get_mut("attestation")
            .and_then(|a| a.as_object_mut())
        {
            stamp.remove("digest");
        }
    }
    format!("sha256:{:x}", Sha256::digest(body.to_string().as_bytes()))
}

/// Stamp a verified report: record the holder, machine and time, then
/// compute the checksum over the report including those three fields.
/// Call it last: anything added to the report afterwards breaks the
/// checksum. [`finalize`] does that in the right order.
pub fn attest(report: &mut ExposureReport, attestor: &Attestor) {
    report.attestation = Some(Attestation {
        holder: attestor.holder.clone(),
        machine: attestor.machine.clone(),
        verified_at: chrono::Utc::now().to_rfc3339(),
        digest: String::new(),
    });
    let digest = report_digest(report);
    if let Some(stamp) = report.attestation.as_mut() {
        stamp.digest = digest;
    }
}

/// A wallet-level finding (delegation state, PSBT policy, signer policy).
#[derive(Debug, Clone)]
pub struct BlockchainFinding {
    pub wallet: String,
    pub chain: String,
    pub title: String,
    pub severity: Severity,
    pub assurance: Assurance,
    pub persistence: Persistence,
    pub details: Vec<String>,
    pub dangerous: bool,
}

pub struct Options {
    pub verify: bool,
    pub declarations: Option<PathBuf>,
    pub max_hops: Option<usize>,
}

pub fn run(opts: &Options) -> Result<ExposureReport, String> {
    let decl_path = opts
        .declarations
        .clone()
        .unwrap_or_else(Declarations::default_path);
    let declarations_loaded = decl_path.exists();
    let decl = Declarations::load(&decl_path)?;
    if opts.verify && !decl.settings.allow_remote_verification {
        return Err(
            "remote verification is disabled by authority.toml (allow_remote_verification = false)"
                .into(),
        );
    }
    let mut ctx = Context::from_process(&decl);
    let (tagged, sources) = discover::discover_sources(&mut ctx);
    let (mut discovered, source_of): (Vec<Discovered>, Vec<String>) = tagged
        .into_iter()
        .map(|(d, id)| (d, id.to_string()))
        .unzip();
    let mut notes = std::mem::take(&mut ctx.notes);
    let mut coverage_failures = std::mem::take(&mut ctx.coverage_failures);

    let verifications = if opts.verify {
        let outcome = verify::verify_all(&mut discovered, &decl, &ctx.env);
        notes.extend(outcome.notes);
        outcome.verifications
    } else {
        notes.push("local discovery only: permissions marked 'inferred' have not been checked with the provider. Run with --verify to confirm (read-only).".into());
        vec![Verification::not_attempted(); discovered.len()]
    };

    let max_hops = opts.max_hops.unwrap_or(decl.settings.max_hops).clamp(1, 12);
    let (graph, laptop, cred_nodes) = build_graph(&discovered, &decl);

    let mut findings = Vec::new();
    let mut finding_meta = Vec::new();
    for (((d, node), source), verification) in discovered
        .iter()
        .zip(cred_nodes.iter())
        .zip(source_of)
        .zip(verifications)
    {
        finding_meta.push(FindingMeta {
            source,
            verification,
        });
        // Paths from this credential to anything interesting, worst first.
        let mut paths = Vec::new();
        for kind in [
            NodeKind::Wallet,
            NodeKind::FinancialAsset,
            NodeKind::Signer,
            NodeKind::SecretsManager,
            NodeKind::ProductionService,
            NodeKind::Cluster,
            NodeKind::CiSystem,
            NodeKind::Registry,
            NodeKind::Repository,
            NodeKind::CloudRole,
            NodeKind::Other,
        ] {
            let mut found = graph.paths_to_kind(*node, kind, max_hops);
            // Keep the best path per target so the report stays readable.
            found.dedup_by(|a, b| a.target() == b.target());
            paths.extend(found);
        }
        findings.push(scoring::score_finding(&graph, &d.credential, &paths));
    }
    let mut paired: Vec<(ExposureFinding, FindingMeta)> =
        findings.into_iter().zip(finding_meta).collect();
    paired.sort_by(|(a, _), (b, _)| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.credential.name.cmp(&b.credential.name))
    });
    let (findings, finding_meta): (Vec<_>, Vec<_>) = paired.into_iter().unzip();

    let reachable = max_reachable_authority(&graph, laptop, max_hops + 1);
    let blockchain =
        blockchain_findings(&decl, &ctx, opts.verify, &mut notes, &mut coverage_failures);
    let dangerous = blockchain.iter().filter(|b| b.dangerous).count();
    let summary = scoring::summarize(&findings, dangerous);

    let report = ExposureReport {
        findings,
        summary,
        graph,
        laptop,
        reachable,
        blockchain,
        notes,
        verified: opts.verify,
        declarations_path: decl_path,
        declarations_loaded,
        attestation: None,
        incomplete: !coverage_failures.is_empty(),
        coverage_failures,
        finding_meta,
        sources_assessed: sources.assessed,
        sources_unavailable: sources.unavailable,
        record: None,
    };
    Ok(report)
}

/// The compromised-laptop simulation. For every node reachable from the
/// laptop, keep the best path (strongest outcome, fewest approval gates,
/// strongest assurance, shortest) and drop anything that is mere possession
/// or reachability of a non-financial system. Sorted worst first.
pub fn max_reachable_authority(
    graph: &PermissionGraph,
    laptop: NodeId,
    max_hops: usize,
) -> Vec<PathSummary> {
    let reach = graph.reachability(laptop, max_hops);
    let mut out: Vec<PathSummary> = reach
        .best_paths
        .values()
        .filter(|p| graph.get(p.target()).kind != NodeKind::Credential)
        .filter(|p| {
            let target = graph.get(p.target());
            p.outcome >= PathOutcome::Read || target.kind.is_financial() || target.production
        })
        .map(|p| scoring::summarize_path(graph, p))
        .collect();
    out.sort_by(|a, b| {
        b.outcome
            .cmp(&a.outcome)
            .then_with(|| a.approvals_required.len().cmp(&b.approvals_required.len()))
            .then_with(|| a.assurance.cmp(&b.assurance))
            .then_with(|| a.hops.cmp(&b.hops))
    });
    out
}

/// Build the graph: laptop → credentials → systems, plus declared topology.
pub fn build_graph(
    discovered: &[Discovered],
    decl: &Declarations,
) -> (PermissionGraph, NodeId, Vec<NodeId>) {
    let mut g = PermissionGraph::new();
    let laptop = g.node(NodeKind::Laptop, "this laptop");
    let mut cred_nodes = Vec::new();

    // Declared infrastructure first so discovered links attach to it.
    for system in &decl.production_systems {
        let kind = system_kind(&system.kind);
        let id = g.node(kind, &system.name);
        g.mark_production(id);
        for target in &system.deploys_to {
            let t_kind = decl
                .production_systems
                .iter()
                .find(|s| &s.name == target)
                .map(|s| system_kind(&s.kind))
                .unwrap_or(NodeKind::ProductionService);
            let t = g.node(t_kind, target);
            g.mark_production(t);
            g.edge_full(
                id,
                t,
                EdgeKind::CanDeploy,
                Assurance::Inferred,
                None,
                vec![format!("declared: {} deploys to {target}", system.name)],
                system.change_approval.clone(),
            );
        }
        for signer_name in &system.reaches {
            let s = g.node(NodeKind::Signer, signer_name);
            g.mark_production(s);
            let approval = decl.signer(signer_name).and_then(|sg| {
                if sg.requires_independent_approval {
                    sg.approval
                        .clone()
                        .or_else(|| Some("independent approval (declared)".into()))
                } else {
                    None
                }
            });
            g.edge_full(
                id,
                s,
                EdgeKind::CanRequestSignature,
                Assurance::Inferred,
                None,
                vec![format!("declared: {} reaches {signer_name}", system.name)],
                None,
            );
            let _ = approval;
        }
    }
    for signer in &decl.signers {
        let s = g.node(NodeKind::Signer, &signer.name);
        g.mark_production(s);
        g.note(
            s,
            &format!(
                "{} signer; policy enforcement: {}",
                signer.kind,
                if signer.enforces_transaction_policy {
                    "yes"
                } else {
                    "no"
                }
            ),
        );
        let quorum_here = matches!((signer.threshold, signer.approvers_on_this_laptop), (Some(t), Some(h)) if h >= t);
        let approval = if signer.requires_independent_approval && !quorum_here {
            signer
                .approval
                .clone()
                .or_else(|| Some("independent approval (declared)".into()))
        } else {
            None
        };
        for wallet_name in &signer.wallets {
            let w = g.node(NodeKind::Wallet, wallet_name);
            if decl
                .wallet(wallet_name)
                .map(|w| w.production)
                .unwrap_or(true)
            {
                g.mark_production(w);
            }
            let mut evidence = vec![format!(
                "declared: {} controls wallet {wallet_name}",
                signer.name
            )];
            if quorum_here {
                evidence.push(
                    "quorum of approvers is on this laptop: approval is not independent".into(),
                );
            }
            if !signer.enforces_transaction_policy {
                evidence.push("signer does not enforce a transaction policy".into());
            }
            // A signer that signs whatever it is handed moves funds on request;
            // one with an independent approval gate only moves them after it.
            g.edge_full(
                s,
                w,
                EdgeKind::CanTransferAssets,
                Assurance::Inferred,
                None,
                evidence,
                approval.clone(),
            );
        }
        for dep in &signer.shared_dependencies {
            let d = g.node(NodeKind::Signer, dep);
            g.edge_full(
                d,
                s,
                EdgeKind::CanChangeSigningPolicy,
                Assurance::Inferred,
                None,
                vec![format!("declared: {} depends on {dep}", signer.name)],
                None,
            );
        }
    }
    for wallet in &decl.wallets {
        let w = g.node(NodeKind::Wallet, &wallet.name);
        if wallet.production {
            g.mark_production(w);
        }
        if let Some(addr) = &wallet.address {
            g.note(w, &format!("{} {}", wallet.chain, addr));
        }
    }

    // Discovered credentials.
    for d in discovered {
        let label = format!("{} ({})", d.credential.name, d.credential.kind.label());
        let c = g.node(NodeKind::Credential, &label);
        for ev in &d.credential.evidence {
            g.note(c, ev);
        }
        let possession = if d.credential.permissions.lifetime.is_expired() {
            Assurance::Confirmed
        } else {
            Assurance::Confirmed
        };
        g.edge_full(
            laptop,
            c,
            EdgeKind::CanAuthenticate,
            possession,
            None,
            vec![format!("found at {}", d.credential.location)],
            None,
        );
        for link in &d.links {
            let t = g.node(link.kind, &link.name);
            if link.production {
                g.mark_production(t);
            }
            g.edge_full(
                c,
                t,
                link.edge,
                link.assurance,
                link.scope.clone(),
                link.evidence.clone(),
                link.approval.clone(),
            );
        }
        cred_nodes.push(c);
    }
    (g, laptop, cred_nodes)
}

fn system_kind(kind: &str) -> NodeKind {
    match kind {
        "cluster" => NodeKind::Cluster,
        "ci" => NodeKind::CiSystem,
        "secrets_manager" => NodeKind::SecretsManager,
        "registry" => NodeKind::Registry,
        "repository" => NodeKind::Repository,
        _ => NodeKind::ProductionService,
    }
}

/// Wallet-level checks: EIP-7702 delegation state, Bitcoin PSBT policy,
/// signer 7702 policy.
fn blockchain_findings(
    decl: &Declarations,
    ctx: &Context,
    verify: bool,
    notes: &mut Vec<String>,
    coverage_failures: &mut Vec<CoverageFailure>,
) -> Vec<BlockchainFinding> {
    let mut out = Vec::new();
    for wallet in &decl.wallets {
        // Chain names are compared case-insensitively ("Bitcoin", "ETHEREUM").
        match wallet.chain.trim().to_ascii_lowercase().as_str() {
            "ethereum" => {
                let Some(addr_hex) = &wallet.address else {
                    continue;
                };
                let Ok(addr_bytes) = eip7702::decode_hex(addr_hex) else {
                    notes.push(format!("wallet {}: address is not valid hex", wallet.name));
                    continue;
                };
                if addr_bytes.len() != 20 {
                    notes.push(format!("wallet {}: address must be 20 bytes", wallet.name));
                    continue;
                }
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&addr_bytes);
                let mut registry = eip7702::DelegateRegistry::new();
                for a in &wallet.approved_delegates {
                    if registry.add_approved_hex(a).is_err() {
                        notes.push(format!(
                            "wallet {}: approved delegate {a} is not a valid address",
                            wallet.name
                        ));
                    }
                }
                for a in &wallet.malicious_delegates {
                    let _ = registry.add_malicious_hex(a);
                }
                let code: Option<Vec<u8>> = if verify {
                    match wallet.rpc_url_env.as_deref().and_then(|v| ctx.env.get(v)) {
                        Some(url) => match verify::eth_get_code(url, addr_hex) {
                            Ok(code) => Some(code),
                            Err(e) => {
                                notes.push(format!(
                                    "wallet {}: eth_getCode failed: {e}",
                                    wallet.name
                                ));
                                None
                            }
                        },
                        None => {
                            notes.push(format!("wallet {}: no RPC URL (set rpc_url_env) so delegation state was not checked", wallet.name));
                            None
                        }
                    }
                } else {
                    None
                };
                let assessment = eip7702::assess_delegation(addr, code.as_deref(), &registry);
                let dangerous = matches!(
                    assessment.state.status,
                    eip7702::DelegationStatus::Delegated
                ) && assessment.trust != Some(eip7702::DelegateTrust::Approved);
                let mut details = assessment.reasons.clone();
                if let Some(d) = assessment.state.delegate_hex() {
                    details.push(format!("delegate: {d}"));
                }
                out.push(BlockchainFinding {
                    wallet: wallet.name.clone(),
                    chain: "ethereum".into(),
                    title: match assessment.state.status {
                        eip7702::DelegationStatus::Delegated => {
                            "EIP-7702 delegation installed".into()
                        }
                        eip7702::DelegationStatus::None => "no EIP-7702 delegation".into(),
                        eip7702::DelegationStatus::NotDelegationCode => {
                            "account has contract code".into()
                        }
                        eip7702::DelegationStatus::Unknown => {
                            "EIP-7702 delegation not checked".into()
                        }
                    },
                    severity: assessment.severity,
                    assurance: if code.is_some() {
                        Assurance::Confirmed
                    } else {
                        Assurance::Unknown
                    },
                    persistence: assessment.persistence,
                    details,
                    dangerous,
                });
            }
            "bitcoin" => {
                let Some(policy_cfg) = &wallet.bitcoin_policy else {
                    // A declared PSBT is still read and parsed without a
                    // policy: one that cannot be is lost coverage.
                    if let Some(file) = &wallet.psbt_file {
                        let path = ctx.expand(file);
                        let checked = match std::fs::read_to_string(&path) {
                            Ok(text) => psbt::parse_psbt(text.trim())
                                .map_err(|e| format!("PSBT not parsed: {e:?}")),
                            Err(e) => Err(format!("PSBT file unreadable: {e}")),
                        };
                        match checked {
                            Ok(parsed) => notes.push(format!(
                                "wallet {}: PSBT {file} read ({} input(s), {} output(s)); no [wallet.bitcoin_policy] is declared, so it was not evaluated against a policy",
                                wallet.name,
                                parsed.inputs.len(),
                                parsed.outputs.len()
                            )),
                            Err(reason) => {
                                notes.push(format!("wallet {}: {reason}", wallet.name));
                                coverage_failures.push(CoverageFailure {
                                    location: ctx.display(&path),
                                    reason,
                                });
                            }
                        }
                    }
                    continue;
                };
                let policy = psbt::SigningPolicy {
                    allowed_destinations: policy_cfg.allowed_destinations.clone(),
                    max_fee_sats: policy_cfg.max_fee_sats,
                    max_fee_rate_sat_vb: policy_cfg.max_fee_rate_sat_vb,
                    max_withdrawal_sats: policy_cfg.max_withdrawal_sats,
                    require_change_validation: policy_cfg.require_change_validation,
                    require_independent_output_verification: policy_cfg
                        .require_independent_output_verification,
                    independent_verification_available: policy_cfg
                        .independent_verification_available,
                };
                let network = match policy_cfg.network.trim().to_ascii_lowercase().as_str() {
                    "testnet" => psbt::Network::Testnet,
                    "signet" => psbt::Network::Signet,
                    "regtest" => psbt::Network::Regtest,
                    _ => psbt::Network::Mainnet,
                };
                // A declared PSBT that cannot be read or parsed is lost
                // coverage: the wallet gets only the static signer-policy
                // assessment, labelled as such, never "satisfied".
                let mut psbt_not_assessed = false;
                let report = match &wallet.psbt_file {
                    Some(file) => {
                        let path = ctx.expand(file);
                        let failure = match std::fs::read_to_string(&path) {
                            Ok(text) => match psbt::parse_psbt(text.trim()) {
                                Ok(parsed) => Ok((
                                    psbt::evaluate_policy(&parsed, &policy, network),
                                    format!(
                                        "PSBT {}: {} input(s), {} output(s)",
                                        file,
                                        parsed.inputs.len(),
                                        parsed.outputs.len()
                                    ),
                                )),
                                Err(e) => Err(format!("PSBT not parsed: {e:?}")),
                            },
                            Err(e) => Err(format!("PSBT file unreadable: {e}")),
                        };
                        match failure {
                            Ok(r) => Some(r),
                            Err(reason) => {
                                notes.push(format!("wallet {}: {reason}", wallet.name));
                                coverage_failures.push(CoverageFailure {
                                    location: ctx.display(&path),
                                    reason,
                                });
                                psbt_not_assessed = true;
                                None
                            }
                        }
                    }
                    None => None,
                };
                let (report, context) = match report {
                    Some(r) => r,
                    None if psbt_not_assessed => (
                        psbt::assess_signer_policy(&policy),
                        format!(
                            "PSBT not assessed: {} could not be read or parsed; static signer policy only",
                            wallet.psbt_file.as_deref().unwrap_or_default()
                        ),
                    ),
                    None => (
                        psbt::assess_signer_policy(&policy),
                        "signer policy (no PSBT supplied)".to_string(),
                    ),
                };
                let severity = report.severity.unwrap_or(Severity::Low);
                let mut details = vec![context];
                for f in &report.findings {
                    details.push(format!("{}: {}", f.violation.label(), f.detail));
                }
                if let Some(fee) = report.fee_sats {
                    details.push(format!(
                        "fee {fee} sats; external outputs {} sats; change {} sats",
                        report.external_outputs_sats, report.change_outputs_sats
                    ));
                }
                out.push(BlockchainFinding {
                    wallet: wallet.name.clone(),
                    chain: "bitcoin".into(),
                    title: match (psbt_not_assessed, report.findings.is_empty()) {
                        (true, true) => "Bitcoin signer policy only (PSBT not assessed)".into(),
                        (true, false) => {
                            "Bitcoin signer policy violations (PSBT not assessed)".into()
                        }
                        (false, true) => "Bitcoin signing policy satisfied".into(),
                        (false, false) => "Bitcoin signing policy violations".into(),
                    },
                    severity,
                    assurance: Assurance::Inferred,
                    persistence: Persistence::Unknown,
                    details,
                    dangerous: severity >= Severity::High,
                });
            }
            _ => {}
        }
    }
    for signer in &decl.signers {
        if signer.accepts_arbitrary_7702 {
            let (severity, reasons) = eip7702::assess_signing_service_7702_policy(
                true,
                signer.requires_independent_approval,
            );
            out.push(BlockchainFinding {
                wallet: signer.wallets.join(", "),
                chain: "ethereum".into(),
                title: format!("{} accepts arbitrary EIP-7702 authorizations", signer.name),
                severity,
                assurance: Assurance::Inferred,
                persistence: Persistence::Blockchain,
                details: reasons,
                dangerous: severity >= Severity::High,
            });
        }
    }
    out
}

/// Exit code: 0 clean, 1 a finding at or above the threshold, 2 could not
/// run, 3 incomplete (some known location could not be read or
/// interpreted) with nothing at or above the threshold.
pub const EXIT_INCOMPLETE: i32 = 3;

/// Exit code with the default threshold: 1 when anything is High or worse.
pub fn exit_code(report: &ExposureReport) -> i32 {
    exit_code_at(report, Severity::High)
}

/// Exit code for an integrator-chosen threshold (`--fail-on`): 1 when the
/// worst finding or blockchain authorization is at or above `threshold`,
/// otherwise 3 when the check is incomplete, otherwise 0.
pub fn exit_code_at(report: &ExposureReport, threshold: Severity) -> i32 {
    exit_code_for(report, threshold, report.incomplete)
}

/// [`exit_code_at`] with the incompleteness given by the caller: recording
/// a run can find sources a previous run assessed and this one did not.
pub fn exit_code_for(report: &ExposureReport, threshold: Severity, incomplete: bool) -> i32 {
    let worst = report
        .findings
        .iter()
        .map(|f| f.severity)
        .chain(report.blockchain.iter().map(|b| b.severity))
        .max();
    match worst {
        Some(s) if s >= threshold => 1,
        _ if incomplete => EXIT_INCOMPLETE,
        _ => 0,
    }
}

/// Parse a `--fail-on` value. Accepts the severity labels used in reports.
pub fn parse_severity(text: &str) -> Option<Severity> {
    match text.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hedgehog_taint::authority::{CredentialKind, DiscoveredCredential};

    fn report_with(names: &[&str]) -> ExposureReport {
        let decl = Declarations::default();
        let discovered: Vec<Discovered> = names
            .iter()
            .map(|name| Discovered {
                credential: DiscoveredCredential::new(
                    CredentialKind::AwsAccessKey,
                    name,
                    "~/.aws/credentials",
                    "aws",
                ),
                links: vec![],
                verify_key: None,
                source: None,
            })
            .collect();
        let (graph, laptop, cred_nodes) = build_graph(&discovered, &decl);
        let findings: Vec<_> = discovered
            .iter()
            .zip(cred_nodes.iter())
            .map(|(d, node)| {
                let paths = graph.paths_to_kind(*node, NodeKind::Other, 4);
                scoring::score_finding(&graph, &d.credential, &paths)
            })
            .collect();
        let summary = scoring::summarize(&findings, 0);
        ExposureReport {
            findings,
            summary,
            graph,
            laptop,
            reachable: vec![],
            blockchain: vec![],
            notes: vec![],
            verified: true,
            declarations_path: PathBuf::from("authority.toml"),
            declarations_loaded: false,
            attestation: None,
            coverage_failures: vec![],
            incomplete: false,
            finding_meta: vec![
                FindingMeta {
                    source: "aws-credentials-file".into(),
                    verification: Verification::not_attempted(),
                };
                names.len()
            ],
            sources_assessed: discover::SOURCES
                .iter()
                .map(|(id, _)| id.to_string())
                .collect(),
            sources_unavailable: vec![],
            record: None,
        }
    }

    #[test]
    fn verify_is_gated_on_pro() {
        let err = verify_allowed(Tier::Free).unwrap_err();
        assert_eq!(err, VERIFY_REQUIRES_PRO);
        assert!(err.contains("Gorse Pro"));
        assert!(err.contains("gorse activate <key>"));
        assert!(verify_allowed(Tier::Pro).is_ok());
        assert!(verify_allowed(Tier::Team).is_ok());
    }

    fn stamped(names: &[&str], holder: &str, machine: &str, at: &str) -> ExposureReport {
        let mut r = report_with(names);
        r.attestation = Some(Attestation {
            holder: holder.into(),
            machine: machine.into(),
            verified_at: at.into(),
            digest: String::new(),
        });
        let digest = report_digest(&r);
        r.attestation.as_mut().unwrap().digest = digest;
        r
    }

    const HOLDER: &str = "holder@example.invalid";
    const MACHINE: &str = "fixture-machine";
    const AT: &str = "2026-10-30T12:00:00+00:00";

    #[test]
    fn digest_is_stable_and_tracks_findings() {
        let a = stamped(&["default"], HOLDER, MACHINE, AT);
        let b = stamped(&["default"], HOLDER, MACHINE, AT);
        let first = a.attestation.as_ref().unwrap().digest.clone();
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), "sha256:".len() + 64);
        assert_eq!(first, report_digest(&a), "same report, same digest");
        assert_eq!(
            first,
            b.attestation.as_ref().unwrap().digest,
            "equal reports with equal stamps, same digest"
        );

        let changed = stamped(&["staging"], HOLDER, MACHINE, AT);
        assert_ne!(
            first,
            changed.attestation.unwrap().digest,
            "a changed finding changes the digest"
        );

        // `attest` fills the identity fields and then digests over them.
        let mut live = report_with(&["default"]);
        let attestor = Attestor {
            holder: HOLDER.into(),
            machine: MACHINE.into(),
        };
        attest(&mut live, &attestor);
        let stamp = live.attestation.clone().unwrap();
        assert_eq!(stamp.holder, HOLDER);
        assert_eq!(stamp.machine, MACHINE);
        assert!(chrono::DateTime::parse_from_rfc3339(&stamp.verified_at).is_ok());
        assert_eq!(
            stamp.digest,
            report_digest(&live),
            "stamp agrees with recomputation"
        );
        assert_ne!(stamp.digest, "", "digest is filled in after stamping");
    }

    #[test]
    fn digest_covers_the_stamp_identity_fields() {
        let base = stamped(&["default"], HOLDER, MACHINE, AT);
        let first = base.attestation.as_ref().unwrap().digest.clone();

        let other_holder = stamped(&["default"], "someone@example.invalid", MACHINE, AT);
        assert_ne!(
            first,
            other_holder.attestation.unwrap().digest,
            "editing the holder changes the digest"
        );
        let other_machine = stamped(&["default"], HOLDER, "another-machine", AT);
        assert_ne!(
            first,
            other_machine.attestation.unwrap().digest,
            "editing the machine changes the digest"
        );
        let other_time = stamped(&["default"], HOLDER, MACHINE, "2026-10-31T12:00:00+00:00");
        assert_ne!(
            first,
            other_time.attestation.unwrap().digest,
            "editing the verification time changes the digest"
        );

        // Editing a field in place is caught the same way.
        let mut edited = stamped(&["default"], HOLDER, MACHINE, AT);
        edited.attestation.as_mut().unwrap().holder = "forged@example.invalid".into();
        assert_ne!(report_digest(&edited), first);
    }

    #[test]
    fn digest_is_recomputable_from_rendered_json_by_the_documented_recipe() {
        let r = stamped(&["default"], HOLDER, MACHINE, AT);
        let expected = r.attestation.as_ref().unwrap().digest.clone();

        // The recipe: compact JSON, keys sorted, drop top-level `generated_at`
        // and `attestation.digest`, keep holder/machine/verified_at.
        let mut rendered = report::render_json(&r);
        let object = rendered.as_object_mut().unwrap();
        object.remove("generated_at");
        let stamp = object["attestation"].as_object_mut().unwrap();
        assert_eq!(stamp["holder"], HOLDER);
        assert_eq!(stamp["machine"], MACHINE);
        assert_eq!(stamp["verified_at"], AT);
        stamp.remove("digest");
        let recomputed = format!(
            "sha256:{:x}",
            Sha256::digest(rendered.to_string().as_bytes())
        );
        assert_eq!(recomputed, expected);
        assert_eq!(digest_of_json(report::render_json(&r)), expected);

        // Round trip through the text form a reader would actually hold.
        let text = serde_json::to_string_pretty(&report::render_json(&r)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(digest_of_json(parsed), expected);
    }

    /// The documented recipe, applied by hand to an emitted JSON document:
    /// compact, keys sorted, without `generated_at` and `attestation.digest`.
    fn recompute(emitted: &serde_json::Value) -> String {
        let text = serde_json::to_string_pretty(emitted).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let object = parsed.as_object_mut().unwrap();
        object.remove("generated_at");
        object["attestation"]
            .as_object_mut()
            .unwrap()
            .remove("digest");
        format!("sha256:{:x}", Sha256::digest(parsed.to_string().as_bytes()))
    }

    #[test]
    fn checksum_covers_the_emitted_document_with_and_without_record() {
        let attestor = Attestor {
            holder: HOLDER.into(),
            machine: MACHINE.into(),
        };

        // Without --record.
        let mut plain = report_with(&["default"]);
        let (emitted, error) = finalize(&mut plain, None, Some(&attestor));
        assert!(error.is_none());
        assert!(emitted.get("changes").is_none());
        let digest = emitted["attestation"]["digest"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(recompute(&emitted), digest);

        // With --record, twice: the second run carries a real comparison.
        let dir = std::env::temp_dir().join(format!(
            "gorse-finalize-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        for round in 0..2 {
            let mut recorded = report_with(&["default"]);
            let target = RecordTarget {
                exposure_dir: &dir,
                trigger: crate::schedule::Trigger::Manual,
                notify: false,
            };
            let (emitted, error) = finalize(&mut recorded, Some(target), Some(&attestor));
            assert!(error.is_none(), "{error:?}");
            assert!(emitted["changes"].is_object(), "{emitted}");
            assert!(emitted["recorded_at"].is_string());
            assert_eq!(emitted["changes"]["first_run"], round == 0);
            let digest = emitted["attestation"]["digest"].as_str().unwrap();
            assert_eq!(recompute(&emitted), digest, "round {round}");
            assert_eq!(digest_of_json(emitted.clone()), digest);

            // The history holds exactly the emitted document.
            let stored: Vec<_> = std::fs::read_dir(dir.join("history"))
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .collect();
            assert_eq!(stored.len(), round + 1);
            let newest = stored.iter().max().unwrap();
            let on_disk: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(newest).unwrap()).unwrap();
            assert_eq!(recompute(&on_disk), digest);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_or_unparseable_psbt_is_lost_coverage_not_satisfied() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-psbt-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let garbage = dir.join("garbage.psbt");
        std::fs::write(&garbage, "this is not a psbt\n").unwrap();
        let missing = dir.join("missing.psbt");
        for (path, reason) in [
            (&garbage, "PSBT not parsed"),
            (&missing, "PSBT file unreadable"),
        ] {
            let decl = Declarations::parse(&format!(
                "[[wallet]]\nname = \"cold\"\nchain = \"bitcoin\"\npsbt_file = \"{}\"\n[wallet.bitcoin_policy]\nallowed_destinations = [\"bc1qexample\"]\nmax_fee_sats = 1000\n",
                path.display().to_string().replace('\\', "/")
            ))
            .unwrap();
            let ctx = Context::from_process(&decl);
            let mut notes = Vec::new();
            let mut failures = Vec::new();
            let found = blockchain_findings(&decl, &ctx, false, &mut notes, &mut failures);
            assert_eq!(failures.len(), 1, "{failures:?}");
            assert!(failures[0].reason.starts_with(reason), "{failures:?}");
            assert_eq!(found.len(), 1);
            assert!(
                found[0].title.contains("PSBT not assessed"),
                "{}",
                found[0].title
            );
            assert!(!found[0].title.contains("satisfied"));
            assert!(found[0].details[0].starts_with("PSBT not assessed"));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_declared_psbt_is_checked_without_a_policy_and_chain_names_ignore_case() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-psbt-nopolicy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let garbage = dir.join("garbage.psbt");
        std::fs::write(&garbage, "this is not a psbt\n").unwrap();
        let missing = dir.join("missing.psbt");
        for (path, reason, chain) in [
            (&garbage, "PSBT not parsed", "bitcoin"),
            (&missing, "PSBT file unreadable", "Bitcoin"),
        ] {
            let decl = Declarations::parse(&format!(
                "[[wallet]]\nname = \"cold\"\nchain = \"{chain}\"\npsbt_file = \"{}\"\n",
                path.display().to_string().replace('\\', "/")
            ))
            .unwrap();
            let ctx = Context::from_process(&decl);
            let mut notes = Vec::new();
            let mut failures = Vec::new();
            let found = blockchain_findings(&decl, &ctx, false, &mut notes, &mut failures);
            assert_eq!(failures.len(), 1, "{chain}: {failures:?}");
            assert!(failures[0].reason.starts_with(reason), "{failures:?}");
            assert!(found.is_empty());
        }
        // With a policy, an upper-case chain name is still Bitcoin.
        let decl = Declarations::parse(&format!(
            "[[wallet]]\nname = \"cold\"\nchain = \"BITCOIN\"\npsbt_file = \"{}\"\n[wallet.bitcoin_policy]\nmax_fee_sats = 1000\n",
            garbage.display().to_string().replace('\\', "/")
        ))
        .unwrap();
        let ctx = Context::from_process(&decl);
        let mut failures = Vec::new();
        let found = blockchain_findings(&decl, &ctx, false, &mut Vec::new(), &mut failures);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].chain, "bitcoin");
        assert_eq!(failures.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_run_the_history_could_not_store_does_not_claim_to_be_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let attestor = Attestor {
            holder: HOLDER.into(),
            machine: MACHINE.into(),
        };
        let dir = std::env::temp_dir().join(format!(
            "gorse-finalize-ro-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let history = dir.join("history");
        std::fs::create_dir_all(&history).unwrap();
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o500)).unwrap();
        let mut r = report_with(&["default"]);
        let target = RecordTarget {
            exposure_dir: &dir,
            trigger: crate::schedule::Trigger::Manual,
            notify: false,
        };
        let (emitted, error) = finalize(&mut r, Some(target), Some(&attestor));
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        let stored = std::fs::read_dir(&history).unwrap().count();
        let _ = std::fs::remove_dir_all(&dir);
        let error = error.expect("the history write fails");
        assert_eq!(stored, 0);
        // Not recorded: no time or trigger. The comparison stays.
        for key in ["recorded_at", "trigger"] {
            assert!(emitted.get(key).is_none(), "{key} left in {emitted}");
        }
        assert!(emitted["changes"].is_object(), "{emitted}");
        let note = format!("this run could not be saved to history: {error}");
        assert!(
            emitted["notes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n.as_str() == Some(note.as_str())),
            "{emitted}"
        );
        let digest = emitted["attestation"]["digest"].as_str().unwrap();
        assert_eq!(recompute(&emitted), digest);
        assert_eq!(digest_of_json(emitted.clone()), digest);
        assert_eq!(report::render_json(&r)["attestation"]["digest"], digest);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_history_write_keeps_the_unassessed_findings_and_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        let attestor = Attestor {
            holder: HOLDER.into(),
            machine: MACHINE.into(),
        };
        let dir = std::env::temp_dir().join(format!(
            "gorse-finalize-unassessed-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let target = |dir| RecordTarget {
            exposure_dir: dir,
            trigger: crate::schedule::Trigger::Manual,
            notify: false,
        };
        let mut first = report_with(&["default"]);
        first.finding_meta[0].source = "ssh".into();
        let (_, error) = finalize(&mut first, Some(target(&dir)), None);
        assert!(error.is_none(), "{error:?}");

        // The comparison is made (begin_record succeeds), then the write
        // into the read-only history fails.
        let history = dir.join("history");
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o500)).unwrap();
        let mut second = report_with(&[]);
        second.sources_assessed.retain(|s| s != "ssh");
        second.sources_unavailable.push((
            "ssh".into(),
            "SSH agent (SSH_AUTH_SOCK): socket missing".into(),
        ));
        let (emitted, error) = finalize(&mut second, Some(target(&dir)), Some(&attestor));
        std::fs::set_permissions(&history, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(error.is_some(), "the history write fails");
        assert_eq!(emitted["incomplete"], true, "{emitted}");
        assert_eq!(emitted["changes"]["counts"]["unassessed"], 1, "{emitted}");
        for key in ["recorded_at", "trigger"] {
            assert!(emitted.get(key).is_none(), "{key} left in {emitted}");
        }
        let digest = emitted["attestation"]["digest"].as_str().unwrap();
        assert_eq!(recompute(&emitted), digest);
        assert_eq!(exit_code(&second), EXIT_INCOMPLETE);
    }

    /// The checksum recipe as docs/schema/exposure-report.v1.schema.json
    /// states it, applied by hand to a history file after
    /// `gorse schedule accept-baseline`, and to a history file from an
    /// older version that carries `accepted_by_user` itself.
    #[test]
    fn the_schema_checksum_recipe_reproduces_the_digest_after_accept_baseline() {
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("docs")
            .join("schema")
            .join("exposure-report.v1.schema.json");
        let schema_text = std::fs::read_to_string(&schema_path)
            .unwrap()
            .replace("\r\n", "\n");
        let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();
        let recipe = schema["properties"]["attestation"]["properties"]["digest"]["description"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        for member in [
            "'generated_at'",
            "'attestation.digest'",
            "'accepted_by_user'",
        ] {
            assert!(recipe.contains(member), "{member} missing from: {recipe}");
        }
        // The recipe, step by step: drop those three members, serialise
        // compactly with keys sorted, SHA-256, hex.
        let by_schema = |doc: &serde_json::Value| {
            let mut doc = doc.clone();
            let object = doc.as_object_mut().unwrap();
            object.remove("generated_at");
            object.remove("accepted_by_user");
            object["attestation"]
                .as_object_mut()
                .unwrap()
                .remove("digest");
            format!("sha256:{:x}", Sha256::digest(doc.to_string().as_bytes()))
        };

        let dir = std::env::temp_dir().join(format!(
            "gorse-accept-recipe-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let attestor = Attestor {
            holder: HOLDER.into(),
            machine: MACHINE.into(),
        };
        let mut r = report_with(&["default"]);
        let target = RecordTarget {
            exposure_dir: &dir,
            trigger: crate::schedule::Trigger::Manual,
            notify: false,
        };
        let (emitted, error) = finalize(&mut r, Some(target), Some(&attestor));
        assert!(error.is_none(), "{error:?}");
        let digest = emitted["attestation"]["digest"]
            .as_str()
            .unwrap()
            .to_string();
        let file = crate::schedule::accept_baseline_in(&dir).unwrap();
        let stored: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("history").join(&file)).unwrap(),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(by_schema(&stored), digest);
        let mut legacy = stored.clone();
        legacy["accepted_by_user"] = serde_json::json!(true);
        assert_eq!(by_schema(&legacy), digest);
        assert_eq!(digest_of_json(legacy), digest);
    }

    #[test]
    fn recording_folds_lost_coverage_into_the_rendered_report() {
        // The baseline assessed `ssh` and had an agent identity; this run
        // did not assess `ssh` (the agent did not answer). The final
        // report is incomplete and lists the identity as not assessed, in
        // JSON, text and HTML alike.
        let dir = std::env::temp_dir().join(format!(
            "gorse-finalize-lost-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut first = report_with(&["default"]);
        first.finding_meta[0].source = "ssh".into();
        let target = |dir| RecordTarget {
            exposure_dir: dir,
            trigger: crate::schedule::Trigger::Manual,
            notify: false,
        };
        let (_, error) = finalize(&mut first, Some(target(&dir)), None);
        assert!(error.is_none());

        let mut second = report_with(&[]);
        second.sources_assessed.retain(|s| s != "ssh");
        second.sources_unavailable.push((
            "ssh".into(),
            "SSH agent (SSH_AUTH_SOCK): socket missing".into(),
        ));
        let (emitted, error) = finalize(&mut second, Some(target(&dir)), None);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(error.is_none());
        assert!(second.incomplete);
        assert_eq!(emitted["incomplete"], true);
        assert_eq!(emitted["changes"]["counts"]["unassessed"], 1);
        assert_eq!(exit_code(&second), EXIT_INCOMPLETE);
        let html = report::render_html(&second);
        assert!(html.contains("Incomplete:"), "{html}");
        assert!(html.contains("Not assessed in this run (1)"), "{html}");
        let text = report::render_text(&second, false);
        assert!(text.contains("Not assessed in this run"), "{text}");
    }

    #[test]
    fn map_opt_out_blocks_verify_before_any_discovery() {
        let dir = std::env::temp_dir().join(format!(
            "hedgehog-exposure-unit-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let map = dir.join("authority.toml");
        std::fs::write(&map, "[settings]\nallow_remote_verification = false\n").unwrap();

        let refused = run(&Options {
            verify: true,
            declarations: Some(map),
            max_hops: Some(2),
        })
        .err()
        .expect("opt-out must refuse verify");
        assert!(refused.contains("disabled"), "{refused}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn exit_code_three_means_incomplete_below_the_threshold() {
        let mut r = report_with(&[]);
        assert_eq!(exit_code(&r), 0);
        r.incomplete = true;
        assert_eq!(exit_code(&r), EXIT_INCOMPLETE);
        let mut found = report_with(&["default"]);
        found.incomplete = true;
        let worst = found.findings[0].severity;
        assert_eq!(
            exit_code_at(&found, worst),
            1,
            "a finding at the threshold wins"
        );
        assert_eq!(
            exit_code_for(&found, Severity::Critical, false),
            if worst >= Severity::Critical { 1 } else { 0 }
        );
    }
}
