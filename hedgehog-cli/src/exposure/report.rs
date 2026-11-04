// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Rendering for `gorse exposure`: terminal text, JSON, and a
//! self-contained HTML page with an SVG permission graph.
//!
//! Written for a developer who is not a security specialist: every finding
//! says what the credential is, what it reaches, how sure we are, whether
//! wiping the laptop would help, and what to do.

use super::{BlockchainFinding, ExposureReport, FindingMeta, Verification};
use hedgehog_taint::authority::graph::{EdgeKind, NodeKind, PathOutcome};
use hedgehog_taint::authority::scoring::{ExposureFinding, Severity};
use hedgehog_taint::authority::{
    Assurance, Capability, EffectivePermissions, Lifetime, Permission,
};

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

fn cap(c: Capability) -> &'static str {
    c.label()
}

/// The capability flags a report lists, each with its own assurance. A
/// flag reads "confirmed" only when a provider check established that
/// specific permission; an identity confirmation never does.
fn capability_bits(p: &EffectivePermissions, permissions: &[(&str, Permission)]) -> Vec<String> {
    permissions
        .iter()
        .filter(|(_, q)| p.get(*q) != Capability::Unknown)
        .map(|(label, q)| {
            format!(
                "{label}: {} ({})",
                cap(p.get(*q)),
                p.capability_assurance(*q).label()
            )
        })
        .collect()
}

fn lifetime_text(l: &Lifetime) -> String {
    match l {
        Lifetime::LongLived => "long-lived, no expiry".into(),
        Lifetime::ExpiresAt(t) => format!("expires {}", fmt_time(*t)),
        Lifetime::ExpiredAt(t) => format!("EXPIRED {}", fmt_time(*t)),
        Lifetime::Unknown => "lifetime unknown".into(),
    }
}

fn fmt_time(t: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(t as i64, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("unix {t}"))
}

// ─── Text ────────────────────────────────────────────────────────────────────

pub fn render_text(r: &ExposureReport, color: bool) -> String {
    let c = |code: &str| {
        if color {
            format!("\x1b[{code}m")
        } else {
            String::new()
        }
    };
    let reset = c("0");
    let bold = c("1");
    let dim = c("90");
    let sev_color = |s: Severity| match s {
        Severity::Critical => c("1;31"),
        Severity::High => c("31"),
        Severity::Medium => c("33"),
        Severity::Low => c("32"),
    };
    let mut o = String::new();
    o.push_str(&format!("{bold}Gorse Exposure Check{reset}\n"));
    o.push_str("If this laptop were compromised, what could an attacker reach?\n\n");
    if r.incomplete {
        let n = r.coverage_failures.len();
        o.push_str(&format!(
            "{}INCOMPLETE: {n} credential location{} could not be read or interpreted, so the findings below may be missing something.{reset}\n",
            sev_color(Severity::High),
            if n == 1 { "" } else { "s" }
        ));
        for c in &r.coverage_failures {
            o.push_str(&format!("  {} — {}\n", c.location, c.reason));
        }
        o.push('\n');
    }
    let unassessed = unassessed_of(r);
    if !unassessed.is_empty() {
        o.push_str(&format!(
            "{bold}Not assessed in this run{reset} (found by the last complete check; nobody looked this time, so they are not resolved)\n"
        ));
        for e in unassessed {
            o.push_str(&format!(
                "  {} {} ({}) at {}{}\n",
                e.severity,
                e.name,
                e.kind,
                e.location,
                e.reason
                    .as_deref()
                    .map(|why| format!(" — {why}"))
                    .unwrap_or_default()
            ));
        }
        o.push('\n');
    }
    let s = &r.summary;
    o.push_str(&format!("{bold}Summary{reset}\n"));
    o.push_str(&format!(
        "  Credentials and sessions found     {}\n",
        s.credentials
    ));
    o.push_str(&format!(
        "  Privileged credentials             {}\n",
        s.privileged_credentials
    ));
    o.push_str(&format!(
        "  Critical indirect permission paths {}\n",
        s.critical_indirect_paths
    ));
    o.push_str(&format!(
        "  Reachable signing systems          {}\n",
        s.reachable_signing_systems
    ));
    o.push_str(&format!(
        "  Dangerous blockchain authorizations {}\n",
        s.dangerous_blockchain_authorizations
    ));
    o.push_str(&format!(
        "  Rotate / revoke needed              {}\n",
        s.persistent_access_risks
    ));
    o.push_str(&format!(
        "  By severity                        {}{} critical{reset}, {}{} high{reset}, {}{} medium{reset}, {}{} low{reset}\n",
        sev_color(Severity::Critical), s.count(Severity::Critical),
        sev_color(Severity::High), s.count(Severity::High),
        sev_color(Severity::Medium), s.count(Severity::Medium),
        sev_color(Severity::Low), s.count(Severity::Low)
    ));
    o.push_str(&format!(
        "  Mode                               {}\n",
        if r.verified {
            "local discovery + read-only provider verification"
        } else {
            "local discovery only (inferred permissions; add --verify)"
        }
    ));
    if r.verified {
        let v = r.verification_counts();
        o.push_str(&format!(
            "  Verified with providers: {} identity confirmed, {} permission confirmed, {} local configuration only, {} failed, {} unsupported\n",
            v.identity_confirmed, v.permission_confirmed, v.local_config, v.failed, v.unsupported
        ));
    }
    o.push_str(&format!("  Infrastructure map                 {}{}\n\n", r.declarations_path.display(), if r.declarations_loaded { "" } else { " (not found; run `gorse exposure --init` to describe your signers and production systems)" }));

    if !r.reachable.is_empty() {
        o.push_str(&format!(
            "{bold}If this laptop were compromised, an attacker could{reset}\n"
        ));
        for p in &r.reachable {
            let what = match p.outcome {
                PathOutcome::MoveFunds => "MOVE FUNDS from",
                PathOutcome::ApproveSignature => "APPROVE transactions on",
                PathOutcome::RequestSignature => "request signatures from",
                PathOutcome::Modify => "modify",
                PathOutcome::Read => "read from",
                PathOutcome::Reachability if p.last_edge == EdgeKind::CanAuthenticate => {
                    "log in to"
                }
                PathOutcome::Reachability | PathOutcome::Possession => "reach",
            };
            let gate = if p.approvals_required.is_empty() {
                String::new()
            } else {
                format!(
                    " {dim}[still needs: {}]{reset}",
                    p.approvals_required.join("; ")
                )
            };
            let color = match p.outcome {
                PathOutcome::MoveFunds | PathOutcome::ApproveSignature => {
                    sev_color(Severity::Critical)
                }
                PathOutcome::RequestSignature | PathOutcome::Modify => sev_color(Severity::High),
                _ => String::new(),
            };
            o.push_str(&format!(
                "  {color}{what} {}{reset} {dim}({}, {} hop{}){reset}{gate}\n",
                p.target,
                p.assurance.label(),
                p.hops,
                if p.hops == 1 { "" } else { "s" }
            ));
            o.push_str(&format!("      {dim}via {}{reset}\n", p.description));
        }
        o.push_str(
            "  Nothing above was exercised; this is computed from the permissions found.\n\n",
        );
    }

    if r.findings.is_empty() {
        o.push_str(
            "  No credentials or authenticated sessions were found in the usual places.\n\n",
        );
    }
    for (i, f) in r.findings.iter().enumerate() {
        let sc = sev_color(f.severity);
        o.push_str(&format!(
            "{sc}[{}]{reset} {bold}{}{reset} — {}\n",
            sev_tag(f.severity),
            f.credential.name,
            f.credential.kind.label()
        ));
        o.push_str(&format!(
            "  Where         {}  {dim}fingerprint {}{reset}\n",
            f.credential.location, f.credential.fingerprint.0
        ));
        o.push_str(&format!(
            "  Reaches       {}\n",
            if f.accessible_systems.is_empty() {
                f.credential.target.clone()
            } else {
                f.accessible_systems.join(", ")
            }
        ));
        let p = &f.credential.permissions;
        let mut perm_bits = Vec::new();
        if let Some(id) = &p.identity {
            perm_bits.push(format!("identity {id}"));
        }
        if let Some(org) = &p.organization {
            perm_bits.push(org.clone());
        }
        perm_bits.push(lifetime_text(&p.lifetime));
        o.push_str(&format!(
            "  Identity      {} {dim}(identity {}){reset}\n",
            perm_bits.join("; "),
            p.assurance.label()
        ));
        let mut caps = capability_bits(
            p,
            &[
                ("admin", Permission::Administrative),
                ("creates credentials", Permission::CreateCredentials),
                ("modifies own permissions", Permission::ModifyOwnPermissions),
                ("assumes roles", Permission::AssumeRole),
                ("production access", Permission::AccessProduction),
                ("modifies production", Permission::ModifyProduction),
                ("reaches signing", Permission::ReachSigningInfrastructure),
                ("MFA", Permission::RequiresMfa),
                (
                    "independent approval",
                    Permission::RequiresIndependentApproval,
                ),
            ],
        );
        if !p.scope.is_empty() {
            caps.push(p.scope.join(", "));
        }
        if !p.restrictions.is_empty() {
            caps.push(format!("restricted to {}", p.restrictions.join(", ")));
        }
        o.push_str(&format!(
            "  Permissions   {}\n",
            if caps.is_empty() {
                "nothing established beyond possession".to_string()
            } else {
                caps.join("; ")
            }
        ));
        o.push_str(&format!("  Confidence    {}\n", f.confidence.label()));
        if r.verified {
            if let Some(m) = r.finding_meta.get(i) {
                o.push_str(&format!(
                    "  Provider      {}: {}\n",
                    m.verification.status.label(),
                    m.verification.detail
                ));
            }
        }
        for why in &f.reasons {
            o.push_str(&format!("  Why           {why}\n"));
        }
        for ev in &f.credential.evidence {
            o.push_str(&format!("  Evidence      {dim}{ev}{reset}\n"));
        }
        for path in &f.paths {
            if path.outcome <= PathOutcome::Reachability && f.severity == Severity::Low {
                continue;
            }
            let gate = if path.approvals_required.is_empty() {
                String::new()
            } else {
                format!(
                    " {dim}[gated by: {}]{reset}",
                    path.approvals_required.join("; ")
                )
            };
            o.push_str(&format!(
                "  Path          {} {dim}→ {} ({}){reset}{gate}\n",
                path.description,
                path.outcome.label(),
                path.assurance.label()
            ));
        }
        o.push_str(&format!(
            "  After a wipe  {}\n",
            if f.persistence.survives_cleanup() {
                format!("ROTATE / REVOKE NEEDED — {}", f.persistence.label())
            } else {
                f.persistence.label().to_string()
            }
        ));
        if !f.compensating_controls.is_empty() {
            o.push_str(&format!(
                "  Controls      {}\n",
                f.compensating_controls.join("; ")
            ));
        }
        for fix in &f.remediation {
            o.push_str(&format!("  Fix           {fix}\n"));
        }
        o.push('\n');
    }

    if !r.blockchain.is_empty() {
        o.push_str(&format!("{bold}Blockchain authorizations{reset}\n"));
        for b in &r.blockchain {
            let sc = sev_color(b.severity);
            o.push_str(&format!(
                "{sc}[{}]{reset} {} — {} ({})\n",
                sev_tag(b.severity),
                b.wallet,
                b.title,
                b.chain
            ));
            o.push_str(&format!(
                "  Confidence    {}; persistence: {}\n",
                b.assurance.label(),
                b.persistence.label()
            ));
            for d in &b.details {
                o.push_str(&format!("  {dim}{d}{reset}\n"));
            }
        }
        o.push('\n');
    }

    if !r.notes.is_empty() {
        o.push_str(&format!("{bold}Notes{reset}\n"));
        for n in &r.notes {
            o.push_str(&format!("  • {n}\n"));
        }
        o.push('\n');
    }
    if let Some(a) = &r.attestation {
        o.push_str(&format!("{bold}Verified report{reset}\n"));
        o.push_str(&format!("  Holder        {}\n", a.holder));
        o.push_str(&format!("  Machine       {}\n", a.machine));
        o.push_str(&format!("  Verified at   {}\n", a.verified_at));
        o.push_str(&format!("  Integrity checksum  {}\n", a.digest));
        o.push_str(&format!("  {dim}{CHECKSUM_NOTE}{reset}\n"));
        o.push('\n');
    }
    o.push_str(&format!("{dim}Read-only. Nothing was signed, sent, assumed or changed. Secrets are shown as fingerprints only.{reset}\n"));
    o
}

/// What the verified-report stamp's checksum is, and how to recompute it.
/// Shared by the text and HTML reports.
pub const CHECKSUM_NOTE: &str = "Each finding's provider check says what the provider confirmed (identity or a specific permission) under a Gorse Pro licence. The integrity checksum covers the report as emitted, including any history comparison, and its stamp. It detects accidental or careless edits; it is not a cryptographic signature and does not prove who produced the report. Recipe: 'sha256:' and the hex SHA-256 of the JSON report serialised compactly with keys sorted, with the top-level 'generated_at' and 'attestation.digest' removed (and the top-level 'accepted_by_user' that history files from older versions may carry).";

/// Previous findings this run did not assess (recorded runs only).
fn unassessed_of(r: &ExposureReport) -> &[crate::schedule::ChangeEntry] {
    r.record
        .as_ref()
        .map(|rec| rec.changes.unassessed.as_slice())
        .unwrap_or(&[])
}

// ─── JSON ────────────────────────────────────────────────────────────────────

fn finding_json(f: &ExposureFinding, meta: Option<&FindingMeta>) -> serde_json::Value {
    let p = &f.credential.permissions;
    let not_attempted = Verification::not_attempted();
    let verification = meta.map(|m| &m.verification).unwrap_or(&not_attempted);
    serde_json::json!({
        "source": meta.map(|m| m.source.as_str()).unwrap_or(""),
        "verification": {
            "status": verification.status.key(),
            "detail": verification.detail,
        },
        "kind": format!("{:?}", f.credential.kind),
        "kind_label": f.credential.kind.label(),
        "name": f.credential.name,
        "location": f.credential.location,
        "fingerprint": f.credential.fingerprint.0,
        "target": f.credential.target,
        "severity": f.severity.label(),
        "confidence": f.confidence.label(),
        "identity": p.identity,
        "organization": p.organization,
        "scope": p.scope,
        "restrictions": p.restrictions,
        "lifetime": lifetime_text(&p.lifetime),
        "expired": p.lifetime.is_expired(),
        "permissions": {
            // The capability flags taken together: confirmed only when every
            // determined flag was established by a provider check of that
            // permission. Who the credential is lives in identity_assurance.
            "assurance": p.capabilities_assurance().label(),
            "identity_assurance": p.assurance.label(),
            "capability_assurance": Permission::ALL
                .iter()
                .filter(|q| p.get(**q) != Capability::Unknown)
                .map(|q| (q.key().to_string(), serde_json::Value::from(p.capability_assurance(*q).label())))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
            "administrative": cap(p.administrative),
            "can_create_credentials": cap(p.can_create_credentials),
            "can_modify_own_permissions": cap(p.can_modify_own_permissions),
            "can_assume_role": cap(p.can_assume_role),
            "can_access_production": cap(p.can_access_production),
            "can_modify_production": cap(p.can_modify_production),
            "can_reach_signing_infrastructure": cap(p.can_reach_signing_infrastructure),
            "requires_mfa": cap(p.requires_mfa),
            "requires_independent_approval": cap(p.requires_independent_approval),
            "automated": cap(p.automated),
            "revoked": cap(p.revoked),
        },
        "accessible_systems": f.accessible_systems,
        "paths": f.paths.iter().map(|path| serde_json::json!({
            "description": path.description,
            "hops": path.hops,
            "outcome": path.outcome.key(),
            "outcome_label": path.outcome.label(),
            "assurance": path.assurance.label(),
            "approvals_required": path.approvals_required,
            "target": path.target,
            "target_kind": path.target_kind.label(),
            "target_production": path.target_production,
        })).collect::<Vec<_>>(),
        "persistence": {
            "key": f.persistence.key(),
            "label": f.persistence.label(),
            "survives_cleanup": f.persistence.survives_cleanup(),
        },
        "evidence": f.credential.evidence,
        "reasons": f.reasons,
        "compensating_controls": f.compensating_controls,
        "remediation": f.remediation,
    })
}

fn blockchain_json(b: &BlockchainFinding) -> serde_json::Value {
    serde_json::json!({
        "wallet": b.wallet,
        "chain": b.chain,
        "title": b.title,
        "severity": b.severity.label(),
        "confidence": b.assurance.label(),
        "persistence": b.persistence.key(),
        "dangerous": b.dangerous,
        "details": b.details,
    })
}

/// Version of the JSON report shape. Bumped only for breaking changes:
/// renamed or removed fields, changed enumerations. New optional fields do
/// not bump it. The schema is published at
/// https://gorse.is/schema/exposure-report.v1.json.
pub const SCHEMA_VERSION: u32 = 1;

pub fn render_json(r: &ExposureReport) -> serde_json::Value {
    let mut value = render_json_body(r);
    if let Some(record) = &r.record {
        value["recorded_at"] = serde_json::Value::String(record.recorded_at.clone());
        value["trigger"] = serde_json::Value::String(record.trigger.clone());
        value["changes"] = record.changes.json();
    }
    value
}

fn render_json_body(r: &ExposureReport) -> serde_json::Value {
    let s = &r.summary;
    let counts = r.verification_counts();
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "hedgehog_version": env!("CARGO_PKG_VERSION"),
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "verified": r.verified,
        "declarations": { "path": r.declarations_path.display().to_string(), "loaded": r.declarations_loaded },
        "summary": {
            "credentials": s.credentials,
            "privileged_credentials": s.privileged_credentials,
            "critical_indirect_paths": s.critical_indirect_paths,
            "reachable_signing_systems": s.reachable_signing_systems,
            "dangerous_blockchain_authorizations": s.dangerous_blockchain_authorizations,
            "persistent_access_risks": s.persistent_access_risks,
            "by_severity": {
                "critical": s.count(Severity::Critical),
                "high": s.count(Severity::High),
                "medium": s.count(Severity::Medium),
                "low": s.count(Severity::Low),
            },
            "verification_counts": {
                "identity_confirmed": counts.identity_confirmed,
                "permission_confirmed": counts.permission_confirmed,
                "local_config": counts.local_config,
                "failed": counts.failed,
                "unsupported": counts.unsupported,
                "not_attempted": counts.not_attempted,
            },
        },
        "reachable": r.reachable.iter().map(|p| serde_json::json!({
            "target": p.target,
            "target_kind": p.target_kind.label(),
            "target_production": p.target_production,
            "outcome": p.outcome.key(),
            "outcome_label": p.outcome.label(),
            "assurance": p.assurance.label(),
            "hops": p.hops,
            "approvals_required": p.approvals_required,
            "path": p.description,
        })).collect::<Vec<_>>(),
        "findings": r.findings.iter().enumerate().map(|(i, f)| finding_json(f, r.finding_meta.get(i))).collect::<Vec<_>>(),
        "blockchain": r.blockchain.iter().map(blockchain_json).collect::<Vec<_>>(),
        "graph": {
            "start": r.laptop.0,
            "nodes": r.graph.nodes.iter().map(|n| serde_json::json!({"id": n.id.0, "kind": n.kind.label(), "name": n.name, "production": n.production, "notes": n.notes})).collect::<Vec<_>>(),
            "edges": r.graph.edges.iter().map(|e| serde_json::json!({"from": e.from.0, "to": e.to.0, "kind": e.kind.label(), "assurance": e.assurance.label(), "scope": e.scope, "evidence": e.evidence, "requires_approval": e.requires_approval})).collect::<Vec<_>>(),
        },
        "notes": r.notes,
        "incomplete": r.incomplete,
        "coverage_failures": r.coverage_failures.iter().map(|c| serde_json::json!({
            "location": c.location,
            "reason": c.reason,
        })).collect::<Vec<_>>(),
        "sources_assessed": r.sources_assessed,
        "sources_unavailable": r.sources_unavailable.iter().map(|(source, reason)| serde_json::json!({
            "source": source,
            "reason": reason,
        })).collect::<Vec<_>>(),
        "engines": r.engines.iter().map(|e| serde_json::json!({
            "name": e.name,
            "version": e.version,
            "locations": e.locations,
            "detections": e.detections,
            "added": e.added,
            "verification": "off",
            "error": e.error,
        })).collect::<Vec<_>>(),
        "attestation": r.attestation.as_ref().map(|a| serde_json::json!({
            "holder": a.holder,
            "machine": a.machine,
            "verified_at": a.verified_at,
            "digest": a.digest,
        })),
    })
}

// ─── HTML with SVG graph ─────────────────────────────────────────────────────

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn column_for(kind: NodeKind) -> usize {
    match kind {
        NodeKind::Laptop => 0,
        NodeKind::Credential => 1,
        NodeKind::Identity | NodeKind::CloudRole => 2,
        NodeKind::CiSystem
        | NodeKind::Repository
        | NodeKind::Registry
        | NodeKind::Cluster
        | NodeKind::Workload
        | NodeKind::ProductionService
        | NodeKind::SecretsManager
        | NodeKind::Other => 3,
        NodeKind::Signer => 4,
        NodeKind::Wallet | NodeKind::FinancialAsset => 5,
    }
}

const COLUMN_TITLES: [&str; 6] = [
    "Laptop",
    "Credentials",
    "Roles",
    "Systems",
    "Signers",
    "Assets",
];

pub fn render_svg(r: &ExposureReport) -> String {
    let g = &r.graph;
    let col_w = 230.0;
    let box_w = 200.0;
    let box_h = 34.0;
    let row_h = 48.0;
    let mut rows = [0usize; 6];
    let mut pos: Vec<(f64, f64)> = Vec::with_capacity(g.nodes.len());
    for n in &g.nodes {
        let col = column_for(n.kind);
        let x = 20.0 + col as f64 * col_w;
        let y = 50.0 + rows[col] as f64 * row_h;
        rows[col] += 1;
        pos.push((x, y));
    }
    let height = 60.0 + rows.iter().copied().max().unwrap_or(1).max(1) as f64 * row_h;
    let width = 20.0 + 6.0 * col_w;
    let mut s = String::new();
    s.push_str(&format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px;font-family:ui-sans-serif,system-ui,sans-serif;font-size:12px">"#));
    s.push_str(r#"<defs><marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker></defs>"#);
    for (i, title) in COLUMN_TITLES.iter().enumerate() {
        s.push_str(&format!(
            r#"<text x="{}" y="30" fill="var(--muted)" font-weight="600">{}</text>"#,
            20.0 + i as f64 * col_w,
            title
        ));
    }
    for e in &g.edges {
        let (x1, y1) = pos[e.from.0];
        let (x2, y2) = pos[e.to.0];
        let (sx, sy) = (x1 + box_w, y1 + box_h / 2.0);
        let (tx, ty) = (x2, y2 + box_h / 2.0);
        let color = if e.kind.is_financial_authority() {
            "var(--crit)"
        } else if e.kind.is_mutating() {
            "var(--warn)"
        } else {
            "var(--edge)"
        };
        let dash = match e.assurance {
            Assurance::Confirmed => "",
            Assurance::Inferred => r#" stroke-dasharray="6 4""#,
            Assurance::Unknown => r#" stroke-dasharray="2 4""#,
        };
        let gate = e
            .requires_approval
            .as_deref()
            .map(|a| format!(" [gated: {a}]"))
            .unwrap_or_default();
        let title = format!(
            "{} ({}){}{}",
            e.kind.label(),
            e.assurance.label(),
            gate,
            if e.evidence.is_empty() {
                String::new()
            } else {
                format!(" — {}", e.evidence.join("; "))
            }
        );
        let mx = (sx + tx) / 2.0;
        s.push_str(&format!(r#"<path d="M{sx},{sy} C{mx},{sy} {mx},{ty} {tx},{ty}" fill="none" stroke="{color}" stroke-width="1.6"{dash} marker-end="url(#arrow)"><title>{}</title></path>"#, esc(&title)));
    }
    for (i, n) in g.nodes.iter().enumerate() {
        let (x, y) = pos[i];
        let fill = match n.kind {
            NodeKind::Laptop => "var(--laptop)",
            NodeKind::Credential => "var(--cred)",
            NodeKind::Signer | NodeKind::Wallet | NodeKind::FinancialAsset => "var(--fin)",
            _ => "var(--sys)",
        };
        let stroke = if n.production {
            "var(--crit)"
        } else {
            "var(--border)"
        };
        let mut label = n.name.clone();
        if label.chars().count() > 30 {
            label = format!("{}…", label.chars().take(29).collect::<String>());
        }
        let title = format!(
            "{} ({}){}{}",
            n.name,
            n.kind.label(),
            if n.production { " — production" } else { "" },
            if n.notes.is_empty() {
                String::new()
            } else {
                format!("\n{}", n.notes.join("\n"))
            }
        );
        s.push_str(&format!(r#"<g><title>{}</title><rect x="{x}" y="{y}" rx="6" width="{box_w}" height="{box_h}" fill="{fill}" stroke="{stroke}" stroke-width="{}"/><text x="{}" y="{}" fill="var(--fg)">{}</text></g>"#, esc(&title), if n.production { 2 } else { 1 }, x + 10.0, y + 21.0, esc(&label)));
    }
    s.push_str("</svg>");
    s
}

pub fn render_html(r: &ExposureReport) -> String {
    let s = &r.summary;
    let mut rows = String::new();
    for (i, f) in r.findings.iter().enumerate() {
        let paths: Vec<String> = f
            .paths
            .iter()
            .filter(|p| p.outcome > PathOutcome::Reachability || f.severity > Severity::Low)
            .map(|p| {
                format!(
                    "{} <span class=muted>→ {} ({}){}</span>",
                    esc(&p.description),
                    esc(p.outcome.label()),
                    p.assurance.label(),
                    if p.approvals_required.is_empty() {
                        String::new()
                    } else {
                        format!(" gated by {}", esc(&p.approvals_required.join("; ")))
                    }
                )
            })
            .collect();
        rows.push_str(&format!(
            concat!(
                "<article class=\"finding sev-{sev}\">",
                "<header><span class=\"tag {sev}\">{SEV}</span> <b>{name}</b> <span class=muted>{kind}</span> <code>{loc}</code> <span class=muted>fp {fp}</span></header>",
                "<dl class=facts>",
                "<div><dt>Reaches</dt><dd>{systems}</dd></div>",
                "<div><dt>Effective permissions</dt><dd>{perms}<br><span class=muted>{assur}</span></dd></div>",
                "<div><dt>Confidence</dt><dd>{conf}</dd></div>",
                "{provider}",
                "<div><dt>After laptop cleanup</dt><dd>{persist}</dd></div>",
                "</dl>",
                "<div class=detail>",
                "<section><h3>Why / attack path</h3>{why}{paths}</section>",
                "<section><h3>Fix</h3>{fix}</section>",
                "</div>",
                "</article>"
            ),
            sev = f.severity.label(),
            SEV = sev_tag(f.severity),
            name = esc(&f.credential.name),
            kind = esc(f.credential.kind.label()),
            loc = esc(&f.credential.location),
            fp = esc(&f.credential.fingerprint.0),
            systems = esc(&if f.accessible_systems.is_empty() { f.credential.target.clone() } else { f.accessible_systems.join(", ") }),
            perms = {
                let p = &f.credential.permissions;
                let mut bits = Vec::new();
                if let Some(id) = &p.identity { bits.push(esc(id)); }
                bits.push(esc(&lifetime_text(&p.lifetime)));
                bits.extend(capability_bits(p, &[("admin", Permission::Administrative), ("creates credentials", Permission::CreateCredentials), ("modifies production", Permission::ModifyProduction), ("production access", Permission::AccessProduction), ("reaches signing", Permission::ReachSigningInfrastructure), ("MFA", Permission::RequiresMfa), ("independent approval", Permission::RequiresIndependentApproval)]).iter().map(|b| esc(b)));
                if !p.scope.is_empty() { bits.push(esc(&p.scope.join(", "))); }
                bits.join("<br>")
            },
            assur = format!("identity {}; capabilities {}", f.credential.permissions.assurance.label(), f.credential.permissions.capabilities_assurance().label()),
            conf = f.confidence.label(),
            provider = match (r.verified, r.finding_meta.get(i)) {
                (true, Some(m)) => format!(
                    "<div><dt>Provider check</dt><dd>{}<br><span class=muted>{}</span></dd></div>",
                    esc(m.verification.status.label()),
                    esc(&m.verification.detail)
                ),
                _ => String::new(),
            },
            why = if f.reasons.is_empty() && paths.is_empty() { "<div class=muted>—</div>".to_string() } else { f.reasons.iter().map(|w| format!("<div>{}</div>", esc(w))).collect::<String>() },
            paths = if paths.is_empty() { String::new() } else { format!("<ul class=paths>{}</ul>", paths.iter().map(|p| format!("<li>{p}</li>")).collect::<String>()) },
            persist = if f.persistence.survives_cleanup() { format!("<b>Rotate / revoke needed</b><br><span class=muted>{}</span>", esc(f.persistence.label())) } else { esc(f.persistence.label()) },
            fix = if f.remediation.is_empty() { "<div class=muted>—</div>".to_string() } else { f.remediation.iter().map(|x| format!("<div>{}</div>", esc(x))).collect::<String>() },
        ));
    }
    let blockchain: String = r.blockchain.iter().map(|b| format!("<tr><td><span class=\"tag {}\">{}</span></td><td><b>{}</b><br><span class=muted>{}</span></td><td>{}</td><td>{}<br><span class=muted>{}</span></td><td>{}</td></tr>", b.severity.label(), sev_tag(b.severity), esc(&b.wallet), esc(&b.chain), esc(&b.title), b.assurance.label(), esc(b.persistence.label()), b.details.iter().map(|d| format!("<div>{}</div>", esc(d))).collect::<String>())).collect();
    let notes: String = r
        .notes
        .iter()
        .map(|n| format!("<li>{}</li>", esc(n)))
        .collect();
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gorse Exposure Check</title>
<style>
:root{{--bg:#fafaf8;--fg:#1b1b1b;--muted:#6b6b6b;--border:#d9d9d4;--card:#fff;--crit:#c0392b;--high:#d35400;--warn:#d68910;--low:#2e7d32;--edge:#9aa0a6;--laptop:#e8f0fe;--cred:#fff7e6;--sys:#f1f3f4;--fin:#fdecea}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#111;--fg:#eee;--muted:#9a9a9a;--border:#333;--card:#1b1b1b;--edge:#666;--laptop:#1e2a3a;--cred:#3a2e1a;--sys:#242424;--fin:#3a1f1c}}}}
:root[data-theme="dark"]{{--bg:#111;--fg:#eee;--muted:#9a9a9a;--border:#333;--card:#1b1b1b;--edge:#666;--laptop:#1e2a3a;--cred:#3a2e1a;--sys:#242424;--fin:#3a1f1c}}
body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,sans-serif}}
main{{max-width:1280px;margin:0 auto}}h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:18px;margin:32px 0 12px}}
.sub{{color:var(--muted);margin:0 0 20px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px}}.card b{{display:block;font-size:26px}}.card span{{color:var(--muted);font-size:13px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;font-size:14px}}th,td{{text-align:left;vertical-align:top;padding:10px;border-top:1px solid var(--border)}}th{{background:var(--sys);border-top:0;font-weight:600}}
.tag{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;color:#fff;background:var(--low)}}.tag.critical{{background:var(--crit)}}.tag.high{{background:var(--high)}}.tag.medium{{background:var(--warn)}}
.tablewrap{{overflow-x:auto}}.muted{{color:var(--muted)}}code{{font-size:12px;word-break:break-all}}.paths{{margin:6px 0 0;padding-left:18px}}
.graph{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px;overflow-x:auto}}.legend{{color:var(--muted);font-size:13px;margin:8px 0 0}}
.findings{{display:flex;flex-direction:column;gap:12px}}
.finding{{background:var(--card);border:1px solid var(--border);border-left:5px solid var(--low);border-radius:10px;padding:14px 16px;font-size:14px;break-inside:avoid}}
.finding.sev-critical{{border-left-color:var(--crit)}}.finding.sev-high{{border-left-color:var(--high)}}.finding.sev-medium{{border-left-color:var(--warn)}}
.finding header{{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 10px;margin:0 0 10px}}.finding header b{{font-size:16px}}.finding header code{{word-break:break-all}}
.finding .facts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px 20px;margin:0 0 12px;padding:10px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border)}}
.finding .facts>div{{min-width:0}}.finding dt,.finding h3{{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 3px}}.finding dd{{margin:0;overflow-wrap:anywhere}}
.finding .detail{{display:grid;grid-template-columns:1fr 1fr;gap:12px 24px}}.finding .detail section{{min-width:0}}.finding .detail section>div{{margin:0 0 4px}}
@media (max-width:720px){{table,thead,tbody,tr,td,th{{display:block}}thead{{display:none}}td{{border-top:0;padding:4px 10px}}tr{{border-top:1px solid var(--border);padding:8px 0}}.finding .detail{{grid-template-columns:1fr}}}}
@media print{{.finding{{page-break-inside:avoid;border-color:#999}}}}
</style></head><body><main>
<h1>Gorse Exposure Check</h1>
<p class=sub>If this laptop were compromised, what could an attacker reach? {mode}</p>
{incomplete}
<div class=cards>
<div class=card><b>{c1}</b><span>credentials and sessions</span></div>
<div class=card><b>{c2}</b><span>privileged credentials</span></div>
<div class=card><b>{c3}</b><span>critical indirect paths</span></div>
<div class=card><b>{c4}</b><span>reachable signing systems</span></div>
<div class=card><b>{c5}</b><span>dangerous blockchain authorizations</span></div>
<div class=card><b>{c6}</b><span>rotate / revoke needed</span></div>
</div>
{reach}
<h2>Permission graph</h2>
<div class=graph>{svg}<p class=legend>Solid edges are confirmed with the provider; dashed edges are inferred from local configuration. Red edges move or authorise money; amber edges change infrastructure; grey edges only reach or read. Boxes outlined in red are production. Hover for evidence.</p></div>
<h2>Findings ({n})</h2>
<div class=findings>{rows}</div>
{bc}
{notes}
{stamp}
<p class=muted>Read-only. Nothing was signed, sent, assumed or changed. Secrets are shown as fingerprints only. Generated by Gorse {ver}.</p>
</main></body></html>"#,
        mode = if r.verified {
            "Each finding says what the provider confirmed (identity or a specific permission) using read-only queries; a check that only read local configuration confirms nothing."
        } else {
            "Local discovery only: permissions are <i>inferred</i> until run with <code>--verify</code>."
        },
        incomplete = {
            let mut banner = if r.incomplete {
                format!(
                    "<div class=\"card incomplete\" style=\"border-color:var(--high)\"><b style=\"font-size:16px;color:var(--high)\">Incomplete: {} credential location{} or source{} could not be read or assessed</b><span>The findings may be missing something.</span><ul>{}</ul></div>",
                    r.coverage_failures.len(),
                    if r.coverage_failures.len() == 1 { "" } else { "s" },
                    if r.coverage_failures.len() == 1 { "" } else { "s" },
                    r.coverage_failures.iter().map(|c| format!("<li><code>{}</code> — {}</li>", esc(&c.location), esc(&c.reason))).collect::<String>()
                )
            } else {
                String::new()
            };
            let unassessed = unassessed_of(r);
            if !unassessed.is_empty() {
                banner.push_str(&format!(
                    "<h2>Not assessed in this run ({})</h2><p class=muted>Found by the last complete check. Their source did not run this time, so nobody looked: they are not resolved.</p><div class=tablewrap><table class=unassessed><thead><tr><th>Severity</th><th>Credential</th><th>Location</th><th>Why</th></tr></thead><tbody>{}</tbody></table></div>",
                    unassessed.len(),
                    unassessed.iter().map(|e| format!(
                        "<tr><td>{}</td><td><b>{}</b> <span class=muted>{}</span></td><td><code>{}</code></td><td>not assessed in this run{}</td></tr>",
                        esc(&e.severity),
                        esc(&e.name),
                        esc(&e.kind),
                        esc(&e.location),
                        e.reason.as_deref().map(|why| format!(": {}", esc(why))).unwrap_or_default()
                    )).collect::<String>()
                ));
            }
            banner
        },
        c1 = s.credentials,
        c2 = s.privileged_credentials,
        c3 = s.critical_indirect_paths,
        c4 = s.reachable_signing_systems,
        c5 = s.dangerous_blockchain_authorizations,
        c6 = s.persistent_access_risks,
        reach = if r.reachable.is_empty() {
            String::new()
        } else {
            format!("<h2>If this laptop were compromised, an attacker could</h2><div class=tablewrap><table><thead><tr><th>Outcome</th><th>Target</th><th>Confidence</th><th>Still needs</th><th>Path</th></tr></thead><tbody>{}</tbody></table></div><p class=muted>Nothing here was exercised; it is computed from the permissions found.</p>",
                r.reachable.iter().map(|p| {
                    let cls = match p.outcome { PathOutcome::MoveFunds | PathOutcome::ApproveSignature => "critical", PathOutcome::RequestSignature | PathOutcome::Modify => "high", PathOutcome::Read => "medium", _ => "" };
                    format!("<tr><td><span class=\"tag {cls}\">{}</span></td><td>{}{}</td><td>{}</td><td>{}</td><td class=muted>{}</td></tr>",
                        esc(p.outcome.label()), esc(&p.target), if p.target_production { " <span class=muted>(production)</span>" } else { "" }, p.assurance.label(),
                        if p.approvals_required.is_empty() { "—".to_string() } else { esc(&p.approvals_required.join("; ")) }, esc(&p.description))
                }).collect::<String>())
        },
        svg = render_svg(r),
        n = r.findings.len(),
        rows = rows,
        bc = if r.blockchain.is_empty() {
            String::new()
        } else {
            format!("<h2>Blockchain authorizations</h2><div class=tablewrap><table><thead><tr><th>Severity</th><th>Wallet</th><th>Finding</th><th>Confidence</th><th>Details</th></tr></thead><tbody>{blockchain}</tbody></table></div>")
        },
        notes = if notes.is_empty() {
            String::new()
        } else {
            format!("<h2>Notes</h2><ul>{notes}</ul>")
        },
        stamp = match &r.attestation {
            None => String::new(),
            Some(a) => format!(
                "<h2>Verified report</h2><div class=card><table><tbody><tr><th>Holder</th><td>{}</td></tr><tr><th>Machine</th><td><code>{}</code></td></tr><tr><th>Verified at</th><td>{}</td></tr><tr><th>Integrity checksum</th><td><code>{}</code></td></tr></tbody></table><p class=muted>{}</p></div>",
                esc(&a.holder),
                esc(&a.machine),
                esc(&a.verified_at),
                esc(&a.digest),
                esc(CHECKSUM_NOTE)
            ),
        },
        ver = env!("CARGO_PKG_VERSION"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::config::Declarations;
    use crate::exposure::discover::Discovered;
    use crate::exposure::{build_graph, discover};
    use hedgehog_taint::authority::graph::NodeKind;
    use hedgehog_taint::authority::{scoring, CredentialKind, DiscoveredCredential};
    use std::path::PathBuf;

    /// A report with one AWS finding whose identity the provider confirmed,
    /// with `administrative` read from a policy name and, when asked, the
    /// role assumption confirmed by the provider.
    fn report(confirm_assume_role: bool) -> ExposureReport {
        let mut c = DiscoveredCredential::new(
            CredentialKind::AwsAccessKey,
            "default",
            "~/.aws/credentials",
            "AWS",
        );
        c.permissions.assurance = Assurance::Confirmed;
        c.permissions.identity = Some("arn:aws:iam::123456789012:user/alice".into());
        c.permissions
            .infer(Permission::Administrative, Capability::Yes);
        if confirm_assume_role {
            c.permissions
                .confirm(Permission::AssumeRole, Capability::Yes);
        }
        let discovered = vec![Discovered {
            credential: c,
            links: vec![],
            verify_key: None,
            source: None,
        }];
        let decl = Declarations::default();
        let (graph, laptop, nodes) = build_graph(&discovered, &decl);
        let paths = graph.paths_to_kind(nodes[0], NodeKind::Other, 4);
        let findings = vec![scoring::score_finding(
            &graph,
            &discovered[0].credential,
            &paths,
        )];
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
            engines: vec![],
            coverage_failures: vec![],
            incomplete: false,
            finding_meta: vec![FindingMeta {
                source: "aws-credentials-file".into(),
                verification: Verification {
                    status: super::super::VerificationStatus::IdentityConfirmed,
                    detail: "aws sts get-caller-identity: the provider confirmed the identity"
                        .into(),
                },
            }],
            sources_assessed: discover::SOURCES
                .iter()
                .map(|(id, _)| id.to_string())
                .collect(),
            sources_unavailable: vec![],
            record: None,
        }
    }

    #[test]
    fn identity_confirmation_never_prints_a_capability_as_confirmed() {
        let r = report(false);
        assert_eq!(r.findings[0].confidence, Assurance::Inferred);

        let text = render_text(&r, false);
        assert!(text.contains("admin: yes (inferred)"), "{text}");
        assert!(!text.contains("yes (confirmed)"), "{text}");
        assert!(text.contains("(identity confirmed)"), "{text}");
        assert!(text.contains("Confidence    inferred"), "{text}");

        let json = render_json(&r);
        let f = &json["findings"][0];
        assert_eq!(f["confidence"], "inferred");
        assert_eq!(f["permissions"]["administrative"], "yes");
        assert_eq!(f["permissions"]["assurance"], "inferred");
        assert_eq!(f["permissions"]["identity_assurance"], "confirmed");
        assert_eq!(
            f["permissions"]["capability_assurance"]["administrative"],
            "inferred"
        );

        let html = render_html(&r);
        assert!(html.contains("admin: yes (inferred)"), "html");
        assert!(!html.contains("yes (confirmed)"), "html");
        assert!(html.contains("identity confirmed; capabilities inferred"));
    }

    #[test]
    fn a_capability_a_provider_established_reads_confirmed() {
        let r = report(true);
        let text = render_text(&r, false);
        assert!(text.contains("assumes roles: yes (confirmed)"), "{text}");
        assert!(text.contains("admin: yes (inferred)"), "{text}");
        let json = render_json(&r);
        let p = &json["findings"][0]["permissions"];
        assert_eq!(p["capability_assurance"]["can_assume_role"], "confirmed");
        assert_eq!(p["capability_assurance"]["administrative"], "inferred");
        // Taken together the capabilities are only as confirmed as the
        // weakest one.
        assert_eq!(p["assurance"], "inferred");
    }
}
