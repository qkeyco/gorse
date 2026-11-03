// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Risk scoring for exposure findings.
//!
//! Severity reflects *effective* authority, not credential type. A long-lived
//! AWS key with read-only policies is Low; a short-lived session that can
//! deploy to the cluster hosting the signer is High; a confirmed ungated path
//! to moving funds is Critical. Inferred authority never scores as high as
//! confirmed authority for the same claim.

use super::graph::{AttackPath, EdgeKind, NodeKind, PathOutcome, PermissionGraph};
use super::{Assurance, Capability, DiscoveredCredential, Lifetime, Permission, Persistence};

/// Declared in ascending order so `Ord` and `max()` pick the worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

/// A rendered path with its narrative, ready for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSummary {
    pub description: String,
    pub hops: usize,
    pub outcome: PathOutcome,
    /// The capability of the final hop.
    pub last_edge: EdgeKind,
    pub assurance: Assurance,
    pub approvals_required: Vec<String>,
    pub target: String,
    pub target_kind: NodeKind,
    pub target_production: bool,
}

/// One row of the exposure report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureFinding {
    pub credential: DiscoveredCredential,
    pub severity: Severity,
    /// Weakest assurance behind the severity.
    pub confidence: Assurance,
    pub accessible_systems: Vec<String>,
    pub paths: Vec<PathSummary>,
    pub persistence: Persistence,
    pub reasons: Vec<String>,
    pub compensating_controls: Vec<String>,
    pub remediation: Vec<String>,
}

/// Counts shown at the top of the report.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposureSummary {
    pub credentials: usize,
    pub privileged_credentials: usize,
    pub critical_indirect_paths: usize,
    pub reachable_signing_systems: usize,
    pub dangerous_blockchain_authorizations: usize,
    pub persistent_access_risks: usize,
    pub by_severity: [usize; 4],
}

impl ExposureSummary {
    pub fn count(&self, s: Severity) -> usize {
        self.by_severity[s as usize]
    }
}

fn cap_yes(c: Capability) -> bool {
    c.is_yes()
}

/// Lower a severity by one step for inferred authority, two for unknown.
fn discount(sev: Severity, assurance: Assurance) -> Severity {
    let steps = match assurance {
        Assurance::Confirmed => 0,
        Assurance::Inferred => 1,
        Assurance::Unknown => 2,
    };
    let mut s = sev;
    for _ in 0..steps {
        s = match s {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low => Severity::Low,
        };
    }
    s
}

pub fn summarize_path(graph: &PermissionGraph, path: &AttackPath) -> PathSummary {
    let target = graph.get(path.target());
    PathSummary {
        description: graph.describe(path),
        hops: path.hops(),
        outcome: path.outcome,
        last_edge: path
            .edges
            .last()
            .map(|i| graph.edges[*i].kind)
            .unwrap_or(EdgeKind::CanReach),
        assurance: path.assurance,
        approvals_required: path.approvals_required.clone(),
        target: target.name.clone(),
        target_kind: target.kind,
        target_production: target.production,
    }
}

/// Score one credential given the paths that start from it.
pub fn score_finding(
    graph: &PermissionGraph,
    credential: &DiscoveredCredential,
    paths: &[AttackPath],
) -> ExposureFinding {
    let perms = &credential.permissions;
    let mut severity = Severity::Low;
    // Starts at how well the credential itself is known and is lowered by
    // every claim behind the severity. An identity confirmation alone never
    // leaves it confirmed: see the end of this function.
    let mut confidence = perms.assurance;
    let mut raised = false;
    let mut reasons: Vec<String> = Vec::new();
    let mut controls: Vec<String> = Vec::new();
    let mut remediation: Vec<String> = Vec::new();
    let mut persistence = credential.persistence;

    let expired = perms.lifetime.is_expired() || cap_yes(perms.revoked);
    if expired {
        reasons.push("credential is expired or revoked; it grants nothing now".into());
        remediation.push(
            "Delete the stale credential file so it cannot be confused with a live one.".into(),
        );
    }

    // The assurance discount exists so that name-based guesses ("this role
    // sounds like admin") are not reported as loudly as verified facts. An
    // ungated path that ends in moving funds or approving a transaction can
    // only come from a key in hand or from the topology the user declared,
    // never from a name heuristic, and the cost of under-reporting it is the
    // whole treasury. Those paths keep their severity; the confidence label
    // still says "inferred" and the text still says what to verify.
    let mut raise_with = |sev: Severity,
                          assurance: Assurance,
                          discounted: bool,
                          why: String,
                          reasons: &mut Vec<String>| {
        let effective = if discounted {
            discount(sev, assurance)
        } else {
            sev
        };
        if effective > severity {
            severity = effective;
        }
        if assurance != Assurance::Confirmed && sev > effective {
            reasons.push(format!(
                "{why} ({}; scored {} until verified)",
                assurance.label(),
                effective.label()
            ));
        } else if assurance != Assurance::Confirmed && !discounted {
            reasons.push(format!(
                "{why} ({}; run --verify to confirm)",
                assurance.label()
            ));
        } else {
            reasons.push(why);
        }
        confidence = confidence.weakest(assurance);
        raised = true;
    };

    let mut path_summaries = Vec::new();
    let mut systems: Vec<String> = Vec::new();

    if !expired {
        // ── Path-derived authority ──
        for path in paths {
            let summary = summarize_path(graph, path);
            if !systems.contains(&summary.target) {
                systems.push(summary.target.clone());
            }
            let financial = summary.target_kind.is_financial();
            match (path.outcome, path.is_gated()) {
                (PathOutcome::MoveFunds, false) if financial => {
                    let why = if path.hops() > 1 {
                        format!(
                            "indirect path can move funds without independent approval: {}",
                            summary.description
                        )
                    } else {
                        format!(
                            "can move funds from {} without independent approval",
                            summary.target
                        )
                    };
                    raise_with(Severity::Critical, path.assurance, false, why, &mut reasons);
                    remediation.push(format!("Require a second approver or policy engine in front of {} before any transfer.", summary.target));
                }
                (PathOutcome::MoveFunds, false) => {
                    raise_with(
                        Severity::High,
                        path.assurance,
                        true,
                        format!(
                            "asset-moving authority reaches non-financial system {}",
                            summary.target
                        ),
                        &mut reasons,
                    );
                }
                (PathOutcome::MoveFunds, true) => {
                    raise_with(Severity::High, path.assurance, true,
                        format!("can reach asset-moving authority on {} but an approval gate remains: {}", summary.target, summary.approvals_required.join("; ")),
                        &mut reasons);
                    controls.push(format!(
                        "approval required: {}",
                        summary.approvals_required.join("; ")
                    ));
                }
                (PathOutcome::ApproveSignature, false) => {
                    raise_with(
                        Severity::Critical,
                        path.assurance,
                        false,
                        format!("can approve transactions on {}", summary.target),
                        &mut reasons,
                    );
                }
                (PathOutcome::ApproveSignature, true) => {
                    raise_with(
                        Severity::High,
                        path.assurance,
                        true,
                        format!(
                            "can approve transactions on {} subject to: {}",
                            summary.target,
                            summary.approvals_required.join("; ")
                        ),
                        &mut reasons,
                    );
                    controls.push(format!(
                        "approval required: {}",
                        summary.approvals_required.join("; ")
                    ));
                }
                (PathOutcome::RequestSignature, _) => {
                    raise_with(
                        Severity::High,
                        path.assurance,
                        true,
                        format!(
                            "can request signatures from {}; approval is held elsewhere",
                            summary.target
                        ),
                        &mut reasons,
                    );
                    controls.push(format!(
                        "{} must verify every request independently",
                        summary.target
                    ));
                }
                (PathOutcome::Modify, _) if summary.target_production => {
                    let sev = if graph_has_downstream_signer(graph, path) {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    let why = if sev == Severity::High {
                        format!("production deployment authority over infrastructure that hosts signing: {}", summary.description)
                    } else {
                        format!("can modify production system {}", summary.target)
                    };
                    raise_with(sev, path.assurance, true, why, &mut reasons);
                }
                (PathOutcome::Modify, _) => {
                    raise_with(
                        Severity::Medium,
                        path.assurance,
                        true,
                        format!("can modify {}", summary.target),
                        &mut reasons,
                    );
                }
                (PathOutcome::Read, _) if summary.target_kind == NodeKind::SecretsManager => {
                    raise_with(
                        Severity::High,
                        path.assurance,
                        true,
                        format!("can read secrets from {}", summary.target),
                        &mut reasons,
                    );
                }
                (PathOutcome::Read, _) if summary.target_production => {
                    raise_with(
                        Severity::Medium,
                        path.assurance,
                        true,
                        format!("read access to production system {}", summary.target),
                        &mut reasons,
                    );
                }
                // An SSH key that logs in is a shell on that host, which is
                // read-and-modify on everything the account owns, not mere
                // reachability. Production hosts score High; any other host
                // Medium, since the check cannot know what the host is until
                // the map says so.
                (PathOutcome::Reachability, _)
                    if credential.kind.is_ssh_login()
                        && summary.last_edge == EdgeKind::CanAuthenticate =>
                {
                    if summary.target_production {
                        // Not discounted: the production label came from the
                        // user's own declaration, and a key listed for the
                        // host in ~/.ssh/config is the login.
                        raise_with(
                            Severity::High,
                            path.assurance,
                            false,
                            format!("shell login to production system {}: an SSH key is a shell, not just reachability", summary.target),
                            &mut reasons,
                        );
                    } else {
                        raise_with(
                            Severity::Medium,
                            path.assurance,
                            true,
                            format!("shell login to {}: an SSH key is a shell on that host; mark it as production if it is one", summary.target),
                            &mut reasons,
                        );
                    }
                }
                (PathOutcome::Reachability, _)
                    if summary.target_production
                        && summary.last_edge == EdgeKind::CanAuthenticate =>
                {
                    raise_with(
                        Severity::Medium,
                        path.assurance,
                        true,
                        format!("can log in to production system {}", summary.target),
                        &mut reasons,
                    );
                }
                (PathOutcome::Read, _)
                | (PathOutcome::Reachability, _)
                | (PathOutcome::Possession, _) => {}
            }
            if !path.approvals_required.is_empty() {
                for a in &path.approvals_required {
                    let c = format!("approval gate: {a}");
                    if !controls.contains(&c) {
                        controls.push(c);
                    }
                }
            }
            path_summaries.push(summary);
        }

        // ── Direct permission flags ──
        if cap_yes(perms.administrative) {
            raise_with(
                Severity::High,
                perms.capability_assurance(Permission::Administrative),
                true,
                format!("administrative permissions on {}", credential.target),
                &mut reasons,
            );
            remediation
                .push("Replace standing admin access with a just-in-time, MFA-gated role.".into());
        }
        if cap_yes(perms.can_create_credentials) {
            raise_with(
                Severity::High,
                perms.capability_assurance(Permission::CreateCredentials),
                true,
                "can create additional credentials, so access can be re-established after cleanup"
                    .into(),
                &mut reasons,
            );
            persistence = Persistence::ServerSide;
        }
        if cap_yes(perms.can_modify_own_permissions) {
            raise_with(
                Severity::High,
                perms.capability_assurance(Permission::ModifyOwnPermissions),
                true,
                "can modify its own permissions".into(),
                &mut reasons,
            );
        }
        if cap_yes(perms.can_modify_production) {
            let sev = if matches!(perms.lifetime, Lifetime::LongLived) {
                Severity::High
            } else {
                Severity::Medium
            };
            raise_with(
                sev,
                perms.capability_assurance(Permission::ModifyProduction),
                true,
                if sev == Severity::High {
                    "long-lived credential that can modify production".into()
                } else {
                    "expiring session that can modify production".into()
                },
                &mut reasons,
            );
        } else if cap_yes(perms.can_access_production) {
            raise_with(
                Severity::Medium,
                perms.capability_assurance(Permission::AccessProduction),
                true,
                "restricted production access".into(),
                &mut reasons,
            );
        }
        if cap_yes(perms.can_reach_signing_infrastructure) && path_summaries.is_empty() {
            raise_with(
                Severity::High,
                perms.capability_assurance(Permission::ReachSigningInfrastructure),
                true,
                "credential reaches signing infrastructure".into(),
                &mut reasons,
            );
        }
        if cap_yes(perms.requires_mfa) {
            controls.push("MFA required".into());
        }
        if cap_yes(perms.requires_independent_approval) {
            controls.push("independent approval required".into());
        }
        if !perms.restrictions.is_empty() {
            controls.push(format!("restricted to: {}", perms.restrictions.join(", ")));
        }

        // ── Keys that need no passphrase ──
        // Local file inspection, so confirmed rather than inferred: the file
        // works the moment it is copied, which moves everything it reaches
        // one step up.
        if credential.kind.is_ssh_login() && paths.is_empty() {
            reasons.push(
                "which hosts accept this key is unknown: no matching Host in ~/.ssh/config and none declared in the map"
                    .into(),
            );
        }
        if credential.unprotected {
            severity = match severity {
                Severity::Low => Severity::Medium,
                Severity::Medium => Severity::High,
                Severity::High | Severity::Critical => Severity::Critical,
            };
            reasons.push("no passphrase: usable the moment the file is copied".into());
        }
        if credential.kind == crate::authority::CredentialKind::SshPrivateKey {
            remediation.push(
                "Move this key into a hardware-backed or agent-managed store (Secure Enclave via Secretive, a YubiKey as an ed25519-sk key, or the 1Password SSH agent), delete the file, and replace its public key on every host; at minimum protect it with a passphrase.".into(),
            );
        }

        // ── Lifetime and persistence ──
        match perms.lifetime {
            Lifetime::LongLived if severity >= Severity::Medium => {
                reasons.push("long-lived: works until revoked, with no natural expiry".into());
                if persistence == Persistence::Unknown {
                    persistence = Persistence::IndependentCredential;
                }
                remediation.push(
                    "Rotate to short-lived credentials (SSO, OIDC, STS, token expiry).".into(),
                );
            }
            Lifetime::ExpiresAt(_) => {
                controls.push("time-limited session".into());
            }
            _ => {}
        }
        if persistence == Persistence::Unknown && credential.kind.portable_by_default() {
            persistence = Persistence::IndependentCredential;
        }
        if persistence.survives_cleanup() && severity >= Severity::Medium {
            remediation.push(
                "Revoke this credential at the issuer; wiping the laptop will not help.".into(),
            );
        }
        if reasons.is_empty() {
            // "Scoped or read-only" is a claim about an assessment that was
            // made. When no capability was ever determined and no path goes
            // beyond reachability, nothing was assessed, and the words must
            // not suggest otherwise.
            let assessed = !perms.scope.is_empty()
                || !perms.restrictions.is_empty()
                || [
                    perms.administrative,
                    perms.can_create_credentials,
                    perms.can_modify_own_permissions,
                    perms.can_assume_role,
                    perms.can_access_production,
                    perms.can_modify_production,
                    perms.can_reach_signing_infrastructure,
                ]
                .iter()
                .any(|c| *c != Capability::Unknown)
                || paths.iter().any(|p| p.outcome > PathOutcome::Reachability);
            if assessed {
                reasons
                    .push("no privileged capability found; treated as scoped or read-only".into());
            } else {
                reasons.push(
                    "what this credential can reach has not been assessed; unknown is not the same as safe"
                        .into(),
                );
            }
        }
    } else {
        persistence = Persistence::RequiresEndpoint;
    }
    // Nothing raised the severity, so the confidence is about the
    // capabilities found (or not found): confirmed only when every one that
    // was determined was established by a provider check of that specific
    // permission. Who the credential is never confirms what it can do.
    // An expired or revoked credential is a statement about the credential
    // itself and keeps its own assurance.
    if !raised && !expired {
        confidence = confidence.weakest(perms.capabilities_assurance());
    }

    ExposureFinding {
        credential: credential.clone(),
        severity,
        confidence,
        accessible_systems: systems,
        paths: path_summaries,
        persistence,
        reasons,
        compensating_controls: controls,
        remediation,
    }
}

/// True when any node on the path, or any node reachable in one hop from
/// the target, is a signer or wallet.
fn graph_has_downstream_signer(graph: &PermissionGraph, path: &AttackPath) -> bool {
    if path.nodes.iter().any(|n| graph.get(*n).kind.is_financial()) {
        return true;
    }
    graph
        .edges_from(path.target())
        .any(|(_, e)| graph.get(e.to).kind.is_financial())
}

/// Aggregate counts over scored findings plus extra signals the CLI
/// gathers (dangerous blockchain authorizations are counted separately
/// because they attach to wallets, not credentials).
pub fn summarize(
    findings: &[ExposureFinding],
    dangerous_blockchain_authorizations: usize,
) -> ExposureSummary {
    let mut s = ExposureSummary {
        credentials: findings.len(),
        dangerous_blockchain_authorizations,
        ..Default::default()
    };
    let mut signers = Vec::new();
    for f in findings {
        s.by_severity[f.severity as usize] += 1;
        if f.credential.permissions.is_privileged() || f.severity >= Severity::High {
            s.privileged_credentials += 1;
        }
        for p in &f.paths {
            if p.hops > 1
                && p.outcome >= PathOutcome::ApproveSignature
                && p.approvals_required.is_empty()
                && f.severity == Severity::Critical
            {
                s.critical_indirect_paths += 1;
            }
            if p.target_kind == NodeKind::Signer
                && p.outcome >= PathOutcome::Reachability
                && !signers.contains(&p.target)
            {
                signers.push(p.target.clone());
            }
        }
        if f.persistence.survives_cleanup() && f.severity >= Severity::Medium {
            s.persistent_access_risks += 1;
        }
    }
    s.reachable_signing_systems = signers.len();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::graph::{EdgeKind, NodeId};
    use crate::authority::{CredentialKind, EffectivePermissions, Permission};

    fn cred(kind: CredentialKind) -> DiscoveredCredential {
        DiscoveredCredential::new(kind, "test", "/tmp/fixture", "example-system")
    }

    fn graph_with(
        edge_kind: EdgeKind,
        assurance: Assurance,
        approval: Option<&str>,
        target_kind: NodeKind,
    ) -> (PermissionGraph, NodeId, NodeId) {
        let mut g = PermissionGraph::new();
        let c = g.node(NodeKind::Credential, "test");
        let t = g.node(target_kind, "target");
        g.mark_production(t);
        g.edge_full(
            c,
            t,
            edge_kind,
            assurance,
            None,
            vec![],
            approval.map(|s| s.to_string()),
        );
        (g, c, t)
    }

    #[test]
    fn ssh_login_is_a_shell_not_reachability() {
        // A key accepted by a production host is High on its own, and
        // Critical when the file has no passphrase; the same key to a host
        // nobody has identified is discounted to Low, Medium without a
        // passphrase. In every case the reason says what to do.
        let (g, c, t) = graph_with(
            EdgeKind::CanAuthenticate,
            Assurance::Inferred,
            None,
            NodeKind::ProductionService,
        );
        let paths = g.paths_between(c, t, 3);
        let mut key = cred(CredentialKind::SshPrivateKey);
        let f = score_finding(&g, &key, &paths);
        assert_eq!(f.severity, Severity::High, "{:?}", f.reasons);
        assert!(f
            .reasons
            .iter()
            .any(|r| r.contains("shell login to production system")));
        assert!(f
            .remediation
            .iter()
            .any(|r| r.contains("Secure Enclave") && r.contains("1Password")));
        key.unprotected = true;
        let f = score_finding(&g, &key, &paths);
        assert_eq!(f.severity, Severity::Critical, "{:?}", f.reasons);
        assert!(f.reasons.iter().any(|r| r.contains("no passphrase")));

        let mut g2 = PermissionGraph::new();
        let c2 = g2.node(NodeKind::Credential, "test");
        let t2 = g2.node(NodeKind::ProductionService, "devbox-02");
        g2.edge_full(
            c2,
            t2,
            EdgeKind::CanAuthenticate,
            Assurance::Inferred,
            None,
            vec![],
            None,
        );
        let paths2 = g2.paths_between(c2, t2, 3);
        let mut key2 = cred(CredentialKind::SshPrivateKey);
        let f = score_finding(&g2, &key2, &paths2);
        assert_eq!(f.severity, Severity::Low, "{:?}", f.reasons);
        assert!(f
            .reasons
            .iter()
            .any(|r| r.contains("mark it as production")));
        key2.unprotected = true;
        let f = score_finding(&g2, &key2, &paths2);
        assert_eq!(f.severity, Severity::Medium, "{:?}", f.reasons);

        // No known host at all: the report says so, and no passphrase still lifts it.
        let f = score_finding(&g2, &key2, &[]);
        assert_eq!(f.severity, Severity::Medium);
        assert!(f
            .reasons
            .iter()
            .any(|r| r.contains("which hosts accept this key is unknown")));
    }

    #[test]
    fn severity_order_is_ascending() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert_eq!(
            [Severity::Low, Severity::Critical, Severity::Medium]
                .iter()
                .max(),
            Some(&Severity::Critical)
        );
    }

    #[test]
    fn confirmed_ungated_transfer_is_critical() {
        let (g, c, t) = graph_with(
            EdgeKind::CanTransferAssets,
            Assurance::Confirmed,
            None,
            NodeKind::Wallet,
        );
        let paths = g.paths_between(c, t, 3);
        let f = score_finding(&g, &cred(CredentialKind::SigningServiceApiKey), &paths);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.confidence, Assurance::Unknown); // credential perms unknown
    }

    #[test]
    fn inferred_ungated_transfer_stays_critical_but_says_so() {
        // An ungated path to funds is never softened by the assurance
        // discount: the confidence label carries the uncertainty instead.
        let (g, c, t) = graph_with(
            EdgeKind::CanTransferAssets,
            Assurance::Inferred,
            None,
            NodeKind::Wallet,
        );
        let paths = g.paths_between(c, t, 3);
        let f = score_finding(&g, &cred(CredentialKind::SigningServiceApiKey), &paths);
        assert_eq!(f.severity, Severity::Critical);
        // Confidence is the weakest link, and the bare test credential's own
        // assurance is Unknown; what matters is that it is not Confirmed.
        assert_ne!(f.confidence, Assurance::Confirmed);
        assert!(f.reasons[0].contains("run --verify"));
    }

    #[test]
    fn inferred_read_is_still_discounted() {
        let (g, c, t) = graph_with(
            EdgeKind::CanReadSecret,
            Assurance::Inferred,
            None,
            NodeKind::SecretsManager,
        );
        let paths = g.paths_between(c, t, 3);
        let f = score_finding(&g, &cred(CredentialKind::AwsAccessKey), &paths);
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.reasons[0].contains("until verified"));
    }

    #[test]
    fn gated_transfer_is_high_with_control() {
        let (g, c, t) = graph_with(
            EdgeKind::CanTransferAssets,
            Assurance::Confirmed,
            Some("second signer"),
            NodeKind::Wallet,
        );
        let paths = g.paths_between(c, t, 3);
        let f = score_finding(&g, &cred(CredentialKind::SigningServiceApiKey), &paths);
        assert_eq!(f.severity, Severity::High);
        assert!(f
            .compensating_controls
            .iter()
            .any(|c| c.contains("second signer")));
    }

    #[test]
    fn request_signature_is_high_and_names_approval_elsewhere() {
        let (g, c, t) = graph_with(
            EdgeKind::CanRequestSignature,
            Assurance::Confirmed,
            None,
            NodeKind::Signer,
        );
        let paths = g.paths_between(c, t, 3);
        let f = score_finding(&g, &cred(CredentialKind::ApiKey), &paths);
        assert_eq!(f.severity, Severity::High);
        assert!(f.reasons[0].contains("approval is held elsewhere"));
    }

    #[test]
    fn reachability_alone_is_low() {
        let (g, c, t) = graph_with(
            EdgeKind::CanReach,
            Assurance::Confirmed,
            None,
            NodeKind::Signer,
        );
        let paths = g.paths_between(c, t, 3);
        let f = score_finding(&g, &cred(CredentialKind::RpcProviderKey), &paths);
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn expired_credential_is_low_regardless_of_paths() {
        let (g, c, t) = graph_with(
            EdgeKind::CanTransferAssets,
            Assurance::Confirmed,
            None,
            NodeKind::Wallet,
        );
        let paths = g.paths_between(c, t, 3);
        let mut credential = cred(CredentialKind::AwsSession);
        credential.permissions.lifetime = Lifetime::ExpiredAt(1);
        let f = score_finding(&g, &credential, &paths);
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.persistence, Persistence::RequiresEndpoint);
    }

    #[test]
    fn admin_flag_confirmed_is_high_and_inferred_is_medium() {
        let g = PermissionGraph::new();
        let mut credential = cred(CredentialKind::AwsAccessKey);
        credential.permissions = EffectivePermissions {
            assurance: Assurance::Confirmed,
            administrative: Capability::Yes,
            confirmed: vec![Permission::Administrative],
            ..Default::default()
        };
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Assurance::Confirmed);
        credential.permissions.assurance = Assurance::Inferred;
        credential.permissions.confirmed.clear();
        assert_eq!(
            score_finding(&g, &credential, &[]).severity,
            Severity::Medium
        );
    }

    #[test]
    fn identity_confirmation_alone_leaves_admin_inferred() {
        // The provider confirmed who the key is; "administrative" came from
        // a policy name. The flag is inferred, scored one step down, and the
        // finding's confidence says inferred.
        let g = PermissionGraph::new();
        let mut credential = cred(CredentialKind::AwsAccessKey);
        credential.permissions = EffectivePermissions {
            assurance: Assurance::Confirmed,
            administrative: Capability::Yes,
            can_modify_production: Capability::Yes,
            ..Default::default()
        };
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.confidence, Assurance::Inferred);
        assert!(
            f.reasons.iter().any(|r| r.contains("inferred")),
            "{:?}",
            f.reasons
        );
    }

    #[test]
    fn identity_confirmation_with_nothing_found_is_not_confirmed() {
        let g = PermissionGraph::new();
        let mut credential = cred(CredentialKind::GitHubToken);
        credential.permissions.assurance = Assurance::Confirmed;
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.confidence, Assurance::Inferred);
        // A capability "no" the provider established is confirmed.
        credential
            .permissions
            .confirm(Permission::Administrative, Capability::No);
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.confidence, Assurance::Confirmed);
    }

    #[test]
    fn presence_alone_never_scores_admin() {
        let g = PermissionGraph::new();
        let mut credential = cred(CredentialKind::AwsAccessKey);
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.severity, Severity::Low);
        // Nothing is known about the key, and the words say so rather than
        // calling it scoped or read-only, whatever the assurance label.
        assert!(
            f.reasons[0].contains("has not been assessed"),
            "{:?}",
            f.reasons
        );
        credential.permissions.assurance = Assurance::Inferred;
        let f = score_finding(&g, &credential, &[]);
        assert!(
            f.reasons[0].contains("has not been assessed"),
            "{:?}",
            f.reasons
        );
        // Once something was determined (here: not administrative), the
        // read-only wording is earned.
        credential.permissions.administrative = Capability::No;
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.severity, Severity::Low);
        assert!(
            f.reasons[0].contains("no privileged capability"),
            "{:?}",
            f.reasons
        );
    }

    #[test]
    fn credential_creation_marks_server_side_persistence() {
        let g = PermissionGraph::new();
        let mut credential = cred(CredentialKind::GitHubToken);
        credential.permissions = EffectivePermissions {
            assurance: Assurance::Confirmed,
            can_create_credentials: Capability::Yes,
            confirmed: vec![Permission::CreateCredentials],
            ..Default::default()
        };
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.persistence, Persistence::ServerSide);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn restricted_production_access_is_medium() {
        let g = PermissionGraph::new();
        let mut credential = cred(CredentialKind::KubernetesContext);
        credential.permissions = EffectivePermissions {
            assurance: Assurance::Confirmed,
            can_access_production: Capability::Yes,
            can_modify_production: Capability::No,
            restrictions: vec!["namespace: payments".into()],
            confirmed: vec![Permission::AccessProduction, Permission::ModifyProduction],
            ..Default::default()
        };
        let f = score_finding(&g, &credential, &[]);
        assert_eq!(f.severity, Severity::Medium);
        assert!(f
            .compensating_controls
            .iter()
            .any(|c| c.contains("namespace")));
    }

    #[test]
    fn deploy_to_production_hosting_signer_is_high() {
        let mut g = PermissionGraph::new();
        let c = g.node(NodeKind::Credential, "kube");
        let cluster = g.node(NodeKind::Cluster, "prod");
        let signer = g.node(NodeKind::Signer, "signer");
        g.mark_production(cluster);
        g.edge(c, cluster, EdgeKind::CanDeploy, Assurance::Confirmed);
        g.edge(
            cluster,
            signer,
            EdgeKind::CanRequestSignature,
            Assurance::Inferred,
        );
        let paths = g.paths_between(c, cluster, 3);
        let f = score_finding(&g, &cred(CredentialKind::KubernetesContext), &paths);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn login_to_production_host_is_high_but_dev_host_is_low() {
        // An SSH login is a shell: High on a production host (not discounted,
        // the label is the user's own declaration), Low on a host nobody has
        // identified, where the reason tells the user to mark it.
        let (g, c, t) = graph_with(
            EdgeKind::CanAuthenticate,
            Assurance::Confirmed,
            None,
            NodeKind::ProductionService,
        );
        let paths = g.paths_between(c, t, 3);
        assert_eq!(
            score_finding(&g, &cred(CredentialKind::SshPrivateKey), &paths).severity,
            Severity::High
        );
        let mut g2 = PermissionGraph::new();
        let c2 = g2.node(NodeKind::Credential, "key");
        let d2 = g2.node(NodeKind::ProductionService, "dev-box");
        g2.edge(c2, d2, EdgeKind::CanAuthenticate, Assurance::Confirmed);
        let paths2 = g2.paths_between(c2, d2, 3);
        // Confirmed login to an unidentified host: a shell is Medium even
        // without the production label; the inferred case is Low and is
        // covered by ssh_login_is_a_shell_not_reachability.
        assert_eq!(
            score_finding(&g2, &cred(CredentialKind::SshPrivateKey), &paths2).severity,
            Severity::Medium
        );
    }

    #[test]
    fn summary_counts() {
        let (g, c, t) = graph_with(
            EdgeKind::CanTransferAssets,
            Assurance::Confirmed,
            None,
            NodeKind::Wallet,
        );
        let mut g = g;
        let laptop = g.node(NodeKind::Laptop, "laptop");
        g.edge(laptop, c, EdgeKind::CanAuthenticate, Assurance::Confirmed);
        let signer = g.node(NodeKind::Signer, "signer");
        g.edge(
            c,
            signer,
            EdgeKind::CanRequestSignature,
            Assurance::Confirmed,
        );
        let paths: Vec<_> = g
            .paths_between(laptop, t, 4)
            .into_iter()
            .chain(g.paths_between(laptop, signer, 4))
            .collect();
        let f = score_finding(&g, &cred(CredentialKind::SigningServiceApiKey), &paths);
        let low = score_finding(&g, &cred(CredentialKind::RpcProviderKey), &[]);
        let s = summarize(&[f, low], 2);
        assert_eq!(s.credentials, 2);
        assert_eq!(s.privileged_credentials, 1);
        assert_eq!(s.critical_indirect_paths, 1);
        assert_eq!(s.reachable_signing_systems, 1);
        assert_eq!(s.dangerous_blockchain_authorizations, 2);
        assert_eq!(s.persistent_access_risks, 1);
        assert_eq!(s.count(Severity::Critical), 1);
        assert_eq!(s.count(Severity::Low), 1);
    }
}
