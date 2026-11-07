// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Read-only local discovery of credentials and authenticated sessions.
//!
//! Every source here reads files the user already owns, extracts metadata,
//! and throws the secret away. The only things that leave this module are
//! fingerprints, identities, expiry times and structural facts. Nothing is
//! exported, exercised, or sent anywhere.

use super::config::Declarations;
use super::parsers::{self, Yaml};
use hedgehog_taint::authority::graph::{EdgeKind, NodeKind};
use hedgehog_taint::authority::{
    redact_text, Assurance, Capability, CredentialKind, DiscoveredCredential, EffectivePermissions,
    Fingerprint, Lifetime, Persistence,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A capability relation a credential has to a system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub kind: NodeKind,
    pub name: String,
    pub edge: EdgeKind,
    pub assurance: Assurance,
    pub scope: Option<String>,
    pub evidence: Vec<String>,
    pub approval: Option<String>,
    pub production: bool,
}

impl Link {
    pub fn new(kind: NodeKind, name: &str, edge: EdgeKind, assurance: Assurance) -> Self {
        Self {
            kind,
            name: name.to_string(),
            edge,
            assurance,
            scope: None,
            evidence: Vec::new(),
            approval: None,
            production: false,
        }
    }
    pub fn evidence(mut self, e: &str) -> Self {
        self.evidence.push(redact_text(e));
        self
    }
    pub fn scope(mut self, s: &str) -> Self {
        self.scope = Some(s.to_string());
        self
    }
    pub fn approval(mut self, a: Option<String>) -> Self {
        self.approval = a;
        self
    }
    pub fn production(mut self, p: bool) -> Self {
        self.production = p;
        self
    }
}

#[derive(Debug, Clone)]
pub struct Discovered {
    pub credential: DiscoveredCredential,
    pub links: Vec<Link>,
    /// Name to use when matching `--verify` results back (profile, context, host).
    pub verify_key: Option<String>,
    /// The file this credential was read from, as an absolute path, or
    /// `None` when it came from the environment or a running agent. The
    /// display `location` is for people and may carry a note in
    /// parentheses; verification and coverage use this path, never a path
    /// recovered from the location text (a file may itself be named
    /// `config (production).yaml`).
    pub source: Option<PathBuf>,
}

/// Everything discovery needs; constructed explicitly so tests can point it
/// at a fixture home and a synthetic environment.
pub struct Context<'a> {
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub decl: &'a Declarations,
    pub now: u64,
    /// Human-readable notes about sources that could not be read.
    pub notes: Vec<String>,
    /// Known credential locations that exist but could not be read or
    /// parsed. Every source records its failures here as well as in
    /// `notes`, so a check that lost coverage is reported as incomplete
    /// rather than as a clean run with fewer findings.
    pub coverage_failures: Vec<CoverageFailure>,
    /// Set by a source that could not ask what it covers at all (no SSH
    /// agent named in this environment): the source is not assessed, with
    /// this reason, but no location failed. Previous findings of the
    /// source then become unassessed when the run is recorded.
    pub source_unavailable: Option<String>,
}

/// A known credential location that exists but could not be read: a
/// permission error, an I/O error or a file that is present but does not
/// parse. Never carries file contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageFailure {
    /// Display path (`~/...`) or the name of the engine that failed.
    pub location: String,
    pub reason: String,
}

impl<'a> Context<'a> {
    pub fn from_process(decl: &'a Declarations) -> Self {
        let home = crate::content_scanner::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
        let env = std::env::vars().collect();
        Self {
            home,
            cwd,
            env,
            decl,
            now: hedgehog_taint::authority::now_unix(),
            notes: Vec::new(),
            coverage_failures: Vec::new(),
            source_unavailable: None,
        }
    }

    /// Record that a location which exists could not be read: a note for
    /// the report and a structural entry for the coverage check.
    pub(crate) fn coverage_failure(&mut self, p: &Path, reason: String) {
        let location = self.display(p);
        self.notes
            .push(format!("could not read {location}: {reason}"));
        self.coverage_failures
            .push(CoverageFailure { location, reason });
    }

    /// Record that a known credential file exists and has content but its
    /// parser found no credential in it: a format Gorse cannot read is lost
    /// coverage, never a clean result.
    pub(crate) fn could_not_interpret(&mut self, p: &Path) {
        let location = self.display(p);
        let reason = format!("could not interpret {location} (unsupported format)");
        self.notes.push(reason.clone());
        self.coverage_failures
            .push(CoverageFailure { location, reason });
    }

    /// Record that one entry of a credential file (a profile, a context,
    /// a registry, a machine) is in a shape the parser does not understand.
    /// The rest of the file may still parse, but the source is not fully
    /// assessed: that entry's credential may be missing from the findings.
    pub(crate) fn could_not_interpret_entry(&mut self, p: &Path, entry: &str) {
        let location = self.display(p);
        let reason = format!("could not interpret {entry} in {location}");
        self.notes.push(reason.clone());
        self.coverage_failures
            .push(CoverageFailure { location, reason });
    }

    /// Whether a credential location (file or directory) is present and
    /// can be read. Absent (`NotFound`, or a path through a plain file) is
    /// a fact: `false`, nothing recorded. Any other error, a permission
    /// error above all, is lost coverage: recorded, and `false`, because
    /// nothing in it could be assessed. Never use `Path::exists()` on a
    /// credential location: it reports a permission error as absent.
    fn present(&mut self, p: &Path) -> bool {
        let absent = |e: &std::io::Error| {
            e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory
        };
        let opened = match std::fs::metadata(p) {
            Ok(meta) if meta.is_dir() => std::fs::read_dir(p).map(|_| ()),
            Ok(_) => std::fs::File::open(p).map(|_| ()),
            Err(e) => Err(e),
        };
        match opened {
            Ok(()) => true,
            Err(e) if absent(&e) => false,
            Err(e) => {
                self.coverage_failure(p, e.to_string());
                false
            }
        }
    }

    /// List a directory that may hold credential files. `None` when it does
    /// not exist; a directory that exists but cannot be listed is a coverage
    /// failure.
    fn read_dir(&mut self, p: &Path) -> Option<std::fs::ReadDir> {
        match std::fs::read_dir(p) {
            Ok(entries) => Some(entries),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                // A plain file where a directory was expected is not a
                // credential store; a directory that will not list is.
                if p.is_dir() || e.kind() == std::io::ErrorKind::PermissionDenied {
                    self.coverage_failure(p, e.to_string());
                }
                None
            }
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    pub(crate) fn display(&self, p: &Path) -> String {
        match p.strip_prefix(&self.home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => p.display().to_string(),
        }
    }

    fn read(&mut self, p: &Path) -> Option<String> {
        // Only ordinary files, and only up to a size no credential file
        // reaches: a named pipe would block for ever and a device or huge
        // file would exhaust memory. Both are recorded as lost coverage.
        const MAX_BYTES: u64 = 8 * 1024 * 1024;
        match std::fs::metadata(p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Ok(m) if m.is_dir() => return None,
            Ok(m) if !m.is_file() => {
                self.coverage_failure(p, "not an ordinary file; skipped".to_string());
                return None;
            }
            Ok(m) if m.len() > MAX_BYTES => {
                self.coverage_failure(p, "larger than 8 MB; skipped".to_string());
                return None;
            }
            _ => {}
        }
        let read = std::fs::File::open(p).and_then(|f| {
            use std::io::Read;
            let mut text = String::new();
            f.take(MAX_BYTES).read_to_string(&mut text).map(|_| text)
        });
        match read {
            Ok(s) => Some(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                // A directory (`InvalidInput` on some platforms) is not a
                // credential file; everything else that exists but will not
                // read is lost coverage.
                if p.is_dir() {
                    return None;
                }
                self.coverage_failure(p, e.to_string());
                None
            }
        }
    }

    fn read_json(&mut self, p: &Path) -> Option<serde_json::Value> {
        let text = self.read(p)?;
        // The Azure CLI writes its JSON with a UTF-8 byte order mark.
        match serde_json::from_str(text.trim_start_matches('\u{feff}')) {
            Ok(v) => Some(v),
            Err(_) => {
                self.coverage_failure(p, "not valid JSON; skipped".to_string());
                None
            }
        }
    }

    pub(crate) fn expand(&self, p: &str) -> PathBuf {
        if let Some(rest) = p.strip_prefix("~/") {
            self.home.join(rest)
        } else {
            PathBuf::from(p)
        }
    }

    fn is_production(&self, name: &str) -> bool {
        self.decl.is_production_name(name)
    }
}

/// One discovery procedure: a stable id that findings carry as `source`,
/// and the function that runs it.
type Source = (&'static str, fn(&mut Context) -> Vec<Discovered>);

/// Every discovery procedure, in run order. The ids are part of the JSON
/// report (`findings[].source`, `sources_assessed`, `sources_unavailable`)
/// and of change detection: a recorded finding is only reported resolved
/// when the run that no longer has it assessed the same source. Never
/// rename an id.
pub const SOURCES: &[Source] = &[
    ("aws-credentials-file", aws),
    ("gcloud-config", gcp),
    ("azure-cli-profile", azure),
    ("secrets-manager-clis", secrets_managers),
    ("github-cli", github),
    ("ci-tokens", other_ci),
    ("ai-agent-credentials", ai_agents),
    ("docker-config", docker),
    ("kubeconfig", kubernetes),
    ("terraform-credentials", terraform),
    ("doctl-config", digitalocean),
    ("ssh", ssh),
    ("ssh-agent", ssh_agent),
    ("crypto-wallets", crypto_wallets),
    ("declared-signers", declared_signers),
    ("env", environment),
    ("project-env-files", project_env_files),
];

/// What one discovery run covered: the procedures that ran to completion
/// and those that did not, with why. A procedure that hit a coverage
/// failure (a known file it could not read or interpret) is unavailable,
/// so a finding of its that went missing is never taken as resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceCoverage {
    pub assessed: Vec<String>,
    pub unavailable: Vec<(String, String)>,
}

/// Run every discovery source. Each finding is paired with the id of the
/// source that found it.
pub fn discover_sources(ctx: &mut Context) -> (Vec<(Discovered, &'static str)>, SourceCoverage) {
    let mut out = Vec::new();
    let mut coverage = SourceCoverage::default();
    for (id, run) in SOURCES {
        let before = ctx.coverage_failures.len();
        ctx.source_unavailable = None;
        out.extend(run(ctx).into_iter().map(|d| (d, *id)));
        let unavailable = ctx.source_unavailable.take();
        let failures = &ctx.coverage_failures[before..];
        if failures.is_empty() {
            match unavailable {
                Some(reason) => coverage.unavailable.push((id.to_string(), reason)),
                None => coverage.assessed.push(id.to_string()),
            }
        } else {
            let reason = failures
                .iter()
                .map(|f| format!("{}: {}", f.location, f.reason))
                .collect::<Vec<_>>()
                .join("; ");
            coverage.unavailable.push((id.to_string(), reason));
        }
    }
    (dedupe(out), coverage)
}

/// Run every discovery source, without the source ids.
#[cfg(test)]
pub fn discover_all(ctx: &mut Context) -> Vec<Discovered> {
    discover_sources(ctx)
        .0
        .into_iter()
        .map(|(d, _)| d)
        .collect()
}

/// Whether a configuration file has anything in it besides blank lines and
/// comments.
fn has_content(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim().trim_start_matches('\u{feff}');
        !l.is_empty() && !l.starts_with('#') && !l.starts_with(';')
    })
}

/// The same secret can be found by two sources (a declared signer's env var
/// is also a generic environment secret). Keep the most specific record.
fn dedupe<T>(found: Vec<(Discovered, T)>) -> Vec<(Discovered, T)> {
    let generic = |k: CredentialKind| {
        matches!(
            k,
            CredentialKind::EnvironmentSecret | CredentialKind::ApiKey | CredentialKind::Other
        )
    };
    let mut out: Vec<(Discovered, T)> = Vec::with_capacity(found.len());
    for (d, tag) in found {
        if d.credential.fingerprint.0 == "—" {
            out.push((d, tag));
            continue;
        }
        if let Some(existing) = out.iter_mut().find(|(e, _)| {
            e.credential.fingerprint == d.credential.fingerprint
                && e.credential.location == d.credential.location
        }) {
            if generic(existing.0.credential.kind) && !generic(d.credential.kind) {
                *existing = (d, tag);
            }
            continue;
        }
        out.push((d, tag));
    }
    out
}

fn lifetime_from_rfc3339(text: &str, now: u64) -> Lifetime {
    match chrono::DateTime::parse_from_rfc3339(text) {
        Ok(t) => {
            let ts = t.timestamp().max(0) as u64;
            if ts <= now {
                Lifetime::ExpiredAt(ts)
            } else {
                Lifetime::ExpiresAt(ts)
            }
        }
        Err(_) => Lifetime::Unknown,
    }
}

fn apply_role_hint(decl: &Declarations, name: &str, perms: &mut EffectivePermissions) {
    if let Some(hint) = decl.role_hint(name) {
        perms.assurance = perms.assurance.weakest(Assurance::Inferred);
        if hint.administrative {
            perms.administrative = Capability::Yes;
            perms.can_modify_production = Capability::Yes;
        }
        if hint.can_create_credentials {
            perms.can_create_credentials = Capability::Yes;
        }
        if hint.production {
            perms.can_access_production = Capability::Yes;
        }
        if hint.read_only {
            perms.administrative = Capability::No;
            perms.can_modify_production = Capability::No;
        }
        return;
    }
    let lower = name.to_ascii_lowercase();
    if lower.contains("administrator")
        || lower.contains("admin")
        || lower.contains("owner")
        || lower.contains("poweruser")
    {
        perms.administrative = Capability::Yes;
        perms.assurance = Assurance::Inferred;
    } else if lower.contains("deploy")
        || lower.contains("write")
        || lower.contains("operator")
        || lower.contains("editor")
    {
        perms.can_modify_production = Capability::Yes;
        perms.assurance = Assurance::Inferred;
    } else if lower.contains("readonly")
        || lower.contains("read-only")
        || lower.contains("viewer")
        || lower.contains("auditor")
    {
        perms.administrative = Capability::No;
        perms.can_modify_production = Capability::No;
        perms.assurance = Assurance::Inferred;
    }
}

fn attach_declared_systems(
    ctx: &Context,
    host_name: &str,
    cred_links: &mut Vec<Link>,
    edge: EdgeKind,
    assurance: Assurance,
) {
    for system in ctx.decl.systems_hosting(host_name) {
        let kind = match system.kind.as_str() {
            "cluster" => NodeKind::Cluster,
            "ci" => NodeKind::CiSystem,
            "secrets_manager" => NodeKind::SecretsManager,
            "registry" => NodeKind::Registry,
            "repository" => NodeKind::Repository,
            _ => NodeKind::ProductionService,
        };
        cred_links.push(
            Link::new(kind, &system.name, edge, assurance)
                .evidence(&format!(
                    "declared in authority.toml: {} hosts {host_name}",
                    system.name
                ))
                .approval(system.change_approval.clone())
                .production(true),
        );
    }
}

// ─── AWS ─────────────────────────────────────────────────────────────────────

fn aws(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let creds_path = ctx.path(".aws/credentials");
    let config_path = ctx.path(".aws/config");
    let creds_text = ctx.read(&creds_path);
    let creds = creds_text
        .as_deref()
        .map(parsers::parse_ini)
        .unwrap_or_default();
    let config_text = ctx.read(&config_path);
    let config = config_text
        .as_deref()
        .map(parsers::parse_ini)
        .unwrap_or_default();
    // A credentials file holds keys by definition; one with content but no
    // profile carrying a credential key is in a shape the parser missed.
    const CREDENTIAL_KEYS: &[&str] = &[
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "credential_process",
        "role_arn",
        "sso_start_url",
        "sso_session",
    ];
    if creds_text.as_deref().is_some_and(has_content)
        && !creds
            .iter()
            .any(|(_, m)| m.keys().any(|k| CREDENTIAL_KEYS.contains(&k.as_str())))
    {
        ctx.could_not_interpret(&creds_path);
    }
    // The config file may hold only regions, but never nothing at all.
    if config_text.as_deref().is_some_and(has_content) && config.is_empty() {
        ctx.could_not_interpret(&config_path);
    }

    // Each profile is checked on its own: one with a line the parser cannot
    // read, or with an access key id and no secret (or the reverse), is a
    // profile whose credential may be missing. It is reported and skipped,
    // and the source is not assessed, so its earlier finding is never
    // taken as resolved.
    let mut broken: std::collections::BTreeSet<String> = Default::default();
    for (path, text, sections, is_config) in [
        (&creds_path, &creds_text, &creds, false),
        (&config_path, &config_text, &config, true),
    ] {
        let Some(text) = text else { continue };
        let mut bad = parsers::ini_malformed_sections(text);
        for (section, map) in sections {
            let has_id = map.contains_key("aws_access_key_id");
            let has_secret = map.contains_key("aws_secret_access_key");
            if has_id != has_secret && !bad.contains(section) {
                bad.push(section.clone());
            }
        }
        for section in bad {
            let name = if is_config {
                section.strip_prefix("profile ").unwrap_or(&section)
            } else {
                section.as_str()
            }
            .trim()
            .to_string();
            let entry = if section.is_empty() {
                "the lines before the first profile".to_string()
            } else {
                format!("profile {name}")
            };
            ctx.could_not_interpret_entry(path, &entry);
            broken.insert(name);
        }
    }

    let mut profiles: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (section, map) in creds {
        profiles.entry(section.clone()).or_default().extend(map);
    }
    for (section, map) in config {
        let name = section
            .strip_prefix("profile ")
            .unwrap_or(&section)
            .to_string();
        if section.starts_with("sso-session ") {
            continue;
        }
        profiles.entry(name).or_default().extend(map);
    }

    for (profile, map) in &profiles {
        if broken.contains(profile) {
            continue;
        }
        let source_path = if map.contains_key("aws_access_key_id") {
            creds_path.clone()
        } else {
            config_path.clone()
        };
        let location = ctx.display(&source_path);
        let mut cred;
        let mut links = Vec::new();
        let account_hint = map.get("sso_account_id").cloned().or_else(|| {
            map.get("role_arn")
                .and_then(|arn| arn.split(':').nth(4).map(|s| s.to_string()))
        });
        if let Some(key_id) = map.get("aws_access_key_id") {
            let temporary = key_id.starts_with("ASIA") || map.contains_key("aws_session_token");
            let kind = if temporary {
                CredentialKind::AwsSession
            } else {
                CredentialKind::AwsAccessKey
            };
            cred = DiscoveredCredential::new(kind, profile, &location, "AWS");
            cred.fingerprint = Fingerprint::from_public_id(key_id);
            cred.permissions.lifetime = if temporary {
                Lifetime::Unknown
            } else {
                Lifetime::LongLived
            };
            cred.permissions.automated = if temporary {
                Capability::No
            } else {
                Capability::Unknown
            };
            cred.evidence.push(if temporary {
                "temporary STS credentials (ASIA… or session token present)".into()
            } else {
                "long-lived IAM access key (AKIA…): works until deleted".into()
            });
            cred.persistence = Persistence::IndependentCredential;
        } else if map.contains_key("sso_start_url") || map.contains_key("sso_session") {
            cred =
                DiscoveredCredential::new(CredentialKind::AwsSsoSession, profile, &location, "AWS");
            cred.fingerprint = Fingerprint::from_secret(
                format!(
                    "{}|{}|{}",
                    map.get("sso_start_url").map(String::as_str).unwrap_or(""),
                    map.get("sso_account_id").map(String::as_str).unwrap_or(""),
                    map.get("sso_role_name").map(String::as_str).unwrap_or("")
                )
                .as_bytes(),
            );
            cred.evidence.push(format!(
                "SSO profile: account {} role {}",
                map.get("sso_account_id").map(String::as_str).unwrap_or("?"),
                map.get("sso_role_name").map(String::as_str).unwrap_or("?")
            ));
            cred.permissions.requires_mfa = Capability::Unknown;
            cred.persistence = Persistence::RequiresEndpoint;
            if let Some(role) = map.get("sso_role_name") {
                apply_role_hint(ctx.decl, role, &mut cred.permissions);
                cred.permissions.scope.push(format!("SSO role {role}"));
            }
            // Session validity comes from the SSO cache below.
            cred.permissions.lifetime =
                sso_cache_lifetime(ctx, map.get("sso_start_url").map(String::as_str));
            if cred.permissions.lifetime.is_expired() {
                cred.evidence
                    .push("no unexpired SSO cache entry: a new browser login is needed".into());
            }
        } else if map.contains_key("role_arn") {
            cred = DiscoveredCredential::new(
                CredentialKind::AwsProfileRole,
                profile,
                &location,
                "AWS",
            );
            cred.persistence = Persistence::IndependentCredential;
        } else if map.contains_key("credential_process") {
            cred = DiscoveredCredential::new(CredentialKind::AwsSession, profile, &location, "AWS");
            cred.evidence
                .push("credentials come from an external credential_process".into());
            cred.persistence = Persistence::RequiresEndpoint;
        } else {
            continue; // region-only profile
        }
        if let Some(acct) = &account_hint {
            cred.permissions.organization = Some(format!("AWS account {acct}"));
        }
        if let Some(arn) = map.get("role_arn") {
            let role_name = arn.rsplit('/').next().unwrap_or(arn);
            let mut role_perms = EffectivePermissions {
                assurance: Assurance::Inferred,
                ..Default::default()
            };
            apply_role_hint(ctx.decl, arn, &mut role_perms);
            cred.permissions.can_assume_role = Capability::Yes;
            cred.permissions.assurance = Assurance::Inferred;
            let gate = map
                .get("mfa_serial")
                .map(|_| "MFA (mfa_serial configured)".to_string());
            if gate.is_some() {
                cred.permissions.requires_mfa = Capability::Yes;
            }
            let production = ctx.is_production(arn);
            cred.fingerprint = Fingerprint::from_secret(arn.as_bytes());
            if production {
                cred.permissions.can_access_production = Capability::Yes;
                if role_perms.can_modify_production.is_yes() {
                    cred.permissions.can_modify_production = Capability::Yes;
                    cred.evidence.push(format!("role name '{role_name}' suggests write access to production (name-based inference)"));
                }
            }
            let mut link = Link::new(
                NodeKind::CloudRole,
                arn,
                EdgeKind::CanAssumeRole,
                Assurance::Inferred,
            )
            .evidence(&format!("role_arn in profile {profile}"))
            .approval(gate)
            .production(production);
            if let Some(src) = map.get("source_profile") {
                link = link.evidence(&format!("source_profile {src}"));
            }
            links.push(link);
            if role_perms.administrative.is_yes() {
                cred.permissions.administrative = Capability::Yes;
                cred.permissions.can_modify_production = if production {
                    Capability::Yes
                } else {
                    Capability::Unknown
                };
                cred.evidence.push(format!(
                    "role name '{role_name}' suggests administrative scope (name-based inference)"
                ));
            }
            attach_declared_systems(
                ctx,
                arn,
                &mut links,
                EdgeKind::CanModifyConfiguration,
                Assurance::Inferred,
            );
            if let Some(acct) = arn.split(':').nth(4) {
                attach_declared_systems(
                    ctx,
                    acct,
                    &mut links,
                    EdgeKind::CanModifyConfiguration,
                    Assurance::Inferred,
                );
            }
        }
        if let Some(acct) = &account_hint {
            if ctx.is_production(acct) {
                cred.permissions.can_access_production = Capability::Yes;
            }
        }
        out.push(Discovered {
            credential: cred,
            links,
            verify_key: Some(profile.clone()),
            source: Some(source_path),
        });
    }

    // Cached assumed-role sessions carry the real ARN and an expiry.
    let cache_dir = ctx.path(".aws/cli/cache");
    if let Some(entries) = ctx.read_dir(&cache_dir) {
        for entry in entries.flatten() {
            let Some(v) = ctx.read_json(&entry.path()) else {
                continue;
            };
            let arn = v["AssumedRoleUser"]["Arn"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let expiry = v["Credentials"]["Expiration"].as_str().unwrap_or("");
            let key_id = v["Credentials"]["AccessKeyId"].as_str().unwrap_or("");
            let name = arn
                .rsplit('/')
                .nth(1)
                .unwrap_or("cached session")
                .to_string();
            let mut cred = DiscoveredCredential::new(
                CredentialKind::AwsSession,
                &name,
                &ctx.display(&entry.path()),
                "AWS",
            );
            cred.fingerprint = Fingerprint::from_public_id(key_id);
            cred.permissions.identity = if arn.is_empty() {
                None
            } else {
                Some(arn.clone())
            };
            cred.permissions.lifetime = lifetime_from_rfc3339(expiry, ctx.now);
            cred.permissions.assurance = Assurance::Inferred;
            cred.persistence = Persistence::IndependentCredential;
            cred.evidence
                .push("cached STS session from a previous assume-role".into());
            apply_role_hint(ctx.decl, &arn, &mut cred.permissions);
            out.push(Discovered {
                credential: cred,
                links: Vec::new(),
                verify_key: None,
                source: Some(entry.path()),
            });
        }
    }

    // Environment credentials.
    if let Some(key_id) = ctx.env.get("AWS_ACCESS_KEY_ID") {
        let temporary = ctx.env.contains_key("AWS_SESSION_TOKEN") || key_id.starts_with("ASIA");
        let kind = if temporary {
            CredentialKind::AwsSession
        } else {
            CredentialKind::AwsAccessKey
        };
        let mut cred =
            DiscoveredCredential::new(kind, "environment", "env AWS_ACCESS_KEY_ID", "AWS");
        cred.fingerprint = Fingerprint::from_public_id(key_id);
        cred.permissions.lifetime = if temporary {
            Lifetime::Unknown
        } else {
            Lifetime::LongLived
        };
        cred.persistence = Persistence::IndependentCredential;
        out.push(Discovered {
            credential: cred,
            links: Vec::new(),
            verify_key: None,
            source: None,
        });
    }
    out
}

fn sso_cache_lifetime(ctx: &mut Context, start_url: Option<&str>) -> Lifetime {
    let dir = ctx.path(".aws/sso/cache");
    let mut best = Lifetime::Unknown;
    let Some(entries) = ctx.read_dir(&dir) else {
        return best;
    };
    for entry in entries.flatten() {
        let Some(v) = ctx.read_json(&entry.path()) else {
            continue;
        };
        if let (Some(url), Some(wanted)) = (v["startUrl"].as_str(), start_url) {
            if url != wanted {
                continue;
            }
        }
        if let Some(exp) = v["expiresAt"].as_str() {
            let lt = lifetime_from_rfc3339(exp, ctx.now);
            match (&best, &lt) {
                (_, Lifetime::ExpiresAt(_)) => best = lt,
                (Lifetime::Unknown, Lifetime::ExpiredAt(_)) => best = lt,
                _ => {}
            }
        }
    }
    best
}

// ─── Google Cloud ────────────────────────────────────────────────────────────

fn gcp(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let adc = ctx.path(".config/gcloud/application_default_credentials.json");
    if let Some(v) = ctx.read_json(&adc) {
        let mut d = gcp_credential_from_json(
            ctx,
            &v,
            &ctx.display(&adc),
            "application default credentials",
        );
        d.source = Some(adc.clone());
        out.push(d);
    }
    if let Some(path) = ctx.env.get("GOOGLE_APPLICATION_CREDENTIALS").cloned() {
        let p = PathBuf::from(&path);
        if let Some(v) = ctx.read_json(&p) {
            out.push(gcp_credential_from_json(
                ctx,
                &v,
                "env GOOGLE_APPLICATION_CREDENTIALS",
                "service account key file",
            ));
        }
    }
    // Active gcloud account/project.
    let cfg = ctx.path(".config/gcloud/configurations/config_default");
    if let Some(text) = ctx.read(&cfg) {
        let ini = parsers::parse_ini(&text);
        if has_content(&text) && ini.is_empty() {
            ctx.could_not_interpret(&cfg);
        }
        // A section with a line the parser cannot read may hide the account.
        let malformed = parsers::ini_malformed_sections(&text);
        for section in &malformed {
            let entry = if section.is_empty() {
                "the lines before the first section".to_string()
            } else {
                format!("section {section}")
            };
            ctx.could_not_interpret_entry(&cfg, &entry);
        }
        let core = ini
            .iter()
            .find(|(s, _)| s == "core")
            .map(|(_, m)| m.clone())
            .unwrap_or_default();
        if let Some(account) = core.get("account") {
            let mut cred = DiscoveredCredential::new(
                CredentialKind::GcpUserCredential,
                "gcloud active account",
                &ctx.display(&cfg),
                "Google Cloud",
            );
            cred.permissions.identity = Some(account.clone());
            cred.permissions.organization = core.get("project").map(|p| format!("project {p}"));
            cred.permissions.assurance = Assurance::Inferred;
            cred.permissions.automated = Capability::No;
            cred.fingerprint = Fingerprint::from_secret(account.as_bytes());
            cred.persistence = Persistence::IndependentCredential;
            cred.evidence
                .push("gcloud CLI keeps a refresh token for this account until revoked".into());
            let mut links = Vec::new();
            if let Some(project) = core.get("project") {
                if ctx.is_production(project) {
                    cred.permissions.can_access_production = Capability::Yes;
                }
                attach_declared_systems(
                    ctx,
                    project,
                    &mut links,
                    EdgeKind::CanModifyConfiguration,
                    Assurance::Inferred,
                );
            }
            out.push(Discovered {
                credential: cred,
                links,
                verify_key: Some(account.clone()),
                source: Some(cfg.clone()),
            });
        }
    }
    out
}

fn gcp_credential_from_json(
    ctx: &Context,
    v: &serde_json::Value,
    location: &str,
    name: &str,
) -> Discovered {
    let ty = v["type"].as_str().unwrap_or("");
    let mut links = Vec::new();
    let cred = if ty == "service_account" {
        let email = v["client_email"].as_str().unwrap_or("?");
        let mut c = DiscoveredCredential::new(
            CredentialKind::GcpServiceAccount,
            name,
            location,
            "Google Cloud",
        );
        c.permissions.identity = Some(email.to_string());
        c.permissions.organization = v["project_id"].as_str().map(|p| format!("project {p}"));
        c.permissions.lifetime = Lifetime::LongLived;
        c.permissions.automated = Capability::Yes;
        c.permissions.requires_mfa = Capability::No;
        c.permissions.assurance = Assurance::Inferred;
        c.fingerprint = Fingerprint::from_public_id(v["private_key_id"].as_str().unwrap_or(""));
        c.persistence = Persistence::IndependentCredential;
        c.evidence
            .push("service account private key: no MFA, no expiry, usable from anywhere".into());
        if let Some(project) = v["project_id"].as_str() {
            if ctx.is_production(project) {
                c.permissions.can_access_production = Capability::Yes;
            }
            attach_declared_systems(
                ctx,
                project,
                &mut links,
                EdgeKind::CanModifyConfiguration,
                Assurance::Inferred,
            );
        }
        c
    } else {
        let mut c = DiscoveredCredential::new(
            CredentialKind::GcpUserCredential,
            name,
            location,
            "Google Cloud",
        );
        c.permissions.lifetime = Lifetime::LongLived;
        c.permissions.automated = Capability::No;
        c.permissions.assurance = Assurance::Inferred;
        c.fingerprint = Fingerprint::from_public_id(v["client_id"].as_str().unwrap_or(""));
        c.persistence = Persistence::IndependentCredential;
        c.evidence
            .push("OAuth refresh token: survives laptop cleanup until revoked".into());
        c.permissions.organization = v["quota_project_id"]
            .as_str()
            .map(|p| format!("project {p}"));
        c
    };
    Discovered {
        credential: cred,
        links,
        verify_key: None,
        source: None,
    }
}

// ─── Azure ───────────────────────────────────────────────────────────────────

fn azure(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let profile = ctx.path(".azure/azureProfile.json");
    if let Some(v) = ctx.read_json(&profile) {
        // Subscriptions missing or not a list: the file was not understood.
        if !v.is_object() || !v["subscriptions"].is_array() {
            ctx.could_not_interpret(&profile);
        }
        let subs = v["subscriptions"].as_array().cloned().unwrap_or_default();
        for (i, sub) in subs.into_iter().enumerate() {
            if !sub.is_object() {
                ctx.could_not_interpret_entry(&profile, &format!("subscription entry {}", i + 1));
                continue;
            }
            let name = sub["name"].as_str().unwrap_or("subscription");
            let user = sub["user"]["name"].as_str().unwrap_or("?");
            let user_type = sub["user"]["type"].as_str().unwrap_or("user");
            let kind = if user_type == "servicePrincipal" {
                CredentialKind::AzureServicePrincipal
            } else {
                CredentialKind::AzureSession
            };
            let Some(id) = sub["id"].as_str().filter(|id| !id.trim().is_empty()) else {
                ctx.could_not_interpret_entry(&profile, &format!("subscription {name}"));
                continue;
            };
            // Display names are not unique; the id is what binds the check.
            let label = format!("{name} ({id})");
            let mut c = DiscoveredCredential::new(kind, &label, &ctx.display(&profile), "Azure");
            c.permissions.identity = Some(safe_identity(user));
            c.permissions.organization = sub["tenantId"].as_str().map(|t| format!("tenant {t}"));
            c.permissions.automated = if kind == CredentialKind::AzureServicePrincipal {
                Capability::Yes
            } else {
                Capability::No
            };
            c.permissions.assurance = Assurance::Inferred;
            c.fingerprint = Fingerprint::from_public_id(sub["id"].as_str().unwrap_or(""));
            c.persistence = Persistence::IndependentCredential;
            c.evidence.push(
                "Azure CLI token cache (MSAL) holds refresh tokens for this subscription".into(),
            );
            if ctx.is_production(name) {
                c.permissions.can_access_production = Capability::Yes;
            }
            let mut links = Vec::new();
            attach_declared_systems(
                ctx,
                name,
                &mut links,
                EdgeKind::CanModifyConfiguration,
                Assurance::Inferred,
            );
            if let Some(id) = sub["id"].as_str() {
                attach_declared_systems(
                    ctx,
                    id,
                    &mut links,
                    EdgeKind::CanModifyConfiguration,
                    Assurance::Inferred,
                );
            }
            out.push(Discovered {
                credential: c,
                links,
                verify_key: Some(id.to_string()),
                source: Some(profile.clone()),
            });
        }
    }
    let sp = ctx.path(".azure/service_principal_entries.json");
    if let Some(v) = ctx.read_json(&sp) {
        if !v.is_array() {
            ctx.could_not_interpret(&sp);
        }
        for (i, entry) in v
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            if !entry.is_object() {
                ctx.could_not_interpret_entry(&sp, &format!("entry {}", i + 1));
                continue;
            }
            let client = entry["client_id"].as_str().unwrap_or("?");
            let mut c = DiscoveredCredential::new(
                CredentialKind::AzureServicePrincipal,
                "service principal",
                &ctx.display(&sp),
                "Azure",
            );
            c.permissions.identity = Some(client.to_string());
            c.permissions.organization = entry["tenant"].as_str().map(|t| format!("tenant {t}"));
            c.permissions.automated = Capability::Yes;
            c.permissions.lifetime = Lifetime::LongLived;
            c.fingerprint = Fingerprint::from_public_id(client);
            c.persistence = Persistence::IndependentCredential;
            c.evidence
                .push("service principal secret or certificate stored by the CLI".into());
            out.push(Discovered {
                credential: c,
                links: Vec::new(),
                verify_key: None,
                source: Some(sp.clone()),
            });
        }
    }
    out
}

// ─── Secrets managers ────────────────────────────────────────────────────────

fn secrets_managers(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    // ~/.vault-token and VAULT_TOKEN are separate credentials when both
    // exist: each is its own finding, verified with its own token.
    let vault_token = ctx.path(".vault-token");
    let mut found: Vec<(String, String, Option<PathBuf>)> = Vec::new();
    if let Some(t) = ctx.read(&vault_token) {
        if t.trim().is_empty() {
            ctx.could_not_interpret(&vault_token);
        } else {
            found.push((
                t.trim().to_string(),
                ctx.display(&vault_token),
                Some(vault_token.clone()),
            ));
        }
    }
    if let Some(t) = ctx.env.get("VAULT_TOKEN").filter(|t| !t.trim().is_empty()) {
        found.push((t.clone(), "env VAULT_TOKEN".to_string(), None));
    }
    for (material, location, source) in found {
        let addr = ctx
            .env
            .get("VAULT_ADDR")
            .cloned()
            .unwrap_or_else(|| "Vault".into());
        let mut c =
            DiscoveredCredential::new(CredentialKind::VaultToken, "vault token", &location, &addr);
        c.fingerprint = Fingerprint::from_secret(material.as_bytes());
        c.persistence = Persistence::IndependentCredential;
        c.evidence.push(
            match hedgehog_taint::content_patterns::safe_prefix(&material, 4) {
                "hvs." => "service token (hvs.)".to_string(),
                "hvb." => "batch token (hvb.)".to_string(),
                _ => "token format: legacy or unknown".to_string(),
            },
        );
        let links = vec![Link::new(
            NodeKind::SecretsManager,
            &addr,
            EdgeKind::CanReadSecret,
            Assurance::Inferred,
        )
        .evidence("vault token present; policies unknown until verified")];
        out.push(Discovered {
            credential: c,
            links,
            verify_key: Some("vault".into()),
            source,
        });
    }
    let others: &[(&str, &str, &str)] = &[
        (".config/op", "1Password CLI", "1Password"),
        (".doppler/.doppler.yaml", "Doppler CLI", "Doppler"),
        (".infisical", "Infisical CLI", "Infisical"),
        (".config/akeyless", "Akeyless CLI", "Akeyless"),
    ];
    for (rel, name, target) in others {
        let p = ctx.path(rel);
        if ctx.present(&p) {
            let mut c = DiscoveredCredential::new(
                CredentialKind::SecretsManagerAccess,
                name,
                &ctx.display(&p),
                target,
            );
            c.fingerprint = Fingerprint::from_secret(rel.as_bytes());
            c.persistence = Persistence::Unknown;
            c.evidence
                .push("CLI session state present; scope unknown".into());
            let links = vec![Link::new(
                NodeKind::SecretsManager,
                target,
                EdgeKind::CanReadSecret,
                Assurance::Inferred,
            )
            .evidence("CLI configured on this machine")];
            out.push(Discovered {
                credential: c,
                links,
                verify_key: None,
                source: Some(p.clone()),
            });
        }
    }
    out
}

// ─── GitHub ──────────────────────────────────────────────────────────────────

fn github_token_kind(token: &str) -> (&'static str, Lifetime, Capability) {
    if token.starts_with("ghp_") {
        (
            "classic personal access token",
            Lifetime::Unknown,
            Capability::No,
        )
    } else if token.starts_with("gho_") {
        (
            "OAuth token (gh login)",
            Lifetime::LongLived,
            Capability::No,
        )
    } else if token.starts_with("github_pat_") {
        (
            "fine-grained personal access token",
            Lifetime::Unknown,
            Capability::No,
        )
    } else if token.starts_with("ghs_") {
        (
            "GitHub App installation token (1h)",
            Lifetime::Unknown,
            Capability::Yes,
        )
    } else if token.starts_with("ghu_") {
        ("GitHub App user token", Lifetime::Unknown, Capability::No)
    } else {
        (
            "token of unknown format",
            Lifetime::Unknown,
            Capability::Unknown,
        )
    }
}

/// The evidence on a saved gh login whose token is in the system keyring
/// rather than written in hosts.yml.
pub const GH_KEYRING_EVIDENCE: &str = "token stored in the system keyring";

fn github(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let hosts = ctx.path(".config/gh/hosts.yml");
    if let Some(text) = ctx.read(&hosts) {
        let y = parsers::parse_yaml(&text);
        if has_content(&text) && y.entries().is_empty() {
            ctx.could_not_interpret(&hosts);
        }
        for (host, entry) in y.entries() {
            // Each host is a mapping of user, token and protocol; one that
            // is not hides whatever login it was meant to hold.
            if !matches!(entry, Yaml::Map(_)) {
                ctx.could_not_interpret_entry(&hosts, &format!("host {host}"));
                continue;
            }
            let user = entry.str("user").unwrap_or("?").to_string();
            let token = entry.str("oauth_token").map(|s| s.to_string());
            let mut c = DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                &format!("gh login {host}"),
                &ctx.display(&hosts),
                host,
            );
            c.permissions.identity = Some(safe_identity(&user));
            c.permissions.automated = Capability::No;
            c.permissions.assurance = Assurance::Inferred;
            match token {
                Some(t) => {
                    let (desc, lifetime, _) = github_token_kind(&t);
                    c.fingerprint = Fingerprint::from_secret(t.as_bytes());
                    c.permissions.lifetime = lifetime;
                    c.evidence.push(desc.to_string());
                }
                None => c.evidence.push(GH_KEYRING_EVIDENCE.into()),
            }
            c.persistence = Persistence::IndependentCredential;
            c.evidence.push("gh scopes are unknown until verified; `repo` and `workflow` scopes allow pushing code and editing CI".into());
            let mut links = vec![Link::new(
                NodeKind::Repository,
                &format!("{host} repositories"),
                EdgeKind::CanPushCode,
                Assurance::Inferred,
            )
            .evidence("gh login present")];
            for system in &ctx.decl.production_systems {
                if system.kind == "repository" || system.kind == "ci" {
                    if system.hosts.iter().any(|h| h.contains(host.as_str())) {
                        links.push(
                            Link::new(
                                NodeKind::CiSystem,
                                &system.name,
                                EdgeKind::CanPushCode,
                                Assurance::Inferred,
                            )
                            .approval(system.change_approval.clone())
                            .evidence(&format!("declared: {} lives on {host}", system.name))
                            .production(true),
                        );
                    }
                }
            }
            out.push(Discovered {
                credential: c,
                links,
                verify_key: Some(host.clone()),
                source: Some(hosts.clone()),
            });
        }
    }
    for var in ["GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN"] {
        if let Some(t) = ctx.env.get(var) {
            let (desc, lifetime, automated) = github_token_kind(t);
            let mut c = DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                var,
                &format!("env {var}"),
                "github.com",
            );
            c.fingerprint = Fingerprint::from_secret(t.as_bytes());
            c.permissions.lifetime = lifetime;
            c.permissions.automated = automated;
            c.evidence.push(desc.to_string());
            c.persistence = Persistence::IndependentCredential;
            out.push(Discovered {
                credential: c,
                links: Vec::new(),
                verify_key: None,
                source: None,
            });
        }
    }
    let git_creds = ctx.path(".git-credentials");
    if let Some(text) = ctx.read(&git_creds) {
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let host = line
                .split('@')
                .last()
                .unwrap_or("?")
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .map(safe_host)
                .unwrap_or_else(|| "?".to_string());
            // The user is what sits before ':' inside the part before '@'.
            // GitHub's own helper may store the token there instead.
            let user = line
                .split("//")
                .nth(1)
                .and_then(|r| r.split('@').next())
                .and_then(|u| u.split(':').next())
                .map(safe_identity)
                .unwrap_or_else(|| "?".to_string());
            let mut c = DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                &format!("git credential {host}"),
                &ctx.display(&git_creds),
                &host,
            );
            c.permissions.identity = Some(user);
            c.fingerprint = Fingerprint::from_secret(line.as_bytes());
            c.permissions.lifetime = Lifetime::Unknown;
            c.persistence = Persistence::IndependentCredential;
            c.evidence
                .push("plaintext git credential helper store".into());
            let links = vec![Link::new(
                NodeKind::Repository,
                &format!("{host} repositories"),
                EdgeKind::CanPushCode,
                Assurance::Inferred,
            )];
            out.push(Discovered {
                credential: c,
                links,
                verify_key: None,
                source: Some(git_creds.clone()),
            });
        }
    }
    // GitHub App private keys: *.private-key.pem in config/home top level.
    for dir in [ctx.path(".config"), ctx.home.clone(), ctx.path("Downloads")] {
        let Some(entries) = ctx.read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".private-key.pem") {
                let mut c = DiscoveredCredential::new(
                    CredentialKind::GitHubAppKey,
                    &name,
                    &ctx.display(&entry.path()),
                    "github.com",
                );
                c.fingerprint = Fingerprint::from_secret(name.as_bytes());
                c.permissions.lifetime = Lifetime::LongLived;
                c.permissions.automated = Capability::Yes;
                c.permissions.can_create_credentials = Capability::Yes;
                c.permissions.assurance = Assurance::Inferred;
                c.persistence = Persistence::ServerSide;
                c.evidence
                    .push("GitHub App private key mints installation tokens on demand".into());
                out.push(Discovered {
                    credential: c,
                    links: Vec::new(),
                    verify_key: None,
                    source: Some(entry.path()),
                });
            }
        }
    }
    out
}

// ─── Other CI/CD and deployment platforms ────────────────────────────────────

fn other_ci(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    struct Src {
        rel: &'static str,
        name: &'static str,
        target: &'static str,
        kind: CredentialKind,
        edge: EdgeKind,
        node: NodeKind,
        token_key: &'static str,
    }
    let sources = [
        Src {
            rel: ".config/glab-cli/config.yml",
            name: "GitLab CLI",
            target: "gitlab.com",
            kind: CredentialKind::GitLabToken,
            edge: EdgeKind::CanPushCode,
            node: NodeKind::Repository,
            token_key: "token",
        },
        Src {
            rel: ".circleci/cli.yml",
            name: "CircleCI CLI",
            target: "CircleCI",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanModifyConfiguration,
            node: NodeKind::CiSystem,
            token_key: "token",
        },
        Src {
            rel: ".fly/config.yml",
            name: "Fly.io CLI",
            target: "Fly.io",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "access_token",
        },
        Src {
            rel: ".vercel/auth.json",
            name: "Vercel CLI",
            target: "Vercel",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "token",
        },
        Src {
            rel: "Library/Application Support/com.vercel.cli/auth.json",
            name: "Vercel CLI",
            target: "Vercel",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "token",
        },
        // Linux: the CLI keeps its global config in the XDG data folder
        // (documented), and some releases used ~/.config/vercel.
        Src {
            rel: ".local/share/com.vercel.cli/auth.json",
            name: "Vercel CLI",
            target: "Vercel",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "token",
        },
        Src {
            rel: ".config/vercel/auth.json",
            name: "Vercel CLI",
            target: "Vercel",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "token",
        },
        // Cloudflare Wrangler: `oauth_token` after `wrangler login`,
        // `api_token` when set by hand. Linux, macOS, then the legacy folder.
        Src {
            rel: ".config/.wrangler/config/default.toml",
            name: "Cloudflare Wrangler",
            target: "Cloudflare",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "_token",
        },
        Src {
            rel: "AppData/Roaming/xdg.config/.wrangler/config/default.toml",
            name: "Cloudflare Wrangler",
            target: "Cloudflare",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "_token",
        },
        Src {
            rel: "Library/Preferences/.wrangler/config/default.toml",
            name: "Cloudflare Wrangler",
            target: "Cloudflare",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "_token",
        },
        Src {
            rel: ".wrangler/config/default.toml",
            name: "Cloudflare Wrangler",
            target: "Cloudflare",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "_token",
        },
        Src {
            rel: ".config/netlify/config.json",
            name: "Netlify CLI",
            target: "Netlify",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "token",
        },
        Src {
            rel: ".railway/config.json",
            name: "Railway CLI",
            target: "Railway",
            kind: CredentialKind::CiToken,
            edge: EdgeKind::CanDeploy,
            node: NodeKind::ProductionService,
            token_key: "token",
        },
        Src {
            rel: ".npmrc",
            name: "npm publish token",
            target: "npm registry",
            kind: CredentialKind::ApiKey,
            edge: EdgeKind::CanPushCode,
            node: NodeKind::Registry,
            token_key: "_authToken",
        },
        Src {
            rel: ".pypirc",
            name: "PyPI credentials",
            target: "PyPI",
            kind: CredentialKind::ApiKey,
            edge: EdgeKind::CanPushCode,
            node: NodeKind::Registry,
            token_key: "password",
        },
    ];
    for s in &sources {
        let p = ctx.path(s.rel);
        let Some(text) = ctx.read(&p) else { continue };
        if has_content(&text) && !ci_config_understood(s.rel, &text) {
            ctx.could_not_interpret(&p);
            continue;
        }
        let token_line = text.lines().find(|l| {
            l.contains(s.token_key)
                && (l.contains(':') || l.contains('='))
                && !l.trim_start().starts_with('#')
        });
        // The file may exist without a token (e.g. npm config without auth).
        let Some(line) = token_line else { continue };
        let mut c = DiscoveredCredential::new(s.kind, s.name, &ctx.display(&p), s.target);
        c.fingerprint = Fingerprint::from_secret(line.trim().as_bytes());
        c.evidence.push("token stored in plaintext config".into());
        c.permissions.lifetime = Lifetime::Unknown;
        c.permissions.assurance = Assurance::Inferred;
        c.persistence = Persistence::IndependentCredential;
        if matches!(s.edge, EdgeKind::CanDeploy) {
            c.permissions.can_modify_production = Capability::Yes;
            c.evidence
                .push("deployment platform tokens publish to production by default".into());
        }
        if matches!(s.node, NodeKind::Registry) {
            c.evidence.push("package publishing: a compromised token is a supply-chain attack on every downstream user".into());
        }
        let links = vec![Link::new(s.node, s.target, s.edge, Assurance::Inferred)
            .evidence(&format!("{} configured", s.name))
            .production(matches!(s.edge, EdgeKind::CanDeploy))];
        out.push(Discovered {
            credential: c,
            links,
            verify_key: None,
            source: Some(p.clone()),
        });
    }
    // Supabase CLI: the access token alone in a file.
    for rel in [".config/supabase/access-token", ".supabase/access-token"] {
        let p = ctx.path(rel);
        let Some(text) = ctx.read(&p) else { continue };
        let token = text.trim();
        if token.is_empty() {
            continue;
        }
        if token.len() < 8 || token.contains(char::is_whitespace) {
            ctx.could_not_interpret(&p);
            continue;
        }
        let mut c = DiscoveredCredential::new(
            CredentialKind::CiToken,
            "Supabase CLI",
            &ctx.display(&p),
            "Supabase",
        );
        c.fingerprint = Fingerprint::from_secret(token.as_bytes());
        c.evidence.push("token stored in plaintext config".into());
        c.evidence
            .push("deployment platform tokens publish to production by default".into());
        c.permissions.lifetime = Lifetime::Unknown;
        c.permissions.assurance = Assurance::Inferred;
        c.permissions.can_modify_production = Capability::Yes;
        c.persistence = Persistence::IndependentCredential;
        let links = vec![Link::new(
            NodeKind::ProductionService,
            "Supabase",
            EdgeKind::CanDeploy,
            Assurance::Inferred,
        )
        .evidence("Supabase CLI configured")
        .production(true)];
        out.push(Discovered {
            credential: c,
            links,
            verify_key: None,
            source: Some(p.clone()),
        });
    }
    // Heroku / generic .netrc
    let netrc = ctx.path(".netrc");
    if let Some(text) = ctx.read(&netrc) {
        let entries = parsers::parse_netrc(&text);
        if has_content(&text) && entries.is_empty() {
            ctx.could_not_interpret(&netrc);
        }
        for entry in entries {
            if !entry.well_formed {
                ctx.could_not_interpret_entry(
                    &netrc,
                    &format!("machine {}", safe_host(&entry.machine)),
                );
                continue;
            }
            // The default entry was never reported; it names no host.
            if entry.machine == "default" {
                continue;
            }
            let m = &safe_host(&entry.machine);
            let mut c = DiscoveredCredential::new(
                CredentialKind::ApiKey,
                &format!("netrc {m}"),
                &ctx.display(&netrc),
                m,
            );
            c.permissions.identity = entry.login.as_deref().map(safe_identity);
            c.fingerprint = Fingerprint::from_secret(m.as_bytes());
            c.permissions.lifetime = Lifetime::Unknown;
            c.persistence = Persistence::IndependentCredential;
            c.evidence.push("plaintext .netrc entry".into());
            out.push(Discovered {
                credential: c,
                links: Vec::new(),
                verify_key: None,
                source: Some(netrc.clone()),
            });
        }
    }
    out
}

/// Whether a CI or publishing CLI's config file has the structure its
/// format calls for: a JSON object, a YAML mapping, `key=value` lines
/// (.npmrc) or INI sections (.pypirc). A file with that structure and no
/// token is a configuration without a login; one without it was not
/// understood, and a token in it would otherwise vanish silently.
fn ci_config_understood(rel: &str, text: &str) -> bool {
    if rel.ends_with(".json") {
        return serde_json::from_str::<serde_json::Value>(text).is_ok_and(|v| v.is_object());
    }
    if rel.ends_with(".yml") || rel.ends_with(".yaml") {
        return matches!(parsers::parse_yaml(text), Yaml::Map(ref m) if !m.is_empty());
    }
    if rel.ends_with(".pypirc") {
        return !parsers::parse_ini(text).is_empty()
            && parsers::ini_malformed_sections(text).is_empty();
    }
    if rel.ends_with(".npmrc") {
        return text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
            .all(|l| l.find('=').is_some_and(|i| !l[..i].trim().is_empty()));
    }
    true
}

// ─── AI coding agents and MCP configs ────────────────────────────────────────

/// How an AI agent's file is laid out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AgentFormat {
    /// JSON: every string under a secret-looking key counts.
    Json,
    /// `key: value` or `key = value` lines (YAML, TOML).
    Lines,
    /// The token alone in the file.
    Raw,
}

struct AgentFile {
    rel: &'static str,
    name: &'static str,
    target: &'static str,
    kind: CredentialKind,
    format: AgentFormat,
    /// A sign-in file: content with no credential in it is a format Gorse
    /// does not understand (lost coverage). A config file without secrets
    /// is just a config file.
    sign_in: bool,
}

const fn agent(
    rel: &'static str,
    name: &'static str,
    target: &'static str,
    kind: CredentialKind,
    format: AgentFormat,
    sign_in: bool,
) -> AgentFile {
    AgentFile {
        rel,
        name,
        target,
        kind,
        format,
        sign_in,
    }
}

/// Sign-in files of AI coding agents and the configs (MCP servers above
/// all) where people write API keys literally. The same home-relative
/// paths on macOS and Linux; on Windows the CLIs use the same folders
/// under %USERPROFILE%.
#[rustfmt::skip]
/// An identity read from a credential file, made safe to show. Some tools
/// put the token itself where a user name goes (`https://ghp_…@github.com`
/// in ~/.git-credentials, a token as the .netrc login), so anything that
/// looks like a secret is cut to four characters, as previews are.
pub(crate) fn safe_identity(raw: &str) -> String {
    let s = raw.trim();
    let redacted = redact_text(s);
    let long_random = s.len() >= 20
        && !s.contains(['@', ' '])
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_alphabetic());
    if redacted != s || long_random {
        let head: String = s.chars().take(4).collect();
        return format!("{head}****");
    }
    s.to_string()
}

/// True when a config key name is built only from ordinary words
/// (`OPENAI_API_KEY`, `accessToken`, `client_secret`), so it cannot be a
/// secret written where a name goes.
fn plain_key_name(name: &str) -> bool {
    const WORDS: &[&str] = &[
        "api",
        "key",
        "keys",
        "token",
        "tokens",
        "secret",
        "secrets",
        "access",
        "refresh",
        "id",
        "client",
        "password",
        "passwd",
        "pass",
        "auth",
        "authorization",
        "bearer",
        "oauth",
        "session",
        "private",
        "personal",
        "app",
        "bot",
        "user",
        "service",
        "account",
        "env",
        "openai",
        "anthropic",
        "claude",
        "gemini",
        "google",
        "github",
        "gitlab",
        "aws",
        "azure",
        "mistral",
        "groq",
        "cohere",
        "deepseek",
        "openrouter",
        "together",
        "perplexity",
        "xai",
        "huggingface",
        "hf",
        "slack",
        "linear",
        "notion",
        "stripe",
        "supabase",
        "vercel",
        "cloudflare",
        "brave",
        "search",
        "tavily",
        "exa",
        "firecrawl",
        "sentry",
        "figma",
        "jira",
        "atlassian",
        "confluence",
        "postgres",
        "database",
        "db",
        "url",
        "mcp",
        "server",
        "x",
        "header",
        "headers",
        "copilot",
        "cursor",
        "codex",
        "ollama",
        "voyage",
        "replicate",
        "fireworks",
        "pinecone",
        "weaviate",
        "qdrant",
        "redis",
        "mongodb",
        "mongo",
        "neon",
    ];
    if name.is_empty() || name.len() > 48 {
        return false;
    }
    let mut parts: Vec<String> = Vec::new();
    for chunk in name.split(['_', '-', '.']) {
        let mut cur = String::new();
        for ch in chunk.chars() {
            if ch.is_ascii_uppercase() && cur.chars().last().is_some_and(|c| c.is_ascii_lowercase())
            {
                parts.push(std::mem::take(&mut cur));
            }
            cur.push(ch);
        }
        if !cur.is_empty() {
            parts.push(cur);
        }
    }
    !parts.is_empty()
        && parts
            .iter()
            .all(|p| WORDS.contains(&p.to_ascii_lowercase().as_str()))
}

/// A host name read from a file, shown only when it looks like one.
fn safe_host(raw: &str) -> String {
    let s = raw.trim();
    if s.contains('.')
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
    {
        s.to_string()
    } else {
        safe_identity(s)
    }
}

const AGENT_FILES: &[AgentFile] = &[
    agent(
        ".claude/.credentials.json",
        "Claude Code sign-in",
        "Anthropic (Claude)",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".claude.json",
        "Claude Code config",
        "Anthropic (Claude)",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".claude/settings.json",
        "Claude Code settings",
        "Anthropic (Claude)",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".gemini/oauth_creds.json",
        "Gemini CLI sign-in",
        "Google (Gemini)",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".gemini/mcp-oauth-tokens.json",
        "Gemini CLI MCP sign-ins",
        "MCP servers",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".gemini/settings.json",
        "Gemini CLI settings",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".codex/auth.json",
        "Codex CLI sign-in",
        "OpenAI",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".codex/config.toml",
        "Codex CLI config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Lines,
        false,
    ),
    agent(
        ".cursor/auth.json",
        "Cursor CLI sign-in",
        "Cursor",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".cursor/mcp.json",
        "Cursor MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".qwen/oauth_creds.json",
        "Qwen Code sign-in",
        "Qwen",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".local/share/opencode/auth.json",
        "OpenCode sign-in",
        "AI model providers",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".config/github-copilot/hosts.json",
        "GitHub Copilot sign-in",
        "GitHub Copilot",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".config/github-copilot/apps.json",
        "GitHub Copilot sign-in",
        "GitHub Copilot",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        "Library/Application Support/Claude/claude_desktop_config.json",
        "Claude Desktop MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".config/Claude/claude_desktop_config.json",
        "Claude Desktop MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        "Library/Application Support/Code/User/mcp.json",
        "VS Code MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".config/Code/User/mcp.json",
        "VS Code MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".codeium/windsurf/mcp_config.json",
        "Windsurf MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        ".config/devin/mcp_config.json",
        "Devin MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    // Windows keeps these under %APPDATA% (AppData/Roaming) and
    // %LOCALAPPDATA% (AppData/Local) inside the home folder.
    agent(
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "Claude Desktop MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        "AppData/Roaming/Code/User/mcp.json",
        "VS Code MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        "AppData/Roaming/devin/mcp_config.json",
        "Devin MCP config",
        "MCP servers",
        CredentialKind::ApiKey,
        AgentFormat::Json,
        false,
    ),
    agent(
        "AppData/Local/github-copilot/hosts.json",
        "GitHub Copilot sign-in",
        "GitHub Copilot",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        "AppData/Local/github-copilot/apps.json",
        "GitHub Copilot sign-in",
        "GitHub Copilot",
        CredentialKind::OAuthSession,
        AgentFormat::Json,
        true,
    ),
    agent(
        ".continue/config.yaml",
        "Continue config",
        "AI model providers",
        CredentialKind::ApiKey,
        AgentFormat::Lines,
        false,
    ),
    agent(
        ".aider.conf.yml",
        "Aider config",
        "AI model providers",
        CredentialKind::ApiKey,
        AgentFormat::Lines,
        false,
    ),
    agent(
        ".cache/huggingface/token",
        "Hugging Face token",
        "Hugging Face",
        CredentialKind::ApiKey,
        AgentFormat::Raw,
        true,
    ),
    agent(
        ".huggingface/token",
        "Hugging Face token",
        "Hugging Face",
        CredentialKind::ApiKey,
        AgentFormat::Raw,
        true,
    ),
];

/// Whether a config key names secret material: `accessToken`,
/// `refresh_token`, `apiKey`, `GITHUB_TOKEN`, `client_secret`,
/// `Authorization`. Not `token_type`, `max_tokens` or `apiKeyHelper`.
fn agent_secret_key(key: &str) -> bool {
    let k: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    [
        "token",
        "apikey",
        "secret",
        "password",
        "accesskey",
        "authorization",
    ]
    .iter()
    .any(|end| k.ends_with(end))
        || matches!(k.as_str(), "key" | "access" | "refresh")
}

/// Whether a value is written literally, not a reference to somewhere
/// else (`${GITHUB_TOKEN}`, `{env:KEY}`, `op://vault/item`).
fn agent_literal_value(v: &str) -> bool {
    let v = v.trim();
    v.len() >= 8
        && !v.starts_with('$')
        && !v.contains("${")
        && !v.contains("{env:")
        && !v.starts_with("env:")
        && !v.starts_with("op://")
}

/// Secret-keyed literal strings in a JSON document: (key, value) pairs.
fn agent_json_secrets<'v>(v: &'v serde_json::Value, out: &mut Vec<(String, &'v str)>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                match val {
                    serde_json::Value::String(s)
                        if agent_secret_key(k) && agent_literal_value(s) =>
                    {
                        out.push((k.clone(), s.as_str()))
                    }
                    _ => agent_json_secrets(val, out),
                }
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| agent_json_secrets(i, out)),
        _ => {}
    }
}

/// Secret-keyed literal values on `key: value` / `key = value` lines.
/// A config value without its quotes, a trailing `# comment`, a trailing
/// comma, or an `Authorization` scheme word (`Bearer …`, `Basic …`).
fn agent_clean_value(raw: &str) -> &str {
    let raw = raw.trim();
    let value = match raw.chars().next() {
        Some(q @ ('"' | '\'')) => raw[1..].split(q).next().unwrap_or(""),
        _ => raw
            .split(" #")
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches(',')
            .trim(),
    };
    let value = value.trim();
    for scheme in ["Bearer ", "bearer ", "Basic ", "Token ", "token "] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest.trim();
        }
    }
    value
}

fn agent_line_secrets(text: &str) -> Vec<(String, &str)> {
    let unquote = |s: &str| {
        s.trim()
            .trim_end_matches(',')
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .to_string()
    };
    let mut out = Vec::new();
    // Aider's `api-key:` takes a list of `provider=key` items.
    let mut in_key_list: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let listed = trimmed.starts_with("- ");
        let l = trimmed.trim_start_matches("- ");
        if l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        if let (true, Some(key)) = (listed, in_key_list.as_ref()) {
            if let Some((_, v)) = l.split_once('=') {
                let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
                if agent_literal_value(v) && !v.contains(char::is_whitespace) {
                    out.push((key.clone(), v));
                }
            }
            continue;
        }
        if !listed {
            in_key_list = None;
        }
        let Some(i) = l.find([':', '=']) else {
            continue;
        };
        let key = unquote(&l[..i]);
        let raw = l[i + 1..].trim();
        if raw.is_empty() && agent_secret_key(&key) {
            in_key_list = Some(key);
            continue;
        }
        // TOML inline table: `env = { OPENAI_API_KEY = "…", OTHER = "…" }`.
        if let Some(inner) = raw
            .trim_end_matches(',')
            .trim_end()
            .strip_prefix('{')
            .and_then(|r| r.strip_suffix('}'))
        {
            for part in inner.split(',') {
                if let Some((k, v)) = part.split_once(['=', ':']) {
                    let k = unquote(k);
                    let v = agent_clean_value(v);
                    if agent_secret_key(&k)
                        && agent_literal_value(v)
                        && !v.contains(char::is_whitespace)
                    {
                        out.push((k, v));
                    }
                }
            }
            continue;
        }
        let value = agent_clean_value(raw);
        // `api-key: anthropic=sk-…` (Aider): the key follows a lowercase
        // provider name. Base64 padding (`…Ng==`) is not a provider split.
        let value = match value.split_once('=') {
            Some((provider, rest))
                if !provider.is_empty()
                    && provider.len() <= 24
                    && provider.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                    && rest.len() >= 8 =>
            {
                rest
            }
            _ => value,
        };
        if agent_secret_key(&key)
            && agent_literal_value(value)
            && !value.contains(char::is_whitespace)
        {
            out.push((key, value));
        }
    }
    out
}

/// An expiry written in the file (`expiresAt`, `expiry_date`, `expires`),
/// in seconds; milliseconds are converted.
fn agent_expiry(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                let lower = k.to_ascii_lowercase().replace('_', "");
                if matches!(
                    lower.as_str(),
                    "expiresat" | "expirydate" | "expires" | "expiry"
                ) {
                    if let Some(n) = val.as_u64() {
                        return Some(if n > 100_000_000_000 { n / 1000 } else { n });
                    }
                }
                if let Some(t) = agent_expiry(val) {
                    return Some(t);
                }
            }
            None
        }
        _ => None,
    }
}

fn ai_agents(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    for f in AGENT_FILES {
        let p = ctx.path(f.rel);
        let Some(text) = ctx.read(&p) else { continue };
        let text = text.trim_start_matches('\u{feff}');
        if text.trim().is_empty() {
            continue;
        }
        let json = match f.format {
            AgentFormat::Json => match serde_json::from_str::<serde_json::Value>(text) {
                Ok(v) => Some(v),
                // A sign-in file that is not JSON is unreadable; a config
                // may be JSON with comments, which the line reader handles.
                Err(_) if f.sign_in => {
                    ctx.could_not_interpret(&p);
                    continue;
                }
                Err(_) => None,
            },
            _ => None,
        };
        if json
            .as_ref()
            .is_some_and(|v| v.as_object().is_some_and(|m| m.is_empty()))
        {
            continue; // `{}`: signed out
        }
        let secrets: Vec<(String, &str)> = match (&json, f.format) {
            (Some(v), _) => {
                let mut s = Vec::new();
                agent_json_secrets(v, &mut s);
                s
            }
            (None, AgentFormat::Raw) => {
                let t = text.trim();
                if t.len() >= 8 && !t.contains(char::is_whitespace) {
                    vec![("token".to_string(), t)]
                } else {
                    Vec::new()
                }
            }
            (None, _) => agent_line_secrets(text),
        };
        if secrets.is_empty() {
            if f.sign_in {
                ctx.could_not_interpret(&p);
            }
            continue;
        }
        let refresh = secrets
            .iter()
            .any(|(k, _)| k.to_ascii_lowercase().contains("refresh"));
        let mut material = Vec::new();
        for (_, v) in &secrets {
            material.extend_from_slice(v.as_bytes());
            material.push(0);
        }
        let mut c = DiscoveredCredential::new(f.kind, f.name, &ctx.display(&p), f.target);
        c.fingerprint = Fingerprint::from_secret(&material);
        c.permissions.assurance = Assurance::Inferred;
        c.persistence = Persistence::IndependentCredential;
        if f.sign_in {
            c.evidence.push(
                "sign-in token stored in a plaintext file: a copy works from another machine"
                    .into(),
            );
        } else {
            let mut keys: Vec<&str> = secrets.iter().map(|(k, _)| k.as_str()).collect();
            keys.sort_unstable();
            keys.dedup();
            // A name is shown only when it is made of known words; a file can
            // use the secret itself as a property name.
            let nameable: Vec<&str> = keys.iter().copied().filter(|k| plain_key_name(k)).collect();
            let shown: Vec<&str> = nameable.iter().take(5).copied().collect();
            let hidden = keys.len() - shown.len();
            let text = match (shown.is_empty(), hidden) {
                (true, n) => format!(
                    "{n} secret{} written literally in the config",
                    if n == 1 { "" } else { "s" }
                ),
                (false, 0) => format!(
                    "secrets written literally in the config ({})",
                    shown.join(", ")
                ),
                (false, n) => format!(
                    "secrets written literally in the config ({} and {n} more)",
                    shown.join(", ")
                ),
            };
            c.evidence.push(redact_text(&text));
        }
        c.permissions.lifetime = if refresh {
            c.evidence
                .push("refresh token: renews access until signed out or revoked".into());
            Lifetime::LongLived
        } else {
            match json.as_ref().and_then(agent_expiry) {
                Some(t) if t <= ctx.now => Lifetime::ExpiredAt(t),
                Some(t) => Lifetime::ExpiresAt(t),
                None => Lifetime::Unknown,
            }
        };
        let links = vec![Link::new(
            NodeKind::Other,
            f.target,
            EdgeKind::CanAuthenticate,
            Assurance::Inferred,
        )
        .evidence(&format!("{} found", f.name))];
        out.push(Discovered {
            credential: c,
            links,
            verify_key: None,
            source: Some(p.clone()),
        });
    }
    out
}

// ─── Docker registries ───────────────────────────────────────────────────────

fn docker(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let p = ctx.path(".docker/config.json");
    let Some(v) = ctx.read_json(&p) else {
        return out;
    };
    if !v.is_object() || !(v["auths"].is_object() || v["auths"].is_null()) {
        ctx.could_not_interpret(&p);
    }
    let store = v["credsStore"].as_str().map(|s| s.to_string());
    if let Some(auths) = v["auths"].as_object() {
        for (registry, entry) in auths {
            if !docker_auth_understood(entry) {
                ctx.could_not_interpret_entry(&p, &format!("registry {registry}"));
                continue;
            }
            let mut c = DiscoveredCredential::new(
                CredentialKind::DockerRegistry,
                registry,
                &ctx.display(&p),
                registry,
            );
            match entry["auth"].as_str() {
                Some(auth) => {
                    c.fingerprint = Fingerprint::from_secret(auth.as_bytes());
                    c.evidence
                        .push("base64 username:password stored in config.json".into());
                }
                None => {
                    c.fingerprint = Fingerprint::from_secret(registry.as_bytes());
                    c.evidence.push(match &store {
                        Some(s) => format!("credentials held by helper '{s}'"),
                        None => "login recorded; secret in a credential helper".into(),
                    });
                }
            }
            c.permissions.lifetime = Lifetime::Unknown;
            c.permissions.assurance = Assurance::Inferred;
            c.persistence = Persistence::IndependentCredential;
            let production = ctx.is_production(registry)
                || registry.contains("ecr")
                || registry.contains("gcr.io")
                || registry.contains("pkg.dev")
                || registry.contains("azurecr");
            let mut links = vec![Link::new(
                NodeKind::Registry,
                registry,
                EdgeKind::CanPushCode,
                Assurance::Inferred,
            )
            .evidence("registry login present; push rights unknown until verified")
            .production(production)];
            attach_declared_systems(
                ctx,
                registry,
                &mut links,
                EdgeKind::CanPushCode,
                Assurance::Inferred,
            );
            out.push(Discovered {
                credential: c,
                links,
                verify_key: None,
                source: Some(p.clone()),
            });
        }
    }
    out
}

/// Whether a docker `auths` entry is in the shape docker writes: an object
/// whose `auth`, when present and not empty, is base64 of `user:secret`, and
/// whose `identitytoken`, when present, is a string.
fn docker_auth_understood(entry: &serde_json::Value) -> bool {
    use base64::Engine;
    if !entry.is_object() {
        return false;
    }
    let auth_ok = match &entry["auth"] {
        serde_json::Value::Null => true,
        serde_json::Value::String(a) if a.is_empty() => true,
        serde_json::Value::String(a) => base64::engine::general_purpose::STANDARD
            .decode(a.trim())
            .is_ok_and(|bytes| bytes.contains(&b':')),
        _ => false,
    };
    auth_ok && (entry["identitytoken"].is_null() || entry["identitytoken"].is_string())
}

// ─── Kubernetes ──────────────────────────────────────────────────────────────

fn kubernetes(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let mut files = vec![ctx.path(".kube/config")];
    if let Some(list) = ctx.env.get("KUBECONFIG") {
        // The platform's own list separator: ':' on Unix, ';' on Windows,
        // where paths themselves contain ':' after the drive letter.
        for part in std::env::split_paths(list) {
            if !part.as_os_str().is_empty() {
                files.push(part);
            }
        }
    }
    files.dedup();
    for file in files {
        let Some(text) = ctx.read(&file) else {
            continue;
        };
        let y = parsers::parse_yaml(&text);
        let produced_before = out.len();
        let current = y.str("current-context").unwrap_or("").to_string();
        let clusters: BTreeMap<String, String> = y
            .list("clusters")
            .iter()
            .filter_map(|c| {
                Some((
                    c.str("name")?.to_string(),
                    c.get("cluster")?.str("server").unwrap_or("?").to_string(),
                ))
            })
            .collect();
        // Every user and context entry must be read; one that is not is
        // reported by name (or position) and the source is not assessed.
        let mut users: BTreeMap<String, &Yaml> = BTreeMap::new();
        for (i, u) in y.list("users").iter().enumerate() {
            match (u.str("name"), u.get("user")) {
                (Some(name), Some(user)) if kube_user_understood(user) => {
                    users.insert(name.to_string(), user);
                }
                (name, _) => {
                    let label = name
                        .map(|n| format!("user {n}"))
                        .unwrap_or_else(|| format!("user entry {}", i + 1));
                    ctx.could_not_interpret_entry(&file, &label);
                }
            }
        }
        let mut broken_users = false;
        for (i, context) in y.list("contexts").iter().enumerate() {
            if !matches!(
                (context.str("name"), context.get("context")),
                (Some(_), Some(Yaml::Map(_)))
            ) {
                let label = context
                    .str("name")
                    .map(|n| format!("context {n}"))
                    .unwrap_or_else(|| format!("context entry {}", i + 1));
                ctx.could_not_interpret_entry(&file, &label);
                broken_users = true;
            }
        }
        for context in y.list("contexts") {
            let Some(name) = context.str("name") else {
                continue;
            };
            let Some(inner) = context.get("context") else {
                continue;
            };
            let cluster = inner.str("cluster").unwrap_or("?").to_string();
            let user = inner.str("user").unwrap_or("?").to_string();
            let namespace = inner.str("namespace").map(|s| s.to_string());
            let server = clusters
                .get(&cluster)
                .cloned()
                .unwrap_or_else(|| "?".into());
            let mut c = DiscoveredCredential::new(
                CredentialKind::KubernetesContext,
                name,
                &ctx.display(&file),
                &format!("cluster {cluster}"),
            );
            c.permissions.identity = Some(safe_identity(&user));
            c.permissions.organization = Some(server.clone());
            c.permissions.assurance = Assurance::Inferred;
            let production = ctx.is_production(name)
                || ctx.is_production(&cluster)
                || ctx.is_production(&server);
            if production {
                c.permissions.can_access_production = Capability::Yes;
            }
            if let Some(ns) = &namespace {
                c.permissions
                    .restrictions
                    .push(format!("default namespace {ns}"));
            }
            if name == current {
                c.evidence.push("current context".into());
            }
            let (auth_desc, persistence, material) = match users.get(&user) {
                Some(u) if u.str("token").is_some() => (
                    "static bearer token in kubeconfig",
                    Persistence::IndependentCredential,
                    u.str("token").map(|s| s.to_string()),
                ),
                Some(u)
                    if u.str("client-certificate-data").is_some()
                        || u.str("client-certificate").is_some() =>
                {
                    (
                        "client certificate (typically no expiry under a year, not revocable)",
                        Persistence::IndependentCredential,
                        u.str("client-certificate-data").map(|s| s.to_string()),
                    )
                }
                Some(u) if u.get("exec").is_some() => {
                    let exec = u.get("exec").unwrap();
                    let cmd = exec.str("command").unwrap_or("?");
                    let args: Vec<&str> = exec
                        .list("args")
                        .iter()
                        .filter_map(|a| a.as_str())
                        .collect();
                    c.evidence
                        .push(format!("auth via exec plugin: {cmd} {}", args.join(" ")));
                    if cmd.ends_with("aws") {
                        let profile = args
                            .iter()
                            .position(|a| *a == "--profile")
                            .and_then(|i| args.get(i + 1))
                            .map(|s| s.to_string());
                        c.evidence.push(format!(
                            "depends on AWS credentials{}",
                            profile
                                .as_ref()
                                .map(|p| format!(" (profile {p})"))
                                .unwrap_or_default()
                        ));
                    }
                    (
                        "short-lived token minted from cloud credentials",
                        Persistence::RequiresEndpoint,
                        None,
                    )
                }
                Some(u) if u.get("auth-provider").is_some() => (
                    "cloud auth provider (refresh token)",
                    Persistence::IndependentCredential,
                    None,
                ),
                Some(_) => ("unrecognised user entry", Persistence::Unknown, None),
                None => ("user entry missing", Persistence::Unknown, None),
            };
            c.evidence.push(auth_desc.to_string());
            c.persistence = persistence;
            c.fingerprint = match material {
                Some(m) => Fingerprint::from_secret(m.as_bytes()),
                None => Fingerprint::from_secret(format!("{server}|{user}").as_bytes()),
            };
            c.permissions.lifetime = if persistence == Persistence::RequiresEndpoint {
                Lifetime::Unknown
            } else {
                Lifetime::LongLived
            };
            if user.contains("admin") || name.contains("admin") {
                c.permissions.administrative = Capability::Yes;
                c.evidence
                    .push("'admin' in context or user name (name-based inference)".into());
            }
            let mut links = vec![Link::new(
                NodeKind::Cluster,
                &cluster,
                EdgeKind::CanAuthenticate,
                Assurance::Inferred,
            )
            .evidence(&format!("context {name} → {server}"))
            .scope(namespace.as_deref().unwrap_or("all namespaces"))
            .production(production)];
            if c.permissions.administrative.is_yes() {
                links.push(
                    Link::new(
                        NodeKind::Cluster,
                        &cluster,
                        EdgeKind::CanDeploy,
                        Assurance::Inferred,
                    )
                    .evidence("admin-named context; verify with --verify")
                    .production(production),
                );
            }
            for host in [name, cluster.as_str(), server.as_str()] {
                attach_declared_systems(
                    ctx,
                    host,
                    &mut links,
                    EdgeKind::CanDeploy,
                    Assurance::Inferred,
                );
            }
            out.push(Discovered {
                credential: c,
                links,
                verify_key: Some(name.to_string()),
                source: Some(file.clone()),
            });
        }
        // `contexts: []` (or no value) is a kubeconfig with nothing in it;
        // anything else that yielded no context was not understood.
        if out.len() == produced_before
            && !broken_users
            && has_content(&text)
            && !matches!(y.get("contexts"), Some(Yaml::Null))
        {
            ctx.could_not_interpret(&file);
        }
    }
    out
}

/// Whether a kubeconfig `user` entry is one Gorse reads: empty, or holding
/// at least one of the authentication fields kubectl understands.
fn kube_user_understood(user: &Yaml) -> bool {
    const KNOWN: &[&str] = &[
        "token",
        "tokenFile",
        "client-certificate",
        "client-certificate-data",
        "client-key",
        "client-key-data",
        "exec",
        "auth-provider",
        "username",
        "password",
        "as",
        "as-uid",
        "as-groups",
        "as-user-extra",
        "extensions",
    ];
    match user {
        Yaml::Null => true,
        Yaml::Map(entries) => {
            entries.is_empty() || entries.iter().any(|(k, _)| KNOWN.contains(&k.as_str()))
        }
        _ => false,
    }
}

// ─── Terraform / IaC ─────────────────────────────────────────────────────────

fn terraform(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let p = ctx.path(".terraform.d/credentials.tfrc.json");
    if let Some(v) = ctx.read_json(&p) {
        if !v["credentials"].is_object() {
            ctx.could_not_interpret(&p);
        }
        if let Some(creds) = v["credentials"].as_object() {
            for (host, entry) in creds {
                if !entry["token"].is_string() {
                    ctx.could_not_interpret_entry(&p, &format!("credentials for {host}"));
                    continue;
                }
                let mut c = DiscoveredCredential::new(
                    CredentialKind::TerraformToken,
                    host,
                    &ctx.display(&p),
                    host,
                );
                c.fingerprint =
                    Fingerprint::from_secret(entry["token"].as_str().unwrap_or(host).as_bytes());
                c.permissions.lifetime = Lifetime::Unknown;
                c.permissions.assurance = Assurance::Inferred;
                c.permissions.can_modify_production = Capability::Yes;
                c.persistence = Persistence::IndependentCredential;
                c.evidence.push("Terraform Cloud/Enterprise user token: can queue applies in every workspace the user can access".into());
                let links = vec![Link::new(
                    NodeKind::CiSystem,
                    host,
                    EdgeKind::CanModifyConfiguration,
                    Assurance::Inferred,
                )
                .evidence("IaC token")
                .approval(Some(
                    "workspace apply policy (Sentinel/OPA) if configured".into(),
                ))
                .production(true)];
                out.push(Discovered {
                    credential: c,
                    links,
                    verify_key: None,
                    source: Some(p.clone()),
                });
            }
        }
    }
    for (var, val) in &ctx.env {
        if let Some(host) = var.strip_prefix("TF_TOKEN_") {
            let host = host.replace("__", "-").replace('_', ".");
            let mut c = DiscoveredCredential::new(
                CredentialKind::TerraformToken,
                &host,
                &format!("env {var}"),
                &host,
            );
            c.fingerprint = Fingerprint::from_secret(val.as_bytes());
            c.permissions.can_modify_production = Capability::Yes;
            c.permissions.assurance = Assurance::Inferred;
            c.persistence = Persistence::IndependentCredential;
            out.push(Discovered {
                credential: c,
                links: vec![Link::new(
                    NodeKind::CiSystem,
                    &host,
                    EdgeKind::CanModifyConfiguration,
                    Assurance::Inferred,
                )
                .production(true)],
                verify_key: None,
                source: None,
            });
        }
    }
    let pulumi = ctx.path(".pulumi/credentials.json");
    if let Some(v) = ctx.read_json(&pulumi) {
        if !v.is_object() || !(v["accessTokens"].is_object() || v["accessTokens"].is_null()) {
            ctx.could_not_interpret(&pulumi);
        }
        if let Some(tokens) = v["accessTokens"].as_object() {
            for (backend, token) in tokens {
                if !token.is_string() {
                    ctx.could_not_interpret_entry(&pulumi, &format!("access token for {backend}"));
                    continue;
                }
                let mut c = DiscoveredCredential::new(
                    CredentialKind::TerraformToken,
                    &format!("Pulumi {backend}"),
                    &ctx.display(&pulumi),
                    backend,
                );
                c.fingerprint =
                    Fingerprint::from_secret(token.as_str().unwrap_or(backend).as_bytes());
                c.permissions.can_modify_production = Capability::Yes;
                c.permissions.assurance = Assurance::Inferred;
                c.persistence = Persistence::IndependentCredential;
                out.push(Discovered {
                    credential: c,
                    links: vec![Link::new(
                        NodeKind::CiSystem,
                        backend,
                        EdgeKind::CanModifyConfiguration,
                        Assurance::Inferred,
                    )
                    .production(true)],
                    verify_key: None,
                    source: Some(pulumi.clone()),
                });
            }
        }
    }
    out
}

// ─── DigitalOcean ────────────────────────────────────────────────────────────

/// Where doctl keeps its tokens: `access-token` for the default context and
/// `auth-contexts` for named ones. Every platform's location is tried, so a
/// config copied from another machine is found too.
fn doctl_config_paths(ctx: &Context) -> Vec<PathBuf> {
    let mut paths = vec![
        ctx.path("Library/Application Support/doctl/config.yaml"),
        ctx.path(".config/doctl/config.yaml"),
    ];
    if let Some(xdg) = ctx.env.get("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        paths.push(PathBuf::from(xdg).join("doctl").join("config.yaml"));
    }
    if let Some(appdata) = ctx.env.get("APPDATA").filter(|v| !v.is_empty()) {
        paths.push(PathBuf::from(appdata).join("doctl").join("config.yaml"));
    }
    paths.dedup();
    paths
}

/// The key of a doctl config's top-level `access-token`, which doctl uses
/// for its default context (the finding is named `default`).
pub const DOCTL_TOP_LEVEL: &str = "access-token";

/// The finding name of a context called `default` under `auth-contexts`,
/// which is not the token doctl's default context uses.
pub const DOCTL_DEFAULT_CONTEXT: &str = "auth-contexts default";

/// The verification-key prefix of a doctl token that is checked through a
/// temporary config holding only that token: the top-level access-token
/// (`config-token:access-token`) and a context named `default`
/// (`config-token:default`).
pub const DOCTL_TOKEN_KEY: &str = "config-token:";

fn digitalocean(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    for p in doctl_config_paths(ctx) {
        let Some(text) = ctx.read(&p) else {
            continue;
        };
        let y = parsers::parse_yaml(&text);
        let current = y.str("context").unwrap_or("default").trim().to_string();
        // (name, token, selected by doctl's `context:`, verification key).
        // doctl's `--context default` reads the top-level access-token, so
        // the top-level token and a context named default are each bound
        // to a temporary config holding only that token, never by name.
        let mut tokens: Vec<(String, String, bool, String)> = Vec::new();
        if let Some(t) = y
            .str("access-token")
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            tokens.push((
                "default".into(),
                t.to_string(),
                current == "default",
                format!("{DOCTL_TOKEN_KEY}{DOCTL_TOP_LEVEL}"),
            ));
        }
        let mut broken_contexts = false;
        if let Some(contexts) = y.get("auth-contexts") {
            for (name, v) in contexts.entries() {
                match v {
                    Yaml::Str(t) if !t.trim().is_empty() => {
                        // doctl never selects a context named default
                        // from auth-contexts (`--context default` is the
                        // top-level token), so it gets a name of its own.
                        let (label, key, selected) = if name == "default" {
                            (
                                DOCTL_DEFAULT_CONTEXT.to_string(),
                                format!("{DOCTL_TOKEN_KEY}{name}"),
                                false,
                            )
                        } else {
                            (name.clone(), name.clone(), *name == current)
                        };
                        tokens.push((label, t.trim().to_string(), selected, key))
                    }
                    Yaml::Str(_) | Yaml::Null => {}
                    _ => {
                        ctx.could_not_interpret_entry(&p, &format!("context {name}"));
                        broken_contexts = true;
                    }
                }
            }
        }
        if has_content(&text) && !broken_contexts && !doctl_shape_understood(&y, tokens.is_empty())
        {
            ctx.could_not_interpret(&p);
        }
        let location = ctx.display(&p);
        for (name, token, selected, key) in tokens {
            let mut d = digitalocean_token(ctx, &name, &location, &token, selected, Some(key));
            d.source = Some(p.clone());
            out.push(d);
        }
    }
    for var in ["DIGITALOCEAN_ACCESS_TOKEN", "DIGITALOCEAN_TOKEN"] {
        if let Some(value) = ctx.env.get(var).map(|v| v.trim()).filter(|v| v.len() >= 8) {
            out.push(digitalocean_token(
                ctx,
                var,
                &format!("env {var}"),
                value,
                false,
                Some(format!("env:{var}")),
            ));
        }
    }
    out
}

/// Whether a doctl config was read as doctl writes it. `auth-contexts`
/// must be a mapping of names to tokens (or empty), and a config that
/// yielded no token must say so plainly: an empty `access-token` and no
/// named context with a token. Anything else is a shape the parser did not
/// understand, and its tokens would otherwise vanish silently.
fn doctl_shape_understood(y: &Yaml, no_tokens: bool) -> bool {
    let empty = |v: Option<&Yaml>| match v {
        None | Some(Yaml::Null) => true,
        Some(Yaml::Str(s)) => s.trim().is_empty(),
        _ => false,
    };
    let contexts_ok = match y.get("auth-contexts") {
        None | Some(Yaml::Null) => true,
        Some(Yaml::Map(entries)) => entries
            .iter()
            .all(|(_, v)| matches!(v, Yaml::Str(_) | Yaml::Null)),
        _ => false,
    };
    if !contexts_ok || !matches!(y, Yaml::Map(_)) {
        return false;
    }
    if !no_tokens {
        return true;
    }
    y.get("access-token").is_some() && empty(y.get("access-token"))
}

fn digitalocean_token(
    ctx: &Context,
    name: &str,
    location: &str,
    token: &str,
    selected: bool,
    verify_key: Option<String>,
) -> Discovered {
    let mut c = DiscoveredCredential::new(
        CredentialKind::DigitalOceanToken,
        name,
        location,
        "DigitalOcean",
    );
    c.fingerprint = Fingerprint::from_secret(token.as_bytes());
    c.permissions.lifetime = Lifetime::Unknown;
    c.permissions.assurance = Assurance::Inferred;
    c.persistence = Persistence::IndependentCredential;
    c.evidence.push(if token.starts_with("dop_v1_") {
        "personal access token (dop_v1_…): works from anywhere until revoked or expired".into()
    } else if token.starts_with("doo_v1_") {
        "OAuth token (doo_v1_…): issued to an application, works until revoked".into()
    } else {
        "token of unrecognised format".into()
    });
    c.evidence.push(
        "whether the token is read-only, full access or fine-grained, and when it expires, is not stored on this machine; --verify confirms the account but the API does not report scope"
            .into(),
    );
    if selected {
        c.evidence.push("selected doctl context".into());
    }
    let production = ctx.is_production(name);
    if production {
        c.permissions.can_access_production = Capability::Yes;
    }
    let mut links = vec![Link::new(
        NodeKind::CloudRole,
        "DigitalOcean account",
        EdgeKind::CanAuthenticate,
        Assurance::Inferred,
    )
    .evidence("API token for the whole account: droplets, Kubernetes clusters, databases, registry and apps; which exist, and whether writes are allowed, are unknown until verified")
    .production(production)];
    for host in [name, "digitalocean"] {
        attach_declared_systems(
            ctx,
            host,
            &mut links,
            EdgeKind::CanModifyConfiguration,
            Assurance::Inferred,
        );
    }
    Discovered {
        credential: c,
        links,
        verify_key,
        source: None,
    }
}

// ─── SSH ─────────────────────────────────────────────────────────────────────

/// Whether a file in ~/.ssh that is not a public key, certificate or one of
/// ssh's own files looks like a private key: a PEM or OpenSSH private-key
/// header, a PuTTY key, or the `id_*` name ssh-keygen gives keys.
fn looks_like_private_key(name: &str, text: &str) -> bool {
    let header = text.contains("-----BEGIN") && text.contains("PRIVATE KEY");
    header || text.starts_with("PuTTY-User-Key-File") || name.starts_with("id_")
}

fn ssh(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let dir = ctx.path(".ssh");
    let production_hosts = ssh_config_hosts(ctx);
    if let Some(entries) = ctx.read_dir(&dir) {
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            // Finder's folder metadata is not a key file.
            if name == ".DS_Store" {
                continue;
            }
            if name.ends_with("-cert.pub") {
                if let Some(text) = ctx.read(&path) {
                    let cert = parsers::parse_ssh_certificate(text.trim());
                    if cert.is_none() && has_content(&text) {
                        ctx.could_not_interpret(&path);
                    }
                    if let Some(cert) = cert {
                        let mut c = DiscoveredCredential::new(
                            CredentialKind::SshCertificate,
                            &name,
                            &ctx.display(&path),
                            "SSH hosts trusting the CA",
                        );
                        c.permissions.identity = Some(cert.key_id.clone());
                        c.permissions.scope = cert
                            .principals
                            .iter()
                            .map(|p| format!("principal {p}"))
                            .collect();
                        c.permissions.lifetime = if cert.valid_before == u64::MAX {
                            Lifetime::LongLived
                        } else if cert.valid_before <= ctx.now {
                            Lifetime::ExpiredAt(cert.valid_before)
                        } else {
                            Lifetime::ExpiresAt(cert.valid_before)
                        };
                        c.permissions.assurance = Assurance::Inferred;
                        c.fingerprint = Fingerprint(format!("serial {}", cert.serial));
                        c.persistence = Persistence::IndependentCredential;
                        c.evidence.push(format!(
                            "{} certificate, {} extension(s): {}",
                            if cert.cert_type == 1 { "user" } else { "host" },
                            cert.extensions.len(),
                            cert.extensions.join(", ")
                        ));
                        let production = cert.principals.iter().any(|p| ctx.is_production(p));
                        if production {
                            c.permissions.can_access_production = Capability::Yes;
                        }
                        let links = cert
                            .principals
                            .iter()
                            .map(|p| {
                                Link::new(
                                    NodeKind::ProductionService,
                                    &format!("hosts accepting principal {p}"),
                                    EdgeKind::CanAuthenticate,
                                    Assurance::Inferred,
                                )
                                .production(ctx.is_production(p))
                            })
                            .collect();
                        out.push(Discovered {
                            credential: c,
                            links,
                            verify_key: None,
                            source: Some(path.clone()),
                        });
                    }
                }
                continue;
            }
            if name.ends_with(".pub")
                || name == "known_hosts"
                || name == "config"
                || name == "authorized_keys"
                || name.ends_with(".old")
                || path.is_dir()
            {
                continue;
            }
            let Some(text) = ctx.read(&path) else {
                continue;
            };
            let Some(info) = parsers::inspect_ssh_private_key(&text) else {
                // Not every file in ~/.ssh is a key, but one that looks like
                // a key and cannot be read as one is lost coverage.
                if has_content(&text) && looks_like_private_key(&name, &text) {
                    ctx.could_not_interpret(&path);
                }
                continue;
            };
            let pub_path = path.with_extension("pub");
            let pub_line = ctx.read(&pub_path);
            let mut c = DiscoveredCredential::new(
                CredentialKind::SshPrivateKey,
                &name,
                &ctx.display(&path),
                "SSH hosts",
            );
            c.fingerprint = pub_line
                .as_deref()
                .and_then(parsers::ssh_public_key_fingerprint)
                .map(Fingerprint)
                .unwrap_or_else(|| Fingerprint::from_secret(name.as_bytes()));
            c.permissions.lifetime = Lifetime::LongLived;
            c.permissions.assurance = Assurance::Inferred;
            c.persistence = Persistence::IndependentCredential;
            match info.encrypted {
                Some(true) => {
                    c.evidence
                        .push(format!("{} key, passphrase-protected", info.format));
                }
                Some(false) => {
                    c.unprotected = true;
                    c.evidence.push(format!(
                        "{} key, NO passphrase: usable immediately if copied",
                        info.format
                    ))
                }
                None => c
                    .evidence
                    .push(format!("{} key, passphrase status unknown", info.format)),
            }
            if let Some(comment) = pub_line
                .as_deref()
                .and_then(|l| l.split_whitespace().nth(2))
            {
                c.permissions.identity = Some(comment.to_string());
            }
            let mut links = Vec::new();
            for (host, forward) in &production_hosts {
                let mut l = Link::new(
                    NodeKind::ProductionService,
                    host,
                    EdgeKind::CanAuthenticate,
                    Assurance::Inferred,
                )
                .evidence(&format!("Host {host} in ~/.ssh/config"))
                .production(ctx.is_production(host));
                if *forward {
                    l = l.evidence("ForwardAgent yes: a compromised host can use every agent key");
                }
                links.push(l);
                attach_declared_systems(
                    ctx,
                    host,
                    &mut links,
                    EdgeKind::CanAuthenticate,
                    Assurance::Inferred,
                );
            }
            if info.encrypted == Some(true) {
                c.permissions.requires_mfa = Capability::Unknown;
            }
            out.push(Discovered {
                credential: c,
                links,
                verify_key: None,
                source: Some(path.clone()),
            });
        }
    }
    out
}

/// Why the `ssh-agent` source is not assessed when no agent is named.
pub const SSH_AGENT_NOT_SET: &str =
    "SSH_AUTH_SOCK is not set in this environment, so the agent could not be asked";

/// ssh-agent identities (read-only: request identities, never sign), a
/// source of their own (`ssh-agent`) apart from the key files.
///
/// No SSH_AUTH_SOCK does not prove the agent stopped: a scheduled check
/// runs without the login session's environment while the agent keeps its
/// keys unlocked. So the source is not assessed: identities a previous run
/// recorded become unassessed (the run is incomplete), and with none
/// recorded nothing is lost. An agent that is named but does not answer
/// is lost coverage, never "no identities".
fn ssh_agent(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    match ctx.env.get("SSH_AUTH_SOCK").cloned() {
        None => {
            ctx.notes.push(format!(
                "SSH agent identities not assessed: {SSH_AGENT_NOT_SET}"
            ));
            ctx.source_unavailable = Some(SSH_AGENT_NOT_SET.into());
        }
        Some(sock) => match ssh_agent_identities(&sock) {
            Ok(ids) => {
                for (fp, comment) in ids {
                    let mut c = DiscoveredCredential::new(
                        CredentialKind::SshAgentIdentity,
                        &comment,
                        "ssh-agent (SSH_AUTH_SOCK)",
                        "SSH hosts",
                    );
                    c.fingerprint = Fingerprint(fp);
                    c.permissions.identity = Some(comment.clone());
                    c.persistence = Persistence::RequiresEndpoint;
                    c.permissions.lifetime = Lifetime::Unknown;
                    c.evidence.push(
                        "unlocked in the agent: any process on this laptop can sign with it now"
                            .into(),
                    );
                    out.push(Discovered {
                        credential: c,
                        links: Vec::new(),
                        verify_key: None,
                        source: None,
                    });
                }
            }
            Err(AgentError::Unsupported(why)) => {
                ctx.notes.push(format!("ssh-agent not queried: {why}"));
                ctx.source_unavailable = Some(why);
            }
            Err(AgentError::Unreachable(reason)) => {
                ctx.notes.push(format!(
                    "could not query the SSH agent (SSH_AUTH_SOCK): {reason}; its identities were not assessed"
                ));
                ctx.coverage_failures.push(CoverageFailure {
                    location: SSH_AGENT_LOCATION.into(),
                    reason,
                });
            }
        },
    }
    out
}

/// The coverage-failure location for an SSH agent that did not answer.
pub const SSH_AGENT_LOCATION: &str = "SSH agent (SSH_AUTH_SOCK)";

/// Why the SSH agent's identities could not be listed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentError {
    /// This platform has no agent query: nothing was ever listed, so
    /// nothing can be falsely resolved. A note, not lost coverage.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported(String),
    /// SSH_AUTH_SOCK names an agent that could not be asked: the class of
    /// error (socket missing, connection refused, timed out, ...).
    Unreachable(String),
}

/// The class of an I/O error talking to the agent, without the path.
#[cfg(unix)]
fn agent_error_class(e: &std::io::Error) -> AgentError {
    use std::io::ErrorKind;
    AgentError::Unreachable(
        match e.kind() {
            ErrorKind::NotFound => "socket missing",
            ErrorKind::ConnectionRefused => "connection refused",
            ErrorKind::TimedOut | ErrorKind::WouldBlock => "timed out",
            ErrorKind::PermissionDenied => "permission denied",
            ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe => "the agent closed the connection",
            _ => "could not talk to the agent",
        }
        .to_string(),
    )
}

/// Hosts from ~/.ssh/config with whether agent forwarding is on.
fn ssh_config_hosts(ctx: &mut Context) -> Vec<(String, bool)> {
    let p = ctx.path(".ssh/config");
    let Some(text) = ctx.read(&p) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    let mut current: Option<(String, bool)> = None;
    for line in text.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host ") {
            if let Some(h) = current.take() {
                hosts.push(h);
            }
            let name = rest.split_whitespace().next().unwrap_or("").to_string();
            if !name.contains('*') && !name.contains('?') && !name.is_empty() {
                current = Some((
                    line[5..]
                        .trim()
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .to_string(),
                    false,
                ));
            }
        } else if lower.starts_with("forwardagent") && lower.contains("yes") {
            if let Some(h) = current.as_mut() {
                h.1 = true;
            }
        }
    }
    if let Some(h) = current.take() {
        hosts.push(h);
    }
    hosts
}

#[cfg(unix)]
fn ssh_agent_identities(sock: &str) -> Result<Vec<(String, String)>, AgentError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let unexpected = |why: &str| AgentError::Unreachable(format!("unexpected agent reply ({why})"));
    let mut stream = UnixStream::connect(sock).map_err(|e| agent_error_class(&e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();
    // SSH_AGENTC_REQUEST_IDENTITIES = 11
    stream
        .write_all(&[0, 0, 0, 1, 11])
        .map_err(|e| agent_error_class(&e))?;
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| agent_error_class(&e))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > 1 << 20 {
        return Err(unexpected("too large"));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| agent_error_class(&e))?;
    if body.first() != Some(&12) {
        return Err(unexpected("not an identities answer"));
    }
    let mut pos = 1;
    let take_u32 = |pos: &mut usize| -> Option<u32> {
        let b = body.get(*pos..*pos + 4)?;
        *pos += 4;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let truncated = || unexpected("truncated");
    let count = take_u32(&mut pos).ok_or_else(truncated)? as usize;
    let mut out = Vec::new();
    for _ in 0..count.min(256) {
        let blob_len = take_u32(&mut pos).ok_or_else(truncated)? as usize;
        let blob = body
            .get(pos..pos + blob_len)
            .ok_or_else(truncated)?
            .to_vec();
        pos += blob_len;
        let comment_len = take_u32(&mut pos).ok_or_else(truncated)? as usize;
        let comment =
            String::from_utf8_lossy(body.get(pos..pos + comment_len).ok_or_else(truncated)?)
                .to_string();
        pos += comment_len;
        use base64::Engine;
        use sha2::Digest;
        let fp = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(&blob))
        );
        out.push((
            fp,
            if comment.is_empty() {
                "(no comment)".into()
            } else {
                comment
            },
        ));
    }
    Ok(out)
}

#[cfg(not(unix))]
fn ssh_agent_identities(_sock: &str) -> Result<Vec<(String, String)>, AgentError> {
    Err(AgentError::Unsupported(
        "agent query not supported on this platform".into(),
    ))
}

// ─── Cryptocurrency wallets and signing ──────────────────────────────────────

fn crypto_wallets(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();

    // Ethereum JSON keystores (geth, foundry, hardhat). Only the public address is read.
    for rel in [
        ".ethereum/keystore",
        "Library/Ethereum/keystore",
        ".foundry/keystores",
        ".local/share/io.parity.ethereum/keys",
    ] {
        let dir = ctx.path(rel);
        let Some(entries) = ctx.read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() || entry.file_name() == ".DS_Store" {
                continue;
            }
            let Some(v) = ctx.read_json(&path) else {
                continue;
            };
            // A keystore names its address at the top level. One without it
            // (some tools leave it out) is still a keystore when it has the
            // encrypted key; anything else in a keystore folder is a shape
            // Gorse cannot read, never "no wallet".
            let address = v["address"].as_str().map(|a| {
                if a.starts_with("0x") {
                    a.to_string()
                } else {
                    format!("0x{a}")
                }
            });
            let keystore_without_address = address.is_none()
                && (v["crypto"].is_object() || v["Crypto"].is_object())
                && v["id"].is_string();
            if address.is_none() && !keystore_without_address {
                ctx.could_not_interpret(&path);
                continue;
            }
            let mut c = DiscoveredCredential::new(
                CredentialKind::EthereumKeystore,
                &entry.file_name().to_string_lossy(),
                &ctx.display(&path),
                "Ethereum",
            );
            c.permissions.identity = address.clone();
            c.fingerprint = match &address {
                Some(a) => Fingerprint::from_public_id(a),
                None => Fingerprint::from_public_id(v["id"].as_str().unwrap_or_default()),
            };
            if address.is_none() {
                c.evidence.push(
                    "keystore does not name its address; the wallet it controls is unknown".into(),
                );
            }
            let address = address.unwrap_or_default();
            c.permissions.lifetime = Lifetime::LongLived;
            c.permissions.assurance = Assurance::Inferred;
            c.persistence = Persistence::IndependentCredential;
            c.evidence.push("password-encrypted keystore (scrypt/pbkdf2); offline brute force is possible once copied".into());
            let links = if address.is_empty() {
                Vec::new()
            } else {
                wallet_links_for_address(ctx, &address, "Ethereum", Assurance::Inferred)
            };
            out.push(Discovered {
                credential: c,
                links,
                verify_key: None,
                source: Some(path.clone()),
            });
        }
    }

    // Solana keypair: 64-byte array, public key is the second half.
    let sol = ctx.path(".config/solana/id.json");
    if let Some(v) = ctx.read_json(&sol) {
        // Exactly 64 integers 0-255; anything else is a shape Gorse cannot
        // read, never "no keypair".
        let bytes: Option<Vec<u8>> = v.as_array().and_then(|arr| {
            arr.iter()
                .map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect()
        });
        let bytes = bytes.filter(|b| b.len() == 64);
        if bytes.is_none() {
            ctx.could_not_interpret(&sol);
        }
        if let Some(bytes) = bytes {
            let mut c = DiscoveredCredential::new(
                CredentialKind::SolanaKeypair,
                "solana id.json",
                &ctx.display(&sol),
                "Solana",
            );
            if bytes.len() == 64 {
                let pubkey = base58(&bytes[32..]);
                c.permissions.identity = Some(pubkey.clone());
                c.fingerprint = Fingerprint::from_public_id(&pubkey);
                let links = wallet_links_for_address(ctx, &pubkey, "Solana", Assurance::Inferred);
                c.permissions.lifetime = Lifetime::LongLived;
                c.permissions.assurance = Assurance::Inferred;
                c.permissions.requires_independent_approval = Capability::No;
                c.persistence = Persistence::IndependentCredential;
                c.evidence.push(
                    "UNENCRYPTED private key: anyone with the file can sign and transfer".into(),
                );
                out.push(Discovered {
                    credential: c,
                    links,
                    verify_key: None,
                    source: Some(sol.clone()),
                });
            }
        }
    }

    // Bitcoin Core, Electrum, Sparrow, Ledger Live: wallet files and RPC config.
    let btc_dirs = [".bitcoin", "Library/Application Support/Bitcoin"];
    for rel in btc_dirs {
        let conf = ctx.path(rel).join("bitcoin.conf");
        if let Some(text) = ctx.read(&conf) {
            let has_rpc = text.lines().any(|l| {
                l.starts_with("rpcuser") || l.starts_with("rpcauth") || l.starts_with("rpcpassword")
            });
            let mut c = DiscoveredCredential::new(
                CredentialKind::BitcoinWallet,
                "Bitcoin Core node",
                &ctx.display(&conf),
                "Bitcoin Core RPC",
            );
            c.fingerprint = Fingerprint::from_secret(text.as_bytes());
            c.permissions.assurance = Assurance::Inferred;
            c.persistence = Persistence::IndependentCredential;
            if has_rpc {
                c.evidence.push("RPC credentials in bitcoin.conf: sendtoaddress/walletprocesspsbt callable if the wallet is unlocked".into());
                c.permissions.requires_independent_approval = Capability::No;
            }
            let wallets_dir = ctx.path(rel).join("wallets");
            if let Some(w) = ctx.read_dir(&wallets_dir) {
                let names: Vec<String> = w
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect();
                if !names.is_empty() {
                    c.evidence.push(format!(
                        "{} wallet(s) on disk: {}",
                        names.len(),
                        names.join(", ")
                    ));
                }
            }
            let links = vec![Link::new(
                NodeKind::Wallet,
                "Bitcoin Core wallet",
                EdgeKind::CanRequestSignature,
                Assurance::Inferred,
            )
            .evidence("local node RPC")
            .approval(if has_rpc {
                Some("wallet passphrase (if encrypted)".into())
            } else {
                None
            })];
            out.push(Discovered {
                credential: c,
                links,
                verify_key: None,
                source: Some(conf.clone()),
            });
        }
    }
    let wallet_apps: &[(&str, &str, &str)] = &[
        (".electrum/wallets", "Electrum", "Bitcoin"),
        (
            "Library/Application Support/Electrum/wallets",
            "Electrum",
            "Bitcoin",
        ),
        (".sparrow/wallets", "Sparrow", "Bitcoin"),
        (
            "Library/Application Support/Sparrow/wallets",
            "Sparrow",
            "Bitcoin",
        ),
        (
            "Library/Application Support/Ledger Live",
            "Ledger Live (hardware-backed; keys stay on device)",
            "multi-chain",
        ),
        (
            ".config/Ledger Live",
            "Ledger Live (hardware-backed; keys stay on device)",
            "multi-chain",
        ),
        (
            "Library/Application Support/Frame",
            "Frame wallet",
            "Ethereum",
        ),
    ];
    for (rel, app, chain) in wallet_apps {
        let p = ctx.path(rel);
        if ctx.present(&p) {
            let count = ctx.read_dir(&p).map(|d| d.count()).unwrap_or(0);
            let mut c = DiscoveredCredential::new(
                CredentialKind::BitcoinWallet,
                app,
                &ctx.display(&p),
                chain,
            );
            c.fingerprint = Fingerprint::from_secret(rel.as_bytes());
            c.permissions.assurance = Assurance::Inferred;
            let hardware = app.contains("hardware");
            c.persistence = if hardware {
                Persistence::RequiresEndpoint
            } else {
                Persistence::IndependentCredential
            };
            c.permissions.requires_independent_approval = if hardware {
                Capability::Yes
            } else {
                Capability::Unknown
            };
            c.evidence.push(format!(
                "{count} entries; {}",
                if hardware {
                    "signing needs the physical device and on-device confirmation"
                } else {
                    "software wallet files; protected only by the wallet password"
                }
            ));
            out.push(Discovered {
                credential: c,
                links: Vec::new(),
                verify_key: None,
                source: Some(p.clone()),
            });
        }
    }

    // Browser extension wallets (vault is password-encrypted, but the vault file is portable).
    let ext_roots = [
        "Library/Application Support/Google/Chrome",
        "Library/Application Support/BraveSoftware/Brave-Browser",
        "Library/Application Support/Microsoft Edge",
        "Library/Application Support/Arc/User Data",
        ".config/google-chrome",
        ".config/BraveSoftware/Brave-Browser",
        "AppData/Local/Google/Chrome/User Data",
    ];
    let extensions: &[(&str, &str)] = &[
        ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
        ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"),
        ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
        ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
        ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
        ("ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask (Edge)"),
    ];
    for root in ext_roots {
        let root_path = ctx.path(root);
        if !ctx.present(&root_path) {
            continue;
        }
        let Some(profiles) = ctx.read_dir(&root_path) else {
            continue;
        };
        for profile in profiles.flatten() {
            let settings = profile.path().join("Local Extension Settings");
            if !ctx.present(&settings) {
                continue;
            }
            for (id, name) in extensions {
                let p = settings.join(id);
                if ctx.present(&p) {
                    let mut c = DiscoveredCredential::new(
                        CredentialKind::EthereumKeystore,
                        &format!("{name} browser wallet"),
                        &ctx.display(&p),
                        "browser wallet",
                    );
                    c.fingerprint = Fingerprint::from_secret(id.as_bytes());
                    c.permissions.assurance = Assurance::Inferred;
                    c.permissions.requires_independent_approval = Capability::Yes;
                    c.persistence = Persistence::IndependentCredential;
                    c.evidence.push("vault encrypted with the wallet password; dApp connections (incl. WalletConnect) live here too".into());
                    c.evidence.push("every transaction needs a click in the extension, but a compromised browser can be driven".into());
                    out.push(Discovered {
                        credential: c,
                        links: Vec::new(),
                        verify_key: None,
                        source: Some(p.clone()),
                    });
                }
            }
        }
    }

    // WalletConnect desktop session stores.
    for rel in [
        ".walletconnect",
        "Library/Application Support/WalletConnect",
    ] {
        let p = ctx.path(rel);
        if ctx.present(&p) {
            let mut c = DiscoveredCredential::new(
                CredentialKind::WalletConnectSession,
                "WalletConnect session store",
                &ctx.display(&p),
                "connected dApps",
            );
            c.fingerprint = Fingerprint::from_secret(rel.as_bytes());
            c.persistence = Persistence::RequiresEndpoint;
            c.permissions.requires_independent_approval = Capability::Yes;
            c.evidence.push(
                "sessions let dApps *request* signatures; the wallet still approves each one"
                    .into(),
            );
            out.push(Discovered {
                credential: c,
                links: Vec::new(),
                verify_key: None,
                source: Some(p.clone()),
            });
        }
    }
    out
}

/// Links from a key to the declared wallet(s) it controls.
fn wallet_links_for_address(
    ctx: &Context,
    address: &str,
    chain: &str,
    assurance: Assurance,
) -> Vec<Link> {
    let mut links = Vec::new();
    let matched = ctx.decl.wallets.iter().find(|w| {
        w.address
            .as_deref()
            .map(|a| a.eq_ignore_ascii_case(address))
            .unwrap_or(false)
    });
    match matched {
        Some(w) => {
            links.push(
                Link::new(
                    NodeKind::Wallet,
                    &w.name,
                    EdgeKind::CanTransferAssets,
                    assurance,
                )
                .evidence(&format!(
                    "key controls declared wallet {} ({})",
                    w.name, w.chain
                ))
                .production(w.production),
            );
        }
        None => {
            let short = Fingerprint::from_public_id(address).0;
            links.push(
                Link::new(
                    NodeKind::Wallet,
                    &format!("{chain} account {short}"),
                    EdgeKind::CanTransferAssets,
                    assurance,
                )
                .evidence("raw key: no policy, no second approver")
                .production(false),
            );
        }
    }
    links
}

fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s: String = bytes.iter().take_while(|b| **b == 0).map(|_| '1').collect();
    s.extend(digits.iter().rev().map(|d| ALPHABET[*d as usize] as char));
    s
}

// ─── Declared signing services ───────────────────────────────────────────────

fn declared_signers(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let signers = ctx.decl.signers.clone();
    for signer in &signers {
        let mut present: Vec<(String, Fingerprint)> = Vec::new();
        for var in &signer.api_env {
            if let Some(v) = ctx.env.get(var) {
                present.push((format!("env {var}"), Fingerprint::from_secret(v.as_bytes())));
            }
        }
        for file in &signer.api_files {
            let p = ctx.expand(file);
            if ctx.present(&p) {
                present.push((ctx.display(&p), Fingerprint::from_secret(file.as_bytes())));
            }
        }
        // Well-known signing-service variables, so a declaration with no api_env still works.
        let known: &[(&str, &str)] = &[
            ("FIREBLOCKS_API_KEY", "fireblocks"),
            ("FIREBLOCKS_SECRET_KEY_PATH", "fireblocks"),
            ("TURNKEY_API_PRIVATE_KEY", "turnkey"),
            ("DFNS_PRIVATE_KEY", "dfns"),
            ("BITGO_ACCESS_TOKEN", "bitgo"),
            ("COBO_API_SECRET", "cobo"),
            ("COPPER_API_SECRET", "copper"),
            ("SAFE_API_KEY", "safe"),
        ];
        for (var, vendor) in known {
            if signer.name.to_ascii_lowercase().contains(vendor)
                || signer.kind.to_ascii_lowercase().contains(vendor)
            {
                if let Some(v) = ctx.env.get(*var) {
                    if !present.iter().any(|(loc, _)| loc == &format!("env {var}")) {
                        present
                            .push((format!("env {var}"), Fingerprint::from_secret(v.as_bytes())));
                    }
                }
            }
        }
        if present.is_empty() {
            continue;
        }
        let (location, fingerprint) = present[0].clone();
        let mut c = DiscoveredCredential::new(
            CredentialKind::SigningServiceApiKey,
            &format!("{} API credential", signer.name),
            &location,
            &signer.name,
        );
        c.fingerprint = fingerprint;
        c.permissions.assurance = Assurance::Inferred;
        c.permissions.lifetime = Lifetime::Unknown;
        c.permissions.can_reach_signing_infrastructure = Capability::Yes;
        c.permissions.requires_independent_approval = if signer.requires_independent_approval {
            Capability::Yes
        } else {
            Capability::No
        };
        c.persistence = Persistence::IndependentCredential;
        c.evidence
            .push(format!("{} signer declared in authority.toml", signer.kind));
        if present.len() > 1 {
            c.evidence
                .push(format!("{} credential sources present", present.len()));
        }
        if !signer.enforces_transaction_policy {
            c.evidence.push(
                "signer signs supplied payloads; it does not enforce destinations or limits".into(),
            );
        }
        if let (Some(t), Some(here)) = (signer.threshold, signer.approvers_on_this_laptop) {
            if here >= t {
                c.evidence.push(format!("{here} of the {t} required approvers are on this laptop: quorum is NOT independent"));
            } else {
                c.evidence
                    .push(format!("{here} of {t} required approvers on this laptop"));
            }
        }
        if !signer.shared_dependencies.is_empty() {
            c.evidence.push(format!(
                "shares a dependency with: {} (one compromise, several 'independent' signers)",
                signer.shared_dependencies.join(", ")
            ));
        }
        let mut links = Vec::new();
        let approval = if signer.requires_independent_approval {
            signer
                .approval
                .clone()
                .or_else(|| Some("independent approval (declared)".into()))
        } else {
            None
        };
        let quorum_here = matches!((signer.threshold, signer.approvers_on_this_laptop), (Some(t), Some(h)) if h >= t);
        let approval = if quorum_here { None } else { approval };
        links.push(
            Link::new(
                NodeKind::Signer,
                &signer.name,
                EdgeKind::CanRequestSignature,
                Assurance::Inferred,
            )
            .evidence(&format!("API credential present ({location})"))
            .production(true),
        );
        if signer.api_can_change_policy {
            links.push(
                Link::new(
                    NodeKind::Signer,
                    &signer.name,
                    EdgeKind::CanChangeSigningPolicy,
                    Assurance::Inferred,
                )
                .evidence("declared: API credential can change signing policy or signer set")
                .approval(approval.clone())
                .production(true),
            );
        }
        if signer.accepts_arbitrary_7702 {
            links.push(
                Link::new(
                    NodeKind::Signer,
                    &signer.name,
                    EdgeKind::CanInstallDelegation,
                    Assurance::Inferred,
                )
                .evidence("declared: signer accepts arbitrary EIP-7702 authorization tuples")
                .approval(approval.clone())
                .production(true),
            );
        }
        out.push(Discovered {
            credential: c,
            links,
            verify_key: Some(format!("signer:{}", signer.name)),
            source: None,
        });
    }
    out
}

// ─── Environment variables ───────────────────────────────────────────────────

/// (variable, kind, target, description)
const ENV_TABLE: &[(&str, CredentialKind, &str, &str)] = &[
    (
        "ALCHEMY_API_KEY",
        CredentialKind::RpcProviderKey,
        "Alchemy",
        "RPC provider key: read chain state, submit signed txs; cannot sign",
    ),
    (
        "INFURA_API_KEY",
        CredentialKind::RpcProviderKey,
        "Infura",
        "RPC provider key: read chain state, submit signed txs; cannot sign",
    ),
    (
        "INFURA_PROJECT_ID",
        CredentialKind::RpcProviderKey,
        "Infura",
        "RPC provider key: read chain state, submit signed txs; cannot sign",
    ),
    (
        "QUICKNODE_API_KEY",
        CredentialKind::RpcProviderKey,
        "QuickNode",
        "RPC provider key",
    ),
    (
        "HELIUS_API_KEY",
        CredentialKind::RpcProviderKey,
        "Helius",
        "Solana RPC provider key",
    ),
    (
        "ETHERSCAN_API_KEY",
        CredentialKind::RpcProviderKey,
        "Etherscan",
        "block explorer API key (read-only)",
    ),
    (
        "MORALIS_API_KEY",
        CredentialKind::RpcProviderKey,
        "Moralis",
        "chain data API key",
    ),
    (
        "ETH_RPC_URL",
        CredentialKind::RpcProviderKey,
        "Ethereum RPC",
        "RPC endpoint (may embed a provider key)",
    ),
    (
        "RPC_URL",
        CredentialKind::RpcProviderKey,
        "RPC",
        "RPC endpoint (may embed a provider key)",
    ),
    (
        "WALLETCONNECT_PROJECT_ID",
        CredentialKind::RpcProviderKey,
        "WalletConnect Cloud",
        "project id (public identifier)",
    ),
    (
        "PRIVATE_KEY",
        CredentialKind::EthereumPrivateKey,
        "Ethereum",
        "raw private key in the environment: full signing authority, no approval",
    ),
    (
        "DEPLOYER_PRIVATE_KEY",
        CredentialKind::EthereumPrivateKey,
        "Ethereum",
        "deployer private key: deploys and upgrades contracts",
    ),
    (
        "ETH_PRIVATE_KEY",
        CredentialKind::EthereumPrivateKey,
        "Ethereum",
        "raw private key in the environment",
    ),
    (
        "MNEMONIC",
        CredentialKind::EthereumPrivateKey,
        "HD wallet",
        "seed phrase in the environment: every derived account",
    ),
    (
        "SEED_PHRASE",
        CredentialKind::EthereumPrivateKey,
        "HD wallet",
        "seed phrase in the environment: every derived account",
    ),
    (
        "FIREBLOCKS_API_KEY",
        CredentialKind::SigningServiceApiKey,
        "Fireblocks",
        "custody API key; authority depends on the API user's role and TAP policy",
    ),
    (
        "TURNKEY_API_PRIVATE_KEY",
        CredentialKind::SigningServiceApiKey,
        "Turnkey",
        "signing service API key; authority depends on org policies",
    ),
    (
        "DFNS_PRIVATE_KEY",
        CredentialKind::SigningServiceApiKey,
        "Dfns",
        "signing service credential",
    ),
    (
        "BITGO_ACCESS_TOKEN",
        CredentialKind::SigningServiceApiKey,
        "BitGo",
        "custody access token; spending limits apply per token",
    ),
    (
        "COBO_API_SECRET",
        CredentialKind::SigningServiceApiKey,
        "Cobo",
        "custody API secret",
    ),
    (
        "ANTHROPIC_API_KEY",
        CredentialKind::ApiKey,
        "Anthropic",
        "billable API key",
    ),
    (
        "OPENAI_API_KEY",
        CredentialKind::ApiKey,
        "OpenAI",
        "billable API key",
    ),
    (
        "STRIPE_SECRET_KEY",
        CredentialKind::ApiKey,
        "Stripe",
        "payment API key: refunds, payouts and charges are real money",
    ),
    (
        "TWILIO_AUTH_TOKEN",
        CredentialKind::ApiKey,
        "Twilio",
        "billable messaging credential",
    ),
    (
        "SENDGRID_API_KEY",
        CredentialKind::ApiKey,
        "SendGrid",
        "mail sending credential",
    ),
    (
        "DATABASE_URL",
        CredentialKind::ApiKey,
        "database",
        "connection string with embedded password",
    ),
    (
        "NPM_TOKEN",
        CredentialKind::ApiKey,
        "npm registry",
        "package publishing token",
    ),
    (
        "DOCKER_PASSWORD",
        CredentialKind::DockerRegistry,
        "container registry",
        "registry password",
    ),
    (
        "CI_JOB_TOKEN",
        CredentialKind::CiToken,
        "GitLab CI",
        "job token",
    ),
    (
        "CIRCLE_TOKEN",
        CredentialKind::CiToken,
        "CircleCI",
        "API token",
    ),
    (
        "VERCEL_TOKEN",
        CredentialKind::CiToken,
        "Vercel",
        "deployment token",
    ),
    (
        "HEROKU_API_KEY",
        CredentialKind::CiToken,
        "Heroku",
        "deployment token",
    ),
    (
        "CLOUDFLARE_API_TOKEN",
        CredentialKind::CiToken,
        "Cloudflare",
        "DNS/Workers token: DNS control enables traffic interception",
    ),
    (
        "DIGITALOCEAN_ACCESS_TOKEN",
        CredentialKind::CiToken,
        "DigitalOcean",
        "infrastructure token",
    ),
    (
        "AZURE_CLIENT_SECRET",
        CredentialKind::AzureServicePrincipal,
        "Azure",
        "service principal secret",
    ),
    (
        "K8S_TOKEN",
        CredentialKind::KubernetesContext,
        "Kubernetes",
        "bearer token",
    ),
];

/// True for a value shaped like an EVM private key: 32 bytes as hex,
/// with or without a 0x prefix.
fn looks_like_evm_private_key(value: &str) -> bool {
    let hex = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn classify_env_var(name: &str, value: &str) -> Option<(CredentialKind, String, String)> {
    if let Some((_, kind, target, desc)) = ENV_TABLE.iter().find(|(n, _, _, _)| *n == name) {
        // Table entries for wallet keys are only trusted when the value has
        // the shape of one; a PEM key under DEPLOYER_PRIVATE_KEY is still a
        // private key, but not a wallet that can move funds.
        if *kind == CredentialKind::EthereumPrivateKey && !looks_like_evm_private_key(value) {
            return Some((
                CredentialKind::EnvironmentSecret,
                target.to_string(),
                "private key of unknown purpose (not a wallet key by shape)".to_string(),
            ));
        }
        return Some((*kind, target.to_string(), desc.to_string()));
    }
    let upper = name.to_ascii_uppercase();
    let generic = [
        "_TOKEN",
        "_SECRET",
        "_API_KEY",
        "_APIKEY",
        "_PASSWORD",
        "_PRIVATE_KEY",
        "_ACCESS_KEY",
    ];
    if generic.iter().any(|s| upper.ends_with(s)) {
        // `*_PRIVATE_KEY` is a wallet key only when the value is shaped like
        // one. A TLS or signing key in PEM form is a private key of unknown
        // purpose, reported as such rather than as funds at risk.
        let (kind, desc) = if upper.ends_with("_PRIVATE_KEY") {
            if looks_like_evm_private_key(value) {
                (
                    CredentialKind::EthereumPrivateKey,
                    "secret-looking environment variable",
                )
            } else {
                (
                    CredentialKind::EnvironmentSecret,
                    "private key of unknown purpose (not a wallet key by shape)",
                )
            }
        } else {
            (
                CredentialKind::EnvironmentSecret,
                "secret-looking environment variable",
            )
        };
        return Some((
            kind,
            name.trim_end_matches(|c: char| c.is_ascii_uppercase() || c == '_')
                .to_string(),
            desc.to_string(),
        ));
    }
    None
}

fn environment(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let skip = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "VAULT_TOKEN",
        "DIGITALOCEAN_ACCESS_TOKEN",
        "DIGITALOCEAN_TOKEN",
    ];
    for (name, value) in &ctx.env {
        if skip.contains(&name.as_str()) || name.starts_with("TF_TOKEN_") || value.trim().is_empty()
        {
            continue;
        }
        if name.starts_with("GORSE_") || name.starts_with("HEDGEHOG_") {
            continue;
        }
        let Some((kind, target, desc)) = classify_env_var(name, value) else {
            continue;
        };
        let is_url = value.contains("://");
        let embeds_secret = is_url
            && value
                .split("//")
                .nth(1)
                .map(|r| r.contains('@') || r.matches('/').count() >= 2)
                .unwrap_or(false);
        if kind == CredentialKind::RpcProviderKey && is_url && !embeds_secret {
            continue; // public endpoint, nothing to protect
        }
        if value.len() < 8 && kind != CredentialKind::RpcProviderKey {
            continue; // placeholder like "changeme"
        }
        out.push(env_credential(
            ctx,
            kind,
            name,
            &format!("env {name}"),
            &target,
            &desc,
            value,
        ));
    }
    out
}

fn env_credential(
    ctx: &Context,
    kind: CredentialKind,
    name: &str,
    location: &str,
    target: &str,
    desc: &str,
    value: &str,
) -> Discovered {
    let mut c = DiscoveredCredential::new(kind, name, location, target);
    c.fingerprint = Fingerprint::from_secret(value.trim().as_bytes());
    c.permissions.lifetime = Lifetime::Unknown;
    c.permissions.assurance = Assurance::Inferred;
    c.persistence = Persistence::IndependentCredential;
    c.evidence.push(desc.to_string());
    let mut links = Vec::new();
    match kind {
        CredentialKind::EthereumPrivateKey => {
            c.permissions.lifetime = Lifetime::LongLived;
            c.permissions.requires_independent_approval = Capability::No;
            c.permissions.requires_mfa = Capability::No;
            let is_seed = value.split_whitespace().count() >= 12;
            let name_for_wallet = if is_seed {
                "HD wallet (seed phrase)".to_string()
            } else {
                format!("account signed by {name}")
            };
            let declared = ctx.decl.wallets.iter().find(|w| {
                w.name.eq_ignore_ascii_case(name) || w.rpc_url_env.as_deref() == Some(name)
            });
            let wallet_name = declared.map(|w| w.name.clone()).unwrap_or(name_for_wallet);
            links.push(
                Link::new(
                    NodeKind::Wallet,
                    &wallet_name,
                    EdgeKind::CanTransferAssets,
                    Assurance::Inferred,
                )
                .evidence("raw key material: whoever holds it signs anything")
                .production(declared.map(|w| w.production).unwrap_or(false)),
            );
            c.evidence.push(if is_seed {
                "seed phrase: controls every derived account on every chain".into()
            } else {
                "a raw key has no policy engine, no limit and no second approver".into()
            });
        }
        CredentialKind::SigningServiceApiKey => {
            c.permissions.can_reach_signing_infrastructure = Capability::Yes;
            let declared = ctx.decl.signers.iter().find(|s| {
                s.api_env.iter().any(|v| v == name)
                    || target
                        .to_ascii_lowercase()
                        .contains(&s.name.to_ascii_lowercase())
                    || s.name
                        .to_ascii_lowercase()
                        .contains(&target.to_ascii_lowercase())
            });
            match declared {
                Some(s) => {
                    let approval = if s.requires_independent_approval {
                        s.approval
                            .clone()
                            .or_else(|| Some("independent approval (declared)".into()))
                    } else {
                        None
                    };
                    links.push(
                        Link::new(
                            NodeKind::Signer,
                            &s.name,
                            EdgeKind::CanRequestSignature,
                            Assurance::Inferred,
                        )
                        .approval(approval)
                        .production(true),
                    );
                }
                None => {
                    links.push(
                        Link::new(
                            NodeKind::Signer,
                            target,
                            EdgeKind::CanRequestSignature,
                            Assurance::Inferred,
                        )
                        .evidence("not declared in authority.toml: approval policy unknown")
                        .production(true),
                    );
                    c.permissions.requires_independent_approval = Capability::Unknown;
                }
            }
        }
        CredentialKind::RpcProviderKey => {
            links.push(
                Link::new(
                    NodeKind::Other,
                    target,
                    EdgeKind::CanReach,
                    Assurance::Inferred,
                )
                .evidence("RPC access reads public chain state; it cannot sign"),
            );
        }
        CredentialKind::CiToken => {
            c.permissions.can_modify_production = Capability::Yes;
            links.push(
                Link::new(
                    NodeKind::CiSystem,
                    target,
                    EdgeKind::CanDeploy,
                    Assurance::Inferred,
                )
                .production(true),
            );
        }
        CredentialKind::ApiKey if target == "Stripe" => {
            links.push(
                Link::new(
                    NodeKind::FinancialAsset,
                    "Stripe balance",
                    EdgeKind::CanTransferAssets,
                    Assurance::Inferred,
                )
                .evidence("secret key can create payouts and refunds")
                .production(!value.contains("_test_")),
            );
            if value.contains("_test_") {
                c.evidence.push("test-mode key".into());
            }
        }
        _ => {}
    }
    Discovered {
        credential: c,
        links,
        verify_key: None,
        source: None,
    }
}

/// `.env*` files in the current directory and declared project dirs.
fn project_env_files(ctx: &mut Context) -> Vec<Discovered> {
    let mut out = Vec::new();
    let mut dirs = vec![ctx.cwd.clone()];
    for d in &ctx.decl.settings.project_dirs {
        dirs.push(ctx.expand(d));
    }
    dirs.dedup();
    for dir in dirs {
        let Some(entries) = ctx.read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !(name == ".env" || name.starts_with(".env."))
                || name.ends_with(".example")
                || name.ends_with(".sample")
                || name.ends_with(".template")
            {
                continue;
            }
            let path = entry.path();
            let Some(text) = ctx.read(&path) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim().trim_start_matches("export ").trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((k, v)) = line.split_once('=') else {
                    continue;
                };
                let key = k.trim();
                let value = v.trim().trim_matches('"').trim_matches('\'');
                if value.is_empty() || value.starts_with("${") {
                    continue;
                }
                let Some((kind, target, desc)) = classify_env_var(key, value) else {
                    continue;
                };
                if kind == CredentialKind::RpcProviderKey
                    && value.contains("://")
                    && !value.contains('@')
                    && value.matches('/').count() < 4
                {
                    continue;
                }
                if value.len() < 8 {
                    continue;
                }
                let location = format!("{} ({key})", ctx.display(&path));
                let mut d = env_credential(ctx, kind, key, &location, &target, &desc, value);
                d.source = Some(path.clone());
                out.push(d);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_variables_are_wallets_only_by_shape() {
        // A 32-byte hex value is a wallet key; anything else under a
        // *_PRIVATE_KEY name (a TLS key in PEM, a signing key) is a private
        // key of unknown purpose and never "funds at risk".
        let hex = "0x".to_string() + &"ab".repeat(32);
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        assert_eq!(
            classify_env_var("TLS_PRIVATE_KEY", pem).unwrap().0,
            CredentialKind::EnvironmentSecret
        );
        assert_eq!(
            classify_env_var("TLS_PRIVATE_KEY", &hex).unwrap().0,
            CredentialKind::EthereumPrivateKey
        );
        assert_eq!(
            classify_env_var("DEPLOYER_PRIVATE_KEY", pem).unwrap().0,
            CredentialKind::EnvironmentSecret
        );
        assert_eq!(
            classify_env_var("DEPLOYER_PRIVATE_KEY", &"cd".repeat(32))
                .unwrap()
                .0,
            CredentialKind::EthereumPrivateKey
        );
        assert_eq!(
            classify_env_var("JWT_PRIVATE_KEY", "not-a-key").unwrap().0,
            CredentialKind::EnvironmentSecret
        );
        assert!(classify_env_var("TLS_PRIVATE_KEY", pem)
            .unwrap()
            .2
            .contains("unknown purpose"));
        assert!(classify_env_var("UNRELATED_SETTING", "x").is_none());
    }

    fn fixture_home() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hedgehog-exposure-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write(home: &Path, rel: &str, text: &str) {
        let p = home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn ctx<'a>(home: &Path, decl: &'a Declarations) -> Context<'a> {
        Context {
            home: home.to_path_buf(),
            cwd: home.to_path_buf(),
            env: BTreeMap::new(),
            decl,
            now: 1_800_000_000,
            notes: Vec::new(),
            coverage_failures: Vec::new(),
            source_unavailable: None,
        }
    }

    const FAKE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    #[test]
    fn doctl_contexts_and_environment_tokens_are_found_once_each() {
        // doctl keeps the default token under access-token and named ones
        // under auth-contexts; the selected context is marked. A token in
        // the environment is one credential, not a DigitalOcean one plus a
        // generic environment secret.
        let home = fixture_home();
        write(
            &home,
            ".config/doctl/config.yaml",
            "access-token: dop_v1_1111111111111111111111111111111111111111111111111111111111111111\ncontext: staging\nauth-contexts:\n  staging: dop_v1_2222222222222222222222222222222222222222222222222222222222222222\noutput: text\n",
        );
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        c.env.insert(
            "DIGITALOCEAN_TOKEN".into(),
            "dop_v1_3333333333333333333333333333333333333333333333333333333333333333".into(),
        );
        let found = discover_all(&mut c);
        let tokens: Vec<&Discovered> = found
            .iter()
            .filter(|d| d.credential.kind == CredentialKind::DigitalOceanToken)
            .collect();
        assert_eq!(
            tokens.len(),
            3,
            "{:?}",
            found
                .iter()
                .map(|d| (&d.credential.name, d.credential.kind))
                .collect::<Vec<_>>()
        );
        let by_name = |n: &str| {
            tokens
                .iter()
                .find(|d| d.credential.name == n)
                .unwrap_or_else(|| panic!("no token named {n}"))
        };
        let default = by_name("default");
        let staging = by_name("staging");
        let env_token = by_name("DIGITALOCEAN_TOKEN");
        assert_eq!(default.credential.location, "~/.config/doctl/config.yaml");
        assert_eq!(
            default.verify_key.as_deref(),
            Some("config-token:access-token")
        );
        assert_eq!(staging.verify_key.as_deref(), Some("staging"));
        assert_eq!(env_token.credential.location, "env DIGITALOCEAN_TOKEN");
        assert_eq!(
            env_token.verify_key.as_deref(),
            Some("env:DIGITALOCEAN_TOKEN")
        );
        assert!(staging
            .credential
            .evidence
            .iter()
            .any(|e| e == "selected doctl context"));
        assert!(!default
            .credential
            .evidence
            .iter()
            .any(|e| e == "selected doctl context"));
        assert_ne!(
            default.credential.fingerprint,
            staging.credential.fingerprint
        );
        for d in &tokens {
            let text = format!("{:?}", d.credential);
            assert!(
                !text.contains("dop_v1_1111")
                    && !text.contains("dop_v1_2222")
                    && !text.contains("dop_v1_3333"),
                "{text}"
            );
            assert_eq!(d.credential.persistence, Persistence::IndependentCredential);
            assert_eq!(d.credential.permissions.assurance, Assurance::Inferred);
            assert!(d
                .links
                .iter()
                .any(|l| l.kind == NodeKind::CloudRole && l.name == "DigitalOcean account"));
        }
        assert!(
            !found
                .iter()
                .any(|d| d.credential.kind == CredentialKind::EnvironmentSecret
                    && d.credential.name == "DIGITALOCEAN_TOKEN"),
            "the environment token must not also be listed as a generic secret"
        );
    }

    fn doctl_tokens(text: &str) -> (Vec<(String, String)>, Vec<CoverageFailure>, SourceCoverage) {
        let home = fixture_home();
        write(&home, ".config/doctl/config.yaml", text);
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let (found, coverage) = discover_sources(&mut c);
        let tokens = found
            .iter()
            .filter(|(d, _)| d.credential.kind == CredentialKind::DigitalOceanToken)
            .map(|(d, source)| {
                assert_eq!(*source, "doctl-config");
                (
                    d.credential.name.clone(),
                    d.credential.fingerprint.0.clone(),
                )
            })
            .collect();
        let _ = std::fs::remove_dir_all(&home);
        (tokens, c.coverage_failures, coverage)
    }

    #[test]
    fn byte_order_mark_and_finder_metadata_are_not_coverage_failures() {
        let home = fixture_home();
        write(
            &home,
            ".azure/azureProfile.json",
            "\u{feff}{\"subscriptions\": [{\"id\": \"00000000-0000-0000-0000-000000000001\", \"name\": \"Pay-As-You-Go\", \"user\": {\"name\": \"a@example.invalid\", \"type\": \"user\"}}]}",
        );
        let ds = home.join(".ssh/.DS_Store");
        std::fs::create_dir_all(ds.parent().unwrap()).unwrap();
        std::fs::write(&ds, [0u8, 0, 0, 1, 0xff, 0xfe, 0x80]).unwrap();
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let found = discover_all(&mut c);
        assert!(c.coverage_failures.is_empty(), "{:?}", c.coverage_failures);
        assert!(found
            .iter()
            .any(|d| d.credential.kind == CredentialKind::AzureSession));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn flow_style_doctl_config_yields_the_same_tokens_as_block_style() {
        let block = "access-token: dop_v1_1111111111111111111111111111111111111111111111111111111111111111\ncontext: staging\nauth-contexts:\n  staging: dop_v1_2222222222222222222222222222222222222222222222222222222222222222\n  \"prod\": 'dop_v1_4444444444444444444444444444444444444444444444444444444444444444'\n";
        let flow = "access-token: dop_v1_1111111111111111111111111111111111111111111111111111111111111111\ncontext: staging\nauth-contexts: {staging: dop_v1_2222222222222222222222222222222222222222222222222222222222222222, \"prod\": 'dop_v1_4444444444444444444444444444444444444444444444444444444444444444'}\n";
        let (a, a_failures, a_cov) = doctl_tokens(block);
        let (b, b_failures, b_cov) = doctl_tokens(flow);
        assert_eq!(a.len(), 3, "{a:?}");
        assert_eq!(a, b);
        assert!(a_failures.is_empty() && b_failures.is_empty());
        assert!(a_cov.assessed.iter().any(|s| s == "doctl-config"));
        assert!(b_cov.assessed.iter().any(|s| s == "doctl-config"));
    }

    #[test]
    fn a_credential_file_in_an_unsupported_format_is_lost_coverage() {
        // A flow mapping split over lines is beyond the parser: the tokens
        // are not found, and that is reported, never a clean result.
        let (tokens, failures, coverage) = doctl_tokens(
            "auth-contexts: {staging: dop_v1_2222222222222222222222222222222222222222222222222222222222222222,\n  prod: dop_v1_4444444444444444444444444444444444444444444444444444444444444444}\n",
        );
        assert!(tokens.is_empty());
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].location, "~/.config/doctl/config.yaml");
        assert_eq!(
            failures[0].reason,
            "could not interpret ~/.config/doctl/config.yaml (unsupported format)"
        );
        assert!(!coverage.assessed.iter().any(|s| s == "doctl-config"));
        assert!(coverage
            .unavailable
            .iter()
            .any(|(s, r)| s == "doctl-config" && r.contains("unsupported format")));

        // A logged-out config says so plainly and is not a failure.
        let (tokens, failures, _) =
            doctl_tokens("access-token: \"\"\ncontext: default\noutput: text\n");
        assert!(tokens.is_empty());
        assert!(failures.is_empty(), "{failures:?}");

        // Other hand-written parsers report the same way.
        let home = fixture_home();
        write(&home, ".kube/config", "this is not a kubeconfig\n");
        write(
            &home,
            ".aws/credentials",
            "aws_access_key_id AKIAIOSFODNN7EXAMPLE\n",
        );
        write(&home, ".config/gh/hosts.yml", "- github.com\n");
        write(&home, ".docker/config.json", "{\"auths\": [\"x\"]}");
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let (_, coverage) = discover_sources(&mut c);
        let failed: Vec<&str> = c
            .coverage_failures
            .iter()
            .map(|f| f.location.as_str())
            .collect();
        for location in [
            "~/.kube/config",
            "~/.aws/credentials",
            "~/.config/gh/hosts.yml",
            "~/.docker/config.json",
        ] {
            assert!(failed.contains(&location), "{location}: {failed:?}");
        }
        for source in [
            "kubeconfig",
            "aws-credentials-file",
            "github-cli",
            "docker-config",
        ] {
            assert!(!coverage.assessed.iter().any(|s| s == source), "{source}");
        }
        // An empty kubeconfig is not a failure.
        write(
            &home,
            ".kube/config",
            "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n",
        );
        let mut c = ctx(&home, &decl);
        let _ = discover_sources(&mut c);
        assert!(!c
            .coverage_failures
            .iter()
            .any(|f| f.location == "~/.kube/config"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn aws_profiles_distinguish_long_lived_sessions_and_roles() {
        let home = fixture_home();
        write(&home, ".aws/credentials", &format!("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {FAKE_SECRET}\n[temp]\naws_access_key_id = ASIAIOSFODNN7EXAMPLE\naws_secret_access_key = {FAKE_SECRET}\naws_session_token = FwoGZXIvYXdzEBYaDEXAMPLETOKEN\n"));
        write(&home, ".aws/config", "[profile prod-admin]\nrole_arn = arn:aws:iam::123456789012:role/AdministratorAccess\nsource_profile = default\nmfa_serial = arn:aws:iam::123456789012:mfa/alice\n[profile sso]\nsso_start_url = https://example.awsapps.com/start\nsso_account_id = 999\nsso_role_name = ReadOnlyAccess\n");
        write(
            &home,
            ".aws/sso/cache/abc.json",
            r#"{"startUrl":"https://example.awsapps.com/start","expiresAt":"2020-01-01T00:00:00Z"}"#,
        );
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let found = aws(&mut c);
        let by_name = |n: &str| found.iter().find(|d| d.credential.name == n).unwrap();
        let default = by_name("default");
        assert_eq!(default.credential.kind, CredentialKind::AwsAccessKey);
        assert_eq!(default.credential.permissions.lifetime, Lifetime::LongLived);
        assert_eq!(default.credential.fingerprint.0, "AKIA…MPLE");
        assert_eq!(by_name("temp").credential.kind, CredentialKind::AwsSession);
        let admin = by_name("prod-admin");
        assert_eq!(admin.credential.kind, CredentialKind::AwsProfileRole);
        assert!(admin.credential.permissions.administrative.is_yes());
        assert_eq!(admin.credential.permissions.assurance, Assurance::Inferred);
        assert_eq!(admin.credential.permissions.requires_mfa, Capability::Yes);
        assert_eq!(admin.links[0].edge, EdgeKind::CanAssumeRole);
        assert!(admin.links[0].approval.as_deref().unwrap().contains("MFA"));
        let sso = by_name("sso");
        assert!(sso.credential.permissions.lifetime.is_expired());
        assert_eq!(sso.credential.permissions.administrative, Capability::No);
        // Nothing secret leaks into any string.
        let dump = format!("{found:?}");
        assert!(!dump.contains(FAKE_SECRET));
        assert!(!dump.contains("FwoGZXIvYXdzEBYaDEXAMPLETOKEN"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn kubeconfig_contexts_production_and_declared_systems() {
        let home = fixture_home();
        write(&home, ".kube/config", "current-context: prod\nclusters:\n- name: prod-eks\n  cluster:\n    server: https://prod.example.com\n- name: dev\n  cluster:\n    server: https://dev.example.com\ncontexts:\n- name: prod\n  context:\n    cluster: prod-eks\n    user: alice\n    namespace: payments\n- name: dev\n  context:\n    cluster: dev\n    user: dev-admin\nusers:\n- name: alice\n  user:\n    token: kube-token-value-not-real-0123456789\n- name: dev-admin\n  user:\n    exec:\n      command: aws\n      args: [eks, get-token]\n");
        let decl = Declarations::parse("[[production_system]]\nname = \"payments-api\"\nhosts = [\"prod-eks\"]\nreaches = [\"signer\"]\n").unwrap();
        let mut c = ctx(&home, &decl);
        let found = kubernetes(&mut c);
        assert_eq!(found.len(), 2);
        let prod = &found[0];
        assert_eq!(
            prod.credential.permissions.can_access_production,
            Capability::Yes
        );
        assert_eq!(
            prod.credential.persistence,
            Persistence::IndependentCredential
        );
        assert!(prod
            .links
            .iter()
            .any(|l| l.kind == NodeKind::ProductionService
                && l.name == "payments-api"
                && l.edge == EdgeKind::CanDeploy));
        let dev = &found[1];
        assert_eq!(dev.credential.persistence, Persistence::RequiresEndpoint);
        assert!(dev.credential.permissions.administrative.is_yes());
        assert!(!format!("{found:?}").contains("kube-token-value-not-real"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn github_docker_and_env_sources() {
        let home = fixture_home();
        write(&home, ".config/gh/hosts.yml", "github.com:\n    user: alice\n    oauth_token: gho_0123456789abcdefghijklmnopqrstuvwxyz\n");
        write(
            &home,
            ".docker/config.json",
            r#"{"auths":{"123456789012.dkr.ecr.us-east-1.amazonaws.com":{"auth":"dXNlcjpwYXNz"}},"credsStore":"osxkeychain"}"#,
        );
        let decl = Declarations::parse("[[signer]]\nname = \"treasury\"\nkind = \"mpc\"\napi_env = [\"TREASURY_API_KEY\"]\nrequires_independent_approval = true\napproval = \"2-of-3\"\n").unwrap();
        let mut c = ctx(&home, &decl);
        c.env.insert(
            "TREASURY_API_KEY".into(),
            "abcdefghijklmnop0123456789".into(),
        );
        c.env
            .insert("ALCHEMY_API_KEY".into(), "alchemy-key-0123456789".into());
        c.env
            .insert("PRIVATE_KEY".into(), "0x".to_string() + &"ab".repeat(32));
        c.env.insert("PATH".into(), "/usr/bin".into());
        c.env.insert("HOME_TOKEN".into(), "short".into());
        let gh = github(&mut c);
        assert_eq!(
            gh[0].credential.permissions.identity.as_deref(),
            Some("alice")
        );
        assert_eq!(gh[0].credential.permissions.lifetime, Lifetime::LongLived);
        let dk = docker(&mut c);
        assert!(dk[0].links[0].production);
        let signers = declared_signers(&mut c);
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].links[0].edge, EdgeKind::CanRequestSignature);
        assert_eq!(
            signers[0]
                .credential
                .permissions
                .requires_independent_approval,
            Capability::Yes
        );
        let env = environment(&mut c);
        let names: Vec<&str> = env.iter().map(|d| d.credential.name.as_str()).collect();
        assert!(names.contains(&"ALCHEMY_API_KEY"));
        assert!(names.contains(&"PRIVATE_KEY"));
        assert!(!names.contains(&"PATH"));
        assert!(!names.contains(&"HOME_TOKEN"));
        let pk = env
            .iter()
            .find(|d| d.credential.name == "PRIVATE_KEY")
            .unwrap();
        assert_eq!(pk.links[0].edge, EdgeKind::CanTransferAssets);
        let dump = format!("{gh:?}{dk:?}{signers:?}{env:?}");
        assert!(!dump.contains("gho_0123456789"));
        assert!(!dump.contains("abababab"));
        assert!(!dump.contains("abcdefghijklmnop0123456789"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn ssh_keys_and_certificates() {
        let home = fixture_home();
        write(
            &home,
            ".ssh/id_plain",
            "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
        );
        write(&home, ".ssh/id_plain.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice@laptop");
        write(
            &home,
            ".ssh/config",
            "Host prod-bastion\n  HostName 10.0.0.1\n  ForwardAgent yes\nHost *\n  User alice\n",
        );
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let found = ssh(&mut c);
        assert_eq!(found.len(), 1);
        let key = &found[0];
        assert!(key.credential.fingerprint.0.starts_with("SHA256:"));
        assert!(key.credential.evidence[0].contains("NO passphrase"));
        assert_eq!(key.links.len(), 1);
        assert!(key.links[0].production);
        assert!(key.links[0]
            .evidence
            .iter()
            .any(|e| e.contains("ForwardAgent")));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn solana_keypair_exposes_only_public_key() {
        let home = fixture_home();
        let mut bytes = vec![7u8; 32];
        bytes.extend(vec![1u8; 32]);
        write(
            &home,
            ".config/solana/id.json",
            &serde_json::to_string(&bytes).unwrap(),
        );
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let found = crypto_wallets(&mut c);
        let sol = found
            .iter()
            .find(|d| d.credential.kind == CredentialKind::SolanaKeypair)
            .unwrap();
        let pubkey = sol.credential.permissions.identity.clone().unwrap();
        assert_eq!(pubkey, base58(&[1u8; 32]));
        assert_eq!(sol.links[0].edge, EdgeKind::CanTransferAssets);
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn base58_known_vector() {
        assert_eq!(base58(&[0, 0, 1]), "112");
        assert_eq!(base58(b"hello"), "Cn8eVZg");
    }

    #[test]
    fn declared_signer_env_var_is_not_double_counted() {
        let home = fixture_home();
        let decl = Declarations::parse(
            "[[signer]]\nname = \"treasury\"\napi_env = [\"TREASURY_API_KEY\"]\n",
        )
        .unwrap();
        let mut c = ctx(&home, &decl);
        c.env.insert(
            "TREASURY_API_KEY".into(),
            "abcdefghijklmnop0123456789".into(),
        );
        let found = discover_all(&mut c);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].credential.kind,
            CredentialKind::SigningServiceApiKey
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn missing_sources_produce_nothing_and_no_panic() {
        let home = fixture_home();
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let found = discover_all(&mut c);
        assert!(found.is_empty());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn unreadable_json_is_noted_not_fatal() {
        let home = fixture_home();
        write(&home, ".docker/config.json", "{not json");
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        assert!(docker(&mut c).is_empty());
        assert!(c.notes.iter().any(|n| n.contains("not valid JSON")));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn project_env_file_skips_examples_and_placeholders() {
        let home = fixture_home();
        write(&home, ".env", "PRIVATE_KEY=0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\nDATABASE_URL=short\nETH_RPC_URL=https://mainnet.example.com/v2\n# STRIPE_SECRET_KEY=sk_live_notreal\n");
        write(
            &home,
            ".env.example",
            "PRIVATE_KEY=0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabce\n",
        );
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let found = project_env_files(&mut c);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential.kind, CredentialKind::EthereumPrivateKey);
        std::fs::remove_dir_all(&home).ok();
    }

    #[cfg(unix)]
    fn agent_run(
        sock: Option<&Path>,
    ) -> (
        Vec<String>,
        SourceCoverage,
        Vec<CoverageFailure>,
        Vec<String>,
    ) {
        let home = fixture_home();
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        if let Some(sock) = sock {
            c.env
                .insert("SSH_AUTH_SOCK".into(), sock.display().to_string());
        }
        let (found, coverage) = discover_sources(&mut c);
        let _ = std::fs::remove_dir_all(&home);
        (
            found
                .iter()
                .map(|(d, id)| format!("{}:{:?}", id, d.credential.kind))
                .collect(),
            coverage,
            c.coverage_failures,
            c.notes,
        )
    }

    #[cfg(unix)]
    #[test]
    fn unreachable_ssh_agent_is_lost_coverage_not_an_empty_agent() {
        // SSH_AUTH_SOCK names a socket that does not exist.
        let missing = std::env::temp_dir().join(format!(
            "gorse-no-agent-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let (found, coverage, failures, _) = agent_run(Some(&missing));
        assert!(found.iter().all(|f| !f.contains("SshAgentIdentity")));
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].location, SSH_AGENT_LOCATION);
        assert_eq!(failures[0].reason, "socket missing");
        assert!(
            !coverage.assessed.iter().any(|s| s == "ssh-agent"),
            "{coverage:?}"
        );
        assert!(coverage.unavailable.iter().any(|(s, _)| s == "ssh-agent"));
        // The key files are a separate source and were read.
        assert!(coverage.assessed.iter().any(|s| s == "ssh"), "{coverage:?}");

        // A socket that accepts and closes at once.
        let dir = std::env::temp_dir().join(format!(
            "gorse-agent-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
            }
        });
        let (found, coverage, failures, _) = agent_run(Some(&path));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(found.iter().all(|f| !f.contains("SshAgentIdentity")));
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].location, SSH_AGENT_LOCATION);
        assert!(
            failures[0].reason == "the agent closed the connection"
                || failures[0].reason.starts_with("unexpected agent reply"),
            "{}",
            failures[0].reason
        );
        assert!(!coverage.assessed.iter().any(|s| s == "ssh-agent"));
    }

    #[test]
    fn no_ssh_auth_sock_leaves_the_agent_unassessed_without_a_failure() {
        // The variable missing does not prove the agent stopped: the
        // source is not assessed, but no location failed, so a run with no
        // agent identities on record stays complete.
        let home = fixture_home();
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        let (found, coverage) = discover_sources(&mut c);
        let _ = std::fs::remove_dir_all(&home);
        assert!(found.iter().all(|(_, id)| *id != "ssh-agent"));
        assert!(c.coverage_failures.is_empty(), "{:?}", c.coverage_failures);
        assert!(coverage.assessed.iter().any(|s| s == "ssh"));
        assert!(!coverage.assessed.iter().any(|s| s == "ssh-agent"));
        assert!(
            coverage
                .unavailable
                .contains(&("ssh-agent".to_string(), SSH_AGENT_NOT_SET.to_string())),
            "{coverage:?}"
        );
        assert_eq!(
            SSH_AGENT_NOT_SET,
            "SSH_AUTH_SOCK is not set in this environment, so the agent could not be asked"
        );
    }

    #[cfg(unix)]
    #[test]
    fn agent_identities_are_their_own_source() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-agent-ok-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 5];
                stream.read_exact(&mut request).unwrap();
                let blob = b"fake-key-blob";
                let comment = b"me@laptop";
                let mut body = vec![12u8, 0, 0, 0, 1];
                body.extend((blob.len() as u32).to_be_bytes());
                body.extend(blob);
                body.extend((comment.len() as u32).to_be_bytes());
                body.extend(comment);
                let mut reply = (body.len() as u32).to_be_bytes().to_vec();
                reply.extend(body);
                stream.write_all(&reply).unwrap();
            }
        });
        let (found, coverage, failures, _) = agent_run(Some(&path));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(found, vec!["ssh-agent:SshAgentIdentity".to_string()]);
        assert!(coverage.assessed.iter().any(|s| s == "ssh-agent"));
    }

    /// Failures and coverage of one discovery run over a fixture home.
    fn run_home(
        home: &Path,
    ) -> (
        Vec<(Discovered, &'static str)>,
        Vec<CoverageFailure>,
        SourceCoverage,
    ) {
        let decl = Declarations::default();
        let mut c = ctx(home, &decl);
        let (found, coverage) = discover_sources(&mut c);
        (found, c.coverage_failures, coverage)
    }

    fn reasons(failures: &[CoverageFailure]) -> Vec<String> {
        failures.iter().map(|f| f.reason.clone()).collect()
    }

    #[test]
    fn a_malformed_aws_profile_is_reported_by_name_and_skipped() {
        let home = fixture_home();
        // `prod` lost its `=`; `default` is fine.
        write(
            &home,
            ".aws/credentials",
            &format!("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {FAKE_SECRET}\n\n[prod]\naws_access_key_id = AKIAI44QH8DHBPRODKEY\naws_secret_access_key {FAKE_SECRET}\n"),
        );
        // A config profile with a key id and no secret, plus nested values
        // (indented continuation lines are fine).
        write(
            &home,
            ".aws/config",
            "[default]\nregion = eu-west-1\ns3 =\n    max_concurrent_requests = 20\n[profile half]\naws_access_key_id = AKIAHALFHALFEXAMPLE\n",
        );
        let (found, failures, coverage) = run_home(&home);
        let names: Vec<&str> = found
            .iter()
            .filter(|(_, s)| *s == "aws-credentials-file")
            .map(|(d, _)| d.credential.name.as_str())
            .collect();
        assert_eq!(names, vec!["default"]);
        let reasons = reasons(&failures);
        assert!(
            reasons.contains(&"could not interpret profile prod in ~/.aws/credentials".to_string()),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&"could not interpret profile half in ~/.aws/config".to_string()),
            "{reasons:?}"
        );
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(!coverage
            .assessed
            .iter()
            .any(|s| s == "aws-credentials-file"));
        assert!(coverage
            .unavailable
            .iter()
            .any(|(s, r)| s == "aws-credentials-file" && r.contains("profile prod")));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn other_hand_written_parsers_check_every_entry() {
        let home = fixture_home();
        // netrc: the second machine holds a token netrc does not define.
        write(
            &home,
            ".netrc",
            "machine api.heroku.com login a@b.c password x\nmachine git.example.com loginn bob password y\n",
        );
        // docker: one entry whose auth is not base64 user:secret.
        write(
            &home,
            ".docker/config.json",
            "{\"auths\": {\"ghcr.io\": {\"auth\": \"dXNlcjpzZWNyZXQ=\"}, \"quay.io\": {\"auth\": 42}}}",
        );
        // kubeconfig: one user in a shape Gorse does not read.
        write(
            &home,
            ".kube/config",
            "apiVersion: v1\nclusters:\n- name: c\n  cluster:\n    server: https://k\ncontexts:\n- name: ok\n  context:\n    cluster: c\n    user: good\nusers:\n- name: good\n  user:\n    token: abc\n- name: odd\n  user:\n    mystery: field\n",
        );
        // terraform and pulumi: one token each that is not a string.
        write(
            &home,
            ".terraform.d/credentials.tfrc.json",
            "{\"credentials\": {\"app.terraform.io\": {\"token\": \"t\"}, \"tfe.example.com\": {\"tok\": 1}}}",
        );
        write(
            &home,
            ".pulumi/credentials.json",
            "{\"accessTokens\": {\"https://api.pulumi.com\": \"pul-x\", \"https://p.example.com\": {}}}",
        );
        // doctl: one context that is a mapping, not a token.
        write(
            &home,
            ".config/doctl/config.yaml",
            "access-token: dop_v1_1111111111111111111111111111111111111111111111111111111111111111\nauth-contexts:\n  odd:\n    nested: value\n",
        );
        let (found, failures, coverage) = run_home(&home);
        let reasons = reasons(&failures);
        for expected in [
            "could not interpret machine git.example.com in ~/.netrc",
            "could not interpret registry quay.io in ~/.docker/config.json",
            "could not interpret user odd in ~/.kube/config",
            "could not interpret credentials for tfe.example.com in ~/.terraform.d/credentials.tfrc.json",
            "could not interpret access token for https://p.example.com in ~/.pulumi/credentials.json",
            "could not interpret context odd in ~/.config/doctl/config.yaml",
        ] {
            assert!(reasons.iter().any(|r| r == expected), "{expected}: {reasons:?}");
        }
        for source in [
            "ci-tokens",
            "docker-config",
            "kubeconfig",
            "terraform-credentials",
            "doctl-config",
        ] {
            assert!(!coverage.assessed.iter().any(|s| s == source), "{source}");
        }
        // The well-formed entries are still found.
        let names: Vec<&str> = found
            .iter()
            .map(|(d, _)| d.credential.name.as_str())
            .collect();
        for name in [
            "netrc api.heroku.com",
            "ghcr.io",
            "ok",
            "app.terraform.io",
            "default",
        ] {
            assert!(names.contains(&name), "{name}: {names:?}");
        }
        assert!(!names.contains(&"netrc git.example.com"));
        assert!(!names.contains(&"quay.io"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn unrecognised_wallet_and_certificate_content_is_lost_coverage() {
        let home = fixture_home();
        // Valid JSON, but not 64 integers.
        write(&home, ".config/solana/id.json", "[1, 2, 3]");
        // A JSON file in a keystore folder that is not a keystore.
        write(
            &home,
            ".ethereum/keystore/notes.json",
            "{\"hello\": \"world\"}",
        );
        // A keystore without an address is still a keystore.
        write(
            &home,
            ".foundry/keystores/deployer",
            "{\"crypto\": {\"cipher\": \"aes-128-ctr\"}, \"id\": \"3198bc9c-6672-5ab3-d995-4942343ae5b6\", \"version\": 3}",
        );
        // An SSH certificate the parser rejects.
        write(
            &home,
            ".ssh/id_ed25519-cert.pub",
            "ssh-ed25519-cert-v01@openssh.com AAAAnotbase64!!! me\n",
        );
        let (found, failures, coverage) = run_home(&home);
        // Windows joins home-relative paths with backslashes; compare in one form.
        let failed: Vec<(String, String)> = failures
            .iter()
            .map(|f| (f.location.replace('\\', "/"), f.reason.replace('\\', "/")))
            .collect();
        for location in [
            "~/.config/solana/id.json",
            "~/.ethereum/keystore/notes.json",
            "~/.ssh/id_ed25519-cert.pub",
        ] {
            assert!(
                failed.iter().any(|(l, r)| *l == location
                    && *r == format!("could not interpret {location} (unsupported format)")),
                "{location}: {failed:?}"
            );
        }
        assert_eq!(failed.len(), 3, "{failed:?}");
        for source in ["crypto-wallets", "ssh"] {
            assert!(!coverage.assessed.iter().any(|s| s == source), "{source}");
        }
        let keystore = found
            .iter()
            .find(|(d, _)| d.credential.name == "deployer")
            .expect("keystore without address");
        assert_eq!(keystore.0.credential.kind, CredentialKind::EthereumKeystore);
        assert!(keystore.0.credential.permissions.identity.is_none());

        // A Solana keypair with a value out of byte range is not a keypair.
        let bad: Vec<String> = (0..64)
            .map(|i| if i == 0 { "256".into() } else { "1".into() })
            .collect();
        write(
            &home,
            ".config/solana/id.json",
            &format!("[{}]", bad.join(",")),
        );
        std::fs::remove_file(home.join(".ethereum/keystore/notes.json")).unwrap();
        std::fs::remove_file(home.join(".ssh/id_ed25519-cert.pub")).unwrap();
        let (_, failures, _) = run_home(&home);
        assert_eq!(
            reasons(&failures),
            vec!["could not interpret ~/.config/solana/id.json (unsupported format)".to_string()]
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_credential_location_behind_a_permission_error_is_lost_coverage() {
        use std::os::unix::fs::PermissionsExt;
        let home = fixture_home();
        // ~/.config is unreadable: ~/.config/op cannot be checked.
        std::fs::create_dir_all(home.join(".config/op")).unwrap();
        std::fs::create_dir_all(home.join(".electrum/wallets")).unwrap();
        std::fs::set_permissions(home.join(".config"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        std::fs::set_permissions(
            home.join(".electrum/wallets"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let probe = std::fs::metadata(home.join(".config/op"));
        let (found, failures, coverage) = run_home(&home);
        std::fs::set_permissions(home.join(".config"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::set_permissions(
            home.join(".electrum/wallets"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::remove_dir_all(&home).ok();
        if probe.is_ok() {
            return; // running as root: permissions are not enforced
        }
        let locations: Vec<&str> = failures.iter().map(|f| f.location.as_str()).collect();
        assert!(locations.contains(&"~/.config/op"), "{locations:?}");
        assert!(locations.contains(&"~/.electrum/wallets"), "{locations:?}");
        for source in ["secrets-manager-clis", "crypto-wallets"] {
            assert!(!coverage.assessed.iter().any(|s| s == source), "{source}");
        }
        assert!(found
            .iter()
            .all(|(d, _)| d.credential.name != "1Password CLI"));
    }

    /// Lint: `Path::exists()` reports a permission error as "absent", so a
    /// credential location checked with it silently drops out of coverage.
    /// Discovery uses `Context::present`, which records such errors. Any
    /// remaining `.exists()` must be listed here with the reason it is safe.
    #[test]
    fn discovery_never_uses_exists_on_credential_locations() {
        // (line fragment, why it is safe). Empty: there are none.
        const ALLOWED: &[(&str, &str)] = &[];
        // Git may check the file out with CRLF line endings on Windows.
        let source = include_str!("discover.rs").replace('\r', "");
        let code = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let offending: Vec<(usize, &str)> = code
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let l = l.trim_start();
                !l.starts_with("//") && (l.contains(".exists()") || l.contains("try_exists("))
            })
            .filter(|(_, l)| !ALLOWED.iter().any(|(frag, _)| l.contains(frag)))
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();
        assert!(
            offending.is_empty(),
            "use ctx.present() instead of .exists() on credential locations: {offending:?}"
        );
    }

    #[test]
    fn vault_file_and_environment_tokens_are_separate_findings() {
        let home = fixture_home();
        write(&home, ".vault-token", "hvs.filetoken\n");
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        c.env.insert("VAULT_TOKEN".into(), "hvs.envtoken".into());
        let found: Vec<Discovered> = discover_all(&mut c)
            .into_iter()
            .filter(|d| d.credential.kind == CredentialKind::VaultToken)
            .collect();
        let locations: Vec<&str> = found
            .iter()
            .map(|d| d.credential.location.as_str())
            .collect();
        assert_eq!(locations, ["~/.vault-token", "env VAULT_TOKEN"]);
        assert_ne!(
            found[0].credential.fingerprint,
            found[1].credential.fingerprint
        );
        assert_eq!(
            found[0].source.as_deref(),
            Some(home.join(".vault-token").as_path())
        );
        assert_eq!(found[1].source, None);

        // An empty token file is lost coverage, not a token.
        write(&home, ".vault-token", "\n");
        let (found, failures, _) = run_home(&home);
        assert!(!found
            .iter()
            .any(|(d, _)| d.credential.kind == CredentialKind::VaultToken));
        assert!(
            failures.iter().any(|f| f.location == "~/.vault-token"),
            "{:?}",
            reasons(&failures)
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn a_parenthesised_file_name_is_kept_whole_as_the_source() {
        let home = fixture_home();
        let file = home.join("config (production).yaml");
        std::fs::write(
            &file,
            "current-context: prod\nclusters:\n  - name: prod\n    cluster:\n      server: https://cluster.invalid\nusers:\n  - name: op\n    user:\n      token: synthetic\ncontexts:\n  - name: prod\n    context:\n      cluster: prod\n      user: op\n",
        )
        .unwrap();
        let decl = Declarations::default();
        let mut c = ctx(&home, &decl);
        c.env
            .insert("KUBECONFIG".into(), file.display().to_string());
        let found: Vec<Discovered> = discover_all(&mut c)
            .into_iter()
            .filter(|d| d.credential.kind == CredentialKind::KubernetesContext)
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].source.as_deref(), Some(file.as_path()));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn malformed_cloud_and_gh_entries_are_lost_coverage() {
        let home = fixture_home();
        // gcloud: a section with a line the parser cannot read.
        write(
            &home,
            ".config/gcloud/configurations/config_default",
            "[core]\naccount = alice@example.com\nproject prod\n",
        );
        // gh: one host is a mapping, the other is not.
        write(
            &home,
            ".config/gh/hosts.yml",
            "github.com:\n    user: alice\n    oauth_token: gho_synthetic\nghe.example.com: broken\n",
        );
        // Azure: one subscription is not an object; service principals
        // hold a non-object entry.
        write(
            &home,
            ".azure/azureProfile.json",
            r#"{"subscriptions":[{"id":"00000000-0000-0000-0000-000000000001","name":"Dev","user":{"name":"a@example.com","type":"user"}},"oops"]}"#,
        );
        write(
            &home,
            ".azure/service_principal_entries.json",
            r#"[{"client_id":"c1","tenant":"t"},42]"#,
        );
        let (found, failures, _) = run_home(&home);
        let reasons = reasons(&failures);
        for expected in [
            "could not interpret section core in ~/.config/gcloud/configurations/config_default",
            "could not interpret host ghe.example.com in ~/.config/gh/hosts.yml",
            "could not interpret subscription entry 2 in ~/.azure/azureProfile.json",
            "could not interpret entry 2 in ~/.azure/service_principal_entries.json",
        ] {
            assert!(
                reasons.iter().any(|r| r == expected),
                "{expected}: {reasons:?}"
            );
        }
        let names: Vec<&str> = found
            .iter()
            .map(|(d, _)| d.credential.name.as_str())
            .collect();
        assert!(names.contains(&"gh login github.com"), "{names:?}");
        assert!(
            names.contains(&"Dev (00000000-0000-0000-0000-000000000001)"),
            "{names:?}"
        );

        // Subscriptions missing, or not a list; service principals not a
        // list.
        for profile in [r#"{"installationId":"x"}"#, r#"{"subscriptions":{}}"#] {
            write(&home, ".azure/azureProfile.json", profile);
            write(&home, ".azure/service_principal_entries.json", r#"{"a":1}"#);
            let (_, failures, _) = run_home(&home);
            let reasons = super::tests::reasons(&failures);
            for expected in [
                "could not interpret ~/.azure/azureProfile.json (unsupported format)",
                "could not interpret ~/.azure/service_principal_entries.json (unsupported format)",
            ] {
                assert!(
                    reasons.iter().any(|r| r == expected),
                    "{expected}: {reasons:?}"
                );
            }
        }
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn ai_agent_sign_ins_are_assessed_on_every_platform() {
        // The tester's Linux repro: synthetic sign-ins of four agents.
        let home = fixture_home();
        write(
            &home,
            ".claude/.credentials.json",
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-FAKE","refreshToken":"sk-ant-ort01-FAKE","expiresAt":1900000000000,"scopes":["user:inference"]}}"#,
        );
        write(
            &home,
            ".gemini/oauth_creds.json",
            r#"{"access_token":"ya29.FAKE-synthetic","refresh_token":"1//FAKE-synthetic","token_type":"Bearer","expiry_date":1900000000000}"#,
        );
        write(
            &home,
            ".codex/auth.json",
            r#"{"tokens":{"access_token":"eyJFAKE.eyJFAKE.FAKE","refresh_token":"FAKE-synthetic"}}"#,
        );
        write(
            &home,
            ".cursor/auth.json",
            r#"{"accessToken":"eyJFAKE.eyJFAKE.FAKE"}"#,
        );
        // An MCP config with one literal key and one reference.
        write(
            &home,
            ".cursor/mcp.json",
            r#"{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"ghp_FAKEsynthetic","OTHER":"${OTHER_TOKEN}"}}}}"#,
        );
        let (found, failures, coverage) = run_home(&home);
        assert!(failures.is_empty(), "{:?}", reasons(&failures));
        assert!(
            coverage
                .assessed
                .iter()
                .any(|s| s == "ai-agent-credentials"),
            "{:?}",
            coverage.assessed
        );
        let agents: Vec<&Discovered> = found
            .iter()
            .filter(|(_, id)| *id == "ai-agent-credentials")
            .map(|(d, _)| d)
            .collect();
        let locations: Vec<String> = agents
            .iter()
            .map(|d| d.credential.location.replace('\\', "/"))
            .collect();
        for rel in [
            "~/.claude/.credentials.json",
            "~/.gemini/oauth_creds.json",
            "~/.codex/auth.json",
            "~/.cursor/auth.json",
            "~/.cursor/mcp.json",
        ] {
            assert!(locations.iter().any(|l| l == rel), "{rel}: {locations:?}");
        }
        assert_eq!(agents.len(), 5, "{locations:?}");
        let claude = agents
            .iter()
            .find(|d| d.credential.location.contains(".claude"))
            .unwrap();
        assert_eq!(claude.credential.kind, CredentialKind::OAuthSession);
        assert_eq!(claude.credential.permissions.lifetime, Lifetime::LongLived);
        // Cursor has no refresh token and no expiry.
        let cursor = agents
            .iter()
            .find(|d| {
                d.credential.location.ends_with("auth.json")
                    && d.credential.name.starts_with("Cursor")
            })
            .unwrap();
        assert_eq!(cursor.credential.permissions.lifetime, Lifetime::Unknown);
        // The MCP finding names the key, never the value or the reference.
        let mcp = agents
            .iter()
            .find(|d| d.credential.location.ends_with("mcp.json"))
            .unwrap();
        assert!(
            mcp.credential
                .evidence
                .iter()
                .any(|e| e.contains("GITHUB_TOKEN")),
            "{:?}",
            mcp.credential.evidence
        );
        // No secret value reaches the findings.
        let dump = format!("{agents:?}");
        for secret in [
            "sk-ant-",
            "ya29.",
            "1//FAKE",
            "eyJFAKE",
            "ghp_FAKE",
            "FAKE-synthetic",
        ] {
            assert!(!dump.contains(secret), "{secret} leaked");
        }
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn unreadable_ai_agent_sign_ins_are_lost_coverage_and_configs_are_not() {
        let home = fixture_home();
        write(&home, ".claude/.credentials.json", "not json");
        write(&home, ".codex/auth.json", r#"{"mode":"chatgpt"}"#);
        // Signed out, and a JSONC config with no secrets.
        write(&home, ".cursor/auth.json", "{}");
        write(
            &home,
            ".config/Code/User/mcp.json",
            "// my servers\n{\"servers\": {}}\n",
        );
        let (found, failures, coverage) = run_home(&home);
        let reasons = reasons(&failures);
        for rel in [".claude/.credentials.json", ".codex/auth.json"] {
            let expected = format!("could not interpret ~/{rel} (unsupported format)");
            assert!(
                reasons.iter().any(|r| r.replace('\\', "/") == expected),
                "{expected}: {reasons:?}"
            );
        }
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(coverage
            .unavailable
            .iter()
            .any(|(s, _)| s == "ai-agent-credentials"));
        assert!(found.iter().all(|(_, id)| *id != "ai-agent-credentials"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn linux_deployment_platform_tokens_are_found() {
        let home = fixture_home();
        write(
            &home,
            ".local/share/com.vercel.cli/auth.json",
            r#"{"token":"vercel_synthetic_xdg"}"#,
        );
        write(
            &home,
            ".config/vercel/auth.json",
            r#"{"token":"vercel_synthetic_config"}"#,
        );
        write(
            &home,
            ".config/.wrangler/config/default.toml",
            "oauth_token = \"wrangler_synthetic\"\nexpiration_time = \"2030-01-01T00:00:00Z\"\n",
        );
        write(
            &home,
            ".config/supabase/access-token",
            "sbp_synthetic0000\n",
        );
        let (found, failures, coverage) = run_home(&home);
        assert!(failures.is_empty(), "{:?}", reasons(&failures));
        assert!(coverage.assessed.iter().any(|s| s == "ci-tokens"));
        let locations: Vec<String> = found
            .iter()
            .filter(|(_, id)| *id == "ci-tokens")
            .map(|(d, _)| d.credential.location.replace('\\', "/"))
            .collect();
        for rel in [
            "~/.local/share/com.vercel.cli/auth.json",
            "~/.config/vercel/auth.json",
            "~/.config/.wrangler/config/default.toml",
            "~/.config/supabase/access-token",
        ] {
            assert!(locations.iter().any(|l| l == rel), "{rel}: {locations:?}");
        }
        let dump = format!("{found:?}");
        assert!(!dump.contains("synthetic"), "a token value leaked");
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn ci_token_files_without_their_structure_are_lost_coverage() {
        let cases = [
            (".vercel/auth.json", "token: not json"),
            (".config/netlify/config.json", "[1, 2]"),
            (".railway/config.json", "{\"token\": "),
            (".config/glab-cli/config.yml", "just a sentence"),
            (".circleci/cli.yml", "- token\n- list\n"),
            (".fly/config.yml", "access_token"),
            (".npmrc", "//registry.npmjs.org/:_authToken npm_synthetic\n"),
            (".pypirc", "password pypi-synthetic\n"),
        ];
        for (rel, text) in cases {
            let home = fixture_home();
            write(&home, rel, text);
            let (found, failures, coverage) = run_home(&home);
            let expected = format!("could not interpret ~/{rel} (unsupported format)");
            assert!(
                reasons(&failures).iter().any(|r| *r == expected),
                "{rel}: {:?}",
                reasons(&failures)
            );
            assert!(!coverage.assessed.iter().any(|s| s == "ci-tokens"), "{rel}");
            assert!(found
                .iter()
                .all(|(d, _)| !d.credential.location.contains(rel)));
            std::fs::remove_dir_all(&home).ok();
        }
        // Well-formed files with and without a token are not failures.
        let home = fixture_home();
        write(&home, ".npmrc", "registry=https://registry.npmjs.org/\n");
        write(
            &home,
            ".vercel/auth.json",
            r#"{"token":"vercel_synthetic"}"#,
        );
        write(&home, ".pypirc", "[distutils]\nindex-servers = pypi\n");
        let (found, failures, _) = run_home(&home);
        assert!(failures.is_empty(), "{:?}", reasons(&failures));
        assert!(found.iter().any(|(d, _)| d.credential.name == "Vercel CLI"));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn an_unreadable_private_key_in_ssh_is_lost_coverage() {
        let home = fixture_home();
        write(&home, ".ssh/id_work", "this is not a key\n");
        write(
            &home,
            ".ssh/deploy",
            // A key header the parser does not accept where it is.
            "pasted from chat:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        // ssh's own files and public keys never count.
        write(&home, ".ssh/known_hosts", "github.com ssh-ed25519 AAAA\n");
        write(&home, ".ssh/config", "Host *\n  User me\n");
        write(&home, ".ssh/authorized_keys", "ssh-ed25519 AAAA me\n");
        write(&home, ".ssh/id_work.pub", "ssh-ed25519 AAAA me\n");
        write(&home, ".ssh/.DS_Store", "\0\0\0\x01Bud1");
        write(&home, ".ssh/notes.txt", "remember to rotate\n");
        let (_, failures, _) = run_home(&home);
        // Windows reports home-relative paths with backslashes.
        let reasons: Vec<String> = reasons(&failures)
            .into_iter()
            .map(|r| r.replace('\\', "/"))
            .collect();
        let ssh: Vec<&String> = reasons.iter().filter(|r| r.contains("~/.ssh/")).collect();
        assert_eq!(
            ssh,
            [
                "could not interpret ~/.ssh/deploy (unsupported format)",
                "could not interpret ~/.ssh/id_work (unsupported format)",
            ],
            "{reasons:?}"
        );
        std::fs::remove_dir_all(&home).ok();
    }
}

#[cfg(test)]
mod aider_format_tests {
    use super::agent_line_secrets;

    #[test]
    fn aider_api_key_list_and_inline_provider_forms_are_read() {
        // Synthetic values.
        let list = "model: sonnet\napi-key:\n  - anthropic=sk-ant-api03-Zq3Xr7Lm2Np8Vt4Wy6Bc1\n  - openai=sk-proj-Q7xR2mK9pL4vN8cT3wZ6\nauto-commits: false\n";
        let found = agent_line_secrets(list);
        assert_eq!(
            found.len(),
            2,
            "{:?}",
            found.iter().map(|(k, _)| k).collect::<Vec<_>>()
        );
        assert!(found
            .iter()
            .all(|(k, v)| k == "api-key" && v.starts_with("sk-")));
        let inline = "api-key: anthropic=sk-ant-api03-Zq3Xr7Lm2Np8Vt4Wy6Bc1\n";
        let found = agent_line_secrets(inline);
        assert_eq!(found.len(), 1);
        assert!(found[0].1.starts_with("sk-ant-"), "provider name stripped");
    }
}

#[cfg(test)]
mod leak_guard_tests {
    use super::{plain_key_name, safe_identity};

    #[test]
    fn token_shaped_identities_are_cut_to_four_characters() {
        // Synthetic tokens.
        assert_eq!(
            safe_identity("ghp_Q7xR2mK9pL4vN8cT3wZ6yB1hD5fJ0gS2uE7a"),
            "ghp_****"
        );
        assert_eq!(safe_identity("glpatQ7xR2mK9pL4vN8cT3wZ6"), "glpa****");
        assert_eq!(safe_identity("james"), "james");
        assert_eq!(safe_identity("ops@acme.dev"), "ops@acme.dev");
    }

    #[test]
    fn only_word_built_key_names_are_shown() {
        for ok in [
            "OPENAI_API_KEY",
            "accessToken",
            "client_secret",
            "apiKey",
            "Authorization",
            "GITHUB_PERSONAL_ACCESS_TOKEN",
        ] {
            assert!(plain_key_name(ok), "{ok}");
        }
        for hidden in [
            "CedarFox42_token",
            "N7vQ9mK2pL4xR8wT1zToken",
            "q7xr2mk9pl4vn8ct_secret",
        ] {
            assert!(!plain_key_name(hidden), "{hidden}");
        }
    }
}

#[cfg(test)]
mod agent_syntax_tests {
    use super::agent_line_secrets;

    #[test]
    fn comments_bearer_headers_inline_tables_and_base64_padding() {
        // Synthetic values.
        let f = agent_line_secrets("apiKey: Q7xR2mK9pL4vN8cT3wZ6 # production\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1, "Q7xR2mK9pL4vN8cT3wZ6");
        let f = agent_line_secrets("Authorization = \"Bearer Q7xR2mK9pL4vN8cT3wZ6\"\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1, "Q7xR2mK9pL4vN8cT3wZ6");
        let f = agent_line_secrets(
            "env = { OPENAI_API_KEY = \"sk-proj-Q7xR2mK9pL4vN8cT3wZ6\", MODE = \"fast\" }\n",
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, "OPENAI_API_KEY");
        let f = agent_line_secrets("apiKey: \"Q2VkYXJGb3g0Mk5lY3Rhcg==\"\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1, "Q2VkYXJGb3g0Mk5lY3Rhcg==");
    }
}
