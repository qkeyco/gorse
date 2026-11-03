// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Opt-in, read-only remote verification (`gorse exposure --verify`).
//!
//! Local discovery can only infer. These checks ask the provider what a
//! credential actually is and can do, using the user's own installed CLIs
//! and only query-style subcommands:
//!
//! | provider   | command                                                    | mutates? |
//! |------------|------------------------------------------------------------|----------|
//! | AWS        | sts get-caller-identity, iam list-attached-*-policies      | no       |
//! | GitHub     | gh auth status (never --show-token), gh api repos/{o}/{r}  | no       |
//! | Kubernetes | kubectl config view --minify, get namespaces, auth can-i (--list, -A) | no |
//! | Vault      | vault token lookup                                         | no       |
//! | Google     | gcloud auth list (local configuration only, Google not asked) | no    |
//! | Azure      | az account show, az role assignment list (identity; roles inferred) | no |
//! | DigitalOcean | doctl account get and read-only listings, pinned to the credential under test (see [`doctl_binding`]) | no |
//! | Ethereum   | JSON-RPC eth_getCode                                       | no       |
//!
//! Each adapter says what its answer establishes ([`VerificationStatus`]):
//! sts, gh auth status, vault token lookup, doctl account get and az role
//! assignment list confirm an identity; kubectl auth can-i, a GitHub
//! repository's permissions object and eth_getCode confirm a permission;
//! gcloud auth list and az account show read local configuration only.
//! Running a tool successfully is never by itself a confirmation.
//!
//! Identity is not permission. A capability flag reads "confirmed" only
//! when a provider check established that specific permission (see
//! [`EffectivePermissions::confirm`]): an AWS policy name, a GitHub token
//! scope, an Azure role name, a DigitalOcean project called Production or a
//! Vault policy name only ever give an inferred capability, and the
//! evidence says so. A successful AWS role assumption confirms that one
//! hop (can assume this role) and nothing the role can then do, so the
//! finding stays identity-confirmed.
//!
//! Every check is bound to the credential under test, so a token in the
//! environment, an active profile or another saved login can never answer
//! for it (see [`CliBinding`] and [`doctl_binding`]).
//!
//! [`EffectivePermissions::confirm`]: hedgehog_taint::authority::EffectivePermissions::confirm
//!
//! Nothing here signs, assumes, creates, deletes or changes anything. Every
//! call has a timeout and a failure simply leaves the permission "inferred".
//!
//! Two rules keep the result honest. A provider answer only ever confirms
//! what it actually says: the absence of a GitHub classic scope or of a rule
//! in one Kubernetes namespace is not proof that the access is missing
//! elsewhere, so it never produces a confirmed "no"; a "no" needs every
//! place that could grant the access to have been asked (see
//! [`apply_kube_checks`] and [`apply_repo_access`]). And no graph edge may
//! claim more assurance than the credential it hangs off; see
//! [`cap_links_to_credential`].

use super::discover::{Discovered, Link};
use hedgehog_taint::authority::graph::{EdgeKind, NodeKind};
use hedgehog_taint::authority::{
    redact_text, Assurance, Capability, CredentialKind, Lifetime, Permission,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Outcome {
    pub notes: Vec<String>,
    /// One per credential, in the order given to [`verify_all`].
    pub verifications: Vec<Verification>,
}

/// What happened when Gorse asked the provider about one credential. Kept
/// apart from the finding's confidence: a provider that could not be asked
/// leaves the permissions inferred, and this says why.
///
/// A tool that ran successfully never by itself means confirmation: the
/// level says what its answer actually establishes. Only
/// [`IdentityConfirmed`](Self::IdentityConfirmed) and
/// [`PermissionConfirmed`](Self::PermissionConfirmed) raise a finding's
/// confidence, and only `PermissionConfirmed` may leave a graph edge
/// confirmed (see [`verify_all`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// The provider authenticated the credential and returned an identity.
    IdentityConfirmed,
    /// The provider confirmed a specific permission, or listed resources the
    /// credential can reach.
    PermissionConfirmed,
    /// The tool ran but only read local state; the provider was not asked.
    LocalConfig,
    /// The provider check errored or timed out.
    Failed,
    /// Gorse has no provider check for this credential.
    Unsupported,
    /// The run was made without `--verify`.
    NotAttempted,
}

impl VerificationStatus {
    pub fn key(self) -> &'static str {
        match self {
            VerificationStatus::IdentityConfirmed => "identity_confirmed",
            VerificationStatus::PermissionConfirmed => "permission_confirmed",
            VerificationStatus::LocalConfig => "local_config",
            VerificationStatus::Failed => "failed",
            VerificationStatus::Unsupported => "unsupported",
            VerificationStatus::NotAttempted => "not_attempted",
        }
    }

    /// The status in plain words, as the text and HTML reports show it.
    pub fn label(self) -> &'static str {
        match self {
            VerificationStatus::IdentityConfirmed => "identity confirmed by provider",
            VerificationStatus::PermissionConfirmed => "permission confirmed by provider",
            VerificationStatus::LocalConfig => "local configuration only, provider not asked",
            VerificationStatus::Failed => "check failed",
            VerificationStatus::Unsupported => "not supported yet",
            VerificationStatus::NotAttempted => "not checked with the provider",
        }
    }

    /// The provider authenticated the credential: the only outcomes that may
    /// raise a finding's confidence to confirmed.
    pub fn provider_answered(self) -> bool {
        matches!(
            self,
            VerificationStatus::IdentityConfirmed | VerificationStatus::PermissionConfirmed
        )
    }
}

/// What a provider check that ran to completion established, and the
/// detail shown for it. Each adapter classifies its own commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub status: VerificationStatus,
    pub detail: String,
}

impl Checked {
    fn new(status: VerificationStatus, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }
}

/// The verification outcome for one finding. `detail` names the check and,
/// for a failure, the class of error (never provider output that could
/// carry secret material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub status: VerificationStatus,
    pub detail: String,
}

impl Verification {
    pub fn not_attempted() -> Self {
        Self {
            status: VerificationStatus::NotAttempted,
            detail: "not checked with the provider: run with --verify".into(),
        }
    }

    pub fn unsupported(why: &str) -> Self {
        Self {
            status: VerificationStatus::Unsupported,
            detail: why.to_string(),
        }
    }
}

/// The provider check that runs first for a credential kind, as shown in a
/// verification detail. `None` when Gorse has no adapter for the kind.
fn adapter_command(kind: CredentialKind) -> Option<&'static str> {
    Some(match kind {
        CredentialKind::AwsAccessKey
        | CredentialKind::AwsSession
        | CredentialKind::AwsSsoSession
        | CredentialKind::AwsProfileRole => "aws sts get-caller-identity",
        CredentialKind::GitHubToken => "gh auth status",
        CredentialKind::KubernetesContext => "kubectl auth can-i",
        CredentialKind::VaultToken => "vault token lookup",
        CredentialKind::DigitalOceanToken => "doctl account get",
        CredentialKind::GcpUserCredential => "gcloud auth list",
        CredentialKind::AzureSession | CredentialKind::AzureServicePrincipal => "az account show",
        _ => return None,
    })
}

/// The error class of a failed provider check: the command and what went
/// wrong (timed out, not installed, exited with an error, unexpected
/// output), without the tool's own message.
fn failure_detail(error: &str) -> String {
    const EXITED: &str = " exited with an error";
    if let Some(i) = error.find(EXITED) {
        return error[..i + EXITED.len()].to_string();
    }
    if let Some(i) = error.find(" not available") {
        return format!("{} not available", &error[..i]);
    }
    redact_text(error)
}

const TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(test)]
thread_local! {
    static TIMEOUT_OVERRIDE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

fn timeout() -> Duration {
    #[cfg(test)]
    if let Some(t) = TIMEOUT_OVERRIDE.with(|t| t.get()) {
        return t;
    }
    TIMEOUT
}

/// How a command is named in errors: the program and its leading
/// subcommands (`aws sts get-caller-identity`, `kubectl auth can-i`).
fn command_label(program: &str, args: &[&str]) -> String {
    let mut label = program.to_string();
    for a in args.iter().take_while(|a| !a.starts_with('-')).take(2) {
        label.push(' ');
        label.push_str(a);
    }
    label
}

/// What a read-only CLI call produced. Stderr is reduced to its first
/// non-blank line, redacted, so secrets printed by a tool never surface.
struct CliOutput {
    success: bool,
    stdout: String,
    /// All of stderr, for tools (gh) that print their answer there. Never
    /// stored as is: callers parse it or redact it.
    stderr: String,
    stderr_first: String,
}

/// Run a read-only CLI command with a timeout, keeping the exit status.
/// Some query commands (`kubectl auth can-i`) answer "no" with exit code 1,
/// so a non-zero exit is not always a failure.
#[cfg(test)]
fn run_cli_raw(
    program: &str,
    args: &[&str],
    env: &BTreeMap<String, String>,
) -> Result<CliOutput, String> {
    run_cli_raw_bound(program, args, env, &[])
}

/// Read a pipe to the end on its own thread, so a tool that writes more
/// than the pipe buffer holds never blocks waiting for Gorse to read.
fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// [`run_cli_raw`] with named variables removed from the child's
/// environment (the inherited one as well as `env`), for a tool whose
/// credential selection must not depend on what this process inherited.
fn run_cli_raw_bound(
    program: &str,
    args: &[&str],
    env: &BTreeMap<String, String>,
    remove: &[&str],
) -> Result<CliOutput, String> {
    let label = command_label(program, args);
    let mut command = Command::new(program);
    command
        .args(args)
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .envs(env.iter());
    for name in remove {
        command.env_remove(name);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{label} could not run: {program} not available ({e})"))?;
    let stdout_rx = drain(child.stdout.take());
    let stderr_rx = drain(child.stderr.take());
    let limit = timeout();
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > limit {
                    let _ = child.kill();
                    // Reap it so no zombie is left. The readers are left to
                    // finish on their own: a grandchild may still hold the
                    // pipes open.
                    let _ = child.wait();
                    return Err(format!("{label} timed out after {}s", limit.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{label} could not be waited on ({e})"));
            }
        }
    };
    // The process has exited; its pipes close unless something it started
    // still holds them, so the wait for the readers is bounded too.
    let remaining = limit
        .saturating_sub(start.elapsed())
        .max(Duration::from_secs(1));
    let stdout = stdout_rx
        .recv_timeout(remaining)
        .map_err(|_| format!("{label} timed out after {}s", limit.as_secs()))?;
    let stderr = stderr_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap_or_default();
    let err = String::from_utf8_lossy(&stderr).to_string();
    let first = err
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("non-zero exit");
    Ok(CliOutput {
        success: status.success(),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr_first: redact_text(first.trim()),
        stderr: err,
    })
}

/// Run a read-only CLI command with a timeout. Stdout only; a non-zero exit
/// is an error naming the command, with the first (redacted) stderr line.
#[cfg(test)]
fn run_cli(program: &str, args: &[&str], env: &BTreeMap<String, String>) -> Result<String, String> {
    let out = run_cli_raw(program, args, env)?;
    if !out.success {
        return Err(format!(
            "{} exited with an error: {}",
            command_label(program, args),
            out.stderr_first
        ));
    }
    Ok(out.stdout)
}

// ─── Binding a check to the credential under test ───────────────────────────

/// Where the value of a variable set in a provider tool's environment comes
/// from. A secret is never written into a binding: it is copied from the
/// verification environment or read from the credential's own file at the
/// moment of the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvSource {
    /// A literal, non-secret value (a directory or file path, a name).
    Value(String),
    /// The value of this variable in the verification environment.
    Var(String),
    /// The contents of this file, trimmed (a saved token).
    File(PathBuf),
}

/// How every call of one provider check is tied to exactly the credential
/// under test, so that a variable in the environment, an active profile or
/// another saved login can never answer for it. Built by a pure function
/// per adapter ([`aws_binding`], [`gh_binding`], [`kube_binding`],
/// [`vault_binding`], [`gcloud_binding`], [`azure_binding`]; DigitalOcean
/// has [`doctl_binding`]), applied by [`run_bound`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliBinding {
    /// Arguments appended to every call.
    pub args: Vec<String>,
    /// Variables set in the child's environment.
    pub set: Vec<(String, EnvSource)>,
    /// Variables removed from the child's environment (inherited or not).
    pub remove: Vec<String>,
    /// Every variable starting with one of these is removed too.
    pub remove_prefixes: Vec<String>,
    /// What the evidence line records about the binding.
    pub evidence: String,
}

impl CliBinding {
    /// The child's environment and the names to strip from what it
    /// inherits. A variable that is set is never also removed.
    fn resolve(
        &self,
        env: &BTreeMap<String, String>,
    ) -> Result<(BTreeMap<String, String>, Vec<String>), String> {
        let mut remove: Vec<String> = self.remove.clone();
        if !self.remove_prefixes.is_empty() {
            let inherited = std::env::vars_os().filter_map(|(k, _)| k.into_string().ok());
            for name in env.keys().cloned().chain(inherited) {
                if self
                    .remove_prefixes
                    .iter()
                    .any(|p| name.starts_with(p.as_str()))
                    && !remove.contains(&name)
                {
                    remove.push(name);
                }
            }
        }
        let mut child = env.clone();
        for name in &remove {
            child.remove(name);
        }
        for (name, source) in &self.set {
            let value = match source {
                EnvSource::Value(v) => v.clone(),
                EnvSource::Var(var) => env
                    .get(var)
                    .cloned()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| format!("{var} is not set in this environment"))?,
                EnvSource::File(path) => std::fs::read_to_string(path)
                    .map(|t| t.trim().to_string())
                    .ok()
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
                        format!("the saved credential at {} is not readable", path.display())
                    })?,
            };
            child.insert(name.clone(), value);
            remove.retain(|r| r != name);
        }
        Ok((child, remove))
    }
}

/// Run one read-only call under a binding: the binding's arguments are
/// appended, its environment applied.
fn run_bound(
    program: &str,
    args: &[&str],
    binding: &CliBinding,
    env: &BTreeMap<String, String>,
) -> Result<CliOutput, String> {
    let (child, remove) = binding.resolve(env)?;
    let mut all: Vec<&str> = args.to_vec();
    all.extend(binding.args.iter().map(String::as_str));
    let remove: Vec<&str> = remove.iter().map(String::as_str).collect();
    run_cli_raw_bound(program, &all, &child, &remove)
}

/// [`run_bound`], stdout only; a non-zero exit is an error.
fn run_bound_ok(
    program: &str,
    args: &[&str],
    binding: &CliBinding,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let out = run_bound(program, args, binding, env)?;
    if !out.success {
        return Err(format!(
            "{} exited with an error: {}",
            command_label(program, args),
            out.stderr_first
        ));
    }
    Ok(out.stdout)
}

/// Variables through which the AWS CLI takes credentials or a profile from
/// the environment instead of the profile under test.
const AWS_ENV_OVERRIDES: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
];

/// AWS: `--profile <profile>` on every call, the CLI pointed at the
/// credentials and config files in the directory where the profile was
/// found, and every environment credential or profile override removed.
pub fn aws_binding(profile: &str, found_in: &Path) -> CliBinding {
    let dir = found_in.parent().unwrap_or(Path::new("."));
    CliBinding {
        args: vec!["--profile".into(), profile.to_string()],
        set: vec![
            (
                "AWS_SHARED_CREDENTIALS_FILE".into(),
                EnvSource::Value(dir.join("credentials").display().to_string()),
            ),
            (
                "AWS_CONFIG_FILE".into(),
                EnvSource::Value(dir.join("config").display().to_string()),
            ),
        ],
        remove: AWS_ENV_OVERRIDES.iter().map(|s| s.to_string()).collect(),
        remove_prefixes: Vec::new(),
        evidence: format!(
            "aws was bound to profile {profile} in {}: run with --profile and those files, with any credential or profile in the environment removed",
            dir.display()
        ),
    }
}

/// Every variable gh reads a token from, in its own order of preference.
const GH_TOKEN_VARS: &[&str] = &[
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
];

/// GitHub. gh prefers a token in `GH_TOKEN`, `GITHUB_TOKEN`,
/// `GH_ENTERPRISE_TOKEN` or `GITHUB_ENTERPRISE_TOKEN` over any saved login,
/// so left to itself it can confirm someone else's token for a saved one.
///
/// * `env:<VAR>`: only `VAR` is left in the child's environment, the other
///   token variables are removed, and `GH_CONFIG_DIR` points at
///   `empty_dir` (an empty, user-only temporary directory) so no saved
///   login can answer instead.
/// * `<host>`: a login saved in `hosts_yml`. Every token variable is
///   removed and `GH_CONFIG_DIR` is the directory holding that file.
///
/// Callers pass `--hostname` on every call.
pub fn gh_binding(key: &str, hosts_yml: &Path, empty_dir: &Path) -> CliBinding {
    let quiet = [
        (
            "GH_PROMPT_DISABLED".to_string(),
            EnvSource::Value("1".into()),
        ),
        (
            "GH_NO_UPDATE_NOTIFIER".to_string(),
            EnvSource::Value("1".into()),
        ),
    ];
    if let Some(var) = key.strip_prefix("env:") {
        let mut set = vec![
            (var.to_string(), EnvSource::Var(var.to_string())),
            (
                "GH_CONFIG_DIR".to_string(),
                EnvSource::Value(empty_dir.display().to_string()),
            ),
        ];
        set.extend(quiet);
        CliBinding {
            args: Vec::new(),
            set,
            remove: GH_TOKEN_VARS
                .iter()
                .filter(|v| **v != var)
                .map(|s| s.to_string())
                .collect(),
            remove_prefixes: Vec::new(),
            evidence: format!(
                "gh was bound to the token in {var}: the other token variables removed and an empty configuration directory, so no saved login could answer"
            ),
        }
    } else {
        let dir = hosts_yml.parent().unwrap_or(Path::new("."));
        let mut set = vec![(
            "GH_CONFIG_DIR".to_string(),
            EnvSource::Value(dir.display().to_string()),
        )];
        set.extend(quiet);
        CliBinding {
            args: Vec::new(),
            set,
            remove: GH_TOKEN_VARS.iter().map(|s| s.to_string()).collect(),
            remove_prefixes: Vec::new(),
            evidence: format!(
                "gh was bound to the {key} login saved in {}: run with that configuration directory and every token variable removed",
                hosts_yml.display()
            ),
        }
    }
}

/// Kubernetes: `--kubeconfig <file> --context <context>` on every call, for
/// the file the context was found in, with `KUBECONFIG` removed.
pub fn kube_binding(context: &str, kubeconfig: &Path) -> CliBinding {
    CliBinding {
        args: vec![
            "--kubeconfig".into(),
            kubeconfig.display().to_string(),
            "--context".into(),
            context.to_string(),
        ],
        set: Vec::new(),
        remove: vec!["KUBECONFIG".into()],
        remove_prefixes: Vec::new(),
        evidence: format!(
            "kubectl was bound to context {context} of {}: run with --kubeconfig and --context, KUBECONFIG removed",
            kubeconfig.display()
        ),
    }
}

/// Vault reads `VAULT_TOKEN` before `~/.vault-token`, so the token under
/// test is always passed in `VAULT_TOKEN`, in the child's environment only:
/// copied from the variable for an `env VAULT_TOKEN` finding, read from the
/// saved file for a file finding (where a token in the environment would
/// otherwise answer instead).
pub fn vault_binding(location: &str, token_file: &Path) -> CliBinding {
    match location.strip_prefix("env ") {
        Some(var) => CliBinding {
            args: Vec::new(),
            set: vec![("VAULT_TOKEN".into(), EnvSource::Var(var.to_string()))],
            remove: Vec::new(),
            remove_prefixes: Vec::new(),
            evidence: format!("vault was bound to the token in {var}"),
        },
        None => CliBinding {
            args: Vec::new(),
            set: vec![(
                "VAULT_TOKEN".into(),
                EnvSource::File(token_file.to_path_buf()),
            )],
            remove: Vec::new(),
            remove_prefixes: Vec::new(),
            evidence: format!(
                "vault was bound to the token saved in {}: passed in the environment of the check only, replacing any VAULT_TOKEN",
                token_file.display()
            ),
        },
    }
}

/// Google Cloud: the gcloud configuration directory and named configuration
/// the account was found in (`CLOUDSDK_CONFIG`,
/// `CLOUDSDK_ACTIVE_CONFIG_NAME`), with every other `CLOUDSDK_*` override
/// and `GOOGLE_APPLICATION_CREDENTIALS` removed. `found_in` is either a
/// `configurations/config_<name>` file or the configuration directory.
pub fn gcloud_binding(account: &str, found_in: &Path) -> CliBinding {
    let file = found_in
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("config_"));
    let (dir, config) = match (file, found_in.parent().and_then(Path::parent)) {
        (Some(name), Some(dir)) => (dir.to_path_buf(), Some(name.to_string())),
        _ => (found_in.to_path_buf(), None),
    };
    let mut set = vec![(
        "CLOUDSDK_CONFIG".to_string(),
        EnvSource::Value(dir.display().to_string()),
    )];
    if let Some(name) = &config {
        set.push((
            "CLOUDSDK_ACTIVE_CONFIG_NAME".to_string(),
            EnvSource::Value(name.clone()),
        ));
    }
    CliBinding {
        args: Vec::new(),
        set,
        remove: vec!["GOOGLE_APPLICATION_CREDENTIALS".into()],
        remove_prefixes: vec!["CLOUDSDK_".into()],
        evidence: format!(
            "gcloud was bound to account {account} in {}{}: other CLOUDSDK_ settings and GOOGLE_APPLICATION_CREDENTIALS removed",
            dir.display(),
            config
                .map(|c| format!(" (configuration {c})"))
                .unwrap_or_default()
        ),
    }
}

/// Azure: `AZURE_CONFIG_DIR` set to the directory holding the profile the
/// subscription was found in, `--subscription <name>` on every call, and
/// every other `AZURE_*` variable removed.
pub fn azure_binding(subscription: &str, profile_json: &Path) -> CliBinding {
    let dir = profile_json.parent().unwrap_or(Path::new("."));
    CliBinding {
        args: vec!["--subscription".into(), subscription.to_string()],
        set: vec![(
            "AZURE_CONFIG_DIR".into(),
            EnvSource::Value(dir.display().to_string()),
        )],
        remove: Vec::new(),
        remove_prefixes: vec!["AZURE_".into()],
        evidence: format!(
            "az was bound to subscription {subscription} in {}: run with that configuration directory and --subscription, other AZURE_ variables removed",
            dir.display()
        ),
    }
}

/// The verification key for a credential discovery left without one, where
/// the location alone selects it: a GitHub token in one of gh's own
/// variables.
fn fallback_key(d: &Discovered) -> Option<String> {
    if d.credential.kind != CredentialKind::GitHubToken {
        return None;
    }
    let var = d.credential.location.strip_prefix("env ")?;
    GH_TOKEN_VARS.contains(&var).then(|| format!("env:{var}"))
}

/// The display path of where a credential was found, without any
/// parenthesised note, as an absolute path.
fn found_path(d: &Discovered, env: &BTreeMap<String, String>) -> PathBuf {
    expand_home(
        d.credential
            .location
            .split(" (")
            .next()
            .unwrap_or(&d.credential.location),
        env,
    )
}

pub fn verify_all(
    discovered: &mut [Discovered],
    decl: &super::config::Declarations,
    env: &BTreeMap<String, String>,
) -> Outcome {
    let mut notes = Vec::new();
    let mut verifications = Vec::with_capacity(discovered.len());
    for d in discovered.iter_mut() {
        if adapter_command(d.credential.kind).is_none() {
            verifications.push(Verification::unsupported(
                "Gorse has no provider check for this kind of credential",
            ));
            continue;
        }
        let Some(key) = d.verify_key.clone().or_else(|| fallback_key(d)) else {
            verifications.push(Verification::unsupported(
                "this credential cannot be selected for a provider check",
            ));
            continue;
        };
        let before = d.credential.permissions.assurance;
        let result = match d.credential.kind {
            CredentialKind::AwsAccessKey
            | CredentialKind::AwsSession
            | CredentialKind::AwsSsoSession
            | CredentialKind::AwsProfileRole => verify_aws(d, &key, decl, env),
            CredentialKind::GitHubToken => verify_github(d, &key, decl, env),
            CredentialKind::KubernetesContext => verify_kubernetes(d, &key, decl, env),
            CredentialKind::VaultToken => verify_vault(d, env),
            CredentialKind::DigitalOceanToken => verify_digitalocean(d, &key, decl, env),
            CredentialKind::GcpUserCredential => verify_gcloud(d, &key, env),
            CredentialKind::AzureSession | CredentialKind::AzureServicePrincipal => {
                verify_azure(d, &key, decl, env)
            }
            _ => unreachable!("adapter_command lists exactly these kinds"),
        };
        let status = match &result {
            Ok(checked) => checked.status,
            Err(_) => VerificationStatus::Failed,
        };
        settle_assurance(d, before, status);
        match result {
            Ok(checked) => verifications.push(Verification {
                status: checked.status,
                detail: checked.detail,
            }),
            Err(e) => {
                notes.push(format!(
                    "{} ({}): not verified: {e}",
                    d.credential.name,
                    d.credential.kind.label()
                ));
                verifications.push(Verification {
                    status: VerificationStatus::Failed,
                    detail: failure_detail(&e),
                });
            }
        }
        cap_links_to_credential(d);
    }
    Outcome {
        notes,
        verifications,
    }
}

/// Hold the credential and its edges to what the check established. A
/// finding's confidence is raised only when the provider authenticated the
/// credential (identity or permission confirmed); a check that read local
/// configuration only, or failed part-way, puts back what discovery had.
/// An edge stays confirmed only when the provider confirmed that specific
/// permission: an identity answer says who the credential is, not what it
/// can reach, so every edge drops to at most inferred and a multi-hop path
/// through it stays inferred.
///
/// Capability flags follow the same rule one by one: only a flag an adapter
/// set with [`EffectivePermissions::confirm`] reads as confirmed, and a
/// check that did not reach the provider leaves none confirmed. An edge
/// whose own permission was confirmed that way (a role assumption that went
/// through) keeps its confirmation under an identity answer.
///
/// [`EffectivePermissions::confirm`]: hedgehog_taint::authority::EffectivePermissions::confirm
pub fn settle_assurance(d: &mut Discovered, before: Assurance, status: VerificationStatus) {
    let p = &mut d.credential.permissions;
    if !status.provider_answered() {
        p.assurance = p.assurance.weakest(before);
        p.clear_confirmations();
    }
    if status != VerificationStatus::PermissionConfirmed {
        let confirmed = p.confirmed.clone();
        for l in &mut d.links {
            let backed = edge_permission(l.edge).is_some_and(|q| confirmed.contains(&q));
            if !backed {
                l.assurance = l.assurance.weakest(Assurance::Inferred);
            }
        }
    }
}

/// The capability flag an edge kind stands for, where there is exactly one.
fn edge_permission(edge: EdgeKind) -> Option<Permission> {
    match edge {
        EdgeKind::CanAssumeRole => Some(Permission::AssumeRole),
        _ => None,
    }
}

/// No edge may carry more assurance than the credential it belongs to. A
/// verifier that ends with the credential still `inferred` (or that failed
/// outright) therefore cannot leave a `confirmed` edge behind.
pub fn cap_links_to_credential(d: &mut Discovered) {
    let ceiling = d.credential.permissions.assurance;
    for l in &mut d.links {
        l.assurance = l.assurance.weakest(ceiling);
    }
}

fn confirm_links(d: &mut Discovered, kind: NodeKind, edge: EdgeKind, evidence: &str) {
    for l in d
        .links
        .iter_mut()
        .filter(|l| l.kind == kind && l.edge == edge)
    {
        l.assurance = Assurance::Confirmed;
        l.evidence.push(redact_text(evidence));
    }
}

fn verify_aws(
    d: &mut Discovered,
    profile: &str,
    decl: &super::config::Declarations,
    env: &BTreeMap<String, String>,
) -> Result<Checked, String> {
    let binding = aws_binding(profile, &found_path(d, env));
    let out = run_bound_ok(
        "aws",
        &["sts", "get-caller-identity", "--output", "json"],
        &binding,
        env,
    )?;
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|_| "unexpected sts output")?;
    let arn = v["Arn"].as_str().ok_or("no Arn")?.to_string();
    let account = v["Account"].as_str().unwrap_or("?").to_string();
    d.credential.evidence.push(binding.evidence.clone());
    // Identity: who the key is and that it is live. Nothing about what it
    // can do; every capability below is inferred unless confirmed one by one.
    d.credential.permissions.identity = Some(arn.clone());
    d.credential.permissions.organization = Some(format!("AWS account {account}"));
    d.credential.permissions.assurance = Assurance::Confirmed;
    d.credential.permissions.revoked = Capability::No;
    d.credential
        .evidence
        .push("sts get-caller-identity succeeded".into());
    if d.credential.permissions.lifetime.is_expired() {
        d.credential.permissions.lifetime = Lifetime::Unknown;
    }
    // sts answering for a role profile with an assumed-role ARN means the
    // role assumption itself went through: that one capability (assuming
    // this role, one hop) is confirmed by the provider. What the role can
    // then do is not: its policies are not evaluated, so the finding is an
    // identity confirmation, never a permission confirmation.
    let assumed =
        d.credential.kind == CredentialKind::AwsProfileRole && arn.contains(":assumed-role/");
    if assumed {
        d.credential
            .permissions
            .confirm(Permission::AssumeRole, Capability::Yes);
        confirm_links(
            d,
            NodeKind::CloudRole,
            EdgeKind::CanAssumeRole,
            "assume-role succeeded via sts",
        );
    }
    let identity_detail = if assumed {
        "aws sts get-caller-identity: the provider confirmed the identity; role assumption confirmed; the role's effective permissions were not evaluated (permission boundaries, SCPs, explicit denies)"
    } else {
        "aws sts get-caller-identity: the provider confirmed the identity"
    };
    let checked = |extra: &str| {
        Checked::new(
            VerificationStatus::IdentityConfirmed,
            format!("{identity_detail}{extra}"),
        )
    };
    // Attached managed policies, where IAM lets us read them.
    let (subcommand, flag, name) = if let Some(user) = arn.split(":user/").nth(1) {
        (
            "list-attached-user-policies",
            "--user-name",
            user.to_string(),
        )
    } else if let Some(role) = arn
        .split(":assumed-role/")
        .nth(1)
        .and_then(|r| r.split('/').next())
    {
        (
            "list-attached-role-policies",
            "--role-name",
            role.to_string(),
        )
    } else {
        return Ok(checked(""));
    };
    let Ok(out) = run_bound_ok(
        "aws",
        &["iam", subcommand, flag, &name, "--output", "json"],
        &binding,
        env,
    ) else {
        d.credential
            .evidence
            .push("policy listing denied: scope stays inferred".into());
        return Ok(checked("; attached policies not readable"));
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) else {
        d.credential
            .evidence
            .push("policy listing unreadable: scope stays inferred".into());
        return Ok(checked("; attached policies not readable"));
    };
    let names: Vec<String> = v["AttachedPolicies"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["PolicyName"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    for n in &names {
        let perms = &mut d.credential.permissions;
        perms.scope.push(format!("policy {n}"));
        let lower = n.to_ascii_lowercase();
        let hint = decl.role_hint(n);
        // A policy's name is not its effect: boundaries, SCPs and explicit
        // denies can take any of it away. Capabilities read from names are
        // inferred.
        let mut inferred: Vec<&str> = Vec::new();
        if lower == "administratoraccess"
            || lower == "poweruseraccess"
            || hint.map(|h| h.administrative).unwrap_or(false)
        {
            perms.infer(Permission::Administrative, Capability::Yes);
            perms.infer(Permission::ModifyProduction, Capability::Yes);
            inferred.push("administrative access");
        }
        if lower == "administratoraccess"
            || lower == "iamfullaccess"
            || hint.map(|h| h.can_create_credentials).unwrap_or(false)
        {
            perms.infer(Permission::CreateCredentials, Capability::Yes);
            perms.infer(Permission::ModifyOwnPermissions, Capability::Yes);
            inferred.push("credential creation");
        }
        if !inferred.is_empty() {
            d.credential.evidence.push(format!(
                "policy {n} attached: {} inferred from the policy name, not evaluated",
                inferred.join(" and ")
            ));
        }
        if lower.contains("readonly") || lower.contains("viewonly") {
            // A read-only policy attached does not rule out administrative
            // access: group and inline policies are not listed here, and any
            // of them could grant it. Administrative stays unknown until the
            // whole grant set has been evaluated.
            d.credential.evidence.push(format!(
                "{n} attached; group and inline policies not checked, so administrative access stays unknown"
            ));
        }
    }
    if names.is_empty() {
        d.credential
            .evidence
            .push("no attached managed policies (inline or group policies not checked)".into());
    }
    d.credential.evidence.push(AWS_POLICY_NOTE.into());
    Ok(checked(&format!("; {AWS_POLICY_NOTE}")))
}

/// Why listing attached policies is not a confirmation of what the
/// credential can do.
const AWS_POLICY_NOTE: &str = "attached policies listed, but permission boundaries, service control policies and explicit denies were not evaluated, so effective permissions are not confirmed";

// ─── GitHub ──────────────────────────────────────────────────────────────────

/// What `gh auth status` said about one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GhAuthStatus {
    pub logged_in: bool,
    pub account: Option<String>,
    /// Classic OAuth scopes as gh lists them. Empty for fine-grained tokens,
    /// whose per-repository permissions gh cannot list.
    pub scopes: Vec<String>,
    /// gh showed a `github_pat_` token, or listed no classic scopes.
    pub fine_grained: bool,
}

/// Parse `gh auth status` output (either stream; gh has used both).
pub fn parse_gh_auth_status(text: &str) -> GhAuthStatus {
    let scopes: Vec<String> = text
        .lines()
        .find(|l| l.contains("Token scopes:"))
        .map(|l| {
            l.split("Token scopes:")
                .nth(1)
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
                .filter(|s| !s.is_empty() && s != "none")
                .collect()
        })
        .unwrap_or_default();
    let account = text
        .lines()
        .find(|l| l.contains("account "))
        .and_then(|line| {
            line.split("account ")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .map(|s| s.to_string())
        });
    GhAuthStatus {
        logged_in: text.contains("Logged in"),
        account,
        fine_grained: text.contains("github_pat_") || scopes.is_empty(),
        scopes,
    }
}

/// Apply what `gh auth status` established: who the token is and that it
/// works (identity), and the classic scopes it carries. A scope is not a
/// repository permission (a `repo`-scoped token may be read-only on a given
/// repository, and write access does not imply pushing to a protected
/// branch), so nothing a scope implies is confirmed: every capability and
/// edge read from scopes is inferred and the evidence says so. A missing
/// scope proves nothing either: fine-grained tokens carry per-repository
/// permissions that gh does not list. Only a repository's own permissions
/// object confirms anything (see [`apply_repo_access`]).
pub fn apply_gh_auth_status(d: &mut Discovered, status: &GhAuthStatus, host: &str) {
    let fine_grained = status.fine_grained
        || d.credential
            .evidence
            .iter()
            .any(|e| e.contains("fine-grained"));
    let p = &mut d.credential.permissions;
    if let Some(acct) = &status.account {
        p.identity = Some(acct.clone());
    }
    p.revoked = Capability::No;
    // The login itself was confirmed by GitHub.
    p.assurance = Assurance::Confirmed;
    if fine_grained {
        p.scope =
            vec!["fine-grained token: permissions are per repository and not listed by gh".into()];
        d.credential.evidence.push(
            "gh auth status: logged in; write access stays unknown until checked against a declared repository"
                .into(),
        );
        for l in d
            .links
            .iter_mut()
            .filter(|l| l.edge == EdgeKind::CanPushCode)
        {
            l.assurance = l.assurance.weakest(Assurance::Inferred);
            l.evidence.push(
                "write access not confirmed: fine-grained token, no classic scopes to read".into(),
            );
        }
        return;
    }
    p.scope = status.scopes.iter().map(|s| format!("scope {s}")).collect();
    let has = |s: &str| status.scopes.iter().any(|x| x == s);
    let scope_note = if has("repo") {
        Some((
            "scope repo: write access inferred from the token scope; scopes are not repository permissions",
            true,
        ))
    } else if has("public_repo") {
        Some((
            "scope public_repo: write access to public repositories inferred from the token scope",
            false,
        ))
    } else {
        None
    };
    for l in d
        .links
        .iter_mut()
        .filter(|l| l.edge == EdgeKind::CanPushCode)
    {
        l.assurance = l.assurance.weakest(Assurance::Inferred);
        match scope_note {
            Some((note, all)) if all || l.kind == NodeKind::Repository => {
                l.evidence.push(note.into())
            }
            Some(_) => {}
            // Not confirmed, not disproved: gh lists classic scopes only.
            None => l.evidence.push(
                "no repo scope listed by gh: write access not confirmed (and not disproved; only classic scopes are listed)"
                    .into(),
            ),
        }
    }
    if has("workflow") {
        d.links.push(
            Link::new(
                NodeKind::CiSystem,
                &format!("{host} Actions workflows"),
                EdgeKind::CanModifyConfiguration,
                Assurance::Inferred,
            )
            .evidence("scope workflow: can edit CI definitions, which run with CI secrets (inferred from the token scope)"),
        );
    }
    if has("admin:org") {
        let p = &mut d.credential.permissions;
        p.infer(Permission::Administrative, Capability::Yes);
        p.infer(Permission::ModifyOwnPermissions, Capability::Yes);
        d.credential.evidence.push(
            "scope admin:org: administrative access to organizations inferred from the token scope, not checked against any organization"
                .into(),
        );
    }
    if has("delete_repo") {
        d.credential
            .permissions
            .scope
            .push("can delete repositories".into());
    }
}

/// `owner/repo` from a declared host entry such as `acme/api`,
/// `github.com/acme/api` or `https://github.com/acme/api.git`. Entries that
/// name a different host, or only a host, yield nothing.
pub fn declared_repo(entry: &str, host: &str) -> Option<String> {
    let mut s = entry.trim();
    for prefix in ["https://", "http://", "ssh://git@", "git@"] {
        s = s.strip_prefix(prefix).unwrap_or(s);
    }
    if let Some(rest) = s.strip_prefix(host) {
        s = rest.trim_start_matches(['/', ':']);
    } else if s.contains('.') && s.split(['/', ':']).next().map(|h| h.contains('.')) == Some(true) {
        // Some other host.
        return None;
    }
    let s = s.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = s.split('/');
    let (owner, repo, rest) = (parts.next()?, parts.next()?, parts.next());
    if owner.is_empty() || repo.is_empty() || rest.is_some() {
        return None;
    }
    if owner.contains('.') || owner.contains(':') || repo.contains(':') {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

/// What `GET repos/{owner}/{repo}` (read-only) said about one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoAccess {
    /// `permissions.push = true`; `admin` when `permissions.admin` is too.
    Write { admin: bool },
    /// `permissions.pull = true` and no push.
    ReadOnly,
    /// Visible, but neither push nor pull.
    Visible,
    /// The API answered without a `permissions` object.
    NoPermissions,
    /// The repository could not be read with this token (redacted reason).
    Unreadable(String),
}

impl RepoAccess {
    /// Read the `permissions` object of a repository response.
    pub fn from_permissions(perms: &serde_json::Value) -> RepoAccess {
        let push = perms.get("push").and_then(|v| v.as_bool());
        let pull = perms.get("pull").and_then(|v| v.as_bool());
        let admin = perms.get("admin").and_then(|v| v.as_bool()) == Some(true);
        match (push, pull) {
            (None, _) => RepoAccess::NoPermissions,
            (Some(true), _) => RepoAccess::Write { admin },
            (Some(false), Some(true)) => RepoAccess::ReadOnly,
            (Some(false), _) => RepoAccess::Visible,
        }
    }

    /// The edge this answer confirms, and the word for it. `None` when the
    /// repository could not be judged.
    fn edge(&self) -> Option<(EdgeKind, &'static str)> {
        match self {
            RepoAccess::Write { admin: true } => Some((EdgeKind::CanPushCode, "admin")),
            RepoAccess::Write { admin: false } => Some((EdgeKind::CanPushCode, "write")),
            RepoAccess::ReadOnly => Some((EdgeKind::CanReadSecret, "read-only")),
            RepoAccess::Visible => Some((EdgeKind::CanReach, "visible only")),
            RepoAccess::NoPermissions | RepoAccess::Unreadable(_) => None,
        }
    }

    /// Why the repository could not be judged.
    fn gap(&self) -> Option<String> {
        match self {
            RepoAccess::NoPermissions => Some("no permissions object returned".into()),
            RepoAccess::Unreadable(e) => Some(format!("not readable with this token: {e}")),
            _ => None,
        }
    }
}

/// Fold the per-repository answers for one declared system into its edges.
/// This is the one place a repository may be confirmed read-only, because
/// it was asked about that repository.
///
/// Each judged repository becomes its own confirmed edge to the system
/// node, scoped `repository owner/repo`, so a writable repository and a
/// read-only one sit side by side instead of overwriting each other. The
/// discovery guess for the system as a whole (the unscoped edge) is
/// retired once the repositories describe the system completely: when any
/// grants write, or when every declared repository was judged and none
/// does. While some repository could not be judged and none grants write,
/// the guess stays inferred and the evidence names the gap. Answers are
/// folded by repository name, so the order in the map never matters.
pub fn apply_repo_access(d: &mut Discovered, system: &str, repos: &[(String, RepoAccess)]) {
    let mut repos: Vec<&(String, RepoAccess)> = repos.iter().collect();
    repos.sort_by(|a, b| a.0.cmp(&b.0));
    repos.dedup_by(|a, b| a.0 == b.0);
    let generic = |l: &Link| {
        l.kind == NodeKind::CiSystem
            && l.name == system
            && l.scope.is_none()
            && matches!(
                l.edge,
                EdgeKind::CanPushCode | EdgeKind::CanReadSecret | EdgeKind::CanReach
            )
    };
    // The system's existing edge carries the declared approval gate and
    // production flag; a graph merge drops a gate the new edge lacks.
    let Some(template) = d.links.iter().find(|l| generic(l)).cloned() else {
        return;
    };
    let mut judged: Vec<String> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    let mut any_write = false;
    for (repo, access) in &repos {
        match access.edge() {
            Some((edge, what)) => {
                any_write |= edge == EdgeKind::CanPushCode;
                let detail = match access {
                    RepoAccess::Write { admin } => format!(
                        "permissions.push = true{}",
                        if *admin { ", admin = true" } else { "" }
                    ),
                    RepoAccess::ReadOnly => "permissions.push = false, pull = true".to_string(),
                    _ => "permissions.push = false, pull = false".to_string(),
                };
                let mut link = Link::new(NodeKind::CiSystem, system, edge, Assurance::Confirmed)
                    .scope(&format!("repository {repo}"))
                    .approval(template.approval.clone())
                    .production(template.production);
                link.evidence = template.evidence.clone();
                link.evidence.push(redact_text(&format!(
                    "repos/{repo}: {detail} ({what} on this repository)"
                )));
                d.links.push(link);
                d.credential
                    .permissions
                    .scope
                    .push(format!("{repo}: {what}"));
                judged.push(format!("{what} on {repo}"));
            }
            None => {
                let why = access.gap().unwrap_or_default();
                d.credential
                    .permissions
                    .scope
                    .push(format!("{repo}: not checked"));
                gaps.push(format!("{repo} ({why})"));
            }
        }
    }
    if judged.is_empty() && gaps.is_empty() {
        return;
    }
    if !judged.is_empty() {
        d.credential.permissions.assurance = Assurance::Confirmed;
    }
    let mut summary = judged.clone();
    if !gaps.is_empty() {
        summary.push(format!("not checked: {}", gaps.join(", ")));
    }
    d.credential
        .evidence
        .push(format!("{system} repositories: {}", summary.join("; ")));
    if any_write || gaps.is_empty() {
        // The repositories now describe the system; the guess is redundant
        // (write confirmed) or disproved on every declared repository.
        d.links.retain(|l| !generic(l));
    } else {
        for l in d.links.iter_mut().filter(|l| generic(l)) {
            l.evidence.push(format!(
                "no declared repository confirmed write; not checked: {}; access stays {}",
                gaps.join(", "),
                l.assurance.label()
            ));
        }
    }
}

/// A user-only temporary directory, removed on drop: the configuration
/// directory for a check that must see no saved login.
struct EmptyDir {
    path: PathBuf,
}

impl EmptyDir {
    fn create(tag: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "gorse-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            // Owner only. A directory needs the execute bit to be used, so
            // this is 0700 rather than 0600.
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|e| format!("cannot create an empty configuration directory: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for EmptyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The detail of a check that reached a different account from the one the
/// saved credential records.
const GH_OTHER_ACCOUNT: &str = "provider reported a different account than the saved credential";

fn verify_github(
    d: &mut Discovered,
    key: &str,
    decl: &super::config::Declarations,
    env: &BTreeMap<String, String>,
) -> Result<Checked, String> {
    // Bind every gh call to the credential under test (see [`gh_binding`]).
    let (host, empty) = match key.strip_prefix("env:") {
        Some(var) if var.contains("ENTERPRISE") => (
            env.get("GH_HOST")
                .filter(|h| !h.is_empty())
                .cloned()
                .ok_or_else(|| {
                    format!("{var} is for a GitHub Enterprise host and GH_HOST is not set")
                })?,
            Some(EmptyDir::create("gh")?),
        ),
        Some(_) => ("github.com".to_string(), Some(EmptyDir::create("gh")?)),
        None => (key.to_string(), None),
    };
    let binding = gh_binding(
        key,
        &found_path(d, env),
        empty
            .as_ref()
            .map(|e| e.path.as_path())
            .unwrap_or(Path::new("")),
    );
    // The account the saved login records, to compare with GitHub's answer.
    let recorded = if key.starts_with("env:") {
        None
    } else {
        d.credential
            .permissions
            .identity
            .clone()
            .filter(|u| !u.is_empty() && u != "?")
    };
    // gh prints status to stderr on some versions and stdout on others; capture both.
    let output = run_bound(
        "gh",
        &["auth", "status", "--hostname", &host],
        &binding,
        env,
    )?;
    let text = format!("{}{}", output.stdout, output.stderr);
    let status = parse_gh_auth_status(&text);
    if !output.success && !status.logged_in {
        return Err(format!(
            "gh auth status exited with an error: {}",
            redact_text(text.lines().next().unwrap_or("not logged in"))
        ));
    }
    if let (Some(saved), Some(reported)) = (&recorded, &status.account) {
        if !saved.eq_ignore_ascii_case(reported) {
            return Err(GH_OTHER_ACCOUNT.into());
        }
    }
    d.credential.evidence.push(binding.evidence.clone());
    apply_gh_auth_status(d, &status, &host);
    // Token scopes are not repository permissions, so nothing gh auth
    // status implied stays confirmed. Only a repository's own permissions
    // object, below, confirms an edge.
    for l in &mut d.links {
        l.assurance = l.assurance.weakest(Assurance::Inferred);
    }

    // Repository-specific permissions for declared repositories: the only
    // check that can settle a fine-grained token's write access. Each
    // repository is asked about once; the answers are folded per system.
    let mut by_system: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in decl
        .production_systems
        .iter()
        .filter(|s| s.kind == "repository" || s.kind == "ci")
        .filter(|s| {
            d.links
                .iter()
                .any(|l| l.kind == NodeKind::CiSystem && l.name == s.name)
        })
    {
        let repos = by_system.entry(s.name.clone()).or_default();
        repos.extend(s.hosts.iter().filter_map(|h| declared_repo(h, &host)));
    }
    let mut answers: BTreeMap<String, RepoAccess> = BTreeMap::new();
    for repo in by_system.values().flatten() {
        if answers.contains_key(repo) {
            continue;
        }
        let path = format!("repos/{repo}");
        let access = match run_bound_ok("gh", &["api", "--hostname", &host, &path], &binding, env) {
            Ok(out) => {
                let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
                RepoAccess::from_permissions(&v["permissions"])
            }
            Err(e) => RepoAccess::Unreadable(e),
        };
        answers.insert(repo.clone(), access);
    }
    for (system, repos) in &by_system {
        let results: Vec<(String, RepoAccess)> = repos
            .iter()
            .filter_map(|r| answers.get(r).map(|a| (r.clone(), a.clone())))
            .collect();
        apply_repo_access(d, system, &results);
    }
    // gh auth status asks GitHub who the token belongs to: identity. A
    // repository answer is the provider confirming a specific permission on
    // that repository.
    let judged = answers.values().filter(|a| a.edge().is_some()).count();
    if judged > 0 {
        Ok(Checked::new(
            VerificationStatus::PermissionConfirmed,
            format!(
                "gh auth status and gh api repos: the provider confirmed the identity and the permission on {judged} declared repositor{}; repository write access does not imply pushing to a protected branch",
                if judged == 1 { "y" } else { "ies" }
            ),
        ))
    } else {
        Ok(Checked::new(
            VerificationStatus::IdentityConfirmed,
            "gh auth status: the provider confirmed the identity; token scopes are not repository permissions, and write access does not imply pushing to a protected branch",
        ))
    }
}

// ─── Kubernetes ──────────────────────────────────────────────────────────────

/// Parse `kubectl auth can-i --list` output into (resource, verbs).
pub fn parse_can_i_list(text: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        // Columns: Resources, Non-Resource URLs, Resource Names, Verbs. Verbs is the last [..] group.
        let verbs_start = line.rfind('[').unwrap_or(line.len());
        let verbs: Vec<String> = line[verbs_start..]
            .trim_matches(|c| c == '[' || c == ']')
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        out.push((cols[0].to_string(), verbs));
    }
    out
}

/// Parse a single `kubectl auth can-i VERB RESOURCE` answer.
pub fn parse_can_i_answer(text: &str) -> Option<bool> {
    let first = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let lower = first.to_ascii_lowercase();
    if lower.starts_with("yes") {
        Some(true)
    } else if lower.starts_with("no") {
        Some(false)
    } else {
        None
    }
}

/// Interpret RBAC rules into capability edges.
pub fn kube_capabilities(rules: &[(String, Vec<String>)]) -> KubeCaps {
    let mut caps = KubeCaps::default();
    let writes = |v: &[String]| {
        v.iter()
            .any(|x| x == "*" || x == "create" || x == "update" || x == "patch" || x == "delete")
    };
    let reads = |v: &[String]| v.iter().any(|x| x == "*" || x == "get" || x == "list");
    for (res, verbs) in rules {
        if res == "*.*" && verbs.iter().any(|v| v == "*") {
            caps.admin = true;
        }
        if (res.starts_with("deployments")
            || res.starts_with("pods")
            || res.starts_with("daemonsets")
            || res.starts_with("statefulsets")
            || res.starts_with("jobs")
            || res.starts_with("cronjobs"))
            && writes(verbs)
        {
            caps.deploy = true;
        }
        if res == "secrets" && reads(verbs) {
            caps.read_secrets = true;
        }
        if (res == "secrets"
            || res == "serviceaccounts/token"
            || res.starts_with("serviceaccounts"))
            && writes(verbs)
        {
            caps.create_credentials = true;
        }
        if (res == "configmaps" || res.starts_with("ingresses") || res == "services")
            && writes(verbs)
        {
            caps.modify_config = true;
        }
        if (res.starts_with("clusterrolebindings")
            || res.starts_with("rolebindings")
            || res.starts_with("clusterroles"))
            && writes(verbs)
        {
            caps.escalate = true;
        }
    }
    if caps.admin {
        caps.deploy = true;
        caps.read_secrets = true;
        caps.create_credentials = true;
        caps.modify_config = true;
        caps.escalate = true;
    }
    caps
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KubeCaps {
    pub admin: bool,
    pub deploy: bool,
    pub read_secrets: bool,
    pub create_credentials: bool,
    pub modify_config: bool,
    pub escalate: bool,
}

impl KubeCaps {
    fn summary(&self) -> String {
        format!(
            "admin={} deploy={} read-secrets={} create-credentials={} modify-config={} escalate={}",
            self.admin,
            self.deploy,
            self.read_secrets,
            self.create_credentials,
            self.modify_config,
            self.escalate
        )
    }
    fn granted(&self) -> String {
        let mut g = Vec::new();
        if self.admin {
            g.push("admin");
        }
        if self.deploy {
            g.push("deploy");
        }
        if self.read_secrets {
            g.push("read secrets");
        }
        if self.create_credentials {
            g.push("create credentials");
        }
        if self.modify_config {
            g.push("modify configuration");
        }
        if self.escalate {
            g.push("escalate");
        }
        if g.is_empty() {
            "none of the tracked capabilities".to_string()
        } else {
            g.join(", ")
        }
    }
}

/// Where a Kubernetes RBAC answer applies. `kubectl auth can-i --list` is
/// always about one namespace (the API refuses an empty one); only a check
/// made with `--all-namespaces` speaks for the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubeScope {
    Namespace(String),
    AllNamespaces,
}

impl KubeScope {
    pub fn label(&self) -> String {
        match self {
            KubeScope::Namespace(ns) => format!("namespace {ns}"),
            KubeScope::AllNamespaces => "cluster-wide".to_string(),
        }
    }
    /// How a sentence should place it: "in namespace payments" / "cluster-wide".
    pub fn in_phrase(&self) -> String {
        match self {
            KubeScope::Namespace(ns) => format!("in namespace {ns}"),
            KubeScope::AllNamespaces => "cluster-wide".to_string(),
        }
    }
    fn command(&self) -> String {
        match self {
            KubeScope::Namespace(ns) => format!("kubectl auth can-i --list -n {ns}"),
            KubeScope::AllNamespaces => "kubectl auth can-i --all-namespaces".to_string(),
        }
    }
}

/// One RBAC answer: what the context may do, and where that was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeCheck {
    pub scope: KubeScope,
    pub caps: KubeCaps,
}

/// The namespace `kubectl` would use for this context: the context's own,
/// or `default` when it sets none. Read-only (`kubectl config view`).
fn kube_current_namespace(binding: &CliBinding, env: &BTreeMap<String, String>) -> String {
    let ns = run_bound_ok(
        "kubectl",
        &[
            "config",
            "view",
            "--minify",
            "-o",
            "jsonpath={.contexts[0].context.namespace}",
        ],
        binding,
        env,
    )
    .map(|s| s.trim().trim_matches('\'').to_string())
    .unwrap_or_default();
    if ns.is_empty() {
        "default".to_string()
    } else {
        ns
    }
}

/// Cluster-wide capabilities via `kubectl auth can-i VERB RESOURCE
/// --all-namespaces`: each is a SelfSubjectAccessReview against the
/// cluster scope, which only ClusterRole bindings satisfy. Returns `None`
/// when any probe failed to answer, so a partial picture is never reported
/// as cluster-wide.
fn kube_cluster_wide_probe(
    binding: &CliBinding,
    env: &BTreeMap<String, String>,
) -> Option<KubeCaps> {
    let ask = |verb: &str, resource: &str| -> Option<bool> {
        let out = run_bound(
            "kubectl",
            &["auth", "can-i", verb, resource, "--all-namespaces"],
            binding,
            env,
        )
        .ok()?;
        parse_can_i_answer(&out.stdout)
    };
    Some(KubeCaps {
        admin: ask("*", "*")?,
        deploy: ask("create", "deployments.apps")?,
        read_secrets: ask("get", "secrets")?,
        create_credentials: ask("create", "secrets")?,
        modify_config: ask("update", "configmaps")?,
        escalate: ask("create", "clusterrolebindings.rbac.authorization.k8s.io")?,
    })
}

/// Every namespace in the cluster via `kubectl get namespaces` (read-only).
/// `None` when the context may not list them, so completeness is unknown.
fn kube_list_namespaces(
    binding: &CliBinding,
    env: &BTreeMap<String, String>,
) -> Option<Vec<String>> {
    let out = run_bound_ok(
        "kubectl",
        &[
            "get",
            "namespaces",
            "-o",
            "jsonpath={.items[*].metadata.name}",
        ],
        binding,
        env,
    )
    .ok()?;
    let mut names: Vec<String> = Vec::new();
    for ns in out.split_whitespace().map(|s| s.trim_matches('\'')) {
        if !ns.is_empty() && !names.iter().any(|n| n == ns) {
            names.push(ns.to_string());
        }
    }
    Some(names)
}

/// Upper bound on namespaces checked beyond the context's own and the
/// declared ones. A cluster with more leaves the remainder unchecked, which
/// the coverage records, so a denial can never be read as complete.
const MAX_LISTED_NAMESPACE_CHECKS: usize = 50;

/// Which namespaces a verification covered, so a denial can be judged
/// complete or not. A denial is complete only when every namespace that
/// could matter was asked: the cluster scope, every namespace the map
/// declares for systems on this cluster, and every namespace the cluster
/// lists. When the list is not readable, completeness is unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KubeCoverage {
    /// Namespaces the map declares for systems this credential reaches.
    pub declared: Vec<String>,
    /// Every namespace in the cluster, when `kubectl get namespaces` was
    /// allowed; `None` when it was denied or failed.
    pub listed: Option<Vec<String>>,
    /// Namespaces whose check did not run, with the reason.
    pub failures: BTreeMap<String, String>,
}

impl KubeCoverage {
    /// Namespaces that should have been checked but were not, with a phrase
    /// saying why each matters and what happened.
    fn unchecked(&self, checks: &[KubeCheck]) -> Vec<(String, String)> {
        let checked = |ns: &str| {
            checks
                .iter()
                .any(|c| matches!(&c.scope, KubeScope::Namespace(n) if n == ns))
        };
        let mut out: Vec<(String, String)> = Vec::new();
        for ns in self.declared.iter().chain(self.listed.iter().flatten()) {
            if checked(ns) || out.iter().any(|(n, _)| n == ns) {
                continue;
            }
            let origin = if self.declared.contains(ns) {
                "declared in the map"
            } else {
                "exists in the cluster"
            };
            let why = match self.failures.get(ns) {
                Some(f) => format!("{origin}, not checked: {f}"),
                None => format!("{origin}, not checked"),
            };
            out.push((ns.clone(), why));
        }
        out
    }
}

fn verify_kubernetes(
    d: &mut Discovered,
    context: &str,
    decl: &super::config::Declarations,
    env: &BTreeMap<String, String>,
) -> Result<Checked, String> {
    let binding = kube_binding(context, &found_path(d, env));
    // The namespace kubectl would actually check for this context.
    let current = d
        .credential
        .permissions
        .restrictions
        .iter()
        .find_map(|r| r.strip_prefix("default namespace ").map(|s| s.to_string()))
        .unwrap_or_else(|| kube_current_namespace(&binding, env));
    let mut namespaces = vec![current];
    // Namespaces the map declares for systems hosted on this context/cluster.
    let mut hosts: Vec<String> = vec![context.to_string()];
    hosts.extend(
        d.links
            .iter()
            .filter(|l| l.kind == NodeKind::Cluster)
            .map(|l| l.name.clone()),
    );
    if let Some(server) = &d.credential.permissions.organization {
        hosts.push(server.clone());
    }
    let mut declared: Vec<String> = Vec::new();
    for h in &hosts {
        for system in decl.systems_hosting(h) {
            for ns in &system.namespaces {
                if !ns.trim().is_empty() && !declared.contains(ns) {
                    declared.push(ns.clone());
                }
            }
        }
    }
    for ns in &declared {
        if !namespaces.contains(ns) {
            namespaces.push(ns.clone());
        }
    }
    // The real namespace list, when readable, decides whether a denial is
    // complete; every listed namespace is checked too, up to a bound.
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let listed = kube_list_namespaces(&binding, env);
    let mut extra = 0usize;
    for ns in listed.iter().flatten() {
        if namespaces.contains(ns) {
            continue;
        }
        if extra >= MAX_LISTED_NAMESPACE_CHECKS {
            failures.insert(
                ns.clone(),
                format!("beyond the {MAX_LISTED_NAMESPACE_CHECKS}-namespace limit"),
            );
            continue;
        }
        extra += 1;
        namespaces.push(ns.clone());
    }

    let mut checks = Vec::new();
    let mut skipped = Vec::new();
    for (i, ns) in namespaces.iter().enumerate() {
        let args = ["auth", "can-i", "--list", "-n", ns];
        match run_bound_ok("kubectl", &args, &binding, env) {
            Ok(out) => checks.push(KubeCheck {
                scope: KubeScope::Namespace(ns.clone()),
                caps: kube_capabilities(&parse_can_i_list(&out)),
            }),
            // The context's own namespace failing means the context does not work.
            Err(e) if i == 0 => return Err(e),
            Err(e) => {
                failures.insert(ns.clone(), format!("kubectl: {e}"));
            }
        }
    }
    if let Some(caps) = kube_cluster_wide_probe(&binding, env) {
        checks.push(KubeCheck {
            scope: KubeScope::AllNamespaces,
            caps,
        });
    } else {
        skipped.push("cluster-wide probe incomplete: nothing is reported as cluster-wide".into());
    }
    let coverage = KubeCoverage {
        declared,
        listed,
        failures,
    };
    apply_kube_checks(d, &checks, &coverage);
    d.credential.evidence.extend(skipped);
    d.credential.evidence.push(binding.evidence.clone());
    Ok(Checked::new(
        VerificationStatus::PermissionConfirmed,
        "kubectl auth can-i: the cluster confirmed which actions this context may take",
    ))
}

/// Fold RBAC answers into the credential and its edges. Each confirmed edge
/// is labelled with the scope it was checked in. A capability missing from
/// one namespace's listing is not evidence about any other namespace, so it
/// never removes an inferred edge on its own. A capability is "no" only
/// when the coverage is complete: the cluster-wide probe denied it, the
/// namespace list was readable, and every namespace in that list and in the
/// map was checked and denied it. Any gap leaves it unknown, and the
/// evidence says exactly which namespaces were checked and which were not.
/// A grant in any scope is always kept.
pub fn apply_kube_checks(d: &mut Discovered, checks: &[KubeCheck], coverage: &KubeCoverage) {
    let any = |f: fn(&KubeCaps) -> bool| checks.iter().any(|c| f(&c.caps));
    let cluster_wide = checks.iter().find(|c| c.scope == KubeScope::AllNamespaces);
    let unchecked = coverage.unchecked(checks);
    let complete = cluster_wide.is_some() && coverage.listed.is_some() && unchecked.is_empty();
    let decide = |f: fn(&KubeCaps) -> bool| -> Capability {
        if any(f) {
            Capability::Yes
        } else if complete {
            Capability::No
        } else {
            Capability::Unknown
        }
    };
    let p = &mut d.credential.permissions;
    p.assurance = Assurance::Confirmed;
    p.revoked = Capability::No;
    // Each of these is a SelfSubjectAccessReview answer for that specific
    // permission, so the cluster confirmed it (an unknown confirms nothing).
    p.confirm(Permission::Administrative, decide(|c| c.admin));
    p.confirm(
        Permission::CreateCredentials,
        decide(|c| c.create_credentials),
    );
    p.confirm(Permission::ModifyOwnPermissions, decide(|c| c.escalate));
    let production = d.links.iter().any(|l| l.production);
    if production {
        p.confirm(
            Permission::ModifyProduction,
            decide(|c| c.deploy || c.modify_config),
        );
    }
    // One line per scope that grants something, and for the cluster scope;
    // namespaces that grant nothing are summarised together.
    let mut empty_namespaces: Vec<String> = Vec::new();
    for c in checks {
        let granted = c.caps != KubeCaps::default();
        if let (KubeScope::Namespace(ns), false) = (&c.scope, granted) {
            empty_namespaces.push(ns.clone());
            continue;
        }
        p.scope.push(format!(
            "RBAC {}: {}",
            c.scope.in_phrase(),
            c.caps.granted()
        ));
        d.credential.evidence.push(format!(
            "{} ({}): {}",
            c.scope.command(),
            c.scope.in_phrase(),
            c.caps.summary()
        ));
    }
    if !empty_namespaces.is_empty() {
        let phrase = namespaces_phrase(&empty_namespaces);
        p.scope.push(format!(
            "RBAC in {phrase}: {}",
            KubeCaps::default().granted()
        ));
        d.credential.evidence.push(format!(
            "kubectl auth can-i --list ({phrase}): {}",
            KubeCaps::default().summary()
        ));
    }
    // What was covered, so a reader can see where a denial applies.
    let checked: Vec<String> = checks
        .iter()
        .filter_map(|c| match &c.scope {
            KubeScope::Namespace(ns) => Some(ns.clone()),
            KubeScope::AllNamespaces => None,
        })
        .collect();
    let gaps = coverage_gaps(&unchecked, coverage, cluster_wide.is_some());
    d.credential.evidence.push(if complete {
        format!(
            "namespaces checked: {} (all {} listed by kubectl get namespaces) and cluster-wide; denials are complete",
            checked.join(", "),
            checked.len()
        )
    } else {
        format!(
            "namespaces checked: {}{}; {}; denials stay unknown",
            checked.join(", "),
            if cluster_wide.is_some() {
                " and cluster-wide"
            } else {
                ""
            },
            gaps.join("; ")
        )
    });

    // One entry per target node, however many links already point at it.
    let mut cluster_links: Vec<(NodeKind, String, bool)> = Vec::new();
    for l in d
        .links
        .iter()
        .filter(|l| matches!(l.kind, NodeKind::Cluster | NodeKind::ProductionService))
    {
        match cluster_links
            .iter_mut()
            .find(|(k, n, _)| *k == l.kind && *n == l.name)
        {
            Some(entry) => entry.2 |= l.production,
            None => cluster_links.push((l.kind, l.name.clone(), l.production)),
        }
    }
    for l in d
        .links
        .iter_mut()
        .filter(|l| l.kind == NodeKind::Cluster && l.edge == EdgeKind::CanAuthenticate)
    {
        l.assurance = Assurance::Confirmed;
    }
    // The inferred, unscoped deploy guess (an "admin"-named context) goes
    // only when the coverage is complete and nothing granted it anywhere.
    let any_deploy = any(|c| c.deploy);
    if !any_deploy {
        if complete {
            d.links
                .retain(|l| !(l.edge == EdgeKind::CanDeploy && l.assurance == Assurance::Inferred));
        } else {
            let scopes: Vec<String> = checks.iter().map(|c| c.scope.label()).collect();
            for l in d
                .links
                .iter_mut()
                .filter(|l| l.edge == EdgeKind::CanDeploy && l.assurance == Assurance::Inferred)
            {
                l.evidence.push(format!(
                    "not granted in {}; {}, so this stays inferred",
                    scopes.join(", "),
                    gaps.join("; ")
                ));
            }
        }
    }
    for c in checks {
        let scope = c.scope.label();
        let phrase = c.scope.in_phrase();
        let caps = c.caps;
        for (kind, name, production) in &cluster_links {
            let mut push = |edge: EdgeKind, why: &str| {
                d.links.push(
                    Link::new(*kind, name, edge, Assurance::Confirmed)
                        .evidence(&format!("{why} {phrase}"))
                        .scope(&scope)
                        .production(*production),
                );
            };
            if caps.deploy {
                push(EdgeKind::CanDeploy, "RBAC allows creating workloads");
            }
            if caps.read_secrets {
                push(EdgeKind::CanReadSecret, "RBAC allows reading secrets");
            }
            if caps.create_credentials {
                push(
                    EdgeKind::CanCreateCredential,
                    "RBAC allows creating secrets or service account tokens",
                );
            }
            if caps.modify_config {
                push(
                    EdgeKind::CanModifyConfiguration,
                    "RBAC allows changing configmaps, services or ingresses",
                );
            }
        }
    }
}

/// "namespace a" or "namespaces a, b, c".
fn namespaces_phrase(names: &[String]) -> String {
    if names.len() == 1 {
        format!("namespace {}", names[0])
    } else {
        format!("namespaces {}", names.join(", "))
    }
}

/// Why a Kubernetes denial is not complete, as phrases naming each gap.
/// Empty when nothing was missed.
fn coverage_gaps(
    unchecked: &[(String, String)],
    coverage: &KubeCoverage,
    cluster_wide: bool,
) -> Vec<String> {
    let mut gaps: Vec<String> = unchecked
        .iter()
        .map(|(ns, why)| format!("namespace {ns} {why}"))
        .collect();
    if coverage.listed.is_none() {
        gaps.push(
            "other namespaces not checked (the namespace list is not readable with this context)"
                .into(),
        );
    }
    if !cluster_wide {
        gaps.push("cluster scope not checked".into());
    }
    gaps
}

fn verify_vault(d: &mut Discovered, env: &BTreeMap<String, String>) -> Result<Checked, String> {
    let binding = vault_binding(&d.credential.location, &found_path(d, env));
    let out = run_bound_ok("vault", &["token", "lookup", "-format=json"], &binding, env)?;
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|_| "unexpected vault output")?;
    d.credential.evidence.push(binding.evidence.clone());
    let data = &v["data"];
    let policies: Vec<String> = data["policies"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    d.credential.permissions.assurance = Assurance::Confirmed;
    d.credential.permissions.revoked = Capability::No;
    d.credential.permissions.identity = data["display_name"].as_str().map(|s| s.to_string());
    d.credential.permissions.scope = policies.iter().map(|p| format!("policy {p}")).collect();
    if policies.iter().any(|p| p == "root") {
        // The lookup names the policies; it does not evaluate them, so what
        // they grant is inferred.
        let p = &mut d.credential.permissions;
        p.infer(Permission::Administrative, Capability::Yes);
        p.infer(Permission::CreateCredentials, Capability::Yes);
        p.infer(Permission::ModifyOwnPermissions, Capability::Yes);
        d.credential.evidence.push(
            "root policy attached: administrative access inferred from the policy name; capabilities were not checked with vault token capabilities"
                .into(),
        );
    }
    if let Some(ttl) = data["ttl"].as_u64() {
        d.credential.permissions.lifetime = if ttl == 0 {
            Lifetime::LongLived
        } else {
            Lifetime::ExpiresAt(hedgehog_taint::authority::now_unix() + ttl)
        };
    }
    // Token lookup proves the token is valid and who it is; it says nothing
    // about which secret paths the token can read, so the secret-reading
    // links stay inferred until `vault token capabilities <path>` is checked.
    d.credential.evidence.push(
        "token lookup succeeded: identity and validity confirmed; secret read access not checked (stays inferred)"
            .into(),
    );
    Ok(Checked::new(
        VerificationStatus::IdentityConfirmed,
        "vault token lookup: the provider confirmed the token and its identity; secret read access not checked",
    ))
}

/// Hosts in ~/.ssh/config with an explicit HostName, as (alias, address),
/// so a droplet listed by its public address can be matched to the alias the
/// SSH key finding already uses.
fn ssh_aliases(env: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let home = env
        .get("HOME")
        .or_else(|| env.get("USERPROFILE"))
        .cloned()
        .or_else(|| std::env::var("HOME").ok())
        .or_else(|| std::env::var("USERPROFILE").ok());
    let Some(home) = home else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(std::path::Path::new(&home).join(".ssh/config")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut alias: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            alias = (!name.is_empty() && !name.contains('*') && !name.contains('?')).then(|| {
                line[5..]
                    .trim()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_string()
            });
        } else if lower.starts_with("hostname ") {
            if let (Some(a), Some(addr)) = (alias.as_ref(), line.split_whitespace().nth(1)) {
                out.push((a.clone(), addr.to_string()));
            }
        }
    }
    out
}

fn looks_production_tag(tags: &serde_json::Value) -> bool {
    tags.as_array()
        .map(|a| {
            a.iter().filter_map(|t| t.as_str()).any(|t| {
                let t = t.to_ascii_lowercase();
                t == "prod" || t == "production" || t.starts_with("prod-") || t.ends_with("-prod")
            })
        })
        .unwrap_or(false)
}

/// The environment variable doctl reads a token from.
const DOCTL_TOKEN_VAR: &str = "DIGITALOCEAN_ACCESS_TOKEN";
/// doctl's own environment override for `--context`.
const DOCTL_CONTEXT_VAR: &str = "DIGITALOCEAN_CONTEXT";

/// How a doctl call is tied to exactly the credential under test.
///
/// doctl picks a token in this order: `DIGITALOCEAN_ACCESS_TOKEN`, then the
/// token of the selected context (`--context`, `DIGITALOCEAN_CONTEXT`, or
/// the `context:` key of its config file), then the config's default
/// token. Left to itself it may therefore confirm a different credential
/// from the one Gorse found: an environment token is shadowed by nothing,
/// but a config context is shadowed by any token in the environment, and
/// an environment token's check would silently fall through to a saved
/// context if the variable were empty. So every call pins both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctlBinding {
    /// Arguments placed before the subcommand on every call.
    pub args: Vec<String>,
    /// Variables set in the child's environment, by name; the value is
    /// taken from the verification environment, never written here.
    pub env_from: Vec<(String, String)>,
    /// Variables removed from the child's environment.
    pub env_remove: Vec<String>,
    /// What the evidence line records about the binding.
    pub evidence: String,
}

/// Build the binding for a verification key, as a pure function.
///
/// * `env:<VAR>`: the token is in `VAR`. doctl runs with `--config
///   <empty_config>` (an empty, user-only temporary file) so no saved
///   context exists to be selected, `DIGITALOCEAN_CONTEXT` is removed, and
///   `DIGITALOCEAN_ACCESS_TOKEN` is set from `VAR` in the child's
///   environment. The token is never an argument.
/// * `<context>`: a named context in the doctl config file at
///   `config_path`. doctl runs with `--config <config_path> --context
///   <context>`, with `DIGITALOCEAN_ACCESS_TOKEN` and `DIGITALOCEAN_CONTEXT`
///   removed so nothing in the environment can override the context's
///   token.
pub fn doctl_binding(key: &str, config_path: &Path, empty_config: &Path) -> DoctlBinding {
    if let Some(var) = key.strip_prefix("env:") {
        DoctlBinding {
            args: vec!["--config".into(), empty_config.display().to_string()],
            env_from: vec![(DOCTL_TOKEN_VAR.to_string(), var.to_string())],
            env_remove: vec![DOCTL_CONTEXT_VAR.to_string()],
            evidence: format!(
                "doctl was bound to the token in {var}: run with an empty config file so no saved context could be selected, the token passed in the environment only"
            ),
        }
    } else {
        DoctlBinding {
            args: vec![
                "--config".into(),
                config_path.display().to_string(),
                "--context".into(),
                key.to_string(),
            ],
            env_from: Vec::new(),
            env_remove: vec![DOCTL_TOKEN_VAR.to_string(), DOCTL_CONTEXT_VAR.to_string()],
            evidence: format!(
                "doctl was bound to context {key} of {}: run with --config and --context, with any token in the environment removed",
                config_path.display()
            ),
        }
    }
}

/// An empty doctl config file, created user-only and removed on drop, so
/// an environment-token check can run with no saved context in reach.
struct EmptyConfig {
    path: PathBuf,
}

impl EmptyConfig {
    fn create() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "gorse-doctl-empty-{}-{}.yaml",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&path)
            .map_err(|e| format!("cannot create an empty doctl config: {e}"))?;
        Ok(Self { path })
    }
}

impl Drop for EmptyConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `~/`-relative display paths back to absolute, using the verification
/// environment's home.
fn expand_home(location: &str, env: &BTreeMap<String, String>) -> PathBuf {
    if let Some(rest) = location.strip_prefix("~/") {
        let home = env
            .get("HOME")
            .or_else(|| env.get("USERPROFILE"))
            .cloned()
            .or_else(|| std::env::var("HOME").ok())
            .or_else(|| std::env::var("USERPROFILE").ok());
        if let Some(home) = home {
            return Path::new(&home).join(rest);
        }
    }
    PathBuf::from(location)
}

/// DigitalOcean, through doctl, read-only. `account get` confirms the token
/// is live and whose it is. The listings say what the account holds, so the
/// graph can connect the token to the droplets, clusters, databases,
/// registry and apps behind it. Nothing here proves the token's scope: the
/// API does not report it and no write is attempted, so "administrative"
/// stays unknown and every resource edge stays inferred. Databases and apps
/// are listed as text columns, because their JSON forms carry connection
/// passwords and environment values that must never enter this process.
///
/// Every call is pinned to the credential under test (see
/// [`doctl_binding`]) so a named active context or a stray environment
/// token can never answer for it.
fn verify_digitalocean(
    d: &mut Discovered,
    key: &str,
    decl: &super::config::Declarations,
    env: &BTreeMap<String, String>,
) -> Result<Checked, String> {
    let config_path = expand_home(
        d.credential
            .location
            .split(" (")
            .next()
            .unwrap_or(&d.credential.location),
        env,
    );
    let empty = if key.starts_with("env:") {
        Some(EmptyConfig::create()?)
    } else {
        None
    };
    let binding = doctl_binding(
        key,
        &config_path,
        empty
            .as_ref()
            .map(|e| e.path.as_path())
            .unwrap_or(Path::new("")),
    );
    let mut env = env.clone();
    for (name, from) in &binding.env_from {
        match env.get(from).cloned() {
            Some(value) => {
                env.insert(name.clone(), value);
            }
            None => return Err(format!("{from} is not set in this environment")),
        }
    }
    let remove: Vec<&str> = binding
        .env_remove
        .iter()
        .map(String::as_str)
        .filter(|name| !binding.env_from.iter().any(|(set, _)| set == name))
        .collect();
    for name in &remove {
        env.remove(*name);
    }
    let run = |args: &[&str]| -> Result<String, String> {
        let mut all: Vec<&str> = binding.args.iter().map(String::as_str).collect();
        all.extend_from_slice(args);
        let out = run_cli_raw_bound("doctl", &all, &env, &remove)?;
        if !out.success {
            return Err(format!(
                "{} exited with an error: {}",
                command_label("doctl", &all),
                out.stderr_first
            ));
        }
        Ok(out.stdout)
    };

    let out = run(&["account", "get", "-o", "json"])?;
    d.credential.evidence.push(binding.evidence.clone());
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|_| "unexpected doctl output")?;
    let perms = &mut d.credential.permissions;
    perms.assurance = Assurance::Confirmed;
    perms.identity = v["email"].as_str().map(|s| s.to_string());
    perms.organization = v["team"]["name"].as_str().map(|s| s.to_string());
    let status = v["status"].as_str().unwrap_or("unknown");
    perms.revoked = if status == "active" {
        Capability::No
    } else {
        Capability::Unknown
    };
    d.credential.evidence.push(format!(
        "account get succeeded (status {status}): the token is live and the identity confirmed; the API does not report a token's scope and no write was attempted, so whether it can change anything stays unknown"
    ));

    let mut counts: Vec<String> = Vec::new();

    // Projects: only to learn which ones the account calls Production.
    match run(&["projects", "list", "-o", "json"]) {
        Ok(out) => {
            let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
            for p in v.as_array().cloned().unwrap_or_default() {
                let name = p["name"].as_str().unwrap_or("?");
                let environment = p["environment"].as_str().unwrap_or("");
                d.credential.permissions.scope.push(format!(
                    "project {name}{}",
                    if environment.is_empty() {
                        String::new()
                    } else {
                        format!(" ({environment})")
                    }
                ));
                if environment.eq_ignore_ascii_case("production") {
                    // The account has a Production project; whether this
                    // token can reach it is not reported, so it is inferred.
                    d.credential
                        .permissions
                        .infer(Permission::AccessProduction, Capability::Yes);
                    d.credential.evidence.push(format!(
                        "project {name} is marked Production: production access inferred from the project's environment; the token's scope is not reported"
                    ));
                }
            }
        }
        Err(e) => d
            .credential
            .evidence
            .push(format!("projects not listed: {e}")),
    }

    // Droplets: a token with write scope can power them off, snapshot them
    // and reset the root password, which is a shell. Scope is unknown, so
    // the edge is inferred.
    let aliases = ssh_aliases(&env);
    match run(&["compute", "droplet", "list", "-o", "json"]) {
        Ok(out) => {
            let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
            let droplets = v.as_array().cloned().unwrap_or_default();
            counts.push(format!(
                "{} droplet{}",
                droplets.len(),
                plural(droplets.len())
            ));
            for droplet in droplets {
                let name = droplet["name"].as_str().unwrap_or("?").to_string();
                let region = droplet["region"]["slug"].as_str().unwrap_or("?");
                let public_ip = droplet["networks"]["v4"]
                    .as_array()
                    .and_then(|nets| {
                        nets.iter()
                            .find(|n| n["type"].as_str() == Some("public"))
                            .and_then(|n| n["ip_address"].as_str())
                    })
                    .unwrap_or("no public address")
                    .to_string();
                let production = decl.is_production_name(&name)
                    || looks_production_tag(&droplet["tags"])
                    || aliases
                        .iter()
                        .any(|(a, addr)| *addr == public_ip && decl.is_production_name(a));
                d.links.push(
                    Link::new(
                        NodeKind::ProductionService,
                        &name,
                        EdgeKind::CanModifyConfiguration,
                        Assurance::Inferred,
                    )
                    .evidence(&format!(
                        "droplet {name} ({public_ip}, {region}) listed by this token; with write scope it can be powered off, snapshotted or have its root password reset"
                    ))
                    .production(production),
                );
                for (alias, addr) in aliases.iter().filter(|(_, addr)| *addr == public_ip) {
                    d.links.push(
                        Link::new(
                            NodeKind::ProductionService,
                            alias,
                            EdgeKind::CanModifyConfiguration,
                            Assurance::Inferred,
                        )
                        .evidence(&format!(
                            "droplet {name} is Host {alias} in ~/.ssh/config ({addr})"
                        ))
                        .production(production || decl.is_production_name(alias)),
                    );
                }
                for host in [name.as_str(), public_ip.as_str()] {
                    declared_links(d, decl, host, EdgeKind::CanModifyConfiguration);
                }
            }
        }
        Err(e) => d
            .credential
            .evidence
            .push(format!("droplets not listed: {e}")),
    }

    // Kubernetes: the cluster's admin kubeconfig is served by a read
    // endpoint (kubernetes:read), so any scope of this token mints
    // cluster-admin. The node name matches what `doctl kubernetes cluster
    // kubeconfig save` writes, so an existing kubeconfig finding joins it.
    match run(&["kubernetes", "cluster", "list", "-o", "json"]) {
        Ok(out) => {
            let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
            let clusters = v.as_array().cloned().unwrap_or_default();
            counts.push(format!(
                "{} Kubernetes cluster{}",
                clusters.len(),
                plural(clusters.len())
            ));
            for cluster in clusters {
                let name = cluster["name"].as_str().unwrap_or("?").to_string();
                let region = cluster["region"].as_str().unwrap_or("?");
                let node = format!("do-{region}-{name}");
                let production = decl.is_production_name(&name)
                    || decl.is_production_name(&node)
                    || looks_production_tag(&cluster["tags"]);
                d.links.push(
                    Link::new(
                        NodeKind::Cluster,
                        &node,
                        EdgeKind::CanCreateCredential,
                        Assurance::Inferred,
                    )
                    .evidence(&format!(
                        "cluster {name} ({region}) listed by this token; its admin kubeconfig comes from a read endpoint, so even a read-only token obtains cluster-admin (inferred from the API's design, not exercised)"
                    ))
                    .production(production),
                );
                declared_links(d, decl, &name, EdgeKind::CanDeploy);
            }
        }
        Err(e) => d
            .credential
            .evidence
            .push(format!("Kubernetes clusters not listed: {e}")),
    }

    // Databases, as text columns: the JSON form carries the connection
    // password, which must not enter this process.
    match run(&[
        "databases",
        "list",
        "--format",
        "ID,Name,Engine,Region,Status",
        "--no-header",
    ]) {
        Ok(out) => {
            let rows: Vec<Vec<&str>> = out
                .lines()
                .map(|l| l.split_whitespace().collect::<Vec<_>>())
                .filter(|cols| cols.len() >= 2)
                .collect();
            counts.push(format!(
                "{} database cluster{}",
                rows.len(),
                plural(rows.len())
            ));
            for cols in rows {
                let name = cols[1].to_string();
                let engine = cols.get(2).copied().unwrap_or("?");
                let region = cols.get(3).copied().unwrap_or("?");
                let production = decl.is_production_name(&name);
                d.links.push(
                    Link::new(
                        NodeKind::ProductionService,
                        &name,
                        EdgeKind::CanReadSecret,
                        Assurance::Inferred,
                    )
                    .evidence(&format!(
                        "database cluster {name} ({engine}, {region}) listed by this token; its connection password is returned by the database read endpoint, which Gorse did not request"
                    ))
                    .production(production),
                );
                declared_links(d, decl, &name, EdgeKind::CanReadSecret);
            }
        }
        Err(e) => d
            .credential
            .evidence
            .push(format!("databases not listed: {e}")),
    }

    match run(&["registry", "get", "-o", "json"]) {
        Ok(out) => {
            let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
            if let Some(name) = v["name"].as_str() {
                counts.push("1 container registry".into());
                d.links.push(
                    Link::new(
                        NodeKind::Registry,
                        name,
                        EdgeKind::CanPushCode,
                        Assurance::Inferred,
                    )
                    .evidence(&format!(
                        "container registry {name} listed by this token; push rights depend on the token's scope, which is unknown"
                    ))
                    .production(decl.is_production_name(name)),
                );
                declared_links(d, decl, name, EdgeKind::CanPushCode);
            }
        }
        Err(e) => d
            .credential
            .evidence
            .push(format!("container registry not read: {e}")),
    }

    // Apps, as text columns: the JSON spec carries environment values.
    match run(&["apps", "list", "--format", "ID,Spec.Name", "--no-header"]) {
        Ok(out) => {
            let rows: Vec<Vec<&str>> = out
                .lines()
                .map(|l| l.split_whitespace().collect::<Vec<_>>())
                .filter(|cols| cols.len() >= 2)
                .collect();
            counts.push(format!("{} app{}", rows.len(), plural(rows.len())));
            for cols in rows {
                let name = cols[1].to_string();
                let production = decl.is_production_name(&name);
                d.links.push(
                    Link::new(
                        NodeKind::ProductionService,
                        &name,
                        EdgeKind::CanDeploy,
                        Assurance::Inferred,
                    )
                    .evidence(&format!(
                        "App Platform app {name} listed by this token; with write scope it can be redeployed with a changed spec"
                    ))
                    .production(production),
                );
                declared_links(d, decl, &name, EdgeKind::CanDeploy);
            }
        }
        Err(e) => d.credential.evidence.push(format!("apps not listed: {e}")),
    }

    if !counts.is_empty() {
        d.credential.evidence.push(format!(
            "the account holds {}; every resource edge is inferred because the token's scope is unknown",
            counts.join(", ")
        ));
    }
    Ok(Checked::new(
        VerificationStatus::IdentityConfirmed,
        "doctl account get: the provider confirmed the identity; the token's scope is not reported, so what it can change is not confirmed",
    ))
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Attach the declared production systems that list `host` among their
/// hosts, the way discovery does for things it finds locally.
fn declared_links(
    d: &mut Discovered,
    decl: &super::config::Declarations,
    host: &str,
    edge: EdgeKind,
) {
    for system in decl.systems_hosting(host) {
        if d.links
            .iter()
            .any(|l| l.name == system.name && l.edge == edge)
        {
            continue;
        }
        d.links.push(
            Link::new(
                NodeKind::ProductionService,
                &system.name,
                edge,
                Assurance::Inferred,
            )
            .evidence(&format!(
                "declared in authority.toml: {} hosts {host}",
                system.name
            ))
            .approval(system.change_approval.clone())
            .production(true),
        );
    }
}

fn verify_gcloud(
    d: &mut Discovered,
    account: &str,
    env: &BTreeMap<String, String>,
) -> Result<Checked, String> {
    let binding = gcloud_binding(account, &found_path(d, env));
    let out = run_bound_ok("gcloud", &["auth", "list", "--format=json"], &binding, env)?;
    d.credential.evidence.push(binding.evidence.clone());
    let v: serde_json::Value =
        serde_json::from_str(&out).map_err(|_| "unexpected gcloud output")?;
    let active = v
        .as_array()
        .map(|a| {
            a.iter().any(|e| {
                e["account"].as_str() == Some(account) && e["status"].as_str() == Some("ACTIVE")
            })
        })
        .unwrap_or(false);
    if active {
        // `gcloud auth list` reports which locally stored account is
        // selected. It does not contact Google, so it proves neither that the
        // credential still works nor what it can do: the account is confirmed
        // to be configured here, validity and roles stay unknown.
        d.credential
            .evidence
            .push("gcloud auth list: account configured and selected locally; validity not checked (no provider call), IAM roles not enumerated".into());
    } else {
        d.credential
            .evidence
            .push("gcloud auth list: account not active".into());
    }
    // No read-only Google call proves identity without printing a token, so
    // this stays local configuration: Google was not asked.
    Ok(Checked::new(
        VerificationStatus::LocalConfig,
        if active {
            "gcloud auth list: account configured and selected locally; Google was not asked"
        } else {
            "gcloud auth list: account not active locally; Google was not asked"
        },
    ))
}

/// What `az role assignment list` does not evaluate, so a role name only
/// suggests what a principal can do.
const AZURE_ROLE_NOTE: &str = "deny assignments, PIM eligibility, conditional access, group-inherited assignments and custom role definitions were not evaluated";

fn verify_azure(
    d: &mut Discovered,
    user: &str,
    decl: &super::config::Declarations,
    env: &BTreeMap<String, String>,
) -> Result<Checked, String> {
    let binding = azure_binding(&d.credential.name, &found_path(d, env));
    let out = run_bound_ok("az", &["account", "show", "-o", "json"], &binding, env)?;
    let v: serde_json::Value = serde_json::from_str(&out).map_err(|_| "unexpected az output")?;
    if v["user"]["name"].as_str() != Some(user) {
        return Err("active az account differs from this subscription's user".into());
    }
    d.credential.evidence.push(binding.evidence.clone());
    // `az account show` reads the local profile (~/.azure): Azure was not
    // asked. Only the role assignment listing below reaches the provider.
    let local = || {
        Checked::new(
            VerificationStatus::LocalConfig,
            "az account show: subscription configured locally; Azure was not asked (role assignments not readable)",
        )
    };
    let Ok(out) = run_bound_ok(
        "az",
        &[
            "role",
            "assignment",
            "list",
            "--assignee",
            user,
            "--all",
            "-o",
            "json",
        ],
        &binding,
        env,
    ) else {
        d.credential
            .evidence
            .push("role assignments not readable: scope stays inferred".into());
        return Ok(local());
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) else {
        d.credential
            .evidence
            .push("role assignments unreadable: scope stays inferred".into());
        return Ok(local());
    };
    // Azure answered for this principal with its stored token: identity.
    // The roles it lists are names; what they grant after deny assignments,
    // PIM and conditional access is not evaluated, so every capability
    // read from them is inferred.
    d.credential.permissions.assurance = Assurance::Confirmed;
    d.credential.permissions.revoked = Capability::No;
    let assignments = v.as_array().cloned().unwrap_or_default();
    if assignments.is_empty() {
        let p = &mut d.credential.permissions;
        p.infer(Permission::AccessProduction, Capability::No);
        p.infer(Permission::ModifyProduction, Capability::No);
        d.credential.evidence.push(format!(
            "az role assignment list: no role assignments were found for this principal, so production access is inferred as no; {AZURE_ROLE_NOTE}"
        ));
        return Ok(Checked::new(
            VerificationStatus::IdentityConfirmed,
            format!(
                "az role assignment list: the provider answered for this principal and no role assignments were found for this principal; production access is inferred as no; {AZURE_ROLE_NOTE}"
            ),
        ));
    }
    for a in &assignments {
        let role = a["roleDefinitionName"].as_str().unwrap_or("?").to_string();
        let scope = a["scope"].as_str().unwrap_or("?").to_string();
        let p = &mut d.credential.permissions;
        p.scope.push(format!("{role} on {scope}"));
        let hint = decl.role_hint(&role);
        let mut inferred: Vec<&str> = Vec::new();
        if role == "Owner"
            || role == "Contributor"
            || hint.map(|h| h.administrative).unwrap_or(false)
        {
            p.infer(Permission::Administrative, Capability::Yes);
            p.infer(Permission::ModifyProduction, Capability::Yes);
            inferred.push("administrative access");
        }
        if role == "Owner" || role == "User Access Administrator" {
            p.infer(Permission::ModifyOwnPermissions, Capability::Yes);
            p.infer(Permission::CreateCredentials, Capability::Yes);
            inferred.push("permission and credential management");
        }
        if !inferred.is_empty() {
            d.credential.evidence.push(redact_text(&format!(
                "role {role} on {scope}: {} inferred from the role name",
                inferred.join(" and ")
            )));
        }
    }
    d.credential.evidence.push(format!(
        "az role assignment list: {} role assignment{} listed; {AZURE_ROLE_NOTE}",
        assignments.len(),
        plural(assignments.len())
    ));
    Ok(Checked::new(
        VerificationStatus::IdentityConfirmed,
        format!(
            "az role assignment list: the provider confirmed the identity and listed {} role assignment{} for this principal; capabilities are inferred from role names; {AZURE_ROLE_NOTE}",
            assignments.len(),
            plural(assignments.len())
        ),
    ))
}

/// JSON-RPC eth_getCode. Read-only; the result is the account's code bytes.
/// The chain's answer is the delegation state itself, so it is the
/// permission-level equivalent for a wallet: the blockchain finding it feeds
/// is confirmed.
pub fn eth_get_code(url: &str, address: &str) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":[address, "latest"]});
    let response = ureq::post(url)
        .timeout(TIMEOUT)
        .set("content-type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| redact_text(&e.to_string()))?;
    let text = response.into_string().map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") {
        return Err(redact_text(&err.to_string()));
    }
    let hex = v["result"].as_str().ok_or("no result")?;
    hedgehog_taint::authority::eip7702::decode_hex(hex).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hedgehog_taint::authority::DiscoveredCredential;

    // ── Stand-in provider tools ──
    // The verification functions shell out to the user's own CLIs. These
    // tests put a tiny script on PATH under the tool's name so the real
    // function runs end to end against canned answers, which is also the
    // only way to prove what a result does and does not claim.
    #[cfg(unix)]
    fn fake_tool(dir: &std::path::Path, name: &str, script: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn fake_env(dir: &std::path::Path) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), dir.display().to_string());
        env
    }

    #[cfg(unix)]
    fn temp_tools(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hedgehog-verify-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn digitalocean_verification_confirms_identity_lists_resources_and_leaves_scope_unknown() {
        // A stand-in doctl answers the read-only listings. The token's
        // identity is confirmed, the droplet, cluster, database, registry
        // and app become inferred edges (the API never reports scope, so no
        // edge is confirmed and "administrative" stays unknown), the droplet
        // is matched to its ~/.ssh/config alias by address, databases and
        // apps are read as text columns so no password enters the process,
        // and the token is never put on a command line.
        let dir = temp_tools("doctl");
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(
            home.join(".ssh/config"),
            "Host prod-api\n  HostName 203.0.113.10\n  User deploy\n",
        )
        .unwrap();
        let log = dir.join("doctl-args.log");
        fake_tool(
            &dir,
            "doctl",
            &format!(
                r#"echo "$@" >> '{log}'
[ -n "$DIGITALOCEAN_ACCESS_TOKEN" ] && echo "env-token-present" >> '{log}'
case "$*" in
  *"account get"*) echo '{{"email":"ops@example.invalid","uuid":"u-1","status":"active","team":{{"name":"Example Co"}}}}';;
  *"projects list"*) echo '[{{"name":"Shop","environment":"Production","is_default":true}}]';;
  *"droplet list"*) echo '[{{"id":1,"name":"api-1","status":"active","tags":["production"],"region":{{"slug":"nyc1"}},"networks":{{"v4":[{{"ip_address":"10.0.0.5","type":"private"}},{{"ip_address":"203.0.113.10","type":"public"}}]}}}}]';;
  *"cluster list"*) echo '[{{"id":"c1","name":"shop","region":"nyc1","tags":[]}}]';;
  *"databases list"*) echo 'db-1    orders-db    pg    nyc1    online';;
  *"registry get"*) echo '{{"name":"example-registry","region":"nyc3"}}';;
  *"apps list"*) echo 'app-1    storefront';;
  *) exit 1;;
esac"#,
                log = log.display()
            ),
        );
        let mut env = fake_env(&dir);
        env.insert("HOME".into(), home.display().to_string());
        let decl = super::super::config::Declarations::default();

        let mut d = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::DigitalOceanToken,
                "staging",
                "~/.config/doctl/config.yaml",
                "DigitalOcean",
            ),
            links: Vec::new(),
            verify_key: Some("staging".into()),
        };
        verify_digitalocean(&mut d, "staging", &decl, &env).unwrap();
        let p = &d.credential.permissions;
        assert_eq!(p.assurance, Assurance::Confirmed);
        assert_eq!(p.identity.as_deref(), Some("ops@example.invalid"));
        assert_eq!(p.organization.as_deref(), Some("Example Co"));
        assert_eq!(p.revoked, Capability::No);
        assert_eq!(
            p.administrative,
            Capability::Unknown,
            "scope is never reported, so admin stays unknown"
        );
        assert_eq!(
            p.can_access_production,
            Capability::Yes,
            "a project called Production"
        );
        assert_eq!(
            p.capability_assurance(Permission::AccessProduction),
            Assurance::Inferred,
            "a project's environment says nothing about this token's scope"
        );
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("production access inferred")),
            "{:?}",
            d.credential.evidence
        );
        assert!(
            p.scope.iter().any(|s| s == "project Shop (Production)"),
            "{:?}",
            p.scope
        );

        let link = |kind: NodeKind, name: &str, edge: EdgeKind| {
            d.links
                .iter()
                .find(|l| l.kind == kind && l.name == name && l.edge == edge)
                .unwrap_or_else(|| {
                    panic!(
                        "no {kind:?} {name} {edge:?} in {:?}",
                        d.links
                            .iter()
                            .map(|l| (&l.name, l.edge))
                            .collect::<Vec<_>>()
                    )
                })
        };
        let droplet = link(
            NodeKind::ProductionService,
            "api-1",
            EdgeKind::CanModifyConfiguration,
        );
        assert!(droplet.production, "tagged production");
        let alias = link(
            NodeKind::ProductionService,
            "prod-api",
            EdgeKind::CanModifyConfiguration,
        );
        assert!(
            alias
                .evidence
                .iter()
                .any(|e| e.contains("droplet api-1 is Host prod-api")),
            "{:?}",
            alias.evidence
        );
        let cluster = link(
            NodeKind::Cluster,
            "do-nyc1-shop",
            EdgeKind::CanCreateCredential,
        );
        assert!(
            cluster
                .evidence
                .iter()
                .any(|e| e.contains("read-only token obtains cluster-admin")),
            "{:?}",
            cluster.evidence
        );
        link(
            NodeKind::ProductionService,
            "orders-db",
            EdgeKind::CanReadSecret,
        );
        link(
            NodeKind::Registry,
            "example-registry",
            EdgeKind::CanPushCode,
        );
        link(
            NodeKind::ProductionService,
            "storefront",
            EdgeKind::CanDeploy,
        );
        assert!(
            d.links.iter().all(|l| l.assurance == Assurance::Inferred),
            "no resource edge may be confirmed"
        );
        assert!(
            d.credential.evidence.iter().any(|e| e.contains(
                "1 droplet, 1 Kubernetes cluster, 1 database cluster, 1 container registry, 1 app"
            )),
            "{:?}",
            d.credential.evidence
        );

        let calls = std::fs::read_to_string(&log).unwrap();
        let config = home.join(".config/doctl/config.yaml").display().to_string();
        assert!(
            calls
                .lines()
                .all(|l| l.starts_with(&format!("--config {config} --context staging "))),
            "every call is pinned to the context's own config file: {calls}"
        );
        assert!(!calls.contains("--access-token"), "{calls}");
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("bound to context staging")),
            "{:?}",
            d.credential.evidence
        );
        let db_call = calls
            .lines()
            .find(|l| l.contains("databases list"))
            .unwrap();
        assert!(
            db_call.contains("--format") && !db_call.contains("json"),
            "{db_call}"
        );
        let app_call = calls.lines().find(|l| l.contains("apps list")).unwrap();
        assert!(
            app_call.contains("--format") && !app_call.contains("json"),
            "{app_call}"
        );
        for verb in [
            "delete",
            "create",
            "update",
            "power",
            "reset",
            "kubeconfig save",
        ] {
            assert!(
                !calls.contains(verb),
                "a write verb was used: {verb} in {calls}"
            );
        }
        assert!(!calls.contains("env-token-present"));

        // A token from the environment is handed to doctl under the name it
        // reads, in the environment, with no --context and nothing on argv.
        std::fs::remove_file(&log).unwrap();
        let mut env_cred = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::DigitalOceanToken,
                "DIGITALOCEAN_TOKEN",
                "env DIGITALOCEAN_TOKEN",
                "DigitalOcean",
            ),
            links: Vec::new(),
            verify_key: Some("env:DIGITALOCEAN_TOKEN".into()),
        };
        env.insert("DIGITALOCEAN_TOKEN".into(), "dop_v1_fixture".into());
        // A saved context in the environment must not be able to answer
        // for the environment token.
        env.insert("DIGITALOCEAN_CONTEXT".into(), "staging".into());
        fake_tool(
            &dir,
            "doctl",
            &format!(
                r#"echo "$@" >> '{log}'
[ -n "$DIGITALOCEAN_ACCESS_TOKEN" ] && echo "env-token-present" >> '{log}'
[ -n "$DIGITALOCEAN_CONTEXT" ] && echo "context-var-present" >> '{log}'
for a in "$@"; do case "$prev" in --config) [ -f "$a" ] && [ ! -s "$a" ] && echo "config-empty" >> '{log}';; esac; prev="$a"; done
case "$*" in
  *"account get"*) echo '{{"email":"ops@example.invalid","uuid":"u-1","status":"active","team":{{"name":"Example Co"}}}}';;
  *) exit 1;;
esac"#,
                log = log.display()
            ),
        );
        verify_digitalocean(&mut env_cred, "env:DIGITALOCEAN_TOKEN", &decl, &env).unwrap();
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(calls.contains("env-token-present"), "{calls}");
        assert!(!calls.contains("context-var-present"), "{calls}");
        assert!(
            calls.contains("config-empty"),
            "an empty config file was passed: {calls}"
        );
        assert!(
            !calls.contains("--context") && !calls.contains("dop_v1_fixture"),
            "{calls}"
        );
        assert!(
            calls
                .lines()
                .all(|l| !l.starts_with("--config ") || l.contains("gorse-doctl-empty-")),
            "{calls}"
        );
        assert_eq!(
            env_cred.credential.permissions.assurance,
            Assurance::Confirmed
        );
        assert!(env_cred
            .credential
            .evidence
            .iter()
            .any(|e| e.contains("bound to the token in DIGITALOCEAN_TOKEN")));
        // The empty config was removed afterwards.
        let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("gorse-doctl-empty-{}-", std::process::id()))
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn doctl_binding_pins_the_credential_under_test() {
        let config = Path::new("/home/u/.config/doctl/config.yaml");
        let empty = Path::new("/tmp/gorse-doctl-empty-1.yaml");
        let env = doctl_binding("env:DIGITALOCEAN_TOKEN", config, empty);
        assert_eq!(env.args, ["--config", "/tmp/gorse-doctl-empty-1.yaml"]);
        assert_eq!(
            env.env_from,
            [(
                "DIGITALOCEAN_ACCESS_TOKEN".to_string(),
                "DIGITALOCEAN_TOKEN".to_string()
            )]
        );
        assert_eq!(env.env_remove, ["DIGITALOCEAN_CONTEXT"]);
        assert!(env.evidence.contains("empty config"), "{}", env.evidence);
        assert!(
            !env.args.iter().any(|a| a.contains("token")),
            "no token on argv"
        );
        // The native variable: set from itself, nothing else.
        let native = doctl_binding("env:DIGITALOCEAN_ACCESS_TOKEN", config, empty);
        assert_eq!(
            native.env_from,
            [(
                "DIGITALOCEAN_ACCESS_TOKEN".to_string(),
                "DIGITALOCEAN_ACCESS_TOKEN".to_string()
            )]
        );

        let context = doctl_binding("staging", config, empty);
        assert_eq!(
            context.args,
            [
                "--config",
                "/home/u/.config/doctl/config.yaml",
                "--context",
                "staging"
            ]
        );
        assert!(context.env_from.is_empty());
        assert_eq!(
            context.env_remove,
            ["DIGITALOCEAN_ACCESS_TOKEN", "DIGITALOCEAN_CONTEXT"]
        );
        assert!(
            context.evidence.contains("context staging"),
            "{}",
            context.evidence
        );
        assert!(!context.args.iter().any(|a| a.contains("empty")));
    }

    #[cfg(unix)]
    #[test]
    fn aws_read_only_policy_does_not_prove_not_administrative() {
        let dir = temp_tools("aws");
        fake_tool(
            &dir,
            "aws",
            r#"case "$*" in
  *get-caller-identity*) echo '{"Arn":"arn:aws:iam::123456789012:user/alice","Account":"123456789012"}';;
  *list-attached-user-policies*) echo '{"AttachedPolicies":[{"PolicyName":"ReadOnlyAccess"}]}';;
  *) exit 1;;
esac"#,
        );
        let mut d = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::AwsAccessKey,
                "default",
                "~/.aws/credentials",
                "AWS",
            ),
            links: vec![],
            verify_key: None,
        };
        verify_aws(
            &mut d,
            "default",
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        )
        .unwrap();
        assert_eq!(
            d.credential.permissions.assurance,
            Assurance::Confirmed,
            "identity is confirmed"
        );
        assert_eq!(
            d.credential.permissions.administrative,
            Capability::Unknown,
            "a read-only managed policy says nothing about group or inline policies: {:?}",
            d.credential.evidence
        );
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("administrative access stays unknown")),
            "{:?}",
            d.credential.evidence
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn vault_token_lookup_confirms_identity_not_secret_access() {
        let dir = temp_tools("vault");
        fake_tool(
            &dir,
            "vault",
            r#"echo '{"data":{"display_name":"token-alice","policies":["default","app-read"],"ttl":3600}}'"#,
        );
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".vault-token"), "hvs.saved-token\n").unwrap();
        let mut env = fake_env(&dir);
        env.insert("HOME".into(), home.display().to_string());
        let mut d = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::VaultToken,
                "token",
                "~/.vault-token",
                "Vault",
            ),
            links: vec![Link::new(
                NodeKind::SecretsManager,
                "vault",
                EdgeKind::CanReadSecret,
                Assurance::Inferred,
            )],
            verify_key: None,
        };
        verify_vault(&mut d, &env).unwrap();
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);
        assert_eq!(
            d.credential.permissions.revoked,
            Capability::No,
            "lookup proves the token is live"
        );
        assert_eq!(
            d.links[0].assurance,
            Assurance::Inferred,
            "reading secrets was never checked, so the link stays inferred"
        );
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("secret read access not checked")),
            "{:?}",
            d.credential.evidence
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn gcloud_auth_list_is_local_configuration_not_validity() {
        let dir = temp_tools("gcloud");
        fake_tool(
            &dir,
            "gcloud",
            r#"echo '[{"account":"alice@example.com","status":"ACTIVE"}]'"#,
        );
        let mut d = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GcpUserCredential,
                "alice@example.com",
                "~/.config/gcloud",
                "Google Cloud",
            ),
            links: vec![],
            verify_key: None,
        };
        d.credential.permissions.assurance = Assurance::Inferred;
        verify_gcloud(&mut d, "alice@example.com", &fake_env(&dir)).unwrap();
        assert_ne!(
            d.credential.permissions.assurance,
            Assurance::Confirmed,
            "auth list never contacts Google"
        );
        assert_eq!(
            d.credential.permissions.revoked,
            Capability::Unknown,
            "validity was not checked"
        );
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("validity not checked")),
            "{:?}",
            d.credential.evidence
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const CAN_I: &str = "Resources                                       Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
deployments.apps                                []                  []               [get list create update patch]
secrets                                         []                  []               [get list]
configmaps                                      []                  []               [get]
                                                [/healthz]          []               [get]
";

    /// `gh auth status` for a classic token with the `repo` scope.
    const GH_CLASSIC_REPO: &str = "github.com
  ✓ Logged in to github.com account alice (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org', 'repo', 'workflow'
";

    /// A classic token whose scopes do not include `repo`.
    const GH_CLASSIC_NO_REPO: &str = "github.com
  ✓ Logged in to github.com account alice (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org'
";

    /// A fine-grained token: gh shows the prefix and lists no classic scopes.
    const GH_FINE_GRAINED: &str = "github.com
  ✓ Logged in to github.com account alice (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: github_pat_********************************
  - Token scopes: none
";

    fn github_fixture() -> Discovered {
        Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                "gh login github.com",
                "~/.config/gh/hosts.yml",
                "github.com",
            ),
            links: vec![
                Link::new(
                    NodeKind::Repository,
                    "github.com repositories",
                    EdgeKind::CanPushCode,
                    Assurance::Inferred,
                ),
                Link::new(
                    NodeKind::CiSystem,
                    "payments-api",
                    EdgeKind::CanPushCode,
                    Assurance::Inferred,
                )
                .production(true),
            ],
            verify_key: Some("github.com".into()),
        }
    }

    fn push_edges(d: &Discovered) -> Vec<&Link> {
        d.links
            .iter()
            .filter(|l| l.edge == EdgeKind::CanPushCode)
            .collect()
    }

    #[test]
    fn gh_status_parser_reads_scopes_account_and_token_type() {
        let s = parse_gh_auth_status(GH_CLASSIC_REPO);
        assert!(s.logged_in);
        assert_eq!(s.account.as_deref(), Some("alice"));
        assert_eq!(s.scopes, ["gist", "read:org", "repo", "workflow"]);
        assert!(!s.fine_grained);

        let f = parse_gh_auth_status(GH_FINE_GRAINED);
        assert!(f.logged_in);
        assert!(f.scopes.is_empty(), "'none' is not a scope");
        assert!(f.fine_grained);

        let none = parse_gh_auth_status("You are not logged into any GitHub hosts.");
        assert!(!none.logged_in);
    }

    #[test]
    fn fine_grained_token_leaves_write_capability_unknown() {
        let mut d = github_fixture();
        apply_gh_auth_status(&mut d, &parse_gh_auth_status(GH_FINE_GRAINED), "github.com");
        cap_links_to_credential(&mut d);
        // The login (identity) is confirmed; no capability is.
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);
        assert!(d.credential.permissions.confirmed.is_empty());
        assert_eq!(d.credential.permissions.revoked, Capability::No);
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::Unknown
        );
        assert_eq!(
            push_edges(&d).len(),
            2,
            "write edges are kept, not rewritten"
        );
        assert!(
            d.links.iter().all(|l| l.assurance != Assurance::Confirmed),
            "nothing is confirmed from a fine-grained login: {:?}",
            d.links
        );
        assert!(
            !d.links.iter().any(|l| l.edge == EdgeKind::CanReadSecret),
            "no edge was converted to confirmed read-only"
        );
    }

    #[test]
    fn classic_token_with_repo_scope_infers_write() {
        // Scopes say what a classic token carries, not what it may do on any
        // repository: identity is confirmed, every edge read from a scope
        // is inferred and says where it came from.
        let mut d = github_fixture();
        apply_gh_auth_status(&mut d, &parse_gh_auth_status(GH_CLASSIC_REPO), "github.com");
        cap_links_to_credential(&mut d);
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);
        assert_eq!(d.credential.permissions.identity.as_deref(), Some("alice"));
        let pushes = push_edges(&d);
        assert_eq!(pushes.len(), 2);
        assert!(pushes.iter().all(|l| l.assurance == Assurance::Inferred));
        assert!(pushes.iter().all(|l| l
            .evidence
            .iter()
            .any(|e| e.contains("inferred from the token scope"))));
        assert!(d
            .links
            .iter()
            .any(|l| l.edge == EdgeKind::CanModifyConfiguration
                && l.name.contains("Actions workflows")
                && l.assurance == Assurance::Inferred));
    }

    #[test]
    fn github_admin_scope_gives_inferred_admin() {
        let mut d = github_fixture();
        apply_gh_auth_status(
            &mut d,
            &parse_gh_auth_status(
                "github.com\n  Logged in to github.com account alice (keyring)\n  Token: gho_****\n  Token scopes: 'repo', 'admin:org'\n",
            ),
            "github.com",
        );
        settle_assurance(
            &mut d,
            Assurance::Inferred,
            VerificationStatus::IdentityConfirmed,
        );
        let p = &d.credential.permissions;
        assert_eq!(p.assurance, Assurance::Confirmed, "identity");
        assert_eq!(p.administrative, Capability::Yes);
        assert_eq!(
            p.capability_assurance(Permission::Administrative),
            Assurance::Inferred
        );
        assert!(d
            .credential
            .evidence
            .iter()
            .any(|e| e.contains("admin:org") && e.contains("inferred")));
        let decl = crate::exposure::config::Declarations::default();
        let found = vec![d];
        let (graph, _laptop, nodes) = crate::exposure::build_graph(&found, &decl);
        let paths = graph.paths_to_kind(nodes[0], NodeKind::Repository, 4);
        let f =
            hedgehog_taint::authority::scoring::score_finding(&graph, &found[0].credential, &paths);
        assert_eq!(f.confidence, Assurance::Inferred);
    }

    #[test]
    fn classic_token_without_repo_scope_does_not_confirm_read_only() {
        let mut d = github_fixture();
        apply_gh_auth_status(
            &mut d,
            &parse_gh_auth_status(GH_CLASSIC_NO_REPO),
            "github.com",
        );
        cap_links_to_credential(&mut d);
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);
        assert!(
            !d.links.iter().any(|l| l.edge == EdgeKind::CanReadSecret),
            "a missing scope must not become a confirmed read-only edge"
        );
        let pushes = push_edges(&d);
        assert_eq!(pushes.len(), 2);
        assert!(
            pushes.iter().all(|l| l.assurance == Assurance::Inferred),
            "write edges stay at their discovery assurance"
        );
        assert!(pushes
            .iter()
            .all(|l| l.evidence.iter().any(|e| e.contains("not confirmed"))));
    }

    fn repo(name: &str, access: RepoAccess) -> (String, RepoAccess) {
        (name.to_string(), access)
    }

    fn system_links<'a>(d: &'a Discovered, system: &str) -> Vec<&'a Link> {
        d.links
            .iter()
            .filter(|l| l.kind == NodeKind::CiSystem && l.name == system)
            .collect()
    }

    #[test]
    fn repo_access_reads_the_permissions_object() {
        let perms = |v: serde_json::Value| RepoAccess::from_permissions(&v);
        assert_eq!(
            perms(serde_json::json!({"admin": true, "push": true, "pull": true})),
            RepoAccess::Write { admin: true }
        );
        assert_eq!(
            perms(serde_json::json!({"admin": false, "push": true, "pull": true})),
            RepoAccess::Write { admin: false }
        );
        assert_eq!(
            perms(serde_json::json!({"push": false, "pull": true})),
            RepoAccess::ReadOnly
        );
        assert_eq!(
            perms(serde_json::json!({"push": false, "pull": false})),
            RepoAccess::Visible
        );
        assert_eq!(perms(serde_json::Value::Null), RepoAccess::NoPermissions);
    }

    #[test]
    fn repository_check_settles_a_declared_repo_edge() {
        // Fine-grained token: only the per-repository answer can confirm.
        let mut d = github_fixture();
        apply_gh_auth_status(&mut d, &parse_gh_auth_status(GH_FINE_GRAINED), "github.com");
        apply_repo_access(
            &mut d,
            "payments-api",
            &[repo("acme/payments", RepoAccess::Write { admin: false })],
        );
        cap_links_to_credential(&mut d);
        let declared = system_links(&d, "payments-api");
        assert_eq!(declared.len(), 1, "{declared:?}");
        assert_eq!(declared[0].edge, EdgeKind::CanPushCode);
        assert_eq!(declared[0].assurance, Assurance::Confirmed);
        assert_eq!(
            declared[0].scope.as_deref(),
            Some("repository acme/payments")
        );
        assert!(declared[0].production, "production flag is inherited");
        let generic = d
            .links
            .iter()
            .find(|l| l.name == "github.com repositories")
            .unwrap();
        assert_eq!(
            generic.assurance,
            Assurance::Inferred,
            "unchecked repos stay inferred"
        );
        assert!(d
            .credential
            .permissions
            .scope
            .contains(&"acme/payments: write".to_string()));

        // Read-only on that repository is the one confirmed "no write".
        let mut d = github_fixture();
        apply_gh_auth_status(
            &mut d,
            &parse_gh_auth_status(GH_CLASSIC_NO_REPO),
            "github.com",
        );
        apply_repo_access(
            &mut d,
            "payments-api",
            &[repo("acme/payments", RepoAccess::ReadOnly)],
        );
        let declared = system_links(&d, "payments-api");
        assert_eq!(declared.len(), 1, "{declared:?}");
        assert_eq!(declared[0].edge, EdgeKind::CanReadSecret);
        assert_eq!(declared[0].assurance, Assurance::Confirmed);

        // No permissions object: nothing changes but the note.
        let mut d = github_fixture();
        apply_repo_access(
            &mut d,
            "payments-api",
            &[repo("acme/payments", RepoAccess::NoPermissions)],
        );
        let pushes = push_edges(&d);
        assert_eq!(pushes.len(), 2);
        assert!(pushes.iter().all(|l| l.assurance == Assurance::Inferred));
        assert_eq!(d.credential.permissions.assurance, Assurance::Unknown);
        assert!(d
            .credential
            .evidence
            .iter()
            .any(|e| e.contains("not checked: acme/payments (no permissions object")));
    }

    #[test]
    fn repository_results_do_not_depend_on_map_order() {
        let writable = repo("acme/payments", RepoAccess::Write { admin: false });
        let read_only = repo("acme/docs", RepoAccess::ReadOnly);
        let run = |repos: &[(String, RepoAccess)]| {
            let mut d = github_fixture();
            apply_gh_auth_status(&mut d, &parse_gh_auth_status(GH_FINE_GRAINED), "github.com");
            apply_repo_access(&mut d, "payments-api", repos);
            cap_links_to_credential(&mut d);
            d
        };
        let a = run(&[writable.clone(), read_only.clone()]);
        let b = run(&[read_only, writable]);
        assert_eq!(a.links, b.links, "edges differ with repository order");
        assert_eq!(a.credential.permissions, b.credential.permissions);
        assert_eq!(a.credential.evidence, b.credential.evidence);

        // A confirmed write path is present, and the read-only repository
        // sits beside it instead of overwriting it.
        let system = system_links(&a, "payments-api");
        assert_eq!(system.len(), 2, "{system:?}");
        let write = system
            .iter()
            .find(|l| l.edge == EdgeKind::CanPushCode)
            .expect("confirmed write edge");
        assert_eq!(write.assurance, Assurance::Confirmed);
        assert_eq!(write.scope.as_deref(), Some("repository acme/payments"));
        let read = system
            .iter()
            .find(|l| l.edge == EdgeKind::CanReadSecret)
            .expect("confirmed read-only edge");
        assert_eq!(read.assurance, Assurance::Confirmed);
        assert_eq!(read.scope.as_deref(), Some("repository acme/docs"));
        assert!(
            system.iter().all(|l| l.scope.is_some()),
            "the unscoped guess is retired once write is confirmed"
        );
        assert_eq!(a.credential.permissions.assurance, Assurance::Confirmed);
        assert!(a
            .credential
            .evidence
            .iter()
            .any(|e| e.contains("write on acme/payments") && e.contains("read-only on acme/docs")));

        // Writable repositories in both orders with the generic approval kept.
        let mut d = github_fixture();
        d.links[1].approval = Some("PR review".into());
        apply_repo_access(
            &mut d,
            "payments-api",
            &[repo("acme/payments", RepoAccess::Write { admin: true })],
        );
        let system = system_links(&d, "payments-api");
        assert_eq!(system[0].approval.as_deref(), Some("PR review"));
    }

    #[test]
    fn unreadable_repository_keeps_the_system_inferred_and_names_it() {
        let mut d = github_fixture();
        apply_gh_auth_status(&mut d, &parse_gh_auth_status(GH_FINE_GRAINED), "github.com");
        apply_repo_access(
            &mut d,
            "payments-api",
            &[repo(
                "acme/payments",
                RepoAccess::Unreadable("HTTP 404: Not Found".into()),
            )],
        );
        cap_links_to_credential(&mut d);
        let system = system_links(&d, "payments-api");
        assert_eq!(system.len(), 1, "{system:?}");
        assert_eq!(system[0].edge, EdgeKind::CanPushCode);
        assert_eq!(system[0].assurance, Assurance::Inferred);
        assert!(system[0].scope.is_none());
        assert!(
            system[0]
                .evidence
                .iter()
                .any(|e| e.contains("not checked: acme/payments (not readable with this token")),
            "{:?}",
            system[0].evidence
        );
        assert!(d.credential.permissions.confirmed.is_empty());
        assert!(!d.links.iter().any(|l| l.assurance == Assurance::Confirmed));

        // One readable read-only repository plus one unreadable one: the
        // read-only fact is confirmed, the system's write guess stays.
        let mut d = github_fixture();
        apply_gh_auth_status(&mut d, &parse_gh_auth_status(GH_FINE_GRAINED), "github.com");
        apply_repo_access(
            &mut d,
            "payments-api",
            &[
                repo("acme/docs", RepoAccess::ReadOnly),
                repo("acme/payments", RepoAccess::Unreadable("HTTP 403".into())),
            ],
        );
        cap_links_to_credential(&mut d);
        let system = system_links(&d, "payments-api");
        assert_eq!(system.len(), 2, "{system:?}");
        let guess = system
            .iter()
            .find(|l| l.edge == EdgeKind::CanPushCode)
            .expect("inferred write guess kept");
        assert_eq!(guess.assurance, Assurance::Inferred);
        assert!(guess.evidence.iter().any(|e| e.contains("acme/payments")));
        let read = system
            .iter()
            .find(|l| l.edge == EdgeKind::CanReadSecret)
            .unwrap();
        assert_eq!(read.assurance, Assurance::Confirmed);
    }

    #[test]
    fn declared_repo_accepts_owner_repo_forms_only() {
        assert_eq!(
            declared_repo("acme/payments", "github.com").as_deref(),
            Some("acme/payments")
        );
        assert_eq!(
            declared_repo("github.com/acme/payments", "github.com").as_deref(),
            Some("acme/payments")
        );
        assert_eq!(
            declared_repo("https://github.com/acme/payments.git", "github.com").as_deref(),
            Some("acme/payments")
        );
        assert_eq!(
            declared_repo("git@github.com:acme/payments.git", "github.com").as_deref(),
            Some("acme/payments")
        );
        assert_eq!(declared_repo("github.com", "github.com"), None);
        assert_eq!(declared_repo("prod-eks", "github.com"), None);
        assert_eq!(declared_repo("acme/payments/extra", "github.com"), None);
        assert_eq!(
            declared_repo("ghe.example.com/acme/payments", "github.com"),
            None,
            "another host's repository is not asked about on this one"
        );
    }

    #[test]
    fn links_never_exceed_credential_assurance() {
        let mut d = github_fixture();
        d.links[0].assurance = Assurance::Confirmed;
        d.credential.permissions.assurance = Assurance::Inferred;
        cap_links_to_credential(&mut d);
        assert!(d.links.iter().all(|l| l.assurance == Assurance::Inferred));
        d.credential.permissions.assurance = Assurance::Unknown;
        cap_links_to_credential(&mut d);
        assert!(d.links.iter().all(|l| l.assurance == Assurance::Unknown));
    }

    #[test]
    fn can_i_list_parses_and_maps_to_capabilities() {
        let rules = parse_can_i_list(CAN_I);
        assert!(rules
            .iter()
            .any(|(r, v)| r == "deployments.apps" && v.contains(&"create".to_string())));
        let caps = kube_capabilities(&rules);
        assert!(caps.deploy);
        assert!(caps.read_secrets);
        assert!(!caps.create_credentials);
        assert!(!caps.modify_config);
        assert!(!caps.admin);
        assert!(!caps.escalate);
    }

    #[test]
    fn can_i_answer_parses_yes_no_and_noise() {
        assert_eq!(parse_can_i_answer("yes\n"), Some(true));
        assert_eq!(parse_can_i_answer("no\n"), Some(false));
        assert_eq!(
            parse_can_i_answer("yes - the server is allowing this\n"),
            Some(true)
        );
        assert_eq!(parse_can_i_answer(""), None);
        assert_eq!(parse_can_i_answer("error: context not found"), None);
    }

    #[test]
    fn cluster_admin_rule_grants_everything() {
        let caps = kube_capabilities(&[("*.*".into(), vec!["*".into()])]);
        assert!(
            caps.admin
                && caps.deploy
                && caps.read_secrets
                && caps.create_credentials
                && caps.escalate
        );
    }

    #[test]
    fn read_only_rules_grant_nothing_dangerous() {
        let caps = kube_capabilities(&[
            ("pods".into(), vec!["get".into(), "list".into()]),
            ("configmaps".into(), vec!["get".into()]),
        ]);
        assert_eq!(caps, KubeCaps::default());
    }

    fn kube_fixture() -> Discovered {
        let mut d = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::KubernetesContext,
                "prod",
                "~/.kube/config",
                "cluster prod",
            ),
            links: vec![
                Link::new(
                    NodeKind::Cluster,
                    "prod",
                    EdgeKind::CanAuthenticate,
                    Assurance::Inferred,
                )
                .production(true),
                Link::new(
                    NodeKind::Cluster,
                    "prod",
                    EdgeKind::CanDeploy,
                    Assurance::Inferred,
                )
                .evidence("admin-named context; verify with --verify")
                .production(true),
            ],
            verify_key: Some("prod".into()),
        };
        d.credential.permissions.administrative = Capability::Yes; // name-based guess
        d
    }

    fn ns_check(ns: &str, caps: KubeCaps) -> KubeCheck {
        KubeCheck {
            scope: KubeScope::Namespace(ns.into()),
            caps,
        }
    }

    fn cluster_check(caps: KubeCaps) -> KubeCheck {
        KubeCheck {
            scope: KubeScope::AllNamespaces,
            caps,
        }
    }

    /// Coverage where the namespace list was readable and names exactly `all`.
    fn full_coverage(declared: &[&str], all: &[&str]) -> KubeCoverage {
        KubeCoverage {
            declared: declared.iter().map(|s| s.to_string()).collect(),
            listed: Some(all.iter().map(|s| s.to_string()).collect()),
            failures: BTreeMap::new(),
        }
    }

    /// Coverage where `kubectl get namespaces` was denied.
    fn unlisted_coverage(declared: &[&str]) -> KubeCoverage {
        KubeCoverage {
            declared: declared.iter().map(|s| s.to_string()).collect(),
            listed: None,
            failures: BTreeMap::new(),
        }
    }

    #[test]
    fn namespace_listing_is_namespace_scoped_and_keeps_inferred_cluster_capability() {
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &[ns_check(
                "payments",
                KubeCaps {
                    read_secrets: true,
                    ..Default::default()
                },
            )],
            &unlisted_coverage(&[]),
        );
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);
        // One namespace says nothing about cluster-admin elsewhere.
        assert_eq!(d.credential.permissions.administrative, Capability::Unknown);
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::Unknown
        );
        // The inferred deploy edge survives, with the caveat recorded.
        let deploy = d
            .links
            .iter()
            .find(|l| l.edge == EdgeKind::CanDeploy)
            .expect("inferred deploy edge kept");
        assert_eq!(deploy.assurance, Assurance::Inferred);
        assert!(deploy.evidence.iter().any(
            |e| e.contains("namespace payments") && e.contains("other namespaces not checked")
        ));
        // The confirmed edge is labelled with the namespace it was checked in.
        let secrets = d
            .links
            .iter()
            .find(|l| l.edge == EdgeKind::CanReadSecret)
            .unwrap();
        assert_eq!(secrets.assurance, Assurance::Confirmed);
        assert_eq!(secrets.scope.as_deref(), Some("namespace payments"));
        assert!(secrets
            .evidence
            .iter()
            .any(|e| e.ends_with(" in namespace payments")));
        // Nothing claims to be cluster-wide.
        let text = format!("{:?} {:?}", d.credential, d.links);
        assert!(!text.contains("cluster-wide"), "{text}");
        assert!(d
            .credential
            .permissions
            .scope
            .iter()
            .any(|s| s == "RBAC in namespace payments: read secrets"));
        assert!(d.credential.evidence.iter().any(
            |e| e.starts_with("kubectl auth can-i --list -n payments (in namespace payments)")
        ));
    }

    #[test]
    fn complete_coverage_may_remove_inferred_deploy() {
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &[
                ns_check(
                    "payments",
                    KubeCaps {
                        read_secrets: true,
                        ..Default::default()
                    },
                ),
                cluster_check(KubeCaps::default()),
            ],
            &full_coverage(&["payments"], &["payments"]),
        );
        assert_eq!(d.credential.permissions.administrative, Capability::No);
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::No
        );
        assert!(
            !d.links.iter().any(|l| l.edge == EdgeKind::CanDeploy),
            "cluster-wide denial plus every namespace denied removes the guess"
        );
        assert!(d
            .credential
            .evidence
            .iter()
            .any(|e| e.contains("(cluster-wide)")));
        assert!(
            d.credential.evidence.iter().any(|e| e
                .starts_with("namespaces checked: payments (all 1 listed")
                && e.contains("denials are complete")),
            "{:?}",
            d.credential.evidence
        );
    }

    #[test]
    fn declared_namespace_left_unchecked_keeps_production_unknown() {
        // Cluster-wide denied, `default` denied, but the map says the
        // system lives in `prod` and that namespace was not checked. A
        // RoleBinding there is still possible, so nothing is "no".
        let denied = [
            ns_check("default", KubeCaps::default()),
            cluster_check(KubeCaps::default()),
        ];
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &denied,
            &full_coverage(&["prod"], &["default", "prod"]),
        );
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::Unknown
        );
        assert_eq!(d.credential.permissions.administrative, Capability::Unknown);
        assert_eq!(
            d.credential.permissions.can_create_credentials,
            Capability::Unknown
        );
        let deploy = d
            .links
            .iter()
            .find(|l| l.edge == EdgeKind::CanDeploy)
            .expect("inferred deploy edge kept");
        assert_eq!(deploy.assurance, Assurance::Inferred);
        assert!(
            deploy
                .evidence
                .iter()
                .any(|e| e.contains("namespace default")
                    && e.contains("cluster-wide")
                    && e.contains("namespace prod declared in the map, not checked")),
            "{:?}",
            deploy.evidence
        );
        assert!(
            d.credential.evidence.iter().any(|e| e
                .starts_with("namespaces checked: default and cluster-wide")
                && e.contains("namespace prod declared in the map, not checked")
                && e.contains("denials stay unknown")),
            "{:?}",
            d.credential.evidence
        );
        // The check that failed is named with its reason.
        let mut d = kube_fixture();
        let mut coverage = full_coverage(&["prod"], &["default", "prod"]);
        coverage
            .failures
            .insert("prod".into(), "kubectl: forbidden".into());
        apply_kube_checks(&mut d, &denied, &coverage);
        assert!(d
            .credential
            .evidence
            .iter()
            .any(|e| e
                .contains("namespace prod declared in the map, not checked: kubectl: forbidden")));

        // `prod` checked and denied too, with the namespace list complete:
        // now the denial covers every namespace that could matter.
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &[
                ns_check("default", KubeCaps::default()),
                ns_check("prod", KubeCaps::default()),
                cluster_check(KubeCaps::default()),
            ],
            &full_coverage(&["prod"], &["default", "prod"]),
        );
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::No
        );
        assert!(!d.links.iter().any(|l| l.edge == EdgeKind::CanDeploy));
        assert!(d.credential.permissions.scope.contains(
            &"RBAC in namespaces default, prod: none of the tracked capabilities".to_string()
        ));

        // `prod` granted: yes, with a confirmed edge scoped to it.
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &[
                ns_check("default", KubeCaps::default()),
                ns_check(
                    "prod",
                    KubeCaps {
                        deploy: true,
                        ..Default::default()
                    },
                ),
                cluster_check(KubeCaps::default()),
            ],
            &full_coverage(&["prod"], &["default", "prod"]),
        );
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::Yes
        );
        let confirmed: Vec<&Link> = d
            .links
            .iter()
            .filter(|l| l.edge == EdgeKind::CanDeploy && l.assurance == Assurance::Confirmed)
            .collect();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].scope.as_deref(), Some("namespace prod"));
    }

    #[test]
    fn unreadable_namespace_list_keeps_denials_unknown() {
        // Every declared namespace and the cluster scope denied, but the
        // context may not list namespaces: others may exist.
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &[
                ns_check("default", KubeCaps::default()),
                ns_check("prod", KubeCaps::default()),
                cluster_check(KubeCaps::default()),
            ],
            &unlisted_coverage(&["prod"]),
        );
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::Unknown
        );
        assert_eq!(d.credential.permissions.administrative, Capability::Unknown);
        let deploy = d
            .links
            .iter()
            .find(|l| l.edge == EdgeKind::CanDeploy)
            .expect("inferred deploy edge kept");
        assert!(deploy
            .evidence
            .iter()
            .any(|e| e.contains("namespace list is not readable")));

        // A namespace the cluster lists but that was not checked (over the
        // limit) is a gap too.
        let mut d = kube_fixture();
        let mut coverage = full_coverage(&[], &["default", "kube-system"]);
        coverage
            .failures
            .insert("kube-system".into(), "beyond the limit".into());
        apply_kube_checks(
            &mut d,
            &[
                ns_check("default", KubeCaps::default()),
                cluster_check(KubeCaps::default()),
            ],
            &coverage,
        );
        assert_eq!(d.credential.permissions.administrative, Capability::Unknown);
        assert!(d.credential.evidence.iter().any(|e| {
            e.contains("namespace kube-system exists in the cluster, not checked: beyond the limit")
        }));
    }

    #[test]
    fn namespace_grant_is_kept_even_when_cluster_wide_denies() {
        let mut d = kube_fixture();
        apply_kube_checks(
            &mut d,
            &[
                ns_check(
                    "payments",
                    KubeCaps {
                        deploy: true,
                        ..Default::default()
                    },
                ),
                cluster_check(KubeCaps::default()),
            ],
            &unlisted_coverage(&["payments"]),
        );
        assert_eq!(
            d.credential.permissions.can_modify_production,
            Capability::Yes
        );
        let deploy: Vec<&Link> = d
            .links
            .iter()
            .filter(|l| l.edge == EdgeKind::CanDeploy && l.assurance == Assurance::Confirmed)
            .collect();
        assert_eq!(deploy.len(), 1);
        assert_eq!(deploy[0].scope.as_deref(), Some("namespace payments"));
    }

    #[cfg(unix)]
    fn aws_fixture() -> Discovered {
        Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::AwsAccessKey,
                "default",
                "~/.aws/credentials",
                "AWS",
            ),
            links: vec![],
            verify_key: Some("default".into()),
        }
    }

    #[cfg(unix)]
    fn verify_one(script: &str, tag: &str) -> (Verification, Discovered, Vec<String>) {
        let dir = temp_tools(tag);
        fake_tool(&dir, "aws", script);
        let mut found = vec![aws_fixture()];
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        );
        let _ = std::fs::remove_dir_all(&dir);
        (
            outcome.verifications[0].clone(),
            found.remove(0),
            outcome.notes,
        )
    }

    #[cfg(unix)]
    #[test]
    fn verification_outcome_is_recorded_apart_from_confidence() {
        // The provider answered.
        let (v, d, _) = verify_one(
            r#"case "$*" in
  *get-caller-identity*) echo '{"Arn":"arn:aws:iam::123456789012:user/alice","Account":"123456789012"}';;
  *) echo '{"AttachedPolicies":[]}';;
esac"#,
            "outcome-ok",
        );
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed);
        assert!(
            v.detail
                .starts_with("aws sts get-caller-identity: the provider confirmed the identity"),
            "{}",
            v.detail
        );
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);

        // Non-zero exit: failed, the detail is the error class, never the
        // tool's message; the permissions stay inferred.
        let (v, d, notes) = verify_one(
            "echo 'An error occurred (InvalidClientTokenId) AKIAIOSFODNN7SECRETISH' >&2; exit 254",
            "outcome-exit",
        );
        assert_eq!(v.status, VerificationStatus::Failed);
        assert_eq!(v.detail, "aws sts get-caller-identity exited with an error");
        assert_ne!(d.credential.permissions.assurance, Assurance::Confirmed);
        assert!(
            notes.iter().any(|n| n.contains("not verified")),
            "{notes:?}"
        );

        // Timeout: failed, and says so.
        TIMEOUT_OVERRIDE.with(|t| t.set(Some(Duration::from_secs(1))));
        let started = Instant::now();
        let (v, _, _) = verify_one("exec /bin/sleep 30", "outcome-timeout");
        TIMEOUT_OVERRIDE.with(|t| t.set(None));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(v.status, VerificationStatus::Failed);
        assert_eq!(v.detail, "aws sts get-caller-identity timed out after 1s");

        // No adapter for the kind, or nothing to select it by: unsupported.
        let mut found = vec![
            Discovered {
                credential: DiscoveredCredential::new(
                    CredentialKind::DockerRegistry,
                    "ghcr.io",
                    "~/.docker/config.json",
                    "ghcr.io",
                ),
                links: vec![],
                verify_key: None,
            },
            Discovered {
                verify_key: None,
                ..aws_fixture()
            },
        ];
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &BTreeMap::new(),
        );
        assert_eq!(outcome.verifications.len(), 2);
        assert!(outcome
            .verifications
            .iter()
            .all(|v| v.status == VerificationStatus::Unsupported));
    }

    #[cfg(unix)]
    #[test]
    fn large_output_does_not_block_the_tool() {
        // More than a pipe buffer on both streams: read while waiting, so
        // the tool finishes at once instead of stalling until the timeout.
        let dir = temp_tools("large-output");
        fake_tool(
            &dir,
            "big",
            "head -c 1048576 /dev/zero | tr '\\0' 'a'; head -c 200000 /dev/zero | tr '\\0' 'b' >&2; exit 0",
        );
        let mut env = fake_env(&dir);
        env.insert("PATH".into(), format!("{}:/usr/bin:/bin", dir.display()));
        let started = Instant::now();
        let out = run_cli_raw("big", &[], &env).expect("completes");
        assert!(out.success);
        assert_eq!(out.stdout.len(), 1_048_576);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cli_is_an_error_not_a_panic() {
        let env = BTreeMap::new();
        let err = run_cli("hedgehog-definitely-missing-binary", &["x"], &env).unwrap_err();
        assert!(err.contains("not available"));
    }

    #[cfg(unix)]
    #[test]
    fn empty_gcloud_auth_list_is_local_configuration_not_confirmation() {
        // A synthetic `gcloud auth list` with no accounts: the tool ran, but
        // it only read local configuration. That is never a confirmation.
        let dir = temp_tools("gcloud-empty");
        fake_tool(&dir, "gcloud", "echo '[]'");
        let mut found = vec![Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GcpUserCredential,
                "alice@example.com",
                "~/.config/gcloud",
                "Google Cloud",
            ),
            links: vec![Link::new(
                NodeKind::CloudRole,
                "project-a",
                EdgeKind::CanAuthenticate,
                Assurance::Inferred,
            )],
            verify_key: Some("alice@example.com".into()),
        }];
        found[0].credential.permissions.assurance = Assurance::Inferred;
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        );
        let _ = std::fs::remove_dir_all(&dir);
        let v = &outcome.verifications[0];
        assert_eq!(v.status, VerificationStatus::LocalConfig);
        assert_eq!(v.status.key(), "local_config");
        assert!(v.detail.contains("Google was not asked"), "{}", v.detail);
        assert_eq!(
            found[0].credential.permissions.assurance,
            Assurance::Inferred
        );
        assert_eq!(found[0].links[0].assurance, Assurance::Inferred);
    }

    #[cfg(unix)]
    #[test]
    fn aws_policy_listing_is_identity_with_boundary_note() {
        let (v, d, _) = verify_one(
            r#"case "$*" in
  *get-caller-identity*) echo '{"Arn":"arn:aws:iam::123456789012:user/alice","Account":"123456789012"}';;
  *list-attached-user-policies*) echo '{"AttachedPolicies":[{"PolicyName":"AdministratorAccess"}]}';;
  *) exit 1;;
esac"#,
            "aws-boundary",
        );
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed);
        assert!(
            v.detail.contains("permission boundaries")
                && v.detail.contains("explicit denies")
                && v.detail.contains("not confirmed"),
            "{}",
            v.detail
        );
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("permission boundaries")),
            "{:?}",
            d.credential.evidence
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_confirmation_leaves_an_inferred_path_inferred() {
        // sts confirms who the key is. The edge to a production system was
        // inferred by discovery, and an identity answer says nothing about
        // it, so the edge (and every path through it) stays inferred, while
        // the credential itself is confirmed.
        let dir = temp_tools("aws-path");
        fake_tool(
            &dir,
            "aws",
            r#"case "$*" in
  *get-caller-identity*) echo '{"Arn":"arn:aws:iam::123456789012:user/alice","Account":"123456789012"}';;
  *) exit 1;;
esac"#,
        );
        let mut d = aws_fixture();
        d.links.push(
            Link::new(
                NodeKind::ProductionService,
                "payments",
                EdgeKind::CanDeploy,
                Assurance::Inferred,
            )
            .production(true),
        );
        let mut found = vec![d];
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            outcome.verifications[0].status,
            VerificationStatus::IdentityConfirmed
        );
        let d = &found[0];
        assert_eq!(d.credential.permissions.assurance, Assurance::Confirmed);
        assert!(d.links.iter().all(|l| l.assurance != Assurance::Confirmed));

        // Scored through the real graph: the path to payments stays inferred.
        let decl = crate::exposure::config::Declarations::default();
        let (graph, _laptop, nodes) = crate::exposure::build_graph(&found, &decl);
        let paths = graph.paths_to_kind(nodes[0], NodeKind::ProductionService, 4);
        assert!(!paths.is_empty());
        assert!(paths.iter().all(|p| p.assurance == Assurance::Inferred));
        let finding =
            hedgehog_taint::authority::scoring::score_finding(&graph, &found[0].credential, &paths);
        assert!(finding
            .paths
            .iter()
            .all(|p| p.assurance == Assurance::Inferred));
    }

    #[test]
    fn settle_assurance_keeps_edges_only_for_permission_checks() {
        let fixture = || Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                "github.com",
                "~/.config/gh/hosts.yml",
                "GitHub",
            ),
            links: vec![Link::new(
                NodeKind::Repository,
                "acme/api",
                EdgeKind::CanPushCode,
                Assurance::Confirmed,
            )],
            verify_key: None,
        };
        for (status, edge, cred) in [
            (
                VerificationStatus::PermissionConfirmed,
                Assurance::Confirmed,
                Assurance::Confirmed,
            ),
            (
                VerificationStatus::IdentityConfirmed,
                Assurance::Inferred,
                Assurance::Confirmed,
            ),
            (
                VerificationStatus::LocalConfig,
                Assurance::Inferred,
                Assurance::Inferred,
            ),
            (
                VerificationStatus::Failed,
                Assurance::Inferred,
                Assurance::Inferred,
            ),
        ] {
            let mut d = fixture();
            d.credential.permissions.assurance = Assurance::Confirmed;
            settle_assurance(&mut d, Assurance::Inferred, status);
            assert_eq!(d.links[0].assurance, edge, "{status:?}");
            assert_eq!(d.credential.permissions.assurance, cred, "{status:?}");
        }
    }

    #[test]
    fn status_keys_never_say_plain_confirmed() {
        for s in [
            VerificationStatus::IdentityConfirmed,
            VerificationStatus::PermissionConfirmed,
            VerificationStatus::LocalConfig,
            VerificationStatus::Failed,
            VerificationStatus::Unsupported,
            VerificationStatus::NotAttempted,
        ] {
            assert_ne!(s.key(), "confirmed");
        }
        assert_eq!(
            VerificationStatus::LocalConfig.label(),
            "local configuration only, provider not asked"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gh_auth_status_is_identity_and_scopes_confirm_no_edge() {
        let dir = temp_tools("gh-identity");
        fake_tool(
            &dir,
            "gh",
            r#"echo "github.com
  Logged in to github.com account alice (keyring)
  Token: gho_************************************
  Token scopes: 'repo', 'workflow'" >&2"#,
        );
        let mut found = vec![github_fixture()];
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        );
        let _ = std::fs::remove_dir_all(&dir);
        let v = &outcome.verifications[0];
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed, "{v:?}");
        assert!(v.detail.contains("protected branch"), "{}", v.detail);
        assert!(found[0]
            .links
            .iter()
            .all(|l| l.assurance != Assurance::Confirmed));
    }

    // ── Identity is not permission ──

    /// Score a verified finding through the real graph.
    fn score(found: &[Discovered]) -> hedgehog_taint::authority::ExposureFinding {
        let decl = crate::exposure::config::Declarations::default();
        let (graph, _laptop, nodes) = crate::exposure::build_graph(found, &decl);
        let mut paths = Vec::new();
        for kind in [
            NodeKind::ProductionService,
            NodeKind::CloudRole,
            NodeKind::Repository,
            NodeKind::CiSystem,
        ] {
            paths.extend(graph.paths_to_kind(nodes[0], kind, 4));
        }
        hedgehog_taint::authority::scoring::score_finding(&graph, &found[0].credential, &paths)
    }

    #[cfg(unix)]
    #[test]
    fn aws_administrator_access_with_identity_confirmed_is_inferred_admin() {
        let (v, d, _) = verify_one(
            r#"case "$*" in
  *get-caller-identity*) echo '{"Arn":"arn:aws:iam::123456789012:user/alice","Account":"123456789012"}';;
  *list-attached-user-policies*) echo '{"AttachedPolicies":[{"PolicyName":"AdministratorAccess"}]}';;
  *) exit 1;;
esac"#,
            "aws-admin-inferred",
        );
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed);
        let p = &d.credential.permissions;
        assert_eq!(p.assurance, Assurance::Confirmed, "identity");
        assert_eq!(p.administrative, Capability::Yes);
        assert_eq!(
            p.capability_assurance(Permission::Administrative),
            Assurance::Inferred
        );
        assert_eq!(
            p.capability_assurance(Permission::ModifyProduction),
            Assurance::Inferred
        );
        assert!(p.confirmed.is_empty(), "{:?}", p.confirmed);
        assert!(
            d.credential
                .evidence
                .iter()
                .any(|e| e.contains("AdministratorAccess")
                    && e.contains("inferred from the policy name")),
            "{:?}",
            d.credential.evidence
        );
        let f = score(&[d]);
        assert_eq!(f.confidence, Assurance::Inferred);
        assert_eq!(f.severity, hedgehog_taint::authority::Severity::Medium);
    }

    #[cfg(unix)]
    #[test]
    fn assumed_role_is_identity_with_only_the_assumption_confirmed() {
        let dir = temp_tools("aws-assumed");
        fake_tool(
            &dir,
            "aws",
            r#"case "$*" in
  *get-caller-identity*) echo '{"Arn":"arn:aws:sts::123456789012:assumed-role/deploy/botocore-session-1","Account":"123456789012"}';;
  *list-attached-role-policies*) echo '{"AttachedPolicies":[{"PolicyName":"AdministratorAccess"}]}';;
  *) exit 1;;
esac"#,
        );
        let mut found = vec![Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::AwsProfileRole,
                "deploy",
                "~/.aws/config",
                "AWS",
            ),
            links: vec![Link::new(
                NodeKind::CloudRole,
                "deploy",
                EdgeKind::CanAssumeRole,
                Assurance::Inferred,
            )],
            verify_key: Some("deploy".into()),
        }];
        found[0].credential.permissions.assurance = Assurance::Inferred;
        found[0].credential.permissions.can_assume_role = Capability::Yes;
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        );
        let _ = std::fs::remove_dir_all(&dir);
        let v = &outcome.verifications[0];
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed, "{v:?}");
        assert!(
            v.detail.contains("role assumption confirmed; the role's effective permissions were not evaluated (permission boundaries, SCPs, explicit denies)"),
            "{}",
            v.detail
        );
        let d = &found[0];
        let p = &d.credential.permissions;
        assert_eq!(
            p.capability_assurance(Permission::AssumeRole),
            Assurance::Confirmed
        );
        assert_eq!(p.administrative, Capability::Yes);
        assert_eq!(
            p.capability_assurance(Permission::Administrative),
            Assurance::Inferred
        );
        let edge = d
            .links
            .iter()
            .find(|l| l.edge == EdgeKind::CanAssumeRole)
            .unwrap();
        assert_eq!(
            edge.assurance,
            Assurance::Confirmed,
            "the one hop is confirmed"
        );
        assert_eq!(score(&found).confidence, Assurance::Inferred);
    }

    #[cfg(unix)]
    fn azure_case(roles: &str, tag: &str) -> (Verification, Discovered) {
        let dir = temp_tools(tag);
        fake_tool(
            &dir,
            "az",
            &format!(
                r#"case "$*" in
  *"account show"*) echo '{{"name":"Production","user":{{"name":"alice@example.com","type":"user"}}}}';;
  *"role assignment list"*) echo '{roles}';;
  *) exit 1;;
esac"#
            ),
        );
        let mut found = vec![Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::AzureSession,
                "Production",
                "~/.azure/azureProfile.json",
                "Azure",
            ),
            links: vec![],
            verify_key: Some("alice@example.com".into()),
        }];
        // As discovery leaves it: production inferred from the subscription name.
        found[0].credential.permissions.assurance = Assurance::Inferred;
        found[0].credential.permissions.can_access_production = Capability::Yes;
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &fake_env(&dir),
        );
        let _ = std::fs::remove_dir_all(&dir);
        (outcome.verifications[0].clone(), found.remove(0))
    }

    #[cfg(unix)]
    #[test]
    fn azure_roles_are_identity_with_inferred_capabilities() {
        let (v, d) = azure_case(
            r#"[{"roleDefinitionName":"Owner","scope":"/subscriptions/0000"}]"#,
            "az-owner",
        );
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed, "{v:?}");
        assert!(
            v.detail.contains("deny assignments") && v.detail.contains("PIM"),
            "{}",
            v.detail
        );
        let p = &d.credential.permissions;
        assert_eq!(p.assurance, Assurance::Confirmed);
        assert_eq!(p.administrative, Capability::Yes);
        assert!(p.confirmed.is_empty(), "{:?}", p.confirmed);
        assert_eq!(p.can_access_production, Capability::Yes);
        assert_eq!(
            p.capability_assurance(Permission::AccessProduction),
            Assurance::Inferred,
            "a subscription called Production is a name, not a permission"
        );
        assert_eq!(score(&[d]).confidence, Assurance::Inferred);
    }

    #[cfg(unix)]
    #[test]
    fn azure_without_role_assignments_infers_no_production_access() {
        let (v, d) = azure_case("[]", "az-empty");
        assert_eq!(v.status, VerificationStatus::IdentityConfirmed, "{v:?}");
        assert!(
            v.detail
                .contains("no role assignments were found for this principal"),
            "{}",
            v.detail
        );
        let p = &d.credential.permissions;
        assert_eq!(p.can_access_production, Capability::No);
        assert_eq!(p.can_modify_production, Capability::No);
        assert_eq!(
            p.capability_assurance(Permission::AccessProduction),
            Assurance::Inferred
        );
    }

    /// A stand-in gh that answers like the real one: a token variable wins
    /// over the saved login, otherwise the user in `$GH_CONFIG_DIR/hosts.yml`.
    #[cfg(unix)]
    const GH_ALICE_BOB: &str = r#"echo "GH_CONFIG_DIR=$GH_CONFIG_DIR" >> "$GH_LOG"
[ -f "$GH_CONFIG_DIR/hosts.yml" ] && echo "hosts-present" >> "$GH_LOG"
if [ -n "$GH_TOKEN" ]; then acct=$GH_TOKEN
elif [ -n "$GITHUB_TOKEN" ]; then acct=$GITHUB_TOKEN
elif [ -f "$GH_CONFIG_DIR/hosts.yml" ]; then acct=$(sed -n 's/^ *user: *//p' "$GH_CONFIG_DIR/hosts.yml" | head -n 1)
else echo "You are not logged into any GitHub hosts." >&2; exit 1
fi
printf 'github.com\n  Logged in to github.com account %s (keyring)\n  Token: gho_****\n  Token scopes: '"'"'repo'"'"'\n' "$acct" >&2"#;

    #[cfg(unix)]
    #[test]
    fn github_verification_is_bound_to_the_credential_under_test() {
        // Alice's login is saved in hosts.yml; Bob's token is in GH_TOKEN.
        // Left to itself gh would answer "bob" for Alice's saved login.
        let dir = temp_tools("gh-alice-bob");
        fake_tool(&dir, "gh", GH_ALICE_BOB);
        let home = dir.join("home");
        std::fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::fs::write(
            home.join(".config/gh/hosts.yml"),
            "github.com:\n    user: alice\n    oauth_token: gho_alice\n    git_protocol: https\n",
        )
        .unwrap();
        let log = dir.join("gh.log");
        let mut env = fake_env(&dir);
        env.insert("PATH".into(), format!("{}:/usr/bin:/bin", dir.display()));
        env.insert("HOME".into(), home.display().to_string());
        env.insert("GH_TOKEN".into(), "bob".into());
        env.insert("GH_LOG".into(), log.display().to_string());

        let mut saved = github_fixture();
        saved.credential.permissions.identity = Some("alice".into());
        let env_token = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                "GH_TOKEN",
                "env GH_TOKEN",
                "github.com",
            ),
            links: vec![],
            verify_key: None,
        };
        let mut found = vec![saved, env_token];
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &env,
        );
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(
            outcome.verifications[0].status,
            VerificationStatus::IdentityConfirmed,
            "{:?}",
            outcome.verifications
        );
        assert_eq!(
            found[0].credential.permissions.identity.as_deref(),
            Some("alice"),
            "Bob's token must not answer for Alice's saved login"
        );
        assert_eq!(
            outcome.verifications[1].status,
            VerificationStatus::IdentityConfirmed,
            "{:?}",
            outcome.verifications
        );
        assert_eq!(
            found[1].credential.permissions.identity.as_deref(),
            Some("bob"),
            "the environment token is checked as itself"
        );
        // The saved login ran in its own configuration directory; the
        // environment token ran in an empty one, deleted afterwards.
        let dirs: Vec<&str> = calls
            .lines()
            .filter_map(|l| l.strip_prefix("GH_CONFIG_DIR="))
            .collect();
        assert_eq!(dirs.len(), 2, "{calls}");
        assert!(dirs[0].ends_with(".config/gh"), "{calls}");
        assert_eq!(calls.matches("hosts-present").count(), 1, "{calls}");
        assert!(dirs[1].contains("gorse-gh-"), "{calls}");
        assert!(!Path::new(dirs[1]).exists(), "temporary directory removed");

        // The saved login records a different user from the one GitHub
        // reports: failed, never confirmed for the wrong account.
        let mut other = github_fixture();
        other.credential.permissions.identity = Some("carol".into());
        let mut found = vec![other];
        let outcome = verify_all(
            &mut found,
            &crate::exposure::config::Declarations::default(),
            &env,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(outcome.verifications[0].status, VerificationStatus::Failed);
        assert_eq!(
            outcome.verifications[0].detail,
            "provider reported a different account than the saved credential"
        );
        assert_eq!(
            found[0].credential.permissions.identity.as_deref(),
            Some("carol")
        );
        assert_ne!(
            found[0].credential.permissions.assurance,
            Assurance::Confirmed
        );
    }

    // ── Bindings, as pure functions ──

    fn set_of(b: &CliBinding, name: &str) -> Option<EnvSource> {
        b.set
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn aws_binding_passes_profile_and_strips_environment_credentials() {
        let b = aws_binding("prod", Path::new("/home/a/.aws/credentials"));
        assert_eq!(b.args, ["--profile", "prod"]);
        for var in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
        ] {
            assert!(b.remove.iter().any(|r| r == var), "{var}");
        }
        // Both files are joined to the profile's folder with the platform's
        // separator, so build the expectation the same way.
        let dir = Path::new("/home/a/.aws");
        assert_eq!(
            set_of(&b, "AWS_SHARED_CREDENTIALS_FILE"),
            Some(EnvSource::Value(
                dir.join("credentials").display().to_string()
            ))
        );
        let config = dir.join("config").display().to_string();
        assert_eq!(
            set_of(&b, "AWS_CONFIG_FILE"),
            Some(EnvSource::Value(config))
        );
        let mut env = BTreeMap::new();
        env.insert("AWS_ACCESS_KEY_ID".to_string(), "AKIAOTHER".to_string());
        env.insert("AWS_PROFILE".to_string(), "other".to_string());
        let (child, remove) = b.resolve(&env).unwrap();
        assert!(!child.contains_key("AWS_ACCESS_KEY_ID"));
        assert!(!child.contains_key("AWS_PROFILE"));
        assert!(remove.iter().any(|r| r == "AWS_SESSION_TOKEN"));
    }

    #[test]
    fn gh_binding_for_a_saved_login_removes_every_token_variable() {
        let b = gh_binding(
            "github.com",
            Path::new("/home/a/.config/gh/hosts.yml"),
            Path::new(""),
        );
        assert!(b.args.is_empty());
        for var in GH_TOKEN_VARS {
            assert!(b.remove.iter().any(|r| r == var), "{var}");
        }
        assert_eq!(
            set_of(&b, "GH_CONFIG_DIR"),
            Some(EnvSource::Value("/home/a/.config/gh".into()))
        );
        let mut env = BTreeMap::new();
        env.insert("GH_TOKEN".to_string(), "bob".to_string());
        env.insert("GITHUB_TOKEN".to_string(), "bob2".to_string());
        let (child, remove) = b.resolve(&env).unwrap();
        assert!(!child.contains_key("GH_TOKEN") && !child.contains_key("GITHUB_TOKEN"));
        assert!(remove.iter().any(|r| r == "GH_ENTERPRISE_TOKEN"));
    }

    #[test]
    fn gh_binding_for_an_environment_token_keeps_only_that_variable() {
        let b = gh_binding(
            "env:GITHUB_TOKEN",
            Path::new("/irrelevant"),
            Path::new("/tmp/empty"),
        );
        assert_eq!(
            set_of(&b, "GITHUB_TOKEN"),
            Some(EnvSource::Var("GITHUB_TOKEN".into()))
        );
        assert_eq!(
            set_of(&b, "GH_CONFIG_DIR"),
            Some(EnvSource::Value("/tmp/empty".into()))
        );
        assert!(!b.remove.iter().any(|r| r == "GITHUB_TOKEN"));
        for var in ["GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"] {
            assert!(b.remove.iter().any(|r| r == var), "{var}");
        }
        let mut env = BTreeMap::new();
        env.insert("GITHUB_TOKEN".to_string(), "mine".to_string());
        env.insert("GH_TOKEN".to_string(), "other".to_string());
        let (child, remove) = b.resolve(&env).unwrap();
        assert_eq!(child.get("GITHUB_TOKEN").map(String::as_str), Some("mine"));
        assert!(!child.contains_key("GH_TOKEN"));
        assert!(!remove.iter().any(|r| r == "GITHUB_TOKEN"));
        // The variable under test missing is an error, never a fall-through
        // to some other login.
        assert!(b.resolve(&BTreeMap::new()).is_err());
    }

    #[test]
    fn kube_binding_names_the_file_and_context() {
        let b = kube_binding("prod", Path::new("/home/a/.kube/config"));
        assert_eq!(
            b.args,
            ["--kubeconfig", "/home/a/.kube/config", "--context", "prod"]
        );
        assert_eq!(b.remove, ["KUBECONFIG"]);
    }

    #[test]
    fn vault_binding_passes_only_the_token_under_test() {
        let file = vault_binding("~/.vault-token", Path::new("/home/a/.vault-token"));
        assert_eq!(
            set_of(&file, "VAULT_TOKEN"),
            Some(EnvSource::File(PathBuf::from("/home/a/.vault-token")))
        );
        let env_token = vault_binding("env VAULT_TOKEN", Path::new("/irrelevant"));
        assert_eq!(
            set_of(&env_token, "VAULT_TOKEN"),
            Some(EnvSource::Var("VAULT_TOKEN".into()))
        );
        // A saved-file check replaces whatever VAULT_TOKEN the shell has.
        let dir = std::env::temp_dir().join(format!("gorse-vault-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".vault-token");
        std::fs::write(&path, "hvs.saved\n").unwrap();
        let b = vault_binding("~/.vault-token", &path);
        let mut env = BTreeMap::new();
        env.insert("VAULT_TOKEN".to_string(), "hvs.other".to_string());
        let (child, remove) = b.resolve(&env).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            child.get("VAULT_TOKEN").map(String::as_str),
            Some("hvs.saved")
        );
        assert!(!remove.iter().any(|r| r == "VAULT_TOKEN"));
    }

    #[test]
    fn gcloud_binding_names_the_configuration_and_strips_overrides() {
        let b = gcloud_binding(
            "alice@example.com",
            Path::new("/home/a/.config/gcloud/configurations/config_default"),
        );
        assert_eq!(
            set_of(&b, "CLOUDSDK_CONFIG"),
            Some(EnvSource::Value("/home/a/.config/gcloud".into()))
        );
        assert_eq!(
            set_of(&b, "CLOUDSDK_ACTIVE_CONFIG_NAME"),
            Some(EnvSource::Value("default".into()))
        );
        assert_eq!(b.remove_prefixes, ["CLOUDSDK_"]);
        assert!(b
            .remove
            .iter()
            .any(|r| r == "GOOGLE_APPLICATION_CREDENTIALS"));
        let mut env = BTreeMap::new();
        env.insert(
            "CLOUDSDK_CORE_ACCOUNT".to_string(),
            "bob@example.com".to_string(),
        );
        env.insert("CLOUDSDK_CONFIG".to_string(), "/elsewhere".to_string());
        let (child, remove) = b.resolve(&env).unwrap();
        assert!(!child.contains_key("CLOUDSDK_CORE_ACCOUNT"));
        assert!(remove.iter().any(|r| r == "CLOUDSDK_CORE_ACCOUNT"));
        assert_eq!(
            child.get("CLOUDSDK_CONFIG").map(String::as_str),
            Some("/home/a/.config/gcloud")
        );
        assert!(!remove.iter().any(|r| r == "CLOUDSDK_CONFIG"));
        // A directory location keeps the directory and names no configuration.
        let d = gcloud_binding("alice@example.com", Path::new("/home/a/.config/gcloud"));
        assert_eq!(
            set_of(&d, "CLOUDSDK_CONFIG"),
            Some(EnvSource::Value("/home/a/.config/gcloud".into()))
        );
        assert_eq!(set_of(&d, "CLOUDSDK_ACTIVE_CONFIG_NAME"), None);
    }

    #[test]
    fn azure_binding_names_the_profile_and_subscription() {
        let b = azure_binding("Production", Path::new("/home/a/.azure/azureProfile.json"));
        assert_eq!(b.args, ["--subscription", "Production"]);
        assert_eq!(
            set_of(&b, "AZURE_CONFIG_DIR"),
            Some(EnvSource::Value("/home/a/.azure".into()))
        );
        assert_eq!(b.remove_prefixes, ["AZURE_"]);
        let mut env = BTreeMap::new();
        env.insert("AZURE_CLIENT_SECRET".to_string(), "x".to_string());
        env.insert("AZURE_CONFIG_DIR".to_string(), "/elsewhere".to_string());
        let (child, remove) = b.resolve(&env).unwrap();
        assert!(!child.contains_key("AZURE_CLIENT_SECRET"));
        assert_eq!(
            child.get("AZURE_CONFIG_DIR").map(String::as_str),
            Some("/home/a/.azure")
        );
        assert!(!remove.iter().any(|r| r == "AZURE_CONFIG_DIR"));
    }

    #[test]
    fn github_environment_tokens_get_a_verification_key() {
        let d = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                "GH_TOKEN",
                "env GH_TOKEN",
                "github.com",
            ),
            links: vec![],
            verify_key: None,
        };
        assert_eq!(fallback_key(&d).as_deref(), Some("env:GH_TOKEN"));
        let other = Discovered {
            credential: DiscoveredCredential::new(
                CredentialKind::GitHubToken,
                "git credential github.com",
                "~/.git-credentials",
                "github.com",
            ),
            links: vec![],
            verify_key: None,
        };
        assert_eq!(fallback_key(&other), None);
    }
}
