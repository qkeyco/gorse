// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Secret file detection.
//!
//! Identifies files that contain credentials/secrets through:
//! 1. Exact path matching (known locations like ~/.ssh/id_rsa)
//! 2. Pattern matching (glob-like patterns for .env files)
//! 3. Directory matching (anything under ~/.ssh/)

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Priority ranking for secrets — highest risk first.
/// The free tier protects only the top N by priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretPriority {
    /// Critical: SSH keys, cloud credentials (free tier covers these)
    Critical = 0,
    /// High: API keys, tokens (paid tier)
    High = 1,
    /// Medium: config files that may contain secrets (paid tier)
    Medium = 2,
}

/// How the secret was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// Detected by file path (known secret file locations).
    PathBased,
    /// Detected by scanning file contents for secret patterns.
    ContentBased,
}

/// A detected secret with its priority.
#[derive(Debug, Clone)]
pub struct DetectedSecret {
    pub path: PathBuf,
    pub priority: SecretPriority,
    pub description: String,
    /// Whether this secret is actively protected (within tier limit).
    pub protected: bool,
    /// How the secret was detected.
    pub source: SecretSource,
}

/// A credential location on the watch list, with whether it exists on this
/// machine. This is what user-facing commands should report: a location that
/// is not on disk is watched, but it has not been *found*, and nothing about
/// it can be "protected".
#[derive(Debug, Clone)]
pub struct WatchedLocation {
    pub path: PathBuf,
    pub priority: SecretPriority,
    pub description: String,
    /// True when the file or directory exists on disk right now.
    pub present: bool,
    /// True for Gorse's own files (its config, logs, approvals and the
    /// agent settings that carry its hook). They are watched so an agent
    /// reading them taints the process, but they are not the user's
    /// credentials and must not be counted as such.
    pub self_protection: bool,
}

/// Detects whether a file path refers to a secret/credential file.
pub struct SecretDetector {
    /// Exact paths that are secrets.
    exact_paths: HashSet<PathBuf>,
    /// Directory prefixes — anything under these dirs is a secret.
    secret_dirs: HashSet<PathBuf>,
    /// Filename patterns (matched against the file name component only).
    secret_names: HashSet<String>,
    /// Priority for exact paths (for tier-based gating).
    path_priorities: Vec<(PathBuf, SecretPriority, String)>,
    /// Watched paths that are Gorse's own files rather than credentials.
    self_protection_paths: HashSet<PathBuf>,
    /// Maximum number of secrets to actively protect (enforcement limit, includes monitor reserve).
    max_protected: usize,
    /// User-facing display limit (what the tier actually advertises).
    display_limit: usize,
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDetector {
    /// Create with default known secret locations (unlimited protection).
    pub fn new() -> Self {
        let mut d = Self {
            exact_paths: HashSet::with_capacity(32),
            secret_dirs: HashSet::with_capacity(8),
            secret_names: HashSet::with_capacity(16),
            path_priorities: Vec::with_capacity(32),
            self_protection_paths: HashSet::with_capacity(8),
            max_protected: usize::MAX,
            display_limit: usize::MAX,
        };
        d.load_defaults();
        d
    }

    /// Create with a tier-based protection limit.
    /// `max_protected` is the enforcement limit (includes monitor reserve).
    /// `display_limit` is the user-facing number (what the tier advertises).
    pub fn with_limit(max_protected: usize, display_limit: usize) -> Self {
        let mut d = Self {
            exact_paths: HashSet::with_capacity(32),
            secret_dirs: HashSet::with_capacity(8),
            secret_names: HashSet::with_capacity(16),
            path_priorities: Vec::with_capacity(32),
            self_protection_paths: HashSet::with_capacity(8),
            max_protected,
            display_limit,
        };
        d.load_defaults();
        d
    }

    /// Create empty (for testing).
    pub fn empty() -> Self {
        Self {
            exact_paths: HashSet::new(),
            secret_dirs: HashSet::new(),
            secret_names: HashSet::new(),
            path_priorities: Vec::new(),
            self_protection_paths: HashSet::new(),
            max_protected: usize::MAX,
            display_limit: usize::MAX,
        }
    }

    /// Set the maximum number of protected secrets (tier upgrade).
    /// `max` is the enforcement limit (includes monitor reserve).
    /// `display` is the user-facing number (what the tier advertises).
    pub fn set_max_protected(&mut self, max: usize, display: usize) {
        self.max_protected = max;
        self.display_limit = display;
    }

    /// Check if a file path is a secret AND is within the protection limit.
    /// Free tier: only the top 15 priority secrets return true.
    /// Paid tiers: all secrets return true.
    pub fn is_secret(&self, path: &Path) -> bool {
        if !self.is_known_secret(path) {
            return false;
        }

        // If unlimited, all known secrets are protected
        if self.max_protected == usize::MAX {
            return true;
        }

        // Tier-limited: check if this path is within the protected set
        self.is_within_protected_limit(path)
    }

    /// Check if a file is a known secret (regardless of tier/protection limit).
    /// Used by the scanner to show ALL secrets found.
    pub fn is_known_secret(&self, path: &Path) -> bool {
        // 1. Exact path match
        if self.exact_paths.contains(path) {
            return true;
        }

        // 2. Directory prefix match
        for dir in &self.secret_dirs {
            if path.starts_with(dir) {
                return true;
            }
        }

        // 3. Filename match
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if self.secret_names.contains(name) {
                return true;
            }
            // Also check common patterns
            if name.starts_with(".env") || name == ".secret" || name == ".secrets" {
                return true;
            }
            if SECRET_NAME_SUFFIXES.iter().any(|s| name.ends_with(s)) {
                return true;
            }
        }

        false
    }

    /// Check if a secret path falls within the tier's protection limit.
    /// Secrets are prioritized: Critical (SSH, cloud) first, then High (API keys), then Medium.
    ///
    /// Protection slots are allocated in order:
    /// 1. Critical priority paths (SSH, AWS, GCP, GPG, Kube) — always first
    /// 2. .env files and filename-matched secrets — these are Critical by nature
    /// 3. High/Medium priority paths fill remaining slots
    fn is_within_protected_limit(&self, path: &Path) -> bool {
        // .env files and filename-pattern matches are always Critical priority.
        // They share the same pool as prioritized paths.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(".env") || name == ".secret" || name == ".secrets" {
                // .env files count as Critical — always within free tier limit
                return true;
            }
            if self.secret_names.contains(name)
                || SECRET_NAME_SUFFIXES.iter().any(|s| name.ends_with(s))
            {
                return true;
            }
        }

        // Directory matches (e.g., anything under .ssh/) — check if the dir
        // is in the priority list and within the limit
        for dir in &self.secret_dirs {
            if path.starts_with(dir) {
                // Find this dir's priority rank
                for (i, (p, _, _)) in self.path_priorities.iter().enumerate() {
                    if dir.starts_with(p) || p.starts_with(dir) {
                        return i < self.max_protected;
                    }
                }
            }
        }

        // Exact path match — check priority rank
        for (i, (p, _, _)) in self.path_priorities.iter().enumerate() {
            if p == path {
                return i < self.max_protected;
            }
        }

        // Dynamically added paths (via add_path) that aren't in priority list:
        // count them after the prioritized ones
        let base_count = self.path_priorities.len();
        // If total prioritized paths haven't filled the limit, additional paths get slots
        base_count < self.max_protected
    }

    /// Get all secrets found, with protection status based on tier.
    /// This powers the "42 secrets found, 15 protected" upgrade prompt.
    /// Uses the enforcement limit (not display) for the `protected` flag
    /// because this determines actual protection behavior.
    pub fn scan_results(&self) -> Vec<DetectedSecret> {
        let mut results: Vec<DetectedSecret> = self
            .path_priorities
            .iter()
            .enumerate()
            .map(|(i, (path, priority, description))| DetectedSecret {
                path: path.clone(),
                priority: *priority,
                description: description.clone(),
                protected: i < self.max_protected,
                source: SecretSource::PathBased,
            })
            .collect();
        results.sort_by_key(|s| s.priority);
        results
    }

    /// Add a content-based finding to the detector's priority list.
    /// Used by the content scanner to register findings alongside path-based secrets.
    pub fn add_content_finding(
        &mut self,
        path: &Path,
        priority: SecretPriority,
        description: &str,
    ) {
        let full_path = path.to_path_buf();
        self.exact_paths.insert(full_path.clone());
        self.path_priorities
            .push((full_path, priority, description.to_string()));
    }

    /// Every ranked location on the watch list, with whether it exists on
    /// disk. Sorted by priority; within a priority, present locations first.
    ///
    /// The watch list itself is unchanged by this: the taint engine keeps
    /// tracking opens of absent paths in case they appear later. Reporting
    /// is a different matter. A path that is not on the machine must not be
    /// shown as "found", and nothing absent can honestly be called protected.
    pub fn watched_locations(&self) -> Vec<WatchedLocation> {
        let mut seen: HashSet<&PathBuf> = HashSet::with_capacity(self.path_priorities.len());
        let mut results: Vec<WatchedLocation> = self
            .path_priorities
            .iter()
            .filter(|(path, _, _)| seen.insert(path))
            .map(|(path, priority, description)| WatchedLocation {
                path: path.clone(),
                priority: *priority,
                description: description.clone(),
                present: path.exists(),
                self_protection: self.self_protection_paths.contains(path),
            })
            .collect();
        results.sort_by_key(|s| (s.priority, !s.present));
        results
    }

    /// The watched *credential* locations: Gorse's own files are left
    /// out, present or not. This is the list `scan --all` should show.
    pub fn credential_locations(&self) -> Vec<WatchedLocation> {
        self.watched_locations()
            .into_iter()
            .filter(|l| !l.self_protection)
            .collect()
    }

    /// The watched credential locations that exist on this machine. This is
    /// the honest "found" list for `status`, `scan` and the dashboard.
    pub fn present_locations(&self) -> Vec<WatchedLocation> {
        self.credential_locations()
            .into_iter()
            .filter(|l| l.present)
            .collect()
    }

    /// Number of watched credential locations that exist on this machine.
    pub fn present_count(&self) -> usize {
        self.present_locations().len()
    }

    /// Count of protected vs unprotected secrets by tier slot (engine view).
    ///
    /// This counts watch-list *slots* against the tier's display limit and
    /// says nothing about whether the paths exist or whether any enforcement
    /// layer is running. It is kept for the engine, FFI and tier tests. User
    /// facing output must use [`present_locations`](Self::present_locations)
    /// and decide "protected" from what is actually enforcing.
    pub fn protection_summary(&self) -> (usize, usize) {
        let total = self.path_priorities.len();
        let protected = total.min(self.display_limit);
        (protected, total.saturating_sub(protected))
    }

    /// Add an exact secret file path.
    pub fn add_path(&mut self, path: &str) {
        self.exact_paths.insert(PathBuf::from(path));
    }

    /// Add a directory whose contents are all secrets.
    pub fn add_dir(&mut self, dir: &str) {
        self.secret_dirs.insert(PathBuf::from(dir));
    }

    /// Add a filename that is always a secret regardless of directory.
    pub fn add_name(&mut self, name: &str) {
        self.secret_names.insert(name.to_string());
    }

    /// Load default known secret locations with priority rankings.
    /// Critical secrets are protected first on the free tier.
    fn load_defaults(&mut self) {
        // Get home directory. Windows normally sets USERPROFILE, not HOME;
        // without this fallback a Windows machine learns none of the default
        // secret locations.
        let home = match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            Ok(h) if !h.is_empty() => PathBuf::from(h),
            _ => return, // Can't detect defaults without a home directory
        };

        // Everything rooted at a home directory
        self.add_user_home(&home);

        // Filenames that are always secrets (these count as Critical)
        self.secret_names.insert(".env".to_string());
        self.secret_names.insert(".env.local".to_string());
        self.secret_names.insert(".env.production".to_string());
        self.secret_names.insert(".env.staging".to_string());
        self.secret_names.insert(".env.development".to_string());
        self.secret_names.insert(".secrets".to_string());

        // Exported credential stores carry the same secrets as the store.
        self.secret_names.insert("credentials.xml".to_string());
        self.secret_names.insert("securestring.xml".to_string());

        // T-19: system keychain — not under any user's home.
        #[cfg(target_os = "macos")]
        self.watch(
            PathBuf::from("/Library/Keychains/System.keychain"),
            Kind::File,
            SecretPriority::Critical,
            "macOS System Keychain",
        );

        // Machine-wide Windows Vault, outside every profile.
        #[cfg(windows)]
        {
            let program_data =
                std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
            self.watch(
                PathBuf::from(program_data).join("Microsoft\\Vault"),
                Kind::Dir,
                SecretPriority::Critical,
                "Windows Vault",
            );
        }
    }

    /// Register every default secret location for the user whose home
    /// directory is `home` (~/.ssh, ~/.aws/credentials, ...).
    ///
    /// `load_defaults` calls this once for `$HOME`. The macOS system extension
    /// runs as root, so its own HOME is /var/root; it calls this again for
    /// each real user under /Users so their secrets are tracked too.
    ///
    /// Every entry here is on the reported watch list: `gorse status` and
    /// `scan --all` list it, the Fast Scan checks whether it exists and hands
    /// it to TruffleHog, and the agent guard treats reads of it as secret
    /// access. The register in hedgehog-cli/data/credential-locations.toml
    /// records the published source for each one; a test there fails when
    /// this list and the register drift apart.
    ///
    /// Priority ranking is global: after each call the whole list is re-ranked
    /// so every user's Critical secrets fill the free-tier slots before
    /// anyone's High or Medium ones.
    pub fn add_user_home(&mut self, home: &Path) {
        // Gorse's own logs — contain block events, taint details, approved
        // commands. Guarded, not reported.
        self.secret_dirs.insert(home.join(".hedgehog/logs"));

        for (path, kind, priority, description) in HOME_LOCATIONS {
            let full_path = home.join(path);
            if is_self_protection_path(path) {
                self.self_protection_paths.insert(full_path.clone());
            }
            self.watch(full_path, *kind, *priority, description);
        }

        #[cfg(target_os = "macos")]
        for (path, kind, priority, description) in MACOS_HOME_LOCATIONS {
            self.watch(home.join(path), *kind, *priority, description);
        }

        #[cfg(target_os = "linux")]
        for (path, kind, priority, description) in LINUX_HOME_LOCATIONS {
            self.watch(home.join(path), *kind, *priority, description);
        }

        #[cfg(windows)]
        {
            // %APPDATA% and %LOCALAPPDATA% normally sit under the profile.
            // When the variables point elsewhere (or this is another user's
            // home) fall back to the standard layout.
            let under_home = |var: &str, default: &str| -> PathBuf {
                std::env::var(var)
                    .ok()
                    .map(PathBuf::from)
                    .filter(|p| p.starts_with(home))
                    .unwrap_or_else(|| home.join(default))
            };
            let appdata = under_home("APPDATA", "AppData\\Roaming");
            let local = under_home("LOCALAPPDATA", "AppData\\Local");
            for (base, path, kind, priority, description) in WINDOWS_HOME_LOCATIONS {
                let root = match base {
                    WinBase::Profile => home,
                    WinBase::Roaming => appdata.as_path(),
                    WinBase::Local => local.as_path(),
                };
                self.watch(root.join(path), *kind, *priority, description);
            }
        }

        // Sort by priority so Critical comes first. The sort is stable, so
        // homes registered earlier keep their order within each priority.
        self.path_priorities.sort_by_key(|(_, p, _)| *p);
    }

    /// Put one location on the watch list: the agent guard learns it as an
    /// exact file or a directory prefix, and it is reported with a priority.
    fn watch(&mut self, path: PathBuf, kind: Kind, priority: SecretPriority, description: &str) {
        match kind {
            Kind::Dir => {
                self.secret_dirs.insert(path.clone());
            }
            Kind::File => {
                self.exact_paths.insert(path.clone());
            }
        }
        self.path_priorities
            .push((path, priority, description.to_string()));
    }
}

/// Whether a watch-list entry is a single file or a directory whose whole
/// contents are secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    File,
    Dir,
}

use Kind::{Dir, File};
use SecretPriority::{Critical, High, Medium};

/// Filename suffixes that mark a secret wherever the file lives: password
/// databases, VPN profiles and exported certificates with private keys.
const SECRET_NAME_SUFFIXES: &[&str] = &[".kdbx", ".ovpn", ".pfx", ".p12"];

/// Watch-list entries under every user's home directory, on every platform.
/// Unix-style relative paths; `Path::join` renders them for the host.
///
/// Free tier of the agent guard protects the top entries by priority, so
/// Critical holds the keys that reach servers and cloud accounts outright,
/// High holds tokens that reach one vendor, Medium holds files that often
/// carry a secret but need not.
const HOME_LOCATIONS: &[(&str, Kind, SecretPriority, &str)] = &[
    // ─── Critical ───
    (".ssh", Dir, Critical, "SSH keys — full server access"),
    (
        ".aws/credentials",
        File,
        Critical,
        "AWS credentials — cloud billing",
    ),
    (
        ".kube/config",
        File,
        Critical,
        "Kubernetes config — cluster access",
    ),
    (
        ".config/gcloud/application_default_credentials.json",
        File,
        Critical,
        "Google Cloud credentials",
    ),
    (
        ".config/gcloud/credentials.db",
        File,
        Critical,
        "Google Cloud user credentials — every signed-in account",
    ),
    (".gnupg", Dir, Critical, "GPG keys — code signing"),
    // ─── High ───
    (
        ".docker/config.json",
        File,
        High,
        "Docker registry credentials",
    ),
    (".npmrc", File, High, "npm token — package publishing"),
    (
        ".pypirc",
        File,
        High,
        "PyPI credentials — package publishing",
    ),
    (".netrc", File, High, "Network credentials (FTP, Git, API)"),
    (
        ".config/stripe/config.toml",
        File,
        High,
        "Stripe API keys — payment processing",
    ),
    (
        ".config/solana/id.json",
        File,
        High,
        "Solana wallet — cryptocurrency",
    ),
    (".config/gh/hosts.yml", File, High, "GitHub CLI token"),
    (
        ".azure/accessTokens.json",
        File,
        High,
        "Azure access tokens",
    ),
    (
        ".azure/msal_token_cache.json",
        File,
        High,
        "Azure CLI token cache — current sign-in",
    ),
    (
        ".config/gcloud/access_tokens.db",
        File,
        High,
        "Google Cloud access token cache",
    ),
    (
        ".config/gcloud/legacy_credentials",
        Dir,
        High,
        "Google Cloud per-account credentials",
    ),
    (
        ".git-credentials",
        File,
        High,
        "Git credential store — plaintext tokens for every remote",
    ),
    (
        ".config/git/credentials",
        File,
        High,
        "Git credential store — plaintext tokens for every remote",
    ),
    (
        ".cargo/credentials.toml",
        File,
        High,
        "Cargo registry token — crate publishing",
    ),
    (
        ".cargo/credentials",
        File,
        High,
        "Cargo registry token — crate publishing",
    ),
    (
        ".composer/auth.json",
        File,
        High,
        "Composer auth — GitHub and GitLab tokens",
    ),
    (
        ".config/composer/auth.json",
        File,
        High,
        "Composer auth — GitHub and GitLab tokens",
    ),
    (
        ".gem/credentials",
        File,
        High,
        "RubyGems API key — gem publishing",
    ),
    (".vault-token", File, High, "HashiCorp Vault token"),
    (".consul-token", File, High, "Consul token"),
    (".pgpass", File, High, "PostgreSQL passwords"),
    (
        ".my.cnf",
        File,
        High,
        "MySQL client config — may hold the password",
    ),
    (
        ".mylogin.cnf",
        File,
        High,
        "MySQL login path file — passwords",
    ),
    (
        ".config/filezilla/sitemanager.xml",
        File,
        High,
        "FileZilla saved servers — FTP/SFTP passwords",
    ),
    (
        ".config/filezilla/recentservers.xml",
        File,
        High,
        "FileZilla recent servers — FTP/SFTP passwords",
    ),
    (
        ".claude/.credentials.json",
        File,
        High,
        "Claude Code sign-in credentials",
    ),
    (
        ".config/anthropic/credentials",
        File,
        High,
        "Anthropic CLI profiles — refresh tokens",
    ),
    (
        ".codex/auth.json",
        File,
        High,
        "Codex CLI sign-in credentials",
    ),
    (
        ".gemini/oauth_creds.json",
        File,
        High,
        "Gemini CLI sign-in credentials",
    ),
    (
        ".gemini/mcp-oauth-tokens.json",
        File,
        High,
        "Gemini CLI MCP server tokens",
    ),
    (".cursor/auth.json", File, High, "Cursor CLI sign-in token"),
    (
        ".copilot/providers.json",
        File,
        High,
        "Copilot CLI provider keys — stored as plain text",
    ),
    (
        ".copilot/mcp-secrets",
        File,
        High,
        "Copilot CLI MCP server secrets",
    ),
    (
        ".config/github-copilot/hosts.json",
        File,
        High,
        "Copilot editor sign-in tokens",
    ),
    (
        ".config/github-copilot/apps.json",
        File,
        High,
        "Copilot editor sign-in tokens",
    ),
    (".cache/huggingface/token", File, High, "Hugging Face token"),
    (".huggingface/token", File, High, "Hugging Face token"),
    (
        ".local/share/opencode/auth.json",
        File,
        High,
        "OpenCode sign-in credentials",
    ),
    (
        ".config/goose/secrets.yaml",
        File,
        High,
        "Goose provider keys",
    ),
    (
        ".qwen/oauth_creds.json",
        File,
        High,
        "Qwen Code sign-in credentials",
    ),
    (".augment/session.json", File, High, "Augment session token"),
    (
        ".kimi/credentials/kimi-code.json",
        File,
        High,
        "Kimi Code credentials",
    ),
    (".local/share/amp/secrets.json", File, High, "Amp secrets"),
    (
        ".local/share/devin/credentials.toml",
        File,
        High,
        "Devin CLI credentials",
    ),
    (
        ".config/muse/auth.json",
        File,
        High,
        "Muse sign-in credentials",
    ),
    (
        ".pi/agent/auth.json",
        File,
        High,
        "Pi agent sign-in credentials",
    ),
    (
        ".openclaw/credentials/oauth.json",
        File,
        High,
        "OpenClaw sign-in credentials",
    ),
    (
        ".wrangler",
        Dir,
        High,
        "Cloudflare Wrangler config — API token",
    ),
    // ─── Medium ───
    (
        ".aws/config",
        File,
        Medium,
        "AWS config (may contain SSO settings)",
    ),
    (
        ".azure/azureProfile.json",
        File,
        Medium,
        "Azure CLI profile — subscriptions and tenants",
    ),
    (".vercel/auth.json", File, Medium, "Vercel deployment token"),
    (
        ".config/supabase/access-token",
        File,
        Medium,
        "Supabase access token",
    ),
    (
        ".supabase/access-token",
        File,
        Medium,
        "Supabase access token",
    ),
    (
        ".terraform.d/credentials.tfrc.json",
        File,
        Medium,
        "Terraform Cloud credentials",
    ),
    (".yarnrc.yml", File, Medium, "Yarn registry tokens"),
    (
        ".gitconfig",
        File,
        Medium,
        "Git config — credential helper, sometimes inline tokens",
    ),
    (".m2/settings.xml", File, Medium, "Maven server passwords"),
    (
        ".m2/settings-security.xml",
        File,
        Medium,
        "Maven master password",
    ),
    (
        ".gradle/gradle.properties",
        File,
        Medium,
        "Gradle repository and signing credentials",
    ),
    (
        ".nuget/NuGet/NuGet.Config",
        File,
        Medium,
        "NuGet source credentials",
    ),
    (
        ".config/NuGet/NuGet.Config",
        File,
        Medium,
        "NuGet source credentials",
    ),
    (
        ".config/pip/pip.conf",
        File,
        Medium,
        "pip index URLs — may embed a password",
    ),
    (
        ".pip/pip.conf",
        File,
        Medium,
        "pip index URLs — may embed a password",
    ),
    (
        ".zsh_history",
        File,
        Medium,
        "Shell history — tokens pasted into commands",
    ),
    (
        ".bash_history",
        File,
        Medium,
        "Shell history — tokens pasted into commands",
    ),
    (
        ".zshrc",
        File,
        Medium,
        "Shell start-up file — exported API keys",
    ),
    (
        ".zprofile",
        File,
        Medium,
        "Shell start-up file — exported API keys",
    ),
    (
        ".zshenv",
        File,
        Medium,
        "Shell start-up file — exported API keys",
    ),
    (
        ".bashrc",
        File,
        Medium,
        "Shell start-up file — exported API keys",
    ),
    (
        ".bash_profile",
        File,
        Medium,
        "Shell start-up file — exported API keys",
    ),
    (
        ".profile",
        File,
        Medium,
        "Shell start-up file — exported API keys",
    ),
    (
        ".claude.json",
        File,
        Medium,
        "Claude Code config — MCP server env and headers",
    ),
    (
        ".claude/backups",
        Dir,
        Medium,
        "Claude Code config backups — MCP server env and headers",
    ),
    (
        ".claude/history.jsonl",
        File,
        Medium,
        "Claude Code prompt history",
    ),
    (
        ".codex/config.toml",
        File,
        Medium,
        "Codex CLI config — MCP server env and headers",
    ),
    (
        ".cursor/mcp.json",
        File,
        Medium,
        "Cursor MCP config — env and headers",
    ),
    (
        ".copilot/config.json",
        File,
        Medium,
        "Copilot CLI config and sign-in data",
    ),
    (
        ".copilot/mcp-config.json",
        File,
        Medium,
        "Copilot CLI MCP config",
    ),
    (
        ".codeium/windsurf/mcp_config.json",
        File,
        Medium,
        "Windsurf MCP config — env and headers",
    ),
    (
        ".config/devin/mcp_config.json",
        File,
        Medium,
        "Devin MCP config — env and headers",
    ),
    (
        ".continue/config.yaml",
        File,
        Medium,
        "Continue config — API keys",
    ),
    (".aider.conf.yml", File, Medium, "Aider config — API keys"),
    (".ollama/id_ed25519", File, Medium, "Ollama identity key"),
    (
        ".anydesk",
        Dir,
        Medium,
        "AnyDesk config — remote access to this machine",
    ),
    // ─── Gorse self-protection (High) ───
    // An agent reading these is reconnaissance against the protection system.
    (
        ".hedgehog/approvals.json",
        File,
        High,
        "Gorse approvals — agent could forge a pending user approval",
    ),
    (
        ".hedgehog/exceptions.log",
        File,
        High,
        "Gorse legacy exception log — reveals blocked commands and justifications",
    ),
    (
        ".hedgehog/config.toml",
        File,
        High,
        "Gorse config — contains allowlist rules an agent could exploit",
    ),
    (
        ".hedgehog/history.db",
        File,
        High,
        "Gorse command history — reveals security patterns and blocked actions",
    ),
    (".hedgehog/license.key", File, High, "Gorse license key"),
    // ─── Agent hook config (High) ───
    // An agent reading/modifying this could disable Gorse protection.
    (
        ".claude/settings.json",
        File,
        High,
        "Claude Code settings — contains Gorse hook config, agent could disable protection",
    ),
    (
        ".gemini/settings.json",
        File,
        High,
        "Gemini CLI settings — contains Gorse hook config, agent could disable protection",
    ),
];

/// macOS-only entries under the home directory (Library paths).
#[cfg(target_os = "macos")]
const MACOS_HOME_LOCATIONS: &[(&str, Kind, SecretPriority, &str)] = &[
    // T-19: accessing these means the process is touching the system
    // credential store directly.
    (
        "Library/Keychains",
        Dir,
        Critical,
        "macOS Keychain — system credential store",
    ),
    (
        "Library/Application Support/Firefox/Profiles",
        Dir,
        High,
        "Firefox profiles — saved logins and cookies",
    ),
    (
        "Library/Application Support/Google/Chrome/Default/Login Data",
        File,
        High,
        "Chrome saved logins",
    ),
    (
        "Library/Application Support/glab-cli/config.yml",
        File,
        High,
        "GitLab CLI tokens",
    ),
    (
        "Library/Preferences/.wrangler/config/default.toml",
        File,
        High,
        "Cloudflare Wrangler API token",
    ),
    (
        "Library/Application Support/Bitwarden CLI/data.json",
        File,
        High,
        "Bitwarden CLI vault copy — offline attack on the master password",
    ),
    (
        "Library/Application Support/Exodus",
        Dir,
        High,
        "Exodus wallet data",
    ),
    (
        "Library/Application Support/Coinomi",
        Dir,
        High,
        "Coinomi wallet data",
    ),
    (
        "Library/Application Support/Wasabi",
        Dir,
        High,
        "Wasabi wallet data",
    ),
    (
        "Library/Application Support/atomic",
        Dir,
        High,
        "Atomic wallet data",
    ),
    (
        "Library/Application Support/Guarda",
        Dir,
        High,
        "Guarda wallet data",
    ),
    (
        "Library/Application Support/Binance",
        Dir,
        High,
        "Binance desktop app data",
    ),
    (
        "Library/Application Support/TON",
        Dir,
        High,
        "TON wallet data",
    ),
    (
        "Library/Application Support/com.vercel.cli/auth.json",
        File,
        Medium,
        "Vercel CLI token",
    ),
    (
        "Library/Preferences/netlify/config.json",
        File,
        Medium,
        "Netlify CLI token",
    ),
    (
        "Library/Preferences/helm/registry/config.json",
        File,
        Medium,
        "Helm registry logins",
    ),
    (
        "Library/Preferences/helm/repositories.yaml",
        File,
        Medium,
        "Helm repository credentials",
    ),
    (
        "Library/Application Support/pip/pip.conf",
        File,
        Medium,
        "pip index URLs — may embed a password",
    ),
    (
        "Library/Application Support/Bitwarden",
        Dir,
        Medium,
        "Bitwarden desktop data",
    ),
    (
        "Library/Application Support/Claude/claude_desktop_config.json",
        File,
        Medium,
        "Claude Desktop MCP config — env written literally",
    ),
    (
        "Library/Application Support/Code/User/mcp.json",
        File,
        Medium,
        "VS Code MCP config — env written literally",
    ),
];

/// Linux-only entries under the home directory (XDG paths and keyrings).
#[cfg(target_os = "linux")]
const LINUX_HOME_LOCATIONS: &[(&str, Kind, SecretPriority, &str)] = &[
    (
        ".local/share/keyrings",
        Dir,
        Critical,
        "GNOME Keyring files",
    ),
    (".local/share/kwalletd", Dir, Critical, "KDE Wallet files"),
    (
        ".mozilla/firefox",
        Dir,
        High,
        "Firefox profiles — saved logins and cookies",
    ),
    (
        ".config/.wrangler/config/default.toml",
        File,
        High,
        "Cloudflare Wrangler API token",
    ),
    (
        ".config/Bitwarden CLI/data.json",
        File,
        High,
        "Bitwarden CLI vault copy — offline attack on the master password",
    ),
    (
        ".local/share/com.vercel.cli/auth.json",
        File,
        Medium,
        "Vercel CLI token",
    ),
    (".config/vercel/auth.json", File, Medium, "Vercel CLI token"),
    (
        ".config/helm",
        Dir,
        Medium,
        "Helm registry logins and repository credentials",
    ),
    (".config/Bitwarden", Dir, Medium, "Bitwarden desktop data"),
    (
        ".config/Claude/claude_desktop_config.json",
        File,
        Medium,
        "Claude Desktop MCP config — env written literally",
    ),
    (
        ".config/Code/User/mcp.json",
        File,
        Medium,
        "VS Code MCP config — env written literally",
    ),
];

/// Which Windows folder a Windows-only entry is relative to.
#[cfg(windows)]
#[derive(Clone, Copy)]
enum WinBase {
    /// %USERPROFILE%
    Profile,
    /// %APPDATA%
    Roaming,
    /// %LOCALAPPDATA%
    Local,
}

/// Windows-only entries: the profile, roaming and local AppData folders.
#[cfg(windows)]
const WINDOWS_HOME_LOCATIONS: &[(WinBase, &str, Kind, SecretPriority, &str)] = &[
    (
        WinBase::Roaming,
        "Microsoft\\Credentials",
        Dir,
        Critical,
        "Windows Credential Manager store",
    ),
    (
        WinBase::Roaming,
        "Microsoft\\Protect",
        Dir,
        Critical,
        "DPAPI master keys",
    ),
    (
        WinBase::Local,
        "Microsoft\\Credentials",
        Dir,
        Critical,
        "Windows Credential Manager store",
    ),
    (
        WinBase::Local,
        "Microsoft\\Vault",
        Dir,
        Critical,
        "Windows Vault",
    ),
    (
        WinBase::Roaming,
        "gcloud\\application_default_credentials.json",
        File,
        Critical,
        "Google Cloud credentials",
    ),
    (
        WinBase::Roaming,
        "gcloud\\credentials.db",
        File,
        Critical,
        "Google Cloud user credentials — every signed-in account",
    ),
    (
        WinBase::Roaming,
        "gnupg",
        Dir,
        Critical,
        "GPG keys — code signing",
    ),
    (
        WinBase::Roaming,
        "gcloud\\access_tokens.db",
        File,
        High,
        "Google Cloud access token cache",
    ),
    (
        WinBase::Roaming,
        "gcloud\\legacy_credentials",
        Dir,
        High,
        "Google Cloud per-account credentials",
    ),
    (
        WinBase::Roaming,
        "GitHub CLI\\hosts.yml",
        File,
        High,
        "GitHub CLI token",
    ),
    (
        WinBase::Roaming,
        "stripe\\config.toml",
        File,
        High,
        "Stripe API keys — payment processing",
    ),
    (
        WinBase::Profile,
        "_netrc",
        File,
        High,
        "Network credentials (FTP, Git, API)",
    ),
    (
        WinBase::Profile,
        ".azure\\msal_token_cache.bin",
        File,
        High,
        "Azure CLI token cache — current sign-in",
    ),
    (
        WinBase::Roaming,
        "FileZilla\\sitemanager.xml",
        File,
        High,
        "FileZilla saved servers — FTP/SFTP passwords",
    ),
    (
        WinBase::Roaming,
        "FileZilla\\recentservers.xml",
        File,
        High,
        "FileZilla recent servers — FTP/SFTP passwords",
    ),
    (
        WinBase::Roaming,
        "Composer\\auth.json",
        File,
        High,
        "Composer auth — GitHub and GitLab tokens",
    ),
    (
        WinBase::Roaming,
        "xdg.config\\.wrangler\\config\\default.toml",
        File,
        High,
        "Cloudflare Wrangler API token",
    ),
    (
        WinBase::Local,
        "glab-cli\\config.yml",
        File,
        High,
        "GitLab CLI tokens",
    ),
    (
        WinBase::Roaming,
        "Bitwarden CLI\\data.json",
        File,
        High,
        "Bitwarden CLI vault copy — offline attack on the master password",
    ),
    (
        WinBase::Roaming,
        "Mozilla\\Firefox\\Profiles",
        Dir,
        High,
        "Firefox profiles — saved logins and cookies",
    ),
    (
        WinBase::Local,
        "Google\\Chrome\\User Data\\Default\\Login Data",
        File,
        High,
        "Chrome saved logins",
    ),
    (
        WinBase::Roaming,
        "Anthropic\\credentials",
        File,
        High,
        "Anthropic CLI profiles — refresh tokens",
    ),
    (
        WinBase::Roaming,
        "devin\\credentials.toml",
        File,
        High,
        "Devin CLI credentials",
    ),
    (
        WinBase::Local,
        "github-copilot\\hosts.json",
        File,
        High,
        "Copilot editor sign-in tokens",
    ),
    (
        WinBase::Local,
        "github-copilot\\apps.json",
        File,
        High,
        "Copilot editor sign-in tokens",
    ),
    (
        WinBase::Roaming,
        "Block\\goose\\config\\secrets.yaml",
        File,
        High,
        "Goose provider keys",
    ),
    (
        WinBase::Roaming,
        "Exodus\\exodus.wallet",
        Dir,
        High,
        "Exodus wallet data",
    ),
    (
        WinBase::Local,
        "Coinomi\\Coinomi\\wallets",
        Dir,
        High,
        "Coinomi wallet data",
    ),
    (
        WinBase::Roaming,
        "atomic\\Local Storage\\leveldb",
        Dir,
        High,
        "Atomic wallet data",
    ),
    (
        WinBase::Roaming,
        "Binance",
        Dir,
        High,
        "Binance desktop app data",
    ),
    (
        WinBase::Roaming,
        "com.vercel.cli\\auth.json",
        File,
        Medium,
        "Vercel CLI token",
    ),
    (
        WinBase::Roaming,
        "terraform.d\\credentials.tfrc.json",
        File,
        Medium,
        "Terraform Cloud credentials",
    ),
    (
        WinBase::Roaming,
        "Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        File,
        Medium,
        "PowerShell history — tokens pasted into commands",
    ),
    (
        WinBase::Roaming,
        "NuGet\\NuGet.Config",
        File,
        Medium,
        "NuGet source credentials",
    ),
    (
        WinBase::Roaming,
        "pip\\pip.ini",
        File,
        Medium,
        "pip index URLs — may embed a password",
    ),
    (
        WinBase::Roaming,
        "helm\\registry\\config.json",
        File,
        Medium,
        "Helm registry logins",
    ),
    (
        WinBase::Roaming,
        "netlify\\Config\\config.json",
        File,
        Medium,
        "Netlify CLI token",
    ),
    (
        WinBase::Roaming,
        "doctl\\config.yaml",
        File,
        Medium,
        "DigitalOcean token",
    ),
    (
        WinBase::Roaming,
        "Bitwarden",
        Dir,
        Medium,
        "Bitwarden desktop data",
    ),
    (
        WinBase::Roaming,
        "Claude\\claude_desktop_config.json",
        File,
        Medium,
        "Claude Desktop MCP config — env written literally",
    ),
    (
        WinBase::Roaming,
        "Code\\User\\mcp.json",
        File,
        Medium,
        "VS Code MCP config — env written literally",
    ),
    (
        WinBase::Roaming,
        "devin\\mcp_config.json",
        File,
        Medium,
        "Devin MCP config — env and headers",
    ),
    (
        WinBase::Roaming,
        "AnyDesk",
        Dir,
        Medium,
        "AnyDesk config — remote access to this machine",
    ),
    (
        WinBase::Profile,
        "OpenVPN\\config",
        Dir,
        Medium,
        "OpenVPN profiles — keys and passwords",
    ),
];
/// Home-relative watch-list entries that are Gorse's own files or the
/// agent settings carrying its hook, rather than the user's credentials.
fn is_self_protection_path(relative: &str) -> bool {
    relative.starts_with(".hedgehog/")
        || relative == ".claude/settings.json"
        || relative == ".gemini/settings.json"
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn detector() -> SecretDetector {
        let mut d = SecretDetector::empty();
        d.add_path("/Users/test/.aws/credentials");
        d.add_dir("/Users/test/.ssh");
        d.add_name(".env");
        d
    }

    #[test]
    fn exact_path_match() {
        let d = detector();
        assert!(d.is_secret(Path::new("/Users/test/.aws/credentials")));
    }

    #[test]
    fn dir_prefix_match() {
        let d = detector();
        assert!(d.is_secret(Path::new("/Users/test/.ssh/id_rsa")));
        assert!(d.is_secret(Path::new("/Users/test/.ssh/id_ed25519")));
        assert!(d.is_secret(Path::new("/Users/test/.ssh/known_hosts"))); // Even this
    }

    #[test]
    fn filename_match() {
        let d = detector();
        assert!(d.is_secret(Path::new("/any/project/dir/.env")));
        assert!(d.is_secret(Path::new("/deep/nested/path/.env")));
    }

    #[test]
    fn env_variants_caught() {
        let d = detector();
        // .env.* variants caught by starts_with(".env") check
        assert!(d.is_secret(Path::new("/project/.env.local")));
        assert!(d.is_secret(Path::new("/project/.env.production")));
        assert!(d.is_secret(Path::new("/project/.env.staging")));
    }

    #[test]
    fn add_user_home_registers_defaults_for_that_home_only() {
        let mut d = SecretDetector::empty();
        d.add_user_home(Path::new("/Users/alice"));
        assert!(d.is_secret(Path::new("/Users/alice/.aws/credentials")));
        assert!(d.is_secret(Path::new("/Users/alice/.ssh/id_rsa")));
        assert!(d.is_secret(Path::new("/Users/alice/.gnupg/secring.gpg")));
        assert!(d.is_secret(Path::new("/Users/alice/.npmrc")));
        assert!(!d.is_secret(Path::new("/Users/bob/.ssh/id_rsa")));
        assert!(!d.is_secret(Path::new("/Users/bob/.aws/credentials")));
    }

    #[test]
    fn second_home_critical_secrets_stay_within_free_tier_limit() {
        // Free tier: 15 advertised + 10 monitor reserve. $HOME's defaults
        // alone can fill every slot, so a second home must be re-ranked in
        // rather than appended after them.
        let mut d = SecretDetector::with_limit(25, 15);
        d.add_user_home(Path::new("/Users/alice"));
        assert!(d.is_secret(Path::new("/Users/alice/.ssh/id_ed25519")));
        assert!(d.is_secret(Path::new("/Users/alice/.aws/credentials")));
        assert!(d.is_secret(Path::new("/Users/alice/.kube/config")));
    }

    #[test]
    fn watched_locations_report_only_what_exists_as_present() {
        let home = std::env::temp_dir().join(format!(
            "hedgehog-secrets-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::write(home.join(".aws/credentials"), "[default]\n").unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();

        let mut d = SecretDetector::empty();
        d.add_user_home(&home);

        let watched = d.watched_locations();
        assert!(watched.len() > 2, "the whole watch list is still reported");
        let present = d.present_locations();
        let present_paths: Vec<_> = present.iter().map(|l| l.path.clone()).collect();
        assert_eq!(
            present_paths,
            vec![home.join(".ssh"), home.join(".aws/credentials")],
            "only the file and directory on disk count as found"
        );
        assert_eq!(d.present_count(), 2);
        assert!(present.iter().all(|l| l.present));
        assert!(watched
            .iter()
            .filter(|l| l.path == home.join(".kube/config"))
            .all(|l| !l.present));

        // The watch list is untouched: absent paths are still secrets.
        assert!(d.is_secret(&home.join(".kube/config")));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn hedgehog_own_files_are_watched_but_not_counted_as_credentials() {
        let home = std::env::temp_dir().join(format!(
            "hedgehog-secrets-self-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(home.join(".gemini/settings.json"), "{}").unwrap();
        std::fs::create_dir_all(home.join(".hedgehog")).unwrap();
        std::fs::write(home.join(".hedgehog/config.toml"), "").unwrap();
        std::fs::write(home.join(".npmrc"), "//registry/:_authToken=x").unwrap();

        let mut d = SecretDetector::empty();
        d.add_user_home(&home);

        // Still secrets for taint tracking.
        assert!(d.is_secret(&home.join(".claude/settings.json")));
        assert!(d.is_secret(&home.join(".gemini/settings.json")));
        assert!(d.is_secret(&home.join(".hedgehog/config.toml")));

        // Flagged on the full list, absent from the credential lists.
        let watched = d.watched_locations();
        assert!(watched
            .iter()
            .any(|l| l.self_protection && l.path == home.join(".hedgehog/config.toml")));
        assert!(watched
            .iter()
            .any(|l| l.self_protection && l.path == home.join(".claude/settings.json")));
        assert!(d.credential_locations().iter().all(|l| !l.self_protection));
        let present: Vec<_> = d.present_locations().into_iter().map(|l| l.path).collect();
        assert_eq!(present, vec![home.join(".npmrc")]);
        assert_eq!(d.present_count(), 1);

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn present_count_is_zero_for_an_empty_home() {
        let home = std::env::temp_dir().join(format!(
            "hedgehog-secrets-empty-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let mut d = SecretDetector::empty();
        d.add_user_home(&home);
        assert_eq!(d.present_count(), 0);
        assert!(d.present_locations().is_empty());
        // The engine's slot count is unaffected by what is on disk.
        let (protected, _) = d.protection_summary();
        assert!(protected > 0);
    }

    #[test]
    fn name_rules_catch_exports_and_password_databases() {
        let d = SecretDetector::empty();
        // Filename suffixes: password databases, VPN profiles, exported certificates.
        assert!(d.is_secret(Path::new("/Users/test/Documents/Passwords.kdbx")));
        assert!(d.is_secret(Path::new("/Users/test/Downloads/office.ovpn")));
        assert!(d.is_secret(Path::new("C:\\Users\\test\\Desktop\\signing.pfx")));
        assert!(d.is_secret(Path::new("/tmp/cert.p12")));
        assert!(!d.is_secret(Path::new("/Users/test/Documents/notes.txt")));
        assert!(!d.is_secret(Path::new("/Users/test/src/p12.rs")));

        // Exported credential stores are filenames learned by the defaults.
        let d = SecretDetector::new();
        assert!(d.is_secret(Path::new("/Users/test/Desktop/credentials.xml")));
        assert!(d.is_secret(Path::new("/Users/test/Desktop/securestring.xml")));
    }

    #[test]
    fn home_list_is_reported_with_priorities_on_every_platform() {
        let home = Path::new("/Users/test");
        let mut d = SecretDetector::empty();
        d.add_user_home(home);
        let watched = d.credential_locations();
        let has = |rel: &str| watched.iter().any(|l| l.path == home.join(rel));
        // A sample across the families the register cites.
        for rel in [
            ".ssh",
            ".config/gcloud/credentials.db",
            ".git-credentials",
            ".cargo/credentials.toml",
            ".config/filezilla/sitemanager.xml",
            ".zsh_history",
            ".zshrc",
            ".claude/.credentials.json",
            ".codex/auth.json",
            ".cursor/mcp.json",
            ".pgpass",
        ] {
            assert!(has(rel), "{rel} is on the reported watch list");
            assert!(d.is_secret(&home.join(rel)), "{rel} is known to the guard");
        }
        // Directories guard everything beneath them.
        assert!(d.is_secret(&home.join(".anydesk/service.conf")));
        assert!(d.is_secret(&home.join(".claude/backups/x.json")));
        // Critical entries come first.
        assert_eq!(watched[0].priority, SecretPriority::Critical);
        assert!(
            watched
                .iter()
                .filter(|l| l.priority == SecretPriority::Critical)
                .count()
                >= 6
        );
    }

    #[test]
    fn normal_files_not_secret() {
        let d = detector();
        assert!(!d.is_secret(Path::new("/Users/test/src/main.rs")));
        assert!(!d.is_secret(Path::new("/tmp/foo.txt")));
        assert!(!d.is_secret(Path::new("/Users/test/README.md")));
    }
}
