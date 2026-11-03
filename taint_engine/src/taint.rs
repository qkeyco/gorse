// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Core taint tracking engine.
//!
//! Maintains a map of PID → TaintInfo. When a process reads a secret file
//! or connects to a secret provider (Vault, AWS Secrets Manager, 1Password, etc.),
//! it becomes tainted. Taint propagates through fork/exec. Tainted processes
//! are blocked from network connections to non-allowlisted destinations.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::allowlist::Allowlist;
use crate::clipboard::ClipboardTracker;
use crate::container::ContainerPathResolver;
use crate::derived::DerivedSecretTracker;
use crate::ipc::IpcTracker;
use crate::localhost::LocalhostTracker;
use crate::logger::{EventLogger, EventType, LogEntry};
use crate::process_tree::ProcessTree;
use crate::project::ProjectRegistry;
use crate::secret_providers::SecretProviderRegistry;
use crate::secrets::SecretDetector;
use crate::tier::{License, Tier};

/// Decision returned by the taint engine for authorization events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum Decision {
    /// Allow the operation to proceed.
    Allow = 0,
    /// Allow the file open but mark the process as tainted.
    Taint = 1,
    /// Block the network connection.
    Block = 2,
}

/// Information about why a process is tainted.
#[derive(Debug, Clone)]
pub struct TaintInfo {
    pub pid: i32,
    pub tainted_at: Instant,
    /// Which secret file caused the initial taint.
    pub source_file: PathBuf,
    /// All secret files this process has accessed.
    pub accessed_files: Vec<PathBuf>,
    /// The executable path of the tainted process.
    pub process_path: Option<PathBuf>,
    /// Parent PID if taint was inherited via fork.
    pub inherited_from: Option<i32>,
    /// Last time this process accessed a secret file.
    pub last_access: Instant,
}

/// Statistics about the taint engine's current state.
#[derive(Debug, Clone, Default)]
pub struct TaintStats {
    pub tainted_processes: usize,
    pub total_taints: u64,
    pub total_blocks: u64,
    pub total_allows: u64,
    pub total_propagations: u64,
}

/// Configuration for the taint engine.
pub struct TaintConfig {
    /// How long taint persists after the last secret file access.
    /// None = taint only cleared on process exit.
    pub taint_ttl: Option<Duration>,
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            // A process can retain a credential in memory indefinitely.
            // Clear taint on exit; elapsed time is not evidence of erasure.
            taint_ttl: None,
        }
    }
}

/// The main taint tracking engine.
pub struct TaintEngine {
    /// Host-selected containment policy. Unlike destination allowlists, this
    /// also denies DNS and local relays after a detected secret access.
    deny_tainted_network: bool,
    tainted: HashMap<i32, TaintInfo>,
    secrets: SecretDetector,
    allowlist: Allowlist,
    process_tree: ProcessTree,
    logger: EventLogger,
    config: TaintConfig,
    stats: TaintStats,
    // v0.3: Localhost relay detection
    localhost: LocalhostTracker,
    // v0.4: Per-project allowlist scoping
    projects: ProjectRegistry,
    // v0.5: Write taint propagation
    derived: DerivedSecretTracker,
    // v0.6: Secret provider endpoint taint
    secret_providers: SecretProviderRegistry,
    // v0.7: Container path resolution
    container: ContainerPathResolver,
    // v0.8: Clipboard monitoring
    clipboard: ClipboardTracker,
    // v0.8: IPC/pipe taint propagation
    ipc: IpcTracker,
    // Licensing
    license: License,
}

impl TaintEngine {
    /// Enable the host's strict egress policy without clearing existing taint.
    /// This policy is independent of paid feature limits.
    pub fn set_deny_tainted_network(&mut self, enabled: bool) {
        self.deny_tainted_network = enabled;
    }

    /// Apply a lease already verified by the trusted platform host. The core
    /// does not verify signatures. Absolute expiry cannot be extended by a
    /// restart, and replacing the lease never clears existing process taint.
    pub fn set_verified_lease(&mut self, tier: Tier, expires_at: u64) {
        let now = SystemTime::now();
        let expiry = UNIX_EPOCH.checked_add(Duration::from_secs(expires_at));
        self.license = match expiry {
            Some(expiry)
                if tier != Tier::Free
                    && expiry > now
                    && expiry
                        .duration_since(now)
                        .is_ok_and(|left| left.as_secs() <= 86400) =>
            {
                License {
                    tier,
                    expires_at: Some(expiry),
                    key: None,
                }
            }
            _ => License::free(),
        };
        self.refresh_secret_limits();
    }

    fn refresh_secret_limits(&mut self) {
        let limits = self.license.limits();
        self.secrets.set_max_protected(
            limits.effective_secret_limit(),
            limits.max_protected_secrets,
        );
    }

    /// Create a new taint engine with default configuration (free tier).
    pub fn new() -> Self {
        let license = License::free();
        let limits = license.limits();
        Self {
            deny_tainted_network: false,
            tainted: HashMap::with_capacity(256),
            secrets: SecretDetector::with_limit(
                limits.effective_secret_limit(),
                limits.max_protected_secrets,
            ),
            allowlist: Allowlist::new(),
            process_tree: ProcessTree::new(),
            logger: EventLogger::new(),
            config: TaintConfig::default(),
            stats: TaintStats::default(),
            localhost: LocalhostTracker::new(),
            projects: ProjectRegistry::new(),
            derived: DerivedSecretTracker::new(),
            secret_providers: SecretProviderRegistry::new(),
            container: ContainerPathResolver::new(),
            clipboard: ClipboardTracker::new(),
            ipc: IpcTracker::new(),
            license,
        }
    }

    /// Create with custom config (free tier).
    pub fn with_config(config: TaintConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    /// Activate a license (upgrade tier).
    pub fn activate_license(&mut self, tier: Tier, key: String, valid_days: u64) {
        self.license = License::licensed(tier, key, valid_days);
        let limits = self.license.limits();
        self.secrets.set_max_protected(
            limits.effective_secret_limit(),
            limits.max_protected_secrets,
        );

        self.logger.log(LogEntry {
            event: EventType::Tainted, // reuse for now
            pid: 0,
            detail: format!(
                "License activated: {} ({})",
                tier.name(),
                tier.price_display()
            ),
        });
    }

    /// Get current license info.
    pub fn license(&self) -> &License {
        &self.license
    }

    /// Get protection summary: (protected, unprotected) secret counts.
    pub fn protection_summary(&self) -> (usize, usize) {
        self.secrets.protection_summary()
    }

    // ─── Event Handlers (called from ESF / ETW / eBPF) ───

    /// A process opened a file. If it's a secret (or derived secret), taint the process.
    /// Always returns Allow or Taint (never blocks file opens).
    pub fn on_file_open(&mut self, pid: i32, path: &Path) -> Decision {
        self.refresh_secret_limits();
        // v0.7: Resolve container paths to host paths
        let resolved;
        let check_path = if self.container.in_container() {
            if let Some(host_path) = self.container.resolve_to_host(path) {
                resolved = host_path;
                &resolved
            } else {
                path
            }
        } else {
            path
        };

        // v0.7: Container secret paths are always treated as secrets
        let is_container_secret = ContainerPathResolver::is_container_secret(path);

        // v0.5: Check derived secrets in addition to original secrets
        let is_original = self.secrets.is_secret(check_path) || is_container_secret;
        let is_derived = self.derived.is_derived_secret(check_path);

        if !is_original && !is_derived {
            return Decision::Allow;
        }

        let now = Instant::now();

        if let Some(existing) = self.tainted.get_mut(&pid) {
            // Repeated reads must not grow authorization-path memory forever.
            // The original source and taint remain regardless of this display cap.
            if existing.accessed_files.len() < 64
                && !existing.accessed_files.iter().any(|p| p == path)
            {
                existing.accessed_files.push(path.to_path_buf());
            }
            existing.last_access = now;
        } else {
            self.tainted.insert(
                pid,
                TaintInfo {
                    pid,
                    tainted_at: now,
                    source_file: path.to_path_buf(),
                    accessed_files: vec![path.to_path_buf()],
                    process_path: None,
                    inherited_from: None,
                    last_access: now,
                },
            );
            self.stats.total_taints += 1;
        }

        self.logger.log(LogEntry {
            event: EventType::Tainted,
            pid,
            detail: format!("PID {} tainted: read {}", pid, path.display()),
        });

        Decision::Taint
    }

    /// A process wants to connect to a network address.
    /// If tainted and destination not allowlisted → Block.
    /// v0.6: If destination is a secret provider, taint the process first.
    pub fn on_connect(&mut self, pid: i32, addr: &str, port: u16) -> Decision {
        self.cleanup_expired();

        if self.deny_tainted_network && self.tainted.contains_key(&pid) {
            self.stats.total_blocks += 1;
            return Decision::Block;
        }

        // v0.6: Secret provider endpoint detection.
        // If the process is connecting to a vault/secrets manager/password manager,
        // it will receive secrets — taint it now so future connections are restricted.
        if !self.tainted.contains_key(&pid) {
            if let Some(provider_match) = self.secret_providers.check(addr) {
                let now = Instant::now();
                let source = PathBuf::from(format!(
                    "<secret-provider:{}:{}>",
                    provider_match.endpoint, port
                ));
                self.tainted.insert(
                    pid,
                    TaintInfo {
                        pid,
                        tainted_at: now,
                        source_file: source,
                        accessed_files: Vec::new(),
                        process_path: None,
                        inherited_from: None,
                        last_access: now,
                    },
                );
                self.stats.total_taints += 1;

                self.logger.log(LogEntry {
                    event: EventType::Tainted,
                    pid,
                    detail: format!(
                        "PID {} tainted: connected to {} ({})",
                        pid, provider_match.endpoint, provider_match.provider_name
                    ),
                });

                // Strict mode has no trusted secret-fetch channel. Deny at
                // flow creation rather than allowing a handshake whose first
                // outgoing data callback would immediately be denied.
                if self.deny_tainted_network {
                    self.stats.total_blocks += 1;
                    return Decision::Block;
                }
                // Legacy destination policy allows the initial secret fetch.
                self.stats.total_allows += 1;
                return Decision::Allow;
            }
        }

        // v0.3: If connecting to localhost, check for relay and propagate taint
        // (requires Pro tier for localhost detection)
        if is_localhost_addr(addr) {
            if self.license.limits().localhost_detection && self.tainted.contains_key(&pid) {
                let relay_targets = self.localhost.on_localhost_connect(pid, port);
                for target_pid in relay_targets {
                    if !self.tainted.contains_key(&target_pid) {
                        if let Some(source_taint) = self.tainted.get(&pid).cloned() {
                            let now = std::time::Instant::now();
                            self.tainted.insert(
                                target_pid,
                                TaintInfo {
                                    pid: target_pid,
                                    tainted_at: now,
                                    source_file: source_taint.source_file.clone(),
                                    accessed_files: Vec::new(),
                                    process_path: None,
                                    inherited_from: Some(pid),
                                    last_access: now,
                                },
                            );
                            self.stats.total_propagations += 1;
                            self.logger.log(LogEntry {
                                event: EventType::Propagated,
                                pid: target_pid,
                                detail: format!(
                                    "Taint relay: PID {} → localhost:{} → PID {}",
                                    pid, port, target_pid
                                ),
                            });
                        }
                    }
                }
            }
            // Localhost connections are always allowed (we just propagate taint)
            self.stats.total_allows += 1;
            return Decision::Allow;
        }

        let taint = match self.tainted.get(&pid) {
            Some(t) => t,
            None => {
                self.stats.total_allows += 1;
                return Decision::Allow;
            }
        };

        // v0.4: Check project-specific allowlist first (requires Pro tier)
        if self.license.limits().project_scoping {
            if let Some(allowed) = self.projects.is_allowed_for_pid(pid, addr, port) {
                if allowed {
                    self.stats.total_allows += 1;
                    return Decision::Allow;
                } else {
                    // Project allowlist explicitly denies — block even if global allows
                    self.stats.total_blocks += 1;
                    self.logger.log(LogEntry {
                        event: EventType::Blocked,
                        pid,
                        detail: format!(
                            "BLOCKED (project scope): PID {} (tainted by {}) → {}:{}",
                            pid,
                            taint.source_file.display(),
                            addr,
                            port
                        ),
                    });
                    return Decision::Block;
                }
            }
        }

        // Fall through to global allowlist
        if self.allowlist.is_allowed(addr, port) {
            self.stats.total_allows += 1;
            return Decision::Allow;
        }

        // BLOCKED
        self.stats.total_blocks += 1;

        self.logger.log(LogEntry {
            event: EventType::Blocked,
            pid,
            detail: format!(
                "BLOCKED: PID {} (tainted by {}) → {}:{}",
                pid,
                taint.source_file.display(),
                addr,
                port
            ),
        });

        Decision::Block
    }

    /// A process forked. If parent is tainted, child inherits taint.
    pub fn on_fork(&mut self, parent_pid: i32, child_pid: i32) {
        self.process_tree.add_child(parent_pid, child_pid);
        // v0.4: Propagate project assignment
        self.projects.on_fork(parent_pid, child_pid);

        if let Some(parent_taint) = self.tainted.get(&parent_pid).cloned() {
            let now = Instant::now();
            self.tainted.insert(
                child_pid,
                TaintInfo {
                    pid: child_pid,
                    tainted_at: now,
                    source_file: parent_taint.source_file.clone(),
                    accessed_files: parent_taint.accessed_files.clone(),
                    process_path: None,
                    inherited_from: Some(parent_pid),
                    last_access: now,
                },
            );
            self.stats.total_propagations += 1;

            self.logger.log(LogEntry {
                event: EventType::Propagated,
                pid: child_pid,
                detail: format!("Taint: PID {} → PID {} (fork)", parent_pid, child_pid),
            });
        }
    }

    /// A process exec'd a new binary. Update executable path, keep taint.
    pub fn on_exec(&mut self, pid: i32, new_executable: &Path) {
        if let Some(taint) = self.tainted.get_mut(&pid) {
            taint.process_path = Some(new_executable.to_path_buf());
        }
    }

    /// A process exited. Remove taint and process tree entry.
    pub fn on_exit(&mut self, pid: i32) {
        self.tainted.remove(&pid);
        self.process_tree.remove(pid);
        // v0.3: Clean up localhost listeners
        self.localhost.on_exit(pid);
        // v0.4: Clean up project assignment
        self.projects.on_exit(pid);
        // v0.8: Clean up clipboard and IPC state
        self.clipboard.on_exit(pid);
        self.ipc.on_exit(pid);
    }

    // ─── v0.8: Clipboard monitoring ───

    /// A process wrote to the clipboard (pbcopy, xclip, etc.).
    /// Returns true if the clipboard became tainted.
    pub fn on_clipboard_write(&mut self, pid: i32, content_hash: u64) -> bool {
        let is_tainted = self.tainted.contains_key(&pid);
        let result = self
            .clipboard
            .on_clipboard_write(pid, is_tainted, content_hash);
        if result {
            self.logger.log(LogEntry {
                event: EventType::Tainted,
                pid,
                detail: format!("Clipboard tainted by PID {}", pid),
            });
        }
        result
    }

    /// A process read from the clipboard (pbpaste, xsel, etc.).
    /// Returns true if the clipboard was tainted (for audit warning).
    pub fn on_clipboard_read(&mut self, pid: i32) -> bool {
        let result = self.clipboard.on_clipboard_read(pid);
        if result {
            self.logger.log(LogEntry {
                event: EventType::Tainted,
                pid,
                detail: format!("PID {} read tainted clipboard", pid),
            });
        }
        result
    }

    // ─── v0.8: IPC/pipe taint propagation ───

    /// A process wrote to a named pipe or Unix domain socket.
    /// If the writer is tainted, propagates taint to readers.
    pub fn on_ipc_write(&mut self, pid: i32, path: &Path) {
        let is_tainted = self.tainted.contains_key(&pid);
        let targets = self.ipc.on_ipc_write(pid, path, is_tainted);

        if is_tainted {
            let source_taint = self.tainted.get(&pid).cloned();
            for target_pid in targets {
                if !self.tainted.contains_key(&target_pid) {
                    if let Some(ref source) = source_taint {
                        let now = Instant::now();
                        self.tainted.insert(
                            target_pid,
                            TaintInfo {
                                pid: target_pid,
                                tainted_at: now,
                                source_file: source.source_file.clone(),
                                accessed_files: Vec::new(),
                                process_path: None,
                                inherited_from: Some(pid),
                                last_access: now,
                            },
                        );
                        self.stats.total_propagations += 1;
                        self.logger.log(LogEntry {
                            event: EventType::Propagated,
                            pid: target_pid,
                            detail: format!(
                                "IPC taint: PID {} → {} → PID {}",
                                pid,
                                path.display(),
                                target_pid
                            ),
                        });
                    }
                }
            }
        }
    }

    /// A process read from a named pipe or Unix domain socket.
    /// If the channel is tainted, the reader becomes tainted.
    pub fn on_ipc_read(&mut self, pid: i32, path: &Path) {
        if self.ipc.on_ipc_read(pid, path) && !self.tainted.contains_key(&pid) {
            let now = Instant::now();
            self.tainted.insert(
                pid,
                TaintInfo {
                    pid,
                    tainted_at: now,
                    source_file: PathBuf::from(format!("<ipc:{}>", path.display())),
                    accessed_files: Vec::new(),
                    process_path: None,
                    inherited_from: None,
                    last_access: now,
                },
            );
            self.stats.total_taints += 1;
            self.logger.log(LogEntry {
                event: EventType::Tainted,
                pid,
                detail: format!("PID {} tainted via IPC: {}", pid, path.display()),
            });
        }
    }

    // ─── Query methods ───

    pub fn is_tainted(&self, pid: i32) -> bool {
        self.tainted.contains_key(&pid)
    }

    pub fn get_taint(&self, pid: i32) -> Option<&TaintInfo> {
        self.tainted.get(&pid)
    }

    pub fn tainted_count(&self) -> usize {
        self.tainted.len()
    }

    pub fn stats(&self) -> &TaintStats {
        &self.stats
    }

    pub fn secrets_mut(&mut self) -> &mut SecretDetector {
        &mut self.secrets
    }

    pub fn allowlist_mut(&mut self) -> &mut Allowlist {
        &mut self.allowlist
    }

    pub fn localhost_mut(&mut self) -> &mut LocalhostTracker {
        &mut self.localhost
    }

    pub fn projects_mut(&mut self) -> &mut ProjectRegistry {
        &mut self.projects
    }

    pub fn derived_mut(&mut self) -> &mut DerivedSecretTracker {
        &mut self.derived
    }

    pub fn secret_providers_mut(&mut self) -> &mut SecretProviderRegistry {
        &mut self.secret_providers
    }

    pub fn container_mut(&mut self) -> &mut ContainerPathResolver {
        &mut self.container
    }

    pub fn clipboard_mut(&mut self) -> &mut ClipboardTracker {
        &mut self.clipboard
    }

    pub fn ipc_mut(&mut self) -> &mut IpcTracker {
        &mut self.ipc
    }

    pub fn derived_count(&self) -> usize {
        self.derived.count()
    }

    pub fn drain_logs(&mut self) -> Vec<LogEntry> {
        self.logger.drain()
    }

    // ─── v0.3: Localhost relay detection ───

    /// A process started listening on a port.
    pub fn on_listen(&mut self, pid: i32, port: u16) {
        self.localhost.on_listen(pid, port);
    }

    /// A process stopped listening on a port.
    pub fn on_unlisten(&mut self, pid: i32, port: u16) {
        self.localhost.on_unlisten(pid, port);
    }

    /// Report a process's open file descriptors (called by Swift host on taint).
    /// Returns list of non-allowlisted remote addresses for audit.
    pub fn report_open_fds(&mut self, snapshot: crate::localhost::FdSnapshot) -> Vec<String> {
        let mut suspicious = Vec::new();
        for sock in &snapshot.open_sockets {
            if !self
                .allowlist
                .is_allowed(&sock.remote_addr, sock.remote_port)
            {
                suspicious.push(format!("{}:{}", sock.remote_addr, sock.remote_port));
            }
        }
        if !suspicious.is_empty() {
            self.logger.log(LogEntry {
                event: EventType::Blocked,
                pid: snapshot.pid,
                detail: format!(
                    "WARNING: PID {} tainted with pre-existing connections: {:?}",
                    snapshot.pid, suspicious
                ),
            });
        }
        self.localhost.store_fd_snapshot(snapshot);
        suspicious
    }

    // ─── v0.4: Per-project allowlist scoping ───

    /// Set the working directory for a process (determines project scope).
    pub fn set_pid_cwd(&mut self, pid: i32, cwd: &Path) {
        self.projects.set_pid_cwd(pid, cwd);
    }

    // ─── v0.5: Write taint propagation ───

    /// A process wrote to a file. If tainted, mark the file as a derived secret.
    /// Returns true if the file was newly marked as derived.
    /// Requires Pro tier or above (v0.5 feature).
    pub fn on_file_write(&mut self, pid: i32, path: &Path) -> bool {
        if !self.license.limits().derived_tracking {
            return false;
        }
        if let Some(taint) = self.tainted.get(&pid) {
            let source = taint.source_file.clone();
            let marked = self.derived.on_tainted_write(pid, path, &source);
            if marked {
                self.logger.log(LogEntry {
                    event: EventType::Tainted,
                    pid,
                    detail: format!(
                        "Derived secret: PID {} wrote {} (tainted by {})",
                        pid,
                        path.display(),
                        source.display()
                    ),
                });
            }
            marked
        } else {
            false
        }
    }

    fn cleanup_expired(&mut self) {
        if let Some(ttl) = self.config.taint_ttl {
            let now = Instant::now();
            self.tainted
                .retain(|_pid, info| now.duration_since(info.last_access) < ttl);
        }
    }
}

/// Check if an address is localhost.
fn is_localhost_addr(addr: &str) -> bool {
    addr == "localhost"
        || addr == "127.0.0.1"
        || addr == "::1"
        || addr == "0.0.0.0"
        || addr.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_egress_denies_cloud_dns_and_local_relays_after_read() {
        let mut e = engine();
        e.set_deny_tainted_network(true);
        let destinations = [
            ("github.com", 443),
            ("attacker.s3.amazonaws.com", 443),
            ("8.8.8.8", 53),
            ("127.0.0.1", 8080),
            ("::1", 443),
            ("", 0),
        ];
        for (host, port) in destinations {
            assert_eq!(e.on_connect(100, host, port), Decision::Allow);
        }
        assert_eq!(
            e.on_file_open(100, Path::new("/Users/test/.env")),
            Decision::Taint
        );
        for (host, port) in destinations {
            assert_eq!(e.on_connect(100, host, port), Decision::Block);
        }
        e.on_fork(100, 101);
        e.on_exec(101, Path::new("/usr/bin/curl"));
        assert_eq!(e.on_connect(101, "github.com", 443), Decision::Block);
        e.on_exit(101);
        assert_eq!(e.on_connect(101, "github.com", 443), Decision::Allow);
    }

    #[test]
    fn strict_egress_has_no_implicit_secret_provider_exception() {
        let mut e = engine();
        e.set_deny_tainted_network(true);
        assert_eq!(
            e.on_connect(100, "secretsmanager.us-east-1.amazonaws.com", 443),
            Decision::Block
        );
        assert!(e.is_tainted(100));
    }

    #[test]
    fn verified_lease_is_absolute_and_downgrade_preserves_taint() {
        let mut e = engine();
        e.set_deny_tainted_network(true);
        e.on_file_open(100, Path::new("/Users/test/.env"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        e.set_verified_lease(Tier::Pro, now + 60);
        assert_eq!(e.license().effective_tier(), Tier::Pro);
        assert_eq!(
            e.license().expires_at,
            Some(UNIX_EPOCH + Duration::from_secs(now + 60))
        );
        for expiry in [0, now, now + 86402, u64::MAX] {
            e.set_verified_lease(Tier::Pro, expiry);
            assert_eq!(e.license().effective_tier(), Tier::Free);
            assert_eq!(e.on_connect(100, "github.com", 443), Decision::Block);
        }
    }

    fn engine() -> TaintEngine {
        let mut e = TaintEngine::new();
        // Activate Pro tier for full feature testing
        e.activate_license(Tier::Pro, "TEST-KEY".to_string(), 365);
        e.secrets_mut().add_path("/Users/test/.env");
        e.secrets_mut().add_path("/Users/test/.ssh/id_rsa");
        e.allowlist_mut().add_domain("registry.npmjs.org");
        e.allowlist_mut().add_domain("github.com");
        e
    }

    #[test]
    fn non_secret_not_tainted() {
        let mut e = engine();
        assert_eq!(
            e.on_file_open(100, Path::new("/tmp/foo.txt")),
            Decision::Allow
        );
        assert!(!e.is_tainted(100));
    }

    #[test]
    fn secret_taints_process() {
        let mut e = engine();
        assert_eq!(
            e.on_file_open(100, Path::new("/Users/test/.env")),
            Decision::Taint
        );
        assert!(e.is_tainted(100));
    }

    #[test]
    fn sleeping_does_not_clear_default_taint() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.tainted.get_mut(&100).unwrap().last_access = Instant::now() - Duration::from_secs(7200);
        assert_eq!(e.on_connect(100, "exfil.invalid", 443), Decision::Block);
        e.on_exit(100);
        assert_eq!(e.on_connect(100, "exfil.invalid", 443), Decision::Allow);
    }

    #[test]
    fn tainted_blocked_unknown_host() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        assert_eq!(e.on_connect(100, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn tainted_allowed_known_host() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        assert_eq!(
            e.on_connect(100, "registry.npmjs.org", 443),
            Decision::Allow
        );
    }

    #[test]
    fn untainted_allowed_any_host() {
        let mut e = engine();
        assert_eq!(e.on_connect(200, "evil.com", 443), Decision::Allow);
    }

    #[test]
    fn fork_propagates_taint() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_fork(100, 101);
        assert!(e.is_tainted(101));
        assert_eq!(e.on_connect(101, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn fork_chain_propagation() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_fork(100, 101);
        e.on_fork(101, 102);
        e.on_fork(102, 103);
        assert!(e.is_tainted(103));
        assert_eq!(e.on_connect(103, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn exec_preserves_taint() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_exec(100, Path::new("/usr/bin/curl"));
        assert!(e.is_tainted(100));
        assert_eq!(
            e.get_taint(100).unwrap().process_path.as_deref(),
            Some(Path::new("/usr/bin/curl"))
        );
    }

    #[test]
    fn exit_clears_taint() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_exit(100);
        assert!(!e.is_tainted(100));
    }

    #[test]
    fn multiple_secrets_tracked() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_file_open(100, Path::new("/Users/test/.ssh/id_rsa"));
        assert_eq!(e.get_taint(100).unwrap().accessed_files.len(), 2);
    }

    #[test]
    fn untainted_fork_no_propagation() {
        let mut e = engine();
        e.on_fork(200, 201);
        assert!(!e.is_tainted(201));
    }

    #[test]
    fn stats_tracking() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_connect(100, "evil.com", 443);
        e.on_connect(100, "github.com", 443);
        e.on_fork(100, 101);

        assert_eq!(e.stats().total_taints, 1);
        assert_eq!(e.stats().total_blocks, 1);
        assert_eq!(e.stats().total_allows, 1);
        assert_eq!(e.stats().total_propagations, 1);
    }

    // ─── v0.3: Localhost relay tests ───

    #[test]
    fn localhost_relay_propagates_taint() {
        let mut e = engine();
        // PID 200 is a proxy listening on port 9999
        e.on_listen(200, 9999);
        // PID 100 reads a secret
        e.on_file_open(100, Path::new("/Users/test/.env"));
        // PID 100 connects to localhost:9999 (relay attempt)
        let decision = e.on_connect(100, "127.0.0.1", 9999);
        // Localhost always allowed (we don't block local traffic)
        assert_eq!(decision, Decision::Allow);
        // But the listener (200) should now be tainted!
        assert!(e.is_tainted(200));
        // And 200 should be blocked from external connections
        assert_eq!(e.on_connect(200, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn localhost_no_relay_if_not_tainted() {
        let mut e = engine();
        e.on_listen(200, 9999);
        // PID 100 is NOT tainted, connects to localhost
        e.on_connect(100, "127.0.0.1", 9999);
        // Listener should NOT be tainted
        assert!(!e.is_tainted(200));
    }

    #[test]
    fn fd_snapshot_reports_suspicious() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));

        let suspicious = e.report_open_fds(crate::localhost::FdSnapshot {
            pid: 100,
            open_sockets: vec![
                crate::localhost::SocketInfo {
                    fd: 5,
                    remote_addr: "evil.com".to_string(),
                    remote_port: 443,
                    local_port: 54321,
                    socket_type: crate::localhost::SocketType::Tcp,
                },
                crate::localhost::SocketInfo {
                    fd: 6,
                    remote_addr: "github.com".to_string(),
                    remote_port: 443,
                    local_port: 54322,
                    socket_type: crate::localhost::SocketType::Tcp,
                },
            ],
        });
        // evil.com should be flagged, github.com should not
        assert_eq!(suspicious.len(), 1);
        assert!(suspicious[0].contains("evil.com"));
    }

    // ─── v0.4: Project scoping tests ───

    #[test]
    fn project_scoping_restricts_allowlist() {
        let mut e = engine();
        // Register a project that only allows stripe
        let mut project_allowlist = crate::allowlist::Allowlist::empty();
        project_allowlist.add_domain("api.stripe.com");
        e.projects_mut().add_project(crate::project::ProjectConfig {
            name: "webapp".to_string(),
            root: PathBuf::from("/Users/dev/webapp"),
            allowlist: project_allowlist,
        });

        // Assign PID 100 to the webapp project
        e.set_pid_cwd(100, Path::new("/Users/dev/webapp/src"));
        // Taint PID 100
        e.on_file_open(100, Path::new("/Users/test/.env"));

        // Stripe is allowed by project scope
        assert_eq!(e.on_connect(100, "api.stripe.com", 443), Decision::Allow);
        // GitHub is allowed globally but NOT in project scope → blocked
        assert_eq!(e.on_connect(100, "github.com", 443), Decision::Block);
        // Evil is blocked by both
        assert_eq!(e.on_connect(100, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn unscoped_process_uses_global() {
        let mut e = engine();
        // No project assigned — falls through to global
        e.on_file_open(100, Path::new("/Users/test/.env"));
        assert_eq!(e.on_connect(100, "github.com", 443), Decision::Allow);
    }

    #[test]
    fn project_scope_inherited_on_fork() {
        let mut e = engine();
        let mut project_allowlist = crate::allowlist::Allowlist::empty();
        project_allowlist.add_domain("api.stripe.com");
        e.projects_mut().add_project(crate::project::ProjectConfig {
            name: "webapp".to_string(),
            root: PathBuf::from("/Users/dev/webapp"),
            allowlist: project_allowlist,
        });
        e.set_pid_cwd(100, Path::new("/Users/dev/webapp"));
        e.on_file_open(100, Path::new("/Users/test/.env"));

        // Fork: child inherits project scope
        e.on_fork(100, 101);
        assert_eq!(e.on_connect(101, "api.stripe.com", 443), Decision::Allow);
        assert_eq!(e.on_connect(101, "github.com", 443), Decision::Block);
    }

    // ─── v0.5: Write taint propagation tests ───

    #[test]
    fn derived_secret_taints_reader() {
        let mut e = engine();
        // PID 100 reads .env (tainted)
        e.on_file_open(100, Path::new("/Users/test/.env"));
        // PID 100 writes to /tmp/exfil.txt (derived secret)
        assert!(e.on_file_write(100, Path::new("/tmp/exfil.txt")));
        // PID 100 exits
        e.on_exit(100);

        // PID 200 (clean) reads the derived secret
        let decision = e.on_file_open(200, Path::new("/tmp/exfil.txt"));
        assert_eq!(decision, Decision::Taint);
        assert!(e.is_tainted(200));
        // And now PID 200 is blocked
        assert_eq!(e.on_connect(200, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn write_from_untainted_not_tracked() {
        let mut e = engine();
        // PID 100 is NOT tainted, writes to /tmp/normal.txt
        assert!(!e.on_file_write(100, Path::new("/tmp/normal.txt")));
        // PID 200 reads it — no taint
        assert_eq!(
            e.on_file_open(200, Path::new("/tmp/normal.txt")),
            Decision::Allow
        );
    }

    #[test]
    fn derived_secret_dev_null_excluded() {
        let mut e = engine();
        e.on_file_open(100, Path::new("/Users/test/.env"));
        // Writing to /dev/null should NOT create a derived secret
        assert!(!e.on_file_write(100, Path::new("/dev/null")));
    }

    #[test]
    fn full_relay_attack_blocked() {
        // The complete /tmp laundering attack from the evasion analysis
        let mut e = engine();
        e.secrets_mut().add_path("/Users/test/.ssh/id_rsa");

        // Attacker process reads SSH key
        e.on_file_open(300, Path::new("/Users/test/.ssh/id_rsa"));
        assert!(e.is_tainted(300));

        // Attacker writes to temp file
        e.on_file_write(300, Path::new("/tmp/.cache_x8k2j"));
        // Attacker exits
        e.on_exit(300);

        // "Clean" process reads the temp file
        let decision = e.on_file_open(400, Path::new("/tmp/.cache_x8k2j"));
        assert_eq!(decision, Decision::Taint);
        // Now blocked from exfiltrating
        assert_eq!(e.on_connect(400, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn localhost_plus_derived_combo() {
        // Combined attack: read secret → write to file → relay via localhost
        let mut e = engine();

        // Setup: proxy on port 9999
        e.on_listen(500, 9999);

        // PID 100 reads secret, writes derived, connects to localhost relay
        e.on_file_open(100, Path::new("/Users/test/.env"));
        e.on_file_write(100, Path::new("/tmp/relay.dat"));
        e.on_connect(100, "127.0.0.1", 9999);

        // Proxy got tainted via localhost relay
        assert!(e.is_tainted(500));
        assert_eq!(e.on_connect(500, "evil.com", 443), Decision::Block);
    }

    // ─── v0.6: Secret provider endpoint taint tests ───

    #[test]
    fn vault_connection_taints_process() {
        let mut e = engine();
        // Process connects to AWS Secrets Manager — should get tainted
        let decision = e.on_connect(500, "secretsmanager.us-east-1.amazonaws.com", 443);
        assert_eq!(decision, Decision::Allow); // connection allowed
        assert!(e.is_tainted(500)); // but process is now tainted
                                    // Future connection to evil.com is blocked
        assert_eq!(e.on_connect(500, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn vault_tainted_can_still_use_allowlist() {
        let mut e = engine();
        e.on_connect(500, "secretsmanager.us-east-1.amazonaws.com", 443);
        assert!(e.is_tainted(500));
        // Allowlisted destinations still work
        assert_eq!(e.on_connect(500, "github.com", 443), Decision::Allow);
    }

    #[test]
    fn one_password_connection_taints() {
        let mut e = engine();
        let decision = e.on_connect(600, "my.1password.com", 443);
        assert_eq!(decision, Decision::Allow);
        assert!(e.is_tainted(600));
        assert_eq!(e.on_connect(600, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn azure_keyvault_connection_taints() {
        let mut e = engine();
        let decision = e.on_connect(700, "mycompany.vault.azure.net", 443);
        assert_eq!(decision, Decision::Allow);
        assert!(e.is_tainted(700));
    }

    #[test]
    fn normal_connection_no_taint() {
        let mut e = engine();
        // Connecting to a normal host should NOT taint
        e.on_connect(500, "api.stripe.com", 443);
        assert!(!e.is_tainted(500));
    }

    #[test]
    fn already_tainted_skips_provider_but_checks_allowlist() {
        let mut e = engine();
        // Taint via file first
        e.on_file_open(500, Path::new("/Users/test/.env"));
        assert!(e.is_tainted(500));
        // Connect to AWS — already tainted, provider check skipped.
        // AWS is in the default allowlist (.amazonaws.com suffix), so it's allowed.
        let decision = e.on_connect(500, "secretsmanager.us-east-1.amazonaws.com", 443);
        assert_eq!(decision, Decision::Allow);
        // But a non-allowlisted secret provider would be blocked:
        let decision = e.on_connect(500, "vault.internal.company.com", 8200);
        assert_eq!(decision, Decision::Block);
    }

    #[test]
    fn vault_taint_propagates_on_fork() {
        let mut e = engine();
        e.on_connect(500, "secretsmanager.us-east-1.amazonaws.com", 443);
        assert!(e.is_tainted(500));
        e.on_fork(500, 501);
        assert!(e.is_tainted(501));
        assert_eq!(e.on_connect(501, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn vault_taint_triggers_write_propagation() {
        let mut e = engine();
        // Process fetches from vault
        e.on_connect(500, "secretsmanager.us-east-1.amazonaws.com", 443);
        assert!(e.is_tainted(500));
        // Writes secret to a file (dead man drop)
        assert!(e.on_file_write(500, Path::new("/tmp/vault_secret.txt")));
        e.on_exit(500);
        // Another process reads the file — gets tainted
        assert_eq!(
            e.on_file_open(600, Path::new("/tmp/vault_secret.txt")),
            Decision::Taint
        );
        assert_eq!(e.on_connect(600, "evil.com", 443), Decision::Block);
    }

    #[test]
    fn custom_vault_endpoint_works() {
        let mut e = engine();
        e.secret_providers_mut()
            .add_endpoint("vault.internal.mycompany.com");
        let decision = e.on_connect(500, "vault.internal.mycompany.com", 8200);
        assert_eq!(decision, Decision::Allow);
        assert!(e.is_tainted(500));
    }

    // ─── Tier/License tests ───

    #[test]
    fn free_tier_is_default() {
        let e = TaintEngine::new();
        assert_eq!(e.license().effective_tier(), Tier::Free);
    }

    #[test]
    fn free_tier_limits_secrets() {
        let mut e = TaintEngine::new();
        // Free tier: only 15 secrets protected
        // Add 20 custom secrets
        for i in 0..20 {
            e.secrets_mut().add_path(&format!("/test/secret_{}", i));
        }
        let (protected, _unprotected) = e.protection_summary();
        // Exact numbers depend on defaults + custom, but limit should apply
        assert!(protected <= 15 || e.license().effective_tier() != Tier::Free);
    }

    #[test]
    fn license_upgrade_unlocks_all() {
        let mut e = TaintEngine::new();
        assert_eq!(e.license().effective_tier(), Tier::Free);

        e.activate_license(Tier::Pro, "TEST-123".to_string(), 365);
        assert_eq!(e.license().effective_tier(), Tier::Pro);
        assert!(e.license().is_valid());
    }

    #[test]
    fn free_tier_no_derived_tracking() {
        let mut e = TaintEngine::new();
        // Keep as free tier
        e.secrets_mut().add_path("/Users/test/.env");

        e.on_file_open(100, Path::new("/Users/test/.env"));
        // Write tracking should be disabled on free tier
        assert!(!e.on_file_write(100, Path::new("/tmp/exfil.txt")));
    }

    #[test]
    fn paid_tier_enables_derived_tracking() {
        let mut e = TaintEngine::new();
        e.activate_license(Tier::Pro, "KEY".to_string(), 365);
        e.secrets_mut().add_path("/Users/test/.env");

        e.on_file_open(100, Path::new("/Users/test/.env"));
        assert!(e.on_file_write(100, Path::new("/tmp/exfil.txt")));
    }

    #[test]
    fn free_tier_no_localhost_relay() {
        let mut e = TaintEngine::new();
        // Keep as free tier
        e.secrets_mut().add_path("/Users/test/.env");
        e.on_listen(200, 9999);
        e.on_file_open(100, Path::new("/Users/test/.env"));

        // Localhost connect should NOT propagate taint on free tier
        e.on_connect(100, "127.0.0.1", 9999);
        assert!(!e.is_tainted(200));
    }

    #[test]
    fn free_tier_still_blocks_basic() {
        let mut e = TaintEngine::new();
        e.allowlist_mut().add_domain("github.com");

        // .env files are caught by filename pattern (always active, no tier limit)
        // Use a .env file which is matched by name, not by priority list
        e.on_file_open(100, Path::new("/some/project/.env"));
        assert!(e.is_tainted(100));
        assert_eq!(e.on_connect(100, "evil.com", 443), Decision::Block);
        assert_eq!(e.on_connect(100, "github.com", 443), Decision::Allow);
    }

    #[test]
    fn protection_summary_reflects_tier() {
        let e = TaintEngine::new();
        let (protected, _unprotected) = e.protection_summary();
        // Free tier limits to 15
        assert!(protected <= 15);
    }
}
