// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Write taint propagation — derived secrets (v0.5).
//!
//! When a tainted process writes to ANY file, that file becomes a "derived secret."
//! If any other process later reads that file, it inherits taint. This closes the
//! /tmp laundering attack: tainted process writes to /tmp/x, exits, clean process
//! reads /tmp/x and exfils — with derived tracking, the second read triggers taint.
//!
//! Exclusions prevent tainting the entire filesystem: /dev, /proc, pipes, log files,
//! and other high-frequency write targets that would cause false positives.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Configuration for derived secret tracking.
pub struct DerivedConfig {
    /// How long a derived secret persists after the writing process exits.
    /// None = persist until explicit cleanup.
    pub ttl: Option<Duration>,
    /// Maximum number of derived secrets to track (memory bound).
    pub max_entries: usize,
}

impl Default for DerivedConfig {
    fn default() -> Self {
        Self {
            ttl: Some(Duration::from_secs(3600)), // 1 hour
            max_entries: 10_000,
        }
    }
}

/// Information about a derived secret file.
#[derive(Debug, Clone)]
pub struct DerivedSecretInfo {
    /// The path of the derived secret.
    pub path: PathBuf,
    /// PID that wrote to this file while tainted.
    pub writer_pid: i32,
    /// The original secret file that caused the writer's taint.
    pub original_secret: PathBuf,
    /// When the derived secret was created.
    pub created_at: Instant,
    /// Last time this derived secret was written to by a tainted process.
    pub last_write: Instant,
}

/// Tracks files written by tainted processes (derived secrets).
pub struct DerivedSecretTracker {
    /// Path → derived secret info
    secrets: HashMap<PathBuf, DerivedSecretInfo>,
    /// Paths excluded from derived tracking (high-frequency write targets).
    excluded_prefixes: Vec<PathBuf>,
    /// Excluded filenames (exact match on filename component).
    excluded_names: HashSet<String>,
    /// Config
    config: DerivedConfig,
}

impl DerivedSecretTracker {
    pub fn new() -> Self {
        let mut tracker = Self {
            secrets: HashMap::with_capacity(256),
            excluded_prefixes: Vec::new(),
            excluded_names: HashSet::new(),
            config: DerivedConfig::default(),
        };
        tracker.load_exclusions();
        tracker
    }

    pub fn with_config(config: DerivedConfig) -> Self {
        let mut tracker = Self {
            secrets: HashMap::with_capacity(256),
            excluded_prefixes: Vec::new(),
            excluded_names: HashSet::new(),
            config,
        };
        tracker.load_exclusions();
        tracker
    }

    /// A tainted process wrote to a file. Mark it as a derived secret.
    /// Returns true if the file was newly marked (not already tracked or excluded).
    pub fn on_tainted_write(
        &mut self,
        writer_pid: i32,
        path: &Path,
        original_secret: &Path,
    ) -> bool {
        // Check exclusions first
        if self.is_excluded(path) {
            return false;
        }

        // Enforce memory limit
        if self.secrets.len() >= self.config.max_entries {
            self.cleanup_expired();
            if self.secrets.len() >= self.config.max_entries {
                self.evict_oldest();
            }
        }

        let now = Instant::now();
        let canonical = path.to_path_buf();

        if let Some(existing) = self.secrets.get_mut(&canonical) {
            existing.last_write = now;
            false // already tracked
        } else {
            self.secrets.insert(
                canonical.clone(),
                DerivedSecretInfo {
                    path: canonical,
                    writer_pid,
                    original_secret: original_secret.to_path_buf(),
                    created_at: now,
                    last_write: now,
                },
            );
            true
        }
    }

    /// Check if a file is a derived secret. Called during file open events.
    pub fn is_derived_secret(&self, path: &Path) -> bool {
        self.secrets.contains_key(path)
    }

    /// Get info about a derived secret.
    pub fn get_info(&self, path: &Path) -> Option<&DerivedSecretInfo> {
        self.secrets.get(path)
    }

    /// Remove a derived secret (e.g., when the file is deleted).
    pub fn remove(&mut self, path: &Path) {
        self.secrets.remove(path);
    }

    /// Number of tracked derived secrets.
    pub fn count(&self) -> usize {
        self.secrets.len()
    }

    /// Add an exclusion prefix (paths starting with this are never tracked).
    pub fn add_exclusion_prefix(&mut self, prefix: &Path) {
        self.excluded_prefixes.push(prefix.to_path_buf());
    }

    /// Add an excluded filename (files with this exact name are never tracked).
    pub fn add_exclusion_name(&mut self, name: &str) {
        self.excluded_names.insert(name.to_string());
    }

    /// Check if a path is excluded from derived tracking.
    fn is_excluded(&self, path: &Path) -> bool {
        // Check prefix exclusions
        for prefix in &self.excluded_prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }

        // Check filename exclusions
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if self.excluded_names.contains(name) {
                return true;
            }
        }

        // Exclude pipes, sockets, and special files
        let path_str = path.to_str().unwrap_or("");
        if path_str.starts_with("/dev/")
            || path_str.starts_with("/proc/")
            || path_str.starts_with("/sys/")
            || path_str == "/dev/null"
            || path_str == "/dev/stdout"
            || path_str == "/dev/stderr"
        {
            return true;
        }

        false
    }

    /// Remove expired derived secrets (based on TTL).
    pub fn cleanup_expired(&mut self) {
        if let Some(ttl) = self.config.ttl {
            let now = Instant::now();
            self.secrets
                .retain(|_, info| now.duration_since(info.last_write) < ttl);
        }
    }

    /// Evict the oldest entry to make room.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .secrets
            .iter()
            .min_by_key(|(_, info)| info.last_write)
            .map(|(k, _)| k.clone())
        {
            self.secrets.remove(&oldest_key);
        }
    }

    /// Load default exclusions to prevent tainting the entire filesystem.
    fn load_exclusions(&mut self) {
        // System directories (high-frequency, not data exfil targets)
        let prefix_exclusions = [
            "/dev",
            "/proc",
            "/sys",
            "/var/log",
            "/var/run",
            "/private/var/log",     // macOS
            "/private/var/folders", // macOS temp
            "/Library/Caches",
            "/System",
        ];
        for p in &prefix_exclusions {
            self.excluded_prefixes.push(PathBuf::from(p));
        }

        // Common non-secret filenames
        let name_exclusions = [
            ".DS_Store",
            "Thumbs.db",
            ".gitkeep",
            ".keep",
            "debug.log",
            "npm-debug.log",
            "yarn-debug.log",
            "yarn-error.log",
        ];
        for n in &name_exclusions {
            self.excluded_names.insert(n.to_string());
        }
    }

    /// Get all derived secrets (for debugging/audit).
    pub fn all_secrets(&self) -> Vec<&DerivedSecretInfo> {
        self.secrets.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_write_and_read() {
        let mut t = DerivedSecretTracker::new();
        let wrote = t.on_tainted_write(
            100,
            Path::new("/tmp/exfil.txt"),
            Path::new("/Users/dev/.env"),
        );
        assert!(wrote);
        assert!(t.is_derived_secret(Path::new("/tmp/exfil.txt")));
        assert!(!t.is_derived_secret(Path::new("/tmp/other.txt")));
    }

    #[test]
    fn duplicate_write_returns_false() {
        let mut t = DerivedSecretTracker::new();
        assert!(t.on_tainted_write(100, Path::new("/tmp/x"), Path::new("/.env")));
        assert!(!t.on_tainted_write(100, Path::new("/tmp/x"), Path::new("/.env")));
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn dev_excluded() {
        let mut t = DerivedSecretTracker::new();
        let wrote = t.on_tainted_write(100, Path::new("/dev/null"), Path::new("/.env"));
        assert!(!wrote);
        assert!(!t.is_derived_secret(Path::new("/dev/null")));
    }

    #[test]
    fn proc_excluded() {
        let mut t = DerivedSecretTracker::new();
        assert!(!t.on_tainted_write(100, Path::new("/proc/self/fd/1"), Path::new("/.env")));
    }

    #[test]
    fn var_log_excluded() {
        let mut t = DerivedSecretTracker::new();
        assert!(!t.on_tainted_write(100, Path::new("/var/log/syslog"), Path::new("/.env")));
    }

    #[test]
    fn macos_caches_excluded() {
        let mut t = DerivedSecretTracker::new();
        assert!(!t.on_tainted_write(
            100,
            Path::new("/Library/Caches/com.apple.something"),
            Path::new("/.env"),
        ));
    }

    #[test]
    fn ds_store_excluded() {
        let mut t = DerivedSecretTracker::new();
        assert!(!t.on_tainted_write(
            100,
            Path::new("/Users/dev/project/.DS_Store"),
            Path::new("/.env"),
        ));
    }

    #[test]
    fn tmp_file_not_excluded() {
        let mut t = DerivedSecretTracker::new();
        // /tmp itself is NOT excluded — that's the primary exfil vector
        assert!(t.on_tainted_write(100, Path::new("/tmp/sneaky.dat"), Path::new("/.env")));
    }

    #[test]
    fn remove_derived() {
        let mut t = DerivedSecretTracker::new();
        t.on_tainted_write(100, Path::new("/tmp/x"), Path::new("/.env"));
        assert!(t.is_derived_secret(Path::new("/tmp/x")));
        t.remove(Path::new("/tmp/x"));
        assert!(!t.is_derived_secret(Path::new("/tmp/x")));
    }

    #[test]
    fn info_tracks_origin() {
        let mut t = DerivedSecretTracker::new();
        t.on_tainted_write(
            100,
            Path::new("/tmp/x"),
            Path::new("/Users/dev/.ssh/id_rsa"),
        );
        let info = t.get_info(Path::new("/tmp/x")).unwrap();
        assert_eq!(info.writer_pid, 100);
        assert_eq!(
            info.original_secret,
            PathBuf::from("/Users/dev/.ssh/id_rsa")
        );
    }

    #[test]
    fn custom_exclusion_prefix() {
        let mut t = DerivedSecretTracker::new();
        t.add_exclusion_prefix(Path::new("/Users/dev/project/node_modules"));
        assert!(!t.on_tainted_write(
            100,
            Path::new("/Users/dev/project/node_modules/.cache/something"),
            Path::new("/.env"),
        ));
    }

    #[test]
    fn custom_exclusion_name() {
        let mut t = DerivedSecretTracker::new();
        t.add_exclusion_name("package-lock.json");
        assert!(!t.on_tainted_write(
            100,
            Path::new("/Users/dev/project/package-lock.json"),
            Path::new("/.env"),
        ));
    }

    #[test]
    fn max_entries_enforced() {
        let config = DerivedConfig {
            ttl: None,
            max_entries: 3,
        };
        let mut t = DerivedSecretTracker::with_config(config);
        t.on_tainted_write(100, Path::new("/tmp/a"), Path::new("/.env"));
        t.on_tainted_write(100, Path::new("/tmp/b"), Path::new("/.env"));
        t.on_tainted_write(100, Path::new("/tmp/c"), Path::new("/.env"));
        // 4th should evict the oldest
        t.on_tainted_write(100, Path::new("/tmp/d"), Path::new("/.env"));
        assert_eq!(t.count(), 3);
        // d should be there, a should be evicted (oldest)
        assert!(t.is_derived_secret(Path::new("/tmp/d")));
    }

    #[test]
    fn all_secrets_returns_all() {
        let mut t = DerivedSecretTracker::new();
        t.on_tainted_write(100, Path::new("/tmp/a"), Path::new("/.env"));
        t.on_tainted_write(200, Path::new("/tmp/b"), Path::new("/.ssh/id_rsa"));
        let all = t.all_secrets();
        assert_eq!(all.len(), 2);
    }
}
