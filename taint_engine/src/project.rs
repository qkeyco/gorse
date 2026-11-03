// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Per-project allowlist scoping (v0.4).
//!
//! Instead of a single global allowlist, projects declare which services
//! they use. A Node.js web app might need npm + GitHub + Stripe. A Rust
//! CLI tool might only need crates.io. When a tainted process is scoped
//! to a project, only that project's allowlist applies — preventing
//! exfiltration through unrelated allowlisted services.
//!
//! Projects are identified by working directory. The Swift host reads
//! hedgehog.toml from project roots and registers them at startup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::allowlist::Allowlist;

/// Configuration for a single project's allowed services.
#[derive(Debug, Clone)]
pub struct ProjectConfig {
    /// Human-readable project name.
    pub name: String,
    /// Root directory of the project.
    pub root: PathBuf,
    /// Project-specific allowlist (overrides global when set).
    pub allowlist: Allowlist,
}

/// Registry of projects, mapping directories and PIDs to project configs.
pub struct ProjectRegistry {
    /// Project root → project index
    projects: Vec<ProjectConfig>,
    /// Directory path → project index (for fast lookup)
    dir_to_project: HashMap<PathBuf, usize>,
    /// PID → project index (cached mapping)
    pid_to_project: HashMap<i32, usize>,
    /// PID → working directory (reported by Swift host)
    pid_cwd: HashMap<i32, PathBuf>,
}

impl ProjectRegistry {
    pub fn new() -> Self {
        Self {
            projects: Vec::new(),
            dir_to_project: HashMap::new(),
            pid_to_project: HashMap::new(),
            pid_cwd: HashMap::new(),
        }
    }

    /// Register a project with its allowed services.
    pub fn add_project(&mut self, config: ProjectConfig) -> usize {
        let idx = self.projects.len();
        self.dir_to_project.insert(config.root.clone(), idx);
        self.projects.push(config);
        idx
    }

    /// Set the working directory for a process (called by Swift host).
    /// This determines which project's allowlist applies.
    pub fn set_pid_cwd(&mut self, pid: i32, cwd: &Path) {
        self.pid_cwd.insert(pid, cwd.to_path_buf());
        // Resolve project from cwd
        if let Some(idx) = self.find_project_for_path(cwd) {
            self.pid_to_project.insert(pid, idx);
        }
    }

    /// Find which project a path belongs to (walks up directories).
    fn find_project_for_path(&self, path: &Path) -> Option<usize> {
        let mut current = Some(path);
        // Walk up the directory tree to find a matching project root
        while let Some(dir) = current {
            if let Some(&idx) = self.dir_to_project.get(dir) {
                return Some(idx);
            }
            current = dir.parent();
        }
        None
    }

    /// Get the project-specific allowlist for a process, if any.
    pub fn get_project_allowlist(&self, pid: i32) -> Option<&Allowlist> {
        self.pid_to_project
            .get(&pid)
            .and_then(|&idx| self.projects.get(idx))
            .map(|p| &p.allowlist)
    }

    /// Get project config for a process.
    pub fn get_project(&self, pid: i32) -> Option<&ProjectConfig> {
        self.pid_to_project
            .get(&pid)
            .and_then(|&idx| self.projects.get(idx))
    }

    /// Get project config by index.
    pub fn get_project_by_index(&self, idx: usize) -> Option<&ProjectConfig> {
        self.projects.get(idx)
    }

    /// Propagate project assignment from parent to child (on fork).
    pub fn on_fork(&mut self, parent_pid: i32, child_pid: i32) {
        if let Some(&idx) = self.pid_to_project.get(&parent_pid) {
            self.pid_to_project.insert(child_pid, idx);
        }
        if let Some(cwd) = self.pid_cwd.get(&parent_pid).cloned() {
            self.pid_cwd.insert(child_pid, cwd);
        }
    }

    /// Clean up on process exit.
    pub fn on_exit(&mut self, pid: i32) {
        self.pid_to_project.remove(&pid);
        self.pid_cwd.remove(&pid);
    }

    /// Check if a destination is allowed for a specific process.
    /// Returns:
    ///   Some(true)  — project allowlist exists and allows
    ///   Some(false) — project allowlist exists and denies
    ///   None        — no project scoping, fall through to global
    pub fn is_allowed_for_pid(&self, pid: i32, addr: &str, port: u16) -> Option<bool> {
        self.get_project_allowlist(pid)
            .map(|allowlist| allowlist.is_allowed(addr, port))
    }

    /// Number of registered projects.
    pub fn project_count(&self) -> usize {
        self.projects.len()
    }

    /// List all project names and roots.
    pub fn list_projects(&self) -> Vec<(&str, &Path)> {
        self.projects
            .iter()
            .map(|p| (p.name.as_str(), p.root.as_path()))
            .collect()
    }
}

/// Parse a minimal hedgehog.toml config format.
/// Format:
/// ```toml
/// name = "my-project"
/// allow_domains = ["registry.npmjs.org", "api.stripe.com"]
/// allow_suffixes = [".amazonaws.com"]
/// ```
///
/// Returns None if parsing fails (we never crash on bad config).
pub fn parse_project_config(root: &Path, contents: &str) -> Option<ProjectConfig> {
    let mut name = String::new();
    let mut domains = Vec::new();
    let mut suffixes = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(val) = line.strip_prefix("name") {
            if let Some(val) = val.trim().strip_prefix('=') {
                name = val.trim().trim_matches('"').to_string();
            }
        } else if let Some(val) = line.strip_prefix("allow_domains") {
            if let Some(val) = val.trim().strip_prefix('=') {
                domains = parse_string_array(val.trim());
            }
        } else if let Some(val) = line.strip_prefix("allow_suffixes") {
            if let Some(val) = val.trim().strip_prefix('=') {
                suffixes = parse_string_array(val.trim());
            }
        }
    }

    if name.is_empty() {
        // Use directory name as fallback
        name = root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
    }

    let mut allowlist = Allowlist::empty();
    // Always allow localhost and DNS for all projects
    for d in &domains {
        allowlist.add_domain(d);
    }
    for s in &suffixes {
        allowlist.add_suffix(s);
    }

    Some(ProjectConfig {
        name,
        root: root.to_path_buf(),
        allowlist,
    })
}

/// Parse a TOML-style string array: ["a", "b", "c"]
fn parse_string_array(s: &str) -> Vec<String> {
    let s = s.trim();
    let s = s.strip_prefix('[').unwrap_or(s);
    let s = s.strip_suffix(']').unwrap_or(s);
    s.split(',')
        .map(|item| item.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_project(name: &str, root: &str, domains: &[&str]) -> ProjectConfig {
        let mut allowlist = Allowlist::empty();
        for d in domains {
            allowlist.add_domain(d);
        }
        ProjectConfig {
            name: name.to_string(),
            root: PathBuf::from(root),
            allowlist,
        }
    }

    #[test]
    fn register_and_lookup() {
        let mut reg = ProjectRegistry::new();
        reg.add_project(make_project(
            "webapp",
            "/Users/dev/webapp",
            &["api.stripe.com"],
        ));
        reg.add_project(make_project(
            "cli-tool",
            "/Users/dev/cli-tool",
            &["crates.io"],
        ));

        reg.set_pid_cwd(100, Path::new("/Users/dev/webapp/src"));
        reg.set_pid_cwd(200, Path::new("/Users/dev/cli-tool"));

        // webapp process can reach stripe
        assert_eq!(
            reg.is_allowed_for_pid(100, "api.stripe.com", 443),
            Some(true)
        );
        // webapp process cannot reach crates.io (not in its allowlist)
        assert_eq!(reg.is_allowed_for_pid(100, "crates.io", 443), Some(false));

        // cli-tool process can reach crates.io
        assert_eq!(reg.is_allowed_for_pid(200, "crates.io", 443), Some(true));
        // cli-tool process cannot reach stripe
        assert_eq!(
            reg.is_allowed_for_pid(200, "api.stripe.com", 443),
            Some(false)
        );
    }

    #[test]
    fn no_project_returns_none() {
        let reg = ProjectRegistry::new();
        // Unscoped process falls through to global allowlist
        assert_eq!(reg.is_allowed_for_pid(999, "anything.com", 443), None);
    }

    #[test]
    fn fork_inherits_project() {
        let mut reg = ProjectRegistry::new();
        reg.add_project(make_project(
            "webapp",
            "/Users/dev/webapp",
            &["api.stripe.com"],
        ));
        reg.set_pid_cwd(100, Path::new("/Users/dev/webapp"));

        reg.on_fork(100, 101);
        assert_eq!(
            reg.is_allowed_for_pid(101, "api.stripe.com", 443),
            Some(true)
        );
    }

    #[test]
    fn exit_cleans_up() {
        let mut reg = ProjectRegistry::new();
        reg.add_project(make_project(
            "webapp",
            "/Users/dev/webapp",
            &["api.stripe.com"],
        ));
        reg.set_pid_cwd(100, Path::new("/Users/dev/webapp"));

        reg.on_exit(100);
        assert_eq!(reg.is_allowed_for_pid(100, "api.stripe.com", 443), None);
    }

    #[test]
    fn subdirectory_matches_project() {
        let mut reg = ProjectRegistry::new();
        reg.add_project(make_project(
            "webapp",
            "/Users/dev/webapp",
            &["api.stripe.com"],
        ));

        // Process CWD is deep in the project tree
        reg.set_pid_cwd(100, Path::new("/Users/dev/webapp/src/api/handlers"));
        assert_eq!(
            reg.is_allowed_for_pid(100, "api.stripe.com", 443),
            Some(true)
        );
    }

    #[test]
    fn parse_config_basic() {
        let toml = r#"
name = "my-webapp"
allow_domains = ["api.stripe.com", "registry.npmjs.org"]
allow_suffixes = [".amazonaws.com"]
"#;
        let config = parse_project_config(Path::new("/Users/dev/webapp"), toml).unwrap();
        assert_eq!(config.name, "my-webapp");
        assert!(config.allowlist.is_allowed("api.stripe.com", 443));
        assert!(config.allowlist.is_allowed("registry.npmjs.org", 443));
        assert!(config.allowlist.is_allowed("s3.amazonaws.com", 443));
        assert!(!config.allowlist.is_allowed("evil.com", 443));
    }

    #[test]
    fn parse_config_fallback_name() {
        let toml = r#"
allow_domains = ["crates.io"]
"#;
        let config = parse_project_config(Path::new("/Users/dev/my-cli"), toml).unwrap();
        assert_eq!(config.name, "my-cli"); // falls back to dir name
    }

    #[test]
    fn parse_config_comments_and_blanks() {
        let toml = r#"
# This is a comment
name = "test"

# Another comment
allow_domains = ["a.com"]
"#;
        let config = parse_project_config(Path::new("/tmp/test"), toml).unwrap();
        assert_eq!(config.name, "test");
        assert!(config.allowlist.is_allowed("a.com", 443));
    }

    #[test]
    fn localhost_always_allowed_in_project() {
        let toml = r#"
name = "restrictive"
allow_domains = ["only-this.com"]
"#;
        let config = parse_project_config(Path::new("/tmp/test"), toml).unwrap();
        // localhost is always allowed even in restrictive projects
        assert!(config.allowlist.is_allowed("localhost", 3000));
        assert!(config.allowlist.is_allowed("127.0.0.1", 8080));
    }

    #[test]
    fn list_projects() {
        let mut reg = ProjectRegistry::new();
        reg.add_project(make_project("a", "/a", &[]));
        reg.add_project(make_project("b", "/b", &[]));
        let list = reg.list_projects();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "a");
        assert_eq!(list[1].0, "b");
    }
}
