// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Container mount path resolution (v0.7).
//!
//! When secrets are bind-mounted into Docker/Podman containers
//! (e.g., -v /host/.ssh:/root/.ssh), the taint engine needs to resolve
//! the container-internal path back to the host path for accurate
//! secret detection.
//!
//! Also detects common container secret mount patterns:
//! - Kubernetes secrets: /var/run/secrets/kubernetes.io/
//! - Docker secrets: /run/secrets/
//! - Vault Agent: /vault/secrets/

use std::path::{Path, PathBuf};

/// Maps container paths to host paths for taint tracking.
pub struct ContainerPathResolver {
    /// Container path prefix → host path prefix.
    mounts: Vec<MountMapping>,
    /// Whether we're running inside a container.
    in_container: bool,
}

/// A bind-mount mapping from host to container.
#[derive(Debug, Clone)]
pub struct MountMapping {
    /// Path inside the container.
    pub container_path: PathBuf,
    /// Corresponding path on the host.
    pub host_path: PathBuf,
    /// Whether the mount is read-only.
    pub read_only: bool,
}

/// Well-known container secret paths that should always be treated as secrets.
const CONTAINER_SECRET_PATHS: &[&str] = &[
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/run/secrets/",
    "/vault/secrets/",
    "/mnt/secrets/",
];

impl ContainerPathResolver {
    pub fn new() -> Self {
        let in_container = detect_container();
        Self {
            mounts: Vec::new(),
            in_container,
        }
    }

    /// Add a mount mapping (parsed from Docker inspect or /proc/mounts).
    pub fn add_mount(&mut self, container_path: &Path, host_path: &Path, read_only: bool) {
        self.mounts.push(MountMapping {
            container_path: container_path.to_path_buf(),
            host_path: host_path.to_path_buf(),
            read_only,
        });
    }

    /// Resolve a path that may be inside a container to its host equivalent.
    /// Returns None if no mount mapping applies (path is container-local).
    pub fn resolve_to_host(&self, container_path: &Path) -> Option<PathBuf> {
        let path_str = container_path.to_string_lossy();
        for mount in &self.mounts {
            let prefix = mount.container_path.to_string_lossy();
            if path_str.starts_with(prefix.as_ref()) {
                let relative = &path_str[prefix.len()..];
                let host = mount.host_path.join(relative.trim_start_matches('/'));
                return Some(host);
            }
        }
        None
    }

    /// Check if a path is a known container secret path.
    pub fn is_container_secret(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in CONTAINER_SECRET_PATHS {
            if path_str.starts_with(pattern) {
                return true;
            }
        }
        false
    }

    /// Whether we're running inside a container.
    pub fn in_container(&self) -> bool {
        self.in_container
    }

    /// Load mount mappings from /proc/self/mountinfo (Linux).
    pub fn load_proc_mounts(&mut self) {
        if let Ok(contents) = std::fs::read_to_string("/proc/self/mountinfo") {
            for line in contents.lines() {
                // mountinfo format: ID parent major:minor root mount-point options ... - fs source options
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    // Find the separator "-"
                    if let Some(sep_idx) = parts.iter().position(|&p| p == "-") {
                        if sep_idx + 2 < parts.len() {
                            let mount_point = parts[4];
                            let source = parts[sep_idx + 2];
                            // Only track bind mounts that look like secret paths
                            if source.starts_with('/') && mount_point.starts_with('/') {
                                let is_secret_mount = CONTAINER_SECRET_PATHS
                                    .iter()
                                    .any(|p| mount_point.starts_with(p));
                                if is_secret_mount {
                                    self.add_mount(
                                        Path::new(mount_point),
                                        Path::new(source),
                                        line.contains("ro,") || line.contains("ro "),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Parse Docker inspect JSON to extract mount mappings.
    /// Input: the "Mounts" array from `docker inspect <container>`.
    pub fn parse_docker_mounts(&mut self, mounts_json: &str) {
        // Simple JSON parsing without serde (zero-dependency requirement)
        // Format: [{"Source":"/host/path","Destination":"/container/path","RW":true}, ...]
        for mount_str in mounts_json.split('{').skip(1) {
            let mut source = String::new();
            let mut destination = String::new();
            let mut rw = true;

            for field in mount_str.split(',') {
                let field = field.trim();
                if field.contains("\"Source\"") {
                    if let Some(val) = extract_json_string(field) {
                        source = val;
                    }
                } else if field.contains("\"Destination\"") {
                    if let Some(val) = extract_json_string(field) {
                        destination = val;
                    }
                } else if field.contains("\"RW\"") {
                    rw = field.contains("true");
                }
            }

            if !source.is_empty() && !destination.is_empty() {
                self.add_mount(Path::new(&destination), Path::new(&source), !rw);
            }
        }
    }

    /// List all mount mappings.
    pub fn mounts(&self) -> &[MountMapping] {
        &self.mounts
    }
}

/// Detect if we're running inside a container.
fn detect_container() -> bool {
    // Check /.dockerenv
    if Path::new("/.dockerenv").exists() {
        return true;
    }
    // Check /run/.containerenv (Podman)
    if Path::new("/run/.containerenv").exists() {
        return true;
    }
    // Check cgroup for container indicators
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("containerd")
        {
            return true;
        }
    }
    // Check for Kubernetes service account
    if Path::new("/var/run/secrets/kubernetes.io").exists() {
        return true;
    }
    false
}

/// Extract a string value from a JSON field like `"Key": "value"`.
fn extract_json_string(field: &str) -> Option<String> {
    let mut in_value = false;
    let mut start = 0;
    let bytes = field.as_bytes();
    let mut colon_seen = false;

    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' && !colon_seen {
            colon_seen = true;
            continue;
        }
        if colon_seen && b == b'"' {
            if !in_value {
                in_value = true;
                start = i + 1;
            } else {
                return Some(field[start..i].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_mount_path() {
        let mut r = ContainerPathResolver::new();
        r.add_mount(Path::new("/root/.ssh"), Path::new("/home/user/.ssh"), true);

        let resolved = r.resolve_to_host(Path::new("/root/.ssh/id_rsa"));
        assert_eq!(resolved, Some(PathBuf::from("/home/user/.ssh/id_rsa")));
    }

    #[test]
    fn no_mount_returns_none() {
        let r = ContainerPathResolver::new();
        assert_eq!(r.resolve_to_host(Path::new("/tmp/foo")), None);
    }

    #[test]
    fn container_secret_paths_detected() {
        assert!(ContainerPathResolver::is_container_secret(Path::new(
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        )));
        assert!(ContainerPathResolver::is_container_secret(Path::new(
            "/run/secrets/db_password"
        )));
        assert!(ContainerPathResolver::is_container_secret(Path::new(
            "/vault/secrets/config"
        )));
        assert!(!ContainerPathResolver::is_container_secret(Path::new(
            "/tmp/foo"
        )));
    }

    #[test]
    fn parse_docker_mounts_json() {
        let mut r = ContainerPathResolver::new();
        let json = r#"[{"Source":"/home/user/.ssh","Destination":"/root/.ssh","RW":false},{"Source":"/home/user/.aws","Destination":"/root/.aws","RW":true}]"#;
        r.parse_docker_mounts(json);
        assert_eq!(r.mounts().len(), 2);
        assert_eq!(r.mounts()[0].host_path, PathBuf::from("/home/user/.ssh"));
        assert!(r.mounts()[0].read_only);
    }

    #[test]
    fn extract_json_string_works() {
        assert_eq!(
            extract_json_string(r#""Source": "/home/user""#),
            Some("/home/user".to_string())
        );
        assert_eq!(extract_json_string("no json here"), None);
    }
}
