// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Network destination allowlist.
//!
//! Tainted processes can still connect to known-good destinations.
//! This is the permit/deny boundary.

use std::collections::HashSet;

/// Manages allowed network destinations for tainted processes.
#[derive(Debug, Clone)]
pub struct Allowlist {
    /// Allowed domain names (exact match and suffix match).
    domains: HashSet<String>,
    /// Allowed domain suffixes (e.g., ".amazonaws.com").
    suffixes: Vec<String>,
    /// Allowed IP addresses.
    ips: HashSet<String>,
    /// Always-allowed ports (e.g., DNS on 53).
    allowed_ports: HashSet<u16>,
    /// System DNS resolvers (only these IPs are allowed on port 53).
    /// If empty, port 53 is allowed to any destination (legacy behavior).
    dns_resolvers: HashSet<String>,
}

impl Allowlist {
    /// Create with default developer infrastructure allowlist.
    pub fn new() -> Self {
        let mut a = Self {
            domains: HashSet::with_capacity(64),
            suffixes: Vec::with_capacity(16),
            ips: HashSet::with_capacity(8),
            allowed_ports: HashSet::new(),
            dns_resolvers: HashSet::new(),
        };
        a.load_defaults();
        a.load_system_dns();
        a
    }

    /// Create empty (for testing).
    pub fn empty() -> Self {
        Self {
            domains: HashSet::new(),
            suffixes: Vec::new(),
            ips: HashSet::new(),
            allowed_ports: HashSet::new(),
            dns_resolvers: HashSet::new(),
        }
    }

    /// Check if a destination is allowed.
    pub fn is_allowed(&self, addr: &str, port: u16) -> bool {
        // Always allow localhost
        if is_localhost(addr) {
            return true;
        }

        // DNS: only allow to known system resolvers (prevents DNS exfiltration)
        if port == 53 {
            if self.dns_resolvers.is_empty() {
                // No resolvers configured — allow all (legacy / fallback)
                return true;
            }
            return self.dns_resolvers.contains(addr);
        }

        // Always-allowed ports
        if self.allowed_ports.contains(&port) {
            return true;
        }

        // Exact domain match
        let addr_lower = addr.to_lowercase();
        if self.domains.contains(&addr_lower) {
            return true;
        }

        // Suffix match (e.g., "s3.amazonaws.com" matches ".amazonaws.com")
        for suffix in &self.suffixes {
            if addr_lower.ends_with(suffix) {
                return true;
            }
        }

        // IP match
        if self.ips.contains(&addr_lower) {
            return true;
        }

        false
    }

    /// Add an exact domain to the allowlist.
    pub fn add_domain(&mut self, domain: &str) {
        self.domains.insert(domain.to_lowercase());
    }

    /// Add a domain suffix (matches all subdomains).
    pub fn add_suffix(&mut self, suffix: &str) {
        let s = if suffix.starts_with('.') {
            suffix.to_lowercase()
        } else {
            format!(".{}", suffix.to_lowercase())
        };
        self.suffixes.push(s);
    }

    /// Add an IP address.
    pub fn add_ip(&mut self, ip: &str) {
        self.ips.insert(ip.to_string());
    }

    /// Add a known DNS resolver IP. When resolvers are configured,
    /// only these IPs are allowed on port 53 (prevents DNS exfiltration).
    pub fn add_dns_resolver(&mut self, ip: &str) {
        self.dns_resolvers.insert(ip.to_string());
    }

    /// T-11: Load a community-maintained allowlist from a file.
    /// Format: one entry per line, # comments, optional type prefix:
    ///   domain:registry.npmjs.org
    ///   suffix:.amazonaws.com
    ///   ip:1.2.3.4
    ///   registry.npmjs.org   (bare = domain)
    pub fn load_community_allowlist(&mut self, path: &std::path::Path) -> Result<usize, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let mut count = 0;
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(domain) = trimmed.strip_prefix("domain:") {
                self.add_domain(domain.trim());
            } else if let Some(suffix) = trimmed.strip_prefix("suffix:") {
                self.add_suffix(suffix.trim());
            } else if let Some(ip) = trimmed.strip_prefix("ip:") {
                self.add_ip(ip.trim());
            } else if trimmed.starts_with('.') {
                self.add_suffix(trimmed);
            } else {
                self.add_domain(trimmed);
            }
            count += 1;
        }
        Ok(count)
    }

    /// Load all .allowlist files from a directory (community allowlists).
    pub fn load_community_dir(&mut self, dir: &std::path::Path) -> usize {
        let mut total = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("allowlist") {
                    if let Ok(n) = self.load_community_allowlist(&path) {
                        total += n;
                    }
                }
            }
        }
        total
    }

    /// Get domain count (for status display).
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Get suffix count.
    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    /// Load system DNS resolvers from /etc/resolv.conf.
    /// When populated, only these IPs are allowed on port 53.
    fn load_system_dns(&mut self) {
        // Parse /etc/resolv.conf for nameserver entries
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    if let Some(ip) = trimmed.split_whitespace().nth(1) {
                        self.dns_resolvers.insert(ip.to_string());
                    }
                }
            }
        }

        // Always include well-known public resolvers as fallback
        // (macOS often uses scutil --dns instead of resolv.conf)
        if self.dns_resolvers.is_empty() {
            // Common ISP/system resolvers will be added at runtime
            // by the Swift host via hedgehog_add_dns_resolver().
            // For now, add the most common public ones.
            for ip in &["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"] {
                self.dns_resolvers.insert(ip.to_string());
            }
        }
    }

    /// Load default developer infrastructure allowlist.
    fn load_defaults(&mut self) {
        // Package registries
        let registries = [
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "pypi.org",
            "files.pythonhosted.org",
            "rubygems.org",
            "crates.io",
            "static.crates.io",
            "pkg.go.dev",
            "proxy.golang.org",
            "sum.golang.org",
            "repo1.maven.org",
            "plugins.gradle.org",
            "cocoapods.org",
            "cdn.cocoapods.org",
            "pub.dev",
        ];

        // Code hosting
        let code_hosts = [
            "github.com",
            "api.github.com",
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "gitlab.com",
            "bitbucket.org",
        ];

        // Common dev services (API endpoints)
        let services = [
            "api.stripe.com",
            "api.twilio.com",
            "sentry.io",
            "api.segment.io",
            "api.datadog.com",
            "api.anthropic.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
        ];

        for d in registries
            .iter()
            .chain(code_hosts.iter())
            .chain(services.iter())
        {
            self.domains.insert(d.to_string());
        }

        // Cloud provider suffixes (all subdomains allowed)
        let cloud_suffixes = [
            ".amazonaws.com",
            ".googleapis.com",
            ".azure.com",
            ".azurewebsites.net",
            ".cloudfront.net",
            ".digitaloceanspaces.com",
        ];
        for s in &cloud_suffixes {
            self.suffixes.push(s.to_string());
        }
    }
}

fn is_localhost(addr: &str) -> bool {
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
    fn localhost_always_allowed() {
        let a = Allowlist::empty();
        assert!(a.is_allowed("localhost", 3000));
        assert!(a.is_allowed("127.0.0.1", 8080));
        assert!(a.is_allowed("::1", 443));
    }

    #[test]
    fn dns_allowed_when_no_resolvers_configured() {
        let a = Allowlist::empty();
        // Empty resolver list = allow all DNS (legacy/fallback)
        assert!(a.is_allowed("8.8.8.8", 53));
        assert!(a.is_allowed("evil-dns.com", 53));
    }

    #[test]
    fn dns_restricted_to_configured_resolvers() {
        let mut a = Allowlist::empty();
        a.add_dns_resolver("8.8.8.8");
        a.add_dns_resolver("1.1.1.1");
        // Known resolvers: allowed
        assert!(a.is_allowed("8.8.8.8", 53));
        assert!(a.is_allowed("1.1.1.1", 53));
        // Attacker DNS server: blocked
        assert!(!a.is_allowed("evil-dns.com", 53));
        assert!(!a.is_allowed("45.33.12.8", 53));
    }

    #[test]
    fn exact_domain_match() {
        let mut a = Allowlist::empty();
        a.add_domain("github.com");
        assert!(a.is_allowed("github.com", 443));
        assert!(!a.is_allowed("evil.com", 443));
    }

    #[test]
    fn case_insensitive() {
        let mut a = Allowlist::empty();
        a.add_domain("GitHub.com");
        assert!(a.is_allowed("github.com", 443));
        assert!(a.is_allowed("GITHUB.COM", 443));
    }

    #[test]
    fn suffix_match() {
        let mut a = Allowlist::empty();
        a.add_suffix(".amazonaws.com");
        assert!(a.is_allowed("s3.amazonaws.com", 443));
        assert!(a.is_allowed("ec2.us-east-1.amazonaws.com", 443));
        assert!(!a.is_allowed("amazonaws.com.evil.com", 443));
    }

    #[test]
    fn defaults_include_npm() {
        let a = Allowlist::new();
        assert!(a.is_allowed("registry.npmjs.org", 443));
    }

    #[test]
    fn defaults_include_github() {
        let a = Allowlist::new();
        assert!(a.is_allowed("github.com", 443));
    }

    #[test]
    fn unknown_blocked() {
        let a = Allowlist::new();
        assert!(!a.is_allowed("evil-data-collector.ru", 443));
        assert!(!a.is_allowed("45.33.12.8", 443));
    }
}
