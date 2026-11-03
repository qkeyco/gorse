// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Secret provider endpoint detection.
//!
//! Recognizes network destinations that serve secrets (Vault, AWS Secrets Manager,
//! 1Password, Keychain, etc.). When a process connects to one of these endpoints,
//! it should be tainted — the process now holds secrets and must be restricted.
//!
//! This closes the "vault gap": secrets fetched via API (not file open) were
//! previously invisible to the taint engine.
//!
//! ## Threat model
//!
//! A malicious dependency calls AWS Secrets Manager to read your database password,
//! then tries to POST it to evil.com. Without this module, the taint engine sees
//! a normal HTTPS connection to AWS and a normal HTTPS connection to evil.com —
//! no file was opened, no taint applied. With this module, the AWS connection
//! triggers taint, and the evil.com connection is blocked.

use std::collections::HashSet;

/// Registry of known secret provider endpoint patterns.
///
/// Matches against the hostname (addr) in network connect events.
pub struct SecretProviderRegistry {
    /// Exact hostnames that are secret providers.
    exact: HashSet<String>,
    /// Suffix patterns — any hostname ending with this is a secret provider.
    /// Stored WITHOUT leading dot (e.g., "vault.azure.net" matches "myvault.vault.azure.net").
    suffixes: Vec<String>,
    /// Prefix patterns — any hostname starting with this is a secret provider.
    prefixes: Vec<String>,
    /// User-added custom endpoints.
    custom: HashSet<String>,
    /// Whether this feature is enabled.
    enabled: bool,
}

/// Information about why an endpoint was classified as a secret provider.
#[derive(Debug, Clone)]
pub struct SecretProviderMatch {
    pub endpoint: String,
    pub provider_name: &'static str,
}

impl SecretProviderRegistry {
    /// Create with default known providers.
    pub fn new() -> Self {
        let mut reg = Self {
            exact: HashSet::with_capacity(16),
            suffixes: Vec::with_capacity(16),
            prefixes: Vec::with_capacity(16),
            custom: HashSet::new(),
            enabled: true,
        };
        reg.load_defaults();
        reg
    }

    /// Create empty (for testing).
    pub fn empty() -> Self {
        Self {
            exact: HashSet::new(),
            suffixes: Vec::new(),
            prefixes: Vec::new(),
            custom: HashSet::new(),
            enabled: true,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check if an address is a known secret provider endpoint.
    /// Returns the provider name if matched.
    pub fn check(&self, addr: &str) -> Option<SecretProviderMatch> {
        if !self.enabled {
            return None;
        }

        let addr_lower = addr.to_lowercase();

        // Exact match
        if self.exact.contains(&addr_lower) || self.custom.contains(&addr_lower) {
            return Some(SecretProviderMatch {
                endpoint: addr.to_string(),
                provider_name: self.identify_provider(&addr_lower),
            });
        }

        // Suffix match (e.g., *.vault.azure.net)
        for suffix in &self.suffixes {
            if addr_lower.ends_with(suffix)
                && (addr_lower.len() == suffix.len()
                    || addr_lower.as_bytes()[addr_lower.len() - suffix.len() - 1] == b'.')
            {
                return Some(SecretProviderMatch {
                    endpoint: addr.to_string(),
                    provider_name: self.identify_provider(&addr_lower),
                });
            }
        }

        // Prefix match (e.g., secretsmanager.*.amazonaws.com)
        for prefix in &self.prefixes {
            if addr_lower.starts_with(prefix) {
                return Some(SecretProviderMatch {
                    endpoint: addr.to_string(),
                    provider_name: self.identify_provider(&addr_lower),
                });
            }
        }

        None
    }

    /// Add a custom secret provider endpoint.
    pub fn add_endpoint(&mut self, addr: &str) {
        self.custom.insert(addr.to_lowercase());
    }

    /// Identify which provider a hostname belongs to (for logging).
    fn identify_provider(&self, addr: &str) -> &'static str {
        // HashiCorp Vault
        if addr.contains("vault") && !addr.contains("azure") {
            return "HashiCorp Vault";
        }
        // Azure Key Vault
        if addr.ends_with("vault.azure.net") {
            return "Azure Key Vault";
        }
        // AWS
        if addr.contains("amazonaws.com") {
            if addr.starts_with("secretsmanager") {
                return "AWS Secrets Manager";
            }
            if addr.starts_with("ssm") {
                return "AWS Systems Manager Parameter Store";
            }
            if addr.starts_with("kms") {
                return "AWS KMS";
            }
            return "AWS (secret service)";
        }
        // GCP
        if addr.contains("secretmanager.googleapis.com") {
            return "GCP Secret Manager";
        }
        // 1Password
        if addr.contains("1password") {
            return "1Password";
        }
        // Bitwarden
        if addr.contains("bitwarden") {
            return "Bitwarden";
        }
        // LastPass
        if addr.contains("lastpass") {
            return "LastPass";
        }
        // Doppler
        if addr.contains("doppler") {
            return "Doppler";
        }
        // Infisical
        if addr.contains("infisical") {
            return "Infisical";
        }
        "Secret provider"
    }

    /// Load default known secret provider endpoints.
    fn load_defaults(&mut self) {
        // ─── HashiCorp Vault ───
        // Common self-hosted patterns (user should add their own via config)
        self.exact.insert("vault.service.consul".to_string());

        // ─── Azure Key Vault ───
        // *.vault.azure.net
        self.suffixes.push("vault.azure.net".to_string());

        // ─── AWS Secrets Manager ───
        // secretsmanager.{region}.amazonaws.com
        self.prefixes.push("secretsmanager.".to_string());
        // AWS Systems Manager Parameter Store
        // ssm.{region}.amazonaws.com
        self.prefixes.push("ssm.".to_string());
        // AWS KMS (key management — processes that talk to KMS often hold secrets)
        self.prefixes.push("kms.".to_string());

        // ─── GCP Secret Manager ───
        self.exact
            .insert("secretmanager.googleapis.com".to_string());

        // ─── 1Password ───
        self.suffixes.push("1password.com".to_string());
        self.suffixes.push("1password.eu".to_string());
        self.suffixes.push("1password.ca".to_string());

        // ─── Bitwarden ───
        self.suffixes.push("bitwarden.com".to_string());
        self.exact.insert("api.bitwarden.com".to_string());
        self.exact.insert("vault.bitwarden.com".to_string());

        // ─── LastPass ───
        self.suffixes.push("lastpass.com".to_string());

        // ─── Doppler (secrets management) ───
        self.exact.insert("api.doppler.com".to_string());

        // ─── Infisical ───
        self.exact.insert("api.infisical.com".to_string());
        self.suffixes.push("infisical.com".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_secrets_manager_detected() {
        let reg = SecretProviderRegistry::new();
        let m = reg.check("secretsmanager.us-east-1.amazonaws.com");
        assert!(m.is_some());
        assert_eq!(m.unwrap().provider_name, "AWS Secrets Manager");
    }

    #[test]
    fn aws_ssm_detected() {
        let reg = SecretProviderRegistry::new();
        let m = reg.check("ssm.eu-west-1.amazonaws.com");
        assert!(m.is_some());
        assert_eq!(
            m.unwrap().provider_name,
            "AWS Systems Manager Parameter Store"
        );
    }

    #[test]
    fn azure_key_vault_detected() {
        let reg = SecretProviderRegistry::new();
        let m = reg.check("mycompany.vault.azure.net");
        assert!(m.is_some());
        assert_eq!(m.unwrap().provider_name, "Azure Key Vault");
    }

    #[test]
    fn gcp_secret_manager_detected() {
        let reg = SecretProviderRegistry::new();
        let m = reg.check("secretmanager.googleapis.com");
        assert!(m.is_some());
        assert_eq!(m.unwrap().provider_name, "GCP Secret Manager");
    }

    #[test]
    fn one_password_detected() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("my.1password.com").is_some());
        assert!(reg.check("api.1password.eu").is_some());
    }

    #[test]
    fn bitwarden_detected() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("api.bitwarden.com").is_some());
        assert!(reg.check("vault.bitwarden.com").is_some());
    }

    #[test]
    fn normal_endpoints_not_matched() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("github.com").is_none());
        assert!(reg.check("registry.npmjs.org").is_none());
        assert!(reg.check("google.com").is_none());
        assert!(reg.check("api.stripe.com").is_none());
    }

    #[test]
    fn custom_endpoint_works() {
        let mut reg = SecretProviderRegistry::new();
        reg.add_endpoint("vault.internal.mycompany.com");
        assert!(reg.check("vault.internal.mycompany.com").is_some());
    }

    #[test]
    fn disabled_returns_none() {
        let mut reg = SecretProviderRegistry::new();
        reg.set_enabled(false);
        assert!(reg
            .check("secretsmanager.us-east-1.amazonaws.com")
            .is_none());
    }

    #[test]
    fn case_insensitive() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("SecretManager.googleapis.com").is_some());
        assert!(reg
            .check("SECRETSMANAGER.US-EAST-1.AMAZONAWS.COM")
            .is_some());
    }

    #[test]
    fn suffix_requires_dot_boundary() {
        let reg = SecretProviderRegistry::new();
        // "not1password.com" should NOT match the suffix "1password.com"
        // because there's no dot boundary
        assert!(reg.check("not1password.com").is_none());
        // But "app.1password.com" should match
        assert!(reg.check("app.1password.com").is_some());
        // And exact "1password.com" should match (length equals suffix)
        assert!(reg.check("1password.com").is_some());
    }

    #[test]
    fn vault_consul_detected() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("vault.service.consul").is_some());
    }

    #[test]
    fn doppler_detected() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("api.doppler.com").is_some());
    }

    #[test]
    fn infisical_detected() {
        let reg = SecretProviderRegistry::new();
        assert!(reg.check("api.infisical.com").is_some());
        assert!(reg.check("app.infisical.com").is_some());
    }
}
