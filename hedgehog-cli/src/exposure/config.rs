// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Declared infrastructure for exposure analysis: `~/.hedgehog/authority.toml`.
//!
//! A laptop cannot see, on its own, that the cluster its kubeconfig reaches
//! hosts the service that talks to the treasury signer. Teams declare that
//! topology once, here, and discovery attaches real credentials to it.
//! Everything in this file is metadata: names, addresses, policies. It
//! must never contain secrets, and the scanner never writes to it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Declarations {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, rename = "production_system")]
    pub production_systems: Vec<ProductionSystem>,
    #[serde(default, rename = "signer")]
    pub signers: Vec<Signer>,
    #[serde(default, rename = "wallet")]
    pub wallets: Vec<Wallet>,
    #[serde(default, rename = "role")]
    pub roles: Vec<RoleHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Allow `gorse exposure --verify` to run read-only identity and
    /// permission queries against remote providers. The flag is still
    /// required; this only forbids it when false.
    #[serde(default = "default_true")]
    pub allow_remote_verification: bool,
    /// Substrings that mark a cluster, profile, host or context as production.
    #[serde(default = "default_production_patterns")]
    pub production_patterns: Vec<String>,
    /// Extra directories whose `.env*` files are inspected for signing and
    /// provider credentials (the current directory is always included).
    #[serde(default)]
    pub project_dirs: Vec<String>,
    /// Maximum hops when searching for indirect paths.
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_remote_verification: true,
            production_patterns: default_production_patterns(),
            project_dirs: Vec::new(),
            max_hops: default_max_hops(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_max_hops() -> usize {
    6
}
fn default_production_patterns() -> Vec<String> {
    ["prod", "production", "mainnet", "live", "treasury"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// A production service, cluster, CI system or secrets manager and what it
/// can reach. `hosts` are the names discovery will match against: kube
/// context or cluster names, AWS account ids or role names, hostnames,
/// GitHub `owner/repo`, registry hostnames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionSystem {
    pub name: String,
    /// service | cluster | ci | secrets_manager | registry | repository
    #[serde(default = "default_service_kind")]
    pub kind: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Names of signers this system can request signatures from.
    #[serde(default)]
    pub reaches: Vec<String>,
    /// Names of other production systems this one can deploy to or modify.
    #[serde(default)]
    pub deploys_to: Vec<String>,
    /// Kubernetes namespaces this system lives in. `--verify` checks RBAC in
    /// each of them (read-only) as well as the context's own namespace.
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// An approval that gates changes here (e.g. "PR review + CI", "change ticket").
    #[serde(default)]
    pub change_approval: Option<String>,
}

fn default_service_kind() -> String {
    "service".to_string()
}

/// A signing service: HSM, MPC, multisig coordinator, custody API, or a
/// plain software signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub name: String,
    /// hsm | mpc | multisig | custody | software
    #[serde(default = "default_signer_kind")]
    pub kind: String,
    /// Environment variables whose presence means this laptop can authenticate to the signer.
    #[serde(default)]
    pub api_env: Vec<String>,
    /// Files whose presence means this laptop can authenticate to the signer (~ expands).
    #[serde(default)]
    pub api_files: Vec<String>,
    /// Hostnames of the signing API.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Wallet names (from `[[wallet]]`) this signer controls.
    #[serde(default)]
    pub wallets: Vec<String>,
    /// True when a request from an API credential is not enough: another
    /// party or policy engine must approve before anything is signed.
    #[serde(default)]
    pub requires_independent_approval: bool,
    /// Description of that approval ("2-of-3 TAP policy", "second HSM operator").
    #[serde(default)]
    pub approval: Option<String>,
    /// Whether the device enforces a transaction policy (destinations,
    /// limits) or merely signs whatever payload it is handed.
    #[serde(default)]
    pub enforces_transaction_policy: bool,
    /// Whether the API credential can change the signing policy or signer set.
    #[serde(default)]
    pub api_can_change_policy: bool,
    /// Whether the service will sign arbitrary EIP-7702 authorization tuples.
    #[serde(default)]
    pub accepts_arbitrary_7702: bool,
    /// Other signers or services whose compromise also compromises this one
    /// (shared key-management dependency across "independent" participants).
    #[serde(default)]
    pub shared_dependencies: Vec<String>,
    /// Required approvers (multisig threshold), when known.
    #[serde(default)]
    pub threshold: Option<u32>,
    /// How many approvers live on this laptop (keys or sessions present).
    #[serde(default)]
    pub approvers_on_this_laptop: Option<u32>,
}

fn default_signer_kind() -> String {
    "software".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wallet {
    pub name: String,
    /// ethereum | bitcoin | solana
    pub chain: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default = "default_true")]
    pub production: bool,
    /// Environment variable holding the RPC URL used for `--verify` (eth_getCode only).
    #[serde(default)]
    pub rpc_url_env: Option<String>,
    /// Reviewed EIP-7702 delegate implementations.
    #[serde(default)]
    pub approved_delegates: Vec<String>,
    /// Known-malicious delegate implementations (from a threat feed).
    #[serde(default)]
    pub malicious_delegates: Vec<String>,
    /// Bitcoin signing policy an independent approver should enforce.
    #[serde(default)]
    pub bitcoin_policy: Option<BitcoinPolicy>,
    /// A PSBT file to evaluate against the policy (never signed).
    #[serde(default)]
    pub psbt_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BitcoinPolicy {
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    #[serde(default)]
    pub max_fee_sats: Option<u64>,
    #[serde(default)]
    pub max_fee_rate_sat_vb: Option<u64>,
    #[serde(default)]
    pub max_withdrawal_sats: Option<u64>,
    #[serde(default)]
    pub require_change_validation: bool,
    #[serde(default)]
    pub require_independent_output_verification: bool,
    #[serde(default)]
    pub independent_verification_available: bool,
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_network() -> String {
    "mainnet".to_string()
}

/// What a cloud role or policy means, when its name alone is not enough.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleHint {
    /// Substring matched against role ARNs, policy names, Azure role names, Vault policies.
    pub name_contains: String,
    #[serde(default)]
    pub administrative: bool,
    #[serde(default)]
    pub production: bool,
    #[serde(default)]
    pub can_create_credentials: bool,
    #[serde(default)]
    pub read_only: bool,
}

impl Declarations {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut decl: Declarations = toml::from_str(text).map_err(|e| e.to_string())?;
        // `change_approval = ""` / `approval = ""` mean "none", not an
        // unnamed gate. Normalise so every consumer sees `None`.
        fn blank_to_none(v: &mut Option<String>) {
            if v.as_deref().map(|s| s.trim().is_empty()).unwrap_or(false) {
                *v = None;
            }
        }
        for s in &mut decl.production_systems {
            blank_to_none(&mut s.change_approval);
        }
        for s in &mut decl.signers {
            blank_to_none(&mut s.approval);
        }
        // Refuse anything that looks like secret material in a metadata file.
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("private_key")
                || lower.contains("mnemonic")
                || lower.contains("seed_phrase")
            {
                return Err("authority.toml must not contain private keys or seed phrases".into());
            }
        }
        Ok(decl)
    }

    pub fn default_path() -> PathBuf {
        crate::config::config_dir().join("authority.toml")
    }

    pub fn is_production_name(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        // What the user declared wins over any guess from the name: a host
        // called "james-devbox-02" can be the master production server.
        if self
            .production_systems
            .iter()
            .any(|s| s.hosts.iter().any(|h| h.eq_ignore_ascii_case(name)))
        {
            return true;
        }
        let defaults = default_production_patterns();
        if self
            .settings
            .production_patterns
            .iter()
            .filter(|p| !defaults.iter().any(|d| d.eq_ignore_ascii_case(p)))
            .any(|p| !p.is_empty() && lower.contains(&p.to_ascii_lowercase()))
        {
            return true;
        }
        if [
            "nonprod", "non-prod", "preprod", "pre-prod", "staging", "sandbox", "dev",
        ]
        .iter()
        .any(|neg| lower.contains(neg))
        {
            return false;
        }
        self.settings
            .production_patterns
            .iter()
            .any(|p| !p.is_empty() && lower.contains(&p.to_ascii_lowercase()))
    }

    /// Record a host as a production system in the map at `path`, creating
    /// the map from the example when it does not exist. Returns whether a
    /// change was written. The file is re-parsed before it is kept.
    pub fn mark_production(path: &Path, host: &str) -> Result<bool, String> {
        let host = host.trim();
        if host.is_empty() || host.contains('"') || host.contains('\n') {
            return Err("host name must be a plain name".into());
        }
        let existing = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => EXAMPLE.to_string(),
            Err(e) => return Err(format!("could not read {}: {e}", path.display())),
        };
        let current = Declarations::parse(&existing)?;
        if current
            .production_systems
            .iter()
            .any(|s| s.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
        {
            return Ok(false);
        }
        let mut text = existing;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!(
            "\n# Marked as production from the app.\n[[production_system]]\nname = \"{host}\"\nkind = \"service\"\nhosts = [\"{host}\"]\n"
        ));
        let parsed = Declarations::parse(&text)?;
        if !parsed.is_production_name(host) {
            return Err("the map did not accept the new entry".into());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, text)
            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(true)
    }

    pub fn systems_hosting(&self, name: &str) -> Vec<&ProductionSystem> {
        let lower = name.to_ascii_lowercase();
        self.production_systems
            .iter()
            .filter(|s| {
                s.hosts.iter().any(|h| {
                    lower == h.to_ascii_lowercase() || lower.contains(&h.to_ascii_lowercase())
                })
            })
            .collect()
    }

    pub fn role_hint(&self, name: &str) -> Option<&RoleHint> {
        let lower = name.to_ascii_lowercase();
        self.roles
            .iter()
            .find(|r| lower.contains(&r.name_contains.to_ascii_lowercase()))
    }

    pub fn signer(&self, name: &str) -> Option<&Signer> {
        self.signers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn wallet(&self, name: &str) -> Option<&Wallet> {
        self.wallets
            .iter()
            .find(|w| w.name.eq_ignore_ascii_case(name))
    }

    /// Example file written by `gorse exposure --init`.
    pub fn example() -> &'static str {
        EXAMPLE
    }
}

const EXAMPLE: &str = r#"# Gorse authority map — describe your infrastructure so the exposure
# check can connect the credentials on this laptop to what they reach.
# Metadata only. Never put keys, tokens or seed phrases in this file.

[settings]
allow_remote_verification = true
production_patterns = ["prod", "production", "mainnet", "live", "treasury"]
project_dirs = []
max_hops = 6

# A production system and what it can reach.
# [[production_system]]
# name = "payments-api"
# kind = "service"
# hosts = ["prod-eks", "arn:aws:eks:us-east-1:123456789012:cluster/prod"]
# namespaces = ["payments"]
# reaches = ["treasury-signer"]
# change_approval = "PR review + CI"

# A signing service.
# [[signer]]
# name = "treasury-signer"
# kind = "mpc"
# api_env = ["FIREBLOCKS_API_KEY"]
# api_files = ["~/.fireblocks/api.key"]
# hosts = ["api.fireblocks.io"]
# wallets = ["treasury"]
# requires_independent_approval = true
# approval = "2-of-3 transaction authorization policy"
# enforces_transaction_policy = true
# api_can_change_policy = false
# accepts_arbitrary_7702 = false

# A wallet.
# [[wallet]]
# name = "treasury"
# chain = "ethereum"
# address = "0x0000000000000000000000000000000000000000"
# production = true
# rpc_url_env = "ETH_RPC_URL"
# approved_delegates = []

# [[wallet]]
# name = "cold-storage"
# chain = "bitcoin"
# psbt_file = "~/Desktop/pending.psbt"
# [wallet.bitcoin_policy]
# allowed_destinations = ["bc1q..."]
# max_fee_sats = 50000
# max_withdrawal_sats = 100000000
# require_change_validation = true
# require_independent_output_verification = true
# independent_verification_available = false

# What a role name means.
# [[role]]
# name_contains = "AdministratorAccess"
# administrative = true
# can_create_credentials = true
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_hosts_beat_the_dev_name_heuristic() {
        let d = Declarations::parse(Declarations::example()).unwrap();
        assert!(
            !d.is_production_name("james-devbox-02"),
            "a dev-looking name is not production by default"
        );
        assert!(d.is_production_name("prod-eks"));
        let dir = std::env::temp_dir().join(format!("hedgehog-map-{}", std::process::id()));
        let path = dir.join("authority.toml");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(Declarations::mark_production(&path, "james-devbox-02").unwrap());
        assert!(
            !Declarations::mark_production(&path, "james-devbox-02").unwrap(),
            "second call is a no-op"
        );
        let d = Declarations::load(&path).unwrap();
        assert!(
            d.is_production_name("james-devbox-02"),
            "the declaration wins over the name"
        );
        assert!(d.is_production_name("JAMES-DEVBOX-02"));
        assert!(!d.is_production_name("devbox-03"));
        assert!(Declarations::mark_production(&path, "bad\"name").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn example_parses_and_is_empty() {
        let d = Declarations::parse(Declarations::example()).unwrap();
        assert!(d.signers.is_empty());
        assert_eq!(d.settings.max_hops, 6);
    }

    #[test]
    fn full_declaration_parses() {
        let d = Declarations::parse(
            r#"
[[production_system]]
name = "payments-api"
hosts = ["prod-eks"]
reaches = ["treasury-signer"]

[[signer]]
name = "treasury-signer"
kind = "hsm"
api_env = ["SIGNER_API_KEY"]
wallets = ["treasury"]
requires_independent_approval = true
approval = "second operator"

[[wallet]]
name = "treasury"
chain = "ethereum"
address = "0x1111111111111111111111111111111111111111"

[[role]]
name_contains = "Admin"
administrative = true
"#,
        )
        .unwrap();
        assert!(d.is_production_name("prod-eks"));
        assert!(d.is_production_name("my-production-cluster"));
        assert!(!d.is_production_name("preprod-cluster"));
        assert_eq!(d.systems_hosting("prod-eks")[0].name, "payments-api");
        assert!(
            d.role_hint("arn:aws:iam::1:role/AdminRole")
                .unwrap()
                .administrative
        );
        assert!(d.signer("TREASURY-SIGNER").is_some());
    }

    #[test]
    fn blank_approvals_normalise_to_none() {
        let d = Declarations::parse(
            "[[production_system]]\nname = \"w\"\nchange_approval = \"\"\n\n[[signer]]\nname = \"s\"\nkind = \"hsm\"\napproval = \" \"\n",
        )
        .unwrap();
        assert!(d.production_systems[0].change_approval.is_none());
        assert!(d.signers[0].approval.is_none());
    }

    #[test]
    fn rejects_secret_material() {
        assert!(Declarations::parse("[settings]\n# private_key = x\n").is_err());
        assert!(
            Declarations::parse("[[wallet]]\nname='a'\nchain='ethereum'\nunknown=1\n").is_err()
        );
    }
}
