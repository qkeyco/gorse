// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Authority analysis — "if this laptop were compromised, what could an
//! attacker reach?"
//!
//! The secret detector answers *which* credential files exist. This module
//! answers what those credentials can *do*: which identities they represent,
//! what permissions they confer, which systems they reach indirectly, whether
//! they can request or approve a financial signature, and whether the access
//! would survive the laptop being wiped.
//!
//! Everything here is pure data and pure logic with zero dependencies, so it
//! can run offline and inside the macOS system extension. File I/O, network
//! verification and report rendering live in the CLI.
//!
//! Security invariants, enforced by construction:
//! - No type here can hold a raw secret. Credentials are described by a
//!   [`Fingerprint`] (a short, non-reversible identifier) and metadata.
//! - Nothing here signs, submits, authenticates or mutates anything.
//! - Confirmed, inferred and unknown permissions are distinct states and
//!   never collapse into one another.

pub mod eip7702;
pub mod graph;
pub mod psbt;
pub mod scoring;

pub use graph::{
    AttackPath, Edge, EdgeKind, Node, NodeId, NodeKind, PermissionGraph, Reachability,
};
pub use scoring::{score_finding, ExposureFinding, ExposureSummary, Severity};

/// Current unix time in seconds (0 if the clock is before 1970).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Non-reversible identifier for a credential: never the secret itself.
///
/// For keys with a public component (SSH, AWS access key id, GitHub token
/// prefix) use the public or structural part. For opaque tokens use a
/// truncated digest. Either way the value is safe to print and persist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    /// Build a fingerprint from a public identifier such as an AWS access
    /// key id or a token prefix: keeps a recognisable prefix and the last
    /// four characters, masks the middle.
    pub fn from_public_id(id: &str) -> Self {
        let chars: Vec<char> = id.chars().collect();
        if chars.len() <= 8 {
            return Fingerprint("…".to_string());
        }
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        Fingerprint(format!("{head}…{tail}"))
    }

    /// Build a fingerprint from secret material. The input is hashed with a
    /// fixed, non-cryptographic 64-bit FNV-1a and only 8 hex digits are kept.
    /// This is enough to recognise the same credential twice and far too
    /// little to recover it.
    pub fn from_secret(material: &[u8]) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in material {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Fingerprint(format!("fnv:{:08x}", (hash >> 32) as u32 ^ hash as u32))
    }
}

/// Whether a statement about a permission is backed by evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Assurance {
    /// Verified against the authority that grants it (an API answered).
    Confirmed,
    /// Derived from local configuration, naming or credential type.
    Inferred,
    /// Could not be determined; the capability may or may not exist.
    Unknown,
}

impl Assurance {
    pub fn label(&self) -> &'static str {
        match self {
            Assurance::Confirmed => "confirmed",
            Assurance::Inferred => "inferred",
            Assurance::Unknown => "unknown",
        }
    }

    /// The weaker of two assurances. A path is only as confirmed as its
    /// least confirmed step.
    pub fn weakest(self, other: Assurance) -> Assurance {
        if self >= other {
            self
        } else {
            other
        }
    }
}

/// A single capability claim with the state of knowledge behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Yes,
    No,
    Unknown,
}

impl Capability {
    pub fn label(&self) -> &'static str {
        match self {
            Capability::Yes => "yes",
            Capability::No => "no",
            Capability::Unknown => "unknown",
        }
    }
    pub fn is_yes(&self) -> bool {
        matches!(self, Capability::Yes)
    }
}

/// What a credential is for. Drives discovery, defaults and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    AwsAccessKey,
    AwsSession,
    AwsSsoSession,
    AwsProfileRole,
    GcpUserCredential,
    GcpServiceAccount,
    AzureSession,
    AzureServicePrincipal,
    VaultToken,
    SecretsManagerAccess,
    GitHubToken,
    GitHubAppKey,
    GitLabToken,
    CiToken,
    DockerRegistry,
    KubernetesContext,
    TerraformToken,
    DigitalOceanToken,
    SshPrivateKey,
    SshCertificate,
    SshAgentIdentity,
    EthereumKeystore,
    EthereumPrivateKey,
    BitcoinWallet,
    SolanaKeypair,
    WalletConnectSession,
    SigningServiceApiKey,
    RpcProviderKey,
    OAuthSession,
    ApiKey,
    EnvironmentSecret,
    Other,
}

impl CredentialKind {
    /// A credential that logs in to hosts over SSH: a shell, not mere
    /// reachability.
    pub fn is_ssh_login(&self) -> bool {
        matches!(
            self,
            CredentialKind::SshPrivateKey
                | CredentialKind::SshCertificate
                | CredentialKind::SshAgentIdentity
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            CredentialKind::AwsAccessKey => "AWS access key",
            CredentialKind::AwsSession => "AWS temporary session",
            CredentialKind::AwsSsoSession => "AWS SSO session",
            CredentialKind::AwsProfileRole => "AWS role profile",
            CredentialKind::GcpUserCredential => "Google Cloud user credential",
            CredentialKind::GcpServiceAccount => "Google Cloud service account key",
            CredentialKind::AzureSession => "Azure CLI session",
            CredentialKind::AzureServicePrincipal => "Azure service principal",
            CredentialKind::VaultToken => "HashiCorp Vault token",
            CredentialKind::SecretsManagerAccess => "Secrets manager access",
            CredentialKind::GitHubToken => "GitHub token",
            CredentialKind::GitHubAppKey => "GitHub App private key",
            CredentialKind::GitLabToken => "GitLab token",
            CredentialKind::CiToken => "CI/CD token",
            CredentialKind::DockerRegistry => "Container registry login",
            CredentialKind::KubernetesContext => "Kubernetes context",
            CredentialKind::TerraformToken => "Terraform/IaC token",
            CredentialKind::DigitalOceanToken => "DigitalOcean API token",
            CredentialKind::SshPrivateKey => "SSH private key",
            CredentialKind::SshCertificate => "SSH certificate",
            CredentialKind::SshAgentIdentity => "SSH agent identity",
            CredentialKind::EthereumKeystore => "Ethereum keystore",
            CredentialKind::EthereumPrivateKey => "Ethereum private key",
            CredentialKind::BitcoinWallet => "Bitcoin wallet",
            CredentialKind::SolanaKeypair => "Solana keypair",
            CredentialKind::WalletConnectSession => "WalletConnect session",
            CredentialKind::SigningServiceApiKey => "Signing service API credential",
            CredentialKind::RpcProviderKey => "Blockchain RPC provider key",
            CredentialKind::OAuthSession => "OAuth session",
            CredentialKind::ApiKey => "API key",
            CredentialKind::EnvironmentSecret => "Environment secret",
            CredentialKind::Other => "Credential",
        }
    }

    /// Whether this kind of credential is, by its nature, usable from
    /// anywhere once copied (as opposed to being bound to this machine).
    pub fn portable_by_default(&self) -> bool {
        !matches!(
            self,
            CredentialKind::WalletConnectSession | CredentialKind::SshAgentIdentity
        )
    }
}

/// Lifetime of a credential as far as it can be determined locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lifetime {
    /// No expiry: usable until revoked.
    LongLived,
    /// Expires at the given unix time.
    ExpiresAt(u64),
    /// Already expired at the given unix time.
    ExpiredAt(u64),
    /// Not determinable from local data.
    Unknown,
}

impl Lifetime {
    pub fn is_expired(&self) -> bool {
        matches!(self, Lifetime::ExpiredAt(_))
    }
    pub fn label(&self) -> String {
        match self {
            Lifetime::LongLived => "long-lived (no expiry)".to_string(),
            Lifetime::ExpiresAt(t) => format!("expires at unix {t}"),
            Lifetime::ExpiredAt(t) => format!("expired at unix {t}"),
            Lifetime::Unknown => "unknown lifetime".to_string(),
        }
    }
}

/// Where a credential would still work after the laptop is wiped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Persistence {
    /// Only usable while the attacker has the endpoint (agent socket,
    /// browser session bound to device, hardware-backed key).
    RequiresEndpoint,
    /// Copied credential keeps working on its own until revoked or expired.
    IndependentCredential,
    /// Attacker can mint server-side access that outlives the credential
    /// (new keys, new roles, deploy tokens, OAuth refresh).
    ServerSide,
    /// On-chain authorization (EIP-7702 delegation, Safe module, approval)
    /// that persists until explicitly removed.
    Blockchain,
    Unknown,
}

impl Persistence {
    pub fn label(&self) -> &'static str {
        match self {
            Persistence::RequiresEndpoint => "requires current endpoint access",
            Persistence::IndependentCredential => {
                "usable through an independently valid credential"
            }
            Persistence::ServerSide => "persistent server-side access",
            Persistence::Blockchain => "persistent blockchain authorization",
            Persistence::Unknown => "unknown",
        }
    }
    pub fn key(&self) -> &'static str {
        match self {
            Persistence::RequiresEndpoint => "requires_endpoint",
            Persistence::IndependentCredential => "independent_credential",
            Persistence::ServerSide => "server_side",
            Persistence::Blockchain => "blockchain",
            Persistence::Unknown => "unknown",
        }
    }
    /// Whether the access survives cleaning the laptop.
    pub fn survives_cleanup(&self) -> bool {
        !matches!(self, Persistence::RequiresEndpoint)
    }
}

/// One capability flag of [`EffectivePermissions`], by name, so the
/// assurance behind each flag can be tracked on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    Administrative,
    CreateCredentials,
    ModifyOwnPermissions,
    AssumeRole,
    AccessProduction,
    ModifyProduction,
    ReachSigningInfrastructure,
    RequiresMfa,
    RequiresIndependentApproval,
}

impl Permission {
    pub const ALL: [Permission; 9] = [
        Permission::Administrative,
        Permission::CreateCredentials,
        Permission::ModifyOwnPermissions,
        Permission::AssumeRole,
        Permission::AccessProduction,
        Permission::ModifyProduction,
        Permission::ReachSigningInfrastructure,
        Permission::RequiresMfa,
        Permission::RequiresIndependentApproval,
    ];

    /// The field name, as the JSON report uses it.
    pub fn key(self) -> &'static str {
        match self {
            Permission::Administrative => "administrative",
            Permission::CreateCredentials => "can_create_credentials",
            Permission::ModifyOwnPermissions => "can_modify_own_permissions",
            Permission::AssumeRole => "can_assume_role",
            Permission::AccessProduction => "can_access_production",
            Permission::ModifyProduction => "can_modify_production",
            Permission::ReachSigningInfrastructure => "can_reach_signing_infrastructure",
            Permission::RequiresMfa => "requires_mfa",
            Permission::RequiresIndependentApproval => "requires_independent_approval",
        }
    }
}

/// What a credential is known or believed to be able to do.
///
/// Every field is a [`Capability`], never a bool, so "we did not check" is
/// representable and is the default.
///
/// Two kinds of assurance are kept apart. [`assurance`](Self::assurance)
/// says how well the credential itself is established: who it is and that
/// it is live. A provider that answers "this key belongs to alice" makes it
/// confirmed, and that answer says nothing about what alice can do. Each
/// capability flag is confirmed only when a provider check established that
/// specific permission, recorded in [`confirmed`](Self::confirmed); every
/// other flag, however it was set (a policy name, a token scope, a naming
/// convention), is at most inferred. Read a flag's assurance with
/// [`capability_assurance`](Self::capability_assurance), never with
/// `assurance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePermissions {
    /// How well the identity and validity of the credential are known.
    pub assurance: Assurance,
    /// Identity the credential acts as (account, user, principal, address).
    pub identity: Option<String>,
    /// Owning account, organisation, project or tenant.
    pub organization: Option<String>,
    /// Human-readable permission scope (policy names, token scopes, RBAC rules).
    pub scope: Vec<String>,
    /// Resource restrictions (namespaces, repos, buckets, chains).
    pub restrictions: Vec<String>,
    pub lifetime: Lifetime,
    pub revoked: Capability,
    /// Interactive user credential vs automation.
    pub automated: Capability,
    pub requires_mfa: Capability,
    pub requires_independent_approval: Capability,
    pub can_assume_role: Capability,
    pub can_modify_own_permissions: Capability,
    pub can_create_credentials: Capability,
    pub can_access_production: Capability,
    pub can_modify_production: Capability,
    pub can_reach_signing_infrastructure: Capability,
    pub administrative: Capability,
    /// Capabilities a provider check established one by one. Only these
    /// may be reported as confirmed. Set through [`confirm`](Self::confirm).
    pub confirmed: Vec<Permission>,
}

impl Default for EffectivePermissions {
    fn default() -> Self {
        Self {
            assurance: Assurance::Unknown,
            identity: None,
            organization: None,
            scope: Vec::new(),
            restrictions: Vec::new(),
            lifetime: Lifetime::Unknown,
            revoked: Capability::Unknown,
            automated: Capability::Unknown,
            requires_mfa: Capability::Unknown,
            requires_independent_approval: Capability::Unknown,
            can_assume_role: Capability::Unknown,
            can_modify_own_permissions: Capability::Unknown,
            can_create_credentials: Capability::Unknown,
            can_access_production: Capability::Unknown,
            can_modify_production: Capability::Unknown,
            can_reach_signing_infrastructure: Capability::Unknown,
            administrative: Capability::Unknown,
            confirmed: Vec::new(),
        }
    }
}

impl EffectivePermissions {
    pub fn unknown() -> Self {
        Self::default()
    }

    /// The value of one capability flag.
    pub fn get(&self, p: Permission) -> Capability {
        match p {
            Permission::Administrative => self.administrative,
            Permission::CreateCredentials => self.can_create_credentials,
            Permission::ModifyOwnPermissions => self.can_modify_own_permissions,
            Permission::AssumeRole => self.can_assume_role,
            Permission::AccessProduction => self.can_access_production,
            Permission::ModifyProduction => self.can_modify_production,
            Permission::ReachSigningInfrastructure => self.can_reach_signing_infrastructure,
            Permission::RequiresMfa => self.requires_mfa,
            Permission::RequiresIndependentApproval => self.requires_independent_approval,
        }
    }

    fn slot(&mut self, p: Permission) -> &mut Capability {
        match p {
            Permission::Administrative => &mut self.administrative,
            Permission::CreateCredentials => &mut self.can_create_credentials,
            Permission::ModifyOwnPermissions => &mut self.can_modify_own_permissions,
            Permission::AssumeRole => &mut self.can_assume_role,
            Permission::AccessProduction => &mut self.can_access_production,
            Permission::ModifyProduction => &mut self.can_modify_production,
            Permission::ReachSigningInfrastructure => &mut self.can_reach_signing_infrastructure,
            Permission::RequiresMfa => &mut self.requires_mfa,
            Permission::RequiresIndependentApproval => &mut self.requires_independent_approval,
        }
    }

    /// Set a capability that a provider check established for this specific
    /// permission. An `Unknown` value establishes nothing and is recorded
    /// as not confirmed.
    pub fn confirm(&mut self, p: Permission, value: Capability) {
        *self.slot(p) = value;
        self.confirmed.retain(|c| *c != p);
        if value != Capability::Unknown {
            self.confirmed.push(p);
        }
    }

    /// Set a capability from anything short of a provider check of that
    /// permission: a policy or role name, a token scope, a naming
    /// convention. It reads as inferred at best.
    pub fn infer(&mut self, p: Permission, value: Capability) {
        *self.slot(p) = value;
        self.confirmed.retain(|c| *c != p);
    }

    /// Whether a provider check established this capability.
    pub fn is_confirmed(&self, p: Permission) -> bool {
        self.confirmed.contains(&p)
    }

    /// The assurance behind one capability flag: confirmed only when a
    /// provider check established it; otherwise no stronger than inferred,
    /// and no stronger than the credential's own assurance.
    pub fn capability_assurance(&self, p: Permission) -> Assurance {
        if self.is_confirmed(p) {
            Assurance::Confirmed
        } else {
            self.assurance.weakest(Assurance::Inferred)
        }
    }

    /// The assurance behind the capability flags taken together: the
    /// weakest of every flag that was determined (yes or no). With nothing
    /// determined it is never confirmed, since nothing was established.
    pub fn capabilities_assurance(&self) -> Assurance {
        let mut determined = Permission::ALL
            .iter()
            .filter(|p| self.get(**p) != Capability::Unknown)
            .peekable();
        if determined.peek().is_none() {
            return self.assurance.weakest(Assurance::Inferred);
        }
        determined.fold(Assurance::Confirmed, |a, p| {
            a.weakest(self.capability_assurance(*p))
        })
    }

    /// Drop every per-capability confirmation: what remains is inferred.
    pub fn clear_confirmations(&mut self) {
        self.confirmed.clear();
    }

    /// True when any privileged capability is confirmed or inferred.
    pub fn is_privileged(&self) -> bool {
        self.administrative.is_yes()
            || self.can_modify_own_permissions.is_yes()
            || self.can_create_credentials.is_yes()
            || self.can_modify_production.is_yes()
            || self.can_reach_signing_infrastructure.is_yes()
    }
}

/// A discovered credential or authenticated session. Never holds the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCredential {
    pub kind: CredentialKind,
    /// Human name: profile name, context name, key comment, hostname.
    pub name: String,
    /// Where it was found (file path, env var name, agent socket).
    pub location: String,
    pub fingerprint: Fingerprint,
    /// Remote system the credential authenticates to.
    pub target: String,
    pub permissions: EffectivePermissions,
    pub persistence: Persistence,
    /// Short factual notes shown as evidence (never secret material).
    pub evidence: Vec<String>,
    /// A private key stored with no passphrase: usable the moment the file is
    /// copied. Set by discovery when it can tell; false when unknown.
    pub unprotected: bool,
}

impl DiscoveredCredential {
    pub fn new(kind: CredentialKind, name: &str, location: &str, target: &str) -> Self {
        Self {
            kind,
            name: name.to_string(),
            location: location.to_string(),
            fingerprint: Fingerprint("—".to_string()),
            target: target.to_string(),
            permissions: EffectivePermissions::unknown(),
            persistence: Persistence::Unknown,
            evidence: Vec::new(),
            unprotected: false,
        }
    }
}

/// Scrub anything that looks like secret material out of free text before
/// it is stored as evidence. Replaces long high-entropy tokens with their
/// fingerprint. Conservative: it would rather mask a harmless word.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for token in text.split_inclusive(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '=' || c == ':'
    }) {
        let trimmed_end = token.trim_end_matches(|c: char| {
            c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '=' || c == ':'
        });
        let suffix = &token[trimmed_end.len()..];
        if looks_like_secret(trimmed_end) {
            out.push_str(&Fingerprint::from_secret(trimmed_end.as_bytes()).0);
        } else {
            out.push_str(trimmed_end);
        }
        out.push_str(suffix);
    }
    out
}

fn looks_like_secret(token: &str) -> bool {
    if token.len() < 20 {
        return false;
    }
    let classes = [
        token.chars().any(|c| c.is_ascii_lowercase()),
        token.chars().any(|c| c.is_ascii_uppercase()),
        token.chars().any(|c| c.is_ascii_digit()),
    ];
    let class_count = classes.iter().filter(|c| **c).count();
    let alnum = token
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || *c == '_'
                || *c == '-'
                || *c == '+'
                || *c == '/'
                || *c == '='
        })
        .count();
    // Mostly token characters, mixed classes, no path separators: looks like a secret.
    alnum * 10 >= token.len() * 9
        && class_count >= 2
        && !token.contains('/')
        && !token.contains('.')
        || token.starts_with("0x") && token.len() >= 40
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_from_public_id_masks_middle() {
        let f = Fingerprint::from_public_id("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(f.0, "AKIA…MPLE");
        assert!(!f.0.contains("IOSFODNN"));
    }

    #[test]
    fn fingerprint_from_secret_is_short_and_stable() {
        let a = Fingerprint::from_secret(b"ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        let b = Fingerprint::from_secret(b"ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(a, b);
        assert!(a.0.starts_with("fnv:"));
        assert_eq!(a.0.len(), 12);
    }

    #[test]
    fn redact_text_masks_token_like_words_and_keeps_prose() {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let text = format!("token={secret} user=alice scope=repo");
        let redacted = redact_text(&text);
        assert!(!redacted.contains(secret));
        assert!(redacted.contains("user=alice"));
        assert!(redacted.contains("scope=repo"));
    }

    #[test]
    fn redact_text_keeps_paths_and_urls() {
        let text = "https://api.github.com/user and /Users/alice/.config/gh/hosts.yml";
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn assurance_weakest_prefers_unknown() {
        assert_eq!(
            Assurance::Confirmed.weakest(Assurance::Inferred),
            Assurance::Inferred
        );
        assert_eq!(
            Assurance::Inferred.weakest(Assurance::Unknown),
            Assurance::Unknown
        );
        assert_eq!(
            Assurance::Confirmed.weakest(Assurance::Confirmed),
            Assurance::Confirmed
        );
    }

    #[test]
    fn identity_assurance_never_confirms_a_capability() {
        let mut p = EffectivePermissions {
            assurance: Assurance::Confirmed,
            ..Default::default()
        };
        p.infer(Permission::Administrative, Capability::Yes);
        assert_eq!(
            p.capability_assurance(Permission::Administrative),
            Assurance::Inferred
        );
        assert_eq!(p.capabilities_assurance(), Assurance::Inferred);
        p.confirm(Permission::Administrative, Capability::Yes);
        assert_eq!(
            p.capability_assurance(Permission::Administrative),
            Assurance::Confirmed
        );
        assert_eq!(p.capabilities_assurance(), Assurance::Confirmed);
        // A later inference takes the confirmation away.
        p.infer(Permission::Administrative, Capability::Yes);
        assert!(!p.is_confirmed(Permission::Administrative));
        // Confirming "unknown" establishes nothing.
        p.confirm(Permission::AssumeRole, Capability::Unknown);
        assert!(!p.is_confirmed(Permission::AssumeRole));
        // Nothing determined: never confirmed.
        let q = EffectivePermissions {
            assurance: Assurance::Confirmed,
            ..Default::default()
        };
        assert_eq!(q.capabilities_assurance(), Assurance::Inferred);
    }

    #[test]
    fn persistence_survival() {
        assert!(!Persistence::RequiresEndpoint.survives_cleanup());
        assert!(Persistence::IndependentCredential.survives_cleanup());
        assert!(Persistence::Blockchain.survives_cleanup());
    }
}
