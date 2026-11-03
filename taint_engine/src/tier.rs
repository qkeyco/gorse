// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! License tiers and feature gating.
//!
//! The free tier shows ALL secrets the scanner finds but only PROTECTS 15.
//! That gap — "you have 27 unprotected secrets" — is the conversion moment.
//!
//! Pricing:
//!   Free — $0                  — everything that runs locally: the full
//!                                exposure report (text, JSON, HTML), the MCP
//!                                tool, hooks, canaries and the secret scan;
//!                                15 protected secrets, 1 agent
//!   Pro  — per computer per year (see gorse.is/pricing) — `gorse exposure --verify` and the
//!                                verified report stamp; unlimited protected
//!                                secrets, project scoping, custom patterns,
//!                                audit export, dashboard, derived tracking,
//!                                localhost detection, ESF daemon
//!   Team — per laptop per year — everything in Pro plus centralized policy,
//!                                MDM, report upload, SSO
//!
//! The numeric values are part of the C ABI (`hedgehog_get_tier`,
//! `hedgehog_activate_license`). Pro keeps the value 2 that the old
//! Developer tier had so existing FFI callers passing 2 still work; the
//! retired value 1 (old Personal) maps to Pro.

use std::time::{Duration, SystemTime};

/// License tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub enum Tier {
    Free = 0,
    Pro = 2,
    Team = 3,
}

/// Extra protection slots reserved for internal monitoring tokens.
/// These don't count against the user's paid quota.
const MONITOR_RESERVE: usize = 10;

/// Feature limits per tier.
#[derive(Debug, Clone)]
pub struct TierLimits {
    /// Maximum number of secrets that are actively protected (user-facing).
    pub max_protected_secrets: usize,
    /// Extra slots reserved for internal monitoring (invisible to user).
    pub monitor_reserve: usize,
    /// Maximum number of agent integrations (hook configs).
    pub max_agents: usize,
    /// Whether the ESF daemon (kernel-level taint tracking) is enabled.
    pub esf_enabled: bool,
    /// Whether per-project allowlist scoping is enabled.
    pub project_scoping: bool,
    /// Whether multi-machine sync is available.
    pub multi_machine: bool,
    /// Whether custom patterns can be added.
    pub custom_patterns: bool,
    /// Whether audit log export is available.
    pub audit_export: bool,
    /// Whether the visual dashboard is available.
    pub dashboard: bool,
    /// Whether derived secret tracking (v0.5) is enabled.
    pub derived_tracking: bool,
    /// Whether localhost relay detection (v0.3) is enabled.
    pub localhost_detection: bool,
}

impl TierLimits {
    /// The actual enforcement limit: user-visible quota + internal monitoring reserve.
    /// This is the number passed to SecretDetector for enforcement.
    pub fn effective_secret_limit(&self) -> usize {
        self.max_protected_secrets
            .saturating_add(self.monitor_reserve)
    }
}

impl Tier {
    pub fn limits(&self) -> TierLimits {
        match self {
            Tier::Free => TierLimits {
                max_protected_secrets: 15,
                monitor_reserve: MONITOR_RESERVE,
                max_agents: 1,
                esf_enabled: false,
                project_scoping: false,
                multi_machine: false,
                custom_patterns: false,
                audit_export: false,
                dashboard: false,
                derived_tracking: false,
                localhost_detection: false,
            },
            Tier::Pro => TierLimits {
                max_protected_secrets: usize::MAX,
                monitor_reserve: 0, // unlimited tier, no reserve needed
                max_agents: usize::MAX,
                esf_enabled: true,
                project_scoping: true,
                multi_machine: true,
                custom_patterns: true,
                audit_export: true,
                dashboard: true,
                derived_tracking: true,
                localhost_detection: true,
            },
            Tier::Team => TierLimits {
                max_protected_secrets: usize::MAX,
                monitor_reserve: 0, // unlimited tier, no reserve needed
                max_agents: usize::MAX,
                esf_enabled: true,
                project_scoping: true,
                multi_machine: true,
                custom_patterns: true,
                audit_export: true,
                dashboard: true,
                derived_tracking: true,
                localhost_detection: true,
            },
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Tier::Free => "Free",
            Tier::Pro => "Pro",
            Tier::Team => "Team",
        }
    }

    pub fn price_display(&self) -> &'static str {
        match self {
            Tier::Free => "$0",
            Tier::Pro => "per computer per year",
            Tier::Team => "per laptop per year",
        }
    }

    /// C-compatible integer conversion. `1` was the retired Personal tier and
    /// `2` the retired Developer tier; both now mean Pro so nobody is
    /// downgraded by the rename.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Tier::Free),
            1 | 2 => Some(Tier::Pro),
            3 => Some(Tier::Team),
            _ => None,
        }
    }
}

/// License state.
#[derive(Debug, Clone)]
pub struct License {
    pub tier: Tier,
    /// When the license expires (None = free tier, never expires).
    pub expires_at: Option<SystemTime>,
    /// License key (for validation).
    pub key: Option<String>,
}

impl License {
    /// Create a free tier license.
    pub fn free() -> Self {
        Self {
            tier: Tier::Free,
            expires_at: None,
            key: None,
        }
    }

    /// Create a licensed tier.
    pub fn licensed(tier: Tier, key: String, valid_days: u64) -> Self {
        Self {
            tier,
            expires_at: Some(SystemTime::now() + Duration::from_secs(valid_days * 86400)),
            key: Some(key),
        }
    }

    /// Check if the license is currently valid.
    pub fn is_valid(&self) -> bool {
        match self.tier {
            Tier::Free => true, // Free never expires
            _ => {
                if let Some(expires) = self.expires_at {
                    SystemTime::now() < expires
                } else {
                    false
                }
            }
        }
    }

    /// Get the effective tier (drops to Free if expired).
    pub fn effective_tier(&self) -> Tier {
        if self.is_valid() {
            self.tier
        } else {
            Tier::Free
        }
    }

    /// Get feature limits for the effective tier.
    pub fn limits(&self) -> TierLimits {
        self.effective_tier().limits()
    }

    /// Days remaining on license, or None if free/expired.
    pub fn days_remaining(&self) -> Option<u64> {
        self.expires_at.and_then(|exp| {
            exp.duration_since(SystemTime::now())
                .ok()
                .map(|d| d.as_secs() / 86400)
        })
    }
}

/// Upgrade prompt shown to free tier users.
pub struct UpgradePrompt {
    pub total_secrets_found: usize,
    pub protected_count: usize,
    pub unprotected_count: usize,
    pub unprotected_paths: Vec<String>,
}

impl UpgradePrompt {
    pub fn message(&self) -> String {
        format!(
            "Gorse found {} secrets on your machine.\n\
             Protected: {} | Unprotected: {}\n\n\
             Upgrade to Gorse Pro to protect all of them.\n\
             → gorse.is/pricing",
            self.total_secrets_found, self.protected_count, self.unprotected_count,
        )
    }

    pub fn short_message(&self) -> String {
        format!(
            "{} secrets unprotected. Upgrade: gorse.is/pricing",
            self.unprotected_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_tier_limits() {
        let limits = Tier::Free.limits();
        assert_eq!(limits.max_protected_secrets, 15);
        assert_eq!(limits.monitor_reserve, 10);
        assert_eq!(limits.effective_secret_limit(), 25);
        assert_eq!(limits.max_agents, 1);
        assert!(!limits.esf_enabled);
        assert!(!limits.project_scoping);
        assert!(!limits.dashboard);
        assert!(!limits.derived_tracking);
    }

    #[test]
    fn pro_tier_limits() {
        let limits = Tier::Pro.limits();
        assert_eq!(limits.max_protected_secrets, usize::MAX);
        assert_eq!(limits.monitor_reserve, 0);
        assert_eq!(limits.max_agents, usize::MAX);
        assert!(limits.esf_enabled);
        assert!(limits.dashboard);
        assert!(limits.derived_tracking);
        assert!(limits.localhost_detection);
        assert!(limits.project_scoping);
        assert!(limits.multi_machine);
        assert!(limits.custom_patterns);
        assert!(limits.audit_export);
    }

    #[test]
    fn team_tier_has_everything() {
        let limits = Tier::Team.limits();
        assert!(limits.project_scoping);
        assert!(limits.multi_machine);
        assert!(limits.custom_patterns);
        assert!(limits.audit_export);
        assert!(limits.dashboard);
    }

    #[test]
    fn free_license_always_valid() {
        let lic = License::free();
        assert!(lic.is_valid());
        assert_eq!(lic.effective_tier(), Tier::Free);
    }

    #[test]
    fn licensed_tier_valid() {
        let lic = License::licensed(Tier::Pro, "TEST-KEY".to_string(), 365);
        assert!(lic.is_valid());
        assert_eq!(lic.effective_tier(), Tier::Pro);
        assert!(lic.days_remaining().unwrap() >= 364);
    }

    #[test]
    fn expired_license_drops_to_free() {
        let lic = License {
            tier: Tier::Pro,
            expires_at: Some(SystemTime::now() - Duration::from_secs(86400)),
            key: Some("EXPIRED".to_string()),
        };
        assert!(!lic.is_valid());
        assert_eq!(lic.effective_tier(), Tier::Free);
    }

    #[test]
    fn tier_from_i32() {
        assert_eq!(Tier::from_i32(0), Some(Tier::Free));
        // Retired Personal (1) and Developer (2) both map to Pro.
        assert_eq!(Tier::from_i32(1), Some(Tier::Pro));
        assert_eq!(Tier::from_i32(2), Some(Tier::Pro));
        assert_eq!(Tier::from_i32(3), Some(Tier::Team));
        assert_eq!(Tier::from_i32(99), None);
    }

    #[test]
    fn tier_numeric_values_are_abi_stable() {
        assert_eq!(Tier::Free as i32, 0);
        assert_eq!(Tier::Pro as i32, 2);
        assert_eq!(Tier::Team as i32, 3);
    }

    #[test]
    fn upgrade_prompt_message() {
        let prompt = UpgradePrompt {
            total_secrets_found: 42,
            protected_count: 15,
            unprotected_count: 27,
            unprotected_paths: vec![],
        };
        let msg = prompt.message();
        assert!(msg.contains("42 secrets"));
        assert!(msg.contains("27"));
        assert!(msg.contains("Pro"));
        assert!(msg.contains("gorse.is/pricing"));
    }

    #[test]
    fn tier_ordering() {
        assert!(Tier::Free < Tier::Pro);
        assert!(Tier::Pro < Tier::Team);
    }

    #[test]
    fn tier_names() {
        assert_eq!(Tier::Free.name(), "Free");
        assert_eq!(Tier::Pro.name(), "Pro");
        assert_eq!(Tier::Team.name(), "Team");
        assert_eq!(Tier::Free.price_display(), "$0");
        assert_eq!(Tier::Pro.price_display(), "per computer per year");
        assert_eq!(Tier::Team.price_display(), "per laptop per year");
    }
}
