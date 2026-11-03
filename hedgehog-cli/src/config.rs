// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Unified configuration for Gorse.
//!
//! ~/.hedgehog/config.toml — single config file for all platforms.
//!
//! Compatible with DCG TOML pack format: custom packs can be placed
//! in ~/.hedgehog/packs/ and they'll be loaded alongside built-in packs.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::PathBuf;

/// Prefixes for the user-facing environment overrides (`NO_UPDATE_CHECK`,
/// `STATE_DIR`, `API_ORIGIN`, `NO_TRUFFLEHOG`, `TRUFFLEHOG*`). `GORSE_<name>`
/// is read first, then the older `HEDGEHOG_<name>`, so setups made before the
/// product was renamed keep working.
pub const ENV_PREFIXES: [&str; 2] = ["GORSE_", "HEDGEHOG_"];

/// `GORSE_<name>`, else `HEDGEHOG_<name>`, with the full variable name that
/// was found (for messages that name the variable).
pub fn env_var_named(name: &str) -> Option<(String, String)> {
    ENV_PREFIXES.iter().find_map(|prefix| {
        let full = format!("{prefix}{name}");
        std::env::var(&full).ok().map(|value| (full, value))
    })
}

/// `GORSE_<name>`, else `HEDGEHOG_<name>`.
pub fn env_var(name: &str) -> Option<String> {
    env_var_named(name).map(|(_, value)| value)
}

/// `GORSE_<name>`, else `HEDGEHOG_<name>`, as an `OsString`.
pub fn env_var_os(name: &str) -> Option<OsString> {
    ENV_PREFIXES
        .iter()
        .find_map(|prefix| std::env::var_os(format!("{prefix}{name}")))
}

/// True when `GORSE_<name>` or `HEDGEHOG_<name>` is set to anything.
pub fn env_flag(name: &str) -> bool {
    env_var_os(name).is_some()
}

/// Top-level Gorse configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HedgehogConfig {
    /// General settings.
    #[serde(default)]
    pub general: GeneralConfig,
    /// Taint engine settings.
    #[serde(default)]
    pub taint: TaintConfig,
    /// Pack/guardrail settings.
    #[serde(default)]
    pub packs: PackConfig,
    /// Allowlist overrides.
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    /// Security defense layers (heuristics, LLM classification, canaries).
    #[serde(default)]
    pub security: SecurityConfig,
    /// Remote alerting channels (Telegram, WhatsApp, SMS, webhook).
    #[serde(default)]
    pub alerts: AlertConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Obsolete plaintext key field. Ignored for entitlement; removed on activation/deactivation.
    #[serde(default)]
    pub license_key: String,
    /// Log level: error, warn, info, debug, trace.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Enable/disable the daemon auto-start.
    #[serde(default = "default_true")]
    pub daemon_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintConfig {
    /// How long derived secrets persist (seconds). 0 = forever.
    #[serde(default = "default_derived_ttl")]
    pub derived_secret_ttl_secs: u64,
    /// Maximum derived secrets to track.
    #[serde(default = "default_max_derived")]
    pub max_derived_secrets: usize,
    /// Additional secret file paths to monitor.
    #[serde(default)]
    pub extra_secret_paths: Vec<String>,
    /// Additional secret directories to monitor.
    #[serde(default)]
    pub extra_secret_dirs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackConfig {
    /// Disabled pack categories (e.g., ["disclosure"] to disable disclosure checks).
    #[serde(default)]
    pub disabled_categories: Vec<String>,
    /// Directory for custom TOML packs (default: ~/.hedgehog/packs/).
    #[serde(default)]
    pub custom_pack_dir: Option<String>,
}

/// Security defense layer settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable LLM intent classification for suspicious commands (paranoid mode).
    #[serde(default)]
    pub paranoid_mode: bool,
    /// LLM provider: "anthropic", "openai", or "ollama".
    #[serde(default = "default_llm_provider")]
    pub llm_provider: String,
    /// LLM model to use for classification.
    #[serde(default = "default_llm_model")]
    pub llm_model: String,
    /// Enable canary token detection in hook checks.
    #[serde(default = "default_true")]
    pub canary_enabled: bool,
    /// Enable obfuscation heuristic scoring.
    #[serde(default = "default_true")]
    pub heuristics_enabled: bool,
    /// Enable script content scanning before execution.
    #[serde(default = "default_true")]
    pub script_scanning_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    /// Additional allowed domains.
    #[serde(default)]
    pub extra_domains: Vec<String>,
    /// Additional allowed domain suffixes.
    #[serde(default)]
    pub extra_suffixes: Vec<String>,
    /// Additional allowed IPs.
    #[serde(default)]
    pub extra_ips: Vec<String>,
    /// Additional trusted DNS resolver IPs (port 53 restriction).
    #[serde(default)]
    pub extra_dns_resolvers: Vec<String>,
}

/// Remote alerting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable remote alerting.
    #[serde(default)]
    pub enabled: bool,
    /// Legacy setting retained for configuration compatibility. Delivery now
    /// deduplicates stable event IDs instead of suppressing events by time.
    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: u64,
    /// Minimum severity to send: info, medium, high, critical.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    /// Telegram Bot API channel.
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,
    /// WhatsApp Business Cloud API channel.
    #[serde(default)]
    pub whatsapp: Option<WhatsAppConfig>,
    /// Twilio SMS channel.
    #[serde(default)]
    pub twilio: Option<TwilioConfig>,
    /// Generic webhook channel (Slack, Discord, PagerDuty, etc.).
    #[serde(default)]
    pub webhook: Option<AlertWebhookConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppConfig {
    pub phone_number_id: String,
    pub access_token: String,
    pub to_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwilioConfig {
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
    pub to_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertWebhookConfig {
    pub url: String,
    #[serde(default)]
    pub auth_header: Option<String>,
}

fn default_dedup_window() -> u64 {
    300
}
fn default_min_severity() -> String {
    "medium".to_string()
}

fn default_log_level() -> String {
    "warn".to_string()
}
fn default_true() -> bool {
    true
}
fn default_llm_provider() -> String {
    "anthropic".to_string()
}
fn default_llm_model() -> String {
    "claude-haiku-4-5-20251001".to_string()
}
fn default_derived_ttl() -> u64 {
    3600
}
fn default_max_derived() -> usize {
    10_000
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            license_key: String::new(),
            log_level: default_log_level(),
            daemon_enabled: true,
        }
    }
}

impl Default for TaintConfig {
    fn default() -> Self {
        Self {
            derived_secret_ttl_secs: default_derived_ttl(),
            max_derived_secrets: default_max_derived(),
            extra_secret_paths: Vec::new(),
            extra_secret_dirs: Vec::new(),
        }
    }
}

impl Default for PackConfig {
    fn default() -> Self {
        Self {
            disabled_categories: Vec::new(),
            custom_pack_dir: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            paranoid_mode: false,
            llm_provider: default_llm_provider(),
            llm_model: default_llm_model(),
            canary_enabled: true,
            heuristics_enabled: true,
            script_scanning_enabled: true,
        }
    }
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            extra_domains: Vec::new(),
            extra_suffixes: Vec::new(),
            extra_ips: Vec::new(),
            extra_dns_resolvers: Vec::new(),
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dedup_window_secs: default_dedup_window(),
            min_severity: default_min_severity(),
            telegram: None,
            whatsapp: None,
            twilio: None,
            webhook: None,
        }
    }
}

impl Default for HedgehogConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            taint: TaintConfig::default(),
            packs: PackConfig::default(),
            allowlist: AllowlistConfig::default(),
            security: SecurityConfig::default(),
            alerts: AlertConfig::default(),
        }
    }
}

/// Get the config directory path.
pub fn config_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let appdata = std::env::var("APPDATA")
            .unwrap_or_else(|_| r"C:\Users\default\AppData\Roaming".to_string());
        PathBuf::from(appdata).join("hedgehog")
    }
    #[cfg(not(windows))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".hedgehog")
    }
}

/// Get the config file path.
pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Get the custom packs directory.
pub fn packs_dir() -> PathBuf {
    config_dir().join("packs")
}

/// Load config from the default path.
pub fn load_config() -> Result<HedgehogConfig, String> {
    let path = config_path();
    if !path.exists() {
        return Err(format!("Config file not found: {}", path.display()));
    }
    let contents =
        std::fs::read_to_string(&path).map_err(|e| format!("Failed to read config: {e}"))?;
    toml::from_str(&contents).map_err(|e| format!("Failed to parse config: {e}"))
}

/// Save config to the default path.
pub fn save_config(cfg: &HedgehogConfig) -> Result<(), String> {
    let path = config_path();
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create config dir: {e}"))?;

    let toml_str =
        toml::to_string_pretty(cfg).map_err(|e| format!("Failed to serialize config: {e}"))?;

    let header = "# Gorse Configuration\n\
                  # https://gorse.is/docs/config\n\
                  #\n\
                  # Place custom TOML security packs in ~/.hedgehog/packs/\n\
                  # They'll be loaded alongside built-in packs.\n\n";

    crate::encrypted_store::write_private_atomic(&path, format!("{header}{toml_str}").as_bytes())
        .map_err(|e| format!("Failed to write config: {e}"))?;

    Ok(())
}

/// Create a default config file.
pub fn init_config() -> Result<(), String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create config dir: {e}"))?;
    std::fs::create_dir_all(packs_dir()).map_err(|e| format!("Failed to create packs dir: {e}"))?;

    let config = HedgehogConfig::default();
    let toml_str =
        toml::to_string_pretty(&config).map_err(|e| format!("Failed to serialize config: {e}"))?;

    let header = "# Gorse Configuration\n\
                  # https://gorse.is/docs/config\n\
                  #\n\
                  # Place custom TOML security packs in ~/.hedgehog/packs/\n\
                  # They'll be loaded alongside built-in packs.\n\n";

    std::fs::write(config_path(), format!("{header}{toml_str}"))
        .map_err(|e| format!("Failed to write config: {e}"))?;

    Ok(())
}
