// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Team admin dashboard and SIEM webhook integration (L-09).
//!
//! Provides:
//! - OCSF-formatted event reporting to a central webhook
//! - Team-wide status aggregation
//! - Admin dashboard data API
//! - SIEM integration (Splunk, Datadog, Elastic)

use serde::{Deserialize, Serialize};

/// OCSF (Open Cybersecurity Schema Framework) event envelope.
/// https://schema.ocsf.io/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    /// OCSF class ID: 6003 = Security Finding
    pub class_uid: u32,
    /// Activity: 1=Create, 2=Update
    pub activity_id: u32,
    /// Event severity: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
    pub severity_id: u32,
    /// ISO 8601 timestamp
    pub time: String,
    /// Event message
    pub message: String,
    /// Machine identifier
    pub device: DeviceInfo,
    /// Finding details
    pub finding: FindingInfo,
    /// Metadata
    pub metadata: EventMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub hostname: String,
    pub os_name: String,
    pub agent_version: String,
    pub machine_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingInfo {
    pub title: String,
    pub category: String,
    pub tool_name: Option<String>,
    pub command: Option<String>,
    pub action: String, // "block", "allow", "approved"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub product: ProductInfo,
    pub version: String,
    pub logged_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductInfo {
    pub name: String,
    pub vendor_name: String,
}

/// Team dashboard webhook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL (HTTPS)
    pub url: String,
    /// Optional bearer token for authentication
    pub auth_token: Option<String>,
    /// SIEM format: "ocsf" (default), "splunk_hec", "datadog", "elastic"
    pub format: WebhookFormat,
    /// Whether to send events in real-time or batch
    pub batch: bool,
    /// Batch interval in seconds (only if batch=true)
    pub batch_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookFormat {
    #[serde(rename = "ocsf")]
    Ocsf,
    #[serde(rename = "splunk_hec")]
    SplunkHec,
    #[serde(rename = "datadog")]
    Datadog,
    #[serde(rename = "elastic")]
    Elastic,
}

impl Default for WebhookFormat {
    fn default() -> Self {
        WebhookFormat::Ocsf
    }
}

/// Build an OCSF event from a Gorse log entry.
pub fn build_ocsf_event(
    action: &str,
    category: &str,
    tool_name: Option<&str>,
    command: Option<&str>,
    severity: u32,
) -> OcsfEvent {
    let hostname = hostname();
    let now = timestamp_iso8601();

    OcsfEvent {
        class_uid: 6003, // Security Finding
        activity_id: 1,  // Create
        severity_id: severity,
        time: now.clone(),
        message: format!(
            "Gorse {action}: {category}{}",
            command.map(|c| format!(" — {c}")).unwrap_or_default()
        ),
        device: DeviceInfo {
            hostname: hostname.clone(),
            os_name: std::env::consts::OS.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            machine_id: machine_id(),
        },
        finding: FindingInfo {
            title: format!("Command {action}"),
            category: category.to_string(),
            tool_name: tool_name.map(String::from),
            command: command.map(String::from),
            action: action.to_string(),
        },
        metadata: EventMetadata {
            product: ProductInfo {
                name: "Gorse".to_string(),
                vendor_name: "Gorse Security".to_string(),
            },
            version: env!("CARGO_PKG_VERSION").to_string(),
            logged_time: now,
        },
    }
}

/// Format an event for Splunk HEC (HTTP Event Collector).
pub fn format_splunk_hec(event: &OcsfEvent) -> String {
    let payload = serde_json::json!({
        "event": event,
        "source": "gorse",
        "sourcetype": "gorse:security",
        "host": event.device.hostname,
    });
    serde_json::to_string(&payload).unwrap_or_default()
}

/// Format an event for Datadog Log API.
pub fn format_datadog(event: &OcsfEvent) -> String {
    let payload = serde_json::json!({
        "ddsource": "gorse",
        "ddtags": format!("action:{},category:{}", event.finding.action, event.finding.category),
        "hostname": event.device.hostname,
        "message": event.message,
        "service": "gorse",
        "status": match event.severity_id {
            1 => "info",
            2 => "warn",
            3 | 4 => "error",
            5 => "critical",
            _ => "info",
        },
    });
    serde_json::to_string(&payload).unwrap_or_default()
}

/// Send an event to a webhook (blocking HTTP POST via std).
pub fn send_webhook(config: &WebhookConfig, event: &OcsfEvent) -> Result<(), String> {
    let body = match config.format {
        WebhookFormat::Ocsf => serde_json::to_string(event).unwrap_or_default(),
        WebhookFormat::SplunkHec => format_splunk_hec(event),
        WebhookFormat::Datadog => format_datadog(event),
        WebhookFormat::Elastic => serde_json::to_string(event).unwrap_or_default(),
    };

    // Use curl for simplicity (avoids adding HTTP client dependency)
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-s", "-X", "POST"])
        .arg(&config.url)
        .args(["-H", "Content-Type: application/json"]);

    if let Some(ref token) = config.auth_token {
        cmd.args(["-H", &format!("Authorization: Bearer {token}")]);
    }

    // Splunk HEC uses a different auth header
    if matches!(config.format, WebhookFormat::SplunkHec) {
        if let Some(ref token) = config.auth_token {
            cmd.args(["-H", &format!("Authorization: Splunk {token}")]);
        }
    }

    cmd.args(["-d", &body]);

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run curl: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Webhook failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Team dashboard summary data.
#[derive(Debug, Clone, Serialize)]
pub struct TeamDashboard {
    pub machines: Vec<MachineStatus>,
    pub total_blocks: u64,
    pub total_events: u64,
    pub top_categories: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineStatus {
    pub hostname: String,
    pub machine_id: String,
    pub last_seen: String,
    pub version: String,
    pub blocks_24h: u64,
    pub secrets_protected: u32,
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        let output = std::process::Command::new("hostname")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        output
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

fn machine_id() -> String {
    // Use a hash of hostname + OS + arch as a simple machine ID
    let raw = format!(
        "{}-{}-{}",
        hostname(),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    format!("{:x}", simple_hash(raw.as_bytes()))
}

fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn timestamp_iso8601() -> String {
    // Simple ISO 8601 without chrono dependency
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert epoch to ISO 8601 (approximate, good enough for logging)
    let secs_per_day = 86400u64;
    let days = now / secs_per_day;
    let time_of_day = now % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simplified date calculation (doesn't handle leap years perfectly)
    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let month_days: [u64; 12] = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ocsf_event_creates_valid_event() {
        let event = build_ocsf_event("block", "destructive", Some("claude"), Some("rm -rf /"), 4);

        assert_eq!(event.class_uid, 6003);
        assert_eq!(event.severity_id, 4);
        assert!(event.message.contains("block"));
        assert!(event.message.contains("destructive"));
        assert_eq!(event.finding.action, "block");
        assert_eq!(event.finding.category, "destructive");
        assert_eq!(event.finding.tool_name, Some("claude".to_string()));
    }

    #[test]
    fn splunk_hec_format() {
        let event = build_ocsf_event("block", "secrets", None, None, 3);
        let hec = format_splunk_hec(&event);
        assert!(hec.contains("gorse:security"));
        assert!(hec.contains("\"source\":\"gorse\""));
    }

    #[test]
    fn datadog_format() {
        let event = build_ocsf_event("allow", "spending", None, None, 1);
        let dd = format_datadog(&event);
        assert!(dd.contains("\"ddsource\":\"gorse\""));
        assert!(dd.contains("\"status\":\"info\""));
    }

    #[test]
    fn timestamp_looks_reasonable() {
        let ts = timestamp_iso8601();
        assert!(ts.starts_with("20"));
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
    }

    #[test]
    fn machine_id_is_deterministic() {
        let id1 = machine_id();
        let id2 = machine_id();
        assert_eq!(id1, id2);
    }
}
