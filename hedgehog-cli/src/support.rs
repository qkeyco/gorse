// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Support bundle generation for `gorse support`.
//!
//! Collects system info, redacted logs, and redacted config into a JSON bundle.
//! Two modes:
//!   - `gorse support`          → saves bundle locally (no network)
//!   - `gorse support --upload` → POSTs to /api/support/upload

use crate::config;
use crate::credential_store;
use crate::reporting;
use serde::Serialize;
use std::io::Read;

/// The support bundle payload.
#[derive(Debug, Serialize)]
pub struct SupportBundle {
    pub system_info: SystemInfo,
    pub config: RedactedConfig,
    pub recent_logs: Vec<serde_json::Value>,
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub hedgehog_version: String,
    pub tier: String,
    pub machine_id: String,
    pub ai_tools: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RedactedConfig {
    pub license_key: String,
    pub log_level: String,
    pub daemon_enabled: bool,
    pub disabled_categories: Vec<String>,
}

/// Build the support bundle.
fn build_bundle() -> SupportBundle {
    let cfg = config::load_config().unwrap_or_default();

    let license = credential_store::status();

    let ai_tools: Vec<String> = reporting::detect_ai_tools()
        .into_iter()
        .map(|t| t.name)
        .collect();

    let recent_logs = collect_recent_logs(3);

    SupportBundle {
        system_info: SystemInfo {
            os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            arch: std::env::consts::ARCH.to_string(),
            hedgehog_version: env!("CARGO_PKG_VERSION").to_string(),
            tier: license.tier,
            machine_id: license
                .machine_id
                .unwrap_or_else(|| "unavailable".to_string()),
            ai_tools,
        },
        config: RedactedConfig {
            license_key: "(not included)".to_string(),
            log_level: cfg.general.log_level,
            daemon_enabled: cfg.general.daemon_enabled,
            disabled_categories: cfg.packs.disabled_categories,
        },
        recent_logs,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Commands, messages, patterns and unknown fields may contain secrets. Keep
/// only bounded diagnostic metadata; do not upload a prefix of sensitive text.
fn redacted_log(value: &serde_json::Value) -> serde_json::Value {
    let mut result = serde_json::Map::new();
    for field in ["timestamp", "event", "tool_name", "category"] {
        if let Some(text) = value[field].as_str() {
            if text.len() <= 128 && !text.chars().any(char::is_control) {
                result.insert(field.into(), serde_json::Value::String(text.into()));
            }
        }
    }
    serde_json::Value::Object(result)
}

/// Collect last N days of JSONL logs, redacting sensitive fields.
fn collect_recent_logs(days: i64) -> Vec<serde_json::Value> {
    let logs_dir = config::config_dir().join("logs");
    if !logs_dir.exists() {
        return Vec::new();
    }

    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);
    let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&logs_dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return Vec::new(),
    };

    let mut logs = Vec::new();

    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.ends_with(".jsonl") {
            continue;
        }

        let file_date = name_str.trim_end_matches(".jsonl");
        if file_date < cutoff_str.as_str() {
            continue;
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = match options.open(entry.path()) {
            Ok(file) => file,
            Err(_) => continue,
        };
        if !file
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 1024 * 1024)
        {
            continue;
        }
        let mut contents = String::new();
        if file
            .take(1024 * 1024 + 1)
            .read_to_string(&mut contents)
            .is_err()
            || contents.len() > 1024 * 1024
        {
            continue;
        }

        for line in contents.lines() {
            let parsed: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            logs.push(redacted_log(&parsed));
            if logs.len() >= 1000 {
                return logs;
            }
        }
    }

    logs
}

/// Save bundle to ~/.hedgehog/support-bundle-{timestamp}.json
pub fn cmd_support_local() {
    let bundle = build_bundle();
    let json = serde_json::to_string_pretty(&bundle).unwrap_or_default();

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("support-bundle-{timestamp}.json");
    let dir = config::config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(&filename);

    match std::fs::write(&path, &json) {
        Ok(_) => {
            println!("Support bundle saved to: {}", path.display());
            println!();
            println!("To upload this bundle, run:");
            println!("  gorse support --upload --subject \"Your issue\" --description \"Details\"");
            println!();
            println!("Or email the file to support@gorse.is");
        }
        Err(e) => {
            eprintln!("Failed to save support bundle: {e}");
            std::process::exit(1);
        }
    }
}

/// Upload bundle to /api/support/upload
pub fn cmd_support_upload(subject: &str, description: &str) {
    println!("Building support bundle...");
    let bundle = build_bundle();
    let json = serde_json::to_string(&bundle).unwrap_or_default();

    // Read and verify the private lease immediately before constructing the
    // authenticated request. Legacy config text never grants upload access.
    let auth = credential_store::load_license_key().and_then(|key| {
        let machine = credential_store::machine_id().ok()?;
        credential_store::validate_lease(&key, &machine, credential_store::now(), true).ok()?;
        Some((key, machine))
    });
    let Some((key, machine)) = auth else {
        eprintln!("A current machine-bound device key is required. Sign in on the dashboard to recover your license, or save a local support bundle.");
        std::process::exit(1);
    };
    if json.len() > 1024 * 1024 {
        eprintln!("Support bundle exceeds the 1 MiB upload limit. Save and review it locally.");
        std::process::exit(1);
    }

    let payload = serde_json::json!({
        "subject": subject,
        "description": description,
        "bundle": bundle,
        "machine_id": machine,
    });

    println!("Uploading to Gorse support...");
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let resp = agent
        .post(&crate::api_origin::api_url("/api/support/upload"))
        .set("Authorization", &format!("Bearer {key}"))
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string());

    match resp {
        Ok(r) => {
            let status = r.status();
            let mut body = Vec::new();
            let bounded = r
                .into_reader()
                .take(64 * 1024 + 1)
                .read_to_end(&mut body)
                .is_ok()
                && body.len() <= 64 * 1024;
            if status == 200 && bounded {
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                let ticket_id = parsed["ticket_id"].as_str().unwrap_or("");
                if ticket_id.is_empty()
                    || ticket_id.len() > 64
                    || !ticket_id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    eprintln!(
                        "Support returned an invalid ticket reference. Check your dashboard."
                    );
                    std::process::exit(1);
                }
                println!("Support ticket created: {ticket_id}");
                println!("We'll get back to you via email.");
            } else {
                eprintln!("Upload failed or returned an oversized response ({status}).");
                // Save locally as fallback
                let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                let path = config::config_dir().join(format!("support-bundle-{timestamp}.json"));
                let _ = std::fs::write(&path, &json);
                eprintln!("Bundle saved locally: {}", path.display());
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("Support upload did not complete. Review the saved bundle before retrying.");
            // Save locally as fallback
            let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
            let path = config::config_dir().join(format!("support-bundle-{timestamp}.json"));
            let _ = std::fs::write(&path, &json);
            eprintln!("Bundle saved locally: {}", path.display());
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_logs_omit_secret_bearing_and_unknown_fields() {
        let input = serde_json::json!({"timestamp":"2026-09-05T12:00:00Z","event":"block","tool_name":"shell","category":"credentials",
            "command":"secret command","message":"secret message","pattern":"secret pattern","request_id":"secret code","future_field":{"token":"secret token"}});
        let output = redacted_log(&input);
        assert_eq!(output.as_object().unwrap().len(), 4);
        assert!(!output.to_string().contains("secret"));
    }

    #[test]
    fn support_logs_bound_unicode_metadata_without_slicing_panics() {
        let output = redacted_log(
            &serde_json::json!({"event":"€".repeat(200),"category":"line\nbreak","command":"€".repeat(201),"tool_name":"shell"}),
        );
        assert_eq!(output, serde_json::json!({"tool_name":"shell"}));
    }
}
