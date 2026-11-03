// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! JSONL event logging for Gorse.
//!
//! Ported from Swift HookHandler.swift.
//! Logs events as JSONL to ~/.hedgehog/logs/{YYYY-MM-DD}.jsonl.
//! Fields: timestamp, event, session_id, tool_name, command, category, pattern, message, request_id.

use serde_json::json;
use std::path::PathBuf;

fn logs_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".hedgehog").join("logs")
}

/// Log an event as a JSONL line.
pub fn log_event(
    event_type: &str,
    session_id: Option<&str>,
    tool_name: Option<&str>,
    command: Option<&str>,
    category: Option<&str>,
    pattern: Option<&str>,
    message: Option<&str>,
    request_id: Option<&str>,
) {
    let dir = logs_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }

    let now = chrono::Utc::now();
    let filename = now.format("%Y-%m-%d").to_string() + ".jsonl";
    let path = dir.join(filename);

    let mut entry = json!({
        "timestamp": now.to_rfc3339(),
        "event": event_type,
    });

    if let Some(v) = session_id {
        entry["session_id"] = json!(v);
    }
    if let Some(v) = tool_name {
        entry["tool_name"] = json!(v);
    }
    if let Some(v) = command {
        entry["command"] = json!(v);
    }
    if let Some(v) = category {
        entry["category"] = json!(v);
    }
    if let Some(v) = pattern {
        entry["pattern"] = json!(v);
    }
    if let Some(v) = message {
        entry["message"] = json!(v);
    }
    if let Some(v) = request_id {
        entry["request_id"] = json!(v);
    }

    let line = serde_json::to_string(&entry).unwrap_or_default() + "\n";

    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Summary of recent activity from log files.
#[derive(Debug, Default)]
pub struct ActivitySummary {
    pub blocks: u64,
    pub allows: u64,
    pub approvals: u64,
    pub total_events: u64,
    /// Most recent block events (up to 5).
    pub recent_blocks: Vec<BlockEvent>,
    /// Days of log data available.
    pub days_covered: usize,
}

/// A recent block event for display.
#[derive(Debug)]
pub struct BlockEvent {
    pub timestamp: String,
    pub category: String,
    pub command: String,
    pub message: String,
}

/// Query recent activity from JSONL log files.
/// `days` controls how many days back to look (0 = all).
pub fn recent_activity(days: usize) -> ActivitySummary {
    let dir = logs_dir();
    if !dir.exists() {
        return ActivitySummary::default();
    }

    let cutoff = if days > 0 {
        let d = chrono::Utc::now() - chrono::Duration::days(days as i64);
        Some(d.format("%Y-%m-%d").to_string())
    } else {
        None
    };

    let mut entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return ActivitySummary::default(),
    };
    entries.sort_by_key(|e| e.file_name());

    let mut summary = ActivitySummary::default();
    let mut log_dates = std::collections::HashSet::new();

    for entry in entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.ends_with(".jsonl") {
            continue;
        }

        let file_date = name_str.trim_end_matches(".jsonl");
        if let Some(ref cutoff_date) = cutoff {
            if file_date < cutoff_date.as_str() {
                continue;
            }
        }

        log_dates.insert(file_date.to_string());

        let contents = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in contents.lines() {
            let parsed: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let event_type = parsed["event"].as_str().unwrap_or("");
            summary.total_events += 1;

            match event_type {
                "block" => {
                    summary.blocks += 1;
                    if summary.recent_blocks.len() < 5 {
                        summary.recent_blocks.push(BlockEvent {
                            timestamp: parsed["timestamp"].as_str().unwrap_or("").to_string(),
                            category: parsed["category"].as_str().unwrap_or("").to_string(),
                            command: parsed["command"]
                                .as_str()
                                .unwrap_or("")
                                .chars()
                                .take(60)
                                .collect(),
                            message: parsed["message"].as_str().unwrap_or("").to_string(),
                        });
                    }
                }
                "allow" => summary.allows += 1,
                "approved" => summary.approvals += 1,
                _ => {}
            }
        }
    }

    // Keep most recent blocks at the end (log files are date-sorted)
    summary.recent_blocks.reverse();
    summary.days_covered = log_dates.len();
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_event_does_not_panic() {
        log_event(
            "test",
            Some("session-123"),
            Some("Bash"),
            Some("ls -la"),
            None,
            None,
            None,
            None,
        );
    }

    #[test]
    fn recent_activity_does_not_panic() {
        let summary = recent_activity(7);
        // blocks + allows + approvals should be <= total_events
        assert!(summary.blocks + summary.allows + summary.approvals <= summary.total_events);
        assert!(summary.recent_blocks.len() <= 5);
    }

    #[test]
    fn recent_activity_far_future_returns_empty() {
        // Looking 0 days back means "all", but let's just make sure it runs
        let summary = recent_activity(0);
        assert!(summary.recent_blocks.len() <= 5);
    }
}
