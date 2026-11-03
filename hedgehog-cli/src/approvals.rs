// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! One-shot human approvals for blocked tool requests.
//!
//! When the hook blocks a request it records the block in history with a
//! *request id*: the SHA-256 of the tool name and the exact text the hook
//! inspected. The user, in their own terminal, runs `gorse allow` to see
//! the recent blocks and `gorse allow <id>` to approve one. The approval
//! is written to `~/.hedgehog/approvals.json` (mode 0600) and is consumed the
//! first time the hook sees a request with the same id, within ten minutes.
//!
//! The agent never sees a code and has no field to submit: the only way
//! through a block is a human typing a command in a terminal the hook does
//! not watch. `~/.hedgehog/` is covered by the self-protection and
//! secret-read rules, so an agent can neither read nor forge this file.
//! Approvals never apply to the `self_protection` category.

use crate::config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How long an approval stays valid.
pub const APPROVAL_TTL_SECS: i64 = 600;

/// How far back `gorse allow` lists blocks.
pub const RECENT_BLOCK_WINDOW_SECS: i64 = 15 * 60;

/// Length of the id shown to the user (a prefix of the full hash).
pub const SHORT_ID_LEN: usize = 6;

/// Category that can never be approved: a human who wants to change or
/// remove Gorse does it in a terminal, which is not hooked.
pub const UNAPPROVABLE_CATEGORY: &str = "self_protection";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Full SHA-256 hex of the tool name and inspected text.
    pub request_id: String,
    pub tool_name: String,
    pub category: String,
    pub rule: String,
    /// Display form of the request, already truncated for the terminal.
    pub command: String,
    /// RFC 3339 creation time.
    pub created: String,
    /// Unix seconds after which the approval is ignored.
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn approvals_path() -> PathBuf {
    config::config_dir().join("approvals.json")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The exact text the hook inspects for a request, with the canonical tool
/// name, so that two requests hash alike only when the hook would judge them
/// alike. Every field a rule can look at is included: approving a write to a
/// path does not approve different content at that path.
pub fn inspected_text(tool_name: &str, tool_input: &serde_json::Value) -> String {
    let field = |name: &str| tool_input[name].as_str().unwrap_or("");
    let fields: Vec<(&str, &str)> = match tool_name {
        "Bash" => vec![("command", field("command")), ("cwd", field("cwd"))],
        "Write" => vec![
            ("file_path", field("file_path")),
            ("content", field("content")),
        ],
        "Edit" => vec![
            ("file_path", field("file_path")),
            ("old_string", field("old_string")),
            ("new_string", field("new_string")),
        ],
        "Read" => vec![("path", read_tool_path(tool_input))],
        "Grep" => vec![
            ("path", grep_tool_path(tool_input)),
            ("pattern", field("pattern")),
            ("glob", field("glob")),
            ("include", field("include")),
            ("type", field("type")),
        ],
        "WebFetch" => vec![("url", field("url"))],
        _ => Vec::new(),
    };
    let mut text = String::from(tool_name);
    for (name, value) in fields {
        text.push('\0');
        text.push_str(name);
        text.push('=');
        text.push_str(value);
    }
    text
}

/// The path a Read tool call is about to read. Claude Code's Read sends
/// `file_path`; Gemini CLI's `read_file` sends `absolute_path` (older
/// releases `path`).
pub fn read_tool_path(tool_input: &serde_json::Value) -> &str {
    tool_input["file_path"]
        .as_str()
        .or_else(|| tool_input["absolute_path"].as_str())
        .or_else(|| tool_input["path"].as_str())
        .unwrap_or("")
}

/// The file or directory a Grep tool call searches. Claude Code's Grep sends
/// `path` (absent means the working directory); Gemini CLI's
/// `search_file_content` sends `path` (older releases `dir_path`).
pub fn grep_tool_path(tool_input: &serde_json::Value) -> &str {
    tool_input["path"]
        .as_str()
        .or_else(|| tool_input["dir_path"].as_str())
        .unwrap_or("")
}

/// SHA-256 hex of [`inspected_text`].
pub fn request_id(tool_name: &str, tool_input: &serde_json::Value) -> String {
    request_id_with_context(tool_name, tool_input, "")
}

/// [`request_id`] for a block whose identity goes beyond the request text.
/// The execution-time script scan passes the scanned file's name and content
/// hash, so approving `bash x.sh` approves running the `x.sh` that was
/// scanned: once the file changes, the same command is a different request.
/// An empty `context` gives the plain [`request_id`].
pub fn request_id_with_context(
    tool_name: &str,
    tool_input: &serde_json::Value,
    context: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut text = inspected_text(tool_name, tool_input);
    if !context.is_empty() {
        text.push('\0');
        text.push_str(context);
    }
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The prefix of a request id that `gorse allow` prints.
pub fn short_id(request_id: &str) -> &str {
    let end = request_id
        .char_indices()
        .nth(SHORT_ID_LEN)
        .map_or(request_id.len(), |(i, _)| i);
    &request_id[..end]
}

fn load() -> Vec<Approval> {
    let path = approvals_path();
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Write the approvals file readable by the owner only.
fn save(approvals: &[Approval]) -> Result<(), String> {
    let path = approvals_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let json = serde_json::to_string_pretty(approvals).map_err(|e| e.to_string())?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    use std::io::Write;
    file.write_all(json.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Record a one-shot approval. Replaces any earlier approval for the same
/// request and drops expired ones. Refuses the unapprovable category.
pub fn record(approval: Approval) -> Result<(), String> {
    if approval.category == UNAPPROVABLE_CATEGORY {
        return Err(format!(
            "blocks in the '{UNAPPROVABLE_CATEGORY}' category cannot be approved"
        ));
    }
    let now = now_secs();
    let mut approvals: Vec<Approval> = load()
        .into_iter()
        .filter(|a| a.expires_at > now && a.request_id != approval.request_id)
        .collect();
    approvals.push(approval);
    save(&approvals)
}

/// Take the approval for this request id, if one exists and has not expired.
/// Consuming removes it, so it is valid exactly once. An approval for the
/// unapprovable category is discarded without being honoured.
pub fn consume(request_id: &str) -> Option<Approval> {
    let approvals = load();
    if approvals.is_empty() {
        return None;
    }
    let now = now_secs();
    let mut matched = None;
    let mut remaining = Vec::with_capacity(approvals.len());
    for approval in approvals {
        if approval.expires_at <= now {
            continue;
        }
        if matched.is_none() && approval.request_id == request_id {
            matched = Some(approval);
            continue;
        }
        remaining.push(approval);
    }
    // Save even when nothing matched so expired entries are pruned.
    let _ = save(&remaining);
    matched.filter(|a| a.category != UNAPPROVABLE_CATEGORY)
}

/// Build an approval that expires [`APPROVAL_TTL_SECS`] from now.
pub fn new_approval(
    request_id: &str,
    tool_name: &str,
    category: &str,
    rule: &str,
    command: &str,
    reason: Option<&str>,
) -> Approval {
    Approval {
        request_id: request_id.to_string(),
        tool_name: tool_name.to_string(),
        category: category.to_string(),
        rule: rule.to_string(),
        command: command.to_string(),
        created: chrono::Utc::now().to_rfc3339(),
        expires_at: now_secs() + APPROVAL_TTL_SECS,
        reason: reason
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_sha256_of_tool_and_inspected_fields() {
        let a = request_id(
            "Bash",
            &serde_json::json!({"command": "cat ~/.aws/credentials"}),
        );
        let b = request_id(
            "Bash",
            &serde_json::json!({"command": "cat ~/.aws/credentials"}),
        );
        let c = request_id("Bash", &serde_json::json!({"command": "cat ~/.aws/config"}));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(short_id(&a).len(), SHORT_ID_LEN);
    }

    #[test]
    fn same_text_under_a_different_tool_is_a_different_request() {
        let read = request_id("Read", &serde_json::json!({"file_path": "~/.aws"}));
        let grep = request_id("Grep", &serde_json::json!({"path": "~/.aws"}));
        assert_ne!(read, grep);
    }

    #[test]
    fn write_content_is_part_of_the_request() {
        let a = request_id(
            "Write",
            &serde_json::json!({"file_path": "x.tf", "content": "a"}),
        );
        let b = request_id(
            "Write",
            &serde_json::json!({"file_path": "x.tf", "content": "b"}),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn grep_pattern_is_part_of_the_request() {
        let a = request_id(
            "Grep",
            &serde_json::json!({"path": "~/.aws", "pattern": "x"}),
        );
        let b = request_id(
            "Grep",
            &serde_json::json!({"path": "~/.aws", "pattern": "."}),
        );
        assert_ne!(a, b);
        // Gemini's older field name maps to the same request.
        let c = request_id(
            "Grep",
            &serde_json::json!({"dir_path": "~/.aws", "pattern": "x"}),
        );
        assert_eq!(a, c);
    }

    #[test]
    fn unapprovable_category_is_refused() {
        let approval = new_approval("abc", "Bash", UNAPPROVABLE_CATEGORY, "r", "cmd", None);
        assert!(record(approval).is_err());
    }

    #[test]
    fn reason_is_trimmed_and_empty_becomes_none() {
        assert_eq!(
            new_approval("a", "Bash", "secrets", "r", "c", Some("  ok  ")).reason,
            Some("ok".to_string())
        );
        assert_eq!(
            new_approval("a", "Bash", "secrets", "r", "c", Some("   ")).reason,
            None
        );
    }
}
