// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! SQLite-based command history audit trail (D-31/DCG-09).
//!
//! Stores all hook events in ~/.hedgehog/history.db with structured queries.
//! Supplements JSONL logging with fast, queryable storage.

use crate::config;
use rusqlite::{params, Connection};
use std::path::PathBuf;

/// Get the path to the history database.
fn db_path() -> PathBuf {
    config::config_dir().join("history.db")
}

/// Open (or create) the history database and ensure schema exists.
fn open_db() -> Result<Connection, String> {
    let path = db_path();
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create dir: {e}"))?;

    let conn = Connection::open(&path).map_err(|e| format!("Failed to open history.db: {e}"))?;

    // WAL mode for better concurrent read/write
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| format!("Failed to set WAL mode: {e}"))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            session_id TEXT,
            tool_name TEXT,
            command TEXT,
            category TEXT,
            rule_name TEXT,
            message TEXT,
            request_id TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
        ",
    )
    .map_err(|e| format!("Failed to create schema: {e}"))?;

    migrate_request_id_column(&conn)?;

    Ok(conn)
}

/// Databases written before approvals replaced bypass codes have a
/// `bypass_code` column where `request_id` now lives. Rename it in place so
/// old rows keep working and new rows land in the right column.
fn migrate_request_id_column(conn: &Connection) -> Result<(), String> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(events)")
        .map_err(|e| format!("Failed to read schema: {e}"))?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| format!("Failed to read schema: {e}"))?
        .flatten()
        .collect();
    if columns.iter().any(|c| c == "bypass_code") && !columns.iter().any(|c| c == "request_id") {
        conn.execute_batch("ALTER TABLE events RENAME COLUMN bypass_code TO request_id;")
            .map_err(|e| format!("Failed to migrate schema: {e}"))?;
    }
    Ok(())
}

/// Record a hook event in the SQLite database.
/// This is called alongside the JSONL log_event for structured storage.
pub fn record_event(
    event_type: &str,
    session_id: Option<&str>,
    tool_name: Option<&str>,
    command: Option<&str>,
    category: Option<&str>,
    rule_name: Option<&str>,
    message: Option<&str>,
    request_id: Option<&str>,
) {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return, // Silently fail — don't block the hook
    };

    let now = chrono::Utc::now().to_rfc3339();
    let _ = conn.execute(
        "INSERT INTO events (timestamp, event_type, session_id, tool_name, command, category, rule_name, message, request_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            now,
            event_type,
            session_id,
            tool_name,
            command,
            category,
            rule_name,
            message,
            request_id,
        ],
    );
}

/// A block the user may approve with `gorse allow`.
#[derive(Debug, Clone)]
pub struct RecentBlock {
    /// Full request id (SHA-256 hex) recorded with the block.
    pub request_id: String,
    pub timestamp: String,
    pub tool_name: String,
    /// The full inspected text; callers truncate before printing.
    pub command: String,
    pub category: String,
    pub rule_name: String,
}

/// Blocks recorded in the last `window_secs`, newest first, one row per
/// request id (a request blocked several times is listed once).
pub fn recent_blocks(window_secs: i64) -> Vec<RecentBlock> {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(window_secs)).to_rfc3339();
    let mut stmt = match conn.prepare(
        "SELECT request_id, timestamp, COALESCE(tool_name,''), COALESCE(command,''), COALESCE(category,''), COALESCE(rule_name,'')
         FROM events
         WHERE event_type = 'block' AND request_id IS NOT NULL AND timestamp >= ?1
         ORDER BY id DESC",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = match stmt.query_map(params![cutoff], |row| {
        Ok(RecentBlock {
            request_id: row.get(0)?,
            timestamp: row.get(1)?,
            tool_name: row.get(2)?,
            command: row.get(3)?,
            category: row.get(4)?,
            rule_name: row.get(5)?,
        })
    }) {
        Ok(iter) => iter.flatten(),
        Err(_) => return Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    rows.filter(|b| seen.insert(b.request_id.clone())).collect()
}

/// Summary statistics from the history database.
#[derive(Debug, Default)]
pub struct HistoryStats {
    pub total_events: u64,
    pub blocks: u64,
    pub allows: u64,
    pub approvals: u64,
    pub top_categories: Vec<(String, u64)>,
    pub first_event: Option<String>,
    pub last_event: Option<String>,
}

/// Query aggregate stats from the history database.
pub fn query_stats() -> HistoryStats {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return HistoryStats::default(),
    };

    let mut stats = HistoryStats::default();

    // Total counts by event type
    if let Ok(mut stmt) =
        conn.prepare("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
    {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        }) {
            for row in rows.flatten() {
                match row.0.as_str() {
                    "block" => stats.blocks = row.1,
                    "allow" => stats.allows = row.1,
                    "approved" => stats.approvals = row.1,
                    _ => {}
                }
                stats.total_events += row.1;
            }
        }
    }

    // Top blocked categories
    if let Ok(mut stmt) = conn.prepare(
        "SELECT category, COUNT(*) as cnt FROM events WHERE event_type = 'block' AND category IS NOT NULL GROUP BY category ORDER BY cnt DESC LIMIT 5",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        }) {
            stats.top_categories = rows.flatten().collect();
        }
    }

    // First and last event timestamps
    if let Ok(mut stmt) = conn.prepare("SELECT MIN(timestamp), MAX(timestamp) FROM events") {
        if let Ok(row) = stmt.query_row([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        }) {
            stats.first_event = row.0;
            stats.last_event = row.1;
        }
    }

    stats
}

/// A recent event row for display.
#[derive(Debug)]
pub struct EventRow {
    pub timestamp: String,
    pub event_type: String,
    pub tool_name: String,
    pub command: String,
    pub category: String,
    pub message: String,
}

/// Query recent events from the history database.
/// `limit` controls how many events to return. `event_filter` optionally filters by type.
pub fn query_recent(limit: usize, event_filter: Option<&str>) -> Vec<EventRow> {
    let conn = match open_db() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let sql = if event_filter.is_some() {
        "SELECT timestamp, event_type, COALESCE(tool_name,''), COALESCE(command,''), COALESCE(category,''), COALESCE(message,'') FROM events WHERE event_type = ?1 ORDER BY id DESC LIMIT ?2"
    } else {
        "SELECT timestamp, event_type, COALESCE(tool_name,''), COALESCE(command,''), COALESCE(category,''), COALESCE(message,'') FROM events ORDER BY id DESC LIMIT ?1"
    };

    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let map_row = |row: &rusqlite::Row| -> rusqlite::Result<EventRow> {
        Ok(EventRow {
            timestamp: row.get(0)?,
            event_type: row.get(1)?,
            tool_name: row.get(2)?,
            command: row.get(3)?,
            category: row.get(4)?,
            message: row.get(5)?,
        })
    };

    let results: Vec<EventRow> = if let Some(filter) = event_filter {
        match stmt.query_map(params![filter, limit as u32], map_row) {
            Ok(iter) => iter.flatten().collect(),
            Err(_) => Vec::new(),
        }
    } else {
        match stmt.query_map(params![limit as u32], map_row) {
            Ok(iter) => iter.flatten().collect(),
            Err(_) => Vec::new(),
        }
    };

    results
}

/// Get the database file size in bytes (for status display).
pub fn db_size_bytes() -> u64 {
    let path = db_path();
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_query_events() {
        // Use a temp database
        let tmp = std::env::temp_dir().join("hedgehog_test_history.db");
        let _ = std::fs::remove_file(&tmp);

        let conn = Connection::open(&tmp).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                session_id TEXT,
                tool_name TEXT,
                command TEXT,
                category TEXT,
                rule_name TEXT,
                message TEXT,
                request_id TEXT
            );",
        )
        .unwrap();

        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO events (timestamp, event_type, session_id, tool_name, command, category, rule_name, message, request_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![now, "block", "sess-1", "Bash", "rm -rf /", "destructive", "rm-rf", "Blocked dangerous command", Option::<String>::None],
        ).unwrap();

        conn.execute(
            "INSERT INTO events (timestamp, event_type, session_id, tool_name, command, category, rule_name, message, request_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![now, "allow", "sess-1", "Bash", "ls -la", Option::<String>::None, Option::<String>::None, Option::<String>::None, Option::<String>::None],
        ).unwrap();

        // Count
        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);

        // Filter
        let block_count: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_type = 'block'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(block_count, 1);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn query_stats_does_not_panic() {
        let stats = query_stats();
        // Just a smoke test — the real DB may or may not exist
        assert!(stats.top_categories.len() <= 5);
    }

    #[test]
    fn query_recent_does_not_panic() {
        let events = query_recent(10, None);
        assert!(events.len() <= 10);
    }

    #[test]
    fn db_size_returns_zero_or_positive() {
        let size = db_size_bytes();
        // Just don't panic
        let _ = size;
    }
}
