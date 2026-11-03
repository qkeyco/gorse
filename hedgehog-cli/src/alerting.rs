// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Independent alert system for Gorse security events.
//!
//! Sends alerts via Telegram, WhatsApp Business API, Twilio SMS, and generic
//! webhooks — independently of any AI agent process.
//!
//! Events are committed before returning to short-lived hooks. A persistent
//! worker retries pending deliveries. This user-owned outbox is not a boundary
//! against another unrestricted process running as the same user or as root.

use crate::config;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

// ─── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Severity::Info => "[i]",
            Severity::Medium => "[!]",
            Severity::High => "[!!]",
            Severity::Critical => "[!!!]",
        }
    }

    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "info" => Severity::Info,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertType {
    CredentialAccess,
    ExfiltrationBlocked,
    IntrusionDetected,
    Watchdog,
}

impl AlertType {
    pub fn label(&self) -> &'static str {
        match self {
            AlertType::CredentialAccess => "Credential Access",
            AlertType::ExfiltrationBlocked => "Exfiltration Blocked",
            AlertType::IntrusionDetected => "Intrusion Detected",
            AlertType::Watchdog => "Watchdog",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    #[serde(default)]
    pub event_id: String,
    pub alert_type: AlertType,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub hostname: String,
    pub timestamp: String,
    pub source: Option<String>,
    pub actor: Option<String>,
}

impl SecurityAlert {
    fn format_text(&self) -> String {
        let mut msg = format!(
            "{} Gorse Security Alert\n\n{}: {}\n\n{}",
            self.severity.emoji(),
            self.severity.label(),
            self.title,
            self.detail,
        );
        if let Some(ref actor) = self.actor {
            msg.push_str(&format!("\nActor: {}", actor));
        }
        if let Some(ref source) = self.source {
            msg.push_str(&format!("\nSource: {}", source));
        }
        msg.push_str(&format!("\nHost: {}", self.hostname));
        msg.push_str(&format!("\nTime: {}", self.timestamp));
        msg.push_str(&format!("\nEvent: {}", self.event_id));
        msg
    }

    fn format_json(&self) -> String {
        serde_json::json!({
            "alert_type": self.alert_type.label(),
            "severity": self.severity.label(),
            "title": self.title,
            "detail": self.detail,
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "source": self.source,
            "actor": self.actor,
            "product": "Gorse",
            "event_id": self.event_id,
        })
        .to_string()
    }
}

// ─── Global Dispatcher ──────────────────────────────────────────────────────

static DISPATCHER: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);
static HEARTBEAT_WORKER: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

fn outbox_path() -> PathBuf {
    config::config_dir()
        .join("alert-outbox")
        .join("events.sqlite3")
}

fn event_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Outbox(Connection);

struct Pending {
    alert: SecurityAlert,
    receipts: BTreeMap<String, String>,
    attempts: u32,
    lease: String,
}

impl Outbox {
    fn open(path: &Path) -> Result<Self, String> {
        let dir = path.parent().ok_or("Outbox has no parent directory")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("Create outbox directory: {e}"))?;
        let metadata = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Outbox directory must be a real directory".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err("Outbox directory is owned by a different user".into());
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        match options.open(path) {
            Ok(file) => file.sync_all().map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("Create outbox: {e}")),
        }
        // Only the database file itself is checked. SQLite creates and removes
        // its journal beside it while other gorse processes (concurrent
        // hooks, the watcher) hold the outbox open, so a journal observed
        // mid-creation can legitimately carry a transient mode. The directory
        // above is already 0700 and owned by this user, which is what keeps
        // every side file private; a second check on the journal only races.
        for candidate in [path.to_path_buf()] {
            match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    if !metadata.is_file() || metadata.file_type().is_symlink() {
                        return Err("Outbox contains a non-regular file".into());
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if metadata.uid() != unsafe { libc::geteuid() }
                            || metadata.nlink() != 1
                            || metadata.mode() & 0o077 != 0
                        {
                            return Err(
                                "Outbox files must be private and owned by this user".into()
                            );
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        // macOS /var and /tmp are system symlinks. Resolve the validated parent
        // while retaining NOFOLLOW for the database itself.
        let canonical_path = dir
            .canonicalize()
            .map_err(|e| e.to_string())?
            .join(path.file_name().ok_or("Outbox has no filename")?);
        let conn = Connection::open_with_flags(
            canonical_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| format!("Open outbox: {e}"))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA max_page_count=32768;
            CREATE TABLE IF NOT EXISTS outbox (
                id TEXT PRIMARY KEY, alert TEXT NOT NULL, receipts TEXT NOT NULL DEFAULT '{}',
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0,
                lease TEXT NOT NULL DEFAULT '', complete INTEGER NOT NULL DEFAULT 0,
                last_error TEXT, updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS worker_health (id INTEGER PRIMARY KEY CHECK(id=1),
                updated INTEGER NOT NULL, message TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS heartbeat_config (id INTEGER PRIMARY KEY CHECK(id=1),
                url TEXT NOT NULL, monitor_id TEXT NOT NULL, token TEXT NOT NULL,
                sequence INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS heartbeat_health (id INTEGER PRIMARY KEY CHECK(id=1),
                attempted INTEGER NOT NULL, sequence INTEGER NOT NULL, accepted INTEGER, state TEXT NOT NULL,
                message TEXT NOT NULL);",
        )
        .map_err(|e| format!("Initialize outbox: {e}"))?;
        Ok(Self(conn))
    }

    fn enqueue(&mut self, alert: &SecurityAlert) -> Result<(), String> {
        let json = serde_json::to_string(alert).map_err(|e| e.to_string())?;
        if json.len() > 16_384 {
            return Err("Alert exceeds the durable event size limit".into());
        }
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE id=?1)",
                [&alert.event_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            // Retain recent accepted IDs for replay deduplication. Pending and
            // quarantined events are never deleted to make room.
            tx.execute("DELETE FROM outbox WHERE id IN (SELECT id FROM outbox WHERE complete=1 ORDER BY updated DESC,id DESC LIMIT -1 OFFSET 10000)",[]).map_err(|e| e.to_string())?;
            let pending: i64 = tx
                .query_row("SELECT COUNT(*) FROM outbox WHERE complete!=1", [], |r| {
                    r.get(0)
                })
                .map_err(|e| e.to_string())?;
            if pending >= 10_000 {
                return Err("Alert outbox full; monitoring delivery is degraded".into());
            }
            tx.execute(
                "INSERT INTO outbox(id,alert,updated) VALUES (?1,?2,?3)",
                params![alert.event_id, json, chrono::Utc::now().timestamp_millis()],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| format!("Persist alert: {e}"))
    }

    fn claim(&mut self, now: i64) -> Result<Option<Pending>, String> {
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let row: Option<(String,String,String,u32)> = tx.query_row(
            "SELECT id,alert,receipts,attempts FROM outbox WHERE complete=0 AND next_attempt<=?1 ORDER BY updated,id LIMIT 1", [now],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|e| e.to_string())?;
        let Some((id, json, receipts, attempts)) = row else {
            return Ok(None);
        };
        let parsed_alert = serde_json::from_str::<SecurityAlert>(&json);
        let parsed_receipts = serde_json::from_str::<BTreeMap<String, String>>(&receipts);
        let (Ok(alert), Ok(receipts)) = (parsed_alert, parsed_receipts) else {
            tx.execute("UPDATE outbox SET complete=-1,last_error='corrupt record; quarantined for repair' WHERE id=?1",[&id]).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
            return Err("Corrupt outbox record quarantined; other records remain eligible".into());
        };
        if alert.event_id != id || id.is_empty() {
            tx.execute("UPDATE outbox SET complete=-1,last_error='invalid event identity; quarantined for repair' WHERE id=?1",[&id]).map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
            return Err("Invalid queued event identity quarantined".into());
        }
        let lease = event_id();
        tx.execute(
            "UPDATE outbox SET next_attempt=?1, attempts=attempts+1, lease=?2 WHERE id=?3",
            params![now + 60_000, lease, alert.event_id],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Some(Pending {
            alert,
            receipts,
            attempts: attempts.saturating_add(1),
            lease,
        }))
    }

    fn checkpoint(
        &self,
        pending: &Pending,
        complete: bool,
        error: Option<&str>,
        now: i64,
    ) -> Result<(), String> {
        let delay = (2u64.saturating_pow(pending.attempts.min(8))).min(300) as i64 * 1000;
        let updated = self.0.execute("UPDATE outbox SET receipts=?1,complete=?2,last_error=?3,next_attempt=?4,updated=?5 WHERE id=?6 AND lease=?7",
            params![serde_json::to_string(&pending.receipts).map_err(|e| e.to_string())?,complete,error,now+delay,now,pending.alert.event_id,pending.lease]).map_err(|e| e.to_string())?;
        if updated != 1 {
            return Err("Alert delivery lease expired; receipt not committed".into());
        }
        Ok(())
    }

    fn health(&self, message: &str) -> Result<(), String> {
        self.0.execute("INSERT INTO worker_health(id,updated,message) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET updated=excluded.updated,message=excluded.message",
            params![chrono::Utc::now().timestamp_millis(),message]).map(|_| ()).map_err(|e| e.to_string())
    }
}

/// Initialize the alert dispatcher. Spawns a background worker thread.
/// Safe to call multiple times — only the first call has effect.
pub fn init() -> Result<(), String> {
    init_heartbeat()?;
    let mut guard = DISPATCHER.lock().map_err(|_| "Alert worker lock failed")?;
    if guard.as_ref().is_some_and(|worker| !worker.is_finished()) {
        return Ok(());
    }
    Outbox::open(&outbox_path())?;
    *guard = Some(
        std::thread::Builder::new()
            .name("hedgehog-alerting".into())
            .spawn(|| {
                let mut previous_error = None;
                loop {
                    let error = deliver_pending().err();
                    if error != previous_error {
                        if let Some(e) = &error {
                            eprintln!("Alert delivery degraded: {e}");
                        }
                        previous_error = error;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            })
            .map_err(|e| format!("Start alert worker: {e}"))?,
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeartbeatEnrollment {
    url: String,
    monitor_id: String,
    token: String,
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_heartbeat_enrollment(enrollment: &HeartbeatEnrollment) -> Result<(), String> {
    let url = &enrollment.url;
    // Restrict the entire URL so query/userinfo/fragment cannot carry data and
    // bearer credentials never travel over plaintext outside a loopback test.
    let origin = url
        .strip_suffix("/heartbeat")
        .ok_or("Heartbeat URL must end in /heartbeat")?;
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or("Heartbeat URL requires HTTPS")?;
    let local = origin
        .strip_prefix("http://")
        .and_then(|value| value.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|address| address.ip().is_loopback());
    if host.is_empty()
        || host.contains(['/', '?', '#', '@', '\\'])
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
        || (!origin.starts_with("https://") && !local)
        || !lower_hex(&enrollment.monitor_id, 32)
        || !lower_hex(&enrollment.token, 64)
    {
        return Err("Invalid heartbeat enrollment or non-HTTPS destination".into());
    }
    Ok(())
}

/// Accept enrollment through stdin, never a command-line token or public config
/// dump. The private outbox holds the credential and monotonic sequence together.
pub fn enroll_heartbeat(json: &[u8]) -> Result<(), String> {
    if json.len() > 4096 {
        return Err("Heartbeat enrollment exceeds 4 KiB".into());
    }
    let enrollment: HeartbeatEnrollment = serde_json::from_slice(json)
        .map_err(|_| "Invalid heartbeat enrollment JSON (url, monitor_id, token required)")?;
    validate_heartbeat_enrollment(&enrollment)?;
    let outbox = Outbox::open(&outbox_path())?;
    outbox.0.execute("INSERT INTO heartbeat_config(id,url,monitor_id,token) VALUES(1,?1,?2,?3)",
        params![enrollment.url,enrollment.monitor_id,enrollment.token])
        .map_err(|_| "Heartbeat enrollment could not be stored; existing enrollment is never reset automatically")?;
    Ok(())
}

fn init_heartbeat() -> Result<(), String> {
    let mut guard = HEARTBEAT_WORKER
        .lock()
        .map_err(|_| "Heartbeat worker lock failed")?;
    if guard.as_ref().is_some_and(|worker| !worker.is_finished()) {
        return Ok(());
    }
    *guard = Some(
        std::thread::Builder::new()
            .name("hedgehog-heartbeat".into())
            .spawn(|| {
                let mut previous_error = None;
                loop {
                    let error = send_heartbeat().err();
                    if error != previous_error {
                        if let Some(error) = &error {
                            eprintln!("External heartbeat degraded: {error}");
                        }
                        previous_error = error;
                    }
                    std::thread::sleep(Duration::from_secs(30));
                }
            })
            .map_err(|_| "Cannot start heartbeat worker")?,
    );
    Ok(())
}

/// Reserve and commit a sequence before transport. A failed/ambiguous request
/// consumes its sequence; later attempts cannot replay an earlier healthy state.
fn reserve_heartbeat(outbox: &mut Outbox) -> Result<Option<(HeartbeatEnrollment, i64)>, String> {
    let tx = outbox
        .0
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let current = tx
        .query_row(
            "SELECT url,monitor_id,token,sequence FROM heartbeat_config WHERE id=1",
            [],
            |row| {
                Ok((
                    HeartbeatEnrollment {
                        url: row.get(0)?,
                        monitor_id: row.get(1)?,
                        token: row.get(2)?,
                    },
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some((enrollment, sequence)) = current else {
        return Ok(None);
    };
    validate_heartbeat_enrollment(&enrollment)?;
    if !(0..9_007_199_254_740_991).contains(&sequence) {
        return Err("Heartbeat sequence exhausted or invalid; re-enroll on the monitor".into());
    }
    let next = sequence + 1;
    tx.execute("UPDATE heartbeat_config SET sequence=?1 WHERE id=1", [next])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Some((enrollment, next)))
}

pub fn send_heartbeat() -> Result<bool, String> {
    use std::io::Read;
    let mut outbox = Outbox::open(&outbox_path())?;
    let Some((enrollment, sequence)) = reserve_heartbeat(&mut outbox)? else {
        return Ok(false);
    };
    let canary_health = crate::canary_watcher::heartbeat_health();
    let secret_health = crate::canary_watcher::secret_access::heartbeat_health();
    // A configured secret monitor may never disappear behind a healthy canary
    // report. An idle, unconfigured secret monitor leaves earlier behavior alone.
    let mut health = match secret_health {
        Some("degraded" | "unverified") => "degraded",
        Some("healthy")
            if canary_health == "unverified" && crate::canary_watcher::canary_monitor_idle() =>
        {
            "healthy"
        }
        _ => canary_health,
    };
    let pending: i64 = outbox
        .0
        .query_row("SELECT COUNT(*) FROM outbox WHERE complete!=1", [], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    if pending > 0 {
        health = "degraded";
    }
    if health == "healthy" {
        let remote_enabled = config::load_config()
            .is_ok_and(|cfg| cfg.alerts.enabled && !channels(&cfg.alerts).is_empty());
        let updated: Option<i64> = outbox
            .0
            .query_row("SELECT updated FROM worker_health WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;
        if !remote_enabled
            || !updated.is_some_and(|time| {
                (0..120_000).contains(&(chrono::Utc::now().timestamp_millis() - time))
            })
        {
            health = "degraded";
        }
    }
    let now = chrono::Utc::now().timestamp_millis();
    outbox.0.execute("INSERT INTO heartbeat_health(id,attempted,state,sequence,message) VALUES(1,?1,?2,?3,'awaiting acknowledgement')
        ON CONFLICT(id) DO UPDATE SET attempted=excluded.attempted,state=excluded.state,sequence=excluded.sequence,message=excluded.message WHERE excluded.sequence>heartbeat_health.sequence", params![now,health,sequence])
        .map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        let response = ureq::AgentBuilder::new().redirects(0).timeout(Duration::from_secs(5)).build()
            .post(&enrollment.url).set("Authorization", &format!("Bearer {}", enrollment.token))
            .set("Content-Type", "application/json")
            .send_string(&serde_json::json!({"monitor_id":enrollment.monitor_id,"sequence":sequence,"health":health}).to_string())
            .map_err(|_| "Heartbeat request failed; remote supervision may report loss")?;
        if response.status() != 200 {
            return Err("Heartbeat server did not acknowledge the request".into());
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(1025)
            .read_to_end(&mut bytes)
            .map_err(|_| "Heartbeat acknowledgement unreadable")?;
        if bytes.len() > 1024 {
            return Err("Heartbeat acknowledgement exceeds limit".into());
        }
        let ack: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid heartbeat acknowledgement")?;
        if ack.get("accepted").and_then(|v| v.as_bool()) != Some(true)
            || ack.get("sequence").and_then(|v| v.as_i64()) != Some(sequence)
        {
            return Err("Heartbeat acknowledgement does not match the sent sequence".into());
        }
        Ok(())
    })();
    outbox.0.execute("UPDATE heartbeat_health SET accepted=CASE WHEN ?1 THEN ?2 ELSE accepted END,message=?3 WHERE id=1 AND sequence=?4",
        params![result.is_ok(),chrono::Utc::now().timestamp_millis(),if result.is_ok() {"server acknowledged report"} else {"request or acknowledgement failed"},sequence])
        .map_err(|e| e.to_string())?;
    result.map(|()| true)
}

pub fn heartbeat_status_lines() -> Vec<String> {
    let result = (|| -> Result<Vec<String>, String> {
        let outbox = Outbox::open(&outbox_path())?;
        let enrolled: bool = outbox
            .0
            .query_row("SELECT EXISTS(SELECT 1 FROM heartbeat_config)", [], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        if !enrolled {
            return Ok(vec!["External heartbeat: not enrolled".into()]);
        }
        let report = outbox
            .0
            .query_row(
                "SELECT accepted,state,message FROM heartbeat_health WHERE id=1",
                [],
                |r| {
                    Ok((
                        r.get::<_, Option<i64>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let message = match report {
            Some((Some(time),state,message)) if (0..120_000).contains(&(chrono::Utc::now().timestamp_millis()-time))
                && ["healthy","degraded","unverified"].contains(&state.as_str()) && message == "server acknowledged report" =>
                format!("External heartbeat: server recently acknowledged '{state}' availability report"),
            _ => "External heartbeat: enrolled; acknowledgement absent, stale or failed".into(),
        };
        Ok(vec![message,"Remote acceptance does not prove enforcement or receipt of a health alarm. Stopping this sender does not cancel remote supervision.".into()])
    })();
    result.unwrap_or_else(|_| vec!["External heartbeat: local state unavailable".into()])
}

/// Commit an event locally. Success means durable storage, not remote delivery.
pub fn send(mut alert: SecurityAlert) -> Result<String, String> {
    if alert.event_id.is_empty() {
        alert.event_id = event_id();
    }
    Outbox::open(&outbox_path())?.enqueue(&alert)?;
    Ok(alert.event_id)
}

/// Send a test alert to all configured channels. Returns results per channel.
/// Blocking — waits for all channels to respond (5s timeout each).
pub fn send_test() -> Vec<(String, Result<(), String>)> {
    let cfg = match config::load_config() {
        Ok(c) => c.alerts,
        Err(e) => return vec![("config".into(), Err(e))],
    };

    let alert = SecurityAlert {
        event_id: event_id(),
        alert_type: AlertType::Watchdog,
        severity: Severity::Info,
        title: "Test Alert".into(),
        detail: "Channel test only. This does not test canary sensing or network enforcement."
            .into(),
        hostname: hostname(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: Some("gorse alerts test".into()),
        actor: None,
    };

    let mut results = Vec::new();

    if let Some(ref tg) = cfg.telegram {
        results.push(("Telegram".into(), send_telegram(tg, &alert)));
    }
    if let Some(ref wa) = cfg.whatsapp {
        results.push(("WhatsApp".into(), send_whatsapp(wa, &alert)));
    }
    if let Some(ref tw) = cfg.twilio {
        results.push(("Twilio SMS".into(), send_twilio(tw, &alert)));
    }
    if let Some(ref wh) = cfg.webhook {
        results.push(("Webhook".into(), send_webhook(wh, &alert)));
    }

    if results.is_empty() {
        results.push(("(none)".into(), Err("No alert channels configured".into())));
    }

    results
}

// ─── Convenience Builders ───────────────────────────────────────────────────

pub fn alert_credential_access(
    _file_path: &str,
    _process_name: &str,
    _detail: &str,
) -> Result<(), String> {
    send(SecurityAlert {
        event_id: String::new(),
        alert_type: AlertType::CredentialAccess,
        severity: Severity::Critical,
        title: "Canary Rule Triggered".into(),
        detail: "A hook matched a registered decoy reference or value. Review local records for context; a match does not establish malicious intent.".into(),
        hostname: hostname(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: Some("canary_hook".into()),
        actor: None,
    }).map(|_| ())
}

pub fn alert_canary_access(
    token_id: &str,
    placement_id: &str,
    sensor_event: &str,
    is_selftest: bool,
) -> Result<(), String> {
    for id in [token_id, placement_id, sensor_event] {
        if id.is_empty()
            || id.len() > 160
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c))
        {
            return Err("Canary alarm identity is invalid".into());
        }
    }
    send(SecurityAlert {
        event_id: format!("canary:{sensor_event}:{placement_id}:{token_id}"),
        alert_type: AlertType::CredentialAccess,
        severity: Severity::Critical,
        title: if is_selftest { "Canary Self-test" } else { "Registered Decoy Opened" }.into(),
        detail: if is_selftest {
            "The endpoint sensor observed the deliberate synthetic decoy probe for a live canary self-test. This is a test notification, not an attack report."
        } else {
            "The endpoint sensor observed a read-open of a registered decoy. Review local records for process context."
        }.into(),
        hostname: hostname(), timestamp: chrono::Utc::now().to_rfc3339(),
        source: Some(placement_id.into()), actor: None,
    }).map(|_| ())
}

/// Only validated sensor identifiers enter this payload. Paths, signing names,
/// command text and secret contents remain in the local sensor record.
pub(crate) fn secret_access_alert(
    owner_uid: u32,
    policy_revision: &str,
    secret_id: &str,
    stream: &str,
    sequence: u64,
    pid: u32,
    identity_unverified: bool,
) -> Result<SecurityAlert, String> {
    for value in [policy_revision, secret_id] {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Invalid secret alarm identity".into());
        }
    }
    if stream.is_empty()
        || stream.len() > 64
        || !stream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || sequence == 0
        || pid == 0
    {
        return Err("Invalid secret sensor event identity".into());
    }
    Ok(SecurityAlert {
        event_id: format!("secret-access:{owner_uid}:{stream}:{sequence}:{policy_revision}:{secret_id}"),
        alert_type: AlertType::CredentialAccess,
        severity: Severity::High,
        title: "Unapproved Secret Access".into(),
        detail: if identity_unverified {
            "The sensor observed a read-capable open of an enrolled secret by a process whose code identity could not be verified. Review the local access record. This is an access-policy alarm, not proof of malicious intent or transferred bytes."
        } else {
            "The sensor observed a read-capable open of an enrolled secret by a reader absent from its approved list. Review the local access record. This is an access-policy alarm, not proof of malicious intent or transferred bytes."
        }.into(),
        hostname: hostname(), timestamp: chrono::Utc::now().to_rfc3339(),
        source: Some(secret_id.into()), actor: Some(format!("PID {pid}")),
    })
}

pub fn alert_exfiltration_blocked(
    _tool_name: &str,
    _command: &str,
    _category: &str,
    _message: &str,
) -> Result<(), String> {
    send(SecurityAlert {
        event_id: String::new(),
        alert_type: AlertType::ExfiltrationBlocked,
        severity: Severity::High,
        title: "Security Rule Blocked an Operation".into(),
        detail: "A local security rule blocked an operation. Review local records for details; this is not confirmation of an attempted attack.".into(),
        hostname: hostname(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: Some("security_rule".into()),
        actor: None,
    }).map(|_| ())
}

pub fn alert_watchdog(title: &str, detail: &str) -> Result<(), String> {
    send(SecurityAlert {
        event_id: String::new(),
        alert_type: AlertType::Watchdog,
        severity: Severity::High,
        title: title.to_string(),
        detail: detail.to_string(),
        hostname: hostname(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: None,
        actor: None,
    })
    .map(|_| ())
}

// ─── Background Worker ──────────────────────────────────────────────────────

fn channels(cfg: &config::AlertConfig) -> Vec<&'static str> {
    let mut names = Vec::new();
    if cfg.telegram.is_some() {
        names.push("Telegram");
    }
    if cfg.whatsapp.is_some() {
        names.push("WhatsApp");
    }
    if cfg.twilio.is_some() {
        names.push("Twilio SMS");
    }
    if cfg.webhook.is_some() {
        names.push("Webhook");
    }
    names
}

fn receipt_key(channel: &str, cfg: &config::AlertConfig) -> Result<String, String> {
    let json = match channel {
        "Telegram" => serde_json::to_vec(&cfg.telegram),
        "WhatsApp" => serde_json::to_vec(&cfg.whatsapp),
        "Twilio SMS" => serde_json::to_vec(&cfg.twilio),
        "Webhook" => serde_json::to_vec(&cfg.webhook),
        _ => return Err("Unknown alert channel".into()),
    }
    .map_err(|e| e.to_string())?;
    Ok(format!("{channel}:{:x}", Sha256::digest(json)))
}

/// Pins configured recipients without exposing their addresses or credentials.
/// This is a local delivery expectation, not a remote or human acknowledgement.
pub struct SelftestDeliveryExpectation {
    receipt_keys: Vec<String>,
    config_fingerprint: [u8; 32],
}

impl SelftestDeliveryExpectation {
    pub fn channel_count(&self) -> usize {
        self.receipt_keys.len()
    }

    fn from_config(cfg: &config::AlertConfig) -> Result<Self, String> {
        let names = channels(cfg);
        if !cfg.enabled || names.is_empty() {
            return Err("Live alarm self-test requires enabled, configured alert channels".into());
        }
        let receipt_keys = names
            .into_iter()
            .map(|name| receipt_key(name, cfg))
            .collect::<Result<Vec<_>, _>>()?;
        let json = serde_json::to_vec(cfg)
            .map_err(|_| "Alert configuration could not be pinned".to_string())?;
        Ok(Self {
            receipt_keys,
            config_fingerprint: Sha256::digest(json).into(),
        })
    }

    fn verify_config(&self, cfg: &config::AlertConfig) -> Result<(), String> {
        let current = Self::from_config(cfg)?;
        if current.config_fingerprint != self.config_fingerprint {
            return Err("Alert configuration changed during the live alarm self-test".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelftestDeliveryStatus {
    Missing,
    Pending {
        accepted: usize,
        total: usize,
    },
    /// Every pinned provider accepted this event; this does not prove a person
    /// received or read it, nor that the endpoint sensor observed the access.
    Accepted {
        channels: usize,
    },
}

pub fn selftest_delivery_expectation() -> Result<SelftestDeliveryExpectation, String> {
    let cfg =
        config::load_config().map_err(|_| "Alert configuration is unavailable".to_string())?;
    SelftestDeliveryExpectation::from_config(&cfg.alerts)
}

/// Observe daemon delivery of one verified sensor event. Never enqueue an
/// alert, acquire a delivery lease, retry a provider, or drain unrelated events.
pub fn selftest_delivery_status(
    event_id: &str,
    expectation: &SelftestDeliveryExpectation,
    started: chrono::DateTime<chrono::Utc>,
) -> Result<SelftestDeliveryStatus, String> {
    let cfg =
        config::load_config().map_err(|_| "Alert configuration is unavailable".to_string())?;
    expectation.verify_config(&cfg.alerts)?;
    let status = match selftest_read_only_outbox(&outbox_path())? {
        Some(outbox) => selftest_delivery_status_in(
            &outbox,
            event_id,
            expectation,
            &cfg.alerts,
            started,
            chrono::Utc::now,
        ),
        None => Ok(SelftestDeliveryStatus::Missing),
    }?;
    // Reject recipient or policy changes across the read as well as between
    // polls. No receipt from a previous destination can satisfy this run.
    let current =
        config::load_config().map_err(|_| "Alert configuration is unavailable".to_string())?;
    expectation.verify_config(&current.alerts)?;
    Ok(status)
}

fn selftest_read_only_outbox(path: &Path) -> Result<Option<Outbox>, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Cannot inspect the live alarm outbox".into()),
        Ok(_) => {}
    }
    let dir = path.parent().ok_or("Outbox has no parent directory")?;
    for (candidate, directory) in [
        (dir.to_path_buf(), true),
        (path.to_path_buf(), false),
        (PathBuf::from(format!("{}-journal", path.display())), false),
    ] {
        let metadata = match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && candidate != dir
                    && candidate != path =>
            {
                continue;
            }
            Err(_) => return Err("Cannot inspect the live alarm outbox".into()),
        };
        if metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err("Live alarm outbox contains an unsafe filesystem entry".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || (!directory && metadata.nlink() != 1)
            {
                return Err("Live alarm outbox must be private and owned by this user".into());
            }
        }
    }
    let canonical_path = dir
        .canonicalize()
        .map_err(|_| "Cannot resolve the live alarm outbox".to_string())?
        .join(path.file_name().ok_or("Outbox has no filename")?);
    let connection = Connection::open_with_flags(
        canonical_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "Cannot open the live alarm outbox for observation".to_string())?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| "Cannot configure the live alarm outbox reader".to_string())?;
    Ok(Some(Outbox(connection)))
}

fn selftest_delivery_status_in(
    outbox: &Outbox,
    event_id: &str,
    expectation: &SelftestDeliveryExpectation,
    cfg: &config::AlertConfig,
    started: chrono::DateTime<chrono::Utc>,
    now: impl FnOnce() -> chrono::DateTime<chrono::Utc>,
) -> Result<SelftestDeliveryStatus, String> {
    expectation.verify_config(cfg)?;
    // Placement and token IDs do not contain colons; a sensor identity may.
    let identity: Vec<_> = event_id
        .strip_prefix("canary:")
        .ok_or("Live alarm self-test requires a canary sensor event identity")?
        .rsplitn(3, ':')
        .collect();
    if identity.len() != 3
        || identity.iter().any(|part| {
            part.is_empty()
                || part.len() > 160
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c))
        })
    {
        return Err("Live alarm self-test event identity is invalid".into());
    }
    let row: Option<(String, String, i64)> = outbox
        .0
        .query_row(
            "SELECT alert,receipts,complete FROM outbox WHERE id=?1",
            [event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| "Cannot read the live alarm event".to_string())?;
    let Some((json, receipts, complete)) = row else {
        return Ok(SelftestDeliveryStatus::Missing);
    };
    // Sample the clock after the row snapshot: a worker may commit a receipt
    // between opening the reader and executing the query.
    let now = now();
    if complete < 0 {
        return Err("Live alarm event is quarantined; repair is required".into());
    }
    if complete > 1 {
        return Err("Live alarm event has an invalid delivery state".into());
    }
    let alert: SecurityAlert =
        serde_json::from_str(&json).map_err(|_| "Live alarm event is corrupt".to_string())?;
    if alert.event_id != event_id
        || alert.alert_type != AlertType::CredentialAccess
        || alert.severity != Severity::Critical
        || alert.source.as_deref() != Some(identity[1])
        || alert.title != "Canary Self-test"
    {
        return Err("Live alarm event does not match the expected canary access".into());
    }
    let timestamp = chrono::DateTime::parse_from_rfc3339(&alert.timestamp)
        .map_err(|_| "Live alarm event has an invalid timestamp".to_string())?
        .with_timezone(&chrono::Utc);
    if timestamp <= started || timestamp > now {
        return Err("Live alarm event timestamp is outside this self-test run".into());
    }
    let receipts: BTreeMap<String, String> = serde_json::from_str(&receipts)
        .map_err(|_| "Live alarm receipts are corrupt".to_string())?;
    let mut accepted = 0;
    for key in &expectation.receipt_keys {
        if let Some(receipt) = receipts.get(key) {
            let receipt = chrono::DateTime::parse_from_rfc3339(receipt)
                .map_err(|_| "Live alarm receipt has an invalid timestamp".to_string())?
                .with_timezone(&chrono::Utc);
            if receipt <= started || receipt < timestamp || receipt > now {
                return Err("Live alarm receipt timestamp is outside this self-test event".into());
            }
            accepted += 1;
        }
    }
    let total = expectation.channel_count();
    Ok(if accepted == total {
        SelftestDeliveryStatus::Accepted { channels: total }
    } else {
        SelftestDeliveryStatus::Pending { accepted, total }
    })
}

/// Delivers at most 16 due events. Successful requests mean provider acceptance,
/// not a human reading a message. An interrupted request can be retried with
/// the same event ID; receivers should deduplicate that ID.
pub fn deliver_pending() -> Result<usize, String> {
    let mut outbox = Outbox::open(&outbox_path())?;
    let cfg = match config::load_config() {
        Ok(cfg) => cfg.alerts,
        Err(_) => {
            outbox.health("configuration unavailable; events retained")?;
            return Err("Alert configuration unavailable; events retained locally".into());
        }
    };
    if !cfg.enabled || channels(&cfg).is_empty() {
        outbox.health("remote delivery disabled or unconfigured; events retained")?;
        return Err("Remote delivery disabled or unconfigured; events retained locally".into());
    }
    let mut completed = 0;
    outbox.health("delivery worker running")?;
    for _ in 0..16 {
        let Some(result) = deliver_one(
            &mut outbox,
            &cfg,
            chrono::Utc::now().timestamp_millis(),
            |channel, alert| match channel {
                "Telegram" => send_telegram(cfg.telegram.as_ref().unwrap(), alert),
                "WhatsApp" => send_whatsapp(cfg.whatsapp.as_ref().unwrap(), alert),
                "Twilio SMS" => send_twilio(cfg.twilio.as_ref().unwrap(), alert),
                "Webhook" => send_webhook(cfg.webhook.as_ref().unwrap(), alert),
                _ => Err("Unknown delivery channel".into()),
            },
        )?
        else {
            break;
        };
        if result {
            completed += 1;
        }
        outbox.health(if result {
            "provider accepted event"
        } else {
            "pending delivery; inspect event status"
        })?;
    }
    let pending: i64 = outbox
        .0
        .query_row("SELECT COUNT(*) FROM outbox WHERE complete!=1", [], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    if pending > 0 {
        return Err(format!(
            "{completed} event(s) completed this pass; {pending} remain pending"
        ));
    }
    Ok(completed)
}

fn deliver_one(
    outbox: &mut Outbox,
    cfg: &config::AlertConfig,
    now: i64,
    mut deliver: impl FnMut(&str, &SecurityAlert) -> Result<(), String>,
) -> Result<Option<bool>, String> {
    if !cfg.enabled || channels(cfg).is_empty() {
        return Ok(None);
    }
    let Some(mut pending) = outbox.claim(now)? else {
        return Ok(None);
    };
    if pending.alert.severity < Severity::from_str(&cfg.min_severity) {
        outbox.checkpoint(
            &pending,
            false,
            Some("below configured severity; retained locally"),
            now,
        )?;
        return Ok(Some(false));
    }
    let mut failed = false;
    for channel in channels(cfg) {
        let receipt_key = receipt_key(channel, cfg)?;
        if pending.receipts.contains_key(&receipt_key) {
            continue;
        }
        match deliver(channel, &pending.alert) {
            Ok(()) => {
                pending
                    .receipts
                    .insert(receipt_key, chrono::Utc::now().to_rfc3339());
                let updated = outbox
                    .0
                    .execute(
                        "UPDATE outbox SET receipts=?1 WHERE id=?2 AND lease=?3",
                        params![
                            serde_json::to_string(&pending.receipts).map_err(|e| e.to_string())?,
                            pending.alert.event_id,
                            pending.lease
                        ],
                    )
                    .map_err(|e| e.to_string())?;
                if updated != 1 {
                    return Err("Delivery receipt lease expired".into());
                }
            }
            Err(_) => {
                failed = true;
            } // Never persist provider errors containing tokens/URLs.
        }
    }
    outbox.checkpoint(
        &pending,
        !failed,
        if failed {
            Some("provider request failed; retry scheduled")
        } else {
            None
        },
        now,
    )?;
    Ok(Some(!failed))
}

// ─── Channel Implementations ────────────────────────────────────────────────

fn channel_request(url: &str, alert: &SecurityAlert) -> ureq::Request {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(5))
        .build()
        .post(url)
        .set("Idempotency-Key", &alert.event_id)
}

fn request_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(status, _) => format!("Provider returned HTTP {status}"),
        ureq::Error::Transport(_) => "Provider transport failed".into(),
    }
}

fn send_telegram(cfg: &config::TelegramConfig, alert: &SecurityAlert) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", cfg.bot_token);
    let body = serde_json::json!({
        "chat_id": cfg.chat_id,
        "text": alert.format_text(),
    });
    let json = serde_json::to_string(&body).map_err(|e| format!("JSON error: {e}"))?;

    let resp = channel_request(&url, alert)
        .set("Content-Type", "application/json")
        .send_string(&json)
        .map_err(request_error)?;

    if resp.status() != 200 {
        return Err(format!("Telegram returned status {}", resp.status()));
    }
    Ok(())
}

fn send_whatsapp(cfg: &config::WhatsAppConfig, alert: &SecurityAlert) -> Result<(), String> {
    let url = format!(
        "https://graph.facebook.com/v21.0/{}/messages",
        cfg.phone_number_id
    );
    let body = serde_json::json!({
        "messaging_product": "whatsapp",
        "to": cfg.to_number,
        "type": "text",
        "text": {
            "body": alert.format_text()
        }
    });
    let json = serde_json::to_string(&body).map_err(|e| format!("JSON error: {e}"))?;

    let resp = channel_request(&url, alert)
        .set("Authorization", &format!("Bearer {}", cfg.access_token))
        .set("Content-Type", "application/json")
        .send_string(&json)
        .map_err(request_error)?;

    if resp.status() != 200 && resp.status() != 201 {
        return Err(format!("WhatsApp returned status {}", resp.status()));
    }
    Ok(())
}

fn send_twilio(cfg: &config::TwilioConfig, alert: &SecurityAlert) -> Result<(), String> {
    let url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        cfg.account_sid
    );

    let body = format!(
        "From={}&To={}&Body={}",
        url_encode(&cfg.from_number),
        url_encode(&cfg.to_number),
        url_encode(&alert.format_text()),
    );

    let credentials = format!("{}:{}", cfg.account_sid, cfg.auth_token);
    let auth = format!(
        "Basic {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials)
    );

    let resp = channel_request(&url, alert)
        .set("Authorization", &auth)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)
        .map_err(request_error)?;

    if resp.status() != 201 && resp.status() != 200 {
        return Err(format!("Twilio returned status {}", resp.status()));
    }
    Ok(())
}

fn send_webhook(cfg: &config::AlertWebhookConfig, alert: &SecurityAlert) -> Result<(), String> {
    // Plain HTTP is available only for a literal loopback test receiver.
    let local = cfg
        .url
        .strip_prefix("http://")
        .and_then(|s| s.split('/').next())
        .and_then(|host| host.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|addr| addr.ip().is_loopback());
    if !cfg.url.starts_with("https://") && !local {
        return Err("Webhook requires HTTPS (literal loopback HTTP is allowed for tests)".into());
    }
    let mut req = channel_request(&cfg.url, alert).set("Content-Type", "application/json");

    if let Some(ref auth) = cfg.auth_header {
        req = req.set("Authorization", auth);
    }

    let json = alert.format_json();

    let resp = req.send_string(&json).map_err(request_error)?;

    if !(200..300).contains(&resp.status()) {
        return Err(format!("Webhook returned status {}", resp.status()));
    }
    if alert.alert_type == AlertType::CredentialAccess
        && (alert.title == "Canary Self-test" || alert.event_id.starts_with("secret-access:"))
    {
        // A live self-test needs acknowledgement of this exact event; a proxy
        // login page or an unrelated successful HTTP response is insufficient.
        // Enrolled-secret alarms use the same exact-event acknowledgement.
        // Earlier ordinary webhook alerts retain their HTTP success contract.
        validate_selftest_webhook_ack(resp.into_reader(), &alert.event_id)?;
    }
    Ok(())
}

/// Self-test receivers must return a JSON object containing exactly
/// {"accepted":true,"event_id":"<the current event ID>"}, at most 4096 bytes.
/// This proves receiver acceptance, not notification delivery to a person.
fn validate_selftest_webhook_ack(reader: impl std::io::Read, event_id: &str) -> Result<(), String> {
    use std::io::Read;
    const MAX_ACK_BYTES: u64 = 4096;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Acknowledgement {
        accepted: bool,
        event_id: String,
    }
    let mut body = Vec::new();
    reader
        .take(MAX_ACK_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| "Self-test webhook acknowledgement could not be read".to_string())?;
    if body.len() > MAX_ACK_BYTES as usize {
        return Err("Self-test webhook acknowledgement exceeds 4096 bytes".into());
    }
    let acknowledgement: Acknowledgement = serde_json::from_slice(&body)
        .map_err(|_| "Self-test webhook acknowledgement is not valid expected JSON".to_string())?;
    if !acknowledgement.accepted || event_id.is_empty() || acknowledgement.event_id != event_id {
        return Err("Self-test webhook did not acknowledge this exact event".into());
    }
    Ok(())
}

// ─── Utilities ──────────────────────────────────────────────────────────────

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0x0F) as usize]));
            }
        }
    }
    out
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".into())
}

/// Return status info about configured alert channels.
pub fn status_lines() -> Vec<String> {
    let cfg = match config::load_config() {
        Ok(c) => c.alerts,
        Err(_) => {
            let mut lines =
                vec!["Alert configuration unavailable; remote delivery unverified".into()];
            lines.extend(outbox_status_lines(&outbox_path()));
            return lines;
        }
    };

    let mut lines = Vec::new();
    lines.push(format!(
        "Alerting: {}",
        if cfg.enabled { "enabled" } else { "disabled" }
    ));
    lines.push(format!("Min severity: {}", cfg.min_severity));
    lines.push(
        "Duplicate sensor event IDs are retained once; time-based suppression is disabled".into(),
    );

    if let Some(ref tg) = cfg.telegram {
        lines.push(format!("Telegram: configured (chat_id: {})", tg.chat_id));
    }
    if let Some(ref _wa) = cfg.whatsapp {
        lines.push("WhatsApp: configured".into());
    }
    if let Some(ref _tw) = cfg.twilio {
        lines.push("Twilio SMS: configured".into());
    }
    if cfg.webhook.is_some() {
        lines.push("Webhook: configured".into());
    }

    if cfg.telegram.is_none()
        && cfg.whatsapp.is_none()
        && cfg.twilio.is_none()
        && cfg.webhook.is_none()
    {
        lines.push("No alert channels configured".into());
    }

    lines.extend(outbox_status_lines(&outbox_path()));
    lines
}

fn outbox_status_lines(path: &Path) -> Vec<String> {
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return vec!["Outbox: no events recorded; delivery unverified".into()];
    }
    match (|| -> Result<Vec<String>, String> {
        let outbox = Outbox::open(path)?;
        let (pending, complete, quarantined): (i64, i64, i64) = outbox
            .0
            .query_row(
                "SELECT COALESCE(SUM(complete=0),0),COALESCE(SUM(complete=1),0),COALESCE(SUM(complete=-1),0) FROM outbox",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        let health: Option<(i64, String)> = outbox
            .0
            .query_row(
                "SELECT updated,message FROM worker_health WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let worker = match health {
            Some((updated,message)) if (0..120_000).contains(&(chrono::Utc::now().timestamp_millis()-updated)) => format!("Delivery worker last report: {message}"),
            _ => "Delivery worker: absent or stale; pending events need a running daemon or 'gorse alerts deliver'".into(),
        };
        Ok(vec![format!("Outbox: {pending} pending, {complete} provider-accepted events, {quarantined} quarantined (repair required)"),worker,
            "Provider acceptance does not confirm human receipt; queued events use currently configured channels".into()])
    })() {
        Ok(lines) => lines,
        Err(e) => vec![format!("Outbox: DEGRADED ({e})")],
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PROOF_EVENT_ID: &str = "canary:sensor:sequence:placement:token";

    #[test]
    fn selftest_webhook_ack_requires_positive_acceptance_of_the_exact_event() {
        let valid = serde_json::json!({"accepted": true, "event_id": PROOF_EVENT_ID}).to_string();
        validate_selftest_webhook_ack(valid.as_bytes(), PROOF_EVENT_ID).unwrap();
        for body in [
            "<html>Log in to continue</html>".to_string(),
            "{broken".into(),
            "{}".into(),
            serde_json::json!({"accepted": false, "event_id": PROOF_EVENT_ID}).to_string(),
            serde_json::json!({"accepted": "true", "event_id": PROOF_EVENT_ID}).to_string(),
            serde_json::json!({"accepted": true, "event_id": "canary:previous:placement:token"})
                .to_string(),
            serde_json::json!({"accepted": true, "event_id": PROOF_EVENT_ID, "extra": true})
                .to_string(),
            format!(
                "{{\"accepted\":true,\"event_id\":\"{PROOF_EVENT_ID}\",\"event_id\":\"other\"}}"
            ),
        ] {
            assert!(validate_selftest_webhook_ack(body.as_bytes(), PROOF_EVENT_ID).is_err());
        }
        assert!(validate_selftest_webhook_ack(valid.as_bytes(), "").is_err());
    }

    #[test]
    fn selftest_webhook_ack_is_bounded_even_when_valid_json_is_padded() {
        let mut body =
            serde_json::json!({"accepted": true, "event_id": PROOF_EVENT_ID}).to_string();
        body.push_str(&" ".repeat(4096 - body.len()));
        validate_selftest_webhook_ack(body.as_bytes(), PROOF_EVENT_ID).unwrap();
        body.push(' ');
        assert!(
            validate_selftest_webhook_ack(body.as_bytes(), PROOF_EVENT_ID)
                .unwrap_err()
                .contains("4096")
        );
        let mut bytes_read = 0usize;
        let endless = std::io::repeat(b' ');
        struct CountReads<'a, R> {
            reader: R,
            count: &'a mut usize,
        }
        impl<R: std::io::Read> std::io::Read for CountReads<'_, R> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let bytes = self.reader.read(buffer)?;
                *self.count += bytes;
                Ok(bytes)
            }
        }
        assert!(validate_selftest_webhook_ack(
            CountReads {
                reader: endless,
                count: &mut bytes_read
            },
            PROOF_EVENT_ID
        )
        .is_err());
        assert_eq!(bytes_read, 4097);
    }

    fn proof_time(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_788_566_400 + seconds, 0).unwrap()
    }

    fn proof_alert() -> SecurityAlert {
        SecurityAlert {
            event_id: PROOF_EVENT_ID.into(),
            alert_type: AlertType::CredentialAccess,
            severity: Severity::Critical,
            title: "Canary Self-test".into(),
            detail: "Deliberate synthetic probe".into(),
            hostname: "synthetic-host".into(),
            timestamp: proof_time(1).to_rfc3339(),
            source: Some("placement".into()),
            actor: None,
        }
    }

    fn proof_status(
        outbox: &Outbox,
        expectation: &SelftestDeliveryExpectation,
        cfg: &config::AlertConfig,
    ) -> Result<SelftestDeliveryStatus, String> {
        selftest_delivery_status_in(
            outbox,
            PROOF_EVENT_ID,
            expectation,
            cfg,
            proof_time(0),
            || proof_time(10),
        )
    }

    fn proof_receipts(outbox: &Outbox, receipts: &BTreeMap<String, String>) {
        outbox
            .0
            .execute(
                "UPDATE outbox SET receipts=?1 WHERE id=?2",
                params![serde_json::to_string(receipts).unwrap(), PROOF_EVENT_ID],
            )
            .unwrap();
    }

    #[test]
    fn selftest_delivery_pins_enabled_channels_and_the_complete_configuration() {
        assert!(SelftestDeliveryExpectation::from_config(&config::AlertConfig::default()).is_err());
        let cfg = delivery_config();
        let expectation = SelftestDeliveryExpectation::from_config(&cfg).unwrap();
        assert_eq!(expectation.channel_count(), 1);
        expectation.verify_config(&cfg).unwrap();
        let mut changed = cfg.clone();
        changed.enabled = false;
        assert!(expectation.verify_config(&changed).is_err());
        changed = cfg.clone();
        changed.webhook = None;
        assert!(expectation.verify_config(&changed).is_err());
        changed = cfg.clone();
        changed.webhook.as_mut().unwrap().url = "https://other.invalid".into();
        assert!(expectation.verify_config(&changed).is_err());
        changed = cfg.clone();
        changed.webhook.as_mut().unwrap().auth_header = Some("secret-new-token".into());
        let error = expectation.verify_config(&changed).unwrap_err();
        assert!(!error.contains("secret-new-token"));
        changed = cfg.clone();
        changed.min_severity = "critical".into();
        assert!(expectation.verify_config(&changed).is_err());
        changed = cfg.clone();
        changed.telegram = Some(config::TelegramConfig {
            bot_token: "unused-secret".into(),
            chat_id: "unused-recipient".into(),
        });
        assert!(expectation.verify_config(&changed).is_err());
    }

    #[test]
    fn selftest_delivery_requires_every_pinned_receipt_for_the_exact_event() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        let mut cfg = delivery_config();
        cfg.telegram = Some(config::TelegramConfig {
            bot_token: "synthetic-token".into(),
            chat_id: "synthetic-recipient".into(),
        });
        let expectation = SelftestDeliveryExpectation::from_config(&cfg).unwrap();
        let mut unrelated = proof_alert();
        unrelated.event_id = "canary:other:placement:token".into();
        outbox.enqueue(&unrelated).unwrap();
        outbox
            .0
            .execute("UPDATE outbox SET complete=1", [])
            .unwrap();
        assert_eq!(
            proof_status(&outbox, &expectation, &cfg).unwrap(),
            SelftestDeliveryStatus::Missing
        );
        outbox.enqueue(&proof_alert()).unwrap();
        assert_eq!(
            proof_status(&outbox, &expectation, &cfg).unwrap(),
            SelftestDeliveryStatus::Pending {
                accepted: 0,
                total: 2
            }
        );
        let mut receipts = BTreeMap::from([
            (
                receipt_key("Telegram", &cfg).unwrap(),
                proof_time(2).to_rfc3339(),
            ),
            ("Webhook:wrong-recipient".into(), proof_time(2).to_rfc3339()),
        ]);
        proof_receipts(&outbox, &receipts);
        // A completion flag alone cannot substitute for the actual receipts.
        outbox
            .0
            .execute("UPDATE outbox SET complete=1", [])
            .unwrap();
        assert_eq!(
            proof_status(&outbox, &expectation, &cfg).unwrap(),
            SelftestDeliveryStatus::Pending {
                accepted: 1,
                total: 2
            }
        );
        receipts.insert(
            receipt_key("Webhook", &cfg).unwrap(),
            proof_time(3).to_rfc3339(),
        );
        proof_receipts(&outbox, &receipts);
        assert_eq!(
            proof_status(&outbox, &expectation, &cfg).unwrap(),
            SelftestDeliveryStatus::Accepted { channels: 2 }
        );
        let mut changed = cfg.clone();
        changed.telegram.as_mut().unwrap().chat_id = "another-recipient".into();
        assert!(proof_status(&outbox, &expectation, &changed).is_err());
    }

    #[test]
    fn selftest_delivery_rejects_wrong_payload_identity_type_source_and_test_marker() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        let cfg = delivery_config();
        let expectation = SelftestDeliveryExpectation::from_config(&cfg).unwrap();
        outbox.enqueue(&proof_alert()).unwrap();
        let mut variants = Vec::new();
        let mut alert = proof_alert();
        alert.event_id = "canary:wrong:placement:token".into();
        variants.push(alert);
        alert = proof_alert();
        alert.alert_type = AlertType::Watchdog;
        variants.push(alert);
        alert = proof_alert();
        alert.severity = Severity::Info;
        variants.push(alert);
        alert = proof_alert();
        alert.source = Some("other-placement".into());
        variants.push(alert);
        alert = proof_alert();
        alert.title = "Registered Decoy Opened".into();
        variants.push(alert);
        for alert in variants {
            outbox
                .0
                .execute(
                    "UPDATE outbox SET alert=?1 WHERE id=?2",
                    params![serde_json::to_string(&alert).unwrap(), PROOF_EVENT_ID],
                )
                .unwrap();
            assert!(proof_status(&outbox, &expectation, &cfg).is_err());
        }
        for id in [
            "",
            "unrelated-event",
            "canary:sensor:token",
            "canary::placement:token",
            "canary:sensor:placement:bad/token",
        ] {
            assert!(selftest_delivery_status_in(
                &outbox,
                id,
                &expectation,
                &cfg,
                proof_time(0),
                || proof_time(10)
            )
            .is_err());
        }
    }

    #[test]
    fn selftest_delivery_rejects_stale_future_and_malformed_timestamps() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        let cfg = delivery_config();
        let expectation = SelftestDeliveryExpectation::from_config(&cfg).unwrap();
        outbox.enqueue(&proof_alert()).unwrap();
        for timestamp in [
            proof_time(-1).to_rfc3339(),
            proof_time(0).to_rfc3339(),
            proof_time(11).to_rfc3339(),
            "invalid".into(),
        ] {
            let mut alert = proof_alert();
            alert.timestamp = timestamp;
            outbox
                .0
                .execute(
                    "UPDATE outbox SET alert=?1 WHERE id=?2",
                    params![serde_json::to_string(&alert).unwrap(), PROOF_EVENT_ID],
                )
                .unwrap();
            assert!(proof_status(&outbox, &expectation, &cfg).is_err());
        }
        outbox
            .0
            .execute(
                "UPDATE outbox SET alert=?1 WHERE id=?2",
                params![
                    serde_json::to_string(&proof_alert()).unwrap(),
                    PROOF_EVENT_ID
                ],
            )
            .unwrap();
        for timestamp in [
            proof_time(-1).to_rfc3339(),
            proof_time(0).to_rfc3339(),
            (proof_time(1) - chrono::Duration::milliseconds(1)).to_rfc3339(),
            proof_time(11).to_rfc3339(),
            "invalid".into(),
        ] {
            proof_receipts(
                &outbox,
                &BTreeMap::from([(receipt_key("Webhook", &cfg).unwrap(), timestamp)]),
            );
            assert!(proof_status(&outbox, &expectation, &cfg).is_err());
        }
    }

    #[test]
    fn selftest_delivery_observation_preserves_pending_and_quarantined_events() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        let cfg = delivery_config();
        let expectation = SelftestDeliveryExpectation::from_config(&cfg).unwrap();
        outbox.enqueue(&proof_alert()).unwrap();
        outbox
            .0
            .execute(
                "UPDATE outbox SET attempts=9,lease='another-worker',next_attempt=999999",
                [],
            )
            .unwrap();
        let snapshot = |outbox: &Outbox| -> (String, String, i64, String, i64, i64) {
            outbox.0.query_row("SELECT alert,receipts,attempts,lease,next_attempt,complete FROM outbox WHERE id=?1", [PROOF_EVENT_ID], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).unwrap()
        };
        let pending_before = snapshot(&outbox);
        let reader = selftest_read_only_outbox(&fixture.path).unwrap().unwrap();
        assert_eq!(
            proof_status(&reader, &expectation, &cfg).unwrap(),
            SelftestDeliveryStatus::Pending {
                accepted: 0,
                total: 1
            }
        );
        assert_eq!(snapshot(&outbox), pending_before);
        assert!(reader.0.execute("DELETE FROM outbox", []).is_err());
        outbox
            .0
            .execute("UPDATE outbox SET complete=-1", [])
            .unwrap();
        proof_receipts(
            &outbox,
            &BTreeMap::from([(
                receipt_key("Webhook", &cfg).unwrap(),
                proof_time(2).to_rfc3339(),
            )]),
        );
        let quarantined_before = snapshot(&outbox);
        assert!(proof_status(&reader, &expectation, &cfg)
            .unwrap_err()
            .contains("quarantined"));
        assert_eq!(snapshot(&outbox), quarantined_before);
    }

    #[test]
    fn selftest_delivery_missing_outbox_is_not_created() {
        let fixture = TestOutbox::new();
        assert!(selftest_read_only_outbox(&fixture.path).unwrap().is_none());
        assert!(!fixture.path.parent().unwrap().exists());
    }

    #[test]
    fn selftest_delivery_corrupt_receipts_and_invalid_state_cannot_pass() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        let cfg = delivery_config();
        let expectation = SelftestDeliveryExpectation::from_config(&cfg).unwrap();
        outbox.enqueue(&proof_alert()).unwrap();
        outbox
            .0
            .execute("UPDATE outbox SET receipts='broken'", [])
            .unwrap();
        assert!(proof_status(&outbox, &expectation, &cfg).is_err());
        outbox
            .0
            .execute("UPDATE outbox SET receipts='{}',complete=2", [])
            .unwrap();
        assert!(proof_status(&outbox, &expectation, &cfg).is_err());
    }

    #[test]
    fn heartbeat_sequences_commit_before_transport_and_survive_restart() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        assert!(reserve_heartbeat(&mut outbox).unwrap().is_none());
        outbox
            .0
            .execute(
                "INSERT INTO heartbeat_config(id,url,monitor_id,token) VALUES(1,?1,?2,?3)",
                params![
                    "https://monitor.example/heartbeat",
                    "a".repeat(32),
                    "b".repeat(64)
                ],
            )
            .unwrap();
        assert_eq!(reserve_heartbeat(&mut outbox).unwrap().unwrap().1, 1);
        // No delivery occurred. A new process must still advance, not replay 1.
        drop(outbox);
        let mut restarted = Outbox::open(&fixture.path).unwrap();
        assert_eq!(reserve_heartbeat(&mut restarted).unwrap().unwrap().1, 2);
        restarted
            .0
            .execute("UPDATE heartbeat_config SET sequence=9007199254740991", [])
            .unwrap();
        assert!(reserve_heartbeat(&mut restarted).is_err());
        restarted
            .0
            .execute("UPDATE heartbeat_config SET sequence=-1", [])
            .unwrap();
        assert!(reserve_heartbeat(&mut restarted).is_err());
    }

    #[test]
    fn concurrent_heartbeat_reservations_are_unique() {
        let fixture = TestOutbox::new();
        let outbox = Outbox::open(&fixture.path).unwrap();
        outbox
            .0
            .execute(
                "INSERT INTO heartbeat_config(id,url,monitor_id,token) VALUES(1,?1,?2,?3)",
                params![
                    "https://monitor.example/heartbeat",
                    "a".repeat(32),
                    "b".repeat(64)
                ],
            )
            .unwrap();
        drop(outbox);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let path = fixture.path.clone();
                std::thread::spawn(move || {
                    reserve_heartbeat(&mut Outbox::open(&path).unwrap())
                        .unwrap()
                        .unwrap()
                        .1
                })
            })
            .collect();
        let mut sequences: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        sequences.sort();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
    }

    #[test]
    fn heartbeat_enrollment_restricts_payload_and_transport() {
        let mut enrollment = HeartbeatEnrollment {
            url: "https://monitor.example/heartbeat".into(),
            monitor_id: "a".repeat(32),
            token: "b".repeat(64),
        };
        assert!(validate_heartbeat_enrollment(&enrollment).is_ok());
        for url in [
            "http://127.0.0.1:1234/heartbeat",
            "http://[::1]:1234/heartbeat",
        ] {
            enrollment.url = url.into();
            assert!(validate_heartbeat_enrollment(&enrollment).is_ok());
        }
        for url in [
            "http://monitor.example/heartbeat",
            "http://localhost:1234/heartbeat",
            "https://user:password@monitor.example/heartbeat",
            "https://monitor.example/heartbeat?secret=value",
            "https://monitor.example/path/heartbeat",
            "https://monitor.example/#/heartbeat",
            "https://monitor.example\\evil/heartbeat",
        ] {
            enrollment.url = url.into();
            assert!(validate_heartbeat_enrollment(&enrollment).is_err(), "{url}");
        }
        enrollment.url = "https://monitor.example/heartbeat".into();
        enrollment.token = "secret-command-output".into();
        assert!(validate_heartbeat_enrollment(&enrollment).is_err());
        let arbitrary = serde_json::json!({"url":"https://monitor.example/heartbeat","monitor_id":"a".repeat(32),"token":"b".repeat(64),"command":"private data"});
        assert!(serde_json::from_value::<HeartbeatEnrollment>(arbitrary).is_err());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_from_str_valid() {
        assert_eq!(Severity::from_str("info"), Severity::Info);
        assert_eq!(Severity::from_str("MEDIUM"), Severity::Medium);
        assert_eq!(Severity::from_str("High"), Severity::High);
        assert_eq!(Severity::from_str("critical"), Severity::Critical);
    }

    #[test]
    fn severity_from_str_default() {
        assert_eq!(Severity::from_str("unknown"), Severity::Medium);
        assert_eq!(Severity::from_str(""), Severity::Medium);
    }

    #[test]
    fn url_encode_passthrough() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("abc123"), "abc123");
    }

    #[test]
    fn url_encode_special_chars() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("+1 555"), "%2B1%20555");
        assert_eq!(url_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn alert_format_text() {
        let alert = SecurityAlert {
            event_id: "synthetic-1".into(),
            alert_type: AlertType::Watchdog,
            severity: Severity::Info,
            title: "Test".into(),
            detail: "Detail".into(),
            hostname: "testhost".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            source: None,
            actor: None,
        };
        let text = alert.format_text();
        assert!(text.contains("Test"));
        assert!(text.contains("Detail"));
        assert!(text.contains("testhost"));
    }

    #[test]
    fn alert_format_json() {
        let alert = SecurityAlert {
            event_id: "synthetic-2".into(),
            alert_type: AlertType::CredentialAccess,
            severity: Severity::Critical,
            title: "Cred Access".into(),
            detail: "Someone read .env".into(),
            hostname: "srv1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            source: Some("/app/.env".into()),
            actor: Some("node".into()),
        };
        let json = alert.format_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["alert_type"], "Credential Access");
        assert_eq!(v["severity"], "CRITICAL");
        assert_eq!(v["product"], "Gorse");
    }

    #[test]
    fn queue_survives_reopen_and_deduplicates_only_identical_event_ids() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("first")).unwrap();
        outbox.enqueue(&synthetic("first")).unwrap();
        outbox.enqueue(&synthetic("second")).unwrap();
        drop(outbox);
        let mut reopened = Outbox::open(&fixture.path).unwrap();
        let count: i64 = reopened
            .0
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
        let mut ids = Vec::new();
        for _ in 0..2 {
            assert_eq!(
                deliver_one(&mut reopened, &delivery_config(), 1_000, |_, a| {
                    ids.push(a.event_id.clone());
                    Ok(())
                })
                .unwrap(),
                Some(true)
            );
        }
        ids.sort();
        assert_eq!(ids, ["first", "second"]);
        assert_eq!(
            deliver_one(&mut reopened, &delivery_config(), 2_000, |_, _| panic!(
                "already accepted"
            ))
            .unwrap(),
            None
        );
    }

    #[test]
    fn failed_delivery_retries_original_id_without_resending_accepted_channel() {
        let fixture = TestOutbox::new();
        let mut cfg = delivery_config();
        cfg.telegram = Some(config::TelegramConfig {
            bot_token: "synthetic".into(),
            chat_id: "synthetic".into(),
        });
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("retry")).unwrap();
        let mut calls = Vec::new();
        assert_eq!(
            deliver_one(&mut outbox, &cfg, 1_000, |channel, _| {
                calls.push(channel.to_string());
                if channel == "Webhook" {
                    Err("synthetic secret URL that must not be stored".into())
                } else {
                    Ok(())
                }
            })
            .unwrap(),
            Some(false)
        );
        assert_eq!(calls, ["Telegram", "Webhook"]);
        let error: String = outbox
            .0
            .query_row("SELECT last_error FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert!(!error.contains("secret URL"));
        drop(outbox);
        let mut reopened = Outbox::open(&fixture.path).unwrap();
        assert_eq!(
            deliver_one(&mut reopened, &cfg, 1_001, |_, _| panic!("retry too early")).unwrap(),
            None
        );
        assert_eq!(
            deliver_one(&mut reopened, &cfg, 4_000, |channel, a| {
                assert_eq!(channel, "Webhook");
                assert_eq!(a.event_id, "retry");
                Ok(())
            })
            .unwrap(),
            Some(true)
        );
    }

    #[test]
    fn abandoned_worker_lease_is_recoverable_and_stale_worker_cannot_complete() {
        let fixture = TestOutbox::new();
        let mut first = Outbox::open(&fixture.path).unwrap();
        first.enqueue(&synthetic("lease")).unwrap();
        let abandoned = first.claim(1_000).unwrap().unwrap();
        let mut other = Outbox::open(&fixture.path).unwrap();
        assert!(other.claim(1_001).unwrap().is_none());
        let recovered = other.claim(61_001).unwrap().unwrap();
        assert_eq!(recovered.alert.event_id, abandoned.alert.event_id);
        assert!(first.checkpoint(&abandoned, true, None, 61_002).is_err());
        other.checkpoint(&recovered, true, None, 61_003).unwrap();
    }

    #[test]
    fn changed_recipient_does_not_inherit_another_recipients_receipt() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("route-change")).unwrap();
        let mut cfg = delivery_config();
        cfg.telegram = Some(config::TelegramConfig {
            bot_token: "secret-token".into(),
            chat_id: "old".into(),
        });
        assert!(!receipt_key("Telegram", &cfg)
            .unwrap()
            .contains("secret-token"));
        deliver_one(&mut outbox, &cfg, 1_000, |channel, _| {
            if channel == "Telegram" {
                Ok(())
            } else {
                Err("offline".into())
            }
        })
        .unwrap();
        cfg.telegram.as_mut().unwrap().chat_id = "new".into();
        let mut retried = Vec::new();
        assert_eq!(
            deliver_one(&mut outbox, &cfg, 4_000, |channel, _| {
                retried.push(channel.to_string());
                Ok(())
            })
            .unwrap(),
            Some(true)
        );
        assert_eq!(retried, ["Telegram", "Webhook"]);
    }

    #[test]
    fn corrupt_record_is_retained_for_repair_without_wedging_later_events() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("corrupt")).unwrap();
        outbox
            .0
            .execute(
                "UPDATE outbox SET alert='broken',updated=0 WHERE id='corrupt'",
                [],
            )
            .unwrap();
        outbox.enqueue(&synthetic("healthy")).unwrap();
        assert!(deliver_one(&mut outbox, &delivery_config(), 1_000, |_, _| panic!()).is_err());
        assert_eq!(
            deliver_one(&mut outbox, &delivery_config(), 1_000, |_, a| {
                assert_eq!(a.event_id, "healthy");
                Ok(())
            })
            .unwrap(),
            Some(true)
        );
        assert!(outbox_status_lines(&fixture.path)
            .join("\n")
            .contains("1 quarantined"));
        let raw: String = outbox
            .0
            .query_row("SELECT alert FROM outbox WHERE id='corrupt'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(raw, "broken");
    }

    #[test]
    fn accepted_event_retention_never_discards_pending_alarms() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("keep-pending")).unwrap();
        let tx = outbox.0.transaction().unwrap();
        for i in 0..10_005 {
            tx.execute(
                "INSERT INTO outbox(id,alert,complete,updated) VALUES (?1,'{}',1,?2)",
                params![format!("old-{i}"), i],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        outbox.enqueue(&synthetic("new-pending")).unwrap();
        let counts: (i64, i64) = outbox
            .0
            .query_row(
                "SELECT SUM(complete=0),SUM(complete=1) FROM outbox",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(counts, (2, 10_000));
    }

    #[test]
    fn disabled_or_severity_filtered_events_remain_visible_and_pending() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("filtered")).unwrap();
        let mut cfg = delivery_config();
        cfg.enabled = false;
        assert_eq!(
            deliver_one(&mut outbox, &cfg, 1_000, |_, _| panic!("disabled")).unwrap(),
            None
        );
        cfg.enabled = true;
        cfg.min_severity = "critical".into();
        assert_eq!(
            deliver_one(&mut outbox, &cfg, 1_000, |_, _| panic!("below severity")).unwrap(),
            Some(false)
        );
        let status = outbox_status_lines(&fixture.path).join("\n");
        assert!(status.contains("1 pending"));
        assert!(status.contains("absent or stale"));
    }

    #[test]
    fn persistence_failure_does_not_report_success_or_erase_existing_events() {
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        outbox.enqueue(&synthetic("existing")).unwrap();
        outbox.0.execute_batch("PRAGMA query_only=ON").unwrap();
        assert!(outbox.enqueue(&synthetic("cannot-write")).is_err());
        drop(outbox);
        let reopened = Outbox::open(&fixture.path).unwrap();
        let count: i64 = reopened
            .0
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn outbox_rejects_symlinks_and_is_private() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = TestOutbox::new();
        let outbox = Outbox::open(&fixture.path).unwrap();
        drop(outbox);
        assert_eq!(
            std::fs::metadata(&fixture.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let target = fixture.path.with_extension("sentinel");
        std::fs::rename(&fixture.path, &target).unwrap();
        let before = std::fs::read(&target).unwrap();
        symlink(&target, &fixture.path).unwrap();
        assert!(Outbox::open(&fixture.path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), before);
    }

    #[test]
    fn webhook_rejects_plaintext_remote_destinations_before_sending() {
        for url in [
            "http://example.invalid/",
            "http://127.0.0.1.example.invalid:80/",
            "http://127.0.0.1@evil.invalid:80/",
        ] {
            assert!(send_webhook(
                &config::AlertWebhookConfig {
                    url: url.into(),
                    auth_header: None
                },
                &synthetic("http")
            )
            .unwrap_err()
            .contains("requires HTTPS"));
        }
    }

    #[test]
    fn secret_access_journal_survives_outbox_restart_and_requires_exact_remote_ack() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/alarms", listener.local_addr().unwrap());
        // The synthetic receiver never panics on I/O: every failure is returned
        // through the join handle so the test reports what went wrong instead
        // of a bare unwrap inside a detached thread.
        let receiver = std::thread::spawn(move || -> Result<Vec<String>, String> {
            let io = |step: &str, e: std::io::Error| format!("receiver {step} failed: {e}");
            let mut ids = Vec::new();
            for attempt in 0..2 {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(e) => return Err(io("accept", e)),
                    }
                };
                // BSD-derived kernels (macOS included) hand accepted sockets the
                // listener's O_NONBLOCK, so a read before the request lands
                // would fail with WouldBlock instead of waiting. Make the
                // connection blocking with timeouts well above the client's 5s.
                stream
                    .set_nonblocking(false)
                    .map_err(|e| io("set_blocking", e))?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .map_err(|e| io("set_read_timeout", e))?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(20)))
                    .map_err(|e| io("set_write_timeout", e))?;
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 2048];
                let (body_start, length) = loop {
                    let count = match stream.read(&mut buffer) {
                        Ok(0) => return Err("client closed before sending headers".into()),
                        Ok(count) => count,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(io("header read", e)),
                    };
                    bytes.extend_from_slice(&buffer[..count]);
                    if bytes.len() >= 64 * 1024 {
                        return Err("request headers exceed 64 KiB".into());
                    }
                    if let Some(position) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        let header = String::from_utf8(bytes[..position].to_vec())
                            .map_err(|_| "request headers are not UTF-8".to_string())?;
                        let length = header
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .ok_or_else(|| "request lacks Content-Length".to_string())?;
                        break (position + 4, length);
                    }
                };
                if length >= 32 * 1024 {
                    return Err("request body exceeds 32 KiB".into());
                }
                while bytes.len() < body_start + length {
                    match stream.read(&mut buffer) {
                        Ok(0) => return Err("client closed before sending the body".into()),
                        Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(io("body read", e)),
                    }
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&bytes[body_start..body_start + length])
                        .map_err(|e| format!("request body is not JSON: {e}"))?;
                let text = body.to_string();
                if text.contains("SYNTHETIC-PRIVATE-PATH") || text.contains("UNTRUSTED-SIGNER") {
                    return Err("alarm leaked private path or signer".into());
                }
                if body["title"] != "Unapproved Secret Access" {
                    return Err(format!("unexpected alarm title {}", body["title"]));
                }
                let id = body["event_id"]
                    .as_str()
                    .ok_or_else(|| "alarm lacks event_id".to_string())?
                    .to_string();
                ids.push(id.clone());
                let response = if attempt == 0 {
                    "<html>Login required</html>".to_string()
                } else {
                    serde_json::json!({"accepted":true,"event_id":id}).to_string()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .and_then(|_| stream.flush())
                .map_err(|e| io("response write", e))?;
            }
            Ok(ids)
        });
        let mut cfg = delivery_config();
        cfg.webhook.as_mut().unwrap().url = url;
        let fixture = TestOutbox::new();
        let mut outbox = Outbox::open(&fixture.path).unwrap();
        let event = |sequence, decision| {
            serde_json::json!({"schema":1,"stream":"secret-fixture","sequence":sequence,
            "timestamp":chrono::Utc::now().to_rfc3339(),"event":"secret_open","policy_revision":"a".repeat(32),
            "owner_uid":501,"secret_id":"b".repeat(32),"device":1,"inode":2,"pid":123,"reader_uid":501,
            "executable":"/SYNTHETIC-PRIVATE-PATH/program","audit_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "reader":{"cdhash":"c".repeat(40),"signing_id":"UNTRUSTED-SIGNER","team_id":"TEAM","platform_binary":false},
            "decision":decision,"coverage_issues":[]})
        };
        let journal = format!("{}\n{}\n", event(1, "approved"), event(2, "unapproved"));
        for _ in 0..2 {
            crate::canary_watcher::secret_access::fixture_alarms(
                journal.as_bytes(),
                501,
                |alert| outbox.enqueue(&alert),
            )
            .unwrap();
        }
        let count: i64 = outbox
            .0
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count, 1,
            "approved reads and replay must not create extra alarms"
        );
        drop(outbox);
        let mut reopened = Outbox::open(&fixture.path).unwrap();
        assert_eq!(
            deliver_one(&mut reopened, &cfg, 1000, |_, alert| send_webhook(
                cfg.webhook.as_ref().unwrap(),
                alert
            ))
            .unwrap(),
            Some(false)
        );
        drop(reopened);
        let mut reopened = Outbox::open(&fixture.path).unwrap();
        assert_eq!(
            deliver_one(&mut reopened, &cfg, 4000, |_, alert| send_webhook(
                cfg.webhook.as_ref().unwrap(),
                alert
            ))
            .unwrap(),
            Some(true)
        );
        assert_eq!(
            deliver_one(&mut reopened, &cfg, 8000, |_, _| panic!(
                "already delivered"
            ))
            .unwrap(),
            None
        );
        let ids = receiver.join().expect("receiver thread panicked").unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], ids[1]);
    }

    struct TestOutbox {
        path: PathBuf,
    }
    impl TestOutbox {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("hedgehog-outbox-test-{}", event_id()));
            Self {
                path: dir.join("queue.sqlite3"),
            }
        }
    }
    impl Drop for TestOutbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
        }
    }
    fn synthetic(id: &str) -> SecurityAlert {
        SecurityAlert {
            event_id: id.into(),
            alert_type: AlertType::CredentialAccess,
            severity: Severity::High,
            title: "Synthetic event".into(),
            detail: "No real credentials".into(),
            hostname: "synthetic-host".into(),
            timestamp: "2026-09-05T00:00:00Z".into(),
            source: None,
            actor: None,
        }
    }
    fn delivery_config() -> config::AlertConfig {
        config::AlertConfig {
            enabled: true,
            webhook: Some(config::AlertWebhookConfig {
                url: "https://unused.invalid".into(),
                auth_header: None,
            }),
            ..Default::default()
        }
    }
}
