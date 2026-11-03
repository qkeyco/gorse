// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Consume the entitled macOS extension's canary-open journal.
//!
//! Access times and post-event `lsof` lookups cannot reliably identify short
//! lived readers. The extension records the vnode and process audit identity
//! at NOTIFY_OPEN time. This observes read-capable opens of reserved canary
//! paths; it does not establish that bytes were read or prevent exfiltration.

use crate::canary;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SENSOR_DIRECTORY: &str = "/Library/Application Support/Hedgehog";
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024 + 32 * 1024;
const POLL_INTERVAL_SECS: u64 = 2;
const SCOPE_DESCRIPTION: &str = "Canary scope: read-capable opens of registered reserved canary paths; this does not prove exfiltration prevention or alarm delivery.";
const HEALTH_ISSUES: &[&str] = &[
    "sensor_not_verified",
    "registry_unavailable",
    "registry_missing_after_registration",
    "sensor_unavailable_or_untrusted",
    "journal_or_alarm_persistence_failed",
    "journal_unavailable_or_untrusted",
    "journal_behind_sensor",
    "cursor_persistence_failed",
    "event_coverage_gap",
    "placement_requires_redeployment",
    "placement_missing_or_unreadable",
    "placement_replaced",
    "placement_has_unmonitored_aliases",
    "sensor_schema_unsupported",
    "sensor_not_active",
    "sensor_dropped_events",
    "sensor_heartbeat_stale",
    "sensor_heartbeat_invalid",
];

#[derive(Debug, Clone)]
struct Placement {
    token_id: String,
    is_selftest: bool,
    id: String,
    path: PathBuf,
    identity: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OpenEvent {
    schema: u32,
    stream: String,
    sequence: u64,
    timestamp: String,
    event: String,
    path: String,
    device: u64,
    inode: u64,
    pid: u32,
    executable: String,
    audit_token: String,
}

#[derive(Debug, Deserialize)]
struct SensorStatus {
    updated: String,
    canary_sensor: String,
    canary_schema: u32,
    canary_stream: String,
    canary_sequence: u64,
    canary_dropped: u64,
    canary_scope: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Cursor {
    streams: BTreeMap<String, u64>,
    #[serde(default)]
    registry_expected: bool,
    /// Once retention or parsing loses events, don't erase that evidence on
    /// the next healthy heartbeat. Reset requires an explicit fresh baseline.
    coverage_gap: bool,
}

#[derive(Debug, Serialize)]
struct Health {
    updated: String,
    state: &'static str,
    issues: Vec<&'static str>,
    registered_files: usize,
    scope: &'static str,
}

#[derive(Debug, Deserialize)]
struct HealthReport {
    updated: String,
    state: String,
    issues: Vec<String>,
    registered_files: u64,
    scope: String,
}

/// The last local monitor report is evidence only for the stated scope and
/// freshness window. Outbox availability is deliberately not used here.
pub fn status_lines() -> Vec<String> {
    status_lines_at(
        &crate::config::config_dir().join("canary-monitor-status.json"),
        chrono::Utc::now(),
    )
}

/// Readiness only: a local report cannot prove a sensor observation or remote
/// receipt. An idle monitor can accept the first self-test registration.
pub fn selftest_monitor_ready() -> Result<(), String> {
    let bytes = read_private(
        &crate::config::config_dir().join("canary-monitor-status.json"),
        64 * 1024,
    )
    .map_err(|_| "Canary monitor report is unavailable or unsafe to read")?;
    selftest_monitor_ready_at(&bytes, chrono::Utc::now())
}

fn selftest_monitor_ready_at(
    bytes: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let (report, updated) = validated_health(bytes).ok_or("Invalid canary monitor report")?;
    if !["active", "idle"].contains(&report.state.as_str())
        || !report.issues.is_empty()
        || !(-5_000..=120_000).contains(&now.signed_duration_since(updated).num_milliseconds())
    {
        return Err("Canary monitor is not ready or its report is stale".into());
    }
    Ok(())
}

/// Only an entitled sensor's trusted status can establish this checkpoint.
/// Its contents are opaque so callers cannot manufacture a production baseline.
pub struct SelftestSensorBaseline {
    stream: String,
    sequence: u64,
    captured_at: chrono::DateTime<chrono::Utc>,
}

pub fn selftest_sensor_baseline() -> Result<SelftestSensorBaseline, String> {
    #[cfg(target_os = "macos")]
    {
        let now = chrono::Utc::now();
        let status = selftest_trusted_status(now)?;
        Ok(SelftestSensorBaseline {
            stream: status.canary_stream,
            sequence: status.canary_sequence,
            captured_at: now,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Installed canary sensor self-test is available only on macOS".into())
    }
}

fn valid_sensor_stream(stream: &str) -> bool {
    !stream.is_empty()
        && stream.len() <= 64
        && stream
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn selftest_validated_status(
    bytes: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SensorStatus, String> {
    let status: SensorStatus =
        serde_json::from_slice(bytes).map_err(|_| "Invalid installed sensor status")?;
    let issues = sensor_issues(&status, now);
    if !issues.is_empty() || !valid_sensor_stream(&status.canary_stream) {
        return Err(format!(
            "Installed canary sensor is not verified healthy: {}",
            if issues.is_empty() {
                "invalid sensor stream".into()
            } else {
                issues.join(", ")
            }
        ));
    }
    Ok(status)
}

#[cfg(target_os = "macos")]
fn selftest_trusted_status(now: chrono::DateTime<chrono::Utc>) -> Result<SensorStatus, String> {
    let bytes = read_trusted(&Path::new(SENSOR_DIRECTORY).join("status.json"), 64 * 1024)
        .map_err(|_| "Installed sensor status is unavailable or untrusted")?;
    selftest_validated_status(&bytes, now)
}

/// Return the exact new event identity from root-owned sensor journals. This
/// does not consult the user-writable monitor history or alert outbox.
pub fn selftest_sensor_event(
    baseline: &SelftestSensorBaseline,
    placement: &canary::CanaryPlacement,
    pid: u32,
    started: chrono::DateTime<chrono::Utc>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let before = selftest_trusted_status(chrono::Utc::now())?;
        let mut journals = Vec::new();
        for name in ["canary-events.jsonl.previous", "canary-events.jsonl"] {
            match read_trusted(&Path::new(SENSOR_DIRECTORY).join(name), MAX_JOURNAL_BYTES) {
                Ok(bytes) => journals.push(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("Installed sensor journal is unavailable or untrusted".into()),
            }
        }
        let now = chrono::Utc::now();
        let after = selftest_trusted_status(now)?;
        selftest_event_in_journals(
            baseline, placement, pid, started, now, &before, &after, &journals,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (baseline, placement, pid, started);
        Err("Installed canary sensor self-test is available only on macOS".into())
    }
}

#[allow(clippy::too_many_arguments)]
fn selftest_event_in_journals(
    baseline: &SelftestSensorBaseline,
    placement: &canary::CanaryPlacement,
    pid: u32,
    started: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    before: &SensorStatus,
    after: &SensorStatus,
    journals: &[Vec<u8>],
) -> Result<Option<String>, String> {
    if pid == 0
        // The entitled journal serializes timestamps to milliseconds. Keep
        // the same boundary for a trigger captured in the baseline's last
        // submillisecond, while still requiring a new event sequence.
        || started.timestamp_millis() < baseline.captured_at.timestamp_millis()
        || started > now
        || placement.identity.is_none()
        || !posix_absolute(&placement.path)
        || !reserved_path(Path::new(&placement.path))
    {
        return Err("Invalid self-test trigger identity or time".into());
    }
    for status in [before, after] {
        if !sensor_issues(status, now).is_empty()
            || status.canary_stream != baseline.stream
            || !valid_sensor_stream(&status.canary_stream)
            || status.canary_sequence < baseline.sequence
        {
            return Err("Sensor restarted, lost coverage, or is no longer verified healthy".into());
        }
    }
    if after.canary_sequence < before.canary_sequence {
        return Err("Sensor sequence moved backwards during self-test".into());
    }
    let mut events = BTreeMap::<u64, OpenEvent>::new();
    for bytes in journals {
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err("Installed sensor journal exceeds the evidence limit".into());
        }
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if line.len() > 32 * 1024 {
                return Err("Oversized installed sensor event".into());
            }
            // A concurrent append may leave an unfinished tail. It cannot
            // establish evidence until a later poll sees the complete line.
            if line.last() != Some(&b'\n') {
                break;
            }
            let event: OpenEvent =
                serde_json::from_slice(line).map_err(|_| "Malformed installed sensor event")?;
            use base64::Engine;
            let audit = base64::engine::general_purpose::STANDARD
                .decode(&event.audit_token)
                .map_err(|_| "Malformed installed sensor audit identity")?;
            if event.schema != 1
                || event.event != "canary_open"
                || event.sequence == 0
                || !valid_sensor_stream(&event.stream)
                || chrono::DateTime::parse_from_rfc3339(&event.timestamp).is_err()
                || !posix_absolute(&event.path)
                || !reserved_path(Path::new(&event.path))
                || !posix_absolute(&event.executable)
                || event.pid == 0
                || audit.len() != 32
                || u32::from_le_bytes(audit[20..24].try_into().unwrap()) != event.pid
            {
                return Err("Invalid installed sensor event identity or schema".into());
            }
            if event.stream == baseline.stream && event.sequence > baseline.sequence {
                if let Some(previous) = events.insert(event.sequence, event.clone()) {
                    if serde_json::to_vec(&previous).map_err(|e| e.to_string())?
                        != serde_json::to_vec(&event).map_err(|e| e.to_string())?
                    {
                        return Err("Conflicting installed sensor event identities".into());
                    }
                }
            }
        }
    }
    let mut consumed = baseline.sequence;
    let mut found = None;
    for event in events.values() {
        if consumed.checked_add(1) != Some(event.sequence) {
            return Err("Installed sensor journal lost events after the self-test baseline".into());
        }
        consumed = event.sequence;
        let timestamp = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .map_err(|_| "Invalid installed sensor event timestamp")?;
        let identity = placement.identity.as_ref().unwrap();
        if event.pid == pid
            && event.path == placement.path
            && event.device == identity.device
            && event.inode == identity.inode
            && timestamp >= started
            && timestamp <= now
            && found.is_none()
        {
            found = Some(format!("{}:{}", event.stream, event.sequence));
        }
    }
    if consumed < before.canary_sequence {
        return Err("Installed sensor journal does not cover its advertised event sequence".into());
    }
    if consumed < after.canary_sequence {
        // A later event may have been appended after our journal snapshot.
        // Re-read before reporting success so newly reported gaps cannot hide.
        return Ok(None);
    }
    Ok(found)
}

fn status_lines_at(path: &Path, now: chrono::DateTime<chrono::Utc>) -> Vec<String> {
    let bytes = match read_private(path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return vec![
                "Canary monitor: unverified (no local sensor report)".into(),
                SCOPE_DESCRIPTION.into(),
            ];
        }
        Err(_) => {
            return vec![
                "Canary monitor: unverified (local sensor report cannot be read safely)".into(),
                SCOPE_DESCRIPTION.into(),
            ];
        }
    };
    render_status_report(&bytes, now)
}

fn validated_health(bytes: &[u8]) -> Option<(HealthReport, chrono::DateTime<chrono::FixedOffset>)> {
    let report = serde_json::from_slice::<HealthReport>(bytes).ok()?;
    if report.scope != "reserved_path_read_opens"
        || !["starting", "active", "idle", "degraded"].contains(&report.state.as_str())
        || report.issues.len() > HEALTH_ISSUES.len()
        || report
            .issues
            .iter()
            .any(|issue| !HEALTH_ISSUES.contains(&issue.as_str()))
        || (report.state == "active" && (!report.issues.is_empty() || report.registered_files == 0))
        || (report.state == "idle" && (!report.issues.is_empty() || report.registered_files != 0))
    {
        return None;
    }
    let updated = chrono::DateTime::parse_from_rfc3339(&report.updated).ok()?;
    Some((report, updated))
}

/// A bounded availability report, not proof of installed enforcement. Idle
/// monitoring has no registered decoys and must not become a healthy claim.
pub fn heartbeat_health() -> &'static str {
    match read_private(
        &crate::config::config_dir().join("canary-monitor-status.json"),
        64 * 1024,
    ) {
        Ok(bytes) => heartbeat_health_at(&bytes, chrono::Utc::now()),
        Err(_) => "unverified",
    }
}

pub fn canary_monitor_idle() -> bool {
    read_private(
        &crate::config::config_dir().join("canary-monitor-status.json"),
        64 * 1024,
    )
    .ok()
    .and_then(|bytes| validated_health(&bytes))
    .is_some_and(|(report, updated)| {
        report.state == "idle"
            && report.registered_files == 0
            && report.issues.is_empty()
            && (-5_000..=120_000).contains(
                &chrono::Utc::now()
                    .signed_duration_since(updated)
                    .num_milliseconds(),
            )
    })
}

fn heartbeat_health_at(bytes: &[u8], now: chrono::DateTime<chrono::Utc>) -> &'static str {
    let Some((report, updated)) = validated_health(bytes) else {
        return "unverified";
    };
    if !(-5_000..=120_000).contains(&now.signed_duration_since(updated).num_milliseconds())
        || report.state == "degraded"
    {
        return "degraded";
    }
    if report.state == "active" {
        "healthy"
    } else {
        "unverified"
    }
}

fn render_status_report(bytes: &[u8], now: chrono::DateTime<chrono::Utc>) -> Vec<String> {
    let Some((report, updated)) = validated_health(bytes) else {
        return vec![
            "Canary monitor: unverified (invalid local sensor report)".into(),
            SCOPE_DESCRIPTION.into(),
        ];
    };
    let age = now.signed_duration_since(updated).num_milliseconds();
    let mut lines = if !(-5_000..=120_000).contains(&age) {
        vec![
            "Canary monitor: degraded (local sensor report is stale or future-dated)".into(),
            format!("Last reported monitor state: {}", report.state),
        ]
    } else if report.state == "starting" {
        vec!["Canary monitor: unverified (last reported state: starting)".into()]
    } else {
        vec![format!(
            "Canary monitor: {} (last reported state; fresh within 120 seconds)",
            report.state
        )]
    };
    lines.push(format!(
        "Registered canary files in last report: {}",
        report.registered_files
    ));
    if !report.issues.is_empty() {
        lines.push(format!(
            "Canary monitor issues: {}",
            report.issues.join(", ")
        ));
    }
    lines.push(SCOPE_DESCRIPTION.into());
    lines
}

/// The daemon stays alive while the registry changes or the sensor recovers.
/// Its health report is local: an independent remote heartbeat supervisor is
/// still required to detect the death of this daemon itself.
pub fn watch_loop() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("Reliable canary sensing currently requires the macOS system extension".into());
    }
    let state_dir = crate::config::config_dir();
    std::fs::create_dir_all(&state_dir).map_err(|e| e.to_string())?;
    let _monitor_lock = acquire_monitor_lock(&state_dir.join("canary-monitor.lock"))?;
    let mut secret_monitor = secret_access::Monitor::start(&state_dir)?;
    write_private_json(
        &state_dir.join("canary-monitor-status.json"),
        &Health {
            updated: chrono::Utc::now().to_rfc3339(),
            state: "starting",
            issues: vec!["sensor_not_verified"],
            registered_files: 0,
            scope: "reserved_path_read_opens",
        },
    )?;
    let cursor_path = state_dir.join("canary-sensor-cursor.json");
    let mut cursor: Cursor = match read_private(&cursor_path, 1024 * 1024) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| "Canary cursor is corrupt; coverage cannot be established".to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Cursor::default(),
        Err(_) => return Err("Canary cursor cannot be read safely".into()),
    };
    let mut previous_issues = Vec::new();
    loop {
        secret_monitor.poll(&state_dir)?;
        let mut issues = Vec::new();
        let registry_snapshot = canary::locked_registry_snapshot();
        let placements = match &registry_snapshot {
            Ok(snapshot) => {
                if let Some(issue) = registry_observation(
                    &mut cursor,
                    snapshot.exists,
                    !snapshot.registry.tokens.is_empty(),
                ) {
                    issues.push(issue);
                }
                snapshot
                    .registry
                    .tokens
                    .iter()
                    .flat_map(|token| {
                        token.placements.iter().map(move |placement| Placement {
                            token_id: token.id.clone(),
                            is_selftest: token.env_name == canary::SELFTEST_ENV_NAME,
                            id: placement.id.clone(),
                            path: PathBuf::from(&placement.path),
                            identity: placement.identity.as_ref().map(|id| (id.device, id.inode)),
                        })
                    })
                    .collect::<Vec<_>>()
            }
            Err(_) => {
                issues.push("registry_unavailable");
                Vec::new()
            }
        };
        // Capture the journal while cooperating registry writers are locked.
        // A new placement cannot be committed and read between our registry
        // snapshot and journal snapshot, then skipped as an unknown identity.
        // Release before outbox I/O; later journal appends wait for next poll.
        let sensor = read_trusted(&Path::new(SENSOR_DIRECTORY).join("status.json"), 64 * 1024)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SensorStatus>(&bytes).ok());
        let journals = ["canary-events.jsonl.previous", "canary-events.jsonl"]
            .map(|name| read_trusted(&Path::new(SENSOR_DIRECTORY).join(name), MAX_JOURNAL_BYTES));
        drop(registry_snapshot);
        for placement in &placements {
            if let Some(issue) = placement_issue(placement) {
                issues.push(issue);
            }
        }
        match &sensor {
            Some(status) => issues.extend(sensor_issues(status, chrono::Utc::now())),
            None => issues.push("sensor_unavailable_or_untrusted"),
        }
        // Do not advance past events while the registry is unavailable: doing
        // so would silently discard accesses to its missing placements.
        if !issues.iter().any(|issue| issue.starts_with("registry_")) {
            for journal in journals {
                match journal {
                    Ok(bytes) => {
                        if consume_journal(&bytes, &placements, &mut cursor, |placement, event| {
                            // This acknowledgement means durably queued, not
                            // remotely delivered. The outbox tracks receipt.
                            crate::alerting::alert_canary_access(
                                &placement.token_id,
                                &placement.id,
                                &format!("{}:{}", event.stream, event.sequence),
                                placement.is_selftest,
                            )?;
                            append_local_access(&state_dir, placement, event)
                        })
                        .is_err()
                        {
                            issues.push("journal_or_alarm_persistence_failed");
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        issues.push("journal_unavailable_or_untrusted");
                        break;
                    }
                }
            }
            if let Some(status) = &sensor {
                let consumed = cursor
                    .streams
                    .get(&status.canary_stream)
                    .copied()
                    .unwrap_or(0);
                if consumed < status.canary_sequence {
                    issues.push("journal_behind_sensor");
                }
            }
        }
        if write_private_json(&cursor_path, &cursor).is_err() {
            issues.push("cursor_persistence_failed");
        }
        if cursor.coverage_gap {
            issues.push("event_coverage_gap");
        }
        issues.sort_unstable();
        issues.dedup();
        let health = Health {
            updated: chrono::Utc::now().to_rfc3339(),
            state: if !issues.is_empty() {
                "degraded"
            } else if placements.is_empty() {
                "idle"
            } else {
                "active"
            },
            issues: issues.clone(),
            registered_files: placements.len(),
            scope: "reserved_path_read_opens",
        };
        // If persistence fails, exiting lets the launcher/service report the
        // failure. Continuing would leave a misleading stale active status.
        write_private_json(&state_dir.join("canary-monitor-status.json"), &health)?;
        if issues != previous_issues {
            eprintln!("Canary monitor {}: {}", health.state, issues.join(", "));
            if !issues.is_empty() {
                // Fixed issue codes only: no filenames, commands, or process
                // strings may enter the outbound health message.
                crate::alerting::alert_watchdog("Canary monitoring degraded", &issues.join(", "))?;
            }
            previous_issues = issues;
        }
        std::thread::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS));
    }
}

/// An explicitly saved empty registry is a deliberate removal operation.
/// Disappearance of a previously nonempty registry is a health failure,
/// including across daemon restarts. This witness is local, not tamperproof.
fn registry_observation(
    cursor: &mut Cursor,
    present: bool,
    nonempty: bool,
) -> Option<&'static str> {
    if !present && (cursor.registry_expected || nonempty) {
        cursor.registry_expected = true;
        return Some("registry_missing_after_registration");
    }
    if present {
        cursor.registry_expected = nonempty;
    }
    None
}

/// Sensor journals and placements carry macOS paths. Check them as POSIX
/// paths on every host, so a Windows build of the CLI validates the same
/// records the same way (and the tests behave identically on Windows CI).
fn posix_absolute(path: &str) -> bool {
    path.starts_with('/')
}

fn reserved_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(id) = name
        .strip_prefix(".hedgehog-canary-")
        .and_then(|name| name.strip_suffix(".txt"))
    else {
        return false;
    };
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn placement_issue(placement: &Placement) -> Option<&'static str> {
    if !reserved_path(&placement.path) || placement.identity.is_none() {
        return Some("placement_requires_redeployment");
    }
    let Ok(metadata) = std::fs::symlink_metadata(&placement.path) else {
        return Some("placement_missing_or_unreadable");
    };
    if !metadata.file_type().is_file() {
        return Some("placement_replaced");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if placement.identity != Some((metadata.dev(), metadata.ino())) {
            return Some("placement_replaced");
        }
        if metadata.nlink() != 1 {
            return Some("placement_has_unmonitored_aliases");
        }
    }
    None
}

fn sensor_issues(status: &SensorStatus, now: chrono::DateTime<chrono::Utc>) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if status.canary_schema != 1 || status.canary_scope != "reserved_path_read_opens" {
        issues.push("sensor_schema_unsupported");
    }
    if status.canary_sensor != "active" {
        issues.push("sensor_not_active");
    }
    if status.canary_dropped > 0 {
        issues.push("sensor_dropped_events");
    }
    match chrono::DateTime::parse_from_rfc3339(&status.updated) {
        Ok(updated) => {
            let age = now.signed_duration_since(updated).num_milliseconds();
            if !(-5_000..=120_000).contains(&age) {
                issues.push("sensor_heartbeat_stale");
            }
        }
        Err(_) => issues.push("sensor_heartbeat_invalid"),
    }
    issues
}

fn consume_journal(
    bytes: &[u8],
    placements: &[Placement],
    cursor: &mut Cursor,
    mut record: impl FnMut(&Placement, &OpenEvent) -> Result<(), String>,
) -> Result<(), String> {
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        // A concurrent append may leave an incomplete final line. Re-read it
        // next poll; status sequence comparison prevents a false healthy lag.
        if line.last() != Some(&b'\n') {
            break;
        }
        let event: OpenEvent = serde_json::from_slice(line).map_err(|_| {
            cursor.coverage_gap = true;
            "Malformed canary journal event".to_string()
        })?;
        if line.len() > 32 * 1024
            || event.schema != 1
            || event.event != "canary_open"
            || event.sequence == 0
            || event.stream.len() > 64
            || event.stream.is_empty()
            || !event
                .stream
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || chrono::DateTime::parse_from_rfc3339(&event.timestamp).is_err()
        {
            cursor.coverage_gap = true;
            return Err("Unsupported canary journal event".into());
        }
        let last = cursor.streams.get(&event.stream).copied().unwrap_or(0);
        if event.sequence <= last {
            continue;
        }
        if event.sequence != last + 1 {
            cursor.coverage_gap = true;
        }
        for placement in placements {
            if placement.identity == Some((event.device, event.inode))
                && reserved_path(Path::new(&event.path))
            {
                record(placement, &event)?;
            }
        }
        // Bound hostile/corrupt cursor input instead of evicting checkpoints
        // and replaying acknowledged events as new alarms.
        if cursor.streams.len() >= 4096 && !cursor.streams.contains_key(&event.stream) {
            return Err("Canary cursor session capacity reached".into());
        }
        cursor.streams.insert(event.stream, event.sequence);
    }
    Ok(())
}

fn read_private(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other("Not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(std::io::Error::other("Untrusted private state file"));
        }
    }
    bounded_read(file, limit)
}

fn acquire_monitor_lock(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let file = options.open(path).map_err(|e| e.to_string())?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("Canary monitor lock is not a regular file".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Another canary monitor holds the journal cursor lock".into());
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path).map_err(|e| e.to_string())
    }
}

fn read_trusted(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        for parent in path.ancestors().skip(1) {
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(std::io::Error::other("Untrusted sensor directory"));
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(std::io::Error::other("Untrusted sensor file"));
        }
        bounded_read(file, limit)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, limit);
        Err(std::io::Error::other("Trusted sensor unavailable"))
    }
}

fn bounded_read(mut file: std::fs::File, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("Sensor file exceeds limit"));
    }
    Ok(bytes)
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let temporary = path.with_extension(format!("tmp-{:016x}", rand::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(parent) = path.parent() {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(parent)?
                    .sync_all()?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|e| e.to_string())
}

fn append_local_access(
    directory: &Path,
    placement: &Placement,
    event: &OpenEvent,
) -> Result<(), String> {
    let document = serde_json::json!({"placement_id":placement.id,"token_id":placement.token_id,"access":event});
    let mut bytes = serde_json::to_vec(&document).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let path = directory.join("canary-access.jsonl");
    let mut file = options.open(&path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Local canary journal is not a regular file".into());
    }
    if file.metadata().map_err(|e| e.to_string())?.len() >= 4 * 1024 * 1024 {
        drop(file);
        std::fs::rename(&path, directory.join("canary-access.jsonl.previous"))
            .map_err(|e| e.to_string())?;
        file = options.open(&path).map_err(|e| e.to_string())?;
    }
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}

/// Consume protected ordinary-secret access records independently of canary
/// registration. The extension evaluates the administrator-approved policy at
/// event time; changing today's policy must not erase an earlier violation.
pub mod secret_access {
    use super::{
        acquire_monitor_lock, read_private, read_trusted, write_private_json, MAX_JOURNAL_BYTES,
        SENSOR_DIRECTORY,
    };
    use crate::canary::secret_policy::LoadedPolicy;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    const SCOPE: &str = "enrolled_file_read_opens";

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Reader {
        cdhash: String,
        signing_id: String,
        team_id: String,
        platform_binary: bool,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct AccessEvent {
        schema: u32,
        stream: String,
        sequence: u64,
        timestamp: String,
        event: String,
        policy_revision: String,
        owner_uid: u32,
        secret_id: String,
        device: u64,
        inode: u64,
        pid: u32,
        reader_uid: u32,
        executable: String,
        audit_token: String,
        reader: Reader,
        decision: String,
        #[serde(default)]
        coverage_issues: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct PolicyStatus {
        owner_uid: u32,
        revision: String,
        policy_sha256: String,
        registered_files: usize,
        state: String,
        issues: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct SensorStatus {
        updated: String,
        secret_sensor: String,
        secret_schema: u32,
        secret_stream: String,
        secret_sequence: u64,
        secret_dropped: u64,
        secret_scope: String,
        secret_policies: Vec<PolicyStatus>,
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Cursor {
        streams: BTreeMap<String, u64>,
        coverage_gap: bool,
        policy_expected: bool,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Health {
        schema: u32,
        updated: String,
        state: String,
        issues: Vec<String>,
        registered_files: usize,
        policy_expected: bool,
        policy_revision: Option<String>,
        policy_sha256: Option<String>,
        scope: String,
    }

    fn hex(value: &str, size: usize) -> bool {
        value.len() == size
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn safe_text(value: &str, max: usize) -> bool {
        value.len() <= max && !value.chars().any(char::is_control)
    }

    fn stream_valid(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }

    fn fresh(value: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
        chrono::DateTime::parse_from_rfc3339(value).is_ok_and(|date| {
            (-5_000..=120_000).contains(&now.signed_duration_since(date).num_milliseconds())
        })
    }

    fn validate_event(event: &AccessEvent, now: chrono::DateTime<chrono::Utc>) -> bool {
        use base64::Engine;
        let identity_valid = if event.decision == "identity_unverified" {
            event.reader.cdhash.is_empty() || hex(&event.reader.cdhash, 40)
        } else {
            hex(&event.reader.cdhash, 40)
                && !event.reader.signing_id.is_empty()
                && (!event.reader.team_id.is_empty() || event.reader.platform_binary)
        };
        event.schema == 1
            && event.event == "secret_open"
            && event.sequence > 0
            && stream_valid(&event.stream)
            && hex(&event.policy_revision, 32)
            && hex(&event.secret_id, 32)
            && event.inode > 0
            && event.pid > 0
            && safe_text(&event.executable, 4096)
            && event.executable.starts_with('/')
            && safe_text(&event.reader.signing_id, 512)
            && safe_text(&event.reader.team_id, 64)
            && ["approved", "unapproved", "identity_unverified"].contains(&event.decision.as_str())
            && identity_valid
            && base64::engine::general_purpose::STANDARD
                .decode(&event.audit_token)
                .is_ok_and(|v| v.len() == 32)
            && event.coverage_issues.len() <= 2
            && event
                .coverage_issues
                .iter()
                .all(|v| ["file_replaced", "file_alias_observed"].contains(&v.as_str()))
            && chrono::DateTime::parse_from_rfc3339(&event.timestamp)
                .is_ok_and(|date| now.signed_duration_since(date).num_milliseconds() >= -5_000)
    }

    fn consume(
        bytes: &[u8],
        owner_uid: u32,
        cursor: &mut Cursor,
        mut record: impl FnMut(&AccessEvent) -> Result<(), String>,
    ) -> Result<(), String> {
        let now = chrono::Utc::now();
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            if line.last() != Some(&b'\n') {
                break;
            }
            if line.len() > 32 * 1024 {
                cursor.coverage_gap = true;
                return Err("Oversized secret access event".into());
            }
            let event: AccessEvent = serde_json::from_slice(line).map_err(|_| {
                cursor.coverage_gap = true;
                "Malformed secret access event".to_string()
            })?;
            if !validate_event(&event, now) {
                cursor.coverage_gap = true;
                return Err("Invalid secret access event".into());
            }
            let last = cursor.streams.get(&event.stream).copied().unwrap_or(0);
            if event.sequence <= last {
                continue;
            }
            if event.sequence != last + 1 {
                cursor.coverage_gap = true;
            }
            if event.owner_uid == owner_uid {
                if !event.coverage_issues.is_empty() {
                    cursor.coverage_gap = true;
                }
                // Approved accesses are retained in the protected source
                // journal too. Both decisions remain inspectable locally.
                record(&event)?;
            }
            if cursor.streams.len() >= 4096 && !cursor.streams.contains_key(&event.stream) {
                cursor.coverage_gap = true;
                return Err("Secret access cursor capacity reached".into());
            }
            // The caller must durably queue an alarm before this checkpoint.
            cursor.streams.insert(event.stream, event.sequence);
        }
        Ok(())
    }

    fn alarm(event: &AccessEvent) -> Result<Option<crate::alerting::SecurityAlert>, String> {
        if event.decision == "approved" {
            return Ok(None);
        }
        crate::alerting::secret_access_alert(
            event.owner_uid,
            &event.policy_revision,
            &event.secret_id,
            &event.stream,
            event.sequence,
            event.pid,
            event.decision == "identity_unverified",
        )
        .map(Some)
    }

    fn inspect_sensor(
        owner_uid: u32,
        loaded: Option<&LoadedPolicy>,
        bytes: Option<&[u8]>,
    ) -> Value {
        let mut issues = Vec::<String>::new();
        let sensor = bytes.and_then(|b| serde_json::from_slice::<SensorStatus>(b).ok());
        let count = loaded.map_or(0, |p| p.policy.secrets.len());
        if let Some(policy) = loaded {
            match &sensor {
                Some(status) => {
                    if status.secret_schema != 1
                        || status.secret_scope != SCOPE
                        || !stream_valid(&status.secret_stream)
                    {
                        issues.push("sensor_schema_invalid".into());
                    }
                    if status.secret_sensor != "active" {
                        issues.push("sensor_not_active".into());
                    }
                    if status.secret_dropped > 0 {
                        issues.push("sensor_dropped_events".into());
                    }
                    if !fresh(&status.updated, chrono::Utc::now()) {
                        issues.push("sensor_heartbeat_stale".into());
                    }
                    if status.secret_policies.len() > 256 {
                        issues.push("sensor_policy_limit".into());
                    }
                    let matching: Vec<_> = status
                        .secret_policies
                        .iter()
                        .filter(|v| v.owner_uid == owner_uid)
                        .collect();
                    match matching.as_slice() {
                        [state]
                            if state.revision == policy.policy.revision
                                && state.policy_sha256 == policy.sha256
                                && state.registered_files == count =>
                        {
                            if state.state != "active" || !state.issues.is_empty() {
                                issues.push("policy_coverage_degraded".into());
                            }
                        }
                        _ => issues.push("policy_not_acknowledged".into()),
                    }
                }
                None => issues.push("sensor_unavailable_or_untrusted".into()),
            }
        }
        let state = if loaded.is_none() {
            "unverified"
        } else if !issues.is_empty() {
            "degraded"
        } else if count == 0 {
            "idle"
        } else {
            "active"
        };
        json!({"state":state,"message":match state {
            "active"=>"The sensor reports the exact installed policy loaded. This is status evidence, not a live access or delivery test.",
            "idle"=>"The installed policy explicitly monitors no files.",
            "degraded"=>"The enrolled policy is not fully acknowledged or sensor coverage is degraded.",
            _=>"No monitored-secret policy has been installed."
        },"issues":issues,"registered_files":count,"policy_revision":loaded.map(|p| &p.policy.revision),
            "policy_sha256":loaded.map(|p| &p.sha256),"scope":SCOPE})
    }

    pub fn sensor_status(owner_uid: u32, loaded: Option<&LoadedPolicy>) -> Value {
        let bytes = read_trusted(
            &Path::new(SENSOR_DIRECTORY).join("status.json"),
            1024 * 1024,
        )
        .ok();
        inspect_sensor(owner_uid, loaded, bytes.as_deref())
    }

    fn read_health() -> Option<Health> {
        let bytes = read_private(
            &crate::config::config_dir().join("secret-access-monitor-status.json"),
            64 * 1024,
        )
        .ok()?;
        let report: Health = serde_json::from_slice(&bytes).ok()?;
        if report.schema != 1
            || report.scope != SCOPE
            || report.registered_files > 256
            || !["starting", "active", "idle", "degraded"].contains(&report.state.as_str())
            || report.issues.len() > 64
            || report
                .issues
                .iter()
                .any(|s| s.len() > 80 || !s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            || (report.state == "active"
                && (!report.issues.is_empty()
                    || report.registered_files == 0
                    || !report.policy_expected
                    || !report
                        .policy_revision
                        .as_deref()
                        .is_some_and(|v| hex(v, 32))
                    || !report.policy_sha256.as_deref().is_some_and(|v| hex(v, 64))))
            || (report.state == "idle"
                && (!report.issues.is_empty()
                    || report.registered_files != 0
                    || report.policy_expected))
        {
            return None;
        }
        Some(report)
    }

    pub fn monitor_status() -> Value {
        let Some(report) = read_health() else {
            return json!({"state":"unverified","message":"Start the local monitor to consume protected secret-access records.",
                "issues":["monitor_report_unavailable"],"registered_files":0,"updated":null,"policy_revision":null,"policy_sha256":null,"scope":SCOPE});
        };
        let is_fresh = fresh(&report.updated, chrono::Utc::now());
        json!({"state":if is_fresh {report.state.as_str()} else {"degraded"},
            "message":if is_fresh {"Last reported journal processing state. Queued alarms do not establish remote receipt."}
                else {"The local secret-access monitor report is stale."},
            "issues":if is_fresh {report.issues} else {vec!["monitor_report_stale".into()]},
            "registered_files":report.registered_files,"updated":report.updated,
            "policy_revision":report.policy_revision,"policy_sha256":report.policy_sha256,"scope":SCOPE})
    }

    pub fn recent_access() -> Value {
        let directory = crate::config::config_dir();
        let mut events = std::collections::VecDeque::new();
        for name in [
            "secret-access-history.previous.jsonl",
            "secret-access-history.jsonl",
        ] {
            let bytes = match read_private(&directory.join(name), 1024 * 1024 + 32 * 1024) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    return json!({"state":"unavailable","message":"Local access history could not be read safely.","events":[]})
                }
            };
            for line in bytes.split_inclusive(|b| *b == b'\n') {
                if line.last() != Some(&b'\n') {
                    break;
                }
                let event = serde_json::from_slice::<AccessEvent>(line)
                    .ok()
                    .filter(|event| {
                        line.len() <= 32 * 1024 && validate_event(event, chrono::Utc::now())
                    });
                let Some(event) = event else {
                    return json!({"state":"unavailable","message":"Local access history is malformed. It cannot establish coverage.","events":[]});
                };
                if events.len() == 100 {
                    events.pop_front();
                }
                events.push_back(event);
            }
        }
        json!({"state":"available","message":"Recent local access records; an empty history does not establish monitoring or alarm delivery.","events":events})
    }

    /// None means no secret policy is configured. Never replace a missing
    /// configured monitor with a healthy canary-only availability claim.
    pub fn heartbeat_health() -> Option<&'static str> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let policy = crate::canary::secret_policy::load_current();
        let report = read_health();
        let expected = match &policy {
            Ok(Some(p)) => !p.policy.secrets.is_empty(),
            Ok(None) => report.as_ref().is_some_and(|r| r.policy_expected),
            Err(_) => true,
        };
        if !expected {
            return None;
        }
        let Some(report) = report else {
            return Some("unverified");
        };
        let current = policy
            .as_ref()
            .ok()
            .and_then(|p| p.as_ref())
            .is_some_and(|p| {
                report.policy_revision.as_ref() == Some(&p.policy.revision)
                    && report.policy_sha256.as_ref() == Some(&p.sha256)
                    && report.registered_files == p.policy.secrets.len()
            });
        Some(
            if current && report.state == "active" && fresh(&report.updated, chrono::Utc::now()) {
                "healthy"
            } else {
                "degraded"
            },
        )
    }

    pub(super) struct Monitor {
        _lock: std::fs::File,
        cursor: Cursor,
        cursor_path: PathBuf,
        previous_issues: Vec<String>,
    }

    impl Monitor {
        pub(super) fn start(state_dir: &Path) -> Result<Self, String> {
            let lock = acquire_monitor_lock(&state_dir.join("secret-access-monitor.lock"))?;
            let cursor_path = state_dir.join("secret-access-cursor.json");
            let cursor: Cursor = match read_private(&cursor_path, 1024 * 1024) {
                Ok(bytes) => {
                    serde_json::from_slice(&bytes).map_err(|_| "Secret access cursor is corrupt")?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Cursor::default(),
                Err(_) => return Err("Secret access cursor is unavailable or unsafe".into()),
            };
            if cursor.streams.len() > 4096 || cursor.streams.keys().any(|v| !stream_valid(v)) {
                return Err("Invalid secret access cursor".into());
            }
            Ok(Self {
                _lock: lock,
                cursor,
                cursor_path,
                previous_issues: Vec::new(),
            })
        }

        pub(super) fn poll(&mut self, state_dir: &Path) -> Result<(), String> {
            #[cfg(unix)]
            let uid = unsafe { libc::geteuid() };
            #[cfg(not(unix))]
            let uid = 0;
            let mut issues = Vec::<String>::new();
            let loaded = crate::canary::secret_policy::load_current();
            let policy = match &loaded {
                Ok(value) => value.as_ref(),
                Err(_) => {
                    issues.push("policy_unavailable_or_untrusted".into());
                    None
                }
            };
            if let Some(p) = policy {
                self.cursor.policy_expected = !p.policy.secrets.is_empty();
            } else if self.cursor.policy_expected {
                issues.push("policy_missing_after_enrollment".into());
            }
            let bytes = read_trusted(
                &Path::new(SENSOR_DIRECTORY).join("status.json"),
                1024 * 1024,
            )
            .ok();
            let sensor = bytes
                .as_deref()
                .and_then(|b| serde_json::from_slice::<SensorStatus>(b).ok());
            let observation = inspect_sensor(uid, policy, bytes.as_deref());
            if self.cursor.policy_expected {
                issues.extend(
                    observation["issues"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v.as_str().map(str::to_string)),
                );
            }
            for name in [
                "secret-access-events.jsonl.previous",
                "secret-access-events.jsonl",
            ] {
                match read_trusted(&Path::new(SENSOR_DIRECTORY).join(name), MAX_JOURNAL_BYTES) {
                    Ok(bytes) => {
                        if consume(&bytes, uid, &mut self.cursor, |event| {
                            if let Some(alert) = alarm(event)? {
                                crate::alerting::send(alert)?;
                            }
                            append_local(state_dir, event)
                        })
                        .is_err()
                        {
                            issues.push("journal_or_alarm_persistence_failed".into());
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        issues.push("journal_unavailable_or_untrusted".into());
                        break;
                    }
                }
            }
            if self.cursor.policy_expected {
                if let Some(status) = &sensor {
                    if self
                        .cursor
                        .streams
                        .get(&status.secret_stream)
                        .copied()
                        .unwrap_or(0)
                        < status.secret_sequence
                    {
                        issues.push("journal_behind_sensor".into());
                    }
                }
                if self.cursor.coverage_gap {
                    issues.push("event_coverage_gap".into());
                }
            }
            if write_private_json(&self.cursor_path, &self.cursor).is_err() {
                issues.push("cursor_persistence_failed".into());
            }
            issues.sort();
            issues.dedup();
            if issues != self.previous_issues && !issues.is_empty() {
                crate::alerting::alert_watchdog(
                    "Secret access monitoring degraded",
                    &issues.join(", "),
                )?;
            }
            self.previous_issues = issues.clone();
            let count = policy.map_or(0, |p| p.policy.secrets.len());
            write_private_json(
                &state_dir.join("secret-access-monitor-status.json"),
                &Health {
                    schema: 1,
                    updated: chrono::Utc::now().to_rfc3339(),
                    state: if !issues.is_empty() {
                        "degraded"
                    } else if count == 0 {
                        "idle"
                    } else {
                        "active"
                    }
                    .into(),
                    issues,
                    registered_files: count,
                    policy_expected: self.cursor.policy_expected,
                    policy_revision: policy.map(|p| p.policy.revision.clone()),
                    policy_sha256: policy.map(|p| p.sha256.clone()),
                    scope: SCOPE.into(),
                },
            )
        }
    }

    fn append_local(state_dir: &Path, event: &AccessEvent) -> Result<(), String> {
        let path = state_dir.join("secret-access-history.jsonl");
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.is_file() {
                return Err("Secret history is not a regular file".into());
            }
            if metadata.len() >= 1024 * 1024 {
                std::fs::rename(
                    &path,
                    state_dir.join("secret-access-history.previous.jsonl"),
                )
                .map_err(|_| "Cannot rotate secret access history")?;
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| "Cannot open secret access history")?;
        let meta = file
            .metadata()
            .map_err(|_| "Cannot inspect secret access history")?;
        if !meta.is_file() {
            return Err("Unsafe secret access history".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o077 != 0
                || meta.nlink() != 1
            {
                return Err("Secret access history permissions are unsafe".into());
            }
        }
        let mut bytes =
            serde_json::to_vec(event).map_err(|_| "Cannot encode secret access history")?;
        bytes.push(b'\n');
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Cannot persist secret access history".into())
    }

    #[cfg(test)]
    pub(crate) fn fixture_alarms(
        bytes: &[u8],
        owner_uid: u32,
        mut record: impl FnMut(crate::alerting::SecurityAlert) -> Result<(), String>,
    ) -> Result<u64, String> {
        let mut cursor = Cursor::default();
        consume(bytes, owner_uid, &mut cursor, |event| {
            if let Some(alert) = alarm(event)? {
                record(alert)?;
            }
            Ok(())
        })?;
        Ok(cursor.streams.values().sum())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn event(sequence: u64, decision: &str) -> Value {
            json!({"schema":1,"stream":"fixture-stream","sequence":sequence,
                "timestamp":chrono::Utc::now().to_rfc3339(),"event":"secret_open",
                "policy_revision":"a".repeat(32),"owner_uid":501,"secret_id":"b".repeat(32),
                "device":1,"inode":2,"pid":123,"reader_uid":501,"executable":"/Applications/Synthetic.app/Contents/MacOS/Synthetic",
                "audit_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "reader":{"cdhash":"c".repeat(40),"signing_id":"synthetic","team_id":"TEAM","platform_binary":false},
                "decision":decision,"coverage_issues":[]})
        }
        fn line(value: Value) -> Vec<u8> {
            format!("{value}\n").into_bytes()
        }

        #[test]
        fn approved_reads_remain_observable_but_only_unapproved_reads_alarm() {
            let mut bytes = line(event(1, "approved"));
            bytes.extend(line(event(2, "unapproved")));
            bytes.extend(line(event(3, "identity_unverified")));
            let mut alerts = Vec::new();
            assert_eq!(
                fixture_alarms(&bytes, 501, |alert| {
                    alerts.push(alert);
                    Ok(())
                })
                .unwrap(),
                3
            );
            assert_eq!(alerts.len(), 2);
            assert!(alerts[0]
                .event_id
                .starts_with("secret-access:501:fixture-stream:2:"));
            let wire = serde_json::to_string(&alerts).unwrap();
            assert!(!wire.contains("Synthetic.app"));
            assert!(!wire.contains("TEAM"));
            assert!(wire.contains("could not be verified"));
        }

        #[test]
        fn persistence_failure_does_not_advance_and_replay_uses_same_alarm_id() {
            let bytes = line(event(1, "unapproved"));
            let mut cursor = Cursor::default();
            let mut ids = Vec::new();
            assert!(consume(&bytes, 501, &mut cursor, |event| {
                ids.push(alarm(event)?.unwrap().event_id);
                Err("disk full".into())
            })
            .is_err());
            assert!(cursor.streams.is_empty());
            consume(&bytes, 501, &mut cursor, |event| {
                ids.push(alarm(event)?.unwrap().event_id);
                Ok(())
            })
            .unwrap();
            assert_eq!(ids[0], ids[1]);
            consume(&bytes, 501, &mut cursor, |_| {
                panic!("duplicate must not be replayed")
            })
            .unwrap();
        }

        #[test]
        fn other_accounts_are_checkpointed_without_sending_their_alarm() {
            assert_eq!(
                fixture_alarms(&line(event(1, "unapproved")), 502, |_| panic!(
                    "wrong account"
                ))
                .unwrap(),
                1
            );
        }

        #[test]
        fn sequence_loss_aliases_and_malformed_identity_are_not_healthy() {
            let mut cursor = Cursor::default();
            consume(&line(event(3, "approved")), 501, &mut cursor, |_| Ok(())).unwrap();
            assert!(cursor.coverage_gap);
            let mut changed = event(4, "approved");
            changed["coverage_issues"] = json!(["file_alias_observed"]);
            consume(&line(changed), 501, &mut cursor, |_| Ok(())).unwrap();
            assert!(cursor.coverage_gap);
            for (field, value) in [
                ("decision", json!("allow")),
                ("audit_token", json!("broken")),
                ("secret_id", json!("not-an-id")),
                ("timestamp", json!("bad-date")),
            ] {
                let mut bad = event(5, "unapproved");
                bad[field] = value;
                assert!(consume(&line(bad), 501, &mut cursor, |_| Ok(())).is_err());
            }
            assert_eq!(cursor.streams["fixture-stream"], 4);
        }

        #[test]
        fn incomplete_append_waits_and_changed_policy_does_not_hide_historical_alarm() {
            let mut cursor = Cursor::default();
            let bytes = line(event(1, "unapproved"));
            consume(&bytes[..bytes.len() - 1], 501, &mut cursor, |_| {
                panic!("partial")
            })
            .unwrap();
            assert!(cursor.streams.is_empty());
            consume(&bytes, 501, &mut cursor, |event| {
                assert_eq!(event.policy_revision, "a".repeat(32));
                Ok(())
            })
            .unwrap();
        }

        #[test]
        fn active_status_requires_exact_policy_hash_fresh_sensor_and_complete_coverage() {
            let loaded=LoadedPolicy {
                policy:serde_json::from_value(json!({"schema":1,"owner_uid":501,"revision":"a".repeat(32),"base_policy_sha256":null,
                    "secrets":[{"id":"b".repeat(32),"path":"/Users/synthetic/secret","device":1,"inode":2,"readers":[]}]})).unwrap(),
                sha256:"d".repeat(64),
            };
            let status = json!({"updated":chrono::Utc::now().to_rfc3339(),"secret_sensor":"active","secret_schema":1,
                "secret_stream":"fixture-stream","secret_sequence":0,"secret_dropped":0,"secret_scope":SCOPE,
                "secret_policies":[{"owner_uid":501,"revision":"a".repeat(32),"policy_sha256":"d".repeat(64),
                    "registered_files":1,"state":"active","issues":[]}]});
            let inspect = |v: &Value| {
                inspect_sensor(501, Some(&loaded), Some(&serde_json::to_vec(v).unwrap()))
            };
            assert_eq!(inspect(&status)["state"], "active");
            assert_eq!(
                inspect_sensor(501, None, Some(&serde_json::to_vec(&status).unwrap()))["state"],
                "unverified"
            );
            assert_eq!(
                inspect_sensor(501, Some(&loaded), None)["state"],
                "degraded"
            );
            let mut changed = status.clone();
            changed["secret_policies"][0]["policy_sha256"] = json!("e".repeat(64));
            assert_eq!(inspect(&changed)["state"], "degraded");
            changed = status.clone();
            changed["secret_policies"][0]["issues"] = json!(["file_replaced"]);
            assert_eq!(inspect(&changed)["state"], "degraded");
            changed = status.clone();
            changed["updated"] = json!("2000-01-01T00:00:00Z");
            assert_eq!(inspect(&changed)["state"], "degraded");
            changed = status.clone();
            changed["secret_dropped"] = json!(1);
            assert_eq!(inspect(&changed)["state"], "degraded");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement() -> Placement {
        Placement {
            token_id: "token".into(),
            is_selftest: false,
            id: "placement".into(),
            path: PathBuf::from("/synthetic/.hedgehog-canary-0123456789abcdef0123456789abcdef.txt"),
            identity: Some((12, 34)),
        }
    }
    fn event(sequence: u64) -> OpenEvent {
        OpenEvent {
            schema: 1,
            stream: "sensor-session".into(),
            sequence,
            timestamp: "2026-09-05T12:00:00Z".into(),
            event: "canary_open".into(),
            path: placement().path.to_string_lossy().into_owned(),
            device: 12,
            inode: 34,
            pid: 321,
            executable: "/tmp/hedgehog-backupd-spoof".into(),
            audit_token: "AAECAwQFBgc=".into(),
        }
    }
    fn line(event: &OpenEvent) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(event).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn selftest_fixture() -> (
        SelftestSensorBaseline,
        canary::CanaryPlacement,
        SensorStatus,
        OpenEvent,
        chrono::DateTime<chrono::Utc>,
    ) {
        use base64::Engine;
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let baseline = SelftestSensorBaseline {
            stream: "sensor-session".into(),
            sequence: 9,
            captured_at: now - chrono::Duration::seconds(2),
        };
        let placement = canary::CanaryPlacement {
            id: "0123456789abcdef0123456789abcdef".into(),
            path: placement().path.to_string_lossy().into_owned(),
            identity: Some(canary::CanaryFileIdentity {
                device: 12,
                inode: 34,
            }),
            expected_content: None,
        };
        let status = SensorStatus {
            updated: now.to_rfc3339(),
            canary_sensor: "active".into(),
            canary_schema: 1,
            canary_stream: baseline.stream.clone(),
            canary_sequence: baseline.sequence,
            canary_dropped: 0,
            canary_scope: "reserved_path_read_opens".into(),
        };
        let mut access = event(10);
        let mut audit = [0_u8; 32];
        audit[20..24].copy_from_slice(&access.pid.to_le_bytes());
        audit[28..32].copy_from_slice(&1_u32.to_le_bytes());
        access.audit_token = base64::engine::general_purpose::STANDARD.encode(audit);
        (baseline, placement, status, access, now)
    }

    #[test]
    fn selftest_requires_exact_fresh_sensor_event_but_accepts_lagging_heartbeat_sequence() {
        let (baseline, placement, status, access, now) = selftest_fixture();
        let started = now - chrono::Duration::seconds(1);
        assert_eq!(
            selftest_event_in_journals(
                &baseline,
                &placement,
                access.pid,
                started,
                now,
                &status,
                &status,
                &[line(&access)],
            )
            .unwrap(),
            Some("sensor-session:10".into())
        );
        let mut old = access.clone();
        old.sequence = baseline.sequence;
        assert_eq!(
            selftest_event_in_journals(
                &baseline,
                &placement,
                access.pid,
                started,
                now,
                &status,
                &status,
                &[line(&old)],
            )
            .unwrap(),
            None
        );
        let mut partial = line(&access);
        partial.pop();
        assert_eq!(
            selftest_event_in_journals(
                &baseline,
                &placement,
                access.pid,
                started,
                now,
                &status,
                &status,
                &[partial],
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn selftest_baseline_and_trigger_share_millisecond_precision() {
        let (mut baseline, placement, status, access, now) = selftest_fixture();
        baseline.captured_at = now - chrono::Duration::microseconds(500);
        let started = now - chrono::Duration::milliseconds(1);
        assert_eq!(
            selftest_event_in_journals(
                &baseline,
                &placement,
                access.pid,
                started,
                now,
                &status,
                &status,
                &[line(&access)],
            )
            .unwrap(),
            Some("sensor-session:10".into())
        );
        assert!(selftest_event_in_journals(
            &baseline,
            &placement,
            access.pid,
            started - chrono::Duration::milliseconds(1),
            now,
            &status,
            &status,
            &[line(&access)],
        )
        .is_err());
    }

    #[test]
    fn selftest_does_not_match_wrong_path_pid_inode_device_or_trigger_time() {
        let (baseline, placement, status, access, now) = selftest_fixture();
        let started = now - chrono::Duration::seconds(1);
        for variant in 0..7 {
            let mut other = access.clone();
            let mut expected_pid = access.pid;
            match variant {
                0 => expected_pid += 1,
                1 => other.path = other.path.replace("/synthetic/", "/other/"),
                2 => other.inode += 1,
                3 => other.device += 1,
                4 => other.timestamp = (started - chrono::Duration::milliseconds(1)).to_rfc3339(),
                5 => other.timestamp = (now + chrono::Duration::milliseconds(1)).to_rfc3339(),
                6 => other.stream = "previous-session".into(),
                _ => unreachable!(),
            }
            assert_eq!(
                selftest_event_in_journals(
                    &baseline,
                    &placement,
                    expected_pid,
                    started,
                    now,
                    &status,
                    &status,
                    &[line(&other)],
                )
                .unwrap(),
                None,
                "variant {variant} incorrectly matched"
            );
        }
    }

    #[test]
    fn selftest_rejects_malformed_audit_identity_events_and_conflicting_sequences() {
        let (baseline, placement, status, access, now) = selftest_fixture();
        let started = now - chrono::Duration::seconds(1);
        for variant in 0..8 {
            let mut other = access.clone();
            match variant {
                0 => other.audit_token = "not-base64".into(),
                1 => other.audit_token = "AAECAwQFBgc=".into(),
                2 => other.pid += 1,
                3 => other.schema = 99,
                4 => other.stream = "invalid:stream".into(),
                5 => other.timestamp = "invalid-time".into(),
                6 => other.path = "relative-path".into(),
                7 => other.executable = "relative-executable".into(),
                _ => unreachable!(),
            }
            assert!(
                selftest_event_in_journals(
                    &baseline,
                    &placement,
                    access.pid,
                    started,
                    now,
                    &status,
                    &status,
                    &[line(&other)],
                )
                .is_err(),
                "variant {variant} accepted invalid evidence"
            );
        }
        assert!(selftest_event_in_journals(
            &baseline,
            &placement,
            access.pid,
            started,
            now,
            &status,
            &status,
            &[b"broken-json\n".to_vec()],
        )
        .is_err());
        let mut conflict = access.clone();
        conflict.inode += 1;
        assert!(selftest_event_in_journals(
            &baseline,
            &placement,
            access.pid,
            started,
            now,
            &status,
            &status,
            &[line(&access), line(&conflict)],
        )
        .is_err());
    }

    #[test]
    fn selftest_detects_restart_loss_stale_status_and_sequence_gaps() {
        let (baseline, placement, mut status, access, now) = selftest_fixture();
        let started = now - chrono::Duration::seconds(1);
        for variant in 0..7 {
            let (_, _, mut changed, _, _) = selftest_fixture();
            match variant {
                0 => changed.canary_stream = "restarted-session".into(),
                1 => changed.canary_dropped = 1,
                2 => changed.canary_sensor = "failed".into(),
                3 => changed.updated = (now - chrono::Duration::seconds(121)).to_rfc3339(),
                4 => changed.canary_sequence = baseline.sequence - 1,
                5 => changed.canary_schema = 99,
                6 => changed.canary_scope = "unknown".into(),
                _ => unreachable!(),
            }
            assert!(
                selftest_event_in_journals(
                    &baseline,
                    &placement,
                    access.pid,
                    started,
                    now,
                    &status,
                    &changed,
                    &[line(&access)],
                )
                .is_err(),
                "variant {variant} accepted unhealthy sensor"
            );
        }
        let mut gap = access.clone();
        gap.sequence += 1;
        assert!(selftest_event_in_journals(
            &baseline,
            &placement,
            access.pid,
            started,
            now,
            &status,
            &status,
            &[line(&gap)],
        )
        .is_err());
        status.canary_sequence = access.sequence;
        assert!(selftest_event_in_journals(
            &baseline,
            &placement,
            access.pid,
            started,
            now,
            &status,
            &status,
            &[],
        )
        .is_err());
    }

    #[test]
    fn selftest_retries_when_status_advances_after_journal_snapshot() {
        let (baseline, placement, before, access, now) = selftest_fixture();
        let (_, _, mut after, _, _) = selftest_fixture();
        after.canary_sequence = access.sequence + 1;
        assert_eq!(
            selftest_event_in_journals(
                &baseline,
                &placement,
                access.pid,
                now - chrono::Duration::seconds(1),
                now,
                &before,
                &after,
                &[line(&access)],
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn selftest_status_requires_bounded_valid_stream_and_monitor_readiness() {
        let (_, _, _, _, now) = selftest_fixture();
        let mut status = serde_json::json!({
            "updated": now.to_rfc3339(), "canary_sensor": "active", "canary_schema": 1,
            "canary_stream": "sensor-session", "canary_sequence": 0, "canary_dropped": 0,
            "canary_scope": "reserved_path_read_opens"
        });
        assert!(selftest_validated_status(&serde_json::to_vec(&status).unwrap(), now).is_ok());
        for offset in [-120_001, 5_001] {
            status["updated"] = (now + chrono::Duration::milliseconds(offset))
                .to_rfc3339()
                .into();
            assert!(selftest_validated_status(&serde_json::to_vec(&status).unwrap(), now).is_err());
        }
        status["updated"] = now.to_rfc3339().into();
        for stream in ["".to_string(), "x".repeat(65), "bad:stream".to_string()] {
            status["canary_stream"] = stream.into();
            assert!(selftest_validated_status(&serde_json::to_vec(&status).unwrap(), now).is_err());
        }
        let mut report = health_fixture();
        report["updated"] = now.to_rfc3339().into();
        assert!(selftest_monitor_ready_at(&serde_json::to_vec(&report).unwrap(), now).is_ok());
        report["state"] = "idle".into();
        report["registered_files"] = 0.into();
        assert!(selftest_monitor_ready_at(&serde_json::to_vec(&report).unwrap(), now).is_ok());
        report["state"] = "starting".into();
        assert!(selftest_monitor_ready_at(&serde_json::to_vec(&report).unwrap(), now).is_err());
        report["state"] = "idle".into();
        report["updated"] = (now - chrono::Duration::seconds(121)).to_rfc3339().into();
        assert!(selftest_monitor_ready_at(&serde_json::to_vec(&report).unwrap(), now).is_err());
        report["updated"] = now.to_rfc3339().into();
        report["issues"] = serde_json::json!(["sensor_dropped_events"]);
        assert!(selftest_monitor_ready_at(&serde_json::to_vec(&report).unwrap(), now).is_err());
    }

    #[test]
    fn short_lived_reader_keeps_event_identity_without_lsof_or_name_exceptions() {
        let mut cursor = Cursor::default();
        let mut seen = Vec::new();
        consume_journal(&line(&event(1)), &[placement()], &mut cursor, |_, event| {
            seen.push((
                event.pid,
                event.audit_token.clone(),
                event.executable.clone(),
            ));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            vec![(
                321,
                "AAECAwQFBgc=".into(),
                "/tmp/hedgehog-backupd-spoof".into()
            )]
        );
    }
    #[test]
    fn durable_ack_precedes_cursor_and_replay_is_idempotent() {
        let bytes = line(&event(1));
        let mut cursor = Cursor::default();
        assert!(
            consume_journal(&bytes, &[placement()], &mut cursor, |_, _| Err(
                "disk full".into()
            ))
            .is_err()
        );
        assert!(cursor.streams.is_empty());
        let mut count = 0;
        consume_journal(&bytes, &[placement()], &mut cursor, |_, _| {
            count += 1;
            Ok(())
        })
        .unwrap();
        let json = serde_json::to_vec(&cursor).unwrap();
        let mut restarted: Cursor = serde_json::from_slice(&json).unwrap();
        consume_journal(&bytes, &[placement()], &mut restarted, |_, _| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn every_placement_matches_by_identity_not_comma_joined_path() {
        let mut other = placement();
        other.identity = Some((12, 99));
        other.id = "second".into();
        let mut event = event(1);
        event.inode = 99;
        let mut seen = Vec::new();
        consume_journal(
            &line(&event),
            &[placement(), other],
            &mut Cursor::default(),
            |placement, _| {
                seen.push(placement.id.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, vec!["second"]);
    }
    #[test]
    fn replacement_inode_never_matches_original() {
        let mut event = event(1);
        event.inode = 777;
        consume_journal(
            &line(&event),
            &[placement()],
            &mut Cursor::default(),
            |_, _| panic!("wrong inode matched"),
        )
        .unwrap();
    }
    #[test]
    fn gaps_and_corrupt_lines_are_reported() {
        let mut cursor = Cursor::default();
        consume_journal(&line(&event(3)), &[], &mut cursor, |_, _| Ok(())).unwrap();
        assert!(cursor.coverage_gap);
        let mut cursor = Cursor::default();
        assert!(consume_journal(b"not-json\n", &[], &mut cursor, |_, _| Ok(())).is_err());
        assert!(cursor.coverage_gap);
    }
    #[test]
    fn partial_tail_is_retried_and_new_session_is_not_discarded() {
        let mut cursor = Cursor::default();
        let mut bytes = line(&event(1));
        bytes.pop();
        consume_journal(&bytes, &[], &mut cursor, |_, _| Ok(())).unwrap();
        assert!(cursor.streams.is_empty());
        bytes.push(b'\n');
        consume_journal(&bytes, &[], &mut cursor, |_, _| Ok(())).unwrap();
        let mut next = event(1);
        next.stream = "new-session".into();
        consume_journal(&line(&next), &[], &mut cursor, |_, _| Ok(())).unwrap();
        assert_eq!(cursor.streams.len(), 2);
        assert!(!cursor.coverage_gap);
    }
    #[test]
    fn stale_future_and_loss_statuses_never_report_active() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut status = SensorStatus {
            updated: now.to_rfc3339(),
            canary_sensor: "active".into(),
            canary_schema: 1,
            canary_stream: "session".into(),
            canary_sequence: 0,
            canary_dropped: 0,
            canary_scope: "reserved_path_read_opens".into(),
        };
        assert!(sensor_issues(&status, now).is_empty());
        status.updated = (now - chrono::Duration::seconds(121)).to_rfc3339();
        assert!(sensor_issues(&status, now).contains(&"sensor_heartbeat_stale"));
        status.updated = (now + chrono::Duration::seconds(6)).to_rfc3339();
        assert!(sensor_issues(&status, now).contains(&"sensor_heartbeat_stale"));
        status.updated = now.to_rfc3339();
        status.canary_dropped = 1;
        assert!(sensor_issues(&status, now).contains(&"sensor_dropped_events"));
    }
    #[test]
    fn legacy_paths_and_missing_files_are_degraded() {
        let mut placement = placement();
        placement.identity = None;
        assert_eq!(
            placement_issue(&placement),
            Some("placement_requires_redeployment")
        );
        placement.identity = Some((12, 34));
        assert_eq!(
            placement_issue(&placement),
            Some("placement_missing_or_unreadable")
        );
        assert!(!reserved_path(Path::new(".env")));
        assert!(!reserved_path(Path::new(".hedgehog-canary-not-an-id.txt")));
    }

    #[test]
    fn disappeared_registry_stays_degraded_after_restart_but_explicit_empty_is_valid() {
        let mut cursor = Cursor::default();
        assert_eq!(registry_observation(&mut cursor, false, false), None);
        assert_eq!(registry_observation(&mut cursor, true, true), None);
        assert_eq!(
            registry_observation(&mut cursor, false, false),
            Some("registry_missing_after_registration")
        );
        let mut restarted: Cursor =
            serde_json::from_slice(&serde_json::to_vec(&cursor).unwrap()).unwrap();
        assert_eq!(
            registry_observation(&mut restarted, false, false),
            Some("registry_missing_after_registration")
        );
        assert_eq!(registry_observation(&mut restarted, true, false), None);
        assert!(!restarted.registry_expected);
        // Existing checkpoints from before the witness field still decode.
        let legacy: Cursor =
            serde_json::from_str(r#"{"streams":{},"coverage_gap":false}"#).unwrap();
        assert!(!legacy.registry_expected);
    }

    fn health_fixture() -> serde_json::Value {
        serde_json::json!({
            "updated":"2026-09-05T12:00:00Z", "state":"active", "issues":[],
            "registered_files":2, "scope":"reserved_path_read_opens",
        })
    }

    #[test]
    fn fresh_report_labels_the_observed_scope_without_inferring_delivery() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let lines = render_status_report(&serde_json::to_vec(&health_fixture()).unwrap(), now);
        assert_eq!(
            lines[0],
            "Canary monitor: active (last reported state; fresh within 120 seconds)"
        );
        assert!(lines
            .iter()
            .any(|line| line.contains("does not prove exfiltration prevention or alarm delivery")));
        let mut degraded = health_fixture();
        degraded["state"] = "degraded".into();
        degraded["issues"] = serde_json::json!(["sensor_dropped_events"]);
        let lines = render_status_report(&serde_json::to_vec(&degraded).unwrap(), now);
        assert!(lines[0].starts_with("Canary monitor: degraded"));
        assert!(lines
            .iter()
            .any(|line| line == "Canary monitor issues: sensor_dropped_events"));
    }

    #[test]
    fn heartbeat_never_claims_healthy_for_idle_missing_invalid_or_stale_sensor() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let report = health_fixture();
        assert_eq!(
            heartbeat_health_at(&serde_json::to_vec(&report).unwrap(), now),
            "healthy"
        );
        assert_eq!(heartbeat_health_at(b"{}", now), "unverified");
        for state in ["idle", "starting", "degraded"] {
            let mut changed = report.clone();
            changed["state"] = state.into();
            changed["registered_files"] = 0.into();
            assert_ne!(
                heartbeat_health_at(&serde_json::to_vec(&changed).unwrap(), now),
                "healthy"
            );
        }
        for milliseconds in [-120_001, 5_001] {
            let mut changed = report.clone();
            changed["updated"] = (now + chrono::Duration::milliseconds(milliseconds))
                .to_rfc3339()
                .into();
            assert_eq!(
                heartbeat_health_at(&serde_json::to_vec(&changed).unwrap(), now),
                "degraded"
            );
        }
    }

    #[test]
    fn stale_and_future_monitor_reports_are_degraded_including_fractional_boundaries() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for milliseconds in [-120_001, -121_000, 5_001, 6_000] {
            let mut report = health_fixture();
            report["updated"] = (now + chrono::Duration::milliseconds(milliseconds))
                .to_rfc3339()
                .into();
            let lines = render_status_report(&serde_json::to_vec(&report).unwrap(), now);
            assert_eq!(
                lines[0],
                "Canary monitor: degraded (local sensor report is stale or future-dated)"
            );
        }
    }

    #[test]
    fn malformed_or_inconsistent_reports_never_echo_untrusted_states_or_issues() {
        let now = chrono::Utc::now();
        let mut invalid_reports = vec![serde_json::json!({})];
        for (field, value) in [
            ("state", serde_json::json!("forged\nACTIVE")),
            ("scope", serde_json::json!("all_exfiltration_blocked")),
            ("issues", serde_json::json!(["forged\nACTIVE"])),
            ("updated", serde_json::json!("not-a-time")),
            ("registered_files", serde_json::json!(-1)),
            ("registered_files", serde_json::json!(0)),
        ] {
            let mut report = health_fixture();
            report[field] = value;
            invalid_reports.push(report);
        }
        for report in invalid_reports {
            let lines = render_status_report(&serde_json::to_vec(&report).unwrap(), now);
            assert_eq!(
                lines[0],
                "Canary monitor: unverified (invalid local sensor report)"
            );
            assert!(!lines.join("\n").contains("forged"));
        }
        assert!(render_status_report(b"broken-json", now)[0].contains("unverified"));
    }

    #[test]
    fn missing_report_is_unverified_and_atomic_private_report_is_readable() {
        let directory = std::env::temp_dir().join(format!(
            "hedgehog-health-status-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("status.json");
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            status_lines_at(&path, now)[0],
            "Canary monitor: unverified (no local sensor report)"
        );
        write_private_json(&path, &health_fixture()).unwrap();
        assert!(status_lines_at(&path, now)[0].starts_with("Canary monitor: active"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let link = directory.join("link");
            symlink(&path, &link).unwrap();
            assert_eq!(
                status_lines_at(&link, now)[0],
                "Canary monitor: unverified (local sensor report cannot be read safely)"
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert_eq!(
                status_lines_at(&path, now)[0],
                "Canary monitor: unverified (local sensor report cannot be read safely)"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn untrusted_log_and_symlink_are_rejected() {
        use std::os::unix::fs::symlink;
        let directory =
            std::env::temp_dir().join(format!("hedgehog-sensor-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("journal");
        std::fs::write(&file, b"test").unwrap();
        assert!(read_trusted(&file, 100).is_err());
        let link = directory.join("link");
        symlink(&file, &link).unwrap();
        assert!(read_private(&link, 100).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replacement_and_hardlink_aliases_degrade_file_health() {
        use std::os::unix::fs::MetadataExt;
        let directory = std::env::temp_dir().join(format!(
            "hedgehog-sensor-identity-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut placement = placement();
        placement.path = directory.join(placement.path.file_name().unwrap());
        std::fs::write(&placement.path, b"synthetic fixture").unwrap();
        let metadata = std::fs::metadata(&placement.path).unwrap();
        placement.identity = Some((metadata.dev(), metadata.ino()));
        assert_eq!(placement_issue(&placement), None);
        let alias = directory.join("alias");
        std::fs::hard_link(&placement.path, &alias).unwrap();
        assert_eq!(
            placement_issue(&placement),
            Some("placement_has_unmonitored_aliases")
        );
        std::fs::remove_file(&placement.path).unwrap();
        std::fs::write(&placement.path, b"replacement").unwrap();
        assert_eq!(placement_issue(&placement), Some("placement_replaced"));
        std::fs::remove_file(&placement.path).unwrap();
        assert_eq!(
            placement_issue(&placement),
            Some("placement_missing_or_unreadable")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn only_one_monitor_advances_a_cursor() {
        let path = std::env::temp_dir().join(format!(
            "hedgehog-sensor-lock-{:016x}",
            rand::random::<u64>()
        ));
        let first = acquire_monitor_lock(&path).unwrap();
        assert!(acquire_monitor_lock(&path).is_err());
        drop(first);
        drop(acquire_monitor_lock(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }
}
