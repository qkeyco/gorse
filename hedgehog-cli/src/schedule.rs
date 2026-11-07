// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Scheduled exposure checks with change detection.
//!
//! `gorse schedule set daily|hourly|off` installs or removes an entry in the
//! platform scheduler (launchd, systemd user timers or Task Scheduler) that
//! runs `gorse schedule run`. Each run records the full exposure report under
//! `~/.hedgehog/exposure/history/`, compares it with the previous recorded
//! run and sends a desktop notification when something new or worse appears.
//! `gorse exposure --record` feeds a manual check into the same history so a
//! check started from the app also counts.
//!
//! Nothing here ever prints, logs or stores secret values: the report JSON
//! carries fingerprints and metadata only, and notifications carry counts.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Subcommand, ValueEnum};
use hedgehog_taint::tier::Tier;

pub const UPGRADE_URL: &str = "https://www.gorse.is/pricing";
pub const REQUIRES_PRO: &str =
    "Scheduled checks are part of Gorse Pro. See https://www.gorse.is/pricing";
const LICENCE_REQUIRED: &str = "licence required";
/// The status message a scheduled run leaves when this program is not one
/// QKey signed.
pub const UNTRUSTED_PROGRAM: &str = "program is not signed by QKey; schedule refused";
/// Apple Developer Team ID of QKey Co. (James Tagg), the only signer a
/// scheduled check will run as.
pub const QKEY_TEAM_ID: &str = "4H5SCV7U38";

/// How many recorded runs to keep.
pub const HISTORY_KEEP: usize = 90;
/// Entries kept per change list in a run file.
pub const CHANGE_LIST_CAP: usize = 50;
/// The scheduler log is truncated once it passes this size.
const LOG_LIMIT_BYTES: u64 = 1024 * 1024;

// The platform names and the pure text generators below are all compiled
// everywhere (so their tests run on every platform) but each is only called
// on its own operating system.
pub const LAUNCHD_LABEL: &str = "is.hedgehog.schedule";
#[allow(dead_code)]
pub const SYSTEMD_UNIT: &str = "gorse-schedule";
#[allow(dead_code)]
pub const WINDOWS_TASK: &str = "Gorse Scheduled Check";

#[derive(Subcommand)]
pub enum ScheduleCommand {
    /// Turn scheduled checks on (daily at 09:30, or hourly) or off (Pro)
    Set {
        /// off, daily or hourly
        frequency: Frequency,
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
    },
    /// Show whether scheduled checks are on and what the last run found
    Status {
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
    },
    /// Run one scheduled check now (what the scheduler invokes)
    Run {
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
    },
    /// Accept the latest recorded check as the baseline, even if it is
    /// incomplete; later checks are compared with it and its missing
    /// coverage is no longer reported as lost
    AcceptBaseline {
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
    },
    /// List recorded checks, newest first, with what changed in each
    History {
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
        /// How many runs to show
        #[arg(long, default_value = "30")]
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Frequency {
    Off,
    Daily,
    Hourly,
}

impl Frequency {
    pub fn label(self) -> &'static str {
        match self {
            Frequency::Off => "off",
            Frequency::Daily => "daily",
            Frequency::Hourly => "hourly",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Frequency::Off),
            "daily" => Some(Frequency::Daily),
            "hourly" => Some(Frequency::Hourly),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Scheduled,
    Manual,
}

impl Trigger {
    pub fn label(self) -> &'static str {
        match self {
            Trigger::Scheduled => "scheduled",
            Trigger::Manual => "manual",
        }
    }
}

// ─── Paths ───────────────────────────────────────────────────────────────────

/// `~/.hedgehog/exposure`: schedule.json, status.json, schedule.log and the
/// history folder live here. Follows the config directory, so a test home
/// isolates it.
pub fn exposure_dir() -> PathBuf {
    crate::config::config_dir().join("exposure")
}

pub fn history_dir() -> PathBuf {
    exposure_dir().join("history")
}

pub fn schedule_path() -> PathBuf {
    exposure_dir().join("schedule.json")
}

pub fn status_path() -> PathBuf {
    exposure_dir().join("status.json")
}

pub fn log_path() -> PathBuf {
    exposure_dir().join("schedule.log")
}

/// `exposure_dir/baseline.json`: the run the user accepted as the baseline
/// with `gorse schedule accept-baseline`. Kept apart from the run itself so
/// a recorded (and possibly stamped) run file is never modified.
pub fn accepted_baseline_path_in(exposure_dir: &Path) -> PathBuf {
    exposure_dir.join("baseline.json")
}

/// Create a directory (and parents) readable by this user only.
fn create_private_dir(path: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

/// Write a JSON document atomically (temp file, then rename), user-only.
fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    crate::encrypted_store::write_private_atomic(path, text.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

// ─── Change detection ────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeEntry {
    pub kind: String,
    pub name: String,
    pub location: String,
    pub severity: String,
    pub previous_severity: Option<String>,
    /// Why an `unassessed` finding could not be reassessed.
    pub reason: Option<String>,
}

impl ChangeEntry {
    fn json(&self) -> serde_json::Value {
        let mut o = serde_json::json!({
            "kind": self.kind,
            "name": self.name,
            "location": self.location,
            "severity": self.severity,
        });
        if let Some(prev) = &self.previous_severity {
            o["previous_severity"] = serde_json::Value::String(prev.clone());
        }
        if let Some(reason) = &self.reason {
            o["reason"] = serde_json::Value::String(reason.clone());
        }
        o
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub new: Vec<ChangeEntry>,
    pub worsened: Vec<ChangeEntry>,
    pub resolved: Vec<ChangeEntry>,
    pub improved: Vec<ChangeEntry>,
    /// Previous findings missing now whose discovery source this run did
    /// not assess (a file it could not interpret). Never resolved: nobody
    /// looked.
    pub unassessed: Vec<ChangeEntry>,
    /// Counts before the lists were capped.
    pub new_count: usize,
    pub worsened_count: usize,
    pub resolved_count: usize,
    pub improved_count: usize,
    pub unassessed_count: usize,
    /// One coverage failure per source behind `unassessed`; added to the
    /// recorded report so it is incomplete and never becomes the baseline.
    pub unassessed_failures: Vec<crate::exposure::CoverageFailure>,
    /// No previous run to compare with.
    pub first_run: bool,
    /// The current run could not read every known credential location.
    /// Nothing is reported as resolved from such a run: a finding that is
    /// missing may simply be in the file that could not be read.
    pub incomplete: bool,
    /// Locations the current run could not read.
    pub coverage_failures: usize,
    /// The previous (complete) run read everything and this one did not:
    /// an unattended check silently losing coverage is itself a risk, so
    /// it is notified like a new finding.
    pub coverage_lost: bool,
}

impl Changes {
    /// A notification is due when something is new or worse, or coverage
    /// was lost, and there was a previous run to compare with.
    pub fn notify(&self) -> bool {
        !self.first_run && (self.new_count > 0 || self.worsened_count > 0 || self.coverage_lost)
    }

    pub fn json(&self) -> serde_json::Value {
        let list = |v: &Vec<ChangeEntry>| v.iter().map(ChangeEntry::json).collect::<Vec<_>>();
        serde_json::json!({
            "first_run": self.first_run,
            "notify": self.notify(),
            "incomplete": self.incomplete,
            "coverage_failures": self.coverage_failures,
            "coverage_lost": self.coverage_lost,
            "counts": {
                "new": self.new_count,
                "worsened": self.worsened_count,
                "resolved": self.resolved_count,
                "improved": self.improved_count,
                "unassessed": self.unassessed_count,
            },
            "new": list(&self.new),
            "worsened": list(&self.worsened),
            "resolved": list(&self.resolved),
            "improved": list(&self.improved),
            "unassessed": list(&self.unassessed),
        })
    }

    /// The worst severity among what is new or worse, as a label.
    pub fn highest_severity(&self) -> Option<&'static str> {
        self.new
            .iter()
            .chain(self.worsened.iter())
            .map(|e| severity_rank(&e.severity))
            .max()
            .map(severity_label)
    }
}

/// Critical > High > Medium > Low; unknown labels rank below Low.
pub fn severity_rank(label: &str) -> u8 {
    match label.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_label(rank: u8) -> &'static str {
    match rank {
        4 => "Critical",
        3 => "High",
        2 => "Medium",
        1 => "Low",
        _ => "Unknown",
    }
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Identity of a finding across runs: `(kind, location, fingerprint)`.
fn finding_key(f: &serde_json::Value) -> (String, String, String) {
    (
        str_field(f, "kind"),
        str_field(f, "location"),
        str_field(f, "fingerprint"),
    )
}

fn entry_of(f: &serde_json::Value, previous_severity: Option<String>) -> ChangeEntry {
    ChangeEntry {
        kind: str_field(f, "kind"),
        name: str_field(f, "name"),
        location: str_field(f, "location"),
        severity: str_field(f, "severity"),
        previous_severity,
        reason: None,
    }
}

/// The discovery sources a report assessed. `None` for a report written
/// before sources were recorded: change detection then falls back to the
/// complete/incomplete rule alone.
fn sources_assessed(report: &serde_json::Value) -> Option<Vec<String>> {
    report.get("sources_assessed")?.as_array().map(|a| {
        a.iter()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect()
    })
}

/// Why a report did not assess `source`.
fn unavailable_reason(report: &serde_json::Value, source: &str) -> String {
    report
        .get("sources_unavailable")
        .and_then(|u| u.as_array())
        .and_then(|list| {
            list.iter()
                .find(|u| u.get("source").and_then(|s| s.as_str()) == Some(source))
        })
        .and_then(|u| u.get("reason").and_then(|r| r.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| "it did not run".to_string())
}

/// Mark a report incomplete with the coverage failures for sources a
/// previous run assessed and this one did not. A no-op when there are none.
pub fn apply_unassessed(report: &mut serde_json::Value, changes: &Changes) {
    if changes.unassessed_failures.is_empty() {
        return;
    }
    report["incomplete"] = serde_json::Value::Bool(true);
    if !report
        .get("coverage_failures")
        .is_some_and(|c| c.is_array())
    {
        report["coverage_failures"] = serde_json::json!([]);
    }
    if let Some(list) = report["coverage_failures"].as_array_mut() {
        for f in &changes.unassessed_failures {
            list.push(serde_json::json!({"location": f.location, "reason": f.reason}));
        }
    }
}

fn findings_of(report: &serde_json::Value) -> Vec<&serde_json::Value> {
    report
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

/// Whether a recorded report could not read every credential location.
pub fn is_incomplete(report: &serde_json::Value) -> bool {
    report
        .get("incomplete")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn coverage_failure_count(report: &serde_json::Value) -> usize {
    report
        .get("coverage_failures")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

/// Compare a report with the previous recorded one (`None` on the first
/// run). Findings are matched on `(kind, location, fingerprint)`.
///
/// A previous finding that is missing now is `resolved` only when its
/// discovery `source` is among the current run's `sources_assessed`.
/// Otherwise nobody looked: it is `unassessed`, never resolved, and the
/// run becomes incomplete with a coverage failure per such source (see
/// [`apply_unassessed`]) so it never becomes the baseline.
///
/// When the current report is incomplete (a known location could not be
/// read) nothing is reported as resolved: the missing finding may be in
/// the unreadable file. New and worsened findings are still real and are
/// still reported.
pub fn diff(previous: Option<&serde_json::Value>, current: &serde_json::Value) -> Changes {
    let incomplete = is_incomplete(current);
    let mut changes = Changes {
        first_run: previous.is_none(),
        incomplete,
        coverage_failures: coverage_failure_count(current),
        ..Default::default()
    };
    let assessed_now = sources_assessed(current);
    let now: Vec<_> = findings_of(current);
    let before: Vec<_> = previous.map(findings_of).unwrap_or_default();
    let before_by_key: std::collections::HashMap<_, _> =
        before.iter().map(|f| (finding_key(f), *f)).collect();
    let now_keys: std::collections::HashSet<_> = now.iter().map(|f| finding_key(f)).collect();

    let push = |list: &mut Vec<ChangeEntry>, count: &mut usize, entry: ChangeEntry| {
        *count += 1;
        if list.len() < CHANGE_LIST_CAP {
            list.push(entry);
        }
    };

    for f in &now {
        match before_by_key.get(&finding_key(f)) {
            None => push(&mut changes.new, &mut changes.new_count, entry_of(f, None)),
            Some(old) => {
                let old_sev = str_field(old, "severity");
                let now_rank = severity_rank(&str_field(f, "severity"));
                let old_rank = severity_rank(&old_sev);
                if now_rank > old_rank {
                    push(
                        &mut changes.worsened,
                        &mut changes.worsened_count,
                        entry_of(f, Some(old_sev)),
                    );
                } else if now_rank < old_rank {
                    push(
                        &mut changes.improved,
                        &mut changes.improved_count,
                        entry_of(f, Some(old_sev)),
                    );
                }
            }
        }
    }
    let mut unassessed_sources: Vec<(String, String)> = Vec::new();
    for f in &before {
        if now_keys.contains(&finding_key(f)) {
            continue;
        }
        let mut source = str_field(f, "source");
        // Runs recorded before the agent became its own source filed its
        // identities under `ssh`.
        if source == "ssh" && str_field(f, "kind") == "SshAgentIdentity" {
            source = "ssh-agent".into();
        }
        let reassessed = match &assessed_now {
            // Recorded by a version that did not name sources: the
            // complete/incomplete rule alone decides.
            _ if source.is_empty() => true,
            None => true,
            Some(now) => now.contains(&source),
        };
        if !reassessed {
            let reason = unavailable_reason(current, &source);
            let mut entry = entry_of(f, None);
            entry.reason = Some(reason.clone());
            push(
                &mut changes.unassessed,
                &mut changes.unassessed_count,
                entry,
            );
            if !unassessed_sources.iter().any(|(s, _)| *s == source) {
                unassessed_sources.push((source, reason));
            }
        } else if !incomplete {
            push(
                &mut changes.resolved,
                &mut changes.resolved_count,
                entry_of(f, None),
            );
        }
    }
    // A source that is unavailable because of a coverage failure the report
    // already lists (an unreadable file) needs no second entry.
    let listed: Vec<String> = current
        .get("coverage_failures")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("location").and_then(|l| l.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for (source, reason) in unassessed_sources {
        let explained = listed.iter().any(|l| reason.contains(l.as_str()));
        if explained {
            changes.incomplete = true;
            continue;
        }
        changes
            .unassessed_failures
            .push(crate::exposure::CoverageFailure {
                location: format!("{source} (source)"),
                reason: format!("source {source} was not assessed in this run ({reason})"),
            });
    }
    if !changes.unassessed_failures.is_empty() {
        changes.incomplete = true;
        changes.coverage_failures += changes.unassessed_failures.len();
    }
    changes.coverage_lost = changes.incomplete && previous.is_some_and(|p| !is_incomplete(p));
    changes
}

// ─── History ─────────────────────────────────────────────────────────────────

/// Severity counts from a report's `summary.by_severity`.
pub fn counts_of(report: &serde_json::Value) -> serde_json::Value {
    let by = report.get("summary").and_then(|s| s.get("by_severity"));
    let n = |k: &str| {
        by.and_then(|b| b.get(k))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    serde_json::json!({
        "critical": n("critical"),
        "high": n("high"),
        "medium": n("medium"),
        "low": n("low"),
    })
}

/// History files, newest first (names are UTC timestamps, so name order is
/// time order).
pub fn history_files() -> Vec<PathBuf> {
    history_files_in(&history_dir())
}

/// [`history_files`] for an explicit history directory.
fn history_files_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.chars().next().is_some_and(|c| c.is_ascii_digit()))
        })
        .collect();
    files.sort();
    files.reverse();
    files
}

/// The baseline for change detection: the newest recorded run that read
/// every credential location. Incomplete runs are kept in the history but
/// never become the baseline, so a later complete run is compared with the
/// last complete one and a finding that briefly vanished behind a
/// permission error is not reported as resolved and then new again.
///
/// The run the user accepted with `gorse schedule accept-baseline` (named
/// by `accepted`, read from `baseline.json`) is a baseline even when it is
/// incomplete, until a newer complete run exists. A run file from an older
/// version that carries `accepted_by_user: true` itself counts the same way.
pub fn baseline_file(
    files: &[PathBuf],
    accepted: Option<&str>,
) -> Option<(PathBuf, serde_json::Value)> {
    files.iter().find_map(|p| {
        let run = read_json(p)?;
        (!is_incomplete(&run) || is_accepted(p, &run, accepted)).then(|| (p.clone(), run))
    })
}

/// Whether the user accepted a recorded run as the baseline: it is the run
/// named in `baseline.json`, or (histories from older versions) the run
/// file itself carries `accepted_by_user: true`.
fn is_accepted(path: &Path, report: &serde_json::Value, accepted: Option<&str>) -> bool {
    let named = accepted.is_some_and(|name| {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == name)
    });
    named
        || report
            .get("accepted_by_user")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
}

/// The run file name recorded in `exposure_dir/baseline.json`, if the user
/// accepted one. Anything that is not a plain file name is ignored.
pub fn accepted_baseline_in(exposure_dir: &Path) -> Option<String> {
    let record = read_json(&accepted_baseline_path_in(exposure_dir))?;
    if record.get("accepted_by_user").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let file = record.get("file")?.as_str()?;
    let plain = !file.is_empty()
        && Path::new(file).file_name().and_then(|n| n.to_str()) == Some(file)
        && !file.contains(['/', '\\']);
    plain.then(|| file.to_string())
}

/// Accept the newest recorded run in `exposure_dir/history` as the
/// baseline, even if it is incomplete: later runs are compared with it
/// until a newer complete run exists. The run file is never modified (a
/// stamped run's checksum must still recompute); the acceptance is written
/// to `exposure_dir/baseline.json` instead. Returns the run file's name.
pub fn accept_baseline_in(exposure_dir: &Path) -> Result<String, String> {
    let files = history_files_in(&exposure_dir.join("history"));
    let latest = files.first().ok_or_else(|| {
        "No recorded check to accept: run `gorse exposure --record` first.".to_string()
    })?;
    read_json(latest)
        .filter(|run| run.is_object())
        .ok_or_else(|| {
            format!(
                "Could not read the latest recorded check ({})",
                latest.display()
            )
        })?;
    let file = latest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "The latest recorded check has no usable file name".to_string())?
        .to_string();
    let record = serde_json::json!({
        "file": file,
        "accepted_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "accepted_by_user": true,
    });
    write_json_atomic(&accepted_baseline_path_in(exposure_dir), &record)?;
    Ok(file)
}

/// Keep the newest `keep` history files in `dir`; delete the rest.
pub fn prune_history(dir: &Path, keep: usize) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files.reverse();
    let mut removed = 0;
    for old in files.iter().skip(keep) {
        if std::fs::remove_file(old).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// A free name for a run file: `<stamp>.json`, or `<stamp>_N.json` when a
/// run already landed in the same second (`_` sorts after `.`, so the later
/// run stays newest).
fn run_file_name(dir: &Path, stamp: &str) -> PathBuf {
    let plain = dir.join(format!("{stamp}.json"));
    if !plain.exists() {
        return plain;
    }
    (1..)
        .map(|n| dir.join(format!("{stamp}_{n}.json")))
        .find(|p| !p.exists())
        .expect("unbounded")
}

/// What a recorded run leaves in `status.json`.
#[derive(Clone, Debug)]
pub struct RunRecord {
    pub at: String,
    pub ok: bool,
    pub counts: serde_json::Value,
    pub changes: Changes,
    pub trigger: Trigger,
    pub message: String,
    pub file: Option<String>,
    /// The run file this one was compared with (the last complete run).
    pub baseline: Option<String>,
}

impl RunRecord {
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "at": self.at,
            "ok": self.ok,
            "incomplete": self.changes.incomplete,
            "coverage_failures": self.changes.coverage_failures,
            "trigger": self.trigger.label(),
            "counts": self.counts,
            "new": self.changes.new_count,
            "worsened": self.changes.worsened_count,
            "resolved": self.changes.resolved_count,
            "improved": self.changes.improved_count,
            "unassessed": self.changes.unassessed_count,
            "first_run": self.changes.first_run,
            "notify": self.changes.notify(),
            "message": self.message,
            "file": self.file,
            "baseline": self.baseline,
        })
    }
}

/// The status message of a run that could not read every location.
pub fn incomplete_message(failures: usize) -> String {
    format!("incomplete: {failures} location(s) could not be read")
}

/// `status.json`: the last run plus the configured frequency.
fn write_status(record: &RunRecord) -> Result<(), String> {
    write_status_in(&exposure_dir(), record)
}

fn write_status_in(exposure_dir: &Path, record: &RunRecord) -> Result<(), String> {
    let mut status = record.json();
    let frequency = read_json(&exposure_dir.join("schedule.json"))
        .and_then(|s| {
            s.get("frequency")
                .and_then(|f| f.as_str())
                .and_then(Frequency::parse)
        })
        .unwrap_or(Frequency::Off);
    status["frequency"] = serde_json::Value::String(frequency.label().to_string());
    write_json_atomic(&exposure_dir.join("status.json"), &status)
}

/// Record a failed run (the check could not start or finish).
pub fn record_failure(trigger: Trigger, message: &str) -> RunRecord {
    let record = RunRecord {
        at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ok: false,
        counts: serde_json::json!({"critical": 0, "high": 0, "medium": 0, "low": 0}),
        changes: Changes::default(),
        trigger,
        message: message.to_string(),
        file: None,
        baseline: None,
    };
    if let Err(e) = write_status(&record) {
        eprintln!("Could not write the schedule status: {e}");
    }
    record
}

/// Record a completed exposure report: write the run file, prune the
/// history, update `status.json` and notify when something new or worse
/// appeared. Returns the record; notification and pruning never fail the
/// run.
///
/// A report that could not read every credential location is recorded
/// with `ok: false` and an `incomplete:` message, is compared with the
/// last complete run (never with another incomplete one), reports nothing
/// as resolved, and does not become the baseline for later runs.
pub fn record_run(mut report: serde_json::Value, trigger: Trigger) -> Result<RunRecord, String> {
    let pending = begin_record(&exposure_dir(), &report, trigger)?;
    apply_unassessed(&mut report, &pending.changes);
    report["recorded_at"] = serde_json::Value::String(pending.at.clone());
    report["trigger"] = serde_json::Value::String(trigger.label().to_string());
    report["changes"] = pending.changes.json();
    finish_record(pending, &report, true)
}

/// A run compared with the history but not yet written: the first half of
/// recording, so a caller can fold the comparison (lost coverage, findings
/// not assessed) into its report before rendering and stamping it, and
/// then store exactly the document it emits.
#[derive(Clone, Debug)]
pub struct PendingRecord {
    exposure_dir: PathBuf,
    path: PathBuf,
    baseline: Option<PathBuf>,
    pub changes: Changes,
    /// RFC 3339 UTC time the run is recorded at.
    pub at: String,
    pub trigger: Trigger,
}

/// Compare `report` with the last complete run in `exposure_dir/history`.
/// Nothing is written.
pub fn begin_record(
    exposure_dir: &Path,
    report: &serde_json::Value,
    trigger: Trigger,
) -> Result<PendingRecord, String> {
    let dir = exposure_dir.join("history");
    create_private_dir(&dir)?;
    let accepted = accepted_baseline_in(exposure_dir);
    let baseline = baseline_file(&history_files_in(&dir), accepted.as_deref());
    let changes = diff(baseline.as_ref().map(|(_, run)| run), report);
    let now = chrono::Utc::now();
    let at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    Ok(PendingRecord {
        exposure_dir: exposure_dir.to_path_buf(),
        path: run_file_name(&dir, &stamp),
        baseline: baseline.map(|(p, _)| p),
        changes,
        at,
        trigger,
    })
}

/// Write `report` (the final document, already carrying `recorded_at`,
/// `trigger` and `changes`) as the run file, prune the history, update
/// `status.json` and, when `notify` is set and something is new or worse,
/// notify.
pub fn finish_record(
    pending: PendingRecord,
    report: &serde_json::Value,
    notify_user: bool,
) -> Result<RunRecord, String> {
    let dir = pending.exposure_dir.join("history");
    write_json_atomic(&pending.path, report)?;

    let file_name = |p: &Path| {
        p.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    };
    let changes = pending.changes;
    let record = RunRecord {
        at: pending.at,
        ok: !changes.incomplete,
        counts: counts_of(report),
        message: if changes.incomplete {
            incomplete_message(changes.coverage_failures)
        } else {
            "ok".into()
        },
        changes,
        trigger: pending.trigger,
        file: file_name(&pending.path),
        baseline: pending.baseline.as_deref().and_then(file_name),
    };
    if let Err(e) = write_status_in(&pending.exposure_dir, &record) {
        // All or nothing: a run whose status could not be written is taken
        // back out of the history, so the caller can report it unrecorded.
        let _ = std::fs::remove_file(&pending.path);
        return Err(e);
    }
    prune_history(&dir, HISTORY_KEEP);
    if notify_user && record.changes.notify() {
        notify(&record.changes);
    }
    Ok(record)
}

// ─── Notification ────────────────────────────────────────────────────────────

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// The notification text: counts and the worst severity only. Never a
/// name, location or fingerprint.
pub fn notification_body(changes: &Changes) -> String {
    let mut parts = Vec::new();
    if changes.new_count > 0 {
        parts.push(plural(changes.new_count, "new finding"));
    }
    if changes.worsened_count > 0 {
        parts.push(format!("{} worsened", changes.worsened_count));
    }
    let mut body = String::new();
    if !parts.is_empty() {
        body.push_str(&parts.join(", "));
        body.push('.');
        if let Some(sev) = changes.highest_severity() {
            body.push_str(&format!(" Highest: {sev}."));
        }
    }
    if changes.coverage_lost {
        if !body.is_empty() {
            body.push(' ');
        }
        if changes.unassessed_count > 0 {
            body.push_str(&format!(
                "{} could not be reassessed; ",
                plural(changes.unassessed_count, "earlier finding")
            ));
        }
        if changes.unassessed_failures.is_empty() {
            body.push_str(&format!(
                "Gorse could not read {}; the check is incomplete.",
                plural(changes.coverage_failures, "credential location")
            ));
        } else {
            body.push_str(&format!(
                "Gorse could not read or assess {}; the check is incomplete.",
                plural(changes.coverage_failures, "credential location or source")
            ));
        }
    }
    body.push_str(" Open Gorse to review.");
    body
}

/// Quote a string for an AppleScript literal.
pub fn applescript_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Send a desktop notification, best effort. Spawns and never blocks the
/// run for more than five seconds.
pub fn notify(changes: &Changes) {
    let body = notification_body(changes);
    let subtitle = if changes.new_count == 0 && changes.worsened_count == 0 {
        "Exposure check: incomplete"
    } else {
        "Exposure check: something changed"
    };
    let mut command = if cfg!(target_os = "macos") {
        let script = format!(
            "display notification \"{}\" with title \"Gorse\" subtitle \"{}\"",
            applescript_escape(&body),
            applescript_escape(subtitle)
        );
        let mut c = Command::new("osascript");
        c.arg("-e").arg(script);
        c
    } else if cfg!(target_os = "linux") {
        let mut c = Command::new("notify-send");
        c.arg("Gorse").arg(&body);
        c
    } else if cfg!(windows) {
        // BurntToast is the one widely installed toast module; without it
        // the command is a no-op rather than a modal dialog.
        let ps = format!(
            "if (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue) {{ New-BurntToastNotification -Text 'Gorse', '{}' }}",
            body.replace('\'', "''")
        );
        let mut c = Command::new("powershell");
        c.args(["-NoProfile", "-NonInteractive", "-Command", &ps]);
        c
    } else {
        return;
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return;
    };
    // Reap or kill in the background; the run does not wait on it.
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
    });
}

// ─── Platform schedulers ─────────────────────────────────────────────────────

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "launchd"
    } else if cfg!(windows) {
        "schtasks"
    } else {
        "systemd"
    }
}

/// The program the scheduler runs: this executable, by absolute path (the
/// Mac app ships the CLI inside its bundle).
pub fn program_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this program: {e}"))?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// launchd agent that runs `<program> schedule run`.
#[allow(dead_code)]
pub fn launchd_plist(program: &Path, log: &Path, frequency: Frequency) -> String {
    let when = match frequency {
        Frequency::Hourly => "\t<key>StartInterval</key>\n\t<integer>3600</integer>\n".to_string(),
        _ => "\t<key>StartCalendarInterval</key>\n\t<dict>\n\t\t<key>Hour</key>\n\t\t<integer>9</integer>\n\t\t<key>Minute</key>\n\t\t<integer>30</integer>\n\t</dict>\n".to_string(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>Label</key>\n\
\t<string>{label}</string>\n\
\t<key>ProgramArguments</key>\n\
\t<array>\n\
\t\t<string>{program}</string>\n\
\t\t<string>schedule</string>\n\
\t\t<string>run</string>\n\
\t</array>\n\
{when}\
\t<key>RunAtLoad</key>\n\
\t<false/>\n\
\t<key>ProcessType</key>\n\
\t<string>Background</string>\n\
\t<key>StandardOutPath</key>\n\
\t<string>{log}</string>\n\
\t<key>StandardErrorPath</key>\n\
\t<string>{log}</string>\n\
</dict>\n\
</plist>\n",
        label = LAUNCHD_LABEL,
        program = xml_escape(&program.display().to_string()),
        log = xml_escape(&log.display().to_string()),
    )
}

/// systemd user service that runs `<program> schedule run`.
#[allow(dead_code)]
pub fn systemd_service(program: &Path, log: &Path) -> String {
    format!(
        "[Unit]\n\
Description=Gorse scheduled exposure check\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart={program} schedule run\n\
StandardOutput=append:{log}\n\
StandardError=append:{log}\n",
        program = program.display(),
        log = log.display(),
    )
}

/// systemd user timer for the service.
#[allow(dead_code)]
pub fn systemd_timer(frequency: Frequency) -> String {
    let on = match frequency {
        Frequency::Hourly => "hourly",
        _ => "*-*-* 09:30:00",
    };
    format!(
        "[Unit]\n\
Description=Run the Gorse exposure check on a schedule\n\
\n\
[Timer]\n\
OnCalendar={on}\n\
Persistent=true\n\
\n\
[Install]\n\
WantedBy=timers.target\n"
    )
}

/// Arguments for `schtasks` that create the task.
#[allow(dead_code)]
pub fn schtasks_create_args(program: &Path, frequency: Frequency) -> Vec<String> {
    let run = format!("\"{}\" schedule run", program.display());
    let mut args = vec![
        "/Create".to_string(),
        "/TN".into(),
        WINDOWS_TASK.into(),
        "/TR".into(),
        run,
        "/SC".into(),
    ];
    match frequency {
        Frequency::Hourly => args.extend(["HOURLY".to_string(), "/MO".into(), "1".into()]),
        _ => args.extend(["DAILY".to_string(), "/ST".into(), "09:30".into()]),
    }
    args.push("/F".into());
    args
}

/// Arguments for `schtasks` that delete the task.
#[allow(dead_code)]
pub fn schtasks_delete_args() -> Vec<String> {
    vec![
        "/Delete".into(),
        "/TN".into(),
        WINDOWS_TASK.into(),
        "/F".into(),
    ]
}

#[allow(dead_code)]
fn run_quiet(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!(
            "{program} {} failed{}",
            args.join(" "),
            if err.is_empty() {
                String::new()
            } else {
                format!(": {err}")
            }
        ))
    }
}

#[allow(dead_code)]
fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn home_dir() -> Result<PathBuf, String> {
    crate::content_scanner::home_dir().ok_or_else(|| "cannot find the home directory".to_string())
}

#[allow(dead_code)]
pub fn launchd_plist_path() -> Result<PathBuf, String> {
    Ok(home_dir()?
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist")))
}

#[allow(dead_code)]
fn systemd_unit_dir() -> Result<PathBuf, String> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => home_dir()?.join(".config"),
    };
    Ok(base.join("systemd/user"))
}

#[allow(dead_code)]
fn launchd_uid() -> Option<String> {
    let output = Command::new("id").arg("-u").output().ok()?;
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!uid.is_empty() && uid.chars().all(|c| c.is_ascii_digit())).then_some(uid)
}

#[cfg(target_os = "macos")]
fn install_entry(program: &Path, frequency: Frequency) -> Result<(), String> {
    let plist = launchd_plist_path()?;
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&plist, launchd_plist(program, &log_path(), frequency))
        .map_err(|e| format!("cannot write {}: {e}", plist.display()))?;
    let uid = launchd_uid().ok_or("cannot find the current user id")?;
    let service = format!("gui/{uid}/{LAUNCHD_LABEL}");
    let domain = format!("gui/{uid}");
    let plist_text = plist.display().to_string();
    let _ = run_quiet("launchctl", &["bootout", &service]);
    if run_quiet("launchctl", &["bootstrap", &domain, &plist_text]).is_ok() {
        return Ok(());
    }
    let _ = run_quiet("launchctl", &["unload", &plist_text]);
    run_quiet("launchctl", &["load", "-w", &plist_text])
}

#[cfg(target_os = "macos")]
fn remove_entry() -> Result<(), String> {
    let plist = launchd_plist_path()?;
    // No agent file under this home means nothing of ours is loaded:
    // launchd is left alone (a test home must never unload a real entry).
    if !plist.exists() {
        return Ok(());
    }
    if let Some(uid) = launchd_uid() {
        let _ = run_quiet(
            "launchctl",
            &["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")],
        );
    }
    let _ = run_quiet("launchctl", &["unload", &plist.display().to_string()]);
    std::fs::remove_file(&plist).map_err(|e| format!("cannot remove {}: {e}", plist.display()))
}

#[cfg(target_os = "macos")]
fn entry_installed() -> bool {
    let Ok(plist) = launchd_plist_path() else {
        return false;
    };
    if !plist.exists() {
        return false;
    }
    launchd_uid().is_some_and(|uid| {
        command_succeeds(
            "launchctl",
            &["print", &format!("gui/{uid}/{LAUNCHD_LABEL}")],
        )
    })
}

#[cfg(target_os = "macos")]
fn install_note() -> Option<String> {
    None
}

#[cfg(all(unix, not(target_os = "macos")))]
fn install_entry(program: &Path, frequency: Frequency) -> Result<(), String> {
    let dir = systemd_unit_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::write(
        dir.join(format!("{SYSTEMD_UNIT}.service")),
        systemd_service(program, &log_path()),
    )
    .map_err(|e| format!("cannot write the service unit: {e}"))?;
    std::fs::write(
        dir.join(format!("{SYSTEMD_UNIT}.timer")),
        systemd_timer(frequency),
    )
    .map_err(|e| format!("cannot write the timer unit: {e}"))?;
    if !systemctl_present() {
        return Ok(());
    }
    run_quiet("systemctl", &["--user", "daemon-reload"])?;
    run_quiet(
        "systemctl",
        &[
            "--user",
            "enable",
            "--now",
            &format!("{SYSTEMD_UNIT}.timer"),
        ],
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn remove_entry() -> Result<(), String> {
    let dir = systemd_unit_dir()?;
    // No timer unit under this config home means nothing of ours is
    // enabled: systemd is left alone (a test home must never disable a
    // real timer).
    if !dir.join(format!("{SYSTEMD_UNIT}.timer")).exists() {
        return Ok(());
    }
    if systemctl_present() {
        let _ = run_quiet(
            "systemctl",
            &[
                "--user",
                "disable",
                "--now",
                &format!("{SYSTEMD_UNIT}.timer"),
            ],
        );
    }
    for name in [
        format!("{SYSTEMD_UNIT}.timer"),
        format!("{SYSTEMD_UNIT}.service"),
    ] {
        let path = dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        }
    }
    if systemctl_present() {
        let _ = run_quiet("systemctl", &["--user", "daemon-reload"]);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn systemctl_present() -> bool {
    command_succeeds("systemctl", &["--version"])
}

#[cfg(all(unix, not(target_os = "macos")))]
fn entry_installed() -> bool {
    let Ok(dir) = systemd_unit_dir() else {
        return false;
    };
    if !dir.join(format!("{SYSTEMD_UNIT}.timer")).exists() {
        return false;
    }
    if !systemctl_present() {
        return true;
    }
    command_succeeds(
        "systemctl",
        &["--user", "is-enabled", &format!("{SYSTEMD_UNIT}.timer")],
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn install_note() -> Option<String> {
    (!systemctl_present()).then(|| {
        "systemctl was not found: the timer files were written but not started.".to_string()
    })
}

#[cfg(windows)]
fn install_entry(program: &Path, frequency: Frequency) -> Result<(), String> {
    let args = schtasks_create_args(program, frequency);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_quiet("schtasks", &refs)
}

#[cfg(windows)]
fn remove_entry() -> Result<(), String> {
    let args = schtasks_delete_args();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // A missing task is already "off".
    let _ = run_quiet("schtasks", &refs);
    Ok(())
}

#[cfg(windows)]
fn entry_installed() -> bool {
    command_succeeds("schtasks", &["/Query", "/TN", WINDOWS_TASK])
}

#[cfg(windows)]
fn install_note() -> Option<String> {
    None
}

#[cfg(not(any(unix, windows)))]
fn install_entry(_program: &Path, _frequency: Frequency) -> Result<(), String> {
    Err("scheduled checks are not supported on this platform".into())
}

#[cfg(not(any(unix, windows)))]
fn remove_entry() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn entry_installed() -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
fn install_note() -> Option<String> {
    None
}

// ─── Program trust ───────────────────────────────────────────────────────────

/// Whether the program a scheduler would run (or runs) is one QKey signed.
/// The scheduler entry names an absolute path that anything able to write
/// to it could swap, so every scheduled run re-checks the program it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramTrust {
    pub trusted: bool,
    /// The signing team, when the program carries a real signature.
    pub team_id: Option<String>,
    /// On macOS, under `/Applications/`; elsewhere always true.
    pub in_applications: bool,
}

impl ProgramTrust {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "program_trusted": self.trusted,
            "program_team_id": self.team_id,
            "program_in_applications": self.in_applications,
        })
    }
}

/// The `TeamIdentifier=` field of `codesign -dv --verbose=2` output. `None`
/// for an unsigned or ad-hoc signed binary (no field, or `not set`).
pub fn parse_codesign_team(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|team| !team.is_empty() && *team != "not set")
        .map(str::to_string)
}

/// What `codesign` said about a program, as three independent answers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodesignResults {
    /// `codesign --verify --strict --deep <program>` exited 0: the code,
    /// its resources and any nested code match their seal.
    pub verify_ok: bool,
    /// `codesign --verify -R="anchor apple generic and certificate
    /// leaf[subject.OU] = \"4H5SCV7U38\"" <program>` exited 0: the seal is
    /// bound to a certificate Apple issued to QKey's team.
    pub requirement_ok: bool,
    /// The combined output of `codesign -dv --verbose=2 <program>`, used
    /// only to report the team for display.
    pub info: String,
}

/// The trust decision from the three codesign answers.
///
/// Both checks are needed. `--verify --strict --deep` proves integrity (the
/// program is exactly what its signer sealed) but accepts any signer, even
/// an ad-hoc seal with no certificate at all. The requirement check binds
/// the seal to a certificate chaining to Apple with QKey's Team ID in the
/// leaf's OU, but on its own would be satisfied by metadata; together they
/// say "this exact code was signed by QKey". `codesign -dv` is never a
/// basis for trust: it prints `TeamIdentifier=` from the signature's
/// metadata whether or not the code still matches it, so a tampered
/// QKey-signed binary would show QKey's team. It is parsed only to name
/// the team in `program_team_id`.
///
/// A program that fails either check is untrusted. The one exception is a
/// program with no team at all (unsigned or ad-hoc signed) when
/// `allow_unsigned` is set: `GORSE_ALLOW_UNSIGNED_SCHEDULE=1`, meant for
/// developer builds only. The override never trusts a signed program that
/// fails verification, whoever signed it.
pub fn trust_from_codesign(
    results: &CodesignResults,
    allow_unsigned: bool,
) -> (bool, Option<String>) {
    let team = parse_codesign_team(&results.info);
    if results.verify_ok && results.requirement_ok {
        return (true, team.or_else(|| Some(QKEY_TEAM_ID.to_string())));
    }
    match team {
        Some(team) => (false, Some(team)),
        None => (allow_unsigned, None),
    }
}

/// `GORSE_ALLOW_UNSIGNED_SCHEDULE=1` (or the `HEDGEHOG_` spelling) lets an
/// unsigned developer build be scheduled.
fn allow_unsigned() -> bool {
    crate::config::env_var("ALLOW_UNSIGNED_SCHEDULE").as_deref() == Some("1")
}

/// The designated requirement a scheduled program must satisfy: a
/// certificate chain anchored at Apple whose leaf carries QKey's Team ID.
#[cfg(target_os = "macos")]
fn qkey_requirement() -> String {
    format!("=anchor apple generic and certificate leaf[subject.OU] = \"{QKEY_TEAM_ID}\"")
}

#[cfg(target_os = "macos")]
fn codesign_results(program: &Path) -> CodesignResults {
    let verify_ok = command_succeeds(
        "codesign",
        &[
            "--verify",
            "--strict",
            "--deep",
            &program.display().to_string(),
        ],
    );
    let requirement_ok = command_succeeds(
        "codesign",
        &[
            "--verify",
            "-R",
            &qkey_requirement(),
            &program.display().to_string(),
        ],
    );
    // The fields are on stderr; an unsigned binary makes codesign fail
    // with "code object is not signed at all", which parses to no team.
    let info = Command::new("codesign")
        .args(["-dv", "--verbose=2"])
        .arg(program)
        .stdin(Stdio::null())
        .output()
        .map(|output| {
            let mut text = String::from_utf8_lossy(&output.stderr).to_string();
            text.push_str(&String::from_utf8_lossy(&output.stdout));
            text
        })
        .unwrap_or_default();
    CodesignResults {
        verify_ok,
        requirement_ok,
        info,
    }
}

#[cfg(target_os = "macos")]
pub fn program_trust(program: &Path) -> ProgramTrust {
    let (trusted, team_id) = trust_from_codesign(&codesign_results(program), allow_unsigned());
    ProgramTrust {
        trusted,
        team_id,
        in_applications: program.starts_with("/Applications/"),
    }
}

/// No code-signing check on Linux or Windows yet.
#[cfg(not(target_os = "macos"))]
pub fn program_trust(_program: &Path) -> ProgramTrust {
    let _ = allow_unsigned;
    ProgramTrust {
        trusted: true,
        team_id: None,
        in_applications: true,
    }
}

/// The plain refusal `schedule set` prints for an untrusted program.
fn untrusted_message(trust: &ProgramTrust) -> String {
    match &trust.team_id {
        Some(team) if team == QKEY_TEAM_ID => format!(
            "This copy of Gorse carries a QKey signature that does not verify (it may have been modified since it was signed), so it cannot be scheduled. Download Gorse again from {} and try again.",
            crate::update_check::DOWNLOAD_URL
        ),
        Some(team) => format!(
            "This copy of Gorse is signed by another developer (team {team}), not QKey, so it cannot be scheduled. Download Gorse from {} and try again.",
            crate::update_check::DOWNLOAD_URL
        ),
        None => format!(
            "This copy of Gorse is not signed by QKey, so it cannot be scheduled. Download Gorse from {} and try again.",
            crate::update_check::DOWNLOAD_URL
        ),
    }
}

// ─── schedule.json ───────────────────────────────────────────────────────────

fn configured_frequency() -> Frequency {
    read_json(&schedule_path())
        .and_then(|s| {
            s.get("frequency")
                .and_then(|f| f.as_str())
                .and_then(Frequency::parse)
        })
        .unwrap_or(Frequency::Off)
}

fn configured_program() -> Option<PathBuf> {
    read_json(&schedule_path())
        .and_then(|s| s.get("program").and_then(|p| p.as_str()).map(PathBuf::from))
}

fn write_schedule(frequency: Frequency, program: &Path) -> Result<(), String> {
    write_json_atomic(
        &schedule_path(),
        &serde_json::json!({
            "frequency": frequency.label(),
            "installed_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "program": program.display().to_string(),
            "platform": platform_name(),
        }),
    )
}

// ─── Status ──────────────────────────────────────────────────────────────────

fn last_run_json() -> Option<serde_json::Value> {
    let mut status = read_json(&status_path())?;
    status.as_object_mut()?.remove("frequency");
    Some(status)
}

/// The `schedule status --json` object.
pub fn status_json(licensed: bool) -> serde_json::Value {
    let frequency = configured_frequency();
    let program = configured_program();
    let installed = frequency != Frequency::Off && entry_installed();
    // Trust of the configured program, else of this executable (what
    // `schedule set` would install).
    let trust = program
        .clone()
        .or_else(|| program_path().ok())
        .map(|p| program_trust(&p))
        .unwrap_or(ProgramTrust {
            trusted: false,
            team_id: None,
            in_applications: false,
        });
    let mut status = serde_json::json!({
        "frequency": frequency.label(),
        "installed": installed,
        "platform": platform_name(),
        "program": program.as_ref().map(|p| p.display().to_string()),
        "program_exists": program.as_ref().is_some_and(|p| p.exists()),
        "licensed": licensed,
        "last_run": last_run_json(),
        "history_count": history_files().len(),
    });
    if let (Some(into), Some(from)) = (status.as_object_mut(), trust.json().as_object()) {
        into.extend(from.clone());
    }
    status
}

fn short_time(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|t| {
            t.with_timezone(&chrono::Utc)
                .format("%Y-%m-%d %H:%M UTC")
                .to_string()
        })
        .unwrap_or_else(|_| rfc3339.to_string())
}

fn n(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
}

fn counts_text(counts: &serde_json::Value) -> String {
    format!(
        "{} critical, {} high, {} medium, {} low",
        n(counts, "critical"),
        n(counts, "high"),
        n(counts, "medium"),
        n(counts, "low")
    )
}

fn status_text(status: &serde_json::Value) -> String {
    let mut out = String::new();
    let frequency = status["frequency"].as_str().unwrap_or("off");
    let installed = status["installed"].as_bool().unwrap_or(false);
    match frequency {
        "off" => out.push_str("Scheduled checks: off\n"),
        "daily" => out.push_str(&format!(
            "Scheduled checks: daily at 09:30 ({})\n",
            if installed {
                "installed"
            } else {
                "not installed"
            }
        )),
        _ => out.push_str(&format!(
            "Scheduled checks: hourly ({})\n",
            if installed {
                "installed"
            } else {
                "not installed"
            }
        )),
    }
    if let Some(program) = status["program"].as_str() {
        out.push_str(&format!(
            "Program: {program}{}\n",
            if status["program_exists"].as_bool().unwrap_or(false) {
                ""
            } else {
                " (missing)"
            }
        ));
    }
    out.push_str(&format!(
        "Licence: {}\n",
        if status["licensed"].as_bool().unwrap_or(false) {
            "Pro"
        } else {
            "Free (scheduled checks need Gorse Pro)"
        }
    ));
    if let Some(trusted) = status["program_trusted"].as_bool() {
        let team = status["program_team_id"].as_str();
        out.push_str(&format!(
            "Program signature: {}\n",
            match (trusted, team) {
                (true, Some(team)) => format!("signed by QKey (team {team})"),
                (true, None) if cfg!(target_os = "macos") =>
                    "unsigned developer build (allowed by GORSE_ALLOW_UNSIGNED_SCHEDULE)"
                        .to_string(),
                (true, None) => "not checked on this platform".to_string(),
                (false, Some(team)) if team == QKEY_TEAM_ID =>
                    "QKey signature does not verify (modified since signing); scheduled checks are refused"
                        .to_string(),
                (false, Some(team)) =>
                    format!("signed by team {team}, not QKey; scheduled checks are refused"),
                (false, None) => "not signed by QKey; scheduled checks are refused".to_string(),
            }
        ));
    }
    match status.get("last_run") {
        Some(run) if run.is_object() => {
            let at = run["at"].as_str().map(short_time).unwrap_or_default();
            if run["incomplete"].as_bool().unwrap_or(false) {
                let unassessed = n(run, "unassessed");
                out.push_str(&format!(
                    "Last run: {at}, incomplete: {} could not be {}; {}; {} new, {} worsened{} (nothing reported as resolved from an incomplete run)\n",
                    plural(n(run, "coverage_failures") as usize, if unassessed > 0 { "credential location or source" } else { "credential location" }),
                    if unassessed > 0 { "read or assessed" } else { "read" },
                    counts_text(&run["counts"]),
                    n(run, "new"),
                    n(run, "worsened"),
                    if unassessed > 0 { format!(", {unassessed} unassessed") } else { String::new() }
                ));
                if let Some(baseline) = run["baseline"].as_str() {
                    out.push_str(&format!(
                        "Compared with: {baseline} (the last complete run)\n"
                    ));
                }
            } else if run["ok"].as_bool().unwrap_or(false) {
                out.push_str(&format!(
                    "Last run: {at}, ok: {}; {} new, {} worsened, {} resolved\n",
                    counts_text(&run["counts"]),
                    n(run, "new"),
                    n(run, "worsened"),
                    n(run, "resolved")
                ));
            } else {
                out.push_str(&format!(
                    "Last run: {at}, failed: {}\n",
                    run["message"].as_str().unwrap_or("unknown error")
                ));
            }
        }
        _ => out.push_str("Last run: never\n"),
    }
    out.push_str(&format!(
        "History: {} recorded run{}\n",
        n(status, "history_count"),
        if n(status, "history_count") == 1 {
            ""
        } else {
            "s"
        }
    ));
    out
}

// ─── History listing ─────────────────────────────────────────────────────────

fn history_entry_json(path: &Path, accepted: Option<&str>) -> Option<serde_json::Value> {
    let run = read_json(path)?;
    let changes = run.get("changes").cloned().unwrap_or(serde_json::json!({}));
    let c = changes
        .get("counts")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    Some(serde_json::json!({
        "file": path.file_name().and_then(|f| f.to_str()),
        "at": run.get("recorded_at"),
        "trigger": run.get("trigger"),
        "counts": counts_of(&run),
        "new": n(&c, "new"),
        "worsened": n(&c, "worsened"),
        "resolved": n(&c, "resolved"),
        "improved": n(&c, "improved"),
        "unassessed": n(&c, "unassessed"),
        "first_run": changes.get("first_run").and_then(|v| v.as_bool()).unwrap_or(false),
        "incomplete": is_incomplete(&run),
        "coverage_failures": coverage_failure_count(&run),
        "accepted_by_user": is_accepted(path, &run, accepted),
    }))
}

fn history_text(entries: &[serde_json::Value]) -> String {
    if entries.is_empty() {
        return "No recorded checks yet. Run `gorse exposure --record` or turn on scheduled checks with `gorse schedule set daily`.\n".to_string();
    }
    let mut out = format!(
        "{:<20} {:>4} {:>4} {:>4} {:>4}  {:>4} {:>6} {:>8} {:>10}  {:<10} {}\n",
        "When",
        "Crit",
        "High",
        "Med",
        "Low",
        "New",
        "Worse",
        "Resolved",
        "Unassessed",
        "Trigger",
        "Status"
    );
    for e in entries {
        let at = e["at"].as_str().map(short_time).unwrap_or_default();
        let c = &e["counts"];
        let status = if e["incomplete"].as_bool().unwrap_or(false) {
            if n(e, "unassessed") > 0 {
                format!(
                    "incomplete ({} unreadable or unassessed)",
                    n(e, "coverage_failures")
                )
            } else {
                format!("incomplete ({} unreadable)", n(e, "coverage_failures"))
            }
        } else {
            "ok".to_string()
        };
        out.push_str(&format!(
            "{:<20} {:>4} {:>4} {:>4} {:>4}  {:>4} {:>6} {:>8} {:>10}  {:<10} {}\n",
            at.trim_end_matches(" UTC"),
            n(c, "critical"),
            n(c, "high"),
            n(c, "medium"),
            n(c, "low"),
            n(e, "new"),
            n(e, "worsened"),
            n(e, "resolved"),
            n(e, "unassessed"),
            e["trigger"].as_str().unwrap_or(""),
            status
        ));
    }
    out
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Quiet lease renewal, then the effective tier.
fn refreshed_tier() -> Tier {
    let status = crate::credential_store::refresh_quietly_if_due(crate::credential_store::status());
    crate::credential_store::tier_of(&status)
}

/// Truncate the scheduler log once it is over the limit so it never grows
/// without bound.
fn trim_log() {
    let path = log_path();
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_LIMIT_BYTES) {
        let _ = std::fs::write(&path, b"");
    }
}

pub fn cmd_schedule(command: ScheduleCommand) {
    match command {
        ScheduleCommand::Set { frequency, json } => cmd_set(frequency, json),
        ScheduleCommand::Status { json } => cmd_status(json),
        ScheduleCommand::Run { json } => cmd_run(json),
        ScheduleCommand::History { json, limit } => cmd_history(json, limit),
        ScheduleCommand::AcceptBaseline { json } => cmd_accept_baseline(json),
    }
}

fn cmd_accept_baseline(json: bool) {
    match accept_baseline_in(&exposure_dir()) {
        Ok(file) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "baseline": file,
                        "accepted_by_user": true,
                    }))
                    .unwrap()
                );
            } else {
                println!("Accepted {file} as the baseline. Later checks are compared with it.");
            }
        }
        Err(e) => fail(&e, json),
    }
}

fn fail(message: &str, json: bool) -> ! {
    if json {
        println!("{}", serde_json::json!({"error": message}));
    } else {
        eprintln!("{message}");
    }
    std::process::exit(2);
}

fn cmd_set(frequency: Frequency, json: bool) {
    let program = program_path().unwrap_or_else(|e| fail(&e, json));
    // Only turning checks on is gated. `set off` removes the scheduler
    // entry whatever the licence and whoever signed this program: a person
    // must always be able to stop an unattended check, and the apps rely
    // on it succeeding on the Free tier.
    if frequency != Frequency::Off {
        let trust = program_trust(&program);
        if !trust.trusted {
            if json {
                let mut error = serde_json::json!({"error": untrusted_message(&trust)});
                if let (Some(into), Some(from)) = (error.as_object_mut(), trust.json().as_object())
                {
                    into.extend(from.clone());
                }
                println!("{error}");
                std::process::exit(2);
            }
            fail(&untrusted_message(&trust), json);
        }
        let tier = refreshed_tier();
        if tier < Tier::Pro {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"error": REQUIRES_PRO, "upgrade_url": UPGRADE_URL})
                );
            } else {
                println!("{REQUIRES_PRO}");
            }
            std::process::exit(2);
        }
    }
    if let Err(e) = create_private_dir(&exposure_dir()) {
        fail(&e, json);
    }
    let result = match frequency {
        Frequency::Off => remove_entry(),
        _ => install_entry(&program, frequency),
    };
    if let Err(e) = result {
        fail(&format!("Could not update the scheduler: {e}"), json);
    }
    if let Err(e) = write_schedule(frequency, &program) {
        fail(&e, json);
    }
    if json {
        let licensed = crate::credential_store::current_tier() >= Tier::Pro;
        println!(
            "{}",
            serde_json::to_string_pretty(&status_json(licensed)).unwrap()
        );
        return;
    }
    match frequency {
        Frequency::Off => println!("Scheduled checks are off."),
        Frequency::Daily => println!(
            "Scheduled checks are on: every day at 09:30. Gorse will notify you when something new appears."
        ),
        Frequency::Hourly => println!(
            "Scheduled checks are on: every hour. Gorse will notify you when something new appears."
        ),
    }
    if let Some(note) = install_note() {
        println!("{note}");
    }
}

fn cmd_status(json: bool) {
    let licensed = crate::credential_store::current_tier() >= Tier::Pro;
    let status = status_json(licensed);
    if json {
        println!("{}", serde_json::to_string_pretty(&status).unwrap());
    } else {
        print!("{}", status_text(&status));
    }
}

fn cmd_run(json: bool) {
    trim_log();
    let trusted = program_path().is_ok_and(|p| program_trust(&p).trusted);
    let record = if !trusted {
        // Whatever the scheduler is pointing at, it is not a Gorse QKey
        // signed: do nothing, not even the lease renewal.
        record_failure(Trigger::Scheduled, UNTRUSTED_PROGRAM)
    } else if refreshed_tier() < Tier::Pro {
        // The schedule stays in place: a lapsed subscription that renews
        // picks up again without reinstalling anything.
        record_failure(Trigger::Scheduled, LICENCE_REQUIRED)
    } else {
        match crate::exposure::run(&crate::exposure::Options {
            verify: false,
            declarations: None,
            max_hops: None,
        }) {
            Ok(report) => {
                let value = crate::exposure::report::render_json(&report);
                match record_run(value, Trigger::Scheduled) {
                    Ok(record) => record,
                    Err(e) => {
                        eprintln!("Could not record the exposure check: {e}");
                        record_failure(Trigger::Scheduled, &format!("could not record: {e}"))
                    }
                }
            }
            Err(e) => {
                eprintln!("Exposure check could not run: {e}");
                record_failure(Trigger::Scheduled, &e)
            }
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status_json(
                crate::credential_store::current_tier() >= Tier::Pro
            ))
            .unwrap()
        );
    } else if !record.ok {
        eprintln!("Scheduled check not completed: {}", record.message);
    }
}

fn cmd_history(json: bool, limit: usize) {
    let accepted = accepted_baseline_in(&exposure_dir());
    let entries: Vec<serde_json::Value> = history_files()
        .iter()
        .take(limit)
        .filter_map(|p| history_entry_json(p, accepted.as_deref()))
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "runs": entries,
                "total": history_files().len(),
            }))
            .unwrap()
        );
    } else {
        print!("{}", history_text(&entries));
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(kind: &str, location: &str, fp: &str, severity: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": kind,
            "kind_label": kind,
            "name": format!("{kind} at {location}"),
            "location": location,
            "fingerprint": fp,
            "severity": severity,
        })
    }

    fn report(findings: Vec<serde_json::Value>) -> serde_json::Value {
        let count = |s: &str| {
            findings
                .iter()
                .filter(|f| f["severity"].as_str() == Some(s))
                .count()
        };
        serde_json::json!({
            "summary": {"by_severity": {
                "critical": count("critical"), "high": count("high"),
                "medium": count("medium"), "low": count("low"),
            }},
            "findings": findings,
        })
    }

    fn sourced(kind: &str, location: &str, fp: &str, source: &str) -> serde_json::Value {
        let mut f = finding(kind, location, fp, "high");
        f["source"] = serde_json::json!(source);
        f
    }

    fn with_sources(
        mut report: serde_json::Value,
        assessed: &[&str],
        unavailable: &[(&str, &str)],
    ) -> serde_json::Value {
        report["sources_assessed"] = serde_json::json!(assessed);
        report["sources_unavailable"] = serde_json::json!(unavailable
            .iter()
            .map(|(s, r)| serde_json::json!({"source": s, "reason": r}))
            .collect::<Vec<_>>());
        report["incomplete"] = serde_json::json!(false);
        report["coverage_failures"] = serde_json::json!([]);
        report
    }

    #[test]
    fn missing_finding_resolves_only_when_its_source_was_reassessed() {
        let before = with_sources(
            report(vec![
                sourced(
                    "DigitalOceanToken",
                    "~/.config/doctl/config.yaml",
                    "a",
                    "doctl-config",
                ),
                sourced("KubernetesContext", "~/.kube/config", "b", "kubeconfig"),
            ]),
            &["doctl-config", "kubeconfig"],
            &[],
        );
        // Both gone; kubeconfig was assessed, doctl-config was not.
        let now = with_sources(
            report(vec![]),
            &["kubeconfig"],
            &[(
                "doctl-config",
                "could not interpret ~/.config/doctl/config.yaml (unsupported format)",
            )],
        );
        let changes = diff(Some(&before), &now);
        assert_eq!(changes.resolved_count, 1);
        assert_eq!(changes.resolved[0].location, "~/.kube/config");
        assert_eq!(changes.unassessed_count, 1);
        assert_eq!(
            changes.unassessed[0].location,
            "~/.config/doctl/config.yaml"
        );
        assert_eq!(
            changes.unassessed[0].reason.as_deref(),
            Some("could not interpret ~/.config/doctl/config.yaml (unsupported format)")
        );
        assert!(
            changes.incomplete,
            "an unassessed finding makes the run incomplete"
        );
        assert!(changes.coverage_lost);
        assert!(changes.notify());
        assert_eq!(changes.unassessed_failures.len(), 1);
        assert_eq!(
            changes.unassessed_failures[0].reason,
            "source doctl-config was not assessed in this run (could not interpret ~/.config/doctl/config.yaml (unsupported format))"
        );
        assert_eq!(changes.coverage_failures, 1);
        let json = changes.json();
        assert_eq!(json["counts"]["unassessed"], 1);
        assert_eq!(
            json["unassessed"][0]["reason"],
            "could not interpret ~/.config/doctl/config.yaml (unsupported format)"
        );

        // Recorded, the report itself becomes incomplete, so it is never
        // chosen as the baseline.
        let mut recorded = now.clone();
        apply_unassessed(&mut recorded, &changes);
        assert!(is_incomplete(&recorded));
        assert_eq!(coverage_failure_count(&recorded), 1);
        assert!(!is_incomplete(&now));
    }

    #[test]
    fn findings_recorded_without_a_source_keep_the_old_rule() {
        let before = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let now = with_sources(report(vec![]), &["kubeconfig"], &[]);
        let changes = diff(Some(&before), &now);
        assert_eq!(changes.resolved_count, 1);
        assert_eq!(changes.unassessed_count, 0);
        assert!(!changes.incomplete);
        // And a current report without sources (an older binary) likewise.
        let before = with_sources(
            report(vec![sourced(
                "AwsKey",
                "~/.aws/credentials",
                "a",
                "aws-credentials-file",
            )]),
            &["aws-credentials-file"],
            &[],
        );
        let changes = diff(Some(&before), &report(vec![]));
        assert_eq!(changes.resolved_count, 1);
    }

    #[test]
    fn an_unreadable_file_already_listed_is_not_listed_twice() {
        let before = with_sources(
            report(vec![sourced(
                "AwsKey",
                "~/.aws/credentials",
                "a",
                "aws-credentials-file",
            )]),
            &["aws-credentials-file"],
            &[],
        );
        let mut now = with_sources(
            report(vec![]),
            &[],
            &[(
                "aws-credentials-file",
                "~/.aws/credentials: Permission denied",
            )],
        );
        now["incomplete"] = serde_json::json!(true);
        now["coverage_failures"] =
            serde_json::json!([{"location": "~/.aws/credentials", "reason": "Permission denied"}]);
        let changes = diff(Some(&before), &now);
        assert_eq!(changes.unassessed_count, 1);
        assert!(changes.unassessed_failures.is_empty());
        assert_eq!(changes.coverage_failures, 1);
    }

    #[test]
    fn agent_identities_recorded_under_ssh_follow_the_agent_source() {
        let before = with_sources(
            report(vec![sourced(
                "SshAgentIdentity",
                "ssh-agent (SSH_AUTH_SOCK)",
                "SHA256:x",
                "ssh",
            )]),
            &["ssh"],
            &[],
        );
        let now = with_sources(
            report(vec![]),
            &["ssh"],
            &[(
                "ssh-agent",
                "SSH_AUTH_SOCK is not set in this environment, so the agent could not be asked",
            )],
        );
        let changes = diff(Some(&before), &now);
        assert_eq!(changes.resolved_count, 0);
        assert_eq!(changes.unassessed_count, 1);
        assert!(changes.incomplete);
        assert_eq!(
            changes.unassessed_failures[0].reason,
            "source ssh-agent was not assessed in this run (SSH_AUTH_SOCK is not set in this environment, so the agent could not be asked)"
        );
        // With no agent identity on record, the missing agent loses nothing.
        let before = with_sources(report(vec![]), &["ssh", "ssh-agent"], &[]);
        let changes = diff(Some(&before), &now);
        assert!(!changes.incomplete);
    }

    #[test]
    fn first_run_marks_everything_new_without_notifying() {
        let now = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let changes = diff(None, &now);
        assert!(changes.first_run);
        assert_eq!(changes.new_count, 1);
        assert_eq!(changes.new[0].name, "AwsKey at ~/.aws/credentials");
        assert!(!changes.notify());
        assert_eq!(changes.json()["notify"], false);
        assert_eq!(changes.json()["counts"]["new"], 1);
    }

    #[test]
    fn diff_finds_new_worsened_resolved_and_improved() {
        let before = report(vec![
            finding("AwsKey", "~/.aws/credentials", "a", "high"),
            finding("GhToken", "~/.config/gh/hosts.yml", "b", "medium"),
            finding("Kube", "~/.kube/config", "c", "critical"),
            finding("Old", "~/old", "d", "low"),
        ]);
        let now = report(vec![
            finding("AwsKey", "~/.aws/credentials", "a", "critical"),
            finding("GhToken", "~/.config/gh/hosts.yml", "b", "medium"),
            finding("Kube", "~/.kube/config", "c", "low"),
            finding("Vault", "~/.vault-token", "e", "high"),
        ]);
        let changes = diff(Some(&before), &now);
        assert!(!changes.first_run);
        assert_eq!(changes.new.len(), 1);
        assert_eq!(changes.new[0].kind, "Vault");
        assert_eq!(changes.worsened.len(), 1);
        assert_eq!(changes.worsened[0].kind, "AwsKey");
        assert_eq!(
            changes.worsened[0].previous_severity.as_deref(),
            Some("high")
        );
        assert_eq!(changes.improved.len(), 1);
        assert_eq!(changes.improved[0].kind, "Kube");
        assert_eq!(changes.resolved.len(), 1);
        assert_eq!(changes.resolved[0].kind, "Old");
        assert!(changes.notify());
        assert_eq!(changes.highest_severity(), Some("Critical"));
        let j = changes.json();
        assert_eq!(j["worsened"][0]["previous_severity"], "high");
        assert!(j["new"][0].get("previous_severity").is_none());
    }

    #[test]
    fn identity_is_kind_location_fingerprint() {
        let before = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        // Same kind and location, different fingerprint: rotated key.
        let rotated = report(vec![finding("AwsKey", "~/.aws/credentials", "z", "high")]);
        let changes = diff(Some(&before), &rotated);
        assert_eq!(changes.new_count, 1);
        assert_eq!(changes.resolved_count, 1);
        // Same fingerprint elsewhere is a different finding too.
        let moved = report(vec![finding("AwsKey", "~/other", "a", "high")]);
        let changes = diff(Some(&before), &moved);
        assert_eq!(changes.new_count, 1);
        assert_eq!(changes.resolved_count, 1);
        // Unchanged: nothing to report.
        let changes = diff(Some(&before), &before);
        assert_eq!(changes, Changes::default());
        assert!(!changes.notify());
    }

    #[test]
    fn only_resolved_does_not_notify() {
        let before = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let changes = diff(Some(&before), &report(vec![]));
        assert_eq!(changes.resolved_count, 1);
        assert!(!changes.notify());
    }

    #[test]
    fn change_lists_are_capped_but_counts_are_not() {
        let many: Vec<_> = (0..70)
            .map(|i| finding("Key", &format!("~/f{i}"), &format!("fp{i}"), "low"))
            .collect();
        let changes = diff(Some(&report(vec![])), &report(many));
        assert_eq!(changes.new.len(), CHANGE_LIST_CAP);
        assert_eq!(changes.new_count, 70);
    }

    #[test]
    fn severity_rank_is_case_insensitive_and_ordered() {
        assert!(severity_rank("Critical") > severity_rank("high"));
        assert!(severity_rank("HIGH") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("Low"));
        assert!(severity_rank("low") > severity_rank("weird"));
    }

    #[test]
    fn notification_body_has_counts_only() {
        let before = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let now = report(vec![
            finding("AwsKey", "~/.aws/credentials", "a", "critical"),
            finding("Vault", "~/.vault-token", "fp-secret-1", "high"),
            finding("Kube", "~/.kube/config", "fp-secret-2", "medium"),
        ]);
        let changes = diff(Some(&before), &now);
        let body = notification_body(&changes);
        assert_eq!(
            body,
            "2 new findings, 1 worsened. Highest: Critical. Open Gorse to review."
        );
        for leak in ["~/", "fp-secret", "hosts.yml", "AwsKey at", "Vault at"] {
            assert!(!body.contains(leak), "notification leaks {leak}: {body}");
        }
        let one = diff(
            Some(&report(vec![])),
            &report(vec![finding("Vault", "~/.vault-token", "x", "low")]),
        );
        assert_eq!(
            notification_body(&one),
            "1 new finding. Highest: Low. Open Gorse to review."
        );
    }

    #[test]
    fn applescript_escaping() {
        assert_eq!(applescript_escape(r#"a "b" \c"#), r#"a \"b\" \\c"#);
    }

    #[test]
    fn launchd_plist_text() {
        let daily = launchd_plist(
            Path::new("/Applications/Gorse.app/Contents/MacOS/gorse-cli"),
            Path::new("/Users/x/.hedgehog/exposure/schedule.log"),
            Frequency::Daily,
        );
        assert!(daily.contains("<string>is.hedgehog.schedule</string>"));
        assert!(daily
            .contains("<string>/Applications/Gorse.app/Contents/MacOS/gorse-cli</string>\n\t\t<string>schedule</string>\n\t\t<string>run</string>"));
        assert!(daily.contains("<key>StartCalendarInterval</key>"));
        assert!(daily.contains("<key>Hour</key>\n\t\t<integer>9</integer>"));
        assert!(daily.contains("<key>Minute</key>\n\t\t<integer>30</integer>"));
        assert!(daily.contains("<key>RunAtLoad</key>\n\t<false/>"));
        assert!(daily.contains("<key>ProcessType</key>\n\t<string>Background</string>"));
        assert!(daily.contains("<key>StandardOutPath</key>\n\t<string>/Users/x/.hedgehog/exposure/schedule.log</string>"));
        assert!(!daily.contains("StartInterval"));
        let hourly = launchd_plist(
            Path::new("/bin/gorse"),
            Path::new("/tmp/l"),
            Frequency::Hourly,
        );
        assert!(hourly.contains("<key>StartInterval</key>\n\t<integer>3600</integer>"));
        assert!(!hourly.contains("StartCalendarInterval"));
        let odd = launchd_plist(Path::new("/A&B/<g>"), Path::new("/l"), Frequency::Daily);
        assert!(odd.contains("<string>/A&amp;B/&lt;g&gt;</string>"));
    }

    #[test]
    fn systemd_unit_text() {
        let service = systemd_service(
            Path::new("/usr/local/bin/gorse"),
            Path::new("/home/x/l.log"),
        );
        assert!(service.contains("ExecStart=/usr/local/bin/gorse schedule run\n"));
        assert!(service.contains("StandardOutput=append:/home/x/l.log\n"));
        assert!(service.contains("Type=oneshot"));
        let daily = systemd_timer(Frequency::Daily);
        assert!(daily.contains("OnCalendar=*-*-* 09:30:00\n"));
        assert!(daily.contains("Persistent=true\n"));
        assert!(daily.contains("WantedBy=timers.target"));
        assert!(systemd_timer(Frequency::Hourly).contains("OnCalendar=hourly\n"));
    }

    #[test]
    fn schtasks_arguments() {
        let daily = schtasks_create_args(
            Path::new(r"C:\Program Files\Gorse\gorse.exe"),
            Frequency::Daily,
        );
        assert_eq!(
            daily,
            vec![
                "/Create",
                "/TN",
                "Gorse Scheduled Check",
                "/TR",
                r#""C:\Program Files\Gorse\gorse.exe" schedule run"#,
                "/SC",
                "DAILY",
                "/ST",
                "09:30",
                "/F",
            ]
        );
        let hourly = schtasks_create_args(Path::new("gorse.exe"), Frequency::Hourly);
        assert_eq!(&hourly[6..], &["HOURLY", "/MO", "1", "/F"]);
        assert_eq!(
            schtasks_delete_args(),
            vec!["/Delete", "/TN", "Gorse Scheduled Check", "/F"]
        );
    }

    #[test]
    fn an_accepted_incomplete_run_becomes_the_baseline() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-accept-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let history = dir.join("history");
        std::fs::create_dir_all(&history).unwrap();
        assert!(accept_baseline_in(&dir).is_err(), "no history yet");
        let complete = report(vec![]);
        let mut incomplete = report(vec![]);
        incomplete["incomplete"] = serde_json::json!(true);
        write_json_atomic(&history.join("20260101T000000Z.json"), &complete).unwrap();
        write_json_atomic(&history.join("20260102T000000Z.json"), &incomplete).unwrap();
        let files = history_files_in(&history);
        assert_eq!(accepted_baseline_in(&dir), None);
        assert_eq!(
            baseline_file(&files, None).unwrap().0,
            history.join("20260101T000000Z.json")
        );
        let before = std::fs::read(history.join("20260102T000000Z.json")).unwrap();
        assert_eq!(accept_baseline_in(&dir).unwrap(), "20260102T000000Z.json");
        assert_eq!(
            std::fs::read(history.join("20260102T000000Z.json")).unwrap(),
            before,
            "the run file is never modified"
        );
        let accepted = accepted_baseline_in(&dir);
        assert_eq!(accepted.as_deref(), Some("20260102T000000Z.json"));
        let record = read_json(&accepted_baseline_path_in(&dir)).unwrap();
        assert_eq!(record["accepted_by_user"], true);
        assert!(
            chrono::DateTime::parse_from_rfc3339(record["accepted_at"].as_str().unwrap()).is_ok()
        );
        let (path, run) = baseline_file(&files, accepted.as_deref()).unwrap();
        assert_eq!(path, history.join("20260102T000000Z.json"));
        assert!(run.get("accepted_by_user").is_none());
        assert_eq!(run["incomplete"], true, "the run itself is unchanged");
        assert_eq!(
            history_entry_json(&path, accepted.as_deref()).unwrap()["accepted_by_user"],
            true
        );
        assert_eq!(
            history_entry_json(&history.join("20260101T000000Z.json"), accepted.as_deref())
                .unwrap()["accepted_by_user"],
            false
        );

        // A later incomplete run does not displace the accepted one; a
        // later complete run does.
        write_json_atomic(&history.join("20260103T000000Z.json"), &incomplete).unwrap();
        let files = history_files_in(&history);
        assert_eq!(
            baseline_file(&files, accepted.as_deref()).unwrap().0,
            history.join("20260102T000000Z.json")
        );
        write_json_atomic(&history.join("20260104T000000Z.json"), &complete).unwrap();
        let files = history_files_in(&history);
        assert_eq!(
            baseline_file(&files, accepted.as_deref()).unwrap().0,
            history.join("20260104T000000Z.json")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn accepting_a_stamped_run_keeps_its_checksum_and_the_documented_recipe_is_the_code() {
        use sha2::{Digest, Sha256};
        // The recipe as docs/EXPOSURE_CHECK.md and the checksum note state it.
        let documented = |run: &serde_json::Value| {
            let mut body = run.clone();
            let object = body.as_object_mut().unwrap();
            object.remove("generated_at");
            object.remove("accepted_by_user");
            if let Some(stamp) = object
                .get_mut("attestation")
                .and_then(|a| a.as_object_mut())
            {
                stamp.remove("digest");
            }
            format!("sha256:{:x}", Sha256::digest(body.to_string().as_bytes()))
        };
        let dir = std::env::temp_dir().join(format!(
            "gorse-accept-stamped-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let history = dir.join("history");
        std::fs::create_dir_all(&history).unwrap();
        let mut run = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        run["generated_at"] = serde_json::json!("2026-11-03T09:00:00+00:00");
        run["recorded_at"] = serde_json::json!("2026-11-03T09:00:00Z");
        run["incomplete"] = serde_json::json!(true);
        run["attestation"] = serde_json::json!({
            "holder": "holder@example.com",
            "machine": "machine-0001",
            "verified_at": "2026-11-03T09:00:00Z",
        });
        let digest = crate::exposure::digest_of_json(run.clone());
        assert_eq!(digest, documented(&run));
        run["attestation"]["digest"] = serde_json::json!(digest);
        let path = history.join("20261103T090000Z.json");
        write_json_atomic(&path, &run).unwrap();
        assert_eq!(accept_baseline_in(&dir).unwrap(), "20261103T090000Z.json");
        let stored = read_json(&path).unwrap();
        assert_eq!(stored, run, "the run file is never modified");
        assert_eq!(documented(&stored), stored["attestation"]["digest"]);
        assert_eq!(
            crate::exposure::digest_of_json(stored.clone()),
            stored["attestation"]["digest"]
        );
        // A legacy file that carries accepted_by_user still recomputes.
        let mut legacy = stored.clone();
        legacy["accepted_by_user"] = serde_json::json!(true);
        assert_eq!(documented(&legacy), stored["attestation"]["digest"]);
        assert_eq!(
            crate::exposure::digest_of_json(legacy),
            stored["attestation"]["digest"]
        );
        let files = history_files_in(&history);
        let accepted = accepted_baseline_in(&dir);
        assert_eq!(baseline_file(&files, accepted.as_deref()).unwrap().0, path);
        assert!(baseline_file(&files, None).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_in_file_acceptance_is_still_honoured() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-accept-legacy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let history = dir.join("history");
        std::fs::create_dir_all(&history).unwrap();
        let mut legacy = report(vec![]);
        legacy["incomplete"] = serde_json::json!(true);
        legacy["accepted_by_user"] = serde_json::json!(true);
        write_json_atomic(&history.join("20260101T000000Z.json"), &report(vec![])).unwrap();
        write_json_atomic(&history.join("20260102T000000Z.json"), &legacy).unwrap();
        let files = history_files_in(&history);
        assert_eq!(
            baseline_file(&files, None).unwrap().0,
            history.join("20260102T000000Z.json")
        );
        // A baseline.json naming something that is not a plain file name is
        // ignored.
        for bad in ["../history/20260101T000000Z.json", "", "a/b.json"] {
            write_json_atomic(
                &accepted_baseline_path_in(&dir),
                &serde_json::json!({"file": bad, "accepted_by_user": true}),
            )
            .unwrap();
            assert_eq!(accepted_baseline_in(&dir), None, "{bad}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn history_retention_keeps_newest() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-schedule-prune-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..100 {
            std::fs::write(dir.join(format!("20260101T{i:06}Z.json")), "{}").unwrap();
        }
        std::fs::write(dir.join("notes.txt"), "keep").unwrap();
        assert_eq!(prune_history(&dir, HISTORY_KEEP), 10);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".json"))
            .collect();
        left.sort();
        assert_eq!(left.len(), HISTORY_KEEP);
        assert_eq!(left[0], "20260101T000010Z.json");
        assert_eq!(left[89], "20260101T000099Z.json");
        assert!(dir.join("notes.txt").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_file_names_do_not_collide_and_stay_ordered() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-schedule-names-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first = run_file_name(&dir, "20260101T000000Z");
        std::fs::write(&first, "{}").unwrap();
        let second = run_file_name(&dir, "20260101T000000Z");
        assert_ne!(first, second);
        assert!(second.ends_with("20260101T000000Z_1.json"));
        assert!(second > first, "a same-second run must sort as newer");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn status_record_shape() {
        let before = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let now = report(vec![
            finding("AwsKey", "~/.aws/credentials", "a", "high"),
            finding("Vault", "~/.vault-token", "b", "critical"),
        ]);
        let record = RunRecord {
            at: "2026-11-03T09:30:00Z".into(),
            ok: true,
            counts: counts_of(&now),
            changes: diff(Some(&before), &now),
            trigger: Trigger::Scheduled,
            message: "ok".into(),
            file: Some("20261103T093000Z.json".into()),
            baseline: Some("20261102T093000Z.json".into()),
        };
        let j = record.json();
        assert_eq!(j["at"], "2026-11-03T09:30:00Z");
        assert_eq!(j["incomplete"], false);
        assert_eq!(j["coverage_failures"], 0);
        assert_eq!(j["baseline"], "20261102T093000Z.json");
        assert_eq!(j["ok"], true);
        assert_eq!(j["trigger"], "scheduled");
        assert_eq!(j["counts"]["critical"], 1);
        assert_eq!(j["counts"]["high"], 1);
        assert_eq!(j["counts"]["medium"], 0);
        assert_eq!(j["counts"]["low"], 0);
        assert_eq!(j["new"], 1);
        assert_eq!(j["worsened"], 0);
        assert_eq!(j["resolved"], 0);
        assert_eq!(j["notify"], true);
        assert_eq!(j["first_run"], false);
        assert_eq!(j["message"], "ok");
        let failed = RunRecord {
            at: "2026-11-03T09:30:00Z".into(),
            ok: false,
            counts: counts_of(&serde_json::json!({})),
            changes: Changes::default(),
            trigger: Trigger::Scheduled,
            message: LICENCE_REQUIRED.into(),
            file: None,
            baseline: None,
        };
        let j = failed.json();
        assert_eq!(j["ok"], false);
        assert_eq!(j["message"], "licence required");
        assert_eq!(j["counts"]["critical"], 0);
        assert!(j["file"].is_null());
    }

    const CODESIGN_SIGNED: &str = "Executable=/Applications/Gorse.app/Contents/MacOS/gorse\n\
Identifier=is.hedgehog.app\n\
Format=app bundle with Mach-O thin (arm64)\n\
CodeDirectory v=20500 size=1864 flags=0x10000(runtime) hashes=47+7 location=embedded\n\
Signature size=9023\n\
Authority=Developer ID Application: James Tagg (4H5SCV7U38)\n\
Authority=Developer ID Certification Authority\n\
Authority=Apple Root CA\n\
Timestamp=3 Nov 2026 at 09:12:44\n\
Info.plist entries=22\n\
TeamIdentifier=4H5SCV7U38\n\
Runtime Version=14.0.0\n\
Sealed Resources version=2 rules=13 files=6\n\
Internal requirements count=1 size=180\n";

    const CODESIGN_ADHOC: &str = "Executable=/Users/dev/hedgehog/target/debug/gorse\n\
Identifier=gorse\n\
Format=Mach-O thin (arm64)\n\
CodeDirectory v=20400 size=41260 flags=0x2(adhoc) hashes=1284+2 location=embedded\n\
Signature=adhoc\n\
Info.plist=not bound\n\
TeamIdentifier=not set\n\
Sealed Resources=none\n\
Internal requirements count=0 size=12\n";

    const CODESIGN_UNSIGNED: &str =
        "/Users/dev/gorse: code object is not signed at all\nIn architecture: x86_64\n";

    const CODESIGN_OTHER_TEAM: &str =
        "Executable=/tmp/gorse\nAuthority=Developer ID Application: Someone Else (ABCDE12345)\nTeamIdentifier=ABCDE12345\n";

    #[test]
    fn codesign_output_parses_team_identifier() {
        assert_eq!(
            parse_codesign_team(CODESIGN_SIGNED).as_deref(),
            Some("4H5SCV7U38")
        );
        assert_eq!(parse_codesign_team(CODESIGN_ADHOC), None);
        assert_eq!(parse_codesign_team(CODESIGN_UNSIGNED), None);
        assert_eq!(
            parse_codesign_team(CODESIGN_OTHER_TEAM).as_deref(),
            Some("ABCDE12345")
        );
        assert_eq!(parse_codesign_team(""), None);
        assert_eq!(parse_codesign_team("TeamIdentifier=\n"), None);
    }

    fn codesign(verify_ok: bool, requirement_ok: bool, info: &str) -> CodesignResults {
        CodesignResults {
            verify_ok,
            requirement_ok,
            info: info.to_string(),
        }
    }

    #[test]
    fn trust_needs_both_codesign_checks_or_the_developer_override() {
        let qkey = Some("4H5SCV7U38".to_string());
        // Intact and bound to QKey's certificate: trusted.
        assert_eq!(
            trust_from_codesign(&codesign(true, true, CODESIGN_SIGNED), false),
            (true, qkey.clone())
        );
        // Tampered: the metadata still names QKey, verification fails.
        assert_eq!(
            trust_from_codesign(&codesign(false, true, CODESIGN_SIGNED), false),
            (false, qkey.clone())
        );
        assert_eq!(
            trust_from_codesign(&codesign(false, false, CODESIGN_SIGNED), true),
            (false, qkey.clone()),
            "the override never trusts a signed program that fails verification"
        );
        // Intact but not QKey's certificate (another team, or a self-signed
        // certificate claiming the Team ID in its OU).
        assert_eq!(
            trust_from_codesign(&codesign(true, false, CODESIGN_OTHER_TEAM), false),
            (false, Some("ABCDE12345".to_string()))
        );
        assert_eq!(
            trust_from_codesign(&codesign(true, false, CODESIGN_OTHER_TEAM), true),
            (false, Some("ABCDE12345".to_string())),
            "the override never trusts another team"
        );
        assert_eq!(
            trust_from_codesign(&codesign(true, false, CODESIGN_SIGNED), false),
            (false, qkey.clone())
        );
        // Ad-hoc signed developer build: integrity holds, no certificate.
        assert_eq!(
            trust_from_codesign(&codesign(true, false, CODESIGN_ADHOC), false),
            (false, None)
        );
        assert_eq!(
            trust_from_codesign(&codesign(true, false, CODESIGN_ADHOC), true),
            (true, None)
        );
        // Unsigned: both checks fail.
        assert_eq!(
            trust_from_codesign(&codesign(false, false, CODESIGN_UNSIGNED), false),
            (false, None)
        );
        assert_eq!(
            trust_from_codesign(&codesign(false, false, CODESIGN_UNSIGNED), true),
            (true, None)
        );
        // Both checks passed but the info could not be read: still QKey.
        assert_eq!(
            trust_from_codesign(&codesign(true, true, ""), false),
            (true, qkey)
        );
    }

    #[test]
    fn tampered_qkey_signature_has_its_own_message() {
        let tampered = ProgramTrust {
            trusted: false,
            team_id: Some(QKEY_TEAM_ID.into()),
            in_applications: true,
        };
        let message = untrusted_message(&tampered);
        assert!(message.contains("does not verify"), "{message}");
        assert!(!message.contains("another developer"), "{message}");
        let mut status = serde_json::json!({"frequency": "off", "installed": false, "licensed": true, "history_count": 0, "last_run": null});
        status["program_trusted"] = serde_json::json!(false);
        status["program_team_id"] = serde_json::json!(QKEY_TEAM_ID);
        assert!(status_text(&status).contains("QKey signature does not verify"));
    }

    fn incomplete_report(findings: Vec<serde_json::Value>, failures: &[&str]) -> serde_json::Value {
        let mut r = report(findings);
        r["incomplete"] = serde_json::json!(!failures.is_empty());
        r["coverage_failures"] = serde_json::json!(failures
            .iter()
            .map(|l| serde_json::json!({"location": l, "reason": "permission denied"}))
            .collect::<Vec<_>>());
        r
    }

    #[test]
    fn incomplete_run_never_resolves_but_still_reports_new_and_notifies_lost_coverage() {
        let before = report(vec![
            finding("AwsKey", "~/.aws/credentials", "a", "high"),
            finding("GhToken", "~/.config/gh/hosts.yml", "b", "medium"),
        ]);
        // The AWS file could not be read, so its finding is absent; a new
        // Vault token appeared.
        let now = incomplete_report(
            vec![
                finding("GhToken", "~/.config/gh/hosts.yml", "b", "medium"),
                finding("Vault", "~/.vault-token", "c", "high"),
            ],
            &["~/.aws/credentials"],
        );
        let changes = diff(Some(&before), &now);
        assert!(changes.incomplete);
        assert_eq!(changes.coverage_failures, 1);
        assert!(changes.coverage_lost);
        assert_eq!(changes.resolved_count, 0, "{changes:?}");
        assert!(changes.resolved.is_empty());
        assert_eq!(changes.new_count, 1);
        assert_eq!(changes.new[0].kind, "Vault");
        assert!(changes.notify());
        let j = changes.json();
        assert_eq!(j["incomplete"], true);
        assert_eq!(j["coverage_failures"], 1);
        assert_eq!(j["coverage_lost"], true);
        assert_eq!(j["counts"]["resolved"], 0);

        // Nothing new, coverage lost: notified on that alone, with a
        // distinct message that carries no location.
        let quiet = incomplete_report(
            vec![finding("GhToken", "~/.config/gh/hosts.yml", "b", "medium")],
            &["~/.aws/credentials"],
        );
        let changes = diff(Some(&before), &quiet);
        assert_eq!(
            changes.new_count + changes.worsened_count + changes.resolved_count,
            0
        );
        assert!(changes.coverage_lost);
        assert!(changes.notify());
        assert_eq!(
            notification_body(&changes),
            "Gorse could not read 1 credential location; the check is incomplete. Open Gorse to review."
        );
        assert!(!notification_body(&changes).contains(".aws"));

        // Both messages when something is new as well.
        let changes = diff(Some(&before), &now);
        assert_eq!(
            notification_body(&changes),
            "1 new finding. Highest: High. Gorse could not read 1 credential location; the check is incomplete. Open Gorse to review."
        );

        // The previous run was itself incomplete: no coverage was lost
        // between the two, so a quiet incomplete run does not notify.
        let changes = diff(Some(&quiet), &quiet);
        assert!(changes.incomplete);
        assert!(!changes.coverage_lost);
        assert!(!changes.notify());

        // First run, incomplete: nothing to compare with, no notification.
        let changes = diff(None, &quiet);
        assert!(changes.first_run && changes.incomplete && !changes.coverage_lost);
        assert!(!changes.notify());

        // A complete run again: compared with the complete baseline, the
        // AWS finding is back and nothing is new or resolved.
        let changes = diff(Some(&before), &before);
        assert!(!changes.incomplete && !changes.coverage_lost);
        assert_eq!(changes, Changes::default());
    }

    #[test]
    fn baseline_skips_incomplete_runs() {
        let dir = std::env::temp_dir().join(format!(
            "gorse-schedule-baseline-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let complete = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let partial = incomplete_report(vec![], &["~/.aws/credentials"]);
        std::fs::write(dir.join("20260101T000001Z.json"), complete.to_string()).unwrap();
        std::fs::write(dir.join("20260101T000002Z.json"), partial.to_string()).unwrap();
        std::fs::write(dir.join("20260101T000003Z.json"), partial.to_string()).unwrap();
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        files.reverse();
        let (path, run) = baseline_file(&files, None).unwrap();
        assert!(path.ends_with("20260101T000001Z.json"));
        assert_eq!(run["findings"].as_array().unwrap().len(), 1);
        assert!(
            baseline_file(&files[..2], None).is_none(),
            "only incomplete runs: no baseline"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn incomplete_record_and_history_shapes() {
        assert_eq!(
            incomplete_message(2),
            "incomplete: 2 location(s) could not be read"
        );
        let before = report(vec![finding("AwsKey", "~/.aws/credentials", "a", "high")]);
        let now = incomplete_report(vec![], &["~/.aws/credentials"]);
        let changes = diff(Some(&before), &now);
        let record = RunRecord {
            at: "2026-11-03T09:30:00Z".into(),
            ok: !changes.incomplete,
            counts: counts_of(&now),
            message: incomplete_message(changes.coverage_failures),
            changes,
            trigger: Trigger::Scheduled,
            file: Some("20261103T093000Z.json".into()),
            baseline: Some("20261102T093000Z.json".into()),
        };
        let j = record.json();
        assert_eq!(j["ok"], false);
        assert_eq!(j["incomplete"], true);
        assert_eq!(j["coverage_failures"], 1);
        assert_eq!(j["resolved"], 0);
        assert_eq!(j["baseline"], "20261102T093000Z.json");
        assert_eq!(j["message"], "incomplete: 1 location(s) could not be read");

        let mut status = serde_json::json!({
            "frequency": "daily", "installed": true, "licensed": true, "history_count": 2,
        });
        status["last_run"] = j;
        let text = status_text(&status);
        assert!(text.contains("Last run: 2026-11-03 09:30 UTC, incomplete: 1 credential location could not be read"), "{text}");
        assert!(
            text.contains("Compared with: 20261102T093000Z.json"),
            "{text}"
        );

        let entry = serde_json::json!({
            "at": "2026-11-03T09:30:00Z", "trigger": "scheduled", "counts": counts_of(&now),
            "new": 0, "worsened": 0, "resolved": 0, "incomplete": true, "coverage_failures": 1,
        });
        let text = history_text(&[entry]);
        assert!(text.contains("Status"), "{text}");
        assert!(text.contains("incomplete (1 unreadable)"), "{text}");
        let ok = serde_json::json!({
            "at": "2026-11-03T09:30:00Z", "trigger": "manual", "counts": counts_of(&before),
            "new": 0, "worsened": 0, "resolved": 0, "incomplete": false, "coverage_failures": 0,
        });
        assert!(history_text(&[ok]).lines().nth(1).unwrap().ends_with("ok"));
    }

    #[test]
    fn program_trust_json_shape() {
        let t = ProgramTrust {
            trusted: true,
            team_id: None,
            in_applications: false,
        };
        let j = t.json();
        assert_eq!(j["program_trusted"], true);
        assert!(j["program_team_id"].is_null());
        assert_eq!(j["program_in_applications"], false);
        assert!(untrusted_message(&t).contains("not signed by QKey"));
        let other = ProgramTrust {
            trusted: false,
            team_id: Some("ABCDE12345".into()),
            in_applications: true,
        };
        assert!(untrusted_message(&other).contains("ABCDE12345"));
    }

    #[test]
    fn status_text_reads_well() {
        let status = serde_json::json!({
            "frequency": "daily", "installed": true, "program": "/bin/gorse",
            "program_exists": true, "licensed": true, "history_count": 2,
            "last_run": {"at": "2026-11-03T09:30:00Z", "ok": true,
                "counts": {"critical": 0, "high": 1, "medium": 2, "low": 3},
                "new": 0, "worsened": 0, "resolved": 1, "message": "ok"},
        });
        let text = status_text(&status);
        assert!(text.contains("Scheduled checks: daily at 09:30 (installed)"));
        assert!(text.contains("Last run: 2026-11-03 09:30 UTC, ok: 0 critical, 1 high, 2 medium, 3 low; 0 new, 0 worsened, 1 resolved"));
        assert!(text.contains("History: 2 recorded runs"));
        assert!(!text.contains("Program signature"), "{text}");
        let mut signed = status.clone();
        signed["program_trusted"] = serde_json::json!(true);
        signed["program_team_id"] = serde_json::json!("4H5SCV7U38");
        assert!(
            status_text(&signed).contains("Program signature: signed by QKey (team 4H5SCV7U38)")
        );
        let mut refused = status.clone();
        refused["program_trusted"] = serde_json::json!(false);
        refused["program_team_id"] = serde_json::Value::Null;
        assert!(status_text(&refused).contains("not signed by QKey; scheduled checks are refused"));
        let off = serde_json::json!({"frequency": "off", "installed": false, "licensed": false, "history_count": 0, "last_run": null});
        let text = status_text(&off);
        assert!(text.contains("Scheduled checks: off"));
        assert!(text.contains("Last run: never"));
        assert!(!text.contains('$'), "no prices in CLI text");
    }

    #[test]
    fn frequency_parsing() {
        assert_eq!(Frequency::parse("Daily"), Some(Frequency::Daily));
        assert_eq!(Frequency::parse(" hourly "), Some(Frequency::Hourly));
        assert_eq!(Frequency::parse("off"), Some(Frequency::Off));
        assert_eq!(Frequency::parse("weekly"), None);
    }

    /// Real launchd round trip. Only on macOS and only when asked for, so
    /// CI on Ubuntu and ordinary `cargo test` runs never touch LaunchAgents.
    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_install_and_remove() {
        if std::env::var("GORSE_SCHEDULE_TEST_INSTALL").as_deref() != Ok("1") {
            eprintln!("skipped: set GORSE_SCHEDULE_TEST_INSTALL=1 to exercise launchd");
            return;
        }
        let program = program_path().unwrap();
        install_entry(&program, Frequency::Hourly).unwrap();
        assert!(launchd_plist_path().unwrap().exists());
        assert!(entry_installed());
        remove_entry().unwrap();
        assert!(!launchd_plist_path().unwrap().exists());
        assert!(!entry_installed());
    }
}
