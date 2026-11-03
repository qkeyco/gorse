// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Gorse for Windows (also builds on macOS and Linux for development):
//! a window around `gorse exposure --json --html …` that lists every
//! credential on this computer, where it is, what it reaches and whether it
//! needs rotating or revoking at its service, and saves the HTML report. The command-line tool next to
//! this executable does all the reading; this program never opens a
//! credential file itself and never prints a secret.
#![cfg_attr(windows, windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

// ---------------------------------------------------------------- report ----

#[derive(Deserialize, Clone, Default)]
struct Report {
    /// The checker reports itself as `hedgehog_version` (schema v1 key, kept
    /// for compatibility); accept the new spelling too.
    #[serde(rename = "hedgehog_version", alias = "gorse_version")]
    cli_version: Option<String>,
    verified: Option<bool>,
    #[serde(default)]
    findings: Vec<Finding>,
    summary: Summary,
    #[serde(default)]
    notes: Vec<String>,
    /// A known credential location could not be read or interpreted (or a
    /// source an earlier recorded run assessed was not assessed): the
    /// findings may be missing something, so this is never "all clear".
    #[serde(default)]
    incomplete: bool,
    #[serde(default)]
    coverage_failures: Vec<CoverageFailure>,
    #[serde(default)]
    sources_assessed: Vec<String>,
    #[serde(default)]
    sources_unavailable: Vec<SourceUnavailable>,
    /// What changed since the last recorded run (`--record`). Read
    /// leniently: a missing or malformed value is no changes, never an
    /// unreadable report.
    #[serde(default, deserialize_with = "lenient_changes")]
    changes: Changes,
}

impl Report {
    /// Earlier findings this run could not reassess: the CLI's count (the
    /// list may be capped), never less than the list.
    fn unassessed_count(&self) -> u64 {
        self.changes
            .unassessed_count
            .max(self.changes.unassessed.len() as u64)
    }

    /// Incomplete by the CLI's flag, a coverage failure, or earlier
    /// findings that could not be reassessed: never shown as all clear.
    fn is_incomplete(&self) -> bool {
        self.incomplete
            || !self.coverage_failures.is_empty()
            || self.unassessed_count() > 0
            || self.changes.engine_coverage_lost
    }
}

/// `changes` in a recorded report, only the parts this window shows.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Changes {
    unassessed: Vec<ChangeEntry>,
    unassessed_count: u64,
    engine_coverage_lost: bool,
}

/// A finding an earlier recorded run made whose source this run could not
/// assess. `severity` is the severity it had then; `reason` says why it
/// could not be looked at again.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct ChangeEntry {
    kind: String,
    name: String,
    location: String,
    severity: String,
    reason: String,
}

impl ChangeEntry {
    fn title(&self) -> &str {
        if !self.name.is_empty() {
            &self.name
        } else if !self.kind.is_empty() {
            &self.kind
        } else {
            "Credential"
        }
    }
}

impl Changes {
    fn from_value(v: &serde_json::Value) -> Self {
        let text = |e: &serde_json::Value, key: &str| {
            e.get(key)
                .and_then(|s| s.as_str())
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };
        let unassessed = v
            .get("unassessed")
            .and_then(|u| u.as_array())
            .map(|list| {
                list.iter()
                    .filter(|e| e.is_object())
                    .map(|e| {
                        let previous = text(e, "previous_severity");
                        ChangeEntry {
                            kind: text(e, "kind"),
                            name: text(e, "name"),
                            location: text(e, "location"),
                            severity: if previous.is_empty() {
                                text(e, "severity")
                            } else {
                                previous
                            },
                            reason: text(e, "reason"),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Changes {
            unassessed,
            unassessed_count: v
                .get("counts")
                .and_then(|c| c.get("unassessed"))
                .and_then(|n| n.as_u64())
                .unwrap_or(0),
            engine_coverage_lost: v
                .get("engine_coverage_lost")
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
        }
    }
}

fn lenient_changes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Changes, D::Error> {
    let value = serde_json::Value::deserialize(d)?;
    Ok(Changes::from_value(&value))
}

#[derive(Deserialize, Clone, Default)]
struct CoverageFailure {
    location: String,
    reason: String,
}

#[derive(Deserialize, Clone, Default)]
struct SourceUnavailable {
    source: String,
    reason: String,
}

/// `summary.verification_counts`: what the provider checks of a verified
/// run came to, separately from each finding's confidence.
#[derive(Deserialize, Clone, Copy, Default, PartialEq, Eq, Debug)]
struct VerificationCounts {
    #[serde(default)]
    identity_confirmed: u64,
    #[serde(default)]
    permission_confirmed: u64,
    #[serde(default)]
    local_config: u64,
    /// Written by CLIs before the levels were split ("the tool ran"). Read
    /// so an older report still decodes and shows something honest.
    #[serde(default)]
    confirmed: u64,
    #[serde(default)]
    failed: u64,
    #[serde(default)]
    unsupported: u64,
    #[serde(default)]
    not_attempted: u64,
}

impl VerificationCounts {
    /// The report's own counts, or counted from the findings for a report
    /// that predates them.
    fn of(report: &Report) -> Self {
        if let Some(c) = report.summary.verification_counts {
            return c;
        }
        let mut c = Self::default();
        for f in &report.findings {
            match f.verification.as_ref().map(|v| v.status.as_str()) {
                Some("identity_confirmed") => c.identity_confirmed += 1,
                Some("permission_confirmed") => c.permission_confirmed += 1,
                Some("local_config") => c.local_config += 1,
                Some("confirmed") => c.confirmed += 1,
                Some("failed") => c.failed += 1,
                Some("unsupported") => c.unsupported += 1,
                _ => c.not_attempted += 1,
            }
        }
        c
    }

    fn summary(&self) -> String {
        let levels = self.identity_confirmed + self.permission_confirmed + self.local_config;
        if self.confirmed > 0 && levels == 0 {
            // An older CLI: it did not say what each check established.
            return format!(
                "{} answered, {} failed, {} unsupported",
                self.confirmed, self.failed, self.unsupported
            );
        }
        format!(
            "{} identity confirmed, {} permission confirmed, {} local configuration only, {} failed, {} unsupported",
            self.identity_confirmed,
            self.permission_confirmed,
            self.local_config,
            self.failed,
            self.unsupported
        )
    }
}

/// A finding's verification status in plain words. Tolerates the older
/// `confirmed` value, which only meant the tool ran.
fn verification_label(status: &str) -> &'static str {
    match status {
        "identity_confirmed" => "identity confirmed by provider",
        "permission_confirmed" => "permission confirmed by provider",
        "local_config" => "local configuration only, provider not asked",
        "confirmed" => "provider check ran",
        "failed" => "check failed",
        "unsupported" => "not supported yet",
        _ => "not checked with the provider",
    }
}

#[derive(Deserialize, Clone, Default)]
struct FindingVerification {
    status: String,
    #[serde(default)]
    detail: String,
}

#[derive(Deserialize, Clone, Default)]
struct Summary {
    #[serde(default)]
    credentials: u64,
    by_severity: Option<SeverityCounts>,
    critical_indirect_paths: Option<u64>,
    persistent_access_risks: Option<u64>,
    privileged_credentials: Option<u64>,
    verification_counts: Option<VerificationCounts>,
}

#[derive(Deserialize, Clone, Default)]
struct SeverityCounts {
    #[serde(default)]
    critical: u64,
}

#[derive(Deserialize, Clone)]
struct Finding {
    name: String,
    kind_label: Option<String>,
    location: Option<String>,
    identity: Option<String>,
    severity: String,
    confidence: Option<String>,
    lifetime: Option<String>,
    expired: Option<bool>,
    persistence: Option<Persistence>,
    #[serde(default)]
    paths: Vec<ReachPath>,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    remediation: Vec<String>,
    #[serde(default)]
    evidence: Vec<String>,
    /// Stable id of the discovery procedure that found it.
    source: Option<String>,
    verification: Option<FindingVerification>,
}

#[derive(Deserialize, Clone)]
struct Persistence {
    label: Option<String>,
    survives_cleanup: Option<bool>,
}

#[derive(Deserialize, Clone)]
struct ReachPath {
    target: String,
    target_production: Option<bool>,
    outcome_label: Option<String>,
    hops: Option<u32>,
}

// The file scan (`gorse-cli scan --deep --json`): secrets by content in
// Desktop, Documents, Downloads and Pictures, or the whole home folder.
#[derive(Deserialize, Clone, Default)]
struct ScanReport {
    #[serde(default)]
    engines: Vec<ScanEngine>,
    #[serde(default)]
    findings: Vec<ScanFinding>,
    #[serde(default)]
    total: u64,
    #[serde(default)]
    files_scanned: u64,
    #[serde(default)]
    elapsed_secs: u64,
    #[serde(default)]
    interrupted: bool,
    coverage: Option<ScanCoverage>,
}

#[derive(Deserialize, Clone, Default)]
struct ScanCoverage {
    #[serde(default)]
    complete: bool,
    has_gaps: Option<bool>,
    #[serde(default)]
    permission_denied: u64,
    #[serde(default)]
    files_over_size_limit: u64,
    #[serde(default)]
    files_skipped_by_type: u64,
    #[serde(default)]
    dirs_skipped_by_rule: u64,
    limit_reached: Option<String>,
}

#[derive(Deserialize, Clone, Default)]
#[allow(dead_code)]
struct ScanEngine {
    #[serde(default)]
    name: String,
    version: Option<String>,
    findings: Option<u64>,
    error: Option<String>,
}

#[derive(Deserialize, Clone)]
struct ScanFinding {
    rotation_guide: Option<String>,
    path: String,
    category: String,
    severity: String,
    #[serde(default)]
    line: u64,
    #[serde(default)]
    preview: String,
    #[serde(default)]
    description: String,
}

// Which plan this computer is on, from the CLI's licence state.
#[derive(Deserialize, Clone, Default)]
struct LicenseStatus {
    tier: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct ActivateResponse {
    error: Option<String>,
    license: Option<LicenseStatus>,
}

#[derive(Clone, Default)]
struct License {
    tier: String,
    email: Option<String>,
}

impl License {
    fn is_paid(&self) -> bool {
        self.tier == "pro" || self.tier == "team"
    }
    fn label(&self) -> &'static str {
        match self.tier.as_str() {
            "pro" => "Pro",
            "team" => "Team",
            _ => "Free",
        }
    }
}

const PRICING_URL: &str = "https://www.gorse.is/pricing";
const DASHBOARD_URL: &str = "https://www.gorse.is/dashboard";

fn run_cli(args: &[&str], input: Option<&str>) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let cli = cli_path().ok_or_else(|| {
        "The checker is missing. Keep gorse-cli.exe in the same folder as this program.".to_string()
    })?;
    let mut cmd = Command::new(&cli);
    cmd.args(args);
    cmd.stdin(if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not start the checker: {e}"))?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        // The key goes over stdin so it never appears in a process list.
        let _ = stdin.write_all(text.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("The checker did not finish: {e}"))?;
    Ok(output.stdout)
}

fn license_status() -> License {
    let Ok(out) = run_cli(&["license", "status", "--json"], None) else {
        return License::default();
    };
    let parsed: LicenseStatus = serde_json::from_slice(&out).unwrap_or_default();
    License {
        tier: parsed
            .tier
            .unwrap_or_else(|| "free".into())
            .to_ascii_lowercase(),
        email: parsed.email,
    }
}

/// Activates a key the user typed; the CLI validates it against gorse.is
/// and stores the lease. Returns the new state or an error to show.
fn activate_key(key: &str) -> Result<License, String> {
    let out = run_cli(&["activate", "--stdin", "--json"], Some(key.trim()))?;
    if let Ok(r) = serde_json::from_slice::<ActivateResponse>(&out) {
        if let Some(e) = r.error.filter(|e| !e.is_empty()) {
            return Err(e);
        }
        if let Some(l) = r.license {
            return Ok(License {
                tier: l.tier.unwrap_or_else(|| "free".into()).to_ascii_lowercase(),
                email: l.email,
            });
        }
    }
    if let Ok(l) = serde_json::from_slice::<LicenseStatus>(&out) {
        return Ok(License {
            tier: l.tier.unwrap_or_else(|| "free".into()).to_ascii_lowercase(),
            email: l.email,
        });
    }
    Err("The key could not be activated.".into())
}

/// Tells the checker that a target is a production system, then the caller
/// runs the check again.
fn mark_production(target: &str) -> Result<(), String> {
    let out = run_cli(&["exposure", "--mark-production", target, "--json"], None)?;
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) {
        if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
            return Err(e.to_string());
        }
    }
    Ok(())
}

/// What the window says about a newer Gorse.
#[derive(Clone, Debug, PartialEq, Eq)]
enum UpdateNotice {
    /// Newer, and its signed release manifest verified: offer the download.
    Verified(String),
    /// Newer but not verified (missing, invalid, unbound, unreachable or
    /// mismatched signature): say so calmly, offer no download.
    Unverified(String),
}

/// Asks the checker whether a newer Gorse exists (one request to
/// gorse.is carrying only the version).
fn update_notice() -> Option<UpdateNotice> {
    let out = run_cli(&["version", "--check", "--json"], None).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out).ok()?;
    update_notice_of(&v)
}

/// A download is offered only when the checker says the release is newer
/// *and* its signature verified; `newer_available` alone is not enough.
/// The checker only reports a `signature` for a newer published version,
/// so any other signature value is a newer version it will not recommend.
fn update_notice_of(v: &serde_json::Value) -> Option<UpdateNotice> {
    let latest = v
        .get("latest")
        .and_then(|l| l.as_str())
        .map(str::trim)
        .filter(|l| !l.is_empty())?
        .to_string();
    let newer = v.get("newer_available").and_then(|n| n.as_bool()) == Some(true);
    let signature = v.get("signature").and_then(|s| s.as_str());
    match signature {
        Some("verified") if newer => Some(UpdateNotice::Verified(latest)),
        Some("verified") => None,
        Some(_) => Some(UpdateNotice::Unverified(latest)),
        None if newer => Some(UpdateNotice::Unverified(latest)),
        None => None,
    }
}

const DOWNLOAD_URL: &str = "https://www.gorse.is/download";
const SECURITY_URL: &str = "https://www.gorse.is/trust";

// Optional engines, via the CLI: status, and a one-click TruffleHog install
// with download progress streamed on stderr.
#[derive(Clone, Default)]
struct EngineState {
    installed: bool,
    managed: bool,
    version: Option<String>,
    download_mb: u64,
}

fn engine_status() -> EngineState {
    let Ok(out) = run_cli(&["engines", "status", "--json"], None) else {
        return EngineState {
            download_mb: 75,
            ..Default::default()
        };
    };
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap_or_default();
    let t = &v["trufflehog"];
    EngineState {
        installed: t["installed"].as_bool().unwrap_or(false),
        managed: t["managed"].as_bool().unwrap_or(false),
        version: t["version"].as_str().map(|s| s.to_string()),
        download_mb: t["download_mb"].as_u64().unwrap_or(75),
    }
}

#[derive(Clone, Default)]
struct DownloadProgress {
    received: u64,
    total: Option<u64>,
}

type SharedDownload = std::sync::Arc<std::sync::Mutex<DownloadProgress>>;

fn install_trufflehog(progress: SharedDownload) -> Result<(), String> {
    use std::io::{BufRead, Read};
    let cli = cli_path().ok_or("The checker is missing.")?;
    let mut cmd = Command::new(&cli);
    cmd.args(["engines", "install", "trufflehog", "--json", "--progress"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not start the checker: {e}"))?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let p = progress.clone();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if v.get("event").and_then(|e| e.as_str()) == Some("download") {
                    let mut g = p.lock().unwrap();
                    g.received = v
                        .get("received")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(g.received);
                    g.total = v.get("total").and_then(|x| x.as_u64());
                }
            }
        }
    });
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = reader.join();
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) {
        if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
            return Err(e.to_string());
        }
    }
    if !status.success() {
        return Err("TruffleHog could not be installed.".into());
    }
    Ok(())
}

fn open_url(url: &str) {
    #[cfg(windows)]
    let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = Command::new("xdg-open").arg(url).spawn();
}

fn severity_rank(s: &str) -> usize {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn severity_color(s: &str) -> Color32 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Color32::from_rgb(220, 53, 69),
        "high" => Color32::from_rgb(230, 126, 34),
        "medium" => Color32::from_rgb(201, 162, 39),
        _ => Color32::from_rgb(52, 120, 220),
    }
}

// ---------------------------------------------------------------- runner ----

/// The command-line tool that does the work. It ships next to this program
/// as `gorse-cli` (`Gorse.exe` and `gorse.exe` would be the same
/// file on a case-insensitive disk), with a fallback to `gorse` on PATH or,
/// for development, in the same target tree. Never this program itself.
fn cli_path() -> Option<PathBuf> {
    let (bundled, plain) = if cfg!(windows) {
        ("gorse-cli.exe", "gorse.exe")
    } else {
        ("gorse-cli", "gorse")
    };
    let here = std::env::current_exe().ok()?;
    let me = here.canonicalize().unwrap_or(here.clone());
    let dir = here.parent()?.to_path_buf();
    let mut candidates = vec![
        dir.join(bundled),
        dir.join(plain),
        dir.join("..").join("release").join(plain),
        dir.join("..").join("debug").join(plain),
    ];
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|p| p.join(plain)));
    }
    candidates
        .into_iter()
        .find(|c| c.is_file() && c.canonicalize().map(|real| real != me).unwrap_or(false))
}

/// Where the HTML report of the latest run lives until the user saves it.
fn report_path() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
            })
    };
    let dir = base.unwrap_or_else(std::env::temp_dir).join("Gorse");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("exposure.html")
}

enum Outcome {
    Done {
        report: Box<Report>,
        html: PathBuf,
    },
    /// The checker declined before doing anything (a `--verify` run on the
    /// Free plan): its own message, shown with the upgrade link.
    Refused(String),
    Failed(String),
}

/// What Verify does, shown before it runs. The provider tools are the
/// person's own; nothing is sent to Gorse.
const VERIFY_EXPLANATION: &str = "Verify asks your own installed provider tools read-only questions (aws, gh, kubectl, vault, gcloud, az, doctl); nothing is sent to Gorse.";

/// Runs the check on a worker thread. Exit 1 means findings at or above
/// "high" and exit 3 an incomplete check; both are results. Only exit 2 or
/// a crash is a failure. Every run is recorded in the check history
/// (`--record`), as the Mac app does; with `verify` it also asks the
/// providers (`--verify`, Pro).
fn run_check(verify: bool) -> Receiver<Outcome> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let outcome = (|| {
            let cli = cli_path().ok_or_else(|| {
                "The checker is missing. Keep gorse-cli.exe in the same folder as this program."
                    .to_string()
            })?;
            let html = report_path();
            let _ = std::fs::remove_file(&html);
            let mut cmd = Command::new(&cli);
            cmd.args(["exposure", "--json", "--record", "--html"])
                .arg(&html);
            if verify {
                cmd.arg("--verify");
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flashes up
            }
            let output = cmd
                .output()
                .map_err(|e| format!("Could not start the checker: {e}"))?;
            let code = output.status.code().unwrap_or(2);
            if code == 2 {
                // The checker refuses `--verify` on the Free plan with
                // `{"error": ...}` on stdout; that is a message, not a crash.
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
                        return Ok(Err(e.to_string()));
                    }
                }
            }
            if !matches!(code, 0 | 1 | 3) {
                let err = String::from_utf8_lossy(&output.stderr);
                let tail: String = err
                    .chars()
                    .rev()
                    .take(2000)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                return Err(if tail.trim().is_empty() {
                    "The check could not complete.".into()
                } else {
                    tail.trim().to_string()
                });
            }
            let report: Report = serde_json::from_slice(&output.stdout).map_err(|_| {
                "The checker returned a report this program could not read.".to_string()
            })?;
            Ok(Ok((report, html)))
        })();
        let _ = tx.send(match outcome {
            Ok(Ok((report, html))) => Outcome::Done {
                report: Box::new(report),
                html,
            },
            Ok(Err(refusal)) => Outcome::Refused(refusal),
            Err(e) => Outcome::Failed(e),
        });
    });
    rx
}

/// The report's `confidence` value in plain words.
fn confidence_label(confidence: Option<&str>) -> &'static str {
    match confidence.map(|c| c.to_ascii_lowercase()).as_deref() {
        Some("confirmed") => "confirmed",
        Some("inferred") => "inferred",
        _ => "could not be checked",
    }
}

fn confidence_color(label: &str) -> Color32 {
    match label {
        "confirmed" => Color32::from_rgb(40, 167, 69),
        "inferred" => Color32::from_rgb(201, 162, 39),
        _ => Color32::GRAY,
    }
}

#[derive(Clone, Default)]
struct ScanProgress {
    files: u64,
    findings: u64,
    dir: Option<String>,
    phase: Option<String>,
}

type SharedProgress = std::sync::Arc<std::sync::Mutex<ScanProgress>>;

enum ScanOutcome {
    Done(ScanReport),
    Failed(String),
}

/// Runs the file scan on a worker thread, with `--progress` lines from the
/// checker's stderr folded into `progress` as they arrive. Exit codes other
/// than 0 are errors.
fn run_scan(whole_home: bool, progress: SharedProgress) -> Receiver<ScanOutcome> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let outcome = (|| {
            use std::io::{BufRead, Read};
            let cli = cli_path().ok_or_else(|| {
                "The checker is missing. Keep gorse-cli.exe in the same folder as this program."
                    .to_string()
            })?;
            let mut cmd = Command::new(&cli);
            cmd.args(["scan", "--deep", "--json", "--progress"]);
            if whole_home {
                cmd.arg("--all-dirs");
            }
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x0800_0000);
            }
            let mut child = cmd
                .spawn()
                .map_err(|e| format!("Could not start the scanner: {e}"))?;
            let stderr = child.stderr.take().ok_or("no stderr")?;
            let mut stdout = child.stdout.take().ok_or("no stdout")?;
            let progress_for_reader = progress.clone();
            let reader = std::thread::spawn(move || {
                let mut other = String::new();
                for line in std::io::BufReader::new(stderr)
                    .lines()
                    .map_while(Result::ok)
                {
                    if line.starts_with('{') {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                            let mut p = progress_for_reader.lock().unwrap();
                            match v.get("event").and_then(|e| e.as_str()) {
                                Some("progress") => {
                                    p.files = v
                                        .get("files_scanned")
                                        .and_then(|x| x.as_u64())
                                        .unwrap_or(p.files);
                                    p.findings = v
                                        .get("findings")
                                        .and_then(|x| x.as_u64())
                                        .unwrap_or(p.findings);
                                    if let Some(d) = v.get("dir").and_then(|x| x.as_str()) {
                                        p.dir = Some(d.to_string());
                                    }
                                    p.phase = None;
                                }
                                Some("phase") => {
                                    p.phase = v
                                        .get("name")
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                }
                                _ => {}
                            }
                        }
                    } else if other.len() < 4000 {
                        other.push_str(&line);
                        other.push('\n');
                    }
                }
                other
            });
            let mut out = Vec::new();
            stdout.read_to_end(&mut out).map_err(|e| e.to_string())?;
            let status = child
                .wait()
                .map_err(|e| format!("The scanner did not finish: {e}"))?;
            let other = reader.join().unwrap_or_default();
            if !status.success() {
                let tail = other.trim();
                return Err(if tail.is_empty() {
                    "The scan could not complete.".into()
                } else {
                    tail.chars()
                        .rev()
                        .take(2000)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect()
                });
            }
            serde_json::from_slice::<ScanReport>(&out).map_err(|_| {
                "The scanner returned a report this program could not read.".to_string()
            })
        })();
        let _ = tx.send(match outcome {
            Ok(r) => ScanOutcome::Done(r),
            Err(e) => ScanOutcome::Failed(e),
        });
    });
    rx
}

fn open_path(path: &Path) {
    #[cfg(windows)]
    let _ = Command::new("cmd")
        .args(["/C", "start", ""])
        .arg(path)
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = Command::new("xdg-open").arg(path).spawn();
}

fn reveal_path(path: &Path) {
    #[cfg(windows)]
    let _ = Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = Command::new("open").arg("-R").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(dir) = path.parent() {
        let _ = Command::new("xdg-open").arg(dir).spawn();
    }
}

fn home_abbrev(location: &str) -> String {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(|h| h.to_string_lossy().into_owned());
    match home {
        Some(h) if !h.is_empty() && location.starts_with(&h) => {
            format!("~{}", &location[h.len()..])
        }
        _ => location.to_string(),
    }
}

// ------------------------------------------------------------------- app ----

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Reach,
    Files,
}

struct App {
    engine: EngineState,
    engine_rx: Option<Receiver<EngineState>>,
    install_rx: Option<Receiver<Result<(), String>>>,
    install_progress: SharedDownload,
    install_error: Option<String>,
    scan_progress: SharedProgress,
    update_rx: Option<Receiver<Option<UpdateNotice>>>,
    newer: Option<UpdateNotice>,
    update_dismissed: bool,
    mark_rx: Option<Receiver<Result<(), String>>>,
    license: License,
    license_rx: Option<Receiver<Result<License, String>>>,
    key_entry: Option<String>,
    key_error: Option<String>,
    mode: Mode,
    scan_running: Option<Receiver<ScanOutcome>>,
    scan: Option<ScanReport>,
    scan_error: Option<String>,
    whole_home: bool,
    running: Option<Receiver<Outcome>>,
    report: Option<Report>,
    html: Option<PathBuf>,
    error: Option<String>,
    expanded: std::collections::HashSet<String>,
    started_at: Option<std::time::Instant>,
    /// Verify was clicked: the explanation is showing, waiting for a go.
    verify_armed: bool,
    /// The checker's refusal of the last Verify (Free plan).
    verify_refused: Option<String>,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            engine: EngineState {
                download_mb: 75,
                ..Default::default()
            },
            engine_rx: None,
            install_rx: None,
            install_progress: SharedDownload::default(),
            install_error: None,
            scan_progress: SharedProgress::default(),
            update_rx: None,
            newer: None,
            update_dismissed: false,
            mark_rx: None,
            license: License::default(),
            license_rx: None,
            key_entry: None,
            key_error: None,
            mode: Mode::Reach,
            scan_running: None,
            scan: None,
            scan_error: None,
            whole_home: false,
            running: None,
            report: None,
            html: None,
            error: None,
            expanded: Default::default(),
            started_at: None,
            verify_armed: false,
            verify_refused: None,
        };
        app.start();
        app
    }

    fn refresh_engines(&mut self) {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(engine_status());
        });
        self.engine_rx = Some(rx);
    }

    fn refresh_license(&mut self) {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(Ok(license_status()));
        });
        self.license_rx = Some(rx);
    }

    fn submit_key(&mut self, key: String) {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(activate_key(&key));
        });
        self.license_rx = Some(rx);
    }

    fn start(&mut self) {
        if self.license_rx.is_none() && self.license.tier.is_empty() {
            self.refresh_license();
            let (tx, rx) = channel();
            std::thread::spawn(move || {
                let _ = tx.send(update_notice());
            });
            self.update_rx = Some(rx);
            self.refresh_engines();
        }
        self.error = None;
        self.verify_refused = None;
        self.verify_armed = false;
        self.started_at = Some(std::time::Instant::now());
        self.running = Some(run_check(false));
    }

    /// The Verify run: the same check, with the providers asked. The
    /// checker gates it on the licence itself.
    fn start_verify(&mut self) {
        self.error = None;
        self.verify_refused = None;
        self.verify_armed = false;
        self.started_at = Some(std::time::Instant::now());
        self.running = Some(run_check(true));
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.engine_rx {
            match rx.try_recv() {
                Ok(state) => {
                    self.engine = state;
                    self.engine_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.engine_rx = None,
                Err(_) => ctx.request_repaint_after(Duration::from_millis(500)),
            }
        }
        if let Some(rx) = &self.install_rx {
            match rx.try_recv() {
                Ok(Ok(())) => {
                    self.install_rx = None;
                    self.refresh_engines();
                }
                Ok(Err(message)) => {
                    self.install_rx = None;
                    self.install_error = Some(message);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.install_rx = None,
                Err(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
        if let Some(rx) = &self.update_rx {
            match rx.try_recv() {
                Ok(newer) => {
                    self.newer = newer;
                    self.update_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.update_rx = None,
                Err(_) => ctx.request_repaint_after(Duration::from_millis(500)),
            }
        }
        if let Some(rx) = &self.mark_rx {
            match rx.try_recv() {
                Ok(Ok(())) => {
                    self.mark_rx = None;
                    self.start();
                }
                Ok(Err(message)) => {
                    self.mark_rx = None;
                    self.error = Some(message);
                }
                Err(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
        if let Some(rx) = &self.license_rx {
            match rx.try_recv() {
                Ok(Ok(license)) => {
                    let paid = license.is_paid();
                    self.license = license;
                    self.license_rx = None;
                    if paid {
                        self.key_entry = None;
                        self.key_error = None;
                    } else if self.key_entry.is_some() && self.key_error.is_none() {
                        self.key_error = Some("The key was accepted but no paid plan is active. Check your dashboard at gorse.is.".into());
                    }
                }
                Ok(Err(message)) => {
                    self.key_error = Some(message);
                    self.license_rx = None;
                }
                Err(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
        if let Some(rx) = &self.scan_running {
            match rx.try_recv() {
                Ok(ScanOutcome::Done(report)) => {
                    self.scan = Some(report);
                    self.scan_running = None;
                }
                Ok(ScanOutcome::Failed(message)) => {
                    self.scan = None;
                    self.scan_error = Some(message);
                    self.scan_running = None;
                }
                Err(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
        if let Some(rx) = &self.running {
            match rx.try_recv() {
                Ok(Outcome::Done { report, html }) => {
                    self.html = html.is_file().then_some(html);
                    self.report = Some(*report);
                    self.running = None;
                }
                Ok(Outcome::Refused(message)) => {
                    // The previous report stays; only the refusal is shown.
                    self.verify_refused = Some(message);
                    self.running = None;
                }
                Ok(Outcome::Failed(message)) => {
                    self.report = None;
                    self.html = None;
                    self.error = Some(message);
                    self.running = None;
                }
                Err(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
    }

    fn save_report(&mut self) {
        let Some(html) = &self.html else { return };
        if let Some(dest) = rfd::FileDialog::new()
            .set_title("Save the exposure report")
            .set_file_name("gorse-exposure.html")
            .add_filter("Web page", &["html"])
            .save_file()
        {
            if let Err(e) = std::fs::copy(html, &dest) {
                self.error = Some(format!("The report could not be saved: {e}"));
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        egui::TopBottomPanel::top("mode").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.mode, Mode::Reach, "Fast Scan");
                ui.selectable_value(&mut self.mode, Mode::Files, "Deep Scan");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("Gorse {}", env!("CARGO_PKG_VERSION"))).strong(),
                    );
                    ui.separator();
                    let paid = self.license.is_paid();
                    let badge_color = if paid {
                        Color32::from_rgb(40, 167, 69)
                    } else {
                        Color32::GRAY
                    };
                    if paid {
                        if ui.small_button("Manage…").clicked() {
                            open_url(DASHBOARD_URL);
                        }
                        if let Some(e) = &self.license.email {
                            ui.label(RichText::new(e).small().weak());
                        }
                    } else {
                        if ui.small_button("Enter Key…").clicked() {
                            self.key_entry = Some(String::new());
                            self.key_error = None;
                        }
                        if ui.small_button("Upgrade to Pro").clicked() {
                            open_url(PRICING_URL);
                        }
                    }
                    egui::Frame::new()
                        .fill(badge_color.linear_multiply(0.18))
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .corner_radius(4)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(self.license.label())
                                    .small()
                                    .strong()
                                    .color(badge_color),
                            );
                        });
                });
            });
            ui.add_space(4.0);
        });
        if let Some(notice) = self.newer.clone() {
            if !self.update_dismissed {
                egui::TopBottomPanel::top("update").show(ctx, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        match &notice {
                            UpdateNotice::Verified(latest) => {
                                ui.label(
                                    RichText::new(format!("Gorse {latest} is available."))
                                        .color(Color32::from_rgb(52, 120, 220)),
                                );
                                ui.label(RichText::new("Signed release").small().weak())
                                    .on_hover_text("The release signature verified.");
                                if ui.small_button("Download").clicked() {
                                    open_url(DOWNLOAD_URL);
                                }
                            }
                            UpdateNotice::Unverified(_) => {
                                ui.label(
                                    RichText::new("A newer version is published but could not be verified, so it is not recommended.")
                                        .weak(),
                                );
                                if ui.link("gorse.is/trust").clicked() {
                                    open_url(SECURITY_URL);
                                }
                            }
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("✕").clicked() {
                                self.update_dismissed = true;
                            }
                        });
                    });
                    ui.add_space(4.0);
                });
            }
        }
        if self.key_entry.is_some() {
            let mut open = true;
            let mut submit: Option<String> = None;
            let mut cancel = false;
            let busy = self.license_rx.is_some();
            let error = self.key_error.clone();
            egui::Window::new("Enter your licence key").collapsible(false).resizable(false).open(&mut open).show(ctx, |ui| {
                ui.label(RichText::new("Your key is in your dashboard at gorse.is after purchase. It is sent to gorse.is to bind a lease to this computer and is not kept by this program.").small().weak());
                if let Some(k) = self.key_entry.as_mut() {
                    ui.add(egui::TextEdit::singleline(k).password(true).desired_width(360.0).hint_text("Licence key"));
                }
                if let Some(e) = &error { ui.label(RichText::new(e).small().color(severity_color("critical"))); }
                ui.horizontal(|ui| {
                    if ui.button("Get a key…").clicked() { open_url(PRICING_URL); }
                    let filled = self.key_entry.as_deref().map(|k| !k.trim().is_empty()).unwrap_or(false);
                    if ui.add_enabled(filled && !busy, egui::Button::new(if busy { "Activating…" } else { "Activate" })).clicked() {
                        submit = self.key_entry.clone();
                    }
                    if ui.button("Cancel").clicked() { cancel = true; }
                });
            });
            if let Some(k) = submit {
                self.key_error = None;
                self.submit_key(k);
            }
            if cancel || !open {
                self.key_entry = None;
                self.key_error = None;
            }
        }
        if self.mode == Mode::Files {
            self.files_ui(ctx);
            return;
        }
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.heading("Fast scan: what this computer reaches");
                    ui.label(RichText::new(self.subtitle()).small().weak());
                    ui.label(
                        RichText::new("The places tools keep credentials, about 60 known locations, not every file. Deep Scan reads everything else.")
                            .small()
                            .weak(),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let busy = self.running.is_some();
                    let label = if busy { "Scanning…" } else if self.report.is_some() { "Run Again" } else { "Run Fast Scan" };
                    if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                        self.start();
                    }
                    if ui
                        .add_enabled(!busy && !self.verify_armed, egui::Button::new("Verify with providers (Pro)"))
                        .on_hover_text(VERIFY_EXPLANATION)
                        .clicked()
                    {
                        self.verify_armed = true;
                        self.verify_refused = None;
                    }
                    let has_html = self.html.is_some();
                    if ui
                        .add_enabled(has_html, egui::Button::new("Save Report…"))
                        .clicked()
                    {
                        self.save_report();
                    }
                    if ui
                        .add_enabled(has_html, egui::Button::new("Open Report"))
                        .clicked()
                    {
                        if let Some(h) = &self.html {
                            open_path(h);
                        }
                    }
                });
            });
            if self.verify_armed {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(VERIFY_EXPLANATION).small());
                    if ui.small_button("Verify now").clicked() {
                        self.start_verify();
                    }
                    if ui.small_button("Cancel").clicked() {
                        self.verify_armed = false;
                    }
                });
            }
            if let Some(refusal) = self.verify_refused.clone() {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(refusal).small().color(severity_color("high")));
                    if ui.small_button("Upgrade to Pro").clicked() {
                        open_url(PRICING_URL);
                    }
                    ui.label(RichText::new(PRICING_URL).small().weak());
                });
            }
            if let Some(report) = self.report.clone() {
                ui.add_space(8.0);
                self.summary_strip(ui, &report.summary);
                let unassessed = report.unassessed_count();
                if unassessed > 0 {
                    ui.label(
                        RichText::new(format!(
                            "+ {unassessed} not assessed: earlier findings not counted above that may still be present."
                        ))
                        .small()
                        .color(AMBER),
                    );
                }
                if report.verified == Some(true) {
                    ui.label(
                        RichText::new(format!(
                            "Verified with providers: {}.",
                            VerificationCounts::of(&report).summary()
                        ))
                        .small(),
                    );
                }
            }
            ui.add_space(8.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(message) = self.error.clone() {
                placeholder(ui, "The check could not complete", &message);
            } else if self.running.is_some() {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.spinner();
                    ui.add_space(8.0);
                    ui.label("Reading credential files, agent settings and signed-in sessions on this computer…");
                    ui.label(RichText::new("Nothing leaves this computer. No secret is shown.").small().weak());
                });
            } else if let Some(report) = self.report.clone() {
                if report.is_incomplete() {
                    incomplete_banner(ui, &report);
                    if report.unassessed_count() > 0 {
                        unassessed_section(ui, &report);
                    }
                    if !report.findings.is_empty() {
                        self.findings_list(ui, &report);
                    }
                } else if report.findings.is_empty() {
                    placeholder(ui, "No credentials found",
                        "Nothing on this computer matched a credential location Gorse knows.");
                } else {
                    self.findings_list(ui, &report);
                }
            } else {
                placeholder(ui, "Checking this computer…", "");
            }
        });
    }
}

impl App {
    fn files_ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("files-header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.heading("Deep scan: files for secrets");
                    let sub = match &self.scan {
                        None => "Documents, Desktop, Downloads and Pictures, including the text inside screenshots. Nothing leaves this computer.".to_string(),
                        Some(r) => {
                            let mut t = format!("{} finding{} in {} file{}", r.total, if r.total == 1 { "" } else { "s" }, r.files_scanned, if r.files_scanned == 1 { "" } else { "s" });
                            if r.elapsed_secs > 0 { t.push_str(&format!(", {}s", r.elapsed_secs)); }
                            if r.interrupted { t.push_str(" (stopped early)"); }
                            if let Some(th) = r.engines.iter().find(|e| e.name == "trufflehog") {
                                if th.error.is_none() {
                                    t.push_str(&format!(" · with TruffleHog {}", th.version.clone().unwrap_or_default()));
                                } else {
                                    t.push_str(" · TruffleHog failed");
                                }
                            }
                            t
                        }
                    };
                    ui.label(RichText::new(sub).small().weak());
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let busy = self.scan_running.is_some();
                    let label = if busy { "Scanning…" } else if self.whole_home { "Deep Scan, Whole Home" } else { "Deep Scan" };
                    if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                        self.scan_error = None;
                        *self.scan_progress.lock().unwrap() = ScanProgress::default();
                        self.scan_running = Some(run_scan(self.whole_home, self.scan_progress.clone()));
                    }
                    let paid = self.license.is_paid();
                    if !paid { self.whole_home = false; }
                    ui.add_enabled(!busy && paid, egui::Checkbox::new(&mut self.whole_home, "Whole home folder (Pro, slower)"));
                    if !paid {
                        if ui.small_button("Upgrade to Pro").clicked() { open_url(PRICING_URL); }
                        ui.label(RichText::new("Free plan").small().weak());
                    }
                });
            });
            ui.add_space(6.0);
            if self.engine.installed {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(if self.engine.managed {
                        format!("TruffleHog {} is installed: its ≈800 detectors run with every Deep Scan, verification off.", self.engine.version.clone().unwrap_or_default())
                    } else {
                        "TruffleHog found on this computer: its detectors run with every Deep Scan, verification off.".to_string()
                    }).small().weak());
                });
            } else if self.install_rx.is_some() {
                let p = self.install_progress.lock().unwrap().clone();
                let mb = p.received as f64 / 1_048_576.0;
                match p.total {
                    Some(t) if t > 0 => {
                        ui.add(egui::ProgressBar::new((p.received as f64 / t as f64).min(1.0) as f32).text(format!("Downloading TruffleHog… {:.0} of {:.0} MB", mb, t as f64 / 1_048_576.0)));
                    }
                    _ => { ui.label(format!("Downloading TruffleHog… {mb:.0} MB")); }
                }
                ctx.request_repaint_after(Duration::from_millis(250));
            } else {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Add TruffleHog's ≈800 detectors.").small().strong());
                    ui.label(RichText::new(format!("Open source, by Truffle Security. A {} MB download from GitHub (about 175 MB on disk), checked against a known checksum and kept in Gorse's own folder. Runs with verification off, so nothing leaves this computer.", self.engine.download_mb)).small().weak());
                    if ui.small_button("Add TruffleHog").clicked() {
                        self.install_error = None;
                        *self.install_progress.lock().unwrap() = DownloadProgress::default();
                        let progress = self.install_progress.clone();
                        let (tx, rx) = channel();
                        std::thread::spawn(move || {
                            let _ = tx.send(install_trufflehog(progress));
                        });
                        self.install_rx = Some(rx);
                    }
                });
                if let Some(e) = &self.install_error {
                    ui.label(RichText::new(e).small().color(severity_color("critical")));
                }
            }
            ui.add_space(8.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(message) = self.scan_error.clone() {
                placeholder(ui, "The scan could not complete", &message);
            } else if self.scan_running.is_some() {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.spinner();
                    ui.add_space(8.0);
                    let p = self.scan_progress.lock().unwrap().clone();
                    match p.phase.as_deref() {
                        Some("images") => { ui.label("Reading the text inside pictures…"); }
                        Some("notes") => { ui.label("Reading notes…"); }
                        Some("trufflehog") => {
                            ui.label("Running TruffleHog's detectors…");
                        }
                        Some(_) => { ui.label("Finishing…"); }
                        None if p.files == 0 && p.dir.is_none() => { ui.label("Starting…"); }
                        None => {
                            ui.label(RichText::new(format!("{} files read · {} finding{} so far", p.files, p.findings, if p.findings == 1 { "" } else { "s" })).strong());
                            if let Some(d) = &p.dir { ui.label(RichText::new(home_abbrev(d)).monospace().small().weak()); }
                        }
                    }
                    ctx.request_repaint_after(Duration::from_millis(250));
                });
            } else if let Some(report) = self.scan.clone() {
                let gaps = report.coverage.as_ref().map(|c| c.has_gaps.unwrap_or(!c.complete)).unwrap_or(true) || report.interrupted;
                if let Some(c) = &report.coverage {
                    if gaps {
                        let mut why = Vec::new();
                        if c.permission_denied > 0 { why.push(format!("{} files could not be read (permission denied)", c.permission_denied)); }
                        if c.files_over_size_limit > 0 { why.push(format!("{} files over the size limit", c.files_over_size_limit)); }
                        if c.files_skipped_by_type > 0 { why.push(format!("{} files of a type that is checked by name only", c.files_skipped_by_type)); }
                        if c.dirs_skipped_by_rule > 0 { why.push(format!("{} app or developer folders skipped", c.dirs_skipped_by_rule)); }
                        if let Some(l) = &c.limit_reached { why.push(format!("stopped early: {l}")); }
                        ui.label(RichText::new(format!("Scan finished with gaps: {}.", if why.is_empty() { "not everything was checked".to_string() } else { why.join("; ") })).small().color(severity_color("high")));
                        ui.separator();
                    }
                }
                if report.findings.is_empty() {
                    placeholder(ui, if gaps { "No secrets found in the files that were checked" } else { "No secrets found" },
                        &format!("{} files were read.", report.files_scanned));
                } else {
                    let mut findings = report.findings.clone();
                    findings.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)).then_with(|| a.category.cmp(&b.category)));
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        let mut current = String::new();
                        for f in &findings {
                            if f.category != current {
                                current = f.category.clone();
                                ui.add_space(8.0);
                                let n = findings.iter().filter(|x| x.category == current).count();
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&current).strong());
                                    ui.label(RichText::new(n.to_string()).weak());
                                });
                                ui.separator();
                            }
                            egui::Frame::new().inner_margin(egui::Margin::symmetric(4, 5)).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    badge(ui, &f.severity);
                                    ui.label(RichText::new(home_abbrev(&f.path)).monospace().small());
                                    if f.line > 0 { ui.label(RichText::new(format!("line {}", f.line)).small().weak()); }
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if let Some(g) = &f.rotation_guide {
                                            if ui.small_button("How to rotate").clicked() {
                                                open_url(g);
                                            }
                                        }
                                        if ui.small_button("Show file").clicked() { reveal_path(Path::new(&f.path)); }
                                    });
                                });
                                if !f.description.is_empty() { ui.label(RichText::new(&f.description).small().weak()); }
                                if !f.preview.is_empty() { ui.label(RichText::new(&f.preview).monospace().small().weak()); }
                            });
                        }
                        ui.add_space(16.0);
                    });
                }
            } else {
                placeholder(ui, "Ready to scan",
                    "Click Deep Scan. Gorse reads your documents, downloads, code and screenshots for API keys, passwords, private keys, seed phrases, card numbers and other sensitive content. Whole home folder covers everything you own.");
            }
        });
    }

    fn subtitle(&self) -> String {
        match &self.report {
            None => "If this laptop were stolen tonight, what could they get into?".to_string(),
            Some(r) => {
                let mut parts = vec![format!(
                    "{} credential{} found",
                    r.summary.credentials,
                    if r.summary.credentials == 1 { "" } else { "s" }
                )];
                let unassessed = r.unassessed_count();
                if unassessed > 0 {
                    parts.push(format!("{unassessed} not assessed"));
                }
                if r.is_incomplete() {
                    parts.push("incomplete check".into());
                }
                if let Some(v) = &r.cli_version {
                    parts.push(format!("Gorse {v}"));
                }
                if r.verified != Some(true) {
                    parts.push("not verified with providers".into());
                }
                parts.join(" · ")
            }
        }
    }

    fn summary_strip(&self, ui: &mut egui::Ui, s: &Summary) {
        let tiles = [
            ("Credentials", s.credentials, Color32::GRAY),
            (
                "Critical",
                s.by_severity.as_ref().map_or(0, |b| b.critical),
                severity_color("critical"),
            ),
            (
                "Paths to production",
                s.critical_indirect_paths.unwrap_or(0),
                severity_color("high"),
            ),
            (
                "Rotate / revoke needed",
                s.persistent_access_risks.unwrap_or(0),
                Color32::from_rgb(142, 68, 173),
            ),
            (
                "Privileged",
                s.privileged_credentials.unwrap_or(0),
                severity_color("low"),
            ),
        ];
        ui.horizontal(|ui| {
            for (label, value, color) in tiles {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_width(130.0);
                    ui.vertical(|ui| {
                        let c = if value > 0 { color } else { Color32::GRAY };
                        ui.label(
                            RichText::new(value.to_string())
                                .size(22.0)
                                .strong()
                                .color(c),
                        );
                        ui.label(RichText::new(label).small().weak());
                    });
                });
            }
        });
    }

    fn findings_list(&mut self, ui: &mut egui::Ui, report: &Report) {
        let mut findings = report.findings.clone();
        findings.sort_by(|a, b| {
            severity_rank(&a.severity)
                .cmp(&severity_rank(&b.severity))
                .then_with(|| {
                    a.kind_label
                        .as_deref()
                        .unwrap_or(&a.name)
                        .cmp(b.kind_label.as_deref().unwrap_or(&b.name))
                })
        });
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let mut current = String::new();
                for (i, f) in findings.iter().enumerate() {
                    let sev = f.severity.to_ascii_lowercase();
                    if sev != current {
                        current = sev.clone();
                        ui.add_space(8.0);
                        let count = findings
                            .iter()
                            .filter(|x| x.severity.eq_ignore_ascii_case(&sev))
                            .count();
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(capitalize(&sev))
                                    .strong()
                                    .color(severity_color(&sev)),
                            );
                            ui.label(RichText::new(count.to_string()).weak());
                        });
                        ui.separator();
                    }
                    self.finding_row(ui, f, i);
                }
                if !report.notes.is_empty() {
                    ui.add_space(12.0);
                    ui.label(RichText::new("Notes").strong());
                    for n in &report.notes {
                        ui.label(RichText::new(n).small().weak());
                    }
                }
                ui.add_space(16.0);
            });
    }

    fn finding_row(&mut self, ui: &mut egui::Ui, f: &Finding, index: usize) {
        let key = format!("{index}:{}:{}", f.name, f.location.as_deref().unwrap_or(""));
        let expanded = self.expanded.contains(&key);
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(4, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    badge(ui, &f.severity);
                    let title = f.kind_label.clone().unwrap_or_else(|| f.name.clone());
                    ui.label(RichText::new(&title).strong());
                    if title != f.name {
                        ui.label(RichText::new(&f.name).weak());
                    }
                    if f.persistence.as_ref().and_then(|p| p.survives_cleanup) == Some(true) {
                        ui.label(
                            RichText::new("rotate / revoke needed")
                                .small()
                                .color(Color32::from_rgb(142, 68, 173)),
                        )
                        .on_hover_text(
                            f.persistence
                                .as_ref()
                                .and_then(|p| p.label.clone())
                                .unwrap_or_else(|| {
                                    "Wiping the laptop does not remove this access. Rotate or revoke the credential at the server or service that issued it.".into()
                                }),
                        );
                    }
                    if f.expired == Some(true) {
                        ui.label(RichText::new("expired").small().weak());
                    }
                    if self.report.as_ref().and_then(|r| r.verified) == Some(true) {
                        let label = confidence_label(f.confidence.as_deref());
                        ui.label(RichText::new(label).small().color(confidence_color(label)))
                            .on_hover_text("Whether the provider confirmed what this credential can do, Gorse inferred it from local files, or it could not be checked.");
                        if let Some(v) = &f.verification {
                            let text = verification_label(&v.status);
                            let color = match v.status.as_str() {
                                "identity_confirmed" | "permission_confirmed" => {
                                    confidence_color("confirmed")
                                }
                                "failed" => severity_color("high"),
                                _ => Color32::GRAY,
                            };
                            ui.label(RichText::new(text).small().color(color))
                                .on_hover_text(&v.detail);
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button(if expanded {
                                "Hide"
                            } else {
                                "Why, and what to do"
                            })
                            .clicked()
                        {
                            if expanded {
                                self.expanded.remove(&key);
                            } else {
                                self.expanded.insert(key.clone());
                            }
                        }
                        if let Some(loc) = &f.location {
                            if !loc.is_empty() && ui.small_button("Show file").clicked() {
                                reveal_path(Path::new(loc));
                            }
                        }
                    });
                });
                if let Some(loc) = &f.location {
                    if !loc.is_empty() {
                        ui.label(RichText::new(home_abbrev(loc)).monospace().small().weak());
                    }
                }
                let mut paths = f.paths.clone();
                paths.sort_by(|a, b| {
                    b.target_production
                        .unwrap_or(false)
                        .cmp(&a.target_production.unwrap_or(false))
                        .then_with(|| a.hops.unwrap_or(0).cmp(&b.hops.unwrap_or(0)))
                });
                let shown = if expanded {
                    paths.len()
                } else {
                    paths.len().min(2)
                };
                for p in paths.iter().take(shown) {
                    let mut text = format!("→ {}", p.target);
                    if let Some(o) = &p.outcome_label {
                        if !o.is_empty() {
                            text.push_str(": ");
                            text.push_str(o);
                        }
                    }
                    if let Some(h) = p.hops {
                        if h > 1 {
                            text.push_str(&format!(" ({h} hops)"));
                        }
                    }
                    if p.target_production == Some(true) {
                        text.push_str(" · production");
                    }
                    let rt = RichText::new(text).small();
                    ui.label(if p.target_production == Some(true) {
                        rt.color(severity_color("critical"))
                    } else {
                        rt.weak()
                    });
                }
                if !expanded && paths.len() > 2 {
                    ui.label(
                        RichText::new(format!("and {} more", paths.len() - 2))
                            .small()
                            .weak(),
                    );
                }
                if expanded {
                    let mut unmarked: Vec<String> = paths
                        .iter()
                        .filter(|p| p.target_production != Some(true))
                        .map(|p| p.target.clone())
                        .collect();
                    unmarked.sort();
                    unmarked.dedup();
                    if !unmarked.is_empty() {
                        ui.label(RichText::new("Is one of these a production system? Gorse scores what it cannot identify as ordinary; tell it and it re-scores.").small().weak());
                        ui.horizontal_wrapped(|ui| {
                            for target in unmarked {
                                let busy = self.mark_rx.is_some() || self.running.is_some();
                                if ui.add_enabled(!busy, egui::Button::new(format!("Mark {target} as production")).small()).clicked() {
                                    let (tx, rx) = channel();
                                    std::thread::spawn(move || {
                                        let _ = tx.send(mark_production(&target));
                                    });
                                    self.mark_rx = Some(rx);
                                }
                            }
                        });
                    }
                    if !f.reasons.is_empty() {
                        detail_block(ui, "Why it matters", &f.reasons);
                    }
                    if !f.remediation.is_empty() {
                        detail_block(ui, "What to do", &f.remediation);
                    }
                    if !f.evidence.is_empty() {
                        detail_block(ui, "Evidence", &f.evidence);
                    }
                    let mut meta = Vec::new();
                    if let Some(c) = &f.confidence {
                        meta.push(format!("confidence {c}"));
                    }
                    if let Some(source) = f.source.as_deref().filter(|s| !s.is_empty()) {
                        meta.push(format!("found by {source}"));
                    }
                    if let Some(l) = &f.lifetime {
                        if !l.is_empty() {
                            meta.push(format!("lifetime {l}"));
                        }
                    }
                    if let Some(i) = &f.identity {
                        if !i.is_empty() {
                            meta.push(i.clone());
                        }
                    }
                    if !meta.is_empty() {
                        ui.label(RichText::new(meta.join("  ·  ")).small().weak());
                    }
                }
            });
    }
}

fn badge(ui: &mut egui::Ui, severity: &str) {
    let color = severity_color(severity);
    egui::Frame::new()
        .fill(color.linear_multiply(0.18))
        .inner_margin(egui::Margin::symmetric(5, 1))
        .corner_radius(3)
        .show(ui, |ui| {
            ui.label(
                RichText::new(severity.to_ascii_uppercase())
                    .monospace()
                    .size(9.0)
                    .strong()
                    .color(color),
            );
        });
}

fn detail_block(ui: &mut egui::Ui, title: &str, lines: &[String]) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.label(RichText::new(title).small().strong());
        for l in lines {
            ui.label(RichText::new(format!("• {l}")).small().weak());
        }
    });
}

const AMBER: Color32 = Color32::from_rgb(201, 162, 39);

/// The heading of an incomplete check: what could not be read or assessed.
fn incomplete_lines(report: &Report) -> (String, Vec<String>) {
    let n = report.coverage_failures.len();
    let title = if report.findings.is_empty() {
        "Incomplete check: nothing was found in what could be read, which is not the same as nothing being there.".to_string()
    } else {
        "Incomplete check: the findings below may be missing something.".to_string()
    };
    let mut lines: Vec<String> = report
        .coverage_failures
        .iter()
        .map(|c| format!("{}: {}", c.location, c.reason))
        .collect();
    let unassessed = report.unassessed_count();
    if unassessed > 0 {
        lines.push(format!(
            "{unassessed} earlier finding{} could not be assessed in this run (listed below).",
            if unassessed == 1 { "" } else { "s" }
        ));
    } else if n == 0 {
        lines.push("Some credential locations could not be read.".into());
    }
    // Sources that did not run, other than an optional engine that simply
    // is not installed or was switched off (those are not gaps by
    // themselves; a lost engine shows up as a coverage failure above).
    for u in &report.sources_unavailable {
        let ordinary = u.reason == "not installed" || u.reason.starts_with("switched off");
        if !ordinary && !lines.iter().any(|l| l.contains(&u.reason)) {
            lines.push(format!("Not assessed: {} ({})", u.source, u.reason));
        }
    }
    if !report.sources_assessed.is_empty() {
        lines.push(format!(
            "{} sources were checked completely.",
            report.sources_assessed.len()
        ));
    }
    (title, lines)
}

/// Amber, never the green all-clear: an incomplete check has gaps.
fn incomplete_banner(ui: &mut egui::Ui, report: &Report) {
    let (title, lines) = incomplete_lines(report);
    egui::Frame::group(ui.style())
        .stroke(egui::Stroke::new(1.0_f32, AMBER))
        .show(ui, |ui| {
            ui.label(RichText::new("Incomplete check").strong().color(AMBER));
            ui.add(egui::Label::new(RichText::new(title).color(AMBER)).wrap());
            for line in lines {
                ui.add(egui::Label::new(RichText::new(format!("• {line}")).small()).wrap());
            }
        });
    ui.add_space(8.0);
}

/// Worst earlier severity first.
fn sorted_unassessed(report: &Report) -> Vec<ChangeEntry> {
    let mut entries = report.changes.unassessed.clone();
    entries.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.title().cmp(b.title()))
    });
    entries
}

/// The heading and one line per entry of "Not assessed in this run (N)".
fn unassessed_lines(report: &Report) -> (String, Vec<String>) {
    let title = format!("Not assessed in this run ({})", report.unassessed_count());
    let lines = sorted_unassessed(report)
        .iter()
        .map(|e| {
            let mut line = format!("{} {}", e.severity.to_ascii_uppercase(), e.title());
            if !e.kind.is_empty() && e.kind != e.title() {
                line.push_str(&format!(" ({})", e.kind));
            }
            if !e.location.is_empty() {
                line.push_str(&format!(" at {}", home_abbrev(&e.location)));
            }
            if !e.reason.is_empty() {
                line.push_str(&format!(": {}", e.reason));
            }
            line
        })
        .collect();
    (title, lines)
}

/// Earlier findings this run could not look at again: shown with the
/// severity they had, as possibly still present, never as resolved.
fn unassessed_section(ui: &mut egui::Ui, report: &Report) {
    let count = report.unassessed_count();
    let (title, _) = unassessed_lines(report);
    let entries = sorted_unassessed(report);
    egui::Frame::group(ui.style())
        .stroke(egui::Stroke::new(1.0_f32, AMBER))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(AMBER));
            ui.add(
                egui::Label::new(RichText::new(if count == 1 {
                    "An earlier check found this credential. This run could not look again, so it may still be present. Not resolved."
                } else {
                    "An earlier check found these credentials. This run could not look again, so they may still be present. Not resolved."
                }))
                .wrap(),
            );
            egui::ScrollArea::vertical()
                .id_salt("unassessed")
                .max_height(160.0)
                .show(ui, |ui| {
                    for e in &entries {
                        ui.horizontal_wrapped(|ui| {
                            let severity = if e.severity.is_empty() { "unknown" } else { &e.severity };
                            badge(ui, severity);
                            ui.label(RichText::new(e.title()).strong());
                            if !e.kind.is_empty() && e.kind != e.title() {
                                ui.label(RichText::new(&e.kind).weak());
                            }
                            if !e.location.is_empty() {
                                ui.label(RichText::new(home_abbrev(&e.location)).monospace().small().weak());
                            }
                        });
                        if !e.reason.is_empty() {
                            ui.label(RichText::new(format!("Not assessed: {}", e.reason)).small().weak());
                        }
                    }
                    let listed = entries.len() as u64;
                    if count > listed {
                        ui.label(
                            RichText::new(format!(
                                "{} more not listed here; see the saved report.",
                                count - listed
                            ))
                            .small()
                            .weak(),
                        );
                    }
                });
        });
    ui.add_space(8.0);
}

fn placeholder(ui: &mut egui::Ui, title: &str, detail: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.heading(title);
        if !detail.is_empty() {
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(detail).weak()).wrap());
        }
    });
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(confidence: Option<&str>) -> Finding {
        Finding {
            name: "x".into(),
            kind_label: None,
            location: None,
            identity: None,
            severity: "low".into(),
            confidence: confidence.map(|c| c.to_string()),
            lifetime: None,
            expired: None,
            persistence: None,
            paths: vec![],
            reasons: vec![],
            remediation: vec![],
            evidence: vec![],
            source: None,
            verification: None,
        }
    }

    #[test]
    fn verify_summary_comes_from_verification_counts() {
        let report: Report = serde_json::from_value(serde_json::json!({
            "summary": {"credentials": 3, "verification_counts": {
                "confirmed": 2, "failed": 1, "unsupported": 4, "not_attempted": 0}},
            "findings": [{
                "name": "default", "severity": "high", "confidence": "inferred",
                "source": "aws-credentials-file",
                "verification": {"status": "failed", "detail": "aws sts get-caller-identity timed out after 20s"}
            }],
            "incomplete": false, "coverage_failures": [],
            "sources_assessed": ["aws-credentials-file"],
            "sources_unavailable": [{"source": "trufflehog", "reason": "not installed"}],
        }))
        .unwrap();
        let counts = VerificationCounts::of(&report);
        assert_eq!(counts.summary(), "2 answered, 1 failed, 4 unsupported");
        assert_eq!(
            report.findings[0].source.as_deref(),
            Some("aws-credentials-file")
        );
        assert_eq!(
            report.findings[0].verification.as_ref().unwrap().status,
            "failed"
        );
        assert_eq!(report.sources_unavailable[0].source, "trufflehog");

        // Without the summary counts, counted from the findings.
        let mut older = report.clone();
        older.summary.verification_counts = None;
        assert_eq!(VerificationCounts::of(&older).failed, 1);
    }

    #[test]
    fn verification_levels_are_shown_in_plain_words() {
        let report: Report = serde_json::from_value(serde_json::json!({
            "summary": {"credentials": 4, "verification_counts": {
                "identity_confirmed": 2, "permission_confirmed": 1, "local_config": 1,
                "failed": 0, "unsupported": 0, "not_attempted": 0}},
            "findings": [{
                "name": "alice@example.com", "severity": "low", "confidence": "inferred",
                "verification": {"status": "local_config", "detail": "gcloud auth list: Google was not asked"}
            }],
        }))
        .unwrap();
        assert_eq!(
            VerificationCounts::of(&report).summary(),
            "2 identity confirmed, 1 permission confirmed, 1 local configuration only, 0 failed, 0 unsupported"
        );
        let status = &report.findings[0].verification.as_ref().unwrap().status;
        assert_eq!(
            verification_label(status),
            "local configuration only, provider not asked"
        );
        assert_eq!(verification_label("confirmed"), "provider check ran");
        assert_eq!(
            verification_label("identity_confirmed"),
            "identity confirmed by provider"
        );
        assert_eq!(
            verification_label("permission_confirmed"),
            "permission confirmed by provider"
        );
        assert_eq!(verification_label("failed"), "check failed");
        assert_eq!(verification_label("unsupported"), "not supported yet");
    }

    #[test]
    fn incomplete_report_is_never_the_empty_state() {
        let report: Report = serde_json::from_value(serde_json::json!({
            "summary": {"credentials": 0},
            "findings": [],
            "incomplete": true,
            "coverage_failures": [{"location": "~/.config/doctl/config.yaml",
                "reason": "could not interpret ~/.config/doctl/config.yaml (unsupported format)"}],
        }))
        .unwrap();
        assert!(report.incomplete);
        let (title, lines) = incomplete_lines(&report);
        assert!(title.starts_with("Incomplete check"), "{title}");
        assert!(
            title.contains("not the same as nothing being there"),
            "{title}"
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("unsupported format"));
        // An older report without the fields reads as complete.
        let old: Report = serde_json::from_value(serde_json::json!({
            "summary": {"credentials": 0}, "findings": []
        }))
        .unwrap();
        assert!(!old.incomplete && old.coverage_failures.is_empty());
    }

    #[test]
    fn unassessed_findings_are_shown_never_resolved() {
        let report: Report = serde_json::from_value(serde_json::json!({
            "summary": {"credentials": 1},
            "findings": [],
            "incomplete": true,
            "changes": {
                "counts": {"unassessed": 3, "new": 0},
                "engine_coverage_lost": true,
                "unassessed": [
                    {"kind": "github_token", "name": "GitHub token", "location": "/x/.env",
                     "severity": "high", "reason": "TruffleHog is not installed"},
                    {"kind": "aws_access_key", "name": "AWS key", "location": "/x/creds",
                     "severity": "critical", "reason": "could not interpret /x/creds"},
                    "not an entry"
                ]
            }
        }))
        .unwrap();
        assert!(report.is_incomplete());
        assert_eq!(
            report.unassessed_count(),
            3,
            "the CLI's count wins over the capped list"
        );
        let (title, lines) = unassessed_lines(&report);
        assert_eq!(title, "Not assessed in this run (3)");
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].starts_with("CRITICAL AWS key (aws_access_key) at /x/creds"),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].ends_with(": could not interpret /x/creds"),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("TruffleHog is not installed"),
            "{}",
            lines[1]
        );
        let (_, banner) = incomplete_lines(&report);
        assert!(
            banner
                .iter()
                .any(|l| l.contains("3 earlier findings could not be assessed")),
            "{banner:?}"
        );

        // Unassessed alone makes a report incomplete, even without the flag.
        let report: Report = serde_json::from_value(serde_json::json!({
            "summary": {"credentials": 0}, "findings": [],
            "changes": {"unassessed": [{"name": "k", "severity": "low"}]}
        }))
        .unwrap();
        assert!(report.is_incomplete());
        assert_eq!(report.unassessed_count(), 1);

        // A malformed `changes` never makes the report unreadable.
        for changes in [
            serde_json::json!("x"),
            serde_json::json!({"unassessed": 5, "counts": []}),
        ] {
            let report: Report = serde_json::from_value(serde_json::json!({
                "summary": {"credentials": 0}, "findings": [], "changes": changes
            }))
            .unwrap();
            assert_eq!(report.unassessed_count(), 0);
            assert!(!report.is_incomplete());
        }
    }

    #[test]
    fn only_a_verified_newer_release_offers_a_download() {
        let notice = |v: serde_json::Value| update_notice_of(&v);
        assert_eq!(
            notice(
                serde_json::json!({"latest": "9.9.9", "newer_available": true, "signature": "verified"})
            ),
            Some(UpdateNotice::Verified("9.9.9".into()))
        );
        // newer_available without a verified signature is never a download.
        assert_eq!(
            notice(
                serde_json::json!({"latest": "9.9.9", "newer_available": true, "signature": "invalid"})
            ),
            Some(UpdateNotice::Unverified("9.9.9".into()))
        );
        assert_eq!(
            notice(serde_json::json!({"latest": "9.9.9", "newer_available": true})),
            Some(UpdateNotice::Unverified("9.9.9".into()))
        );
        for signature in ["missing", "invalid", "unbound", "unreachable", "mismatch"] {
            assert_eq!(
                notice(
                    serde_json::json!({"latest": "9.9.9", "newer_available": false, "signature": signature})
                ),
                Some(UpdateNotice::Unverified("9.9.9".into())),
                "{signature}"
            );
        }
        assert_eq!(
            notice(
                serde_json::json!({"latest": "0.4.5", "newer_available": false, "signature": null})
            ),
            None
        );
        assert_eq!(
            notice(
                serde_json::json!({"latest": "0.4.5", "newer_available": false, "signature": "verified"})
            ),
            None
        );
    }

    #[test]
    fn confidence_labels() {
        let _ = finding(Some("confirmed"));
        assert_eq!(confidence_label(Some("Confirmed")), "confirmed");
        assert_eq!(confidence_label(Some("unknown")), "could not be checked");
        assert_eq!(confidence_label(None), "could not be checked");
        assert!(VERIFY_EXPLANATION.contains("nothing is sent to Gorse"));
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(concat!("Gorse ", env!("CARGO_PKG_VERSION")))
            .with_inner_size([940.0, 640.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native("Gorse", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}
