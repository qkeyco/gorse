// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Deep Scan: the files on this computer read for secrets by
//! `gorse-cli scan --deep --json --progress`, as the Mac app shows it.
//! The default places are always scanned first; folders added here are
//! extras, scanned after them one at a time (unless the default places
//! already read them), each with its own resume file, and the reports are
//! merged. Live progress and findings come from
//! the CLI's stderr, one JSON object per line. A stop creates the stop file,
//! so the CLI finishes cleanly and prints what it found (marked
//! `interrupted`); nothing is ever thrown away for time. The window never
//! reads the `preview` field of a finding, so it can never show it.

use crate::text::{
    abbrev_with, capitalise_first, count, file_size, home_abbrev, home_dir, now_unix,
    relative_time, thousands,
};
use crate::{
    app_dir, badge, cli_path, open_url, placeholder, reveal_path, safe_url, severity_color,
    severity_rank, App, AMBER, PRICING_URL,
};
use eframe::egui::{self, Color32, RichText};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- report ----

#[derive(Deserialize, Clone, Default, Debug)]
pub struct ScanReport {
    #[serde(default)]
    pub engines: Vec<ScanEngine>,
    #[serde(default)]
    pub findings: Vec<ScanFinding>,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub files_scanned: u64,
    #[serde(default)]
    pub elapsed_secs: u64,
    #[serde(default)]
    pub interrupted: bool,
    /// What the scan did not look at. Absent from an older CLI's report,
    /// which is then treated as unconfirmed, never as complete.
    pub coverage: Option<ScanCoverage>,
}

#[derive(Deserialize, Clone, Default, Debug, PartialEq)]
pub struct ScanEngine {
    #[serde(default)]
    pub name: String,
    pub version: Option<String>,
    pub findings: Option<u64>,
    pub error: Option<String>,
}

#[derive(Deserialize, Clone, Default, Debug, PartialEq)]
pub struct NamedCount {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub count: u64,
}

#[derive(Deserialize, Clone, Default, Debug, PartialEq)]
pub struct UnreadableEntry {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub reason: String,
}

/// Mirrors `ScanCoverage` in the CLI's content scanner.
#[derive(Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(default)]
pub struct ScanCoverage {
    pub complete: bool,
    /// Newer CLIs: something the person would expect to be checked was
    /// not. Absent in older reports, which fall back to `!complete`.
    pub has_gaps: Option<bool>,
    pub interrupted: bool,
    pub files_scanned: u64,
    pub files_skipped_by_type: u64,
    pub skipped_types: Vec<NamedCount>,
    pub dirs_skipped_by_rule: u64,
    pub skipped_dirs: Vec<NamedCount>,
    pub files_unreadable: u64,
    pub permission_denied: u64,
    pub other_read_errors: u64,
    pub unreadable_examples: Vec<UnreadableEntry>,
    pub files_over_size_limit: u64,
    pub size_limit_bytes: u64,
    pub oversize_examples: Vec<String>,
    pub dirs_beyond_depth_limit: u64,
    pub files_skipped_other: u64,
    pub limit_reached: Option<String>,
    pub images_seen: u64,
    pub images_content_not_checked: u64,
    pub image_ocr_cap_reached: bool,
}

impl ScanCoverage {
    fn gaps(&self) -> bool {
        self.has_gaps.unwrap_or(!self.complete)
    }

    /// Two coverage reports summed; a gap in either is a gap in the merge.
    pub fn merging(&self, o: &ScanCoverage) -> ScanCoverage {
        fn sum(a: &[NamedCount], b: &[NamedCount]) -> Vec<NamedCount> {
            let mut counts: BTreeMap<String, u64> = BTreeMap::new();
            for n in a.iter().chain(b) {
                *counts.entry(n.name.clone()).or_default() += n.count;
            }
            let mut list: Vec<NamedCount> = counts
                .into_iter()
                .map(|(name, count)| NamedCount { name, count })
                .collect();
            list.sort_by(|x, y| y.count.cmp(&x.count).then_with(|| x.name.cmp(&y.name)));
            list
        }
        let first6 = |a: &[String], b: &[String]| -> Vec<String> {
            a.iter().chain(b).take(6).cloned().collect()
        };
        ScanCoverage {
            complete: self.complete && o.complete,
            has_gaps: Some(self.gaps() || o.gaps()),
            interrupted: self.interrupted || o.interrupted,
            files_scanned: self.files_scanned + o.files_scanned,
            files_skipped_by_type: self.files_skipped_by_type + o.files_skipped_by_type,
            skipped_types: sum(&self.skipped_types, &o.skipped_types),
            dirs_skipped_by_rule: self.dirs_skipped_by_rule + o.dirs_skipped_by_rule,
            skipped_dirs: sum(&self.skipped_dirs, &o.skipped_dirs),
            files_unreadable: self.files_unreadable + o.files_unreadable,
            permission_denied: self.permission_denied + o.permission_denied,
            other_read_errors: self.other_read_errors + o.other_read_errors,
            unreadable_examples: self
                .unreadable_examples
                .iter()
                .chain(&o.unreadable_examples)
                .take(6)
                .cloned()
                .collect(),
            files_over_size_limit: self.files_over_size_limit + o.files_over_size_limit,
            size_limit_bytes: self.size_limit_bytes.max(o.size_limit_bytes),
            oversize_examples: first6(&self.oversize_examples, &o.oversize_examples),
            dirs_beyond_depth_limit: self.dirs_beyond_depth_limit + o.dirs_beyond_depth_limit,
            files_skipped_other: self.files_skipped_other + o.files_skipped_other,
            limit_reached: self
                .limit_reached
                .clone()
                .or_else(|| o.limit_reached.clone()),
            images_seen: self.images_seen + o.images_seen,
            images_content_not_checked: self.images_content_not_checked
                + o.images_content_not_checked,
            image_ocr_cap_reached: self.image_ocr_cap_reached || o.image_ocr_cap_reached,
        }
    }
}

/// One finding. `preview` is deliberately not read: the window never shows
/// any part of a secret.
#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ScanFinding {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub line: u64,
    #[serde(default)]
    pub description: String,
    /// How sure the scanner is that this is a real secret, 0-100. An
    /// estimate; absent from older reports.
    #[serde(default, deserialize_with = "lenient_percent")]
    pub likelihood: Option<u8>,
    /// "credential" or "sensitive"; absent from older reports (credential).
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub rotation_guide: Option<String>,
    #[serde(default)]
    pub engine: Option<String>,
}

fn lenient_percent<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u8>, D::Error> {
    let v = serde_json::Value::deserialize(d)?;
    Ok(v.as_f64()
        .filter(|n| n.is_finite())
        .map(|n| n.round().clamp(0.0, 100.0) as u8))
}

impl ScanFinding {
    /// "AWS Access Key" from "AWS Access Key — grants access to AWS".
    pub fn kind(&self) -> String {
        let first = self.description.split(" — ").next().unwrap_or("").trim();
        if first.is_empty() {
            self.category.clone()
        } else {
            first.to_string()
        }
    }

    /// Why it matters: the part after the dash, capitalised, if any.
    pub fn reason(&self) -> Option<String> {
        let mut parts = self.description.split(" — ");
        parts.next();
        let rest = parts.collect::<Vec<_>>().join(" — ");
        let rest = rest.trim();
        (!rest.is_empty()).then(|| capitalise_first(rest))
    }

    pub fn is_sensitive(&self) -> bool {
        self.group.as_deref() == Some("sensitive")
    }

    /// "~/Documents/keys.txt · line 12".
    pub fn location_with(&self, home: &str) -> String {
        let mut text = abbrev_with(home, &self.path);
        if self.line > 0 {
            text.push_str(&format!(" · line {}", self.line));
        }
        text
    }
}

pub const SURE_HELP: &str = "How sure Gorse is that this is a real secret, from how exact the match is and where it sits (a comment or a test file counts against it). An estimate.";

/// Every folder's report merged into one.
pub fn merge_reports<'a>(parts: impl IntoIterator<Item = &'a ScanReport>) -> Option<ScanReport> {
    let mut merged: Option<ScanReport> = None;
    for r in parts {
        let m = merged.get_or_insert_with(|| ScanReport {
            coverage: None,
            ..Default::default()
        });
        m.findings.extend(r.findings.iter().cloned());
        m.total += r.total;
        m.files_scanned += r.files_scanned;
        m.elapsed_secs += r.elapsed_secs;
        m.interrupted |= r.interrupted;
        for e in &r.engines {
            if !m.engines.contains(e) {
                m.engines.push(e.clone());
            }
        }
        if let Some(c) = &r.coverage {
            m.coverage = Some(match &m.coverage {
                Some(prev) => prev.merging(c),
                None => c.clone(),
            });
        }
    }
    merged
}

/// What the results say about how much was checked.
#[derive(Debug, Clone, PartialEq)]
pub enum CoverageState {
    /// Every file was read and checked: the only state that may show green.
    AllClear(u64),
    /// Some files or folders were not checked, for the listed reasons.
    Gaps {
        headline: String,
        reasons: Vec<String>,
    },
}

fn files_were(n: u64) -> String {
    if n == 1 {
        "1 file was".into()
    } else {
        format!("{} files were", thousands(n))
    }
}

fn items(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{} {plural}", thousands(n))
    }
}

pub fn coverage_state(report: &ScanReport) -> CoverageState {
    let Some(c) = &report.coverage else {
        return CoverageState::Gaps {
            headline: format!(
                "{} checked. The scanner did not say what it skipped.",
                files_were(report.files_scanned)
            ),
            reasons: vec!["This report came from an older version of Gorse that does not describe what it covered. Download Gorse again to get a full report.".into()],
        };
    };
    if !c.gaps() && !c.interrupted && !report.interrupted {
        return CoverageState::AllClear(c.files_scanned);
    }
    CoverageState::Gaps {
        headline: gaps_headline(c),
        reasons: gaps_reasons(c, report.interrupted),
    }
}

/// Files never read by design (PDFs, archives, pictures), under a green result.
pub fn coverage_notes(report: &ScanReport) -> Vec<String> {
    let Some(c) = &report.coverage else {
        return vec![];
    };
    let mut notes = vec![];
    if c.files_skipped_by_type > 0 {
        notes.push(format!(
            "{} of a type this scanner cannot read, such as PDFs or archives, {} checked by name only.",
            items(c.files_skipped_by_type, "file", "files"),
            if c.files_skipped_by_type == 1 { "was" } else { "were" }
        ));
    }
    if c.images_content_not_checked > 0 {
        notes.push(format!(
            "{} checked by file name only. The text inside them was not read.",
            items(c.images_content_not_checked, "picture was", "pictures were")
        ));
    }
    notes
}

fn gaps_headline(c: &ScanCoverage) -> String {
    let not_checked = c.files_skipped_by_type
        + c.files_unreadable
        + c.files_over_size_limit
        + c.files_skipped_other
        + c.images_content_not_checked;
    if not_checked > 0 {
        return format!(
            "{} checked. {} not checked.",
            files_were(c.files_scanned),
            files_were(not_checked)
        );
    }
    if c.dirs_skipped_by_rule > 0 || c.dirs_beyond_depth_limit > 0 {
        return format!(
            "{} checked, but some folders were skipped.",
            files_were(c.files_scanned)
        );
    }
    format!(
        "{} checked, but the scan did not finish.",
        files_were(c.files_scanned)
    )
}

fn gaps_reasons(c: &ScanCoverage, interrupted: bool) -> Vec<String> {
    let names = |list: &[NamedCount]| -> String {
        if list.is_empty() {
            return String::new();
        }
        let shown: Vec<String> = list
            .iter()
            .map(|n| {
                if n.count > 1 {
                    format!("{} ×{}", n.name, n.count)
                } else {
                    n.name.clone()
                }
            })
            .collect();
        format!(" ({})", shown.join(", "))
    };
    let file_names = |paths: Vec<&str>| -> String {
        let shown: Vec<String> = paths
            .iter()
            .take(3)
            .map(|p| {
                Path::new(p)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| p.to_string())
            })
            .collect();
        if shown.is_empty() {
            String::new()
        } else {
            format!(": {}", shown.join(", "))
        }
    };
    let was_were = |n: u64| if n == 1 { "was" } else { "were" };
    let mut reasons = vec![];
    if c.permission_denied > 0 {
        let examples = c
            .unreadable_examples
            .iter()
            .filter(|e| e.reason == "permission denied")
            .map(|e| e.path.as_str())
            .collect();
        reasons.push(format!(
            "{} could not be read because access was denied{}.",
            items(c.permission_denied, "file", "files"),
            file_names(examples)
        ));
    }
    if c.other_read_errors > 0 {
        let examples = c
            .unreadable_examples
            .iter()
            .filter(|e| e.reason != "permission denied")
            .map(|e| e.path.as_str())
            .collect();
        reasons.push(format!(
            "{} could not be read{}.",
            items(c.other_read_errors, "file or folder", "files or folders"),
            file_names(examples)
        ));
    }
    if c.files_over_size_limit > 0 {
        let mb = (c.size_limit_bytes / 1_048_576).max(1);
        reasons.push(format!(
            "{} larger than the {mb} MB limit and {} not read{}.",
            items(c.files_over_size_limit, "file is", "files are"),
            was_were(c.files_over_size_limit),
            file_names(c.oversize_examples.iter().map(String::as_str).collect())
        ));
    }
    if c.files_skipped_by_type > 0 {
        reasons.push(format!(
            "{} of a type this scanner cannot read, such as PDFs, archives or app data{}.",
            items(c.files_skipped_by_type, "file is", "files are"),
            names(&c.skipped_types)
        ));
    }
    if c.images_content_not_checked > 0 {
        reasons.push(format!(
            "{} checked by file name only. The text inside them was not read.",
            items(c.images_content_not_checked, "image was", "images were")
        ));
    }
    if c.image_ocr_cap_reached {
        reasons.push("The limit on how many pictures can be read in one scan was reached.".into());
    }
    if c.dirs_skipped_by_rule > 0 {
        reasons.push(format!(
            "{} skipped because {} app or developer files{}. Files inside are not counted.",
            items(c.dirs_skipped_by_rule, "folder was", "folders were"),
            if c.dirs_skipped_by_rule == 1 {
                "it holds"
            } else {
                "they hold"
            },
            names(&c.skipped_dirs)
        ));
    }
    if c.dirs_beyond_depth_limit > 0 {
        reasons.push(format!(
            "{} nested too deeply and {} not opened.",
            items(c.dirs_beyond_depth_limit, "folder is", "folders are"),
            was_were(c.dirs_beyond_depth_limit)
        ));
    }
    if c.files_skipped_other > 0 {
        reasons.push(format!(
            "{} skipped because {} not an ordinary file.",
            items(c.files_skipped_other, "item was", "items were"),
            if c.files_skipped_other == 1 {
                "it is"
            } else {
                "they are"
            }
        ));
    }
    if let Some(limit) = &c.limit_reached {
        reasons.push(format!("The scan stopped early: {limit}."));
    }
    if c.interrupted || interrupted {
        reasons.push("The scan stopped before it finished.".into());
    }
    if reasons.is_empty() {
        reasons.push(
            "The scanner reported that it did not check everything, without saying why.".into(),
        );
    }
    reasons
}

/// "38 credentials · 12 sensitive items".
pub fn split_counts(findings: &[ScanFinding]) -> (usize, usize, String) {
    let sensitive = findings.iter().filter(|f| f.is_sensitive()).count();
    let credentials = findings.len() - sensitive;
    let text = format!(
        "{} · {}",
        count(credentials as u64, "credential", "credentials"),
        count(sensitive as u64, "sensitive item", "sensitive items")
    );
    (credentials, sensitive, text)
}

/// Findings of one section grouped by category, the biggest group first,
/// each group worst severity first and then most likely first.
pub fn grouped(findings: &[ScanFinding], sensitive: bool) -> Vec<(String, Vec<ScanFinding>)> {
    let mut groups: BTreeMap<String, Vec<ScanFinding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.is_sensitive() == sensitive) {
        groups
            .entry(f.category.clone())
            .or_default()
            .push(f.clone());
    }
    let mut list: Vec<(String, Vec<ScanFinding>)> = groups.into_iter().collect();
    for (_, items) in list.iter_mut() {
        items.sort_by(|a, b| {
            severity_rank(&a.severity)
                .cmp(&severity_rank(&b.severity))
                .then_with(|| b.likelihood.cmp(&a.likelihood))
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.line.cmp(&b.line))
        });
    }
    list.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    list
}

// ---------------------------------------------------------------- places ----

/// A place a default Deep Scan reads, as `gorse-cli scan --list-places` names it.
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct ScanPlace {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub detail: String,
}

impl ScanPlace {
    pub fn icon(&self) -> &'static str {
        match self.kind.as_str() {
            "settings" => "⚙",
            "code" => "</>",
            "pictures" => "🖼",
            "notes" => "📝",
            _ => "🗀",
        }
    }
}

/// `{"places":[...]}`, in the order given; nothing for anything else.
pub fn parse_places(bytes: &[u8]) -> Vec<ScanPlace> {
    #[derive(Deserialize)]
    struct List {
        #[serde(default)]
        places: Vec<ScanPlace>,
    }
    serde_json::from_slice::<List>(bytes)
        .map(|l| l.places)
        .unwrap_or_default()
}

// -------------------------------------------------------------- progress ----

/// One line of `--progress` output.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanEvent {
    Start {
        roots: Vec<String>,
    },
    Estimate {
        files: u64,
        bytes: u64,
    },
    Phase(String),
    Images {
        done: u64,
        total: u64,
    },
    Progress {
        files: u64,
        findings: u64,
        dir: Option<String>,
        done: bool,
    },
    Finding {
        files: u64,
        findings: u64,
        finding: Box<ScanFinding>,
    },
    Resumed {
        files: u64,
        findings: u64,
    },
}

pub fn parse_event(line: &str) -> Option<ScanEvent> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let n = |key: &str| v.get(key).and_then(|x| x.as_u64()).unwrap_or(0);
    Some(match v.get("event")?.as_str()? {
        "start" => ScanEvent::Start {
            roots: v
                .get("roots")
                .and_then(|r| r.as_array())
                .map(|r| {
                    r.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        },
        "estimate" => ScanEvent::Estimate {
            files: n("files_total"),
            bytes: n("bytes_total"),
        },
        "phase" => ScanEvent::Phase(v.get("name")?.as_str()?.to_string()),
        "images" => ScanEvent::Images {
            done: n("done"),
            total: n("total"),
        },
        "progress" => ScanEvent::Progress {
            files: n("files_scanned"),
            findings: n("findings"),
            dir: v.get("dir").and_then(|d| d.as_str()).map(str::to_string),
            done: v.get("done").and_then(|d| d.as_bool()).unwrap_or(false),
        },
        "finding" => ScanEvent::Finding {
            files: n("files_scanned"),
            findings: n("findings"),
            finding: Box::new(serde_json::from_value(v.get("finding")?.clone()).ok()?),
        },
        "resumed" => ScanEvent::Resumed {
            files: n("files_scanned"),
            findings: n("findings"),
        },
        _ => return None,
    })
}

/// What the running scan has said so far. Times are seconds since the scan
/// started, so the arithmetic can be tested without a clock.
#[derive(Default, Debug, Clone)]
pub struct LiveScan {
    pub files: u64,
    pub findings: u64,
    pub dir: Option<String>,
    pub phase: Option<String>,
    pub estimate: Option<(u64, u64)>,
    pub images: Option<(u64, u64)>,
    /// When reading files began, and how many had been read then.
    files_started: Option<(f64, u64)>,
    /// Findings so far, newest first.
    pub found: Vec<ScanFinding>,
    pub heard: bool,
}

impl LiveScan {
    pub fn apply(&mut self, event: ScanEvent, now: f64) {
        self.heard = true;
        match event {
            ScanEvent::Start { .. } => {
                // A new folder: its own counts and estimate; findings carry on.
                self.files = 0;
                self.findings = 0;
                self.dir = None;
                self.phase = None;
                self.estimate = None;
                self.images = None;
                self.files_started = None;
            }
            ScanEvent::Estimate { files, bytes } => self.estimate = Some((files, bytes)),
            ScanEvent::Phase(name) => self.phase = Some(name),
            ScanEvent::Images { done, total } => {
                self.images = Some((done, total));
                self.phase = Some("images".into());
            }
            ScanEvent::Progress {
                files,
                findings,
                dir,
                ..
            } => {
                self.files = files;
                self.findings = findings;
                if dir.is_some() {
                    self.dir = dir;
                }
                self.phase = None;
                if self.files_started.is_none() {
                    self.files_started = Some((now, files));
                }
            }
            ScanEvent::Finding {
                files,
                findings,
                finding,
            } => {
                self.found.insert(0, *finding);
                self.files = self.files.max(files);
                self.findings = self.findings.max(findings);
            }
            ScanEvent::Resumed { files, findings } => {
                self.files = files;
                self.findings = findings;
                self.files_started = None;
            }
        }
    }

    pub fn found_count(&self) -> u64 {
        self.findings.max(self.found.len() as u64)
    }

    /// Share done once the total is known; never 100% until it really ends.
    pub fn fraction(&self) -> Option<f32> {
        if self.phase.as_deref() == Some("images") {
            if let Some((done, total)) = self.images.filter(|i| i.1 > 0) {
                return Some((done as f32 / total as f32).min(0.99));
            }
        }
        let (total, _) = self.estimate.filter(|e| e.0 > 0)?;
        Some((self.files as f32 / total as f32).min(0.99))
    }

    /// "about 25 min left", from the reading speed so far, once there are
    /// more than ten seconds of it.
    pub fn time_left(&self, now: f64) -> Option<String> {
        let (total, _) = self.estimate?;
        let (t0, f0) = self.files_started?;
        if self.phase.is_some() || self.files <= f0 {
            return None;
        }
        let elapsed = now - t0;
        if elapsed <= 10.0 {
            return None;
        }
        let rate = (self.files - f0) as f64 / elapsed;
        let remaining = total.saturating_sub(self.files) as f64 / rate.max(0.1);
        Some(format!(
            "about {} left",
            crate::text::duration_left(remaining)
        ))
    }

    /// "12,153 of 674,926 files (91.6 GB) · 40 findings · about 1 h 50 min left".
    pub fn progress_line(&self, now: f64) -> String {
        let findings = count(self.found_count(), "finding", "findings");
        if self.phase.as_deref() == Some("images") {
            if let Some((done, total)) = self.images {
                return format!(
                    "Text in pictures: {} of {} · {findings}",
                    thousands(done),
                    thousands(total)
                );
            }
        }
        match self.estimate {
            None => format!(
                "{} · {findings} · counting…",
                count(self.files, "file read", "files read")
            ),
            Some((total, bytes)) => {
                let left = self
                    .time_left(now)
                    .map(|t| format!(" · {t}"))
                    .unwrap_or_default();
                format!(
                    "{} of {} files ({}) · {findings}{left}",
                    thousands(self.files),
                    thousands(total),
                    file_size(bytes)
                )
            }
        }
    }

    pub fn phase_text(&self) -> Option<&'static str> {
        Some(match self.phase.as_deref()? {
            "images" => "Reading the text inside pictures…",
            "notes" => "Reading notes…",
            "trufflehog" => "Running TruffleHog's detectors…",
            _ => "Finishing…",
        })
    }

    /// Share of the disk's used space this scan reads, 1-100.
    pub fn disk_coverage(&self, used: Option<u64>) -> Option<u32> {
        let (_, bytes) = self.estimate?;
        let used = used.filter(|u| *u > 0)? as f64;
        Some(((bytes as f64 / used * 100.0).round() as u32).clamp(1, 100))
    }
}

// --------------------------------------------------------------- folders ----

fn same_part(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    if cfg!(windows) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

fn parts(p: &Path) -> Vec<&std::ffi::OsStr> {
    p.components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .map(|c| c.as_os_str())
        .collect()
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    let (a, b) = (parts(a), parts(b));
    a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| same_part(x, y))
}

/// True when `inner` is strictly inside `outer`.
pub fn is_inside(inner: &Path, outer: &Path) -> bool {
    let (i, o) = (parts(inner), parts(outer));
    i.len() > o.len() && o.iter().zip(&i).all(|(x, y)| same_part(x, y))
}

/// Adds an extra folder. A folder already added, or inside one, is not
/// added (it would be read twice); choosing a parent replaces the folders
/// inside it. Returns the folders it replaced, or None when not added.
pub fn add_folder(folders: &mut Vec<PathBuf>, new: PathBuf) -> Option<Vec<PathBuf>> {
    if folders
        .iter()
        .any(|f| same_path(f, &new) || is_inside(&new, f))
    {
        return None;
    }
    let (inner, keep): (Vec<PathBuf>, Vec<PathBuf>) =
        folders.drain(..).partition(|f| is_inside(f, &new));
    *folders = keep;
    folders.push(new);
    Some(inner)
}

/// Drops folders inside another chosen folder (an older list may have both).
pub fn tidy_folders(list: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for f in list {
        if !out.iter().any(|o| same_path(o, &f)) {
            out.push(f);
        }
    }
    let all = out.clone();
    out.retain(|f| !all.iter().any(|o| is_inside(f, o)));
    out
}

pub fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

pub const DEFAULTS_KEY: &str = "__default_places__";

pub fn key_of(target: &Option<PathBuf>) -> String {
    match target {
        Some(p) => p.display().to_string(),
        None => DEFAULTS_KEY.to_string(),
    }
}

/// The folders a default Deep Scan reads: each default place's folder (the
/// hidden settings folders one by one, never the whole home they sit in),
/// or the home folder itself when whole-home is on.
pub fn default_roots(places: &[ScanPlace], home: Option<&Path>, whole_home: bool) -> Vec<PathBuf> {
    if whole_home {
        if let Some(h) = home {
            return vec![h.to_path_buf()];
        }
    }
    let mut roots = Vec::new();
    for place in places {
        let Some(path) = place.path.as_deref().filter(|p| !p.is_empty()) else {
            continue;
        };
        if place.kind == "settings" {
            for name in place
                .detail
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
            {
                roots.push(Path::new(path).join(name));
            }
        } else {
            roots.push(PathBuf::from(path));
        }
    }
    roots
}

/// True when the default places already read `folder`: it is one of
/// `roots` or inside one (case-insensitively on Windows).
pub fn is_covered(folder: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|r| same_path(folder, r) || is_inside(folder, r))
}

/// What the scan button does next.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub label: String,
    /// Start over: forget earlier results and resume files first.
    pub rescan_all: bool,
    /// `None` is the default places (or the whole home folder), always
    /// first; then each added folder the defaults do not already read.
    pub targets: Vec<Option<PathBuf>>,
    /// Offer a separate "Rescan All" as well.
    pub offer_rescan_all: bool,
}

/// The default places are always scanned; `extras` are the added folders
/// not already read by them.
pub fn plan_scan(
    extras: &[PathBuf],
    has_report: impl Fn(&str) -> bool,
    has_resume: impl Fn(&str) -> bool,
    whole_home: bool,
) -> Plan {
    let key = |f: &PathBuf| f.display().to_string();
    // A whole-home scan is never resumed: the Pro check runs each time.
    let defaults_resumable = !whole_home && has_resume(DEFAULTS_KEY);
    let resumable = defaults_resumable || extras.iter().any(|f| has_resume(&key(f)));
    let all: Vec<Option<PathBuf>> = std::iter::once(None)
        .chain(extras.iter().cloned().map(Some))
        .collect();
    if resumable {
        // Carry on the stopped targets and any not yet scanned, never a
        // finished one.
        let mut targets = Vec::new();
        if defaults_resumable || !has_report(DEFAULTS_KEY) {
            targets.push(None);
        }
        targets.extend(
            extras
                .iter()
                .filter(|f| has_resume(&key(f)) || !has_report(&key(f)))
                .cloned()
                .map(Some),
        );
        return Plan {
            label: "Resume Scan".into(),
            rescan_all: false,
            targets,
            offer_rescan_all: true,
        };
    }
    let label = if whole_home {
        "Deep Scan, Whole Home"
    } else if has_report(DEFAULTS_KEY) || extras.iter().any(|f| has_report(&key(f))) {
        "Rescan"
    } else {
        "Deep Scan"
    };
    Plan {
        label: label.into(),
        rescan_all: true,
        targets: all,
        offer_rescan_all: false,
    }
}

/// A short stable name for a target's resume file (FNV-1a, twice).
pub fn hashed_name(key: &str) -> String {
    let fnv = |seed: u64| {
        let mut h = seed;
        for b in key.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    };
    format!(
        "{:016x}{:08x}",
        fnv(0xcbf2_9ce4_8422_2325),
        fnv(0x84222325_cbf29ce4) as u32
    )
}

fn private_dir(dir: &Path) -> PathBuf {
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    dir.to_path_buf()
}

/// Where a stopped scan of `key` keeps its place.
pub fn resume_file(key: &str) -> PathBuf {
    private_dir(&app_dir().join("resume")).join(format!("{}.json", hashed_name(key)))
}

fn stop_file() -> PathBuf {
    app_dir().join(format!("stop-{}.flag", std::process::id()))
}

fn folders_file() -> PathBuf {
    app_dir().join("folders.json")
}

/// The chosen folders from last time (paths only; never results).
fn load_folders() -> Vec<PathBuf> {
    let Ok(bytes) = std::fs::read(folders_file()) else {
        return vec![];
    };
    let list: Vec<String> = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("folders").cloned())
        .and_then(|f| serde_json::from_value(f).ok())
        .unwrap_or_default();
    tidy_folders(
        list.into_iter()
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .collect(),
    )
}

fn save_folders(folders: &[PathBuf]) {
    let list: Vec<String> = folders.iter().map(|p| p.display().to_string()).collect();
    let _ = std::fs::write(
        folders_file(),
        serde_json::json!({ "folders": list }).to_string(),
    );
}

// ------------------------------------------------------------- disk size ----

/// Used bytes (total minus available) from `df -Pk` output.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn parse_df(output: &str) -> Option<u64> {
    let line = output.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    // Filesystem 1024-blocks Used Available Capacity Mounted-on; the
    // filesystem name may contain spaces, so count from the end.
    if cols.len() < 6 {
        return None;
    }
    let n = cols.len();
    let total: u64 = cols[n - 5].parse().ok()?;
    let avail: u64 = cols[n - 3].parse().ok()?;
    Some(total.saturating_sub(avail) * 1024)
}

/// Used space on the disk that holds the home folder.
#[cfg(unix)]
fn disk_used_bytes(home: &Path) -> Option<u64> {
    let out = Command::new("df")
        .arg("-Pk")
        .arg(home)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    parse_df(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(windows)]
fn disk_used_bytes(home: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            directory: *const u16,
            free_to_caller: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = home.as_os_str().encode_wide().chain(Some(0)).collect();
    let (mut caller, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: a NUL-terminated wide string and three valid u64 out-pointers
    // (ULARGE_INTEGER is a u64).
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut caller, &mut total, &mut free) };
    (ok != 0).then(|| total.saturating_sub(free))
}

#[cfg(not(any(unix, windows)))]
fn disk_used_bytes(_home: &Path) -> Option<u64> {
    None
}

// ---------------------------------------------------------------- runner ----

pub enum DeepMsg {
    Event(ScanEvent),
    TargetDone {
        key: String,
        report: Box<ScanReport>,
    },
    Failed(String),
    Finished,
}

pub struct ScanJob {
    rx: Receiver<DeepMsg>,
    stop: Arc<AtomicBool>,
    started: Instant,
}

fn tail(text: &str, max: usize) -> String {
    let t = text.trim();
    let chars: Vec<char> = t.chars().collect();
    chars[chars.len().saturating_sub(max)..].iter().collect()
}

/// The arguments for one target.
pub fn scan_args(
    target: &Option<PathBuf>,
    whole_home: bool,
    resume: Option<&Path>,
    stop: &Path,
) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = ["scan", "--deep", "--json", "--progress"]
        .iter()
        .map(Into::into)
        .collect();
    match target {
        Some(p) => {
            args.push("--path".into());
            args.push(p.into());
        }
        None if whole_home => args.push("--all-dirs".into()),
        None => {}
    }
    if let Some(r) = resume {
        args.push("--resume".into());
        args.push(r.into());
    }
    args.push("--stop-file".into());
    args.push(stop.into());
    args
}

fn run_target(
    cli: &Path,
    target: &Option<PathBuf>,
    whole_home: bool,
    stop: &AtomicBool,
    tx: &Sender<DeepMsg>,
) -> Result<ScanReport, String> {
    use std::io::{BufRead, Read};
    let resume = if target.is_none() && whole_home {
        None
    } else {
        Some(resume_file(&key_of(target)))
    };
    let stop_path = stop_file();
    let mut cmd = Command::new(cli);
    cmd.args(scan_args(target, whole_home, resume.as_deref(), &stop_path))
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
        .map_err(|e| format!("Could not start the scanner: {e}"))?;
    let stderr = child.stderr.take().ok_or("The scanner did not start.")?;
    let mut stdout = child.stdout.take().ok_or("The scanner did not start.")?;
    let events = tx.clone();
    let err_reader = std::thread::spawn(move || {
        let mut other = String::new();
        let mut reader = std::io::BufReader::new(stderr);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end();
            if line.starts_with('{') {
                if let Some(ev) = parse_event(line) {
                    let _ = events.send(DeepMsg::Event(ev));
                }
            } else if other.len() < 16_000 {
                other.push_str(line);
                other.push('\n');
            }
        }
        other
    });
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    // No time limit: the scan runs until it finishes or is asked to stop.
    // A stop writes the stop file (kept in place until the CLI exits, in
    // case it had not started watching yet); the CLI then prints its report.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => break Err(format!("The scanner did not finish: {e}")),
        }
        if stop.load(Ordering::SeqCst) && !stop_path.exists() {
            let _ = std::fs::write(&stop_path, b"stop");
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let _ = std::fs::remove_file(&stop_path);
    let out = out_reader.join().unwrap_or_default();
    let other = err_reader.join().unwrap_or_default();
    let status = status?;
    if !status.success() {
        let t = tail(&other, 2000);
        return Err(if t.is_empty() {
            "The scan could not complete.".into()
        } else {
            t
        });
    }
    serde_json::from_slice::<ScanReport>(&out)
        .map_err(|_| "The scanner returned a report this program could not read.".to_string())
}

fn start_scan(targets: Vec<Option<PathBuf>>, whole_home: bool) -> ScanJob {
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    std::thread::spawn(move || {
        let Some(cli) = cli_path() else {
            let _ = tx.send(DeepMsg::Failed(
                "The scanner is missing. Keep gorse-cli.exe in the same folder as this program."
                    .into(),
            ));
            let _ = tx.send(DeepMsg::Finished);
            return;
        };
        for target in targets {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            match run_target(&cli, &target, whole_home, &flag, &tx) {
                Ok(report) => {
                    let _ = tx.send(DeepMsg::TargetDone {
                        key: key_of(&target),
                        report: Box::new(report),
                    });
                }
                Err(e) => {
                    let _ = tx.send(DeepMsg::Failed(e));
                    break;
                }
            }
        }
        let _ = tx.send(DeepMsg::Finished);
    });
    ScanJob {
        rx,
        stop,
        started: Instant::now(),
    }
}

// ----------------------------------------------------------------- state ----

pub struct DeepState {
    pub places: Vec<ScanPlace>,
    places_rx: Option<Receiver<(Vec<ScanPlace>, Option<u64>)>>,
    pub folders: Vec<PathBuf>,
    pub whole_home: bool,
    reports: BTreeMap<String, ScanReport>,
    pub report: Option<ScanReport>,
    pub error: Option<String>,
    job: Option<ScanJob>,
    pub live: LiveScan,
    pub stopping: bool,
    resumable: HashSet<String>,
    last_scan: Option<i64>,
    disk_used: Option<u64>,
    gaps_open: bool,
}

impl DeepState {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let places = crate::run_cli(&["scan", "--list-places"], None)
                .map(|out| parse_places(&out))
                .unwrap_or_default();
            let used = home_dir().and_then(|h| disk_used_bytes(&h));
            let _ = tx.send((places, used));
        });
        let mut state = Self {
            places: vec![],
            places_rx: Some(rx),
            folders: load_folders(),
            whole_home: false,
            reports: BTreeMap::new(),
            report: None,
            error: None,
            job: None,
            live: LiveScan::default(),
            stopping: false,
            resumable: HashSet::new(),
            last_scan: None,
            disk_used: None,
            gaps_open: false,
        };
        state.refresh_resumable();
        state
    }

    pub fn is_scanning(&self) -> bool {
        self.job.is_some()
    }

    fn refresh_resumable(&mut self) {
        let mut keys: Vec<String> = self
            .folders
            .iter()
            .map(|f| f.display().to_string())
            .collect();
        keys.push(DEFAULTS_KEY.into());
        self.resumable = keys
            .into_iter()
            .filter(|k| resume_file(k).is_file())
            .collect();
    }

    /// Merges the default places' report with the extras' reports, leaving
    /// out any folder the default places now read, so nothing counts twice.
    fn rebuild(&mut self) {
        let keys: HashSet<String> = self
            .extras()
            .iter()
            .map(|f| f.display().to_string())
            .chain(Some(DEFAULTS_KEY.to_string()))
            .collect();
        self.reports.retain(|k, _| keys.contains(k));
        self.report = merge_reports(self.reports.values());
    }

    /// Where the default places read (the home folder when whole-home is on).
    pub fn roots(&self) -> Vec<PathBuf> {
        default_roots(&self.places, home_dir().as_deref(), self.whole_home)
    }

    /// The added folders the default places do not already read.
    pub fn extras(&self) -> Vec<PathBuf> {
        let roots = self.roots();
        self.folders
            .iter()
            .filter(|f| !is_covered(f, &roots))
            .cloned()
            .collect()
    }

    pub fn plan(&self) -> Plan {
        plan_scan(
            &self.extras(),
            |k| self.reports.contains_key(k),
            |k| self.resumable.contains(k),
            self.whole_home,
        )
    }

    fn choose_folders(&mut self) {
        let mut dialog = rfd::FileDialog::new().set_title("Choose folders to scan");
        if let Some(home) = home_dir() {
            let docs = home.join("Documents");
            dialog = dialog.set_directory(if docs.is_dir() { docs } else { home });
        }
        let Some(picked) = dialog.pick_folders() else {
            return;
        };
        let roots = self.roots();
        for p in picked {
            // Already read by the default places: nothing to add.
            if is_covered(&p, &roots) {
                continue;
            }
            if let Some(replaced) = add_folder(&mut self.folders, p) {
                for r in replaced {
                    self.reports.remove(&r.display().to_string());
                }
            }
        }
        self.after_folders_changed();
    }

    fn remove_folder(&mut self, folder: &Path) {
        self.folders.retain(|f| !same_path(f, folder));
        self.reports.remove(&folder.display().to_string());
        self.after_folders_changed();
    }

    fn after_folders_changed(&mut self) {
        save_folders(&self.folders);
        self.rebuild();
        self.refresh_resumable();
    }

    pub fn run(&mut self, plan: Plan) {
        if self.is_scanning() {
            return;
        }
        if plan.rescan_all {
            // Start over: no carrying on from a stopped scan.
            self.reports.clear();
            for f in &self.folders {
                let _ = std::fs::remove_file(resume_file(&f.display().to_string()));
            }
            let _ = std::fs::remove_file(resume_file(DEFAULTS_KEY));
            self.resumable.clear();
        }
        self.rebuild();
        self.error = None;
        self.live = LiveScan::default();
        self.stopping = false;
        self.job = Some(start_scan(plan.targets, self.whole_home));
    }

    pub fn stop(&mut self) {
        if let Some(job) = &self.job {
            if !self.stopping {
                self.stopping = true;
                job.stop.store(true, Ordering::SeqCst);
            }
        }
    }

    fn clear(&mut self) {
        self.reports.clear();
        self.report = None;
        self.error = None;
    }

    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.places_rx {
            match rx.try_recv() {
                Ok((places, used)) => {
                    self.places = places;
                    self.disk_used = used;
                    self.places_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.places_rx = None,
                Err(_) => ctx.request_repaint_after(Duration::from_millis(300)),
            }
        }
        let Some(job) = &self.job else { return };
        let now = job.started.elapsed().as_secs_f64();
        let mut finished = false;
        let mut msgs = Vec::new();
        loop {
            match job.rx.try_recv() {
                Ok(m) => msgs.push(m),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        for m in msgs {
            match m {
                DeepMsg::Event(ev) => self.live.apply(ev, now),
                DeepMsg::TargetDone { key, report } => {
                    self.reports.insert(key, *report);
                    self.last_scan = Some(now_unix());
                    self.rebuild();
                }
                DeepMsg::Failed(e) => self.error = Some(e),
                DeepMsg::Finished => finished = true,
            }
        }
        if finished {
            self.job = None;
            self.stopping = false;
            self.live = LiveScan::default();
            self.refresh_resumable();
        } else {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }

    fn subtitle(&self) -> String {
        let Some(r) = &self.report else {
            return "Nothing scanned yet".into();
        };
        let mut text = format!(
            "{} in {}s",
            count(r.total, "finding", "findings"),
            r.elapsed_secs.max(1)
        );
        if r.interrupted {
            text.push_str(" (stopped early)");
        }
        if let Some(th) = r.engines.iter().find(|e| e.name == "trufflehog") {
            if th.error.is_none() {
                text.push_str(&format!(
                    " · with TruffleHog {}",
                    th.version.clone().unwrap_or_default()
                ));
            } else {
                text.push_str(" · TruffleHog failed");
            }
        }
        if matches!(coverage_state(r), CoverageState::Gaps { .. }) {
            text.push_str(" · some files not checked");
        }
        if let Some(t) = self.last_scan {
            text.push_str(&format!(" · {}", relative_time(t, now_unix())));
        }
        text
    }
}

// -------------------------------------------------------------------- UI ----

impl App {
    pub(crate) fn files_ui(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("deep-folders")
            .resizable(true)
            .default_width(300.0)
            .width_range(250.0..=420.0)
            .show(ctx, |ui| self.folder_pane(ui));
        egui::CentralPanel::default().show(ctx, |ui| self.results_pane(ui));
    }

    fn folder_pane(&mut self, ui: &mut egui::Ui) {
        let scanning = self.deep.is_scanning();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Deep scan: files for secrets").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(!scanning, egui::Button::new("+ Add…"))
                    .on_hover_text("Choose folders to scan")
                    .clicked()
                {
                    self.deep.choose_folders();
                }
            });
        });
        ui.separator();
        egui::TopBottomPanel::bottom("deep-run")
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(0, 8)))
            .show_inside(ui, |ui| self.run_controls(ui));
        egui::ScrollArea::vertical()
            .id_salt("deep-left")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.places_list(ui);
                self.folder_list(ui);
                ui.add_space(8.0);
                self.engine_card(ui);
            });
    }

    fn run_controls(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width();
        if self.deep.is_scanning() {
            let label = if self.deep.stopping {
                "Stopping, keeping what was found…"
            } else {
                "Stop and Show Results"
            };
            ui.horizontal(|ui| {
                ui.spinner();
                if ui
                    .add_enabled(
                        !self.deep.stopping,
                        egui::Button::new(label).min_size(egui::vec2(width - 30.0, 30.0)),
                    )
                    .clicked()
                {
                    self.deep.stop();
                }
            });
        } else {
            let plan = self.deep.plan();
            let offer = plan.offer_rescan_all;
            if ui
                .add(
                    egui::Button::new(RichText::new(&plan.label).strong())
                        .min_size(egui::vec2(width, 30.0)),
                )
                .clicked()
            {
                self.deep.run(plan);
            } else if offer {
                ui.add_space(4.0);
                if ui
                    .small_button("Rescan All")
                    .on_hover_text("Start again from the beginning instead of carrying on.")
                    .clicked()
                {
                    let mut plan = plan_scan(
                        &self.deep.extras(),
                        |_| true,
                        |_| false,
                        self.deep.whole_home,
                    );
                    plan.rescan_all = true;
                    self.deep.run(plan);
                }
            }
        }
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Files are read on this computer and nothing leaves it. No secret is shown in full.",
                )
                .small()
                .weak(),
            )
            .wrap(),
        );
    }

    fn places_list(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.label(RichText::new("Where Gorse looks").strong());
        ui.add_space(4.0);
        let whole = self.deep.whole_home;
        if self.deep.places.is_empty() {
            ui.add(
                egui::Label::new(
                    RichText::new("Desktop, Documents (including code checkouts such as GitHub), Downloads and Pictures, and the text inside screenshots and photos.")
                        .small()
                        .weak(),
                )
                .wrap(),
            );
        } else {
            for place in self.deep.places.clone() {
                ui.scope(|ui| {
                    if whole {
                        ui.multiply_opacity(0.4);
                    }
                    ui.horizontal_top(|ui| {
                        ui.add_sized(
                            [22.0, 16.0],
                            egui::Label::new(RichText::new(place.icon()).small().weak()),
                        );
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&place.label).small().strong());
                            if place.kind != "settings" {
                                if let Some(p) = &place.path {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(home_abbrev(p)).small().weak(),
                                        )
                                        .truncate(),
                                    );
                                }
                            }
                            if !place.detail.is_empty() {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&place.detail).small().color(Color32::GRAY),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                    });
                });
                ui.add_space(3.0);
            }
        }
        ui.add_space(8.0);
        let paid = self.license.is_paid();
        if !paid {
            self.deep.whole_home = false;
        }
        ui.add_enabled(
            paid && !self.deep.is_scanning(),
            egui::Checkbox::new(
                &mut self.deep.whole_home,
                RichText::new("Whole home folder (Pro)").small().strong(),
            ),
        );
        ui.add(
            egui::Label::new(
                RichText::new("Every folder you own, hidden ones included, instead of the default places. Slower. Part of Gorse Pro.")
                    .small()
                    .weak(),
            )
            .wrap(),
        );
        if !paid {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("You are on the free plan.").small().weak());
                if ui.link(RichText::new("Upgrade to Pro").small()).clicked() {
                    open_url(PRICING_URL);
                }
            });
        }
        ui.add_space(6.0);
        ui.add(
            egui::Label::new(
                RichText::new("To scan other folders as well, add them with the Add button.")
                    .small()
                    .color(Color32::GRAY),
            )
            .wrap(),
        );
    }

    /// The added folders, below the default places; each removable.
    fn folder_list(&mut self, ui: &mut egui::Ui) {
        if self.deep.folders.is_empty() {
            return;
        }
        let scanning = self.deep.is_scanning();
        let roots = self.deep.roots();
        let mut remove: Option<PathBuf> = None;
        ui.add_space(8.0);
        ui.label(RichText::new("Also scan").strong());
        ui.add_space(4.0);
        for folder in &self.deep.folders {
            let covered = is_covered(folder, &roots);
            ui.horizontal(|ui| {
                ui.label("🗀");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!scanning, egui::Button::new("🗙").small().frame(false))
                        .on_hover_text("Remove from scan")
                        .clicked()
                    {
                        remove = Some(folder.clone());
                    }
                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.add(egui::Label::new(display_name(folder)).truncate());
                        ui.add(
                            egui::Label::new(
                                RichText::new(home_abbrev(&folder.display().to_string()))
                                    .small()
                                    .weak(),
                            )
                            .truncate(),
                        );
                        if covered {
                            ui.label(
                                RichText::new("Already included above")
                                    .small()
                                    .color(Color32::GRAY),
                            );
                        }
                    });
                });
            });
            ui.add_space(4.0);
        }
        if let Some(f) = remove {
            self.deep.remove_folder(&f);
        }
    }

    fn engine_card(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if self.engine.installed {
                ui.add(
                    egui::Label::new(
                        RichText::new(if self.engine.managed {
                            format!("✔ TruffleHog {} is installed. Its ≈800 detectors run with every Deep Scan, verification off.", self.engine.version.clone().unwrap_or_default())
                        } else {
                            "✔ TruffleHog found on this computer. Its detectors run with every Deep Scan, verification off.".to_string()
                        })
                        .small()
                        .weak(),
                    )
                    .wrap(),
                );
                if self.engine.managed
                    && ui.link(RichText::new("Remove").small()).clicked()
                {
                    self.remove_trufflehog();
                }
            } else if self.install_rx.is_some() {
                let p = self.install_progress.lock().unwrap().clone();
                let mb = p.received as f64 / 1_048_576.0;
                match p.total {
                    Some(t) if t > 0 => {
                        ui.label(RichText::new(format!("Downloading TruffleHog… {:.0} of {:.0} MB", mb, t as f64 / 1_048_576.0)).small());
                        ui.add(egui::ProgressBar::new((p.received as f64 / t as f64).min(1.0) as f32));
                    }
                    _ => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new(format!("Downloading TruffleHog… {mb:.0} MB")).small());
                        });
                    }
                }
                ui.ctx().request_repaint_after(Duration::from_millis(250));
            } else {
                ui.label(RichText::new("Add TruffleHog's ≈800 detectors").small().strong());
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("Open source, by Truffle Security. A {} MB download from GitHub (about 175 MB on disk), checked against a known checksum and kept in Gorse's own folder. Runs with verification off, so nothing leaves this computer.", self.engine.download_mb))
                            .small()
                            .weak(),
                    )
                    .wrap(),
                );
                if ui.small_button("Add TruffleHog").clicked() {
                    self.start_trufflehog_install();
                }
                if let Some(e) = &self.install_error {
                    ui.add(
                        egui::Label::new(RichText::new(e).small().color(severity_color("critical")))
                            .wrap(),
                    );
                }
            }
        });
    }

    fn results_pane(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading("Findings");
                ui.label(RichText::new(self.deep.subtitle()).small().weak());
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.deep.report.is_some()
                    && ui
                        .add_enabled(!self.deep.is_scanning(), egui::Button::new("Clear"))
                        .clicked()
                {
                    self.deep.clear();
                }
            });
        });
        ui.separator();
        if let Some(message) = self.deep.error.clone() {
            placeholder(ui, "The scan could not complete", &message);
            return;
        }
        if self.deep.is_scanning() {
            let now = self
                .deep
                .job
                .as_ref()
                .map(|j| j.started.elapsed().as_secs_f64())
                .unwrap_or(0.0);
            if self.deep.live.found.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    ui.spinner();
                    ui.add_space(8.0);
                    self.progress_block(ui, now);
                });
            } else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.vertical(|ui| self.progress_block(ui, now));
                });
                ui.separator();
                let found = self.deep.live.found.clone();
                let home = home_dir()
                    .map(|h| h.to_string_lossy().into_owned())
                    .unwrap_or_default();
                egui::ScrollArea::vertical()
                    .id_salt("deep-live")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for f in &found {
                            finding_row(ui, f, &home);
                        }
                    });
            }
            return;
        }
        let Some(report) = self.deep.report.clone() else {
            placeholder(
                ui,
                "Ready to scan",
                "Click Deep Scan. Gorse reads your documents, downloads, code and screenshots for API keys, passwords, private keys, seed phrases, card numbers and other sensitive content.",
            );
            return;
        };
        match (report.findings.is_empty(), coverage_state(&report)) {
            (true, CoverageState::AllClear(n)) => {
                let mut detail = vec![format!(
                    "{} in the places scanned {} read, and nothing matched a known secret or sensitive-content pattern.",
                    if n == 1 { "1 readable file".to_string() } else { format!("{} readable files", thousands(n)) },
                    if n == 1 { "was" } else { "were" }
                )];
                detail.extend(coverage_notes(&report));
                placeholder(ui, "No secrets found", &detail.join(" "));
            }
            (true, CoverageState::Gaps { headline, reasons }) => {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.heading(RichText::new("Scan finished with gaps").color(AMBER));
                    ui.add_space(6.0);
                    ui.add(egui::Label::new(RichText::new("No secrets were found in the files that were checked, but the scan did not cover everything.").weak()).wrap());
                });
                ui.add_space(8.0);
                gaps_detail(ui, &headline, &reasons);
            }
            (false, state) => {
                if let CoverageState::Gaps { headline, reasons } = state {
                    egui::Frame::new()
                        .fill(AMBER.linear_multiply(0.12))
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .corner_radius(4)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("Scan finished with gaps")
                                        .strong()
                                        .color(AMBER),
                                );
                                let open = self.deep.gaps_open;
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.link(if open { "Hide" } else { "Why?" }).clicked() {
                                            self.deep.gaps_open = !open;
                                        }
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&headline).small().weak(),
                                            )
                                            .truncate(),
                                        );
                                    },
                                );
                            });
                            if self.deep.gaps_open {
                                for r in &reasons {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("– {r}")).small().weak(),
                                        )
                                        .wrap(),
                                    );
                                }
                            }
                        });
                    ui.add_space(4.0);
                }
                findings_sections(ui, &report.findings);
            }
        }
    }

    fn progress_block(&mut self, ui: &mut egui::Ui, now: f64) {
        let live = &self.deep.live;
        if !live.heard {
            ui.label(RichText::new("Starting…").small().weak());
            return;
        }
        ui.label(RichText::new(live.progress_line(now)).strong());
        if let Some(f) = live.fraction() {
            ui.add(egui::ProgressBar::new(f).desired_width(360.0));
        }
        if let Some(percent) = live.disk_coverage(self.deep.disk_used) {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("Covers about {percent}% of what is on this disk."))
                        .small()
                        .weak(),
                );
                if !self.deep.whole_home
                    && ui
                        .link(RichText::new("Whole-disk scan with Pro").small())
                        .clicked()
                {
                    open_url(PRICING_URL);
                }
            });
        }
        if let Some(text) = live.phase_text() {
            ui.label(RichText::new(text).small().weak());
        } else if let Some(d) = &live.dir {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("Reading {}", home_abbrev(d)))
                        .monospace()
                        .small()
                        .weak(),
                )
                .truncate(),
            );
        }
    }
}

fn gaps_detail(ui: &mut egui::Ui, headline: &str, reasons: &[String]) {
    egui::Frame::new()
        .fill(AMBER.linear_multiply(0.12))
        .inner_margin(egui::Margin::same(10))
        .corner_radius(6)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(headline).small().strong());
            for r in reasons {
                ui.add(egui::Label::new(RichText::new(format!("• {r}")).small().weak()).wrap());
            }
        });
}

/// Credentials first, then sensitive content, each grouped by category.
fn findings_sections(ui: &mut egui::Ui, findings: &[ScanFinding]) {
    let (credentials, sensitive, header) = split_counts(findings);
    let home = home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();
    ui.label(RichText::new(header).small().weak());
    egui::ScrollArea::vertical()
        .id_salt("deep-findings")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (title, n, is_sensitive) in [
                ("Credentials", credentials, false),
                ("Sensitive content", sensitive, true),
            ] {
                if n == 0 {
                    continue;
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.heading(title);
                    ui.label(RichText::new(thousands(n as u64)).weak());
                });
                for (category, items) in grouped(findings, is_sensitive) {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&category).strong());
                        ui.label(RichText::new(items.len().to_string()).weak());
                    });
                    ui.separator();
                    for f in &items {
                        finding_row(ui, f, &home);
                    }
                }
            }
            ui.add_space(16.0);
        });
}

/// What it looks like and how sure, never the secret itself.
fn finding_row(ui: &mut egui::Ui, f: &ScanFinding, home: &str) {
    let path = PathBuf::from(&f.path);
    let guide = f.rotation_guide.clone().filter(|g| safe_url(g));
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(4, 5))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                badge(ui, &f.severity);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("🗐").on_hover_text("Copy path").clicked() {
                        ui.ctx().copy_text(f.path.clone());
                    }
                    if ui
                        .small_button("🗁")
                        .on_hover_text("Show in folder")
                        .clicked()
                    {
                        reveal_path(&path);
                    }
                    if let Some(l) = f.likelihood {
                        egui::Frame::new()
                            .fill(Color32::GRAY.linear_multiply(0.15))
                            .inner_margin(egui::Margin::symmetric(6, 1))
                            .corner_radius(4)
                            .show(ui, |ui| {
                                ui.label(RichText::new(format!("{l}% sure")).small().strong());
                            })
                            .response
                            .on_hover_text(SURE_HELP);
                    }
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("Looks like: {}", f.kind())).strong(),
                            )
                            .truncate(),
                        );
                    });
                });
            });
            if let Some(reason) = f.reason() {
                ui.add(egui::Label::new(RichText::new(reason).small().weak()).wrap());
            }
            ui.add(
                egui::Label::new(
                    RichText::new(f.location_with(home))
                        .monospace()
                        .small()
                        .color(Color32::GRAY),
                )
                .truncate(),
            );
            if let Some(g) = &guide {
                if ui
                    .link(RichText::new("How to rotate this key…").small())
                    .clicked()
                {
                    open_url(g);
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(desc: &str, group: Option<&str>) -> ScanFinding {
        ScanFinding {
            path: "/home/al/Documents/keys.txt".into(),
            category: "Cloud Credentials".into(),
            severity: "critical".into(),
            line: 3,
            description: desc.into(),
            group: group.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn findings_parse_without_the_preview_and_split_kind_and_reason() {
        let f: ScanFinding = serde_json::from_value(serde_json::json!({
            "path": "/home/al/Documents/keys.txt", "category": "Cloud Credentials",
            "severity": "critical", "confidence": "high", "context": "data", "line": 3,
            "preview": "AKIA…MPLE", "description": "AWS Access Key — grants access to AWS services",
            "likelihood": 97, "group": "credential",
            "rotation_guide": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        }))
        .unwrap();
        assert_eq!(f.kind(), "AWS Access Key");
        assert_eq!(f.reason().as_deref(), Some("Grants access to AWS services"));
        assert_eq!(f.likelihood, Some(97));
        assert!(!f.is_sensitive());
        assert_eq!(f.location_with("/home/al"), "~/Documents/keys.txt · line 3");
        // The preview is never read, so it cannot appear anywhere.
        assert!(!format!("{f:?}").contains("AKIA"));

        // Old reports: no likelihood or group; odd likelihoods are tolerated.
        let old: ScanFinding = serde_json::from_value(serde_json::json!({
            "path": "/x", "category": "Financial", "severity": "high", "line": 0,
            "description": "", "likelihood": "high"
        }))
        .unwrap();
        assert_eq!(old.likelihood, None);
        assert_eq!(old.kind(), "Financial");
        assert_eq!(old.reason(), None);
        assert_eq!(old.location_with("/home/al"), "/x");
        let f = finding("A — b — c", None);
        assert_eq!(f.reason().as_deref(), Some("B — c"));
        let pct: ScanFinding =
            serde_json::from_value(serde_json::json!({"likelihood": 140.4})).unwrap();
        assert_eq!(pct.likelihood, Some(100));
    }

    #[test]
    fn findings_split_into_credentials_and_sensitive_content() {
        let mut list = vec![
            finding("AWS key — x", Some("credential")),
            finding("GitHub token — y", None),
            ScanFinding {
                category: "Financial".into(),
                severity: "high".into(),
                ..finding("Card number — z", Some("sensitive"))
            },
        ];
        list[1].category = "Code Hosting".into();
        let (c, s, text) = split_counts(&list);
        assert_eq!((c, s), (2, 1));
        assert_eq!(text, "2 credentials · 1 sensitive item");
        let creds = grouped(&list, false);
        assert_eq!(creds.len(), 2);
        assert!(creds
            .iter()
            .all(|(_, items)| items.iter().all(|f| !f.is_sensitive())));
        let sens = grouped(&list, true);
        assert_eq!(sens[0].0, "Financial");
        assert_eq!(
            split_counts(&list[..1]).2,
            "1 credential · 0 sensitive items"
        );
    }

    #[test]
    fn places_parse_in_order_with_optional_paths() {
        let places = parse_places(
            br#"{"places":[
                {"kind":"notes","label":"Apple Notes","path":null,"detail":"Read first"},
                {"kind":"folder","label":"Desktop","path":"/home/al/Desktop","detail":""},
                {"kind":"settings","label":"Hidden settings folders","path":"/home/al","detail":".aws, .ssh"},
                {"kind":"code","label":"src","path":"/home/al/src","detail":"Code checkouts"}
            ]}"#,
        );
        assert_eq!(places.len(), 4);
        assert_eq!(places[0].path, None);
        assert_eq!(places[1].label, "Desktop");
        assert_eq!(places[2].icon(), "⚙");
        assert_eq!(places[3].icon(), "</>");
        assert_eq!(places[1].icon(), "🗀");
        assert!(parse_places(b"not json").is_empty());
        assert!(parse_places(br#"{"other":1}"#).is_empty());
    }

    #[test]
    fn progress_events_parse() {
        assert_eq!(
            parse_event(r#"{"event":"start","roots":["/a","/b"]}"#),
            Some(ScanEvent::Start {
                roots: vec!["/a".into(), "/b".into()]
            })
        );
        assert_eq!(
            parse_event(r#"{"event":"estimate","files_total":674926,"bytes_total":91600000000}"#),
            Some(ScanEvent::Estimate {
                files: 674_926,
                bytes: 91_600_000_000
            })
        );
        assert_eq!(
            parse_event(r#"{"event":"phase","name":"images"}"#),
            Some(ScanEvent::Phase("images".into()))
        );
        assert_eq!(
            parse_event(r#"{"event":"images","done":100,"total":5000}"#),
            Some(ScanEvent::Images {
                done: 100,
                total: 5000
            })
        );
        assert_eq!(
            parse_event(
                r#"{"event":"progress","files_scanned":12,"findings":1,"dir":"/a/b","done":true}"#
            ),
            Some(ScanEvent::Progress {
                files: 12,
                findings: 1,
                dir: Some("/a/b".into()),
                done: true
            })
        );
        assert_eq!(
            parse_event(r#"{"event":"progress","files_scanned":12,"findings":1,"dir":null}"#),
            Some(ScanEvent::Progress {
                files: 12,
                findings: 1,
                dir: None,
                done: false
            })
        );
        assert_eq!(
            parse_event(r#"{"event":"resumed","files_scanned":500,"findings":3}"#),
            Some(ScanEvent::Resumed {
                files: 500,
                findings: 3
            })
        );
        match parse_event(
            r#"{"event":"finding","files_scanned":7,"findings":2,"finding":{"path":"/a/k.env","category":"Cloud Credentials","severity":"critical","line":1,"preview":"AKIA…","description":"AWS Access Key — grants access","likelihood":90,"group":"credential"}}"#,
        ) {
            Some(ScanEvent::Finding {
                files: 7,
                findings: 2,
                finding,
            }) => assert_eq!(finding.kind(), "AWS Access Key"),
            other => panic!("{other:?}"),
        }
        assert_eq!(parse_event(r#"{"event":"download","received":1}"#), None);
        assert_eq!(parse_event("Scanning..."), None);
        assert_eq!(parse_event(r#"{"event":"finding","finding":"x"}"#), None);
    }

    #[test]
    fn progress_line_matches_the_mac_wording() {
        let mut live = LiveScan::default();
        live.apply(ScanEvent::Start { roots: vec![] }, 0.0);
        live.apply(
            ScanEvent::Progress {
                files: 12_153,
                findings: 40,
                dir: Some("/x".into()),
                done: false,
            },
            1.0,
        );
        assert_eq!(
            live.progress_line(1.0),
            "12,153 files read · 40 findings · counting…"
        );
        assert_eq!(live.fraction(), None);
        live.apply(
            ScanEvent::Estimate {
                files: 674_926,
                bytes: 91_600_000_000,
            },
            2.0,
        );
        // Not yet ten seconds of reading: no time left.
        assert_eq!(
            live.progress_line(5.0),
            "12,153 of 674,926 files (91.6 GB) · 40 findings"
        );
        // 100 files a second since t=1: 642,773 left is about 1 h 47 min.
        live.apply(
            ScanEvent::Progress {
                files: 12_153 + 20_000,
                findings: 40,
                dir: None,
                done: false,
            },
            201.0,
        );
        assert_eq!(
            live.progress_line(201.0),
            "32,153 of 674,926 files (91.6 GB) · 40 findings · about 1 h 47 min left"
        );
        assert_eq!(
            live.dir.as_deref(),
            Some("/x"),
            "a progress line without a folder keeps the last one"
        );
        let f = live.fraction().unwrap();
        assert!((f - 32_153.0 / 674_926.0).abs() < 1e-4);
        assert_eq!(live.disk_coverage(Some(183_200_000_000)), Some(50));
        assert_eq!(live.disk_coverage(Some(0)), None);
        assert_eq!(live.disk_coverage(Some(1_000_000_000_000_000)), Some(1));

        // Pictures.
        live.apply(
            ScanEvent::Images {
                done: 100,
                total: 5000,
            },
            22.0,
        );
        assert_eq!(
            live.progress_line(22.0),
            "Text in pictures: 100 of 5,000 · 40 findings"
        );
        assert_eq!(live.phase_text(), Some("Reading the text inside pictures…"));
        assert!((live.fraction().unwrap() - 0.02).abs() < 1e-6);
        live.apply(
            ScanEvent::Images {
                done: 5000,
                total: 5000,
            },
            23.0,
        );
        assert_eq!(live.fraction(), Some(0.99), "never 100% before the end");
        live.apply(ScanEvent::Phase("trufflehog".into()), 24.0);
        assert_eq!(live.phase_text(), Some("Running TruffleHog's detectors…"));
        live.apply(ScanEvent::Phase("done".into()), 25.0);
        assert_eq!(live.phase_text(), Some("Finishing…"));

        // Findings arrive newest first and the count never goes backwards.
        let mut live = LiveScan::default();
        live.apply(
            ScanEvent::Finding {
                files: 0,
                findings: 1,
                finding: Box::new(finding("A — a", None)),
            },
            0.0,
        );
        live.apply(
            ScanEvent::Finding {
                files: 9,
                findings: 2,
                finding: Box::new(finding("B — b", None)),
            },
            0.0,
        );
        assert_eq!(live.found[0].kind(), "B");
        assert_eq!(live.files, 9);
        assert_eq!(
            live.progress_line(0.0),
            "9 files read · 2 findings · counting…"
        );
        live.apply(
            ScanEvent::Progress {
                files: 1,
                findings: 1,
                dir: None,
                done: false,
            },
            0.0,
        );
        assert_eq!(live.found_count(), 2);
        assert_eq!(
            live.progress_line(0.0),
            "1 file read · 2 findings · counting…"
        );
    }

    #[test]
    fn folders_inside_chosen_ones_are_not_added_and_parents_replace() {
        let mut folders = vec![PathBuf::from("/h/Documents/a")];
        assert_eq!(
            add_folder(&mut folders, PathBuf::from("/h/Documents/a")),
            None
        );
        assert_eq!(
            add_folder(&mut folders, PathBuf::from("/h/Documents/a/b")),
            None
        );
        assert_eq!(
            add_folder(&mut folders, PathBuf::from("/h/Documents/ab")),
            Some(vec![])
        );
        let replaced = add_folder(&mut folders, PathBuf::from("/h/Documents")).unwrap();
        assert_eq!(
            replaced,
            vec![
                PathBuf::from("/h/Documents/a"),
                PathBuf::from("/h/Documents/ab")
            ]
        );
        assert_eq!(folders, vec![PathBuf::from("/h/Documents")]);
        assert!(is_inside(Path::new("/h/x/y"), Path::new("/h/x")));
        assert!(!is_inside(Path::new("/h/x"), Path::new("/h/x")));
        assert!(!is_inside(Path::new("/h/xy"), Path::new("/h/x")));
        assert_eq!(
            tidy_folders(vec!["/a".into(), "/a/b".into(), "/c".into(), "/a".into()]),
            vec![PathBuf::from("/a"), PathBuf::from("/c")]
        );
    }

    #[test]
    fn the_scan_button_resumes_scans_new_folders_or_starts_over() {
        let none = |_: &str| false;
        let p = plan_scan(&[], none, none, false);
        assert_eq!(
            (p.label.as_str(), p.targets.clone()),
            ("Deep Scan", vec![None])
        );
        let p = plan_scan(&[], |k| k == DEFAULTS_KEY, none, false);
        assert_eq!(p.label, "Rescan");
        assert!(p.rescan_all);
        let p = plan_scan(&[], none, |k| k == DEFAULTS_KEY, false);
        assert_eq!(p.label, "Resume Scan");
        assert!(!p.rescan_all && p.offer_rescan_all);
        // A whole-home scan is never resumed.
        let p = plan_scan(&[], none, |k| k == DEFAULTS_KEY, true);
        assert_eq!(p.label, "Deep Scan, Whole Home");
        assert!(p.rescan_all);

        // Added folders are extras: the default places are still scanned,
        // first, and the label never says the defaults were replaced.
        let folders = vec![
            PathBuf::from("/a"),
            PathBuf::from("/b"),
            PathBuf::from("/c"),
        ];
        let p = plan_scan(&folders, none, none, false);
        assert_eq!(p.label, "Deep Scan");
        assert_eq!(
            p.targets,
            vec![
                None,
                Some("/a".into()),
                Some("/b".into()),
                Some("/c".into())
            ]
        );
        assert!(p.rescan_all && !p.offer_rescan_all);
        let p = plan_scan(&folders, none, none, true);
        assert_eq!(p.label, "Deep Scan, Whole Home");
        assert_eq!(p.targets.len(), 4);
        assert_eq!(p.targets[0], None);
        // Results from the defaults alone, or from one extra, make it a
        // rescan of everything.
        let p = plan_scan(&folders, |k| k == DEFAULTS_KEY, none, false);
        assert_eq!(p.label, "Rescan");
        assert!(p.rescan_all);
        assert_eq!(p.targets.len(), 4);
        let p = plan_scan(&folders, |k| k == "/a", none, false);
        assert_eq!(p.label, "Rescan");
        let p = plan_scan(&folders, |_| true, none, false);
        assert_eq!(p.label, "Rescan");
        // Resuming carries on the stopped targets and any not yet scanned,
        // never a finished one: a stopped default scan goes first.
        let p = plan_scan(&folders, |k| k != "/c", |k| k == "/b", false);
        assert_eq!(p.label, "Resume Scan");
        assert_eq!(p.targets, vec![Some("/b".into()), Some("/c".into())]);
        assert!(!p.rescan_all && p.offer_rescan_all);
        let p = plan_scan(&folders, |k| k == "/a", |k| k == DEFAULTS_KEY, false);
        assert_eq!(p.label, "Resume Scan");
        assert_eq!(p.targets, vec![None, Some("/b".into()), Some("/c".into())]);
        // Stopped during an extra after the defaults finished.
        let p = plan_scan(&folders, |k| k != "/b" && k != "/c", |k| k == "/b", false);
        assert_eq!(p.targets, vec![Some("/b".into()), Some("/c".into())]);
        // An extra's resume file still resumes with whole-home on; the
        // whole-home part, never resumed, runs again only if it has no
        // results.
        let p = plan_scan(&folders, |_| true, |k| k == "/a", true);
        assert_eq!(p.label, "Resume Scan");
        assert_eq!(p.targets, vec![Some("/a".into())]);
        for p in [
            plan_scan(&folders, none, none, false),
            plan_scan(&folders, |_| true, none, false),
            plan_scan(&folders, none, |_| true, false),
            plan_scan(&[], none, none, false),
        ] {
            assert_ne!(p.label, "Scan Chosen Folders");
        }
    }

    fn place(kind: &str, path: Option<&str>, detail: &str) -> ScanPlace {
        ScanPlace {
            kind: kind.into(),
            label: kind.into(),
            path: path.map(str::to_string),
            detail: detail.into(),
        }
    }

    #[test]
    fn folders_the_default_places_read_are_already_included() {
        let places = vec![
            place("notes", None, "Read first"),
            place("pictures", None, "Text in pictures"),
            place("folder", Some("/h/Desktop"), ""),
            place("settings", Some("/h"), ".aws, .ssh"),
            place("folder", Some("/h/Documents"), ""),
            place("code", Some("/h/src"), "Code checkouts"),
        ];
        let roots = default_roots(&places, Some(Path::new("/h")), false);
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/h/Desktop"),
                PathBuf::from("/h/.aws"),
                PathBuf::from("/h/.ssh"),
                PathBuf::from("/h/Documents"),
                PathBuf::from("/h/src"),
            ]
        );
        // Equal to, or inside, a default place.
        assert!(is_covered(Path::new("/h/Documents"), &roots));
        assert!(is_covered(Path::new("/h/Documents/GitHub/app"), &roots));
        assert!(is_covered(Path::new("/h/Documents/"), &roots));
        assert!(is_covered(Path::new("/h/.ssh/keys"), &roots));
        // The settings entry stands for its hidden folders, not the home
        // folder they sit in.
        assert!(!is_covered(Path::new("/h/Music"), &roots));
        assert!(!is_covered(Path::new("/h"), &roots));
        assert!(!is_covered(Path::new("/h/Documents2"), &roots));
        assert!(!is_covered(Path::new("/srv/data"), &roots));
        // Whole home reads everything under the home folder.
        let whole = default_roots(&places, Some(Path::new("/h")), true);
        assert_eq!(whole, vec![PathBuf::from("/h")]);
        assert!(is_covered(Path::new("/h/Music"), &whole));
        assert!(is_covered(Path::new("/h"), &whole));
        assert!(!is_covered(Path::new("/srv/data"), &whole));
        // Without a home folder, whole home falls back to the places.
        assert_eq!(default_roots(&places, None, true), roots);
        assert!(default_roots(&[], Some(Path::new("/h")), false).is_empty());
    }

    #[test]
    fn covered_check_ignores_case_only_on_windows() {
        if cfg!(windows) {
            let roots = vec![PathBuf::from(r"C:\Users\Al\Documents")];
            assert!(is_covered(
                Path::new(r"c:\users\al\documents\GitHub"),
                &roots
            ));
            assert!(is_covered(Path::new(r"C:\USERS\AL\DOCUMENTS"), &roots));
            assert!(!is_covered(Path::new(r"C:\Users\Al\Music"), &roots));
        } else {
            let roots = vec![PathBuf::from("/h/Documents")];
            assert!(!is_covered(Path::new("/h/documents/x"), &roots));
            assert!(is_covered(Path::new("/h/Documents/x"), &roots));
        }
    }

    #[test]
    fn scan_arguments_and_resume_names() {
        let stop = Path::new("/d/stop.flag");
        let args = |t: Option<PathBuf>, whole: bool, resume: Option<&Path>| -> Vec<String> {
            scan_args(&t, whole, resume, stop)
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            args(Some("/h/Docs".into()), false, Some(Path::new("/d/r.json"))),
            [
                "scan",
                "--deep",
                "--json",
                "--progress",
                "--path",
                "/h/Docs",
                "--resume",
                "/d/r.json",
                "--stop-file",
                "/d/stop.flag"
            ]
        );
        assert_eq!(
            args(None, true, None),
            [
                "scan",
                "--deep",
                "--json",
                "--progress",
                "--all-dirs",
                "--stop-file",
                "/d/stop.flag"
            ]
        );
        assert_eq!(
            args(None, false, Some(Path::new("/d/r.json"))),
            [
                "scan",
                "--deep",
                "--json",
                "--progress",
                "--resume",
                "/d/r.json",
                "--stop-file",
                "/d/stop.flag"
            ]
        );
        assert_eq!(hashed_name("/a"), hashed_name("/a"));
        assert_ne!(hashed_name("/a"), hashed_name("/b"));
        assert_eq!(hashed_name(DEFAULTS_KEY).len(), 24);
        assert!(hashed_name("x").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn coverage_gaps_are_explained_and_reports_merge() {
        let report: ScanReport = serde_json::from_value(serde_json::json!({
            "findings": [], "total": 0, "files_scanned": 10, "elapsed_secs": 3, "interrupted": true,
            "coverage": {"complete": false, "has_gaps": true, "interrupted": true, "files_scanned": 10,
                "permission_denied": 2, "unreadable_examples": [{"path": "/h/secret/a.txt", "reason": "permission denied"}],
                "files_over_size_limit": 1, "size_limit_bytes": 10485760, "oversize_examples": ["/h/big.log"],
                "dirs_skipped_by_rule": 3, "skipped_dirs": [{"name": "node_modules", "count": 3}]}
        }))
        .unwrap();
        match coverage_state(&report) {
            CoverageState::Gaps { headline, reasons } => {
                assert_eq!(headline, "10 files were checked. 1 file was not checked.");
                assert!(
                    reasons[0]
                        .starts_with("2 files could not be read because access was denied: a.txt"),
                    "{reasons:?}"
                );
                assert!(reasons.iter().any(
                    |r| r == "1 file is larger than the 10 MB limit and was not read: big.log."
                ));
                assert!(reasons.iter().any(|r| r.contains("(node_modules ×3)")));
                assert_eq!(
                    reasons.last().unwrap(),
                    "The scan stopped before it finished."
                );
            }
            other => panic!("{other:?}"),
        }
        let clean: ScanReport = serde_json::from_value(serde_json::json!({
            "findings": [], "files_scanned": 5,
            "coverage": {"complete": true, "has_gaps": false, "files_scanned": 5, "files_skipped_by_type": 1}
        }))
        .unwrap();
        assert_eq!(coverage_state(&clean), CoverageState::AllClear(5));
        assert_eq!(coverage_notes(&clean).len(), 1);
        // An older report without coverage is never all clear.
        let old: ScanReport =
            serde_json::from_value(serde_json::json!({"findings": [], "files_scanned": 1}))
                .unwrap();
        assert!(matches!(coverage_state(&old), CoverageState::Gaps { .. }));

        let merged = merge_reports([&report, &clean]).unwrap();
        assert_eq!(merged.files_scanned, 15);
        assert!(merged.interrupted);
        let c = merged.coverage.unwrap();
        assert_eq!(c.files_scanned, 15);
        assert_eq!(c.has_gaps, Some(true));
        assert!(!c.complete);
        assert!(merge_reports(std::iter::empty()).is_none());
    }

    #[test]
    fn df_output_gives_used_bytes() {
        let out = "Filesystem     1024-blocks      Used Available Capacity  Mounted on\n/dev/disk3s1s1  971350180  10000000 400000000     3%    /\n";
        assert_eq!(parse_df(out), Some((971_350_180 - 400_000_000) * 1024));
        let spaced = "Filesystem 1024-blocks Used Available Capacity Mounted on\nmap auto home 100 50 40 56% /System/Volumes/Data/home\n";
        assert_eq!(parse_df(spaced), Some(60 * 1024));
        assert_eq!(parse_df("garbage"), None);
    }

    /// Feeds output captured from a real `gorse scan --deep --json
    /// --progress` run through the parsers. Run with
    /// `GORSE_CAPTURE_DIR=<dir> cargo test -- --ignored real_cli_output`,
    /// where the folder holds `stdout.json` and `stderr.txt` (and
    /// optionally `stop_*`/`resume_*` pairs and `places.json`).
    #[test]
    #[ignore]
    fn real_cli_output() {
        let dir = PathBuf::from(std::env::var("GORSE_CAPTURE_DIR").expect("GORSE_CAPTURE_DIR"));
        for prefix in ["", "stop_", "resume_"] {
            let Ok(err) = std::fs::read_to_string(dir.join(format!("{prefix}stderr.txt"))) else {
                continue;
            };
            let out = std::fs::read(dir.join(format!("{prefix}stdout.json"))).unwrap();
            let mut live = LiveScan::default();
            let (mut lines, mut parsed, mut findings) = (0, 0, 0);
            for (i, line) in err.lines().enumerate() {
                if !line.starts_with('{') {
                    continue;
                }
                lines += 1;
                let ev = parse_event(line)
                    .unwrap_or_else(|| panic!("{prefix} line {i} did not parse: {line}"));
                if matches!(ev, ScanEvent::Finding { .. }) {
                    findings += 1;
                }
                parsed += 1;
                live.apply(ev, i as f64);
            }
            let report: ScanReport = serde_json::from_slice(&out).expect("report");
            println!(
                "{prefix}: {parsed}/{lines} progress lines parsed, {findings} live findings; last line: {}",
                live.progress_line(lines as f64)
            );
            println!(
                "{prefix}: report {} findings, {} files, interrupted {}, coverage {:?}",
                report.findings.len(),
                report.files_scanned,
                report.interrupted,
                coverage_state(&report)
            );
            let (_, _, header) = split_counts(&report.findings);
            println!("{prefix}: {header}");
            for f in report.findings.iter().take(4) {
                println!(
                    "  [{}] Looks like: {} · {:?}% sure · {:?} · {}",
                    f.severity,
                    f.kind(),
                    f.likelihood,
                    f.reason(),
                    f.location_with(&home_dir().unwrap().to_string_lossy())
                );
                assert!(f.likelihood.is_some(), "the current CLI sends likelihood");
                assert!(f.group.is_some(), "the current CLI sends group");
            }
            assert_eq!(parsed, lines);
            assert_eq!(live.found.len(), findings);
            assert!(!format!("{report:?}").contains("preview"));
        }
        if let Ok(p) = std::fs::read(dir.join("places.json")) {
            let places = parse_places(&p);
            assert!(!places.is_empty());
            for p in &places {
                println!(
                    "  place {} {} {:?} — {}",
                    p.icon(),
                    p.label,
                    p.path.as_deref().map(home_abbrev),
                    p.detail
                );
            }
        }
    }
}
