// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Scheduled checks: Gorse re-runs the exposure check on its own (Task
//! Scheduler on Windows, a systemd user timer on Linux, both installed by
//! the CLI) and keeps a history. The CLI owns the schedule, the licence gate
//! and the history; this asks `gorse-cli schedule …` and shows the answer.
//! Every field is read leniently so an older or newer CLI still works.

use crate::text::{now_unix, parse_rfc3339, relative_time, utc_label};
use crate::{badge, open_url, run_cli_full, severity_color, App, AMBER, DOWNLOAD_URL, PRICING_URL};
use eframe::egui::{self, Color32, RichText};
use serde_json::Value;
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counts {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low
    }
}

fn num(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|n| n.as_u64())
}

fn flag(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(|b| b.as_bool())
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|s| s.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// One recorded check.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Run {
    pub at: Option<String>,
    pub ok: Option<bool>,
    pub trigger: Option<String>,
    pub counts: Option<Counts>,
    pub new: u64,
    pub worsened: u64,
    pub resolved: u64,
    pub unassessed: u64,
    pub incomplete: Option<bool>,
    pub coverage_failures: u64,
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Some locations were not read (and maybe some findings not reassessed).
    Incomplete {
        not_read: u64,
        not_assessed: u64,
    },
    /// The run itself failed.
    Failed,
    Findings(u64),
    /// A complete run with no findings.
    Clean,
    /// Neither `ok` nor `incomplete` said how the run went (an older CLI).
    Unknown,
}

impl Run {
    pub fn from_value(v: &Value) -> Option<Run> {
        if !v.is_object() {
            return None;
        }
        let counts = v.get("counts").filter(|c| c.is_object()).map(|c| Counts {
            critical: num(c, "critical").unwrap_or(0),
            high: num(c, "high").unwrap_or(0),
            medium: num(c, "medium").unwrap_or(0),
            low: num(c, "low").unwrap_or(0),
        });
        let changes = v.get("changes");
        let unassessed = [
            num(v, "unassessed"),
            changes
                .and_then(|c| c.get("counts"))
                .and_then(|c| num(c, "unassessed")),
            changes
                .and_then(|c| c.get("unassessed"))
                .and_then(|u| u.as_array())
                .map(|u| u.len() as u64),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0);
        Some(Run {
            at: text(v, "at"),
            ok: flag(v, "ok"),
            trigger: text(v, "trigger"),
            counts,
            new: num(v, "new").unwrap_or(0),
            worsened: num(v, "worsened").unwrap_or(0),
            resolved: num(v, "resolved").unwrap_or(0),
            unassessed,
            incomplete: flag(v, "incomplete"),
            coverage_failures: num(v, "coverage_failures").unwrap_or(0),
            message: text(v, "message"),
        })
    }

    pub fn total(&self) -> u64 {
        self.counts.as_ref().map_or(0, Counts::total)
    }

    /// Incomplete wins over everything: a run that could not read some
    /// locations never reads as clean. Only an explicit `ok: true` or
    /// `incomplete: false` lets a run with nothing found say "no findings".
    pub fn outcome(&self) -> Outcome {
        if self.incomplete == Some(true) {
            return Outcome::Incomplete {
                not_read: self.coverage_failures,
                not_assessed: self.unassessed,
            };
        }
        if self.ok == Some(false) {
            return Outcome::Failed;
        }
        let total = self.total();
        if total > 0 {
            return Outcome::Findings(total);
        }
        if self.ok == Some(true) || self.incomplete == Some(false) {
            return Outcome::Clean;
        }
        Outcome::Unknown
    }

    /// "incomplete: 1 location not read · 2 not assessed".
    pub fn incomplete_summary(&self) -> Option<String> {
        let Outcome::Incomplete {
            not_read,
            not_assessed,
        } = self.outcome()
        else {
            return None;
        };
        let mut t = format!(
            "incomplete: {not_read} location{} not read",
            if not_read == 1 { "" } else { "s" }
        );
        if not_assessed > 0 {
            t.push_str(&format!(" · {not_assessed} not assessed"));
        }
        Some(t)
    }

    /// "+2 new, 1 worsened, 0 resolved".
    pub fn changes_line(&self) -> String {
        let mut t = format!(
            "+{} new, {} worsened, {} resolved",
            self.new, self.worsened, self.resolved
        );
        if self.unassessed > 0 && self.incomplete != Some(true) {
            t.push_str(&format!(", {} not assessed", self.unassessed));
        }
        t
    }

    pub fn when(&self, now: i64) -> (String, String) {
        match self.at.as_deref().and_then(parse_rfc3339) {
            Some(t) => (relative_time(t, now), utc_label(t)),
            None => {
                let raw = self.at.clone().unwrap_or_else(|| "Unknown time".into());
                (raw.clone(), raw)
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Status {
    pub frequency: String,
    pub installed: Option<bool>,
    pub program_exists: Option<bool>,
    pub program_trusted: Option<bool>,
    pub last_run: Option<Run>,
    pub history_count: u64,
}

pub const FREQUENCIES: [&str; 3] = ["off", "daily", "hourly"];

impl Status {
    pub fn from_value(v: &Value) -> Option<Status> {
        if !v.is_object() || v.get("error").is_some() {
            return None;
        }
        let f = text(v, "frequency")
            .unwrap_or_default()
            .to_ascii_lowercase();
        Some(Status {
            frequency: if FREQUENCIES.contains(&f.as_str()) {
                f
            } else {
                "off".into()
            },
            installed: flag(v, "installed"),
            program_exists: flag(v, "program_exists"),
            program_trusted: flag(v, "program_trusted"),
            last_run: v.get("last_run").and_then(Run::from_value),
            history_count: num(v, "history_count").unwrap_or(0),
        })
    }
}

pub fn parse_status(bytes: &[u8]) -> Option<Status> {
    Status::from_value(&serde_json::from_slice(bytes).ok()?)
}

pub fn parse_history(bytes: &[u8]) -> Option<Vec<Run>> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    Some(
        v.get("runs")?
            .as_array()?
            .iter()
            .filter_map(Run::from_value)
            .collect(),
    )
}

/// The `{"error": …}` a refused `schedule set` prints.
pub fn parse_failure(bytes: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    text(&v, "error")
}

/// "Last check: 3 hours ago · 12 findings · 2 new / 1 worsened".
pub fn last_run_line(run: &Run, now: i64) -> String {
    let mut parts = vec![match run.at.as_deref().and_then(parse_rfc3339) {
        Some(t) => format!("Last check: {}", relative_time(t, now)),
        None => "Last check".to_string(),
    }];
    let total = run.total();
    let findings = format!("{total} finding{}", if total == 1 { "" } else { "s" });
    match run.outcome() {
        Outcome::Failed => parts.push("did not complete".into()),
        Outcome::Incomplete { .. } => {
            parts.push(
                run.incomplete_summary()
                    .unwrap_or_else(|| "incomplete".into()),
            );
            if total > 0 {
                parts.push(format!("{findings} so far"));
            }
        }
        Outcome::Unknown => parts.push("result unknown".into()),
        Outcome::Findings(_) | Outcome::Clean => {
            parts.push(findings);
            parts.push(format!("{} new / {} worsened", run.new, run.worsened));
            if run.unassessed > 0 {
                parts.push(format!("{} not assessed", run.unassessed));
            }
        }
    }
    parts.join(" · ")
}

pub const UNTRUSTED: &str = "This copy of Gorse is not signed by QKey, so scheduled checks are off. Download it again from gorse.is.";

/// Something to fix before scheduled checks will run.
pub fn warning(status: &Status) -> Option<&'static str> {
    if status.frequency == "off" {
        return None;
    }
    if status.program_exists == Some(false) {
        return Some("Gorse moved. Choose a frequency again to repair the schedule.");
    }
    if status.installed == Some(false) {
        return Some("The schedule is not installed. Choose a frequency again.");
    }
    None
}

enum SetResult {
    Applied(Status),
    Refresh,
    Failed(String),
}

pub struct ScheduleState {
    pub status: Option<Status>,
    pub history: Vec<Run>,
    pub history_loaded: bool,
    pub busy: bool,
    pub error: Option<String>,
    /// What the control shows: set ahead of the CLI's answer so it does not
    /// snap back while the scheduler entry is written.
    pub frequency: String,
    previous: String,
    status_rx: Option<Receiver<Option<Status>>>,
    set_rx: Option<Receiver<SetResult>>,
    history_rx: Option<Receiver<Option<Vec<Run>>>>,
}

impl ScheduleState {
    pub fn new() -> Self {
        let mut s = Self {
            status: None,
            history: vec![],
            history_loaded: false,
            busy: false,
            error: None,
            frequency: "off".into(),
            previous: "off".into(),
            status_rx: None,
            set_rx: None,
            history_rx: None,
        };
        s.refresh();
        s
    }

    pub fn refresh(&mut self) {
        if self.status_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let status = run_cli_full(&["schedule", "status", "--json"], None)
                .ok()
                .filter(|(code, _, _)| *code == 0)
                .and_then(|(_, out, _)| parse_status(&out));
            let _ = tx.send(status);
        });
        self.status_rx = Some(rx);
        if self.history_loaded {
            self.load_history();
        }
    }

    fn load_history(&mut self) {
        if self.history_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let runs = run_cli_full(&["schedule", "history", "--json", "--limit", "30"], None)
                .ok()
                .filter(|(code, _, _)| *code == 0)
                .and_then(|(_, out, _)| parse_history(&out));
            let _ = tx.send(runs);
        });
        self.history_rx = Some(rx);
    }

    fn set_frequency(&mut self, wanted: &str) {
        if self.busy || !FREQUENCIES.contains(&wanted) || wanted == self.frequency {
            return;
        }
        self.previous = self.frequency.clone();
        self.frequency = wanted.to_string();
        self.busy = true;
        self.error = None;
        let value = wanted.to_string();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let result = match run_cli_full(&["schedule", "set", &value, "--json"], None) {
                Err(e) => SetResult::Failed(e),
                Ok((code, out, err)) => {
                    if let Some(f) = parse_failure(&out).or_else(|| parse_failure(&err)) {
                        SetResult::Failed(f)
                    } else if code != 0 {
                        let detail = String::from_utf8_lossy(&err).trim().to_string();
                        SetResult::Failed(if detail.is_empty() {
                            "The schedule could not be changed.".into()
                        } else {
                            detail
                                .chars()
                                .rev()
                                .take(400)
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect()
                        })
                    } else if let Some(s) = parse_status(&out) {
                        SetResult::Applied(s)
                    } else {
                        SetResult::Refresh
                    }
                }
            };
            let _ = tx.send(result);
        });
        self.set_rx = Some(rx);
    }

    fn apply(&mut self, status: Status) {
        self.frequency = status.frequency.clone();
        self.status = Some(status);
    }

    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.status_rx {
            match rx.try_recv() {
                Ok(s) => {
                    self.status_rx = None;
                    if let Some(s) = s {
                        if !self.busy {
                            self.apply(s);
                        } else {
                            self.status = Some(s);
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.status_rx = None,
                Err(_) => ctx.request_repaint_after(Duration::from_millis(300)),
            }
        }
        if let Some(rx) = &self.history_rx {
            match rx.try_recv() {
                Ok(runs) => {
                    self.history_rx = None;
                    if let Some(runs) = runs {
                        self.history = runs;
                    }
                    self.history_loaded = true;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.history_rx = None,
                Err(_) => ctx.request_repaint_after(Duration::from_millis(300)),
            }
        }
        if let Some(rx) = &self.set_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.set_rx = None;
                    self.busy = false;
                    match result {
                        SetResult::Applied(s) => self.apply(s),
                        SetResult::Refresh => self.refresh(),
                        SetResult::Failed(e) => {
                            self.frequency = self.previous.clone();
                            self.error = Some(e);
                            self.refresh();
                        }
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.set_rx = None;
                    self.busy = false;
                }
                Err(_) => ctx.request_repaint_after(Duration::from_millis(250)),
            }
        }
    }

    fn is_on(&self) -> bool {
        self.frequency != "off"
    }

    fn untrusted(&self) -> bool {
        self.status.as_ref().and_then(|s| s.program_trusted) == Some(false)
    }
}

impl App {
    /// The "Scheduled checks" card under the Fast Scan findings.
    pub(crate) fn schedule_card(&mut self, ui: &mut egui::Ui) {
        let paid = self.license.is_paid();
        let s = &mut self.schedule;
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Scheduled checks").strong());
            if !paid {
                egui::Frame::new()
                    .fill(Color32::from_rgb(40, 167, 69).linear_multiply(0.18))
                    .inner_margin(egui::Margin::symmetric(6, 1))
                    .corner_radius(4)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("Pro")
                                .small()
                                .strong()
                                .color(Color32::from_rgb(40, 167, 69)),
                        );
                    })
                    .response
                    .on_hover_text("Part of Gorse Pro");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if s.busy {
                    ui.spinner();
                }
                // Off can always be chosen, so a lapsed licence never leaves
                // a schedule that cannot be turned off; the CLI gates the rest.
                let enabled = !s.busy && !(!s.is_on() && (!paid || s.untrusted()));
                let hover = if paid {
                    "How often Gorse re-runs the check on its own."
                } else if s.is_on() {
                    "Daily and hourly checks are part of Gorse Pro. You can turn the schedule off."
                } else {
                    "Scheduled checks are part of Gorse Pro."
                };
                let mut picked: Option<&str> = None;
                for (value, label) in [("hourly", "Hourly"), ("daily", "Daily"), ("off", "Off")] {
                    let selected = s.frequency == value;
                    if ui
                        .add_enabled(enabled, egui::SelectableLabel::new(selected, label))
                        .on_hover_text(hover)
                        .on_disabled_hover_text(hover)
                        .clicked()
                    {
                        picked = Some(value);
                    }
                }
                if let Some(v) = picked {
                    s.set_frequency(v);
                }
            });
        });
        ui.label(
            RichText::new(
                "Gorse re-runs the check on its own and tells you when something new appears.",
            )
            .small()
            .weak(),
        );
        if paid {
            ui.label(
                RichText::new("Daily checks run at 9:30 each morning.")
                    .small()
                    .color(Color32::GRAY),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Scheduled checks are part of Gorse Pro.")
                        .small()
                        .weak(),
                );
                if ui.link(RichText::new("See pricing").small()).clicked() {
                    open_url(PRICING_URL);
                }
            });
        }
        if s.untrusted() {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(UNTRUSTED)
                        .small()
                        .color(severity_color("critical")),
                );
                if ui.link(RichText::new("Download Gorse").small()).clicked() {
                    open_url(DOWNLOAD_URL);
                }
            });
        }
        if let Some(w) = s.status.as_ref().filter(|_| s.is_on()).and_then(warning) {
            ui.label(RichText::new(format!("⚠ {w}")).small().color(AMBER));
        }
        if let Some(e) = &s.error {
            ui.add(
                egui::Label::new(RichText::new(e).small().color(severity_color("critical"))).wrap(),
            );
        }
        let now = now_unix();
        ui.horizontal(
            |ui| match s.status.as_ref().and_then(|st| st.last_run.as_ref()) {
                Some(run) => {
                    let attention =
                        matches!(run.outcome(), Outcome::Failed | Outcome::Incomplete { .. });
                    let line = RichText::new(last_run_line(run, now)).small();
                    ui.label(if attention {
                        line.color(AMBER)
                    } else {
                        line.weak()
                    });
                    if run.outcome() == Outcome::Failed {
                        if let Some(m) = &run.message {
                            ui.add(
                                egui::Label::new(RichText::new(m).small().color(Color32::GRAY))
                                    .truncate(),
                            );
                        }
                    }
                }
                None => {
                    ui.label(RichText::new("Not run yet").small().color(Color32::GRAY));
                }
            },
        );
        let count = s.status.as_ref().map_or(0, |st| st.history_count);
        let title = if count > 0 {
            format!("History ({count})")
        } else {
            "History".to_string()
        };
        let resp = egui::CollapsingHeader::new(RichText::new(title).small())
            .id_salt("schedule-history")
            .show(ui, |ui| {
                if !s.history_loaded {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Loading…").small().weak());
                    });
                } else if s.history.is_empty() {
                    ui.label(
                        RichText::new(
                            "No checks recorded yet. Run the Fast Scan, or turn on a schedule.",
                        )
                        .small()
                        .weak(),
                    );
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt("schedule-history-list")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            for run in &s.history {
                                history_row(ui, run, now);
                            }
                        });
                }
            });
        if resp.body_returned.is_some() && !s.history_loaded {
            s.load_history();
        }
        ui.add_space(6.0);
    }
}

fn history_row(ui: &mut egui::Ui, run: &Run, now: i64) {
    ui.horizontal(|ui| {
        let (relative, exact) = run.when(now);
        ui.add_sized([120.0, 16.0], egui::Label::new(RichText::new(relative).small()).truncate())
            .on_hover_text(exact);
        match run.outcome() {
            Outcome::Incomplete { .. } => {
                ui.label(
                    RichText::new(run.incomplete_summary().unwrap_or_else(|| "incomplete".into()))
                        .small()
                        .color(AMBER),
                )
                .on_hover_text("This check could not read every location, so it is not a clean result. Anything it did find is shown.");
                severity_badges(ui, run);
            }
            Outcome::Failed => {
                ui.label(RichText::new("did not complete").small().color(AMBER));
            }
            Outcome::Findings(_) => severity_badges(ui, run),
            Outcome::Clean => {
                ui.label(RichText::new("no findings").small().weak());
            }
            Outcome::Unknown => {
                ui.label(RichText::new("result unknown").small().weak());
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(t) = &run.trigger {
                ui.label(RichText::new(t).small().color(Color32::GRAY));
            }
            let attention = run.unassessed > 0 || run.incomplete == Some(true);
            let changes = RichText::new(run.changes_line()).small();
            let l = ui.label(if attention { changes.color(AMBER) } else { changes.weak() });
            if run.unassessed > 0 {
                l.on_hover_text("Not assessed: earlier findings this run could not look at again. They may still be present.");
            }
        });
    });
}

fn severity_badges(ui: &mut egui::Ui, run: &Run) {
    let Some(c) = &run.counts else { return };
    for (name, n) in [
        ("critical", c.critical),
        ("high", c.high),
        ("medium", c.medium),
        ("low", c.low),
    ] {
        if n > 0 {
            badge(ui, name);
            ui.label(RichText::new(n.to_string()).small().weak());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parses_leniently() {
        let s = parse_status(br#"{"frequency":"Daily","installed":true,"platform":"windows",
            "program":"C:\\Gorse\\gorse-cli.exe","program_exists":true,"licensed":true,
            "history_count":4,"program_trusted":true,"program_team_id":null,"program_in_applications":true,
            "last_run":{"at":"2026-11-03T09:30:00Z","ok":true,"incomplete":false,"coverage_failures":0,
              "trigger":"scheduled","counts":{"critical":1,"high":2,"medium":0,"low":3},
              "new":2,"worsened":1,"resolved":0,"improved":0,"unassessed":0,"message":"ok"}}"#)
        .unwrap();
        assert_eq!(s.frequency, "daily");
        assert_eq!(s.history_count, 4);
        assert_eq!(s.program_trusted, Some(true));
        let run = s.last_run.clone().unwrap();
        assert_eq!(run.total(), 6);
        assert_eq!(run.outcome(), Outcome::Findings(6));
        let now = parse_rfc3339("2026-11-03T12:31:00Z").unwrap();
        assert_eq!(
            last_run_line(&run, now),
            "Last check: 3 hours ago · 6 findings · 2 new / 1 worsened"
        );
        assert_eq!(warning(&s), None);

        let off = parse_status(br#"{"frequency":"weekly","last_run":null,"counts":"x"}"#).unwrap();
        assert_eq!(off.frequency, "off");
        assert!(off.last_run.is_none());
        assert!(parse_status(br#"{"error":"nope"}"#).is_none());
        assert!(parse_status(b"").is_none());

        let broken =
            parse_status(br#"{"frequency":"hourly","installed":false,"program_exists":false}"#)
                .unwrap();
        assert_eq!(
            warning(&broken),
            Some("Gorse moved. Choose a frequency again to repair the schedule.")
        );
        let missing =
            parse_status(br#"{"frequency":"hourly","installed":false,"program_exists":true}"#)
                .unwrap();
        assert_eq!(
            warning(&missing),
            Some("The schedule is not installed. Choose a frequency again.")
        );
    }

    #[test]
    fn incomplete_runs_never_read_as_clean() {
        let run = Run::from_value(&serde_json::json!({
            "at": "2026-11-03T09:30:00Z", "ok": true, "incomplete": true,
            "coverage_failures": 1, "counts": {"critical": 0, "high": 2},
            "changes": {"counts": {"unassessed": 2}}
        }))
        .unwrap();
        assert_eq!(
            run.outcome(),
            Outcome::Incomplete {
                not_read: 1,
                not_assessed: 2
            }
        );
        assert_eq!(
            run.incomplete_summary().as_deref(),
            Some("incomplete: 1 location not read · 2 not assessed")
        );
        let now = parse_rfc3339("2026-11-03T09:30:30Z").unwrap();
        assert_eq!(
            last_run_line(&run, now),
            "Last check: just now · incomplete: 1 location not read · 2 not assessed · 2 findings so far"
        );
        assert_eq!(run.changes_line(), "+0 new, 0 worsened, 0 resolved");

        let failed =
            Run::from_value(&serde_json::json!({"ok": false, "message": "licence required"}))
                .unwrap();
        assert_eq!(failed.outcome(), Outcome::Failed);
        assert_eq!(last_run_line(&failed, 0), "Last check · did not complete");
        let unknown = Run::from_value(&serde_json::json!({"at": "x"})).unwrap();
        assert_eq!(unknown.outcome(), Outcome::Unknown);
        assert_eq!(unknown.when(0).0, "x");
        let clean =
            Run::from_value(&serde_json::json!({"incomplete": false, "unassessed": 1})).unwrap();
        assert_eq!(clean.outcome(), Outcome::Clean);
        assert_eq!(
            clean.changes_line(),
            "+0 new, 0 worsened, 0 resolved, 1 not assessed"
        );
        assert!(Run::from_value(&serde_json::json!("nope")).is_none());
    }

    #[test]
    fn history_and_refusals_parse() {
        let runs = parse_history(br#"{"runs":[
            {"file":"a.json","at":"2026-11-03T09:30:00Z","trigger":"manual","counts":{"critical":0,"high":0,"medium":0,"low":0},
             "new":0,"worsened":0,"resolved":1,"improved":0,"unassessed":0,"first_run":false,"incomplete":false,"coverage_failures":0},
            7,
            {"at":"2026-11-02T09:30:00Z","trigger":"scheduled","incomplete":true,"coverage_failures":2}
        ],"total":3}"#)
        .unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].outcome(), Outcome::Clean);
        assert_eq!(runs[0].trigger.as_deref(), Some("manual"));
        assert_eq!(
            runs[1].outcome(),
            Outcome::Incomplete {
                not_read: 2,
                not_assessed: 0
            }
        );
        assert!(parse_history(b"{}").is_none());
        assert_eq!(
            parse_failure(br#"{"error":"Scheduled checks are part of Gorse Pro.","upgrade_url":"https://www.gorse.is/pricing"}"#).as_deref(),
            Some("Scheduled checks are part of Gorse Pro.")
        );
        assert_eq!(parse_failure(br#"{"frequency":"off"}"#), None);
    }

    /// `schedule status --json` and `schedule history --json` captured from
    /// the real CLI (`sched.json`, `hist.json` in GORSE_CAPTURE_DIR).
    #[test]
    #[ignore]
    fn real_cli_output() {
        let dir = std::path::PathBuf::from(
            std::env::var("GORSE_CAPTURE_DIR").expect("GORSE_CAPTURE_DIR"),
        );
        let status = parse_status(&std::fs::read(dir.join("sched.json")).unwrap()).expect("status");
        println!("status: {status:?}");
        if let Some(run) = &status.last_run {
            println!("{}", last_run_line(run, now_unix()));
        }
        let runs = parse_history(&std::fs::read(dir.join("hist.json")).unwrap()).expect("history");
        assert!(!runs.is_empty());
        for r in runs.iter().take(5) {
            println!(
                "  {:?} {:?} {} {:?}",
                r.when(now_unix()),
                r.outcome(),
                r.changes_line(),
                r.trigger
            );
        }
    }
}
