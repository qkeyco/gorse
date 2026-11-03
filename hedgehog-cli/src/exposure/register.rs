// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Keeps `data/credential-locations.toml` and the code in step.
//!
//! The register records why each credential location is on the Fast Scan's
//! list (which published source cites it) and how it is covered. The code
//! decides how a location is checked. These tests fail when either side
//! changes without the other: a path added to the watch list or a discovery
//! adapter must be entered in the register with a source, and a register
//! entry marked as covered must really be checked.
#![cfg(test)]

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const REGISTER: &str = include_str!("../../data/credential-locations.toml");
const DISCOVER_SRC: &str = include_str!("discover.rs");

#[derive(Deserialize)]
struct Register {
    meta: Meta,
    #[serde(default)]
    source: Vec<Source>,
    #[serde(default)]
    location: Vec<Location>,
}

#[derive(Deserialize)]
struct Meta {
    reviewed: String,
    procedure: String,
}

#[derive(Deserialize)]
struct Source {
    id: String,
    kind: String,
    title: String,
    url: String,
    #[serde(default)]
    date: String,
    reviewed: String,
}

#[derive(Deserialize)]
struct Location {
    id: String,
    vendor: String,
    what: String,
    #[serde(default)]
    macos: Vec<String>,
    #[serde(default)]
    linux: Vec<String>,
    #[serde(default)]
    windows: Vec<String>,
    #[serde(default)]
    watched: Vec<String>,
    #[serde(default)]
    guarded: Vec<String>,
    #[serde(default)]
    discovered: bool,
    status: String,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    pattern: bool,
    #[serde(default)]
    note: String,
}

const STATUS: &[&str] = &["covered", "gap", "excluded"];
const PLATFORMS: &[&str] = &["macos", "linux", "windows"];
const SOURCE_KINDS: &[&str] = &[
    "vendor-docs",
    "framework",
    "infostealer-analysis",
    "scanner",
    "incident",
    "audit-guidance",
];

fn here() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

impl Location {
    fn paths_here(&self) -> &[String] {
        match here() {
            "macos" => &self.macos,
            "windows" => &self.windows,
            _ => &self.linux,
        }
    }

    fn on(list: &[String]) -> bool {
        list.iter().any(|p| p == "all" || p == here())
    }

    fn watched_here(&self) -> bool {
        Self::on(&self.watched)
    }

    fn guarded_here(&self) -> bool {
        Self::on(&self.guarded)
    }

    /// The literals a discovery adapter is expected to contain.
    fn discovery_literals(&self) -> Vec<String> {
        if let Some(code) = &self.code {
            return vec![code.clone()];
        }
        self.macos
            .iter()
            .chain(self.linux.iter())
            .map(|p| p.trim_start_matches("~/").to_string())
            .collect()
    }
}

fn load() -> Register {
    toml::from_str(REGISTER).expect("data/credential-locations.toml parses")
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .expect("a home directory")
}

/// Expand `~`, `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%` and
/// `%ProgramData%` and normalise separators so paths compare the same on
/// every platform.
fn expand(path: &str) -> String {
    let mut s = path.to_string();
    if let Some(rest) = s.strip_prefix("~/") {
        s = format!("{}/{}", home().display(), rest);
    } else if s == "~" {
        s = home().display().to_string();
    }
    // The engine resolves the profile the same way `home()` does (HOME, then
    // USERPROFILE), so the register must too, or a runner that sets both to
    // different values would fail here for no real reason.
    if s.starts_with("%USERPROFILE%") {
        s = s.replacen("%USERPROFILE%", &home().display().to_string(), 1);
    }
    for (var, name, default) in [
        ("%APPDATA%", "APPDATA", "AppData/Roaming"),
        ("%LOCALAPPDATA%", "LOCALAPPDATA", "AppData/Local"),
    ] {
        if s.starts_with(var) {
            let value =
                std::env::var(name).unwrap_or_else(|_| format!("{}/{}", home().display(), default));
            s = s.replacen(var, &value, 1);
        }
    }
    if s.starts_with("%ProgramData%") {
        let value = std::env::var("ProgramData").unwrap_or_else(|_| "C:/ProgramData".to_string());
        s = s.replacen("%ProgramData%", &value, 1);
    }
    normalise(Path::new(&s))
}

fn normalise(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string()
}

fn watch_list() -> BTreeSet<String> {
    crate::credential_locations()
        .iter()
        .map(|l| normalise(&l.path))
        .collect()
}

/// True when this test build carries the platform crate whose `guarded`
/// paths the register describes. Without it the agent guard's extra paths
/// are not compiled in and cannot be checked.
fn platform_guard_compiled() -> bool {
    let platform = here();
    if platform == "macos" {
        return true;
    }
    (platform == "linux" && cfg!(feature = "linux-daemon"))
        || (platform == "windows" && cfg!(feature = "windows-daemon"))
}

fn detector() -> hedgehog_taint::secrets::SecretDetector {
    let mut d = hedgehog_taint::secrets::SecretDetector::new();
    crate::add_platform_secrets(&mut d);
    d
}

#[test]
fn register_is_well_formed() {
    let reg = load();
    assert!(
        reg.meta.reviewed.len() == 10,
        "meta.reviewed must be a YYYY-MM-DD date"
    );
    let procedure = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(&reg.meta.procedure);
    assert!(
        procedure.exists(),
        "meta.procedure points at a missing file: {}",
        procedure.display()
    );

    let mut source_ids = BTreeSet::new();
    for s in &reg.source {
        assert!(
            source_ids.insert(s.id.as_str()),
            "duplicate source id {}",
            s.id
        );
        assert!(
            SOURCE_KINDS.contains(&s.kind.as_str()),
            "source {} has unknown kind {}",
            s.id,
            s.kind
        );
        assert!(
            !s.title.is_empty() && !s.url.is_empty(),
            "source {} needs title and url",
            s.id
        );
        assert!(
            s.reviewed.len() == 10,
            "source {} needs a reviewed date",
            s.id
        );
        let _ = &s.date;
    }

    let mut ids = BTreeSet::new();
    for l in &reg.location {
        assert!(ids.insert(l.id.as_str()), "duplicate location id {}", l.id);
        assert!(
            STATUS.contains(&l.status.as_str()),
            "location {} has unknown status {}",
            l.id,
            l.status
        );
        for p in l.watched.iter().chain(l.guarded.iter()) {
            assert!(
                p == "all" || PLATFORMS.contains(&p.as_str()),
                "location {} lists unknown platform {}",
                l.id,
                p
            );
        }
        let checked = !l.watched.is_empty() || !l.guarded.is_empty() || l.discovered;
        match l.status.as_str() {
            "covered" => assert!(checked, "location {} is covered by nothing", l.id),
            _ => assert!(
                !checked,
                "location {} is {} but claims to be watched, guarded or discovered",
                l.id, l.status
            ),
        }
        assert!(
            !l.vendor.is_empty() && !l.what.is_empty(),
            "location {} needs vendor and what",
            l.id
        );
        assert!(
            !l.sources.is_empty(),
            "location {} cites no source; every entry must say where it came from",
            l.id
        );
        for s in &l.sources {
            assert!(
                source_ids.contains(s.as_str()),
                "location {} cites unknown source {}",
                l.id,
                s
            );
        }
        if !l.pattern {
            assert!(
                !(l.macos.is_empty() && l.linux.is_empty() && l.windows.is_empty()),
                "location {} has no paths",
                l.id
            );
        }
        if l.status == "excluded" {
            assert!(
                !l.note.is_empty(),
                "excluded location {} must say why in note",
                l.id
            );
        }
    }
}

#[test]
fn every_watched_entry_is_on_the_watch_list_and_vice_versa() {
    let reg = load();
    let watched = watch_list();

    let mut missing = Vec::new();
    let mut claimed: BTreeMap<String, &str> = BTreeMap::new();
    for l in reg.location.iter().filter(|l| !l.pattern) {
        for p in l.paths_here() {
            let full = expand(p);
            if l.watched_here() {
                if !watched.contains(&full) {
                    missing.push(format!("{} ({})", l.id, p));
                }
                claimed.insert(full, &l.id);
            } else if watched.contains(&full) {
                missing.push(format!(
                    "{} ({}) is on the watch list but the register does not say watched on {}",
                    l.id,
                    p,
                    here()
                ));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "register and watch list disagree on {}:\n  {}",
        here(),
        missing.join("\n  ")
    );

    let unregistered: Vec<_> = watched
        .iter()
        .filter(|p| !claimed.contains_key(*p))
        .cloned()
        .collect();
    assert!(
        unregistered.is_empty(),
        "watch-list paths with no register entry on {} (add them to data/credential-locations.toml with a source):\n  {}",
        here(),
        unregistered.join("\n  ")
    );
}

#[test]
fn every_discovered_entry_has_an_adapter() {
    let reg = load();
    let mut missing = Vec::new();
    for l in reg.location.iter().filter(|l| l.discovered) {
        for lit in l.discovery_literals() {
            if !DISCOVER_SRC.contains(&lit) {
                missing.push(format!("{} expects discover.rs to read {:?}", l.id, lit));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "register entries marked discovered with no matching adapter literal:\n  {}",
        missing.join("\n  ")
    );
    for l in reg.location.iter().filter(|l| !l.discovered && !l.pattern) {
        if let Some(code) = &l.code {
            assert!(
                !DISCOVER_SRC.contains(code),
                "{} says it is not discovered but discover.rs reads {:?}",
                l.id,
                code
            );
        }
    }
}

#[test]
fn guarded_entries_are_known_to_the_agent_guard() {
    let reg = load();
    if !platform_guard_compiled() {
        eprintln!(
            "skipping: the {} platform crate is not compiled into this test build",
            here()
        );
        return;
    }
    let d = detector();
    let mut wrong = Vec::new();
    for l in reg.location.iter().filter(|l| !l.pattern) {
        for p in l.paths_here() {
            let full = expand(p);
            let known = d.is_secret(Path::new(&full));
            let should = l.watched_here() || l.guarded_here();
            if should && !known {
                wrong.push(format!("{} ({}) is not treated as a secret path", l.id, p));
            }
            if !should && known && l.status != "covered" {
                wrong.push(format!(
                    "{} ({}) is a {} but the agent guard already knows it",
                    l.id, p, l.status
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "register and agent guard disagree on {}:\n  {}",
        here(),
        wrong.join("\n  ")
    );
}
