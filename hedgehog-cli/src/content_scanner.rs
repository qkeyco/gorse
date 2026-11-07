// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Content-based secret scanner — file I/O and directory walking.
//!
//! Reads files in common locations (Desktop, Documents, Downloads, Pictures)
//! and runs content pattern matching to find exposed secrets, API keys,
//! seed phrases, credit cards, and other sensitive data.
//!
//! Uses `hedgehog_taint::content_patterns` for pure matching logic.
//! This module handles all file I/O, binary detection, and skip logic.

use hedgehog_taint::content_patterns::{self, Confidence, ContentFinding, LineContext, Severity};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

/// Configuration for content scanning.
pub struct ScanConfig {
    /// Maximum file size to scan (bytes). Files larger than this are skipped.
    pub max_file_size: u64,
    /// Whether to scan image filenames for suspicious keywords.
    pub scan_images: bool,
    /// Also descend into folders the default rules skip (dependency, VCS and
    /// build-output folders, hidden folders, app bundles). Every file inside
    /// is still subject to the same per-file limits.
    pub include_skipped: bool,
    /// Folders a stopped scan already finished: skipped when it resumes.
    pub done_dirs: Option<Arc<std::collections::HashSet<PathBuf>>>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // 4 MB: large enough for exported CSVs, logs, JSON dumps and
            // long notes, where pasted credentials turn up. Raised from 1 MB
            // once matching ran in parallel and numeric lines got a fast
            // path; bigger files are counted as a gap, never silently.
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            scan_images: true,
            include_skipped: false,
            done_dirs: None,
        }
    }
}

/// Default per-file size limit for the deep scan (4 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 4 * 1_048_576;

/// How deep `ScanEvent::DirDone` is reported: every level the scan reads,
/// so a scan stopped inside one big folder still resumes from close by.
/// Callers keep the list short by dropping folders inside finished ones.
pub const DIR_DONE_DEPTH: usize = MAX_SCAN_DEPTH;

/// Government classification and dissemination markings (TOP SECRET,
/// SECRET, CONFIDENTIAL, CUI, NOFORN, ORCON, REL TO, portion marks) are
/// detected silently: the guard may protect the file, but the finding is
/// never shown, written to JSON or uploaded (policy since 2026-02-11).
/// Commercial and export-control markings stay visible.
pub fn is_silent(finding: &ContentFinding) -> bool {
    finding.secret_type.is_government_classification()
}

/// A finding tied to a specific file path.
#[derive(Debug)]
pub struct ScanResult {
    pub path: PathBuf,
    pub finding: ContentFinding,
}

// ---------------------------------------------------------------------------
// Coverage — what a scan did and did not look at
// ---------------------------------------------------------------------------

/// How many example paths a coverage summary keeps per reason.
const COVERAGE_EXAMPLES: usize = 5;
/// How many extension / folder names a coverage summary lists.
const COVERAGE_TOP_NAMES: usize = 8;

/// A name with an occurrence count (an extension or a folder name).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NamedCount {
    pub name: String,
    pub count: usize,
}

/// A file or folder the scanner could not read, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UnreadableEntry {
    pub path: String,
    pub reason: String,
}

/// Everything a scan did not check, by reason. `complete` is true only when
/// every entry under the scanned roots was read and checked: nothing was
/// skipped for a reason the user did not choose, no limit was hit and no
/// read error occurred. The deliberate folder rules (dependency, VCS and
/// build output) still count as gaps; they are reported by name so the user
/// can decide whether they matter.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ScanCoverage {
    /// Strict: true only when every file was read and nothing was skipped
    /// for any reason, including file types this scanner cannot read.
    pub complete: bool,
    /// True when something the user would expect to be checked was not:
    /// permission denied, skipped folders, oversize files, interruption,
    /// budgets. Binary file types the scanner never reads (PDFs, images,
    /// archives) do not count as a gap; they are reported as notes.
    pub has_gaps: bool,
    pub interrupted: bool,
    /// Files whose contents (or, for images, file names) were checked.
    pub files_scanned: usize,
    /// Files not read because their type is binary or their contents were
    /// not text (known binary extensions, or sniffed binary / non-UTF-8).
    pub files_skipped_by_type: usize,
    /// Most common extensions among `files_skipped_by_type`.
    pub skipped_types: Vec<NamedCount>,
    /// Folders not entered because a skip rule matched their name.
    pub dirs_skipped_by_rule: usize,
    /// Most common folder names among `dirs_skipped_by_rule`.
    pub skipped_dirs: Vec<NamedCount>,
    /// Files and folders that could not be opened or read.
    pub files_unreadable: usize,
    pub permission_denied: usize,
    pub other_read_errors: usize,
    pub unreadable_examples: Vec<UnreadableEntry>,
    /// Files larger than `size_limit_bytes`.
    pub files_over_size_limit: usize,
    pub size_limit_bytes: u64,
    pub oversize_examples: Vec<String>,
    /// Folders nested deeper than the scanner follows.
    pub dirs_beyond_depth_limit: usize,
    /// Entries skipped for another reason (not a regular file, hard link).
    pub files_skipped_other: usize,
    pub other_skip_examples: Vec<String>,
    /// A scan-wide budget that stopped the scan early, if any.
    pub limit_reached: Option<String>,
    /// Image files seen under the scanned roots.
    pub images_seen: usize,
    /// Image files whose contents were not read (OCR unavailable, not
    /// attempted, or over the OCR cap). Their names were still checked.
    pub images_content_not_checked: usize,
    pub image_ocr_cap_reached: bool,
    #[serde(skip)]
    type_counts: BTreeMap<String, usize>,
    #[serde(skip)]
    dir_counts: BTreeMap<String, usize>,
}

impl ScanCoverage {
    pub fn new(config: &ScanConfig) -> Self {
        Self {
            complete: true,
            size_limit_bytes: config.max_file_size,
            ..Default::default()
        }
    }

    pub fn record_scanned(&mut self) {
        self.files_scanned += 1;
    }

    pub fn record_image_scanned(&mut self) {
        self.files_scanned += 1;
        self.images_seen += 1;
    }

    pub fn record_skipped_type(&mut self, label: &str) {
        self.files_skipped_by_type += 1;
        *self.type_counts.entry(label.to_string()).or_default() += 1;
    }

    pub fn record_skipped_dir(&mut self, name: &str) {
        self.dirs_skipped_by_rule += 1;
        *self.dir_counts.entry(name.to_string()).or_default() += 1;
    }

    pub fn record_unreadable(&mut self, path: &Path, error: &std::io::Error) {
        let denied = error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(libc_eacces());
        let reason = if denied {
            "permission denied".to_string()
        } else {
            io_reason(error)
        };
        self.record_read_error_with(path, reason, denied);
    }

    pub fn record_read_error(&mut self, path: &Path, reason: &str) {
        self.record_read_error_with(path, reason.to_string(), false);
    }

    fn record_read_error_with(&mut self, path: &Path, reason: String, denied: bool) {
        self.files_unreadable += 1;
        if denied {
            self.permission_denied += 1;
        } else {
            self.other_read_errors += 1;
        }
        if self.unreadable_examples.len() < COVERAGE_EXAMPLES {
            self.unreadable_examples.push(UnreadableEntry {
                path: path.display().to_string(),
                reason,
            });
        }
    }

    pub fn record_oversize(&mut self, path: &Path) {
        self.files_over_size_limit += 1;
        if self.oversize_examples.len() < COVERAGE_EXAMPLES {
            self.oversize_examples.push(path.display().to_string());
        }
    }

    pub fn record_depth_limit(&mut self) {
        self.dirs_beyond_depth_limit += 1;
    }

    pub fn record_skipped_other(&mut self, path: &Path, reason: &str) {
        self.files_skipped_other += 1;
        if self.other_skip_examples.len() < COVERAGE_EXAMPLES {
            self.other_skip_examples
                .push(format!("{} ({reason})", path.display()));
        }
    }

    pub fn record_limit(&mut self, reason: &str) {
        if self.limit_reached.is_none() {
            self.limit_reached = Some(reason.to_string());
        }
    }

    /// Fold another root's coverage into this one.
    pub fn merge(&mut self, other: ScanCoverage) {
        self.interrupted |= other.interrupted;
        self.has_gaps |= other.has_gaps;
        self.files_scanned += other.files_scanned;
        self.files_skipped_by_type += other.files_skipped_by_type;
        self.dirs_skipped_by_rule += other.dirs_skipped_by_rule;
        self.files_unreadable += other.files_unreadable;
        self.permission_denied += other.permission_denied;
        self.other_read_errors += other.other_read_errors;
        self.files_over_size_limit += other.files_over_size_limit;
        self.size_limit_bytes = self.size_limit_bytes.max(other.size_limit_bytes);
        self.dirs_beyond_depth_limit += other.dirs_beyond_depth_limit;
        self.files_skipped_other += other.files_skipped_other;
        self.images_seen += other.images_seen;
        self.images_content_not_checked += other.images_content_not_checked;
        self.image_ocr_cap_reached |= other.image_ocr_cap_reached;
        if self.limit_reached.is_none() {
            self.limit_reached = other.limit_reached;
        }
        for (name, count) in other.type_counts {
            *self.type_counts.entry(name).or_default() += count;
        }
        for (name, count) in other.dir_counts {
            *self.dir_counts.entry(name).or_default() += count;
        }
        extend_capped(&mut self.unreadable_examples, other.unreadable_examples);
        extend_capped(&mut self.oversize_examples, other.oversize_examples);
        extend_capped(&mut self.other_skip_examples, other.other_skip_examples);
        self.finalize();
    }

    /// Recompute the derived fields (`complete`, top names). Call after the
    /// last record and after every merge.
    pub fn finalize(&mut self) {
        self.skipped_types = top_names(&self.type_counts);
        self.skipped_dirs = top_names(&self.dir_counts);
        self.has_gaps = self.interrupted
            || self.dirs_skipped_by_rule > 0
            || self.files_unreadable > 0
            || self.files_over_size_limit > 0
            || self.dirs_beyond_depth_limit > 0
            || self.files_skipped_other > 0
            || self.limit_reached.is_some()
            || self.image_ocr_cap_reached;
        self.complete = !self.interrupted
            && self.files_skipped_by_type == 0
            && self.dirs_skipped_by_rule == 0
            && self.files_unreadable == 0
            && self.files_over_size_limit == 0
            && self.dirs_beyond_depth_limit == 0
            && self.files_skipped_other == 0
            && self.limit_reached.is_none()
            && self.images_content_not_checked == 0
            && !self.image_ocr_cap_reached;
    }

    /// Files under the scanned roots that were not checked. Folders skipped
    /// by rule are not expanded, so their contents are not in this number.
    pub fn files_not_checked(&self) -> usize {
        self.files_skipped_by_type
            + self.files_unreadable
            + self.files_over_size_limit
            + self.files_skipped_other
            + self.images_content_not_checked
    }

    /// Plain-English notes about files the scanner never reads by design
    /// (binary types, pictures). Shown under a clean result; not gaps.
    pub fn note_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.files_skipped_by_type > 0 {
            lines.push(format!(
                "{} of a type this scanner does not read{}",
                plural_is(self.files_skipped_by_type, "file"),
                join_named(&self.skipped_types)
            ));
        }
        if self.images_content_not_checked > 0 {
            lines.push(format!(
                "{} checked by file name only, not by the text inside",
                plural_was(self.images_content_not_checked, "image")
            ));
        }
        lines
    }

    /// Plain-English reasons for the gaps, one per line, for the CLI. `home`
    /// is replaced by `~` in example paths.
    pub fn gap_lines(&self, home: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let short = |p: &str| shorten_path(Path::new(p), home);
        if self.permission_denied > 0 {
            let examples: Vec<String> = self
                .unreadable_examples
                .iter()
                .filter(|e| e.reason == "permission denied")
                .map(|e| short(&e.path))
                .collect();
            lines.push(format!(
                "{} could not be read (permission denied){}",
                plural(self.permission_denied, "file"),
                join_examples(&examples)
            ));
        }
        if self.other_read_errors > 0 {
            let examples: Vec<String> = self
                .unreadable_examples
                .iter()
                .filter(|e| e.reason != "permission denied")
                .map(|e| format!("{} ({})", short(&e.path), e.reason))
                .collect();
            lines.push(format!(
                "{} could not be read{}",
                plural(self.other_read_errors, "file or folder"),
                join_examples(&examples)
            ));
        }
        if self.files_over_size_limit > 0 {
            let examples: Vec<String> = self.oversize_examples.iter().map(|p| short(p)).collect();
            lines.push(format!(
                "{} larger than the {} limit{}",
                plural_is(self.files_over_size_limit, "file"),
                human_size(self.size_limit_bytes),
                join_examples(&examples)
            ));
        }
        if self.files_skipped_by_type > 0 {
            lines.push(format!(
                "{} of a type this scanner does not read{}",
                plural_is(self.files_skipped_by_type, "file"),
                join_named(&self.skipped_types)
            ));
        }
        if self.images_content_not_checked > 0 {
            lines.push(format!(
                "{} checked by file name only, not by the text inside",
                plural_was(self.images_content_not_checked, "image")
            ));
        }
        if self.image_ocr_cap_reached {
            lines.push(format!(
                "the image text (OCR) cap of {OCR_MAX_IMAGES} images was reached"
            ));
        }
        if self.files_skipped_other > 0 {
            lines.push(format!(
                "{} skipped (not a regular file){}",
                plural_was(self.files_skipped_other, "entry"),
                join_examples(&self.other_skip_examples)
            ));
        }
        if self.dirs_skipped_by_rule > 0 {
            lines.push(format!(
                "{} skipped by rule and not counted above{}",
                plural_was(self.dirs_skipped_by_rule, "folder"),
                join_named(&self.skipped_dirs)
            ));
        }
        if self.dirs_beyond_depth_limit > 0 {
            lines.push(format!(
                "{} nested deeper than {} levels and not entered",
                plural_was(self.dirs_beyond_depth_limit, "folder"),
                MAX_SCAN_DEPTH
            ));
        }
        if let Some(limit) = &self.limit_reached {
            lines.push(format!("the scan stopped early: {limit}"));
        }
        if self.interrupted {
            lines.push("the scan was interrupted before it finished".to_string());
        }
        lines
    }
}

fn libc_eacces() -> i32 {
    #[cfg(unix)]
    {
        libc::EACCES
    }
    #[cfg(not(unix))]
    {
        5
    }
}

fn io_reason(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "vanished during the scan".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => {
            let text = error.to_string();
            match text.split(" (os error").next() {
                Some(head) if !head.is_empty() => head.to_string(),
                _ => text,
            }
        }
    }
}

fn extend_capped<T>(target: &mut Vec<T>, extra: Vec<T>) {
    for item in extra {
        if target.len() >= COVERAGE_EXAMPLES {
            break;
        }
        target.push(item);
    }
}

fn top_names(counts: &BTreeMap<String, usize>) -> Vec<NamedCount> {
    let mut names: Vec<NamedCount> = counts
        .iter()
        .map(|(name, count)| NamedCount {
            name: name.clone(),
            count: *count,
        })
        .collect();
    names.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    names.truncate(COVERAGE_TOP_NAMES);
    names
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

fn plural_is(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun} is")
    } else {
        format!("{n} {noun}s are")
    }
}

fn plural_was(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun} was")
    } else if noun == "entry" {
        format!("{n} entries were")
    } else {
        format!("{n} {noun}s were")
    }
}

fn join_examples(examples: &[String]) -> String {
    if examples.is_empty() {
        String::new()
    } else {
        format!(": {}", examples.join(", "))
    }
}

fn join_named(names: &[NamedCount]) -> String {
    if names.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = names
        .iter()
        .map(|n| {
            if n.count > 1 {
                format!("{} \u{d7}{}", n.name, n.count)
            } else {
                n.name.clone()
            }
        })
        .collect();
    format!(" ({})", parts.join(", "))
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1_048_576 && bytes % 1_048_576 == 0 {
        format!("{} MB", bytes / 1_048_576)
    } else if bytes >= 1024 && bytes % 1024 == 0 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{bytes} bytes")
    }
}

/// Label used to group a file that was not read, by its type.
fn type_label(path: &Path) -> String {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if !ext.is_empty() {
            return ext.to_lowercase();
        }
    }
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) if name.starts_with('.') && name.len() > 1 => name[1..].to_string(),
        _ => "(no extension)".to_string(),
    }
}

/// Image file extensions (filename-only heuristic).
const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "heic", "webp", "gif", "bmp", "tiff"];

/// Extensions that are always binary and never hold checkable text. Every
/// other file is read and content-sniffed, so backup copies (`.bak`,
/// `.backup`, `.old`, `.orig`, `name~`), editor files and extensionless
/// files are scanned like any text file.
#[rustfmt::skip]
const BINARY_EXTENSIONS: &[&str] = &[
    // Documents and archives
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pages", "numbers", "odt", "ods", "odp",
    "epub", "mobi", "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "tar", "dmg", "pkg", "iso",
    "jar", "war", "deb", "rpm", "msi", "cab", "zst", "lz4",
    // Media
    "mp3", "mp4", "m4a", "m4v", "mov", "avi", "mkv", "wav", "flac", "aac", "ogg", "webm", "wmv",
    "aiff", "mid",
    // Executables and libraries
    "exe", "dll", "so", "dylib", "o", "a", "lib", "class", "pyc", "pyo", "wasm",
    // Fonts
    "ttf", "otf", "woff", "woff2", "eot",
    // Images not covered by the filename heuristic
    "psd", "ai", "ico", "icns", "raw", "cr2", "nef", "dng", "sketch", "fig", "xcf",
    // Databases, 3D assets, disk images
    "sqlite", "sqlite3", "mdb", "accdb", "realm", "fbx", "blend", "uasset", "umap", "glb", "stl",
    "vmdk", "vdi", "qcow2", "vhd", "vhdx",
];

/// Directories to skip during scanning. These are dependency, VCS, build
/// output, tooling and application-data trees: large, machine-generated and
/// not where a person keeps their own files. Every skip is counted and named
/// in the coverage summary, and `--include-skipped` turns the list off.
///
/// Generic user folder names (`projects`, `repos`, `GitHub`, `data`, …) were
/// removed on purpose: a person's project folders are exactly where
/// credentials live, and the per-file limits already bound the cost.
const SKIP_DIRS: &[&str] = &[
    // VCS / package managers
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    "target",
    ".npm",
    ".cargo",
    ".rustup",
    ".nvm",
    ".pyenv",
    ".rbenv",
    ".gem",
    "venv",
    ".venv",
    "site-packages",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "Pods",
    "Carthage",
    "bower_components",
    "third_party",
    "third-party",
    // Vendored Solidity libraries inside Foundry and Hardhat projects:
    // other people's code, dense with test keys and hashes.
    "forge-std",
    "ds-test",
    "solmate",
    "openzeppelin-contracts",
    "openzeppelin-contracts-upgradeable",
    "typechain-types",
    ".gradle",
    ".m2",
    ".cocoapods",
    // IDE / tooling
    ".vs",
    ".idea",
    ".eclipse",
    "obj",
    "bin",
    // macOS application data
    ".app",
    ".Trash",
    "Library",
    ".cache",
    ".local",
    // Game engine build trees (generated, binary)
    "Binaries",
    "Intermediate",
    "DerivedDataCache",
    "Engine",
    "Plugins",
    // Creative apps' auto-generated caches
    "Adobe",
    "DAZ 3D",
];

/// How many folder levels below a scan root are entered. Deep enough for
/// real project and document trees (a checkout inside `Documents/GitHub`
/// with `src/main/java/com/...` reaches 10 or more), while still bounding a
/// walk into runaway nesting. Folders beyond it are counted as a gap.
/// Was 6 until 0.4.19; raised once matching ran on several cores.
const MAX_SCAN_DEPTH: usize = 12;

/// What happened to one file during a scan.
#[derive(Debug)]
pub enum FileOutcome {
    /// Contents were read and checked.
    Scanned(Vec<ContentFinding>),
    /// An image: the file name was checked, the contents were not read.
    Image(Vec<ContentFinding>),
    /// Not read: a binary type, or sniffed as binary / non-text. The label
    /// is the extension (or a stand-in) for the coverage summary.
    SkippedType(String),
    /// Larger than the configured size limit.
    Oversize,
    /// Could not be opened or read.
    Unreadable(std::io::Error),
}

/// Scan a single file for content-based secrets. Convenience wrapper over
/// [`scan_file_outcome`] that drops the reason when nothing was checked.
#[allow(dead_code)]
pub fn scan_file(path: &Path, config: &ScanConfig) -> Vec<ContentFinding> {
    match scan_file_outcome(path, config) {
        FileOutcome::Scanned(findings) | FileOutcome::Image(findings) => findings,
        _ => Vec::new(),
    }
}

/// Decide whether a file's name marks it as binary. Images are handled
/// separately by the caller.
fn is_binary_extension(extension: &str) -> bool {
    BINARY_EXTENSIONS.contains(&extension)
}

/// Scan a single file and say what was done with it.
pub fn scan_file_outcome(path: &Path, config: &ScanConfig) -> FileOutcome {
    match scan_file_outcome_until(path, config, None) {
        Some(outcome) => outcome,
        // Unreachable without an interrupt flag; kept total for safety.
        None => FileOutcome::Scanned(Vec::new()),
    }
}

/// [`scan_file_outcome`] that gives up part-way through a large file when
/// `interrupt` is raised. `None` means the file was not fully checked and
/// must not be counted.
fn scan_file_outcome_until(
    path: &Path,
    config: &ScanConfig,
    interrupt: Option<&AtomicBool>,
) -> Option<FileOutcome> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return Some(FileOutcome::Unreadable(e)),
    };
    if metadata.len() > config.max_file_size {
        return Some(FileOutcome::Oversize);
    }

    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Image filename heuristic (don't read contents)
    if IMAGE_EXTENSIONS.contains(&extension.as_str()) {
        let mut findings = Vec::new();
        if config.scan_images {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(finding) = content_patterns::check_image_filename(filename) {
                    findings.push(finding);
                }
            }
        }
        return Some(FileOutcome::Image(findings));
    }

    if is_binary_extension(&extension) {
        return Some(FileOutcome::SkippedType(type_label(path)));
    }

    if metadata.len() == 0 {
        return Some(FileOutcome::Scanned(Vec::new()));
    }

    // Read file contents. Everything that is not a known binary type is read
    // and sniffed, whatever its name.
    let contents = match std::fs::read(path) {
        Ok(c) => c,
        Err(e) => return Some(FileOutcome::Unreadable(e)),
    };

    let override_ctx = if is_history_file(path) {
        Some(LineContext::Executed)
    } else {
        None
    };

    // D-28: UTF-16 BOM detection — decode before scanning
    if let Some(decoded) = content_patterns::decode_utf16(&contents) {
        let lines: Vec<&str> = decoded.lines().collect();
        return scan_lines(&lines, override_ctx, false, interrupt).map(FileOutcome::Scanned);
    }

    // Binary file detection: check first 512 bytes for null bytes
    let check_len = contents.len().min(512);
    if contents[..check_len].contains(&0u8) {
        return Some(FileOutcome::SkippedType(type_label(path)));
    }

    let text = match std::str::from_utf8(&contents) {
        Ok(t) => t,
        Err(_) => return Some(FileOutcome::SkippedType(type_label(path))),
    };

    let lines: Vec<&str> = text.lines().collect();
    scan_lines(&lines, override_ctx, true, interrupt).map(FileOutcome::Scanned)
}

/// How many lines are checked between looks at the interrupt flag.
const INTERRUPT_CHECK_LINES: usize = 1024;

/// Run the line, base64, (optionally) unicode-obfuscation and multi-line
/// checks over decoded text. `None` when `interrupt` was raised part-way.
fn scan_lines(
    lines: &[&str],
    override_ctx: Option<LineContext>,
    unicode_check: bool,
    interrupt: Option<&AtomicBool>,
) -> Option<Vec<ContentFinding>> {
    let stopped = || interrupt.is_some_and(|flag| flag.load(Ordering::Relaxed));
    let mut findings = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i % INTERRUPT_CHECK_LINES == 0 && stopped() {
            return None;
        }
        findings.extend(content_patterns::check_line_with_context(
            line,
            i + 1,
            override_ctx,
        ));
        findings.extend(content_patterns::check_base64_content(line, i + 1));
        if unicode_check {
            findings.extend(content_patterns::check_unicode_obfuscated(line, i + 1));
        }
    }
    if stopped() {
        return None;
    }
    findings.extend(content_patterns::check_multi_line(lines));
    Some(findings)
}

/// Check if a file path is a shell history file (findings get Executed context).
fn is_history_file(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        matches!(
            name,
            ".bash_history"
                | ".zsh_history"
                | ".sh_history"
                | ".fish_history"
                | ".node_repl_history"
                | ".python_history"
                | ".psql_history"
                | ".mysql_history"
                | ".sqlite_history"
                | ".irb_history"
        )
    } else {
        false
    }
}

/// Live callback: called for each event during scanning.
#[allow(dead_code)]
pub enum ScanEvent<'a> {
    /// Entering a new directory.
    EnterDir {
        files_scanned: usize,
        findings_count: usize,
        dir: &'a Path,
    },
    /// A new finding was discovered.
    Finding {
        files_scanned: usize,
        findings_count: usize,
        result: &'a ScanResult,
    },
    /// A folder (at most `DIR_DONE_DEPTH` below a root) was read in full.
    DirDone { dir: &'a Path },
}

pub type ScanCallback<'a> = &'a mut dyn FnMut(ScanEvent<'_>);

/// Checked audit coverage. Skips count omitted entries or subtrees, not every
/// file hidden inside them. A partial scan can retain findings but cannot pass.
#[derive(Debug)]
pub struct ScanReport {
    /// User-visible findings. Silent findings ([`is_silent`]) are never here.
    pub results: Vec<ScanResult>,
    /// Files that carry a government classification marking. Kept only so
    /// the guard can protect them; never print, serialise or upload these.
    pub silent_paths: Vec<PathBuf>,
    pub files_scanned: usize,
    pub complete: bool,
    pub error_count: usize,
    pub skipped_count: usize,
    /// Per-reason breakdown of `error_count` and `skipped_count`.
    pub coverage: ScanCoverage,
}

/// Audit a stable directory tree without following symbolic links. Unlike the
/// legacy convenience scan, this scans UTF text regardless of filename and does
/// not silently omit source trees, package directories or unknown extensions.
pub fn scan_directory_checked(
    dir: &Path,
    config: &ScanConfig,
    interrupt: &Arc<AtomicBool>,
    callback: Option<ScanCallback<'_>>,
) -> ScanReport {
    let mut report = ScanReport {
        results: Vec::new(),
        silent_paths: Vec::new(),
        files_scanned: 0,
        complete: true,
        error_count: 0,
        skipped_count: 0,
        coverage: ScanCoverage::new(config),
    };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    checked_audit::scan(dir, config, interrupt, callback, &mut report);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // No race-safe traversal is implemented for this platform yet.
        let _ = (config, callback);
        report.error_count = 1;
        report
            .coverage
            .record_read_error(dir, "checked audit is not available on this platform");
    }
    let interrupted = interrupt.load(Ordering::Relaxed);
    report.complete &= report.error_count == 0 && report.skipped_count == 0 && !interrupted;
    report.coverage.files_scanned = report.files_scanned;
    report.coverage.interrupted |= interrupted;
    report.coverage.finalize();
    // The checked walker records every error and skip in both counters, so
    // the two views agree; the legacy flag stays authoritative for callers.
    report.coverage.complete = report.complete;
    report
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod checked_audit {
    use super::*;
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::{File, Metadata};
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    const MAX_ENTRIES: usize = 20_000;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_FINDINGS: usize = 10_000;

    struct Budget {
        entries: usize,
        bytes: u64,
        stopped: bool,
    }

    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }

    fn open_at(parent: &File, name: &OsStr, flags: libc::c_int) -> io::Result<File> {
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in file name"))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY
                    | flags,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    /// Resolve every component through held directory descriptors. A symlink in
    /// the requested path is an error, including a symlink to a directory.
    fn open_root(path: &Path) -> io::Result<File> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut directory = File::open("/")?;
        for component in absolute.components() {
            match component {
                Component::Normal(name) => {
                    directory = open_at(&directory, name, libc::O_DIRECTORY)?;
                }
                Component::ParentDir => {
                    directory = open_at(&directory, OsStr::new(".."), libc::O_DIRECTORY)?;
                }
                Component::RootDir | Component::CurDir => {}
                Component::Prefix(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Unsupported path",
                    ));
                }
            }
        }
        Ok(directory)
    }

    fn same_object(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mode() == b.mode()
            && a.nlink() == b.nlink()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }

    fn unchanged(file: &File, before: &Metadata) -> bool {
        file.metadata()
            .is_ok_and(|after| same_object(before, &after))
    }

    fn current_entry(parent: &File, name: &OsStr, before: &Metadata) -> bool {
        open_at(parent, name, 0)
            .and_then(|file| file.metadata())
            .is_ok_and(|after| same_object(before, &after))
    }

    pub(super) fn scan(
        dir: &Path,
        config: &ScanConfig,
        interrupt: &Arc<AtomicBool>,
        mut callback: Option<ScanCallback<'_>>,
        report: &mut ScanReport,
    ) {
        if interrupt.load(Ordering::Relaxed) {
            report.complete = false;
            return;
        }
        let root = match open_root(dir) {
            Ok(root) => root,
            Err(error) => {
                report.error_count += 1;
                if error.kind() == io::ErrorKind::PermissionDenied {
                    report.coverage.record_unreadable(dir, &error);
                } else {
                    // O_NOFOLLOW turns a symlinked path component into
                    // ELOOP/ENOTDIR; say what the user can act on.
                    report.coverage.record_read_error(
                        dir,
                        "could not be opened as a plain folder path (symbolic links are not followed)",
                    );
                }
                return;
            }
        };
        let before = match root.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                report.error_count += 1;
                report.coverage.record_unreadable(dir, &error);
                return;
            }
        };
        let mut budget = Budget {
            entries: 0,
            bytes: 0,
            stopped: false,
        };
        walk(
            &root,
            dir,
            config,
            interrupt,
            &mut callback,
            report,
            &mut budget,
            0,
        );
        if !unchanged(&root, &before)
            || !open_root(dir)
                .and_then(|file| file.metadata())
                .is_ok_and(|after| same_object(&before, &after))
        {
            report.error_count += 1;
            report
                .coverage
                .record_read_error(dir, "folder changed during the scan");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        directory: &File,
        path: &Path,
        config: &ScanConfig,
        interrupt: &Arc<AtomicBool>,
        callback: &mut Option<ScanCallback<'_>>,
        report: &mut ScanReport,
        budget: &mut Budget,
        depth: usize,
    ) {
        if depth > MAX_SCAN_DEPTH {
            report.skipped_count += 1;
            report.coverage.record_depth_limit();
            return;
        }
        let duplicate = match directory.try_clone() {
            Ok(file) => file.into_raw_fd(),
            Err(error) => {
                report.error_count += 1;
                report.coverage.record_unreadable(path, &error);
                return;
            }
        };
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(duplicate) };
            report.error_count += 1;
            report.coverage.record_unreadable(path, &error);
            return;
        }
        let stream = Directory(stream);
        if let Some(cb) = callback {
            cb(ScanEvent::EnterDir {
                files_scanned: report.files_scanned,
                findings_count: report.results.len(),
                dir: path,
            });
        }
        loop {
            if interrupt.load(Ordering::Relaxed) || budget.stopped {
                report.complete = false;
                return;
            }
            // readdir distinguishes end-of-directory from errors through errno.
            unsafe {
                #[cfg(target_os = "macos")]
                {
                    *libc::__error() = 0;
                }
                #[cfg(target_os = "linux")]
                {
                    *libc::__errno_location() = 0;
                }
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    report.error_count += 1;
                    report.coverage.record_unreadable(path, &error);
                }
                return;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            budget.entries += 1;
            if budget.entries > MAX_ENTRIES {
                report.skipped_count += 1;
                report
                    .coverage
                    .record_limit(&format!("more than {MAX_ENTRIES} entries"));
                budget.stopped = true;
                return;
            }
            let name = OsStr::from_bytes(name);
            let child_path = path.join(name);
            let file = match open_at(directory, name, 0) {
                Ok(file) => file,
                Err(error) => {
                    report.error_count += 1;
                    report.coverage.record_unreadable(&child_path, &error);
                    continue;
                }
            };
            let before = match file.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.error_count += 1;
                    report.coverage.record_unreadable(&child_path, &error);
                    continue;
                }
            };
            if before.is_dir() {
                walk(
                    &file,
                    &child_path,
                    config,
                    interrupt,
                    callback,
                    report,
                    budget,
                    depth + 1,
                );
            } else if before.is_file() {
                read_file(
                    &file,
                    &before,
                    &child_path,
                    config,
                    interrupt,
                    callback,
                    report,
                    budget,
                );
            } else {
                report.skipped_count += 1;
                report
                    .coverage
                    .record_skipped_other(&child_path, "not a regular file");
            }
            if !unchanged(&file, &before) || !current_entry(directory, name, &before) {
                report.error_count += 1;
                report
                    .coverage
                    .record_read_error(&child_path, "changed during the scan");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read_file(
        file: &File,
        before: &Metadata,
        path: &Path,
        config: &ScanConfig,
        interrupt: &Arc<AtomicBool>,
        callback: &mut Option<ScanCallback<'_>>,
        report: &mut ScanReport,
        budget: &mut Budget,
    ) {
        let limit = config
            .max_file_size
            .min(MAX_FILE_BYTES)
            .min(MAX_TOTAL_BYTES.saturating_sub(budget.bytes));
        if before.nlink() != 1 {
            report.skipped_count += 1;
            report.coverage.record_skipped_other(path, "hard link");
            return;
        }
        if before.len() > limit {
            report.skipped_count += 1;
            if before.len() > config.max_file_size.min(MAX_FILE_BYTES) {
                report.coverage.record_oversize(path);
            } else {
                report
                    .coverage
                    .record_limit(&format!("more than {} MB read", MAX_TOTAL_BYTES >> 20));
            }
            return;
        }
        let mut bytes = Vec::new();
        if let Err(error) = file.take(limit + 1).read_to_end(&mut bytes) {
            report.error_count += 1;
            report.coverage.record_unreadable(path, &error);
            return;
        }
        budget.bytes += bytes.len() as u64;
        if bytes.len() as u64 > limit || budget.bytes > MAX_TOTAL_BYTES {
            report.skipped_count += 1;
            report
                .coverage
                .record_limit(&format!("more than {} MB read", MAX_TOTAL_BYTES >> 20));
            budget.stopped = true;
            return;
        }
        if !unchanged(file, before) || bytes.len() as u64 != before.len() {
            report.error_count += 1;
            report
                .coverage
                .record_read_error(path, "changed during the scan");
            return;
        }
        let text = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            content_patterns::decode_utf16(&bytes)
        } else {
            String::from_utf8(bytes).ok()
        };
        let text = match text {
            Some(text) if !text.contains('\0') => text,
            _ => {
                report.skipped_count += 1;
                report.coverage.record_skipped_type(&type_label(path));
                return;
            }
        };
        let context = is_history_file(path).then_some(LineContext::Executed);
        let lines: Vec<_> = text.lines().collect();
        let mut findings = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if interrupt.load(Ordering::Relaxed) {
                report.complete = false;
                return;
            }
            findings.extend(content_patterns::check_line_with_context(
                line,
                index + 1,
                context,
            ));
            findings.extend(content_patterns::check_base64_content(line, index + 1));
            findings.extend(content_patterns::check_unicode_obfuscated(line, index + 1));
            if findings.len() + report.results.len() > MAX_FINDINGS {
                report.skipped_count += 1;
                report
                    .coverage
                    .record_limit(&format!("more than {MAX_FINDINGS} findings"));
                budget.stopped = true;
                break;
            }
        }
        if !budget.stopped {
            findings.extend(content_patterns::check_multi_line(&lines));
            report.files_scanned += 1;
        }
        let (silent, findings): (Vec<_>, Vec<_>) = findings.into_iter().partition(is_silent);
        if !silent.is_empty() && !report.silent_paths.iter().any(|p| p == path) {
            report.silent_paths.push(path.to_path_buf());
        }
        for finding in findings
            .into_iter()
            .take(MAX_FINDINGS - report.results.len())
        {
            let result = ScanResult {
                path: path.to_path_buf(),
                finding,
            };
            if let Some(cb) = callback {
                cb(ScanEvent::Finding {
                    files_scanned: report.files_scanned,
                    findings_count: report.results.len() + 1,
                    result: &result,
                });
            }
            report.results.push(result);
        }
        if report.results.len() >= MAX_FINDINGS {
            report.skipped_count += 1;
            report
                .coverage
                .record_limit(&format!("more than {MAX_FINDINGS} findings"));
            budget.stopped = true;
        }
    }
}

/// Results of a convenience scan together with what it did not look at.
#[derive(Debug)]
pub struct ScanOutcome {
    pub results: Vec<ScanResult>,
    pub coverage: ScanCoverage,
}

/// Scan a directory recursively for content-based secrets (no progress).
pub fn scan_directory(dir: &Path, config: &ScanConfig) -> Vec<ScanResult> {
    let no_interrupt = Arc::new(AtomicBool::new(false));
    scan_directory_with_coverage(dir, config, &no_interrupt, None).results
}

/// Scan a directory recursively and report coverage: every file or folder
/// that was not checked is counted by reason.
///
/// The folders are walked on the calling thread; files are read and checked
/// on a small pool of worker threads ([`scan_workers`]). Results are put
/// back into walk order before anything is recorded, so the findings, the
/// coverage and every [`ScanEvent`] (always delivered on the calling
/// thread) come out exactly as a one-file-at-a-time scan would produce
/// them. `DirDone` for a folder is only sent once every file in it and its
/// subfolders has been checked, and never after an interrupt.
pub fn scan_directory_with_coverage(
    dir: &Path,
    config: &ScanConfig,
    interrupt: &Arc<AtomicBool>,
    callback: Option<ScanCallback<'_>>,
) -> ScanOutcome {
    let workers = scan_workers();
    let (job_tx, job_rx) = mpsc::channel::<(u64, PathBuf)>();
    let (done_tx, done_rx) = mpsc::channel::<(u64, Option<FileOutcome>)>();
    let job_rx = Mutex::new(job_rx);
    let (results, mut coverage) = std::thread::scope(|scope| {
        for _ in 0..workers {
            let done_tx = done_tx.clone();
            let job_rx = &job_rx;
            let interrupt: &AtomicBool = interrupt;
            scope.spawn(move || scan_worker(job_rx, done_tx, config, interrupt));
        }
        drop(done_tx);
        let mut pipe = ScanPipeline {
            jobs: Some(job_tx),
            done: done_rx,
            pending: VecDeque::new(),
            ready: HashMap::new(),
            next_id: 0,
            in_flight: 0,
            max_in_flight: workers * IN_FLIGHT_PER_WORKER,
            halted: false,
            config,
            interrupt,
            results: Vec::new(),
            coverage: ScanCoverage::new(config),
            callback,
        };
        scan_directory_recursive(dir, config, interrupt, &mut pipe, 0);
        pipe.finish();
        (pipe.results, pipe.coverage)
    });
    coverage.interrupted |= interrupt.load(Ordering::Relaxed);
    coverage.finalize();
    ScanOutcome { results, coverage }
}

/// Upper bound on file-checking threads. Matching is CPU-bound; beyond
/// eight threads the walk and the disk become the limit, and a scan should
/// not take over a large machine.
const MAX_SCAN_WORKERS: usize = 8;

/// Files handed to each worker that have not come back yet. Enough to keep
/// every worker busy while one slow file holds up the in-order results,
/// small enough to bound memory and keep progress events current.
const IN_FLIGHT_PER_WORKER: usize = 32;

/// How long the walker waits for a result before looking at the interrupt
/// flag again.
const RESULT_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// Threads that read and check files: one per core, leaving one core for
/// the walk and the rest of the computer, at most [`MAX_SCAN_WORKERS`].
fn scan_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .saturating_sub(1)
        .clamp(1, MAX_SCAN_WORKERS)
}

/// One worker: take a file, check it, send the outcome back. `None` means
/// the scan was interrupted before the file was fully checked.
fn scan_worker(
    jobs: &Mutex<mpsc::Receiver<(u64, PathBuf)>>,
    done: mpsc::Sender<(u64, Option<FileOutcome>)>,
    config: &ScanConfig,
    interrupt: &AtomicBool,
) {
    loop {
        let job = jobs.lock().unwrap_or_else(|e| e.into_inner()).recv();
        let Ok((id, path)) = job else {
            return;
        };
        let outcome = if interrupt.load(Ordering::Relaxed) {
            None
        } else {
            // A panic while checking one file must not hang the walker,
            // which waits for every result in order: report the file as
            // unreadable instead.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scan_file_outcome_until(&path, config, Some(interrupt))
            }))
            .unwrap_or_else(|_| {
                Some(FileOutcome::Unreadable(std::io::Error::other(
                    "could not be checked (internal error)",
                )))
            })
        };
        if done.send((id, outcome)).is_err() {
            return;
        }
    }
}

/// One step of a scan in walk order. Files are checked out of order by the
/// workers; everything is recorded in this order.
enum ScanStep {
    EnterDir(PathBuf),
    File(u64, PathBuf),
    SkippedDir(String),
    Unreadable(PathBuf, std::io::Error),
    DepthLimit,
    SkippedOther(PathBuf),
    DirDone(PathBuf),
}

/// The walker's side of a parallel scan: sends files to the workers, puts
/// their outcomes back in walk order and records them.
struct ScanPipeline<'a, 'cb> {
    jobs: Option<mpsc::Sender<(u64, PathBuf)>>,
    done: mpsc::Receiver<(u64, Option<FileOutcome>)>,
    /// Steps not yet recorded, oldest first.
    pending: VecDeque<ScanStep>,
    /// Outcomes that came back before the steps ahead of them were recorded.
    ready: HashMap<u64, Option<FileOutcome>>,
    next_id: u64,
    in_flight: usize,
    max_in_flight: usize,
    /// A file was abandoned by an interrupt: nothing after it is recorded.
    halted: bool,
    config: &'a ScanConfig,
    interrupt: &'a Arc<AtomicBool>,
    results: Vec<ScanResult>,
    coverage: ScanCoverage,
    callback: Option<ScanCallback<'cb>>,
}

impl ScanPipeline<'_, '_> {
    fn interrupted(&self) -> bool {
        self.interrupt.load(Ordering::Relaxed)
    }

    /// Queue a step that needs no worker and record whatever is ready.
    fn step(&mut self, step: ScanStep) {
        self.pending.push_back(step);
        self.collect(false);
    }

    /// Hand a file to the workers. Waits while too many are outstanding.
    fn file(&mut self, path: PathBuf) {
        let id = self.next_id;
        self.next_id += 1;
        let sent = self
            .jobs
            .as_ref()
            .is_some_and(|jobs| jobs.send((id, path.clone())).is_ok());
        if sent {
            self.in_flight += 1;
        } else {
            // No worker left (they only stop when the walk is over);
            // check the file here rather than lose it.
            let outcome = scan_file_outcome_until(&path, self.config, None);
            self.ready.insert(id, outcome);
        }
        self.pending.push_back(ScanStep::File(id, path));
        self.collect(false);
        while self.in_flight >= self.max_in_flight && !self.interrupted() {
            self.collect(true);
        }
    }

    /// Take finished outcomes (waiting up to [`RESULT_POLL`] for one when
    /// `wait` is set), then record every step that is now in order.
    fn collect(&mut self, wait: bool) {
        if wait && self.in_flight > 0 {
            match self.done.recv_timeout(RESULT_POLL) {
                Ok((id, outcome)) => {
                    self.in_flight -= 1;
                    self.ready.insert(id, outcome);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => self.in_flight = 0,
            }
        }
        while let Ok((id, outcome)) = self.done.try_recv() {
            self.in_flight -= 1;
            self.ready.insert(id, outcome);
        }
        self.record_ready();
    }

    /// Stop handing out files and record everything still outstanding.
    /// After an interrupt the workers skip what is left, so this returns
    /// at once.
    fn finish(&mut self) {
        self.jobs = None;
        while self.in_flight > 0 {
            self.collect(true);
        }
        self.record_ready();
    }

    fn record_ready(&mut self) {
        while !self.halted {
            let Some(front) = self.pending.front() else {
                return;
            };
            if let ScanStep::File(id, _) = front {
                match self.ready.remove(id) {
                    None => return,
                    Some(None) => {
                        self.halted = true;
                        self.pending.clear();
                        return;
                    }
                    Some(Some(outcome)) => {
                        let Some(ScanStep::File(_, path)) = self.pending.pop_front() else {
                            unreachable!()
                        };
                        self.record_file(path, outcome);
                    }
                }
                continue;
            }
            let Some(step) = self.pending.pop_front() else {
                return;
            };
            match step {
                ScanStep::EnterDir(dir) => {
                    if let Some(cb) = self.callback.as_mut() {
                        cb(ScanEvent::EnterDir {
                            files_scanned: self.coverage.files_scanned,
                            findings_count: self.results.len(),
                            dir: &dir,
                        });
                    }
                }
                ScanStep::SkippedDir(name) => self.coverage.record_skipped_dir(&name),
                ScanStep::Unreadable(path, error) => self.coverage.record_unreadable(&path, &error),
                ScanStep::DepthLimit => self.coverage.record_depth_limit(),
                ScanStep::SkippedOther(path) => self
                    .coverage
                    .record_skipped_other(&path, "not a regular file"),
                ScanStep::DirDone(dir) => {
                    if !self.interrupted() {
                        if let Some(cb) = self.callback.as_mut() {
                            cb(ScanEvent::DirDone { dir: &dir });
                        }
                    }
                }
                ScanStep::File(..) => unreachable!(),
            }
        }
    }

    fn record_file(&mut self, path: PathBuf, outcome: FileOutcome) {
        let findings = match outcome {
            FileOutcome::Scanned(findings) => {
                self.coverage.record_scanned();
                findings
            }
            FileOutcome::Image(findings) => {
                self.coverage.record_image_scanned();
                findings
            }
            FileOutcome::SkippedType(label) => {
                self.coverage.record_skipped_type(&label);
                return;
            }
            FileOutcome::Oversize => {
                self.coverage.record_oversize(&path);
                return;
            }
            FileOutcome::Unreadable(error) => {
                self.coverage.record_unreadable(&path, &error);
                return;
            }
        };
        for finding in findings.into_iter().filter(|f| !is_silent(f)) {
            let result = ScanResult {
                path: path.clone(),
                finding,
            };
            if let Some(cb) = self.callback.as_mut() {
                cb(ScanEvent::Finding {
                    files_scanned: self.coverage.files_scanned,
                    findings_count: self.results.len() + 1,
                    result: &result,
                });
            }
            self.results.push(result);
        }
    }
}

/// Why a folder is not entered by default. `None` means scan it.
fn dir_skip_reason(name: &str, depth: usize) -> Option<&'static str> {
    if SKIP_DIRS.contains(&name) {
        return Some("rule");
    }
    // Hidden dirs below the root (the roots themselves may be .ssh, .aws …)
    if depth > 0 && name.starts_with('.') {
        return Some("hidden");
    }
    // macOS .app bundles (e.g. "Opera GX Installer.app")
    if name.ends_with(".app") {
        return Some("app bundle");
    }
    // Browser "Save Complete Webpage" resource dirs (e.g. "Page_files")
    if name.ends_with("_files") {
        return Some("saved web page");
    }
    // Solidity/EVM build artifact dirs
    if name == "artifacts" || name == "cache" {
        return Some("build artifacts");
    }
    None
}

/// A quick count of what a deep scan of `dir` will read: files within the
/// size limit and their total bytes. Walks the same folders as the scan
/// (same depth limit and skip rules) but opens no file, so it finishes long
/// before the scan and lets the apps show a real progress bar.
pub fn estimate_scan(
    dir: &Path,
    max_file_size: u64,
    include_skipped: bool,
    interrupt: &Arc<AtomicBool>,
) -> (u64, u64) {
    fn walk(
        dir: &Path,
        limits: (u64, bool),
        interrupt: &Arc<AtomicBool>,
        depth: usize,
        acc: &mut (u64, u64),
    ) {
        if interrupt.load(Ordering::Relaxed) || depth > MAX_SCAN_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if !limits.1 {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if dir_skip_reason(name, depth).is_some() {
                            continue;
                        }
                    }
                }
                walk(&path, limits, interrupt, depth + 1, acc);
            } else if meta.is_file() && meta.len() <= limits.0 {
                acc.0 += 1;
                acc.1 += meta.len();
            }
        }
    }
    let mut acc = (0, 0);
    walk(
        dir,
        (max_file_size, include_skipped),
        interrupt,
        0,
        &mut acc,
    );
    acc
}

/// Walk one folder in the same order and with the same rules as always,
/// handing its files to the pipeline.
fn scan_directory_recursive(
    dir: &Path,
    config: &ScanConfig,
    interrupt: &Arc<AtomicBool>,
    pipe: &mut ScanPipeline<'_, '_>,
    depth: usize,
) {
    if interrupt.load(Ordering::Relaxed) {
        return;
    }
    if depth > MAX_SCAN_DEPTH {
        pipe.step(ScanStep::DepthLimit);
        return;
    }
    if config
        .done_dirs
        .as_ref()
        .is_some_and(|done| done.contains(dir))
    {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(error) => {
            pipe.step(ScanStep::Unreadable(dir.to_path_buf(), error));
            return;
        }
    };

    pipe.step(ScanStep::EnterDir(dir.to_path_buf()));

    for entry in entries {
        if interrupt.load(Ordering::Relaxed) {
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                pipe.step(ScanStep::Unreadable(dir.to_path_buf(), error));
                continue;
            }
        };

        let path = entry.path();

        if path.is_dir() {
            if !config.include_skipped {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if dir_skip_reason(name, depth).is_some() {
                        pipe.step(ScanStep::SkippedDir(name.to_string()));
                        continue;
                    }
                }
            }
            scan_directory_recursive(&path, config, interrupt, pipe, depth + 1);
        } else if path.is_file() {
            pipe.file(path);
        } else {
            // Broken symlink, socket, FIFO or device: nothing to read.
            pipe.step(ScanStep::SkippedOther(path));
        }
    }
    if depth <= DIR_DONE_DEPTH && !interrupt.load(Ordering::Relaxed) {
        // Recorded (and sent) only after every file queued before it.
        pipe.step(ScanStep::DirDone(dir.to_path_buf()));
    }
}

/// Return directories to scan for `--deep` mode in smart priority order.
///
/// Phase 1 — Dotfiles at $HOME (where most secrets actually live)
/// Phase 2 — Common dumping grounds (Desktop, Downloads, Documents)
/// Phase 3 — Media (Pictures, for filename heuristic)
pub fn smart_scan_dirs() -> Vec<PathBuf> {
    match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        Ok(h) => smart_scan_dirs_in(Path::new(&h)),
        Err(_) => Vec::new(),
    }
}

fn smart_scan_dirs_in(home: &Path) -> Vec<PathBuf> {
    let home = home.to_path_buf();
    let mut dirs = Vec::new();

    // Desktop first: it is where people drop things, and the apps list it
    // straight after Apple Notes and the text in pictures.
    let desktop = home.join("Desktop");
    if desktop.exists() {
        dirs.push(desktop);
    }

    // Phase 1: Dotfiles and config dirs where secrets commonly live
    // Includes .hedgehog — our own logs/config could contain sensitive data
    // and an attacker might hide secrets there thinking we won't check.
    let dotdirs = [
        ".ssh",
        ".aws",
        ".config",
        ".gnupg",
        ".kube",
        ".docker",
        ".hedgehog",
    ];
    for d in &dotdirs {
        let p = home.join(d);
        if p.exists() {
            dirs.push(p);
        }
    }
    // Dotfiles that are single files — we scan their parent, but these are
    // handled by the file scanner when we scan $HOME dotfiles directly.
    // Add individual dotfiles as their parent dir (home) only once for phase 1.
    let dotfiles = [".env", ".npmrc", ".pypirc", ".netrc", ".env.local"];
    let has_dotfile = dotfiles.iter().any(|f| home.join(f).exists());
    if has_dotfile && !dirs.contains(&home) {
        // We don't add $HOME itself — the dir scanner will be too broad.
        // Instead we handle dotfiles by scanning $HOME with depth=1 later.
        // For now, just ensure the dotdirs above are included.
    }

    // Phase 2: Common dumping grounds
    for d in &["Downloads", "Documents"] {
        let p = home.join(d);
        if p.exists() {
            dirs.push(p);
        }
    }

    // Phase 2b: code checkouts kept directly in the home folder (a GitHub
    // folder inside Documents is already covered above). Both spellings are
    // listed for case-sensitive file systems; duplicates are dropped.
    for d in CODE_DIRS {
        let p = home.join(d);
        if p.is_dir() && !same_dir_listed(&dirs, &p) {
            dirs.push(p);
        }
    }

    // Phase 3: Media (filename heuristic only)
    let p = home.join("Pictures");
    if p.exists() {
        dirs.push(p);
    }

    dirs
}

/// Folders in the home folder where people usually keep code checkouts.
pub const CODE_DIRS: &[&str] = &[
    "GitHub",
    "github",
    "Developer",
    "Projects",
    "projects",
    "repos",
    "Repos",
    "code",
    "Code",
    "src",
    "dev",
    "git",
    "workspace",
    "Workspace",
    "Sites",
];

/// True when `candidate` is a folder already in `dirs`, by identity rather
/// than spelling: on a case-insensitive disk "GitHub" and "github" are one.
fn same_dir_listed(dirs: &[PathBuf], candidate: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let id = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
        let wanted = id(candidate);
        dirs.iter()
            .any(|d| d == candidate || (wanted.is_some() && id(d) == wanted))
    }
    #[cfg(not(unix))]
    {
        let wanted = candidate.to_string_lossy().to_lowercase();
        dirs.iter()
            .any(|d| d.to_string_lossy().to_lowercase() == wanted)
    }
}

/// One place a default deep scan reads, for the apps to show before a scan.
#[derive(serde::Serialize, Debug)]
pub struct ScanPlace {
    /// "settings", "folder", "code", "pictures" or "notes".
    pub kind: &'static str,
    pub label: String,
    /// Absent for Apple Notes, which is a database rather than a folder.
    pub path: Option<String>,
    pub detail: String,
}

/// The places `scan --deep` reads when no folders are given, in the order
/// it reads them: Apple Notes and the text in pictures first, then each
/// folder, with the hidden settings folders as one entry after Desktop.
pub fn default_scan_places() -> Vec<ScanPlace> {
    let home = home_dir();
    let mut settings = Vec::new();
    let mut places = Vec::new();
    if cfg!(target_os = "macos") {
        places.push(ScanPlace {
            kind: "notes",
            label: "Apple Notes".into(),
            path: None,
            detail: "Read first. Needs Full Disk Access".into(),
        });
    }
    // Text in pictures is read on every platform: Vision on macOS, the
    // Windows OCR engine, tesseract on Linux.
    places.push(ScanPlace {
        kind: "pictures",
        label: "Screenshots and photos".into(),
        path: None,
        detail: "The text inside pictures on the Desktop and in Documents, Downloads and Pictures"
            .into(),
    });
    for dir in smart_scan_dirs() {
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let path = Some(dir.to_string_lossy().into_owned());
        let (kind, detail) = if name.starts_with('.') {
            settings.push(name);
            continue;
        } else if CODE_DIRS.contains(&name.as_str()) {
            ("code", "Code checkouts")
        } else if name == "Documents" {
            (
                "folder",
                "Including code checkouts kept here, such as GitHub",
            )
        } else if name == "Pictures" {
            (
                "folder",
                "Its other files; the text in its pictures is read above",
            )
        } else {
            ("folder", "")
        };
        places.push(ScanPlace {
            kind,
            label: name,
            path,
            detail: detail.into(),
        });
    }
    if !settings.is_empty() {
        // Read straight after Desktop.
        let at = places
            .iter()
            .position(|p| p.label == "Desktop")
            .map_or(places.len().min(2), |i| i + 1);
        places.insert(
            at,
            ScanPlace {
                kind: "settings",
                label: "Settings folders".into(),
                path: home.map(|h| h.to_string_lossy().into_owned()),
                detail: settings.join(", "),
            },
        );
    }
    places
}

/// Return the home directory for full `--all-dirs` scan.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

/// Format scan results for CLI output (used by reporting, not the live CLI).
#[allow(dead_code)]
pub fn format_results(results: &[ScanResult]) -> String {
    let mut output = String::new();
    let home = std::env::var("HOME").unwrap_or_default();

    output.push_str("Deep scan results:\n");
    output.push_str("==================\n\n");

    // Group by severity (danger level of the secret type), not by match confidence
    let critical: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::Critical)
        .collect();
    let high: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::High)
        .collect();
    let medium: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::Medium)
        .collect();
    let low: Vec<&ScanResult> = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::Low)
        .collect();

    if !critical.is_empty() {
        output.push_str("CRITICAL — Direct credentials:\n");
        for r in &critical {
            let path_str = shorten_path(&r.path, &home);
            output.push_str(&format!(
                "  [CRITICAL] {}:{}\n",
                path_str, r.finding.line_number
            ));
            output.push_str(&format!("             {}\n", r.finding.redacted_preview));
            output.push_str(&format!("             {}\n\n", r.finding.description));
        }
    }

    if !high.is_empty() {
        output.push_str("HIGH — Sensitive material:\n");
        for r in &high {
            let path_str = shorten_path(&r.path, &home);
            output.push_str(&format!(
                "  [HIGH] {}:{}\n",
                path_str, r.finding.line_number
            ));
            output.push_str(&format!("         {}\n", r.finding.redacted_preview));
            output.push_str(&format!("         {}\n\n", r.finding.description));
        }
    }

    if !medium.is_empty() {
        output.push_str("MEDIUM — Policy/regulatory:\n");
        for r in &medium {
            let path_str = shorten_path(&r.path, &home);
            output.push_str(&format!(
                "  [MEDIUM] {}:{}\n",
                path_str, r.finding.line_number
            ));
            output.push_str(&format!("           {}\n", r.finding.redacted_preview));
            output.push_str(&format!("           {}\n\n", r.finding.description));
        }
    }

    if !low.is_empty() {
        output.push_str("LOW — Heuristic suspicion:\n");
        for r in &low {
            let path_str = shorten_path(&r.path, &home);
            output.push_str(&format!("  [LOW] {}\n", path_str));
            output.push_str(&format!("        {}\n", r.finding.redacted_preview));
            output.push_str(&format!("        {}\n\n", r.finding.description));
        }
    }

    // Summary
    output.push_str("Risk Summary:\n");
    output.push_str(&format!(
        "  {} critical findings (credentials, API keys, private keys)\n",
        critical.len()
    ));
    output.push_str(&format!(
        "  {} high findings (financial, identity, auth tokens, classified docs)\n",
        high.len()
    ));
    output.push_str(&format!(
        "  {} medium findings (policy/regulatory markings)\n",
        medium.len()
    ));
    output.push_str(&format!(
        "  {} low findings (suspicious images)\n",
        low.len()
    ));

    let total = results.len();
    if total > 0 {
        output.push_str(
            "\n  These files are accessible to any AI agent or process on your machine.\n",
        );
    } else {
        output.push_str("\n  No content-based secrets found. Nice!\n");
    }

    output
}

/// Format just the summary (finding counts by severity tier). Used by report generation.
#[allow(dead_code)]
pub fn format_summary(results: &[ScanResult]) -> String {
    let mut output = String::new();

    let critical = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::Critical)
        .count();
    let high = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::High)
        .count();
    let medium = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::Medium)
        .count();
    let low = results
        .iter()
        .filter(|r| r.finding.secret_type.severity() == Severity::Low)
        .count();
    let total = results.len();

    output.push_str("Risk Summary:\n");
    output.push_str(&format!(
        "  \x1b[31m{critical}\x1b[0m critical (credentials, API keys, private keys)\n"
    ));
    output.push_str(&format!(
        "  \x1b[33m{high}\x1b[0m high (financial, identity, auth, classified)\n"
    ));
    output.push_str(&format!(
        "  \x1b[34m{medium}\x1b[0m medium (policy/regulatory markings)\n"
    ));
    output.push_str(&format!("  \x1b[36m{low}\x1b[0m low (suspicious images)\n"));
    output.push_str(&format!("  \x1b[1m{total}\x1b[0m total findings\n"));

    if total > 0 {
        output.push_str(
            "\n  These files are accessible to any AI agent or process on your machine.\n",
        );
    } else {
        output.push_str("\n  No content-based secrets found. Nice!\n");
    }

    output
}

/// Convert scan results to report entries for the team dashboard.
///
/// Nothing from inside a file leaves the machine: no preview, line, match
/// text or line number. Each entry is a category, a severity, a count and a
/// home-relative path. Government classification findings ([`is_silent`])
/// and every other sensitivity-label finding are left out entirely, and an
/// Apple Notes title (the note's first line) is never sent.
pub fn results_to_report_entries(results: &[ScanResult]) -> Vec<ContentFindingEntry> {
    let home = home_dir();
    let mut counts: BTreeMap<(String, &'static str, &'static str), usize> = BTreeMap::new();
    for r in results {
        if is_silent(&r.finding)
            || matches!(
                r.finding.secret_type,
                content_patterns::ContentSecretType::SensitiveMarking { .. }
            )
        {
            continue;
        }
        let file = report_path(&r.path, home.as_deref());
        *counts
            .entry((
                file,
                finding_category(r),
                r.finding.secret_type.severity().label(),
            ))
            .or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|((file, category, severity), count)| ContentFindingEntry {
            category: category.to_string(),
            severity: severity.to_string(),
            count,
            file,
        })
        .collect()
}

/// A content finding entry for the team report payload: metadata only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ContentFindingEntry {
    pub category: String,
    pub severity: String,
    pub count: usize,
    /// Home-relative (`~/...`) where the file is under the home folder.
    pub file: String,
}

/// A path for upload: relative to the home folder (HOME, then USERPROFILE on
/// Windows) so the account name is not sent. Apple Notes pseudo-paths carry
/// the note's first line and are replaced by a fixed name.
pub fn report_path(path: &Path, home: Option<&Path>) -> String {
    if path.to_string_lossy().starts_with("AppleNotes:") {
        return "Apple Notes".to_string();
    }
    if let Some(home) = home.filter(|h| !h.as_os_str().is_empty()) {
        if let Ok(rest) = path.strip_prefix(home) {
            let rest = rest.to_string_lossy();
            return if rest.is_empty() {
                "~".to_string()
            } else {
                format!("~{}{}", std::path::MAIN_SEPARATOR, rest)
            };
        }
    }
    path.display().to_string()
}

/// Shorten a path by replacing $HOME with ~.
fn shorten_path(path: &Path, home: &str) -> String {
    let path_str = path.display().to_string();
    if !home.is_empty() && path_str.starts_with(home) {
        format!("~{}", &path_str[home.len()..])
    } else {
        path_str
    }
}

/// Map a scan result to a dashboard category name.
/// Special-cases `.env` files (PasswordPattern in .env* → ".env Files").
pub fn finding_category(result: &ScanResult) -> &'static str {
    let cat = result.finding.secret_type.category();
    // Special case: passwords found in .env files get their own category
    if cat == "Passwords" {
        if let Some(name) = result.path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(".env") {
                return ".env Files";
            }
        }
    }
    cat
}

/// Every note with a body, whatever entity number this database gave notes.
#[cfg(target_os = "macos")]
const NOTES_QUERY: &str = "SELECT z1.ZSNIPPET, z2.ZDATA, z1.Z_PK \
     FROM ZICCLOUDSYNCINGOBJECT z1 \
     JOIN ZICNOTEDATA z2 ON z1.Z_PK = z2.ZNOTE \
     WHERE z1.Z_ENT IN (SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME = 'ICNote') \
       AND IFNULL(z1.ZMARKEDFORDELETION, 0) != 1 \
       AND z2.ZDATA IS NOT NULL";

/// Scan Apple Notes on macOS. Notes are stored in a SQLite DB readable by
/// any process. Reads the full note body from `ZICNOTEDATA.ZDATA` (gzip-
/// compressed protobuf), decompresses it, extracts printable text, and
/// scans for secrets.
///
/// Returns `(results, notes_scanned_count, error_message)`.
#[cfg(target_os = "macos")]
pub fn scan_apple_notes(_config: &ScanConfig) -> (Vec<ScanResult>, usize, Option<String>) {
    let home = match home_dir() {
        Some(h) => h,
        None => return (Vec::new(), 0, None),
    };

    let db_path = home.join("Library/Group Containers/group.com.apple.notes/NoteStore.sqlite");
    if !db_path.exists() {
        return (Vec::new(), 0, None);
    }

    // Open read-only to avoid WAL locking issues
    let conn = match rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("locked") {
                return (
                    Vec::new(),
                    0,
                    Some("Apple Notes DB locked (Notes app may be open)".to_string()),
                );
            }
            if msg.contains("authorization denied") || msg.contains("unable to open") {
                return (
                    Vec::new(),
                    0,
                    Some(
                        "Permission denied — grant Full Disk Access in System Settings > Privacy"
                            .to_string(),
                    ),
                );
            }
            return (Vec::new(), 0, Some(format!("Notes DB open failed: {e}")));
        }
    };

    // Notes are one entity in the polymorphic ZICCLOUDSYNCINGOBJECT table.
    // Its Z_ENT number is assigned per database by Core Data (it was 12 on
    // some Macs, not on others), so look it up by name. ZMARKEDFORDELETION
    // is often NULL, and NULL != 1 is not true in SQL, so treat NULL as 0.
    // ZTITLE is NULL for notes — title is derived from the body text.
    // JOIN ZICNOTEDATA to get the compressed body (ZDATA).
    let mut stmt = match conn.prepare(NOTES_QUERY) {
        Ok(s) => s,
        Err(e) => return (Vec::new(), 0, Some(format!("Notes query failed: {e}"))),
    };

    let mut results = Vec::new();
    let mut notes_count = 0usize;

    let rows = match stmt.query_map([], |row| {
        let snippet: Option<String> = row.get(0)?;
        let zdata: Vec<u8> = row.get(1)?;
        let id: i64 = row.get(2)?;
        Ok((snippet, zdata, id))
    }) {
        Ok(r) => r,
        Err(e) => return (Vec::new(), 0, Some(format!("Notes query failed: {e}"))),
    };

    for row in rows.flatten() {
        let (snippet, zdata, id) = row;
        notes_count += 1;

        // Decompress body; fall back to snippet if decompression fails
        let body_text = decompress_note_body(&zdata).unwrap_or_else(|| snippet.unwrap_or_default());

        if body_text.is_empty() {
            continue;
        }

        // A note is named by its number in the Notes database, never by its
        // text: a note's first line can be the secret itself.
        let note_path = PathBuf::from(format!("AppleNotes:note {id}"));

        // Scan all lines for single-line patterns
        let lines: Vec<&str> = body_text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let line_findings = content_patterns::check_line(line, i + 1);
            for finding in line_findings.into_iter().filter(|f| !is_silent(f)) {
                results.push(ScanResult {
                    path: note_path.clone(),
                    finding,
                });
            }
        }

        // Multi-line scanning (seed phrases, 2FA backup codes)
        if lines.len() > 1 {
            let multi_findings = content_patterns::check_multi_line(&lines);
            for finding in multi_findings {
                results.push(ScanResult {
                    path: note_path.clone(),
                    finding,
                });
            }
        }
    }

    (results, notes_count, None)
}

/// Decompress ZDATA and extract printable text from the protobuf payload.
///
/// Apple Notes stores the body as compressed protobuf — most use gzip (1F8B),
/// some older notes use zlib/deflate (789C). We try both. Rather than pulling
/// in a full protobuf parser, we extract contiguous runs of printable UTF-8
/// (>= 8 bytes), which reliably captures the note text embedded as protobuf
/// string fields.
#[cfg(target_os = "macos")]
fn decompress_note_body(data: &[u8]) -> Option<String> {
    use std::io::Read;

    let mut decompressed = Vec::new();

    if data.starts_with(&[0x1F, 0x8B]) {
        // Gzip format
        let mut decoder = flate2::read::GzDecoder::new(data);
        if decoder.read_to_end(&mut decompressed).is_err() {
            return None;
        }
    } else if data.starts_with(&[0x78]) {
        // Zlib/deflate format (0x78 0x9C, 0x78 0x01, 0x78 0xDA, etc.)
        let mut decoder = flate2::read::ZlibDecoder::new(data);
        if decoder.read_to_end(&mut decompressed).is_err() {
            return None;
        }
    } else {
        return None;
    }

    let text = extract_printable_text(&decompressed);
    if text.is_empty() {
        return None;
    }
    Some(text)
}

/// Extract contiguous runs of printable UTF-8 characters from binary data.
/// Only keeps runs of 8+ bytes to filter out protobuf field tags and noise.
#[cfg(target_os = "macos")]
fn extract_printable_text(data: &[u8]) -> String {
    let mut output = String::new();
    let mut run = Vec::new();

    for &byte in data {
        if byte == b'\n' || byte == b'\t' || (byte >= 0x20 && byte < 0x7F) {
            run.push(byte);
        } else {
            if run.len() >= 8 {
                if let Ok(s) = std::str::from_utf8(&run) {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str(s.trim());
                }
            }
            run.clear();
        }
    }
    // Flush final run
    if run.len() >= 8 {
        if let Ok(s) = std::str::from_utf8(&run) {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str(s.trim());
        }
    }

    output
}

#[cfg(not(target_os = "macos"))]
pub fn scan_apple_notes(_config: &ScanConfig) -> (Vec<ScanResult>, usize, Option<String>) {
    (Vec::new(), 0, None)
}

// ---------------------------------------------------------------------------
// Image OCR scanning — extract text from images using platform-native OCR
// ---------------------------------------------------------------------------

/// Minimum image file size to bother OCR-ing (10 KB).
const OCR_MIN_FILE_SIZE: u64 = 10_240;

/// Maximum image file size to OCR (20 MB).
const OCR_MAX_FILE_SIZE: u64 = 20_971_520;

/// Maximum number of images to OCR in a single scan.
pub const OCR_MAX_IMAGES: usize = 5000;

/// Number of images to process per OCR batch (for progress updates).
pub const OCR_BATCH_SIZE: usize = 25;

/// Images eligible for OCR, and whether the per-scan cap cut the list short.
pub struct ImageBatch {
    pub paths: Vec<PathBuf>,
    pub cap_reached: bool,
}

/// Collect image file paths from `dirs`, applying the same skip rules as
/// `scan_directory_recursive` (SKIP_DIRS, hidden dirs, .app bundles, depth limit).
pub fn collect_image_paths(
    dirs: &[PathBuf],
    config: &ScanConfig,
    interrupt: &Arc<AtomicBool>,
) -> ImageBatch {
    let mut images = Vec::new();
    let mut cap_reached = false;
    for dir in dirs {
        if interrupt.load(Ordering::Relaxed) || cap_reached {
            break;
        }
        collect_images_recursive(dir, config, interrupt, &mut images, &mut cap_reached, 0);
    }
    images.truncate(OCR_MAX_IMAGES);
    ImageBatch {
        paths: images,
        cap_reached,
    }
}

fn collect_images_recursive(
    dir: &Path,
    config: &ScanConfig,
    interrupt: &Arc<AtomicBool>,
    images: &mut Vec<PathBuf>,
    cap_reached: &mut bool,
    depth: usize,
) {
    if interrupt.load(Ordering::Relaxed) || depth > MAX_SCAN_DEPTH || *cap_reached {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if interrupt.load(Ordering::Relaxed) || *cap_reached {
            return;
        }

        let path = entry.path();

        if path.is_dir() {
            if !config.include_skipped {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if dir_skip_reason(name, depth).is_some() {
                        continue;
                    }
                }
            }
            collect_images_recursive(&path, config, interrupt, images, cap_reached, depth + 1);
        } else if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !IMAGE_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            if let Ok(meta) = std::fs::metadata(&path) {
                let size = meta.len();
                if size >= OCR_MIN_FILE_SIZE && size <= OCR_MAX_FILE_SIZE {
                    if images.len() >= OCR_MAX_IMAGES {
                        *cap_reached = true;
                        return;
                    }
                    images.push(path);
                }
            }
        }
    }
}

/// Run OCR on a batch of images and scan the extracted text for secrets.
///
/// Call with a slice of image paths (typically `OCR_BATCH_SIZE` at a time).
/// Returns `(results, error_message)`.
pub fn ocr_scan_batch(image_paths: &[PathBuf]) -> (Vec<ScanResult>, usize, Option<String>) {
    if image_paths.is_empty() {
        return (Vec::new(), 0, None);
    }

    // Run platform-native OCR
    let ocr_output = match run_platform_ocr(image_paths) {
        Ok(text) => text,
        Err(e) => return (Vec::new(), image_paths.len(), Some(e)),
    };

    let (texts, unread) = ocr_records(&ocr_output, image_paths);
    let mut results = Vec::new();
    for (path, text) in texts {
        results.extend(scan_ocr_text(path, &text));
    }
    (results, unread, None)
}

/// The text of each picture in a batch, with the path always taken from
/// `image_paths` (never from the helper's output, so text in a picture
/// cannot name another file), and how many pictures could not be read.
/// The Mac helper prints one JSON record per picture; the Windows and Linux
/// readers print `---PATH:<path>` blocks, accepted only for listed paths.
fn ocr_records(output: &str, image_paths: &[PathBuf]) -> (Vec<(PathBuf, String)>, usize) {
    let mut texts = Vec::new();
    if output.trim_start().starts_with('{') {
        let mut seen = vec![false; image_paths.len()];
        let mut unread = 0;
        for line in output.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(i) = v.get("i").and_then(|i| i.as_u64()).map(|i| i as usize) else {
                continue;
            };
            if i >= image_paths.len() || seen[i] {
                continue;
            }
            seen[i] = true;
            if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
                unread += 1;
                continue;
            }
            let text = v.get("text").and_then(|t| t.as_str()).unwrap_or("");
            if !text.trim().is_empty() {
                texts.push((image_paths[i].clone(), text.to_string()));
            }
        }
        unread += seen.iter().filter(|s| !**s).count();
        return (texts, unread);
    }
    let listed: std::collections::HashSet<&std::path::Path> =
        image_paths.iter().map(|p| p.as_path()).collect();
    for chunk in output.split("\n---PATH:") {
        let chunk = chunk.trim();
        let Some((path_str, text)) = chunk.split_once('\n') else {
            continue;
        };
        let path = std::path::Path::new(path_str.trim());
        if listed.contains(path) && !text.trim().is_empty() {
            texts.push((path.to_path_buf(), text.to_string()));
        }
    }
    (texts, 0)
}

/// Scan the text read from one picture for secrets.
/// Filters out noisy OCR patterns that cause false positives.
fn scan_ocr_text(image_path: PathBuf, text: &str) -> Vec<ScanResult> {
    use hedgehog_taint::content_patterns::ContentSecretType;

    let mut results = Vec::new();
    {
        let text = text.trim();
        if text.is_empty() {
            return results;
        }

        // Scan each line — only keep high-signal findings from OCR text.
        // OCR is noisy: random numbers, table data, and short strings
        // trigger low-confidence patterns. We only keep Definitive and High.
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let line_findings = content_patterns::check_line(line, i + 1);
            for finding in line_findings {
                if is_silent(&finding) {
                    continue;
                }
                // Skip heuristic-confidence findings from OCR (too noisy)
                if finding.confidence == Confidence::Heuristic {
                    continue;
                }
                // Skip financial patterns from OCR — receipts, invoices, phone numbers
                if finding.secret_type == ContentSecretType::CreditCard {
                    continue;
                }
                results.push(ScanResult {
                    path: image_path.clone(),
                    finding,
                });
            }
        }

        // Multi-line scanning — skip 2FA backup code detection for OCR.
        // OCR text from tables, spreadsheets, and receipts generates lines
        // of short numbers that look exactly like backup code grids.
        // Seed phrases are still valuable to detect (12/24 BIP-39 words),
        // including a phrase Vision read as a single line.
        if !lines.is_empty() {
            let multi_findings = content_patterns::check_multi_line(&lines);
            for finding in multi_findings {
                // Keep seed phrases, skip 2FA codes from OCR
                if finding.secret_type == ContentSecretType::TwoFactorBackupCodes {
                    continue;
                }
                results.push(ScanResult {
                    path: image_path.clone(),
                    finding,
                });
            }
        }
    }

    results
}

/// The OCR helper the Mac apps bundle beside the CLI (`gorse-ocr`, Apple
/// Vision), or the one `GORSE_OCR_HELPER` names. None for a bare CLI.
#[cfg(target_os = "macos")]
pub fn bundled_ocr_helper() -> Option<PathBuf> {
    // Development only: release builds never let the environment choose
    // which program reads the pictures.
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("GORSE_OCR_HELPER") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let exe = std::env::current_exe().ok()?;
    let helper = exe.parent()?.join("gorse-ocr");
    helper.is_file().then_some(helper)
}

#[cfg(not(target_os = "macos"))]
pub fn bundled_ocr_helper() -> Option<PathBuf> {
    None
}

/// True when the developer tools are installed, so `swift` runs a script
/// instead of asking the person to install the tools.
#[cfg(target_os = "macos")]
fn developer_tools_installed() -> bool {
    std::process::Command::new("/usr/bin/xcode-select")
        .arg("-p")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// macOS: Apple Vision, through the bundled `gorse-ocr` helper when the CLI
/// runs inside a Mac app, otherwise through a Swift script when the
/// developer tools are installed.
#[cfg(target_os = "macos")]
fn run_platform_ocr(image_paths: &[PathBuf]) -> Result<String, String> {
    use std::process::{Command, Stdio};

    if let Some(helper) = bundled_ocr_helper() {
        use std::io::Read;
        let mut child = Command::new(&helper)
            .args(image_paths)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to run the OCR helper: {e}"))?;
        let mut stdout = child.stdout.take().ok_or("The OCR helper gave no output")?;
        let reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            let _ = stdout.read_to_end(&mut text);
            text
        });
        // A picture Vision cannot finish must not stall the scan: a batch
        // gets a few seconds per picture, then the helper is stopped.
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(30 + 10 * image_paths.len() as u64);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The OCR helper did not finish in time".to_string());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let text = reader.join().unwrap_or_default();
        if !status.success() {
            return Err("The OCR helper failed".to_string());
        }
        // One odd byte must not lose the whole batch.
        return Ok(String::from_utf8_lossy(&text).into_owned());
    }
    if !developer_tools_installed() {
        return Err("Text in pictures is read by the Gorse app; the command-line tool alone cannot read it on this Mac".to_string());
    }

    let swift_code = r#"
import Foundation
import Vision

#if canImport(AppKit)
import AppKit
#endif

let paths = CommandLine.arguments.dropFirst()
for path in paths {
    guard let image = NSImage(contentsOfFile: path),
          let tiffData = image.tiffRepresentation,
          let bitmap = NSBitmapImageRep(data: tiffData),
          let cgImage = bitmap.cgImage(forProposedRect: nil, context: nil, hints: nil)
    else { continue }

    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = false
    let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
    try? handler.perform([request])

    guard let observations = request.results as? [VNRecognizedTextObservation] else { continue }
    let text = observations.compactMap { $0.topCandidates(1).first?.string }.joined(separator: "\n")
    if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { continue }

    print("\n---PATH:\(path)")
    print(text)
}
"#;

    // Write Swift script to temp file
    let tmp_dir = std::env::temp_dir();
    let script_path = tmp_dir.join("hedgehog_ocr.swift");
    std::fs::write(&script_path, swift_code)
        .map_err(|e| format!("Failed to write OCR script: {e}"))?;

    // Build argument list: swift <script> <path1> <path2> ...
    let mut cmd = Command::new("swift");
    cmd.arg(&script_path);
    for p in image_paths {
        cmd.arg(p);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run Swift OCR: {e}"))?;

    let _ = std::fs::remove_file(&script_path);

    if !output.status.success() {
        return Err("Swift OCR process failed".to_string());
    }

    String::from_utf8(output.stdout).map_err(|e| format!("OCR output encoding error: {e}"))
}

/// Windows: use Windows.Media.Ocr via PowerShell.
#[cfg(target_os = "windows")]
fn run_platform_ocr(image_paths: &[PathBuf]) -> Result<String, String> {
    use std::process::{Command, Stdio};

    // Build the PowerShell script with embedded paths
    let mut script = String::from(
        r#"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime]

function Await($WinRtTask, $ResultType) {
    $asTask = $WinRtTask.GetType().GetMethod('AsTask', [type[]]@())
    if ($asTask -eq $null) {
        $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() |
            Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.IsGenericMethod } |
            Select-Object -First 1
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
    } else {
        $netTask = $asTask.Invoke($WinRtTask, @())
    }
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}

$ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($ocrEngine -eq $null) { exit 1 }

$paths = @(
"#,
    );

    for p in image_paths {
        let escaped = p.display().to_string().replace('\'', "''");
        script.push_str(&format!("  '{}'\n", escaped));
    }

    script.push_str(
        r#")

foreach ($path in $paths) {
    try {
        $file = [System.IO.File]::OpenRead($path)
        $stream = [Windows.Storage.Streams.RandomAccessStream, Windows.Foundation, ContentType = WindowsRuntime]
        $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($file.AsRandomAccessStream())) ([Windows.Graphics.Imaging.BitmapDecoder])
        $bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        $result = Await ($ocrEngine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
        $text = $result.Text
        $file.Close()
        if ($text.Trim().Length -gt 0) {
            Write-Output "`n---PATH:$path"
            Write-Output $text
        }
    } catch { continue }
}
"#,
    );

    let tmp_dir = std::env::temp_dir();
    let script_path = tmp_dir.join("hedgehog_ocr.ps1");
    std::fs::write(&script_path, &script)
        .map_err(|e| format!("Failed to write OCR script: {e}"))?;

    let output = Command::new("powershell.exe")
        .args(["-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("Failed to run PowerShell OCR: {e}"))?;

    let _ = std::fs::remove_file(&script_path);

    if !output.status.success() {
        return Err("PowerShell OCR process failed".to_string());
    }

    String::from_utf8(output.stdout).map_err(|e| format!("OCR output encoding error: {e}"))
}

/// Linux: use tesseract if available (optional — most Linux users don't photograph secrets).
#[cfg(target_os = "linux")]
fn run_platform_ocr(image_paths: &[PathBuf]) -> Result<String, String> {
    use std::process::{Command, Stdio};

    // Check if tesseract is installed — skip silently if not
    let which = Command::new("which")
        .arg("tesseract")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match which {
        Ok(s) if s.success() => {}
        _ => return Ok(String::new()), // No tesseract = skip OCR quietly
    }

    let mut output_text = String::new();

    for path in image_paths {
        let result = Command::new("tesseract")
            .arg(path)
            .arg("stdout")
            .args(["-l", "eng"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();

        if let Ok(out) = result {
            if out.status.success() {
                if let Ok(text) = String::from_utf8(out.stdout) {
                    let text = text.trim();
                    if !text.is_empty() {
                        output_text.push_str(&format!("\n---PATH:{}\n{}\n", path.display(), text));
                    }
                }
            }
        }
    }

    Ok(output_text)
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn run_platform_ocr(_image_paths: &[PathBuf]) -> Result<String, String> {
    Err("Image OCR not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hedgehog_taint::content_patterns::ContentSecretType;
    use std::io::Write;

    fn create_test_dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("hedgehog_test_{}_{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // clean any stale leftovers
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_test_dir(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scan_file_with_aws_key() {
        let dir = create_test_dir();
        let file_path = dir.join("notes.txt");
        std::fs::write(&file_path, "My AWS key: AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let config = ScanConfig::default();
        let findings = scan_file(&file_path, &config);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::AwsAccessKey));

        cleanup_test_dir(&dir);
    }

    #[test]
    fn skip_binary_files() {
        let dir = create_test_dir();
        let file_path = dir.join("binary.txt");
        let mut contents = vec![0u8; 100]; // null bytes = binary
        contents.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        std::fs::write(&file_path, &contents).unwrap();

        let config = ScanConfig::default();
        let findings = scan_file(&file_path, &config);
        assert!(findings.is_empty());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn skip_large_files() {
        let dir = create_test_dir();
        let file_path = dir.join("large.txt");
        let config = ScanConfig {
            max_file_size: 100,
            scan_images: false,
            include_skipped: false,
            done_dirs: None,
        };

        // Create a file larger than the limit
        let mut f = std::fs::File::create(&file_path).unwrap();
        for _ in 0..20 {
            f.write_all(b"AKIAIOSFODNN7EXAMPLE padding text here\n")
                .unwrap();
        }
        drop(f);

        let findings = scan_file(&file_path, &config);
        assert!(findings.is_empty());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn scan_directory_finds_secrets() {
        let dir = create_test_dir();
        std::fs::write(dir.join("secrets.txt"), "password = mysupersecretvalue\n").unwrap();
        std::fs::write(dir.join("safe.txt"), "This is a normal text file.\n").unwrap();

        let config = ScanConfig::default();
        let results = scan_directory(&dir, &config);
        assert!(results
            .iter()
            .any(|r| r.finding.secret_type == ContentSecretType::PasswordPattern));

        cleanup_test_dir(&dir);
    }

    #[test]
    fn skip_node_modules() {
        let dir = create_test_dir();
        let nm = dir.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();

        let config = ScanConfig::default();
        let results = scan_directory(&dir, &config);
        assert!(results.is_empty());

        cleanup_test_dir(&dir);
    }

    #[test]
    fn image_filename_detection() {
        let dir = create_test_dir();
        let img_path = dir.join("recovery-key-backup.png");
        std::fs::write(&img_path, "fake image data").unwrap();

        let config = ScanConfig {
            scan_images: true,
            include_skipped: false,
            ..Default::default()
        };
        let findings = scan_file(&img_path, &config);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::SuspiciousImage));

        cleanup_test_dir(&dir);
    }

    #[test]
    fn format_results_redacted() {
        let results = vec![ScanResult {
            path: PathBuf::from("/Users/test/Desktop/notes.txt"),
            finding: ContentFinding {
                secret_type: ContentSecretType::AwsAccessKey,
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number: 14,
                redacted_preview: "AKIA****XXXX".to_string(),
                description: "AWS Access Key",
            },
        }];
        let output = format_results(&results);
        assert!(output.contains("AKIA****XXXX"));
        // format_results groups by the secret type's severity, not by match
        // confidence. An AWS access key is Severity::Critical.
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("1 critical findings"));
    }

    fn marking_result(path: &str, marking: &'static str) -> ScanResult {
        ScanResult {
            path: PathBuf::from(path),
            finding: ContentFinding {
                secret_type: ContentSecretType::SensitiveMarking { marking },
                confidence: Confidence::High,
                context: LineContext::Code,
                line_number: 1,
                redacted_preview: "[MARKING] fixed".to_string(),
                description: "marking",
            },
        }
    }

    fn aws_result(path: &str) -> ScanResult {
        ScanResult {
            path: PathBuf::from(path),
            finding: ContentFinding {
                secret_type: ContentSecretType::AwsAccessKey,
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number: 14,
                redacted_preview: "AKIA****MPLE".to_string(),
                description: "AWS Access Key",
            },
        }
    }

    #[test]
    fn report_entries_are_metadata_only_and_drop_markings() {
        let home = home_dir().expect("HOME is set in tests");
        let inside = home.join("Desktop").join("notes.txt");
        let inside = inside.to_str().unwrap();
        let results = vec![
            aws_result(inside),
            aws_result(inside),
            aws_result("AppleNotes:My bank PIN is 1234"),
            marking_result(inside, "TOP SECRET"),
            marking_result(inside, "NOFORN"),
            marking_result(inside, "ITAR"),
            marking_result(inside, "PROPRIETARY"),
        ];
        let entries = results_to_report_entries(&results);
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            entries,
            vec![
                ContentFindingEntry {
                    category: "API Keys".into(),
                    severity: "critical".into(),
                    count: 1,
                    file: "Apple Notes".into(),
                },
                ContentFindingEntry {
                    category: "API Keys".into(),
                    severity: "critical".into(),
                    count: 2,
                    file: format!("~{sep}Desktop{sep}notes.txt"),
                },
            ]
        );
        let json = serde_json::to_string(&entries).unwrap();
        for leaked in ["AKIA", "PIN", "1234", "MARKING", "Sensitivity", "line"] {
            assert!(!json.contains(leaked), "{leaked} leaked into {json}");
        }
        let home_text = home.to_string_lossy();
        assert!(!json.contains(home_text.as_ref()), "{json}");
    }

    #[test]
    fn report_path_is_home_relative_on_a_component_boundary() {
        let home = Path::new("/Users/test");
        assert_eq!(
            report_path(Path::new("/Users/test/.aws/credentials"), Some(home)),
            format!("~{}.aws/credentials", std::path::MAIN_SEPARATOR)
        );
        assert_eq!(
            report_path(Path::new("/Users/test2/file"), Some(home)),
            "/Users/test2/file"
        );
        assert_eq!(report_path(Path::new("/tmp/x"), None), "/tmp/x");
    }

    #[test]
    fn silent_policy_covers_government_markings_only() {
        for marking in [
            "TOP SECRET",
            "SECRET",
            "CONFIDENTIAL",
            "CUI",
            "(TS)",
            "(S)",
            "(C)",
            "(CUI)",
            "NOFORN",
            "ORCON",
            "REL TO",
        ] {
            assert!(
                is_silent(&marking_result("/x", marking).finding),
                "{marking}"
            );
        }
        for marking in [
            "ITAR",
            "EAR",
            "PROPRIETARY",
            "TRADE SECRET",
            "NDA PROTECTED",
        ] {
            assert!(
                !is_silent(&marking_result("/x", marking).finding),
                "{marking}"
            );
        }
        assert!(!is_silent(&aws_result("/x").finding));
    }

    #[test]
    fn deep_scan_hides_government_markings_but_shows_itar() {
        let dir = create_test_dir();
        std::fs::write(
            dir.join("brief.txt"),
            "TOP SECRET//SI//EXAMPLECODEWORD//NOFORN\n(S) paragraph\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("export.txt"),
            "EXAMPLECODEWORD controlled under 22 CFR 120-130\n",
        )
        .unwrap();
        let results = scan_directory(&dir, &ScanConfig::default());
        assert!(
            results.iter().all(|r| !is_silent(&r.finding)),
            "{results:?}"
        );
        let previews: Vec<&str> = results
            .iter()
            .map(|r| r.finding.redacted_preview.as_str())
            .collect();
        assert_eq!(previews, ["[MARKING] ITAR export-control notice"]);
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_keeps_government_markings_internal() {
        let dir = create_test_dir().canonicalize().unwrap();
        std::fs::write(dir.join("brief.txt"), "SECRET//NOFORN\n").unwrap();
        let report = checked(&dir);
        assert!(report.results.is_empty(), "{:?}", report.results);
        assert_eq!(report.silent_paths, vec![dir.join("brief.txt")]);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn shorten_path_replaces_home() {
        assert_eq!(
            shorten_path(Path::new("/Users/test/Desktop/notes.txt"), "/Users/test"),
            "~/Desktop/notes.txt"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked(path: &Path) -> ScanReport {
        scan_directory_checked(
            path,
            &ScanConfig::default(),
            &Arc::new(AtomicBool::new(false)),
            None,
        )
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_scans_unknown_extensions_and_previously_skipped_directories() {
        let dir = create_test_dir().canonicalize().unwrap();
        let nested = dir.join("node_modules").join(".hidden");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("credential.custom"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        std::fs::write(dir.join("empty"), "").unwrap();
        let report = checked(&dir);
        assert!(report.complete, "{report:?}");
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.error_count, 0);
        assert_eq!(report.skipped_count, 0);
        assert!(report
            .results
            .iter()
            .any(|r| r.finding.secret_type == ContentSecretType::AwsAccessKey));
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_missing_roots_and_symlinks_are_incomplete() {
        use std::os::unix::fs::symlink;
        let dir = create_test_dir().canonicalize().unwrap();
        let outside = dir.join("outside");
        let scope = dir.join("scope");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&scope).unwrap();
        std::fs::write(outside.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        symlink(&outside, scope.join("linked-dir")).unwrap();
        symlink(outside.join("secret.txt"), scope.join("linked-file")).unwrap();
        symlink(&scope, dir.join("root-link")).unwrap();
        let report = checked(&scope);
        assert!(!report.complete);
        assert_eq!(report.error_count, 2);
        assert_eq!(report.files_scanned, 0);
        assert!(report.results.is_empty());
        for root in [dir.join("missing"), dir.join("root-link")] {
            let report = checked(&root);
            assert!(!report.complete);
            assert!(report.error_count > 0);
        }
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_reports_oversize_and_unsupported_encoding_as_skipped() {
        let dir = create_test_dir().canonicalize().unwrap();
        std::fs::write(dir.join("oversize.txt"), "x".repeat(101)).unwrap();
        std::fs::write(dir.join("binary.txt"), [0u8, 1, 2]).unwrap();
        std::fs::write(dir.join("invalid.txt"), [0xffu8, 0x80]).unwrap();
        std::fs::write(dir.join("broken-utf16.txt"), [0xffu8, 0xfe, 0]).unwrap();
        let config = ScanConfig {
            max_file_size: 100,
            scan_images: false,
            include_skipped: false,
            done_dirs: None,
        };
        let report = scan_directory_checked(&dir, &config, &Arc::new(AtomicBool::new(false)), None);
        assert!(!report.complete);
        assert_eq!(report.skipped_count, 4);
        assert_eq!(report.files_scanned, 0);
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_handles_utf16_without_counting_binary_content_as_scanned() {
        let dir = create_test_dir().canonicalize().unwrap();
        let mut bytes = vec![0xff, 0xfe];
        for unit in "AKIAIOSFODNN7EXAMPLE\n".encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        std::fs::write(dir.join("encoded.custom"), bytes).unwrap();
        let report = checked(&dir);
        assert!(report.complete);
        assert_eq!(report.files_scanned, 1);
        assert!(!report.results.is_empty());
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_reports_depth_limit_and_interruption() {
        let dir = create_test_dir().canonicalize().unwrap();
        let mut nested = dir.clone();
        for _ in 0..MAX_SCAN_DEPTH + 1 {
            nested = nested.join("nested");
        }
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let report = checked(&dir);
        assert!(!report.complete);
        assert_eq!(report.skipped_count, 1);
        let report = scan_directory_checked(
            &dir,
            &ScanConfig::default(),
            &Arc::new(AtomicBool::new(true)),
            None,
        );
        assert!(!report.complete);
        assert_eq!(report.files_scanned, 0);
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_refuses_directory_swap_during_traversal() {
        use std::os::unix::fs::symlink;
        let dir = create_test_dir().canonicalize().unwrap();
        let scope = dir.join("scope");
        let child = scope.join("child");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(child.join("safe.txt"), "ordinary text").unwrap();
        std::fs::write(outside.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let mut swapped = false;
        let mut callback = |event: ScanEvent<'_>| {
            if let ScanEvent::EnterDir { dir: entered, .. } = event {
                if entered == child && !swapped {
                    std::fs::rename(&child, dir.join("held")).unwrap();
                    symlink(&outside, &child).unwrap();
                    swapped = true;
                }
            }
        };
        let report = scan_directory_checked(
            &scope,
            &ScanConfig::default(),
            &Arc::new(AtomicBool::new(false)),
            Some(&mut callback),
        );
        assert!(swapped);
        assert!(!report.complete);
        assert!(report.error_count > 0);
        assert!(
            report.results.is_empty(),
            "Must not read the replacement directory"
        );
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_refuses_file_symlink_swap_before_open() {
        use std::os::unix::fs::symlink;
        let dir = create_test_dir().canonicalize().unwrap();
        let scope = dir.join("scope");
        std::fs::create_dir(&scope).unwrap();
        let file = scope.join("item.txt");
        let outside = dir.join("outside.txt");
        std::fs::write(&file, "ordinary text").unwrap();
        std::fs::write(&outside, "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        let mut callback = |event: ScanEvent<'_>| {
            if let ScanEvent::EnterDir { .. } = event {
                std::fs::remove_file(&file).unwrap();
                symlink(&outside, &file).unwrap();
            }
        };
        let report = scan_directory_checked(
            &scope,
            &ScanConfig::default(),
            &Arc::new(AtomicBool::new(false)),
            Some(&mut callback),
        );
        assert!(!report.complete);
        assert!(report.error_count > 0);
        assert_eq!(report.files_scanned, 0);
        assert!(report.results.is_empty());
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_fifo_is_skipped_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = create_test_dir().canonicalize().unwrap();
        let fifo = std::ffi::CString::new(dir.join("pipe.txt").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let began = std::time::Instant::now();
        let report = checked(&dir);
        assert!(began.elapsed() < std::time::Duration::from_secs(2));
        assert!(!report.complete);
        assert_eq!(report.skipped_count, 1);
        assert_eq!(report.files_scanned, 0);
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_unreadable_file_reports_error() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = create_test_dir().canonicalize().unwrap();
        let file = dir.join("private.txt");
        std::fs::write(&file, "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let report = checked(&dir);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!report.complete);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.files_scanned, 0);
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_refuses_hard_links_to_unrelated_content() {
        let dir = create_test_dir().canonicalize().unwrap();
        let scope = dir.join("scope");
        std::fs::create_dir(&scope).unwrap();
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        std::fs::hard_link(&outside, scope.join("linked.txt")).unwrap();
        let report = checked(&scope);
        assert!(!report.complete);
        assert_eq!(report.skipped_count, 1);
        assert_eq!(report.files_scanned, 0);
        assert!(report.results.is_empty());
        assert_eq!(report.coverage.files_skipped_other, 1);
        assert!(report.coverage.other_skip_examples[0].contains("hard link"));
        cleanup_test_dir(&dir);
    }

    // ── Coverage ────────────────────────────────────────────────────────────

    const AWS_KEY_LINE: &str = "aws_key = AKIAIOSFODNN7EXAMPLE\n";

    fn covered(dir: &Path, config: &ScanConfig) -> ScanOutcome {
        scan_directory_with_coverage(dir, config, &Arc::new(AtomicBool::new(false)), None)
    }

    fn has_aws(results: &[ScanResult], suffix: &str) -> bool {
        results.iter().any(|r| {
            // Compare with forward slashes so the same test runs on Windows.
            r.path
                .to_string_lossy()
                .replace('\\', "/")
                .ends_with(suffix)
                && r.finding.secret_type == ContentSecretType::AwsAccessKey
        })
    }

    /// The old one-file-at-a-time walk, kept here as the reference the
    /// parallel scan must reproduce exactly.
    fn reference_walk(
        dir: &Path,
        config: &ScanConfig,
        results: &mut Vec<(PathBuf, String)>,
        coverage: &mut ScanCoverage,
        depth: usize,
    ) {
        if depth > MAX_SCAN_DEPTH {
            coverage.record_depth_limit();
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(error) => {
                coverage.record_unreadable(dir, &error);
                return;
            }
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_str().unwrap();
                if !config.include_skipped && dir_skip_reason(name, depth).is_some() {
                    coverage.record_skipped_dir(name);
                    continue;
                }
                reference_walk(&path, config, results, coverage, depth + 1);
            } else if path.is_file() {
                let findings = match scan_file_outcome(&path, config) {
                    FileOutcome::Scanned(f) => {
                        coverage.record_scanned();
                        f
                    }
                    FileOutcome::Image(f) => {
                        coverage.record_image_scanned();
                        f
                    }
                    FileOutcome::SkippedType(label) => {
                        coverage.record_skipped_type(&label);
                        continue;
                    }
                    FileOutcome::Oversize => {
                        coverage.record_oversize(&path);
                        continue;
                    }
                    FileOutcome::Unreadable(error) => {
                        coverage.record_unreadable(&path, &error);
                        continue;
                    }
                };
                for f in findings.into_iter().filter(|f| !is_silent(f)) {
                    results.push((path.clone(), format!("{:?}", f.secret_type)));
                }
            } else {
                coverage.record_skipped_other(&path, "not a regular file");
            }
        }
    }

    /// A tree with findings, every skip reason and folders past the depth
    /// limit, spread over enough files to keep several workers busy.
    fn busy_tree() -> PathBuf {
        let dir = create_test_dir();
        let mut deep = dir.join("deep");
        for level in 0..MAX_SCAN_DEPTH + 2 {
            std::fs::create_dir_all(&deep).unwrap();
            std::fs::write(deep.join(format!("k{level}.env")), AWS_KEY_LINE).unwrap();
            deep = deep.join(format!("d{level}"));
        }
        for d in 0..6 {
            let sub = dir.join(format!("folder{d}")).join("inner");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::create_dir_all(dir.join(format!("folder{d}")).join("node_modules")).unwrap();
            for f in 0..25 {
                let body = match f % 5 {
                    0 => AWS_KEY_LINE.to_string(),
                    1 => "card 4111 1111 1111 1111\n".to_string(),
                    2 => "1.0,2.0,3.0\n".repeat(200),
                    3 => "x".repeat(300),
                    _ => "nothing here\n".to_string(),
                };
                std::fs::write(sub.join(format!("f{f}.txt")), &body).unwrap();
                std::fs::write(
                    dir.join(format!("folder{d}")).join(format!("g{f}.csv")),
                    &body,
                )
                .unwrap();
            }
            std::fs::write(sub.join("a.pdf"), "%PDF").unwrap();
            std::fs::write(sub.join("bin"), b"ab\0cd").unwrap();
        }
        dir
    }

    #[test]
    fn parallel_scan_matches_one_file_at_a_time() {
        let dir = busy_tree();
        let config = ScanConfig {
            max_file_size: 256,
            ..Default::default()
        };
        let mut expected = Vec::new();
        let mut reference = ScanCoverage::new(&config);
        reference_walk(&dir, &config, &mut expected, &mut reference, 0);
        reference.finalize();

        let outcome = covered(&dir, &config);
        let got: Vec<(PathBuf, String)> = outcome
            .results
            .iter()
            .map(|r| (r.path.clone(), format!("{:?}", r.finding.secret_type)))
            .collect();
        assert!(expected.len() > 20, "the tree has findings: {expected:?}");
        assert_eq!(got, expected, "same findings in the same order");
        let c = &outcome.coverage;
        assert_eq!(
            (
                c.files_scanned,
                c.files_skipped_by_type,
                c.files_over_size_limit,
                c.files_unreadable,
                c.dirs_skipped_by_rule,
                c.dirs_beyond_depth_limit,
                c.files_skipped_other,
            ),
            (
                reference.files_scanned,
                reference.files_skipped_by_type,
                reference.files_over_size_limit,
                reference.files_unreadable,
                reference.dirs_skipped_by_rule,
                reference.dirs_beyond_depth_limit,
                reference.files_skipped_other,
            )
        );
        assert!(c.dirs_beyond_depth_limit > 0 && c.files_over_size_limit > 0);
        assert_eq!(c.oversize_examples, reference.oversize_examples);
        assert_eq!(c.skipped_types, reference.skipped_types);
        assert_eq!(c.skipped_dirs, reference.skipped_dirs);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn dir_done_comes_after_every_file_below_it_and_counts_only_grow() {
        let dir = busy_tree();
        let mut seen_findings: Vec<PathBuf> = Vec::new();
        let mut done: Vec<PathBuf> = Vec::new();
        let mut last = (0usize, 0usize);
        let mut on_event = |event: ScanEvent<'_>| match event {
            ScanEvent::EnterDir {
                files_scanned,
                findings_count,
                ..
            } => {
                assert!(files_scanned >= last.0 && findings_count >= last.1);
                last = (files_scanned, findings_count);
            }
            ScanEvent::Finding {
                files_scanned,
                findings_count,
                result,
            } => {
                assert!(files_scanned >= last.0 && findings_count == last.1 + 1);
                last = (files_scanned, findings_count);
                assert!(
                    !done.iter().any(|d| result.path.starts_with(d)),
                    "finding in {} after its folder was reported done",
                    result.path.display()
                );
                seen_findings.push(result.path.clone());
            }
            ScanEvent::DirDone { dir } => done.push(dir.to_path_buf()),
        };
        let outcome = scan_directory_with_coverage(
            &dir,
            &ScanConfig::default(),
            &Arc::new(AtomicBool::new(false)),
            Some(&mut on_event),
        );
        assert_eq!(seen_findings.len(), outcome.results.len());
        assert_eq!(last.1, outcome.results.len());
        assert_eq!(done.last(), Some(&dir), "the root is done last");
        cleanup_test_dir(&dir);
    }

    #[test]
    fn interrupt_stops_the_parallel_scan_without_marking_folders_done() {
        let dir = busy_tree();
        let interrupt = Arc::new(AtomicBool::new(false));
        let stop = interrupt.clone();
        let mut done_after_stop = 0;
        let mut on_event = |event: ScanEvent<'_>| match event {
            ScanEvent::Finding { .. } => stop.store(true, Ordering::Relaxed),
            ScanEvent::DirDone { .. } if stop.load(Ordering::Relaxed) => done_after_stop += 1,
            _ => {}
        };
        let started = std::time::Instant::now();
        let outcome = scan_directory_with_coverage(
            &dir,
            &ScanConfig::default(),
            &interrupt,
            Some(&mut on_event),
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(done_after_stop, 0);
        assert!(outcome.coverage.interrupted && outcome.coverage.has_gaps);
        assert!(!outcome.coverage.complete);
        assert!(!outcome.results.is_empty());
        cleanup_test_dir(&dir);
    }

    #[test]
    fn coverage_is_complete_for_plain_text_tree() {
        let dir = create_test_dir();
        std::fs::write(dir.join("a.txt"), "hello\n").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("b.md"), "world\n").unwrap();
        std::fs::write(dir.join("empty"), "").unwrap();
        let outcome = covered(&dir, &ScanConfig::default());
        assert!(outcome.coverage.complete, "{:?}", outcome.coverage);
        assert_eq!(outcome.coverage.files_scanned, 3);
        assert_eq!(outcome.coverage.files_not_checked(), 0);
        assert!(outcome.coverage.gap_lines("").is_empty());
        cleanup_test_dir(&dir);
    }

    #[test]
    fn code_folders_in_home_are_default_roots_once() {
        let home = create_test_dir();
        for d in ["Documents", "GitHub", "Developer", "code"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let dirs = smart_scan_dirs_in(&home);
        for d in ["GitHub", "Developer", "code"] {
            let n = dirs
                .iter()
                .filter(|p| {
                    std::fs::metadata(p).ok().map(|m| m.is_dir()) == Some(true)
                        && same_dir_listed(&[home.join(d)], p)
                })
                .count();
            assert_eq!(n, 1, "{d} should be a default root exactly once: {dirs:?}");
        }
        assert!(
            !dirs.iter().any(|p| p.ends_with("Projects")),
            "absent folders are not listed"
        );
        cleanup_test_dir(&home);
    }

    #[test]
    fn projects_folder_is_scanned() {
        let dir = create_test_dir();
        for folder in ["projects", "repos", "GitHub", "data", "work", "code"] {
            let nested = dir.join(folder).join("foo");
            std::fs::create_dir_all(&nested).unwrap();
            std::fs::write(nested.join("creds.txt"), AWS_KEY_LINE).unwrap();
        }
        let outcome = covered(&dir, &ScanConfig::default());
        for folder in ["projects", "repos", "GitHub", "data", "work", "code"] {
            assert!(
                has_aws(&outcome.results, &format!("{folder}/foo/creds.txt")),
                "{folder} was not scanned: {:?}",
                outcome.coverage
            );
        }
        assert!(outcome.coverage.complete);
        assert_eq!(outcome.coverage.dirs_skipped_by_rule, 0);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn backup_and_extensionless_files_are_scanned() {
        let dir = create_test_dir();
        let names = [
            "notes.backup",
            "notes.bak",
            "notes.old",
            "config.orig",
            "notes.txt~",
            "credentials",
            "weird.custom",
            ".secrets",
        ];
        for name in names {
            std::fs::write(dir.join(name), AWS_KEY_LINE).unwrap();
        }
        let outcome = covered(&dir, &ScanConfig::default());
        for name in names {
            assert!(
                has_aws(&outcome.results, name),
                "{name} was not scanned: {:?}",
                outcome.coverage
            );
        }
        assert_eq!(outcome.coverage.files_scanned, names.len());
        assert!(outcome.coverage.complete);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn coverage_counts_each_skip_reason() {
        let dir = create_test_dir();
        std::fs::write(dir.join("plain.txt"), "hello\n").unwrap();
        // Known binary types and sniffed binary content.
        std::fs::write(dir.join("report.pdf"), b"%PDF-1.4").unwrap();
        std::fs::write(dir.join("slides.pdf"), b"%PDF-1.4").unwrap();
        std::fs::write(dir.join("blob.dat"), [0u8, 1, 2, 3]).unwrap();
        // Over the size limit.
        std::fs::write(dir.join("big.log"), "x".repeat(200)).unwrap();
        // Rule-skipped folders, including hidden ones below the root.
        for folder in ["node_modules", ".git", "node_modules2"] {
            let d = dir.join(folder);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("x.txt"), AWS_KEY_LINE).unwrap();
        }
        std::fs::rename(dir.join("node_modules2"), dir.join("vendor")).unwrap();
        // Image: counted as scanned by name, content not read.
        std::fs::write(dir.join("photo.png"), b"\x89PNG").unwrap();
        let config = ScanConfig {
            max_file_size: 100,
            ..Default::default()
        };
        let outcome = covered(&dir, &config);
        let c = &outcome.coverage;
        assert!(!c.complete);
        assert_eq!(c.files_scanned, 2, "{c:?}"); // plain.txt + photo.png
        assert_eq!(c.files_skipped_by_type, 3);
        assert_eq!(
            c.skipped_types[0],
            NamedCount {
                name: "pdf".into(),
                count: 2
            }
        );
        assert!(c.skipped_types.iter().any(|t| t.name == "dat"));
        assert_eq!(c.files_over_size_limit, 1);
        assert!(c.oversize_examples[0].ends_with("big.log"));
        assert_eq!(c.size_limit_bytes, 100);
        assert_eq!(c.dirs_skipped_by_rule, 3);
        let dir_names: Vec<&str> = c.skipped_dirs.iter().map(|d| d.name.as_str()).collect();
        assert!(dir_names.contains(&"node_modules"));
        assert!(dir_names.contains(&".git"));
        assert!(dir_names.contains(&"vendor"));
        assert_eq!(c.images_seen, 1);
        assert_eq!(c.files_unreadable, 0);
        assert_eq!(c.files_not_checked(), 4);
        assert!(outcome.results.is_empty());

        let lines = c.gap_lines("");
        assert!(lines
            .iter()
            .any(|l| l.contains("larger than the 100 bytes limit")));
        assert!(lines
            .iter()
            .any(|l| l.contains("type this scanner does not read")));
        assert!(lines
            .iter()
            .any(|l| l.contains("3 folders were skipped by rule")));

        // Opting in scans the rule-skipped folders with the same limits.
        let config = ScanConfig {
            max_file_size: 100,
            include_skipped: true,
            ..Default::default()
        };
        let outcome = covered(&dir, &config);
        assert_eq!(outcome.coverage.dirs_skipped_by_rule, 0);
        assert!(has_aws(&outcome.results, "node_modules/x.txt"));
        assert!(has_aws(&outcome.results, ".git/x.txt"));
        cleanup_test_dir(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn coverage_is_incomplete_on_permission_denied() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = create_test_dir();
        std::fs::write(dir.join("open.txt"), "hello\n").unwrap();
        let locked = dir.join("locked.txt");
        std::fs::write(&locked, AWS_KEY_LINE).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let locked_dir = dir.join("private");
        std::fs::create_dir(&locked_dir).unwrap();
        std::fs::write(locked_dir.join("x.txt"), AWS_KEY_LINE).unwrap();
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let outcome = covered(&dir, &ScanConfig::default());
        // The checked walker refuses symlinked roots (/var -> /private/var).
        let checked_report = checked(&dir.canonicalize().unwrap());

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let c = &outcome.coverage;
        assert!(!c.complete, "{c:?}");
        assert_eq!(c.files_scanned, 1);
        assert_eq!(c.files_unreadable, 2);
        assert_eq!(c.permission_denied, 2);
        assert_eq!(c.other_read_errors, 0);
        assert!(c
            .unreadable_examples
            .iter()
            .any(|e| e.path.ends_with("locked.txt") && e.reason == "permission denied"));
        assert!(c
            .unreadable_examples
            .iter()
            .any(|e| e.path.ends_with("private") && e.reason == "permission denied"));
        assert!(outcome.results.is_empty());
        let lines = c.gap_lines("");
        assert!(lines
            .iter()
            .any(|l| l.starts_with("2 files could not be read (permission denied)")));

        // The checked audit walker reports the same reasons.
        let cc = &checked_report.coverage;
        assert!(!cc.complete);
        assert!(!checked_report.complete);
        assert_eq!(cc.permission_denied, 2, "{cc:?}");
        assert_eq!(cc.files_unreadable, checked_report.error_count);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn coverage_merges_across_roots_and_serializes() {
        let a = create_test_dir();
        let b = create_test_dir();
        std::fs::write(a.join("a.txt"), "hello\n").unwrap();
        std::fs::write(a.join("a.pdf"), b"%PDF").unwrap();
        std::fs::create_dir(a.join("node_modules")).unwrap();
        std::fs::write(b.join("b.txt"), "hello\n").unwrap();
        std::fs::write(b.join("b.pdf"), b"%PDF").unwrap();
        std::fs::create_dir(b.join("node_modules")).unwrap();
        let config = ScanConfig::default();
        let mut merged = ScanCoverage::new(&config);
        merged.merge(covered(&a, &config).coverage);
        merged.merge(covered(&b, &config).coverage);
        assert_eq!(merged.files_scanned, 2);
        assert_eq!(merged.files_skipped_by_type, 2);
        assert_eq!(
            merged.skipped_types,
            vec![NamedCount {
                name: "pdf".into(),
                count: 2
            }]
        );
        assert_eq!(
            merged.skipped_dirs,
            vec![NamedCount {
                name: "node_modules".into(),
                count: 2
            }]
        );
        assert!(!merged.complete);

        let json = serde_json::to_value(&merged).unwrap();
        assert_eq!(json["complete"], false);
        assert_eq!(json["files_scanned"], 2);
        assert_eq!(json["skipped_types"][0]["name"], "pdf");
        assert_eq!(json["skipped_dirs"][0]["count"], 2);
        assert!(
            json.get("type_counts").is_none(),
            "internal maps stay private"
        );
        cleanup_test_dir(&a);
        cleanup_test_dir(&b);
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn checked_audit_coverage_names_oversize_and_binary_reasons() {
        let dir = create_test_dir().canonicalize().unwrap();
        std::fs::write(dir.join("oversize.txt"), "x".repeat(101)).unwrap();
        std::fs::write(dir.join("binary.dat"), [0u8, 1, 2]).unwrap();
        let config = ScanConfig {
            max_file_size: 100,
            ..Default::default()
        };
        let report = scan_directory_checked(&dir, &config, &Arc::new(AtomicBool::new(false)), None);
        let c = &report.coverage;
        assert!(!c.complete);
        assert_eq!(c.files_over_size_limit, 1);
        assert_eq!(c.files_skipped_by_type, 1);
        assert_eq!(c.skipped_types[0].name, "dat");
        assert_eq!(c.files_not_checked(), report.skipped_count);
        cleanup_test_dir(&dir);
    }

    #[test]
    fn binary_types_are_notes_not_gaps_but_permission_denied_is_a_gap() {
        let mut c = ScanCoverage::default();
        c.files_scanned = 4;
        c.files_skipped_by_type = 2;
        c.images_content_not_checked = 1;
        c.finalize();
        assert!(
            !c.complete,
            "strict completeness still notices skipped types"
        );
        assert!(!c.has_gaps, "types the scanner never reads are not gaps");
        assert_eq!(c.note_lines().len(), 2);

        let mut d = ScanCoverage::default();
        d.files_scanned = 1;
        d.files_unreadable = 1;
        d.permission_denied = 1;
        d.finalize();
        assert!(d.has_gaps);

        c.merge(d);
        assert!(c.has_gaps, "merging a root with a gap keeps the gap");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod notes_query_tests {
    use super::NOTES_QUERY;

    /// A synthetic NoteStore: notes are entity 9 here, not 12, and two of
    /// the three live notes have a NULL deletion flag.
    #[test]
    fn notes_are_found_whatever_their_entity_number_and_with_null_flags() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE Z_PRIMARYKEY (Z_ENT INTEGER, Z_NAME TEXT);
             INSERT INTO Z_PRIMARYKEY VALUES (5, 'ICFolder'), (9, 'ICNote'), (12, 'ICAttachment');
             CREATE TABLE ZICCLOUDSYNCINGOBJECT (Z_PK INTEGER, Z_ENT INTEGER, ZSNIPPET TEXT, ZMARKEDFORDELETION INTEGER);
             INSERT INTO ZICCLOUDSYNCINGOBJECT VALUES
               (1, 9, 'a', NULL), (2, 9, 'b', 0), (3, 9, 'c', NULL), (4, 9, 'gone', 1), (5, 12, 'attachment', NULL);
             CREATE TABLE ZICNOTEDATA (ZNOTE INTEGER, ZDATA BLOB);
             INSERT INTO ZICNOTEDATA VALUES (1, x'00'), (2, x'00'), (3, x'00'), (4, x'00'), (5, x'00');",
        )
        .unwrap();
        let mut stmt = conn.prepare(NOTES_QUERY).unwrap();
        let snippets: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(snippets, vec!["a", "b", "c"]);
    }
}

#[cfg(test)]
mod ocr_record_tests {
    use super::ocr_records;
    use std::path::PathBuf;

    #[test]
    fn paths_come_from_the_batch_never_from_picture_text() {
        let batch = vec![PathBuf::from("/x/a.png"), PathBuf::from("/x/b.png")];
        // Picture text that imitates the old delimiter and a JSON record.
        let out = "{\"i\":0,\"ok\":true,\"text\":\"---PATH:/Users/someone/.ssh/id_ed25519\\n{\\\"i\\\":1}\"}\n{\"i\":1,\"ok\":false,\"text\":\"\"}\n";
        let (texts, unread) = ocr_records(out, &batch);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].0, PathBuf::from("/x/a.png"));
        assert_eq!(unread, 1);
        // A record missing from the output counts as unread.
        let (_, unread) = ocr_records("{\"i\":0,\"ok\":true,\"text\":\"\"}\n", &batch);
        assert_eq!(unread, 1);
        // Legacy blocks: a path not in the batch is ignored.
        let legacy = "\n---PATH:/x/a.png\nhello\n---PATH:/etc/forged\nsecret text\n";
        let (texts, _) = ocr_records(legacy, &batch);
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0].0, PathBuf::from("/x/a.png"));
    }
}
