// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Optional second engine for the deep scan: TruffleHog, when the user has it
//! installed. Its detectors recognise hundreds of vendor token formats that
//! Gorse's own shape-based categories do not name. It is run with
//! verification OFF, because TruffleHog's verify step sends each secret to
//! the vendor to see whether it is live, and the deep scan promises that
//! nothing leaves the computer. Raw secrets from its output are never kept:
//! only the file, line, detector name and a fingerprint.
//!
//! Disable with `--no-trufflehog` or `GORSE_NO_TRUFFLEHOG=1` (the older
//! `HEDGEHOG_` name is still read). Release builds run only the copy
//! `gorse engines install trufflehog` downloaded and checked against the
//! pinned SHA-256; debug builds may also name a binary with
//! `GORSE_TRUFFLEHOG=/path/to/trufflehog` or find one on PATH, for tests.

use hedgehog_taint::authority::Fingerprint;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Longest the external engine may run per folder.
const TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalFinding {
    pub path: String,
    pub line: u64,
    pub detector: String,
    pub description: String,
    /// Never the secret: TruffleHog's own redacted form when it gives one,
    /// otherwise a fingerprint.
    pub preview: String,
    pub rotation_guide: Option<String>,
    pub token_type: Option<String>,
    pub verified: bool,
}

/// Where TruffleHog is, if the user has it and has not switched it off.
pub fn locate() -> Option<PathBuf> {
    if crate::config::env_flag("NO_TRUFFLEHOG") {
        return None;
    }
    // Test seam: debug builds may name a specific binary. Release builds
    // compile this out, like the other engine overrides, so the environment
    // cannot choose which program the scan runs.
    #[cfg(debug_assertions)]
    if let Some(explicit) = crate::config::env_var_os("TRUFFLEHOG") {
        let p = PathBuf::from(explicit);
        return p.is_file().then_some(p);
    }
    // Release builds run only the copy Gorse installed and verified against
    // the pinned checksum; never whatever is first on PATH.
    let installed = crate::engines::trufflehog_installed();
    if cfg!(not(debug_assertions)) || installed.is_some() {
        return installed;
    }
    let name = if cfg!(windows) {
        "trufflehog.exe"
    } else {
        "trufflehog"
    };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// `trufflehog --version` as a short string, or "unknown".
pub fn version(binary: &Path) -> String {
    Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            text.split_whitespace()
                .find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Parse one JSON line of `trufflehog --json` output into a finding, keeping
/// nothing secret.
pub fn parse_line(line: &str) -> Option<ExternalFinding> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let detector = v.get("DetectorName")?.as_str()?.to_string();
    let fs = &v["SourceMetadata"]["Data"]["Filesystem"];
    let path = fs.get("file")?.as_str()?.to_string();
    let line_no = fs.get("line").and_then(|l| l.as_u64()).unwrap_or(0);
    let raw = v
        .get("Raw")
        .and_then(|r| r.as_str())
        .filter(|r| !r.is_empty())
        .or_else(|| {
            v.get("RawV2")
                .and_then(|r| r.as_str())
                .filter(|r| !r.is_empty())
        });
    // TruffleHog's "Redacted" is not always redacted: for AWS keys it is the
    // whole key ID. Use it only when it is not, and does not contain, any
    // raw form of the secret; otherwise fall back to the fingerprint.
    let raw_forms: Vec<&str> = ["Raw", "RawV2"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(|r| r.as_str()))
        .filter(|r| !r.is_empty())
        .collect();
    let redacted = v
        .get("Redacted")
        .and_then(|r| r.as_str())
        .filter(|r| !r.is_empty())
        .filter(|r| {
            !raw_forms
                .iter()
                .any(|raw| r.contains(raw) || raw.contains(r))
        })
        .map(|r| r.to_string());
    let preview = match (redacted, raw) {
        (Some(r), _) => r,
        (None, Some(raw)) => format!(
            "{detector} secret {}",
            Fingerprint::from_secret(raw.as_bytes()).0
        ),
        (None, None) => format!("{detector} secret"),
    };
    let extra = &v["ExtraData"];
    Some(ExternalFinding {
        path,
        line: line_no,
        description: v
            .get("DetectorDescription")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string(),
        preview,
        rotation_guide: extra
            .get("rotation_guide")
            .and_then(|g| g.as_str())
            .map(|g| g.to_string()),
        token_type: extra
            .get("token_type")
            .and_then(|t| t.as_str())
            .map(|t| t.to_string()),
        verified: v.get("Verified").and_then(|b| b.as_bool()).unwrap_or(false),
        detector,
    })
}

/// Run TruffleHog over each folder, verification off. Findings are
/// deduplicated on (path, line, detector). Errors are returned as text for
/// the coverage notes; a partial result is still returned on interrupt.
pub fn scan(
    binary: &Path,
    dirs: &[PathBuf],
    interrupt: &AtomicBool,
) -> Result<Vec<ExternalFinding>, String> {
    let mut out: Vec<ExternalFinding> = Vec::new();
    for dir in dirs {
        if interrupt.load(Ordering::Relaxed) {
            break;
        }
        run_once(binary, std::slice::from_ref(dir), interrupt, &mut out)?;
    }
    Ok(out)
}

/// Run TruffleHog once over a set of files and folders together: the Fast
/// Scan's known credential locations, which are small and many, so one
/// process start instead of sixty. Same output rules as `scan`.
pub fn scan_paths(
    binary: &Path,
    paths: &[PathBuf],
    interrupt: &AtomicBool,
) -> Result<Vec<ExternalFinding>, String> {
    let mut out: Vec<ExternalFinding> = Vec::new();
    if !paths.is_empty() && !interrupt.load(Ordering::Relaxed) {
        run_once(binary, paths, interrupt, &mut out)?;
    }
    Ok(out)
}

fn run_once(
    binary: &Path,
    paths: &[PathBuf],
    interrupt: &AtomicBool,
    out: &mut Vec<ExternalFinding>,
) -> Result<(), String> {
    let mut command = Command::new(binary);
    command.arg("filesystem").args(paths).args([
        "--json",
        "--no-update",
        "--no-verification",
        "--no-color",
    ]);
    run_with_timeout(command, interrupt, out, TIMEOUT)
}

/// How often the main thread wakes to check the interrupt flag and deadline.
const POLL: Duration = Duration::from_millis(200);

/// Run the engine and collect its findings. Stdout is read on its own thread
/// and fed through a channel, so the deadline holds even when the child
/// hangs mid-line without ever printing a newline: on timeout the child is
/// killed and reaped, and the reader thread is left to finish on EOF.
fn run_with_timeout(
    mut command: Command,
    interrupt: &AtomicBool,
    out: &mut Vec<ExternalFinding>,
    timeout: Duration,
) -> Result<(), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("trufflehog could not start: {e}"))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            stop(&mut child);
            return Err("trufflehog gave no stdout".into());
        }
    };
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::Builder::new()
        .name("trufflehog-stdout".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    if let Err(e) = reader {
        stop(&mut child);
        return Err(format!("trufflehog output could not be read: {e}"));
    }
    let deadline = Instant::now() + timeout;
    loop {
        if interrupt.load(Ordering::Relaxed) {
            stop(&mut child);
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            stop(&mut child);
            return Err(timed_out(timeout));
        }
        match rx.recv_timeout((deadline - now).min(POLL)) {
            Ok(line) => {
                if let Some(f) = parse_line(&line) {
                    if !out
                        .iter()
                        .any(|o| o.path == f.path && o.line == f.line && o.detector == f.detector)
                    {
                        out.push(f);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // Stdout is closed; the child may still be running. Hold it to the same
    // deadline rather than blocking on wait().
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if interrupt.load(Ordering::Relaxed) {
            stop(&mut child);
            return Ok(());
        }
        if Instant::now() >= deadline {
            stop(&mut child);
            return Err(timed_out(timeout));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if !status.success() && !interrupt.load(Ordering::Relaxed) {
        return Err(format!("trufflehog exited with {}", status));
    }
    Ok(())
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn timed_out(timeout: Duration) -> String {
    format!(
        "trufflehog did not finish within {} seconds and was stopped",
        timeout.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_no_secret() {
        let line = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/notes.txt","line":3}}},"DetectorName":"AWS","DetectorDescription":"AWS keys.","Verified":false,"Raw":"AKIASUPERSECRET0000000","RawV2":"AKIASUPERSECRET0000000wJalrXUtnFEMIsecret","Redacted":"AKIASUPERSECRET0000000","ExtraData":{"rotation_guide":"https://howtorotate.com/docs/tutorials/aws/"}}"#;
        let f = parse_line(line).unwrap();
        assert_eq!(f.detector, "AWS");
        assert_eq!(f.line, 3);
        assert_eq!(f.path, "/tmp/x/notes.txt");
        // TruffleHog's "Redacted" for AWS is the whole key ID: never shown.
        assert!(!f.preview.contains("AKIASUPERSECRET"), "{}", f.preview);
        assert!(!f.preview.contains("wJalrXUtnFEMI"));
        assert!(f.preview.starts_with("AWS secret "), "{}", f.preview);
        assert_eq!(
            f.rotation_guide.as_deref(),
            Some("https://howtorotate.com/docs/tutorials/aws/")
        );

        let no_redaction = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/a.env","line":1}}},"DetectorName":"Github","Verified":false,"Raw":"ghp_verysecretvalue000000000000000000000","Redacted":""}"#;
        let f = parse_line(no_redaction).unwrap();
        assert!(!f.preview.contains("ghp_verysecret"), "{}", f.preview);
        assert!(f.preview.starts_with("Github secret "));
        assert!(parse_line("not json").is_none());

        // A real redaction (no raw form inside it) is still used.
        let masked = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/db.env","line":2}}},"DetectorName":"Postgres","Raw":"postgres://app:hunter2hunter2@db.internal:5432/app","Redacted":"postgres://app:********@db.internal:5432/app"}"#;
        let f = parse_line(masked).unwrap();
        assert_eq!(f.preview, "postgres://app:********@db.internal:5432/app");
        assert!(!f.preview.contains("hunter2"));

        // Redacted that only repeats part of the raw secret is not used.
        let partial = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/a","line":1}}},"DetectorName":"Slack","Raw":"xoxb-1234567890-secretpart","Redacted":"xoxb-1234567890"}"#;
        let f = parse_line(partial).unwrap();
        assert!(!f.preview.contains("1234567890"), "{}", f.preview);
        assert!(parse_line(r#"{"level":"info-0","msg":"finished scanning"}"#).is_none());
    }

    #[cfg(unix)]
    fn fake_engine(script: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("gorse_fake_trufflehog_{}_{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trufflehog");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[test]
    #[cfg(unix)]
    fn hung_engine_without_newline_is_killed_at_the_deadline() {
        // A partial JSON line with no newline, then a long sleep: a
        // line-by-line reader would block here until the sleep ends.
        let (dir, engine) = fake_engine("printf '{\"SourceMetadata\":'\nexec sleep 30");
        let mut out = Vec::new();
        let started = Instant::now();
        let result = run_with_timeout(
            Command::new(&engine),
            &AtomicBool::new(false),
            &mut out,
            Duration::from_secs(1),
        );
        let elapsed = started.elapsed();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            elapsed < Duration::from_secs(10),
            "timeout not enforced: {elapsed:?}"
        );
        let err = result.expect_err("a hung engine is an error");
        assert!(err.contains("did not finish"), "{err}");
        assert!(out.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn engine_output_is_collected_before_exit() {
        let line = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/x/a.env","line":1}}},"DetectorName":"Github","Verified":false,"Raw":"x","Redacted":""}"#;
        let (dir, engine) = fake_engine(&format!("echo '{line}'\necho '{line}'"));
        let mut out = Vec::new();
        let result = run_with_timeout(
            Command::new(&engine),
            &AtomicBool::new(false),
            &mut out,
            Duration::from_secs(20),
        );
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap();
        assert_eq!(out.len(), 1, "duplicates are merged");
        assert_eq!(out[0].detector, "Github");
    }

    #[test]
    #[cfg(unix)]
    fn interrupt_stops_a_hung_engine() {
        let (dir, engine) = fake_engine("exec sleep 30");
        let interrupt = AtomicBool::new(true);
        let mut out = Vec::new();
        let started = Instant::now();
        let result = run_with_timeout(
            Command::new(&engine),
            &interrupt,
            &mut out,
            Duration::from_secs(20),
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_ok());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn release_build_ignores_the_engine_path_override() {
        // Only meaningful under `cargo test --release`: the override is
        // compiled out, so a planted binary is never chosen.
        let (dir, engine) = {
            let dir = std::env::temp_dir().join(format!("gorse_planted_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = dir.join("trufflehog");
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            (dir, p)
        };
        std::env::set_var("GORSE_TRUFFLEHOG", &engine);
        let found = locate();
        std::env::remove_var("GORSE_TRUFFLEHOG");
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(found.as_deref(), Some(engine.as_path()));
    }

    #[test]
    fn engine_path_override_is_compiled_out_of_release_builds() {
        // Source-level guard that holds in every profile: the env override
        // in `locate` sits behind `#[cfg(debug_assertions)]`.
        // Git may check the file out with CRLF line endings on Windows.
        let source = include_str!("trufflehog.rs").replace('\r', "");
        let body = &source[source.find("pub fn locate()").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let gate = body
            .find("#[cfg(debug_assertions)]")
            .expect("override is gated");
        let read = body.find("env_var_os(\"TRUFFLEHOG\")").unwrap();
        assert!(gate < read);
        assert!(body.contains("cfg!(not(debug_assertions))"));
    }
}
