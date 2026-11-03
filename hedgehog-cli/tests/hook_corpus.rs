// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Black-box adversarial corpus for the `gorse check --hook` interface.
//!
//! This test is the executable SPECIFICATION of what the hook must block and
//! what it must allow. Each case lives in a TOML file under `tests/corpus/`
//! and is run against the REAL binary, exactly as an AI coding agent would
//! run it: one PreToolUse JSON object on stdin, a verdict read back from the
//! exit code (2 = block, 0 = allow, anything else / a timeout = error).
//!
//! The corpus deliberately includes behaviour that is not implemented yet
//! (self-protection, credential reads, environment disclosure, destructive
//! cloud and persistence). Those cases are expected to be RED until the rules
//! land and GREEN afterwards. Cases whose verdict is genuinely debatable are
//! marked `soft = true`: a mismatch there is reported as a warning, never a
//! hard failure.
//!
//! ## Running
//!
//!   cargo test -p hedgehog-cli --test hook_corpus -- --nocapture
//!
//! The `--nocapture` matters: the mismatch table and the per-file summary are
//! printed to stdout, and `cargo` hides stdout for passing tests otherwise.
//!
//! ## Environment knobs
//!
//! * `HEDGEHOG_CORPUS_FILTER=<substring>` — only run cases whose id OR whose
//!   corpus file name contains the substring. Handy while iterating on one
//!   category, e.g. `HEDGEHOG_CORPUS_FILTER=reads`.
//!
//! * `HEDGEHOG_CORPUS_BIN=<path>` — run the corpus against an arbitrary
//!   shipped binary instead of the freshly built one. Use this to validate a
//!   release zip:
//!       HEDGEHOG_CORPUS_BIN=/path/to/unzipped/hedgehog \
//!         cargo test -p hedgehog-cli --test hook_corpus -- --nocapture
//!
//! Each case runs in a fresh temp HOME (HOME + USERPROFILE + APPDATA +
//! XDG_CONFIG_HOME + HEDGEHOG_STATE_DIR all redirected) seeded with synthetic
//! fixtures (a fake AWS credentials file, a fake ssh key, a fake `.env`) so
//! that credential paths actually exist. No real secrets and no real hosts.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How long a single hook invocation may take before we call it an error.
const CASE_TIMEOUT: Duration = Duration::from_secs(10);

/// One corpus case, as parsed from TOML.
#[derive(Debug, Clone)]
struct Case {
    file: String,
    id: String,
    tool: String,
    // Bash
    command: Option<String>,
    // Write / Edit / Read
    file_path: Option<String>,
    content: Option<String>,
    old_string: Option<String>,
    new_string: Option<String>,
    // Grep (Claude Code's Grep; Gemini's search_file_content)
    path: Option<String>,
    pattern: Option<String>,
    // WebFetch
    url: Option<String>,
    expect: Expect,
    why: String,
    os: OsReq,
    soft: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Block,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsReq {
    Any,
    Unix,
    Windows,
}

/// What the binary actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Block,
    Allow,
    Error(String),
}

/// A fresh, isolated HOME with synthetic credential fixtures.
struct TestEnv {
    root: PathBuf,
    workdir: PathBuf,
    home: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hedgehog-corpus-{}-{}",
            std::process::id(),
            unique()
        ));
        let home = root.join("home");
        let workdir = root.join("work");
        for dir in [&home, &workdir] {
            fs::create_dir_all(dir).expect("create temp dir");
        }
        // Synthetic fixtures so credential paths exist. Fake values only.
        write_file(
            &home.join(".aws/credentials"),
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrFAKEsecretKEYdoNOTuseEXAMPLEkey1234\n",
        );
        write_file(&home.join(".aws/config"), "[default]\nregion = us-east-1\n");
        write_file(
            &home.join(".ssh/id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nTHIS-IS-A-FAKE-TEST-KEY-NOT-A-REAL-SECRET\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        write_file(
            &home.join(".ssh/id_ed25519.pub"),
            "ssh-ed25519 AAAAFAKE test@fixture\n",
        );
        write_file(
            &home.join(".npmrc"),
            "//registry.npmjs.org/:_authToken=npm_FAKEtoken0000\n",
        );
        write_file(&home.join(".kube/config"), "apiVersion: v1\nkind: Config\n");
        write_file(
            &home.join(".config/gh/hosts.yml"),
            "github.com:\n  oauth_token: gho_FAKE0000\n",
        );
        // A real-looking .env in the working directory, plus allowlisted templates.
        write_file(
            &workdir.join(".env"),
            "API_KEY=test\nDATABASE_URL=postgres://u:p@localhost/db\n",
        );
        write_file(&workdir.join(".env.example"), "API_KEY=\nDATABASE_URL=\n");
        // Hook target dirs so self-protection paths resolve.
        write_file(
            &home.join(".claude/settings.json"),
            "{\"hooks\":{\"PreToolUse\":[]}}\n",
        );
        write_file(&home.join(".gemini/settings.json"), "{\"hooks\":{}}\n");
        write_file(
            &home.join(".hedgehog/config.toml"),
            "[packs]\nenabled = true\n",
        );
        Self {
            root,
            workdir,
            home,
        }
    }

    fn command(&self, bin: &Path) -> Command {
        let mut command = Command::new(bin);
        command
            .current_dir(&self.workdir)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("HEDGEHOG_STATE_DIR", self.root.join("state"))
            .env("TMPDIR", self.root.join("tmp"))
            .env("TEMP", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"));
        command
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix in the address of a stack local for a little extra entropy.
    let x = 0u8;
    nanos ^ ((&x as *const u8 as u64) << 1)
}

fn write_file(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture parent");
    }
    fs::write(path, body).expect("write fixture");
}

/// Build the PreToolUse JSON payload for a case.
fn payload_for(case: &Case) -> serde_json::Value {
    let mut tool_input = serde_json::Map::new();
    match case.tool.as_str() {
        "Bash" => {
            tool_input.insert(
                "command".into(),
                serde_json::Value::String(case.command.clone().unwrap_or_default()),
            );
        }
        "Write" => {
            tool_input.insert(
                "file_path".into(),
                serde_json::Value::String(case.file_path.clone().unwrap_or_default()),
            );
            tool_input.insert(
                "content".into(),
                serde_json::Value::String(case.content.clone().unwrap_or_default()),
            );
        }
        "Edit" => {
            tool_input.insert(
                "file_path".into(),
                serde_json::Value::String(case.file_path.clone().unwrap_or_default()),
            );
            tool_input.insert(
                "old_string".into(),
                serde_json::Value::String(case.old_string.clone().unwrap_or_default()),
            );
            tool_input.insert(
                "new_string".into(),
                serde_json::Value::String(case.new_string.clone().unwrap_or_default()),
            );
        }
        "Read" => {
            tool_input.insert(
                "file_path".into(),
                serde_json::Value::String(case.file_path.clone().unwrap_or_default()),
            );
        }
        "Grep" => {
            // `path` is optional for Grep (absent means the working directory).
            if let Some(path) = &case.path {
                tool_input.insert("path".into(), serde_json::Value::String(path.clone()));
            }
            tool_input.insert(
                "pattern".into(),
                serde_json::Value::String(case.pattern.clone().unwrap_or_default()),
            );
        }
        "WebFetch" => {
            tool_input.insert(
                "url".into(),
                serde_json::Value::String(case.url.clone().unwrap_or_default()),
            );
        }
        other => panic!("case {}: unknown tool {other}", case.id),
    }
    serde_json::json!({
        "session_id": "corpus",
        "hook_event_name": "PreToolUse",
        "tool_name": case.tool,
        "tool_input": serde_json::Value::Object(tool_input),
    })
}

/// A short, single-line description of the input, for the mismatch table.
fn truncated_input(case: &Case) -> String {
    let raw = match case.tool.as_str() {
        "Bash" => case.command.clone().unwrap_or_default(),
        "WebFetch" => case.url.clone().unwrap_or_default(),
        "Grep" => format!(
            "{} :: /{}/",
            case.path.clone().unwrap_or_default(),
            case.pattern.clone().unwrap_or_default()
        ),
        "Edit" => format!(
            "{} :: {} -> {}",
            case.file_path.clone().unwrap_or_default(),
            case.old_string.clone().unwrap_or_default(),
            case.new_string.clone().unwrap_or_default()
        ),
        _ => format!(
            "{} :: {}",
            case.file_path.clone().unwrap_or_default(),
            case.content.clone().unwrap_or_default()
        ),
    };
    let one_line: String = raw
        .chars()
        .map(|c| if c == '\n' { '\u{23ce}' } else { c })
        .collect();
    let max = 68;
    if one_line.chars().count() > max {
        let kept: String = one_line.chars().take(max - 1).collect();
        format!("{kept}\u{2026}")
    } else {
        one_line
    }
}

/// Run one case and return (verdict, first_stderr_line).
fn run_case(env: &TestEnv, bin: &Path, case: &Case) -> (Verdict, String) {
    let payload = payload_for(case).to_string();
    let mut child: Child = match env
        .command(bin)
        .args(["check", "--hook"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (Verdict::Error(format!("spawn failed: {e}")), String::new()),
    };

    if let Some(mut stdin) = child.stdin.take() {
        // A write error here usually means the child already exited; ignore it
        // and let the exit-code logic below report what happened.
        let _ = stdin.write_all(payload.as_bytes());
    }

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= CASE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (
                        Verdict::Error(format!("timed out after {}s", CASE_TIMEOUT.as_secs())),
                        String::new(),
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return (Verdict::Error(format!("wait failed: {e}")), String::new()),
        }
    };

    // Collect stderr (stdout is the decision JSON we do not need here).
    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        use std::io::Read;
        let _ = handle.read_to_string(&mut stderr);
    }
    let first_stderr = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string();

    let verdict = match status.code() {
        Some(2) => Verdict::Block,
        Some(0) => Verdict::Allow,
        Some(other) => Verdict::Error(format!("exit code {other}")),
        None => Verdict::Error("killed by signal".into()),
    };
    (verdict, first_stderr)
}

// ─── TOML parsing (using the `toml` crate already in [dependencies]) ──────

fn parse_file(path: &Path) -> Vec<Case> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string();
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let value: toml::Value =
        toml::from_str(&text).unwrap_or_else(|e| panic!("parse {file_name}: {e}"));
    let array = value
        .get("case")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("{file_name}: no [[case]] array"));

    array
        .iter()
        .map(|item| parse_case(&file_name, item))
        .collect()
}

fn parse_case(file: &str, item: &toml::Value) -> Case {
    let get_str = |key: &str| item.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let id = get_str("id").unwrap_or_else(|| panic!("{file}: a case is missing `id`"));
    let tool = get_str("tool").unwrap_or_else(|| panic!("{file}/{id}: missing `tool`"));
    let expect = match get_str("expect").as_deref() {
        Some("block") => Expect::Block,
        Some("allow") => Expect::Allow,
        other => panic!("{file}/{id}: `expect` must be block|allow, got {other:?}"),
    };
    let os = match get_str("os").as_deref() {
        None | Some("any") => OsReq::Any,
        Some("unix") => OsReq::Unix,
        Some("windows") => OsReq::Windows,
        other => panic!("{file}/{id}: `os` must be any|unix|windows, got {other:?}"),
    };
    let soft = item.get("soft").and_then(|v| v.as_bool()).unwrap_or(false);
    let why = get_str("why").unwrap_or_default();

    Case {
        file: file.to_string(),
        id,
        tool,
        command: get_str("command"),
        file_path: get_str("file_path"),
        content: get_str("content"),
        old_string: get_str("old_string"),
        new_string: get_str("new_string"),
        path: get_str("path"),
        pattern: get_str("pattern"),
        url: get_str("url"),
        expect,
        why,
        os,
        soft,
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
}

fn resolve_bin() -> PathBuf {
    match std::env::var("HEDGEHOG_CORPUS_BIN") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(env!("CARGO_BIN_EXE_gorse")),
    }
}

fn host_matches(os: OsReq) -> bool {
    match os {
        OsReq::Any => true,
        OsReq::Unix => cfg!(unix),
        OsReq::Windows => cfg!(windows),
    }
}

#[derive(Default, Clone)]
struct Tally {
    passed: usize,
    failed: usize,
    soft_warned: usize,
    skipped: usize,
}

#[test]
fn hook_corpus() {
    let bin = resolve_bin();
    assert!(
        bin.exists(),
        "gorse binary not found at {bin:?} (set HEDGEHOG_CORPUS_BIN to point at a shipped build)"
    );
    let filter = std::env::var("HEDGEHOG_CORPUS_FILTER").unwrap_or_default();

    // Load every TOML file in the corpus dir.
    let mut files: Vec<PathBuf> = fs::read_dir(corpus_dir())
        .expect("read corpus dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("toml"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no corpus TOML files found in {:?}",
        corpus_dir()
    );

    let env = TestEnv::new();

    // Guard against duplicate ids across the whole corpus.
    let mut seen_ids: BTreeMap<String, String> = BTreeMap::new();

    let mut per_file: BTreeMap<String, Tally> = BTreeMap::new();
    let mut mismatches: Vec<MismatchRow> = Vec::new();
    let mut total = Tally::default();

    for file in &files {
        let cases = parse_file(file);
        let file_name = file.file_name().unwrap().to_str().unwrap().to_string();
        let tally = per_file.entry(file_name.clone()).or_default();

        for case in &cases {
            if let Some(prev) = seen_ids.insert(case.id.clone(), file_name.clone()) {
                panic!("duplicate case id `{}` in {prev} and {file_name}", case.id);
            }

            // Filter: match on id OR file name.
            if !filter.is_empty() && !case.id.contains(&filter) && !file_name.contains(&filter) {
                continue;
            }

            if !host_matches(case.os) {
                tally.skipped += 1;
                total.skipped += 1;
                continue;
            }

            let (verdict, stderr) = run_case(&env, &bin, case);
            let want = case.expect;
            let ok = matches!(
                (&verdict, want),
                (Verdict::Block, Expect::Block) | (Verdict::Allow, Expect::Allow)
            );

            if ok {
                tally.passed += 1;
                total.passed += 1;
                continue;
            }

            // Mismatch. Record it. An Error is always a hard failure; a plain
            // wrong verdict is soft-warned when the case opted in.
            let is_error = matches!(verdict, Verdict::Error(_));
            let hard = is_error || !case.soft;
            if hard {
                tally.failed += 1;
                total.failed += 1;
            } else {
                tally.soft_warned += 1;
                total.soft_warned += 1;
            }
            mismatches.push(MismatchRow {
                hard,
                id: case.id.clone(),
                file: file_name.clone(),
                tool: case.tool.clone(),
                input: truncated_input(case),
                expected: match want {
                    Expect::Block => "block",
                    Expect::Allow => "allow",
                },
                got: match &verdict {
                    Verdict::Block => "block".to_string(),
                    Verdict::Allow => "allow".to_string(),
                    Verdict::Error(e) => format!("ERROR({e})"),
                },
                stderr,
                why: case.why.clone(),
            });
        }
    }

    print_report(&bin, &per_file, &mismatches, &total);

    assert_eq!(
        total.failed, 0,
        "{} hard corpus failure(s); see the table above. \
         Soft warnings ({}) do not fail the build.",
        total.failed, total.soft_warned
    );
}

struct MismatchRow {
    hard: bool,
    id: String,
    file: String,
    tool: String,
    input: String,
    expected: &'static str,
    got: String,
    stderr: String,
    why: String,
}

fn print_report(
    bin: &Path,
    per_file: &BTreeMap<String, Tally>,
    mismatches: &[MismatchRow],
    total: &Tally,
) {
    println!("\n==================== HOOK CORPUS ====================");
    println!("binary: {}", bin.display());
    println!("host:   {}", if cfg!(windows) { "windows" } else { "unix" });

    // Per-file summary.
    println!("\n-- per file (passed / failed / soft-warned / skipped) --");
    for (file, t) in per_file {
        println!(
            "  {file:<26} {:>4} / {:>4} / {:>4} / {:>4}",
            t.passed, t.failed, t.soft_warned, t.skipped
        );
    }
    println!(
        "  {:<26} {:>4} / {:>4} / {:>4} / {:>4}",
        "TOTAL", total.passed, total.failed, total.soft_warned, total.skipped
    );

    if mismatches.is_empty() {
        println!("\nNo mismatches. Corpus fully green.");
        println!("=====================================================\n");
        return;
    }

    // Hard failures first, then soft warnings.
    let mut rows: Vec<&MismatchRow> = mismatches.iter().collect();
    rows.sort_by_key(|r| (!r.hard, r.file.clone(), r.id.clone()));

    println!("\n-- mismatches ({} total) --", mismatches.len());
    println!(
        "  {:<4} {:<18} {:<8} {:<7} {:<16} {}",
        "KIND", "ID", "TOOL", "EXPECT", "GOT", "INPUT"
    );
    for r in rows {
        let kind = if r.hard { "FAIL" } else { "warn" };
        println!(
            "  {:<4} {:<18} {:<8} {:<7} {:<16} {}",
            kind, r.id, r.tool, r.expected, r.got, r.input
        );
        if !r.stderr.is_empty() {
            println!("       stderr: {}", clip(&r.stderr, 90));
        }
        if !r.why.is_empty() {
            println!("       why:    {}", clip(&r.why, 90));
        }
    }
    println!(
        "\n{} hard failure(s), {} soft warning(s).",
        total.failed, total.soft_warned
    );
    println!("=====================================================\n");
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let kept: String = s.chars().take(max - 1).collect();
        format!("{kept}\u{2026}")
    } else {
        s.to_string()
    }
}
