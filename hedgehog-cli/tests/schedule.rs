// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Integration tests for `gorse schedule` and `gorse exposure --record`.
//!
//! Each test runs the binary against a private home so no real history,
//! licence or scheduler entry is read or written. Nothing here installs a
//! launchd, systemd or Task Scheduler entry: `schedule set` is only tested
//! on the free tier, where it refuses before touching the scheduler.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct TestHome {
    root: PathBuf,
}

impl TestHome {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "gorse-schedule-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        for directory in ["home", "state", "tmp"] {
            fs::create_dir(root.join(directory)).unwrap();
        }
        Self { root }
    }

    /// A command with the inherited environment cleared, so the developer's
    /// own credentials, licence and TruffleHog stay out of the picture.
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gorse"));
        command.env_clear();
        command
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.root.join("home"))
            .env("USERPROFILE", self.root.join("home"))
            .env("APPDATA", self.root.join("home/AppData/Roaming"))
            .env("LOCALAPPDATA", self.root.join("home/AppData/Local"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("GORSE_STATE_DIR", self.root.join("state"))
            .env("HEDGEHOG_NO_TRUFFLEHOG", "1")
            // The test binary is unsigned (or ad-hoc signed); without this
            // every scheduled command would refuse before doing anything.
            .env("GORSE_ALLOW_UNSIGNED_SCHEDULE", "1")
            .env("TMPDIR", self.root.join("tmp"))
            .env("TEMP", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"))
            .env("NO_COLOR", "1")
            .current_dir(self.root.join("home"));
        command
    }

    /// Where the CLI keeps exposure history for this home.
    fn exposure_dir(&self) -> PathBuf {
        if cfg!(windows) {
            self.root.join("home/AppData/Roaming/hedgehog/exposure")
        } else {
            self.root.join("home/.hedgehog/exposure")
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("run gorse")
    }

    fn json(&self, args: &[&str]) -> (Output, serde_json::Value) {
        let output = self.run(args);
        let json = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid JSON: {error}; output: {output:?}"));
        (output, json)
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn schedule_set_on_free_tier_refuses_with_upgrade_message() {
    let home = TestHome::new();
    let output = home.run(&["schedule", "set", "daily"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "Scheduled checks are part of Gorse Pro. See https://www.gorse.is/pricing\n"
    );
    assert!(!home.exposure_dir().join("schedule.json").exists());

    let (output, json) = home.json(&["schedule", "set", "hourly", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        json["error"],
        "Scheduled checks are part of Gorse Pro. See https://www.gorse.is/pricing"
    );
    assert_eq!(json["upgrade_url"], "https://www.gorse.is/pricing");
}

#[test]
fn schedule_status_with_no_history() {
    let home = TestHome::new();
    let (output, json) = home.json(&["schedule", "status", "--json"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(json["frequency"], "off");
    assert_eq!(json["installed"], false);
    assert_eq!(json["licensed"], false);
    assert!(json["program"].is_null());
    assert_eq!(json["program_exists"], false);
    assert!(json["last_run"].is_null());
    assert_eq!(json["history_count"], 0);
    assert_eq!(json["program_trusted"], true, "{json}");
    assert!(json["program_team_id"].is_null(), "{json}");
    assert_eq!(json["program_in_applications"], !cfg!(target_os = "macos"));

    let output = home.run(&["schedule", "status"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Scheduled checks: off"), "{text}");
    assert!(text.contains("Last run: never"), "{text}");

    let (output, json) = home.json(&["schedule", "history", "--json"]);
    assert!(output.status.success());
    assert_eq!(json["total"], 0);
    assert_eq!(json["runs"].as_array().unwrap().len(), 0);
}

#[test]
fn schedule_run_on_free_tier_records_licence_required_and_exits_zero() {
    let home = TestHome::new();
    let output = home.run(&["schedule", "run"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    let status: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
            .unwrap();
    assert_eq!(status["ok"], false);
    assert_eq!(status["message"], "licence required");
    assert_eq!(status["frequency"], "off");
    assert!(!home.exposure_dir().join("history").exists());

    let (_, json) = home.json(&["schedule", "status", "--json"]);
    assert_eq!(json["last_run"]["ok"], false);
    assert_eq!(json["last_run"]["message"], "licence required");
    assert_eq!(json["history_count"], 0);
}

#[test]
fn exposure_record_builds_history_and_detects_changes() {
    let home = TestHome::new();

    let (output, first) = home.json(&["exposure", "--json", "--record"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(first["changes"]["first_run"], true);
    assert_eq!(first["changes"]["notify"], false);
    assert!(first["recorded_at"].is_string());

    let history = home.exposure_dir().join("history");
    let files = |dir: &PathBuf| -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    };
    let after_first = files(&history);
    assert_eq!(after_first.len(), 1, "{after_first:?}");
    assert!(after_first[0].ends_with("Z.json"), "{after_first:?}");

    let status: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
            .unwrap();
    assert_eq!(status["ok"], true);
    assert_eq!(status["trigger"], "manual");
    assert_eq!(status["first_run"], true);
    assert_eq!(status["notify"], false);
    assert_eq!(status["frequency"], "off");
    let finding_count = first["findings"].as_array().unwrap().len() as u64;
    assert_eq!(status["new"], finding_count);
    assert_eq!(status["worsened"], 0);
    assert_eq!(status["resolved"], 0);
    for key in ["critical", "high", "medium", "low"] {
        assert_eq!(status["counts"][key], first["summary"]["by_severity"][key]);
    }

    let run_file: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(history.join(&after_first[0])).unwrap()).unwrap();
    assert_eq!(run_file["trigger"], "manual");
    assert!(run_file["recorded_at"].is_string());
    assert_eq!(run_file["changes"]["first_run"], true);
    assert_eq!(run_file["changes"]["counts"]["new"], finding_count);
    assert!(run_file["findings"].is_array());
    assert!(run_file["summary"]["by_severity"].is_object());

    let (output, second) = home.json(&["exposure", "--json", "--record"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(second["changes"]["first_run"], false);
    assert_eq!(second["changes"]["notify"], false);
    assert_eq!(second["changes"]["counts"]["new"], 0);
    assert_eq!(second["changes"]["counts"]["worsened"], 0);
    assert_eq!(second["changes"]["counts"]["resolved"], 0);
    assert_eq!(files(&history).len(), 2);

    let (output, status) = home.json(&["schedule", "status", "--json"]);
    assert!(output.status.success());
    assert_eq!(status["history_count"], 2);
    assert_eq!(status["last_run"]["ok"], true);
    assert_eq!(status["last_run"]["first_run"], false);
    assert_eq!(status["last_run"]["new"], 0);
    assert!(status.get("frequency").is_some());
    assert!(status["last_run"].get("frequency").is_none());

    let (output, history_json) = home.json(&["schedule", "history", "--json", "--limit", "1"]);
    assert!(output.status.success());
    assert_eq!(history_json["total"], 2);
    let runs = history_json["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["trigger"], "manual");
    assert_eq!(runs[0]["first_run"], false);

    let output = home.run(&["schedule", "history"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("When"), "{text}");
    assert_eq!(text.lines().count(), 3, "{text}");
    assert!(text.contains("manual"), "{text}");
}

/// `schedule set off` always works: no licence and no signature check
/// stands between a person and stopping an unattended check. The apps
/// rely on it succeeding on the Free tier.
#[cfg(not(windows))]
#[test]
fn schedule_set_off_works_on_free_tier_and_without_the_signature_override() {
    let home = TestHome::new();
    let output = home.run(&["schedule", "set", "off"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "Scheduled checks are off."
    );
    let schedule: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(home.exposure_dir().join("schedule.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(schedule["frequency"], "off");

    let (output, json) = home.json(&["schedule", "set", "off", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(json.get("error").is_none(), "{json}");
    assert_eq!(json["frequency"], "off");
    assert_eq!(json["licensed"], false);

    // Unsigned (or ad-hoc signed) build, no developer override: still off.
    let mut command = home.command();
    command.env_remove("GORSE_ALLOW_UNSIGNED_SCHEDULE");
    let output = command.args(["schedule", "set", "off"]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // Turning it on is still gated.
    let output = home.run(&["schedule", "set", "daily"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

/// Running as root ignores file permissions, so an unreadable fixture
/// cannot be made.
#[cfg(unix)]
fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// A credential file that becomes unreadable between two recorded runs
/// is lost coverage, not a resolved finding: the second run is incomplete
/// (`ok: false`), reports nothing as resolved, names the location, and the
/// first run stays the baseline. When the file is readable again the third
/// run compares with that baseline and finds nothing changed.
#[cfg(unix)]
#[test]
fn unreadable_credential_file_makes_the_run_incomplete_not_resolved() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipped: root can read a mode-000 file");
        return;
    }
    let home = TestHome::new();
    let creds = home.root.join("home/.aws/credentials");
    fs::create_dir_all(creds.parent().unwrap()).unwrap();
    fs::write(
        &creds,
        "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .unwrap();

    let (output, first) = home.json(&["exposure", "--json", "--record"]);
    assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
    assert_eq!(first["incomplete"], false, "{first}");
    assert_eq!(first["coverage_failures"].as_array().unwrap().len(), 0);
    let found = first["findings"].as_array().unwrap().len();
    assert!(found >= 1, "the fixture credential must be found: {first}");
    let history = home.exposure_dir().join("history");
    let files = |dir: &PathBuf| -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    };
    let baseline = files(&history)[0].clone();

    // The file exists but cannot be read.
    fs::set_permissions(&creds, fs::Permissions::from_mode(0o000)).unwrap();
    let (output, second) = home.json(&["exposure", "--json", "--record"]);
    // Restore before asserting so a failure never leaves the fixture locked.
    fs::set_permissions(&creds, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(second["incomplete"], true, "{second}");
    assert_eq!(
        output.status.code(),
        Some(3),
        "incomplete with nothing at the threshold exits 3: {output:?}"
    );
    let failures = second["coverage_failures"].as_array().unwrap();
    assert_eq!(failures.len(), 1, "{second}");
    assert_eq!(failures[0]["location"], "~/.aws/credentials");
    assert!(
        failures[0]["reason"]
            .as_str()
            .unwrap()
            .contains("ermission"),
        "{second}"
    );
    assert_eq!(second["changes"]["counts"]["resolved"], 0, "{second}");
    assert_eq!(second["changes"]["resolved"].as_array().unwrap().len(), 0);
    assert_eq!(second["changes"]["incomplete"], true);
    assert_eq!(second["changes"]["coverage_lost"], true);
    assert_eq!(second["changes"]["notify"], true);
    assert_eq!(second["changes"]["first_run"], false);

    let status: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
            .unwrap();
    assert_eq!(status["ok"], false, "{status}");
    assert_eq!(status["incomplete"], true);
    assert_eq!(status["coverage_failures"], 1);
    assert_eq!(
        status["message"],
        "incomplete: 1 location(s) could not be read"
    );
    assert_eq!(status["resolved"], 0);
    assert_eq!(
        status["baseline"], baseline,
        "the complete run stays the baseline"
    );
    assert_eq!(files(&history).len(), 2);

    let (_, json) = home.json(&["schedule", "status", "--json"]);
    assert_eq!(json["last_run"]["ok"], false);
    assert_eq!(json["last_run"]["incomplete"], true);
    assert_eq!(json["last_run"]["coverage_failures"], 1);
    let output = home.run(&["schedule", "status"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("incomplete"), "{text}");
    assert!(text.contains("Compared with: "), "{text}");
    let (_, json) = home.json(&["schedule", "history", "--json"]);
    let runs = json["runs"].as_array().unwrap();
    assert_eq!(runs[0]["incomplete"], true);
    assert_eq!(runs[0]["coverage_failures"], 1);
    assert_eq!(runs[1]["incomplete"], false);
    let output = home.run(&["schedule", "history"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.lines().nth(1).unwrap().contains("incomplete"),
        "{text}"
    );

    // The text report says so near the top and names the location.
    fs::set_permissions(&creds, fs::Permissions::from_mode(0o000)).unwrap();
    let output = home.run(&["exposure"]);
    fs::set_permissions(&creds, fs::Permissions::from_mode(0o600)).unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let head: String = text.lines().take(6).collect::<Vec<_>>().join("\n");
    assert!(
        head.contains("INCOMPLETE: 1 credential location could not be read"),
        "{text}"
    );
    assert!(head.contains("~/.aws/credentials"), "{text}");

    // Readable again: compared with the complete baseline, nothing changed.
    let (_, third) = home.json(&["exposure", "--json", "--record"]);
    assert_eq!(third["incomplete"], false);
    assert_eq!(third["findings"].as_array().unwrap().len(), found);
    assert_eq!(third["changes"]["counts"]["new"], 0, "{third}");
    assert_eq!(third["changes"]["counts"]["resolved"], 0, "{third}");
    assert_eq!(third["changes"]["notify"], false);
    let status: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
            .unwrap();
    assert_eq!(status["ok"], true);
    assert_eq!(status["message"], "ok");
    assert_eq!(status["baseline"], baseline);
}

/// A finding from the optional TruffleHog engine is only resolved by a run
/// in which the engine ran. Uninstalling it leaves the file unexamined: the
/// finding is `unassessed`, the run is incomplete (exit 3, `ok: false`),
/// the notification says engine coverage was lost, and the run with the
/// engine stays the baseline.
#[cfg(unix)]
#[test]
fn removing_the_engine_leaves_its_findings_unassessed_not_resolved() {
    use std::os::unix::fs::PermissionsExt;
    let home = TestHome::new();
    let cache = home.root.join("home/.azure/msal_token_cache.json");
    fs::create_dir_all(cache.parent().unwrap()).unwrap();
    fs::write(&cache, "{\"AccessToken\": {}}\n").unwrap();
    let tools = home.root.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let engine = tools.join("trufflehog");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'trufflehog 9.9.9'; exit 0; fi\necho '{{\"SourceMetadata\":{{\"Data\":{{\"Filesystem\":{{\"file\":\"{}\",\"line\":1}}}}}},\"DetectorName\":\"JWT\",\"Verified\":false,\"Raw\":\"RAWJWTVALUE\",\"Redacted\":\"eyJ****\"}}'\n",
        cache.display()
    );
    fs::write(&engine, script).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
    let run_with = |extra: &[&str]| {
        let output = home
            .command()
            .env_remove("HEDGEHOG_NO_TRUFFLEHOG")
            .env("GORSE_TRUFFLEHOG", &engine)
            .args(["exposure", "--json", "--record"])
            .args(extra)
            .output()
            .expect("run gorse");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("invalid JSON: {e}; {output:?}"));
        (output, json)
    };
    let run = || run_with(&[]);

    let (output, first) = run();
    assert_eq!(first["incomplete"], false, "{first}");
    assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
    let assessed: Vec<&str> = first["sources_assessed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    assert!(assessed.contains(&"trufflehog"), "{first}");
    assert!(assessed.contains(&"kubeconfig"), "{first}");
    let engine_findings: Vec<_> = first["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["source"] == "trufflehog")
        .collect();
    assert_eq!(engine_findings.len(), 1, "{first}");
    assert_eq!(
        engine_findings[0]["verification"]["status"],
        "not_attempted"
    );
    assert!(!first.to_string().contains("RAWJWTVALUE"));
    let history = home.exposure_dir().join("history");
    let baseline = fs::read_dir(&history)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .to_string();

    // The engine is gone; the file it read is unchanged.
    fs::remove_file(&engine).unwrap();
    let html_path = home.root.join("report.html");
    let (output, second) = run_with(&["--html", html_path.to_str().unwrap()]);
    // The HTML is rendered from the same final report as the JSON: after
    // the history comparison found the engine's coverage missing.
    let html = fs::read_to_string(&html_path).unwrap();
    assert!(html.contains("Incomplete:"), "no incomplete banner: {html}");
    assert!(
        html.contains(
            "TruffleHog ran in the previous check and did not run in this one (not installed)"
        ),
        "{html}"
    );
    assert!(html.contains("Not assessed in this run (1)"), "{html}");
    assert!(html.contains("~/.azure/msal_token_cache.json"), "{html}");
    assert!(
        html.contains("not assessed in this run: not installed"),
        "{html}"
    );
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(second["incomplete"], true, "{second}");
    let changes = &second["changes"];
    assert_eq!(changes["counts"]["resolved"], 0, "{second}");
    assert_eq!(changes["counts"]["unassessed"], 1, "{second}");
    assert_eq!(
        changes["unassessed"][0]["location"],
        "~/.azure/msal_token_cache.json"
    );
    assert_eq!(changes["unassessed"][0]["reason"], "not installed");
    assert_eq!(changes["engine_coverage_lost"], true);
    assert_eq!(changes["notify"], true);
    let unavailable = second["sources_unavailable"].as_array().unwrap();
    assert!(
        unavailable
            .iter()
            .any(|u| u["source"] == "trufflehog" && u["reason"] == "not installed"),
        "{second}"
    );
    let failures = second["coverage_failures"].as_array().unwrap();
    assert!(
        failures.iter().any(|f| f["reason"]
            == "TruffleHog ran in the previous check and did not run in this one (not installed)"),
        "{second}"
    );

    let status: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
            .unwrap();
    assert_eq!(status["ok"], false, "{status}");
    assert_eq!(status["unassessed"], 1);
    assert_eq!(status["resolved"], 0);
    assert_eq!(status["baseline"], baseline, "the baseline is unchanged");
    let recorded: Vec<_> = fs::read_dir(&history).unwrap().collect();
    assert_eq!(recorded.len(), 2);

    let text = String::from_utf8_lossy(&home.run(&["schedule", "status"]).stdout).to_string();
    assert!(text.contains("1 unassessed"), "{text}");
    let (_, json) = home.json(&["schedule", "history", "--json"]);
    assert_eq!(json["runs"][0]["unassessed"], 1, "{json}");
    assert_eq!(json["runs"][0]["incomplete"], true);

    // A third run without the engine is compared with the same baseline:
    // still unassessed, still never resolved.
    let (_, third) = run();
    assert_eq!(third["changes"]["counts"]["unassessed"], 1, "{third}");
    assert_eq!(third["changes"]["counts"]["resolved"], 0);
}

/// The newest file in the history folder.
fn newest_run(home: &TestHome) -> String {
    let mut names: Vec<String> = fs::read_dir(home.exposure_dir().join("history"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names.pop().unwrap()
}

fn status(home: &TestHome) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
        .unwrap()
}

/// One profile of ~/.aws/credentials loses its `=`: that profile's
/// credential is not resolved but unassessed, the run is incomplete (exit
/// 3), and the run before stays the baseline.
#[test]
fn a_partially_malformed_aws_file_leaves_the_broken_profile_unassessed() {
    let home = TestHome::new();
    let creds = home.root.join("home/.aws/credentials");
    fs::create_dir_all(creds.parent().unwrap()).unwrap();
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let write = |prod_line: &str| {
        fs::write(
            &creds,
            format!("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = {secret}\n\n[prod]\naws_access_key_id = AKIAI44QH8DHBPRODKEY\n{prod_line}\n"),
        )
        .unwrap();
    };
    let run = || home.json(&["exposure", "--json", "--record", "--fail-on", "critical"]);
    write(&format!("aws_secret_access_key = {secret}"));
    let (output, first) = run();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(first["incomplete"], false, "{first}");
    let baseline = newest_run(&home);

    write(&format!("aws_secret_access_key {secret}"));
    let (output, second) = run();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(second["incomplete"], true, "{second}");
    let changes = &second["changes"];
    assert_eq!(changes["counts"]["resolved"], 0, "{second}");
    assert_eq!(changes["counts"]["unassessed"], 1, "{second}");
    assert_eq!(changes["unassessed"][0]["name"], "prod", "{second}");
    assert!(second["coverage_failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["reason"] == "could not interpret profile prod in ~/.aws/credentials"));
    let status = status(&home);
    assert_eq!(status["ok"], false);
    assert_eq!(status["baseline"], baseline, "the baseline is unchanged");
    assert!(!second.to_string().contains(secret));
}

/// The agent's identities are their own source. Running without
/// SSH_AUTH_SOCK (as a scheduler may) does not prove the agent stopped:
/// the identity recorded earlier is unassessed, the run incomplete (exit
/// 3) and not the baseline; with the variable back nothing is "new".
#[cfg(unix)]
#[test]
fn removing_ssh_auth_sock_leaves_agent_identities_unassessed() {
    use std::io::{Read, Write};
    // Socket paths are short on macOS: keep this one out of the test home.
    let sock = std::env::temp_dir().join(format!("ga{}.sock", rand::random::<u32>()));
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = [0u8; 5];
            if stream.read_exact(&mut request).is_err() {
                continue;
            }
            let blob = b"fake-agent-key-blob";
            let comment = b"me@laptop";
            let mut body = vec![12u8, 0, 0, 0, 1];
            body.extend((blob.len() as u32).to_be_bytes());
            body.extend(blob);
            body.extend((comment.len() as u32).to_be_bytes());
            body.extend(comment);
            let mut reply = (body.len() as u32).to_be_bytes().to_vec();
            reply.extend(body);
            let _ = stream.write_all(&reply);
        }
    });
    let home = TestHome::new();
    let run = |with_agent: bool| {
        let mut command = home.command();
        if with_agent {
            command.env("SSH_AUTH_SOCK", &sock);
        }
        let output = command
            .args(["exposure", "--json", "--record", "--fail-on", "critical"])
            .output()
            .expect("run gorse");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("invalid JSON: {e}; {output:?}"));
        (output, json)
    };

    let (output, first) = run(true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(first["incomplete"], false, "{first}");
    let agent: Vec<_> = first["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["source"] == "ssh-agent")
        .collect();
    assert_eq!(agent.len(), 1, "{first}");
    let baseline = newest_run(&home);

    let (output, second) = run(false);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(second["incomplete"], true, "{second}");
    assert_eq!(second["changes"]["counts"]["unassessed"], 1, "{second}");
    assert_eq!(second["changes"]["counts"]["resolved"], 0, "{second}");
    assert!(!second["sources_assessed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "ssh-agent"));
    assert!(second["sources_unavailable"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| {
            u["source"] == "ssh-agent"
            && u["reason"]
                == "SSH_AUTH_SOCK is not set in this environment, so the agent could not be asked"
        }));
    assert_eq!(
        status(&home)["baseline"],
        baseline,
        "the baseline is unchanged"
    );

    let (output, third) = run(true);
    let _ = fs::remove_file(&sock);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(third["changes"]["counts"]["new"], 0, "{third}");
    assert_eq!(third["incomplete"], false, "{third}");

    // A home that never had agent identities stays complete without the
    // variable.
    let fresh = TestHome::new();
    let (output, json) = fresh.json(&["exposure", "--json", "--record"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let (output, json2) = fresh.json(&["exposure", "--json", "--record"]);
    assert_eq!(output.status.code(), Some(0), "{output:?} {json} {json2}");
    assert_eq!(json2["incomplete"], false);
}

/// TruffleHog ran and found nothing; then it is gone. Nothing is
/// unassessed, but the files only it reads were not examined: the run is
/// incomplete (exit 3) and never becomes the baseline. A user who removed
/// the engine on purpose accepts the new state with
/// `gorse schedule accept-baseline`.
#[cfg(unix)]
#[test]
fn losing_an_engine_that_found_nothing_is_incomplete_until_accepted() {
    use std::os::unix::fs::PermissionsExt;
    let home = TestHome::new();
    let tools = home.root.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let engine = tools.join("trufflehog");
    fs::write(
        &engine,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'trufflehog 9.9.9'; exit 0; fi\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
    // Something for the engine to be handed.
    let cache = home.root.join("home/.azure/msal_token_cache.json");
    fs::create_dir_all(cache.parent().unwrap()).unwrap();
    fs::write(&cache, "{\"AccessToken\": {}}\n").unwrap();
    let run = || {
        let output = home
            .command()
            .env_remove("HEDGEHOG_NO_TRUFFLEHOG")
            .env("GORSE_TRUFFLEHOG", &engine)
            .args(["exposure", "--json", "--record"])
            .output()
            .expect("run gorse");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("invalid JSON: {e}; {output:?}"));
        (output, json)
    };
    let (output, first) = run();
    assert_eq!(output.status.code(), Some(0), "{output:?} {first}");
    assert!(first["sources_assessed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "trufflehog"));
    let baseline = newest_run(&home);

    fs::remove_file(&engine).unwrap();
    let (output, second) = run();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(second["incomplete"], true, "{second}");
    assert_eq!(second["changes"]["counts"]["unassessed"], 0);
    assert!(second["coverage_failures"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["reason"]
            == "TruffleHog ran in the previous check and did not run in this one (not installed)"));
    assert_eq!(status(&home)["baseline"], baseline);
    let lost = newest_run(&home);

    // Still lost on the next run: compared with the same baseline.
    let (output, _) = run();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(status(&home)["baseline"], baseline);
    let latest = newest_run(&home);
    assert_ne!(latest, lost);

    // The user accepts the run without the engine.
    let (output, json) = home.json(&["schedule", "accept-baseline", "--json"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(json["baseline"], latest.as_str());
    assert_eq!(json["accepted_by_user"], true);
    let stored: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(home.exposure_dir().join("history").join(&latest)).unwrap(),
    )
    .unwrap();
    assert_eq!(stored["accepted_by_user"], true);
    let (output, fourth) = run();
    assert_eq!(output.status.code(), Some(0), "{output:?} {fourth}");
    assert_eq!(fourth["incomplete"], false, "{fourth}");
    assert_eq!(status(&home)["baseline"], latest.as_str());

    let output = home.run(&["schedule", "accept-baseline"]);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("as the baseline"));
}

#[test]
fn accept_baseline_without_history_fails_cleanly() {
    let home = TestHome::new();
    let (output, json) = home.json(&["schedule", "accept-baseline", "--json"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("No recorded check"));
}

#[test]
fn exposure_without_record_leaves_no_history() {
    let home = TestHome::new();
    let (output, json) = home.json(&["exposure", "--json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(json.get("changes").is_none());
    assert!(!home.exposure_dir().exists());
}

#[test]
fn schedule_is_listed_in_help_without_prices() {
    let home = TestHome::new();
    let output = home.run(&["--help"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("schedule"), "{text}");
    assert!(text.contains("Scheduled checks"), "{text}");
    let output = home.run(&["schedule", "--help"]);
    let text = String::from_utf8_lossy(&output.stdout);
    for sub in ["set", "status", "run", "history", "accept-baseline"] {
        assert!(text.contains(sub), "{text}");
    }
    assert!(!text.contains('$'), "{text}");
    let output = home.run(&["exposure", "--help"]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("--record"), "--record stays hidden: {text}");
}

/// On macOS a build that is not signed by QKey (this test binary is unsigned
/// or ad-hoc signed) is refused by `schedule run` and `schedule set`, unless
/// the developer override is set; `schedule set off` always works.
#[cfg(target_os = "macos")]
#[test]
fn unsigned_program_is_refused_without_the_developer_override() {
    let home = TestHome::new();
    let mut command = home.command();
    command.env_remove("GORSE_ALLOW_UNSIGNED_SCHEDULE");
    let output = command.args(["schedule", "run"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.exposure_dir().join("status.json")).unwrap())
            .unwrap();
    assert_eq!(status["ok"], false);
    assert_eq!(
        status["message"],
        "program is not signed by QKey; schedule refused"
    );
    assert!(!home.exposure_dir().join("history").exists());

    let mut command = home.command();
    command.env_remove("GORSE_ALLOW_UNSIGNED_SCHEDULE");
    let output = command.args(["schedule", "set", "daily"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not signed by QKey"), "{stderr}");
    assert!(!home.exposure_dir().join("schedule.json").exists());

    let mut command = home.command();
    command.env_remove("GORSE_ALLOW_UNSIGNED_SCHEDULE");
    let output = command
        .args(["schedule", "set", "hourly", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("not signed by QKey"));
    assert_eq!(json["program_trusted"], false);
    assert!(json["program_team_id"].is_null());

    let mut command = home.command();
    command.env_remove("GORSE_ALLOW_UNSIGNED_SCHEDULE");
    let output = command
        .args(["schedule", "status", "--json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["program_trusted"], false);
    assert_eq!(json["program_in_applications"], false);
    let mut command = home.command();
    command.env_remove("GORSE_ALLOW_UNSIGNED_SCHEDULE");
    let output = command.args(["schedule", "status"]).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("Program signature: not signed by QKey"),
        "{text}"
    );
}
