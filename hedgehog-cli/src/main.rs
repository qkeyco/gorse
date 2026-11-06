// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Gorse CLI — cross-platform credential exfiltration protection.
//!
//! Commands:
//!   gorse status       — show taint engine status, secret count, platform info
//!   gorse scan         — scan for secrets and show protection status
//!   gorse check <cmd>  — check a command against security packs
//!   gorse explain <cmd>— explain why a command is blocked/allowed
//!   gorse daemon       — start the kernel-level taint tracking daemon
//!   gorse config       — show/edit unified configuration
//!   gorse audit <dir>  — audit a project directory for secrets
//!   gorse exposure     — what could an attacker reach if this laptop were compromised?
//!   gorse schedule     — run the exposure check daily or hourly and notify on change (Pro)
//!   gorse mcp          — run as MCP tool server (JSON-RPC over stdio)
//!   gorse shell-init   — output shell integration code (eval "$(gorse shell-init)")
//!   gorse dashboard    — unified view: secrets, hooks, activity, security status
//!   gorse history      — show recent command history from audit logs
//!   gorse allowlist    — manage network allowlist (add/remove/list)
//!   gorse watch        — monitor a package install for secret access
//!   gorse dns          — manage DNS resolver restrictions (list/add/remove)
//!   gorse project      — per-project allowlist scoping (init/list/show)
//!   gorse canary       — manage monitored credentials for security testing
//!   gorse alerts       — manage remote alert channels (Telegram, WhatsApp, SMS, webhook)
//!   gorse web          — open the web dashboard in your browser
//!   gorse install      — (preview) one-command setup: config, hooks, status check
//!   gorse uninstall    — (preview) remove all Gorse hooks
//!   gorse hook         — (preview) install the agent guard for one AI agent
//!   gorse activate     — activate a license key
//!   gorse deactivate   — remove license key from this machine
//!   gorse support      — generate a support bundle
//!   gorse version      — show version and platform info

use clap::{Parser, Subcommand};
use hedgehog_packs::PackEngine;
use hedgehog_taint::secrets::SecretDetector;

mod agent_taint;
mod alerting;
mod api_origin;
mod approvals;
mod canary;
mod canary_watcher;
mod config;
mod content_scanner;
mod credential_store;
mod device_link;
mod encrypted_store;
mod engines;
mod exposure;
mod heuristics;
mod history;
mod hook;
mod llm_classifier;
mod logging;
mod mcp;
mod release_signature;
mod reporting;
mod schedule;
mod script_scan;
mod selftest;
mod sso;
mod support;
mod team_dashboard;
mod trufflehog;
mod update_check;
mod web;

#[derive(Parser)]
#[command(
    name = "gorse",
    version,
    about = "Find the credentials on this computer and see what they could reach"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum LicenseCommand {
    /// Show machine ID and verified local lease status without revealing the key
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Renew at gorse.is (requires network and a current paid subscription)
    Refresh {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// What Gorse can see on this computer, and the licence state
    Status {
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
    },
    /// Scan the files on this computer for exposed secrets
    Scan {
        #[arg(long)]
        all: bool,
        /// Deep content scan: read files in Desktop/Documents/Downloads/Pictures
        #[arg(long)]
        deep: bool,
        /// Scan all of $HOME (slower, requires --deep)
        #[arg(long, requires = "deep")]
        all_dirs: bool,
        /// Output as JSON (for programmatic consumers, requires --deep)
        #[arg(long)]
        json: bool,
        /// Scan only these folders (repeatable, requires --deep). Skips the
        /// home-directory defaults, image OCR and Apple Notes.
        #[arg(long = "path", value_name = "DIR", requires = "deep")]
        paths: Vec<std::path::PathBuf>,
        /// Also scan folders the default rules skip: dependency, VCS and
        /// build folders, hidden folders and app bundles (requires --deep).
        #[arg(long, requires = "deep")]
        include_skipped: bool,
        /// With --json: stream progress as JSON lines on stderr while scanning
        /// (files read, findings so far, current folder). The apps use this.
        #[arg(long, requires = "json")]
        progress: bool,
        /// Do not run TruffleHog's detectors even when it is installed
        #[arg(long)]
        no_trufflehog: bool,
        /// Print, as JSON, the places a default deep scan reads, and exit
        /// (the apps show this list before the first scan)
        #[arg(long, hide = true)]
        list_places: bool,
        /// With --json: save progress to FILE so a stopped scan can carry on
        /// from where it stopped; a finished scan removes the file
        #[arg(long, value_name = "FILE", requires = "json", hide = true)]
        resume: Option<std::path::PathBuf>,
        /// Stop cleanly, reporting what was found, once FILE exists (how
        /// the apps stop a scan on Windows, where there is no SIGINT)
        #[arg(long, value_name = "FILE", hide = true)]
        stop_file: Option<std::path::PathBuf>,
        /// List every match instead of folding many of one kind in a file
        /// into one entry (release checks need each match)
        #[arg(long, hide = true)]
        all_matches: bool,
    },
    /// Check a command against the agent guard rules (preview)
    #[command(hide = true)]
    Check {
        /// Command words (when not using --hook)
        command: Vec<String>,
        /// Run as hook handler: read JSON from stdin (tool_name, tool_input, session_id)
        #[arg(long)]
        hook: bool,
    },
    /// Approve a blocked agent request once (run this yourself, in a terminal; preview)
    #[command(hide = true)]
    Allow {
        /// The id shown by `gorse allow` with no arguments
        id: Option<String>,
        /// Why you are approving it (recorded in the audit log)
        #[arg(long)]
        reason: Option<String>,
    },
    /// Explain why a command is blocked or allowed (preview)
    #[command(hide = true)]
    Explain { command: Vec<String> },
    /// Start the kernel-level taint tracking daemon (experimental)
    #[command(hide = true)]
    Daemon,
    /// Show or edit configuration
    Config {
        #[arg(long)]
        path: bool,
        #[arg(long)]
        init: bool,
    },
    /// Turn on the agent guard for one AI coding agent (preview)
    #[command(hide = true)]
    Hook {
        #[arg(value_enum)]
        agent: Agent,
    },
    /// Send a team report to the dashboard (requires team-tier license)
    Report,
    /// Activate Pro on this computer: in the browser (--browser) or with a key
    Activate {
        /// License key (prefer --stdin to keep it out of process arguments)
        #[arg(required_unless_present_any = ["stdin", "browser", "browser_start"], conflicts_with_all = ["stdin", "browser", "browser_start", "browser_wait"])]
        key: Option<String>,
        /// Read a bounded key from standard input
        #[arg(long)]
        stdin: bool,
        /// Sign in on gorse.is in the browser and confirm a code; no key to copy
        #[arg(long, conflicts_with_all = ["stdin", "browser_start", "browser_wait"])]
        browser: bool,
        /// For the apps: start a browser activation and print its code and page as JSON
        #[arg(long, hide = true, conflicts_with_all = ["stdin", "browser_wait"])]
        browser_start: bool,
        /// For the apps: wait for a browser activation; the device secret is read from standard input
        #[arg(long, hide = true, requires = "stdin")]
        browser_wait: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect or renew a signed machine-bound paid lease
    License {
        #[command(subcommand)]
        command: LicenseCommand,
    },
    /// Remove the license key from this machine
    Deactivate {
        #[arg(long)]
        json: bool,
    },
    /// Generate a support bundle for troubleshooting
    Support {
        /// Upload the bundle to Gorse support (requires network)
        #[arg(long)]
        upload: bool,
        /// Ticket subject (required with --upload)
        #[arg(long)]
        subject: Option<String>,
        /// Ticket description (required with --upload)
        #[arg(long)]
        description: Option<String>,
    },
    /// Audit a project directory for secrets and security issues
    Audit {
        /// Directory to scan
        path: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// What could an attacker reach if this laptop were compromised? (read-only)
    #[command(
        after_help = "Exit codes:\n  0  complete, nothing at or above the --fail-on severity\n  1  a finding is at or above the --fail-on severity (default high)\n  2  the check could not run\n  3  incomplete: a known credential location could not be read or interpreted (or a source a recorded run assessed was not assessed this time), and nothing met the threshold"
    )]
    Exposure {
        /// Output as JSON (for programmatic consumers)
        #[arg(long)]
        json: bool,
        /// Confirm identities and permissions with read-only provider queries (aws, gh, kubectl, vault, gcloud, az, doctl, eth_getCode)
        #[arg(long)]
        verify: bool,
        /// Write a self-contained HTML report with the permission graph to this file
        #[arg(long, value_name = "FILE")]
        html: Option<std::path::PathBuf>,
        /// Infrastructure map to use instead of ~/.hedgehog/authority.toml
        #[arg(long, value_name = "FILE")]
        map: Option<std::path::PathBuf>,
        /// Maximum hops when searching indirect paths (default from the map, 6)
        #[arg(long)]
        max_hops: Option<usize>,
        /// Write an example ~/.hedgehog/authority.toml and exit
        #[arg(long)]
        init: bool,
        /// Exit 1 when any finding is at or above this severity: critical, high (default), medium or low (exit 3 means incomplete)
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,
        /// Record a host or system name as production in the map and exit (the apps use this)
        #[arg(long, value_name = "NAME")]
        mark_production: Option<String>,
        /// Do not run TruffleHog over the known credential locations even if it is installed
        #[arg(long)]
        no_trufflehog: bool,
        /// Record this run in the check history and compare it with the previous one (the apps use this)
        #[arg(long, hide = true)]
        record: bool,
    },
    /// Scheduled checks: run the exposure check automatically every day or every hour and get a notification when something new appears (Pro)
    #[command(subcommand)]
    Schedule(schedule::ScheduleCommand),
    /// Optional engines: add TruffleHog's detectors with one download
    #[command(subcommand)]
    Engines(EnginesCommand),
    /// Run as MCP tool server (JSON-RPC over stdio)
    Mcp,
    /// Output shell integration code (eval "$(gorse shell-init)") (preview)
    #[command(hide = true)]
    ShellInit {
        /// Shell type: bash, zsh, or fish (auto-detected if omitted)
        #[arg(long)]
        shell: Option<String>,
    },
    /// Check a command from the shell interceptor (internal use)
    #[command(hide = true)]
    ShellCheck {
        /// The command to check
        command: Vec<String>,
    },
    /// Unified dashboard: secrets, agent guard activity and security status (preview)
    #[command(hide = true)]
    Dashboard {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show recent agent guard history from audit logs (preview)
    #[command(hide = true)]
    History {
        /// Number of days to show (default: 7)
        #[arg(short, long, default_value = "7")]
        days: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Manage the network allowlist (domains, IPs, suffixes) (experimental)
    #[command(subcommand, hide = true)]
    Allowlist(AllowlistCommand),
    /// Monitor a package install for secret access (npm, pip, etc.) (experimental)
    #[command(hide = true)]
    Watch {
        /// Package manager command to run (e.g., "npm install")
        command: Vec<String>,
    },
    /// Manage DNS resolver restrictions (experimental)
    #[command(subcommand, hide = true)]
    Dns(DnsCommand),
    /// Per-project allowlist scoping (experimental)
    #[command(subcommand, hide = true)]
    Project(ProjectCommand),
    /// Open the web dashboard in your browser (preview)
    #[command(hide = true)]
    Web {
        /// Port to serve on (default: 3141)
        #[arg(short, long, default_value = "3141")]
        port: u16,
        /// Don't open browser automatically
        #[arg(long)]
        no_open: bool,
    },
    /// Show the process tree for tainted processes (experimental)
    #[command(hide = true)]
    Ptree {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Install as a systemd service (Linux only, experimental)
    #[command(hide = true)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Manage monitored credentials for security testing (experimental)
    #[command(subcommand, hide = true)]
    Canary(CanaryCommand),
    /// Review and install local secret access monitoring policy (experimental)
    #[command(subcommand, hide = true)]
    Secrets(canary::secret_policy::SecretCommand),
    /// Manage remote alert channels (Telegram, WhatsApp, SMS, webhook) (experimental)
    #[command(subcommand, hide = true)]
    Alerts(AlertsCommand),
    /// Log in via enterprise SSO (experimental)
    #[command(hide = true)]
    SsoLogin,
    /// Turn on the agent guard for every supported AI coding agent found here (preview)
    #[command(hide = true)]
    Install,
    /// Turn the agent guard off for all agents (preview)
    #[command(hide = true)]
    Uninstall,
    /// Show version and platform info
    Version {
        /// Ask gorse.is whether a newer version exists (one request, carries only this version)
        #[arg(long)]
        check: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check that a downloaded Gorse file is the one QKey published
    VerifyDownload {
        /// The downloaded file (a .zip or .dmg from gorse.is)
        file: std::path::PathBuf,
        /// The release to check against, such as v0.4.1 (default: the latest release)
        #[arg(long)]
        tag: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Prepare a private project snapshot for offline execution; does not run code (experimental)
    #[command(hide = true)]
    WorkspaceSnapshot {
        #[arg(long)]
        source: std::path::PathBuf,
        /// New private JSON file; existing files are never overwritten
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Check shipped logic, or explicitly test installed canary sensing and delivery
    Selftest {
        /// Emit machine-readable JSON (for CI)
        #[arg(long)]
        json: bool,
        /// Fail unless kernel events and network blocking both report active
        /// (checks runtime status, not whether a connection is blocked)
        #[arg(long)]
        require_protection: bool,
        /// Open a temporary synthetic decoy and await test alerts through configured channels
        /// (requires the installed macOS sensor and a running canary daemon)
        #[arg(long, conflicts_with = "require_protection")]
        canary: bool,
        /// Maximum seconds to await the canary event and provider acceptance
        #[arg(long, default_value_t = 30, requires = "canary", value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout_seconds: u64,
    },
}

#[derive(Subcommand)]
enum EnginesCommand {
    /// Which optional engines are installed
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Download and install an engine (today: trufflehog). One download from
    /// Truffle Security's GitHub release, checked against a pinned checksum.
    Install {
        /// Engine name: trufflehog
        name: String,
        #[arg(long)]
        json: bool,
        /// With --json: stream download progress as JSON lines on stderr
        #[arg(long, requires = "json")]
        progress: bool,
    },
    /// Remove an installed engine
    Remove {
        name: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install and start the systemd service
    Install,
    /// Stop and disable the systemd service
    Uninstall,
    /// Show service status
    Status,
}

#[derive(Subcommand)]
enum AllowlistCommand {
    /// List all allowlisted domains, suffixes, and IPs
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a domain, suffix, or IP to the allowlist
    Add {
        /// Type: domain, suffix, or ip
        #[arg(value_enum)]
        entry_type: AllowlistEntryType,
        /// Value to add (e.g., "github.com", ".example.org", "1.2.3.4")
        value: String,
    },
    /// Remove a domain, suffix, or IP from the allowlist
    Remove {
        /// Type: domain, suffix, or ip
        #[arg(value_enum)]
        entry_type: AllowlistEntryType,
        /// Value to remove
        value: String,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum AllowlistEntryType {
    Domain,
    Suffix,
    Ip,
}

#[derive(Subcommand)]
enum DnsCommand {
    /// List configured DNS resolvers (system + custom)
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a trusted DNS resolver IP
    Add {
        /// DNS resolver IP address (e.g., "8.8.8.8")
        ip: String,
    },
    /// Remove a custom DNS resolver IP
    Remove {
        /// DNS resolver IP to remove
        ip: String,
    },
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// Initialize a hedgehog.toml in the current directory
    Init {
        /// Project name (defaults to directory name)
        #[arg(long)]
        name: Option<String>,
    },
    /// List all detected gorse projects
    List,
    /// Show the current project's config
    Show,
}

#[derive(Subcommand)]
enum CanaryCommand {
    /// Show the canary monitor's last reported health and coverage
    Status,
    /// Generate and place test credentials in a directory
    Create {
        /// Directory to place credentials (default: current directory)
        #[arg(long)]
        dir: Option<String>,
    },
    /// List all monitored credentials
    List,
    /// Show security alert history
    Alerts,
    /// Remove all monitored credentials and files
    Remove,
}

#[derive(Subcommand)]
enum AlertsCommand {
    /// Send a test alert to all configured channels
    Test,
    /// Interactive setup for alert channels
    Setup,
    /// Show configured alert channels and status
    Status,
    /// Deliver due persisted alarms using the configured channels
    Deliver,
    /// Store external heartbeat enrollment JSON from stdin (url, monitor_id, token)
    HeartbeatEnroll,
    /// Send one availability report; the daemon sends every 30 seconds
    Heartbeat,
}

#[derive(clap::ValueEnum, Clone)]
enum Agent {
    ClaudeCode,
    Copilot,
    Aider,
    Continue,
    Codex,
    Gemini,
    /// Documented as `gorse hook opencode`; clap would otherwise only accept `open-code`.
    #[value(alias = "opencode")]
    OpenCode,
}

fn main() {
    // Rust ignores SIGPIPE and turns a closed pipe into a write error, which
    // surfaces as a panic when the user runs `gorse scan | head`. Restore
    // the conventional behaviour so the process exits quietly instead.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { json } => cmd_status(json),
        Commands::Scan {
            all,
            deep,
            all_dirs,
            json,
            paths,
            include_skipped,
            progress,
            no_trufflehog,
            list_places,
            resume,
            stop_file,
            all_matches,
        } => {
            if list_places {
                let places = content_scanner::default_scan_places();
                println!("{}", serde_json::json!({ "places": places }));
            } else if deep {
                cmd_deep_scan(
                    all_dirs,
                    json,
                    &paths,
                    include_skipped,
                    progress,
                    no_trufflehog,
                    resume.as_deref(),
                    stop_file.as_deref(),
                    all_matches,
                );
            } else {
                cmd_scan(all);
            }
        }
        Commands::Check {
            command: _,
            hook: true,
        } => cmd_check_hook(),
        Commands::Check {
            command,
            hook: false,
        } => cmd_check(&command.join(" ")),
        Commands::Allow { id, reason } => cmd_allow(id.as_deref(), reason.as_deref()),
        Commands::Explain { command } => cmd_explain(&command.join(" ")),
        Commands::Daemon => cmd_daemon(),
        Commands::Config { path, init } => cmd_config(path, init),
        Commands::Hook { agent } => cmd_hook(agent),
        Commands::Report => cmd_report(),
        Commands::Activate {
            key,
            stdin,
            browser,
            browser_start,
            browser_wait,
            json,
        } => {
            if browser {
                cmd_activate_browser(json)
            } else if browser_start {
                cmd_activate_browser_start(json)
            } else if browser_wait {
                cmd_activate_browser_wait(json)
            } else {
                cmd_activate(key, stdin, json)
            }
        }
        Commands::Deactivate { json } => cmd_deactivate(json),
        Commands::License { command } => match command {
            LicenseCommand::Status { json } => print_license_status(json),
            LicenseCommand::Refresh { json } => {
                if let Err(error) = credential_store::refresh_license() { license_error(&error, json); }
                print_license_status(json);
            }
        },
        Commands::Support {
            upload,
            subject,
            description,
        } => {
            if upload {
                let subj = subject.unwrap_or_else(|| {
                    eprintln!("--subject is required with --upload");
                    std::process::exit(1);
                });
                let desc = description.unwrap_or_default();
                support::cmd_support_upload(&subj, &desc);
            } else {
                support::cmd_support_local();
            }
        }
        Commands::Audit { path, json } => cmd_audit(&path, json),
        Commands::Exposure {
            json,
            verify,
            html,
            map,
            max_hops,
            init,
            fail_on,
            mark_production,
            no_trufflehog,
            record,
        } => cmd_exposure(
            json,
            verify,
            html,
            map,
            max_hops,
            init,
            fail_on,
            mark_production,
            !no_trufflehog,
            record,
        ),
        Commands::Schedule(cmd) => schedule::cmd_schedule(cmd),
        Commands::Engines(cmd) => cmd_engines(cmd),
        Commands::Mcp => mcp::run_server(),
        Commands::ShellInit { shell } => cmd_shell_init(shell),
        Commands::ShellCheck { command } => cmd_shell_check(&command.join(" ")),
        Commands::Dashboard { json } => cmd_dashboard(json),
        Commands::History { days, json } => cmd_history(days, json),
        Commands::Allowlist(sub) => cmd_allowlist(sub),
        Commands::Watch { command } => cmd_watch(&command),
        Commands::Dns(sub) => cmd_dns(sub),
        Commands::Project(sub) => cmd_project(sub),
        Commands::Web { port, no_open } => web::serve(port, no_open),
        Commands::Ptree { json } => cmd_ptree(json),
        Commands::Service { action } => cmd_service(action),
        Commands::Canary(sub) => match sub {
            CanaryCommand::Status => {
                for line in canary_watcher::status_lines() {
                    println!("{line}");
                }
            }
            CanaryCommand::Create { dir } => canary::cmd_create(dir.as_deref()),
            CanaryCommand::List => canary::cmd_list(),
            CanaryCommand::Alerts => canary::cmd_alerts(),
            CanaryCommand::Remove => canary::cmd_remove(),
        },
        Commands::Secrets(command) => canary::secret_policy::run_command(command),
        Commands::Alerts(sub) => match sub {
            AlertsCommand::HeartbeatEnroll => {
                use std::io::Read;
                let mut bytes = Vec::new();
                let result = std::io::stdin().take(4097).read_to_end(&mut bytes)
                    .map_err(|_| "Cannot read heartbeat enrollment".to_string())
                    .and_then(|_| alerting::enroll_heartbeat(&bytes));
                if let Err(error) = result { eprintln!("{error}"); std::process::exit(1); }
                println!("External heartbeat enrolled locally. Run the daemon to send every 30 seconds; remote supervision starts at server enrollment.");
            }
            AlertsCommand::Heartbeat => match alerting::send_heartbeat() {
                Ok(true) => println!("Heartbeat server acknowledged this availability report; enforcement was not tested."),
                Ok(false) => { eprintln!("External heartbeat is not enrolled"); std::process::exit(1); }
                Err(error) => { eprintln!("{error}"); std::process::exit(1); }
            },
            AlertsCommand::Test => cmd_alerts_test(),
            AlertsCommand::Setup => cmd_alerts_setup(),
            AlertsCommand::Status => cmd_alerts_status(),
            AlertsCommand::Deliver => match alerting::deliver_pending() {
                Ok(count) => {
                    println!("{count} queued event(s) accepted by configured providers.");
                    cmd_alerts_status();
                }
                Err(e) => {
                    eprintln!("Alert delivery incomplete: {e}");
                    std::process::exit(1);
                }
            },
        },
        Commands::SsoLogin => cmd_sso_login(),
        Commands::Install => cmd_install(),
        Commands::Uninstall => cmd_uninstall(),
        Commands::Version { check, json } => cmd_version(check, json),
        Commands::VerifyDownload { file, tag, json } => cmd_verify_download(&file, tag, json),
        Commands::WorkspaceSnapshot { source, output } => {
            if let Err(error) = workspace_snapshot(&source, &output) {
                eprintln!("Workspace snapshot failed: {error}");
                std::process::exit(1);
            }
        }
        Commands::Selftest {
            json,
            require_protection,
            canary,
            timeout_seconds,
        } => {
            if canary {
                selftest::cmd_canary_selftest(json, timeout_seconds);
            } else {
                selftest::cmd_selftest(json, require_protection);
            }
        }
    }
}

/// Copy selected project data through anchored directory descriptors. No
/// source path is reopened through an ancestor that an attacker can replace.
/// The snapshot is an input artifact, not a verdict that its code is safe.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn workspace_snapshot(source: &std::path::Path, output: &std::path::Path) -> Result<(), String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::ffi::{CStr, CString};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    fn open_directory(path: &std::path::Path) -> Result<std::fs::File, String> {
        use std::path::Component;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| "Cannot resolve the working directory")?
                .join(path)
        };
        let mut directory = std::fs::File::open("/").map_err(|_| "Cannot open filesystem root")?;
        for component in absolute.components() {
            let name = match component {
                Component::Normal(name) => name,
                Component::ParentDir => std::ffi::OsStr::new(".."),
                Component::RootDir | Component::CurDir => continue,
                Component::Prefix(_) => return Err("Unsupported path prefix".into()),
            };
            let name = CString::new(name.as_bytes()).map_err(|_| "Invalid directory path")?;
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(
                    "Every directory component must be readable and must not be a symlink".into(),
                );
            }
            directory = unsafe { std::fs::File::from_raw_fd(descriptor) };
        }
        Ok(directory)
    }

    #[derive(serde::Serialize)]
    struct InputFile {
        path: String,
        content: String,
        sha256: String,
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    fn excluded(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        name == ".env"
            || name.starts_with(".env.")
            || name.starts_with(".hedgehog-canary-")
            || [
                ".git",
                ".hg",
                ".svn",
                ".ssh",
                ".gnupg",
                ".kube",
                ".docker",
                ".aws",
                ".azure",
                ".config",
                ".hedgehog",
                ".npmrc",
                ".netrc",
                ".pypirc",
                ".yarnrc",
                ".yarnrc.yml",
                "node_modules",
                ".ds_store",
            ]
            .contains(&name.as_str())
    }
    fn walk(
        dir: &std::fs::File,
        prefix: &str,
        depth: usize,
        files: &mut Vec<InputFile>,
        total: &mut usize,
        skipped: &mut usize,
        entries: &mut usize,
    ) -> Result<(), String> {
        if depth > 32 {
            return Err("Project directory depth exceeds 32".into());
        }
        let duplicate = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err("Cannot open project directory stream".into());
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            unsafe {
                libc::close(duplicate);
            }
            return Err("Cannot read project directory".into());
        }
        let stream = Directory(stream);
        let mut names = Vec::new();
        loop {
            // readdir returns NULL on both completion and error; errno must be
            // reset for each call to avoid silently accepting an incomplete tree.
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != 0 {
                    return Err("Project directory enumeration failed".into());
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            *entries += 1;
            if *entries > 8192 {
                return Err("Project exceeds the 8192 entry limit".into());
            }
            let name = std::str::from_utf8(bytes).map_err(|_| "Project paths must be UTF-8")?;
            if !name.is_ascii()
                || name.len() > 255
                || name.chars().any(|c| c.is_control())
                || name.contains(['/', '\\', ':'])
            {
                return Err("This experimental snapshot requires portable ASCII filenames".into());
            }
            if excluded(name) {
                *skipped += 1;
                continue;
            }
            names.push(name.to_string());
            if names.len() > 4096 {
                return Err("Project directory entry limit exceeded".into());
            }
        }
        names.sort();
        let mut folded = std::collections::HashSet::new();
        for name in names {
            if !folded.insert(name.to_ascii_lowercase()) {
                return Err("Case-colliding project entries are unsupported".into());
            }
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if relative.len() > 1024 {
                return Err("Project path length exceeds limit".into());
            }
            let component = CString::new(name).map_err(|_| "Invalid project filename")?;
            let descriptor = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK
                        | libc::O_NOCTTY,
                )
            };
            if descriptor < 0 {
                return Err(
                    "Cannot safely open project entry; symlinks and unreadable paths are rejected"
                        .into(),
                );
            }
            let mut file = unsafe { std::fs::File::from_raw_fd(descriptor) };
            let before = file
                .metadata()
                .map_err(|_| "Cannot inspect project entry")?;
            if before.is_dir() {
                walk(&file, &relative, depth + 1, files, total, skipped, entries)?;
            } else if before.is_file() && before.nlink() == 1 {
                if files.len() >= 4096 || before.len() > 4 * 1024 * 1024 {
                    return Err("Project file count or 4 MiB per-file limit exceeded".into());
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take(4 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "Project file could not be read")?;
                let after = file.metadata().map_err(|_| "Cannot recheck project file")?;
                if bytes.len() as u64 != before.len()
                    || before.len() != after.len()
                    || before.mtime() != after.mtime()
                    || before.mtime_nsec() != after.mtime_nsec()
                    || before.ctime() != after.ctime()
                    || before.ctime_nsec() != after.ctime_nsec()
                    || after.nlink() != 1
                {
                    return Err("Project file changed while being captured".into());
                }
                *total += bytes.len();
                if *total > 16 * 1024 * 1024 {
                    return Err("Project exceeds the 16 MiB snapshot limit".into());
                }
                files.push(InputFile {
                    path: relative,
                    sha256: format!("{:x}", Sha256::digest(&bytes)),
                    content: base64::engine::general_purpose::STANDARD.encode(bytes),
                });
            } else {
                return Err("Project hard links and special files are unsupported".into());
            }
        }
        Ok(())
    }
    let dir = open_directory(source)?;
    let output_parent = open_directory(output.parent().unwrap_or(std::path::Path::new(".")))?;
    let output_name = CString::new(
        output
            .file_name()
            .ok_or("Output needs a filename")?
            .as_bytes(),
    )
    .map_err(|_| "Invalid output filename")?;
    let mut files = Vec::new();
    let mut total = 0;
    let mut skipped = 0;
    let mut entries = 0;
    walk(
        &dir,
        "",
        0,
        &mut files,
        &mut total,
        &mut skipped,
        &mut entries,
    )?;
    // Case-folded duplicate paths cannot be safely imported on every target.
    let mut paths = std::collections::HashSet::new();
    for file in &files {
        if !paths.insert(file.path.to_lowercase()) {
            return Err("Case-colliding project paths are unsupported".into());
        }
    }
    let document =
        serde_json::json!({ "schema": 1, "kind":"hedgehog_offline_workspace", "files":files });
    let bytes = serde_json::to_vec(&document).map_err(|_| "Cannot encode project snapshot")?;
    let output_descriptor = unsafe {
        libc::openat(
            output_parent.as_raw_fd(),
            output_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if output_descriptor < 0 {
        return Err("Snapshot output must be a new private file".into());
    }
    let mut out = unsafe { std::fs::File::from_raw_fd(output_descriptor) };
    out.write_all(&bytes)
        .and_then(|_| out.sync_all())
        .map_err(|_| "Snapshot write failed; inspect the partial output")?;
    println!(
        "{}",
        serde_json::json!({ "schema":1, "scope":"workspace_snapshot", "files":files.len(),
        "bytes":total, "excluded_entries":skipped, "execution_started":false, "contains_untrusted_project_data":true })
    );
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn workspace_snapshot(_source: &std::path::Path, _output: &std::path::Path) -> Result<(), String> {
    Err("Safe directory-descriptor snapshotting is currently supported on macOS and Linux".into())
}

/// Load the pack engine with built-in + custom packs from ~/.hedgehog/packs/.
/// If DCG is detected, disables overlapping Gorse categories.
fn load_engine() -> PackEngine {
    let custom_dir = config::packs_dir();
    let mut engine = PackEngine::builtin_with_custom(&custom_dir).unwrap_or_else(|e| {
        eprintln!("Warning: failed to load custom packs: {e}");
        PackEngine::builtin().unwrap()
    });

    // G-04: DCG coexistence — if DCG is installed, disable overlapping categories
    // to avoid double-blocking. Gorse's unique value is exfiltration protection,
    // not command blocking (DCG handles that).
    if dcg_detected() {
        // DCG covers destructive commands comprehensively
        engine.disable_category("destructive");
        log::info!("DCG detected — disabled 'destructive' category (DCG handles it)");
    }

    engine
}

/// Detect whether DCG (Destructive Command Guard) is installed.
fn dcg_detected() -> bool {
    // Check for DCG binary on PATH
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join("dcg").exists() {
                return true;
            }
        }
    }
    // Check for DCG config directory
    if let Ok(home) = std::env::var("HOME") {
        if std::path::Path::new(&home).join(".dcg").exists() {
            return true;
        }
    }
    false
}

/// What is actually enforcing on this machine and what it covers.
///
/// "Found" means a watched credential location exists on disk. "Protected"
/// means an enforcement layer is live right now: an agent hook whose command
/// was just run and refused a canary upload, or the kernel sensor reporting a
/// fresh heartbeat. A watch list on its own protects nothing, and nothing
/// absent can be protected, so without a live layer the count is zero.
pub(crate) struct Protection {
    /// Every watched credential location, present or not (for `scan --all`).
    /// Gorse's own files are already left out.
    pub(crate) watched: Vec<hedgehog_taint::secrets::WatchedLocation>,
    pub(crate) hooks: Vec<hook::HookStatus>,
    pub(crate) sensor_running: bool,
}

/// The watched credential locations on this machine (present or not), with
/// platform extras added and Gorse's own files left out.
pub(crate) fn credential_locations() -> Vec<hedgehog_taint::secrets::WatchedLocation> {
    let mut detector = SecretDetector::new();
    add_platform_secrets(&mut detector);
    detector.credential_locations()
}

impl Protection {
    pub(crate) fn gather() -> Self {
        Self {
            watched: credential_locations(),
            hooks: hook::installed_hooks(),
            sensor_running: sensor_running(),
        }
    }

    pub(crate) fn found(&self) -> Vec<&hedgehog_taint::secrets::WatchedLocation> {
        self.watched.iter().filter(|l| l.present).collect()
    }

    pub(crate) fn found_count(&self) -> usize {
        self.watched.iter().filter(|l| l.present).count()
    }

    pub(crate) fn live_hooks(&self) -> Vec<&hook::HookStatus> {
        self.hooks.iter().filter(|h| h.live).collect()
    }

    fn broken_hooks(&self) -> Vec<&hook::HookStatus> {
        self.hooks.iter().filter(|h| !h.live).collect()
    }

    pub(crate) fn enforcing(&self) -> bool {
        self.sensor_running || !self.live_hooks().is_empty()
    }

    pub(crate) fn protected_count(&self) -> usize {
        if self.enforcing() {
            self.found_count()
        } else {
            0
        }
    }

    pub(crate) fn hooks_json(&self) -> Vec<serde_json::Value> {
        self.hooks.iter().map(|h| h.to_json()).collect()
    }

    /// The honest "protected" line(s), ready to print after a found count.
    pub(crate) fn protection_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let live = self.live_hooks();
        let broken = self.broken_hooks();
        let count = self.protected_count();

        if self.enforcing() {
            let mut guards: Vec<String> = Vec::new();
            match live.len() {
                0 => {}
                1 => guards.push(format!("the {} hook", live[0].agent)),
                _ => {
                    let names: Vec<&str> = live.iter().map(|h| h.agent).collect();
                    let (last, rest) = names.split_last().unwrap();
                    guards.push(format!("the {} and {last} hooks", rest.join(", ")));
                }
            }
            if self.sensor_running {
                guards.push("the Gorse sensor".to_string());
            }
            let what = match (live.is_empty(), self.sensor_running) {
                (false, false) => {
                    "commands that upload, read or destroy these are blocked inside the agent"
                }
                (true, true) => {
                    "every program that reads these is tracked and blocked from uploading them"
                }
                _ => "blocked inside the agent by the hook, and tracked system-wide by the sensor",
            };
            // "Guarded by the Claude Code hook: 7 (...)"
            lines.push(format!(
                "Guarded by {}: {count} ({what})",
                guards.join(" and ")
            ));
        } else if self.hooks.is_empty() {
            lines.push("Protected by a hook: 0  (no agent hook is installed)".to_string());
        } else {
            let names: Vec<String> = broken
                .iter()
                .map(|h| format!("the {} hook", h.agent))
                .collect();
            lines.push(format!(
                "Protected by a hook: 0  ({} is installed but broken — run `gorse install` to repair it)",
                names.join(" and ")
            ));
        }
        for hook in &broken {
            lines.push(format!(
                "Broken hook: {} — {}",
                hook.agent,
                hook.problem
                    .as_deref()
                    .unwrap_or("failed the liveness check")
            ));
        }
        lines
    }
}

/// Is the kernel sensor (macOS system extension, or the Linux/Windows
/// daemon) reporting a fresh heartbeat? Reads the same `status.json` the
/// selftest uses: `esf` must be `active` and `updated` within two minutes.
fn sensor_running() -> bool {
    const FRESH_SECS: i64 = 120;
    let candidates = [
        shared_state_dir().join("status.json"),
        config::config_dir().join("status.json"),
    ];
    for path in candidates {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(status) = serde_json::from_str::<serde_json::Value>(&contents) else {
            continue;
        };
        let active = status.get("esf").and_then(|v| v.as_str()) == Some("active");
        let fresh = status
            .get("updated")
            .and_then(|u| u.as_str())
            .and_then(|updated| chrono::DateTime::parse_from_rfc3339(updated).ok())
            .map(|then| {
                let age = chrono::Utc::now() - then.with_timezone(&chrono::Utc);
                age >= chrono::Duration::zero() && age.num_seconds() <= FRESH_SECS
            })
            .unwrap_or(false);
        if active && fresh {
            return true;
        }
    }
    false
}

fn cmd_status(json: bool) {
    let protection = Protection::gather();
    let total = protection.found_count();
    let protected = protection.protected_count();
    let unprotected = total - protected;

    let engine = load_engine();
    let dcg = dcg_detected();
    let activity = logging::recent_activity(7);

    if json {
        let output = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": platform_name(),
            "arch": std::env::consts::ARCH,
            "secrets_total": total,
            "secrets_protected": protected,
            "secrets_unprotected": unprotected,
            "hooks": protection.hooks_json(),
            "sensor_running": protection.sensor_running,
            "tier": credential_store::current_tier().name(),
            "license": credential_store::status(),
            "issuer_public_key": credential_store::issuer_public_key_base64url(),
            "issuer_public_key": credential_store::issuer_public_key_base64url(),
            "rules_loaded": engine.rule_count(),
            "kernel_bridge": kernel_bridge_status(),
            "dcg_detected": dcg,
            "activity_7d": {
                "blocks": activity.blocks,
                "allows": activity.allows,
                "approvals": activity.approvals,
                "total": activity.total_events,
            },
        });
        println!("{}", serde_json::to_string(&output).unwrap());
        return;
    }

    println!("Gorse v{}", env!("CARGO_PKG_VERSION"));
    println!("Platform: {}", platform_name());
    println!("Credential locations found: {total}");
    for line in protection.protection_lines() {
        println!("{line}");
    }
    println!("Tier: {}", credential_store::current_tier().name());
    println!("Security packs: {} rules loaded", engine.rule_count());
    if dcg {
        println!("DCG: detected (destructive category deferred to DCG)");
    }
    println!(
        "Kernel bridge: {}{}",
        kernel_bridge_status(),
        if protection.sensor_running {
            " — sensor running"
        } else {
            ""
        }
    );

    // Recent activity summary
    if activity.total_events > 0 {
        println!();
        println!(
            "Activity (7d): {} blocks, {} allows, {} approvals",
            activity.blocks, activity.allows, activity.approvals
        );
    }
    if let Some(line) = update_check::passive_notice() {
        println!("{line}");
    }
}

fn cmd_scan(show_all: bool) {
    let protection = Protection::gather();
    let total = protection.found_count();

    println!("Secret scan results:");
    println!("====================\n");

    let priority_label = |p: hedgehog_taint::secrets::SecretPriority| match p {
        hedgehog_taint::secrets::SecretPriority::Critical => "CRITICAL",
        hedgehog_taint::secrets::SecretPriority::High => "HIGH",
        hedgehog_taint::secrets::SecretPriority::Medium => "MEDIUM",
    };

    if total == 0 {
        println!("  No credential files found in the usual locations.");
    }
    for location in protection.found() {
        println!(
            "  [FOUND] [{}] {}",
            priority_label(location.priority),
            location.path.display()
        );
        println!("          {}", location.description);
    }
    if show_all {
        let absent: Vec<_> = protection.watched.iter().filter(|l| !l.present).collect();
        if !absent.is_empty() {
            println!();
            println!("  Watched but not present on this machine:");
            for location in absent {
                println!(
                    "  [not present] [{}] {}",
                    priority_label(location.priority),
                    location.path.display()
                );
            }
        }
    } else {
        let absent = protection.watched.len() - total;
        if absent > 0 {
            println!();
            println!(
                "  {absent} more watched location{} not present on this machine (`gorse scan --all` lists them).",
                if absent == 1 { " is" } else { "s are" }
            );
        }
    }

    println!();
    println!("Credential locations found: {total}");
    for line in protection.protection_lines() {
        println!("{line}");
    }
    println!("Run `gorse exposure` to see what these credentials could reach if this laptop were compromised.");
}

// ─── Dashboard UI for deep scan ─────────────────────────────────────────────

const CATEGORIES: &[&str] = &[
    "API Keys",
    "Passwords",
    "Crypto Keys",
    "Seed Phrases",
    "Auth Tokens",
    "DB Credentials",
    "Financial",
    "Identity (SSN)",
    "2FA Codes",
    ".env Files",
    "Suspicious Images",
    "Apple Notes",
    "Sensitivity Labels",
];

/// Total lines the dashboard occupies on screen.
/// header(2) + categories(13) + divider(1) + total(1) + blank(1) + progress(1) + status(1) = 20
const DASHBOARD_LINES: usize = 20;

struct DashboardState {
    counts: [usize; 13],
    total: usize,
    files_scanned: usize,
    status_line: String,
    elapsed_secs: u64,
    first_draw: bool,
    last_redraw: std::time::Instant,
    all_results: Vec<content_scanner::ScanResult>,
    dirs_done: usize,
    dirs_total: usize,
    interrupted: bool,
    notes_status: Option<String>,
    images_status: Option<String>,
    coverage: content_scanner::ScanCoverage,
}

impl DashboardState {
    fn new(dir_count: usize, config: &content_scanner::ScanConfig) -> Self {
        Self {
            counts: [0; 13],
            total: 0,
            files_scanned: 0,
            status_line: "Starting...".to_string(),
            elapsed_secs: 0,
            first_draw: true,
            last_redraw: std::time::Instant::now(),
            all_results: Vec::new(),
            dirs_done: 0,
            dirs_total: dir_count,
            interrupted: false,
            notes_status: None,
            images_status: None,
            coverage: content_scanner::ScanCoverage::new(config),
        }
    }

    fn category_index(result: &content_scanner::ScanResult) -> usize {
        let cat = content_scanner::finding_category(result);
        CATEGORIES.iter().position(|&c| c == cat).unwrap_or(1)
    }

    fn bar(count: usize, max: usize) -> String {
        if count == 0 || max == 0 {
            return String::new();
        }
        let width = ((count as f64 / max as f64) * 20.0).ceil() as usize;
        let width = width.max(1).min(20);
        "\u{2588}".repeat(width)
    }

    fn category_color(cat: &str) -> &'static str {
        match cat {
            "Crypto Keys" | "Seed Phrases" => "\x1b[31m",
            "API Keys" | "Passwords" | ".env Files" => "\x1b[33m",
            "Financial" | "Identity (SSN)" => "\x1b[34m",
            "Suspicious Images" | "Apple Notes" => "\x1b[36m",
            "Sensitivity Labels" => "\x1b[35m",
            _ => "\x1b[37m",
        }
    }

    fn progress_bar(&self) -> String {
        let bar_width = 24;
        if self.dirs_total == 0 {
            return format!("\x1b[90m[{}]\x1b[0m", "\u{2591}".repeat(bar_width));
        }
        let filled = ((self.dirs_done as f64 / self.dirs_total as f64) * bar_width as f64) as usize;
        let filled = filled.min(bar_width);
        let empty = bar_width - filled;
        format!(
            "\x1b[32m[{}\x1b[90m{}\x1b[32m]\x1b[0m",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(empty),
        )
    }

    fn draw(&mut self) {
        use std::io::Write;

        if !self.first_draw {
            eprint!("\x1b[{DASHBOARD_LINES}A");
        }
        self.first_draw = false;

        let max_count = self.counts.iter().copied().max().unwrap_or(0);
        let rate = if self.elapsed_secs > 0 {
            self.files_scanned as f64 / self.elapsed_secs as f64
        } else {
            0.0
        };

        // Header (2 lines)
        eprint!("\x1b[2K \x1b[1mGorse Deep Scan\x1b[0m\n");
        eprint!("\x1b[2K\n");

        // Category rows (12 lines) — only show categories with findings, plus always show a few key ones
        for (i, &cat) in CATEGORIES.iter().enumerate() {
            let count = self.counts[i];
            let color = Self::category_color(cat);
            let bar = Self::bar(count, max_count);
            if count > 0 {
                eprint!("\x1b[2K  {:<20}{color}{:<22}\x1b[0m{}\n", cat, bar, count);
            } else {
                eprint!("\x1b[2K  \x1b[90m{:<20}  —\x1b[0m\n", cat);
            }
        }

        // Divider + total (2 lines)
        eprint!("\x1b[2K  \x1b[90m{}\x1b[0m\n", "\u{2500}".repeat(44));
        if self.total > 0 {
            let total_bar = Self::bar(self.total, self.total.max(1));
            eprint!(
                "\x1b[2K  {:<20}\x1b[1m{:<22}\x1b[0m\x1b[1m{}\x1b[0m\n",
                "Total", total_bar, self.total
            );
        } else {
            eprint!("\x1b[2K  \x1b[90m{:<20}  0\x1b[0m\n", "Total");
        }

        // Blank (1 line)
        eprint!("\x1b[2K\n");

        // Progress bar (1 line)
        let pbar = self.progress_bar();
        eprint!(
            "\x1b[2K {pbar}  {}/{} dirs  \x1b[90m{:.0} files/s\x1b[0m\n",
            self.dirs_done, self.dirs_total, rate
        );

        // Status line (1 line)
        let status = if self.status_line.len() > 60 {
            format!("...{}", &self.status_line[self.status_line.len() - 57..])
        } else {
            self.status_line.clone()
        };
        eprint!(
            "\x1b[2K \x1b[90m{}  [{} files | {}s]\x1b[0m\n",
            status, self.files_scanned, self.elapsed_secs
        );

        let _ = std::io::stderr().flush();
    }

    fn redraw_if_needed(&mut self) {
        if self.last_redraw.elapsed().as_millis() >= 100 {
            self.draw();
            self.last_redraw = std::time::Instant::now();
        }
    }

    fn print_final(&self) {
        use std::io::Write;

        // Overwrite progress bar + status line with final state
        eprint!("\x1b[2A");
        if self.interrupted {
            let pbar = format!("\x1b[33m[{}]\x1b[0m", "\u{2588}".repeat(24));
            eprint!("\x1b[2K {pbar}  \x1b[33mInterrupted\x1b[0m  (Ctrl+C)\n");
        } else {
            let pbar = format!("\x1b[32m[{}]\x1b[0m", "\u{2588}".repeat(24));
            eprint!("\x1b[2K {pbar}  \x1b[32mDone\x1b[0m\n");
        }
        eprint!(
            "\x1b[2K \x1b[90m{} files scanned in {}s\x1b[0m\n",
            self.files_scanned, self.elapsed_secs
        );
        let _ = std::io::stderr().flush();

        // Apple Notes status
        if let Some(ref msg) = self.notes_status {
            println!("\n \x1b[90mApple Notes: {msg}\x1b[0m");
        }

        // Image OCR status
        if let Some(ref msg) = self.images_status {
            if self.notes_status.is_none() {
                println!();
            }
            println!(" \x1b[90mImage OCR: {msg}\x1b[0m");
        }

        // Final summary
        if self.all_results.is_empty() {
            if self.interrupted {
                println!("\n  \x1b[33mScan interrupted — no findings yet.\x1b[0m");
            } else {
                println!();
                print_coverage_summary(&self.coverage, true);
            }
            return;
        }

        let home = std::env::var("HOME").unwrap_or_default();
        println!();
        if self.interrupted {
            println!(" \x1b[1mFindings so far\x1b[0m (interrupted):");
        } else {
            println!(" \x1b[1mFindings:\x1b[0m");
        }

        // Group by category
        for (i, &cat) in CATEGORIES.iter().enumerate() {
            if self.counts[i] == 0 {
                continue;
            }

            let cat_results: Vec<&content_scanner::ScanResult> = self
                .all_results
                .iter()
                .filter(|r| content_scanner::finding_category(r) == cat)
                .collect();

            if cat_results.is_empty() {
                continue;
            }

            println!();
            println!("  \x1b[1m{cat}\x1b[0m ({} found)", cat_results.len());

            // Images: show all. Others: cap at 8.
            let limit = if cat == "Suspicious Images" { 50 } else { 8 };
            for (j, result) in cat_results.iter().enumerate() {
                if j >= limit {
                    println!(
                        "    \x1b[90m... and {} more\x1b[0m",
                        cat_results.len() - limit
                    );
                    break;
                }
                let path_str = shorten_home(&result.path, &home);
                let severity = result.finding.secret_type.severity();
                let tag = match severity {
                    hedgehog_taint::Severity::Critical => "\x1b[31mCRITICAL\x1b[0m",
                    hedgehog_taint::Severity::High => "\x1b[33mHIGH\x1b[0m",
                    hedgehog_taint::Severity::Medium => "\x1b[34mMEDIUM\x1b[0m",
                    hedgehog_taint::Severity::Low => "\x1b[36mLOW\x1b[0m",
                };
                let ctx_tag = match result.finding.context {
                    hedgehog_taint::LineContext::Comment => " \x1b[90m(in comment)\x1b[0m",
                    hedgehog_taint::LineContext::Executed => " \x1b[31m(executed)\x1b[0m",
                    hedgehog_taint::LineContext::Base64Encoded => " \x1b[35m(base64)\x1b[0m",
                    hedgehog_taint::LineContext::Code => "",
                };
                let line = result.finding.line_number;
                if line > 0 {
                    println!("    [{tag}]{ctx_tag} {path_str}:{line}");
                    println!("          {}", result.finding.redacted_preview);
                } else {
                    println!("    [{tag}]{ctx_tag} {path_str}");
                    println!("          {}", result.finding.redacted_preview);
                }
            }
        }

        println!();
        println!("  These files are accessible to any AI agent or process on your machine.");
        if !self.coverage.complete && !self.interrupted {
            println!();
            print_coverage_summary(&self.coverage, false);
        }
    }
}

/// Print the completeness line for a scan or audit. With `no_findings` the
/// line opens with "No secrets found in N files"; otherwise it only lists
/// what was not checked. Never prints an unqualified all-clear.
fn print_coverage_summary(coverage: &content_scanner::ScanCoverage, no_findings: bool) {
    let home = std::env::var("HOME").unwrap_or_default();
    let files = coverage.files_scanned;
    let noun = if files == 1 { "file" } else { "files" };
    if !coverage.has_gaps {
        if no_findings {
            println!("  \x1b[32mNo secrets found in {files} {noun}.\x1b[0m");
        }
        for line in coverage.note_lines() {
            println!("  \x1b[90mNote: {line}.\x1b[0m");
        }
        return;
    }
    let not_checked = coverage.files_not_checked();
    let gaps = coverage.gap_lines(&home);
    let head = if no_findings {
        format!("No secrets found in {files} {noun}.")
    } else {
        format!("{files} {noun} were checked.")
    };
    let tail = if not_checked == 1 {
        "1 file was not checked:".to_string()
    } else if not_checked > 0 {
        format!("{not_checked} files were not checked:")
    } else {
        "The scan did not cover everything:".to_string()
    };
    println!("  \x1b[33m{head} {tail}\x1b[0m");
    for line in &gaps {
        println!("    - {line}");
    }
    if coverage.dirs_skipped_by_rule > 0 {
        println!("  \x1b[90mRe-run with --include-skipped to scan the skipped folders.\x1b[0m");
    }
    if coverage.permission_denied > 0 {
        println!(
            "  \x1b[90mFiles marked permission denied need Full Disk Access or a different user.\x1b[0m"
        );
    }
}

/// Shown when `scan --deep --all-dirs` is requested without a Pro or Team
/// licence. Exact wording is user-facing and tested; no price in the binary.
pub const FULL_SCAN_REQUIRES_PRO: &str = "The full scan of the whole home folder is part of Gorse Pro. Get a key at https://www.gorse.is/pricing then run `gorse activate <key>`. The default scan of Desktop, Documents, Downloads and Pictures is free and unchanged.";

/// Number-shaped matches (card numbers, backup codes, identity numbers)
/// inside drawings and package lock files are coordinates and hashes, not
/// secrets; keys and passwords in those files are still reported.
fn is_structural_number(r: &content_scanner::ScanResult) -> bool {
    let category = content_scanner::finding_category(r);
    if !matches!(category, "Financial" | "2FA Codes" | "Identity (SSN)") {
        return false;
    }
    let name = r
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.ends_with(".svg")
        || name.ends_with(".lock")
        || matches!(
            name.as_str(),
            "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "go.sum"
                | "composer.lock"
        )
}

/// How many matches of one kind a single file may have before they are
/// shown as one entry: a file with hundreds of "seed phrases" or "API keys"
/// is a word list, a dataset or an analysis result, not a store of secrets.
const REPEATS_SHOWN: usize = 5;

/// Folds repeated matches of the same kind in the same file into the first
/// one, with the count, a lower likelihood and a reason that says so.
fn collapse_repeats(findings: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let key = |f: &serde_json::Value| format!("{}\u{0}{}", f["path"], f["description"]);
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for f in &findings {
        *counts.entry(key(f)).or_default() += 1;
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for mut f in findings {
        let k = key(&f);
        let n = counts[&k];
        if n <= REPEATS_SHOWN {
            out.push(f);
            continue;
        }
        if !seen.insert(k) {
            continue;
        }
        let kind = f["description"]
            .as_str()
            .unwrap_or("")
            .split(" — ")
            .next()
            .unwrap_or("")
            .to_string();
        let likelihood = f["likelihood"].as_u64().unwrap_or(50).min(35);
        f["description"] = format!(
            "{kind} — {n} similar matches in this file, so it is probably data or a word list rather than a secret"
        )
        .into();
        f["likelihood"] = likelihood.into();
        f["repeats"] = n.into();
        out.push(f);
    }
    out
}

/// "credential" for something that unlocks an account or a wallet (keys,
/// tokens, passwords, seed phrases, backup codes); "sensitive" for content
/// that matters but unlocks nothing by itself (card and bank numbers,
/// identity numbers, sensitivity labels, suspicious pictures). The apps
/// count only credentials as "credentials found".
fn finding_group(category: &str) -> &'static str {
    match category {
        "Financial" | "Identity (SSN)" | "Sensitivity Labels" | "Suspicious Images" => "sensitive",
        _ => "credential",
    }
}

/// How sure the scanner is that a match is a real secret, as a percentage
/// for people to read. It comes from the match's confidence level (an exact
/// format with a checksum down to a keyword guess), lowered when the line is
/// a comment or the file looks like a test, sample or example. An estimate,
/// not a measured rate.
fn finding_likelihood(r: &content_scanner::ScanResult) -> u8 {
    use hedgehog_taint::content_patterns::{Confidence, LineContext};
    let mut percent: i32 = match r.finding.confidence {
        Confidence::Definitive => 97,
        Confidence::High => 90,
        Confidence::ContextDependent => 75,
        Confidence::Heuristic => 55,
    };
    if r.finding.context == LineContext::Comment {
        percent -= 10;
    }
    let path = r.path.to_string_lossy().to_ascii_lowercase();
    if [
        "/test", "/tests/", "/fixture", "/example", "/sample", "/mock", ".example", "readme",
    ]
    .iter()
    .any(|m| path.contains(m))
    {
        percent -= 20;
    }
    percent.clamp(20, 99) as u8
}

/// One deep-scan finding as the report and the live progress stream show
/// it: where, what kind, and a redacted preview, never the secret itself.
fn deep_finding_json(r: &content_scanner::ScanResult) -> serde_json::Value {
    let likelihood = finding_likelihood(r);
    let category = content_scanner::finding_category(r);
    serde_json::json!({
        "likelihood": likelihood,
        "group": finding_group(category),
        "path": r.path.display().to_string(),
        "category": content_scanner::finding_category(r),
        "severity": r.finding.secret_type.severity().label(),
        "confidence": r.finding.confidence.label(),
        "context": r.finding.context.label(),
        "line": r.finding.line_number,
        "preview": r.finding.redacted_preview,
        "description": r.finding.description,
    })
}

/// What a stopped `scan --deep --json --resume FILE` carries forward: the
/// places it was scanning, folders and phases it finished, files read, and
/// its findings (paths and redacted previews only, as in the report). The
/// file is written owner-only and removed when a scan finishes.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct ResumeState {
    roots: Vec<String>,
    done_dirs: Vec<String>,
    done_phases: Vec<String>,
    /// Pictures already read for text, so a resume does not read them again.
    #[serde(default)]
    done_images: Vec<String>,
    files_scanned: usize,
    findings: Vec<serde_json::Value>,
}

impl ResumeState {
    fn load(path: &std::path::Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    /// Drops finished folders inside another finished folder: skipping the
    /// outer one skips them anyway, and it keeps the saved file small.
    fn pruned_dirs(&self) -> Vec<String> {
        let all: std::collections::HashSet<&str> =
            self.done_dirs.iter().map(String::as_str).collect();
        let mut kept: Vec<String> = self
            .done_dirs
            .iter()
            .filter(|dir| {
                let mut path = std::path::Path::new(dir.as_str()).parent();
                while let Some(parent) = path {
                    if all.contains(parent.to_string_lossy().as_ref()) {
                        return false;
                    }
                    path = parent.parent();
                }
                true
            })
            .cloned()
            .collect();
        kept.sort();
        kept.dedup();
        kept
    }

    fn save(&self, path: &std::path::Path) {
        let compact = ResumeState {
            roots: self.roots.clone(),
            done_dirs: self.pruned_dirs(),
            done_phases: self.done_phases.clone(),
            done_images: self.done_images.clone(),
            files_scanned: self.files_scanned,
            findings: self.findings.clone(),
        };
        let Ok(body) = serde_json::to_vec(&compact) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(&tmp) {
            use std::io::Write;
            if file.write_all(&body).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

/// True when the Apple Notes container exists but cannot be listed. Without
/// Full Disk Access macOS can hide the database itself, so "no NoteStore"
/// would otherwise look like "no notes" rather than "not allowed to look".
fn notes_folder_hidden() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    let Some(home) = content_scanner::home_dir() else {
        return false;
    };
    let folder = home.join("Library/Group Containers/group.com.apple.notes");
    match std::fs::read_dir(&folder) {
        Ok(_) => false,
        Err(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_deep_scan(
    all_dirs: bool,
    json: bool,
    explicit_paths: &[std::path::PathBuf],
    include_skipped: bool,
    progress: bool,
    no_trufflehog: bool,
    resume: Option<&std::path::Path>,
    stop_file: Option<&std::path::Path>,
    all_matches: bool,
) {
    use content_scanner::ScanEvent;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    let mut config = content_scanner::ScanConfig {
        include_skipped,
        ..Default::default()
    };

    // Explicit folders come from a caller that owns its own access grants (the
    // sandboxed scanner app). Only those folders are read; the OCR helper and
    // the Apple Notes database are outside that grant and are skipped.
    let explicit = !explicit_paths.is_empty();
    let dirs = if explicit {
        let mut dirs = Vec::new();
        for path in explicit_paths {
            match std::fs::canonicalize(path) {
                Ok(dir) if dir.is_dir() => dirs.push(dir),
                _ => {
                    eprintln!("Not a readable folder: {}", path.display());
                    std::process::exit(1);
                }
            }
        }
        dirs
    } else if all_dirs {
        // The whole-home scan is a Pro feature; the default places stay free.
        if credential_store::current_tier() < hedgehog_taint::tier::Tier::Pro {
            eprintln!("{FULL_SCAN_REQUIRES_PRO}");
            std::process::exit(2);
        }
        match content_scanner::home_dir() {
            Some(home) => vec![home],
            None => {
                eprintln!("Could not determine home directory.");
                std::process::exit(1);
            }
        }
    } else {
        content_scanner::smart_scan_dirs()
    };

    if dirs.is_empty() {
        eprintln!("No directories found to scan.");
        std::process::exit(1);
    }

    // Install Ctrl+C handler
    let interrupt = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let flag = interrupt.clone();
        unsafe {
            INTERRUPT_FLAG.store(
                flag.as_ref() as *const AtomicBool as *mut AtomicBool,
                Ordering::SeqCst,
            );
            libc::signal(
                libc::SIGINT,
                handle_sigint as extern "C" fn(libc::c_int) as libc::sighandler_t,
            );
        }
    }

    // The stop file works everywhere, Windows included: when it appears the
    // scan stops as if interrupted and still prints its report.
    if let Some(path) = stop_file {
        let _ = std::fs::remove_file(path);
        let (path, flag) = (path.to_path_buf(), interrupt.clone());
        std::thread::spawn(move || loop {
            if path.exists() {
                flag.store(true, Ordering::SeqCst);
                let _ = std::fs::remove_file(&path);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        });
    }

    let home = std::env::var("HOME").unwrap_or_default();
    let start = Instant::now();

    // JSON mode: collect results silently, no dashboard
    if json {
        let mut all_results: Vec<content_scanner::ScanResult> = Vec::new();
        // A stopped scan of the same places carries on: its finished folders
        // are skipped and its findings kept. Anything else starts afresh.
        let roots: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        let mut saved = resume
            .and_then(ResumeState::load)
            .filter(|state| state.roots == roots)
            .unwrap_or_else(|| ResumeState {
                roots: roots.clone(),
                ..Default::default()
            });
        let resumed = !saved.done_dirs.is_empty() || !saved.done_phases.is_empty();
        config.done_dirs = Some(Arc::new(
            saved
                .done_dirs
                .iter()
                .map(std::path::PathBuf::from)
                .collect(),
        ));
        let mut coverage = content_scanner::ScanCoverage::new(&config);

        // Progress, when asked for, goes to stderr as one JSON object per
        // line so a parent process can show "1,234 files · ~/Documents/…"
        // while stdout stays the single report. Throttled so a fast walk
        // does not flood the pipe.
        let mut last_emit = Instant::now() - std::time::Duration::from_secs(1);
        let emit = |line: serde_json::Value| {
            use std::io::Write;
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "{line}");
        };
        if progress {
            emit(serde_json::json!({
                "event": "start",
                "roots": dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>(),
            }));
            // Count what will be read alongside the scan, so the apps can
            // show "x of y files" and a bar. Best effort: a count that is
            // still running when the scan ends is simply never shown.
            let (count_dirs, count_stop) = (dirs.clone(), interrupt.clone());
            let limits = (config.max_file_size, config.include_skipped);
            std::thread::spawn(move || {
                use std::io::Write;
                let (mut files, mut bytes) = (0u64, 0u64);
                for dir in &count_dirs {
                    let (f, b) =
                        content_scanner::estimate_scan(dir, limits.0, limits.1, &count_stop);
                    files += f;
                    bytes += b;
                }
                let line = serde_json::json!({"event": "estimate", "files_total": files, "bytes_total": bytes});
                let _ = writeln!(std::io::stderr().lock(), "{line}");
            });
        }
        // Apple Notes and the text inside pictures first: they are where
        // people paste things, and they are quick next to a big folder.
        // notes_unreadable is set when Notes could not be read (usually no
        // Full Disk Access); the Mac app then offers the privacy settings.
        let mut notes_unreadable = false;
        let send_finding = |r: &content_scanner::ScanResult, total: usize| {
            if progress {
                use std::io::Write;
                let line = serde_json::json!({"event": "finding", "files_scanned": 0, "findings": total, "finding": deep_finding_json(r)});
                let _ = writeln!(std::io::stderr().lock(), "{line}");
            }
        };
        if !explicit
            && !interrupt.load(Ordering::Relaxed)
            && !saved.done_phases.iter().any(|p| p == "notes")
        {
            if progress {
                emit(serde_json::json!({"event": "phase", "name": "notes"}));
            }
            let (apple_results, _, notes_err) = content_scanner::scan_apple_notes(&config);
            notes_unreadable = notes_err.is_some() || notes_folder_hidden();
            for r in apple_results {
                send_finding(&r, saved.findings.len() + all_results.len() + 1);
                all_results.push(r);
            }
            if !interrupt.load(Ordering::Relaxed) {
                saved.done_phases.push("notes".into());
            }
        }

        let mut ocr_error: Option<String> = None;
        let mut ocr_attempted = false;
        if !explicit
            && !interrupt.load(Ordering::Relaxed)
            && !saved.done_phases.iter().any(|p| p == "images")
        {
            if progress {
                emit(serde_json::json!({"event": "phase", "name": "images"}));
            }
            let images = content_scanner::collect_image_paths(&dirs, &config, &interrupt);
            coverage.image_ocr_cap_reached = images.cap_reached;
            ocr_attempted = true;
            let already: std::collections::HashSet<&str> =
                saved.done_images.iter().map(String::as_str).collect();
            let todo: Vec<std::path::PathBuf> = images
                .paths
                .iter()
                .filter(|p| !already.contains(p.to_string_lossy().as_ref()))
                .cloned()
                .collect();
            let total_images = images.paths.len();
            let mut images_done = total_images - todo.len();
            for batch in todo.chunks(content_scanner::OCR_BATCH_SIZE) {
                if interrupt.load(Ordering::Relaxed) {
                    break;
                }
                let (batch_results, batch_err) = content_scanner::ocr_scan_batch(batch);
                if let Some(err) = batch_err {
                    ocr_error = Some(err);
                    break;
                }
                for r in batch_results {
                    send_finding(&r, saved.findings.len() + all_results.len() + 1);
                    all_results.push(r);
                }
                images_done += batch.len();
                saved
                    .done_images
                    .extend(batch.iter().map(|p| p.display().to_string()));
                if progress {
                    emit(
                        serde_json::json!({"event": "images", "done": images_done, "total": total_images}),
                    );
                }
            }
            if !interrupt.load(Ordering::Relaxed) && ocr_error.is_none() {
                saved.done_phases.push("images".into());
            }
        }
        apply_image_coverage(
            &mut coverage,
            ocr_attempted || saved.done_phases.iter().any(|p| p == "images"),
            ocr_error.is_some(),
        );

        // A resumed scan counts on from where it stopped, and shows what it
        // had already found straight away.
        let earlier_files = saved.files_scanned;
        let earlier_findings = saved.findings.len();
        if progress && resumed {
            emit(
                serde_json::json!({"event": "resumed", "files_scanned": saved.files_scanned, "findings": saved.findings.len()}),
            );
            for f in &saved.findings {
                emit(
                    serde_json::json!({"event": "finding", "files_scanned": saved.files_scanned, "findings": saved.findings.len(), "finding": f}),
                );
            }
        }
        let mut newly_done: Vec<String> = Vec::new();
        let mut live_per_file: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        // The first finished folder is saved at once, then every 10 s.
        let mut last_save = Instant::now() - std::time::Duration::from_secs(10);
        for dir in &dirs {
            if interrupt.load(Ordering::Relaxed) {
                break;
            }
            // Counts from each folder start at zero; add what came before.
            let earlier_files = earlier_files + coverage.files_scanned;
            let earlier_findings = earlier_findings + all_results.len();
            let (mut last_files, mut live_found) = (0usize, Vec::<serde_json::Value>::new());
            let mut on_event = |event: ScanEvent<'_>| {
                if !progress && !matches!(event, ScanEvent::DirDone { .. }) {
                    return;
                }
                let (files, findings, current) = match event {
                    ScanEvent::EnterDir {
                        files_scanned,
                        findings_count,
                        dir,
                    } => {
                        last_files = files_scanned;
                        (
                            files_scanned,
                            findings_count,
                            Some(dir.display().to_string()),
                        )
                    }
                    ScanEvent::Finding {
                        files_scanned,
                        findings_count,
                        result,
                    } => {
                        // Every finding goes out at once (not throttled) so
                        // the apps can list it while the scan carries on.
                        let finding = deep_finding_json(result);
                        last_files = files_scanned;
                        // The live list shows a file's first few matches of a
                        // kind; the report folds the rest into one entry.
                        let shown = live_per_file
                            .entry(format!(
                                "{}\u{0}{}",
                                finding["path"], finding["description"]
                            ))
                            .or_insert(0usize);
                        *shown += 1;
                        if is_structural_number(result) || *shown > REPEATS_SHOWN {
                            if resume.is_some() && !is_structural_number(result) {
                                live_found.push(finding);
                            }
                            return;
                        }
                        if resume.is_some() {
                            live_found.push(finding.clone());
                        }
                        emit(serde_json::json!({
                            "event": "finding",
                            "files_scanned": files_scanned + earlier_files,
                            "findings": findings_count + earlier_findings,
                            "finding": finding,
                        }));
                        (files_scanned, findings_count, None)
                    }
                    ScanEvent::DirDone { dir } => {
                        newly_done.push(dir.display().to_string());
                        // Save progress now and then, so a quit, crash or
                        // restart mid-scan still resumes from close by.
                        if let Some(path) = resume {
                            if last_save.elapsed() >= std::time::Duration::from_secs(10) {
                                last_save = Instant::now();
                                let mut findings = saved.findings.clone();
                                findings.extend(all_results.iter().map(deep_finding_json));
                                findings.extend(live_found.iter().cloned());
                                let mut snapshot = ResumeState {
                                    roots: saved.roots.clone(),
                                    done_dirs: saved.done_dirs.clone(),
                                    done_phases: saved.done_phases.clone(),
                                    done_images: saved.done_images.clone(),
                                    files_scanned: earlier_files + last_files,
                                    findings,
                                };
                                snapshot.done_dirs.extend(newly_done.iter().cloned());
                                snapshot.save(path);
                            }
                        }
                        return;
                    }
                };
                if last_emit.elapsed() < std::time::Duration::from_millis(100) && current.is_none()
                {
                    return;
                }
                if last_emit.elapsed() < std::time::Duration::from_millis(100) {
                    return;
                }
                last_emit = Instant::now();
                emit(serde_json::json!({
                    "event": "progress",
                    "files_scanned": files + earlier_files,
                    "findings": findings + earlier_findings,
                    "dir": current,
                }));
            };
            let outcome = content_scanner::scan_directory_with_coverage(
                dir,
                &config,
                &interrupt,
                if progress || resume.is_some() {
                    Some(&mut on_event)
                } else {
                    None
                },
            );
            if progress {
                emit(serde_json::json!({
                    "event": "progress",
                    "files_scanned": outcome.coverage.files_scanned + earlier_files,
                    "findings": outcome.results.len() + earlier_findings,
                    "dir": dir.display().to_string(),
                    "done": true,
                }));
            }
            all_results.extend(
                outcome
                    .results
                    .into_iter()
                    .filter(|r| !is_structural_number(r)),
            );
            coverage.merge(outcome.coverage);
            saved.done_dirs.append(&mut newly_done);
        }

        // Second engine: TruffleHog's detectors, when installed, verification
        // off so nothing leaves the computer. Its findings join the list
        // with the detector name as the category; raw secrets are dropped.
        let mut engines: Vec<serde_json::Value> = Vec::new();
        let mut external: Vec<trufflehog::ExternalFinding> = Vec::new();
        if !no_trufflehog && !interrupt.load(Ordering::Relaxed) {
            if let Some(binary) = trufflehog::locate() {
                if progress {
                    emit(serde_json::json!({"event": "phase", "name": "trufflehog"}));
                }
                let version = trufflehog::version(&binary);
                match trufflehog::scan(&binary, &dirs, &interrupt) {
                    Ok(found) => {
                        engines.push(serde_json::json!({
                            "name": "trufflehog", "version": version, "findings": found.len(),
                            "verification": "off",
                        }));
                        external = found;
                    }
                    Err(e) => {
                        engines.push(serde_json::json!({
                            "name": "trufflehog", "version": version, "error": e,
                        }));
                    }
                }
            }
        }

        coverage.interrupted |= interrupt.load(Ordering::Relaxed);
        coverage.finalize();
        if progress {
            emit(serde_json::json!({"event": "phase", "name": "done"}));
        }

        let elapsed = start.elapsed().as_secs();
        let new_findings: Vec<serde_json::Value> =
            all_results.iter().map(deep_finding_json).collect();
        // A folder that was only part-read when the scan stopped is read
        // again on resume, so drop findings already carried forward.
        let mut findings = saved.findings.clone();
        let key = |f: &serde_json::Value| {
            (
                f["path"].to_string(),
                f["line"].to_string(),
                f["category"].to_string(),
                f["preview"].to_string(),
            )
        };
        let mut seen: std::collections::HashSet<_> = findings.iter().map(key).collect();
        findings.extend(new_findings.iter().filter(|f| seen.insert(key(f))).cloned());
        coverage.files_scanned += saved.files_scanned;
        if let Some(path) = resume {
            if interrupt.load(Ordering::Relaxed) {
                saved.findings = findings.clone();
                saved.files_scanned = coverage.files_scanned;
                saved.save(path);
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
        for f in &external {
            findings.push(serde_json::json!({
                "path": f.path,
                "category": format!("{} (TruffleHog)", f.detector),
                "severity": if f.verified { "critical" } else { "high" },
                "confidence": "high",
                "context": "data",
                "line": f.line,
                "preview": f.preview,
                "description": if let Some(t) = &f.token_type { format!("{} recognised by TruffleHog's {} detector", t, f.detector) } else { format!("{} secret recognised by TruffleHog's detector{}", f.detector, if f.description.is_empty() { String::new() } else { format!(": {}", f.description) }) },
                "rotation_guide": f.rotation_guide,
                "engine": "trufflehog",
                "likelihood": if f.verified { 99 } else { 85 },
                "group": "credential",
            }));
        }

        let mut coverage_json = serde_json::to_value(&coverage).unwrap_or_default();
        if let Some(map) = coverage_json.as_object_mut() {
            map.insert("notes_unreadable".into(), notes_unreadable.into());
        }
        // Saved progress keeps every match; only the report folds repeats.
        let findings = if all_matches {
            findings
        } else {
            collapse_repeats(findings)
        };
        let output = serde_json::json!({
            "findings": findings,
            "total": findings.len(),
            "engines": engines,
            "files_scanned": coverage.files_scanned,
            "elapsed_secs": elapsed,
            "interrupted": interrupt.load(Ordering::Relaxed),
            "resumed": resumed,
            "complete": coverage.complete,
            "coverage": coverage_json,
        });
        println!("{}", serde_json::to_string(&output).unwrap());
        return;
    }

    // Interactive dashboard mode
    // +2 for Image OCR phase + Apple Notes phase
    let mut dashboard = DashboardState::new(dirs.len() + if explicit { 0 } else { 2 }, &config);
    dashboard.status_line = shorten_home(&dirs[0], &home);
    dashboard.draw();

    for (i, dir) in dirs.iter().enumerate() {
        if interrupt.load(Ordering::Relaxed) {
            dashboard.interrupted = true;
            break;
        }

        dashboard.dirs_done = i;
        dashboard.status_line = shorten_home(dir, &home);
        dashboard.elapsed_secs = start.elapsed().as_secs();
        dashboard.draw();

        let files_before = dashboard.coverage.files_scanned;
        let outcome = content_scanner::scan_directory_with_coverage(
            dir,
            &config,
            &interrupt,
            Some(&mut |event| match event {
                ScanEvent::Finding { result, .. } => {
                    let cat_idx = DashboardState::category_index(result);
                    dashboard.counts[cat_idx] += 1;
                    dashboard.total += 1;
                    dashboard.elapsed_secs = start.elapsed().as_secs();
                    dashboard.draw();
                }
                ScanEvent::EnterDir {
                    files_scanned, dir, ..
                } => {
                    dashboard.files_scanned = files_before + files_scanned;
                    dashboard.status_line = shorten_home(dir, &home);
                    dashboard.elapsed_secs = start.elapsed().as_secs();
                    dashboard.redraw_if_needed();
                }
                ScanEvent::DirDone { .. } => {}
            }),
        );
        dashboard.all_results.extend(outcome.results);
        dashboard.coverage.merge(outcome.coverage);
        dashboard.files_scanned = dashboard.coverage.files_scanned;
    }

    // Scan images with OCR in batches (only if not interrupted)
    let mut ocr_attempted = false;
    let mut ocr_failed = false;
    if !explicit && !interrupt.load(Ordering::Relaxed) {
        dashboard.dirs_done = dirs.len();
        dashboard.status_line = "Collecting images for OCR...".to_string();
        dashboard.elapsed_secs = start.elapsed().as_secs();
        dashboard.draw();

        let images = content_scanner::collect_image_paths(&dirs, &config, &interrupt);
        dashboard.coverage.image_ocr_cap_reached = images.cap_reached;
        ocr_attempted = true;
        let image_paths = images.paths;
        let images_total = image_paths.len();
        let mut images_done = 0usize;
        let mut ocr_error: Option<String> = None;

        let cat_idx = CATEGORIES
            .iter()
            .position(|&c| c == "Suspicious Images")
            .unwrap_or(10);

        for batch in image_paths.chunks(content_scanner::OCR_BATCH_SIZE) {
            if interrupt.load(Ordering::Relaxed) {
                break;
            }

            images_done += batch.len();
            dashboard.status_line =
                format!("Scanning images (OCR)... {images_done}/{images_total}");
            dashboard.elapsed_secs = start.elapsed().as_secs();
            dashboard.draw();

            let (batch_results, batch_err) = content_scanner::ocr_scan_batch(batch);
            if let Some(err) = batch_err {
                ocr_error = Some(err);
                break;
            }

            if !batch_results.is_empty() {
                dashboard.counts[cat_idx] += batch_results.len();
                dashboard.total += batch_results.len();
                dashboard.elapsed_secs = start.elapsed().as_secs();
                dashboard.draw();
            }
            dashboard.all_results.extend(batch_results);
        }

        if let Some(err) = ocr_error {
            ocr_failed = true;
            dashboard.images_status = Some(err);
        } else if images_total > 0 {
            dashboard.images_status = Some(format!("{images_total} images scanned"));
        }
    }
    apply_image_coverage(&mut dashboard.coverage, ocr_attempted, ocr_failed);

    // Scan Apple Notes (only if not interrupted)
    if !explicit && !interrupt.load(Ordering::Relaxed) {
        dashboard.dirs_done = dirs.len() + 1;
        dashboard.status_line = "Checking Apple Notes...".to_string();
        dashboard.elapsed_secs = start.elapsed().as_secs();
        dashboard.draw();

        let (apple_results, notes_count, notes_err) = content_scanner::scan_apple_notes(&config);
        if let Some(err) = notes_err {
            dashboard.notes_status = Some(err);
        } else if notes_count > 0 {
            dashboard.notes_status = Some(format!("{notes_count} notes checked"));
        }

        if !apple_results.is_empty() {
            let cat_idx = CATEGORIES
                .iter()
                .position(|&c| c == "Apple Notes")
                .unwrap_or(11);
            dashboard.counts[cat_idx] += apple_results.len();
            dashboard.total += apple_results.len();
        }
        dashboard.all_results.extend(apple_results);
    }

    if interrupt.load(Ordering::Relaxed) {
        dashboard.interrupted = true;
    }
    dashboard.coverage.interrupted |= dashboard.interrupted;
    dashboard.coverage.finalize();
    dashboard.files_scanned = dashboard.coverage.files_scanned;
    dashboard.dirs_done = dashboard.dirs_total;
    dashboard.elapsed_secs = start.elapsed().as_secs();
    dashboard.draw();
    dashboard.print_final();
}

/// Decide how many image files count as content-unchecked. Images are
/// always checked by name; their text is only read when OCR ran to the end.
fn apply_image_coverage(
    coverage: &mut content_scanner::ScanCoverage,
    ocr_attempted: bool,
    ocr_failed: bool,
) {
    if !ocr_attempted || ocr_failed {
        coverage.images_content_not_checked = coverage.images_seen;
    } else if coverage.image_ocr_cap_reached {
        coverage.images_content_not_checked = coverage
            .images_seen
            .saturating_sub(content_scanner::OCR_MAX_IMAGES);
    } else {
        coverage.images_content_not_checked = 0;
    }
}

// Signal handler for graceful Ctrl+C
#[cfg(unix)]
static INTERRUPT_FLAG: std::sync::atomic::AtomicPtr<std::sync::atomic::AtomicBool> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(unix)]
extern "C" fn handle_sigint(_sig: libc::c_int) {
    use std::sync::atomic::Ordering;
    let ptr = INTERRUPT_FLAG.load(Ordering::SeqCst);
    if !ptr.is_null() {
        unsafe { &*ptr }.store(true, Ordering::SeqCst);
    }
}

fn shorten_home(path: &std::path::Path, home: &str) -> String {
    let s = path.display().to_string();
    if !home.is_empty() && s.starts_with(home) {
        format!("~{}", &s[home.len()..])
    } else {
        s
    }
}

fn cmd_check(command: &str) {
    let engine = load_engine();
    match engine.check(command) {
        Some(result) => {
            let icon = if result.severity == "block" {
                "BLOCKED"
            } else {
                "WARNING"
            };
            println!("[{icon}] {}", result.message);
            println!("  Category: {}", result.category);
            println!("  Pack: {}", result.pack_name);
            println!("  Rule: {}", result.rule_name);
            if let Some(ref alt) = result.alternative {
                println!("  Try instead: {alt}");
            }
            if result.embedded {
                println!("  (matched inside embedded command)");
            }
            std::process::exit(1);
        }
        None => {
            // Also check obfuscation heuristics
            let heuristic = heuristics::analyze(command);
            if heuristic.suspicious {
                let message = heuristics::summary_message(&heuristic);
                println!("[WARNING] {message}");
                println!("  Category: evasion");
                println!("  Pack: heuristics");
                for flag in &heuristic.flags {
                    println!(
                        "  Flag: {} (+{} pts) — {}",
                        flag.name, flag.points, flag.description
                    );
                }
                std::process::exit(1);
            }
            println!("OK — no dangerous patterns detected.");
        }
    }
}

/// Hook handler: reads JSON from stdin, checks against packs, outputs structured JSON.
///
/// Defense pipeline:
///   1. [Layer 3] CANARY CHECK — all tool types, runs first, never approvable
///   2. One-shot user approval (`gorse allow`) → Pack engine regex match
///   3. [Layer 2] SCAN BEFORE EXECUTE — a Bash command that downloads or
///      writes a file and runs it in one step is refused; a script file the
///      command would run (`bash x.sh`, `./x.sh`, `python3 x.py`, `npm run`,
///      `make`, ...) is read and every line checked against the packs; a
///      Write/Edit of a script file has its new content checked the same way
///   4. [Layer 1] OBFUSCATION HEURISTICS — structural scoring (Bash only)
///   5. [Layer 4] LLM INTENT CLASSIFICATION — opt-in, if heuristics fire
///   6. ALLOW
///
/// Input JSON: { "tool_name": "Bash", "tool_input": { "command": "..." }, "session_id": "..." }
/// On block: writes a deny JSON object to stdout, the reason to stderr, exits 2.
/// The agent is told to ask the user for approval; it is given nothing it
/// could resubmit on its own.
/// On allow: exits 0.
/// Refuse a tool request Gorse cannot inspect. Printed in the agent's
/// hook protocol (deny JSON, exit 2) so the agent stops instead of treating a
/// confused guard as a green light.
fn deny_unreadable_input(reason: &str) -> ! {
    let msg = format!("GORSE BLOCKED: {reason}. Nothing was run. If this keeps happening, run `gorse selftest` and contact support@gorse.is.");
    eprintln!("{msg}");
    let output = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": msg,
        }
    });
    println!("{}", serde_json::to_string(&output).unwrap_or_default());
    std::process::exit(2);
}

fn cmd_check_hook() {
    use std::io::Read;

    // A hook that cannot understand its input must refuse, not shrug: the
    // agent treats any exit other than 2 as "carry on", so an unreadable or
    // malformed payload would otherwise switch the guard off for that call.
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        deny_unreadable_input("Gorse could not read the tool request (stdin was not valid text)");
    }

    let parsed: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(e) => deny_unreadable_input(&format!(
            "Gorse could not parse the tool request as JSON ({e})"
        )),
    };

    let tool_name = hook::canonical_tool_name(parsed["tool_name"].as_str().unwrap_or(""));
    let tool_input = &parsed["tool_input"];
    let session_id = parsed["session_id"].as_str();

    // For the tools Gorse inspects, the fields it inspects must be text.
    // A command or path that arrives as a number, array or object cannot be
    // checked, so it is refused rather than waved through unexamined.
    let inspected_fields: &[&str] = match tool_name {
        "Bash" => &["command"],
        "Write" | "Edit" | "Read" => &["file_path"],
        "Grep" => &["path", "pattern"],
        "WebFetch" => &["url"],
        _ => &[],
    };
    for field in inspected_fields {
        let value = &tool_input[*field];
        let alt = if *field == "file_path" {
            Some(&tool_input["absolute_path"])
        } else {
            None
        };
        let present_as_text = value.is_string() || alt.is_some_and(|v| v.is_string());
        let missing = value.is_null() && alt.map_or(true, |v| v.is_null());
        if !present_as_text && !missing {
            deny_unreadable_input(&format!(
                "Gorse cannot inspect this {tool_name} request: `{field}` is not text"
            ));
        }
    }

    // ─── Layer 3: CANARY CHECK ───────────────────────────────────────────
    // Runs FIRST, on ALL tool types, BEFORE the approval check.
    // Canary blocks can never be approved.
    //
    // Two checks:
    //   a) FILE REFERENCE — a hook field refers to a registered decoy path.
    //   b) VALUE MATCH — a registered decoy value appears in a hook field.
    // These matches enforce the decoy policy; neither establishes intent or
    // proves that a file was read or a network transmission took place.
    {
        // Collect all text fields from the hook input
        let mut fields: Vec<(&str, String)> = Vec::new();
        if let Some(cmd) = tool_input["command"].as_str() {
            fields.push(("command", cmd.to_string()));
        }
        if let Some(fp) = tool_input["file_path"].as_str() {
            fields.push(("file_path", fp.to_string()));
        }
        if let Some(fp) = tool_input["absolute_path"].as_str() {
            fields.push(("absolute_path", fp.to_string()));
        }
        if let Some(p) = tool_input["path"].as_str() {
            fields.push(("path", p.to_string()));
        }
        if let Some(content) = tool_input["content"].as_str() {
            fields.push(("content", content.to_string()));
        }
        if let Some(ns) = tool_input["new_string"].as_str() {
            fields.push(("new_string", ns.to_string()));
        }
        if let Some(url) = tool_input["url"].as_str() {
            fields.push(("url", url.to_string()));
        }

        // (a) Check if ANY field references a canary file path.
        for (field_name, text) in &fields {
            let found =
                canary::check_file_access(text).unwrap_or_else(|e| canary_check_unavailable(&e));
            if let Some((canary_path, match_type)) = found {
                // Internal log keeps detail for the admin
                let internal_detail =
                    format!("canary_file_access: {} ({})", canary_path, match_type);
                let user_message = "BLOCKED: Unauthorized access to a protected credential file. This cannot be approved.";

                logging::log_event(
                    "credential_access",
                    session_id,
                    Some(tool_name),
                    Some(field_name),
                    Some("secrets"),
                    Some(&internal_detail),
                    Some(user_message),
                    None,
                );
                history::record_event(
                    "credential_access",
                    session_id,
                    Some(tool_name),
                    Some(field_name),
                    Some("secrets"),
                    Some(&internal_detail),
                    Some(user_message),
                    None,
                );

                report_alert_persistence(alerting::alert_credential_access(
                    &canary_path,
                    tool_name,
                    &format!(
                        "Canary file access detected via {} field ({})",
                        field_name, match_type
                    ),
                ));

                eprintln!("GORSE BLOCKED: {user_message}");
                eprintln!();
                eprintln!("This action attempted to access a protected credential file.");
                eprintln!("This block cannot be approved, not even by the user.");

                let output = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": user_message,
                    }
                });
                println!("{}", serde_json::to_string(&output).unwrap());
                std::process::exit(2);
            }
        }

        // (b) Check if any field contains a canary token VALUE.
        let check_fields: Vec<(&str, &str)> =
            fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let found = canary::check_all_fields(&check_fields)
            .unwrap_or_else(|e| canary_check_unavailable(&e));
        if let Some((token, context)) = found {
            // Internal log keeps detail for the admin
            let internal_detail = format!("canary_value: {} in {}", token.env_name, context);
            let user_message = "BLOCKED: Detected credential data in outbound request. This is a security violation. This cannot be approved.";

            logging::log_event(
                "credential_exfil",
                session_id,
                Some(tool_name),
                Some(&context),
                Some("secrets"),
                Some(&internal_detail),
                Some(user_message),
                None,
            );
            history::record_event(
                "credential_exfil",
                session_id,
                Some(tool_name),
                Some(&context),
                Some("secrets"),
                Some(&internal_detail),
                Some(user_message),
                None,
            );

            report_alert_persistence(alerting::alert_credential_access(
                &token.env_name,
                tool_name,
                &format!("Canary token value detected in {} field", context),
            ));

            eprintln!("GORSE BLOCKED: {user_message}");
            eprintln!();
            eprintln!("Sensitive credential data was detected in this action.");
            eprintln!("This block cannot be approved, not even by the user.");

            let output = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": user_message,
                }
            });
            println!("{}", serde_json::to_string(&output).unwrap());
            std::process::exit(2);
        }
    }

    // ─── One-shot user approval ──────────────────────────────────────────
    // The user ran `gorse allow <id>` in their own terminal for exactly
    // this request (same tool, same inspected text). Consume it and allow,
    // once. Canary blocks never reach here, and approvals are never recorded
    // or honoured for the self_protection category.
    let request_id = approvals::request_id(tool_name, tool_input);
    if let Some(approval) = approvals::consume(&request_id) {
        allow_approved(&approval, &request_id, tool_name, session_id);
    }

    let engine = load_engine();

    // ─── Pack engine check ───────────────────────────────────────────────
    let match_result = match tool_name {
        "Bash" => {
            let command = tool_input["command"].as_str().unwrap_or("");
            engine.check(command)
        }
        "Write" | "Edit" => {
            let file_path = tool_input["file_path"].as_str().unwrap_or("");
            let content = tool_input["content"]
                .as_str()
                .or_else(|| tool_input["new_string"].as_str());
            engine.check_tool_input(tool_name, file_path, content)
        }
        "Read" => {
            // Claude Code sends `file_path`; Gemini CLI's read_file sends
            // `absolute_path` (older releases `path`).
            engine.check_tool_input(tool_name, approvals::read_tool_path(tool_input), None)
        }
        "Grep" => {
            // Grep returns matching file contents, so it is a read of every
            // file under `path` (a file or a directory; absent means the
            // working directory).
            engine.check_tool_input(tool_name, approvals::grep_tool_path(tool_input), None)
        }
        "WebFetch" => {
            let url = tool_input["url"].as_str().unwrap_or("");
            engine.check_tool_input(tool_name, url, None)
        }
        _ => None,
    };

    if let Some(result) = match_result {
        emit_block(tool_name, tool_input, session_id, &result);
        return;
    }

    // ─── Layer 2: SCAN BEFORE EXECUTE ────────────────────────────────────
    // The command itself is clean. Now look at what it would run from disk:
    // a script written earlier (possibly by the agent, line by line, in
    // pieces the Write hook could not object to) is scanned before it runs,
    // and a command that fetches a file and runs it in one step is refused
    // because there is nothing to scan yet. A Write or Edit of a script file
    // is checked for the same lines at write time.
    match tool_name {
        "Bash" => {
            let command = tool_input["command"].as_str().unwrap_or("");
            if let Some(result) = script_scan::fetch_and_run(command) {
                emit_block(tool_name, tool_input, session_id, &result);
                return;
            }
            let ctx = script_scan::Context::from_request(&parsed);
            if let Some(block) = script_scan::scan_command(command, &ctx, &engine) {
                // The approval id covers the script's content, so `gorse
                // allow` approves this run of this file as it is now; edit
                // the file and the same command is a new request.
                let request_id = approvals::request_id_with_context(
                    tool_name,
                    tool_input,
                    &block.approval_context(),
                );
                if let Some(approval) = approvals::consume(&request_id) {
                    allow_approved(&approval, &request_id, tool_name, session_id);
                }
                emit_block_with_id(
                    tool_name,
                    tool_input,
                    session_id,
                    &block.result,
                    &request_id,
                );
                return;
            }
        }
        "Write" | "Edit" => {
            let file_path = tool_input["file_path"].as_str().unwrap_or("");
            let content = if tool_name == "Write" {
                tool_input["content"].as_str()
            } else {
                tool_input["new_string"].as_str()
            };
            if let Some(content) = content {
                if let Some(result) = script_scan::scan_written_content(file_path, content, &engine)
                {
                    emit_block(tool_name, tool_input, session_id, &result);
                    return;
                }
            }
        }
        _ => {}
    }

    // ─── Additional defense layers (Bash only, no pack match) ────────────
    if tool_name == "Bash" {
        let command = tool_input["command"].as_str().unwrap_or("");

        // Layer 1: OBFUSCATION HEURISTICS
        let heuristic = heuristics::analyze(command);
        if heuristic.suspicious {
            let message = heuristics::summary_message(&heuristic);
            let flag_names: Vec<&str> = heuristic.flags.iter().map(|f| f.name).collect();

            // Layer 4: LLM INTENT CLASSIFICATION (opt-in)
            // Only fires when heuristics flag suspicious AND paranoid_mode is on.
            let security_config = load_security_config();
            if security_config.paranoid_mode {
                let mut cache = llm_classifier::ClassifierCache::new(300);
                match llm_classifier::classify(
                    command,
                    &security_config.llm_provider,
                    &security_config.llm_model,
                    &mut cache,
                ) {
                    Ok(classification) => {
                        log::info!(
                            "LLM classification: intent={}, confidence={}, should_block={}",
                            classification.intent,
                            classification.confidence,
                            classification.should_block
                        );
                        if !classification.should_block {
                            // LLM says safe — downgrade heuristic, allow with audit
                            logging::log_event(
                                "llm_allow",
                                session_id,
                                Some(tool_name),
                                Some(command),
                                Some("evasion"),
                                Some(&flag_names.join(",")),
                                Some(&format!("LLM override: {}", classification.reasoning)),
                                None,
                            );
                            // Fall through to allow
                        } else {
                            // LLM confirms dangerous — block
                            let llm_message = format!(
                                "{} | LLM classification: {} (confidence: {:.0}%)",
                                message,
                                classification.intent,
                                classification.confidence * 100.0
                            );
                            let result = hedgehog_packs::MatchResult {
                                pack_name: "heuristics+llm".to_string(),
                                category: "evasion".to_string(),
                                rule_name: flag_names.join(","),
                                severity: "block".to_string(),
                                message: llm_message,
                                alternative: Some(
                                    "Use direct, unobfuscated commands instead.".to_string(),
                                ),
                                embedded: false,
                            };
                            emit_block(tool_name, tool_input, session_id, &result);
                            return;
                        }
                    }
                    Err(e) => {
                        // LLM failed — fall back to heuristic-only decision
                        log::warn!("LLM classification failed: {e}");
                        let result = hedgehog_packs::MatchResult {
                            pack_name: "heuristics".to_string(),
                            category: "evasion".to_string(),
                            rule_name: flag_names.join(","),
                            severity: "warn".to_string(),
                            message,
                            alternative: Some(
                                "Use direct, unobfuscated commands instead.".to_string(),
                            ),
                            embedded: false,
                        };
                        emit_block(tool_name, tool_input, session_id, &result);
                        return;
                    }
                }
            } else {
                // No paranoid mode — heuristic-only block
                let result = hedgehog_packs::MatchResult {
                    pack_name: "heuristics".to_string(),
                    category: "evasion".to_string(),
                    rule_name: flag_names.join(","),
                    severity: "warn".to_string(),
                    message,
                    alternative: Some("Use direct, unobfuscated commands instead.".to_string()),
                    embedded: false,
                };
                emit_block(tool_name, tool_input, session_id, &result);
                return;
            }
        }
    }

    // ─── Allow ───────────────────────────────────────────────────────────
    logging::log_event(
        "allow",
        session_id,
        Some(tool_name),
        None,
        None,
        None,
        None,
        None,
    );
    history::record_event(
        "allow",
        session_id,
        Some(tool_name),
        None,
        None,
        None,
        None,
        None,
    );
    std::process::exit(0);
}

/// What the agent is told to do about a block. The agent is never handed a
/// code or a field it could resubmit on its own: the only way through is a
/// human running `gorse allow` in a terminal the hook does not watch.
fn approval_instruction(category: &str) -> &'static str {
    if category == approvals::UNAPPROVABLE_CATEGORY {
        "This cannot be approved from inside an agent. If the user wants this, they run the command themselves in their own terminal (for example `gorse uninstall`)."
    } else {
        "This needs the user's approval. Ask them to run `gorse allow` in their own terminal, then try the same command again."
    }
}

/// Let an approved request through: log it, record it, exit 0.
fn allow_approved(
    approval: &approvals::Approval,
    request_id: &str,
    tool_name: &str,
    session_id: Option<&str>,
) -> ! {
    let reason = approval.reason.as_deref().unwrap_or("");
    let message = format!(
        "approved by the user with `gorse allow` at {}{}{}",
        approval.created,
        if reason.is_empty() { "" } else { ": " },
        reason
    );
    logging::log_event(
        "approved",
        session_id,
        Some(tool_name),
        Some(&approval.command),
        Some(&approval.category),
        Some(&approval.rule),
        Some(&message),
        Some(request_id),
    );
    history::record_event(
        "approved",
        session_id,
        Some(tool_name),
        Some(&approval.command),
        Some(&approval.category),
        Some(&approval.rule),
        Some(&message),
        Some(request_id),
    );
    std::process::exit(0);
}

/// Emit a block response (shared by pack engine, heuristics, script scan, LLM).
fn emit_block(
    tool_name: &str,
    tool_input: &serde_json::Value,
    session_id: Option<&str>,
    result: &hedgehog_packs::MatchResult,
) {
    // The id `gorse allow` lists; the user approves by it, the hook
    // recognises the identical request by it. The agent is not shown it.
    let request_id = approvals::request_id(tool_name, tool_input);
    emit_block_with_id(tool_name, tool_input, session_id, result, &request_id);
}

/// [`emit_block`] with the request id chosen by the caller, for blocks whose
/// identity includes more than the request text (a scanned script's content).
fn emit_block_with_id(
    tool_name: &str,
    tool_input: &serde_json::Value,
    session_id: Option<&str>,
    result: &hedgehog_packs::MatchResult,
    request_id: &str,
) {
    let command_str = match tool_name {
        "Bash" => tool_input["command"].as_str().unwrap_or("").to_string(),
        "Write" | "Edit" => tool_input["file_path"].as_str().unwrap_or("").to_string(),
        "Read" => approvals::read_tool_path(tool_input).to_string(),
        "Grep" => {
            // Shown to the user by `gorse allow`, so say what was searched for.
            let path = approvals::grep_tool_path(tool_input);
            format!(
                "grep {:?} in {}",
                tool_input["pattern"].as_str().unwrap_or(""),
                if path.is_empty() { "." } else { path }
            )
        }
        "WebFetch" => tool_input["url"].as_str().unwrap_or("").to_string(),
        _ => String::new(),
    };

    logging::log_event(
        "block",
        session_id,
        Some(tool_name),
        Some(&command_str),
        Some(&result.category),
        Some(&result.rule_name),
        Some(&result.message),
        Some(request_id),
    );
    history::record_event(
        "block",
        session_id,
        Some(tool_name),
        Some(&command_str),
        Some(&result.category),
        Some(&result.rule_name),
        Some(&result.message),
        Some(request_id),
    );

    // Send remote alert for security-critical categories
    match result.category.as_str() {
        "secrets" | "evasion" | "disclosure" | "exfiltration" | "self_protection" => {
            report_alert_persistence(alerting::alert_exfiltration_blocked(
                tool_name,
                &command_str,
                &result.category,
                &result.message,
            ));
        }
        _ => {}
    }

    let instruction = approval_instruction(&result.category);

    eprintln!("GORSE BLOCKED: {}", result.message);
    eprintln!(
        "  Category: {} | Rule: {} | Pack: {}",
        result.category, result.rule_name, result.pack_name
    );
    eprintln!(
        "  Command:  {}",
        hedgehog_taint::content_patterns::safe_prefix(&command_str, 200)
    );
    eprintln!();
    eprintln!("WHY THIS WAS BLOCKED:");
    eprintln!(
        "  This command matched a dangerous pattern in the '{}' category.",
        result.category
    );
    eprintln!("  {}", result.message);
    if let Some(ref alt) = result.alternative {
        eprintln!();
        eprintln!("SAFER ALTERNATIVE: {alt}");
    }
    eprintln!();
    eprintln!("{instruction}");
    eprintln!("  Nothing was run. Do not retry until the user says they have approved it.");

    let output = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("{} {instruction}", result.message),
        }
    });
    println!("{}", serde_json::to_string(&output).unwrap());
    std::process::exit(2);
}

/// Load security config section (paranoid mode, LLM provider, etc.)
fn load_security_config() -> config::SecurityConfig {
    match config::load_config() {
        Ok(cfg) => cfg.security,
        Err(_) => config::SecurityConfig::default(),
    }
}

fn cmd_explain(command: &str) {
    let engine = load_engine();
    let results = engine.explain(command);

    if results.is_empty() {
        println!("This command is ALLOWED — no security packs match.");
        return;
    }

    println!("This command matches {} rule(s):\n", results.len());
    for (i, r) in results.iter().enumerate() {
        println!(
            "  {}. [{}] {} (pack: {})",
            i + 1,
            r.severity.to_uppercase(),
            r.rule_name,
            r.pack_name
        );
        println!("     {}", r.message);
        println!("     Category: {}", r.category);
        if let Some(ref alt) = r.alternative {
            println!("     Try instead: {alt}");
        }
        if r.embedded {
            println!("     (matched inside embedded command)");
        }
        println!();
    }
}

fn cmd_daemon() {
    if let Err(e) = alerting::init() {
        eprintln!("Cannot start durable alert worker: {e}");
        std::process::exit(1);
    }

    println!("Starting Gorse daemon...");
    println!("Platform: {}", platform_name());

    #[cfg(target_os = "macos")]
    {
        println!("macOS: ESF daemon requires the Hedgehog.app System Extension.");
        println!("Starting canary monitor using the installed extension's file-access sensor...");
        println!();
        if let Err(e) = canary_watcher::watch_loop() {
            eprintln!("Canary monitoring unavailable: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(feature = "windows-daemon")]
    {
        use hedgehog_taint::taint::TaintEngine;
        use std::sync::{Arc, Mutex};

        if !hedgehog_windows::etw::check_admin_privileges() {
            eprintln!("Error: Administrator privileges required for ETW + WFP.");
            eprintln!();
            eprintln!("To fix, run PowerShell as Administrator:");
            eprintln!("  1. Press the Windows key, type \"PowerShell\"");
            eprintln!("  2. Right-click \"Windows PowerShell\" → \"Run as Administrator\"");
            eprintln!("  3. Navigate to gorse and run: gorse daemon");
            eprintln!();
            eprintln!("Or install as a Windows Service (auto-starts on boot):");
            eprintln!("  gorse service install");
            std::process::exit(1);
        }

        let engine = Arc::new(Mutex::new(TaintEngine::new()));
        {
            let mut eng = engine.lock().unwrap();
            hedgehog_windows::secrets::add_windows_secrets(eng.secrets_mut());
        }

        let mut etw = hedgehog_windows::etw::EtwSession::new(engine.clone());
        let mut wfp = hedgehog_windows::wfp::WfpManager::new(engine.clone());

        etw.start().expect("Failed to start ETW session");
        wfp.init().expect("Failed to initialize WFP engine");
        println!("Windows daemon running (ETW + WFP). Press Ctrl+C to stop.");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    #[cfg(feature = "linux-daemon")]
    {
        use hedgehog_taint::taint::TaintEngine;
        use std::sync::{Arc, Mutex};

        let engine = Arc::new(Mutex::new(TaintEngine::new()));
        {
            let mut eng = engine.lock().unwrap();
            hedgehog_linux::secrets::add_linux_secrets(eng.secrets_mut());
        }

        // Check kernel version
        if let Err(e) = hedgehog_linux::check_kernel_version() {
            eprintln!("Warning: {e}");
            eprintln!("eBPF requires kernel 5.10+. Will attempt fanotify fallback.");
        }

        // Check capabilities and report clearly
        if let Err(e) = hedgehog_linux::check_capabilities() {
            eprintln!("Warning: {e}");
            eprintln!();
            eprintln!("To grant capabilities, run:");
            eprintln!("  sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource,cap_sys_admin+ep $(which gorse)");
            eprintln!();
            eprintln!("Or run the daemon as root:");
            eprintln!("  sudo gorse daemon");
            eprintln!();
            eprintln!("Or use the systemd service (recommended):");
            eprintln!("  sudo systemctl start gorse");
            eprintln!();
        }

        let kernel_ok = hedgehog_linux::check_kernel_version().is_ok();
        let caps_ok = hedgehog_linux::check_capabilities().is_ok();

        if kernel_ok && caps_ok {
            let mut ebpf = hedgehog_linux::ebpf::EbpfManager::new(engine.clone());

            // Initialize netfilter for network blocking before starting eBPF.
            // If nftables is available, connect events will trigger blocking rules.
            let mut nf_available = false;
            let mut nf = hedgehog_linux::netfilter::NetfilterManager::new();
            match nf.init() {
                Ok(()) => {
                    let nf_arc = Arc::new(Mutex::new(nf));
                    ebpf.set_netfilter(nf_arc);
                    nf_available = true;
                }
                Err(e) => {
                    eprintln!("Warning: netfilter init failed: {e}");
                    eprintln!("  Network blocking is DISABLED. File taint tracking is active.");
                    eprintln!("  Ensure `nft` is installed: sudo apt install nftables");
                }
            }

            match ebpf.start() {
                Ok(()) => {
                    if nf_available {
                        println!("Linux daemon running (eBPF + nftables). Press Ctrl+C to stop.");
                    } else {
                        println!("Linux daemon running (eBPF only, no network blocking). Press Ctrl+C to stop.");
                    }
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
                Err(e) => {
                    eprintln!("eBPF failed: {e}");
                    eprintln!("Falling back to fanotify...");
                }
            }
        }

        // Fanotify fallback (needs CAP_SYS_ADMIN or root)
        match hedgehog_linux::fanotify::FanotifyMonitor::new(engine.clone()) {
            Ok(monitor) => {
                let _ = monitor.watch_secrets();
                if let Err(e) = monitor.start() {
                    eprintln!("Fanotify start failed: {e}");
                    std::process::exit(1);
                }
                eprintln!("Note: Running in fanotify fallback mode.");
                eprintln!("  File access monitoring: ACTIVE");
                eprintln!("  Network blocking: DISABLED (requires eBPF)");
                eprintln!("  Process tracking: DISABLED (requires eBPF)");
                println!("Linux daemon running (fanotify fallback). Press Ctrl+C to stop.");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
            }
            Err(e) => {
                eprintln!("Failed to start monitor: {e}");
                eprintln!();
                eprintln!("Both eBPF and fanotify failed. The daemon cannot start.");
                eprintln!("This usually means insufficient capabilities.");
                eprintln!();
                eprintln!("Fix with one of:");
                eprintln!("  sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource,cap_sys_admin+ep $(which gorse)");
                eprintln!("  sudo gorse daemon");
                eprintln!("  sudo systemctl start gorse");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(any(
        target_os = "macos",
        feature = "windows-daemon",
        feature = "linux-daemon"
    )))]
    {
        eprintln!("Daemon mode not available in this build.");
        eprintln!();
        #[cfg(target_os = "linux")]
        {
            eprintln!("The kernel-level daemon is experimental and not part of Gorse releases.");
            eprintln!("The exposure check and scan need no daemon: run `gorse exposure`.");
        }
        #[cfg(target_os = "windows")]
        {
            eprintln!("The kernel-level daemon is experimental and not part of Gorse releases.");
            eprintln!("The exposure check and scan need no daemon: run `gorse exposure`.");
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            eprintln!("No daemon is available for this platform.");
            eprintln!("The CLI scanner and hooks still work without the daemon.");
        }
        eprintln!();
        eprintln!("Note: The CLI scanner and hooks work without the daemon:");
        eprintln!("  gorse hook claude-code   # Install Claude Code hook");
        eprintln!("  gorse scan --deep        # Scan for secrets");
        eprintln!("  gorse check --hook       # Hook handler (used by Claude Code)");
        std::process::exit(1);
    }
}

fn cmd_config(show_path: bool, init: bool) {
    let config_path = config::config_path();
    if show_path {
        println!("{}", config_path.display());
        return;
    }
    if init {
        config::init_config().expect("Failed to create config file");
        println!("Config created at: {}", config_path.display());
        return;
    }
    match config::load_config() {
        Ok(cfg) => println!("{}", toml::to_string_pretty(&cfg).unwrap()),
        Err(e) => {
            eprintln!("No config found. Run `gorse config --init` to create one.");
            eprintln!("({})", e);
        }
    }
}

fn cmd_hook(agent: Agent) {
    // The automatic installers prove the hook works before claiming success;
    // a hook that cannot be run is a failure, not a warning.
    let live = match agent {
        Agent::ClaudeCode => hook::install_claude_code(),
        Agent::Gemini => hook::install_gemini(),
        Agent::Copilot => {
            hook::install_copilot();
            true
        }
        Agent::Aider => {
            hook::install_aider();
            true
        }
        Agent::Continue => {
            hook::install_continue();
            true
        }
        Agent::Codex => {
            hook::install_codex();
            true
        }
        Agent::OpenCode => {
            hook::install_opencode();
            true
        }
    };
    if !live {
        std::process::exit(1);
    }
}

fn cmd_report() {
    let key = credential_store::load_license_key().unwrap_or_else(|| {
        eprintln!(
            "A verified current Team lease is required. Activate or refresh your license first."
        );
        std::process::exit(1);
    });
    if credential_store::current_tier() != hedgehog_taint::tier::Tier::Team {
        eprintln!("Team reporting requires a verified Team lease.");
        std::process::exit(1);
    }
    println!("Building team report...");
    let report = reporting::build_report();
    println!("Sending report to the team dashboard...");
    match reporting::send_report(&key, &report) {
        Ok(_) => {
            reporting::save_last_report();
            println!("Report sent successfully.");
        }
        Err(error) => {
            eprintln!("Failed to send report: {error}");
            std::process::exit(1);
        }
    }
}

fn print_license_status(json: bool) {
    let status = credential_store::status();
    if json {
        println!("{}", serde_json::to_string(&status).unwrap());
    } else {
        println!("License: {} ({})", status.tier, status.state);
        if let Some(machine) = status.machine_id {
            println!("Machine ID: {machine}");
        }
        if let Some(expiry) = status.expires_at {
            let expiry = chrono::DateTime::from_timestamp(expiry as i64, 0)
                .map(|date| date.to_rfc3339())
                .unwrap_or_else(|| "unavailable".into());
            println!("Signed expiry: {expiry}");
        }
        println!("{}", status.message);
    }
}

fn license_error(error: &str, json: bool) -> ! {
    if json {
        println!(
            "{}",
            serde_json::json!({"error":error, "license":credential_store::status()})
        );
    } else {
        eprintln!("{error}");
    }
    std::process::exit(1);
}

/// Remove the obsolete plaintext copy without treating it as an entitlement.
/// Invalid existing configuration is reported rather than replaced by defaults.
fn clear_legacy_license() -> Result<(), String> {
    if !config::config_path().exists() {
        return Ok(());
    }
    let mut cfg = config::load_config()?;
    if !cfg.general.license_key.is_empty() {
        cfg.general.license_key.clear();
        config::save_config(&cfg)?;
    }
    Ok(())
}

fn cmd_activate(key: Option<String>, from_stdin: bool, json: bool) {
    use std::io::Read;
    let key = if from_stdin {
        let mut bytes = Vec::new();
        if std::io::stdin()
            .take(credential_store::MAX_KEY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .is_err()
        {
            license_error("Cannot read license key from standard input", json);
        }
        if bytes.len() > credential_store::MAX_KEY_BYTES {
            license_error("License exceeds size limit", json);
        }
        match String::from_utf8(bytes) {
            Ok(key) => key.trim().to_string(),
            Err(_) => license_error("License key is not valid text", json),
        }
    } else {
        key.unwrap_or_default()
    };
    install_license_key(&key, json);
}

/// Validate and store a key, then print the licence state (or exit with an error).
fn install_license_key(key: &str, json: bool) {
    let key = key.to_string();
    // Check signatures even on unsupported platforms before any writes. A
    // signature failure asks the server which issuer key it signs with, so a
    // deployment that signs with a key this build does not trust is named as
    // our problem rather than the customer's.
    if let Err(error) = credential_store::check_license_signature(&key) {
        license_error(&credential_store::explain_signature_failure(error), json);
    }
    if let Err(error) = credential_store::require_runtime_support() {
        license_error(&error, json);
    }
    // Validate before any writes, including migration of the obsolete copy.
    let machine =
        credential_store::machine_id().unwrap_or_else(|error| license_error(&error, json));
    if let Err(error) =
        credential_store::validate_lease(&key, &machine, credential_store::now(), true)
    {
        license_error(&error, json);
    }
    if let Err(error) =
        clear_legacy_license().and_then(|_| credential_store::store_license_key(&key))
    {
        license_error(&error, json);
    }
    print_license_status(json);
}

/// Fifteen minutes plus slack: the server's code lifetime bounds every wait.
const BROWSER_ACTIVATION_WAIT: std::time::Duration = std::time::Duration::from_secs(15 * 60 + 30);

fn browser_activation_start(json: bool) -> device_link::Started {
    let machine =
        credential_store::machine_id().unwrap_or_else(|error| license_error(&error, json));
    device_link::start(&machine).unwrap_or_else(|error| license_error(&error, json))
}

fn cmd_activate_browser(json: bool) {
    let started = browser_activation_start(json);
    if !json {
        println!("Opening {} in your browser.", started.verify_url);
        println!();
        println!("  Check the page shows this code: {}", started.user_code);
        println!();
        println!("Then click Activate. Waiting (press Ctrl-C to stop)...");
    }
    web::open_browser(&started.verify_url);
    let key = device_link::wait(&started.device_secret, BROWSER_ACTIVATION_WAIT)
        .unwrap_or_else(|error| license_error(&error, json));
    install_license_key(&key, json);
}

fn cmd_activate_browser_start(json: bool) {
    let started = browser_activation_start(json);
    if json {
        println!("{}", serde_json::to_string(&started).unwrap());
    } else {
        // Humans use --browser; never print the secret where it could be copied around.
        println!(
            "Open {} and check the code {}",
            started.verify_url, started.user_code
        );
    }
}

fn cmd_activate_browser_wait(json: bool) {
    use std::io::Read;
    let mut secret = String::new();
    if std::io::stdin()
        .take(256)
        .read_to_string(&mut secret)
        .is_err()
    {
        license_error(
            "Cannot read the activation secret from standard input",
            json,
        );
    }
    let key = device_link::wait(secret.trim(), BROWSER_ACTIVATION_WAIT)
        .unwrap_or_else(|error| license_error(&error, json));
    install_license_key(&key, json);
}

fn cmd_deactivate(json: bool) {
    if let Err(error) = credential_store::delete_license_key().and_then(|_| clear_legacy_license())
    {
        license_error(&error, json);
    }
    print_license_status(json);
}

#[allow(clippy::too_many_arguments)]
fn cmd_exposure(
    json: bool,
    verify: bool,
    html: Option<std::path::PathBuf>,
    map: Option<std::path::PathBuf>,
    max_hops: Option<usize>,
    init: bool,
    fail_on: Option<String>,
    mark_production: Option<String>,
    trufflehog: bool,
    record: bool,
) {
    use exposure::config::Declarations;
    if let Some(name) = mark_production {
        let path = map.clone().unwrap_or_else(Declarations::default_path);
        match Declarations::mark_production(&path, &name) {
            Ok(changed) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"marked": name, "changed": changed, "map": path.display().to_string()})
                    );
                } else if changed {
                    println!(
                        "Marked {name} as production in {}. Run `gorse exposure` again.",
                        path.display()
                    );
                } else {
                    println!(
                        "{name} is already a production system in {}.",
                        path.display()
                    );
                }
                return;
            }
            Err(e) => {
                if json {
                    println!("{}", serde_json::json!({"error": e}));
                } else {
                    eprintln!("Could not mark {name} as production: {e}");
                }
                std::process::exit(2);
            }
        }
    }
    let threshold = match fail_on.as_deref() {
        None => hedgehog_taint::authority::scoring::Severity::High,
        Some(text) => match exposure::parse_severity(text) {
            Some(s) => s,
            None => {
                eprintln!("--fail-on must be one of: critical, high, medium, low");
                std::process::exit(2);
            }
        },
    };
    if init {
        let path = map.clone().unwrap_or_else(Declarations::default_path);
        if path.exists() {
            eprintln!("{} already exists; not overwriting.", path.display());
            std::process::exit(2);
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, Declarations::example()) {
            eprintln!("Could not write {}: {e}", path.display());
            std::process::exit(2);
        }
        println!("Wrote {}", path.display());
        println!("Describe your signers, wallets and production systems there, then run `gorse exposure`.");
        return;
    }
    // --verify is the one paid part of the exposure check. The gate runs
    // before anything else so an unlicensed run never starts provider queries.
    let mut attestor = None;
    if verify {
        // Quiet best-effort renewal once the lease is past half its life or in
        // its grace; the stored lease is re-read afterwards, nothing is printed
        // and the command never waits on failure beyond the request timeout.
        let status = credential_store::refresh_quietly_if_due(credential_store::status());
        if let Err(message) = exposure::verify_allowed(credential_store::tier_of(&status)) {
            if json {
                println!("{}", serde_json::json!({"error": message}));
            } else {
                eprintln!("{message}");
            }
            std::process::exit(2);
        }
        attestor = Some(exposure::Attestor {
            holder: status.email.clone().unwrap_or_else(|| "unknown".into()),
            machine: status
                .machine_id
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        });
    }
    if verify && !json {
        eprintln!("Verifying with read-only provider queries (aws sts/iam list, gh auth status, kubectl auth can-i, vault token lookup, gcloud auth list, az account/role list, eth_getCode)...");
    }
    let mut report = match exposure::run(&exposure::Options {
        verify,
        declarations: map,
        max_hops,
        trufflehog,
    }) {
        Ok(r) => r,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"error": e}));
            } else {
                eprintln!("Exposure check could not run: {e}");
            }
            std::process::exit(2);
        }
    };
    // The whole pipeline finishes before anything is rendered: --record
    // compares with the history (which may add lost coverage, make the run
    // incomplete and list previous findings as not assessed), then a
    // verified run is stamped, its integrity checksum computed last over the
    // document as emitted. Text, JSON and HTML all render that final report.
    // Recording never changes the exit code except through incompleteness:
    // a source the previous run assessed that this one did not makes it 3
    // (unless a finding already meets the threshold).
    let exposure_dir = schedule::exposure_dir();
    let target = record.then(|| exposure::RecordTarget {
        exposure_dir: &exposure_dir,
        trigger: schedule::Trigger::Manual,
        notify: true,
    });
    let (value, record_error) = exposure::finalize(&mut report, target, attestor.as_ref());
    if let Some(e) = record_error {
        eprintln!("Could not record this check in the history: {e}");
    }
    if !json {
        if let Some(info) = &report.record {
            for failure in &info.changes.unassessed_failures {
                eprintln!("Incomplete: {}", failure.reason);
            }
        }
    }
    if let Some(path) = &html {
        if let Err(e) = std::fs::write(path, exposure::report::render_html(&report)) {
            eprintln!("Could not write {}: {e}", path.display());
            std::process::exit(2);
        }
        if !json {
            eprintln!("HTML report written to {}", path.display());
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
    } else {
        let color = std::env::var("NO_COLOR").is_err()
            && std::io::IsTerminal::is_terminal(&std::io::stdout());
        print!("{}", exposure::report::render_text(&report, color));
    }
    std::process::exit(exposure::exit_code_for(
        &report,
        threshold,
        report.incomplete,
    ));
}

fn cmd_audit(path: &str, json: bool) {
    let dir = std::path::Path::new(path);
    if !dir.exists() {
        eprintln!("Directory not found: {path}");
        std::process::exit(2);
    }
    if !dir.is_dir() {
        eprintln!("Not a directory: {path}");
        std::process::exit(2);
    }

    let config = content_scanner::ScanConfig::default();
    let interrupt = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let interrupt_clone = interrupt.clone();

    // Handle Ctrl+C
    let _ = ctrlc_handler(&interrupt_clone);

    let start = std::time::Instant::now();
    let report = content_scanner::scan_directory_checked(
        dir,
        &config,
        &interrupt,
        Some(&mut |event| match event {
            content_scanner::ScanEvent::EnterDir {
                files_scanned: f, ..
            } => {
                if !json {
                    eprint!("\r  Scanning... {f} files");
                }
            }
            content_scanner::ScanEvent::Finding {
                files_scanned: f,
                findings_count: n,
                ..
            } => {
                if !json {
                    eprint!("\r  Scanning... {f} files, {n} findings");
                }
            }
            content_scanner::ScanEvent::DirDone { .. } => {}
        }),
    );
    let results = report.results;
    let files_scanned = report.files_scanned;
    let elapsed = start.elapsed();

    if !json {
        eprintln!("\r                                          "); // clear progress
    }

    if json {
        let findings: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "file": r.path.display().to_string(),
                    "line": r.finding.line_number,
                    "type": r.finding.secret_type.name(),
                    "category": r.finding.secret_type.category(),
                    "confidence": r.finding.confidence.label(),
                    "context": r.finding.context.label(),
                    "preview": r.finding.redacted_preview,
                    "description": r.finding.description,
                })
            })
            .collect();
        let output = serde_json::json!({
            "directory": path,
            "complete": report.complete,
            "error_count": report.error_count,
            "skipped_count": report.skipped_count,
            "files_scanned": files_scanned,
            "findings_count": results.len(),
            "elapsed_ms": elapsed.as_millis(),
            "findings": findings,
            "coverage": report.coverage,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        if !report.complete {
            std::process::exit(2);
        }
        if !results.is_empty() {
            std::process::exit(1);
        }
        return;
    }

    println!("Gorse Audit: {path}");
    println!("================{}=", "=".repeat(path.len()));
    println!();
    println!(
        "  Scanned {} files in {:.1}s",
        files_scanned,
        elapsed.as_secs_f64()
    );
    println!();

    if !report.complete {
        eprintln!(
            "Audit incomplete: {} errors and {} skipped entries/subtrees. Findings cover only inspected text.",
            report.error_count, report.skipped_count
        );
    }
    if results.is_empty() {
        print_coverage_summary(&report.coverage, true);
        if !report.complete {
            std::process::exit(2);
        }
        return;
    }

    // Group by confidence
    let mut definitive = Vec::new();
    let mut high = Vec::new();
    let mut context = Vec::new();
    let mut heuristic = Vec::new();

    for r in &results {
        match r.finding.confidence {
            hedgehog_taint::content_patterns::Confidence::Definitive => definitive.push(r),
            hedgehog_taint::content_patterns::Confidence::High => high.push(r),
            hedgehog_taint::content_patterns::Confidence::ContextDependent => context.push(r),
            hedgehog_taint::content_patterns::Confidence::Heuristic => heuristic.push(r),
        }
    }

    let dir_str = dir.display().to_string();
    let shorten = |p: &std::path::Path| -> String {
        let s = p.display().to_string();
        if s.starts_with(&dir_str) {
            format!(".{}", &s[dir_str.len()..])
        } else {
            s
        }
    };

    if !definitive.is_empty() {
        println!("  \x1b[31mDEFINITIVE ({}):\x1b[0m", definitive.len());
        for r in &definitive {
            println!(
                "    {}:{} — {}",
                shorten(&r.path),
                r.finding.line_number,
                r.finding.redacted_preview
            );
            println!("      {}", r.finding.description);
        }
        println!();
    }

    if !high.is_empty() {
        println!("  \x1b[33mHIGH CONFIDENCE ({}):\x1b[0m", high.len());
        for r in &high {
            println!(
                "    {}:{} — {}",
                shorten(&r.path),
                r.finding.line_number,
                r.finding.redacted_preview
            );
        }
        println!();
    }

    if !context.is_empty() {
        println!("  \x1b[34mCONTEXT-DEPENDENT ({}):\x1b[0m", context.len());
        for r in &context {
            println!(
                "    {}:{} — {}",
                shorten(&r.path),
                r.finding.line_number,
                r.finding.redacted_preview
            );
        }
        println!();
    }

    if !heuristic.is_empty() {
        println!("  \x1b[36mHEURISTIC ({}):\x1b[0m", heuristic.len());
        for r in &heuristic {
            println!("    {} — {}", shorten(&r.path), r.finding.redacted_preview);
        }
        println!();
    }

    println!(
        "  Total: {} findings ({} definitive, {} high, {} context, {} heuristic)",
        results.len(),
        definitive.len(),
        high.len(),
        context.len(),
        heuristic.len()
    );

    if !definitive.is_empty() || !high.is_empty() {
        println!();
        println!("  \x1b[1mAction required:\x1b[0m Remove or rotate the secrets above before committing.");
    }
    if !report.complete {
        println!();
        print_coverage_summary(&report.coverage, false);
    }
    std::process::exit(if report.complete { 1 } else { 2 });
}

/// Set up Ctrl+C handler (best-effort, non-fatal if unavailable).
fn ctrlc_handler(flag: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let f = flag.clone();
    let _ = std::thread::spawn(move || {
        // Simple signal handler using libc on Unix
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        let _ = f;
    });
}

fn cmd_install() {
    println!(
        "Gorse v{} — agent guard setup (preview)",
        env!("CARGO_PKG_VERSION")
    );
    println!("The agent guard is a preview: it checks each command a supported AI coding agent is");
    println!(
        "about to run and refuses the dangerous ones. It can refuse a command you meant to run."
    );
    println!(
        "Turn it off at any time with `gorse uninstall`. The exposure check does not need it."
    );
    println!();

    // Step 1: Create config
    let config_exists = config::config_path().exists();
    if !config_exists {
        println!("1. Creating config...");
        match config::init_config() {
            Ok(()) => println!("   Created {}", config::config_path().display()),
            Err(e) => println!("   Warning: {e}"),
        }
    } else {
        println!("1. Config exists: {}", config::config_path().display());
    }

    // Step 2: Create log directory
    let log_dir = config::config_dir().join("logs");
    let _ = std::fs::create_dir_all(&log_dir);

    // Step 3: Detect and install agent hooks
    println!();
    println!("2. Installing agent hooks...");
    let summary = hook::install_all_detected();
    if summary.acted_on == 0 {
        println!("   No AI agents detected. Install hooks manually: gorse hook <agent>");
    }

    // Step 4: Quick status check — counts what exists and what is live,
    // not what is on the watch list.
    println!();
    println!("3. Running quick status check...");
    let protection = Protection::gather();
    let engine = load_engine();

    println!(
        "   Credential locations found: {}",
        protection.found_count()
    );
    for line in protection.protection_lines() {
        println!("   {line}");
    }
    println!("   Security rules: {}", engine.rule_count());
    println!(
        "   Platform:       {} ({})",
        platform_name(),
        std::env::consts::ARCH
    );

    // Summary
    println!();
    if protection.enforcing() && summary.broken == 0 {
        println!("Setup complete. Gorse is guarding your AI agent.");
    } else if summary.broken > 0 {
        println!("Setup is NOT complete: a hook was written but does not work (see above).");
        println!("Until it is fixed the agent runs with no protection.");
    } else {
        println!("Setup is not complete: no agent hook is live, so nothing is protected yet.");
        println!("Install one with `gorse hook claude-code` (or `gorse hook <agent>`).");
    }
    println!();
    println!("Next steps:");
    println!("  gorse scan --deep      Scan files for exposed secrets");
    println!("  gorse activate <key>   Activate your license key");
    println!("  gorse status           Check protection status anytime");
    if summary.broken > 0 {
        std::process::exit(1);
    }
}

fn cmd_uninstall() {
    println!("Uninstalling Gorse hooks...");
    println!();
    hook::uninstall_all();
    println!();
    println!(
        "Hooks removed. Config and logs preserved at: {}",
        config::config_dir().display()
    );
    println!(
        "To fully remove, delete: {}",
        config::config_dir().display()
    );
}

fn cmd_shell_init(shell_arg: Option<String>) {
    let shell = shell_arg.unwrap_or_else(|| {
        // Auto-detect from SHELL env var
        std::env::var("SHELL")
            .ok()
            .and_then(|s| {
                let name = s.rsplit('/').next().unwrap_or("").to_string();
                if name == "bash" || name == "zsh" || name == "fish" {
                    Some(name)
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "zsh".to_string())
    });

    match shell.as_str() {
        "zsh" => print!("{}", shell_init_zsh()),
        "bash" => print!("{}", shell_init_bash()),
        "fish" => print!("{}", shell_init_fish()),
        _ => {
            eprintln!("Unsupported shell: {shell}. Supported: bash, zsh, fish");
            std::process::exit(1);
        }
    }
}

fn shell_init_zsh() -> &'static str {
    r#"# Gorse shell integration for zsh
# Add to ~/.zshrc: eval "$(gorse shell-init)"

__hedgehog_preexec() {
    # Skip if inside gorse itself to avoid recursion
    [[ "$1" == gorse* ]] && return
    # Skip empty commands
    [[ -z "$1" ]] && return
    # Skip simple builtins that can't be dangerous
    case "${1%% *}" in
        cd|echo|printf|type|which|alias|unalias|export|set|unset|true|false|pwd|pushd|popd) return ;;
    esac
    # Check the command against security packs
    if ! gorse shell-check -- $1 2>/dev/null; then
        # Command was blocked — prevent execution by returning 1
        return 1
    fi
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec __hedgehog_preexec
"#
}

fn shell_init_bash() -> &'static str {
    r#"# Gorse shell integration for bash
# Add to ~/.bashrc: eval "$(gorse shell-init)"

__hedgehog_preexec() {
    local cmd="$1"
    # Skip if inside gorse itself
    [[ "$cmd" == gorse* ]] && return 0
    # Skip empty commands
    [[ -z "$cmd" ]] && return 0
    # Skip simple builtins
    case "${cmd%% *}" in
        cd|echo|printf|type|which|alias|unalias|export|set|unset|true|false|pwd|pushd|popd) return 0 ;;
    esac
    # Check the command
    if ! gorse shell-check -- $cmd 2>/dev/null; then
        return 1
    fi
    return 0
}

# Use DEBUG trap for preexec behavior in bash
__hedgehog_debug_trap() {
    # Only intercept at the prompt level (BASH_SUBSHELL=0)
    [[ $BASH_SUBSHELL -gt 0 ]] && return
    # Get the command about to be executed
    local cmd="$BASH_COMMAND"
    __hedgehog_preexec "$cmd"
}

trap '__hedgehog_debug_trap' DEBUG
"#
}

fn shell_init_fish() -> &'static str {
    r#"# Gorse shell integration for fish
# Add to ~/.config/fish/config.fish: gorse shell-init | source

function __hedgehog_preexec --on-event fish_preexec
    # Skip gorse commands
    string match -q 'gorse*' -- $argv[1]; and return
    # Skip empty
    test -z "$argv[1]"; and return
    # Check the command
    gorse shell-check -- $argv[1] 2>/dev/null
    or begin
        echo "Command blocked by Gorse." >&2
        commandline ''
        return 1
    end
end
"#
}

fn cmd_shell_check(command: &str) {
    if command.is_empty() {
        std::process::exit(0);
    }

    let engine = load_engine();
    match engine.check(command) {
        Some(result) => {
            let icon = if result.severity == "block" {
                "\x1b[31mBLOCKED\x1b[0m"
            } else {
                "\x1b[33mWARNING\x1b[0m"
            };

            eprintln!();
            eprintln!("  \x1b[1mGorse [{icon}]\x1b[0m {}", result.message);
            eprintln!(
                "  Category: {} | Rule: {}",
                result.category, result.rule_name
            );
            if let Some(ref alt) = result.alternative {
                eprintln!("  Try instead: {alt}");
            }
            eprintln!();

            // Log the block
            logging::log_event(
                "shell_block",
                None,
                Some("shell"),
                Some(command),
                Some(&result.category),
                Some(&result.rule_name),
                Some(&result.message),
                None,
            );
            history::record_event(
                "shell_block",
                None,
                Some("shell"),
                Some(command),
                Some(&result.category),
                Some(&result.rule_name),
                Some(&result.message),
                None,
            );

            if result.severity == "block" {
                std::process::exit(1);
            }
            // Warnings still allow execution
            std::process::exit(0);
        }
        None => {
            std::process::exit(0);
        }
    }
}

fn cmd_dashboard(json: bool) {
    let protection = Protection::gather();
    let total = protection.found_count();
    let protected = protection.protected_count();
    let unprotected = total - protected;

    let engine = load_engine();
    let dcg = dcg_detected();
    let agents = hook::detect_agents();
    let activity = logging::recent_activity(30);
    let config_exists = config::config_path().exists();

    if json {
        let agents_json: Vec<serde_json::Value> = agents
            .iter()
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "detected": a.detected,
                    "installed": a.installed,
                })
            })
            .collect();

        let recent: Vec<serde_json::Value> = activity
            .recent_blocks
            .iter()
            .map(|b| {
                serde_json::json!({
                    "timestamp": b.timestamp,
                    "category": b.category,
                    "command": b.command,
                    "message": b.message,
                })
            })
            .collect();

        let output = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": platform_name(),
            "arch": std::env::consts::ARCH,
            "tier": credential_store::current_tier().name(),
            "license": credential_store::status(),
            "config_exists": config_exists,
            "dcg_detected": dcg,
            "kernel_bridge": kernel_bridge_status(),
            "sensor_running": protection.sensor_running,
            "secrets": {
                "total": total,
                "protected": protected,
                "unprotected": unprotected,
            },
            "rules_loaded": engine.rule_count(),
            "agents": agents_json,
            "hooks": protection.hooks_json(),
            "activity_30d": {
                "blocks": activity.blocks,
                "allows": activity.allows,
                "approvals": activity.approvals,
                "total": activity.total_events,
                "days_covered": activity.days_covered,
                "recent_blocks": recent,
            },
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    // ─── Header ──────────────────────────────────────────────────
    println!();
    println!(
        "  \x1b[1mGorse Dashboard\x1b[0m  v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("  \x1b[90m{}\x1b[0m", "\u{2500}".repeat(48));
    println!();

    // ─── Protection Status ───────────────────────────────────────
    let shield = if protection.enforcing() && total > 0 {
        "\x1b[32m\u{25cf}\x1b[0m" // green dot: something is live
    } else if total > 0 {
        "\x1b[31m\u{25cf}\x1b[0m" // red dot: credentials found, nothing enforcing
    } else {
        "\x1b[90m\u{25cb}\x1b[0m" // dim empty circle
    };
    println!("  {shield} \x1b[1mCredentials\x1b[0m");
    println!(
        "    Found: {total}  |  Protected: {}",
        if protected > 0 {
            format!("\x1b[32m{protected}\x1b[0m")
        } else {
            format!("\x1b[31m{protected}\x1b[0m")
        }
    );
    for line in protection.protection_lines() {
        println!("    \x1b[90m{line}\x1b[0m");
    }
    println!();

    // ─── Security Packs ──────────────────────────────────────────
    println!("  \x1b[1mSecurity Packs\x1b[0m");
    println!("    {} rules loaded", engine.rule_count());
    if dcg {
        println!("    \x1b[36mDCG detected\x1b[0m — destructive category deferred to DCG");
    }
    println!("    Kernel bridge: {}", kernel_bridge_status());
    println!();

    // ─── Agent Hooks ─────────────────────────────────────────────
    let detected: Vec<_> = agents.iter().filter(|a| a.detected).collect();
    let hooked: Vec<_> = agents.iter().filter(|a| a.installed).collect();

    println!("  \x1b[1mAI Agent Hooks\x1b[0m");
    if detected.is_empty() {
        println!("    \x1b[90mNo AI agents detected\x1b[0m");
    } else {
        for agent in &detected {
            // "Gemini" in detection is "Gemini CLI" in the hook probe.
            let probe = protection.hooks.iter().find(|h| {
                h.agent == agent.name || (agent.name == "Gemini" && h.agent == "Gemini CLI")
            });
            let status = match (agent.installed, probe) {
                (true, Some(h)) if h.live => "\x1b[32m\u{2713}\x1b[0m hooked and live".to_string(),
                (true, Some(h)) => format!(
                    "\x1b[31m\u{2717}\x1b[0m hooked but BROKEN — {}",
                    h.problem.as_deref().unwrap_or("failed the liveness check")
                ),
                (true, None) => "\x1b[33m\u{2717}\x1b[0m hooked (not checked)".to_string(),
                (false, _) => "\x1b[33m\u{2717}\x1b[0m not hooked".to_string(),
            };
            println!("    {} {}", agent.name, status);
        }
    }
    let live_hooks = protection.live_hooks().len();
    if !hooked.is_empty() {
        println!(
            "    \x1b[90m{live_hooks}/{} agents guarded by a live hook\x1b[0m",
            detected.len()
        );
    }
    if protection.sensor_running {
        println!("    \x1b[32m\u{2713}\x1b[0m Gorse sensor running");
    }
    println!();

    // ─── Activity (30 days) ──────────────────────────────────────
    println!("  \x1b[1mActivity (30d)\x1b[0m");
    if activity.total_events == 0 {
        println!("    \x1b[90mNo events recorded yet\x1b[0m");
        println!(
            "    \x1b[90mThe agent guard (preview) records events here once it is turned on\x1b[0m"
        );
    } else {
        // Summary line
        let block_color = if activity.blocks > 0 {
            "\x1b[31m"
        } else {
            "\x1b[90m"
        };
        let approval_color = if activity.approvals > 0 {
            "\x1b[33m"
        } else {
            "\x1b[90m"
        };
        println!(
            "    {block_color}{}\x1b[0m blocked  |  \x1b[32m{}\x1b[0m allowed  |  {approval_color}{}\x1b[0m approved",
            activity.blocks, activity.allows, activity.approvals
        );

        // Miniature bar chart
        let max = activity.blocks.max(activity.allows).max(1);
        let block_w = ((activity.blocks as f64 / max as f64) * 16.0) as usize;
        let allow_w = ((activity.allows as f64 / max as f64) * 16.0) as usize;
        println!(
            "    \x1b[31m{}\x1b[0m  blocks",
            "\u{2588}".repeat(block_w.max(if activity.blocks > 0 { 1 } else { 0 }))
        );
        println!(
            "    \x1b[32m{}\x1b[0m  allows",
            "\u{2588}".repeat(allow_w.max(if activity.allows > 0 { 1 } else { 0 }))
        );

        // Recent blocks
        if !activity.recent_blocks.is_empty() {
            println!();
            println!("    \x1b[90mRecent blocks:\x1b[0m");
            for b in &activity.recent_blocks {
                let ts = if b.timestamp.len() >= 16 {
                    &b.timestamp[..16]
                } else {
                    &b.timestamp
                };
                let cmd_display = if b.command.len() > 40 {
                    format!("{}...", &b.command[..37])
                } else {
                    b.command.clone()
                };
                println!(
                    "    \x1b[90m{ts}\x1b[0m  [\x1b[31m{}\x1b[0m] {cmd_display}",
                    b.category
                );
            }
        }
    }
    println!();

    // ─── Config ──────────────────────────────────────────────────
    if !config_exists {
        println!("  \x1b[33mTip:\x1b[0m Run `gorse config --init` to create a config file");
        println!();
    }
}

/// `gorse allow`: list the recent blocks, or approve one of them once.
///
/// This is a command for the user, typed in their own terminal. Inside a
/// hooked agent, `gorse allow` is itself blocked by the self_protection
/// pack, so an agent cannot approve its own request.
fn cmd_allow(id: Option<&str>, reason: Option<&str>) {
    use hedgehog_taint::content_patterns::safe_prefix;

    let blocks = history::recent_blocks(approvals::RECENT_BLOCK_WINDOW_SECS);
    let window_min = approvals::RECENT_BLOCK_WINDOW_SECS / 60;
    let ttl_min = approvals::APPROVAL_TTL_SECS / 60;

    let Some(wanted) = id else {
        if blocks.is_empty() {
            println!("No blocks in the last {window_min} minutes. Nothing to approve.");
            return;
        }
        println!("Blocked in the last {window_min} minutes:");
        println!();
        for block in &blocks {
            println!(
                "  {}  {}  {}  {} | {}",
                approvals::short_id(&block.request_id),
                relative_time(&block.timestamp),
                block.tool_name,
                block.category,
                block.rule_name
            );
            println!("          {}", safe_prefix(&block.command, 200));
            if block.category == approvals::UNAPPROVABLE_CATEGORY {
                println!(
                    "          (self_protection: cannot be approved; if you want this, run it yourself in a terminal, for example `gorse uninstall`)"
                );
            }
        }
        println!();
        println!(
            "Run `gorse allow <id>` to let that exact request through once (valid for {ttl_min} minutes)."
        );
        println!("Add --reason \"...\" to record why. Every approval is logged.");
        return;
    };

    let wanted = wanted.trim().to_ascii_lowercase();
    if wanted.is_empty() || !wanted.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("'{wanted}' is not an id. Run `gorse allow` with no arguments to list the recent blocks.");
        std::process::exit(1);
    }
    let matches: Vec<&history::RecentBlock> = blocks
        .iter()
        .filter(|b| b.request_id.starts_with(&wanted))
        .collect();
    let block = match matches.as_slice() {
        [one] => *one,
        [] => {
            eprintln!(
                "No block with id {wanted} in the last {window_min} minutes. Run `gorse allow` to list them."
            );
            std::process::exit(1);
        }
        _ => {
            eprintln!("Id {wanted} matches more than one block. Give more characters of the id.");
            std::process::exit(1);
        }
    };

    if block.category == approvals::UNAPPROVABLE_CATEGORY {
        eprintln!(
            "{} is a self_protection block ({}).",
            approvals::short_id(&block.request_id),
            safe_prefix(&block.command, 200)
        );
        eprintln!(
            "Approvals never apply to this category: an agent may not change or remove Gorse. If you want this, run it yourself in a terminal (for example `gorse uninstall`), outside the agent."
        );
        std::process::exit(1);
    }

    let approval = approvals::new_approval(
        &block.request_id,
        &block.tool_name,
        &block.category,
        &block.rule_name,
        &safe_prefix(&block.command, 200),
        reason,
    );
    if let Err(e) = approvals::record(approval.clone()) {
        eprintln!("Could not record the approval: {e}");
        std::process::exit(1);
    }

    println!("Approved once, valid for {ttl_min} minutes:");
    println!("  Id:       {}", approvals::short_id(&approval.request_id));
    println!("  Tool:     {}", approval.tool_name);
    println!(
        "  Category: {} | Rule: {}",
        approval.category, approval.rule
    );
    println!("  Command:  {}", approval.command);
    if let Some(ref reason) = approval.reason {
        println!("  Reason:   {reason}");
    }
    println!();
    println!(
        "Tell the agent to try the same command again. It will go through exactly once; anything different is still checked."
    );
}

/// "just now", "3 min ago" or the clock time, for `gorse allow`.
fn relative_time(timestamp: &str) -> String {
    let Ok(when) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
        return timestamp.chars().take(19).collect();
    };
    let elapsed = chrono::Utc::now().signed_duration_since(when.with_timezone(&chrono::Utc));
    let secs = elapsed.num_seconds().max(0);
    if secs < 60 {
        "just now ".to_string()
    } else if secs < 3600 {
        format!("{:>2} min ago", secs / 60)
    } else {
        when.with_timezone(&chrono::Local)
            .format("%H:%M     ")
            .to_string()
    }
}

fn cmd_history(days: usize, json: bool) {
    let activity = logging::recent_activity(days);
    let db_stats = history::query_stats();
    let recent_events = history::query_recent(20, None);
    let db_size = history::db_size_bytes();

    if json {
        let recent_json: Vec<serde_json::Value> = recent_events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "event_type": e.event_type,
                    "tool_name": e.tool_name,
                    "command": e.command,
                    "category": e.category,
                    "message": e.message,
                })
            })
            .collect();

        let top_cats: Vec<serde_json::Value> = db_stats
            .top_categories
            .iter()
            .map(|(cat, cnt)| serde_json::json!({"category": cat, "count": cnt}))
            .collect();

        let output = serde_json::json!({
            "days": days,
            "jsonl": {
                "blocks": activity.blocks,
                "allows": activity.allows,
                "approvals": activity.approvals,
                "total_events": activity.total_events,
                "days_covered": activity.days_covered,
            },
            "sqlite": {
                "total_events": db_stats.total_events,
                "blocks": db_stats.blocks,
                "allows": db_stats.allows,
                "approvals": db_stats.approvals,
                "top_categories": top_cats,
                "first_event": db_stats.first_event,
                "last_event": db_stats.last_event,
                "db_size_bytes": db_size,
            },
            "recent_events": recent_json,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!(
        "Gorse History ({} day{})",
        days,
        if days == 1 { "" } else { "s" }
    );
    println!("{}", "=".repeat(30));
    println!();

    // Use the richer source of data (SQLite if available, else JSONL)
    let total = if db_stats.total_events > 0 {
        db_stats.total_events
    } else {
        activity.total_events
    };

    if total == 0 {
        println!("  No events recorded.");
        println!("  The agent guard (preview) records events here once it is turned on.");
        return;
    }

    let blocks = activity.blocks.max(db_stats.blocks);
    let allows = activity.allows.max(db_stats.allows);
    let approvals = activity.approvals.max(db_stats.approvals);

    println!("  Events: {} total", total);
    println!("  Blocks: {blocks}");
    println!("  Allows: {allows}");
    println!("  Approvals: {approvals}");

    if !db_stats.top_categories.is_empty() {
        println!();
        println!("  Top blocked categories:");
        for (cat, cnt) in &db_stats.top_categories {
            println!("    {cat}: {cnt}");
        }
    }

    if let (Some(ref first), Some(ref last)) = (db_stats.first_event, db_stats.last_event) {
        let first_short = if first.len() >= 10 {
            &first[..10]
        } else {
            first
        };
        let last_short = if last.len() >= 10 { &last[..10] } else { last };
        println!();
        println!("  Date range: {first_short} to {last_short}");
    }

    // Show recent events from SQLite if available
    if !recent_events.is_empty() {
        println!();
        println!("  Recent events:");
        for e in &recent_events {
            let ts = if e.timestamp.len() >= 19 {
                &e.timestamp[..19]
            } else {
                &e.timestamp
            };
            let icon = match e.event_type.as_str() {
                "block" => "\x1b[31mBLOCK\x1b[0m",
                "allow" => "\x1b[32mALLOW\x1b[0m",
                "approved" => "\x1b[33mAPPROVED\x1b[0m",
                _ => &e.event_type,
            };
            let cmd_display = if e.command.len() > 50 {
                format!("{}...", &e.command[..47])
            } else {
                e.command.clone()
            };
            println!("    {ts}  [{icon}] {cmd_display}");
            if !e.category.is_empty() {
                println!("      \x1b[90mcategory: {}\x1b[0m", e.category);
            }
        }
    } else if !activity.recent_blocks.is_empty() {
        // Fallback to JSONL data
        println!();
        println!("  Recent blocks:");
        for b in &activity.recent_blocks {
            let ts = if b.timestamp.len() >= 19 {
                &b.timestamp[..19]
            } else {
                &b.timestamp
            };
            println!("    {} [{}]", ts, b.category);
            if !b.command.is_empty() {
                println!("      cmd: {}", b.command);
            }
        }
    }

    if db_size > 0 {
        let size_str = if db_size > 1_048_576 {
            format!("{:.1} MB", db_size as f64 / 1_048_576.0)
        } else {
            format!("{:.0} KB", db_size as f64 / 1024.0)
        };
        println!();
        println!("  \x1b[90mDatabase: {size_str}\x1b[0m");
    }
}

fn cmd_allowlist(sub: AllowlistCommand) {
    match sub {
        AllowlistCommand::List { json } => cmd_allowlist_list(json),
        AllowlistCommand::Add { entry_type, value } => cmd_allowlist_add(entry_type, &value),
        AllowlistCommand::Remove { entry_type, value } => cmd_allowlist_remove(entry_type, &value),
    }
}

fn cmd_allowlist_list(json: bool) {
    let cfg = config::load_config().unwrap_or_default();

    // Show both built-in defaults and user additions
    let builtin = hedgehog_taint::allowlist::Allowlist::new();

    if json {
        let output = serde_json::json!({
            "user_domains": cfg.allowlist.extra_domains,
            "user_suffixes": cfg.allowlist.extra_suffixes,
            "user_ips": cfg.allowlist.extra_ips,
            "builtin_note": "Built-in allowlist includes GitHub, npm, PyPI, crates.io, Docker Hub, and other common developer services",
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!("Gorse Allowlist");
    println!("==================\n");

    println!("  \x1b[1mBuilt-in\x1b[0m (always allowed):");
    println!("    Includes: GitHub, npm, PyPI, crates.io, Docker Hub, Homebrew,");
    println!("    Maven Central, NuGet, Cargo, Terraform Registry, and more.");
    println!("    Run `gorse explain <command>` to check if a specific domain is allowed.\n");

    println!("  \x1b[1mUser domains\x1b[0m:");
    if cfg.allowlist.extra_domains.is_empty() {
        println!("    \x1b[90m(none)\x1b[0m");
    } else {
        for d in &cfg.allowlist.extra_domains {
            println!("    \x1b[32m+\x1b[0m {d}");
        }
    }

    println!();
    println!("  \x1b[1mUser suffixes\x1b[0m (matches *.suffix):");
    if cfg.allowlist.extra_suffixes.is_empty() {
        println!("    \x1b[90m(none)\x1b[0m");
    } else {
        for s in &cfg.allowlist.extra_suffixes {
            println!("    \x1b[32m+\x1b[0m *.{s}");
        }
    }

    println!();
    println!("  \x1b[1mUser IPs\x1b[0m:");
    if cfg.allowlist.extra_ips.is_empty() {
        println!("    \x1b[90m(none)\x1b[0m");
    } else {
        for ip in &cfg.allowlist.extra_ips {
            println!("    \x1b[32m+\x1b[0m {ip}");
        }
    }

    let total_user = cfg.allowlist.extra_domains.len()
        + cfg.allowlist.extra_suffixes.len()
        + cfg.allowlist.extra_ips.len();
    println!();
    println!(
        "  \x1b[90m{total_user} user entries in {}\x1b[0m",
        config::config_path().display()
    );

    let _ = builtin; // used for doc display only
}

fn cmd_allowlist_add(entry_type: AllowlistEntryType, value: &str) {
    let mut cfg = config::load_config().unwrap_or_default();

    let (list, label) = match entry_type {
        AllowlistEntryType::Domain => (&mut cfg.allowlist.extra_domains, "domain"),
        AllowlistEntryType::Suffix => (&mut cfg.allowlist.extra_suffixes, "suffix"),
        AllowlistEntryType::Ip => (&mut cfg.allowlist.extra_ips, "IP"),
    };

    let val = value.to_lowercase();
    if list.contains(&val) {
        println!("{label} '{val}' is already in the allowlist.");
        return;
    }

    list.push(val.clone());
    match config::save_config(&cfg) {
        Ok(()) => {
            println!("Added {label} '{val}' to allowlist.");
            println!("Saved to {}", config::config_path().display());
        }
        Err(e) => {
            eprintln!("Failed to save config: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_allowlist_remove(entry_type: AllowlistEntryType, value: &str) {
    let mut cfg = config::load_config().unwrap_or_default();

    let (list, label) = match entry_type {
        AllowlistEntryType::Domain => (&mut cfg.allowlist.extra_domains, "domain"),
        AllowlistEntryType::Suffix => (&mut cfg.allowlist.extra_suffixes, "suffix"),
        AllowlistEntryType::Ip => (&mut cfg.allowlist.extra_ips, "IP"),
    };

    let val = value.to_lowercase();
    let before = list.len();
    list.retain(|v| v != &val);

    if list.len() == before {
        println!("{label} '{val}' was not in the allowlist.");
        return;
    }

    match config::save_config(&cfg) {
        Ok(()) => {
            println!("Removed {label} '{val}' from allowlist.");
            println!("Saved to {}", config::config_path().display());
        }
        Err(e) => {
            eprintln!("Failed to save config: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_watch(command: &[String]) {
    if command.is_empty() {
        eprintln!("Usage: gorse watch -- npm install");
        eprintln!("       gorse watch -- pip install requests");
        std::process::exit(1);
    }

    let cmd_str = command.join(" ");
    let program = &command[0];
    let args = &command[1..];

    // Detect package manager
    let pm_name = match program.as_str() {
        "npm" | "npx" | "yarn" | "pnpm" => "npm",
        "pip" | "pip3" | "pipx" | "uv" => "pip",
        "cargo" => "cargo",
        "gem" | "bundle" => "gem",
        "go" => "go",
        _ => "unknown",
    };

    println!("Gorse Watch: monitoring {pm_name} install");
    println!("{}", "=".repeat(42));
    println!();

    // Snapshot secret files before install
    let detector = SecretDetector::new();
    let secrets_before: Vec<_> = detector
        .scan_results()
        .into_iter()
        .map(|s| s.path.clone())
        .collect();

    let _secret_paths_str: Vec<_> = secrets_before
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    println!(
        "  Monitoring {} secret files during install...",
        secrets_before.len()
    );
    println!("  Running: {cmd_str}");
    println!();

    // Run the command
    let start = std::time::Instant::now();
    let status = std::process::Command::new(program).args(args).status();

    let elapsed = start.elapsed();

    match status {
        Ok(s) => {
            println!();
            if !s.success() {
                println!(
                    "  \x1b[33mCommand exited with status {}\x1b[0m",
                    s.code().unwrap_or(-1)
                );
            }
        }
        Err(e) => {
            eprintln!("Failed to run '{program}': {e}");
            std::process::exit(1);
        }
    }

    // Check for new/modified secret files after install
    println!("  Post-install check ({:.1}s):", elapsed.as_secs_f64());
    println!();

    // Scan for new content findings in common install locations
    let mut suspicious = Vec::new();

    // Check if any secret files were modified during install
    for secret_path in &secrets_before {
        if let Ok(meta) = std::fs::metadata(secret_path) {
            if let Ok(modified) = meta.modified() {
                if let Ok(elapsed_since) = modified.elapsed() {
                    if elapsed_since < elapsed + std::time::Duration::from_secs(2) {
                        suspicious.push(format!(
                            "Secret file modified during install: {}",
                            secret_path.display()
                        ));
                    }
                }
            }
        }
    }

    // Check for new .env files or secret-like files created during install
    let cwd = std::env::current_dir().unwrap_or_default();
    let node_modules = cwd.join("node_modules");
    if node_modules.exists() {
        // Quick scan of node_modules for suspicious postinstall artifacts
        check_install_artifacts(&node_modules, &mut suspicious);
    }

    if suspicious.is_empty() {
        println!("  \x1b[32mNo suspicious activity detected.\x1b[0m");
        println!("  The install appears clean.");
    } else {
        println!("  \x1b[31mSuspicious activity detected:\x1b[0m");
        for s in &suspicious {
            println!("    \x1b[31m!\x1b[0m {s}");
        }
        println!();
        println!("  \x1b[1mAction:\x1b[0m Review these findings before proceeding.");

        // Log the suspicious activity
        for s in &suspicious {
            logging::log_event(
                "watch_alert",
                None,
                Some(pm_name),
                Some(&cmd_str),
                Some("supply-chain"),
                None,
                Some(s),
                None,
            );
            history::record_event(
                "watch_alert",
                None,
                Some(pm_name),
                Some(&cmd_str),
                Some("supply-chain"),
                None,
                Some(s),
                None,
            );
        }

        std::process::exit(1);
    }
}

/// Check for suspicious artifacts in install directories.
fn check_install_artifacts(dir: &std::path::Path, suspicious: &mut Vec<String>) {
    // Look for postinstall scripts that access secret paths
    let _suspicious_files = [".env", "postinstall.sh", "preinstall.sh"];

    // Only scan one level deep in node_modules (package roots)
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Check package.json for suspicious postinstall scripts
        let pkg_json = path.join("package.json");
        if pkg_json.exists() {
            if let Ok(contents) = std::fs::read_to_string(&pkg_json) {
                // Look for scripts that reference secret paths
                let secret_indicators = [
                    ".ssh",
                    ".aws",
                    ".env",
                    "credentials",
                    ".gnupg",
                    "id_rsa",
                    "secret",
                    "token",
                    "/etc/passwd",
                    "curl",
                    "wget",
                    "nc ",
                    "base64",
                ];
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if let Some(scripts) = parsed.get("scripts") {
                        let scripts_str = scripts.to_string().to_lowercase();
                        for indicator in &secret_indicators {
                            if scripts_str.contains(indicator) {
                                suspicious.push(format!(
                                    "Package '{}' has suspicious postinstall referencing '{}'",
                                    path.file_name().unwrap_or_default().to_string_lossy(),
                                    indicator
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── DNS resolver restriction (T-08) ────────────────────────────────────────

fn cmd_dns(sub: DnsCommand) {
    match sub {
        DnsCommand::List { json } => cmd_dns_list(json),
        DnsCommand::Add { ip } => cmd_dns_add(&ip),
        DnsCommand::Remove { ip } => cmd_dns_remove(&ip),
    }
}

fn load_system_resolvers() -> Vec<String> {
    let mut resolvers = Vec::new();
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                if let Some(ip) = trimmed.split_whitespace().nth(1) {
                    resolvers.push(ip.to_string());
                }
            }
        }
    }
    resolvers
}

fn cmd_dns_list(json: bool) {
    let system_resolvers = load_system_resolvers();
    let cfg = config::load_config().unwrap_or_default();

    if json {
        let output = serde_json::json!({
            "system_resolvers": system_resolvers,
            "public_fallbacks": ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"],
            "custom_resolvers": cfg.allowlist.extra_dns_resolvers,
            "note": "Port 53 traffic is restricted to these resolvers to prevent DNS exfiltration",
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    println!("DNS Resolver Restrictions");
    println!("=========================\n");
    println!("  Port 53 traffic is restricted to trusted resolvers.");
    println!("  This prevents DNS exfiltration (encoding secrets in DNS queries).\n");

    println!("  \x1b[1mSystem resolvers\x1b[0m (from /etc/resolv.conf):");
    if system_resolvers.is_empty() {
        println!("    \x1b[90m(none detected — using public fallbacks)\x1b[0m");
    } else {
        for r in &system_resolvers {
            println!("    {r}");
        }
    }

    println!();
    println!("  \x1b[1mPublic fallbacks\x1b[0m:");
    println!("    8.8.8.8  (Google)");
    println!("    8.8.4.4  (Google)");
    println!("    1.1.1.1  (Cloudflare)");
    println!("    1.0.0.1  (Cloudflare)");

    println!();
    println!("  \x1b[1mCustom resolvers\x1b[0m:");
    if cfg.allowlist.extra_dns_resolvers.is_empty() {
        println!("    \x1b[90m(none)\x1b[0m");
    } else {
        for r in &cfg.allowlist.extra_dns_resolvers {
            println!("    \x1b[32m+\x1b[0m {r}");
        }
    }

    println!();
    println!(
        "  \x1b[90mAny other DNS server on port 53 will be blocked for tainted processes.\x1b[0m"
    );
}

fn cmd_dns_add(ip: &str) {
    if !ip.contains('.') && !ip.contains(':') {
        eprintln!("Invalid IP address: {ip}");
        std::process::exit(1);
    }

    let mut cfg = config::load_config().unwrap_or_default();
    let val = ip.to_string();

    if cfg.allowlist.extra_dns_resolvers.contains(&val) {
        println!("DNS resolver '{val}' is already in the list.");
        return;
    }

    cfg.allowlist.extra_dns_resolvers.push(val.clone());
    match config::save_config(&cfg) {
        Ok(()) => {
            println!("Added DNS resolver '{val}'.");
            println!("Saved to {}", config::config_path().display());
        }
        Err(e) => {
            eprintln!("Failed to save config: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_dns_remove(ip: &str) {
    let mut cfg = config::load_config().unwrap_or_default();
    let val = ip.to_string();
    let before = cfg.allowlist.extra_dns_resolvers.len();
    cfg.allowlist.extra_dns_resolvers.retain(|v| v != &val);

    if cfg.allowlist.extra_dns_resolvers.len() == before {
        println!("DNS resolver '{val}' was not in the custom list.");
        return;
    }

    match config::save_config(&cfg) {
        Ok(()) => {
            println!("Removed DNS resolver '{val}'.");
            println!("Saved to {}", config::config_path().display());
        }
        Err(e) => {
            eprintln!("Failed to save config: {e}");
            std::process::exit(1);
        }
    }
}

// ─── Per-project allowlist scoping (T-10) ────────────────────────────────────

fn cmd_project(sub: ProjectCommand) {
    match sub {
        ProjectCommand::Init { name } => cmd_project_init(name),
        ProjectCommand::List => cmd_project_list(),
        ProjectCommand::Show => cmd_project_show(),
    }
}

fn cmd_project_init(name: Option<String>) {
    let cwd = std::env::current_dir().unwrap_or_default();
    let config_path = cwd.join("hedgehog.toml");

    if config_path.exists() {
        println!("hedgehog.toml already exists in this directory.");
        println!("Edit it directly: {}", config_path.display());
        return;
    }

    let project_name = name.unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("my-project")
            .to_string()
    });

    let template = format!(
        r#"# Gorse project configuration
# Only these domains/services will be allowed for tainted processes
# running within this project directory.

name = "{project_name}"

# Allowed domains (exact match)
allow_domains = [
    "github.com",
    "api.github.com",
]

# Allowed domain suffixes (matches all subdomains)
# allow_suffixes = [".amazonaws.com"]

# Examples by project type:
#
# Node.js web app:
#   allow_domains = ["registry.npmjs.org", "api.stripe.com", "github.com"]
#
# Rust CLI tool:
#   allow_domains = ["crates.io", "static.crates.io", "github.com"]
#
# Python ML project:
#   allow_domains = ["pypi.org", "files.pythonhosted.org", "huggingface.co"]
"#
    );

    match std::fs::write(&config_path, &template) {
        Ok(()) => {
            println!("Created hedgehog.toml in {}", cwd.display());
            println!();
            println!("  Project: {project_name}");
            println!("  Config:  {}", config_path.display());
            println!();
            println!("Edit the file to add the domains your project needs.");
            println!("Only these domains will be allowed for tainted processes in this directory.");
        }
        Err(e) => {
            eprintln!("Failed to create hedgehog.toml: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_project_list() {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut found: Vec<(std::path::PathBuf, String)> = Vec::new();

    // Scan common project directories for hedgehog.toml
    let search_dirs = [
        format!("{home}/Documents"),
        format!("{home}/Documents/GitHub"),
        format!("{home}/Projects"),
        format!("{home}/Code"),
        format!("{home}/Developer"),
        format!("{home}/src"),
        format!("{home}/repos"),
        format!("{home}/work"),
        format!("{home}/GitHub"),
    ];

    for dir in &search_dirs {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let toml_path = entry.path().join("hedgehog.toml");
                if toml_path.exists() {
                    if let Ok(contents) = std::fs::read_to_string(&toml_path) {
                        if let Some(config) =
                            hedgehog_taint::project::parse_project_config(&entry.path(), &contents)
                        {
                            found.push((entry.path(), config.name));
                        }
                    }
                }
            }
        }
    }

    // Also check CWD
    let cwd = std::env::current_dir().unwrap_or_default();
    let cwd_toml = cwd.join("hedgehog.toml");
    if cwd_toml.exists() && !found.iter().any(|(p, _)| p == &cwd) {
        if let Ok(contents) = std::fs::read_to_string(&cwd_toml) {
            if let Some(config) = hedgehog_taint::project::parse_project_config(&cwd, &contents) {
                found.push((cwd, config.name));
            }
        }
    }

    println!("Gorse Projects");
    println!("==================\n");

    if found.is_empty() {
        println!("  No projects with hedgehog.toml found.");
        println!();
        println!("  Create one:");
        println!("    cd /path/to/your/project");
        println!("    gorse project init");
    } else {
        for (path, name) in &found {
            let short = shorten_home(path, &home);
            println!("  \x1b[1m{name}\x1b[0m");
            println!("    {short}/hedgehog.toml");
        }
        println!();
        println!("  {} project(s) found", found.len());
    }
}

fn cmd_project_show() {
    let cwd = std::env::current_dir().unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();

    // Walk up to find hedgehog.toml
    let mut dir = cwd.as_path();
    loop {
        let toml_path = dir.join("hedgehog.toml");
        if toml_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&toml_path) {
                if let Some(config) = hedgehog_taint::project::parse_project_config(dir, &contents)
                {
                    let short = shorten_home(&dir.to_path_buf(), &home);
                    println!("Project: {}", config.name);
                    println!("Root:    {short}");
                    println!("Config:  {}/hedgehog.toml", short);
                    println!();
                    println!("  Allowed domains:");
                    if config.allowlist.is_allowed("test-placeholder.invalid", 443) {
                        // Has entries — show them by re-parsing
                    }
                    // Re-parse raw TOML to extract domain/suffix lists
                    let mut domains = Vec::new();
                    let mut suffixes = Vec::new();
                    for line in contents.lines() {
                        let trimmed = line.trim().trim_matches('"').trim_matches(',').trim();
                        // Heuristic: lines with dots that aren't comments/keys
                        if trimmed.starts_with('#') || trimmed.is_empty() {
                            continue;
                        }
                        if trimmed.starts_with("allow_domains")
                            || trimmed.starts_with("allow_suffixes")
                            || trimmed == "["
                            || trimmed == "]"
                            || trimmed.starts_with("name")
                        {
                            continue;
                        }
                        if trimmed.contains('.') && !trimmed.contains('=') {
                            let clean = trimmed.trim_matches(|c: char| {
                                !c.is_alphanumeric() && c != '.' && c != '-'
                            });
                            if !clean.is_empty() {
                                if clean.starts_with('.') {
                                    suffixes.push(clean.to_string());
                                } else {
                                    domains.push(clean.to_string());
                                }
                            }
                        }
                    }
                    if domains.is_empty() && suffixes.is_empty() {
                        println!("    \x1b[90m(none configured)\x1b[0m");
                    }
                    for d in &domains {
                        println!("    {d}");
                    }
                    if !suffixes.is_empty() {
                        println!("  Allowed suffixes:");
                        for s in &suffixes {
                            println!("    *{s}");
                        }
                    }
                    println!();
                    println!("  Tainted processes in this directory tree will be restricted");
                    println!("  to only these destinations (plus localhost).");
                    return;
                }
            }
            eprintln!("Found hedgehog.toml but could not parse it.");
            std::process::exit(1);
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }

    println!("No hedgehog.toml found in the current directory tree.");
    println!();
    println!("Create one: gorse project init");
}

// ─── U-06: Process tree visualization ─────────────────────────────────────────

/// Directory where the kernel extension publishes its shared state
/// (`tainted.json`, `status.json`). On macOS the extension runs as root and
/// writes here world-readable. `GORSE_STATE_DIR` (or the older
/// `HEDGEHOG_STATE_DIR`) overrides it so the readers can be exercised on a
/// dev machine without root.
pub(crate) fn shared_state_dir() -> std::path::PathBuf {
    match crate::config::env_var("STATE_DIR") {
        Some(dir) if !dir.is_empty() => std::path::PathBuf::from(dir),
        _ => std::path::PathBuf::from("/Library/Application Support/Hedgehog"),
    }
}

/// Seconds since an ISO 8601 timestamp written by the extension, or None if
/// it does not parse. Never negative, so clock skew reads as "just now".
pub(crate) fn state_age_secs(updated: &str) -> Option<i64> {
    let then = chrono::DateTime::parse_from_rfc3339(updated).ok()?;
    let age = chrono::Utc::now() - then.with_timezone(&chrono::Utc);
    Some(age.num_seconds().max(0))
}

/// Human form of an age: "12s ago", "3m ago", "2h ago", "5d ago".
pub(crate) fn format_age(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// Read the first tainted.json that matches the extension's contract
/// (`{"updated": ..., "processes": [...]}`). The extension's shared state
/// dir is tried first, then ~/.hedgehog for the Linux/Windows daemons.
/// On failure returns the path that was expected, so the caller can say
/// exactly where it looked.
fn load_tainted_state() -> Result<(std::path::PathBuf, serde_json::Value), std::path::PathBuf> {
    let primary = shared_state_dir().join("tainted.json");
    let fallback = config::config_dir().join("tainted.json");

    for path in [&primary, &fallback] {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Ok(state) = serde_json::from_str::<serde_json::Value>(&contents) {
            if state.get("processes").is_some_and(|p| p.is_array()) {
                return Ok((path.clone(), state));
            }
        }
        // Present but empty or malformed: report this file rather than
        // silently falling through to the next candidate.
        return Err(path.clone());
    }
    Err(primary)
}

/// One-line explanation of why there is no tree to show.
fn no_tree_message(expected: &std::path::Path) -> String {
    let why = if expected.exists() {
        "is empty or not valid JSON"
    } else {
        "not found"
    };
    #[cfg(target_os = "macos")]
    {
        format!(
            "No process tree: {} {why} — the Gorse system extension is not running. Run 'gorse selftest' to check.",
            expected.display()
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        format!(
            "No process tree: {} {why} — the Gorse daemon is not running.",
            expected.display()
        )
    }
}

fn cmd_ptree(json: bool) {
    let (path, state) = match load_tainted_state() {
        Ok(found) => found,
        Err(expected) => {
            // Informational, not an error: the extension simply is not running.
            let message = no_tree_message(&expected);
            if json {
                let out = serde_json::json!({
                    "updated": null,
                    "processes": [],
                    "message": message,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!("{message}");
            }
            return;
        }
    };

    if json {
        // In JSON mode, pass the extension's document through as-is
        println!("{}", serde_json::to_string_pretty(&state).unwrap());
        return;
    }

    println!("Gorse Process Tree");
    println!("=====================\n");

    // Show how fresh the snapshot is so a dead extension is obvious
    let updated = match state.get("updated").and_then(|u| u.as_str()) {
        Some(u) => match state_age_secs(u) {
            Some(secs) => format!("updated {}", format_age(secs)),
            None => format!("updated {u}"),
        },
        None => "update time unknown".to_string(),
    };
    println!("\x1b[2m{updated} — {}\x1b[0m", path.display());
    println!();

    let processes = state
        .get("processes")
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if processes.is_empty() {
        println!("  No tainted processes.");
        return;
    }

    for node in processes {
        print_tree_node(node, 0);
    }
}

fn print_tree_node(node: &serde_json::Value, depth: usize) {
    let indent = "  ".repeat(depth);
    let connector = if depth > 0 { "\u{2514}\u{2500} " } else { "" };
    let pid = node.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
    let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    let tainted = node
        .get("tainted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let status = if tainted {
        "\x1b[31mTAINTED\x1b[0m"
    } else {
        "\x1b[32mclean\x1b[0m"
    };
    println!("{indent}{connector}[{pid}] {name} ({status})");

    // Executable and the secrets it read, dimmed under the node
    let detail = if depth > 0 {
        format!("{indent}     ")
    } else {
        "  ".to_string()
    };
    if let Some(exe) = node.get("exe").and_then(|v| v.as_str()) {
        println!("{detail}\x1b[2mexe: {exe}\x1b[0m");
    }
    if let Some(secrets) = node.get("secrets").and_then(|v| v.as_array()) {
        for secret in secrets.iter().filter_map(|s| s.as_str()) {
            println!("{detail}\x1b[2msecret: {secret}\x1b[0m");
        }
    }

    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            print_tree_node(child, depth + 1);
        }
    }
}

// ─── U-09: Linux systemd service ──────────────────────────────────────────────

fn cmd_service(action: ServiceAction) {
    match action {
        ServiceAction::Install => service_install(),
        ServiceAction::Uninstall => service_uninstall(),
        ServiceAction::Status => service_status(),
    }
}

fn service_install() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("The service command is only available on Linux (systemd).");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        let binary = std::env::current_exe().unwrap_or_else(|_| {
            eprintln!("Could not determine binary path");
            std::process::exit(1);
        });

        let unit = format!(
            "[Unit]\n\
             Description=Gorse Security Daemon\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={} daemon\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            binary.display()
        );

        let service_dir = std::env::var("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".config/systemd/user"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/etc/systemd/user"));

        let service_path = service_dir.join("gorse.service");

        if let Err(e) = std::fs::create_dir_all(&service_dir) {
            eprintln!("Failed to create systemd directory: {e}");
            std::process::exit(1);
        }

        if let Err(e) = std::fs::write(&service_path, &unit) {
            eprintln!("Failed to write service file: {e}");
            std::process::exit(1);
        }

        println!("Installed: {}", service_path.display());

        // Enable and start
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", "gorse.service"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "start", "gorse.service"])
            .status();

        println!("Gorse daemon enabled and started.");
        println!();
        println!("  Check status: gorse service status");
        println!("  View logs:    journalctl --user -u gorse -f");
    }
}

fn service_uninstall() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("The service command is only available on Linux (systemd).");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "gorse.service"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "gorse.service"])
            .status();

        let service_path = std::env::var("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".config/systemd/user/gorse.service"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/etc/systemd/user/gorse.service"));

        if service_path.exists() {
            let _ = std::fs::remove_file(&service_path);
            println!("Removed: {}", service_path.display());
        }

        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();

        println!("Gorse systemd service uninstalled.");
    }
}

fn service_status() {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("The service command is only available on Linux (systemd).");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("systemctl")
            .args(["--user", "status", "gorse.service"])
            .status();

        match status {
            Ok(s) if s.success() => {}
            _ => {
                println!("Gorse service is not running.");
                println!("Install with: gorse service install");
            }
        }
    }
}

// ─── L-10: SSO login ─────────────────────────────────────────────────────────

fn cmd_sso_login() {
    match sso::load_sso_config() {
        Some(config) => {
            match sso::start_sso_login(&config) {
                Ok(result) => {
                    // Store the license key
                    if let Err(e) = credential_store::store_license_key(&result.license_key) {
                        eprintln!("SSO license could not be verified and stored: {e}");
                        std::process::exit(1);
                    }
                    println!("SSO login successful!");
                    println!("  Email: {}", result.email);
                    println!("  Org:   {}", result.org_name);
                    println!("  Tier:  {}", credential_store::current_tier().name());
                    println!();
                    println!("License key stored. Run 'gorse status' to verify.");
                }
                Err(e) => {
                    eprintln!("SSO login failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            eprintln!("No SSO configuration found.");
            eprintln!();
            eprintln!("Create ~/.hedgehog/sso.toml with your organization's SSO settings:");
            eprintln!();
            eprintln!("  provider = \"workos\"");
            eprintln!("  org_id = \"org_...\"");
            eprintln!("  auth_url = \"https://api.workos.com/sso/authorize\"");
            eprintln!("  token_url = \"https://api.workos.com/sso/token\"");
            eprintln!("  client_id = \"client_...\"");
            eprintln!();
            eprintln!("Contact your admin or visit gorse.is/docs/sso for setup instructions.");
            std::process::exit(1);
        }
    }
}

fn cmd_alerts_test() {
    println!("Sending test alert to all configured channels...\n");
    let results = alerting::send_test();
    let mut all_ok = !results.is_empty();
    for (channel, result) in &results {
        match result {
            Ok(()) => {
                println!("  {} ... provider accepted test", channel);
            }
            Err(e) => {
                println!("  {} ... FAILED: {}", channel, e);
                all_ok = false;
            }
        }
    }
    if all_ok {
        println!(
            "\nAll configured providers accepted the test. Confirm receipt on your device(s)."
        );
        println!("This channel test does not verify canary sensing or network blocking.");
    } else {
        eprintln!(
            "\nAlert channel test incomplete: at least one channel failed or none is configured."
        );
        std::process::exit(1);
    }
}

fn report_alert_persistence(result: Result<(), String>) {
    if let Err(e) = result {
        eprintln!("ALERT PERSISTENCE FAILED: {e}");
    }
}

fn canary_check_unavailable(error: &str) -> ! {
    eprintln!("Canary checking unavailable: {error}");
    println!(
        "{}",
        serde_json::json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "Canary registry cannot be verified. Repair monitoring before retrying."
        }})
    );
    std::process::exit(2);
}

fn cmd_alerts_setup() {
    println!("Gorse Alert Setup");
    println!("====================\n");
    println!("Add alert channels to your config file:\n");
    println!("  {}\n", config::config_path().display());
    println!("Example (Telegram):\n");
    println!("  [alerts]");
    println!("  enabled = true\n");
    println!("  [alerts.telegram]");
    println!("  bot_token = \"123456:ABC-DEF...\"");
    println!("  chat_id = \"987654321\"\n");
    println!("Steps for Telegram:");
    println!("  1. Message @BotFather on Telegram, send /newbot");
    println!("  2. Copy the bot token into config.toml");
    println!("  3. Start a chat with your new bot");
    println!("  4. Visit https://api.telegram.org/bot<TOKEN>/getUpdates");
    println!("  5. Find your chat_id in the response JSON");
    println!("  6. Run: gorse alerts test\n");
    println!("Other channels: [alerts.whatsapp], [alerts.twilio], [alerts.webhook]");
    println!("See https://gorse.is/docs/alerts for full documentation.");
}

fn cmd_alerts_status() {
    for line in alerting::status_lines() {
        println!("{}", line);
    }
    for line in canary_watcher::status_lines() {
        println!("{line}");
    }
    for line in alerting::heartbeat_status_lines() {
        println!("{line}");
    }
}

fn cmd_version(check: bool, json: bool) {
    let current = env!("CARGO_PKG_VERSION");
    if json {
        let result = if check {
            update_check::check_detailed(true)
        } else {
            None
        };
        let newer = result.as_ref().and_then(|c| c.newer());
        println!(
            "{}",
            serde_json::json!({
                "version": current,
                "platform": platform_name(),
                "arch": std::env::consts::ARCH,
                "checked": check,
                "latest": result.as_ref().map(|c| c.latest.clone()),
                "tag": result.as_ref().map(|c| c.tag.clone()),
                "newer_available": newer.is_some(),
                "download_url": update_check::DOWNLOAD_URL,
                "signature": result.as_ref().and_then(|c| c.signature_label()),
                "sha256": result.as_ref().and_then(|c| c.sha256.clone()),
            })
        );
        return;
    }
    println!("gorse {current}");
    println!("Platform: {}", platform_name());
    println!("Arch: {}", std::env::consts::ARCH);
    let engine = load_engine();
    println!("Security packs: {} rules", engine.rule_count());
    println!("Kernel bridge: {}", kernel_bridge_status());
    if check {
        match update_check::check_detailed(true) {
            Some(result) => match result.notice_line() {
                Some(line) => println!("{line}"),
                None => println!("Up to date (latest is {}).", result.latest),
            },
            None => println!("Could not reach gorse.is to check for a newer version."),
        }
    } else if let Some(line) = update_check::passive_notice() {
        println!("{line}");
    }
}

/// `gorse verify-download <FILE>`: hash the file, fetch and verify the
/// signed manifest for the release, and compare. Exit 0 only when the
/// signature verified and the hash matches; 1 when the file is not the
/// published one (hash mismatch or name not in the manifest); 2 when the
/// manifest is missing, invalid or unreachable (nothing can be said).
fn cmd_verify_download(file: &std::path::Path, tag: Option<String>, json: bool) {
    use release_signature::FetchError;

    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_string())
        .unwrap_or_default();
    let finish = |code: i32,
                  result: &str,
                  tag: Option<&str>,
                  sha256: Option<&str>,
                  expected: Option<&str>,
                  message: String|
     -> ! {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "file": file.display().to_string(),
                    "name": name,
                    "tag": tag,
                    "sha256": sha256,
                    "expected_sha256": expected,
                    "verified": code == 0,
                    "result": result,
                    "message": message,
                })
            );
        } else if code == 0 {
            println!("{message}");
        } else {
            eprintln!("{message}");
        }
        std::process::exit(code);
    };

    if name.is_empty() {
        finish(
            1,
            "not_a_file",
            None,
            None,
            None,
            format!("{} is not a file name.", file.display()),
        );
    }
    let sha256 = match release_signature::sha256_file(file) {
        Ok(hash) => hash,
        Err(e) => finish(
            1,
            "unreadable",
            None,
            None,
            None,
            format!("Cannot read {}: {e}", file.display()),
        ),
    };
    // A tag the person typed may be checked against an older (v1,
    // tag-unbound) manifest for releases before v0.4.2; a tag taken from
    // the server never is, since nothing then ties the manifest to it.
    let explicit = tag.is_some();
    let tag = match tag {
        Some(t) => {
            let t = t.trim().to_string();
            if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                format!("v{t}")
            } else {
                t
            }
        }
        None => match update_check::fetch_latest() {
            Some(latest) => latest.tag,
            None => finish(
                2,
                "unreachable",
                None,
                Some(&sha256),
                None,
                "Could not reach gorse.is to find the latest release. Check your connection, or pass --tag vX.Y.Z.".to_string(),
            ),
        },
    };
    let policy = if explicit {
        release_signature::V1Policy::AcceptBeforeV2
    } else {
        release_signature::V1Policy::Reject
    };
    let manifest = match release_signature::fetch_manifest(&tag, policy) {
        Ok(manifest) => manifest,
        Err(error) => {
            let message = match &error {
                FetchError::Missing => format!(
                    "Not verified: no signed manifest is published for {tag}, so this file cannot be checked. See {}",
                    update_check::SECURITY_URL
                ),
                FetchError::Unbound if explicit => format!(
                    "Not verified: the signed manifest for {tag} does not name the release (older signature format), and releases from v{} on must. Do not use this download. See {}",
                    release_signature::FIRST_V2_VERSION,
                    update_check::SECURITY_URL
                ),
                FetchError::Unbound => format!(
                    "Not verified: the signed manifest for {tag} does not name the release (older signature format). If you downloaded a release before v{}, pass --tag {tag} to check the file against it. See {}",
                    release_signature::FIRST_V2_VERSION,
                    update_check::SECURITY_URL
                ),
                FetchError::Invalid(why) => format!(
                    "Not verified: the signed manifest for {tag} is not valid ({why}). Do not use this download. See {}",
                    update_check::SECURITY_URL
                ),
                FetchError::Network(why) => format!(
                    "Not verified: could not fetch the signed manifest for {tag} ({why}). Check your connection and try again."
                ),
            };
            finish(2, error.label(), Some(&tag), Some(&sha256), None, message);
        }
    };
    match manifest.entries.get(&name) {
        None => finish(
            1,
            "not_in_manifest",
            Some(&tag),
            Some(&sha256),
            None,
            format!("Not verified: {name} is not one of the files published for {tag}."),
        ),
        Some(expected) if *expected != sha256 => finish(
            1,
            "mismatch",
            Some(&tag),
            Some(&sha256),
            Some(expected),
            format!(
                "Not verified: {name} does not match the file QKey published for {tag}. Delete it and download again from {}",
                update_check::DOWNLOAD_URL
            ),
        ),
        Some(expected) => finish(
            0,
            "verified",
            Some(&tag),
            Some(&sha256),
            Some(expected),
            if manifest.tag_bound {
                format!("Verified: {name} matches the signed manifest for {tag}")
            } else {
                format!("Verified: {name} matches the signed manifest for {tag} (older signature format: the manifest's hashes are signed, the release tag is not)")
            },
        ),
    }
}

fn platform_name() -> &'static str {
    #[cfg(target_os = "macos")]
    return "macOS (ESF)";
    #[cfg(windows)]
    return "Windows (ETW + WFP)";
    #[cfg(target_os = "linux")]
    return "Linux (eBPF)";
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    return "Unknown";
}

fn kernel_bridge_status() -> String {
    #[cfg(target_os = "macos")]
    return "ESF (requires Hedgehog.app)".to_string();
    #[cfg(windows)]
    return "ETW + WFP (user-mode, no driver signing)".to_string();
    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "linux-daemon")]
        {
            let kernel_ok = hedgehog_linux::check_kernel_version().is_ok();
            let caps_ok = hedgehog_linux::check_capabilities().is_ok();
            if kernel_ok && caps_ok {
                return "eBPF (active — run 'gorse daemon' to start)".to_string();
            } else if caps_ok {
                return "fanotify fallback (kernel < 5.10, no eBPF)".to_string();
            } else {
                return "eBPF (needs CAP_BPF + CAP_NET_ADMIN, or run as root)".to_string();
            }
        }
        #[cfg(not(feature = "linux-daemon"))]
        return "not available (build with --features linux-daemon)".to_string();
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    return "not available".to_string();
}

fn add_platform_secrets(detector: &mut SecretDetector) {
    #[cfg(feature = "windows-daemon")]
    {
        hedgehog_windows::secrets::add_windows_secrets(detector);
    }
    #[cfg(feature = "linux-daemon")]
    {
        hedgehog_linux::secrets::add_linux_secrets(detector);
    }
    let _ = detector;
}

fn cmd_engines(cmd: EnginesCommand) {
    match cmd {
        EnginesCommand::Status { json } => {
            let installed = engines::trufflehog_installed();
            let on_path = installed.is_none() && trufflehog::locate().is_some();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "trufflehog": {
                            "installed": installed.is_some() || on_path,
                            "managed": installed.is_some(),
                            "path": installed.as_ref().map(|p| p.display().to_string()).or_else(|| trufflehog::locate().map(|p| p.display().to_string())),
                            "version": installed.as_ref().map(|p| engines::installed_version(p)),
                            "available_version": engines::TRUFFLEHOG_VERSION,
                            "download_mb": engines::TRUFFLEHOG_DOWNLOAD_MB,
                        }
                    })
                );
                return;
            }
            match (installed, on_path) {
                (Some(p), _) => println!(
                    "trufflehog: installed by Gorse at {} (version {})",
                    p.display(),
                    engines::installed_version(&p)
                ),
                (None, true) => println!("trufflehog: found on PATH (not managed by Gorse)"),
                (None, false) => println!(
                    "trufflehog: not installed. Add it with `gorse engines install trufflehog` ({} MB download from GitHub).",
                    engines::TRUFFLEHOG_DOWNLOAD_MB
                ),
            }
        }
        EnginesCommand::Install {
            name,
            json,
            progress,
        } => {
            if name != "trufflehog" {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"error": format!("unknown engine {name}")})
                    );
                } else {
                    eprintln!("Unknown engine {name}. Available: trufflehog");
                }
                std::process::exit(2);
            }
            let mut last = std::time::Instant::now() - std::time::Duration::from_secs(1);
            let mut on_progress = |got: u64, total: Option<u64>| {
                if !progress {
                    return;
                }
                let finished = total.is_some_and(|t| got >= t);
                if last.elapsed() < std::time::Duration::from_millis(200) && !finished {
                    return;
                }
                last = std::time::Instant::now();
                use std::io::Write;
                let mut err = std::io::stderr().lock();
                let _ = writeln!(
                    err,
                    "{}",
                    serde_json::json!({"event": "download", "received": got, "total": total})
                );
            };
            match engines::install_trufflehog(Some(&mut on_progress)) {
                Ok(path) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({"installed": "trufflehog", "path": path.display().to_string(), "version": engines::TRUFFLEHOG_VERSION})
                        );
                    } else {
                        println!(
                            "Installed TruffleHog {} at {}. Deep scans now use its detectors, with verification off.",
                            engines::TRUFFLEHOG_VERSION,
                            path.display()
                        );
                    }
                }
                Err(e) => {
                    if json {
                        println!("{}", serde_json::json!({"error": e}));
                    } else {
                        eprintln!("Could not install TruffleHog: {e}");
                    }
                    std::process::exit(2);
                }
            }
        }
        EnginesCommand::Remove { name, json } => {
            if name != "trufflehog" {
                eprintln!("Unknown engine {name}");
                std::process::exit(2);
            }
            match engines::remove_trufflehog() {
                Ok(removed) => {
                    if json {
                        println!("{}", serde_json::json!({"removed": removed}));
                    } else {
                        println!(
                            "{}",
                            if removed {
                                "Removed TruffleHog."
                            } else {
                                "TruffleHog was not installed by Gorse."
                            }
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Could not remove TruffleHog: {e}");
                    std::process::exit(2);
                }
            }
        }
    }
}

#[cfg(test)]
mod finding_noise_tests {
    use super::*;

    fn finding(path: &str, description: &str) -> serde_json::Value {
        serde_json::json!({"path": path, "description": description, "likelihood": 90, "category": "Seed Phrases"})
    }

    #[test]
    fn many_matches_of_one_kind_in_a_file_fold_into_one() {
        let mut list: Vec<_> = (0..40)
            .map(|_| finding("/d/words.txt", "BIP-39 mnemonic seed phrase"))
            .collect();
        list.push(finding("/d/notes.txt", "BIP-39 mnemonic seed phrase"));
        let out = collapse_repeats(list);
        assert_eq!(out.len(), 2);
        let folded = out.iter().find(|f| f["path"] == "/d/words.txt").unwrap();
        assert_eq!(folded["repeats"], 40);
        assert_eq!(folded["likelihood"], 35);
        assert!(folded["description"]
            .as_str()
            .unwrap()
            .starts_with("BIP-39 mnemonic seed phrase — 40 similar matches"));
        let single = out.iter().find(|f| f["path"] == "/d/notes.txt").unwrap();
        assert_eq!(
            single["likelihood"], 90,
            "a lone match keeps its likelihood"
        );
    }

    #[test]
    fn a_few_matches_are_left_alone() {
        let list: Vec<_> = (0..REPEATS_SHOWN)
            .map(|_| finding("/d/a.env", "Password"))
            .collect();
        assert_eq!(collapse_repeats(list).len(), REPEATS_SHOWN);
    }
}
