// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Integration tests for the Gorse taint engine.
//!
//! These tests exercise the full taint tracking lifecycle:
//! file open → taint → fork/exec propagation → connect decision → exit cleanup.

use hedgehog_taint::taint::{Decision, TaintEngine};
use hedgehog_taint::tier::Tier;
use std::path::Path;

/// Create an engine with personal tier (unlimited secrets) for integration tests.
fn engine() -> TaintEngine {
    let mut e = TaintEngine::new();
    e.activate_license(Tier::Pro, "integration-test".into(), 365);
    e
}

/// Helper: register a secret path.
fn add_secret(engine: &mut TaintEngine, path: &str) {
    engine.secrets_mut().add_path(path);
}

// ──────────────────────────────────────────────────────────────────
// Full lifecycle tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn full_lifecycle_taint_and_block() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    // 1. Process 100 opens a secret → should be tainted
    let decision = engine.on_file_open(100, Path::new("/home/user/.ssh/id_rsa"));
    assert_eq!(decision, Decision::Taint);
    assert!(engine.is_tainted(100));

    // 2. Tainted process tries to connect to unknown host → blocked
    let decision = engine.on_connect(100, "evil.com", 443);
    assert_eq!(decision, Decision::Block);

    // 3. Tainted process connects to allowlisted host → allowed
    let decision = engine.on_connect(100, "github.com", 443);
    assert_eq!(decision, Decision::Allow);

    // 4. Process exits → taint cleared
    engine.on_exit(100);
    assert!(!engine.is_tainted(100));
}

#[test]
fn fork_propagates_taint_to_child() {
    let mut engine = engine();
    add_secret(&mut engine, "/etc/shadow");

    // Parent reads secret
    engine.on_file_open(200, Path::new("/etc/shadow"));
    assert!(engine.is_tainted(200));

    // Parent forks child
    engine.on_fork(200, 201);
    assert!(engine.is_tainted(201));

    // Child is also blocked
    let decision = engine.on_connect(201, "attacker.com", 80);
    assert_eq!(decision, Decision::Block);

    // Parent exits, child still tainted
    engine.on_exit(200);
    assert!(engine.is_tainted(201));

    // Child exits
    engine.on_exit(201);
    assert!(!engine.is_tainted(201));
}

#[test]
fn exec_preserves_taint() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.aws/credentials");

    engine.on_file_open(300, Path::new("/home/user/.aws/credentials"));
    assert!(engine.is_tainted(300));

    // Process execs into curl
    engine.on_exec(300, Path::new("/usr/bin/curl"));
    assert!(engine.is_tainted(300));

    // Still blocked after exec
    let decision = engine.on_connect(300, "evil.com", 443);
    assert_eq!(decision, Decision::Block);
}

#[test]
fn untainted_process_connects_freely() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    // Process 400 never opened a secret
    let decision = engine.on_connect(400, "anywhere.com", 443);
    assert_eq!(decision, Decision::Allow);

    let decision = engine.on_connect(400, "evil.com", 80);
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn non_secret_file_does_not_taint() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    let decision = engine.on_file_open(500, Path::new("/home/user/code/main.rs"));
    assert_eq!(decision, Decision::Allow);
    assert!(!engine.is_tainted(500));
}

// ──────────────────────────────────────────────────────────────────
// Fork chain / multi-generation propagation
// ──────────────────────────────────────────────────────────────────

#[test]
fn three_generation_fork_chain() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.gnupg/secring.gpg");

    // Grandparent reads secret
    engine.on_file_open(600, Path::new("/home/user/.gnupg/secring.gpg"));

    // Grandparent → Parent
    engine.on_fork(600, 601);
    // Parent → Child
    engine.on_fork(601, 602);

    // All three are tainted
    assert!(engine.is_tainted(600));
    assert!(engine.is_tainted(601));
    assert!(engine.is_tainted(602));

    // Grandchild is blocked
    let decision = engine.on_connect(602, "exfil.site", 443);
    assert_eq!(decision, Decision::Block);
}

#[test]
fn untainted_fork_does_not_propagate() {
    let mut engine = engine();
    add_secret(&mut engine, "/etc/shadow");

    // Untainted parent forks
    engine.on_fork(700, 701);
    assert!(!engine.is_tainted(700));
    assert!(!engine.is_tainted(701));

    // Child connects freely
    let decision = engine.on_connect(701, "anywhere.com", 80);
    assert_eq!(decision, Decision::Allow);
}

// ──────────────────────────────────────────────────────────────────
// Multiple secrets
// ──────────────────────────────────────────────────────────────────

#[test]
fn multiple_secrets_all_tracked() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");
    add_secret(&mut engine, "/home/user/.aws/credentials");
    add_secret(&mut engine, "/home/user/.npmrc");

    engine.on_file_open(800, Path::new("/home/user/.ssh/id_rsa"));
    engine.on_file_open(800, Path::new("/home/user/.aws/credentials"));
    assert!(engine.is_tainted(800));

    // Non-secret process not tainted
    engine.on_file_open(801, Path::new("/tmp/random.txt"));
    assert!(!engine.is_tainted(801));
}

// ──────────────────────────────────────────────────────────────────
// Tier / licensing tests
// ──────────────────────────────────────────────────────────────────

#[test]
fn free_tier_limits_protected_secrets() {
    let engine = TaintEngine::new(); // free tier

    let (protected, _unprotected) = engine.protection_summary();
    // Free tier protects at most 15 secrets from the default list
    assert!(
        protected <= 15,
        "Free tier should limit to 15 protected secrets, got {protected}"
    );
}

#[test]
fn paid_tier_unlocks_more_secrets() {
    let mut engine = TaintEngine::new();
    engine.activate_license(Tier::Pro, "test-key".into(), 365);

    // The summary counts ranked findings, not bare exact paths, and the
    // default ranked list depends on the host's home directory. Register
    // the sixty findings explicitly so the test measures the tier, not the
    // environment.
    for i in 0..60 {
        engine.secrets_mut().add_content_finding(
            Path::new(&format!("/secret/{i}")),
            hedgehog_taint::secrets::SecretPriority::Critical,
            "integration fixture",
        );
    }
    let (protected, unprotected) = engine.protection_summary();
    assert!(
        protected > 15,
        "Pro tier should protect more than 15 secrets, got {protected}"
    );
    assert!(protected + unprotected >= 60);
}

// ──────────────────────────────────────────────────────────────────
// Stats tracking
// ──────────────────────────────────────────────────────────────────

#[test]
fn stats_increment_correctly() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    // Taint
    engine.on_file_open(900, Path::new("/home/user/.ssh/id_rsa"));
    let stats = engine.stats();
    assert!(stats.total_taints >= 1);

    // Block
    engine.on_connect(900, "evil.com", 443);
    let stats = engine.stats();
    assert!(stats.total_blocks >= 1);

    // Allow (known host)
    engine.on_connect(900, "github.com", 443);
    let stats = engine.stats();
    assert!(stats.total_allows >= 1);
}

// ──────────────────────────────────────────────────────────────────
// Allowlist
// ──────────────────────────────────────────────────────────────────

#[test]
fn custom_allowlist_permits_connection() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");
    engine.allowlist_mut().add_domain("mycompany.com");
    engine.allowlist_mut().add_suffix("mycompany.com"); // subdomains

    engine.on_file_open(1000, Path::new("/home/user/.ssh/id_rsa"));

    // Custom domain allowed (exact match)
    let decision = engine.on_connect(1000, "mycompany.com", 443);
    assert_eq!(decision, Decision::Allow);

    // Subdomain allowed (suffix match)
    let decision = engine.on_connect(1000, "api.mycompany.com", 443);
    assert_eq!(decision, Decision::Allow);

    // Unknown still blocked
    let decision = engine.on_connect(1000, "evil.com", 443);
    assert_eq!(decision, Decision::Block);
}

#[test]
fn localhost_always_allowed() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    engine.on_file_open(1100, Path::new("/home/user/.ssh/id_rsa"));
    assert!(engine.is_tainted(1100));

    let decision = engine.on_connect(1100, "127.0.0.1", 8080);
    assert_eq!(decision, Decision::Allow);

    let decision = engine.on_connect(1100, "localhost", 3000);
    assert_eq!(decision, Decision::Allow);
}

// ──────────────────────────────────────────────────────────────────
// Write taint propagation (derived secrets)
// ──────────────────────────────────────────────────────────────────

#[test]
fn write_from_tainted_creates_derived_secret() {
    let mut engine = TaintEngine::new();
    // Need Pro tier for derived tracking
    engine.activate_license(Tier::Pro, "test-key".into(), 365);
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    // Process reads secret
    engine.on_file_open(1200, Path::new("/home/user/.ssh/id_rsa"));
    assert!(engine.is_tainted(1200));

    // Tainted process writes to a new file → derived secret
    engine.on_file_write(1200, Path::new("/tmp/exfil.txt"));

    // Another process reads the derived file → should become tainted
    let decision = engine.on_file_open(1201, Path::new("/tmp/exfil.txt"));
    assert_eq!(decision, Decision::Taint);
    assert!(engine.is_tainted(1201));
}

// ──────────────────────────────────────────────────────────────────
// Concurrent simulation (sequential but simulating multiple procs)
// ──────────────────────────────────────────────────────────────────

#[test]
fn many_processes_isolated() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    // Only odd PIDs read the secret
    for pid in 1300..1320 {
        if pid % 2 == 1 {
            engine.on_file_open(pid, Path::new("/home/user/.ssh/id_rsa"));
        }
    }

    // Verify isolation
    for pid in 1300..1320 {
        if pid % 2 == 1 {
            assert!(engine.is_tainted(pid), "PID {pid} should be tainted");
            assert_eq!(engine.on_connect(pid, "evil.com", 443), Decision::Block);
        } else {
            assert!(!engine.is_tainted(pid), "PID {pid} should NOT be tainted");
            assert_eq!(engine.on_connect(pid, "evil.com", 443), Decision::Allow);
        }
    }
}

#[test]
fn rapid_fork_exec_exit_cycle() {
    let mut engine = engine();
    add_secret(&mut engine, "/home/user/.ssh/id_rsa");

    // Simulate a shell pipeline: parent reads secret, forks 5 children, each execs and exits
    engine.on_file_open(1400, Path::new("/home/user/.ssh/id_rsa"));
    for child in 1401..1406 {
        engine.on_fork(1400, child);
        engine.on_exec(child, Path::new("/usr/bin/cat"));
        assert!(engine.is_tainted(child));
        assert_eq!(engine.on_connect(child, "evil.com", 80), Decision::Block);
        engine.on_exit(child);
        assert!(!engine.is_tainted(child));
    }

    // Parent still tainted
    assert!(engine.is_tainted(1400));
}
