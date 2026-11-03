// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Latency: run many benign and blocked payloads through the real binary and
//! report p50 / p99 wall-clock per invocation (process spawn + decision).
//!
//! Gated behind `HEDGEHOG_LATENCY=1` so it never slows the default `cargo
//! test` run (it spawns ~1000 processes). Thresholds are environment-
//! overridable and asserted only when the gate is on:
//!
//!   HEDGEHOG_LATENCY=1          run this test (otherwise it is a no-op)
//!   HEDGEHOG_LAT_P50_MS=<ms>    p50 ceiling (default 30)
//!   HEDGEHOG_LAT_P99_MS=<ms>    p99 ceiling (default 150)
//!   HEDGEHOG_LAT_N=<n>          cases per class (default 500)
//!   HEDGEHOG_LAT_NOASSERT=1     measure and print only, do not assert
//!
//! The thresholds target a CI-class machine. If the test proves flaky on a
//! given runner, set HEDGEHOG_LAT_NOASSERT=1 (or raise the ceilings) rather
//! than relaxing them in source.

mod support;

use std::time::Instant;

use support::{benign_commands, blocked_bases, TestHome};

fn envn(key: &str, default: u128) -> u128 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn percentile(sorted_ms: &[u128], p: f64) -> u128 {
    if sorted_ms.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * (sorted_ms.len() as f64 - 1.0)).round() as usize;
    sorted_ms[rank.min(sorted_ms.len() - 1)]
}

fn measure(home: &TestHome, payloads: &[serde_json::Value]) -> Vec<u128> {
    let mut times = Vec::with_capacity(payloads.len());
    for p in payloads {
        let t = Instant::now();
        let _ = home.hook_json(p);
        times.push(t.elapsed().as_micros());
    }
    times
}

#[test]
fn hook_latency_p50_p99() {
    if std::env::var("HEDGEHOG_LATENCY").is_err() {
        eprintln!("hook_latency: skipped (set HEDGEHOG_LATENCY=1 to run)");
        return;
    }

    let n = envn("HEDGEHOG_LAT_N", 500) as usize;
    let home = TestHome::new("latency");

    // Build n benign and n blocked payloads by cycling the template sets.
    let benign = benign_commands();
    let blocked = blocked_bases();
    let mut benign_payloads = Vec::with_capacity(n);
    let mut blocked_payloads = Vec::with_capacity(n);
    for i in 0..n {
        let cmd = benign[i % benign.len()];
        benign_payloads.push(serde_json::json!({
            "tool_name": "Bash", "tool_input": {"command": cmd}
        }));
        let bcmd = &blocked[i % blocked.len()];
        blocked_payloads.push(serde_json::json!({
            "tool_name": "Bash", "tool_input": {"command": bcmd}
        }));
    }

    // Warm up the binary (first spawn pays page-cache / dyld costs).
    for p in benign_payloads.iter().take(10) {
        let _ = home.hook_json(p);
    }

    let mut benign_us = measure(&home, &benign_payloads);
    let mut blocked_us = measure(&home, &blocked_payloads);
    let mut all_us: Vec<u128> = benign_us.iter().chain(blocked_us.iter()).copied().collect();
    benign_us.sort_unstable();
    blocked_us.sort_unstable();
    all_us.sort_unstable();

    let report = |label: &str, v: &[u128]| {
        eprintln!(
            "{label:<8} n={:>4}  p50={:>6.2}ms  p90={:>6.2}ms  p99={:>6.2}ms  max={:>6.2}ms",
            v.len(),
            percentile(v, 50.0) as f64 / 1000.0,
            percentile(v, 90.0) as f64 / 1000.0,
            percentile(v, 99.0) as f64 / 1000.0,
            (*v.last().unwrap()) as f64 / 1000.0,
        );
    };
    eprintln!("\n=== hook latency (real binary, {n} cases/class) ===");
    report("benign", &benign_us);
    report("blocked", &blocked_us);
    report("all", &all_us);
    eprintln!();

    if std::env::var("HEDGEHOG_LAT_NOASSERT").is_ok() {
        eprintln!("hook_latency: assertions disabled (HEDGEHOG_LAT_NOASSERT)");
        return;
    }

    let p50_ceiling_us = envn("HEDGEHOG_LAT_P50_MS", 30) * 1000;
    let p99_ceiling_us = envn("HEDGEHOG_LAT_P99_MS", 150) * 1000;
    let p50 = percentile(&all_us, 50.0);
    let p99 = percentile(&all_us, 99.0);
    assert!(
        p50 <= p50_ceiling_us,
        "p50 {:.2}ms exceeds ceiling {}ms",
        p50 as f64 / 1000.0,
        p50_ceiling_us / 1000
    );
    assert!(
        p99 <= p99_ceiling_us,
        "p99 {:.2}ms exceeds ceiling {}ms",
        p99 as f64 / 1000.0,
        p99_ceiling_us / 1000
    );
}
