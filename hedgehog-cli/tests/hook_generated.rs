// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Generated corpus: tens of thousands of PreToolUse payloads built from
//! templates (credential paths × spellings × readers/transports,
//! metamorphic transforms over already-blocked commands, and benign
//! developer commands), checked fast in-process through the public pack
//! engine + a faithful heuristics copy, with a deterministic sampled subset
//! cross-checked against the real binary.
//!
//! This is a *new* test layer. It does not modify product behaviour.
//!
//! Assertions:
//!   * CONSISTENCY (always hard): on the sampled subset, the real binary's
//!     verdict must equal the in-process reference model's verdict. This is
//!     test-infrastructure correctness — it guards the heuristics copy in
//!     `support` against drift from the product.
//!   * BENIGN / COVERAGE / METAMORPHIC (reported): security-correct `expect`
//!     vs the current engine's actual verdict, printed per category and per
//!     dimension. Gaps in categories other agents are still implementing are
//!     expected. Set HEDGEHOG_GEN_STRICT=1 to turn benign false positives and
//!     coverage gaps into hard failures.
//!
//! Benign false positives are always printed in full (never papered over);
//! the strict gate only controls whether they fail the build.
//!
//! Env knobs:
//!   HEDGEHOG_GEN_SEED=<u64>     sampling seed (default 0x51ED)
//!   HEDGEHOG_GEN_SAMPLE=<n>     binary sample size (default 300)
//!   HEDGEHOG_GEN_FULL=1         run the entire corpus through the binary
//!   HEDGEHOG_GEN_STRICT=1       benign FPs become hard failures

mod support;

use std::collections::BTreeMap;

use support::{build_corpus, Case, Verdict, XorShift64};

fn seed() -> u64 {
    std::env::var("HEDGEHOG_GEN_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x51ED)
}

fn sample_size(total: usize) -> usize {
    if std::env::var("HEDGEHOG_GEN_FULL").is_ok() {
        return total;
    }
    std::env::var("HEDGEHOG_GEN_SAMPLE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
        .min(total)
}

fn model_verdict(engine: &hedgehog_packs::PackEngine, case: &Case) -> Verdict {
    if support::engine_blocks(engine, &case.tool, &case.fields) {
        Verdict::Block
    } else {
        Verdict::Allow
    }
}

fn case_cmd(case: &Case) -> String {
    case.fields
        .command
        .clone()
        .or_else(|| case.fields.file_path.clone())
        .or_else(|| case.fields.url.clone())
        .unwrap_or_default()
}

#[test]
fn generated_corpus_in_process_and_binary_agree() {
    let engine = hedgehog_packs::PackEngine::builtin().expect("builtin packs load");
    let corpus = build_corpus();
    let total = corpus.len();
    assert!(total > 10_000, "corpus should be large; got {total}");

    // ── In-process pass over the whole corpus ───────────────────────────
    // category -> [cases, expect_met, blocked, allowed]
    let mut cov: BTreeMap<&str, [usize; 4]> = BTreeMap::new();
    // (category, dim) -> gap count (expect != actual)
    let mut gap_by_dim: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut benign_fp: Vec<String> = Vec::new();
    let mut model: Vec<Verdict> = Vec::with_capacity(total);

    for case in &corpus {
        let v = model_verdict(&engine, case);
        model.push(v);
        let e = cov.entry(leak(&case.category)).or_default();
        e[0] += 1;
        if v == case.expect {
            e[1] += 1;
        } else {
            *gap_by_dim
                .entry((case.category.clone(), case.dim.clone()))
                .or_default() += 1;
        }
        match v {
            Verdict::Block => e[2] += 1,
            _ => e[3] += 1,
        }
        if case.category == "benign" && v == Verdict::Block {
            benign_fp.push(format!("{} [{}]: {}", case.id, case.dim, case_cmd(case)));
        }
    }

    // ── Coverage report ─────────────────────────────────────────────────
    eprintln!("\n=== generated corpus: {total} cases ===");
    eprintln!(
        "{:<16} {:>7} {:>10} {:>8} {:>8} {:>8}",
        "category", "cases", "expect_met", "blocked", "allowed", "gap"
    );
    for (cat, [cases, met, blocked, allowed]) in &cov {
        eprintln!(
            "{:<16} {:>7} {:>10} {:>8} {:>8} {:>8}",
            cat,
            cases,
            met,
            blocked,
            allowed,
            cases - met
        );
    }
    if !gap_by_dim.is_empty() {
        eprintln!("\n--- coverage gaps by dimension (expect != actual) ---");
        for ((cat, dim), n) in &gap_by_dim {
            eprintln!("  {:<16} {:<28} {}", cat, dim, n);
        }
    }

    // ── Benign false positives: always reported in full ─────────────────
    if !benign_fp.is_empty() {
        eprintln!(
            "\n--- BENIGN FALSE POSITIVES ({}) — ordinary commands blocked ---",
            benign_fp.len()
        );
        for line in &benign_fp {
            eprintln!("  {line}");
        }
        eprintln!("(these are a product finding: the high_entropy_inline heuristic scores");
        eprintln!(" 3/3 on many `bash -c \"...\"` wrappings. See docs/HOOK_GENERATED_TESTS.md)");
    }

    // ── Sampled binary cross-check (consistency) — ALWAYS HARD ──────────
    let n = sample_size(total);
    let mut rng = XorShift64::new(seed());
    let idxs = rng.sample_indices(total, n);
    let home = support::TestHome::new("gen");
    let mut mismatches: Vec<String> = Vec::new();
    for &i in &idxs {
        let case = &corpus[i];
        let bin = home.verdict(&case.payload());
        if bin != model[i] && mismatches.len() < 40 {
            mismatches.push(format!(
                "{} [{}/{}] model={:?} binary={:?} :: {}",
                case.id,
                case.category,
                case.dim,
                model[i],
                bin,
                case_cmd(case)
            ));
        }
    }
    eprintln!(
        "\nbinary cross-check: {} cases, {} mismatch(es)\n",
        idxs.len(),
        mismatches.len()
    );
    assert!(
        mismatches.is_empty(),
        "in-process model and binary disagree (heuristics copy drift or engine inconsistency):\n{}",
        mismatches.join("\n")
    );

    // ── Strict gate: benign FPs fail the build only when asked ──────────
    if std::env::var("HEDGEHOG_GEN_STRICT").is_ok() {
        assert!(
            benign_fp.is_empty(),
            "HEDGEHOG_GEN_STRICT: {} benign false positive(s)",
            benign_fp.len()
        );
    }
}

/// Separate, cheap view of the metamorphic invariant, reported on its own.
#[test]
fn metamorphic_invariance_report() {
    let engine = hedgehog_packs::PackEngine::builtin().expect("builtin packs load");
    let corpus = build_corpus();
    let mut per_transform: BTreeMap<String, [usize; 2]> = BTreeMap::new();
    let mut evasions: Vec<String> = Vec::new();
    for case in &corpus {
        if case.category != "metamorphic" {
            continue;
        }
        let blocks = support::engine_blocks(&engine, &case.tool, &case.fields);
        let e = per_transform.entry(case.dim.clone()).or_default();
        e[0] += 1;
        if blocks {
            e[1] += 1;
        } else if evasions.len() < 60 {
            evasions.push(format!(
                "{}: {}",
                case.dim,
                case_cmd(case).replace('\n', "\\n")
            ));
        }
    }
    eprintln!("\n=== metamorphic invariance (blocked-base stays blocked) ===");
    eprintln!(
        "{:<20} {:>7} {:>14} {:>8}",
        "transform", "total", "stayed_blocked", "evaded"
    );
    for (tf, [total, kept]) in &per_transform {
        eprintln!("{:<20} {:>7} {:>14} {:>8}", tf, total, kept, total - kept);
    }
    if !evasions.is_empty() {
        eprintln!("\nevading transforms (current engine lets these through):");
        for e in &evasions {
            eprintln!("  {e}");
        }
    }
    eprintln!();
}

/// Intern a category string into a `'static` key for the report map.
fn leak(s: &str) -> &'static str {
    use std::sync::Mutex;
    static POOL: Mutex<Option<Vec<&'static str>>> = Mutex::new(None);
    let mut g = POOL.lock().unwrap();
    let pool = g.get_or_insert_with(Vec::new);
    if let Some(found) = pool.iter().find(|x| **x == s) {
        return found;
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    pool.push(leaked);
    leaked
}
