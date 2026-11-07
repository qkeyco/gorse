// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Secret-detection rules imported from Gitleaks (MIT), run by Gorse's own
//! dependency-free matcher.
//!
//! `gitleaks_generated.rs` is produced by `scripts/gitleaks-import.ts` from
//! `third_party/gitleaks/gitleaks.toml`. Each line is scanned once by a
//! keyword automaton ([`keywords`]); only rules whose keyword occurs in the
//! lowercased line run their pattern ([`minire`]), as in Gitleaks. A match
//! then passes the rule's entropy threshold and allowlists (the rule's own
//! and Gitleaks' global one) before it becomes a [`ContentFinding`].
//!
//! Secret text never leaves this module except as the four-character
//! `redacted_preview` prefix.

pub mod keywords;
pub mod minire;

mod gitleaks_generated;

use std::sync::OnceLock;

use crate::content_patterns::{
    shannon_entropy, Confidence, ContentFinding, ContentSecretType, LineContext,
};
use gitleaks_generated::{GLOBAL_ALLOWLIST, RULES};
use keywords::KeywordMatcher;
use minire::Regex;

/// Which text an allowlist regex is tested against (Gitleaks `regexTarget`).
// The v8.30.1 import only has secret-targeted allowlists (the match and line
// ones belong to excluded rules); the other targets stay for future imports.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllowTarget {
    /// The extracted secret (Gitleaks' default).
    Secret,
    /// The whole regex match.
    Match,
    /// The whole line.
    Line,
}

/// One Gitleaks allowlist reduced to what a line scan can evaluate: regexes
/// on the secret, match or line, and stopwords contained in the secret. A
/// finding is allowed when any regex matches or any stopword occurs.
#[derive(Debug)]
pub(crate) struct GlAllowlist {
    pub target: AllowTarget,
    pub regexes: &'static [&'static str],
    pub stopwords: &'static [&'static str],
    /// SHA-256 (hex) of literal secrets to ignore: published example keys,
    /// kept as hashes so no key-shaped text sits in Gorse's source.
    pub hashes: &'static [&'static str],
}

/// One imported Gitleaks rule.
#[derive(Debug)]
pub(crate) struct GlRule {
    /// Gitleaks rule id (read by tests and debugging only).
    #[cfg_attr(not(test), allow(dead_code))]
    pub id: &'static str,
    /// Human name for `ContentSecretType::ApiKey { service }`.
    pub service: &'static str,
    pub description: &'static str,
    pub regex: &'static str,
    /// Lowercase keywords; the rule runs only when one occurs in the line.
    pub keywords: &'static [&'static str],
    /// Minimum Shannon entropy of the secret (exclusive), if any.
    pub entropy: Option<f64>,
    /// None: the first non-empty capture group, else the whole match
    /// (Gitleaks' default). Some(0): the whole match. Some(n): group n.
    pub secret_group: Option<u8>,
    pub allowlists: &'static [GlAllowlist],
}

struct CompiledAllow {
    target: AllowTarget,
    regexes: Vec<Regex>,
    stopwords: &'static [&'static str],
    hashes: &'static [&'static str],
}

struct CompiledRule {
    regex: Option<Regex>,
    confidence: Confidence,
    allowlists: Vec<CompiledAllow>,
}

struct Compiled {
    rules: Vec<CompiledRule>,
    keywords: KeywordMatcher,
    global: CompiledAllow,
}

fn compile_allow(a: &GlAllowlist) -> CompiledAllow {
    CompiledAllow {
        target: a.target,
        // A regex that does not compile is dropped; the build-time test
        // `every_generated_regex_compiles` guarantees there are none.
        regexes: a
            .regexes
            .iter()
            .filter_map(|r| Regex::new(r).ok())
            .collect(),
        stopwords: a.stopwords,
        hashes: a.hashes,
    }
}

/// Confidence set by hand where the literal-prefix heuristic misjudges a
/// rule. `curl-auth-user`, `curl-auth-header` and `nuget-config-password`
/// start with a literal (`curl`, `<add key=`) that names the context, not
/// the secret: the value can be anything, so High. `aws-access-token` has
/// no literal prefix only because it lists several (AKIA, ASIA, ...), each
/// with a fixed-length base-32 body: Definitive.
const CONFIDENCE_OVERRIDES: &[(&str, Confidence)] = &[
    ("curl-auth-user", Confidence::High),
    ("curl-auth-header", Confidence::High),
    ("nuget-config-password", Confidence::High),
    ("aws-access-token", Confidence::Definitive),
];

fn rule_confidence(id: &str, literal_prefix: usize) -> Confidence {
    if let Some((_, c)) = CONFIDENCE_OVERRIDES.iter().find(|(r, _)| *r == id) {
        return *c;
    }
    if literal_prefix >= 4 {
        Confidence::Definitive
    } else {
        Confidence::High
    }
}

fn compiled() -> &'static Compiled {
    static COMPILED: OnceLock<Compiled> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let rules = RULES
            .iter()
            .map(|r| {
                let regex = Regex::new(r.regex).ok();
                let prefix = regex.as_ref().map_or(0, |re| re.literal_prefix_len());
                CompiledRule {
                    regex,
                    confidence: rule_confidence(r.id, prefix),
                    allowlists: r.allowlists.iter().map(compile_allow).collect(),
                }
            })
            .collect();
        let keywords = KeywordMatcher::new(
            RULES
                .iter()
                .enumerate()
                .flat_map(|(i, r)| r.keywords.iter().map(move |k| (*k, i as u32))),
        );
        Compiled {
            rules,
            keywords,
            global: compile_allow(&GLOBAL_ALLOWLIST),
        }
    })
}

/// Number of imported Gitleaks rules.
pub fn gitleaks_rule_count() -> usize {
    RULES.len()
}

/// Gitleaks release the rules were imported from.
pub fn gitleaks_source_version() -> &'static str {
    gitleaks_generated::SOURCE_VERSION
}

fn allowed(a: &CompiledAllow, secret: &str, matched: &str, line: &str) -> bool {
    let target = match a.target {
        AllowTarget::Secret => secret,
        AllowTarget::Match => matched,
        AllowTarget::Line => line,
    };
    if a.regexes.iter().any(|re| re.is_match(target)) {
        return true;
    }
    if !a.hashes.is_empty() {
        let digest = crate::authority::psbt::sha256(target.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if a.hashes.contains(&hex.as_str()) {
            return true;
        }
    }
    if a.stopwords.is_empty() {
        return false;
    }
    let lower = secret.to_ascii_lowercase();
    a.stopwords
        .iter()
        .any(|w| lower.contains(&w.to_ascii_lowercase()))
}

fn redact(secret: &str) -> String {
    let mut preview: String = secret.chars().take(4).collect();
    preview.push_str("****");
    preview
}

/// Room for every generated rule; a test checks the table fits.
#[cfg(test)]
const MAX_RULES: usize = 256;

/// How far before the end of a keyword, and after it, a rule looks. The
/// keyword-style rules allow 50 name characters before the keyword and an
/// assignment plus a value of up to 150 after; prefix rules start at the
/// keyword. Generous margins on both.
const WINDOW_BEFORE: usize = 160;
const WINDOW_AFTER: usize = 640;
/// Rules whose only keywords are command names (`curl`) put the secret
/// anywhere later on the command line ("Copy as cURL" lines run to many
/// kilobytes of headers): their windows reach the end of the line, up to
/// this many bytes after the keyword.
const WINDOW_AFTER_COMMAND: usize = 16 * 1024;
const COMMAND_KEYWORDS: &[&str] = &["curl", "wget"];
/// Windows per rule per line: a line repeating one keyword thousands of
/// times is data, not a store of keys. 80 tokens 1.5 KB apart (one-line
/// JSON exports) all fit.
const MAX_WINDOWS: usize = 2048;
/// Overlapping windows merge only up to this length; past it the next
/// keyword starts a new window (each window still holds its keyword's full
/// margins, so no match is cut). Unbounded merging made one window of a
/// whole long line, and every search in it cost the whole line again.
const MAX_MERGED_WINDOW: usize = 4096;
/// Steps the matcher may spend on one line, over all rules and windows: a
/// base plus a per-byte allowance. Ordinary lines use a tiny fraction.
const LINE_BUDGET_BASE: usize = 2_000_000;
const LINE_BUDGET_PER_BYTE: usize = 64;
/// How far a window edge moves outward to finish a token it cut, so `\b`
/// and `$` never fire on half a key.
const WINDOW_TOKEN_SLACK: usize = 256;

/// Characters that can continue a key or token across a window edge.
fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/' | b'=' | b'.')
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Runs the imported Gitleaks rules on one line. A secret span two rules
/// both match is reported once, by the first rule.
pub fn check_line_gitleaks(line: &str, line_number: usize) -> Vec<ContentFinding> {
    check_line_gitleaks_spans(line, line_number)
        .into_iter()
        .map(|(f, _)| f)
        .collect()
}

/// `check_line_gitleaks`, with each finding's secret as a byte span of the
/// line (so callers can tell the same key from a second one).
pub(crate) fn check_line_gitleaks_spans(
    line: &str,
    line_number: usize,
) -> Vec<(ContentFinding, (usize, usize))> {
    let mut findings = Vec::new();
    if line.len() < 4 {
        return findings;
    }
    let c = compiled();
    // Where each rule's keywords occur. Most lines hold none, and then this
    // single pass over the line is the whole cost.
    let mut hits: Vec<(u32, usize)> = Vec::new();
    c.keywords.scan_positions(line.as_bytes(), |id, end| {
        if (id as usize) < RULES.len() {
            hits.push((id, end));
        }
    });
    if hits.is_empty() {
        return findings;
    }
    hits.sort_unstable();
    let bytes = line.as_bytes();
    let mut reported: Vec<(usize, usize)> = Vec::new();
    // One step budget for the whole line, shared by every rule and window.
    let mut budget =
        LINE_BUDGET_BASE.saturating_add(LINE_BUDGET_PER_BYTE.saturating_mul(line.len()));

    let mut i = 0;
    while i < hits.len() {
        let idx = hits[i].0 as usize;
        let rule = &RULES[idx];
        let after = if rule.keywords.iter().all(|k| COMMAND_KEYWORDS.contains(k)) {
            WINDOW_AFTER_COMMAND
        } else {
            WINDOW_AFTER
        };
        // Every rule's match sits near one of its keywords (a key's prefix
        // is its keyword; a service name comes just before the value), so
        // each rule searches only short windows around them. However long
        // the line (minified code, one-line JSON), the work stays small.
        let mut windows: Vec<(usize, usize)> = Vec::new();
        while i < hits.len() && hits[i].0 as usize == idx {
            let end = hits[i].1;
            i += 1;
            let mut ws = floor_boundary(line, end.saturating_sub(WINDOW_BEFORE));
            let mut we = ceil_boundary(line, end.saturating_add(after).min(line.len()));
            // Move each edge out past the end of a token it cut, and one
            // character further, so the window holds the token's delimiter
            // and `\b`, `$` and `\z` see what the full line has there.
            // Token bytes are ASCII; the extra character is stepped over
            // by character boundary.
            let floor = ws.saturating_sub(WINDOW_TOKEN_SLACK);
            while ws > floor && token_byte(bytes[ws - 1]) {
                ws -= 1;
            }
            if ws > 0 {
                ws = floor_boundary(line, ws - 1);
            }
            let ceil = (we + WINDOW_TOKEN_SLACK).min(line.len());
            while we < ceil && token_byte(bytes[we]) {
                we += 1;
            }
            if we < line.len() {
                we = ceil_boundary(line, we + 1);
            }
            match windows.last_mut() {
                // Inside the previous window already: nothing new to search.
                Some(last) if ws >= last.0 && we <= last.1 => {}
                Some(last)
                    if ws <= last.1 && we.max(last.1) - last.0.min(ws) <= MAX_MERGED_WINDOW =>
                {
                    last.0 = last.0.min(ws);
                    last.1 = last.1.max(we);
                }
                _ => {
                    if windows.len() < MAX_WINDOWS {
                        windows.push((ws, we));
                    }
                }
            }
        }
        let compiled_rule = &c.rules[idx];
        let Some(re) = &compiled_rule.regex else {
            continue;
        };
        for (ws, we) in windows {
            if budget == 0 {
                break;
            }
            let text = &line[ws..we];
            for caps in re.captures_all(text, &mut budget) {
                let Some((ms, me)) = caps[0] else {
                    continue;
                };
                let span = match rule.secret_group {
                    Some(0) => Some((ms, me)),
                    Some(g) => caps.get(g as usize).copied().flatten(),
                    None => caps[1..]
                        .iter()
                        .flatten()
                        .find(|(a, b)| b > a)
                        .copied()
                        .or(Some((ms, me))),
                };
                let Some((ss, se)) = span else {
                    continue;
                };
                let secret = &text[ss..se];
                if secret.is_empty() {
                    continue;
                }
                if let Some(min) = rule.entropy {
                    if shannon_entropy(secret) <= min {
                        continue;
                    }
                }
                let abs = (ws + ss, ws + se);
                if reported.contains(&abs) {
                    continue;
                }
                let matched = &text[ms..me];
                if compiled_rule
                    .allowlists
                    .iter()
                    .chain(std::iter::once(&c.global))
                    .any(|a| allowed(a, secret, matched, line))
                {
                    continue;
                }
                reported.push(abs);
                findings.push((
                    ContentFinding {
                        secret_type: ContentSecretType::ApiKey {
                            service: rule.service,
                        },
                        confidence: compiled_rule.confidence,
                        context: LineContext::Code,
                        line_number,
                        redacted_preview: redact(secret),
                        description: rule.description,
                    },
                    abs,
                ));
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod capacity_tests {
    #[test]
    fn every_rule_fits_the_candidate_array() {
        assert!(super::RULES.len() <= super::MAX_RULES);
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    /// Development aid: GORSE_PROFILE_DIR=<folder> cargo test --release
    /// rules::profile_tests -- --ignored --nocapture. Prints, per rule, the
    /// time spent and the lines it ran on; never any line text.
    #[test]
    #[ignore]
    fn profile_rules_on_a_folder() {
        let Some(dir) = std::env::var_os("GORSE_PROFILE_DIR") else {
            return;
        };
        let mut lines: Vec<String> = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(dir)];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if p.is_dir() {
                    if !name.starts_with('.') && name != "node_modules" && name != "target" {
                        stack.push(p);
                    }
                } else if lines.len() < 400_000 {
                    if let Ok(t) = std::fs::read_to_string(&p) {
                        lines.extend(t.lines().map(str::to_string));
                    }
                }
            }
        }
        let c = compiled();
        let mut per: Vec<(std::time::Duration, usize)> = vec![Default::default(); RULES.len()];
        let t0 = std::time::Instant::now();
        for line in &lines {
            let mut cand = [false; MAX_RULES];
            c.keywords
                .scan(line.as_bytes(), |id| cand[id as usize] = true);
            for (i, _) in RULES.iter().enumerate().filter(|(i, _)| cand[*i]) {
                if let Some(re) = &c.rules[i].regex {
                    let s = std::time::Instant::now();
                    let _ = re.captures_at(line, 0);
                    per[i].0 += s.elapsed();
                    per[i].1 += 1;
                }
            }
        }
        println!("{} lines, total {:?}", lines.len(), t0.elapsed());
        let mut order: Vec<usize> = (0..RULES.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(per[i].0));
        for &i in order.iter().take(15) {
            println!("{:>10?} {:>8} lines  {}", per[i].0, per[i].1, RULES[i].id);
        }
    }
}

#[cfg(test)]
mod hash_allow_tests {
    use super::*;

    #[test]
    fn a_hashed_literal_is_allowed_and_nothing_else() {
        let key: String = "AIza".to_string()
            + &"Q7xR2mK9pL4vN8cT3wZ6yB1hD5fJ0gS2uE7aX"
                .chars()
                .take(35)
                .collect::<String>();
        let hex: String = crate::authority::psbt::sha256(key.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let leaked: &'static str = Box::leak(hex.into_boxed_str());
        let hashes: &'static [&'static str] = Box::leak(vec![leaked].into_boxed_slice());
        let allow = compile_allow(&GlAllowlist {
            target: AllowTarget::Secret,
            regexes: &[],
            stopwords: &[],
            hashes,
        });
        assert!(allowed(&allow, &key, &key, &key));
        let other = key.replacen('Q', "R", 1);
        assert!(!allowed(&allow, &other, &other, &other));
    }
}

#[cfg(test)]
mod long_line_tests {
    use super::*;

    #[test]
    fn a_long_line_full_of_keywords_is_fast_and_a_key_deep_inside_is_found() {
        // Minified-code shape: a keyword every few characters for 400 KB.
        let filler = "var a={key:b.token,auth:c,api:d,secret:e};".repeat(10_000);
        // A synthetic GitHub-shaped token placed far into the line.
        let token: String = "ghp_".to_string()
            + &"Zq3Xr7Lm2Np8Vt4Wy6Bc1Dk5Fh9Gj0Hs2Ju7Ka"
                .chars()
                .take(36)
                .collect::<String>();
        let line = format!("{filler} const T=\"{token}\"; {filler}");
        let start = std::time::Instant::now();
        let found = check_line_gitleaks(&line, 1);
        let took = start.elapsed();
        assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
        assert!(
            found.iter().any(|f| f.redacted_preview.starts_with("ghp_")),
            "deep key not found"
        );
    }
}
