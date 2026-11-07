// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Secret-detection rules imported from Betterleaks (MIT, the Gitleaks
//! author's successor rule set), run by Gorse's own dependency-free matcher.
//!
//! `betterleaks_generated.rs` is produced by `scripts/betterleaks-import.ts`
//! from `third_party/betterleaks/betterleaks.toml`. Each line is scanned once
//! by a keyword automaton ([`keywords`]); only rules whose keyword occurs in
//! the lowercased line run their pattern ([`minire`]), as upstream does. A
//! match then passes the rule's entropy threshold, its token-ratio limit
//! ([`tokens`]: text that splits into few, long word pieces reads like
//! prose, not a key) and its allowlists (the parts of the upstream filter a
//! line scan can evaluate) before it becomes a [`ContentFinding`].
//!
//! Secret text never leaves this module except as the four-character
//! `redacted_preview` prefix.

pub mod keywords;
pub mod minire;
pub(crate) mod tokens;

// Generated data, laid out by the importer rather than rustfmt.
#[rustfmt::skip]
mod betterleaks_generated;

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::content_patterns::{
    shannon_entropy, Confidence, ContentFinding, ContentSecretType, LineContext,
};
use betterleaks_generated::{GLOBAL_ALLOWLISTS, RULES};
use keywords::KeywordMatcher;
use minire::Regex;

/// Which text an allowlist regex is tested against (the upstream filter's
/// `finding["secret"]`, `finding["match"]` or `finding["line"]`).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllowTarget {
    /// The extracted secret (the default).
    Secret,
    /// The whole regex match.
    Match,
    /// The whole line.
    Line,
}

/// The upstream rule's own confidence (`confidence = "high" | "medium" |
/// "low"`): how sure the rule is that a match is a credential of that service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rated {
    High,
    Medium,
    /// Upstream's three low-confidence rules are all excluded today, so
    /// nothing constructs this yet.
    #[allow(dead_code)]
    Low,
}

/// One upstream filter condition reduced to what a line scan can evaluate:
/// regexes on the secret, match or line, and stopwords contained in the
/// secret. A finding is allowed when any regex matches or any stopword occurs.
#[derive(Debug)]
pub(crate) struct GlAllowlist {
    pub target: AllowTarget,
    pub regexes: &'static [&'static str],
    pub stopwords: &'static [&'static str],
    /// SHA-256 (hex) of literal secrets to ignore: published example keys,
    /// kept as hashes so no key-shaped text sits in Gorse's source.
    pub hashes: &'static [&'static str],
}

/// One imported rule.
#[derive(Debug)]
pub(crate) struct GlRule {
    /// Upstream rule id (read by tests and debugging only).
    #[cfg_attr(not(test), allow(dead_code))]
    pub id: &'static str,
    /// Human name for `ContentSecretType::ApiKey { service }`.
    pub service: &'static str,
    pub description: &'static str,
    pub regex: &'static str,
    /// Lowercase keywords; the rule runs only when one occurs in the line.
    pub keywords: &'static [&'static str],
    /// Entropy floor of the secret, if any: a secret below it is discarded.
    pub entropy: Option<f64>,
    /// Upstream wrote `entropy <= N`: a secret exactly at the floor is
    /// discarded too.
    pub entropy_inclusive: bool,
    /// The pattern finds the key by the words around it (`service … = value`),
    /// not by a prefix of the key itself; such a rule is never Definitive.
    pub contextual: bool,
    /// Discard a secret whose bytes-per-token ratio under cl100k_base is
    /// this or more (upstream `tokenRatio(secret) >= N`), if any.
    pub token_ratio: Option<f64>,
    /// None: the first non-empty capture group, else the whole match
    /// (the upstream default). Some(0): the whole match. Some(n): group n.
    pub secret_group: Option<u8>,
    pub rated: Rated,
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
    /// Upstream's root-level filter plus Gorse's own, applied to every rule.
    global: Vec<CompiledAllow>,
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

/// A fixed key prefix of four or more characters (`ghp_`, a payment
/// provider's live-key prefix) names the service on its own, so a
/// high-confidence upstream rule for a key with one is Definitive; any other
/// high- or medium-confidence rule is High (a named service's key, found by
/// shape or by context). Low-confidence upstream rules depend on context
/// whatever they match.
fn rule_confidence(id: &str, literal_prefix: usize, contextual: bool, rated: Rated) -> Confidence {
    if let Some((_, c)) = CONFIDENCE_OVERRIDES.iter().find(|(r, _)| *r == id) {
        return *c;
    }
    match rated {
        Rated::High if literal_prefix >= 4 && !contextual => Confidence::Definitive,
        Rated::High | Rated::Medium => Confidence::High,
        Rated::Low => Confidence::ContextDependent,
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
                    confidence: rule_confidence(r.id, prefix, r.contextual, r.rated),
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
            global: GLOBAL_ALLOWLISTS.iter().map(compile_allow).collect(),
        }
    })
}

/// Number of imported rules.
pub fn imported_rule_count() -> usize {
    RULES.len()
}

/// Betterleaks release the rules were imported from.
pub fn imported_source_version() -> &'static str {
    betterleaks_generated::SOURCE_VERSION
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
const MAX_RULES: usize = 512;

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

/// Runs the imported rules on one line. A secret span two rules both match
/// is reported once, by the first rule.
pub fn check_line_imported(line: &str, line_number: usize) -> Vec<ContentFinding> {
    check_line_imported_spans(line, line_number)
        .into_iter()
        .map(|(f, _)| f)
        .collect()
}

/// `check_line_imported`, with each finding's secret as a byte span of the
/// line (so callers can tell the same key from a second one).
pub(crate) fn check_line_imported_spans(
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
    // Each reported span, with the finding's index and whether its rule's
    // keyword sits inside the secret. A map, so a line with thousands of
    // matches costs one lookup per match rather than a scan of all before.
    let mut by_span: HashMap<(usize, usize), (usize, bool)> = HashMap::new();
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
                    let entropy = shannon_entropy(secret);
                    if entropy < min || (rule.entropy_inclusive && entropy == min) {
                        continue;
                    }
                }
                if let Some(max) = rule.token_ratio {
                    if tokens::token_ratio(secret).is_some_and(|ratio| ratio >= max) {
                        continue;
                    }
                }
                let abs = (ws + ss, ws + se);
                if fragment_of_longer_run(line, abs) || snake_case_identifier(secret) {
                    continue;
                }
                let matched = &text[ms..me];
                if compiled_rule
                    .allowlists
                    .iter()
                    .chain(c.global.iter())
                    .any(|a| allowed(a, secret, matched, line))
                {
                    continue;
                }
                let finding = ContentFinding {
                    secret_type: ContentSecretType::ApiKey {
                        service: rule.service,
                    },
                    confidence: compiled_rule.confidence,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: redact(secret),
                    description: rule.description,
                };
                // Two rules on one span (a curl header rule and a service
                // rule on the same token): one finding, under the more
                // confident name (`Confidence` orders Definitive first) and,
                // at equal confidence, the rule that names the key by its own
                // shape (its keyword is inside the secret) over one that
                // names it by the context around it.
                let lower = secret.to_ascii_lowercase();
                let named_by_shape = rule.keywords.iter().any(|k| lower.contains(k));
                if let Some((pos, shape_named)) = by_span.get_mut(&abs) {
                    let existing = &mut findings[*pos].0;
                    let better = finding.confidence < existing.confidence
                        || (finding.confidence == existing.confidence
                            && named_by_shape
                            && !*shape_named);
                    if better {
                        *existing = finding;
                        *shape_named = named_by_shape;
                    }
                    continue;
                }
                by_span.insert(abs, (findings.len(), named_by_shape));
                findings.push((finding, abs));
            }
        }
    }
    findings
}

/// Whether the secret at `span` (byte offsets into `line`) sits inside a
/// longer run of base64-alphabet characters that continues past it on
/// both sides by 32 characters or more in total. Such a match is a slice
/// of an encoded image, hash or blob (`data:image/png;base64,…`), where a
/// `+` or `/` happens to make a word boundary before a rule's prefix, not
/// a key of its own. A key at the end of `KEY=`, inside quotes, or in a
/// URL query is bounded on at least one side and is kept.
fn fragment_of_longer_run(line: &str, (s, e): (usize, usize)) -> bool {
    let b = line.as_bytes();
    let run = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'_' | b'-');
    let mut a = s;
    while a > 0 && run(b[a - 1]) {
        a -= 1;
    }
    let mut z = e;
    while z < b.len() && run(b[z]) {
        z += 1;
    }
    a < s && z > e && (z - a) - (e - s) >= 32
}

/// Whether a secret is a `snake_case` identifier: three or more
/// underscore-separated words of letters only, none longer than twelve,
/// and no digit anywhere (`lip_sync_offset_frames`). A rule whose secret
/// alphabet admits `_` otherwise matches variable names; a real token has
/// digits, or a single run of letters far longer than any word.
fn snake_case_identifier(secret: &str) -> bool {
    if secret.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut words = 0;
    for part in secret.split('_') {
        if part.is_empty() || part.len() > 12 || !part.bytes().all(|b| b.is_ascii_alphabetic()) {
            return false;
        }
        words += 1;
    }
    words >= 3
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
        let found = check_line_imported(&line, 1);
        let took = start.elapsed();
        assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
        assert!(
            found.iter().any(|f| f.redacted_preview.starts_with("ghp_")),
            "deep key not found"
        );
    }
}
