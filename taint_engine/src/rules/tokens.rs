// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Byte-pair token counting with OpenAI's cl100k_base vocabulary.
//!
//! Betterleaks filters many of its rules with `tokenRatio(secret) >= 2.5`:
//! the secret's byte length divided by the number of word pieces it splits
//! into. Text a tokenizer trained on prose and code compresses well (`your
//! api key here`, `ChangeMe`) scores high and is not a key; random key
//! material scores near one byte per piece. Gorse evaluates the same
//! condition with the same vocabulary so the imported rules keep their
//! upstream tuning.
//!
//! The vocabulary (100,256 byte strings in rank order, packed by
//! `scripts/cl100k-pack.ts`) is embedded from `third_party/tiktoken/`; the
//! splitting and merging below are written from the published tiktoken
//! pre-tokenizer pattern and the byte-pair merge rule, not copied from any
//! implementation. The pattern, for reference:
//!
//! ```text
//! (?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}|
//!  ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+
//! ```
//!
//! Unicode classes come from the standard library: `\p{N}` is exactly
//! `char::is_numeric`; `\p{L}` is approximated by `char::is_alphabetic` less
//! the numeric letters, which differs from the true class only for a few
//! combining marks. Every byte of ASCII, which is what key regexes match,
//! splits identically.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Length-prefixed token byte strings, rank 0 first.
static PACKED: &[u8] = include_bytes!("../../../third_party/tiktoken/cl100k_base.bin");

/// Mergeable ranks in cl100k_base (special tokens are not included; their
/// spelling is counted as ordinary text, as upstream does).
pub(crate) const RANKS: usize = 100_256;

/// A secret longer than this is measured on its first bytes only, so a
/// pathological match cannot make the quadratic merge loop expensive.
const MAX_BYTES: usize = 4096;

struct Vocab {
    ranks: HashMap<&'static [u8], u32>,
}

fn vocab() -> &'static Vocab {
    static VOCAB: OnceLock<Vocab> = OnceLock::new();
    VOCAB.get_or_init(|| {
        let mut ranks = HashMap::with_capacity(RANKS);
        let mut i = 0;
        let mut rank = 0u32;
        while i < PACKED.len() {
            let n = PACKED[i] as usize;
            let Some(token) = PACKED.get(i + 1..i + 1 + n) else {
                break;
            };
            if n == 0 {
                break;
            }
            ranks.insert(token, rank);
            rank += 1;
            i += 1 + n;
        }
        Vocab { ranks }
    })
}

/// Bytes per token of `text`, as Betterleaks's `tokenRatio` computes it.
/// `None` for empty text or an unusable vocabulary, in which case the caller
/// keeps the finding (the filter cannot be evaluated).
pub(crate) fn token_ratio(text: &str) -> Option<f64> {
    let v = vocab();
    if v.ranks.len() != RANKS {
        return None;
    }
    // Upstream strips line breaks from short multi-line secrets before
    // measuring; a line scan never produces one, but the rule is kept so
    // the two agree on any input.
    let stripped;
    let mut text = text;
    if text.chars().count() < 20 && text.contains(['\r', '\n']) {
        stripped = text.replace(['\r', '\n'], "");
        text = &stripped;
    }
    if text.len() > MAX_BYTES {
        let mut end = MAX_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text = &text[..end];
    }
    if text.is_empty() {
        return None;
    }
    let count = count_tokens(text, v);
    if count == 0 {
        return None;
    }
    Some(text.len() as f64 / count as f64)
}

/// Number of cl100k_base tokens in `text` (tests and the differential
/// check against tiktoken).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn count(text: &str) -> usize {
    count_tokens(text, vocab())
}

fn count_tokens(text: &str, v: &Vocab) -> usize {
    let mut rest = text;
    let mut total = 0;
    while !rest.is_empty() {
        let n = next_piece(rest);
        total += bpe_count(rest[..n].as_bytes(), &v.ranks);
        rest = &rest[n..];
    }
    total
}

/// Number of tokens one pre-tokenized piece merges into: the whole piece
/// when it is itself a token, else start from single bytes and repeatedly
/// merge the adjacent pair with the lowest rank until none is mergeable.
fn bpe_count(piece: &[u8], ranks: &HashMap<&'static [u8], u32>) -> usize {
    if piece.len() <= 1 || ranks.contains_key(piece) {
        return piece.len().min(1);
    }
    // Part boundaries: parts[i]..parts[i + 1] is one part.
    let mut parts: Vec<usize> = (0..=piece.len()).collect();
    loop {
        let mut best: Option<(u32, usize)> = None;
        for i in 0..parts.len() - 2 {
            if let Some(&r) = ranks.get(&piece[parts[i]..parts[i + 2]]) {
                if best.is_none_or(|(b, _)| r < b) {
                    best = Some((r, i));
                }
            }
        }
        match best {
            Some((_, i)) => {
                parts.remove(i + 1);
            }
            None => return parts.len() - 1,
        }
    }
}

fn is_letter(c: char) -> bool {
    c.is_alphabetic() && !c.is_numeric()
}

fn is_number(c: char) -> bool {
    c.is_numeric()
}

fn is_newline(c: char) -> bool {
    c == '\r' || c == '\n'
}

/// Simple case fold for the contraction letters (`(?i:'s|…)`), including
/// the two non-ASCII letters that fold onto ASCII ones.
fn folded(c: char) -> char {
    match c {
        '\u{17F}' => 's',
        '\u{212A}' => 'k',
        _ => c.to_lowercase().next().unwrap_or(c),
    }
}

/// Byte length of the pre-tokenizer piece at the start of `s` (non-empty):
/// the first alternative of the pattern that matches, as a regex engine
/// would pick it, including the backtracking each alternative allows.
fn next_piece(s: &str) -> usize {
    let mut chars = s.char_indices();
    let (_, c0) = chars.next().expect("non-empty");
    let w0 = c0.len_utf8();

    // (?i:'s|'t|'re|'ve|'m|'ll|'d)
    if c0 == '\'' {
        let mut tail = s[1..].chars();
        if let Some(a) = tail.next() {
            let fa = folded(a);
            if matches!(fa, 's' | 't' | 'm' | 'd') {
                return 1 + a.len_utf8();
            }
            if let Some(b) = tail.next() {
                let fb = folded(b);
                if matches!((fa, fb), ('r', 'e') | ('v', 'e') | ('l', 'l')) {
                    return 1 + a.len_utf8() + b.len_utf8();
                }
            }
        }
    }

    // [^\r\n\p{L}\p{N}]?\p{L}+
    if is_letter(c0) {
        return w0 + letters_len(&s[w0..]);
    }
    if !is_newline(c0) && !is_number(c0) {
        let after = &s[w0..];
        if after.chars().next().is_some_and(is_letter) {
            return w0 + letters_len(after);
        }
        // Without the optional prefix the piece would have to start with a
        // letter, and c0 is not one: the alternative fails.
    }

    // \p{N}{1,3}
    if is_number(c0) {
        return s
            .chars()
            .take(3)
            .take_while(|c| is_number(*c))
            .map(char::len_utf8)
            .sum();
    }

    //  ?[^\s\p{L}\p{N}]+[\r\n]*
    {
        let (skip, first) = if c0 == ' ' {
            (1, s[1..].chars().next())
        } else {
            (0, Some(c0))
        };
        let symbol = |c: char| !c.is_whitespace() && !is_letter(c) && !is_number(c);
        if first.is_some_and(symbol) {
            let mut end = skip;
            for c in s[skip..].chars() {
                if !symbol(c) {
                    break;
                }
                end += c.len_utf8();
            }
            for c in s[end..].chars() {
                if !is_newline(c) {
                    break;
                }
                end += c.len_utf8();
            }
            return end;
        }
        // With the space consumed and no symbol after it, the regex retries
        // without the space; a space is not a symbol either, so it fails.
    }

    if c0.is_whitespace() {
        // The whitespace run from the start, and where its last newline is.
        let mut run_end = 0;
        let mut last_char_start = 0;
        let mut last_newline_end = None;
        for (i, c) in s.char_indices() {
            if !c.is_whitespace() {
                break;
            }
            last_char_start = i;
            run_end = i + c.len_utf8();
            if is_newline(c) {
                last_newline_end = Some(run_end);
            }
        }
        // \s*[\r\n]+ : greedy \s* backs off until [\r\n]+ can take the tail.
        if let Some(end) = last_newline_end {
            return end;
        }
        // \s+(?!\S) : the whole run at end of text, else all but its last
        // character (so the final space stays attached to the next word).
        if run_end == s.len() {
            return run_end;
        }
        if last_char_start > 0 {
            return last_char_start;
        }
        // \s+ : a single whitespace character before a non-space.
        return run_end;
    }

    // Unreachable in practice: every character class above is covered.
    w0
}

fn letters_len(s: &str) -> usize {
    s.chars()
        .take_while(|c| is_letter(*c))
        .map(char::len_utf8)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_loads_completely() {
        assert_eq!(vocab().ranks.len(), RANKS);
        // Every single byte is a token, so no piece can fail to merge.
        for b in 0..=255u8 {
            assert!(vocab().ranks.contains_key(&[b][..]), "byte {b:#x} missing");
        }
    }

    /// Reference counts produced by tiktoken 0.12 (`cl100k_base`,
    /// `encode(text, disallowed_special=())`).
    const REFERENCE: &[(&str, usize)] = &[
        ("hello world", 2),
        ("Hello, World!", 4),
        ("sk_test_4eC39HqLyjWDarjtT1zdp7dc", 20),
        ("AKIAIOSFODNN7EXAMPLE", 8),
        ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", 25),
        ("the quick brown fox jumps over the lazy dog", 9),
        ("ThisIsAPasswordPlaceholder", 5),
        ("xoxb-1234567890-abcdefghij", 11),
        ("I'm sure they're we've it's don't I'll I'd", 15),
        ("   leading spaces", 3),
        ("trailing spaces   ", 4),
        ("a  b", 3),
        ("line1\nline2\r\n\n", 6),
        ("1234567890", 4),
        ("x1234", 3),
        ("café naïve", 4),
        ("日本語のテキスト", 8),
        ("emoji 😀 test", 3),
        ("a1b2c3d4e5f6", 12),
        ("---------", 1),
        ("========================", 2),
        ("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=", 27),
        ("deadbeefcafebabe0123456789abcdef", 11),
        ("your_api_key_here", 4),
        ("CHANGE_ME", 2),
        ("https://example.com/path?x=1", 9),
        ("user@example.com", 3),
        ("\t\t", 1),
        ("", 0),
        ("'S 'T 'RE", 5),
        ("ÄÖÜ ß", 5),
        ("x", 1),
        (" ", 1),
        ("\n", 1),
        ("  \n  x", 3),
        ("a\n", 2),
        ("ab\r\ncd", 3),
        ("TyGJMuHbEL31IeL2HPcHyGcFRl1S", 21),
        ("PnXNYvMIHa_2o76umfXfKm_r5kJP1VrT-1FJors_6I", 33),
        ("i8IHn5kxsC7tV", 11),
        ("O_HbkQfyy_KV5zjR3j1twdTKWTddB-XhkAS1voQG6yyzyN9", 33),
        ("zHYIa4UOrGNATMuDJawTgsu8PO-799nKSNrh9UCauSDmLhuV", 31),
        ("cqcYezdZ_tDDj8hYs5suKcNd8Zra9A", 23),
        ("sKPxZ9W3qLy7zKUVQDT7S8sTQCBNR3YbDgblep", 30),
        ("1QHt61QTC4XATWS8PHp9NHfY", 18),
        ("FM5DI4pZj59fhZ5R1Py4oJe2J", 19),
        ("mPTuSgR7cMy-UcU3zr1Zt", 18),
    ];

    #[test]
    fn counts_match_tiktoken() {
        for (text, expected) in REFERENCE {
            assert_eq!(count(text), *expected, "{text:?}");
        }
    }

    #[test]
    fn ratio_separates_text_from_keys() {
        // Readable placeholders sit above the 2.5 line Betterleaks uses…
        assert!(token_ratio("your_api_key_here").unwrap() >= 2.5);
        assert!(token_ratio("ThisIsAPasswordPlaceholder").unwrap() >= 2.5);
        assert!(token_ratio("the quick brown fox").unwrap() >= 2.5);
        // …and random key material well below it.
        assert!(token_ratio("sk_test_4eC39HqLyjWDarjtT1zdp7dc").unwrap() < 2.0);
        assert!(token_ratio("zHYIa4UOrGNATMuDJawTgsu8PO-799nKSNrh9UCauSDmLhuV").unwrap() < 2.0);
        assert_eq!(token_ratio(""), None);
    }

    #[test]
    fn short_multiline_secret_is_measured_without_its_line_breaks() {
        assert_eq!(token_ratio("ab\r\ncd"), token_ratio("abcd"));
        // At twenty characters or more the breaks stay.
        let long = "abcdefghij\nklmnopqrst";
        assert_ne!(token_ratio(long), token_ratio("abcdefghijklmnopqrst"));
    }

    #[test]
    fn long_input_is_bounded() {
        let big = "x".repeat(MAX_BYTES * 3);
        assert!(token_ratio(&big).is_some());
        let multibyte = "é".repeat(MAX_BYTES);
        assert!(token_ratio(&multibyte).is_some());
    }
}
