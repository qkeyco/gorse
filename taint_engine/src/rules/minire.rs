// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! A small backtracking regular-expression matcher, std only.
//!
//! It supports exactly the subset of Go/RE2 syntax the Betterleaks rules use:
//! literals; escapes (`\b \B \A \z \s \S \w \W \d \D \t \n \r \f \v`,
//! `\xHH`, `\x{H..}`, escaped punctuation); character classes with ranges,
//! negation, escapes and POSIX names (`[[:alnum:]]`); `.`; the quantifiers
//! `* + ? {n} {n,} {n,m}` and their lazy forms; capturing, named
//! (`(?P<name>…)`) and non-capturing groups; alternation; inline flags
//! `(?i)` / `(?s)` and scoped `(?i:…)` / `(?-i:…)`; `^` and `$` (start and end
//! of the text, as in Go without `(?m)`). A `{` that does not start a valid
//! repetition is a literal, as in Go.
//!
//! Semantics follow Go's `regexp` for these features: leftmost-first
//! (Perl-like) alternation and capture selection, ASCII-only `\b \w \s \d`,
//! ASCII case folding for `(?i)`. Matching works on bytes; `.` and negated
//! classes consume one whole UTF-8 character, so every span is a valid `str`
//! boundary. Non-ASCII characters inside patterns are rejected.
//!
//! The program is a list of instructions run by an explicit-stack
//! backtracker. Visited (instruction, position) pairs are remembered when the
//! table fits in [`MEMO_LIMIT_BITS`], which bounds the work to
//! instructions × text length (RE2's "bit-state" technique; exact for
//! first-match semantics because a state that failed once fails again).
//! Every search also has a step budget; when it runs out the search reports
//! no match rather than burning CPU. Without memoisation the explicit
//! backtracking stack is bounded too ([`stack_limit`]), so a pattern such as
//! `(a*)*b` on megabytes of `a` fails fast in bounded memory.
//! [`Regex::captures_all`] finds every match in one text with one shared
//! budget, computing the keyword anchor table once.

use std::cell::RefCell;
use std::fmt;

/// Visited-table size above which the matcher runs without memoisation.
const MEMO_LIMIT_BITS: usize = 1 << 24;
/// Steps allowed per search: a base plus a per-byte allowance.
const STEP_BUDGET_BASE: usize = 1_000_000;
const STEP_BUDGET_PER_BYTE: usize = 256;
/// Largest counted repetition, as in RE2.
const MAX_REPEAT: u32 = 1000;
/// Largest compiled program.
const MAX_PROGRAM: usize = 100_000;
/// Smallest backtracking-stack bound (jobs) for a search without
/// memoisation; see [`stack_limit`].
const MIN_STACK_LIMIT: usize = 1 << 16;

/// Most pending jobs a search without memoisation may hold: 4 × program
/// length × 64, and never less than [`MIN_STACK_LIMIT`]. A memoised search
/// pushes each (instruction, position) state at most once, so its stack is
/// already bounded by the visited table.
fn stack_limit(prog_len: usize) -> usize {
    prog_len.saturating_mul(256).max(MIN_STACK_LIMIT)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub pos: usize,
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "regex error at byte {}: {}", self.pos, self.msg)
    }
}

impl std::error::Error for Error {}

// ─── Byte sets ───────────────────────────────────────────────────────────────

/// A set of ASCII bytes plus one flag for "any non-ASCII character".
#[derive(Clone, Copy, PartialEq, Eq, Default)]
struct Set {
    bits: [u64; 2],
    non_ascii: bool,
}

impl Set {
    fn single(b: u8) -> Set {
        let mut s = Set::default();
        s.insert(b);
        s
    }
    fn insert(&mut self, b: u8) {
        debug_assert!(b < 128);
        self.bits[(b >> 6) as usize] |= 1u64 << (b & 63);
    }
    fn insert_range(&mut self, lo: u8, hi: u8) {
        for b in lo..=hi {
            self.insert(b);
        }
    }
    fn has(&self, b: u8) -> bool {
        if b >= 128 {
            return self.non_ascii;
        }
        self.bits[(b >> 6) as usize] & (1u64 << (b & 63)) != 0
    }
    fn union(&mut self, o: &Set) {
        self.bits[0] |= o.bits[0];
        self.bits[1] |= o.bits[1];
        self.non_ascii |= o.non_ascii;
    }
    fn negate(&mut self) {
        self.bits[0] = !self.bits[0];
        self.bits[1] = !self.bits[1];
        self.non_ascii = !self.non_ascii;
    }
    fn fold_case(&mut self) {
        for b in b'a'..=b'z' {
            let u = b.to_ascii_uppercase();
            if self.has(b) || self.has(u) {
                self.insert(b);
                self.insert(u);
            }
        }
    }
    fn count_ascii(&self) -> u32 {
        self.bits[0].count_ones() + self.bits[1].count_ones()
    }
    /// True when the set is one character, or one letter in either case.
    fn is_single_char(&self) -> bool {
        if self.non_ascii {
            return false;
        }
        match self.count_ascii() {
            1 => true,
            2 => (b'a'..=b'z').any(|b| self.has(b) && self.has(b.to_ascii_uppercase())),
            _ => false,
        }
    }
    fn digit() -> Set {
        let mut s = Set::default();
        s.insert_range(b'0', b'9');
        s
    }
    fn word() -> Set {
        let mut s = Set::digit();
        s.insert_range(b'a', b'z');
        s.insert_range(b'A', b'Z');
        s.insert(b'_');
        s
    }
    fn space() -> Set {
        // Go's \s: [\t\n\f\r ].
        let mut s = Set::default();
        for b in [b'\t', b'\n', 0x0c, b'\r', b' '] {
            s.insert(b);
        }
        s
    }
    fn negated(mut self) -> Set {
        self.negate();
        self
    }
}

impl fmt::Debug for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Set({} ascii, non_ascii={})",
            self.count_ascii(),
            self.non_ascii
        )
    }
}

// ─── Syntax tree ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Look {
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    Set(Set),
    Look(Look),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Group(Box<Node>, Option<usize>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
}

#[derive(Clone, Copy)]
struct Flags {
    case_insensitive: bool,
    dot_all: bool,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    ncap: usize,
}

impl<'a> Parser<'a> {
    fn err<T>(&self, msg: &str) -> Result<T, Error> {
        Err(Error {
            pos: self.i,
            msg: msg.to_string(),
        })
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn starts_with(&self, lit: &str) -> bool {
        self.s[self.i..].starts_with(lit.as_bytes())
    }

    /// Alternation up to `)` or end of input. Inline flags persist to the end
    /// of the enclosing group, across `|`, as in RE2.
    fn parse_alt(&mut self, flags: &mut Flags) -> Result<Node, Error> {
        let mut branches = vec![self.parse_concat(flags)?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            branches.push(self.parse_concat(flags)?);
        }
        Ok(if branches.len() == 1 {
            branches.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(branches)
        })
    }

    fn parse_concat(&mut self, flags: &mut Flags) -> Result<Node, Error> {
        let mut items: Vec<Node> = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                b'|' | b')' => break,
                b'*' | b'+' | b'?' => {
                    self.i += 1;
                    let (min, max) = match c {
                        b'*' => (0, None),
                        b'+' => (1, None),
                        _ => (0, Some(1)),
                    };
                    self.apply_repeat(&mut items, min, max)?;
                }
                b'{' => {
                    if let Some((min, max, len)) = self.repeat_spec() {
                        self.i += len;
                        self.apply_repeat(&mut items, min, max)?;
                    } else {
                        self.i += 1;
                        items.push(literal(b'{', flags));
                    }
                }
                b'(' => {
                    if let Some(node) = self.parse_group(flags)? {
                        items.push(node);
                    }
                }
                b'[' => {
                    self.i += 1;
                    let set = self.parse_class(flags)?;
                    items.push(Node::Set(set));
                }
                b'.' => {
                    self.i += 1;
                    let mut set = Set::default().negated();
                    if !flags.dot_all {
                        set.bits[0] &= !(1u64 << b'\n');
                    }
                    items.push(Node::Set(set));
                }
                b'^' => {
                    self.i += 1;
                    items.push(Node::Look(Look::Start));
                }
                b'$' => {
                    self.i += 1;
                    items.push(Node::Look(Look::End));
                }
                b'\\' => {
                    self.i += 1;
                    items.push(self.parse_escape(flags)?);
                }
                c if c >= 0x80 => return self.err("non-ASCII character in pattern"),
                c => {
                    self.i += 1;
                    items.push(literal(c, flags));
                }
            }
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    /// `{n}`, `{n,}` or `{n,m}` at the cursor: (min, max, length in bytes).
    fn repeat_spec(&self) -> Option<(u32, Option<u32>, usize)> {
        let rest = &self.s[self.i..];
        let close = rest.iter().position(|&b| b == b'}')?;
        let inner = std::str::from_utf8(&rest[1..close]).ok()?;
        let number = |t: &str| -> Option<u32> {
            if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            t.parse().ok()
        };
        let (min, max) = match inner.split_once(',') {
            None => {
                let n = number(inner)?;
                (n, Some(n))
            }
            Some((a, "")) => (number(a)?, None),
            Some((a, b)) => (number(a)?, Some(number(b)?)),
        };
        Some((min, max, close + 1))
    }

    fn apply_repeat(
        &mut self,
        items: &mut Vec<Node>,
        min: u32,
        max: Option<u32>,
    ) -> Result<(), Error> {
        let greedy = if self.peek() == Some(b'?') {
            self.i += 1;
            false
        } else {
            true
        };
        if min > MAX_REPEAT || max.is_some_and(|m| m > MAX_REPEAT) {
            return self.err("repetition count too large");
        }
        if max.is_some_and(|m| m < min) {
            return self.err("invalid repetition range");
        }
        let Some(last) = items.pop() else {
            return self.err("repetition without an operand");
        };
        if matches!(last, Node::Repeat { .. } | Node::Look(_) | Node::Empty) {
            return self.err("invalid repetition operand");
        }
        items.push(Node::Repeat {
            node: Box::new(last),
            min,
            max,
            greedy,
        });
        Ok(())
    }

    /// Parses a group or a flag directive; returns None for `(?i)`-style
    /// directives, which only change `flags`.
    fn parse_group(&mut self, flags: &mut Flags) -> Result<Option<Node>, Error> {
        self.i += 1; // (
        let mut local = *flags;
        let mut capture = None;
        if self.starts_with("?P<") || self.starts_with("?<") {
            self.i += if self.starts_with("?P<") { 3 } else { 2 };
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'>' {
                    break;
                }
                if !(c.is_ascii_alphanumeric() || c == b'_') {
                    return self.err("invalid group name");
                }
                self.i += 1;
            }
            if self.peek() != Some(b'>') || self.i == start {
                return self.err("invalid group name");
            }
            self.i += 1;
            self.ncap += 1;
            capture = Some(self.ncap);
        } else if self.peek() == Some(b'?') {
            self.i += 1;
            let mut negate = false;
            loop {
                match self.peek() {
                    Some(b'i') => local.case_insensitive = !negate,
                    Some(b's') => local.dot_all = !negate,
                    Some(b'-') if !negate => negate = true,
                    Some(b')') => {
                        self.i += 1;
                        *flags = local;
                        return Ok(None);
                    }
                    Some(b':') => {
                        self.i += 1;
                        break;
                    }
                    _ => return self.err("unsupported group flag"),
                }
                self.i += 1;
            }
        } else {
            self.ncap += 1;
            capture = Some(self.ncap);
        }
        let inner = self.parse_alt(&mut local)?;
        if self.peek() != Some(b')') {
            return self.err("missing )");
        }
        self.i += 1;
        Ok(Some(Node::Group(Box::new(inner), capture)))
    }

    /// Escape outside a class (the backslash is consumed).
    fn parse_escape(&mut self, flags: &Flags) -> Result<Node, Error> {
        let Some(c) = self.peek() else {
            return self.err("trailing backslash");
        };
        match c {
            b'b' => {
                self.i += 1;
                Ok(Node::Look(Look::WordBoundary))
            }
            b'B' => {
                self.i += 1;
                Ok(Node::Look(Look::NotWordBoundary))
            }
            b'A' => {
                self.i += 1;
                Ok(Node::Look(Look::Start))
            }
            b'z' => {
                self.i += 1;
                Ok(Node::Look(Look::End))
            }
            _ => {
                let mut set = self.class_escape()?;
                if flags.case_insensitive {
                    set.fold_case();
                }
                Ok(Node::Set(set))
            }
        }
    }

    /// An escape that denotes a set of characters (the backslash is consumed).
    fn class_escape(&mut self) -> Result<Set, Error> {
        let Some(c) = self.peek() else {
            return self.err("trailing backslash");
        };
        self.i += 1;
        Ok(match c {
            b'd' => Set::digit(),
            b'D' => Set::digit().negated(),
            b'w' => Set::word(),
            b'W' => Set::word().negated(),
            b's' => Set::space(),
            b'S' => Set::space().negated(),
            b't' => Set::single(b'\t'),
            b'n' => Set::single(b'\n'),
            b'r' => Set::single(b'\r'),
            b'f' => Set::single(0x0c),
            b'v' => Set::single(0x0b),
            b'x' => Set::single(self.hex_escape()?),
            c if c.is_ascii_punctuation() || c == b' ' => Set::single(c),
            _ => {
                self.i -= 1;
                return self.err("unsupported escape");
            }
        })
    }

    fn hex_escape(&mut self) -> Result<u8, Error> {
        let digits: &[u8] = if self.peek() == Some(b'{') {
            let rest = &self.s[self.i + 1..];
            let Some(end) = rest.iter().position(|&b| b == b'}') else {
                return self.err("unterminated \\x{");
            };
            self.i += end + 2;
            &rest[..end]
        } else {
            let Some(d) = self.s.get(self.i..self.i + 2) else {
                return self.err("short \\x escape");
            };
            self.i += 2;
            d
        };
        let text = std::str::from_utf8(digits).unwrap_or("");
        match u32::from_str_radix(text, 16) {
            Ok(v) if v < 0x80 && !text.is_empty() => Ok(v as u8),
            Ok(_) => self.err("non-ASCII \\x escape"),
            Err(_) => self.err("invalid \\x escape"),
        }
    }

    /// Character class body; the `[` is already consumed.
    fn parse_class(&mut self, flags: &Flags) -> Result<Set, Error> {
        let mut set = Set::default();
        let negate = if self.peek() == Some(b'^') {
            self.i += 1;
            true
        } else {
            false
        };
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return self.err("missing ]");
            };
            if c == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            if c == b'[' && self.starts_with("[:") {
                if let Some(end) = self.s[self.i + 2..].windows(2).position(|w| w == b":]") {
                    let name =
                        std::str::from_utf8(&self.s[self.i + 2..self.i + 2 + end]).unwrap_or("");
                    let (neg, name) = match name.strip_prefix('^') {
                        Some(n) => (true, n),
                        None => (false, name),
                    };
                    let mut p = posix_class(name).ok_or(Error {
                        pos: self.i,
                        msg: format!("unknown POSIX class {name}"),
                    })?;
                    if neg {
                        p.negate();
                    }
                    set.union(&p);
                    self.i += end + 4;
                    continue;
                }
            }
            // One item: a character, an escape, or a range.
            let lo = if c == b'\\' {
                self.i += 1;
                let e = self.class_escape()?;
                if !e.is_single_char() || e.count_ascii() != 1 {
                    set.union(&e);
                    continue;
                }
                first_byte(&e)
            } else if c >= 0x80 {
                return self.err("non-ASCII character in class");
            } else {
                self.i += 1;
                c
            };
            if self.peek() == Some(b'-') && self.s.get(self.i + 1).is_some_and(|&n| n != b']') {
                self.i += 1;
                let hi = match self.peek() {
                    Some(b'\\') => {
                        self.i += 1;
                        let e = self.class_escape()?;
                        if e.count_ascii() != 1 || e.non_ascii {
                            return self.err("invalid range end");
                        }
                        first_byte(&e)
                    }
                    Some(h) if h < 0x80 => {
                        self.i += 1;
                        h
                    }
                    _ => return self.err("invalid range end"),
                };
                if hi < lo {
                    return self.err("invalid range");
                }
                set.insert_range(lo, hi);
            } else {
                set.insert(lo);
            }
        }
        if flags.case_insensitive {
            set.fold_case();
        }
        if negate {
            set.negate();
        }
        Ok(set)
    }
}

fn first_byte(s: &Set) -> u8 {
    (0u8..128).find(|&b| s.has(b)).unwrap_or(0)
}

fn literal(c: u8, flags: &Flags) -> Node {
    let mut s = Set::single(c);
    if flags.case_insensitive {
        s.fold_case();
    }
    Node::Set(s)
}

fn posix_class(name: &str) -> Option<Set> {
    let mut s = Set::default();
    match name {
        "alnum" => {
            s.insert_range(b'0', b'9');
            s.insert_range(b'a', b'z');
            s.insert_range(b'A', b'Z');
        }
        "alpha" => {
            s.insert_range(b'a', b'z');
            s.insert_range(b'A', b'Z');
        }
        "digit" => s.insert_range(b'0', b'9'),
        "lower" => s.insert_range(b'a', b'z'),
        "upper" => s.insert_range(b'A', b'Z'),
        "xdigit" => {
            s.insert_range(b'0', b'9');
            s.insert_range(b'a', b'f');
            s.insert_range(b'A', b'F');
        }
        "word" => s = Set::word(),
        "space" => {
            s = Set::space();
            s.insert(0x0b);
        }
        "punct" => {
            for b in 0u8..128 {
                if b.is_ascii_punctuation() {
                    s.insert(b);
                }
            }
        }
        _ => return None,
    }
    Some(s)
}

// ─── Analysis ────────────────────────────────────────────────────────────────

/// Length of the fixed literal text every match starts with. An alternation
/// counts as its shortest literal branch.
fn literal_prefix(node: &Node) -> (usize, bool) {
    match node {
        Node::Empty | Node::Look(_) => (0, true),
        Node::Set(s) => {
            if s.is_single_char() {
                (1, true)
            } else {
                (0, false)
            }
        }
        Node::Group(n, _) => literal_prefix(n),
        Node::Concat(items) => {
            let mut total = 0;
            for it in items {
                let (len, complete) = literal_prefix(it);
                total += len;
                if !complete {
                    return (total, false);
                }
            }
            (total, true)
        }
        Node::Alt(branches) => (
            branches
                .iter()
                .map(|b| literal_prefix(b).0)
                .min()
                .unwrap_or(0),
            false,
        ),
        Node::Repeat { node, min, max, .. } => {
            let (len, complete) = literal_prefix(node);
            if complete && Some(*min) == *max {
                (len * *min as usize, true)
            } else if *min > 0 {
                (len, false)
            } else {
                (0, false)
            }
        }
    }
}

/// The set of bytes a match can start with, and whether a match can be empty.
fn first_set(node: &Node) -> (Set, bool) {
    match node {
        Node::Empty | Node::Look(_) => (Set::default(), true),
        Node::Set(s) => (*s, false),
        Node::Group(n, _) => first_set(n),
        Node::Concat(items) => {
            let mut acc = Set::default();
            for it in items {
                let (s, nullable) = first_set(it);
                acc.union(&s);
                if !nullable {
                    return (acc, false);
                }
            }
            (acc, true)
        }
        Node::Alt(branches) => {
            let mut acc = Set::default();
            let mut nullable = false;
            for b in branches {
                let (s, n) = first_set(b);
                acc.union(&s);
                nullable |= n;
            }
            (acc, nullable)
        }
        Node::Repeat { node, min, .. } => {
            let (s, n) = first_set(node);
            (s, n || *min == 0)
        }
    }
}

/// Every way `node` can match as a fixed string of single-character sets
/// (case folding included), or None if it is not such a finite literal.
fn literal_strings(node: &Node) -> Option<Vec<Vec<Set>>> {
    const MAX: usize = 64;
    match node {
        Node::Empty | Node::Look(_) => Some(vec![Vec::new()]),
        Node::Set(s) if s.is_single_char() => Some(vec![vec![*s]]),
        Node::Set(_) => None,
        Node::Group(n, _) => literal_strings(n),
        Node::Concat(items) => {
            let mut acc = vec![Vec::new()];
            for it in items {
                let parts = literal_strings(it)?;
                if acc.len() * parts.len() > MAX {
                    return None;
                }
                acc = acc
                    .iter()
                    .flat_map(|a| {
                        parts.iter().map(move |p| {
                            let mut v = a.clone();
                            v.extend_from_slice(p);
                            v
                        })
                    })
                    .collect();
            }
            Some(acc)
        }
        Node::Alt(branches) => {
            let mut acc = Vec::new();
            for b in branches {
                acc.extend(literal_strings(b)?);
                if acc.len() > MAX {
                    return None;
                }
            }
            Some(acc)
        }
        Node::Repeat { .. } => None,
    }
}

/// Minimum and maximum width in bytes of any match of `node`.
fn width(node: &Node) -> (usize, Option<usize>) {
    match node {
        Node::Empty | Node::Look(_) => (0, Some(0)),
        Node::Set(s) => (1, Some(if s.non_ascii { 4 } else { 1 })),
        Node::Group(n, _) => width(n),
        Node::Concat(items) => items.iter().fold((0, Some(0)), |(lo, hi), it| {
            let (l, h) = width(it);
            (lo + l, hi.zip(h).map(|(a, b)| a + b))
        }),
        Node::Alt(branches) => {
            let ws: Vec<_> = branches.iter().map(width).collect();
            let lo = ws.iter().map(|w| w.0).min().unwrap_or(0);
            let hi = ws.iter().try_fold(0, |m, w| w.1.map(|h| m.max(h)));
            (lo, hi)
        }
        Node::Repeat { node, min, max, .. } => {
            let (l, h) = width(node);
            (l * *min as usize, max.zip(h).map(|(m, h)| m as usize * h))
        }
    }
}

/// A literal every match must contain, at a bounded distance from the match
/// start: the first top-level item that is a finite set of non-empty literal
/// strings and is preceded only by items of bounded width. Keyword-style
/// Imported rules (`[\w.-]{0,50}?(?:twitter)...`) start with a run that can
/// begin almost anywhere; searching for the keyword first and trying only
/// starts within reach of it keeps them fast.
#[derive(Debug)]
struct Anchor {
    literals: Vec<Vec<Set>>,
    min_offset: usize,
    max_offset: usize,
}

fn find_anchor(ast: &Node) -> Option<Anchor> {
    let items: &[Node] = match ast {
        Node::Concat(items) => items,
        other => std::slice::from_ref(other),
    };
    let (mut lo, mut hi) = (0usize, 0usize);
    for it in items {
        if let Some(lits) = literal_strings(it) {
            if !lits.is_empty() && lits.iter().all(|l| !l.is_empty()) {
                return Some(Anchor {
                    literals: lits,
                    min_offset: lo,
                    max_offset: hi,
                });
            }
        }
        let (l, h) = width(it);
        lo += l;
        hi += h?;
    }
    None
}

impl Anchor {
    /// Marks the start positions from which a match is possible.
    fn allowed_starts(&self, text: &[u8], out: &mut Vec<bool>) {
        out.clear();
        out.resize(text.len() + 1, false);
        for lit in &self.literals {
            if lit.len() > text.len() {
                continue;
            }
            for p in 0..=text.len() - lit.len() {
                if lit
                    .iter()
                    .zip(&text[p..])
                    .all(|(set, &b)| b < 128 && set.has(b))
                {
                    let lo = p.saturating_sub(self.max_offset);
                    if p >= self.min_offset {
                        for slot in &mut out[lo..=p - self.min_offset] {
                            *slot = true;
                        }
                    }
                }
            }
        }
    }
}

fn starts_anchored(node: &Node) -> bool {
    match node {
        Node::Look(Look::Start) => true,
        Node::Group(n, _) => starts_anchored(n),
        Node::Concat(items) => items.first().is_some_and(starts_anchored),
        Node::Alt(branches) => branches.iter().all(starts_anchored),
        _ => false,
    }
}

// ─── Program ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Inst {
    Set(Set),
    /// Try the first target, then the second.
    Split(usize, usize),
    Jmp(usize),
    Save(usize),
    Look(Look),
    Match,
}

struct Compiler {
    prog: Vec<Inst>,
}

impl Compiler {
    fn emit(&mut self, i: Inst) -> Result<usize, Error> {
        if self.prog.len() >= MAX_PROGRAM {
            return Err(Error {
                pos: 0,
                msg: "pattern too large".into(),
            });
        }
        self.prog.push(i);
        Ok(self.prog.len() - 1)
    }

    fn compile(&mut self, node: &Node) -> Result<(), Error> {
        match node {
            Node::Empty => {}
            Node::Set(s) => {
                self.emit(Inst::Set(*s))?;
            }
            Node::Look(l) => {
                self.emit(Inst::Look(*l))?;
            }
            Node::Concat(items) => {
                for it in items {
                    self.compile(it)?;
                }
            }
            Node::Alt(branches) => {
                let mut jumps = Vec::new();
                for (k, b) in branches.iter().enumerate() {
                    if k + 1 < branches.len() {
                        let split = self.emit(Inst::Split(0, 0))?;
                        self.compile(b)?;
                        jumps.push(self.emit(Inst::Jmp(0))?);
                        let next = self.prog.len();
                        self.prog[split] = Inst::Split(split + 1, next);
                    } else {
                        self.compile(b)?;
                    }
                }
                let end = self.prog.len();
                for j in jumps {
                    self.prog[j] = Inst::Jmp(end);
                }
            }
            Node::Group(inner, cap) => {
                if let Some(c) = cap {
                    self.emit(Inst::Save(2 * c))?;
                    self.compile(inner)?;
                    self.emit(Inst::Save(2 * c + 1))?;
                } else {
                    self.compile(inner)?;
                }
            }
            Node::Repeat {
                node,
                min,
                max,
                greedy,
            } => {
                for _ in 0..*min {
                    self.compile(node)?;
                }
                match max {
                    None => {
                        let split = self.emit(Inst::Split(0, 0))?;
                        self.compile(node)?;
                        self.emit(Inst::Jmp(split))?;
                        let out = self.prog.len();
                        self.prog[split] = if *greedy {
                            Inst::Split(split + 1, out)
                        } else {
                            Inst::Split(out, split + 1)
                        };
                    }
                    Some(max) => {
                        // x{0,k} compiles as (x(x(x)?)?)?, as in RE2.
                        let mut splits = Vec::new();
                        for _ in *min..*max {
                            splits.push(self.emit(Inst::Split(0, 0))?);
                            self.compile(node)?;
                        }
                        let out = self.prog.len();
                        for s in splits {
                            self.prog[s] = if *greedy {
                                Inst::Split(s + 1, out)
                            } else {
                                Inst::Split(out, s + 1)
                            };
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// A compiled pattern.
pub struct Regex {
    prog: Vec<Inst>,
    /// Number of capture groups, not counting group 0 (the whole match).
    groups: usize,
    first: Option<Set>,
    anchored: bool,
    prefix_len: usize,
    anchor: Option<Anchor>,
}

impl fmt::Debug for Regex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Regex")
            .field("instructions", &self.prog.len())
            .field("groups", &self.groups)
            .finish()
    }
}

/// Spans of a match: index 0 is the whole match, then each capture group.
pub type Captures = Vec<Option<(usize, usize)>>;

#[derive(Clone, Copy)]
enum Job {
    Explore(usize, usize),
    Restore(usize, usize),
}

#[derive(Default)]
struct Scratch {
    visited: Vec<u64>,
    stack: Vec<Job>,
    slots: Vec<usize>,
    starts: Vec<bool>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

/// Runs `f` with this thread's scratch space (a fresh one on re-entrant use,
/// which is not expected).
fn with_scratch<R>(f: impl FnOnce(&mut Scratch) -> R) -> R {
    SCRATCH.with(|cell| match cell.try_borrow_mut() {
        Ok(mut s) => f(&mut s),
        Err(_) => f(&mut Scratch::default()),
    })
}

const NONE: usize = usize::MAX;

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, Error> {
        let mut p = Parser {
            s: pattern.as_bytes(),
            i: 0,
            ncap: 0,
        };
        let mut flags = Flags {
            case_insensitive: false,
            dot_all: false,
        };
        let ast = p.parse_alt(&mut flags)?;
        if p.i != p.s.len() {
            return p.err("unmatched )");
        }
        let (first, nullable) = first_set(&ast);
        let anchored = starts_anchored(&ast);
        let prefix_len = literal_prefix(&ast).0;
        let anchor = find_anchor(&ast);
        let whole = Node::Group(Box::new(ast), Some(0));
        let mut c = Compiler { prog: Vec::new() };
        c.compile(&whole)?;
        c.emit(Inst::Match)?;
        Ok(Regex {
            prog: c.prog,
            groups: p.ncap,
            first: if nullable { None } else { Some(first) },
            anchored,
            prefix_len,
            anchor,
        })
    }

    /// Number of capture groups (not counting the whole match).
    pub fn groups(&self) -> usize {
        self.groups
    }

    /// Length of the fixed literal prefix every match starts with
    /// (case-insensitive letters count; an alternation counts its shortest
    /// literal branch).
    pub fn literal_prefix_len(&self) -> usize {
        self.prefix_len
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.captures_at(text, 0).is_some()
    }

    pub fn find(&self, text: &str) -> Option<(usize, usize)> {
        self.captures_at(text, 0).and_then(|c| c[0])
    }

    /// Leftmost-first match starting at or after byte `start`. Assertions see
    /// the whole text. Returns None on no match or when the step budget runs out.
    pub fn captures_at(&self, text: &str, start: usize) -> Option<Captures> {
        if start > text.len() {
            return None;
        }
        let mut budget =
            STEP_BUDGET_BASE.saturating_add(STEP_BUDGET_PER_BYTE.saturating_mul(text.len()));
        with_scratch(|sc| {
            let memo = self.prepare(text.as_bytes(), sc);
            self.search(text.as_bytes(), start, sc, memo, &mut budget)
        })
    }

    /// Every non-overlapping leftmost-first match in `text`, in order (Go's
    /// `FindAllSubmatchIndex`: after an empty match the search moves on one
    /// character). The anchor table and the visited table are built once
    /// for the text, and all searches draw on one `budget` of steps, which
    /// is decremented; when it runs out the matches found so far are
    /// returned. Reusing the visited table across searches is sound: a later
    /// search starts at or after the end of the previous match, positions
    /// only grow, and a state that failed before fails again; the only
    /// states it skips lead back to an empty match at that end, which
    /// `FindAll` ignores as well.
    pub fn captures_all(&self, text: &str, budget: &mut usize) -> Vec<Captures> {
        let mut out = Vec::new();
        with_scratch(|sc| {
            let memo = self.prepare(text.as_bytes(), sc);
            let mut from = 0;
            while from <= text.len() {
                let Some(caps) = self.search(text.as_bytes(), from, sc, memo, budget) else {
                    break;
                };
                let Some((ms, me)) = caps[0] else {
                    break;
                };
                from = if me > ms {
                    me
                } else {
                    ms + text[ms..].chars().next().map_or(1, char::len_utf8)
                };
                out.push(caps);
            }
        });
        out
    }

    /// Per-text setup: clears the visited table when it fits (returns
    /// whether the search is memoised) and marks the anchor's start
    /// positions.
    fn prepare(&self, text: &[u8], sc: &mut Scratch) -> bool {
        let width = text.len() + 1;
        let memo = self.prog.len().saturating_mul(width) <= MEMO_LIMIT_BITS;
        if memo {
            let words = (self.prog.len() * width).div_ceil(64);
            sc.visited.clear();
            sc.visited.resize(words, 0);
        }
        if let Some(a) = &self.anchor {
            a.allowed_starts(text, &mut sc.starts);
        }
        memo
    }

    fn search(
        &self,
        text: &[u8],
        start: usize,
        sc: &mut Scratch,
        memo: bool,
        budget: &mut usize,
    ) -> Option<Captures> {
        let n = text.len();
        sc.slots.clear();
        sc.slots.resize(2 * (self.groups + 1), NONE);

        if self.anchored && start > 0 {
            return None;
        }
        let last = if self.anchored { 0 } else { n };
        let mut s = start;
        while s <= last {
            let boundary = s == n || (text[s] & 0xC0) != 0x80;
            let possible = match &self.first {
                Some(f) => s < n && f.has(text[s]),
                None => true,
            };
            let reachable = self.anchor.is_none() || sc.starts[s];
            if boundary && possible && reachable {
                for v in sc.slots.iter_mut() {
                    *v = NONE;
                }
                match self.run(text, s, sc, memo, budget) {
                    Some(true) => {
                        let caps = sc
                            .slots
                            .chunks(2)
                            .map(|p| {
                                if p[0] != NONE && p[1] != NONE {
                                    Some((p[0], p[1]))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        return Some(caps);
                    }
                    Some(false) => {}
                    None => return None, // budget exhausted
                }
            }
            s += 1;
        }
        None
    }

    /// Some(true) on match, Some(false) on no match from `start`, None when the
    /// step budget is exhausted.
    fn run(
        &self,
        text: &[u8],
        start: usize,
        sc: &mut Scratch,
        memo: bool,
        budget: &mut usize,
    ) -> Option<bool> {
        let n = text.len();
        let width = n + 1;
        let limit = if memo {
            usize::MAX
        } else {
            stack_limit(self.prog.len())
        };
        sc.stack.clear();
        sc.stack.push(Job::Explore(0, start));
        while let Some(job) = sc.stack.pop() {
            let (mut pc, mut pos) = match job {
                Job::Restore(slot, v) => {
                    sc.slots[slot] = v;
                    continue;
                }
                Job::Explore(pc, pos) => (pc, pos),
            };
            loop {
                // Out of steps or of stack: report no match.
                if *budget == 0 || sc.stack.len() > limit {
                    return None;
                }
                *budget -= 1;
                if memo {
                    let k = pc * width + pos;
                    let (w, b) = (k >> 6, 1u64 << (k & 63));
                    if sc.visited[w] & b != 0 {
                        break;
                    }
                    sc.visited[w] |= b;
                }
                match &self.prog[pc] {
                    Inst::Set(set) => {
                        if pos >= n {
                            break;
                        }
                        let b = text[pos];
                        if !set.has(b) {
                            break;
                        }
                        pos += utf8_len(b);
                        pc += 1;
                    }
                    Inst::Split(a, b) => {
                        sc.stack.push(Job::Explore(*b, pos));
                        pc = *a;
                    }
                    Inst::Jmp(a) => pc = *a,
                    Inst::Save(slot) => {
                        sc.stack.push(Job::Restore(*slot, sc.slots[*slot]));
                        sc.slots[*slot] = pos;
                        pc += 1;
                    }
                    Inst::Look(l) => {
                        let ok = match l {
                            Look::Start => pos == 0,
                            Look::End => pos == n,
                            Look::WordBoundary | Look::NotWordBoundary => {
                                let before = pos > 0 && is_word(text[pos - 1]);
                                let after = pos < n && is_word(text[pos]);
                                (before != after) == (*l == Look::WordBoundary)
                            }
                        };
                        if !ok {
                            break;
                        }
                        pc += 1;
                    }
                    Inst::Match => return Some(true),
                }
            }
        }
        Some(false)
    }
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn utf8_len(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(p: &str, t: &str) -> Option<(usize, usize)> {
        Regex::new(p).unwrap().find(t)
    }
    fn group(p: &str, t: &str, g: usize) -> Option<String> {
        let c = Regex::new(p).unwrap().captures_at(t, 0)?;
        c[g].map(|(a, b)| t[a..b].to_string())
    }

    #[test]
    fn literals_and_classes() {
        assert_eq!(find("abc", "xxabcxx"), Some((2, 5)));
        assert_eq!(find("a.c", "abc"), Some((0, 3)));
        assert_eq!(find("a.c", "a\nc"), None);
        assert_eq!(find("(?s:a.c)", "a\nc"), Some((0, 3)));
        assert_eq!(find("[a-c]+", "zzbcaz"), Some((2, 5)));
        assert_eq!(find("[^a-c]+", "abxyc"), Some((2, 4)));
        assert_eq!(find(r"[\w.-]+", "  a.b-c "), Some((2, 7)));
        assert_eq!(find(r"[^]]+", "]]ab]"), Some((2, 4)));
        assert_eq!(find(r"[]a]+", "x]a]x"), Some((1, 4)));
        assert_eq!(find(r"[[:alnum:]]+", "--ab12--"), Some((2, 6)));
        assert_eq!(find(r"[\x60'\s]", "a`b"), Some((1, 2)));
        assert_eq!(find(r"\x60", "a`b"), Some((1, 2)));
        assert_eq!(find(r"[\s\S-]{3}", "a\tb"), Some((0, 3)));
        assert_eq!(find(r"[a-z0-9=_\-]+", "AB=_-x9"), Some((2, 7)));
        assert_eq!(find(r"[\w .-/]+", "/a b./"), Some((0, 6)));
    }

    #[test]
    fn escapes() {
        assert_eq!(find(r"\d\d", "ab12"), Some((2, 4)));
        assert_eq!(find(r"\D+", "12ab3"), Some((2, 4)));
        assert_eq!(find(r"\s", "a b"), Some((1, 2)));
        assert_eq!(find(r"\S+", "  ab "), Some((2, 4)));
        assert_eq!(find(r"\W", "ab-"), Some((2, 3)));
        assert_eq!(find(r"\\[nr]", r"x\ny"), Some((1, 3)));
        assert_eq!(find(r"\$\{x\}", "a${x}"), Some((1, 5)));
        assert_eq!(find(r"\.\*\+\?\|\(\)", ".*+?|()"), Some((0, 7)));
        assert!(Regex::new(r"\q").is_err());
        assert!(Regex::new(r"\1").is_err());
    }

    #[test]
    fn literal_braces() {
        assert_eq!(find(r"^\${(?:[A-Z_]+)}$", "${HOME}"), Some((0, 7)));
        assert_eq!(
            find(r"\{\{[ \t]*\w+[ \t]*}}", "x {{ name }}"),
            Some((2, 12))
        );
        assert_eq!(find(r"^\{\d{0,2}}$", "{12}"), Some((0, 4)));
        assert_eq!(find(r"a{,2}", "a{,2}"), Some((0, 5)));
    }

    #[test]
    fn quantifiers() {
        assert_eq!(find("a*", "aaa"), Some((0, 3)));
        assert_eq!(find("a*?", "aaa"), Some((0, 0)));
        assert_eq!(find("a+?", "aaa"), Some((0, 1)));
        assert_eq!(find("ba?", "baa"), Some((0, 2)));
        assert_eq!(find("ba??", "baa"), Some((0, 1)));
        assert_eq!(find("a{3}", "aaaa"), Some((0, 3)));
        assert_eq!(find("a{2,}", "aaaa"), Some((0, 4)));
        assert_eq!(find("a{2,3}", "aaaa"), Some((0, 3)));
        assert_eq!(find("a{2,3}?", "aaaa"), Some((0, 2)));
        assert_eq!(find("x[0-9]{4}y", "x123y x1234y"), Some((6, 12)));
        assert!(Regex::new("a{1001}").is_err());
        assert!(Regex::new("a{3,2}").is_err());
        assert!(Regex::new("*a").is_err());
    }

    #[test]
    fn groups_and_alternation() {
        assert_eq!(group("(a)(b)?(c)", "ac", 1).as_deref(), Some("a"));
        assert_eq!(group("(a)(b)?(c)", "ac", 2), None);
        assert_eq!(group("(a)(b)?(c)", "ac", 3).as_deref(), Some("c"));
        assert_eq!(group("(?:x|(y))z", "yz", 1).as_deref(), Some("y"));
        assert_eq!(group("(?P<n>ab)c", "abc", 1).as_deref(), Some("ab"));
        // Leftmost-first: the first alternative wins, not the longest.
        assert_eq!(find("a|ab", "ab"), Some((0, 1)));
        assert_eq!(find("ab|a", "ab"), Some((0, 2)));
        assert_eq!(group("(a+)(a*)", "aaa", 2).as_deref(), Some(""));
        assert_eq!(group("(a+?)(a*)", "aaa", 1).as_deref(), Some("a"));
        assert_eq!(Regex::new("(a)(?:b)(?P<x>c)").unwrap().groups(), 2);
        assert!(Regex::new("(a").is_err());
        assert!(Regex::new("a)").is_err());
    }

    #[test]
    fn flags() {
        assert_eq!(find("(?i)abc", "xABC"), Some((1, 4)));
        assert_eq!(find("(?i)[a-c]+", "xAbC"), Some((1, 4)));
        assert_eq!(find("(?i)[^a-c]", "AbCd"), Some((3, 4)));
        assert_eq!(find("a(?i)bc", "aBC"), Some((0, 3)));
        assert_eq!(find("a(?i)bc", "ABC"), None);
        assert_eq!(find("(?i)a(?-i:b)c", "AbC"), Some((0, 3)));
        assert_eq!(find("(?i)a(?-i:b)c", "ABC"), None);
        assert_eq!(find("(?i:a)b", "Ab"), Some((0, 2)));
        assert_eq!(find("(?i:a)b", "AB"), None);
        // Flags last to the end of the enclosing group, across alternation.
        assert_eq!(find("(?i)^true|false|null$", "FALSE"), Some((0, 5)));
        assert_eq!(find("(?:(?i)a)b", "AB"), None);
        assert!(Regex::new("(?m)a").is_err());
    }

    #[test]
    fn anchors_and_boundaries() {
        assert_eq!(find("^ab", "ab"), Some((0, 2)));
        assert_eq!(find("^ab", "cab"), None);
        assert_eq!(find("ab$", "cab"), Some((1, 3)));
        assert_eq!(find("ab$", "abc"), None);
        assert_eq!(find(r"ab\z", "cab"), Some((1, 3)));
        assert_eq!(find(r"\bab\b", "xab ab"), Some((4, 6)));
        assert_eq!(find(r"\Bab", "ab xab"), Some((4, 6)));
        assert_eq!(find(r"(?:x|$)", "ab"), Some((2, 2)));
        let re = Regex::new("^a").unwrap();
        assert!(re.captures_at("aa", 1).is_none());
    }

    #[test]
    fn utf8_safety() {
        let t = "é1é2";
        let (a, b) = find(".+", t).unwrap();
        assert_eq!(&t[a..b], t);
        let (a, b) = find(r"[^\d]", t).unwrap();
        assert_eq!(&t[a..b], "é");
        assert_eq!(find(r"\w", "é1"), Some((2, 3)));
        assert_eq!(find(r"\b1", "é1"), Some((2, 3)));
        assert!(Regex::new("é").is_err());
        // Search from inside a character skips to the next boundary.
        assert_eq!(
            Regex::new(r"\d").unwrap().captures_at(t, 1).unwrap()[0],
            Some((2, 3))
        );
    }

    #[test]
    fn literal_prefix() {
        let p = |s: &str| Regex::new(s).unwrap().literal_prefix_len();
        assert_eq!(p("ghp_[0-9a-zA-Z]{36}"), 4);
        assert_eq!(p(r"\b(sk-ant-api03-[a-z]{3})"), 13);
        assert_eq!(p(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z2-7]{16})\b"), 3);
        assert_eq!(p(r"(?i)\b(npm_[a-z0-9]{36})"), 4);
        assert_eq!(p(r"(?i)[\w.-]{0,50}?(?:adafruit)"), 0);
        assert_eq!(p("x{3}y"), 4);
    }

    #[test]
    fn keyword_anchor_keeps_leftmost_match() {
        let p = r"(?i)[\w.-]{0,5}?(?:key|token)[ =:]+([a-z]{3})\b";
        assert_eq!(find(p, "my.api_KEY = abc"), Some((2, 16)));
        assert_eq!(find(p, "abcdefgh_key=abc"), Some((4, 16)));
        assert_eq!(group(p, "x token: xyz", 1).as_deref(), Some("xyz"));
        assert_eq!(find(p, "keyless = abc"), None);
        assert_eq!(find("ab(?:cd|ef)", "xxabefab"), Some((2, 6)));
        assert_eq!(find("[a-z]*cd", "aaaacd"), Some((0, 6)));
        let re = Regex::new(p).unwrap();
        assert!(re.anchor.is_some());
        assert!(Regex::new("[a-z]*cd").unwrap().anchor.is_none());
    }

    #[test]
    fn catastrophic_patterns_terminate() {
        let long = "a".repeat(5000) + "!";
        // Memoised: linear in instructions × length.
        assert_eq!(find("(a*)*b", &long), None);
        assert_eq!(find("(a|aa)+b", &long), None);
        // Without memoisation (huge program × long text) the budget stops it.
        let big = "a".repeat(20_000);
        let start = std::time::Instant::now();
        assert_eq!(find("(?:a{0,100}){0,100}b", &big), None);
        assert!(start.elapsed().as_secs() < 10);
    }

    #[test]
    fn unmemoised_search_has_a_bounded_stack() {
        // 5 MB is far past the memo table, so only the stack bound stops
        // the backtracker from holding millions of pending jobs.
        let huge = "a".repeat(5 * 1024 * 1024);
        let re = Regex::new("(a*)*b").unwrap();
        let start = std::time::Instant::now();
        assert_eq!(re.find(&huge), None);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "took {:?}",
            start.elapsed()
        );
        SCRATCH.with(|c| {
            let sc = c.borrow();
            assert!(sc.stack.capacity() <= 4 * stack_limit(re.prog.len()));
            assert!(sc.visited.len() * 64 <= MEMO_LIMIT_BITS + 64);
        });
        // A legitimate long greedy run within the bound still matches.
        assert_eq!(find("a*b", &("a".repeat(30_000) + "b")), Some((0, 30_001)));
    }

    #[test]
    fn captures_all_shares_one_budget_and_finds_every_match() {
        let re = Regex::new(r"(?i)[\w.-]{0,5}?(?:key)=([a-z0-9]{4})").unwrap();
        let text = "key=ab12; key=cd34; xkey=ef56";
        let mut budget = 1_000_000;
        let all = re.captures_all(text, &mut budget);
        let secrets: Vec<&str> = all
            .iter()
            .map(|c| c[1].map(|(a, b)| &text[a..b]).unwrap())
            .collect();
        assert_eq!(secrets, ["ab12", "cd34", "ef56"]);
        assert!(budget < 1_000_000);
        // An exhausted budget finds nothing more.
        let mut none = 0;
        assert!(re.captures_all(text, &mut none).is_empty());
        // Empty matches step forward one character.
        let e = Regex::new("x*").unwrap();
        let mut b = 1_000_000;
        assert_eq!(e.captures_all("axxb", &mut b).len(), 3);
    }
}
