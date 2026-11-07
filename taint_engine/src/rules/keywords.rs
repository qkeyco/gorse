// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Aho–Corasick keyword automaton, std only.
//!
//! Betterleaks (as Gitleaks before it) runs a rule only when the lowercased line contains one of the
//! rule's keywords. With ~200 rules, checking each keyword separately would
//! scan every line hundreds of times; this automaton finds every keyword in
//! one pass. Matching is ASCII case-insensitive (keywords are lowercased when
//! the automaton is built, text bytes are folded as they are read).

/// A complete DFA over keyword bytes, with byte classes to keep it small.
pub struct KeywordMatcher {
    /// Byte (any case) → class index; 0 is "byte in no keyword".
    classes: [u8; 256],
    stride: usize,
    /// `state * stride + class` → next state.
    next: Vec<u32>,
    /// Ids reported in each state (its own keywords and those of its
    /// fail-link chain), deduplicated.
    out: Vec<Vec<u32>>,
}

impl KeywordMatcher {
    /// Builds the automaton from (keyword, id) pairs. Several keywords may
    /// share an id; empty keywords are ignored.
    pub fn new<'a, I>(keywords: I) -> KeywordMatcher
    where
        I: IntoIterator<Item = (&'a str, u32)>,
    {
        let keywords: Vec<(Vec<u8>, u32)> = keywords
            .into_iter()
            .filter(|(k, _)| !k.is_empty())
            .map(|(k, id)| (k.bytes().map(|b| b.to_ascii_lowercase()).collect(), id))
            .collect();

        // Byte classes: one per distinct (lowercased) keyword byte.
        let mut classes = [0u8; 256];
        let mut by_lower = [0u8; 256];
        let mut count: usize = 1;
        for (k, _) in &keywords {
            for &b in k {
                if by_lower[b as usize] == 0 {
                    assert!(count < 256, "too many distinct keyword bytes");
                    by_lower[b as usize] = count as u8;
                    count += 1;
                }
            }
        }
        for (b, class) in classes.iter_mut().enumerate() {
            *class = by_lower[(b as u8).to_ascii_lowercase() as usize];
        }
        let stride = count;

        // Trie.
        const NO: u32 = u32::MAX;
        let mut next: Vec<u32> = vec![NO; stride];
        let mut out: Vec<Vec<u32>> = vec![Vec::new()];
        for (k, id) in &keywords {
            let mut s = 0usize;
            for &b in k {
                let c = classes[b as usize] as usize;
                if next[s * stride + c] == NO {
                    let new = out.len();
                    next.extend(std::iter::repeat_n(NO, stride));
                    out.push(Vec::new());
                    next[s * stride + c] = new as u32;
                }
                s = next[s * stride + c] as usize;
            }
            if !out[s].contains(id) {
                out[s].push(*id);
            }
        }

        // Breadth-first: fail links, then fill missing transitions so the
        // trie becomes a complete DFA.
        let states = out.len();
        let mut fail = vec![0usize; states];
        let mut queue = std::collections::VecDeque::new();
        for slot in next.iter_mut().take(stride) {
            match *slot {
                NO => *slot = 0,
                t => {
                    fail[t as usize] = 0;
                    queue.push_back(t as usize);
                }
            }
        }
        while let Some(s) = queue.pop_front() {
            let f = fail[s];
            let inherited = out[f].clone();
            for id in inherited {
                if !out[s].contains(&id) {
                    out[s].push(id);
                }
            }
            for c in 0..stride {
                let t = next[s * stride + c];
                if t == NO {
                    next[s * stride + c] = next[f * stride + c];
                } else {
                    fail[t as usize] = next[f * stride + c] as usize;
                    queue.push_back(t as usize);
                }
            }
        }
        KeywordMatcher {
            classes,
            stride,
            next,
            out,
        }
    }

    /// Calls `hit` with the id of every keyword occurrence in `text` (an id
    /// may be reported more than once).
    pub fn scan(&self, text: &[u8], mut hit: impl FnMut(u32)) {
        let mut s = 0usize;
        for &b in text {
            s = self.next[s * self.stride + self.classes[b as usize] as usize] as usize;
            for &id in &self.out[s] {
                hit(id);
            }
        }
    }

    /// As `scan`, with the byte offset just past each occurrence.
    pub fn scan_positions(&self, text: &[u8], mut hit: impl FnMut(u32, usize)) {
        let mut s = 0usize;
        for (i, &b) in text.iter().enumerate() {
            s = self.next[s * self.stride + self.classes[b as usize] as usize] as usize;
            for &id in &self.out[s] {
                hit(id, i + 1);
            }
        }
    }

    /// Marks `seen[id]` for every id whose keyword occurs in `text`.
    pub fn mark(&self, text: &[u8], seen: &mut [bool]) {
        self.scan(text, |id| {
            if let Some(slot) = seen.get_mut(id as usize) {
                *slot = true;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(m: &KeywordMatcher, text: &str) -> Vec<u32> {
        let mut v = Vec::new();
        m.scan(text.as_bytes(), |id| v.push(id));
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn finds_overlapping_and_nested_keywords() {
        let m = KeywordMatcher::new([("he", 0), ("she", 1), ("his", 2), ("hers", 3)]);
        assert_eq!(ids(&m, "ushers"), vec![0, 1, 3]);
        assert_eq!(ids(&m, "this"), vec![2]);
        assert_eq!(ids(&m, "nothing"), Vec::<u32>::new());
    }

    #[test]
    fn case_insensitive_and_punctuation() {
        let m = KeywordMatcher::new([("sk-ant-api03", 7), ("<add key=", 8), ("xoxb", 9)]);
        assert_eq!(ids(&m, "KEY=SK-ANT-API03-abc"), vec![7]);
        assert_eq!(ids(&m, r#"<ADD Key="Password""#), vec![8]);
        assert_eq!(ids(&m, "xoxB-1"), vec![9]);
        assert_eq!(ids(&m, "xox b"), Vec::<u32>::new());
    }

    #[test]
    fn shared_ids_and_failure_links() {
        let m = KeywordMatcher::new([("aaab", 1), ("ab", 2), ("b", 3), ("", 4)]);
        assert_eq!(ids(&m, "aaaab"), vec![1, 2, 3]);
        let m = KeywordMatcher::new([("twitter", 5), ("twitter", 6), ("tw", 6)]);
        assert_eq!(ids(&m, "Twitter"), vec![5, 6]);
        let mut seen = vec![false; 8];
        m.mark(b"a tw", &mut seen);
        assert!(seen[6] && !seen[5]);
    }

    #[test]
    fn non_ascii_text_is_harmless() {
        let m = KeywordMatcher::new([("key", 0)]);
        assert_eq!(ids(&m, "clé key 鍵"), vec![0]);
    }
}
