//! Comparer: a word- or character-level diff of two texts (requests, responses,
//! or anything pasted in). Stateless, like the Decoder. Uses a longest-common-
//! subsequence diff and coalesces runs so the UI can render insert/delete/equal
//! spans directly.

use serde::{Deserialize, Serialize};

/// Granularity of the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffMode {
    /// Tokens are runs of whitespace and runs of non-whitespace.
    Words,
    /// Tokens are individual Unicode scalar values.
    Chars,
}

/// One span of the diff. `Equal` is in both; `Delete` is only in A; `Insert`
/// is only in B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Seg {
    Equal { text: String },
    Insert { text: String },
    Delete { text: String },
}

/// Above this many tokens per side the quadratic diff is skipped past: the first
/// `MAX_TOKENS` tokens are diffed and the remainder is reported as a bulk
/// delete/insert. Keeps worst-case memory and time bounded for huge inputs.
const MAX_TOKENS: usize = 4000;

/// Compare `a` and `b`, returning the diff as a sequence of spans.
pub fn compare(a: &str, b: &str, mode: DiffMode) -> Vec<Seg> {
    let ta = tokenize(a, mode);
    let tb = tokenize(b, mode);

    let na = ta.len().min(MAX_TOKENS);
    let nb = tb.len().min(MAX_TOKENS);
    let mut segs = lcs_diff(&ta[..na], &tb[..nb]);

    // Anything beyond the cap is reported wholesale rather than diffed.
    if ta.len() > na {
        push(&mut segs, Kind::Delete, &ta[na..].concat());
    }
    if tb.len() > nb {
        push(&mut segs, Kind::Insert, &tb[nb..].concat());
    }
    segs
}

fn tokenize(s: &str, mode: DiffMode) -> Vec<&str> {
    match mode {
        DiffMode::Chars => {
            let mut out = Vec::with_capacity(s.len());
            let mut it = s.char_indices().peekable();
            while let Some((i, _)) = it.next() {
                let end = it.peek().map(|(j, _)| *j).unwrap_or(s.len());
                out.push(&s[i..end]);
            }
            out
        }
        DiffMode::Words => {
            let mut out = Vec::new();
            let mut start = 0usize;
            let mut prev_ws: Option<bool> = None;
            for (i, c) in s.char_indices() {
                let ws = c.is_whitespace();
                match prev_ws {
                    Some(p) if p != ws => {
                        out.push(&s[start..i]);
                        start = i;
                    }
                    _ => {}
                }
                prev_ws = Some(ws);
            }
            if start < s.len() {
                out.push(&s[start..]);
            }
            out
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Equal,
    Insert,
    Delete,
}

/// Append `text` as a `kind` span, merging into the previous span when it is the
/// same kind so the output is already coalesced.
fn push(segs: &mut Vec<Seg>, kind: Kind, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(last) = segs.last_mut() {
        match (kind, last) {
            (Kind::Equal, Seg::Equal { text: t })
            | (Kind::Insert, Seg::Insert { text: t })
            | (Kind::Delete, Seg::Delete { text: t }) => {
                t.push_str(text);
                return;
            }
            _ => {}
        }
    }
    segs.push(match kind {
        Kind::Equal => Seg::Equal {
            text: text.to_string(),
        },
        Kind::Insert => Seg::Insert {
            text: text.to_string(),
        },
        Kind::Delete => Seg::Delete {
            text: text.to_string(),
        },
    });
}

fn lcs_diff(a: &[&str], b: &[&str]) -> Vec<Seg> {
    let (n, m) = (a.len(), b.len());
    // dp[i][j] = length of the LCS of a[i..] and b[j..].
    let mut dp = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut segs = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            push(&mut segs, Kind::Equal, a[i]);
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            push(&mut segs, Kind::Delete, a[i]);
            i += 1;
        } else {
            push(&mut segs, Kind::Insert, b[j]);
            j += 1;
        }
    }
    while i < n {
        push(&mut segs, Kind::Delete, a[i]);
        i += 1;
    }
    while j < m {
        push(&mut segs, Kind::Insert, b[j]);
        j += 1;
    }
    segs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(segs: &[Seg]) -> (String, String) {
        let mut a = String::new();
        let mut b = String::new();
        for s in segs {
            match s {
                Seg::Equal { text } => {
                    a.push_str(text);
                    b.push_str(text);
                }
                Seg::Delete { text } => a.push_str(text),
                Seg::Insert { text } => b.push_str(text),
            }
        }
        (a, b)
    }

    #[test]
    fn identical_is_one_equal_span() {
        let segs = compare("hello world", "hello world", DiffMode::Words);
        assert_eq!(
            segs,
            vec![Seg::Equal {
                text: "hello world".into()
            }]
        );
    }

    #[test]
    fn char_insertion() {
        let segs = compare("abc", "abXc", DiffMode::Chars);
        assert_eq!(
            segs,
            vec![
                Seg::Equal { text: "ab".into() },
                Seg::Insert { text: "X".into() },
                Seg::Equal { text: "c".into() },
            ]
        );
    }

    #[test]
    fn word_deletion_reconstructs_both_sides() {
        let a = "the quick brown fox";
        let b = "the brown fox";
        let segs = compare(a, b, DiffMode::Words);
        let (ra, rb) = text(&segs);
        assert_eq!(ra, a);
        assert_eq!(rb, b);
        assert!(
            segs.iter()
                .any(|s| matches!(s, Seg::Delete { text } if text.contains("quick")))
        );
    }

    #[test]
    fn modes_differ_in_granularity() {
        // "ab" -> "ba": char mode finds a shared letter; word mode sees two
        // different whole words with no common subsequence.
        let chars = compare("ab", "ba", DiffMode::Chars);
        assert!(chars.iter().any(|s| matches!(s, Seg::Equal { .. })));
        let words = compare("ab", "ba", DiffMode::Words);
        assert!(!words.iter().any(|s| matches!(s, Seg::Equal { .. })));
    }

    #[test]
    fn both_sides_reconstruct_for_a_real_edit() {
        let a = "{\"role\":\"user\",\"id\":7}";
        let b = "{\"role\":\"admin\",\"id\":7}";
        let segs = compare(a, b, DiffMode::Chars);
        let (ra, rb) = text(&segs);
        assert_eq!(ra, a);
        assert_eq!(rb, b);
    }
}
