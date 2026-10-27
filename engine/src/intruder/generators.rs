//! Payload generators for Intruder: produce a payload list programmatically
//! instead of pasting one. All generators are bounded by [`MAX_GENERATED`] so a
//! generator can never produce an unbounded set.

use serde::Deserialize;

/// Hard ceiling on how many payloads a single generator may emit.
pub const MAX_GENERATED: usize = 50_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Generator {
    /// Decimal numbers from `from` to `to` inclusive, stepping by `step`.
    Numbers { from: i64, to: i64, step: i64 },
    /// Every string of length `min_len`..=`max_len` over `charset`.
    BruteForce {
        charset: String,
        min_len: usize,
        max_len: usize,
    },
    /// All upper/lower-case permutations of the letters in `word`.
    CaseVariations { word: String },
    /// `count` empty payloads (e.g. to repeat a base request N times).
    NullPayloads { count: usize },
}

/// Expand a generator into its (capped) payload list.
pub fn generate(g: &Generator) -> Vec<String> {
    match g {
        Generator::Numbers { from, to, step } => numbers(*from, *to, *step),
        Generator::BruteForce {
            charset,
            min_len,
            max_len,
        } => brute_force(charset, *min_len, *max_len),
        Generator::CaseVariations { word } => case_variations(word),
        Generator::NullPayloads { count } => vec![String::new(); (*count).min(MAX_GENERATED)],
    }
}

fn numbers(from: i64, to: i64, step: i64) -> Vec<String> {
    let mut out = Vec::new();
    if step == 0 {
        return out;
    }
    let mut n = from;
    while (step > 0 && n <= to) || (step < 0 && n >= to) {
        out.push(n.to_string());
        if out.len() >= MAX_GENERATED {
            break;
        }
        match n.checked_add(step) {
            Some(next) => n = next,
            None => break,
        }
    }
    out
}

fn brute_force(charset: &str, min_len: usize, max_len: usize) -> Vec<String> {
    let chars: Vec<char> = charset.chars().collect();
    let mut out = Vec::new();
    if chars.is_empty() || min_len > max_len || max_len == 0 {
        return out;
    }
    for len in min_len.max(1)..=max_len {
        // indices into `chars`, little-endian odometer
        let mut idx = vec![0usize; len];
        loop {
            out.push(idx.iter().map(|&i| chars[i]).collect::<String>());
            if out.len() >= MAX_GENERATED {
                return out;
            }
            // increment odometer
            let mut pos = 0;
            loop {
                if pos == len {
                    // wrapped completely -> done with this length
                    idx = Vec::new();
                    break;
                }
                idx[pos] += 1;
                if idx[pos] < chars.len() {
                    break;
                }
                idx[pos] = 0;
                pos += 1;
            }
            if idx.is_empty() {
                break;
            }
        }
    }
    out
}

fn case_variations(word: &str) -> Vec<String> {
    let chars: Vec<char> = word.chars().collect();
    let letters: Vec<usize> = chars
        .iter()
        .enumerate()
        .filter(|(_, c)| c.is_alphabetic())
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::new();
    if letters.len() > 20 {
        // 2^21 would blow the cap; refuse rather than truncate misleadingly.
        return vec![word.to_string()];
    }
    let combos = 1usize << letters.len();
    for mask in 0..combos {
        let mut c = chars.clone();
        for (bit, &li) in letters.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                c[li] = c[li].to_ascii_uppercase();
            } else {
                c[li] = c[li].to_ascii_lowercase();
            }
        }
        out.push(c.into_iter().collect());
        if out.len() >= MAX_GENERATED {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_inclusive_and_stepped() {
        assert_eq!(
            generate(&Generator::Numbers {
                from: 1,
                to: 5,
                step: 1
            }),
            ["1", "2", "3", "4", "5"]
        );
        assert_eq!(
            generate(&Generator::Numbers {
                from: 0,
                to: 10,
                step: 5
            }),
            ["0", "5", "10"]
        );
        assert_eq!(
            generate(&Generator::Numbers {
                from: 3,
                to: 1,
                step: -1
            }),
            ["3", "2", "1"]
        );
        assert!(
            generate(&Generator::Numbers {
                from: 1,
                to: 5,
                step: 0
            })
            .is_empty()
        );
    }

    #[test]
    fn brute_force_counts_are_correct() {
        let out = generate(&Generator::BruteForce {
            charset: "ab".into(),
            min_len: 1,
            max_len: 2,
        });
        // 2^1 + 2^2 = 6
        assert_eq!(out.len(), 6);
        assert!(out.contains(&"a".to_string()));
        assert!(out.contains(&"ba".to_string()));
    }

    #[test]
    fn brute_force_is_capped() {
        let out = generate(&Generator::BruteForce {
            charset: "abcdefghij".into(),
            min_len: 6,
            max_len: 6,
        });
        assert!(out.len() <= MAX_GENERATED);
    }

    #[test]
    fn case_variations_cover_all_masks() {
        let out = generate(&Generator::CaseVariations { word: "aB".into() });
        // two letters -> 4 variants
        assert_eq!(out.len(), 4);
        assert!(out.contains(&"ab".to_string()));
        assert!(out.contains(&"AB".to_string()));
        assert!(out.contains(&"aB".to_string()));
        assert!(out.contains(&"Ab".to_string()));
    }

    #[test]
    fn null_payloads_are_empty_and_bounded() {
        let out = generate(&Generator::NullPayloads { count: 5 });
        assert_eq!(out.len(), 5);
        assert!(out.iter().all(|s| s.is_empty()));
        assert_eq!(
            generate(&Generator::NullPayloads { count: usize::MAX }).len(),
            MAX_GENERATED
        );
    }
}
