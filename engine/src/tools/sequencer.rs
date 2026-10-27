//! Sequencer: a basic statistical analysis of a sample of tokens (session ids,
//! CSRF tokens, …) to judge how much randomness they carry. Stateless.
//!
//! This is a pragmatic, honest summary — Shannon entropy over the observed
//! characters plus simple shape stats — not a full FIPS-140 randomness battery.
//! It is enough to spot obviously weak tokens (short, low per-character entropy,
//! many duplicates) and to compare candidates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerReport {
    /// Non-empty tokens analysed.
    pub count: usize,
    /// Distinct token values (count minus exact duplicates).
    pub unique: usize,
    pub min_len: usize,
    pub max_len: usize,
    pub mean_len: f64,
    /// Shannon entropy of the character distribution, in bits per character.
    pub bits_per_char: f64,
    /// Size of the observed character alphabet.
    pub alphabet: usize,
    /// Rough entropy estimate for a whole token: `bits_per_char * mean_len`.
    pub bits_per_token: f64,
    /// Qualitative verdict derived from the numbers above.
    pub verdict: String,
}

/// Analyse a sample of tokens. Empty tokens are ignored.
pub fn analyze(tokens: &[String]) -> SequencerReport {
    let toks: Vec<&String> = tokens.iter().filter(|t| !t.is_empty()).collect();
    let count = toks.len();
    if count == 0 {
        return SequencerReport {
            count: 0,
            unique: 0,
            min_len: 0,
            max_len: 0,
            mean_len: 0.0,
            bits_per_char: 0.0,
            alphabet: 0,
            bits_per_token: 0.0,
            verdict: "no tokens to analyse".into(),
        };
    }

    let unique = {
        let set: std::collections::HashSet<&&String> = toks.iter().collect();
        set.len()
    };

    let lens: Vec<usize> = toks.iter().map(|t| t.chars().count()).collect();
    let min_len = *lens.iter().min().unwrap();
    let max_len = *lens.iter().max().unwrap();
    let mean_len = lens.iter().sum::<usize>() as f64 / count as f64;

    // Character frequency across all tokens → Shannon entropy per character.
    let mut freq: HashMap<char, u64> = HashMap::new();
    let mut total_chars: u64 = 0;
    for t in &toks {
        for c in t.chars() {
            *freq.entry(c).or_insert(0) += 1;
            total_chars += 1;
        }
    }
    let alphabet = freq.len();
    let bits_per_char = if total_chars == 0 {
        0.0
    } else {
        freq.values().fold(0.0, |acc, &n| {
            let p = n as f64 / total_chars as f64;
            acc - p * p.log2()
        })
    };
    let bits_per_token = bits_per_char * mean_len;

    let dup_ratio = 1.0 - (unique as f64 / count as f64);
    let verdict = if count < 20 {
        "too few samples for a confident verdict — collect more tokens".into()
    } else if dup_ratio > 0.01 {
        format!("WEAK — {:.1}% of tokens are duplicates", dup_ratio * 100.0)
    } else if bits_per_token < 64.0 {
        format!("WEAK — only ~{bits_per_token:.0} bits of entropy per token")
    } else if bits_per_token < 128.0 {
        format!("MODERATE — ~{bits_per_token:.0} bits of entropy per token")
    } else {
        format!("STRONG — ~{bits_per_token:.0} bits of entropy per token")
    };

    SequencerReport {
        count,
        unique,
        min_len,
        max_len,
        mean_len,
        bits_per_char,
        alphabet,
        bits_per_token,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sample_is_handled() {
        let r = analyze(&[]);
        assert_eq!(r.count, 0);
        assert!(r.verdict.contains("no tokens"));
    }

    #[test]
    fn constant_tokens_have_zero_char_entropy_and_flag_duplicates() {
        let toks: Vec<String> = std::iter::repeat_n("AAAA".to_string(), 50).collect();
        let r = analyze(&toks);
        assert_eq!(r.count, 50);
        assert_eq!(r.unique, 1);
        assert_eq!(r.alphabet, 1);
        assert!(r.bits_per_char.abs() < 1e-9);
        assert!(r.verdict.contains("WEAK"));
    }

    #[test]
    fn varied_tokens_report_positive_entropy() {
        // 64 distinct 16-char tokens over a 16-symbol alphabet.
        let toks: Vec<String> = (0..64u32)
            .map(|i| format!("{:016x}", i.wrapping_mul(2654435761)))
            .collect();
        let r = analyze(&toks);
        assert_eq!(r.count, 64);
        assert_eq!(r.unique, 64);
        assert!(
            r.bits_per_char > 1.0,
            "hex alphabet should carry >1 bit/char"
        );
        assert!(r.min_len == 16 && r.max_len == 16);
    }
}
