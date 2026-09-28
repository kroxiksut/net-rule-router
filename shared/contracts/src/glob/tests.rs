use std::time::{Duration, Instant};

use super::*;

#[test]
fn equivalence_table() {
    // (pattern, text, matches)
    let cases: &[(&str, &str, bool)] = &[
        ("chrome.exe", "chrome.exe", true),
        ("chrome.exe", "firefox.exe", false),
        ("", "", true),
        ("", "x", false),
        ("*", "", true),
        ("*", "anything.exe", true),
        ("**", "anything", true),
        ("*.exe", "chrome.exe", true),
        ("*.exe", "chrome.dll", false),
        ("chrome*", "chrome", true),
        ("chrome*", "chrome.exe", true),
        ("chrome*", "firefox.exe", false),
        ("*vpn*.exe", "foovpnbar.exe", true),
        ("*vpn*.exe", "vpn.exe", true),
        ("*vpn*.exe", "chrome.exe", false),
        ("*foo*bar*", "xfooyybarz", true),
        ("*foo*bar*", "xfoobaz", false),
        ("a*b*c.exe", "axxbyyc.exe", true),
        ("a*b*c.exe", "axxc.exe", false),
        ("a*a", "a", false),
        ("a*b", "axc", false),
        ("*chrome*", "c:/x/chrome.exe", true),
        ("c:\\*\\x.exe", "c:\\program files\\x.exe", true),
        ("vk?.exe", "vk1.exe", false),
        ("vk?.exe", "vk?.exe", true),
        ("vk?.exe", "vk12.exe", false),
        ("vk?.exe", "vk.exe", false),
        ("?", "é", false),
        ("?", "?", true),
        ("*?*", "what?.exe", true),
        ("*?*", "what.exe", false),
        ("*é*", "caféx", true),
        ("CHROME.EXE", "chrome.exe", true),
        ("chrome.exe", "CHROME.EXE", true),
        // Folding is ASCII only, as every caller's own lower-casing is.
        ("É", "é", false),
    ];
    for &(pattern, text, expected) in cases {
        assert_eq!(
            glob_match(pattern, text),
            expected,
            "{pattern:?} ~ {text:?}"
        );
    }
}

#[test]
fn a_pathological_pattern_returns_promptly() {
    let pattern = format!("{}b", "*a".repeat(60));
    let text = "a".repeat(260);
    let started = Instant::now();
    assert!(!glob_match(&pattern, &text));
    let elapsed = started.elapsed();
    eprintln!("pathological glob: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(100), "took {elapsed:?}");
}

// ── The matchers this one replaced, kept as oracles ──────────────────────

/// The rule engine's and the tunnel-client registry's: bytes, `*` only,
/// case-sensitive over input both callers had already lower-cased.
fn oracle_recursive_star(pat: &[u8], txt: &[u8]) -> bool {
    match pat.first() {
        None => txt.is_empty(),
        Some(b'*') => (0..=txt.len()).any(|i| oracle_recursive_star(&pat[1..], &txt[i..])),
        Some(&pc) => txt
            .first()
            .is_some_and(|&tc| tc == pc && oracle_recursive_star(&pat[1..], &txt[1..])),
    }
}

/// The observation store's: split on `*`, anchored ends, leftmost middles.
fn oracle_split(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let Some(mut rest) = name.strip_prefix(parts[0]) else {
        return false;
    };
    let last_idx = parts.len() - 1;
    for (i, seg) in parts.iter().enumerate().skip(1) {
        if seg.is_empty() {
            continue;
        }
        if i == last_idx {
            if !rest.ends_with(seg) {
                return false;
            }
        } else {
            match rest.find(seg) {
                Some(idx) => rest = &rest[idx + seg.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Deterministic generator: no dependency, and a failure reproduces exactly.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) % bound as u64) as usize
    }

    fn string(&mut self, alphabet: &[char], max_len: usize) -> String {
        let len = self.next(max_len + 1);
        (0..len)
            .map(|_| alphabet[self.next(alphabet.len())])
            .collect()
    }
}

#[test]
fn agrees_with_every_matcher_it_replaced() {
    const PATTERN: &[char] = &['a', 'b', 'A', '*', '*', '?', '.', 'é'];
    const TEXT: &[char] = &['a', 'b', 'A', 'B', '?', '.', 'é', '\\'];
    let mut rng = Lcg(0x5eed);
    let mut matched = 0usize;
    for _ in 0..3000 {
        let pattern = rng.string(PATTERN, 7);
        let text = rng.string(TEXT, 9);

        // The old callers lower-cased both sides before matching.
        let (pat_lower, txt_lower) = (pattern.to_ascii_lowercase(), text.to_ascii_lowercase());
        let expected = oracle_recursive_star(pat_lower.as_bytes(), txt_lower.as_bytes());
        assert_eq!(
            glob_match(&pattern, &text),
            expected,
            "{pattern:?} ~ {text:?}"
        );
        assert_eq!(
            oracle_split(&pat_lower, &txt_lower),
            expected,
            "the two old literal matchers disagree on {pattern:?} ~ {text:?}",
        );
        matched += usize::from(expected);
    }
    // A generator that only produced misses would prove nothing.
    assert!((100..2900).contains(&matched), "{matched} of 3000 matched");
}
