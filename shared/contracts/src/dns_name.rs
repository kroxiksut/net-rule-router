//! What a name read off the wire may carry before the product learns it.
//!
//! Learned names reach the cache, the logs and every screen that lists them.
//! A label with `<`, `>` or `&` would let a DNS answer style or spoof that text,
//! so the decoders on every OS keep only letters, digits, `-` and `_`.

/// Whether `label` (one dot-free label, as the wire carries it) may be learned.
#[must_use]
pub fn is_learnable_label(label: &[u8]) -> bool {
    !label.is_empty()
        && label
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_digits_hyphen_and_underscore_only() {
        for good in ["example", "xn--e1afmkfd", "_sip", "a-1", "WWW"] {
            assert!(is_learnable_label(good.as_bytes()), "{good}");
        }
        for bad in ["", "<b>", "a&b", "x>y", "a b", "a/b", "a.b", "a*", "привет"] {
            assert!(!is_learnable_label(bad.as_bytes()), "{bad}");
        }
    }
}
