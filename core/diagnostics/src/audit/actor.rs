//! One-way identifier of who performed an audited action.
//!
//! The audit trail never stores a username, a SID or a uid: it stores a hash,
//! so the record says "the same person as that other record" without saying who
//! that is. The hash has to be computed identically in two places — when an
//! event is written, and when a read is scoped to the caller's own events — so
//! it is declared once here rather than in either of them.

use sha2::{Digest, Sha256};

/// Hash of a stored principal (`S-1-5-…`, `unix:uid:<n>`), or `None` for an
/// unattributed actor.
///
/// SHA-256 over the stored string, lowercase hex. Not salted on purpose: the
/// point is to correlate one actor's events with each other without naming
/// them, and a per-record salt would defeat exactly that. The input is a local
/// account identifier, not a secret.
pub fn actor_id_hash(stored_principal: &str) -> Option<String> {
    if stored_principal.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(stored_principal.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::actor_id_hash;

    /// Scoping a read to the caller works only if the write side and the read
    /// side agree — the whole reason this lives in one function.
    #[test]
    fn the_same_principal_always_hashes_the_same_way() {
        let a = actor_id_hash("S-1-5-21-1").expect("hashable");
        let b = actor_id_hash("S-1-5-21-1").expect("hashable");
        assert_eq!(a, b);
        assert_ne!(a, actor_id_hash("S-1-5-21-2").expect("hashable"));
    }

    /// An unattributed action (the service acting on its own) has no actor to
    /// hash, and must not be given a hash that could collide with a person's.
    #[test]
    fn an_empty_principal_has_no_hash() {
        assert_eq!(actor_id_hash(""), None);
    }

    #[test]
    fn the_hash_is_lowercase_hex_of_the_full_digest() {
        let h = actor_id_hash("unix:uid:1000").expect("hashable");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }
}
