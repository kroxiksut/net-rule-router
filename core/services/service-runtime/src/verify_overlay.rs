//! `?` rules a check verdict moved to the other link, until the user answers.
//!
//! Enforcement-only, like subdomain coverage: every reader that builds what is
//! enforced (the rules provider, the activation snapshot, the explain probe)
//! reads it, and nothing stored or hashed does. Process-wide and keyed by
//! principal, so no wiring can hand one reader a different set than another;
//! a service restart forgets it, which is what makes the check repeat.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_domain::RuleId;

struct Entry {
    moved: Arc<BTreeSet<RuleId>>,
    generation: u64,
}

/// Moves whenever any principal's set changes.
static CHANGES: AtomicU64 = AtomicU64::new(0);

fn registry() -> &'static RwLock<HashMap<String, Entry>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

fn empty() -> Arc<BTreeSet<RuleId>> {
    static EMPTY: OnceLock<Arc<BTreeSet<RuleId>>> = OnceLock::new();
    Arc::clone(EMPTY.get_or_init(Default::default))
}

/// A number that moves whenever what the overlay serves changes; an
/// enforcement pass counts it among its inputs.
pub(crate) fn changes() -> u64 {
    CHANGES.load(Ordering::Acquire)
}

/// `principal`'s moved rule ids and the generation they carry (0 when none).
pub(crate) fn moved_for(principal: &str) -> (u64, Arc<BTreeSet<RuleId>>) {
    let map = registry().read().unwrap_or_else(PoisonError::into_inner);
    match map.get(principal) {
        Some(e) => (e.generation, Arc::clone(&e.moved)),
        None => (0, empty()),
    }
}

/// Replace `principal`'s set; `false` when it was already this one.
pub(crate) fn set(principal: &str, moved: BTreeSet<RuleId>) -> bool {
    let mut map = registry().write().unwrap_or_else(PoisonError::into_inner);
    let current = map.get(principal).map(|e| e.moved.as_ref());
    if current.map_or(moved.is_empty(), |c| *c == moved) {
        return false;
    }
    // Never 0, which stands for "no entry".
    let generation = CHANGES.fetch_add(1, Ordering::AcqRel) + 1;
    if moved.is_empty() {
        map.remove(principal);
    } else {
        map.insert(
            principal.to_owned(),
            Entry {
                moved: Arc::new(moved),
                generation,
            },
        );
    }
    true
}

/// `book` as enforcement sees it for `principal`.
pub(crate) fn effective(book: &CanonicalRuleBook, principal: &str) -> CanonicalRuleBook {
    book.with_verify_effective(&moved_for(principal).1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(names: &[&str]) -> BTreeSet<RuleId> {
        names.iter().map(|n| RuleId((*n).to_string())).collect()
    }

    #[test]
    fn a_set_is_served_to_its_principal_only_and_moves_the_change_number() {
        let before = changes();
        assert!(set("S-overlay-1", ids(&["r-1"])));
        assert!(changes() > before);
        let (generation, moved) = moved_for("S-overlay-1");
        assert_ne!(generation, 0);
        assert_eq!(*moved, ids(&["r-1"]));
        assert!(moved_for("S-overlay-2").1.is_empty());

        assert!(
            !set("S-overlay-1", ids(&["r-1"])),
            "the same set is no change"
        );
        assert!(set("S-overlay-1", BTreeSet::new()));
        assert_eq!(moved_for("S-overlay-1").0, 0);
        assert!(!set("S-overlay-1", BTreeSet::new()));
    }
}
