//! A set that remembers what it learned, but not forever.
//!
//! Everything the service learns by watching traffic — destinations an
//! application used, addresses a reverse lookup was tried on, hostnames a
//! warning was already issued for — is keyed by something an outsider supplies.
//! Kept in a plain `HashSet`, each of those grows for as long as the service
//! runs, and a machine that talks to many hosts is exactly the machine where
//! that matters.
//!
//! Two failure shapes, and the second is the reason this exists at all:
//!
//! - **Unbounded**: the map grows with the traffic. Slow, undramatic, and it
//!   never stops.
//! - **Bounded by refusal**: a cap that drops the NEW entry freezes the set.
//!   What was learned first stays forever, and nothing learned later is ever
//!   admitted — an application that moves to new servers keeps the addresses of
//!   a previous session.
//!
//! So: bounded, and the OLDEST gives way. Re-observing an entry makes it the
//! newest again, so what survives is what is still in use, and an entry that
//! falls out can be learned again — which is also how a one-off failure heals
//! instead of being remembered for the life of the process.

use std::collections::{HashSet, VecDeque};
use std::hash::Hash;

/// Bounded set with least-recently-observed eviction.
#[derive(Debug)]
pub struct BoundedRecentSet<T: Eq + Hash + Clone> {
    order: VecDeque<T>,
    members: HashSet<T>,
    cap: usize,
}

impl<T: Eq + Hash + Clone> BoundedRecentSet<T> {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            order: VecDeque::new(),
            members: HashSet::new(),
            cap: cap.max(1),
        }
    }

    /// Record `value`, returning whether it was NOT already present and what (if
    /// anything) had to give way for it.
    ///
    /// Re-observing refreshes: the value moves to the newest end without
    /// evicting anything.
    pub fn observe(&mut self, value: T) -> Observation<T> {
        if self.members.contains(&value) {
            self.touch(&value);
            return Observation {
                is_new: false,
                evicted: None,
            };
        }
        let evicted = if self.members.len() >= self.cap {
            self.order.pop_front().inspect(|old| {
                self.members.remove(old);
            })
        } else {
            None
        };
        self.members.insert(value.clone());
        self.order.push_back(value);
        Observation {
            is_new: true,
            evicted,
        }
    }

    /// Whether `value` is currently remembered. Does NOT refresh it: a
    /// membership question is not a sighting.
    #[must_use]
    pub fn contains(&self, value: &T) -> bool {
        self.members.contains(value)
    }

    pub fn remove(&mut self, value: &T) -> bool {
        if let Some(pos) = self.order.iter().position(|x| x == value) {
            self.order.remove(pos);
        }
        self.members.remove(value)
    }

    /// Oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.order.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    fn touch(&mut self, value: &T) {
        if let Some(pos) = self.order.iter().position(|x| x == value) {
            self.order.remove(pos);
        }
        self.order.push_back(value.clone());
    }
}

/// What one [`BoundedRecentSet::observe`] did.
#[derive(Debug, PartialEq, Eq)]
pub struct Observation<T> {
    /// `true` when the value had not been remembered — callers use this to
    /// trigger the work a genuinely new observation implies.
    pub is_new: bool,
    /// The value dropped to make room, if the set was full.
    pub evicted: Option<T>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_oldest_gives_way_not_the_newest() {
        let mut set = BoundedRecentSet::new(2);
        assert!(set.observe(1).is_new);
        assert!(set.observe(2).is_new);
        let third = set.observe(3);
        assert!(third.is_new);
        assert_eq!(third.evicted, Some(1), "the oldest gave way");
        assert!(!set.contains(&1));
        assert!(set.contains(&3), "a full set still admits what is new");
    }

    #[test]
    fn re_observing_refreshes_without_evicting() {
        let mut set = BoundedRecentSet::new(2);
        set.observe(1);
        set.observe(2);
        let again = set.observe(1);
        assert!(!again.is_new);
        assert_eq!(again.evicted, None, "a repeat costs nobody their place");
        set.observe(3);
        assert!(set.contains(&1), "still in use, so still remembered");
        assert!(!set.contains(&2), "the stale one gave way");
    }

    #[test]
    fn membership_is_not_a_sighting() {
        // Otherwise a reader keeps entries alive: asking "do we know this?"
        // would refresh it and the set would evict by query order, not use.
        let mut set = BoundedRecentSet::new(2);
        set.observe(1);
        set.observe(2);
        assert!(set.contains(&1));
        set.observe(3);
        assert!(!set.contains(&1), "asking did not save it");
    }

    #[test]
    fn an_evicted_entry_can_be_learned_again() {
        // This is the self-healing property: a one-off failure recorded here is
        // not remembered for the life of the process.
        let mut set = BoundedRecentSet::new(1);
        set.observe("a");
        set.observe("b");
        assert!(set.observe("a").is_new, "a is learnable again");
    }

    #[test]
    fn a_zero_cap_still_holds_one_entry() {
        // A cap of zero would make the set refuse everything while looking like
        // it works; clamp it rather than leave that trap.
        let mut set = BoundedRecentSet::new(0);
        assert!(set.observe(1).is_new);
        assert!(set.contains(&1));
    }
}
