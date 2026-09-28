//! One IPC connection's slot in the concurrency budget.
//!
//! Both transports cap concurrent connections and count them with an
//! `AtomicUsize`: increment on accept, decrement when the worker returns. The
//! decrement sat at the end of the worker closure, which is exactly where it
//! does not run — a panic anywhere in dispatch unwinds straight past it and the
//! slot is leaked. The cap is 32; thirty-two panics and the service accepts
//! nothing ever again, while every other part of it looks healthy.
//!
//! A guard decrements in `Drop`, which unwinding does run. The counter then
//! measures what it claims to: connections currently being served.
//!
//! The same budget is also split per caller ([`PerPrincipalSlots`]): any local
//! user reaches the endpoint by design, so the global cap alone lets one
//! account hold every slot and lock everyone else out without sending a byte.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Holds one slot for as long as it lives.
#[derive(Debug)]
pub struct ConnectionSlot {
    count: Arc<AtomicUsize>,
}

impl ConnectionSlot {
    /// Claim a slot. The caller has already decided there is room.
    #[must_use]
    pub fn claim(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self { count }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Concurrent connections one caller may hold. A desktop session peaks near
/// eight: window and tray each open up to three RPC lanes plus the startup
/// client, and the elevation broker runs under the same account. Twelve rides
/// out a reconnect storm and still leaves most of the 32 for other users.
pub const MAX_CONNECTIONS_PER_PRINCIPAL: usize = 12;

/// Live connections per caller (SID on Windows, uid on Unix). Holds only open
/// connections, so an idle machine keeps an empty map.
#[derive(Debug)]
pub struct PerPrincipalSlots<K: Eq + Hash + Clone> {
    counts: Mutex<HashMap<K, usize>>,
}

impl<K: Eq + Hash + Clone> Default for PerPrincipalSlots<K> {
    fn default() -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash + Clone> PerPrincipalSlots<K> {
    /// A slot for `principal`, or `None` when that caller is at the cap.
    #[must_use]
    pub fn claim(self: &Arc<Self>, principal: &K) -> Option<PrincipalSlot<K>> {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let count = counts.entry(principal.clone()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_PRINCIPAL {
            return None;
        }
        *count += 1;
        Some(PrincipalSlot {
            slots: Arc::clone(self),
            principal: principal.clone(),
        })
    }
}

/// Releases the caller's slot on drop, including when the worker panics.
#[derive(Debug)]
pub struct PrincipalSlot<K: Eq + Hash + Clone> {
    slots: Arc<PerPrincipalSlots<K>>,
    principal: K,
}

impl<K: Eq + Hash + Clone> Drop for PrincipalSlot<K> {
    fn drop(&mut self) {
        let mut counts = self.slots.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(count) = counts.get_mut(&self.principal) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.principal);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_is_released_when_the_worker_returns() {
        let count = Arc::new(AtomicUsize::new(0));
        {
            let _slot = ConnectionSlot::claim(Arc::clone(&count));
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_panicking_worker_still_releases_its_slot() {
        // The whole point: a panic anywhere in dispatch must still release the
        // slot. Thirty-two panics that don't and the transport is closed for
        // business.
        let count = Arc::new(AtomicUsize::new(0));
        let moved = Arc::clone(&count);
        let outcome = std::panic::catch_unwind(move || {
            let _slot = ConnectionSlot::claim(moved);
            panic!("dispatch blew up");
        });
        assert!(outcome.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn one_caller_cannot_take_every_slot() {
        let slots = Arc::new(PerPrincipalSlots::<String>::default());
        let alice = "S-1-5-21-ALICE".to_string();
        let held: Vec<_> = (0..MAX_CONNECTIONS_PER_PRINCIPAL)
            .map(|_| slots.claim(&alice).expect("under the cap"))
            .collect();
        assert!(slots.claim(&alice).is_none(), "the cap binds");
        assert!(
            slots.claim(&"S-1-5-21-BOB".to_string()).is_some(),
            "another caller is unaffected"
        );
        drop(held);
        assert!(
            slots.claim(&alice).is_some(),
            "closing gives the slots back"
        );
    }

    #[test]
    fn a_panicking_worker_still_releases_its_principal_slot() {
        let slots = Arc::new(PerPrincipalSlots::<u32>::default());
        let moved = Arc::clone(&slots);
        let outcome = std::panic::catch_unwind(move || {
            let _slot = moved.claim(&1000).expect("free");
            panic!("dispatch blew up");
        });
        assert!(outcome.is_err());
        assert!(slots.counts.lock().expect("lock").is_empty());
    }
}
