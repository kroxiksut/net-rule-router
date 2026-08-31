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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
        // The whole point: the decrement used to be the last statement of the
        // worker closure, and a panic in dispatch skipped it. Thirty-two of
        // those and the transport is closed for business.
        let count = Arc::new(AtomicUsize::new(0));
        let moved = Arc::clone(&count);
        let outcome = std::panic::catch_unwind(move || {
            let _slot = ConnectionSlot::claim(moved);
            panic!("dispatch blew up");
        });
        assert!(outcome.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
