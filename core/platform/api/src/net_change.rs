//! A "the network moved" generation and readings cached against it.
//!
//! Reading the route table or enumerating adapters costs an OS call, and the
//! enforcement pass asks on every hook. The OS already says when either
//! changes ([`NetworkChangeObserver`]), so a reading is re-taken only after
//! that notice, plus a slow safety re-read in case a notice is lost. Without a
//! live feed the reading is taken on every call, as before.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::network_change::{
    NetworkChangeCallback, NetworkChangeObserver, NetworkChangeSubscription,
};

/// How long a cached reading is trusted when no notice arrives.
pub const SAFETY_REREAD: Duration = Duration::from_secs(45);

/// Counts OS network-change notices. Clones share the count.
#[derive(Clone, Default)]
pub struct NetChangeGeneration {
    count: Arc<AtomicU64>,
    fed: Arc<AtomicBool>,
}

impl NetChangeGeneration {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count a notice.
    pub fn bump(&self) {
        self.count.fetch_add(1, Ordering::Release);
    }

    #[must_use]
    pub fn current(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    /// The callback to hand an observer.
    #[must_use]
    pub fn poker(&self) -> NetworkChangeCallback {
        let this = self.clone();
        Arc::new(move || this.bump())
    }

    /// Follow `observer`. Keep the returned subscription alive; `None` when the
    /// OS refused, and readings then stay uncached.
    #[must_use]
    pub fn follow(
        &self,
        observer: &dyn NetworkChangeObserver,
    ) -> Option<NetworkChangeSubscription> {
        let subscription = observer.subscribe(self.poker()).ok()?;
        self.fed.store(true, Ordering::Release);
        Some(subscription)
    }

    fn is_fed(&self) -> bool {
        self.fed.load(Ordering::Acquire)
    }
}

struct Entry<T> {
    value: T,
    generation: u64,
    at: Instant,
}

/// A reading re-taken only when the generation moved or the safety interval ran
/// out. A failed read (`None`) is never kept.
pub struct ChangeCached<T> {
    generation: NetChangeGeneration,
    safety: Duration,
    read: Box<dyn Fn() -> Option<T> + Send + Sync>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
    entry: Mutex<Option<Entry<T>>>,
}

impl<T: Clone> ChangeCached<T> {
    #[must_use]
    pub fn new(
        generation: NetChangeGeneration,
        read: impl Fn() -> Option<T> + Send + Sync + 'static,
    ) -> Self {
        Self {
            generation,
            safety: SAFETY_REREAD,
            read: Box::new(read),
            now: Box::new(Instant::now),
            entry: Mutex::new(None),
        }
    }

    #[must_use]
    pub fn with_safety(mut self, safety: Duration) -> Self {
        self.safety = safety;
        self
    }

    #[must_use]
    pub fn with_clock(mut self, now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        self.now = Box::new(now);
        self
    }

    /// The cached reading, or a fresh one when it is stale.
    pub fn get(&self) -> Option<T> {
        let mut entry = self.entry.lock().unwrap_or_else(|p| p.into_inner());
        if self.generation.is_fed() {
            if let Some(kept) = entry.as_ref() {
                let age = (self.now)().saturating_duration_since(kept.at);
                if kept.generation == self.generation.current() && age < self.safety {
                    return Some(kept.value.clone());
                }
            }
        }
        self.take(&mut entry)
    }

    /// A fresh reading whatever the cache holds, kept for later [`Self::get`]s.
    pub fn refresh(&self) -> Option<T> {
        let mut entry = self.entry.lock().unwrap_or_else(|p| p.into_inner());
        self.take(&mut entry)
    }

    fn take(&self, entry: &mut Option<Entry<T>>) -> Option<T> {
        // The generation is noted before the read: a notice landing during it
        // leaves the entry stale, so the next call reads again.
        let generation = self.generation.current();
        let value = (self.read)();
        *entry = value.clone().map(|value| Entry {
            value,
            generation,
            at: (self.now)(),
        });
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PlatformError;
    use std::sync::atomic::AtomicUsize;

    /// An observer the test fires by hand.
    #[derive(Default)]
    struct FakeFeed {
        callback: Mutex<Option<NetworkChangeCallback>>,
        refuse: bool,
    }

    impl FakeFeed {
        fn fire(&self) {
            let callback = self.callback.lock().expect("lock").clone();
            (callback.expect("subscribed"))();
        }
    }

    impl NetworkChangeObserver for FakeFeed {
        fn subscribe(
            &self,
            on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            if self.refuse {
                return Err(PlatformError::NotSupported { reason: "test" });
            }
            *self.callback.lock().expect("lock") = Some(on_change);
            Ok(NetworkChangeSubscription::inert())
        }
    }

    fn counting(generation: &NetChangeGeneration) -> (Arc<AtomicUsize>, ChangeCached<usize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        let cached = ChangeCached::new(generation.clone(), move || {
            Some(counter.fetch_add(1, Ordering::SeqCst) + 1)
        });
        (reads, cached)
    }

    #[test]
    fn no_os_read_without_an_event() {
        let generation = NetChangeGeneration::new();
        let feed = FakeFeed::default();
        let _sub = generation.follow(&feed).expect("subscribed");
        let (reads, cached) = counting(&generation);
        assert_eq!(cached.get(), Some(1));
        for _ in 0..10 {
            assert_eq!(cached.get(), Some(1));
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_event_triggers_exactly_one_reread() {
        let generation = NetChangeGeneration::new();
        let feed = FakeFeed::default();
        let _sub = generation.follow(&feed).expect("subscribed");
        let (reads, cached) = counting(&generation);
        assert_eq!(cached.get(), Some(1));
        feed.fire();
        feed.fire();
        assert_eq!(cached.get(), Some(2), "a change must show at once");
        assert_eq!(cached.get(), Some(2));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_safety_timer_rereads_when_an_event_was_lost() {
        let generation = NetChangeGeneration::new();
        let feed = FakeFeed::default();
        let _sub = generation.follow(&feed).expect("subscribed");
        let start = Instant::now();
        let offset = Arc::new(AtomicU64::new(0));
        let clock_offset = Arc::clone(&offset);
        let reads = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        let cached = ChangeCached::new(generation, move || {
            Some(counter.fetch_add(1, Ordering::SeqCst))
        })
        .with_safety(Duration::from_secs(30))
        .with_clock(move || start + Duration::from_secs(clock_offset.load(Ordering::SeqCst)));
        cached.get();
        offset.store(29, Ordering::SeqCst);
        cached.get();
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        offset.store(31, Ordering::SeqCst);
        cached.get();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn without_a_live_feed_every_call_reads() {
        let generation = NetChangeGeneration::new();
        let feed = FakeFeed {
            refuse: true,
            ..FakeFeed::default()
        };
        assert!(generation.follow(&feed).is_none());
        let (reads, cached) = counting(&generation);
        cached.get();
        cached.get();
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_feeds_the_cache_and_a_failed_read_is_not_kept() {
        let generation = NetChangeGeneration::new();
        let feed = FakeFeed::default();
        let _sub = generation.follow(&feed).expect("subscribed");
        let (reads, cached) = counting(&generation);
        assert_eq!(cached.refresh(), Some(1));
        assert_eq!(cached.get(), Some(1));
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let fail = Arc::new(AtomicBool::new(true));
        let failing = Arc::clone(&fail);
        let cached = ChangeCached::new(generation, move || {
            (!failing.load(Ordering::SeqCst)).then_some(7_u8)
        });
        assert_eq!(cached.get(), None);
        fail.store(false, Ordering::SeqCst);
        assert_eq!(cached.get(), Some(7), "a failure was cached");
    }
}
