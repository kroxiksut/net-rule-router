//! Share classification of one native topology event across its consumers.

use super::{NetworkChangeCallback, NetworkChangeSubscription};
use crate::error::PlatformError;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{JoinHandle, ThreadId};

const MAX_CONSUMERS: usize = 64;
const MAX_PENDING_CHANGES: usize = 64;
type Registry = Arc<Mutex<Option<Hub>>>;

/// One native registration, shared until its last consumer leaves.
#[derive(Default)]
pub struct SharedNetworkChangeFeed {
    registry: Registry,
}

impl SharedNetworkChangeFeed {
    /// `register` supplies the same classified native feed for every consumer.
    /// Callbacks run on a worker; overflowing topology notices coalesce.
    pub fn subscribe(
        &self,
        callback: NetworkChangeCallback,
        register: impl FnOnce(NetworkChangeCallback) -> Result<NetworkChangeSubscription, PlatformError>,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        // A refused callback may drop another subscription; keep it alive past the lock.
        let (id, entry) = if let Some(hub) = registry.as_ref() {
            hub.dispatch.insert(Arc::clone(&callback))?
        } else {
            let dispatch = Arc::new(Dispatch::default());
            let (id, entry) = dispatch.insert(Arc::clone(&callback))?;
            let worker_dispatch = Arc::clone(&dispatch);
            let worker = std::thread::Builder::new()
                .name("nrr-net-change".into())
                .spawn(move || worker_dispatch.run())
                .map_err(|error| PlatformError::Transient {
                    operation: "start shared network change worker",
                    detail: error.to_string(),
                })?;
            let mut hub = Hub {
                dispatch,
                native: None,
                worker: Some(worker),
            };
            let signal = Arc::clone(&hub.dispatch);
            match register(Arc::new(move || signal.poke())) {
                Ok(native) => hub.native = Some(native),
                Err(error) => {
                    // A callback may itself subscribe; never join while holding the registry.
                    drop(registry);
                    drop(hub);
                    return Err(error);
                }
            }
            *registry = Some(hub);
            (id, entry)
        };
        Ok(NetworkChangeSubscription::new(Box::new(Consumer {
            registry: Arc::clone(&self.registry),
            id,
            entry,
        })))
    }
}

struct Hub {
    dispatch: Arc<Dispatch>,
    native: Option<NetworkChangeSubscription>,
    worker: Option<JoinHandle<()>>,
}

impl Hub {
    fn cancel_native(&mut self) {
        self.dispatch.stop();
        drop(self.native.take());
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        self.cancel_native();
        if let Some(worker) = self.worker.take() {
            // Self-unsubscribe retires this worker after its current callback returns.
            if worker.thread().id() != std::thread::current().id() {
                let _ = worker.join();
            }
        }
    }
}

struct Consumer {
    registry: Registry,
    id: usize,
    entry: Arc<Entry>,
}

impl Drop for Consumer {
    fn drop(&mut self) {
        self.entry.deactivate();
        let retired = {
            let mut registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
            let empty = registry
                .as_ref()
                .is_some_and(|hub| hub.dispatch.remove(self.id));
            if empty {
                let mut retired = registry.take();
                if let Some(hub) = retired.as_mut() {
                    // Finish cancellation before another subscriber opens a native feed.
                    hub.cancel_native();
                }
                retired
            } else {
                None
            }
        };
        self.entry.wait_until_idle();
        drop(retired);
    }
}

#[derive(Default)]
struct Dispatch {
    state: Mutex<DispatchState>,
    changed: Condvar,
}

#[derive(Default)]
struct DispatchState {
    entries: Vec<Option<Arc<Entry>>>,
    pending: usize,
    stopping: bool,
}

impl Dispatch {
    fn insert(
        &self,
        callback: NetworkChangeCallback,
    ) -> Result<(usize, Arc<Entry>), PlatformError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let id = state
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or(state.entries.len());
        if id == MAX_CONSUMERS {
            return Err(PlatformError::Transient {
                operation: "subscribe shared network changes",
                detail: "network change consumer limit reached".into(),
            });
        }
        let entry = Arc::new(Entry {
            callback,
            state: Mutex::new(EntryState {
                active: true,
                in_flight: None,
            }),
            idle: Condvar::new(),
        });
        if id == state.entries.len() {
            state.entries.push(Some(Arc::clone(&entry)));
        } else {
            state.entries[id] = Some(Arc::clone(&entry));
        }
        Ok((id, entry))
    }

    fn remove(&self, id: usize) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = state.entries.get_mut(id) {
            *slot = None;
        }
        state.entries.iter().all(Option::is_none)
    }

    fn poke(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.stopping {
            state.pending = (state.pending + 1).min(MAX_PENDING_CHANGES);
            self.changed.notify_one();
        }
    }

    fn stop(&self) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .stopping = true;
        self.changed.notify_one();
    }

    fn run(&self) {
        loop {
            let callbacks: Vec<_> = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                while state.pending == 0 && !state.stopping {
                    state = self.changed.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                if state.stopping {
                    return;
                }
                state.pending -= 1;
                state.entries.iter().flatten().cloned().collect()
            };
            for entry in callbacks {
                entry.call();
            }
        }
    }
}

struct Entry {
    callback: NetworkChangeCallback,
    state: Mutex<EntryState>,
    idle: Condvar,
}

struct EntryState {
    active: bool,
    in_flight: Option<ThreadId>,
}

impl Entry {
    fn call(&self) {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if !state.active {
                return;
            }
            state.in_flight = Some(std::thread::current().id());
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.callback)()));
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .in_flight = None;
        self.idle.notify_all();
    }

    fn deactivate(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).active = false;
    }

    fn wait_until_idle(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let current = std::thread::current().id();
        while state.in_flight.is_some_and(|owner| owner != current) {
            state = self.idle.wait(state).unwrap_or_else(|p| p.into_inner());
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::own_route_writes::{OwnRouteWrites, RouteChangeKey};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    thread_local! {
        static IN_NATIVE_CALLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[derive(Default)]
    struct NativeFeed {
        callbacks: Mutex<BTreeMap<usize, NetworkChangeCallback>>,
        registrations: AtomicUsize,
        cancellations: AtomicUsize,
        cancelled_inside_callback: AtomicUsize,
        writes: OwnRouteWrites,
    }

    struct NativeGuard {
        source: Arc<NativeFeed>,
        id: usize,
    }

    impl Drop for NativeGuard {
        fn drop(&mut self) {
            if IN_NATIVE_CALLBACK.with(|active| active.get()) {
                self.source
                    .cancelled_inside_callback
                    .fetch_add(1, Ordering::SeqCst);
            }
            self.source.callbacks.lock().unwrap().remove(&self.id);
            self.source.cancellations.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl NativeFeed {
        fn register(
            self: &Arc<Self>,
            callback: NetworkChangeCallback,
        ) -> NetworkChangeSubscription {
            let id = self.registrations.fetch_add(1, Ordering::SeqCst);
            self.callbacks.lock().unwrap().insert(id, callback);
            NetworkChangeSubscription::new(Box::new(NativeGuard {
                source: Arc::clone(self),
                id,
            }))
        }

        fn emit(&self, route: RouteChangeKey) {
            let callbacks: Vec<_> = self.callbacks.lock().unwrap().values().cloned().collect();
            for callback in callbacks {
                if !self.writes.take_echo(route, Instant::now()) {
                    IN_NATIVE_CALLBACK.with(|active| active.set(true));
                    callback();
                    IN_NATIVE_CALLBACK.with(|active| active.set(false));
                }
            }
        }
    }

    fn key() -> RouteChangeKey {
        RouteChangeKey {
            destination: "203.0.113.9".parse().unwrap(),
            prefix_length: 32,
            interface_index: 7,
            removed: false,
        }
    }

    fn counter() -> (Arc<AtomicUsize>, NetworkChangeCallback) {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        (
            count,
            Arc::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    fn subscribe(
        shared: &SharedNetworkChangeFeed,
        source: &Arc<NativeFeed>,
        callback: NetworkChangeCallback,
    ) -> NetworkChangeSubscription {
        shared
            .subscribe(callback, |callback| Ok(source.register(callback)))
            .unwrap()
    }

    fn wait_for(mut ready: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(2);
        while !ready() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(ready(), "notification did not arrive before the deadline");
    }

    #[test]
    fn own_route_echo_does_not_invalidate_either_consumer_but_next_foreign_change_does() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let (first, first_callback) = counter();
        let (second, second_callback) = counter();
        let _first = subscribe(&shared, &source, first_callback);
        let _second = subscribe(&shared, &source, second_callback);
        source.writes.expect(key(), Instant::now());
        source.emit(key());
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            first.load(Ordering::SeqCst),
            0,
            "our write is not a network change"
        );
        assert_eq!(
            second.load(Ordering::SeqCst),
            0,
            "a second consumer must not steal the first consumer's echo"
        );
        source.emit(key());
        wait_for(|| first.load(Ordering::SeqCst) == 1 && second.load(Ordering::SeqCst) == 1);
    }

    #[test]
    fn dropping_one_consumer_keeps_the_native_feed_until_the_last_consumer_leaves() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let (first, callback) = counter();
        let first_guard = subscribe(&shared, &source, callback);
        let (second, callback) = counter();
        let second_guard = subscribe(&shared, &source, callback);
        drop(first_guard);
        assert_eq!(source.cancellations.load(Ordering::SeqCst), 0);
        source.emit(key());
        wait_for(|| second.load(Ordering::SeqCst) == 1);
        assert_eq!(first.load(Ordering::SeqCst), 0);
        drop(second_guard);
        assert_eq!(source.cancellations.load(Ordering::SeqCst), 1);
        let (_, callback) = counter();
        let _restarted = subscribe(&shared, &source, callback);
        assert_eq!(source.registrations.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_first_consumers_do_not_duplicate_native_classification() {
        let shared = Arc::new(SharedNetworkChangeFeed::default());
        let source = Arc::new(NativeFeed::default());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let shared = Arc::clone(&shared);
                let source = Arc::clone(&source);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let (_, callback) = counter();
                    subscribe(&shared, &source, callback)
                })
            })
            .collect();
        barrier.wait();
        let _guards: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(source.registrations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_consumer_can_unsubscribe_itself_without_cancelling_inside_the_native_callback() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let own_guard = Arc::new(Mutex::new(None));
        let weak_guard = Arc::downgrade(&own_guard);
        let callback: NetworkChangeCallback = Arc::new(move || {
            if let Some(guard) = weak_guard.upgrade() {
                drop(guard.lock().unwrap().take());
            }
        });
        *own_guard.lock().unwrap() = Some(subscribe(&shared, &source, callback));
        source.emit(key());
        wait_for(|| source.cancellations.load(Ordering::SeqCst) == 1);
        assert_eq!(source.cancelled_inside_callback.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn failed_registration_can_retry_and_a_synchronous_native_notice_is_not_lost() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let (_, callback) = counter();
        assert!(shared
            .subscribe(callback, |_| Err(PlatformError::Transient {
                operation: "subscribe network changes",
                detail: "unavailable".into(),
            }))
            .is_err());
        let (observed, callback) = counter();
        let _guard = shared
            .subscribe(callback, |callback| {
                callback();
                Ok(source.register(callback))
            })
            .unwrap();
        wait_for(|| observed.load(Ordering::SeqCst) == 1);
        source.emit(key());
        wait_for(|| observed.load(Ordering::SeqCst) == 2);
    }

    #[test]
    fn a_panicking_consumer_does_not_hide_the_change_from_the_other_consumer() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let _broken = subscribe(&shared, &source, Arc::new(|| panic!("broken consumer")));
        let (observed, callback) = counter();
        let _healthy = subscribe(&shared, &source, callback);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| source.emit(key())));
        wait_for(|| observed.load(Ordering::SeqCst) == 1);
    }

    #[test]
    fn excess_consumers_are_refused_without_replacing_existing_consumers() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let mut guards = Vec::new();
        for _ in 0..64 {
            let (_, callback) = counter();
            guards.push(subscribe(&shared, &source, callback));
        }
        let (_, callback) = counter();
        assert!(shared
            .subscribe(callback, |callback| Ok(source.register(callback)))
            .is_err());
        assert_eq!(source.registrations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelling_another_consumer_before_its_turn_skips_its_queued_callback() {
        let shared = SharedNetworkChangeFeed::default();
        let source = Arc::new(NativeFeed::default());
        let other_guard = Arc::new(Mutex::new(None));
        let weak_guard = Arc::downgrade(&other_guard);
        let first_called = Arc::new(AtomicUsize::new(0));
        let first_seen = Arc::clone(&first_called);
        let _first = subscribe(
            &shared,
            &source,
            Arc::new(move || {
                if let Some(guard) = weak_guard.upgrade() {
                    drop(guard.lock().unwrap().take());
                }
                first_seen.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let (second, callback) = counter();
        *other_guard.lock().unwrap() = Some(subscribe(&shared, &source, callback));
        source.emit(key());
        wait_for(|| first_called.load(Ordering::SeqCst) == 1);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(second.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn refusing_a_callback_that_owns_a_subscription_does_not_deadlock_its_destructor() {
        let (finished, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let shared = SharedNetworkChangeFeed::default();
            let source = Arc::new(NativeFeed::default());
            let mut guards = Vec::new();
            for _ in 0..63 {
                let (_, callback) = counter();
                guards.push(subscribe(&shared, &source, callback));
            }
            let (_, callback) = counter();
            let owned_guard = subscribe(&shared, &source, callback);
            let callback: NetworkChangeCallback = Arc::new(move || {
                let _ = &owned_guard;
            });
            let refused = shared
                .subscribe(callback, |callback| Ok(source.register(callback)))
                .is_err();
            finished.send(refused).unwrap();
        });
        assert_eq!(
            result.recv_timeout(Duration::from_secs(2)),
            Ok(true),
            "refusing a consumer must release its callback outside the subscription locks",
        );
    }
}
