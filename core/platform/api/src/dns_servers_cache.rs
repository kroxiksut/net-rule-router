//! A [`SystemDnsServersPort`] that enumerates once per network change.
//!
//! Enumeration can cost a child process (PowerShell, `nmcli`, `resolvectl`),
//! and a caller that resolves names one by one would pay it per name. The
//! server list only changes when the network does, so the cached list is
//! dropped by the OS's own change notification rather than by a timer that is
//! either too slow to notice a new link or too fast to save anything.
//! [`also_reading_on_dns_config_change`](NetworkChangeCachedDnsServers::also_reading_on_dns_config_change)
//! adds the sibling case: a DHCP-pushed domain or a VPN client's own
//! namespace, which moves no link or route.
//!
//! Every enumeration runs on one worker thread. A change re-reads the list of
//! a cache that has served a lookup, so the first unanswered name after a
//! change finds it ready instead of waiting for the child process inside its
//! answer budget. A lookup that finds no list asks the worker and waits for it
//! at most for the time it was given; it never starts a second enumeration.
//!
//! A lookup that reached none of the cached servers is the other event: the
//! list is dropped once and read again. When that fresh read returns the very
//! list that just failed, within the same network generation, failures stop
//! dropping it until a change notification arrives or a read returns another
//! list — a dead network would otherwise cost one child process per lookup.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::dns::{SystemDnsServersPort, UpstreamDnsCandidate};
use crate::dns_config_change::DnsConfigChangeObserver;
use crate::error::PlatformError;
use crate::network_change::{NetworkChangeObserver, NetworkChangeSubscription};

/// A link change arrives as a burst of notifications; the list is read once,
/// this long after the first of them.
const CHANGE_SETTLE: Duration = Duration::from_millis(250);

/// Caches the inner port's answer until the next network change, or until a
/// lookup reaches none of it.
pub struct NetworkChangeCachedDnsServers {
    shared: Arc<Shared>,
    /// Dropped before the worker is stopped, so no change arrives after it.
    subscription: Option<NetworkChangeSubscription>,
    /// A DNS-configuration change (a DHCP-pushed domain, a VPN client's own
    /// namespace) that moves no link or route; `None` when nothing asked for
    /// it or the OS registration failed. Same drop-before-stop rule.
    dns_config_subscription: Option<NetworkChangeSubscription>,
    worker: Option<JoinHandle<()>>,
}

struct Shared {
    inner: Arc<dyn SystemDnsServersPort>,
    /// Bumped by every change notification; a cached list is current only while
    /// it was read at the present generation.
    generation: AtomicU64,
    state: Mutex<CacheState>,
    /// Wakes the worker: a change, a lookup's request, or shutdown.
    wake: Condvar,
    /// Wakes the lookups waiting for an enumeration to end.
    published: Condvar,
}

#[derive(Default)]
struct CacheState {
    current: Option<CachedList>,
    /// The list last dropped for reaching nobody, with its generation.
    failed: Option<(u64, Vec<UpstreamDnsCandidate>)>,
    request: Option<Request>,
    enumerating: bool,
    /// Finished enumerations, so a waiter can tell that the one it waited for
    /// has ended even when it left nothing in `current`.
    completed: u64,
    /// What the last enumeration returned, empty included.
    last: Vec<UpstreamDnsCandidate>,
    /// A cache nobody reads (the resolver never armed) is not re-read on
    /// every change.
    in_use: bool,
    shutdown: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Request {
    /// Waits out the rest of the burst first.
    Change,
    /// A lookup is waiting.
    Lookup,
}

struct CachedList {
    generation: u64,
    servers: Vec<UpstreamDnsCandidate>,
    /// Re-read right after failing and found unchanged: failures no longer
    /// drop it, only a network change does.
    settled: bool,
}

impl NetworkChangeCachedDnsServers {
    /// `Err` when the change notification cannot be registered: without it a
    /// cached list would never be refreshed, so the caller keeps the inner port.
    pub fn new(
        inner: Arc<dyn SystemDnsServersPort>,
        observer: &dyn NetworkChangeObserver,
    ) -> Result<Self, PlatformError> {
        Self::with_settle(inner, observer, CHANGE_SETTLE)
    }

    fn with_settle(
        inner: Arc<dyn SystemDnsServersPort>,
        observer: &dyn NetworkChangeObserver,
        settle: Duration,
    ) -> Result<Self, PlatformError> {
        let shared = Arc::new(Shared {
            inner,
            generation: AtomicU64::new(0),
            state: Mutex::new(CacheState::default()),
            wake: Condvar::new(),
            published: Condvar::new(),
        });
        // Weak: a subscription that outlives the cache must not keep it alive.
        let notified: Weak<Shared> = Arc::downgrade(&shared);
        let subscription = observer.subscribe(Arc::new(move || {
            if let Some(shared) = notified.upgrade() {
                shared.changed();
            }
        }))?;
        let for_worker = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("nrr-dns-servers-cache".to_string())
            .spawn(move || for_worker.run(settle))
            .map_err(|e| PlatformError::Transient {
                operation: "dns_servers_cache.spawn",
                detail: e.to_string(),
            })?;
        Ok(Self {
            shared,
            subscription: Some(subscription),
            dns_config_subscription: None,
            worker: Some(worker),
        })
    }

    /// Re-reads the list on this feed too: a DNS setting (a DHCP-pushed
    /// domain, a VPN client's own namespace) can change without any link or
    /// route event, and the two feeds share the one worker and its 250 ms
    /// settle window. Best-effort — a registration that fails leaves the
    /// cache exactly as it was (network-change-only) and is logged once;
    /// nothing here re-fires this same feed, since a read enumerates and
    /// never writes the configuration it watches.
    pub fn also_reading_on_dns_config_change(
        mut self,
        observer: &dyn DnsConfigChangeObserver,
    ) -> Self {
        let notified: Weak<Shared> = Arc::downgrade(&self.shared);
        match observer.subscribe(Arc::new(move || {
            if let Some(shared) = notified.upgrade() {
                shared.changed();
            }
        })) {
            Ok(subscription) => self.dns_config_subscription = Some(subscription),
            Err(e) => tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-servers-cache-config-feed-unwatched",
                error = %e,
                "DNS-configuration changes cannot be watched; the cache still refreshes on link and route changes",
            ),
        }
        self
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, CacheState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        let mut state = self.lock();
        if state.in_use && state.request.is_none() {
            state.request = Some(Request::Change);
            self.wake.notify_one();
        }
    }

    /// `None` waits for as long as the enumeration takes.
    fn lookup(&self, budget: Option<Duration>) -> Vec<UpstreamDnsCandidate> {
        let deadline = budget.and_then(|b| Instant::now().checked_add(b));
        let mut state = self.lock();
        state.in_use = true;
        let generation = self.generation.load(Ordering::Acquire);
        if let Some(current) = &state.current {
            if current.generation == generation {
                return current.servers.clone();
            }
        }
        // The one in flight, even if a change has already outdated it: the
        // pending re-read is the worker's, not a second child process here.
        if !state.enumerating {
            // Replacing a pending change cuts its settle short.
            state.request = Some(Request::Lookup);
            self.wake.notify_one();
        }
        let awaited = state.completed;
        while state.completed == awaited {
            state = match deadline {
                None => self
                    .published
                    .wait(state)
                    .unwrap_or_else(|p| p.into_inner()),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Vec::new();
                    }
                    self.published
                        .wait_timeout(state, left)
                        .unwrap_or_else(|p| p.into_inner())
                        .0
                }
            };
        }
        state.last.clone()
    }

    fn run(&self, settle: Duration) {
        let mut state = self.lock();
        loop {
            while state.request.is_none() && !state.shutdown {
                state = self.wake.wait(state).unwrap_or_else(|p| p.into_inner());
            }
            if state.shutdown {
                return;
            }
            if state.request == Some(Request::Change) {
                let until = Instant::now() + settle;
                while state.request == Some(Request::Change) && !state.shutdown {
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    state = self
                        .wake
                        .wait_timeout(state, left)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                if state.shutdown {
                    return;
                }
            }
            state.request = None;
            state.enumerating = true;
            // Read before enumerating: a change landing mid-enumeration leaves
            // the stored list one generation behind, and its request re-reads.
            let generation = self.generation.load(Ordering::Acquire);
            drop(state);
            // A panicking mechanism must not leave lookups waiting forever.
            let servers = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.inner.upstream_candidates_v4()
            }))
            .unwrap_or_default();
            state = self.lock();
            state.publish(generation, servers);
            self.published.notify_all();
        }
    }
}

impl CacheState {
    fn publish(&mut self, generation: u64, servers: Vec<UpstreamDnsCandidate>) {
        self.enumerating = false;
        self.completed = self.completed.wrapping_add(1);
        // Empty means "could not tell" (a mechanism restarting, a failed
        // command), not "the network has no servers": it is not remembered.
        self.current = if servers.is_empty() {
            None
        } else {
            let settled = self
                .failed
                .as_ref()
                .is_some_and(|(at, failed)| *at == generation && *failed == servers);
            Some(CachedList {
                generation,
                servers: servers.clone(),
                settled,
            })
        };
        self.last = servers;
    }
}

impl SystemDnsServersPort for NetworkChangeCachedDnsServers {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        self.shared.lookup(None)
    }

    fn upstream_candidates_v4_within(&self, budget: Duration) -> Vec<UpstreamDnsCandidate> {
        self.shared.lookup(Some(budget))
    }

    fn report_all_unreachable(&self, servers: &[UpstreamDnsCandidate]) {
        let generation = self.shared.generation.load(Ordering::Acquire);
        let mut state = self.shared.lock();
        // Only the list in hand, once: a report about an older list, or a
        // second lookup failing on the same one, finds nothing to drop.
        let stale = state.current.as_ref().is_some_and(|current| {
            current.generation == generation && !current.settled && current.servers == servers
        });
        if stale {
            if let Some(dropped) = state.current.take() {
                state.failed = Some((dropped.generation, dropped.servers));
            }
        }
    }
}

impl Drop for NetworkChangeCachedDnsServers {
    /// Waits for an enumeration in flight: the worker owns the inner port's
    /// child process until it returns.
    fn drop(&mut self) {
        drop(self.subscription.take());
        drop(self.dns_config_subscription.take());
        self.shared.lock().shutdown = true;
        self.shared.wake.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_change::NetworkChangeCallback;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::mpsc;

    /// Short enough to keep the suite fast, long enough to hold a burst.
    const TEST_SETTLE: Duration = Duration::from_millis(40);

    struct CountingServers {
        calls: AtomicUsize,
        answer: Mutex<Vec<UpstreamDnsCandidate>>,
    }

    impl CountingServers {
        fn new(answer: Vec<UpstreamDnsCandidate>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                answer: Mutex::new(answer),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn answer(&self, servers: Vec<UpstreamDnsCandidate>) {
            *self.answer.lock().unwrap_or_else(|p| p.into_inner()) = servers;
        }
    }

    impl SystemDnsServersPort for CountingServers {
        fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    /// Holds each enumeration until the test releases it.
    struct GatedServers {
        calls: AtomicUsize,
        answer: Vec<UpstreamDnsCandidate>,
        started: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
        finished: AtomicBool,
    }

    impl GatedServers {
        fn new(
            answer: Vec<UpstreamDnsCandidate>,
        ) -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let servers = Arc::new(Self {
                calls: AtomicUsize::new(0),
                answer,
                started: Mutex::new(started_tx),
                release: Mutex::new(release_rx),
                finished: AtomicBool::new(false),
            });
            (servers, started_rx, release_tx)
        }
    }

    impl SystemDnsServersPort for GatedServers {
        fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self
                .started
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .send(());
            let _ = self
                .release
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .recv();
            self.finished.store(true, Ordering::SeqCst);
            self.answer.clone()
        }
    }

    /// Hands the test the callback the OS would call.
    #[derive(Default)]
    struct ManualObserver {
        callback: Mutex<Option<NetworkChangeCallback>>,
    }

    impl ManualObserver {
        fn fire(&self) {
            let callback = self
                .callback
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(callback) = callback {
                callback();
            }
        }
    }

    impl NetworkChangeObserver for ManualObserver {
        fn subscribe(
            &self,
            on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            *self.callback.lock().unwrap_or_else(|p| p.into_inner()) = Some(on_change);
            Ok(NetworkChangeSubscription::inert())
        }
    }

    /// A `ManualObserver` doubles as the DNS-config feed in tests that need
    /// two independent hand-fired sources.
    impl DnsConfigChangeObserver for ManualObserver {
        fn subscribe(
            &self,
            on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            NetworkChangeObserver::subscribe(self, on_change)
        }
    }

    struct RefusingObserver;

    impl NetworkChangeObserver for RefusingObserver {
        fn subscribe(
            &self,
            _on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            Err(PlatformError::NotSupported {
                reason: "no change notification",
            })
        }
    }

    impl DnsConfigChangeObserver for RefusingObserver {
        fn subscribe(
            &self,
            _on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            Err(PlatformError::NotSupported {
                reason: "no DNS settings notification",
            })
        }
    }

    fn server(last: u8) -> UpstreamDnsCandidate {
        UpstreamDnsCandidate::new(Some(2), Ipv4Addr::new(192, 0, 2, last))
    }

    fn cached(
        inner: Arc<dyn SystemDnsServersPort>,
        observer: &ManualObserver,
    ) -> NetworkChangeCachedDnsServers {
        NetworkChangeCachedDnsServers::with_settle(inner, observer, TEST_SETTLE)
            .expect("the manual observer subscribes")
    }

    fn cache_over(
        answer: Vec<UpstreamDnsCandidate>,
    ) -> (
        Arc<CountingServers>,
        ManualObserver,
        NetworkChangeCachedDnsServers,
    ) {
        let inner = CountingServers::new(answer);
        let observer = ManualObserver::default();
        let cached = cached(inner.clone(), &observer);
        (inner, observer, cached)
    }

    fn eventually(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Long enough for a settle and an enumeration that should not happen.
    fn quiet_period() {
        std::thread::sleep(TEST_SETTLE * 5);
    }

    #[test]
    fn many_lookups_enumerate_once() {
        let (inner, _observer, cached) = cache_over(vec![server(53)]);

        for _ in 0..200 {
            assert_eq!(cached.upstream_candidates_v4(), vec![server(53)]);
        }
        assert_eq!(inner.calls(), 1);
    }

    #[test]
    fn a_network_change_enumerates_again() {
        let (inner, observer, cached) = cache_over(vec![server(53)]);
        assert_eq!(cached.upstream_candidates_v4(), vec![server(53)]);

        inner.answer(vec![server(54)]);
        observer.fire();

        assert_eq!(cached.upstream_candidates_v4(), vec![server(54)]);
        assert_eq!(cached.upstream_candidates_v4(), vec![server(54)]);
        assert_eq!(inner.calls(), 2);
    }

    /// The list is re-read on the change itself, so the next lookup finds it
    /// ready rather than waiting for the enumeration.
    #[test]
    fn a_network_change_re_reads_in_the_background() {
        let (inner, observer, cached) = cache_over(vec![server(53)]);
        cached.upstream_candidates_v4();

        inner.answer(vec![server(54)]);
        observer.fire();
        eventually("the background enumeration", || inner.calls() == 2);
        eventually("its list", || {
            cached.upstream_candidates_v4_within(Duration::ZERO) == vec![server(54)]
        });

        for _ in 0..50 {
            assert_eq!(
                cached.upstream_candidates_v4_within(Duration::ZERO),
                vec![server(54)]
            );
        }
        assert_eq!(inner.calls(), 2);
    }

    #[test]
    fn a_burst_of_changes_is_one_enumeration() {
        let (inner, observer, cached) = cache_over(vec![server(53)]);
        cached.upstream_candidates_v4();

        for _ in 0..20 {
            observer.fire();
        }
        eventually("the background enumeration", || inner.calls() == 2);
        quiet_period();

        assert_eq!(inner.calls(), 2);
    }

    /// Nothing reads the list while the resolver is not armed, so a change
    /// costs no child process.
    #[test]
    fn a_cache_nobody_read_is_not_re_read_on_a_change() {
        let (inner, observer, _cached) = cache_over(vec![server(53)]);

        observer.fire();
        quiet_period();

        assert_eq!(inner.calls(), 0);
    }

    /// Lookups arriving during the warm-up share it; one given too little time
    /// answers without the list instead of starting its own.
    #[test]
    fn lookups_during_a_warm_up_wait_for_it_within_their_budget() {
        let (inner, started, release) = GatedServers::new(vec![server(53)]);
        let observer = ManualObserver::default();
        let cached = Arc::new(cached(inner.clone(), &observer));
        let first = {
            let cached = Arc::clone(&cached);
            std::thread::spawn(move || cached.upstream_candidates_v4())
        };
        started.recv().expect("the first enumeration starts");
        release.send(()).expect("release the first enumeration");
        assert_eq!(first.join().expect("first lookup"), vec![server(53)]);

        observer.fire();
        started.recv().expect("the warm-up starts");
        let short = Instant::now();
        assert!(cached
            .upstream_candidates_v4_within(Duration::from_millis(30))
            .is_empty());
        assert!(short.elapsed() < Duration::from_secs(2));
        let waiting: Vec<_> = (0..4)
            .map(|_| {
                let cached = Arc::clone(&cached);
                std::thread::spawn(move || {
                    cached.upstream_candidates_v4_within(Duration::from_secs(10))
                })
            })
            .collect();
        std::thread::sleep(TEST_SETTLE);
        release.send(()).expect("release the warm-up");

        for lookup in waiting {
            assert_eq!(lookup.join().expect("lookup"), vec![server(53)]);
        }
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dropping_the_cache_joins_the_worker() {
        let (inner, started, release) = GatedServers::new(vec![server(53)]);
        let observer = ManualObserver::default();
        let cached = Arc::new(cached(inner.clone(), &observer));
        let lookup = {
            let cached = Arc::clone(&cached);
            std::thread::spawn(move || cached.upstream_candidates_v4())
        };
        started.recv().expect("the enumeration starts");
        release.send(()).expect("release it");
        lookup.join().expect("lookup");
        observer.fire();
        started.recv().expect("the warm-up starts");

        let dropper = std::thread::spawn(move || drop(cached));
        std::thread::sleep(TEST_SETTLE);
        assert!(!dropper.is_finished(), "drop waits for the enumeration");
        release.send(()).expect("release the warm-up");
        dropper.join().expect("drop");

        assert!(inner.finished.load(Ordering::SeqCst));
        // The worker's hold on the inner port is gone with the thread.
        assert_eq!(Arc::strong_count(&inner), 1);
    }

    /// A failed enumeration is not a network without servers: the next lookup
    /// asks again instead of failing until the next link change.
    #[test]
    fn an_empty_answer_is_not_remembered() {
        let (inner, _observer, cached) = cache_over(Vec::new());
        assert!(cached.upstream_candidates_v4().is_empty());

        inner.answer(vec![server(53)]);

        assert_eq!(cached.upstream_candidates_v4(), vec![server(53)]);
        assert_eq!(cached.upstream_candidates_v4(), vec![server(53)]);
        assert_eq!(inner.calls(), 2);
    }

    #[test]
    fn a_lookup_that_reached_no_server_enumerates_once_more() {
        let (inner, _observer, cached) = cache_over(vec![server(53), server(54)]);
        let servers = cached.upstream_candidates_v4();

        cached.report_all_unreachable(&servers);
        // A concurrent lookup failing on the same list is the same event.
        cached.report_all_unreachable(&servers);

        for _ in 0..10 {
            assert_eq!(cached.upstream_candidates_v4(), servers);
        }
        assert_eq!(inner.calls(), 2);
    }

    /// A dead network keeps failing on an unchanged list; only a network change
    /// earns another enumeration.
    #[test]
    fn repeated_failures_on_an_unchanged_list_wait_for_a_network_change() {
        let (inner, observer, cached) = cache_over(vec![server(53)]);
        let servers = cached.upstream_candidates_v4();
        cached.report_all_unreachable(&servers);
        assert_eq!(cached.upstream_candidates_v4(), servers);
        assert_eq!(inner.calls(), 2);

        for _ in 0..50 {
            cached.report_all_unreachable(&servers);
            assert_eq!(cached.upstream_candidates_v4(), servers);
        }
        assert_eq!(inner.calls(), 2);

        observer.fire();
        assert_eq!(cached.upstream_candidates_v4(), servers);
        assert_eq!(inner.calls(), 3);
        cached.report_all_unreachable(&servers);
        assert_eq!(cached.upstream_candidates_v4(), servers);
        assert_eq!(inner.calls(), 4);
    }

    #[test]
    fn a_changed_list_after_a_failure_can_fail_again() {
        let (inner, _observer, cached) = cache_over(vec![server(53)]);
        let first = cached.upstream_candidates_v4();
        inner.answer(vec![server(54)]);
        cached.report_all_unreachable(&first);

        let second = cached.upstream_candidates_v4();
        assert_eq!(second, vec![server(54)]);
        cached.report_all_unreachable(&second);

        assert_eq!(cached.upstream_candidates_v4(), vec![server(54)]);
        assert_eq!(inner.calls(), 3);
    }

    /// A report about a list the cache no longer holds says nothing about the
    /// one it does.
    #[test]
    fn a_report_about_another_list_is_ignored() {
        let (inner, _observer, cached) = cache_over(vec![server(53), server(54)]);
        cached.upstream_candidates_v4();

        cached.report_all_unreachable(&[server(53)]);

        cached.upstream_candidates_v4();
        assert_eq!(inner.calls(), 1);
    }

    #[test]
    fn no_notification_means_no_cache() {
        let inner = CountingServers::new(vec![server(53)]);

        assert!(NetworkChangeCachedDnsServers::new(inner, &RefusingObserver).is_err());
    }

    /// A DNS-configuration change (no link or route event) enumerates again,
    /// exactly like a network change does.
    #[test]
    fn a_dns_config_change_enumerates_again() {
        let inner = CountingServers::new(vec![server(53)]);
        let network = ManualObserver::default();
        let dns_config = ManualObserver::default();
        let cached = cached(inner.clone(), &network).also_reading_on_dns_config_change(&dns_config);
        assert_eq!(cached.upstream_candidates_v4(), vec![server(53)]);

        inner.answer(vec![server(54)]);
        dns_config.fire();

        assert_eq!(cached.upstream_candidates_v4(), vec![server(54)]);
        assert_eq!(inner.calls(), 2);
    }

    /// A burst touching both feeds inside one settle window still costs one
    /// enumeration: they share the same worker and coalescing window.
    #[test]
    fn a_burst_of_both_feeds_is_one_enumeration() {
        let inner = CountingServers::new(vec![server(53)]);
        let network = ManualObserver::default();
        let dns_config = ManualObserver::default();
        let cached = cached(inner.clone(), &network).also_reading_on_dns_config_change(&dns_config);
        cached.upstream_candidates_v4();

        for _ in 0..10 {
            network.fire();
            dns_config.fire();
        }
        eventually("the background enumeration", || inner.calls() == 2);
        quiet_period();

        assert_eq!(inner.calls(), 2);
    }

    /// Nothing reads the list while the resolver is not armed, so a DNS
    /// settings change costs no child process either.
    #[test]
    fn a_cache_nobody_read_is_not_re_read_on_a_dns_config_change() {
        let inner = CountingServers::new(vec![server(53)]);
        let network = ManualObserver::default();
        let dns_config = ManualObserver::default();
        let _cached =
            cached(inner.clone(), &network).also_reading_on_dns_config_change(&dns_config);

        dns_config.fire();
        quiet_period();

        assert_eq!(inner.calls(), 0);
    }

    /// A refused DNS-config registration keeps the cache working on the
    /// network-change feed alone rather than failing the whole thing.
    #[test]
    fn a_refused_dns_config_feed_keeps_the_network_change_cache() {
        let (inner, observer, cached) = cache_over(vec![server(53)]);
        let cached = cached.also_reading_on_dns_config_change(&RefusingObserver);
        assert_eq!(cached.upstream_candidates_v4(), vec![server(53)]);

        inner.answer(vec![server(54)]);
        observer.fire();

        assert_eq!(cached.upstream_candidates_v4(), vec![server(54)]);
        assert_eq!(inner.calls(), 2);
    }

    /// The re-read is a plain read of the OS's DNS configuration; it writes
    /// nothing back, so a write of ours that reaches the config-change feed
    /// (a search-list write, a resolv.conf redirect) costs at most the one
    /// re-read it caused — the read itself cannot fire the feed again.
    #[test]
    fn the_re_read_itself_never_re_fires_the_dns_config_feed() {
        let inner = CountingServers::new(vec![server(53)]);
        let network = ManualObserver::default();
        let dns_config = ManualObserver::default();
        let cached = cached(inner.clone(), &network).also_reading_on_dns_config_change(&dns_config);
        cached.upstream_candidates_v4();

        // `CountingServers::upstream_candidates_v4` never calls `dns_config`,
        // exactly like the production enumeration (a read-only system call):
        // one fire settles to one enumeration, not a diverging chain.
        dns_config.fire();
        eventually("the background enumeration", || inner.calls() == 2);
        quiet_period();

        assert_eq!(inner.calls(), 2);
    }
}
