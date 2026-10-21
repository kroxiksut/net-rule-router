//! How often a pass asks the OS for the table and the links.

use super::*;
use nrr_platform_api::net_change::NetChangeGeneration;
use nrr_platform_api::network_change::{
    NetworkChangeCallback, NetworkChangeObserver, NetworkChangeSubscription,
};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counts the reads and delegates everything else.
struct CountingApi {
    inner: MockWindowsApi,
    tables: AtomicUsize,
    adapters: AtomicUsize,
}

impl CountingApi {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MockWindowsApi::new(),
            tables: AtomicUsize::new(0),
            adapters: AtomicUsize::new(0),
        })
    }
    fn tables(&self) -> usize {
        self.tables.load(Ordering::SeqCst)
    }
    fn adapters(&self) -> usize {
        self.adapters.load(Ordering::SeqCst)
    }
}

impl RouteTablePort for CountingApi {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        self.tables.fetch_add(1, Ordering::SeqCst);
        self.inner.get_ip_forward_table()
    }
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.inner.create_ip_forward_entry(entry)
    }
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.inner.delete_ip_forward_entry(entry)
    }
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        self.adapters.fetch_add(1, Ordering::SeqCst);
        self.inner.get_adapter_infos()
    }
    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
        self.inner.interface_luid_for_index(ifindex)
    }
}

/// An OS feed the test fires by hand.
#[derive(Default)]
struct HandFeed {
    callback: Mutex<Option<NetworkChangeCallback>>,
}

impl HandFeed {
    fn fire(&self) {
        let callback = self.callback.lock().unwrap().clone();
        (callback.expect("subscribed"))();
    }
}

impl NetworkChangeObserver for HandFeed {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        *self.callback.lock().unwrap() = Some(on_change);
        Ok(NetworkChangeSubscription::inert())
    }
}

fn counted_coordinator(api: &Arc<CountingApi>) -> SecondaryRouteCoordinator {
    SecondaryRouteCoordinator::new(
        Arc::clone(api) as Arc<dyn RouteTablePort>,
        Arc::new(FakeRules::new()) as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    )
}

#[test]
fn the_links_are_read_again_only_after_the_network_moved() {
    let api = CountingApi::new();
    let coord = counted_coordinator(&api);
    let generation = NetChangeGeneration::new();
    let feed = HandFeed::default();
    let _sub = generation.follow(&feed).expect("subscribed");
    let _cache = coord.adapter_cache(generation);

    for _ in 0..5 {
        let _ = coord.read_machine();
    }
    assert_eq!(api.adapters(), 1, "five readers, one enumeration");

    feed.fire();
    let _ = coord.read_machine();
    assert_eq!(api.adapters(), 2);
}

#[test]
fn a_pass_reads_past_the_cache_so_an_uncounted_notice_cannot_outdate_it() {
    let api = CountingApi::new();
    let coord = counted_coordinator(&api);
    let generation = NetChangeGeneration::new();
    let feed = HandFeed::default();
    let _sub = generation.follow(&feed).expect("subscribed");
    let _cache = coord.adapter_cache(generation);
    let _ = coord.read_machine();
    assert_eq!(api.adapters(), 1);

    // The notice has not been counted, yet the pass reads the OS.
    let _ = coord.recompute_active(&[]);
    assert_eq!(api.adapters(), 2);
    // What the pass read serves the apply that follows it.
    let _ = coord.read_machine();
    assert_eq!(api.adapters(), 2);
}

#[test]
fn the_apply_after_a_pass_shares_one_reading_until_a_write_of_ours() {
    let api = CountingApi::new();
    let coord = counted_coordinator(&api);

    let _ = coord.read_machine();
    let _ = coord.read_machine();
    assert_eq!(api.tables(), 2, "no pass has run: every call reads");

    let _ = coord.recompute_active(&[]);
    let after_pass = api.tables();
    let _ = coord.read_machine();
    let _ = coord.read_machine();
    let _ = coord.read_machine();
    assert_eq!(api.tables(), after_pass + 1, "the apply's reads share one");

    let _ = coord.recompute_for("S-IVANOV", &res(None));
    let before = api.tables();
    let _ = coord.read_machine();
    assert_eq!(api.tables(), before + 1, "our own write dropped it");
}

#[test]
fn without_a_feed_every_reader_reads() {
    let api = CountingApi::new();
    let coord = counted_coordinator(&api);
    let _cache = coord.adapter_cache(NetChangeGeneration::new());
    let _ = coord.read_machine();
    let _ = coord.read_machine();
    assert_eq!(api.adapters(), 2);
}
