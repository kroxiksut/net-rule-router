use super::*;
use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::windows_api::MockWindowsApi;
use nrr_platform_api::{
    InterfaceRowsPort, InterfacesDataSource, MockInterfaceRows, PlaceholderInterfaceRows,
};
use std::net::Ipv4Addr;

fn provider_over(api: Arc<MockWindowsApi>) -> MonitoredAdaptersSnapshotProvider {
    MonitoredAdaptersSnapshotProvider::new(
        api as Arc<dyn RouteTablePort>,
        Arc::new(PlaceholderInterfaceRows) as Arc<dyn InterfaceRowsPort>,
    )
}

#[test]
fn empty_adapter_list_yields_empty_wire_response() {
    let provider = provider_over(Arc::new(MockWindowsApi::new()));
    let resp = provider.adapters_snapshot(false);
    assert!(resp.adapters.is_empty());
    let source = InterfacesDataSource::from_title(&resp.data_source);
    assert_eq!(source.title(), resp.data_source);
}

/// The placeholder dataset must never be announced as a live enumeration:
/// four invented adapters presented as this machine's own are what a user
/// binds a route to.
#[test]
fn placeholder_rows_are_never_announced_as_live() {
    let provider = provider_over(Arc::new(MockWindowsApi::new()));
    let resp = provider.adapters_snapshot(false);
    assert!(resp
        .rows
        .iter()
        .any(|row| row.adapter_name.starts_with("{FAKE-")));
    assert_eq!(
        resp.data_source,
        InterfacesDataSource::FallbackMock.title(),
        "placeholder rows announced as a live enumeration",
    );
}

/// Answers for every row the filter picks, without the network.
fn answering_probe(
    rows: &mut [nrr_platform_api::InterfaceRouteRow],
    wanted: &dyn Fn(&nrr_platform_api::InterfaceRouteRow) -> bool,
) {
    for row in rows.iter_mut() {
        if wanted(row) {
            row.observed_facts.external_ip = Some("198.51.100.77".to_owned());
        }
    }
}

fn external_of<'a>(resp: &'a SnapshotInterfacesResponse, id: &str) -> Option<&'a str> {
    resp.rows
        .iter()
        .find(|row| row.persistent_id == id)
        .and_then(|row| row.observed_facts.external_ip.as_deref())
}

/// The provenance on the wire is the enumeration's own; the probe runs in the
/// service, only when a user asked for it.
#[test]
fn snapshot_reports_the_enumerations_provenance_and_probes_only_on_request() {
    let rows = Arc::new(MockInterfaceRows::new(
        InterfacesDataSource::LinuxLive,
        nrr_platform_api::fallback_rows(),
    ));
    let provider = MonitoredAdaptersSnapshotProvider::new(
        Arc::new(MockWindowsApi::new()) as Arc<dyn RouteTablePort>,
        Arc::clone(&rows) as Arc<dyn InterfaceRowsPort>,
    )
    .with_external_probe(answering_probe);
    let plain = provider.adapters_snapshot(false);
    assert_eq!(plain.data_source, InterfacesDataSource::LinuxLive.title());
    assert!(plain
        .rows
        .iter()
        .all(|r| r.observed_facts.external_ip.is_none()));
    let probed = provider.adapters_snapshot_probing_external_ip();
    assert!(probed
        .rows
        .iter()
        .any(|r| r.observed_facts.external_ip.is_some()));
    assert_eq!(
        rows.probe_requests(),
        [false, false],
        "the port never probes"
    );
}

/// One user's check leaves only by the connections they bound, and what it
/// found is shown to them, not to another user.
#[test]
fn an_external_address_check_is_the_askers_own() {
    use nrr_platform_api::interface_rows::{
        PREVIEW_ETHERNET_PERSISTENT_ID, PREVIEW_VPN_PERSISTENT_ID,
    };
    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";
    let provider = MonitoredAdaptersSnapshotProvider::new(
        Arc::new(MockWindowsApi::new()) as Arc<dyn RouteTablePort>,
        Arc::new(MockInterfaceRows::new(
            InterfacesDataSource::LinuxLive,
            nrr_platform_api::fallback_rows(),
        )) as Arc<dyn InterfaceRowsPort>,
    )
    .with_external_probe(answering_probe)
    .with_caller_bindings(Arc::new(|sid: &str| match sid {
        ALICE => Some(vec![PREVIEW_ETHERNET_PERSISTENT_ID.to_owned()]),
        BOB => Some(vec![PREVIEW_VPN_PERSISTENT_ID.to_owned()]),
        _ => None,
    }));

    let checked = provider.adapters_snapshot_probing_external_ip_for(ALICE);
    assert_eq!(
        external_of(&checked, PREVIEW_ETHERNET_PERSISTENT_ID),
        Some("198.51.100.77")
    );
    assert_eq!(
        external_of(&checked, PREVIEW_VPN_PERSISTENT_ID),
        None,
        "another user's tunnel is not probed"
    );
    assert_eq!(
        external_of(
            &provider.adapters_snapshot_for(false, ALICE),
            PREVIEW_ETHERNET_PERSISTENT_ID
        ),
        Some("198.51.100.77"),
        "remembered for the one who checked"
    );
    assert_eq!(
        external_of(
            &provider.adapters_snapshot_for(false, BOB),
            PREVIEW_ETHERNET_PERSISTENT_ID
        ),
        None,
        "and not shown to anyone else"
    );
    let unknown = provider.adapters_snapshot_probing_external_ip_for("S-1-5-21-unreadable");
    assert!(
        unknown
            .rows
            .iter()
            .all(|r| r.observed_facts.external_ip.is_none()),
        "bindings that cannot be read probe nothing"
    );
}

/// A plain refresh shows what the service sends; unscored rows turned every
/// badge into "allowed, not recommended" the moment the user refreshed.
#[test]
fn snapshot_rows_arrive_scored() {
    let provider = provider_over(Arc::new(MockWindowsApi::new()));
    let resp = provider.adapters_snapshot(false);
    assert!(resp
        .rows
        .iter()
        .all(|row| !row.recommendation.key_signals.is_empty()));
    assert!(resp
        .rows
        .iter()
        .any(|row| row.recommendation.class == "preferred-primary"));
}

#[test]
fn projection_carries_mac_and_index() {
    use nrr_platform_api::adapters::AdapterInfo;
    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![AdapterInfo {
        index: 17,
        adapter_name: "{ABCD-EFGH}".into(),
        description: "Test Wi-Fi".into(),
        friendly_name: "Wi-Fi".into(),
        mac: Some([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]),
        interface_type: InterfaceType::Wireless,
        oper_status: IfOperStatus::Up,
        ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 5)],
        ipv6_addresses: Vec::new(),
        gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
    }]);
    let provider = provider_over(api);
    let resp = provider.adapters_snapshot(false);
    assert_eq!(resp.adapters.len(), 1);
    let entry = &resp.adapters[0];
    assert_eq!(entry.ipv6_if_index, 17);
    assert_eq!(entry.physical_address.as_deref(), Some("DE:AD:BE:EF:00:01"));
    assert_eq!(entry.persistent_id, "de:ad:be:ef:00:01");
    assert_eq!(entry.interface_description, "Test Wi-Fi");
}

// ── AdapterAddressRecorder wiring ─────────────────────────────────────────

struct FakeAddressRecorder {
    calls: Mutex<Vec<(String, String, String)>>,
    /// What the STORE holds: `adapter_key -> (local_ip, external_ip)`.
    /// Separate from `calls` because the guard reads the persisted pair,
    /// not the calls made to it.
    stored: Mutex<std::collections::HashMap<String, (String, Option<String>)>>,
    forgotten: Mutex<Vec<String>>,
}

impl FakeAddressRecorder {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            stored: Mutex::new(std::collections::HashMap::new()),
            forgotten: Mutex::new(Vec::new()),
        }
    }
}

impl AdapterAddressRecorder for FakeAddressRecorder {
    fn record(&self, adapter_key: &str, local_ip: &str, external_ip: &str, _ms: i64) {
        self.calls.lock().expect("lock").push((
            adapter_key.to_string(),
            local_ip.to_string(),
            external_ip.to_string(),
        ));
    }

    fn remembered_local_ip(&self, adapter_key: &str) -> Option<String> {
        let stored = self.stored.lock().expect("lock");
        stored.get(adapter_key).map(|pair| pair.0.clone())
    }

    fn forget_external(&self, adapter_key: &str, local_ip: &str, _ms: i64) {
        self.forgotten
            .lock()
            .expect("lock")
            .push(adapter_key.to_string());
        self.stored
            .lock()
            .expect("lock")
            .insert(adapter_key.to_string(), (local_ip.to_string(), None));
    }
}

/// A fresh probe result on the Ethernet row. The placeholder dataset no
/// longer ships one — it never ran a probe, and pretending otherwise is what
/// made the adapter panel print an invented address — so the test states the
/// precondition it is actually about.
fn rows_with_fresh_ethernet_probe() -> Vec<nrr_platform_api::interface_rows::InterfaceRouteRow> {
    let mut rows = nrr_platform_api::interface_rows::fallback_rows();
    for row in &mut rows {
        if row.name == "Ethernet" {
            nrr_platform_api::interface_rows::apply_external_probe(
                &mut row.observed_facts,
                nrr_platform_api::ExternalIpProbeOutcome::Resolved(std::net::Ipv4Addr::new(
                    203, 0, 113, 10,
                )),
            );
        }
    }
    rows
}

#[test]
fn fold_cached_external_persists_fresh_resolution_keyed_by_name() {
    // The Ethernet entry's `adapter_name` ("{FAKE-ETHERNET-ADAPTER}", a
    // GUID) is deliberately distinct from `name` ("Ethernet") —
    // proves the join key used is `name`, matching the traffic
    // ledger's `Alias`-derived key, not the low-level identity GUID.
    let api = Arc::new(MockWindowsApi::new());
    let recorder = Arc::new(FakeAddressRecorder::new());
    let provider = provider_over(api)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

    let mut rows = rows_with_fresh_ethernet_probe();
    provider.fold_cached_external(&mut rows, true);

    let calls = recorder.calls.lock().expect("lock");
    assert_eq!(
        calls.len(),
        1,
        "only the Ethernet row carries a fresh probe result"
    );
    assert_eq!(
        calls[0],
        (
            "Ethernet".to_string(),
            "192.0.2.20".to_string(),
            "203.0.113.10".to_string(),
        )
    );
}

/// The stored pair belongs to whatever adapter answered to this NAME last
/// time. A rename — or a reinstall that took the name back — leaves the
/// previous adapter's external address under it, and the traffic screen
/// prints that pair verbatim, with no freshness or identity check of its
/// own. So the moment a snapshot sees a different local address under a
/// remembered name, the external half has to go.
///
/// Compared against the STORE, not against the in-process cache: after a
/// service restart that cache is empty, and "restarted, and the adapter was
/// renamed meanwhile" is the likeliest way into this state.
#[test]
fn a_remembered_address_under_a_reused_name_is_forgotten_not_shown() {
    let api = Arc::new(MockWindowsApi::new());
    let recorder = Arc::new(FakeAddressRecorder::new());
    // Someone else's pair is already on disk under "Ethernet".
    recorder.stored.lock().expect("lock").insert(
        "Ethernet".to_string(),
        ("10.9.9.9".to_string(), Some("198.51.100.200".to_string())),
    );
    let provider = provider_over(api)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

    // A snapshot with NO fresh probe — the common one, and the only kind
    // that reads the stored pair instead of overwriting it.
    let mut rows = rows_with_fresh_ethernet_probe();
    for row in &mut rows {
        row.observed_facts.external_ip = None;
    }
    provider.fold_cached_external(&mut rows, true);

    assert_eq!(
        recorder.forgotten.lock().expect("lock").as_slice(),
        ["Ethernet".to_string()],
        "the stale external address must be dropped"
    );

    // Positive control: the same fold with a MATCHING stored local address
    // forgets nothing — the guard must not throw away a legitimate memory.
    let recorder = Arc::new(FakeAddressRecorder::new());
    recorder.stored.lock().expect("lock").insert(
        "Ethernet".to_string(),
        ("192.0.2.20".to_string(), Some("203.0.113.10".to_string())),
    );
    let api = Arc::new(MockWindowsApi::new());
    let provider = provider_over(api)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);
    let mut rows = rows_with_fresh_ethernet_probe();
    for row in &mut rows {
        row.observed_facts.external_ip = None;
    }
    provider.fold_cached_external(&mut rows, true);
    assert!(recorder.forgotten.lock().expect("lock").is_empty());
}

#[test]
fn fold_cached_external_does_not_persist_a_replayed_address() {
    // Second call: nothing in the fresh set has changed, so
    // `apply_external_ip_probes` was never re-run — simulate that by
    // clearing `external_ip` on a copy and folding again. The replay
    // path (carry-forward from `last_external`) must NOT call the
    // recorder — only a genuinely fresh resolution does.
    let api = Arc::new(MockWindowsApi::new());
    let recorder = Arc::new(FakeAddressRecorder::new());
    let provider = provider_over(api)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

    let mut first = rows_with_fresh_ethernet_probe();
    provider.fold_cached_external(&mut first, true);
    assert_eq!(recorder.calls.lock().expect("lock").len(), 1);

    let mut second = rows_with_fresh_ethernet_probe();
    for row in &mut second {
        row.observed_facts.external_ip = None;
    }
    provider.fold_cached_external(&mut second, true);
    assert_eq!(
        recorder.calls.lock().expect("lock").len(),
        1,
        "a replayed (cached) address must not be persisted again"
    );
}

#[test]
fn without_a_recorder_fold_cached_external_is_a_noop_for_persistence() {
    let api = Arc::new(MockWindowsApi::new());
    let provider = provider_over(api);
    let mut rows = nrr_platform_api::interface_rows::fallback_rows();
    // Must not panic without a recorder wired.
    provider.fold_cached_external(&mut rows, true);
}

fn ethernet_external(
    rows: &[nrr_platform_api::interface_rows::InterfaceRouteRow],
) -> Option<String> {
    rows.iter()
        .find(|row| row.name == "Ethernet")
        .and_then(|row| row.observed_facts.external_ip.clone())
}

fn without_fresh_probe(
    mut rows: Vec<nrr_platform_api::interface_rows::InterfaceRouteRow>,
) -> Vec<nrr_platform_api::interface_rows::InterfaceRouteRow> {
    for row in &mut rows {
        row.observed_facts.external_ip = None;
    }
    rows
}

/// The tunnel went down: the exit it had is not its exit any more, and on its
/// return it may leave by another one, so nothing is shown until it is
/// checked again.
#[test]
fn a_link_that_went_down_shows_no_remembered_external_address() {
    let provider = provider_over(Arc::new(MockWindowsApi::new()));
    let mut fresh = rows_with_fresh_ethernet_probe();
    provider.fold_cached_external(&mut fresh, true);

    let mut up = without_fresh_probe(rows_with_fresh_ethernet_probe());
    provider.fold_cached_external(&mut up, true);
    assert_eq!(
        ethernet_external(&up).as_deref(),
        Some("203.0.113.10"),
        "a link that stayed up keeps its address across snapshots"
    );

    let mut down = without_fresh_probe(rows_with_fresh_ethernet_probe());
    for row in &mut down {
        if row.name == "Ethernet" {
            row.availability_status = nrr_platform_api::BasicAvailabilityStatus::Unavailable;
        }
    }
    provider.fold_cached_external(&mut down, true);
    assert_eq!(ethernet_external(&down), None, "a down link has no exit");

    let mut back = without_fresh_probe(rows_with_fresh_ethernet_probe());
    provider.fold_cached_external(&mut back, true);
    assert_eq!(
        ethernet_external(&back),
        None,
        "back up, on the same local address: still unknown until checked"
    );
}

/// A tunnel whose adapter is removed while disconnected (WireGuard does this)
/// comes back with the same local address; the address it had must not.
#[test]
fn a_link_gone_from_a_live_enumeration_is_forgotten() {
    let provider = provider_over(Arc::new(MockWindowsApi::new()));
    let mut fresh = rows_with_fresh_ethernet_probe();
    provider.fold_cached_external(&mut fresh, true);

    let mut gone: Vec<_> = without_fresh_probe(rows_with_fresh_ethernet_probe())
        .into_iter()
        .filter(|row| row.name != "Ethernet")
        .collect();
    // A placeholder answer says nothing about which adapters exist.
    provider.fold_cached_external(&mut gone, false);
    let mut still = without_fresh_probe(rows_with_fresh_ethernet_probe());
    provider.fold_cached_external(&mut still, true);
    assert_eq!(ethernet_external(&still).as_deref(), Some("203.0.113.10"));

    provider.fold_cached_external(&mut gone, true);
    let mut back = without_fresh_probe(rows_with_fresh_ethernet_probe());
    provider.fold_cached_external(&mut back, true);
    assert_eq!(ethernet_external(&back), None);
}
