use super::*;
use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::windows_api::MockWindowsApi;
use std::net::Ipv4Addr;

#[test]
fn empty_adapter_list_yields_empty_wire_response() {
    let api = Arc::new(MockWindowsApi::new());
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>);
    let resp = provider.adapters_snapshot(false);
    assert!(resp.adapters.is_empty());
    // The spelling used to be hardcoded `windows-live`, which is also what
    // this assertion pinned. Which of the two the enumeration reaches is a
    // property of the HOST (a Windows box with adapters answers live, a
    // Linux one answers with the placeholder), so the assertion below is
    // the honesty invariant instead: the label has to be one the contract
    // defines, and it must round-trip.
    let source = nrr_platform_api::InterfacesDataSource::from_title(&resp.data_source);
    assert_eq!(source.title(), resp.data_source);
}

/// The placeholder dataset must never be announced as a live enumeration:
/// four invented adapters presented as this machine's own are what a user
/// binds a route to (§36.15.1).
#[test]
fn placeholder_rows_are_never_announced_as_live() {
    let api = Arc::new(MockWindowsApi::new());
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>);
    let resp = provider.adapters_snapshot(false);
    let placeholder_shipped = resp
        .rows
        .iter()
        .any(|row| row.adapter_name.starts_with("{FAKE-"));
    if placeholder_shipped {
        assert_eq!(
            resp.data_source,
            nrr_platform_api::InterfacesDataSource::FallbackMock.title(),
            "placeholder rows announced as a live enumeration",
        );
    }
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
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>);
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
        if row.windows_name == "Ethernet" {
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
fn fold_cached_external_persists_fresh_resolution_keyed_by_windows_name() {
    // The Ethernet entry's `adapter_name` ("{FAKE-ETHERNET-ADAPTER}", a
    // GUID) is deliberately distinct from `windows_name` ("Ethernet") —
    // proves the join key used is `windows_name`, matching the traffic
    // ledger's `Alias`-derived key, not the low-level identity GUID.
    let api = Arc::new(MockWindowsApi::new());
    let recorder = Arc::new(FakeAddressRecorder::new());
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

    let mut rows = rows_with_fresh_ethernet_probe();
    provider.fold_cached_external(&mut rows);

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
            "192.168.1.20".to_string(),
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
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

    // A snapshot with NO fresh probe — the common one, and the only kind
    // that reads the stored pair instead of overwriting it.
    let mut rows = rows_with_fresh_ethernet_probe();
    for row in &mut rows {
        row.observed_facts.external_ip = None;
    }
    provider.fold_cached_external(&mut rows);

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
        ("192.168.1.20".to_string(), Some("203.0.113.10".to_string())),
    );
    let api = Arc::new(MockWindowsApi::new());
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);
    let mut rows = rows_with_fresh_ethernet_probe();
    for row in &mut rows {
        row.observed_facts.external_ip = None;
    }
    provider.fold_cached_external(&mut rows);
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
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>)
        .with_address_recorder(Arc::clone(&recorder) as Arc<dyn AdapterAddressRecorder>);

    let mut first = rows_with_fresh_ethernet_probe();
    provider.fold_cached_external(&mut first);
    assert_eq!(recorder.calls.lock().expect("lock").len(), 1);

    let mut second = rows_with_fresh_ethernet_probe();
    for row in &mut second {
        row.observed_facts.external_ip = None;
    }
    provider.fold_cached_external(&mut second);
    assert_eq!(
        recorder.calls.lock().expect("lock").len(),
        1,
        "a replayed (cached) address must not be persisted again"
    );
}

#[test]
fn without_a_recorder_fold_cached_external_is_a_noop_for_persistence() {
    let api = Arc::new(MockWindowsApi::new());
    let provider = MonitoredAdaptersSnapshotProvider::new(api as Arc<dyn RouteTablePort>);
    let mut rows = nrr_platform_api::interface_rows::fallback_rows();
    // Must not panic without a recorder wired.
    provider.fold_cached_external(&mut rows);
}
