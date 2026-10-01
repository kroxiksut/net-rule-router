//! One compute reads the machine once, whatever it asks about it.

use super::*;
use crate::route_coordinator::{RuleScopeProvider, SecondaryRouteCoordinator};
use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::{PlatformError, RouteEntry};
use std::sync::atomic::{AtomicUsize, Ordering};

const SID: &str = "S-1-5-21-READS";
const PRIMARY: u32 = 12;
const TUNNEL: u32 = 78;
const FOREIGN: u32 = 40;

/// The mock machine, counting the two enumerations.
struct CountingPort {
    inner: Arc<MockWindowsApi>,
    routes: AtomicUsize,
    adapters: AtomicUsize,
}

impl CountingPort {
    fn counts(&self) -> (usize, usize) {
        (
            self.adapters.load(Ordering::SeqCst),
            self.routes.load(Ordering::SeqCst),
        )
    }
    fn reset(&self) {
        self.routes.store(0, Ordering::SeqCst);
        self.adapters.store(0, Ordering::SeqCst);
    }
}

impl RouteTablePort for CountingPort {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        self.routes.fetch_add(1, Ordering::SeqCst);
        RouteTablePort::get_ip_forward_table(self.inner.as_ref())
    }
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        RouteTablePort::create_ip_forward_entry(self.inner.as_ref(), entry)
    }
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        RouteTablePort::delete_ip_forward_entry(self.inner.as_ref(), entry)
    }
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        self.adapters.fetch_add(1, Ordering::SeqCst);
        RouteTablePort::get_adapter_infos(self.inner.as_ref())
    }
    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
        RouteTablePort::interface_luid_for_index(self.inner.as_ref(), ifindex)
    }
}

fn link(name: &str, index: u32, description: &str, gateway: Option<Ipv4Addr>) -> AdapterInfo {
    AdapterInfo {
        index,
        adapter_name: name.into(),
        description: description.into(),
        friendly_name: description.into(),
        mac: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: IfOperStatus::Up,
        ipv4_addresses: vec![Ipv4Addr::new(192, 0, 2, index as u8)],
        ipv6_addresses: Vec::new(),
        gateways: gateway.into_iter().collect(),
    }
}

fn route(dest: [u8; 4], prefix: u8, next_hop: [u8; 4], ifindex: u32) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(dest)),
        prefix_length: prefix,
        next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
        interface_index: ifindex,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

/// A main link, our gateway-less tunnel (its next hop has to be derived from
/// the table) and somebody else's tunnel: every resolver has work to do.
fn counting_machine() -> Arc<CountingPort> {
    let inner = Arc::new(MockWindowsApi::new());
    inner.set_adapter_infos(vec![
        link(
            "wifi",
            PRIMARY,
            "Wireless",
            Some(Ipv4Addr::new(192, 0, 2, 1)),
        ),
        link("tap", TUNNEL, "Wintun Userspace Tunnel", None),
        link("wg", FOREIGN, "WireGuard Tunnel", None),
    ]);
    inner.set_route_table(vec![
        route([0, 0, 0, 0], 0, [192, 0, 2, 1], PRIMARY),
        route([192, 0, 2, 0], 24, [0, 0, 0, 0], PRIMARY),
        route([203, 0, 113, 7], 32, [192, 0, 2, 1], PRIMARY),
        route([0, 0, 0, 0], 1, [10, 91, 192, 1], TUNNEL),
        route([128, 0, 0, 0], 1, [10, 91, 192, 1], TUNNEL),
    ]);
    Arc::new(CountingPort {
        inner,
        routes: AtomicUsize::new(0),
        adapters: AtomicUsize::new(0),
    })
}

/// The orchestrator as the service wires it. `shared` hands the resolvers the
/// compute's reading; otherwise each reads the machine for itself.
fn orchestrator(
    port: &Arc<CountingPort>,
    source: &Arc<ScriptedSource>,
    rules: &Arc<ScriptedRules>,
    shared: bool,
) -> PerSidApplyOrchestrator {
    let coord = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(port) as Arc<dyn RouteTablePort>,
        Arc::clone(rules) as Arc<dyn RulesProvider>,
        Arc::clone(source) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    ));
    let wfp = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(wfp as Arc<dyn WindowsApiPort>).unwrap());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(source) as Arc<dyn RoutePolicySource>,
        Arc::clone(rules) as Arc<dyn RulesProvider>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    );
    let (ks, v6, fc) = (Arc::clone(&coord), Arc::clone(&coord), Arc::clone(&coord));
    if shared {
        orch.with_machine_reader(Arc::new(move || coord.read_machine()))
            .with_kill_switch_resolver(Arc::new(move |sid, m| ks.kill_switch_exemptions(sid, m)))
            .with_ipv6_guard_resolver(Arc::new(move |sid, m| v6.ipv6_guard(sid, m)))
            .with_fail_closed_exemptions_resolver(Arc::new(move |sid, m| {
                fc.fail_closed_exemptions(sid, m)
            }))
    } else {
        orch.with_kill_switch_resolver(Arc::new(move |sid, _| {
            ks.kill_switch_exemptions(sid, &ks.read_machine())
        }))
        .with_ipv6_guard_resolver(Arc::new(move |sid, _| {
            v6.ipv6_guard(sid, &v6.read_machine())
        }))
        .with_fail_closed_exemptions_resolver(Arc::new(move |sid, _| {
            fc.fail_closed_exemptions(sid, &fc.read_machine())
        }))
    }
}

fn filter_ids(orch: &PerSidApplyOrchestrator) -> Vec<u64> {
    let ComputedFilterSet::Install(plan) = orch
        .compute_filters_for_sid(SID, false, None, ComputeIntent::Preview)
        .expect("compute")
    else {
        panic!("the fixture has a policy and rules");
    };
    let mut ids: Vec<u64> = plan.filters.iter().map(|f| f.id.raw).collect();
    ids.sort_unstable();
    ids
}

#[test]
fn one_compute_enumerates_the_adapters_and_reads_the_route_table_once() {
    let port = counting_machine();
    let source = Arc::new(ScriptedSource::default());
    let mut policy = snap_full("wifi", "tap");
    // Strict with the guard armed asks the kill-switch resolver three times.
    policy.mode = PerSidBehaviorMode::StrictSecondaryFailClosed;
    source.set(SID, policy);
    let rules = Arc::new(ScriptedRules::default());
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 9)));

    let each_reads_its_own = orchestrator(&port, &source, &rules, false);
    port.reset();
    let expected = filter_ids(&each_reads_its_own);
    let (adapters, routes) = port.counts();
    assert!(
        adapters > 1 && routes > 1,
        "the fixture must make the resolvers read more than once apiece ({adapters}, {routes})"
    );

    let shared = orchestrator(&port, &source, &rules, true);
    port.reset();
    let got = filter_ids(&shared);
    assert_eq!(
        port.counts(),
        (1, 1),
        "one adapter enumeration, one table read"
    );
    assert_eq!(got, expected, "sharing the reading changes no filter");
    assert!(!got.is_empty());
}
