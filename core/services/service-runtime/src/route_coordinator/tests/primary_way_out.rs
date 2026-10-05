//! A main link must reach somewhere on its own facts.
//!
//! A host-only adapter bound as the main connection once carried our overlay
//! halves; counted as its routes, they vouched for it on every later pass and
//! every unrouted connection went into a dead end.

use super::*;
use crate::ipc_handlers::event_bus::EventBus;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

const SID: &str = "S-1-5-21-HOSTONLY";
const UPLINK: u32 = 2;
const HOST_ONLY: u32 = 3;
const TUNNEL: u32 = 12;

fn route(dest: [u8; 4], prefix: u8, next_hop: [u8; 4], ifindex: u32, ours: bool) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(dest)),
        prefix_length: prefix,
        next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
        interface_index: ifindex,
        metric: 5,
        is_ours: ours,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

/// The host-only link's own subnet plus the overlay we once put through it.
fn host_only_with_our_overlay() -> Vec<RouteEntry> {
    vec![
        route([192, 168, 56, 0], 24, [0, 0, 0, 0], HOST_ONLY, false),
        route([0, 0, 0, 0], 1, [0, 0, 0, 0], HOST_ONLY, true),
        route([128, 0, 0, 0], 1, [0, 0, 0, 0], HOST_ONLY, true),
    ]
}

#[test]
fn our_own_overlay_does_not_give_a_link_a_way_out() {
    let host_only = adapter("hostonly", HOST_ONLY, true, true, None);
    let routes = host_only_with_our_overlay();
    assert!(
        has_own_way_out(&host_only, &routes, |_| false),
        "positive control: counted, our halves cover the internet on that link"
    );
    assert!(!has_own_way_out(&host_only, &routes, |r| r.is_ours));
}

#[test]
fn a_gateway_less_pppoe_link_still_has_a_way_out() {
    let ppp = adapter("ppp0", UPLINK, true, true, None);
    let routes = vec![route([0, 0, 0, 0], 0, [0, 0, 0, 0], UPLINK, false)];
    assert!(has_own_way_out(&ppp, &routes, |r| r.is_ours));
}

#[test]
fn a_host_only_main_link_gives_way_to_the_os_default_and_says_so() {
    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![
        adapter("uplink", UPLINK, true, true, Some([10, 0, 2, 2])),
        adapter("hostonly", HOST_ONLY, true, true, None),
        adapter("tunnel", TUNNEL, true, true, None),
    ]);
    let mut routes = host_only_with_our_overlay();
    routes.push(route([0, 0, 0, 0], 0, [10, 0, 2, 2], UPLINK, false));
    routes.push(route([0, 0, 0, 0], 1, [10, 88, 0, 1], TUNNEL, false));
    routes.push(route([128, 0, 0, 0], 1, [10, 88, 0, 1], TUNNEL, false));
    api.set_route_table(routes);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary(SID, "win-adapter:hostonly");
    policy.bind_secondary(SID, "win-adapter:tunnel");
    let bus = Arc::new(EventBus::new());
    let sub = bus
        .subscribe_as("test".into(), Some(SID.into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_event_bus(Arc::clone(&bus));

    let resolution = coord.resolve(SID);
    let primary = resolution
        .primary
        .expect("derived from the OS default route");
    assert_eq!(primary.interface_index, UPLINK);
    assert_eq!(primary.gateway, Ipv4Addr::new(10, 0, 2, 2));
    assert_eq!(
        resolution.secondary.map(|t| t.interface_index),
        Some(TUNNEL)
    );

    let _ = coord.resolve(SID);
    let primary_statuses: Vec<String> = bus
        .peek_pending_for(&sub, 16)
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged { status, role, .. }
                if role == "primary" =>
            {
                Some(status.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        primary_statuses,
        vec!["primary-no-way-out".to_string()],
        "told once, however many passes run"
    );
}
