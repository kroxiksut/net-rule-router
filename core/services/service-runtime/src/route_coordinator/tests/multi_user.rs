//! Several signed-in users in the one machine table: the console user and a
//! remote one, tray or no tray.

use super::*;

const VASYA: &str = "S-1-5-21-1-2-3-1001";
const PETYA: &str = "S-1-5-21-1-2-3-1002";

fn sids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn host(d: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, d)
}

fn host_block(d: u8) -> nrr_shared::ip_block::IpBlock {
    nrr_shared::ip_block::IpBlock::new(IpAddr::V4(host(d)), 32).unwrap()
}

/// Two tunnels — Vasya's on interface 9, Petya's on 11 — and a coordinator
/// under service-driven scope, so signed-in users count with no tray.
struct Machine {
    api: Arc<MockWindowsApi>,
    rules: Arc<FakeRules>,
    policy: Arc<FakePolicy>,
    coord: SecondaryRouteCoordinator,
    vpn_a: String,
    vpn_b: String,
}

fn machine() -> Machine {
    let api = Arc::new(MockWindowsApi::new());
    let a = adapter("vpn-a", 9, true, true, Some([10, 0, 0, 1]));
    let b = adapter("vpn-b", 11, true, true, Some([10, 0, 1, 1]));
    let (vpn_a, vpn_b) = (a.stable_id(), b.stable_id());
    api.set_adapter_infos(vec![a, b]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    let coord = SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::clone(&policy) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| true) as RuleScopeProvider,
    )
    // Each test here moves who is signed in between passes on purpose.
    .with_departure_grace(std::time::Duration::ZERO);
    Machine {
        api,
        rules,
        policy,
        coord,
        vpn_a,
        vpn_b,
    }
}

impl Machine {
    fn user(&self, sid: &str, vpn: &str, hosts: &[u8]) {
        self.policy.bind_secondary(sid, vpn);
        self.rules.set_secondary(
            sid,
            CanonicalRuleSet::from_rules(
                hosts
                    .iter()
                    .map(|d| ip_rule(&format!("r-{sid}-{d}"), 198, 51, 100, *d))
                    .collect(),
            ),
        );
    }

    fn signed_in(&self, users: &[&str]) {
        self.api.set_interactive_user_sids(users);
    }

    /// The interface each of our routes to `host(d)` uses.
    fn links_to(&self, d: u8) -> Vec<u32> {
        let mut links: Vec<u32> = self
            .api
            .get_ip_forward_table()
            .unwrap()
            .iter()
            .filter(|r| r.destination == IpAddr::V4(host(d)) && r.prefix_length == 32)
            .map(|r| r.interface_index)
            .collect();
        links.sort_unstable();
        links
    }
}

#[test]
fn a_second_user_adds_their_routes_and_removes_nothing_of_the_first() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[2]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(m.links_to(1), vec![9]);

    m.signed_in(&[VASYA, PETYA]);
    let delta = m.coord.recompute_active(&[]).unwrap();
    assert_eq!(
        delta.removed, 0,
        "the first user's routes stay where they are"
    );
    assert_eq!(delta.added, 1);
    assert_eq!(m.links_to(1), vec![9]);
    assert_eq!(m.links_to(2), vec![11]);
}

#[test]
fn the_same_address_through_the_same_link_is_one_route() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_a, &[1]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();
    m.signed_in(&[VASYA, PETYA]);
    let delta = m.coord.recompute_active(&[]).unwrap();
    assert!(delta.is_noop(), "{delta:?}");
    assert_eq!(m.links_to(1), vec![9]);
    assert!(!m.coord.routed_for_another_user(PETYA, host_block(1)));
}

#[test]
fn a_contested_address_stays_with_the_user_served_longer() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[1, 2]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();

    // Petya is enumerated first (console order says nothing about who came
    // first): Vasya was served first and keeps the address.
    m.signed_in(&[PETYA, VASYA]);
    let delta = m.coord.recompute_active(&[]).unwrap();
    assert_eq!(delta.removed, 0);
    assert_eq!(m.links_to(1), vec![9], "never both links, never Petya's");
    assert_eq!(m.links_to(2), vec![11], "the newcomer's other routes go in");

    // The service accounts follow the table: Vasya's link carries .1.
    assert!(m.coord.routed_for_another_user(PETYA, host_block(1)));
    assert!(!m.coord.routed_for_another_user(VASYA, host_block(1)));
    assert!(!m.coord.routed_for_another_user(PETYA, host_block(2)));

    // Reported once: a repeat pass with the same conflict says nothing new.
    let conflict = crate::route_coordinator::merge::RouteConflict {
        sid: PETYA.to_string(),
        holder: VASYA.to_string(),
        destination: IpAddr::V4(host(1)),
        prefix_length: 32,
    };
    assert_eq!(m.coord.note_conflicts(std::slice::from_ref(&conflict)), 0);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(m.coord.reported_conflicts.lock().unwrap().len(), 1);
}

#[test]
fn when_the_longer_served_user_leaves_the_newcomer_gets_the_address() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[1, 2]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();
    m.signed_in(&[VASYA, PETYA]);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(m.links_to(1), vec![9]);

    m.signed_in(&[PETYA]);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(m.links_to(1), vec![11]);
    assert_eq!(m.links_to(2), vec![11]);
    assert!(m.coord.reported_conflicts.lock().unwrap().is_empty());
    assert!(!m.coord.routed_for_another_user(PETYA, host_block(1)));
}

#[test]
fn two_remote_users_with_no_tray_and_nobody_at_the_console_are_both_served() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[2]);
    m.signed_in(&[VASYA, PETYA]);
    assert_eq!(m.coord.served_sids(&[]), sids(&[VASYA, PETYA]));
    assert_eq!(m.coord.effective_routing_sid(&[]).as_deref(), Some(VASYA));
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(m.links_to(1), vec![9]);
    assert_eq!(m.links_to(2), vec![11]);
}

#[test]
fn a_tray_and_a_session_without_one_are_both_served() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[2]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();
    // Petya connects over RDP and his tray registers; Vasya never had one.
    m.signed_in(&[VASYA, PETYA]);
    let delta = m.coord.recompute_active(&sids(&[PETYA])).unwrap();
    assert_eq!(delta.removed, 0);
    assert_eq!(m.coord.served_sids(&sids(&[PETYA])), sids(&[VASYA, PETYA]));
    assert_eq!(m.links_to(1), vec![9]);
    assert_eq!(m.links_to(2), vec![11]);
}

#[test]
fn a_paused_newcomer_beside_another_user_contributes_nothing() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[2]);
    let coord = machine_with_pause(&m, PETYA, PausedRouteDisposition::ClearAll);
    m.signed_in(&[VASYA, PETYA]);
    coord.recompute_active(&[]).unwrap();
    assert_eq!(m.links_to(1), vec![9]);
    assert!(m.links_to(2).is_empty());
}

#[test]
fn nobody_signed_in_clears_every_users_routes() {
    let m = machine();
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[2]);
    m.signed_in(&[VASYA, PETYA]);
    m.coord.recompute_active(&[]).unwrap();
    m.signed_in(&[]);
    m.coord.recompute_active(&[]).unwrap();
    assert!(m.links_to(1).is_empty());
    assert!(m.links_to(2).is_empty());
    assert_eq!(m.coord.owned_count(), 0);
}

fn held_notices(
    bus: &crate::ipc_handlers::event_bus::EventBus,
    sub: &str,
) -> Vec<(String, u64, Vec<String>)> {
    bus.peek_pending_for(sub, 64)
        .into_iter()
        .filter_map(|e| match e.event {
            nrr_shared::ipc_payloads::StatusUpdateEvent::RoutesHeldByAnotherUser {
                sid,
                count,
                sample,
            } => Some((sid, count, sample)),
            _ => None,
        })
        .collect()
}

/// The newcomer is told, once per change and nobody else is; a client that
/// connects later reads the same from the snapshot; the end is news too.
#[test]
fn the_newcomer_alone_is_told_which_destinations_another_user_holds() {
    let bus = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
    let petya_sub = bus
        .subscribe_as("petya".into(), Some(PETYA.into()), None)
        .subscription_id;
    let vasya_sub = bus
        .subscribe_as("vasya".into(), Some(VASYA.into()), None)
        .subscription_id;
    let mut m = machine();
    m.coord = m.coord.with_event_bus(Arc::clone(&bus));
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[1, 2]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();
    m.signed_in(&[VASYA, PETYA]);
    m.coord.recompute_active(&[]).unwrap();
    m.coord.recompute_active(&[]).unwrap();

    assert_eq!(
        held_notices(&bus, &petya_sub),
        vec![(PETYA.to_string(), 1, vec!["198.51.100.1".to_string()])],
        "one notice for one change, however many passes"
    );
    assert!(
        held_notices(&bus, &vasya_sub).is_empty(),
        "the user who keeps the route is not told about the other one"
    );
    let standing = m.coord.enforcement_status();
    assert_eq!(
        standing.routes_held(PETYA).map(|h| h.count),
        Some(1),
        "the snapshot carries it for a client that connects later"
    );
    assert_eq!(standing.routes_held(VASYA), None);

    m.signed_in(&[PETYA]);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(
        held_notices(&bus, &petya_sub).last(),
        Some(&(PETYA.to_string(), 0, Vec::new())),
        "the end of the conflict clears the notice"
    );
    assert_eq!(standing.routes_held(PETYA), None);
}

/// One enumeration that misses the longer-served user must not hand their
/// destination to the newcomer and back.
#[test]
fn a_single_missed_enumeration_moves_no_route() {
    let mut m = machine();
    m.coord = m
        .coord
        .with_departure_grace(std::time::Duration::from_secs(60));
    m.user(VASYA, &m.vpn_a, &[1]);
    m.user(PETYA, &m.vpn_b, &[1, 2]);
    m.signed_in(&[VASYA]);
    m.coord.recompute_active(&[]).unwrap();
    m.signed_in(&[VASYA, PETYA]);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(m.links_to(1), vec![9]);

    m.signed_in(&[PETYA]);
    let delta = m.coord.recompute_active(&[]).unwrap();
    assert!(delta.is_noop(), "{delta:?}");
    assert_eq!(m.links_to(1), vec![9], "Vasya keeps the address");
    assert_eq!(m.coord.served_sids(&[]), sids(&[VASYA, PETYA]));

    m.signed_in(&[]);
    m.coord.recompute_active(&[]).unwrap();
    assert_eq!(
        m.links_to(2),
        vec![11],
        "an empty answer is a miss too, not a teardown"
    );
}

/// A second coordinator over `m`'s machine with `sid` paused.
fn machine_with_pause(
    m: &Machine,
    sid: &'static str,
    disposition: PausedRouteDisposition,
) -> SecondaryRouteCoordinator {
    SecondaryRouteCoordinator::new(
        Arc::clone(&m.api) as Arc<dyn RouteTablePort>,
        Arc::clone(&m.rules) as Arc<dyn RulesProvider>,
        Arc::clone(&m.policy) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| true) as RuleScopeProvider,
    )
    .with_pause_state(Arc::new(move |s: &str| {
        if s == sid {
            disposition
        } else {
            PausedRouteDisposition::Active
        }
    }))
}
