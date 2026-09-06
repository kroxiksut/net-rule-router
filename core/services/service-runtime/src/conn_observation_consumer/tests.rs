//! Unit tests for [`super`] — ConnectionObservationConsumer.
//!
//! 1000 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

use super::*;
// `block_reason_for` moved to `super::connection_facts`; the parent no longer
// imports the type its verdicts are made of.
use nrr_domain::block_notice::BlockReason;
use nrr_platform_api::conn_observe::TransportProtocol;
use std::net::{Ipv4Addr, SocketAddrV4};

const ETHERNET: u32 = 16;
const VPN: u32 = 20;

fn v4(ip: Ipv4Addr) -> IpAddr {
    IpAddr::V4(ip)
}

fn obs(local: Ipv4Addr, remote: Ipv4Addr) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: Some(r"\device\harddiskvolume2\chrome.exe".to_string()),
        user_sid: None,
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::V4(SocketAddrV4::new(local, 50000)),
        remote: SocketAddr::V4(SocketAddrV4::new(remote, 443)),
        verdict: ConnectionVerdict::Permit,
        drop_filter_id: None,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

// ── App-pin collateral detection ────────────────────────────────────────

/// The rule book routes this one application over the additional link.
fn routed() -> Vec<String> {
    vec!["assistant.exe".to_string()]
}

fn pinned_store() -> AppObservationStore {
    let store = AppObservationStore::new();
    store.record("assistant.exe", Ipv4Addr::new(178, 248, 237, 68));
    store
}

fn owners_for(
    store: &AppObservationStore,
    this_app: &str,
    routed_apps: &[String],
    role: EgressRole,
    ip: Ipv4Addr,
) -> Vec<String> {
    collateral_pin_owners(store, this_app, "nrr-service.exe", routed_apps, role, ip)
}

#[test]
fn a_foreign_process_on_the_tunnel_names_the_pin_that_moved_it() {
    let owners = owners_for(
        &pinned_store(),
        "chrome.exe",
        &routed(),
        EgressRole::Secondary,
        Ipv4Addr::new(178, 248, 237, 68),
    );
    assert_eq!(owners, vec!["assistant".to_string()]);
}

/// Regression from a live run: the store holds an entry for EVERY process,
/// so `chrome.exe` — which no rule names — was reported as the owner of a
/// pin it never had, and the log claimed a rule had pinned the address.
#[test]
fn a_process_no_rule_names_never_owns_a_pin() {
    let store = AppObservationStore::new();
    store.record("chrome.exe", Ipv4Addr::new(209, 85, 233, 188));
    let owners = owners_for(
        &store,
        "assistant.exe",
        &routed(),
        EgressRole::Secondary,
        Ipv4Addr::new(209, 85, 233, 188),
    );
    assert!(owners.is_empty(), "{owners:?}");
}

/// The same run also withdrew from `claude.exe.old.<stamp>` — an updater's
/// leftover, with the real application as the supposed intruder.
#[test]
fn an_updaters_leftover_binary_is_not_an_owner() {
    let store = AppObservationStore::new();
    store.record(
        "assistant.exe.old.1787377508929",
        Ipv4Addr::new(34, 149, 66, 165),
    );
    let owners = owners_for(
        &store,
        "assistant.exe",
        &routed(),
        EgressRole::Secondary,
        Ipv4Addr::new(34, 149, 66, 165),
    );
    assert!(owners.is_empty(), "{owners:?}");
}

#[test]
fn one_routed_application_is_not_an_intruder_on_another() {
    // Both want the tunnel and the route serves them identically.
    let store = AppObservationStore::new();
    store.record("assistant.exe", Ipv4Addr::new(178, 248, 237, 68));
    let both = vec!["assistant.exe".to_string(), "helper.exe".to_string()];
    let owners = owners_for(
        &store,
        "helper.exe",
        &both,
        EgressRole::Secondary,
        Ipv4Addr::new(178, 248, 237, 68),
    );
    assert!(owners.is_empty(), "{owners:?}");
}

#[test]
fn a_glob_rule_covers_the_processes_it_names() {
    let store = AppObservationStore::new();
    store.record("codex-helper.exe", Ipv4Addr::new(178, 248, 237, 68));
    let routed = vec!["codex*.exe".to_string()];
    // Owner matches the glob → a real pin, and chrome is a real intruder.
    assert_eq!(
        owners_for(
            &store,
            "chrome.exe",
            &routed,
            EgressRole::Secondary,
            Ipv4Addr::new(178, 248, 237, 68)
        ),
        vec!["codex-helper".to_string()]
    );
}

#[test]
fn the_owning_application_using_its_own_pin_is_not_collateral() {
    let owners = owners_for(
        &pinned_store(),
        "assistant.exe",
        &routed(),
        EgressRole::Secondary,
        Ipv4Addr::new(178, 248, 237, 68),
    );
    assert!(owners.is_empty());
}

#[test]
fn the_relays_own_dials_are_never_collateral() {
    // The service connects to an application's destinations over the tunnel
    // on its behalf; mistaking that for an intruder would withdraw every
    // pin the moment it started working.
    let owners = owners_for(
        &pinned_store(),
        "nrr-service.exe",
        &routed(),
        EgressRole::Secondary,
        Ipv4Addr::new(178, 248, 237, 68),
    );
    assert!(owners.is_empty());
}

#[test]
fn the_same_flow_over_the_main_link_proves_nothing() {
    // No pin is in effect there, so there is nothing to withdraw.
    for role in [EgressRole::Primary, EgressRole::Unknown, EgressRole::Other] {
        let owners = owners_for(
            &pinned_store(),
            "chrome.exe",
            &routed(),
            role,
            Ipv4Addr::new(178, 248, 237, 68),
        );
        assert!(owners.is_empty(), "{role:?}");
    }
}

#[test]
fn an_address_no_application_rule_pinned_is_left_alone() {
    let owners = owners_for(
        &pinned_store(),
        "chrome.exe",
        &routed(),
        EgressRole::Secondary,
        Ipv4Addr::new(93, 184, 216, 34),
    );
    assert!(owners.is_empty());
}

#[test]
fn without_a_rule_book_the_check_stays_silent() {
    // `None` provider → empty slice → no withdrawal is ever proposed.
    let owners = owners_for(
        &pinned_store(),
        "chrome.exe",
        &[],
        EgressRole::Secondary,
        Ipv4Addr::new(178, 248, 237, 68),
    );
    assert!(owners.is_empty());
}

// ── Reactive VPN self-learning: consume()-level gate tests ──────────────

/// `RoutePolicySource` that never resolves a policy — sufficient here
/// because [`test_consumer`] wires an `active_sid` closure that always
/// returns `None`, so `consume()` never reaches the coordinator at all.
struct NoopPolicySource;
impl crate::per_sid_orchestrator::RoutePolicySource for NoopPolicySource {
    fn load_for_sid(
        &self,
        _sid: &str,
    ) -> Option<crate::per_sid_orchestrator::PerSidPolicySnapshot> {
        None
    }
}

/// One observed connection matching every VPN-learn precondition except
/// role-verification: a Block verdict attributed to us, from a process
/// matching the built-in VPN-client glob, to a public routable V4 remote.
/// `spec_id` is the caller-controlled variable under test.
fn vpn_drop_obs(spec_id: Option<u64>) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: Some(r"C:\Program Files\OpenVPN\bin\openvpn.exe".to_string()),
        user_sid: None,
        protocol: TransportProtocol::Udp,
        local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
        remote: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 50), 1194)),
        verdict: ConnectionVerdict::Block,
        drop_filter_id: Some(80122),
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: spec_id,
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

/// Build a consumer wired with a VPN-endpoint learner that records into
/// the returned sink, and (when `check` is `Some`) the role-verification
/// gate backed by that closure. `active_sid` always returns `None`, so
/// `consume()` never needs a live route coordinator — the field is only
/// present to satisfy the constructor.
fn test_consumer(
    check: Option<KillswitchDropCheckFn>,
) -> (
    ConnectionObservationConsumer,
    Arc<Mutex<Vec<std::net::Ipv4Addr>>>,
) {
    let api: Arc<dyn nrr_platform_api::route_table::RouteTablePort> =
        Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
    let coordinator = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(&api),
        Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
            as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
        Arc::new(NoopPolicySource) as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
        Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
            as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        Arc::new(|| false),
    ));
    let active_sid: ActiveSidFn = Arc::new(|| None);
    let learned: Arc<Mutex<Vec<std::net::Ipv4Addr>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&learned);
    // The gate is no longer optional here: the builder takes it with the
    // learner, so "learner wired, gate missing" is not a state a caller can
    // reach. A gate that refuses every id is the reachable equivalent.
    let consumer = ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
        .with_vpn_endpoint_learner(
            Arc::new(move |ip| {
                sink.lock().unwrap_or_else(|p| p.into_inner()).push(ip);
            }),
            check.unwrap_or_else(|| Arc::new(|_| false)),
        );
    (consumer, learned)
}

#[test]
fn vpn_learn_fires_when_spec_id_is_role_verified() {
    let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
    let (consumer, learned) = test_consumer(Some(check));
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.vpn_endpoints_learned, 1);
    assert_eq!(
        *learned.lock().unwrap_or_else(|p| p.into_inner()),
        vec![Ipv4Addr::new(203, 0, 113, 50)]
    );
}

#[test]
fn vpn_learn_skips_when_spec_id_unknown_to_registry() {
    // Simulates a foreign drop or the user's own Block rule: a spec id
    // exists (so `blocked_by_nrr` alone would have taught it under the
    // pre-fix logic) but the role-verification check rejects it.
    let check: KillswitchDropCheckFn = Arc::new(|_id| false);
    let (consumer, learned) = test_consumer(Some(check));
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.vpn_endpoints_learned, 0);
    assert!(learned.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

#[test]
fn vpn_learn_skips_when_spec_id_absent() {
    // The observation carries no decoded spec id at all (undecodable or
    // pre-dating the encoding) even though the check would accept
    // anything — absence of a spec id must never be treated as verified.
    let check: KillswitchDropCheckFn = Arc::new(|_id| true);
    let (consumer, learned) = test_consumer(Some(check));
    let summary = consumer.consume(&[vpn_drop_obs(None)], SystemTime::now());
    assert_eq!(summary.vpn_endpoints_learned, 0);
    assert!(learned.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

#[test]
fn vpn_learn_skips_when_the_gate_refuses_the_id() {
    // A matching VPN process name + a spec id present is not sufficient: the
    // role-verification gate decides. This used to pin "no gate wired at all",
    // which the builder no longer lets a caller express — the learner takes its
    // gate with it. A gate that refuses is what remains reachable, and it is
    // the shape production actually hits (a drop by someone else's filter).
    let (consumer, learned) = test_consumer(None);
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.vpn_endpoints_learned, 0);
    assert!(learned.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

// ── Proactive VPN-client (app-scoped) learning ─────────────

/// Wire the client-app learner on top of [`test_consumer`], recording
/// every observed path into the returned sink. The sink reports "new"
/// exactly once per distinct path (mirroring the production registry).
fn with_app_learner(
    consumer: ConnectionObservationConsumer,
) -> (ConnectionObservationConsumer, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let consumer = consumer.with_vpn_client_app_learner(Arc::new(move |path: &str| {
        let mut g = sink.lock().unwrap_or_else(|p| p.into_inner());
        let new = !g.iter().any(|p| p.eq_ignore_ascii_case(path));
        g.push(path.to_string());
        new
    }));
    (consumer, seen)
}

#[test]
fn vpn_client_app_learner_fires_on_role_verified_drop() {
    let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
    let (consumer, _) = test_consumer(Some(check));
    let (consumer, apps) = with_app_learner(consumer);
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.vpn_client_apps_learned, 1);
    assert_eq!(
        *apps.lock().unwrap_or_else(|p| p.into_inner()),
        vec![r"C:\Program Files\OpenVPN\bin\openvpn.exe".to_string()]
    );
}

#[test]
fn vpn_client_app_learner_skips_unverified_drops() {
    // Same drop, but the spec id fails role verification (a user's own
    // Block rule / foreign filter): the client app must NOT be learned.
    let check: KillswitchDropCheckFn = Arc::new(|_id| false);
    let (consumer, _) = test_consumer(Some(check));
    let (consumer, apps) = with_app_learner(consumer);
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.vpn_client_apps_learned, 0);
    assert!(apps.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

#[test]
fn vpn_client_app_learner_dedups_within_a_batch_across_rotated_ips() {
    // The exact field failure mode: one client process dropped against
    // several ROTATING remote IPs in one batch — the app sink is invoked
    // once and the summary counts one newly-learned client.
    let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
    let (consumer, _) = test_consumer(Some(check));
    let (consumer, apps) = with_app_learner(consumer);
    let mut second = vpn_drop_obs(Some(80122));
    second.remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 51), 443));
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122)), second], SystemTime::now());
    assert_eq!(summary.vpn_client_apps_learned, 1);
    assert_eq!(
        apps.lock().unwrap_or_else(|p| p.into_inner()).len(),
        1,
        "one sink call per process path per batch"
    );
}

// ── kill-switch drops while the secondary is USABLE ────────

/// `RoutePolicySource` binding every SID's secondary to one fixed stable
/// id — enough for the coordinator to resolve a live secondary against
/// the mock adapter table.
struct OneSecondaryPolicy {
    stable_id: String,
}
impl crate::per_sid_orchestrator::RoutePolicySource for OneSecondaryPolicy {
    fn load_for_sid(
        &self,
        _sid: &str,
    ) -> Option<crate::per_sid_orchestrator::PerSidPolicySnapshot> {
        use crate::per_sid_orchestrator::{PerSidBinding, PerSidPolicySnapshot};
        Some(PerSidPolicySnapshot {
            primary: None,
            secondary: Some(PerSidBinding {
                stable_id: self.stable_id.clone(),
                display_name: String::new(),
                user_confirmed: true,
                known_stable_ids: Vec::new(),
            }),
            mode: crate::per_sid_orchestrator::PerSidBehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: true,
            allow_dns_over_primary: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            kill_switch_strict_shared_ips: true,
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
            link_provider_exe_paths: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            doh_resolver_ips: Vec::new(),
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            block_ipv6_when_protected: true,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
        })
    }
}

/// Consumer whose coordinator RESOLVES a live secondary (Up adapter with
/// a gateway, ifindex [`VPN`]) for the active SID, with the
/// role-verification check accepting spec id 80122.
fn test_consumer_with_live_secondary() -> ConnectionObservationConsumer {
    let mock = nrr_platform_api::windows_api::MockWindowsApi::new();
    let vpn = AdapterInfo {
        index: VPN,
        adapter_name: "{vpn-live}".into(),
        description: "hidemy.name VPN 3.0 OpenVPN Adapter".into(),
        friendly_name: "hidemy.name VPN".into(),
        mac: None,
        interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
        oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
        ipv4_addresses: vec![Ipv4Addr::new(10, 88, 1, 41)],
        gateways: vec![Ipv4Addr::new(10, 88, 0, 1)],
    };
    let stable_id = vpn.stable_id();
    mock.set_adapter_infos(vec![vpn]);
    let api: Arc<dyn nrr_platform_api::route_table::RouteTablePort> = Arc::new(mock);
    let coordinator = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(&api),
        Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
            as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
        Arc::new(OneSecondaryPolicy { stable_id })
            as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
        Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
            as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        Arc::new(|| false),
    ));
    let active_sid: ActiveSidFn = Arc::new(|| Some("S-1-5-21-TEST".to_string()));
    ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
        .with_killswitch_drop_check(Arc::new(|id| id == 80122))
}

#[test]
fn killswitch_drop_with_live_secondary_is_counted() {
    // The scope-bug detector: a role-verified kill-switch drop while the
    // coordinator resolves a usable secondary must be counted — this
    // combination should be impossible when the blocking scope is right.
    let consumer = test_consumer_with_live_secondary();
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.killswitch_drops_live_secondary, 1);
}

#[test]
fn user_block_rule_drop_is_not_counted_even_with_live_secondary() {
    // A spec id that fails role verification is the user's own Block rule
    // (or another non-kill-switch filter) — legitimate with a live
    // secondary, so it must not feed the scope-bug counter.
    let consumer = test_consumer_with_live_secondary();
    let summary = consumer.consume(&[vpn_drop_obs(Some(999))], SystemTime::now());
    assert_eq!(summary.killswitch_drops_live_secondary, 0);
    assert_eq!(summary.blocked_nrr, 1, "the drop itself is still counted");
}

#[test]
fn app_scoped_killswitch_drop_is_split_out_of_the_scope_bug_count() {
    // An app pin covers every destination its process talks
    // to, including addresses routing has never seen, so its first-contact
    // drop is expected. It must land in the app-scope bucket and leave the
    // actionable destination-scoped remainder at zero.
    let consumer = test_consumer_with_live_secondary()
        .with_killswitch_app_scope_check(Arc::new(|id| id == 80122));
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.killswitch_drops_live_secondary, 1);
    assert_eq!(summary.killswitch_drops_live_secondary_app_scope, 1);
    assert_eq!(summary.killswitch_drops_live_secondary_dest_scope(), 0);
}

#[test]
fn destination_scoped_killswitch_drop_stays_in_the_scope_bug_count() {
    // The same drop, from a filter the registry does NOT classify as
    // app-scoped, is the actionable kind: a destination pin fired while
    // the link that was supposed to carry that destination is usable.
    let consumer =
        test_consumer_with_live_secondary().with_killswitch_app_scope_check(Arc::new(|_| false));
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.killswitch_drops_live_secondary, 1);
    assert_eq!(summary.killswitch_drops_live_secondary_app_scope, 0);
    assert_eq!(summary.killswitch_drops_live_secondary_dest_scope(), 1);
}

#[test]
fn without_a_scope_classifier_every_drop_reads_as_destination_scoped() {
    // Conservative default: an unwired classifier must over-report the
    // actionable half rather than silently swallow it.
    let consumer = test_consumer_with_live_secondary();
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.killswitch_drops_live_secondary_app_scope, 0);
    assert_eq!(summary.killswitch_drops_live_secondary_dest_scope(), 1);
}

#[test]
fn destination_scoped_drop_with_live_secondary_tears_the_stale_flow_down() {
    // One /32 sweep per victim address, however often it is re-observed.
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let consumer = test_consumer_with_live_secondary()
        .with_killswitch_app_scope_check(Arc::new(|_| false))
        .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

    // The same stalled flow observed twice in one batch sweeps once.
    consumer.consume(
        &[vpn_drop_obs(Some(80122)), vpn_drop_obs(Some(80122))],
        SystemTime::now(),
    );

    assert_eq!(reset.calls(), vec![(Ipv4Addr::new(203, 0, 113, 50), 32)]);
}

#[test]
fn app_scoped_drop_with_live_secondary_is_not_torn_down() {
    // First contact on an address routing has never seen — no older socket
    // to free, so nothing is swept.
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let consumer = test_consumer_with_live_secondary()
        .with_killswitch_app_scope_check(Arc::new(|id| id == 80122))
        .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

    consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());

    assert!(reset.calls().is_empty());
}

#[test]
fn a_drop_with_an_unresolved_secondary_is_never_torn_down() {
    // The outage case: nowhere better for those sockets to go.
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
    let (consumer, _) = test_consumer(Some(check));
    let consumer = consumer.with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

    consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());

    assert!(reset.calls().is_empty());
}

#[test]
fn killswitch_drop_with_unresolved_secondary_is_not_counted() {
    // No active SID → no resolved secondary → the drop is the block-all
    // doing exactly its job during an outage window.
    let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
    let (consumer, _) = test_consumer(Some(check));
    let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
    assert_eq!(summary.killswitch_drops_live_secondary, 0);
}

// ── reactive VPN self-learning helpers ─────────

#[test]
fn vpn_name_match_accepts_vpn_clients_rejects_others() {
    // NT device paths (what a WFP app-id decodes to) — match on the basename.
    assert!(process_name_matches_vpn(Some(
        r"\device\harddiskvolume2\program files\openvpn\bin\openvpn.exe"
    )));
    assert!(process_name_matches_vpn(Some(
        r"\device\harddiskvolume3\hidemy.name\hidemy.name.exe"
    )));
    assert!(process_name_matches_vpn(Some(
        r"C:\Program Files\WireGuard\wireguard.exe"
    ))); // DOS path + forward/back mix
         // Non-VPN processes never match.
    assert!(!process_name_matches_vpn(Some(
        r"\device\harddiskvolume2\chrome.exe"
    )));
    assert!(!process_name_matches_vpn(Some(r"\device\...\svchost.exe")));
    // Absent / empty never matches.
    assert!(!process_name_matches_vpn(None));
    assert!(!process_name_matches_vpn(Some("")));
    assert!(!process_name_matches_vpn(Some(r"C:\dir\")));
}

#[test]
fn learnable_endpoint_filters_non_routable_keeps_public_and_private() {
    // Public and private (corp-VPN) servers are learnable.
    assert!(is_learnable_endpoint(Ipv4Addr::new(203, 0, 113, 7)));
    assert!(is_learnable_endpoint(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(is_learnable_endpoint(Ipv4Addr::new(192, 168, 1, 1)));
    // Loopback / link-local / unspecified / broadcast are not.
    assert!(!is_learnable_endpoint(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(!is_learnable_endpoint(Ipv4Addr::new(169, 254, 1, 1)));
    assert!(!is_learnable_endpoint(Ipv4Addr::UNSPECIFIED));
    assert!(!is_learnable_endpoint(Ipv4Addr::BROADCAST));
    // L2 review-fix — 0.0.0.0/8, multicast 224/4, CGNAT 100.64/10 rejected.
    assert!(!is_learnable_endpoint(Ipv4Addr::new(0, 1, 2, 3)));
    assert!(!is_learnable_endpoint(Ipv4Addr::new(224, 0, 0, 1)));
    assert!(!is_learnable_endpoint(Ipv4Addr::new(239, 255, 255, 250)));
    assert!(!is_learnable_endpoint(Ipv4Addr::new(100, 64, 0, 1)));
    assert!(!is_learnable_endpoint(Ipv4Addr::new(100, 127, 255, 254)));
    // 100.128/9 is NOT CGNAT — public, still learnable.
    assert!(is_learnable_endpoint(Ipv4Addr::new(100, 128, 0, 1)));
    // The fake-IP pool terminates at our own TUN — never a learnable
    // endpoint, and just outside it the rule does not over-reach.
    assert!(!is_learnable_endpoint(Ipv4Addr::new(198, 18, 0, 35)));
    assert!(!is_learnable_endpoint(Ipv4Addr::new(198, 19, 255, 254)));
    assert!(is_learnable_endpoint(Ipv4Addr::new(198, 20, 0, 1)));
}

#[test]
fn build_unicast_table_flattens_adapter_addresses() {
    let infos = vec![AdapterInfo {
        index: ETHERNET,
        adapter_name: "{eth}".into(),
        description: "Ethernet".into(),
        friendly_name: "Ethernet".into(),
        mac: None,
        interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
        oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
        ipv4_addresses: vec![
            Ipv4Addr::new(192, 168, 0, 50),
            Ipv4Addr::new(192, 168, 0, 51),
        ],
        gateways: vec![Ipv4Addr::new(192, 168, 0, 1)],
    }];
    let table = build_unicast_table(&infos);
    assert_eq!(table.len(), 2);
    assert!(table.contains(&(v4(Ipv4Addr::new(192, 168, 0, 50)), ETHERNET)));
}

#[test]
fn classify_labels_vpn_source_as_secondary() {
    let unicast = vec![(v4(Ipv4Addr::new(10, 8, 0, 6)), VPN)];
    let rec = classify_connection(
        &obs(Ipv4Addr::new(10, 8, 0, 6), Ipv4Addr::new(188, 40, 167, 82)),
        &unicast,
        Some(ETHERNET),
        Some(VPN),
    );
    assert_eq!(rec.egress.role, EgressRole::Secondary);
    assert_eq!(rec.egress.ifindex, VPN);
    assert_eq!(rec.remote.ip(), IpAddr::V4(Ipv4Addr::new(188, 40, 167, 82)));
}

#[test]
fn classify_labels_lan_source_as_primary() {
    let unicast = vec![(v4(Ipv4Addr::new(192, 168, 0, 50)), ETHERNET)];
    let rec = classify_connection(
        &obs(
            Ipv4Addr::new(192, 168, 0, 50),
            Ipv4Addr::new(93, 184, 216, 34),
        ),
        &unicast,
        Some(ETHERNET),
        Some(VPN),
    );
    assert_eq!(rec.egress.role, EgressRole::Primary);
}

#[test]
fn trace_ring_caps_and_snapshots_newest_first() {
    let ring = ConnectionTraceRing::new(2);
    let unicast = vec![(v4(Ipv4Addr::new(192, 168, 0, 50)), ETHERNET)];
    let mk = |r: u8| {
        classify_connection(
            &obs(Ipv4Addr::new(192, 168, 0, 50), Ipv4Addr::new(10, 0, 0, r)),
            &unicast,
            Some(ETHERNET),
            Some(VPN),
        )
    };
    ring.push(mk(1));
    ring.push(mk(2));
    ring.push(mk(3)); // evicts #1 (cap 2)
    assert_eq!(ring.len(), 2);

    let (page, total) = ring.snapshot(0, 10);
    assert_eq!(total, 2);
    assert_eq!(page.len(), 2);
    // Newest-first: #3 then #2.
    assert_eq!(page[0].remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    assert_eq!(page[1].remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

    // Cursor: skip the newest, take one.
    let (p2, _) = ring.snapshot(1, 1);
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
}

#[test]
fn p2p_processes_suppress_fcrdns_learning_others_do_not() {
    // A torrent client's dropped peers must be skipped;
    // a browser's drop (the legit dzen.ru FCrDNS case) must not.
    assert!(process_is_p2p_fcrdns_suppressed(Some(
        r"\device\harddiskvolume5\users\krox\appdata\roaming\bittorrent web\btweb.exe"
    )));
    assert!(process_is_p2p_fcrdns_suppressed(Some(
        r"C:\Program Files\qBittorrent\qbittorrent.exe"
    )));
    assert!(process_is_p2p_fcrdns_suppressed(Some("bitcoind.exe")));
    // Non-P2P processes keep learning (the dzen.ru recovery path).
    assert!(!process_is_p2p_fcrdns_suppressed(Some("chrome.exe")));
    assert!(!process_is_p2p_fcrdns_suppressed(Some("VBoxSVC.exe")));
    assert!(!process_is_p2p_fcrdns_suppressed(None));
    assert!(!process_is_p2p_fcrdns_suppressed(Some("")));
}

// ── block-notice reporting ─────────────────────────────

#[test]
fn block_reason_prefers_killswitch_then_default_block_then_falls_back_to_rule() {
    // Role-verified kill-switch/fail-closed drop → the route is down.
    assert_eq!(
        block_reason_for(Some(1), true, Some(99), false, false, false),
        BlockReason::RouteUnavailable
    );
    // Not kill-switch, but matches the deterministic default-block-all id
    // → nothing routed this destination.
    assert_eq!(
        block_reason_for(Some(99), false, Some(99), false, false, false),
        BlockReason::NotCoveredByRules
    );
    // Neither → the only remaining production source is an explicit rule.
    assert_eq!(
        block_reason_for(Some(5), false, Some(99), false, false, false),
        BlockReason::BlockedByRule
    );
    // No active SID this batch (default id unknown) → same cautious default.
    assert_eq!(
        block_reason_for(Some(5), false, None, false, false, false),
        BlockReason::BlockedByRule
    );
    // Unidentified filter: ours, but which one is unknown — say only that.
    assert_eq!(
        block_reason_for(None, false, Some(99), false, false, false),
        BlockReason::Unattributed
    );
    // The fail-closed window still outranks it: there the cause is known.
    assert_eq!(
        block_reason_for(None, false, Some(99), true, false, false),
        BlockReason::RouteUnavailable
    );
}

#[test]
fn a_drop_of_the_closed_ipv6_family_names_the_family_not_a_rule() {
    // The v6 cut is an identified filter of ours that no rule can explain.
    assert_eq!(
        block_reason_for(Some(5), false, Some(99), false, true, false),
        BlockReason::Ipv6Blocked
    );
    // Even while the block-all is armed: the outage has its own notice,
    // and the switch that closed v6 is what the user can act on here.
    assert_eq!(
        block_reason_for(Some(5), false, Some(99), true, true, false),
        BlockReason::Ipv6Blocked
    );
}

#[test]
fn a_resolver_drop_names_the_dns_lockdown_not_a_rule() {
    // An app reaching for its own public resolver: identified filter,
    // no rule behind it, and the switch is in Settings.
    assert_eq!(
        block_reason_for(Some(5), false, Some(99), false, false, true),
        BlockReason::DnsLockdown
    );
    // Also while the block-all is armed — the outage has its own notice,
    // and this drop would have happened without it.
    assert_eq!(
        block_reason_for(Some(5), false, Some(99), true, false, true),
        BlockReason::DnsLockdown
    );
    // A role-verified kill-switch drop still wins: the bands are disjoint,
    // and a drop that reaches both readings is the outage.
    assert_eq!(
        block_reason_for(Some(5), true, Some(99), false, false, true),
        BlockReason::RouteUnavailable
    );
}

/// Consumer wired with a reverse-DNS learner that records what it is asked to
/// name, plus the DoH/DoT lockdown band check under test.
fn reverse_learner_consumer(
    lockdown_check: KillswitchDropCheckFn,
) -> (
    ConnectionObservationConsumer,
    Arc<Mutex<Vec<std::net::Ipv4Addr>>>,
) {
    let api: Arc<dyn nrr_platform_api::route_table::RouteTablePort> =
        Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
    let coordinator = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(&api),
        Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
            as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
        Arc::new(NoopPolicySource) as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
        Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
            as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        Arc::new(|| false),
    ));
    let active_sid: ActiveSidFn = Arc::new(|| None);
    let named: Arc<Mutex<Vec<std::net::Ipv4Addr>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&named);
    let consumer = ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
        .with_dns_lockdown_drop_check(lockdown_check)
        .with_reverse_dns_learner(Arc::new(move |ip, _allow_direct| {
            sink.lock().unwrap_or_else(|p| p.into_inner()).push(ip);
        }));
    (consumer, named)
}

#[test]
fn a_dns_lockdown_drop_never_reaches_the_reverse_learner() {
    // The field case: an app goes to Google Public DNS of its own, the
    // lockdown cuts it, and naming the address registered the resolver as a
    // DIRECT host — whose block-all exemption outranks the lockdown block.
    const LOCKDOWN_SPEC: u64 = 5;
    let (consumer, named) = reverse_learner_consumer(Arc::new(|id| id == LOCKDOWN_SPEC));
    let resolver = || {
        let mut o = block_obs(Some(true), Some(LOCKDOWN_SPEC));
        o.remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 443));
        o
    };
    consumer.consume(&[resolver()], SystemTime::now());
    assert!(
        named.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
        "a resolver the lockdown just cut must not be named"
    );

    // Positive control: the same drop from any other band still teaches the
    // learner — the gate must not have silenced reverse learning outright.
    let mut other = resolver();
    other.nrr_drop_spec_id = Some(LOCKDOWN_SPEC + 1);
    consumer.consume(&[other], SystemTime::now());
    assert_eq!(
        *named.lock().unwrap_or_else(|p| p.into_inner()),
        vec![Ipv4Addr::new(8, 8, 4, 4)]
    );
}

#[test]
fn an_unrecognised_drop_during_a_fail_closed_window_reads_as_the_outage() {
    // The exact 0811 case: fail-closed armed, the packet caught by a filter
    // outside the current kill-switch registry (a fake-address block).
    // Calling that "a rule blocked you" sends the user editing rules.
    assert_eq!(
        block_reason_for(Some(5), false, Some(99), true, false, false),
        BlockReason::RouteUnavailable
    );
    // "No rule covers this host" is still the more specific answer and keeps
    // precedence over the posture.
    assert_eq!(
        block_reason_for(Some(99), false, Some(99), true, false, false),
        BlockReason::NotCoveredByRules
    );
}

/// One observed connection blocked by `blocked_by_nrr`/`spec_id`, from a
/// fixed process to a fixed destination — the variables under test.
fn block_obs(blocked_by_nrr: Option<bool>, spec_id: Option<u64>) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: Some(r"C:\Program Files\Telegram\Telegram.exe".to_string()),
        user_sid: None,
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
        remote: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443)),
        verdict: ConnectionVerdict::Block,
        drop_filter_id: Some(1),
        blocked_by_nrr,
        nrr_drop_spec_id: spec_id,
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

/// Consumer wired with `with_block_notice`, whose sink runs every
/// `BlockAttempt` through a REAL `BlockNoticeLedger` (fixed `now_ms = 0`
/// so retries land in the same episode) — the same folding the
/// production `BlockNoticeCenter` does. `notices` collects only the
/// attempts that survived folding, so the test can assert on episode
/// behaviour, not just on what the consumer decided to report.
fn block_notice_consumer(
    killswitch_check: Option<KillswitchDropCheckFn>,
) -> (
    ConnectionObservationConsumer,
    Arc<Mutex<Vec<nrr_domain::block_notice::BlockNotice>>>,
) {
    let api: Arc<dyn nrr_platform_api::route_table::RouteTablePort> =
        Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
    let coordinator = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(&api),
        Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
            as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
        Arc::new(NoopPolicySource) as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
        Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
            as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        Arc::new(|| false),
    ));
    let active_sid: ActiveSidFn = Arc::new(|| None);
    let ledger = Arc::new(Mutex::new(
        nrr_domain::block_notice::BlockNoticeLedger::default(),
    ));
    let notices: Arc<Mutex<Vec<nrr_domain::block_notice::BlockNotice>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink_ledger = Arc::clone(&ledger);
    let sink_notices = Arc::clone(&notices);
    let mut consumer = ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
        .with_block_notice(
            Arc::new(|_ip| None),
            Arc::new(move |_sid: &str, attempt: BlockAttempt| {
                let mut g = sink_ledger.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(notice) = g.record(0, &attempt) {
                    sink_notices
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(notice);
                }
            }),
        );
    if let Some(check) = killswitch_check {
        consumer = consumer.with_killswitch_drop_check(check);
    }
    (consumer, notices)
}

#[test]
fn a_foreign_drop_never_produces_a_block_notice() {
    // `Some(false)` is a firewall/antivirus filter, not ours — reporting
    // it would blame our policy for someone else's block.
    let (consumer, notices) = block_notice_consumer(None);
    let summary = consumer.consume(&[block_obs(Some(false), Some(42))], SystemTime::now());
    assert_eq!(summary.blocked_foreign, 1);
    assert!(notices.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

#[test]
fn an_unattributed_drop_never_produces_a_block_notice() {
    // `None` means ownership could not be resolved — not evidence enough
    // to tell the user "we blocked this".
    let (consumer, notices) = block_notice_consumer(None);
    consumer.consume(&[block_obs(None, Some(42))], SystemTime::now());
    assert!(notices.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

#[test]
fn a_role_verified_drop_opens_one_episode_and_its_retry_stays_silent() {
    let check: KillswitchDropCheckFn = Arc::new(|id| id == 777);
    let (consumer, notices) = block_notice_consumer(Some(check));

    consumer.consume(&[block_obs(Some(true), Some(777))], SystemTime::now());
    // A retry of the SAME attempt inside the episode gap.
    consumer.consume(&[block_obs(Some(true), Some(777))], SystemTime::now());

    let got = notices.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(got.len(), 1, "one notice per episode, not per drop");
    assert_eq!(got[0].reason, BlockReason::RouteUnavailable);
    assert_eq!(got[0].destination, "203.0.113.9");
    assert_eq!(got[0].app, "telegram.exe");
}

#[test]
fn housekeeping_destinations_never_produce_a_block_notice() {
    // The field case: mDNS, MLD and a BitTorrent discovery group made up
    // 1400 of 1420 blocked v6 destinations in one session. None of them is
    // a site, and none of them is a rule the user could edit.
    for dest in [
        "ff02::fb",
        "ff02::16",
        "ff15::efc0:988f",
        "224.0.0.251",
        "255.255.255.255",
    ] {
        let (consumer, notices) = block_notice_consumer(None);
        let mut obs = block_obs(Some(true), Some(42));
        obs.remote = SocketAddr::new(dest.parse().expect("address literal"), 5353);
        consumer.consume(&[obs], SystemTime::now());
        assert!(
            notices.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
            "{dest} must not raise a notice"
        );
    }
}

/// A subnet-directed broadcast is indistinguishable from a host address —
/// `192.168.1.255` is the broadcast of a /24 and an ordinary host in a /23
/// — so it classified as routable and a dropped NetBIOS-NS raised a notice
/// about a destination no rule can name. The port is what settles it.
#[test]
fn a_discovery_datagram_to_a_private_broadcast_raises_no_notice() {
    for (dest, port) in [
        ("192.168.1.255", 137u16),
        ("192.168.0.255", 138),
        ("10.0.0.255", 3702),
    ] {
        let (consumer, notices) = block_notice_consumer(None);
        let mut obs = block_obs(Some(true), Some(42));
        obs.remote = SocketAddr::new(dest.parse().expect("address literal"), port);
        consumer.consume(&[obs], SystemTime::now());
        assert!(
            notices.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
            "{dest}:{port} must not raise a notice"
        );
    }

    // Positive control: the same private network on an ordinary port is a
    // destination the user can write a rule about, and still gets its
    // notice. The widening must not silence the LAN wholesale.
    let (consumer, notices) = block_notice_consumer(None);
    let mut obs = block_obs(Some(true), Some(42));
    obs.remote = SocketAddr::new("192.168.1.10".parse().expect("v4"), 443);
    consumer.consume(&[obs], SystemTime::now());
    assert_eq!(notices.lock().unwrap_or_else(|p| p.into_inner()).len(), 1);
}

#[test]
fn a_cut_ipv6_destination_is_announced_as_the_closed_family() {
    let (mut consumer, notices) = block_notice_consumer(None);
    consumer = consumer.with_ipv6_cut_drop_check(Arc::new(|id| id == 42));
    let mut obs = block_obs(Some(true), Some(42));
    obs.remote = SocketAddr::new("2606:4700::1111".parse().expect("v6"), 443);
    consumer.consume(&[obs], SystemTime::now());

    let got = notices.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].reason, BlockReason::Ipv6Blocked);
}

#[test]
fn a_drop_whose_spec_id_fails_role_verification_still_reports_as_blocked_by_rule() {
    // The spec id exists but is not in the kill-switch registry (the
    // user's own Block rule): still ours, still worth a notice, just a
    // different reason.
    let check: KillswitchDropCheckFn = Arc::new(|_id| false);
    let (consumer, notices) = block_notice_consumer(Some(check));
    consumer.consume(&[block_obs(Some(true), Some(555))], SystemTime::now());
    let got = notices.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].reason, BlockReason::BlockedByRule);
}
