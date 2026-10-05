//! Held networks at the orchestrator's Fail-Closed call site, and end to end
//! through what an install puts in place.

use super::*;

use crate::address_ownership::{AddressOwnership, ZoneVsIpOrder};
use crate::enforcement_planner::NetworkHolds;
use crate::killswitch_codegen::KillSwitchProtocols;
use nrr_domain::rule_shape::RuleShapeSupport;
use nrr_shared::ip_block::IpBlock;

const SID: &str = "S-1-5-21-A";
const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const LAN: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 168, 1, 0), 24);
const SECONDARY_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 4);
const MAIN_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);

fn route(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn subnet(text: &str) -> CanonicalAddressMatch {
    CanonicalAddressMatch::Subnet(IpBlock::parse(text).expect("subnet"))
}

fn block(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("block")
}

/// The address book every test starts from: a secondary host, and the main
/// link naming `MAIN_HOST`.
fn address_book() -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("p-host", MAIN_HOST)]),
        secondary: CanonicalRuleSet::from_rules(vec![route(
            "s-host",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(SECONDARY_HOST)),
        )]),
    }
}

/// [`address_book`] plus the additional link's networks: a `/24` around
/// `MAIN_HOST` (held), a `/12` (too wide) and the machine's own LAN (spared).
fn network_book() -> CanonicalRuleBook {
    let mut rules = address_book().secondary.rules().to_vec();
    rules.push(route("s-24", subnet("198.51.100.0/24")));
    rules.push(route("s-12", subnet("172.16.0.0/12")));
    rules.push(route("s-lan", subnet("192.168.1.0/24")));
    CanonicalRuleBook {
        primary: address_book().primary,
        secondary: CanonicalRuleSet::from_rules(rules),
    }
}

/// The arbiter as it reads once enforcement carries networks.
fn ownership_with_networks(book: &CanonicalRuleBook) -> AddressOwnership {
    AddressOwnership::resolve_with_support(
        book,
        &MockFqdnCacheLookup::new(),
        ZoneVsIpOrder::default(),
        RuleShapeSupport {
            network_destination: true,
            ..crate::wfp_codegen::current_rule_shape_support()
        },
    )
}

fn exemptions() -> FailClosedExemptions {
    FailClosedExemptions {
        bootstrap_server_ips: vec![SERVER],
        local_subnets: vec![LAN],
        ..FailClosedExemptions::default()
    }
}

/// What the unresolved-tunnel branch arms in split mode, per destination.
fn fail_closed_set(holds: &NetworkHolds) -> Vec<WfpFilterSpec> {
    let (_api, orch, _src, _rules, _audit) = fixture();
    orch.fail_closed_filters(
        SID,
        RouteBehaviorMode::PreferPrimary,
        &[IpAddr::V4(SECONDARY_HOST)],
        holds,
        &exemptions(),
        KillSwitchProtocols::ALL,
        FailClosedPosture { block_all: false },
    )
}

fn holds_for(book: &CanonicalRuleBook) -> NetworkHolds {
    let exemptions = exemptions();
    NetworkHolds::for_pass(
        &ownership_with_networks(book),
        &[IpAddr::V4(SECONDARY_HOST)],
        || exemptions.never_blocked_networks(),
    )
}

/// The action of the highest-weight ALE filter an unlisted process meets on
/// the main link for `ip`; `None` lets it through.
fn ale_verdict(filters: &[WfpFilterSpec], ip: Ipv4Addr) -> Option<WfpAction> {
    let covers = |f: &WfpFilterSpec| {
        f.remote_ip == Some(ip)
            || f.remote_ip_set.contains(&ip)
            || f.remote_subnet.is_some_and(|(net, len)| {
                IpBlock::new(IpAddr::V4(net), len).is_some_and(|b| b.contains(IpAddr::V4(ip)))
            })
    };
    filters
        .iter()
        .filter(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.app_pattern.is_none()
                && f.local_interface_luid.is_none()
                && covers(f)
        })
        .max_by_key(|f| f.weight)
        .map(|f| f.action)
}

#[test]
fn an_unresolved_tunnel_blocks_a_secondary_slash_24() {
    let holds = holds_for(&network_book());
    assert_eq!(holds.held, vec![block("198.51.100.0/24")]);

    let filters = fail_closed_set(&holds);
    assert!(filters.iter().any(|f| f.action == WfpAction::Block
        && f.layer == WfpLayerKey::AleAuthConnectV4
        && f.remote_subnet == Some((Ipv4Addr::new(198, 51, 100, 0), 24))));
    assert_eq!(
        ale_verdict(&filters, Ipv4Addr::new(198, 51, 100, 9)),
        Some(WfpAction::Block)
    );
}

#[test]
fn a_slash_12_is_too_wide_to_hold_and_is_reported() {
    let holds = holds_for(&network_book());
    assert_eq!(holds.too_wide, vec![block("172.16.0.0/12")]);

    let filters = fail_closed_set(&holds);
    assert!(!filters
        .iter()
        .any(|f| f.remote_subnet.is_some_and(|(_, len)| len == 12)));
    assert_eq!(ale_verdict(&filters, Ipv4Addr::new(172, 16, 4, 4)), None);
}

#[test]
fn the_machines_own_lan_is_spared() {
    let holds = holds_for(&network_book());
    assert_eq!(holds.spared, vec![block("192.168.1.0/24")]);
    assert_eq!(
        ale_verdict(&fail_closed_set(&holds), Ipv4Addr::new(192, 168, 1, 20)),
        None
    );
}

#[test]
fn a_primary_address_inside_the_held_slash_24_stays_open() {
    let filters = fail_closed_set(&holds_for(&network_book()));
    assert_eq!(
        ale_verdict(&filters, MAIN_HOST),
        Some(WfpAction::Permit),
        "the narrower main-link rule wins inside the held network"
    );
    assert!(!filters
        .iter()
        .any(|f| f.action == WfpAction::Block && f.remote_ip == Some(MAIN_HOST)));
}

#[test]
fn without_networks_the_hold_is_free_and_adds_nothing() {
    let holds = NetworkHolds::for_pass(
        &ownership_with_networks(&address_book()),
        &[IpAddr::V4(SECONDARY_HOST)],
        || unreachable!("a book without networks never reads the exemptions"),
    );
    assert_eq!(holds, NetworkHolds::default());

    let filters = fail_closed_set(&holds);
    let per_address = crate::killswitch_codegen::fail_closed_block_destinations(
        SID,
        &[IpAddr::V4(SECONDARY_HOST)],
        KillSwitchProtocols::ALL,
    );
    assert_eq!(filters, per_address);
}

/// End to end through an install: network rules add their own filters on top
/// of everything the address book installs, in both postures; with the
/// additional link unresolved Fail-Closed holds the `/24` and neither the
/// too-wide `/12` nor the machine's own LAN.
#[test]
fn network_rules_install_on_top_of_the_address_book() {
    use nrr_platform_api::types::{WfpAction, WfpFilterRecord};
    use std::collections::HashSet;
    // The machine as the coordinator reports it with the tunnel gone: the LAN
    // and the server stay reachable.
    let installed = |book: CanonicalRuleBook, resolution: Option<KillSwitchResolution>| {
        let api = Arc::new(MockWindowsApi::new());
        let session = Arc::new(
            WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).expect("session"),
        );
        let src = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&src) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            Arc::new(MockFqdnCacheLookup::new()),
            Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_, _| resolution.clone()))
        .with_fail_closed_exemptions_resolver(Arc::new(|_, _| {
            crate::killswitch_codegen::FailClosedExemptions {
                bootstrap_server_ips: vec![SERVER],
                local_subnets: vec![LAN],
                ..Default::default()
            }
        }));
        rules.set(ActiveRulesSnapshot {
            rule_book: book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        src.set(SID, snap_block("Wi-Fi", "TAP"));
        orch.install_for_sid(SID).expect("install");
        let filters: Vec<WfpFilterRecord> = api.wfp_filters.lock().expect("filters").clone();
        filters
    };
    // What a filter enforces, without the id and weight that only place it.
    let keys = |filters: &[WfpFilterRecord]| -> HashSet<String> {
        filters
            .iter()
            .map(|f| {
                format!(
                    "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
                    f.layer,
                    f.action,
                    f.remote_ip,
                    f.remote_ip_set,
                    f.remote_subnet,
                    f.remote_port,
                    f.app_pattern,
                    f.local_interface_luid,
                    f.user_sid,
                )
            })
            .collect()
    };
    let net = |text: &str| {
        let b = block(text);
        match b.network() {
            IpAddr::V4(v4) => (v4, b.prefix_len()),
            IpAddr::V6(_) => unreachable!("v4 fixture"),
        }
    };
    for resolution in [None, Some(full_ks_resolution())] {
        let without = installed(address_book(), resolution.clone());
        assert!(!without.is_empty(), "fixture guard");
        let with = installed(network_book(), resolution);
        assert!(
            keys(&with).is_superset(&keys(&without)),
            "a network rule must not take anything of the address book away"
        );
        assert!(
            with.iter()
                .any(|f| f.remote_subnet == Some(net("198.51.100.0/24"))),
            "the network rule's own filter is installed"
        );
    }

    let down = installed(network_book(), None);
    let blocked = |text: &str| {
        down.iter()
            .any(|f| f.action == WfpAction::Block && f.remote_subnet == Some(net(text)))
    };
    assert!(blocked("198.51.100.0/24"), "the held network is blocked");
    assert!(!blocked("172.16.0.0/12"), "too wide to hold");
    assert!(
        !blocked("192.168.1.0/24"),
        "the machine's own LAN is spared"
    );
}
