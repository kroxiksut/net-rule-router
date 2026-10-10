//! The tick's wiring with scripted sources: what a drop of each role becomes,
//! and what is left when the drop reports cannot start.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    MockConnectionObservationSource, TransportProtocol,
};
use nrr_platform_api::enforcement::{EgressBinding, EgressBindingSource, UserPrincipal};
use nrr_platform_api::PlatformError;
use nrr_platform_linux::drop_tag::{DropKind, DropTag};
use nrr_service_runtime::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use nrr_service_runtime::block_notice_center::BlockNoticeCenter;
use nrr_service_runtime::block_notice_journal_store::{
    BlockNoticeJournalStore, InMemoryBlockNoticeJournalStore,
};
use nrr_service_runtime::conn_observation_consumer::{ConnTraceTee, ConnectionTraceRing};
use nrr_service_runtime::service_tasks::{fold_observations, AppObservationWiring};

use super::*;

const ETH: u32 = 2;
const WG: u32 = 9;

fn alice() -> String {
    UserPrincipal::from_linux_uid(1000).as_stored().to_owned()
}

fn bob() -> String {
    UserPrincipal::from_linux_uid(1001).as_stored().to_owned()
}

fn root() -> String {
    UserPrincipal::from_linux_uid(0).as_stored().to_owned()
}

struct NoBindings;
impl EgressBindingSource for NoBindings {
    fn bindings_for(&self, _principal: &UserPrincipal) -> EgressBinding {
        EgressBinding {
            primary: None,
            secondary: None,
        }
    }
}

fn adapter(index: u32, name: &str, ip: Ipv4Addr) -> AdapterInfo {
    AdapterInfo {
        index,
        adapter_name: name.into(),
        description: name.into(),
        friendly_name: name.into(),
        mac: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: IfOperStatus::Up,
        ipv4_addresses: vec![ip],
        ipv6_addresses: Vec::new(),
        gateways: Vec::new(),
    }
}

struct Rig {
    socket_table: Arc<MockConnectionObservationSource>,
    reports: Arc<MockConnectionObservationSource>,
    ring: Arc<ConnectionTraceRing>,
    store: Arc<AppObservationStore>,
    /// Every notice the centre raised, per user.
    journal: Arc<InMemoryBlockNoticeJournalStore>,
    wiring: AppObservationWiring,
}

impl Rig {
    fn fold(&self) {
        fold_observations(&self.wiring);
    }

    fn notices_of(&self, sid: &str) -> Vec<&'static str> {
        self.journal
            .list_pending(sid, 0)
            .into_iter()
            .map(|entry| entry.notice.reason.slug())
            .collect()
    }

    fn reasons(&self) -> Vec<Option<&'static str>> {
        let (rows, _) = self.ring.snapshot(0, 64);
        rows.into_iter().map(|r| r.nrr_block_reason).collect()
    }
}

/// Alice's additional route is down, Bob's is up. `reports_start` decides
/// whether the drop reports come up.
fn rig(reports_start: bool) -> Rig {
    let api = nrr_platform_api::windows_api::MockWindowsApi::new();
    api.set_adapter_infos(vec![
        adapter(ETH, "eth0", Ipv4Addr::new(192, 168, 0, 5)),
        adapter(WG, "wg0", Ipv4Addr::new(10, 8, 0, 2)),
    ]);
    let api: Arc<dyn nrr_platform_api::route_table::RouteTablePort> = Arc::new(api);
    let ring = Arc::new(ConnectionTraceRing::new(64));
    let tee = Arc::new(ConnTraceTee::new(
        Arc::clone(&ring),
        Arc::clone(&api),
        Arc::new(NoBindings),
    ));
    let (alice, bob) = (alice(), bob());
    let journal = Arc::new(InMemoryBlockNoticeJournalStore::new());
    let center = Arc::new(
        BlockNoticeCenter::new()
            .with_journal(Arc::clone(&journal) as Arc<dyn BlockNoticeJournalStore>),
    );
    let parts = DropObservationParts {
        api,
        egress_of: Arc::new(move |owner: &str| {
            if owner == alice {
                (Some(ETH), None)
            } else if owner == bob {
                (Some(ETH), Some(WG))
            } else {
                (None, None)
            }
        }),
        notice_sink: notice_sink(center),
        vpn_endpoint_learner: Arc::new(|_ip: Ipv4Addr| {}),
        log_ndjson: Arc::default(),
        stale_flow_reset: None,
    };
    let socket_table = Arc::new(MockConnectionObservationSource::new());
    let reports = Arc::new(MockConnectionObservationSource::new());
    let store = Arc::new(AppObservationStore::new());
    let started = Arc::clone(&reports);
    let wiring = app_observation_wiring(
        Arc::clone(&socket_table) as Arc<dyn ConnectionObservationSource>,
        move || {
            if reports_start {
                Ok(started as Arc<dyn ConnectionObservationSource>)
            } else {
                Err(PlatformError::Transient {
                    operation: "bind the drop-report group",
                    detail: "EPERM".into(),
                })
            }
        },
        Some(parts),
        Some(tee),
        Arc::clone(&store),
    );
    Rig {
        socket_table,
        reports,
        ring,
        store,
        journal,
        wiring,
    }
}

fn connection(owner: &str, remote_last: u8) -> ConnectionObservation {
    ConnectionObservation {
        pid: 4242,
        process_path: Some("/usr/bin/browser".into()),
        user_sid: Some(owner.to_owned()),
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)), 40_000),
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, remote_last)), 443),
        verdict: ConnectionVerdict::Unknown,
        drop_filter_id: None,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

/// What the NFLOG observer hands over: a verdict and a role, no program.
fn dropped(owner: &str, tag: DropTag, remote_last: u8) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: None,
        verdict: ConnectionVerdict::Block,
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: Some(tag.spec_id()),
        ..connection(owner, remote_last)
    }
}

fn now_ms() -> u64 {
    nrr_service_runtime::conn_observation_consumer::now_unix_ms()
}

#[test]
fn a_pin_drop_during_an_outage_joins_that_users_list_only() {
    let rig = rig(true);
    rig.ring.outage_blocks().outage_began(&alice(), now_ms());
    rig.reports
        .push(dropped(&alice(), DropTag::user(DropKind::Pin), 1));
    rig.reports
        .push(dropped(&bob(), DropTag::user(DropKind::Pin), 2));
    rig.fold();

    let list = rig.ring.outage_blocks().snapshot(&alice());
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].remote.ip(), Ipv4Addr::new(198, 51, 100, 1));
    assert!(
        rig.ring.outage_blocks().snapshot(&bob()).entries.is_empty(),
        "Bob's route is up: his drop is no outage of his"
    );
    assert_eq!(rig.notices_of(&alice()), vec!["route-unavailable"]);
    assert!(rig.notices_of(&bob()).is_empty());
    assert!(rig.ring.outage_blocks().is_fed());
}

#[test]
fn a_system_drop_raises_no_notice_and_joins_no_list() {
    let rig = rig(true);
    let system_pin = DropTag {
        kind: DropKind::Pin,
        system: true,
    };
    rig.ring.outage_blocks().outage_began(&root(), now_ms());
    rig.reports.push(dropped(&root(), system_pin, 1));
    rig.reports.push(dropped(
        &root(),
        DropTag {
            kind: DropKind::Rule,
            system: true,
        },
        2,
    ));
    rig.fold();

    assert!(rig.notices_of(&root()).is_empty());
    assert!(rig
        .ring
        .outage_blocks()
        .snapshot(&root())
        .entries
        .is_empty());
    assert!(rig
        .ring
        .outage_blocks()
        .snapshot(&alice())
        .entries
        .is_empty());
    assert_eq!(rig.reasons().len(), 2, "the trace still shows them");
}

#[test]
fn each_role_gets_its_own_reason() {
    let rig = rig(true);
    rig.reports
        .push(dropped(&bob(), DropTag::user(DropKind::Default), 1));
    rig.reports
        .push(dropped(&bob(), DropTag::user(DropKind::Rule), 2));
    rig.reports
        .push(dropped(&bob(), DropTag::user(DropKind::DnsLockdown), 3));
    rig.fold();
    // Newest first.
    assert_eq!(
        rig.reasons(),
        vec![
            Some("dns-lockdown"),
            Some("blocked-by-rule"),
            Some("not-covered-by-rules"),
        ]
    );
    assert_eq!(
        rig.notices_of(&bob()),
        vec!["not-covered-by-rules", "blocked-by-rule", "dns-lockdown"]
    );
}

#[test]
fn a_socket_row_and_its_drop_report_make_one_trace_row() {
    let rig = rig(true);
    rig.socket_table.push(connection(&bob(), 1));
    rig.socket_table.push(connection(&bob(), 2));
    rig.reports
        .push(dropped(&bob(), DropTag::user(DropKind::Rule), 1));
    rig.fold();

    let (rows, total) = rig.ring.snapshot(0, 8);
    assert_eq!(total, 2, "one row per connection");
    let blocked = rows
        .iter()
        .find(|r| r.verdict == ConnectionVerdict::Block)
        .map(|r| r.process_path.clone());
    assert_eq!(
        blocked,
        Some(Some("/usr/bin/browser".to_owned())),
        "the drop row names the program the socket row knew"
    );
    assert!(rows.iter().all(|r| r.observed_unix_ms.is_some()));
}

#[test]
fn without_drop_reports_the_socket_table_still_feeds_trace_and_app_rules() {
    let rig = rig(false);
    assert!(rig.wiring.consumer.is_none());
    rig.socket_table.push(connection(&alice(), 7));
    rig.fold();

    let (rows, total) = rig.ring.snapshot(0, 8);
    assert_eq!(total, 1);
    assert_eq!(rows[0].verdict, ConnectionVerdict::Unknown);
    assert_eq!(
        rig.store.ips_for_app("browser"),
        vec![Ipv4Addr::new(198, 51, 100, 7)]
    );
    assert!(
        !rig.ring.outage_blocks().is_fed(),
        "the outage list must say it is not watching"
    );
}

#[test]
fn with_drop_reports_the_app_rules_still_learn_destinations() {
    let rig = rig(true);
    rig.socket_table.push(connection(&alice(), 7));
    rig.fold();
    assert_eq!(
        rig.store.ips_for_app("browser"),
        vec![Ipv4Addr::new(198, 51, 100, 7)]
    );
}

#[test]
fn only_the_tunnel_guards_verify_and_every_system_tag_is_a_service_accounts() {
    let verifies = tag_check(|tag| tag.kind.verifies_kill_switch());
    let system = tag_check(|tag| tag.system);
    for tag in DropTag::all() {
        assert_eq!(
            verifies(tag.spec_id()),
            tag.kind.verifies_kill_switch(),
            "{tag:?}"
        );
        assert_eq!(system(tag.spec_id()), tag.system, "{tag:?}");
    }
    assert!(!verifies(80_122), "a foreign id verifies nothing");
}
