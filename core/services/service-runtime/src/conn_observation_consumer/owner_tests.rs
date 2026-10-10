//! The consumer where every user binds links of their own and drop ids name
//! their role: each drop is judged by its owner's links, an outage is
//! announced once per owner's episode, system drops stay out of everything a
//! user reads, and a socket row folds into the drop report of its connection.

use super::*;
use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
use nrr_platform_api::conn_observe::TransportProtocol;
use std::net::{Ipv4Addr, SocketAddrV4};

const ALICE: &str = "u-alice";
const BOB: &str = "u-bob";
const SYSTEM: &str = "u-system";

const PIN: u64 = 0x10;
const RULE: u64 = 0x20;
const DEFAULT: u64 = 0x30;
const SYSTEM_PIN: u64 = 0x110;

const ETH: u32 = 2;
const WG: u32 = 9;

type Notices = Arc<Mutex<Vec<(String, &'static str)>>>;

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

struct Fixture {
    consumer: ConnectionObservationConsumer,
    ring: Arc<ConnectionTraceRing>,
    notices: Notices,
    learned: Arc<Mutex<Vec<Ipv4Addr>>>,
}

/// Alice's additional route is down, Bob's is up; nobody is "the active user".
fn fixture() -> Fixture {
    let api = nrr_platform_api::windows_api::MockWindowsApi::new();
    api.set_adapter_infos(vec![
        adapter(ETH, "eth0", Ipv4Addr::new(192, 168, 0, 5)),
        adapter(WG, "wg0", Ipv4Addr::new(10, 8, 0, 2)),
    ]);
    let egress: EgressIfindexesFn = Arc::new(|owner: &str| match owner {
        ALICE => (Some(ETH), None),
        BOB => (Some(ETH), Some(WG)),
        _ => (None, None),
    });
    let ring = Arc::new(ConnectionTraceRing::new(64));
    let notices: Notices = Arc::new(Mutex::new(Vec::new()));
    let learned = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&notices);
    let learn = Arc::clone(&learned);
    let consumer =
        ConnectionObservationConsumer::with_egress(Arc::new(api), egress, Arc::new(|| None), false)
            .with_owner_scoped_egress()
            .with_drop_pairing()
            .with_trace_ring(Arc::clone(&ring))
            .with_not_covered_drop_check(Arc::new(|id: u64| id == DEFAULT))
            .with_service_account_drop_check(Arc::new(|id: u64| id == SYSTEM_PIN))
            .with_vpn_endpoint_learner(
                Arc::new(move |ip: Ipv4Addr| {
                    learn.lock().unwrap_or_else(|p| p.into_inner()).push(ip)
                }),
                Arc::new(|id: u64| id == PIN || id == SYSTEM_PIN),
            )
            .with_block_notice(
                Arc::new(|_: Ipv4Addr| -> Option<String> { None }),
                Arc::new(
                    move |sid: &str, attempt: BlockAttempt, _seen: Option<u64>| {
                        sink.lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push((sid.to_owned(), attempt.reason.slug()));
                    },
                ),
            );
    Fixture {
        consumer,
        ring,
        notices,
        learned,
    }
}

fn drop_by(owner: &str, spec_id: u64, remote_last: u8, at_ms: u64) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: Some("/usr/bin/browser".into()),
        user_sid: Some(owner.to_owned()),
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 5), 40_000)),
        remote: SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(198, 51, 100, remote_last),
            443,
        )),
        verdict: ConnectionVerdict::Block,
        drop_filter_id: None,
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: Some(spec_id),
        observed_unix_ms: Some(at_ms),
        progress: ConnectionProgress::Attempt,
    }
}

fn at(ms: u64) -> SystemTime {
    std::time::UNIX_EPOCH + Duration::from_millis(ms)
}

fn notices(f: &Fixture) -> Vec<(String, &'static str)> {
    f.notices.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

#[test]
fn a_pin_drop_during_its_owners_outage_lands_in_that_owners_list_only() {
    let f = fixture();
    f.consumer.consume(
        &[drop_by(ALICE, PIN, 1, 1_000), drop_by(BOB, PIN, 2, 1_000)],
        at(1_500),
    );

    let alice = f.ring.outage_blocks().snapshot(ALICE);
    assert_eq!(alice.entries.len(), 1);
    assert_eq!(alice.entries[0].remote.ip(), Ipv4Addr::new(198, 51, 100, 1));
    assert!(
        f.ring.outage_blocks().snapshot(BOB).entries.is_empty(),
        "Bob's route is up: his pin drop is a stale socket, not an outage"
    );
    assert_eq!(
        notices(&f),
        vec![(ALICE.to_owned(), "route-unavailable")],
        "only the owner whose route is down hears of it"
    );
    let (rows, _) = f.ring.snapshot(0, 8);
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|r| r.nrr_block_reason == Some("route-unavailable")));
}

#[test]
fn an_outage_is_announced_once_per_episode_and_per_owner() {
    let f = fixture();
    let charlie = "u-charlie";
    f.consumer.consume(
        &[
            drop_by(ALICE, PIN, 1, 1_000),
            drop_by(ALICE, PIN, 2, 1_100),
            drop_by(charlie, PIN, 3, 1_200),
        ],
        at(1_500),
    );
    assert_eq!(
        notices(&f),
        vec![
            (ALICE.to_owned(), "route-unavailable"),
            (charlie.to_owned(), "route-unavailable"),
        ],
        "a second destination is the same news; another user's outage is not"
    );

    f.ring.outage_blocks().outage_ended(ALICE, 2_000);
    f.consumer
        .consume(&[drop_by(ALICE, PIN, 4, 2_100)], at(2_200));
    assert_eq!(notices(&f).len(), 2, "a straggler of the ended outage");

    f.consumer
        .consume(&[drop_by(ALICE, PIN, 5, 600_000)], at(600_100));
    assert_eq!(
        notices(&f).last(),
        Some(&(ALICE.to_owned(), "route-unavailable")),
        "the next outage is news again"
    );
    assert_eq!(notices(&f).len(), 3);
}

#[test]
fn a_system_drop_teaches_a_tunnel_server_and_nothing_else() {
    let f = fixture();
    let mut client = drop_by(SYSTEM, SYSTEM_PIN, 9, 1_000);
    client.process_path = Some("/usr/sbin/openvpn".into());
    let summary = f.consumer.consume(&[client], at(1_500));

    assert!(notices(&f).is_empty(), "nobody's notice");
    assert!(f.ring.outage_blocks().snapshot(SYSTEM).entries.is_empty());
    assert_eq!(summary.vpn_endpoints_learned, 1);
    assert_eq!(
        *f.learned.lock().unwrap_or_else(|p| p.into_inner()),
        vec![Ipv4Addr::new(198, 51, 100, 9)]
    );
    let (rows, _) = f.ring.snapshot(0, 8);
    assert_eq!(rows.len(), 1, "the trace still shows it");
}

#[test]
fn a_catch_all_drop_reads_not_covered_and_a_rule_drop_reads_as_a_rule() {
    let f = fixture();
    f.consumer.consume(
        &[
            drop_by(BOB, DEFAULT, 1, 1_000),
            drop_by(BOB, RULE, 2, 1_000),
        ],
        at(1_500),
    );
    let (rows, _) = f.ring.snapshot(0, 8);
    assert_eq!(rows[1].nrr_block_reason, Some("not-covered-by-rules"));
    assert_eq!(rows[0].nrr_block_reason, Some("blocked-by-rule"));
    assert_eq!(
        notices(&f),
        vec![
            (BOB.to_owned(), "not-covered-by-rules"),
            (BOB.to_owned(), "blocked-by-rule"),
        ]
    );
}

#[test]
fn a_socket_row_and_its_drop_report_make_one_trace_row() {
    let f = fixture();
    let mut drop = drop_by(BOB, RULE, 1, 1_000);
    drop.process_path = None;
    let socket = ConnectionObservation {
        pid: 77,
        process_path: Some("/usr/bin/mail".into()),
        verdict: ConnectionVerdict::Unknown,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        ..drop_by(BOB, RULE, 1, 1_000)
    };
    let unrelated = ConnectionObservation {
        verdict: ConnectionVerdict::Unknown,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        ..drop_by(BOB, RULE, 2, 1_000)
    };
    f.consumer.consume(&[socket, drop, unrelated], at(1_500));

    let (rows, total) = f.ring.snapshot(0, 8);
    assert_eq!(total, 2);
    let blocked = rows
        .iter()
        .find(|r| r.verdict == ConnectionVerdict::Block)
        .map(|r| r.process_path.clone());
    assert_eq!(blocked, Some(Some("/usr/bin/mail".to_owned())));
}

#[test]
fn each_connection_is_labelled_by_its_owners_links() {
    let f = fixture();
    let on_tunnel = ConnectionObservation {
        local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 8, 0, 2), 40_001)),
        verdict: ConnectionVerdict::Unknown,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        ..drop_by(BOB, RULE, 1, 1_000)
    };
    let alice_on_tunnel = ConnectionObservation {
        user_sid: Some(ALICE.to_owned()),
        ..on_tunnel.clone()
    };
    f.consumer.consume(&[on_tunnel, alice_on_tunnel], at(1_500));
    let (rows, _) = f.ring.snapshot(0, 8);
    assert_eq!(rows[1].egress.role, EgressRole::Secondary, "Bob's tunnel");
    assert_eq!(
        rows[0].egress.role,
        EgressRole::Other,
        "the same link is not Alice's additional route"
    );
}
