//! A drop that is part of the fake-address machinery itself is nobody's block:
//! no notice, no rule named, nothing offered. A real rule block still is one.

use super::*;
use nrr_domain::block_notice::BlockReason;
use nrr_platform_api::conn_observe::TransportProtocol;
use nrr_platform_api::fake_ip::FakeIpPoolConfig;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

/// A user's deny rule.
const DENY: u64 = 0x51;
/// One of our filters that is in no band the observer can name — the pool's
/// UDP veto is one.
const OURS_UNNAMED: u64 = 0x52;
const DENIED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const FAKE_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 8);

type Attempts = Arc<Mutex<Vec<BlockAttempt>>>;

fn quic_drop(remote: SocketAddr, spec_id: u64) -> ConnectionObservation {
    let local = match remote {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5),
            51000,
            0,
            0,
        )),
    };
    ConnectionObservation {
        pid: 0,
        process_path: Some(r"C:\Program Files\Browser\chrome.exe".to_string()),
        user_sid: None,
        protocol: TransportProtocol::Udp,
        local,
        remote,
        verdict: ConnectionVerdict::Block,
        drop_filter_id: Some(170_345),
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: Some(spec_id),
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

fn v4(ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, 443))
}

fn consumer() -> (
    ConnectionObservationConsumer,
    Attempts,
    Arc<ConnectionTraceRing>,
) {
    let attempts: Attempts = Arc::default();
    let reported = Arc::clone(&attempts);
    let ring = Arc::new(ConnectionTraceRing::new(8));
    let consumer = ConnectionObservationConsumer::with_egress(
        Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new()),
        Arc::new(|_: &str| -> (Option<u32>, Option<u32>) { (None, None) }),
        Arc::new(|| None),
        false,
    )
    .with_killswitch_drop_check(Arc::new(|_| false))
    .with_rule_block_drop_check(Arc::new(|id: u64| id == DENY))
    .with_fail_closed_armed(Arc::new(|| false))
    .with_trace_ring(Arc::clone(&ring))
    .with_block_notice(
        Arc::new(|_: Ipv4Addr| None),
        Arc::new(
            move |_sid: &str, attempt: BlockAttempt, _seen: Option<u64>| {
                reported
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(attempt);
            },
        ),
    );
    (consumer, attempts, ring)
}

fn attempts(of: &Attempts) -> Vec<BlockAttempt> {
    of.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

#[test]
fn a_quic_drop_into_the_fake_pool_raises_no_notice() {
    let (consumer, noted, ring) = consumer();
    consumer.consume(&[quic_drop(v4(FAKE_V4), OURS_UNNAMED)], SystemTime::now());

    assert!(
        attempts(&noted).is_empty(),
        "nothing to tell, nothing to offer"
    );
    let (rows, _) = ring.snapshot(0, 8);
    assert_eq!(rows.len(), 1, "the trace still shows the drop");
    assert_eq!(rows[0].nrr_block_reason, None, "and blames no rule for it");
}

#[test]
fn a_quic_drop_into_the_v6_fake_pool_raises_no_notice() {
    let fake_v6 = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 8);
    let (consumer, noted, _) = consumer();
    consumer.consume(
        &[quic_drop(
            SocketAddr::V6(SocketAddrV6::new(fake_v6, 443, 0, 0)),
            OURS_UNNAMED,
        )],
        SystemTime::now(),
    );
    assert!(attempts(&noted).is_empty());
}

#[test]
fn the_pool_is_read_from_its_configuration() {
    let moved = FakeIpPoolConfig {
        v4_base: Ipv4Addr::new(100, 80, 0, 0),
        v4_prefix_len: 16,
        ..FakeIpPoolConfig::default()
    };
    let (consumer, noted, _) = consumer();
    let consumer = consumer.with_fake_ip_pool(moved);
    consumer.consume(
        &[quic_drop(v4(Ipv4Addr::new(100, 80, 0, 8)), OURS_UNNAMED)],
        SystemTime::now(),
    );
    assert!(attempts(&noted).is_empty());
}

#[test]
fn the_same_drop_to_a_real_address_under_a_block_rule_still_raises_the_rule_notice() {
    let (consumer, noted, ring) = consumer();
    consumer.consume(&[quic_drop(v4(DENIED), DENY)], SystemTime::now());

    let noted = attempts(&noted);
    assert_eq!(noted.len(), 1);
    assert_eq!(noted[0].reason, BlockReason::BlockedByRule);
    assert_eq!(noted[0].dest, DENIED.to_string());
    let (rows, _) = ring.snapshot(0, 8);
    assert_eq!(rows[0].nrr_block_reason, Some("blocked-by-rule"));
}

#[test]
fn a_filter_of_ours_that_no_rule_compiled_to_is_not_called_a_rule() {
    // The deny classifier knows every filter a Block rule compiled to; any
    // other filter of ours that dropped a real address is not the user's rule.
    let (consumer, noted, ring) = consumer();
    consumer.consume(&[quic_drop(v4(DENIED), OURS_UNNAMED)], SystemTime::now());

    let noted = attempts(&noted);
    assert_eq!(noted.len(), 1);
    assert_eq!(noted[0].reason, BlockReason::Unattributed);
    let (rows, _) = ring.snapshot(0, 8);
    assert_eq!(rows[0].nrr_block_reason, Some("unattributed"));
}
