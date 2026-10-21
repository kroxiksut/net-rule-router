//! A drop by the user's own deny rule costs no lookup of its address, and is
//! still shown by the rule and the address it hit.

use super::*;
use nrr_domain::block_notice::BlockReason;
use nrr_platform_api::conn_observe::TransportProtocol;
use std::net::{Ipv4Addr, SocketAddrV4};

const DENY: u64 = 0x31;
const PIN: u64 = 0x32;
const DENIED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

type Named = Arc<Mutex<Vec<Ipv4Addr>>>;
type Attempts = Arc<Mutex<Vec<BlockAttempt>>>;

fn drop_by(spec_id: u64) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: Some(r"C:\Program Files\Browser\browser.exe".to_string()),
        user_sid: None,
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
        remote: SocketAddr::V4(SocketAddrV4::new(DENIED, 443)),
        verdict: ConnectionVerdict::Block,
        drop_filter_id: Some(1),
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: Some(spec_id),
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

/// Wired as production is: the reverse learner, the leak guard's and the
/// deny rules' classifiers, the block notice with a name from DNS observation.
fn consumer(armed: bool) -> (ConnectionObservationConsumer, Named, Attempts) {
    let named: Named = Arc::default();
    let attempts: Attempts = Arc::default();
    let learned = Arc::clone(&named);
    let reported = Arc::clone(&attempts);
    let consumer = ConnectionObservationConsumer::with_egress(
        Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new()),
        Arc::new(|_: &str| -> (Option<u32>, Option<u32>) { (None, None) }),
        Arc::new(|| None),
        false,
    )
    .with_killswitch_drop_check(Arc::new(|id: u64| id == PIN))
    .with_rule_block_drop_check(Arc::new(|id: u64| id == DENY))
    .with_fail_closed_armed(Arc::new(move || armed))
    .with_reverse_dns_learner(Arc::new(move |ip, _allow_direct, _origin, _owner| {
        learned.lock().unwrap_or_else(|p| p.into_inner()).push(ip);
    }))
    .with_block_notice(
        Arc::new(|ip: Ipv4Addr| (ip == DENIED).then(|| "denied.example".to_string())),
        Arc::new(
            move |_sid: &str, attempt: BlockAttempt, _seen: Option<u64>| {
                reported
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(attempt);
            },
        ),
    );
    (consumer, named, attempts)
}

fn named(named: &Named) -> Vec<Ipv4Addr> {
    named.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

#[test]
fn a_deny_rule_drop_sends_no_lookup() {
    let (consumer, learned, _) = consumer(false);
    consumer.consume(&[drop_by(DENY)], SystemTime::now());
    assert!(named(&learned).is_empty(), "a denied site is never named");
}

#[test]
fn a_deny_rule_drop_sends_no_lookup_during_an_outage_either() {
    // The outage changes the notice's wording, not who the filter belongs to.
    let (consumer, learned, _) = consumer(true);
    consumer.consume(&[drop_by(DENY)], SystemTime::now());
    assert!(named(&learned).is_empty());
}

#[test]
fn a_leak_protection_drop_is_still_named() {
    let (consumer, learned, _) = consumer(true);
    consumer.consume(&[drop_by(PIN)], SystemTime::now());
    assert_eq!(named(&learned), vec![DENIED]);
}

#[test]
fn an_unclassified_drop_of_ours_is_still_named() {
    let (consumer, learned, _) = consumer(false);
    consumer.consume(&[drop_by(DENY + 100)], SystemTime::now());
    assert_eq!(named(&learned), vec![DENIED]);
}

#[test]
fn a_deny_rule_drop_is_still_reported_by_its_name_and_address() {
    let (consumer, _, attempts) = consumer(false);
    let ring = Arc::new(ConnectionTraceRing::new(8));
    let consumer = consumer.with_trace_ring(Arc::clone(&ring));
    consumer.consume(&[drop_by(DENY)], SystemTime::now());

    let attempts = attempts.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].reason, BlockReason::BlockedByRule);
    assert_eq!(attempts[0].host.as_deref(), Some("denied.example"));
    assert_eq!(attempts[0].dest, DENIED.to_string());

    let (rows, _) = ring.snapshot(0, 8);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].nrr_block_reason, Some("blocked-by-rule"));
    assert_eq!(rows[0].remote.ip(), IpAddr::V4(DENIED));
}

#[test]
fn a_deny_rule_drop_during_an_outage_names_the_rule_not_the_outage() {
    let (consumer, _, attempts) = consumer(true);
    let ring = Arc::new(ConnectionTraceRing::new(8));
    let consumer = consumer.with_trace_ring(Arc::clone(&ring));
    consumer.consume(&[drop_by(DENY)], SystemTime::now());

    let attempts = attempts.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].reason, BlockReason::BlockedByRule);
    assert_eq!(attempts[0].host.as_deref(), Some("denied.example"));

    let (rows, _) = ring.snapshot(0, 8);
    assert_eq!(rows[0].nrr_block_reason, Some("blocked-by-rule"));
}

#[test]
fn a_leak_protection_drop_during_an_outage_still_reads_as_the_outage() {
    // Read from the trace row: the notice itself may be held by start-up quiet.
    let (consumer, _, _) = consumer(true);
    let ring = Arc::new(ConnectionTraceRing::new(8));
    let consumer = consumer.with_trace_ring(Arc::clone(&ring));
    consumer.consume(&[drop_by(PIN)], SystemTime::now());
    let (rows, _) = ring.snapshot(0, 8);
    assert_eq!(rows[0].nrr_block_reason, Some("route-unavailable"));
}
