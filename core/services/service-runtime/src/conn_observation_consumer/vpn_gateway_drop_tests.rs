//! A dropped handshake of another VPN becomes one question for its owner, and
//! only a guard's drop of a handshake-shaped flow does.

use super::*;
use nrr_platform_api::conn_observe::TransportProtocol;
use std::net::{Ipv4Addr, SocketAddrV4};

const GUARD: u64 = 0x41;
const DENY: u64 = 0x42;
const SERVICE: u64 = 0x43;
const OWNER: &str = "S-1-5-21-1-2-3-1001";
const GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

type Noted = Arc<Mutex<Vec<(String, IpAddr, Option<String>)>>>;

fn drop_of(
    spec_id: u64,
    protocol: TransportProtocol,
    port: u16,
    program: &str,
) -> ConnectionObservation {
    ConnectionObservation {
        pid: 0,
        process_path: Some(program.to_string()),
        user_sid: Some(OWNER.to_string()),
        protocol,
        local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
        remote: SocketAddr::V4(SocketAddrV4::new(GATEWAY, port)),
        verdict: ConnectionVerdict::Block,
        drop_filter_id: Some(1),
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: Some(spec_id),
        observed_unix_ms: None,
        progress: ConnectionProgress::Attempt,
    }
}

fn consumer() -> (ConnectionObservationConsumer, Noted) {
    let noted: Noted = Arc::default();
    let sink = Arc::clone(&noted);
    let consumer = ConnectionObservationConsumer::with_egress(
        Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new()),
        Arc::new(|_: &str| -> (Option<u32>, Option<u32>) { (None, None) }),
        Arc::new(|| None),
        false,
    )
    .with_killswitch_drop_check(Arc::new(|id: u64| id == GUARD || id == SERVICE))
    .with_service_account_drop_check(Arc::new(|id: u64| id == SERVICE))
    .with_rule_block_drop_check(Arc::new(|id: u64| id == DENY))
    .with_vpn_gateway_drops(Arc::new(move |owner: &str, ip, program: Option<&str>| {
        sink.lock().unwrap_or_else(|p| p.into_inner()).push((
            owner.to_string(),
            ip,
            program.map(str::to_string),
        ));
    }));
    (consumer, noted)
}

fn noted(noted: &Noted) -> Vec<(String, IpAddr, Option<String>)> {
    noted.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

#[test]
fn a_guard_drop_on_4500_from_an_unknown_program_is_noted_for_its_owner() {
    let (consumer, seen) = consumer();
    consumer.consume(
        &[drop_of(
            GUARD,
            TransportProtocol::Udp,
            4500,
            r"C:\Corp\agent.exe",
        )],
        SystemTime::now(),
    );
    assert_eq!(
        noted(&seen),
        vec![(
            OWNER.to_string(),
            IpAddr::V4(GATEWAY),
            Some(r"C:\Corp\agent.exe".to_string())
        )]
    );
}

#[test]
fn only_a_guard_drop_of_a_handshake_shaped_flow_counts() {
    let (consumer, seen) = consumer();
    consumer.consume(
        &[
            // The user's own deny rule.
            drop_of(DENY, TransportProtocol::Udp, 4500, r"C:\Corp\agent.exe"),
            // System traffic: nobody to ask.
            drop_of(SERVICE, TransportProtocol::Udp, 500, r"C:\Corp\agent.exe"),
            // Not a handshake.
            drop_of(GUARD, TransportProtocol::Tcp, 443, r"C:\Corp\agent.exe"),
            drop_of(GUARD, TransportProtocol::Udp, 443, r"C:\Corp\agent.exe"),
            // A recognised client goes to the client question instead.
            drop_of(
                GUARD,
                TransportProtocol::Udp,
                1194,
                r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            ),
            drop_of(
                GUARD,
                TransportProtocol::Udp,
                51820,
                r"C:\Program Files\WireGuard\wireguard.exe",
            ),
        ],
        SystemTime::now(),
    );
    assert!(noted(&seen).is_empty(), "{:?}", noted(&seen));
}

#[test]
fn esp_is_noted_without_naming_the_program_it_carried() {
    let (consumer, seen) = consumer();
    consumer.consume(
        &[drop_of(
            GUARD,
            TransportProtocol::Other(50),
            0,
            "/usr/bin/browser",
        )],
        SystemTime::now(),
    );
    assert_eq!(
        noted(&seen),
        vec![(OWNER.to_string(), IpAddr::V4(GATEWAY), None)]
    );
}

/// The IPv6 cut proves nothing about our tunnel, yet a handshake it stopped is
/// the same question: without it a VPN whose server is IPv6 could never be
/// allowed, since nobody was asked.
#[test]
fn a_handshake_the_ipv6_cut_dropped_is_noted_for_its_owner() {
    const CUT: u64 = 0x44;
    let gateway: std::net::Ipv6Addr = "2001:db8::20".parse().expect("ip");
    let (consumer, seen) = consumer();
    let consumer = consumer.with_ipv6_cut_drop_check(Arc::new(|id: u64| id == CUT));
    let mut rec = drop_of(CUT, TransportProtocol::Udp, 500, r"C:\Corp\agent.exe");
    rec.local = "[2001:db8::5]:51000".parse().expect("addr");
    rec.remote = SocketAddr::new(IpAddr::V6(gateway), 500);
    consumer.consume(&[rec], SystemTime::now());
    assert_eq!(
        noted(&seen),
        vec![(
            OWNER.to_string(),
            IpAddr::V6(gateway),
            Some(r"C:\Corp\agent.exe".to_string())
        )]
    );
}
