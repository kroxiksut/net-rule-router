use super::*;

use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};
use nrr_platform_api::icmp_echo::EchoOutcome;
use std::net::{IpAddr, Ipv4Addr};

const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const REAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// An echo request as `tracert` sends it, hop limit `ttl`.
fn echo_request(destination: Ipv4Addr, ttl: u8) -> Vec<u8> {
    let icmp = [8, 0, 0x55, 0xaa, 0x00, 0x01, 0x00, 0x2a, b'h', b'i'];
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, ttl, 1, 0, 0];
    packet[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&CLIENT.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(&icmp);
    packet
}

/// A stack whose only name `trace.test` sits at a virtual address and really
/// lives at [`REAL`] over the secondary route.
fn stack_with(dialer: Arc<dialer::MockRelayDialer>) -> (FakeIpStack, Arc<MockTunState>, Ipv4Addr) {
    let mut allocator = FakeIpAllocator::default();
    let fake = allocator.allocate("trace.test").expect("allocate").v4;
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(relay::StaticUpstreamResolver::new().with("trace.test", &[IpAddr::V4(REAL)])),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Secondary)),
    );
    let (device, state) = open_mock_device();
    let stack = FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        relay,
        dialer,
        StackWaker::new(),
    );
    (stack, state, fake)
}

/// Step until the stack has written something or five seconds have passed; the
/// answer is built on a worker thread.
fn step_until_written(stack: &mut FakeIpStack, state: &MockTunState) -> Vec<Vec<u8>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut now_ms = 0;
    while state.written_packets().is_empty() && std::time::Instant::now() < deadline {
        now_ms += 5;
        stack.step(now_ms).expect("stack step");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    state.written_packets()
}

#[test]
fn a_traceroute_probe_to_a_name_is_answered_by_the_real_router_on_its_route() {
    let dialer = Arc::new(dialer::MockRelayDialer::new());
    dialer.set_echo_outcome(EchoOutcome::TtlExpired { router: ROUTER });
    let (mut stack, state, fake) = stack_with(Arc::clone(&dialer));

    state.push_inbound(echo_request(fake, 3));
    let written = step_until_written(&mut stack, &state);

    let dials = dialer.dials();
    assert_eq!(dials.len(), 1);
    assert_eq!(dials[0].address, Some(SocketAddr::new(IpAddr::V4(REAL), 0)));
    assert_eq!(dials[0].route, nrr_shared::RouteRole::Secondary);
    assert_eq!(
        dialer.echo_ttls(),
        vec![3],
        "the tool's hop limit goes out as it came"
    );

    assert_eq!(written.len(), 1);
    let ip = Ipv4Packet::new_checked(&written[0][..]).expect("ipv4");
    assert_eq!((ip.src_addr(), ip.dst_addr()), (ROUTER, CLIENT));
    let icmp = ip.payload();
    assert_eq!(icmp[0], 11, "time exceeded");
    let quoted = Ipv4Packet::new_unchecked(&icmp[8..]);
    assert_eq!(
        quoted.dst_addr(),
        fake,
        "the quote names the address the tool aimed at, or it cannot match its probe"
    );
}

#[test]
fn a_ping_to_a_name_is_answered_from_its_virtual_address() {
    let dialer = Arc::new(dialer::MockRelayDialer::new());
    dialer.set_echo_outcome(EchoOutcome::Reply);
    let (mut stack, state, fake) = stack_with(dialer);

    state.push_inbound(echo_request(fake, 128));
    let written = step_until_written(&mut stack, &state);

    assert_eq!(written.len(), 1);
    let ip = Ipv4Packet::new_checked(&written[0][..]).expect("ipv4");
    assert_eq!((ip.src_addr(), ip.dst_addr()), (fake, CLIENT));
    assert_eq!(ip.payload()[0], 0, "echo reply");
}

#[test]
fn an_echo_to_an_address_nobody_holds_is_not_carried() {
    let dialer = Arc::new(dialer::MockRelayDialer::new());
    dialer.set_echo_outcome(EchoOutcome::Reply);
    let (mut stack, state, fake) = stack_with(Arc::clone(&dialer));
    let unmapped = Ipv4Addr::from(u32::from(fake) + 1);

    state.push_inbound(echo_request(unmapped, 64));
    for now_ms in 1..20 {
        stack.step(now_ms * 5).expect("stack step");
    }

    assert!(dialer.dials().is_empty());
    assert!(state.written_packets().is_empty());
}
