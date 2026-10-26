use super::*;
use crate::fake_ip::binding_release::{BindingReleaser, LiveFlowAddresses};
use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};
use std::sync::atomic::AtomicUsize;

// ── The packet loop only hands over where its flows are ──────────────────────

const GONE: &str = "gone.example";

fn allocator_with(hosts: &[&str]) -> Arc<StdMutex<FakeIpAllocator>> {
    let mut allocator = FakeIpAllocator::default();
    for host in hosts {
        allocator.allocate(host).expect("allocate");
    }
    Arc::new(StdMutex::new(allocator))
}

fn bound(allocator: &Arc<StdMutex<FakeIpAllocator>>, host: &str) -> Option<std::net::Ipv4Addr> {
    allocator
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .binding_for_domain(host)
        .map(|b| b.v4)
}

fn stack_over(
    allocator: &Arc<StdMutex<FakeIpAllocator>>,
    live: &Arc<LiveFlowAddresses>,
) -> FakeIpStack {
    let (device, _state) = open_mock_device();
    FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        RelayCore::new(
            Arc::clone(allocator),
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(relay::StaticUpstreamResolver::new()),
            Arc::new(relay::FixedRouteSelector(RouteRole::Secondary)),
        ),
        Arc::new(dialer::MockRelayDialer::new()),
        StackWaker::new(),
    )
    .with_live_flow_addresses(Arc::clone(live))
}

/// A live TCP flow from the client to `fake`.
fn open_flow_to(stack: &mut FakeIpStack, fake: std::net::Ipv4Addr, hostname: &str) {
    let key = FlowKey {
        protocol: FlowProtocol::Tcp,
        source: SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), 40_100)),
        destination: SocketAddr::from((fake, 443)),
    };
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 1024]),
        tcp::SocketBuffer::new(vec![0u8; 1024]),
    );
    socket
        .listen(IpListenEndpoint {
            addr: Some(smoltcp_address(key.destination.ip())),
            port: key.destination.port(),
        })
        .expect("listen");
    let handle = stack.sockets.add(socket);
    let shared = FlowShared::for_flow(Arc::clone(&stack.waker), Arc::clone(&stack.ready), key);
    stack.flows.insert(
        key,
        FlowConn {
            handle,
            shared,
            policy: FlowPolicy {
                hostname: hostname.to_owned(),
                site: super::super::site_of(hostname),
                book_route: Some(RouteRole::Secondary),
                owner: None,
            },
            client_close_sent: false,
            abort_sent: false,
        },
    );
}

/// The rule checks behind a release must never run on the packet loop: a
/// book match there is a pause in every relayed connection. A keeper that
/// counts its calls sees none from any number of steps, and the releaser,
/// run off the loop, still frees the departed host.
#[test]
fn the_packet_loop_never_asks_whose_rules_name_a_host() {
    let allocator = allocator_with(&[GONE]);
    let live = Arc::new(LiveFlowAddresses::new());
    let asked = Arc::new(AtomicUsize::new(0));
    let keeper = {
        let asked = Arc::clone(&asked);
        Arc::new(move |_: &str| {
            asked.fetch_add(1, Ordering::SeqCst);
            false
        })
    };
    let releaser = BindingReleaser::new(Arc::clone(&allocator), keeper, Arc::clone(&live))
        .with_idle(Duration::ZERO);
    let mut stack = stack_over(&allocator, &live);
    for now in 0..50 {
        stack.step(now * LIVE_PUBLISH_EVERY_MS).expect("step");
    }
    assert_eq!(asked.load(Ordering::SeqCst), 0, "no rule check on the loop");
    assert!(bound(&allocator, GONE).is_some(), "no release on the loop");

    assert_eq!(releaser.run_once(), 1, "the slow tick releases it");
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    assert_eq!(bound(&allocator, GONE), None);
}

/// A download that outlives its rule keeps its virtual address: the loop
/// hands its address over, and the releaser leaves it alone.
#[test]
fn a_live_flows_address_is_handed_over_and_never_freed() {
    let allocator = allocator_with(&[GONE]);
    let live = Arc::new(LiveFlowAddresses::new());
    let fake = bound(&allocator, GONE).expect("bound");
    let releaser = BindingReleaser::new(
        Arc::clone(&allocator),
        Arc::new(|_: &str| false),
        Arc::clone(&live),
    )
    .with_idle(Duration::ZERO);
    let mut stack = stack_over(&allocator, &live);
    open_flow_to(&mut stack, fake, GONE);
    stack.step(1).expect("step");
    assert_eq!(releaser.run_once(), 0);
    assert_eq!(bound(&allocator, GONE), Some(fake));
}
