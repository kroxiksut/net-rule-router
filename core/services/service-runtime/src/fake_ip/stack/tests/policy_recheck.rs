use super::*;
use std::sync::atomic::AtomicU64;

// ── A rule change reaches flows that are already open ────────────────────────

const MOVED: &str = "moved.example";
const STEADY: &str = "steady.example";

/// The routing user's book: `MOVED` goes over the secondary until it is
/// blocked; every other host takes the primary. The stamp moves only when the
/// test says a book changed.
#[derive(Default)]
struct SwitchableBook {
    blocked: AtomicBool,
    stamp: AtomicU64,
}

impl SwitchableBook {
    fn block_moved_host(&self) {
        self.blocked.store(true, Ordering::SeqCst);
        self.stamp.fetch_add(1, Ordering::SeqCst);
    }
}

impl relay::RouteSelector for SwitchableBook {
    fn route_for(&self, hostname: &str) -> Option<RouteRole> {
        match hostname {
            MOVED if self.blocked.load(Ordering::SeqCst) => None,
            MOVED => Some(RouteRole::Secondary),
            _ => Some(RouteRole::Primary),
        }
    }

    fn policy_stamp(&self) -> u64 {
        self.stamp.load(Ordering::SeqCst)
    }
}

fn stack_over(book: &Arc<SwitchableBook>) -> FakeIpStack {
    let (device, _state) = open_mock_device();
    let routes: Arc<dyn relay::RouteSelector> = Arc::clone(book) as Arc<dyn relay::RouteSelector>;
    FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        RelayCore::new(
            Arc::new(StdMutex::new(
                nrr_platform_api::fake_ip::FakeIpAllocator::default(),
            )),
            nrr_platform_api::fake_ip::FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(relay::StaticUpstreamResolver::new()),
            routes,
        ),
        Arc::new(dialer::MockRelayDialer::new()),
        StackWaker::new(),
    )
}

/// A live TCP flow to `hostname`, opened while the book gave it `book_route`.
fn park_flow(
    stack: &mut FakeIpStack,
    client_port: u16,
    hostname: &str,
    book_route: RouteRole,
) -> FlowKey {
    let key = FlowKey {
        protocol: FlowProtocol::Tcp,
        source: SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), client_port)),
        destination: SocketAddr::from((std::net::Ipv4Addr::new(198, 18, 0, 7), 443)),
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
                book_route: Some(book_route),
                owner: None,
            },
            client_close_sent: false,
            abort_sent: false,
        },
    );
    key
}

/// A host blocked after its connection opened loses that connection: the
/// relay carried it over the secondary, where none of the user's filters see
/// the service's own dial. The flows the change did not touch stay up, and so
/// does the in-tunnel rescue, which no book names.
#[test]
fn a_host_blocked_while_its_flow_is_open_has_that_flow_reset() {
    let book = Arc::new(SwitchableBook::default());
    let mut stack = stack_over(&book);
    let moved = park_flow(&mut stack, 40_001, MOVED, RouteRole::Secondary);
    let steady = park_flow(&mut stack, 40_002, STEADY, RouteRole::Primary);
    let rescue = park_flow(&mut stack, 40_003, "10.117.0.1", RouteRole::Secondary);
    stack.step(1).expect("step");
    assert_eq!(stack.flow_count(), 3);

    book.block_moved_host();
    stack.step(2).expect("step");
    assert!(
        stack.flows[&moved].abort_sent,
        "the blocked host's flow is reset"
    );
    assert!(!stack.flows[&steady].abort_sent);
    assert!(!stack.flows[&rescue].abort_sent);

    // The reset goes out with this step and the flow is reaped by it.
    stack.step(3).expect("step");
    assert!(!stack.flows.contains_key(&moved));
    assert!(stack.flows.contains_key(&steady));
    assert!(stack.flows.contains_key(&rescue));
}

/// Nothing is re-decided while no book moved: the recheck is paid once per
/// rule change, never per packet.
#[test]
fn flows_are_not_re_decided_while_the_stamp_stands() {
    let book = Arc::new(SwitchableBook::default());
    let mut stack = stack_over(&book);
    let moved = park_flow(&mut stack, 40_001, MOVED, RouteRole::Secondary);
    stack.step(1).expect("step");

    book.blocked.store(true, Ordering::SeqCst);
    stack.step(2).expect("step");
    assert!(!stack.flows[&moved].abort_sent);
}

/// A UDP bind decided by the routing user's book goes whole when that book
/// moves its host: every client of the endpoint would otherwise re-dial with
/// the target the old book chose.
#[test]
fn a_udp_bind_whose_host_the_book_blocked_is_dropped() {
    let book = Arc::new(SwitchableBook::default());
    let mut stack = stack_over(&book);
    let fake = std::net::Ipv4Addr::new(198, 18, 0, 9);
    let key = (std::net::IpAddr::V4(fake), 443);
    let make_buffer = || {
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; 1024],
        )
    };
    let mut socket = udp::Socket::new(make_buffer(), make_buffer());
    let local = smoltcp_address(key.0);
    socket
        .bind(IpListenEndpoint {
            addr: Some(local),
            port: key.1,
        })
        .expect("bind");
    let handle = stack.sockets.add(socket);
    let client = SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), 50_000));
    stack.udp_binds.insert(
        key,
        UdpBind {
            handle,
            local,
            target: dialer::UpstreamTarget::at(
                MOVED.to_owned(),
                "203.0.113.5:443".parse().expect("address"),
                RouteRole::Secondary,
            ),
            clients: HashMap::new(),
            pending: HashMap::from([(
                client,
                PendingUdpDial {
                    outcome: Arc::new(Mutex::new(None)),
                    book_route: Some(RouteRole::Secondary),
                    owner: None,
                    queued: VecDeque::new(),
                    first_payload_len: 0,
                    started_at: std::time::Instant::now(),
                },
            )]),
        },
    );
    stack.step(1).expect("step");
    assert!(stack.udp_binds.contains_key(&key));

    book.block_moved_host();
    stack.step(2).expect("step");
    assert!(
        !stack.udp_binds.contains_key(&key),
        "the bind went with its rule"
    );
}
