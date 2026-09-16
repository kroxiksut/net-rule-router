use super::*;

// ── fake_ip_instant_rst hold-and-retry ──────────────────────────────────
//
// Focused unit tests directly on `dial_tcp_with_hold`, rather than another
// full in-process TCP handshake like the two tests above: the retry logic
// is a pure decision over dial outcomes plus timing, and exercising it
// through a real smoltcp handshake would only make the window-exhaustion
// and mid-hold-death cases slow and harder to reason about. `retry_interval`
// / `retry_window` are passed in milliseconds here (never the real
// `HOLD_RETRY_INTERVAL`/`HOLD_RETRY_WINDOW` constants `spawn_dial_worker`
// uses) so these tests run fast and deterministically.

use std::sync::atomic::AtomicU32;

/// Refuses with `RelayError::SourcePolicyRefused` for the first
/// `refuse_calls` attempts, then succeeds. `u32::MAX` never succeeds — used
/// to exercise the "still refused" paths deterministically.
struct FlakyPolicyDialer {
    calls: AtomicU32,
    refuse_calls: u32,
}
impl FlakyPolicyDialer {
    fn new(refuse_calls: u32) -> Self {
        Self {
            calls: AtomicU32::new(0),
            refuse_calls,
        }
    }
    fn call_count(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}
impl dialer::RelayDialer for FlakyPolicyDialer {
    fn connect_tcp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, dialer::RelayError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= self.refuse_calls {
            Err(dialer::RelayError::SourcePolicyRefused {
                reason: "secondary adapter unresolved (test)",
            })
        } else {
            Ok(Box::new(EmptyStream))
        }
    }
    fn connect_udp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayDatagram>, dialer::RelayError> {
        Err(dialer::RelayError::Upstream {
            detail: "udp not used in this test".to_string(),
        })
    }
}

/// A trivial successful stream: no bytes either way, just enough to prove
/// the dial resolved to `Ok`.
struct EmptyStream;
impl std::io::Read for EmptyStream {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}
impl std::io::Write for EmptyStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl dialer::RelayStream for EmptyStream {
    fn shutdown_write(&mut self) -> Result<(), dialer::RelayError> {
        Ok(())
    }
    fn into_split(self: Box<Self>) -> Result<dialer::RelaySplit, dialer::RelayError> {
        Ok(dialer::RelaySplit {
            reader: Box::new(EmptyStream),
            writer: Box::new(EmptyWriteHalf),
        })
    }
}
struct EmptyWriteHalf;
impl std::io::Write for EmptyWriteHalf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl dialer::RelayWriteHalf for EmptyWriteHalf {
    fn shutdown_write(&mut self) -> Result<(), dialer::RelayError> {
        Ok(())
    }
}

fn hold_test_target() -> dialer::UpstreamTarget {
    dialer::UpstreamTarget::at(
        "reconnecting.test".to_string(),
        "10.0.0.9:443".parse().expect("address"),
        nrr_shared::RouteRole::Secondary,
    )
}

#[test]
fn dial_tcp_with_hold_instant_refuses_when_instant_rst_is_on() {
    let dialer = FlakyPolicyDialer::new(u32::MAX); // always refuses
    let shared = FlowShared::new(StackWaker::new());
    let instant_rst = AtomicBool::new(true);
    let (result, mode, attempts) = dial_tcp_with_hold(
        shared.as_ref(),
        &dialer,
        &hold_test_target(),
        &instant_rst,
        Duration::from_millis(10),
        Duration::from_millis(200),
    );
    assert!(matches!(
        result,
        Err(RelayError::SourcePolicyRefused { .. })
    ));
    assert_eq!(mode, "instant");
    assert_eq!(attempts, 1);
    assert_eq!(dialer.call_count(), 1, "instant mode must never retry");
}

#[test]
fn dial_tcp_with_hold_genuine_network_error_never_holds_even_when_off() {
    // A non-policy failure (e.g. connection refused) must fail fast
    // regardless of `fake_ip_instant_rst` — only a SourcePolicyRefused is
    // ever held.
    struct AlwaysUpstreamError;
    impl dialer::RelayDialer for AlwaysUpstreamError {
        fn connect_tcp(
            &self,
            _target: &dialer::UpstreamTarget,
        ) -> Result<Box<dyn dialer::RelayStream>, dialer::RelayError> {
            Err(dialer::RelayError::Upstream {
                detail: "connection refused (test)".to_string(),
            })
        }
        fn connect_udp(
            &self,
            _target: &dialer::UpstreamTarget,
        ) -> Result<Box<dyn dialer::RelayDatagram>, dialer::RelayError> {
            Err(dialer::RelayError::Upstream {
                detail: "udp not used in this test".to_string(),
            })
        }
    }

    let shared = FlowShared::new(StackWaker::new());
    let instant_rst = AtomicBool::new(false); // hold-and-retry is enabled...
    let started = std::time::Instant::now();
    let (result, mode, attempts) = dial_tcp_with_hold(
        shared.as_ref(),
        &AlwaysUpstreamError,
        &hold_test_target(),
        &instant_rst,
        Duration::from_millis(10),
        Duration::from_secs(5), // ...with a long window that must NOT be used
    );
    assert!(matches!(result, Err(RelayError::Upstream { .. })));
    assert_eq!(mode, "instant");
    assert_eq!(attempts, 1);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "a genuine network error must fail fast, never hold"
    );
}

#[test]
fn dial_tcp_with_hold_retries_and_succeeds_when_instant_rst_is_off() {
    let dialer = FlakyPolicyDialer::new(2); // refuses twice, succeeds on the 3rd
    let shared = FlowShared::new(StackWaker::new());
    let instant_rst = AtomicBool::new(false);
    let (result, mode, attempts) = dial_tcp_with_hold(
        shared.as_ref(),
        &dialer,
        &hold_test_target(),
        &instant_rst,
        Duration::from_millis(10),
        Duration::from_secs(5),
    );
    assert!(result.is_ok(), "must succeed once the refusal clears");
    assert_eq!(mode, "held");
    assert_eq!(attempts, 3);
    assert_eq!(dialer.call_count(), 3);
}

#[test]
fn dial_tcp_with_hold_gives_up_after_the_window_when_still_refused() {
    let dialer = FlakyPolicyDialer::new(u32::MAX); // never resolves
    let shared = FlowShared::new(StackWaker::new());
    let instant_rst = AtomicBool::new(false);
    let started = std::time::Instant::now();
    let (result, mode, attempts) = dial_tcp_with_hold(
        shared.as_ref(),
        &dialer,
        &hold_test_target(),
        &instant_rst,
        Duration::from_millis(10),
        Duration::from_millis(60),
    );
    assert!(matches!(
        result,
        Err(RelayError::SourcePolicyRefused { .. })
    ));
    assert_eq!(mode, "held");
    assert!(
        attempts >= 2,
        "must have retried at least once before giving up, got {attempts}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "must give up promptly once the window elapses, not hang"
    );
}

#[test]
fn dial_tcp_with_hold_stops_retrying_when_the_flow_dies_mid_hold() {
    let dialer = FlakyPolicyDialer::new(u32::MAX); // never resolves
    let shared = FlowShared::new(StackWaker::new());
    let instant_rst = AtomicBool::new(false);
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            shared.mark_dead();
        });
    }
    let started = std::time::Instant::now();
    let (result, mode, _attempts) = dial_tcp_with_hold(
        shared.as_ref(),
        &dialer,
        &hold_test_target(),
        &instant_rst,
        Duration::from_millis(10),
        Duration::from_secs(10), // long window — the death must cut it short
    );
    assert!(matches!(
        result,
        Err(RelayError::SourcePolicyRefused { .. })
    ));
    assert_eq!(mode, "held");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a dead flow must stop the hold promptly instead of running out the window"
    );
}

/// A dialer that parks the dial for one designated upstream until released,
/// and delegates everything else to the scripted upstream. Models a dead
/// host that sits in `connect` for its full timeout.
struct GatedDialer {
    inner: ScriptedUpstream,
    gate_addr: SocketAddr,
    released: Arc<(StdMutex<bool>, Condvar)>,
    parked: Arc<AtomicBool>,
}
impl dialer::RelayDialer for GatedDialer {
    fn connect_tcp(
        &self,
        target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, dialer::RelayError> {
        if target.address == Some(self.gate_addr) {
            self.parked.store(true, Ordering::SeqCst);
            let (lock, cv) = &*self.released;
            let deadline = StdInstant::now() + Duration::from_secs(10);
            let mut released = guard(lock);
            while !*released {
                if StdInstant::now() >= deadline {
                    return Err(dialer::RelayError::Upstream {
                        detail: "gate never released".to_string(),
                    });
                }
                let (next, _) = cv
                    .wait_timeout(released, Duration::from_millis(20))
                    .unwrap_or_else(PoisonError::into_inner);
                released = next;
            }
        }
        self.inner.connect_tcp(target)
    }
    fn connect_udp(
        &self,
        target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayDatagram>, dialer::RelayError> {
        self.inner.connect_udp(target)
    }
}

#[test]
fn a_slow_dial_does_not_stall_other_flows() {
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

    const MTU: u16 = 1500;
    let client_addr = std::net::Ipv4Addr::new(10, 0, 0, 1);

    let mut allocator = FakeIpAllocator::default();
    let slow_v4 = allocator.allocate("slow.test").expect("allocate").v4;
    let fast_v4 = allocator.allocate("fast.test").expect("allocate").v4;

    let pool = FakeIpPoolConfig::default();
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            relay::StaticUpstreamResolver::new()
                .with("slow.test", &[std::net::IpAddr::V4(slow_v4)])
                .with("fast.test", &[std::net::IpAddr::V4(fast_v4)]),
        ),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );

    let scripted = ScriptedUpstream::new(b"HTTP/1.1 200 OK\r\n\r\nhi");
    let released = Arc::new((StdMutex::new(false), Condvar::new()));
    let parked = Arc::new(AtomicBool::new(false));
    let dialer = Arc::new(GatedDialer {
        inner: scripted.clone(),
        gate_addr: SocketAddr::new(std::net::IpAddr::V4(slow_v4), 443),
        released: Arc::clone(&released),
        parked: Arc::clone(&parked),
    });

    let c2s: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
    let s2c: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
    let stack_device = Box::new(PipeTunDevice {
        inbound: Arc::clone(&c2s),
        outbound: Arc::clone(&s2c),
        mtu: MTU,
    });
    let mut stack = FakeIpStack::new(stack_device, &pool, relay, dialer, StackWaker::new());

    let mut client_device = PipeClientDevice {
        inbound: Arc::clone(&s2c),
        outbound: Arc::clone(&c2s),
        mtu: usize::from(MTU),
    };
    let config = Config::new(HardwareAddress::Ip);
    let mut client = Interface::new(config, &mut client_device, SmolInstant::from_millis(0));
    client.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(client_addr), 24));
    });
    let _ = client
        .routes_mut()
        .add_default_ipv4_route(std::net::Ipv4Addr::new(10, 0, 0, 2));

    let mut client_sockets = SocketSet::new(Vec::new());
    let make_socket = || {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        )
    };
    let slow_handle = client_sockets.add(make_socket());
    let fast_handle = client_sockets.add(make_socket());
    client_sockets
        .get_mut::<tcp::Socket>(slow_handle)
        .connect(client.context(), (IpAddress::Ipv4(slow_v4), 443), 49700)
        .expect("slow connect initiates");

    let mut now_ms = 0u64;

    // Let the doomed flow's SYN reach the stack and its dial worker park.
    for _ in 0..2000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
        if parked.load(Ordering::SeqCst) {
            break;
        }
    }
    assert!(parked.load(Ordering::SeqCst), "the slow dial is in flight");

    // With the slow dial still parked, a second flow must splice end to end.
    client_sockets
        .get_mut::<tcp::Socket>(fast_handle)
        .connect(client.context(), (IpAddress::Ipv4(fast_v4), 443), 49701)
        .expect("fast connect initiates");

    let request = b"GET / HTTP/1.1\r\n\r\n";
    let mut response = Vec::new();
    let mut sent_request = false;
    for _ in 0..2000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        {
            let socket = client_sockets.get_mut::<tcp::Socket>(fast_handle);
            if socket.may_send() && !sent_request {
                socket.send_slice(request).expect("fast client send");
                sent_request = true;
            }
            let mut buf = [0u8; 1024];
            if socket.can_recv() {
                if let Ok(n) = socket.recv_slice(&mut buf) {
                    response.extend_from_slice(&buf[..n]);
                }
            }
        }
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
        if !response.is_empty() {
            break;
        }
    }
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "the fast flow spliced while the slow dial was parked, got {response:?}"
    );

    // Release the gate: the slow flow now completes too.
    {
        let (lock, cv) = &*released;
        *guard(lock) = true;
        cv.notify_all();
    }
    let mut slow_got_bytes = false;
    for _ in 0..2000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        {
            let socket = client_sockets.get_mut::<tcp::Socket>(slow_handle);
            let mut buf = [0u8; 1024];
            if socket.can_recv() && matches!(socket.recv_slice(&mut buf), Ok(n) if n > 0) {
                slow_got_bytes = true;
            }
        }
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
        if slow_got_bytes {
            break;
        }
    }
    assert!(
        slow_got_bytes,
        "the slow flow completes once its dial returns"
    );
    assert_eq!(scripted.dials().len(), 2, "both upstreams were dialled");
}

#[test]
fn a_client_udp_datagram_is_relayed_and_the_reply_comes_back() {
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

    const MTU: u16 = 1500;
    let client_addr = std::net::Ipv4Addr::new(10, 0, 0, 1);

    let mut allocator = FakeIpAllocator::default();
    let binding = allocator.allocate("voice.test").expect("allocate");
    let fake_v4 = binding.v4;

    let pool = FakeIpPoolConfig::default();
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            relay::StaticUpstreamResolver::new()
                .with("voice.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );

    let dialer = dialer::MockRelayDialer::new();
    dialer.set_response(b"udp-reply");
    let dialer = Arc::new(dialer);

    let c2s: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
    let s2c: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));

    let stack_device = Box::new(PipeTunDevice {
        inbound: Arc::clone(&c2s),
        outbound: Arc::clone(&s2c),
        mtu: MTU,
    });
    let mut stack = FakeIpStack::new(
        stack_device,
        &pool,
        relay,
        Arc::clone(&dialer) as Arc<dyn dialer::RelayDialer>,
        StackWaker::new(),
    );

    let mut client_device = PipeClientDevice {
        inbound: Arc::clone(&s2c),
        outbound: Arc::clone(&c2s),
        mtu: usize::from(MTU),
    };
    let config = Config::new(HardwareAddress::Ip);
    let mut client = Interface::new(config, &mut client_device, SmolInstant::from_millis(0));
    client.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(client_addr), 24));
    });
    let _ = client
        .routes_mut()
        .add_default_ipv4_route(std::net::Ipv4Addr::new(10, 0, 0, 2));

    let mut client_sockets = SocketSet::new(Vec::new());
    let socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]),
    );
    let handle = client_sockets.add(socket);
    client_sockets
        .get_mut::<udp::Socket>(handle)
        .bind(51000)
        .expect("client udp bind");

    let request = b"quic-initial";
    let mut sent = false;
    let mut reply = Vec::new();
    let mut now_ms = 0u64;

    for _ in 0..2000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        {
            let socket = client_sockets.get_mut::<udp::Socket>(handle);
            if socket.can_send() && !sent {
                socket
                    .send_slice(request, (IpAddress::Ipv4(fake_v4), 443))
                    .expect("client send");
                sent = true;
            }
            let mut buf = [0u8; 1024];
            if socket.can_recv() {
                if let Ok((n, _meta)) = socket.recv_slice(&mut buf) {
                    reply.extend_from_slice(&buf[..n]);
                }
            }
        }
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
        if sent && !reply.is_empty() && !dialer.written().is_empty() {
            break;
        }
    }

    assert_eq!(
        dialer.written(),
        request,
        "the client's datagram reached the real upstream"
    );
    assert_eq!(
        reply, b"udp-reply",
        "the upstream's reply reached the client"
    );
    assert_eq!(dialer.dials().len(), 1);
    assert_eq!(dialer.dials()[0].hostname, "voice.test");
}
