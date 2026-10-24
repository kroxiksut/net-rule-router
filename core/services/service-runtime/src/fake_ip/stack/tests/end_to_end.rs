use super::*;

// ── In-process end-to-end: a real TCP handshake through the stack ─────────
//
// A second smoltcp interface plays the application. It connects to a fake
// address; our stack accepts the connection, dials the mock upstream and
// splices. Everything runs in one process over an in-memory packet pipe —
// no TUN adapter, no network — but the handshake, checksums and TCP state
// machines are the real ones, so the splice wiring is genuinely exercised.

#[test]
fn a_client_connection_completes_the_handshake_and_splices_both_ways() {
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

    const MTU: u16 = 1500;
    let client_addr = std::net::Ipv4Addr::new(10, 0, 0, 1);

    // One binding: example.test -> a fake address.
    let mut allocator = FakeIpAllocator::default();
    let binding = allocator.allocate("example.test").expect("allocate");
    let fake_v4 = binding.v4;

    let pool = FakeIpPoolConfig::default();
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            relay::StaticUpstreamResolver::new()
                .with("example.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );

    let dialer = ScriptedUpstream::new(b"HTTP/1.1 200 OK\r\n\r\nhi");
    let dialer = Arc::new(dialer);

    // The shared packet pipe: c2s carries client->stack, s2c the reverse.
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

    // The client interface.
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
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 8192]),
        tcp::SocketBuffer::new(vec![0u8; 8192]),
    );
    let handle = client_sockets.add(socket);
    client_sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(client.context(), (IpAddress::Ipv4(fake_v4), 443), 49500)
        .expect("connect initiates");

    let request = b"GET / HTTP/1.1\r\n\r\n";
    let mut response = Vec::new();
    let mut sent_request = false;
    let mut now_ms = 0u64;

    for _ in 0..2000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        {
            let socket = client_sockets.get_mut::<tcp::Socket>(handle);
            if socket.may_send() && !sent_request {
                socket.send_slice(request).expect("client send");
                sent_request = true;
            }
            let mut buf = [0u8; 1024];
            if socket.can_recv() {
                if let Ok(n) = socket.recv_slice(&mut buf) {
                    response.extend_from_slice(&buf[..n]);
                }
            }
        }
        // Drain whatever the client just queued; each step takes one packet.
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
        if sent_request && !response.is_empty() && !dialer.written().is_empty() {
            break;
        }
    }

    assert_eq!(
        dialer.written(),
        request,
        "the client's request reached the real upstream"
    );
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "the upstream's response came back to the client, got {response:?}"
    );
    // Exactly one upstream was dialled, for the right hostname.
    assert_eq!(dialer.dials().len(), 1);
    assert_eq!(dialer.dials()[0].hostname, "example.test");
}

/// A dialer that refuses every upstream, for the fail-fast reset path.
struct RefusingDialer;
impl dialer::RelayDialer for RefusingDialer {
    fn connect_tcp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, dialer::RelayError> {
        Err(dialer::RelayError::Upstream {
            detail: "refused by test".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayDatagram>, dialer::RelayError> {
        Err(dialer::RelayError::Upstream {
            detail: "refused by test".to_string(),
        })
    }
}

#[test]
fn a_failed_dial_resets_the_client_instead_of_stalling_it() {
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

    const MTU: u16 = 1500;
    let client_addr = std::net::Ipv4Addr::new(10, 0, 0, 1);

    let mut allocator = FakeIpAllocator::default();
    let binding = allocator.allocate("dead.test").expect("allocate");
    let fake_v4 = binding.v4;

    let pool = FakeIpPoolConfig::default();
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            relay::StaticUpstreamResolver::new()
                .with("dead.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );

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
        Arc::new(RefusingDialer),
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
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 8192]),
        tcp::SocketBuffer::new(vec![0u8; 8192]),
    );
    let handle = client_sockets.add(socket);
    client_sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(client.context(), (IpAddress::Ipv4(fake_v4), 443), 49600)
        .expect("connect initiates");

    let mut now_ms = 0u64;
    let mut client_closed = false;
    for _ in 0..2000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        if client_sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed {
            client_closed = true;
            break;
        }
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    assert!(
        client_closed,
        "the client must be actively reset, not left to stall"
    );
    // The doomed flow is reaped, not leaked.
    for _ in 0..50 {
        stack.step(now_ms).expect("stack step");
        if stack.flow_count() == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(stack.flow_count(), 0, "the failed flow is reaped");
}

/// The upstream accepts the connection and then refuses every write: the
/// tunnel died, or the server reset an idle keep-alive connection just as the
/// browser wrote a new request on it. The program must see a reset, as from a
/// socket of its own, not a request that went nowhere.
struct WriteRefusingDialer;
struct WriteRefusingStream;
impl std::io::Read for WriteRefusingStream {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        std::thread::sleep(Duration::from_millis(20));
        Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
    }
}
impl std::io::Write for WriteRefusingStream {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl dialer::RelayWriteHalf for WriteRefusingStream {
    fn shutdown_write(&mut self) -> Result<(), dialer::RelayError> {
        Ok(())
    }
}
impl dialer::RelayStream for WriteRefusingStream {
    fn shutdown_write(&mut self) -> Result<(), dialer::RelayError> {
        Ok(())
    }
    fn into_split(self: Box<Self>) -> Result<dialer::RelaySplit, dialer::RelayError> {
        Ok(dialer::RelaySplit {
            reader: Box::new(WriteRefusingStream),
            writer: Box::new(WriteRefusingStream),
        })
    }
}
impl dialer::RelayDialer for WriteRefusingDialer {
    fn connect_tcp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, dialer::RelayError> {
        Ok(Box::new(WriteRefusingStream))
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

#[test]
fn an_upstream_that_refuses_the_write_resets_the_client() {
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

    const MTU: u16 = 1500;
    let client_addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
    let mut allocator = FakeIpAllocator::default();
    let fake_v4 = allocator.allocate("gone.test").expect("allocate").v4;
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            relay::StaticUpstreamResolver::new()
                .with("gone.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );
    let c2s: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
    let s2c: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
    let mut stack = FakeIpStack::new(
        Box::new(PipeTunDevice {
            inbound: Arc::clone(&c2s),
            outbound: Arc::clone(&s2c),
            mtu: MTU,
        }),
        &FakeIpPoolConfig::default(),
        relay,
        Arc::new(WriteRefusingDialer),
        StackWaker::new(),
    );
    let mut client_device = PipeClientDevice {
        inbound: Arc::clone(&s2c),
        outbound: Arc::clone(&c2s),
        mtu: usize::from(MTU),
    };
    let mut client = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut client_device,
        SmolInstant::from_millis(0),
    );
    client.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(client_addr), 24));
    });
    let _ = client
        .routes_mut()
        .add_default_ipv4_route(std::net::Ipv4Addr::new(10, 0, 0, 2));
    let mut client_sockets = SocketSet::new(Vec::new());
    let handle = client_sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 8192]),
        tcp::SocketBuffer::new(vec![0u8; 8192]),
    ));
    client_sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(client.context(), (IpAddress::Ipv4(fake_v4), 443), 49601)
        .expect("connect initiates");

    let mut now_ms = 0u64;
    let mut sent = false;
    let mut reset = false;
    for _ in 0..3000 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        let socket = client_sockets.get_mut::<tcp::Socket>(handle);
        if !sent && socket.state() == tcp::State::Established {
            sent = socket.send_slice(b"GET / HTTP/1.1\r\n\r\n").is_ok();
        }
        if sent && socket.state() == tcp::State::Closed {
            reset = true;
            break;
        }
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(sent, "the connection was established and the request sent");
    assert!(reset, "a write the server refused must reset the client");
}
