use super::*;

// ── Port-unreachable for datagrams the relay cannot carry ────────────────

#[test]
fn a_v4_port_unreachable_quotes_the_offending_datagram() {
    let fake: SocketAddr = "198.18.0.7:443".parse().expect("fake endpoint");
    let client: SocketAddr = "10.0.0.1:51000".parse().expect("client endpoint");
    let mut out = [0u8; UNREACHABLE_MAX_BYTES];
    let len = build_port_unreachable(fake, client, 1200, &mut out).expect("v4 unreachable");

    let packet = Ipv4Packet::new_checked(&out[..len]).expect("valid ipv4");
    assert_eq!(packet.next_header(), IpProtocol::Icmp);
    assert_eq!(
        std::net::IpAddr::V4(packet.src_addr()),
        fake.ip(),
        "the error comes FROM the address the client dialed"
    );
    assert_eq!(std::net::IpAddr::V4(packet.dst_addr()), client.ip());
    assert!(packet.verify_checksum(), "outer header checksum is filled");

    let icmp = Icmpv4Packet::new_checked(packet.payload()).expect("valid icmpv4");
    assert!(icmp.verify_checksum(), "icmp checksum is filled");
    assert_eq!(icmp.msg_type(), Icmpv4Message::DstUnreachable);
    assert_eq!(
        icmp.msg_code(),
        u8::from(Icmpv4DstUnreachable::PortUnreachable)
    );

    // The quote must read as the client's own outbound datagram, or the
    // receiving stack cannot match the error to the socket that sent it.
    // Read off the wire rather than through `Icmpv4Repr::parse`: a quote
    // carries the ORIGINAL total length over only its first 8 payload
    // bytes, which that parser rejects (and `smoltcp` emits the same shape
    // for the unreachables it generates itself).
    let quoted = Ipv4Packet::new_unchecked(icmp.data());
    assert_eq!(std::net::IpAddr::V4(quoted.src_addr()), client.ip());
    assert_eq!(std::net::IpAddr::V4(quoted.dst_addr()), fake.ip());
    assert_eq!(quoted.next_header(), IpProtocol::Udp);
    assert_eq!(
        usize::from(quoted.total_len()),
        20 + UDP_HEADER_BYTES + 1200,
        "the quote keeps the offending datagram's real length"
    );

    let quoted_udp = &out[len - UDP_HEADER_BYTES..len];
    assert_eq!(
        u16::from_be_bytes([quoted_udp[0], quoted_udp[1]]),
        client.port()
    );
    assert_eq!(
        u16::from_be_bytes([quoted_udp[2], quoted_udp[3]]),
        fake.port()
    );
}

#[test]
fn a_v6_port_unreachable_quotes_the_offending_datagram() {
    let fake: SocketAddr = "[fc00::7]:443".parse().expect("fake endpoint");
    let client: SocketAddr = "[fc00::1]:51000".parse().expect("client endpoint");
    let mut out = [0u8; UNREACHABLE_MAX_BYTES];
    let len = build_port_unreachable(fake, client, 1200, &mut out).expect("v6 unreachable");

    let packet = Ipv6Packet::new_checked(&out[..len]).expect("valid ipv6");
    assert_eq!(packet.next_header(), IpProtocol::Icmpv6);
    assert_eq!(std::net::IpAddr::V6(packet.src_addr()), fake.ip());
    assert_eq!(std::net::IpAddr::V6(packet.dst_addr()), client.ip());

    let icmp = Icmpv6Packet::new_checked(packet.payload()).expect("valid icmpv6");
    let repr = Icmpv6Repr::parse(
        &packet.src_addr(),
        &packet.dst_addr(),
        &icmp,
        &ChecksumCapabilities::default(),
    )
    .expect("icmp repr");
    let Icmpv6Repr::DstUnreachable { reason, header, .. } = repr else {
        panic!("expected a destination-unreachable message");
    };
    assert_eq!(reason, Icmpv6DstUnreachable::PortUnreachable);
    assert_eq!(std::net::IpAddr::V6(header.src_addr), client.ip());
    assert_eq!(std::net::IpAddr::V6(header.dst_addr), fake.ip());
}

#[test]
fn a_port_unreachable_is_not_built_across_ip_families() {
    let fake: SocketAddr = "198.18.0.7:443".parse().expect("fake endpoint");
    let client: SocketAddr = "[fc00::1]:51000".parse().expect("client endpoint");
    let mut out = [0u8; UNREACHABLE_MAX_BYTES];
    assert!(build_port_unreachable(fake, client, 0, &mut out).is_none());
    // A buffer too small must be declined, never truncated onto the wire.
    let mut tiny = [0u8; 8];
    let client_v4: SocketAddr = "10.0.0.1:51000".parse().expect("client endpoint");
    assert!(build_port_unreachable(fake, client_v4, 0, &mut tiny).is_none());
}

/// A dialer whose UDP upstream accepts the dial but refuses every send —
/// the shape of a route torn down under an established flow.
struct DeadSendDialer;

struct DeadSendDatagram;

impl RelayDatagram for DeadSendDatagram {
    fn send(&self, _payload: &[u8]) -> Result<usize, RelayError> {
        Err(RelayError::Upstream {
            detail: "upstream socket is gone".to_string(),
        })
    }
    fn receive(&self, _buffer: &mut [u8]) -> Result<usize, RelayError> {
        Err(RelayError::WouldBlock)
    }
}

/// Upstream that accepts datagrams but whose reader dies at once — the
/// Windows shape: `send` keeps succeeding after an ICMP port-unreachable,
/// only `recv` reports the reset.
struct DeadReadDatagram;

impl RelayDatagram for DeadReadDatagram {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError> {
        Ok(payload.len())
    }
    fn receive(&self, _buffer: &mut [u8]) -> Result<usize, RelayError> {
        Err(RelayError::Upstream {
            detail: "connection reset by peer".to_string(),
        })
    }
}

struct DeadReadDialer;

impl RelayDialer for DeadReadDialer {
    fn connect_tcp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, RelayError> {
        Err(RelayError::Upstream {
            detail: "tcp not used in this test".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn RelayDatagram>, RelayError> {
        Ok(Box::new(DeadReadDatagram))
    }
}

impl RelayDialer for DeadSendDialer {
    fn connect_tcp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, RelayError> {
        Err(RelayError::Upstream {
            detail: "tcp not used in this test".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn RelayDatagram>, RelayError> {
        Ok(Box::new(DeadSendDatagram))
    }
}

/// Drive one client datagram to `fake_v4:443` through a stack built over
/// `dialer`, and return every client-bound packet the stack emitted.
fn client_bound_after_udp_datagrams(
    dialer: Arc<dyn RelayDialer>,
    health: &Arc<health::FakeIpHealth>,
    datagrams: usize,
    ready_for_next: &dyn Fn(&FakeIpStack) -> bool,
) -> Vec<Vec<u8>> {
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

    let c2s: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
    let s2c: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));

    let stack_device = Box::new(PipeTunDevice {
        inbound: Arc::clone(&c2s),
        outbound: Arc::clone(&s2c),
        mtu: MTU,
    });
    let mut stack = FakeIpStack::new(stack_device, &pool, relay, dialer, StackWaker::new())
        .with_health(Arc::clone(health));

    let mut client_device = PipeClientDevice {
        inbound: Arc::new(StdMutex::new(VecDeque::new())),
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

    // The client's inbound queue is deliberately detached from `s2c` so the
    // stack's reply stays inspectable instead of being consumed by a poll.
    let mut sent = 0usize;
    let mut now_ms = 0u64;
    // Queue depth at the moment the LAST datagram went out. Waiting for the
    // queue to be non-empty instead would stop the loop on the reply to an
    // EARLIER datagram, which is a reply this caller has already seen — the
    // stack then never gets the steps its last datagram needs.
    let mut depth_at_last_send: Option<usize> = None;
    for _ in 0..200 {
        now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        client.poll(t, &mut client_device, &mut client_sockets);
        if sent < datagrams && (sent == 0 || ready_for_next(&stack)) {
            let socket = client_sockets.get_mut::<udp::Socket>(handle);
            if socket.can_send() {
                socket
                    .send_slice(b"quic-initial", (IpAddress::Ipv4(fake_v4), 443))
                    .expect("client send");
                sent += 1;
            }
        }
        if sent == datagrams && depth_at_last_send.is_none() {
            depth_at_last_send = Some(guard(&s2c).len());
        }
        for _ in 0..4 {
            stack.step(now_ms).expect("stack step");
        }
        if depth_at_last_send.is_some_and(|depth| guard(&s2c).len() > depth) {
            break;
        }
    }
    let emitted: Vec<Vec<u8>> = guard(&s2c).iter().cloned().collect();
    emitted
}

/// Whether a client-bound packet is an ICMPv4 port-unreachable.
fn is_port_unreachable(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new_checked(packet) else {
        return false;
    };
    if ip.next_header() != IpProtocol::Icmp {
        return false;
    }
    let Ok(icmp) = Icmpv4Packet::new_checked(ip.payload()) else {
        return false;
    };
    icmp.msg_type() == Icmpv4Message::DstUnreachable
        && icmp.msg_code() == u8::from(Icmpv4DstUnreachable::PortUnreachable)
}

#[test]
fn a_refused_udp_dial_tells_the_client_the_port_is_unreachable() {
    let dialer = dialer::MockRelayDialer::new();
    dialer.fail_dials("secondary adapter unresolved");
    let health = Arc::new(health::FakeIpHealth::new());
    let emitted = client_bound_after_udp_datagrams(
        Arc::new(dialer) as Arc<dyn RelayDialer>,
        &health,
        1,
        &|_| true,
    );

    assert!(
        emitted.iter().any(|p| is_port_unreachable(p)),
        "a dial the relay cannot make must not be a silent black hole"
    );
    assert_eq!(health.udp_unreachable_sent(), 1);
    assert_eq!(health.udp_dial_failed(), 1);
}

#[test]
fn a_dead_udp_upstream_retires_the_client_and_reports_unreachable() {
    let health = Arc::new(health::FakeIpHealth::new());
    let emitted = client_bound_after_udp_datagrams(
        Arc::new(DeadSendDialer) as Arc<dyn RelayDialer>,
        &health,
        1,
        &|_| true,
    );

    assert!(
        emitted.iter().any(|p| is_port_unreachable(p)),
        "an upstream that cannot take the datagram must reach the client as an error"
    );
    assert_eq!(health.udp_dial_ok(), 1, "the dial itself succeeded");
    assert_eq!(health.udp_unreachable_sent(), 1);
}

#[test]
fn a_hard_read_error_marks_the_udp_flow_dead() {
    let replies = UdpReplies::new(StackWaker::new());
    let worker = spawn_udp_reader(Arc::new(DeadReadDatagram), Arc::clone(&replies));
    worker.join().expect("reader thread");
    assert!(
        replies.is_dead(),
        "a reader that gives up silently leaves the client bound to a flow nobody reads"
    );
}

#[test]
fn a_client_whose_reader_died_is_retired_instead_of_kept_forever() {
    // `send` on this upstream never fails, so the old code refreshed
    // `last_seen_at` on every datagram and the idle reap never came.
    let health = Arc::new(health::FakeIpHealth::new());
    let probe = Arc::clone(&health);
    let _ = client_bound_after_udp_datagrams(
        Arc::new(DeadReadDialer) as Arc<dyn RelayDialer>,
        &health,
        2,
        // Send the second datagram only once the dead flow has actually been
        // reaped. "The reader returned an error" is one store earlier than
        // that, and sleeping over the gap is what made this test flaky: on a
        // loaded machine the second datagram still met a live flow, which
        // takes it and refreshes `last_seen_at` instead of re-dialing.
        &|stack| probe.udp_dial_ok() >= 1 && stack.udp_binds.is_empty(),
    );
    assert!(
        health.udp_dial_ok() >= 2,
        "the dead flow must be dropped and re-dialed, not kept and fed (dials: {})",
        health.udp_dial_ok()
    );
}
