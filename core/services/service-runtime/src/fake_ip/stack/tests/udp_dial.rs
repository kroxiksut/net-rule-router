use super::*;

// ── A UDP dial that resolves slowly must not stall the poll thread ───────

const SLOW_HOST: &str = "slow.test";
const FAST_HOST: &str = "fast.test";

/// Holds the slow host's dial until opened — the stand-in for a resolver
/// chain inside `connect_udp` that takes seconds under a slow upstream.
#[derive(Default)]
struct DialGate {
    open: StdMutex<bool>,
    opened: Condvar,
    entered: AtomicBool,
}

impl DialGate {
    fn release(&self) {
        *guard(&self.open) = true;
        self.opened.notify_all();
    }
}

type SentByHost = Arc<StdMutex<HashMap<String, Vec<Vec<u8>>>>>;

struct GatedUdpDialer {
    gate: Arc<DialGate>,
    sent: SentByHost,
}

impl GatedUdpDialer {
    fn sent_to(&self, host: &str) -> Vec<Vec<u8>> {
        guard(&self.sent).get(host).cloned().unwrap_or_default()
    }
}

impl RelayDialer for GatedUdpDialer {
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
        target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn RelayDatagram>, RelayError> {
        if target.hostname == SLOW_HOST {
            self.gate.entered.store(true, Ordering::SeqCst);
            // Capped so a broken test fails instead of hanging.
            let deadline = StdInstant::now() + Duration::from_secs(10);
            let mut open = guard(&self.gate.open);
            while !*open && StdInstant::now() < deadline {
                let (next, _) = self
                    .gate
                    .opened
                    .wait_timeout(open, Duration::from_millis(50))
                    .unwrap_or_else(PoisonError::into_inner);
                open = next;
            }
        }
        Ok(Box::new(RecordingDatagram {
            host: target.hostname.clone(),
            sent: Arc::clone(&self.sent),
            replied: AtomicBool::new(false),
        }))
    }
}

/// Records what the relay sends and answers the first datagram once.
struct RecordingDatagram {
    host: String,
    sent: SentByHost,
    replied: AtomicBool,
}

impl RelayDatagram for RecordingDatagram {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError> {
        guard(&self.sent)
            .entry(self.host.clone())
            .or_default()
            .push(payload.to_vec());
        Ok(payload.len())
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize, RelayError> {
        let has_request = guard(&self.sent)
            .get(&self.host)
            .is_some_and(|sent| !sent.is_empty());
        if !has_request || self.replied.swap(true, Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
            return Err(RelayError::WouldBlock);
        }
        let reply = format!("{}-reply", self.host);
        let n = reply.len().min(buffer.len());
        buffer[..n].copy_from_slice(&reply.as_bytes()[..n]);
        Ok(n)
    }
}

/// A client talking to two fake endpoints through one stack.
struct TwoHostHarness {
    stack: FakeIpStack,
    client: Interface,
    client_device: PipeClientDevice,
    client_sockets: SocketSet<'static>,
    handle: SocketHandle,
    slow: std::net::Ipv4Addr,
    fast: std::net::Ipv4Addr,
    now_ms: u64,
}

impl TwoHostHarness {
    fn new(dialer: Arc<dyn RelayDialer>) -> Self {
        use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};
        const MTU: u16 = 1500;

        let mut allocator = FakeIpAllocator::default();
        let slow = allocator.allocate(SLOW_HOST).expect("allocate slow").v4;
        let fast = allocator.allocate(FAST_HOST).expect("allocate fast").v4;
        let relay = RelayCore::new(
            Arc::new(StdMutex::new(allocator)),
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(
                relay::StaticUpstreamResolver::new()
                    .with(SLOW_HOST, &["192.0.2.10".parse().expect("address")])
                    .with(FAST_HOST, &["192.0.2.20".parse().expect("address")]),
            ),
            Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
        );

        let c2s: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
        let s2c: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
        let stack = FakeIpStack::new(
            Box::new(PipeTunDevice {
                inbound: Arc::clone(&c2s),
                outbound: Arc::clone(&s2c),
                mtu: MTU,
            }),
            &FakeIpPoolConfig::default(),
            relay,
            dialer,
            StackWaker::new(),
        );

        let mut client_device = PipeClientDevice {
            inbound: s2c,
            outbound: c2s,
            mtu: usize::from(MTU),
        };
        let mut client = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut client_device,
            SmolInstant::from_millis(0),
        );
        client.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                24,
            ));
        });
        let _ = client
            .routes_mut()
            .add_default_ipv4_route(std::net::Ipv4Addr::new(10, 0, 0, 2));
        let mut client_sockets = SocketSet::new(Vec::new());
        let handle = client_sockets.add(udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8192]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8192]),
        ));
        client_sockets
            .get_mut::<udp::Socket>(handle)
            .bind(51000)
            .expect("client udp bind");

        Self {
            stack,
            client,
            client_device,
            client_sockets,
            handle,
            slow,
            fast,
            now_ms: 0,
        }
    }

    fn send(&mut self, to: std::net::Ipv4Addr, payload: &[u8]) {
        self.client_sockets
            .get_mut::<udp::Socket>(self.handle)
            .send_slice(payload, (IpAddress::Ipv4(to), 443))
            .expect("client send");
    }

    /// One round: the client polls, the stack steps. Every step is timed —
    /// the claim under test is that none of them waits on a dial.
    fn tick(&mut self) -> Vec<Vec<u8>> {
        self.now_ms += 5;
        let t = SmolInstant::from_millis(i64::try_from(self.now_ms).unwrap_or(i64::MAX));
        self.client
            .poll(t, &mut self.client_device, &mut self.client_sockets);
        for _ in 0..4 {
            let started = StdInstant::now();
            self.stack.step(self.now_ms).expect("stack step");
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "a step took {:?} — the poll thread waited on a dial",
                started.elapsed()
            );
        }
        self.client
            .poll(t, &mut self.client_device, &mut self.client_sockets);
        let mut received = Vec::new();
        let socket = self.client_sockets.get_mut::<udp::Socket>(self.handle);
        let mut buf = [0u8; 256];
        while let Ok((n, _)) = socket.recv_slice(&mut buf) {
            received.push(buf[..n].to_vec());
        }
        std::thread::sleep(Duration::from_millis(1));
        received
    }

    fn held_for_slow(&self) -> usize {
        self.stack
            .udp_binds
            .get(&(std::net::IpAddr::V4(self.slow), 443))
            .map_or(0, |bind| {
                bind.pending.values().map(|p| p.queued.len()).sum()
            })
    }
}

fn gated_dialer() -> (Arc<GatedUdpDialer>, Arc<DialGate>) {
    let gate = Arc::new(DialGate::default());
    let dialer = Arc::new(GatedUdpDialer {
        gate: Arc::clone(&gate),
        sent: Arc::default(),
    });
    (dialer, gate)
}

#[test]
fn a_slow_udp_dial_leaves_other_flows_running_and_delivers_once_it_lands() {
    let (dialer, gate) = gated_dialer();
    let mut harness = TwoHostHarness::new(Arc::clone(&dialer) as Arc<dyn RelayDialer>);

    harness.send(harness.slow, b"slow-initial");
    for _ in 0..400 {
        harness.tick();
        if gate.entered.load(Ordering::SeqCst) {
            break;
        }
    }
    assert!(gate.entered.load(Ordering::SeqCst), "the slow dial started");

    // While that dial sits in resolution, another flow is carried end to end.
    harness.send(harness.fast, b"fast-initial");
    let mut fast_reply = Vec::new();
    for _ in 0..400 {
        fast_reply.extend(harness.tick());
        if !fast_reply.is_empty() {
            break;
        }
    }
    assert_eq!(fast_reply, vec![b"fast.test-reply".to_vec()]);
    assert!(
        dialer.sent_to(SLOW_HOST).is_empty(),
        "nothing reaches the slow upstream before its dial lands"
    );
    assert_eq!(harness.held_for_slow(), 1, "the datagram is held, not lost");

    gate.release();
    let mut slow_reply = Vec::new();
    for _ in 0..400 {
        slow_reply.extend(harness.tick());
        if !slow_reply.is_empty() {
            break;
        }
    }
    assert_eq!(dialer.sent_to(SLOW_HOST), vec![b"slow-initial".to_vec()]);
    assert_eq!(slow_reply, vec![b"slow.test-reply".to_vec()]);
    assert_eq!(dialer.sent_to(FAST_HOST), vec![b"fast-initial".to_vec()]);
}

#[test]
fn datagrams_past_the_hold_bound_are_dropped_while_the_dial_runs() {
    let (dialer, gate) = gated_dialer();
    let mut harness = TwoHostHarness::new(Arc::clone(&dialer) as Arc<dyn RelayDialer>);

    let payloads: Vec<Vec<u8>> = (0..UDP_PENDING_DIAL_QUEUE + 4)
        .map(|i| format!("datagram-{i}").into_bytes())
        .collect();
    for payload in &payloads {
        harness.send(harness.slow, payload);
        // Two rounds per datagram: the client emits it, the stack takes it.
        harness.tick();
        harness.tick();
    }
    assert!(gate.entered.load(Ordering::SeqCst), "the slow dial started");
    assert_eq!(harness.held_for_slow(), UDP_PENDING_DIAL_QUEUE);

    gate.release();
    for _ in 0..400 {
        harness.tick();
        if dialer.sent_to(SLOW_HOST).len() >= UDP_PENDING_DIAL_QUEUE {
            break;
        }
    }
    // A few more rounds, so a late extra datagram would have had its chance.
    for _ in 0..10 {
        harness.tick();
    }
    assert_eq!(
        dialer.sent_to(SLOW_HOST),
        payloads[..UDP_PENDING_DIAL_QUEUE].to_vec(),
        "the held datagrams go out oldest first; the overflow was dropped"
    );
}
