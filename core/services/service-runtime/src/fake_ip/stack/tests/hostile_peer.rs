use super::*;

// ── What a remote peer or a hostile client can push at the stack ──────────
//
// A UDP peer shapes how fast replies arrive; a local client shapes how many
// dials start. Neither may grow the service or take the poll thread down.

/// A UDP upstream that always has a reply ready — a peer faster than any
/// poll loop.
struct FloodingDatagram;

impl RelayDatagram for FloodingDatagram {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError> {
        Ok(payload.len())
    }
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, RelayError> {
        let n = buffer.len().min(1024);
        buffer[..n].fill(0x51);
        Ok(n)
    }
}

#[test]
fn udp_replies_are_bounded_by_count_and_bytes_and_the_excess_is_counted() {
    let health = Arc::new(health::FakeIpHealth::new());
    let replies = UdpReplies::new(StackWaker::new(), Arc::clone(&health));
    let slots = UDP_REPLY_QUEUE_MAX_DATAGRAMS;

    // Count bound: small datagrams past the slot count are dropped.
    for _ in 0..slots {
        assert!(replies.push(&[1u8; 16]));
    }
    assert!(
        !replies.push(&[1u8; 16]),
        "one past the count bound is dropped"
    );
    assert_eq!(replies.queued(), (slots, 16 * slots));
    assert_eq!(health.udp_replies_dropped(), 1);

    // Draining makes room again, oldest first and intact.
    let drained = replies.drain();
    assert_eq!(drained.len(), slots);
    assert!(drained.iter().all(|d| d == &[1u8; 16]));
    assert_eq!(replies.queued(), (0, 0));

    // Byte bound: full-size datagrams fill it long before the count does.
    // Not a divisor of the bound, so room is left for a small one.
    let big = vec![2u8; 60_000];
    let fit = UDP_REPLY_QUEUE_MAX_BYTES / big.len();
    for _ in 0..fit {
        assert!(replies.push(&big));
    }
    assert!(!replies.push(&big), "one past the byte bound is dropped");
    assert!(
        replies.push(&[3u8; 8]),
        "a small one still fits under the byte bound"
    );
    assert_eq!(health.udp_replies_dropped(), 2);
    let (count, bytes) = replies.queued();
    assert_eq!(count, fit + 1);
    assert!(bytes <= UDP_REPLY_QUEUE_MAX_BYTES);
}

#[test]
fn a_udp_peer_faster_than_the_poll_loop_cannot_grow_the_reply_queue() {
    let health = Arc::new(health::FakeIpHealth::new());
    let replies = UdpReplies::new(StackWaker::new(), Arc::clone(&health));
    let worker =
        spawn_udp_reader(Arc::new(FloodingDatagram), Arc::clone(&replies)).expect("spawn reader");

    // Nobody drains: the queue must settle at its bound, not keep growing.
    std::thread::sleep(Duration::from_millis(100));
    let (count, bytes) = replies.queued();
    assert!(count <= UDP_REPLY_QUEUE_MAX_DATAGRAMS, "count {count}");
    assert!(bytes <= UDP_REPLY_QUEUE_MAX_BYTES, "bytes {bytes}");
    let dropped = health.udp_replies_dropped();
    assert!(dropped > 0, "the excess is dropped and counted");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        replies.queued(),
        (count, bytes),
        "a full queue stays full, not bigger"
    );
    assert!(
        health.udp_replies_dropped() > dropped,
        "the peer kept sending"
    );

    replies.mark_dead();
    let deadline = StdInstant::now() + Duration::from_secs(5);
    while !worker.is_finished() && StdInstant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        worker.is_finished(),
        "a flooding reader still notices teardown"
    );
    let _ = worker.join();
}

// ── Dials through a bounded pool ──────────────────────────────────────────

/// Holds every TCP dial until released, then fails it — the shape of a dial
/// to a dead host, which is what occupies a worker for the whole timeout.
#[derive(Default)]
struct HeldTcpDialer {
    open: StdMutex<bool>,
    opened: Condvar,
    entered: std::sync::atomic::AtomicUsize,
}

impl HeldTcpDialer {
    fn release(&self) {
        *guard(&self.open) = true;
        self.opened.notify_all();
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }
}

impl RelayDialer for HeldTcpDialer {
    fn connect_tcp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn dialer::RelayStream>, RelayError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let deadline = StdInstant::now() + Duration::from_secs(10);
        let mut open = guard(&self.open);
        while !*open && StdInstant::now() < deadline {
            let (next, _) = self
                .opened
                .wait_timeout(open, Duration::from_millis(20))
                .unwrap_or_else(PoisonError::into_inner);
            open = next;
        }
        Err(RelayError::Upstream {
            detail: "held dial released".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &dialer::UpstreamTarget,
    ) -> Result<Box<dyn RelayDatagram>, RelayError> {
        Err(RelayError::Upstream {
            detail: "udp not used in this test".to_string(),
        })
    }
}

/// A stack over the mock device with one relayable host, driven by hand.
fn stack_with(
    dialer: Arc<dyn RelayDialer>,
    health: &Arc<health::FakeIpHealth>,
) -> (FakeIpStack, std::net::Ipv4Addr) {
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};
    let mut allocator = FakeIpAllocator::default();
    let fake_v4 = allocator.allocate("held.test").expect("allocate").v4;
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            relay::StaticUpstreamResolver::new()
                .with("held.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );
    let (device, _state) = open_mock_device();
    let stack = FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        relay,
        dialer,
        StackWaker::new(),
    )
    .with_health(Arc::clone(health))
    .with_socket_buffer_bytes(1024);
    (stack, fake_v4)
}

fn syn(fake_v4: std::net::Ipv4Addr, port: u16) -> ParsedPacket {
    ParsedPacket {
        key: FlowKey {
            protocol: FlowProtocol::Tcp,
            source: SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), port)),
            destination: SocketAddr::from((fake_v4, 443)),
        },
        is_connection_open: true,
        payload_offset: 0,
    }
}

fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    let deadline = StdInstant::now() + Duration::from_secs(5);
    while !done() {
        if StdInstant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

#[test]
fn past_the_dial_pool_a_new_flow_fails_at_once_and_no_thread_is_started() {
    let health = Arc::new(health::FakeIpHealth::new());
    let dialer = Arc::new(HeldTcpDialer::default());
    let (stack, fake_v4) = stack_with(Arc::clone(&dialer) as Arc<dyn RelayDialer>, &health);
    let mut stack = stack.with_dial_pool_limits(1, 1);
    let refused_key = syn(fake_v4, 40_002).key;
    let queued_key = syn(fake_v4, 40_001).key;

    // One worker busy, one dial queued, the third has nowhere to go.
    stack.maybe_open_flow(&syn(fake_v4, 40_000), 0);
    assert!(wait_until(|| dialer.entered() == 1));
    stack.maybe_open_flow(&syn(fake_v4, 40_001), 0);
    stack.maybe_open_flow(&syn(fake_v4, 40_002), 0);

    assert_eq!(stack.dial_pool.live_workers(), 1, "the pool holds its cap");
    assert_eq!(stack.dial_pool.queued(), 1);
    assert_eq!(health.dial_pool_refused(), 1);
    assert_eq!(health.tcp_dial_failed(), 1, "a refused dial failed");
    let refused = stack
        .flows
        .get(&refused_key)
        .expect("the refused flow is kept so it can be reset");
    assert!(refused.shared.dial_has_failed());
    let queued = stack.flows.get(&queued_key).expect("queued flow");
    assert!(!queued.shared.dial_has_failed(), "still pending");
    assert_eq!(stack.flows.len(), 3);

    // The refused flow is reset on the next steps; the other two survive.
    for _ in 0..3 {
        stack.step(1_000).expect("step");
    }
    assert!(!stack.flows.contains_key(&refused_key));
    assert_eq!(stack.flows.len(), 2);

    // Released, the queued dial runs on the same single worker.
    dialer.release();
    assert!(wait_until(|| dialer.entered() == 2));
    assert!(wait_until(|| health.tcp_dial_failed() == 3));
    assert!(stack.dial_pool.live_workers() <= 1);
}

#[test]
fn a_dial_queued_behind_others_is_skipped_once_its_client_is_gone() {
    let health = Arc::new(health::FakeIpHealth::new());
    let dialer = Arc::new(HeldTcpDialer::default());
    let (stack, fake_v4) = stack_with(Arc::clone(&dialer) as Arc<dyn RelayDialer>, &health);
    let mut stack = stack.with_dial_pool_limits(1, 8);

    stack.maybe_open_flow(&syn(fake_v4, 40_000), 0);
    assert!(wait_until(|| dialer.entered() == 1));
    stack.maybe_open_flow(&syn(fake_v4, 40_001), 0);
    // The second client resets before its dial starts — the SYN+RST loop
    // that used to leave a thread behind for the whole connect timeout.
    let gone = stack
        .flows
        .remove(&syn(fake_v4, 40_001).key)
        .expect("queued flow");
    gone.shared.mark_dead();

    dialer.release();
    assert!(wait_until(|| health.tcp_dial_failed() == 1));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(dialer.entered(), 1, "no dial for a dead flow");
}

#[test]
fn a_thread_the_os_refuses_is_a_flow_error_not_a_panic() {
    let health = Arc::new(health::FakeIpHealth::new());
    let dialer = Arc::new(HeldTcpDialer::default());
    let (stack, fake_v4) = stack_with(Arc::clone(&dialer) as Arc<dyn RelayDialer>, &health);
    let mut stack = stack.with_dial_pool_limits(4, 4);
    stack.dial_pool.set_refuse_spawns(true);

    stack.maybe_open_flow(&syn(fake_v4, 40_000), 0);

    assert_eq!(health.worker_spawn_failed(), 1);
    assert_eq!(health.dial_pool_refused(), 1);
    assert_eq!(stack.dial_pool.live_workers(), 0);
    assert_eq!(stack.dial_pool.queued(), 0, "nobody can run it");
    let flow = stack
        .flows
        .get(&syn(fake_v4, 40_000).key)
        .expect("flow kept for the reset");
    assert!(flow.shared.dial_has_failed());
    assert_eq!(dialer.entered(), 0);

    // Once the OS gives threads again, dials resume on the same pool.
    stack.dial_pool.set_refuse_spawns(false);
    dialer.release();
    stack.maybe_open_flow(&syn(fake_v4, 40_001), 0);
    assert!(wait_until(|| dialer.entered() == 1));
}

// ── A poll step that panics ───────────────────────────────────────────────

/// A device whose first `panics_left` reads panic, then reads nothing.
struct PanickingDevice {
    panics_left: usize,
    reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl TunDevice for PanickingDevice {
    fn mtu(&self) -> u16 {
        1500
    }
    fn read_packet(&mut self, _buf: &mut [u8]) -> Result<usize, PlatformError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.panics_left > 0 {
            self.panics_left -= 1;
            panic!("device read panicked (test)");
        }
        Ok(0)
    }
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PlatformError> {
        Ok(packet.len())
    }
    fn control(&self) -> Arc<dyn nrr_platform_api::fake_ip::tun::TunControl> {
        Arc::new(NoopControl)
    }
}

fn stack_over(device: PanickingDevice, health: &Arc<health::FakeIpHealth>) -> FakeIpStack {
    let relay = RelayCore::new(
        Arc::new(StdMutex::new(
            nrr_platform_api::fake_ip::FakeIpAllocator::default(),
        )),
        nrr_platform_api::fake_ip::FakeIpScope::default(),
        Arc::new(relay::StaticUpstreamResolver::new()),
        Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
    );
    FakeIpStack::new(
        Box::new(device),
        &FakeIpPoolConfig::default(),
        relay,
        Arc::new(dialer::MockRelayDialer::new()),
        StackWaker::new(),
    )
    .with_health(Arc::clone(health))
}

#[test]
fn a_panicking_step_is_contained_and_the_run_loop_goes_on() {
    let health = Arc::new(health::FakeIpHealth::new());
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut stack = stack_over(
        PanickingDevice {
            panics_left: 2,
            reads: Arc::clone(&reads),
        },
        &health,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let run = std::thread::spawn(move || stack.run(&thread_stop));

    // Two steps panic; the loop must still be reading afterwards.
    assert!(
        wait_until(|| reads.load(Ordering::SeqCst) >= 4),
        "the loop stopped after the panics"
    );
    assert_eq!(health.poll_step_panics(), 2);
    stop.store(true, Ordering::SeqCst);
    let outcome = run.join().expect("the run thread must not unwind");
    assert!(
        outcome.is_ok(),
        "a contained panic is not a run-loop failure: {outcome:?}"
    );
}

#[test]
fn a_streak_of_panicking_steps_hands_the_stack_back_to_the_watchdog() {
    let health = Arc::new(health::FakeIpHealth::new());
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut stack = stack_over(
        PanickingDevice {
            panics_left: usize::MAX,
            reads,
        },
        &health,
    );
    let stop = AtomicBool::new(false);
    let outcome = stack.run(&stop);
    assert!(
        outcome.is_err(),
        "a broken stack must be rebuilt, not spun forever"
    );
    assert_eq!(
        health.poll_step_panics(),
        u64::from(MAX_CONSECUTIVE_STEP_PANICS),
        "the loop gives up exactly at the streak bound"
    );
}
