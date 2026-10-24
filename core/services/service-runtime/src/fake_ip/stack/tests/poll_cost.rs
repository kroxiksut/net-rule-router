use super::*;

// ── The cost of one poll: how many flows does a step visit? ──────────────────

/// Park an idle flow in the stack without dialing anything: a listening socket
/// plus its shared state, exactly as `maybe_open_flow` leaves a flow whose dial
/// is still in flight. Enough to be walked by the pump, which is what is being
/// measured.
fn park_idle_flow(stack: &mut FakeIpStack, client_port: u16) -> FlowKey {
    let fake = std::net::Ipv4Addr::new(198, 18, 0, 7);
    let key = FlowKey {
        protocol: FlowProtocol::Tcp,
        source: SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), client_port)),
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
                hostname: "parked.example".to_owned(),
                site: "parked.example".to_owned(),
                book_route: Some(nrr_shared::RouteRole::Primary),
                owner: None,
            },
            client_close_sent: false,
            abort_sent: false,
        },
    );
    key
}

fn idle_stack_with_flows(count: u16, health: &Arc<health::FakeIpHealth>) -> FakeIpStack {
    let (device, _state) = open_mock_device();
    let mut stack = FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        RelayCore::new(
            Arc::new(StdMutex::new(
                nrr_platform_api::fake_ip::FakeIpAllocator::default(),
            )),
            nrr_platform_api::fake_ip::FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(relay::StaticUpstreamResolver::new()),
            Arc::new(relay::FixedRouteSelector(nrr_shared::RouteRole::Primary)),
        ),
        Arc::new(dialer::MockRelayDialer::new()),
        StackWaker::new(),
    )
    .with_health(Arc::clone(health));
    for port in 0..count {
        park_idle_flow(&mut stack, 40_000 + port);
    }
    stack
}

/// A step must cost the flows it has work for, not the flows that exist —
/// walking every parked flow on every step would make a busy relay pay for
/// every idle connection on the machine.
#[test]
fn an_idle_step_visits_no_flows_however_many_are_parked() {
    const FLOWS: u16 = 300;
    let health = Arc::new(health::FakeIpHealth::new());
    let mut stack = idle_stack_with_flows(FLOWS, &health);
    // The first step is the periodic sweep (last sweep at 0), so start after it.
    stack.step(1).expect("step");
    let after_sweep = health.tcp_flow_visits();

    for step in 0..100u64 {
        stack.step(2 + step).expect("step");
    }
    assert_eq!(
        health.tcp_flow_visits(),
        after_sweep,
        "100 idle steps over {FLOWS} parked flows must visit none of them",
    );
}

/// The sweep is the safety net, and it is the one thing that still costs the
/// whole map — once a second, not once a packet.
#[test]
fn the_periodic_sweep_visits_every_flow() {
    const FLOWS: u16 = 300;
    let health = Arc::new(health::FakeIpHealth::new());
    let mut stack = idle_stack_with_flows(FLOWS, &health);
    stack.step(1).expect("step");
    let before = health.tcp_flow_visits();

    stack.step(1 + FLOW_SWEEP_INTERVAL_MS).expect("step");

    assert_eq!(
        health.tcp_flow_visits() - before,
        u64::from(FLOWS),
        "the sweep visits every parked flow exactly once",
    );
}

/// A flow whose upstream spoke has work even though no packet arrived for it —
/// the worker says so. Without that the flow would wait for the next sweep, and
/// a failed dial would sit on the client for up to a second.
#[test]
fn a_flow_its_worker_woke_is_serviced_before_the_next_sweep() {
    let health = Arc::new(health::FakeIpHealth::new());
    let mut stack = idle_stack_with_flows(5, &health);
    stack.step(1).expect("step");
    let before = health.tcp_flow_visits();

    let key = *stack.flows.keys().next().expect("a parked flow");
    stack.flows[&key].shared.signal_dial_failed();
    stack.step(2).expect("step");

    assert_eq!(
        health.tcp_flow_visits() - before,
        1,
        "exactly the woken flow is visited",
    );
    // Aborted on this step, reaped on the next one it asks for itself.
    stack.step(3).expect("step");
    assert!(
        !stack.flows.contains_key(&key),
        "the failed flow is reaped without waiting for the sweep",
    );
}

/// Park a UDP bind whose one client is still dialling, so the reap keeps it.
fn park_udp_bind(stack: &mut FakeIpStack, port: u16) -> UdpBindKey {
    let key: UdpBindKey = (
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 8)),
        port,
    );
    let make_buffer = || {
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
            vec![0u8; 256],
        )
    };
    let mut socket = udp::Socket::new(make_buffer(), make_buffer());
    let local = smoltcp_address(key.0);
    socket
        .bind(IpListenEndpoint {
            addr: Some(local),
            port,
        })
        .expect("bind");
    let handle = stack.sockets.add(socket);
    stack.udp_binds.insert(
        key,
        UdpBind {
            handle,
            local,
            target: dialer::UpstreamTarget::at(
                "parked.example".to_owned(),
                "203.0.113.5:443".parse().expect("address"),
                nrr_shared::RouteRole::Primary,
            ),
            clients: HashMap::new(),
            pending: HashMap::from([(
                SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), port)),
                PendingUdpDial {
                    outcome: Arc::new(Mutex::new(None)),
                    book_route: Some(nrr_shared::RouteRole::Primary),
                    owner: None,
                    queued: VecDeque::new(),
                    first_payload_len: 0,
                    started_at: std::time::Instant::now(),
                },
            )]),
        },
    );
    key
}

/// UDP pays per bind with work, like TCP: a browser's QUIC binds are not all
/// walked on every packet of every other flow.
#[test]
fn an_idle_step_visits_no_udp_binds_and_the_sweep_visits_them_all() {
    const BINDS: u16 = 100;
    let health = Arc::new(health::FakeIpHealth::new());
    let mut stack = idle_stack_with_flows(0, &health);
    let keys: Vec<UdpBindKey> = (0..BINDS)
        .map(|n| park_udp_bind(&mut stack, 20_000 + n))
        .collect();
    stack.step(1).expect("step");
    let parked = health.udp_bind_visits();

    for step in 0..100u64 {
        stack.step(2 + step).expect("step");
    }
    assert_eq!(health.udp_bind_visits(), parked, "idle steps visit no bind");

    stack.ready_udp.mark(keys[0]);
    stack.step(200).expect("step");
    assert_eq!(
        health.udp_bind_visits() - parked,
        1,
        "exactly the marked bind"
    );

    stack.step(200 + FLOW_SWEEP_INTERVAL_MS).expect("step");
    assert_eq!(
        health.udp_bind_visits() - parked,
        1 + u64::from(BINDS),
        "the sweep visits every bind once"
    );
    assert_eq!(
        stack.udp_binds.len(),
        usize::from(BINDS),
        "dialling binds are kept"
    );
}

/// Benchmark, kept runnable rather than quoted: 300 parked flows, 20 000
/// steps, comparing event-driven servicing (only flows with work) against
/// sweeping every flow each step. Ignored by default — a measurement, not an
/// assertion.
///
/// `cargo test -p nrr-service-runtime --lib the_pump_cost_at_scale -- --ignored --nocapture`
#[test]
#[ignore = "measurement, not an assertion"]
fn the_pump_cost_at_scale() {
    const FLOWS: u16 = 300;
    const STEPS: u64 = 20_000;

    let health = Arc::new(health::FakeIpHealth::new());
    let mut stack = idle_stack_with_flows(FLOWS, &health);
    let started = std::time::Instant::now();
    for step in 0..STEPS {
        stack.step(step).expect("step");
    }
    let event_driven = started.elapsed();
    let event_visits = health.tcp_flow_visits();

    let health = Arc::new(health::FakeIpHealth::new());
    let mut stack = idle_stack_with_flows(FLOWS, &health);
    let started = std::time::Instant::now();
    for step in 0..STEPS {
        stack.last_flow_sweep_ms = 0;
        stack.step(FLOW_SWEEP_INTERVAL_MS + step).expect("step");
    }
    let walk_everything = started.elapsed();

    eprintln!("{FLOWS} flows x {STEPS} steps");
    eprintln!("  event-driven:     {event_driven:?} over {event_visits} flow visits");
    eprintln!(
        "  walk-everything:  {walk_everything:?} over {} flow visits",
        health.tcp_flow_visits(),
    );
}
