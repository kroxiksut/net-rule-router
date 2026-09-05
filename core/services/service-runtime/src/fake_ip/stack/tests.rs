//! Unit tests for [`super`] — the fake-IP stack.
//!
//! 1792 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

/// The half-close must not overtake the request it follows.
#[test]
fn a_half_close_waits_for_the_dial_that_carries_the_request() {
    for state in [
        tcp::State::CloseWait,
        tcp::State::Closing,
        tcp::State::LastAck,
        tcp::State::TimeWait,
    ] {
        assert!(
            !client_fin_may_propagate(false, state),
            "{state:?}: while the dial is in flight the client's bytes are still in the                  socket buffer, so forwarding the FIN sends the upstream home empty-handed",
        );
        assert!(client_fin_may_propagate(true, state), "{state:?}");
    }
    // Before the handshake completes there is no half-close to forward.
    for state in [
        tcp::State::Listen,
        tcp::State::SynReceived,
        tcp::State::Established,
    ] {
        assert!(!client_fin_may_propagate(true, state), "{state:?}");
    }
}
use super::*;
// The phy adapter moved to `super::phy`; the parent no longer imports its traits.
use nrr_platform_api::fake_ip::tun::{
    MockTunAdapter, MockTunState, TunAdapterConfig, TunAdapterPort,
};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::wire::Icmpv4Message;
use std::sync::Arc;

fn open_mock_device() -> (Box<dyn TunDevice>, Arc<MockTunState>) {
    let (adapter, state) = MockTunAdapter::new();
    let device = adapter
        .open(&TunAdapterConfig::default())
        .expect("mock open");
    (device, state)
}

#[test]
fn phy_device_delivers_an_ingested_packet_once() {
    let (device, _state) = open_mock_device();
    let mut phy = TunPhyDevice::new(device);
    assert_eq!(phy.mtu(), TunAdapterConfig::default().mtu);

    phy.ingest(vec![0x45, 0x00, 0x00, 0x14]);
    let now = SmolInstant::from_millis(0);
    let received = phy.receive(now);
    assert!(received.is_some(), "pending packet is delivered");
    let (rx, _tx) = received.expect("token pair");
    rx.consume(|bytes| assert_eq!(bytes, &[0x45, 0x00, 0x00, 0x14]));

    assert!(
        phy.receive(now).is_none(),
        "the lookahead holds exactly one packet"
    );
}

#[test]
fn phy_transmit_writes_to_the_underlying_device() {
    let (device, state) = open_mock_device();
    let mut phy = TunPhyDevice::new(device);
    let tx = phy.transmit(SmolInstant::from_millis(0)).expect("tx token");
    tx.consume(4, |buf| buf.copy_from_slice(&[1, 2, 3, 4]));
    assert_eq!(state.written_packets(), vec![vec![1, 2, 3, 4]]);
}

#[test]
fn phy_capabilities_report_ip_medium_and_mtu() {
    let (device, _state) = open_mock_device();
    let phy = TunPhyDevice::new(device);
    let caps = phy.capabilities();
    assert_eq!(caps.medium, Medium::Ip);
    assert_eq!(
        caps.max_transmission_unit,
        usize::from(TunAdapterConfig::default().mtu)
    );
}

#[test]
fn stack_waker_wakes_and_then_clears() {
    let waker = StackWaker::new();
    waker.wake();
    // Already signalled: returns immediately and clears the flag.
    waker.wait(std::time::Duration::from_millis(10));
    // No signal now: returns after the timeout without hanging. The bound
    // is well under the requested 20 ms on purpose — the claim is "it
    // waited rather than returning at once", and Windows timer granularity
    // (~15.6 ms) lets a 20 ms sleep come back just under a 15 ms threshold.
    let start = std::time::Instant::now();
    waker.wait(std::time::Duration::from_millis(20));
    assert!(start.elapsed() >= std::time::Duration::from_millis(5));
}

#[test]
fn upstream_reader_survives_timeouts_and_exits_on_dead() {
    // A stalled upstream surfaces as periodic TimedOut reads (production
    // sets a socket read timeout). Those must be teardown checks, not EOF:
    // the worker keeps waiting while the flow lives, and exits promptly
    // once the flow is marked dead — a reader parked in a blocking read
    // that no teardown could reach would wedge the poll thread when it
    // joined the worker.
    use crate::fake_ip::RelayWriteHalf;
    use std::io;
    use std::io::{Read, Write};

    struct StallingReader;
    impl Read for StallingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(10));
            Err(io::Error::from(io::ErrorKind::TimedOut))
        }
    }
    struct SinkWriter;
    impl Write for SinkWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl RelayWriteHalf for SinkWriter {
        fn shutdown_write(&mut self) -> Result<(), RelayError> {
            Ok(())
        }
    }

    let shared = FlowShared::new(StackWaker::new());
    let workers = spawn_upstream_workers(
        Arc::clone(&shared),
        RelaySplit {
            reader: Box::new(StallingReader),
            writer: Box::new(SinkWriter),
        },
    );
    std::thread::sleep(std::time::Duration::from_millis(60));
    assert!(
        !shared.upstream_eof.load(Ordering::SeqCst),
        "a read timeout must not be treated as upstream EOF"
    );
    shared.mark_dead();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    for worker in workers {
        while !worker.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            worker.is_finished(),
            "workers must exit promptly once the flow is dead"
        );
        let _ = worker.join();
    }
}

#[test]
fn a_hard_upstream_read_error_is_a_reset_not_an_eof() {
    // A body cut in half must not reach the client under a clean FIN: it
    // would parse as the whole answer, and a cache would keep it.
    use crate::fake_ip::RelayWriteHalf;
    use std::io;
    use std::io::{Read, Write};

    struct ResettingReader;
    impl Read for ResettingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::ConnectionReset))
        }
    }
    struct SinkWriter;
    impl Write for SinkWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl RelayWriteHalf for SinkWriter {
        fn shutdown_write(&mut self) -> Result<(), RelayError> {
            Ok(())
        }
    }

    let shared = FlowShared::new(StackWaker::new());
    let workers = spawn_upstream_workers(
        Arc::clone(&shared),
        RelaySplit {
            reader: Box::new(ResettingReader),
            writer: Box::new(SinkWriter),
        },
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !shared.upstream_was_reset() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        shared.upstream_was_reset(),
        "a hard error must signal reset"
    );
    assert!(
        !shared.upstream_eof.load(Ordering::SeqCst),
        "and must not also claim a clean end of the answer"
    );
    shared.mark_dead();
    for worker in workers {
        let _ = worker.join();
    }
}

#[test]
fn at_capacity_a_new_syn_is_refused_and_live_flows_are_kept() {
    // Evicting a live flow to admit a new one trades a working download for
    // a connection that may be a port scan; the cap exists to bound memory,
    // not to ration fairness.
    use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};
    const CAP: usize = 2;

    let health = Arc::new(super::super::health::FakeIpHealth::new());
    let mut allocator = FakeIpAllocator::default();
    let fake_v4 = allocator.allocate("voice.test").expect("allocate").v4;
    let relay = RelayCore::new(
        Arc::new(std::sync::Mutex::new(allocator)),
        FakeIpScope::enabled(Vec::<String>::new()),
        Arc::new(
            super::super::relay::StaticUpstreamResolver::new()
                .with("voice.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
    );
    let (device, _state) = open_mock_device();
    let mut stack = FakeIpStack::new(
        device,
        &FakeIpPoolConfig::default(),
        relay,
        Arc::new(super::super::dialer::MockRelayDialer::new()),
        StackWaker::new(),
    )
    .with_health(Arc::clone(&health))
    .with_socket_buffer_bytes(1024)
    .with_max_flows(CAP);

    let syn_from = |port: u16| ParsedPacket {
        key: FlowKey {
            protocol: FlowProtocol::Tcp,
            source: SocketAddr::from((std::net::Ipv4Addr::new(10, 0, 0, 1), port)),
            destination: SocketAddr::from((fake_v4, 443)),
        },
        is_connection_open: true,
        payload_offset: 0,
    };
    for port in 0..CAP {
        stack.maybe_open_flow(&syn_from(40_000 + u16::try_from(port).unwrap_or(0)), 0);
    }
    assert_eq!(stack.flows.len(), CAP, "the fixture must reach the cap");
    let before: Vec<_> = stack.flows.keys().copied().collect();

    stack.maybe_open_flow(&syn_from(50_000), 1_000);

    assert_eq!(
        stack.flows.len(),
        CAP,
        "the cap must hold — no socket for the new SYN"
    );
    assert_eq!(health.tcp_flows_refused_at_capacity(), 1);
    assert!(
        before.iter().all(|key| stack.flows.contains_key(key)),
        "no live flow may be evicted to make room"
    );
}

#[test]
fn a_reader_parks_while_the_client_bound_queue_is_full() {
    // Unbounded, this queue grew to whatever the upstream could deliver
    // while the client's socket stalled — memory instead of a closed window.
    use crate::fake_ip::RelayWriteHalf;
    use std::io;
    use std::io::{Read, Write};

    struct FloodingReader;
    impl Read for FloodingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(0x41);
            Ok(buf.len())
        }
    }
    struct SinkWriter;
    impl Write for SinkWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl RelayWriteHalf for SinkWriter {
        fn shutdown_write(&mut self) -> Result<(), RelayError> {
            Ok(())
        }
    }

    let shared = FlowShared::new(StackWaker::new());
    let workers = spawn_upstream_workers(
        Arc::clone(&shared),
        RelaySplit {
            reader: Box::new(FloodingReader),
            writer: Box::new(SinkWriter),
        },
    );
    // Nobody drains: the queue must settle just past the high-water mark
    // (one chunk of overshoot), not keep growing.
    std::thread::sleep(std::time::Duration::from_millis(120));
    let settled = guard(&shared.from_upstream).len();
    std::thread::sleep(std::time::Duration::from_millis(120));
    let later = guard(&shared.from_upstream).len();
    assert!(
        settled <= FLOW_QUEUE_HIGH_WATER_BYTES + PUMP_CHUNK_BYTES,
        "queue overshot its high-water mark: {settled}"
    );
    assert_eq!(settled, later, "a parked reader must not keep buffering");

    shared.mark_dead();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    for worker in workers {
        while !worker.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            worker.is_finished(),
            "a parked reader must still notice teardown"
        );
        let _ = worker.join();
    }
}

#[test]
fn flow_buffers_take_and_return_in_order() {
    let shared = FlowShared::new(StackWaker::new());
    shared.push_from_upstream(b"abcdef");
    let first = shared.take_from_upstream(3);
    assert_eq!(first, b"abc");
    // A partial send returns the tail to the front, preserving order.
    shared.return_from_upstream(b"bc");
    let rest = shared.take_from_upstream(16);
    assert_eq!(rest, b"bcdef");
    assert!(shared.upstream_queue_is_empty());
}

#[test]
fn a_step_with_no_traffic_reports_no_progress() {
    let (device, _state) = open_mock_device();
    let pool = FakeIpPoolConfig::default();
    let relay = RelayCore::new(
        Arc::new(std::sync::Mutex::new(
            nrr_platform_api::fake_ip::FakeIpAllocator::default(),
        )),
        nrr_platform_api::fake_ip::FakeIpScope::default(),
        Arc::new(super::super::relay::StaticUpstreamResolver::new()),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
    );
    let dialer = Arc::new(super::super::dialer::MockRelayDialer::new());
    let mut stack = FakeIpStack::new(device, &pool, relay, dialer, StackWaker::new());
    // Empty mock queue -> read returns 0 -> no packet processed this step.
    assert!(!stack.step(0).expect("step"), "idle step made no progress");
    assert_eq!(stack.flow_count(), 0);
}

// ── In-process end-to-end: a real TCP handshake through the stack ─────────
//
// A second smoltcp interface plays the application. It connects to a fake
// address; our stack accepts the connection, dials the mock upstream and
// splices. Everything runs in one process over an in-memory packet pipe —
// no TUN adapter, no network — but the handshake, checksums and TCP state
// machines are the real ones, so the splice wiring is genuinely exercised.

use std::collections::VecDeque;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant as StdInstant};

type PacketQueue = Arc<StdMutex<VecDeque<Vec<u8>>>>;

// A test upstream with realistic ordering: its reply is released only once
// the client's request has been written, so the request must be spliced out
// before the response comes back — exercising both directions in the order a
// real server would produce them (unlike a canned reply available instantly).
struct ScriptedState {
    response: Vec<u8>,
    written: StdMutex<Vec<u8>>,
    request_ready: Condvar,
    dials: StdMutex<Vec<super::super::dialer::UpstreamTarget>>,
}

#[derive(Clone)]
struct ScriptedUpstream {
    state: Arc<ScriptedState>,
}

impl ScriptedUpstream {
    fn new(response: &[u8]) -> Self {
        Self {
            state: Arc::new(ScriptedState {
                response: response.to_vec(),
                written: StdMutex::new(Vec::new()),
                request_ready: Condvar::new(),
                dials: StdMutex::new(Vec::new()),
            }),
        }
    }
    fn written(&self) -> Vec<u8> {
        guard(&self.state.written).clone()
    }
    fn dials(&self) -> Vec<super::super::dialer::UpstreamTarget> {
        guard(&self.state.dials).clone()
    }
}

impl super::super::dialer::RelayDialer for ScriptedUpstream {
    fn connect_tcp(
        &self,
        target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError> {
        guard(&self.state.dials).push(target.clone());
        Ok(Box::new(ScriptedStream {
            state: Arc::clone(&self.state),
        }))
    }
    fn connect_udp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayDatagram>, super::super::dialer::RelayError>
    {
        Err(super::super::dialer::RelayError::Upstream {
            detail: "udp not used in this test".to_string(),
        })
    }
}

struct ScriptedStream {
    state: Arc<ScriptedState>,
}
impl std::io::Read for ScriptedStream {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}
impl std::io::Write for ScriptedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl super::super::dialer::RelayStream for ScriptedStream {
    fn shutdown_write(&mut self) -> Result<(), super::super::dialer::RelayError> {
        Ok(())
    }
    fn into_split(
        self: Box<Self>,
    ) -> Result<super::super::dialer::RelaySplit, super::super::dialer::RelayError> {
        Ok(super::super::dialer::RelaySplit {
            reader: Box::new(ScriptedReader {
                state: Arc::clone(&self.state),
                sent: false,
            }),
            writer: Box::new(ScriptedWriter { state: self.state }),
        })
    }
}

struct ScriptedReader {
    state: Arc<ScriptedState>,
    sent: bool,
}
impl std::io::Read for ScriptedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.sent {
            return Ok(0); // EOF after the single scripted reply
        }
        // Block until the client's request has been spliced through.
        let deadline = StdInstant::now() + Duration::from_secs(5);
        let mut written = guard(&self.state.written);
        while written.is_empty() && StdInstant::now() < deadline {
            let (next, _) = self
                .state
                .request_ready
                .wait_timeout(written, Duration::from_millis(50))
                .unwrap_or_else(PoisonError::into_inner);
            written = next;
        }
        drop(written);
        self.sent = true;
        let n = self.state.response.len().min(buf.len());
        buf[..n].copy_from_slice(&self.state.response[..n]);
        Ok(n)
    }
}

struct ScriptedWriter {
    state: Arc<ScriptedState>,
}
impl std::io::Write for ScriptedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        guard(&self.state.written).extend_from_slice(buf);
        self.state.request_ready.notify_all();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl super::super::dialer::RelayWriteHalf for ScriptedWriter {
    fn shutdown_write(&mut self) -> Result<(), super::super::dialer::RelayError> {
        Ok(())
    }
}

/// The stack side of the pipe, as a neutral [`TunDevice`].
struct PipeTunDevice {
    inbound: PacketQueue,
    outbound: PacketQueue,
    mtu: u16,
}

struct NoopControl;
impl nrr_platform_api::fake_ip::tun::TunControl for NoopControl {
    fn shutdown(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}

impl TunDevice for PipeTunDevice {
    fn mtu(&self) -> u16 {
        self.mtu
    }
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError> {
        match guard(&self.inbound).pop_front() {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PlatformError> {
        guard(&self.outbound).push_back(packet.to_vec());
        Ok(packet.len())
    }
    fn control(&self) -> Arc<dyn nrr_platform_api::fake_ip::tun::TunControl> {
        Arc::new(NoopControl)
    }
}

/// The client side of the pipe, as a smoltcp phy device.
struct PipeClientDevice {
    inbound: PacketQueue,
    outbound: PacketQueue,
    mtu: usize,
}

struct VecRxToken(Vec<u8>);
impl RxToken for VecRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
struct QueueTxToken(PacketQueue);
impl TxToken for QueueTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        guard(&self.0).push_back(buf);
        result
    }
}

impl Device for PipeClientDevice {
    type RxToken<'a> = VecRxToken;
    type TxToken<'a> = QueueTxToken;
    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = guard(&self.inbound).pop_front()?;
        Some((VecRxToken(packet), QueueTxToken(Arc::clone(&self.outbound))))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken(Arc::clone(&self.outbound)))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        #[allow(clippy::field_reassign_with_default)]
        {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = self.mtu;
            caps
        }
    }
}

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
            super::super::relay::StaticUpstreamResolver::new()
                .with("example.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
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
        Arc::clone(&dialer) as Arc<dyn super::super::dialer::RelayDialer>,
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
impl super::super::dialer::RelayDialer for RefusingDialer {
    fn connect_tcp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError> {
        Err(super::super::dialer::RelayError::Upstream {
            detail: "refused by test".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayDatagram>, super::super::dialer::RelayError>
    {
        Err(super::super::dialer::RelayError::Upstream {
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
            super::super::relay::StaticUpstreamResolver::new()
                .with("dead.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
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
impl super::super::dialer::RelayDialer for FlakyPolicyDialer {
    fn connect_tcp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= self.refuse_calls {
            Err(super::super::dialer::RelayError::SourcePolicyRefused {
                reason: "secondary adapter unresolved (test)",
            })
        } else {
            Ok(Box::new(EmptyStream))
        }
    }
    fn connect_udp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayDatagram>, super::super::dialer::RelayError>
    {
        Err(super::super::dialer::RelayError::Upstream {
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
impl super::super::dialer::RelayStream for EmptyStream {
    fn shutdown_write(&mut self) -> Result<(), super::super::dialer::RelayError> {
        Ok(())
    }
    fn into_split(
        self: Box<Self>,
    ) -> Result<super::super::dialer::RelaySplit, super::super::dialer::RelayError> {
        Ok(super::super::dialer::RelaySplit {
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
impl super::super::dialer::RelayWriteHalf for EmptyWriteHalf {
    fn shutdown_write(&mut self) -> Result<(), super::super::dialer::RelayError> {
        Ok(())
    }
}

fn hold_test_target() -> super::super::dialer::UpstreamTarget {
    super::super::dialer::UpstreamTarget::at(
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
    impl super::super::dialer::RelayDialer for AlwaysUpstreamError {
        fn connect_tcp(
            &self,
            _target: &super::super::dialer::UpstreamTarget,
        ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError>
        {
            Err(super::super::dialer::RelayError::Upstream {
                detail: "connection refused (test)".to_string(),
            })
        }
        fn connect_udp(
            &self,
            _target: &super::super::dialer::UpstreamTarget,
        ) -> Result<Box<dyn super::super::dialer::RelayDatagram>, super::super::dialer::RelayError>
        {
            Err(super::super::dialer::RelayError::Upstream {
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
impl super::super::dialer::RelayDialer for GatedDialer {
    fn connect_tcp(
        &self,
        target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError> {
        if target.address == Some(self.gate_addr) {
            self.parked.store(true, Ordering::SeqCst);
            let (lock, cv) = &*self.released;
            let deadline = StdInstant::now() + Duration::from_secs(10);
            let mut released = guard(lock);
            while !*released {
                if StdInstant::now() >= deadline {
                    return Err(super::super::dialer::RelayError::Upstream {
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
        target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayDatagram>, super::super::dialer::RelayError>
    {
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
            super::super::relay::StaticUpstreamResolver::new()
                .with("slow.test", &[std::net::IpAddr::V4(slow_v4)])
                .with("fast.test", &[std::net::IpAddr::V4(fast_v4)]),
        ),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
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
            super::super::relay::StaticUpstreamResolver::new()
                .with("voice.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
    );

    let dialer = super::super::dialer::MockRelayDialer::new();
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
        Arc::clone(&dialer) as Arc<dyn super::super::dialer::RelayDialer>,
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
#[derive(Default)]
struct DeadReadDatagram {
    read_failed: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayDatagram for DeadReadDatagram {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError> {
        Ok(payload.len())
    }
    fn receive(&self, _buffer: &mut [u8]) -> Result<usize, RelayError> {
        self.read_failed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Err(RelayError::Upstream {
            detail: "connection reset by peer".to_string(),
        })
    }
}

#[derive(Default)]
struct DeadReadDialer {
    read_failed: Arc<std::sync::atomic::AtomicBool>,
}

impl RelayDialer for DeadReadDialer {
    fn connect_tcp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayStream>, RelayError> {
        Err(RelayError::Upstream {
            detail: "tcp not used in this test".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn RelayDatagram>, RelayError> {
        Ok(Box::new(DeadReadDatagram {
            read_failed: Arc::clone(&self.read_failed),
        }))
    }
}

impl RelayDialer for DeadSendDialer {
    fn connect_tcp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn super::super::dialer::RelayStream>, RelayError> {
        Err(RelayError::Upstream {
            detail: "tcp not used in this test".to_string(),
        })
    }
    fn connect_udp(
        &self,
        _target: &super::super::dialer::UpstreamTarget,
    ) -> Result<Box<dyn RelayDatagram>, RelayError> {
        Ok(Box::new(DeadSendDatagram))
    }
}

/// Drive one client datagram to `fake_v4:443` through a stack built over
/// `dialer`, and return every client-bound packet the stack emitted.
fn client_bound_after_udp_datagrams(
    dialer: Arc<dyn RelayDialer>,
    health: &Arc<super::super::health::FakeIpHealth>,
    datagrams: usize,
    ready_for_next: &dyn Fn() -> bool,
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
            super::super::relay::StaticUpstreamResolver::new()
                .with("voice.test", &[std::net::IpAddr::V4(fake_v4)]),
        ),
        Arc::new(super::super::relay::FixedRouteSelector(
            nrr_shared::RouteRole::Primary,
        )),
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
        if sent < datagrams && (sent == 0 || ready_for_next()) {
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
    let dialer = super::super::dialer::MockRelayDialer::new();
    dialer.fail_dials("secondary adapter unresolved");
    let health = Arc::new(super::super::health::FakeIpHealth::new());
    let emitted = client_bound_after_udp_datagrams(
        Arc::new(dialer) as Arc<dyn RelayDialer>,
        &health,
        1,
        &|| true,
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
    let health = Arc::new(super::super::health::FakeIpHealth::new());
    let emitted = client_bound_after_udp_datagrams(
        Arc::new(DeadSendDialer) as Arc<dyn RelayDialer>,
        &health,
        1,
        &|| true,
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
    let worker = spawn_udp_reader(Arc::new(DeadReadDatagram::default()), Arc::clone(&replies));
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
    let health = Arc::new(super::super::health::FakeIpHealth::new());
    let read_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dialer = DeadReadDialer {
        read_failed: Arc::clone(&read_failed),
    };
    let _ = client_bound_after_udp_datagrams(
        Arc::new(dialer) as Arc<dyn RelayDialer>,
        &health,
        2,
        // Send the second datagram only once the reader has actually
        // failed — otherwise it races a flow that is still alive.
        &|| {
            if !read_failed.load(std::sync::atomic::Ordering::SeqCst) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
            true
        },
    );
    assert!(
        health.udp_dial_ok() >= 2,
        "the dead flow must be dropped and re-dialed, not kept and fed (dials: {})",
        health.udp_dial_ok()
    );
}
