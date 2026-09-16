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
use super::super::{dialer, health, relay};
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

// ── In-memory pipe harness shared by every theme below ───────────────

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

mod echo_relay;
mod end_to_end;
mod instant_rst;
mod poll_cost;
mod port_unreachable;
