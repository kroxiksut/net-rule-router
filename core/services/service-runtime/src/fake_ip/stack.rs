//! The userspace TCP/IP stack that terminates a fake-IP flow and splices it.
//!
//! The [`relay`](super::relay) layer decides *what* each flow is; this module
//! is *how* the bytes actually move. The TUN adapter hands us raw IP packets
//! addressed to the fake pool, but an application that dialled `198.18.0.7:443`
//! expects a real TCP peer to answer — there is no server behind a fake address.
//! So we run a small TCP/IP stack (`smoltcp`) that speaks the client's TCP
//! handshake locally, and for each accepted connection we open the *real*
//! upstream through the [`RelayDialer`] and splice the two together byte for
//! byte. No TLS is touched: the client's own encrypted stream is copied through,
//! which is why fake-IP needs no certificates and survives encrypted SNI/ECH.
//!
//! Why the stack lives here and not in the platform layer: it is pure policy
//! mechanism over the neutral [`TunDevice`] port, identical on every OS. Only
//! the adapter *behind* the port is per-OS (Wintun on Windows, `/dev/net/tun`
//! on Linux, `utun` on macOS).
//!
//! ## Threading model
//!
//! `smoltcp` sockets are not `Send` and must be driven from one thread. That
//! thread — the poll loop — owns the [`Interface`], the [`SocketSet`] and the
//! [`TunPhyDevice`]. Upstream I/O, which blocks, cannot run on it: a blocking
//! read waiting on the server would freeze every other flow. So a TCP flow gets
//! two worker threads that own the two halves of its upstream socket
//! ([`RelayStream::into_split`]); a UDP flow gets one (only the receive side
//! blocks — sends are non-blocking and go out inline). Both exchange bytes with
//! the poll loop through per-flow buffers; the poll loop never blocks on the
//! network, and the workers never touch a `smoltcp` socket.
//!
//! ## What is finished here and what is not
//!
//! TCP and UDP are both complete: the TCP handshake, bidirectional splice,
//! half-close mirroring and idle teardown; and UDP/QUIC (one bound socket per
//! fake endpoint, multiplexed per client, idle-reaped). What is left before a
//! hardware run: the production
//! [`UpstreamAddressResolver`]/[`RouteSelector`] adapters over the FQDN cache
//! and rule engine, and giving the Windows [`TunDevice`] a bounded-wait read so
//! the poll loop can service upstream->client data while no inbound packet is
//! pending (the mock device already returns promptly, so the neutral logic is
//! exercised in tests today).

use std::collections::{HashMap, VecDeque};
use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::fake_ip::tun::{TunControl, TunDevice};
use nrr_platform_api::fake_ip::FakeIpPoolConfig;

use std::net::SocketAddr;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv6DstUnreachable,
    Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol,
    Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

use super::dialer::{RelayDatagram, RelayDialer, RelayError, RelaySplit};
use super::flow::{parse_packet, FlowKey, FlowProtocol, ParsedPacket};
use super::relay::{RelayCore, RelayDecision, DEFAULT_SESSION_IDLE_MS};

/// Per-socket receive/transmit buffer (64 KiB each). Large enough for a full
/// TLS record burst without stalling the splice, small enough that a few
/// thousand idle flows stay well within a desktop's memory.
pub const DEFAULT_SOCKET_BUFFER_BYTES: usize = 64 * 1024;

/// Chunk size for moving bytes between a `smoltcp` socket and the flow buffers.
const PUMP_CHUNK_BYTES: usize = 16 * 1024;

/// How long the run loop parks when idle (no packet processed and no worker
/// wake). With a device that honours `set_readable_waker` this is only a
/// fallback heartbeat — inbound packets and upstream workers both cut the park
/// short — so it mainly bounds staleness for devices with no readiness signal
/// (the mock) and for timer-driven TCP work (retransmits) on a quiet stack.
const IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Recover a mutex guard even if a worker thread panicked while holding it. The
/// stack tears the flow down on any anomaly, so a poisoned buffer is drained,
/// not trusted — never a reason to panic the poll loop.
fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── TUN <-> smoltcp phy adapter ──────────────────────────────────────────────

/// Presents the neutral [`TunDevice`] to `smoltcp` as an IP-medium phy device.
///
/// One-packet lookahead: the poll loop reads a packet, classifies it (to open a
/// socket for a new flow *before* `smoltcp` sees the SYN), then [`ingest`]s it
/// so the very next `poll` consumes it. `smoltcp` pulls at most that one pending
/// packet per poll, which keeps "inspect, then deliver" a single step.
///
/// [`ingest`]: TunPhyDevice::ingest
pub struct TunPhyDevice {
    device: Box<dyn TunDevice>,
    mtu: u16,
    pending_rx: Option<Vec<u8>>,
}

impl TunPhyDevice {
    #[must_use]
    pub fn new(device: Box<dyn TunDevice>) -> Self {
        let mtu = device.mtu();
        Self {
            device,
            mtu,
            pending_rx: None,
        }
    }

    /// Read one raw IP packet from the adapter into `buf`, returning its length,
    /// or `0` when nothing is pending / the device has shut down.
    pub fn read_raw(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError> {
        self.device.read_packet(buf)
    }

    /// Hand `smoltcp` the packet the poll loop just read and classified.
    pub fn ingest(&mut self, packet: Vec<u8>) {
        self.pending_rx = Some(packet);
    }

    /// Write one client-bound IP packet the poll loop built itself, bypassing
    /// `smoltcp`. Used only for the ICMP unreachable that answers a datagram the
    /// relay accepted but cannot carry — a socket-less error reply has no
    /// `smoltcp` socket to emit it. Best-effort like [`TunTxToken::consume`]: a
    /// full ring drops the reply, which is never a reason to unwind the loop.
    pub fn write_client_packet(&mut self, packet: &[u8]) {
        let _ = self.device.write_packet(packet);
    }

    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// A cross-thread handle that unblocks the reader and tears the adapter down
    /// — how the lifecycle controller stops the run loop.
    #[must_use]
    pub fn control(&self) -> Arc<dyn TunControl> {
        self.device.control()
    }
}

/// Received-packet token: owns the bytes, so it needs no borrow of the device.
pub struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Transmit token: borrows the device just long enough to write one reply.
pub struct TunTxToken<'a> {
    device: &'a mut dyn TunDevice,
}

impl TxToken for TunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        // Best-effort: a full TUN ring drops the reply, which TCP treats as a
        // lost segment and retransmits — never a reason to unwind the loop.
        let _ = self.device.write_packet(&buf);
        result
    }
}

impl Device for TunPhyDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.pending_rx.take()?;
        Some((
            TunRxToken(packet),
            TunTxToken {
                device: &mut *self.device,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken {
            device: &mut *self.device,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        // `DeviceCapabilities` is `#[non_exhaustive]` upstream, so default +
        // field assignment is the only way to build it.
        #[allow(clippy::field_reassign_with_default)]
        {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = usize::from(self.mtu);
            caps
        }
    }
}

// ── Poll-loop wake ───────────────────────────────────────────────────────────

/// Lets an upstream worker nudge the poll loop when it has produced client-bound
/// bytes or closed, so the loop can service the flow without waiting out its
/// idle timer.
#[derive(Debug, Default)]
pub struct StackWaker {
    signalled: Mutex<bool>,
    cv: Condvar,
}

impl StackWaker {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Wake a loop currently in [`wait`](Self::wait).
    pub fn wake(&self) {
        *guard(&self.signalled) = true;
        self.cv.notify_all();
    }

    /// Park until woken or `timeout` elapses, then clear the signal.
    pub fn wait(&self, timeout: std::time::Duration) {
        let mut signalled = guard(&self.signalled);
        if !*signalled {
            let (next, _) = self
                .cv
                .wait_timeout(signalled, timeout)
                .unwrap_or_else(PoisonError::into_inner);
            signalled = next;
        }
        *signalled = false;
    }
}

// ── Per-flow splice buffers ──────────────────────────────────────────────────

/// The shared state between the poll loop and one flow's two upstream workers.
///
/// `to_upstream` carries the client's bytes out; `from_upstream` carries the
/// server's bytes back. The flags mirror the two half-closes and the teardown
/// so each side ends the conversation cleanly instead of severing it.
struct FlowShared {
    to_upstream: Mutex<VecDeque<u8>>,
    from_upstream: Mutex<VecDeque<u8>>,
    /// Client sent FIN: stop writing upstream and mirror the half-close.
    client_fin: AtomicBool,
    /// Upstream returned EOF: once `from_upstream` drains, close the client side.
    upstream_eof: AtomicBool,
    /// Flow is being torn down: workers must exit.
    dead: AtomicBool,
    /// The upstream dial finished and the splice workers are running. Until
    /// then the poll loop leaves client bytes in the socket buffer, so the
    /// client's TCP window — not an unbounded queue — absorbs a slow dial.
    dial_done: AtomicBool,
    /// The upstream dial failed: the poll loop must abort the client socket.
    dial_failed: AtomicBool,
    /// Splice workers, parked here by the dial worker once the upstream is
    /// open. The dial happens off the poll thread, so worker handles cannot be
    /// stored in [`FlowConn`] at open time; the poll loop drains this at reap.
    late_workers: Mutex<Vec<JoinHandle<()>>>,
    /// Wakes the upstream *writer* parked on `to_upstream` when it grows or a
    /// flag flips. Paired with the `to_upstream` mutex — never a separate lock,
    /// so the writer releases `to_upstream` while it waits.
    writer_cv: Condvar,
    /// Wakes the poll loop when `from_upstream` grows or upstream closed.
    stack_waker: Arc<StackWaker>,
}

impl FlowShared {
    fn new(stack_waker: Arc<StackWaker>) -> Arc<Self> {
        Arc::new(Self {
            to_upstream: Mutex::new(VecDeque::new()),
            from_upstream: Mutex::new(VecDeque::new()),
            client_fin: AtomicBool::new(false),
            upstream_eof: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            dial_done: AtomicBool::new(false),
            dial_failed: AtomicBool::new(false),
            late_workers: Mutex::new(Vec::new()),
            writer_cv: Condvar::new(),
            stack_waker,
        })
    }

    /// Called by the dial worker: adopt the splice workers and open the
    /// client->upstream direction. Order matters — workers first, so a poll
    /// that observes `dial_done` can already rely on a live writer.
    fn complete_dial(&self, workers: Vec<JoinHandle<()>>) {
        guard(&self.late_workers).extend(workers);
        self.dial_done.store(true, Ordering::SeqCst);
        self.stack_waker.wake();
    }

    fn signal_dial_failed(&self) {
        self.dial_failed.store(true, Ordering::SeqCst);
        self.stack_waker.wake();
    }

    fn dial_is_done(&self) -> bool {
        self.dial_done.load(Ordering::SeqCst)
    }

    fn dial_has_failed(&self) -> bool {
        self.dial_failed.load(Ordering::SeqCst)
    }

    fn take_workers(&self) -> Vec<JoinHandle<()>> {
        guard(&self.late_workers).drain(..).collect()
    }

    fn push_to_upstream(&self, bytes: &[u8]) {
        guard(&self.to_upstream).extend(bytes.iter().copied());
        self.writer_cv.notify_all();
    }

    fn signal_client_fin(&self) {
        if !self.client_fin.swap(true, Ordering::SeqCst) {
            self.writer_cv.notify_all();
        }
    }

    fn push_from_upstream(&self, bytes: &[u8]) {
        guard(&self.from_upstream).extend(bytes.iter().copied());
        self.stack_waker.wake();
    }

    fn signal_upstream_eof(&self) {
        self.upstream_eof.store(true, Ordering::SeqCst);
        self.stack_waker.wake();
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn mark_dead(&self) {
        self.dead.store(true, Ordering::SeqCst);
        self.writer_cv.notify_all();
        self.stack_waker.wake();
    }

    /// Take up to `max` client bytes for a `smoltcp` send; leaves the rest.
    fn take_from_upstream(&self, max: usize) -> Vec<u8> {
        let mut buffer = guard(&self.from_upstream);
        let take = buffer.len().min(max);
        buffer.drain(..take).collect()
    }

    /// Return bytes a partial `send_slice` could not accept, to the front.
    fn return_from_upstream(&self, unsent: &[u8]) {
        let mut buffer = guard(&self.from_upstream);
        for &byte in unsent.iter().rev() {
            buffer.push_front(byte);
        }
    }

    fn upstream_queue_is_empty(&self) -> bool {
        guard(&self.from_upstream).is_empty()
    }
}

// ── A live flow ──────────────────────────────────────────────────────────────

struct FlowConn {
    handle: SocketHandle,
    shared: Arc<FlowShared>,
    /// Set once the upstream half-close has been mirrored to the client, so we
    /// only call `close()` on the smoltcp socket a single time.
    client_close_sent: bool,
    /// Set when a failed dial aborted the socket; the flow is reaped one poll
    /// later so the RST the abort queued actually reaches the client.
    abort_sent: bool,
}

// ── UDP flows ────────────────────────────────────────────────────────────────
//
// UDP has no handshake, so the model differs from TCP: one smoltcp UDP socket is
// bound per fake destination endpoint (fake_ip:port) and MULTIPLEXES every
// client that talks to it, told apart by the datagram's source. Each distinct
// client gets its own upstream datagram socket (so replies map back correctly)
// and one reader worker; the send direction is non-blocking, so the poll loop
// forwards the client's datagrams upstream inline without a writer thread. This
// carries QUIC/HTTP-3 (443/udp) unchanged — the relay never inspects payloads.

/// Datagrams coming back from one UDP flow's upstream, filled by its reader
/// worker and drained by the poll loop back to the client.
struct UdpReplies {
    queue: Mutex<VecDeque<Vec<u8>>>,
    dead: AtomicBool,
    waker: Arc<StackWaker>,
}

impl UdpReplies {
    fn new(waker: Arc<StackWaker>) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            dead: AtomicBool::new(false),
            waker,
        })
    }
    fn push(&self, datagram: Vec<u8>) {
        guard(&self.queue).push_back(datagram);
        self.waker.wake();
    }
    fn drain(&self) -> Vec<Vec<u8>> {
        guard(&self.queue).drain(..).collect()
    }
    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }
    fn mark_dead(&self) {
        self.dead.store(true, Ordering::SeqCst);
    }
}

/// One client talking to a bound fake endpoint, and its own upstream socket.
struct UdpClientFlow {
    upstream: Arc<dyn RelayDatagram>,
    replies: Arc<UdpReplies>,
    worker: JoinHandle<()>,
    last_seen_at: u64,
}

/// One bound fake endpoint (`fake_ip:port`) and every client using it.
struct UdpBind {
    handle: SocketHandle,
    /// The fake address the socket is bound to — stamped on replies so they
    /// leave FROM the fake address the client is talking to.
    local: IpAddress,
    target: super::dialer::UpstreamTarget,
    clients: HashMap<SocketAddr, UdpClientFlow>,
}

/// Metadata ring slots per UDP socket — the max datagrams that can queue before
/// the oldest is dropped (UDP is lossy; TCP would need more).
const UDP_META_SLOTS: usize = 64;

/// Bytes of a UDP header — the "first 8 bytes past the IP header" an ICMP error
/// quotes back (RFC 792 / RFC 4443).
const UDP_HEADER_BYTES: usize = 8;

/// Hop limit for the relay's own ICMP replies, matching what `smoltcp` stamps on
/// the unreachables it generates itself.
const UNREACHABLE_HOP_LIMIT: u8 = 64;

/// Upper bound for a port-unreachable message: 40 bytes of outer IPv6 header,
/// 8 of ICMPv6, 40 of quoted IPv6 header and 8 of quoted UDP header. The IPv4
/// form is smaller, so one stack buffer of this size serves both and the error
/// path allocates nothing.
const UNREACHABLE_MAX_BYTES: usize = 96;

/// Notified once for every TCP flow the stack decides to relay, with the
/// client's own endpoint, the fake destination it dialed, and the hostname that
/// fake address stands for. The default is a no-op; the production observer
/// (VPN self-heal) uses it to notice a VPN client reaching its server through
/// the relay. Called on the poll thread, so an implementation must return
/// promptly (off-load any I/O).
pub trait FlowObserver: Send + Sync {
    fn on_flow_opened(
        &self,
        client: std::net::SocketAddr,
        fake: std::net::SocketAddr,
        hostname: &str,
    );
}

/// The inert default [`FlowObserver`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopFlowObserver;

impl FlowObserver for NoopFlowObserver {
    fn on_flow_opened(
        &self,
        _client: std::net::SocketAddr,
        _fake: std::net::SocketAddr,
        _hostname: &str,
    ) {
    }
}

// ── The stack ────────────────────────────────────────────────────────────────

/// Owns the `smoltcp` interface and every live flow. Driven single-threaded by
/// [`step`](FakeIpStack::step) / [`run`](FakeIpStack::run).
pub struct FakeIpStack {
    iface: Interface,
    device: TunPhyDevice,
    sockets: SocketSet<'static>,
    relay: RelayCore,
    dialer: Arc<dyn RelayDialer>,
    flows: HashMap<FlowKey, FlowConn>,
    udp_binds: HashMap<(std::net::IpAddr, u16), UdpBind>,
    socket_buffer_bytes: usize,
    waker: Arc<StackWaker>,
    log_gate: Arc<DialLogGate>,
    flow_observer: Arc<dyn FlowObserver>,
    health: Arc<super::health::FakeIpHealth>,
    /// Fake-IP instant reset (schema v40 `fake_ip_instant_rst`) — the live
    /// gate the TCP dial-worker reads per dial. `true` (default) keeps the
    /// instant-reset behaviour for a source-policy refusal; `false` holds and
    /// retries that refusal class (see [`dial_tcp_with_hold`]). Production
    /// wires the process-wide flag [`super::global_instant_rst_enabled`] so a
    /// settings save flips it live with no stack rebuild.
    instant_rst: Arc<AtomicBool>,
    /// Worker handles from reaped flows, swept non-blockingly each step. The
    /// poll thread must NEVER `join()` a worker directly: one upstream that
    /// stalls without FIN/RST would freeze the whole datapath (observed
    /// running to tens of minutes of "answers without ingress" ending in a
    /// detached zombie stack thread).
    worker_graveyard: Vec<JoinHandle<()>>,
    /// Rate limit for the lingering-worker warning below.
    last_graveyard_warn: Option<std::time::Instant>,
}

/// Graveyard size at which lingering workers become worth a warning.
const LINGERING_WORKER_WARN_THRESHOLD: usize = 16;
/// Minimum spacing between lingering-worker warnings.
const GRAVEYARD_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

impl FakeIpStack {
    /// Build a stack over `device`, serving the fake `pool`. `relay` decides
    /// each flow; `dialer` opens the real upstreams.
    #[must_use]
    pub fn new(
        mut device: Box<dyn TunDevice>,
        pool: &FakeIpPoolConfig,
        relay: RelayCore,
        dialer: Arc<dyn RelayDialer>,
        waker: Arc<StackWaker>,
    ) -> Self {
        // Let the device cut an idle park short when a packet arrives: inbound
        // traffic then wakes the run loop exactly like upstream data does,
        // instead of waiting out the poll interval.
        {
            let wake = Arc::clone(&waker);
            device.set_readable_waker(Arc::new(move || wake.wake()));
        }
        let mut device = TunPhyDevice::new(device);
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(pool.gateway_v4()),
                pool.v4_prefix_len,
            ));
            if let Some(v6) = pool.gateway_v6() {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), pool.v6_prefix_len));
            }
        });
        // The pool is thousands of addresses none of which the adapter carries
        // literally; AnyIP lets the stack answer for every one of them.
        iface.set_any_ip(true);
        // A reply travels back to the client's own address, which is off the
        // pool subnet, so the stack needs a route to emit it. The TUN is the
        // only egress for these flows, so a default route through the adapter's
        // own gateway address is exactly right.
        let _ = iface.routes_mut().add_default_ipv4_route(pool.gateway_v4());
        if let Some(v6) = pool.gateway_v6() {
            let _ = iface.routes_mut().add_default_ipv6_route(v6);
        }

        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            relay,
            dialer,
            flows: HashMap::new(),
            udp_binds: HashMap::new(),
            socket_buffer_bytes: DEFAULT_SOCKET_BUFFER_BYTES,
            waker,
            log_gate: DialLogGate::new(),
            flow_observer: Arc::new(NoopFlowObserver),
            health: Arc::new(super::health::FakeIpHealth::new()),
            instant_rst: Arc::new(AtomicBool::new(true)),
            worker_graveyard: Vec::new(),
            last_graveyard_warn: None,
        }
    }

    /// Share the datapath-health counters (relay watchdog): every inbound
    /// packet read off the device bumps the ingress pulse. Builder-style; the
    /// default is a private counter nobody reads.
    #[must_use]
    pub fn with_health(mut self, health: Arc<super::health::FakeIpHealth>) -> Self {
        self.health = health;
        self
    }

    /// Wire the live `fake_ip_instant_rst` gate (schema v40). Builder-style;
    /// the default is a private flag defaulting to `true` (today's
    /// instant-reset behaviour), so a caller that never wires this — every
    /// existing test — sees unchanged behaviour.
    #[must_use]
    pub fn with_instant_rst(mut self, flag: Arc<AtomicBool>) -> Self {
        self.instant_rst = flag;
        self
    }

    /// Carry a flow whose hostname has no cached address and let the dialer
    /// resolve it. Set together with the dialer's name resolver — on its own it
    /// would only move the failure later.
    #[must_use]
    pub fn with_dial_time_resolution(mut self, enabled: bool) -> Self {
        self.relay.set_dial_time_resolution(enabled);
        self
    }

    /// Override the per-socket buffer size (tests use a small value).
    #[must_use]
    pub fn with_socket_buffer_bytes(mut self, bytes: usize) -> Self {
        self.socket_buffer_bytes = bytes.max(1);
        self
    }

    /// Wire an observer notified for every relayed TCP flow (VPN self-heal in
    /// production). Builder-style; the default observer is inert.
    #[must_use]
    pub fn with_flow_observer(mut self, observer: Arc<dyn FlowObserver>) -> Self {
        self.flow_observer = observer;
        self
    }

    /// Number of flows currently carried.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// A cross-thread handle to unblock the reader and tear the adapter down.
    #[must_use]
    pub fn control(&self) -> Arc<dyn TunControl> {
        self.device.control()
    }

    /// Run until `stop` is set or the device errors. Between packets it parks on
    /// the waker so upstream->client data is serviced promptly without
    /// busy-spinning. The controller stops the loop by setting `stop` AND calling
    /// [`control`](Self::control)`.shutdown()` to unblock a parked reader.
    ///
    /// Graceful stop is governed by `stop`, not by a zero-length read: a real
    /// adapter's `Ok(0)` means "shut down", but the mock's also means "idle", so
    /// only the flag is authoritative. An unexpected device failure surfaces as
    /// `Err` and ends the loop, which the controller reaps.
    pub fn run(&mut self, stop: &AtomicBool) -> Result<(), PlatformError> {
        let start = std::time::Instant::now();
        while !stop.load(Ordering::Relaxed) {
            let now_ms = start.elapsed().as_millis();
            let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);
            // Drain fast: if this step processed a packet, loop immediately to
            // clear the rest of the burst before parking; only park when idle, so
            // a run of inbound packets is not throttled to one per wait interval.
            let progressed = self.step(now_ms)?;
            if !progressed {
                self.waker.wait(IDLE_POLL_INTERVAL);
            }
        }
        Ok(())
    }

    /// One iteration: ingest a packet (if any), advance the TCP/UDP state
    /// machines, and pump both directions. Returns whether a packet was
    /// processed — the caller drains without parking while that stays `true`.
    pub fn step(&mut self, now_ms: u64) -> Result<bool, PlatformError> {
        let mut buf = vec![0u8; usize::from(self.device.mtu())];
        let read = self.device.read_raw(&mut buf)?;
        if read > 0 {
            self.health.record_ingress();
            buf.truncate(read);
            if let Some(parsed) = parse_packet(&buf) {
                match parsed.key.protocol {
                    FlowProtocol::Tcp => self.maybe_open_flow(&parsed, now_ms),
                    FlowProtocol::Udp => self.maybe_open_udp(&parsed),
                }
            }
            self.device.ingest(buf);
            let now = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
            self.iface.poll(now, &mut self.device, &mut self.sockets);
        }
        // Poll again even with no inbound packet: upstream workers may have
        // queued client-bound bytes the sockets must now emit.
        let now = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.service_flows();
        self.service_udp(now_ms);
        self.sweep_worker_graveyard();

        Ok(read > 0)
    }

    /// Drop handles of workers that have exited; keep the rest for a later
    /// sweep. Strictly non-blocking — `is_finished` is a flag read, and
    /// joining a finished thread returns immediately.
    fn sweep_worker_graveyard(&mut self) {
        if self.worker_graveyard.is_empty() {
            return;
        }
        self.worker_graveyard.retain(|worker| !worker.is_finished());
        // Read/write timeouts bound every worker, so lingering here means an
        // upstream is stalling right now — worth seeing in a triage, but only
        // when it aggregates (a handful is normal churn).
        if self.worker_graveyard.len() >= LINGERING_WORKER_WARN_THRESHOLD
            && self
                .last_graveyard_warn
                .is_none_or(|at| at.elapsed() >= GRAVEYARD_WARN_INTERVAL)
        {
            self.last_graveyard_warn = Some(std::time::Instant::now());
            tracing::warn!(
                target: "nrr::fake-ip",
                lingering = self.worker_graveyard.len(),
                "fake-IP upstream workers are lingering past flow teardown — upstreams are stalling",
            );
        }
    }

    /// Open a flow for a fresh TCP SYN to an in-scope fake address.
    ///
    /// The client handshake is answered immediately; the upstream dial runs on
    /// its own worker thread. A dial can block for seconds (dead host, downed
    /// route), and the poll thread is shared by every flow — one doomed dial
    /// must never stall the stack for everyone else. A failed dial surfaces to
    /// the client as an RST right after the handshake instead of a stall.
    fn maybe_open_flow(&mut self, packet: &ParsedPacket, now_ms: u64) {
        if packet.key.protocol != FlowProtocol::Tcp || !packet.is_connection_open {
            return;
        }
        if self.flows.contains_key(&packet.key) {
            return;
        }
        let (hostname, target) = match self.relay.decide(packet) {
            RelayDecision::Relay { hostname, target } => (hostname, target),
            // Anything else (not ours, unmapped, out of scope, no upstream) gets
            // no socket, so smoltcp answers the SYN with a reset — the flow fails
            // closed instead of leaking to a guess.
            refusal => {
                self.log_gate.log_refusal(&packet.key.destination, &refusal);
                return;
            }
        };
        // Notify the observer (VPN self-heal) with the client's own endpoint and
        // the fake destination it dialed. Must be prompt — the production
        // observer only enqueues.
        self.flow_observer
            .on_flow_opened(packet.key.source, packet.key.destination, &hostname);

        let rx = tcp::SocketBuffer::new(vec![0u8; self.socket_buffer_bytes]);
        let tx = tcp::SocketBuffer::new(vec![0u8; self.socket_buffer_bytes]);
        let mut socket = tcp::Socket::new(rx, tx);
        let listen = IpListenEndpoint {
            addr: Some(smoltcp_address(packet.key.destination.ip())),
            port: packet.key.destination.port(),
        };
        if socket.listen(listen).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);

        self.health.record_tcp_relay_flow_opened();
        let shared = FlowShared::new(Arc::clone(&self.waker));
        spawn_dial_worker(
            Arc::clone(&shared),
            Arc::clone(&self.dialer),
            target,
            Arc::clone(&self.log_gate),
            Arc::clone(&self.health),
            Arc::clone(&self.instant_rst),
        );
        self.flows.insert(
            packet.key,
            FlowConn {
                handle,
                shared,
                client_close_sent: false,
                abort_sent: false,
            },
        );
        let _ = now_ms;
    }

    /// Move bytes between every socket and its upstream, then reap finished flows.
    fn service_flows(&mut self) {
        let mut finished = Vec::new();
        for (key, flow) in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);

            // The dial worker gave up: reset the client instead of stalling it.
            // The reap waits one poll so the queued RST is actually dispatched;
            // a retransmission after removal is reset by the interface anyway.
            if flow.shared.dial_has_failed() && !flow.abort_sent {
                socket.abort();
                flow.abort_sent = true;
                continue;
            }
            if flow.abort_sent {
                flow.shared.mark_dead();
                finished.push(*key);
                continue;
            }

            // Client -> upstream — only once the upstream exists. While the
            // dial is in flight the bytes stay in the socket buffer, so the
            // client's own TCP window backpressures instead of an unbounded
            // queue growing against a slow dial.
            while flow.shared.dial_is_done() && socket.can_recv() {
                let mut chunk = [0u8; PUMP_CHUNK_BYTES];
                match socket.recv_slice(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => flow.shared.push_to_upstream(&chunk[..n]),
                }
            }
            // Client half-closed its send direction. Detect this by the states
            // that only follow the peer's FIN — NOT by `!may_recv()`, which is
            // also true before the handshake completes (Listen / SynReceived)
            // and would tear the upstream down before a byte ever flows.
            if matches!(
                socket.state(),
                tcp::State::CloseWait
                    | tcp::State::Closing
                    | tcp::State::LastAck
                    | tcp::State::TimeWait
            ) {
                flow.shared.signal_client_fin();
            }

            // Upstream -> client.
            while socket.can_send() {
                let chunk = flow.shared.take_from_upstream(PUMP_CHUNK_BYTES);
                if chunk.is_empty() {
                    break;
                }
                match socket.send_slice(&chunk) {
                    Ok(sent) if sent < chunk.len() => {
                        flow.shared.return_from_upstream(&chunk[sent..]);
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        flow.shared.return_from_upstream(&chunk);
                        break;
                    }
                }
            }
            // Upstream is done and drained: mirror its close to the client once.
            if flow.shared.upstream_eof.load(Ordering::SeqCst)
                && flow.shared.upstream_queue_is_empty()
                && !flow.client_close_sent
                && socket.may_send()
            {
                socket.close();
                flow.client_close_sent = true;
            }

            if socket.state() == tcp::State::Closed {
                flow.shared.mark_dead();
                finished.push(*key);
            }
        }

        for key in finished {
            if let Some(flow) = self.flows.remove(&key) {
                self.sockets.remove(flow.handle);
                flow.shared.mark_dead();
                // Handles go to the graveyard, never joined here: a worker
                // blocked on a stalled upstream would hold this join — and
                // with it the poll thread, i.e. the entire datapath.
                self.worker_graveyard.extend(flow.shared.take_workers());
            }
        }
    }

    /// Bind a UDP socket for a fresh datagram to an in-scope fake endpoint.
    fn maybe_open_udp(&mut self, packet: &ParsedPacket) {
        let local = packet.key.destination;
        let key = (local.ip(), local.port());
        if self.udp_binds.contains_key(&key) {
            return;
        }
        let (_hostname, target) = match self.relay.decide(packet) {
            RelayDecision::Relay { hostname, target } => (hostname, target),
            refusal => {
                self.log_gate.log_refusal(&packet.key.destination, &refusal);
                return;
            }
        };
        let make_buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
                vec![0u8; self.socket_buffer_bytes],
            )
        };
        let mut socket = udp::Socket::new(make_buffer(), make_buffer());
        let local_addr = smoltcp_address(local.ip());
        if socket
            .bind(IpListenEndpoint {
                addr: Some(local_addr),
                port: local.port(),
            })
            .is_err()
        {
            return;
        }
        let handle = self.sockets.add(socket);
        self.udp_binds.insert(
            key,
            UdpBind {
                handle,
                local: local_addr,
                target,
                clients: HashMap::new(),
            },
        );
    }

    /// Pump every UDP bind: client datagrams out to their upstreams, upstream
    /// replies back to their clients, then reap idle flows.
    fn service_udp(&mut self, now_ms: u64) {
        let keys: Vec<(std::net::IpAddr, u16)> = self.udp_binds.keys().copied().collect();
        for key in keys {
            let Some(&UdpBind { handle, local, .. }) = self.udp_binds.get(&key) else {
                continue;
            };

            // Client -> upstream. Copy each datagram out (releasing the socket
            // borrow) before dialing, since dialing mutates the bind map.
            let mut inbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
            {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                while socket.can_recv() {
                    match socket.recv() {
                        Ok((payload, meta)) => {
                            inbound.push((endpoint_to_socketaddr(meta.endpoint), payload.to_vec()));
                        }
                        Err(_) => break,
                    }
                }
            }
            for (client, payload) in inbound {
                self.udp_forward_upstream(&key, client, &payload, now_ms);
            }

            // Upstream -> client. Drain each client's reply queue, then emit.
            let replies: Vec<(SocketAddr, Vec<Vec<u8>>)> = match self.udp_binds.get(&key) {
                Some(bind) => bind
                    .clients
                    .iter()
                    .map(|(client, flow)| (*client, flow.replies.drain()))
                    .collect(),
                None => continue,
            };
            {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                for (client, datagrams) in replies {
                    for datagram in datagrams {
                        let mut meta = udp::UdpMetadata::from(socketaddr_to_endpoint(client));
                        meta.local_address = Some(local);
                        let _ = socket.send_slice(&datagram, meta);
                    }
                }
            }

            self.reap_idle_udp(&key, now_ms);
        }
    }

    /// Send one client datagram upstream, dialing (and starting the reader) the
    /// first time that client is seen on this bind.
    fn udp_forward_upstream(
        &mut self,
        key: &(std::net::IpAddr, u16),
        client: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) {
        let known = self
            .udp_binds
            .get(key)
            .is_some_and(|bind| bind.clients.contains_key(&client));
        if !known {
            let Some(target) = self.udp_binds.get(key).map(|bind| bind.target.clone()) else {
                return;
            };
            // UDP dials run inline on the poll thread (no per-flow worker
            // thread exists for the send/first-dial path — see the module
            // doc), so they are NEVER held: a 10 s hold here would freeze
            // every other flow the stack carries. `fake_ip_instant_rst` is a
            // TCP-only setting; UDP always instant-refuses a source-policy
            // refusal, same as every other dial failure.
            self.health.record_udp_relay_flow_opened();
            let dial_started = std::time::Instant::now();
            let datagram = match self.dialer.connect_udp(&target) {
                Ok(datagram) => {
                    self.health.record_udp_dial_ok();
                    datagram
                }
                Err(error) => {
                    let elapsed_ms = dial_started.elapsed().as_millis();
                    if matches!(error, RelayError::SourcePolicyRefused { .. }) {
                        self.health.record_udp_dial_refused();
                        tracing::warn!(
                            target: "nrr::fake-ip",
                            hostname = %target.hostname,
                            route = ?target.route,
                            elapsed_ms = %elapsed_ms,
                            mode = "instant",
                            attempts = 1u32,
                            error = %error,
                            "fake-IP UDP dial refused by source policy — no relay for this client (UDP dials are never held)",
                        );
                    } else {
                        self.health.record_udp_dial_failed();
                    }
                    // Fail CLOSED but not SILENT: the datagram is never relayed,
                    // and the client is told the port is unreachable so it stops
                    // waiting on a protocol timeout and falls back at once. A
                    // refused TCP flow already gets its reset this way.
                    self.send_port_unreachable(*key, client, payload.len());
                    return;
                }
            };
            let upstream: Arc<dyn RelayDatagram> = Arc::from(datagram);
            let replies = UdpReplies::new(Arc::clone(&self.waker));
            let worker = spawn_udp_reader(Arc::clone(&upstream), Arc::clone(&replies));
            if let Some(bind) = self.udp_binds.get_mut(key) {
                bind.clients.insert(
                    client,
                    UdpClientFlow {
                        upstream,
                        replies,
                        worker,
                        last_seen_at: now_ms,
                    },
                );
            }
        }
        let Some(flow) = self
            .udp_binds
            .get_mut(key)
            .and_then(|bind| bind.clients.get_mut(&client))
        else {
            return;
        };
        match flow.upstream.send(payload) {
            Ok(_) => flow.last_seen_at = now_ms,
            // The upstream socket is gone (route torn down under the flow, peer
            // hard-refusing). Retiring the client here means the next datagram
            // re-dials rather than being swallowed until the idle reap, and the
            // client learns now instead of at its own timeout.
            Err(_) => {
                if let Some(retired) = self
                    .udp_binds
                    .get_mut(key)
                    .and_then(|bind| bind.clients.remove(&client))
                {
                    retired.replies.mark_dead();
                    // Graveyard, not join — same poll-thread rule as the reap.
                    self.worker_graveyard.push(retired.worker);
                }
                self.send_port_unreachable(*key, client, payload.len());
            }
        }
    }

    /// Tell the client the fake endpoint's port is unreachable for a datagram
    /// the relay accepted but could not carry.
    ///
    /// Built and written straight to the device: the datagram was already
    /// consumed by a bound `smoltcp` socket, so the interface's own
    /// port-unreachable path (which fires only when NO socket claims the
    /// endpoint — the refusal case in [`maybe_open_udp`]) never sees it.
    fn send_port_unreachable(
        &mut self,
        fake: (std::net::IpAddr, u16),
        client: SocketAddr,
        payload_len: usize,
    ) {
        let fake = SocketAddr::new(fake.0, fake.1);
        let mut packet = [0u8; UNREACHABLE_MAX_BYTES];
        if let Some(len) = build_port_unreachable(fake, client, payload_len, &mut packet) {
            self.health.record_udp_unreachable_sent();
            self.device.write_client_packet(&packet[..len]);
        }
    }

    /// Drop UDP client flows idle past the window; drop a bind once it has none.
    fn reap_idle_udp(&mut self, key: &(std::net::IpAddr, u16), now_ms: u64) {
        let cutoff = now_ms.saturating_sub(DEFAULT_SESSION_IDLE_MS);
        let mut reaped_workers = Vec::new();
        let empty = if let Some(bind) = self.udp_binds.get_mut(key) {
            let stale: Vec<SocketAddr> = bind
                .clients
                .iter()
                .filter(|(_, flow)| flow.last_seen_at < cutoff)
                .map(|(client, _)| *client)
                .collect();
            for client in stale {
                if let Some(flow) = bind.clients.remove(&client) {
                    flow.replies.mark_dead();
                    // Graveyard, not join — same poll-thread rule as TCP reap.
                    reaped_workers.push(flow.worker);
                }
            }
            bind.clients.is_empty()
        } else {
            false
        };
        self.worker_graveyard.extend(reaped_workers);
        if empty {
            if let Some(bind) = self.udp_binds.remove(key) {
                self.sockets.remove(bind.handle);
            }
        }
    }
}

impl Drop for FakeIpStack {
    /// Signal every worker to exit so no splice thread outlives the stack. Workers
    /// observe the flag and return; we do not join here (a blocked upstream read
    /// is paced by its own timeout), so drop stays prompt.
    fn drop(&mut self) {
        for flow in self.flows.values() {
            flow.shared.mark_dead();
        }
        for bind in self.udp_binds.values() {
            for flow in bind.clients.values() {
                flow.replies.mark_dead();
            }
        }
    }
}

/// `smoltcp` endpoint (v4/v6) to a std `SocketAddr`.
fn endpoint_to_socketaddr(endpoint: IpEndpoint) -> SocketAddr {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(v4) => std::net::IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => std::net::IpAddr::V6(v6),
    };
    SocketAddr::new(ip, endpoint.port)
}

/// Build an ICMP "destination unreachable / port unreachable" for a datagram the
/// relay took off a bound fake endpoint but cannot carry, addressed back to the
/// client. Writes into `out` and returns the message length, or `None` when the
/// two endpoints are of different IP families (impossible for a parsed flow) or
/// the buffer is too small.
///
/// This is the UDP counterpart of the reset a refused TCP flow gets. Without it
/// the client's datagram is swallowed in silence and the application waits out
/// its own protocol timeout before falling back — the QUIC-to-TCP fallback the
/// browser makes in milliseconds when the port is reported unreachable.
///
/// The quoted header is rebuilt from the flow's endpoints rather than kept from
/// the wire: the original bytes are gone by the time a dial fails, and a
/// receiver matches an ICMP error to a socket on the quoted addresses and ports,
/// never on its checksum (left zero, which is also the legal "no checksum" value
/// for IPv4 UDP).
fn build_port_unreachable(
    fake: SocketAddr,
    client: SocketAddr,
    payload_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    let udp_len = u16::try_from(UDP_HEADER_BYTES.saturating_add(payload_len)).unwrap_or(u16::MAX);
    let mut quoted_udp = [0u8; UDP_HEADER_BYTES];
    quoted_udp[0..2].copy_from_slice(&client.port().to_be_bytes());
    quoted_udp[2..4].copy_from_slice(&fake.port().to_be_bytes());
    quoted_udp[4..6].copy_from_slice(&udp_len.to_be_bytes());

    let checksums = ChecksumCapabilities::default();
    match (fake.ip(), client.ip()) {
        (std::net::IpAddr::V4(fake_ip), std::net::IpAddr::V4(client_ip)) => {
            let quoted = Ipv4Repr {
                src_addr: client_ip,
                dst_addr: fake_ip,
                next_header: IpProtocol::Udp,
                payload_len: usize::from(udp_len),
                hop_limit: UNREACHABLE_HOP_LIMIT,
            };
            let icmp = Icmpv4Repr::DstUnreachable {
                reason: Icmpv4DstUnreachable::PortUnreachable,
                header: quoted,
                data: &quoted_udp,
            };
            let outer = Ipv4Repr {
                src_addr: fake_ip,
                dst_addr: client_ip,
                next_header: IpProtocol::Icmp,
                payload_len: icmp.buffer_len(),
                hop_limit: UNREACHABLE_HOP_LIMIT,
            };
            let total = outer.buffer_len() + icmp.buffer_len();
            let out = out.get_mut(..total)?;
            let (header, payload) = out.split_at_mut(outer.buffer_len());
            icmp.emit(&mut Icmpv4Packet::new_unchecked(payload), &checksums);
            outer.emit(&mut Ipv4Packet::new_unchecked(header), &checksums);
            Some(total)
        }
        (std::net::IpAddr::V6(fake_ip), std::net::IpAddr::V6(client_ip)) => {
            let quoted = Ipv6Repr {
                src_addr: client_ip,
                dst_addr: fake_ip,
                next_header: IpProtocol::Udp,
                payload_len: usize::from(udp_len),
                hop_limit: UNREACHABLE_HOP_LIMIT,
            };
            let icmp = Icmpv6Repr::DstUnreachable {
                reason: Icmpv6DstUnreachable::PortUnreachable,
                header: quoted,
                data: &quoted_udp,
            };
            let outer = Ipv6Repr {
                src_addr: fake_ip,
                dst_addr: client_ip,
                next_header: IpProtocol::Icmpv6,
                payload_len: icmp.buffer_len(),
                hop_limit: UNREACHABLE_HOP_LIMIT,
            };
            let total = outer.buffer_len() + icmp.buffer_len();
            let out = out.get_mut(..total)?;
            let (header, payload) = out.split_at_mut(outer.buffer_len());
            icmp.emit(
                &fake_ip,
                &client_ip,
                &mut Icmpv6Packet::new_unchecked(payload),
                &checksums,
            );
            outer.emit(&mut Ipv6Packet::new_unchecked(header));
            Some(total)
        }
        _ => None,
    }
}

/// A std `SocketAddr` to a `smoltcp` endpoint.
fn socketaddr_to_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint {
        addr: smoltcp_address(addr.ip()),
        port: addr.port(),
    }
}

/// The reader worker for one UDP flow: block on the upstream socket, push each
/// reply to the poll loop. A read timeout surfaces as `WouldBlock`, which is a
/// poll tick — the loop re-checks teardown rather than treating it as an error.
fn spawn_udp_reader(upstream: Arc<dyn RelayDatagram>, replies: Arc<UdpReplies>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            if replies.is_dead() {
                return;
            }
            match upstream.receive(&mut buf) {
                Ok(n) => replies.push(buf[..n].to_vec()),
                Err(RelayError::WouldBlock) => {} // poll tick — re-check teardown
                Err(_) => return,
            }
        }
    })
}

/// Convert a std [`std::net::IpAddr`] to the `smoltcp` wire type.
fn smoltcp_address(ip: std::net::IpAddr) -> IpAddress {
    match ip {
        std::net::IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        std::net::IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

// ── First-per-destination flow diagnostics ───────────────────────────────────

/// Deduplicates relay flow logs so acceptance runs can read outcomes at the
/// default (non-verbose) level without per-connection log spam: each distinct
/// destination logs its first refusal, first successful dial and first failed
/// dial once per stack lifetime. Bounded so a port-scanning client cannot grow
/// it without limit — once full, new destinations are simply not logged.
struct DialLogGate {
    seen: Mutex<std::collections::HashSet<String>>,
}

/// Max distinct (destination, outcome) entries remembered for dedup.
const DIAL_LOG_GATE_CAP: usize = 1024;

impl DialLogGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// True exactly once per key, until the cap is reached.
    fn first(&self, key: String) -> bool {
        let mut seen = guard(&self.seen);
        if seen.len() >= DIAL_LOG_GATE_CAP {
            return false;
        }
        seen.insert(key)
    }

    fn log_refusal(&self, destination: &SocketAddr, refusal: &RelayDecision) {
        let slug = refusal.slug();
        let hostname = match refusal {
            RelayDecision::Relay { .. } => return,
            RelayDecision::NoUpstreamAddress { hostname }
            | RelayDecision::OutOfScope { hostname, .. } => hostname.clone(),
            _ => String::new(),
        };
        if self.first(format!("refuse|{destination}|{slug}")) {
            tracing::info!(
                target: "nrr::fake_ip",
                destination = %destination,
                hostname = %hostname,
                verdict = slug,
                "fake-IP flow refused — client gets a reset (first per destination this session)"
            );
        }
    }

    fn log_dial_ok(&self, target: &super::dialer::UpstreamTarget, elapsed_ms: u128) {
        let endpoint = target.endpoint_label();
        if self.first(format!("ok|{endpoint}")) {
            tracing::info!(
                target: "nrr::fake_ip",
                hostname = %target.hostname,
                upstream = %endpoint,
                route = ?target.route,
                elapsed_ms = %elapsed_ms,
                "fake-IP upstream connected (first per destination this session)"
            );
        }
    }

    fn log_dial_failed(
        &self,
        target: &super::dialer::UpstreamTarget,
        elapsed_ms: u128,
        error: &RelayError,
    ) {
        let endpoint = target.endpoint_label();
        if self.first(format!("fail|{endpoint}")) {
            tracing::warn!(
                target: "nrr::fake_ip",
                hostname = %target.hostname,
                upstream = %endpoint,
                route = ?target.route,
                elapsed_ms = %elapsed_ms,
                error = %error,
                "fake-IP upstream dial failed — client gets a reset (first per destination this session)"
            );
        }
    }
}

/// How often the hold-and-retry path (`fake_ip_instant_rst` off) re-attempts a
/// TCP dial that failed on source-address policy alone (e.g. the secondary
/// adapter is unresolved mid-VPN-reconnect). Frequent enough that a reconnect
/// completing mid-window is picked up promptly, without hammering route
/// resolution.
const HOLD_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Total time the hold-and-retry path waits for a source-policy refusal to
/// clear before giving up and refusing exactly like the instant-reset path.
/// Same order of magnitude as `UPSTREAM_CONNECT_TIMEOUT`, so a held client sees
/// a bounded, predictable stall rather than an open-ended one.
const HOLD_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// Attempts the TCP dial, holding and retrying ONLY a source-policy refusal
/// when `instant_rst` is off. A genuine network failure (unreachable host,
/// connection refused, timeout) always fails on the first attempt — holding
/// those would mask a real outage as a slow connect instead of letting the
/// application retry or fail over on its own.
///
/// Runs on the dial-worker thread spawned by [`spawn_dial_worker`], which is
/// never joined by the poll loop OR by
/// [`FakeIpController::stop`](super::lifecycle::FakeIpController::stop) —
/// `stop` only joins the poll-loop thread (`RunningStack.join`), never a
/// per-flow dial worker. Holding here for up to `HOLD_RETRY_WINDOW` therefore
/// cannot delay a clean stack shutdown; the bounded window (rather than an
/// explicit cancel signal) is what keeps a held dial from outliving the flow
/// indefinitely. `shared.is_dead()` is also checked every iteration so a
/// client that resets mid-hold stops the retry immediately instead of running
/// out the window pointlessly.
///
/// Returns the dial result, which mode applied (`"instant"` / `"held"`), and
/// how many attempts were made — all three feed the Task-2 telemetry in
/// [`spawn_dial_worker`].
///
/// `retry_interval`/`retry_window` are parameters (not the
/// [`HOLD_RETRY_INTERVAL`]/[`HOLD_RETRY_WINDOW`] constants directly) purely so
/// tests can exercise the window-exhaustion path in milliseconds instead of
/// really waiting out 10 s; production always calls with the two constants.
fn dial_tcp_with_hold(
    shared: &FlowShared,
    dialer: &dyn RelayDialer,
    target: &super::dialer::UpstreamTarget,
    instant_rst: &AtomicBool,
    retry_interval: std::time::Duration,
    retry_window: std::time::Duration,
) -> (Result<RelaySplit, RelayError>, &'static str, u32) {
    let first = dialer
        .connect_tcp(target)
        .and_then(|stream| stream.into_split());
    let is_policy_refusal = matches!(first, Err(RelayError::SourcePolicyRefused { .. }));
    if !is_policy_refusal || instant_rst.load(Ordering::Relaxed) {
        return (first, "instant", 1);
    }
    let deadline = std::time::Instant::now() + retry_window;
    let mut attempts = 1u32;
    let mut result = first;
    while matches!(result, Err(RelayError::SourcePolicyRefused { .. }))
        && !shared.is_dead()
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(retry_interval);
        if shared.is_dead() {
            break;
        }
        attempts += 1;
        result = dialer
            .connect_tcp(target)
            .and_then(|stream| stream.into_split());
    }
    (result, "held", attempts)
}

/// Dial the upstream off the poll thread, then hand the flow its workers.
///
/// Never joined by the poll loop: a dial can sit in `connect` for the full
/// timeout — or, with `fake_ip_instant_rst` off, in the hold-and-retry window
/// (see [`dial_tcp_with_hold`]) — and joining it would recreate the very
/// stall this thread exists to prevent. It owns nothing but `Arc`s and exits
/// on its own — when the flow died while dialing, the fresh upstream is
/// simply dropped.
fn spawn_dial_worker(
    shared: Arc<FlowShared>,
    dialer: Arc<dyn RelayDialer>,
    target: super::dialer::UpstreamTarget,
    log_gate: Arc<DialLogGate>,
    health: Arc<super::health::FakeIpHealth>,
    instant_rst: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let (split, mode, attempts) = dial_tcp_with_hold(
            shared.as_ref(),
            dialer.as_ref(),
            &target,
            instant_rst.as_ref(),
            HOLD_RETRY_INTERVAL,
            HOLD_RETRY_WINDOW,
        );
        let elapsed_ms = started.elapsed().as_millis();
        let was_held = mode == "held";
        match split {
            Ok(split) => {
                health.record_tcp_dial_ok();
                if shared.is_dead() {
                    return; // client already gone; drop the upstream
                }
                log_gate.log_dial_ok(&target, elapsed_ms);
                if was_held {
                    // Hold/relay behaviour is otherwise invisible without
                    // per-connection events; log every held resolution
                    // explicitly rather than relying on the deduped
                    // per-destination gate above.
                    tracing::info!(
                        target: "nrr::fake-ip",
                        hostname = %target.hostname,
                        route = ?target.route,
                        elapsed_ms = %elapsed_ms,
                        mode,
                        attempts,
                        "fake-IP dial succeeded after holding for the secondary to resolve",
                    );
                }
                let workers = spawn_upstream_workers(Arc::clone(&shared), split);
                shared.complete_dial(workers);
            }
            Err(error) => {
                let is_policy_refusal = matches!(error, RelayError::SourcePolicyRefused { .. });
                if is_policy_refusal {
                    health.record_tcp_dial_refused();
                } else {
                    health.record_tcp_dial_failed();
                }
                log_gate.log_dial_failed(&target, elapsed_ms, &error);
                if is_policy_refusal {
                    tracing::warn!(
                        target: "nrr::fake-ip",
                        hostname = %target.hostname,
                        route = ?target.route,
                        elapsed_ms = %elapsed_ms,
                        mode,
                        attempts,
                        error = %error,
                        "fake-IP dial refused by source policy — client gets a reset",
                    );
                }
                shared.signal_dial_failed();
            }
        }
    });
}

/// Spawn the reader and writer threads that own the two halves of a flow's
/// upstream socket and exchange bytes with the poll loop.
fn spawn_upstream_workers(shared: Arc<FlowShared>, split: RelaySplit) -> Vec<JoinHandle<()>> {
    let RelaySplit {
        mut reader,
        mut writer,
    } = split;

    let reader_shared = Arc::clone(&shared);
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; PUMP_CHUNK_BYTES];
        loop {
            if reader_shared.is_dead() {
                return;
            }
            match reader.read(&mut buf) {
                Ok(0) => {
                    reader_shared.signal_upstream_eof();
                    return;
                }
                Ok(n) => reader_shared.push_from_upstream(&buf[..n]),
                // The upstream socket carries a read timeout (see
                // `connect_tcp`) precisely so a silent peer becomes this
                // periodic teardown check instead of an unjoinable thread.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(_) => {
                    reader_shared.signal_upstream_eof();
                    return;
                }
            }
        }
    });

    let writer_shared = Arc::clone(&shared);
    let writer_thread = std::thread::spawn(move || loop {
        let pending: Vec<u8> = {
            let mut buffer = guard(&writer_shared.to_upstream);
            loop {
                if writer_shared.is_dead() {
                    return;
                }
                if !buffer.is_empty() {
                    break buffer.drain(..).collect();
                }
                if writer_shared.client_fin.load(Ordering::SeqCst) {
                    drop(buffer);
                    let _ = writer.shutdown_write();
                    return;
                }
                // Park ON the `to_upstream` mutex, releasing it while waiting so
                // the poll loop can enqueue more client bytes.
                let (next, _timeout) = writer_shared
                    .writer_cv
                    .wait_timeout(buffer, std::time::Duration::from_millis(200))
                    .unwrap_or_else(PoisonError::into_inner);
                buffer = next;
            }
        };
        if writer.write_all(&pending).is_err() {
            writer_shared.mark_dead();
            return;
        }
    });

    vec![reader_thread, writer_thread]
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use nrr_platform_api::fake_ip::tun::{
        MockTunAdapter, MockTunState, TunAdapterConfig, TunAdapterPort,
    };
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
        // No signal now: returns after the timeout without hanging.
        let start = std::time::Instant::now();
        waker.wait(std::time::Duration::from_millis(20));
        assert!(start.elapsed() >= std::time::Duration::from_millis(15));
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
        ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError>
        {
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
        ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError>
        {
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
        ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError>
        {
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
            ) -> Result<
                Box<dyn super::super::dialer::RelayDatagram>,
                super::super::dialer::RelayError,
            > {
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
        ) -> Result<Box<dyn super::super::dialer::RelayStream>, super::super::dialer::RelayError>
        {
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
    fn client_bound_after_one_udp_datagram(
        dialer: Arc<dyn RelayDialer>,
        health: &Arc<super::super::health::FakeIpHealth>,
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
        let mut sent = false;
        let mut now_ms = 0u64;
        for _ in 0..200 {
            now_ms += 5;
            let t = SmolInstant::from_millis(i64::try_from(now_ms).unwrap_or(i64::MAX));
            client.poll(t, &mut client_device, &mut client_sockets);
            if !sent {
                let socket = client_sockets.get_mut::<udp::Socket>(handle);
                if socket.can_send() {
                    socket
                        .send_slice(b"quic-initial", (IpAddress::Ipv4(fake_v4), 443))
                        .expect("client send");
                    sent = true;
                }
            }
            for _ in 0..4 {
                stack.step(now_ms).expect("stack step");
            }
            if sent && !guard(&s2c).is_empty() {
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
        let emitted =
            client_bound_after_one_udp_datagram(Arc::new(dialer) as Arc<dyn RelayDialer>, &health);

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
        let emitted = client_bound_after_one_udp_datagram(
            Arc::new(DeadSendDialer) as Arc<dyn RelayDialer>,
            &health,
        );

        assert!(
            emitted.iter().any(|p| is_port_unreachable(p)),
            "an upstream that cannot take the datagram must reach the client as an error"
        );
        assert_eq!(health.udp_dial_ok(), 1, "the dial itself succeeded");
        assert_eq!(health.udp_unreachable_sent(), 1);
    }
}
