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
use smoltcp::phy::ChecksumCapabilities;
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

/// Ceiling on simultaneously relayed TCP flows. Each one owns two
/// [`DEFAULT_SOCKET_BUFFER_BYTES`] buffers plus two worker threads, so the cap
/// is a memory bound before it is anything else: 512 flows is about 64 MiB of
/// socket buffers. Past it a new SYN gets no socket — smoltcp resets it, the
/// client falls back at once, and flows already carrying traffic are untouched.
/// Evicting a live flow to admit a new one would trade a working download for
/// a connection that may be a port scan.
const MAX_ACTIVE_TCP_FLOWS: usize = 512;

/// Idle window before a relayed TCP flow is torn down, and the keep-alive
/// interval that keeps a genuinely live-but-quiet connection out of it. A
/// client that vanishes without FIN (laptop lid, killed process, VPN flap)
/// leaves smoltcp holding the socket forever otherwise.
const TCP_FLOW_IDLE: std::time::Duration =
    std::time::Duration::from_millis(super::relay::DEFAULT_SESSION_IDLE_MS);
const TCP_FLOW_KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(30);

/// Chunk size for moving bytes between a `smoltcp` socket and the flow buffers.
const PUMP_CHUNK_BYTES: usize = 16 * 1024;

/// High-water mark for each direction's hand-off queue. Both were unbounded:
/// the poll loop drained the client's socket as fast as smoltcp could deliver,
/// whatever the upstream writer managed, and the reader thread pushed replies
/// in whether or not the client's socket was taking them. A stalled peer in
/// either direction then grew a queue instead of applying backpressure — and
/// TCP already has the mechanism, so the fix is to stop consuming and let the
/// window close.
const FLOW_QUEUE_HIGH_WATER_BYTES: usize = 256 * 1024;

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
//
// Lives in `fake_ip::stack::phy`.
//
// The two transports live beside the poll loop rather than inside it: TCP in
// `stack::tcp_splice`, datagrams in `stack::datagrams`. NOT `udp` —
// `smoltcp::socket::udp` is already imported here under that name.
mod datagrams;
mod phy;
mod tcp_splice;

pub use phy::{TunPhyDevice, TunRxToken, TunTxToken};

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
    /// Upstream broke off mid-answer (reset, hard I/O error). Mirrored to the
    /// client as a reset, never as FIN: a truncated body that arrives under a
    /// clean close reads as the whole answer.
    upstream_reset: AtomicBool,
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
    /// Wakes the upstream *reader* parked on a full `from_upstream`. Paired
    /// with that queue's mutex, so the poll loop can drain it while the reader
    /// waits.
    reader_cv: Condvar,
}

impl FlowShared {
    fn new(stack_waker: Arc<StackWaker>) -> Arc<Self> {
        Arc::new(Self {
            to_upstream: Mutex::new(VecDeque::new()),
            from_upstream: Mutex::new(VecDeque::new()),
            client_fin: AtomicBool::new(false),
            upstream_eof: AtomicBool::new(false),
            upstream_reset: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            dial_done: AtomicBool::new(false),
            dial_failed: AtomicBool::new(false),
            late_workers: Mutex::new(Vec::new()),
            writer_cv: Condvar::new(),
            reader_cv: Condvar::new(),
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

    fn signal_upstream_reset(&self) {
        self.upstream_reset.store(true, Ordering::SeqCst);
        self.stack_waker.wake();
    }

    fn upstream_was_reset(&self) -> bool {
        self.upstream_reset.load(Ordering::SeqCst)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    fn mark_dead(&self) {
        self.dead.store(true, Ordering::SeqCst);
        self.writer_cv.notify_all();
        self.reader_cv.notify_all();
        self.stack_waker.wake();
    }

    /// Take up to `max` client bytes for a `smoltcp` send; leaves the rest.
    fn take_from_upstream(&self, max: usize) -> Vec<u8> {
        let mut buffer = guard(&self.from_upstream);
        let take = buffer.len().min(max);
        let taken: Vec<u8> = buffer.drain(..take).collect();
        if buffer.len() < FLOW_QUEUE_HIGH_WATER_BYTES {
            self.reader_cv.notify_all();
        }
        taken
    }

    fn to_upstream_len(&self) -> usize {
        guard(&self.to_upstream).len()
    }

    /// Park until the client-bound queue has room, the flow dies, or the wait
    /// times out. The timeout is what keeps a wedged poll loop from turning
    /// backpressure into a stuck reader.
    fn await_upstream_queue_room(&self) {
        let mut buffer = guard(&self.from_upstream);
        while buffer.len() >= FLOW_QUEUE_HIGH_WATER_BYTES && !self.is_dead() {
            // The timeout is a liveness check, not a licence to read on: a
            // spurious wake or a missed notify must not let the queue grow by
            // another chunk every 50 ms.
            let (next, _elapsed) = self
                .reader_cv
                .wait_timeout(buffer, std::time::Duration::from_millis(50))
                .unwrap_or_else(|p| p.into_inner());
            buffer = next;
        }
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
    max_flows: usize,
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
    last_capacity_warn: Option<std::time::Instant>,
    /// Reusable MTU-sized landing area for the device read.
    ///
    /// This is the data path: a fresh `vec![0u8; mtu]` per `step()` meant an
    /// allocation on every poll, including the far more numerous polls that
    /// read nothing at all.
    read_buffer: Vec<u8>,
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
            max_flows: MAX_ACTIVE_TCP_FLOWS,
            waker,
            log_gate: DialLogGate::new(),
            flow_observer: Arc::new(NoopFlowObserver),
            health: Arc::new(super::health::FakeIpHealth::new()),
            instant_rst: Arc::new(AtomicBool::new(true)),
            worker_graveyard: Vec::new(),
            last_graveyard_warn: None,
            last_capacity_warn: None,
            read_buffer: Vec::new(),
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
    /// Lower the flow ceiling. Only tests do: production wants the memory
    /// bound the constant states.
    #[cfg(test)]
    fn with_max_flows(mut self, flows: usize) -> Self {
        self.max_flows = flows.max(1);
        self
    }

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
        let mtu = usize::from(self.device.mtu());
        if self.read_buffer.len() != mtu {
            self.read_buffer.resize(mtu, 0);
        }
        let read = self.device.read_raw(&mut self.read_buffer)?;
        if read > 0 {
            self.health.record_ingress();
            // `smoltcp` consumes the packet buffer, so this copy is the one the
            // device hand-off needs — sized to the PACKET rather than the MTU.
            let buf = self.read_buffer[..read].to_vec();
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

    /// Say it once a minute, not once per refused SYN: at the cap the refusals
    /// arrive as fast as the client retries.
    fn warn_at_flow_capacity(&mut self) {
        if self
            .last_capacity_warn
            .is_some_and(|at| at.elapsed() < GRAVEYARD_WARN_INTERVAL)
        {
            return;
        }
        self.last_capacity_warn = Some(std::time::Instant::now());
        tracing::warn!(
            target: "nrr::fake-ip",
            active = self.flows.len(),
            cap = self.max_flows,
            "fake-IP is carrying its maximum number of TCP flows — new connections are being reset until some finish",
        );
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
                // The upstream socket is finished (on Windows a connected UDP
                // socket reports WSAECONNRESET once an ICMP port-unreachable
                // comes back). Say so: a reader that just returns leaves the
                // client bound to a flow nothing reads, and its `send` keeps
                // succeeding, so the idle reap never comes for it either.
                Err(_) => {
                    replies.mark_dead();
                    return;
                }
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
/// Whether the client's half-close may be forwarded to the upstream yet.
///
/// Two conditions, and both were learned the hard way.
///
/// The STATE test is by the states that only follow the peer's FIN, never by
/// `!may_recv()`: that is also true before the handshake completes (Listen /
/// SynReceived) and would tear the upstream down before a byte ever flowed.
///
/// The DIAL test mirrors the drain that feeds the upstream queue. A client that
/// sends its request and immediately half-closes — the ordinary shape of a
/// one-shot request — does so while the dial is still in flight (2.8-3.2 s
/// through a tunnel). Its bytes are still sitting in the socket buffer, so a
/// FIN raised then reaches the upstream writer first: it finds an empty queue,
/// shuts the write half and returns, and the request is never sent. Once the
/// dial completes, the drain runs in the same tick and the FIN follows it.
///
/// A dial that FAILS never satisfies this — it marks the flow dead instead, and
/// the writer exits on that.
fn client_fin_may_propagate(dial_is_done: bool, state: tcp::State) -> bool {
    dial_is_done
        && matches!(
            state,
            tcp::State::CloseWait
                | tcp::State::Closing
                | tcp::State::LastAck
                | tcp::State::TimeWait
        )
}

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
            // The client is not keeping up: stop reading so the upstream's own
            // window closes, instead of buffering the difference here.
            reader_shared.await_upstream_queue_room();
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
                // Not an EOF: the peer went away mid-answer. Distinguished
                // from `Ok(0)` so the poll loop mirrors a reset rather than a
                // clean close.
                Err(_) => {
                    reader_shared.signal_upstream_reset();
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
mod tests;
