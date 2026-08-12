//! Opening the REAL connection a fake-IP flow stands for.
//!
//! Once the relay knows that "the application is talking to `198.18.0.7:443`"
//! means "the application is talking to `chatgpt.com:443`", something has to
//! open that real connection and move bytes. That something is a dialer, kept
//! behind a trait for two reasons:
//!
//! - the relay logic stays testable without a network (see [`MockRelayDialer`]);
//! - binding the outgoing socket to a particular interface — how a flow is
//!   actually STEERED onto the primary or the additional adapter — is the one
//!   part that will differ per OS, so it must not be welded into the relay.
//!
//! No TLS is terminated anywhere here: the relay copies the application's own
//! bytes through untouched, which is why fake-IP needs no certificates and
//! survives encrypted SNI.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_shared::RouteRole;

/// How long to wait for the upstream TCP handshake before giving up. A fake-IP
/// flow is already "connected" from the application's point of view by the time
/// we dial, so this deadline is what the user experiences as "the page gave
/// up". It has to outlast a slow tunnel — a dial through a loaded VPN measured
/// 2.8–3.2 s against 0.1–0.16 s direct, and a lossy link retransmits the SYN on
/// top of that — while staying inside what a browser is still willing to wait,
/// so the reset arrives before the user has given up on their own.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How often a UDP reader wakes to check for teardown when no datagram is
/// arriving. Short enough that a torn-down flow's worker exits promptly.
pub const UDP_READ_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How often a TCP splice reader wakes to check for teardown when the upstream
/// is silent. Without this, a peer that stalls without ever sending FIN/RST (a
/// flow through a tunnel that just went down) parks the reader in a blocking
/// `read` forever — `mark_dead` cannot unblock a thread that never returns.
pub const TCP_READ_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound for one upstream `write`. A peer that accepts nothing for this
/// long while bytes are pending is dead for relay purposes; failing the write
/// tears the flow down instead of leaving the writer thread unjoinable.
pub const UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a flow really goes, and over which route it must leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamTarget {
    /// Hostname the fake address stands for.
    pub hostname: String,
    /// The real address to reach, or `None` when nothing is known for the
    /// hostname yet and the dialer must find out. Resolving is allowed HERE and
    /// nowhere upstream of it: the dial already runs on its own thread, while
    /// the decision that produced this target runs on the shared poll loop,
    /// where a blocking lookup would stall every other flow.
    pub address: Option<SocketAddr>,
    /// Port the client asked for. Known even when the address is not.
    pub port: u16,
    /// Route the policy picked for this hostname.
    pub route: RouteRole,
}

impl UpstreamTarget {
    /// A target whose address is already known.
    #[must_use]
    pub fn at(hostname: String, address: SocketAddr, route: RouteRole) -> Self {
        Self {
            hostname,
            port: address.port(),
            address: Some(address),
            route,
        }
    }

    /// What to print for this target: the address once known, the name until
    /// then. Logs are keyed on it, so an unresolved flow does not collapse into
    /// one anonymous line with every other unresolved flow.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        match self.address {
            Some(address) => address.to_string(),
            None => format!("{}:{}", self.hostname, self.port),
        }
    }
}

/// Finds where a hostname really lives, at dial time.
///
/// Deliberately narrow: the dialer asks for addresses and nothing else. The
/// production implementation decides how — which resolver, over which link,
/// what it caches — without the dialer knowing any of it.
pub trait RelayNameResolver: Send + Sync {
    /// Addresses for `hostname`, best first. Empty means "could not find out",
    /// which fails the dial.
    fn resolve(&self, hostname: &str) -> Vec<IpAddr>;
}

/// Failure to establish or use an upstream connection.
#[derive(Debug)]
pub enum RelayError {
    /// The upstream refused, timed out, or the network is unreachable — a
    /// genuine network-level failure, never held by the instant-reset toggle.
    Upstream { detail: String },
    /// The dial was refused by source-address POLICY (see
    /// [`SourceBindDecision::Refuse`]), not by the network — most commonly
    /// the secondary adapter is unresolved during a VPN reconnect. Kept
    /// distinct from [`Self::Upstream`] so `fake_ip_instant_rst = false` can
    /// hold and retry ONLY this refusal class; a genuine network error always
    /// fails fast.
    SourcePolicyRefused { reason: &'static str },
    /// No datagram was ready within the read window — not an error, a poll tick.
    /// A UDP reader loops on this to stay responsive to teardown between packets.
    WouldBlock,
    /// The relay is shutting down.
    ShuttingDown,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream { detail } => write!(f, "upstream connection failed: {detail}"),
            Self::SourcePolicyRefused { reason } => {
                write!(f, "dial refused by source policy: {reason}")
            }
            Self::WouldBlock => write!(f, "no datagram ready"),
            Self::ShuttingDown => write!(f, "relay is shutting down"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<io::Error> for RelayError {
    fn from(error: io::Error) -> Self {
        // A read-timeout / non-blocking miss is a poll tick, not a failure.
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::WouldBlock,
            _ => Self::Upstream {
                detail: error.to_string(),
            },
        }
    }
}

/// A byte-stream to the real destination. `Read`/`Write` are all the relay
/// needs — it splices, it does not interpret.
pub trait RelayStream: Read + Write + Send {
    /// Signal end-of-stream upstream after the application closed its side,
    /// so a half-closed connection is mirrored instead of being torn down.
    fn shutdown_write(&mut self) -> Result<(), RelayError>;

    /// Split into independently owned read and write halves.
    ///
    /// The userspace stack pumps each direction of a spliced connection on its
    /// own thread: a blocking read waiting on the upstream server must never
    /// hold up a write carrying the client's request the other way. A single
    /// `Read + Write` handle cannot do both at once, so the stack asks for the
    /// two halves up front.
    fn into_split(self: Box<Self>) -> Result<RelaySplit, RelayError>;
}

/// The write half of a split [`RelayStream`], plus the half-close signal the
/// stack needs when the client stops sending.
pub trait RelayWriteHalf: Write + Send {
    /// Mirror the client's half-close upstream (see [`RelayStream::shutdown_write`]).
    fn shutdown_write(&mut self) -> Result<(), RelayError>;
}

/// The two halves of a split [`RelayStream`].
pub struct RelaySplit {
    /// Bytes coming back from the upstream server.
    pub reader: Box<dyn Read + Send>,
    /// Bytes going out to the upstream server.
    pub writer: Box<dyn RelayWriteHalf>,
}

/// A datagram socket bound for one UDP flow.
///
/// `Send + Sync` so the userspace stack can share one datagram between the poll
/// loop (which sends the client's bytes upstream) and a worker thread (which
/// blocks reading the upstream's replies) — the two directions of one UDP flow.
pub trait RelayDatagram: Send + Sync {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError>;
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, RelayError>;
}

/// Opens upstream connections on behalf of the relay.
pub trait RelayDialer: Send + Sync {
    fn connect_tcp(&self, target: &UpstreamTarget) -> Result<Box<dyn RelayStream>, RelayError>;
    fn connect_udp(&self, target: &UpstreamTarget) -> Result<Box<dyn RelayDatagram>, RelayError>;
}

// ── Source-address policy ────────────────────────────────────────────────────

/// What the dialer should do about the outgoing socket's source address for
/// one dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceBindDecision {
    /// Bind the socket to this local address before connecting — the flow
    /// egresses that address's adapter regardless of the default route.
    Bind(IpAddr),
    /// Leave the choice to the OS routing table.
    Unbound,
    /// Do not dial at all. The relay runs outside the per-user kill-switch
    /// scope, so a dial the policy cannot steer would silently egress the
    /// wrong link; refusing keeps the flow fail-closed (client sees a reset).
    Refuse { reason: &'static str },
}

/// Live source-address policy for relay dials, consulted per dial so adapter
/// churn (a VPN reconnect changing its address) is picked up immediately —
/// a snapshot taken at stack start would go stale mid-session.
pub trait RelaySourceAddrs: Send + Sync {
    fn decide(&self, route: RouteRole, remote: &SocketAddr) -> SourceBindDecision;
}

/// Fixed per-role source addresses; roles without one stay [`Unbound`]
/// (`SourceBindDecision::Unbound`). This is the permissive policy: it never
/// refuses, so it suits tests and setups with no live adapter source.
#[derive(Debug, Default, Clone)]
pub struct StaticSourceAddrs {
    primary: Option<IpAddr>,
    secondary: Option<IpAddr>,
}

impl RelaySourceAddrs for StaticSourceAddrs {
    fn decide(&self, route: RouteRole, _remote: &SocketAddr) -> SourceBindDecision {
        let source = match route {
            RouteRole::Primary => self.primary,
            RouteRole::Secondary => self.secondary,
        };
        source.map_or(SourceBindDecision::Unbound, SourceBindDecision::Bind)
    }
}

// ── Production dialer over the OS sockets ────────────────────────────────────

/// Dials with the operating system's own stack.
///
/// Route steering is applied by binding the outgoing socket to the source
/// address of the chosen adapter, per the [`RelaySourceAddrs`] policy. The
/// default policy never binds — the OS routing table picks, which is only
/// correct for the primary route — so production wires a live policy via
/// [`Self::with_source_addrs`].
#[derive(Default, Clone)]
pub struct SystemRelayDialer {
    fixed: StaticSourceAddrs,
    live: Option<Arc<dyn RelaySourceAddrs>>,
    /// Resolves a target that arrived without an address. Unwired means the
    /// relay never produces such targets, and one arriving anyway fails the
    /// dial rather than guessing.
    names: Option<Arc<dyn RelayNameResolver>>,
}

impl std::fmt::Debug for SystemRelayDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemRelayDialer")
            .field("fixed", &self.fixed)
            .field("live", &self.live.as_ref().map(|_| "…"))
            .finish()
    }
}

impl SystemRelayDialer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wire the live source-address policy (production: backed by the current
    /// adapter resolution). Takes precedence over any fixed addresses.
    #[must_use]
    pub fn with_source_addrs(mut self, source_addrs: Arc<dyn RelaySourceAddrs>) -> Self {
        self.live = Some(source_addrs);
        self
    }

    /// Bind flows routed to `role` to a fixed `source` address. Ignored while
    /// a live policy is wired.
    #[must_use]
    pub fn with_source(mut self, role: RouteRole, source: IpAddr) -> Self {
        match role {
            RouteRole::Primary => self.fixed.primary = Some(source),
            RouteRole::Secondary => self.fixed.secondary = Some(source),
        }
        self
    }

    /// Wire the dial-time name resolution the relay relies on when the address
    /// cache has nothing for a hostname.
    #[must_use]
    pub fn with_name_resolver(mut self, names: Arc<dyn RelayNameResolver>) -> Self {
        self.names = Some(names);
        self
    }

    fn decide(&self, route: RouteRole, address: &SocketAddr) -> SourceBindDecision {
        match self.live.as_ref() {
            Some(live) => live.decide(route, address),
            None => self.fixed.decide(route, address),
        }
    }

    /// The address to dial: the one the target carries, or one looked up now.
    ///
    /// This is the only DNS on the relay path, and it is on the dial thread by
    /// construction.
    fn dial_address(&self, target: &UpstreamTarget) -> Result<SocketAddr, RelayError> {
        if let Some(address) = target.address {
            return Ok(address);
        }
        let Some(names) = self.names.as_ref() else {
            return Err(RelayError::Upstream {
                detail: format!("no address for {} and no resolver wired", target.hostname),
            });
        };
        let started = std::time::Instant::now();
        let Some(ip) = names.resolve(&target.hostname).into_iter().next() else {
            return Err(RelayError::Upstream {
                detail: format!("could not find out where {} lives", target.hostname),
            });
        };
        tracing::debug!(
            target: "nrr::fake_ip",
            hostname = %target.hostname,
            address = %ip,
            elapsed_ms = started.elapsed().as_millis(),
            "resolved a flow's destination at dial time — nothing was cached for it",
        );
        Ok(SocketAddr::new(ip, target.port))
    }

    /// Resolve the bind decision for `address`, verifying address families: a
    /// mismatched bind (v4 source for a v6 remote) cannot steer the flow, and
    /// silently ignoring it would leak via the default route instead.
    fn bind_address_for(
        &self,
        route: RouteRole,
        address: &SocketAddr,
    ) -> Result<Option<SocketAddr>, RelayError> {
        match self.decide(route, address) {
            SourceBindDecision::Unbound => Ok(None),
            SourceBindDecision::Refuse { reason } => {
                Err(RelayError::SourcePolicyRefused { reason })
            }
            SourceBindDecision::Bind(source) => {
                if source.is_ipv4() != address.is_ipv4() {
                    return Err(RelayError::Upstream {
                        detail: format!(
                            "source address family mismatch: cannot bind {source} for {address}"
                        ),
                    });
                }
                Ok(Some(SocketAddr::new(source, 0)))
            }
        }
    }
}

/// Name a failed dial for what it was. The blanket `From<io::Error>` folds a
/// timeout into [`RelayError::WouldBlock`] because that is right for a READ
/// poll tick — on a dial it produced "no datagram ready" for an expired
/// connect, which is the last state of the poll rather than the reason, and it
/// sent an investigation looking for a UDP problem that did not exist. Says how
/// long it waited, so the ceiling can be judged from the log instead of guessed.
fn dial_failed(error: io::Error, address: SocketAddr, elapsed: Duration) -> RelayError {
    let waited_ms = elapsed.as_millis();
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => RelayError::Upstream {
            detail: format!(
                "connecting to {address} timed out after {waited_ms} ms (limit {} s)",
                UPSTREAM_CONNECT_TIMEOUT.as_secs()
            ),
        },
        _ => RelayError::Upstream {
            detail: format!("connecting to {address} failed after {waited_ms} ms: {error}"),
        },
    }
}

impl RelayDialer for SystemRelayDialer {
    fn connect_tcp(&self, target: &UpstreamTarget) -> Result<Box<dyn RelayStream>, RelayError> {
        let address = self.dial_address(target)?;
        let started = std::time::Instant::now();
        let stream = match self.bind_address_for(target.route, &address)? {
            None => TcpStream::connect_timeout(&address, UPSTREAM_CONNECT_TIMEOUT)
                .map_err(|e| dial_failed(e, address, started.elapsed()))?,
            Some(bind) => {
                // `std` cannot bind before connect; `socket2` can.
                let domain = if address.is_ipv4() {
                    socket2::Domain::IPV4
                } else {
                    socket2::Domain::IPV6
                };
                let socket = socket2::Socket::new(
                    domain,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                socket.bind(&bind.into())?;
                socket
                    .connect_timeout(&address.into(), UPSTREAM_CONNECT_TIMEOUT)
                    .map_err(|e| dial_failed(e, address, started.elapsed()))?;
                socket.into()
            }
        };
        stream.set_nodelay(true).ok();
        // Both timeouts exist so worker threads stay joinable: the reader turns
        // a silent-forever upstream into periodic teardown checks, the writer
        // cannot sit in `write` past the bound. Failure to set them must fail
        // the dial — an unbounded worker is exactly the wedge this prevents.
        stream.set_read_timeout(Some(TCP_READ_POLL_INTERVAL))?;
        stream.set_write_timeout(Some(UPSTREAM_WRITE_TIMEOUT))?;
        Ok(Box::new(TcpRelayStream { stream }))
    }

    fn connect_udp(&self, target: &UpstreamTarget) -> Result<Box<dyn RelayDatagram>, RelayError> {
        let address = self.dial_address(target)?;
        let bind: SocketAddr = match (self.bind_address_for(target.route, &address)?, address) {
            (Some(bind), _) => bind,
            (None, SocketAddr::V4(_)) => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
            (None, SocketAddr::V6(_)) => SocketAddr::new(IpAddr::from([0u16; 8]), 0),
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(address)?;
        // A read timeout turns a blocking `recv` into a poll tick, so the reader
        // worker observes teardown between datagrams instead of parking forever.
        socket.set_read_timeout(Some(UDP_READ_POLL_INTERVAL))?;
        Ok(Box::new(UdpRelayDatagram { socket }))
    }
}

struct TcpRelayStream {
    stream: TcpStream,
}

impl Read for TcpRelayStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for TcpRelayStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl RelayStream for TcpRelayStream {
    fn shutdown_write(&mut self) -> Result<(), RelayError> {
        self.stream.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }

    fn into_split(self: Box<Self>) -> Result<RelaySplit, RelayError> {
        // Both halves are handles to the same socket (`try_clone` dups the
        // descriptor), so a half-close on the writer reaches the peer while the
        // reader keeps draining the response already in flight.
        let reader = self.stream.try_clone()?;
        Ok(RelaySplit {
            reader: Box::new(reader),
            writer: Box::new(TcpWriteHalf {
                stream: self.stream,
            }),
        })
    }
}

struct TcpWriteHalf {
    stream: TcpStream,
}

impl Write for TcpWriteHalf {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl RelayWriteHalf for TcpWriteHalf {
    fn shutdown_write(&mut self) -> Result<(), RelayError> {
        self.stream.shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }
}

struct UdpRelayDatagram {
    socket: UdpSocket,
}

impl RelayDatagram for UdpRelayDatagram {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError> {
        Ok(self.socket.send(payload)?)
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize, RelayError> {
        Ok(self.socket.recv(buffer)?)
    }
}

// ── Test double ──────────────────────────────────────────────────────────────

/// Records every dial and hands back scripted streams. Always compiled, per the
/// crate convention, so the relay can be driven end-to-end in tests.
#[derive(Debug, Default, Clone)]
pub struct MockRelayDialer {
    state: Arc<Mutex<MockDialerState>>,
}

#[derive(Debug, Default)]
struct MockDialerState {
    dials: Vec<UpstreamTarget>,
    /// Bytes each opened stream will return to the relay.
    canned_response: Vec<u8>,
    /// Bytes the relay wrote upstream, concatenated.
    written: Vec<u8>,
    fail_with: Option<String>,
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::expect_used)]
impl MockRelayDialer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every upstream this dialer was asked to open, in order.
    #[must_use]
    pub fn dials(&self) -> Vec<UpstreamTarget> {
        self.state.lock().expect("mock dialer mutex").dials.clone()
    }

    /// Bytes the relay sent upstream.
    #[must_use]
    pub fn written(&self) -> Vec<u8> {
        self.state
            .lock()
            .expect("mock dialer mutex")
            .written
            .clone()
    }

    /// Seed what an opened stream returns when read.
    pub fn set_response(&self, bytes: &[u8]) {
        self.state
            .lock()
            .expect("mock dialer mutex")
            .canned_response = bytes.to_vec();
    }

    /// Make every subsequent dial fail — the "site is unreachable" path.
    pub fn fail_dials(&self, detail: &str) {
        self.state.lock().expect("mock dialer mutex").fail_with = Some(detail.to_string());
    }

    fn record(&self, target: &UpstreamTarget) -> Result<Vec<u8>, RelayError> {
        let mut state = self.state.lock().expect("mock dialer mutex");
        state.dials.push(target.clone());
        match &state.fail_with {
            Some(detail) => Err(RelayError::Upstream {
                detail: detail.clone(),
            }),
            None => Ok(state.canned_response.clone()),
        }
    }
}

#[allow(clippy::expect_used)]
impl RelayDialer for MockRelayDialer {
    fn connect_tcp(&self, target: &UpstreamTarget) -> Result<Box<dyn RelayStream>, RelayError> {
        let response = self.record(target)?;
        Ok(Box::new(MockStream {
            state: Arc::clone(&self.state),
            response,
            read_offset: 0,
            write_shut: false,
        }))
    }

    fn connect_udp(&self, target: &UpstreamTarget) -> Result<Box<dyn RelayDatagram>, RelayError> {
        let response = self.record(target)?;
        Ok(Box::new(MockDatagram {
            state: Arc::clone(&self.state),
            response,
            delivered: AtomicBool::new(false),
        }))
    }
}

struct MockStream {
    state: Arc<Mutex<MockDialerState>>,
    response: Vec<u8>,
    read_offset: usize,
    write_shut: bool,
}

#[allow(clippy::expect_used)]
impl Read for MockStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.response.len().saturating_sub(self.read_offset);
        let take = remaining.min(buffer.len());
        buffer[..take].copy_from_slice(&self.response[self.read_offset..self.read_offset + take]);
        self.read_offset += take;
        Ok(take)
    }
}

#[allow(clippy::expect_used)]
impl Write for MockStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.write_shut {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            ));
        }
        self.state
            .lock()
            .expect("mock dialer mutex")
            .written
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RelayStream for MockStream {
    fn shutdown_write(&mut self) -> Result<(), RelayError> {
        self.write_shut = true;
        Ok(())
    }

    fn into_split(self: Box<Self>) -> Result<RelaySplit, RelayError> {
        Ok(RelaySplit {
            reader: Box::new(MockReadHalf {
                response: self.response,
                read_offset: self.read_offset,
            }),
            writer: Box::new(MockWriteHalf {
                state: Arc::clone(&self.state),
                write_shut: self.write_shut,
            }),
        })
    }
}

struct MockReadHalf {
    response: Vec<u8>,
    read_offset: usize,
}

impl Read for MockReadHalf {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.response.len().saturating_sub(self.read_offset);
        let take = remaining.min(buffer.len());
        buffer[..take].copy_from_slice(&self.response[self.read_offset..self.read_offset + take]);
        self.read_offset += take;
        Ok(take)
    }
}

struct MockWriteHalf {
    state: Arc<Mutex<MockDialerState>>,
    write_shut: bool,
}

#[allow(clippy::expect_used)]
impl Write for MockWriteHalf {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.write_shut {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            ));
        }
        self.state
            .lock()
            .expect("mock dialer mutex")
            .written
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RelayWriteHalf for MockWriteHalf {
    fn shutdown_write(&mut self) -> Result<(), RelayError> {
        self.write_shut = true;
        Ok(())
    }
}

struct MockDatagram {
    state: Arc<Mutex<MockDialerState>>,
    response: Vec<u8>,
    /// The scripted reply is delivered once; further reads report `WouldBlock`,
    /// modelling a real socket that has no more datagrams pending.
    delivered: AtomicBool,
}

#[allow(clippy::expect_used)]
impl RelayDatagram for MockDatagram {
    fn send(&self, payload: &[u8]) -> Result<usize, RelayError> {
        self.state
            .lock()
            .expect("mock dialer mutex")
            .written
            .extend_from_slice(payload);
        Ok(payload.len())
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize, RelayError> {
        if self.delivered.swap(true, Ordering::SeqCst) {
            return Err(RelayError::WouldBlock);
        }
        let take = self.response.len().min(buffer.len());
        buffer[..take].copy_from_slice(&self.response[..take]);
        Ok(take)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// `Box<dyn RelayStream>` is not `Debug`, so `expect` is unavailable on a
    /// dial result — unwrap it explicitly instead.
    fn dialed(
        result: Result<Box<dyn RelayStream>, RelayError>,
        context: &str,
    ) -> Box<dyn RelayStream> {
        match result {
            Ok(stream) => stream,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn dial_error(result: Result<Box<dyn RelayStream>, RelayError>) -> RelayError {
        match result {
            Ok(_) => panic!("expected the dial to fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn an_expired_dial_says_it_timed_out_and_how_long_it_waited() {
        let address: SocketAddr = "203.0.113.7:443".parse().expect("address");
        let error = dial_failed(
            io::Error::from(io::ErrorKind::TimedOut),
            address,
            Duration::from_millis(10_004),
        );
        let text = error.to_string();
        assert!(
            text.contains("timed out") && text.contains("10004 ms"),
            "a dial that ran out of time must say so, got: {text}"
        );
        // Never the read-poll answer: "no datagram ready" for an expired TCP
        // connect is the poll state, not the reason.
        assert!(!matches!(error, RelayError::WouldBlock), "{text}");
    }

    #[test]
    fn a_refused_dial_keeps_the_underlying_reason() {
        let address: SocketAddr = "203.0.113.7:443".parse().expect("address");
        let error = dial_failed(
            io::Error::from(io::ErrorKind::ConnectionRefused),
            address,
            Duration::from_millis(12),
        );
        let text = error.to_string();
        assert!(text.contains("12 ms"), "{text}");
        assert!(!text.contains("timed out"), "{text}");
    }

    fn target(address: &str, route: RouteRole) -> UpstreamTarget {
        UpstreamTarget::at(
            "chatgpt.com".to_string(),
            address.parse().expect("address"),
            route,
        )
    }

    /// A target the relay produced without an address — the dialer is expected
    /// to find one.
    fn unresolved_target(hostname: &str, port: u16) -> UpstreamTarget {
        UpstreamTarget {
            hostname: hostname.to_string(),
            address: None,
            port,
            route: RouteRole::Primary,
        }
    }

    #[test]
    fn mock_records_dials_and_splices_bytes_both_ways() {
        let dialer = MockRelayDialer::new();
        dialer.set_response(b"from-upstream");
        let mut stream = dialed(
            dialer.connect_tcp(&target("1.2.3.4:443", RouteRole::Secondary)),
            "dial",
        );

        stream.write_all(b"client-hello").expect("write");
        let mut received = [0u8; 32];
        let read = stream.read(&mut received).expect("read");

        assert_eq!(&received[..read], b"from-upstream");
        assert_eq!(dialer.written(), b"client-hello");
        assert_eq!(dialer.dials().len(), 1);
        assert_eq!(dialer.dials()[0].route, RouteRole::Secondary);
        assert_eq!(dialer.dials()[0].hostname, "chatgpt.com");
    }

    #[test]
    fn a_half_close_stops_further_writes() {
        let dialer = MockRelayDialer::new();
        let mut stream = dialed(
            dialer.connect_tcp(&target("1.2.3.4:443", RouteRole::Primary)),
            "dial",
        );
        stream.shutdown_write().expect("shutdown");
        assert!(stream.write_all(b"late").is_err());
    }

    #[test]
    fn an_unreachable_upstream_surfaces_as_an_error() {
        let dialer = MockRelayDialer::new();
        dialer.fail_dials("network unreachable");
        let error = dial_error(dialer.connect_tcp(&target("1.2.3.4:443", RouteRole::Primary)));
        assert!(matches!(error, RelayError::Upstream { .. }));
        // The attempt is still recorded — diagnostics must show what was tried.
        assert_eq!(dialer.dials().len(), 1);
    }

    #[test]
    fn a_split_stream_carries_each_direction_independently() {
        let dialer = MockRelayDialer::new();
        dialer.set_response(b"server-reply");
        let stream = dialed(
            dialer.connect_tcp(&target("1.2.3.4:443", RouteRole::Primary)),
            "dial",
        );
        let split = match stream.into_split() {
            Ok(split) => split,
            Err(error) => panic!("split: {error}"),
        };
        let RelaySplit {
            mut reader,
            mut writer,
        } = split;

        writer.write_all(b"client-request").expect("write");
        let mut received = Vec::new();
        reader.read_to_end(&mut received).expect("read");
        assert_eq!(received, b"server-reply");
        assert_eq!(dialer.written(), b"client-request");

        writer.shutdown_write().expect("half close");
        assert!(writer.write_all(b"late").is_err());
    }

    #[test]
    fn system_dialer_binds_the_source_address_the_policy_chose() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        // Hand the accepted socket back instead of dropping it here: closing
        // it before the connecting side's readiness poll observes the
        // handshake can turn a healthy connect into a spurious hang-up under
        // scheduling pressure (a real flake this test used to have). Keeping
        // it open until after the dial already succeeded removes the race.
        let accepted = std::thread::spawn(move || listener.accept().expect("accept"));

        let dialer = SystemRelayDialer::new()
            .with_source(RouteRole::Secondary, IpAddr::from([127, 0, 0, 1]));
        let _stream = dialed(
            dialer.connect_tcp(&target(&address.to_string(), RouteRole::Secondary)),
            "bound connect",
        );
        let (_socket, peer) = accepted.join().expect("accept thread");
        assert_eq!(
            peer.ip(),
            IpAddr::from([127, 0, 0, 1]),
            "the connection left from the bound source address"
        );
    }

    /// A refusing policy for the fail-closed dial path.
    struct RefuseAll;
    impl RelaySourceAddrs for RefuseAll {
        fn decide(&self, _route: RouteRole, _remote: &SocketAddr) -> SourceBindDecision {
            SourceBindDecision::Refuse {
                reason: "refused by test policy",
            }
        }
    }

    #[test]
    fn system_dialer_refuses_when_the_policy_says_so() {
        // A listener that must never see a connection.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let dialer = SystemRelayDialer::new().with_source_addrs(Arc::new(RefuseAll));
        let error =
            dial_error(dialer.connect_tcp(&target(&address.to_string(), RouteRole::Secondary)));
        assert!(
            error.to_string().contains("refused by test policy"),
            "the refusal reason surfaces in the error, got: {error}"
        );
        assert!(
            matches!(
                listener.accept(),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock
            ),
            "no connection was attempted"
        );
    }

    #[test]
    fn system_dialer_rejects_a_source_family_mismatch_instead_of_leaking() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");

        // v6 source for a v4 remote cannot steer the flow; silently dialing
        // unbound would egress the default route instead of the policy's link.
        let dialer = SystemRelayDialer::new()
            .with_source(RouteRole::Secondary, "::1".parse().expect("v6 source"));
        let error =
            dial_error(dialer.connect_tcp(&target(&address.to_string(), RouteRole::Secondary)));
        assert!(
            error.to_string().contains("family mismatch"),
            "got: {error}"
        );
    }

    #[test]
    fn a_target_without_an_address_is_resolved_at_dial_time() {
        // The flow the relay could not have decided on the poll thread: nothing
        // was cached for the hostname, so the address is found here instead of
        // the client getting a reset.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let accepted = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut buffer = [0u8; 16];
            let read = socket.read(&mut buffer).expect("read");
            buffer[..read].to_vec()
        });

        struct Knows(IpAddr);
        impl RelayNameResolver for Knows {
            fn resolve(&self, _hostname: &str) -> Vec<IpAddr> {
                vec![self.0]
            }
        }
        let dialer = SystemRelayDialer::new().with_name_resolver(Arc::new(Knows(address.ip())));
        let mut stream = dialed(
            dialer.connect_tcp(&unresolved_target("late.example", address.port())),
            "connect",
        );
        stream.write_all(b"ping").expect("write");
        stream.shutdown_write().expect("half close");

        assert_eq!(accepted.join().expect("join"), b"ping");
    }

    #[test]
    fn an_unresolvable_target_fails_the_dial_instead_of_guessing() {
        struct KnowsNothing;
        impl RelayNameResolver for KnowsNothing {
            fn resolve(&self, _hostname: &str) -> Vec<IpAddr> {
                Vec::new()
            }
        }
        let dialer = SystemRelayDialer::new().with_name_resolver(Arc::new(KnowsNothing));
        let error = dial_error(dialer.connect_tcp(&unresolved_target("nowhere.example", 443)));
        assert!(
            error.to_string().contains("nowhere.example"),
            "got: {error}"
        );

        // And with no resolver wired at all the dial fails rather than the
        // process pretending it can reach the name.
        let bare = SystemRelayDialer::new();
        let error = dial_error(bare.connect_tcp(&unresolved_target("nowhere.example", 443)));
        assert!(error.to_string().contains("no resolver"), "got: {error}");
    }

    #[test]
    fn system_dialer_connects_to_a_real_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let accepted = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut buffer = [0u8; 16];
            let read = socket.read(&mut buffer).expect("read");
            buffer[..read].to_vec()
        });

        let dialer = SystemRelayDialer::new();
        let mut stream = dialed(
            dialer.connect_tcp(&UpstreamTarget::at(
                "localhost".to_string(),
                address,
                RouteRole::Primary,
            )),
            "connect",
        );
        stream.write_all(b"ping").expect("write");
        stream.shutdown_write().expect("half close");

        assert_eq!(accepted.join().expect("join"), b"ping");
    }

    #[test]
    fn system_dialer_binds_udp_and_sends() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let address = peer.local_addr().expect("addr");
        let dialer = SystemRelayDialer::new()
            .with_source(RouteRole::Primary, "127.0.0.1".parse().expect("source"));
        let socket = match dialer.connect_udp(&UpstreamTarget::at(
            "localhost".to_string(),
            address,
            RouteRole::Primary,
        )) {
            Ok(socket) => socket,
            Err(error) => panic!("connect: {error}"),
        };
        socket.send(b"datagram").expect("send");

        let mut buffer = [0u8; 16];
        let (read, _) = peer.recv_from(&mut buffer).expect("recv");
        assert_eq!(&buffer[..read], b"datagram");
    }
}
