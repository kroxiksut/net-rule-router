//! Which upstream DNS server the loopback resolver forwards to.
//!
//! Mode B puts our listener in front of every name query on the machine, so the
//! upstream it forwards to is a single point of failure: pick a server that does
//! not answer and name resolution stops working machine-wide, with nothing in
//! the UI to explain it. Enumeration is per-OS ([`SystemDnsServersPort`]);
//! choosing among the candidates is policy and lives here — probe before
//! committing, rotate when the active one stops answering, re-enumerate when the
//! network changes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsServer};

/// Standard DNS port; the OS never reports a port with its server list.
const DNS_PORT: u16 = 53;

/// Consecutive forward failures that retire the active server. One lost
/// datagram is ordinary UDP; three in a row on a link that is otherwise up is
/// the server, not the network.
const FAILURES_BEFORE_ROTATE: u32 = 3;

/// Floor between re-enumerations. Enumerating shells out to the OS, and a burst
/// of failures (or a flapping link) would otherwise hammer it.
const MIN_REFRESH_GAP: Duration = Duration::from_secs(10);

/// Floor between probe sweeps that found nothing. [`MIN_REFRESH_GAP`] only gates
/// re-enumeration; without a floor here an offline machine pays the whole
/// candidate list at [`PROBE_TIMEOUT`] each on every failed forward, in every
/// worker at once.
const MIN_SWEEP_GAP: Duration = Duration::from_secs(3);

/// Floor between checks of the active server against the published foreign
/// interfaces on the query path: one lock-free-ish read per second, not per query.
const EXCLUSION_RECHECK: Duration = Duration::from_secs(1);

/// Foreign resolvers probed to tell "only a corporate resolver is reachable"
/// from "nothing answers"; bounded because the sweep that asks already failed.
const FOREIGN_PROBES: usize = 2;

/// Name used to probe a candidate. Reserved by RFC 2606, answered by every
/// recursive resolver, owned by nobody — and the probe accepts ANY well-formed
/// reply (NXDOMAIN and REFUSED included), so what is being tested is reachability
/// of the server, never the health of the wider internet.
const PROBE_NAME: &str = "example.com";

/// Probe budget. Short: this runs while the resolver is arming, and a candidate
/// that needs longer than this is not the one to put in front of every query.
const PROBE_TIMEOUT: Duration = Duration::from_millis(700);

/// Answers "does this server reply at all". Behind a trait so the pool's
/// rotation logic is unit-tested without sockets.
pub trait UpstreamProbe: Send + Sync {
    fn responds(&self, server: SocketAddr) -> bool;
}

/// Production probe: one `A` query, any well-formed reply counts.
pub struct UdpUpstreamProbe {
    timeout: Duration,
}

impl Default for UdpUpstreamProbe {
    fn default() -> Self {
        Self {
            timeout: PROBE_TIMEOUT,
        }
    }
}

/// Query id for one probe. Random, because the id is the only thing that ties
/// a reply to this probe: a counter starting at a fixed value announces the
/// next id to anyone who saw the last one.
fn probe_id() -> u16 {
    let mut bytes = [0u8; 2];
    match getrandom::fill(&mut bytes) {
        Ok(()) => u16::from_ne_bytes(bytes),
        // Same fallback shape as the token store: a clock-derived value is
        // weaker than random but better than a predictable sequence.
        Err(_) => {
            static PROBE_ID: AtomicU32 = AtomicU32::new(0x5100);
            PROBE_ID.fetch_add(1, Ordering::Relaxed) as u16
        }
    }
}

impl UpstreamProbe for UdpUpstreamProbe {
    fn responds(&self, server: SocketAddr) -> bool {
        let id = probe_id();
        let Some(query) =
            crate::dns_wire::build_address_query(id, PROBE_NAME, crate::dns_wire::QTYPE_A)
        else {
            return false;
        };
        let wildcard: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let Ok(sock) = UdpSocket::bind(wildcard) else {
            return false;
        };
        nrr_platform_api::own_traffic::mark_own_socket(&sock);
        // Connected, so the kernel drops datagrams from anyone but the server
        // being probed. Unconnected, any host on the segment could answer for
        // it — and this probe is what decides which upstream we then trust with
        // every rule-host lookup.
        if sock.set_read_timeout(Some(self.timeout)).is_err()
            || sock.connect(server).is_err()
            || sock.send(&query).is_err()
        {
            return false;
        }
        // A smaller buffer fails the receive on Windows, and a live server that
        // answers big is still a live server.
        let mut buf = [0u8; crate::dns_resolver_ports::MAX_REPLY_DATAGRAM];
        let Ok(n) = sock.recv(&mut buf) else {
            return false;
        };
        // Beyond the source, only the id has to match: an NXDOMAIN or REFUSED
        // proves the server is there, which is the whole question.
        n >= crate::dns_wire::DNS_HEADER_LEN && u16::from_be_bytes([buf[0], buf[1]]) == id
    }
}

/// Accepts every candidate. For tests and for callers that deliberately skip
/// probing.
pub struct AcceptingProbe;

impl UpstreamProbe for AcceptingProbe {
    fn responds(&self, _server: SocketAddr) -> bool {
        true
    }
}

/// Names the interface whose resolver should be preferred — the link the
/// routing policy actually sends traffic over. `None` while nothing is bound or
/// resolvable, which simply leaves the OS enumeration order in charge.
pub type PreferredInterfaceFn = Arc<dyn Fn() -> Option<u32> + Send + Sync>;

/// The interfaces whose resolvers must never serve as a general upstream:
/// somebody else's tunnels. Their servers answer for their own namespaces only,
/// and sending every name there would hand them the machine's whole lookup history.
pub type ExcludedInterfacesFn = Arc<dyn Fn() -> Vec<u32> + Send + Sync>;

/// The same set as already published, `None` before the first publication.
/// Never reads the machine, so the query path may ask it.
pub type PublishedExcludedFn = Arc<dyn Fn() -> Option<Vec<u32>> + Send + Sync>;

/// Whether a server listed on no interface is reached through a foreign tunnel.
type UnboundBarredFn = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Why no upstream is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamDarkCause {
    /// No candidate answered.
    NothingAnswers,
    /// Every resolver outside the foreign tunnels is unreachable and a foreign
    /// tunnel's resolver does answer: a full-tunnel VPN that blocks other DNS.
    OnlyForeignAnswers,
}

struct PoolState {
    /// Candidates in preference order, as last enumerated.
    candidates: Vec<UpstreamDnsServer>,
    /// The server currently being forwarded to.
    active: Option<IpAddr>,
    /// Consecutive failures reported against `active`.
    failures: u32,
    last_refresh: Option<Instant>,
    /// When the last full sweep ended with nothing answering. Gates the probes
    /// themselves, which `last_refresh` does not.
    last_empty_sweep: Option<Instant>,
    /// Last time the active server was checked against the published foreign
    /// interfaces on the query path.
    last_exclusion_check: Option<Instant>,
}

/// The live choice of upstream DNS server.
///
/// Cloneable handle semantics: wrap in `Arc` and share — every consumer sees the
/// same active server, and a rotation triggered by one is immediately visible to
/// the others.
pub struct UpstreamDnsPool {
    servers: Arc<dyn SystemDnsServersPort>,
    probe: Arc<dyn UpstreamProbe>,
    /// What every candidate is reached on; only an explicitly dictated
    /// address ([`Self::fixed`]) differs from the standard port.
    port: u16,
    preferred_interface: OnceLock<PreferredInterfaceFn>,
    excluded_interfaces: OnceLock<ExcludedInterfacesFn>,
    published_excluded: OnceLock<PublishedExcludedFn>,
    unbound_barred: OnceLock<UnboundBarredFn>,
    /// The excluded set the last background re-selection ran for, sorted;
    /// see [`Self::note_excluded_change_in_background`].
    followed_excluded: Mutex<Vec<u32>>,
    /// The preferred interface as last read; the question reads the machine,
    /// so it is asked at most once per [`MIN_REFRESH_GAP`] and on a network
    /// change.
    preferred_cache: Mutex<Option<(Instant, Option<u32>)>>,
    /// Held for the duration of one sweep. Probing is slow and the answer is
    /// shared, so a second caller takes the current choice rather than running
    /// the same probes beside the first.
    sweep: Mutex<()>,
    state: Mutex<PoolState>,
    /// A background re-selection is under way; see
    /// [`Self::note_network_change_in_background`].
    background_refresh: AtomicBool,
    /// The last sweep found no server answering and nothing has answered
    /// since. Read by the resolver service, which lifts the redirect while it
    /// holds: every forward would wait out its timeout and fail.
    dark: AtomicBool,
    /// With `dark`: the foreign tunnel's resolver answers while nothing else does.
    dark_foreign_only: AtomicBool,
    /// The idle sockets queries reuse; a network change closes them.
    sockets: &'static crate::dns_upstream_sockets::UpstreamSockets,
}

impl UpstreamDnsPool {
    pub fn new(servers: Arc<dyn SystemDnsServersPort>, probe: Arc<dyn UpstreamProbe>) -> Self {
        Self {
            servers,
            probe,
            port: DNS_PORT,
            preferred_interface: OnceLock::new(),
            excluded_interfaces: OnceLock::new(),
            published_excluded: OnceLock::new(),
            unbound_barred: OnceLock::new(),
            followed_excluded: Mutex::new(Vec::new()),
            preferred_cache: Mutex::new(None),
            sweep: Mutex::new(()),
            state: Mutex::new(PoolState {
                candidates: Vec::new(),
                active: None,
                failures: 0,
                last_refresh: None,
                last_empty_sweep: None,
                last_exclusion_check: None,
            }),
            background_refresh: AtomicBool::new(false),
            dark: AtomicBool::new(false),
            dark_foreign_only: AtomicBool::new(false),
            sockets: crate::dns_upstream_sockets::shared(),
        }
    }

    /// Whether no upstream is known to answer right now — see [`Self::dark`].
    pub fn upstream_dark(&self) -> bool {
        self.dark.load(Ordering::Relaxed)
    }

    /// Why the pool is dark; `None` while an upstream answers.
    pub fn upstream_dark_cause(&self) -> Option<UpstreamDarkCause> {
        if !self.upstream_dark() {
            return None;
        }
        Some(if self.dark_foreign_only.load(Ordering::Relaxed) {
            UpstreamDarkCause::OnlyForeignAnswers
        } else {
            UpstreamDarkCause::NothingAnswers
        })
    }

    /// Prefer the resolver of the interface this returns.
    ///
    /// Reachability alone picks the wrong server when the machine's default
    /// route belongs to a link the policy does not use: that link's resolver
    /// answers for the internet but knows nothing of the bound link's internal
    /// names, and the traffic itself still leaves over the bound link. The
    /// preference only reorders — an unreachable preferred server is still
    /// passed over.
    pub fn with_preferred_interface(self, preferred: PreferredInterfaceFn) -> Self {
        self.set_preferred_interface(preferred);
        self
    }

    /// Same, for the shared pool: it is built before the routing coordinator
    /// that answers the question exists. First writer wins.
    pub fn set_preferred_interface(&self, preferred: PreferredInterfaceFn) {
        let _ = self.preferred_interface.set(preferred);
    }

    /// Keep the resolvers of the interfaces this returns out of the candidate
    /// list. First writer wins. Asked on every reselect, failures on the query
    /// path included, so it reads published state rather than the machine.
    pub fn set_excluded_interfaces(&self, excluded: ExcludedInterfacesFn) {
        let _ = self.excluded_interfaces.set(excluded);
    }

    /// The published form of the same set: lets the query path drop an active
    /// server whose interface turned foreign without waiting for a reselect.
    pub fn set_published_excluded(&self, published: PublishedExcludedFn) {
        let _ = self.published_excluded.set(published);
    }

    /// Both sets from `cell`, for a platform whose routing pass publishes the
    /// foreign tunnels there and has nothing to ask before it does: until the
    /// first publication nothing is excluded, since doubt is "not foreign".
    /// A server whose mechanism names no link is barred only when it is reached
    /// through a tunnel; elsewhere it may be the user's only resolver.
    pub fn follow_foreign_tunnels(&self, cell: Arc<crate::foreign_tunnels::ForeignTunnelCell>) {
        let published = Arc::clone(&cell);
        self.set_published_excluded(Arc::new(move || published.interfaces()));
        let carried = Arc::clone(&cell);
        let _ = self
            .unbound_barred
            .set(Arc::new(move |server| match server {
                IpAddr::V4(v4) => carried.routes_through_tunnel(v4),
                IpAddr::V6(_) => false,
            }));
        self.set_excluded_interfaces(Arc::new(move || cell.interfaces().unwrap_or_default()));
    }

    /// Barred from general use: listed on an excluded interface, or on none
    /// while it is reached through a foreign tunnel.
    fn is_barred(&self, candidate: &UpstreamDnsServer, excluded: &[u32]) -> bool {
        match candidate.interface_index {
            Some(index) => excluded.contains(&index),
            None => self
                .unbound_barred
                .get()
                .is_some_and(|carried| carried(candidate.server)),
        }
    }

    /// A pool pinned to one server, with no enumeration and no probing. The
    /// shape callers use when the upstream is dictated rather than discovered
    /// (tests, and any caller handed an explicit address).
    pub fn fixed(server: SocketAddr) -> Self {
        let ip = server.ip();
        let servers = match ip {
            IpAddr::V4(v4) => nrr_platform_api::dns::StaticDnsServers::new(vec![v4]),
            IpAddr::V6(v6) => {
                nrr_platform_api::dns::StaticDnsServers::new(Vec::new()).with_v6(vec![v6])
            }
        };
        Self {
            servers: Arc::new(servers),
            probe: Arc::new(AcceptingProbe),
            port: server.port(),
            preferred_interface: OnceLock::new(),
            excluded_interfaces: OnceLock::new(),
            published_excluded: OnceLock::new(),
            unbound_barred: OnceLock::new(),
            followed_excluded: Mutex::new(Vec::new()),
            preferred_cache: Mutex::new(None),
            sweep: Mutex::new(()),
            state: Mutex::new(PoolState {
                candidates: vec![UpstreamDnsServer {
                    interface_index: None,
                    server: ip,
                }],
                active: Some(ip),
                failures: 0,
                last_refresh: Some(Instant::now()),
                last_empty_sweep: None,
                last_exclusion_check: None,
            }),
            background_refresh: AtomicBool::new(false),
            dark: AtomicBool::new(false),
            dark_foreign_only: AtomicBool::new(false),
            sockets: crate::dns_upstream_sockets::shared(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The server to forward to right now, or `None` while no candidate has been
    /// found to answer. `None` means "do not redirect": leaving the OS resolver
    /// alone beats pointing it at a black hole.
    ///
    /// When this drops a server whose link turned foreign, a re-selection
    /// starts in the background: the query that saw the drop goes without, the
    /// next one finds a server, and none of them waits on a probe.
    pub fn current(self: &Arc<Self>) -> Option<SocketAddr> {
        let (active, dropped) = self.current_checked();
        if dropped {
            self.in_background(Self::refresh, |_| {});
        }
        active
    }

    /// [`Self::current`] for a caller that would rather wait for a sweep than
    /// go without: it re-selects in place.
    pub fn current_or_select(&self) -> Option<SocketAddr> {
        self.current_checked()
            .0
            .or_else(|| self.note_network_change())
    }

    /// The active server, after dropping it if its link turned foreign; the
    /// flag says whether it was dropped.
    fn current_checked(&self) -> (Option<SocketAddr>, bool) {
        {
            let mut state = self.lock();
            let due = self.published_excluded.get().is_some()
                && state
                    .last_exclusion_check
                    .is_none_or(|at| at.elapsed() >= EXCLUSION_RECHECK);
            if !due {
                return (
                    state.active.map(|ip| SocketAddr::from((ip, self.port))),
                    false,
                );
            }
            state.last_exclusion_check = Some(Instant::now());
        }
        let mut dropped = false;
        if let Some(excluded) = self.published_excluded.get().and_then(|f| f()) {
            if self.drop_barred_active(&excluded) {
                dropped = true;
                // The next caller may re-select at once.
                let mut state = self.lock();
                state.last_refresh = None;
                state.last_empty_sweep = None;
                tracing::warn!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-upstream-dropped-foreign",
                    "upstream DNS server dropped: its interface now belongs to another VPN",
                );
            }
        }
        let active = self
            .lock()
            .active
            .map(|ip| SocketAddr::from((ip, self.port)));
        (active, dropped)
    }

    /// Forget the active server when every place it is listed is barred.
    /// Returns whether it did.
    fn drop_barred_active(&self, excluded: &[u32]) -> bool {
        let mut state = self.lock();
        let Some(active) = state.active else {
            return false;
        };
        let (mut here, mut elsewhere) = (false, false);
        for c in state.candidates.iter().filter(|c| c.server == active) {
            if self.is_barred(c, excluded) {
                here = true;
            } else {
                elsewhere = true;
            }
        }
        if here && !elsewhere {
            state.active = None;
            state.failures = 0;
            return true;
        }
        false
    }

    /// A forward succeeded — the active server is good.
    pub fn note_success(&self) {
        self.lock().failures = 0;
        self.dark.store(false, Ordering::Relaxed);
    }

    /// A forward failed. Returns the replacement once the failure streak retires
    /// the active server, so the caller can retry the same query immediately
    /// instead of making the client wait for its own timeout.
    pub fn note_failure(&self) -> Option<SocketAddr> {
        {
            let mut state = self.lock();
            state.failures = state.failures.saturating_add(1);
            if state.failures < FAILURES_BEFORE_ROTATE {
                return None;
            }
        }
        let retired = self.lock().active;
        let replacement = self.reselect(retired);
        if replacement != retired {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-upstream-rotated",
                retired = ?retired,
                active = ?replacement,
                "upstream DNS stopped answering — switched to another server",
            );
        }
        replacement
            .filter(|ip| Some(*ip) != retired)
            .map(|ip| SocketAddr::from((ip, self.port)))
    }

    /// Re-enumerate and re-probe now, regardless of the failure streak. Called
    /// when arming and whenever the OS reports a network change — a new link
    /// usually means a new resolver, and the old one may still answer while
    /// pointing at the wrong network.
    pub fn refresh(&self) -> Option<SocketAddr> {
        let previous = self.lock().active;
        {
            let mut state = self.lock();
            // An explicit refresh ignores both floors: a network change is a
            // reason to re-probe even if the last sweep just came up empty.
            state.last_refresh = None;
            state.last_empty_sweep = None;
        }
        let selected = self.reselect(None);
        if selected != previous {
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "dns-upstream-reselected",
                previous = ?previous,
                active = ?selected,
                "upstream DNS re-selected after a network change",
            );
        }
        selected.map(|ip| SocketAddr::from((ip, self.port)))
    }

    /// Probe the known candidates again (re-enumerating only when the list is
    /// stale), for a caller waiting for ANY server to answer. Honours the
    /// pool's floors, so calling it every few seconds costs one sweep each.
    pub fn reprobe(&self) -> Option<SocketAddr> {
        let ip = self.reselect(None)?;
        // `reselect` keeps the previous server when nothing answered; the
        // redirect may come back only on one that answered, never on that.
        if self.dark.load(Ordering::Relaxed) {
            return None;
        }
        Some(SocketAddr::from((ip, self.port)))
    }

    /// The OS reported a network change. Re-selects at most once per
    /// [`MIN_REFRESH_GAP`] — this is called from the adapter hook, which fires
    /// on every interface flap, and re-selection shells out to the OS.
    pub fn note_network_change(&self) -> Option<SocketAddr> {
        // Before the gap check: a reused socket would keep asking from the
        // old network's address until it ages out.
        self.sockets.drain();
        *self
            .preferred_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        let due = {
            let state = self.lock();
            state
                .last_refresh
                .is_none_or(|at| at.elapsed() >= MIN_REFRESH_GAP)
        };
        if !due {
            // A server dropped just now is replaced here, not left for later.
            let (active, dropped) = self.current_checked();
            if !dropped {
                return active;
            }
        }
        self.refresh()
    }

    /// [`Self::note_network_change`] on a worker thread, handing the selection
    /// to `then`. Probing dead servers costs up to a probe timeout each, and the
    /// enforcement pass that notices a network change must not wait on it.
    /// While one background re-selection runs, another request is dropped:
    /// that one already answers for the current network.
    pub fn note_network_change_in_background<F>(self: &Arc<Self>, then: F)
    where
        F: FnOnce(Option<SocketAddr>) + Send + 'static,
    {
        self.in_background(Self::note_network_change, then);
    }

    /// A routing pass may have moved the excluded set. When it did, re-select
    /// at once on a worker thread, past the refresh floor: a tunnel that came
    /// up bars its resolver, one that went away frees it, and a dropped active
    /// server would otherwise wait for a failure streak no query reports.
    /// Reads published state only; returns whether a re-selection started.
    pub fn note_excluded_change_in_background<F>(self: &Arc<Self>, then: F) -> bool
    where
        F: FnOnce(Option<SocketAddr>) + Send + 'static,
    {
        let Some(excluded) = self.excluded_interfaces.get() else {
            return false;
        };
        let mut now = excluded();
        now.sort_unstable();
        now.dedup();
        let mut followed = self
            .followed_excluded
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if *followed == now {
            return false;
        }
        // Recorded only once a worker takes it: one that is busy may have read
        // the set before it moved, and the next pass asks again.
        let started = self.in_background(Self::refresh, then);
        if started {
            *followed = now;
        }
        started
    }

    /// Run `work` on a worker thread and hand its selection to `then`. At most
    /// one runs at a time; returns whether this call started one.
    fn in_background<F>(self: &Arc<Self>, work: fn(&Self) -> Option<SocketAddr>, then: F) -> bool
    where
        F: FnOnce(Option<SocketAddr>) + Send + 'static,
    {
        if self.background_refresh.swap(true, Ordering::SeqCst) {
            return false;
        }
        /// Clears the busy flag however the worker ends, a panic included:
        /// left set, it would drop every later re-selection for good.
        struct RefreshDone(Arc<UpstreamDnsPool>);
        impl Drop for RefreshDone {
            fn drop(&mut self) {
                self.0.background_refresh.store(false, Ordering::SeqCst);
            }
        }
        let pool = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("nrr-dns-upstream-refresh".into())
            .spawn(move || {
                let done = RefreshDone(pool);
                let selected = work(&done.0);
                drop(done);
                then(selected);
            });
        if let Err(e) = spawned {
            self.background_refresh.store(false, Ordering::SeqCst);
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-upstream-worker-spawn-failed",
                error = %e,
                "could not start the upstream DNS re-selection worker",
            );
            return false;
        }
        true
    }

    fn preferred_interface_now(&self) -> Option<u32> {
        let resolve = self.preferred_interface.get()?;
        let mut cache = self
            .preferred_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match *cache {
            Some((at, value)) if at.elapsed() < MIN_REFRESH_GAP => value,
            _ => {
                let value = resolve();
                *cache = Some((Instant::now(), value));
                value
            }
        }
    }

    /// Pick the first candidate that answers, preferring anything over `avoid`.
    /// Re-enumerates from the OS when the candidate list is stale.
    fn reselect(&self, avoid: Option<IpAddr>) -> Option<IpAddr> {
        // Before the early returns below, which hand back `active` as is.
        let excluded = self.excluded_interfaces.get().map(|f| f());
        if let Some(excluded) = excluded.as_deref() {
            self.drop_barred_active(excluded);
        }
        let swept_recently = {
            let state = self.lock();
            state
                .last_empty_sweep
                .is_some_and(|at| at.elapsed() < MIN_SWEEP_GAP)
        };
        if swept_recently {
            return self.lock().active;
        }
        // A sweep already under way answers for everyone: waiting on it would
        // cost the same as running it, and running it twice costs double.
        let Ok(_sweeping) = self.sweep.try_lock() else {
            return self.lock().active;
        };
        let stale = {
            let state = self.lock();
            state
                .last_refresh
                .is_none_or(|at| at.elapsed() >= MIN_REFRESH_GAP)
        };
        if stale {
            // Per link: a server barred on a foreign tunnel stays usable when
            // a link of ours offers it too.
            let fresh = self.servers.upstream_candidates_per_link();
            let mut state = self.lock();
            state.last_refresh = Some(Instant::now());
            if !fresh.is_empty() {
                state.candidates = fresh;
            }
        }
        let mut candidates = self.lock().candidates.clone();
        let mut barred: Vec<IpAddr> = Vec::new();
        if let Some(excluded) = excluded.as_deref() {
            let is_excluded = |c: &UpstreamDnsServer| self.is_barred(c, excluded);
            barred = candidates
                .iter()
                .filter(|c| is_excluded(c))
                .map(|c| c.server)
                .collect();
            candidates.retain(|c| !is_excluded(c));
            barred.retain(|ip| !candidates.iter().any(|c| c.server == *ip));
            barred.sort_unstable();
            barred.dedup();
            // The list may have been re-enumerated since the drop above.
            self.drop_barred_active(excluded);
        }
        // Preferred interface first, then everything else, and the server we are
        // trying to move off of last.
        let preferred = self.preferred_interface_now();
        let on_preferred =
            |c: &UpstreamDnsServer| preferred.is_some() && c.interface_index == preferred;
        let mut ordered: Vec<&UpstreamDnsServer> = Vec::with_capacity(candidates.len());
        ordered.extend(
            candidates
                .iter()
                .filter(|c| Some(c.server) != avoid && on_preferred(c)),
        );
        ordered.extend(
            candidates
                .iter()
                .filter(|c| Some(c.server) != avoid && !on_preferred(c)),
        );
        ordered.extend(candidates.iter().filter(|c| Some(c.server) == avoid));
        // A server several links offer is probed once, at its best place.
        let mut probed: Vec<IpAddr> = Vec::with_capacity(ordered.len());
        for ip in ordered.into_iter().map(|c| c.server) {
            if probed.contains(&ip) {
                continue;
            }
            probed.push(ip);
            if self.probe.responds(SocketAddr::from((ip, self.port))) {
                let mut state = self.lock();
                state.active = Some(ip);
                state.failures = 0;
                state.last_empty_sweep = None;
                self.dark.store(false, Ordering::Relaxed);
                self.dark_foreign_only.store(false, Ordering::Relaxed);
                return Some(ip);
            }
        }
        // Nothing answered. Keep the previous choice rather than blanking it:
        // a machine that is briefly offline has no better server to offer, and
        // dropping the redirect mid-session would be the louder failure. The
        // `dark` flag says so for whoever must act on it.
        let foreign_answers = barred
            .iter()
            .take(FOREIGN_PROBES)
            .any(|ip| self.probe.responds(SocketAddr::from((*ip, self.port))));
        self.dark_foreign_only
            .store(foreign_answers, Ordering::Relaxed);
        self.dark.store(true, Ordering::Relaxed);
        let mut state = self.lock();
        state.last_empty_sweep = Some(Instant::now());
        // The rotation this streak asked for has been attempted and there was
        // nowhere to go. Leaving the streak at its limit would re-enter the
        // sweep on every single failure that follows.
        state.failures = 0;
        state.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::dns::{StaticDnsServers, UpstreamDnsCandidate};
    use std::sync::atomic::AtomicUsize;

    /// A network with DNS only over IPv6: the pool must be able to pick a v6
    /// server at all, or such a network has no upstream.
    #[test]
    fn an_ipv6_only_server_list_yields_a_v6_upstream() {
        struct AnyProbe;
        impl UpstreamProbe for AnyProbe {
            fn responds(&self, _server: SocketAddr) -> bool {
                true
            }
        }
        let v6: Ipv6Addr = "2001:db8::53".parse().expect("v6");
        let pool = UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::new(Vec::new()).with_v6(vec![v6])),
            Arc::new(AnyProbe),
        );
        assert_eq!(pool.refresh(), Some(SocketAddr::from((v6, 53))));
    }

    /// "Nothing answers" is a state the resolver service acts on; it must be
    /// raised by an empty sweep and cleared by the first server that answers.
    #[test]
    fn an_empty_sweep_marks_the_pool_dark_until_a_server_answers() {
        let probe = ScriptedProbe::new(vec![]);
        let pool = pool(vec![ip(0)], Arc::clone(&probe));
        assert!(!pool.upstream_dark());
        pool.refresh();
        assert!(pool.upstream_dark(), "no candidate answered");
        probe.set_alive(vec![ip(0)]);
        pool.refresh();
        assert!(!pool.upstream_dark(), "a probe that answers clears it");
        probe.set_alive(vec![]);
        pool.refresh();
        assert!(pool.upstream_dark());
        pool.note_success();
        assert!(
            !pool.upstream_dark(),
            "a forward that succeeded clears it too"
        );
    }

    /// Probe answering only for an allow-list, counting calls.
    struct ScriptedProbe {
        alive: Mutex<Vec<Ipv4Addr>>,
        calls: AtomicUsize,
    }

    impl ScriptedProbe {
        fn new(alive: Vec<Ipv4Addr>) -> Arc<Self> {
            Arc::new(Self {
                alive: Mutex::new(alive),
                calls: AtomicUsize::new(0),
            })
        }

        fn set_alive(&self, alive: Vec<Ipv4Addr>) {
            *self.alive.lock().unwrap_or_else(|p| p.into_inner()) = alive;
        }
    }

    impl UpstreamProbe for ScriptedProbe {
        fn responds(&self, server: SocketAddr) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let SocketAddr::V4(v4) = server else {
                return false;
            };
            self.alive
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(v4.ip())
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, last, 1)
    }

    fn pool(candidates: Vec<Ipv4Addr>, probe: Arc<ScriptedProbe>) -> UpstreamDnsPool {
        UpstreamDnsPool::new(Arc::new(StaticDnsServers::new(candidates)), probe)
    }

    #[test]
    fn a_foreign_tunnels_resolver_never_becomes_the_upstream() {
        let corporate = UpstreamDnsCandidate {
            interface_index: Some(9),
            server: ip(1),
        };
        let home = UpstreamDnsCandidate {
            interface_index: Some(4),
            server: ip(2),
        };
        let probe = ScriptedProbe::new(vec![ip(1), ip(2)]);
        let pool = UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![corporate, home])),
            probe.clone(),
        );
        pool.set_excluded_interfaces(Arc::new(|| vec![9]));
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(2))));
        // The home resolver goes quiet: the corporate one answers but is not taken.
        probe.set_alive(vec![ip(1)]);
        assert_ne!(pool.reprobe().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));
    }

    #[test]
    fn an_active_server_that_turns_out_to_be_a_foreign_tunnels_is_dropped() {
        let corporate = UpstreamDnsCandidate {
            interface_index: Some(9),
            server: ip(1),
        };
        let probe = ScriptedProbe::new(vec![ip(1)]);
        let pool = UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![corporate])),
            probe,
        );
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));
        pool.set_excluded_interfaces(Arc::new(|| vec![9]));
        assert_eq!(pool.reprobe(), None);
        assert!(pool.upstream_dark());
    }

    /// The redirect comes back on `reprobe` answering a server, so that answer
    /// must mean a server answered just now. A VPN that lets no outside DNS
    /// through, or a laptop woken with no network: the server that answered
    /// before is silent, every sweep and every quick recheck after it says so,
    /// and the system DNS is never pointed back at a resolver with nowhere to
    /// ask.
    #[test]
    fn a_silent_server_is_never_reported_as_answering_again() {
        let probe = ScriptedProbe::new(vec![ip(1)]);
        let pool = pool(vec![ip(1), ip(2)], probe.clone());
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));
        probe.set_alive(Vec::new());
        assert_eq!(pool.reprobe(), None, "the sweep found nobody");
        assert_eq!(pool.reprobe(), None, "a recheck right after the sweep");
        assert!(pool.upstream_dark());
        probe.set_alive(vec![ip(2)]);
        // The quick recheck window is still open: no fresh answer yet either.
        assert_eq!(pool.reprobe(), None, "nothing probed, nothing answered");
    }

    fn corporate_and_home() -> (UpstreamDnsCandidate, UpstreamDnsCandidate) {
        (
            UpstreamDnsCandidate::new(Some(9), ip(1)),
            UpstreamDnsCandidate::new(Some(4), ip(2)),
        )
    }

    #[test]
    fn a_full_tunnel_that_blocks_other_dns_is_told_apart_from_an_offline_machine() {
        let (corporate, home) = corporate_and_home();
        let probe = ScriptedProbe::new(vec![ip(1)]);
        let pool = UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![corporate, home])),
            probe.clone(),
        );
        pool.set_excluded_interfaces(Arc::new(|| vec![9]));
        assert_eq!(pool.refresh(), None);
        assert_eq!(
            pool.upstream_dark_cause(),
            Some(UpstreamDarkCause::OnlyForeignAnswers)
        );
        probe.set_alive(vec![]);
        pool.refresh();
        assert_eq!(
            pool.upstream_dark_cause(),
            Some(UpstreamDarkCause::NothingAnswers),
            "the corporate resolver is gone too"
        );
        probe.set_alive(vec![ip(2)]);
        pool.refresh();
        assert_eq!(pool.upstream_dark_cause(), None);
    }

    /// What the pool serves once a re-selection it started has settled.
    fn current_within(pool: &Arc<UpstreamDnsPool>, limit: Duration) -> Option<IpAddr> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(server) = pool.current() {
                return Some(server.ip());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// No query reports a failure after the drop, so only the pool itself can
    /// start the re-selection; the query that saw the drop must not wait for it.
    #[test]
    fn an_active_server_on_a_link_that_turns_foreign_is_replaced_off_the_query_path() {
        let (corporate, home) = corporate_and_home();
        let probe = ParkingProbe::new();
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![corporate, home])),
            Arc::clone(&probe) as Arc<dyn UpstreamProbe>,
        ));
        // The corporate resolver was picked before the tunnel was published.
        {
            let mut state = pool.lock();
            state.candidates = vec![corporate.into(), home.into()];
            state.active = Some(IpAddr::V4(ip(1)));
            state.last_refresh = Some(Instant::now());
        }
        let published = Arc::new(Mutex::new(None::<Vec<u32>>));
        let read = Arc::clone(&published);
        pool.set_published_excluded(Arc::new(move || {
            read.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }));
        let read = Arc::clone(&published);
        pool.set_excluded_interfaces(Arc::new(move || {
            read.lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
                .unwrap_or_default()
        }));
        assert_eq!(pool.current().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));

        *published.lock().unwrap_or_else(|p| p.into_inner()) = Some(vec![9]);
        pool.lock().last_exclusion_check = None;
        let (sender, receiver) = std::sync::mpsc::channel();
        {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || {
                let _ = sender.send(pool.current());
            });
        }
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("the query is not held by the re-selection"),
            None,
            "the foreign resolver is not served"
        );

        probe.wait_until_inside();
        probe.release();
        assert_eq!(
            current_within(&pool, Duration::from_secs(5)),
            Some(IpAddr::V4(ip(2)))
        );
        assert_eq!(
            probe.calls.load(Ordering::Relaxed),
            1,
            "only the home resolver is probed"
        );
    }

    #[test]
    fn a_server_that_is_also_listed_on_a_link_of_ours_survives_the_exclusion() {
        let shared = [
            UpstreamDnsCandidate::new(Some(9), ip(1)),
            UpstreamDnsCandidate::new(Some(4), ip(1)),
        ];
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(shared.to_vec())),
            ScriptedProbe::new(vec![ip(1)]),
        ));
        pool.refresh();
        pool.set_published_excluded(Arc::new(|| Some(vec![9])));
        assert_eq!(pool.current().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));
    }

    /// The shape the Linux mechanisms report: the tunnel, read first, lists
    /// the home server too. That server stays a general upstream, probed once;
    /// the one only the tunnel lists never becomes one.
    #[test]
    fn a_server_a_link_of_ours_also_offers_survives_a_reselect_and_the_tunnels_own_does_not() {
        let listed = vec![
            UpstreamDnsCandidate::new(Some(9), ip(2)),
            UpstreamDnsCandidate::new(Some(9), ip(1)),
            UpstreamDnsCandidate::new(Some(4), ip(2)),
        ];
        let probe = ScriptedProbe::new(vec![ip(1), ip(2)]);
        let pool = UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(listed)),
            probe.clone(),
        );
        pool.set_excluded_interfaces(Arc::new(|| vec![9]));
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(2))));
        probe.set_alive(vec![ip(1)]);
        let before = probe.calls.load(Ordering::Relaxed);
        assert_ne!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));
        assert_eq!(
            probe.calls.load(Ordering::Relaxed) - before,
            2,
            "the shared server once, then the tunnel's for the dark cause"
        );
        assert_eq!(
            pool.upstream_dark_cause(),
            Some(UpstreamDarkCause::OnlyForeignAnswers)
        );
    }

    fn tunnel_carrying(cidr: &str) -> Arc<crate::foreign_tunnels::ForeignTunnelCell> {
        let cell = Arc::new(crate::foreign_tunnels::ForeignTunnelCell::new());
        cell.publish_tunnels(&[], &[], &[9]);
        cell.publish_networks(vec![
            nrr_domain::ipv4_network::Ipv4Network::parse(cidr).expect("network")
        ]);
        cell
    }

    /// A plain `resolv.conf` names no interface. Such a server inside a
    /// foreign tunnel's networks is the tunnel's; one outside them may be the
    /// user's only resolver.
    #[test]
    fn a_resolver_on_no_interface_is_barred_only_inside_the_tunnels_networks() {
        let (corporate, _) = corporate_and_home();
        let inside = UpstreamDnsCandidate::new(None, ip(3));
        let outside = UpstreamDnsCandidate::new(None, ip(5));
        let probe = ScriptedProbe::new(vec![ip(1), ip(3), ip(5)]);
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![
                corporate, inside, outside,
            ])),
            probe.clone(),
        ));
        pool.follow_foreign_tunnels(tunnel_carrying("192.168.3.0/24"));
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(5))));
        assert_eq!(pool.current().map(|s| s.ip()), Some(IpAddr::V4(ip(5))));

        // The outside one goes quiet: the tunnel's answer but are not taken.
        probe.set_alive(vec![ip(1), ip(3)]);
        assert_eq!(
            pool.refresh().map(|s| s.ip()),
            Some(IpAddr::V4(ip(5))),
            "the last good server is kept, not swapped for the tunnel's"
        );
        assert_eq!(
            pool.upstream_dark_cause(),
            Some(UpstreamDarkCause::OnlyForeignAnswers)
        );
    }

    /// The corporate tunnel routes a whole private `/16`, the home LAN is a
    /// `/24` inside it on our uplink: the home router is reached locally and
    /// stays usable; an address only the tunnel's range holds does not.
    #[test]
    fn a_resolver_on_no_interface_on_our_own_lan_inside_the_tunnels_range_stays_usable() {
        fn route(dest: [u8; 4], prefix: u8, ifindex: u32) -> nrr_platform_api::RouteEntry {
            nrr_platform_api::RouteEntry {
                destination: IpAddr::V4(Ipv4Addr::from(dest)),
                prefix_length: prefix,
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                interface_index: ifindex,
                metric: 10,
                is_ours: false,
                table: Default::default(),
            }
        }
        let (tunnel, eth0) = (9, 4);
        let routes = [
            route([192, 168, 0, 0], 16, tunnel),
            route([192, 168, 1, 0], 24, eth0),
            route([0, 0, 0, 0], 0, eth0),
        ];
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let corporate_only = Ipv4Addr::new(192, 168, 50, 1);
        let cell = Arc::new(crate::foreign_tunnels::ForeignTunnelCell::new());
        cell.publish_tunnels(&routes, &[], &[tunnel]);
        assert!(cell.carries(router), "the tunnel's range holds both");

        let probe = ScriptedProbe::new(vec![router, corporate_only]);
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![
                UpstreamDnsCandidate::new(None, corporate_only),
                UpstreamDnsCandidate::new(None, router),
            ])),
            probe.clone(),
        ));
        pool.follow_foreign_tunnels(cell);
        assert_eq!(
            pool.refresh().map(|s| s.ip()),
            Some(IpAddr::V4(router)),
            "the home router is usable, the tunnel's own address is passed over"
        );
        probe.set_alive(vec![corporate_only]);
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(router)));
        assert_eq!(
            pool.upstream_dark_cause(),
            Some(UpstreamDarkCause::OnlyForeignAnswers),
            "the address only the tunnel's range holds stays barred"
        );
    }

    /// The tunnel comes up under a server picked from `resolv.conf`: it is
    /// dropped and replaced without a failing query to set it off.
    #[test]
    fn an_active_resolver_on_no_interface_that_a_tunnel_takes_over_is_replaced() {
        let unbound = UpstreamDnsCandidate::new(None, ip(3));
        let home = UpstreamDnsCandidate::new(Some(4), ip(2));
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![unbound, home])),
            ScriptedProbe::new(vec![ip(2), ip(3)]),
        ));
        let cell = Arc::new(crate::foreign_tunnels::ForeignTunnelCell::new());
        pool.follow_foreign_tunnels(Arc::clone(&cell));
        assert_eq!(pool.refresh().map(|s| s.ip()), Some(IpAddr::V4(ip(3))));

        cell.publish_tunnels(&[], &[], &[9]);
        cell.publish_networks(vec![nrr_domain::ipv4_network::Ipv4Network::parse(
            "192.168.3.0/24",
        )
        .expect("network")]);
        pool.lock().last_exclusion_check = None;
        assert_eq!(pool.current(), None, "the tunnel's resolver is not served");
        assert_eq!(
            current_within(&pool, Duration::from_secs(5)),
            Some(IpAddr::V4(ip(2)))
        );
    }

    fn selection_after(pool: &Arc<UpstreamDnsPool>) -> Option<Option<IpAddr>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        if !pool.note_excluded_change_in_background(move |selected| {
            let _ = sender.send(selected.map(|s| s.ip()));
        }) {
            return None;
        }
        Some(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("selection"),
        )
    }

    /// The platform without a route coordinator: the routing pass publishes
    /// the tunnels into the cell, and the pool re-selects when, and only when,
    /// that set moves.
    #[test]
    fn the_exclusion_follows_the_published_tunnel_set() {
        let (corporate, home) = corporate_and_home();
        let probe = ScriptedProbe::new(vec![ip(1), ip(2)]);
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::with_interfaces(vec![corporate, home])),
            probe.clone(),
        ));
        let cell = Arc::new(crate::foreign_tunnels::ForeignTunnelCell::new());
        pool.follow_foreign_tunnels(Arc::clone(&cell));
        assert_eq!(
            pool.refresh().map(|s| s.ip()),
            Some(IpAddr::V4(ip(1))),
            "nothing published yet: nothing is foreign"
        );
        assert_eq!(selection_after(&pool), None, "no set moved");

        cell.publish_tunnels(&[], &[], &[9]);
        assert_eq!(selection_after(&pool), Some(Some(IpAddr::V4(ip(2)))));
        assert_eq!(selection_after(&pool), None, "the same set again");
        probe.set_alive(vec![ip(1)]);
        assert_ne!(pool.reprobe().map(|s| s.ip()), Some(IpAddr::V4(ip(1))));

        // The tunnel went away: its resolver is an ordinary candidate again.
        cell.publish_tunnels(&[], &[], &[]);
        assert_eq!(selection_after(&pool), Some(Some(IpAddr::V4(ip(1)))));
    }

    /// Before any wiring there is no set to follow and nothing to re-select.
    #[test]
    fn an_unwired_pool_never_re_selects_for_the_tunnel_set() {
        let pool = Arc::new(pool(vec![ip(1)], ScriptedProbe::new(vec![ip(1)])));
        assert_eq!(selection_after(&pool), None);
    }

    #[test]
    fn a_dead_preferred_server_is_skipped_for_one_that_answers() {
        // The boot bug: the disconnected adapter's DNS is enumerated first.
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(1), ip(0)], Arc::clone(&probe));
        assert_eq!(
            pool.refresh(),
            Some(SocketAddr::from((ip(0), 53))),
            "the server that answers must win over the one merely listed first"
        );
    }

    #[test]
    fn the_bound_links_resolver_wins_over_the_one_that_merely_owns_the_default_route() {
        // Both answer, and the default-route link is enumerated first — but the
        // policy sends traffic over the bound link, and only its resolver knows
        // that network's internal names.
        let probe = ScriptedProbe::new(vec![ip(0), ip(1)]);
        let servers = StaticDnsServers::with_interfaces(vec![
            UpstreamDnsCandidate::new(Some(11), ip(1)),
            UpstreamDnsCandidate::new(Some(17), ip(0)),
        ]);
        let pool = UpstreamDnsPool::new(Arc::new(servers), probe)
            .with_preferred_interface(Arc::new(|| Some(17)));
        assert_eq!(pool.refresh(), Some(SocketAddr::from((ip(0), 53))));
    }

    /// The question reads the machine: a burst of reselects asks it once, and
    /// a network change asks it again.
    #[test]
    fn the_preferred_interface_is_read_once_per_gap_and_again_after_a_network_change() {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        let pool = pool(vec![ip(1)], ScriptedProbe::new(vec![ip(1)])).with_preferred_interface(
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Some(17)
            }),
        );
        pool.refresh();
        pool.reprobe();
        pool.reprobe();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        pool.note_network_change();
        pool.reprobe();
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_preferred_interface_that_does_not_answer_is_still_passed_over() {
        let probe = ScriptedProbe::new(vec![ip(1)]);
        let servers = StaticDnsServers::with_interfaces(vec![
            UpstreamDnsCandidate::new(Some(11), ip(1)),
            UpstreamDnsCandidate::new(Some(17), ip(0)),
        ]);
        let pool = UpstreamDnsPool::new(Arc::new(servers), probe)
            .with_preferred_interface(Arc::new(|| Some(17)));
        assert_eq!(
            pool.refresh(),
            Some(SocketAddr::from((ip(1), 53))),
            "preference reorders, it never overrides reachability"
        );
    }

    #[test]
    fn no_candidate_answering_yields_no_upstream() {
        let probe = ScriptedProbe::new(vec![]);
        let pool = Arc::new(pool(vec![ip(1)], Arc::clone(&probe)));
        assert_eq!(pool.refresh(), None);
        assert_eq!(pool.current(), None, "never commit to an unprobed server");
    }

    #[test]
    fn rotation_needs_a_streak_and_then_moves_off_the_dead_server() {
        let probe = ScriptedProbe::new(vec![ip(0), ip(2)]);
        let pool = Arc::new(pool(vec![ip(0), ip(2)], Arc::clone(&probe)));
        assert_eq!(pool.refresh(), Some(SocketAddr::from((ip(0), 53))));

        probe.set_alive(vec![ip(2)]); // the active server goes away
        for _ in 1..FAILURES_BEFORE_ROTATE {
            assert_eq!(pool.note_failure(), None, "a short streak must not rotate");
        }
        assert_eq!(
            pool.note_failure(),
            Some(SocketAddr::from((ip(2), 53))),
            "the streak retires the active server and hands back the replacement"
        );
        assert_eq!(pool.current(), Some(SocketAddr::from((ip(2), 53))));
    }

    #[test]
    fn a_success_clears_the_streak() {
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(0)], Arc::clone(&probe));
        pool.refresh();
        pool.note_failure();
        pool.note_failure();
        pool.note_success();
        assert_eq!(
            pool.note_failure(),
            None,
            "failures must be consecutive to count"
        );
    }

    #[test]
    fn the_last_good_server_is_kept_when_everything_stops_answering() {
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = Arc::new(pool(vec![ip(0)], Arc::clone(&probe)));
        pool.refresh();
        probe.set_alive(vec![]);
        pool.refresh();
        assert_eq!(
            pool.current(),
            Some(SocketAddr::from((ip(0), 53))),
            "a brief outage must not blank the upstream mid-session"
        );
    }

    #[test]
    fn an_offline_machine_does_not_re_probe_on_every_failure() {
        // Each sweep costs the whole candidate list at PROBE_TIMEOUT. Without a
        // floor, every forward that fails pays for it again.
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(0), ip(1), ip(2)], Arc::clone(&probe));
        pool.refresh();
        probe.set_alive(vec![]);
        for _ in 0..FAILURES_BEFORE_ROTATE {
            pool.note_failure();
        }
        let after_first_sweep = probe.calls.load(Ordering::Relaxed);
        for _ in 0..30 {
            pool.note_failure();
        }
        assert_eq!(
            probe.calls.load(Ordering::Relaxed),
            after_first_sweep,
            "a sweep that found nothing must not be repeated within MIN_SWEEP_GAP"
        );
    }

    #[test]
    fn a_sweep_that_found_nothing_resets_the_failure_streak() {
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(0)], Arc::clone(&probe));
        pool.refresh();
        probe.set_alive(vec![]);
        for _ in 0..FAILURES_BEFORE_ROTATE {
            pool.note_failure();
        }
        assert_eq!(
            pool.lock().failures,
            0,
            "leaving the streak at its limit re-enters the sweep on every later failure"
        );
    }

    #[test]
    fn a_network_change_re_probes_even_right_after_an_empty_sweep() {
        // The floor must not outlive its reason: a new link is exactly when a
        // server that was unreachable a second ago becomes reachable.
        let probe = ScriptedProbe::new(vec![]);
        let pool = pool(vec![ip(0)], Arc::clone(&probe));
        pool.refresh();
        let after_empty = probe.calls.load(Ordering::Relaxed);
        probe.set_alive(vec![ip(0)]);
        assert_eq!(
            pool.refresh(),
            Some(SocketAddr::from((ip(0), 53))),
            "an explicit refresh must probe again"
        );
        assert!(probe.calls.load(Ordering::Relaxed) > after_empty);
    }

    /// Probe that parks inside the first call until it is released.
    struct ParkingProbe {
        entered: (Mutex<bool>, std::sync::Condvar),
        release: (Mutex<bool>, std::sync::Condvar),
        calls: AtomicUsize,
    }

    impl ParkingProbe {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: (Mutex::new(false), std::sync::Condvar::new()),
                release: (Mutex::new(false), std::sync::Condvar::new()),
                calls: AtomicUsize::new(0),
            })
        }

        fn wait_until_inside(&self) {
            let (lock, cv) = &self.entered;
            let mut inside = lock.lock().unwrap_or_else(|p| p.into_inner());
            while !*inside {
                inside = cv.wait(inside).unwrap_or_else(|p| p.into_inner());
            }
        }

        fn release(&self) {
            let (lock, cv) = &self.release;
            *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
            cv.notify_all();
        }
    }

    impl UpstreamProbe for ParkingProbe {
        fn responds(&self, _server: SocketAddr) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed);
            {
                let (lock, cv) = &self.entered;
                *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
                cv.notify_all();
            }
            let (lock, cv) = &self.release;
            let mut released = lock.lock().unwrap_or_else(|p| p.into_inner());
            while !*released {
                released = cv.wait(released).unwrap_or_else(|p| p.into_inner());
            }
            true
        }
    }

    #[test]
    fn a_second_caller_takes_the_current_choice_instead_of_sweeping_beside_the_first() {
        // Eight serve workers report failures independently; the probes are the
        // expensive part and the answer is shared.
        let probe = ParkingProbe::new();
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::new(vec![ip(0)])),
            Arc::clone(&probe) as Arc<dyn UpstreamProbe>,
        ));
        let sweeping = {
            let pool = Arc::clone(&pool);
            std::thread::spawn(move || pool.refresh())
        };
        probe.wait_until_inside();
        assert_eq!(
            pool.refresh(),
            None,
            "the second caller must return the current choice, not queue behind the sweep"
        );
        probe.release();
        assert_eq!(
            sweeping.join().expect("sweep thread"),
            Some(SocketAddr::from((ip(0), 53)))
        );
        assert_eq!(probe.calls.load(Ordering::Relaxed), 1, "one sweep, not two");
    }

    /// The caller is an enforcement pass: it must not wait out probes of dead
    /// servers, and the selection still has to reach it.
    #[test]
    fn a_background_reselection_does_not_hold_the_caller_and_reports_its_choice() {
        struct SlowProbe;
        impl UpstreamProbe for SlowProbe {
            fn responds(&self, _server: SocketAddr) -> bool {
                std::thread::sleep(Duration::from_millis(300));
                true
            }
        }
        let pool = Arc::new(UpstreamDnsPool::new(
            Arc::new(StaticDnsServers::new(vec![ip(7)])),
            Arc::new(SlowProbe),
        ));
        let (sender, receiver) = std::sync::mpsc::channel();
        let started = Instant::now();
        pool.note_network_change_in_background(move |selected| {
            let _ = sender.send(selected);
        });
        assert!(started.elapsed() < Duration::from_millis(200));
        // A second request while the first probes is absorbed by it.
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let second_ran = Arc::clone(&second_ran);
            pool.note_network_change_in_background(move |_| {
                second_ran.store(true, Ordering::SeqCst);
            });
        }
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("selection"),
            Some(SocketAddr::from((ip(7), 53)))
        );
        std::thread::sleep(Duration::from_millis(700));
        assert!(!second_ran.load(Ordering::SeqCst));
    }

    /// A live server that answers past 512 bytes is still live: on Windows a
    /// smaller buffer fails the receive and the probe would pass it over.
    #[test]
    fn a_server_answering_past_a_classic_datagram_still_responds() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake dns");
        let addr = server.local_addr().expect("fake dns addr");
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("cfg fake dns");
        let answered = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, src) = server.recv_from(&mut buf).expect("the probe asks");
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            reply.resize(4000, 0);
            server.send_to(&reply, src).expect("reply sent");
        });

        assert!(UdpUpstreamProbe::default().responds(addr));
        answered.join().expect("fake server finished");
    }

    /// After a network change no query goes out on a socket connected from the
    /// old network: it would wait out its timeout on an address that is gone.
    #[test]
    fn a_network_change_closes_the_idle_upstream_sockets() {
        let sockets: &'static crate::dns_upstream_sockets::UpstreamSockets =
            Box::leak(Box::new(crate::dns_upstream_sockets::UpstreamSockets::new()));
        let server: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let lease = sockets
            .checkout(
                crate::dns_upstream_sockets::UpstreamKey { bind: None, server },
                || std::net::UdpSocket::bind("127.0.0.1:0"),
            )
            .expect("open");
        lease.release();
        assert_eq!(sockets.idle_count(), 1);
        let pool = UpstreamDnsPool {
            sockets,
            ..UpstreamDnsPool::fixed(server)
        };
        let _ = pool.note_network_change();
        assert_eq!(
            sockets.idle_count(),
            0,
            "a socket from the old network was kept"
        );
    }
}
