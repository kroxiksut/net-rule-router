//! Connection-observation consumer (conn-trace).
//!
//! Where [`crate::dns_observation_consumer`] turns observed DNS *resolutions*
//! into routes, this consumer turns observed outbound *connections* (from a
//! [`ConnectionObservationSource`](nrr_platform_api::conn_observe::ConnectionObservationSource))
//! into a diagnostic egress trace: for each connection it derives **which
//! interface the flow actually left through** — by mapping the connection's
//! local (source) address to an interface index via the live adapter table —
//! and labels it `primary` (direct/provider), `secondary` (VPN), `other`, or
//! `unknown` against the active user's routing bindings.
//!
//! This is the answer to "does NRR see every app's egress, and did it go out
//! the secondary adapter or the provider?" — a question the DNS observer cannot answer (it is
//! blind to DoH and never sees the socket). The trace observes the real socket,
//! so it is complete regardless of how the name was resolved.
//!
//! It is **observation only** — it never installs routes or filters. Per-process
//! *enforcement* (acting on this) is the Pro experiment; the trace itself is a
//! Free diagnostic.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_domain::block_notice::{BlockAttempt, BlockReason};
use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::conn_observe::egress::{resolve_egress, EgressInterface, EgressRole};
use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionProgress, ConnectionVerdict, TransportProtocol,
};
use nrr_platform_api::fake_ip::stale_flows::StaleFlowReset;
use nrr_platform_api::windows_api::WindowsApiPort;

use crate::app_observation_lookup::AppObservationStore;
use crate::dns_observation_consumer::ActiveSidFn;
use crate::route_coordinator::SecondaryRouteCoordinator;

/// Outcome of consuming a batch of connection observations — counts by the
/// egress role each connection resolved to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnConsumeSummary {
    pub total: u32,
    /// Egressed the primary (direct/provider) interface.
    pub primary: u32,
    /// Egressed the secondary (VPN) interface.
    pub secondary: u32,
    /// Local loopback flow (127.0.0.0/8 or ::1) — never routable.
    pub loopback: u32,
    /// Egressed some other live interface (neither bound role).
    pub other: u32,
    /// Local source address mapped to no known interface.
    pub unknown: u32,
    /// App-routing via observation — count of NEW app→IP pairs
    /// recorded this batch. `> 0` means an `Application` rule may now have new
    /// destinations to route, so the conn-observe task fires a recompute.
    pub app_ips_added: u32,
    /// Count of VPN bootstrap endpoints learned
    /// this batch: distinct remote IPs of flows that OUR kill-switch dropped
    /// from a process whose name matches a VPN-client pattern. `> 0` means the
    /// fail-closed exemption set just grew, so the conn-observe task fires a
    /// recompute to arm the new server hole promptly (else the VPN's retry is
    /// dropped again until the 30 s safety tick).
    pub vpn_endpoints_learned: u32,
    /// Count of VPN CLIENT APPLICATIONS newly learned this batch: distinct
    /// process paths of role-verified kill-switch drops from VPN-named
    /// processes. `> 0` means the app-scoped block-all exemption
    /// set just grew, so the conn-observe task fires a recompute — the
    /// client's next connectivity check (rotating provider IPs) then escapes
    /// by app id instead of hanging until the next per-IP drop-and-learn.
    pub vpn_client_apps_learned: u32,
    /// Drops attributed to OUR filters this batch.
    pub blocked_nrr: u32,
    /// Drops attributed to a FOREIGN WFP filter (firewall /
    /// antivirus) this batch. Answers "blocked, but not by us" at a glance.
    pub blocked_foreign: u32,
    /// Role-verified kill-switch/fail-closed drops observed WHILE
    /// the secondary resolved as usable (routes up, not probe-dead). The
    /// block-all exists only for windows where the secondary is unusable, so
    /// this must stay ~0: a sustained nonzero value means the blocking scope
    /// is wider than the outage window — a scope bug, not user policy (the
    /// user's own Block rules fail role verification and are never counted
    /// here). Edge-of-window races (a drop from the tail of a block-all
    /// window drained after recovery — the drain runs every ~5 s) can
    /// contribute isolated counts.
    ///
    /// This total spans BOTH blocking scopes; read it together
    /// with [`Self::killswitch_drops_live_secondary_app_scope`], which carries
    /// the expected half.
    pub killswitch_drops_live_secondary: u32,
    /// The subset of [`Self::killswitch_drops_live_secondary`]
    /// produced by an APP-SCOPED block (`ALE_APP_ID` only, no destination —
    /// `killswitch_codegen::app_kill_switch_filters`). A secondary-routed
    /// application is pinned to the tunnel for EVERY destination, but the only
    /// thing that puts one of its destinations on the tunnel is a `/32` route
    /// derived from an address the observer has already seen. First contact
    /// with a new address therefore drops by design — and that drop is what
    /// teaches `app_observation_lookup` the address, after which the route and
    /// the per-destination pin follow within a tick. Bounded (one burst per
    /// new destination) and self-healing, so it is NOT evidence of a scope
    /// bug; only the destination-scoped remainder is.
    pub killswitch_drops_live_secondary_app_scope: u32,
}

impl ConnConsumeSummary {
    /// The half of [`Self::killswitch_drops_live_secondary`] that a correct
    /// blocking scope cannot produce: drops from a block that names a
    /// destination, while that destination's link is usable.
    pub fn killswitch_drops_live_secondary_dest_scope(&self) -> u32 {
        self.killswitch_drops_live_secondary
            .saturating_sub(self.killswitch_drops_live_secondary_app_scope)
    }
}

impl ConnConsumeSummary {
    pub fn made_progress(&self) -> bool {
        self.total > 0
    }
}

/// One sampled destination-scoped kill-switch drop, carried only far enough to
/// name a concrete victim in the scope-bug WARN.
#[derive(Debug, Clone)]
struct DropSample {
    /// WFP runtime filter id from the drop event — what to look up in the
    /// engine to see the offending filter's actual conditions.
    filter_id: u64,
    /// Our own spec id decoded from the filter key — what to match against
    /// `wfp_codegen::filter_id_for` to name the emitter.
    spec_id: u64,
    process: String,
    remote: SocketAddr,
}

impl Default for DropSample {
    fn default() -> Self {
        Self {
            filter_id: 0,
            spec_id: 0,
            process: String::new(),
            remote: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        }
    }
}

/// A single resolved connection-trace record (pure data; the egress interface
/// has been derived). This is the row a sink/GUI renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTraceRecord {
    pub process_path: Option<String>,
    pub user_sid: Option<String>,
    pub protocol: TransportProtocol,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub egress: EgressInterface,
    pub verdict: ConnectionVerdict,
    /// Drop attribution: `Some(true)` — NetRuleRouter
    /// dropped it; `Some(false)` — another WFP filter (firewall/antivirus);
    /// `None` — not a drop or owner unresolved.
    pub blocked_by_nrr: Option<bool>,
    /// The dropping filter's decoded NRR codegen spec id, when resolvable (see
    /// [`nrr_platform_api::conn_observe::ConnectionObservation::nrr_drop_spec_id`]).
    /// Lets a consumer check the filter's ROLE (e.g. kill-switch/fail-closed
    /// Block) via a registry before treating the drop as security-relevant
    /// evidence — `blocked_by_nrr` alone only proves WE own the filter, not
    /// which one.
    pub nrr_drop_spec_id: Option<u64>,
    pub observed_unix_ms: Option<u64>,
}

/// Bounded in-memory ring of the most-recent resolved
/// connection traces, backing the Diagnostics "connection trace" panel. Newest
/// records are at the back; `snapshot` returns them newest-first. Shared (Arc)
/// between the [`ConnectionObservationConsumer`] (writer) and the IPC handler
/// (reader). Holds RAW PII (process path, remote IP) — redaction is applied on
/// READ by the handler, mirroring the FQDN cache viewer.
pub struct ConnectionTraceRing {
    inner: Mutex<VecDeque<ConnectionTraceRecord>>,
    cap: usize,
}

impl ConnectionTraceRing {
    /// Ring holding at most `cap` records (clamped to `>= 1`).
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
            cap: cap.max(1),
        }
    }

    /// Append the newest record, evicting the oldest when full.
    pub fn push(&self, rec: ConnectionTraceRecord) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        while g.len() >= self.cap {
            g.pop_front();
        }
        g.push_back(rec);
    }

    /// Newest-first page: skip the newest `offset` records, take up to `limit`.
    /// Returns `(page, total_len)` — the caller derives the next cursor from
    /// `offset + page.len()` vs `total`.
    pub fn snapshot(&self, offset: usize, limit: usize) -> (Vec<ConnectionTraceRecord>, usize) {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let total = g.len();
        let page = g.iter().rev().skip(offset).take(limit).cloned().collect();
        (page, total)
    }

    /// Total records currently retained.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Flatten live adapter infos into the `(unicast address → ifindex)` table the
/// egress derivation consumes. Adapter enumeration is IPv4-only today, so the
/// table holds only v4 addresses — an IPv6 source therefore resolves to an
/// unknown egress (the v6-leak signal; NRR routes no v6 in Free).
pub fn build_unicast_table(infos: &[AdapterInfo]) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    for info in infos {
        for ip in &info.ipv4_addresses {
            out.push((IpAddr::V4(*ip), info.index));
        }
    }
    out
}

/// Pure: resolve one observation's egress interface against the live unicast
/// table and the active primary/secondary bindings. No I/O — unit-testable.
pub fn classify_connection(
    obs: &ConnectionObservation,
    unicast: &[(IpAddr, u32)],
    primary_ifindex: Option<u32>,
    secondary_ifindex: Option<u32>,
) -> ConnectionTraceRecord {
    let egress = resolve_egress(obs.local.ip(), unicast, primary_ifindex, secondary_ifindex);
    ConnectionTraceRecord {
        process_path: obs.process_path.clone(),
        user_sid: obs.user_sid.clone(),
        protocol: obs.protocol,
        local: obs.local,
        remote: obs.remote,
        egress,
        verdict: obs.verdict,
        blocked_by_nrr: obs.blocked_by_nrr,
        nrr_drop_spec_id: obs.nrr_drop_spec_id,
        observed_unix_ms: obs.observed_unix_ms,
    }
}

/// Egress-role wire slug (SSOT for both the NDJSON log and the conn-trace DTO).
pub fn role_str(role: EgressRole) -> &'static str {
    match role {
        EgressRole::Primary => "primary",
        EgressRole::Secondary => "secondary",
        EgressRole::Loopback => "loopback",
        EgressRole::Other => "other",
        EgressRole::Unknown => "unknown",
    }
}

/// Verdict wire slug.
pub fn verdict_str(v: ConnectionVerdict) -> &'static str {
    match v {
        ConnectionVerdict::Permit => "permit",
        ConnectionVerdict::Block => "block",
        ConnectionVerdict::Unknown => "unknown",
    }
}

/// Transport-protocol wire slug.
pub fn proto_str(p: TransportProtocol) -> &'static str {
    match p {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
        TransportProtocol::Other(_) => "other",
    }
}

/// Resolves the egress interface of each observed connection and logs the
/// per-connection trace. Holds only cheap handles; the live context (adapter
/// table + active bindings) is read fresh per batch, mirroring how
/// [`crate::dns_observation_consumer::DnsObservationConsumer`] reads the active
/// SID + rules per call.
pub struct ConnectionObservationConsumer {
    api: Arc<dyn WindowsApiPort>,
    coordinator: Arc<SecondaryRouteCoordinator>,
    active_sid: ActiveSidFn,
    /// Whether to emit the per-connection detail line (process + remote IP +
    /// egress) to the operational NDJSON. Off when the user enabled only the
    /// GUI-stream output (Slice E pushes to the panel instead). The aggregate
    /// per-tick summary is logged regardless — it carries counts, no PII.
    log_ndjson: bool,
    /// App-routing via observation — when wired, every observed
    /// `(process → remote IP)` is recorded here so the WFP codegen can route an
    /// `Application` rule's traffic via the secondary adapter. `None` keeps the
    /// observer purely diagnostic.
    app_observations: Option<Arc<AppObservationStore>>,
    /// When wired, every resolved trace is pushed into
    /// this ring so the Diagnostics panel can read recent connections over IPC.
    /// `None` keeps the observer log-only.
    trace_ring: Option<Arc<ConnectionTraceRing>>,
    /// When wired, each distinct remote IP of a
    /// flow that OUR kill-switch dropped from a VPN-client process is handed to
    /// this sink (which persists it as a bootstrap endpoint). `None` keeps the
    /// observer from learning.
    vpn_endpoint_learner: Option<VpnEndpointLearnFn>,
    /// Role-verification gate for the VPN-endpoint learner: given a dropping
    /// filter's decoded NRR spec id, returns whether that filter is a
    /// kill-switch/fail-closed Block (as opposed to, say, the user's own Block
    /// rule). The learner only fires when this is wired AND the observation
    /// carries a spec id AND the check returns `true` — closing the review
    /// finding that provider-only attribution (`blocked_by_nrr`) cannot tell a
    /// leak-guard drop from a user's own Block rule. `None` keeps the learner
    /// permanently inert even if [`Self::vpn_endpoint_learner`] is wired.
    killswitch_drop_check: Option<KillswitchDropCheckFn>,
    /// Scope classifier for a role-verified drop: `true` when the
    /// dropping filter is an APP-SCOPED block (no destination condition). Only
    /// splits the scope-bug counter; it grants nothing and gates nothing.
    /// `None` leaves every verified drop counted as destination-scoped, which
    /// is the conservative reading (it over-reports the actionable half).
    killswitch_app_scope_check: Option<KillswitchDropCheckFn>,
    /// Proactive VPN-client learning — when wired, the OBSERVED
    /// PROCESS PATH of every role-verified kill-switch drop from a VPN-named
    /// process is handed to this sink, which registers the client for an
    /// app-scoped block-all exemption (and persists it across sessions). The
    /// sink returns `true` when the client is NEW — counted in the summary so
    /// the observe task fires a recompute. Gated by the SAME role-verification
    /// as [`Self::vpn_endpoint_learner`]: without a wired
    /// [`Self::killswitch_drop_check`] it never fires. `None` keeps the
    /// observer from learning client apps — the per-IP endpoint learner alone.
    vpn_client_app_learner: Option<VpnClientAppLearnFn>,
    /// When wired (FCrDNS), each distinct remote
    /// IP of ANY flow OUR enforcement dropped (`blocked_by_nrr == Some(true)`,
    /// routable V4) is handed to this sink, which forward-confirms the name behind
    /// the IP and, if it matches a rule, caches it (see
    /// [`crate::fcrdns_learner`]). Unlike the VPN learner this grants NO exemption
    /// — it only feeds the rule-gated cache — so it is safe to enable and is NOT
    /// gated on the process name. `None` keeps the observer from reverse-learning.
    reverse_dns_learner: Option<ReverseDnsLearnFn>,
    /// `(process basename, remote ip, remote port)` triples whose
    /// BLOCK has already been detail-logged this session. The first drop of a
    /// triple logs at info with full attribution (remote, process, our/foreign
    /// filter, filter id) so a "site X does not open" report is answerable from
    /// the NDJSON alone; repeats drop to debug (a broken site retries forever,
    /// which would otherwise produce thousands of identical lines). Cleared
    /// wholesale if it ever exceeds [`DROP_LOG_KEY_CAP`] (bounded memory; the
    /// worst case is a rare re-log, not growth).
    drop_logged: Mutex<HashSet<(String, IpAddr, u16)>>,
    /// Companion discovery from real traffic. A connection that left over the
    /// PRIMARY link while the user is on a routed site is the half-broken page
    /// itself: the address the site needed, going the wrong way. Both halves
    /// must be wired — a name for the address, and somewhere to report it —
    /// or the observer stays purely diagnostic, as before.
    name_for_address: Option<NameForAddressFn>,
    companion_in_use: Option<CompanionInUseFn>,
    companion_primary_health: Option<CompanionPrimaryHealthFn>,
    /// Addresses already reported this session. A page reconnects to the same
    /// host constantly; the ledger needs the fact once.
    companion_reported: Mutex<HashSet<std::net::Ipv4Addr>>,
    /// Last time traffic left over the SECONDARY link, as a cheap proxy for
    /// "the user is on a routed site right now". Gates the reverse lookup
    /// below: without it every direct connection on an idle machine would
    /// queue a PTR query.
    last_secondary_at: Mutex<Option<Instant>>,
    /// Block-notice reporting. Resolves a destination address to the name
    /// the user recognizes — the same recent-resolution memory the
    /// companion feature reads, wired independently so block notices work
    /// even when companion discovery is not. `None` falls back to the raw
    /// address, which [`BlockAttempt::destination_label`] already handles.
    block_notice_name_for_address: Option<NameForAddressFn>,
    /// Sink for one qualifying `BlockAttempt`. `None` keeps the observer
    /// from reporting blocks at all — as before this feature existed.
    block_notice_sink: Option<BlockNoticeSinkFn>,
    /// Tears down connections a destination pin caught on the wrong link — a
    /// socket older than the pin keeps its interface until it dies. `None`
    /// leaves the drop standing and the application waiting.
    stale_flow_reset: Option<Arc<dyn StaleFlowReset>>,
    /// Is the fail-closed block-all posture armed right now? Under it every
    /// drop of ours has one cause — the additional route is unavailable —
    /// whatever the filter that caught the packet, and telling the user a rule
    /// blocked their site sends them editing rules over an outage.
    fail_closed_armed: Option<FailClosedArmedFn>,
}

/// How long after secondary traffic a direct connection still counts as
/// "beside a routed site". Roughly one page load.
const COMPANION_WINDOW: Duration = Duration::from_secs(30);

/// Cap on remembered reported companions (same bounded-memory reasoning as
/// [`DROP_LOG_KEY_CAP`]: on overflow the set is cleared, costing a repeat).
const COMPANION_REPORT_CAP: usize = 4096;

/// Cap on remembered drop-log triples (see `drop_logged`).
const DROP_LOG_KEY_CAP: usize = 8192;

/// Destinations one batch may sweep for stale flows; the rest ride the next
/// tick, seconds away.
const MAX_STALE_FLOW_RESETS_PER_BATCH: usize = 64;

/// Sink for a learned VPN bootstrap endpoint IP.
/// The production impl persists it via
/// `nrr_storage::vpn_bootstrap_endpoints::VpnBootstrapEndpointsRepository`; the
/// route coordinator's exemption loader reads it back, so a
/// learned server is exempted on the next recompute. `Send + Sync` so the
/// consumer can live behind an `Arc` shared with the supervised task.
pub type VpnEndpointLearnFn = Arc<dyn Fn(std::net::Ipv4Addr) + Send + Sync>;

/// Proactive VPN-client learning — sink for the observed process
/// path of a role-verified kill-switch drop from a VPN-named process. The
/// production impl converts the WFP app-id NT device path to a Win32 path,
/// verifies the file exists on disk, registers it in
/// [`crate::vpn_client_registry::LearnedVpnClientApps`] and persists it via
/// `nrr_storage::vpn_client_apps`. Returns `true` when the client is NEWLY
/// learned (drives the prompt-recompute signal). `Send + Sync` so the consumer
/// can live behind an `Arc` shared with the supervised task.
pub type VpnClientAppLearnFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Role-verification check for a dropping filter's decoded NRR spec id: `true`
/// when that filter belongs to the kill-switch/fail-closed BLOCK set (see
/// [`crate::killswitch_drop_registry::KillswitchBlockFilterRegistry`]). The
/// production impl is `Arc::clone`d over that registry's `contains`.
pub type KillswitchDropCheckFn = Arc<dyn Fn(u64) -> bool + Send + Sync>;

/// Reads the live fail-closed block-all posture (production: the same
/// `BlockAllPostureStatus` the GUI banner reads).
pub type FailClosedArmedFn = Arc<dyn Fn() -> bool + Send + Sync>;

/// Sink for an NRR-dropped destination IP the
/// FCrDNS learner should try to name. The production impl wraps
/// [`crate::fcrdns_learner::ReverseDnsLearner`] (PTR + forward-confirm + rule-gated
/// cache). `Send + Sync` so the consumer can live behind an `Arc`.
/// The `bool` is `allow_direct` — see
/// [`crate::fcrdns_learner::ReverseDnsLearner::learn_scoped`].
pub type ReverseDnsLearnFn = Arc<dyn Fn(std::net::Ipv4Addr, bool) + Send + Sync>;

/// Names a destination IP the service has seen resolved, or `None` when it
/// knows of none. Production reads the recent-resolution memory the resolver
/// already maintains — no lookup, no guessing.
pub type NameForAddressFn = Arc<dyn Fn(std::net::Ipv4Addr) -> Option<String> + Send + Sync>;

/// Reports a companion host the user's traffic actually reached while it was
/// leaving over the WRONG link — the half-broken page, observed directly.
pub type CompanionInUseFn = Arc<dyn Fn(&str) + Send + Sync>;

/// Reports how a host fared on the primary route: `true` when a connection to
/// it stalled, `false` when one closed in order. Separate from
/// [`CompanionInUseFn`] because it answers a different question — not "did the
/// traffic take the wrong link" but "does this host work over that link".
pub type CompanionPrimaryHealthFn = Arc<dyn Fn(&str, bool) + Send + Sync>;

/// Sink for one blocked-connection attempt worth reporting. The production
/// impl hands it to `block_notice_center::BlockNoticeCenter::record`, which
/// folds it into an episode and logs the notices that survive. This consumer
/// only decides WHICH drops qualify and what `BlockAttempt` to build.
/// The owning principal comes first: mutes are personal, so the sink must know
/// whose block this was. An empty SID means the owner could not be determined.
pub type BlockNoticeSinkFn = Arc<dyn Fn(&str, BlockAttempt) + Send + Sync>;

impl ConnectionObservationConsumer {
    pub fn new(
        api: Arc<dyn WindowsApiPort>,
        coordinator: Arc<SecondaryRouteCoordinator>,
        active_sid: ActiveSidFn,
        log_ndjson: bool,
    ) -> Self {
        Self {
            api,
            coordinator,
            active_sid,
            log_ndjson,
            app_observations: None,
            trace_ring: None,
            vpn_endpoint_learner: None,
            killswitch_drop_check: None,
            killswitch_app_scope_check: None,
            vpn_client_app_learner: None,
            reverse_dns_learner: None,
            drop_logged: Mutex::new(HashSet::new()),
            name_for_address: None,
            companion_in_use: None,
            companion_primary_health: None,
            companion_reported: Mutex::new(HashSet::new()),
            last_secondary_at: Mutex::new(None),
            block_notice_name_for_address: None,
            block_notice_sink: None,
            stale_flow_reset: None,
            fail_closed_armed: None,
        }
    }

    /// Wire the live fail-closed posture so a drop during an outage window is
    /// explained as an outage (see [`Self::fail_closed_armed`]).
    #[must_use]
    pub fn with_fail_closed_armed(mut self, armed: FailClosedArmedFn) -> Self {
        self.fail_closed_armed = Some(armed);
        self
    }

    /// Wire the teardown for flows a destination pin caught on the wrong link
    /// (see [`Self::stale_flow_reset`]).
    #[must_use]
    pub fn with_stale_flow_reset(mut self, reset: Arc<dyn StaleFlowReset>) -> Self {
        self.stale_flow_reset = Some(reset);
        self
    }

    /// Wire block-notice reporting: a name for the destination and the sink
    /// that turns a qualifying drop into a `BlockAttempt`. Mirrors
    /// [`Self::with_companion_in_use`]'s shape, but the pairing is not a hard
    /// requirement here — a sink with no name resolver still reports, just
    /// with the raw address standing in for the host.
    #[must_use]
    pub fn with_block_notice(
        mut self,
        name_for_address: NameForAddressFn,
        sink: BlockNoticeSinkFn,
    ) -> Self {
        self.block_notice_name_for_address = Some(name_for_address);
        self.block_notice_sink = Some(sink);
        self
    }

    /// Wire companion discovery from observed traffic: a name for a
    /// destination address, and a sink for the companions found leaving over
    /// the wrong link. Both or neither — a sink with no names would never fire,
    /// and names with no sink would be work for nothing.
    #[must_use]
    pub fn with_companion_in_use(
        mut self,
        name_for_address: NameForAddressFn,
        sink: CompanionInUseFn,
    ) -> Self {
        self.name_for_address = Some(name_for_address);
        self.companion_in_use = Some(sink);
        self
    }

    /// Wire the primary-route health signal. Needs the same name resolution as
    /// [`Self::with_companion_in_use`], so it is only useful alongside it.
    #[must_use]
    pub fn with_companion_primary_health(mut self, sink: CompanionPrimaryHealthFn) -> Self {
        self.companion_primary_health = Some(sink);
        self
    }

    /// One connection to a named destination stalled or finished cleanly on the
    /// primary link. Unlike [`Self::note_companion_in_use`] this is NOT deduped
    /// per address: the verdict is built from how often each outcome happened,
    /// so collapsing repeats would erase the evidence.
    fn note_companion_primary_health(&self, remote: IpAddr, stalled: bool) {
        let (Some(name_of), Some(sink)) = (
            self.name_for_address.as_ref(),
            self.companion_primary_health.as_ref(),
        ) else {
            return;
        };
        let IpAddr::V4(ip) = remote else {
            return;
        };
        if let Some(hostname) = name_of(ip) {
            sink(&hostname, stalled);
        }
    }

    /// One connection that left over the primary link: if we can name its
    /// destination, that name is a companion the user's traffic reached the
    /// wrong way.
    fn note_companion_in_use(&self, remote: IpAddr) {
        let (Some(name_of), Some(sink)) = (
            self.name_for_address.as_ref(),
            self.companion_in_use.as_ref(),
        ) else {
            return;
        };
        let IpAddr::V4(ip) = remote else {
            return;
        };
        {
            let mut seen = self
                .companion_reported
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if seen.len() >= COMPANION_REPORT_CAP {
                seen.clear();
            }
            if !seen.insert(ip) {
                return;
            }
        }
        let Some(hostname) = name_of(ip) else {
            // Nobody resolved this address through us — the browser answered
            // from its own cache or over DoH. The name is recoverable only by
            // reverse lookup, and only if a routed site is actually in play:
            // on an idle machine every direct connection would queue a query
            // for nothing.
            if self.beside_routed_traffic() {
                if let Some(learner) = self.reverse_dns_learner.as_ref() {
                    if is_learnable_endpoint(ip) {
                        // Not a drop at all — a flow that left over the primary
                        // beside a routed site. Nothing forbids the direct
                        // classification here.
                        learner(ip, true);
                    }
                }
            }
            return;
        };
        sink(&hostname);
    }

    /// Did traffic leave over the secondary link recently enough that a direct
    /// connection now is plausibly part of the same page?
    fn beside_routed_traffic(&self) -> bool {
        self.last_secondary_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|at| at.elapsed() <= COMPANION_WINDOW)
    }

    /// Turn one OUR-attributed Block into a `BlockAttempt` and hand it to the
    /// wired sink. A foreign filter (`blocked_by_nrr == Some(false)`) never
    /// reaches this method — see the `consume` call site — because blaming
    /// our policy for someone else's firewall would be actively wrong.
    /// `default_block_id` is the deterministic id of the "no rule covers this
    /// host" catch-all for the active SID (see `block_reason_for`).
    fn note_block_attempt(
        &self,
        rec: &ConnectionTraceRecord,
        killswitch_verified: bool,
        default_block_id: Option<u64>,
    ) {
        let Some(sink) = self.block_notice_sink.as_ref() else {
            return;
        };
        let reason = block_reason_for(
            rec.nrr_drop_spec_id,
            killswitch_verified,
            default_block_id,
            self.fail_closed_armed.as_ref().is_some_and(|armed| armed()),
        );
        let host = match rec.remote.ip() {
            IpAddr::V4(ip) => self
                .block_notice_name_for_address
                .as_ref()
                .and_then(|name_of| name_of(ip)),
            IpAddr::V6(_) => None,
        };
        let app = rec
            .process_path
            .as_deref()
            .map(process_basename_lower)
            .filter(|s| !s.is_empty());
        sink(
            rec.user_sid.as_deref().unwrap_or_default(),
            BlockAttempt {
                host,
                dest: rec.remote.ip().to_string(),
                app,
                reason,
            },
        );
    }

    /// Detail-log ONE blocked connection, once per
    /// `(process, remote ip, remote port)` triple per session (debug on
    /// repeats). Unconditional — NOT gated on `log_ndjson`: attributed drops
    /// are the single most valuable diagnostic line this observer produces,
    /// and the once-per-triple gate keeps the volume bounded.
    fn log_drop_once(&self, rec: &ConnectionTraceRecord, drop_filter_id: Option<u64>) {
        let process = rec.process_path.as_deref().unwrap_or("?");
        let key = (
            process_basename_lower(process),
            rec.remote.ip(),
            rec.remote.port(),
        );
        let first = {
            let mut g = self.drop_logged.lock().unwrap_or_else(|p| p.into_inner());
            if g.len() >= DROP_LOG_KEY_CAP {
                g.clear();
            }
            g.insert(key)
        };
        let owner = match rec.blocked_by_nrr {
            Some(true) => "nrr",
            Some(false) => "foreign",
            None => "unknown",
        };
        if first {
            tracing::info!(
                target: "nrr::conn-trace",
                remote_ip = %rec.remote.ip(),
                remote_port = rec.remote.port(),
                protocol = proto_str(rec.protocol),
                process = process,
                blocked_by = owner,
                drop_filter_id = drop_filter_id.unwrap_or(0),
                "observed BLOCKED connection (first per app/destination this session)",
            );
        } else {
            tracing::debug!(
                target: "nrr::conn-trace",
                remote_ip = %rec.remote.ip(),
                remote_port = rec.remote.port(),
                process = process,
                blocked_by = owner,
                "observed blocked connection (repeat)",
            );
        }
    }

    /// Wire the FCrDNS reverse-DNS learner so an
    /// NRR block drop of an as-yet-unlearned destination is named and (if it
    /// matches a rule) cached, closing the "browser cache / DoH hid the name"
    /// blind spot under block-all. Without it the observer does not reverse-learn.
    pub fn with_reverse_dns_learner(mut self, learner: ReverseDnsLearnFn) -> Self {
        self.reverse_dns_learner = Some(learner);
        self
    }

    /// Wire the VPN-endpoint learner so a
    /// kill-switch drop of a VPN-client flow teaches the exemption set the
    /// tunnel's server IP. Without it the observer never learns.
    pub fn with_vpn_endpoint_learner(mut self, learner: VpnEndpointLearnFn) -> Self {
        self.vpn_endpoint_learner = Some(learner);
        self
    }

    /// Wire the role-verification gate the VPN-endpoint learner requires: a
    /// drop only teaches an exemption when its filter's spec id passes this
    /// check (in production: membership in the live kill-switch/fail-closed
    /// Block id registry). Without it the learner never fires, regardless of
    /// [`Self::with_vpn_endpoint_learner`].
    pub fn with_killswitch_drop_check(mut self, check: KillswitchDropCheckFn) -> Self {
        self.killswitch_drop_check = Some(check);
        self
    }

    /// Wire the blocking-scope classifier (in production: the same registry's
    /// `is_app_scoped`) so the scope-bug counter can separate an app pin's
    /// expected first-contact drop from a destination pin that outran its
    /// route. Diagnostics only — it never changes what is blocked or learned.
    pub fn with_killswitch_app_scope_check(mut self, check: KillswitchDropCheckFn) -> Self {
        self.killswitch_app_scope_check = Some(check);
        self
    }

    /// Wire the client-app sink
    /// so a role-verified kill-switch drop registers the CLIENT PROCESS for an
    /// app-scoped exemption (in addition to the per-IP endpoint learner).
    /// Without it the observer never learns client apps. Requires
    /// [`Self::with_killswitch_drop_check`] to ever fire, exactly like the
    /// endpoint learner.
    pub fn with_vpn_client_app_learner(mut self, learner: VpnClientAppLearnFn) -> Self {
        self.vpn_client_app_learner = Some(learner);
        self
    }

    /// Wire the observed app→IP store so this consumer feeds app-routing.
    /// Without it the consumer stays diagnostic-only.
    pub fn with_app_observations(mut self, store: Arc<AppObservationStore>) -> Self {
        self.app_observations = Some(store);
        self
    }

    /// Wire the trace ring so resolved connections are
    /// retained for the Diagnostics panel. Without it the observer is log-only.
    pub fn with_trace_ring(mut self, ring: Arc<ConnectionTraceRing>) -> Self {
        self.trace_ring = Some(ring);
        self
    }

    /// Consume a batch: derive each connection's egress interface and emit a
    /// per-connection trace line on `nrr::conn-trace`. Returns counts by role.
    pub fn consume(&self, batch: &[ConnectionObservation], _now: SystemTime) -> ConnConsumeSummary {
        let mut summary = ConnConsumeSummary::default();
        if batch.is_empty() {
            return summary;
        }

        // Live context, read once per batch. Prefer the full unicast table
        // (IPv4 + IPv6 → ifindex) so v6 egress is labelled; fall back to the
        // IPv4-only adapter table if that query is unavailable.
        let mut unicast = self.api.unicast_ip_addresses().unwrap_or_default();
        if unicast.is_empty() {
            unicast = build_unicast_table(&self.api.get_adapter_infos().unwrap_or_default());
        }
        let active_sid_now = (self.active_sid)();
        let (primary_ifindex, secondary_ifindex) = match active_sid_now.as_deref() {
            Some(sid) => self.coordinator.resolve_egress_ifindexes(sid),
            None => (None, None),
        };
        // The "no rule covers this host" catch-all's id is deterministic
        // (same hash the codegen used to mint it) — computed once per batch,
        // only when a sink is actually wired, so an idle observer never pays
        // for it.
        let default_block_id: Option<u64> = self.block_notice_sink.as_ref().and_then(|_| {
            active_sid_now.as_deref().map(|sid| {
                crate::wfp_codegen::filter_id_for(sid, "default", "", "default", "block-all").raw
            })
        });

        // De-dup learned endpoints within the batch
        // so a burst of drops to one server calls the learner once.
        let mut learned_this_batch: std::collections::HashSet<std::net::Ipv4Addr> =
            std::collections::HashSet::new();
        // Separate per-batch dedup for the FCrDNS learner so it
        // never couples with the VPN learner's dedup above (different concerns,
        // same IP could matter to both).
        let mut reverse_learned_this_batch: std::collections::HashSet<std::net::Ipv4Addr> =
            std::collections::HashSet::new();
        // Per-batch dedup for the client-app learner: one call per
        // process path per batch, no matter how many endpoints its checks hit.
        let mut app_learned_this_batch: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // First destination-scoped offender of the batch, so the
        // scope-bug WARN can name the filter and one concrete victim instead
        // of only a count. One `Option` write per batch, no allocation beyond
        // the sampled process path.
        let mut dest_scope_sample: Option<DropSample> = None;
        // Destinations whose pin caught a socket on the wrong link this batch.
        // Deduped (a stalled flow is re-observed every tick) and capped.
        let mut stale_flow_victims: std::collections::BTreeSet<std::net::Ipv4Addr> =
            std::collections::BTreeSet::new();

        for obs in batch {
            let rec = classify_connection(obs, &unicast, primary_ifindex, secondary_ifindex);
            // A resend or an orderly close is evidence about a peer, not a
            // connection of its own: it must never become a trace row, an
            // NDJSON line, an app→IP fact or a drop statistic. Only the primary
            // link is asked about — the offer is "move this into the tunnel",
            // and how a host behaves once already inside it answers nothing.
            if obs.progress != ConnectionProgress::Attempt {
                if rec.egress.role == EgressRole::Primary {
                    self.note_companion_primary_health(
                        rec.remote.ip(),
                        obs.progress == ConnectionProgress::Retransmit,
                    );
                }
                continue;
            }
            summary.total += 1;
            // Role verification, shared by the VPN-endpoint learner and the
            // live-secondary drop counter below: the dropping filter's spec id
            // must be a member of the live kill-switch/fail-closed Block
            // registry — `blocked_by_nrr` alone cannot tell a leak-guard drop
            // from the user's own Block rule.
            let killswitch_verified = rec
                .nrr_drop_spec_id
                .zip(self.killswitch_drop_check.as_ref())
                .is_some_and(|(spec_id, check)| check(spec_id));
            // Was the dropping filter the APP-SCOPED block? Read once here
            // because the FCrDNS gate below needs it outside the live-secondary
            // scope-bug branch that also consults it.
            let killswitch_app_scoped = rec
                .nrr_drop_spec_id
                .zip(self.killswitch_app_scope_check.as_ref())
                .is_some_and(|(spec_id, check)| check(spec_id));
            // Surface every attributed drop in the NDJSON
            // (once per app/destination; see `log_drop_once`) and count it in
            // the tick summary so "N connections were being blocked right
            // then" is visible even with detail lines deduped away.
            if rec.verdict == ConnectionVerdict::Block {
                match rec.blocked_by_nrr {
                    Some(true) => summary.blocked_nrr += 1,
                    Some(false) => summary.blocked_foreign += 1,
                    None => {}
                }
                // Not an outage: the pinned link is up and both branches below
                // heal themselves, so this class is repaired, never announced —
                // a notice here would call a working route unavailable.
                let pinned_while_secondary_live =
                    killswitch_verified && secondary_ifindex.is_some();
                // Block-notice reporting: a foreign filter (`Some(false)`) is
                // never ours to explain, so only OUR drops reach the sink.
                if rec.blocked_by_nrr == Some(true) && !pinned_while_secondary_live {
                    self.note_block_attempt(&rec, killswitch_verified, default_block_id);
                }
                // Scope-bug detector: a kill-switch drop while
                // the secondary is resolved and USABLE should be impossible
                // (the block-all is only for outage windows). See the summary
                // field doc for the tolerated edge-of-window races.
                if rec.blocked_by_nrr == Some(true) && pinned_while_secondary_live {
                    summary.killswitch_drops_live_secondary += 1;
                    // Split by blocking scope. An app-scoped block
                    // covers destinations the routing layer has never seen, so
                    // its first-contact drop is expected and self-healing; only
                    // the destination-scoped remainder can be a scope bug, and
                    // that is the half worth naming in the WARN.
                    if killswitch_app_scoped {
                        summary.killswitch_drops_live_secondary_app_scope += 1;
                    } else {
                        // Routed through the tunnel, yet this socket is on the
                        // other link — a teardown candidate.
                        if let IpAddr::V4(rip) = rec.remote.ip() {
                            if stale_flow_victims.len() < MAX_STALE_FLOW_RESETS_PER_BATCH {
                                stale_flow_victims.insert(rip);
                            }
                        }
                        if dest_scope_sample.is_none() {
                            dest_scope_sample = Some(DropSample {
                                filter_id: obs.drop_filter_id.unwrap_or(0),
                                spec_id: rec.nrr_drop_spec_id.unwrap_or(0),
                                process: rec.process_path.clone().unwrap_or_default(),
                                remote: rec.remote,
                            });
                        }
                    }
                }
                self.log_drop_once(&rec, obs.drop_filter_id);
            }
            // Reactive self-learning: a flow that OUR kill-switch/fail-closed
            // Block dropped, from a process whose name matches a VPN-client
            // pattern, teaches the exemption set the tunnel's server IP, so the
            // client's own retry (VPN clients retry) is permitted and the
            // tunnel comes up — no user action, no first-connect deadlock.
            // Requires ALL of: our drop, a VPN-named process, a routable V4
            // remote, AND the dropping filter's spec id passing the wired
            // role-verification check — `blocked_by_nrr` alone cannot tell a
            // leak-guard drop from the user's own Block rule, so without a
            // verified spec id membership in the kill-switch registry the
            // learner never fires.
            // Shared gate for both VPN learners: OUR drop, whose filter's spec
            // id passes the wired role-verification check, from a VPN-named
            // process. Absence of a wired check keeps both learners inert.
            let role_verified_vpn_drop = rec.verdict == ConnectionVerdict::Block
                && rec.blocked_by_nrr == Some(true)
                && killswitch_verified
                && process_name_matches_vpn(rec.process_path.as_deref());
            if let Some(learner) = self.vpn_endpoint_learner.as_ref() {
                if role_verified_vpn_drop {
                    if let IpAddr::V4(rip) = rec.remote.ip() {
                        if is_learnable_endpoint(rip) && learned_this_batch.insert(rip) {
                            learner(rip);
                            summary.vpn_endpoints_learned += 1;
                            tracing::info!(
                                target: "nrr::vpn-learn",
                                server = %rip,
                                process = rec.process_path.as_deref().unwrap_or("?"),
                                "learned VPN bootstrap endpoint from a role-verified kill-switch drop — exempting so the tunnel can reconnect",
                            );
                        }
                    }
                }
            }
            // Proactive VPN-client learning: the same role-verified
            // drop also identifies the CLIENT PROCESS itself. Register it for an
            // app-scoped exemption so the next block-all arming permits the
            // whole process up front — its egress IS the tunnel's transport —
            // instead of chasing one rotated endpoint IP per drop (the
            // hidemy.name-over-rotating-Google-IPs failure mode). Not gated on
            // the remote IP being a learnable endpoint: the client's role is
            // proven by the drop regardless of which address the check targeted.
            if let Some(learner) = self.vpn_client_app_learner.as_ref() {
                if role_verified_vpn_drop {
                    if let Some(path) = rec.process_path.as_deref() {
                        if app_learned_this_batch.insert(path.to_ascii_lowercase()) && learner(path)
                        {
                            summary.vpn_client_apps_learned += 1;
                        }
                    }
                }
            }
            // FCrDNS reverse-learning: OUR block
            // of a routable V4 that no rule permitted (the browser-cache/DoH blind
            // spot under block-all) is handed to the learner, which names the IP
            // (PTR + forward-confirm) and caches it iff it matches a rule. NOT
            // gated on the process name and safe even if `blocked_by_nrr` over-
            // attributes (it grants no exemption — only the rule-gated cache; a
            // user's own Block rule still blocks). De-duped per batch.
            if let Some(learner) = self.reverse_dns_learner.as_ref() {
                if rec.verdict == ConnectionVerdict::Block
                    && rec.blocked_by_nrr == Some(true)
                    // Never learn from a P2P process's dropped peers:
                    // their ISP-pool PTRs forward-confirm and match broad zone
                    // rules, flooding the zone permit cap with junk.
                    && !process_is_p2p_fcrdns_suppressed(rec.process_path.as_deref())
                {
                    if let IpAddr::V4(rip) = rec.remote.ip() {
                        if is_learnable_endpoint(rip) && reverse_learned_this_batch.insert(rip) {
                            // An app-scoped kill-switch drop is the routed app
                            // waiting for its tunnel, not a name we failed to
                            // see. Naming it is still useful; calling it DIRECT
                            // would punch that app's destination out of the
                            // block-all.
                            learner(rip, !(killswitch_verified && killswitch_app_scoped));
                        }
                    }
                }
            }
            // App-routing via observation: record (app → remote IP)
            // so the codegen routes this app's destinations via the secondary on
            // the next apply. The store ignores unroutable IPs itself.
            if let Some(store) = self.app_observations.as_ref() {
                if let (Some(path), IpAddr::V4(rip)) =
                    (rec.process_path.as_deref(), rec.remote.ip())
                {
                    if store.record(path, rip) {
                        summary.app_ips_added += 1;
                    }
                }
            }
            // A flow leaving over the primary while the user is on a routed
            // site IS the half-broken page. The ledger decides whether it means
            // anything — it only counts inside an open anchor window — so the
            // observer stays a reporter of facts.
            if rec.egress.role == EgressRole::Secondary {
                *self
                    .last_secondary_at
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
            }
            if rec.egress.role == EgressRole::Primary {
                self.note_companion_in_use(rec.remote.ip());
            }
            match rec.egress.role {
                EgressRole::Primary => summary.primary += 1,
                EgressRole::Secondary => summary.secondary += 1,
                EgressRole::Loopback => summary.loopback += 1,
                EgressRole::Other => summary.other += 1,
                EgressRole::Unknown => summary.unknown += 1,
            }
            if self.log_ndjson {
                tracing::info!(
                    target: "nrr::conn-trace",
                    process = rec.process_path.as_deref().unwrap_or("?"),
                    sid = rec.user_sid.as_deref().unwrap_or("?"),
                    proto = proto_str(rec.protocol),
                    remote = %rec.remote,
                    local = %rec.local,
                    egress_ifindex = rec.egress.ifindex,
                    egress = role_str(rec.egress.role),
                    verdict = verdict_str(rec.verdict),
                    "observed outbound connection",
                );
            }
            // Retain for the Diagnostics panel (last use of `rec`).
            if let Some(ring) = self.trace_ring.as_ref() {
                ring.push(rec);
            }
        }
        // The scope-bug indicator must be loud: this count is
        // supposed to be zero (see the summary field doc), so any nonzero
        // batch gets one WARN (bounded by the ~5 s drain cadence, and only
        // while the condition actually occurs).
        //
        // WARN only on the DESTINATION-scoped half. An app pin
        // covers every destination its process talks to, including addresses
        // routing has never seen, so its first-contact drop is expected and
        // self-healing (the drop is the observation that creates the route);
        // it gets an INFO line naming the volume instead of a WARN that cries
        // wolf. The destination-scoped half keeps the WARN and names the
        // dropping filter, its spec id, the process and one victim address,
        // so a diagnosis does not depend on cross-referencing a bare count
        // against the per-drop lines.
        let dest_scope = summary.killswitch_drops_live_secondary_dest_scope();
        if dest_scope > 0 {
            let sample = dest_scope_sample.unwrap_or_default();
            tracing::warn!(
                target: "nrr::conn-trace",
                count = dest_scope,
                app_scoped = summary.killswitch_drops_live_secondary_app_scope,
                filter_id = sample.filter_id,
                spec_id = sample.spec_id,
                process = sample.process.as_str(),
                remote = %sample.remote,
                "a destination pin dropped connections while the secondary was resolved and USABLE — the usual cause is a socket older than the pin, kept on the wrong interface for life, which the teardown below repairs. Counts that stay nonzero after the teardown mean the blocking scope is wider than the outage, i.e. a scope bug. The sampled filter/spec/process/remote is one concrete victim of this batch",
            );
        }
        // The socket predates the pin and can never reach the tunnel; tearing it
        // down is what makes the application reconnect onto the route.
        if let Some(reset) = self.stale_flow_reset.as_ref() {
            let mut torn_down = 0usize;
            for ip in &stale_flow_victims {
                torn_down = torn_down.saturating_add(reset.reset_flows_to(*ip, 32).torn_down);
            }
            if torn_down > 0 {
                tracing::info!(
                    target: "nrr::conn-trace",
                    torn_down,
                    destinations = stale_flow_victims.len(),
                    "tore down connections a destination pin caught on the wrong link — the application reconnects over the additional route",
                );
            }
        }
        if summary.killswitch_drops_live_secondary_app_scope > 0 {
            tracing::info!(
                target: "nrr::conn-trace",
                count = summary.killswitch_drops_live_secondary_app_scope,
                "app-pinned processes hit the kill-switch on destinations that are not routed through the additional link yet — expected first contact: the drop is what teaches the destination, and the route plus its own pin follow on the next reconcile",
            );
        }
        summary
    }
}

/// Base file name of a process path, lower-cased — the process identity
/// shown to the user (in logs and, later, block notices). `process_path` is
/// whatever form the observer captured (NT device path or Win32 path); only
/// the last `\`- or `/`-separated component matters.
fn process_basename_lower(process_path: &str) -> String {
    process_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(process_path)
        .to_ascii_lowercase()
}

/// Which [`BlockReason`] an OUR-attributed drop maps to.
///
/// `killswitch_verified` already distinguishes the kill-switch/fail-closed
/// Block band via [`crate::killswitch_drop_registry`] — that band means the
/// route the destination is pinned to is down, i.e. [`BlockReason::RouteUnavailable`].
///
/// `default_block_id` is the deterministic id of the "no rule covers this
/// host" catch-all ([`crate::wfp_codegen::filter_id_for`] with role
/// `"default"`, computed fresh per batch from the active SID) — matching it
/// needs no new registry, only the same hash the codegen used to mint it, so
/// it maps cleanly to [`BlockReason::NotCoveredByRules`].
///
/// `fail_closed_armed` is the live block-all posture. The registry above only
/// recognizes the filters of the CURRENT compute, so a drop caught by a
/// neighbouring filter of the same outage (a fake-address block, a filter from
/// the compute before this one) falls through it — and calling that "a rule
/// blocked you" while the tunnel is down sends the user editing rules over an
/// outage. While the posture is armed there is exactly one cause worth naming.
///
/// Anything else attributed to us is an explicit rule Block action — the
/// only remaining source of an OUR drop in production codegen once the bands
/// above are ruled out — so it falls to [`BlockReason::BlockedByRule`].
/// That is also the safest default when `default_block_id` is unknown (no
/// active SID this batch): it never claims a route problem that may not
/// exist.
fn block_reason_for(
    spec_id: Option<u64>,
    killswitch_verified: bool,
    default_block_id: Option<u64>,
    fail_closed_armed: bool,
) -> BlockReason {
    if killswitch_verified {
        return BlockReason::RouteUnavailable;
    }
    if spec_id.is_some() && spec_id == default_block_id {
        return BlockReason::NotCoveredByRules;
    }
    if fail_closed_armed {
        return BlockReason::RouteUnavailable;
    }
    BlockReason::BlockedByRule
}

/// Does `process_path`'s file name match any
/// built-in VPN-client pattern? `process_path` is a WFP app-id (an NT device
/// path like `\device\harddiskvolume2\...\openvpn.exe`); we match the bare file
/// name (last `\`- or `/`-separated component) against
/// [`crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS`] using the same
/// case-insensitive globber the resolver uses. `None`/empty never matches.
fn process_name_matches_vpn(process_path: Option<&str>) -> bool {
    let Some(path) = process_path else {
        return false;
    };
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path).trim();
    if name.is_empty() {
        return false;
    }
    crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS
        .iter()
        .any(|glob| nrr_platform_api::app_path_resolver::glob_match(glob, name))
}

/// Does the drop's process belong to a peer-to-peer group
/// whose peers must be kept OUT of the FCrDNS rule-host learner? A P2P peer's
/// ISP hostname (`host.corbina.ru`) forward-confirms and matches a broad zone
/// rule (`.ru`), so learning it inflates the zone permit cap with thousands of
/// junk peers. The neutral [`nrr_platform_api::classify_app`]
/// dictionary + `suppresses_fcrdns_learning()` is the single source of truth for
/// which processes qualify (BitTorrent / P2P file-sharing / crypto nodes).
/// `None`/empty never suppresses.
fn process_is_p2p_fcrdns_suppressed(process_path: Option<&str>) -> bool {
    let Some(path) = process_path else {
        return false;
    };
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path).trim();
    nrr_platform_api::classify_app(name)
        .map(|kind| kind.suppresses_fcrdns_learning())
        .unwrap_or(false)
}

/// Is `ip` a sensible VPN server to exempt? Skips
/// addresses that can never be a real unicast tunnel server: loopback /
/// link-local (already exempt in codegen), the unspecified / broadcast
/// addresses, the `0.0.0.0/8` "this network" block, multicast `224.0.0.0/4`,
/// and CGNAT `100.64.0.0/10`. A private-range IP (10/8,
/// 172.16/12, 192.168/16) IS learnable — a corporate VPN server can sit there.
fn is_learnable_endpoint(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let is_this_network = a == 0; // 0.0.0.0/8
    let is_cgnat = a == 100 && (64..=127).contains(&b); // 100.64.0.0/10
                                                        // A fake-pool destination is our own TUN, not a real endpoint: a PTR
                                                        // lookup on it is meaningless and a "VPN server" learned there would
                                                        // exempt the pool from the kill-switch.
    let is_fake_pool =
        nrr_platform_api::fake_ip::FakeIpPoolConfig::is_default_pool_addr(std::net::IpAddr::V4(ip));
    !nrr_platform_api::is_exempt_from_blocking(ip)
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast() // 224.0.0.0/4
        && !is_this_network
        && !is_cgnat
        && !is_fake_pool
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::conn_observe::TransportProtocol;
    use std::net::{Ipv4Addr, SocketAddrV4};

    const ETHERNET: u32 = 16;
    const VPN: u32 = 20;

    fn v4(ip: Ipv4Addr) -> IpAddr {
        IpAddr::V4(ip)
    }

    fn obs(local: Ipv4Addr, remote: Ipv4Addr) -> ConnectionObservation {
        ConnectionObservation {
            pid: 0,
            process_path: Some(r"\device\harddiskvolume2\chrome.exe".to_string()),
            user_sid: None,
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::V4(SocketAddrV4::new(local, 50000)),
            remote: SocketAddr::V4(SocketAddrV4::new(remote, 443)),
            verdict: ConnectionVerdict::Permit,
            drop_filter_id: None,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            observed_unix_ms: None,
            progress: ConnectionProgress::Attempt,
        }
    }

    // ── Reactive VPN self-learning: consume()-level gate tests ──────────────

    /// `RoutePolicySource` that never resolves a policy — sufficient here
    /// because [`test_consumer`] wires an `active_sid` closure that always
    /// returns `None`, so `consume()` never reaches the coordinator at all.
    struct NoopPolicySource;
    impl crate::per_sid_orchestrator::RoutePolicySource for NoopPolicySource {
        fn load_for_sid(
            &self,
            _sid: &str,
        ) -> Option<crate::per_sid_orchestrator::PerSidPolicySnapshot> {
            None
        }
    }

    /// One observed connection matching every VPN-learn precondition except
    /// role-verification: a Block verdict attributed to us, from a process
    /// matching the built-in VPN-client glob, to a public routable V4 remote.
    /// `spec_id` is the caller-controlled variable under test.
    fn vpn_drop_obs(spec_id: Option<u64>) -> ConnectionObservation {
        ConnectionObservation {
            pid: 0,
            process_path: Some(r"C:\Program Files\OpenVPN\bin\openvpn.exe".to_string()),
            user_sid: None,
            protocol: TransportProtocol::Udp,
            local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
            remote: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 50), 1194)),
            verdict: ConnectionVerdict::Block,
            drop_filter_id: Some(80122),
            blocked_by_nrr: Some(true),
            nrr_drop_spec_id: spec_id,
            observed_unix_ms: None,
            progress: ConnectionProgress::Attempt,
        }
    }

    /// Build a consumer wired with a VPN-endpoint learner that records into
    /// the returned sink, and (when `check` is `Some`) the role-verification
    /// gate backed by that closure. `active_sid` always returns `None`, so
    /// `consume()` never needs a live route coordinator — the field is only
    /// present to satisfy the constructor.
    fn test_consumer(
        check: Option<KillswitchDropCheckFn>,
    ) -> (
        ConnectionObservationConsumer,
        Arc<Mutex<Vec<std::net::Ipv4Addr>>>,
    ) {
        let api: Arc<dyn nrr_platform_api::windows_api::WindowsApiPort> =
            Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
        let coordinator = Arc::new(SecondaryRouteCoordinator::new(
            Arc::clone(&api),
            Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
                as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
            Arc::new(NoopPolicySource) as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
                as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
            Arc::new(|| false),
        ));
        let active_sid: ActiveSidFn = Arc::new(|| None);
        let learned: Arc<Mutex<Vec<std::net::Ipv4Addr>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&learned);
        let mut consumer = ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
            .with_vpn_endpoint_learner(Arc::new(move |ip| {
                sink.lock().unwrap_or_else(|p| p.into_inner()).push(ip);
            }));
        if let Some(check) = check {
            consumer = consumer.with_killswitch_drop_check(check);
        }
        (consumer, learned)
    }

    #[test]
    fn vpn_learn_fires_when_spec_id_is_role_verified() {
        let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
        let (consumer, learned) = test_consumer(Some(check));
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.vpn_endpoints_learned, 1);
        assert_eq!(
            *learned.lock().unwrap_or_else(|p| p.into_inner()),
            vec![Ipv4Addr::new(203, 0, 113, 50)]
        );
    }

    #[test]
    fn vpn_learn_skips_when_spec_id_unknown_to_registry() {
        // Simulates a foreign drop or the user's own Block rule: a spec id
        // exists (so `blocked_by_nrr` alone would have taught it under the
        // pre-fix logic) but the role-verification check rejects it.
        let check: KillswitchDropCheckFn = Arc::new(|_id| false);
        let (consumer, learned) = test_consumer(Some(check));
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.vpn_endpoints_learned, 0);
        assert!(learned.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
    }

    #[test]
    fn vpn_learn_skips_when_spec_id_absent() {
        // The observation carries no decoded spec id at all (undecodable or
        // pre-dating the encoding) even though the check would accept
        // anything — absence of a spec id must never be treated as verified.
        let check: KillswitchDropCheckFn = Arc::new(|_id| true);
        let (consumer, learned) = test_consumer(Some(check));
        let summary = consumer.consume(&[vpn_drop_obs(None)], SystemTime::now());
        assert_eq!(summary.vpn_endpoints_learned, 0);
        assert!(learned.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
    }

    #[test]
    fn vpn_learn_skips_when_no_check_wired() {
        // A matching VPN process name + a spec id present is no longer
        // sufficient on its own: without a role-verification gate wired at
        // all, the learner must stay inert.
        let (consumer, learned) = test_consumer(None);
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.vpn_endpoints_learned, 0);
        assert!(learned.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
    }

    // ── Proactive VPN-client (app-scoped) learning ─────────────

    /// Wire the client-app learner on top of [`test_consumer`], recording
    /// every observed path into the returned sink. The sink reports "new"
    /// exactly once per distinct path (mirroring the production registry).
    fn with_app_learner(
        consumer: ConnectionObservationConsumer,
    ) -> (ConnectionObservationConsumer, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let consumer = consumer.with_vpn_client_app_learner(Arc::new(move |path: &str| {
            let mut g = sink.lock().unwrap_or_else(|p| p.into_inner());
            let new = !g.iter().any(|p| p.eq_ignore_ascii_case(path));
            g.push(path.to_string());
            new
        }));
        (consumer, seen)
    }

    #[test]
    fn vpn_client_app_learner_fires_on_role_verified_drop() {
        let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
        let (consumer, _) = test_consumer(Some(check));
        let (consumer, apps) = with_app_learner(consumer);
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.vpn_client_apps_learned, 1);
        assert_eq!(
            *apps.lock().unwrap_or_else(|p| p.into_inner()),
            vec![r"C:\Program Files\OpenVPN\bin\openvpn.exe".to_string()]
        );
    }

    #[test]
    fn vpn_client_app_learner_skips_unverified_drops() {
        // Same drop, but the spec id fails role verification (a user's own
        // Block rule / foreign filter): the client app must NOT be learned.
        let check: KillswitchDropCheckFn = Arc::new(|_id| false);
        let (consumer, _) = test_consumer(Some(check));
        let (consumer, apps) = with_app_learner(consumer);
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.vpn_client_apps_learned, 0);
        assert!(apps.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
    }

    #[test]
    fn vpn_client_app_learner_dedups_within_a_batch_across_rotated_ips() {
        // The exact field failure mode: one client process dropped against
        // several ROTATING remote IPs in one batch — the app sink is invoked
        // once and the summary counts one newly-learned client.
        let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
        let (consumer, _) = test_consumer(Some(check));
        let (consumer, apps) = with_app_learner(consumer);
        let mut second = vpn_drop_obs(Some(80122));
        second.remote = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 51), 443));
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122)), second], SystemTime::now());
        assert_eq!(summary.vpn_client_apps_learned, 1);
        assert_eq!(
            apps.lock().unwrap_or_else(|p| p.into_inner()).len(),
            1,
            "one sink call per process path per batch"
        );
    }

    // ── kill-switch drops while the secondary is USABLE ────────

    /// `RoutePolicySource` binding every SID's secondary to one fixed stable
    /// id — enough for the coordinator to resolve a live secondary against
    /// the mock adapter table.
    struct OneSecondaryPolicy {
        stable_id: String,
    }
    impl crate::per_sid_orchestrator::RoutePolicySource for OneSecondaryPolicy {
        fn load_for_sid(
            &self,
            _sid: &str,
        ) -> Option<crate::per_sid_orchestrator::PerSidPolicySnapshot> {
            use crate::per_sid_orchestrator::{PerSidBinding, PerSidPolicySnapshot};
            Some(PerSidPolicySnapshot {
                primary: None,
                secondary: Some(PerSidBinding {
                    stable_id: self.stable_id.clone(),
                    display_name: String::new(),
                    user_confirmed: true,
                    known_stable_ids: Vec::new(),
                }),
                mode: crate::per_sid_orchestrator::PerSidBehaviorMode::PreferPrimary,
                block_secondary_when_unavailable: false,
                kill_switch_fail_closed: true,
                kill_switch_protocols: 0x7F,
                kill_switch_block_all: false,
                kill_switch_enabled: true,
                allow_dns_over_primary: false,
                shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
                kill_switch_strict_shared_ips: true,
                mode_a_coverage_strategy:
                    nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
                link_provider_exe_paths: Vec::new(),
                doh_lockdown_enabled: false,
                doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
                doh_resolver_ips: Vec::new(),
                auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            })
        }
    }

    /// Consumer whose coordinator RESOLVES a live secondary (Up adapter with
    /// a gateway, ifindex [`VPN`]) for the active SID, with the
    /// role-verification check accepting spec id 80122.
    fn test_consumer_with_live_secondary() -> ConnectionObservationConsumer {
        let mock = nrr_platform_api::windows_api::MockWindowsApi::new();
        let vpn = AdapterInfo {
            index: VPN,
            adapter_name: "{vpn-live}".into(),
            description: "hidemy.name VPN 3.0 OpenVPN Adapter".into(),
            friendly_name: "hidemy.name VPN".into(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
            oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(10, 88, 1, 41)],
            gateways: vec![Ipv4Addr::new(10, 88, 0, 1)],
        };
        let stable_id = vpn.stable_id();
        mock.set_adapter_infos(vec![vpn]);
        let api: Arc<dyn nrr_platform_api::windows_api::WindowsApiPort> = Arc::new(mock);
        let coordinator = Arc::new(SecondaryRouteCoordinator::new(
            Arc::clone(&api),
            Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
                as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
            Arc::new(OneSecondaryPolicy { stable_id })
                as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
                as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
            Arc::new(|| false),
        ));
        let active_sid: ActiveSidFn = Arc::new(|| Some("S-1-5-21-TEST".to_string()));
        ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
            .with_killswitch_drop_check(Arc::new(|id| id == 80122))
    }

    #[test]
    fn killswitch_drop_with_live_secondary_is_counted() {
        // The scope-bug detector: a role-verified kill-switch drop while the
        // coordinator resolves a usable secondary must be counted — this
        // combination should be impossible when the blocking scope is right.
        let consumer = test_consumer_with_live_secondary();
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.killswitch_drops_live_secondary, 1);
    }

    #[test]
    fn user_block_rule_drop_is_not_counted_even_with_live_secondary() {
        // A spec id that fails role verification is the user's own Block rule
        // (or another non-kill-switch filter) — legitimate with a live
        // secondary, so it must not feed the scope-bug counter.
        let consumer = test_consumer_with_live_secondary();
        let summary = consumer.consume(&[vpn_drop_obs(Some(999))], SystemTime::now());
        assert_eq!(summary.killswitch_drops_live_secondary, 0);
        assert_eq!(summary.blocked_nrr, 1, "the drop itself is still counted");
    }

    #[test]
    fn app_scoped_killswitch_drop_is_split_out_of_the_scope_bug_count() {
        // An app pin covers every destination its process talks
        // to, including addresses routing has never seen, so its first-contact
        // drop is expected. It must land in the app-scope bucket and leave the
        // actionable destination-scoped remainder at zero.
        let consumer = test_consumer_with_live_secondary()
            .with_killswitch_app_scope_check(Arc::new(|id| id == 80122));
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.killswitch_drops_live_secondary, 1);
        assert_eq!(summary.killswitch_drops_live_secondary_app_scope, 1);
        assert_eq!(summary.killswitch_drops_live_secondary_dest_scope(), 0);
    }

    #[test]
    fn destination_scoped_killswitch_drop_stays_in_the_scope_bug_count() {
        // The same drop, from a filter the registry does NOT classify as
        // app-scoped, is the actionable kind: a destination pin fired while
        // the link that was supposed to carry that destination is usable.
        let consumer = test_consumer_with_live_secondary()
            .with_killswitch_app_scope_check(Arc::new(|_| false));
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.killswitch_drops_live_secondary, 1);
        assert_eq!(summary.killswitch_drops_live_secondary_app_scope, 0);
        assert_eq!(summary.killswitch_drops_live_secondary_dest_scope(), 1);
    }

    #[test]
    fn without_a_scope_classifier_every_drop_reads_as_destination_scoped() {
        // Conservative default: an unwired classifier must over-report the
        // actionable half rather than silently swallow it.
        let consumer = test_consumer_with_live_secondary();
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.killswitch_drops_live_secondary_app_scope, 0);
        assert_eq!(summary.killswitch_drops_live_secondary_dest_scope(), 1);
    }

    #[test]
    fn destination_scoped_drop_with_live_secondary_tears_the_stale_flow_down() {
        // One /32 sweep per victim address, however often it is re-observed.
        let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
        let consumer = test_consumer_with_live_secondary()
            .with_killswitch_app_scope_check(Arc::new(|_| false))
            .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

        // The same stalled flow observed twice in one batch sweeps once.
        consumer.consume(
            &[vpn_drop_obs(Some(80122)), vpn_drop_obs(Some(80122))],
            SystemTime::now(),
        );

        assert_eq!(reset.calls(), vec![(Ipv4Addr::new(203, 0, 113, 50), 32)]);
    }

    #[test]
    fn app_scoped_drop_with_live_secondary_is_not_torn_down() {
        // First contact on an address routing has never seen — no older socket
        // to free, so nothing is swept.
        let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
        let consumer = test_consumer_with_live_secondary()
            .with_killswitch_app_scope_check(Arc::new(|id| id == 80122))
            .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

        consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());

        assert!(reset.calls().is_empty());
    }

    #[test]
    fn a_drop_with_an_unresolved_secondary_is_never_torn_down() {
        // The outage case: nowhere better for those sockets to go.
        let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
        let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
        let (consumer, _) = test_consumer(Some(check));
        let consumer =
            consumer.with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

        consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());

        assert!(reset.calls().is_empty());
    }

    #[test]
    fn killswitch_drop_with_unresolved_secondary_is_not_counted() {
        // No active SID → no resolved secondary → the drop is the block-all
        // doing exactly its job during an outage window.
        let check: KillswitchDropCheckFn = Arc::new(|id| id == 80122);
        let (consumer, _) = test_consumer(Some(check));
        let summary = consumer.consume(&[vpn_drop_obs(Some(80122))], SystemTime::now());
        assert_eq!(summary.killswitch_drops_live_secondary, 0);
    }

    // ── reactive VPN self-learning helpers ─────────

    #[test]
    fn vpn_name_match_accepts_vpn_clients_rejects_others() {
        // NT device paths (what a WFP app-id decodes to) — match on the basename.
        assert!(process_name_matches_vpn(Some(
            r"\device\harddiskvolume2\program files\openvpn\bin\openvpn.exe"
        )));
        assert!(process_name_matches_vpn(Some(
            r"\device\harddiskvolume3\hidemy.name\hidemy.name.exe"
        )));
        assert!(process_name_matches_vpn(Some(
            r"C:\Program Files\WireGuard\wireguard.exe"
        ))); // DOS path + forward/back mix
             // Non-VPN processes never match.
        assert!(!process_name_matches_vpn(Some(
            r"\device\harddiskvolume2\chrome.exe"
        )));
        assert!(!process_name_matches_vpn(Some(r"\device\...\svchost.exe")));
        // Absent / empty never matches.
        assert!(!process_name_matches_vpn(None));
        assert!(!process_name_matches_vpn(Some("")));
        assert!(!process_name_matches_vpn(Some(r"C:\dir\")));
    }

    #[test]
    fn learnable_endpoint_filters_non_routable_keeps_public_and_private() {
        // Public and private (corp-VPN) servers are learnable.
        assert!(is_learnable_endpoint(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(is_learnable_endpoint(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_learnable_endpoint(Ipv4Addr::new(192, 168, 1, 1)));
        // Loopback / link-local / unspecified / broadcast are not.
        assert!(!is_learnable_endpoint(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_learnable_endpoint(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_learnable_endpoint(Ipv4Addr::UNSPECIFIED));
        assert!(!is_learnable_endpoint(Ipv4Addr::BROADCAST));
        // L2 review-fix — 0.0.0.0/8, multicast 224/4, CGNAT 100.64/10 rejected.
        assert!(!is_learnable_endpoint(Ipv4Addr::new(0, 1, 2, 3)));
        assert!(!is_learnable_endpoint(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_learnable_endpoint(Ipv4Addr::new(239, 255, 255, 250)));
        assert!(!is_learnable_endpoint(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_learnable_endpoint(Ipv4Addr::new(100, 127, 255, 254)));
        // 100.128/9 is NOT CGNAT — public, still learnable.
        assert!(is_learnable_endpoint(Ipv4Addr::new(100, 128, 0, 1)));
        // The fake-IP pool terminates at our own TUN — never a learnable
        // endpoint, and just outside it the rule does not over-reach.
        assert!(!is_learnable_endpoint(Ipv4Addr::new(198, 18, 0, 35)));
        assert!(!is_learnable_endpoint(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(is_learnable_endpoint(Ipv4Addr::new(198, 20, 0, 1)));
    }

    #[test]
    fn build_unicast_table_flattens_adapter_addresses() {
        let infos = vec![AdapterInfo {
            index: ETHERNET,
            adapter_name: "{eth}".into(),
            description: "Ethernet".into(),
            friendly_name: "Ethernet".into(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
            oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
            ipv4_addresses: vec![
                Ipv4Addr::new(192, 168, 0, 50),
                Ipv4Addr::new(192, 168, 0, 51),
            ],
            gateways: vec![Ipv4Addr::new(192, 168, 0, 1)],
        }];
        let table = build_unicast_table(&infos);
        assert_eq!(table.len(), 2);
        assert!(table.contains(&(v4(Ipv4Addr::new(192, 168, 0, 50)), ETHERNET)));
    }

    #[test]
    fn classify_labels_vpn_source_as_secondary() {
        let unicast = vec![(v4(Ipv4Addr::new(10, 8, 0, 6)), VPN)];
        let rec = classify_connection(
            &obs(Ipv4Addr::new(10, 8, 0, 6), Ipv4Addr::new(188, 40, 167, 82)),
            &unicast,
            Some(ETHERNET),
            Some(VPN),
        );
        assert_eq!(rec.egress.role, EgressRole::Secondary);
        assert_eq!(rec.egress.ifindex, VPN);
        assert_eq!(rec.remote.ip(), IpAddr::V4(Ipv4Addr::new(188, 40, 167, 82)));
    }

    #[test]
    fn classify_labels_lan_source_as_primary() {
        let unicast = vec![(v4(Ipv4Addr::new(192, 168, 0, 50)), ETHERNET)];
        let rec = classify_connection(
            &obs(
                Ipv4Addr::new(192, 168, 0, 50),
                Ipv4Addr::new(93, 184, 216, 34),
            ),
            &unicast,
            Some(ETHERNET),
            Some(VPN),
        );
        assert_eq!(rec.egress.role, EgressRole::Primary);
    }

    #[test]
    fn trace_ring_caps_and_snapshots_newest_first() {
        let ring = ConnectionTraceRing::new(2);
        let unicast = vec![(v4(Ipv4Addr::new(192, 168, 0, 50)), ETHERNET)];
        let mk = |r: u8| {
            classify_connection(
                &obs(Ipv4Addr::new(192, 168, 0, 50), Ipv4Addr::new(10, 0, 0, r)),
                &unicast,
                Some(ETHERNET),
                Some(VPN),
            )
        };
        ring.push(mk(1));
        ring.push(mk(2));
        ring.push(mk(3)); // evicts #1 (cap 2)
        assert_eq!(ring.len(), 2);

        let (page, total) = ring.snapshot(0, 10);
        assert_eq!(total, 2);
        assert_eq!(page.len(), 2);
        // Newest-first: #3 then #2.
        assert_eq!(page[0].remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
        assert_eq!(page[1].remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

        // Cursor: skip the newest, take one.
        let (p2, _) = ring.snapshot(1, 1);
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn p2p_processes_suppress_fcrdns_learning_others_do_not() {
        // A torrent client's dropped peers must be skipped;
        // a browser's drop (the legit dzen.ru FCrDNS case) must not.
        assert!(process_is_p2p_fcrdns_suppressed(Some(
            r"\device\harddiskvolume5\users\krox\appdata\roaming\bittorrent web\btweb.exe"
        )));
        assert!(process_is_p2p_fcrdns_suppressed(Some(
            r"C:\Program Files\qBittorrent\qbittorrent.exe"
        )));
        assert!(process_is_p2p_fcrdns_suppressed(Some("bitcoind.exe")));
        // Non-P2P processes keep learning (the dzen.ru recovery path).
        assert!(!process_is_p2p_fcrdns_suppressed(Some("chrome.exe")));
        assert!(!process_is_p2p_fcrdns_suppressed(Some("VBoxSVC.exe")));
        assert!(!process_is_p2p_fcrdns_suppressed(None));
        assert!(!process_is_p2p_fcrdns_suppressed(Some("")));
    }

    // ── block-notice reporting ─────────────────────────────

    #[test]
    fn block_reason_prefers_killswitch_then_default_block_then_falls_back_to_rule() {
        // Role-verified kill-switch/fail-closed drop → the route is down.
        assert_eq!(
            block_reason_for(Some(1), true, Some(99), false),
            BlockReason::RouteUnavailable
        );
        // Not kill-switch, but matches the deterministic default-block-all id
        // → nothing routed this destination.
        assert_eq!(
            block_reason_for(Some(99), false, Some(99), false),
            BlockReason::NotCoveredByRules
        );
        // Neither → the only remaining production source is an explicit rule.
        assert_eq!(
            block_reason_for(Some(5), false, Some(99), false),
            BlockReason::BlockedByRule
        );
        // No active SID this batch (default id unknown) → same cautious default.
        assert_eq!(
            block_reason_for(Some(5), false, None, false),
            BlockReason::BlockedByRule
        );
    }

    #[test]
    fn an_unrecognised_drop_during_a_fail_closed_window_reads_as_the_outage() {
        // The exact 0811 case: fail-closed armed, the packet caught by a filter
        // outside the current kill-switch registry (a fake-address block).
        // Calling that "a rule blocked you" sends the user editing rules.
        assert_eq!(
            block_reason_for(Some(5), false, Some(99), true),
            BlockReason::RouteUnavailable
        );
        // "No rule covers this host" is still the more specific answer and keeps
        // precedence over the posture.
        assert_eq!(
            block_reason_for(Some(99), false, Some(99), true),
            BlockReason::NotCoveredByRules
        );
    }

    /// One observed connection blocked by `blocked_by_nrr`/`spec_id`, from a
    /// fixed process to a fixed destination — the variables under test.
    fn block_obs(blocked_by_nrr: Option<bool>, spec_id: Option<u64>) -> ConnectionObservation {
        ConnectionObservation {
            pid: 0,
            process_path: Some(r"C:\Program Files\Telegram\Telegram.exe".to_string()),
            user_sid: None,
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51000)),
            remote: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443)),
            verdict: ConnectionVerdict::Block,
            drop_filter_id: Some(1),
            blocked_by_nrr,
            nrr_drop_spec_id: spec_id,
            observed_unix_ms: None,
            progress: ConnectionProgress::Attempt,
        }
    }

    /// Consumer wired with `with_block_notice`, whose sink runs every
    /// `BlockAttempt` through a REAL `BlockNoticeLedger` (fixed `now_ms = 0`
    /// so retries land in the same episode) — the same folding the
    /// production `BlockNoticeCenter` does. `notices` collects only the
    /// attempts that survived folding, so the test can assert on episode
    /// behaviour, not just on what the consumer decided to report.
    fn block_notice_consumer(
        killswitch_check: Option<KillswitchDropCheckFn>,
    ) -> (
        ConnectionObservationConsumer,
        Arc<Mutex<Vec<nrr_domain::block_notice::BlockNotice>>>,
    ) {
        let api: Arc<dyn nrr_platform_api::windows_api::WindowsApiPort> =
            Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
        let coordinator = Arc::new(SecondaryRouteCoordinator::new(
            Arc::clone(&api),
            Arc::new(crate::per_sid_orchestrator::NoopRulesProvider)
                as Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
            Arc::new(NoopPolicySource) as Arc<dyn crate::per_sid_orchestrator::RoutePolicySource>,
            Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new())
                as Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
            Arc::new(|| false),
        ));
        let active_sid: ActiveSidFn = Arc::new(|| None);
        let ledger = Arc::new(Mutex::new(
            nrr_domain::block_notice::BlockNoticeLedger::default(),
        ));
        let notices: Arc<Mutex<Vec<nrr_domain::block_notice::BlockNotice>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink_ledger = Arc::clone(&ledger);
        let sink_notices = Arc::clone(&notices);
        let mut consumer = ConnectionObservationConsumer::new(api, coordinator, active_sid, false)
            .with_block_notice(
                Arc::new(|_ip| None),
                Arc::new(move |_sid: &str, attempt: BlockAttempt| {
                    let mut g = sink_ledger.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(notice) = g.record(0, &attempt) {
                        sink_notices
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(notice);
                    }
                }),
            );
        if let Some(check) = killswitch_check {
            consumer = consumer.with_killswitch_drop_check(check);
        }
        (consumer, notices)
    }

    #[test]
    fn a_foreign_drop_never_produces_a_block_notice() {
        // `Some(false)` is a firewall/antivirus filter, not ours — reporting
        // it would blame our policy for someone else's block.
        let (consumer, notices) = block_notice_consumer(None);
        let summary = consumer.consume(&[block_obs(Some(false), Some(42))], SystemTime::now());
        assert_eq!(summary.blocked_foreign, 1);
        assert!(notices.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
    }

    #[test]
    fn an_unattributed_drop_never_produces_a_block_notice() {
        // `None` means ownership could not be resolved — not evidence enough
        // to tell the user "we blocked this".
        let (consumer, notices) = block_notice_consumer(None);
        consumer.consume(&[block_obs(None, Some(42))], SystemTime::now());
        assert!(notices.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
    }

    #[test]
    fn a_role_verified_drop_opens_one_episode_and_its_retry_stays_silent() {
        let check: KillswitchDropCheckFn = Arc::new(|id| id == 777);
        let (consumer, notices) = block_notice_consumer(Some(check));

        consumer.consume(&[block_obs(Some(true), Some(777))], SystemTime::now());
        // A retry of the SAME attempt inside the episode gap.
        consumer.consume(&[block_obs(Some(true), Some(777))], SystemTime::now());

        let got = notices.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(got.len(), 1, "one notice per episode, not per drop");
        assert_eq!(got[0].reason, BlockReason::RouteUnavailable);
        assert_eq!(got[0].destination, "203.0.113.9");
        assert_eq!(got[0].app, "telegram.exe");
    }

    #[test]
    fn a_drop_whose_spec_id_fails_role_verification_still_reports_as_blocked_by_rule() {
        // The spec id exists but is not in the kill-switch registry (the
        // user's own Block rule): still ours, still worth a notice, just a
        // different reason.
        let check: KillswitchDropCheckFn = Arc::new(|_id| false);
        let (consumer, notices) = block_notice_consumer(Some(check));
        consumer.consume(&[block_obs(Some(true), Some(555))], SystemTime::now());
        let got = notices.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].reason, BlockReason::BlockedByRule);
    }
}
