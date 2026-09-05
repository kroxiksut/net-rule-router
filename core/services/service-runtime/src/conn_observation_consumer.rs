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
//! *enforcement* (acting on this) is out of scope here; the trace itself is a
//! Free diagnostic.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_domain::block_notice::BlockAttempt;
use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::conn_observe::egress::{resolve_egress, EgressInterface, EgressRole};
use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionProgress, ConnectionVerdict, TransportProtocol,
};
use nrr_platform_api::fake_ip::stale_flows::StaleFlowReset;
use nrr_platform_api::route_table::RouteTablePort;

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
    /// App-routing collateral — count of app→IP pairs WITHDRAWN this batch
    /// because the host route they produced was carrying a process the rule
    /// never named. `> 0` fires a recompute the same way a new pair does: the
    /// `/32` has to come off promptly, not at the next apply.
    pub app_ips_retracted: u32,
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
    /// teaches `app_observation_lookup` the address, after which the route
    /// follows within a tick. Bounded (one burst per
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
    api: Arc<dyn RouteTablePort>,
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
    /// Delete one remembered destination from the cross-session store. Wired
    /// alongside `app_observations`: withdrawing a pair only in memory would
    /// leave the persisted row to re-seed it at the next start, and the
    /// collateral would come back with it. `None` keeps the withdrawal
    /// in-memory (tests, degraded boot).
    app_destination_forget: Option<AppDestinationForgetFn>,
    /// Which applications a rule actually routes. Without it the collateral
    /// check cannot tell a pin from an ordinary observation — the store holds
    /// an entry for EVERY process, and withdrawing a "pin" from one no rule
    /// names is a withdrawal of nothing. `None` disables the check entirely,
    /// which is the safe direction: no false withdrawals.
    routed_apps: Option<RoutedAppsFn>,

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
    /// Classifier for the blanket IPv6 cut: `true` when the dropping filter is
    /// one of the filters that close the v6 family while the protection is on.
    /// Drives the notice wording only. `None` leaves such a drop reported as
    /// whatever its spec id says, which is how it came to blame the user's
    /// rules for a family the product closed on purpose.
    ipv6_cut_drop_check: Option<KillswitchDropCheckFn>,
    /// Classifier for the DoH/DoT lockdown band: `true` when the dropping
    /// filter is one of the resolver blocks. Drives the notice wording only.
    /// `None` leaves such a drop reported as a rule block, which is the one
    /// reading that sends the user editing rules over a switch.
    dns_lockdown_drop_check: Option<KillswitchDropCheckFn>,
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
    /// Destinations already torn down once (see [`Self::note_torn_down`]).
    torn_down_before: Mutex<HashSet<std::net::Ipv4Addr>>,
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

/// Delete one `(app, destination)` pair from the cross-session store, so a
/// withdrawal survives the restart that would otherwise re-seed it.
pub type AppDestinationForgetFn = Arc<dyn Fn(&str, std::net::Ipv4Addr) + Send + Sync>;

/// The application patterns the rule book currently routes over the additional
/// link. Read per batch: a rule edit must take effect without a restart.
pub type RoutedAppsFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Which application rules' pins this observation proves to be collateral.
///
/// A host route cannot be scoped to a process, so a destination learned for one
/// application moves every process that talks to it. Seeing a DIFFERENT process
/// egress the additional link on such an address is that collateral caught in
/// the act — no failure has to happen first, and waiting for one would mean
/// waiting on a timeout that may never arrive.
///
/// `routed` is the rule book's application patterns, and it is what makes the
/// answer mean anything. The observation store holds an entry for EVERY process
/// the observer ever saw, so an "owner" that no rule names never had a pin to
/// withdraw — a live run produced exactly that: `chrome.exe`, which no rule
/// mentions, and `claude.exe.old.<stamp>`, an updater's leftover. Both sides are
/// filtered: an intruder that is itself a routed application is no intruder
/// either, because the route serves both of them the same way.
///
/// Nothing is returned unless all of it holds: the flow left over the additional
/// link (on the main link no pin is in effect), the process is identified, it is
/// not this service (the relay dials an application's destinations over the
/// tunnel on its behalf, which is the mechanism working), the process is not
/// itself a routed application, and the owner is one.
fn collateral_pin_owners(
    store: &AppObservationStore,
    this_app: &str,
    own_process_key: &str,
    routed: &[String],
    role: EgressRole,
    ip: std::net::Ipv4Addr,
) -> Vec<String> {
    use crate::app_observation_lookup::{app_key, pattern_matches};
    // Both sides through the same key: the census holds keys, callers may hold
    // a rule spelling, and a raw compare would silently disagree.
    let this_app = app_key(this_app);
    if role != EgressRole::Secondary || this_app.is_empty() || this_app == app_key(own_process_key)
    {
        return Vec::new();
    }
    if routed.iter().any(|p| pattern_matches(p, &this_app)) {
        return Vec::new();
    }
    store
        .apps_for_ip(ip)
        .into_iter()
        .filter(|owner| owner != &this_app)
        .filter(|owner| routed.iter().any(|p| pattern_matches(p, owner)))
        .collect()
}

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

impl ConnectionObservationConsumer {}

// The per-connection predicates live in
// `conn_observation_consumer::connection_facts`.
// The impl is split by subject: wiring in `::builder`, companion sinks in
// `::companion`, the drop notice/log path in `::drop_reporter`, and the
// batch loop itself in `::consume`.
mod builder;
mod companion;
mod connection_facts;
mod consume;
mod drop_reporter;

use connection_facts::{
    block_reason_for, is_learnable_endpoint, process_basename_lower,
    process_is_p2p_fcrdns_suppressed, process_name_matches_vpn,
};

#[cfg(test)]
mod tests;
