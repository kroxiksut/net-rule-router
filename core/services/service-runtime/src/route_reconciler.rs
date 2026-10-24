//! secondary-route reconciler.
//!
//! Brings the system route table into line with a desired owned route set
//! (produced by [`crate::route_codegen`]). It tracks the routes it has
//! applied and, on each [`SecondaryRouteReconciler::reconcile`], diffs the
//! new desired set against them: it **deletes** owned routes that are no
//! longer desired and **adds** newly-desired ones, in a single
//! [`RoutingTransaction`] that rolls back on partial failure.
//!
//! ## One table, several users
//!
//! The Windows route table is **machine-wide** — a route entry has no user
//! dimension. So the desired set is the union of every signed-in user's
//! routes, merged by the route coordinator: a destination two users send
//! through different links goes the way of the one served longer. Per-SID
//! WFP filters (the kill-switch) stay per user. This reconciler sees only
//! the merged set.
//!
//! ## Ownership tracking
//!
//! The OS never reports `is_ours` (the FFI stamps `false`), so the
//! reconciler is the source of truth for which routes it owns, tracked
//! in-memory. Routes a crash orphaned are adopted by their signature
//! ([`crate::route_codegen::is_owned_route`]) before the first reconcile, so
//! that reconcile takes back the ones no longer wanted.
//!
//! Memory is not the table: a route deleted from outside, or taken by the OS
//! with a link that dropped and came back, is still remembered. So a pass that
//! keeps routes checks them against the live table first and puts back what
//! is gone, touching nothing that is still there.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nrr_platform_api::route_signature::signed_routes;
pub use nrr_platform_api::route_signature::{
    sweep_owned_routes, sweep_owned_routes_with, RouteSweepError,
};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::routing::RoutingTransaction;
use nrr_platform_api::{PlatformError, RouteEntry, RoutingAction};
use nrr_shared::ip_block::IpBlock;

use crate::route_codegen::{OVERLAY_HIGH, OVERLAY_LOW};

/// Identity of a route for diffing — everything but `metric`/`is_ours`.
/// Two routes with the same key are "the same route"; a metric-only change
/// is not a meaningful diff for our `/32` host routes. The table is part of
/// it: two users' tables may hold the same route.
type RouteKey = (IpAddr, u8, IpAddr, u32, nrr_platform_api::RouteTableRef);

fn route_key(r: &RouteEntry) -> RouteKey {
    (
        r.destination,
        r.prefix_length,
        r.next_hop,
        r.interface_index,
        r.table.clone(),
    )
}

/// Whether a remembered route is still in the live table: the identity the OS
/// reports back as asked. The next hop is left out, as in
/// [`SecondaryRouteReconciler::owns`]: a hop reported in another spelling would
/// read as gone, and its re-add would conflict and lose the claim on it.
type PresenceKey = (IpAddr, u8, u32, nrr_platform_api::RouteTableRef);

fn presence_key(r: &RouteEntry) -> PresenceKey {
    (
        r.destination,
        r.prefix_length,
        r.interface_index,
        r.table.clone(),
    )
}

/// A reading of the live table a caller already holds, taken after
/// [`SecondaryRouteReconciler::write_count`] returned `writes`.
#[derive(Clone, Copy, Debug)]
pub struct TableReading<'a> {
    pub writes: u64,
    pub rows: &'a [RouteEntry],
}

/// The routes we own, and which of them went in ahead of a pass.
#[derive(Default)]
struct OwnedRoutes {
    routes: Vec<RouteEntry>,
    /// A route installed ahead of the pass that will plan it, with the write
    /// count its install brought the table to. A pass planned before that
    /// write never wanted it and must not take it out.
    ahead: Vec<(RouteKey, u64)>,
    /// Routes another program keeps removing, keyed by route.
    contested: std::collections::HashMap<RouteKey, Contest>,
}

/// Put-backs of one route within [`CONTEST_WINDOW`] after which the program
/// removing it is left alone: a client that enforces its own routes would
/// otherwise trade deletes with us every pass, and the route's traffic would
/// flap between links.
const CONTEST_LIMIT: usize = 3;
const CONTEST_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a contested route stays out before it is tried again.
const CONTEST_BACKOFF: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Debug, Default)]
struct Contest {
    put_back: Vec<std::time::Instant>,
    held_until: Option<std::time::Instant>,
}

impl OwnedRoutes {
    fn installed_after(&self, key: &RouteKey, planned_at: u64) -> bool {
        self.ahead
            .iter()
            .any(|(k, at)| k == key && *at > planned_at)
    }

    /// A route of ours went missing; `true` when that makes it contested.
    fn note_vanished(&mut self, key: RouteKey, now: std::time::Instant) -> bool {
        let contest = self.contested.entry(key).or_default();
        contest
            .put_back
            .retain(|at| now.saturating_duration_since(*at) < CONTEST_WINDOW);
        contest.put_back.push(now);
        if contest.put_back.len() < CONTEST_LIMIT {
            return false;
        }
        contest.put_back.clear();
        contest.held_until = Some(now + CONTEST_BACKOFF);
        true
    }

    fn held_out(&self, key: &RouteKey, now: std::time::Instant) -> bool {
        self.contested
            .get(key)
            .and_then(|c| c.held_until)
            .is_some_and(|until| now < until)
    }

    /// Only what the plan still wants is remembered, and a hold that ran out
    /// is tried again.
    fn settle_contests(&mut self, desired: &HashSet<RouteKey>, now: std::time::Instant) {
        self.contested.retain(|key, _| desired.contains(key));
        for contest in self.contested.values_mut() {
            if contest.held_until.is_some_and(|until| now >= until) {
                contest.held_until = None;
            }
        }
    }
}

/// What a route currently in the system table represents, from the
/// route-ownership coordinator's perspective.
///
/// NetRuleRouter takes ownership of the IPv4 route table over a
/// redirect-gateway VPN: it may strip the VPN client's self-installed
/// split-default overlay (so mode A's non-rule traffic falls back to the
/// primary default, and mode B installs *our* overlay instead), but it must
/// NEVER remove the bootstrap host route to the VPN server — doing so kills
/// the tunnel. This classification is the safety gate for that stripping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOwnership {
    /// We installed it (`is_ours`). Reconciled against the desired set; never
    /// treated as foreign.
    Ours,
    /// A split-default half (`0.0.0.0/1` / `128.0.0.0/1`) the VPN client
    /// installed on the secondary interface (`redirect-gateway`). Strippable
    /// when NetRuleRouter owns the table.
    VpnRedirectOverlay,
    /// The bootstrap host route to the VPN server itself — a `/32` reached via
    /// the *primary* gateway, so the encrypted tunnel packets egress the real
    /// link rather than the tunnel. Removing it tears down the VPN. NEVER strip.
    BootstrapHostRoute,
    /// Anything else (the OS default `0.0.0.0/0`, on-link routes, unrelated
    /// entries). Not ours and not the VPN's redirect/bootstrap — leave it.
    Untracked,
}

/// Classify one route for ownership-based stripping.
///
/// `secondary_ifindex` is the VPN interface; `primary_gateway` is the real
/// (Ethernet) next-hop, used to recognise — and protect — the bootstrap host
/// route. Pure; no I/O. Only [`RouteOwnership::VpnRedirectOverlay`] is safe to
/// strip; every other variant must be left in place.
pub fn classify_route_ownership(
    route: &RouteEntry,
    secondary_ifindex: u32,
    primary_gateway: Option<IpAddr>,
) -> RouteOwnership {
    if route.is_ours {
        return RouteOwnership::Ours;
    }
    // Bootstrap host route FIRST so it can never be mistaken for anything
    // strippable: a /32 reached via the primary gateway. Checked regardless of
    // interface — defence in depth, even if a client installs it unusually.
    if route.is_host_route() {
        if let Some(pg) = primary_gateway {
            if route.next_hop == pg {
                return RouteOwnership::BootstrapHostRoute;
            }
        }
    }
    // The VPN's redirect-gateway split halves on the secondary interface.
    if route.interface_index == secondary_ifindex && is_split_default_half(route) {
        return RouteOwnership::VpnRedirectOverlay;
    }
    RouteOwnership::Untracked
}

fn is_split_default_half(route: &RouteEntry) -> bool {
    (route.destination == OVERLAY_LOW.0 && route.prefix_length == OVERLAY_LOW.1)
        || (route.destination == OVERLAY_HIGH.0 && route.prefix_length == OVERLAY_HIGH.1)
}

/// the VPN **server** IPs the
/// kill-switch must never block, so the tunnel can (re)establish.
///
/// These are the destinations of the bootstrap host-routes: a `/32` reached
/// via the primary gateway (see [`classify_route_ownership`]). The VPN client
/// installs one per server endpoint so its own encrypted traffic reaches the
/// server over the real interface, *outside* the tunnel. Deduplicated, order
/// preserved. Empty when there is no primary gateway or no such route — the
/// caller then refuses to arm the catch-all (fail-open), since blocking the
/// server would deadlock reconnection.
pub fn bootstrap_server_ips(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
    primary_gateway: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    bootstrap_servers(routes, secondary_ifindex, primary_gateway.map(IpAddr::V4))
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// The IPv6 half of [`bootstrap_server_ips`]: the tunnel's v6 endpoints, read
/// off the `/128` bootstrap routes taken via the primary's v6 gateway.
///
/// The route table is the honest source. The model has no v6 endpoint field,
/// and learning one from observed drops would grow the exemption set out of
/// whatever the tunnel happened to try — the table states what the client
/// itself installed.
pub fn bootstrap_server_ips_v6(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
    primary_gateway: Option<Ipv6Addr>,
) -> Vec<Ipv6Addr> {
    bootstrap_servers(routes, secondary_ifindex, primary_gateway.map(IpAddr::V6))
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(d) => Some(d),
            IpAddr::V4(_) => None,
        })
        .collect()
}

fn bootstrap_servers(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
    primary_gateway: Option<IpAddr>,
) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    routes
        .iter()
        .filter(|r| {
            matches!(
                classify_route_ownership(r, secondary_ifindex, primary_gateway),
                RouteOwnership::BootstrapHostRoute
            )
        })
        .map(|r| r.destination)
        .filter(|ip| seen.insert(*ip))
        .collect()
}

/// The primary link's IPv6 default gateway, from its own `::/0` route.
///
/// [`AdapterInfo::gateways`][nrr_platform_api::adapters::AdapterInfo::gateways]
/// enumerates IPv4 only, so the v6 next hop has exactly one source on both
/// platforms: the route the OS itself installed.
#[must_use]
pub fn primary_gateway_v6(routes: &[RouteEntry], primary_ifindex: u32) -> Option<Ipv6Addr> {
    routes
        .iter()
        .filter(|r| r.interface_index == primary_ifindex && r.prefix_length == 0)
        .find_map(|r| match (r.destination, r.next_hop) {
            (IpAddr::V6(_), IpAddr::V6(gw)) if !gw.is_unspecified() => Some(gw),
            _ => None,
        })
}

/// The interface's directly-connected IPv4 subnets AS THE OS REPORTS THEM, as
/// `(network, prefix_len)`.
///
/// Derived from the on-link connected routes on `primary_ifindex` (next-hop
/// `0.0.0.0`, prefix `1..=31` — skips the default route and host routes).
/// Deduplicated, order preserved.
///
/// Not an exemption list: the network chose these numbers, and a hostile one
/// chooses a `/1`. Anything a blanket block lets through reads
/// [`exemptible_local_subnets`] instead; this raw form serves the readers that
/// describe a link (a tunnel's interior, a settings row).
///
/// Windows carries an on-link `224.0.0.0/4` route on every interface, which
/// looks exactly like a connected subnet here. Left in, it named a "local
/// network" the user could see and untick in Settings, and it exempted all
/// multicast from the kill-switch instead of the control block the codegen
/// exempts deliberately. Only a unicast destination can be a subnet.
pub fn primary_local_subnets(routes: &[RouteEntry], primary_ifindex: u32) -> Vec<(Ipv4Addr, u8)> {
    let mut seen = HashSet::new();
    routes
        .iter()
        .filter(|r| {
            r.interface_index == primary_ifindex
                && r.next_hop.is_unspecified()
                && (1..=31).contains(&r.prefix_length)
                && matches!(r.destination, IpAddr::V4(d) if is_unicast_destination(d, r.prefix_length))
        })
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some((d, r.prefix_length)),
            IpAddr::V6(_) => None,
        })
        .filter(|s| seen.insert(*s))
        .collect()
}

/// The IPv6 half of [`primary_local_subnets`]: the prefixes the primary link is
/// directly attached to over v6.
///
/// The on-link form is the same — no next hop — but the scope test differs:
/// `fe80::/64` and the multicast scopes are already exempt everywhere, so
/// listing them here would only restate that. A `/128` is the interface's own
/// address, not a segment.
pub fn primary_local_subnets_v6(
    routes: &[RouteEntry],
    primary_ifindex: u32,
) -> Vec<(Ipv6Addr, u8)> {
    let mut seen = HashSet::new();
    routes
        .iter()
        .filter(|r| r.interface_index == primary_ifindex && r.next_hop.is_unspecified())
        .filter(|r| (1..=127).contains(&r.prefix_length))
        .filter_map(|r| match r.destination {
            IpAddr::V6(d) if is_unicast_destination_v6(d, r.prefix_length) => {
                Some((d, r.prefix_length))
            }
            _ => None,
        })
        .filter(|s| seen.insert(*s))
        .collect()
}

/// What a blanket block lets through to one interface's attached segments,
/// and which reported segments it refused as too wide.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExemptibleLocalSubnets {
    pub v4: Vec<(Ipv4Addr, u8)>,
    pub v6: Vec<(Ipv6Addr, u8)>,
    /// Segments the OS reported wider than a segment can be; nothing of them
    /// is exempt, and the user is told.
    pub too_wide: Vec<IpBlock>,
    /// Public IPv6 prefixes the link is attached to — a home network's own
    /// addresses. Only the user can vouch for one, so none is exempt here.
    pub public_v6: Vec<(Ipv6Addr, u8)>,
}

/// [`primary_local_subnets`] and its v6 twin passed through the one decision
/// of what part of a reported segment a blanket block may exempt
/// (`nrr_domain::ip_network_policy::local_segment_exemption`). Both OS
/// backends read exemptions through here.
pub fn exemptible_local_subnets(routes: &[RouteEntry], ifindex: u32) -> ExemptibleLocalSubnets {
    use nrr_domain::ip_network_policy::{local_segment_exemption, LocalSegmentExemption};
    let mut out = ExemptibleLocalSubnets::default();
    let reported = primary_local_subnets(routes, ifindex)
        .into_iter()
        .filter_map(|(net, prefix)| IpBlock::new(IpAddr::V4(net), prefix))
        .chain(
            primary_local_subnets_v6(routes, ifindex)
                .into_iter()
                .filter_map(|(net, prefix)| IpBlock::new(IpAddr::V6(net), prefix)),
        );
    for segment in reported {
        match local_segment_exemption(segment) {
            LocalSegmentExemption::Exempt(blocks) => {
                for block in blocks {
                    match block.network() {
                        IpAddr::V4(net) if !out.v4.contains(&(net, block.prefix_len())) => {
                            out.v4.push((net, block.prefix_len()));
                        }
                        IpAddr::V6(net) if !out.v6.contains(&(net, block.prefix_len())) => {
                            out.v6.push((net, block.prefix_len()));
                        }
                        _ => {}
                    }
                }
            }
            LocalSegmentExemption::TooWide => out.too_wide.push(segment),
            LocalSegmentExemption::NotPrivate => {
                if let IpAddr::V6(net) = segment.network() {
                    out.public_v6.push((net, segment.prefix_len()));
                }
            }
        }
    }
    out
}

/// `false` for v6 destinations already covered elsewhere or that no host lives
/// on: multicast, the link-local scope, loopback and the unspecified block.
///
/// A segment numbered from `::` with a short prefix is NOT the unspecified
/// address — it is a network handing out half the internet, which the
/// exemption decision has to see to refuse and report.
fn is_unicast_destination_v6(net: Ipv6Addr, prefix: u8) -> bool {
    let s = net.segments();
    !net.is_multicast()
        && (s[0] & 0xffc0) != 0xfe80
        && net != Ipv6Addr::LOCALHOST
        && !(net.is_unspecified() && prefix >= 8)
}

/// `false` for the destinations that are routing artefacts rather than
/// segments a host can live on. `0.0.0.0/8` is "this network"; `0.0.0.0/1`
/// is a segment somebody handed out, kept so it can be refused by name.
fn is_unicast_destination(net: Ipv4Addr, prefix: u8) -> bool {
    !(net.is_multicast()
        || net.is_broadcast()
        || net.is_loopback()
        || (net.is_unspecified() && prefix >= 8))
}

/// Directly-connected private subnets of the host's LOCAL virtual-machine
/// adapters (hypervisor host-only / NAT / bridged), excluding `exclude_ifindex`
/// — the additional route, whose own subnet must never be exempted.
///
/// These are segments that live inside this machine: traffic to them never
/// reaches a provider, so a kill-switch blocking them protects nothing and only
/// takes the user's virtual machines away. What it must NOT do is exempt a
/// tunnel that happens to use the same address space — see
/// [`nrr_platform_api::adapters::is_virtual_machine_adapter`]. A hypervisor
/// adapter carrying a public range is no local segment either, and the same
/// decision as for the main link keeps it out.
pub fn virtual_machine_local_subnets(
    routes: &[RouteEntry],
    adapters: &[nrr_platform_api::adapters::AdapterInfo],
    exclude_ifindex: Option<u32>,
) -> Vec<(Ipv4Addr, u8)> {
    let mut seen = HashSet::new();
    adapters
        .iter()
        .filter(|info| Some(info.index) != exclude_ifindex)
        .filter(|info| nrr_platform_api::adapters::is_virtual_machine_adapter(info))
        .flat_map(|info| exemptible_local_subnets(routes, info.index).v4)
        .filter(|s| seen.insert(*s))
        .collect()
}

/// What a single `reconcile` changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RouteReconcileDelta {
    pub added: usize,
    pub removed: usize,
}

impl RouteReconcileDelta {
    pub fn is_noop(&self) -> bool {
        self.added == 0 && self.removed == 0
    }
}

/// Reconciles the owned secondary-route set into the system route table.
pub struct SecondaryRouteReconciler {
    api: Arc<dyn RouteTablePort>,
    /// Routes this reconciler currently owns (last successfully applied
    /// desired set, plus what went in ahead of the next pass).
    owned: Mutex<OwnedRoutes>,
    /// Bumped after every write of ours to the table: a reading taken before
    /// it may miss a route we own, and is read again.
    writes: AtomicU64,
    /// "Has the stop teardown begun?" A route added behind it stays in the OS
    /// table with no service left to reap it. Injected rather than read from
    /// the static directly so a test can flip it for itself alone.
    teardown_gate: Arc<dyn Fn() -> bool + Send + Sync>,
    clock: Arc<dyn Fn() -> std::time::Instant + Send + Sync>,
}

// `owned` is a `Mutex`; `lock().unwrap_or_else(into_inner)` recovers from a
// poisoned lock instead of unwrapping (workspace denies `unwrap_used`).
impl SecondaryRouteReconciler {
    pub fn new(api: Arc<dyn RouteTablePort>) -> Self {
        Self {
            api,
            owned: Mutex::new(OwnedRoutes::default()),
            writes: AtomicU64::new(0),
            teardown_gate: Arc::new(crate::teardown_in_progress),
            clock: Arc::new(std::time::Instant::now),
        }
    }

    #[cfg(test)]
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> std::time::Instant + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Answer "is the service stopping?" from something other than the
    /// process-wide latch.
    #[cfg(test)]
    pub fn with_teardown_gate(mut self, gate: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.teardown_gate = gate;
        self
    }

    /// Seed the owned set without touching the route table. Used by the
    /// wiring layer's startup orphan-adoption (routes already present in
    /// the OS table that match our signature) so the next `reconcile`
    /// can delete the ones the new desired set no longer wants.
    pub fn adopt_owned(&self, routes: Vec<RouteEntry>) {
        let mut owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        *owned = OwnedRoutes {
            routes,
            ..OwnedRoutes::default()
        };
    }

    /// Add to the owned set every row of the live table that carries our
    /// signature, so the next reconcile keeps what is still wanted and takes
    /// back the rest. Returns how many rows carried it.
    pub fn adopt_signed_routes(&self) -> Result<usize, PlatformError> {
        self.adopt_signed_routes_with(&|_: &RouteEntry| false)
    }

    /// [`Self::adopt_signed_routes`], also taking the rows `also_ours` claims
    /// (every route in a table only we write).
    pub fn adopt_signed_routes_with(
        &self,
        also_ours: &dyn Fn(&RouteEntry) -> bool,
    ) -> Result<usize, PlatformError> {
        let found = signed_routes(self.api.as_ref(), also_ours)?;
        let count = found.len();
        let mut owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        for route in found {
            if !owned
                .routes
                .iter()
                .any(|o| route_key(o) == route_key(&route))
            {
                owned.routes.push(route);
            }
        }
        Ok(count)
    }

    /// Is this table row one of ours? Compared by destination, prefix and
    /// interface — the identity the OS table exposes; metric and flags are not
    /// part of it because the OS may report them differently from what we asked.
    ///
    /// The FFI reports `is_ours = false` for every row it enumerates (it cannot
    /// know), so a caller that classifies a raw table needs this to stamp the
    /// field before deriving anything from ownership.
    pub fn owns(&self, route: &RouteEntry) -> bool {
        self.owned
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .routes
            .iter()
            .any(|our| {
                our.destination == route.destination
                    && our.prefix_length == route.prefix_length
                    && our.interface_index == route.interface_index
            })
    }

    /// Number of routes currently owned.
    pub fn owned_count(&self) -> usize {
        self.owned
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .routes
            .len()
    }

    /// How many writes of ours the table has seen; pairs with
    /// [`Self::reconcile_seen`] and [`Self::reconcile_planned`]. A pass reads
    /// it BEFORE the inputs it plans from, so a route installed ahead of it
    /// after that reading is recognised as newer than its plan.
    pub fn write_count(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }

    /// Diff `desired` against the owned set and apply the difference. On
    /// success the owned set becomes exactly `desired`. On any platform
    /// error the partial changes are rolled back and the owned set follows
    /// what the rollback actually restored.
    ///
    /// `desired` is taken as the whole truth: a route installed ahead of a pass
    /// goes too. A pass that planned from inputs read earlier passes the write
    /// count it read first to [`Self::reconcile_planned`] instead.
    pub fn reconcile(&self, desired: &[RouteEntry]) -> Result<RouteReconcileDelta, PlatformError> {
        let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        self.reconcile_owned(desired, owned, None, None)
    }

    /// [`Self::reconcile`] for a pass that read [`Self::write_count`] as
    /// `planned_at` before the inputs `desired` was planned from: a route
    /// installed ahead of the pass after that reading is kept, since the plan
    /// never saw the address it serves. Only a pass planned later drops it.
    pub fn reconcile_planned(
        &self,
        desired: &[RouteEntry],
        planned_at: u64,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        self.reconcile_owned(desired, owned, Some(planned_at), None)
    }

    /// [`Self::reconcile_planned`] also checking the kept routes against
    /// `seen`, the table the caller read for this pass, instead of reading it
    /// again. Stale once a write of ours followed it, and then read afresh.
    pub fn reconcile_seen(
        &self,
        desired: &[RouteEntry],
        planned_at: u64,
        seen: Option<TableReading<'_>>,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        self.reconcile_owned(desired, owned, Some(planned_at), seen)
    }

    /// Forget the kept routes the live table no longer holds, so the diff puts
    /// them back. Only routes kept across the pass are checked: one being
    /// dropped is deleted anyway, and deleting what is gone is success. A fresh
    /// read happens under the owned-set lock, so no write of ours lands
    /// between it and the diff.
    fn forget_vanished(
        &self,
        owned: &mut OwnedRoutes,
        desired: &HashSet<RouteKey>,
        seen: Option<TableReading<'_>>,
    ) {
        if !owned.routes.iter().any(|o| desired.contains(&route_key(o))) {
            return;
        }
        let fresh: Vec<RouteEntry>;
        let rows = match seen {
            Some(reading) if reading.writes == self.write_count() => reading.rows,
            _ => match self.api.get_ip_forward_table() {
                Ok(rows) => {
                    fresh = rows;
                    fresh.as_slice()
                }
                Err(e) => {
                    tracing::debug!(
                        target: "nrr::route-reconciler",
                        error = %e,
                        "route table unreadable: the kept routes are taken as still in place",
                    );
                    return;
                }
            },
        };
        let present: HashSet<PresenceKey> = rows.iter().map(presence_key).collect();
        let mut vanished: Vec<RouteEntry> = Vec::new();
        owned.routes.retain(|o| {
            let kept = !desired.contains(&route_key(o)) || present.contains(&presence_key(o));
            if !kept {
                vanished.push(o.clone());
            }
            kept
        });
        if vanished.is_empty() {
            return;
        }
        tracing::info!(
            target: "nrr::route-reconciler",
            vanished = vanished.len() as u64,
            "routes of ours were removed from outside; putting them back",
        );
        let now = (self.clock)();
        for route in vanished {
            if owned.note_vanished(route_key(&route), now) {
                tracing::warn!(
                    target: "nrr::route-reconciler",
                    msg_key = "routerecon-route-contested",
                    destination = %route.destination,
                    prefix_len = route.prefix_length,
                    interface = route.interface_index,
                    "another program keeps removing a route of ours; it is left to it for five minutes",
                );
            }
        }
    }

    /// The body of [`Self::reconcile`], entered with the owned-set lock ALREADY
    /// held. Callers that derive `desired` FROM the owned set must hold the lock
    /// across both steps: releasing it in between lets a concurrent reconcile
    /// change what is owned, and the derived set then deletes routes it never
    /// looked at (see [`Self::retain_rule_routes`]).
    fn reconcile_owned(
        &self,
        desired: &[RouteEntry],
        mut owned: std::sync::MutexGuard<'_, OwnedRoutes>,
        planned_at: Option<u64>,
        seen: Option<TableReading<'_>>,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let desired_keys: HashSet<RouteKey> = desired.iter().map(route_key).collect();
        let now = (self.clock)();
        owned.settle_contests(&desired_keys, now);
        self.forget_vanished(&mut owned, &desired_keys, seen);
        // A route the plan wants is the plan's from here on.
        owned.ahead.retain(|(k, _)| !desired_keys.contains(k));
        let owned_keys: HashSet<RouteKey> = owned.routes.iter().map(route_key).collect();

        let mut actions: Vec<RoutingAction> = Vec::new();
        // Delete owned routes the new desired set drops — except one that went
        // in ahead of this pass after its plan was read: the plan never saw
        // the address, so its absence from `desired` says nothing.
        let mut removed = 0usize;
        let mut kept_ahead: Vec<RouteEntry> = Vec::new();
        for r in owned.routes.iter() {
            let key = route_key(r);
            if desired_keys.contains(&key) {
                continue;
            }
            if planned_at.is_some_and(|at| owned.installed_after(&key, at)) {
                kept_ahead.push(r.clone());
                continue;
            }
            actions.push(RoutingAction::DeleteRoute(r.clone()));
            removed += 1;
        }
        owned
            .ahead
            .retain(|(k, _)| kept_ahead.iter().any(|r| route_key(r) == *k));
        // Add newly-desired routes (AddRoute is idempotent on conflict, so
        // a route already in the table is harmless). Never once the stop
        // teardown has begun: a pass that entered before the latch is still
        // running, and what it adds behind the teardown outlives the process.
        // Deletes stay — converging downward is exactly what the stop wants.
        let mut added = 0usize;
        let mut refused = 0usize;
        for r in desired.iter() {
            let key = route_key(r);
            if !owned_keys.contains(&key) {
                if owned.held_out(&key, now) {
                    continue;
                }
                if (self.teardown_gate)() {
                    refused += 1;
                    continue;
                }
                actions.push(RoutingAction::AddRoute(r.clone()));
                added += 1;
            }
        }
        if refused > 0 {
            tracing::info!(
                target: "nrr::route-reconciler",
                msg_key = "routerecon-teardown-refused",
                refused = refused as u64,
                "teardown in progress — route adds refused (a route added behind the stop outlives the process)",
            );
        }

        if actions.is_empty() {
            return Ok(RouteReconcileDelta::default());
        }

        let mut tx = RoutingTransaction::new(Arc::clone(&self.api));
        let executed = tx.execute(&actions);
        self.writes.fetch_add(1, Ordering::SeqCst);
        match executed {
            Ok(()) => {
                // Claim what we ACTUALLY added, plus what we already owned and
                // still want. A conflicting add reports success without adding
                // anything - the route belongs to somebody else, typically a
                // redirect VPN's own overlay - and claiming the whole desired
                // set would adopt it and delete it on a later pass, which is
                // exactly what destabilises the VPN client.
                let landed: HashSet<RouteKey> = tx.added_routes().iter().map(route_key).collect();
                tx.finalize();
                owned.routes = desired
                    .iter()
                    .filter(|d| {
                        let key = route_key(d);
                        landed.contains(&key) || owned_keys.contains(&key)
                    })
                    .cloned()
                    .chain(kept_ahead)
                    .collect();
                Ok(RouteReconcileDelta { added, removed })
            }
            Err(e) => {
                // The claim follows what the table holds after the undo. Clearing
                // it orphaned the restored routes (to a gateway that may be dead)
                // until restart; keeping it whole claimed routes the undo failed
                // to put back, so the next diff never re-added them.
                let residue = tx.rollback_with_residue();
                owned.routes.retain(|o| {
                    !residue
                        .still_removed
                        .iter()
                        .any(|r| route_key(r) == route_key(o))
                });
                for r in residue.still_added {
                    if !owned.routes.iter().any(|o| route_key(o) == route_key(&r)) {
                        owned.routes.push(r);
                    }
                }
                Err(e)
            }
        }
    }

    /// Tear down every owned route (active user logged off / service
    /// stopping). Equivalent to `reconcile(&[])`.
    pub fn clear(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconcile(&[])
    }

    /// Installs `extra` beside the owned set without touching the rest of it,
    /// and claims what actually landed — a conflicting add stays whoever's it
    /// is. For a first contact with a new address: the full reconcile that
    /// wants the same routes runs seconds later and finds them in place, and
    /// a pass already planned when they went in leaves them alone (see
    /// [`Self::reconcile_planned`]). Returns how many were added.
    pub fn install_additional(&self, extra: &[RouteEntry]) -> Result<usize, PlatformError> {
        if (self.teardown_gate)() {
            return Ok(0);
        }
        let mut owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        let actions: Vec<RoutingAction> = extra
            .iter()
            .filter(|r| !owned.routes.iter().any(|o| route_key(o) == route_key(r)))
            .map(|r| RoutingAction::AddRoute(r.clone()))
            .collect();
        if actions.is_empty() {
            return Ok(0);
        }
        let mut tx = RoutingTransaction::new(Arc::clone(&self.api));
        let executed = tx.execute(&actions);
        let installed_at = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if let Err(e) = executed {
            owned.routes.extend(tx.rollback_with_residue().still_added);
            return Err(e);
        }
        let landed = tx.added_routes();
        tx.finalize();
        let added = landed.len();
        owned
            .ahead
            .extend(landed.iter().map(|r| (route_key(r), installed_at)));
        owned.routes.extend(landed);
        Ok(added)
    }

    /// Graceful-stop teardown: delete our overlays (the mode-A counter-overlays,
    /// the mode-B split-default) and keep every rule route — hosts and network
    /// pieces alike — so rule traffic keeps its link after the service stops
    /// while the rest returns to whatever the OS or VPN provides. The overlay
    /// signature decides, not the prefix: a network piece can be a `/32`, and
    /// a network rule is wider than one.
    pub fn retain_rule_routes(&self) -> Result<RouteReconcileDelta, PlatformError> {
        // One lock across derive AND apply: `keep` IS the owned set minus the
        // overlays, so a reconcile slipping in between would have its routes
        // deleted by a `desired` that predates them.
        let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        let keep: Vec<RouteEntry> = owned
            .routes
            .iter()
            .filter(|r| !crate::route_codegen::is_overlay_route(r))
            .cloned()
            .collect();
        self.reconcile_owned(&keep, owned, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::MockWindowsApi;

    fn route(d: [u8; 4], gw: [u8; 4], ifx: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(d)),
            prefix_length: 32,
            next_hop: IpAddr::V4(Ipv4Addr::from(gw)),
            interface_index: ifx,
            metric: 5,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn table_dests(api: &MockWindowsApi) -> HashSet<Ipv4Addr> {
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .filter_map(|r| match r.destination {
                IpAddr::V4(d) => Some(d),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// A route table where one destination is already occupied by somebody
    /// else - the shape a redirect VPN's own overlay makes.
    struct ForeignRouteApi {
        inner: MockWindowsApi,
        taken: Ipv4Addr,
    }

    impl RouteTablePort for ForeignRouteApi {
        fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
            self.inner.get_ip_forward_table()
        }
        fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
            if entry.destination == self.taken {
                return Err(PlatformError::Win32 {
                    operation: "CreateIpForwardEntry2",
                    code: nrr_platform_api::error::win32_codes::ERROR_OBJECT_ALREADY_EXISTS,
                    message: "route already exists".into(),
                });
            }
            self.inner.create_ip_forward_entry(entry)
        }
        fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
            self.inner.delete_ip_forward_entry(entry)
        }
        fn get_adapter_infos(&self) -> Result<Vec<nrr_platform_api::AdapterInfo>, PlatformError> {
            self.inner.get_adapter_infos()
        }
        fn interface_luid_for_index(&self, index: u32) -> Result<u64, PlatformError> {
            self.inner.interface_luid_for_index(index)
        }
    }

    /// A conflicting add means the route is somebody ELSE'S - a redirect VPN's
    /// own `/1` overlay is the usual one. Treating the whole desired set as
    /// ours afterwards adopted that route, and the next pass that no longer
    /// wanted it DELETED it, which is precisely what destabilises the VPN
    /// client we were careful not to touch.
    #[test]
    fn a_route_we_did_not_add_is_never_claimed_as_ours() {
        let taken = Ipv4Addr::new(198, 51, 100, 1);
        let api = Arc::new(ForeignRouteApi {
            inner: MockWindowsApi::new(),
            taken,
        });
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let desired = vec![
            route([198, 51, 100, 1], [10, 0, 0, 1], 7),
            route([198, 51, 100, 2], [10, 0, 0, 1], 7),
        ];
        rec.reconcile(&desired).expect("conflict is not a failure");
        assert_eq!(
            rec.owned_count(),
            1,
            "only the route we actually added is ours",
        );

        // The next pass wants neither. Ours goes; the foreign one is left alone.
        rec.reconcile(&[]).expect("second reconcile");
        assert_eq!(rec.owned_count(), 0);
    }

    /// A first-contact route goes in beside what is owned and is claimed, so
    /// the full pass that wants it finds it in place; a route somebody else
    /// already holds stays theirs.
    #[test]
    fn an_additional_route_is_claimed_and_the_full_pass_finds_it_in_place() {
        let taken = Ipv4Addr::new(198, 51, 100, 1);
        let api = Arc::new(ForeignRouteApi {
            inner: MockWindowsApi::new(),
            taken,
        });
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.reconcile(&[route([198, 51, 100, 3], [10, 0, 0, 1], 7)])
            .expect("first pass");

        let extra = vec![
            route([198, 51, 100, 2], [10, 0, 0, 1], 7),
            route([198, 51, 100, 1], [10, 0, 0, 1], 7),
        ];
        assert_eq!(rec.install_additional(&extra).expect("install"), 1);
        assert_eq!(
            rec.owned_count(),
            2,
            "the owned route stays, only ours is claimed"
        );

        let delta = rec
            .reconcile(&[
                route([198, 51, 100, 3], [10, 0, 0, 1], 7),
                route([198, 51, 100, 2], [10, 0, 0, 1], 7),
            ])
            .expect("full pass");
        assert!(delta.is_noop(), "{delta:?}");
    }

    /// The stop strips the table, and a pass that entered before the latch is
    /// still running: what it adds afterwards stays behind with no service to
    /// reap it. Deletes must still land — converging downward is the point.
    #[test]
    fn a_reconcile_that_lands_during_teardown_removes_but_never_adds() {
        let api = Arc::new(MockWindowsApi::new());
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = {
            let stopping = Arc::clone(&stopping);
            Arc::new(move || stopping.load(std::sync::atomic::Ordering::SeqCst))
                as Arc<dyn Fn() -> bool + Send + Sync>
        };
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>)
            .with_teardown_gate(gate);
        rec.reconcile(&[route([198, 51, 100, 1], [10, 0, 0, 1], 7)])
            .expect("first pass");

        stopping.store(true, std::sync::atomic::Ordering::SeqCst);
        let delta = rec
            .reconcile(&[route([198, 51, 100, 2], [10, 0, 0, 1], 7)])
            .expect("teardown pass");
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 0,
                removed: 1
            },
        );
        assert!(
            table_dests(&api).is_empty(),
            "the new route never reached the table",
        );
        assert_eq!(
            rec.install_additional(&[route([198, 51, 100, 3], [10, 0, 0, 1], 7)])
                .expect("additional"),
            0
        );
        assert!(table_dests(&api).is_empty());
    }

    type AddFailure = Box<dyn Fn(&RouteEntry) -> bool + Send>;

    /// A route table whose adds fail on demand, for driving a reconcile into
    /// its rollback.
    struct FlakyAddApi {
        inner: MockWindowsApi,
        fail_add: Mutex<AddFailure>,
    }

    impl FlakyAddApi {
        fn new() -> Self {
            Self {
                inner: MockWindowsApi::new(),
                fail_add: Mutex::new(Box::new(|_| false)),
            }
        }
        fn fail_adds_when(&self, pred: impl Fn(&RouteEntry) -> bool + Send + 'static) {
            *self.fail_add.lock().unwrap() = Box::new(pred);
        }
    }

    impl RouteTablePort for FlakyAddApi {
        fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
            self.inner.get_ip_forward_table()
        }
        fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
            if (self.fail_add.lock().unwrap())(entry) {
                return Err(PlatformError::Win32 {
                    operation: "CreateIpForwardEntry2",
                    code: 0x5,
                    message: "simulated fatal".into(),
                });
            }
            self.inner.create_ip_forward_entry(entry)
        }
        fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
            self.inner.delete_ip_forward_entry(entry)
        }
        fn get_adapter_infos(&self) -> Result<Vec<nrr_platform_api::AdapterInfo>, PlatformError> {
            self.inner.get_adapter_infos()
        }
        fn interface_luid_for_index(&self, index: u32) -> Result<u64, PlatformError> {
            self.inner.interface_luid_for_index(index)
        }
    }

    fn table_gateways(api: &FlakyAddApi) -> HashSet<IpAddr> {
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .map(|r| r.next_hop)
            .collect()
    }

    /// The gateway moves, the switch fails half-way and the rollback puts the
    /// old routes back. They are still ours: when the secondary then goes away
    /// they must go with it, not stay pointing at a dead gateway.
    #[test]
    fn routes_restored_by_a_rollback_stay_owned_and_are_removed_later() {
        let api = Arc::new(FlakyAddApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let old_gw = [10, 0, 0, 1];
        let new_gw = [192, 168, 0, 1];
        rec.reconcile(&[
            route([198, 51, 100, 1], old_gw, 7),
            route([198, 51, 100, 2], old_gw, 7),
        ])
        .expect("first pass");

        let failing = route([198, 51, 100, 2], new_gw, 9);
        api.fail_adds_when(move |r| r == &failing);
        rec.reconcile(&[
            route([198, 51, 100, 1], new_gw, 9),
            route([198, 51, 100, 2], new_gw, 9),
        ])
        .expect_err("the second add fails");
        assert_eq!(
            table_gateways(&api),
            HashSet::from([IpAddr::V4(Ipv4Addr::from(old_gw))]),
            "the rollback restored the old routes",
        );
        assert_eq!(rec.owned_count(), 2);

        api.fail_adds_when(|_| false);
        rec.reconcile(&[]).expect("secondary gone");
        assert!(
            table_dests_of(&api).is_empty(),
            "no route to the old gateway survives",
        );
    }

    /// Positive control for the other direction: a route the rollback failed to
    /// put back is not claimed, so the next pass that wants it re-adds it.
    #[test]
    fn a_route_the_rollback_could_not_restore_is_re_added_next_pass() {
        let api = Arc::new(FlakyAddApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let old = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        rec.reconcile(std::slice::from_ref(&old))
            .expect("first pass");

        api.fail_adds_when(|_| true);
        rec.reconcile(&[route([198, 51, 100, 1], [192, 168, 0, 1], 9)])
            .expect_err("the add and its undo both fail");
        assert!(table_dests_of(&api).is_empty());
        assert_eq!(rec.owned_count(), 0, "a route that is gone is not ours");

        api.fail_adds_when(|_| false);
        let delta = rec.reconcile(std::slice::from_ref(&old)).expect("retry");
        assert_eq!(delta.added, 1);
        assert_eq!(table_dests_of(&api).len(), 1);
    }

    fn table_dests_of(api: &FlakyAddApi) -> HashSet<IpAddr> {
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .map(|r| r.destination)
            .collect()
    }

    #[test]
    fn first_reconcile_adds_all_desired() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let desired = vec![
            route([198, 51, 100, 1], [10, 0, 0, 1], 7),
            route([198, 51, 100, 2], [10, 0, 0, 1], 7),
        ];
        let delta = rec.reconcile(&desired).unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 2,
                removed: 0
            }
        );
        assert_eq!(rec.owned_count(), 2);
        assert_eq!(
            table_dests(&api),
            HashSet::from([
                Ipv4Addr::new(198, 51, 100, 1),
                Ipv4Addr::new(198, 51, 100, 2)
            ])
        );
    }

    #[test]
    fn reconcile_is_idempotent_when_desired_unchanged() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let desired = vec![route([198, 51, 100, 1], [10, 0, 0, 1], 7)];
        rec.reconcile(&desired).unwrap();
        let delta = rec.reconcile(&desired).unwrap();
        assert!(delta.is_noop());
        assert_eq!(table_dests(&api).len(), 1);
    }

    #[test]
    fn reconcile_adds_new_and_removes_dropped() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.reconcile(&[
            route([198, 51, 100, 1], [10, 0, 0, 1], 7),
            route([198, 51, 100, 2], [10, 0, 0, 1], 7),
        ])
        .unwrap();
        // New desired: drop .2, keep .1, add .3.
        let delta = rec
            .reconcile(&[
                route([198, 51, 100, 1], [10, 0, 0, 1], 7),
                route([198, 51, 100, 3], [10, 0, 0, 1], 7),
            ])
            .unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 1,
                removed: 1
            }
        );
        assert_eq!(
            table_dests(&api),
            HashSet::from([
                Ipv4Addr::new(198, 51, 100, 1),
                Ipv4Addr::new(198, 51, 100, 3)
            ])
        );
    }

    #[test]
    fn changing_secondary_gateway_replaces_the_route() {
        // Same destination, different gateway/ifindex → delete old + add new.
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.reconcile(&[route([198, 51, 100, 1], [10, 0, 0, 1], 7)])
            .unwrap();
        let delta = rec
            .reconcile(&[route([198, 51, 100, 1], [192, 168, 0, 1], 9)])
            .unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 1,
                removed: 1
            }
        );
        let table = api.get_ip_forward_table().unwrap();
        let r = table
            .iter()
            .find(|r| r.destination == Ipv4Addr::new(198, 51, 100, 1))
            .unwrap();
        assert_eq!(r.next_hop, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(r.interface_index, 9);
    }

    #[test]
    fn clear_removes_all_owned_routes() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.reconcile(&[
            route([198, 51, 100, 1], [10, 0, 0, 1], 7),
            route([198, 51, 100, 2], [10, 0, 0, 1], 7),
        ])
        .unwrap();
        let delta = rec.clear().unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 0,
                removed: 2
            }
        );
        assert!(table_dests(&api).is_empty());
        assert_eq!(rec.owned_count(), 0);
    }

    #[test]
    fn adopt_owned_lets_next_reconcile_purge_orphans() {
        // Simulate a crash: routes exist in the table + we adopt them as
        // owned; a fresh desired set then drops one.
        let api = Arc::new(MockWindowsApi::new());
        let orphan_a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        let orphan_b = route([198, 51, 100, 2], [10, 0, 0, 1], 7);
        api.set_route_table(vec![orphan_a.clone(), orphan_b.clone()]);
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.adopt_owned(vec![orphan_a.clone(), orphan_b]);
        // New desired keeps only .1 → .2 must be purged.
        let delta = rec.reconcile(&[orphan_a]).unwrap();
        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 0,
                removed: 1
            }
        );
        assert_eq!(
            table_dests(&api),
            HashSet::from([Ipv4Addr::new(198, 51, 100, 1)])
        );
    }

    // ── routes removed from outside ──

    /// A kept route deleted from outside, in either family, is put back on the
    /// next pass; the one still in place is neither removed nor re-added.
    #[test]
    fn a_kept_route_removed_from_outside_is_put_back_and_nothing_else_moves() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        let b = route([198, 51, 100, 2], [10, 0, 0, 1], 7);
        let v6 = RouteEntry {
            destination: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            prefix_length: 128,
            next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ..a.clone()
        };
        let desired = [a, b.clone(), v6.clone()];
        rec.reconcile(&desired).unwrap();

        api.delete_ip_forward_entry(&b).unwrap();
        api.delete_ip_forward_entry(&v6).unwrap();
        let delta = rec.reconcile(&desired).unwrap();

        assert_eq!(
            delta,
            RouteReconcileDelta {
                added: 2,
                removed: 0
            }
        );
        assert_eq!(rec.owned_count(), 3);
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 3, "each once");
        assert!(rec.reconcile(&desired).unwrap().is_noop());
    }

    /// A client that enforces its own table deletes our route again and again;
    /// past three put-backs a minute the route is left to it for five minutes,
    /// then tried again, instead of trading deletes on every pass.
    #[test]
    fn a_route_removed_again_and_again_is_left_alone_for_a_while() {
        let api = Arc::new(MockWindowsApi::new());
        let now = Arc::new(Mutex::new(std::time::Instant::now()));
        let clock = {
            let now = Arc::clone(&now);
            Arc::new(move || *now.lock().expect("clock"))
        };
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>)
            .with_clock(clock);
        let a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        let desired = [a.clone()];
        rec.reconcile(&desired).unwrap();

        let mut put_back = 0;
        for _ in 0..3 {
            api.delete_ip_forward_entry(&a).unwrap();
            *now.lock().expect("clock") += std::time::Duration::from_secs(5);
            put_back += rec.reconcile(&desired).unwrap().added;
        }
        assert_eq!(put_back, 2, "the third removal is not answered");
        assert!(api.get_ip_forward_table().unwrap().is_empty());
        assert!(
            rec.reconcile(&desired).unwrap().is_noop(),
            "held while it lasts"
        );

        *now.lock().expect("clock") += CONTEST_BACKOFF;
        assert_eq!(rec.reconcile(&desired).unwrap().added, 1, "tried again");
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);
    }

    /// The OS may report a route of ours with another next-hop spelling or
    /// metric. It is still in place: re-adding it would conflict and lose the
    /// claim on it.
    #[test]
    fn a_route_reported_in_another_spelling_is_still_in_place() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        rec.reconcile(std::slice::from_ref(&a)).unwrap();
        api.set_route_table(vec![RouteEntry {
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            metric: 261,
            is_ours: false,
            ..a.clone()
        }]);

        assert!(rec.reconcile(&[a]).unwrap().is_noop());
        assert_eq!(rec.owned_count(), 1);
    }

    /// An unreadable table proves nothing gone: memory stands, nothing moves.
    #[test]
    fn an_unreadable_table_keeps_what_is_remembered() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        rec.reconcile(std::slice::from_ref(&a)).unwrap();
        api.set_route_table_read_error(Some("busy"));

        assert!(rec.reconcile(&[a]).unwrap().is_noop());
        assert_eq!(rec.owned_count(), 1);
    }

    /// The pass hands over the table it began with, trusted only while no
    /// write of ours has followed it: a route added since would read as gone,
    /// and its re-add would conflict.
    #[test]
    fn a_handed_reading_is_trusted_until_a_write_of_ours_follows_it() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        let c = route([198, 51, 100, 3], [10, 0, 0, 1], 7);
        rec.reconcile(std::slice::from_ref(&a)).unwrap();

        let writes = rec.write_count();
        let rows = api.get_ip_forward_table().unwrap();
        rec.install_additional(std::slice::from_ref(&c)).unwrap();
        let both = [a, c];
        let stale = TableReading {
            writes,
            rows: &rows,
        };
        let delta = rec.reconcile_seen(&both, writes, Some(stale)).unwrap();
        assert!(delta.is_noop(), "read again, and both are there: {delta:?}");

        // A current reading is taken at its word.
        let writes = rec.write_count();
        let current = TableReading { writes, rows: &[] };
        assert_eq!(
            rec.reconcile_seen(&both, writes, Some(current))
                .unwrap()
                .added,
            2
        );
    }

    /// The DNS answer that installs a first-contact route lands while a pass
    /// is already planned from an older cache: that pass must not take the
    /// route out, or the host's next connection leaves by the main link until
    /// the forced pass puts it back. A pass planned after the install, whose
    /// plan still does not want the route, drops it as any route of ours.
    #[test]
    fn a_route_installed_ahead_survives_the_pass_planned_before_it() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let a = route([198, 51, 100, 1], [10, 0, 0, 1], 7);
        let x = route([198, 51, 100, 9], [10, 0, 0, 1], 7);
        rec.reconcile(std::slice::from_ref(&a)).unwrap();

        // The pass reads the write count, then its inputs (without X)...
        let planned_at = rec.write_count();
        // ...and the DNS answer installs X in between.
        assert_eq!(rec.install_additional(std::slice::from_ref(&x)).unwrap(), 1);

        let delta = rec
            .reconcile_planned(std::slice::from_ref(&a), planned_at)
            .unwrap();
        assert!(delta.is_noop(), "{delta:?}");
        assert!(table_dests(&api).contains(&Ipv4Addr::new(198, 51, 100, 9)));
        assert_eq!(rec.owned_count(), 2, "X stays ours");

        // The pass planned after the install, with X in its plan, redoes nothing.
        let planned_at = rec.write_count();
        let both = [a.clone(), x.clone()];
        assert!(rec.reconcile_planned(&both, planned_at).unwrap().is_noop());

        // One planned after the install without X takes it out.
        let planned_at = rec.write_count();
        let delta = rec
            .reconcile_planned(std::slice::from_ref(&a), planned_at)
            .unwrap();
        assert_eq!(delta.removed, 1);
        assert!(!table_dests(&api).contains(&Ipv4Addr::new(198, 51, 100, 9)));
    }

    /// A pass with no plan origin — the teardown's `clear`, a persist-pause
    /// `retain_rule_routes` — still owns everything, ahead routes included.
    #[test]
    fn a_pass_without_a_plan_origin_takes_ahead_routes_out_too() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let x = route([198, 51, 100, 9], [10, 0, 0, 1], 7);
        assert_eq!(rec.install_additional(std::slice::from_ref(&x)).unwrap(), 1);
        assert_eq!(rec.clear().unwrap().removed, 1);
        assert!(table_dests(&api).is_empty());
        assert_eq!(rec.owned_count(), 0);
    }

    // ── route ownership classification ──

    fn raw_route(d: [u8; 4], prefix: u8, gw: [u8; 4], ifx: u32, ours: bool) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(d)),
            prefix_length: prefix,
            next_hop: IpAddr::V4(Ipv4Addr::from(gw)),
            interface_index: ifx,
            metric: 5,
            is_ours: ours,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    // ── Kill-switch exemptions ──────────────────────────────────────────────

    #[test]
    fn bootstrap_server_ips_collects_host_routes_via_primary_gateway() {
        let pg = [192, 168, 1, 1];
        let routes = vec![
            raw_route([203, 0, 113, 7], 32, pg, 12, false), // VPN server #1 (bootstrap)
            raw_route([198, 51, 100, 9], 32, pg, 12, false), // VPN server #2 (bootstrap)
            raw_route([203, 0, 113, 7], 32, pg, 12, false), // dup → deduped
            raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false), // VPN redirect half (not a server)
            raw_route([203, 0, 113, 138], 32, [10, 91, 192, 1], 78, true), // our /32 (is_ours)
        ];
        let got = bootstrap_server_ips(&routes, 78, Some(Ipv4Addr::from(pg)));
        assert_eq!(
            got,
            vec![
                Ipv4Addr::new(203, 0, 113, 7),
                Ipv4Addr::new(198, 51, 100, 9)
            ]
        );
    }

    #[test]
    fn bootstrap_server_ips_empty_without_primary_gateway() {
        // No primary gateway → the bootstrap classifier can't fire → empty,
        // which makes the caller refuse to arm the catch-all (fail-open).
        let routes = vec![raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false)];
        assert!(bootstrap_server_ips(&routes, 78, None).is_empty());
    }

    /// Windows puts an on-link multicast route on every interface; it is not a
    /// subnet, and exempting it would open all multicast rather than the
    /// control block.
    #[test]
    fn multicast_and_broadcast_routes_are_not_local_subnets() {
        let routes = vec![
            raw_route([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, false),
            raw_route([224, 0, 0, 0], 4, [0, 0, 0, 0], 12, false),
            raw_route([127, 0, 0, 0], 8, [0, 0, 0, 0], 12, false),
        ];
        assert_eq!(
            primary_local_subnets(&routes, 12),
            vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]
        );
    }

    #[test]
    fn primary_local_subnets_collects_on_link_connected_routes_only() {
        let routes = vec![
            raw_route([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, false), // connected /24 → yes
            raw_route([10, 0, 0, 0], 8, [0, 0, 0, 0], 12, false),     // connected /8 → yes
            raw_route([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, false),  // default → no
            raw_route([192, 168, 1, 50], 32, [0, 0, 0, 0], 12, false), // host /32 → no
            raw_route([172, 16, 0, 0], 12, [0, 0, 0, 0], 99, false),  // other ifindex → no
        ];
        let got = primary_local_subnets(&routes, 12);
        assert_eq!(
            got,
            vec![
                (Ipv4Addr::new(192, 168, 1, 0), 24),
                (Ipv4Addr::new(10, 0, 0, 0), 8)
            ]
        );
    }

    fn raw_route_v6(d: Ipv6Addr, prefix: u8, ifx: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V6(d),
            prefix_length: prefix,
            next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            interface_index: ifx,
            metric: 5,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    /// A hostile access point hands out a `/1`: half the internet would read
    /// as the LAN and leave both the tunnel and Fail-Closed. Nothing of such
    /// a segment is exempt, and it is reported; a sane segment keeps only its
    /// private part. Pure over the route table, so the same on both OSes.
    #[test]
    fn a_half_internet_segment_is_refused_and_reported_in_both_families() {
        let routes = vec![
            raw_route([0, 0, 0, 0], 1, [0, 0, 0, 0], 12, false),
            raw_route([128, 0, 0, 0], 1, [0, 0, 0, 0], 12, false),
            raw_route([192, 0, 0, 0], 8, [0, 0, 0, 0], 12, false),
            raw_route([203, 0, 113, 0], 24, [0, 0, 0, 0], 12, false),
            raw_route([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, false),
            raw_route_v6(Ipv6Addr::UNSPECIFIED, 1, 12),
            raw_route_v6(Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 0), 64, 12),
            raw_route_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 64, 12),
        ];
        let got = exemptible_local_subnets(&routes, 12);
        assert_eq!(got.v4, vec![(Ipv4Addr::new(192, 168, 0, 0), 16)]);
        assert_eq!(
            got.v6,
            vec![(Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 0), 64)]
        );
        assert_eq!(
            got.public_v6,
            vec![(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 64)],
            "a public prefix is a candidate, never an exemption"
        );
        assert_eq!(
            got.too_wide,
            vec![
                IpBlock::parse("0.0.0.0/1").expect("block"),
                IpBlock::parse("128.0.0.0/1").expect("block"),
                IpBlock::parse("::/1").expect("block"),
            ]
        );
        // The raw reading still names the segment, as the link's description.
        assert!(primary_local_subnets(&routes, 12).contains(&(Ipv4Addr::UNSPECIFIED, 1)));
    }

    /// Builds an adapter whose only interesting properties here are its index
    /// and what its description says it is.
    fn named_adapter(index: u32, description: &str) -> nrr_platform_api::adapters::AdapterInfo {
        use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
        nrr_platform_api::adapters::AdapterInfo {
            index,
            adapter_name: format!("{{{index}}}"),
            description: description.to_string(),
            friendly_name: description.to_string(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(10, 0, 0, 1)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    /// The exemption must cover a hypervisor's local segment and must NOT cover
    /// a VPN adapter — both live in RFC1918 space, and mistaking one for the
    /// other would punch a hole in the kill-switch instead of keeping a virtual
    /// machine reachable.
    #[test]
    fn virtual_machine_subnets_take_the_hypervisor_and_leave_every_tunnel_alone() {
        let routes = vec![
            raw_route([192, 168, 56, 0], 24, [0, 0, 0, 0], 21, false), // VirtualBox host-only
            raw_route([172, 20, 0, 0], 16, [0, 0, 0, 0], 22, false),   // Hyper-V / WSL
            raw_route([10, 7, 0, 0], 24, [0, 0, 0, 0], 23, false),     // WireGuard
            raw_route([10, 88, 0, 0], 10, [0, 0, 0, 0], 24, false),    // the additional route
            raw_route([203, 0, 113, 0], 24, [0, 0, 0, 0], 25, false),  // public on a vSwitch
        ];
        let adapters = vec![
            named_adapter(21, "VirtualBox Host-Only Ethernet Adapter"),
            named_adapter(22, "Hyper-V Virtual Ethernet Adapter"),
            named_adapter(23, "WireGuard Tunnel"),
            named_adapter(24, "VMware Virtual Ethernet Adapter"),
            named_adapter(25, "VMware Virtual Ethernet Adapter for VMnet0"),
        ];

        let got = virtual_machine_local_subnets(&routes, &adapters, Some(24));
        assert_eq!(
            got,
            vec![
                (Ipv4Addr::new(192, 168, 56, 0), 24),
                (Ipv4Addr::new(172, 20, 0, 0), 16),
            ],
            "hypervisor segments only: the WireGuard link is a tunnel, ifindex 24 is the \
             additional route, and a public range is not a local segment"
        );
    }

    #[test]
    fn classify_our_own_overlay_is_ours_not_foreign() {
        // Our mode-B overlay (is_ours) must classify as Ours even though it has
        // the same /1 shape as the VPN's redirect pair — so we never strip it.
        let r = raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, true);
        assert_eq!(
            classify_route_ownership(&r, 78, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))),
            RouteOwnership::Ours
        );
    }

    #[test]
    fn classify_vpn_redirect_pair_on_secondary() {
        let pg: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let lo = raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false);
        let hi = raw_route([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&lo, 78, pg),
            RouteOwnership::VpnRedirectOverlay
        );
        assert_eq!(
            classify_route_ownership(&hi, 78, pg),
            RouteOwnership::VpnRedirectOverlay
        );
    }

    #[test]
    fn classify_split_half_on_other_interface_is_untracked() {
        // A /1 on some other interface is not our VPN's redirect — don't touch.
        let r = raw_route([0, 0, 0, 0], 1, [10, 0, 0, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&r, 78, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))),
            RouteOwnership::Untracked
        );
    }

    #[test]
    fn classify_bootstrap_host_route_via_primary_gateway_is_preserved() {
        // /32 to the VPN server via the Ethernet gateway → never strip.
        let pg = Ipv4Addr::new(192, 168, 1, 1);
        let boot = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&boot, 78, Some(IpAddr::V4(pg))),
            RouteOwnership::BootstrapHostRoute
        );
        // Defence in depth: even if it appeared on the secondary ifindex.
        let boot_on_sec = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&boot_on_sec, 78, Some(IpAddr::V4(pg))),
            RouteOwnership::BootstrapHostRoute
        );
    }

    #[test]
    fn classify_os_default_and_unrelated_are_untracked() {
        let pg: Option<IpAddr> = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        // OS default /0 (prefix 0, not 1) — never strippable.
        let def = raw_route([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&def, 78, pg),
            RouteOwnership::Untracked
        );
        // Unrelated /24 on the secondary interface.
        let other = raw_route([10, 0, 0, 0], 24, [10, 0, 0, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&other, 78, pg),
            RouteOwnership::Untracked
        );
    }

    #[test]
    fn classify_without_primary_gateway_leaves_host_route_untracked() {
        // Without a known primary gateway we cannot identify the bootstrap, so
        // a /32 falls through to Untracked — safe, since stripping only ever
        // targets VpnRedirectOverlay (/1 on the secondary), never /32s.
        let r = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&r, 78, None),
            RouteOwnership::Untracked
        );
    }

    #[test]
    fn retain_rule_routes_keeps_every_rule_route_and_drops_overlays() {
        // Graceful stop: rule routes keep their link, the overlays go and
        // general traffic returns to the OS default.
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let host_a = route([198, 51, 100, 8], [10, 0, 0, 1], 14);
        let host_b = route([198, 51, 100, 1], [10, 0, 0, 1], 14);
        let counter_overlay = raw_route([64, 0, 0, 0], 2, [192, 168, 0, 1], 16, true);
        let split_default = raw_route([0, 0, 0, 0], 1, [10, 0, 0, 1], 14, true);
        // A network rule's pieces sit at their own metric, wide and single.
        let network_piece = RouteEntry {
            metric: crate::route_codegen::NETWORK_ROUTE_METRIC,
            ..raw_route([10, 20, 0, 0], 16, [10, 0, 0, 1], 14, true)
        };
        let single_piece = RouteEntry {
            metric: crate::route_codegen::NETWORK_ROUTE_METRIC,
            ..raw_route([10, 30, 0, 7], 32, [10, 0, 0, 1], 14, true)
        };
        rec.reconcile(&[
            host_a,
            host_b,
            counter_overlay,
            split_default,
            network_piece,
            single_piece,
        ])
        .unwrap();
        assert_eq!(rec.owned_count(), 6);

        let delta = rec.retain_rule_routes().unwrap();
        assert_eq!(
            delta.removed, 2,
            "both overlays removed (the /2 and the /1)"
        );
        assert_eq!(delta.added, 0);
        assert_eq!(rec.owned_count(), 4, "hosts and network pieces remain");
        let dests = table_dests(&api);
        assert!(dests.contains(&Ipv4Addr::new(198, 51, 100, 8)));
        assert!(dests.contains(&Ipv4Addr::new(198, 51, 100, 1)));
        assert!(
            dests.contains(&Ipv4Addr::new(10, 20, 0, 0)),
            "a wide piece stays"
        );
        assert!(dests.contains(&Ipv4Addr::new(10, 30, 0, 7)));
        assert!(
            !dests.contains(&Ipv4Addr::new(64, 0, 0, 0)),
            "counter-overlay gone"
        );
        assert!(
            !dests.contains(&Ipv4Addr::new(0, 0, 0, 0)),
            "split-default gone"
        );
    }
}
