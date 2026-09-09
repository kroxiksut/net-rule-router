//! secondary-route reconciler.
//!
//! Brings the system route table into line with a desired owned route set
//! (produced by [`crate::route_codegen`]). It tracks the routes it has
//! applied and, on each [`SecondaryRouteReconciler::reconcile`], diffs the
//! new desired set against them: it **deletes** owned routes that are no
//! longer desired and **adds** newly-desired ones, in a single
//! [`RoutingTransaction`] that rolls back on partial failure.
//!
//! ## Single-active-user model (Free)
//!
//! The Windows route table is **machine-wide** — a route entry has no user
//! dimension. So the table reflects exactly one user's routing at a time:
//! the active console-session user (block 16.18 wiring). When the active
//! user changes, the wiring recomputes the desired set for the new user
//! and calls `reconcile`, which tears down the previous user's routes and
//! installs the new user's. Per-SID WFP filters (the kill-switch) remain
//! per-user and simultaneous; only the route table is single-owner.
//! Simultaneous distinct routing for multiple concurrently-active sessions
//! needs a kernel callout driver and is not supported (`strategy.rs`).
//!
//! ## Ownership tracking
//!
//! The OS never reports `is_ours` (the FFI stamps `false`), so the
//! reconciler is the source of truth for which routes it owns, tracked
//! in-memory. Cleanup of routes orphaned by a crash (present in the OS
//! table but not in memory) is handled at startup by the wiring layer,
//! which knows the secondary gateway/metric signature — kept out of this
//! pure diff/apply core.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::routing::RoutingTransaction;
use nrr_platform_api::{PlatformError, RouteEntry, RoutingAction};

use crate::route_codegen::{OVERLAY_HIGH, OVERLAY_LOW};

/// Identity of a route for diffing — everything but `metric`/`is_ours`.
/// Two routes with the same key are "the same route"; a metric-only change
/// is not a meaningful diff for our `/32` host routes.
type RouteKey = (Ipv4Addr, u8, Ipv4Addr, u32);

fn route_key(r: &RouteEntry) -> RouteKey {
    (
        r.destination,
        r.prefix_length,
        r.next_hop,
        r.interface_index,
    )
}

/// What a route currently in the system table represents, from the
/// route-ownership coordinator's perspective (block 16.18.vpn).
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

/// Classify one route for ownership-based stripping (block 16.18.vpn).
///
/// `secondary_ifindex` is the VPN interface; `primary_gateway` is the real
/// (Ethernet) next-hop, used to recognise — and protect — the bootstrap host
/// route. Pure; no I/O. Only [`RouteOwnership::VpnRedirectOverlay`] is safe to
/// strip; every other variant must be left in place.
pub fn classify_route_ownership(
    route: &RouteEntry,
    secondary_ifindex: u32,
    primary_gateway: Option<Ipv4Addr>,
) -> RouteOwnership {
    if route.is_ours {
        return RouteOwnership::Ours;
    }
    // Bootstrap host route FIRST so it can never be mistaken for anything
    // strippable: a /32 reached via the primary gateway. Checked regardless of
    // interface — defence in depth, even if a client installs it unusually.
    if route.prefix_length == 32 {
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

/// the primary interface's
/// directly-connected IPv4 subnets, as `(network, prefix_len)`.
///
/// Derived from the on-link connected routes on `primary_ifindex` (next-hop
/// `0.0.0.0`, prefix `1..=31` — skips the default route and host routes). The
/// catch-all kill-switch permits these so DHCP renewal, the local
/// router/DNS, and LAN devices keep working while everything else off-tunnel
/// is blocked. Deduplicated, order preserved.
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
                && is_unicast_destination(r.destination)
        })
        .map(|r| (r.destination, r.prefix_length))
        .filter(|s| seen.insert(*s))
        .collect()
}

/// `false` for the destinations that are routing artefacts rather than
/// segments a host can live on.
fn is_unicast_destination(net: Ipv4Addr) -> bool {
    !net.is_multicast() && !net.is_broadcast() && !net.is_loopback() && !net.is_unspecified()
}

/// `true` for the RFC1918 ranges — the only ones a local virtual network may
/// claim. A hypervisor adapter carrying a public range is not a local segment
/// in any useful sense, and exempting it would be a hole, so it is left out.
fn is_private_v4(net: Ipv4Addr) -> bool {
    let o = net.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Directly-connected private subnets of the host's LOCAL virtual-machine
/// adapters (hypervisor host-only / NAT / bridged), excluding `exclude_ifindex`
/// — the additional route, whose own subnet must never be exempted.
///
/// These are segments that live inside this machine: traffic to them never
/// reaches a provider, so a kill-switch blocking them protects nothing and only
/// takes the user's virtual machines away. What it must NOT do is exempt a
/// tunnel that happens to use the same address space — see
/// [`nrr_platform_api::adapters::is_virtual_machine_adapter`].
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
        .flat_map(|info| primary_local_subnets(routes, info.index))
        .filter(|(net, _)| is_private_v4(*net))
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
    /// desired set).
    owned: Mutex<Vec<RouteEntry>>,
}

// `owned` is a `Mutex`; `lock().unwrap_or_else(into_inner)` recovers from a
// poisoned lock instead of unwrapping (workspace denies `unwrap_used`).
impl SecondaryRouteReconciler {
    pub fn new(api: Arc<dyn RouteTablePort>) -> Self {
        Self {
            api,
            owned: Mutex::new(Vec::new()),
        }
    }

    /// Seed the owned set without touching the route table. Used by the
    /// wiring layer's startup orphan-adoption (routes already present in
    /// the OS table that match our signature) so the next `reconcile`
    /// can delete the ones the new desired set no longer wants.
    pub fn adopt_owned(&self, routes: Vec<RouteEntry>) {
        let mut owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        *owned = routes;
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
            .iter()
            .any(|our| {
                our.destination == route.destination
                    && our.prefix_length == route.prefix_length
                    && our.interface_index == route.interface_index
            })
    }

    /// Number of routes currently owned.
    pub fn owned_count(&self) -> usize {
        self.owned.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Diff `desired` against the owned set and apply the difference. On
    /// success the owned set becomes exactly `desired`. On any platform
    /// error the partial changes are rolled back and the owned set is left
    /// unchanged.
    pub fn reconcile(&self, desired: &[RouteEntry]) -> Result<RouteReconcileDelta, PlatformError> {
        let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        self.reconcile_owned(desired, owned)
    }

    /// The body of [`Self::reconcile`], entered with the owned-set lock ALREADY
    /// held. Callers that derive `desired` FROM the owned set must hold the lock
    /// across both steps: releasing it in between lets a concurrent reconcile
    /// change what is owned, and the derived set then deletes routes it never
    /// looked at (see [`Self::retain_secondary_hosts`]).
    fn reconcile_owned(
        &self,
        desired: &[RouteEntry],
        mut owned: std::sync::MutexGuard<'_, Vec<RouteEntry>>,
    ) -> Result<RouteReconcileDelta, PlatformError> {
        let desired_keys: HashSet<RouteKey> = desired.iter().map(route_key).collect();
        let owned_keys: HashSet<RouteKey> = owned.iter().map(route_key).collect();

        let mut actions: Vec<RoutingAction> = Vec::new();
        // Delete owned routes the new desired set drops.
        let mut removed = 0usize;
        for r in owned.iter() {
            if !desired_keys.contains(&route_key(r)) {
                actions.push(RoutingAction::DeleteRoute(r.clone()));
                removed += 1;
            }
        }
        // Add newly-desired routes (AddRoute is idempotent on conflict, so
        // a route already in the table is harmless).
        let mut added = 0usize;
        for r in desired.iter() {
            if !owned_keys.contains(&route_key(r)) {
                actions.push(RoutingAction::AddRoute(r.clone()));
                added += 1;
            }
        }

        if actions.is_empty() {
            return Ok(RouteReconcileDelta::default());
        }

        let mut tx = RoutingTransaction::new(Arc::clone(&self.api));
        match tx.execute(&actions) {
            Ok(()) => {
                // Claim what we ACTUALLY added, plus what we already owned and
                // still want. A conflicting add reports success without adding
                // anything - the route belongs to somebody else, typically a
                // redirect VPN's own overlay - and claiming the whole desired
                // set would adopt it and delete it on a later pass, which is
                // exactly what destabilises the VPN client.
                let landed = tx.added_routes();
                tx.finalize();
                *owned = desired
                    .iter()
                    .filter(|d| {
                        landed.iter().any(|l| route_key(l) == route_key(d))
                            || owned.iter().any(|o| route_key(o) == route_key(d))
                    })
                    .cloned()
                    .collect();
                Ok(RouteReconcileDelta { added, removed })
            }
            Err(e) => {
                // Best-effort undo of the actions that landed before the
                // failure. What the table holds afterwards is not knowable from
                // here - the rollback is best-effort too - so we stop claiming
                // anything: the next reconcile re-derives the full desired set
                // and re-adds it (an add of a route that is already there is
                // idempotent). Keeping the old claim was worse: a route the
                // rollback did delete stayed listed as ours, the next diff saw
                // no work to do, and the rule silently stopped working until a
                // restart.
                let _ = tx.rollback();
                owned.clear();
                Err(e)
            }
        }
    }

    /// Tear down every owned route (active user logged off / service
    /// stopping). Equivalent to `reconcile(&[])`.
    pub fn clear(&self) -> Result<RouteReconcileDelta, PlatformError> {
        self.reconcile(&[])
    }

    /// graceful-stop "keep secondary" teardown: delete NRR's
    /// overlays (the mode-A `/2` counter-overlays and the mode-B `/1`
    /// split-default) but KEEP the secondary `/32` host routes, so rule-matched
    /// hosts keep egressing the secondary adapter after the service stops while general
    /// traffic returns to whatever the OS/VPN provides — the primary default
    /// for a gateway-less VPN, the VPN's own redirect for a full-tunnel one. No
    /// fabricated default, so a split / corp VPN is respected (its non-org
    /// traffic is not forced through the tunnel). Equivalent to
    /// `reconcile(owned.filter(|r| r.prefix_length == 32))`.
    pub fn retain_secondary_hosts(&self) -> Result<RouteReconcileDelta, PlatformError> {
        // One lock across derive AND apply: `keep` IS the owned set minus the
        // overlays, so a reconcile slipping in between would have its routes
        // deleted by a `desired` that predates them.
        let owned = self.owned.lock().unwrap_or_else(|p| p.into_inner());
        let keep: Vec<RouteEntry> = owned
            .iter()
            .filter(|r| r.prefix_length == 32)
            .cloned()
            .collect();
        self.reconcile_owned(&keep, owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::MockWindowsApi;

    fn route(d: [u8; 4], gw: [u8; 4], ifx: u32) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(d),
            prefix_length: 32,
            next_hop: Ipv4Addr::from(gw),
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
            .map(|r| r.destination)
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
        let taken = Ipv4Addr::new(1, 1, 1, 1);
        let api = Arc::new(ForeignRouteApi {
            inner: MockWindowsApi::new(),
            taken,
        });
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let desired = vec![
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
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

    #[test]
    fn first_reconcile_adds_all_desired() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let desired = vec![
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
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
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)])
        );
    }

    #[test]
    fn reconcile_is_idempotent_when_desired_unchanged() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let desired = vec![route([1, 1, 1, 1], [10, 0, 0, 1], 7)];
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
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
        ])
        .unwrap();
        // New desired: drop .2, keep .1, add .3.
        let delta = rec
            .reconcile(&[
                route([1, 1, 1, 1], [10, 0, 0, 1], 7),
                route([3, 3, 3, 3], [10, 0, 0, 1], 7),
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
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3)])
        );
    }

    #[test]
    fn changing_secondary_gateway_replaces_the_route() {
        // Same destination, different gateway/ifindex → delete old + add new.
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.reconcile(&[route([1, 1, 1, 1], [10, 0, 0, 1], 7)])
            .unwrap();
        let delta = rec
            .reconcile(&[route([1, 1, 1, 1], [192, 168, 0, 1], 9)])
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
            .find(|r| r.destination == Ipv4Addr::new(1, 1, 1, 1))
            .unwrap();
        assert_eq!(r.next_hop, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(r.interface_index, 9);
    }

    #[test]
    fn clear_removes_all_owned_routes() {
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        rec.reconcile(&[
            route([1, 1, 1, 1], [10, 0, 0, 1], 7),
            route([2, 2, 2, 2], [10, 0, 0, 1], 7),
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
        let orphan_a = route([1, 1, 1, 1], [10, 0, 0, 1], 7);
        let orphan_b = route([2, 2, 2, 2], [10, 0, 0, 1], 7);
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
            HashSet::from([Ipv4Addr::new(1, 1, 1, 1)])
        );
    }

    // ── route ownership classification (block 16.18.vpn, slice B) ──

    fn raw_route(d: [u8; 4], prefix: u8, gw: [u8; 4], ifx: u32, ours: bool) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(d),
            prefix_length: prefix,
            next_hop: Ipv4Addr::from(gw),
            interface_index: ifx,
            metric: 5,
            is_ours: ours,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    // ── Kill-switch exemptions (block 16.18.vpn D3) ─────────────────────────

    #[test]
    fn bootstrap_server_ips_collects_host_routes_via_primary_gateway() {
        let pg = [192, 168, 1, 1];
        let routes = vec![
            raw_route([203, 0, 113, 7], 32, pg, 12, false), // VPN server #1 (bootstrap)
            raw_route([198, 51, 100, 9], 32, pg, 12, false), // VPN server #2 (bootstrap)
            raw_route([203, 0, 113, 7], 32, pg, 12, false), // dup → deduped
            raw_route([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, false), // VPN redirect half (not a server)
            raw_route([23, 10, 20, 138], 32, [10, 91, 192, 1], 78, true), // our /32 (is_ours)
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
            classify_route_ownership(&r, 78, Some(Ipv4Addr::new(192, 168, 1, 1))),
            RouteOwnership::Ours
        );
    }

    #[test]
    fn classify_vpn_redirect_pair_on_secondary() {
        let pg = Some(Ipv4Addr::new(192, 168, 1, 1));
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
            classify_route_ownership(&r, 78, Some(Ipv4Addr::new(192, 168, 1, 1))),
            RouteOwnership::Untracked
        );
    }

    #[test]
    fn classify_bootstrap_host_route_via_primary_gateway_is_preserved() {
        // /32 to the VPN server via the Ethernet gateway → never strip.
        let pg = Ipv4Addr::new(192, 168, 1, 1);
        let boot = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, false);
        assert_eq!(
            classify_route_ownership(&boot, 78, Some(pg)),
            RouteOwnership::BootstrapHostRoute
        );
        // Defence in depth: even if it appeared on the secondary ifindex.
        let boot_on_sec = raw_route([203, 0, 113, 7], 32, [192, 168, 1, 1], 78, false);
        assert_eq!(
            classify_route_ownership(&boot_on_sec, 78, Some(pg)),
            RouteOwnership::BootstrapHostRoute
        );
    }

    #[test]
    fn classify_os_default_and_unrelated_are_untracked() {
        let pg = Some(Ipv4Addr::new(192, 168, 1, 1));
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
    fn retain_secondary_hosts_keeps_slash32_drops_overlays() {
        // graceful stop keeps the /32 rule-routes and
        // drops NRR's /2 counter-overlay and /1 split-default, so rule-matched
        // hosts keep egressing the secondary adapter while general traffic returns to the OS
        // default.
        let api = Arc::new(MockWindowsApi::new());
        let rec = SecondaryRouteReconciler::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let host_a = route([8, 8, 8, 8], [10, 0, 0, 1], 14);
        let host_b = route([1, 1, 1, 1], [10, 0, 0, 1], 14);
        let counter_overlay = raw_route([64, 0, 0, 0], 2, [192, 168, 0, 1], 16, true);
        let split_default = raw_route([0, 0, 0, 0], 1, [10, 0, 0, 1], 14, true);
        rec.reconcile(&[host_a, host_b, counter_overlay, split_default])
            .unwrap();
        assert_eq!(rec.owned_count(), 4);

        let delta = rec.retain_secondary_hosts().unwrap();
        assert_eq!(
            delta.removed, 2,
            "both overlays removed (the /2 and the /1)"
        );
        assert_eq!(delta.added, 0);
        assert_eq!(rec.owned_count(), 2, "only the two /32 host routes remain");
        let dests = table_dests(&api);
        assert!(dests.contains(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(dests.contains(&Ipv4Addr::new(1, 1, 1, 1)));
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
