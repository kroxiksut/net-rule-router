//! Putting the planned ROUTES into the system tables.
//!
//! Packet filters decide what may leave; routes decide where it leaves through.
//! Enforcing only the first half is worse than enforcing neither: a rule that
//! says "this host goes over the tunnel" lowers to a filter that permits the
//! host on the tunnel and drops it elsewhere, so without the matching route the
//! traffic follows the default path, meets that drop, and the user sees the site
//! go dark.
//!
//! Where the platform routes per user ([`PrincipalRoutingPort`]), each present
//! user's routes go to a table of their own, and the route-table owner's also
//! to the table the service accounts look up: nothing one user's rules ask for
//! reaches another user's traffic. Elsewhere one table serves everybody, so it
//! carries the owner's routes alone.
//!
//! Everything here is OS-neutral: the reconciler works through
//! [`RouteTablePort`], and an egress target is an interface index plus an
//! optional gateway on every platform this product targets.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterEventSource, AdapterInfo, IfOperStatus};
use nrr_platform_api::enforcement::{
    EgressBindingSource, EnforcementPlan, RouteTableRef, UserPrincipal,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::route_lowering::{lower_routes, RouteTarget};
use nrr_platform_api::route_table::{
    PrincipalRoutingPort, RouteTablePort, SelectorPlan, TableSelector,
};
use nrr_platform_api::RouteEntry;

use crate::route_reconciler::SecondaryRouteReconciler;

/// What one route pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteApplyReport {
    pub added: usize,
    pub removed: usize,
    /// Plans whose egress could not be resolved to a live interface, so their
    /// routes were not installed. Named rather than counted: the user needs to
    /// know WHOSE traffic is not being steered.
    pub unresolved: Vec<String>,
    /// Why the pass could not run at all. Carried in the report rather than
    /// returned as an error, so a route failure is visible beside a successful
    /// filter apply instead of collapsing the whole pass into a failure.
    pub failure: Option<String>,
}

/// Who one route pass is for.
#[derive(Clone, Copy, Debug)]
pub struct RoutePass<'a> {
    pub plans: &'a [EnforcementPlan],
    /// Everyone present, planned or not: each is selected into a table of
    /// their own, so nobody falls into the service accounts' one.
    pub present: &'a [UserPrincipal],
    /// Whose routes the service accounts follow.
    pub owner: Option<&'a UserPrincipal>,
}

/// Installs the routes a set of plans asks for, and removes the ones we own that
/// they no longer ask for.
pub struct PlannedRouteApplier {
    reconciler: SecondaryRouteReconciler,
    adapters: Arc<dyn AdapterEventSource>,
    bindings: Arc<dyn EgressBindingSource>,
    /// Whether a previous run's routes have been taken over yet.
    leftovers_adopted: AtomicBool,
    /// Per-user tables. `None`: one table for everybody.
    principal_routing: Option<Arc<dyn PrincipalRoutingPort>>,
    /// Latched once the kernel refuses to select by user.
    principal_routing_refused: AtomicBool,
}

impl PlannedRouteApplier {
    pub fn new(
        api: Arc<dyn RouteTablePort>,
        adapters: Arc<dyn AdapterEventSource>,
        bindings: Arc<dyn EgressBindingSource>,
    ) -> Self {
        Self {
            reconciler: SecondaryRouteReconciler::new(api),
            adapters,
            bindings,
            leftovers_adopted: AtomicBool::new(false),
            principal_routing: None,
            principal_routing_refused: AtomicBool::new(false),
        }
    }

    /// Route each present user through a table of their own.
    #[must_use]
    pub fn with_principal_routing(mut self, port: Arc<dyn PrincipalRoutingPort>) -> Self {
        self.principal_routing = Some(port);
        self
    }

    /// Take over the routes a previous run left in the tables, once, before
    /// the first reconcile. Without it a crash strands them: a wanted route's
    /// add conflicts and is never claimed, an unwanted one is never deleted.
    /// An unreadable table is retried on the next pass.
    fn adopt_leftovers(&self) {
        if self.leftovers_adopted.load(Ordering::Acquire) {
            return;
        }
        let port = self.principal_routing.as_deref();
        let in_our_table = |r: &RouteEntry| port.is_some_and(|p| p.is_principal_table(&r.table));
        match self.reconciler.adopt_signed_routes_with(&in_our_table) {
            Ok(count) => {
                self.leftovers_adopted.store(true, Ordering::Release);
                if count > 0 {
                    tracing::info!(
                        target: "nrr::routes",
                        msg_key = "route-orphans-adopted",
                        count,
                        "adopted routes a previous run left in the table",
                    );
                }
            }
            Err(e) => tracing::warn!(
                target: "nrr::routes",
                msg_key = "route-orphan-enum-failed",
                error = %e,
                "route table unreadable: a previous run's routes are adopted on a later pass",
            ),
        }
    }

    /// Reconcile the system route table against every plan's intents, each in
    /// the table the intent names.
    ///
    /// One snapshot of the interfaces for the whole pass: two users resolved
    /// against two different readings of the machine would produce a table that
    /// never matched either of them.
    pub fn apply(&self, plans: &[EnforcementPlan]) -> Result<RouteApplyReport, String> {
        let adapters = self.read_adapters()?;
        self.adopt_leftovers();
        let mut desired = Vec::new();
        let mut unresolved = Vec::new();
        for plan in plans {
            desired.extend(self.lowered(plan, &adapters, &mut unresolved));
        }
        self.reconcile(&desired, unresolved)
    }

    /// One pass: every present user's routes in their own table, the owner's
    /// also in the service accounts' one. Without per-user routing, or on a
    /// kernel that refuses it, the owner's routes alone go to the one table.
    pub fn apply_pass(&self, pass: RoutePass<'_>) -> Result<RouteApplyReport, String> {
        let port = self
            .principal_routing
            .as_deref()
            .filter(|_| !self.principal_routing_refused.load(Ordering::Acquire));
        let Some(port) = port else {
            let owned = pass
                .owner
                .and_then(|o| pass.plans.iter().position(|p| &p.principal == o))
                .map_or(0..0, |i| i..i + 1);
            return self.apply(&pass.plans[owned]);
        };

        let adapters = self.read_adapters()?;
        self.adopt_leftovers();
        let mut desired = Vec::new();
        let mut unresolved = Vec::new();
        let mut selectors = SelectorPlan::default();
        let mut system = TableSelector::default();
        for principal in pass.present {
            let routes = pass
                .plans
                .iter()
                .find(|p| &p.principal == principal)
                .map(|plan| self.lowered(plan, &adapters, &mut unresolved))
                .unwrap_or_default();
            let selector = TableSelector {
                overlay_prefix_v4: overlay_prefix(&routes),
            };
            match port.table_for(principal) {
                Some(table) => {
                    desired.extend(in_table(&routes, &table));
                    selectors.users.push((principal.clone(), selector));
                }
                None if !routes.is_empty() => unresolved.push(principal.as_stored().to_owned()),
                None => {}
            }
            if pass.owner == Some(principal) {
                desired.extend(in_table(&routes, &port.system_table()));
                system = selector;
            }
        }
        selectors.system = (!pass.present.is_empty()).then_some(system);

        // Selectors first: a refusal turns this pass into the one-table one
        // before anything lands in a per-user table.
        let selected = match port.reconcile_selectors(&selectors) {
            Err(PlatformError::NotSupported { reason }) => {
                self.principal_routing_refused
                    .store(true, Ordering::Release);
                tracing::warn!(
                    target: "nrr::routes",
                    msg_key = "per-user-routing-unsupported",
                    reason,
                    "this kernel cannot route each user separately: the system route table carries one signed-in user's routes for everyone",
                );
                return self.apply_pass(pass);
            }
            Err(e) => Some(format!("per-user routing could not be selected: {e}")),
            Ok(delta) => {
                if delta.added > 0 || delta.removed > 0 {
                    tracing::debug!(
                        target: "nrr::routes",
                        added = delta.added,
                        removed = delta.removed,
                        "per-user routing selectors updated",
                    );
                }
                None
            }
        };
        let mut report = self.reconcile(&desired, unresolved)?;
        report.failure = selected;
        Ok(report)
    }

    fn read_adapters(&self) -> Result<Vec<AdapterInfo>, String> {
        self.adapters
            .enumerate_all()
            .map_err(|e| format!("adapters could not be read: {e}"))
    }

    /// One plan's routes against the live links. No live secondary means
    /// every intent that names it is unroutable: installing the primary half
    /// alone would leave the policy half-applied while looking installed.
    fn lowered(
        &self,
        plan: &EnforcementPlan,
        adapters: &[AdapterInfo],
        unresolved: &mut Vec<String>,
    ) -> Vec<RouteEntry> {
        let binding = self.bindings.bindings_for(&plan.principal);
        let secondary = binding
            .secondary
            .as_deref()
            .and_then(|name| target_for(adapters, name));
        let primary = binding
            .primary
            .as_deref()
            .and_then(|name| target_for(adapters, name));
        let Some(secondary) = secondary else {
            if !plan.routes.is_empty() {
                unresolved.push(plan.principal.as_stored().to_owned());
            }
            return Vec::new();
        };
        lower_routes(plan, secondary, primary)
    }

    fn reconcile(
        &self,
        desired: &[RouteEntry],
        unresolved: Vec<String>,
    ) -> Result<RouteApplyReport, String> {
        let delta = self
            .reconciler
            .reconcile(desired)
            .map_err(|e| format!("route table could not be reconciled: {e}"))?;
        Ok(RouteApplyReport {
            added: delta.added,
            removed: delta.removed,
            unresolved,
            failure: None,
        })
    }

    /// Drop every route and selector this product owns — used when policy
    /// stops applying, so stopping the service restores the machine's own
    /// routing. Selectors go first: without them our tables are inert.
    pub fn clear(&self) -> Result<RouteApplyReport, String> {
        self.adopt_leftovers();
        let selectors = match self.principal_routing.as_deref() {
            Some(port) => port
                .clear_selectors()
                .map(|_| ())
                .map_err(|e| format!("per-user routing selectors could not be removed: {e}")),
            None => Ok(()),
        };
        let delta = self
            .reconciler
            .clear()
            .map_err(|e| format!("owned routes could not be removed: {e}"))?;
        selectors?;
        Ok(RouteApplyReport {
            added: delta.added,
            removed: delta.removed,
            unresolved: Vec::new(),
            failure: None,
        })
    }
}

/// The longest overlay half among `routes`: what the selectors in front of
/// their table must let the main table's more specific routes beat.
fn overlay_prefix(routes: &[RouteEntry]) -> Option<u8> {
    routes
        .iter()
        .filter(|r| crate::route_codegen::is_overlay_route(r))
        .map(|r| r.prefix_length)
        .max()
}

fn in_table<'a>(
    routes: &'a [RouteEntry],
    table: &'a RouteTableRef,
) -> impl Iterator<Item = RouteEntry> + 'a {
    routes.iter().map(move |r| RouteEntry {
        table: table.clone(),
        ..r.clone()
    })
}

/// Resolve a saved binding name to the interface it names right now.
///
/// The gateway is optional by design: a tunnel is usually point-to-point and has
/// none, and a route through such a link is addressed by interface alone.
/// Refusing those would leave exactly the VPN case unroutable.
fn target_for(adapters: &[AdapterInfo], name: &str) -> Option<RouteTarget> {
    let adapter = adapters.iter().find(|a| {
        (a.friendly_name == name || a.adapter_name == name) && a.oper_status == IfOperStatus::Up
    })?;
    // Index 0 means "unspecified" — a route installed against it would go
    // somewhere nobody chose.
    if adapter.index == 0 {
        return None;
    }
    Some(RouteTarget {
        gateway: adapter
            .gateways
            .first()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED),
        // No v6 gateway is modelled on an adapter yet, and a tunnel commonly
        // carries no v6 address at all — so a v6 route out of this egress is
        // on-link, addressed by interface alone. The same shape the
        // gateway-less v4 tunnel already uses.
        gateway_v6: Ipv6Addr::UNSPECIFIED,
        interface_index: adapter.index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::InterfaceType;

    fn adapter(name: &str, index: u32, up: bool, gw: Option<Ipv4Addr>) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.to_owned(),
            description: String::new(),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: if up {
                IfOperStatus::Up
            } else {
                IfOperStatus::Down
            },
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            gateways: gw.into_iter().collect(),
        }
    }

    /// A tunnel with no gateway must still be routable: point-to-point links are
    /// the normal case for the very feature this product exists for.
    #[test]
    fn a_gatewayless_link_resolves_to_an_interface_route() {
        let adapters = vec![adapter("tun0", 7, true, None)];
        let target = target_for(&adapters, "tun0").expect("a live link must resolve");
        assert_eq!(target.interface_index, 7);
        assert_eq!(target.gateway, Ipv4Addr::UNSPECIFIED);
    }

    /// A link that is down resolves to nothing — installing a route through it
    /// would black-hole the traffic it was meant to carry.
    #[test]
    fn a_down_link_does_not_resolve() {
        let adapters = vec![adapter("tun0", 7, false, None)];
        assert!(target_for(&adapters, "tun0").is_none());
    }

    /// Index 0 is "unspecified". A route against it goes somewhere nobody chose.
    #[test]
    fn an_unspecified_index_is_refused() {
        let adapters = vec![adapter("tun0", 0, true, None)];
        assert!(target_for(&adapters, "tun0").is_none());
    }

    struct Bound;
    impl EgressBindingSource for Bound {
        fn bindings_for(
            &self,
            _: &nrr_platform_api::enforcement::UserPrincipal,
        ) -> nrr_platform_api::enforcement::EgressBinding {
            nrr_platform_api::enforcement::EgressBinding {
                primary: Some("eth0".into()),
                secondary: Some("tun0".into()),
            }
        }
    }

    fn row(
        dst: [u8; 4],
        prefix: u8,
        metric: u32,
        table: nrr_platform_api::RouteTableRef,
    ) -> nrr_platform_api::RouteEntry {
        nrr_platform_api::RouteEntry {
            destination: std::net::IpAddr::V4(Ipv4Addr::from(dst)),
            prefix_length: prefix,
            next_hop: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface_index: 7,
            metric,
            is_ours: false,
            table,
        }
    }

    /// After a crash the table still holds our routes and no process owns
    /// them. The first pass takes back what is no longer wanted and keeps the
    /// rest — recognised by metric, shape and table, never by shape alone.
    #[test]
    fn the_first_pass_takes_over_what_a_previous_run_left() {
        use nrr_platform_api::enforcement::{DstMatch, EgressRef, RouteIntent};
        use nrr_platform_api::RouteTableRef;

        let main = || RouteTableRef::Main;
        let network = crate::route_codegen::NETWORK_ROUTE_METRIC;
        let host = crate::route_codegen::SECONDARY_ROUTE_METRIC;
        let wanted = row([198, 51, 100, 0], 24, network, main());
        let foreign = vec![
            row([10, 30, 0, 0], 16, 100, main()),
            // A wide shape at the network metric is not a rule's route.
            row([128, 0, 0, 0], 1, network, main()),
            row([10, 40, 0, 0], 16, network, RouteTableRef::Tagged(51820)),
        ];
        let api = Arc::new(nrr_platform_api::MockWindowsApi::new());
        let mut table = vec![
            wanted.clone(),
            row([10, 20, 0, 0], 16, network, main()),
            row([0, 0, 0, 0], 1, host, main()),
        ];
        table.extend(foreign.iter().cloned());
        api.set_route_table(table);
        let adapters = Arc::new(nrr_platform_api::adapters::MockAdapterEventSource::new());
        *adapters.adapters.lock().unwrap_or_else(|p| p.into_inner()) = vec![
            adapter("eth0", 2, true, Some(Ipv4Addr::new(192, 168, 1, 1))),
            adapter("tun0", 7, true, None),
        ];
        let applier = PlannedRouteApplier::new(
            Arc::clone(&api) as Arc<dyn RouteTablePort>,
            adapters as Arc<dyn AdapterEventSource>,
            Arc::new(Bound),
        );
        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(1000),
            flows: Vec::new(),
            routes: vec![RouteIntent {
                dst: DstMatch::SubnetV4 {
                    net: Ipv4Addr::new(198, 51, 100, 0),
                    prefix: 24,
                },
                egress: EgressRef::Secondary,
                metric: network,
                table: RouteTableRef::Main,
            }],
            policy_rules: Vec::new(),
        };

        let report = applier.apply(&[plan]).expect("apply");

        assert_eq!((report.added, report.removed), (0, 2));
        let mut want = vec![wanted];
        want.extend(foreign);
        let left = api.get_ip_forward_table().expect("table");
        assert_eq!(left.len(), want.len(), "{left:?}");
        assert!(want.iter().all(|w| left.contains(w)), "{left:?}");
    }

    mod per_user {
        use super::*;
        use nrr_platform_api::enforcement::{DstMatch, EgressRef, RouteIntent, UserPrincipal};
        use nrr_platform_api::route_table::SelectorDelta;
        use std::net::IpAddr;
        use std::sync::Mutex;

        const SHARED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
        const ETH: u32 = 2;
        const TUN: u32 = 7;
        const SYSTEM: u32 = 9_999;

        /// A route table that, like the kernel, tells tables apart.
        #[derive(Default)]
        struct Tables(Mutex<Vec<RouteEntry>>);

        impl Tables {
            fn rows(&self) -> Vec<RouteEntry> {
                self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
            }

            fn links_of(&self, table: RouteTableRef) -> Vec<u32> {
                self.rows()
                    .into_iter()
                    .filter(|r| r.table == table && r.destination == IpAddr::V4(SHARED))
                    .map(|r| r.interface_index)
                    .collect()
            }
        }

        impl RouteTablePort for Tables {
            fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
                Ok(self.rows())
            }
            fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
                self.0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(entry.clone());
                Ok(())
            }
            fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
                self.0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .retain(|r| {
                        !(r.destination == entry.destination
                            && r.prefix_length == entry.prefix_length
                            && r.interface_index == entry.interface_index
                            && r.table == entry.table)
                    });
                Ok(())
            }
            fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
                Ok(Vec::new())
            }
            fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
                Ok(u64::from(ifindex))
            }
        }

        /// Records what it was asked to select; refuses like an old kernel
        /// when told to.
        #[derive(Default)]
        struct Selectors {
            last: Mutex<Option<SelectorPlan>>,
            calls: Mutex<usize>,
            cleared: Mutex<usize>,
            old_kernel: bool,
        }

        impl PrincipalRoutingPort for Selectors {
            fn table_for(&self, principal: &UserPrincipal) -> Option<RouteTableRef> {
                principal
                    .as_unix_uid()
                    .map(|uid| RouteTableRef::Tagged(10_000 + uid))
            }
            fn system_table(&self) -> RouteTableRef {
                RouteTableRef::Tagged(SYSTEM)
            }
            fn is_principal_table(&self, table: &RouteTableRef) -> bool {
                matches!(table, RouteTableRef::Tagged(n) if (SYSTEM..20_000).contains(n))
            }
            fn reconcile_selectors(
                &self,
                plan: &SelectorPlan,
            ) -> Result<SelectorDelta, PlatformError> {
                *self.calls.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                if self.old_kernel {
                    return Err(PlatformError::NotSupported {
                        reason: "old kernel",
                    });
                }
                *self.last.lock().unwrap_or_else(|p| p.into_inner()) = Some(plan.clone());
                Ok(SelectorDelta::default())
            }
            fn clear_selectors(&self) -> Result<usize, PlatformError> {
                *self.cleared.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                Ok(0)
            }
        }

        fn table_of(uid: u32) -> RouteTableRef {
            RouteTableRef::Tagged(10_000 + uid)
        }

        fn intent(dst: DstMatch, egress: EgressRef) -> RouteIntent {
            RouteIntent {
                dst,
                egress,
                metric: crate::route_codegen::SECONDARY_ROUTE_METRIC,
                table: RouteTableRef::Main,
            }
        }

        /// uid 1000 tunnels the shared host, uid 1001 keeps it on the main
        /// link: one address, two answers.
        fn plan(uid: u32) -> EnforcementPlan {
            let egress = if uid == 1000 {
                EgressRef::Secondary
            } else {
                EgressRef::Primary
            };
            EnforcementPlan {
                principal: UserPrincipal::from_linux_uid(uid),
                flows: Vec::new(),
                routes: vec![intent(DstMatch::HostV4(SHARED), egress)],
                policy_rules: Vec::new(),
            }
        }

        fn rig(old_kernel: bool) -> (PlannedRouteApplier, Arc<Tables>, Arc<Selectors>) {
            let tables = Arc::new(Tables::default());
            let selectors = Arc::new(Selectors {
                old_kernel,
                ..Selectors::default()
            });
            let adapters = Arc::new(nrr_platform_api::adapters::MockAdapterEventSource::new());
            *adapters.adapters.lock().unwrap_or_else(|p| p.into_inner()) = vec![
                adapter("eth0", ETH, true, Some(Ipv4Addr::new(192, 0, 2, 1))),
                adapter("tun0", TUN, true, None),
            ];
            let applier = PlannedRouteApplier::new(
                Arc::clone(&tables) as Arc<dyn RouteTablePort>,
                adapters as Arc<dyn AdapterEventSource>,
                Arc::new(Bound),
            )
            .with_principal_routing(Arc::clone(&selectors) as Arc<dyn PrincipalRoutingPort>);
            (applier, tables, selectors)
        }

        fn users(uids: &[u32]) -> Vec<UserPrincipal> {
            uids.iter()
                .map(|u| UserPrincipal::from_linux_uid(*u))
                .collect()
        }

        fn pass<'a>(
            plans: &'a [EnforcementPlan],
            present: &'a [UserPrincipal],
            owner: usize,
        ) -> RoutePass<'a> {
            RoutePass {
                plans,
                present,
                owner: present.get(owner),
            }
        }

        #[test]
        fn two_users_route_one_address_their_own_ways() {
            let (applier, tables, selectors) = rig(false);
            let plans = [plan(1000), plan(1001)];
            let present = users(&[1000, 1001]);

            let report = applier.apply_pass(pass(&plans, &present, 0)).expect("pass");

            assert_eq!(report.failure, None);
            assert_eq!(tables.links_of(table_of(1000)), vec![TUN]);
            assert_eq!(tables.links_of(table_of(1001)), vec![ETH]);
            assert_eq!(tables.links_of(RouteTableRef::Tagged(SYSTEM)), vec![TUN]);
            assert!(
                tables.links_of(RouteTableRef::Main).is_empty(),
                "nobody's routes in the shared table"
            );
            let selected = selectors.last.lock().expect("lock").clone().expect("asked");
            assert_eq!(selected.users.len(), 2);
            assert!(selected.system.is_some());
        }

        #[test]
        fn a_user_leaving_takes_only_their_own_routes() {
            let (applier, tables, selectors) = rig(false);
            let plans = [plan(1000), plan(1001)];
            let both = users(&[1000, 1001]);
            applier.apply_pass(pass(&plans, &both, 0)).expect("pass");

            let one = users(&[1001]);
            applier
                .apply_pass(pass(&plans[1..], &one, 0))
                .expect("pass");

            assert!(tables.links_of(table_of(1000)).is_empty());
            assert_eq!(tables.links_of(table_of(1001)), vec![ETH]);
            assert_eq!(
                tables.links_of(RouteTableRef::Tagged(SYSTEM)),
                vec![ETH],
                "the service accounts follow the new owner"
            );
            let selected = selectors.last.lock().expect("lock").clone().expect("asked");
            assert_eq!(selected.users.len(), 1);
            assert_eq!(selected.users[0].0, UserPrincipal::from_linux_uid(1001));
        }

        /// A present user with no plan is still selected, so their traffic
        /// never falls into the service accounts' table.
        #[test]
        fn a_present_user_without_a_plan_is_still_selected() {
            let (applier, tables, selectors) = rig(false);
            let plans = [plan(1000)];
            let present = users(&[1000, 0]);
            applier.apply_pass(pass(&plans, &present, 0)).expect("pass");

            let selected = selectors.last.lock().expect("lock").clone().expect("asked");
            assert_eq!(selected.users.len(), 2);
            assert!(tables.links_of(table_of(0)).is_empty());
        }

        /// The previous version kept the owner's routes in the main table, and
        /// a crash can leave a departed user's table behind: the first pass
        /// takes both back and leaves everyone else's routes alone.
        #[test]
        fn the_first_pass_takes_back_main_table_and_stale_table_leftovers() {
            let (applier, tables, _) = rig(false);
            let host = crate::route_codegen::SECONDARY_ROUTE_METRIC;
            let foreign = row([10, 40, 0, 0], 16, 100, RouteTableRef::Tagged(51_820));
            tables.0.lock().expect("lock").extend([
                row([198, 51, 100, 9], 32, host, RouteTableRef::Main),
                row([198, 51, 100, 9], 32, host, table_of(2000)),
                foreign.clone(),
            ]);
            let plans = [plan(1000)];
            let present = users(&[1000]);

            applier.apply_pass(pass(&plans, &present, 0)).expect("pass");

            let rows = tables.rows();
            assert!(rows.contains(&foreign));
            assert!(rows
                .iter()
                .all(|r| r.destination != IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))));
            assert_eq!(tables.links_of(table_of(1000)), vec![TUN]);
        }

        /// A mode-B plan's overlays travel to the selectors as their length,
        /// so the main table's LAN still beats them.
        #[test]
        fn an_overlay_s_length_reaches_the_selectors() {
            let (applier, _, selectors) = rig(false);
            let mut owner = plan(1000);
            owner.routes.push(intent(
                DstMatch::SubnetV4 {
                    net: Ipv4Addr::UNSPECIFIED,
                    prefix: 1,
                },
                EgressRef::Secondary,
            ));
            let plans = [owner, plan(1001)];
            let present = users(&[1000, 1001]);
            applier.apply_pass(pass(&plans, &present, 0)).expect("pass");

            let selected = selectors.last.lock().expect("lock").clone().expect("asked");
            assert_eq!(selected.users[0].1.overlay_prefix_v4, Some(1));
            assert_eq!(selected.users[1].1.overlay_prefix_v4, None);
            assert_eq!(selected.system.and_then(|s| s.overlay_prefix_v4), Some(1));
        }

        /// A kernel that cannot select by user gets today's behaviour: the
        /// owner's routes in the main table, and it is asked only once.
        #[test]
        fn an_old_kernel_falls_back_to_the_owner_s_routes_in_main() {
            let (applier, tables, selectors) = rig(true);
            let plans = [plan(1000), plan(1001)];
            let present = users(&[1000, 1001]);

            applier.apply_pass(pass(&plans, &present, 1)).expect("pass");
            applier.apply_pass(pass(&plans, &present, 1)).expect("pass");

            assert_eq!(tables.links_of(RouteTableRef::Main), vec![ETH]);
            assert!(tables.links_of(table_of(1000)).is_empty());
            assert!(tables.links_of(table_of(1001)).is_empty());
            assert_eq!(*selectors.calls.lock().expect("lock"), 1);
        }

        #[test]
        fn clearing_removes_selectors_and_every_table_s_routes() {
            let (applier, tables, selectors) = rig(false);
            let plans = [plan(1000), plan(1001)];
            let present = users(&[1000, 1001]);
            applier.apply_pass(pass(&plans, &present, 0)).expect("pass");

            applier.clear().expect("clear");

            assert_eq!(*selectors.cleared.lock().expect("lock"), 1);
            assert!(tables.rows().is_empty(), "{:?}", tables.rows());
        }

        #[test]
        fn nobody_present_selects_nobody() {
            let (applier, tables, selectors) = rig(false);
            applier.apply_pass(pass(&[], &[], 0)).expect("pass");
            let selected = selectors.last.lock().expect("lock").clone().expect("asked");
            assert!(selected.users.is_empty());
            assert!(selected.system.is_none());
            assert!(tables.rows().is_empty());
        }
    }
}
