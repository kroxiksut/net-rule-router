//! Putting the planned ROUTES into the system table.
//!
//! Packet filters decide what may leave; routes decide where it leaves through.
//! Enforcing only the first half is worse than enforcing neither: a rule that
//! says "this host goes over the tunnel" lowers to a filter that permits the
//! host on the tunnel and drops it elsewhere, so without the matching route the
//! traffic follows the default path, meets that drop, and the user sees the site
//! go dark.
//!
//! Everything here is OS-neutral: the reconciler works through
//! [`RouteTablePort`], and an egress target is an interface index plus an
//! optional gateway on every platform this product targets.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterEventSource, AdapterInfo, IfOperStatus};
use nrr_platform_api::enforcement::{EgressBindingSource, EnforcementPlan};
use nrr_platform_api::route_lowering::{lower_routes, RouteTarget};
use nrr_platform_api::route_table::RouteTablePort;

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

/// Installs the routes a set of plans asks for, and removes the ones we own that
/// they no longer ask for.
pub struct PlannedRouteApplier {
    reconciler: SecondaryRouteReconciler,
    adapters: Arc<dyn AdapterEventSource>,
    bindings: Arc<dyn EgressBindingSource>,
    /// Whether a previous run's routes have been taken over yet.
    leftovers_adopted: AtomicBool,
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
        }
    }

    /// Take over the routes a previous run left in the table, once, before
    /// the first reconcile. Without it a crash strands them: a wanted route's
    /// add conflicts and is never claimed, an unwanted one is never deleted.
    /// An unreadable table is retried on the next pass.
    fn adopt_leftovers(&self) {
        if self.leftovers_adopted.load(Ordering::Acquire) {
            return;
        }
        match self.reconciler.adopt_signed_routes() {
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

    /// Reconcile the system route table against every plan's intents.
    ///
    /// One snapshot of the interfaces for the whole pass: two users resolved
    /// against two different readings of the machine would produce a table that
    /// never matched either of them.
    pub fn apply(&self, plans: &[EnforcementPlan]) -> Result<RouteApplyReport, String> {
        let adapters = self
            .adapters
            .enumerate_all()
            .map_err(|e| format!("adapters could not be read: {e}"))?;

        self.adopt_leftovers();
        let mut desired = Vec::new();
        let mut unresolved = Vec::new();
        for plan in plans {
            let binding = self.bindings.bindings_for(&plan.principal);
            let secondary = binding
                .secondary
                .as_deref()
                .and_then(|name| target_for(&adapters, name));
            let primary = binding
                .primary
                .as_deref()
                .and_then(|name| target_for(&adapters, name));

            // No live secondary means every intent that names it is unroutable.
            // Installing the primary half alone would leave the policy half-
            // applied while looking installed.
            let Some(secondary) = secondary else {
                if !plan.routes.is_empty() {
                    unresolved.push(plan.principal.as_stored().to_owned());
                }
                continue;
            };
            desired.extend(lower_routes(plan, secondary, primary));
        }

        let delta = self
            .reconciler
            .reconcile(&desired)
            .map_err(|e| format!("route table could not be reconciled: {e}"))?;

        Ok(RouteApplyReport {
            added: delta.added,
            removed: delta.removed,
            unresolved,
            failure: None,
        })
    }

    /// Drop every route this product owns — used when policy stops applying, so
    /// stopping the service restores the machine's own routing.
    pub fn clear(&self) -> Result<RouteApplyReport, String> {
        self.adopt_leftovers();
        let delta = self
            .reconciler
            .clear()
            .map_err(|e| format!("owned routes could not be removed: {e}"))?;
        Ok(RouteApplyReport {
            added: delta.added,
            removed: delta.removed,
            unresolved: Vec::new(),
            failure: None,
        })
    }
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
}
