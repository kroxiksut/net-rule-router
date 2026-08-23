//! Putting the planned ROUTES into the system table.
//!
//! Packet filters decide what may leave; routes decide where it leaves through.
//! Enforcing only the first half is worse than enforcing neither: a rule that
//! says "this host goes over the tunnel" lowers to a filter that permits the
//! host on the tunnel and drops it elsewhere, so without the matching route the
//! traffic follows the default path, meets that drop, and the user sees the site
//! go dark. That was the state of the Linux path until this landed.
//!
//! Everything here is OS-neutral: the reconciler works through
//! [`RouteTablePort`], and an egress target is an interface index plus an
//! optional gateway on every platform this product targets.

use std::net::Ipv4Addr;
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
}
