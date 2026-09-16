//! Neutral lowering of route INTENTS into system route-table entries.
//!
//! Lived in the Windows lowering until Linux needed the same step. Nothing about
//! it was ever Windows-specific: a route entry names a destination, an interface
//! and (sometimes) a gateway on every OS this product targets, and the mechanism
//! that installs it sits behind [`crate::route_table::RouteTablePort`].
//!
//! Routes are the ROUTING mechanism; packet filters are the blocking one. They
//! are lowered and applied separately on purpose — they fail differently, and a
//! single combined report would hide a half-applied policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::enforcement::{DstMatch, EgressRef, EnforcementPlan};
use crate::types::RouteEntry;

/// A resolved egress target for route lowering — the concrete gateway + interface
/// index an [`EgressRef`] maps to. This is the route analog of the kill-switch
/// LUID: a lowering-time, per-OS binding the neutral plan never carries.
#[derive(Clone, Copy, Debug)]
pub struct RouteTarget {
    pub gateway: Ipv4Addr,
    /// The IPv6 next hop out of this egress. `UNSPECIFIED` means on-link —
    /// the same spelling v4 already uses for a gateway-less tunnel, and the
    /// only spelling available on a tunnel that carries no v6 address at all.
    pub gateway_v6: Ipv6Addr,
    pub interface_index: u32,
}

/// Lower the [`RouteIntent`](nrr_platform_api::enforcement::RouteIntent)s of `plan`
/// into system route-table [`RouteEntry`]s — the Windows half of
/// `route_codegen::generate_routes` (the routing mechanism; WFP is the blocking
/// one). Each intent's [`EgressRef`] is resolved to its [`RouteTarget`]
/// (`Secondary` → `secondary`, `Primary` → `primary` — skipped if the caller has
/// no primary target, matching the codegen's `PrimaryExceptionsUnavailable`), and
/// its [`DstMatch`] to `(destination, prefix_length)` (`HostV4` → `/32`,
/// `HostV6` → `/128`, the subnet variants → the overlay prefix). `is_ours = true`
/// and `metric` come straight from the intent; only the `Main` table is produced
/// on Windows. Each family takes its own next hop from the target, so a v6
/// destination is never handed a v4 gateway.
pub fn lower_routes(
    plan: &EnforcementPlan,
    secondary: RouteTarget,
    primary: Option<RouteTarget>,
) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for intent in &plan.routes {
        let target = match intent.egress {
            EgressRef::Secondary => secondary,
            EgressRef::Primary => match primary {
                Some(p) => p,
                None => continue,
            },
            EgressRef::Adapter(_) => continue,
        };
        let (destination, prefix_length, next_hop) = match intent.dst {
            DstMatch::HostV4(ip) => (IpAddr::V4(ip), 32u8, IpAddr::V4(target.gateway)),
            DstMatch::SubnetV4 { net, prefix } => {
                (IpAddr::V4(net), prefix, IpAddr::V4(target.gateway))
            }
            DstMatch::HostV6(ip) => (IpAddr::V6(ip), 128u8, IpAddr::V6(target.gateway_v6)),
            DstMatch::SubnetV6 { net, prefix } => {
                (IpAddr::V6(net), prefix, IpAddr::V6(target.gateway_v6))
            }
            // `Any` names no destination, so it is a filter, never a route.
            DstMatch::Any => continue,
        };
        out.push(RouteEntry {
            destination,
            prefix_length,
            next_hop,
            interface_index: target.interface_index,
            metric: intent.metric,
            is_ours: true,
            table: intent.table.clone(),
        });
    }
    out
}
