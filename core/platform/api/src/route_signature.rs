//! How a row of the system route table is recognised as one of ours.
//!
//! The OS never marks a route as ours, so every reader that has no record of
//! what it installed (crash adoption, the reconciler's live check, the reset
//! verb, the uninstall sweep on either OS) recognises our rows by the signature
//! the route codegen writes: metric, a shape emitted at that metric, and the
//! main table. One definition here, below both the service and the uninstall
//! path, so the two can never disagree about which routes are ours.

use std::net::IpAddr;
use std::sync::Arc;

use crate::enforcement::RouteTableRef;
use crate::error::{ErrorClass, PlatformError};
use crate::route_table::RouteTablePort;
use crate::types::RouteEntry;

/// Prefix length of a host route — the shape every address rule fans out to.
pub const HOST_PREFIX: u8 = 32;

/// The same shape in IPv6.
pub const HOST_PREFIX_V6: u8 = 128;

/// Metric for our host routes and overlay halves. Low enough to win over the
/// default route, uncommon enough that another program's route rarely shares it.
pub const SECONDARY_ROUTE_METRIC: u32 = 5;

/// Metric for a network rule's routes. Its own value, because a rule network
/// can have an overlay half's length (`/8`..`/13`): by shape alone the two are
/// one thing, and pausing or a crash would treat the rule as an overlay.
pub const NETWORK_ROUTE_METRIC: u32 = 4;

/// Longest prefix that still reads as "steer a chunk of the internet" rather
/// than "reach one network": a commercial tunnel's redirect set bottoms out at
/// `/9`, a corporate split tunnel names `/16`s and narrower, which are its
/// business, not ours.
pub const TUNNEL_CATCH_ALL_MAX_PREFIX: u8 = 12;

/// Every length an overlay half can have: the `/1` split-default pair up to
/// one bit longer than the narrowest tunnel catch-all we answer.
pub const OVERLAY_PREFIXES: std::ops::RangeInclusive<u8> = 1..=TUNNEL_CATCH_ALL_MAX_PREFIX + 1;

/// Whether `prefix_length` is a shape we emit at [`SECONDARY_ROUTE_METRIC`];
/// network routes carry their own signature ([`is_network_shape`] at
/// [`NETWORK_ROUTE_METRIC`]).
///
/// The overlay range is every length the counter-overlay can take, not the
/// ones seen so far: an unrecognised half survives a crash and keeps steering
/// traffic after the service is gone.
///
/// The FAMILY is part of the shape. `/32` in IPv6 is a prefix, not a host
/// route, so a family-blind answer adopts a stranger. Only host routes are
/// emitted over IPv6 — the overlays are IPv4 mechanisms.
#[must_use]
pub fn is_owned_shape(destination: IpAddr, prefix_length: u8) -> bool {
    match destination {
        IpAddr::V4(_) => prefix_length == HOST_PREFIX || OVERLAY_PREFIXES.contains(&prefix_length),
        IpAddr::V6(_) => prefix_length == HOST_PREFIX_V6,
    }
}

/// A length a network rule's route can have: no wider than a rule may be,
/// down to a single address (a piece split around a tunnel server).
#[must_use]
pub fn is_network_shape(destination: IpAddr, prefix_length: u8) -> bool {
    let max = if destination.is_ipv4() {
        HOST_PREFIX
    } else {
        HOST_PREFIX_V6
    };
    (nrr_domain::ip_network_policy::widest_rule_prefix(destination.is_ipv4())..=max)
        .contains(&prefix_length)
}

/// Whether a row read back from the system table carries our signature:
/// metric, a shape we emit at that metric, and the main table (a Linux dump
/// also returns other tables, which this signature never claims).
#[must_use]
pub fn is_owned_route(route: &RouteEntry) -> bool {
    route.table == RouteTableRef::Main
        && match route.metric {
            SECONDARY_ROUTE_METRIC => is_owned_shape(route.destination, route.prefix_length),
            NETWORK_ROUTE_METRIC => is_network_shape(route.destination, route.prefix_length),
            _ => false,
        }
}

/// One of our overlay halves — the routes that carry what no rule names.
/// Never a rule's route, whatever its length: those sit at
/// [`NETWORK_ROUTE_METRIC`] or are host routes.
#[must_use]
pub fn is_overlay_route(route: &RouteEntry) -> bool {
    route.metric == SECONDARY_ROUTE_METRIC
        && route.table == RouteTableRef::Main
        && route.destination.is_ipv4()
        && OVERLAY_PREFIXES.contains(&route.prefix_length)
}

/// The rows of the live table carrying our signature or claimed by
/// `also_ours`, stamped as ours.
pub fn signed_routes(
    api: &dyn RouteTablePort,
    also_ours: &dyn Fn(&RouteEntry) -> bool,
) -> Result<Vec<RouteEntry>, PlatformError> {
    Ok(api
        .get_ip_forward_table()?
        .into_iter()
        .filter(|r| is_owned_route(r) || also_ours(r))
        .map(|mut r| {
            r.is_ours = true;
            r
        })
        .collect())
}

/// Why an offline route sweep stopped.
#[derive(Debug)]
pub enum RouteSweepError {
    /// The table could not be read, so nothing was touched.
    Enumerate(PlatformError),
    /// At least one route found could not be removed; the rest went.
    Delete(PlatformError),
}

impl std::fmt::Display for RouteSweepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enumerate(e) => write!(f, "could not read the route table: {e}"),
            Self::Delete(e) => write!(f, "could not remove the routes found: {e}"),
        }
    }
}

/// Remove every route in the table that carries our signature, with no service
/// running to say which it installed. Returns how many went.
pub fn sweep_owned_routes(api: Arc<dyn RouteTablePort>) -> Result<usize, RouteSweepError> {
    sweep_owned_routes_with(api, &|_: &RouteEntry| false)
}

/// [`sweep_owned_routes`], also removing the rows `also_ours` claims.
///
/// Each route on its own: nobody is left to want a route back, so one refusal
/// must neither undo the removals before it nor keep the rest in place.
pub fn sweep_owned_routes_with(
    api: Arc<dyn RouteTablePort>,
    also_ours: &dyn Fn(&RouteEntry) -> bool,
) -> Result<usize, RouteSweepError> {
    let orphans = signed_routes(api.as_ref(), also_ours).map_err(RouteSweepError::Enumerate)?;
    let mut removed = 0usize;
    let mut refused = None;
    for route in &orphans {
        match api.delete_ip_forward_entry(route) {
            Ok(()) => removed += 1,
            Err(e) if e.classify() == ErrorClass::Idempotent => {}
            Err(e) => {
                refused.get_or_insert(e);
            }
        }
    }
    match refused {
        None => Ok(removed),
        Some(e) => Err(RouteSweepError::Delete(e)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::MockWindowsApi;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn row(destination: IpAddr, prefix_length: u8, ifindex: u32, metric: u32) -> RouteEntry {
        RouteEntry {
            destination,
            prefix_length,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            interface_index: ifindex,
            metric,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// The uninstall and reset sweeps take our host routes, overlay halves and
    /// network pieces, and nothing a VPN client, the OS or the user installed:
    /// a VPN's own split default sits at its own metric, the user's static
    /// route at theirs, and a table we never write is not ours by signature.
    #[test]
    fn the_sweep_takes_our_signature_and_leaves_every_other_route() {
        let api = Arc::new(MockWindowsApi::new());
        let ours = [
            row(v4(198, 51, 100, 4), HOST_PREFIX, 7, SECONDARY_ROUTE_METRIC),
            row(v4(0, 0, 0, 0), 2, 3, SECONDARY_ROUTE_METRIC),
            row(v4(10, 20, 0, 0), 16, 7, NETWORK_ROUTE_METRIC),
            row(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4)),
                HOST_PREFIX_V6,
                7,
                SECONDARY_ROUTE_METRIC,
            ),
        ];
        let foreign = vec![
            // A redirect VPN's split default and its server's bootstrap route.
            row(v4(0, 0, 0, 0), 1, 7, 1),
            row(v4(203, 0, 113, 7), HOST_PREFIX, 3, 0),
            // Another VPN's subnet and the OS default.
            row(v4(10, 7, 0, 0), 24, 9, 256),
            row(v4(0, 0, 0, 0), 0, 3, 25),
            // The user's own static route, and a v6 `/32` prefix at our metric.
            row(v4(192, 168, 50, 0), 24, 3, 10),
            row(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                32,
                7,
                SECONDARY_ROUTE_METRIC,
            ),
            // Our metric and shape, but in a table this signature never claims.
            RouteEntry {
                table: RouteTableRef::Tagged(51820),
                ..row(v4(198, 51, 100, 5), HOST_PREFIX, 7, SECONDARY_ROUTE_METRIC)
            },
            // Too wide for a rule network.
            row(v4(0, 0, 0, 0), 2, 9, NETWORK_ROUTE_METRIC),
        ];
        api.set_route_table(ours.iter().chain(&foreign).cloned().collect());

        let removed = sweep_owned_routes(Arc::clone(&api) as Arc<dyn RouteTablePort>).unwrap();

        assert_eq!(removed, ours.len());
        assert_eq!(api.get_ip_forward_table().unwrap(), foreign);
    }

    #[test]
    fn a_clean_table_sweeps_to_nothing() {
        let api = Arc::new(MockWindowsApi::new());
        api.set_route_table(vec![row(v4(0, 0, 0, 0), 0, 3, 25)]);
        assert_eq!(
            sweep_owned_routes(Arc::clone(&api) as Arc<dyn RouteTablePort>).unwrap(),
            0
        );
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);
    }

    /// One refused delete is reported, and the routes after it still go.
    #[test]
    fn one_refused_delete_does_not_keep_the_rest() {
        struct RefusesOne(MockWindowsApi);
        impl RouteTablePort for RefusesOne {
            fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
                self.0.get_ip_forward_table()
            }
            fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
                self.0.create_ip_forward_entry(entry)
            }
            fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
                if entry.destination == v4(198, 51, 100, 1) {
                    return Err(PlatformError::Win32 {
                        operation: "DeleteIpForwardEntry2",
                        code: 0x5,
                        message: "access denied".into(),
                    });
                }
                self.0.delete_ip_forward_entry(entry)
            }
            fn get_adapter_infos(&self) -> Result<Vec<crate::AdapterInfo>, PlatformError> {
                self.0.get_adapter_infos()
            }
            fn interface_luid_for_index(&self, index: u32) -> Result<u64, PlatformError> {
                self.0.interface_luid_for_index(index)
            }
        }
        let api = Arc::new(RefusesOne(MockWindowsApi::new()));
        api.0.set_route_table(vec![
            row(v4(198, 51, 100, 1), HOST_PREFIX, 7, SECONDARY_ROUTE_METRIC),
            row(v4(198, 51, 100, 2), HOST_PREFIX, 7, SECONDARY_ROUTE_METRIC),
        ]);

        let outcome = sweep_owned_routes(Arc::clone(&api) as Arc<dyn RouteTablePort>);

        assert!(matches!(outcome, Err(RouteSweepError::Delete(_))));
        let left: Vec<IpAddr> = api
            .get_ip_forward_table()
            .unwrap()
            .iter()
            .map(|r| r.destination)
            .collect();
        assert_eq!(left, vec![v4(198, 51, 100, 1)]);
    }
}
