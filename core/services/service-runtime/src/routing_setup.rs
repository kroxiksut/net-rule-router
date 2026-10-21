//! Whether anyone present has set routing up yet, and which connection to
//! offer as main to a user who has not.
//!
//! Until a user binds a connection the service changes nothing about the
//! machine's network: no routes, no filters (the policy source has nothing to
//! plan from) and no local resolver taking over name resolution, which is the
//! one machine-wide change that would otherwise arm at sign-in. A silent
//! install with no adapter chosen leaves the network as it was.

use std::sync::{Arc, Mutex};

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::RouteEntry;
use nrr_storage::route_bindings::RouteBindingsRepository;
use rusqlite::Connection;

/// A yes/no the resolver controller asks.
pub type Flag = Arc<dyn Fn() -> bool + Send + Sync>;

/// Who is present right now, in stored principal form.
pub type PresentFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Whether any of `principals` has bound a connection. A read that fails
/// answers yes: the resolver then arms as it did before this gate existed.
pub fn someone_has_bound(conn: &Mutex<Connection>, principals: &[String]) -> bool {
    if principals.is_empty() {
        return false;
    }
    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
    let repo = RouteBindingsRepository::new(&guard);
    principals
        .iter()
        .any(|p| repo.has_binding_for_sid(p).unwrap_or(true))
}

/// `signed_in`, narrowed to "and one of those present has bound a
/// connection". Asked on the arm and while the arm waits, never per query.
pub fn resolver_may_arm(signed_in: Flag, present: PresentFn, conn: Arc<Mutex<Connection>>) -> Flag {
    Arc::new(move || signed_in() && someone_has_bound(&conn, &present()))
}

/// The one link holding a default route of its own in the family — the
/// machine's uplink by structure, whatever it is called. `None` with none or
/// with two: then the table cannot say which one is the uplink. Our own fake-IP
/// adapter never counts.
pub fn sole_default_route_holder(
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    v6: bool,
) -> Option<u32> {
    nrr_platform_api::uplink::sole_default_route_holder(adapters, routes, v6, &[])
}

/// The connection to offer as main to a user who bound none: the sole holder
/// of a default route, when both families agree on it or only one has one.
/// Named as the interfaces list shows it. A suggestion, never a binding: only
/// the user's confirmation stores it.
pub fn primary_suggestion(adapters: &[AdapterInfo], routes: &[RouteEntry]) -> Option<String> {
    let index = match (
        sole_default_route_holder(adapters, routes, false),
        sole_default_route_holder(adapters, routes, true),
    ) {
        (Some(v4), Some(v6)) if v4 != v6 => return None,
        (Some(only), _) | (None, Some(only)) => only,
        (None, None) => return None,
    };
    adapters
        .iter()
        .find(|a| a.index == index)
        .map(|a| nrr_platform_api::adapters::preferred_display_name(a).to_owned())
        .filter(|name| !name.is_empty())
}

/// [`primary_suggestion`] over the live machine. Asked only for a user with no
/// binding, at the cadence of the pass that reports them.
pub fn suggest_primary(port: &dyn RouteTablePort) -> Option<String> {
    let adapters = port.get_adapter_infos().ok()?;
    let routes = port.get_ip_forward_table().ok()?;
    primary_suggestion(&adapters, &routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::route_bindings::{BindingSource, RouteBindingRecord, RoutePolicyRecord};

    fn conn() -> Arc<Mutex<Connection>> {
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        let runner =
            SqliteMigrationRunner::for_state_db(Connection::open_in_memory().expect("open"));
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn bind_primary(conn: &Arc<Mutex<Connection>>, sid: &str) {
        let mut record = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        record.primary = Some(RouteBindingRecord {
            stable_id: "eth-1".into(),
            display_name: "Ethernet".into(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        });
        let guard = conn.lock().expect("conn");
        RouteBindingsRepository::new(&guard)
            .update_for_sid(sid, &record, 1)
            .expect("bind");
    }

    #[test]
    fn the_resolver_waits_until_someone_present_has_bound_a_connection() {
        let conn = conn();
        let present: PresentFn = Arc::new(|| vec!["S-1-5-21-1".to_owned()]);
        let gate = resolver_may_arm(Arc::new(|| true), Arc::clone(&present), Arc::clone(&conn));
        assert!(
            !gate(),
            "signed in, nothing bound: the network stays as it was"
        );
        bind_primary(&conn, "S-1-5-21-2");
        assert!(!gate(), "another user's binding is not this user's routing");
        bind_primary(&conn, "S-1-5-21-1");
        assert!(gate());
        let nobody = resolver_may_arm(Arc::new(|| false), present, conn);
        assert!(!nobody(), "nobody signed in still waits");
    }

    fn link(index: u32, name: &str) -> AdapterInfo {
        use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
        AdapterInfo {
            index,
            adapter_name: format!("{{guid-{index}}}"),
            description: format!("driver {index}"),
            friendly_name: name.to_owned(),
            mac: Some([0, 1, 2, 3, 4, index as u8]),
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![std::net::Ipv4Addr::new(192, 0, 2, index as u8)],
            ipv6_addresses: Vec::new(),
            gateways: vec![std::net::Ipv4Addr::new(192, 0, 2, 1)],
        }
    }

    fn default_route(index: u32, v6: bool) -> RouteEntry {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let (destination, next_hop): (IpAddr, IpAddr) = if v6 {
            (
                Ipv6Addr::UNSPECIFIED.into(),
                "fe80::1".parse::<Ipv6Addr>().expect("v6").into(),
            )
        } else {
            (
                Ipv4Addr::UNSPECIFIED.into(),
                Ipv4Addr::new(192, 0, 2, 1).into(),
            )
        };
        RouteEntry {
            destination,
            prefix_length: 0,
            next_hop,
            interface_index: index,
            metric: 25,
            is_ours: false,
            table: Default::default(),
        }
    }

    #[test]
    fn the_sole_default_route_holder_is_suggested_and_nothing_when_there_are_two() {
        let adapters = [link(3, "Ethernet"), link(7, "Wi-Fi")];
        assert_eq!(
            primary_suggestion(&adapters, &[default_route(3, false)]).as_deref(),
            Some("Ethernet")
        );
        assert_eq!(
            primary_suggestion(
                &adapters,
                &[default_route(3, false), default_route(7, false)]
            ),
            None,
            "two holders: the table cannot tell which is the uplink"
        );
        assert_eq!(
            primary_suggestion(
                &adapters,
                &[default_route(3, false), default_route(7, true)]
            ),
            None,
            "the families disagree"
        );
        assert_eq!(
            primary_suggestion(&adapters, &[default_route(7, true)]).as_deref(),
            Some("Wi-Fi")
        );
        let mut ours = default_route(7, false);
        ours.is_ours = true;
        assert_eq!(
            primary_suggestion(&adapters, &[default_route(3, false), ours]).as_deref(),
            Some("Ethernet"),
            "a default route we installed holds nothing"
        );
        assert_eq!(primary_suggestion(&adapters, &[]), None);
    }

    #[test]
    fn our_fake_ip_adapter_is_never_suggested_and_never_spoils_the_count() {
        let own_tun = link(9, nrr_shared::product_identity::TUN_ADAPTER_NAME);
        let adapters = [link(3, "Home internet"), own_tun];
        let routes = [default_route(3, false), default_route(9, false)];
        assert_eq!(
            primary_suggestion(&adapters, &routes).as_deref(),
            Some("Home internet")
        );
        assert_eq!(primary_suggestion(&adapters[1..], &routes[1..]), None);
    }
}
