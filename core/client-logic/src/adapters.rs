//! Which adapter may take which route, and how it reads to a user.
//!
//! Every function reads one live row of `interfaces.snapshot`
//! ([`InterfaceRowDto`]). The service leaves `selected_role` empty on a live
//! refresh; the client fills it from the user's bindings before asking
//! [`held_other_role`] or [`offered_for_role`].

use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::{InterfaceRowDto, RouteBindingDto};
use nrr_shared::product_identity::TUN_ADAPTER_NAME;

use crate::{js, Route};

/// A field as the window's mapped row has it: a missing address reads `-`.
fn or_dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

/// Whether the row stays in the list (`adapterPassesFilter`): unavailable
/// ones only when asked for, and `search` (any case) in its name,
/// description, address, resolvers or type.
pub fn adapter_passes_filter(row: &InterfaceRowDto, show_unavailable: bool, search: &str) -> bool {
    if !show_unavailable && row.availability == "unavailable" {
        return false;
    }
    let q = search.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    format!(
        "{} {} {} {} {}",
        row.name,
        row.interface_description,
        or_dash(&row.local_ip),
        or_dash(&row.dns_servers),
        row.interface_type
    )
    .to_lowercase()
    .contains(&q)
}

/// A loopback adapter is a local address space, never a route
/// (`adapterIsLoopback`).
fn adapter_is_loopback(row: &InterfaceRowDto) -> bool {
    [
        row.name.as_str(),
        row.interface_type.as_str(),
        row.interface_description.as_str(),
        row.derived_assessment.classification.as_str(),
    ]
    .iter()
    .any(|text| text.to_lowercase().contains("loopback"))
}

/// Whether the row names a resolver (`adapterHasConfiguredDns`); the
/// placeholders of a row without one read as none.
fn adapter_has_configured_dns(row: &InterfaceRowDto) -> bool {
    let raw = or_dash(&row.dns_servers).trim().to_lowercase();
    !raw.is_empty() && !["\u{2014}", "-", "none", "(none)", "n/a"].contains(&raw.as_str())
}

/// Where the row stands in the list sorted by `sort_by` (`adapterSortRank`):
/// `default`, `vpn-like` or `primary-candidate`, higher first. A bound adapter
/// leads whatever the order, loopback sinks.
pub fn adapter_sort_rank(row: &InterfaceRowDto, sort_by: &str) -> i32 {
    if adapter_is_loopback(row) {
        return -10_000;
    }
    match row.selected_role.as_deref() {
        Some("primary") => return 1_000_000,
        Some("secondary") => return 900_000,
        _ => {}
    }
    let rec = row.recommendation.class.as_str();
    let vpn = row.derived_assessment.vpn_tunnel_likelihood.as_str();
    let virt = row.derived_assessment.virtual_interface_likelihood.as_str();
    let dns = i32::from(adapter_has_configured_dns(row));
    match sort_by {
        "vpn-like" => {
            dns + match (vpn, virt) {
                ("likely", _) => 100,
                ("possible", _) => 60,
                (_, "likely") => 40,
                (_, "possible") => 25,
                _ => 0,
            }
        }
        "primary-candidate" => {
            dns + match rec {
                "preferred-primary" => 100,
                "allowed-but-not-recommended" => 40,
                "preferred-secondary" => 30,
                "not-recommended" => 0,
                _ => 10,
            }
        }
        _ => {
            let availability = match row.availability.as_str() {
                "available" => 50,
                "requires-check" => 20,
                _ => 0,
            };
            let recommendation = match rec {
                "preferred-primary" => 40,
                "preferred-secondary" => 25,
                "allowed-but-not-recommended" => 10,
                _ => 0,
            };
            availability + dns * 30 + recommendation
        }
    }
}

/// Why an adapter cannot carry traffic out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnroutableReason {
    /// Confidently a virtual / host-only adapter, and it has no gateway.
    VirtualHostOnly,
    /// The service found neither a gateway nor a default-style route with a
    /// real next hop on it.
    NoForwardingPath,
}

impl UnroutableReason {
    /// The slug the locale keys are built from.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VirtualHostOnly => "virtual-host-only",
            Self::NoForwardingPath => "no-forwarding-path",
        }
    }
}

/// The hint shown beside an adapter's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleHint {
    /// A link with no way out.
    NoInternet,
    /// The service recommends it as the main link.
    LooksPrimary,
    /// It looks like a VPN while its kind does not already say so.
    LooksVpn,
}

impl RoleHint {
    /// The slug the locale keys are built from.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoInternet => "no-internet",
            Self::LooksPrimary => "looks-primary",
            Self::LooksVpn => "looks-vpn",
        }
    }
}

/// The enumerations that are this machine's (`INTERFACES_LIVE_SOURCES`). Any
/// other spelling, an unknown one included, is placeholder rows.
pub const LIVE_SOURCES: [&str; 2] = ["windows-live", "linux-live"];

/// Whether rows reported with `data_source` name this machine's adapters
/// (`interfacesSourceIsLive`). Every role assignment is gated on it: a role
/// bound to a placeholder row names no adapter here.
pub fn rows_are_live(data_source: &str) -> bool {
    LIVE_SOURCES.contains(&data_source)
}

/// Confidence a two-signal heuristic hit scores; a single weak signal stays
/// below it.
const CONFIDENT_PERCENT: u8 = 70;

/// The product's own fake-IP tunnel (`isOwnFakeIpTunRow`). Never offered for
/// a role: a route bound to it would loop traffic back into the product. The
/// OS name is the identity — the GUID changes whenever the adapter is
/// recreated, and the driver description is shared by every Wintun user.
pub fn is_own_fake_ip_tun(row: &InterfaceRowDto) -> bool {
    row.name == TUN_ADAPTER_NAME
}

/// `gateway` names an address packets can be handed to. The enumeration
/// writes `-` for "none"; all-zeroes says the same.
fn has_usable_gateway(gateway: &str) -> bool {
    !matches!(js::trim(gateway), "" | "-" | "0.0.0.0" | "::" | "::0")
}

/// Why `row` cannot carry traffic out, or `None` when it can
/// (`unroutableInterfaceReasonSlug`).
///
/// An adapter that is merely down is never flagged: binding a tunnel before it
/// is up is a supported workflow. `has_default_route` is deliberately not read
/// — it mirrors the gateway and reads false for every healthy gateway-less
/// tunnel — and an unevaluated `has_forwarding_path` never warns.
pub fn unroutable_reason(row: &InterfaceRowDto) -> Option<UnroutableReason> {
    if row.availability != "available" || has_usable_gateway(&row.gateway) {
        return None;
    }
    let assessment = &row.derived_assessment;
    let confidently_virtual = assessment.virtual_interface_likelihood == "likely"
        || (assessment.classification == "virtual-interface-likely"
            && assessment.confidence_percent >= CONFIDENT_PERCENT);
    if confidently_virtual {
        Some(UnroutableReason::VirtualHostOnly)
    } else if row.has_forwarding_path == Some(false) {
        Some(UnroutableReason::NoForwardingPath)
    } else {
        None
    }
}

/// Whether `row` can carry traffic out (`!interfaceCannotCarryTrafficOut`).
pub fn can_carry_traffic_out(row: &InterfaceRowDto) -> bool {
    unroutable_reason(row).is_none()
}

/// How an adapter reads to a user everywhere it is named
/// (`adapterDisplayName`): the connection name the user knows, then the
/// driver description when it adds something. Both are the OS's text, so the
/// result goes through [`display_text`]; it is never a key.
pub fn display_name(row: &InterfaceRowDto) -> String {
    let name = js::trim(&row.name);
    let description = js::trim(&row.interface_description);
    let joined = if name.is_empty() {
        description.to_owned()
    } else if description.is_empty() || description == name {
        name.to_owned()
    } else {
        format!("{name} \u{2014} {description}")
    };
    display_text(&joined).into_owned()
}

/// The hint beside an adapter's kind (`adapterRoleHintSlug`). A tunnel gets
/// no word for lacking a way out — it has none until its client installs one
/// — and no second word for being a VPN.
pub fn role_hint(row: &InterfaceRowDto) -> Option<RoleHint> {
    let kind = row.kind.as_str();
    if kind != "tunnel" && !can_carry_traffic_out(row) {
        return Some(RoleHint::NoInternet);
    }
    let class = row.recommendation.class.as_str();
    if class == "preferred-primary" {
        return Some(RoleHint::LooksPrimary);
    }
    if kind == "tunnel" || kind == "virtual" {
        return None;
    }
    match row.derived_assessment.vpn_tunnel_likelihood.as_str() {
        "likely" => Some(RoleHint::LooksVpn),
        "possible" if class == "preferred-secondary" => Some(RoleHint::LooksVpn),
        _ => None,
    }
}

/// The role `row` holds other than `role`, if any (`adapterHeldOtherRole`).
/// One adapter cannot carry both routes.
pub fn held_other_role(row: &InterfaceRowDto, role: Route) -> Option<&str> {
    row.selected_role
        .as_deref()
        .filter(|held| !held.is_empty() && *held != role.as_str())
}

/// Whether a picker for `role` may offer `row`: not the product's own tunnel,
/// and not already holding the other route.
pub fn offered_for_role(row: &InterfaceRowDto, role: Route) -> bool {
    !is_own_fake_ip_tun(row) && held_other_role(row, role).is_none()
}

/// The row `binding` names (`boundWireRowIndex`): its current or an earlier id
/// against the row's id or OS adapter name, ASCII case-insensitive. The first
/// match wins. This is how a client fills the `selected_role` the service
/// leaves empty.
pub fn bound_row_index(rows: &[InterfaceRowDto], binding: &RouteBindingDto) -> Option<usize> {
    let names = |id: &str| {
        std::iter::once(binding.stable_id.as_str())
            .chain(binding.known_stable_ids.iter().map(String::as_str))
            .any(|known| !known.is_empty() && known.eq_ignore_ascii_case(id))
    };
    rows.iter()
        .position(|row| names(&row.persistent_id) || names(&row.adapter_name))
}

/// The main-connection binding a confirmed suggestion writes
/// (`suggestedPrimaryBinding`): the one row whose connection name or driver
/// description is `name`, ASCII case aside. `None` when no row or more than one
/// answers to it — the choice then goes to the interfaces screen.
pub fn suggested_primary_binding(rows: &[InterfaceRowDto], name: &str) -> Option<RouteBindingDto> {
    let wanted = name.trim();
    if wanted.is_empty() {
        return None;
    }
    let mut answering = rows.iter().filter(|row| {
        row.name.trim().eq_ignore_ascii_case(wanted)
            || row
                .interface_description
                .trim()
                .eq_ignore_ascii_case(wanted)
    });
    let row = match (answering.next(), answering.next()) {
        (Some(only), None) => only,
        _ => return None,
    };
    if row.persistent_id.is_empty() {
        return None;
    }
    let shown = row.name.trim();
    Some(RouteBindingDto {
        stable_id: row.persistent_id.clone(),
        display_name: if shown.is_empty() { wanted } else { shown }.to_owned(),
        user_confirmed: true,
        known_stable_ids: Vec::new(),
    })
}
