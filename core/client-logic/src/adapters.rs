//! Which adapter may take which route, and how it reads to a user.
//!
//! Every function reads one live row of `interfaces.snapshot`
//! ([`InterfaceRowDto`]). The service leaves `selected_role` empty on a live
//! refresh; the client fills it from the user's bindings before asking
//! [`held_other_role`] or [`offered_for_role`].

use nrr_shared::ipc_payloads::InterfaceRowDto;
use nrr_shared::product_identity::TUN_ADAPTER_NAME;

use crate::{js, Route};

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
/// driver description when it adds something.
pub fn display_name(row: &InterfaceRowDto) -> String {
    let name = js::trim(&row.name);
    let description = js::trim(&row.interface_description);
    if name.is_empty() {
        description.to_owned()
    } else if description.is_empty() || description == name {
        name.to_owned()
    } else {
        format!("{name} \u{2014} {description}")
    }
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
