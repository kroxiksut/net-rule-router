//! Which live adapter a stored binding means, and what to route out of it.
//!
//! Pure functions over [`AdapterInfo`] and the route table: no `self`, no I/O,
//! no coordinator state. That is what made them the first thing to move out of
//! `route_coordinator.rs` — the interface is the signatures, and there is
//! nothing else to weigh.
//!
//! The identity question is the delicate one and the comments below carry it:
//! the binding stores the GUI's persistent id, `AdapterInfo::stable_id()` uses
//! a different scheme, and a direct compare between them silently matched
//! nothing.

use std::net::{IpAddr, Ipv4Addr};

use nrr_platform_api::adapters::{classify_availability, AdapterAvailability, AdapterInfo};
use nrr_platform_api::RouteEntry;

use crate::route_codegen::SecondaryRouteTarget;

/// Match a stored route-binding id against a live [`AdapterInfo`].
///
/// The binding stores the GUI **snapshot persistent id**
/// (`win-adapter:{lowercased-adapter-name}`, or the
/// `win-ifindex-mac:{idx}:{MAC}` / `win-ifindex:{idx}` fallbacks) produced by
/// `nrr_platform_api::interface_manager::build_persistent_id`. The
/// low-level `AdapterInfo::stable_id()` uses a DIFFERENT scheme (MAC hex, or
/// the bare adapter name) — so a direct `stable_id()` compare NEVER matched a
/// real binding. That silent mismatch made the coordinator report
/// "secondary adapter not found" for a live, working VPN and route nothing.
/// Reconstruct the persistent id here (keep in sync with `build_persistent_id`).
pub fn adapter_binding_matches(info: &AdapterInfo, bound_id: &str) -> bool {
    identity_matches(
        &info.adapter_name,
        info.index,
        mac_dash(info).as_deref(),
        &info.stable_id(),
        bound_id,
    )
}

/// Same matching rules as [`adapter_binding_matches`], for the wire-shaped
/// [`AdapterEntry`] the IPC layer hands to per-SID consumers (e.g. the
/// Fail-Closed probe) that only ever see the already-enumerated snapshot,
/// not the raw platform-api `AdapterInfo` list.
///
/// `AdapterEntry::physical_address` is colon-separated hex (see
/// `adapter_to_entry`); normalize to the dash form the persistent-id scheme
/// uses before comparing. `AdapterEntry::persistent_id` is populated from
/// `AdapterInfo::stable_id()`, so it is the correct back-compat fallback.
pub fn adapter_entry_binding_matches(
    entry: &nrr_shared::ipc_payloads::AdapterEntry,
    bound_id: &str,
) -> bool {
    let mac_dash = entry
        .physical_address
        .as_deref()
        .map(|mac| mac.replace(':', "-"));
    identity_matches(
        &entry.adapter_name,
        entry.ipv6_if_index,
        mac_dash.as_deref(),
        &entry.persistent_id,
        bound_id,
    )
}

/// Core identity-matching rules, parametrized over the fields both adapter
/// representations in this crate carry. `stable_id_fallback` is the
/// low-level `AdapterInfo::stable_id()` value, kept for bindings persisted
/// before the `win-adapter:`/`win-ifindex-mac:`/`win-ifindex:` scheme
/// existed.
pub(super) fn identity_matches(
    name: &str,
    index: u32,
    mac_dash: Option<&str>,
    stable_id_fallback: &str,
    bound_id: &str,
) -> bool {
    let name = name.trim().to_ascii_lowercase();
    if !name.is_empty() && bound_id.eq_ignore_ascii_case(&format!("win-adapter:{name}")) {
        return true;
    }
    if let Some(mac) = mac_dash {
        if bound_id.eq_ignore_ascii_case(&format!("win-ifindex-mac:{index}:{mac}")) {
            return true;
        }
        // The ifindex-free anchor. A Wi-Fi or Bluetooth adapter that lost power
        // comes back with a new ifindex and sometimes a new GUID, but never a
        // new burned-in MAC — so this is the identity that survives what the
        // other two do not. Only written for adapters whose MAC is independent
        // of their GUID (see `mac_anchor_id`).
        if bound_id.eq_ignore_ascii_case(&format!("win-mac:{mac}")) {
            return true;
        }
    }
    if bound_id.eq_ignore_ascii_case(&format!("win-ifindex:{index}")) {
        return true;
    }
    // Back-compat: a binding stored with the low-level stable_id scheme.
    bound_id.eq_ignore_ascii_case(stable_id_fallback)
}

/// match a live adapter against a binding's current
/// `stable_id` OR any previously-known id the auto-heal folded in. A VPN whose
/// GUID rotated across a reinstall is recognised directly by a prior id,
/// without depending on the friendly-name heal firing again this session.
pub(super) fn binding_matches_live(
    info: &AdapterInfo,
    stable_id: &str,
    known_ids: &[String],
) -> bool {
    adapter_binding_matches(info, stable_id)
        || known_ids.iter().any(|id| adapter_binding_matches(info, id))
}

/// A live adapter as the bound-adapter check sees it, whichever form it was
/// read in: the service's own list or the snapshot the leak-protection banner
/// is judged from.
pub trait BoundCandidate {
    /// Whether this adapter answers to the binding id `id`.
    fn answers_to(&self, id: &str) -> bool;
    /// Up, with an IPv4 address, and of a kind a route can be bound to.
    fn usable(&self) -> bool;
}

impl BoundCandidate for AdapterInfo {
    fn answers_to(&self, id: &str) -> bool {
        adapter_binding_matches(self, id)
    }
    fn usable(&self) -> bool {
        classify_availability(self) == Some(AdapterAvailability::Available)
    }
}

impl BoundCandidate for nrr_shared::ipc_payloads::AdapterEntry {
    fn answers_to(&self, id: &str) -> bool {
        adapter_entry_binding_matches(self, id)
    }
    fn usable(&self) -> bool {
        self.usable
    }
}

/// The first live adapter answering to a binding's current or a prior id.
pub fn bound_adapter<'a, T: BoundCandidate>(
    live: &'a [T],
    stable_id: &str,
    known_ids: &[String],
) -> Option<&'a T> {
    live.iter().find(|candidate| {
        candidate.answers_to(stable_id) || known_ids.iter().any(|id| candidate.answers_to(id))
    })
}

/// Whether the adapter a binding names carries traffic now — the one answer
/// the route coordinator and the leak-protection banner both give, so the
/// banner never says one thing while the service does another.
pub fn bound_adapter_usable<T: BoundCandidate>(
    live: &[T],
    stable_id: &str,
    known_ids: &[String],
) -> bool {
    bound_adapter(live, stable_id, known_ids).is_some_and(BoundCandidate::usable)
}

/// `true` when a whitespace token of an adapter friendly name is purely a
/// version designator (all digits/dots, optionally a leading `v`): "3.0",
/// "4.1", "v3", "2". VPN vendors bump these across reinstalls/upgrades
/// ("examplevpn VPN OpenVPN Adapter" ↔ "ExampleVPN 3.0 OpenVPN
/// Adapter"), so a version token must never participate in identity matching.
pub(super) fn is_version_token(token: &str) -> bool {
    let stripped = token.trim_start_matches(['v', 'V']);
    !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Words that name a category, not a vendor. A family match resting only on
/// these is not evidence: every tunnel on the machine carries some of them, and
/// Windows names connections from them in the system language ("Local Area
/// Connection* 12", «Подключение по локальной сети 12»), differing only by a
/// number the matcher drops.
pub(super) const GENERIC_NAME_TOKENS: &[&str] = &[
    "vpn",
    "adapter",
    "tunnel",
    "client",
    "network",
    "connection",
    "ethernet",
    "wireless",
    "virtual",
    "tap",
    "wintun",
    "local",
    "area",
    "wi",
    "fi",
    "bluetooth",
    "lan",
    "подключение",
    "подключения",
    "по",
    "локальной",
    "сети",
    "сеть",
    "сетевое",
    "сетевой",
    "беспроводная",
    "беспроводное",
    "адаптер",
    "туннель",
    "клиент",
    "виртуальный",
    "виртуальная",
];

/// Lower-cased tokens of a friendly name with version tokens dropped — the
/// stable "family" identity of an adapter description.
///
/// Splits on `_` and `-` as well as whitespace: a vendor writes the same name
/// both ways across its own products ("examplevpn VPN OpenVPN Adapter" for
/// the TAP device, "examplevpn_VPN" for the WireGuard one), and treating the
/// underscore spelling as one opaque token left the family match blind exactly
/// when the user switched transport. `.` stays a word character — it belongs to
/// brand names like "examplevpn". The `*` Windows puts in hidden connection
/// names ("Local Area Connection* 2") is not part of a word.
pub(super) fn core_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| c.is_whitespace() || c == '_' || c == '-')
        .map(|t| t.trim_matches('*'))
        .filter(|t| !t.is_empty() && !is_version_token(t))
        .map(str::to_lowercase)
        .collect()
}

/// Heuristic name-family match for the stale-GUID auto-heal: `true` when the
/// binding's saved `display_name` and the live adapter's `description` name
/// the SAME adapter family, ignoring version tokens.
///
/// Both sides are reduced to their version-stripped core token set (so
/// "examplevpn VPN OpenVPN Adapter" and "ExampleVPN 3.0 OpenVPN Adapter"
/// reduce to the same family), then matched by **symmetric** containment:
/// either core set is a subset of the other. A one-directional subset test
/// misses the case where the SAVED name carries the version token and the
/// live description dropped it, or vice versa (saved "…VPN 3.0 OpenVPN
/// Adapter" vs live "…VPN OpenVPN Adapter"), leaving a live, working VPN
/// reported as "not found among live adapters". The caller only uses this when
/// EXACTLY ONE usable adapter matches, bounding false positives.
/// Containment alone is not enough once `_`/`-` split names into short token
/// sets: an adapter merely called "VPN" is a subset of every VPN name there is.
/// At least one shared token must name the vendor rather than the category.
pub(super) fn description_matches_display_name(description: &str, display_name: &str) -> bool {
    let saved = core_tokens(display_name);
    let live = core_tokens(description);
    if saved.is_empty() || live.is_empty() {
        return false;
    }
    let contained =
        saved.iter().all(|t| live.contains(t)) || live.iter().all(|t| saved.contains(t));
    contained
        && saved
            .iter()
            .any(|t| live.contains(t) && !GENERIC_NAME_TOKENS.contains(&t.as_str()))
}

/// Words every client on a stock tunnel driver shares. Two clients on the same
/// driver agree on these, so agreeing on them alone says nothing about whose
/// tunnel it is.
const STOCK_DRIVER_TOKENS: &[&str] = &[
    "windows",
    "openvpn",
    "wireguard",
    "ndis",
    "tun",
    "ovpn",
    "dco",
    "userspace",
    "miniport",
];

/// For a tunnel that is foreign by structure: one of its names must match by a
/// vendor word (neither a category nor a stock-driver word) AND add no
/// vendor word the saved name lacks. "Cisco AnyConnect Secure Mobility …" is not
/// the connection saved as "AnyConnect"; "acme.name_VPN" is the one saved as
/// "acme.name VPN 3.0 OpenVPN Adapter".
pub(super) fn adapter_carries_only_the_saved_brand(info: &AdapterInfo, display_name: &str) -> bool {
    let is_vendor = |t: &String| {
        !GENERIC_NAME_TOKENS.contains(&t.as_str()) && !STOCK_DRIVER_TOKENS.contains(&t.as_str())
    };
    let saved: Vec<String> = core_tokens(display_name)
        .into_iter()
        .filter(is_vendor)
        .collect();
    [&info.description, &info.friendly_name].iter().any(|name| {
        let live: Vec<String> = core_tokens(name).into_iter().filter(is_vendor).collect();
        description_matches_display_name(name, display_name)
            && live.iter().any(|t| saved.contains(t))
            && live.iter().all(|t| saved.contains(t))
    })
}

/// Does `info` still answer to the name the binding was saved under?
///
/// The saved name is whatever the GUI showed, which is the CONNECTION name
/// (`friendly_name`) — a VPN client that renames its connection but ships the
/// stock driver ("TAP-Windows Adapter V9") shares no token with the driver
/// description, so matching the description alone leaves the heal dead exactly
/// where GUID churn makes it necessary.
pub(super) fn adapter_answers_to_saved_name(info: &AdapterInfo, display_name: &str) -> bool {
    description_matches_display_name(&info.description, display_name)
        || description_matches_display_name(&info.friendly_name, display_name)
}

/// Per-kind counts of one codegen's diagnostics, so the log line states which
/// cause fired instead of listing the ones that might have.
#[derive(Default)]
pub(super) struct DiagnosticTally {
    pub(super) hostname_unresolved: usize,
    pub(super) suffix_empty: usize,
    pub(super) zone_empty: usize,
    pub(super) app_rule_address_and_app_not_routed: usize,
    pub(super) app_rule_unobserved: usize,
    pub(super) app_rule_dest_claimed_by_main_link: usize,
    pub(super) app_rule_dest_used_by_other_process: usize,
    pub(super) address_claimed_by_main_link: usize,
    pub(super) private_kept_out_of_tunnel: usize,
    pub(super) primary_exceptions_unavailable: usize,
    pub(super) network_yields_to_local_network: usize,
    pub(super) network_routed_around_tunnel_server: usize,
    pub(super) network_claimed_by_main_link: usize,
    pub(super) network_routes_capped: usize,
}

pub(super) fn diagnostic_tally(
    diagnostics: &[crate::route_codegen::RouteCodegenDiagnostic],
) -> DiagnosticTally {
    use crate::route_codegen::RouteCodegenDiagnostic as D;
    let mut t = DiagnosticTally::default();
    for d in diagnostics {
        match d {
            D::HostnameUnresolved { .. } => t.hostname_unresolved += 1,
            D::SuffixEmpty { .. } => t.suffix_empty += 1,
            D::ZoneEmpty { .. } => t.zone_empty += 1,
            D::AppRuleAddressAndAppNotRouted { .. } => t.app_rule_address_and_app_not_routed += 1,
            D::AppRuleUnobserved { .. } => t.app_rule_unobserved += 1,
            D::AppRuleDestinationClaimedByMainLink { .. } => {
                t.app_rule_dest_claimed_by_main_link += 1
            }
            D::AppRuleDestinationUsedByOtherProcess { .. } => {
                t.app_rule_dest_used_by_other_process += 1
            }
            D::AddressClaimedByMainLink { count, .. } => t.address_claimed_by_main_link += count,
            D::PrivateAddressKeptOutOfTunnel { count, .. } => t.private_kept_out_of_tunnel += count,
            D::PrimaryExceptionsUnavailable => t.primary_exceptions_unavailable += 1,
            D::NetworkYieldsToLocalNetwork { .. } => t.network_yields_to_local_network += 1,
            D::NetworkRoutedAroundTunnelServer { .. } => t.network_routed_around_tunnel_server += 1,
            D::NetworkClaimedByMainLink { .. } => t.network_claimed_by_main_link += 1,
            D::NetworkRoutesCapped { .. } => t.network_routes_capped += 1,
        }
    }
    t
}

/// Dash-separated upper-case MAC, the spelling every persistent-id form uses.
pub(super) fn mac_dash(info: &AdapterInfo) -> Option<String> {
    info.mac.map(|mac| {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join("-")
    })
}

/// `true` when the MAC identifies the adapter independently of its GUID.
///
/// A tunnel adapter derives its MAC from its own GUID — a live TAP-Windows
/// instance was observed as MAC `00:FF:AA:BB:CC:DD` under GUID
/// `{AABBCCDD-1111-2222-3333-444444444444}` — so the two rotate together on
/// every reconnect and the MAC carries no identity the GUID did not already
/// carry. Anchoring on it would either never match or, worse, match whatever
/// instance the client created last. Interface TYPE cannot make this call:
/// TAP reports itself as Ethernet.
pub(super) fn mac_is_independent_identity(info: &AdapterInfo) -> bool {
    let Some(mac) = info.mac else {
        return false;
    };
    if nrr_platform_api::adapters::description_matches_virtual_software(&info.description) {
        return false;
    }
    let guid_head: String = info
        .adapter_name
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(8)
        .collect();
    let mac_tail: String = mac[2..].iter().map(|b| format!("{b:02x}")).collect();
    !guid_head.eq_ignore_ascii_case(&mac_tail)
}

/// The MAC-only identity to remember for a binding, or `None` when this
/// adapter's MAC is not an identity of its own (see
/// [`mac_is_independent_identity`]).
pub(super) fn mac_anchor_id(info: &AdapterInfo) -> Option<String> {
    if !mac_is_independent_identity(info) {
        return None;
    }
    mac_dash(info).map(|mac| format!("win-mac:{mac}"))
}

/// The one usable adapter other than `bound` running another copy of its
/// driver, unless `excluded` (the user's other route) says it is spoken for.
/// A VPN client on a stock driver brings up whichever copy it likes, so the
/// copy a route was bound to can stay down for good while its sibling carries
/// the tunnel. `None` for zero or several: which of two is theirs is not ours
/// to guess.
pub(super) fn sole_live_driver_sibling<'a>(
    infos: &'a [AdapterInfo],
    bound: &AdapterInfo,
    excluded: impl Fn(&AdapterInfo) -> bool,
) -> Option<&'a AdapterInfo> {
    let mut siblings = infos.iter().filter(|info| {
        info.index != bound.index
            && info.friendly_name != nrr_shared::product_identity::TUN_ADAPTER_NAME
            && classify_availability(info) == Some(AdapterAvailability::Available)
            && nrr_shared::same_driver(&info.description, &bound.description)
            && !excluded(info)
    });
    let only = siblings.next()?;
    siblings.next().is_none().then_some(only)
}

/// Where a dead additional binding's VPN may have come up: the live tunnels
/// that are nobody else's (`foreign`: not ours, not a link the machine leaves
/// by), less the other route's link (`excluded`), corporate clients, and
/// links with no way out of their own. A VPN client may bring its tunnel up
/// on an adapter of another driver than the one bound — its vendor's own
/// beside a pool of stock copies — so the driver does not decide here.
pub(super) fn adoptable_tunnels<'a>(
    infos: &'a [AdapterInfo],
    foreign: &[u32],
    routes: &[RouteEntry],
    excluded: impl Fn(&AdapterInfo) -> bool,
) -> Vec<&'a AdapterInfo> {
    use nrr_platform_api::vpn_discovery::{vpn_client_class, VpnClientClass};
    infos
        .iter()
        .filter(|info| foreign.contains(&info.index))
        .filter(|info| info.friendly_name != nrr_shared::product_identity::TUN_ADAPTER_NAME)
        .filter(|info| classify_availability(info) == Some(AdapterAvailability::Available))
        .filter(|info| !excluded(info))
        .filter(|info| {
            [info.friendly_name.as_str(), info.description.as_str()]
                .iter()
                .all(|name| vpn_client_class(name) != Some(VpnClientClass::Corporate))
        })
        .filter(|info| {
            !info.gateways.is_empty() || derive_secondary_next_hop(routes, info.index).is_some()
        })
        .collect()
}

/// Live connections worth offering when the bound one is gone; tunnels first
/// for the additional route. One definition, shared with the other platform.
pub(super) fn replacement_candidates(infos: &[AdapterInfo], role: &str) -> Vec<String> {
    nrr_platform_api::adapters::replacement_candidates(infos, role == "secondary")
}

/// The name to store for an adapter: the connection name the GUI lists, with
/// the driver description as the fallback.
pub(super) fn preferred_display_name(info: &AdapterInfo) -> &str {
    nrr_platform_api::adapters::preferred_display_name(info)
}

/// Derive a usable next-hop for a secondary adapter that exposes **no**
/// classic default gateway. OpenVPN / WireGuard TUN links commonly install
/// split-default routes (`0.0.0.0/1` + `128.0.0.0/1`, or a plain
/// `0.0.0.0/0`) pointing at the tunnel **peer** instead of setting a
/// gateway on the adapter — so `GetAdaptersAddresses` reports an empty
/// gateway list and the adapter-gateway lookup finds nothing, even though
/// the link is up and routing fine. We reuse that peer as the next-hop for
/// our `/32` overlays so matched traffic travels exactly like the VPN's own
/// redirected traffic. (Observed on a live examplevpn OpenVPN link:
/// `0.0.0.0/1 -> 10.91.192.1` with no adapter gateway.)
///
/// Default-style routes on `ifindex` with a real (non-unspecified,
/// non-loopback) next-hop are preferred (`/0`, then the `/1` halves, then
/// lowest metric); ANY other gateway-style route on the interface is a
/// last resort — on a point-to-point tunnel every such route
/// names the one peer, which recovers the next-hop after the catch-alls
/// were stripped and a restart lost the in-memory cache. Returns `None`
/// when the interface carries only on-link routes (host-only virtual
/// adapter, or a tunnel whose client has not yet installed any route).
/// The single implementation lives in `nrr-platform-api` so the interface
/// enumeration reports exactly the next-hop this layer would route through —
/// otherwise the GUI could call an adapter unusable that the router uses
/// happily (or the reverse).
pub(super) fn derive_secondary_next_hop(routes: &[RouteEntry], ifindex: u32) -> Option<Ipv4Addr> {
    nrr_platform_api::interface_rows::derive_forwarding_next_hop(routes, ifindex)
}

/// The IPv6 twin of [`derive_secondary_next_hop`].
///
/// `None` — this link has no IPv6 way out, and policy must not name a `/128`
/// through it. Read from the route table for the same reason the v4 answer is:
/// a TUN client installs routes, not an adapter gateway.
pub(super) fn derive_secondary_next_hop_v6(
    routes: &[RouteEntry],
    ifindex: u32,
) -> Option<std::net::Ipv6Addr> {
    nrr_platform_api::interface_rows::derive_forwarding_next_hop_v6(routes, ifindex)
}

/// Whether `info` can carry traffic out on its own: a gateway, or a forwarding
/// path in routes we did not install. Our overlay through an adapter proves
/// nothing about it — counted, a host-only link once used as the main one
/// would keep vouching for itself.
pub(super) fn has_own_way_out(
    info: &AdapterInfo,
    routes: &[RouteEntry],
    owns: impl Fn(&RouteEntry) -> bool,
) -> bool {
    if !info.gateways.is_empty() {
        return true;
    }
    let foreign: Vec<RouteEntry> = routes.iter().filter(|r| !owns(r)).cloned().collect();
    nrr_platform_api::interface_rows::derive_forwarding_next_hop(&foreign, info.index).is_some()
}

/// Derive the **primary** routing target (gateway + interface) from the OS
/// default route, for when the user bound only a secondary (VPN) adapter.
///
/// Mode-A's `/2` counter-overlay (so unmatched traffic egresses the real link
/// instead of the tunnel) and mode-B's exception `/32`s both route via the
/// primary gateway. Requiring the user to *also* bind a primary just for this
/// is a footgun — "direct" silently kept unmatched traffic on the secondary
/// adapter. So when no primary is explicitly bound we fall back to the real
/// internet gateway: the lowest-metric `0.0.0.0/0` whose interface is NOT the
/// secondary and whose next-hop is a real address (the OS default-route
/// anchor the secondary adapter leaves on the physical NIC).
///
/// Failing that, an on-link `/0` (PPPoE has no gateway) routed via `0.0.0.0`,
/// as a bound gateway-less primary is — but never one on a `foreign_tunnels`
/// link, whose on-link `/0` would send "direct" traffic into someone else's
/// tunnel. Returns `None` when neither exists (e.g. a VPN that replaced `/0`
/// itself) — the caller then logs the actionable gap.
pub(crate) fn derive_primary_target(
    routes: &[RouteEntry],
    secondary_ifindex: u32,
    foreign_tunnels: &[u32],
) -> Option<SecondaryRouteTarget> {
    // (on-link, metric, gateway, ifindex): any gateway route outranks on-link.
    let mut best: Option<(bool, u32, Ipv4Addr, u32)> = None;
    for r in routes {
        if r.interface_index == secondary_ifindex {
            continue;
        }
        if !(r.destination.is_unspecified() && r.prefix_length == 0) {
            continue;
        }
        let IpAddr::V4(nh) = r.next_hop else {
            continue; // this probe names the IPv4 gateway
        };
        if nh.is_loopback() {
            continue;
        }
        let on_link = nh.is_unspecified();
        if on_link && (r.is_ours || foreign_tunnels.contains(&r.interface_index)) {
            continue;
        }
        let cand = (on_link, r.metric, nh, r.interface_index);
        best = Some(match best {
            Some(b) if (b.0, b.1) <= (cand.0, cand.1) => b,
            _ => cand,
        });
    }
    best.map(|(_, _, gateway, interface_index)| SecondaryRouteTarget {
        gateway,
        gateway_v6: derive_secondary_next_hop_v6(routes, interface_index),
        interface_index,
    })
}
