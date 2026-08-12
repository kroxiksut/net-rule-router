//! Neutral adapter rich-row types + deterministic enrichment.
//!
//! Owns the [`InterfaceRouteRow`] type and the pure enrichment that turns a
//! live adapter enumeration into the rows the GUI "Interfaces & routes" list
//! renders: observed connectivity facts, heuristic VPN/virtual/service
//! classification, a default (unknown) recommendation slot, the wire-DTO
//! projection, and the deterministic `fallback_rows` dataset. All of it is
//! OS-neutral (pure functions over `nrr-shared` value types). The live Windows
//! enumeration (`collect_interfaces_rows`, which reads the OS adapter table)
//! stays in `nrr-platform-windows` and re-exports these definitions.

use std::net::Ipv4Addr;

use nrr_shared::{
    ConnectivityState, DerivedLikelihood, ExternalIpStatus, RecommendationClass,
    RecommendationConfidence, RouteRole, RouteSelectionState,
};

use crate::external_ip::ExternalIpProbeOutcome;
use crate::types::RouteEntry;

/// Coarse availability bucket derived from the adapter `oper_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasicAvailabilityStatus {
    Available,
    Unavailable,
    RequiresCheck,
}

impl BasicAvailabilityStatus {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::RequiresCheck => "requires-check",
        }
    }
}

/// Provenance of the enriched row set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfacesDataSource {
    WindowsLive,
    FallbackMock,
}

impl InterfacesDataSource {
    pub const fn title(self) -> &'static str {
        match self {
            Self::WindowsLive => "windows-live",
            Self::FallbackMock => "fallback-mock",
        }
    }
}

/// One enriched adapter row consumed by the GUI list and the diagnostics
/// surfaces. `selected_role` / `route_state` start unbound here — the
/// preview layer (mock-backend) and the GUI re-apply user role bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceRouteRow {
    pub persistent_id: String,
    pub adapter_name: String,
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub is_bluetooth_like: bool,
    pub local_ip: String,
    pub gateway: String,
    pub dns_servers: String,
    pub has_default_route: bool,
    /// Whether traffic can actually be forwarded out of this interface: it
    /// exposes a classic gateway, OR the route table carries a default-style
    /// route on it with a real next-hop (see [`derive_forwarding_next_hop`]).
    ///
    /// [`Self::has_default_route`] cannot answer this — the enumeration
    /// derives it as "a gateway is present", so it says the same thing twice
    /// and reads `false` for every healthy gateway-less tunnel (OpenVPN /
    /// WireGuard install split-default routes instead of a gateway). This
    /// field is what separates "no way out" (host-only virtual adapter) from
    /// "no gateway, but routed" (the ordinary VPN case), and it is computed
    /// where the route table is available rather than guessed in the GUI.
    ///
    /// `None` = not evaluated (route table unavailable, or a row that came
    /// from a sender predating the field). Consumers must not read that as
    /// "unusable".
    pub has_forwarding_path: Option<bool>,
    pub availability_status: BasicAvailabilityStatus,
    pub observed_facts: ObservedInterfaceFacts,
    pub derived_assessment: DerivedInterfaceAssessment,
    pub recommendation: RouteRoleRecommendation,
    pub selected_role: Option<RouteRole>,
    pub route_state: RouteSelectionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedInterfaceFacts {
    pub connectivity_state: ConnectivityState,
    pub external_ip_status: ExternalIpStatus,
    pub external_ip: Option<String>,
    pub external_probe_attempted: bool,
    pub external_probe_note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedInterfaceAssessment {
    pub vpn_tunnel_likelihood: DerivedLikelihood,
    pub virtual_interface_likelihood: DerivedLikelihood,
    pub service_interface_likelihood: DerivedLikelihood,
    pub classification: String,
    pub confidence_percent: u8,
    pub heuristic_only: bool,
    pub signals: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRoleRecommendation {
    pub class: RecommendationClass,
    pub confidence: RecommendationConfidence,
    pub advisory_only: bool,
    pub summary: String,
    pub key_signals: Vec<String>,
    pub excluded_alternatives: Vec<String>,
}

/// Derive the next-hop traffic would leave `ifindex` through, for an adapter
/// that exposes **no** classic default gateway.
///
/// OpenVPN / WireGuard TUN links commonly install split-default routes
/// (`0.0.0.0/1` + `128.0.0.0/1`, or a plain `0.0.0.0/0`) pointing at the
/// tunnel **peer** instead of setting a gateway on the adapter, so
/// `GetAdaptersAddresses` reports an empty gateway list even though the link
/// is up and routing fine. Preference order, then lowest metric within a rank
/// (ties broken by the numerically-lowest next-hop, for determinism):
///
/// 1. a real default (`0.0.0.0/0`);
/// 2. a redirect-gateway split half (`0.0.0.0/1` / `128.0.0.0/1`);
/// 3. ANY other route with a real (non-unspecified, non-loopback) next-hop —
///    a last resort: with the catch-alls absent (VPN client
///    still installing them right after media-up, or stripped once the
///    routing layer owns the table and the service restarted, losing its
///    in-memory next-hop cache) the interface often still carries
///    gateway-style host routes through the SAME tunnel peer — including
///    routes this product installed earlier, whose next-hop was that peer.
///    On a point-to-point tunnel every gateway-style route names the one
///    peer, so recovering it from any of them is sound.
///
/// `None` means there is genuinely nowhere to forward to — an adapter whose
/// routes are all on-link (the host-only virtual-adapter shape, and a freshly
/// connected tunnel before its client has installed any gateway route).
///
/// Single source of truth: both the routing layer (which installs overlays
/// through this next-hop) and the interface enumeration (which reports
/// [`InterfaceRouteRow::has_forwarding_path`]) call this one function, so the
/// GUI can never describe an adapter as unusable that the router would happily
/// route through.
pub fn derive_forwarding_next_hop(routes: &[RouteEntry], ifindex: u32) -> Option<Ipv4Addr> {
    let mut best: Option<(u8, u32, u32)> = None;
    for r in routes {
        if r.interface_index != ifindex {
            continue;
        }
        let nh = r.next_hop;
        if nh.is_unspecified() || nh.is_loopback() {
            continue;
        }
        // Rank by how "default" the route is (see the doc comment).
        let pref = match (r.destination, r.prefix_length) {
            (d, 0) if d.is_unspecified() => 0u8,
            (d, 1) if d.is_unspecified() => 1, // 0.0.0.0/1
            (d, 1) if d == Ipv4Addr::new(128, 0, 0, 0) => 1, // 128.0.0.0/1
            _ => 2,                            // any other gateway-style route
        };
        let cand = (pref, r.metric, u32::from(nh));
        best = Some(match best {
            Some(b) if b <= cand => b,
            _ => cand,
        });
    }
    best.map(|(_, _, nh)| Ipv4Addr::from(nh))
}

/// Build the observed-facts block from local route metadata. Performs no
/// I/O: connectivity is inferred from the presence of a local IP and a
/// gateway, so `external_ip_status` always starts out `NotChecked`.
///
/// The external-address probe is a separate, explicit step: an enumeration
/// must never reach the network by itself. A caller that has the user's
/// request to probe runs [`crate::external_ip::probe_external_ipv4_batch`]
/// over the [`external_probe_target`]s and folds the outcomes back in with
/// [`apply_external_probe`].
pub fn build_observed_facts(
    availability_status: BasicAvailabilityStatus,
    local_ip: &str,
    gateway: &str,
) -> ObservedInterfaceFacts {
    let connectivity_state = match availability_status {
        BasicAvailabilityStatus::Unavailable => ConnectivityState::Unavailable,
        BasicAvailabilityStatus::RequiresCheck => ConnectivityState::Unknown,
        BasicAvailabilityStatus::Available => {
            if local_ip == "-" {
                ConnectivityState::Unknown
            } else if gateway == "-" {
                ConnectivityState::Degraded
            } else {
                ConnectivityState::Available
            }
        }
    };

    ObservedInterfaceFacts {
        connectivity_state,
        external_ip_status: ExternalIpStatus::NotChecked,
        external_ip: None,
        external_probe_attempted: false,
        external_probe_note:
            "External probe is optional; snapshot uses local checks when probe is skipped."
                .to_string(),
    }
}

/// Decide whether an adapter is worth probing and, if so, which source
/// address the probe should bind to. Pure — the decision is the policy half
/// of the probe and is tested without a socket in sight.
///
/// An adapter that is not up, or whose address the stack cannot source
/// outbound traffic from, would only buy a guaranteed timeout: probing it
/// would spend the whole budget to learn nothing, and would slow down the
/// adapters that can actually answer.
#[must_use]
pub fn external_probe_target(
    availability_status: BasicAvailabilityStatus,
    local_ip: &str,
) -> Option<Ipv4Addr> {
    if availability_status != BasicAvailabilityStatus::Available {
        return None;
    }
    let address = local_ip.trim().parse::<Ipv4Addr>().ok()?;
    if address.is_unspecified()
        || address.is_loopback()
        // 169.254.0.0/16 means DHCP never answered — there is no path out.
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
    {
        return None;
    }
    Some(address)
}

/// Fold a probe outcome into an adapter's observed facts. Pure and total:
/// every outcome, including "never tried", produces a coherent status, note
/// and address triple, so the row can never claim an address it did not see.
pub fn apply_external_probe(facts: &mut ObservedInterfaceFacts, outcome: ExternalIpProbeOutcome) {
    facts.external_ip_status = outcome.status();
    facts.external_ip = outcome.address().map(|address| address.to_string());
    facts.external_probe_attempted = outcome.was_attempted();
    facts.external_probe_note = outcome.note().to_string();
}

#[allow(clippy::too_many_arguments)]
pub fn build_derived_assessment(
    windows_name: &str,
    interface_type: &str,
    interface_description: &str,
    adapter_name: &str,
    gateway: &str,
    local_ip: &str,
    has_default_route: bool,
    observed_connectivity: ConnectivityState,
) -> DerivedInterfaceAssessment {
    let mut signals = Vec::new();
    let haystack = format!(
        "{} {} {} {}",
        windows_name, interface_type, interface_description, adapter_name
    )
    .to_ascii_lowercase();

    let mut vpn_score = 0;
    // Shared with the traffic counter's tunnel-overlap classification (block
    // T) via `crate::adapters::VPN_TUNNEL_ADAPTER_MARKERS` — one definition
    // of "this text reads as a VPN adapter".
    if contains_any(&haystack, crate::adapters::VPN_TUNNEL_ADAPTER_MARKERS) {
        vpn_score += 2;
        signals.push("vpn_tunnel_marker_in_name_or_type".to_string());
    }
    if interface_type.to_ascii_lowercase().contains("tunnel") {
        vpn_score += 1;
        signals.push("interface_type_tunnel".to_string());
    }
    if gateway == "-" && local_ip != "-" {
        vpn_score += 1;
        signals.push("gateway_missing_with_local_ip".to_string());
    }

    let mut virtual_score = 0;
    if contains_any(
        &haystack,
        &[
            "virtual",
            "vmware",
            "vbox",
            "hyper-v",
            "host-only",
            "loopback",
            "docker",
        ],
    ) {
        virtual_score += 2;
        signals.push("virtual_marker_in_name_or_description".to_string());
    }
    if interface_type.to_ascii_lowercase().contains("loopback") {
        virtual_score += 2;
        signals.push("interface_type_loopback".to_string());
    }
    if !has_default_route && matches!(observed_connectivity, ConnectivityState::Unavailable) {
        virtual_score += 1;
        signals.push("no_default_route_and_unavailable".to_string());
    }

    let mut service_score = 0;
    if contains_any(&haystack, &["loopback", "isatap", "teredo", "pseudo"]) {
        service_score += 2;
        signals.push("service_marker_in_name_or_description".to_string());
    }
    if !has_default_route && gateway == "-" && local_ip == "-" {
        service_score += 1;
        signals.push("no_gateway_dns_or_local_ip".to_string());
    }
    if matches!(
        observed_connectivity,
        ConnectivityState::Unknown | ConnectivityState::Unavailable
    ) {
        service_score += 1;
        signals.push("low_connectivity_confirms_service_risk".to_string());
    }

    let vpn_tunnel_likelihood = likelihood_from_score(vpn_score);
    let virtual_interface_likelihood = likelihood_from_score(virtual_score);
    let service_interface_likelihood = likelihood_from_score(service_score);
    let max_score = vpn_score.max(virtual_score).max(service_score);

    let classification = if max_score == 0 {
        "regular-interface"
    } else if vpn_score >= virtual_score && vpn_score >= service_score {
        "vpn-or-tunnel-likely"
    } else if virtual_score >= service_score {
        "virtual-interface-likely"
    } else {
        "service-interface-likely"
    }
    .to_string();

    let confidence_percent = match max_score {
        0 => 30,
        1 => 50,
        2 => 70,
        _ => 85,
    };

    DerivedInterfaceAssessment {
        vpn_tunnel_likelihood,
        virtual_interface_likelihood,
        service_interface_likelihood,
        classification,
        confidence_percent,
        heuristic_only: true,
        signals,
    }
}

/// Default recommendation for a freshly-collected row. The preview layer
/// overwrites this with a scored recommendation; the service path leaves
/// it as-is (the GUI does not score on a live refresh).
pub fn unknown_recommendation() -> RouteRoleRecommendation {
    RouteRoleRecommendation {
        class: RecommendationClass::AllowedButNotRecommended,
        confidence: RecommendationConfidence::Unknown,
        advisory_only: true,
        summary: "Recommendation pending heuristic evaluation".to_string(),
        key_signals: Vec::new(),
        excluded_alternatives: Vec::new(),
    }
}

fn likelihood_from_score(score: u8) -> DerivedLikelihood {
    match score {
        0 => DerivedLikelihood::Unlikely,
        1 => DerivedLikelihood::Possible,
        _ => DerivedLikelihood::Likely,
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

/// Heuristic Bluetooth-PAN classification from an adapter's display strings.
/// Pure/neutral; `pub` so the Windows live enumeration can consume it.
pub fn is_bluetooth_like_interface(
    windows_name: &str,
    interface_description: &str,
    adapter_name: &str,
) -> bool {
    let haystack = format!(
        "{} {} {}",
        windows_name, interface_description, adapter_name
    )
    .to_ascii_lowercase();
    contains_any(
        &haystack,
        &["bluetooth", "bt-pan", "personal area network", "pan"],
    )
}

/// Deterministic adapter dataset used when no live Windows enumeration is
/// available (off-Windows builds, dev/test, empty enumeration).
pub fn fallback_rows() -> Vec<InterfaceRouteRow> {
    let mut ethernet_observed = build_observed_facts(
        BasicAvailabilityStatus::Available,
        "192.168.1.20",
        "192.168.1.1",
    );
    ethernet_observed.external_ip_status = ExternalIpStatus::Resolved;
    ethernet_observed.external_ip = Some("203.0.113.10".to_string());
    ethernet_observed.external_probe_attempted = true;
    ethernet_observed.external_probe_note =
        "External probe succeeded in deterministic fallback dataset.".to_string();
    let ethernet_derived = build_derived_assessment(
        "Ethernet",
        "Ethernet",
        "Fallback Ethernet adapter",
        "{FAKE-ETHERNET-ADAPTER}",
        "192.168.1.1",
        "192.168.1.20",
        true,
        ethernet_observed.connectivity_state,
    );

    let wifi_observed = build_observed_facts(
        BasicAvailabilityStatus::Available,
        "10.10.0.15",
        "10.10.0.1",
    );
    let wifi_derived = build_derived_assessment(
        "Wi-Fi",
        "Wireless",
        "Fallback Wi-Fi adapter",
        "{FAKE-WIFI-ADAPTER}",
        "10.10.0.1",
        "10.10.0.15",
        true,
        wifi_observed.connectivity_state,
    );

    let vpn_observed = build_observed_facts(BasicAvailabilityStatus::RequiresCheck, "-", "-");
    let vpn_derived = build_derived_assessment(
        "VPN",
        "Tunnel",
        "Fallback VPN tunnel",
        "{FAKE-VPN-ADAPTER}",
        "-",
        "-",
        false,
        vpn_observed.connectivity_state,
    );
    let bluetooth_observed = build_observed_facts(
        BasicAvailabilityStatus::Available,
        "172.20.10.5",
        "172.20.10.1",
    );
    let bluetooth_derived = build_derived_assessment(
        "Bluetooth PAN",
        "Wireless",
        "Bluetooth Personal Area Network",
        "{FAKE-BLUETOOTH-PAN-ADAPTER}",
        "172.20.10.1",
        "172.20.10.5",
        true,
        bluetooth_observed.connectivity_state,
    );

    vec![
        InterfaceRouteRow {
            persistent_id: "win-adapter:ethernet-fallback".to_string(),
            adapter_name: "{FAKE-ETHERNET-ADAPTER}".to_string(),
            windows_name: "Ethernet".to_string(),
            interface_description: "Fallback Ethernet adapter".to_string(),
            interface_type: "Ethernet".to_string(),
            is_bluetooth_like: false,
            local_ip: "192.168.1.20".to_string(),
            gateway: "192.168.1.1".to_string(),
            dns_servers: "1.1.1.1, 8.8.8.8".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            availability_status: BasicAvailabilityStatus::Available,
            observed_facts: ethernet_observed,
            derived_assessment: ethernet_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
        InterfaceRouteRow {
            persistent_id: "win-adapter:wifi-fallback".to_string(),
            adapter_name: "{FAKE-WIFI-ADAPTER}".to_string(),
            windows_name: "Wi-Fi".to_string(),
            interface_description: "Fallback Wi-Fi adapter".to_string(),
            interface_type: "Wireless".to_string(),
            is_bluetooth_like: false,
            local_ip: "10.10.0.15".to_string(),
            gateway: "10.10.0.1".to_string(),
            dns_servers: "9.9.9.9".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            availability_status: BasicAvailabilityStatus::Available,
            observed_facts: wifi_observed,
            derived_assessment: wifi_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
        InterfaceRouteRow {
            persistent_id: "win-adapter:vpn-fallback".to_string(),
            adapter_name: "{FAKE-VPN-ADAPTER}".to_string(),
            windows_name: "VPN".to_string(),
            interface_description: "Fallback VPN tunnel".to_string(),
            interface_type: "Tunnel".to_string(),
            is_bluetooth_like: false,
            local_ip: "-".to_string(),
            gateway: "-".to_string(),
            dns_servers: "-".to_string(),
            has_default_route: false,
            has_forwarding_path: Some(false),
            availability_status: BasicAvailabilityStatus::RequiresCheck,
            observed_facts: vpn_observed,
            derived_assessment: vpn_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::RequiresVerification,
        },
        InterfaceRouteRow {
            persistent_id: "win-adapter:bluetooth-pan-fallback".to_string(),
            adapter_name: "{FAKE-BLUETOOTH-PAN-ADAPTER}".to_string(),
            windows_name: "Bluetooth PAN".to_string(),
            interface_description: "Bluetooth Personal Area Network".to_string(),
            interface_type: "Wireless".to_string(),
            is_bluetooth_like: true,
            local_ip: "172.20.10.5".to_string(),
            gateway: "172.20.10.1".to_string(),
            dns_servers: "8.8.4.4".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            availability_status: BasicAvailabilityStatus::Available,
            observed_facts: bluetooth_observed,
            derived_assessment: bluetooth_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
    ]
}

// ── Wire-DTO mapping ──────────────────────────────────────────────────────────

impl From<&InterfaceRouteRow> for nrr_shared::ipc_payloads::InterfaceRowDto {
    /// Project an enriched row into the kebab-case wire DTO. Slug strings
    /// match the cold-start `interface_rows_json` shape one-to-one so the
    /// GUI renders a live-refresh row exactly like a cold-start one.
    fn from(row: &InterfaceRouteRow) -> Self {
        nrr_shared::ipc_payloads::InterfaceRowDto {
            persistent_id: row.persistent_id.clone(),
            adapter_name: row.adapter_name.clone(),
            windows_name: row.windows_name.clone(),
            interface_description: row.interface_description.clone(),
            interface_type: row.interface_type.clone(),
            is_bluetooth_like: row.is_bluetooth_like,
            local_ip: row.local_ip.clone(),
            gateway: row.gateway.clone(),
            dns_servers: row.dns_servers.clone(),
            has_default_route: row.has_default_route,
            has_forwarding_path: row.has_forwarding_path,
            availability: row.availability_status.title().to_string(),
            selected_role: row.selected_role.map(|role| match role {
                RouteRole::Primary => "primary".to_string(),
                RouteRole::Secondary => "secondary".to_string(),
            }),
            route_state: row.route_state.title().to_string(),
            observed_facts: nrr_shared::ipc_payloads::InterfaceObservedFactsDto {
                connectivity_state: row.observed_facts.connectivity_state.title().to_string(),
                external_ip_status: row.observed_facts.external_ip_status.title().to_string(),
                external_ip: row.observed_facts.external_ip.clone(),
                external_probe_attempted: row.observed_facts.external_probe_attempted,
                external_probe_note: row.observed_facts.external_probe_note.clone(),
            },
            derived_assessment: nrr_shared::ipc_payloads::InterfaceDerivedAssessmentDto {
                vpn_tunnel_likelihood: row
                    .derived_assessment
                    .vpn_tunnel_likelihood
                    .title()
                    .to_string(),
                virtual_interface_likelihood: row
                    .derived_assessment
                    .virtual_interface_likelihood
                    .title()
                    .to_string(),
                service_interface_likelihood: row
                    .derived_assessment
                    .service_interface_likelihood
                    .title()
                    .to_string(),
                classification: row.derived_assessment.classification.clone(),
                confidence_percent: row.derived_assessment.confidence_percent,
                heuristic_only: row.derived_assessment.heuristic_only,
                signals: row.derived_assessment.signals.clone(),
            },
            recommendation: nrr_shared::ipc_payloads::InterfaceRecommendationDto {
                class: row.recommendation.class.title().to_string(),
                confidence: row.recommendation.confidence.title().to_string(),
                advisory_only: row.recommendation.advisory_only,
                summary: row.recommendation.summary.clone(),
                key_signals: row.recommendation.key_signals.clone(),
                excluded_alternatives: row.recommendation.excluded_alternatives.clone(),
            },
        }
    }
}

impl InterfaceRouteRow {
    /// Reconstruct an enriched row from its wire DTO. Display and
    /// scoring-input fields (identity, IP/gateway/DNS, availability,
    /// observed connectivity, derived classification) are faithfully
    /// parsed back from their slug form. The *decoration* slots —
    /// `recommendation`, `selected_role`, `route_state` — are reset to
    /// their undecorated defaults: the IPC facade re-runs the advisory
    /// recommendation engine and re-applies the user's role bindings via
    /// `decorate_interface_rows`, so the service-sourced row ends up
    /// decorated exactly like a locally-enumerated one (the service does
    /// not run the preview engine itself).
    pub fn from_wire_dto(dto: &nrr_shared::ipc_payloads::InterfaceRowDto) -> Self {
        InterfaceRouteRow {
            persistent_id: dto.persistent_id.clone(),
            adapter_name: dto.adapter_name.clone(),
            windows_name: dto.windows_name.clone(),
            interface_description: dto.interface_description.clone(),
            interface_type: dto.interface_type.clone(),
            is_bluetooth_like: dto.is_bluetooth_like,
            local_ip: dto.local_ip.clone(),
            gateway: dto.gateway.clone(),
            dns_servers: dto.dns_servers.clone(),
            has_default_route: dto.has_default_route,
            has_forwarding_path: dto.has_forwarding_path,
            availability_status: availability_status_from_slug(&dto.availability),
            observed_facts: ObservedInterfaceFacts {
                connectivity_state: connectivity_state_from_slug(
                    &dto.observed_facts.connectivity_state,
                ),
                external_ip_status: external_ip_status_from_slug(
                    &dto.observed_facts.external_ip_status,
                ),
                external_ip: dto.observed_facts.external_ip.clone(),
                external_probe_attempted: dto.observed_facts.external_probe_attempted,
                external_probe_note: dto.observed_facts.external_probe_note.clone(),
            },
            derived_assessment: DerivedInterfaceAssessment {
                vpn_tunnel_likelihood: likelihood_from_slug(
                    &dto.derived_assessment.vpn_tunnel_likelihood,
                ),
                virtual_interface_likelihood: likelihood_from_slug(
                    &dto.derived_assessment.virtual_interface_likelihood,
                ),
                service_interface_likelihood: likelihood_from_slug(
                    &dto.derived_assessment.service_interface_likelihood,
                ),
                classification: dto.derived_assessment.classification.clone(),
                confidence_percent: dto.derived_assessment.confidence_percent,
                heuristic_only: dto.derived_assessment.heuristic_only,
                signals: dto.derived_assessment.signals.clone(),
            },
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        }
    }
}

fn availability_status_from_slug(slug: &str) -> BasicAvailabilityStatus {
    match slug {
        "available" => BasicAvailabilityStatus::Available,
        "unavailable" => BasicAvailabilityStatus::Unavailable,
        // "requires-check" and any unknown slug map to the conservative
        // "needs a check" bucket so the preview engine never over-trusts.
        _ => BasicAvailabilityStatus::RequiresCheck,
    }
}

fn connectivity_state_from_slug(slug: &str) -> ConnectivityState {
    match slug {
        "available" => ConnectivityState::Available,
        "degraded" => ConnectivityState::Degraded,
        "unavailable" => ConnectivityState::Unavailable,
        "timeout" => ConnectivityState::Timeout,
        _ => ConnectivityState::Unknown,
    }
}

fn external_ip_status_from_slug(slug: &str) -> ExternalIpStatus {
    match slug {
        "resolved" => ExternalIpStatus::Resolved,
        "check-failed" => ExternalIpStatus::CheckFailed,
        "rate-limited" => ExternalIpStatus::RateLimited,
        "blocked" => ExternalIpStatus::Blocked,
        _ => ExternalIpStatus::NotChecked,
    }
}

fn likelihood_from_slug(slug: &str) -> DerivedLikelihood {
    match slug {
        "likely" => DerivedLikelihood::Likely,
        "possible" => DerivedLikelihood::Possible,
        "unlikely" => DerivedLikelihood::Unlikely,
        _ => DerivedLikelihood::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(
        dest: [u8; 4],
        prefix: u8,
        next_hop: [u8; 4],
        ifindex: u32,
        metric: u32,
    ) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: prefix,
            next_hop: Ipv4Addr::from(next_hop),
            interface_index: ifindex,
            metric,
            is_ours: false,
            table: crate::RouteTableRef::Main,
        }
    }

    #[test]
    fn a_gateway_less_tunnel_forwards_through_its_split_default_routes() {
        // The shape a live OpenVPN link leaves behind: no adapter gateway, but
        // `0.0.0.0/1` + `128.0.0.0/1` pointing at the tunnel peer. The GUI must
        // see this as usable, not as "nowhere to forward to" — the whole reason
        // this signal exists instead of reading `has_default_route`.
        let routes = vec![
            route([0, 0, 0, 0], 1, [10, 91, 192, 1], 23, 1),
            route([128, 0, 0, 0], 1, [10, 91, 192, 1], 23, 1),
            route([10, 91, 193, 99], 32, [0, 0, 0, 0], 23, 256), // on-link, ignored
        ];
        assert_eq!(
            derive_forwarding_next_hop(&routes, 23),
            Some(Ipv4Addr::new(10, 91, 192, 1))
        );
    }

    #[test]
    fn a_host_only_adapter_with_only_on_link_routes_has_nowhere_to_forward() {
        // The VirtualBox host-only shape: an on-link subnet route and nothing
        // else. This is the case the warning is actually for.
        let routes = vec![
            route([192, 168, 56, 0], 24, [0, 0, 0, 0], 15, 256),
            route([0, 0, 0, 0], 0, [192, 168, 0, 1], 17, 25), // another interface
        ];
        assert_eq!(derive_forwarding_next_hop(&routes, 15), None);
    }

    #[test]
    fn a_real_default_route_outranks_the_split_halves_and_metric_breaks_ties() {
        let routes = vec![
            route([0, 0, 0, 0], 1, [10, 0, 0, 1], 5, 1),
            route([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50),
        ];
        assert_eq!(
            derive_forwarding_next_hop(&routes, 5),
            Some(Ipv4Addr::new(10, 0, 0, 9)),
            "a real /0 wins over a /1 half even with a worse metric"
        );
        let tie = vec![
            route([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50),
            route([0, 0, 0, 0], 0, [10, 0, 0, 3], 5, 10),
        ];
        assert_eq!(
            derive_forwarding_next_hop(&tie, 5),
            Some(Ipv4Addr::new(10, 0, 0, 3))
        );
    }

    #[test]
    fn a_loopback_or_unspecified_next_hop_never_counts_as_a_way_out() {
        let routes = vec![
            route([0, 0, 0, 0], 0, [127, 0, 0, 1], 5, 1),
            route([0, 0, 0, 0], 1, [0, 0, 0, 0], 5, 1),
        ];
        assert_eq!(derive_forwarding_next_hop(&routes, 5), None);
    }

    #[test]
    fn a_tunnel_with_only_on_link_routes_derives_nothing_yet() {
        // hidemy.name OpenVPN, 10.88.1.41/24, ifindex 60: the
        // adapter is Up with IPv4 but the client has not yet installed any
        // gateway route — the table holds only on-link entries. There is
        // genuinely nothing to derive; the state resolves itself seconds
        // later when the client installs its split-default catch-alls.
        let routes = vec![
            route([10, 88, 1, 0], 24, [0, 0, 0, 0], 60, 256),
            route([10, 88, 1, 41], 32, [0, 0, 0, 0], 60, 256),
            route([0, 0, 0, 0], 0, [192, 168, 0, 1], 16, 25), // primary NIC
        ];
        assert_eq!(derive_forwarding_next_hop(&routes, 60), None);
    }

    #[test]
    fn a_gateway_style_host_route_recovers_the_peer_when_catch_alls_are_absent() {
        // Same tunnel after the routing layer stripped the VPN's catch-alls
        // and (say) a service restart lost the in-memory next-hop cache: the
        // /32 overlays installed earlier still name the tunnel peer, so the
        // last-resort rank recovers 10.88.0.1 from them.
        let routes = vec![
            route([10, 88, 1, 0], 24, [0, 0, 0, 0], 60, 256), // on-link, ignored
            route([142, 250, 74, 78], 32, [10, 88, 0, 1], 60, 5),
            route([13, 107, 42, 14], 32, [10, 88, 0, 1], 60, 5),
            route([0, 0, 0, 0], 0, [192, 168, 0, 1], 16, 25), // primary NIC
        ];
        assert_eq!(
            derive_forwarding_next_hop(&routes, 60),
            Some(Ipv4Addr::new(10, 88, 0, 1))
        );
    }

    #[test]
    fn catch_all_routes_outrank_the_last_resort_host_routes() {
        // A live split-default names the CURRENT peer; stale host routes from
        // a previous session must never outvote it, whatever their metric.
        let routes = vec![
            route([142, 250, 74, 78], 32, [10, 88, 0, 1], 60, 1), // stale peer
            route([0, 0, 0, 0], 1, [10, 89, 0, 1], 60, 30),       // current peer
            route([128, 0, 0, 0], 1, [10, 89, 0, 1], 60, 30),
        ];
        assert_eq!(
            derive_forwarding_next_hop(&routes, 60),
            Some(Ipv4Addr::new(10, 89, 0, 1))
        );
    }

    #[test]
    fn fallback_rows_are_deterministic_and_enriched() {
        let rows = fallback_rows();
        assert_eq!(rows.len(), 4);
        let vpn = rows
            .iter()
            .find(|r| r.windows_name == "VPN")
            .expect("vpn row");
        assert_eq!(
            vpn.derived_assessment.vpn_tunnel_likelihood,
            DerivedLikelihood::Likely
        );
        assert!(vpn.derived_assessment.heuristic_only);
        assert_eq!(
            vpn.observed_facts.external_ip_status,
            ExternalIpStatus::NotChecked
        );
    }

    #[test]
    fn only_a_live_adapter_with_a_routable_address_is_probed() {
        assert_eq!(
            external_probe_target(BasicAvailabilityStatus::Available, "192.168.1.20"),
            Some(Ipv4Addr::new(192, 168, 1, 20)),
            "a private LAN address is the normal case — NAT is what we ask about"
        );
        assert_eq!(
            external_probe_target(BasicAvailabilityStatus::Available, " 10.10.0.15 "),
            Some(Ipv4Addr::new(10, 10, 0, 15)),
            "surrounding whitespace must not disqualify an adapter"
        );

        for unusable in [
            "-",           // the enumeration's "no address" marker
            "",            //
            "127.0.0.1",   // loopback
            "0.0.0.0",     // unspecified
            "169.254.4.7", // APIPA: DHCP never answered
            "224.0.0.1",   // multicast
            "255.255.255.255",
            "fe80::1", // IPv6: the probe binds an IPv4 source
            "not-an-address",
        ] {
            assert_eq!(
                external_probe_target(BasicAvailabilityStatus::Available, unusable),
                None,
                "{unusable} must not be probed"
            );
        }

        for status in [
            BasicAvailabilityStatus::Unavailable,
            BasicAvailabilityStatus::RequiresCheck,
        ] {
            assert_eq!(
                external_probe_target(status, "192.168.1.20"),
                None,
                "{status:?} adapters must not be probed"
            );
        }
    }

    #[test]
    fn probe_outcomes_fold_into_honest_observed_facts() {
        let base =
            || build_observed_facts(BasicAvailabilityStatus::Available, "10.0.0.2", "10.0.0.1");

        let mut resolved = base();
        apply_external_probe(
            &mut resolved,
            ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(203, 0, 113, 10)),
        );
        assert_eq!(resolved.external_ip_status, ExternalIpStatus::Resolved);
        assert_eq!(resolved.external_ip.as_deref(), Some("203.0.113.10"));
        assert!(resolved.external_probe_attempted);

        // A VPN or split-tunnel adapter with no reachable path degrades to a
        // failed check — never to a stale or borrowed address.
        let mut unreachable = base();
        apply_external_probe(&mut unreachable, ExternalIpProbeOutcome::Unreachable);
        assert_eq!(
            unreachable.external_ip_status,
            ExternalIpStatus::CheckFailed
        );
        assert_eq!(unreachable.external_ip, None);
        assert!(unreachable.external_probe_attempted);

        let mut blocked = base();
        apply_external_probe(&mut blocked, ExternalIpProbeOutcome::LocallyBlocked);
        assert_eq!(blocked.external_ip_status, ExternalIpStatus::Blocked);
        assert_eq!(blocked.external_ip, None);

        let mut skipped = base();
        apply_external_probe(&mut skipped, ExternalIpProbeOutcome::Skipped);
        assert_eq!(skipped.external_ip_status, ExternalIpStatus::NotChecked);
        assert_eq!(skipped.external_ip, None);
        assert!(!skipped.external_probe_attempted);
    }

    #[test]
    fn a_resolved_row_survives_the_wire_round_trip() {
        let mut row = fallback_rows()
            .into_iter()
            .find(|r| r.windows_name == "Wi-Fi")
            .expect("wifi row");
        apply_external_probe(
            &mut row.observed_facts,
            ExternalIpProbeOutcome::Resolved(Ipv4Addr::new(198, 51, 100, 7)),
        );
        let dto = nrr_shared::ipc_payloads::InterfaceRowDto::from(&row);
        assert_eq!(dto.observed_facts.external_ip_status, "resolved");
        assert_eq!(
            dto.observed_facts.external_ip.as_deref(),
            Some("198.51.100.7")
        );

        let back = InterfaceRouteRow::from_wire_dto(&dto);
        assert_eq!(
            back.observed_facts.external_ip_status,
            ExternalIpStatus::Resolved
        );
        assert_eq!(
            back.observed_facts.external_ip.as_deref(),
            Some("198.51.100.7")
        );
        assert!(back.observed_facts.external_probe_attempted);
    }

    #[test]
    fn dto_projection_matches_cold_start_slug_shape() {
        let rows = fallback_rows();
        let ethernet = rows
            .iter()
            .find(|r| r.windows_name == "Ethernet")
            .expect("ethernet row");
        let dto = nrr_shared::ipc_payloads::InterfaceRowDto::from(ethernet);
        assert_eq!(dto.windows_name, "Ethernet");
        assert_eq!(dto.availability, "available");
        assert_eq!(dto.route_state, "not-selected");
        assert_eq!(dto.selected_role, None);
        assert_eq!(dto.observed_facts.external_ip_status, "resolved");
        assert_eq!(dto.derived_assessment.classification, "regular-interface");
        // kebab-case wire round-trip preserves the nested shape.
        let json = serde_json::to_value(&dto).expect("serialize");
        assert_eq!(json["windows-name"], "Ethernet");
        assert_eq!(json["has-default-route"], true);
        assert_eq!(json["observed-facts"]["external-ip-status"], "resolved");
        assert_eq!(
            json["derived-assessment"]["vpn-tunnel-likelihood"],
            "unlikely"
        );
    }

    #[test]
    fn wire_dto_round_trip_preserves_display_and_scoring_fields() {
        let rows = fallback_rows();
        let vpn = rows
            .iter()
            .find(|r| r.windows_name == "VPN")
            .expect("vpn row");
        let dto = nrr_shared::ipc_payloads::InterfaceRowDto::from(vpn);
        let back = InterfaceRouteRow::from_wire_dto(&dto);

        // Identity + display fields survive the slug round-trip.
        assert_eq!(back.persistent_id, vpn.persistent_id);
        assert_eq!(back.windows_name, "VPN");
        assert_eq!(back.interface_type, vpn.interface_type);
        assert_eq!(back.dns_servers, vpn.dns_servers);
        assert_eq!(back.is_bluetooth_like, vpn.is_bluetooth_like);
        // Scoring-input enums are faithfully parsed back.
        assert_eq!(back.availability_status, vpn.availability_status);
        assert_eq!(
            back.observed_facts.connectivity_state,
            vpn.observed_facts.connectivity_state
        );
        assert_eq!(
            back.derived_assessment.vpn_tunnel_likelihood,
            vpn.derived_assessment.vpn_tunnel_likelihood
        );
        // Decoration slots are reset for the caller to re-apply.
        assert_eq!(back.selected_role, None);
        assert_eq!(back.route_state, RouteSelectionState::NotSelected);
    }
}
