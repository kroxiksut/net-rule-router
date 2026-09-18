// Turning observed facts into an assessment and a route-role recommendation.

use super::*;

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
