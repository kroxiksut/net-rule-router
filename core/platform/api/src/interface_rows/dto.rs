// Conversion to the wire DTO and back from its slugs.

use super::*;

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
            runtime_data_unavailable: row.runtime_data_unavailable,
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
            runtime_data_unavailable: dto.runtime_data_unavailable,
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
