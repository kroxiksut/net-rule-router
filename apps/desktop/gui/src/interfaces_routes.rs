use nrr_application::backend_facade::network_interfaces::{
    interfaces_routes_preview_snapshot, RouteSelectionRequest,
};
use nrr_shared::{AppShellModel, InterfaceFieldId, RouteRole};

pub fn render_interfaces_and_routes_screen(shell: &AppShellModel) {
    let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());

    println!("Interfaces and routes screen (block 2 preview):");
    println!("- Data source: {}", snapshot.data_source.title());
    println!("- {}", snapshot.preview_notice);
    println!("- {}", snapshot.role_explanation);
    println!("- {}", snapshot.data_scope_note);
    println!(
        "- Selected behavior mode: {}",
        snapshot.selected_behavior_mode.user_label()
    );
    let modes = snapshot
        .supported_behavior_modes
        .iter()
        .map(|mode| mode.user_label())
        .collect::<Vec<_>>()
        .join(", ");
    println!("- Available behavior modes: {}", modes);
    println!(
        "- Shared preview policy: {}",
        shell.interfaces_routes.preview_notice
    );
    println!(
        "- Roles policy: primary='{}', secondary='{}'",
        RouteRole::Primary.user_label(),
        RouteRole::Secondary.user_label()
    );
    println!(
        "- Diagnostics/explain alignment: {}",
        shell.interfaces_routes.diagnostics_alignment_note
    );
    println!(
        "- Recommendation policy: {}",
        snapshot.recommendation_policy_note
    );
    println!(
        "- Show Bluetooth adapters by default: {}",
        shell.interfaces_routes.show_bluetooth_adapters_default
    );
    println!(
        "- Bluetooth recommendation policy: {}",
        shell.interfaces_routes.bluetooth_recommendation_policy
    );
    println!(
        "- Bluetooth detection signals: {}",
        shell
            .interfaces_routes
            .bluetooth_detection_signals
            .join(", ")
    );
    println!(
        "- Manual confirmation required: {}",
        snapshot
            .role_assignment_advisory
            .manual_confirmation_required
    );
    println!(
        "- User choice priority: {}",
        snapshot.role_assignment_advisory.user_choice_priority_note
    );
    if let Some(conflict) = snapshot
        .role_assignment_advisory
        .conflict_warning
        .as_deref()
    {
        println!("- Conflict warning: {conflict}");
    }
    for warning in &snapshot.role_assignment_advisory.warnings {
        println!("- Role warning: {warning}");
    }
    println!(
        "- Unknown marker: '{}'",
        shell.interfaces_routes.display_format.unknown_value_marker
    );
    println!(
        "- Observed vs derived boundary: {}",
        shell.interfaces_routes.observed_vs_derived_boundary
    );
    println!(
        "- Role conflict policy: {}",
        shell.interfaces_routes.role_conflict_policy
    );
    println!(
        "- Confirmed choice priority policy: {}",
        shell.interfaces_routes.confirmed_choice_priority_policy
    );
    println!(
        "- Connectivity checks policy: local_only={} external_probe={} timeout_ms={} retries={} min_refresh_s={} offline_behavior={}",
        shell.interfaces_routes
            .connectivity_checks_policy
            .local_checks_without_network_probe,
        shell.interfaces_routes
            .connectivity_checks_policy
            .external_probe_allowed,
        shell.interfaces_routes.connectivity_checks_policy.probe_timeout_ms,
        shell.interfaces_routes.connectivity_checks_policy.max_probe_retries,
        shell.interfaces_routes
            .connectivity_checks_policy
            .min_refresh_interval_seconds,
        shell.interfaces_routes
            .connectivity_checks_policy
            .offline_mode_behavior
    );
    println!("- Interfaces:");
    for row in &snapshot.rows {
        println!("  {}", format_interface_row_for_contract(shell, row));
    }
}

pub fn format_interface_row_for_contract(
    shell: &AppShellModel,
    row: &nrr_application::backend_facade::network_interfaces::InterfaceRouteRow,
) -> String {
    let unknown = shell.interfaces_routes.display_format.unknown_value_marker;
    let role = match row.selected_role {
        Some(RouteRole::Primary) => "primary",
        Some(RouteRole::Secondary) => "secondary",
        None => unknown,
    };

    let mut chunks = Vec::new();
    for field in shell.interfaces_routes.display_format.ordered_fields {
        let value = match field {
            InterfaceFieldId::WindowsName => value_or_unknown(&row.windows_name, unknown),
            InterfaceFieldId::InterfaceType => value_or_unknown(&row.interface_type, unknown),
            InterfaceFieldId::LocalIp => value_or_unknown(&row.local_ip, unknown),
            InterfaceFieldId::Gateway => value_or_unknown(&row.gateway, unknown),
            InterfaceFieldId::DnsServers => value_or_unknown(&row.dns_servers, unknown),
            InterfaceFieldId::HasDefaultRoute => {
                if row.has_default_route {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            InterfaceFieldId::BasicAvailabilityStatus => {
                row.availability_status.title().to_string()
            }
        };
        chunks.push(format!("{}={value}", field.title()));
    }
    chunks.push(format!("Role={role}"));
    chunks.push(format!("State={}", row.route_state.title()));
    chunks.push(format!(
        "connectivity_state={}",
        row.observed_facts.connectivity_state.title()
    ));
    chunks.push(format!(
        "external_ip_status={}",
        row.observed_facts.external_ip_status.title()
    ));
    chunks.push(format!(
        "external_ip={}",
        row.observed_facts.external_ip.as_deref().unwrap_or(unknown)
    ));
    chunks.push(format!("bluetooth_like={}", row.is_bluetooth_like));
    chunks.push(format!(
        "vpn_tunnel_likelihood={}",
        row.derived_assessment.vpn_tunnel_likelihood.title()
    ));
    chunks.push(format!(
        "virtual_interface_likelihood={}",
        row.derived_assessment.virtual_interface_likelihood.title()
    ));
    chunks.push(format!(
        "service_interface_likelihood={}",
        row.derived_assessment.service_interface_likelihood.title()
    ));
    chunks.push(format!(
        "derived_classification={}",
        row.derived_assessment.classification
    ));
    chunks.push(format!(
        "confidence={}%",
        row.derived_assessment.confidence_percent
    ));
    chunks.push(format!(
        "heuristic_only={}",
        row.derived_assessment.heuristic_only
    ));
    chunks.push(format!(
        "signals={}",
        if row.derived_assessment.signals.is_empty() {
            unknown.to_string()
        } else {
            row.derived_assessment.signals.join(",")
        }
    ));
    chunks.push(format!(
        "recommendation_class={}",
        row.recommendation.class.title()
    ));
    chunks.push(format!(
        "recommendation_confidence={}",
        row.recommendation.confidence.title()
    ));
    chunks.push(format!(
        "recommendation_summary={}",
        row.recommendation.summary
    ));
    chunks.push(format!(
        "recommendation_signals={}",
        if row.recommendation.key_signals.is_empty() {
            unknown.to_string()
        } else {
            row.recommendation.key_signals.join(",")
        }
    ));
    chunks.push(format!(
        "excluded_alternatives={}",
        if row.recommendation.excluded_alternatives.is_empty() {
            unknown.to_string()
        } else {
            row.recommendation.excluded_alternatives.join(",")
        }
    ));
    chunks.join(" | ")
}

fn value_or_unknown(value: &str, unknown: &str) -> String {
    if value.trim().is_empty() || value == "-" {
        unknown.to_string()
    } else {
        value.to_string()
    }
}
