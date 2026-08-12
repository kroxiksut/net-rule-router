use nrr_shared::{
    gui_shell_v1, AdapterCheckActionId, AdapterCheckResultStatus, ConnectivityState, DataReadiness,
    ExternalIpStatus, InterfaceFieldId, InterfaceFieldUsageScope, RecommendationClass,
    RouteSelectionState, SnapshotValueAvailability,
};

#[test]
fn interfaces_routes_contract_exposes_required_fields_and_states() {
    let shell = gui_shell_v1();
    let field_matrix = shell
        .interfaces_routes
        .field_readiness
        .iter()
        .map(|entry| (entry.field, entry.readiness))
        .collect::<Vec<_>>();

    assert!(field_matrix.contains(&(InterfaceFieldId::WindowsName, DataReadiness::RealInBlock2)));
    assert!(field_matrix.contains(&(InterfaceFieldId::DnsServers, DataReadiness::RealInBlock2)));
    assert!(field_matrix.contains(&(
        InterfaceFieldId::BasicAvailabilityStatus,
        DataReadiness::PlaceholderUntilBlock5
    )));
    assert!(shell.interfaces_routes.field_snapshot_status.contains(
        &nrr_shared::InterfaceFieldSnapshotStatus {
            field: InterfaceFieldId::Gateway,
            availability: SnapshotValueAvailability::MayBeUnknownFromSnapshot,
        }
    ));
    assert!(shell.interfaces_routes.field_usage_scopes.contains(
        &nrr_shared::InterfaceFieldUsage {
            field: InterfaceFieldId::DnsServers,
            scope: InterfaceFieldUsageScope::UiOnly,
        }
    ));
    assert_eq!(
        shell.interfaces_routes.display_format.unknown_value_marker,
        "-"
    );
    assert!(shell
        .interfaces_routes
        .connectivity_states
        .contains(&ConnectivityState::Timeout));
    assert!(shell
        .interfaces_routes
        .external_ip_statuses
        .contains(&ExternalIpStatus::NotChecked));
    assert!(shell
        .interfaces_routes
        .enriched_fields
        .contains(&"vpn_tunnel_likelihood"));
    assert!(shell
        .interfaces_routes
        .observed_vs_derived_boundary
        .contains("observed_facts"));
    assert_eq!(
        shell
            .interfaces_routes
            .connectivity_checks_policy
            .max_probe_retries,
        1
    );
    assert!(shell
        .interfaces_routes
        .recommendation_classes
        .contains(&RecommendationClass::PreferredPrimary));
    assert!(shell
        .interfaces_routes
        .recommendation_advisory_policy
        .contains("advisory-only"));
    assert!(shell
        .interfaces_routes
        .recommendation_hints_catalog
        .iter()
        .any(|hint| hint.contains("wireguard-openvpn")));
    assert!(shell.interfaces_routes.manual_role_confirmation_required);
    assert!(shell
        .interfaces_routes
        .role_conflict_policy
        .contains("cannot"));
    assert!(shell
        .interfaces_routes
        .confirmed_choice_priority_policy
        .contains("priority"));
    assert!(shell
        .interfaces_routes
        .secondary_role_ux_warnings
        .contains(&"no-suitable-secondary-found"));
    assert!(!shell.interfaces_routes.show_bluetooth_adapters_default);
    assert!(shell
        .interfaces_routes
        .bluetooth_detection_signals
        .contains(&"windows_name_contains_bluetooth"));
    assert!(shell
        .interfaces_routes
        .bluetooth_recommendation_policy
        .contains("allowed-but-not-recommended"));
    assert!(shell.interfaces_routes.adapter_check_actions.contains(
        &nrr_shared::AdapterCheckActionContract {
            id: AdapterCheckActionId::ShowExternalIp,
            scope: nrr_shared::AdapterCheckExecutionScope::ReadOnlyDiagnostics,
            description: "Show external IP status/value from latest probe or local fallback.",
        }
    ));
    assert!(shell
        .interfaces_routes
        .adapter_check_result_statuses
        .contains(&AdapterCheckResultStatus::Timeout));
    assert!(shell
        .interfaces_routes
        .diagnostics_explain_integration_note
        .contains("core"));
    assert!(shell
        .interfaces_routes
        .route_state_placeholders
        .contains(&RouteSelectionState::FailClosedConflict));
}
