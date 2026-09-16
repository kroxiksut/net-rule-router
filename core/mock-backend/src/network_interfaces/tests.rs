use super::{
    assign_preview_roles, assign_recommendations, decorate_interface_rows, fallback_rows,
    interface_diagnostics_checks_from, interface_diagnostics_checks_snapshot,
    interfaces_routes_preview_snapshot, InterfaceRouteRow, InterfacesDataSource,
    RouteSelectionRequest,
};
use nrr_shared::{ConnectivityState, RouteBehaviorMode, RouteRole, RouteSelectionState};

#[test]
fn named_candidates_are_respected_in_preview_assignment() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        primary_candidate_id: None,
        primary_candidate_name: Some("Wi-Fi".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: None,
        secondary_candidate_name: Some("Ethernet".to_string()),
        secondary_candidate_confirmed: true,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    assign_preview_roles(&mut rows, &request);

    let wifi = find_row(&rows, "Wi-Fi");
    let ethernet = find_row(&rows, "Ethernet");
    assert_eq!(wifi.selected_role, Some(RouteRole::Primary));
    assert_eq!(wifi.route_state, RouteSelectionState::Selected);
    assert_eq!(ethernet.selected_role, Some(RouteRole::Secondary));
    assert_eq!(ethernet.route_state, RouteSelectionState::Selected);
}

#[test]
fn strict_secondary_mode_marks_unavailable_secondary_as_conflict() {
    let mut rows = vec![
        InterfaceRouteRow {
            persistent_id: "win-adapter:primary".to_string(),
            adapter_name: "{PRIMARY-ADAPTER}".to_string(),
            windows_name: "Primary".to_string(),
            interface_description: "Primary adapter".to_string(),
            interface_type: "Ethernet".to_string(),
            is_bluetooth_like: false,
            local_ip: "192.168.0.2".to_string(),
            gateway: "192.168.0.1".to_string(),
            dns_servers: "1.1.1.1".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            runtime_data_unavailable: false,
            availability_status: super::BasicAvailabilityStatus::Available,
            observed_facts: super::build_observed_facts(
                super::BasicAvailabilityStatus::Available,
                "192.168.0.2",
                "192.168.0.1",
            ),
            derived_assessment: super::build_derived_assessment(
                "Primary",
                "Ethernet",
                "Primary adapter",
                "{PRIMARY-ADAPTER}",
                "192.168.0.1",
                "192.168.0.2",
                true,
                ConnectivityState::Available,
            ),
            recommendation: super::unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
        InterfaceRouteRow {
            persistent_id: "win-adapter:backup".to_string(),
            adapter_name: "{BACKUP-ADAPTER}".to_string(),
            windows_name: "Backup".to_string(),
            interface_description: "Backup adapter".to_string(),
            interface_type: "Wireless".to_string(),
            is_bluetooth_like: false,
            local_ip: "-".to_string(),
            gateway: "-".to_string(),
            dns_servers: "-".to_string(),
            has_forwarding_path: Some(false),
            runtime_data_unavailable: false,
            has_default_route: false,
            availability_status: super::BasicAvailabilityStatus::Unavailable,
            observed_facts: super::build_observed_facts(
                super::BasicAvailabilityStatus::Unavailable,
                "-",
                "-",
            ),
            derived_assessment: super::build_derived_assessment(
                "Backup",
                "Wireless",
                "Backup adapter",
                "{BACKUP-ADAPTER}",
                "-",
                "-",
                false,
                ConnectivityState::Unavailable,
            ),
            recommendation: super::unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::Unavailable,
        },
    ];

    let request = RouteSelectionRequest {
        primary_candidate_id: None,
        primary_candidate_name: Some("Primary".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: None,
        secondary_candidate_name: Some("Backup".to_string()),
        secondary_candidate_confirmed: true,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
    };
    assign_preview_roles(&mut rows, &request);

    let backup = find_row(&rows, "Backup");
    assert_eq!(backup.selected_role, Some(RouteRole::Secondary));
    assert_eq!(backup.route_state, RouteSelectionState::FailClosedConflict);
}

#[test]
fn snapshot_exposes_preview_contract_markers() {
    let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());
    assert!(!snapshot.rows.is_empty());
    assert!(snapshot
        .supported_behavior_modes
        .contains(&RouteBehaviorMode::StrictSecondaryFailClosed));
}

#[test]
fn stable_identity_candidates_are_respected_before_names() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
        primary_candidate_name: Some("Wi-Fi".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: Some("win-adapter:wifi-fallback".to_string()),
        secondary_candidate_name: Some("Ethernet".to_string()),
        secondary_candidate_confirmed: true,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    assign_preview_roles(&mut rows, &request);

    let ethernet = find_row(&rows, "Ethernet");
    let wifi = find_row(&rows, "Wi-Fi");
    assert_eq!(ethernet.selected_role, Some(RouteRole::Primary));
    assert_eq!(wifi.selected_role, Some(RouteRole::Secondary));
}

#[test]
fn fallback_rows_include_enriched_connectivity_and_external_ip_status() {
    let rows = fallback_rows();
    let ethernet = find_row(&rows, "Ethernet");
    let vpn = find_row(&rows, "VPN");

    assert_eq!(
        ethernet.observed_facts.connectivity_state,
        ConnectivityState::Available
    );
    // No probe runs in a placeholder dataset, so neither row may claim a
    // resolved external address.
    assert_eq!(
        ethernet.observed_facts.external_ip_status,
        nrr_shared::ExternalIpStatus::NotChecked
    );
    assert_eq!(
        vpn.observed_facts.connectivity_state,
        ConnectivityState::Unknown
    );
    assert_eq!(
        vpn.observed_facts.external_ip_status,
        nrr_shared::ExternalIpStatus::NotChecked
    );
}

#[test]
fn derived_assessment_marks_tunnel_as_vpn_likely_and_heuristic_only() {
    let rows = fallback_rows();
    let vpn = find_row(&rows, "VPN");
    assert_eq!(
        vpn.derived_assessment.vpn_tunnel_likelihood,
        nrr_shared::DerivedLikelihood::Likely
    );
    assert!(vpn.derived_assessment.heuristic_only);
    assert!(!vpn.derived_assessment.signals.is_empty());
}

#[test]
fn heuristics_do_not_auto_assign_roles_without_user_choice() {
    let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());
    assert!(snapshot.rows.iter().all(|row| row.selected_role.is_none()));
}

/// A failed IP Helper query leaves EVERY row at `"-"`. Read as "this
/// adapter has no address" it blocks all of them, and a machine with a
/// working link is told it has no usable adapter.
#[test]
fn a_failed_data_query_does_not_block_every_adapter() {
    let mut row = InterfaceRouteRow {
        persistent_id: "win-adapter:primary".to_string(),
        adapter_name: "{PRIMARY-ADAPTER}".to_string(),
        windows_name: "Primary".to_string(),
        interface_description: "Primary adapter".to_string(),
        interface_type: "Ethernet".to_string(),
        is_bluetooth_like: false,
        local_ip: "-".to_string(),
        gateway: "-".to_string(),
        dns_servers: "-".to_string(),
        has_default_route: false,
        has_forwarding_path: None,
        runtime_data_unavailable: true,
        availability_status: super::BasicAvailabilityStatus::Available,
        observed_facts: super::build_observed_facts(
            super::BasicAvailabilityStatus::Available,
            "-",
            "-",
        ),
        derived_assessment: super::build_derived_assessment(
            "Primary",
            "Ethernet",
            "Primary adapter",
            "{PRIMARY-ADAPTER}",
            "-",
            "-",
            false,
            ConnectivityState::Unknown,
        ),
        recommendation: super::unknown_recommendation(),
        selected_role: None,
        route_state: RouteSelectionState::NotSelected,
    };

    let explicit = super::ExplicitChoices {
        primary: None,
        secondary: None,
    };
    let unreadable = super::evaluate_recommendation_score(&row, 0, explicit);
    assert!(
        !unreadable.blocked,
        "a query that failed is not evidence the adapter is unusable"
    );
    assert!(unreadable
        .key_signals
        .iter()
        .any(|s| s == "adapter-data-unreadable"));

    // The same row without the flag IS a genuine "no address" reading.
    row.runtime_data_unavailable = false;
    let genuine = super::evaluate_recommendation_score(&row, 0, explicit);
    assert!(genuine.blocked);
    assert!(genuine
        .key_signals
        .iter()
        .any(|s| s == "blocked-missing-local-ip"));
}

#[test]
fn recommendation_engine_marks_primary_and_secondary_candidates() {
    // Fixed two-adapter fixture (strong wired link + VPN-shaped tunnel) run
    // through the same decoration path production uses for service-supplied
    // rows, so the assertion doesn't depend on what the host machine enumerates.
    let wired = InterfaceRouteRow {
        persistent_id: "win-adapter:primary".to_string(),
        adapter_name: "{PRIMARY-ADAPTER}".to_string(),
        windows_name: "Primary".to_string(),
        interface_description: "Primary adapter".to_string(),
        interface_type: "Ethernet".to_string(),
        is_bluetooth_like: false,
        local_ip: "192.168.0.2".to_string(),
        gateway: "192.168.0.1".to_string(),
        dns_servers: "1.1.1.1".to_string(),
        has_default_route: true,
        has_forwarding_path: Some(true),
        runtime_data_unavailable: false,
        availability_status: super::BasicAvailabilityStatus::Available,
        observed_facts: super::build_observed_facts(
            super::BasicAvailabilityStatus::Available,
            "192.168.0.2",
            "192.168.0.1",
        ),
        derived_assessment: super::build_derived_assessment(
            "Primary",
            "Ethernet",
            "Primary adapter",
            "{PRIMARY-ADAPTER}",
            "192.168.0.1",
            "192.168.0.2",
            true,
            ConnectivityState::Available,
        ),
        recommendation: super::unknown_recommendation(),
        selected_role: None,
        route_state: RouteSelectionState::NotSelected,
    };
    let vpn_tunnel = InterfaceRouteRow {
        persistent_id: "win-adapter:vpn-tunnel".to_string(),
        adapter_name: "{VPN-ADAPTER}".to_string(),
        windows_name: "VPN Tunnel".to_string(),
        interface_description: "VPN tunnel adapter".to_string(),
        interface_type: "Tunnel".to_string(),
        is_bluetooth_like: false,
        local_ip: "10.8.0.5".to_string(),
        gateway: "-".to_string(),
        dns_servers: "-".to_string(),
        has_default_route: false,
        has_forwarding_path: Some(false),
        runtime_data_unavailable: false,
        availability_status: super::BasicAvailabilityStatus::Available,
        observed_facts: super::build_observed_facts(
            super::BasicAvailabilityStatus::Available,
            "10.8.0.5",
            "-",
        ),
        derived_assessment: super::build_derived_assessment(
            "VPN Tunnel",
            "Tunnel",
            "VPN tunnel adapter",
            "{VPN-ADAPTER}",
            "-",
            "10.8.0.5",
            false,
            ConnectivityState::Degraded,
        ),
        recommendation: super::unknown_recommendation(),
        selected_role: None,
        route_state: RouteSelectionState::NotSelected,
    };

    let snapshot = decorate_interface_rows(
        vec![wired, vpn_tunnel],
        &RouteSelectionRequest::default(),
        InterfacesDataSource::WindowsLive,
    );
    assert!(snapshot.rows.iter().any(|row| {
        row.recommendation.class == nrr_shared::RecommendationClass::PreferredPrimary
    }));
    assert!(snapshot.rows.iter().any(|row| {
        row.recommendation.class == nrr_shared::RecommendationClass::PreferredSecondary
    }));
    assert!(snapshot
        .rows
        .iter()
        .all(|row| row.recommendation.advisory_only));
}

/// The platform layer computes `has_forwarding_path` for exactly the link a
/// visible default route misses: a TUN tunnel that points its split-default
/// at the PEER and advertises no gateway at all. Judging it by
/// `has_default_route` called a healthy tunnel degraded — the one thing
/// `nrr_platform_api::interface_rows` promises the GUI will never do.
#[test]
fn a_gatewayless_link_with_a_forwarding_path_is_not_called_degraded() {
    let mut rows = fallback_rows();
    let vpn = rows
        .iter_mut()
        .find(|row| row.windows_name == "VPN")
        .expect("fallback set has a VPN row");
    vpn.has_default_route = false;
    vpn.gateway = "-".to_string();
    vpn.has_forwarding_path = Some(true);
    vpn.availability_status = super::BasicAvailabilityStatus::Available;
    vpn.observed_facts.connectivity_state = ConnectivityState::Available;

    let checks = super::evaluate_adapter_checks(find_row(&rows, "VPN"));
    let route_check = checks
        .iter()
        .find(|c| c.action == nrr_shared::AdapterCheckActionId::CheckRoute)
        .expect("route check present");
    assert_eq!(
        route_check.status,
        nrr_shared::AdapterCheckResultStatus::Success,
        "a usable forwarding path is a route, gateway or not: {}",
        route_check.explanation
    );

    // Positive control: with the platform layer reporting no way out, the
    // same row is still degraded.
    let mut cold = rows.clone();
    cold.iter_mut()
        .find(|row| row.windows_name == "VPN")
        .expect("row")
        .has_forwarding_path = Some(false);
    let checks = super::evaluate_adapter_checks(find_row(&cold, "VPN"));
    let route_check = checks
        .iter()
        .find(|c| c.action == nrr_shared::AdapterCheckActionId::CheckRoute)
        .expect("route check present");
    assert_eq!(
        route_check.status,
        nrr_shared::AdapterCheckResultStatus::Degraded
    );
}

/// An adapter the platform layer says reaches nothing must not be the
/// PREFERRED secondary — rules would be routed into a link that goes
/// nowhere. The exemption that keeps the setup flow working is tested with
/// it: a VPN-shaped adapter is normally down at the moment the user binds
/// it, and that is the same `Some(false)`.
#[test]
fn an_adapter_with_no_way_out_is_not_recommended_unless_it_looks_like_a_tunnel() {
    let mut rows = fallback_rows();
    for row in rows.iter_mut() {
        if row.windows_name == "Wi-Fi" {
            row.has_default_route = false;
            row.gateway = "-".to_string();
            row.has_forwarding_path = Some(false);
        }
    }
    assign_recommendations(&mut rows, &RouteSelectionRequest::default());
    assert!(find_row(&rows, "Wi-Fi")
        .recommendation
        .key_signals
        .iter()
        .any(|s| s == "no-forwarding-path"));
    assert_ne!(
        find_row(&rows, "Wi-Fi").recommendation.class,
        nrr_shared::RecommendationClass::PreferredSecondary
    );

    // The VPN row of the same fixture already carries
    // `has_forwarding_path: Some(false)` and a tunnel likelihood — it keeps
    // its old score, because a tunnel that is not up yet is the normal
    // state at binding time.
    assert!(!find_row(&rows, "VPN")
        .recommendation
        .key_signals
        .iter()
        .any(|s| s == "no-forwarding-path"));
}

#[test]
fn a_stale_name_does_not_pin_a_second_adapter() {
    // Rename an adapter and the saved name still matches the row that took
    // it over, while the saved id keeps pointing at the original. The role
    // goes to the id (id-first resolution), so the scoring bonus must go
    // there too — otherwise the GUI recommends one adapter while another
    // holds the role.
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
        primary_candidate_name: Some("Wi-Fi".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: None,
        secondary_candidate_name: None,
        secondary_candidate_confirmed: false,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    assign_preview_roles(&mut rows, &request);
    assign_recommendations(&mut rows, &request);

    assert_eq!(
        find_row(&rows, "Ethernet").selected_role,
        Some(RouteRole::Primary)
    );
    assert!(find_row(&rows, "Ethernet")
        .recommendation
        .key_signals
        .iter()
        .any(|s| s == "manual-primary-pin"));
    assert!(!find_row(&rows, "Wi-Fi")
        .recommendation
        .key_signals
        .iter()
        .any(|s| s == "manual-primary-pin"));
}

#[test]
fn an_empty_id_is_not_an_explicit_choice() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        primary_candidate_id: Some(String::new()),
        primary_candidate_name: None,
        primary_candidate_confirmed: true,
        secondary_candidate_id: None,
        secondary_candidate_name: None,
        secondary_candidate_confirmed: false,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    assign_recommendations(&mut rows, &request);

    assert!(rows.iter().all(|row| !row
        .recommendation
        .key_signals
        .iter()
        .any(|s| s == "manual-primary-pin")));
}

#[test]
fn bluetooth_rows_are_hidden_by_default() {
    let mut rows = fallback_rows();
    assert!(rows
        .iter()
        .any(|row| row.windows_name == "Bluetooth PAN" && row.is_bluetooth_like));
    rows.retain(|row| !row.is_bluetooth_like);
    assert!(!rows.iter().any(|row| row.windows_name == "Bluetooth PAN"));
}

/// The row the user confirmed is never filtered away by a substring guess.
/// Before this, a false "pan" match made the confirmed adapter disappear
/// under "Confirmed primary adapter is currently unavailable in this
/// snapshot" — about an adapter that is present and working — and the
/// Bluetooth warning that exists for exactly this case could never fire.
#[test]
fn a_confirmed_adapter_survives_the_bluetooth_filter() {
    let request = RouteSelectionRequest {
        primary_candidate_id: None,
        primary_candidate_name: Some("Bluetooth PAN".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: None,
        secondary_candidate_name: None,
        secondary_candidate_confirmed: false,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    let snapshot = decorate_interface_rows(
        fallback_rows(),
        &request,
        InterfacesDataSource::FallbackMock,
    );

    let kept = find_row(&snapshot.rows, "Bluetooth PAN");
    assert_eq!(kept.selected_role, Some(RouteRole::Primary));
    assert!(
        snapshot
            .role_assignment_advisory
            .warnings
            .iter()
            .any(|w| w.contains("Bluetooth")),
        "the warning about the confirmed choice must be reachable"
    );

    // Negative control: an UNCONFIRMED Bluetooth row is still filtered out.
    let snapshot = decorate_interface_rows(
        fallback_rows(),
        &RouteSelectionRequest::default(),
        InterfacesDataSource::FallbackMock,
    );
    assert!(!snapshot
        .rows
        .iter()
        .any(|row| row.windows_name == "Bluetooth PAN"));
}

#[test]
fn bluetooth_rows_can_be_included_explicitly() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        include_bluetooth_adapters: true,
        ..RouteSelectionRequest::default()
    };
    assign_recommendations(&mut rows, &request);
    assert!(rows.iter().any(|row| row.windows_name == "Bluetooth PAN"));
}

#[test]
fn bluetooth_row_is_never_preferred_when_included() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        include_bluetooth_adapters: true,
        ..RouteSelectionRequest::default()
    };
    assign_recommendations(&mut rows, &request);
    let bluetooth = find_row(&rows, "Bluetooth PAN");
    assert_eq!(
        bluetooth.recommendation.class,
        nrr_shared::RecommendationClass::AllowedButNotRecommended
    );
    assert!(bluetooth
        .recommendation
        .key_signals
        .iter()
        .any(|signal| { signal == "bluetooth-adapter-nondefault-routing-profile" }));
}

#[test]
fn same_adapter_cannot_be_confirmed_for_primary_and_secondary() {
    // Deterministic fixture: live enumeration on a host without an
    // "Ethernet"-named adapter would leave both roles unresolved and the
    // assertions below vacuously true, so exercise the fallback dataset instead.
    let snapshot = decorate_interface_rows(
        fallback_rows(),
        &RouteSelectionRequest {
            primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
            primary_candidate_name: Some("Ethernet".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
            secondary_candidate_name: Some("Ethernet".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        },
        InterfacesDataSource::FallbackMock,
    );

    assert!(snapshot.role_assignment_advisory.conflict_warning.is_some());
    let primary_count = snapshot
        .rows
        .iter()
        .filter(|row| row.selected_role == Some(RouteRole::Primary))
        .count();
    let secondary_count = snapshot
        .rows
        .iter()
        .filter(|row| row.selected_role == Some(RouteRole::Secondary))
        .count();
    assert_eq!(primary_count, 1);
    assert_eq!(secondary_count, 0);
}

#[test]
fn unconfirmed_candidate_names_do_not_assign_roles() {
    let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest {
        primary_candidate_id: None,
        primary_candidate_name: Some("Ethernet".to_string()),
        primary_candidate_confirmed: false,
        secondary_candidate_id: None,
        secondary_candidate_name: Some("VPN".to_string()),
        secondary_candidate_confirmed: false,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    assert!(snapshot.rows.iter().all(|row| row.selected_role.is_none()));
}

#[test]
fn confirmed_selection_has_priority_over_heuristic_recommendation() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        primary_candidate_id: None,
        primary_candidate_name: Some("VPN".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: None,
        secondary_candidate_name: Some("Ethernet".to_string()),
        secondary_candidate_confirmed: true,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    let advisory = assign_preview_roles(&mut rows, &request);

    let vpn = find_row(&rows, "VPN");
    let ethernet = find_row(&rows, "Ethernet");
    assert_eq!(vpn.selected_role, Some(RouteRole::Primary));
    assert_eq!(ethernet.selected_role, Some(RouteRole::Secondary));
    assert!(advisory.user_choice_priority_note.contains("priority"));
}

#[test]
fn confirmed_secondary_without_ip_is_preserved_and_warned() {
    let mut rows = fallback_rows();
    let request = RouteSelectionRequest {
        primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
        primary_candidate_name: Some("Ethernet".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: Some("win-adapter:vpn-fallback".to_string()),
        secondary_candidate_name: Some("VPN".to_string()),
        secondary_candidate_confirmed: true,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };
    assign_recommendations(&mut rows, &request);
    let advisory = assign_preview_roles(&mut rows, &request);
    let secondary = find_row(&rows, "VPN");
    assert_eq!(secondary.selected_role, Some(RouteRole::Secondary));
    assert_eq!(
        secondary.route_state,
        RouteSelectionState::RequiresVerification
    );
    assert!(advisory
        .warnings
        .iter()
        .any(|warning| warning.contains("has no IP address")));
}

#[test]
fn missing_confirmed_secondary_keeps_selection_contract() {
    let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest {
        primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
        primary_candidate_name: Some("Ethernet".to_string()),
        primary_candidate_confirmed: true,
        secondary_candidate_id: Some("win-adapter:missing-secondary".to_string()),
        secondary_candidate_name: Some("Missing secondary".to_string()),
        secondary_candidate_confirmed: true,
        include_bluetooth_adapters: false,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    assert!(snapshot
        .role_assignment_advisory
        .warnings
        .iter()
        .any(|warning| warning.contains("selection is preserved")));
}

#[test]
fn diagnostics_checks_snapshot_uses_required_status_set() {
    let snapshot = interface_diagnostics_checks_snapshot(RouteSelectionRequest::default());
    assert!(!snapshot.rows.is_empty());
    let statuses = snapshot
        .rows
        .iter()
        .flat_map(|row| row.checks.iter().map(|check| check.status))
        .collect::<Vec<_>>();
    assert!(statuses.iter().all(|status| matches!(
        status,
        nrr_shared::AdapterCheckResultStatus::Success
            | nrr_shared::AdapterCheckResultStatus::Degraded
            | nrr_shared::AdapterCheckResultStatus::Unavailable
            | nrr_shared::AdapterCheckResultStatus::Timeout
    )));
}

#[test]
fn diagnostics_checks_are_read_only_for_block_5_6() {
    let snapshot = interface_diagnostics_checks_snapshot(RouteSelectionRequest::default());
    assert!(snapshot
        .rows
        .iter()
        .flat_map(|row| row.checks.iter())
        .all(|check| check.read_only && !check.requires_service_mediation));
}

fn find_row<'a>(rows: &'a [InterfaceRouteRow], name: &str) -> &'a InterfaceRouteRow {
    rows.iter()
        .find(|row| row.windows_name == name)
        .unwrap_or_else(|| panic!("row '{name}' not found"))
}

#[test]
fn the_checks_describe_the_rows_they_were_given() {
    // The regression this guards: the checks used to come from a SECOND
    // enumeration, so a tunnel appearing between the two calls showed in
    // one list and not the other.
    let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());
    let derived = interface_diagnostics_checks_from(&snapshot);

    assert_eq!(derived.rows.len(), snapshot.rows.len());
    for (checks, row) in derived.rows.iter().zip(snapshot.rows.iter()) {
        assert_eq!(checks.persistent_id, row.persistent_id);
        assert_eq!(checks.windows_name, row.windows_name);
    }
    assert_eq!(derived.data_source, snapshot.data_source);
}
