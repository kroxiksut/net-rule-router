// Every test runs over fixed rows, never over this machine's adapters: the
// live enumeration differs per host and would leave assertions vacuous.

use super::{
    decorate_interface_rows, fallback_rows, interfaces_snapshot_from, InterfaceRouteRow,
    InterfacesDataSource, InterfacesRoutesPreviewSnapshot, MockInterfaceRows,
    RouteSelectionRequest, PREVIEW_ETHERNET_PERSISTENT_ID, PREVIEW_VPN_PERSISTENT_ID,
    PREVIEW_WIFI_PERSISTENT_ID,
};
use nrr_shared::{ConnectivityState, RouteBehaviorMode, RouteRole, RouteSelectionState};

fn snapshot(request: &RouteSelectionRequest) -> InterfacesRoutesPreviewSnapshot {
    let port = MockInterfaceRows::new(InterfacesDataSource::FallbackMock, fallback_rows());
    interfaces_snapshot_from(&port, request)
}

fn confirmed(
    primary: (Option<&str>, Option<&str>),
    secondary: (Option<&str>, Option<&str>),
) -> RouteSelectionRequest {
    let owned = |value: Option<&str>| value.map(str::to_string);
    RouteSelectionRequest {
        primary_candidate_id: owned(primary.0),
        primary_candidate_name: owned(primary.1),
        primary_candidate_confirmed: primary.0.is_some() || primary.1.is_some(),
        secondary_candidate_id: owned(secondary.0),
        secondary_candidate_name: owned(secondary.1),
        secondary_candidate_confirmed: secondary.0.is_some() || secondary.1.is_some(),
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

fn find_row<'a>(rows: &'a [InterfaceRouteRow], name: &str) -> &'a InterfaceRouteRow {
    rows.iter()
        .find(|row| row.name == name)
        .unwrap_or_else(|| panic!("row '{name}' not found"))
}

fn role_holders(rows: &[InterfaceRouteRow], role: RouteRole) -> Vec<&str> {
    rows.iter()
        .filter(|row| row.selected_role == Some(role))
        .map(|row| row.name.as_str())
        .collect()
}

#[test]
fn named_candidates_are_respected() {
    let snapshot = snapshot(&confirmed((None, Some("Wi-Fi")), (None, Some("Ethernet"))));

    let wifi = find_row(&snapshot.rows, "Wi-Fi");
    let ethernet = find_row(&snapshot.rows, "Ethernet");
    assert_eq!(wifi.selected_role, Some(RouteRole::Primary));
    assert_eq!(wifi.route_state, RouteSelectionState::Selected);
    assert_eq!(ethernet.selected_role, Some(RouteRole::Secondary));
    assert_eq!(ethernet.route_state, RouteSelectionState::Selected);
}

#[test]
fn strict_secondary_mode_marks_an_unavailable_secondary_as_a_conflict() {
    let mut rows = fallback_rows();
    let wifi = rows
        .iter_mut()
        .find(|row| row.name == "Wi-Fi")
        .expect("wifi row");
    wifi.availability_status = super::BasicAvailabilityStatus::Unavailable;
    wifi.observed_facts.connectivity_state = ConnectivityState::Unavailable;
    let request = RouteSelectionRequest {
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        ..confirmed((None, Some("Ethernet")), (None, Some("Wi-Fi")))
    };

    let snapshot = decorate_interface_rows(rows, &request, InterfacesDataSource::FallbackMock);

    let wifi = find_row(&snapshot.rows, "Wi-Fi");
    assert_eq!(wifi.selected_role, Some(RouteRole::Secondary));
    assert_eq!(wifi.route_state, RouteSelectionState::FailClosedConflict);
}

#[test]
fn the_snapshot_carries_the_supplier_provenance_and_the_modes() {
    let snapshot = snapshot(&RouteSelectionRequest::default());
    assert_eq!(snapshot.data_source, InterfacesDataSource::FallbackMock);
    assert_eq!(snapshot.rows.len(), fallback_rows().len());
    assert!(snapshot
        .supported_behavior_modes
        .contains(&RouteBehaviorMode::StrictSecondaryFailClosed));
}

#[test]
fn stable_identity_is_respected_before_names() {
    let snapshot = snapshot(&confirmed(
        (Some(PREVIEW_ETHERNET_PERSISTENT_ID), Some("Wi-Fi")),
        (Some(PREVIEW_WIFI_PERSISTENT_ID), Some("Ethernet")),
    ));

    assert_eq!(
        role_holders(&snapshot.rows, RouteRole::Primary),
        ["Ethernet"]
    );
    assert_eq!(
        role_holders(&snapshot.rows, RouteRole::Secondary),
        ["Wi-Fi"]
    );
}

#[test]
fn heuristics_never_assign_a_role() {
    let snapshot = snapshot(&RouteSelectionRequest::default());
    assert!(snapshot.rows.iter().all(|row| row.selected_role.is_none()));
    assert!(snapshot.rows.iter().any(|row| {
        row.recommendation.class == nrr_shared::RecommendationClass::PreferredPrimary
    }));
}

#[test]
fn an_empty_id_without_a_name_binds_nothing() {
    let snapshot = snapshot(&confirmed((Some(""), None), (None, None)));
    assert!(role_holders(&snapshot.rows, RouteRole::Primary).is_empty());
}

#[test]
fn the_same_adapter_cannot_hold_both_roles() {
    let ethernet = (Some(PREVIEW_ETHERNET_PERSISTENT_ID), Some("Ethernet"));
    let snapshot = snapshot(&confirmed(ethernet, ethernet));

    assert_eq!(
        role_holders(&snapshot.rows, RouteRole::Primary),
        ["Ethernet"]
    );
    assert!(role_holders(&snapshot.rows, RouteRole::Secondary).is_empty());
}

#[test]
fn unconfirmed_candidates_do_not_assign_roles() {
    let request = RouteSelectionRequest {
        primary_candidate_confirmed: false,
        secondary_candidate_confirmed: false,
        ..confirmed((None, Some("Ethernet")), (None, Some("VPN")))
    };
    let snapshot = snapshot(&request);
    assert!(snapshot.rows.iter().all(|row| row.selected_role.is_none()));
}

#[test]
fn the_users_choice_outranks_the_recommendation() {
    let snapshot = snapshot(&confirmed((None, Some("VPN")), (None, Some("Ethernet"))));

    let vpn = find_row(&snapshot.rows, "VPN");
    assert_eq!(vpn.selected_role, Some(RouteRole::Primary));
    assert_ne!(
        vpn.recommendation.class,
        nrr_shared::RecommendationClass::PreferredPrimary,
        "the binding moves the role, not the advice"
    );
    assert_eq!(
        find_row(&snapshot.rows, "Ethernet").selected_role,
        Some(RouteRole::Secondary)
    );
}

#[test]
fn a_confirmed_secondary_without_an_address_is_kept_and_marked_for_verification() {
    let snapshot = snapshot(&confirmed(
        (Some(PREVIEW_ETHERNET_PERSISTENT_ID), None),
        (Some(PREVIEW_VPN_PERSISTENT_ID), None),
    ));
    let vpn = find_row(&snapshot.rows, "VPN");
    assert_eq!(vpn.selected_role, Some(RouteRole::Secondary));
    assert_eq!(vpn.route_state, RouteSelectionState::RequiresVerification);
}

#[test]
fn a_missing_secondary_leaves_the_role_empty_and_keeps_the_primary() {
    let snapshot = snapshot(&confirmed(
        (Some(PREVIEW_ETHERNET_PERSISTENT_ID), None),
        (Some("preview-adapter:missing"), Some("Missing secondary")),
    ));
    assert_eq!(
        role_holders(&snapshot.rows, RouteRole::Primary),
        ["Ethernet"]
    );
    assert!(role_holders(&snapshot.rows, RouteRole::Secondary).is_empty());
}

/// The screen hides Bluetooth by the user's toggle; the snapshot hands every
/// row over, so a bound Bluetooth adapter can never vanish from under it.
#[test]
fn bluetooth_rows_reach_the_screen_and_a_bound_one_keeps_its_role() {
    let snapshot = snapshot(&confirmed((None, Some("Bluetooth PAN")), (None, None)));
    let bluetooth = find_row(&snapshot.rows, "Bluetooth PAN");
    assert!(bluetooth.is_bluetooth_like);
    assert_eq!(bluetooth.selected_role, Some(RouteRole::Primary));
}

#[test]
fn the_placeholder_set_runs_no_probe_and_marks_the_tunnel() {
    let rows = fallback_rows();
    let ethernet = find_row(&rows, "Ethernet");
    let vpn = find_row(&rows, "VPN");
    assert_eq!(
        ethernet.observed_facts.connectivity_state,
        ConnectivityState::Available
    );
    for row in [ethernet, vpn] {
        assert_eq!(
            row.observed_facts.external_ip_status,
            nrr_shared::ExternalIpStatus::NotChecked
        );
    }
    assert_eq!(
        vpn.derived_assessment.vpn_tunnel_likelihood,
        nrr_shared::DerivedLikelihood::Likely
    );
}
