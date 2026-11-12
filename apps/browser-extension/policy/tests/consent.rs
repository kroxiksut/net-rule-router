use nrr_browser_policy::resolve_mode;

#[test]
fn an_imported_profile_cannot_enable_browser_changes_without_consent() {
    assert_eq!(resolve_mode(0, 2, 0, 1, 1), 4);
    assert_eq!(resolve_mode(2, 1, 0, 1, 1), 4);
    assert_eq!(resolve_mode(3, 1, 0, 1, 1), 4);
}

#[test]
fn an_explicit_system_choice_stops_global_inheritance() {
    assert_eq!(resolve_mode(1, 2, 0, 0, 0), 1);
    assert_eq!(resolve_mode(1, 3, 1, 1, 1), 1);
}

#[test]
fn removing_a_site_override_returns_to_the_global_profile() {
    assert_eq!(resolve_mode(2, 1, 1, 1, 1), 2);
    assert_eq!(resolve_mode(0, 1, 1, 1, 1), 1);
    assert_eq!(resolve_mode(0, 3, 1, 1, 1), 3);
}

#[test]
fn manual_language_survives_an_unavailable_or_changed_route() {
    assert_eq!(resolve_mode(2, 3, 1, 0, 1), 2);
    assert_eq!(resolve_mode(2, 3, 1, 1, 1), 2);
}

#[test]
fn losing_nrr_cannot_confirm_a_route_based_setting() {
    assert_eq!(resolve_mode(3, 1, 1, 0, 1), 5);
    assert_eq!(resolve_mode(0, 3, 1, 0, 1), 5);
}

#[test]
fn unsupported_browser_capabilities_cannot_report_applied() {
    assert_eq!(resolve_mode(2, 1, 1, 1, 0), 6);
    assert_eq!(resolve_mode(3, 1, 1, 1, 0), 6);
    assert_eq!(resolve_mode(1, 1, 1, 1, 0), 1);
}

#[test]
fn malformed_wire_values_cannot_be_coerced_into_permission() {
    for invalid in [2, 3, 4, 255, u32::MAX] {
        assert_eq!(resolve_mode(2, 1, invalid, 1, 1), 0);
        assert_eq!(resolve_mode(2, 1, 1, invalid, 1), 0);
        assert_eq!(resolve_mode(2, 1, 1, 1, invalid), 0);
    }
    for invalid in [4, 5, 255, u32::MAX] {
        assert_eq!(resolve_mode(invalid, 1, 1, 1, 1), 0);
        assert_eq!(resolve_mode(0, invalid, 1, 1, 1), 0);
    }
    assert_eq!(resolve_mode(0, 0, 1, 1, 1), 0);
}
