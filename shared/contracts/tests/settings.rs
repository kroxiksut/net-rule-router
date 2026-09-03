use nrr_shared::{
    gui_shell_v1, FreeRuleType, RouteBehaviorMode, RouteRole, RuleScenario, SettingAvailability,
    SettingFieldId, SettingOwnership, SettingsSectionId, ThemeMode,
};

#[test]
fn settings_contract_sections_are_fixed_for_block_2_5() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell
            .settings
            .sections
            .iter()
            .map(|section| section.id)
            .collect::<Vec<_>>(),
        vec![
            SettingsSectionId::General,
            SettingsSectionId::Appearance,
            SettingsSectionId::Accessibility,
            SettingsSectionId::Language,
            SettingsSectionId::LogsAndDiagnostics,
            SettingsSectionId::RoutingBehavior,
            SettingsSectionId::ExperimentalFeatures,
            SettingsSectionId::FreeUpdates
        ]
    );
}

#[test]
fn routing_behavior_fields_include_expected_ids_in_order() {
    let shell = gui_shell_v1();
    let routing = shell
        .settings
        .sections
        .iter()
        .find(|section| section.id == SettingsSectionId::RoutingBehavior)
        .unwrap_or_else(|| panic!("routing behavior section must exist"));
    assert_eq!(
        routing
            .fields
            .iter()
            .map(|field| field.id)
            .collect::<Vec<_>>(),
        vec![
            SettingFieldId::DefaultRoutingMode,
            SettingFieldId::FailClosedBehavior,
            SettingFieldId::WarnWhenSecondaryUnavailable,
            SettingFieldId::RulesFileChangeMode,
            SettingFieldId::RuleIncludeChildProcesses,
            SettingFieldId::ShowOtherOsRules,
            SettingFieldId::ZonePriorityOverIp,
        ]
    );
}

#[test]
fn routing_behavior_policy_fields_are_policy_affecting_preview() {
    let shell = gui_shell_v1();
    let routing = shell
        .settings
        .sections
        .iter()
        .find(|section| section.id == SettingsSectionId::RoutingBehavior)
        .unwrap_or_else(|| panic!("routing behavior section must exist"));
    let policy_fields: Vec<_> = routing
        .fields
        .iter()
        .filter(|f| f.ownership == SettingOwnership::PolicyAffectingPreview)
        .map(|f| f.id)
        .collect();
    assert!(policy_fields.contains(&SettingFieldId::DefaultRoutingMode));
    assert!(policy_fields.contains(&SettingFieldId::RulesFileChangeMode));
    assert!(policy_fields.contains(&SettingFieldId::RuleIncludeChildProcesses));
}

#[test]
fn show_other_os_rules_is_ui_preference() {
    let shell = gui_shell_v1();
    let routing = shell
        .settings
        .sections
        .iter()
        .find(|section| section.id == SettingsSectionId::RoutingBehavior)
        .unwrap_or_else(|| panic!("routing behavior section must exist"));
    let field = routing
        .fields
        .iter()
        .find(|f| f.id == SettingFieldId::ShowOtherOsRules)
        .unwrap_or_else(|| panic!("ShowOtherOsRules field must exist"));
    assert_eq!(field.ownership, SettingOwnership::UiPreference);
    assert_eq!(field.availability, SettingAvailability::Preview);
}

#[test]
fn each_mode_states_where_unmatched_traffic_goes() {
    // Three call sites derive behaviour from this — the availability check, the
    // final-action stage, and companion discovery, which drops suggestions that
    // name this role because they would change nothing.
    assert_eq!(
        RouteBehaviorMode::PreferPrimary.default_route_role(),
        RouteRole::Primary
    );
    assert_eq!(
        RouteBehaviorMode::PreferSecondaryWhenAvailable.default_route_role(),
        RouteRole::Secondary
    );
    assert_eq!(
        RouteBehaviorMode::StrictSecondaryFailClosed.default_route_role(),
        RouteRole::Secondary
    );
}

#[test]
fn theme_and_language_parsing_are_stable() {
    assert_eq!("dark".parse::<ThemeMode>(), Ok(ThemeMode::Dark));
    assert_eq!(
        "high-contrast".parse::<ThemeMode>(),
        Ok(ThemeMode::HighContrast)
    );
    assert_eq!(
        "strict-secondary-fail-closed".parse::<RouteBehaviorMode>(),
        Ok(RouteBehaviorMode::StrictSecondaryFailClosed)
    );
    // legacy slug "exact-fqdn" is a migration alias for Domain
    assert_eq!(
        "exact-fqdn".parse::<FreeRuleType>(),
        Ok(FreeRuleType::Domain)
    );
    assert_eq!("domain".parse::<FreeRuleType>(), Ok(FreeRuleType::Domain));
    assert_eq!("reorder".parse::<RuleScenario>(), Ok(RuleScenario::Reorder));
    assert!("unknown-theme".parse::<ThemeMode>().is_err());
}

#[test]
fn a_park_older_than_the_window_is_expired() {
    use nrr_shared::{parked_intents_expired, PARKED_AT_MS_KEY};

    let day_ms = 24 * 60 * 60 * 1000_i64;
    let parked = format!(r#"{{"{PARKED_AT_MS_KEY}":1000}}"#);
    assert!(!parked_intents_expired(&parked, 1000 + 6 * day_ms));
    assert!(parked_intents_expired(&parked, 1000 + 8 * day_ms));
}

#[test]
fn a_park_with_no_stamp_or_no_json_is_carried_not_discarded() {
    use nrr_shared::parked_intents_expired;

    // Losing a user's parked work over a missing field would be the worse
    // failure of the two.
    assert!(!parked_intents_expired(
        r#"{"route-policy":{"a":1}}"#,
        i64::MAX
    ));
    assert!(!parked_intents_expired("not json", i64::MAX));
    assert!(!parked_intents_expired("", i64::MAX));
}
