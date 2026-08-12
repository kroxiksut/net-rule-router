use nrr_shared::{
    gui_shell_v1, FreeRuleListType, FreeRuleType, RuleFormFieldId, RuleListEditFieldId,
    RuleListLoadFieldId, RuleReplaceReviewFieldId, RuleScenario, RulesDuplicateResolution,
    RulesEnabledFilter, RulesFileChangeBehavior, RulesTypeFilter, RulesViewSort,
};

#[test]
fn rules_contract_exposes_required_types_scenarios_fields_and_dialogs() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.rules.supported_free_rule_types,
        &[
            FreeRuleType::Application,
            FreeRuleType::Domain,
            FreeRuleType::Zone,
            FreeRuleType::ExactIp
        ]
    );
    assert!(shell
        .rules
        .placeholder_scenarios
        .contains(&RuleScenario::Create));
    assert!(shell
        .rules
        .placeholder_scenarios
        .contains(&RuleScenario::Delete));
    assert!(shell
        .rules
        .placeholder_scenarios
        .contains(&RuleScenario::Reorder));
    assert!(shell
        .rules
        .placeholder_scenarios
        .contains(&RuleScenario::Search));
    assert!(shell
        .rules
        .form_fields
        .iter()
        .any(|field| field.id == RuleFormFieldId::RuleType && field.required));
    assert!(shell
        .rules
        .form_fields
        .iter()
        .any(|field| field.id == RuleFormFieldId::MatchValue && field.required));
    assert!(shell
        .rules
        .form_fields
        .iter()
        .all(|field| field.visible_in_gui_v1));
    assert_eq!(
        shell.rules.supported_free_list_types,
        &[
            FreeRuleListType::SingleActiveManagedList,
            FreeRuleListType::ImportedPresetReplacingActiveList
        ]
    );
    assert!(shell
        .rules
        .load_list_dialog_fields
        .contains(&RuleListLoadFieldId::FilePath));
    assert!(shell
        .rules
        .edit_list_dialog_fields
        .contains(&RuleListEditFieldId::ListName));
    assert!(shell
        .rules
        .edit_list_dialog_fields
        .contains(&RuleListEditFieldId::DefaultMode));
    assert!(shell
        .rules
        .replace_review_dialog_fields
        .contains(&RuleReplaceReviewFieldId::IncomingRulesCount));
    assert!(shell
        .rules
        .replace_review_dialog_fields
        .contains(&RuleReplaceReviewFieldId::ReplaceAction));
    assert!(shell.rules.load_list_requires_review_before_replace);
}

#[test]
fn rules_contract_exposes_sort_and_filter_options() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.rules.supported_sort_modes,
        &[
            RulesViewSort::ByDisplayOrder,
            RulesViewSort::ByMatchValue,
            RulesViewSort::ByType,
            RulesViewSort::ByRoute,
        ]
    );
    assert_eq!(
        shell.rules.supported_enabled_filters,
        &[
            RulesEnabledFilter::All,
            RulesEnabledFilter::EnabledOnly,
            RulesEnabledFilter::DisabledOnly,
        ]
    );
    assert_eq!(
        shell.rules.supported_type_filters,
        &[
            RulesTypeFilter::All,
            RulesTypeFilter::Zones,
            RulesTypeFilter::Domain,
            RulesTypeFilter::ExactIp,
            RulesTypeFilter::Application,
            RulesTypeFilter::Windows,
            RulesTypeFilter::Linux,
            RulesTypeFilter::MacOS,
        ]
    );
    assert_eq!(
        shell.rules.other_os_type_filters,
        &[RulesTypeFilter::Linux, RulesTypeFilter::MacOS]
    );
}

#[test]
fn rules_contract_exposes_duplicate_resolution_options() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.rules.supported_duplicate_resolutions,
        &[
            RulesDuplicateResolution::KeepInPrimary,
            RulesDuplicateResolution::KeepInSecondary,
            RulesDuplicateResolution::KeepInBoth,
        ]
    );
}

#[test]
fn rules_contract_block_secondary_default_is_fail_open() {
    let shell = gui_shell_v1();
    assert!(!shell.rules.block_secondary_when_unavailable_default);
}

#[test]
fn rules_type_filter_roundtrip() {
    for variant in RulesTypeFilter::ALL {
        let slug = variant.slug();
        assert_eq!(slug.parse::<RulesTypeFilter>(), Ok(variant));
        assert_eq!(variant.to_string(), slug);
    }
    assert_eq!(RulesTypeFilter::default(), RulesTypeFilter::All);
}

#[test]
fn rules_duplicate_resolution_roundtrip() {
    for variant in RulesDuplicateResolution::ALL {
        let slug = variant.slug();
        assert_eq!(slug.parse::<RulesDuplicateResolution>(), Ok(variant));
        assert_eq!(variant.to_string(), slug);
    }
}

#[test]
fn rules_file_change_behavior_roundtrip() {
    for variant in RulesFileChangeBehavior::ALL {
        let slug = variant.slug();
        assert_eq!(slug.parse::<RulesFileChangeBehavior>(), Ok(variant));
        assert_eq!(variant.to_string(), slug);
    }
    assert_eq!(
        RulesFileChangeBehavior::default(),
        RulesFileChangeBehavior::Notify
    );
}

#[test]
fn rules_file_change_behavior_labels_are_nonempty() {
    for variant in RulesFileChangeBehavior::ALL {
        assert!(!variant.label().is_empty());
        assert!(!variant.slug().is_empty());
    }
}

#[test]
fn rules_contract_exposes_file_change_behaviors() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.rules.supported_file_change_behaviors,
        &[
            RulesFileChangeBehavior::Notify,
            RulesFileChangeBehavior::AutoApply
        ]
    );
    assert_eq!(
        shell.rules.default_file_change_behavior,
        RulesFileChangeBehavior::Notify
    );
}

#[test]
fn rules_contract_supports_rule_enable_toggle() {
    let shell = gui_shell_v1();
    assert!(shell.rules.supports_rule_enable_toggle);
}

#[test]
fn rules_contract_supports_rule_comments() {
    let shell = gui_shell_v1();
    assert!(shell.rules.supports_rule_comments);
}

/// A rule the user adds without touching the enable toggle is enabled.
///
/// Pinned because the opposite is silent: a rule that lands disabled is saved,
/// shipped to the service and listed in the review diff exactly like any other
/// one, yet enforces nothing. The Add/Edit dialog has to re-seed the toggle on
/// every open for this to hold — a cleared checkbox must not survive into the
/// next Add.
#[test]
fn rules_contract_defaults_a_newly_added_rule_to_enabled() {
    let shell = gui_shell_v1();
    assert!(shell.rules.new_rule_enabled_default);
}

/// The rules-table row carries rule provenance, and it carries it under the
/// same field name and the same shape as the rules FILE and the canonical
/// rules JSON do.
///
/// Three surfaces read this one spelling — the rules-file inline comment, the
/// canonical `RuleDto.origin`, and the GUI row below — so a rename in any of
/// them silently turns "added for you, for youtube.com" into an unexplained
/// rule the user did not write. Pinned here rather than trusted to review.
#[test]
fn rule_row_entry_carries_origin_in_the_published_wire_shape() {
    use nrr_shared::ipc_payloads::RuleRowEntry;
    use nrr_shared::{AutoRuleReason, RuleOrigin};

    let row = RuleRowEntry {
        id: "auto-0a1b2c".into(),
        rule_type: "domain".into(),
        match_value: "cdn.example.test".into(),
        target_route: "secondary".into(),
        comment: None,
        enabled: true,
        validation_status: "ok".into(),
        validation_message_key: None,
        hosts_override: None,
        origin: Some(RuleOrigin::auto(
            AutoRuleReason::SiteCompanion,
            "example.test",
            "2026-07-31",
        )),
    };
    let json = serde_json::to_string(&row).expect("serialize");
    assert!(
        json.contains(
            r#""origin":{"kind":"auto","reason":"site-companion","anchor":"example.test","added":"2026-07-31"}"#
        ),
        "origin wire shape drifted; got {json}"
    );

    // A rule the user typed carries no origin, and the field is elided rather
    // than emitted as null — older peers and the GUI both read "absent" as
    // "user-authored".
    let plain = RuleRowEntry {
        origin: None,
        ..row
    };
    let json = serde_json::to_string(&plain).expect("serialize");
    assert!(!json.contains("origin"), "absent origin leaked: {json}");

    // A payload written before the field existed still decodes.
    let decoded: RuleRowEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.origin, None);
}
