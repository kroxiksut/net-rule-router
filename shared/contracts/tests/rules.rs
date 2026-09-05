use nrr_shared::{RulesDuplicateResolution, RulesFileChangeBehavior, RulesTypeFilter};

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
        main_route: None,
        hosts_override: None,
        origin: Some(RuleOrigin::auto(
            AutoRuleReason::SiteCompanion,
            "example.test",
            "2026-07-31",
        )),
        pinned_destinations: None,
        pinned_destinations_total: None,
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

/// The addresses one application rule holds are the only unbounded part of a
/// `rules.list` response, and the whole response has to fit one IPC frame.
/// The list is capped; the COUNT the window shows must still be the real one.
#[test]
fn a_rule_row_caps_its_address_list_but_keeps_the_true_count() {
    use nrr_shared::ipc_payloads::{RuleRowEntry, MAX_PINNED_DESTINATIONS_PER_ROW};

    let total = MAX_PINNED_DESTINATIONS_PER_ROW * 4;
    let mut held: Vec<String> = (0..total).map(|i| format!("203.0.113.{i}")).collect();
    held.truncate(MAX_PINNED_DESTINATIONS_PER_ROW);

    let row = RuleRowEntry {
        id: "r-1".into(),
        rule_type: "application".into(),
        match_value: "chrome.exe".into(),
        target_route: "secondary".into(),
        comment: None,
        enabled: true,
        validation_status: "ok".into(),
        validation_message_key: None,
        main_route: None,
        hosts_override: None,
        origin: None,
        pinned_destinations: Some(held),
        pinned_destinations_total: Some(total),
    };
    let json = serde_json::to_value(&row).expect("serialise");
    assert_eq!(
        json["pinned-destinations"].as_array().expect("list").len(),
        MAX_PINNED_DESTINATIONS_PER_ROW
    );
    assert_eq!(json["pinned-destinations-total"], total);

    // A row holding nothing carries neither field, so an ordinary response is
    // no larger than it was.
    let empty = RuleRowEntry {
        pinned_destinations: None,
        pinned_destinations_total: None,
        ..row
    };
    let json = serde_json::to_value(&empty).expect("serialise");
    assert!(json.get("pinned-destinations").is_none());
    assert!(json.get("pinned-destinations-total").is_none());
}

/// The window reads the total, not the length of the list it received.
#[test]
fn the_window_reads_the_total_rather_than_the_delivered_length() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/qml/Main.qml"),
    )
    .expect("read Main.qml");
    assert!(
        source.contains(r#"pinnedCount: Number(w["pinned-destinations-total"]"#),
        "Main.qml no longer takes the pinned count from the service's total"
    );
}
