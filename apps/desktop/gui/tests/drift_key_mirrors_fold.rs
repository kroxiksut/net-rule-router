//! The GUI's drift sort key and the Rust comparison fold describe one thing.
//!
//! `driftSortKey` in `lib/rules.js` orders the rules before the window compares
//! its own table against a baseline, and `comparison_key` in
//! `nrr_shared::rules_json` orders them before the drift hash. Both must name
//! every field a drift DTO carries: a key blind to one of them leaves two rules
//! in arrival order, and the same set re-sorted in the table reads as changed.
//! No JS engine runs here, so this pins the fields the function reads.

use std::path::Path;

fn drift_sort_key_body() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml/lib/rules.js");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let start = source
        .find("function driftSortKey(")
        .unwrap_or_else(|| panic!("driftSortKey is not declared in lib/rules.js"));
    let rest = &source[start..];
    let end = rest
        .find("\n}")
        .unwrap_or_else(|| panic!("driftSortKey has no closing brace"));
    rest[..end].to_string()
}

#[test]
fn the_gui_drift_key_reads_every_field_the_fold_orders_on() {
    let body = drift_sort_key_body();
    for needle in [
        "\"address-match\"",
        "am.network",
        "am.first",
        "am.last",
        "\"app-match\"",
        "\"app:\"",
        "pattern",
        "\"include-child-processes\"",
        "d.enabled",
        "d.action",
        "String.fromCharCode(0)",
    ] {
        assert!(
            body.contains(needle),
            "driftSortKey no longer reads {needle}; it must stay in step with \
             `comparison_key` in nrr_shared::rules_json:\n{body}"
        );
    }
}

/// Whatever order the window hands over, the fold settles it: the service side
/// of the contract, which the GUI key above mirrors.
#[test]
fn the_fold_orders_rules_sharing_an_address_by_everything_else() {
    use nrr_shared::rules_json::{
        fold_for_comparison, to_canonical_string, AddressMatchDto, AppMatchDto, AppPatternDto,
        CanonicalRulesJsonV1, RuleAction, RuleDto, RULES_JSON_SCHEMA_VERSION,
    };
    let rule = |app: Option<(&str, bool)>, enabled: bool, action: RuleAction| RuleDto {
        id: String::new(),
        enabled,
        address_match: Some(AddressMatchDto::ExactFqdn {
            value: "example.com".into(),
        }),
        app_match: app.map(|(value, children)| AppMatchDto {
            pattern: AppPatternDto::Exact {
                value: value.into(),
            },
            include_child_processes: children,
        }),
        comment: String::new(),
        action,
        origin: None,
    };
    let rules = vec![
        rule(None, true, RuleAction::Route),
        rule(None, true, RuleAction::Block),
        rule(None, false, RuleAction::Route),
        rule(Some(("chrome.exe", false)), true, RuleAction::Route),
        rule(Some(("chrome.exe", true)), true, RuleAction::Route),
    ];
    let fold = |primary: Vec<RuleDto>| {
        let mut dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary,
            secondary: vec![],
        };
        fold_for_comparison(&mut dto);
        to_canonical_string(&dto).expect("canonical")
    };
    let mut reversed = rules.clone();
    reversed.reverse();
    assert_eq!(fold(rules), fold(reversed));
}
