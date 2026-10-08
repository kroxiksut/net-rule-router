//! Every rule type the Add dialog offers is named, explained and filterable.
//!
//! The dialog lists the backend's types and reads their texts by slug, so a
//! type without a locale entry shows its raw slug, and one missing from the
//! filter can be added but never found again. The rules file writer must also
//! know the section each type lives in, in the order the Rust writer uses.

use std::path::{Path, PathBuf};

use nrr_mock_backend::rules::{rules_screen_preview_snapshot, RulesScreenRequest};
use nrr_shared::FreeRuleType;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn locale_has(locale: &serde_json::Value, key: &str) -> bool {
    key.split('.')
        .try_fold(locale, |node, part| node.get(part))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| !text.is_empty())
}

fn offered_types() -> Vec<FreeRuleType> {
    rules_screen_preview_snapshot(RulesScreenRequest::default())
        .supported_rule_types
        .to_vec()
}

#[test]
fn every_offered_rule_type_has_its_texts_in_both_locales() {
    for lang in ["en", "ru"] {
        let locale: serde_json::Value = serde_json::from_str(
            repo_file(&format!("locales/{lang}.json")).trim_start_matches('\u{feff}'),
        )
        .unwrap_or_else(|e| panic!("{lang}.json parses: {e}"));
        for rule_type in offered_types() {
            let slug = rule_type.slug();
            // The application texts are per platform.
            let suffix = if rule_type == FreeRuleType::Application {
                "application-windows"
            } else {
                slug
            };
            for key in [
                format!("rules.type.{slug}"),
                format!("rules.placeholder.{suffix}"),
                format!("rules.hint.{suffix}"),
            ] {
                assert!(locale_has(&locale, &key), "{lang}.json has no `{key}`");
            }
        }
    }
}

#[test]
fn every_offered_rule_type_can_be_filtered_for() {
    let section = repo_file("apps/desktop/qml/sections/RulesSection.qml");
    let model = section
        .lines()
        .find(|line| line.contains("model: [ \"all\", \"zone\""))
        .expect("the type filter's model is a literal list");
    for rule_type in offered_types() {
        assert!(
            model.contains(&format!("\"{}\"", rule_type.slug())),
            "the type filter does not offer `{}`: {model}",
            rule_type.slug()
        );
    }
}

#[test]
fn the_gui_writes_every_rule_section_in_the_canonical_order() {
    let rules_js = repo_file("apps/desktop/qml/lib/rules.js");
    let order = rules_js
        .lines()
        .find_map(|line| line.trim().strip_prefix("var order = ["))
        .expect("buildCanonicalRulesText declares its section order");
    let names: Vec<&str> = order
        .trim_end_matches(']')
        .split(',')
        .map(|name| name.trim().trim_matches('"'))
        .collect();
    assert_eq!(
        names,
        [
            "Zones",
            "Domains",
            "IP",
            "CIDR",
            "Ranges",
            "appSection",
            "Auto"
        ],
        "`nrr_domain::rules_file::RulesFileSection::ALL` order, the app section in place"
    );
    for name in names.into_iter().filter(|name| *name != "appSection") {
        assert!(
            nrr_shared::preset_parser::classify_section(name).is_some(),
            "the parser does not read back `--- {name}`"
        );
    }
    // The app section is the host's own (`appSectionHeader`), which the parser
    // on that host reads as rules.
    let host = match nrr_shared::platform_profile::PlatformProfile::current().os {
        "linux" => "Linux",
        "macos" => "MacOS",
        _ => "Windows",
    };
    assert!(
        nrr_shared::preset_parser::classify_section_lenient(host).is_some(),
        "the parser does not read back `--- {host}` on its own OS"
    );
}
