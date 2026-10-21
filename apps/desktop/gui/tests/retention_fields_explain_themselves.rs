//! Every number on the revisions-retention panel says what changing it gives
//! the user, in both shipped languages, and keeps its visible label as the
//! accessible name: a tooltip is never the only place the meaning lives.

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn locale_text(locale: &serde_json::Value, key: &str) -> Option<String> {
    key.split('.')
        .try_fold(locale, |node, part| node.get(part))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// The first `"key"` passed to `root.tr(` after `marker` in `block`.
fn tr_key_after<'a>(block: &'a str, marker: &str) -> Option<&'a str> {
    let at = block.find(marker)?;
    let rest = &block[at + marker.len()..];
    let open = rest.find("root.tr(\"")? + "root.tr(\"".len();
    rest[open..].split('"').next()
}

#[test]
fn every_retention_number_has_a_tip_and_a_name() {
    let panel = repo_file("apps/desktop/qml/sections/settings/RetentionSettings.qml");
    let en: serde_json::Value =
        serde_json::from_str(&repo_file("locales/en.json")).unwrap_or_else(|e| panic!("{e}"));
    let ru: serde_json::Value =
        serde_json::from_str(&repo_file("locales/ru.json")).unwrap_or_else(|e| panic!("{e}"));
    let boxes: Vec<&str> = panel.split("ThemedSpinBox {").skip(1).collect();
    assert_eq!(boxes.len(), 5, "the panel's number fields changed; recount");
    for block in boxes {
        let block = &block[..block.find("\n            }").unwrap_or(block.len())];
        let tip = tr_key_after(block, "ToolTip.text:")
            .unwrap_or_else(|| panic!("a retention field has no tooltip:\n{block}"));
        let name = tr_key_after(block, "Accessible.name:")
            .unwrap_or_else(|| panic!("a retention field has no accessible name:\n{block}"));
        assert_ne!(tip, name, "the tooltip only repeats the label");
        for key in [tip, name] {
            for (lang, locale) in [("en", &en), ("ru", &ru)] {
                let text = locale_text(locale, key).unwrap_or_default();
                assert!(!text.trim().is_empty(), "{key} missing in {lang}.json");
            }
        }
        assert!(
            panel.contains(&format!("text: root.tr(\"{name}\"")),
            "{name} is not the visible label beside its field"
        );
    }
}

/// "Reset to defaults" restores the service's own defaults, and the panel can
/// say what they are.
#[test]
fn the_panel_resets_to_the_services_defaults() {
    let panel = repo_file("apps/desktop/qml/sections/settings/RetentionSettings.qml");
    let start = panel
        .find("readonly property var defaults: ({")
        .unwrap_or_else(|| panic!("the panel no longer declares its defaults"));
    let block = &panel[start..];
    let block = &block[..block.find("})").unwrap_or(block.len())];
    let value = |name: &str| -> String {
        let at = block
            .find(&format!("{name}:"))
            .unwrap_or_else(|| panic!("{name} missing from the panel's defaults"));
        block[at + name.len() + 1..]
            .split([',', '\n'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let wire = nrr_shared::ipc_payloads::RetentionSettingsSetRequest::DEFAULT;
    for (name, expected) in [
        ("supersededDays", wire.superseded_days.to_string()),
        ("supersededCountCap", wire.superseded_count_cap.to_string()),
        ("rejectedDays", wire.rejected_days.to_string()),
        ("rolledbackDays", wire.rolledback_days.to_string()),
        ("rolledbackCountCap", wire.rolledback_count_cap.to_string()),
        ("pinLkg", wire.pin_lkg.to_string()),
    ] {
        assert_eq!(
            value(name),
            expected,
            "{name} differs from the service default"
        );
    }
    assert!(
        panel.contains("onClicked: group.resetToDefaults()"),
        "the reset button is gone"
    );
}

/// A number typed outside a field's range is refused on focus loss; until then
/// the field itself says so, on every spin box of the app.
#[test]
fn a_number_out_of_range_is_marked_while_it_is_typed() {
    let spin = repo_file("apps/desktop/qml/components/ThemedSpinBox.qml");
    assert!(
        spin.contains("inputOutOfRange: editable && !contentItem.acceptableInput"),
        "the spin box no longer tracks typed text outside its range"
    );
    let border = &spin[spin
        .find("border.color: root.inputOutOfRange")
        .unwrap_or_else(|| panic!("an out-of-range value no longer changes the field's border"))..];
    assert!(
        border
            .lines()
            .nth(1)
            .is_some_and(|l| l.contains("theme.colorDanger")),
        "an out-of-range value is not drawn in the danger colour"
    );
}
