#![allow(clippy::expect_used)]

//! A route the user never renamed is named in the language the window runs
//! now. Baking the word into the preferences at first run left "Primary" and
//! "Secondary" across a Russian window after a language switch.

use nrr_desktop_gui::ui_surface::apply_qt_preferences_payload;
use nrr_ui_support::ui_preferences::UiPreferences;
use std::path::{Path, PathBuf};

fn labels_payload(primary: &str, secondary: &str) -> String {
    serde_json::json!({
        "routePrimaryLabel": primary,
        "routeSecondaryLabel": secondary,
    })
    .to_string()
}

fn renamed() -> UiPreferences {
    UiPreferences {
        route_primary_label: "Дом".to_string(),
        route_secondary_label: "Work VPN".to_string(),
        ..Default::default()
    }
}

#[test]
fn clearing_a_renamed_route_brings_back_the_localized_name() {
    let updated =
        apply_qt_preferences_payload(renamed(), &labels_payload("", "  ")).expect("payload parses");
    assert_eq!(updated.route_primary_label, "");
    assert_eq!(updated.route_secondary_label, "");
}

#[test]
fn a_window_sending_a_former_default_does_not_pin_that_language() {
    let updated = apply_qt_preferences_payload(
        UiPreferences::default(),
        &labels_payload("Primary", "Дополнительный"),
    )
    .expect("payload parses");
    assert_eq!(updated.route_primary_label, "");
    assert_eq!(updated.route_secondary_label, "");
}

#[test]
fn a_renamed_route_is_kept_verbatim() {
    let updated =
        apply_qt_preferences_payload(UiPreferences::default(), &labels_payload("Дом", "Work VPN"))
            .expect("payload parses");
    assert_eq!(updated.route_primary_label, "Дом");
    assert_eq!(updated.route_secondary_label, "Work VPN");
}

fn qml_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// An unrenamed route is stored empty, so a window that shows the stored
/// value directly shows nothing, and a window that starts from a typed-in
/// English word shows English until the context arrives.
#[test]
fn the_tray_names_routes_only_through_the_display_label() {
    let tray = qml_file("Tray.qml");
    for (number, line) in tray.lines().enumerate() {
        let reads_raw = line.contains("? routeSecondaryLabel")
            || line.contains(": routePrimaryLabel")
            || line.contains("property string routePrimaryLabel: \"P")
            || line.contains("property string routeSecondaryLabel: \"S");
        assert!(
            !reads_raw,
            "Tray.qml:{} shows a stored route label as is: {line}",
            number + 1
        );
    }
    let main = qml_file("Main.qml");
    assert!(
        !main.contains("routePrimaryLabel: \"Primary\"")
            && !main.contains("routeSecondaryLabel: \"Secondary\""),
        "Main.qml starts from English route names"
    );
}
