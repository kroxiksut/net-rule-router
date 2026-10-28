//! A preferences file written by a released build loads and is saved again
//! without losing a value, the keys this build does not know included. Every
//! release adds a sample of its own file under `fixtures/`.

use std::collections::BTreeMap;
use std::path::Path;

use nrr_ui_support::ui_preferences::{UiPreferencesStore, CURRENT_UI_PREFS_SCHEMA_VERSION};

/// The sample's stand-in for a key this build does not know. Kept from a file
/// at this build's schema or newer; in an older one it is the residue of a key
/// a schema bump removed, and goes.
const UNKNOWN_KEY: &str = "setting_from_a_newer_build";

const RELEASED_SAMPLES: &[&str] = &["ui_preferences_v12.txt", "ui_preferences_v13.txt"];

/// Keys a schema bump retired, with the version that retired them. A sample
/// older than that version loses exactly these; anything else lost is a defect.
const RETIRED_KEYS: &[(&str, u32)] = &[
    ("route_kill_switch_enabled", 13),
    ("route_kill_switch_fail_closed", 13),
    ("route_kill_switch_block_all", 13),
    ("route_mode_a_coverage_strategy", 13),
];

/// Values a later build reads differently, as `(key, old, new)`.
const REMAPPED_VALUES: &[(&str, &str, &str)] = &[(
    "route_behavior_mode",
    "strict-secondary-fail-closed",
    "prefer-secondary-when-available",
)];

fn settings(text: &str) -> BTreeMap<&str, &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect()
}

fn schema_version(settings: &BTreeMap<&str, &str>) -> u32 {
    settings
        .get("schema_version")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn retired_for(key: &str, sample_version: u32) -> bool {
    RETIRED_KEYS
        .iter()
        .any(|(retired, since)| *retired == key && sample_version < *since)
}

fn expected_value<'a>(key: &str, value: &'a str) -> &'a str {
    REMAPPED_VALUES
        .iter()
        .find(|(k, old, _)| *k == key && *old == value)
        .map_or(value, |(_, _, new)| new)
}

#[test]
fn every_released_sample_loads_and_saves_without_losing_a_value() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    for sample in RELEASED_SAMPLES {
        let original = std::fs::read_to_string(fixtures.join(sample)).expect(sample);
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("preferences.conf");
        std::fs::write(&path, &original).expect("write");

        let store = UiPreferencesStore::for_path(path.clone());
        let loaded = store.load().expect("load");
        // A key carried but not read would still be written back, so the file
        // alone cannot show that this build lost track of a setting.
        for line in &loaded.forward_compat.unknown_lines {
            assert!(
                line.starts_with(&format!("{UNKNOWN_KEY}=")),
                "{sample}: `{line}` is no longer read"
            );
        }
        store.save(&loaded).expect("save");
        let saved = std::fs::read_to_string(&path).expect("read back");

        let (before, after) = (settings(&original), settings(&saved));
        let version = schema_version(&before);
        assert!(before.len() > 50, "{sample}: the sample is not a full file");
        assert!(
            schema_version(&after) >= version,
            "{sample}: the version stamp went down"
        );
        for (key, value) in before.iter().filter(|(key, _)| **key != "schema_version") {
            if retired_for(key, version)
                || (*key == UNKNOWN_KEY && version < CURRENT_UI_PREFS_SCHEMA_VERSION)
            {
                assert_eq!(
                    after.get(key),
                    None,
                    "{sample}: retired `{key}` was carried"
                );
                continue;
            }
            assert_eq!(
                after.get(key).copied(),
                Some(expected_value(key, value)),
                "{sample}: `{key}` was lost or changed"
            );
        }
    }
}
