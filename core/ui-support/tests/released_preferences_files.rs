//! A preferences file written by a released build loads and is saved again
//! without losing a value, the keys this build does not know included. Every
//! release adds a sample of its own file under `fixtures/`.

use std::collections::BTreeMap;
use std::path::Path;

use nrr_ui_support::ui_preferences::UiPreferencesStore;

const RELEASED_SAMPLES: &[&str] = &["ui_preferences_v12.txt"];

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
        store.save(&loaded).expect("save");
        let saved = std::fs::read_to_string(&path).expect("read back");

        let (before, after) = (settings(&original), settings(&saved));
        assert!(before.len() > 50, "{sample}: the sample is not a full file");
        assert!(
            schema_version(&after) >= schema_version(&before),
            "{sample}: the version stamp went down"
        );
        for (key, value) in before.iter().filter(|(key, _)| **key != "schema_version") {
            assert_eq!(
                after.get(key),
                Some(value),
                "{sample}: `{key}` was lost or changed"
            );
        }
    }
}
