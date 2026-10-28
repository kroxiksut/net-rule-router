//! A `user-settings.json` an earlier build wrote survives this build changing
//! one setting in it: every other value stays, the keys this build does not
//! know included. Every release adds a sample of its own file under
//! `fixtures/`; a released sample is never edited.

use std::path::Path;

use nrr_shared::user_settings::{UserSettingsStore, USER_SETTINGS_FILE_NAME};
use serde_json::{json, Value};

/// The oldest shape (the route-policy record still in the four-switch leak
/// settings) and the current one with a key from a newer build.
const RELEASED_SAMPLES: &[&str] = &["user_settings_oct09.json", "user_settings_oct26.json"];

/// The samples' stand-ins for keys only a newer build knows. Any other key
/// this build does not read is a setting it lost track of, carried but
/// ignored.
const UNKNOWN_TOP_LEVEL: &[&str] = &["setting-from-a-newer-build"];
const UNKNOWN_IN_RULES_FILES: &[&str] = &["tertiary"];

fn keys(map: &serde_json::Map<String, Value>) -> Vec<&str> {
    map.keys().map(String::as_str).collect()
}

fn declared<'a>(sample: &Value, at: Option<&str>, unknown: &[&'a str]) -> Vec<&'a str> {
    let object = match at {
        Some(key) => &sample[key],
        None => sample,
    };
    unknown
        .iter()
        .copied()
        .filter(|key| object.get(key).is_some())
        .collect()
}

#[test]
fn every_released_sample_keeps_every_value_when_one_setting_changes() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    for sample in RELEASED_SAMPLES {
        let original = std::fs::read_to_string(fixtures.join(sample)).expect(sample);
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(USER_SETTINGS_FILE_NAME);
        std::fs::write(&path, &original).expect("write");
        let mut expected: Value = serde_json::from_str(&original).expect("sample is JSON");

        let store = UserSettingsStore::at(path.clone());
        let loaded = store
            .load()
            .unwrap_or_else(|e| panic!("{sample}: this build cannot read it: {e}"))
            .expect("the file is there");
        assert_eq!(
            keys(&loaded.other),
            declared(&expected, None, UNKNOWN_TOP_LEVEL),
            "{sample}: a setting is no longer read"
        );
        assert_eq!(
            keys(&loaded.rules_files.other),
            declared(&expected, Some("rules-files"), UNKNOWN_IN_RULES_FILES),
            "{sample}: a rules-file setting is no longer read"
        );

        store
            .update(|settings| settings.rules_folder = "E:/Elsewhere".to_string())
            .unwrap_or_else(|e| panic!("{sample}: this build cannot update it: {e}"));

        expected["rules-folder"] = json!("E:/Elsewhere");
        let saved: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read back"))
                .expect("saved file is JSON");
        assert_eq!(saved, expected, "{sample}: a value was lost or changed");
    }
}
