//! The QML fallback profile must carry every capability flag the contract
//! declares.
//!
//! `Main.qml` ships a stub `platformProfile` so mock/preview renders without a
//! context file, and `supports(feature)` answers TRUE for a flag the stub does
//! not mention. A missing flag therefore reads as "supported" — which is
//! exactly backwards for the capability INVERSIONS, where `false` is the
//! Windows answer. The stub used to list seven of ten.

use std::path::{Path, PathBuf};

fn main_qml() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop/qml/Main.qml")
        .to_path_buf();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `supports: { … }` object of the stub declaration, as its bare key names.
fn stub_support_keys(source: &str) -> Vec<String> {
    let decl = "property var platformProfile: (";
    let start = source
        .find(decl)
        .unwrap_or_else(|| panic!("stub `platformProfile` declaration missing from Main.qml"));
    let supports_at = source[start..]
        .find("supports: {")
        .unwrap_or_else(|| panic!("stub profile has no `supports` object"))
        + start;
    let body_start = supports_at + "supports: {".len();
    let body_end = source[body_start..]
        .find('}')
        .unwrap_or_else(|| panic!("unterminated `supports` object"))
        + body_start;
    source[body_start..body_end]
        .split(',')
        .filter_map(|entry| entry.split(':').next())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

#[test]
fn platform_profile_stub_matches_the_contract() {
    let profile = nrr_shared::platform_profile::PlatformProfile::windows();
    let json = serde_json::to_value(profile).expect("serialise profile");
    let declared: Vec<String> = json["supports"]
        .as_object()
        .expect("supports object")
        .keys()
        .cloned()
        .collect();

    let stub = stub_support_keys(&main_qml());
    for key in &declared {
        assert!(
            stub.contains(key),
            "Main.qml's fallback profile is missing `{key}`; `supports()` answers TRUE for an \
             absent flag, so the preview would claim a capability the platform may not have"
        );
    }
    for key in &stub {
        assert!(
            declared.contains(key),
            "Main.qml's fallback profile declares `{key}`, which the contract does not"
        );
    }
}
