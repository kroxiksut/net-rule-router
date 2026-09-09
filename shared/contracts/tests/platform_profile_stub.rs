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

/// Flags whose value differs between the shipped OS profiles and that the GUI
/// therefore has to ask about — a `false` here is a capability the user would
/// otherwise be offered and never get.
const GATED_IN_QML: [&str; 3] = ["appRouting", "dnsObserve", "perAppBlockLeakproof"];

/// Differing flags deliberately left ungated: both are inversions in the
/// user's FAVOUR (Linux routes per-user and scopes a per-user block to every
/// protocol; Windows cannot). Absent, they promise nothing false, so a gate
/// would be a section invented for a question the product has not asked.
const UNGATED_BY_DECISION: [&str; 2] = ["perUserRouting", "perUserAllProtocolScoping"];

fn supports_of(profile: nrr_shared::platform_profile::PlatformProfile) -> serde_json::Value {
    let json = serde_json::to_value(profile).unwrap_or_else(|e| panic!("serialise profile: {e}"));
    json["supports"].clone()
}

/// Every `.qml` under `apps/desktop/qml`, concatenated.
fn all_qml_sources() -> String {
    fn walk(dir: &Path, out: &mut String) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "qml") {
                out.push_str(
                    &std::fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
                );
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/qml");
    let mut out = String::new();
    walk(&root, &mut out);
    out
}

/// A capability flag with no reader is a promise nobody keeps: the GUI renders
/// the same on every OS and the profile is decoration. Only the flags that
/// actually differ between platforms are held to this — the rest are `true`
/// everywhere, and gating on them would be inventing a distinction.
#[test]
fn every_capability_that_differs_between_platforms_is_either_gated_or_a_stated_exception() {
    let windows = supports_of(nrr_shared::platform_profile::PlatformProfile::windows());
    let linux = supports_of(nrr_shared::platform_profile::PlatformProfile::linux());
    let macos = supports_of(nrr_shared::platform_profile::PlatformProfile::macos());

    let differing: Vec<String> = windows
        .as_object()
        .expect("supports object")
        .keys()
        .filter(|key| windows[key] != linux[key] || windows[key] != macos[key])
        .cloned()
        .collect();

    let qml = all_qml_sources();
    for key in &differing {
        if UNGATED_BY_DECISION.contains(&key.as_str()) {
            continue;
        }
        assert!(
            GATED_IN_QML.contains(&key.as_str()),
            "`{key}` differs between the OS profiles but is neither gated in the GUI nor a stated exception"
        );
        assert!(
            qml.contains(&format!("supports(\"{key}\")")),
            "`{key}` is listed as gated, but no QML asks `supports(\"{key}\")`"
        );
    }
    for key in GATED_IN_QML.iter().chain(UNGATED_BY_DECISION.iter()) {
        assert!(
            differing.contains(&(*key).to_string()),
            "`{key}` no longer differs between the OS profiles; drop it rather than gate on nothing"
        );
    }
}
