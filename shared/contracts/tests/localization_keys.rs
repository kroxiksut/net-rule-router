use nrr_shared::load_locale_map;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const ALLOWED_TOP_LEVEL_DOMAINS: &[&str] = &[
    "menu",
    "section",
    "action",
    "settings",
    "dialog",
    "tray",
    "a11y",
    "label",
    "status",
    "interfaces",
    "rules",
    "diagnostics",
    "diag",
    "logs",
    "audit",
    "first-run",
    "theme",
    // Sanctioned root domains that accreted over time but were never added
    // to the allowlist, leaving this gate red. They are all live, in-use
    // top-level families.
    "connection",
    "errors",
    "mutations",
    "progress",
    "risk",
    // One wording per concept for the two route names, shared by every
    // surface that used to spell them itself.
    "route",
    "routing",
    "toast",
    "unsaved-changes",
    // Notifications centre (footer bell chip + NotificationCenterPopup) —
    // a live top-level family.
    "notifications",
    // VPN-client onboarding dialog (VpnOnboardingDialog). A live top-level
    // family; the workspace-wide locale gate was not run when it was added,
    // so it stayed off the allowlist.
    "vpn-onboarding",
    // Application-group routing dialog (AppGroupRoutingDialog): VMs/emulators
    // and P2P apps found on this machine. Same story as `vpn-onboarding`
    // above — the family shipped before this gate was re-run, so it was
    // missing from the allowlist.
    "app-groups",
    // Block-notification reason slugs, resolved by name from the tray and the
    // per-reason mute settings.
    "block-reason",
];

const RUNTIME_KEY_SOURCE_FILES: &[&str] = &[
    "apps/desktop/qml/Main.qml",
    "apps/desktop/gui/src/ui_surface.rs",
    // lib.rs because nrr-desktop-tray is a lib-only crate consumed by the launcher.
    "apps/desktop/tray/src/lib.rs",
];

#[test]
fn locale_files_have_no_namespace_conflicts_or_invalid_leaf_types() {
    for locale_file in locale_files() {
        let raw = fs::read_to_string(&locale_file)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", locale_file.display()));
        let parsed = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|error| {
                panic!(
                    "failed to parse locale JSON '{}': {error}",
                    locale_file.display()
                )
            });
        let root = parsed
            .as_object()
            .unwrap_or_else(|| panic!("root must be object: '{}'", locale_file.display()));

        assert!(
            root.contains_key("metadata"),
            "locale must include metadata block: '{}'",
            locale_file.display()
        );

        let mut leaf_keys = HashSet::new();
        let mut namespace_keys = HashSet::new();
        let mut errors = Vec::new();
        visit_locale_node(
            &parsed,
            "",
            true,
            &mut leaf_keys,
            &mut namespace_keys,
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "locale '{}' has structural issues:\n{}",
            locale_file.display(),
            errors.join("\n")
        );
    }
}

#[test]
fn locale_root_domains_use_fixed_block_3_5_allowlist() {
    let allowed = ALLOWED_TOP_LEVEL_DOMAINS
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for locale_file in locale_files() {
        let raw = fs::read_to_string(&locale_file)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", locale_file.display()));
        let parsed = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|error| {
                panic!(
                    "failed to parse locale JSON '{}': {error}",
                    locale_file.display()
                )
            });
        let root = parsed
            .as_object()
            .unwrap_or_else(|| panic!("root must be object: '{}'", locale_file.display()));

        let unexpected = root
            .keys()
            .filter(|key| key.as_str() != "metadata")
            .filter(|key| !allowed.contains(key.as_str()))
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            unexpected.is_empty(),
            "locale '{}' has unexpected root domains: {}",
            locale_file.display(),
            unexpected.join(", ")
        );
    }
}

#[test]
fn runtime_uses_known_localization_keys() {
    let en_map = load_locale_map("en");
    let known_keys = en_map.keys().cloned().collect::<HashSet<_>>();
    let runtime_keys = collect_runtime_locale_keys();
    let mut unknown = Vec::new();

    for key in runtime_keys {
        if known_keys.contains(&key) {
            continue;
        }

        if is_allowed_runtime_dynamic_key(&key) {
            continue;
        }

        unknown.push(key);
    }

    assert!(
        unknown.is_empty(),
        "runtime contains unknown localization keys: {}",
        unknown.join(", ")
    );

    let deprecated = collect_runtime_locale_keys()
        .into_iter()
        .filter(|key| key.starts_with("common."))
        .collect::<Vec<_>>();
    assert!(
        deprecated.is_empty(),
        "runtime contains deprecated localization key families: {}",
        deprecated.join(", ")
    );
}

fn is_allowed_runtime_dynamic_key(key: &str) -> bool {
    key.starts_with("action.") && key.ends_with(".description")
}

fn collect_runtime_locale_keys() -> Vec<String> {
    let mut keys = BTreeSet::new();
    for relative_path in RUNTIME_KEY_SOURCE_FILES {
        let path = workspace_root().join(relative_path);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()));
        for literal in extract_quoted_strings(&content) {
            if looks_like_locale_key(&literal) {
                keys.insert(literal);
            }
        }
    }
    keys.into_iter().collect::<Vec<_>>()
}

fn looks_like_locale_key(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    if !ALLOWED_TOP_LEVEL_DOMAINS.contains(&first) {
        return false;
    }

    let tail = parts.collect::<Vec<_>>();
    if tail.is_empty() {
        return false;
    }

    if !is_valid_key_segment(first) {
        return false;
    }

    tail.into_iter().all(is_valid_key_segment)
}

fn is_valid_key_segment(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn extract_quoted_strings(content: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = content.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }

        index += 1;
        let mut current = String::new();
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' {
                index += 1;
                if index < bytes.len() {
                    current.push(bytes[index] as char);
                    index += 1;
                }
                continue;
            }
            if byte == b'"' {
                index += 1;
                break;
            }
            current.push(byte as char);
            index += 1;
        }

        if !current.is_empty() {
            values.push(current);
        }
    }

    values
}

fn visit_locale_node(
    node: &Value,
    prefix: &str,
    is_root: bool,
    leaf_keys: &mut HashSet<String>,
    namespace_keys: &mut HashSet<String>,
    errors: &mut Vec<String>,
) {
    let Some(object) = node.as_object() else {
        errors.push(format!(
            "expected object at '{}'",
            if prefix.is_empty() { "<root>" } else { prefix }
        ));
        return;
    };

    if !is_root && !prefix.is_empty() {
        if leaf_keys.contains(prefix) {
            errors.push(format!(
                "namespace/leaf conflict: '{}' used as namespace and value",
                prefix
            ));
        }
        namespace_keys.insert(prefix.to_string());
    }

    for (key, child) in object {
        if is_root && key == "metadata" {
            continue;
        }

        if !is_valid_key_segment(key) {
            errors.push(format!(
                "invalid key segment '{}' at '{}'",
                key,
                if prefix.is_empty() { "<root>" } else { prefix }
            ));
        }

        let child_key = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };

        if child.is_object() {
            visit_locale_node(child, &child_key, false, leaf_keys, namespace_keys, errors);
            continue;
        }

        if let Some(value) = child.as_str() {
            if value.is_empty() {
                errors.push(format!("empty localized value at '{}'", child_key));
            }
            if namespace_keys.contains(&child_key) {
                errors.push(format!(
                    "namespace/leaf conflict: '{}' used as namespace and value",
                    child_key
                ));
            }
            if !leaf_keys.insert(child_key.clone()) {
                errors.push(format!("duplicate localized key '{}'", child_key));
            }
            continue;
        }

        errors.push(format!(
            "invalid value type for '{}': only string and object are allowed",
            child_key
        ));
    }
}

fn locale_files() -> Vec<PathBuf> {
    let directory = workspace_root().join("locales");
    let mut files = fs::read_dir(&directory)
        .unwrap_or_else(|error| {
            panic!(
                "failed to read locales directory '{}': {error}",
                directory.display()
            )
        })
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!(
                "failed to resolve workspace root from '{}': {error}",
                manifest_dir.display()
            )
        })
}
