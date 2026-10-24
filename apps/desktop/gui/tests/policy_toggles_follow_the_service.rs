//! A routing toggle shows what the service confirmed. Written ahead of the
//! write, the preference mirror outlived a declined prompt: the box stayed ON
//! while the service held OFF, and the panel re-sent that stale value on every
//! visit, over whatever the terminal client had set since. The mirror now
//! follows a confirmed write, a refused write puts the controls back, and
//! nothing in the panel writes the policy on its own.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The text of `function <name>(` up to the next function at the same depth.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name} is gone"));
    let rest = &source[start..];
    let end = rest[1..]
        .find("\n    function ")
        .map_or(rest.len(), |at| at + 1);
    &rest[..end]
}

/// `pure.js` plus `body`, run by node; `None` when node is not installed.
fn run_pure(body: &str) -> Option<Value> {
    let pure = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", "");
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!("this check runs the QML JavaScript through node; install Node.js ({e})")
        });
    let Some(stdin) = child.stdin.as_mut() else {
        panic!("stdin was piped")
    };
    stdin
        .write_all(format!("{pure}\n{body}\n").as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(
        serde_json::from_str(text.trim())
            .unwrap_or_else(|e| panic!("harness output is not JSON: {e}; output: {text}")),
    )
}

/// Lines that assign a `route*` preference in place (`root.prefs.routeX = `).
fn in_place_pref_writes(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| {
            let Some(at) = line.find("root.prefs.route") else {
                return false;
            };
            let after = &line[at + "root.prefs.".len()..];
            let name_len = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            let tail = after[name_len..].trim_start();
            tail.starts_with('=') && !tail.starts_with("==")
        })
        .map(str::trim)
        .collect()
}

#[test]
fn the_mirror_follows_a_confirmed_write_only() {
    let controller = repo_file("apps/desktop/qml/flows/RoutePolicyController.qml");
    assert!(
        in_place_pref_writes(&controller).is_empty(),
        "a preference mirror written ahead of the service: {:?}",
        in_place_pref_writes(&controller)
    );
    let drain = function_body(&controller, "_drainPolicyWrites");
    assert!(
        drain.contains("if (ok2) _mirrorConfirmedPolicy(req, changed)"),
        "the mirror is written once the service confirmed:\n{drain}"
    );
    assert!(
        drain.contains("else policyWriteRefused(confirmed)"),
        "a refused write tells the panels what the service kept:\n{drain}"
    );
    let mirror = function_body(&controller, "_mirrorConfirmedPolicy");
    assert!(mirror.contains("Pure.routePolicyPrefMirrorPatch(req, changed)"));
    assert!(mirror.contains("root.commitPrefs(patch)"));
    assert_eq!(
        controller.matches("_mirrorConfirmedPolicy(").count(),
        2,
        "the mirror has one writer, the queue's drain"
    );
}

#[test]
fn the_panels_never_write_the_policy_on_their_own() {
    let routing = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    for writer in [
        "mutateRoutePolicy(",
        "_applyRoutePolicyKey",
        "_reseedTogglesFromPrefs",
    ] {
        assert!(
            !routing.contains(writer),
            "RoutingSettings carries {writer}"
        );
    }
    // The mode preference is no longer written at the call sites ahead of the
    // service either.
    for file in [
        "apps/desktop/qml/sections/settings/RoutingSettings.qml",
        "apps/desktop/qml/sections/InterfacesRoutesSection.qml",
    ] {
        let text = repo_file(file);
        assert!(
            !text.contains("updatePrefs({ routeBehaviorMode"),
            "{file} writes the mode preference ahead of the service"
        );
        assert!(
            text.contains("function onPolicyWriteRefused(confirmed)"),
            "{file} does not put its controls back after a refused write"
        );
    }
    let show = function_body(&routing, "_showConfirmedPolicy");
    for key in [
        "leak-protection",
        "kill-switch-protocols",
        "allow-dns-over-primary",
        "include-subdomains",
        "resolve-hosts-bypass",
        "mode",
    ] {
        assert!(
            show.contains(&format!("\"{key}\": [")),
            "{key} is not put back"
        );
    }
}

#[test]
fn the_restored_notice_went_with_the_reseed() {
    for file in [
        "apps/desktop/qml/Main.qml",
        "apps/desktop/qml/flows/NotificationsController.qml",
        "locales/en.json",
        "locales/ru.json",
    ] {
        let text = repo_file(file);
        assert!(
            !text.contains("kill-switch-restored"),
            "{file} keeps the dead notice"
        );
    }
}

#[test]
fn the_mirror_patch_names_only_mirrored_keys_the_write_changed() {
    let Some(out) = run_pure(
        r#"var req = { "mode": "prefer-secondary", "kill-switch-protocols": 3,
            "doh-lockdown-enabled": true, "include-subdomains": false, "primary": { "stable-id": "a" } };
        console.log(JSON.stringify([
            routePolicyPrefMirrorPatch(req, ["kill-switch-protocols", "doh-lockdown-enabled", "primary"]),
            routePolicyPrefMirrorPatch(req, ["mode", "include-subdomains"]),
            routePolicyPrefMirrorPatch(req, []),
            routePolicyPrefMirrorPatch({}, ["kill-switch-protocols"])
        ]))"#,
    ) else {
        eprintln!("node not available - skipping the mirror-patch check");
        return;
    };
    assert_eq!(
        out,
        json!([
            { "routeKillSwitchProtocols": 3 },
            { "routeBehaviorMode": "prefer-secondary", "routeIncludeSubdomains": false },
            {},
            {}
        ])
    );
}

/// The routing settings offered follow the additional connection the service
/// holds, as the terminal client reads it, never the pickers' preference; and
/// a confirmed write keeps that reading current.
#[test]
fn the_routing_settings_read_the_bound_connection_from_the_service() {
    let panel = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    let bound = panel
        .split("readonly property bool secondaryBound:")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .expect("the panel's binding reading");
    assert!(
        bound.contains("root._servicePolicySecondaryBound"),
        "{bound}"
    );
    assert!(!bound.contains("prefs"), "{bound}");

    let main = repo_file("apps/desktop/qml/Main.qml");
    let note = function_body(&main, "_noteServicePolicy");
    assert!(note.contains("_servicePolicySecondaryBound ="), "{note}");
    let controller = repo_file("apps/desktop/qml/flows/RoutePolicyController.qml");
    let drain = function_body(&controller, "_drainPolicyWrites");
    assert!(drain.contains("root._noteServicePolicy(p2"), "{drain}");
}
