//! A copy of the program that lacks part of its package says so in the
//! window, naming each part in both shipped languages, instead of leaving the
//! user to find out from a feature that stays silent. The executable check
//! runs the real `pure.js` through `node`; skipped when node is absent.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn run_node(program: &str) -> Option<String> {
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
        .write_all(program.as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn locale_text(locale: &serde_json::Value, key: &str) -> Option<String> {
    key.split('.')
        .try_fold(locale, |node, part| node.get(part))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// The slugs `delivery.rs` can put into the launch context.
fn context_slugs() -> Vec<String> {
    let source = repo_file("apps/desktop/gui/src/ui_surface/delivery.rs");
    source
        .lines()
        .filter(|line| line.starts_with("pub(super) const ") && line.contains(": &str = \""))
        .filter_map(|line| line.split('"').nth(1).map(str::to_owned))
        .collect()
}

#[test]
fn every_part_the_context_can_name_has_words_in_both_languages() {
    let slugs = context_slugs();
    assert_eq!(slugs.len(), 3, "{slugs:?}");
    let controller = repo_file("apps/desktop/qml/flows/NotificationsController.qml");
    let en: serde_json::Value =
        serde_json::from_str(&repo_file("locales/en.json")).unwrap_or_else(|e| panic!("{e}"));
    let ru: serde_json::Value =
        serde_json::from_str(&repo_file("locales/ru.json")).unwrap_or_else(|e| panic!("{e}"));
    let mut keys: Vec<String> = slugs
        .iter()
        .map(|slug| {
            assert!(
                controller.contains(&format!("slug === \"{slug}\"")),
                "the window has no words for the missing {slug}"
            );
            format!("notifications.delivery-incomplete.part.{slug}")
        })
        .collect();
    keys.extend(
        ["title", "body", "part.component"]
            .map(|k| format!("notifications.delivery-incomplete.{k}")),
    );
    for key in keys {
        for (lang, locale) in [("en", &en), ("ru", &ru)] {
            let text = locale_text(locale, &key).unwrap_or_default();
            assert!(!text.trim().is_empty(), "{key} missing in {lang}.json");
        }
    }
}

#[test]
fn the_window_reads_the_gaps_and_asks_the_service_for_its_own() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(
        main.contains("context.deliveryGaps") && main.contains("noteDeliveryGaps("),
        "the window no longer reads what the launch found missing"
    );
    assert!(
        main.contains("checkShippedComponentsOnce"),
        "the window no longer asks the service which of its components are missing"
    );
    let surface = repo_file("apps/desktop/gui/src/ui_surface.rs");
    assert!(surface.contains("\"deliveryGaps\": delivery_gaps"));
}

#[test]
fn only_a_binary_that_is_not_there_is_called_missing() {
    let source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", "");
    let Some(out) = run_node(&format!(
        "{source}\nconsole.log(JSON.stringify(missingShippedComponents([\
           {{ kind: 'binary', key: 'wintun', displayName: 'Wintun', requiredFor: 'fake-ip', verdict: 'missing' }},\
           {{ kind: 'binary', key: 'other', displayName: 'Other', requiredFor: 'x', verdict: 'untrusted' }},\
           {{ kind: 'binary', key: 'ok', displayName: 'Ok', requiredFor: 'x', verdict: 'genuine' }},\
           {{ kind: 'asset', key: 'icons', displayName: 'Icons', requiredFor: 'user-interface', verdict: 'missing' }},\
           null\
         ])), JSON.stringify(missingShippedComponents(undefined)));\n"
    )) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(
        out.trim(),
        "[{\"key\":\"wintun\",\"name\":\"Wintun\",\"feature\":\"fake-ip\"}] []"
    );
}
