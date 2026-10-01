//! "Dismiss" and "Clear all" on the new-version notice hide it until a release
//! other than the dismissed one is offered. The notice is rebuilt from state,
//! so the dismissal has to live in the preferences, not in the notice list.
//! Runs the real `pure.js` through `node`; skipped when node is absent.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn dismissing_the_notice_records_the_release_it_named() {
    let controller = repo_file("apps/desktop/qml/flows/NotificationsController.qml");
    let branch = controller
        .find("notificationId === \"update-available\"")
        .map(|at| &controller[at..])
        .unwrap_or_else(|| panic!("dismissNotification does not handle the update notice"));
    let branch = &branch[..branch.find("}\n").unwrap_or(branch.len())];
    assert!(
        branch.contains("dismissedUpdateVersion"),
        "the dismissal is not remembered by version"
    );
    assert!(
        branch.contains("root.emitPrefs()"),
        "the dismissal is not persisted"
    );

    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(
        main.contains("Pure.updateOfferShown(upd, prefs.dismissedUpdateVersion)"),
        "the notice no longer consults the dismissed version"
    );
    // "Clear all" dismisses through the same path.
    let popup = repo_file("apps/desktop/qml/components/NotificationCenterPopup.qml");
    assert!(popup.contains("notificationsController.dismissNotification(ids[j])"));
}

#[test]
fn a_dismissed_release_stays_hidden_and_another_one_shows() {
    let harness = format!(
        "{source}\n\
         var offer = {{ latestVersion: '2.4.0', url: 'u' }};\n\
         console.log([updateOfferShown(offer, ''), updateOfferShown(offer, '2.4.0'),\n\
                      updateOfferShown({{ latestVersion: '2.5.0', url: 'u' }}, '2.4.0'),\n\
                      updateOfferShown(null, ''), updateOfferShown({{ latestVersion: '' }}, ''),\n\
                      updateOfferShown(offer, undefined)].join(','));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(
        output.trim(),
        "true,false,true,false,false,true",
        "{output}"
    );
}

/// Feed a program to `node` on stdin. `None` when node is not installed.
fn run_node(program: &str) -> Option<String> {
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
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
