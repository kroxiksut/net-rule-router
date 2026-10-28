//! A service that stops or is removed while the window is open is named as
//! such on the banner, not as an unexplained drop, so the banner can offer
//! Start or Install. The executable checks run the real `pure.js`.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn answers(expressions: &str) -> String {
    let source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", "");
    js::run_js(&format!(
        "{source}\nconsole.log(JSON.stringify([{expressions}]));\n"
    ))
}

#[test]
fn the_service_manager_sharpens_an_unexplained_drop() {
    let out = answers(
        "offlineBackendKind('disconnected', 'not-installed'),\
         offlineBackendKind('disconnected', 'stopped'),\
         offlineBackendKind('disconnected', 'running'),\
         offlineBackendKind('disconnected', ''),\
         offlineBackendKind('connecting', 'stopped'),\
         offlineBackendKind('refused', 'not-installed')",
    );
    assert_eq!(
        out.trim(),
        "[\"service-not-installed\",\"service-stopped\",\"disconnected\",\
         \"disconnected\",\"connecting\",\"refused\"]"
    );
}

#[test]
fn one_outage_is_logged_once_however_it_is_named() {
    let out = answers(
        "backendOutageContinues('disconnected', 'service-stopped'),\
         backendOutageContinues('service-stopped', 'service-not-installed'),\
         backendOutageContinues('connected', 'service-stopped'),\
         backendOutageContinues('connecting', 'disconnected'),\
         backendOutageContinues(undefined, 'disconnected')",
    );
    assert_eq!(out.trim(), "[true,true,false,false,false]");
}

/// Every banner kind the poll can now set has its own text.
#[test]
fn the_window_names_the_kind_its_poll_sets() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    let poll = main
        .split("function refreshBackendStatus()")
        .nth(1)
        .and_then(|rest| rest.split("\n    function ").next())
        .unwrap_or_else(|| panic!("refreshBackendStatus not found"));
    assert!(
        poll.contains("Pure.offlineBackendKind(") && poll.contains("_serviceStatusSlug()"),
        "the health poll no longer asks the service manager why the service is gone"
    );
    let banner = main
        .split("function backendStatusBannerText()")
        .nth(1)
        .unwrap_or_else(|| panic!("backendStatusBannerText not found"));
    for kind in ["service-stopped", "service-not-installed"] {
        assert!(
            banner.contains(&format!("case \"{kind}\":")),
            "no banner text for {kind}"
        );
    }
}
