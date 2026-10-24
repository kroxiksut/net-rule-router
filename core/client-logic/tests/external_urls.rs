#![allow(clippy::expect_used)]

//! The window hands a URL it did not build (an about payload, a manifest, a
//! preference, a link inside a translation) only to the browser: the OS opener
//! runs whatever is registered, and a `file:` URL to a program starts it. Each
//! case below is a way someone could try to get a program started.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;
use serde_json::Value;

fn openable(pure: &mut JsLib, url: &str) -> bool {
    let call = format!(
        "isOpenableExternalUrl({})",
        serde_json::to_string(url).expect("json")
    );
    pure.eval_json(&call) == Value::Bool(true)
}

#[test]
fn only_the_web_reaches_the_os_opener() {
    let mut pure = JsLib::pure();
    for web in [
        "https://example.com/releases",
        "http://example.com",
        "HTTPS://EXAMPLE.COM/x",
    ] {
        assert!(openable(&mut pure, web), "{web} is the web");
    }
    for attempt in [
        "file:///C:/Users/u/Downloads/x.exe",
        "FILE:////host/share/x.exe",
        "file://host/share/x.exe",
        "ms-settings:network",
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "search-ms:query=x",
        r"C:\Users\u\Downloads\x.exe",
        r"\\host\share\x.exe",
        " https://example.com",
        "\thttps://example.com",
        "https:/example.com",
        "",
    ] {
        assert!(
            !openable(&mut pure, attempt),
            "{attempt:?} must not reach the opener"
        );
    }
    assert_eq!(
        pure.eval_json("isOpenableExternalUrl(null)"),
        Value::Bool(false)
    );
    assert_eq!(
        pure.eval_json("isOpenableExternalUrl(undefined)"),
        Value::Bool(false)
    );
}

fn own_folder(pure: &mut JsLib, url: &str) -> String {
    let call = format!(
        "ownFolderPath({})",
        serde_json::to_string(url).expect("json")
    );
    pure.eval_json(&call).as_str().expect("a string").to_owned()
}

/// Folders the window computes turn into local paths; a share, a host, a query
/// or another scheme gives nothing to open. The bridge then opens only an
/// existing directory, so a path to a program in this shape opens nothing.
#[test]
fn an_own_folder_is_a_local_path_or_nothing() {
    let mut pure = JsLib::pure();
    let computed = |pure: &mut JsLib, path: &str| {
        let call = format!(
            "ownFolderPath(localFolderUrl({}))",
            serde_json::to_string(path).expect("json")
        );
        pure.eval_json(&call).as_str().expect("a string").to_owned()
    };
    assert_eq!(
        computed(&mut pure, r"C:\ProgramData\NetRuleRouter\logs"),
        "C:/ProgramData/NetRuleRouter/logs"
    );
    assert_eq!(
        computed(&mut pure, "/var/log/netrulerouter"),
        "/var/log/netrulerouter"
    );
    assert_eq!(computed(&mut pure, ""), "");
    for attempt in [
        "file:////host/share",
        "file://host/share",
        "file:///C:/x?open=1",
        "file:///C:/x#frag",
        "https://example.com",
        "ms-settings:network",
        "",
    ] {
        assert_eq!(
            own_folder(&mut pure, attempt),
            "",
            "{attempt:?} is not an own folder"
        );
    }
}

#[test]
fn pure_js_opens_nothing_but_the_web_itself() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/qml/lib/pure.js"),
    )
    .expect("pure.js");
    assert_eq!(
        source.matches("Qt.openUrlExternally(").count(),
        1,
        "the one call is the web door in openExternalUrl"
    );
}
