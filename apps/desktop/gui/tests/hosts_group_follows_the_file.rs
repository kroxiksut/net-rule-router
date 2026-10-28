//! The hosts-file group in Routing settings shows only while the OS hosts file
//! holds a real mapping. The start-up context answers that once, so a mapping
//! added (or removed) under a running window left the group as it was until a
//! restart. Opening the page asks the launcher again, end to end: the page, the
//! transport, the native bridge and the launcher must agree on one operation.

use std::path::Path;

const OP: &str = "\"local.hosts-file.has-entries\"";

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The text from `start` up to `end` (both must exist, `end` after `start`).
fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text
        .find(start)
        .unwrap_or_else(|| panic!("`{start}` not found"));
    let rest = &text[from..];
    let to = rest[start.len()..]
        .find(end)
        .unwrap_or_else(|| panic!("`{end}` not found after `{start}`"));
    &rest[..start.len() + to]
}

#[test]
fn opening_routing_settings_rereads_the_hosts_file() {
    let page = read("../qml/sections/settings/RoutingSettings.qml");
    let group = between(
        &page,
        "\"settings.routing.hosts-group.title\"",
        "ColumnLayout {",
    );
    assert!(
        group.contains("visible: panel.hostsFileHasEntries"),
        "the group follows the page's live answer, not the start-up context:\n{group}"
    );
    let shown = between(&page, "onVisibleChanged: if (visible)", "\n");
    assert!(
        shown.contains("_reloadHostsFileState()"),
        "every visit asks again: {shown}"
    );
    let built = between(&page, "Component.onCompleted: {", "\n    }");
    assert!(
        built.contains("_reloadHostsFileState()"),
        "the first visit asks too"
    );
    let reload = between(&page, "function _reloadHostsFileState()", "\n    }");
    assert!(
        reload.contains("rpcHostsFileHasEntries()"),
        "the answer comes from the launcher, which reads the file the context read"
    );

    let transport = read("../qml/flows/RpcTransport.qml");
    let wrapper = between(&transport, "function rpcHostsFileHasEntries()", "\n    }");
    assert!(
        wrapper.contains("typeof bridge.rpcHostsFileHasEntries === \"function\""),
        "an older native host without the method keeps the start-up answer"
    );

    let header = read("../qt-host/native/src/native_bridge.h");
    assert!(header.contains("Q_INVOKABLE QString rpcHostsFileHasEntries();"));
    let bridge = read("../qt-host/native/src/native_bridge_files.cpp");
    let body = between(&bridge, "NrrNativeBridge::rpcHostsFileHasEntries()", "}");
    assert!(body.contains(OP), "the bridge sends the launcher's slug");

    let launcher = read("../launcher/src/local_handlers.rs");
    assert!(
        launcher.contains(&format!("{OP} =>")),
        "the launcher answers the slug the bridge sends"
    );
}
