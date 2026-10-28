//! The DoH resolvers, the local network names and the VPN gateway and program
//! lists are replaced whole by their `*.set` call. A write built from the copy
//! the window showed (or from a load that failed) erases what another client
//! changed meanwhile, and for the machine-wide lists it does so for every
//! user. Each write is therefore built on a read made just before it, and a
//! list that never loaded cannot be written.

use std::path::{Path, PathBuf};

fn qml(rel: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(rel);
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

fn before(haystack: &str, first: &str, second: &str) -> bool {
    match (haystack.find(first), haystack.find(second)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

#[test]
fn doh_resolver_save_reads_first_and_needs_a_loaded_list() {
    let text = qml("sections/settings/RoutingSettings.qml");
    let save = between(&text, "function _dohSave()", "function _dohSend(");
    assert!(
        save.contains("_dohLoaded"),
        "a list that never loaded must not be saved"
    );
    assert!(
        before(save, "rpcDohResolversGet()", "_dohSend("),
        "the write is built on a fresh read"
    );
    assert!(save.contains("Pure.dohResolversRebase("));
    assert!(
        save.contains("\"drop-seeded\""),
        "a deliberate removal says so, or the service refuses to drop a built-in entry"
    );
    let save_button = between(
        &text,
        "// ── Part B: save ──",
        "onClicked: dohLockdownGroup._dohSave()",
    );
    assert!(
        save_button.contains("enabled: dohLockdownGroup._dohLoaded"),
        "the Save button waits for the list"
    );
    assert!(
        text.contains("settings.routing.doh-lockdown.resolvers.not-read"),
        "a failed load is told apart from an empty list"
    );
}

#[test]
fn local_network_names_change_a_fresh_read() {
    let text = qml("sections/settings/RoutingSettings.qml");
    let add = between(&text, "function _add(name)", "function _remove(");
    assert!(
        add.contains("_mutate(") && !add.contains("_save("),
        "adding goes through the fresh read"
    );
    let remove = between(&text, "function _remove(", "Component.onCompleted");
    assert!(remove.contains("_mutate(") && !remove.contains("_save("));
    let mutate = between(&text, "function _mutate(change)", "function _save(");
    assert!(
        mutate.contains("_loaded"),
        "nothing is written before a load"
    );
    assert!(
        before(mutate, "rpcLocalDnsSuffixesGet()", "_save("),
        "the change runs on a fresh read"
    );
    let reload = between(
        &text,
        "function _reloadServiceBackedControls()",
        "Component.onCompleted",
    );
    assert!(
        reload.contains("localSuffixesGroup._load()"),
        "a reconnect reads the list again"
    );
}

#[test]
fn vpn_gateway_writes_build_on_a_fresh_read() {
    let main = qml("Main.qml");
    let write = between(
        &main,
        "function _writeVpnGateways(build, onSaved)",
        "function _trustVpnGateway(",
    );
    assert!(
        before(write, "_linkProvidersRead()", "rpcRouteVpnGatewaysSet("),
        "the gateway set is read just before it is replaced"
    );
    assert!(write.contains("build("));
    let panel = qml("components/LinkProvidersPanel.qml");
    for (file, text) in [
        ("Main.qml", main.as_str()),
        ("components/LinkProvidersPanel.qml", panel.as_str()),
    ] {
        assert!(
            !text.contains("_writeVpnGateways(Pure."),
            "{file}: a finished list built from the shown copy"
        );
    }
}

#[test]
fn vpn_programs_come_back_only_to_a_service_that_lost_the_policy() {
    let main = qml("Main.qml");
    let resync = between(
        &main,
        "function _resyncLinkProvidersFromPrefs(snapshot)",
        "_writeLinkProviderSet(apps)",
    );
    assert!(
        !resync.contains("svc.length"),
        "an empty set beside a stored policy is the user's own"
    );
    let guard = resync
        .find("if (rpRaw)")
        .expect("a stored policy ends the resync");
    let joined = resync
        .find("confirmedVpnExePaths")
        .expect("the prefs mirror");
    assert!(
        guard < joined,
        "the policy check comes before the mirror is read"
    );
}

#[test]
fn retention_and_traffic_settings_lay_the_change_over_a_fresh_read() {
    let main = qml("Main.qml");
    let retention = between(
        &main,
        "function setRetentionSettings(values)",
        "function setApplyFailurePolicy(",
    );
    assert!(before(
        retention,
        "rpcRetentionSettingsGet()",
        "rpcRetentionSettingsSet("
    ));
    let panel = qml("sections/settings/RetentionSettings.qml");
    assert!(panel.contains("root.setRetentionSettings(group._changedFields())"));

    let traffic = qml("components/TrafficStatsController.qml");
    let patch = between(
        &traffic,
        "function applyPatch(patch)",
        "function applySettings(",
    );
    assert!(before(patch, "rpcTrafficStatsGet(", "applySettings("));
    let settings = qml("sections/settings/TrafficStatsSettings.qml");
    assert!(settings.contains("ctrl.applyPatch(patch)"));
}

/// The log and audit limits are replaced all four at once: a page whose read
/// failed held the defaults, and saving one edited limit put the defaults back
/// over the other three.
#[test]
fn log_retention_lays_the_change_over_a_fresh_read() {
    let text = qml("sections/settings/DiagnosticsLogsSettings.qml");
    let apply = between(
        &text,
        "function _applyLogRetention()",
        "function _fetchLogRetentionConfig(",
    );
    assert!(
        before(
            apply,
            "rpcLogRetentionConfigGet()",
            "rpcLogRetentionConfigSet("
        ),
        "the limits are written without a read just before:\n{apply}"
    );
    assert!(
        apply.contains("shown[key] !== baseline[key] ? shown[key] : fresh[key]"),
        "an unedited limit must come from the fresh read:\n{apply}"
    );
}

/// Every `*.set` the window calls, by how it is kept from writing back what it
/// never read. A new setter fails here until it is placed and, if it replaces
/// a whole value, held by a test above.
#[test]
fn every_setter_is_held_to_what_it_read() {
    // Replace a whole list or row: each has its fresh-read test in this file
    // or in `stability_wire_contract.rs`.
    const WHOLE: &[&str] = &[
        "rpcDohResolversSet",
        "rpcLocalDnsSuffixesSet",
        "rpcRouteVpnGatewaysSet",
        "rpcRouteLinkProviderSet",
        "rpcRetentionSettingsSet",
        "rpcTrafficStatsSet",
        "rpcLogRetentionConfigSet",
        "rpcServiceStabilityConfigSet",
    ];
    // Carry one item or the fields named: nothing unread is restated.
    const PARTIAL: &[&str] = &[
        "rpcBlockNoticeMutesSet",
        "rpcConnHistorySettingsSet",
        "rpcLocalNetworksSet",
        "rpcRefusingAnchorSet",
        "rpcTrafficHistoryMergeSet",
        "rpcApplyFailurePolicySet",
    ];
    let mut called = std::collections::BTreeSet::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.unwrap_or_else(|e| panic!("{e}")).path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.extension().is_some_and(|e| e == "qml" || e == "js") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for (at, _) in text.match_indices("rpc") {
                let name: String = text[at..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                let set_call = name.len() > "rpcSet".len()
                    && name.ends_with("Set")
                    && text[at + name.len()..].starts_with('(');
                if set_call && name[3..].starts_with(|c: char| c.is_ascii_uppercase()) {
                    called.insert(name);
                }
            }
        }
    }
    assert!(
        called.contains("rpcDohResolversSet"),
        "the scan found none of the known setters: {called:?}"
    );
    let unplaced: Vec<&String> = called
        .iter()
        .filter(|n| !WHOLE.contains(&n.as_str()) && !PARTIAL.contains(&n.as_str()))
        .collect();
    assert!(
        unplaced.is_empty(),
        "setters nobody has placed: {unplaced:?}"
    );
}
