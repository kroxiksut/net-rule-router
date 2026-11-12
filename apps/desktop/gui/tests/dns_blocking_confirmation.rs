#[path = "support/js.rs"]
mod js;

use std::path::Path;

use serde_json::{json, Value};

#[test]
fn an_omitted_dns_verdict_is_not_a_confirmed_off_state() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let panel = std::fs::read_to_string(
        root.join("apps/desktop/qml/sections/settings/RoutingSettings.qml"),
    )
    .unwrap_or_else(|e| panic!("read settings: {e}"))
    .replace("\r\n", "\n");
    let start = panel
        .find("function _loadKillSwitchPosture()")
        .unwrap_or_else(|| panic!("missing policy loader"));
    let rest = &panel[start..];
    let end = rest[1..]
        .find("\n    function ")
        .map_or(rest.len(), |i| i + 1);
    let loader = &rest[..end];
    let pure = std::fs::read_to_string(root.join("apps/desktop/qml/lib/pure.js"))
        .unwrap_or_else(|e| panic!("read client logic: {e}"));
    let output = js::run_js(&format!(
        r#"
{pure}
var panel = {{ _rememberRoutePolicy: function() {{}} }};
var root = {{
    bridgeAvailable: true,
    _routePolicyEffective: routePolicyEffective,
    rpc: {{ registerRpcCallback: function(corr, done) {{ done(true, reply) }} }}
}};
var nrrNativeBridge = {{ rpcSnapshotInitialGet: function() {{ return "read" }} }};
function _seedKillSwitchFromPrefs() {{ panel.dohLockdownEffective = null }}
{loader}
var results = [];
var replies = [{{}}, {{"doh-lockdown-effective": false}}, {{"doh-lockdown-effective": true}}];
for (var i = 0; i < replies.length; i++) {{
    var reply = {{"route-policy": replies[i]}};
    _loadKillSwitchPosture();
    results.push(panel.dohLockdownEffective);
}}
console.log(JSON.stringify(results));
"#
    ));
    let actual: Value = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("bad harness result: {e}: {output}"));
    assert_eq!(actual, json!([null, false, true]));
}

#[test]
fn a_dns_notice_keeps_a_hostile_program_name_literal_and_unambiguous() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let card =
        std::fs::read_to_string(root.join("apps/desktop/qml/components/DnsCompatibilityCard.qml"))
            .unwrap_or_else(|error| panic!("read card: {error}"))
            .replace("\r\n", "\n");
    let key = card
        .find("\"settings.routing.dns-compatibility.issue\"")
        .expect("issue label");
    let start = card[..key].rfind("text:").expect("issue text") + "text:".len();
    let end = card[start..]
        .find("\n            }\n        }\n")
        .expect("issue delegate end")
        + start;
    let expression = &card[start..end];
    let pure = std::fs::read_to_string(root.join("apps/desktop/qml/lib/pure.js"))
        .unwrap_or_else(|error| panic!("read client logic: {error}"));
    let program = serde_json::to_string("evil{reason}\u{202e}.exe").expect("program");
    let output = js::run_js(&format!(
        r#"
{pure}
var Pure = {{fillPlaceholders:fillPlaceholders, formatLogLine:formatLogLine,
    displayText:displayText, formatTimestamp:formatTimestamp}};
var root = {{tr:function(key, fallback) {{ return fallback; }} }};
var modelData = {{program:{program}, reason:"our-dns-block", evidence:"confirmed", attempts:1}};
console.log(JSON.stringify({expression}));
"#
    ));
    let text: String = serde_json::from_str(output.trim()).expect("rendered issue");
    assert!(
        text.contains("evil{reason}·.exe"),
        "a process name stays literal: {text}"
    );
    assert!(
        !text.contains('\u{202e}'),
        "a process name cannot change text direction"
    );
}
