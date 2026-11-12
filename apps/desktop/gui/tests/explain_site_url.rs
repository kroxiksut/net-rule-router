#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml;

#[test]
fn nov10_a_pasted_site_url_is_matched_as_its_exact_host_without_widening_www() {
    let functions = qml::functions("components/RuleDiagnosticsPanel.qml", &["_runExplainProbe"]);
    let rules = qml::functions(
        "lib/rules.js",
        &["isHostlikeRuleType", "normalizeHostInput"],
    );
    let program = format!(
        r#"
{rules}
var Rules = globalThis;
var _probeSampleIp = "203.0.113.3", _probeSampleProcess = "browser.exe";
var _probeInputText = "https://www.himalayas.app/path?q=secret";
var request = null, panel = globalThis;
var root = {{bridgeAvailable:true,rpc:{{registerRpcCallback:function() {{}}}}}};
var nrrNativeBridge = {{rpcExplainGetBySample:function(h,ip,p) {{request=[h,ip,p];return "read"}}}};
function _isIpv4() {{return false}} function _isIpv6() {{return false}}
{functions}
_runExplainProbe(); console.log(JSON.stringify(request));
"#
    );
    assert_eq!(
        js::run_js(&program),
        "[\"www.himalayas.app\",\"203.0.113.3\",\"browser.exe\"]\n"
    );
}
