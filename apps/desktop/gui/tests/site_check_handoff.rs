#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml;

#[test]
fn nov10_a_late_start_callback_cannot_replace_the_newly_requested_site() {
    let functions = qml::functions("components/SiteCheckPanel.qml", &["_run"]);
    let program = format!(
        r#"
var callbacks = [], input = {{text:"first.example"}};
var hostInput = input, _report = null, _errorCode = "", _running = false;
var _host = "", _startedAt = 0, _generation = 0;
var panel = globalThis, followTimer = {{restart:function() {{}},stop:function() {{}}}};
var root = {{rpc:{{rpcSiteCheckRun:function(h) {{return h}},
    registerRpcCallback:function(c,done) {{callbacks.push(done)}}}}}};
{functions}
_run(); input.text = "himalayas.app"; _run();
callbacks[1](true,{{host:"himalayas.app"}});
callbacks[0](true,{{host:"first.example"}});
console.log(_host);
"#
    );
    assert_eq!(js::run_js(&program), "himalayas.app\n");
}

#[test]
fn nov10_a_previous_site_report_is_not_displayed_for_the_requested_site() {
    let functions = qml::functions("components/SiteCheckPanel.qml", &["_poll"]);
    let program = format!(
        r#"
var _startedAt = Date.now(), _followMs = 30000, _generation = 1;
var _running = true, _host = "himalayas.app", _report = null, _errorCode = "";
var panel = globalThis, followTimer = {{restart:function() {{}}}};
var root = {{rpc:{{rpcSiteCheckResult:function() {{return "read"}},
 registerRpcCallback:function(c,done) {{done(true,{{state:"done",host:"other.example",
 report:{{site:"other.example",verdict:"fine"}}}})}}}}}};
{functions}
_poll(); console.log(_report === null && _running);
"#
    );
    assert_eq!(js::run_js(&program), "true\n");
}

#[test]
fn nov10_check_site_handoff_keeps_the_address_through_navigation() {
    let functions = qml::functions(
        "flows/NotificationsController.qml",
        &["checkSiteInDiagnostics"],
    );
    let consume = qml::functions(
        "sections/DiagnosticsSection.qml",
        &["_consumePendingSiteCheck"],
    );
    let program = format!(
        r#"
var pendingSiteCheckHost = "", pendingSiteCheckFocus = false;
var nc = globalThis, requested = [], checked = [];
var root = {{section:"rules",notificationsController:nc,
 requestSectionChange:function(section) {{requested.push(section);this.section=section}}}};
var siteCheckPanel = {{check:function(h) {{checked.push(h)}},focusInput:function() {{}}}};
var Qt = {{callLater:function(f) {{}}}};
{functions}
{consume}
checkSiteInDiagnostics(" https://himalayas.app/ ");
_consumePendingSiteCheck(); _consumePendingSiteCheck();
console.log(checked.join(",")); console.log(requested.join(","));
"#
    );
    assert_eq!(
        js::run_js(&program),
        "https://himalayas.app/\ndiagnostics\n"
    );
}
