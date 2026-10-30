#![allow(clippy::expect_used)]

//! Loading a rule set is "load and apply": a stopped service is started first
//! so the set reaches it in the same action, and the outcome is a message box
//! the user cannot miss — the window that started the load (the first-run
//! window) may be gone by then. The box names what went wrong: a service that
//! is not installed is not one that "could not be started", a service that
//! has just started is waited for rather than reported down, and a load whose
//! start was overtaken by another service action hears so. Runs the start
//! helper's and the load controller's own functions against a stand-in.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const STARTER: &[&str] = &[
    "_ctl",
    "_tr",
    "startIfStoppedThen",
    "waitForAnswerThen",
    "restartThen",
    "_begin",
    "_finish",
    "_operationCompleted",
    "_uacDeclined",
    "_tick",
];

const LOADER: &[&str] = &[
    "_whenServiceUp",
    "_retryWhenAnswering",
    "_applyPresetImportOffline",
    "_ruleSetName",
    "_reportImportFailure",
    "_announcePreviewRefusal",
    "_announcePresetImportFailed",
    "_completePresetImportActivation",
    "startBothRoutesPresetImportReviewFlow",
];

/// The service controller (status 1 not installed, 2 stopped, 4 running), the
/// window's channel (`connected`) and the controllers a load reaches. Every
/// call that matters is logged.
const STAND_IN: &str = r#"
function say(line) { console.log(line) }
var connected = false;
var nrrServiceController = {
    status: 2, busy: false,
    startService: function() { say("start") },
    restartService: function() { say("restart") }
};
var _op = "", _opDone = false, _failure = "", _waiters = [];
var _watch = { attempts: 0, stop: function() {}, restart: function() {} };
var serviceStarter = globalThis;
var dryRunAnswer = null;
var nrrNativeBridge = {
    rpcMutationSubmit: function(kind, payload, dryRun) {
        say(dryRun ? "dry run" : "apply");
        return "corr";
    }
};
var root = {
    tr: function(key, fallback) { return fallback },
    statusLine: "",
    bridgeAvailable: true,
    importOnlyActiveSession: true,
    pendingPresetImportState: null,
    serviceStarter: serviceStarter,
    _routingBackendConnected: function() { return connected },
    refreshBackendStatus: function() {},
    serviceOperationErrorText: function(code, message) { return message },
    ipcErrorLabel: function(code) { return code },
    showNotice: function(title, body) { say("notice " + title + ": " + body) },
    reviewIsSuperseded: function() { return false },
    reviewDiffDialog: { open: function() { say("review") } },
    setUnsavedChanges: function() {},
    _refreshRulesFromService: function() {},
    rpc: {
        registerLongRpcCallback: function(corr, callback) { dryRunAnswer = callback }
    }
};
function _refreshRulesAfterPresetImport(state, options) {
    options.onComplete({ rulesCount: 3, passthroughByRoute: {} })
}
function _bindImportedSourcePaths() {}
function _formatImportPassthroughSuffix() { return "" }
function _formatNewerFormatSuffix() { return "" }
function startsUp() { connected = true; nrrServiceController.status = 4; _tick() }
"#;

fn plurals() -> String {
    let body: String = qml_functions::read("lib/plurals.js")
        .lines()
        .filter(|line| !line.trim_start().starts_with('.'))
        .collect::<Vec<_>>()
        .join("\n");
    format!("var Plurals = (function() {{ {body}\n return {{ counted: counted }} }})();")
}

fn run(scenario: &str) -> String {
    js::run_js(&format!(
        "{}\n{}\n{STAND_IN}\n{}\n{}\n{scenario}\n",
        qml_functions::pure(),
        plurals(),
        qml_functions::functions("flows/ServiceStarter.qml", STARTER),
        qml_functions::functions("flows/PresetImportController.qml", LOADER),
    ))
}

const LOAD: &str =
    "startBothRoutesPresetImportReviewFlow('cA==', 'cw==', 'C:/sets/home/rules_primary.txt', '', { label: 'Home' });";

#[test]
fn a_load_starts_a_stopped_service_and_asks_it_once_it_answers() {
    let output = run(&format!(
        "{LOAD}\nsay('-- started');\nstartsUp();\ndryRunAnswer(true, {{ 'review-summary': {{ 'rules-added': [{{}}] }}, 'confirmation-token': 't' }});"
    ));
    let start = output.find("start\n").expect("the service was started");
    let asked = output.find("dry run").expect("the set went to the service");
    let up = output.find("-- started").expect("marker");
    assert!(start < up && up < asked, "{output}");
    assert!(output.contains("review"), "{output}");
}

#[test]
fn a_service_that_is_not_installed_is_named_so() {
    let output = run(&format!("nrrServiceController.status = 1;\n{LOAD}"));
    assert!(!output.contains("start\n"), "{output}");
    assert!(!output.contains("dry run"), "{output}");
    assert!(output.contains("is not installed"), "{output}");
    assert!(!output.contains("could not be started"), "{output}");
}

/// Running to the service manager is not yet listening on its channel: the
/// load waits for it instead of calling it down.
#[test]
fn a_service_that_has_just_started_is_waited_for() {
    let output = run(&format!(
        "nrrServiceController.status = 4;\n{LOAD}\nsay('-- waiting');\n_tick();\nconnected = true;\n_tick();"
    ));
    assert!(!output.contains("notice"), "{output}");
    let waiting = output.find("-- waiting").expect("marker");
    let asked = output
        .find("dry run")
        .expect("the set went once it answered");
    assert!(waiting < asked, "{output}");

    // A dry run that found no channel waits once more before going offline.
    let output = run(&format!(
        "nrrServiceController.status = 4; connected = true;\n{LOAD}\n\
         connected = false;\n\
         dryRunAnswer(false, null, 'transport-disconnected', '');\n\
         say('-- retry');\n\
         connected = true;\n_tick();"
    ));
    assert!(!output.contains("notice"), "{output}");
    assert_eq!(output.matches("dry run").count(), 2, "{output}");
}

#[test]
fn a_service_that_never_answers_is_told_in_bounded_time() {
    let output = run(&format!(
        "nrrServiceController.status = 4;\n{LOAD}\nfor (var i = 0; i < 61; i += 1) _tick();"
    ));
    assert!(!output.contains("dry run"), "{output}");
    assert!(
        output.contains("did not start answering in time"),
        "{output}"
    );
}

/// Two loads while the service starts are both carried by the one start; a
/// restart that overtakes a start tells the waiting load instead of dropping it.
#[test]
fn a_flow_overtaken_by_another_service_action_hears_so() {
    let output = run(
        "startIfStoppedThen(function() { say('first on') }, function(r) { say('first failed: ' + r) });\n\
         startIfStoppedThen(function() { say('second on') }, function(r) { say('second failed: ' + r) });\n\
         startsUp();",
    );
    assert_eq!(output.matches("start\n").count(), 1, "{output}");
    assert!(
        output.contains("first on") && output.contains("second on"),
        "{output}"
    );

    let output = run(
        "startIfStoppedThen(function() { say('load on') }, function(r) { say('load failed: ' + r) });\n\
         restartThen(function() { say('restart on') }, function(r) { say('restart failed') });",
    );
    assert!(
        output.contains("load failed: Another service action started"),
        "a superseded load vanished without a word:\n{output}"
    );
}

#[test]
fn an_applied_set_is_confirmed_in_a_message_box_naming_it_and_its_count() {
    let output = run("_completePresetImportActivation({ label: 'Home' });");
    assert!(
        output.contains("notice Rule set applied: «Home»: 3 rules are now in use."),
        "{output}"
    );
}

#[test]
fn a_failed_load_is_a_message_box_with_the_reason() {
    let output = run(&format!(
        "nrrServiceController.status = 4; connected = true;\n{LOAD}\n\
         dryRunAnswer(false, null, 'rules-locked', '');"
    ));
    assert!(
        output.contains("notice The rules were not imported"),
        "{output}"
    );
    assert!(output.contains("rules-locked"), "{output}");
}
