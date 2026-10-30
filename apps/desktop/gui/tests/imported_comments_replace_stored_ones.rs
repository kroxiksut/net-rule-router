#![allow(clippy::expect_used)]

//! A rule's comment is kept beside the rules, so a file loaded over a set the
//! user had before must replace the comments that set left behind: loading the
//! English demo set and then the Russian one showed Russian rules under English
//! notes until a full reset. A merge keeps the notes of the rules it already
//! had, and a rule deleted and applied takes its note with it — even when it
//! was the last one. Runs the controllers' own functions against a stand-in.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const IMPORT: &[&str] = &[
    "_refreshRulesAfterPresetImport",
    "_writeImportedComments",
    "_completePresetImportActivation",
];

const STAND_IN: &str = r#"
function say(line) { console.log(line) }
var answers = [];
function answerAll() { var a = answers; answers = []; for (var i = 0; i < a.length; i += 1) a[i](true, {}) }
function model(rows) { return { rows: rows, count: rows.length, get: function(i) { return this.rows[i] } } }
var bridgeAvailable = true, _bridgeReady = true;
var nrrNativeBridge = {
    rpcSidecarCommentWrite: function(type, value, route, comment) {
        say("write " + type + "|" + value + "|" + route + " = '" + comment + "'"); return "w"
    },
    rpcSidecarCommentGc: function(active) { say("sweep keeps " + active.length); return "gc" },
    rpcSidecarCommentReadAll: function() { return "read" },
    rpcSidecarPendingApplyClear: function() { return "c" }
};
// What the comment store holds; a read of it answers at once.
var stored = {};
var rpc = { registerRpcCallback: function(corr, callback) {
    if (corr === "read") callback(true, { comments: stored }); else answers.push(callback)
} };
var rpcTransport = rpc;
var ruleEditSupport = { writeComment: function(row, answered) { writeComment(row, answered) } };
var rulesModel = model([]);
var parsed = {};
function _parseCanonicalRulesAsync(text, route, startId, callback) {
    callback({ rows: parsed[route] || [], passthrough: [], duplicateSections: [] })
}
function _writeImportedPassthrough() {}
function _bindImportedSourcePaths() {}
function _formatImportPassthroughSuffix() { return "" }
function _formatNewerFormatSuffix() { return "" }
function _ruleSetName() { return "" }
var Qt = { callLater: function() {} };
var root = {
    tr: function(key, fallback) { return fallback },
    statusLine: "",
    rulesModel: rulesModel,
    unsavedChangesRegistry: {},
    pendingReviewState: { adminBaseline: false },
    _b64ToUtf8: function(text) { return text },
    _sidecarWriteCommentForRow: function(row, answered) { _sidecarWriteCommentForRow(row, answered) },
    _gcSidecarCommentOrphans: function(applied) { _gcSidecarCommentOrphans(applied) },
    _overlaySidecarCommentsOntoRulesModel: function() { say("table re-reads the comments") },
    _refreshRulesFromService: function() { say("table re-reads the rules") },
    _captureRulesDirtyBaseline: function() {},
    setUnsavedChanges: function() {},
    showNotice: function() {},
    rpc: rpc,
    boundFilesController: { _reconcileBoundFileDirty: function() {}, _persistBoundFilesAfterApply: function() {} },
    driftController: { _driftCaptureServiceBaseline: function() {}, _driftRecheckNow: function() {} }
};
function _resolveGuardRulesApply() {}
function row(type, value, route, comment) {
    return { ruleType: type, matchValue: value, targetRoute: route, comment: comment, enabled: true }
}
"#;

fn rules_js() -> String {
    let body: String = qml_functions::read("lib/rules.js")
        .lines()
        .filter(|line| !line.trim_start().starts_with('.'))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{body}\nvar Rules = globalThis;\n")
}

fn run(scenario: &str) -> String {
    js::run_js(&format!(
        "{}\n{STAND_IN}\n{}\n{}\n{}\n{}\n{scenario}\n",
        rules_js(),
        qml_functions::functions("flows/RuleEditSupport.qml", &["writeComment"]),
        qml_functions::functions(
            "Main.qml",
            &["_sidecarWriteCommentForRow", "_gcSidecarCommentOrphans"]
        ),
        qml_functions::functions("flows/PresetImportController.qml", IMPORT),
        qml_functions::functions(
            "flows/ReviewFlowController.qml",
            &["_completeRulesActivation"]
        ),
    ))
}

#[test]
fn a_loaded_set_replaces_the_comments_the_previous_set_left() {
    let output = run(
        "rulesModel.rows = [row('domain', 'example.com', 'primary', 'Exact FQDN')]; rulesModel.count = 1;\n\
         stored = { 'domain|example.com|primary': 'Exact FQDN', 'zone|local|primary': 'All hosts',\n\
                    'domain|same.example|secondary': 'kept' };\n\
         parsed = { primary: [row('domain', 'example.com', 'primary', 'Точное имя'),\n\
                              row('zone', 'local', 'primary', '')],\n\
                    secondary: [row('application', 'chrome.exe', 'secondary', 'Имя процесса'),\n\
                                row('domain', 'same.example', 'secondary', 'kept')] };\n\
         _completePresetImportActivation({ targetRoute: 'both', mode: 'replace',\n\
             primaryBytesB64: 'p', secondaryBytesB64: 's' });\n\
         say('-- answered');\n\
         answerAll();",
    );
    for line in [
        "write domain|example.com|primary = 'Точное имя'",
        "write zone|local|primary = ''",
        "write application|chrome.exe|secondary = 'Имя процесса'",
    ] {
        assert!(output.contains(line), "missing `{line}`:\n{output}");
    }
    assert!(
        !output.contains("same.example"),
        "a comment the store already holds is written again:\n{output}"
    );
    let answered = output.find("-- answered").expect("marker");
    let reread = output
        .rfind("table re-reads the comments")
        .expect("the table never picked up the file's comments");
    assert!(answered < reread, "{output}");
}

#[test]
fn a_merge_keeps_the_comments_of_rules_already_there() {
    let output = run(
        "rulesModel.rows = [row('domain', 'example.com', 'primary', 'mine')]; rulesModel.count = 1;\n\
         parsed = { primary: [row('domain', 'example.com', 'primary', 'theirs'),\n\
                              row('domain', 'new.example', 'primary', 'added')] };\n\
         _completePresetImportActivation({ targetRoute: 'primary', mode: 'merge', bytesB64: 'p' });\n\
         answerAll();",
    );
    assert!(!output.contains("'theirs'"), "{output}");
    assert!(
        output.contains("write domain|new.example|primary = 'added'"),
        "{output}"
    );
}

#[test]
fn applying_a_table_without_rules_drops_every_comment() {
    // The sweep that runs on every re-read cannot tell an empty table from one
    // not filled yet; the apply can.
    let output = run("_gcSidecarCommentOrphans();");
    assert!(!output.contains("sweep"), "{output}");
    let output = run("_completeRulesActivation({});");
    assert!(output.contains("sweep keeps 0"), "{output}");
}
