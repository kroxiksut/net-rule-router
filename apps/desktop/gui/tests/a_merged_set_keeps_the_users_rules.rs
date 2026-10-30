#![allow(clippy::expect_used)]

//! "Merge" in the load window promises the user's own rules stay. With the
//! service up the load went to the service as a set import, which replaces
//! the routes it covers, so the merge removed the very rules it promised to
//! keep. A merge now adds the set to the table and the ordinary review shows
//! the table: additions only. The user's sections for other systems stay too.
//! Runs the load controller's own functions against a stand-in.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const LOADER: &[&str] = &[
    "startPresetImportReviewFlow",
    "startBothRoutesPresetImportReviewFlow",
    "_startMergeLoad",
    "_announceMergeApplied",
    "_whenServiceUp",
    "_refreshRulesAfterPresetImport",
    "_applyImportMerge",
    "_applyImportReplace",
    "_writeImportedPassthrough",
    "_ruleSetName",
];

const STAND_IN: &str = r#"
function say(line) { console.log(line) }
function model(rows) {
    return {
        rows: rows, count: rows.length,
        get: function(i) { return this.rows[i] },
        append: function(batch) { for (var i = 0; i < batch.length; i += 1) this.rows.push(batch[i]); this.count = this.rows.length },
        remove: function(i) { this.rows.splice(i, 1); this.count = this.rows.length },
        setProperty: function(i, name, value) { this.rows[i][name] = value }
    }
}
function row(type, value, route) {
    return { id: "", ruleType: type, matchValue: value, targetRoute: route, enabled: true, comment: "" }
}
function table() {
    var out = [];
    for (var i = 0; i < rulesModel.count; i += 1) {
        var r = rulesModel.get(i); out.push(r.matchValue + "@" + r.targetRoute + (r.verify ? "?" : ""))
    }
    return out.sort().join(" ")
}
var rulesModel = model([]);
var parsed = {}, setSections = {}, ownSections = {};
var dryRunAnswer = null;
var nrrNativeBridge = {
    rpcMutationSubmit: function(kind, payload, dryRun) { say("service " + kind + (dryRun ? " dry run" : "")); return "corr" },
    rpcSidecarPassthroughRead: function(route) { return "read:" + route },
    rpcSidecarPassthroughWrite: function(route, sections) {
        var names = Object.keys(sections).sort();
        for (var i = 0; i < names.length; i += 1) say("keep " + route + " " + names[i] + ": " + JSON.stringify(sections[names[i]]));
        if (names.length === 0) say("keep " + route + " nothing");
        return "write"
    }
};
function _parseCanonicalRulesAsync(text, route, startId, callback) {
    callback({ rows: (parsed[route] || []).map(function(r) { return Object.assign({}, r) }),
               passthrough: setSections[route] || [], duplicateSections: [] })
}
function _writeImportedComments() {}
function _bindImportedSourcePaths() { say("set files bound") }
function _holdForAlert() { return false }
function _announcePreviewRefusal() { return false }
function _formatImportPassthroughSuffix() { return "" }
function _formatNewerFormatSuffix() { return "" }
function _applyPresetImportOffline() { say("offline") }
var guardDone = null;
var root = {
    tr: function(key, fallback) { return fallback },
    statusLine: "",
    bridgeAvailable: true,
    importOnlyActiveSession: true,
    pendingPresetImportState: null,
    serviceStarter: null,
    rulesModel: rulesModel,
    passthroughRevision: 0,
    _b64ToUtf8: function(text) { return text },
    _maxRuleNumericId: function() { return rulesModel.count },
    _aceLowerForSearch: function(v) { return v },
    setUnsavedChanges: function(section, dirty) { say("unsaved " + section + " " + dirty) },
    showNotice: function(title, body) { say("notice " + title + ": " + body) },
    reviewDiffDialog: { open: function() { say("set review") } },
    reviewFlowController: { _guardApplyRules: function(done, origin) {
        say("review of the table: " + table()); guardDone = done
    } },
    rpc: {
        registerLongRpcCallback: function(corr, callback) { dryRunAnswer = callback },
        registerRpcCallback: function(corr, callback) {
            var route = String(corr).split(":")[1];
            if (String(corr).indexOf("read:") === 0) callback(true, { sections: ownSections[route] || {} });
            else callback(true, { dropped: [] })
        }
    }
};
var Plurals = { counted: function(tr, prefix, n, one, many) { return (n === 1 ? one : many).replace("{count}", String(n)) } };
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
        "{}\n{}\n{STAND_IN}\n{}\n{scenario}\n",
        qml_functions::pure(),
        rules_js(),
        qml_functions::functions("flows/PresetImportController.qml", LOADER),
    ))
}

const OWN: &str = "rulesModel.rows = [row('domain', 'mine.example', 'primary'),\n\
                   row('domain', 'kept.example', 'secondary'), row('exact-ip', '192.0.2.1', 'block')];\n\
                   rulesModel.count = 3;\n";

#[test]
fn a_merge_with_the_service_up_keeps_every_own_rule_and_adds_the_sets() {
    let output = run(&format!(
        "{OWN}parsed = {{ primary: [row('domain', 'mine.example', 'primary'), row('domain', 'new.example', 'primary')] }};\n\
         startPresetImportReviewFlow('primary', 'p', 'C:/sets/home/rules_primary.txt', 'merge');"
    ));
    assert!(
        !output.contains("service preset-import"),
        "a merge went to the service as a set import, which replaces the route:\n{output}"
    );
    assert!(
        output.contains(
            "review of the table: 192.0.2.1@block kept.example@secondary mine.example@primary new.example@primary"
        ),
        "{output}"
    );
    assert!(!output.contains("set review"), "{output}");
}

#[test]
fn a_two_file_merge_keeps_every_own_rule_on_both_routes() {
    let output = run(&format!(
        "{OWN}parsed = {{ primary: [row('domain', 'new.example', 'primary')],\n\
                         secondary: [row('domain', 'other.example', 'secondary')] }};\n\
         startBothRoutesPresetImportReviewFlow('p', 's', 'C:/sets/home/rules_primary.txt',\n\
             'C:/sets/home/rules_secondary.txt', {{ mode: 'merge' }});"
    ));
    assert!(!output.contains("service preset-import"), "{output}");
    assert!(
        output.contains(
            "review of the table: 192.0.2.1@block kept.example@secondary mine.example@primary new.example@primary other.example@secondary"
        ),
        "{output}"
    );
}

/// Applied, the merge is announced as additions, and the user's own files stay
/// the files the rules are saved to: binding the set's files would write the
/// merged rules into the set.
#[test]
fn an_applied_merge_names_what_it_added_and_keeps_the_users_files() {
    let output = run(&format!(
        "{OWN}parsed = {{ primary: [row('domain', 'mine.example', 'primary'), row('domain', 'new.example', 'primary')] }};\n\
         startPresetImportReviewFlow('primary', 'p', 'C:/sets/home/rules_primary.txt', 'merge', {{ label: 'Home' }});\n\
         guardDone(true);"
    ));
    assert!(output.contains("«Home»: 1 new rule added"), "{output}");
    assert!(!output.contains("set files bound"), "{output}");
}

/// A merge keeps the user's sections for other systems: the set's go beside
/// them, never over them.
#[test]
fn a_merge_keeps_the_users_sections_for_other_systems() {
    let output = run(&format!(
        "{OWN}ownSections = {{ primary: {{ Linux: 'own-app\\n' }} }};\n\
         setSections = {{ primary: [{{ 'section-name': 'Linux', 'raw-text': 'their-app\\n' }}] }};\n\
         parsed = {{ primary: [row('domain', 'new.example', 'primary')] }};\n\
         startPresetImportReviewFlow('primary', 'p', 'C:/sets/home/rules_primary.txt', 'merge');"
    ));
    assert!(
        output.contains("keep primary Linux: \"own-app\\ntheir-app\\n\""),
        "{output}"
    );

    let output = run(&format!(
        "{OWN}ownSections = {{ primary: {{ Linux: 'own-app\\n' }} }};\n\
         parsed = {{ primary: [row('domain', 'new.example', 'primary')] }};\n\
         startPresetImportReviewFlow('primary', 'p', 'C:/sets/home/rules_primary.txt', 'merge');"
    ));
    assert!(
        output.contains("keep primary Linux: \"own-app\\n\""),
        "a set without sections erased the user's:\n{output}"
    );
}

/// Replace is unchanged: the set import goes to the service, whose review
/// lists what it takes away.
#[test]
fn a_replace_still_goes_to_the_service_as_a_set_import() {
    let output = run(&format!(
        "{OWN}parsed = {{ primary: [row('domain', 'new.example', 'primary')] }};\n\
         startPresetImportReviewFlow('primary', 'p', 'C:/sets/home/rules_primary.txt', 'replace');"
    ));
    assert!(output.contains("service preset-import dry run"), "{output}");
    assert!(!output.contains("review of the table"), "{output}");
}
