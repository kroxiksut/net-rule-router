#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml;

#[test]
fn resource_or_rule_wait_is_explained_without_a_countdown() {
    let pure = qml::pure();
    let functions = qml::functions("components/DiscoveryEpisodesPanel.qml", &["probeDetails"]);
    let program = format!(
        r#"
{pure}
var panel = {{root:{{tr:function(key, fallback) {{
    var words = {{
        "rules.suggestions.episode.queue.wait.resources":"Waiting for space to track automatic checks. This check stays queued.",
        "rules.suggestions.episode.reason.rules-unavailable":"Waiting for the rule set to become available. No probe is sent until it can be evaluated."
    }};
    return words[key] || fallback;
}}}}}};
{functions}
for (var kind of ["resources", "rules"]) {{
    var text = probeDetails({{"probe-queue":{{"wait-kind":kind,"queued-ahead":0,"eligible-in-ms":1000}}}});
    console.log(text.indexOf(kind === "resources" ? "space to track" : "rule set") >= 0);
    console.log(text.indexOf("at least") < 0 && text.indexOf("not a start or completion estimate") >= 0);
}}
"#
    );
    assert_eq!(js::run_js(&program), "true\ntrue\ntrue\ntrue\n");
}

#[test]
fn queue_details_distinguish_eligibility_from_worker_wait_and_preserve_a_measured_result() {
    let pure = qml::pure();
    let functions = qml::functions("components/DiscoveryEpisodesPanel.qml", &["probeDetails"]);
    let program = format!(
        r#"
{pure}
var panel = {{root:{{tr:function(key, fallback) {{
    var words = {{
        "rules.suggestions.episode.queue.wait.rate":"Waiting for the automatic check rate limit.",
        "rules.suggestions.episode.queue.wait.workers":"Waiting for other automatic checks to finish.",
        "rules.suggestions.episode.queue.wait.scheduled":"Waiting for the next automatic check.",
        "rules.suggestions.episode.reason.primary-responds":"The main connection answered the probe."
    }};
    return words[key] || fallback;
}}}}}};
{functions}
var episode = {{"probe-queue":{{"wait-kind":"rate","queued-ahead":3,"eligible-in-ms":1875}},
    history:[{{stage:"probe",reason:"primary-responds","at-unix-ms":1700000000000}},
        {{stage:"probe",reason:"probe-queued","at-unix-ms":1700000001000}}]}};
var text = probeDetails(episode);
console.log(text.indexOf("rate limit") >= 0 && text.indexOf("ahead: 3") >= 0);
console.log(text.indexOf("at least 2 s") >= 0 && text.indexOf("not a start or completion estimate") >= 0);
console.log(text.indexOf("Retained check result at") >= 0 && text.indexOf("answered the probe") >= 0);
episode["probe-queue"]["wait-kind"] = "workers";
text = probeDetails(episode);
console.log(text.indexOf("other automatic checks to finish") >= 0 && text.indexOf("at least") < 0);
episode["probe-queue"]["wait-kind"] = "scheduled";
episode.history = [];
text = probeDetails(episode);
console.log(text.indexOf("next automatic check") >= 0 && text.indexOf("No previous check result is retained") >= 0);
console.log(probeDetails({{}}) === "");
"#
    );
    assert_eq!(js::run_js(&program), "true\ntrue\ntrue\ntrue\ntrue\ntrue\n");
}

#[test]
fn an_unknown_name_keeps_its_explanation_when_the_offer_list_is_empty() {
    let functions = qml::functions(
        "flows/AutoRuleSuggestionsController.qml",
        &["refreshAutoRuleCandidates"],
    );
    let program = format!(
        r#"
var root = {{ bridgeAvailable: true, rpc: {{
    rpcAutoRuleCandidatesList: function() {{ return "read" }},
    registerRpcCallback: function(corr, done) {{ done(true, {{
        candidates: [], "pending-count": 0,
        "discovery-episodes": [{{id:"opaque-1",host:null,destination:"192.0.2.1:443",
            state:"not-created",reason:"name-unknown",stage:"identity"}}],
        "discovery-omitted": 3
    }}) }}
}}, notificationsController: {{ _dropPushNotice: function() {{}} }} }};
var _autoRuleFetchInFlight = false;
var autoRuleSuggestionsController = {{ _tellOwedAnnouncement: function() {{}} }};
{functions}
refreshAutoRuleCandidates();
console.log(JSON.stringify(autoRuleSuggestionsController.discoveryEpisodes || []));
console.log(autoRuleSuggestionsController.discoveryOmitted || 0);
"#
    );
    let output = js::run_js(&program);
    assert!(
        output.contains("name-unknown"),
        "the empty inbox lost the reason: {output}"
    );
    assert!(
        output.ends_with("3\n"),
        "a bounded history must disclose omissions: {output}"
    );
}

#[test]
fn a_prompt_that_never_becomes_visible_is_not_reported_as_delivered() {
    let functions = qml::functions("Tray.qml", &["_presentPrompt"]);
    let program = format!(
        r#"
var promptWindow = {{visible:false, present:function() {{}}}};
{functions}
console.log(_presentPrompt({{}}) === true);
promptWindow.present = function() {{ this.visible = true }};
console.log(_presentPrompt({{}}) === true);
"#
    );
    assert_eq!(js::run_js(&program), "false\ntrue\n");
}

#[test]
fn a_failed_notice_does_not_start_the_sites_day_of_silence() {
    let functions = qml::functions("Tray.qml", &["_showSiteNoticeCard"]);
    let program = format!(
        r#"
var shown = 0;
var promptWindow = null;
var showNotifications = true;
var notifySuggestionChanges = true;
var tray = {{ _noticeSite:"site.example", _recordSitesShown:function() {{ shown += 1 }},
    _siteNoticeBody:function() {{return "site"}}, _reportDiscovery:function() {{}},
    _reportDiscoveryForSite:function() {{}}, _noticeMutedNow:function() {{return false}},
    _siteNoticeDue:function() {{return true}}, _scheduleDrain:function() {{}} }};
var _noticeSite = "site.example";
var _promptAutoRetireMs = 1000;
function tr(key, fallback) {{return fallback}}
function _presentOrQueue(kind, show) {{show()}}
function _presentPrompt() {{return false}}
{functions}
_showSiteNoticeCard("unconfirmed");
console.log(shown);
"#
    );
    assert_eq!(js::run_js(&program), "0\n");
}

#[test]
fn a_notice_only_tray_respects_notifications_being_turned_off() {
    let functions = qml::functions("Tray.qml", &["_showSiteNotice"]);
    let program = format!(
        r#"
var cards = 0;
var showNotifications = false;
var notifySuggestionChanges = true;
var _noticeModeWatch = {{start:function() {{}}}};
var tray = {{_noticeSite:"site.example", _siteNoticeDue:function() {{return true}},
    _siteReachThen:function(host,done) {{done("unconfirmed")}},
    _showSiteNoticeCard:function() {{cards += 1}},
    _noticeMutedNow:function() {{return false}},
    _reportDiscoveryForSite:function() {{}} }};
function _whenNoticeAllowed(kind, done) {{done()}}
function _refreshNoticeMutes(done) {{done()}}
{functions}
_showSiteNotice();
console.log(cards);
"#
    );
    assert_eq!(js::run_js(&program), "0\n");
}

#[test]
fn a_failed_rule_answer_does_not_permanently_silence_the_still_pending_offer() {
    let functions = qml::functions(
        "Tray.qml",
        &[
            "_onPromptAction",
            "_pickIds",
            "_autoRulesAccept",
            "_autoRulesDismiss",
        ],
    );
    let program = format!(
        r#"
var recorded = [];
var noticeLedger = {{recordAll:function(ids) {{recorded = recorded.concat(ids)}}}};
var _autoRuleActiveIds = ["c1"];
var _autoRuleDeclineIds = ["c1"];
var _autoRuleReviewSerial = -1;
var _autoRuleSiteById = {{"c1":"site.example"}};
var _activeNoticeId = "";
var _siteHostsOnScreen = ["site.example"];
var rpc = {{rpcAutoRuleCandidatesAccept:function() {{return "accept"}},
    rpcAutoRuleCandidatesDismiss:function() {{return "dismiss"}},
    registerRpcCallback:function(id,done) {{done(false,null,"unavailable","")}} }};
var tray = globalThis;
console.warn = function() {{}};
function _scheduleDrain() {{}}
function _notePendingCount() {{}}
function _noteReloadAfterAccept() {{}}
function _autoRuleNoticeId(id) {{return "auto-rule:" + id}}
function _autoRuleRefusedId(id) {{return "auto-rule-never:" + id}}
function _siteAnsweredId(host) {{return "site-notice-answered:" + host}}
{functions}
_onPromptAction("auto-rules-dismiss",[0]);
console.log(recorded.length);
recorded = [];
_autoRuleActiveIds = ["c1"];
_autoRuleSiteById = {{"c1":"site.example"}};
_siteHostsOnScreen = ["site.example"];
_onPromptAction("auto-rules-accept",[0]);
console.log(recorded.length);
rpc.registerRpcCallback = function(id,done) {{done(true,{{applied:1,unknown:0,pending:0}})}};
recorded = [];
_autoRuleActiveIds = ["c1"];
_autoRuleSiteById = {{"c1":"site.example"}};
_onPromptAction("auto-rules-accept",[0]);
console.log(recorded.join(","));
recorded = [];
_autoRuleActiveIds = ["c1"];
_autoRuleSiteById = {{"c1":"site.example"}};
_onPromptAction("auto-rules-dismiss",[0]);
console.log(recorded.join(","));
rpc.registerRpcCallback = function(id,done) {{done(true,{{applied:0,unknown:1,pending:1}})}};
recorded = [];
_autoRuleActiveIds = ["c1"];
_autoRuleSiteById = {{"c1":"site.example"}};
_onPromptAction("auto-rules-dismiss",[0]);
console.log(recorded.length);
"#
    );
    assert_eq!(js::run_js(&program), "0\n0\nauto-rule:c1,site-notice-answered:site.example\nsite-notice-answered:site.example\n0\n");
}
