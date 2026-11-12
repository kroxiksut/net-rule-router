#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml;

fn run(case: &str) {
    let source = qml::read("Tray.qml");
    let mut functions = qml::functions(
        "Tray.qml",
        &[
            "_fetchAutoRuleCandidates",
            "_presentAutoRulePrompt",
            "_onPromptAction",
            "_pickIds",
            "_onAutoRuleCandidatesChanged",
        ],
    );
    if source.contains("function _autoRuleReviewOnScreen(") {
        functions.push_str(&qml::function_source(&source, "_autoRuleReviewOnScreen"));
    }
    let replace = qml::functions("components/TrayPromptWindow.qml", &["replaceContent"]);
    let program = format!(
        r#"
{pure}
var done = console.log; console.log = function() {{}}; console.warn = function() {{}};
function check(value, message) {{if (!value) throw new Error(message)}}
function tr(key, fallback) {{return fallback}}
var tray=globalThis, bridgeAvailable=true, callback=null, requests=0, queued=0, presented=0;
var _autoRuleFetchInFlight=false, _autoRuleLatestAnchor="", _autoRuleOnlySitesNotOpening=false;
var _autoRulePendingCount=0, _autoRuleShowAll=false, _autoRuleMaxPerNotice=10;
var _autoRuleActiveIds=[], _autoRuleSiteById={{}}, _autoRuleReviewSerial=-1, _autoRuleDeclineIds=[];
var _autoRuleSilencedUntilMs=0, _autoRuleSnoozedIds={{}}, _activeNoticeId="", _siteHostsOnScreen=[];
var _noticeSite="";
var _siteNoticeRetryTimer={{running:false,start:function(){{this.running=true}},stop:function(){{this.running=false}}}};
var showNotifications=true, notifySuggestionChanges=true, _promptAutoRetireMs=300000;
var noticeLedger={{recordAll:function(){{}}}};
var accepted=[], dismissed=[], reports=[];
function _presentOrQueue() {{queued++}}
function _reportDiscoveryForSite() {{}}
function _reportDiscovery(ids,state,reason) {{reports.push([ids,state,reason])}}
function _scheduleDrain() {{}}
function _autoRuleAnswered() {{return false}}
function _noticeMutedNow() {{return false}}
function _siteNoticeDue() {{return true}}
function _recordSitesShown() {{}}
function _refreshNoticeMutes(fn) {{fn()}}
function _isSelfSigned(c) {{return Pure.autoRuleIsSelfSigned(c)}}
function _companionRowSubtitle() {{return ""}}
function _lessCertainMark() {{return ""}}
function _candidateDetailLine() {{return ""}}
function _routeSentence() {{return ""}}
function _siteNoticeBody() {{return ""}}
function _snoozeCandidates() {{}}
function _autoRulesAccept(ids) {{accepted=ids.slice()}}
function _autoRulesDismiss(ids) {{dismissed=dismissed.concat(ids)}}
var rpc={{rpcAutoRuleCandidatesList:function(){{requests++;return "request"}}, registerRpcCallback:function(id,fn){{callback=fn}}}};
var promptWindow={{visible:false,presentationSerial:0,_settled:false,items:[],_checked:[],detailsExpanded:false,
    placeTimer:{{restart:function(){{}}}}, _applyContent:function(c){{this.items=c.items||[];this.primaryAction=c.primaryAction}},
    present:function(c){{this._applyContent(c);this.visible=true;this.presentationSerial++;this._checked=this.items.map(function(){{return true}});this.detailsExpanded=false}},
    retire:function(){{this.visible=false}}
}};
promptWindow.replaceContent=function(config) {{with(promptWindow) {{{replace}
    replaceContent(config);
}}}};
function _presentPrompt(config) {{presented++;promptWindow.present(config);return true}}
function row(id,anchor) {{return {{id:id,anchor:anchor||id,signal:"main-link-blocked","proposed-match":id+".example",route:"secondary","match-kind":"exact","primary-behavior":"stalls"}}}}
{functions}
try {{
{case}
done("ok");
}} catch (error) {{done("FAIL: " + String(error))}}
"#,
        pure = qml::pure()
    );
    assert_eq!(js::run_js(&program), "ok\n");
}

#[test]
fn paced_candidates_retry_without_waiting_for_another_service_push() {
    run(r#"
_siteNoticeDue=function(){return false};
_autoRuleOnlySitesNotOpening=true;
_presentAutoRulePrompt([row("himalayas")]);
check(_siteNoticeRetryTimer.running,"a ready but paced host must get a local retry");
check(presented===0,"the grouping window still applies");
_siteNoticeDue=function(){return true};
_autoRuleOnlySitesNotOpening=true;
_presentAutoRulePrompt([row("himalayas")]);
check(presented===1,"the ready host is shown when the short window expires");
check(!_siteNoticeRetryTimer.running,"a delivered batch must stop retrying");
"#);
}

#[test]
fn new_sites_join_the_active_review_without_resetting_the_answer_in_progress() {
    run(r#"
_presentAutoRulePrompt([row("a"),row("b")]);
promptWindow._checked=[false,true];promptWindow.detailsExpanded=true;
var serial=promptWindow.presentationSerial;
_onAutoRuleCandidatesChanged({"pending-count":4,announces:true});
check(requests===1,"new sites wait behind an existing review instead of joining it");
var unrelated=row("unrelated");unrelated.signal="delivery-name";
callback(true,{candidates:[row("a"),row("b"),row("c"),unrelated],"pending-count":4});
check(_autoRuleActiveIds.indexOf("unrelated")<0,"an automatic update appended an unrelated unconfirmed companion");
check(promptWindow.presentationSerial===serial && presented===1,"review was presented anew");
check(promptWindow.detailsExpanded,"details collapsed during the answer");
check(JSON.stringify(promptWindow._checked)==="[false,true,false]","existing choices changed or newcomer was preselected");
check(promptWindow.items.every(function(item,i){return item.key===_autoRuleActiveIds[i]}),"rows have no stable candidate identity");
promptWindow.presentationSerial++;_fetchAutoRuleCandidates();
check(requests===1 && queued===1,"another confirmation must keep its place");
"#);
}

#[test]
fn a_late_candidate_reply_cannot_replace_another_confirmation() {
    run(r#"
_fetchAutoRuleCandidates();check(requests===1,"initial fetch");
promptWindow.present({items:[{key:"confirmation"}]});
callback(true,{candidates:[row("a")],"pending-count":1});
check(promptWindow.items[0].key==="confirmation","late reply replaced a different confirmation");
check(_autoRuleActiveIds.length===0,"late reply took ownership of the confirmation");
"#);
}

#[test]
fn accepting_existing_choices_does_not_decline_new_unreviewed_sites() {
    run(r#"
_presentAutoRulePrompt([row("a"),row("b")]);
_presentAutoRulePrompt([row("a"),row("b"),row("c")]);
_onPromptAction("auto-rules-accept",[0]);
check(JSON.stringify(accepted)==='["a"]',"accept exceeded checked consent");
check(JSON.stringify(dismissed)==='["b"]',"an unchecked newcomer was silently declined");
"#);
}

#[test]
fn a_full_review_keeps_existing_rows_instead_of_replacing_them_with_new_sites() {
    run(r#"
var original=[];for(var i=0;i<10;i++)original.push(row("z"+i,"z"));
_presentAutoRulePrompt(original);var prior=_autoRuleActiveIds.slice();
_presentAutoRulePrompt([row("first","a")].concat(original));
check(JSON.stringify(_autoRuleActiveIds)===JSON.stringify(prior),"new ordering evicted a row already under review");
check(promptWindow.items.length===10,"batch exceeded its bound");
"#);
}

#[test]
fn withdrawn_offers_refresh_and_retire_only_their_own_active_review() {
    run(r#"
_presentAutoRulePrompt([row("a")]);
_onAutoRuleCandidatesChanged({"pending-count":0,announces:false});
check(requests===1,"a nonannouncing withdrawal did not refresh the active review");
callback(true,{candidates:[],"pending-count":0});
check(!promptWindow.visible && _autoRuleActiveIds.length===0,"withdrawn offers remain actionable on screen");
promptWindow.present({items:[{key:"confirmation"}]});
_onAutoRuleCandidatesChanged({"pending-count":0,announces:false});
check(promptWindow.visible && promptWindow.items[0].key==="confirmation","a withdrawal retired another confirmation");
check(requests===1,"a withdrawal took ownership of another confirmation");
"#);
}
