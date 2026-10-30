#![allow(clippy::expect_used)]

//! A user who started empty, or whose service lost every rule, sees an empty
//! window and may never find the rule sets. The launch after the first run
//! offers the set the quick-load points at instead of loading it unasked:
//! "Load" goes through the import a user asks for (the service started if
//! stopped, the review, the outcome said), and either answer closes the offer
//! for good until a full reset.
//!
//! The window's own functions run in an embedded engine against a stand-in.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

use qml_functions::{function_source, functions, pure, read};

const WINDOW: &[&str] = &[
    "_hydrateRulesOnLaunch",
    "_coldStartRulesFetch",
    "rulesSourcePathFor",
    "_rememberedRulesPathFor",
    "rulesSourceIsUserBound",
    "_runAutoOpenOnLaunch",
    "ruleSetOfferSetName",
    "ruleSetOfferDueNow",
    "loadOfferedRuleSet",
    "answerRuleSetOffer",
];

const CATALOG: &[&str] = &[
    "_ruleSetEnum",
    "ruleSetLabelAt",
    "ruleSetSelectionKey",
    "ruleSetRememberedIndex",
    "ruleSetPreferredIndex",
    "ruleSetFilePath",
    "defaultRuleSetIndex",
    "ruleSetDisplayName",
    "loadRuleSetAt",
];

/// One shipped set, Russia's, on a Russian system; the service answers per
/// `backendStatus` and `_serviceRuleCount`. Every import is logged.
fn run(setup: &str, then: &str) -> String {
    let program = format!(
        r#"{pure}
function stub() {{
    return new Proxy(function() {{}}, {{
        get: function() {{ return stub() }},
        apply: function() {{ return undefined }}
    }})
}}
var Qt = {{ callLater: function() {{}}, locale: function() {{ return {{ name: "ru_RU" }} }} }};
var backendStatus = {{ kind: "connected" }};
var bridgeAvailable = true;
var userPresetsDir = "";
var statusLine = "";
var ruleEditsLocked = false;
var _serviceRuleCount = -1;
var _firstRunDoneAtLaunch = true;
var rulesModel = {{ count: 0, clear: function() {{ this.count = 0 }} }};
var _ruleSetCacheBox = {{ v: null }};
var _coldStartRulesRetryTimer = {{ restart: function() {{}} }};
var _coldStartAutoOpenFallbackTimer = {{ restart: function() {{}} }};
var boundFilesController = {{ askAboutHandEditedFiles: function() {{}} }};
function tr(key, fallback) {{
    return key === "rules.bundled-preset.name.ru-osnovnoy" ? "Russia: local and foreign" : fallback
}}
function updatePrefs(patch) {{ for (var k in patch) prefs[k] = patch[k] }}
function commitPrefs(patch) {{ updatePrefs(patch) }}
function emitPrefs() {{}}
function isFactoryPresetPath(path) {{ return String(path || "").indexOf("C:/Program Files/") === 0 }}
function _refreshRulesFromService(options) {{
    _serviceRuleCount = 0
    options.onComplete(true)
    return true
}}
var nrrNativeBridge = {{
    listAllPresets: function(dir) {{
        return dir ? "[]" : JSON.stringify([{{ country: "ru", pack: "osnovnoy" }}])
    }},
    resolvePresetPath: function(rel) {{ return "C:/Program Files/NetRuleRouter/presets/" + rel }},
    readFileBytes: function(path) {{ return "cnVsZXM=" }}
}};
var presetImportController = {{
    startBothRoutesPresetImportReviewFlow: function(primary, secondary, primaryPath, secondaryPath, options) {{
        var o = options || {{}}
        console.log((o.hydration ? "hydration of " : "import of ") + primaryPath
            + " named " + String(o.label || ""))
    }}
}};
var prefs = {{ firstRunCompleted: true, autoLoadRulesOnLaunch: true }};
var root = new Proxy({{}}, {{
    get: function(target, key) {{ return (key in globalThis) ? globalThis[key] : stub() }}
}});
var ruleSetCatalog = root;
{catalog}
{window}
{setup}
{then}
"#,
        pure = pure(),
        catalog = functions("flows/RuleSetCatalog.qml", CATALOG),
        window = functions("Main.qml", WINDOW),
    );
    js::run_js(&program)
}

fn offered(output: &str) -> bool {
    output.contains("offer: yes")
}

const ASK: &str =
    r#"console.log(ruleSetOfferDueNow() ? "offer: yes " + ruleSetOfferSetName() : "offer: no")"#;

/// The launch after an empty start: no review of a set nobody picked, an
/// offer naming the set instead — with the service up and empty, and with it
/// not running at all.
#[test]
fn an_empty_start_is_offered_the_set_on_the_next_launch_not_loaded() {
    for (kind, count) in [("connected", "0"), ("service-stopped", "-1")] {
        let output = run(
            &format!("backendStatus = {{ kind: '{kind}' }}; _serviceRuleCount = {count};"),
            &format!("_hydrateRulesOnLaunch(); {ASK}"),
        );
        assert!(
            !output.contains("import of") && !output.contains("hydration of"),
            "{kind}: a set was loaded unasked:\n{output}"
        );
        assert!(
            output.contains("offer: yes Russia: local and foreign"),
            "{kind}: the user with no rules is not offered the set:\n{output}"
        );
    }
}

/// "Start empty" in the first-run window is not questioned in the launch it
/// was chosen in, and nothing is offered while that window is still open.
#[test]
fn the_offer_waits_for_the_launch_after_the_first_run() {
    let open = run(
        "prefs.firstRunCompleted = false; _firstRunDoneAtLaunch = false; _serviceRuleCount = 0;",
        ASK,
    );
    assert!(
        !offered(&open),
        "offered under the first-run window:\n{open}"
    );
    let just_finished = run("_firstRunDoneAtLaunch = false; _serviceRuleCount = 0;", ASK);
    assert!(
        !offered(&just_finished),
        "offered right after the user chose to start empty:\n{just_finished}"
    );
}

/// The offer stands down by itself once the user has rules, whatever brought
/// them, and for a user whose own rules file backs the list.
#[test]
fn rules_or_a_bound_file_close_the_offer() {
    let with_rules = run("_serviceRuleCount = 5;", ASK);
    assert!(!offered(&with_rules), "{with_rules}");
    let added_by_hand = run("_serviceRuleCount = 0; rulesModel.count = 1;", ASK);
    assert!(!offered(&added_by_hand), "{added_by_hand}");
    let bound = run(
        "_serviceRuleCount = 0; prefs.lastSavedPathPrimary = 'D:/rules/mine/rules_primary.txt';",
        ASK,
    );
    assert!(!offered(&bound), "{bound}");
}

/// "Load" is the quick-load's Load on the offered set: the import a user asks
/// for, with the set's name for its outcome, never the silent hydration. It
/// answers the offer and leaves the set remembered as the user's pick.
#[test]
fn load_goes_through_the_import_a_user_asks_for_and_answers_the_offer() {
    let output = run(
        "_serviceRuleCount = 0;",
        &format!(
            "loadOfferedRuleSet(); {ASK}; console.log('answered ' + prefs.ruleSetOfferAnswered); \
             console.log('picked ' + prefs.selectedPresetSet);"
        ),
    );
    assert!(
        output.contains(
            "import of C:/Program Files/NetRuleRouter/presets/ru/osnovnoy/rules_primary.txt \
             named Russia: local and foreign"
        ),
        "{output}"
    );
    assert!(!output.contains("hydration of"), "{output}");
    assert!(output.contains("answered true"), "{output}");
    assert!(output.contains("picked bundled:ru_osnovnoy"), "{output}");
    assert!(output.contains("offer: no"), "{output}");
}

/// "Not now" (or the banner's close button) is an answer: the offer does not
/// come back on the next launch.
#[test]
fn not_now_is_never_asked_again() {
    let output = run(
        "_serviceRuleCount = 0;",
        &format!("answerRuleSetOffer(); {ASK}"),
    );
    assert!(output.contains("offer: no"), "{output}");
    let next_launch = run(
        "_serviceRuleCount = 0; prefs.ruleSetOfferAnswered = true;",
        &format!("_hydrateRulesOnLaunch(); {ASK}"),
    );
    assert!(next_launch.contains("offer: no"), "{next_launch}");
    assert!(!next_launch.contains("import of"), "{next_launch}");
}

/// A full reset starts the user over as a fresh install, so the offer is made
/// again after it.
#[test]
fn a_full_reset_offers_the_set_again() {
    let reset = function_source(&read("flows/FullResetController.qml"), "fullReset");
    let output = run(
        "prefs.ruleSetOfferAnswered = true; _serviceRuleCount = 0; \
         function resetDefaults() {} function clearAllUnsavedChanges() {} \
         var serviceStarter = { startIfStoppedThen: function() {} }; \
         var Pure = globalThis;",
        &format!(
            "{reset}\nfullReset(false); \
             console.log('answered ' + prefs.ruleSetOfferAnswered);"
        ),
    );
    assert!(output.contains("answered false"), "{output}");
}
