//! The first rule set is the user's choice in the first-run window. A fresh
//! install has a service that holds no rules, and the cold-start fetch read
//! that as "hydrate from the file": with nothing bound it fell back to the set
//! the quick-load list points at and ran it through the import review, so a
//! review of a set nobody picked was already open under "Welcome", and its
//! token had expired by the time the user reached it.
//!
//! The startup code is run as written, in an embedded engine, against a
//! stand-in window.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

fn read(relative: &str) -> String {
    let path = qml_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// `function <name>(…) { … }` as written, braces matched outside strings and
/// comments.
fn function_source(source: &str, name: &str) -> String {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("function {name} is gone"));
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == b'"' || c == b'\'' {
            quote = Some(c);
        } else if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return source[start..=i].to_owned();
            }
        }
        i += 1;
    }
    panic!("function {name} never closes");
}

/// The window as the startup code sees it: everything it names exists, and
/// what matters to the question is spelled out in `setup`.
fn run_startup(setup: &str) -> String {
    let main = read("Main.qml");
    let startup = read("flows/StartupController.qml");
    let pure: String = read("lib/pure.js")
        .lines()
        .filter(|line| !line.trim_start().starts_with('.'))
        .collect::<Vec<_>>()
        .join("\n");
    let mut window_functions = String::new();
    for name in [
        "_hydrateRulesOnLaunch",
        "_coldStartRulesFetch",
        "rulesSourcePathFor",
        "_rememberedRulesPathFor",
        "_forgetStaleFactoryRulesBinding",
        "_runAutoOpenOnLaunch",
    ] {
        window_functions.push_str(&function_source(&main, name));
        window_functions.push('\n');
    }
    let post_eula = format!(
        "{}\n{}",
        function_source(&startup, "_runPostEulaStartup"),
        function_source(&startup, "_provisioningCompletesFirstRun")
    );
    js::run_js(&format!(
        r#"{pure}
var Pure = globalThis;
function stub() {{
    return new Proxy(function() {{}}, {{
        get: function() {{ return stub() }},
        apply: function() {{ return undefined }}
    }})
}}
var Qt = {{ callLater: function() {{}} }};
var context = {{}};
var backendStatus = {{ kind: "connected" }};
var bridgeAvailable = true;
var userPresetsDir = "";
var statusLine = "";
var autoCloseMs = 1;
var _serviceRuleCount = -1;
var firstRunWindow = {{ name: "first-run window" }};
function tr(key, fallback) {{ return fallback }}
function logProgress() {{}}
function updatePrefs(patch) {{ for (var k in patch) prefs[k] = patch[k] }}
function commitPrefs(patch) {{ updatePrefs(patch) }}
function emitPrefs() {{}}
function isFactoryPresetPath(path) {{ return String(path || "").indexOf("C:/Program Files/") === 0 }}
function _serviceNeedsInstallPrompt() {{ return false }}
function openChildWindow(w) {{ console.log("open " + w.name) }}
// A fresh install: the service is up and answers that it holds no rules.
function _refreshRulesFromService(options) {{
    _serviceRuleCount = 0
    options.onComplete(true)
    return true
}}
var _coldStartRulesRetryTimer = {{ restart: function() {{}} }};
var _coldStartAutoOpenFallbackTimer = {{ restart: function() {{}} }};
var boundFilesController = {{ askAboutHandEditedFiles: function() {{ console.log("ask about files") }} }};
var ruleSetCatalog = {{
    defaultRuleSetPathFor: function(route) {{
        return "C:/Program Files/NetRuleRouter/presets/ru/default/rules_" + route + ".txt"
    }},
    _rememberHydratedRuleSet: function() {{}},
    _ruleSetEnum: function() {{ return {{ userOwned: false, entries: [] }} }}
}};
var nrrNativeBridge = {{ readFileBytes: function(path) {{ return "cnVsZXM=" }} }};
var presetImportController = {{
    startBothRoutesPresetImportReviewFlow: function(primary, secondary, primaryPath) {{
        console.log("import review of " + primaryPath)
    }}
}};
var provisioning = {{ present: false, completesFirstRun: false }};
var prefs = {{}};
{setup}
{window_functions}
var root = new Proxy({{}}, {{
    get: function(target, key) {{ return (key in globalThis) ? globalThis[key] : stub() }}
}});
{post_eula}
_runPostEulaStartup();
"#
    ))
}

#[test]
fn a_fresh_install_opens_no_rule_set_review_behind_the_first_run_window() {
    let output = run_startup("prefs = { firstRunCompleted: false, autoLoadRulesOnLaunch: true };");
    assert!(
        output.contains("open first-run window"),
        "the first run greets the user:\n{output}"
    );
    assert!(
        !output.contains("import review"),
        "a rule set the user never picked went to the service at start:\n{output}"
    );
}

/// "Start empty" is a choice: a later launch must not answer it with a review
/// of the set the quick-load list happens to point at, whether the service is
/// up and empty or not running at all.
#[test]
fn an_empty_start_stays_empty_on_the_next_launch() {
    for kind in ["connected", "service-stopped"] {
        let output = run_startup(&format!(
            "prefs = {{ firstRunCompleted: true, autoLoadRulesOnLaunch: true }}; \
             backendStatus = {{ kind: '{kind}' }}; _hydrateRulesOnLaunch();"
        ));
        assert!(
            !output.contains("import review"),
            "{kind}: a set the user never picked was opened:\n{output}"
        );
    }
}

/// The fix stops at the first run: a returning user whose service lost its
/// rules is still offered the files they bound.
#[test]
fn a_returning_user_whose_service_holds_nothing_is_offered_the_bound_files() {
    let output = run_startup(
        "prefs = { firstRunCompleted: true, autoLoadRulesOnLaunch: true, \
         lastLoadedPathPrimary: 'D:/rules/mine/rules_primary.txt' };",
    );
    assert!(
        output.contains("import review of D:/rules/mine/rules_primary.txt"),
        "{output}"
    );
}
