//! The first-run window's own functions, run as written against a stand-in
//! window: its adapters, the controllers it hands its answers to, and the
//! properties QML would bind. What reached a controller is logged, one line
//! per call, so a test reads the order the service would see.

#![allow(dead_code)]

#[path = "js.rs"]
mod js;
#[path = "qml_functions.rs"]
mod qml_functions;

const WINDOW: &str = "components/FirstRunWindow.qml";

/// Every function of the window the tests reach, directly or through others.
const FUNCTIONS: &[&str] = &[
    "_rowKey",
    "_modelRows",
    "_modelIndexOfKey",
    "_shownInPicker",
    "_pick",
    "_suggestPicks",
    "_commitPendingPicks",
    "_saveProtection",
    "_applyProtectionChoices",
    "_holdsChosenProtection",
    "_seedProtection",
    "_seedFakeIp",
    "_writeStability",
    "_reviewAdapterName",
    "_reviewLines",
    "_startRun",
    "_commitRun",
    "_startChosenRules",
    "_stepTitle",
    "_onServicePolicyRead",
    "_protectionSettled",
    "_whenProtectionSettled",
    "_holdChosenRules",
    "_siblingWarning",
];

/// The stand-in window. `wire(id, name, patch)` makes an adapter row as the
/// service sends it; `rows` is the list the window shows.
const STAND_IN: &str = r#"
function wire(id, name, patch) {
    var w = {
        "persistent-id": id, "adapter-name": id, "name": name,
        "interface-description": "Example Network Adapter",
        "interface-type": "ethernet", "kind": "ethernet",
        "local-ip": "192.0.2.10", "gateway": "192.0.2.1", "dns-servers": "192.0.2.53",
        "has-default-route": true, "has-forwarding-path": true,
        "availability": "available", "route-state": "not-selected",
        "observed-facts": { "connectivity-state": "internet" },
        "derived-assessment": { "vpn-tunnel-likelihood": "unlikely",
            "classification": "regular-interface" },
        "recommendation": { "class": "preferred-primary" }
    };
    for (var k in (patch || {})) w[k] = patch[k];
    return mapWireInterfaceRow(w);
}
/// A VPN adapter that is connected.
function tunnel(id, name, patch) {
    var p = { "kind": "tunnel", "has-default-route": false, "gateway": "10.8.0.1",
        "derived-assessment": { "vpn-tunnel-likelihood": "likely", "classification": "vpn-tunnel" },
        "recommendation": { "class": "preferred-secondary" } };
    for (var k in (patch || {})) p[k] = patch[k];
    return wire(id, name, p);
}
var rows = [];
var said = [];
var holdWrites = false;
var lastWrite = {};
function say(line) { said.push(line); console.log(line) }
var root = {
    uiRevision: 0,
    interfacesAreLive: true,
    statusLine: "",
    _servicePolicyRead: true,
    _serviceRoutePolicy: null,
    serviceStabilitySupported: false,
    bridgeAvailable: false,
    rpc: {},
    tr: function(key, fallback) { return fallback },
    supports: function() { return false },
    commitPrefs: function() {},
    setAutostartEnabled: function() {},
    _readServiceMirror: function() { return {} },
    showNotice: function(title, body) { say("notice " + title + ": " + body) },
    ipcErrorLabel: function(code) { return code },
    interfacesModel: {
        get count() { return rows.length },
        get: function(i) { return rows[i] }
    },
    interfacesRolesController: {
        assignRole: function(i, role) {
            rows[i].selectedRole = role;
            say("assign " + role + " " + rows[i].persistentId);
        },
        adapterIndexHoldingRole: function(role) {
            for (var i = 0; i < rows.length; i += 1) if (rows[i].selectedRole === role) return i;
            return -1;
        }
    },
    routePolicyController: {
        // The service answers at once unless a test holds the answer back
        // (`holdWrites`) and gives it itself through `lastWrite`.
        applyFirstRunProtections: function(level, doh, origin, outcome) {
            say("protection " + level + " " + (doh === true));
            lastWrite = outcome || {};
            if (!holdWrites && lastWrite.onApplied) lastWrite.onApplied();
        }
    },
    presetImportController: {
        startBothRoutesPresetImportReviewFlow: function(p, s, pp, sp, opts) {
            say("rules " + opts.label);
        },
        startPresetImportReviewFlow: function(route, b, path, mode, opts) {
            say("rules " + opts.label);
        }
    },
    startupController: {
        applyFirstRunStability: function(patch) { say("stability " + JSON.stringify(patch)) }
    }
};
var Qt = { callLater: function(f) { f() } };
var nrrNativeBridge = undefined;
var visible = true;
var step = 0;
var stepCount = 5;
var pickedPrimaryKey = "", pickedSecondaryKey = "";
var pickedPrimaryPath = "", pickedSecondaryPath = "";
var secondaryDeferred = false;
var showAllAdapters = false;
var installedVpnNames = [];
var chosenStart = null, chosenStartError = "";
var wantLeakProtection = "sites", wantDohLockdown = true, wantFakeIp = true;
var wantDiagnosticLogs = false, diagnosticLogsDuration = "four-hours";
var wantBlockNoticesMuted = false, wantTrayAutostart = false;
var _heldProtection = null, _protectionSeeded = false, _protectionTouched = false;
var _stabilityTouched = false, _fakeIpTouched = false;
var _protectionWritten = null, _protectionWritePending = false;
var _optionsApplied = false, _stabilityWritePending = false;
var _protectionWrite = "", _protectionFailure = "", _protectionSending = null, _afterProtection = [];
var defaultRoute = "prefer-primary", leakFloor = "off";
Object.defineProperty(globalThis, "leakProtectionChoice", { get: function() {
    return Pure.raiseLeakProtection(defaultRoute, wantLeakProtection, leakFloor) } });
Object.defineProperty(globalThis, "servicePolicyKnown", { get: function() {
    return root._servicePolicyRead === true } });
function holder(role) { return root.interfacesRolesController.adapterIndexHoldingRole(role) }
Object.defineProperty(globalThis, "assignedPrimaryIndex", { get: function() { return holder("primary") } });
Object.defineProperty(globalThis, "assignedSecondaryIndex", { get: function() { return holder("secondary") } });
Object.defineProperty(globalThis, "primaryAssigned", { get: function() { return holder("primary") >= 0 } });
Object.defineProperty(globalThis, "secondaryAssigned", { get: function() { return holder("secondary") >= 0 } });
Object.defineProperty(globalThis, "assignedPrimaryName", { get: function() {
    return holder("primary") >= 0 ? rows[holder("primary")].name : "" } });
Object.defineProperty(globalThis, "assignedSecondaryName", { get: function() {
    return holder("secondary") >= 0 ? rows[holder("secondary")].name : "" } });
Object.defineProperty(globalThis, "protectionInForce", { get: function() {
    return servicePolicyKnown && !!root._serviceRoutePolicy
        && _holdsChosenProtection(root._serviceRoutePolicy) } });
"#;

/// The Interfaces controller's own warning, as its screen shows it.
const CONTROLLER_WIRING: &str =
    "root.interfacesRolesController.driverSiblingWarning = driverSiblingWarning;";

/// Runs `scenario` after the window's functions; returns what it logged.
pub fn run(scenario: &str) -> String {
    let program = format!(
        "{}\n{STAND_IN}\n{}\n{}\n{CONTROLLER_WIRING}\n{scenario}\n",
        qml_functions::pure(),
        qml_functions::functions(WINDOW, FUNCTIONS),
        qml_functions::functions(
            "flows/InterfacesRolesController.qml",
            &["driverSiblingWarning"]
        )
    );
    js::run_js(&program)
}
