import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

// Rule diagnostics: the interactive explain probe, moved out of
// DiagnosticsSection into its own window. It answers "which rule would win for
// this destination", which people read WHILE editing rules — a section in a
// StackLayout cannot be open next to the rules table, a window can.
//
// The window owns its state rather than reading the section's: the section
// lives in a lazy Loader and does not exist until Diagnostics is opened once,
// so a window borrowing its state would come up empty when opened first.
Window {
    id: probeWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    width: 720
    height: 560
    visible: false
    modality: Qt.NonModal
    color: root ? root.panelColor : "transparent"
    title: root ? root.tr("diag.explain.window-title", "Rule diagnostics") : ""
    transientParent: root
    flags: Qt.Dialog
    onVisibleChanged: if (visible) { root.centerChildWindow(probeWindow); root.applyTitleBarTo(probeWindow) }

    // Interactive explain probe. Replaces the
    // static `diag.explainSample` read with a live `ExplainGet` query.
    // `_probeResultRoute` slugs match `ExplainCompactViewDto.route`:
    // `"primary" | "secondary" | "none" | "blocked"`. This is the
    // SYNTHETIC path (`rpcExplainGetBySample`): the service runs the REAL
    // rule engine (`match_sample`) against the caller's per-SID active rule
    // book + behavior mode and returns a real route/reason (Available). The
    // separate Historical-by-decision-id path (explain snapshot store) is
    // NOT surfaced in this UI, so the probe never returns `Unavailable`.
    property bool _probing: false
    property string _probeInputText: ""
    // A trace row hands its address and program along with the name, so the
    // probe answers for that connection; the next run consumes them.
    property string _probeSampleIp: ""
    property string _probeSampleProcess: ""
    property string _probeResultInput: ""
    property string _probeResultRoute: ""
    property string _probeReasonKey: ""
    property string _probeErrorCode: ""
    property string _probeErrorMessage: ""
    // Optional enforcement caveat carried on the compact explain
    // response (`enforcement` slug; "" = none). When set, the probe surfaces a
    // second amber line warning that although the route resolved, the flow may
    // currently be BLOCKED (block-all-unresolved, or fail-closed while the
    // additional adapter is down). Cleared on every new probe / error.
    property string _probeEnforcement: ""
    // For the shared-IP collateral slugs: how many of the
    // probed host's cached IPs are census-shared with secondary rules, out of
    // how many cached total. 0/0 for every other verdict.
    property int _probeEnforcementShared: 0
    property int _probeEnforcementTotal: 0

    function _isIpv4(s) { return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(s) }
    function _isIpv6(s) { return s.indexOf(":") >= 0 && /^[0-9a-fA-F:]+$/.test(s) }
    function _explainRouteLabel(route) {
        if (route === "" || route === "none")
            return root.tr("diag.explain.route.none", "no route")
        if (route === "blocked")
            return root.tr("diag.explain.route.blocked", "blocked")
        if (route === "primary")
            return root.tr("diag.explain.route.primary", "primary route")
        if (route === "secondary")
            return root.tr("diag.explain.route.secondary", "secondary route")
        return route
    }
    // Main probe verdict, spoken as a "route — status" pair
    // ("Primary — Allowed" / "Secondary — Blocked") instead of the bare
    // route name. Only applies to a resolved primary/secondary route: the
    // "status" half reflects whether the enforcement caveat below (killswitch
    // / fail-closed / block-all) will actually block the flow. Reuses the
    // generic route-role labels (`label.primary`/`label.secondary`) and the
    // conn-trace verdict labels (`diag.conn-trace.verdict.permit`/`.block`)
    // instead of minting new near-duplicate text. "none"/"blocked" routes
    // fall back to the plain route label — there is no route role to pair
    // a status against.
    function _probeVerdictLabel() {
        var route = probeWindow._probeResultRoute
        if (route !== "primary" && route !== "secondary")
            return probeWindow._explainRouteLabel(route)
        var routeWord = route === "primary"
            ? root.tr("label.primary", "Primary")
            : root.tr("label.secondary", "Secondary")
        // Only genuinely-blocking caveats flip the status:
        // the smart-exempt and risk slugs describe a caveat on an ALLOWED flow.
        var blocking = probeWindow._probeEnforcement === "blocked-unknown-under-block-all"
            || probeWindow._probeEnforcement === "fail-closed-when-secondary-down"
            || probeWindow._probeEnforcement === "collateral-blocked-strict"
        var statusWord = blocking
            ? root.tr("diag.conn-trace.verdict.block", "Blocked")
            : root.tr("diag.conn-trace.verdict.permit", "Allowed")
        return routeWord + " — " + statusWord
    }
    function _runExplainProbe() {
        var sampleIp = _probeSampleIp
        var sampleProcess = _probeSampleProcess
        _probeSampleIp = ""
        _probeSampleProcess = ""
        var raw = String(_probeInputText || "").trim()
        if (raw === "") {
            _probeErrorCode = "input-required"
            _probeErrorMessage = ""
            _probeResultInput = ""
            _probeResultRoute = ""
            _probeReasonKey = ""
            _probeEnforcement = ""
            _probeEnforcementShared = 0
            _probeEnforcementTotal = 0
            return
        }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcExplainGetBySample !== "function") {
            _probeErrorCode = "bridge-unavailable"
            _probeErrorMessage = ""
            return
        }
        _probing = true
        _probeResultInput = ""
        _probeResultRoute = ""
        _probeReasonKey = ""
        _probeErrorCode = ""
        _probeErrorMessage = ""
        _probeEnforcement = ""
        _probeEnforcementShared = 0
        _probeEnforcementTotal = 0

        var hostname = ""
        var observedIp = ""
        if (_isIpv4(raw) || _isIpv6(raw)) {
            observedIp = raw
        } else {
            hostname = raw
        }
        if (observedIp === "")
            observedIp = sampleIp
        var corr = nrrNativeBridge.rpcExplainGetBySample(
            hostname, observedIp, sampleProcess, "compact-ui")
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            probeWindow._probing = false
            if (!ok) {
                probeWindow._probeErrorCode = String(errorCode || "unknown")
                probeWindow._probeErrorMessage = String(errorMessage || "")
                probeWindow._probeEnforcement = ""
                probeWindow._probeEnforcementShared = 0
                probeWindow._probeEnforcementTotal = 0
                return
            }
            var compact = (payload && payload.compact) || {}
            probeWindow._probeResultInput = String(compact.input || "-")
            probeWindow._probeResultRoute = String(compact.route || "none")
            // Wire is kebab-case (`reason-key`); fall back to snake_case
            // in case a server variant ever serialises differently.
            probeWindow._probeReasonKey =
                String(compact["reason-key"] || compact.reason_key || "")
            // Optional enforcement caveat (kebab `enforcement`, snake fallback).
            probeWindow._probeEnforcement =
                String(compact["enforcement"] || compact.enforcement || "")
            // Shared-IP collateral counts (N of M cached IPs).
            probeWindow._probeEnforcementShared =
                Number(compact["enforcement-shared-ips"] || 0)
            probeWindow._probeEnforcementTotal =
                Number(compact["enforcement-total-ips"] || 0)
        })
    }
    ScrollView {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingLg
        clip: true
        ColumnLayout {
            width: probeWindow.width - 2 * root.uiTheme.spacingLg
            spacing: root.uiTheme.spacingMd
        // Explain sample probe.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                Label {
                    text: root.tr("diag.explain.title", "Explain sample")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.explain.subtitle",
                        "Enter a hostname or IP to simulate the routing decision against the active rule set.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedTextField {
                        id: probeInput
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        placeholderText: root.tr("diag.explain.probe-placeholder",
                            "hostname or IP")
                        text: probeWindow._probeInputText
                        enabled: !probeWindow._probing
                        onTextChanged: probeWindow._probeInputText = text
                        onAccepted: probeWindow._runExplainProbe()
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.explain.probe-button", "Probe")
                        enabled: !probeWindow._probing
                        onClicked: probeWindow._runExplainProbe()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    visible: probeWindow._probing
                    text: root.tr("diag.explain.probing", "Probing...")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Initial idle state — no probe attempt yet.
                Label {
                    Layout.fillWidth: true
                    visible: !probeWindow._probing
                        && probeWindow._probeResultInput === ""
                        && probeWindow._probeReasonKey === ""
                        && probeWindow._probeErrorCode === ""
                    text: root.tr("diag.explain.empty",
                        "No explain sample available")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Success path — compact view from ExplainGetResponse.
                Label {
                    Layout.fillWidth: true
                    visible: !probeWindow._probing
                        && probeWindow._probeResultInput !== ""
                        && probeWindow._probeErrorCode === ""
                    text: probeWindow._probeResultInput
                        + "  →  "
                        + probeWindow._probeVerdictLabel()
                    color: root.textColor
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: !probeWindow._probing
                        && probeWindow._probeReasonKey !== ""
                        && probeWindow._probeErrorCode === ""
                    text: root.tr(probeWindow._probeReasonKey,
                        probeWindow._probeReasonKey)
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Enforcement caveat — the route resolved, but the flow may
                // currently be BLOCKED (block-all-unresolved, or fail-closed while
                // the additional adapter is down). Amber, second line under the route.
                Label {
                    Layout.fillWidth: true
                    visible: !probeWindow._probing
                        && probeWindow._probeEnforcement !== ""
                        && probeWindow._probeErrorCode === ""
                    // The collateral slugs append the
                    // "N of M cached addresses are shared" counts.
                    text: root.tr("diag.explain.enforcement." + probeWindow._probeEnforcement,
                        probeWindow._probeEnforcement)
                        + (probeWindow._probeEnforcementShared > 0
                            ? " (" + probeWindow._probeEnforcementShared + "/"
                                + probeWindow._probeEnforcementTotal + ")"
                            : "")
                    color: root.uiTheme.colorWarning
                    wrapMode: Text.WordWrap
                }
                // Validation / bridge / wire errors. Wire codes go
                // Through `root.ipcErrorLabel`;
                // local slugs ("input-required", "bridge-unavailable")
                // resolve via dedicated `diag.explain.*` keys.
                Label {
                    Layout.fillWidth: true
                    visible: !probeWindow._probing && probeWindow._probeErrorCode !== ""
                    text: {
                        var code = probeWindow._probeErrorCode
                        if (code === "input-required")
                            return root.tr("diag.explain.input-required",
                                "Enter a hostname or IP to probe")
                        if (code === "bridge-unavailable")
                            return root.tr("diag.explain.bridge-unavailable",
                                "Service bridge not connected — probe unavailable")
                        // Show only the localised slug label — the raw
                        // English wire message ("ipc client is not
                        // connected to service" etc.) is logged in
                        // _probeErrorMessage for diagnostics but never
                        // surfaced to the user-facing label.
                        return (typeof root.ipcErrorLabel === "function")
                            ? root.ipcErrorLabel(code) : code
                    }
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
            }
        }
            Item { Layout.fillHeight: true }
        }
    }
}
