import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/rules.js" as Rules

// The explain probe: which rule would win for a destination, and whether the
// flow would be let through right now. Callers hand it a sample via `probe()`.
Frame {
    id: panel
    property var root
    Layout.fillWidth: true
    padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
    background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }

    // Interactive explain probe, backed by a live `ExplainGet` query.
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
    // The address a literal-IP block vetoed the probe on, "" otherwise.
    property string _probeBlockingIp: ""

    /// The address of the exact-IP block rule `id`, read from the rules list
    /// so the compact probe never has to carry it.
    function _blockRuleAddress(id) {
        var want = Rules.canonicalRuleId(id)
        if (want === "" || !root.rulesModel) return ""
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            var row = root.rulesModel.get(i)
            if (String(row.targetRoute) === "block" && String(row.ruleType) === "exact-ip"
                    && Rules.canonicalRuleId(String(row.id || "")) === want)
                return String(row.matchValue || "")
        }
        return ""
    }

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
            return root.tr("diag.explain.route.secondary", "additional route")
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
        var route = panel._probeResultRoute
        if (route !== "primary" && route !== "secondary")
            return panel._explainRouteLabel(route)
        var routeWord = route === "primary"
            ? root.tr("label.primary", "Primary")
            : root.tr("label.secondary", "Additional")
        // Only genuinely-blocking caveats flip the status:
        // the smart-exempt and risk slugs describe a caveat on an ALLOWED flow.
        var blocking = panel._probeEnforcement === "blocked-unknown-under-block-all"
            || panel._probeEnforcement === "fail-closed-when-secondary-down"
            || panel._probeEnforcement === "collateral-blocked-strict"
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
            _probeBlockingIp = ""
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
        _probeBlockingIp = ""

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
            panel._probing = false
            if (!ok) {
                panel._probeErrorCode = String(errorCode || "unknown")
                panel._probeErrorMessage = String(errorMessage || "")
                panel._probeEnforcement = ""
                panel._probeEnforcementShared = 0
                panel._probeEnforcementTotal = 0
                return
            }
            var compact = (payload && payload.compact) || {}
            panel._probeResultInput = String(compact.input || "-")
            panel._probeResultRoute = String(compact.route || "none")
            // Wire is kebab-case (`reason-key`); fall back to snake_case
            // in case a server variant ever serialises differently.
            panel._probeReasonKey =
                String(compact["reason-key"] || compact.reason_key || "")
            // Optional enforcement caveat (kebab `enforcement`, snake fallback).
            panel._probeEnforcement =
                String(compact["enforcement"] || compact.enforcement || "")
            // Shared-IP collateral counts (N of M cached IPs).
            panel._probeEnforcementShared =
                Number(compact["enforcement-shared-ips"] || 0)
            panel._probeEnforcementTotal =
                Number(compact["enforcement-total-ips"] || 0)
            // Blocked by an address rule: name the address, from the rules
            // list, or from the full answer when that tier carries it.
            if (panel._probeReasonKey === "diag.explain.reason.blocked-by-ip-rule") {
                var full = (payload && payload.full) || {}
                var matched = full.match_section || {}
                var lookup = full.lookup_section || {}
                panel._probeBlockingIp =
                    panel._blockRuleAddress(String(matched.matched_rule_id || ""))
                    || String(lookup.selected_ip || "")
            }
        })
    }
    function probe(input, sampleIp, sampleProcess) {
        // Through the field: typing broke its binding, and the field, the
        // verdict and the button must name the same host.
        probeInput.text = String(input || "")
        _probeInputText = probeInput.text
        _probeSampleIp = String(sampleIp || "")
        _probeSampleProcess = String(sampleProcess || "")
        _runExplainProbe()
    }
    function focusInput() { probeInput.forceActiveFocus() }

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
                text: panel._probeInputText
                enabled: !panel._probing
                onTextChanged: panel._probeInputText = text
                onAccepted: panel._runExplainProbe()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("diag.explain.probe-button", "Probe")
                enabled: !panel._probing
                onClicked: panel._runExplainProbe()
            }
        }
        Label {
            Layout.fillWidth: true
            visible: panel._probing
            text: root.tr("diag.explain.probing", "Probing...")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }
        // Initial idle state — no probe attempt yet.
        Label {
            Layout.fillWidth: true
            visible: !panel._probing
                && panel._probeResultInput === ""
                && panel._probeReasonKey === ""
                && panel._probeErrorCode === ""
            text: root.tr("diag.explain.empty",
                "No explain sample available")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }
        // Success path — compact view from ExplainGetResponse.
        Label {
            Layout.fillWidth: true
            visible: !panel._probing
                && panel._probeResultInput !== ""
                && panel._probeErrorCode === ""
            text: panel._probeResultInput
                + "  →  "
                + panel._probeVerdictLabel()
            color: root.textColor
            wrapMode: Text.WordWrap
        }
        Label {
            Layout.fillWidth: true
            visible: !panel._probing
                && panel._probeReasonKey !== ""
                && panel._probeErrorCode === ""
            text: root.tr(panel._probeReasonKey,
                panel._probeReasonKey)
                + (panel._probeBlockingIp !== "" ? " (" + panel._probeBlockingIp + ")" : "")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }
        // Enforcement caveat — the route resolved, but the flow may
        // currently be BLOCKED (block-all-unresolved, or fail-closed while
        // the additional adapter is down). Amber, second line under the route.
        Label {
            Layout.fillWidth: true
            visible: !panel._probing
                && panel._probeEnforcement !== ""
                && panel._probeErrorCode === ""
            // The collateral slugs append the
            // "N of M cached addresses are shared" counts.
            text: root.tr("diag.explain.enforcement." + panel._probeEnforcement,
                panel._probeEnforcement)
                + (panel._probeEnforcementShared > 0
                    ? " (" + panel._probeEnforcementShared + "/"
                        + panel._probeEnforcementTotal + ")"
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
            visible: !panel._probing && panel._probeErrorCode !== ""
            text: {
                var code = panel._probeErrorCode
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
