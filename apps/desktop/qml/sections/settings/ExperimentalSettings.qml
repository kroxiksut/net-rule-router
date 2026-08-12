import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

// Experimental settings. Detailed mode and the pre-flight apply-policy
// opt-in are working toggles and sit above the divider; extended
// diagnostics and kill-switch mode A are dormant and sit below it,
// disabled, until their wiring lands.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.group.experimental", "Experimental")
    Layout.fillWidth: true

    readonly property var diagCtx: root.context.diagnosticsSettings || {}
    readonly property var modeState: diagCtx.diagnosticMode || {}

    // ISP block-page rule suggestions. GLOBAL service setting, read/written
    // via the same stability RPC as the Routing panel's toggles.
    property bool ispBlockCandidatesEnabled: false
    function _refreshIspBlockCandidatesEnabled() {
        if (typeof root._readServiceMirror === "function") {
            var stability = root._readServiceMirror()["stability"] || {}
            if (stability["isp-block-candidates-enabled"] !== undefined)
                group.ispBlockCandidatesEnabled =
                    stability["isp-block-candidates-enabled"] === true
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function")
            return
        var corr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok) return
            group.ispBlockCandidatesEnabled =
                (payload && payload["isp-block-candidates-enabled"]) === true
            if (typeof root._rememberServiceValues === "function")
                root._rememberServiceValues("stability",
                    { "isp-block-candidates-enabled": group.ispBlockCandidatesEnabled })
        })
    }
    Component.onCompleted: group._refreshIspBlockCandidatesEnabled()

    // Read-modify-write the WHOLE service-stability config, mutating ONLY
    // isp-block-candidates-enabled (Set is a full-config write — omitting a
    // field resets it to its default). Global, admin-gated.
    function _applyIspBlockCandidatesEnabled(want) {
        var v = (want === true)
        root.applyServiceStabilityPatch({ "isp-block-candidates-enabled": v },
            function(ok, code, payload) {
                if (ok) {
                    if (payload && payload["isp-block-candidates-enabled"] !== undefined)
                        group.ispBlockCandidatesEnabled =
                            payload["isp-block-candidates-enabled"] === true
                    root.statusLine = group.ispBlockCandidatesEnabled
                        ? root.tr("status.isp-block-candidates-on",
                            "ISP block-page rule suggestions are on.")
                        : root.tr("status.isp-block-candidates-off",
                            "ISP block-page rule suggestions are off.")
                    return
                }
                root.statusLine = root.tr("status.isp-block-candidates-failed",
                    "Could not change the ISP block-page rule suggestions setting: ")
                    + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
                group._refreshIspBlockCandidatesEnabled()
            }, "user:isp-block-candidates-enabled")
    }

    function formatRemaining(ms) {
        var n = Number(ms || 0)
        if (!isFinite(n) || n <= 0) return "-"
        var totalMinutes = Math.floor(n / 60000)
        var h = Math.floor(totalMinutes / 60)
        var m = totalMinutes % 60
        if (h > 0) return h + "h " + m + "m"
        return m + "m"
    }

    // Real "Extended diagnostics" wiring (the Switch + TTL
    // radios were no-ops that toasted "saved"). Reuses the `diagnostics.mode.set`
    // op; the resulting state echoes back and immediately unredacts the cache +
    // connection-trace viewers (they read the same diagnostic session).
    property bool _diagModeApplying: false
    function _selectedDiagTtlMs() {
        if (ttlRadio4h.checked) return 14400000
        if (ttlRadioRestart.checked) return 0     // 0 → until restart
        return 3600000                            // default: 1 hour
    }
    function _applyDiagnosticMode(enabled) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcDiagnosticModeSet !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Service bridge not connected.")
            diagnosticModeSwitch.checked = !enabled   // revert the visual toggle
            return
        }
        var ttl = group._selectedDiagTtlMs()
        var untilRestart = enabled && (ttl === 0)
        var durationMs = (enabled && ttl > 0) ? ttl : 0
        group._diagModeApplying = true
        var corr = nrrNativeBridge.rpcDiagnosticModeSet(enabled, durationMs, untilRestart, "all")
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            group._diagModeApplying = false
            if (!ok) {
                root.statusLine = root.tr("status.diag-mode-failed",
                    "Failed to change diagnostic mode: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                diagnosticModeSwitch.checked = !enabled
                return
            }
            // payload is the authoritative DiagnosticModeStateDto echo.
            var active = (payload && payload.active) === true
            diagnosticModeSwitch.checked = active
            root.statusLine = active
                ? root.tr("status.diag-mode-enabled", "Extended diagnostics enabled.")
                : root.tr("status.diag-mode-disabled", "Extended diagnostics disabled.")
        })
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        Label {
            Layout.fillWidth: true
            text: root.tr("settings.note.experimental",
                "This section is reserved for upcoming experimental options.")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }

        // Reveals the individual DNS/fake-IP tuning toggles in Routing
        // settings. Off by default: the toggles stay hidden and NetRuleRouter
        // uses its built-in defaults for them; turning this on only changes
        // what is shown, never any saved value. Working today, so it leads
        // the section, ahead of the dormant toggles below.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                CheckBox {
                    id: detailedModeCheck
                    Layout.fillWidth: true
                    text: root.tr("settings.experimental.detailed-mode.label",
                        "Detailed mode")
                    checked: root.uiRevision >= 0
                        ? (root.prefs.routingDetailedMode === true) : false
                    contentItem: Label {
                        text: detailedModeCheck.text
                        leftPadding: detailedModeCheck.indicator.width + detailedModeCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: {
                        root.updatePrefs({ routingDetailedMode: checked })
                        root.emitPrefs()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("settings.experimental.detailed-mode.note",
                        "Shows manual switches for individual DNS and address-routing mechanisms under Settings → Routing. Off by default: without it, NetRuleRouter uses sensible defaults for those mechanisms and keeps this screen simple.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }

        // Reveals the "pre-flight, then all-or-nothing" apply-failure policy
        // in Settings -> Routing. Off by default: its checks (FilterId
        // collisions, batch overflow, missing adapter/executable) are not
        // implemented yet, so today it would just be all-or-nothing with an
        // extra label. Turning this on only changes what is offered — a
        // previously-selected value is always shown regardless.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                CheckBox {
                    id: preFlightApplyPolicyCheck
                    Layout.fillWidth: true
                    text: root.tr("settings.experimental.pre-flight-apply-policy.label",
                        "Offer the pre-flight apply-check policy")
                    checked: root.uiRevision >= 0
                        ? (root.prefs.preFlightApplyPolicyOptIn === true) : false
                    contentItem: Label {
                        text: preFlightApplyPolicyCheck.text
                        leftPadding: preFlightApplyPolicyCheck.indicator.width + preFlightApplyPolicyCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: {
                        root.updatePrefs({ preFlightApplyPolicyOptIn: checked })
                        root.emitPrefs()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("settings.experimental.pre-flight-apply-policy.note",
                        "Adds \"Pre-flight, then all-or-nothing\" to the apply failure policy in Settings → Routing. The pre-flight checks themselves are still in development — until they land, this option behaves the same as All or nothing.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }

        // ISP block-page rule suggestions. Working end to end, but not yet
        // verified on a live machine — hence the badge and living here.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    CheckBox {
                        id: ispBlockCandidatesCheck
                        text: root.tr("settings.experimental.isp-block-candidates.label",
                            "Suggest a rule when a site is blocked by your provider")
                        checked: group.ispBlockCandidatesEnabled
                        Accessible.role: Accessible.CheckBox
                        Accessible.name: text
                        Accessible.description: root.tr("settings.experimental.in-development",
                            "In development")
                        contentItem: Label {
                            text: ispBlockCandidatesCheck.text
                            leftPadding: ispBlockCandidatesCheck.indicator.width + ispBlockCandidatesCheck.spacing
                            color: root.textColor
                            wrapMode: Text.WordWrap
                            verticalAlignment: Text.AlignVCenter
                        }
                        onToggled: group._applyIspBlockCandidatesEnabled(checked)
                    }
                    Label {
                        text: root.tr("settings.experimental.in-development", "In development")
                        color: root.uiTheme.colorAccent
                        font.bold: true
                    }
                    Item { Layout.fillWidth: true }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("settings.experimental.isp-block-candidates.note",
                        "When a site will not open because your internet provider is blocking it, NetRuleRouter offers to move that site to your additional route instead of leaving it unreachable.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }

        // Separates the working toggles above from the dormant ones below.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // Diagnostic mode toggle (moved from Diagnostics and Logs). The
        // `diagnostics.mode.set` wiring is dormant — the toggle round-trips
        // to the service but produces no observable effect yet — so the
        // whole card is disabled until it lands.
        Frame {
            Layout.fillWidth: true
            enabled: false
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Image {
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                        source: root.uiIconSource("icon_diagnostic_mode_on")
                        sourceSize.width: 20
                        sourceSize.height: 20
                        fillMode: Image.PreserveAspectFit
                        asynchronous: true
                    }
                    Switch {
                        id: diagnosticModeSwitch
                        text: root.tr("diag.diagnostic-mode.toggle-label", "Extended diagnostics")
                        checked: !!group.modeState.active
                        Accessible.role: Accessible.CheckBox
                        Accessible.name: text
                        Accessible.description: root.tr("settings.experimental.in-development",
                            "In development")
                        // Apply the real diagnostics.mode.set op.
                        onToggled: group._applyDiagnosticMode(checked)
                    }
                    Label {
                        text: root.tr("settings.experimental.in-development", "In development")
                        color: root.uiTheme.colorAccent
                        font.bold: true
                    }
                    Item { Layout.fillWidth: true }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.diagnostic-mode.toggle-description",
                        "Enables detailed routing and cache information in logs. Automatically expires.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    enabled: diagnosticModeSwitch.checked
                    spacing: root.uiTheme.spacingSm
                    ButtonGroup { id: ttlGroup }
                    RadioButton {
                        id: ttlRadio1h
                        text: root.tr("diag.diagnostic-mode.ttl-1h", "1 hour")
                        ButtonGroup.group: ttlGroup
                        checked: Number(group.modeState.selectedTtlMs || 3600000) === 3600000
                        // Re-arm the session with the new TTL if active.
                        onClicked: if (diagnosticModeSwitch.checked && !group._diagModeApplying)
                            group._applyDiagnosticMode(true)
                    }
                    RadioButton {
                        id: ttlRadio4h
                        text: root.tr("diag.diagnostic-mode.ttl-4h", "4 hours")
                        ButtonGroup.group: ttlGroup
                        checked: Number(group.modeState.selectedTtlMs || 0) === 14400000
                        onClicked: if (diagnosticModeSwitch.checked && !group._diagModeApplying)
                            group._applyDiagnosticMode(true)
                    }
                    RadioButton {
                        id: ttlRadioRestart
                        text: root.tr("diag.diagnostic-mode.ttl-restart", "Until restart")
                        ButtonGroup.group: ttlGroup
                        checked: Number(group.modeState.selectedTtlMs || 0) === 0
                        onClicked: if (diagnosticModeSwitch.checked && !group._diagModeApplying)
                            group._applyDiagnosticMode(true)
                    }
                    Item { Layout.fillWidth: true }
                }
                Label {
                    Layout.fillWidth: true
                    visible: diagnosticModeSwitch.checked
                    text: root.tr("diag.diagnostic-mode.warning-banner",
                        "Extended diagnostics are active. More detailed information is being logged.")
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: diagnosticModeSwitch.checked && Number(group.modeState.remainingMs || 0) > 0
                    text: root.tr("diag.diagnostic-mode.expires-in", "Expires in {time}")
                        .replace("{time}", group.formatRemaining(group.modeState.remainingMs))
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }

        // Legacy kill-switch mode A opt-in. Off by default; when on, the routing
        // settings reveal the historical reactive mode A option in the
        // enforcement-mechanism selector. Device-local display preference — it
        // commits immediately and never arms the footer Apply/Cancel. Disabled
        // pending its own re-verification pass.
        Frame {
            Layout.fillWidth: true
            enabled: false
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    CheckBox {
                        id: allowModeACheck
                        text: root.tr("settings.experimental.allow-mode-a.label",
                            "Allow kill-switch mode A (legacy)")
                        checked: root.uiRevision >= 0
                            ? (root.prefs.allowModeAKillswitch === true) : false
                        Accessible.role: Accessible.CheckBox
                        Accessible.name: text
                        Accessible.description: root.tr("settings.experimental.in-development",
                            "In development")
                        contentItem: Label {
                            text: allowModeACheck.text
                            leftPadding: allowModeACheck.indicator.width + allowModeACheck.spacing
                            color: root.textColor
                            wrapMode: Text.WordWrap
                            verticalAlignment: Text.AlignVCenter
                        }
                        onToggled: {
                            root.updatePrefs({ allowModeAKillswitch: checked })
                            root.emitPrefs()
                        }
                    }
                    Label {
                        text: root.tr("settings.experimental.in-development", "In development")
                        color: root.uiTheme.colorAccent
                        font.bold: true
                    }
                    Item { Layout.fillWidth: true }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("settings.experimental.allow-mode-a.note",
                        "Mode A is a legacy enforcement mode kept only for historical reference. It is not maintained, may not work, and can be removed in a future release. Mode B (the local DNS resolver) is the supported mechanism. Turn this on only if you specifically need to pick mode A in the routing settings.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
