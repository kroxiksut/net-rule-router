import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../flows"
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

// The tray's "Add rule…" while the main window is closed. It hosts the main
// window's own `RuleEditDialog` and acts as its `root`, so every `root.*` name
// the dialog reads is declared here (`rule_dialog_host_contract.rs` holds the
// two files together). What a saved form becomes is shared with the main window
// through `RuleEditSupport` and `lib/rules.js`. The rule book goes back to the
// service whole, built from the service's own rows with the window's mapping,
// so no rule but the new one can change.
ApplicationWindow {
    id: trayRuleWindow

    /// The tray (`Tray.qml`): language, theme, transport, route names, and what
    /// follows a saved rule (bound files, the notice).
    required property var trayHost

    // ── What the dialog reads through `root` ──
    readonly property var uiTheme: trayHost.uiTheme
    // The tray's language is fixed for its lifetime, so nothing re-translates.
    readonly property int uiRevision: 0
    readonly property var rpc: trayHost.rpc
    readonly property var platformProfile: trayHost.platformProfile
    /// Only the setting the form explains; read from the service on open.
    property var prefs: ({ routeIncludeSubdomains: true })
    /// Always a new rule here.
    property int editingRule: -1
    readonly property color textColor: uiTheme.colorText
    readonly property color mutedTextColor: uiTheme.colorTextMuted
    property alias ruleTypesModel: ruleTypesModel
    property alias ruleDialog: ruleDialog
    /// The service's rules as table rows, shaped like a ListModel.
    readonly property var rulesModel: ({
        count: _rows.length,
        get: function(i) { return trayRuleWindow._rows[i] }
    })
    property var ruleOverlapsController: RuleOverlapsController { root: trayRuleWindow }
    /// Read by the overlaps controller; nothing applied is shown here.
    readonly property var routingState: ({})

    function tr(key, fallback) { return trayHost.tr(key, fallback) }
    function supports(feature) { return trayHost.supports(feature) }
    function routeLabel(role) {
        return Rules.routeDisplayLabel(role, trayHost.routePrimaryLabel,
            trayHost.routeSecondaryLabel, tr)
    }
    function routeRoleOptions(includeBlock) { return Rules.routeRoleOptions(includeBlock, routeLabel) }
    function ruleTypeLabel(id) { return support.ruleTypeLabel(id) }
    function _punycodeFor(host) { return support.aceCodec.hint(host) }
    function nextFreeRuleId() { return Rules.nextFreeRuleId(_rows) }
    function comboPopupWidth(control, model, textRole, textResolver) {
        return Pure.comboPopupWidthFor(control, model, textRole, textResolver,
            function(text) { return Math.ceil(fontMetrics.advanceWidth(String(text || ""))) },
            function(width) { return Math.min(Math.max(220, width), Math.max(220, trayRuleWindow.width - 48)) })
    }
    function candidateRouteOverlaps(index, row, done) {
        support.candidateRouteOverlaps(_rows, index, row, prefs.routeIncludeSubdomains !== false, done)
    }
    function saveRule() {
        _submit([support.ruleRowFromDialog(ruleDialog, nextFreeRuleId())], false)
    }
    function saveRuleList(entries) {
        var items = []
        for (var i = 0; i < entries.length; i += 1) {
            items.push(support.ruleRowFromForm({
                ruleType: String(entries[i]["rule-type"] || ""),
                value: String(entries[i].value || ""),
                route: ruleDialog.localRoute,
                verify: ruleDialog.localVerify,
                comment: ruleDialog.localComment,
                enabled: ruleDialog.localEnabled
            }, Rules.nextFreeRuleId(_rows.concat(items))))
        }
        _submit(items, false)
    }

    // ── Window ──
    title: tr("tray.add-rule.title", "Add rule")
    readonly property int _margin: 12
    width: ruleDialog.width + 2 * _margin
    minimumWidth: width
    maximumWidth: width
    height: Math.min(_maxHeight,
        Math.max(ruleDialog.implicitHeight, messagePane.implicitHeight + 2 * uiTheme.spacingLg)
            + 2 * _margin)
    readonly property int _maxHeight: Screen.desktopAvailableHeight > 0
        ? Math.max(320, Math.min(Screen.desktopAvailableHeight, Screen.height) - 80) : 720
    color: uiTheme.colorWindow
    palette.window: uiTheme.colorWindow
    palette.windowText: uiTheme.colorText
    palette.base: uiTheme.colorBase
    palette.alternateBase: uiTheme.colorPanel
    palette.button: uiTheme.colorPanel
    palette.buttonText: uiTheme.colorText
    palette.text: uiTheme.colorText
    palette.highlight: uiTheme.colorAccent
    palette.highlightedText: uiTheme.colorOnAccent
    palette.toolTipBase: uiTheme.colorPanel
    palette.toolTipText: uiTheme.colorText
    font.family: uiTheme.resolvedFontFamily
    font.pixelSize: uiTheme.baseFontSizePx
    onVisibleChanged: {
        if (visible) _applyTitleBar()
        else _releaseIfIdle()
    }

    /// Closed with no rule on its way: the tray drops the window, so a form
    /// opened once does not hold its memory for the rest of the session.
    signal released()
    function _releaseIfIdle() {
        if (!visible && _state !== "busy") released()
    }

    FontMetrics { id: fontMetrics; font: trayRuleWindow.font }
    ListModel { id: ruleTypesModel }

    RuleEditSupport {
        id: support
        host: trayRuleWindow
        language: String(trayRuleWindow.trayHost.language || "")
        rpc: trayRuleWindow.rpc
    }

    RuleEditDialog {
        id: ruleDialog
        root: trayRuleWindow
        // The window's title bar already names the form.
        header: null
    }
    Connections {
        target: ruleDialog
        function onRejected() { trayRuleWindow._closeSoon() }
        // Closed without an answer (a click beside it): nothing to keep the
        // window up for. Deferred past an accept that is still saving.
        function onClosed() {
            Qt.callLater(function() {
                if (!ruleDialog.visible && trayRuleWindow._state === "") trayRuleWindow._closeSoon()
            })
        }
    }

    // ── What happened to the saved rule ──
    // "" while the form is up; "busy", "duplicate", "elsewhere", "error" or
    // "changed-elsewhere" while this pane stands in for it.
    property string _state: ""
    property string _message: ""
    /// Rules waiting for the user's answer to "move it to this route?".
    property var _pendingItems: []
    /// The service's rules as table rows, read on open and again on save.
    property var _rows: []

    ColumnLayout {
        id: messagePane
        visible: trayRuleWindow._state !== ""
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: trayRuleWindow.uiTheme.spacingLg
        spacing: trayRuleWindow.uiTheme.spacingMd
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.WordWrap
            text: trayRuleWindow._message
            color: trayRuleWindow._state === "error" || trayRuleWindow._state === "changed-elsewhere"
                ? trayRuleWindow.uiTheme.colorDanger : trayRuleWindow.textColor
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        RowLayout {
            Layout.fillWidth: true
            visible: trayRuleWindow._state !== "busy"
            spacing: trayRuleWindow.uiTheme.spacingSm
            Item { Layout.fillWidth: true }
            ThemedButton {
                visible: trayRuleWindow._state === "elsewhere"
                theme: trayRuleWindow.uiTheme
                highlighted: true
                text: trayRuleWindow.tr("tray.add-rule.move", "Move to this route")
                onClicked: trayRuleWindow._submit(trayRuleWindow._pendingItems, true)
                Accessible.name: text
            }
            ThemedButton {
                visible: trayRuleWindow._state === "changed-elsewhere"
                theme: trayRuleWindow.uiTheme
                highlighted: true
                text: trayRuleWindow.tr("tray.action.open-window", "Open window")
                onClicked: {
                    trayRuleWindow.trayHost.triggerAction("open-main-window")
                    trayRuleWindow._closeSoon()
                }
                Accessible.name: text
            }
            ThemedButton {
                theme: trayRuleWindow.uiTheme
                text: trayRuleWindow.tr("action.back", "Back")
                onClicked: trayRuleWindow._backToForm()
                Accessible.name: text
            }
            ThemedButton {
                theme: trayRuleWindow.uiTheme
                text: trayRuleWindow.tr("action.close", "Close")
                onClicked: trayRuleWindow._closeSoon()
                Accessible.name: text
            }
        }
    }
    Shortcut {
        sequences: ["Esc"]
        context: Qt.WindowShortcut
        enabled: trayRuleWindow._state !== "" && trayRuleWindow._state !== "busy"
        onActivated: trayRuleWindow._closeSoon()
    }

    /// Open on a fresh form, or bring forward the one already up.
    function present() {
        if (visible) {
            raiseTimer.restart()
            return
        }
        // Closed while a rule was on its way: that answer is still owed.
        if (_state === "busy") {
            show()
            raise()
            requestActivate()
            return
        }
        _state = ""
        _message = ""
        _pendingItems = []
        Pure.clearModel(ruleTypesModel)
        var types = Rules.offeredRuleTypes((trayHost.context || {}).supportedRuleTypes || [],
            supports("appRouting"))
        for (var t = 0; t < types.length; t += 1) ruleTypesModel.append(types[t])
        editingRule = -1
        ruleDialog.resetForEdit()
        _loadRows(null)
        _loadRoutePolicy()
        x = Screen.virtualX + Math.max(0, Math.round((Screen.width - width) / 2))
        y = Screen.virtualY + Math.max(0, Math.round((Screen.height - height) / 2))
        _applyTitleBar()
        show()
        raise()
        requestActivate()
        ruleDialog.open()
    }

    // Closing or raising a window from inside an event Qt is still delivering
    // to it trips an assertion in Qt's window-update path that takes the tray
    // process down (see `TrayPromptWindow`); a zero timer runs after it.
    Timer {
        id: closeTimer
        interval: 0
        repeat: false
        onTriggered: trayRuleWindow.close()
    }
    Timer {
        id: raiseTimer
        interval: 0
        repeat: false
        onTriggered: {
            trayRuleWindow.raise()
            trayRuleWindow.requestActivate()
        }
    }
    function _closeSoon() { closeTimer.restart() }

    function _applyTitleBar() {
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.setWindowDarkTitleBar === "function") {
            nrrNativeBridge.setWindowDarkTitleBar(trayRuleWindow, uiTheme.isDark)
        }
    }

    function _backToForm() {
        _state = ""
        _message = ""
        ruleDialog.open()
    }

    function _setState(state, message) {
        _state = state
        _message = message
    }

    /// The service's rules through the window's own mapping, numbered as the
    /// window numbers them. `done(ok)` may be null.
    function _loadRows(done) {
        var bridge = rpc ? rpc.bridge : null
        if (!bridge || typeof bridge.rpcRulesList !== "function") {
            if (done) done(false)
            return
        }
        var corr = bridge.rpcRulesList()
        if (!corr || String(corr) === "") {
            if (done) done(false)
            return
        }
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok || !payload) {
                console.log("tray add-rule: rules.list failed:", code, msg)
                if (done) done(false)
                return
            }
            var wire = payload.rows || []
            var rows = []
            for (var i = 0; i < wire.length; i += 1) {
                var row = support.serviceRowToModelRow(wire[i])
                row.id = Rules.sequentialRuleId(i)
                rows.push(row)
            }
            trayRuleWindow._rows = rows
            if (done) done(true)
        })
    }

    function _loadRoutePolicy() {
        var bridge = rpc ? rpc.bridge : null
        if (!bridge || typeof bridge.rpcSnapshotInitialGet !== "function") return
        var corr = bridge.rpcSnapshotInitialGet()
        if (!corr || String(corr) === "") return
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            var policy = payload["route-policy"] || payload.routePolicy || {}
            trayRuleWindow.prefs = { routeIncludeSubdomains: policy["include-subdomains"] !== false }
        })
    }

    /// Send the service's rules plus `items`. Read again first: what goes back
    /// must be what the service holds now, not what it held when the form opened.
    function _submit(items, moveElsewhere) {
        _pendingItems = items
        _setState("busy", tr("tray.add-rule.saving", "Adding the rule…"))
        _loadRows(function(ok) {
            if (!ok) {
                trayRuleWindow._fail("error", tr("tray.add-rule.load-failed",
                    "Could not read your rules from the service, so nothing was added. Check that the service is running."))
                return
            }
            var plan = Rules.planRuleAddition(trayRuleWindow._rows, items, moveElsewhere)
            if (plan.elsewhere.length > 0 && !moveElsewhere) {
                trayRuleWindow._setState("elsewhere", trayRuleWindow._elsewhereText(plan.elsewhere))
                return
            }
            if (plan.added === 0 && plan.changed === 0) {
                trayRuleWindow._setState("duplicate",
                    tr("dialog.rule.duplicate-title", "Rule already exists"))
                return
            }
            trayRuleWindow._send(plan)
        })
    }

    function _elsewhereText(elsewhere) {
        if (elsewhere.length === 1) {
            var row = elsewhere[0].row
            return tr("tray.add-rule.on-other-route",
                    "{value} is already in your rules, on the route {route}.")
                .replace("{value}", String(row.matchValue))
                .replace("{route}", routeLabel(String(row.targetRoute)))
        }
        return tr("tray.add-rule.on-other-route-many",
                "{count} of these are already in your rules, on another route.")
            .replace("{count}", String(elsewhere.length))
    }

    function _send(plan) {
        var json = ""
        try {
            json = Rules.buildRulesJson(plan.rows, support.aceCodec.encode)
        } catch (err) {
            console.error("tray add-rule: rules serialization failed:", err)
        }
        var submitter = trayHost.rulesSubmitter
        if (!json || !submitter || typeof submitter.applyNow !== "function") {
            _fail("error", tr("status.rules-serialize-failed",
                "Internal error while preparing rules — see logs"))
            return
        }
        submitter.applyNow(json, "tray-add-rule",
            { added: plan.added, removed: 0, changed: plan.changed },
            function(ok, r) {
                if (ok) trayRuleWindow._succeeded(plan)
                else trayRuleWindow._failed(r)
            })
    }

    function _succeeded(plan) {
        // Comments live in the sidecar, keyed by type, value and route: a moved
        // rule's comment is written again under its new route.
        var touched = plan.addedRows.concat(plan.movedRows)
        for (var i = 0; i < touched.length; i += 1) {
            if (String(touched[i].comment || "") !== "") support.writeComment(touched[i])
        }
        trayHost.boundFileWriter.mirrorServiceIntoFiles()
        trayHost.noteAddRuleOutcome(_outcomeText(plan))
        _state = ""
        _closeSoon()
        _releaseIfIdle()
    }

    function _outcomeText(plan) {
        if (plan.added + plan.changed > 1) {
            var text = tr("status.rules-list-added", "Rules added: {count}.")
                .replace("{count}", String(plan.added))
            if (plan.changed > 0) {
                text += " " + tr("tray.add-rule.moved-count", "Moved to this route: {count}.")
                    .replace("{count}", String(plan.changed))
            }
            return text
        }
        var row = plan.added > 0 ? plan.addedRows[0] : plan.movedRows[0]
        var template = plan.added > 0
            ? (row.enabled === false
                ? tr("tray.add-rule.added-disabled",
                    "Rule added, switched off: {value} → {route}. It does not route anything until you switch it on.")
                : tr("tray.add-rule.added", "Rule added: {value} → {route}"))
            : tr("tray.add-rule.moved", "Rule moved: {value} → {route}")
        return template.replace("{value}", String(row.matchValue))
            .replace("{route}", routeLabel(String(row.targetRoute)))
    }

    function _failed(r) {
        var reason = String((r && r.reason) || "")
        var submitter = trayHost.rulesSubmitter
        if (reason === "unexpected-diff") {
            _fail("changed-elsewhere", tr("tray.add-rule.changed-elsewhere",
                "Your rules were changed elsewhere in the meantime, so nothing was added. Open the main window and add the rule there."))
            return
        }
        _fail("error", typeof submitter.describeFailure === "function"
            ? submitter.describeFailure(r, tr) : String(reason))
    }

    /// Said here, or as a tray notice when the user already closed the window.
    function _fail(state, message) {
        if (!visible) {
            _state = ""
            trayHost.noteAddRuleOutcome(message)
            _releaseIfIdle()
            return
        }
        _setState(state, message)
    }
}
