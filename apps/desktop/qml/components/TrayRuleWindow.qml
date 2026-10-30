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
    /// The rule the form edits, as the main window keeps it; the tray's form
    /// only ever adds, so nothing reads it here.
    property string editingRuleKey: ""
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
    function routeChoiceLabel(role) {
        return Rules.routeChoiceLabel(role, trayHost.routePrimaryLabel,
            trayHost.routeSecondaryLabel, tr)
    }
    function routeRoleOptions() { return Rules.routeRoleOptions(true, routeChoiceLabel, tr) }
    function ruleTypeLabel(id) { return support.ruleTypeLabel(id) }
    function ruleTypeChoiceLabel(id) { return support.ruleTypeChoiceLabel(id) }
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
    /// The service counts its own limit; the form marks nothing over it here.
    function bulkRuleRoom() { return -1 }
    /// A pasted list of rules: its new rules and the moves the user ticked go
    /// to the service in one apply. The plan on screen was made against the
    /// rules read when the form opened, so `_submitBulk` plans it again.
    function saveBulkRules(plan) {
        _submitBulk()
    }
    /// The adds and the moves of a bulk `plan` as table rows.
    function _bulkItems(plan) {
        var adds = []
        var moves = []
        var rows = (plan && plan.rows) || []
        var nextId = parseInt(Rules.nextFreeRuleId(_rows).substring(2), 10)
        for (var i = 0; i < rows.length; i += 1) {
            var r = rows[i]
            if (r.action !== "add" && r.action !== "move") continue
            var item = support.ruleRowFromForm({ ruleType: r.type, value: r.value, route: r.route,
                verify: r.verify, comment: r.comment, enabled: r.enabled },
                Rules.sequentialRuleId(nextId - 1 + adds.length))
            // A line of an `--- Auto` section stays app-authored, as an import keeps it.
            item.originReason = String(r.originReason || "")
            item.originAnchor = String(r.originAnchor || "")
            item.originAdded = String(r.originAdded || "")
            if (r.action === "add") adds.push(item)
            else moves.push(item)
        }
        return { adds: adds, moves: moves }
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
    // "" while the form is up; "busy", "duplicate", "elsewhere", "error",
    // "alert-gate" or "changed-elsewhere" while this pane stands in for it.
    property string _state: ""
    property string _message: ""
    /// Rules waiting for the user's answer to "change the existing rule?".
    property var _pendingItems: []
    /// The answer's button, worded for a move, a deny or a lifted deny.
    property string _moveLabel: ""
    /// The service's rules as table rows, read on open and again on save.
    property var _rows: []
    /// What a pasted list left in the form, put back once the rest is applied.
    property string _bulkRemaining: ""

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
            textFormat: Text.PlainText
            text: trayRuleWindow._message
            color: trayRuleWindow._state === "error" || trayRuleWindow._state === "changed-elsewhere"
                    || trayRuleWindow._state === "alert-gate"
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
                text: trayRuleWindow._moveLabel
                onClicked: trayRuleWindow._submit(trayRuleWindow._pendingItems, true)
                Accessible.name: text
            }
            ThemedButton {
                visible: trayRuleWindow._state === "alert-gate"
                theme: trayRuleWindow.uiTheme
                highlighted: true
                text: trayRuleWindow.tr("action.open-security-alert", "Open the alert")
                onClicked: {
                    trayRuleWindow.trayHost.openSecurityAlerts()
                    trayRuleWindow._closeSoon()
                }
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

    /// `present()` with the form already holding a rule for `host` on `route`.
    function presentFor(host, route) {
        var fresh = !visible && _state !== "busy"
        present()
        if (fresh) ruleDialog.resetForNewOnRoute("domain", host, route)
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
        _bulkRemaining = ""
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
            // The rule is added to exactly these rules, or not at all.
            var submitter = trayRuleWindow.trayHost ? trayRuleWindow.trayHost.rulesSubmitter : null
            if (submitter) {
                submitter.baseRevision = (payload["base-revision"] !== undefined
                    && payload["base-revision"] !== null) ? String(payload["base-revision"]) : null
            }
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
                trayRuleWindow._moveLabel = trayRuleWindow._moveText(plan.elsewhere)
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

    /// The pasted list planned against the rules read again now
    /// (`Rules.planBulkSubmission`) and sent as one rule book. A move whose
    /// rule is gone is added instead; a line whose value has since appeared on
    /// another route goes back into the form with the form's reason.
    function _submitBulk() {
        _pendingItems = []
        _bulkRemaining = ""
        _setState("busy", tr("tray.add-rule.saving", "Adding the rule\u2026"))
        _loadRows(function(ok) {
            if (!ok) {
                trayRuleWindow._fail("error", tr("tray.add-rule.load-failed",
                    "Could not read your rules from the service, so nothing was added. Check that the service is running."))
                return
            }
            var fresh = Rules.planBulkSubmission(ruleDialog.bulkPlanInput(), trayRuleWindow._rows)
            trayRuleWindow._bulkRemaining = String(fresh.remaining || "")
            var items = trayRuleWindow._bulkItems(fresh)
            var first = Rules.planRuleAddition(trayRuleWindow._rows, items.adds, false)
            var second = Rules.planRuleAddition(first.rows, items.moves, true)
            var plan = {
                rows: second.rows,
                added: first.added + second.added,
                changed: second.changed,
                addedRows: first.addedRows.concat(second.addedRows),
                movedRows: second.movedRows,
                duplicates: first.duplicates.concat(second.duplicates),
                elsewhere: second.elsewhere,
                bulk: true
            }
            if (plan.added === 0 && plan.changed === 0) {
                if (trayRuleWindow._giveBackRemaining()) return
                trayRuleWindow._setState("duplicate",
                    tr("dialog.rule.duplicate-title", "Rule already exists"))
                return
            }
            trayRuleWindow._send(plan)
        })
    }

    /// The lines a pasted list did not take, back in the form, which shows why
    /// for each. Shown again if the user closed it meanwhile: they are the
    /// user's typing, not to be dropped. False when there were none.
    function _giveBackRemaining() {
        var remaining = _bulkRemaining
        _bulkRemaining = ""
        if (remaining === "") return false
        _state = ""
        _message = ""
        ruleDialog.resumeBulk(remaining)
        if (!visible) {
            show()
            raise()
            requestActivate()
        }
        ruleDialog.open()
        return true
    }

    // A deny is not a route: the messages below say "denied" where the
    // existing or the chosen rule is one, and name a route only where it is.
    function _deniedCount(elsewhere) {
        var n = 0
        for (var i = 0; i < elsewhere.length; i += 1) {
            if (String(elsewhere[i].row.targetRoute) === "block") n += 1
        }
        return n
    }

    function _elsewhereText(elsewhere) {
        var denied = _deniedCount(elsewhere)
        if (elsewhere.length === 1) {
            var row = elsewhere[0].row
            var one = denied > 0
                ? tr("tray.add-rule.already-denied", "{value} is already denied in your rules.")
                : tr("tray.add-rule.on-other-route",
                    "{value} is already in your rules, on the connection {route}.")
            return one.replace("{value}", Pure.displayText(row.matchValue))
                .replace("{route}", routeLabel(String(row.targetRoute)))
        }
        var many = String(elsewhere[0].item.targetRoute) === "block"
            ? tr("tray.add-rule.on-a-route-many",
                "{count} of these are already in your rules, on one of the connections.")
            : denied === elsewhere.length
            ? tr("tray.add-rule.already-denied-many",
                "{count} of these are already denied in your rules.")
            : denied > 0
            ? tr("tray.add-rule.on-other-route-or-denied-many",
                "{count} of these are already in your rules, on the other connection or denied.")
            : tr("tray.add-rule.on-other-route-many",
                "{count} of these are already in your rules, on the other connection.")
        return many.replace("{count}", String(elsewhere.length))
    }

    function _moveText(elsewhere) {
        if (String(elsewhere[0].item.targetRoute) === "block")
            return tr("tray.add-rule.deny-instead", "Deny instead")
        if (_deniedCount(elsewhere) === elsewhere.length)
            return tr("tray.add-rule.lift-deny", "Lift the deny, use this connection")
        return tr("tray.add-rule.move", "Move to this connection")
    }

    function _send(plan) {
        var json = ""
        var refusal = ""
        try {
            json = Rules.buildRulesJson(plan.rows, support.aceCodec.encode)
        } catch (err) {
            console.error("tray add-rule: rules serialization failed:", err)
            refusal = Rules.wireRefusalCode(err)
        }
        var submitter = trayHost.rulesSubmitter
        if (!json || !submitter || typeof submitter.applyNow !== "function") {
            _fail("error", refusal !== "" ? Pure.ipcErrorLabel(refusal, null, tr)
                : tr("status.rules-serialize-failed",
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
        trayHost.noteAddRuleOutcome(plan.bulk === true ? _bulkOutcomeText(plan) : _outcomeText(plan),
            Rules.additionUndoRecord(plan), _awaitsConfirmation(plan))
        _state = ""
        // Lines a pasted list left behind come back into the form to be fixed.
        if (plan.bulk === true && _giveBackRemaining()) return
        _closeSoon()
        _releaseIfIdle()
    }

    function _bulkOutcomeText(plan) {
        var parts = [tr("status.rules-list-added", "Rules added: {count}.")
            .replace("{count}", String(plan.added))]
        if (plan.changed > 0) {
            parts.push(tr("status.rules-list-moved", "Moved to the chosen connection: {count}.")
                .replace("{count}", String(plan.changed)))
        }
        return parts.join(" ")
    }

    /// A program added with `+override` is held by the protection of system
    /// programs until the user confirms it in the window's rules list.
    function _awaitsConfirmation(plan) {
        var rows = plan.addedRows || []
        for (var i = 0; i < rows.length; i += 1) {
            if (rows[i].enabled !== false
                    && Rules.ruleValueAsksOverride(rows[i].ruleType, rows[i].matchValue))
                return true
        }
        return false
    }

    function _outcomeText(plan) {
        var row = plan.added > 0 ? plan.addedRows[0] : plan.movedRows[0]
        var route = String(row.targetRoute)
        var toDeny = route === "block"
        // A confirmed move moved every `elsewhere` row; the denies among them are lifted.
        var lifted = toDeny ? 0 : _deniedCount(plan.elsewhere)
        if (plan.added + plan.changed > 1) {
            var parts = []
            if (plan.added > 0) {
                parts.push((toDeny
                    ? tr("tray.add-rule.added-deny-many", "Deny rules added: {count}.")
                    : tr("status.rules-list-added", "Rules added: {count}."))
                    .replace("{count}", String(plan.added)))
            }
            if (toDeny && plan.changed > 0) {
                parts.push(tr("tray.add-rule.now-denied-count", "Now denied: {count}.")
                    .replace("{count}", String(plan.changed)))
            }
            if (!toDeny && plan.changed - lifted > 0) {
                parts.push(tr("tray.add-rule.moved-count", "Moved to this connection: {count}.")
                    .replace("{count}", String(plan.changed - lifted)))
            }
            if (lifted > 0) {
                parts.push(tr("tray.add-rule.deny-lifted-count",
                        "Deny lifted, now over {route}: {count}.")
                    .replace("{route}", routeLabel(route))
                    .replace("{count}", String(lifted)))
            }
            return parts.join(" ")
        }
        var template
        if (plan.added > 0 && row.enabled === false) {
            template = toDeny
                ? tr("tray.add-rule.added-deny-disabled",
                    "Rule added, switched off: deny {value}. It does not deny anything until you switch it on.")
                : tr("tray.add-rule.added-disabled",
                    "Rule added, switched off: {value} → {route}. It does not route anything until you switch it on.")
        } else if (plan.added > 0) {
            template = toDeny
                ? tr("tray.add-rule.added-deny", "Rule added: {value} denied.")
                : _awaitsConfirmation(plan)
                ? tr("tray.add-rule.added-awaits-confirmation",
                    "Rule added: {value} → {route}. Not in use yet: it touches a protected system program — confirm it in the rules list.")
                : tr("tray.add-rule.added", "Rule added: {value} → {route}")
        } else {
            template = toDeny
                ? tr("tray.add-rule.moved-deny", "Rule changed: {value} is now denied.")
                : lifted > 0
                ? tr("tray.add-rule.deny-lifted", "Deny lifted: {value} → {route}")
                : tr("tray.add-rule.moved", "Rule moved: {value} → {route}")
        }
        return template.replace("{value}", String(row.matchValue))
            .replace("{route}", routeLabel(route))
    }

    function _failed(r) {
        var reason = String((r && r.reason) || "")
        var submitter = trayHost.rulesSubmitter
        if (reason === "unexpected-diff") {
            _fail("changed-elsewhere", tr("tray.add-rule.changed-elsewhere",
                "Your rules were changed elsewhere in the meantime, so nothing was added. Open the main window and add the rule there."))
            return
        }
        var gate = trayHost.rpc ? trayHost.rpc.securityAlertGateCode : ""
        var refusedByGate = gate !== "" && r
            && (String(r.code || "") === gate || String(r.failure || "") === gate)
        _fail(refusedByGate ? "alert-gate" : "error", typeof submitter.describeFailure === "function"
            ? submitter.describeFailure(r, tr) : String(reason))
    }

    /// Take back the add `record` describes (`Rules.additionUndoRecord`), as
    /// one more ordinary apply: a rule it added leaves, a rule it moved goes
    /// back. A rule changed since is left alone and the user is told.
    function undoAddition(record) {
        if (_state === "busy") return
        _setState("busy", tr("tray.add-rule.undoing", "Undoing\u2026"))
        _loadRows(function(ok) {
            if (!ok) {
                trayRuleWindow._undoDone(tr("tray.add-rule.undo-load-failed",
                    "Could not read your rules from the service, so nothing was undone. Check that the service is running."))
                return
            }
            var plan = Rules.planAdditionUndo(trayRuleWindow._rows, record)
            if (plan.conflict) {
                trayRuleWindow._undoDone(tr("tray.add-rule.undo-changed",
                    "The rule has been changed since, so nothing was undone."))
                return
            }
            var json = ""
            var refusal = ""
            try {
                json = Rules.buildRulesJson(plan.rows, support.aceCodec.encode)
            } catch (err) {
                console.error("tray add-rule undo: rules serialization failed:", err)
                refusal = Rules.wireRefusalCode(err)
            }
            var submitter = trayRuleWindow.trayHost.rulesSubmitter
            if (!json || !submitter || typeof submitter.applyNow !== "function") {
                trayRuleWindow._undoDone(refusal !== ""
                    ? Pure.ipcErrorLabel(refusal, null, trayRuleWindow.tr)
                    : tr("status.rules-serialize-failed",
                        "Internal error while preparing rules \u2014 see logs"))
                return
            }
            submitter.applyNow(json, "tray-add-rule-undo",
                { added: 0, removed: plan.removed, changed: plan.restored },
                function(applied, r) {
                    if (applied) {
                        for (var c = 0; c < plan.comments.length; c += 1)
                            support.writeComment(plan.comments[c])
                        trayRuleWindow.trayHost.boundFileWriter.mirrorServiceIntoFiles()
                        trayRuleWindow._undoDone(tr("tray.add-rule.undone", "Undone: the rules are as they were."))
                    } else if (String((r && r.reason) || "") === "unexpected-diff") {
                        trayRuleWindow._undoDone(tr("tray.add-rule.undo-changed",
                            "The rule has been changed since, so nothing was undone."))
                    } else {
                        trayRuleWindow._undoDone(typeof submitter.describeFailure === "function"
                            ? submitter.describeFailure(r, tr) : String((r && r.reason) || ""))
                    }
                })
        })
    }

    function _undoDone(message) {
        _state = ""
        _message = ""
        trayHost.noteAddRuleOutcome(message, null)
        if (visible) ruleDialog.open()
        _releaseIfIdle()
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
