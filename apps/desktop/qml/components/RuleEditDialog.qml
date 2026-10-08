import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

// Add / Edit rule dialog (extracted from Main.qml).
//
// The dialog keeps its `ruleDialog` id so Main.qml's wiring — the
// `property alias ruleDialog`, the overlays array, and the RulesSection calls
// through `root.ruleDialog.{resetForEdit,open}` — is
// unchanged. All shared state (models, theme, window helpers such as
// `saveRule`, `ruleTypeLabel`, `routeRoleOptions`, `comboPopupWidth`,
// `_punycodeFor`, `platformProfile`) comes in through `root` (the
// ApplicationWindow). The dialog's own fields and validators stay local.
Dialog {
    id: ruleDialog

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    // Placed once per opening instead of bound to the centre: hints appear and
    // disappear as the user types, and a live centre binding walked the whole
    // dialog up and down under their pointer on every keystroke.
    width: 560
    onAboutToShow: {
        ruleDialog._settled = false
        ruleDialog._centreInWindow()
    }
    onOpened: Qt.callLater(function() {
        ruleDialog._centreInWindow()
        ruleDialog._settled = true
    })
    // Growth after that is absorbed downward; the dialog moves again only when
    // it would otherwise hang past the window's bottom edge.
    onHeightChanged: {
        if (!visible) return
        if (ruleDialog._settled) ruleDialog._keepInsideWindow()
        else ruleDialog._centreInWindow()
    }
    /// False until the dialog has been laid out with its real content height.
    property bool _settled: false
    /// Clearance kept between the dialog and the window edge.
    readonly property int _edgeGap: 12
    function _centreInWindow() {
        if (!root) return
        x = Math.round(Math.max(0, (root.width - width) / 2))
        y = Math.round(Math.max(0, (root.height - height) / 2))
    }
    function _keepInsideWindow() {
        if (!root) return
        var maxY = Math.max(0, root.height - height - ruleDialog._edgeGap)
        if (y > maxY) y = Math.round(maxY)
    }
    modal: false
    palette: root.palette
    title: root.editingRule >= 0 ? root.tr("dialog.rule.edit", "Edit") : root.tr("dialog.rule.add", "Add")
    // Own buttons, not Dialog.Ok|Cancel: Qt's standard set carries Qt's own
    // translations, so a Russian UI showed English "OK" / "Cancel".
    standardButtons: Dialog.NoButton
    // The buttons belong to the footer, not to the content column: content
    // anchored to fill its parent adds nothing to the dialog's implicit
    // height, so a button row placed there hangs below the dialog's edge.
    footer: Item {
        implicitHeight: buttonRow.implicitHeight + 2 * root.uiTheme.spacingMd
        RowLayout {
            id: buttonRow
            anchors.fill: parent
            anchors.margins: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.ok", "OK")
                // App rules ARE saveable now — they route the app's observed
                // destinations via the secondary (app-routing via observation).
                enabled: ruleDialog.listMode
                    ? ruleDialog.acceptedListRows.length > 0
                    : ruleDialog.isMatchValueValid(ruleDialog.localRuleType,
                        ruleDialog.localValue)
                onClicked: ruleDialog.accept()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.cancel", "Cancel")
                onClicked: ruleDialog.reject()
            }
        }
    }
    // Local fields are reset imperatively from `resetForEdit()` each time
    // the dialog is opened. We deliberately don't use declarative bindings
    // to `rulesModel.get(editingRule)` because the user's edits assign to
    // these properties via `onTextChanged`, which breaks the binding —
    // after the first interaction stale values would persist into the
    // next Add/Edit invocation.
    property string localRuleType: ""
    property string localValue: ""
    property string localRoute: "primary"
    property string localComment: ""
    // Enabled toggle in Add/Edit dialog. Default
    // true on Add; carries existing state on Edit.
    property bool localEnabled: true
    // Grandfather flag: `block` is no longer an offerable route for new
    // Free rules (it was removed). When Edit opens on a pre-existing block
    // rule we keep the option in the target-route combo so saving doesn't
    // silently downgrade it to `primary`. Latched in resetForEdit(), so the
    // combo model stays stable for the whole dialog session.
    property bool allowBlockRoute: false
    // "Primary first" is offered only for name rules; the combo model follows
    // the type, and a type that cannot carry it moves the route to secondary.
    readonly property bool verifyRouteOffered: Rules.ruleTypeAllowsVerify(localRuleType)
    // The one handler for this signal: QML refuses a second one and the whole
    // dialog — and with it the main window — then fails to load.
    onLocalRuleTypeChanged: {
        var fitted = Rules.routeForRuleType(localRoute, localRuleType)
        if (fitted !== localRoute) localRoute = fitted
        _requestVerdict()
    }
    onLocalRouteChanged: _syncRouteCombo()
    // User input severs the combo's index binding, so it is kept in step by hand.
    function _syncRouteCombo() {
        if (!routeTargetCombo || !root) return
        var roleOpts = root.routeRoleOptions(allowBlockRoute, verifyRouteOffered)
        var rIdx = 0
        for (var i = 0; i < roleOpts.length; i += 1) {
            if (roleOpts[i].id === localRoute) { rIdx = i; break }
        }
        routeTargetCombo.currentIndex = rIdx
    }
    // First rule type that can actually be added today. `application`
    // is excluded (per-process routing not implemented yet) so a fresh
    // Add form never defaults to a non-functional type.
    function firstAddableRuleType() {
        // Default a fresh Add form to the "domain" type — it's the most
        // common rule users add (a hostname like example.com). Fall back
        // to the first non-application type if the backend doesn't expose
        // "domain", then to the first type, then to a hard default.
        for (var d = 0; d < root.ruleTypesModel.count; d += 1) {
            if (root.ruleTypesModel.get(d).id === "domain") return "domain"
        }
        for (var i = 0; i < root.ruleTypesModel.count; i += 1) {
            if (root.ruleTypesModel.get(i).id !== "application") return root.ruleTypesModel.get(i).id
        }
        return root.ruleTypesModel.count > 0 ? root.ruleTypesModel.get(0).id : "exact-ip"
    }
    // Prefill a NEW rule from elsewhere in the app (today: a row in the
    // connection trace). Falls back to the dialog's own default type when the
    // requested one is not offered on this platform, so the user still lands on
    // a usable form instead of a blank one.
    function resetForNew(ruleType, value) {
        root.editingRule = -1
        resetForEdit()
        var wanted = String(ruleType || "")
        for (var i = 0; i < root.ruleTypesModel.count; i += 1) {
            if (root.ruleTypesModel.get(i).id === wanted) {
                localRuleType = wanted
                break
            }
        }
        localValue = String(value || "")
        // Same reason as resetForEdit: user input severs the bindings, so the
        // visible widgets are assigned directly.
        if (matchValueField) matchValueField.text = localValue
        if (ruleTypeCombo) {
            var idx = 0
            for (var k = 0; k < root.ruleTypesModel.count; k += 1) {
                if (root.ruleTypesModel.get(k).id === localRuleType) { idx = k; break }
            }
            ruleTypeCombo.currentIndex = idx
        }
    }
    function resetForEdit() {
        if (root.editingRule >= 0 && root.editingRule < root.rulesModel.count) {
            var r = root.rulesModel.get(root.editingRule)
            localRuleType = String(r.ruleType || (root.ruleTypesModel.count > 0 ? root.ruleTypesModel.get(0).id : "application"))
            localValue = String(r.matchValue || "")
            localRoute = String(r.targetRoute || "primary")
            localComment = String(r.comment || "")
            localEnabled = (r.enabled === undefined) ? true : !!r.enabled
            allowBlockRoute = (String(r.targetRoute || "") === "block")
        } else {
            localRuleType = firstAddableRuleType()
            localValue = ""
            localRoute = "primary"
            localComment = ""
            localEnabled = true
            allowBlockRoute = false
        }
        listMode = false
        listText = ""
        if (listInput) listInput.text = ""
        if (listModeCheck) listModeCheck.checked = false
        // Sync visible widgets to fresh local state. Bindings on `text` /
        // `currentIndex` / `checked` are broken by user input, so do this
        // directly.
        if (matchValueField) matchValueField.text = localValue
        if (ruleCommentField) ruleCommentField.text = localComment
        // The enable toggle was the one control missing from this list. A user
        // click assigns `checked` on the CheckBox itself, which severs the
        // binding to `localEnabled` — without this line a box cleared in one
        // dialog session came back cleared on the next Add, and the rule was
        // saved disabled without the user ever choosing that.
        if (ruleEnabledCheck) ruleEnabledCheck.checked = localEnabled
        if (ruleTypeCombo) {
            var tIdx = 0
            for (var k = 0; k < root.ruleTypesModel.count; k += 1) {
                if (root.ruleTypesModel.get(k).id === localRuleType) { tIdx = k; break }
            }
            ruleTypeCombo.currentIndex = tIdx
        }
        _syncRouteCombo()
    }
    // Copy of `nrr_domain::preset_validation::MAX_INLINE_COMMENT_CHARS`, which
    // rejects a longer comment on import. QML cannot read Rust constants, so
    // `core/domain/tests/inline_comment_limit.rs` holds this literal to it.
    readonly property int commentMaxLength: 200

    // Match-value placeholder + hint depend on rule type. For
    // `application` the hint is platform-specific because the runtime
    // matcher is platform-specific (Windows .exe / Linux process name /
    // macOS bundle id). The QML host is currently Windows-only, but the
    // chooser is wired so the same dialog can run on Linux/macOS once
    // the runtime platforms are added.
    function applicationPlatformKey() {
        if (root.platformProfile.os === "linux") return "application-linux"
        if (root.platformProfile.os === "macos") return "application-macos"
        return "application-windows"
    }
    /// One sentence naming the hosts the rule on screen will match, with the
    /// machine-wide subdomain setting folded in.
    function _coverageHint() {
        var v = String(localValue || "")
        var bare = v.indexOf("*.") === 0 ? v.substring(2) : v
        if (v.indexOf("*.") === 0 || root.prefs.routeIncludeSubdomains !== false) {
            return root.tr("dialog.rule.coverage-with-subdomains",
                "Covers {host} and every subdomain of it.").replace("{host}", bare)
        }
        return root.tr("dialog.rule.coverage-exact-only",
            "Covers {host} only. Type *.{host} to include its subdomains.")
            .replace(/\{host\}/g, bare)
    }

    function matchValueKeySuffix(ruleType) {
        if (ruleType === "application") return applicationPlatformKey()
        return ruleType
    }
    function matchValuePlaceholder(ruleType) {
        var suffix = matchValueKeySuffix(ruleType)
        return root.tr("rules.placeholder." + suffix, "")
    }
    function matchValueHint(ruleType) {
        var suffix = matchValueKeySuffix(ruleType)
        return root.tr("rules.hint." + suffix, "")
    }
    // Permissive partial-match regexes so that the validator allows
    // every intermediate keystroke (otherwise the user can't type the
    // first character — Qt rejects partial input as Invalid). Length
    // ceilings are enforced separately via `maximumLength`; whether the
    // value can be saved is `isMatchValueValid()`.
    //
    // - `exact-ip` accepts hex digits, dots and colons up to 45 chars, the
    //   longest IPv6 text form; `subnet` adds `/` and a prefix, `ip-range` a
    //   `-` and a second address, spaces around it allowed.
    // - the rest cap the length only: `\p{L}` / `\u…` ranges silently block
    //   Cyrillic input on some Qt builds.
    function matchValueRegex(ruleType) {
        if (ruleType === "exact-ip") {
            return new RegExp("^[0-9A-Fa-f.:]{0,45}$")
        }
        if (ruleType === "subnet") return new RegExp("^[0-9A-Fa-f.:/ ]{0,51}$")
        if (ruleType === "ip-range") return new RegExp("^[0-9A-Fa-f.: -]{0,93}$")
        if (ruleType === "zone" || ruleType === "domain") return new RegExp("^.{0,253}$")
        if (ruleType === "application") return new RegExp("^.{0,260}$")
        return new RegExp("^.*$")
    }
    function matchValueMaxLength(ruleType) {
        if (ruleType === "zone" || ruleType === "domain") return 253
        if (ruleType === "exact-ip")    return 45
        if (ruleType === "subnet")      return 51
        if (ruleType === "ip-range")    return 93
        if (ruleType === "application") return 260
        return 260
    }
    /// The address types a pasted list is sorted into.
    function isAddressRuleType(ruleType) {
        return ruleType === "exact-ip" || ruleType === "subnet" || ruleType === "ip-range"
    }
    // The verdict on the value on screen, asked of the launcher: the one the
    // rules table shows, which for a zone or domain is the service's own
    // import pipeline. `key` names the value it answers, so the answer to an
    // earlier keystroke never gates a later one.
    property var _verdict: ({ key: "", status: "", messageKey: "", args: ({}) })
    function _verdictKey(ruleType, raw) {
        return String(ruleType || "") + "|" + String(raw || "").trim()
    }
    function _requestVerdict() {
        var type = localRuleType
        var value = String(localValue || "").trim()
        if (value === "" || !root.rpc || !root.rpc.bridgeAvailable
                || typeof root.rpc.bridge.rpcRuleValueVerdict !== "function") {
            return
        }
        var key = _verdictKey(type, value)
        var corr = root.rpc.bridge.rpcRuleValueVerdict(type, value)
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("local.rule-value-verdict failed:", code, msg)
                return
            }
            ruleDialog._verdict = {
                key: key,
                status: String((payload && payload.status) || ""),
                messageKey: String((payload && payload["message-key"]) || ""),
                args: (payload && payload.args) || ({})
            }
        })
    }
    onLocalValueChanged: _requestVerdict()
    function _verdictFor(ruleType, raw) {
        return _verdict.key === _verdictKey(ruleType, raw) ? _verdict : null
    }
    // No answer yet counts as not saveable: OK waits for the verdict.
    function isMatchValueValid(ruleType, raw) {
        if (String(raw || "").trim() === "") return false
        var verdict = _verdictFor(ruleType, raw)
        return verdict !== null && verdict.status !== "error"
    }
    function isMatchValueRefused(ruleType, raw) {
        var verdict = _verdictFor(ruleType, raw)
        return verdict !== null && verdict.status === "error"
    }
    function isMatchValueWarned(ruleType, raw) {
        var verdict = _verdictFor(ruleType, raw)
        return verdict !== null && verdict.status === "warning"
    }
    /// A verdict's message in the rules table's words, `{name}` args filled in.
    function verdictMessage(messageKey, args, fallback) {
        if (String(messageKey || "") === "") return fallback
        var msg = root.tr(messageKey, fallback)
        for (var k in (args || {})) {
            msg = msg.split("{" + k + "}").join(String(args[k]))
        }
        return msg
    }
    function refusalText() {
        var fallback = root.tr("rules.validation.error", "Error — rule is inactive")
        var verdict = _verdictFor(localRuleType, localValue)
        return verdict === null ? fallback
            : verdictMessage(verdict.messageKey, verdict.args, fallback)
    }
    function warningText() {
        var verdict = _verdictFor(localRuleType, localValue)
        return verdict === null ? ""
            : verdictMessage(verdict.messageKey, verdict.args,
                root.tr("rules.validation.warning", "Warning"))
    }

    // ── A pasted list of addresses, subnets and ranges ──
    // Rust sorts each line into its type and judges it as that type
    // (`local.rule-values-classify`); the dialog only shows the answer.
    property bool listMode: false
    property string listText: ""
    property var _listAnswer: ({ text: "", rows: [], truncated: false })
    readonly property bool listAvailable: !!root && !!root.rpc && root.rpc.bridgeAvailable
        && typeof root.rpc.bridge.rpcRuleValuesClassify === "function"
    readonly property var listRows: _listAnswer.text === listText.trim() ? _listAnswer.rows : []
    readonly property var acceptedListRows: {
        var out = []
        for (var i = 0; i < listRows.length; i += 1) {
            if (String(listRows[i].status) !== "error") out.push(listRows[i])
        }
        return out
    }
    function _requestListClassification() {
        var text = listText.trim()
        if (text === "" || !listAvailable) {
            _listAnswer = { text: text, rows: [], truncated: false }
            return
        }
        var corr = root.rpc.bridge.rpcRuleValuesClassify(text)
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("local.rule-values-classify failed:", code, msg)
                return
            }
            ruleDialog._listAnswer = {
                text: text,
                rows: (payload && payload.rows) || [],
                truncated: !!(payload && payload.truncated)
            }
        })
    }
    // Typing a long list must not ask once per keystroke.
    Timer {
        id: listClassifyTimer
        interval: 200
        repeat: false
        onTriggered: ruleDialog._requestListClassification()
    }
    onListTextChanged: listClassifyTimer.restart()
    function listRowText(row) {
        var status = String(row.status || "")
        if (status === "valid") return root.ruleTypeLabel(String(row["rule-type"]))
        var fallback = status === "error"
            ? root.tr("rules.validation.error", "Error — rule is inactive")
            : root.tr("rules.validation.warning", "Warning")
        var message = verdictMessage(row["message-key"], row.args, fallback)
        if (status === "error") return message
        return root.ruleTypeLabel(String(row["rule-type"])) + " — " + message
    }
    function listSummaryText() {
        var text = root.tr("rules.paste.summary", "To add: {accepted}. Not added: {rejected}.")
            .replace("{accepted}", String(acceptedListRows.length))
            .replace("{rejected}", String(listRows.length - acceptedListRows.length))
        if (_listAnswer.truncated && listRows.length > 0) {
            text += " " + root.tr("rules.paste.truncated",
                "Only the first {count} lines were read.")
                .replace("{count}", String(listRows.length))
        }
        return text
    }

    onAccepted: {
        if (listMode) {
            if (acceptedListRows.length === 0) {
                open()
                return
            }
            root.saveRuleList(acceptedListRows)
            return
        }
        if (!isMatchValueValid(localRuleType, localValue)) {
            // Enter-key submission of a value that cannot be saved (yet):
            // stay on the form, where OK is disabled.
            open()
            return
        }
        root.saveRule()
    }
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingMd
        spacing: root.uiTheme.spacingSm
        Label { text: root.tr("label.rule-type", "Rule type"); color: root.textColor }
        ThemedComboBox {
            id: ruleTypeCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: root.ruleTypesModel
            textRole: "id"
            valueRole: "id"
            labelResolver: function(item) { return item ? root.ruleTypeLabel(item.id) : "" }
            displayText: root.uiRevision >= 0 && currentIndex >= 0 && currentIndex < root.ruleTypesModel.count
                ? root.ruleTypeLabel(root.ruleTypesModel.get(currentIndex).id) : ""
            popup.width: root.comboPopupWidth(ruleTypeCombo, root.ruleTypesModel, "id", function(item) { return root.ruleTypeLabel(item.id) })
            // A pasted list takes each line's type from the line itself.
            enabled: !ruleDialog.listMode
            onActivated: ruleDialog.localRuleType = root.ruleTypesModel.get(currentIndex).id
            // All rule types are selectable. `application` routes the app's
            // OBSERVED destinations via the secondary (app-routing via
            // observation); the Add form still defaults to "domain".
            delegate: ItemDelegate {
                width: ListView.view ? ListView.view.width : ruleTypeCombo.popup.width
                highlighted: ruleTypeCombo.highlightedIndex === index
                background: Rectangle {
                    color: highlighted ? root.uiTheme.colorAccent : root.uiTheme.colorPanel
                    border.width: root.uiTheme.borderWidth
                    border.color: root.uiTheme.stateDefaultBorder
                }
                contentItem: Text {
                    leftPadding: root.uiTheme.spacingSm
                    rightPadding: root.uiTheme.spacingSm
                    text: root.ruleTypeLabel(model.id)
                    color: !enabled
                               ? Qt.rgba(root.uiTheme.colorText.r, root.uiTheme.colorText.g,
                                         root.uiTheme.colorText.b, 0.45)
                               : (highlighted ? root.uiTheme.colorOnAccent : root.uiTheme.colorText)
                    verticalAlignment: Text.AlignVCenter
                    elide: Text.ElideRight
                }
            }
        }
        CheckBox {
            id: listModeCheck
            visible: root.editingRule < 0 && ruleDialog.listAvailable
                && ruleDialog.isAddressRuleType(ruleDialog.localRuleType)
            checked: ruleDialog.listMode
            text: root.uiRevision >= 0
                ? root.tr("rules.paste.toggle", "Add a list of addresses, subnets and ranges")
                : ""
            onToggled: {
                ruleDialog.listMode = checked
                if (checked) listInput.forceActiveFocus()
            }
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
        }
        Label {
            visible: ruleDialog.listMode
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.WordWrap
            color: root.textColor
            text: root.uiRevision >= 0
                ? root.tr("rules.paste.label",
                    "One entry per line. Addresses, subnets and ranges can be mixed: each is added as its own type.")
                : ""
        }
        ScrollView {
            id: listInputScroll
            visible: ruleDialog.listMode
            Layout.fillWidth: true
            Layout.preferredHeight: 120
            clip: true
            ThemedTextArea {
                id: listInput
                theme: root.uiTheme
                wrapMode: TextArea.NoWrap
                placeholderText: root.uiRevision >= 0
                    ? root.tr("rules.placeholder.address-list",
                        "192.0.2.10, 198.51.100.0/24, 203.0.113.5-203.0.113.40")
                    : ""
                onTextChanged: ruleDialog.listText = text
                // Tab leaves the field, as in every other control of the form.
                Keys.onTabPressed: function(event) {
                    var next = listInput.nextItemInFocusChain(true)
                    if (next) next.forceActiveFocus(Qt.TabFocusReason)
                    event.accepted = true
                }
                Keys.onBacktabPressed: function(event) {
                    var prev = listInput.nextItemInFocusChain(false)
                    if (prev) prev.forceActiveFocus(Qt.BacktabFocusReason)
                    event.accepted = true
                }
                Accessible.role: Accessible.EditableText
                Accessible.name: listModeCheck.text
                Accessible.description: root.uiRevision >= 0
                    ? root.tr("rules.paste.label",
                        "One entry per line. Addresses, subnets and ranges can be mixed: each is added as its own type.")
                    : ""
            }
        }
        Label {
            id: listSummary
            visible: ruleDialog.listMode && ruleDialog.listRows.length > 0
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.WordWrap
            color: root.textColor
            text: root.uiRevision >= 0 ? ruleDialog.listSummaryText() : ""
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        ScrollView {
            id: listPreview
            visible: listSummary.visible
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(160, listPreviewColumn.implicitHeight)
            clip: true
            contentWidth: availableWidth
            ColumnLayout {
                id: listPreviewColumn
                width: listPreview.availableWidth
                spacing: 2
                Repeater {
                    model: ruleDialog.listRows
                    delegate: RowLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm
                        Label {
                            Layout.preferredWidth: 200
                            Layout.alignment: Qt.AlignTop
                            elide: Text.ElideMiddle
                            color: root.textColor
                            text: String(modelData.value)
                        }
                        Label {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 0
                            wrapMode: Text.WordWrap
                            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            color: String(modelData.status) === "error" ? root.uiTheme.colorDanger
                                : String(modelData.status) === "warning" ? root.uiTheme.colorWarning
                                : root.mutedTextColor
                            text: root.uiRevision >= 0 ? ruleDialog.listRowText(modelData) : ""
                            Accessible.role: Accessible.StaticText
                            Accessible.name: String(modelData.value) + ": " + text
                        }
                    }
                }
            }
        }
        Label {
            visible: !ruleDialog.listMode
            text: root.tr("label.match-value", "Match value")
            color: root.textColor
        }
        ThemedTextField {
            id: matchValueField
            theme: root.uiTheme
            visible: !ruleDialog.listMode
            Layout.fillWidth: true
            text: ruleDialog.localValue
            onTextChanged: {
                // Reduce a pasted browser URL to its bare host (a no-op for
                // plain hostnames, IPs and application names).
                var norm = Rules.normalizeHostInput(ruleDialog.localRuleType, text)
                if (norm !== text) {
                    text = norm    // re-enters onTextChanged; norm has no URL
                    return          // punctuation, so the next pass settles.
                }
                ruleDialog.localValue = text
            }
            // Placeholder mirrors the canonical example for the chosen
            // rule type so the user sees the expected shape (e.g.
            // `192.0.2.1` for Exact IP) without typing first.
            placeholderText: root.uiRevision >= 0
                ? ruleDialog.matchValuePlaceholder(ruleDialog.localRuleType)
                : ""
            maximumLength: ruleDialog.matchValueMaxLength(ruleDialog.localRuleType)
            // Validator uses partial-match-friendly regex so each
            // keystroke is accepted (Qt rejects Invalid intermediate
            // input outright, which would block the first character).
            // Strict per-type semantic checks live in
            // ruleDialog.isMatchValueValid() and gate the OK button.
            validator: RegularExpressionValidator {
                regularExpression: ruleDialog.matchValueRegex(ruleDialog.localRuleType)
            }
            // Click-to-clear-example hook: when the field text equals
            // the type-specific example placeholder (e.g. user
            // explicitly inserted it), the first focus clears it so
            // typing replaces the example. For an empty field, Qt
            // already hides the placeholder on focus automatically.
            onActiveFocusChanged: {
                if (activeFocus
                        && text !== ""
                        && text === ruleDialog.matchValuePlaceholder(ruleDialog.localRuleType)) {
                    text = ""
                }
            }
        }
        // Browse for an executable (application rules
        // only). Fills the match value with the exe's file name; matching
        // is by name, so a full path is reduced to its basename.
        RowLayout {
            Layout.fillWidth: true
            visible: ruleDialog.localRuleType === "application"
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.browse", "Browse...")
                onClicked: appExeFileDialog.open()
            }
            Item { Layout.fillWidth: true }
        }
        FileDialog {
            id: appExeFileDialog
            title: root.tr("rules.app-browse-title", "Select the application executable")
            fileMode: FileDialog.OpenFile
            nameFilters: [
                root.tr("rules.app-browse-filter-exe", "Executables (*.exe)"),
                root.tr("rules.app-browse-filter-all", "All files (*)")
            ]
            onAccepted: {
                var name = String(selectedFile).replace(/^.*[\\\/]/, "").replace(/[?#].*$/, "")
                if (name !== "") {
                    matchValueField.text = name
                    ruleDialog.localValue = name
                }
            }
        }
        Label {
            Layout.fillWidth: true
            visible: !ruleDialog.listMode
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            text: root.uiRevision >= 0
                ? ruleDialog.matchValueHint(ruleDialog.localRuleType)
                : ""
        }
        // Roadmap note for Application rules: routing a whole app's traffic
        // (per-process) is a planned free feature pending the kernel driver.
        // Until then, route an app by its destinations. Shown only for the
        // `application` rule type so it's contextual, not noise.
        Label {
            Layout.fillWidth: true
            visible: ruleDialog.localRuleType === "application"
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.italic: true
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            text: root.uiRevision >= 0
                ? root.tr("rules.application-routing-note",
                    "Routes everything this app connects to through the additional adapter. NetRuleRouter learns the app's destinations by watching its connections, so routing fills in as the app connects — enable «Connection observation» in Settings → Diagnostics for this to work. Enter the executable name, e.g. chrome.exe.")
                : ""
        }
        // Where a per-application block is not leak-proof, say so next to the
        // control that creates one — a user who blocks an app must not read
        // the rule as a guarantee the platform cannot give.
        Label {
            Layout.fillWidth: true
            visible: ruleDialog.localRuleType === "application"
                && !root.supports("perAppBlockLeakproof")
            wrapMode: Text.WordWrap
            color: root.uiTheme.colorWarning
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            text: root.uiRevision >= 0
                ? root.tr("rules.application-not-leakproof",
                    "On this system an application rule is not airtight: connections the app makes before it is recognised can still get through.")
                : ""
        }
        // What this rule will actually cover, spelled out. A bare
        // `example.com` is an exact host on its own; subdomains come from the
        // "Treat a domain as domain + *.domain" setting, which ships ON. A
        // user cannot be expected to hold that in their head while typing, and
        // the answer changes with a setting they may have turned off.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: ruleDialog.localRuleType === "domain"
                && ruleDialog.localValue !== ""
                && ruleDialog.isMatchValueValid(ruleDialog.localRuleType, ruleDialog.localValue)
            text: root.uiRevision >= 0 ? ruleDialog._coverageHint() : ""
        }
        // Offered ONLY when subdomain coverage is off machine-wide: with the
        // setting on, a "without subdomains" choice would be a lie — the
        // service expands every bare domain anyway.
        CheckBox {
            Layout.fillWidth: true
            visible: ruleDialog.localRuleType === "domain"
                && root.prefs.routeIncludeSubdomains === false
            checked: ruleDialog.localValue.indexOf("*.") === 0
            text: root.tr("dialog.rule.include-subdomains", "Include subdomains")
            onToggled: {
                var v = ruleDialog.localValue
                var bare = v.indexOf("*.") === 0 ? v.substring(2) : v
                matchValueField.text = checked ? ("*." + bare) : bare
            }
        }
        // Why the value cannot be saved, in the rules table's words. A blank
        // value is incomplete, not wrong.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.uiTheme.colorDanger
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: !ruleDialog.listMode && ruleDialog.localValue !== ""
                && ruleDialog.isMatchValueRefused(ruleDialog.localRuleType, ruleDialog.localValue)
            text: root.uiRevision >= 0 ? ruleDialog.refusalText() : ""
        }
        // Saveable, but not quite what was typed or not fully protected — a
        // wide network, host bits cleared, an unusual address.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.uiTheme.colorWarning
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: !ruleDialog.listMode && ruleDialog.localValue !== ""
                && ruleDialog.isMatchValueWarned(ruleDialog.localRuleType, ruleDialog.localValue)
            text: root.uiRevision >= 0 ? ruleDialog.warningText() : ""
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        Label { text: root.tr("label.target-route", "Target route"); color: root.textColor }
        ThemedComboBox {
            id: routeTargetCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: root.routeRoleOptions(ruleDialog.allowBlockRoute, ruleDialog.verifyRouteOffered)
            textRole: "label"
            valueRole: "id"
            popup.width: root.comboPopupWidth(routeTargetCombo, model, "label", null)
            onActivated: ruleDialog.localRoute = model[currentIndex].id
            // A new model (the type changed) resets the index; put it back.
            onModelChanged: Qt.callLater(ruleDialog._syncRouteCombo)
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: ruleDialog.localRoute === "verify"
            text: root.uiRevision >= 0
                ? root.tr("dialog.rule.route-verify-hint",
                    "Opens through the primary route first. Once NetRuleRouter confirms the primary route cannot reach the site, the rule moves to the additional route by itself.")
                : ""
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        RowLayout {
            Layout.fillWidth: true
            Label { text: root.tr("label.comment", "Comment"); color: root.textColor }
            Item { Layout.fillWidth: true }
            Label {
                color: root.mutedTextColor
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                text: root.tr("rules.comment.char-counter", "{used}/{max}")
                    .replace("{used}", ruleDialog.localComment.length)
                    .replace("{max}", ruleDialog.commentMaxLength)
            }
        }
        ThemedTextField {
            id: ruleCommentField
            theme: root.uiTheme
            Layout.fillWidth: true
            text: ruleDialog.localComment
            onTextChanged: {
                if (text.length > ruleDialog.commentMaxLength) {
                    text = text.substring(0, ruleDialog.commentMaxLength)
                }
                ruleDialog.localComment = text
            }
            maximumLength: ruleDialog.commentMaxLength
            placeholderText: root.uiRevision >= 0
                ? root.tr("rules.comment.max-length",
                    "Up to {max} characters").replace("{max}", ruleDialog.commentMaxLength)
                : ""
        }
        // Enabled toggle. Disabled rules stay in the
        // rules file (and on disk) but are NOT applied to routing.
        //
        // Deliberately NOT `Layout.fillWidth`: with it the hit area spanned the
        // whole 560 px dialog, so a click that merely missed the comment field
        // just above landed here and silently disabled the rule. The box now
        // takes only its own width (indicator + label) and sits a full
        // `spacingMd` below the comment field.
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingMd
            CheckBox {
                id: ruleEnabledCheck
                checked: ruleDialog.localEnabled
                onToggled: ruleDialog.localEnabled = checked
                text: ruleDialog.localEnabled
                    ? root.tr("dialog.rule.enabled-on", "Rule is enabled (applied to routing)")
                    : root.tr("dialog.rule.enabled-off", "Rule is disabled (kept in the file, not applied)")
                Accessible.role: Accessible.CheckBox
                Accessible.name: text
            }
            // Absorbs the leftover row width so the click zone above stops at
            // the label instead of stretching across the dialog.
            Item { Layout.fillWidth: true }
        }
        // How far a domain rule actually reaches. A suffix rule matches every
        // name under the value, most of which the user never listed — that is
        // how a background client's own subdomain ends up routed. Stating the
        // reach is cheap; discovering it from a blocked connection is not.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: text !== ""
            text: {
                if (root.uiRevision < 0) return ""
                var rt = ruleDialog.localRuleType
                if (rt !== "domain" && rt !== "suffix-domain") return ""
                var val = String(ruleDialog.localValue || "").trim()
                if (val === "") return ""
                if (Pure.isPublicSuffixValue(val)) {
                    return root.tr("rules.value.public-suffix-warning",
                        "{value} is a public registry, not one service: the rule would "
                        + "route unrelated owners. Use a zone rule if that is what you want.")
                        .replace("{value}", val)
                }
                // A plain domain rule already says how far it reaches, in the
                // coverage line above and in the words of the setting that
                // decides it. Saying it twice, in two wordings, read as two
                // different rules being described.
                if (rt !== "suffix-domain") return ""
                return root.tr("rules.value.suffix-reach",
                    "Matches every name under {value}, including ones you did not list.")
                    .replace("{value}", val)
            }
        }
        // Punycode/IDN hint. When the user types a
        // non-ASCII hostname (e.g. `пример.рф`), surface the ASCII /
        // Punycode form so they can verify what will reach the WFP
        // filter engine. Auto-fill happens at save time; this label
        // is just informational. Bridge-only — preview / Tray omits.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: text !== ""
            text: {
                if (root.uiRevision < 0) return ""
                var rt = ruleDialog.localRuleType
                if (rt !== "zone" && rt !== "domain" && rt !== "suffix-domain"
                        && rt !== "exact-fqdn") return ""
                var val = ruleDialog.localValue
                if (!val) return ""
                var ace = root._punycodeFor(val)
                if (ace === "") return ""
                return root.tr("rules.value.punycode-hint",
                    "Punycode: {ace}").replace("{ace}", ace)
            }
        }
    }
}
