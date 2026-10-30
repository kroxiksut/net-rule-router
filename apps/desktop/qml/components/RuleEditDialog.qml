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
                enabled: ruleDialog.bulkMode
                    ? ruleDialog.bulkCanApply
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
    // `?`: check where the rule works. Kept as ticked when the type cannot
    // carry it; `Rules.rowIsVerify` decides what is saved.
    property bool localVerify: false
    property string localComment: ""
    // Enabled toggle in Add/Edit dialog. Default
    // true on Add; carries existing state on Edit.
    property bool localEnabled: true
    // "Unsure" fits a domain or one address on a route, never a deny.
    readonly property bool verifyOffered: Rules.ruleTypeAllowsVerify(localRuleType)
        && localRoute !== "block" && !anyZoneValue
    readonly property bool anyZoneValue: Rules.valueIsAnyZone(localValue)
    // Ticked on an IPv6 address: saved as an ordinary route, as the service does.
    readonly property bool verifyDroppedForIpv6: localVerify && localRoute !== "block"
        && Rules.valueIsIpv6Literal(localRuleType, localValue)
    // A deny where "Unsure" would otherwise fit: say why the box is off.
    readonly property bool verifyRefusedByDeny: localRoute === "block"
        && Rules.ruleTypeAllowsVerify(localRuleType) && !anyZoneValue
    // The one handler for this signal: QML refuses a second one and the whole
    // dialog — and with it the main window — then fails to load.
    onLocalRuleTypeChanged: {
        _requestVerdict()
        overlapTimer.restart()
        coverageTimer.restart()
    }
    onLocalRouteChanged: {
        // The file cannot hold `!` and `?` together, so choosing a deny clears
        // the tick instead of keeping it for a later route change.
        if (localRoute === "block" && localVerify) {
            localVerify = false
            if (ruleVerifyCheck) ruleVerifyCheck.checked = false
        }
        _syncRouteCombo()
        _requestVerdict()
        overlapTimer.restart()
        coverageTimer.restart()
        if (bulkMode) bulkPlanTimer.restart()
    }
    onLocalEnabledChanged: overlapTimer.restart()
    // User input severs the combo's index binding, so it is kept in step by hand.
    function _syncRouteCombo() {
        if (!routeTargetCombo || !root) return
        var roleOpts = root.routeRoleOptions()
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
    // A new rule for `value` already pointed at `route` (the tray's card about
    // a site that does not open over the main route).
    function resetForNewOnRoute(ruleType, value, route) {
        resetForNew(ruleType, value)
        localRoute = String(route || "primary")
        _syncRouteCombo()
    }
    // "Several rules" holding `names` on `route`, each line set to move a rule
    // that stands on another route (the site check's offer). The user still
    // reviews the plan and confirms it.
    function resetForMoving(names, route) {
        resetForNew("domain", "")
        localRoute = String(route || "primary")
        _syncRouteCombo()
        var list = names || []
        var choices = {}
        for (var i = 0; i < list.length; i += 1)
            choices[String(i + 1)] = { text: String(list[i]), type: "", move: true }
        resumeBulk(list.join("\n"))
        bulkChoices = choices
        _replanBulk()
    }
    function resetForEdit() {
        var editing = root.editingRule >= 0 && root.editingRule < root.rulesModel.count
        // The rule itself, which the save looks up again: the list may be
        // re-read while the form is open.
        root.editingRuleKey = editing ? Rules.mergeKey(root.rulesModel.get(root.editingRule)) : ""
        if (editing) {
            var r = root.rulesModel.get(root.editingRule)
            localRuleType = String(r.ruleType || (root.ruleTypesModel.count > 0 ? root.ruleTypesModel.get(0).id : "application"))
            localValue = String(r.matchValue || "")
            localRoute = String(r.targetRoute || "primary")
            localVerify = r.verify === true
            localComment = String(r.comment || "")
            localEnabled = (r.enabled === undefined) ? true : !!r.enabled
        } else {
            localRuleType = firstAddableRuleType()
            localValue = ""
            localRoute = "primary"
            localVerify = false
            localComment = ""
            localEnabled = true
        }
        bulkMode = false
        bulkText = ""
        bulkChoices = ({})
        _bulkVerdicts = ({})
        _bulkAsked = ({})
        bulkPlan = _emptyBulkPlan
        if (bulkInput) bulkInput.text = ""
        if (oneRuleRadio) oneRuleRadio.checked = true
        if (severalRulesRadio) severalRulesRadio.checked = false
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
        if (ruleVerifyCheck) ruleVerifyCheck.checked = localVerify
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
        if (/\.\*$/.test(v)) {
            var site = v.substring(0, v.length - 2)
            site = site.indexOf("*.") === 0 ? site.substring(2) : site
            return root.tr("dialog.rule.coverage-any-zone",
                "Covers {host} in every zone ({host}.com, {host}.net and so on) with all subdomains. A rule naming the zone wins over it.")
                .replace(/\{host\}/g, site)
        }
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
        if (ruleType === "application") {
            return new RegExp("^.{0," + Rules.ruleValueMaxLength(ruleType) + "}$")
        }
        return new RegExp("^.*$")
    }
    function matchValueMaxLength(ruleType) {
        return Rules.ruleValueMaxLength(ruleType)
    }
    // The verdict on the value on screen, asked of the launcher: the one the
    // rules table shows, which for a zone or domain is the service's own
    // import pipeline. `key` names the value it answers, so the answer to an
    // earlier keystroke never gates a later one. The route is part of it: a
    // deny or the additional route may not name a program the system needs.
    property var _verdict: ({ key: "", status: "", messageKey: "", args: ({}) })
    function _verdictKey(ruleType, raw) {
        return String(ruleType || "") + "|" + String(raw || "").trim() + "|" + String(localRoute || "")
    }
    function _requestVerdict() {
        var type = localRuleType
        var value = String(localValue || "").trim()
        if (value === "" || !root.rpc || !root.rpc.bridgeAvailable
                || typeof root.rpc.bridge.rpcRuleValueVerdict !== "function") {
            return
        }
        var key = _verdictKey(type, value)
        var corr = root.rpc.bridge.rpcRuleValueVerdict(type, value, String(localRoute || ""))
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("local.rule-value-verdict failed:", code, msg)
                // Silence would leave OK inactive with no reason on screen.
                ruleDialog._verdict = { key: key, status: "error",
                    messageKey: "rules.validation.verdict-unavailable", args: ({}) }
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
    onLocalValueChanged: { _requestVerdict(); overlapTimer.restart(); coverageTimer.restart() }
    function _verdictFor(ruleType, raw) {
        return _verdict.key === _verdictKey(ruleType, raw) ? _verdict : null
    }
    // No answer yet counts as not saveable: OK waits for the verdict. A path
    // the service refuses (another user's folder) is not saveable either.
    function isMatchValueValid(ruleType, raw) {
        if (String(raw || "").trim() === "") return false
        var verdict = _verdictFor(ruleType, raw)
        return verdict !== null && verdict.status !== "error"
            && !(ruleType === "application" && coverageRefused())
    }

    // ── A rule by program path ──
    // What the value names (`Rules.appValueForm`), and the service's count of
    // the programs it covers for this user, asked after a pause in typing.
    // `key` names the value and route it answers, as `_verdict` does.
    readonly property string _pathOs: root ? String(root.platformProfile.os || "") : ""
    readonly property string appForm: localRuleType === "application"
        ? Rules.appValueForm(localValue, _pathOs) : ""
    readonly property bool isFolderValue: appForm === "folder" || appForm === "folder-tree"
    readonly property bool coverageAvailable: !!root && !!root.rpc && root.rpc.bridgeAvailable
        && typeof root.rpc.rpcRulesAppPathCoverage === "function"
    property var _coverage: ({ key: "", answer: null })
    onAppFormChanged: {
        // User clicks sever the box's binding; the value decides it.
        if (includeSubfoldersCheck) includeSubfoldersCheck.checked = appForm === "folder-tree"
    }
    function _isPathForm(form) {
        return form === "file" || form === "folder" || form === "folder-tree"
            || form === "file-or-folder"
    }
    function _coverageKey() {
        return String(localValue || "").trim() + "|" + String(localRoute || "")
    }
    function _requestCoverage() {
        if (bulkMode || !_isPathForm(appForm) || !coverageAvailable) return
        var key = _coverageKey()
        var corr = root.rpc.rpcRulesAppPathCoverage(String(localValue || "").trim(),
            String(localRoute || ""))
        if (corr === "") return
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("rules.app-path-coverage.get failed:", code, msg)
                return
            }
            ruleDialog._coverage = { key: key, answer: payload || null }
        })
    }
    function _coverageNow() {
        return _coverage.key === _coverageKey() ? _coverage.answer : null
    }
    function coverageRefused() {
        var a = _coverageNow()
        return a !== null && String(a.outcome || "") === "refused"
    }
    function _hasProfileFolder() {
        return /^\s*[%~]/.test(String(localValue || ""))
    }
    function coverageText() {
        if (!_isPathForm(appForm) || !coverageAvailable) return ""
        var a = _coverageNow()
        if (a === null) return root.tr("dialog.rule.path.counting", "Counting the programs...")
        var outcome = String(a.outcome || "")
        var text = ""
        if (outcome === "found") {
            text = (a.truncated === true
                ? root.tr("dialog.rule.path.count-more",
                    "Programs covered now: the first {count}. The folder holds more than one rule covers.")
                : root.tr("dialog.rule.path.count", "Programs covered now: {count}."))
                .replace("{count}", String(a.programs || 0))
        } else if (outcome === "missing") {
            text = root.tr("dialog.rule.path.missing",
                "Nothing is there yet: the rule takes effect once the program or folder appears.")
        } else if (outcome === "unsupported") {
            return root.tr("dialog.rule.path.unsupported",
                "This system does not apply rules by path yet.")
        } else {
            return ""
        }
        if (_hasProfileFolder() && String(a.place || "") !== "") {
            text += " " + root.tr("dialog.rule.path.place", "For you this is {place}.")
                .replace("{place}", Pure.displayText(String(a.place)))
        }
        return text
    }
    // The service's refusal, when the launcher's verdict has not said it.
    function coverageRefusalText() {
        var a = _coverageNow()
        if (a === null || !coverageRefused()
                || isMatchValueRefused(localRuleType, localValue)) return ""
        return root.tr(String(a["refusal-key"] || ""),
            root.tr("rules.validation.error", "Error — rule is inactive"))
    }
    function coverageWarningText() {
        var a = _coverageNow()
        if (a === null || coverageRefused()) return ""
        var lines = []
        if (a["anyone-can-write"] === true) {
            lines.push(root.tr("dialog.rule.path.anyone-can-write",
                "Anyone can put a program here, so the rule may cover programs you did not install. A program here is never exempt from leak protection."))
        }
        var key = String(a["warning-key"] || "")
        var verdict = _verdictFor(localRuleType, localValue)
        if (key !== "" && (verdict === null || verdict.messageKey !== key)) {
            lines.push(root.tr(key, root.tr("rules.validation.warning", "Valid with warnings")))
        }
        return lines.join("\n")
    }
    Timer {
        id: coverageTimer
        interval: 400
        repeat: false
        onTriggered: ruleDialog._requestCoverage()
    }
    function _pathSeparator() {
        return _pathOs === "linux" || _pathOs === "macos" ? "/" : "\\"
    }
    // The rule flags after the value (`+children`), kept as they stand.
    function _flagTail(v) {
        var m = /(\s+\+[A-Za-z-]+)+$/.exec(v)
        return m ? m[0] : ""
    }
    function _setValueKeepingFlags(path, tail) {
        var next = path + tail
        if (matchValueField) matchValueField.text = next
        localValue = next
    }
    // "Choose folder": the folder with its trailing separator, and `*` when
    // "Include subfolders" is ticked.
    function setFolderValue(folder) {
        var p = String(folder || "")
        if (p === "") return
        var sep = _pathSeparator()
        if (sep === "\\") p = p.replace(/\//g, "\\")
        if (p.charAt(p.length - 1) !== sep) p += sep
        if (includeSubfoldersCheck && includeSubfoldersCheck.checked) p += "*"
        var current = String(localValue || "").trim()
        _setValueKeepingFlags(p, localRuleType === "application" ? _flagTail(current) : "")
    }
    // "Include subfolders" adds or takes off the `*` of a folder rule.
    function setSubfolders(on) {
        var v = String(localValue || "").trim()
        var tail = _flagTail(v)
        var core = v.substring(0, v.length - tail.length)
        var sep = _pathSeparator()
        var isSep = function(c) { return c === "/" || (sep === "\\" && c === "\\") }
        var tree = core.length >= 2 && core.charAt(core.length - 1) === "*"
            && isSep(core.charAt(core.length - 2))
        if (on && !tree) {
            if (!isSep(core.charAt(core.length - 1))) core += sep
            core += "*"
        } else if (!on && tree) {
            core = core.substring(0, core.length - 1)
        }
        _setValueKeepingFlags(core, tail)
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
    /// The type the value on screen is, when its verdict says it belongs to
    /// another one this form offers; "" otherwise.
    function switchTypeTarget() {
        var verdict = _verdictFor(localRuleType, localValue)
        if (verdict === null || verdict.status !== "error") return ""
        var target = Rules.misplacedTargetType(verdict.messageKey)
        return target !== "" && target !== localRuleType && _typeOffered(target) ? target : ""
    }
    /// "Move to that type", on the user's click only.
    function switchToType(target) {
        if (target === "") return
        localRuleType = target
        if (ruleTypeCombo) {
            for (var k = 0; k < root.ruleTypesModel.count; k += 1) {
                if (root.ruleTypesModel.get(k).id === target) {
                    ruleTypeCombo.currentIndex = k
                    break
                }
            }
        }
        if (matchValueField) matchValueField.forceActiveFocus()
    }
    function warningText() {
        var verdict = _verdictFor(localRuleType, localValue)
        return verdict === null ? ""
            : verdictMessage(verdict.messageKey, verdict.args,
                root.tr("rules.validation.warning", "Valid with warnings"))
    }

    // ── Several rules at once ──
    // The text reads as a rules file (`Rules.planBulkRules`; the TUI runs its
    // Rust twin), each row judged by the launcher, once for the whole paste.
    // The route above applies to every line without its own `!`.
    property bool bulkMode: false
    property string bulkText: ""
    /// By line number: `{ text, type, move }`, honoured while the line still
    /// reads `text`, so an edit above it does not hand it to another line.
    property var bulkChoices: ({})
    /// Verdicts by `verdictKey`, kept across keystrokes.
    property var _bulkVerdicts: ({})
    /// Keys asked of the launcher and not answered yet.
    property var _bulkAsked: ({})
    readonly property var _emptyBulkPlan: ({ rows: [], lines: 0, excess: 0, bound: "",
        add: 0, move: 0, keep: 0, drop: 0, remaining: "" })
    property var bulkPlan: _emptyBulkPlan
    readonly property int bulkPendingCount: {
        var n = 0
        for (var i = 0; i < bulkPlan.rows.length; i += 1) {
            if (bulkPlan.rows[i].status === "pending") n += 1
        }
        return n
    }
    readonly property bool bulkCanApply: bulkPlan.add + bulkPlan.move > 0 && bulkPendingCount === 0
    readonly property bool bulkAvailable: !!root && !!root.rpc && root.rpc.bridgeAvailable
        && typeof root.rpc.bridge.rpcRuleValuesVerdicts === "function"
    onBulkTextChanged: bulkPlanTimer.restart()
    onBulkModeChanged: bulkPlanTimer.restart()
    Timer {
        id: bulkPlanTimer
        interval: 200
        repeat: false
        onTriggered: ruleDialog._replanBulk()
    }
    function _typeOffered(type) {
        for (var i = 0; i < root.ruleTypesModel.count; i += 1) {
            if (root.ruleTypesModel.get(i).id === type) return true
        }
        return false
    }
    /// What the planner reads besides the rules: the host plans it against the
    /// rules it holds at Save (`Rules.planBulkSubmission`).
    function bulkPlanInput() {
        return {
            text: bulkText,
            route: localRoute,
            os: String(root.platformProfile.os || ""),
            apps: _typeOffered("application"),
            choices: _bulkLiveChoices(),
            verdicts: _bulkVerdicts,
            room: root.bulkRuleRoom()
        }
    }
    function _bulkLineText(lines, n) {
        return n >= 1 && n <= lines.length ? String(lines[n - 1]).replace(/\r$/, "").trim() : ""
    }
    function _bulkLiveChoices() {
        var lines = bulkText.split("\n")
        var out = {}
        for (var k in bulkChoices) {
            var c = bulkChoices[k]
            if (_bulkLineText(lines, parseInt(k, 10)) === c.text) out[k] = { type: c.type, move: c.move }
        }
        return out
    }
    function _replanBulk() {
        if (!bulkMode || !root) {
            bulkPlan = _emptyBulkPlan
            return
        }
        var plan = Rules.planBulkSubmission(bulkPlanInput(), root.rulesModel)
        // A new model scrolls a list back to its top; the reader stays put.
        var y = bulkPreview ? bulkPreview.contentY : 0
        bulkPlan = plan
        if (bulkPreview) {
            Qt.callLater(function() {
                bulkPreview.contentY = Math.max(0, Math.min(y,
                    bulkPreview.contentHeight - bulkPreview.height))
            })
        }
        _askBulkVerdicts(plan)
    }
    function _askBulkVerdicts(plan) {
        if (!bulkAvailable) return
        var wanted = Rules.bulkPendingVerdicts(plan)
        var asked = {}
        for (var a in _bulkAsked) asked[a] = true
        var values = []
        for (var i = 0; i < wanted.length; i += 1) {
            if (asked[wanted[i].key]) continue
            asked[wanted[i].key] = true
            values.push(wanted[i])
        }
        if (values.length === 0) return
        _bulkAsked = asked
        var query = []
        for (var q = 0; q < values.length; q += 1) {
            query.push({ "rule-type": values[q]["rule-type"], "match-value": values[q]["match-value"] })
        }
        var corr = root.rpc.bridge.rpcRuleValuesVerdicts(JSON.stringify(query))
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            var left = {}
            for (var k in ruleDialog._bulkAsked) left[k] = true
            for (var m = 0; m < values.length; m += 1) delete left[values[m].key]
            ruleDialog._bulkAsked = left
            if (!ok) {
                console.log("local.rule-values-verdicts failed:", code, msg)
                return
            }
            var got = (payload && payload.verdicts) || []
            var next = {}
            var kept = 0
            for (var v in ruleDialog._bulkVerdicts) {
                next[v] = ruleDialog._bulkVerdicts[v]
                kept += 1
            }
            // Typing leaves a verdict per keystroke behind; past a few
            // thousand they are dropped and asked again when needed.
            if (kept > 5000) next = {}
            for (var n = 0; n < values.length && n < got.length; n += 1) {
                next[values[n].key] = {
                    status: String(got[n].status || ""),
                    "message-key": String(got[n]["message-key"] || ""),
                    args: got[n].args || ({})
                }
            }
            ruleDialog._bulkVerdicts = next
            ruleDialog._replanBulk()
        })
    }
    /// The type picked on a preview row; picking it again takes it back.
    function bulkChoose(row, type) {
        var next = {}
        for (var k in bulkChoices) next[k] = bulkChoices[k]
        var key = String(row.line)
        var current = next[key] && next[key].text === row.text ? next[key] : null
        next[key] = {
            text: row.text,
            type: current && current.type === type ? "" : type,
            move: current ? current.move === true : false
        }
        bulkChoices = next
        _replanBulk()
    }
    function bulkSetMove(row, on) {
        var next = {}
        for (var k in bulkChoices) next[k] = bulkChoices[k]
        var key = String(row.line)
        var current = next[key] && next[key].text === row.text ? next[key] : null
        next[key] = { text: row.text, type: current ? current.type : "", move: on === true }
        bulkChoices = next
        _replanBulk()
    }
    /// Back to "several rules" with `text` in the field: what an apply left.
    function resumeBulk(text) {
        bulkMode = true
        if (oneRuleRadio) oneRuleRadio.checked = false
        if (severalRulesRadio) severalRulesRadio.checked = true
        bulkChoices = ({})
        bulkText = String(text || "")
        if (bulkInput) bulkInput.text = bulkText
        _replanBulk()
    }
    function setBulkMode(on) {
        if (on && bulkText === "" && String(localValue || "").trim() !== "") {
            bulkText = String(localValue).trim()
            if (bulkInput) bulkInput.text = bulkText
        }
        bulkMode = on
        if (on && bulkInput) bulkInput.forceActiveFocus()
    }
    /// A verdict's arguments as they read: a route by the user's name for it.
    function _bulkArgs(row) {
        var out = {}
        for (var k in (row.args || {})) out[k] = String(row.args[k])
        if (out.route !== undefined) out.route = root.routeLabel(out.route)
        return out
    }
    function bulkRowText(row) {
        var parts = [row.type !== "" ? root.ruleTypeLabel(row.type)
            : root.tr("dialog.rule.bulk.type-unknown", "Type not known")]
        parts.push(row.route === "block" ? root.tr("label.block", "Denied") : root.routeLabel(row.route))
        if (!row.enabled) parts.push(root.tr("label.disabled", "disabled"))
        if (row.verify) parts.push(root.tr("rules.filter.route.unsure", "Unsure (?)"))
        var status = row.status === "ok" && row.action === "add"
            ? root.tr("dialog.rule.bulk.will-add", "will be added")
            : verdictMessage(row.key, _bulkArgs(row), row.status === "error"
                ? root.tr("rules.validation.error", "Error \u2014 rule is inactive")
                : root.tr("rules.validation.warning", "Valid with warnings"))
        return parts.join(", ") + " \u2014 " + status
    }
    function bulkMoveText(row) {
        if (row.route === "block") return root.tr("tray.add-rule.deny-instead", "Deny instead")
        if (row.otherRoute === "block") {
            return root.tr("tray.add-rule.lift-deny", "Lift the deny, use this route")
        }
        return root.tr("tray.add-rule.move", "Move to this route")
    }
    function bulkSummaryText() {
        var p = bulkPlan
        var text = root.tr("dialog.rule.bulk.summary",
            "To add: {add}. To move: {move}. Stay in the field: {keep}. Already in your rules: {drop}.")
            .replace("{add}", String(p.add)).replace("{move}", String(p.move))
            .replace("{keep}", String(p.keep)).replace("{drop}", String(p.drop))
        if (bulkPendingCount > 0) {
            text += " " + root.tr("dialog.rule.bulk.checking", "Checking: {count}.")
                .replace("{count}", String(bulkPendingCount))
        }
        if (p.bound === "lines") {
            text += " " + root.tr("dialog.rule.bulk.bound-lines",
                "Only the first {max} lines are read; the other {count} stay in the field for the next round.")
                .replace("{max}", String(p.lines)).replace("{count}", String(p.excess))
        } else if (p.bound === "size") {
            text += " " + root.tr("dialog.rule.bulk.bound-size",
                "The text is longer than one round reads: the first {lines} lines are read, the other {count} stay in the field.")
                .replace("{lines}", String(p.lines)).replace("{count}", String(p.excess))
        }
        return text
    }

    // Which rules of the other route this one meets, said before it is saved:
    // the overlaps table then asks only about pairs nobody made on purpose.
    property var _overlapAnswer: ({ key: "", lines: [] })
    readonly property int _overlapLinesShown: 3
    function _overlapKey() {
        return [root.editingRule, localRuleType, String(localValue || "").trim(),
            localRoute, localEnabled].join("|")
    }
    function _requestOverlaps() {
        var value = String(localValue || "").trim()
        if (bulkMode || value === "" || typeof root.candidateRouteOverlaps !== "function") return
        var editing = root.editingRule >= 0 && root.editingRule < root.rulesModel.count
        var key = _overlapKey()
        var row = {
            id: editing ? root.rulesModel.get(root.editingRule).id : root.nextFreeRuleId(),
            enabled: localEnabled,
            ruleType: localRuleType,
            matchValue: value,
            targetRoute: localRoute,
            verify: Rules.rowIsVerify({ ruleType: localRuleType, targetRoute: localRoute,
                verify: localVerify, matchValue: value }),
            comment: ""
        }
        root.candidateRouteOverlaps(editing ? root.editingRule : -1, row, function(pairs, candidate) {
            var lines = []
            for (var i = 0; i < pairs.length; i += 1)
                lines.push(root.ruleOverlapsController.explain(pairs[i], candidate))
            ruleDialog._overlapAnswer = { key: key, lines: lines }
        })
    }
    function overlapText() {
        if (_overlapAnswer.key !== _overlapKey()) return ""
        var lines = _overlapAnswer.lines
        var shown = lines.slice(0, _overlapLinesShown)
        if (lines.length > shown.length) {
            shown.push(root.tr("notifications.block-notice.backlog.more", "and {count} more")
                .replace("{count}", String(lines.length - shown.length)))
        }
        return shown.join("\n")
    }
    Timer {
        id: overlapTimer
        interval: 300
        repeat: false
        onTriggered: ruleDialog._requestOverlaps()
    }

    onAccepted: {
        if (bulkMode) {
            if (!bulkCanApply) {
                open()
                return
            }
            // The rules may have been re-read since the plan on screen.
            var plan = Rules.planBulkSubmission(bulkPlanInput(), root.rulesModel)
            if (plan.add + plan.move === 0) {
                bulkPlan = plan
                open()
                return
            }
            root.saveBulkRules(plan)
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
    // A form taller than the window scrolls inside it rather than pushing its
    // last rows under the buttons (a 720 px screen with every hint showing).
    height: root ? Math.min(implicitHeight, root.height - 2 * _edgeGap) : implicitHeight
    ScrollView {
        id: formScroll
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth
        contentHeight: formColumn.implicitHeight + 2 * root.uiTheme.spacingMd
        ColumnLayout {
            id: formColumn
            x: root.uiTheme.spacingMd
            y: root.uiTheme.spacingMd
            width: formScroll.availableWidth - 2 * root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            // One rule or a pasted list; an edited rule is always one.
            RowLayout {
                Layout.fillWidth: true
                visible: root.editingRule < 0 && ruleDialog.bulkAvailable
                spacing: root.uiTheme.spacingMd
                ThemedRadioButton {
                    id: oneRuleRadio
                    theme: root.uiTheme
                    checked: true
                    text: root.uiRevision >= 0 ? root.tr("dialog.rule.mode.one", "One rule") : ""
                    onToggled: if (checked) ruleDialog.setBulkMode(false)
                    Accessible.name: text
                }
                ThemedRadioButton {
                    id: severalRulesRadio
                    theme: root.uiTheme
                    text: root.uiRevision >= 0 ? root.tr("dialog.rule.mode.several", "Several rules") : ""
                    onToggled: if (checked) ruleDialog.setBulkMode(true)
                    Accessible.name: text
                    Accessible.description: bulkLabel.text
                }
                Item { Layout.fillWidth: true }
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: !ruleDialog.bulkMode
                text: root.tr("label.rule-type", "Rule type")
                color: root.textColor
            }
            ThemedComboBox {
                id: ruleTypeCombo
                accessibleLabel: root.uiRevision >= 0 ? root.tr("label.rule-type", "Rule type") : ""
                theme: root.uiTheme
                visible: !ruleDialog.bulkMode
                Layout.fillWidth: true
                model: root.ruleTypesModel
                textRole: "id"
                valueRole: "id"
                labelResolver: function(item) { return item ? root.ruleTypeLabel(item.id) : "" }
                displayText: root.uiRevision >= 0 && currentIndex >= 0 && currentIndex < root.ruleTypesModel.count
                    ? root.ruleTypeLabel(root.ruleTypesModel.get(currentIndex).id) : ""
                popup.width: root.comboPopupWidth(ruleTypeCombo, root.ruleTypesModel, "id", function(item) { return root.ruleTypeLabel(item.id) })
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
            Label {
                id: bulkLabel
                visible: ruleDialog.bulkMode
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.uiRevision >= 0
                    ? root.tr("dialog.rule.bulk.label",
                        "One rule per line, as in a rules file: !value denies, ?value checks where it works, # value is kept switched off, and a line such as --- Windows gives the lines below it their type. Otherwise the type is read from the value.")
                    : ""
            }
            ScrollView {
                id: bulkInputScroll
                visible: ruleDialog.bulkMode
                Layout.fillWidth: true
                Layout.preferredHeight: 140
                clip: true
                ThemedTextArea {
                    id: bulkInput
                    theme: root.uiTheme
                    wrapMode: TextArea.NoWrap
                    placeholderText: root.uiRevision >= 0
                        ? root.tr("dialog.rule.bulk.placeholder",
                            "example.com\n!ads.example.net\n192.0.2.0/24\n--- Windows\nbrowser.exe")
                        : ""
                    onTextChanged: ruleDialog.bulkText = text
                    // Tab leaves the field, as in every other control of the form.
                    Keys.onTabPressed: function(event) {
                        var next = bulkInput.nextItemInFocusChain(true)
                        if (next) next.forceActiveFocus(Qt.TabFocusReason)
                        event.accepted = true
                    }
                    Keys.onBacktabPressed: function(event) {
                        var prev = bulkInput.nextItemInFocusChain(false)
                        if (prev) prev.forceActiveFocus(Qt.BacktabFocusReason)
                        event.accepted = true
                    }
                    Accessible.role: Accessible.EditableText
                    Accessible.name: severalRulesRadio.text
                    Accessible.description: bulkLabel.text
                }
            }
            Label {
                id: bulkSummary
                visible: ruleDialog.bulkMode
                    && (ruleDialog.bulkPlan.rows.length > 0 || ruleDialog.bulkPlan.bound !== "")
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                color: ruleDialog.bulkPlan.bound !== "" ? root.uiTheme.colorWarning : root.textColor
                text: root.uiRevision >= 0 ? ruleDialog.bulkSummaryText() : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            // A row per rule line. A list, not a column of every row: a paste of
            // a thousand lines builds only the rows in view.
            ListView {
                id: bulkPreview
                visible: ruleDialog.bulkMode && ruleDialog.bulkPlan.rows.length > 0
                Layout.fillWidth: true
                Layout.preferredHeight: Math.min(220, Math.max(48, contentHeight))
                clip: true
                spacing: 4
                boundsBehavior: Flickable.StopAtBounds
                model: ruleDialog.bulkPlan.rows
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                Accessible.role: Accessible.List
                Accessible.name: bulkSummary.text
                delegate: ColumnLayout {
                    id: bulkRow
                    required property var modelData
                    width: ListView.view ? ListView.view.width - 12 : 0
                    spacing: 2
                    readonly property string status: String(modelData.status)
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm
                        Label {
                            Layout.preferredWidth: 190
                            Layout.alignment: Qt.AlignTop
                            elide: Text.ElideMiddle
                            textFormat: Text.PlainText
                            color: root.textColor
                            text: String(bulkRow.modelData.line) + ". "
                                + Pure.displayText(bulkRow.modelData.text)
                        }
                        Label {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 0
                            wrapMode: Text.WordWrap
                            textFormat: Text.PlainText
                            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            color: bulkRow.status === "error" ? root.uiTheme.colorDanger
                                : bulkRow.status === "warning" || bulkRow.status === "needs-type"
                                    || bulkRow.status === "elsewhere" ? root.uiTheme.colorWarning
                                : root.mutedTextColor
                            text: root.uiRevision >= 0 ? ruleDialog.bulkRowText(bulkRow.modelData) : ""
                            Accessible.role: Accessible.StaticText
                            Accessible.name: String(bulkRow.modelData.line) + ". "
                                + Pure.displayText(bulkRow.modelData.text) + ": " + text
                        }
                    }
                    // The type a one-word value is, or the one a value out of
                    // its section belongs to; and the move of a rule that stands
                    // on another route. Each only on the user's click.
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: 190 + root.uiTheme.spacingSm
                        visible: bulkRow.modelData.options.length > 0 || bulkRow.status === "elsewhere"
                        spacing: root.uiTheme.spacingSm
                        Repeater {
                            model: bulkRow.modelData.options
                            delegate: ThemedButton {
                                required property var modelData
                                theme: root.uiTheme
                                highlighted: bulkRow.modelData.type === modelData
                                text: root.uiRevision < 0 ? ""
                                    : bulkRow.modelData.section !== ""
                                    ? root.tr("rules.move-to-type.action", "Move to \u201c{type}\u201d")
                                        .replace("{type}", root.ruleTypeLabel(modelData))
                                    : root.ruleTypeLabel(modelData)
                                onClicked: ruleDialog.bulkChoose(bulkRow.modelData, modelData)
                                Accessible.name: text
                                Accessible.description: bulkRow.modelData.section !== ""
                                    ? root.tr("rules.move-to-type.tooltip",
                                        "Give this rule the type its value is. The line moves to that section of the rules file.")
                                    : ""
                            }
                        }
                        CheckBox {
                            visible: bulkRow.status === "elsewhere"
                            checked: bulkRow.modelData.move === true
                            text: root.uiRevision >= 0 ? ruleDialog.bulkMoveText(bulkRow.modelData) : ""
                            onToggled: ruleDialog.bulkSetMove(bulkRow.modelData, checked)
                            Accessible.role: Accessible.CheckBox
                            Accessible.name: text
                        }
                        Item { Layout.fillWidth: true }
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: !ruleDialog.bulkMode
                text: root.tr("label.match-value", "Match value")
                color: root.textColor
            }
            ThemedTextField {
                id: matchValueField
                accessibleLabel: root.uiRevision >= 0 ? root.tr("label.match-value", "Match value") : ""
                theme: root.uiTheme
                visible: !ruleDialog.bulkMode
                Layout.fillWidth: true
                text: ruleDialog.localValue
                onTextChanged: {
                    // Reduce a pasted browser URL to its bare host (a no-op for
                    // plain hostnames, IPs and application names).
                    var norm = Rules.normalizeHostInput(ruleDialog.localRuleType, text)
                    // A program in one outer pair of quotes, as a rules file
                    // reads it. Only typed text: a value loaded for editing
                    // arrives through localValue and is kept as stored.
                    if (text !== ruleDialog.localValue)
                        norm = Pure.formRuleValue(ruleDialog.localRuleType, norm)
                    if (norm !== text) {
                        // The re-entry finds text === localValue and settles.
                        ruleDialog.localValue = norm
                        text = norm
                        return
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
                visible: !ruleDialog.bulkMode && ruleDialog.localRuleType === "application"
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.browse", "Browse...")
                    onClicked: appExeFileDialog.open()
                }
                // A folder of programs: the rule covers what it holds.
                ThemedButton {
                    theme: root.uiTheme
                    text: root.uiRevision >= 0
                        ? root.tr("dialog.rule.path.choose-folder", "Choose folder...") : ""
                    onClicked: appFolderDialog.open()
                    Accessible.name: text
                }
                CheckBox {
                    id: includeSubfoldersCheck
                    visible: ruleDialog.isFolderValue
                    checked: ruleDialog.appForm === "folder-tree"
                    text: root.uiRevision >= 0
                        ? root.tr("dialog.rule.path.include-subfolders", "Include subfolders") : ""
                    onToggled: ruleDialog.setSubfolders(checked)
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                }
                Item { Layout.fillWidth: true }
            }
            FolderDialog {
                id: appFolderDialog
                title: root.uiRevision >= 0
                    ? root.tr("dialog.rule.path.choose-folder-title",
                        "Choose the folder with the programs")
                    : ""
                onAccepted: ruleDialog.setFolderValue(Pure.localPathFromFileUrl(selectedFolder))
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
                visible: !ruleDialog.bulkMode
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
                visible: !ruleDialog.bulkMode && ruleDialog.localRuleType === "application"
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                font.italic: true
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                text: root.uiRevision >= 0
                    ? (ruleDialog.applicationPlatformKey() === "application-linux"
                        ? root.tr("rules.application-routing-note-linux",
                            "Routes everything this program connects to through the additional connection. NetRuleRouter learns the program's destinations by watching its connections, so routing fills in as it connects. Enter the process name, e.g. browser.")
                        : root.tr("rules.application-routing-note",
                            "Routes everything this app connects to through the additional adapter. NetRuleRouter learns the app's destinations by watching its connections, so routing fills in as the app connects — enable «Connection observation» in Settings → Diagnostics for this to work. Enter the executable name, e.g. chrome.exe."))
                    : ""
            }
            // Where a per-application block is not leak-proof, say so next to the
            // control that creates one — a user who blocks an app must not read
            // the rule as a guarantee the platform cannot give.
            Label {
                Layout.fillWidth: true
                visible: !ruleDialog.bulkMode && ruleDialog.localRuleType === "application"
                    && !root.supports("perAppBlockLeakproof")
                wrapMode: Text.WordWrap
                color: root.uiTheme.colorWarning
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                text: root.uiRevision >= 0
                    ? root.tr("rules.application-not-leakproof",
                        "On this system an application rule is not airtight: connections the app makes before it is recognised can still get through.")
                    : ""
            }
            // A folder rule follows the scripts the folder holds through what
            // they are seen connecting to, so a deny cannot hold them for certain.
            Label {
                readonly property string valueForm: Rules.appValueForm(ruleDialog.localValue,
                    root.platformProfile ? root.platformProfile.os : "")
                Layout.fillWidth: true
                visible: !ruleDialog.bulkMode && ruleDialog.localRuleType === "application"
                    && root.supports("appPathScripts")
                    && (valueForm === "folder" || valueForm === "folder-tree"
                        || valueForm === "file-or-folder")
                wrapMode: Text.WordWrap
                color: ruleDialog.localRoute === "block" ? root.uiTheme.colorWarning : root.mutedTextColor
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                text: root.uiRevision >= 0
                    ? (ruleDialog.localRoute === "block"
                        ? root.tr("rules.application-folder-scripts-deny",
                            "A deny by folder stops the programs in it, but not for certain a script from it that an interpreter installed elsewhere runs.")
                        : root.tr("rules.application-folder-scripts",
                            "Scripts from this folder follow the rule too, even when an interpreter installed elsewhere runs them (a .py, .ps1, .bat, .sh or .jar file, say): from the moment their first connection is seen."))
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
                visible: !ruleDialog.bulkMode && ruleDialog.localRuleType === "domain"
                    && ruleDialog.localValue !== ""
                    && ruleDialog.isMatchValueValid(ruleDialog.localRuleType, ruleDialog.localValue)
                text: root.uiRevision >= 0 ? ruleDialog._coverageHint() : ""
            }
            // Offered ONLY when subdomain coverage is off machine-wide: with the
            // setting on, a "without subdomains" choice would be a lie — the
            // service expands every bare domain anyway.
            CheckBox {
                id: includeSubdomainsCheck
                Layout.fillWidth: true
                visible: !ruleDialog.bulkMode && ruleDialog.localRuleType === "domain"
                    && root.prefs.routeIncludeSubdomains === false
                    && !/\.\*$/.test(ruleDialog.localValue)
                checked: ruleDialog.localValue.indexOf("*.") === 0
                text: root.tr("dialog.rule.include-subdomains", "Include subdomains")
                contentItem: Label {
                    text: includeSubdomainsCheck.text
                    leftPadding: includeSubdomainsCheck.indicator.width + includeSubdomainsCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                Accessible.name: text
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
                visible: !ruleDialog.bulkMode && ruleDialog.localValue !== ""
                    && ruleDialog.isMatchValueRefused(ruleDialog.localRuleType, ruleDialog.localValue)
                text: root.uiRevision >= 0 ? ruleDialog.refusalText() : ""
            }
            // The value is another type's: one click gives the rule that type.
            RowLayout {
                Layout.fillWidth: true
                visible: !ruleDialog.bulkMode && ruleDialog.switchTypeTarget() !== ""
                ThemedButton {
                    theme: root.uiTheme
                    text: root.uiRevision >= 0 && ruleDialog.switchTypeTarget() !== ""
                        ? root.tr("rules.move-to-type.action", "Move to \u201c{type}\u201d")
                            .replace("{type}", root.ruleTypeLabel(ruleDialog.switchTypeTarget()))
                        : ""
                    onClicked: ruleDialog.switchToType(ruleDialog.switchTypeTarget())
                    ToolTip.visible: hovered && ToolTip.text !== ""
                    ToolTip.delay: 400
                    ToolTip.text: root.uiRevision >= 0
                        ? root.tr("rules.move-to-type.tooltip",
                            "Give this rule the type its value is. The line moves to that section of the rules file.")
                        : ""
                    Accessible.name: text
                    Accessible.description: ToolTip.text
                }
                Item { Layout.fillWidth: true }
            }
            // Saveable, but not quite what was typed or not fully protected — a
            // wide network, host bits cleared, an unusual address.
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.uiTheme.colorWarning
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                visible: !ruleDialog.bulkMode && ruleDialog.localValue !== ""
                    && ruleDialog.isMatchValueWarned(ruleDialog.localRuleType, ruleDialog.localValue)
                text: root.uiRevision >= 0 ? ruleDialog.warningText() : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            // A rule by path: how many programs it covers for this user now,
            // and what the service says about the place before it is saved.
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
                color: root.mutedTextColor
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                visible: !ruleDialog.bulkMode && text !== ""
                text: root.uiRevision >= 0 ? ruleDialog.coverageText() : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
                color: root.uiTheme.colorDanger
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                visible: !ruleDialog.bulkMode && text !== ""
                text: root.uiRevision >= 0 ? ruleDialog.coverageRefusalText() : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
                color: root.uiTheme.colorWarning
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                visible: !ruleDialog.bulkMode && text !== ""
                text: root.uiRevision >= 0 ? ruleDialog.coverageWarningText() : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: root.tr("label.target-route", "Target route")
                color: root.textColor
            }
            ThemedComboBox {
                id: routeTargetCombo
                theme: root.uiTheme
                Layout.fillWidth: true
                model: root.routeRoleOptions()
                textRole: "label"
                valueRole: "id"
                // The open list spells out what a deny does; the closed box keeps
                // the short word.
                labelResolver: function(item) { return routeTargetCombo._spoken(item) }
                function _spoken(item) {
                    if (!item) return ""
                    return String(item.description || "") !== "" ? item.description : item.label
                }
                readonly property var _current: currentIndex >= 0 && currentIndex < model.length
                    ? model[currentIndex] : null
                popup.width: root.comboPopupWidth(routeTargetCombo, model, "",
                    function(item) { return routeTargetCombo._spoken(item) })
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("label.target-route", "Target route") + ": "
                        + routeTargetCombo._spoken(routeTargetCombo._current)
                    : ""
                Accessible.description: ""
                ToolTip.visible: hovered && ToolTip.text !== ""
                ToolTip.delay: 400
                ToolTip.text: routeTargetCombo._current
                    ? String(routeTargetCombo._current.description || "") : ""
                onActivated: ruleDialog.localRoute = model[currentIndex].id
                // A new model (the type changed) resets the index; put it back.
                onModelChanged: Qt.callLater(ruleDialog._syncRouteCombo)
            }
            // Own width only, like the enable toggle: a row-wide hit area turns a
            // missed click into a changed rule.
            RowLayout {
                Layout.fillWidth: true
                visible: !ruleDialog.bulkMode
                CheckBox {
                    id: ruleVerifyCheck
                    enabled: ruleDialog.verifyOffered
                    checked: ruleDialog.localVerify
                    onToggled: ruleDialog.localVerify = checked
                    text: root.uiRevision >= 0
                        ? root.tr("dialog.rule.verify", "Unsure — check where it works")
                        : ""
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                    Accessible.description: verifyHint.text
                }
                Item { Layout.fillWidth: true }
            }
            Label {
                id: verifyHint
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                visible: !ruleDialog.bulkMode && (ruleDialog.anyZoneValue
                    || ruleDialog.verifyDroppedForIpv6
                    || ruleDialog.verifyRefusedByDeny
                    || (ruleDialog.verifyOffered && ruleDialog.localVerify))
                text: root.uiRevision >= 0
                    ? (ruleDialog.anyZoneValue
                        ? root.tr("dialog.rule.verify-any-zone",
                            "A site in every zone is not checked: the check needs one host.")
                        : ruleDialog.verifyDroppedForIpv6
                        ? root.tr("dialog.rule.verify-ipv6",
                            "An IPv6 address is not checked: the check goes out over IPv4 only, so this stays an ordinary route rule.")
                        : ruleDialog.verifyRefusedByDeny
                        ? root.tr("dialog.rule.verify-deny",
                            "A denied rule is not checked: its traffic goes through no connection.")
                        : root.tr("dialog.rule.verify-hint",
                            "Works through the route it is written for. If the site or address does not open there but does on the other route, NetRuleRouter offers to move the rule."))
                    : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            // The other route's rules this one overlaps, and which of them wins.
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
                color: root.mutedTextColor
                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                visible: !ruleDialog.bulkMode && text !== ""
                    && ruleDialog.isMatchValueValid(ruleDialog.localRuleType, ruleDialog.localValue)
                text: root.uiRevision >= 0 ? ruleDialog.overlapText() : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            RowLayout {
                Layout.fillWidth: true
                visible: !ruleDialog.bulkMode
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
                accessibleLabel: root.uiRevision >= 0 ? root.tr("label.comment", "Comment") : ""
                theme: root.uiTheme
                visible: !ruleDialog.bulkMode
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
                visible: !ruleDialog.bulkMode
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
                    if (root.uiRevision < 0 || ruleDialog.bulkMode) return ""
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
                    if (root.uiRevision < 0 || ruleDialog.bulkMode) return ""
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
}
