import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs

// Add / Edit rule dialog (extracted from Main.qml).
//
// The dialog keeps its `ruleDialog` id so Main.qml's wiring — the
// `property alias ruleDialog`, the overlays array, and the RulesSection calls
// through `root.ruleDialog.{resetForEdit,open,normalizeHostInput}` — is
// unchanged. All shared state (models, theme, window helpers such as
// `saveRule`, `ruleTypeLabel`, `routeRoleOptions`, `comboPopupWidth`,
// `_punycodeFor`, `platformProfile`) comes in through `root` (the
// ApplicationWindow). The dialog's own fields and validators stay local.
Dialog {
    id: ruleDialog

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    x: Math.round((root.width - width) / 2)
    y: Math.round((root.height - height) / 2)
    width: 560
    modal: false
    palette: root.palette
    title: root.editingRule >= 0 ? root.tr("dialog.rule.edit", "Edit") : root.tr("dialog.rule.add", "Add")
    standardButtons: Dialog.Ok | Dialog.Cancel
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
    // Free rules (it moved to Pro). When Edit opens on a pre-existing block
    // rule we keep the option in the target-route combo so saving doesn't
    // silently downgrade it to `primary`. Latched in resetForEdit(), so the
    // combo model stays stable for the whole dialog session.
    property bool allowBlockRoute: false
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
        if (routeTargetCombo) {
            var roleOpts = root.routeRoleOptions(allowBlockRoute)
            var rIdx = 0
            for (var i = 0; i < roleOpts.length; i += 1) {
                if (roleOpts[i].id === localRoute) { rIdx = i; break }
            }
            routeTargetCombo.currentIndex = rIdx
        }
    }
    // Comment max length is also enforced by the rules-file parser via
    // RulesFileEntry, the back-end validators and docs/en/rules-file-format.md. Keep these
    // four numbers in sync if you ever change one.
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
    // ceilings are enforced separately via `maximumLength`. Strict
    // semantic validation runs in `isMatchValueValid()` and gates the
    // OK button.
    //
    // - `exact-ip` accepts only digits and dots up to 15 chars; full
    //   IPv4 form + per-octet range is checked in isMatchValueValid().
    // - `zone` is a single DNS label — letters/digits/hyphens, no dots
    //   (compound zones like `corp.internal` are rare; if needed, the
    //   user can edit the rules file directly).
    // - `domain` accepts any Unicode letter/digit (Cyrillic, IDN etc.)
    //   plus dot, hyphen, and `*` for the suffix glob.
    // - `application` uses Windows filename rules — every char except
    //   OS-forbidden `< > : " / \ | ?` and control codes, so scripts
    //   (.ps1/.bat/.sh) and Unicode names all pass.
    function matchValueRegex(ruleType) {
        if (ruleType === "exact-ip") {
            return new RegExp("^[0-9.]{0,15}$")
        }
        // Permissive validators — only enforce the per-type length cap.
        // Qt's `RegularExpressionValidator` rejects characters that don't
        // match, which silently blocks Cyrillic / Unicode input on some
        // Qt builds when `\p{L}` or `\u…` ranges are used. The strict
        // semantic check in `isMatchValueValid()` still gates OK, so we
        // can afford to accept anything intermediate here and keep the
        // text field usable on every keyboard layout.
        if (ruleType === "zone")        return new RegExp("^.{0,63}$")
        if (ruleType === "domain")      return new RegExp("^.{0,253}$")
        if (ruleType === "application") return new RegExp("^.{0,260}$")
        return new RegExp("^.*$")
    }
    function matchValueMaxLength(ruleType) {
        if (ruleType === "zone")        return 63
        if (ruleType === "domain")      return 253
        if (ruleType === "exact-ip")    return 15
        if (ruleType === "application") return 260
        return 260
    }
    // Strict semantic validation. Empty values are invalid; per-type
    // rules below. First octet of an IPv4 must be ≥ 1 (0.x.x.x is
    // reserved). Any octet > 255 is rejected. Returns true only when
    // the value can be saved.
    function isMatchValueValid(ruleType, raw) {
        var v = String(raw || "").trim()
        if (v === "") return false
        if (ruleType === "exact-ip") {
            if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return false
            var parts = v.split(".")
            for (var i = 0; i < 4; i += 1) {
                var n = parseInt(parts[i], 10)
                if (isNaN(n)) return false
                if (i === 0 && n < 1) return false
                if (n < 0 || n > 255) return false
            }
            return true
        }
        if (ruleType === "zone") {
            // Strip optional leading dot so `.ru` and `ru` are both
            // accepted forms of the same zone (docs/en/rules-file-format.md uses `.ru`).
            if (v.charAt(0) === ".") v = v.substring(1)
            // Accept any Unicode letter/digit as an IDN label, not just a
            // hardcoded Latin+Greek+Cyrillic subset — `\u0080-\uFFFF`
            // covers Tamil (இந்தியா), CJK (中国), Arabic, Devanagari, etc.
            // Deliberately a SOFT filter (looser than the backend): the
            // Rust SSOT (`rule_value_validation`) strictly validates IDN
            // via UTS-46 (`idna`) on apply, so client pre-validation must
            // never be stricter than the backend.
            return /^[A-Za-z0-9\u0080-\uFFFF-]{1,63}$/.test(v)
        }
        if (ruleType === "domain") {
            if (v.length > 253) return false
            return /^(\*\.)?[A-Za-z0-9\u0080-\uFFFF-]+(\.[A-Za-z0-9\u0080-\uFFFF-]+)*$/.test(v)
        }
        if (ruleType === "application") {
            return /^[^<>:"/\\|?\x00-\x1f]{1,260}$/.test(v)
        }
        return false
    }
    // Paste convenience: when the user pastes a full URL copied from a
    // browser (e.g. `https://www.whatismyip.com/`), reduce it to the bare
    // host so the value passes validation. Applies only to hostname-shaped
    // types — `exact-ip` and `application` values are left untouched. Kept
    // deliberately soft (the Rust `rule_value_validation` SSOT re-validates
    // on apply); it acts only when the text actually looks like a URL, so
    // ordinary typing of a plain hostname is never disturbed.
    function normalizeHostInput(ruleType, raw) {
        if (ruleType !== "zone" && ruleType !== "domain"
                && ruleType !== "suffix-domain" && ruleType !== "exact-fqdn") {
            return raw
        }
        var s = String(raw || "")
        if (!/[:\/@?#]/.test(s)) return raw
        s = s.replace(/^[A-Za-z][A-Za-z0-9\u0080-\uFFFF-]*:\/\//, "") // scheme://
        s = s.replace(/^[^@\/]*@/, "")                        // user:pass@
        s = s.replace(/[\/?#].*$/, "")                        // path/query/fragment
        s = s.replace(/:\d+$/, "")                            // :port
        s = s.toLowerCase()
        // Drop a leading `www.` for broad-match types so a pasted
        // `www.site.com` becomes `site.com` (apex + subdomains). `exact-fqdn`
        // keeps `www.` — there the exact host is the whole point.
        if (ruleType === "domain" || ruleType === "suffix-domain") {
            s = s.replace(/^www\./, "")
        }
        return s
    }

    onAccepted: {
        if (!isMatchValueValid(localRuleType, localValue)) {
            // Re-open the dialog: the inline-warning label is already
            // visible and the OK button stays disabled. This branch only
            // catches Enter-key submission against an invalid value.
            open()
            return
        }
        root.saveRule()
    }
    // Bind the OK button's enabled state to per-type validation. The
    // standardButton lookup is done once on creation; the binding
    // itself reacts to localRuleType / localValue changes thereafter.
    Component.onCompleted: {
        var okBtn = ruleDialog.standardButton(Dialog.Ok)
        if (okBtn) {
            okBtn.enabled = Qt.binding(function() {
                // App rules ARE saveable now — they route the app's observed
                // destinations via the secondary (app-routing via observation).
                return ruleDialog.isMatchValueValid(ruleDialog.localRuleType,
                    ruleDialog.localValue)
            })
        }
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
        Label { text: root.tr("label.match-value", "Match value"); color: root.textColor }
        ThemedTextField {
            id: matchValueField
            theme: root.uiTheme
            Layout.fillWidth: true
            text: ruleDialog.localValue
            onTextChanged: {
                // Reduce a pasted browser URL to its bare host (a no-op for
                // plain hostnames, IPs and application names).
                var norm = ruleDialog.normalizeHostInput(ruleDialog.localRuleType, text)
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
            // Length cap per rule type — `zone` 63, `domain` 253,
            // `exact-ip` 15, `application` 260 (Windows MAX_PATH).
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
                text: root.tr("rules.app-browse", "Browse…")
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
        // Inline validation message — visible only when the field has
        // text but fails the strict per-type check. Blank value is
        // simply "incomplete" and not flagged as an error.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.uiTheme.colorDanger
            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
            visible: ruleDialog.localValue !== ""
                && !ruleDialog.isMatchValueValid(ruleDialog.localRuleType, ruleDialog.localValue)
            text: root.uiRevision >= 0
                ? root.tr("rules.validation.match-value-invalid." + ruleDialog.localRuleType,
                    root.tr("rules.validation.error", "Invalid value"))
                : ""
        }
        Label { text: root.tr("label.target-route", "Target route"); color: root.textColor }
        ThemedComboBox {
            id: routeTargetCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: root.routeRoleOptions(ruleDialog.allowBlockRoute)
            textRole: "label"
            valueRole: "id"
            popup.width: root.comboPopupWidth(routeTargetCombo, model, "label", null)
            onActivated: ruleDialog.localRoute = model[currentIndex].id
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
            placeholderText: (root.uiRevision, root.tr("rules.comment.max-length",
                "Up to {max} characters").replace("{max}", ruleDialog.commentMaxLength))
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
