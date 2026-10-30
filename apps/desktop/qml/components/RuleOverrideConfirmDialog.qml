// Confirming a rule the protection of system programs and folders refuses
// (`+override` in the rules file). The service says what the rule would take
// and what stops working; the person types the rule's value and chooses how
// long it applies. A rule that reaches past its owner needs an administrator:
// the window's broker asks on Windows, polkit asks on Linux, both on Confirm.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

Dialog {
    id: dialog

    /// ApplicationWindow injected by the caller (`ownerRoot: root`).
    property var ownerRoot: null
    /// The rule as the table holds it, and its route slug.
    property string ruleValue: ""
    property string ruleRoute: ""
    /// The service's answer to the preview; null while it is asked.
    property var preview: null
    property bool busy: false
    property string errorText: ""
    property string typedValue: ""
    property string term: "one-day"
    /// Fired once the service confirmed the rule.
    signal granted(var grant)

    readonly property var termOptions: ["one-hour", "one-day", "one-week", "until-revoked"]
    readonly property string status: preview ? String(preview.status || "") : ""
    readonly property bool confirmable: status === "ready" || status === "granted"
    readonly property string os: ownerRoot && ownerRoot.platformProfile
        ? String(ownerRoot.platformProfile.os || "") : ""
    readonly property bool typedMatches: confirmable && typedValue !== ""
        && Rules.ruleOverrideKey("application", typedValue, ruleRoute, os)
            === Rules.ruleOverrideKey("application", String(preview.value || ""), ruleRoute, os)

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") return ownerRoot.tr(key, fallback)
        return fallback
    }

    /// Ask the service about the rule and open.
    function openFor(value, route) {
        ruleValue = String(value || "")
        ruleRoute = String(route || "")
        preview = null
        errorText = ""
        typedValue = ""
        term = "one-day"
        busy = true
        open()
        var rpc = ownerRoot ? ownerRoot.rpc : null
        var corr = rpc && typeof rpc.rpcRulesOverridePreview === "function"
            ? rpc.rpcRulesOverridePreview(ruleValue, ruleRoute) : ""
        if (!corr) {
            busy = false
            errorText = ownerRoot ? ownerRoot.ipcErrorLabel("transport-disconnected") : ""
            return
        }
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            dialog.busy = false
            if (!ok || !payload) {
                dialog.errorText = dialog.ownerRoot ? dialog.ownerRoot.ipcErrorLabel(code) : ""
                return
            }
            dialog.preview = payload
        })
    }

    function _confirm() {
        if (!typedMatches || busy) return
        var rpc = ownerRoot ? ownerRoot.rpc : null
        var corr = rpc && typeof rpc.rpcRulesOverrideGrant === "function"
            ? rpc.rpcRulesOverrideGrant(String(preview.token || ""), typedValue, term) : ""
        if (!corr) {
            errorText = ownerRoot ? ownerRoot.ipcErrorLabel("transport-disconnected") : ""
            return
        }
        busy = true
        errorText = ""
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            dialog.busy = false
            if (!ok || !payload) {
                dialog.errorText = dialog.ownerRoot ? dialog.ownerRoot.ipcErrorLabel(code) : ""
                return
            }
            dialog.close()
            dialog.granted(payload.granted || null)
        })
    }

    /// The protection's own words for why the rule is held.
    function reasonText(reason) {
        var r = String(reason || "")
        if (r === "") return ""
        return tr("rules.validation.match-value-invalid.protected-" + r, r)
    }

    /// An account in words a person reads.
    function accountText(account) {
        var a = String(account || "")
        if (a === "S-1-5-18") return tr("rules.override.account.system", "the system (SYSTEM)")
        if (a === "S-1-5-19") return tr("rules.override.account.local-service", "LOCAL SERVICE")
        if (a === "S-1-5-20") return tr("rules.override.account.network-service", "NETWORK SERVICE")
        if (a === "unix:uid:0") return tr("rules.override.account.root", "root")
        return Pure.displayText(a)
    }

    function _list(items, mapper) {
        var out = []
        var list = items || []
        for (var i = 0; i < list.length; i += 1) out.push(mapper ? mapper(list[i]) : Pure.displayText(list[i]))
        return out.join(", ")
    }

    function _statusText() {
        switch (status) {
        case "not-requested":
            return tr("rules.override.status.not-requested",
                "Save the rule with +override after its value first; then confirm it here.")
        case "not-protected":
            return tr("rules.override.status.not-protected",
                "Nothing to confirm: the protection does not hold this rule.")
        case "not-allowed":
            return tr("rules.override.status.not-allowed",
                "This rule cannot be applied despite the protection.") + " " + reasonText(preview.reason)
        case "unavailable":
            return tr("rules.override.status.unavailable",
                "The service cannot keep confirmations right now, so none can be given.")
        default:
            return ""
        }
    }

    title: tr("rules.override.dialog.title", "Apply despite the protection?")
    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 560
    standardButtons: Dialog.NoButton
    closePolicy: Popup.CloseOnEscape
    header: DialogDragHeader {
        dialog: dialog
        theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
        titleText: dialog.title
    }
    contentItem: ColumnLayout {
        spacing: 10
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.bold: true
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            text: Pure.displayText(dialog.preview ? dialog.preview.value : dialog.ruleValue)
                + " — " + (dialog.ownerRoot && typeof dialog.ownerRoot.routeLabel === "function"
                    ? dialog.ownerRoot.routeLabel(dialog.ruleRoute) : dialog.ruleRoute)
        }
        Label {
            Layout.fillWidth: true
            visible: dialog.busy && !dialog.preview
            wrapMode: Text.Wrap
            color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            text: dialog.tr("rules.override.dialog.reading", "Reading what the rule would take...")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            visible: dialog.preview !== null && !dialog.confirmable
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            text: dialog._statusText()
        }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 6
            visible: dialog.confirmable
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: dialog.preview ? dialog.reasonText(dialog.preview.reason) : ""
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: !dialog.preview ? ""
                    : (dialog.preview["programs-over-cap"] === true
                        ? dialog.tr("rules.override.dialog.programs-over-cap",
                            "Programs it takes: more than {count}.")
                        : dialog.tr("rules.override.dialog.programs", "Programs it takes: {count}."))
                        .replace("{count}", String(Number(dialog.preview.programs || 0)))
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: dialog.preview !== null && (dialog.preview["critical-processes"] || []).length > 0
                color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.colorDanger : palette.text
                text: !dialog.preview ? ""
                    : dialog.tr("rules.override.dialog.critical",
                        "System processes it takes: {list}.")
                        .replace("{list}", dialog._list(dialog.preview["critical-processes"]))
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: dialog.preview !== null && (dialog.preview["service-accounts"] || []).length > 0
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: !dialog.preview ? ""
                    : dialog.tr("rules.override.dialog.accounts",
                        "Running under service accounts: {list}.")
                        .replace("{list}", dialog._list(dialog.preview["service-accounts"],
                            dialog.accountText))
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: dialog.preview !== null && Number(dialog.preview["other-users"] || 0) > 0
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: !dialog.preview ? ""
                    : dialog.tr("rules.override.dialog.other-users",
                        "Other users run what it takes: {count}.")
                        .replace("{count}", String(Number(dialog.preview["other-users"] || 0)))
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: dialog.preview !== null && (dialog.preview.breaks || []).length > 0
                color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.colorWarning : palette.text
                text: !dialog.preview ? ""
                    : dialog.tr("rules.override.dialog.breaks", "What may stop working: {list}.")
                        .replace("{list}", dialog._list(dialog.preview.breaks, function(slug) {
                            return dialog.tr("rules.override.breaks." + String(slug), String(slug))
                        }))
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: dialog.preview !== null && dialog.preview["needs-administrator"] === true
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: dialog.tr("rules.override.dialog.administrator",
                    "It reaches past your own programs, so confirming it needs administrator rights.")
            }
            Label {
                Layout.fillWidth: true
                Layout.topMargin: 6
                wrapMode: Text.Wrap
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: dialog.tr("rules.override.dialog.type", "To confirm, type the rule's value: {value}")
                    .replace("{value}", Pure.displayText(dialog.preview ? dialog.preview.value : ""))
            }
            ThemedTextField {
                id: typedField
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                Layout.fillWidth: true
                text: dialog.typedValue
                onTextChanged: dialog.typedValue = text
                Accessible.name: dialog.tr("rules.override.dialog.type-label", "The rule's value")
                Keys.onReturnPressed: dialog._confirm()
                Keys.onEnterPressed: dialog._confirm()
            }
            Label {
                Layout.fillWidth: true
                Layout.topMargin: 6
                wrapMode: Text.Wrap
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: dialog.tr("rules.override.dialog.term", "Applies for")
            }
            LogWindowDurationCombo {
                id: termCombo
                root: dialog.ownerRoot
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                options: dialog.termOptions
                labelFor: function(slug) { return dialog.tr("rules.override.term." + slug, slug) }
                Layout.fillWidth: true
                currentIndex: Math.max(0, dialog.termOptions.indexOf(dialog.term))
                displayText: dialog.tr("rules.override.term." + dialog.term, dialog.term)
                onActivated: function(index) { dialog.term = dialog.termOptions[index] }
                Accessible.name: dialog.tr("rules.override.dialog.term", "Applies for") + ": " + displayText
            }
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            visible: dialog.errorText !== ""
            color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.colorDanger : palette.text
            text: dialog.errorText
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.confirmable ? dialog.tr("action.cancel", "Cancel")
                    : dialog.tr("action.close", "Close")
                onClicked: dialog.close()
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                visible: dialog.confirmable
                enabled: dialog.typedMatches && !dialog.busy
                highlighted: true
                text: dialog.tr("rules.override.dialog.confirm", "Apply despite the protection")
                Accessible.name: text
                onClicked: dialog._confirm()
            }
        }
    }
}
