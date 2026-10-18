import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

// "Other VPNs (corporate)": a VPN that has to reach its gateway through one
// channel gets an ordinary rule for that gateway. The service lists where the
// program connected lately; the rule goes into the list on screen and reaches
// the service through the usual review and apply.
ColumnLayout {
    id: helper
    property var root
    spacing: root.uiTheme.spacingSm

    property bool _loading: false
    property bool _ran: false
    property string _failure: ""
    property bool _observerActive: true
    property int _omitted: 0
    property var _candidates: []
    // Values ticked for a rule, keyed by the address or name itself. Replaced,
    // never mutated, so the bindings that read it re-evaluate.
    property var _selected: ({})
    property var _detected: []
    property bool _detecting: false
    property int _added: 0

    readonly property string _route: routeCombo.currentIndex === 0 ? "primary" : "secondary"
    readonly property string _commentTemplate: root.uiRevision >= 0
        ? root.tr("settings.routing.vpn-gateway.rule-comment", "VPN gateway: {program}") : ""

    function _draftFor(value) {
        return Rules.vpnGatewayRuleDraft(value, programField.text, helper._route,
            helper._commentTemplate)
    }
    function _isSelected(value) { return helper._selected[value] === true }
    function _setSelected(value, on) {
        var next = {}
        for (var k in helper._selected) {
            if (helper._selected[k] === true) next[k] = true
        }
        if (on) next[value] = true
        else delete next[value]
        helper._selected = next
    }
    // In list order, the manual entry last; a value is drafted once.
    function _drafts() {
        var out = []
        var seen = {}
        var push = function(value) {
            var d = helper._draftFor(value)
            if (d === null || seen[d["rule-type"] + "|" + d.value] === true) return
            seen[d["rule-type"] + "|" + d.value] = true
            out.push(d)
        }
        for (var i = 0; i < helper._candidates.length; i += 1) {
            var c = helper._candidates[i] || {}
            if (helper._isSelected(String(c.address || ""))) push(String(c.address || ""))
            var host = String(c.hostname || "")
            if (host !== "" && helper._isSelected(host)) push(host)
        }
        if (manualField.text.trim() !== "") push(manualField.text)
        return out
    }
    function _reset() {
        helper._candidates = []
        helper._selected = ({})
        helper._ran = false
        helper._failure = ""
        helper._omitted = 0
        helper._added = 0
    }

    function find() {
        var program = Rules.vpnProgramFileName(programField.text)
        if (program === "" || helper._loading) return
        if (!root.rpc || typeof root.rpc.rpcVpnGatewayCandidatesList !== "function") return
        helper._reset()
        helper._loading = true
        var corr = root.rpc.rpcVpnGatewayCandidatesList(program)
        if (!corr) {
            helper._loading = false
            helper._ran = true
            helper._failure = "transport-disconnected"
            return
        }
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            helper._loading = false
            helper._ran = true
            if (!ok || !payload) {
                helper._failure = String(code || "unknown")
                return
            }
            var list = payload.candidates || []
            helper._candidates = list
            helper._omitted = Number(payload.omitted || 0)
            helper._observerActive = payload["observer-active"] !== false
            // The likeliest gateway is ticked; the user unticks it if wrong.
            if (list.length > 0) helper._setSelected(String(list[0].address || ""), true)
        })
    }

    // The detection list the VPN set-up uses, offered as names to pick from.
    function detect() {
        if (helper._detecting || !root.rpc || typeof root.rpc.rpcVpnDiscover !== "function") return
        var corr = root.rpc.rpcVpnDiscover()
        if (!corr) return
        helper._detecting = true
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            helper._detecting = false
            if (!ok || !payload) return
            var names = []
            var list = payload.candidates || []
            for (var i = 0; i < list.length; i += 1) {
                var c = list[i] || {}
                if (String(c.source || "") === "kernel-tunnel") continue
                var name = Rules.vpnProgramFileName(c["exe-path"] || c.exePath || "")
                if (name !== "" && names.indexOf(name) < 0) names.push(name)
            }
            helper._detected = names
            detectedCombo.currentIndex = -1
        })
    }

    function addRules() {
        var drafts = helper._drafts()
        if (drafts.length === 0 || typeof root.addRuleDrafts !== "function") return
        var added = root.addRuleDrafts(drafts)
        // Cleared first: editing the field hides the hint.
        if (added > 0) manualField.text = ""
        helper._added = added
    }

    function _candidateText(c) {
        var ports = (c.ports || []).join(", ")
        return root.tr("settings.routing.vpn-gateway.candidate",
            "{address} · ports {ports} · last seen {time}")
            .replace("{address}", String(c.address || ""))
            .replace("{ports}", ports)
            .replace("{time}", Pure.formatTimestamp(c["last-seen-ms"]))
    }

    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        Layout.topMargin: root.uiTheme.spacingSm
        color: root.textColor
        font.bold: true
        wrapMode: Text.WordWrap
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.vpn-gateway.title", "Other VPNs (corporate)") : ""
    }
    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        color: root.mutedTextColor
        wrapMode: Text.WordWrap
        font.pixelSize: root.uiTheme.baseFontSizePx - 1
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.vpn-gateway.note",
                "For a VPN that connects only from one network, such as a work VPN allowed only from abroad: its gateway gets a rule for the channel you choose, so it always connects through that channel. If that channel is down, the VPN does not connect over the other one.")
            : ""
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Label {
            color: root.textColor
            text: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.program", "VPN program") : ""
        }
        ThemedTextField {
            id: programField
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.maximumWidth: 320
            placeholderText: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.program-placeholder",
                    "Program file name, for example corpvpn.exe") : ""
            Accessible.name: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.program", "VPN program") : ""
            onTextChanged: helper._reset()
            onAccepted: helper.find()
        }
        ThemedButton {
            theme: root.uiTheme
            enabled: !helper._detecting
            text: root.uiRevision >= 0 ? root.tr("vpn-onboarding.scan", "Scan for VPN apps") : ""
            onClicked: helper.detect()
        }
    }
    ThemedComboBox {
        id: detectedCombo
        theme: root.uiTheme
        visible: helper._detected.length > 0
        Layout.fillWidth: true
        Layout.maximumWidth: 460
        model: helper._detected
        currentIndex: -1
        labelResolver: function(item) { return Pure.displayText(item) }
        displayText: root.uiRevision >= 0 && currentIndex >= 0
            ? Pure.displayText(helper._detected[currentIndex])
            : root.tr("settings.routing.vpn-gateway.detected", "Pick a found program")
        onActivated: function(index) { programField.text = String(helper._detected[index] || "") }
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Label {
            color: root.textColor
            text: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.channel", "Connect it through") : ""
        }
        ThemedComboBox {
            id: routeCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.maximumWidth: 320
            // A fixed model: rebuilding it on every preference change would
            // reset the choice.
            model: ["primary", "secondary"]
            labelResolver: function(item) { return root.routeLabel(String(item)) }
            currentIndex: 1
            displayText: root.uiRevision >= 0 && currentIndex >= 0
                ? root.routeLabel(currentIndex === 0 ? "primary" : "secondary") : ""
            Accessible.name: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.channel", "Connect it through") : ""
        }
        ThemedButton {
            theme: root.uiTheme
            enabled: !helper._loading && Rules.vpnProgramFileName(programField.text) !== ""
            text: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.find", "Find gateway addresses") : ""
            onClicked: helper.find()
        }
    }

    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: text !== ""
        color: helper._failure !== "" ? root.uiTheme.colorDanger : root.mutedTextColor
        wrapMode: Text.WordWrap
        text: {
            if (root.uiRevision < 0) return ""
            if (helper._loading)
                return root.tr("settings.routing.vpn-gateway.finding", "Looking at recent connections...")
            if (!helper._ran) return ""
            if (helper._failure !== "")
                return root.tr("settings.routing.vpn-gateway.failed", "Could not read the connections: ")
                    + (typeof root.ipcErrorLabel === "function"
                        ? root.ipcErrorLabel(helper._failure) : helper._failure)
            if (!helper._observerActive && helper._candidates.length === 0)
                return root.tr("settings.routing.vpn-gateway.observer-off",
                    "On this system NetRuleRouter cannot see where a program connects. Type the gateway address below.")
            if (helper._candidates.length === 0)
                return root.tr("settings.routing.vpn-gateway.empty",
                    "{program} has not connected anywhere on the internet recently. Start the VPN and let it try to connect, then search again.")
                    .replace("{program}", Pure.displayText(Rules.vpnProgramFileName(programField.text)))
            return ""
        }
    }

    Repeater {
        model: helper._candidates
        delegate: ColumnLayout {
            required property var modelData
            Layout.fillWidth: true
            spacing: 0
            CheckBox {
                id: addressCheck
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                checked: helper._isSelected(String(modelData.address || ""))
                text: root.uiRevision >= 0 ? helper._candidateText(modelData) : ""
                contentItem: Label {
                    text: addressCheck.text
                    leftPadding: addressCheck.indicator.width + addressCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: helper._setSelected(String(modelData.address || ""), checked)
            }
            CheckBox {
                id: nameCheck
                visible: String(modelData.hostname || "") !== ""
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                Layout.leftMargin: root.uiTheme.spacingLg
                checked: helper._isSelected(String(modelData.hostname || ""))
                text: root.uiRevision >= 0
                    ? root.tr("settings.routing.vpn-gateway.by-name", "By name: {host}")
                        .replace("{host}", Pure.displayText(modelData.hostname))
                    : ""
                contentItem: Label {
                    text: nameCheck.text
                    textFormat: Text.PlainText
                    leftPadding: nameCheck.indicator.width + nameCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: helper._setSelected(String(modelData.hostname || ""), checked)
            }
        }
    }
    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: helper._omitted > 0
        color: root.mutedTextColor
        wrapMode: Text.WordWrap
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.vpn-gateway.omitted", "Addresses not shown: {count}.")
                .replace("{count}", String(helper._omitted))
            : ""
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        ThemedTextField {
            id: manualField
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.maximumWidth: 320
            placeholderText: root.uiRevision >= 0
                ? root.tr("settings.routing.vpn-gateway.manual-placeholder",
                    "Or type the gateway address or name") : ""
            Accessible.name: placeholderText
            onTextChanged: helper._added = 0
            onAccepted: helper.addRules()
        }
        ThemedButton {
            theme: root.uiTheme
            enabled: helper._drafts().length > 0
            text: root.uiRevision >= 0 ? root.tr("settings.routing.vpn-gateway.add", "Add rules") : ""
            onClicked: helper.addRules()
        }
    }
    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: manualField.text.trim() !== ""
            && Rules.vpnProgramFileName(programField.text) !== ""
            && helper._draftFor(manualField.text) === null
        color: root.uiTheme.colorDanger
        wrapMode: Text.WordWrap
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.vpn-gateway.manual-invalid",
                "This is neither an address nor a host name.") : ""
    }
    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: helper._added > 0
        color: root.mutedTextColor
        wrapMode: Text.WordWrap
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.vpn-gateway.apply-hint",
                "The rules are in your list now. Apply the changes to put them into effect.")
            : ""
    }
}
