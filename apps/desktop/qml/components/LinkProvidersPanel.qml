import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

// The programs confirmed as providers of the additional link (a VPN client):
// listed as the service holds them (`root.linkProviderApps`), added by path,
// removed after a second click. Every change goes through
// `root._replaceLinkProviders`, which works it out over a fresh read.
// Below them, the other VPNs' servers the user allowed, each removable.
ColumnLayout {
    id: panel
    property var root
    spacing: root.uiTheme.spacingSm

    readonly property bool _loaded: root.linkProviderAppsKnown
    readonly property bool _busy: root._linkProvidersWriting
    readonly property var _apps: root.linkProviderApps || []
    // Path of the row waiting for its second click.
    property string _confirming: ""

    function _fileName(path) {
        return Pure.vpnProviderNames([{ "exe-path": path }])[0]
    }
    function _nameOf(app) {
        return Pure.displayText(Pure.vpnProviderNames([app || {}])[0])
    }
    function _readable() {
        return root.bridgeAvailable && typeof nrrNativeBridge !== "undefined" && nrrNativeBridge !== null
            && typeof nrrNativeBridge.rpcSnapshotInitialGet === "function"
    }
    function refresh() {
        if (!panel._readable()) return
        var corr = nrrNativeBridge.rpcSnapshotInitialGet()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p) {
            if (!ok) return
            root._recordLinkProvidersFrom(p)
            root.confirmedVpnGateways = (p && p["confirmed-vpn-gateways"]) || []
        })
    }
    function addProgram() {
        var path = pathField.text.trim()
        if (path === "") {
            root.statusLine = root.tr("settings.routing.providers.need-path",
                "Type the program's full path first.")
            return
        }
        root._replaceLinkProviders(function(existing) {
            return Pure.vpnClientTrustConfirmedApps(existing,
                { exePath: path, name: "", bundledExePaths: [] }, false)
        }, function() {
            pathField.text = ""
            return root.tr("vpn-onboarding.confirmed-status",
                "NetRuleRouter will keep {name} working over your main link while leak protection is on.")
                .replace("{name}", Pure.displayText(panel._fileName(path)))
        })
    }
    function removeProgram(path) {
        var gone = ""
        root._replaceLinkProviders(function(existing) {
            for (var i = 0; i < existing.length; i += 1) {
                if (String(existing[i]["exe-path"] || "").toLowerCase() === path.toLowerCase())
                    gone = panel._nameOf(existing[i])
            }
            return Pure.vpnClientTrustRemovedApps(existing, path)
        }, function() {
            return root.tr("settings.routing.providers.removed",
                "{name} was removed. Leak protection no longer keeps it working over your main link.")
                .replace("{name}", gone !== "" ? gone : Pure.displayText(panel._fileName(path)))
        }, function() { panel._confirming = "" })
    }
    // Address of the allowed VPN server waiting for its second click.
    property string _confirmingGateway: ""
    function _gatewayLabel(g) {
        var offer = Pure.vpnGatewayOffers([g])[0] || { address: "", program: "", name: "" }
        return Pure.displayText(offer.address) + " (" + (offer.program !== ""
            ? Pure.displayText(offer.name)
            : root.tr("settings.vpn-gateways.system", "built into the system")) + ")"
    }
    function removeGateway(address) {
        root._writeVpnGateways(Pure.vpnGatewaysRemoved(root.confirmedVpnGateways || [], address), function() {
            panel._confirmingGateway = ""
            root.statusLine = root.tr("settings.vpn-gateways.removed-status",
                "The VPN server {address} is no longer let through.")
                .replace("{address}", Pure.displayText(address))
        })
    }

    Component.onCompleted: refresh()
    onVisibleChanged: if (visible) refresh()

    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        color: root.mutedTextColor
        wrapMode: Text.WordWrap
        font.pixelSize: root.uiTheme.baseFontSizePx - 1
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.providers.note",
                "Programs that keep working over your main link while leak protection is on, such as your VPN client. Type a program's full path to add one.")
            : ""
    }
    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: panel._loaded && panel._apps.length === 0
        color: root.textColor
        wrapMode: Text.WordWrap
        text: root.uiRevision >= 0
            ? root.tr("settings.routing.providers.empty", "No programs are confirmed yet.") : ""
    }
    Repeater {
        model: panel._apps
        delegate: RowLayout {
            id: row
            required property var modelData
            readonly property string path: String(modelData["exe-path"] || "")
            readonly property string title: root.uiRevision >= 0
                ? root.tr("settings.routing.providers.remove", "Remove {name} ({path})")
                    .replace("{name}", panel._nameOf(modelData))
                    .replace("{path}", Pure.displayText(path))
                : ""
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                color: root.textColor
                wrapMode: Text.WrapAnywhere
                textFormat: Text.PlainText
                text: panel._nameOf(row.modelData) + " (" + Pure.displayText(row.path) + ")"
            }
            ThemedButton {
                theme: root.uiTheme
                enabled: !panel._busy
                visible: panel._confirming !== row.path
                text: root.uiRevision >= 0 ? root.tr("action.remove", "Remove") : ""
                Accessible.name: row.title
                onClicked: panel._confirming = row.path
            }
            ThemedButton {
                theme: root.uiTheme
                enabled: !panel._busy
                visible: panel._confirming === row.path
                text: root.uiRevision >= 0 ? root.tr("action.confirm", "Confirm") : ""
                Accessible.name: row.title
                onClicked: panel.removeProgram(row.path)
            }
            ThemedButton {
                theme: root.uiTheme
                visible: panel._confirming === row.path
                text: root.uiRevision >= 0 ? root.tr("action.cancel", "Cancel") : ""
                onClicked: panel._confirming = ""
            }
        }
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        ThemedTextField {
            id: pathField
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.maximumWidth: 460
            enabled: panel._loaded && !panel._busy
            placeholderText: root.uiRevision >= 0
                ? root.tr("settings.routing.providers.new", "Program to add (full path)") : ""
            Accessible.name: placeholderText
            onAccepted: panel.addProgram()
        }
        ThemedButton {
            theme: root.uiTheme
            enabled: panel._loaded && !panel._busy && pathField.text.trim() !== ""
            text: root.uiRevision >= 0 ? root.tr("action.add", "Add") : ""
            onClicked: panel.addProgram()
        }
    }

    ColumnLayout {
        id: gatewaysGroup
        readonly property var gateways: root.confirmedVpnGateways || []
        Layout.fillWidth: true
        Layout.topMargin: root.uiTheme.spacingSm
        spacing: root.uiTheme.spacingSm
        visible: gateways.length > 0
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            color: root.textColor
            font.bold: true
            wrapMode: Text.WordWrap
            text: root.uiRevision >= 0
                ? root.tr("settings.vpn-gateways.title", "Other VPNs you allowed") : ""
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.uiRevision >= 0
                ? root.tr("settings.vpn-gateways.note",
                    "Their servers can be reached over the main connection while leak protection is on, for the VPN's own connection only.")
                : ""
        }
        Repeater {
            model: gatewaysGroup.gateways
            delegate: RowLayout {
                id: gatewayRow
                required property var modelData
                readonly property string address: String(modelData["address"] || "")
                readonly property string title: root.uiRevision >= 0
                    ? root.tr("settings.vpn-gateways.remove", "Remove the allowed VPN server {address}")
                        .replace("{address}", Pure.displayText(address))
                    : ""
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    color: root.textColor
                    wrapMode: Text.WrapAnywhere
                    textFormat: Text.PlainText
                    text: root.uiRevision >= 0 ? panel._gatewayLabel(gatewayRow.modelData) : ""
                }
                ThemedButton {
                    theme: root.uiTheme
                    enabled: !root._vpnGatewaysWriting
                    visible: panel._confirmingGateway !== gatewayRow.address
                    text: root.uiRevision >= 0 ? root.tr("action.remove", "Remove") : ""
                    Accessible.name: gatewayRow.title
                    onClicked: panel._confirmingGateway = gatewayRow.address
                }
                ThemedButton {
                    theme: root.uiTheme
                    enabled: !root._vpnGatewaysWriting
                    visible: panel._confirmingGateway === gatewayRow.address
                    text: root.uiRevision >= 0 ? root.tr("action.confirm", "Confirm") : ""
                    Accessible.name: gatewayRow.title
                    onClicked: panel.removeGateway(gatewayRow.address)
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: panel._confirmingGateway === gatewayRow.address
                    text: root.uiRevision >= 0 ? root.tr("action.cancel", "Cancel") : ""
                    onClicked: panel._confirmingGateway = ""
                }
            }
        }
    }
}
