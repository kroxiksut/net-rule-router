// Virtual machines: which route a hypervisor's traffic takes, and what each of
// its machines needs for site rules to work inside it.
//
// The route is chosen per hypervisor, never per machine: every machine runs as
// the same program, so no rule can tell two of them apart. The buttons edit the
// rules list the same way the application groups do; nothing reaches the
// service until the user applies the list.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../components"

ColumnLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    readonly property var controller: root.virtualMachinesController
    /// Set once a button here changed the rules, so the way to apply them
    /// stays in view.
    property bool rulesChanged: false

    Component.onCompleted: controller.refresh()

    function _hypervisorName(hypervisor) {
        var slug = String((hypervisor || {}).hypervisor || "")
        return root.tr("rules.vm.hypervisor." + slug, slug)
    }
    function _routeNow(hypervisor) {
        var name = section._hypervisorName(hypervisor)
        var route = section.controller.routeOf(hypervisor)
        if (route === "mixed")
            return root.tr("rules.vm.route-now-mixed",
                "The rules send {hypervisor}'s programs over different routes.")
                .replace("{hypervisor}", name)
        if (route === "block")
            return root.tr("rules.vm.route-now-block",
                "The rules block the traffic of every {hypervisor} machine.")
                .replace("{hypervisor}", name)
        return root.tr("rules.vm.route-now", "Every {hypervisor} machine goes over {route}.")
            .replace("{hypervisor}", name)
            .replace("{route}", root.routeLabel(route))
    }
    function _modeLabel(mode) {
        return root.tr("rules.vm.mode." + mode, mode)
    }
    function _adapterText(adapter) {
        var attachment = adapter.attachment || {}
        var mode = String(attachment.mode || "other")
        if (mode === "nat") {
            var advice = attachment.guestDns || {}
            var address = String(advice.address || "")
            if (advice.kind === "use-host-address")
                return root.tr("rules.vm.nat-dns",
                    "For your site rules to work inside this machine, set its DNS server to {address}.")
                    .replace("{address}", address)
            if (advice.command)
                return root.tr("rules.vm.nat-enable-first",
                    "For your site rules to work inside this machine, first let this adapter reach your computer: power the machine off and run the command below. Then set the machine's DNS server to {address}.")
                    .replace("{address}", address)
            return root.tr("rules.vm.nat-enable-first-no-tool",
                "For your site rules to work inside this machine, first let adapter {n} reach your computer with the VBoxManage option --nat-localhostreachable{n} while the machine is off. Then set the machine's DNS server to {address}.")
                .replace(/\{n\}/g, String(Number(adapter.slot) + 1))
                .replace("{address}", address)
        }
        if (mode === "bridged")
            return root.tr("rules.vm.bridged",
                "This adapter is bridged: its traffic goes straight to your network and bypasses your rules. Switch it to NAT for the rules to apply.")
        if (mode === "host-only")
            return root.tr("rules.vm.host-only",
                "Traffic stays between this machine and your computer. Nothing to route.")
        if (mode === "internal")
            return root.tr("rules.vm.internal",
                "Traffic stays between virtual machines. Nothing to route.")
        if (mode === "nat-network")
            return root.tr("rules.vm.nat-network",
                "NAT Network is not supported yet, so this adapter is not covered here.")
        return root.tr("rules.vm.other",
            "This adapter is not attached, or its kind is not supported yet.")
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.Wrap
            color: root.textColor
            text: root.uiRevision >= 0
                ? root.tr("rules.vm.intro",
                    "A virtual machine's traffic leaves your computer as the traffic of its hypervisor, so the route is chosen for the hypervisor and applies to all of its machines. Changes go to your rules list, where you review and apply them.")
                : ""
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("action.refresh", "Refresh")
            enabled: !section.controller.scanning
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section.controller.refresh()
        }
    }

    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: section.controller.scanFailed
        wrapMode: Text.Wrap
        color: root.uiTheme.colorDanger
        text: root.uiRevision >= 0
            ? root.tr("rules.vm.scan-failed", "Could not read the virtual machines. Try Refresh.")
            : ""
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }

    Frame {
        Layout.fillWidth: true
        visible: section.rulesChanged
        padding: root.uiTheme.spacingSm
        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
        RowLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.Wrap
                color: root.textColor
                text: root.uiRevision >= 0
                    ? root.tr("rules.vm.added-note",
                        "The rules are in your rules list. Review and apply them there.")
                    : ""
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.vm.open-rules", "Open rules list")
                Accessible.role: Accessible.Button
                Accessible.name: text
                // The edits are what the rules list shows, so leaving for it
                // loses nothing and the unsaved-changes prompt has nothing to ask.
                onClicked: root.section = "rules"
            }
        }
    }

    ScrollView {
        id: scroller
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: scroller.availableWidth
            spacing: root.uiTheme.spacingMd

            Repeater {
                model: section.controller.hypervisors
                delegate: ColumnLayout {
                    id: hypervisorBlock
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingMd
                    readonly property var hypervisor: modelData
                    readonly property var machines: hypervisor.machines || []
                    property int machineIndex: 0
                    readonly property var machine: machineIndex >= 0 && machineIndex < machines.length
                        ? machines[machineIndex] : null

                    Frame {
                        Layout.fillWidth: true
                        padding: root.uiTheme.spacingMd
                        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: root.uiTheme.spacingSm
                            Label {
                                Layout.fillWidth: true
                                font.bold: true
                                color: root.textColor
                                text: root.uiRevision >= 0 ? section._hypervisorName(hypervisorBlock.hypervisor) : ""
                                Accessible.role: Accessible.Heading
                                Accessible.name: text
                            }
                            Label {
                                Layout.fillWidth: true
                                Layout.preferredWidth: 0
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.uiRevision >= 0
                                    ? root.tr("rules.vm.route-scope",
                                        "{hypervisor} runs every machine as one program ({processes}), so a route applies to all of its machines.")
                                        .replace("{hypervisor}", section._hypervisorName(hypervisorBlock.hypervisor))
                                        .replace("{processes}", (hypervisorBlock.hypervisor.trafficProcesses || []).join(", "))
                                    : ""
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }
                            Label {
                                Layout.fillWidth: true
                                Layout.preferredWidth: 0
                                wrapMode: Text.Wrap
                                color: root.textColor
                                text: root.uiRevision >= 0 && section.controller.rulesRevision >= 0
                                    ? section._routeNow(hypervisorBlock.hypervisor) : ""
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }
                            Label {
                                Layout.fillWidth: true
                                Layout.preferredWidth: 0
                                visible: root.allowUserRuleEdits === false
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.uiRevision >= 0
                                    ? root.tr("rules.locked.banner-title", "Rules are managed by your administrator")
                                    : ""
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }
                            // Recipe 32: the layout sees the Item, not the positioner.
                            Item {
                                Layout.fillWidth: true
                                Layout.preferredHeight: routeButtons.height
                                Flow {
                                    id: routeButtons
                                    anchors.left: parent.left
                                    anchors.right: parent.right
                                    spacing: root.uiTheme.spacingSm
                                    Repeater {
                                        model: ["primary", "secondary"]
                                        delegate: ThemedButton {
                                            theme: root.uiTheme
                                            readonly property string route: modelData
                                            readonly property bool current: section.controller.rulesRevision >= 0
                                                && section.controller.routeOf(hypervisorBlock.hypervisor) === route
                                            text: root.uiRevision >= 0
                                                ? root.tr("rules.vm.route-button", "Send over {route}")
                                                    .replace("{route}", root.routeLabel(route))
                                                : ""
                                            highlighted: current
                                            enabled: !current && root.allowUserRuleEdits !== false
                                            Accessible.role: Accessible.Button
                                            Accessible.name: text
                                            onClicked: {
                                                section.controller.setRoute(hypervisorBlock.hypervisor, route)
                                                section.rulesChanged = true
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Frame {
                        Layout.fillWidth: true
                        padding: root.uiTheme.spacingMd
                        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: root.uiTheme.spacingSm

                            Label {
                                Layout.fillWidth: true
                                Layout.preferredWidth: 0
                                visible: hypervisorBlock.machines.length === 0
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.uiRevision >= 0
                                    ? root.tr("rules.vm.no-machines", "{hypervisor} has no machines yet.")
                                        .replace("{hypervisor}", section._hypervisorName(hypervisorBlock.hypervisor))
                                    : ""
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                visible: hypervisorBlock.machines.length > 0
                                spacing: root.uiTheme.spacingSm
                                Label {
                                    text: root.tr("rules.vm.machine-label", "Machine")
                                    color: root.mutedTextColor
                                }
                                ThemedComboBox {
                                    id: machineCombo
                                    theme: root.uiTheme
                                    Layout.fillWidth: true
                                    Layout.maximumWidth: 380
                                    model: hypervisorBlock.machines
                                    textRole: "name"
                                    labelResolver: function(item) { return item ? String(item.name) : "" }
                                    displayText: hypervisorBlock.machine ? String(hypervisorBlock.machine.name) : ""
                                    currentIndex: hypervisorBlock.machineIndex
                                    onActivated: hypervisorBlock.machineIndex = currentIndex
                                    Accessible.role: Accessible.ComboBox
                                    Accessible.name: root.tr("rules.vm.machine-label", "Machine")
                                }
                            }

                            Label {
                                Layout.fillWidth: true
                                Layout.preferredWidth: 0
                                visible: hypervisorBlock.machine !== null
                                    && (hypervisorBlock.machine.adapters || []).length === 0
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.uiRevision >= 0
                                    ? root.tr("rules.vm.no-adapters", "This machine has no network adapters.")
                                    : ""
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }

                            Repeater {
                                model: hypervisorBlock.machine ? (hypervisorBlock.machine.adapters || []) : []
                                delegate: ColumnLayout {
                                    id: adapterBlock
                                    Layout.fillWidth: true
                                    spacing: root.uiTheme.spacingXs
                                    readonly property var adapter: modelData
                                    readonly property var attachment: adapter.attachment || {}
                                    readonly property var advice: attachment.guestDns || null

                                    Label {
                                        Layout.fillWidth: true
                                        Layout.topMargin: root.uiTheme.spacingXs
                                        font.bold: true
                                        color: root.textColor
                                        text: root.uiRevision >= 0
                                            ? root.tr("rules.vm.adapter-title", "Adapter {n}: {mode}")
                                                .replace("{n}", String(Number(adapterBlock.adapter.slot) + 1))
                                                .replace("{mode}", section._modeLabel(String(adapterBlock.attachment.mode || "other")))
                                            : ""
                                        Accessible.role: Accessible.StaticText
                                        Accessible.name: text
                                    }
                                    Label {
                                        Layout.fillWidth: true
                                        Layout.preferredWidth: 0
                                        wrapMode: Text.Wrap
                                        color: adapterBlock.attachment.mode === "bridged"
                                            ? root.uiTheme.colorDanger : root.textColor
                                        text: root.uiRevision >= 0 ? section._adapterText(adapterBlock.adapter) : ""
                                        Accessible.role: Accessible.StaticText
                                        Accessible.name: text
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        visible: !!(adapterBlock.advice && adapterBlock.advice.command)
                                        spacing: root.uiTheme.spacingSm
                                        Label {
                                            Layout.fillWidth: true
                                            Layout.preferredWidth: 0
                                            wrapMode: Text.WrapAnywhere
                                            font.family: "Consolas, Courier New, monospace"
                                            color: root.textColor
                                            text: adapterBlock.advice && adapterBlock.advice.command
                                                ? String(adapterBlock.advice.command) : ""
                                            Accessible.role: Accessible.StaticText
                                            Accessible.name: text
                                        }
                                        ThemedButton {
                                            theme: root.uiTheme
                                            text: root.tr("action.copy", "Copy")
                                            Accessible.role: Accessible.Button
                                            Accessible.name: text + " " + String(adapterBlock.advice ? adapterBlock.advice.command : "")
                                            onClicked: root.copyToClipboard(String(adapterBlock.advice.command))
                                        }
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        visible: !!adapterBlock.advice
                                        spacing: root.uiTheme.spacingSm
                                        Label {
                                            Layout.fillWidth: true
                                            font.family: "Consolas, Courier New, monospace"
                                            color: root.textColor
                                            text: adapterBlock.advice ? String(adapterBlock.advice.address) : ""
                                            Accessible.role: Accessible.StaticText
                                            Accessible.name: text
                                        }
                                        ThemedButton {
                                            theme: root.uiTheme
                                            text: root.tr("action.copy", "Copy")
                                            Accessible.role: Accessible.Button
                                            Accessible.name: text + " " + String(adapterBlock.advice ? adapterBlock.advice.address : "")
                                            onClicked: root.copyToClipboard(String(adapterBlock.advice.address))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
