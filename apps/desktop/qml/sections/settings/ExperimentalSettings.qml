import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

// Experimental settings. Detailed mode and the virtual-machines screen are
// working toggles and sit above the divider; kill-switch mode A is dormant and
// sits below it, disabled, until its re-verification lands.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.group.experimental", "Experimental")
    Layout.fillWidth: true

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        Label {
            Layout.fillWidth: true
            text: root.tr("settings.note.experimental",
                "Early features that are still being tested. They are off by default and may change or be removed.")
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
                        "Shows extra fine-tuning switches under Settings → Routing. Off by default: without it, NetRuleRouter uses sensible defaults for them. The main routing switches stay visible either way.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }

        // Reveals the Rules -> Virtual machines screen. Off by default: routing
        // a hypervisor's traffic is unverified on real hardware, so the screen
        // ships hidden until it is.
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
                        id: vmSectionCheck
                        Layout.fillWidth: true
                        text: root.tr("settings.experimental.vm-section.label",
                            "Virtual machines screen")
                        checked: root.uiRevision >= 0
                            ? (root.prefs.showVirtualMachinesSection === true) : false
                        Accessible.role: Accessible.CheckBox
                        Accessible.name: text
                        Accessible.description: root.tr("settings.experimental.in-development",
                            "In development")
                        contentItem: Label {
                            text: vmSectionCheck.text
                            leftPadding: vmSectionCheck.indicator.width + vmSectionCheck.spacing
                            color: root.textColor
                            wrapMode: Text.WordWrap
                            verticalAlignment: Text.AlignVCenter
                        }
                        onToggled: {
                            root.updatePrefs({ showVirtualMachinesSection: checked })
                            root.emitPrefs()
                            if (checked) {
                                root.virtualMachinesController.refresh()
                            } else if (root.section === "rule-virtual-machines") {
                                root.requestSectionChange("rules")
                            }
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
                    text: root.tr("settings.experimental.vm-section.note",
                        "Adds a Virtual machines screen under Rules that sends a hypervisor's traffic over the route you pick. Not verified on real hardware yet: the screen may be incomplete and the route may not apply to every machine.")
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

        // Legacy kill-switch mode A opt-in. Off by default; when on, the routing
        // settings reveal the historical reactive mode A option in the
        // enforcement-mechanism selector. Device-local display preference — it
        // commits immediately and never arms the footer Apply/Cancel. Disabled
        // pending its own re-verification pass.
        Frame {
            Layout.fillWidth: true
            enabled: false
            // Mode A rides the system-DNS observer; where the OS has none, the
            // opt-in would reveal a mode the routing settings cannot offer.
            visible: root.supports("dnsObserve")
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
                            "Allow the legacy routing method (watching system DNS)")
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
                        "Watching system DNS is the legacy routing method, kept for reference only. It is not maintained, may not work, and may be removed in a future release; the supported method is the local DNS resolver. Turn this on only if you specifically need to choose it in the routing settings.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
