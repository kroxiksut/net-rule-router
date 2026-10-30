import QtQuick 2.15
import QtQuick.Controls 2.15

// Top-bar indicator showing the current per-user routing state.
// Reads `root.routingState` (mock-backed for now; SnapshotInitial-backed
// once wired). Click to jump to Settings → Routing where the user can
// pause/resume.
Rectangle {
    id: chip
    property var root
    property var theme: root.uiTheme

    readonly property string statusKey: root.routingStatusKey()
    readonly property color statusColor: {
        if (statusKey === "paused") return theme.colorWarning
        if (statusKey === "no-tray") return theme.colorTextMuted
        if (statusKey === "no-rules") return theme.colorTextMuted
        if (statusKey === "disconnected") return theme.colorTextMuted
        if (statusKey === "error") return theme.colorWarning
        if (statusKey === "limited") return theme.colorWarning
        return theme.colorSuccess
    }
    readonly property string labelText: {
        if (statusKey === "paused")
            return root.tr("routing.status.paused", "Rules are off")
        if (statusKey === "no-tray")
            return root.tr("routing.status.no-tray", "Tray icon not running")
        if (statusKey === "no-rules")
            return root.tr("routing.status.no-rules", "No rules")
        if (statusKey === "disconnected")
            return root.tr("routing.status.disconnected", "Service not connected")
        if (statusKey === "error")
            return root.tr("routing.status.error", "Rules not working")
        if (statusKey === "limited")
            return root.tr("routing.status.limited", "Some rules not working")
        return root.tr("routing.status.active", "Rules are working")
    }

    // What the state means, for the tooltip and the screen reader alike: a
    // tooltip is never the only place an explanation lives.
    readonly property string detailText: {
        if (chip.statusKey === "paused")
            return root.tr("routing.status.detail-paused",
                "Rules are off for the time chosen; they come back on their own when it is up, or when you turn them back on.")
        if (chip.statusKey === "no-tray")
            return root.tr("routing.status.detail-no-tray",
                "Start the tray icon so your rules work.")
        if (chip.statusKey === "no-rules")
            return root.tr("routing.status.detail-no-rules",
                "Add rules in the Rules section, then press Apply.")
        if (chip.statusKey === "disconnected")
            return root.tr("routing.status.detail-disconnected",
                "This is an example view. Install and start the NetRuleRouter service so your rules work.")
        // The notices' own headlines: what happens to the traffic differs
        // per status, and only the notice beside the chip says which.
        if (chip.statusKey === "limited")
            return root.enforcementDownDetail()
                || root.tr("routing.status.detail-limited",
                    "Some rules are not being applied right now. The notices say why.")
        return root.tr("routing.status.detail-active",
            "Your rules are working.")
    }

    implicitHeight: 26
    implicitWidth: chipRow.implicitWidth + theme.spacingMd * 2
    radius: theme.radiusSm
    color: Qt.rgba(statusColor.r, statusColor.g, statusColor.b, 0.16)
    border.width: activeFocus ? theme.focusBorderWidth : theme.borderWidth
    border.color: activeFocus
        ? theme.colorButtonOutline
        : Qt.rgba(statusColor.r, statusColor.g, statusColor.b, 0.55)

    signal clicked()

    activeFocusOnTab: visible
    Keys.onSpacePressed: chip.clicked()
    Keys.onReturnPressed: chip.clicked()
    Keys.onEnterPressed: chip.clicked()
    Accessible.role: Accessible.Button
    Accessible.name: chip.labelText
    Accessible.description: chip.detailText
    Accessible.onPressAction: chip.clicked()

    Row {
        id: chipRow
        anchors.centerIn: parent
        spacing: theme.spacingXs
        Rectangle {
            anchors.verticalCenter: parent.verticalCenter
            width: 8; height: 8; radius: 4
            color: chip.statusColor
        }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: chip.labelText
            color: theme.colorText
            font.pixelSize: theme.baseFontSizePx - 1
        }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: chip.clicked()
        hoverEnabled: true
        ToolTip.visible: containsMouse && root.prefs.tooltipsEnabled
        ToolTip.text: chip.detailText
    }
}
