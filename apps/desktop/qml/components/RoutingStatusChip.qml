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
        return theme.colorSuccess
    }
    readonly property string labelText: {
        if (statusKey === "paused")
            return root.tr("routing.status.paused", "Routing paused")
        if (statusKey === "no-tray")
            return root.tr("routing.status.no-tray", "Tray offline")
        if (statusKey === "no-rules")
            return root.tr("routing.status.no-rules", "No rules configured")
        if (statusKey === "disconnected")
            return root.tr("routing.status.disconnected", "Service not connected")
        if (statusKey === "error")
            return root.tr("routing.status.error", "Routing error")
        return root.tr("routing.status.active", "Routing active")
    }

    implicitHeight: 26
    implicitWidth: chipRow.implicitWidth + theme.spacingMd * 2
    radius: theme.radiusSm
    color: Qt.rgba(statusColor.r, statusColor.g, statusColor.b, 0.16)
    border.width: theme.borderWidth
    border.color: Qt.rgba(statusColor.r, statusColor.g, statusColor.b, 0.55)

    signal clicked()

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
        ToolTip.text: {
            if (chip.statusKey === "paused")
                return root.tr("routing.status.detail-paused",
                    "Rules are disabled until you re-enable them.")
            if (chip.statusKey === "no-tray")
                return root.tr("routing.status.detail-no-tray",
                    "Run the tray icon to apply rules on this session.")
            if (chip.statusKey === "no-rules")
                return root.tr("routing.status.detail-no-rules",
                    "Add rules in the Rules section, then click Save and review.")
            if (chip.statusKey === "disconnected")
                return root.tr("routing.status.detail-disconnected",
                    "Showing preview data. Install and start the NetRuleRouter service to apply rules.")
            return root.tr("routing.status.detail-active",
                "Rules apply on this user session.")
        }
    }
}
