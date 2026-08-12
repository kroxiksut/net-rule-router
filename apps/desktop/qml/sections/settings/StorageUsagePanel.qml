import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

// Mock-state read-only storage usage panel. On-demand scan only
// (per design — walking %ProgramData% on every GUI open would be wasteful).
// Refresh will be wired to a StorageUsageGet IPC call.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.storage.title", "Storage usage")
    Layout.fillWidth: true

    readonly property var bytes: (root.uiRevision >= 0)
        ? (root.routingState.storageUsageBytes || {}) : {}
    readonly property string scanState: (root.uiRevision >= 0)
        ? String(root.routingState.storageUsageScanState || "idle") : "idle"

    function rowText(key, fallback, byteValue) {
        var label = root.tr(key, fallback)
        if (group.scanState === "idle") return label + ": —"
        if (group.scanState === "scanning")
            return label + ": " + root.tr("settings.storage.scanning", "Scanning…")
        return label + ": " + Pure.formatStorageBytes(byteValue)
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.storage.description",
                "On-disk footprint of the service state, cache, and log stores.")
        }

        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingSm
            background: CardSurface {
                theme: root.uiTheme
                cornerRadius: root.uiTheme.radiusSm
            }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingXs

                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    text: group.rowText("settings.storage.state-db",
                        "Service state database", group.bytes.stateDb || 0)
                }
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    text: group.rowText("settings.storage.cache-db",
                        "FQDN/IP cache", group.bytes.cacheDb || 0)
                }
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    text: group.rowText("settings.storage.operational-logs",
                        "Operational logs", group.bytes.operationalLogs || 0)
                }
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    text: group.rowText("settings.storage.audit-logs",
                        "Audit logs", group.bytes.auditLogs || 0)
                }
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 1
                    color: root.uiTheme.colorBorder
                }
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    font.bold: true
                    text: group.rowText("settings.storage.total",
                        "Total", group.bytes.total || 0)
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.storage.refresh", "Refresh")
                icon.source: root.uiIconSource("refresh")
                enabled: group.scanState !== "scanning"
                onClicked: root.refreshStorageUsage()
            }
            Item { Layout.fillWidth: true }
            Label {
                visible: group.scanState === "scanning"
                color: root.mutedTextColor
                text: root.tr("settings.storage.scanning", "Scanning…")
            }
        }
    }
}
