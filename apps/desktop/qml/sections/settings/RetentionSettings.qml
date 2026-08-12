import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

// Mock-state panel for retention configuration. Reads/writes
// `root.routingState.retentionSettings`. A later revision will replace direct
// mutations with an IPC round-trip (RetentionSettingsGet/Set) — the field
// shape here mirrors `nrr-storage::RetentionSettings` so the wire-up is a
// straight swap.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.revisions.retention.title", "Revisions retention")
    Layout.fillWidth: true

    readonly property var current: (root.uiRevision >= 0)
        ? (root.routingState.retentionSettings || {}) : {}

    // Local edit buffer — committed via Save so the panel does not surface
    // intermediate invalid values to the (mocked) backend.
    property int draftSupersededDays: current.supersededDays || 30
    property int draftSupersededCountCap: current.supersededCountCap || 100
    property int draftRejectedDays: current.rejectedDays || 7
    property int draftRolledbackDays: current.rolledbackDays || 14
    property int draftRolledbackCountCap: current.rolledbackCountCap || 20
    property bool draftPinLkg: current.pinLkg !== false
    property bool draftDirty: false
    property bool justSaved: false

    function reloadFromCurrent() {
        draftSupersededDays = current.supersededDays || 30
        draftSupersededCountCap = current.supersededCountCap || 100
        draftRejectedDays = current.rejectedDays || 7
        draftRolledbackDays = current.rolledbackDays || 14
        draftRolledbackCountCap = current.rolledbackCountCap || 20
        draftPinLkg = current.pinLkg !== false
        draftDirty = false
    }

    Component.onCompleted: reloadFromCurrent()

    function markDirty() { draftDirty = true; justSaved = false }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm

        Label {
            Layout.fillWidth: true
            text: root.tr("settings.revisions.retention.description",
                "Controls how long superseded, rejected, and rolled-back revisions are kept before pruning.")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }

        GridLayout {
            Layout.fillWidth: true
            columns: 3
            columnSpacing: root.uiTheme.spacingMd
            rowSpacing: root.uiTheme.spacingXs

            Label {
                Layout.fillWidth: true
                text: root.tr("settings.revisions.retention.superseded-days",
                    "Keep superseded revisions for (days)")
                color: root.textColor
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                editable: true
                from: 7; to: 365
                value: group.draftSupersededDays
                onValueModified: { group.draftSupersededDays = value; group.markDirty() }
            }
            Label {
                text: "(7–365)"
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                Layout.fillWidth: true
                text: root.tr("settings.revisions.retention.superseded-count",
                    "Maximum superseded revisions")
                color: root.textColor
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                editable: true
                stepSize: 10
                from: 20; to: 1000
                value: group.draftSupersededCountCap
                onValueModified: { group.draftSupersededCountCap = value; group.markDirty() }
            }
            Label {
                text: "(20–1000)"
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                Layout.fillWidth: true
                text: root.tr("settings.revisions.retention.rejected-days",
                    "Keep rejected revisions for (days)")
                color: root.textColor
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                editable: true
                from: 1; to: 90
                value: group.draftRejectedDays
                onValueModified: { group.draftRejectedDays = value; group.markDirty() }
            }
            Label {
                text: "(1–90)"
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                Layout.fillWidth: true
                text: root.tr("settings.revisions.retention.rolledback-days",
                    "Keep rolled-back revisions for (days)")
                color: root.textColor
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                editable: true
                from: 1; to: 90
                value: group.draftRolledbackDays
                onValueModified: { group.draftRolledbackDays = value; group.markDirty() }
            }
            Label {
                text: "(1–90)"
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                Layout.fillWidth: true
                text: root.tr("settings.revisions.retention.rolledback-count",
                    "Maximum rolled-back revisions")
                color: root.textColor
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                editable: true
                from: 5; to: 100
                value: group.draftRolledbackCountCap
                onValueModified: { group.draftRolledbackCountCap = value; group.markDirty() }
            }
            Label {
                text: "(5–100)"
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                Layout.alignment: Qt.AlignVCenter
            }
        }

        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.revisions.retention.pin-lkg",
                "Always keep last known-good revision")
            checked: group.draftPinLkg
            onToggled: { group.draftPinLkg = checked; group.markDirty() }
        }

        Label {
            Layout.fillWidth: true
            text: root.tr("settings.revisions.retention.pin-lkg-hint",
                "The most recent superseded revision is pinned and excluded from age and count limits.")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm

            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                text: {
                    var ts = group.current.lastCleanupAt || ""
                    if (ts === "") return root.tr("settings.revisions.retention.last-cleanup-never",
                                                  "Last cleanup: never")
                    return root.tr("settings.revisions.retention.last-cleanup",
                                   "Last cleanup: {timestamp}").replace("{timestamp}", ts)
                }
            }
            Label {
                visible: group.justSaved
                color: root.uiTheme.colorAccent
                text: root.tr("settings.revisions.retention.saved", "Saved")
            }
            ThemedButton {
                theme: root.uiTheme
                enabled: group.draftDirty
                text: root.tr("settings.revisions.retention.save", "Save")
                icon.source: root.uiIconSource("save")
                onClicked: {
                    root.setRetentionSettings({
                        supersededDays: group.draftSupersededDays,
                        supersededCountCap: group.draftSupersededCountCap,
                        rejectedDays: group.draftRejectedDays,
                        rolledbackDays: group.draftRolledbackDays,
                        rolledbackCountCap: group.draftRolledbackCountCap,
                        pinLkg: group.draftPinLkg
                    })
                    group.draftDirty = false
                    group.justSaved = true
                }
            }
        }
    }
}
