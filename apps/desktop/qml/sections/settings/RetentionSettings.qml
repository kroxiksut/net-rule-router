import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

// Revision-history retention, service-owned (`settings.retention.*`). Edits
// stay a local draft until Save, which also prunes with the new limits.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.revisions.retention.title", "Revisions retention")
    Layout.fillWidth: true

    readonly property var current: (root.uiRevision >= 0)
        ? (root.routingState.retentionSettings || {}) : {}
    // The service's defaults (`RetentionSettingsSetRequest::DEFAULT`; a GUI
    // test holds the two equal).
    readonly property var defaults: ({
        supersededDays: 30,
        supersededCountCap: 100,
        rejectedDays: 7,
        rolledbackDays: 14,
        rolledbackCountCap: 20,
        pinLkg: true
    })

    // Committed by Save, so half-typed values never reach the service.
    property int draftSupersededDays: current.supersededDays || defaults.supersededDays
    property int draftSupersededCountCap: current.supersededCountCap || defaults.supersededCountCap
    property int draftRejectedDays: current.rejectedDays || defaults.rejectedDays
    property int draftRolledbackDays: current.rolledbackDays || defaults.rolledbackDays
    property int draftRolledbackCountCap: current.rolledbackCountCap || defaults.rolledbackCountCap
    property bool draftPinLkg: current.pinLkg !== false
    property bool draftDirty: false
    property bool justSaved: false

    function loadDraft(values) {
        draftSupersededDays = values.supersededDays || defaults.supersededDays
        draftSupersededCountCap = values.supersededCountCap || defaults.supersededCountCap
        draftRejectedDays = values.rejectedDays || defaults.rejectedDays
        draftRolledbackDays = values.rolledbackDays || defaults.rolledbackDays
        draftRolledbackCountCap = values.rolledbackCountCap || defaults.rolledbackCountCap
        draftPinLkg = values.pinLkg !== false
    }

    function reloadFromCurrent() {
        loadDraft(current)
        draftDirty = false
    }

    // Defaults go into the draft only: Save still decides, as for any edit.
    function resetToDefaults() {
        loadDraft(defaults)
        markDirty()
    }

    readonly property bool draftIsDefault: draftSupersededDays === defaults.supersededDays
        && draftSupersededCountCap === defaults.supersededCountCap
        && draftRejectedDays === defaults.rejectedDays
        && draftRolledbackDays === defaults.rolledbackDays
        && draftRolledbackCountCap === defaults.rolledbackCountCap
        && draftPinLkg === defaults.pinLkg

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
                // The label beside it carries the meaning; the tip says what the number buys.
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.superseded-days",
                        "Keep superseded revisions for (days)") : ""
                ToolTip.visible: hovered || activeFocus
                ToolTip.delay: 400
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.superseded-days-tooltip",
                        "Earlier versions of your rules that you can roll back to. Keep them longer for a longer history, or shorter to save disk space.") : ""
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
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.superseded-count",
                        "Maximum superseded revisions") : ""
                ToolTip.visible: hovered || activeFocus
                ToolTip.delay: 400
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.superseded-count-tooltip",
                        "The most earlier versions kept, whatever their age. Once there are more, the oldest go first.") : ""
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
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.rejected-days",
                        "Keep rejected revisions for (days)") : ""
                ToolTip.visible: hovered || activeFocus
                ToolTip.delay: 400
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.rejected-days-tooltip",
                        "Rule sets the service refused to apply are kept this long, so the history still shows why they were refused.") : ""
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
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.rolledback-days",
                        "Keep rolled-back revisions for (days)") : ""
                ToolTip.visible: hovered || activeFocus
                ToolTip.delay: 400
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.rolledback-days-tooltip",
                        "Rule sets that were undone, by you or after a failed apply, are kept this long so you can return to them.") : ""
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
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.rolledback-count",
                        "Maximum rolled-back revisions") : ""
                ToolTip.visible: hovered || activeFocus
                ToolTip.delay: 400
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("settings.revisions.retention.rolledback-count-tooltip",
                        "The most undone rule sets kept, whatever their age. Once there are more, the oldest go first.") : ""
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
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            Accessible.description: root.uiRevision >= 0
                ? root.tr("settings.revisions.retention.pin-lkg-hint",
                    "The most recent superseded revision is pinned and excluded from age and count limits.") : ""
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
                    // Epoch seconds on the wire.
                    var secs = Number(group.current.lastCleanupAt || 0)
                    if (!(secs > 0)) return root.tr("settings.revisions.retention.last-cleanup-never",
                                                  "Last cleanup: never")
                    return root.tr("settings.revisions.retention.last-cleanup",
                                   "Last cleanup: {timestamp}")
                        .replace("{timestamp}", Pure.formatTimestamp(secs * 1000))
                }
            }
            Label {
                visible: group.justSaved
                color: root.uiTheme.colorAccent
                text: root.tr("settings.revisions.retention.saved", "Saved")
            }
            ThemedButton {
                theme: root.uiTheme
                enabled: !group.draftIsDefault
                text: root.tr("action.reset-defaults", "Reset to defaults")
                Accessible.name: text
                onClicked: group.resetToDefaults()
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
