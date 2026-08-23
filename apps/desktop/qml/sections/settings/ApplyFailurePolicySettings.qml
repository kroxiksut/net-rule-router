import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Mock-state panel for ApplyFailurePolicy. Slug values match
// `nrr-storage::policy_settings::VALID_POLICY_SLUGS` so a later revision can swap the
// setter for the IPC call without changing the QML.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.routing.failure-policy.title", "Apply failure policy")
    Layout.fillWidth: true

    readonly property string currentSlug: (root.uiRevision >= 0)
        ? (root.routingState.applyFailurePolicy || "best-effort")
        : "best-effort"

    readonly property var optionDefs: {
        var defs = [
            {
                slug: "best-effort",
                labelKey: "settings.routing.failure-policy.option.best-effort.label",
                labelFallback: "Best effort (recommended)",
                descKey: "settings.routing.failure-policy.option.best-effort.description",
                descFallback: "Rules that can't be enforced on this host (app not installed, host not yet resolved, missing adapter) are skipped and reported; the rest are applied. Default."
            },
            {
                slug: "all-or-nothing",
                labelKey: "settings.routing.failure-policy.option.all-or-nothing.label",
                labelFallback: "All or nothing",
                descKey: "settings.routing.failure-policy.option.all-or-nothing.description",
                descFallback: "If any single rule can't be enforced, the whole apply rolls back. Exact-or-nothing."
            }
        ]
        defs.push({
            slug: "pre-flight-then-all-or-nothing",
            labelKey: "settings.routing.failure-policy.option.pre-flight.label",
            labelFallback: "Check first, then all or nothing",
            descKey: "settings.routing.failure-policy.option.pre-flight.description",
            descFallback: "Checks the change before touching anything and refuses to start when it cannot be applied as one piece — a very large rule set is applied in several parts, and this option would rather stop than leave half of it live. Rules that would be stored without enforcing anything (a program that is not installed) are reported, not blocked."
        })
        return defs
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.routing.failure-policy.description",
                "Choose how the service handles partial failures during multi-step rule application.")
        }

        ButtonGroup { id: policyGroup }

        Repeater {
            model: group.optionDefs
            delegate: ColumnLayout {
                Layout.fillWidth: true
                spacing: 0
                RadioButton {
                    Layout.fillWidth: true
                    ButtonGroup.group: policyGroup
                    checked: group.currentSlug === modelData.slug
                    text: root.tr(modelData.labelKey, modelData.labelFallback)
                    onClicked: root.setApplyFailurePolicy(modelData.slug)
                }
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: root.uiTheme.spacingLg
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr(modelData.descKey, modelData.descFallback)
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingXs
            spacing: root.uiTheme.spacingSm
            Image {
                Layout.preferredWidth: 16
                Layout.preferredHeight: 16
                Layout.alignment: Qt.AlignTop
                source: root.uiIconSource("shield")
                sourceSize.width: 16
                sourceSize.height: 16
                fillMode: Image.PreserveAspectFit
            }
            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.italic: true
                text: root.tr("settings.routing.failure-policy.requires-elevation",
                    "Changing this setting requires administrator elevation.")
            }
        }
    }
}
