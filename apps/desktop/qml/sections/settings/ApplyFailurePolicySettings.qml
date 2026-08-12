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

    // Pre-flight is gated behind the Experimental opt-in (its checks are not
    // implemented yet, see ExperimentalSettings.qml). A user who already has
    // it selected keeps seeing it even with the opt-in off — we never swap a
    // saved choice out from under them — but it does not appear as a pickable
    // option for anyone else until they opt in.
    readonly property bool preFlightOptedIn:
        root.uiRevision >= 0 && root.prefs.preFlightApplyPolicyOptIn === true
    readonly property bool preFlightAlreadySelected:
        currentSlug === "pre-flight-then-all-or-nothing"

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
        if (group.preFlightOptedIn || group.preFlightAlreadySelected) {
            defs.push({
                slug: "pre-flight-then-all-or-nothing",
                labelKey: "settings.routing.failure-policy.option.pre-flight.label",
                labelFallback: "Pre-flight, then all-or-nothing (experimental)",
                descKey: group.preFlightAlreadySelected && !group.preFlightOptedIn
                    ? "settings.routing.failure-policy.option.pre-flight.description-stale"
                    : "settings.routing.failure-policy.option.pre-flight.description",
                descFallback: group.preFlightAlreadySelected && !group.preFlightOptedIn
                    ? "Selected, but the Experimental opt-in for this option is off. The checks are still in development — this behaves the same as All or nothing today."
                    : "Run predictable-failure checks before applying. Apply still rolls back on real errors. The checks themselves are still in development — this behaves the same as All or nothing today."
            })
        }
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
