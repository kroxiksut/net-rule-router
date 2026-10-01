import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// One line per machine-wide service setting where the value this user chose
// earlier differs from what the service holds. Shown instead of silently
// overwriting another administrator's choice; the user settles it here.
ColumnLayout {
    id: note

    /// The ApplicationWindow: `tr()`, colours, the intent controller and the
    /// setting/value labels the pending-changes dialog already owns.
    property var root
    /// The stability wire keys this panel draws controls for.
    property var keys: []

    readonly property var lines: (root && root.uiRevision >= 0 && root.serviceIntentController)
        ? _lines(root.serviceIntentController.divergence) : []

    function _lines(divergence) {
        var labels = root.offlinePendingController
        var out = []
        for (var i = 0; i < keys.length; i += 1) {
            var key = keys[i]
            if (!divergence || !divergence.hasOwnProperty(key)) continue
            var row = divergence[key]
            out.push({ "key": key, "text": root.tr("settings.service-intent.admin-value",
                    "{setting}: the service uses “{service}” (set by an administrator); your choice was “{mine}”.")
                .replace("{setting}", labels._offlineRoutingKeyLabel("stability", key))
                .replace("{service}", labels._offlineRoutingValueLabel("stability", key, row["service"]))
                .replace("{mine}", labels._offlineRoutingValueLabel("stability", key, row["mine"])) })
        }
        return out
    }

    visible: lines.length > 0
    Layout.fillWidth: true
    spacing: root ? root.uiTheme.spacingXxs : 2

    Repeater {
        model: note.lines
        delegate: ColumnLayout {
            required property var modelData
            Layout.fillWidth: true
            spacing: note.root.uiTheme.spacingXxs

            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                text: modelData.text
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                color: note.root.mutedTextColor
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: note.root.uiTheme.spacingSm

                ThemedButton {
                    theme: note.root.uiTheme
                    text: note.root.tr("settings.service-intent.apply-mine", "Apply my choice")
                    Accessible.name: text
                    Accessible.description: modelData.text
                    ToolTip.visible: hovered && note.root.prefs.tooltipsEnabled
                    ToolTip.delay: 400
                    ToolTip.text: note.root.tr("settings.service-intent.apply-mine-tooltip",
                        "Send your choice to the service. This setting applies to everyone on this computer, so the system may ask for administrator approval.")
                    onClicked: note.root.serviceIntentController.applyMine(modelData.key)
                }
                ThemedButton {
                    theme: note.root.uiTheme
                    text: note.root.tr("settings.service-intent.keep-service", "Keep the service value")
                    Accessible.name: text
                    Accessible.description: modelData.text
                    ToolTip.visible: hovered && note.root.prefs.tooltipsEnabled
                    ToolTip.delay: 400
                    ToolTip.text: note.root.tr("settings.service-intent.keep-service-tooltip",
                        "Forget your earlier choice and leave the service as it is.")
                    onClicked: note.root.serviceIntentController.keepServiceValue(modelData.key)
                }
                Item { Layout.fillWidth: true }
            }
        }
    }
}
