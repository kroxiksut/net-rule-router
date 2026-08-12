// Duplicate-rule modal. Two-button pattern: "Open existing" jumps to the
// offending row in Edit mode; "Cancel" returns to the in-progress form.
// Extracted from Main.qml (thin-shell refactor).
//
// The dialog is "dumb": it emits `openExistingRequested(index)` and the
// caller (Main.qml) performs the ruleDialog manipulation, because ruleDialog
// itself is still inline in Main.qml (extraction deferred). Shared state
// comes in through `ownerRoot` (the ApplicationWindow).
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Master-model index of the existing rule that collides.
    property int duplicateIndex: -1
    /// Display id of the colliding rule (rendered into the body text).
    property string duplicateId: ""
    /// Fired when the user picks "Open existing"; caller opens that row in
    /// the (still-inline) rule editor.
    signal openExistingRequested(int index)

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.rule.duplicate-title", "Rule already exists")
    modal: true
    standardButtons: Dialog.NoButton
    x: root.ownerRoot ? Math.round((root.ownerRoot.width - width) / 2) : 0
    y: root.ownerRoot ? Math.round((root.ownerRoot.height - height) / 2) : 0
    width: 480
    palette: root.ownerRoot ? root.ownerRoot.palette : palette
    contentItem: ColumnLayout {
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 440
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.rule.duplicate-body",
                "A rule with the same type, value, and target route already exists ({id}). Open the existing rule to change it, or cancel to keep editing the new one.")
                    .replace("{id}", root.duplicateId)
        }
        RowLayout {
            Layout.fillWidth: true
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.rule.duplicate-open-existing", "Open existing")
                onClicked: {
                    var idx = root.duplicateIndex
                    root.close()
                    root.openExistingRequested(idx)
                }
            }
        }
    }
}
