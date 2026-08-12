// Confirm dialog: "Load active rules from the service" discards unsaved
// local edits. Extracted from Main.qml (
// thin-shell refactor). The dialog is "dumb": it emits `confirmed()` and
// the caller (Main.qml) runs the reload. Shared state comes in through
// `ownerRoot` (the ApplicationWindow) — never via implicit scope.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired when the user confirms; caller discards local edits + reloads.
    signal confirmed()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 460
    title: tr("dialog.reload-from-service.title",
        "Load active rules from the service?")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    background: Rectangle {
        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "transparent"
        border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 0
        border.color: root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "transparent"
        radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 0
    }
    contentItem: ColumnLayout {
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.reload-from-service.body",
                "You have unsaved changes to the rules. Loading the active "
                + "rules from the service will discard them. Continue?")
        }
        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.reload-from-service.confirm",
                    "Discard and load")
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
