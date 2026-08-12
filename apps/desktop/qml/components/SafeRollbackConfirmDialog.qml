// Confirm dialog for "Safe rollback": reverts the active
// routing configuration to the last-known-good (previous) revision via the
// service `RollbackRequest` recovery action. Destructive → explicit confirm.
// "Dumb" dialog: emits `confirmed()`; the caller (Main.qml) runs the IPC call.
// Shared state comes in through `ownerRoot` (the ApplicationWindow).
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired when the user confirms; caller submits the rollback request.
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
    title: tr("dialog.safe-rollback.title", "Roll back to the previous configuration?")
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
            text: root.tr("dialog.safe-rollback.body",
                "The service will restore the last-known-good routing "
                + "configuration and re-apply it. Your current active rules "
                + "will be replaced. This requires administrator rights. Continue?")
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
                text: root.tr("dialog.safe-rollback.confirm", "Roll back")
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
