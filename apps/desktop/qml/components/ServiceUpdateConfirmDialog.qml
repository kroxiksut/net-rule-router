// Service re-registration confirmation. Same shape as the other confirms here:
// the dialog is "dumb", it emits `confirmed()` and the caller runs the action.
// Worth one deliberate click because the service restarts — routing pauses for
// a moment — and Windows asks for administrator rights.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired when the user confirms; the caller runs the re-registration.
    signal confirmed()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.service-update.title", "Update the background service?")
    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 480
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    contentItem: ColumnLayout {
        spacing: 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.service-update.body",
                "The service will be registered from this folder and restarted. "
                + "Routing pauses for a moment; your rules, settings and history "
                + "are kept. Administrator rights are required.")
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.service-update.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.service-update.confirm", "Update service")
                highlighted: true
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
