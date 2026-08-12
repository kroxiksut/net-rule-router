// Destructive confirm: "Clear all rules" pushes an empty revision to the
// service. Extracted from Main.qml (thin-shell
// refactor). The acknowledgement checkbox is internal; the dialog emits
// `confirmed()` and the caller (Main.qml) performs the clear.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired once the user acknowledges and confirms.
    signal confirmed()

    /// Internal acknowledgement state — reset on every open.
    property bool _ack: false

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.drift-clear-all.title", "Clear all rules")
    modal: true
    popupType: Popup.Item
    width: 480
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    onOpened: _ack = false
    contentItem: ColumnLayout {
        spacing: 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.drift-clear-all.body",
                "This removes ALL rules from the app and pushes an empty "
                + "revision to the service, so no routing rules remain. "
                + "This cannot be undone.")
        }
        CheckBox {
            Layout.fillWidth: true
            checked: root._ack
            onCheckedChanged: root._ack = checked
            text: root.tr("dialog.drift-clear-all.ack",
                "I understand this removes all rules everywhere")
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.drift-clear-all.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.drift-clear-all.confirm", "Clear everything")
                highlighted: true
                enabled: root._ack
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
