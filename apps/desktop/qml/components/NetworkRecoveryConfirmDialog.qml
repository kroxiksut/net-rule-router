// Network-recovery confirmation. The action is reversible in the sense that the
// service re-applies its rules on the next start, so no acknowledgement
// checkbox — but connections open right now can drop, which is worth one
// deliberate click. Like the other confirms here the dialog is "dumb": it emits
// `confirmed()` and the caller runs the action. Shared state comes in through
// `ownerRoot` (the ApplicationWindow), never implicit scope.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// The service runs and is stopped first; the body says so.
    property bool stopsService: false
    /// Fired when the user confirms; the caller runs the recovery.
    signal confirmed()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.network-recovery.title", "Restore network?")
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
            text: root.stopsService
                ? root.tr("dialog.network-recovery.body-stop",
                    "The service will be stopped, and ended if it does not stop in "
                    + "half a minute; then the packet filters, DNS redirect and routes "
                    + "it applied are removed, leak protection included. Connections "
                    + "open right now may drop, and until the service is started again, "
                    + "routing is off and sites meant for the additional adapter can go "
                    + "over the main connection. Administrator rights are required.")
                : root.tr("dialog.network-recovery.body",
                    "The packet filters, DNS redirect and routes the service applied "
                    + "will be removed, leak protection included. Connections open "
                    + "right now may drop, and until the service applies its rules "
                    + "again, routing is off and sites meant for the additional adapter "
                    + "can go over the main connection. Administrator rights are required.")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.network-recovery.overrides",
                "Rules you confirmed despite the protection of system programs are revoked.")
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.stopsService
                    ? root.tr("settings.service.recovery.action-stop",
                        "Stop service and restore network")
                    : root.tr("dialog.network-recovery.confirm", "Restore network")
                highlighted: true
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
