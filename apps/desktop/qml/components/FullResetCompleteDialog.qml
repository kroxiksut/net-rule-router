// Full-reset completion prompt. After a reset the program + tray must be
// fully closed for it to take effect on next launch; this offers to do that
// now. Extracted from Main.qml (thin-shell
// refactor). Emits `closeAllRequested()`; the caller (Main.qml) runs
// `_fullResetCloseAll()`. Shared state comes in through `ownerRoot`.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired when the user chooses to close the program + tray now.
    signal closeAllRequested()

    /// Whether service-side state (rules AND auxiliary data) was fully
    /// cleared. False shows a warning that the reset was only partial.
    property bool serviceCleared: true

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.full-reset-done.title", "Full reset complete")
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
            text: root.tr("dialog.full-reset-done.body",
                "Full reset is done. To apply it the program and the tray must be "
                + "fully closed. Close them now?")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            visible: !root.serviceCleared
            color: root.ownerRoot ? root.ownerRoot.uiTheme.colorWarning : "orange"
            text: root.tr("dialog.full-reset-done.service-warn",
                "Note: the service rules could not be cleared (administrator "
                + "approval is required). Re-run the reset and approve the prompt.")
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.full-reset-done.later", "Later")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.full-reset-done.close-now", "Close everything now")
                highlighted: true
                onClicked: { root.close(); root.closeAllRequested() }
            }
        }
    }
}
