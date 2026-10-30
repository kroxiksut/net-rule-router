// Full-reset completion prompt. After a reset the program + tray must be
// fully closed for it to take effect on next launch; this offers to do that
// now. Emits `closeAllRequested()`; the caller (Main.qml) runs
// `fullResetController.closeAllProcesses()`. Shared state comes in through
// `ownerRoot`.
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
    /// Whether the service came back after the reset. False: routing and
    /// protection are off until it is started, so the dialog says why and
    /// offers the start.
    property bool serviceRestarted: true
    /// The reason the restart did not happen, already in words; may be empty.
    property string restartFailure: ""

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
    // Same sizing as the reset confirm it follows.
    width: Math.min(parent ? parent.width - 32 : 560,
        Math.max(480, (ownerRoot && ownerRoot.uiTheme ? ownerRoot.uiTheme.baseFontSizePx : 14) * 38))
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
                "Note: some service-side data could not be cleared (administrator "
                + "approval may be required, or a temporary error occurred). Re-run the reset.")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            visible: !root.serviceRestarted
            color: root.ownerRoot ? root.ownerRoot.uiTheme.colorWarning : "orange"
            text: root.tr("dialog.full-reset-done.restart-failed",
                "The background service did not start again, so routing and protection are off until it runs.")
                + (root.restartFailure !== "" ? " (" + root.restartFailure + ")" : "")
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            ThemedButton {
                visible: !root.serviceRestarted
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("settings.service.action.start", "Start service")
                onClicked: {
                    if (root.ownerRoot && typeof root.ownerRoot._startServiceFromBanner === "function")
                        root.ownerRoot._startServiceFromBanner()
                    root.serviceRestarted = true
                }
            }
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
