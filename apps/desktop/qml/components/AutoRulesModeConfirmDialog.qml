// Confirm dialog for switching auto-rules mode to "Apply automatically":
// from that point on NetRuleRouter writes suggested addresses into the
// user's rule files by itself, without asking. `Off` and `Suggest only`
// need no such gate — only this one starts unattended writes. Same
// device as DriftClearAllConfirmDialog: a "dumb" dialog that emits
// `confirmed()`/`cancelled()` and lets the caller act.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired once the user confirms switching to "Apply automatically".
    signal confirmed()
    /// Fired on Cancel/Esc/close — caller must not leave the combo showing
    /// "Apply automatically" when the switch was never confirmed.
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.auto-rules-mode.title", "Turn on “Apply automatically”?")
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
    onRejected: root.cancelled()
    contentItem: ColumnLayout {
        spacing: 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.auto-rules-mode.body",
                "From now on NetRuleRouter will add suggested addresses to your rules files by itself, without asking. You can undo this anytime by switching back to “Suggest only”.")
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                onClicked: { root.close(); root.cancelled() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.auto-rules-mode.confirm", "Turn on")
                highlighted: true
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
