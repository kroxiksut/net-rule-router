// Lightweight, reusable informational alert (title + body + single OK
// button). Introduced so flows that have
// nothing further to do (e.g. "Apply" with no pending changes) can tell
// the user plainly instead of opening an empty review dialog. Set `noticeTitle`
// / `noticeBody` (or call the host's `showNotice(title, body)` helper) then
// `open()`. Themed + in-overlay like the other dialogs.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Title text (already localized by the caller).
    property string noticeTitle: ""
    /// Body text (already localized by the caller).
    property string noticeBody: ""

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: noticeTitle
    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 460
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
            text: root.noticeBody
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.notice.ok", "OK")
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: root.close()
            }
        }
    }
}
