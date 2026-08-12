// Last-mile options applied to a preset export AFTER
// the native FileDialog has captured the target path.
//
// QtQuick.Dialogs.FileDialog wraps the OS-native dialog and offers no
// accessory-widget slot, so a per-export "include comments" toggle
// cannot be inlined into the SaveFile dialog itself. The compromise:
// two-step UX — the FileDialog hands the chosen path to this dialog,
// the dialog renders the option toggle, and on Confirm it bubbles
// `confirmed(includeComments)` to the caller which then runs the
// actual file write.
//
// The dialog is route-agnostic: the caller stashes its own
// `pendingRoute` and `pendingPath` in window-scoped variables and
// reads them back in the confirmed handler. The dialog itself only
// carries the option state.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog
    title: tr("dialog.export-options.title", "Export options")

    modal: true
    // Render inside the main window overlay (themed), not a separate
    // top-level OS window — see ReviewDiffDialog for the rationale.
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: dialog
        theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
        titleText: dialog.title
    }
    width: 460
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the dialog (provides `tr`,
    /// `uiTheme`, `textColor`, `mutedTextColor`).
    property var ownerRoot: null

    /// Pre-filled by the caller; bound to the checkbox below. The
    /// caller persists the chosen value across opens (session-scoped
    /// memory of the user's preference) so the second export defaults
    /// to whatever the user picked the first time.
    property bool includeComments: true

    signal confirmed(bool includeComments)
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    onRejected: cancelled()

    onOpened: {
        if (confirmButton) confirmButton.forceActiveFocus()
    }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: dialog.tr(
                "dialog.export-options.body",
                "Customize what to include in the preset file.")
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
        }

        CheckBox {
            id: includeCommentsCheck
            Layout.fillWidth: true
            checked: dialog.includeComments
            onCheckedChanged: dialog.includeComments = checked
            text: dialog.tr(
                "dialog.export-options.include-comments",
                "Include rule comments")
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            Accessible.description: dialog.tr(
                "dialog.export-options.include-comments-description",
                "When on, each rule's ` # comment` suffix is written to the file. Turn off to share rules without your personal notes.")
        }

        Label {
            Layout.fillWidth: true
            visible: !dialog.includeComments
            text: dialog.tr(
                "dialog.export-options.no-comments-hint",
                "Comments will be stripped from the exported file. Existing comments in the app are not affected.")
            wrapMode: Text.Wrap
            font.pixelSize: 11
            color: dialog.ownerRoot
                ? dialog.ownerRoot.mutedTextColor : palette.text
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.export-options.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { dialog.cancelled(); dialog.close() }
            }
            ThemedButton {
                id: confirmButton
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.export-options.confirm", "Export")
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: {
                    dialog.confirmed(dialog.includeComments)
                    dialog.close()
                }
            }
        }
    }
}
