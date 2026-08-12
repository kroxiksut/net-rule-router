import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../theme"

// Modal shown at window-close (Exit / X) AFTER the
// existing UnsavedChangesGuard has cleared. Triggers when the active
// rules revision diverges from the last file sync. Lets the user:
//   - Save to existing imported paths (`prefs.lastSavedPath_<role>`)
//   - Save As... (user picks new paths)
//   - Discard & rollback (revert active to last_file_synced_revision_id;
//     when None, import empty preset to produce an empty revision)
//   - Cancel (abort close)
//
// The dialog does NOT trigger on close-to-tray — data preserved.
Dialog {
    id: root

    property var ownerRoot
    property bool primaryDirty: false
    property bool secondaryDirty: false
    property string primaryPath: ""
    property string secondaryPath: ""

    signal saveSelected()
    signal saveAs()
    signal discardAndRollback()
    signal cancelled()

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    title: tr("dialog.save-before-close.title", "Save rule changes?")
    standardButtons: Dialog.NoButton
    modal: true
    closePolicy: Popup.CloseOnEscape
    width: 540

    onRejected: { cancelled(); root.close() }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr(
                "dialog.save-before-close.intro",
                "Active rules differ from the files you imported. Without saving, those edits will be rolled back.")
            color: root.ownerRoot ? root.ownerRoot.textColor : "white"
        }

        // Per-route divergence rows. Each row shows the route name and
        // either the file path (read-only label) or the "no path" hint.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            visible: root.primaryDirty || root.secondaryDirty

            RowLayout {
                Layout.fillWidth: true
                visible: root.primaryDirty
                Label {
                    text: root.tr("route.primary", "Main")
                    Layout.preferredWidth: 100
                    color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    elide: Text.ElideLeft
                    text: root.primaryPath !== ""
                        ? root.primaryPath
                        : root.tr("dialog.save-before-close.row-no-path",
                            "(no file yet — choose with Save As...)")
                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                }
            }
            RowLayout {
                Layout.fillWidth: true
                visible: root.secondaryDirty
                Label {
                    text: root.tr("route.secondary", "Additional")
                    Layout.preferredWidth: 100
                    color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    elide: Text.ElideLeft
                    text: root.secondaryPath !== ""
                        ? root.secondaryPath
                        : root.tr("dialog.save-before-close.row-no-path",
                            "(no file yet — choose with Save As...)")
                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                }
            }
        }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            visible: root.primaryPath === "" && root.secondaryPath === ""
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("dialog.save-before-close.warning-no-file",
                "Without a file, rules will NOT be applied on the next launch.")
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 6
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.save-before-close.discard-rollback",
                    "Discard & rollback")
                onClicked: { root.discardAndRollback(); root.close() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.save-before-close.save-as", "Save As...")
                onClicked: { root.saveAs(); root.close() }
            }
            ThemedButton {
                id: saveSelectedButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.save-before-close.save-selected",
                    "Save selected")
                highlighted: true
                enabled: (root.primaryDirty && root.primaryPath !== "")
                    || (root.secondaryDirty && root.secondaryPath !== "")
                onClicked: { root.saveSelected(); root.close() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.save-before-close.cancel", "Cancel")
                onClicked: { root.cancelled(); root.close() }
            }
        }
    }
}
