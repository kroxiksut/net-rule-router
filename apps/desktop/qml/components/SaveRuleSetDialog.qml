import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs

// "Save the rules on screen as a named set."
//
// A set is a FOLDER holding one file per route, so the question is a name and
// a place — not a file name. The Rules toolbar used to ask through the Save-As
// file picker and then write a folder anyway, which is how a user came to type
// "test.txt" and find a `test\` folder with two files in it.
//
// UI only: `accepted(name, folder)` hands the answer back, and the caller owns
// creating the folder, the overwrite guard and the write itself.
Dialog {
    id: saveRuleSetDialog
    property var root
    /// Folder the set will be created in. Pre-filled by the caller.
    property string folder: ""
    /// Show the "choose another folder" affordance. Settings already owns the
    /// rule-set folder as a setting, so it opens this without one.
    property bool folderSelectable: true

    signal setAccepted(string name, string folder)
    /// Closed without naming a set. A caller waiting on the save (a close-flow)
    /// needs this to stop waiting.
    signal setDismissed()

    /// Guards `onClosed`, which fires for the confirm as well as the dismiss.
    property bool _accepted: false

    modal: true
    popupType: Popup.Item
    anchors.centerIn: Overlay.overlay
    width: 480
    title: root.tr("settings.presets.save-as-set.title", "Save rules as a set")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// Open with a suggested name (may be empty) and a container folder.
    function openFor(suggestedName, containerFolder) {
        _accepted = false
        folder = String(containerFolder || "")
        nameField.text = String(suggestedName || "")
        open()
        nameField.forceActiveFocus()
    }

    /// One declaration of what a set name may be, in the controller that also
    /// refuses a bad one on the way to the write.
    function nameIsUsable(name) {
        return root.boundFilesController.isUsableSetName(name)
    }

    function _confirm() {
        if (!nameIsUsable(nameField.text)) return
        var n = String(nameField.text).trim()
        _accepted = true
        close()
        saveRuleSetDialog.setAccepted(n, saveRuleSetDialog.folder)
    }

    onClosed: if (!_accepted) saveRuleSetDialog.setDismissed()

    contentItem: ColumnLayout {
        spacing: saveRuleSetDialog.root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: saveRuleSetDialog.root.textColor
            text: saveRuleSetDialog.root.tr("settings.presets.save-as-set.prompt",
                "The current rules of both routes are saved as a new set in your folder. Name it so you can tell it apart later, for example \"work\" or \"home\".")
        }
        ThemedTextField {
            id: nameField
            theme: saveRuleSetDialog.root.uiTheme
            Layout.fillWidth: true
            placeholderText: saveRuleSetDialog.root.tr("settings.presets.save-as-set.name-placeholder",
                "Set name")
            onAccepted: saveRuleSetDialog._confirm()
        }
        Label {
            Layout.fillWidth: true
            visible: nameField.text.trim() !== ""
                        && !saveRuleSetDialog.nameIsUsable(nameField.text)
            wrapMode: Text.WordWrap
            color: saveRuleSetDialog.root.uiTheme.colorDanger
            font.pixelSize: saveRuleSetDialog.root.uiTheme.baseFontSizePx - 1
            text: saveRuleSetDialog.root.tr("settings.presets.save-as-set.name-invalid",
                "A name cannot contain \\ / : or \"..\" — it is a folder name, not a path.")
        }
        RowLayout {
            Layout.fillWidth: true
            visible: saveRuleSetDialog.folderSelectable
            spacing: saveRuleSetDialog.root.uiTheme.spacingSm
            Label {
                color: saveRuleSetDialog.root.mutedTextColor
                text: saveRuleSetDialog.root.tr("settings.presets.save-as-set.folder-label", "Folder:")
            }
            Label {
                Layout.fillWidth: true
                elide: Text.ElideMiddle
                color: saveRuleSetDialog.root.textColor
                text: saveRuleSetDialog.folder
                ToolTip.visible: hovered && saveRuleSetDialog.root.prefs.tooltipsEnabled
                            && saveRuleSetDialog.folder !== ""
                ToolTip.text: saveRuleSetDialog.folder
                // `Label` has no `hovered`; a hover handler supplies it.
                property bool hovered: folderHover.hovered
                HoverHandler { id: folderHover }
            }
            ThemedButton {
                theme: saveRuleSetDialog.root.uiTheme
                text: saveRuleSetDialog.root.tr("settings.presets.save-as-set.choose-folder", "Change...")
                onClicked: {
                    if (saveRuleSetDialog.folder !== "") {
                        setFolderDialog.currentFolder =
                            "file:///" + saveRuleSetDialog.folder.replace(/\\/g, "/")
                    }
                    setFolderDialog.open()
                }
            }
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: saveRuleSetDialog.root.uiTheme.spacingSm
            spacing: saveRuleSetDialog.root.uiTheme.spacingSm
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: saveRuleSetDialog.root.uiTheme
                text: saveRuleSetDialog.root.tr("action.cancel", "Cancel")
                onClicked: saveRuleSetDialog.close()
            }
            ThemedButton {
                theme: saveRuleSetDialog.root.uiTheme
                text: saveRuleSetDialog.root.tr("settings.presets.save-as-set.confirm", "Save set")
                enabled: saveRuleSetDialog.nameIsUsable(nameField.text)
                onClicked: saveRuleSetDialog._confirm()
            }
        }
    }

    FolderDialog {
        id: setFolderDialog
        title: saveRuleSetDialog.root.tr("settings.presets.user-folder.dialog-title",
            "Choose the folder with your rule sets")
        onAccepted: {
            var s = String(selectedFolder || "")
            saveRuleSetDialog.folder = (s.indexOf("file:///") === 0)
                ? s.substring(8)
                : ((s.indexOf("file://") === 0) ? s.substring(7) : s)
        }
    }
}
