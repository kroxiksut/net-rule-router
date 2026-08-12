// The rules file being written lives inside the rule sets that ship with the
// app, and the next application update replaces that folder — rules saved
// there are lost. This WARNS rather than refuses: refusing silently reads as
// "save does nothing", and one write path used to refuse while another wrote
// there freely. Both ways out are offered — save into a folder of your own
// (the save resumes there), or acknowledge the loss and save here anyway. A
// "dumb" dialog like its siblings: it emits, the caller acts. Shared state
// comes in through `ownerRoot` (the ApplicationWindow), never implicit scope.
//
// `mode: "overwrite-set"` reuses the same write-is-about-to-clobber-something
// shape for "save rules as a set" landing on a folder that already holds
// rule files — no folder-choice alternative applies there, so that button
// hides and `saveHereRequested()` is the only way forward besides Cancel.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// The path that was refused — shown so the user recognises the file.
    property string blockedPath: ""
    /// "factory" (writing into the app's own bundled rule sets) or
    /// "overwrite-set" (the chosen set folder already has rule files).
    property string mode: "factory"
    /// The user wants to pick a folder of their own; the caller opens the
    /// folder picker and resumes the save there.
    signal chooseFolderRequested()
    /// The user accepts that an update takes the file with it; the caller
    /// performs the very same write it was holding.
    signal saveHereRequested()
    /// The user declined; the caller reports that nothing was written.
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: Math.max(480, footerRow.implicitWidth + 2 * root.padding)
    padding: ownerRoot ? ownerRoot.uiTheme.spacingLg : 16
    title: mode === "overwrite-set"
        ? tr("dialog.overwrite-set.title", "This set already has saved rules")
        : tr("dialog.factory-preset-save.title",
            "This file belongs to the app's own rule sets")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    background: Rectangle {
        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "transparent"
        border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 0
        border.color: root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "transparent"
        radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 0
    }
    contentItem: ColumnLayout {
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.mode === "overwrite-set"
                ? root.tr("dialog.overwrite-set.body",
                    "The folder you chose already has a primary or additional-route rules file in it. Saving here replaces them.")
                : root.tr("dialog.factory-preset-save.body",
                    "The rules file you are saving to is one of the sets that come with the app, and the next update replaces that folder — anything saved there would be lost. Save into a folder of your own instead, or save here anyway if that is what you want.")
        }
        Label {
            Layout.fillWidth: true
            visible: root.blockedPath !== ""
            wrapMode: Text.Wrap
            elide: Text.ElideMiddle
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
            font.pixelSize: root.ownerRoot
                ? root.ownerRoot.uiTheme.baseFontSizePx - 1 : 12
            text: root.blockedPath
        }
        RowLayout {
            id: footerRow
            Layout.fillWidth: true
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { root.close(); root.cancelled() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                // Same wording as the other "you are writing into the app's
                // own folder" warning, so one concept reads one way. Primary
                // action in overwrite-set mode — there is no third button.
                highlighted: root.mode === "overwrite-set"
                text: root.tr("settings.presets.bundled-write-warning.confirm",
                    "Save here anyway")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { root.close(); root.saveHereRequested() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                highlighted: true
                visible: root.mode !== "overwrite-set"
                text: root.tr("dialog.factory-preset-save.choose-folder",
                    "Save into my folder...")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { root.close(); root.chooseFolderRequested() }
            }
        }
    }
}
