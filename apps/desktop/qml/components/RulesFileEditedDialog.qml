// Question: a linked rules file was edited by hand since the program wrote it,
// and the rules in force have moved on since. The file is not overwritten
// unasked: the user takes the file (into the merge review) or lets the rules
// in force replace it. The dialog is "dumb"; BoundFilesController acts on the
// answer.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// The routes asked about: `[{ route, path }]`.
    property var targets: []

    /// Merge the files into the rules in force, through the review.
    signal takeFiles()
    /// Replace the files with the rules in force.
    signal overwriteFiles()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _pathsText() {
        var lines = []
        for (var i = 0; i < targets.length; i += 1) lines.push(String(targets[i].path || ""))
        return lines.join("\n")
    }

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 520
    title: tr("dialog.rules-file-edited.title", "A rules file was edited outside the app")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    // The keyboard lands on the answer that loses nothing.
    onOpened: laterButton.forceActiveFocus()
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
            text: root.tr("dialog.rules-file-edited.body",
                "Your rules changed elsewhere, and this file was edited by hand since the app last saved it, so it was left as it is. Take the file to compare it with the rules in force and apply what you keep, or replace the file with the rules in force.")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WrapAnywhere
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
            text: root._pathsText()
            Accessible.name: root.tr("dialog.rules-file-edited.files", "Files edited by hand")
        }
        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                id: laterButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.rules-file-edited.later", "Leave both for now")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.rules-file-edited.overwrite", "Replace the file")
                onClicked: { root.close(); root.overwriteFiles() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.rules-file-edited.take", "Take the file")
                onClicked: { root.close(); root.takeFiles() }
            }
        }
    }
}
