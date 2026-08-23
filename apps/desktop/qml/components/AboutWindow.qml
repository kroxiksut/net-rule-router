import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../lib/pure.js" as Pure

// About window (extracted from Main.qml). Logo lockup / author / version /
// license / build channel / project URL, plus buttons to the Licenses window
// and the project page. Keeps its `aboutWindow` id so Main.qml's
// overlays/children arrays and openChildWindow wiring are unchanged. Shared
// state via `root`.
Window {
    id: aboutWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    width: 560
    height: 420
    visible: false
    modality: Qt.NonModal
    color: root.panelColor
    title: root.tr("action.open-about-window", "About")
    transientParent: root
    flags: Qt.Dialog
    onVisibleChanged: if (visible) { root.centerChildWindow(aboutWindow); root.applyTitleBarTo(aboutWindow) }
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingLg
        spacing: root.uiTheme.spacingMd
        // The lockup already carries the product name, so the plain-text name
        // below stands in only when the artwork cannot be loaded.
        Image {
            id: logoImage
            Layout.preferredWidth: 300
            // Height follows the artwork rather than a baked-in ratio, so a
            // redrawn lockup never arrives letterboxed.
            Layout.preferredHeight: implicitWidth > 0
                ? Math.round(300 * implicitHeight / implicitWidth) : 0
            source: root.appLogoLockupSource
            sourceSize.width: 600
            fillMode: Image.PreserveAspectFit
            asynchronous: true
            visible: status === Image.Ready
        }
        RowLayout {
            visible: logoImage.status === Image.Error
                || logoImage.status === Image.Null
            spacing: root.uiTheme.spacingSm
            Image {
                Layout.preferredWidth: 64
                Layout.preferredHeight: 64
                source: root.appIconSource
                sourceSize.width: 64
                sourceSize.height: 64
                fillMode: Image.PreserveAspectFit
                asynchronous: true
            }
            Label { text: (root.context.about || {}).productName || "NetRuleRouter"; color: root.textColor; font.bold: true }
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.textColor
            text: root.tr("label.author", "Author") + ": "
                + root.tr("label.author-name", (root.context.about || {}).author || "-")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.textColor
            visible: String((root.context.about || {}).authorEmail || "") !== ""
            text: root.tr("label.author-email", "E-mail") + ": " + ((root.context.about || {}).authorEmail || "")
        }
        Label { text: root.tr("label.version", "Version") + ": " + ((root.context.about || {}).version || "n/a"); color: root.textColor }
        Label { text: root.tr("label.license", "License") + ": " + ((root.context.about || {}).license || "MPL-2.0"); color: root.textColor }
        Label { text: root.tr("label.build-channel", "Build channel") + ": " + ((root.context.about || {}).buildChannel || "development"); color: root.textColor }
        Label { text: root.tr("label.project-url", "Project") + ": " + ((root.context.about || {}).projectUrl || "-"); color: root.textColor; wrapMode: Text.WordWrap }
        Item { Layout.fillHeight: true }
        RowLayout {
            Layout.fillWidth: true
            Button { activeFocusOnTab: true; text: root.tr("action.open-license-window", "License"); onClicked: root.openChildWindow(root.licenseWindow) }
            Button { activeFocusOnTab: true; text: root.tr("label.project-url", "Project"); onClicked: Pure.openExternalUrl((root.context.about || {}).projectUrl || "") }
            Item { Layout.fillWidth: true }
            Button { activeFocusOnTab: true; text: root.tr("action.close", "Close"); onClicked: aboutWindow.close() }
        }
    }
}
