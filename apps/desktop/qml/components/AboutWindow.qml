import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../lib/pure.js" as Pure

// About window (extracted from Main.qml). Product name / version / license /
// build channel / project URL, plus buttons to the Licenses window and the
// project page. Keeps its `aboutWindow` id so Main.qml's overlays/children
// arrays and openChildWindow wiring are unchanged. Shared state via `root`.
Window {
    id: aboutWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    width: 560
    height: 360
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
        Label { text: root.tr("label.version", "Version") + ": " + ((root.context.about || {}).version || "n/a"); color: root.textColor }
        Label { text: root.tr("label.license", "License") + ": " + ((root.context.about || {}).license || "MPL-2.0"); color: root.textColor }
        Label { text: root.tr("label.build-channel", "Build channel") + ": " + ((root.context.about || {}).buildChannel || "development"); color: root.textColor }
        Label { text: root.tr("label.project-url", "Project") + ": " + ((root.context.about || {}).projectUrl || "-"); color: root.textColor; wrapMode: Text.WordWrap }
        RowLayout {
            Layout.fillWidth: true
            Button { activeFocusOnTab: true; text: root.tr("action.open-license-window", "License"); onClicked: root.openChildWindow(root.licenseWindow) }
            Button { activeFocusOnTab: true; text: root.tr("label.project-url", "Project"); onClicked: Pure.openExternalUrl((root.context.about || {}).projectUrl || "") }
            Item { Layout.fillWidth: true }
            Button { activeFocusOnTab: true; text: root.tr("action.close", "Close"); onClicked: aboutWindow.close() }
        }
    }
}
