// Expandable history for the footer progress pill. Themed in-overlay popup
// (Popup.Item), newest first. Extracted from Main.qml (thin-shell
// refactor). Shared state comes in through
// `ownerRoot` (the ApplicationWindow); the log ListModel is injected via
// `logModel` (it lives at window scope and is not exposed as an alias).
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Popup {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// The window-scoped `startupLogModel` ListModel (timestamped events).
    property var logModel: null

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    readonly property var _theme: ownerRoot ? ownerRoot.uiTheme : null

    popupType: Popup.Item
    modal: false
    focus: true
    width: 440
    height: Math.min(340, 96 + (logModel ? logModel.count : 0) * 24)
    x: parent ? Math.max(_theme ? _theme.spacingMd : 12,
        parent.width - width - (_theme ? _theme.spacingMd : 12)) : 0
    y: parent ? Math.max(_theme ? _theme.spacingMd : 12,
        parent.height - height - (_theme ? _theme.spacingMd : 12)) : 0
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
    background: PanelSurface {
        theme: root._theme
        cornerRadius: root._theme ? root._theme.radiusMd : 8
    }
    contentItem: ColumnLayout {
        spacing: root._theme ? root._theme.spacingSm : 8
        RowLayout {
            Layout.fillWidth: true
            spacing: root._theme ? root._theme.spacingSm : 8
            Label {
                Layout.fillWidth: true
                text: root.tr("progress.log-title", "Startup & connection log")
                font.bold: true
                color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            }
            ThemedButton {
                theme: root._theme
                text: root.tr("action.clear", "Clear")
                onClicked: {
                    if (root.logModel) root.logModel.clear()
                    if (root.ownerRoot) root.ownerRoot.lastProgressMessage = ""
                }
            }
        }
        Label {
            Layout.fillWidth: true
            visible: !root.logModel || root.logModel.count === 0
            text: root.tr("progress.log-empty", "No events yet.")
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
        }
        ListView {
            id: startupLogView
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: root.logModel && root.logModel.count > 0
            clip: true
            model: root.logModel
            spacing: 2
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            delegate: RowLayout {
                width: startupLogView.width
                spacing: root._theme ? root._theme.spacingXs : 4
                Label {
                    Layout.preferredWidth: 62
                    Layout.alignment: Qt.AlignTop
                    text: model.ts
                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
                    font.pixelSize: 11
                }
                Rectangle {
                    Layout.preferredWidth: 7; Layout.preferredHeight: 7; radius: 3.5
                    Layout.topMargin: 4
                    Layout.alignment: Qt.AlignTop
                    color: root.ownerRoot ? root.ownerRoot.progressKindColor(model.kind) : "gray"
                }
                Label {
                    Layout.fillWidth: true
                    text: model.message
                    color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
                    wrapMode: Text.Wrap
                    font.pixelSize: 12
                }
            }
        }
    }
}
