import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Why the user was sent to this setting: what was blocked, what the setting
// does, and when turning it off is safe. The caller's strings may carry names
// from another process, so every line is drawn as plain text, never markup.
Rectangle {
    id: banner

    /// The ApplicationWindow: theme tokens, colours, `tr()`.
    property var root
    property string title: ""
    property string headline: ""
    property string details: ""
    property string whatItDoes: ""
    property string whenSafe: ""

    signal dismissed()

    Layout.fillWidth: true
    implicitHeight: bannerColumn.implicitHeight + root.uiTheme.spacingSm * 2
    radius: root.uiTheme.radiusSm
    // High contrast gets the outline alone: a tint would lower the contrast of
    // the text it sits under.
    color: root.uiTheme.isHighContrast
        ? root.uiTheme.colorPanel
        : Qt.rgba(root.uiTheme.colorFocusRing.r, root.uiTheme.colorFocusRing.g,
            root.uiTheme.colorFocusRing.b, 0.10)
    border.width: root.uiTheme.isHighContrast ? 2 : root.uiTheme.borderWidth
    border.color: root.uiTheme.colorFocusRing

    Accessible.role: Accessible.AlertMessage
    Accessible.name: [title, headline, details, whatItDoes, whenSafe]
        .filter(function(s) { return s !== "" }).join(" ")

    ColumnLayout {
        id: bannerColumn
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: root.uiTheme.spacingSm
        spacing: root.uiTheme.spacingXs

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                text: banner.title
                textFormat: Text.PlainText
                color: root.textColor
                font.bold: true
                wrapMode: Text.WordWrap
            }
            ThemedButton {
                theme: root.uiTheme
                flat: true
                text: root.uiRevision >= 0 ? root.tr("action.dismiss", "Dismiss") : ""
                onClicked: banner.dismissed()
                Accessible.name: text
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: text !== ""
            text: banner.headline
            textFormat: Text.PlainText
            color: root.textColor
            wrapMode: Text.WordWrap
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: text !== ""
            text: banner.details
            textFormat: Text.PlainText
            color: root.mutedTextColor
            wrapMode: Text.WrapAnywhere
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: text !== ""
            text: banner.whatItDoes
            textFormat: Text.PlainText
            color: root.textColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: text !== ""
            text: banner.whenSafe
            textFormat: Text.PlainText
            color: root.textColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
        }
    }
}
