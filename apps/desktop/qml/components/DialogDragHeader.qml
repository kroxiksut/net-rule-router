// Draggable themed title bar for the
// in-window (`popupType: Popup.Item`) dialogs. Set it as a Dialog's
// `header`; dragging the bar repositions the dialog by adjusting the
// owning Dialog's `x`/`y`. This keeps dialogs themed (rendered inside the
// dark main-window overlay) AND movable — the user asked for both.
//
// Usage:
//   header: DialogDragHeader {
//       dialog: root            // the owning Dialog
//       theme: ownerRoot ? ownerRoot.uiTheme : null
//       titleText: root.title
//   }
import QtQuick 2.15
import QtQuick.Controls 2.15

Item {
    id: bar
    /// The owning Dialog — its `x`/`y` are mutated on drag.
    property var dialog: null
    /// ThemeTokens for colours; falls back to dark defaults when null.
    property var theme: null
    property string titleText: ""

    implicitWidth: 100
    implicitHeight: titleLabel.implicitHeight + 16

    Rectangle {
        anchors.fill: parent
        color: bar.theme ? bar.theme.colorPanel : "#2b2b2b"
        Rectangle {
            anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
            height: bar.theme ? bar.theme.borderWidth : 1
            color: bar.theme ? bar.theme.stateDefaultBorder : "#555555"
        }
    }

    Label {
        id: titleLabel
        anchors.verticalCenter: parent.verticalCenter
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: bar.theme ? bar.theme.spacingMd : 12
        anchors.rightMargin: bar.theme ? bar.theme.spacingMd : 12
        text: bar.titleText
        font.bold: true
        elide: Text.ElideRight
        color: bar.theme ? bar.theme.colorText : "white"
    }

    // Drag handle. Accumulating `+=` against the press-point local coord
    // makes the dialog follow the cursor (the bar moves with the dialog,
    // so the press-point local coord stays the anchor — see the standard
    // child-handle window-drag idiom).
    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.SizeAllCursor
        property real pressX: 0
        property real pressY: 0
        onPressed: function(mouse) {
            pressX = mouse.x
            pressY = mouse.y
        }
        onPositionChanged: function(mouse) {
            if (!pressed || !bar.dialog) {
                return
            }
            bar.dialog.x += (mouse.x - pressX)
            bar.dialog.y += (mouse.y - pressY)
        }
    }
}
