import QtQuick 2.15
import QtQuick.Controls 2.15

// A column header that sorts its table: by mouse where the caller already
// handles the click, and from the keyboard (Tab, then Space or Enter) and the
// screen reader's press action here, so sorting never needs a mouse.
Label {
    id: header
    property var theme
    signal activated()

    activeFocusOnTab: true
    Accessible.role: Accessible.ColumnHeader
    Accessible.name: text
    Accessible.onPressAction: header.activated()
    Keys.onSpacePressed: header.activated()
    Keys.onReturnPressed: header.activated()
    Keys.onEnterPressed: header.activated()

    Rectangle {
        anchors.fill: parent
        color: "transparent"
        visible: header.activeFocus
        border.width: header.theme ? header.theme.focusBorderWidth : 2
        border.color: header.theme ? header.theme.colorFocusRing : header.color
        radius: header.theme ? header.theme.radiusSm : 0
    }
}
