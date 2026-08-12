import QtQuick 2.15

Rectangle {
    required property QtObject theme
    property real cornerRadius: theme.radiusMd

    radius: cornerRadius
    color: theme.colorPanel
    border.width: theme.borderWidth
    border.color: theme.stateDefaultBorder
}
