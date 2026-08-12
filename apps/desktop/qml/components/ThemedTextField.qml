import QtQuick 2.15
import QtQuick.Controls 2.15

// Themed TextField wrapper. Native (Windows) style ignores `palette.base`,
// so input fields stay light on a dark/high-contrast theme until the user
// types. Override contentItem-affecting colours and background explicitly.
TextField {
    id: root
    property var theme

    color: theme.colorText
    placeholderTextColor: Qt.rgba(theme.colorTextMuted.r, theme.colorTextMuted.g,
                                  theme.colorTextMuted.b, 0.85)
    selectionColor: theme.colorAccent
    selectedTextColor: theme.colorOnAccent

    background: Rectangle {
        radius: theme.radiusSm
        color: !root.enabled
                   ? theme.stateDisabledFill
                   : theme.colorBase
        border.width: theme.borderWidth
        border.color: root.activeFocus
                          ? theme.stateFocusedBorder
                          : !root.enabled
                              ? theme.stateDisabledBorder
                              : theme.stateDefaultBorder
    }
}
