import QtQuick 2.15
import QtQuick.Controls 2.15

// Themed TextArea wrapper; same reason as `ThemedTextField.qml`: the native
// style ignores `palette.base`, so a multi-line field stays light on a
// dark/high-contrast theme. Put it inside a ScrollView for scrolling.
TextArea {
    id: root
    property var theme

    // Accessible baseline — see the note in `ThemedComboBox.qml`. The name
    // falls back to the placeholder; a caller with a visible label overrides it.
    Accessible.role: Accessible.EditableText
    Accessible.name: root.placeholderText
    Accessible.description: root.ToolTip.text

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
