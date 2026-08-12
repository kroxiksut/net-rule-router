import QtQuick 2.15

Rectangle {
    required property QtObject theme
    property bool selected: false
    property real cornerRadius: theme.radiusSm
    property color overrideFill: "transparent"
    // Optional border override — used by callers that need a state colour
    // (e.g. red for invalid rules). "transparent" = use default.
    property color overrideBorder: "transparent"
    // When true, the border is drawn 2px instead of theme.borderWidth so
    // the danger/warning state is visually distinct.
    property bool emphasizedBorder: false

    radius: cornerRadius
    color: overrideFill !== "transparent"
        ? overrideFill
        : (selected ? theme.stateFocusedFill : theme.colorBase)
    border.width: emphasizedBorder ? 2 : theme.borderWidth
    border.color: overrideBorder !== "transparent"
        ? overrideBorder
        : (selected ? theme.stateFocusedBorder : theme.stateDefaultBorder)
}
