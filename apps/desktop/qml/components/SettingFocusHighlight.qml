import QtQuick 2.15

// Accent outline drawn around a setting another surface pointed at. Declared
// inside the control it marks; takes no input, so the control stays usable
// through it.
Rectangle {
    id: outline

    /// ThemeTokens instance.
    property var theme
    property bool shown: false

    anchors.fill: parent
    anchors.margins: -4
    z: 10
    color: "transparent"
    radius: theme ? theme.radiusSm : 4
    border.width: theme && theme.isHighContrast ? 3 : 2
    border.color: theme ? theme.colorFocusRing : "#2f6feb"
    opacity: shown ? 1 : 0
    visible: opacity > 0
    enabled: false

    // High contrast switches the outline off outright: a fading edge spends
    // its last second at a contrast that theme exists to avoid.
    Behavior on opacity {
        enabled: !(outline.theme && outline.theme.isHighContrast)
        NumberAnimation { duration: 700; easing.type: Easing.OutQuad }
    }
}
