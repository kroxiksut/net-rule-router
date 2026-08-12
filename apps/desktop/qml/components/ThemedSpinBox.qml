import QtQuick 2.15
import QtQuick.Controls 2.15

// Themed SpinBox wrapper. Native style on Windows ignores palette and
// leaves the input field, up/down indicators, and background light on
// dark/high-contrast themes. Override every visual sub-item explicitly.
SpinBox {
    id: root
    property var theme

    // Compact, fixed height so Fusion's default (~36 px) does not bloat
    // multi-spinbox forms. The −/+ indicators get a fixed slot on each
    // side so digits never sit underneath them.
    implicitHeight: 28
    readonly property int _indicatorReserve: 24

    leftPadding: _indicatorReserve + theme.spacingXs
    rightPadding: _indicatorReserve + theme.spacingXs

    contentItem: TextInput {
        text: root.displayText
        font: root.font
        color: theme.colorText
        selectionColor: theme.colorAccent
        selectedTextColor: theme.colorOnAccent
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter
        readOnly: !root.editable
        validator: root.validator
        inputMethodHints: Qt.ImhFormattedNumbersOnly
        // Allow mouse-drag selection and auto-select-all on focus so
        // users can immediately overwrite a value by clicking and
        // typing instead of erasing it digit-by-digit.
        selectByMouse: true
        onActiveFocusChanged: if (activeFocus) selectAll()
    }

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

    up.indicator: Rectangle {
        x: root.mirrored ? 0 : root.width - width
        height: root.height
        implicitWidth: Math.max(20, root.height * 0.8)
        implicitHeight: root.height
        color: !root.enabled
                   ? theme.stateDisabledFill
                   : root.up.pressed
                       ? theme.statePressedFill
                       : root.up.hovered
                           ? theme.stateHoverFill
                           : theme.stateDefaultFill
        border.width: theme.borderWidth
        border.color: theme.stateDefaultBorder
        Text {
            anchors.centerIn: parent
            text: "+"
            font.pixelSize: root.font.pixelSize + 2
            color: root.enabled ? theme.colorText
                                : Qt.rgba(theme.colorText.r, theme.colorText.g,
                                          theme.colorText.b, 0.55)
        }
    }

    down.indicator: Rectangle {
        x: root.mirrored ? root.width - width : 0
        height: root.height
        implicitWidth: Math.max(20, root.height * 0.8)
        implicitHeight: root.height
        color: !root.enabled
                   ? theme.stateDisabledFill
                   : root.down.pressed
                       ? theme.statePressedFill
                       : root.down.hovered
                           ? theme.stateHoverFill
                           : theme.stateDefaultFill
        border.width: theme.borderWidth
        border.color: theme.stateDefaultBorder
        Text {
            anchors.centerIn: parent
            text: "−"
            font.pixelSize: root.font.pixelSize + 2
            color: root.enabled ? theme.colorText
                                : Qt.rgba(theme.colorText.r, theme.colorText.g,
                                          theme.colorText.b, 0.55)
        }
    }
}
