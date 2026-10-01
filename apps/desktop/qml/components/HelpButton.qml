import QtQuick 2.15
import QtQuick.Controls 2.15

// Small "?" affordance next to a control whose consequence isn't obvious
// from its label alone. Click, Enter or Space opens a themed popup with
// `helpText`; Esc (or a click outside) closes it. A hover tooltip mirrors
// the same text as a convenience, never as the only way to reach it
// (accessibility baseline: tooltips are not the sole source of meaning).
Button {
    id: root

    property var theme
    /// Already-localized text shown inside the popup and as the tooltip.
    property string helpText: ""
    /// Already-localized accessible name; defaults to a generic "Help".
    property string accessibleLabel: ""

    text: "?"
    activeFocusOnTab: true
    implicitWidth: 20
    implicitHeight: 20
    padding: 0
    focusPolicy: Qt.StrongFocus

    Accessible.role: Accessible.Button
    Accessible.name: root.accessibleLabel !== "" ? root.accessibleLabel : root.helpText
    ToolTip.visible: root.hovered && root.helpText !== ""
    ToolTip.text: root.helpText

    onClicked: helpPopup.open()

    background: Rectangle {
        radius: width / 2
        color: root.pressed
            ? root.theme.statePressedFill
            : (root.hovered || root.activeFocus ? root.theme.stateHoverFill : root.theme.stateDefaultFill)
        border.width: root.theme.borderWidth
        border.color: root.activeFocus ? root.theme.stateFocusedBorder : root.theme.stateDefaultBorder
    }
    contentItem: Text {
        text: root.text
        font.bold: true
        font.pixelSize: root.theme.baseFontSizePx - 1
        color: root.theme.colorAccent
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }

    Popup {
        id: helpPopup
        parent: root
        x: 0
        y: root.height + root.theme.spacingXs
        width: 320
        modal: false
        focus: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        background: PanelSurface {
            theme: root.theme
            cornerRadius: root.theme.radiusMd
        }
        contentItem: Label {
            text: root.helpText
            wrapMode: Text.Wrap
            color: root.theme.colorText
        }
    }
}
