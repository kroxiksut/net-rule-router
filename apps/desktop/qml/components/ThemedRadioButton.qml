import QtQuick 2.15
import QtQuick.Controls 2.15

// Themed RadioButton wrapper. Default Native (Windows) style ignores
// `palette.*` for the indicator circle and label, so radios are unreadable on
// dark / high-contrast themes. This component sets an explicit indicator,
// contentItem and background so colours follow the active theme. Structure
// mirrors ThemedButton / ThemedComboBox: `property var theme` plus explicit
// contentItem / indicator / background. RadioButtons sharing a parent are
// mutually exclusive automatically (`autoExclusive` is on by default).
RadioButton {
    id: root
    property var theme

    activeFocusOnTab: true
    spacing: theme.spacingSm

    indicator: Rectangle {
        implicitWidth: 18
        implicitHeight: 18
        x: root.leftPadding
        y: (root.height - height) / 2
        radius: width / 2
        color: !root.enabled ? theme.stateDisabledFill : theme.colorBase
        border.width: theme.borderWidth
        border.color: root.activeFocus
                          ? theme.stateFocusedBorder
                          : !root.enabled
                              ? theme.stateDisabledBorder
                              : root.checked
                                  ? theme.colorAccent
                                  : theme.stateDefaultBorder

        Rectangle {
            width: 8
            height: 8
            anchors.centerIn: parent
            radius: width / 2
            visible: root.checked
            color: root.enabled
                       ? theme.colorAccent
                       : Qt.rgba(theme.colorAccent.r, theme.colorAccent.g,
                                 theme.colorAccent.b, 0.55)
        }
    }

    contentItem: Text {
        leftPadding: root.indicator.width + root.spacing
        text: root.text
        font: root.font
        color: root.enabled
                   ? theme.colorText
                   : Qt.rgba(theme.colorText.r, theme.colorText.g,
                             theme.colorText.b, 0.55)
        verticalAlignment: Text.AlignVCenter
        wrapMode: Text.WordWrap
    }

    background: Rectangle {
        color: "transparent"
    }
}
