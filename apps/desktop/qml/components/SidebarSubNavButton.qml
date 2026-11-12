import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// The caller wires navigation through its section controller.
ThemedButton {
    id: control

    // The ApplicationWindow. Not `root`: that is ThemedButton's own id.
    property var shell: null
    property string sectionId: ""
    // Settings categories need selection independent of their section.
    property var selected: null
    property string iconName: ""
    // Items waiting in the section; hidden at zero.
    property int badge: 0
    // Mouse focus is quiet unless enhanced focus is requested.
    readonly property bool focusShown: visualFocus
        || (activeFocus && shell.prefs.enhancedFocus === true)

    theme: shell.uiTheme
    Layout.fillWidth: true
    Layout.preferredWidth: 0
    Layout.minimumWidth: 0
    highlighted: control.selected !== null ? control.selected === true
        : shell.section === control.sectionId
    Accessible.name: control.text
    ToolTip.visible: control.hovered && shell.prefs.tooltipsEnabled
    ToolTip.text: control.text

    background: PanelSurface {
        theme: control.theme
        cornerRadius: control.theme.radiusSm
        color: control.highlighted ? control.shell.accentColor
            : !control.enabled ? control.theme.stateDisabledFill
            : (control.hovered ? control.theme.stateHoverFill : control.shell.panelColor)
        border.width: control.focusShown ? control.theme.focusBorderWidth : control.theme.borderWidth
        border.color: control.focusShown
            ? (control.highlighted ? control.theme.stateFocusedBorderOnFill : control.theme.colorButtonOutline)
            : control.highlighted ? control.theme.stateSelectedBorder
            : !control.enabled ? control.theme.stateDisabledBorder
            : control.theme.stateDefaultBorder
        Rectangle {
            visible: control.focusShown && control.highlighted
            anchors.fill: parent
            anchors.margins: control.theme.focusBorderWidth
            radius: Math.max(0, parent.radius - control.theme.focusBorderWidth)
            color: "transparent"
            border.width: control.theme.borderWidth
            border.color: control.theme.stateFocusedInnerOnFill
        }
    }
    contentItem: RowLayout {
        spacing: control.iconName !== "" ? control.theme.spacingXs : 0
        Image {
            visible: control.iconName !== ""
            opacity: control.enabled ? 1.0 : 0.55
            source: control.iconName === "" ? "" : control.highlighted
                ? control.shell.uiIconSourceOnAccent(control.iconName)
                : control.shell.uiIconSource(control.iconName)
            sourceSize.width: 16
            sourceSize.height: 16
            Layout.preferredWidth: visible ? 16 : 0
            Layout.preferredHeight: visible ? 16 : 0
            fillMode: Image.PreserveAspectFit
            asynchronous: true
        }
        Label {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            text: control.text
            color: control.highlighted ? palette.highlightedText
                : (control.enabled ? control.shell.textColor : control.shell.mutedTextColor)
            elide: Text.ElideRight
            verticalAlignment: Text.AlignVCenter
        }
        Label {
            visible: control.badge > 0
            text: String(control.badge)
            color: control.highlighted ? palette.highlightedText : control.shell.accentColor
            font.bold: true
        }
    }
}
