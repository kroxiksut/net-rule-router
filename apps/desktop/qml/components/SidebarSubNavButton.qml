import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// One entry of a navigation-rail submenu: optional icon, label and an optional
// count, selected while its section is open. The caller wires the click, since
// some entries open their section through a controller.
ThemedButton {
    id: control

    // The ApplicationWindow. Not `root`: that is ThemedButton's own id.
    property var shell: null
    property string sectionId: ""
    // Overrides the section match for entries whose selection is not a section
    // id (a settings category); null keeps the section match.
    property var selected: null
    property string iconName: ""
    // Items waiting in the section; hidden at zero.
    property int badge: 0

    theme: shell.uiTheme
    Layout.fillWidth: true
    highlighted: control.selected !== null ? control.selected === true
        : shell.section === control.sectionId
    Accessible.name: control.text

    background: PanelSurface {
        theme: control.theme
        cornerRadius: control.theme.radiusSm
        color: control.highlighted ? control.shell.accentColor
            : !control.enabled ? control.theme.stateDisabledFill
            : (control.hovered ? control.theme.stateHoverFill : control.shell.panelColor)
        border.color: control.highlighted ? control.theme.stateSelectedBorder
            : !control.enabled ? control.theme.stateDisabledBorder
            : (control.activeFocus ? control.theme.stateFocusedBorder : control.theme.stateDefaultBorder)
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
