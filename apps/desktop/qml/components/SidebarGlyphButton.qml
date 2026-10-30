import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Square navigation-rail control carrying one text glyph (collapse toggle,
// submenu chevron). The name doubles as the tooltip, so the glyph is never the
// only source of meaning.
ThemedButton {
    id: control

    // The ApplicationWindow. Not `root`: that is ThemedButton's own id.
    property var shell: null
    property string glyph: ""
    property int glyphPixelSize: 0
    // The focus ring follows the keyboard: a click leaves focus here without
    // drawing it, unless the user asked for focus to show always.
    readonly property bool focusShown: visualFocus
        || (activeFocus && shell.prefs.enhancedFocus === true)

    theme: shell.uiTheme
    ToolTip.visible: hovered
    ToolTip.delay: 400
    ToolTip.text: Accessible.name
    Accessible.role: Accessible.Button

    background: PanelSurface {
        theme: control.theme
        cornerRadius: control.theme.radiusSm
        color: control.hovered ? control.theme.stateHoverFill : control.shell.panelColor
        border.width: control.focusShown ? control.theme.focusBorderWidth : control.theme.borderWidth
        border.color: control.focusShown ? control.theme.colorButtonOutline : control.theme.stateDefaultBorder
    }
    contentItem: Label {
        text: control.glyph
        color: control.shell.accentColor
        font.pixelSize: control.glyphPixelSize > 0 ? control.glyphPixelSize : control.font.pixelSize
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }
}
