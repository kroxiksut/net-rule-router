import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Themed Button wrapper that respects ThemeTokens regardless of the
// underlying Qt style. Default Native (Windows) style ignores
// `palette.button` / `palette.buttonText`, so footer buttons are unreadable
// on dark / high-contrast themes. This component sets explicit contentItem
// and background so colours follow the active theme. The contentItem also
// renders the Action's `icon.source` next to the label when one is set.
Button {
    id: root
    property var theme
    // Opt-in multi-line label. The default
    // single-line + ElideRight clips long labels (e.g. the full-width sidebar
    // "Revoke admin approval"); set `wrapText: true` to wrap instead.
    property bool wrapText: false
    // Opt-in destructive/danger styling. When
    // true the button paints with the theme's danger colour (red) and
    // danger-contrast text, marking a security/destructive action (e.g. the
    // sidebar "Revoke admin approval"). Composes with `highlighted` —
    // `danger` wins so a destructive primary action still reads as red.
    property bool danger: false
    readonly property color _dangerFill: theme.colorDanger

    activeFocusOnTab: true
    implicitWidth: Math.max(72, contentItem.implicitWidth + theme.spacingMd * 2)
    implicitHeight: Math.max(28, contentItem.implicitHeight + theme.spacingXs * 2)

    contentItem: RowLayout {
        spacing: root.icon.source !== "" ? root.theme.spacingSm : 0
        Image {
            visible: String(root.icon.source) !== ""
            source: root.icon.source
            sourceSize.width: 16
            sourceSize.height: 16
            Layout.preferredWidth: visible ? 16 : 0
            Layout.preferredHeight: visible ? 16 : 0
            fillMode: Image.PreserveAspectFit
            opacity: root.enabled ? 1.0 : 0.55
            asynchronous: true
        }
        // `Layout.fillWidth` so the label
        // actually elides when the button is narrower than the text
        // (toolbar buttons are fillWidth in a fixed-width column; long
        // localized strings used to spill past the button background).
        // Centred within the available width; the icon sits to its left.
        Text {
            Layout.fillWidth: true
            text: root.text
            font: root.font
            // Highlighted (primary-action) buttons get accent-contrast text;
            // see the background note below.
            color: !root.enabled
                ? Qt.rgba(root.theme.colorText.r, root.theme.colorText.g, root.theme.colorText.b, 0.55)
                : ((root.danger || root.highlighted) ? root.theme.colorOnAccent : root.theme.colorText)
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            wrapMode: root.wrapText ? Text.Wrap : Text.NoWrap
            elide: root.wrapText ? Text.ElideNone : Text.ElideRight
            maximumLineCount: root.wrapText ? 3 : 1
        }
    }

    // Actually render `highlighted`. Qt's
    // `Button.highlighted` marks the primary action, but this wrapper's
    // background ignored it, so every `highlighted: true` button (the
    // UnsavedChangesGuard "Save and continue", the drift dialog "Apply app
    // state", …) looked identical to a normal button. Highlighted now paints
    // with the theme accent (hover/press shaded), giving the user a clear
    // primary affordance.
    background: Rectangle {
        radius: theme.radiusSm
        color: !root.enabled
                   ? theme.stateDisabledFill
                   : root.danger
                       ? (root.pressed
                              ? Qt.darker(root._dangerFill, 1.18)
                              : root.hovered
                                  ? Qt.lighter(root._dangerFill, 1.12)
                                  : root._dangerFill)
                       : root.highlighted
                       ? (root.pressed
                              ? Qt.darker(theme.colorAccent, 1.18)
                              : root.hovered
                                  ? Qt.lighter(theme.colorAccent, 1.12)
                                  : theme.colorAccent)
                       : root.pressed
                           ? theme.statePressedFill
                           : root.hovered
                               ? theme.stateHoverFill
                               : theme.stateDefaultFill
        border.width: theme.borderWidth
        border.color: root.activeFocus
                          ? theme.stateFocusedBorder
                          : !root.enabled
                              ? theme.stateDisabledBorder
                              : root.danger
                                  ? Qt.darker(root._dangerFill, 1.25)
                                  : root.highlighted
                                      ? theme.stateSelectedBorder
                                      : theme.stateDefaultBorder
    }
}
