import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Menu item with explicit two-column layout: a left-aligned label that
// stretches across the popup width, and a muted right-aligned shortcut
// hint. Used for every entry in the application MenuBar so the shortcut
// text is reliably flushed right regardless of style. Inline `MenuItem`
// instances render through QML even when `Menu.delegate` is ignored, so
// this is the most reliable form on Windows.
//
// Keyboard wiring is handled by the top-level `Action` / `Shortcut`
// elements in `Main.qml`; this menu item only owns the click trigger and
// the visible label rendering.
MenuItem {
    id: root
    property var theme
    property string labelText: ""
    property string shortcutText: ""

    // `text` is preserved for accessibility and for code that reads the
    // MenuItem's text (some platforms expose it to screen readers via the
    // accessible interface). The visible rendering in `contentItem` ignores
    // it and uses `labelText` / `shortcutText` instead.
    text: labelText

    implicitHeight: 28

    contentItem: RowLayout {
        spacing: theme.spacingLg
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: theme.spacingXs
            text: root.labelText
            color: !root.enabled ? theme.colorTextMuted
                  : root.highlighted ? theme.colorOnAccent : theme.colorText
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }
        Label {
            Layout.rightMargin: theme.spacingXs
            text: root.shortcutText
            color: !root.enabled ? theme.colorTextMuted
                  : root.highlighted ? theme.colorOnAccent : theme.colorTextMuted
            horizontalAlignment: Text.AlignRight
            verticalAlignment: Text.AlignVCenter
        }
    }

    background: Rectangle {
        color: root.highlighted ? theme.colorAccent
              : (root.hovered ? theme.stateHoverFill : theme.colorPanel)
    }
}
