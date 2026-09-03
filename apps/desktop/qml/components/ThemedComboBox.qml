import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Window 2.15

// Themed ComboBox wrapper. Native style ignores palette for the closed
// combobox and the dropdown popup. Override contentItem, background,
// indicator, popup background and a default delegate so the control
// follows the active theme. Callers may still override `delegate` and
// `popup.width` for custom labels.
ComboBox {
    id: root
    property var theme
    property var labelResolver: null

    // Accessible baseline, declared once here instead of at 34 call sites.
    // Qt derives a name from `text` only for `AbstractButton`, and a combo box
    // has no `text`, so without this a screen reader announces a bare "combo
    // box" and the user is told nothing about which one. The tooltip is
    // mirrored into the description for the same reason a tooltip may never be
    // the only carrier of meaning: it is unreachable from the keyboard.
    // A caller that sets either property overrides what is declared here.
    Accessible.role: Accessible.ComboBox
    Accessible.name: root.displayText
    Accessible.description: root.ToolTip.text

    function _labelFor(item) {
        if (typeof labelResolver === "function") return labelResolver(item)
        if (item === null || item === undefined) return ""
        if (typeof item === "object" && root.textRole && item[root.textRole] !== undefined)
            return String(item[root.textRole])
        return String(item)
    }

    contentItem: Text {
        leftPadding: theme.spacingSm
        rightPadding: root.indicator ? root.indicator.width + root.spacing : theme.spacingSm
        text: root.displayText
        font: root.font
        color: root.enabled ? theme.colorText
                            : Qt.rgba(theme.colorText.r, theme.colorText.g,
                                      theme.colorText.b, 0.55)
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
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

    indicator: Text {
        x: root.width - width - theme.spacingSm
        y: (root.height - height) / 2
        text: "▾"
        color: root.enabled ? theme.colorText
                            : Qt.rgba(theme.colorText.r, theme.colorText.g,
                                      theme.colorText.b, 0.55)
        font.pixelSize: root.font.pixelSize
    }

    delegate: ItemDelegate {
        width: ListView.view ? ListView.view.width : root.popup.width
        highlighted: root.highlightedIndex === index
        background: Rectangle {
            color: highlighted ? theme.colorAccent : theme.colorPanel
            border.width: theme.borderWidth
            border.color: theme.stateDefaultBorder
        }
        contentItem: Text {
            leftPadding: theme.spacingSm
            rightPadding: theme.spacingSm
            text: root._labelFor(typeof modelData !== "undefined" ? modelData : model)
            color: highlighted ? theme.colorOnAccent : theme.colorText
            verticalAlignment: Text.AlignVCenter
            wrapMode: Text.WordWrap
            maximumLineCount: 3
            elide: Text.ElideRight
        }
    }

    popup: Popup {
        id: themedPopup
        y: root.height - 1
        width: root.width
        // The default popup is clamped to the window; a custom one whose height
        // is only ever `contentHeight` is not, so a long list runs off the
        // bottom of the screen with no way to reach the end of it. Cap at the
        // space actually below the field (or above it, whichever is larger),
        // and let the list scroll inside that.
        readonly property real _below: root.Window.window
            ? root.Window.window.height - root.mapToItem(null, 0, root.height).y - 8
            : 320
        readonly property real _above: root.Window.window
            ? root.mapToItem(null, 0, 0).y - 8
            : 320
        readonly property real _room: Math.max(120, Math.max(_below, _above))
        height: Math.min(contentItem.implicitHeight + topPadding + bottomPadding, _room)
        padding: theme.spacingXxs
        background: Rectangle {
            color: theme.colorPanel
            border.width: theme.borderWidth
            border.color: theme.stateDefaultBorder
            radius: theme.radiusSm
        }
        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: root.popup.visible ? root.delegateModel : null
            currentIndex: root.highlightedIndex
            // Only meaningful once the popup can be shorter than its content,
            // which is what the height cap above establishes.
            boundsBehavior: Flickable.StopAtBounds
            ScrollIndicator.vertical: ScrollIndicator {
                active: true
                visible: parent.contentHeight > parent.height
            }
        }
    }
}
