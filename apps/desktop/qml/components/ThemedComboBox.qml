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
    // Optional `function(item) -> bool`: an item it rejects is shown but cannot
    // be picked with the mouse. Keyboard stepping still lands on it, so the
    // caller also gates whatever acts on the selection.
    property var itemEnabledResolver: null
    // Optional `function(item) -> bool`: an item it rejects takes no room in
    // the popup; indexes stay those of the model.
    property var itemVisibleResolver: null

    // The visible label beside the box. A screen reader hears it with the
    // value ("Theme: Dark"); the value alone does not say which box it is.
    property string accessibleLabel: ""

    // The tooltip is mirrored into the description: it is unreachable from
    // the keyboard. A caller that sets either property overrides these.
    Accessible.role: Accessible.ComboBox
    Accessible.name: root.accessibleLabel !== ""
        ? root.accessibleLabel.replace(/:\s*$/, "") + ": " + root.displayText
        : root.displayText
    Accessible.description: root.ToolTip.text

    function _labelFor(item) {
        if (typeof labelResolver === "function") return labelResolver(item)
        if (item === null || item === undefined) return ""
        if (typeof item === "object" && root.textRole && item[root.textRole] !== undefined)
            return String(item[root.textRole])
        return String(item)
    }
    // A ListModel with a single role hands its delegate that role's bare value as
    // `modelData`; resolvers expect the row, so give them `model` instead.
    function _delegateItem(data, row) {
        if (data !== undefined && data !== null && typeof data === "object") return data
        if (root.textRole && row && row[root.textRole] !== undefined) return row
        return data !== undefined ? data : row
    }
    function _itemEnabled(item) {
        return typeof itemEnabledResolver === "function" ? !!itemEnabledResolver(item) : true
    }
    function _itemVisible(item) {
        return typeof itemVisibleResolver === "function" ? !!itemVisibleResolver(item) : true
    }
    function _rowAt(i) {
        if (!model) return undefined
        if (typeof model.get === "function") return model.get(i)
        return Array.isArray(model) ? model[i] : undefined
    }
    /// The next row the popup shows from `from` in direction `step`, -1 for none.
    function _shownIndexFrom(from, step) {
        for (var i = from + step; i >= 0 && i < count; i += step)
            if (_itemVisible(_rowAt(i))) return i
        return -1
    }

    // With rows hidden from the popup, Up and Down step over them too: the
    // stock stepping lands on a row nobody sees and picks it.
    Keys.onPressed: function(event) {
        if (typeof itemVisibleResolver !== "function") return
        if (event.key !== Qt.Key_Up && event.key !== Qt.Key_Down) return
        event.accepted = true
        var step = event.key === Qt.Key_Down ? 1 : -1
        var next = _shownIndexFrom(popup.visible ? highlightedIndex : currentIndex, step)
        if (next < 0) return
        if (!popup.visible) {
            currentIndex = next
            activated(next)
            return
        }
        // `highlightedIndex` is read-only: walk the stock stepping onto the row.
        for (var guard = 0; highlightedIndex !== next && guard < count; guard += 1) {
            if (step > 0) incrementCurrentIndex()
            else decrementCurrentIndex()
        }
    }

    contentItem: Text {
        leftPadding: theme.spacingSm
        rightPadding: root.indicator ? root.indicator.width + root.spacing : theme.spacingSm
        text: root.displayText
        // Items include adapter and program names: never read them as markup.
        textFormat: Text.PlainText
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
        border.width: root.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        border.color: root.activeFocus
                          ? theme.colorButtonOutline
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
        id: themedDelegate
        width: ListView.view ? ListView.view.width : root.popup.width
        enabled: root._itemEnabled(root._delegateItem(typeof modelData !== "undefined" ? modelData : undefined, model))
        visible: root._itemVisible(root._delegateItem(typeof modelData !== "undefined" ? modelData : undefined, model))
        height: visible ? implicitHeight : 0
        highlighted: root.highlightedIndex === index
        background: Rectangle {
            color: highlighted ? theme.colorAccent : theme.colorPanel
            border.width: theme.borderWidth
            border.color: theme.stateDefaultBorder
        }
        contentItem: Text {
            leftPadding: theme.spacingSm
            rightPadding: theme.spacingSm
            text: root._labelFor(root._delegateItem(typeof modelData !== "undefined" ? modelData : undefined, model))
            textFormat: Text.PlainText
            color: highlighted ? theme.colorOnAccent
                : themedDelegate.enabled ? theme.colorText
                : Qt.rgba(theme.colorText.r, theme.colorText.g, theme.colorText.b, 0.55)
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
