import QtQuick 2.15
import QtQuick.Controls 2.15

// Themed ComboBox wrapper. Native style ignores palette for the closed
// combobox and the dropdown popup. Override contentItem, background,
// indicator, popup background and a default delegate so the control
// follows the active theme. Callers may still override `delegate` and
// `popup.width` for custom labels.
ComboBox {
    id: root
    property var theme
    property var labelResolver: null

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
        y: root.height - 1
        width: root.width
        implicitHeight: contentItem.implicitHeight
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
            ScrollIndicator.vertical: ScrollIndicator { }
        }
    }
}
