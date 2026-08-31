// Cleanup for exact rules a wildcard rule already covers.
//
// `*.example.com` covers `example.com` and everything under it, so an exact
// rule for a host beneath it is usually a leftover: deleting it changes
// nothing about where traffic goes. Not always, though — an exact rule in the
// OTHER route, or with a different action, is the user carving one host out of
// the wildcard on purpose. `nrr_shared::rules_overlap` decides which is which;
// this dialog only renders the two groups and reports what the user picked.
//
// Deletions land in the rules table like any manual edit — the user still
// applies them through the normal review flow.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog
    title: tr("dialog.rules-overlap.title", "Remove rules already covered")

    modal: true
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: dialog
        theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
        titleText: dialog.title
    }
    width: 640
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the dialog.
    property var ownerRoot: null

    /// Pair keys the user ticked for removal.
    property var checkedKeys: []

    signal removeRequested(var keys)
    signal keepRequested(var keys)

    function tr(key, fallback) {
        return (ownerRoot && typeof ownerRoot.tr === "function")
            ? ownerRoot.tr(key, fallback) : fallback
    }
    function _theme() { return ownerRoot ? ownerRoot.uiTheme : null }
    function _textColor() { return ownerRoot ? ownerRoot.textColor : "black" }
    function _mutedColor() { return ownerRoot ? ownerRoot.mutedTextColor : "gray" }

    function _pairs() {
        return (ownerRoot && typeof ownerRoot.overlapActionablePairs === "function")
            ? ownerRoot.overlapActionablePairs() : []
    }
    /// Pairs the user must judge themselves: the exact rule routes differently
    /// or blocks, so removing it WOULD change something.
    function _deliberate() {
        var all = (ownerRoot && ownerRoot.rulesOverlapPairs) || []
        var out = []
        for (var i = 0; i < all.length; i += 1) {
            if (all[i] && all[i].redundant !== true) out.push(all[i])
        }
        return out
    }
    function _key(pair) {
        return (ownerRoot && typeof ownerRoot.overlapPairKey === "function")
            ? ownerRoot.overlapPairKey(pair) : ""
    }
    function _routeLabel(role) {
        return (ownerRoot && typeof ownerRoot.routeLabel === "function")
            ? ownerRoot.routeLabel(String(role || "")) : String(role || "")
    }
    function _isChecked(key) { return dialog.checkedKeys.indexOf(key) >= 0 }
    function _setChecked(key, on) {
        var next = []
        for (var i = 0; i < dialog.checkedKeys.length; i += 1) {
            if (dialog.checkedKeys[i] !== key) next.push(dialog.checkedKeys[i])
        }
        if (on) next.push(key)
        dialog.checkedKeys = next
    }
    /// Everything spare is ticked on opening: that is the answer the user came
    /// for, and unticking one is cheaper than ticking twenty.
    function selectAllActionable() {
        var pairs = dialog._pairs()
        var keys = []
        for (var i = 0; i < pairs.length; i += 1) keys.push(dialog._key(pairs[i]))
        dialog.checkedKeys = keys
    }

    onOpened: dialog.selectAllActionable()

    contentItem: ColumnLayout {
        spacing: 10

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: dialog._textColor()
            text: dialog.tr("dialog.rules-overlap.body",
                "These rules name a host that one of your wildcard rules already covers. Removing them changes nothing about where your traffic goes — it only shortens the list.")
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.preferredHeight: 300
            clip: true
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            ColumnLayout {
                width: dialog.width - 48
                spacing: 8

                Label {
                    Layout.fillWidth: true
                    visible: dialog._pairs().length > 0
                    font.bold: true
                    color: dialog._textColor()
                    text: dialog.tr("dialog.rules-overlap.group-spare", "Safe to remove")
                        + " (" + dialog._pairs().length + ")"
                }
                Repeater {
                    model: dialog._pairs()
                    delegate: RowLayout {
                        Layout.fillWidth: true
                        spacing: 8
                        CheckBox {
                            checked: dialog._isChecked(dialog._key(modelData))
                            onToggled: dialog._setChecked(dialog._key(modelData), checked)
                            Accessible.name: String(modelData["covered-host"] || "")
                        }
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            color: dialog._textColor()
                            text: dialog.tr("dialog.rules-overlap.covered-by",
                                "{host} — already covered by *.{apex}")
                                .replace("{host}", String(modelData["covered-host"] || ""))
                                .replace("{apex}", String(modelData.apex || ""))
                        }
                        Label {
                            color: dialog._mutedColor()
                            font.pixelSize: 11
                            text: dialog._routeLabel(modelData["covered-route"])
                        }
                        ThemedButton {
                            theme: dialog._theme()
                            text: dialog.tr("dialog.rules-overlap.keep", "Keep")
                            ToolTip.visible: hovered
                            ToolTip.text: dialog.tr("dialog.rules-overlap.keep-tooltip",
                                "Leave this rule alone and stop offering it here.")
                            onClicked: dialog.keepRequested([dialog._key(modelData)])
                        }
                    }
                }

                Label {
                    Layout.fillWidth: true
                    Layout.topMargin: 6
                    visible: dialog._deliberate().length > 0
                    font.bold: true
                    color: dialog._textColor()
                    text: dialog.tr("dialog.rules-overlap.group-deliberate", "Your call")
                        + " (" + dialog._deliberate().length + ")"
                }
                Label {
                    Layout.fillWidth: true
                    visible: dialog._deliberate().length > 0
                    wrapMode: Text.WordWrap
                    color: dialog._mutedColor()
                    text: dialog.tr("dialog.rules-overlap.deliberate-body",
                        "These name a host under a wildcard but send it somewhere else, or block it. That is what an exception looks like, so nothing here is removed for you.")
                }
                Repeater {
                    model: dialog._deliberate()
                    delegate: RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        spacing: 8
                        Label {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            color: dialog._textColor()
                            text: dialog.tr("dialog.rules-overlap.exception-line",
                                "{host} ({coveredRoute}) under *.{apex} ({apexRoute})")
                                .replace("{host}", String(modelData["covered-host"] || ""))
                                .replace("{coveredRoute}", dialog._routeLabel(modelData["covered-route"]))
                                .replace("{apex}", String(modelData.apex || ""))
                                .replace("{apexRoute}", dialog._routeLabel(modelData["apex-route"]))
                        }
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true
            visible: dialog._pairs().length === 0
            wrapMode: Text.WordWrap
            color: dialog._mutedColor()
            text: dialog.tr("dialog.rules-overlap.empty", "Nothing is covered twice right now.")
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: dialog._theme()
                text: dialog.tr("action.cancel", "Cancel")
                onClicked: dialog.close()
            }
            ThemedButton {
                theme: dialog._theme()
                highlighted: true
                enabled: dialog.checkedKeys.length > 0
                text: dialog.tr("dialog.rules-overlap.remove", "Remove selected")
                onClicked: {
                    dialog.removeRequested(dialog.checkedKeys.slice())
                    dialog.close()
                }
            }
        }
    }
}
