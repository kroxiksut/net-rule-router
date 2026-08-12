// Single column of the three-pane ReviewDiffDialog.
//
// One column renders one diff bucket (Added / Removed / Modified+
// Retargeted). When `items` is empty, the column shows `emptyText`
// in muted styling so the user immediately sees "no changes of this
// kind". Each item is a wire `RuleSummaryEntryDto`-shaped object; the
// delegate renders `display + route`, and marks the row when the rule
// is disabled — such a rule is a real change on the wire but enforces
// nothing.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

ColumnLayout {
    id: root
    spacing: 4

    property var ownerRoot: null
    property string title: ""
    property var items: []
    property string emptyText: ""

    // Правила обоих маршрутов идут в один список. При импорте
    // пресета secondary часто кратно больше primary (напр. 232 против 64), и
    // primary-правила «терялись» внизу — пользователь думал, что загрузился
    // только второй файл. Сортируем primary вперёд (затем по display), чтобы
    // оба маршрута были видны сразу. Исходный `items` не мутируем.
    function _routeRank(r) {
        var s = String(r || "")
        if (s === "primary") return 0
        if (s === "secondary") return 1
        return 2
    }
    readonly property var sortedItems: {
        var arr = (root.items || []).slice()
        arr.sort(function(a, b) {
            var ra = (a && typeof a === "object") ? root._routeRank(a.route) : 9
            var rb = (b && typeof b === "object") ? root._routeRank(b.route) : 9
            if (ra !== rb) return ra - rb
            var da = (a && typeof a === "object") ? String(a.display || a.id || "") : String(a)
            var db = (b && typeof b === "object") ? String(b.display || b.id || "") : String(b)
            return da < db ? -1 : (da > db ? 1 : 0)
        })
        return arr
    }

    Label {
        Layout.fillWidth: true
        text: root.title + " (" + String(root.items.length) + ")"
        font.bold: true
        font.pixelSize: 12
        color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
    }

    Rectangle {
        Layout.fillWidth: true
        Layout.fillHeight: true
        color: root.ownerRoot ? root.ownerRoot.baseColor : palette.base
        border.color: root.ownerRoot ? root.ownerRoot.borderColor : palette.mid
        border.width: 1
        radius: 4

        ListView {
            id: list
            anchors.fill: parent
            anchors.margins: 4
            clip: true
            spacing: 2
            interactive: contentHeight > height
            model: root.sortedItems
            visible: root.items.length > 0
            // Visible scrollbar so a long Added/Removed/Modified list
            // signals there's more below the fold (the column is fixed
            // height inside the dialog). Always-on once content
            // overflows; otherwise auto-hidden.
            ScrollBar.vertical: ScrollBar {
                policy: list.contentHeight > list.height
                    ? ScrollBar.AlwaysOn : ScrollBar.AsNeeded
            }
            delegate: Rectangle {
                id: diffRow
                width: ListView.view.width
                height: itemLabel.implicitHeight + 6
                color: "transparent"
                // A disabled rule travels to the service and shows up here
                // like any other change, but enforces nothing — the row has to
                // say so, or the user reads "Added: example.com (secondary)"
                // as "it is routed now". Absent on the wire means enabled
                // (older services never reported the flag).
                readonly property bool entryEnabled:
                    !(typeof modelData === "object" && modelData !== null
                        && modelData.enabled === false)
                Label {
                    id: itemLabel
                    anchors.fill: parent
                    anchors.leftMargin: 6
                    verticalAlignment: Text.AlignVCenter
                    text: {
                        // `modelData` is a wire `RuleSummaryEntryDto`.
                        // Fall back to a stringified view if the shape
                        // differs.
                        if (typeof modelData === "object" && modelData !== null) {
                            var display = modelData.display
                                || modelData["display"] || modelData.id
                                || JSON.stringify(modelData)
                            var suffix = ""
                            if (!diffRow.entryEnabled && root.ownerRoot
                                    && typeof root.ownerRoot.tr === "function") {
                                suffix = "  · " + root.ownerRoot.tr(
                                    "label.disabled", "disabled")
                            }
                            var route = String(modelData.route || modelData["route"] || "")
                            if (route === "") return display + suffix
                            // Reuse the same locale tree the rest of
                            // the GUI uses for route labels so
                            // `[secondary]` becomes `[Дополнительный]`
                            // / `[Secondary]`. The `ownerRoot.routeLabel`
                            // helper additionally honours the user's
                            // custom route display names (preference).
                            var routeText = route
                            if (root.ownerRoot
                                    && typeof root.ownerRoot.routeLabel === "function") {
                                routeText = root.ownerRoot.routeLabel(route)
                            } else if (root.ownerRoot
                                    && typeof root.ownerRoot.tr === "function") {
                                routeText = root.ownerRoot.tr(
                                    "label." + route, route)
                            }
                            return display + "  [" + routeText + "]" + suffix
                        }
                        return String(modelData)
                    }
                    wrapMode: Text.Wrap
                    font.pixelSize: 11
                    font.italic: !diffRow.entryEnabled
                    color: diffRow.entryEnabled
                        ? (root.ownerRoot ? root.ownerRoot.textColor : palette.text)
                        : (root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.mid)
                }
            }
        }

        Label {
            anchors.centerIn: parent
            visible: root.items.length === 0
            text: root.emptyText
            font.italic: true
            font.pixelSize: 12
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.mid
        }
    }
}
