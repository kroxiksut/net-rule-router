// Overlaps: rules of the two routes that claim the same sites, which one wins,
// and a way to confirm it or send those sites over the other route.
//
// Nothing here decides a winner — the pairs come from Rust. The buttons edit
// the rules list; nothing reaches the service until the user applies it.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../components"

ColumnLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    readonly property var controller: root.ruleOverlapsController
    /// A confirmed pair is settled, so it leaves the table unless asked for.
    property bool showResolved: false
    readonly property var shownRows: root.uiRevision >= 0
        ? (section.showResolved ? section.controller.ordered() : section.controller.pending())
        : []

    // Shared by the header and every row so the columns line up. The
    // decision sits right after the two rules so it stays in view in a
    // narrow window; the rule columns take what the fixed ones leave.
    readonly property int colDecisionWidth: 280
    readonly property int colReasonWidth: 170
    readonly property int colRuleMinWidth: 170
    readonly property real _fixedWidth: colDecisionWidth + colReasonWidth
        + 3 * root.uiTheme.spacingMd + 2 * root.uiTheme.spacingSm
    readonly property real tableWidth: Math.max(table.width, 2 * colRuleMinWidth + _fixedWidth)
    readonly property real colRuleWidth: (tableWidth - _fixedWidth) / 2

    Component.onCompleted: root.refreshRulesOverlaps()

    function _describe(side) {
        var type = String(side["rule-type"])
        var value = String(side.value)
        var typeLabel = type === "zone"
            ? root.tr("rules.type.zone", "Zone")
            : root.tr("rules.type.domain", "Domain")
        return root.tr("rules.overlaps.rule", "{value} ({type})")
            .replace("{value}", type === "suffix-domain" ? "*." + value : value)
            .replace("{type}", typeLabel)
    }
    function _routeText(side) {
        return root.routeLabel(section.controller.routeOf(side))
    }
    function _reason(overlap) {
        return String(overlap.kind) === "duplicate"
            ? root.tr("rules.overlaps.reason.duplicate", "Same rule on both routes")
            : root.tr("rules.overlaps.reason.nested", "Narrower rule")
    }
    /// The whole row as one sentence, for a screen reader.
    function _explain(overlap) {
        var sentence = String(overlap.kind) === "duplicate"
            ? root.tr("rules.overlaps.duplicate",
                "{winner} is set on both routes. It goes over {winner-route}: on a tie the main route wins.")
            : root.tr("rules.overlaps.nested",
                "{winner} goes over {winner-route}: it is narrower than {loser} on {loser-route}.")
        return sentence
            .replace("{winner}", section._describe(overlap.winner))
            .replace("{loser}", section._describe(overlap.loser))
            .replace("{winner-route}", section._routeText(overlap.winner))
            .replace("{loser-route}", section._routeText(overlap.loser))
    }

    component HeaderCell: Label {
        font.bold: true
        color: root.textColor
        elide: Text.ElideRight
        verticalAlignment: Text.AlignVCenter
        Accessible.role: Accessible.ColumnHeader
        Accessible.name: text
    }
    component Cell: Label {
        Layout.alignment: Qt.AlignVCenter
        wrapMode: Text.Wrap
        color: root.textColor
        Accessible.role: Accessible.Cell
        Accessible.name: text
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.Wrap
            color: root.textColor
            text: root.uiRevision >= 0
                ? root.tr("rules.overlaps.intro",
                    "When rules of the two routes cover the same sites, the narrower rule wins: an exact name beats a wildcard, a wildcard beats a zone, a longer name beats a shorter one. Check that each site below goes where you want it to: confirm it, or send it over the other route. Changes go to your rules list, where you review and apply them.")
                : ""
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        CheckBox {
            visible: section.controller.overlaps.length > section.controller.pendingCount
            checked: section.showResolved
            text: root.tr("rules.overlaps.show-resolved", "Show resolved")
            onToggled: section.showResolved = checked
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
        }
        ThemedButton {
            theme: root.uiTheme
            visible: section.controller.pendingCount > 0
            text: root.tr("rules.overlaps.confirm-all", "Confirm all")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section.controller.confirmAll()
        }
    }

    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: section.shownRows.length === 0
        wrapMode: Text.Wrap
        color: root.mutedTextColor
        text: root.uiRevision < 0 ? ""
            : section.controller.overlaps.length === 0
            ? root.tr("rules.overlaps.empty", "No rules of the two routes cover the same sites.")
            : root.tr("rules.overlaps.all-resolved", "Every overlap is resolved.")
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }

    // Takes the height the hidden table would, so the text stays at the top.
    Item {
        Layout.fillHeight: true
        visible: !table.visible
    }

    // Horizontal scroll for a narrow window; the header scrolls with the rows.
    Flickable {
        id: table
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: section.shownRows.length > 0
        clip: true
        contentWidth: section.tableWidth
        contentHeight: height
        flickableDirection: Flickable.HorizontalFlick
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.horizontal: ScrollBar { policy: ScrollBar.AsNeeded }

        Frame {
            id: header
            width: section.tableWidth
            padding: root.uiTheme.spacingSm
            background: Rectangle {
                color: root.uiTheme.colorPanel
                border.width: root.uiTheme.borderWidth
                border.color: root.uiTheme.stateDefaultBorder
                radius: root.uiTheme.radiusSm
            }
            RowLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingMd
                HeaderCell {
                    Layout.preferredWidth: section.colRuleWidth
                    text: root.tr("rules.overlaps.column.winner", "Rule that wins")
                }
                HeaderCell {
                    Layout.preferredWidth: section.colRuleWidth
                    text: root.tr("rules.overlaps.column.loser", "Overlaps with")
                }
                HeaderCell {
                    Layout.preferredWidth: section.colDecisionWidth
                    text: root.tr("rules.overlaps.column.decision", "Decision")
                }
                HeaderCell {
                    Layout.preferredWidth: section.colReasonWidth
                    text: root.tr("rules.overlaps.column.reason", "Why it wins")
                }
            }
        }

        ListView {
            id: rows
            anchors.top: header.bottom
            anchors.left: parent.left
            width: section.tableWidth
            height: table.height - header.height
            clip: true
            spacing: 0
            model: section.shownRows
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            delegate: Frame {
                id: row
                width: ListView.view ? ListView.view.width : 0
                padding: root.uiTheme.spacingSm
                topInset: root.uiTheme.spacingXxs
                height: rowLayout.implicitHeight + 2 * padding + topInset
                readonly property var overlap: modelData
                readonly property bool confirmed: root.uiRevision >= 0
                    && section.controller.isConfirmed(row.overlap)
                background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
                Accessible.role: Accessible.Row
                Accessible.name: section._explain(row.overlap)

                RowLayout {
                    id: rowLayout
                    anchors.fill: parent
                    spacing: root.uiTheme.spacingMd
                    ColumnLayout {
                        Layout.preferredWidth: section.colRuleWidth
                        Layout.alignment: Qt.AlignVCenter
                        spacing: 2
                        Cell {
                            Layout.fillWidth: true
                            font.bold: !row.confirmed
                            text: section._describe(row.overlap.winner)
                        }
                        Cell {
                            Layout.fillWidth: true
                            color: root.mutedTextColor
                            text: root.tr("rules.overlaps.via", "via {route}")
                                .replace("{route}", section._routeText(row.overlap.winner))
                        }
                    }
                    ColumnLayout {
                        Layout.preferredWidth: section.colRuleWidth
                        Layout.alignment: Qt.AlignVCenter
                        spacing: 2
                        Cell {
                            Layout.fillWidth: true
                            color: root.mutedTextColor
                            text: section._describe(row.overlap.loser)
                        }
                        Cell {
                            Layout.fillWidth: true
                            color: root.mutedTextColor
                            text: root.tr("rules.overlaps.via", "via {route}")
                                .replace("{route}", section._routeText(row.overlap.loser))
                        }
                    }
                    // Recipe 32: the layout sees the Item, not the positioner.
                    Item {
                        Layout.preferredWidth: section.colDecisionWidth
                        Layout.preferredHeight: actions.height
                        Layout.alignment: Qt.AlignVCenter
                        Flow {
                            id: actions
                            anchors.left: parent.left
                            anchors.right: parent.right
                            spacing: root.uiTheme.spacingSm
                            Label {
                                visible: row.confirmed
                                height: askAgain.height
                                verticalAlignment: Text.AlignVCenter
                                color: root.mutedTextColor
                                text: root.tr("rules.overlaps.confirmed", "Confirmed")
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }
                            ThemedButton {
                                id: askAgain
                                theme: root.uiTheme
                                visible: row.confirmed
                                text: root.tr("rules.overlaps.unconfirm", "Ask again")
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                onClicked: section.controller.unconfirm(row.overlap)
                            }
                            ThemedButton {
                                theme: root.uiTheme
                                visible: !row.confirmed
                                highlighted: true
                                text: root.tr("rules.overlaps.confirm", "Correct")
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                Accessible.description: section._explain(row.overlap)
                                onClicked: section.controller.confirm(row.overlap)
                            }
                            ThemedButton {
                                theme: root.uiTheme
                                visible: section.controller.canReroute(row.overlap)
                                enabled: root.allowUserRuleEdits !== false
                                text: root.tr("rules.overlaps.send-over", "Send over {route} instead")
                                    .replace("{route}", root.routeLabel(String(row.overlap.loser.route)))
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                onClicked: section.controller.sendOverLoserRoute(row.overlap)
                            }
                            Label {
                                visible: !section.controller.canReroute(row.overlap)
                                width: actions.width
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.tr("rules.overlaps.block-note",
                                    "A block rule is part of this pair; change it in the rules list.")
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }
                        }
                    }
                    Cell {
                        Layout.preferredWidth: section.colReasonWidth
                        color: root.mutedTextColor
                        text: section._reason(row.overlap)
                    }
                }
            }
        }
    }
}
