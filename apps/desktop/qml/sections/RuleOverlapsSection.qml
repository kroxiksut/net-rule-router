// Overlaps: rules of the two routes that claim the same sites, which one wins,
// and a way to confirm it or send those sites over the other route. Below the
// intro, the conflicts the service found in the APPLIED rules: rules that
// share addresses rather than names, and rules it cannot enforce as written.
//
// Nothing here decides a winner — the pairs come from Rust. The buttons edit
// the rules list; nothing reaches the service until the user applies it.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../components"
import "../lib/pure.js" as Pure

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

    readonly property var conflicts: section.controller.conflicts

    Component.onCompleted: {
        root.refreshRulesOverlaps()
        if (typeof root.refreshUnenforcedAppRules === "function")
            root.refreshUnenforcedAppRules()
    }

    function _describe(side) { return section.controller.describe(side) }
    function _routeText(side) { return section.controller.routeText(side) }
    function _blockWinsTie(overlap) {
        return !!overlap && overlap["block-wins-tie"] === true
    }
    function _mainStays(overlap) {
        return !!overlap && overlap["main-stays-when-additional-down"] === true
    }
    function _mainStaysText() { return section.controller.mainStaysText() }
    function _reason(overlap) {
        if (section._blockWinsTie(overlap))
            return root.tr("rules.overlaps.reason.block-tie", "A deny wins a tie")
        var kind = String(overlap.kind)
        return kind === "duplicate"
            ? root.tr("rules.overlaps.reason.duplicate", "Same rule on both routes")
            : kind === "intersecting"
            ? root.tr("rules.overlaps.reason.intersecting", "Narrower where they meet")
            : root.tr("rules.overlaps.reason.nested", "Narrower rule")
    }
    function _intersecting(overlap) {
        return !!overlap && String(overlap.kind) === "intersecting"
    }
    /// The whole row as one sentence, for a screen reader.
    function _explain(overlap) { return section.controller.explain(overlap) }

    /// One service-reported conflict as a sentence.
    function _conflictText(c) {
        var ip = String(c.ip || "")
        var kind = String(c.kind)
        var text = kind === "literal-block-overrides-route"
            ? root.tr("rules.overlaps.conflicts.literal-block",
                "{rule}: {host} resolves to {ip}, and a deny of that address wins over any name rule, so the address is denied.")
            : kind === "network-carving-over-cap"
            ? root.tr("rules.overlaps.conflicts.carving-over-cap",
                "{rule} holds more narrower rules than can be carved out of it, so it applies to its whole network and the narrower rules inside it do not take effect. Split it into smaller networks.")
            : kind === "unsupported-rule-shape"
            ? root.tr("rules.overlaps.conflicts.unsupported-shape",
                "{rule} for {app} is not enforced: a rule that limits an address to one application cannot be carried out yet, so it is skipped rather than applied to every application.")
            : kind === "protected-target"
            ? root.tr("rules.overlaps.conflicts.protected", "The rule {rule} is not applied. {reason}")
            : kind === "override-needs-confirmation"
            ? root.tr("rules.overlaps.conflicts.override-pending",
                "The rule {rule} asks to apply despite the protection and is not applied until you confirm it in the rules list. {reason}")
            : kind === "folder-over-cap"
            ? root.tr("rules.overlaps.conflicts.folder-over-cap",
                "{rule} covers the first {count} programs of its folder. The folder holds more, and those are not covered: name the folder of the program you mean instead.")
            : kind === "other-users-folder"
            ? root.tr("rules.overlaps.conflicts.other-users-folder",
                "The rule {rule} is not applied: its folder is in another user's profile, and a rule decides only for its owner's programs. To cover each user's own folder, start the path from %LOCALAPPDATA%, %APPDATA% or %USERPROFILE% on Windows, or from ~ on Linux and macOS.")
            : root.tr("rules.overlaps.conflicts.leak",
                "{rule} does not deny {host}: it shares {ip} with {via}, which a narrower rule routes, so the address stays open.")
        // The protection says why in the rules table's own words.
        var reason = String(c.reason || "")
        var reasonText = reason === "" ? ""
            : root.tr((reason === "file-in-system-folder"
                    ? "rules.validation.match-value-warning.protected-"
                    : "rules.validation.match-value-invalid.protected-") + reason, reason)
        text = text.split("{reason}").join(reasonText)
        text = text.split("{rule}").join(Pure.displayText(c["rule-value"] || c["rule-id"] || ""))
            .split("{app}").join(Pure.displayText(c.app))
            .split("{host}").join(Pure.displayText(c.host || c["rule-value"] || ""))
            .split("{via}").join(Pure.displayText(c["via-host"]))
            .split("{ip}").join(ip)
        // A folder's count is the programs it covers, not more addresses.
        if (kind === "folder-over-cap")
            return text.split("{count}").join(String(Number(c.count || 0)))
        var more = Number(c.count || 0) - 1
        if (more > 0)
            text += " " + root.tr("rules.overlaps.conflicts.more", "Addresses affected besides this one: {count}.")
                .replace("{count}", String(more))
        return text
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
        textFormat: Text.PlainText
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
                    "When rules of the two routes cover the same sites or addresses, the narrower rule wins: an exact name beats a wildcard, a wildcard beats a zone, a longer name beats a shorter one; an exact address beats a subnet or range, a smaller network beats a larger one. Check that each item below goes where you want it to: confirm it, or send it over the other route. Changes go to your rules list, where you review and apply them.")
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

    Frame {
        Layout.fillWidth: true
        visible: section.conflicts.length > 0
        padding: root.uiTheme.spacingSm
        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingXs
            Label {
                Layout.fillWidth: true
                font.bold: true
                wrapMode: Text.Wrap
                color: root.textColor
                text: root.tr("rules.overlaps.conflicts.title", "Conflicts in the applied rules")
                Accessible.role: Accessible.Heading
                Accessible.name: text
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                color: root.mutedTextColor
                text: root.tr("rules.overlaps.conflicts.hint",
                    "Rules the service enforces differently from how they read, as it enforces them now. They update after you apply changes.")
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            Repeater {
                model: section.conflicts
                delegate: Label {
                    required property var modelData
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    textFormat: Text.PlainText
                    color: root.uiTheme.colorWarning
                    text: section._conflictText(modelData)
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }
            }
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
            ? root.tr("rules.overlaps.empty", "No rules of the two routes cover the same sites or addresses.")
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
                        Cell {
                            Layout.fillWidth: true
                            visible: section._blockWinsTie(row.overlap)
                            color: root.uiTheme.colorWarning
                            text: root.tr("rules.overlaps.block-tie-warning",
                                "The other rule names the same sites and never applies.")
                        }
                        Cell {
                            Layout.fillWidth: true
                            visible: section._mainStays(row.overlap)
                            color: root.mutedTextColor
                            text: section._mainStaysText()
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
                                enabled: root.ruleEditsLocked !== true
                                text: root.tr("rules.overlaps.send-over", "Send over {route} instead")
                                    .replace("{route}", root.routeLabel(String(row.overlap.loser.route)))
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                onClicked: section.controller.sendOverLoserRoute(row.overlap)
                            }
                            // The winner only partly overlaps; moving it moves
                            // all of its addresses.
                            Label {
                                visible: section._intersecting(row.overlap)
                                    && section.controller.canReroute(row.overlap)
                                width: actions.width
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.tr("rules.overlaps.send-over-whole",
                                    "This moves the whole rule, including addresses the other rule does not cover.")
                                Accessible.role: Accessible.StaticText
                                Accessible.name: text
                            }
                            Label {
                                visible: !section.controller.canReroute(row.overlap)
                                width: actions.width
                                wrapMode: Text.Wrap
                                color: root.mutedTextColor
                                text: root.tr("rules.overlaps.block-note",
                                        "A deny rule is part of this pair; change it in the rules list.")
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
