// Acknowledging a tamper / key-reset alert trusts the rule sets it lists, so
// the dialog shows exactly those rows before the user confirms. The list comes
// from the service's dry-run; the caller sends the same rows back on confirm.
// "Dumb" like the other confirms: it emits `confirmed()`, the caller acts.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Backend alert-kind slug (`db_tamper_detected`, `key_reset_with_existing_data`).
    property string alertKind: ""
    /// `unverified-rows` from the dry-run response.
    property var rows: []
    signal confirmed()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _scope(row) {
        return row.baseline
            ? tr("diag.alert.review.scope-baseline", "shared baseline")
            : tr("diag.alert.review.scope-user", "user rules")
    }

    function _rowText(row) {
        var when = Pure.formatTimestamp(Number(row["created-at"] || 0) * 1000)
        if (row["row-kind"] === "active-pointer") {
            return tr("diag.alert.review.row-pointer", "Which rule set is active ({scope}), set {when}")
                .replace("{scope}", _scope(row))
                .replace("{when}", when)
        }
        var source = String(row.source || "")
        var parts = [when, tr("diag.alert.review.source." + source, source), _scope(row)]
        if (row["rule-count"] !== undefined && row["rule-count"] !== null) {
            parts.push(tr("diag.alert.review.rule-count", "{count} rules")
                .replace("{count}", String(row["rule-count"])))
        }
        if (row.status === "active") {
            parts.push(tr("diag.alert.review.status-active", "in use"))
        }
        return parts.join(" · ")
    }

    title: tr("diag.alert.review.title", "Acknowledge security alert")
    modal: true
    popupType: Popup.Item
    anchors.centerIn: Overlay.overlay
    width: Math.min(560, Overlay.overlay ? Overlay.overlay.width - 32 : 560)
    standardButtons: Dialog.NoButton
    closePolicy: Popup.CloseOnEscape
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    onOpened: cancelButton.forceActiveFocus()

    contentItem: ColumnLayout {
        spacing: 12
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.rows.length === 0
                ? root.tr("diag.alert.review.body-empty",
                    "No rule set needs to be trusted. Acknowledging only closes the alert.")
                : root.alertKind === "key_reset_with_existing_data"
                    ? root.tr("diag.alert.review.body-key-reset",
                        "The integrity key was recreated, so the stored rule sets below can no longer be verified. Acknowledging trusts them as listed. Rule sets under a separate tampering alert are not included.")
                    : root.tr("diag.alert.review.body-tamper",
                        "The rule set below was changed outside the app. Acknowledging trusts its contents as listed. If it changes again before you confirm, it stays untrusted and a new alert is raised.")
        }
        ListView {
            id: rowList
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(contentHeight, 220)
            visible: root.rows.length > 0
            clip: true
            model: root.rows
            spacing: 4
            activeFocusOnTab: true
            keyNavigationEnabled: true
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            Accessible.role: Accessible.List
            Accessible.name: root.tr("diag.alert.review.list-name", "Rule sets to trust")
            highlightFollowsCurrentItem: true
            highlight: Rectangle {
                visible: rowList.activeFocus
                color: "transparent"
                border.width: 2
                border.color: root.ownerRoot ? root.ownerRoot.uiTheme.colorFocusRing : palette.highlight
                radius: 2
            }
            delegate: Label {
                required property var modelData
                width: rowList.width
                padding: 4
                wrapMode: Text.Wrap
                text: root._rowText(modelData)
                color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
                Accessible.role: Accessible.ListItem
                Accessible.name: text
            }
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                id: cancelButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("diag.alert.action-acknowledge", "Acknowledge")
                highlighted: true
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
