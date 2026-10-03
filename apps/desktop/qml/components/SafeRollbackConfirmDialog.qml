// Confirm dialog for "Safe rollback" of the user's own rules. The caller
// opens it in `phase: "loading"`, asks the service what a rollback would
// restore and fills `phase` / `target` / `errorText`; "Roll back" exists only
// once there is a target. Emits `confirmed()`, the caller runs the rollback.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// "loading" | "ready" | "none" | "error".
    property string phase: "loading"
    /// The dry-run's `target` when `phase` is "ready".
    property var target: null
    property string errorText: ""
    signal confirmed()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function bodyText() {
        if (phase === "ready") {
            var at = target ? Number(target["activated-at"] || 0) * 1000 : 0
            return tr("dialog.safe-rollback.body-ready",
                    "Your current rules will be replaced by the ones you applied on {time} "
                    + "({count} rules), and routing will follow them right away.")
                .replace("{time}", Pure.formatTimestamp(at))
                .replace("{count}", String(target ? Number(target["rule-count"] || 0) : 0))
        }
        if (phase === "none") {
            return tr("dialog.safe-rollback.body-none",
                "There is nothing to roll back to: no earlier version of your rules has been applied.")
        }
        if (phase === "error") {
            return tr("dialog.safe-rollback.body-error", "Cannot roll back: ") + errorText
        }
        return tr("dialog.safe-rollback.body-loading", "Looking for the previous version of your rules…")
    }

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 460
    title: tr("dialog.safe-rollback.title", "Roll back to the previous configuration?")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    background: Rectangle {
        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "transparent"
        border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 0
        border.color: root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "transparent"
        radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 0
    }
    contentItem: ColumnLayout {
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.bodyText()
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.phase === "ready" || root.phase === "loading"
                    ? root.tr("action.cancel", "Cancel")
                    : root.tr("action.close", "Close")
                onClicked: root.close()
            }
            ThemedButton {
                visible: root.phase === "ready"
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.safe-rollback.confirm", "Roll back")
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
