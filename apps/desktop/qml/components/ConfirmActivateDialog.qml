// Final confirmation before applying a reviewed
// mutation.
//
// Receives the same wire `ReviewSummaryResponse` the
// ReviewDiffDialog rendered, plus the IPC-level
// `confirmationToken` issued by the service on the dry-run pass.
// The dialog body text varies by risk level (low/medium/high/
// critical). For Critical, an "I understand the risk" checkbox is
// required before the Confirm button enables — that's the
// design-memory contract for the catastrophic-config bucket.
//
// Contract:
// - `summary` (object) — wire ReviewSummaryResponse (only
//   `risk-level` is read here).
// - `confirmationToken` (string) — opaque service-issued token to
//   be echoed on the confirm `rpcMutationSubmit` call.
// - `signal confirmed(token)` — emitted when user confirms.
//   Caller invokes `rpcMutationSubmit(kind, payload, false, token)`.
// - `signal cancelled()` — emitted on Cancel / close.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root
    title: typeof root.tr === "function"
        ? root.tr("dialog.confirm-activate.title", "Confirm activation")
        : "Confirm activation"

    modal: true
    // Render inside the main window overlay (themed), not a separate
    // top-level OS window — see ReviewDiffDialog for the rationale.
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    width: 480
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    property var ownerRoot: null
    property var summary: ({})
    property string confirmationToken: ""

    signal confirmed(string token)
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function riskLevelSlug() {
        var s = summary && summary["risk-level"] ? String(summary["risk-level"]) : "low"
        return s
    }

    function bodyText() {
        var slug = riskLevelSlug()
        return tr("dialog.confirm-activate.body-" + slug, "Apply these changes?")
    }

    /// Critical risk requires the "I understand" checkbox to be
    /// ticked before Confirm enables. All other levels skip the
    /// checkbox.
    function isCritical() {
        return riskLevelSlug() === "critical"
    }

    property bool _understandChecked: false

    // Reset the checkbox AND focus the Cancel
    // button on open. Cancel-default is the safer keyboard target
    // because Confirm is destructive (Apply changes) and on Critical
    // risk the user must consciously tick the checkbox before
    // moving to Confirm.
    onOpened: {
        _understandChecked = false
        if (cancelButton) cancelButton.forceActiveFocus()
    }
    onRejected: cancelled()

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: root.bodyText()
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: root.bodyText()
        }

        CheckBox {
            id: understandCheckbox
            visible: root.isCritical()
            checked: root._understandChecked
            onCheckedChanged: root._understandChecked = checked
            text: root.tr(
                "dialog.confirm-activate.checkbox-understand",
                "I understand the risk and want to proceed"
            )
            Layout.fillWidth: true
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            Accessible.description: root.tr(
                "dialog.confirm-activate.checkbox-understand-description",
                "Required acknowledgement before applying a Critical-risk activation"
            )
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                id: cancelButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.confirm-activate.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.confirm-activate.cancel-description",
                    "Cancel the activation and keep the previous rule set"
                )
                onClicked: { root.cancelled(); root.close() }
            }
            ThemedButton {
                id: confirmButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.confirm-activate.confirm", "Apply changes")
                highlighted: true
                enabled: !root.isCritical() || root._understandChecked
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.confirm-activate.confirm-description",
                    "Apply the reviewed rule set and start the activation"
                )
                onClicked: {
                    root.confirmed(root.confirmationToken)
                    root.close()
                }
            }
        }
    }
}
