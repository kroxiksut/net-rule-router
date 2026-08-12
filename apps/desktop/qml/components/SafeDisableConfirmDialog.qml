// Confirmation dialog for the tray-initiated
// safe-disable flow.
//
// Trigger: tray menu "Safe disable (temporary)…" → tray bridge
// launches `NetRuleRouter.exe --action=safe-disable` → secondary
// launcher writes `gui-activation.json` with `action: "safe-disable"`
// (+ optional `reason`) → primary GUI's `applyGuiActivationRequest`
// reads the action and opens this dialog.
//
// UX:
//   * Required reason TextField (audit trail).
//   * Confirm button stays disabled until the reason is non-empty.
//   * Cancel / Esc / close = no-op (the dialog just dismisses).
//   * On Confirm, the dialog emits `confirmed(reason)` — the host
//     decides what the next step is (RPC call or — until the bridge
//     lands — a logged stub).
//
// The host's `confirmed` handler runs the real two-phase safe-disable RPC
// (dry-run → confirm via `rpcProductImpactDisable`), with
// a toast tracking progress. This dialog only owns the UX path (reason capture
// + confirm gating); Cancel/Esc dismisses and reports a cancelled status.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog
    title: tr("dialog.safe-disable.title", "Safe disable")

    modal: true
    width: 520
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the dialog (provides `tr`,
    /// `uiTheme`, `textColor`).
    property var ownerRoot: null

    /// Reason text bound to the input. Pre-populated when the tray
    /// passes `--reason=...` (not used today; future Pro UX could
    /// supply context-aware defaults).
    property string reasonText: ""

    signal confirmed(string reason)
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    // Renamed from `reset()` to avoid colliding with Dialog's built-in
    // `reset` signal (Qt warning: "Duplicate method name: invalid
    // override of property change signal or superclass signal").
    function resetForOpen(prefilledReason) {
        reasonText = String(prefilledReason || "")
    }

    onRejected: { cancelled() }

    // Focus the reason field on open so the
    // user can start typing immediately. This is the destructive-
    // dialog exception to the "Cancel-default" rule because the
    // reason MUST be filled before Confirm becomes available
    // anyway, so accidental Enter is impossible.
    onOpened: { if (reasonField) reasonField.forceActiveFocus() }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: dialog.tr(
                "dialog.safe-disable.body",
                "Temporarily disable enforcement and remove all routes and filters owned by NetRuleRouter. The service stays running; you can re-enable at any time. This action is audited."
            )
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            Label {
                Layout.fillWidth: true
                text: dialog.tr(
                    "dialog.safe-disable.reason-label",
                    "Reason (required)")
                font.pixelSize: 12
                color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            }
            ThemedTextField {
                id: reasonField
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                Layout.fillWidth: true
                placeholderText: dialog.tr(
                    "dialog.safe-disable.reason-placeholder",
                    "Why are you disabling protection?")
                text: dialog.reasonText
                onTextChanged: dialog.reasonText = text
                Accessible.role: Accessible.EditableText
                Accessible.name: dialog.tr(
                    "dialog.safe-disable.reason-label",
                    "Reason (required)")
                Accessible.description: dialog.tr(
                    "dialog.safe-disable.reason-required",
                    "Please describe the reason — it is recorded in the audit trail.")
            }
            Label {
                Layout.fillWidth: true
                visible: dialog.reasonText.trim() === ""
                text: dialog.tr(
                    "dialog.safe-disable.reason-required",
                    "Please describe the reason — it is recorded in the audit trail.")
                font.pixelSize: 11
                color: dialog.ownerRoot
                    ? dialog.ownerRoot.uiTheme.colorWarning
                    : "#d97706"
                wrapMode: Text.Wrap
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.safe-disable.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.safe-disable.cancel-description",
                    "Dismiss the dialog and leave enforcement active")
                onClicked: { dialog.cancelled(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.safe-disable.confirm", "Disable now")
                highlighted: true
                enabled: dialog.reasonText.trim() !== ""
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.safe-disable.confirm-description",
                    "Temporarily disable enforcement with the provided reason")
                onClicked: {
                    var reason = dialog.reasonText.trim()
                    dialog.close()
                    dialog.confirmed(reason)
                }
            }
        }
    }
}
