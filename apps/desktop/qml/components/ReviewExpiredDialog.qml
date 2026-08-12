// Shown when the service returns
// `IpcErrorCode::ConfirmationExpired` during the confirm-execute
// pass.
//
// Per design memory: no countdown timer. The dialog states the
// fact ("your token expired") and offers a manual "Compare again"
// retry that triggers a fresh dry-run, after which the GUI flow
// re-opens ReviewDiffDialog with the refreshed summary.
//
// Contract:
// - `signal retry()` — emitted when user clicks "Compare again".
//   Caller re-runs `rpcMutationSubmit` with `dryRun=true`.
// - `signal cancelled()` — emitted on Cancel / close.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root
    title: typeof root.tr === "function"
        ? root.tr("dialog.review-expired.title", "Review session expired")
        : "Review session expired"

    modal: true
    width: 460
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    property var ownerRoot: null

    signal retry()
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    onRejected: cancelled()

    // Focus the safer button (Cancel). The
    // retry path is destructive (re-runs the full dry-run round-
    // trip), so accidental Enter shouldn't fire it.
    onOpened: { if (cancelButton) cancelButton.forceActiveFocus() }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: root.tr(
                "dialog.review-expired.body",
                "Your confirmation token expired before the change was applied. Compare the changes again to refresh the review."
            )
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                id: cancelButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.review-expired.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.review-expired.cancel-description",
                    "Dismiss the dialog without retrying the review")
                onClicked: { root.cancelled(); root.close() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.review-expired.compare-again", "Compare again")
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.review-expired.compare-again-description",
                    "Re-run the review against the current rule set")
                onClicked: { root.retry(); root.close() }
            }
        }
    }
}
