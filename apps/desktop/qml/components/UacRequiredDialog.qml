import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../theme"

// UAC pre-prompt advisory.
//
// Some service operations require Administrator approval. We show
// this lightweight modal BEFORE invoking `ShellExecuteExW` with the
// `runas` verb so the user understands the upcoming Windows UAC
// prompt is initiated by NetRuleRouter, not a system pop-up out of
// nowhere.
//
// The same Dialog instance is reused for the UAC-declined branch
// (different title/body keys via `mode` property): "Action cancelled
// — you can retry from Settings".
Dialog {
    id: root

    property var ownerRoot
    /// `"prompt"` (default) → pre-UAC advisory with Continue/Cancel.
    /// `"declined"` → post-UAC-decline notice with single OK button.
    property string mode: "prompt"

    signal continueRequested()
    signal cancelled()

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    title: root.mode === "declined"
        ? tr("dialog.uac-required.declined-title", "Action cancelled")
        : tr("dialog.uac-required.title", "Administrator approval required")

    standardButtons: Dialog.NoButton
    modal: true
    closePolicy: Popup.CloseOnEscape
    width: 480

    onRejected: { cancelled(); root.close() }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            text: root.mode === "declined"
                ? root.tr("dialog.uac-required.declined-body",
                    "The Administrator prompt was declined. You can retry from Settings → Service management.")
                : root.tr("dialog.uac-required.body",
                    "This action requires Administrator privileges. Click Continue to approve the UAC prompt that follows.")
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.mode === "declined"
                    ? root.tr("dialog.review-diff.cancel", "Cancel")
                    : root.tr("dialog.uac-required.cancel", "Cancel")
                visible: root.mode !== "declined"
                onClicked: { root.cancelled(); root.close() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.mode === "declined"
                    ? "OK"
                    : root.tr("dialog.uac-required.continue", "Continue")
                highlighted: true
                onClicked: {
                    if (root.mode === "declined") {
                        root.cancelled()
                    } else {
                        root.continueRequested()
                    }
                    root.close()
                }
            }
        }
    }
}
