// Gate dialog opened by RulesSection._triggerReviewFlow
// when the user hits "Save and review" while the backend isn't
// connected. Lets the user pick one of three paths:
//
//   1. Start / Install Service — primary action; label depends on
//      `serviceStatusSlug`. Caller (Main.qml) wires
//      `nrrServiceController.startService()` /
//      `nrrServiceController.installService()` and a 10 s wait-for-
//      connect timer. Emits `startServiceRequested` /
//      `installServiceRequested`.
//   2. Work without service — caller writes the current rules-json
//      and summary into the sidecar `pending_apply` row (TTL 7 days)
//      so a future post-connect toast can pick them up. Emits
//      `workWithoutServiceRequested`.
//   3. Cancel — dismiss; no side effects. Emits `cancelled`.
//
// When the sidecar already holds a previous parked changeset whose
// content hash differs from the current rules, `stalePendingExists`
// switches on a warning row so the user knows that picking "Work
// without service" will overwrite the previous park.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog
    title: tr("dialog.service-not-running.title", "Service not running")

    modal: true
    // Render inside the main window overlay (themed), not a separate
    // top-level OS window — see ReviewDiffDialog for the rationale.
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: dialog
        theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
        titleText: dialog.title
    }
    // Grows with the footer: four localized button labels do not fit a fixed
    // width, and a clipped action reads as a missing one.
    width: Math.max(540, footerRow.implicitWidth + 2 * padding)
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the dialog (provides `tr`,
    /// `uiTheme`, `textColor`, `mutedTextColor`).
    property var ownerRoot: null

    /// One of: `"stopped"`, `"not-installed"`, `""` (unknown — falls
    /// back to "Start service" label, the controller will resolve the
    /// correct action). Anything other than `"not-installed"` shows
    /// the Start variant.
    property string serviceStatusSlug: ""

    /// `true` when the sidecar `pending_apply` row already holds a
    /// previous parked changeset whose content hash differs from the
    /// caller's. Caller resolves this BEFORE opening the dialog
    /// (single sidecar.pending-apply.read call) — keeps the dialog
    /// dumb and synchronous.
    property bool stalePendingExists: false

    /// Counts surfaced in the warning row. Caller fills these from
    /// `JSON.parse(entry["summary-json"])` array lengths. Zero values
    /// render as "—".
    property int stalePendingAdded: 0
    property int stalePendingRemoved: 0
    property int stalePendingModified: 0

    signal startServiceRequested()
    signal installServiceRequested()
    signal workWithoutServiceRequested()
    /// Write the rules to their files. Needs no service — the bytes come from
    /// the table in front of the user — so it is offered here as the way to
    /// keep the work when the service will not start.
    signal saveToFileRequested()
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _isNotInstalled() {
        return serviceStatusSlug === "not-installed"
    }

    function _primaryLabel() {
        return _isNotInstalled()
            ? tr("dialog.service-not-running.install-service",
                "Install service…")
            : tr("dialog.service-not-running.start-service",
                "Start service")
    }

    function _primaryDescription() {
        return _isNotInstalled()
            ? tr("dialog.service-not-running.install-service-description",
                "Install the Windows service (requires administrator privileges) and start it.")
            : tr("dialog.service-not-running.start-service-description",
                "Start the Windows service (requires administrator privileges).")
    }

    onRejected: cancelled()

    onOpened: {
        if (cancelButton) cancelButton.forceActiveFocus()
    }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: dialog.tr(
                "dialog.service-not-running.body",
                "The NetRuleRouter service is not running. Rule changes cannot be applied to the network until it is. You can start the service now, save your rules to a file, park the changes for later, or cancel."
            )
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        // ── Stale-pending warning row ────────────────────────────
        Rectangle {
            Layout.fillWidth: true
            visible: dialog.stalePendingExists
            radius: 6
            color: "#fff3cd"
            border.width: 1
            border.color: "#d4a017"
            implicitHeight: stalePendingLabel.implicitHeight + 16
            Label {
                id: stalePendingLabel
                anchors.fill: parent
                anchors.margins: 8
                text: dialog.tr(
                    "dialog.service-not-running.stale-pending-warning",
                    "There is already a parked changeset (+{added} / -{removed} / ~{modified}). Choosing \"Work without service\" will replace it.")
                    .replace("{added}", String(dialog.stalePendingAdded))
                    .replace("{removed}", String(dialog.stalePendingRemoved))
                    .replace("{modified}", String(dialog.stalePendingModified))
                wrapMode: Text.Wrap
                color: "#664d03"
                font.pixelSize: 12
                verticalAlignment: Text.AlignVCenter
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
        }

        RowLayout {
            id: footerRow
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                id: cancelButton
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr(
                    "dialog.service-not-running.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.service-not-running.cancel-description",
                    "Dismiss the dialog without applying or parking the changes.")
                onClicked: { dialog.cancelled(); dialog.close() }
            }
            ThemedButton {
                id: saveToFileButton
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("status.bound-file-save", "Save to file")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.service-not-running.save-to-file-description",
                    "Write the current rules to your rules files. This works with the service stopped.")
                onClicked: { dialog.saveToFileRequested(); dialog.close() }
            }
            ThemedButton {
                id: workWithoutButton
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr(
                    "dialog.service-not-running.work-without",
                    "Work without service")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.service-not-running.work-without-description",
                    "Park the changes locally; they will not be applied to the network until the service is running.")
                onClicked: { dialog.workWithoutServiceRequested(); dialog.close() }
            }
            ThemedButton {
                id: primaryButton
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog._primaryLabel()
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog._primaryDescription()
                onClicked: {
                    if (dialog._isNotInstalled()) {
                        dialog.installServiceRequested()
                    } else {
                        dialog.startServiceRequested()
                    }
                    dialog.close()
                }
            }
        }
    }
}
