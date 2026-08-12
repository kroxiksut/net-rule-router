// Drift detection dialog opened from the banner
// Main.qml renders when `_driftDetected === true`.
//
// Shows the three hashes per route (file / GUI / service) and four
// outcomes:
//
//   1. **Load from file** — re-import the user's saved files into
//      rulesModel via the standard preset-import review flow. After
//      a successful activation, file/gui/service all converge.
//   2. **Apply GUI state** — open the standard "Save & review" flow
//      with the current rulesModel. After confirm, service catches
//      up to GUI; the next 30 s poll picks up the new baseline.
//   3. **Accept service state** — rollback the local rulesModel to
//      the cold-start snapshot rows (the service-baseline view).
//      GUI edits are discarded.
//   4. **Not now** — close. Banner stays visible until the next
//      action resolves the drift.
//
// The dialog is read-mostly: it surfaces the diagnostic and lets the
// user pick one of the resolution paths. The actual work happens on
// the caller side via signal handlers, so this file stays pure
// presentation.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog
    title: tr("dialog.drift.title", "Rules drift detected")

    modal: true
    // Render inside the main window overlay (themed), not a separate
    // top-level OS window — see ReviewDiffDialog for the rationale.
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: dialog
        theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
        titleText: dialog.title
    }
    width: 640
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the dialog (provides `tr`,
    /// `uiTheme`, `textColor`, `mutedTextColor`).
    property var ownerRoot: null

    /// Per-route detail objects. Each has
    /// `{file, gui, service, mismatch}` filled by Main.qml's
    /// `_driftCompare`. `mismatch` is a kebab slug — `none` or one
    /// of `all-three-differ` / `file-vs-gui` / `gui-vs-service` /
    /// `file-vs-service`.
    property var primaryDetails:   ({ file: "", gui: "", service: "", mismatch: "none" })
    property var secondaryDetails: ({ file: "", gui: "", service: "", mismatch: "none" })

    /// `true` when a saved file path is configured for the matching
    /// route. Drives the visibility of the file column and the "Load
    /// from file" button (it can't load when no file exists).
    property bool fileExistsPrimary:   false
    property bool fileExistsSecondary: false

    signal loadFromFileRequested()
    signal applyGuiStateRequested()
    signal acceptServiceStateRequested()
    /// Open a read-only diff of the current app rules
    /// against the service's active revision (added/removed/changed).
    signal showDiffRequested()
    /// Clear all rules in the app AND push an empty
    /// revision to the service. Destructive; the caller gates it on a
    /// confirmation dialog.
    signal clearAllRequested()
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _shortHash(h) {
        var s = String(h || "")
        if (s === "") return "—"
        // Show the first 8 hex chars + last 4 — 32 bits of entropy is
        // plenty for human cross-checking, full hash would just be
        // visual noise.
        if (s.length <= 12) return s
        return s.substring(0, 8) + "…" + s.substring(s.length - 4)
    }

    function _mismatchLabel(slug) {
        return tr("dialog.drift.mismatch-" + slug, slug)
    }

    function _anyFileExists() {
        return fileExistsPrimary || fileExistsSecondary
    }

    onRejected: cancelled()

    onOpened: {
        if (notNowButton) notNowButton.forceActiveFocus()
    }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: dialog.tr(
                "dialog.drift.body",
                "The rules stored in your file, shown in the app, and applied by the service no longer agree. Pick how to resolve.")
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        // ── Per-route detail grid ────────────────────────────────
        GridLayout {
            Layout.fillWidth: true
            columns: 4
            columnSpacing: 12
            rowSpacing: 6

            // Header row
            Label {
                text: dialog.tr("dialog.drift.col-route", "Route")
                font.bold: true
                color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            }
            Label {
                text: dialog.tr("dialog.drift.col-file", "File")
                font.bold: true
                color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            }
            Label {
                text: dialog.tr("dialog.drift.col-gui", "App")
                font.bold: true
                color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            }
            Label {
                text: dialog.tr("dialog.drift.col-service", "Service")
                font.bold: true
                color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            }

            // Primary row
            Label {
                text: dialog.tr("dialog.drift.row-primary", "Primary")
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            }
            Label {
                text: dialog.fileExistsPrimary
                    ? dialog._shortHash(dialog.primaryDetails.file)
                    : dialog.tr("dialog.drift.no-file", "(no file)")
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                font.family: "Consolas, Courier New, monospace"
                font.pixelSize: 12
            }
            Label {
                text: dialog._shortHash(dialog.primaryDetails.gui)
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                font.family: "Consolas, Courier New, monospace"
                font.pixelSize: 12
            }
            Label {
                text: dialog._shortHash(dialog.primaryDetails.service)
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                font.family: "Consolas, Courier New, monospace"
                font.pixelSize: 12
            }

            // Secondary row
            Label {
                text: dialog.tr("dialog.drift.row-secondary", "Secondary")
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            }
            Label {
                text: dialog.fileExistsSecondary
                    ? dialog._shortHash(dialog.secondaryDetails.file)
                    : dialog.tr("dialog.drift.no-file", "(no file)")
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                font.family: "Consolas, Courier New, monospace"
                font.pixelSize: 12
            }
            Label {
                text: dialog._shortHash(dialog.secondaryDetails.gui)
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                font.family: "Consolas, Courier New, monospace"
                font.pixelSize: 12
            }
            Label {
                text: dialog._shortHash(dialog.secondaryDetails.service)
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                font.family: "Consolas, Courier New, monospace"
                font.pixelSize: 12
            }
        }

        // ── Mismatch summary lines ───────────────────────────────
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

            Label {
                Layout.fillWidth: true
                visible: dialog.primaryDetails.mismatch !== "none"
                text: dialog.tr("dialog.drift.summary-primary",
                    "Primary route: {kind}")
                    .replace("{kind}",
                        dialog._mismatchLabel(dialog.primaryDetails.mismatch))
                wrapMode: Text.Wrap
                font.pixelSize: 12
                color: "#a04400"
            }
            Label {
                Layout.fillWidth: true
                visible: dialog.secondaryDetails.mismatch !== "none"
                text: dialog.tr("dialog.drift.summary-secondary",
                    "Secondary route: {kind}")
                    .replace("{kind}",
                        dialog._mismatchLabel(dialog.secondaryDetails.mismatch))
                wrapMode: Text.Wrap
                font.pixelSize: 12
                color: "#a04400"
            }
        }

        // ── Buttons ──────────────────────────────────────────────
        Flow {
            Layout.fillWidth: true
            Layout.topMargin: 8
            spacing: 8
            ThemedButton {
                id: notNowButton
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.drift.not-now", "Not now")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.drift.not-now-description",
                    "Dismiss the dialog. The banner stays until the drift is resolved.")
                onClicked: { dialog.cancelled(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.drift.show-diff", "Show differences")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.drift.show-diff-description",
                    "Open a read-only diff of the current app rules against the service.")
                onClicked: { dialog.showDiffRequested(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.drift.load-from-file", "Load from file")
                enabled: dialog._anyFileExists()
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.drift.load-from-file-description",
                    "Re-import the saved file(s). Local edits are replaced.")
                onClicked: { dialog.loadFromFileRequested(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.drift.accept-service",
                    "Accept service state")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.drift.accept-service-description",
                    "Discard local edits and roll back the app to what the service holds.")
                onClicked: { dialog.acceptServiceStateRequested(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.drift.apply-gui", "Apply app state")
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.drift.apply-gui-description",
                    "Open the review flow and push the current app state to the service.")
                onClicked: { dialog.applyGuiStateRequested(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.drift.clear-all", "Clear everything")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.drift.clear-all-description",
                    "Remove all rules from the app and the service. This cannot be undone.")
                onClicked: { dialog.clearAllRequested(); dialog.close() }
            }
        }
    }
}
