// Single toast card rendered by OperationToastStack.
//
// Visual: themed Rectangle with a color-coded 4 px left accent
// stripe — blue (accent) while running, green (success) on
// completed, red (danger) on failed. Title is the localised mutation
// kind (`toast.operation.title.<slug>`). Body shows the phase label
// while running/completed, or the wire error code when failed.
//
// Auto-dismiss:
//   * Running entries never auto-dismiss (the service controls when
//     the row transitions; no timer here).
//   * Completed entries auto-dismiss after `autoDismissCompletedMs`
//     (default 4 s). The timer pauses while the user hovers — so a
//     toast they're reading doesn't vanish under their pointer.
//   * Failed entries never auto-dismiss. The X button is always
//     visible on failed. On running/completed it appears only on
//     hover so the badge stays uncluttered.
//
// Signals:
//   - `dismissRequested(id)` — bubbles up to the stack container
//     which calls `model.dismissById(id)`.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: root

    // ── Public properties ──────────────────────────────────────────

    /// Theme tokens (ThemeTokens instance). Required.
    required property QtObject theme
    /// Owner root window (ApplicationWindow). Provides `tr(...)`.
    required property var ownerRoot

    /// Synthetic stack-model id used for dismissal addressing.
    property int rowId: 0
    /// Mutation kind slug — `rules-update`, etc.
    property string kind: ""
    /// Phase — `running`, `completed`, `failed`.
    property string phase: "running"
    /// Wire IpcErrorCode slug when `phase === "failed"`; else "".
    property string errorCode: ""

    /// Auto-dismiss timeout (ms) for completed entries. Hover pauses.
    property int autoDismissCompletedMs: 4000

    signal dismissRequested(int id)

    // ── Layout ─────────────────────────────────────────────────────

    width: 380
    height: contentColumn.implicitHeight + 2 * theme.spacingMd
    radius: theme.radiusMd
    color: theme.colorPanel
    border.width: theme.borderWidth
    border.color: theme.stateDefaultBorder

    // Expose the raw wire error code via tooltip
    // so an operator/QA can still inspect the underlying slug while
    // the body shows the localised label.
    ToolTip.visible: root.phase === "failed"
        && root.errorCode !== ""
        && hoverArea.containsMouse
    ToolTip.text: root.errorCode
    ToolTip.delay: 600

    // Accent stripe at the left edge — phase-coloured.
    Rectangle {
        id: accentStripe
        width: 4
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        radius: theme.radiusMd
        color: root._phaseColor()
    }

    RowLayout {
        id: contentColumn
        anchors.fill: parent
        anchors.leftMargin: theme.spacingMd + 4
        anchors.rightMargin: theme.spacingSm
        anchors.topMargin: theme.spacingMd
        anchors.bottomMargin: theme.spacingMd
        spacing: theme.spacingSm

        BusyIndicator {
            visible: root.phase === "running"
            running: visible
            implicitWidth: 18
            implicitHeight: 18
            Layout.alignment: Qt.AlignVCenter
        }

        Label {
            visible: root.phase !== "running"
            text: root.phase === "completed" ? "✓" : "!"
            color: root._phaseColor()
            font.bold: true
            font.pixelSize: 16
            Layout.alignment: Qt.AlignVCenter
            Accessible.role: Accessible.StaticText
            Accessible.name: root.phase === "completed"
                ? root._tr("toast.operation.accessible.completed", "Operation completed")
                : root._tr("toast.operation.accessible.failed", "Operation failed")
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

            Label {
                Layout.fillWidth: true
                text: root._titleText()
                color: theme.colorText
                font.bold: true
                font.pixelSize: 13
                elide: Text.ElideRight
            }
            Label {
                Layout.fillWidth: true
                text: root._bodyText()
                color: theme.colorTextMuted
                font.pixelSize: 12
                wrapMode: Text.Wrap
                maximumLineCount: 3
                elide: Text.ElideRight
            }
        }

        ToolButton {
            id: dismissButton
            // Failed → always visible (user must dismiss). Otherwise
            // show only on hover so the row stays uncluttered.
            visible: root.phase === "failed" || hoverArea.containsMouse
            text: "✕"
            implicitWidth: 24
            implicitHeight: 24
            font.pixelSize: 14
            Layout.alignment: Qt.AlignTop
            Accessible.role: Accessible.Button
            Accessible.name: root._tr(
                "toast.operation.accessible.dismiss",
                "Dismiss notification")
            onClicked: root.dismissRequested(root.rowId)
            background: Rectangle {
                color: dismissButton.hovered ? theme.stateHoverFill : "transparent"
                radius: theme.radiusSm
            }
            contentItem: Label {
                text: dismissButton.text
                color: theme.colorTextMuted
                font: dismissButton.font
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
            }
        }
    }

    // Hover detection drives X-button visibility AND auto-dismiss
    // pause. `MouseArea { hoverEnabled }` propagates clicks to the
    // ToolButton above (acceptedButtons: Qt.NoButton).
    MouseArea {
        id: hoverArea
        anchors.fill: parent
        hoverEnabled: true
        acceptedButtons: Qt.NoButton
        propagateComposedEvents: true
    }

    // Auto-dismiss only fires for `completed` phase. Failed entries
    // require explicit user action; running entries wait for the
    // service to settle them.
    Timer {
        id: autoDismissTimer
        interval: root.autoDismissCompletedMs
        repeat: false
        running: root.phase === "completed" && !hoverArea.containsMouse
        onTriggered: root.dismissRequested(root.rowId)
    }

    // ── Helpers ────────────────────────────────────────────────────

    function _tr(key, fallback) {
        if (root.ownerRoot && typeof root.ownerRoot.tr === "function") {
            return root.ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _phaseColor() {
        switch (root.phase) {
            case "completed": return theme.colorSuccess
            case "failed":    return theme.colorDanger
            default:          return theme.colorAccent
        }
    }

    function _titleText() {
        var slug = root.kind || "unknown"
        return _tr("toast.operation.title." + slug,
                   _tr("toast.operation.title.unknown", "Operation"))
    }

    function _bodyText() {
        if (root.phase === "running") {
            return _tr("toast.operation.phase.running", "Running…")
        }
        if (root.phase === "completed") {
            return _tr("toast.operation.phase.completed", "Completed")
        }
        // failed — resolve the wire code to a
        // localised `errors.<code>` label instead of dumping raw
        // kebab into the body. The raw code stays available via
        // ToolTip for diagnostics.
        if (root.errorCode && root.ownerRoot
                && typeof root.ownerRoot.ipcErrorLabel === "function") {
            return root.ownerRoot.ipcErrorLabel(root.errorCode)
        }
        if (root.errorCode) {
            // Bridge not yet wired (e.g. running in Tray context) —
            // keep the historical "(code)" form so we don't
            // regress before the helper is available.
            var template = _tr(
                "toast.operation.error.with-code",
                "Operation failed ({code})")
            return template.replace("{code}", root.errorCode)
        }
        return _tr("toast.operation.error.generic", "Operation failed")
    }
}
