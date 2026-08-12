// Global "unsaved changes" guard.
//
// Mounted once on `ApplicationWindow`. Sections register dirty
// state through `root.setUnsavedChanges(sectionId, dirty)` (a
// helper Main.qml owns); intent-bearing call sites that would
// otherwise destroy that state (section navigation, window close,
// app quit) route through `guard.requestAction(...)` instead of
// performing the action directly. When the registry says
// nothing's dirty, `requestAction` invokes the intent
// synchronously — the dialog never opens. When there ARE dirty
// sections, the dialog opens with body text matched to the
// intent kind, and the user picks Discard or Cancel.
//
// "Save and continue" — wired as an OPT-IN per dirty section.
// Sections register an async save
// callback through `Main.qml::setSaveCallback(sectionId, fn)`;
// the guard fires it on click and resumes the pending intent
// when `onDone(true)` is called. Sections that don't register
// see only Cancel + Discard (the original B.4 surface). The
// Rules section's multi-step Save (Save → ReviewDiff →
// ConfirmActivate → MutationProgress) is intentionally NOT
// registered — wiring resume across a confirmation chain that
// the user can themselves abort is a separate design problem.
//
// API:
//   guard.requestAction(kind, intent, sectionLabel?)
//     kind         "section-nav" | "window-close" | "app-quit"
//                  | "generic"
//     intent       function() { ...do the destructive thing... }
//     sectionLabel optional human-readable section name for the
//                  "section-nav" body substitution
//
// Signals:
//   discarded(intent)  — emitted after the user confirms
//                        "Discard". Caller may either listen to
//                        the signal OR rely on the intent being
//                        invoked automatically (we do both — the
//                        intent fires; the signal is for
//                        telemetry/audit).
//   cancelled(intent)  — emitted on Cancel / close-without-decision.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: guard

    modal: true
    // The RU labels ("Сохранить и продолжить", "Сбросить изменения",
    // "Отмена") plus the body text wrap need ~580 px to lay out
    // cleanly without truncation or a wrapped button row. Anchor to
    // the centre of the parent window in case the parent is narrower
    // than `width`.
    width: Math.min(620, parent ? parent.width - 32 : 620)
    x: parent ? Math.round((parent.width - width) / 2) : 0
    y: parent ? Math.round((parent.height - height) / 2) : 0
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the registry. Required.
    property var ownerRoot: null

    /// Intent the user is trying to perform. Stored across the
    /// async user prompt; invoked on Discard.
    property var _pendingIntent: null
    property string _pendingKind: "generic"
    property string _pendingSectionLabel: ""
    /// True while a Save-and-continue callback is in flight (between
    /// click and onDone). Disables the button so impatient users do
    /// not stack RPC calls. Reset by both success and failure.
    property bool _saving: false
    /// One line naming exactly which state is unsaved, captured at open.
    property string _detailText: ""

    title: tr("unsaved-changes.title", "Unsaved changes")

    // Renamed `discarded` → `userDiscarded` to avoid colliding with
    // Dialog's built-in `discarded()` signal (Qt warning: "Duplicate
    // signal name: invalid override of property change signal or
    // superclass signal"). `cancelled` is safe — Dialog has `rejected`
    // but no `cancelled`.
    signal userDiscarded(var intent)
    signal cancelled(var intent)

    // ── Public entry point ─────────────────────────────────────────

    /// Consult the registry and either invoke `intent`
    /// synchronously (no dirty state) or open the prompt. Safe to
    /// call from action handlers, onClosing, shutdown polls, etc.
    function requestAction(kind, intent, sectionLabel) {
        if (typeof intent !== "function") {
            console.log("UnsavedChangesGuard: intent must be a function")
            return
        }
        var dirty = false
        if (ownerRoot && typeof ownerRoot.hasAnyUnsavedChanges === "function") {
            dirty = !!ownerRoot.hasAnyUnsavedChanges()
        }
        if (!dirty) {
            intent()
            return
        }
        _pendingIntent = intent
        _pendingKind = kind || "generic"
        _pendingSectionLabel = sectionLabel || ""
        // "Unsaved" is ambiguous for rules — not applied to the service and
        // not written to the file are different losses. Resolve which one is
        // at stake once, here, rather than binding it: the answer depends on
        // whether the service is reachable and must not change under the
        // user while the prompt is on screen.
        _detailText = (ownerRoot && typeof ownerRoot.rulesGuardDetail === "function")
            ? String(ownerRoot.rulesGuardDetail() || "") : ""
        open()
    }

    // ── Internals ──────────────────────────────────────────────────

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _bodyText() {
        var template
        switch (_pendingKind) {
            case "section-nav":
                template = tr(
                    "unsaved-changes.body.section-nav",
                    "You have unsaved changes in {section}. Switch sections anyway?")
                return template.replace("{section}", _pendingSectionLabel
                    || tr("unsaved-changes.body.generic-section", "this section"))
            case "window-close":
                return tr(
                    "unsaved-changes.body.window-close",
                    "You have unsaved changes. Close the window anyway?")
            case "app-quit":
                return tr(
                    "unsaved-changes.body.app-quit",
                    "You have unsaved changes. Quit NetRuleRouter anyway?")
            default:
                return tr(
                    "unsaved-changes.body.generic",
                    "You have unsaved changes. Continue anyway?")
        }
    }

    onRejected: {
        // Dialog closed without an explicit button (Esc, close
        // X). Treat as Cancel — DO NOT invoke the pending intent.
        var intent = _pendingIntent
        _pendingIntent = null
        guard.cancelled(intent)
    }

    // Focus the safer button (Cancel) on
    // open. Discard is destructive (drops unsaved edits); keyboard
    // accidental Enter shouldn't fire it.
    onOpened: { if (cancelButton) cancelButton.forceActiveFocus() }

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: guard._bodyText()
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: guard.ownerRoot ? guard.ownerRoot.textColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: guard._bodyText()
        }

        Label {
            Layout.fillWidth: true
            visible: guard._detailText !== ""
            text: guard._detailText
            wrapMode: Text.Wrap
            font.pixelSize: 12
            color: guard.ownerRoot ? guard.ownerRoot.mutedTextColor : palette.text
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        // Flow lays buttons left-to-right but wraps to a new line when
        // the dialog is narrower than the sum of button widths. Keeps
        // the long RU labels readable on small windows / DPI tweaks
        // instead of clipping the rightmost button.
        // Flow + RightToLeft so the FIRST declared button sits at the
        // right edge of the dialog (primary-action-right convention).
        // When the dialog is narrow enough that all three buttons do
        // not fit on one row, Flow wraps the leftmost buttons to a
        // second row instead of clipping.
        Flow {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            layoutDirection: Qt.RightToLeft
            ThemedButton {
                id: saveContinueButton
                theme: guard.ownerRoot ? guard.ownerRoot.uiTheme : null
                text: guard.tr("unsaved-changes.action.save-continue",
                    "Save and continue")
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: guard.tr(
                    "unsaved-changes.accessible.save-continue",
                    "Save unsaved changes and continue")
                visible: {
                    if (!guard.ownerRoot) return false
                    var rev = guard.ownerRoot.uiRevision
                    if (typeof guard.ownerRoot.firstDirtySectionId !== "function") return false
                    var sectionId = guard.ownerRoot.firstDirtySectionId()
                    if (!sectionId) return false
                    if (typeof guard.ownerRoot.saveCallbackForSection !== "function") return false
                    return guard.ownerRoot.saveCallbackForSection(sectionId) !== null
                }
                enabled: !guard._saving
                onClicked: {
                    if (!guard.ownerRoot
                            || typeof guard.ownerRoot.saveCallbackForSection !== "function") return
                    var sectionId = guard.ownerRoot.firstDirtySectionId()
                    var cb = guard.ownerRoot.saveCallbackForSection(sectionId)
                    if (cb === null) return
                    guard._saving = true
                    cb(function(ok) {
                        guard._saving = false
                        if (!ok) return
                        var intent = guard._pendingIntent
                        guard._pendingIntent = null
                        guard.close()
                        if (typeof intent === "function") intent()
                    })
                }
            }
            ThemedButton {
                theme: guard.ownerRoot ? guard.ownerRoot.uiTheme : null
                text: guard.tr("unsaved-changes.action.discard", "Discard changes")
                Accessible.role: Accessible.Button
                Accessible.name: guard.tr(
                    "unsaved-changes.accessible.discard",
                    "Discard unsaved changes and continue")
                onClicked: {
                    var intent = guard._pendingIntent
                    guard._pendingIntent = null
                    guard.close()
                    // Walk the dirty registry, fire each section's
                    // revert callback (if registered) so its QML
                    // draft state matches the persisted source again,
                    // THEN clear the registry so the next intent does
                    // not re-trigger the dialog. Without this clear,
                    // the dirty flag stays true and the guard re-opens
                    // on the very next navigation — observed bug.
                    if (guard.ownerRoot) {
                        var registry = guard.ownerRoot.unsavedChangesRegistry || {}
                        for (var sectionId in registry) {
                            if (!registry[sectionId]) continue
                            if (typeof guard.ownerRoot.revertCallbackForSection !== "function") continue
                            var revert = guard.ownerRoot.revertCallbackForSection(sectionId)
                            if (revert) revert()
                        }
                        if (typeof guard.ownerRoot.clearAllUnsavedChanges === "function") {
                            guard.ownerRoot.clearAllUnsavedChanges()
                        }
                    }
                    // Fire the user's intent AFTER reverting + clearing
                    // so the caller's state machine starts from a clean
                    // registry — section navigation, window close, etc.
                    if (typeof intent === "function") intent()
                    guard.userDiscarded(intent)
                }
            }
            ThemedButton {
                id: cancelButton
                theme: guard.ownerRoot ? guard.ownerRoot.uiTheme : null
                text: guard.tr("unsaved-changes.action.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: guard.tr(
                    "unsaved-changes.accessible.cancel",
                    "Cancel and stay on the current view")
                onClicked: {
                    var intent = guard._pendingIntent
                    guard._pendingIntent = null
                    guard.close()
                    guard.cancelled(intent)
                }
            }
        }
    }
}
