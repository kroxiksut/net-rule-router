// Toast stack model for transient operation feedback.
//
// Holds up to `capacity` entries (default 5). Each entry tracks one
// mutation submitted by the GUI, keyed by `correlationId` so a later
// `settle()` can flip a running toast to a terminal phase without
// duplicating the row. Entries land in three phases:
//
//   running   ← push()             (created when MutationProgress
//                                    "started" arrives)
//   completed ← settle("completed")  (auto-dismissed by OperationToast
//                                    after a few seconds)
//   failed    ← settle("failed")     (NOT auto-dismissed; user must
//                                    click ✕ — per design memory
//                                    `project_block16_12_design.md`
//                                    decision #8)
//
// Eviction policy when the stack would exceed `capacity`:
//   * Prefer to drop the oldest non-failed entry (completed first,
//     then running). Failed entries persist until manually dismissed.
//   * If every entry in the stack is `failed`, drop the oldest one
//     anyway so the new toast still appears — the cap is a hard
//     ceiling, not a soft hint.
//
// The model is a plain `ListModel`. `Repeater { model: toastStack }`
// in OperationToastStack.qml binds directly to it. Each row exposes
// the same set of keys regardless of phase so the delegate can stay
// uniform.
//
// Each Main.qml-side window (main GUI vs Tray) owns its own model
// instance — they live in separate QML engines and a tray rarely
// emits its own mutations today.

import QtQuick 2.15

ListModel {
    id: model

    // ── Configuration ──────────────────────────────────────────────

    /// Hard cap on stack size; matches design decision #8.
    property int capacity: 5

    // ── Public API ─────────────────────────────────────────────────

    /// Returns the row index of the matching `correlationId` or -1.
    function indexOf(correlationId) {
        if (!correlationId) return -1
        for (var i = 0; i < model.count; i++) {
            if (model.get(i).correlationId === correlationId) return i
        }
        return -1
    }

    /// Insert a new running toast. Idempotent: a second push for the
    /// same correlationId is a no-op (matches the "service replays
    /// `started` after a reader-loop hiccup" tolerance in
    /// MutationsModel._track).
    function push(correlationId, kind) {
        if (!correlationId) return
        if (indexOf(correlationId) >= 0) return
        _evictIfNeeded()
        model.append({
            id: _nextId(),
            correlationId: String(correlationId),
            kind: String(kind || ""),
            phase: "running",
            errorCode: "",
            startedAtMs: Date.now(),
            settledAtMs: 0
        })
    }

    /// Flip a running toast to a terminal phase. If the
    /// correlationId is unknown (e.g. service emits `completed`
    /// without our seeing `started` — possible on bridge reconnect)
    /// we still insert a fresh row so the user sees feedback.
    function settle(correlationId, phase, errorCode) {
        if (!correlationId) return
        var idx = indexOf(correlationId)
        var ph = (phase === "completed" || phase === "failed")
            ? phase : "completed"
        var ec = String(errorCode || "")
        if (idx < 0) {
            _evictIfNeeded()
            model.append({
                id: _nextId(),
                correlationId: String(correlationId),
                kind: "",
                phase: ph,
                errorCode: ec,
                startedAtMs: Date.now(),
                settledAtMs: Date.now()
            })
            return
        }
        model.setProperty(idx, "phase", ph)
        model.setProperty(idx, "errorCode", ec)
        model.setProperty(idx, "settledAtMs", Date.now())
    }

    /// Remove a row by its synthetic `id` (NOT correlationId — the
    /// delegate stores `id` so dismissing the wrong row is
    /// impossible even after rapid churn).
    function dismissById(id) {
        for (var i = 0; i < model.count; i++) {
            if (model.get(i).id === id) {
                model.remove(i)
                return
            }
        }
    }

    /// Drop everything. Called on backend reconnect.
    function clearAll() {
        model.clear()
    }

    // ── Internals ──────────────────────────────────────────────────

    property int _nextIdSeq: 1
    function _nextId() {
        var next = _nextIdSeq
        _nextIdSeq = _nextIdSeq + 1
        return next
    }

    function _evictIfNeeded() {
        if (model.count < capacity) return
        // First pass: drop the oldest non-failed entry.
        for (var i = 0; i < model.count; i++) {
            if (model.get(i).phase !== "failed") {
                model.remove(i)
                return
            }
        }
        // Fallback: every entry is failed — drop the oldest so the
        // cap holds.
        if (model.count > 0) model.remove(0)
    }
}
