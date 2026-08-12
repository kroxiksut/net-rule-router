// Generic in-flight mutation tracker.
//
// Drives `hasInFlight` so every submit-button in the GUI (Save in
// rules editor, Apply for route policy, Rollback, SafeDisable, …)
// can bind `enabled: !root.mutationsModel.hasInFlight`. The model
// listens for `MutationProgress` push events the service emits via
// `ProductionMutationExecutor::emit_progress`
// (service-side) — the wire `phase` values are `"started"` (entry),
// `"completed"` (terminal success), `"failed"` (terminal error).
//
// Correlation contract: the GUI's `rpcMutationSubmit` carries a
// `correlation-id` field inside the payload; the service round-trips
// the same id back in the push event. The model keys all state on
// that id so multiple concurrent mutations (rare in Free tier — see
// `single-config` model — but supported for safety) don't collide.
//
// Not a `ListModel`: this is internal QML state, not a view-bound
// model. Callers read `hasInFlight` / `count` / `kindInFlight(kind)`
// and bind property values reactively. Tray.qml uses an independent
// copy because it lives in a separate process.

import QtQuick 2.15

QtObject {
    id: root

    // ── Public, reactive read surface ─────────────────────────────

    /// `true` while at least one mutation is between `started` and a
    /// terminal phase. Bound to submit-button `enabled` flags
    /// throughout the GUI.
    readonly property bool hasInFlight: count > 0
    /// Number of in-flight mutations. Reactive — derived from
    /// `_entries` length.
    readonly property int count: _entries.length
    /// Last terminal phase observed, for transient toasts. Cleared
    /// when a new `started` arrives.
    property string lastTerminalPhase: ""
    property string lastTerminalCorrelationId: ""
    property string lastTerminalKind: ""
    property string lastTerminalErrorCode: ""

    // ── Internal state ────────────────────────────────────────────

    // Array of `{ correlationId, kind, startedAtMs }`. Mutated
    // through `_setEntries` so the `hasInFlight` / `count`
    // property bindings re-evaluate.
    property var _entries: []

    // ── Public mutators (called by Main.qml on push events) ──────

    /// `phase` is one of "started" / "completed" / "failed".
    /// `errorCode` is the wire IpcErrorCode slug when phase ==
    /// "failed"; ignored otherwise.
    function applyProgress(correlationId, kind, phase, errorCode) {
        if (!correlationId) return
        var k = kind || ""
        var ph = phase || ""
        if (ph === "started") {
            _track(correlationId, k)
        } else if (ph === "completed") {
            _settle(correlationId, k, "completed", "")
        } else if (ph === "failed") {
            _settle(correlationId, k, "failed", errorCode || "")
        } else {
            console.log("MutationsModel: unknown phase", ph,
                        "for correlation", correlationId)
        }
    }

    /// Returns `true` when a mutation of the given kind is in
    /// flight. Convenience for kind-specific buttons.
    function kindInFlight(kind) {
        if (!kind) return false
        for (var i = 0; i < _entries.length; i++) {
            if (_entries[i].kind === kind) return true
        }
        return false
    }

    /// Force-clear the model. Used on bridge reconnect — stale
    /// in-flight entries from before reconnect cannot resolve via
    /// push events because the service may have restarted.
    function clearAll() {
        _setEntries([])
        lastTerminalPhase = ""
        lastTerminalCorrelationId = ""
        lastTerminalKind = ""
        lastTerminalErrorCode = ""
    }

    // ── Internals ────────────────────────────────────────────────

    function _track(correlationId, kind) {
        // Idempotent: re-`started` (e.g. service replayed the event
        // after a transient reader loop hiccup) does NOT duplicate.
        for (var i = 0; i < _entries.length; i++) {
            if (_entries[i].correlationId === correlationId) {
                return
            }
        }
        var next = _entries.slice()
        next.push({
            correlationId: correlationId,
            kind: kind,
            startedAtMs: Date.now()
        })
        _setEntries(next)
        lastTerminalPhase = ""
    }

    function _settle(correlationId, kind, terminalPhase, errorCode) {
        var next = []
        for (var i = 0; i < _entries.length; i++) {
            if (_entries[i].correlationId !== correlationId) {
                next.push(_entries[i])
            }
        }
        _setEntries(next)
        lastTerminalPhase = terminalPhase
        lastTerminalCorrelationId = correlationId
        lastTerminalKind = kind
        lastTerminalErrorCode = errorCode
    }

    function _setEntries(next) {
        _entries = next
    }
}
