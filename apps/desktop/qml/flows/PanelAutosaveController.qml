import QtQuick 2.15

// Non-visual autosave driver for a settings panel that owns draft state.
//
// The panel commits through three paths — the global footer Apply, the
// navigation guard when leaving the section, and this controller, which fires
// the same save function once the user has stopped editing for `intervalSecs`.
// Without it, an edit made and forgotten (or a stale draft carried into the
// next manual Save) is silently lost.
//
// Usage: instantiate inside the panel, feed it the panel's live dirty flag and
// handle `due()` by calling the panel's own save function. The timer is a
// debounce, not a period: every change to `dirty` (i.e. every edit that marks
// the panel dirty again) restarts the countdown, so a user typing through a
// group of fields is not interrupted mid-edit.
QtObject {
    id: controller

    /// The ApplicationWindow (for `prefs` / status reporting by the owner).
    property var root
    /// Live "the panel has unsaved draft state and could be saved right now".
    /// Feed the panel's own validity/loading guards into this, not just the
    /// dirty bit — an invalid draft must never be autosaved.
    property bool dirty: false
    /// Seconds of inactivity before the draft is committed.
    property int intervalSecs: 60
    /// Master switch, so a panel can suspend autosave (e.g. while a modal of
    /// its own is open) without tearing the controller down.
    property bool enabled: true

    /// Emitted when the debounce elapses and the panel should save.
    signal due()

    /// Restart the countdown without changing `dirty` — for panels that keep
    /// editing the same field (a spin box held down) and want the idle window
    /// measured from the last keystroke.
    function poke() {
        if (!enabled || !dirty) return
        _timer.restart()
    }

    onDirtyChanged: {
        if (dirty && enabled) _timer.restart()
        else _timer.stop()
    }
    onEnabledChanged: {
        if (enabled && dirty) _timer.restart()
        else _timer.stop()
    }
    onIntervalSecsChanged: {
        if (_timer.running) _timer.restart()
    }

    property Timer _timer: Timer {
        interval: Math.max(5, controller.intervalSecs | 0) * 1000
        repeat: false
        onTriggered: {
            if (controller.enabled && controller.dirty) controller.due()
        }
    }
}
