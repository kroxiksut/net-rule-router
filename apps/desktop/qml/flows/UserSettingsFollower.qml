import QtQuick 2.15

// Follows the user's settings file, which the terminal client and the other
// surface also write. The launcher answers from the file's stamp and reads it
// only after a rewrite, so the poll costs one stat. The window takes what
// changed (`adopt`); the tray only reads the bound files.
QtObject {
    id: follower

    /// RpcTransport instance (callback table).
    property var rpc: null
    /// The window takes the answer into its preferences; the tray does not.
    property bool adopt: false
    property int intervalMs: 3000

    /// An answer that carried the file: the changed preferences (window
    /// names) and the bound files as the file holds them (null: no file).
    signal followed(var preferences, var rulesFiles)
    /// Every answer, read or not: the window tells a damaged file from it.
    signal answered(var payload)

    property string _stamp: ""
    property bool _inFlight: false
    /// Asked while a request was out: that answer may predate the change.
    property bool _again: false
    property var _next: []

    readonly property bool available: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcUserSettingsFollow === "function"

    /// Ask now. `onDone()` runs once the answer is in, or at once from a host
    /// that cannot ask, so a write that depends on the bound files waits for
    /// it and is never held up for good.
    function follow(onDone) {
        if (typeof onDone === "function") _next.push(onDone)
        if (_inFlight) { _again = true; return }
        _send()
    }

    function _send() {
        var waiting = _next
        _next = []
        _again = false
        if (!available || !rpc) { _run(waiting); return }
        var corr = nrrNativeBridge.rpcUserSettingsFollow({ "since": _stamp, "adopt": adopt })
        if (!corr || String(corr) === "") { _run(waiting); return }
        _inFlight = true
        rpc.registerRpcCallback(corr, function(ok, payload) {
            follower._inFlight = false
            if (ok && payload) {
                follower._stamp = String(payload.stamp || "")
                if (payload.changed === true) {
                    follower.followed(payload.preferences || ({}), payload["rules-files"] || null)
                }
                follower.answered(payload)
            }
            follower._run(waiting)
            if (follower._again) follower._send()
        })
    }

    function _run(waiting) {
        for (var i = 0; i < waiting.length; i += 1) {
            try { waiting[i]() } catch (e) { console.log("user settings follow:", e) }
        }
    }

    property Timer _timer: Timer {
        interval: follower.intervalMs
        running: follower.available
        repeat: true
        onTriggered: follower.follow()
    }
}
