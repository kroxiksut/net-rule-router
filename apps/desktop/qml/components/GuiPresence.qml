import QtQuick 2.15
import "../lib/pure.js" as Pure

// "Is the main window there, and is the user looking at it?" — plus the rules
// files that window is working with.
//
// The tray is a separate process. It has no way to ask the window whether it is
// on the foreground, and no `prefs` object of its own to resolve which files
// back the user's rules. Both answers are cheap for the window and expensive
// (or impossible) for the tray, so the window publishes them into a small JSON
// file and the tray reads it. One file, one format, one component instantiated
// on both sides.
//
// Liveness comes from the `at` timestamp inside the payload, not from the file
// existing: a window that was killed cannot clean up after itself, and a stale
// timestamp is exactly the signal "no window is running". The file is
// deliberately NOT removed on exit (it is marked `gone` instead) — the paths in it stay valid and let the
// tray keep working after the window is closed, which is the whole point.
//
// The rules paths are the window's own answer, not a second resolution of the
// preferences: the window is the surface that owns that decision, and the tray
// must not be able to disagree with it. An empty path means "nothing here is
// worth comparing" and the reader must treat it as such rather than guessing.
QtObject {
    id: presence

    /// File name under the per-user app-local data directory.
    property string fileName: "gui-presence.json"

    /// Heartbeat cadence. Only proves the window is alive — a change of state
    /// (focus gained/lost, a different rules file) is published immediately, so
    /// this can be slow.
    property int heartbeatMs: 10000

    /// How long a published snapshot is trusted as "a window is running". Three
    /// missed heartbeats: long enough to ride out a busy machine, short enough
    /// that the tray takes over promptly after the window is gone.
    property int freshnessMs: 30000

    /// Set by the window. The tray leaves it false and only reads.
    property bool publishing: false

    /// `function() -> { active, visible, rulesPathPrimary, rulesPathSecondary,
    /// rulesFolder, includeComments, notices }`, supplied by the window. Called
    /// on every publish. `notices`: the notification settings the tray honours.
    property var snapshotProvider: null

    property string _path: ""

    readonly property bool _bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.defaultLocalAppDataPath === "function"

    function _resolvePath() {
        if (_path !== "") return _path
        if (!_bridgeReady) return ""
        _path = String(nrrNativeBridge.defaultLocalAppDataPath(fileName) || "")
        return _path
    }

    /// Write the current snapshot. Call directly whenever the published state
    /// changes rather than waiting for the heartbeat.
    function publish() {
        if (!publishing) return
        if (typeof snapshotProvider !== "function") return
        var path = _resolvePath()
        if (path === "" || typeof nrrNativeBridge.writeTextFile !== "function") return
        var snap = snapshotProvider() || {}
        var payload = {
            "at": Date.now(),
            "active": snap.active === true,
            "visible": snap.visible !== false,
            "rules-path-primary": String(snap.rulesPathPrimary || ""),
            "rules-path-secondary": String(snap.rulesPathSecondary || ""),
            "rules-folder": String(snap.rulesFolder || ""),
            "include-comments": snap.includeComments !== false
        }
        var notices = _noticesOf(snap.notices)
        if (notices !== null) payload["notices"] = notices
        nrrNativeBridge.writeTextFile(path, JSON.stringify(payload))
    }

    /// Mark the window gone, keeping the paths: the tray must not wait out the
    /// freshness window on a process that has already exited.
    function publishGone() {
        if (!publishing) return
        if (typeof snapshotProvider !== "function") return
        var path = _resolvePath()
        if (path === "" || typeof nrrNativeBridge.writeTextFile !== "function") return
        var snap = {}
        try { snap = snapshotProvider() || {} } catch (e) { snap = {} }
        var payload = {
            "at": Date.now(),
            "gone": true,
            "active": false,
            "visible": false,
            "rules-path-primary": String(snap.rulesPathPrimary || ""),
            "rules-path-secondary": String(snap.rulesPathSecondary || ""),
            "rules-folder": String(snap.rulesFolder || ""),
            "include-comments": snap.includeComments !== false
        }
        var notices = _noticesOf(snap.notices)
        if (notices !== null) payload["notices"] = notices
        nrrNativeBridge.writeTextFile(path, JSON.stringify(payload))
    }

    /// The notification settings in their published shape, or null when the
    /// source holds none. Both ends go through it: the file is the user's to edit.
    function _noticesOf(raw) {
        return Pure.trayNoticePrefsOf(raw)
    }

    /// Read the published snapshot.
    /// Returns `{ known, windowRunning, windowVisible, windowActive,
    /// rulesPathPrimary, rulesPathSecondary, rulesFolder, includeComments, at,
    /// notices }`.
    /// `known` is false when no window has ever published on this machine — the
    /// caller then has no rules paths and cannot compare anything.
    function read() {
        var blank = {
            known: false, windowRunning: false, windowVisible: false, windowActive: false,
            rulesPathPrimary: "", rulesPathSecondary: "", rulesFolder: "",
            includeComments: true, at: 0, notices: null
        }
        var path = _resolvePath()
        if (path === "") return blank
        if (typeof nrrNativeBridge.statFile !== "function"
                || typeof nrrNativeBridge.readFileBytes !== "function"
                || typeof nrrNativeBridge.decodeBase64Utf8 !== "function") {
            return blank
        }
        var stat = nrrNativeBridge.statFile(path)
        if (!stat || !stat.exists) return blank
        var b64 = String(nrrNativeBridge.readFileBytes(path) || "")
        if (b64 === "") return blank
        var parsed = null
        try {
            parsed = JSON.parse(String(nrrNativeBridge.decodeBase64Utf8(b64) || "{}"))
        } catch (e) {
            return blank
        }
        if (!parsed || typeof parsed !== "object") return blank
        var age = Date.now() - (Number(parsed.at) || 0)
        var running = parsed.gone !== true && age >= 0 && age < freshnessMs
        return {
            known: true,
            windowRunning: running,
            // Closed to the tray the process lives on with its window hidden.
            // Absent (an older window) reads as shown.
            windowVisible: running && parsed.visible !== false,
            // Only a LIVE snapshot can claim focus. A stale one describes a
            // window that may no longer exist.
            windowActive: running && parsed.active === true,
            rulesPathPrimary: String(parsed["rules-path-primary"] || ""),
            rulesPathSecondary: String(parsed["rules-path-secondary"] || ""),
            // The user's rule-set folder, as the window last knew it.
            rulesFolder: String(parsed["rules-folder"] || ""),
            // The user's "comments in rules files" choice; absent means the
            // shipped default (on).
            includeComments: parsed["include-comments"] !== false,
            at: Number(parsed.at) || 0,
            // Null from a window that predates them.
            notices: _noticesOf(parsed.notices)
        }
    }

    // Every exit path ends in a quit or in destroying the window's objects.
    property Connections _quitWatch: Connections {
        target: Qt.application
        function onAboutToQuit() { presence.publishGone() }
    }
    Component.onDestruction: publishGone()

    property Timer _heartbeatTimer: Timer {
        interval: presence.heartbeatMs
        running: presence.publishing
        repeat: true
        triggeredOnStart: true
        onTriggered: presence.publish()
    }
}
