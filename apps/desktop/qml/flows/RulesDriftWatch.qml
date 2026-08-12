import QtQuick 2.15
import "../components"
import "../lib/rules.js" as Rules

// Tray-side watch for "the rules in your files are not the rules being
// enforced".
//
// The main window already compares file / window / service and raises its amber
// banner. That banner is invisible when the window is closed or sitting behind
// something else — which is most of the time, because the product is meant to
// run in the background. The tray lives in the user's session, so it can read
// the user's rules files (the service runs as LocalSystem and has no business
// in a user profile) and ask the service what it currently enforces.
//
// Only two legs are compared here, file and service: with no window there is no
// third "what the app has in its table" leg, and file-vs-service is exactly the
// divergence a user can act on from the tray.
//
// Both legs are canonicalised through the same `local.canonical-rules-hash`
// SSOT the window uses, via the shared builder in `lib/rules.js`, so the two
// surfaces cannot classify the same state differently.
QtObject {
    id: watch

    /// RpcTransport instance (callback table). Requests go straight to the
    /// bridge — these RPCs have no forwarder — and land back through it.
    property var rpc: null
    /// GuiPresence instance: supplies the rules paths and tells us whether the
    /// window is on the foreground.
    property var presence: null
    /// Master gate. The caller folds in the user's notification preference and
    /// whether the service is running.
    property bool enabled: false

    /// Full-comparison cadence: parse both files, hash both legs, ask the
    /// service what it enforces. This is the safety net, not the fast path —
    /// the two sides can also drift apart because the SERVICE changed, and no
    /// amount of watching the files would ever show that. Everything is
    /// skipped outright while the window has focus.
    property int intervalMs: 30000

    /// Cheap disk watch between full comparisons: two `statFile` calls, no
    /// read, no parse, no RPC. The overwhelmingly common trigger is "the user
    /// edited a rules file", and that is visible in mtime + size alone, so a
    /// change starts a full comparison immediately instead of waiting for the
    /// next full tick. Short enough that the user does not notice the wait,
    /// long enough that a burst of editor saves does not turn into a burst of
    /// comparisons.
    property int fileWatchIntervalMs: 6000

    /// Settling delay before a freshly seen divergence is believed. Rules files
    /// are rewritten right after an apply, and a comparison landing mid-write
    /// reports a divergence that stops existing a moment later. Seeing the same
    /// divergence twice a few seconds apart costs one extra `rules.list` and
    /// removes that whole class of false alarm; the file legs come out of the
    /// stat-keyed cache, so the second pass is nearly free.
    property int confirmDelayMs: 4000

    /// Raised when a divergence has been confirmed. `details`:
    ///   signature — state-derived id, stable for as long as the divergence is
    ///               the same one (both hashes of both routes)
    ///   routes    — [{ route, path }] for the routes that differ
    signal driftDetected(var details)
    /// Raised when a previously reported divergence is gone.
    signal driftCleared()

    // ── Internals ────────────────────────────────────────────────────────────

    property bool _inFlight: false
    /// Divergence seen once and awaiting confirmation, "" when none is.
    property string _pendingSignature: ""
    /// When `_pendingSignature` was first seen. The confirming pass can be
    /// brought forward by a file change, so the delay is enforced on the clock
    /// rather than on "some later pass ran".
    property real _pendingSince: 0
    /// Signature currently reported as detected, "" when nothing is.
    property string _reportedSignature: ""
    /// mtime + size of both rules files as of the last cheap watch tick.
    property string _fileStamp: ""

    /// File-leg cache, one slot per route holding `{ key, hash }` where `key`
    /// is path + stat: re-reading, parsing and hashing an unchanged file every
    /// minute would be pure waste.
    property var _fileCache: ({})

    readonly property bool _bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcCanonicalRulesHash === "function"
        && typeof nrrNativeBridge.rpcPresetParse === "function"
        && typeof nrrNativeBridge.rpcRulesList === "function"
        && typeof nrrNativeBridge.statFile === "function"

    /// ACE encoding for the shared serializer; a `.pragma library` cannot reach
    /// the bridge, so the codec crosses as a callback.
    property var aceCodec: HostAceCodec {}

    function _hash(rulesJson, done) {
        var corr = nrrNativeBridge.rpcCanonicalRulesHash(String(rulesJson || ""))
        if (!corr || corr === "") { done(""); return }
        rpc.registerRpcCallback(corr, function(ok, payload) {
            done(ok && payload ? String(payload.hash || "") : "")
        })
    }

    /// Hash of the rules a file holds, for its own route. `done(hash)` with ""
    /// when there is no file, it cannot be read, or the parse failed — the
    /// caller treats an empty leg as "nothing to compare", never as a mismatch.
    function _fileHash(route, path, done) {
        if (path === "") { done(""); return }
        var stat = nrrNativeBridge.statFile(path)
        if (!stat || !stat.exists) { done(""); return }
        var key = path + "|" + String(stat.mtime) + "|" + String(stat.size)
        var cached = _fileCache[route]
        if (cached && cached.key === key) { done(cached.hash); return }
        if (typeof nrrNativeBridge.readFileBytes !== "function"
                || typeof nrrNativeBridge.decodeBase64Utf8 !== "function") {
            done("")
            return
        }
        var b64 = String(nrrNativeBridge.readFileBytes(path) || "")
        if (b64 === "") { done(""); return }
        var text = String(nrrNativeBridge.decodeBase64Utf8(b64) || "")
        var corr = nrrNativeBridge.rpcPresetParse(text)
        if (!corr || corr === "") { done(""); return }
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) { done(""); return }
            var parsed = (payload.result || {}).rules || []
            var rows = []
            for (var i = 0; i < parsed.length; i += 1) {
                rows.push(Rules.driftRowFromParsedRule(parsed[i], route))
            }
            var json = Rules.buildDriftRulesJsonForRoute(
                rows, route, watch.aceCodec.encode)
            watch._hash(json, function(hash) {
                // Keyed on the stat read BEFORE the async chain: a file
                // rewritten meanwhile gets a different key next tick.
                var cache = {}
                for (var r in watch._fileCache) cache[r] = watch._fileCache[r]
                cache[route] = { key: key, hash: hash }
                watch._fileCache = cache
                done(hash)
            })
        })
    }

    /// Hashes of what the service currently enforces, one per route.
    /// `done({primary, secondary})`; empty strings when the service could not
    /// be read.
    function _serviceHashes(done) {
        var corr = nrrNativeBridge.rpcRulesList()
        if (!corr || corr === "") { done({ primary: "", secondary: "" }); return }
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) { done({ primary: "", secondary: "" }); return }
            var wire = payload.rows || []
            var rows = []
            for (var i = 0; i < wire.length; i += 1) {
                rows.push(Rules.driftRowFromServiceWire(wire[i]))
            }
            var out = { primary: "", secondary: "" }
            var pending = 2
            var settle = function() { if (--pending === 0) done(out) }
            watch._hash(
                Rules.buildDriftRulesJsonForRoute(rows, "primary", watch.aceCodec.encode),
                function(h) { out.primary = h; settle() })
            watch._hash(
                Rules.buildDriftRulesJsonForRoute(rows, "secondary", watch.aceCodec.encode),
                function(h) { out.secondary = h; settle() })
        })
    }

    /// One comparison pass.
    function check() {
        if (!enabled || !_bridgeReady || !rpc || !presence) return
        // A pass is already running. Losing the confirming pass would leave a
        // real divergence pending until the next full tick, so ask again.
        if (_inFlight) {
            if (_pendingSignature !== "") _armConfirm()
            return
        }
        var snap = presence.read()
        // No window has ever published: without its answer we do not know which
        // files back the user's rules, and guessing is worse than staying quiet.
        if (!snap.known) return
        // The window is in front of the user and owns the message.
        if (snap.windowActive) return
        var paths = {
            primary: String(snap.rulesPathPrimary || ""),
            secondary: String(snap.rulesPathSecondary || "")
        }
        if (paths.primary === "" && paths.secondary === "") return

        _inFlight = true
        var fileHashes = { primary: "", secondary: "" }
        var pending = 3
        var serviceHashes = { primary: "", secondary: "" }
        var settle = function() {
            if (--pending > 0) return
            watch._inFlight = false
            watch._classify(paths, fileHashes, serviceHashes)
        }
        _fileHash("primary", paths.primary, function(h) { fileHashes.primary = h; settle() })
        _fileHash("secondary", paths.secondary, function(h) { fileHashes.secondary = h; settle() })
        _serviceHashes(function(h) { serviceHashes = h; settle() })
    }

    function _classify(paths, fileHashes, serviceHashes) {
        var routes = []
        var parts = []
        var compare = function(route) {
            var f = fileHashes[route]
            var s = serviceHashes[route]
            // An empty leg means "could not read", not "empty rule set": a
            // service that did not answer must never look like a divergence.
            if (f === "" || s === "" || f === s) return
            routes.push({ route: route, path: paths[route] })
            parts.push(route + ":" + f.substring(0, 16) + ":" + s.substring(0, 16))
        }
        compare("primary")
        compare("secondary")

        if (routes.length === 0) {
            _pendingSignature = ""
            _confirmTimer.stop()
            if (_reportedSignature !== "") {
                _reportedSignature = ""
                driftCleared()
            }
            return
        }
        var signature = "rules-drift:" + parts.join("|")
        if (signature === _reportedSignature) { _confirmTimer.stop(); return }
        // First sighting — or a different divergence than the one being
        // confirmed, which restarts the clock rather than inheriting it.
        if (signature !== _pendingSignature) {
            _pendingSignature = signature
            _pendingSince = Date.now()
            _armConfirm()
            return
        }
        // Same divergence, but a file change pulled this pass in early: it
        // proves nothing yet about the file having settled.
        if ((Date.now() - _pendingSince) < confirmDelayMs) {
            _armConfirm()
            return
        }
        _confirmTimer.stop()
        _reportedSignature = signature
        driftDetected({ signature: signature, routes: routes })
    }

    function _armConfirm() {
        if (!_confirmTimer.running) _confirmTimer.start()
    }

    /// mtime + size of one rules file, as an opaque string. Distinguishes
    /// "no path" from "path with no file": the second one becoming a file is a
    /// change worth comparing on.
    function _statStamp(path) {
        if (path === "") return "-"
        var stat = nrrNativeBridge.statFile(path)
        if (!stat || !stat.exists) return "x"
        return String(stat.mtime) + ":" + String(stat.size)
    }

    /// Cheap tick: did either rules file change on disk since last time?
    function _watchFiles() {
        if (!enabled || !_bridgeReady || !presence) return
        var snap = presence.read()
        if (!snap.known || snap.windowActive) return
        var stamp = _statStamp(String(snap.rulesPathPrimary || ""))
            + "|" + _statStamp(String(snap.rulesPathSecondary || ""))
        if (stamp === _fileStamp) return
        _fileStamp = stamp
        check()
    }

    /// Forget the reported state so the same divergence can be announced again
    /// later (after the refractory window the caller keeps).
    function resetReported() {
        _reportedSignature = ""
        _pendingSignature = ""
        _confirmTimer.stop()
    }

    property Timer _pollTimer: Timer {
        interval: watch.intervalMs
        running: watch.enabled
        repeat: true
        onTriggered: watch.check()
    }

    property Timer _fileWatchTimer: Timer {
        interval: watch.fileWatchIntervalMs
        running: watch.enabled
        repeat: true
        triggeredOnStart: true
        onTriggered: watch._watchFiles()
    }

    /// One-shot re-check of a divergence seen once.
    property Timer _confirmTimer: Timer {
        interval: watch.confirmDelayMs
        repeat: false
        onTriggered: watch.check()
    }
}
