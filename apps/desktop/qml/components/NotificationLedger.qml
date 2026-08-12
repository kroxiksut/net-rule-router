import QtQuick 2.15

// Cross-surface record of notifications the user has already answered.
//
// The window and the tray are separate processes that can raise the SAME
// notice. Once the user has answered it on either one, the other must stop
// showing it — otherwise a decision taken in the tray leaves a stale copy
// sitting in the window (and the reverse). This component is the one mechanism
// both surfaces use for that; nothing about it is specific to a single notice.
//
// Model: a notice carries a STATE-DERIVED id. `record(id)` writes it to a
// shared file; `isDecided(id)` asks whether it has been answered anywhere; the
// `decidedElsewhere(id)` signal fires when a decision made by the OTHER surface
// shows up, so a notice currently on screen can be taken down. Because the id
// encodes the state, the SAME condition arising again in a NEW shape (a
// different external address, a different rules divergence) produces a new id
// and is offered again — a decision suppresses what the user answered, not the
// whole category, forever.
//
// Transport is a small JSON file next to the app's other per-user local state
// (`{ "<id>": <epoch ms> }`), polled on a slow cadence and re-read only when
// its stat changes. A file rather than IPC because the service is not involved:
// this is a decision between two of the user's own processes, and the service
// runs as LocalSystem with no business knowing about them. Writes are
// read-merge-write and not atomic across processes; two decisions taken in the
// same second on two surfaces can lose one, whose only consequence is that its
// notice may be offered once more.
QtObject {
    id: ledger

    /// File name under the per-user app-local data directory. One ledger per
    /// user, shared by every surface that user is running.
    property string fileName: "notification-decisions.json"

    /// How often to look for decisions taken on the other surface. A second is
    /// far below "the user notices the stale copy is still there" and the check
    /// is a stat call that almost always ends there.
    property int pollIntervalMs: 1000

    /// Bounded so a long-lived process cannot grow the file without limit. The
    /// oldest decisions are the safe ones to forget: their state is long gone,
    /// so forgetting them cannot resurrect a live notice.
    property int cap: 512

    /// Decisions older than this are dropped on the next write. A record only
    /// has to outlive the condition it was given about; kept forever, a stale
    /// one silences a NEW notice that happens to land on the same id.
    /// `permanentPrefixes` names the ids that genuinely mean "never again".
    property int maxAgeMs: 7 * 24 * 60 * 60 * 1000
    property var permanentPrefixes: ["auto-rule-never:"]

    function _isPermanent(id) {
        for (var i = 0; i < permanentPrefixes.length; i += 1) {
            if (id.indexOf(permanentPrefixes[i]) === 0) return true
        }
        return false
    }

    /// A decision recorded by the OTHER surface. The local surface reacts by
    /// closing whatever it is showing for that id.
    signal decidedElsewhere(string noticeId)

    // ── Internals ────────────────────────────────────────────────────────────

    /// Resolved lazily: the bridge creates the directory on first ask.
    property string _path: ""
    /// id -> epoch ms of the decision.
    property var _entries: ({})
    /// Stat fingerprint of the last content we read, so an unchanged file costs
    /// one stat call per poll and no read/parse/allocate.
    property string _seenStamp: ""
    /// Ids this surface recorded itself; used to tell "my decision came back
    /// off disk" from "the other surface decided something".
    property var _ownIds: ({})

    readonly property bool _bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.defaultLocalAppDataPath === "function"
        && typeof nrrNativeBridge.writeTextFile === "function"
        && typeof nrrNativeBridge.statFile === "function"

    function _resolvePath() {
        if (_path !== "") return _path
        if (!_bridgeReady) return ""
        _path = String(nrrNativeBridge.defaultLocalAppDataPath(fileName) || "")
        return _path
    }

    /// Pull the file in when its stat changed, and announce every id that is new
    /// to this surface. Called from the poll AND from every read, so a query
    /// answered milliseconds after the other surface decided still sees it —
    /// the stat gate makes the repeat cost one syscall.
    function _refresh() {
        var path = _resolvePath()
        if (path === "") return
        var stat = nrrNativeBridge.statFile(path)
        if (!stat || !stat.exists) return
        var stamp = String(stat.mtime) + ":" + String(stat.size)
        if (stamp === _seenStamp) return
        _seenStamp = stamp
        if (typeof nrrNativeBridge.readFileBytes !== "function"
                || typeof nrrNativeBridge.decodeBase64Utf8 !== "function") {
            return
        }
        var b64 = String(nrrNativeBridge.readFileBytes(path) || "")
        if (b64 === "") return
        var parsed = null
        try {
            parsed = JSON.parse(String(nrrNativeBridge.decodeBase64Utf8(b64) || "{}"))
        } catch (e) {
            // A half-written or hand-edited file must not wedge the poll: drop
            // it and let the next decision rewrite a clean one.
            console.warn("notification ledger: unreadable, ignoring")
            return
        }
        if (!parsed || typeof parsed !== "object") return
        var merged = {}
        for (var known in _entries) merged[known] = _entries[known]
        var fresh = []
        for (var id in parsed) {
            if (merged[id] !== undefined) continue
            merged[id] = Number(parsed[id]) || Date.now()
            if (_ownIds[id] !== true) fresh.push(id)
        }
        _entries = merged
        for (var i = 0; i < fresh.length; i += 1) decidedElsewhere(fresh[i])
    }

    /// Drop the expired entries, then the oldest ones once the cap is still
    /// exceeded, forgetting which of them were ours along with them.
    function _trim(entries) {
        var cutoff = Date.now() - maxAgeMs
        var kept = {}
        for (var id in entries) {
            if (_isPermanent(id) || Number(entries[id] || 0) >= cutoff) {
                kept[id] = entries[id]
            }
        }
        entries = kept
        var ids = Object.keys(entries)
        if (ids.length <= cap) return entries
        ids.sort(function(a, b) { return (entries[a] || 0) - (entries[b] || 0) })
        var out = {}
        var own = {}
        for (var i = ids.length - cap; i < ids.length; i += 1) {
            out[ids[i]] = entries[ids[i]]
            if (_ownIds[ids[i]] === true) own[ids[i]] = true
        }
        _ownIds = own
        return out
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Has this exact notice already been answered, here or on the other
    /// surface?
    function isDecided(noticeId) {
        return decidedAt(noticeId) > 0
    }

    /// When the answer was given, as epoch ms; 0 when it never was, and 0 once
    /// an answer has aged out (see `maxAgeMs`). Lets a caller apply a shorter
    /// refractory period of its own instead of suppressing a recurring
    /// condition forever.
    function decidedAt(noticeId) {
        var id = String(noticeId || "")
        if (id === "") return 0
        _refresh()
        var at = Number(_entries[id] || 0)
        if (at <= 0) return 0
        if (!_isPermanent(id) && (Date.now() - at) > maxAgeMs) return 0
        return at
    }

    /// Record the user's answer.
    function record(noticeId) {
        recordAll([noticeId])
    }

    /// Record several answers as one write — one gesture can settle a whole
    /// list of ids, and a file write per id would be that many read-merge-write
    /// rounds for a single click. Merges whatever the other surface wrote in
    /// the meantime so a concurrent decision is not dropped by our own write.
    function recordAll(noticeIds) {
        var wanted = []
        for (var n = 0; n < (noticeIds || []).length; n += 1) {
            var candidate = String(noticeIds[n] || "")
            if (candidate !== "") wanted.push(candidate)
        }
        if (wanted.length === 0) return
        var path = _resolvePath()
        _refresh()
        var entries = {}
        for (var known in _entries) entries[known] = _entries[known]
        var own = {}
        for (var mine in _ownIds) own[mine] = _ownIds[mine]
        var now = Date.now()
        for (var i = 0; i < wanted.length; i += 1) {
            entries[wanted[i]] = now
            own[wanted[i]] = true
        }
        _ownIds = own
        entries = _trim(entries)
        _entries = entries
        if (path === "") return
        if (!nrrNativeBridge.writeTextFile(path, JSON.stringify(entries))) {
            console.warn("notification ledger: write failed")
            return
        }
        // Our own write changes the stat; adopt it now so the next poll does not
        // re-read a file we already know the contents of.
        var stat = nrrNativeBridge.statFile(path)
        if (stat && stat.exists) {
            _seenStamp = String(stat.mtime) + ":" + String(stat.size)
        }
    }

    /// Poll for decisions taken on the other surface.
    property Timer _pollTimer: Timer {
        interval: ledger.pollIntervalMs
        running: true
        repeat: true
        onTriggered: ledger._refresh()
    }
}
