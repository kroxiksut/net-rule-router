import QtQuick 2.15
import "../components"
import "../lib/rules.js" as Rules

// Tray-side writer for the rules files the user's routes are linked to.
//
// The linked file mirrors what the service enforces. The main window keeps it
// that way after every apply, but the service also authors rules on its own —
// an accepted suggestion, or "add automatically" — and with the window closed
// nobody was left to write them. The file then reported a divergence the user
// never caused, and "Apply" resolved it by pushing the stale file back over
// the rules that had just been added. That loop is what this closes.
//
// Direction matters: this writes service -> file, and ONLY when the caller
// knows the service side is what changed (an auto-rule landed). The periodic
// `RulesDriftWatch` comparison stays a question, because a divergence it finds
// may just as well be the user editing the file by hand.
QtObject {
    id: writer

    /// RpcTransport instance (callback table).
    property var rpc: null
    /// GuiPresence instance — supplies the linked rules-file paths.
    property var presence: null

    /// ACE codec for the shared serializer; a `.pragma library` cannot reach
    /// the bridge, so the conversion crosses as a callback.
    property var aceCodec: HostAceCodec {}

    /// One write at a time: the trigger is a push, and a burst of them would
    /// otherwise interleave two full read-build-write chains over one file.
    property bool _inFlight: false

    readonly property bool _bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcRulesList === "function"
        && typeof nrrNativeBridge.rpcSidecarPassthroughRead === "function"
        && typeof nrrNativeBridge.readFileBytes === "function"
        && typeof nrrNativeBridge.writeTextFile === "function"

    /// Pull what the service enforces and mirror it into every linked file.
    /// Silent and best-effort: a failure leaves the file as it was, and the
    /// ordinary drift watch still has the last word.
    function mirrorServiceIntoFiles() {
        if (_inFlight || !_bridgeReady || !rpc || !presence) return
        var snap = presence.read()
        // Without the window's answer we do not know which files back the
        // user's rules, and guessing which file to overwrite is worse than
        // doing nothing.
        if (!snap.known) return
        // The window is up and owns the write; two writers on one file is the
        // bug that cost a whole run's preferences once already.
        if (snap.windowRunning) return
        var paths = {
            primary: String(snap.rulesPathPrimary || ""),
            secondary: String(snap.rulesPathSecondary || "")
        }
        if (paths.primary === "" && paths.secondary === "") return

        _inFlight = true
        var corr = nrrNativeBridge.rpcRulesList()
        if (!corr || String(corr) === "") { _inFlight = false; return }
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok || !payload) {
                console.log("tray bound-file: rules.list failed:", code, msg)
                writer._inFlight = false
                return
            }
            var wire = payload.rows || []
            var rows = []
            for (var i = 0; i < wire.length; i += 1) {
                rows.push(Rules.fileRowFromServiceWire(wire[i], writer.aceCodec.decode))
            }
            var pending = 2
            var settle = function() { if (--pending === 0) writer._inFlight = false }
            writer._writeRoute("primary", paths.primary, rows, settle)
            writer._writeRoute("secondary", paths.secondary, rows, settle)
        })
    }

    function _writeRoute(route, path, rows, done) {
        if (path === "") { done(); return }
        var corr = nrrNativeBridge.rpcSidecarPassthroughRead(route)
        var build = function(sections) {
            var model = { count: rows.length, get: function(i) { return rows[i] } }
            var text = Rules.buildCanonicalRulesText(model, route, sections, true)
            // Compare the routing body, not the bytes: the header carries a
            // generation timestamp, so a byte compare rewrites every file on
            // every pass and the drift watch then sees its own mtime churn.
            var b64 = String(nrrNativeBridge.readFileBytes(path) || "")
            if (b64 !== "") {
                var current = ""
                try { current = Qt.atob(b64) } catch (e) { current = "" }
                if (current !== ""
                        && Rules.canonicalRulesBody(current)
                            === Rules.canonicalRulesBody(text)) {
                    done()
                    return
                }
            }
            if (!nrrNativeBridge.writeTextFile(path, text)) {
                console.log("tray bound-file: write failed:", route, path)
            } else {
                console.log("tray bound-file: mirrored service rules into", path)
            }
            done()
        }
        if (!corr || String(corr) === "") { build({}); return }
        rpc.registerRpcCallback(corr, function(ok, payload) {
            build((ok && payload && payload.sections) || {})
        })
    }
}
