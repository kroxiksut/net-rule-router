import QtQuick 2.15
import "../components"
import "../lib/rules.js" as Rules

// Tray-side writer for the rules files the user's routes are linked to.
//
// The linked file mirrors what the service enforces. The main window keeps it
// that way while it runs, but rules also land from elsewhere — the service's
// own authors, the terminal UI, a reset — and with the window closed nobody
// was left to write them. The file then reported a divergence the user
// never caused, and "Apply" resolved it by pushing the stale file back over
// the rules that had just been added. That loop is what this closes.
//
// Direction matters: this writes service -> file, and ONLY when the caller
// knows the service side is what changed (a revision landed). The periodic
// `RulesDriftWatch` comparison stays a question, because a divergence it finds
// may just as well be the user editing the file by hand.
QtObject {
    id: writer

    /// RpcTransport instance (callback table).
    property var rpc: null
    /// GuiPresence instance — supplies the linked rules-file paths.
    property var presence: null
    /// `PlatformProfile.os`: picks the application section of the file.
    property string os: ""
    /// The tray window, whose `tr()` words the file's syntax hint.
    property var textSource: null

    /// ACE codec for the shared serializer; a `.pragma library` cannot reach
    /// the bridge, so the conversion crosses as a callback.
    property var aceCodec: HostAceCodec {}

    /// The same writer the main window uses.
    property var fileWriter: RulesFileWriter {
        rpc: writer.rpc
        textSource: writer.textSource
    }

    /// One write at a time: the trigger is a push, and a burst of them would
    /// otherwise interleave two full read-build-write chains over one file.
    property bool _inFlight: false
    /// A push that came during a write: the rules it announces may be newer
    /// than the ones being written, so one more pass follows.
    property bool _again: false

    readonly property bool _bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcRulesList === "function"
        && typeof nrrNativeBridge.rpcSidecarPassthroughRead === "function"
        && typeof nrrNativeBridge.readFileBytes === "function"
        && typeof nrrNativeBridge.rpcUserSettingsRulesFileWrite === "function"

    /// Pull what the service enforces and mirror it into every linked file.
    /// Silent and best-effort: a failure leaves the file as it was, and the
    /// ordinary drift watch still has the last word.
    function mirrorServiceIntoFiles() {
        if (_inFlight) { _again = true; return }
        if (!_bridgeReady || !rpc || !presence) return
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
                writer._settled()
                return
            }
            var wire = payload.rows || []
            var rows = []
            for (var i = 0; i < wire.length; i += 1) {
                rows.push(Rules.fileRowFromServiceWire(wire[i], writer.aceCodec.decode))
            }
            var includeComments = snap.includeComments !== false
            // A file edited by hand since the program wrote it is not ours to
            // replace: it stays, and the window asks about it when it opens
            // (the drift question here may ask first).
            writer.fileWriter.handEdited([paths.primary, paths.secondary], function(edited) {
                var pending = 2
                var settle = function() { if (--pending === 0) writer._settled() }
                writer._writeRoute("primary", paths.primary, rows, includeComments, settle,
                    edited.indexOf(paths.primary) >= 0)
                writer._writeRoute("secondary", paths.secondary, rows, includeComments, settle,
                    edited.indexOf(paths.secondary) >= 0)
            })
        })
    }

    function _settled() {
        _inFlight = false
        if (_again) {
            _again = false
            Qt.callLater(mirrorServiceIntoFiles)
        }
    }

    function _writeRoute(route, path, rows, includeComments, done, keep) {
        if (path === "") { done(); return }
        var model = { count: rows.length, get: function(i) { return rows[i] } }
        fileWriter.writeRoute(route, path, model, includeComments, os, function(ok, changed) {
            if (!ok) console.log("tray bound-file: write failed:", route, path)
            else if (changed) console.log("tray bound-file: mirrored service rules into", path)
            done()
        }, keep === true)
    }
}
