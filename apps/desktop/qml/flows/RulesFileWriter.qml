import QtQuick 2.15
import "../lib/rules.js" as Rules

// Writes one route's rules file from a set of rules rows. Needs no window: the
// main window hands it its table, the tray the rows it read from the service,
// and both get byte-identical files for the same rules.
QtObject {
    id: writer

    /// RpcTransport instance; the passthrough sections come from the sidecar.
    property var rpc: null
    /// The owner window, for its `tr()`: the syntax hint is written in the
    /// language of the moment of writing. English without one.
    property var textSource: null

    /// The translated syntax-hint lines for the file's header.
    function hintLines() {
        var source = writer.textSource
        return Rules.rulesFileHintLines(source && typeof source.tr === "function"
            ? function(key, fallback) { return source.tr(key, fallback) } : null)
    }

    /// The write goes through the launcher, which refuses a file edited by
    /// hand: no bridge-side `writeTextFile` fallback, that is the unchecked
    /// write this exists to replace.
    readonly property bool canWrite: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcUserSettingsRulesFileWrite === "function"
        && rpc !== null && typeof rpc.registerRpcCallback === "function"

    /// The foreign-OS / unsupported sections captured at the last import for
    /// `route`, handed to `onSections`. The sidecar is owned by the launcher,
    /// not the service, so this resolves with the service stopped; any failure
    /// degrades to "no passthrough" rather than blocking the write.
    function readPassthroughSections(route, onSections) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarPassthroughRead !== "function"
                || !rpc || typeof rpc.registerRpcCallback !== "function") {
            onSections({})
            return
        }
        var corr = nrrNativeBridge.rpcSidecarPassthroughRead(route)
        if (!corr || String(corr) === "") { onSections({}); return }
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.log("sidecar.passthrough.read failed:", code, msg)
            onSections((ok && payload && payload.sections) || {})
        })
    }

    /// Does `path` already hold these rules? Compares the routing BODY, not
    /// the bytes: the metadata header carries the generation timestamp, so a
    /// byte compare would call every file stale the moment it is regenerated.
    function fileHoldsText(path, text) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") return false
        if (typeof nrrNativeBridge.decodeBase64Utf8 !== "function") return false
        var b64 = String(nrrNativeBridge.readFileBytes(path) || "")
        if (b64 === "") return false
        // NOT `Qt.atob`: it decodes as latin-1, so every byte of a UTF-8
        // Cyrillic comment comes back as two characters and the comparison
        // never matches — the file is rewritten on every pass.
        var current = String(nrrNativeBridge.decodeBase64Utf8(b64) || "")
        return Rules.canonicalRulesBody(current) === Rules.canonicalRulesBody(text)
    }

    /// Generate `route`'s rules from `rows` (`{count, get(i)}`, a ListModel
    /// works) and write them to `path`. `os` is `PlatformProfile.os`: it picks
    /// the application section. `done(ok, changed)` — `changed` is false when
    /// the file already held these rules and was left alone. `keep`: the file
    /// was edited by hand since the program wrote it, so it is never
    /// overwritten here, only recognised when it already holds these rules.
    /// The launcher makes the same refusal on its own (`done(false, false,
    /// "rules-file-hand-edited")`), whoever calls; `overwrite` is the user's
    /// answer that the file may go.
    function writeRoute(route, path, rows, includeComments, os, done, keep, overwrite) {
        var finish = function(ok, changed, code) {
            if (typeof done === "function") done(!!ok, !!changed, String(code || ""))
        }
        if (!canWrite) {
            finish(false, false)
            return
        }
        readPassthroughSections(route, function(sections) {
            var text = Rules.buildCanonicalRulesText(
                rows, route, sections, !!includeComments, os, writer.hintLines())
            if (writer.fileHoldsText(path, text)) {
                writer.noteWritten(path)
                finish(true, false)
                return
            }
            if (keep === true) {
                console.log("[bound-file] left as edited by hand:", route, path)
                finish(true, false)
                return
            }
            var corr = nrrNativeBridge.rpcUserSettingsRulesFileWrite({
                "path": String(path), "text": text, "overwrite": overwrite === true })
            if (!corr || String(corr) === "") {
                console.log("[bound-file] write request not sent:", route, path)
                finish(false, false)
                return
            }
            rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
                if (!ok) {
                    console.log("[bound-file] write refused:", route, path, code, msg)
                    finish(false, false, code)
                    return
                }
                finish(true, true)
            })
        })
    }

    /// `path` now holds the program's version of its rules: a later change
    /// there is the user's hand, which a write from elsewhere must not erase
    /// unasked (`handEdited`). `done()`, when given, runs once the record is
    /// in or could not be made.
    function noteWritten(path, done) {
        var finish = function() { if (typeof done === "function") done() }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcUserSettingsRulesFileWritten !== "function"
                || !rpc || typeof rpc.registerRpcCallback !== "function") { finish(); return }
        var corr = nrrNativeBridge.rpcUserSettingsRulesFileWritten({ "path": String(path) })
        if (!corr || String(corr) === "") { finish(); return }
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.log("[bound-file] written version not recorded:", code, msg)
            finish()
        })
    }

    /// Which of `paths` were edited by hand since the program last wrote them.
    /// `onAnswer(list)`; a failed check answers every path, so nothing is
    /// overwritten on a guess.
    function handEdited(paths, onAnswer) {
        var asked = []
        for (var i = 0; i < paths.length; i += 1) {
            if (String(paths[i] || "") !== "") asked.push(String(paths[i]))
        }
        if (asked.length === 0) { onAnswer([]); return }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcUserSettingsRulesFilesHandEdited !== "function"
                || !rpc || typeof rpc.registerRpcCallback !== "function") {
            onAnswer([])
            return
        }
        var corr = nrrNativeBridge.rpcUserSettingsRulesFilesHandEdited({ "paths": asked })
        if (!corr || String(corr) === "") { onAnswer(asked); return }
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("[bound-file] hand-edit check failed:", code, msg)
                onAnswer(asked)
                return
            }
            onAnswer((payload && payload["hand-edited"]) || [])
        })
    }
}
