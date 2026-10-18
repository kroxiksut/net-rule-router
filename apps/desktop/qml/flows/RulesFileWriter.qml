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

    readonly property bool canWrite: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.writeTextFile === "function"

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
    /// the file already held these rules and was left alone.
    function writeRoute(route, path, rows, includeComments, os, done) {
        var finish = function(ok, changed) {
            if (typeof done === "function") done(!!ok, !!changed)
        }
        if (!canWrite) {
            finish(false, false)
            return
        }
        readPassthroughSections(route, function(sections) {
            var text = Rules.buildCanonicalRulesText(
                rows, route, sections, !!includeComments, os, writer.hintLines())
            if (writer.fileHoldsText(path, text)) {
                finish(true, false)
                return
            }
            if (!nrrNativeBridge.writeTextFile(path, text)) {
                console.log("[bound-file] writeTextFile failed:", route, path)
                finish(false, false)
                return
            }
            finish(true, true)
        })
    }
}
