import QtQuick 2.15

// ACE / Punycode boundary codec.
//
// Rules travel ACE-encoded on the wire, in WFP filters and in SQLite, while the
// user reads and types the Unicode form. Every surface that serialises rules
// has to cross that boundary the same way, or two surfaces hash the same rule
// set differently and report a divergence that does not exist.
//
// The conversion itself lives in the C++ bridge, which a `.pragma library`
// scope cannot reach — hence a tiny QtObject component instead of a function in
// `lib/rules.js`. Both the main window and the tray instantiate one; the
// serializer in `lib/rules.js` takes `encode` as a callback.
//
// Both directions are total: an unavailable bridge, an empty value or a failed
// conversion returns the trimmed input rather than throwing, so a rule never
// disappears from a payload because its hostname could not be converted.
QtObject {
    /// Unicode host -> ACE. ASCII passes through unchanged (already ACE, or a
    /// plain hostname), which is what the wire boundary wants.
    function encode(host) {
        var trimmed = String(host || "").trim()
        if (trimmed === "") return ""
        var allAscii = true
        for (var i = 0; i < trimmed.length; i += 1) {
            if (trimmed.charCodeAt(i) > 127) { allAscii = false; break }
        }
        if (allAscii) return trimmed
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.punycodeEncodeHost !== "function") {
            return trimmed
        }
        var ace = String(nrrNativeBridge.punycodeEncodeHost(trimmed) || "")
        return ace !== "" ? ace : trimmed
    }

    /// ACE host -> Unicode, for display. A value with no `xn--` label is
    /// returned untouched.
    function decode(host) {
        var trimmed = String(host || "").trim()
        if (trimmed === "") return ""
        if (trimmed.toLowerCase().indexOf("xn--") < 0) return trimmed
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.punycodeDecodeHost !== "function") {
            return trimmed
        }
        var unicode = String(nrrNativeBridge.punycodeDecodeHost(trimmed) || "")
        return unicode !== "" ? unicode : trimmed
    }
}
