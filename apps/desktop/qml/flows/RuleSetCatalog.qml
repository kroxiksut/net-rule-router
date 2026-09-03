import QtQuick 2.15

// Non-visual controller for the RULE-SET CATALOG: what sets exist in the user's
// folder and in the bundled packs, which one is selected, and which files back
// it.
//
// Extracted from Main.qml (thin-shell rule). Enumerating the folder is
// filesystem work reached from bindings that run on every preferences write, so
// the cache below is the load-bearing part — see its own note.
QtObject {
    id: ruleSetCatalog

    /// The ApplicationWindow: preferences, the remembered paths and the status
    /// line all belong to it.
    property var root

    /// Cached on the folder path: this is filesystem work and
    /// `rulesSourcePathFor` runs on every root.prefs write via the Source row's
    /// binding. `invalidateRuleSetCache()` drops it when the folder contents may
    /// have changed under us.
    /// Held INSIDE a box and mutated in place: a plain `property var` written
    /// from here notifies, and every binding that reaches this enumeration —
    /// the Source row, the empty-state text — re-evaluates because of the very
    /// call it made. That is the "Binding loop detected" the rules table logged
    /// on each repaint. An in-place field write on a `var` object notifies
    /// nobody, which is exactly what a cache should do.
    property var _ruleSetCacheBox: ({ v: null })

    function _ruleSetEnum() {
        var dir = root.userPresetsDir
        var cached = _ruleSetCacheBox.v
        if (cached && cached.dir === dir) return cached
        var res = { dir: dir, userOwned: false, entries: [], paths: {} }
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.listAllPresets === "function") {
            if (dir !== "") {
                try {
                    res.entries = JSON.parse(
                        String(nrrNativeBridge.listAllPresets(dir) || "[]"))
                } catch (e) { res.entries = [] }
                res.userOwned = res.entries.length > 0
            }
            if (res.entries.length === 0) {
                try {
                    res.entries = JSON.parse(
                        String(nrrNativeBridge.listAllPresets() || "[]"))
                } catch (e2) { res.entries = [] }
                res.userOwned = false
            }
        }
        _ruleSetCacheBox.v = res
        return res
    }

    function invalidateRuleSetCache() { _ruleSetCacheBox.v = null }

    /// Display label of the set at `index`. Shipped sets read "<cc>_<pack>";
    /// a set of the user's own carries no country, so it must not gain a
    /// leading underscore.
    function ruleSetLabelAt(index) {
        var e = _ruleSetEnum()
        if (index < 0 || index >= e.entries.length) return ""
        var entry = e.entries[index]
        var country = String(entry.country || "")
        var pack = String(entry.pack || "")
        var fallback = country !== "" ? (country + "_" + pack) : pack
        return String(entry.label || fallback)
    }

    /// `<source>:<label>`, the form persisted in `root.prefs.selectedPresetSet`. The
    /// source prefix matters: the user's own folder and the shipped tree can
    /// hold sets with identical labels, and a choice made in one list must not
    /// be restored into the other.
    function ruleSetSelectionKey(index) {
        var label = ruleSetLabelAt(index)
        if (label === "") return ""
        return (_ruleSetEnum().userOwned ? "user:" : "bundled:") + label
    }

    /// Index of the remembered set within the CURRENT list, or -1 when nothing
    /// is remembered, the remembered choice belongs to the other source, or the
    /// set itself is gone (renamed / deleted folder) — each of which falls back
    /// to the default pick rather than stranding on a dead entry.
    function ruleSetRememberedIndex() {
        var want = String(root.prefs.selectedPresetSet || "")
        if (want === "") return -1
        var e = _ruleSetEnum()
        for (var i = 0; i < e.entries.length; i += 1) {
            if (ruleSetSelectionKey(i) === want) return i
        }
        return -1
    }

    /// Default pick when the user never chose a set: match the preset's country
    /// code against the system locale's region, then its language. Sets shaped
    /// by the user carry no country, so the heuristic cannot say anything about
    /// them — those default to the first entry.
    function ruleSetPreferredIndex() {
        var arr = _ruleSetEnum().entries
        if (!arr || arr.length === 0) return -1
        // The test is the DATA, not where it was enumerated from: a user who
        // points the folder at the sets shipped with the app still gets the
        // country/language pick, because those entries do carry a country.
        var hasCountry = false
        for (var c = 0; c < arr.length; c += 1) {
            if (String(arr[c].country || "") !== "") { hasCountry = true; break }
        }
        if (!hasCountry) return 0
        var loc = ""
        try { loc = String(Qt.locale().name || "") } catch (e) { loc = "" }
        var parts = loc.toLowerCase().split(/[_-]/)
        var lang = parts.length > 0 ? parts[0] : ""
        var region = parts.length > 1 ? parts[1] : ""
        for (var pass = 0; pass < 2; pass += 1) {
            var want = (pass === 0) ? region : lang
            if (want === "") continue
            for (var i = 0; i < arr.length; i += 1) {
                if (String(arr[i].country || "").toLowerCase() === want) return i
            }
        }
        return 0
    }

    /// Absolute path of `route`'s rules file inside the set at `index`, or ""
    /// when that set has no file for the route (a set with only one of the two
    /// files is normal).
    function ruleSetFilePath(index, route) {
        var e = _ruleSetEnum()
        if (index < 0 || index >= e.entries.length) return ""
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.resolvePresetPath !== "function") {
            return ""
        }
        var cacheKey = String(index) + ":" + String(route)
        if (e.paths[cacheKey] !== undefined) return e.paths[cacheKey]
        var entry = e.entries[index]
        // Shipped sets live at `<cc>/<pack>/`; a user set is either `<set>/` or
        // the folder root itself, so join only the segments that are present.
        var segments = []
        if (String(entry.country || "") !== "") segments.push(String(entry.country))
        if (String(entry.pack || "") !== "") segments.push(String(entry.pack))
        var file = (String(route) === "primary") ? "rules_primary.txt"
                                                 : "rules_secondary.txt"
        var rel = segments.concat([file]).join("/")
        // Empty override = the shipped tree; non-empty = the user's own folder.
        var abs = String(nrrNativeBridge.resolvePresetPath(
            rel, e.userOwned ? e.dir : "") || "")
        e.paths[cacheKey] = abs
        return abs
    }

    /// The set to fall back on when no file path is remembered at all, per the
    /// user's rule: a configured rule-set folder is the ONLY source — sets in
    /// it load, an empty folder loads nothing (we do not silently substitute a
    /// shipped set for someone who told us where their rules live). With no
    /// folder configured we show the set matching the system locale, which is
    /// what a fresh install has always done.
    function defaultRuleSetIndex() {
        var e = _ruleSetEnum()
        if (root.userPresetsDir !== "" && !e.userOwned) return -1
        var idx = ruleSetRememberedIndex()
        if (idx < 0) idx = ruleSetPreferredIndex()
        return idx
    }

    function defaultRuleSetPathFor(route) {
        return ruleSetFilePath(defaultRuleSetIndex(), route)
    }

    /// Index of the rule set `path` belongs to, or -1 for a file outside every
    /// known set (a rules .txt the user opened from somewhere of their own).
    /// Windows paths compare case-insensitively and separator-agnostically.
    function _ruleSetIndexForPath(path) {
        var want = String(path || "").replace(/\\/g, "/").toLowerCase()
        if (want === "") return -1
        var e = _ruleSetEnum()
        for (var i = 0; i < e.entries.length; i += 1) {
            for (var r = 0; r < 2; r += 1) {
                var p = String(ruleSetFilePath(i, r === 0 ? "primary" : "secondary") || "")
                if (p !== "" && p.replace(/\\/g, "/").toLowerCase() === want) return i
            }
        }
        return -1
    }

    /// Make the quick-load dropdown name the set whose rules are actually on
    /// screen. Derived from the loaded path when there is one — a remembered
    /// path is the stronger fact, and without this step the dropdown would go
    /// on showing its default pick while different rules sit below it.
    /// A choice the user made by hand is never overwritten, and a rules file
    /// outside every known set leaves the dropdown alone. With no path
    /// remembered at all this persists NOTHING: the dropdown already shows the
    /// default pick, and freezing that pick into root.prefs recorded a choice the
    /// user never made (it then outlived the hydration and overrode the
    /// folder they configured later).
    function _rememberHydratedRuleSet() {
        if (String(root.prefs.selectedPresetSet || "") !== "") return
        var primary = root._rememberedRulesPathFor("primary")
        var secondary = root._rememberedRulesPathFor("secondary")
        if (primary === "" && secondary === "") return
        var idx = _ruleSetIndexForPath(primary)
        if (idx < 0) idx = _ruleSetIndexForPath(secondary)
        var key = ruleSetSelectionKey(idx)
        if (key === "") return
        root.updatePrefs({ selectedPresetSet: key })
        root.emitPrefs()
    }
}
