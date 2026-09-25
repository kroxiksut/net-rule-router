import QtQuick 2.15

// Non-visual controller for OVERLAPS: rules of the two routes that claim the
// same hosts. The narrower rule already wins; this screen lets the user see
// which one and confirm it, or send those hosts over the other route.
//
// The pairs and their winners come from Rust (`find_route_overlaps`, through
// `local.rules-overlaps`) over the rules on screen, so an edit shows here
// before it is applied. Every change is an ordinary edit of the rules list,
// applied through the usual review.
QtObject {
    id: ruleOverlapsController

    property var root

    /// Pairs from the last `local.rules-overlaps` pass.
    property var overlaps: []

    readonly property int pendingCount: root && root.uiRevision >= 0 ? _pending().length : 0

    function update(list) {
        overlaps = list || []
    }

    function _confirmedKeys() {
        var raw = String((root && root.prefs && root.prefs.routeOverlapsConfirmedSig) || "")
        return raw === "" ? [] : raw.split("|")
    }
    function isConfirmed(overlap) {
        return !!overlap && _confirmedKeys().indexOf(String(overlap.key)) >= 0
    }
    function pending() { return _pending() }
    function _pending() {
        var out = []
        for (var i = 0; i < overlaps.length; i += 1) {
            if (!isConfirmed(overlaps[i])) out.push(overlaps[i])
        }
        return out
    }

    /// Unconfirmed first, then confirmed, each in the detector's order.
    function ordered() {
        var confirmed = []
        for (var i = 0; i < overlaps.length; i += 1) {
            if (isConfirmed(overlaps[i])) confirmed.push(overlaps[i])
        }
        return _pending().concat(confirmed)
    }

    /// Only keys of pairs that still exist are kept, so the stored list
    /// cannot grow past the rules it describes.
    function _storeConfirmed(keys) {
        var live = {}
        for (var i = 0; i < overlaps.length; i += 1) live[String(overlaps[i].key)] = true
        var kept = []
        for (var k = 0; k < keys.length; k += 1) {
            if (live[keys[k]] && kept.indexOf(keys[k]) < 0) kept.push(keys[k])
        }
        root.commitPrefs({ routeOverlapsConfirmedSig: kept.join("|") })
    }
    function confirm(overlap) {
        _storeConfirmed(_confirmedKeys().concat([String(overlap.key)]))
    }
    function confirmAll() {
        var keys = _confirmedKeys()
        for (var i = 0; i < overlaps.length; i += 1) keys.push(String(overlaps[i].key))
        _storeConfirmed(keys)
    }
    function unconfirm(overlap) {
        var keys = _confirmedKeys()
        var at = keys.indexOf(String(overlap.key))
        if (at >= 0) keys.splice(at, 1)
        _storeConfirmed(keys)
    }

    /// Index in `rulesModel` of one side of a pair; -1 when the table moved on.
    function rowIndexOf(side) {
        if (!side) return -1
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            var row = root.rulesModel.get(i)
            var bucket = String(row.targetRoute) === "primary" ? "primary" : "secondary"
            if (bucket === String(side.route) && String(row.id || "") === String(side["rule-id"]))
                return i
        }
        return -1
    }
    /// The route as the table names it: a block rule sits in the secondary
    /// bucket but is not a route.
    function routeOf(side) {
        var at = rowIndexOf(side)
        return at >= 0 ? String(root.rulesModel.get(at).targetRoute) : String(side.route)
    }
    /// Offering "send over the other route" only makes sense between two
    /// routing rules; a block on either side is edited in the rules list.
    function canReroute(overlap) {
        return routeOf(overlap.winner) !== "block" && routeOf(overlap.loser) !== "block"
    }

    /// Send the shared hosts over the loser's route. A nested winner moves to
    /// that route; of a duplicate the winning copy is switched off, which is
    /// what the review dialog does for the same pair.
    function sendOverLoserRoute(overlap) {
        var at = rowIndexOf(overlap.winner)
        if (at < 0) return
        if (String(overlap.kind) === "duplicate")
            root.rulesModel.setProperty(at, "enabled", false)
        else
            root.rulesModel.setProperty(at, "targetRoute", String(overlap.loser.route))
        root.rulesModelEdited()
        root._recomputeRulesDirty()
        root.statusLine = root.tr("rules.preview-notice",
            "Rule changes take effect only after you review and apply them.")
        root.refreshRulesOverlaps()
    }

    function open() {
        root.requestSectionChange("rule-overlaps")
        root.refreshRulesOverlaps()
    }
}
