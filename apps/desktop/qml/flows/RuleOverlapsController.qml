import QtQuick 2.15
import "../lib/pure.js" as Pure

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
    /// Address conflicts in the applied rules, from the service snapshot.
    readonly property var conflicts: root && root.uiRevision >= 0
        ? (root.routingState.ruleConflicts || []) : []

    readonly property int pendingCount: root && root.uiRevision >= 0 ? _pending().length : 0

    /// Ids of rules saved from the rule dialog since the last fresh pass.
    property var _ownEdits: []

    /// A rule saved from the rule dialog: the exceptions it makes are settled
    /// by the next pass that has read it.
    function noteOwnEdit(ruleId) {
        var id = String(ruleId || "")
        if (id !== "" && _ownEdits.indexOf(id) < 0) _ownEdits = _ownEdits.concat([id])
    }

    /// `fresh` is false for a pass that read the rules before a later edit; it
    /// must not settle that edit's pairs, which it may not have seen.
    function update(list, fresh) {
        overlaps = list || []
        if (fresh === false || _ownEdits.length === 0) return
        var settled = Pure.overlapsConfirmedByOwnEdit(overlaps, _ownEdits)
        _ownEdits = []
        if (settled.length > 0) _storeConfirmed(_confirmedKeys().concat(settled))
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
    /// bucket but is not a route. `candidate` ({id, route}) is a rule still in
    /// the dialog, not in the table yet.
    function routeOf(side, candidate) {
        if (candidate && String(side["rule-id"]) === String(candidate.id))
            return String(candidate.route)
        var at = rowIndexOf(side)
        return at >= 0 ? String(root.rulesModel.get(at).targetRoute) : String(side.route)
    }

    function describe(side) {
        var type = String(side["rule-type"])
        var value = String(side.value)
        // Both name kinds are a "Domain" rule in the rules list.
        var typeLabel = root.ruleTypeLabel(
            type === "exact-fqdn" || type === "suffix-domain" ? "domain" : type)
        return root.tr("rules.overlaps.rule", "{value} ({type})")
            .replace("{value}", type === "suffix-domain" ? "*." + value : value)
            .replace("{type}", typeLabel)
    }
    function routeText(side, candidate) {
        return root.routeLabel(routeOf(side, candidate))
    }
    function mainStaysText() {
        return root.tr("rules.overlaps.main-stays",
            "Addresses of the main link inside this network stay on the main link even when the additional link is down. Leak protection does not block them.")
    }
    /// One pair as a sentence: the overlaps table reads it to a screen reader,
    /// the rule dialog shows it before the rule is saved.
    function explain(overlap, candidate) {
        var sentence = overlap["block-wins-tie"] === true
            ? root.tr("rules.overlaps.block-tie",
                "{winner} names the same sites as {loser} on {loser-route}. They are blocked: on a tie a block wins over a route.")
            : String(overlap.kind) === "duplicate"
            ? root.tr("rules.overlaps.duplicate",
                "{winner} is set on both routes. It goes over {winner-route}: on a tie the main route wins.")
            : String(overlap.kind) === "intersecting"
            ? root.tr("rules.overlaps.intersecting",
                "{winner} and {loser} on {loser-route} share some addresses. Each shared address takes the narrower rule; most of them go over {winner-route}.")
            : root.tr("rules.overlaps.nested",
                "{winner} goes over {winner-route}: it is narrower than {loser} on {loser-route}.")
        sentence = sentence
            .replace("{winner}", describe(overlap.winner))
            .replace("{loser}", describe(overlap.loser))
            .replace("{winner-route}", routeText(overlap.winner, candidate))
            .replace("{loser-route}", routeText(overlap.loser, candidate))
        return overlap["main-stays-when-additional-down"] === true
            ? sentence + " " + mainStaysText() : sentence
    }
    /// Offering "send over the other route" only makes sense between two
    /// routing rules (a `?` rule is one); a block on either side is edited in
    /// the rules list.
    function canReroute(overlap) {
        return _isPlainRoute(routeOf(overlap.winner)) && _isPlainRoute(routeOf(overlap.loser))
    }
    function _isPlainRoute(route) { return route === "primary" || route === "secondary" }

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
