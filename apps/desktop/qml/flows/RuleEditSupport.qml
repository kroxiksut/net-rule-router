import QtQuick 2.15
import "../components"
import "../lib/rules.js" as Rules

// The bridge-facing half of the add/edit rule form: type labels, what a saved
// form becomes, the overlap preview and the comment sidecar. The main window
// and the tray's add-rule window both host `RuleEditDialog`, and each holds one
// of these, so the two forms cannot drift apart. Pure parts live in
// `lib/rules.js`.
QtObject {
    id: support

    /// The window hosting the dialog; supplies `tr(key, fallback)`.
    property var host: null
    /// The host's language: a change drops the cached type labels.
    property string language: ""
    /// RpcTransport instance.
    property var rpc: null
    /// ACE codec; a host that already has one passes it in.
    property var aceCodec: HostAceCodec {}

    /// The rules could not be serialized; the host says so where it reports.
    signal serializeFailed()

    // `ruleTypeLabel` runs once per row on every rules-table sort pass.
    property var _labelCache: ({})
    onLanguageChanged: _labelCache = ({})

    readonly property bool _bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null

    function ruleTypeLabel(id) {
        var slug = String(id)
        var cached = _labelCache[slug]
        if (cached !== undefined) return cached
        var label = host.tr("rules.type." + slug, slug)
        _labelCache[slug] = label
        return label
    }

    /// The type as a picker offers it: its name with a plain explanation.
    function ruleTypeChoiceLabel(id) {
        var slug = String(id)
        return host.tr("rules.type-explained." + slug, ruleTypeLabel(slug))
    }

    /// Lowercase ACE form kept beside a row's value, so the table search
    /// matches either spelling without a bridge call per keystroke.
    function aceLowerForSearch(value) {
        return aceCodec.encode(value).toLowerCase()
    }

    function serviceRowToModelRow(w) {
        return Rules.serviceRuleRowToModelRow(w, ruleTypeLabel, aceCodec.decode,
            aceLowerForSearch)
    }

    /// The table row for form fields `f` (see `Rules.ruleRowFromForm`).
    function ruleRowFromForm(f, id) {
        return Rules.ruleRowFromForm(f, id, {
            ruleTypeLabel: ruleTypeLabel,
            punycodeHint: aceCodec.hint,
            aceLowerForSearch: aceLowerForSearch
        })
    }

    /// The table row a saved `dialog` (a `RuleEditDialog`) stands for.
    function ruleRowFromDialog(dialog, id) {
        return ruleRowFromForm({
            ruleType: dialog.localRuleType,
            value: dialog.localValue,
            route: dialog.localRoute,
            verify: dialog.localVerify,
            comment: dialog.localComment,
            enabled: dialog.localEnabled
        }, id)
    }

    /// Route overlaps the rule still in the dialog would take part in, against
    /// `rows` with that rule in place of row `index` (appended when negative).
    /// `done(pairs, candidate)` is not called when the bridge is out.
    function candidateRouteOverlaps(rows, index, row, includeSubdomains, done) {
        if (!_bridgeReady || !rpc || typeof nrrNativeBridge.rpcRulesOverlaps !== "function") return
        var rulesJson = ""
        try {
            rulesJson = Rules.buildRulesJson(Rules.rowsWithCandidate(rows, index, row),
                aceCodec.encode)
        } catch (err) {
            // A value the wire refuses has no overlaps to show; the dialog's
            // verdict already says why.
            if (Rules.wireRefusalCode(err) !== "") return
            console.error("rule overlap preview: rules serialization failed:", err)
            serializeFailed()
            return
        }
        if (!rulesJson) return
        var candidate = { id: String(row.id), route: String(row.targetRoute) }
        var corr = nrrNativeBridge.rpcRulesOverlaps(rulesJson, includeSubdomains)
        rpc.registerRpcCallback(corr, function(ok, payload) {
            done(Rules.overlapsOfRule((ok && payload && payload["route-overlaps"]) || [],
                candidate.id), candidate)
        })
    }

    /// Best-effort write of one row's comment into the sidecar; an empty one
    /// deletes it. Comments are decoration: a failure is logged, never shown.
    /// `answered`, when given, runs once the write has answered or was skipped.
    function writeComment(row, answered) {
        var done = (typeof answered === "function") ? answered : function() {}
        if (!_bridgeReady || !rpc
                || typeof nrrNativeBridge.rpcSidecarCommentWrite !== "function") {
            done()
            return
        }
        var p = Rules.sidecarRuleSignatureParts(row)
        if (p.type === "" || p.value === "" || p.route === "") {
            done()
            return
        }
        var corr = nrrNativeBridge.rpcSidecarCommentWrite(
            p.type, p.value, p.route, String((row && row.comment) || ""))
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.log("sidecar.comment.write failed:", code, msg)
            done()
        })
    }
}
