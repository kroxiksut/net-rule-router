import QtQuick 2.15
import "../lib/rules.js" as Rules

// Non-visual controller for the POST-CONNECT BACKLOG: one question covering
// everything that was parked while the service was down.
//
// Extracted from Main.qml (thin-shell rule). Rules and routing settings are
// parked by two independent mechanisms, and each used to prompt on its own —
// two modal dialogs a second apart about the same interruption. Both halves are
// collected in parallel here and the dialog opens once both have reported.
//
// The rules half deliberately does NOT apply the parked snapshot: it was
// written once and never refreshed, so it could be older than the table. The
// park is a MARKER ("there is offline rule work"); what gets previewed and
// applied is always the table as it stands against the live service revision.
QtObject {
    id: offlineBacklogCollector

    /// The ApplicationWindow: the dialog, the rules model helpers, the RPC
    /// transport and the parked-settings controller all belong to it.
    property var root

    // ──────────────────────────────────────────────────────────────
    // Post-connect backlog — ONE question for everything parked
    //
    // Rules and routing settings are parked by two independent
    // mechanisms (the rules sidecar, and `root.prefs.routePendingOfflineJson`),
    // and each used to prompt on its own: two modal dialogs a second
    // apart about the same interruption. Both halves are now collected in
    // parallel and the dialog opens only once both have reported.
    //
    // The rules half deliberately does NOT apply the parked snapshot. That
    // snapshot was written once and never refreshed, so it could be older
    // than the table — applying it silently resurrected rules the user had
    // since deleted, and the preview built from it showed nothing while a
    // rule was demonstrably missing. The park is a MARKER ("there is
    // offline rule work"); what gets previewed and applied is always the
    // table as it stands, compared against the live service revision.
    // ──────────────────────────────────────────────────────────────

    /// Both halves of one collect run: `{ rulesReady, rules, settingsReady,
    /// settingsRows }`. Non-null only while a run is in flight — the runs are
    /// idempotent and several triggers (cold start, reconnect) can coincide.
    property var _offlineBacklogRun: null

    /// One-shot: the rules half is already being applied by a review the user
    /// triggered from the "service not running" gate, so the collector must
    /// not ask about it a second time. Settings are unaffected.
    property bool _offlineRulesHandledByResume: false

    /// Ask for a post-connect backlog collect. Public because the first-run
    /// wizard has to re-arm it: the collect it skipped while the wizard was up
    /// is the one carrying the protections chosen IN that wizard.
    function scheduleOfflineBacklogCollect() {
        if (((backendStatus || {}).kind) !== "connected") return
        root._offlineBacklogCollectTimer.restart()
    }

    function _startOfflineBacklogCollect() {
        // Don't stack a modal over the first-launch wizards — come back once
        // it is answered rather than dropping the parked work.
        if (!root.prefs.firstRunCompleted) { root._offlineBacklogCollectTimer.restart(); return }
        if (root.offlinePendingController._offlinePendingDialogActive) return
        if (_offlineBacklogRun !== null) return
        if (!root._routingBackendConnected()) return
        // A table caught mid-repopulate would diff as "rules removed".
        if (root.rulesBulkLoading === true) { root._offlineBacklogCollectTimer.restart(); return }
        _offlineBacklogRun = {
            rulesReady: false, rules: null, settingsReady: false, settingsRows: []
        }
        root.offlinePendingController._offlinePendingDialogActive = true
        _collectOfflineRulesBacklog(function(rules) {
            if (!_offlineBacklogRun) return
            _offlineBacklogRun.rules = rules
            _offlineBacklogRun.rulesReady = true
            _settleOfflineBacklogCollect()
        })
        root.offlinePendingController.collectSettingsBacklog(function(rows) {
            if (!_offlineBacklogRun) return
            _offlineBacklogRun.settingsRows = rows || []
            _offlineBacklogRun.settingsReady = true
            _settleOfflineBacklogCollect()
        })
    }

    function _settleOfflineBacklogCollect() {
        var run = _offlineBacklogRun
        if (!run || !run.rulesReady || !run.settingsReady) return
        _offlineBacklogRun = null
        var hasRules = run.rules !== null
        var hasSettings = run.settingsRows.length > 0
        if (!hasRules && !hasSettings) {
            root.offlinePendingController._offlinePendingDialogActive = false
            return
        }
        // Settings reconcile without a click whenever the service accepts
        // them: the parked keys are per-SID and need no elevation in the
        // common case. Only a refusal surfaces the dialog, through
        // `_applyOfflinePending`'s own fallback.
        //
        // They go through even when rules are ALSO pending. Bundling them into
        // the rules dialog made a protection the user switched on in the wizard
        // wait for an answer about something else — that is how a kill-switch
        // chosen before the service existed stayed off in the service for ten
        // minutes while the additional link was already down.
        if (!hasRules) {
            root.offlinePendingController._applyOfflinePending(run.settingsRows)
            return
        }
        _showOfflineBacklogDialog(run.rules, [])
        // No fallback rows: a refusal must not paint a second dialog over the
        // one just opened. The keys stay parked and the next collect re-offers.
        if (hasSettings) root.offlinePendingController._applyOfflinePending(null)
    }

    /// Open the shared post-connect dialog. `rules` is `{added, removed}` or a
    /// falsy value when only settings are pending (the fallback entry used by
    /// `_applyOfflinePending`).
    function _showOfflineBacklogDialog(rules, settingsRows) {
        root.offlinePendingController._offlinePendingDialogActive = true
        root.offlineBacklogDialog.rulesPending = !!rules
        root.offlineBacklogDialog.rulesAdded = rules ? parseInt(rules.added || 0) : 0
        root.offlineBacklogDialog.rulesRemoved = rules ? parseInt(rules.removed || 0) : 0
        root.offlineBacklogDialog.settingsRows = settingsRows || []
        root.offlineBacklogDialog.open()
    }

    /// Rules half: is there offline rule work, and how much? `done(null)` when
    /// there is nothing to offer — including when a marker exists but the
    /// table already matches the service, in which case the stale marker is
    /// dropped so it can never resurface.
    function _collectOfflineRulesBacklog(done) {
        var finish = function(v) { if (typeof done === "function") done(v || null) }
        // A review the user already triggered is answering this exact
        // question; it clears the flag when it settles.
        if (_offlineRulesHandledByResume) { finish(null); return }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarPendingApplyRead !== "function") {
            finish(null)
            return
        }
        var corr = nrrNativeBridge.rpcSidecarPendingApplyRead()
        // A dropped correlation id never gets a callback, so the collector
        // would wait for a reply that cannot arrive.
        if (!corr || String(corr) === "") { finish(null); return }
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            var entry = ok && p && p.entry
            // No marker and no in-flight offline import: any divergence left
            // is the drift banner's business, not a modal on every connect.
            if (!entry && !root._offlineRulesPendingPush) { finish(null); return }
            _diffRulesAgainstService(function(counts) {
                if (!counts || (counts.added === 0 && counts.removed === 0)) {
                    if (entry) _clearPendingApplyPark()
                    finish(null)
                    return
                }
                finish(counts)
            })
        })
    }

    /// `{added, removed}` for the CURRENT table against the service's live
    /// revision, or `null` when the service cannot be read.
    function _diffRulesAgainstService(done) {
        var finish = function(v) { if (typeof done === "function") done(v || null) }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcRulesList !== "function") {
            finish(null)
            return
        }
        var corr = nrrNativeBridge.rpcRulesList()
        if (!corr || String(corr) === "") { finish(null); return }
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok || !p) { finish(null); return }
            var serviceRows = (p.rows || []).map(Rules.driftRowFromServiceWire)
            finish(Rules.diffRuleRowCounts(
                root._rulesModelToRowArray(), serviceRows, root._aceEncodeHost))
        })
    }

    /// Clear the sidecar pending-apply marker (best-effort). Shared by the
    /// dialog's Discard action and the obsolete-marker auto-drop.
    function _clearPendingApplyPark() {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarPendingApplyClear !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSidecarPendingApplyClear()
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("pending-apply.clear failed:", code, msg)
        })
    }
}
