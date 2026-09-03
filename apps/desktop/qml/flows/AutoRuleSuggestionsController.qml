import QtQuick 2.15

// Non-visual controller for SUGGESTED ADDRESSES: the destinations the service
// parked because a routed site appears to need them.
//
// Extracted from Main.qml (thin-shell rule). The tray asks about them; this
// window is where the ones nobody answered can still be turned into rules, and
// the screen that shows them (`RuleSuggestionsSection.qml`) merges them with
// the dismissed history into one table. The list is deliberately re-fetched on
// every navigation — a list cached before the user browsed on would offer
// addresses the service has since dropped.
QtObject {
    id: autoRuleSuggestionsController

    /// The ApplicationWindow: the RPC transport, the notice stack and the
    /// section router belong to it.
    property var root

    // ── Suggested addresses ──────────────────────────────────────────────────
    //
    // The service parks addresses a routed site appears to need. The tray asks
    // about them; this window is where the ones nobody answered can still be
    // turned into rules. Lives as a section (`RuleSuggestionsSection.qml`,
    // sidebar → Rules → Suggested addresses) rather than a dialog, merged with
    // the dismissed-suggestions history into one table.

    /// Wire rows from the last `autorules.candidates.list`.
    property var autoRuleCandidates: []
    /// How many the service is holding — drives the chip in the Rules header.
    property int autoRuleCandidatesPending: 0
    property bool _autoRuleFetchInFlight: false
    /// Id of the banner currently on screen, so a newer push can replace it.
    property string _autoRuleNoticeId: ""
    /// Id of the on-screen "same rule on both routes" stripe, so a newer
    /// count supersedes the older one instead of stacking.
    property string _ruleDuplicateNoticeId: ""
    /// Id of the "a new application rule is still learning" stripe.
    property string _appRuleLearningNoticeId: ""

    /// Companions the last service pass declined to offer, and a few of their
    /// names — the suggestions screen turns them into a reason for an empty
    /// list. Zero means the pass had nothing to drop either.
    property int autoRuleInertDropped: 0
    property var autoRuleInertSample: []

    function refreshAutoRuleCandidates() {
        if (!root.bridgeAvailable || _autoRuleFetchInFlight) return
        var corr = root.rpc.rpcAutoRuleCandidatesList()
        if (!corr || corr === "") return
        _autoRuleFetchInFlight = true
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            autoRuleSuggestionsController._autoRuleFetchInFlight = false
            if (!ok || !payload) {
                console.log("auto-rule candidates fetch failed:", code, msg)
                return
            }
            var list = payload.candidates || payload["candidates"] || []
            autoRuleSuggestionsController.autoRuleCandidates = list
            autoRuleSuggestionsController.autoRuleCandidatesPending = list.length
            // Why the list is empty, when it is: companions the service saw but
            // did not offer because they already travel the same route.
            autoRuleSuggestionsController.autoRuleInertDropped = Number(payload["inert-dropped"] || 0)
            autoRuleSuggestionsController.autoRuleInertSample = payload["inert-sample"] || []
        })
    }

    /// Navigate to the suggestions section with whatever the service holds
    /// RIGHT NOW — a list cached before the user browsed on would offer
    /// stale addresses.
    function openAutoRuleSuggestions() {
        root.requestSectionChange("rule-suggestions")
        if (root.bridgeAvailable) {
            refreshAutoRuleCandidates()
            refreshAutoRuleDismissed()
        }
    }

    function acceptAutoRuleCandidates(ids) {
        if (!ids || ids.length === 0 || !root.bridgeAvailable) return
        var corr = root.rpc.rpcAutoRuleCandidatesAccept({ "ids": ids })
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule accept failed:", code, msg)
                return
            }
            autoRuleSuggestionsController._noteAutoRulePending(p)
        })
    }

    function dismissAutoRuleCandidates(ids) {
        if (!ids || ids.length === 0 || !root.bridgeAvailable) return
        var corr = root.rpc.rpcAutoRuleCandidatesDismiss({ "ids": ids })
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule dismiss failed:", code, msg)
                return
            }
            autoRuleSuggestionsController._noteAutoRulePending(p)
        })
    }

    /// Rows from the last `autorules.dismissed.list`.
    property var autoRuleDismissed: []

    function refreshAutoRuleDismissed() {
        if (!root.bridgeAvailable) return
        var corr = root.rpc.rpcAutoRuleDismissedList()
        if (!corr || corr === "") return
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok || !payload) {
                console.log("auto-rule dismissed fetch failed:", code, msg)
                return
            }
            autoRuleSuggestionsController.autoRuleDismissed = payload.dismissed || payload["dismissed"] || []
        })
    }

    /// Lifts a refusal and puts the offer back on the pending list, so both
    /// lists are re-read: the row moves from declined to waiting.
    function restoreAutoRuleDismissed(ids) {
        if (!ids || ids.length === 0 || !root.bridgeAvailable) return
        var corr = root.rpc.rpcAutoRuleDismissedRestore({ "ids": ids })
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule restore failed:", code, msg)
                return
            }
            autoRuleSuggestionsController.refreshAutoRuleDismissed()
            autoRuleSuggestionsController.refreshAutoRuleCandidates()
        })
    }

    /// Erases the service's memory of these suggestions entirely, so the host
    /// is offered again from scratch. Both lists are re-read — the row can be
    /// leaving either one.
    function forgetAutoRuleCandidates(ids) {
        if (!ids || ids.length === 0 || !root.bridgeAvailable) return
        var corr = root.rpc.rpcAutoRuleCandidatesForget({ "ids": ids })
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule forget failed:", code, msg)
                return
            }
            autoRuleSuggestionsController.refreshAutoRuleDismissed()
            autoRuleSuggestionsController._noteAutoRulePending(p)
        })
    }

    /// The answer says what is left; take the banner down once nothing is.
    function _noteAutoRulePending(payload) {
        var left = (payload || {}).pending
        if (left === undefined) left = (payload || {})["pending"]
        if (left === undefined) return
        autoRuleCandidatesPending = Number(left)
        if (autoRuleCandidatesPending <= 0) {
            autoRuleCandidates = []
            root.notificationsController._dropPushNotice(_autoRuleNoticeId)
        } else {
            refreshAutoRuleCandidates()
        }
    }

    /// Id of the failure notice currently shown per service operation, so a
    /// repeated press replaces its own notice instead of stacking five.
}
