import QtQuick 2.15
import "../lib/pure.js" as Pure

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
    /// How many the list shows by default, as the service counts them — drives
    /// the sidebar badges. Never re-counted here: a second rule would drift.
    property int autoRuleCandidatesPending: 0
    property bool _autoRuleFetchInFlight: false
    /// The last list read failed: an empty list then means "unknown", not "nothing".
    property bool autoRuleLoadFailed: false
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

    /// An announcing push waiting for the list to hold its offer.
    property var _announceOwed: null

    /// Raise the stripe for an announcing push. Until the list holds the offer
    /// what it is about is unknown, so the stripe waits for the re-read rather
    /// than call a site that does not open a site's companions.
    function announce(event, eventId) {
        var anchor = String((event || {})["top-anchor"] || "")
        var held = (autoRuleCandidates || []).some(function(r) {
            return String((r || {}).anchor || "") === anchor
        })
        if (anchor !== "" && !held && root.bridgeAvailable) {
            _announceOwed = { "event": event, "eventId": eventId }
            refreshAutoRuleCandidates()
            return
        }
        _raiseAnnouncement(anchor, eventId)
    }

    function _raiseAnnouncement(anchor, eventId) {
        // Keyed on the push, not on a constant: dismissing writes to the
        // ledger, and one fixed id would retire the banner for the life of the
        // install. Only one is on screen at a time — the newer supersedes.
        root.notificationsController._dropPushNotice(_autoRuleNoticeId)
        _autoRuleNoticeId = "auto-rule-candidates:" + String(eventId || "")
        var told = announcementText(anchor, autoRuleCandidatesPending)
        root.notificationsController._addPushNotice({
            "id": _autoRuleNoticeId,
            "severity": "info",
            "dismissible": true,
            "kind": "suggestions-changed",
            // News of companions retires itself; a site that does not open is
            // a question and stays until answered.
            "autoDismissMs": told.sitesBlocked ? 0 : 5000,
            "muteKind": "suggestions-changed",
            "title": told.title,
            "body": told.body,
            "actionKey": "open-auto-rule-suggestions",
            "actionText": root.tr("rules.suggestions.open", "Review")
        })
    }

    /// What an announcing push says. A site that did not open over the main
    /// route is named as one, as the terminal UI and the tray name it; any
    /// other offer keeps the companions' count.
    function announcementText(topAnchor, count) {
        var anchor = String(topAnchor || "")
        var rows = Pure.autoRuleRowsShownByDefault(autoRuleCandidates || []).filter(function(r) {
            return anchor !== "" && String((r || {}).anchor || "") === anchor
        })
        if (anchor !== "" && Pure.autoRuleNoticeKind(rows) === "sites-blocked") {
            return {
                "sitesBlocked": true,
                "title": root.tr("tray.auto-rules.title-blocked", "Sites the main route will not carry"),
                "body": root.tr("tray.auto-rules.body-blocked",
                        "Connections to {name} keep failing on the main route.")
                    .replace("{name}", Pure.displayText(anchor))
            }
        }
        return {
            "sitesBlocked": false,
            "title": root.tr("notifications.auto-rule-candidates.title", "Addresses waiting to be added"),
            "body": root.tr("notifications.auto-rule-candidates.body",
                    "The service found {count} addresses the sites you routed need.")
                .replace("{count}", String(count))
        }
    }

    function refreshAutoRuleCandidates() {
        if (!root.bridgeAvailable || _autoRuleFetchInFlight) return
        var corr = root.rpc.rpcAutoRuleCandidatesList()
        if (!corr || corr === "") return
        _autoRuleFetchInFlight = true
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            autoRuleSuggestionsController._autoRuleFetchInFlight = false
            if (!ok || !payload) {
                console.log("auto-rule candidates fetch failed:", code, msg)
                autoRuleSuggestionsController.autoRuleLoadFailed = true
                autoRuleSuggestionsController._tellOwedAnnouncement()
                return
            }
            autoRuleSuggestionsController.autoRuleLoadFailed = false
            var list = payload.candidates || payload["candidates"] || []
            autoRuleSuggestionsController.autoRuleCandidates = list
            autoRuleSuggestionsController.autoRuleCandidatesPending = Number(payload["pending-count"] || 0)
            // A notice promising addresses the list no longer holds goes too.
            if (autoRuleSuggestionsController.autoRuleCandidatesPending <= 0)
                root.notificationsController._dropPushNotice(autoRuleSuggestionsController._autoRuleNoticeId)
            // Why the list is empty, when it is: companions the service saw but
            // did not offer because they already travel the same route.
            autoRuleSuggestionsController.autoRuleInertDropped = Number(payload["inert-dropped"] || 0)
            autoRuleSuggestionsController.autoRuleInertSample = payload["inert-sample"] || []
            autoRuleSuggestionsController._tellOwedAnnouncement()
        })
    }

    /// The announcement that waited for this read; a failed read tells it with
    /// what is known rather than lose it.
    function _tellOwedAnnouncement() {
        var owed = _announceOwed
        _announceOwed = null
        if (owed === null || autoRuleCandidatesPending <= 0) return
        _raiseAnnouncement(String((owed.event || {})["top-anchor"] || ""), owed.eventId)
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

    /// The service could not re-open the page the suggestion came from, so the
    /// user has to reload it for the new route to show.
    property bool autoRuleReloadHint: false

    /// `asAnyZone` takes each offer that names a site in another zone as that
    /// site in every zone (`site.*`) instead of the one name offered.
    function acceptAutoRuleCandidates(ids, asAnyZone) {
        if (!ids || ids.length === 0 || !root.bridgeAvailable) return
        var corr = root.rpc.rpcAutoRuleCandidatesAccept(
            { "ids": ids, "as-any-zone": asAnyZone === true })
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule accept failed:", code, msg)
                return
            }
            autoRuleSuggestionsController.autoRuleReloadHint = !!(p && p["anchor-skipped"] === true)
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
    /// The list is re-read either way: a zero count can still leave rows the
    /// main route handles, listed behind their toggle.
    function _noteAutoRulePending(payload) {
        var left = (payload || {}).pending
        if (left === undefined) left = (payload || {})["pending"]
        if (left === undefined) return
        autoRuleCandidatesPending = Number(left)
        if (autoRuleCandidatesPending <= 0)
            root.notificationsController._dropPushNotice(_autoRuleNoticeId)
        refreshAutoRuleCandidates()
    }

    /// Id of the failure notice currently shown per service operation, so a
    /// repeated press replaces its own notice instead of stacking five.
}
