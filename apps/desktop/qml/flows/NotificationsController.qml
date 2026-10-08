import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller for PUSH-DRIVEN NOTICES: the stack of messages the
// service raises, what each one offers to do, and when it expires.
//
// Extracted from Main.qml (thin-shell rule). The push DISPATCHER stays in the
// shell — routing an event to the right handler is shell business — and what
// moved here is everything downstream of it: composing a notice, retiring it,
// and running the action a notice offers.
//
// The window keeps its own copy of these notices even though the tray owns
// them in the general case: a tray that never started, was killed, or had
// notifications turned off would otherwise swallow the message entirely. Both
// copies carry the SAME id, and `NotificationLedger` guarantees that answering
// one retires the other.
QtObject {
    id: notificationsController

    /// The ApplicationWindow: the notice ledger, the section router and the
    /// preferences all belong to it.
    property var root

    // ── Push-driven notices ──────────────────────────────────────────────────
    //
    // The tray is the surface that can speak while this window is closed, so it
    // owns these notices in the general case. The window keeps its own copy as
    // insurance: a tray that never started, was killed, or had notifications
    // turned off would otherwise swallow the message entirely. Both copies
    // carry the SAME id, and `NotificationLedger` guarantees that answering one
    // retires the other.
    property var _pushNotices: []

    /// `false` when the user silenced this kind of notice on its own. The
    /// master switch is checked by the surfaces that raise OS notifications;
    /// this is the per-kind layer under it.
    function noticeKindEnabled(kind) {
        if (String(kind || "") === "suggestions-changed")
            return root.prefs.notifySuggestionChanges !== false
        if (String(kind || "") === "block-notice")
            return root.prefs.notifyBlockNotices !== false
        if (String(kind || "") === "rule-duplicates")
            return root.prefs.notifyRuleDuplicates !== false
        return true
    }

    /// Silences one kind for good — the "don't show these again" affordance on
    /// the notice itself, so the user never has to find the setting to stop a
    /// stripe that is bothering them right now.
    function muteNoticeKind(kind) {
        var k = String(kind || "")
        if (k === "suggestions-changed") {
            root.commitPrefs({ notifySuggestionChanges: false })
        } else if (k === "block-notice") {
            root.commitPrefs({ notifyBlockNotices: false })
        } else if (k === "rule-duplicates") {
            root.commitPrefs({ notifyRuleDuplicates: false })
        }
    }

    /// "Don't show…" on a card: the same service-kept mute the tray writes, so
    /// both surfaces and the Settings list agree. `choice` is a chooser answer
    /// (`Pure.NOTICE_MUTE_CHOICES_MS`).
    function muteNoticeFor(noticeKind, choice, notificationId) {
        var req = Pure.noticeMuteRequest(noticeKind, choice, Date.now())
        if (req === null || !root.bridgeAvailable || !root.rpc
                || typeof root.rpc.rpcBlockNoticeMutesSet !== "function") return
        var corr = root.rpc.rpcBlockNoticeMutesSet(req)
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("settings.block-notices.add.failed",
                    "Could not add the mute: ") + root.ipcErrorLabel(code)
                return
            }
            notificationsController.dismissNotification(notificationId)
        })
    }

    /// `_addPushNotice` for a kind the tray offers "Don't show…" on. The service
    /// keeps that answer per user; it is read afresh because the tray writes it
    /// and nothing tells this window. `stillWanted` re-checks after the read,
    /// for a notice the next push may already have taken back.
    function _addPushNoticeUnlessMuted(noticeKind, notice, stillWanted) {
        var admit = function(mutes) {
            if (Pure.noticeKindMuted(mutes, noticeKind, Date.now())) return
            if (stillWanted && !stillWanted()) return
            notificationsController._addPushNotice(notice)
        }
        var corr = (root.bridgeAvailable && root.rpc
                && typeof root.rpc.rpcBlockNoticeMutesList === "function")
            ? root.rpc.rpcBlockNoticeMutesList() : ""
        if (!corr || corr === "") {
            admit([])
            return
        }
        root.rpc.registerRpcCallback(corr, function(ok, p) {
            admit(ok && p ? (p.mutes || []) : [])
        })
    }

    function _addPushNotice(notice) {
        if (!notice || String(notice.id || "") === "") return
        if (!noticeKindEnabled(notice.kind)) return
        // `refractoryMs` is for notices whose id carries a counter the SERVICE
        // restarts (the push id): a permanent record of one silences the id's
        // next incarnation, which is a different event entirely.
        var refractory = Number(notice.refractoryMs || 0)
        if (refractory > 0) {
            var answeredAt = root.noticeLedger.decidedAt(String(notice.id))
            if (answeredAt > 0 && (Date.now() - answeredAt) < refractory) return
        } else if (root.noticeLedger.isDecided(String(notice.id))) {
            return
        }
        for (var i = 0; i < _pushNotices.length; i += 1) {
            if (_pushNotices[i].id === notice.id) return
        }
        var entry = notice
        var ttl = Number(notice.autoDismissMs || 0)
        // A notice that carries no decision must not sit over the user's work
        // until it is clicked. Expiry is NOT an answer: nothing goes into the
        // ledger, so a surface that shows the same event can still offer it.
        if (ttl > 0) entry = Object.assign({}, notice, { "expiresAt": Date.now() + ttl })
        _pushNotices = _pushNotices.concat([entry])
    }

    property var _serviceFailureNoticeIds: ({})

    /// Surface a failed service operation where the user cannot miss it.
    ///
    /// The id carries a timestamp: the notice ledger silences an id for good
    /// once answered, and "the stop failed" is a NEW event every time it
    /// happens, not the same one returning.
    function _noteServiceOperationFailed(operation, errorMessage) {
        var op = String(operation || "")
        var previous = String(_serviceFailureNoticeIds[op] || "")
        if (previous !== "") _dropPushNotice(previous)
        var id = "service-op-failed:" + op + ":" + String(Date.now())
        var ids = _serviceFailureNoticeIds
        ids[op] = id
        _serviceFailureNoticeIds = ids
        var reason = String(errorMessage || "").trim()
        var body = root.tr("notifications.service-operation-failed.body",
            "The service did not carry out this action, so nothing changed. Open Settings to try again, or check the logs for the reason.")
        if (reason !== "") body += " (" + reason + ")"
        _addPushNotice({
            "id": id,
            "kind": "service-control",
            "severity": "warning",
            "dismissible": true,
            "title": root.tr("notifications.service-operation-failed.title",
                "Service action failed: {operation}").replace("{operation}", op),
            "body": body,
            "actionKey": "open-routing-settings",
            "actionText": root.tr("action.open-settings",
                "Open settings")
        })
    }

    function _expirePushNotices() {
        var now = Date.now()
        var kept = []
        for (var i = 0; i < _pushNotices.length; i += 1) {
            var n = _pushNotices[i]
            if (Number(n.expiresAt || 0) > 0 && Number(n.expiresAt) <= now) continue
            kept.push(n)
        }
        if (kept.length !== _pushNotices.length) _pushNotices = kept
    }

    /// The service says the user's mutes changed, possibly from the tray: cards
    /// of a kind now muted go, and Settings re-reads its list.
    function onNoticeMutesChanged() {
        root.noticeMutesRevision += 1
        if (!root.bridgeAvailable || !root.rpc
                || typeof root.rpc.rpcBlockNoticeMutesList !== "function") return
        var corr = root.rpc.rpcBlockNoticeMutesList()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) return
            var mutes = p.mutes || []
            var now = Date.now()
            var muted = []
            for (var i = 0; i < _pushNotices.length; i += 1) {
                var kind = String(_pushNotices[i].noticeMuteKind || "")
                if (kind !== "" && Pure.noticeKindMuted(mutes, kind, now)) muted.push(_pushNotices[i].id)
            }
            for (var j = 0; j < muted.length; j += 1) _dropPushNotice(muted[j])
        })
    }

    /// Take a notice down without recording an answer — used when the OTHER
    /// surface already recorded one.
    function _dropPushNotice(noticeId) {
        var id = String(noticeId || "")
        var kept = []
        for (var i = 0; i < _pushNotices.length; i += 1) {
            if (_pushNotices[i].id !== id) kept.push(_pushNotices[i])
        }
        if (kept.length !== _pushNotices.length) _pushNotices = kept
    }
    // Set by RoutingSettings._reseedTogglesFromPrefs when it
    // restores an enabled kill-switch the service had lost; cleared on dismiss.
    property bool killSwitchRestoredNoticeActive: false
    readonly property int notificationCount: root.activeNotifications.length
    // Highest severity present drives the footer chip colour.
    readonly property string notificationTopSeverity: {
        var sev = ""
        for (var i = 0; i < root.activeNotifications.length; i += 1) {
            if (root.activeNotifications[i].severity === "warning") return "warning"
            if (root.activeNotifications[i].severity === "info") sev = "info"
        }
        return sev
    }
    /// `actionArg` is the notice's own subject — the host a block notice names,
    /// for instance. Optional: every older action ignores it.
    function runNotificationAction(actionKey, actionArg) {
        if (actionKey === "explain-host") explainHostInDiagnostics(String(actionArg || ""))
        else if (actionKey === "open-auto-rule-suggestions") root.autoRuleSuggestionsController.openAutoRuleSuggestions()
        else if (actionKey === "open-interfaces") root.section = "interfaces-routes"
        else if (actionKey === "open-rules") root.section = "rules"
        else if (actionKey === "open-routing-settings") root.section = "settings"
        else if (actionKey === "open-release-page") {
            // The release the notice names; else the project's releases page.
            var u = (root.updateCheckController.offer || {}).url || ""
            if (u === "") {
                var base = ((root.context || {}).about || {}).projectUrl || ""
                if (base !== "") u = base + "/releases"
            }
            Pure.openExternalUrl(u)
        }
    }
    /// Answer "why did this not open?" where the question was asked.
    ///
    /// The explain probe has existed in Diagnostics for a while, and it still
    /// left the user guessing: nothing pointed at it from the moment the problem
    /// appeared. This carries the host from the block notice into the probe and
    /// runs it, so the answer arrives instead of a search.
    function explainHostInDiagnostics(host) {
        explainInDiagnostics(host, "", "")
    }
    /// The same, for one observed connection: its address and program travel
    /// with the name so the probe answers for that connection.
    function explainInDiagnostics(host, ip, process) {
        var subject = String(host || "").trim()
        if (subject === "") return
        pendingExplainHost = subject
        pendingExplainIp = String(ip || "")
        pendingExplainProcess = String(process || "")
        root.section = "diagnostics"
    }

    /// Sample handed to the Diagnostics probe on its next load. Cleared once
    /// consumed, so re-opening the page does not re-probe.
    property string pendingExplainHost: ""
    property string pendingExplainIp: ""
    property string pendingExplainProcess: ""

    function dismissNotification(notificationId) {
        if (notificationId === "app-unresolved") {
            // UNION with the previously-acknowledged set so an
            // app that temporarily left the set (resolved while running) stays
            // acknowledged when it returns after its process exits.
            root._unenforcedAppRulesAckSig = root._unenforcedAckUnionSig()
            // Persist the ack so the notice stays dismissed
            // across GUI restarts until a NEW unresolved app appears.
            root.updatePrefs({ unenforcedAppsAckSig: root._unenforcedAppRulesAckSig })
            root.emitPrefs()
        } else if (notificationId === "kill-switch-restored") {
            killSwitchRestoredNoticeActive = false
        } else if (notificationId === "update-available") {
            // Remembered by version: the notice comes back only for a release
            // other than the one dismissed.
            var offer = root.updateCheckController.offer
            if (offer && offer.latestVersion) {
                root.updatePrefs({ dismissedUpdateVersion: String(offer.latestVersion) })
                root.emitPrefs()
            }
        }
        // A push notice is answered for good, on every surface: record it before
        // dropping it so the tray stops offering the same thing. The
        // state-derived notices above are deliberately NOT recorded — they are
        // recomputed from live state and are meant to come back when that state
        // says so.
        var isPushNotice = false
        for (var i = 0; i < _pushNotices.length; i += 1) {
            if (_pushNotices[i].id === notificationId) { isPushNotice = true; break }
        }
        if (!isPushNotice) return
        root.noticeLedger.record(String(notificationId))
        _dropPushNotice(notificationId)
    }

    // Reactive mirror of the strict kill-switch
    // (block-all) setting for the notifications centre. `prefs.routeKillSwitchBlockAll`
    // is mutated IN PLACE by `applyKillSwitchBlockAll` (which does NOT emit
    // `prefsChanged`) and is reassigned wholesale on prefs (re)load — so neither
    // path alone reliably re-evaluates a `prefs.*`-reading binding. This bool is a
    // real property (its own change signal) driven in BOTH: `onPrefsChanged` (every
    // prefs reassignment — load / reseed / restore) and `applyKillSwitchBlockAll`
    // (the in-place live toggle). `activeNotifications` gates the strict notice on it.
}
