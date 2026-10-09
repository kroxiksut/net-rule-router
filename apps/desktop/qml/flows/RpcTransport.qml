import QtQuick 2.15
import "../lib/pure.js" as Pure

// Correlation-id RPC transport over the C++ NrrNativeBridge.
//
// This is the single seam through which every UI surface (main window and
// tray) issues a request to the launcher/service and dispatches the matching
// response. Extracted from Main.qml — and from the near-identical copy that
// used to live in Tray.qml — so the shell no longer owns the pending-callback
// table, the garbage-collection timer, or the bridge forwarders. New RPCs are
// added here, and callers go through `rpc.<fn>` (self-documenting, the same way
// `Pure.<fn>` marks a pure helper).
//
// State-bearing (the pending-callback table plus a periodic GC timer), so this
// is a QtObject component rather than a `.pragma library`. The bridge is
// injected (`bridge: nrrNativeBridge`) instead of referenced as a global,
// keeping the component free of hidden coupling and usable from any surface.
//
// Each call registers a `correlation_id → { cb, deadline }` entry right after
// the bridge emits the request. When the bridge's `rpcResponse` signal fires,
// `handleRpcResponse` dispatches the matching callback. A periodic GC fires a
// synthetic `rpc-timed-out` on callbacks past their deadline, so a response the
// launcher never sends cannot hold an entry forever.
//
// The deadline is per operation and comes from the launcher (`answerDeadlines`,
// derived from the budgets its dispatcher runs on), so the transport never
// gives up on an answer that is still allowed to arrive.
QtObject {
    id: transport

    // Injected C++ bridge (nrrNativeBridge). Every bridge RPC entrypoint is
    // reached through this handle; when it is unavailable (preview / mock
    // builds) each forwarder returns "" and callers treat that as "offline".
    property var bridge: null

    // `{ defaultMs, operationsMs: { <slug>: ms } }` from the launch context.
    property var answerDeadlines: null

    // Only without a launcher context, where no answer ever comes.
    readonly property int _contextlessDeadlineMs: 30000

    // While the user answers an administrator prompt no deadline runs: the
    // call that raised it waits on the person, not on the service. Resuming
    // moves every pending deadline on by the time spent there. The poll that
    // reports the prompt keeps its own deadline, or a lost poll would hold
    // every other one forever.
    property bool consentPending: false
    readonly property string consentPollOperation: "local.broker-status"
    property double _consentSince: 0
    onConsentPendingChanged: {
        var now = Date.now()
        if (consentPending) {
            _consentSince = now
            return
        }
        if (_consentSince <= 0) return
        var paused = now - _consentSince
        _consentSince = 0
        var table = pendingRpc
        for (var id in table) {
            if (table[id].operation !== consentPollOperation) table[id].deadline += paused
        }
        pendingRpc = table
    }

    // correlation-id -> { cb, deadline, operation }. Reassigned wholesale on
    // every mutation so QML property-change tracking observes the update.
    property var pendingRpc: ({})

    // correlation-id -> { operation, at }, filled by the bridge's
    // `rpcRequested` and taken by the registration that follows on the same
    // call stack.
    property var _requestedOps: ({})

    // correlation-id -> { operation, wasLong, at } of calls the GC failed, so
    // their real answer is recognised instead of dropped as unknown.
    property var _expiredRpc: ({})
    readonly property int _recordMemoryMs: 600000

    // A call the GC had already failed has answered after all. Its callback ran
    // with `rpc-timed-out`; a surface whose state the call may have changed
    // re-reads it from here.
    signal lateResponse(string correlationId, string operation, bool wasLong,
                        bool ok, string errorCode)

    // The service refused a change until a security alert is acknowledged —
    // an alert the surface may not list yet. Wire slug of
    // `IpcErrorCode::SecurityAlertUnacknowledged`, pinned by a test.
    readonly property string securityAlertGateCode: "security-alert-unacknowledged"
    signal securityAlertGateHit()

    function answerDeadlineMs(operation) {
        var table = answerDeadlines
        if (!table) return _contextlessDeadlineMs
        var perOp = table.operationsMs ? Number(table.operationsMs[operation]) : NaN
        if (perOp > 0) return perOp
        var fallback = Number(table.defaultMs)
        return fallback > 0 ? fallback : _contextlessDeadlineMs
    }

    property Connections _requestWatch: Connections {
        target: transport.bridge
        ignoreUnknownSignals: true
        function onRpcRequested(correlationId, operation) {
            transport._requestedOps[correlationId] = {
                operation: String(operation || ""), at: Date.now()
            }
        }
    }

    readonly property bool bridgeAvailable: typeof bridge !== "undefined"
        && bridge !== null
        && typeof bridge.rpcRetentionSettingsGet === "function"

    // Correlation ids of calls the caller declared LONG. Reassigned wholesale
    // for the same property-tracking reason as `pendingRpc`.
    property var pendingLongRpc: ({})

    // True while a call that may legitimately hold the client's single
    // in-flight slot for tens of seconds is outstanding — the rules preview and
    // the apply behind it. The service answers one request at a time per
    // connection, so while this is true a timeout on a short poll measures the
    // queue in front of it, not the service. Surfaces reading it must not treat
    // such a timeout as evidence of an outage.
    readonly property bool longCallInFlight: Object.keys(pendingLongRpc).length > 0

    function registerRpcCallback(correlationId, callback) {
        if (!correlationId || correlationId === "") return
        var requested = _requestedOps[correlationId]
        delete _requestedOps[correlationId]
        var operation = requested === undefined ? "" : requested.operation
        var table = pendingRpc
        table[correlationId] = {
            cb: callback,
            deadline: Date.now() + answerDeadlineMs(operation),
            operation: operation
        }
        pendingRpc = table
    }

    // Same registration, plus the "this one is long" mark. Used by every
    // `rpcMutationSubmit` call site: a preview derives the whole per-SID filter
    // plan and an apply installs it, and both have been measured in the tens of
    // seconds on a real rule set.
    function registerLongRpcCallback(correlationId, callback) {
        if (!correlationId || correlationId === "") return
        var longs = pendingLongRpc
        longs[correlationId] = true
        pendingLongRpc = longs
        registerRpcCallback(correlationId, callback)
    }

    // Drop `correlationId` from the long-call set, if it was in it.
    function _forgetLongRpc(correlationId) {
        if (pendingLongRpc[correlationId] === undefined) return
        var longs = pendingLongRpc
        delete longs[correlationId]
        pendingLongRpc = longs
    }

    // A confirmed mutation's `ok` only says it was accepted; the verdict is on
    // its operation record. `done("")` once it completed, `done(code, args)`
    // when it failed, `args` being that failure's own values (or null). A record this account cannot read (another administrator
    // confirmed it) is judged by `settleByState(done)` from what the service
    // holds now.
    function readMutationOutcome(confirmAnswer, settleByState, done) {
        var operationId = String((confirmAnswer && confirmAnswer["operation-id"]) || "")
        var corr = (operationId !== "" && bridgeAvailable
                    && typeof bridge.rpcOperationStatusGet === "function")
            ? bridge.rpcOperationStatusGet(operationId) : ""
        if (!corr) {
            settleByState(done)
            return
        }
        registerRpcCallback(corr, function(ok, status) {
            var failure = Pure.operationOutcome(ok, status)
            if (failure === transport.securityAlertGateCode) transport.securityAlertGateHit()
            if (failure === null) settleByState(done)
            else done(failure, Pure.operationFailureArgs(status))
        })
    }

    // `settleByState` for a mutation the preview describes: it took effect
    // exactly when the same payload now previews as unchanged —
    // `unchanged(summary)`, an empty diff unless given.
    function settleByPreview(kind, payload, unchanged) {
        var isUnchanged = (typeof unchanged === "function") ? unchanged : Pure.reviewSummaryIsEmpty
        return function(done) {
            var again = Object.assign({}, payload, {
                "correlation-id": kind + "-outcome-" + Date.now() + "-"
                    + Math.floor(Math.random() * 1e6)
            })
            var corr = (bridgeAvailable && typeof bridge.rpcMutationSubmit === "function")
                ? bridge.rpcMutationSubmit(kind, again, true /* dryRun */, "") : ""
            if (!corr) {
                done("unknown")
                return
            }
            registerLongRpcCallback(corr, function(ok, p, code) {
                if (!ok) {
                    done(String(code || "unknown"))
                    return
                }
                done(Pure.previewOutcome((p && p["review-summary"]) || p || {}, isUnchanged))
            })
        }
    }

    // --- Bridge forwarders (guarded; return "" when the bridge is absent) ---

    // VPN-onboarding discovery. VpnOnboardingDialog drives its scan through
    // `ownerRoot.rpc.rpcVpnDiscover()`; the empty-string result is treated as
    // scan-failed.
    function rpcVpnDiscover() {
        return (bridgeAvailable && typeof bridge.rpcVpnDiscover === "function")
            ? bridge.rpcVpnDiscover()
            : ""
    }
    // Traffic counter. The polling + model logic lives in
    // TrafficStatsController; these are thin bridge forwarders.
    function rpcTrafficStatsGet(payload) {
        return (bridgeAvailable && typeof bridge.rpcTrafficStatsGet === "function")
            ? bridge.rpcTrafficStatsGet(payload)
            : ""
    }
    function rpcTrafficStatsSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcTrafficStatsSet === "function")
            ? bridge.rpcTrafficStatsSet(payload)
            : ""
    }
    function rpcTrafficStatsClear() {
        return (bridgeAvailable && typeof bridge.rpcTrafficStatsClear === "function")
            ? bridge.rpcTrafficStatsClear()
            : ""
    }
    function rpcTrafficHistoryMergeSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcTrafficHistoryMergeSet === "function")
            ? bridge.rpcTrafficHistoryMergeSet(payload)
            : ""
    }
    // The system appearance as the launcher's probe reports it right now. Asked
    // when the desktop's colour scheme changes under a running window; "" means
    // no bridge, and the shell keeps the appearance it started with.
    function rpcSystemTheme() {
        return (bridgeAvailable && typeof bridge.rpcSystemTheme === "function")
            ? bridge.rpcSystemTheme()
            : ""
    }
    // The Help menu's "Check for updates"; "" means no bridge.
    function rpcUpdateCheckRun() {
        return (bridgeAvailable && typeof bridge.rpcUpdateCheckRun === "function")
            ? bridge.rpcUpdateCheckRun()
            : ""
    }
    // App-group routing discovery (mirrors rpcVpnDiscover); "" == scan-failed.
    function rpcAppGroupsDiscover() {
        return (bridgeAvailable && typeof bridge.rpcAppGroupsDiscover === "function")
            ? bridge.rpcAppGroupsDiscover()
            : ""
    }
    // Hypervisors and their virtual machines (launcher-local); "" == unavailable.
    function rpcVmInventoryList(payload) {
        return (bridgeAvailable && typeof bridge.rpcVmInventoryList === "function")
            ? bridge.rpcVmInventoryList(payload || {})
            : ""
    }
    // Pins a VM's NAT adapter to the additional adapter, or unpins it.
    function rpcVmNatBind(payload) {
        return (bridgeAvailable && typeof bridge.rpcVmNatBind === "function")
            ? bridge.rpcVmNatBind(payload || {})
            : ""
    }
    // Persists the confirmed VPN/link-provider executables to the service-side
    // SSOT (route.link-provider.set), feeding per-app kill-switch exemptions and
    // triggering a server-side recompile. An empty "link-provider-apps" clears
    // the set. Returns the correlation id, or "" when the bridge is unavailable.
    // Local networks kept reachable under the kill-switch: the read returns
    // what the service discovered plus the caller's decisions, the write takes
    // `{ "decisions": [...], "forget": [...] }` and answers with the new list.
    function rpcLocalNetworksGet() {
        return (bridgeAvailable && typeof bridge.rpcLocalNetworksGet === "function")
            ? bridge.rpcLocalNetworksGet()
            : ""
    }
    function rpcLocalNetworksSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcLocalNetworksSet === "function")
            ? bridge.rpcLocalNetworksSet(payload)
            : ""
    }

    // Auto-rule suggestions. The tray fetches the pending candidate list and
    // then either accepts or dismisses a set of ids; both mutations take
    // `{ "ids": [...] }`. Read-then-mutate, no elevation of their own — the
    // service scopes every one of them to the calling SID.
    function rpcRefusingAnchorSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcRefusingAnchorSet === "function")
            ? bridge.rpcRefusingAnchorSet(payload)
            : ""
    }
    function rpcAutoRuleCandidatesProbe(payload) {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleCandidatesProbe === "function")
            ? bridge.rpcAutoRuleCandidatesProbe(payload)
            : ""
    }
    function rpcAutoRuleCandidatesList() {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleCandidatesList === "function")
            ? bridge.rpcAutoRuleCandidatesList()
            : ""
    }
    function rpcAutoRuleCandidatesAccept(payload) {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleCandidatesAccept === "function")
            ? bridge.rpcAutoRuleCandidatesAccept(payload)
            : ""
    }
    function rpcAutoRuleCandidatesDismiss(payload) {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleCandidatesDismiss === "function")
            ? bridge.rpcAutoRuleCandidatesDismiss(payload)
            : ""
    }
    function rpcAutoRuleCandidatesForget(payload) {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleCandidatesForget === "function")
            ? bridge.rpcAutoRuleCandidatesForget(payload)
            : ""
    }
    function rpcAutoRuleDismissedList() {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleDismissedList === "function")
            ? bridge.rpcAutoRuleDismissedList()
            : ""
    }
    function rpcAutoRuleDismissedRestore(payload) {
        return (bridgeAvailable && typeof bridge.rpcAutoRuleDismissedRestore === "function")
            ? bridge.rpcAutoRuleDismissedRestore(payload)
            : ""
    }
    function rpcVerifyVerdictsList() {
        return (bridgeAvailable && typeof bridge.rpcVerifyVerdictsList === "function")
            ? bridge.rpcVerifyVerdictsList()
            : ""
    }
    function rpcVerifyVerdictsAccept(payload) {
        return (bridgeAvailable && typeof bridge.rpcVerifyVerdictsAccept === "function")
            ? bridge.rpcVerifyVerdictsAccept(payload)
            : ""
    }
    function rpcVerifyVerdictsDismiss(payload) {
        return (bridgeAvailable && typeof bridge.rpcVerifyVerdictsDismiss === "function")
            ? bridge.rpcVerifyVerdictsDismiss(payload)
            : ""
    }
    function rpcRouteLinkProviderSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcRouteLinkProviderSet === "function")
            ? bridge.rpcRouteLinkProviderSet(payload)
            : ""
    }
    // The user's own record of the service's settings, in their settings file.
    function rpcUserSettingsIntentGet() {
        return (bridgeAvailable && typeof bridge.rpcUserSettingsIntentGet === "function")
            ? bridge.rpcUserSettingsIntentGet()
            : ""
    }
    function rpcUserSettingsIntentRecord(payload) {
        return (bridgeAvailable && typeof bridge.rpcUserSettingsIntentRecord === "function")
            ? bridge.rpcUserSettingsIntentRecord(payload)
            : ""
    }
    // Block-notice mutes and the "route this over the secondary" shortcut
    // offered alongside a block notice. Read-then-mutate, no elevation of
    // their own — the service scopes every one of them to the calling SID.
    function rpcBlockNoticeMutesList() {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeMutesList === "function")
            ? bridge.rpcBlockNoticeMutesList()
            : ""
    }
    function rpcBlockNoticeMutesSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeMutesSet === "function")
            ? bridge.rpcBlockNoticeMutesSet(payload)
            : ""
    }
    function rpcBlockNoticeMutesRemove(payload) {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeMutesRemove === "function")
            ? bridge.rpcBlockNoticeMutesRemove(payload)
            : ""
    }
    function rpcBlockNoticeMutesClear() {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeMutesClear === "function")
            ? bridge.rpcBlockNoticeMutesClear()
            : ""
    }
    // The backlog a surface drains when it comes up: notices the service
    // raised while nothing was subscribed to show them.
    function rpcBlockNoticeJournalList() {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeJournalList === "function")
            ? bridge.rpcBlockNoticeJournalList()
            : ""
    }
    function rpcBlockNoticeJournalAck(payload) {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeJournalAck === "function")
            ? bridge.rpcBlockNoticeJournalAck(payload)
            : ""
    }
    function rpcBlockNoticeRouteToSecondary(payload) {
        return (bridgeAvailable && typeof bridge.rpcBlockNoticeRouteToSecondary === "function")
            ? bridge.rpcBlockNoticeRouteToSecondary(payload)
            : ""
    }

    function handleRpcResponse(correlationId, ok, payload, errorCode, errorMessage) {
        var entry = pendingRpc[correlationId]
        if (entry === undefined) {
            var expired = _expiredRpc[correlationId]
            if (expired === undefined) {
                console.log("rpc: unknown correlation id", correlationId)
                return
            }
            delete _expiredRpc[correlationId]
            console.log("rpc: late answer", correlationId, expired.operation,
                "ok=" + ok, String(errorCode || ""),
                (Date.now() - expired.at) + " ms after its deadline")
            lateResponse(correlationId, expired.operation, expired.wasLong,
                         !!ok, String(errorCode || ""))
            return
        }
        var table = pendingRpc
        delete table[correlationId]
        pendingRpc = table
        _forgetLongRpc(correlationId)
        if (!ok && String(errorCode || "") === securityAlertGateCode) securityAlertGateHit()
        try {
            entry.cb(ok, payload, errorCode, errorMessage)
        } catch (e) {
            console.log("rpc: callback exception", e)
        }
    }

    function gcPendingRpc() {
        var now = Date.now()
        _forgetOldRecords(now)
        var table = pendingRpc
        var stale = []
        for (var id in table) {
            if (consentPending && table[id].operation !== consentPollOperation) continue
            if (table[id].deadline <= now) stale.push(id)
        }
        if (stale.length === 0) return
        for (var i = 0; i < stale.length; i++) {
            var entry = table[stale[i]]
            var wasLong = pendingLongRpc[stale[i]] !== undefined
            delete table[stale[i]]
            _forgetLongRpc(stale[i])
            _expiredRpc[stale[i]] = { operation: entry.operation, wasLong: wasLong, at: now }
            console.log("rpc: no answer in time", stale[i], entry.operation)
            try {
                entry.cb(false, null, "rpc-timed-out",
                    "no response within "
                    + Math.round(answerDeadlineMs(entry.operation) / 1000) + " s")
            } catch (e) {
                console.log("rpc: gc callback exception", e)
            }
        }
        pendingRpc = table
    }

    // Requests nobody registered for, and failed calls that never answered:
    // neither may pile up over a long session.
    function _forgetOldRecords(now) {
        var id
        for (id in _requestedOps) {
            if (now - _requestedOps[id].at > _recordMemoryMs) delete _requestedOps[id]
        }
        for (id in _expiredRpc) {
            if (now - _expiredRpc[id].at > _recordMemoryMs) delete _expiredRpc[id]
        }
    }

    // Pending-RPC garbage collector. Declared as a property-held Timer so the
    // component works even when hosted by a parent without a default property
    // (SystemTrayIcon in Tray.qml), which is why the tray previously created
    // its collector programmatically.
    property Timer _gcTimer: Timer {
        interval: 5000
        running: true
        repeat: true
        onTriggered: transport.gcPendingRpc()
    }
}
