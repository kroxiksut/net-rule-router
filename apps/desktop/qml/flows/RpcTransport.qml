import QtQuick 2.15

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
// Each set/refresh helper records a `correlation_id → { cb, deadline }` entry
// before emitting the bridge request. When the bridge's `rpcResponse` signal
// fires, `handleRpcResponse` dispatches the matching callback (or logs an
// unknown correlation). A periodic GC fires synthetic timeout errors on stale
// callbacks so the table cannot grow unbounded if the launcher / service drops
// a response. The 30 s budget is well above the longest expected round-trip
// (mutation submit + apply ~ 5 s typical, <= 15 s worst-case).
QtObject {
    id: transport

    // Injected C++ bridge (nrrNativeBridge). Every bridge RPC entrypoint is
    // reached through this handle; when it is unavailable (preview / mock
    // builds) each forwarder returns "" and callers treat that as "offline".
    property var bridge: null

    readonly property int rpcTimeoutMs: 30000

    // correlation-id -> { cb, deadline }. Reassigned wholesale on every
    // mutation so QML property-change tracking observes the update.
    property var pendingRpc: ({})

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
        var table = pendingRpc
        table[correlationId] = { cb: callback, deadline: Date.now() + rpcTimeoutMs }
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
    // App-group routing discovery (mirrors rpcVpnDiscover); "" == scan-failed.
    function rpcAppGroupsDiscover() {
        return (bridgeAvailable && typeof bridge.rpcAppGroupsDiscover === "function")
            ? bridge.rpcAppGroupsDiscover()
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
    function rpcRouteLinkProviderSet(payload) {
        return (bridgeAvailable && typeof bridge.rpcRouteLinkProviderSet === "function")
            ? bridge.rpcRouteLinkProviderSet(payload)
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
            console.log("rpc: unknown correlation id", correlationId)
            return
        }
        var table = pendingRpc
        delete table[correlationId]
        pendingRpc = table
        _forgetLongRpc(correlationId)
        try {
            entry.cb(ok, payload, errorCode, errorMessage)
        } catch (e) {
            console.log("rpc: callback exception", e)
        }
    }

    function gcPendingRpc() {
        var now = Date.now()
        var table = pendingRpc
        var stale = []
        for (var id in table) {
            if (table[id].deadline <= now) stale.push(id)
        }
        if (stale.length === 0) return
        for (var i = 0; i < stale.length; i++) {
            var entry = table[stale[i]]
            delete table[stale[i]]
            _forgetLongRpc(stale[i])
            try {
                entry.cb(false, null, "rpc-timed-out",
                    "no response within " + (rpcTimeoutMs / 1000) + " s")
            } catch (e) {
                console.log("rpc: gc callback exception", e)
            }
        }
        pendingRpc = table
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
