import QtQuick 2.15

// Non-visual controller. Polls `traffic-stats.get`
// on an interval while `active`, holds the today/session/settings model, and
// forwards settings writes + CSV export. Kept OUT of Main.qml (thin-shell rule):
// Main.qml instantiates one and exposes it as `root.trafficStats`; the panel
// under Settings and the Interfaces adapter cards both read the model and
// drive the poll cadence via the visibility flags below. All RPC goes
// through the thin `ownerRoot` bridge forwarders (`rpcTrafficStatsGet` /
// `rpcTrafficStatsSet`) + `registerRpcCallback`.
Item {
    id: controller
    property var ownerRoot

    // Wire model — arrays of { adapter-key, display-name, role, in-bytes, out-bytes }.
    property var todayRows: []
    property var sessionRows: []
    // All-time totals per adapter+role (bounded by the retention window).
    // Absent in older payloads — treated as empty.
    property var allTimeRows: []
    // True while an additional-adapter session is live; false when it has ended
    // or never started. Absent in older payloads — treated as false.
    property bool sessionActive: false
    /// The one-time question the service is asking, or null. `{oldKey, oldName,
    /// newKey, newName, sharedToken}` — see the wire DTO. Null is the normal
    /// state; the panel shows nothing.
    property var historyMerge: null
    property var settings: ({
        enabled: true, countLoopback: false, countVirtual: false, retentionDays: 365
    })
    property bool loaded: false

    // Fast-poll gate: true while a consumer that renders live numbers is
    // actually on screen. One flag per known consumer rather than a shared
    // counter, so a component that forgets to detach can never leak the fast
    // interval — each flag is a live binding driven by its owner's own
    // visibility state (see TrafficStatsSettings.qml / InterfacesRoutesSection.qml),
    // re-asserted continuously rather than incremented/decremented.
    property bool trafficPanelVisible: false
    property bool interfacesPanelVisible: false
    readonly property bool fastPollActive: trafficPanelVisible || interfacesPanelVisible

    // LOCAL epoch-day — MUST match the service `traffic-sample-tick` day key,
    // which is keyed on the machine's civil date (not midnight UTC).
    function epochDay() {
        return Math.floor((Date.now() - new Date().getTimezoneOffset() * 60000) / 86400000)
    }

    function bridgeReady() {
        return ownerRoot
            && ownerRoot.rpc
            && typeof ownerRoot.rpc.rpcTrafficStatsGet === "function"
            && typeof ownerRoot.rpc.registerRpcCallback === "function"
    }

    function _applySettingsPayload(s) {
        return {
            enabled: s["enabled"] !== false,
            countLoopback: s["count-loopback"] === true,
            countVirtual: s["count-virtual"] === true,
            retentionDays: Number(s["retention-days"] || 365)
        }
    }

    function refresh() {
        if (!bridgeReady()) return
        var corr = ownerRoot.rpc.rpcTrafficStatsGet({ "day": controller.epochDay() })
        if (!corr || corr === "") return
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok || !p) return
            controller.todayRows = p["today"] || []
            controller.sessionRows = p["session"] || []
            controller.allTimeRows = p["all-time"] || []
            controller.sessionActive = p["session-active"] === true
            controller.settings = controller._applySettingsPayload(p["settings"] || {})
            controller.historyMerge = controller._mergeQuestion(p["history-merge"])
            controller.loaded = true
        })
    }

    /// Normalise the pending merge question, or null when there is none.
    ///
    /// A question missing either side is dropped rather than shown: the whole
    /// point is that the user is choosing between two named connections, and a
    /// half-named pair cannot be answered honestly.
    function _mergeQuestion(raw) {
        if (!raw) return null
        var oldKey = String(raw["old-key"] || "")
        var newKey = String(raw["new-key"] || "")
        if (oldKey === "" || newKey === "" || oldKey === newKey) return null
        return {
            oldKey: oldKey,
            newKey: newKey,
            oldName: String(raw["old-name"] || oldKey),
            newName: String(raw["new-name"] || newKey),
            sharedToken: String(raw["shared-token"] || "")
        }
    }

    /// Answer the merge question. `merged: false` is an answer too — the pair is
    /// recorded as decided and never offered again, which is why the panel has
    /// no third "ask me later" button.
    function answerHistoryMerge(merged) {
        var q = controller.historyMerge
        if (!q) return
        if (!ownerRoot || !ownerRoot.rpc
                || typeof ownerRoot.rpc.rpcTrafficHistoryMergeSet !== "function") return
        var corr = ownerRoot.rpc.rpcTrafficHistoryMergeSet({
            "old-key": q.oldKey,
            "new-key": q.newKey,
            "merged": merged === true
        })
        if (!corr || corr === "") return
        // Hidden only once the service confirms: the ledger is machine-wide and
        // the write needs Administrator rights, so hiding first would show a
        // refused answer as taken and bring the question back on the next poll
        // with nothing said.
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (ok) {
                controller.historyMerge = null
                controller.refresh()
                return
            }
            ownerRoot.statusLine = (code === "uac-declined")
                ? ownerRoot.tr("progress.service-uac-declined",
                    "Administrator prompt declined - operation cancelled.")
                : ownerRoot.tr("status.traffic-history-merge-failed",
                    "Could not save the answer: ") + String(msg || code || "")
        })
    }

    // Persist the settings; optimistic local update, next poll reconciles.
    function applySettings(obj) {
        controller.settings = obj
        if (!ownerRoot || !ownerRoot.rpc || typeof ownerRoot.rpc.rpcTrafficStatsSet !== "function") return
        var corr = ownerRoot.rpc.rpcTrafficStatsSet({
            "settings": {
                "enabled": obj.enabled === true,
                "count-loopback": obj.countLoopback === true,
                "count-virtual": obj.countVirtual === true,
                "retention-days": Number(obj.retentionDays || 365)
            }
        })
        if (corr && corr !== "" && typeof ownerRoot.rpc.registerRpcCallback === "function") {
            ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
                if (ok && p) controller.settings = controller._applySettingsPayload(p)
            })
        }
    }

    // Reset all traffic data (ledger + session + cursors); settings are kept.
    //
    // The rows are blanked only once the service confirms it did it. The ledger
    // is machine-wide, so the wipe needs Administrator rights; blanking first
    // showed the clear as done even when the rights were refused, and the
    // numbers then reappeared on the next poll with nothing said.
    function clear() {
        if (!ownerRoot || !ownerRoot.rpc || typeof ownerRoot.rpc.rpcTrafficStatsClear !== "function") return
        var corr = ownerRoot.rpc.rpcTrafficStatsClear()
        if (!corr || corr === "") return
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (ok) {
                controller.todayRows = []
                controller.sessionRows = []
                controller.allTimeRows = []
                controller.refresh()
                return
            }
            ownerRoot.statusLine = (code === "uac-declined")
                ? ownerRoot.tr("progress.service-uac-declined",
                    "Administrator prompt declined - operation cancelled.")
                : ownerRoot.tr("status.clear-failed", "Could not clear: ")
                    + String(msg || code || "")
        })
    }

    // Request a CSV export for [fromDay, toDay], with the received/sent columns
    // rendered in `unit` ("bytes" / "kb" / "mb" / "gb"); the service names the
    // columns after the unit. `cb(csvText)` (empty on failure).
    function requestExport(fromDay, toDay, unit, cb) {
        if (!bridgeReady()) { cb(""); return }
        var corr = ownerRoot.rpc.rpcTrafficStatsGet({
            "day": controller.epochDay(),
            "export-from-day": fromDay,
            "export-to-day": toDay,
            "export-unit": String(unit || "bytes")
        })
        if (!corr || corr === "") { cb(""); return }
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            cb((ok && p && p["csv"]) ? p["csv"] : "")
        })
    }

    Timer {
        // Background cadence is 60 s while neither consumer is on screen —
        // the model still needs to stay roughly current (tray/session-active
        // hints), but there is no live number being stared at, so a minute
        // is cheap. Either consumer flipping its visibility flag above (see
        // `fastPollActive`) switches this to 3 s for as long as it stays
        // visible; each consumer also fires an immediate refresh() on
        // becoming visible so re-entering a view never shows a stale 60 s
        // read while waiting for the next tick.
        interval: controller.fastPollActive ? 3000 : 60000
        repeat: true
        triggeredOnStart: true
        running: controller.bridgeReady()
        onTriggered: controller.refresh()
    }
}
