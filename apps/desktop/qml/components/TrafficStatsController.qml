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
            controller.loaded = true
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
    function clear() {
        if (!ownerRoot || !ownerRoot.rpc || typeof ownerRoot.rpc.rpcTrafficStatsClear !== "function") return
        var corr = ownerRoot.rpc.rpcTrafficStatsClear()
        controller.todayRows = []
        controller.sessionRows = []
        controller.allTimeRows = []
        if (corr && corr !== "") controller.refresh()
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
