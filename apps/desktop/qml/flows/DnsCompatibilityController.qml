import QtQuick 2.15
import "../lib/pure.js" as Pure

QtObject {
    id: controller
    property var root
    property var state: ({ status: "unchecked", issues: [], "recovery-pending": false })
    property bool busy: false
    property int connectionGeneration: 0

    function accept(value, generation) {
        if (generation !== undefined && generation !== connectionGeneration) return
        if (value && value.status === "verified" && !root._routingBackendConnected()) return
        state = Pure.mergeDnsCompatibility(state, value)
    }

    function recheck() {
        if (busy || !root.bridgeAvailable || !root._routingBackendConnected()
                || typeof nrrNativeBridge.rpcDnsCompatibilityRecheck !== "function") return
        busy = true
        var generation = connectionGeneration
        var corr = nrrNativeBridge.rpcDnsCompatibilityRecheck()
        if (!corr) { busy = false; return }
        root.rpc.registerRpcCallback(corr, function(ok, payload, code) {
            if (generation !== connectionGeneration) return
            busy = false
            if (ok && payload) accept(payload)
            else root.statusLine = root.tr("errors." + String(code || "internal"),
                root.tr("settings.routing.dns-compatibility.check-failed", "Could not check DNS compatibility."))
        })
    }

    property Connections connection: Connections {
        target: root
        function onBackendStatusChanged() {
            if (typeof root._routingBackendConnected === "function" && !root._routingBackendConnected()) {
                controller.connectionGeneration += 1
                controller.accept(null)
                controller.busy = false
            }
        }
    }
}
