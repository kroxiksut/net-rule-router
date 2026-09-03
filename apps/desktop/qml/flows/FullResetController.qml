import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller owning the FULL RESET flow: wipe the GUI's own state,
// clear the service's rules and auxiliary tables, stop the service, then offer
// to close every NetRuleRouter process so the next launch starts fresh.
//
// Extracted from Main.qml (thin-shell rule). The shell keeps the two dialogs —
// they are what the user sees — and this owns the order the steps run in, which
// is the part that matters: the auxiliary purge survives a declined UAC prompt
// at the rules step, and the service is stopped LAST because every step above
// needs it answering.
QtObject {
    id: fullResetController

    /// The ApplicationWindow. Everything the flow touches — preferences, the
    /// rules model, the RPC transport, the completion dialog — belongs to it.
    property var root

    // GUI prefs + file bindings + first-run flag, clear the local rules
    // model, then clear the service's active rules to an empty revision
    // (async two-phase mutation — under a non-admin GUI the confirm is
    // Forbidden and the launcher's R3 path transparently elevates via UAC).
    // The completion dialog offers to close the program + tray so the reset
    // takes effect on the next launch (fresh first-run).
    function fullReset(allPrincipals) {
        root.statusLine = root.tr("status.full-reset-running", "Performing full reset…")
        if (root.bridgeAvailable && typeof nrrNativeBridge.rpcLogsClear === "function") {
            var cl = nrrNativeBridge.rpcLogsClear(false, true)
            root.rpc.registerRpcCallback(cl, function() {})
        }
        if (root.bridgeAvailable && typeof nrrNativeBridge.rpcSidecarReset === "function") {
            var cs = nrrNativeBridge.rpcSidecarReset()
            root.rpc.registerRpcCallback(cs, function() {})
        }
        if (root.bridgeAvailable && typeof nrrNativeBridge.clearGuiLogs === "function") {
            nrrNativeBridge.clearGuiLogs()
        }
        root.resetDefaults()
        root.updatePrefs({
            lastSavedPathPrimary: "",
            lastSavedPathSecondary: "",
            lastLoadedPathPrimary: "",
            lastLoadedPathSecondary: "",
            autoOpenOnLaunchPathPrimary: "",
            autoOpenOnLaunchPathSecondary: "",
            firstRunCompleted: false,
            // "Reset everything" means the state a fresh install starts from,
            // and that includes not having agreed to anything yet.
            acceptedEulaVersion: 0
        })
        root.emitPrefs()
        Pure.clearModel(root.rulesModel)
        root.clearAllUnsavedChanges()
        // Purge auxiliary state FIRST: disjoint tables from the rules-apply
        // step, but this order survives a declined UAC prompt below.
        _purgePrincipalData(allPrincipals === true, function(purgeOk) {
            applyEmptyRules(function(rulesOk) {
                // Stop the service LAST: it tears its filters down on the way
                // out, and everything above needs it answering. A machine left
                // in the post-reset state has nothing to enforce, so a running
                // service would only be a process with no policy.
                _stopService(function(stopOk) {
                    root.fullResetCompleteDialog.serviceCleared =
                        !!purgeOk && !!rulesOk && !!stopOk
                    root.fullResetCompleteDialog.open()
                })
            })
        })
    }

    // Stop the background service as the last step of a full reset. Elevation
    // goes through the same broker the Settings button uses, so a declined UAC
    // prompt reports itself instead of failing silently. Best-effort: the reset
    // itself already happened, so a service that refuses to stop downgrades the
    // completion notice rather than aborting anything.
    function _stopService(onComplete) {
        if (typeof nrrServiceController === "undefined" || !nrrServiceController
                || typeof nrrServiceController.stopService !== "function") {
            onComplete(false)
            return
        }
        nrrServiceController.stopService()
        _stopWatch.attempts = 0
        _stopWatch.onDone = onComplete
        _stopWatch.restart()
    }

    // The controller reports status asynchronously; poll it a few times rather
    // than block the reset on a signal that may already have fired.
    // Property-held (QtObject has no default property, so a bare child would
    // not be created), exactly as RpcTransport holds its collector.
    property Timer _stopWatch: Timer {
        id: _stopWatch
        interval: 700
        repeat: true
        property int attempts: 0
        property var onDone: null
        onTriggered: {
            attempts += 1
            var busy = (typeof nrrServiceController !== "undefined" && nrrServiceController)
                ? nrrServiceController.busy === true
                : false
            // 4 = running in the controller's status vocabulary; anything else
            // (stopped, not installed) means it is no longer enforcing.
            var stopped = (typeof nrrServiceController !== "undefined" && nrrServiceController)
                ? parseInt(nrrServiceController.status) !== 4
                : false
            if (!busy && (stopped || attempts >= 8)) {
                stop()
                var cb = onDone
                onDone = null
                if (typeof cb === "function") cb(stopped)
            }
        }
    }

    // Full-reset auxiliary-state purge via `principal-data.purge`. Caller's own
    // principal and non-elevated by default; `allPrincipals` clears every OS
    // user's routing and the service demands elevation for it.
    function _purgePrincipalData(allPrincipals, onComplete) {
        if (!root.bridgeAvailable || typeof nrrNativeBridge.rpcPrincipalDataPurge !== "function") {
            onComplete(false)
            return
        }
        // Full reset means the service keeps nothing of ours either — its own
        // copy of the rules goes with the auxiliary state.
        var c = nrrNativeBridge.rpcPrincipalDataPurge(true, allPrincipals === true)
        root.rpc.registerRpcCallback(c, function(ok) { onComplete(!!ok) })
    }

    /// How many OTHER OS users the service holds rules for. `done(count)`; a
    /// service that cannot answer reports 0, which keeps full reset on its
    /// single-user path rather than offering a choice it cannot honour.
    function countOtherPrincipals(done) {
        var finish = function(n) { if (typeof done === "function") done(n | 0) }
        if (!root.bridgeAvailable || !root._routingBackendConnected()
                || typeof nrrNativeBridge.rpcPrincipalDataCount !== "function") {
            finish(0)
            return
        }
        var c = nrrNativeBridge.rpcPrincipalDataCount()
        root.rpc.registerRpcCallback(c, function(ok, p) {
            finish(ok && p ? parseInt(p["other-principals"] || 0) : 0)
        })
    }

    // Silent two-phase empty PresetImport: makes the service's active
    // revision empty (post-install state) WITHOUT opening the review dialog
    // (the Full-reset confirm already gated the action). Same payload shape
    // as `startBothRoutesPresetImportReviewFlow`; the confirm phase carries
    // the dry-run token. Non-admin → confirm Forbidden → launcher R3 elevates
    // (UAC) and retries; `onComplete(false)` on UAC-decline / failure.
    function applyEmptyRules(onComplete) {
        if (!root.bridgeAvailable || typeof nrrNativeBridge.rpcMutationSubmit !== "function") {
            onComplete(false)
            return
        }
        var emptyB64 = Qt.btoa("--- Zones\n\n--- Domains\n\n--- IP\n\n--- Windows\n\n--- Linux\n\n--- MacOS\n")
        var corr = "full-reset-" + (new Date().getTime())
        var payload = {
            "include-child-processes": false,
            "correlation-id": corr,
            "primary-bytes-b64": emptyB64,
            "secondary-bytes-b64": emptyB64
        }
        var c1 = nrrNativeBridge.rpcMutationSubmit("preset-import", payload, true, "")
        root.rpc.registerLongRpcCallback(c1, function(ok, p, code, msg) {
            if (!ok || !p) { onComplete(false); return }
            var token = (p && p["confirmation-token"]) || ""
            var c2 = nrrNativeBridge.rpcMutationSubmit("preset-import", payload, false, token)
            root.rpc.registerLongRpcCallback(c2, function(ok2) { onComplete(!!ok2) })
        })
    }

    // Close every NetRuleRouter process so the reset takes effect on the
    // next launch. The main GUI closes itself directly; `requestTrayShutdown`
    // writes the dedicated tray-shutdown flag the tray polls and quits on.
    function closeAllProcesses() {
        if (root.bridgeAvailable && typeof nrrNativeBridge.requestTrayShutdown === "function") {
            nrrNativeBridge.requestTrayShutdown()
        }
        root.quittingToTray = true
        root.clearAllUnsavedChanges()
        root.close()
        Qt.quit()
    }
}
