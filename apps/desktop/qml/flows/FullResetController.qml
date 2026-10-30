import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller owning the FULL RESET flow: wipe the GUI's own state,
// clear the service's rules and auxiliary tables, restart the service on the
// cleared state, then offer to close every NetRuleRouter process so the next
// launch starts fresh.
//
// The shell keeps the two dialogs; this owns the order the steps run in: the
// auxiliary purge survives a declined UAC prompt at the rules step, and the
// service is restarted LAST because every step above needs it answering. The
// reset ends as a fresh install does — with the service running.
QtObject {
    id: fullResetController

    /// The ApplicationWindow. Everything the flow touches — preferences, the
    /// rules model, the RPC transport, the completion dialog — belongs to it.
    property var root

    // GUI prefs + file bindings + first-run flag, clear the local rules
    // model, then erase the service's copy of the user's rules, which leaves
    // them on the administrator's baseline like a new user. The completion
    // dialog offers to close the program + tray so the reset takes effect on
    // the next launch (fresh first-run).
    function fullReset(allPrincipals) {
        root.statusLine = root.tr("status.full-reset-running", "Performing full reset…")
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
            ruleSetOfferAnswered: false,
            // "Reset everything" means the state a fresh install starts from,
            // and that includes not having agreed to anything yet.
            acceptedEulaVersion: 0
        })
        root.emitPrefs()
        Pure.clearModel(root.rulesModel)
        root.clearAllUnsavedChanges()
        // A stopped service answers none of the steps: it is started first. A
        // declined or failed start leaves the steps to say what they could not
        // clear, and the last step tries the service again.
        var steps = function() { _runResetSteps(allPrincipals === true, []) }
        _restartFailure = ""
        root.serviceStarter.startIfStoppedThen(steps, steps)
    }

    /// Why the restart at the end did not happen, for the completion dialog.
    property string _restartFailure: ""

    // Asks the shared step machine what comes next, runs that step, records
    // its outcome and repeats. The window's own preference reset above is the
    // one GUI-only part. The launcher elevates a refused step by itself, so
    // the machine is told the client can elevate.
    function _runResetSteps(allPrincipals, done) {
        var next = Pure.fullResetNext(true, done)
        if (next.action !== "run") {
            var finished = next.action === "finish"
            root.fullResetCompleteDialog.serviceCleared = finished && next.cleared
            // A reset stopped for want of rights never touched the service.
            root.fullResetCompleteDialog.serviceRestarted = !finished || next.restarted
            root.fullResetCompleteDialog.restartFailure = _restartFailure
            root.fullResetCompleteDialog.open()
            return
        }
        _runResetStep(next.step, allPrincipals, function(result) {
            done.push({ step: next.step, result: result })
            _runResetSteps(allPrincipals, done)
        })
    }

    // Runs one step and reports "ok" | "failed" | "forbidden" | "skipped". The
    // two cleanup calls are best-effort and never gate the rest.
    function _runResetStep(step, allPrincipals, report) {
        var viaBool = function(ok, code) {
            report(ok ? "ok" : (String(code || "") === "forbidden" ? "forbidden" : "failed"))
        }
        var fireAndForget = function(method, a, b) {
            if (!root.bridgeAvailable || typeof nrrNativeBridge[method] !== "function") {
                report("skipped")
                return
            }
            var c = nrrNativeBridge[method](a, b)
            root.rpc.registerRpcCallback(c, function() {})
            report("ok")
        }
        if (step === "clear-logs") fireAndForget("rpcLogsClear", false, true)
        else if (step === "reset-sidecar") fireAndForget("rpcSidecarReset")
        else if (step === "purge-principal-data") _purgePrincipalData(allPrincipals, viaBool)
        else if (step === "restart-service") _restartService(viaBool)
        else report("skipped")
    }

    // The last step: the service comes back on the cleared state, through the
    // same broker the Settings button uses (one prompt for stop and start). A
    // restart that fails keeps its reason for the completion dialog, which
    // offers to start the service from there.
    function _restartService(onComplete) {
        root.serviceStarter.restartThen(function() { onComplete(true) }, function(reason) {
            _restartFailure = String(reason || "")
            onComplete(false)
        })
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
        root.rpc.registerRpcCallback(c, function(ok, p, code) { onComplete(!!ok, code) })
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

    // Silent two-phase empty PresetImport into the caller's own rules, with no
    // review dialog (the caller's confirm already gated it). Not a full reset
    // step: an own empty book would cut the user off the baseline.
    // `onComplete(true)` only once the operation completed, else
    // `onComplete(false, errorCode)`.
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
            if (!ok || !p) { onComplete(false, code); return }
            var token = (p && p["confirmation-token"]) || ""
            var c2 = nrrNativeBridge.rpcMutationSubmit("preset-import", payload, false, token)
            root.rpc.registerLongRpcCallback(c2, function(ok2, p2, code2) {
                if (!ok2) { onComplete(false, code2); return }
                // The confirm only accepts the change; its verdict is on the
                // operation record.
                root.rpc.readMutationOutcome(p2, root.rpc.settleByPreview("preset-import", payload),
                    function(failure) {
                        if (failure !== "") console.log("full-reset: empty rules refused:", failure)
                        onComplete(failure === "", failure)
                    })
            })
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
