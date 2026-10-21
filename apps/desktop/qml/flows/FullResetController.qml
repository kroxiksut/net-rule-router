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
        _startServiceThen(function() { _runResetSteps(allPrincipals === true, []) })
    }

    // A stopped service answers none of the steps, so the reset would only
    // report what it could not clear: it is started first, and the last step
    // stops it again. A declined or failed start leaves the steps to say so.
    function _startServiceThen(next) {
        var ctl = (typeof nrrServiceController !== "undefined") ? nrrServiceController : null
        // 2 = stopped in the controller's status vocabulary.
        if (!ctl || parseInt(ctl.status) !== 2 || typeof ctl.startService !== "function") {
            next()
            return
        }
        ctl.startService()
        _startWatch.attempts = 0
        _startWatch.onDone = next
        _startWatch.restart()
    }

    // Waits for the started service to answer on its channel, not only to run.
    property Timer _startWatch: Timer {
        id: _startWatch
        interval: 500
        repeat: true
        property int attempts: 0
        property var onDone: null
        onTriggered: {
            attempts += 1
            var ctl = (typeof nrrServiceController !== "undefined") ? nrrServiceController : null
            var st = ctl ? parseInt(ctl.status) : 0
            // 3 = start pending, 4 = running: anything else once the prompt
            // is gone means the start was declined or failed.
            var gaveUp = !(ctl && ctl.busy === true) && st !== 3 && st !== 4 && attempts >= 3
            if (root._routingBackendConnected() || gaveUp || attempts >= 40) {
                stop()
                var cb = onDone
                onDone = null
                if (typeof cb === "function") cb()
            }
        }
    }

    // Asks the shared step machine what comes next, runs that step, records
    // its outcome and repeats. The window's own preference reset above is the
    // one GUI-only part. The launcher elevates a refused step by itself, so
    // the machine is told the client can elevate.
    function _runResetSteps(allPrincipals, done) {
        var next = Pure.fullResetNext(true, done)
        if (next.action !== "run") {
            root.fullResetCompleteDialog.serviceCleared = next.action === "finish" && next.cleared
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
        else if (step === "apply-empty-rules") applyEmptyRules(viaBool)
        else if (step === "stop-service") _stopService(viaBool)
        else report("skipped")
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

    // Silent two-phase empty PresetImport: makes the service's active
    // revision empty (post-install state) WITHOUT opening the review dialog
    // (the Full-reset confirm already gated the action). Same payload shape
    // as `startBothRoutesPresetImportReviewFlow`; the confirm phase carries
    // the dry-run token. Non-admin → confirm Forbidden → launcher R3 elevates
    // (UAC) and retries; `onComplete(true)` only once the operation completed,
    // else `onComplete(false, errorCode)`.
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
