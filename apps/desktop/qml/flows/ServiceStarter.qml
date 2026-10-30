import QtQuick 2.15

// Brings the background service up and calls back once it answers on its
// channel: running to the service manager is not yet listening. One copy for
// every flow that needs a live service — the full reset ends with a restart,
// and a rule-set load starts a stopped service before it applies. The start
// goes through the same controller (and broker) as the Settings buttons, so it
// asks for administrator approval exactly when they would.
QtObject {
    id: serviceStarter

    /// The ApplicationWindow: its backend status says when the service answers.
    property var root

    property string _op: ""
    property bool _opDone: false
    property string _failure: ""
    /// Every flow waiting on the current action, `{ready, failed}`.
    property var _waiters: []

    function _ctl() {
        return (typeof nrrServiceController !== "undefined" && nrrServiceController)
            ? nrrServiceController : null
    }

    function _tr(key, fallback) {
        return root && typeof root.tr === "function" ? root.tr(key, fallback) : fallback
    }

    /// Starts a stopped service, then `onGoOn()` once it answers; a service
    /// that is starting, or running but not answering yet, is waited for.
    /// A running one that answers goes straight on. `onFailed(reason, kind)`
    /// when the start was declined, refused or timed out; `kind` is
    /// "not-installed" when there is no service to start.
    function startIfStoppedThen(onGoOn, onFailed) {
        var ctl = _ctl()
        if (!ctl || typeof ctl.startService !== "function") {
            onGoOn()
            return
        }
        // 1 = not installed in the controller's status vocabulary.
        if (parseInt(ctl.status) === 1) {
            if (typeof onFailed === "function")
                onFailed(_tr("errors.service-not-installed",
                    "The service is not installed. Install the NetRuleRouter package and try again."),
                    "not-installed")
            return
        }
        // Whatever is already bringing the service up serves this flow too.
        if (_op !== "") {
            _waiters = _waiters.concat([{ ready: onGoOn, failed: onFailed }])
            return
        }
        // 2 = stopped.
        if (parseInt(ctl.status) !== 2) {
            if (root && typeof root._routingBackendConnected === "function"
                    && !root._routingBackendConnected()) {
                _begin("wait", onGoOn, onFailed)
                return
            }
            onGoOn()
            return
        }
        _begin("start", onGoOn, onFailed)
        ctl.startService()
    }

    /// Waits, bounded, for a service that should be running to answer: the
    /// channel can lag the service manager right after a start.
    function waitForAnswerThen(onReady, onFailed) {
        if (_op !== "") {
            _waiters = _waiters.concat([{ ready: onReady, failed: onFailed }])
            return
        }
        _begin("wait", onReady, onFailed)
    }

    /// Stops and starts the service in one elevated action, so it comes back
    /// on whatever it now reads from disk; `onReady()` once it answers.
    function restartThen(onReady, onFailed) {
        var ctl = _ctl()
        if (!ctl || typeof ctl.restartService !== "function") {
            onFailed("")
            return
        }
        _begin("restart", onReady, onFailed)
        ctl.restartService()
    }

    function _begin(op, onReady, onFailed) {
        // A flow already waiting is told it was superseded, never dropped:
        // its callbacks would otherwise fire on the newer action's outcome.
        if (_op !== "") {
            _failure = _tr("status.service-action-superseded",
                "Another service action started before this one finished.")
            _finish(false)
        }
        _watch.stop()
        _op = op
        _opDone = false
        _failure = ""
        _waiters = [{ ready: onReady, failed: onFailed }]
        _watch.attempts = 0
        _watch.restart()
    }

    function _finish(ok) {
        _watch.stop()
        var waiters = _waiters
        var reason = _failure
        _waiters = []
        _op = ""
        for (var i = 0; i < waiters.length; i += 1) {
            var cb = ok ? waiters[i].ready : waiters[i].failed
            if (typeof cb !== "function") continue
            if (ok) cb()
            else cb(reason)
        }
    }

    // Polls the service until it answers; see `_tick`.
    property Timer _watch: Timer {
        interval: 500
        repeat: true
        property int attempts: 0
        onTriggered: serviceStarter._tick()
    }

    function _operationCompleted(operation, success, errorMessage, errorCode) {
        if (_op === "" || String(operation) !== _op) return
        if (success) {
            _opDone = true
            return
        }
        _failure = (root && typeof root.serviceOperationErrorText === "function")
            ? root.serviceOperationErrorText(errorCode, errorMessage)
            : String(errorMessage || "")
        _finish(false)
    }

    function _uacDeclined(operation) {
        if (_op === "" || String(operation) !== _op) return
        _failure = _tr("progress.service-uac-declined",
            "Administrator prompt declined — operation cancelled.")
        _finish(false)
    }

    // Polls rather than waits on one signal: the channel's state is the
    // window's backend status, which a poll refreshes.
    function _tick() {
        var ctl = _ctl()
        var st = ctl ? parseInt(ctl.status) : 0
        // An administrator prompt may wait on the user for as long as
        // they read it; the action bounds itself and reports its end.
        if (!_opDone && ctl && ctl.busy === true) {
            _watch.attempts = 0
            return
        }
        _watch.attempts += 1
        // A restart is judged only once the controller says it is done:
        // until the old process goes, the channel still reads connected.
        var settled = _op !== "restart" || _opDone
        if (settled && root._routingBackendConnected()) {
            _finish(true)
            return
        }
        if (_watch.attempts % 2 === 0 && typeof root.refreshBackendStatus === "function")
            root.refreshBackendStatus()
        // 3 = start pending, 4 = running: anything else once the action is
        // over means the start did not happen.
        var gaveUp = st !== 3 && st !== 4 && _watch.attempts >= 6
        if (gaveUp || _watch.attempts >= 60) {
            if (_failure === "") {
                _failure = _tr("status.service-did-not-answer",
                    "The service did not start answering in time.")
            }
            _finish(false)
        }
    }

    property Connections _ops: Connections {
        target: serviceStarter._ctl()
        ignoreUnknownSignals: true
        function onOperationCompleted(operation, success, errorMessage, errorCode) {
            serviceStarter._operationCompleted(operation, success, errorMessage, errorCode)
        }
        function onUacDeclined(operation) {
            serviceStarter._uacDeclined(operation)
        }
    }

}
