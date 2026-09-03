import QtQuick 2.15

// Non-visual controller for SERVICE INTENT: what the user actually decided
// about the settings the service owns, and pushing that back into a service
// that disagrees.
//
// Extracted from Main.qml (thin-shell rule). This is what makes the service the
// source of truth about STATE without making it the source of truth about
// INTENT: a wiped or freshly installed state DB answers with its own defaults,
// and replaying the record is what stops those defaults from silently becoming
// the user's settings.
//
// `serviceIntentReplayed` stays a signal ON THE WINDOW rather than moving here:
// two settings panels listen for it in `Connections { target: root }` blocks
// that also handle unrelated shell signals, and splitting one such block across
// two targets buys nothing. The controller raises it through `root`.
QtObject {
    id: serviceIntentController

    /// The ApplicationWindow: the preferences the record lives in, the RPC
    /// transport, and the signal the panels listen for.
    property var root

    /// The service-owned settings the user has actually decided about, as a
    /// map of WIRE key -> value. Distinct from the display mirror above: the
    /// mirror records what the service last said, this records what the user
    /// asked for. Only the second one may be replayed back to the service.
    /// Degrades to "nothing recorded" on any parse error.
    function _readServiceIntent() {
        var raw = String((root.prefs && root.prefs.serviceIntentJson) || "")
        if (raw === "") return {}
        try {
            var o = JSON.parse(raw)
            if (!o || typeof o !== "object") return {}
            return (o["stability"] && typeof o["stability"] === "object") ? o["stability"] : {}
        } catch (e) {
            return {}
        }
    }

    /// Record what the user asked a service-owned setting to be. Called from
    /// the single write path (`root.applyServiceStabilityPatch`) for user-originated
    /// changes only, so a read-back, a replay or an internal re-seed can never
    /// masquerade as a decision the user made.
    function _recordServiceIntent(values) {
        if (!values || typeof values !== "object") return
        var intent = _readServiceIntent()
        var changed = false
        for (var key in values) {
            var value = values[key]
            if (value === undefined) continue
            if (JSON.stringify(intent[key]) === JSON.stringify(value)) continue
            intent[key] = value
            changed = true
        }
        if (!changed) return
        root.prefs.serviceIntentJson = JSON.stringify({ "stability": intent })
        root.emitPrefs()
    }

    /// Push the user's recorded decisions back into a service that disagrees
    /// with them. This is what makes a service the source of truth about
    /// *state* without making it the source of truth about *intent*: a wiped
    /// or freshly installed state DB answers with its own defaults, and
    /// without this the GUI would adopt those defaults and the user's settings
    /// would silently disappear.
    ///
    /// Keys the user parked while offline are skipped — the pending-changes
    /// dialog owns those, and replaying them here would apply changes the user
    /// has not confirmed yet.
    /// Attempts left in the current replay run, and the backoff between them.
    /// A connect lands while the service is still migrating its database and
    /// arming enforcement, so its IPC is at its slowest exactly when we ask —
    /// a single attempt loses the user's settings to that root.
    property int _serviceIntentAttemptsLeft: 0
    readonly property var _serviceIntentBackoffMs: [2000, 6000, 15000]
    property var _serviceIntentRetryTimer: null

    /// Set when the user changes a service-owned setting themselves. A replay
    /// that fires afterwards would push the older recorded value over the
    /// fresher one, so it stands down instead.
    property bool _serviceIntentSupersededByUser: false

    function replayServiceIntentToService() {
        _serviceIntentSupersededByUser = false
        _serviceIntentAttemptsLeft = _serviceIntentBackoffMs.length
        _attemptServiceIntentReplay()
    }

    function _attemptServiceIntentReplay() {
        var intent = _readServiceIntent()
        var hasIntent = false
        for (var probe in intent) { hasIntent = true; break }
        if (!hasIntent) {
            // Not a failure, but not nothing either: it means no setting the
            // user changed while the service was down is waiting to be
            // delivered. Told apart from "the replay ran" only by this line —
            // and telling them apart is the whole triage.
            console.log("service-intent replay: nothing recorded to replay")
            root.serviceIntentReplayed()
            return
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            _scheduleServiceIntentRetry("bridge-unavailable")
            return
        }
        var parked = (typeof root._readPendingOffline === "function")
            ? (root._readPendingOffline()["stability"] || {}) : {}
        var getCorr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(getCorr, function(ok, payload, code, msg) {
            if (!ok) {
                _scheduleServiceIntentRetry("read-failed:" + String(code || ""))
                return
            }
            var live = payload || {}
            var patch = {}
            var diverged = false
            for (var key in intent) {
                if (parked.hasOwnProperty(key)) continue
                if (JSON.stringify(live[key]) === JSON.stringify(intent[key])) continue
                patch[key] = intent[key]
                diverged = true
            }
            if (!diverged) {
                console.log("service-intent replay: the service already holds every",
                            "recorded intent — nothing to push")
                _serviceIntentAttemptsLeft = 0
                root.serviceIntentReplayed()
                return
            }
            console.log("service-intent replay: pushing", JSON.stringify(patch))
            root.applyServiceStabilityPatch(patch, function(ok2, code2) {
                if (ok2) {
                    _serviceIntentAttemptsLeft = 0
                    root.serviceIntentReplayed()
                    return
                }
                _scheduleServiceIntentRetry("write-failed:" + String(code2 || ""))
            }, "intent-replay")
        })
    }

    /// Retry unless we are out of attempts or the reason to replay is gone.
    /// Emits `root.serviceIntentReplayed()` on the last failure too: the panels
    /// wait on that signal to re-read, and leaving them waiting forever would
    /// be worse than reporting a service we could not reconcile with.
    function _scheduleServiceIntentRetry(reason) {
        var attemptsMade = _serviceIntentBackoffMs.length - _serviceIntentAttemptsLeft
        if (_serviceIntentSupersededByUser) {
            console.log("service-intent replay stood down after", attemptsMade,
                        "attempt(s): the user changed the setting themselves")
            _serviceIntentAttemptsLeft = 0
            root.serviceIntentReplayed()
            return
        }
        if (_serviceIntentAttemptsLeft <= 1 || !root._routingBackendConnected()) {
            console.log("service-intent replay gave up after", attemptsMade + 1,
                        "attempt(s), last reason:", reason)
            _serviceIntentAttemptsLeft = 0
            root.serviceIntentReplayed()
            return
        }
        var delay = _serviceIntentBackoffMs[attemptsMade]
        _serviceIntentAttemptsLeft -= 1
        console.log("service-intent replay attempt", attemptsMade + 1, "failed (",
                    reason, ") — retrying in", delay, "ms")
        if (_serviceIntentRetryTimer === null) {
            _serviceIntentRetryTimer = Qt.createQmlObject(
                "import QtQuick 2.15; Timer { repeat: false }", window,
                "serviceIntentRetryTimer")
            _serviceIntentRetryTimer.triggered.connect(function() {
                if (_serviceIntentSupersededByUser || !root._routingBackendConnected()) {
                    console.log("service-intent replay: retry abandoned —",
                                _serviceIntentSupersededByUser
                                    ? "the user changed the setting themselves"
                                    : "the service is not connected")
                    _serviceIntentAttemptsLeft = 0
                    root.serviceIntentReplayed()
                    return
                }
                _attemptServiceIntentReplay()
            })
        }
        _serviceIntentRetryTimer.interval = delay
        _serviceIntentRetryTimer.restart()
    }
}
