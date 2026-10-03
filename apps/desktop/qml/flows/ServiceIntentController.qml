import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller for SERVICE INTENT: what the user actually decided
// about the settings the service owns, and what to do when the service
// disagrees.
//
// The service is the source of truth about STATE, not about INTENT: a wiped or
// freshly installed state DB answers with its own defaults, and the record is
// what lets the GUI show that difference instead of silently adopting them.
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
    /// asked for. Only the second one is compared with the service.
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

    /// Recorded intents the service holds otherwise, as wire key ->
    /// { mine, service }. The settings panels show these instead of the GUI
    /// silently rewriting a machine-wide value.
    property var divergence: ({})

    /// Whether this GUI process itself runs elevated. A live broker session
    /// does not count.
    function _appElevated() {
        if (typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.isElevated !== "function")
            return false
        return !!nrrNativeBridge.isElevated()
    }

    /// Record what the user asked a service-owned setting to be, once the
    /// service CONFIRMED the write merged onto `before`. Called from the single
    /// write path (`root.applyServiceStabilityPatch`) for user-originated
    /// changes only, so a read-back, a replay or an internal re-seed can never
    /// masquerade as a decision the user made. A refused or unanswered write
    /// records nothing: it would come back on every start.
    function _recordServiceIntentAfterWrite(partial, before) {
        var next = Pure.stabilityIntentAfterWrite(_readServiceIntent(), partial || {},
                                                  before || {}, _appElevated())
        if (next !== null) {
            root.prefs.serviceIntentJson = JSON.stringify({ "stability": next })
            root.emitPrefs()
        }
        _dropDivergence(partial)
    }

    /// The user just chose these keys themselves; what the service holds now is
    /// their word, not an administrator's.
    function _dropDivergence(values) {
        var next = {}
        var dropped = false
        for (var key in divergence) {
            if (values && values.hasOwnProperty(key)) { dropped = true; continue }
            next[key] = divergence[key]
        }
        if (dropped) divergence = next
    }

    /// "Apply my choice" on a divergence line. An ordinary user write, so the
    /// launcher may ask for administrator approval: the click is the gesture.
    function applyMine(key) {
        var row = divergence[key]
        if (!row) return
        var partial = {}
        partial[key] = row["mine"]
        root.applyServiceStabilityPatch(partial, function(ok, code) {
            if (!ok) {
                root.statusLine = root.tr("status.route-policy-failed",
                        "Could not save the setting to the service: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                return
            }
            // The panels re-read on this signal and show the value just applied.
            root.serviceIntentReplayed()
        }, "user:intent-apply")
    }

    /// "Keep the service value" on a divergence line: forget the recorded
    /// choice, so the line does not come back on the next connect.
    function keepServiceValue(key) {
        var next = Pure.stabilityIntentWithout(_readServiceIntent(), key)
        if (next !== null) {
            root.prefs.serviceIntentJson = JSON.stringify({ "stability": next })
            root.emitPrefs()
        }
        var gone = {}
        gone[key] = true
        _dropDivergence(gone)
    }

    /// Attempts left in the current reconcile run, and the backoff between them.
    /// A connect lands while the service is still migrating its database and
    /// arming enforcement, so its IPC is at its slowest exactly when we ask.
    property int _serviceIntentAttemptsLeft: 0
    readonly property var _serviceIntentBackoffMs: [2000, 6000, 15000]
    property var _serviceIntentRetryTimer: null

    /// Set when the user changes a service-owned setting themselves: their
    /// write settles the difference, so a pending retry stands down.
    property bool _serviceIntentSupersededByUser: false

    /// Compare the user's recorded decisions with the service on connect.
    /// Nothing is written back: a machine-wide value is never replayed unasked,
    /// so every difference is shown (`divergence`) for the user to settle.
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
            // Logged so triage can tell "nothing recorded" from "the read ran".
            console.log("service-intent reconcile: nothing recorded to compare")
            divergence = ({})
            root.serviceIntentReplayed()
            return
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        // Only a key this OS's service applies can differ from it. No retry
        // when none does: a retry loop exists to outlive an outage, and this is
        // not one.
        intent = root.stabilityPatchForPlatform(intent)
        if (Object.keys(intent).length === 0) return
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
            divergence = Pure.stabilityIntentDivergence(intent, payload || {}, parked)
            console.log("service-intent reconcile: recorded intents the service holds otherwise:",
                        Object.keys(divergence).length)
            _serviceIntentAttemptsLeft = 0
            root.serviceIntentReplayed()
        })
    }

    /// Retry unless we are out of attempts or the reason to compare is gone.
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
