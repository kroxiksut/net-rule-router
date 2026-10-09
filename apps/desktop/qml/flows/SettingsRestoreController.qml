import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller for "Restore my settings": the user's route policy and
// notice mutes, recorded in their own settings file after every write of
// theirs the service confirmed, and offered back when a service that was
// reinstalled or had its data reset answers without them.
//
// Nothing is written unasked. On connect the record is compared with the
// service; a difference raises one card, and only its action sends the one
// write that brings the settings back. The stability settings keep their own
// per-key flow (`ServiceIntentController`).
QtObject {
    id: settingsRestoreController

    /// The ApplicationWindow: RPC, preferences, the notice stack, the status line.
    property var root

    /// The recorded route policy as last read or written (wire key -> value).
    property var recordedRoutePolicy: ({})

    /// The id of the card on screen, "" when none. A new id per connect: a
    /// dismissed card asks again on the next connect only.
    property string _cardId: ""

    property var _checkTimer: null

    /// How long a connect is given to settle before comparing: the parked
    /// delivery and the binding resync run first, and they are the user's
    /// newer word or a copy of it.
    readonly property int _settleMs: 4000

    function _rpc() {
        return (root && root.bridgeAvailable && root.rpc) ? root.rpc : null
    }

    /// The bindings the record holds, `{ primary, secondary }`, for the resync
    /// of a service that has none while the preferences lost theirs.
    function recordedBindings() {
        var rp = recordedRoutePolicy || {}
        return { primary: rp.primary || null, secondary: rp.secondary || null }
    }

    /// Re-reads the record; `done(intent)` gets the whole intent object, or
    /// null when the file could not be read.
    function refreshRecord(done) {
        var rpc = _rpc()
        var corr = (rpc && typeof rpc.rpcUserSettingsIntentGet === "function")
            ? rpc.rpcUserSettingsIntentGet() : ""
        if (!corr) { if (done) done(null); return }
        rpc.registerRpcCallback(corr, function(ok, p) {
            var intent = (ok && p && p["service-intent"]) ? p["service-intent"] : null
            if (intent !== null) {
                var rp = intent["route-policy"]
                recordedRoutePolicy = (rp && typeof rp === "object") ? rp : ({})
            }
            if (done) done(intent)
        })
    }

    /// A route-policy write of the user's the service just confirmed: the keys
    /// it named, with the values it sent. A key it dropped (an unbinding) is
    /// dropped from the record.
    function recordRoutePolicy(req, keys) {
        var merge = {}
        var list = keys || []
        for (var i = 0; i < list.length; i += 1) {
            var value = (req || {})[list[i]]
            merge[list[i]] = (value === undefined) ? null : value
        }
        if (list.length === 0) return
        recordedRoutePolicy = Pure.routePolicyIntentAfterWrite(recordedRoutePolicy, req, list)
        _record({ "namespace": "route-policy", "merge": merge })
    }

    /// The user's mutes as the service holds them after a write of theirs.
    function recordMutes(mutes) {
        if (!Array.isArray(mutes)) return
        _record({ "namespace": "notice-mutes", "value": mutes })
    }

    function _record(payload) {
        var rpc = _rpc()
        if (!rpc || typeof rpc.rpcUserSettingsIntentRecord !== "function") return
        var corr = rpc.rpcUserSettingsIntentRecord(payload)
        if (!corr) return
        rpc.registerRpcCallback(corr, function(ok, p, code) {
            // A read-only session records nothing on purpose; anything else is
            // worth a line for triage, not a word to the user.
            if (!ok && String(code || "") !== "user-settings-read-only")
                console.log("settings record: not written:", code)
        })
    }

    /// The service (re)connected: compare once it has settled.
    function checkOnConnect() {
        if (_checkTimer === null) {
            _checkTimer = Qt.createQmlObject(
                "import QtQuick 2.15; Timer { repeat: false }", root,
                "settingsRestoreCheckTimer")
            _checkTimer.triggered.connect(function() { settingsRestoreController._check() })
        }
        _checkTimer.interval = _settleMs
        _checkTimer.restart()
    }

    /// Reads the record, the service's row and its mutes; `done(state)` gets
    /// `{ intent, policy, adapters, mutes }`, or null when any read failed.
    function _readAll(done) {
        var rpc = _rpc()
        if (!rpc || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") {
            done(null)
            return
        }
        refreshRecord(function(intent) {
            if (intent === null) { done(null); return }
            var snapCorr = nrrNativeBridge.rpcSnapshotInitialGet()
            if (!snapCorr) { done(null); return }
            rpc.registerRpcCallback(snapCorr, function(ok, p) {
                if (!ok || !p) { done(null); return }
                var policy = (p["route-policy"] || p.routePolicy) || {}
                var ids = Pure.presentAdapterIds(p)
                var mutesCorr = (typeof rpc.rpcBlockNoticeMutesList === "function")
                    ? rpc.rpcBlockNoticeMutesList() : ""
                if (!mutesCorr) { done(null); return }
                rpc.registerRpcCallback(mutesCorr, function(okM, pm) {
                    if (!okM || !pm) { done(null); return }
                    done({ intent: intent, policy: policy, adapters: ids,
                           mutes: pm.mutes || [] })
                })
            })
        })
    }

    /// What the service lacks: route-policy keys, and the mutes to bring back.
    function _missing(state) {
        return {
            keys: Pure.routePolicyIntentDivergence(state.intent["route-policy"] || {}, state.policy),
            mutes: Pure.noticeMutesToRestore(state.intent["notice-mutes"], state.mutes, Date.now())
        }
    }

    // Each outcome leaves one line in the launcher log: "no card" has to be
    // told apart from "could not compare" when someone asks why.
    function _check() {
        if (!root._routingBackendConnected()) {
            console.log("settings-restore: not compared, service not connected")
            return
        }
        _readAll(function(state) {
            if (state === null) {
                console.log("settings-restore: not compared, a read failed")
                return
            }
            var missing = _missing(state)
            _dropCard()
            console.log("settings-restore: compared, missing keys=" + missing.keys.join(",")
                + " mutes=" + missing.mutes.length)
            if (missing.keys.length === 0 && missing.mutes.length === 0) return
            _raiseCard(missing)
        })
    }

    /// The name a setting is listed under on the card.
    function _settingName(key) {
        if (key === "primary" || key === "secondary") return root.routeLabel(key)
        var label = (root.offlinePendingController
                && typeof root.offlinePendingController._offlineRoutingKeyLabel === "function")
            ? String(root.offlinePendingController._offlineRoutingKeyLabel("route-policy", key))
            : String(key)
        return label !== String(key) ? label
            : root.tr("notifications.settings-lost.other-setting", "another routing setting")
    }

    function _names(missing) {
        var names = []
        for (var i = 0; i < missing.keys.length; i += 1) {
            var name = _settingName(missing.keys[i])
            if (names.indexOf(name) < 0) names.push(name)
        }
        if (missing.mutes.length > 0)
            names.push(root.tr("notifications.settings-lost.mutes", "hidden notifications"))
        var shown = names.slice(0, 3).join(", ")
        if (names.length > 3) {
            shown += " " + root.tr("notifications.settings-lost.more", "and {count} more")
                .replace("{count}", String(names.length - 3))
        }
        return shown
    }

    function _raiseCard(missing) {
        _cardId = "settings-lost:" + String(Date.now())
        root.notificationsController._addPushNotice({
            "id": _cardId,
            "kind": "settings-lost",
            "severity": "warning",
            "dismissible": true,
            "title": root.tr("notifications.settings-lost.title",
                "The service does not have your settings"),
            "body": root.tr("notifications.settings-lost.body",
                    "This happens after the service was reinstalled or its data was reset. Missing: {settings}.")
                .replace("{settings}", _names(missing)),
            "actionKey": "restore-settings",
            "actionText": root.tr("notifications.settings-lost.action", "Restore my settings")
        })
    }

    function _dropCard() {
        if (_cardId === "") return
        root.notificationsController._dropPushNotice(_cardId)
        _cardId = ""
    }

    /// "Restore my settings": one apply-only write of the route policy, then the
    /// mutes. An ordinary user write, so it is recorded again.
    function restore() {
        _readAll(function(state) {
            if (state === null) {
                root.statusLine = root.tr("status.settings-restore-read-failed",
                    "Could not read your settings or the service's, so nothing was changed.")
                return
            }
            var intentPolicy = state.intent["route-policy"] || {}
            var plan = Pure.routePolicyRestorePlan(intentPolicy, state.policy, state.adapters)
            var mutes = Pure.noticeMutesToRestore(state.intent["notice-mutes"], state.mutes, Date.now())
            var finish = function(ok, code) {
                if (!ok) {
                    var label = (typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(code) : String(code || "")
                    root.statusLine = root.tr("status.settings-restore-failed",
                        "Could not restore your settings: ") + label
                    return
                }
                var cardId = _cardId
                _dropCard()
                if (cardId !== "") root.noticeLedger.record(cardId)
                root.statusLine = _outcome(plan, mutes)
                root.serviceIntentReplayed()
            }
            var restoreMutes = function() {
                _restoreMutes(mutes, 0, finish)
            }
            if (plan.request === null) { restoreMutes(); return }
            root.routePolicyController.mutateRoutePolicy(function(cur) {
                // Planned again over the row this write is built on: another
                // write may have landed since the card was read.
                return Pure.routePolicyRestorePlan(intentPolicy, cur, state.adapters).request
            }, function(ok, code) {
                if (!ok) { finish(false, code); return }
                restoreMutes()
            }, "user:restore-settings")
        })
    }

    function _restoreMutes(mutes, at, finish) {
        if (at >= mutes.length) { finish(true, ""); return }
        var rpc = _rpc()
        var corr = (rpc && typeof rpc.rpcBlockNoticeMutesSet === "function")
            ? rpc.rpcBlockNoticeMutesSet(mutes[at]) : ""
        if (!corr) { finish(false, "bridge-unavailable"); return }
        rpc.registerRpcCallback(corr, function(ok, p, code) {
            if (!ok) { finish(false, code); return }
            if (at === mutes.length - 1 && p) recordMutes(p.mutes || [])
            _restoreMutes(mutes, at + 1, finish)
        })
    }

    /// The status line after a restore: done, and any adapter left out.
    function _outcome(plan, mutes) {
        var restoredAny = (plan.keys.length > 0 || mutes.length > 0)
        var names = []
        for (var i = 0; i < plan.missing.length; i += 1) names.push(String(plan.missing[i].name))
        var missingLine = root.tr("status.settings-restore-adapter-missing",
                "Not restored: the adapter {name} is not on this computer now.")
            .replace("{name}", names.join(", "))
        if (!restoredAny) {
            // Nothing went because its adapter is gone: that is the news.
            return names.length > 0 ? missingLine
                : root.tr("status.settings-restore-nothing", "The service already has your settings.")
        }
        var line = root.tr("status.settings-restored", "Your settings were restored.")
        return names.length > 0 ? line + " " + missingLine : line
    }
}
