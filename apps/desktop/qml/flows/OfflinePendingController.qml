import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller for the "apply the routing changes you made while the
// service was stopped?" flow. Extracted from Main.qml (thin-shell rule): the
// shell keeps the shared park-storage primitives (`_readPendingOffline` /
// `_writePendingOffline` / `_recordOfflineRoutingIntent`, which the route-policy
// apply path and RoutingSettings also drive) and the public
// `offlinePendingApplied()` signal (RoutingSettings connects to it); this
// controller owns the offer/apply/discard flow and its localized value labels.
//
// Main.qml instantiates one, injects itself as `root`, and exposes it as
// `root.offlinePendingController`; the shared post-connect backlog dialog
// drives apply/discard through it. Window-scope symbols are reached through
// `root` (properties, functions, the RPC transport via `root.rpc`, and the
// signal via `root.offlinePendingApplied()`).
// `nrrNativeBridge` is a global QML context property, referenced bare.
QtObject {
    id: offlinePendingController
    property var root

    /// True while an offer is in flight or the dialog is open — prevents the
    /// 3 s health poll from opening the dialog twice concurrently.
    property bool _offlinePendingDialogActive: false

    function _offlineOnOffLabel(v) {
        return v === true
            ? root.tr("dialog.offline-pending.value-on", "On")
            : root.tr("dialog.offline-pending.value-off", "Off")
    }

    function _offlineProtocolsLabel(mask) {
        var m = (mask | 0) & 0x7F
        if (m === 0x7F) return root.tr("dialog.offline-pending.protocols-all", "All protocols")
        if (m === 0) return root.tr("dialog.offline-pending.protocols-none", "None")
        var defs = [
            { bit: 1, slug: "tcp" }, { bit: 2, slug: "udp" }, { bit: 4, slug: "icmp" },
            { bit: 8, slug: "igmp" }, { bit: 16, slug: "gre" }, { bit: 32, slug: "esp" },
            { bit: 64, slug: "other" }
        ]
        var names = []
        for (var i = 0; i < defs.length; i += 1) {
            if ((m & defs[i].bit) !== 0) {
                names.push(root.tr("settings.routing.kill-switch.protocols." + defs[i].slug,
                    defs[i].slug === "icmp" ? "ICMP (ping)"
                        : (defs[i].slug === "other" ? "Other" : defs[i].slug.toUpperCase())))
            }
        }
        return names.join(", ")
    }

    /// Existing locale label of the setting a wire key controls (reused so the
    /// dialog reads in the user's language). Falls back to the raw key.
    function _offlineRoutingKeyLabel(namespace, key) {
        switch (key) {
            case "mode":
                return root.tr("settings.routing.default-route.title", "Default route for unmatched traffic")
            case "block-secondary-when-unavailable":
                return root.tr("settings.routing.kill-switch.title", "Leak protection")
            case "kill-switch-enabled":
                return root.tr("settings.routing.kill-switch.enable-label", "Enable the kill-switch")
            case "kill-switch-fail-closed":
                return root.tr("settings.routing.kill-switch.failure-mode.label",
                    "If the additional adapter can't be found")
            case "kill-switch-protocols":
                return root.tr("settings.routing.kill-switch.protocols.label", "Protocols leak protection cuts")
            case "kill-switch-block-all":
                return root.tr("settings.routing.kill-switch.block-all-label",
                    "When the additional adapter is unavailable, block ALL traffic")
            case "allow-dns-over-primary":
                return root.tr("settings.routing.kill-switch.allow-dns-label",
                    "Allow name resolution over the main link while blocked")
            case "include-subdomains":
                return root.tr("settings.routing-behavior.include-subdomains.label",
                    "Also cover subdomains for domain rules")
            case "shared-ip-policy":
                return root.tr("settings.routing-behavior.shared-ip.label",
                    "When a routed domain shares an IP address with other sites")
            case "mode-a-coverage-strategy":
                return root.tr("settings.routing.mode-a-coverage.label",
                    "When the additional route is unavailable (Mode A)")
            case "resolve-hosts-bypass":
                return root.tr("settings.routing.hosts-bypass.label",
                    "Resolve routed domains bypassing the hosts file")
            case "fake-ip-enabled":
                return root.tr("settings.routing.fake-ip.label",
                    "Route sites over virtual addresses (fake-IP)")
            case "fake-ip-udp-relay":
                return root.tr("settings.routing.fake-ip-udp-relay.label",
                    "Fake-IP UDP relay (experimental)")
            case "fake-ip-instant-rst":
                return root.tr("settings.routing.fake-ip-instant-rst.label",
                    "Instant reset when the additional route is unavailable")
            case "dns-via-secondary":
                return root.tr("settings.routing.dns-via-secondary.label",
                    "DNS through the tunnel")
            case "dns-fast-answers":
                return root.tr("settings.routing.dns-fast-answers.label",
                    "Fast DNS answers")
            case "doh-lockdown-enabled":
                return root.tr("settings.routing.doh-lockdown.label",
                    "Block browser DoH/DoT")
            case "doh-lockdown-scope":
                return root.tr("settings.routing.doh-lockdown.scope-label", "When to apply")
            case "browser-history-auto-seed":
                return root.tr("diag.cache.auto-seed-label",
                    "Seed the cache from browser history automatically at service start")
            case "enforcement-mode":
                return root.tr("settings.routing.enforcement-mode.label", "How routed traffic is enforced")
            case "secondary-liveness-window-secs":
                return root.tr("settings.routing.liveness-window.label", "Secondary tunnel liveness window")
            case "rule-scope-service-driven":
                return root.tr("settings.diagnostics.rule-scope.heading", "When routing rules are enforced")
            case "routing-stop-policy":
                return root.tr("settings.diagnostics.routing-stop.heading",
                    "When routing is paused or the service stops")
            case "verbose-logging":
                return root.tr("settings.diagnostics.service-stability.verbose.label",
                    "Verbose service logging")
            case "conn-trace-ndjson":
                return root.tr("settings.diagnostics.conn-trace.ndjson.label",
                    "Write connection trace to service log (NDJSON)")
            case "conn-trace-gui":
                return root.tr("settings.diagnostics.conn-trace.gui.label",
                    "Show connection trace in diagnostics (GUI)")
            case "cache-refresh-interval-secs":
                return root.tr("settings.diagnostics.cache-refresh.heading",
                    "Address cache refresh")
            case "ipc-accept-policy":
                return root.tr("settings.diagnostics.service-stability.title",
                    "Service stability")
        }
        return String(key)
    }

    /// Human-readable display of a parked value (localised On/Off, option
    /// labels, protocol summaries) reusing existing option locale keys.
    function _offlineRoutingValueLabel(namespace, key, value) {
        switch (key) {
            case "mode":
                return (typeof root.behaviorModeLabel === "function")
                    ? root.behaviorModeLabel(String(value)) : String(value)
            case "shared-ip-policy":
                return root.tr("settings.routing-behavior.shared-ip.option-" + String(value), String(value))
            case "mode-a-coverage-strategy":
                return root.tr("settings.routing.mode-a-coverage.option-" + String(value), String(value))
            case "doh-lockdown-scope":
                return root.tr("settings.routing.doh-lockdown.scope-" + String(value), String(value))
            case "enforcement-mode":
                return root.tr("settings.routing.enforcement-mode.option-" + String(value),
                    String(value) === "resolver"
                        ? "Local DNS resolver (Mode B)" : "Reactive kill-switch (Mode A)")
            case "kill-switch-fail-closed":
                return (value === true)
                    ? root.tr("settings.routing.kill-switch.failure-mode.option-fail-closed",
                        "Block traffic (recommended)")
                    : root.tr("settings.routing.kill-switch.failure-mode.option-fail-open",
                        "Allow traffic and warn me")
            case "routing-stop-policy":
                return (String(value) === "persist")
                    ? root.tr("dialog.offline-pending.stop-policy-persist", "Keep matched routes")
                    : root.tr("dialog.offline-pending.stop-policy-teardown", "Remove all routes (default)")
            case "secondary-liveness-window-secs": {
                var s = value | 0
                return (s === 0)
                    ? root.tr("settings.routing.liveness-window.option-disabled", "Disabled (default)")
                    : String(s) + " " + root.tr("settings.routing.liveness-window.seconds-unit", "seconds")
            }
            case "kill-switch-protocols":
                return _offlineProtocolsLabel(value | 0)
            case "cache-refresh-interval-secs":
                return String(Math.round((value | 0) / 60)) + " "
                    + root.tr("settings.diagnostics.cache-refresh.unit", "min")
            case "ipc-accept-policy": {
                var kind = String((value && (value["kind"] || value.kind)) || "recoverable")
                return (kind === "critical")
                    ? root.tr("settings.diagnostics.service-stability.ipc.policy.critical.label",
                        "Critical (fail-fast)")
                    : root.tr("settings.diagnostics.service-stability.ipc.policy.recoverable.label",
                        "Recoverable (recommended)")
            }
        }
        if (value === true || value === false) return _offlineOnOffLabel(value)
        return String(value)
    }

    /// Read-only half of the post-connect flow: work out WHICH parked settings
    /// still differ from what the service holds, and hand the resulting
    /// `{ label, value }` rows to `done`. Never opens a dialog and never
    /// writes — the window's collector decides what to do with both halves
    /// together, so the user is asked once rather than once per mechanism.
    /// `done([])` on every dead end (nothing parked, no bridge, failed read).
    function collectSettingsBacklog(done) {
        var finish = function(rows) { if (typeof done === "function") done(rows || []) }
        if (!root._routingBackendConnected()) { finish([]); return }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") {
            finish([])
            return
        }
        var obj = root._readPendingOffline()
        if (Pure.pendingOfflineCount(obj) === 0) { finish([]); return }
        var rp = obj["route-policy"] || {}
        var st = obj["stability"] || {}
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        if (!readCorr) { finish([]); return }
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok) { finish([]); return }
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            var finalizeWith = function(cfg) {
                var rows = []
                var k
                for (k in rp) {
                    if (rp[k] !== root._routePolicyEffective(cur, k)) {
                        rows.push({
                            label: _offlineRoutingKeyLabel("route-policy", k),
                            value: _offlineRoutingValueLabel("route-policy", k, rp[k])
                        })
                    }
                }
                for (k in st) {
                    // Structured values (the IPC accept policy) compare by
                    // content — an object is never `===` to its equal twin.
                    var eff = Pure.stabilityEffective(cfg, k)
                    var same = (st[k] !== null && typeof st[k] === "object")
                        ? JSON.stringify(st[k]) === JSON.stringify(eff)
                        : st[k] === eff
                    if (!same) {
                        rows.push({
                            label: _offlineRoutingKeyLabel("stability", k),
                            value: _offlineRoutingValueLabel("stability", k, st[k])
                        })
                    }
                }
                if (rows.length === 0) {
                    // Everything already matches the service — drop the park.
                    root._writePendingOffline({})
                }
                finish(rows)
            }
            if (Object.keys(st).length === 0
                    || typeof nrrNativeBridge.rpcServiceStabilityConfigGet !== "function") {
                finalizeWith({})
                return
            }
            var cfgCorr = nrrNativeBridge.rpcServiceStabilityConfigGet()
            if (!cfgCorr) { finalizeWith({}); return }
            root.rpc.registerRpcCallback(cfgCorr, function(ok2, cfg, code2, msg2) {
                finalizeWith((ok2 && cfg) ? cfg : {})
            })
        })
    }

    /// Apply the parked intents: read a fresh snapshot, build the full
    /// route.policy.update overriding only the changed keys (one RPC), and push
    /// the stability keys through the shared clobber-safe patch writer (one
    /// patch). Clears the store only on OVERALL success; keeps it on failure.
    ///
    /// `fallbackRows` distinguishes the two call sites:
    ///   - Passed (array) by the window's silent reconnect path (settings
    ///     parked, no rule work): on success, reports via the "-auto-applied"
    ///     status line
    ///     (nothing was ever shown to the user); on failure — the service
    ///     refused with `uac-declined` (elevation prompt was shown and
    ///     declined) or any other error — falls back to opening the confirm
    ///     dialog pre-filled with `fallbackRows`, exactly the dialog the user
    ///     would have seen before this silent path existed. The queued
    ///     changes are never dropped on failure either way.
    ///   - Omitted by the dialog's own "Apply all" button: a user-initiated
    ///     retry, so it reports through the plain applied/failed status lines
    ///     and never re-opens itself.
    function _applyOfflinePending(fallbackRows) {
        var obj = root._readPendingOffline()
        var rp = obj["route-policy"] || {}
        var st = obj["stability"] || {}
        var haveRp = Object.keys(rp).length > 0
        var haveSt = Object.keys(st).length > 0
        if (!haveRp && !haveSt) {
            root._writePendingOffline({})
            _offlinePendingDialogActive = false
            return
        }
        if (!root._routingBackendConnected()
                || !root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null) {
            // Lost the service between offer and apply — keep the store intact.
            root.statusLine = root.tr("status.offline-pending-apply-failed",
                "Could not apply the saved changes; they are still pending.")
            _offlinePendingDialogActive = false
            return
        }
        var state = { rpDone: !haveRp, rpOk: true, stDone: !haveSt, stOk: true }
        var settle = function() {
            if (!state.rpDone || !state.stDone) return
            if (state.rpOk && state.stOk) {
                root._writePendingOffline({})
                root.statusLine = fallbackRows
                    ? root.tr("status.offline-pending-auto-applied",
                        "Applied the changes made while the service was stopped.")
                    : root.tr("status.offline-pending-applied",
                        "Your saved changes were applied.")
                root.offlinePendingApplied()
                _offlinePendingDialogActive = false
                return
            }
            if (fallbackRows) {
                // Silent reconnect apply didn't go through — most commonly an
                // elevation-required key came back `uac-declined`, but any
                // failure lands here. Fall back to the shared post-connect
                // dialog, pre-filled with the rows computed at offer time, and
                // keep `_offlinePendingDialogActive` set until the user
                // answers it.
                root._showOfflineBacklogDialog(false, fallbackRows)
                return
            }
            root.statusLine = root.tr("status.offline-pending-apply-failed",
                "Could not apply the saved changes; they are still pending.")
            _offlinePendingDialogActive = false
        }
        if (haveRp) {
            var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
            root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
                if (!ok) { state.rpDone = true; state.rpOk = false; settle(); return }
                var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
                var req = root._buildFullRoutePolicyReq(cur)
                var changed = false
                for (var k in rp) {
                    if (rp[k] !== root._routePolicyEffective(cur, k)) { req[k] = rp[k]; changed = true }
                }
                if (!changed) { state.rpDone = true; state.rpOk = true; settle(); return }
                var wCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
                root.rpc.registerRpcCallback(wCorr, function(ok2, p2, code2, msg2) {
                    state.rpDone = true; state.rpOk = !!ok2; settle()
                })
            })
        }
        if (haveSt) {
            // applyServiceStabilityPatch does its own GET→merge→SET, so sending
            // every parked stability key as one patch is clobber-safe.
            root.applyServiceStabilityPatch(st, function(okS, codeS) {
                state.stDone = true; state.stOk = !!okS; settle()
            }, "offline-pending-apply")
        }
    }

    /// Discard the parked intents (non-destructive to the service) and reload
    /// the routing panels from the service so they show the live values.
    function _discardOfflinePending() {
        root._writePendingOffline({})
        root.statusLine = root.tr("status.offline-pending-discarded",
            "Your saved changes were discarded.")
        root.offlinePendingApplied()
        _offlinePendingDialogActive = false
    }
}
