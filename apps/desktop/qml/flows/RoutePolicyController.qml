import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller for the per-SID route-policy apply handlers driven by
// the Routing settings panel (leak protection and its refinements, DoH lockdown,
// shared-IP, include-subdomains, hosts-bypass, browser-history auto-seed,
// default route) plus the adapter-binding push/resync. Extracted from
// Main.qml (thin-shell rule). Shared infrastructure the shell keeps on the
// window: `_routingBackendConnected`, `_recordOfflineRoutingIntent`,
// `_buildFullRoutePolicyReq`, `_routePolicyEffective`, `applyServiceStabilityPatch`
// (each is also used by other panels / the offline-pending flow).
//
// Main.qml instantiates one, injects itself as `root`, and exposes it as
// `root.routePolicyController`; RoutingSettings / InterfacesRoutesSection /
// DiagnosticsSection drive the handlers through `root.routePolicyController.<fn>`.
// Every apply* handler pushes the authoritative per-SID key through the
// shared `_applyRoutePolicyKey`; the local preference mirrors follow a write
// the service confirmed (`_mirrorConfirmedPolicy`), never precede it. RPC goes
// through `root.rpc`; `nrrNativeBridge` is a global QML context property,
// referenced bare.
QtObject {
    id: routePolicyController
    property var root

    /// The service refused a write: `confirmed` maps each key the write named
    /// to the value the service still holds, for the controls to show again.
    signal policyWriteRefused(var confirmed)

    /// One key, the common case. Thin wrapper over the many-key form so both
    /// take exactly one read and one write.
    function _applyRoutePolicyKey(key, value, o) {
        o = o || {}
        var one = {}
        one[key] = value
        _applyRoutePolicyKeys(one, {
            onApplied: function() { if (o.onApplied) o.onApplied(value) },
            ok: o.ok, uac: o.uac, failPrefix: o.failPrefix, onFailed: o.onFailed,
            origin: o.origin
        })
    }

    /// Apply SEVERAL policy keys as ONE write.
    ///
    /// Not a loop over the single-key form: that would read the policy once per
    /// key, ask for approval once per key, and let two writes race over the
    /// snapshot each of them read. `o.onFailed` runs when the service refused
    /// the write (a parked intent is not a failure: it is sent again).
    function _applyRoutePolicyKeys(changes, o) {
        o = o || {}
        var keys = Object.keys(changes || {})
        if (keys.length === 0) return
        // Service stopped: park the intent + offer it on reconnect.
        if (!root._routingBackendConnected()) {
            for (var i = 0; i < keys.length; i += 1)
                root._recordOfflineRoutingIntent("route-policy", keys[i], changes[keys[i]])
            if (o.onParked) o.onParked()
            return
        }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            // No RPC to carry the change. Park it in the same store a stopped
            // service uses rather than returning silently: only some keys have a
            // local pref mirror, so a silent return dropped the rest outright.
            for (var j = 0; j < keys.length; j += 1)
                root._recordOfflineRoutingIntent("route-policy", keys[j], changes[keys[j]])
            if (o.onParked) o.onParked()
            return
        }
        mutateRoutePolicy(function(cur) {
            var req = root._buildFullRoutePolicyReq(cur)
            for (var m = 0; m < keys.length; m += 1)
                req[keys[m]] = changes[keys[m]]
            // A default-route change can leave a level that route does not
            // offer; the service would refuse the pair.
            return Pure.settleLeakProtection(req)
        }, function(ok, code, stage) {
            // A failed read would build the request from the field defaults,
            // which switch leak protection and the DoH lockdown off. The
            // decision is parked instead, like one made while the service is
            // down: it is still what the user asked for.
            if (stage === "read") {
                for (var k = 0; k < keys.length; k += 1)
                    root._recordOfflineRoutingIntent("route-policy", keys[k], changes[keys[k]])
                var readLabel = (typeof root.ipcErrorLabel === "function")
                    ? root.ipcErrorLabel(code) : code
                root.statusLine = root.tr("status.route-policy-read-failed",
                    "Could not read the current routing policy, so nothing was "
                    + "changed. The setting is saved and will be sent again: ") + readLabel
                if (o.onNotWritten) o.onNotWritten(code)
                return
            }
            if (ok) {
                // Display bookkeeping only — never a push source: panels with no
                // dedicated prefs mirror read it back while the service is stopped.
                if (typeof root._rememberServiceValues === "function") {
                    var remembered = {}
                    for (var n = 0; n < keys.length; n += 1)
                        remembered[keys[n]] = changes[keys[n]]
                    root._rememberServiceValues("route-policy", remembered)
                }
                if (o.onApplied) o.onApplied(changes)
                root.statusLine = o.ok
                return
            }
            if (code === "uac-declined") {
                root.statusLine = o.uac
            } else {
                var label = (typeof root.ipcErrorLabel === "function")
                    ? root.ipcErrorLabel(code) : code
                root.statusLine = o.failPrefix + label
            }
            if (o.onFailed) o.onFailed(code)
            if (o.onNotWritten) o.onNotWritten(code)
        }, o.origin || "user:routing-settings")
    }

    property var _policyWrites: []
    property bool _policyWriteInFlight: false

    /// The ONE way to change the per-SID route policy from this window.
    ///
    /// `route.policy.update` replaces the whole row, so every write is built on
    /// a fresh read. Two in flight read the same row and each carries the
    /// other's field back to its old value: first-run sent leak protection, the
    /// DoH lockdown and both adapter bindings at once, and the service kept
    /// neither protection. Writes therefore run one at a time, each reading
    /// after the previous one landed.
    ///
    /// `build(cur)` returns the request, or null when there is nothing to
    /// write. `done(ok, code, stage)`: `stage` is "read" (nothing was sent),
    /// "unchanged" (build returned null, `ok` true) or "write".
    ///
    /// `origin` says who asked. Only a user's write the service confirmed is
    /// recorded as their intent (`Pure.isUserWriteOrigin`): a resync, a heal
    /// or a re-seed restates what the app holds and must never pass for a
    /// decision.
    function mutateRoutePolicy(build, done, origin) {
        _policyWrites.push({ build: build, done: done, origin: String(origin || "") })
        _drainPolicyWrites()
    }

    function _drainPolicyWrites() {
        if (_policyWriteInFlight || _policyWrites.length === 0) return
        var job = _policyWrites.shift()
        _policyWriteInFlight = true
        var finish = function(ok, code, stage) {
            _policyWriteInFlight = false
            try {
                if (typeof job.done === "function") job.done(ok === true, String(code || ""), stage)
            } catch (e) {
                console.log("route-policy write: completion failed:", e)
            }
            _drainPolicyWrites()
        }
        if (typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            finish(false, "bridge-unavailable", "read")
            return
        }
        // A dropped correlation id never gets a callback; without this the
        // queue would stall behind it for the rest of the session.
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        if (!readCorr) { finish(false, "bridge-unavailable", "read"); return }
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok || !p) { finish(false, code, "read"); return }
            var cur = (p["route-policy"] || p.routePolicy) || {}
            var req = null
            try {
                req = job.build(cur)
            } catch (e) {
                console.log("route-policy write: building the request failed:", e)
                finish(false, "gui-internal", "read")
                return
            }
            if (!req) { finish(true, "", "unchanged"); return }
            // Only what this write changes: a whole row restating the rest would
            // revert whatever the tray wrote since the read.
            var changed = Pure.routePolicyChangedKeys(Pure.buildFullRoutePolicyReq(cur, ""), req)
            if (changed.length === 0) { finish(true, "", "unchanged"); return }
            req["apply-only"] = changed
            // What the service keeps if it refuses: the row this write is built on.
            var confirmed = {}
            for (var c = 0; c < changed.length; c += 1)
                confirmed[changed[c]] = root._routePolicyEffective(cur, changed[c])
            var wCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
            if (!wCorr) {
                policyWriteRefused(confirmed)
                finish(false, "bridge-unavailable", "write")
                return
            }
            root.rpc.registerRpcCallback(wCorr, function(ok2, p2, code2, msg2) {
                if (ok2) _mirrorConfirmedPolicy(req, changed)
                else policyWriteRefused(confirmed)
                // The answer is the row as stored, the install-time start included.
                if (ok2 && p2 && typeof p2 === "object" && p2.mode !== undefined)
                    root._noteServicePolicy(p2, null)
                if (ok2 && Pure.isUserWriteOrigin(job.origin) && root.settingsRestoreController)
                    root.settingsRestoreController.recordRoutePolicy(req, changed)
                finish(ok2, code2, "write")
            })
        })
    }

    /// The local preference mirrors follow a write the service confirmed,
    /// whoever sent it: the user, the parked delivery, a restore.
    function _mirrorConfirmedPolicy(req, changed) {
        // The level in force is what the next default-route change is asked against.
        if (changed.indexOf("mode") >= 0 || changed.indexOf("leak-protection") >= 0) {
            root.updateRoutingState({ leakProtection: Pure.coerceLeakProtection(
                Pure.routePolicyCoerce("mode", req["mode"]),
                Pure.routePolicyCoerce("leak-protection", req["leak-protection"])) })
        }
        var patch = Pure.routePolicyPrefMirrorPatch(req, changed)
        if (Object.keys(patch).length === 0) return
        root.commitPrefs(patch)
        // Coverage decides whether `x` and `*.x` are one rule or two.
        if (patch.hasOwnProperty("routeIncludeSubdomains")) root.refreshRulesOverlaps()
    }
    /// Default route for unmatched traffic: the authoritative per-SID policy
    /// the codegen reads. The `routeBehaviorMode` preference mirrors it once
    /// the service confirms.
    function applyRouteBehaviorMode(modeSlug) {
        var slug = String(modeSlug || "")
        if (slug === "") return
        _applyRoutePolicyKey("mode", slug, {
            ok: root.tr("status.route-mode-applied",
                "\"Where everything else goes\" is saved."),
            uac: root.tr("status.route-mode-uac-declined",
                "Administrator approval was declined; \"Where everything else goes\" was not changed."),
            failPrefix: root.tr("status.route-mode-failed",
                "Could not save \"Where everything else goes\":")
        })
    }
    /// Leak protection: `off` | `sites` | `everything`. A level the current
    /// default route does not offer is settled by the write itself.
    function applyLeakProtection(slug, onFailed) {
        var want = Pure.routePolicyCoerce("leak-protection", slug)
        var o = _leakProtectionMessages(want)
        o.onFailed = onFailed
        _applyRoutePolicyKey("leak-protection", want, o)
    }
    function _leakProtectionMessages(level) {
        return {
            ok: level === "everything"
                ? root.tr("status.leak-protection-everything",
                    "Leak protection: everything. If the additional connection drops, the internet waits until it returns.")
                : level === "sites"
                    ? root.tr("status.leak-protection-sites",
                        "Leak protection: routed sites. What your rules send through the additional connection never goes out the main one while strict protection is on.")
                    : root.tr("status.leak-protection-off",
                        "Leak protection is off. If the additional connection drops, traffic continues over your main connection."),
            uac: root.tr("status.kill-switch-uac-declined",
                "Administrator approval was declined; leak protection was not changed."),
            failPrefix: root.tr("status.kill-switch-enabled-failed",
                "Could not update leak protection: ")
        }
    }
    /// "Treat a domain as `domain` + `*.domain`" — ON by default. When on,
    /// the service expands every bare-domain rule to also
    /// cover its subdomains (apex kept); the stored rules and their canonical
    /// hash are untouched. Turning it off narrows rules back to exact hosts.
    function applyIncludeSubdomains(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("include-subdomains", want, {
            ok: want
                ? root.tr("status.include-subdomains-on",
                    "Domain rules now also cover subdomains.")
                : root.tr("status.include-subdomains-off",
                    "Domain rules now match the exact domain only."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.include-subdomains-failed",
                "Could not update the subdomain setting: ")
        })
    }
    /// Let an application rule take every address its program uses, even one
    /// another rule sends the other way. Those addresses then go that route for
    /// every program, which is why it is off by default.
    function applyAppRulesTakeAllAddresses(enabled, onFailed) {
        var want = enabled === true
        _applyRoutePolicyKey("app-rules-take-all-addresses", want, {
            onApplied: function(v) {
                root.updateRoutingState({ appRulesTakeAllAddresses: v })
            },
            onFailed: onFailed,
            ok: want
                ? root.tr("status.app-rules-take-all-on",
                    "Programs in your rules now take all their traffic.")
                : root.tr("status.app-rules-take-all-off",
                    "Rules for sites and addresses take priority over programs again."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.app-rules-take-all-failed",
                "Could not change how programs in rules are routed: ")
        })
    }
    /// What forwarded traffic gets while the tunnel is down: `as-computer` |
    /// `unprotected`.
    function applyForwardedOutage(slug, onFailed) {
        _applyRoutePolicyKey("forwarded-outage", slug, {
            onApplied: function(v) {
                root.updateRoutingState({ forwardedOutage: v })
                root._onForwardedReading()
            },
            onFailed: onFailed,
            ok: slug === "unprotected"
                ? root.tr("status.forwarded-traffic-unprotected",
                    "WSL, containers and virtual machines are no longer protected while the additional connection is down.")
                : root.tr("status.forwarded-traffic-as-computer",
                    "WSL, containers and virtual machines are now protected like this computer."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.forwarded-traffic-failed",
                "Could not change protection of WSL and containers: ")
        })
    }
    /// Shared-IP policy slug (`majority-of-ip` | `majority-of-rules` |
    /// `any-rule-domain`).
    function applySharedIpPolicy(slug) {
        var want = String(slug || "majority-of-ip")
        _applyRoutePolicyKey("shared-ip-policy", want, {
            ok: root.tr("status.shared-ip-policy-set",
                "Shared-IP handling updated."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.shared-ip-policy-failed",
                "Could not update shared-IP handling: ")
        })
    }
    /// "Resolve rule domains bypassing the hosts file". ON (default) resolves
    /// rule hosts straight against upstream DNS so a local hosts/adblock loopback
    /// pin cannot starve a rule of its routable public IP; OFF honours the hosts
    /// file.
    function applyResolveHostsBypass(enabled) {
        var want = enabled !== false
        _applyRoutePolicyKey("resolve-hosts-bypass", want, {
            ok: root.tr("status.hosts-bypass-set",
                "Rule-domain resolution updated."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.hosts-bypass-failed",
                "Could not update rule-domain resolution: ")
        })
    }
    /// DoH/DoT lockdown MASTER switch. When ON, the service blocks known DoH/DoT
    /// resolver endpoints so browser DNS-over-HTTPS falls back to plaintext the
    /// DNS observer can see (otherwise routed sites resolved over DoH are
    /// invisible to leak protection).
    function applyDohLockdownEnabled(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("doh-lockdown-enabled", want, {
            ok: want
                ? root.tr("status.doh-lockdown-on",
                    "Browser DoH/DoT blocking enabled: DNS falls back to plaintext so routed sites are seen.")
                : root.tr("status.doh-lockdown-off",
                    "Browser DoH/DoT blocking disabled."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.doh-lockdown-failed",
                "Could not update DoH/DoT blocking: ")
        })
    }
    /// DoH/DoT lockdown SCOPE slug (`leak-protection-only` (default,
    /// recommended) | `always`).
    function applyDohLockdownScope(slug) {
        var want = (String(slug) === "always") ? "always" : "leak-protection-only"
        _applyRoutePolicyKey("doh-lockdown-scope", want, {
            ok: root.tr("status.doh-lockdown-scope-set",
                "DoH/DoT blocking scope updated."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.doh-lockdown-failed",
                "Could not update DoH/DoT blocking: ")
        })
    }
    /// Shared-IP strictness of leak protection. "strict" also holds addresses
    /// shared with regular sites (can cut co-tenant sites); "smart" (default)
    /// leaves them out.
    function applyKillSwitchStrictSharedIps(strict) {
        var want = strict === true
        _applyRoutePolicyKey("kill-switch-strict-shared-ips", want, {
            onApplied: function(v) { root.updateRoutingState({ killSwitchStrictSharedIps: v }) },
            ok: want
                ? root.tr("status.kill-switch-shared-strict-on",
                    "Strict leak protection: no exceptions; some ordinary sites may not open while the additional connection is down.")
                : root.tr("status.kill-switch-shared-strict-off",
                    "Smart leak protection: ordinary sites keep opening, but some traffic of routed sites may go out through the main connection."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.kill-switch-shared-strict-failed",
                "Could not switch strict leak protection: ")
        })
    }
    /// Auto-rules mode: what happens to the companion domains found for a routed
    /// site (the CDN/media hosts its rules do not cover yet). "off" = do not
    /// collect; "suggest" (default) = collect and offer them, apply nothing;
    /// "auto" = apply and record them in the user's rules. Any unknown value
    /// falls back to "suggest" — never silently start applying.
    function applyAutoRulesMode(slug) {
        var s = String(slug)
        var want = (s === "off" || s === "auto") ? s : "suggest"
        _applyRoutePolicyKey("auto-rules-mode", want, {
            onApplied: function(v) { root.updateRoutingState({ autoRulesMode: v }) },
            ok: (want === "auto")
                ? root.tr("status.auto-rules-auto",
                    "Suggested addresses will be added to your rules automatically.")
                : ((want === "suggest")
                    ? root.tr("status.auto-rules-suggest",
                        "Suggested addresses will wait for your confirmation.")
                    : root.tr("status.auto-rules-off",
                        "Addresses will no longer be suggested.")),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.auto-rules-failed",
                "Could not update the auto-rules setting: ")
        })
    }
    /// "Stop asking about local networks I have not seen before." Off by
    /// default: keeping a segment reachable is a hole the user should open
    /// knowingly. It silences the QUESTION, not the record — every network is
    /// still listed in Settings and any of them can be refused there, and
    /// turning this back off asks again.
    function applyLocalNetworksAutoAccept(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("local-networks-auto-accept", want, {
            onApplied: function(v) {
                root.updateRoutingState({ localNetworksAutoAccept: v })
                if (v) {
                    root.pendingLocalNetworks = []
                    root.uiRevision += 1
                }
            },
            ok: want
                ? root.tr("status.local-network-auto-accept-on",
                    "New local networks stay reachable without asking. You can still refuse any of them in Settings.")
                : root.tr("status.local-network-auto-accept-off",
                    "You will be asked about each new local network again."),
            uac: root.tr("status.kill-switch-uac-declined",
                "Administrator approval was declined; leak protection was not changed."),
            failPrefix: root.tr("status.local-network-offer-failed",
                "Could not save the answer; it will be asked again.")
        })
    }

    /// "May the service check the main route on its own?" — the opt-in behind
    /// the probe. Off by default: a probe is an outgoing connection, and making
    /// one unasked is the user's call, not ours.
    function applyPrimaryProbeAuto(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("primary-probe-auto", want, {
            onApplied: function(v) {
                root.updateRoutingState({ primaryProbeAuto: v })
            },
            ok: want
                ? root.tr("status.primary-probe-auto-on",
                    "The service will check the main connection for new suggestions itself.")
                : root.tr("status.primary-probe-auto-off",
                    "The main connection will only be checked when you ask."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.primary-probe-failed",
                "Could not change the main connection check: ")
        })
    }

    /// Ask for the additional route's external address each time it connects.
    /// Off by default: the request leaves through the tunnel.
    function applyExternalAddressAutoCheck(enabled, onFailed) {
        var want = enabled === true
        _applyRoutePolicyKey("external-address-auto-check", want, {
            onApplied: function(v) {
                root.updateRoutingState({ externalAddressAutoCheck: v })
            },
            onFailed: onFailed,
            ok: want
                ? root.tr("status.external-address-auto-on",
                    "The external address will be checked each time the additional connection comes up.")
                : root.tr("status.external-address-auto-off",
                    "The external address will only be checked when you ask."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.external-address-auto-failed",
                "Could not change the external-address check: ")
        })
    }

    /// One probing bound. The service clamps every value into its allowed range,
    /// so a number typed here can only narrow a pass, never widen it past what
    /// the service permits.
    function applyPrimaryProbeLimit(key, value) {
        _applyRoutePolicyKey(key, Number(value), {
            onApplied: function() {},
            ok: root.tr("status.primary-probe-limits-saved", "Check limits saved."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.primary-probe-failed",
                "Could not change the main connection check: ")
        })
    }

    /// The three main-route check limits back to their declared defaults, in one
    /// write. The values come from the same table the fields clamp against, so
    /// "default" cannot mean one thing in the button and another in the field.
    function resetPrimaryProbeLimits() {
        var keys = ["primary-probe-timeout-ms", "primary-probe-max-targets",
                    "primary-probe-repeat-secs"]
        var changes = {}
        for (var i = 0; i < keys.length; i += 1)
            changes[keys[i]] = Number(root.routePolicyDefault(keys[i]))
        _applyRoutePolicyKeys(changes, {
            onApplied: function() {},
            ok: root.tr("status.primary-probe-limits-reset",
                "Check limits are back to their defaults."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.primary-probe-failed",
                "Could not change the main connection check: ")
        })
    }

    /// Complete short names with `suffix` for a connection that announces no
    /// domain. One write for both keys, so the domain is never stored switched
    /// on but empty. The service validates the domain.
    function applyShortNames(enabled, suffix, onApplied, onFailed) {
        var want = enabled === true
        var domain = String(suffix || "")
        _applyRoutePolicyKeys({
            "short-name-completion": want,
            "short-name-suffix": domain
        }, {
            onApplied: function() {
                root.updateRoutingState({ shortNameCompletion: want, shortNameSuffix: domain })
                if (onApplied) onApplied(want, domain)
            },
            onFailed: onFailed,
            ok: want
                ? root.tr("status.short-names-on",
                    "Short names will be completed with {domain}.").replace("{domain}", domain)
                : root.tr("status.short-names-off",
                    "Short names are completed only with the domain a connection announces."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.short-names-failed",
                "Could not change short-name completion: ")
        })
    }

    /// Skip the co-activity evidence for hosts whose NAME already looks like a
    /// delivery endpoint, so they are offered on first sight. Trades precision
    /// for speed: ad and tracking CDNs share that shape, so this can put hosts
    /// the user did not intend into the rules.
    function applyAutoRulesEagerDeliveryNames(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("auto-rules-eager-delivery-names", want, {
            onApplied: function(v) {
                root.updateRoutingState({ autoRulesEagerDeliveryNames: v })
            },
            ok: want
                ? root.tr("status.auto-rules-eager-on",
                    "Delivery-looking domains will be offered as soon as they appear.")
                : root.tr("status.auto-rules-eager-off",
                    "Delivery-looking domains will be offered only after they prove related to a site."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.auto-rules-failed",
                "Could not update the auto-rules setting: ")
        })
    }
    /// AUTOMATIC browser-history seed for this SID. When ON, the service runs the
    /// (rule-gated, privacy-narrowed) history seed pass at boot on its own; on
    /// enable we ALSO fire one manual seed immediately — the user expects the
    /// cache to fill now, not at the next service start.
    function applyBrowserHistoryAutoSeed(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("browser-history-auto-seed", want, {
            onApplied: function(v) {
                root.updateRoutingState({ browserHistoryAutoSeed: v })
                if (v && typeof nrrNativeBridge.rpcSeedFromBrowserHistory === "function") {
                    nrrNativeBridge.rpcSeedFromBrowserHistory()
                }
            },
            ok: want
                ? root.tr("status.browser-history-auto-seed-on",
                    "The cache will be seeded from browser history automatically at service start.")
                : root.tr("status.browser-history-auto-seed-off",
                    "Automatic browser-history seeding disabled."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.browser-history-auto-seed-failed",
                "Could not update automatic browser-history seeding: ")
        })
    }
    /// Leak-protection PROTOCOL bitmask (which IP protocols it cuts:
    /// TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16, ESP=32; bit 64 has no box, the
    /// caller keeps it as stored). A mask that selects nothing is not sent: the
    /// service refuses it.
    function applyKillSwitchProtocols(bitmask) {
        var want = bitmask | 0
        if (Pure.routePolicyCoerce("kill-switch-protocols", want) !== want) return
        _applyRoutePolicyKey("kill-switch-protocols", want, {
            ok: root.tr("status.kill-switch-protocols-applied",
                "Leak protection protocols updated."),
            uac: root.tr("status.kill-switch-uac-declined",
                "Administrator approval was declined; leak protection was not changed."),
            failPrefix: root.tr("status.kill-switch-enabled-failed",
                "Could not update leak protection: ")
        })
    }
    /// The first-run protections (wizard or answer file) as ONE write, so leak
    /// protection and the DoH lockdown cannot be sent as two snapshots of the
    /// same row. `leakProtection` is a level slug.
    /// `origin` names who answered: the wizard is the user's own choice, an
    /// answer sheet is the administrator's and is not recorded as theirs.
    /// `outcome` (optional): `onApplied`, `onNotWritten(code)` and `onParked`
    /// for a caller that must not go on before the protection is in force.
    function applyFirstRunProtections(leakProtection, dohLockdown, origin, outcome) {
        var level = Pure.routePolicyCoerce("leak-protection", leakProtection)
        var o = _leakProtectionMessages(level)
        o.origin = origin || "user:first-run"
        if (outcome) {
            var applied = o.onApplied
            o.onApplied = function(changes) {
                if (applied) applied(changes)
                if (outcome.onApplied) outcome.onApplied()
            }
            o.onNotWritten = outcome.onNotWritten
            o.onParked = outcome.onParked
        }
        // "Yes" is the automatic posture; "no" is a choice that holds.
        _applyRoutePolicyKeys({
            "leak-protection": level,
            "doh-lockdown-enabled": dohLockdown === true,
            "doh-lockdown-auto": dohLockdown === true
        }, o)
    }
    /// The DoH/DoT lockdown either decides itself (automatic) or follows the
    /// hand-set toggle; both keys travel in ONE write so the service never
    /// sees a toggle without the posture it belongs to.
    function applyDohLockdownChoice(auto, enabled) {
        var wantAuto = auto === true
        var want = enabled === true
        _applyRoutePolicyKeys({
            "doh-lockdown-auto": wantAuto,
            "doh-lockdown-enabled": want
        }, {
            ok: wantAuto
                ? root.tr("status.doh-lockdown-auto",
                    "Browser DoH/DoT blocking now decides itself: on while your rules need to see site names.")
                : want
                    ? root.tr("status.doh-lockdown-on",
                        "Browser DoH/DoT blocking enabled: DNS falls back to plaintext so routed sites are seen.")
                    : root.tr("status.doh-lockdown-off",
                        "Browser DoH/DoT blocking disabled."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.doh-lockdown-failed",
                "Could not update DoH/DoT blocking: ")
        })
    }
    /// "While everything is held, look up site names over the main connection" (leak
    /// protection = everything, additional connection down). ON (default) keeps
    /// DNS working over the main link; OFF cuts it too, a total blackout in
    /// which the FQDN cache can never fill.
    function applyAllowDnsOverPrimary(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("allow-dns-over-primary", want, {
            ok: want
                ? root.tr("status.allow-dns-over-primary-on",
                    "While blocked, name resolution now works over your main connection.")
                : root.tr("status.allow-dns-over-primary-off",
                    "Strict: while blocked, DNS is blocked over the main connection too."),
            uac: root.tr("status.route-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.allow-dns-over-primary-failed",
                "Could not update the DNS setting: ")
        })
    }
    /// Push the GUI's adapter-binding
    /// selection to the SERVICE per-SID route policy. `assignRole` /
    /// `unassignRole` previously wrote ONLY `UiPreferences`, so the service's
    /// `route_bindings` stayed empty and route enforcement had no
    /// secondary target → matched traffic was never routed out the secondary
    /// NIC. The binding now rides `route.policy.update` (elevation relayed by
    /// the session broker, one UAC reused). The update replaces the whole
    /// per-SID policy atomically, so both slots are always sent: from prefs
    /// when set, otherwise preserved from the current policy `cur`.
    /// INVARIANT: a blank pref means "leave the slot as the service has it",
    /// never "unbind" — prefs can be transiently blank (e.g. the interfaces
    /// list rebuilt while the VPN adapter was Down) and an omitted slot in
    /// this full-replacement request unbinds it server-side, tearing down all
    /// routes. Unbind is only ever explicit, via `opts.unbindPrimary` /
    /// `opts.unbindSecondary`.
    function _routeBindingReqFromPrefs(cur, opts) {
        var o = opts || {}
        // Every policy field rides back through the shared builder, which
        // carries the whole snapshot forward from ONE declaration of the wire
        // fields and their defaults. Re-listing them here is what let
        // `kill-switch-strict-shared-ips` / `browser-history-auto-seed` be
        // forgotten and reset by the server's serde defaults on a binding
        // change; the builder also carries the two slots forward, so a blank
        // pref keeps whatever the service has.
        var req = root._buildFullRoutePolicyReq(cur)
        var pid = String(root.prefs.selectedPrimaryInterfaceId || "")
        var pname = String(root.prefs.selectedPrimaryInterfaceName || "")
        if (pid !== "" || pname !== "") {
            req.primary = {
                "stable-id": pid !== "" ? pid : pname,
                "display-name": pname !== "" ? pname : pid,
                "user-confirmed": root.prefs.primaryRoleUserConfirmed === true
            }
        } else if (o.unbindPrimary === true) {
            // Unbind is only ever explicit: an omitted slot in this
            // full-replacement request clears it server-side.
            delete req.primary
        }
        var sid = String(root.prefs.selectedSecondaryInterfaceId || "")
        var sname = String(root.prefs.selectedSecondaryInterfaceName || "")
        if (sid !== "" || sname !== "") {
            req.secondary = {
                "stable-id": sid !== "" ? sid : sname,
                "display-name": sname !== "" ? sname : sid,
                "user-confirmed": root.prefs.secondaryRoleUserConfirmed === true
            }
        } else if (o.unbindSecondary === true) {
            delete req.secondary
        }
        return req
    }
    /// Status line for a binding write that failed. Success is silent: the
    /// role-assign status already shows.
    function _reportBindingWriteFailure(code) {
        if (code === "uac-declined") {
            root.statusLine = root.tr("status.route-binding-uac-declined",
                "Administrator approval was declined; the adapter binding "
                + "was not saved to the service, so routing will not be enforced.")
        } else {
            var lbl = (typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code
            root.statusLine = root.tr("status.route-binding-failed",
                "Could not save the adapter binding to the service: ") + lbl
        }
    }
    /// Push the current prefs binding to the service now. Reads the live policy
    /// first to preserve mode + failover (mirrors `applyRouteBehaviorMode`).
    /// A blank pref slot keeps the service's current binding; pass
    /// `opts.unbindPrimary` / `opts.unbindSecondary` to actually clear a slot.
    function pushRouteBindingToService(opts, onDone, origin) {
        var settle = function(ok, code) {
            if (typeof onDone === "function") onDone(ok === true, String(code || ""))
        }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            // Offline / preview: prefs is the only sink; `_resyncRouteBinding`
            // re-pushes on the next connect.
            settle(false, "bridge-unavailable")
            return
        }
        mutateRoutePolicy(function(cur) {
            return _routeBindingReqFromPrefs(cur, opts)
        }, function(ok, code, stage) {
            // Settled before the status line, so a caller that retries can tell
            // a declined prompt from a transient failure.
            settle(ok, code)
            if (!ok && stage === "write") _reportBindingWriteFailure(code)
        }, origin)
    }
    /// Attempts left in the current re-sync run, and the backoff between them.
    /// Both reasons this push fails are temporary: right after connect the
    /// service is still migrating its database, and the bound adapter may not
    /// be up yet. One attempt therefore left the service with no policy at all
    /// until the next disconnect — the GUI showed a binding nobody was
    /// enforcing while traffic went unrouted.
    property int _bindingResyncAttemptsLeft: 0
    readonly property var _bindingResyncBackoffMs: [2000, 6000, 15000]
    property var _bindingResyncRetryTimer: null
    /// Set once the service is seen without the binding we hold; cleared when
    /// it has one. Backoff alone spans 23 s, but the adapter can appear minutes
    /// later, so a topology change re-arms a run while this holds.
    property bool _bindingResyncOutstanding: false

    /// Cold-start reverse seed. The service is what actually enforces, so a
    /// slot the app has no answer for is filled from its snapshot: a lost prefs
    /// file (or a second account on the machine) used to leave the interfaces
    /// screen blank while routing kept working, with no way to see or change
    /// what was being enforced.
    ///
    /// A slot the user already filled is never overwritten here — that is the
    /// whole point of the split: only the user knows whether their own choice
    /// or the service's is the stale one, so a disagreement raises the banner
    /// and waits for an answer.
    function seedRouteBindingFromService() {
        if (!root.bridgeAvailable
                || ((root.backendStatus || {}).kind) !== "connected"
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") return
        // A choice parked while the service was stopped is the user's newest
        // word and is delivered separately; seeding over it would restore
        // exactly what they had just changed.
        var parked = root._readPendingOffline()["binding"] || {}
        if (parked.pending === true) return
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok) return
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            var plan = Pure.routeBindingSeedPlan(root.prefs, cur)
            if (Object.keys(plan.patch).length > 0) {
                root.updatePrefs(plan.patch)
                root.emitPrefs()
            }
            root.routeBindingDivergence = plan.divergence
        })
    }

    /// The service re-matched a reinstalled adapter while the app kept the old
    /// id. Same choice, stale copy: follow it without arming Apply or raising
    /// the disagreement banner.
    function followServiceBindingHeal() {
        if (!root.bridgeAvailable
                || ((root.backendStatus || {}).kind) !== "connected"
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") return
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok) return
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            var patch = Pure.routeBindingHealPatch(root.prefs, cur)
            if (Object.keys(patch).length === 0) return
            root.commitPrefs(patch)
            root.routeBindingDivergence = (root.routeBindingDivergence || []).filter(function(d) {
                return !patch.hasOwnProperty(d.role === "primary"
                    ? "selectedPrimaryInterfaceId" : "selectedSecondaryInterfaceId")
            })
            root.interfacesRolesController._reapplyInterfaceRolesFromPrefs()
            root.interfacesRolesController.rebuildInterfacesModel()
        })
    }

    /// The user answered the disagreement with "keep what the service applies".
    /// Nothing is sent — the service already holds these values; the app stops
    /// showing a binding nobody enforces.
    function adoptServiceRouteBinding() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") return
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("status.route-policy-read-failed",
                    "Could not read the current routing policy, so nothing was "
                    + "changed. The setting is saved and will be sent again: ")
                return
            }
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            var patch = Pure.routeBindingAdoptPatch(cur)
            if (Object.keys(patch).length > 0) {
                root.updatePrefs(patch)
                root.emitPrefs()
            }
            root.routeBindingDivergence = []
            root.statusLine = root.tr("status.route-binding-adopted",
                "The app now shows the connections the background service is applying.")
        })
    }

    /// On connect: if the service has NO binding but prefs DO, re-push it.
    /// Covers a wiped service DB (deleted ProgramData) or a migration that
    /// never populated `route_bindings` — without this the GUI shows a binding
    /// the service doesn't have and routing silently does nothing.
    function _resyncRouteBindingIfMissing() {
        _bindingResyncAttemptsLeft = _bindingResyncBackoffMs.length
        _attemptRouteBindingResync()
    }

    /// The adapter set changed: start a fresh run if the service is still
    /// without our binding. This is what closes the case the backoff cannot —
    /// the user's secondary adapter connecting long after the GUI did.
    function resyncRouteBindingOnAdapterChange() {
        if (!_bindingResyncOutstanding || _bindingResyncAttemptsLeft > 0) return
        _resyncRouteBindingIfMissing()
    }

    function _attemptRouteBindingResync() {
        if (!root.bridgeAvailable
                || ((root.backendStatus || {}).kind) !== "connected"
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            _scheduleRouteBindingResyncRetry("bridge-unavailable")
            return
        }
        // The user's own record survives a lost preferences file: a slot the
        // preferences no longer name is taken from it. Read afresh, since the
        // terminal client may have recorded a binding since.
        var restore = root.settingsRestoreController
        if (restore && typeof restore.refreshRecord === "function") {
            restore.refreshRecord(function() { _resyncRouteBindingWith(restore.recordedBindings()) })
        } else {
            _resyncRouteBindingWith({})
        }
    }

    function _resyncRouteBindingWith(recorded) {
        var prefsHasBinding =
            String(root.prefs.selectedPrimaryInterfaceId || root.prefs.selectedPrimaryInterfaceName || "") !== ""
            || String(root.prefs.selectedSecondaryInterfaceId || root.prefs.selectedSecondaryInterfaceName || "") !== ""
        if (!prefsHasBinding && !recorded.primary && !recorded.secondary) {
            _routeBindingResyncSettled()
            return
        }
        mutateRoutePolicy(function(cur) {
            if (cur.primary || cur.secondary) return null // service already has a binding
            _bindingResyncOutstanding = true
            var req = _routeBindingReqFromPrefs(cur)
            if (!req.primary && recorded.primary) req.primary = recorded.primary
            if (!req.secondary && recorded.secondary) req.secondary = recorded.secondary
            return req
        }, function(ok, code, stage) {
            if (stage === "read") {
                _scheduleRouteBindingResyncRetry("read-failed:" + code)
                return
            }
            // A declined prompt is an answer, not a transient failure: retrying
            // would re-prompt on every adapter change, and the policy-inactive
            // notice keeps a manual button.
            if (ok || code === "uac-declined") {
                if (!ok) _reportBindingWriteFailure(code)
                _routeBindingResyncSettled()
                return
            }
            _reportBindingWriteFailure(code)
            _scheduleRouteBindingResyncRetry("write-failed:" + code)
        }, "binding-resync")
    }

    function _routeBindingResyncSettled() {
        _bindingResyncOutstanding = false
        _bindingResyncAttemptsLeft = 0
    }

    /// Retry unless we are out of attempts or the service went away. Giving up
    /// leaves `_bindingResyncOutstanding` set on purpose: the next adapter
    /// change starts a new run.
    function _scheduleRouteBindingResyncRetry(reason) {
        var attemptsMade = _bindingResyncBackoffMs.length - _bindingResyncAttemptsLeft
        if (_bindingResyncAttemptsLeft <= 1 || !root._routingBackendConnected()) {
            console.log("route-binding resync gave up after", attemptsMade + 1,
                        "attempt(s), last reason:", reason)
            _bindingResyncAttemptsLeft = 0
            return
        }
        var delay = _bindingResyncBackoffMs[attemptsMade]
        _bindingResyncAttemptsLeft -= 1
        console.log("route-binding resync attempt", attemptsMade + 1, "failed (",
                    reason, ") — retrying in", delay, "ms")
        if (_bindingResyncRetryTimer === null) {
            _bindingResyncRetryTimer = Qt.createQmlObject(
                "import QtQuick 2.15; Timer { repeat: false }", root,
                "routeBindingResyncRetryTimer")
            _bindingResyncRetryTimer.triggered.connect(function() {
                if (!root._routingBackendConnected()) {
                    _bindingResyncAttemptsLeft = 0
                    return
                }
                _attemptRouteBindingResync()
            })
        }
        _bindingResyncRetryTimer.interval = delay
        _bindingResyncRetryTimer.restart()
    }
}
