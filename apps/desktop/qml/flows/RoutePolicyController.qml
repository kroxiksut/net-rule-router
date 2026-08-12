import QtQuick 2.15

// Non-visual controller for the per-SID route-policy apply handlers driven by
// the Routing settings panel (kill-switch family, DoH lockdown, shared-IP,
// include-subdomains, mode-A coverage, hosts-bypass, browser-history auto-seed,
// default-route mode) plus the adapter-binding push/resync. Extracted from
// Main.qml (thin-shell rule). Shared infrastructure the shell keeps on the
// window: `_routingBackendConnected`, `_recordOfflineRoutingIntent`,
// `_buildFullRoutePolicyReq`, `_routePolicyEffective`, `applyServiceStabilityPatch`
// (each is also used by other panels / the offline-pending flow).
//
// Main.qml instantiates one, injects itself as `root`, and exposes it as
// `root.routePolicyController`; RoutingSettings / InterfacesRoutesSection /
// DiagnosticsSection drive the handlers through `root.routePolicyController.<fn>`.
// Every apply* handler that persists a local mirror writes `root.prefs` +
// `root.emitPrefs()` first, then pushes the authoritative per-SID key through
// the shared `_applyRoutePolicyKey`. RPC goes through `root.rpc`;
// `nrrNativeBridge` is a global QML context property, referenced bare.
QtObject {
    id: routePolicyController
    property var root

    function _applyRoutePolicyKey(key, value, o) {
        o = o || {}
        // Service stopped: park the intent + offer it on reconnect.
        if (!root._routingBackendConnected()) {
            root._recordOfflineRoutingIntent("route-policy", key, value)
            return
        }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            // No RPC to carry the change. Park it in the same store a stopped
            // service uses rather than returning silently: only some keys have a
            // local pref mirror, so a silent return dropped the rest outright.
            root._recordOfflineRoutingIntent("route-policy", key, value)
            return
        }
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            var req = root._buildFullRoutePolicyReq(cur)
            req[key] = value
            var wCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
            root.rpc.registerRpcCallback(wCorr, function(ok2, p2, code2, msg2) {
                if (ok2) {
                    // The service accepted the value, so the GUI's display
                    // mirror must carry it too: the panels that have no
                    // dedicated prefs mirror read it back when the service is
                    // stopped. Display bookkeeping only — never a push source.
                    if (typeof root._rememberServiceValues === "function") {
                        var remembered = {}
                        remembered[key] = value
                        root._rememberServiceValues("route-policy", remembered)
                    }
                    if (o.onApplied) o.onApplied(value)
                    root.statusLine = o.ok
                    return
                }
                var c = String(code2 || "")
                if (c === "uac-declined") {
                    root.statusLine = o.uac
                } else {
                    var label = (typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(c) : c
                    root.statusLine = o.failPrefix + label
                }
            })
        })
    }
    /// Default route for unmatched traffic. The legacy
    /// `updatePrefs({routeBehaviorMode})` path only touched the deprecated
    /// UiPreferences mirror and never reached enforcement; this writes the
    /// authoritative per-SID policy the WFP codegen reads. The local prefs mirror
    /// is already written at the call site.
    function applyRouteBehaviorMode(modeSlug) {
        var slug = String(modeSlug || "")
        if (slug === "") return
        _applyRoutePolicyKey("mode", slug, {
            ok: root.tr("status.route-mode-applied",
                "Default route for unmatched traffic updated."),
            uac: root.tr("status.route-mode-uac-declined",
                "Administrator approval was declined; the default route was not changed."),
            failPrefix: root.tr("status.route-mode-failed",
                "Could not update the default route: ")
        })
    }
    /// Toggle the leak-proof kill-switch (service per-SID
    /// `block-secondary-when-unavailable`): matched traffic is blocked if the
    /// additional adapter drops.
    function applyKillSwitch(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("block-secondary-when-unavailable", want, {
            ok: want
                ? root.tr("status.kill-switch-on",
                    "Leak protection enabled: matched traffic is blocked if the additional adapter drops.")
                : root.tr("status.kill-switch-off",
                    "Leak protection disabled."),
            uac: root.tr("status.kill-switch-uac-declined",
                "Administrator approval was declined; leak protection was not changed."),
            failPrefix: root.tr("status.kill-switch-failed",
                "Could not update leak protection: ")
        })
    }
    /// Kill-switch FAILURE POSTURE. fail-closed (default) blocks when the
    /// additional adapter can't be resolved; fail-open allows + warns. Persisted
    /// locally first so the posture survives a service-DB wipe / offline toggle.
    function applyKillSwitchFailClosed(failClosed) {
        var want = failClosed === true
        root.prefs.routeKillSwitchFailClosed = want
        root.emitPrefs()
        _applyRoutePolicyKey("kill-switch-fail-closed", want, {
            ok: want
                ? root.tr("status.kill-switch-fail-closed-on",
                    "Leak protection set to fail-closed: traffic is blocked if the additional adapter can't be found.")
                : root.tr("status.kill-switch-fail-closed-off",
                    "Leak protection set to fail-open: traffic is allowed (with a warning) if the additional adapter can't be found."),
            uac: root.tr("status.kill-switch-uac-declined",
                "Administrator approval was declined; leak protection was not changed."),
            failPrefix: root.tr("status.kill-switch-failed",
                "Could not update leak protection: ")
        })
    }
    /// "Treat a domain as `domain` + `*.domain`" — ON by default. When on,
    /// the service expands every bare-domain rule to also
    /// cover its subdomains (apex kept); the stored rules and their canonical
    /// hash are untouched. Turning it off narrows rules back to exact hosts.
    /// Persisted locally
    /// first (the UiPreferences mirror is the SSOT of user intent; the service is
    /// re-seeded from it on reconnect).
    function applyIncludeSubdomains(enabled) {
        var want = enabled === true
        root.prefs.routeIncludeSubdomains = want
        root.emitPrefs()
        _applyRoutePolicyKey("include-subdomains", want, {
            ok: want
                ? root.tr("status.include-subdomains-on",
                    "Domain rules now also cover subdomains.")
                : root.tr("status.include-subdomains-off",
                    "Domain rules now match the exact domain only."),
            uac: root.tr("status.include-subdomains-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.include-subdomains-failed",
                "Could not update the subdomain setting: ")
        })
    }
    /// Shared-IP policy slug (`majority-of-ip` | `majority-of-rules` |
    /// `any-rule-domain`).
    function applySharedIpPolicy(slug) {
        var want = String(slug || "majority-of-ip")
        root.prefs.routeSharedIpPolicy = want
        root.emitPrefs()
        _applyRoutePolicyKey("shared-ip-policy", want, {
            ok: root.tr("status.shared-ip-policy-set",
                "Shared-IP handling updated."),
            uac: root.tr("status.shared-ip-policy-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.shared-ip-policy-failed",
                "Could not update shared-IP handling: ")
        })
    }
    /// Mode-A coverage strategy: how Mode A treats traffic whose destination is
    /// not yet in the seeded pin set while the additional route is unavailable.
    /// "per-ip" (default) blocks only the learned addresses; "fail-closed-unknown"
    /// blocks everything unresolved (paranoid opt-in — it can briefly block
    /// unmatched browsing while armed).
    function applyModeACoverageStrategy(slug) {
        var want = String(slug || root.routePolicyDefault("mode-a-coverage-strategy"))
        root.prefs.routeModeACoverageStrategy = want
        root.emitPrefs()
        _applyRoutePolicyKey("mode-a-coverage-strategy", want, {
            ok: root.tr("status.mode-a-coverage-set",
                "Fallback blocking behavior updated."),
            uac: root.tr("status.mode-a-coverage-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.mode-a-coverage-failed",
                "Could not update the fallback blocking behavior: ")
        })
    }
    /// "Resolve rule domains bypassing the hosts file". ON (default) resolves
    /// rule hosts straight against upstream DNS so a local hosts/adblock loopback
    /// pin cannot starve a rule of its routable public IP; OFF honours the hosts
    /// file.
    function applyResolveHostsBypass(enabled) {
        var want = enabled !== false
        root.prefs.routeResolveHostsBypass = want
        root.emitPrefs()
        _applyRoutePolicyKey("resolve-hosts-bypass", want, {
            ok: root.tr("status.hosts-bypass-set",
                "Rule-domain resolution updated."),
            uac: root.tr("status.hosts-bypass-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.hosts-bypass-failed",
                "Could not update rule-domain resolution: ")
        })
    }
    /// DoH/DoT lockdown MASTER switch. When ON, the service blocks known DoH/DoT
    /// resolver endpoints so browser DNS-over-HTTPS falls back to plaintext the
    /// DNS observer can see (otherwise routed sites resolved over DoH are
    /// invisible to the kill-switch).
    function applyDohLockdownEnabled(enabled) {
        var want = enabled === true
        _applyRoutePolicyKey("doh-lockdown-enabled", want, {
            ok: want
                ? root.tr("status.doh-lockdown-on",
                    "Browser DoH/DoT blocking enabled: DNS falls back to plaintext so routed sites are seen.")
                : root.tr("status.doh-lockdown-off",
                    "Browser DoH/DoT blocking disabled."),
            uac: root.tr("status.doh-lockdown-uac-declined",
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
            uac: root.tr("status.doh-lockdown-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.doh-lockdown-failed",
                "Could not update DoH/DoT blocking: ")
        })
    }
    /// Kill-switch shared-IP strictness. "strict" pins census-shared IPs too
    /// (historic behaviour, can cut co-tenant sites); "smart" (default) excludes
    /// them from the pin/block set.
    function applyKillSwitchStrictSharedIps(strict) {
        var want = strict === true
        _applyRoutePolicyKey("kill-switch-strict-shared-ips", want, {
            onApplied: function(v) { root.updateRoutingState({ killSwitchStrictSharedIps: v }) },
            ok: want
                ? root.tr("status.kill-switch-shared-strict-on",
                    "Strict kill switch: addresses shared with regular sites are blocked too.")
                : root.tr("status.kill-switch-shared-strict-off",
                    "Smart kill switch: addresses shared with regular sites are not blocked."),
            uac: root.tr("status.doh-lockdown-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.kill-switch-shared-strict-failed",
                "Could not update the kill-switch shared-address mode: ")
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
                    "Missing companion domains will be added to your rules automatically.")
                : ((want === "suggest")
                    ? root.tr("status.auto-rules-suggest",
                        "Missing companion domains will be offered for your confirmation.")
                    : root.tr("status.auto-rules-off",
                        "Missing companion domains will no longer be collected.")),
            uac: root.tr("status.doh-lockdown-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.auto-rules-failed",
                "Could not update the auto-rules setting: ")
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
            uac: root.tr("status.doh-lockdown-uac-declined",
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
            uac: root.tr("status.doh-lockdown-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.browser-history-auto-seed-failed",
                "Could not update automatic browser-history seeding: ")
        })
    }
    /// Kill-switch PROTOCOL bitmask (which IP protocols the emergency block cuts:
    /// TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64). Persisted locally
    /// first so the selection (incl. ICMP) survives a service-DB wipe.
    function applyKillSwitchProtocols(bitmask) {
        var want = (bitmask | 0) & 0x7F
        root.prefs.routeKillSwitchProtocols = want
        root.emitPrefs()
        _applyRoutePolicyKey("kill-switch-protocols", want, {
            ok: root.tr("status.kill-switch-protocols-applied",
                "Leak protection protocols updated."),
            uac: root.tr("status.kill-switch-uac-declined",
                "Administrator approval was declined; leak protection was not changed."),
            failPrefix: root.tr("status.kill-switch-failed",
                "Could not update leak protection: ")
        })
    }
    /// Aggressive kill-switch SCOPE. When ON, the split-mode fail-closed block
    /// cuts ALL egress (except explicitly primary-routed + exemptions) while the
    /// additional adapter is unavailable, instead of only the cached secondary
    /// destination IPs. `strictKillSwitchActive` mirrors the reactive notice the
    /// notifications centre gates on (the in-place prefs mutation fires no
    /// prefsChanged).
    function applyKillSwitchBlockAll(enabled) {
        var want = enabled === true
        root.prefs.routeKillSwitchBlockAll = want
        root.strictKillSwitchActive = want
        root.emitPrefs()
        _applyRoutePolicyKey("kill-switch-block-all", want, {
            ok: want
                ? root.tr("status.kill-switch-block-all-on",
                    "Kill-switch: while the additional adapter is down, all traffic is now blocked except your primary-routed sites.")
                : root.tr("status.kill-switch-block-all-off",
                    "Kill-switch: while the additional adapter is down, only its routed sites are blocked now."),
            uac: root.tr("status.kill-switch-block-all-uac-declined",
                "Administrator approval was declined; the setting was not changed."),
            failPrefix: root.tr("status.kill-switch-block-all-failed",
                "Could not update the kill-switch setting: ")
        })
    }
    /// MASTER kill-switch toggle (the explicit opt-in). When OFF (default) the
    /// whole leak-guard is disarmed regardless of sub-settings; when ON the gated
    /// sub-settings take effect. The strict-kill-switch notice is only meaningful
    /// while the master is ON, so clear its mirror the moment it goes OFF.
    function applyKillSwitchEnabled(enabled) {
        var want = enabled === true
        root.prefs.routeKillSwitchEnabled = want
        if (!want)
            root.strictKillSwitchActive = false
        root.emitPrefs()
        _applyRoutePolicyKey("kill-switch-enabled", want, {
            ok: want
                ? root.tr("status.kill-switch-enabled-on",
                    "Kill-switch enabled. Choose how it blocks in the options below.")
                : root.tr("status.kill-switch-enabled-off",
                    "Kill-switch disabled. Nothing is blocked — while the additional adapter is down, traffic is allowed to leak (your choice)."),
            uac: root.tr("status.kill-switch-enabled-uac-declined",
                "Administrator approval was declined; the kill-switch was not changed."),
            failPrefix: root.tr("status.kill-switch-enabled-failed",
                "Could not update the kill-switch: ")
        })
    }
    /// "Allow name resolution over the primary link while the block-all is
    /// engaged". ON (default) adds a port-scoped UDP/TCP-53 permit so zones keep
    /// resolving over the main link while everything else is blocked; OFF is the
    /// strict opt-out where the block-all cuts DNS too (a total blackout in
    /// which the FQDN cache can never fill).
    function applyAllowDnsOverPrimary(enabled) {
        var want = enabled === true
        root.prefs.routeAllowDnsOverPrimary = want
        root.emitPrefs()
        _applyRoutePolicyKey("allow-dns-over-primary", want, {
            ok: want
                ? root.tr("status.allow-dns-over-primary-on",
                    "While blocked, name resolution now works over your main link, so zones keep resolving.")
                : root.tr("status.allow-dns-over-primary-off",
                    "Strict: while blocked, DNS is blocked over the main link too."),
            uac: root.tr("status.allow-dns-over-primary-uac-declined",
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
    /// `onDone(ok, code)` runs before the status line is touched, so a caller
    /// that retries can tell a declined prompt from a transient failure.
    function _sendRoutePolicyUpdate(req, onDone) {
        var wCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
        root.rpc.registerRpcCallback(wCorr, function(ok, p, code, msg) {
            var c = String(code || "")
            if (typeof onDone === "function") onDone(ok === true, c)
            if (ok) return // success is silent; the role-assign status already shows
            if (c === "uac-declined") {
                root.statusLine = root.tr("status.route-binding-uac-declined",
                    "Administrator approval was declined; the adapter binding "
                    + "was not saved to the service, so routing will not be enforced.")
            } else {
                var lbl = (typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(c) : c
                root.statusLine = root.tr("status.route-binding-failed",
                    "Could not save the adapter binding to the service: ") + lbl
            }
        })
    }
    /// Push the current prefs binding to the service now. Reads the live policy
    /// first to preserve mode + failover (mirrors `applyRouteBehaviorMode`).
    /// A blank pref slot keeps the service's current binding; pass
    /// `opts.unbindPrimary` / `opts.unbindSecondary` to actually clear a slot.
    function pushRouteBindingToService(opts) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            // Offline / preview: prefs is the only sink; `_resyncRouteBinding`
            // re-pushes on the next connect.
            return
        }
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            _sendRoutePolicyUpdate(_routeBindingReqFromPrefs(cur, opts))
        })
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
        var prefsHasBinding =
            String(root.prefs.selectedPrimaryInterfaceId || root.prefs.selectedPrimaryInterfaceName || "") !== ""
            || String(root.prefs.selectedSecondaryInterfaceId || root.prefs.selectedSecondaryInterfaceName || "") !== ""
        if (!prefsHasBinding) {
            _routeBindingResyncSettled()
            return
        }
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        root.rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok) {
                _scheduleRouteBindingResyncRetry("read-failed:" + String(code || ""))
                return
            }
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            if (cur.primary || cur.secondary) { // service already has a binding
                _routeBindingResyncSettled()
                return
            }
            _bindingResyncOutstanding = true
            _sendRoutePolicyUpdate(_routeBindingReqFromPrefs(cur), function(ok2, code2) {
                if (ok2) {
                    _routeBindingResyncSettled()
                    return
                }
                if (code2 === "uac-declined") {
                    // A declined prompt is an answer, not a transient failure.
                    // Retrying would re-prompt, and again on every adapter
                    // change; the policy-inactive notice keeps a manual button.
                    _routeBindingResyncSettled()
                    return
                }
                _scheduleRouteBindingResyncRetry("write-failed:" + code2)
            })
        })
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
