import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

// Routing-control panel: pause toggle (persistent per-SID)
// + the apply-failure-policy radios + retention. Mounted
// inside SettingsSection's "routing" category. The pause/failure-policy
// surfaces are mock-backed for now; a later revision routes them through IPC ops
// (RoutingPauseToggle, ApplyFailurePolicySet).
ColumnLayout {
    id: panel
    property var root
    spacing: root.uiTheme.spacingMd

    // Kill-switch failure posture. `true` = fail-closed
    // (block when the additional adapter can't be resolved); `false` =
    // fail-open (allow + warn). Read from the live per-SID policy on mount;
    // written via the same route-policy channel as the kill-switch toggle.
    property bool ksFailClosed: true
    // Protocol bitmask the emergency block cuts (TCP=1, UDP=2,
    // ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64). All = 127 (the default).
    property int ksProtocols: 0x7F
    // "Treat a domain as `domain` + `*.domain`". Default ON.
    //  — a rule for a site is expected to cover that site's
    // subdomains, and the widening only ever adds coverage towards the route
    // the rule already names. Read from the live per-SID policy on mount.
    property bool includeSubdomains: true
    // How a SHARED secondary IP (an address a routed domain
    // shares with other sites) is handled. Slug: majority-of-ip (default) |
    // majority-of-rules | any-rule-domain. Read from the live per-SID policy.
    property string sharedIpPolicy: "majority-of-ip"
    // Aggressive kill-switch scope. When ON, split-mode
    // fail-closed blocks ALL egress (except explicitly-allowed) while the
    // additional adapter is down, not just its cached destination IPs — this is
    // what closes the ICMP/ping and rotating-IP leaks of routed hosts. Only
    // meaningful with fail-closed ON. Read from the live per-SID policy. Off.
    property bool ksBlockAll: false
    // MASTER kill-switch toggle (explicit opt-in). When false
    // (the default) the kill-switch is OFF: no fail-closed blocking arms at all,
    // and every sub-setting below is hidden. The sub-settings become visible only
    // when this is true. Read from the live per-SID policy on mount.
    property bool killSwitchEnabled: false
    // OPT-IN "allow name resolution over the primary link while
    // The kill-switch block-all is engaged". (P1b): Default flipped to
    // true — with DNS cut too, an armed block-all is a total blackout. Only
    // meaningful when block-all is on. Read from the per-SID policy.
    property bool allowDnsOverPrimary: true
    // Kill-switch shared-IP strictness. false (default) =
    // "smart": addresses the census has seen on ordinary (non-rule) sites are
    // NOT pinned/blocked, so a shared CDN front-end never cuts an innocent
    // co-tenant (the 0719 google.com collateral). true = "strict": pin every
    // routed address regardless of sharing. Snapshot is the SSOT (no prefs
    // mirror), like the DoH-lockdown toggle.
    property bool ksStrictSharedIps: false
    // What happens to the companion domains found for a routed site (the
    // CDN/media hosts its rules do not cover yet): "off" = do not collect;
    // "suggest" (default) = collect and offer them, apply nothing; "auto" =
    // apply and record them in the user's rules. Per-SID service setting; the
    // snapshot is the SSOT (no prefs mirror), like the DoH-lockdown toggle.
    property string autoRulesMode: "suggest"
    property bool autoRulesEagerDeliveryNames: false
    // Enforcement mechanism: "reactive" (Mode A,
    // default — the existing reactive kill-switch) vs "resolver" (Mode B — a
    // local DNS resolver that enforces BEFORE the app connects). Global service
    // setting (service_stability_config), read/written via the service-stability
    // config RPC. Redirecting system DNS is invasive → default off (reactive).
    property string enforcementMode: "reactive"
    // Virtual-address routing toggle. GLOBAL service
    // setting (`fake-ip-enabled` on the service-stability config), read/written
    // via the same clobber-safe stability RPC as the enforcement mode. Only
    // meaningful in Mode B (the resolver controls the DNS answer), so the
    // checkbox greys out in Mode A. Snapshot is the SSOT (no prefs mirror).
    property bool fakeIpEnabled: false
    // Fake-IP UDP relay toggle. GLOBAL service setting
    // (`fake-ip-udp-relay` on the service-stability config), read/written via
    // the same clobber-safe stability RPC as the fake-IP toggle. Only
    // meaningful while fake-IP itself is on, so the checkbox rides the same
    // visibility as the fake-IP row. Snapshot is the SSOT (no prefs mirror).
    // Defaults OFF, so every read must test `=== true`, never `!== false`.
    property bool fakeIpUdpRelay: false
    // Fake-IP instant-reset toggle. GLOBAL service setting
    // (`fake-ip-instant-rst` on the service-stability config), read/written via
    // the same clobber-safe stability RPC as the fake-IP toggle. Only
    // meaningful while fake-IP itself is on, so the checkbox rides the same
    // visibility as the UDP-relay row. ON (default) keeps today's behaviour: a
    // relay dial refused because the additional route can't be resolved resets
    // the client immediately. Snapshot is the SSOT (no prefs mirror). Defaults
    // ON, so every read must test `!== false`, never `=== true`.
    property bool fakeIpInstantRst: true
    // DNS-over-secondary toggle. GLOBAL service setting
    // (`dns-via-secondary` on the service-stability config), read/written
    // through the same clobber-safe stability RPC as the fake-IP toggle. It
    // decides where the SERVICE's own name lookups leave from, so — unlike
    // fake-IP — it is meaningful in either enforcement mode; it only needs a
    // secondary link to be bound. Snapshot is the SSOT (no prefs mirror).
    property bool dnsViaSecondary: false
    // Fast-DNS-answers toggle. GLOBAL service setting
    // (`dns-fast-answers` on the service-stability config), read/written through
    // the same clobber-safe stability RPC as the DNS-over-secondary toggle. It
    // trades a small protection-install race for answer latency, so — like
    // `dns-via-secondary` — it is meaningful in either enforcement mode.
    // Snapshot is the SSOT (no prefs mirror). Defaults ON: a MISSING field in a
    // reply means "on", so every read must test `!== false`, never `=== true`.
    property bool dnsFastAnswers: true
    // Gates the five manual-tuning toggles above (DNS through the tunnel,
    // fast DNS answers, fake-IP, its UDP relay and instant-reset) behind the
    // "Detailed mode" switch in Experimental settings. Off by default: the
    // toggles stay hidden and their saved values are untouched — only
    // visibility changes. Device-local UI preference.
    readonly property bool detailedModeOn: root.uiRevision >= 0
        ? (root.prefs.routingDetailedMode === true) : false
    // Live integrity verdict of the bundled virtual-adapter
    // driver, from `third-party.components.list`: "" (not loaded yet),
    // "genuine" | "untrusted" | "missing", or "none" when this build ships no
    // driver binary at all (Linux/macOS — kernel TUN is native; line hides).
    property string fakeIpDriverVerdict: ""
    // Mode-A coverage strategy: how Mode A treats traffic whose
    // destination is not yet in the seeded pin set while the additional route
    // Is unavailable. "per-ip" (default) blocks only the learned
    // addresses so default/primary and zone→primary traffic is not blocked;
    // "fail-closed-unknown" is the paranoid opt-in that also blocks unmatched
    // browsing while armed. Per-SID service setting, mirrored in prefs (this
    // pre-read default is overwritten by the live per-SID policy on mount).
    property string modeACoverage: "per-ip"
    // Resolve rule domains bypassing the OS hosts/adblock file.
    // Default true. Per-SID service setting, mirrored in prefs.
    property bool resolveHostsBypass: true
    // DoH/DoT lockdown MASTER toggle (default off). When on, the
    // service blocks known DoH/DoT resolver endpoints so browser DNS falls back to
    // plaintext the observer can see. Per-SID service setting; read from the live
    // per-SID policy on mount (no prefs mirror — the service snapshot is the SSOT).
    property bool dohLockdownEnabled: false
    // When the lockdown applies: "leak-protection-only" (default,
    // recommended — only while a block-all leak-guard is armed) | "always".
    property string dohLockdownScope: "leak-protection-only"
    // Track 1 Chunk 4 — secondary tunnel liveness window (SECONDS). An
    // active ICMP-probe window: how long the tunnel next-hop must be
    // continuously unreachable before the kill-switch fail-closes. `0` =
    // disabled (never fail-closes; safe default); any non-zero value is clamped
    // to [5, 3600]. GLOBAL service setting (service_stability_config), read via
    // the service-stability config RPC. Opt-in.
    property int livenessWindowSecs: 0
    // When the user picks "Custom…" in the liveness dropdown, reveal the spin
    // box even before a value is committed. Also implied by a non-preset value.
    property bool livenessCustomSelected: false
    // Relocated from Diagnostics & Logs: machine-wide,
    // admin-gated routing policy that rides the same service-stability config.
    // rule-scope: keep enforcing while the service runs (even with the app
    // closed). stop-policy: "teardown" (default, all traffic → main link) vs
    // "persist" (keep matched routes on the additional adapter).
    property bool ruleScopeServiceDriven: true
    property string routingStopPolicy: "teardown"
    // The "Show details" disclosures below (kill-switch, default-route,
    // fake-IP, DNS-over-secondary, block-all, strict-shared-IP, exempt
    // addresses, DoH lockdown) live on `root` — see Main.qml — so switching
    // away from Settings and back never re-collapses them.

    // The excluded addresses as reported by the running service; empty when
    // the service reports only their count. Read through `uiRevision` so a
    // snapshot refresh re-evaluates it.
    readonly property var sharedExemptAddresses: root.uiRevision >= 0
        ? (root.routingState.killSwitchSharedIpExemptionAddresses || []) : []

    // Names for those addresses. A bare list of dotted quads answers "how many"
    // but not "what did it let through", which is the only question worth
    // opening the list for. Resolved from the FQDN cache on demand — one small
    // server-side query per address, off the enforcement path and only while
    // the user is looking at it.
    property var _exemptHostByIp: ({})
    property int _exemptHostRev: 0

    function _exemptAddressLine(ip) {
        var hosts = (panel._exemptHostRev >= 0)
            ? panel._exemptHostByIp[String(ip)] : null
        return (hosts && hosts.length > 0)
            ? (String(ip) + "  —  " + hosts.join(", "))
            : String(ip)
    }
    function _exemptAddressLines() {
        return panel.sharedExemptAddresses.map(panel._exemptAddressLine)
    }

    function _loadExemptHostNames() {
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcCacheEntriesList !== "function") return
        var list = panel.sharedExemptAddresses
        for (var i = 0; i < list.length; i += 1) {
            var ip = String(list[i] || "")
            if (ip === "" || panel._exemptHostByIp.hasOwnProperty(ip)) continue
            panel._resolveExemptHost(bridge, ip)
        }
    }
    function _resolveExemptHost(bridge, ip) {
        var corr = bridge.rpcCacheEntriesList("", 8, ip)
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok) return
            var items = ((payload && payload.page) || {}).items || []
            var hosts = []
            for (var i = 0; i < items.length; i += 1) {
                var e = items[i] || {}
                if (String(e.ip || "") !== ip) continue
                var host = String(e.hostname || "")
                if (host !== "" && hosts.indexOf(host) < 0) hosts.push(host)
            }
            // A plain property mutation is not tracked — bump the revision the
            // labels read through. See LESSONS_LEARNED §1.
            panel._exemptHostByIp[ip] = hosts
            panel._exemptHostRev += 1
        })
    }
    // The disclosure flag lives on `root`, so its change signal is reached
    // through Connections rather than an `on...Changed` handler on `panel`.
    Connections {
        target: root
        function onRoutingSharedExemptAddressesExpandedChanged() {
            if (root.routingSharedExemptAddressesExpanded) panel._loadExemptHostNames()
        }
    }

    // Offline seed. When the per-SID service snapshot is
    // unreachable (service stopped), show the user's saved toggle intent from the
    // UiPrefs mirror instead of falling back to QML property defaults (the bug:
    // "kill-switch/subdomain checkboxes reset after the service is stopped"). The
    // write side (Main.qml apply*, emitPrefs) already persists the mirror on every
    // change; this is the missing read side. Read-only — never pushes to the service.
    // P2c — derive the containing-folder `file://` URL for
    // the OS hosts file path reported by `root.platformProfile.hostsFilePath`
    // (computed in Rust; QML must not branch on Qt.platform.os). Handles
    // both Windows backslash paths and POSIX forward-slash paths.
    function _hostsFolderUrl(p) {
        if (!p) return ""
        var dir = p.replace(/[\\/][^\\/]*$/, "")
        var fwd = dir.replace(/\\/g, "/")
        if (fwd.charAt(0) === "/") return "file://" + fwd
        return "file:///" + fwd
    }

    /// Route-policy wire keys this panel displays. Every successful live read
    /// copies the ones the reply carried into the display mirror, so the next
    /// service-stopped launch shows the user's real values instead of the QML
    /// literal defaults.
    readonly property var _mirroredRoutePolicyKeys: [
        "kill-switch-fail-closed", "kill-switch-protocols", "include-subdomains",
        "shared-ip-policy", "kill-switch-block-all", "kill-switch-enabled",
        "allow-dns-over-primary", "mode-a-coverage-strategy", "resolve-hosts-bypass",
        "doh-lockdown-enabled", "doh-lockdown-scope", "kill-switch-strict-shared-ips",
        "auto-rules-mode", "auto-rules-eager-delivery-names"
    ]

    /// Copy the subset of `cur` this panel mirrors into the display mirror.
    /// Absent keys are skipped so a partial reply never records a default as if
    /// the service had reported it.
    function _rememberRoutePolicy(cur) {
        if (!cur || typeof root._rememberServiceValues !== "function") return
        var remembered = {}
        for (var i = 0; i < panel._mirroredRoutePolicyKeys.length; i += 1) {
            var key = panel._mirroredRoutePolicyKeys[i]
            if (cur.hasOwnProperty(key)) remembered[key] = cur[key]
        }
        root._rememberServiceValues("route-policy", remembered)
    }

    /// Same for the shared service-stability config: copy only the `keys` the
    /// reply actually carried into the display mirror.
    function _rememberStability(payload, keys) {
        if (!payload || typeof root._rememberServiceValues !== "function") return
        var remembered = {}
        for (var i = 0; i < keys.length; i += 1) {
            if (payload.hasOwnProperty(keys[i])) remembered[keys[i]] = payload[keys[i]]
        }
        root._rememberServiceValues("stability", remembered)
    }

    /// Read-side namespaces used while no live service snapshot is available.
    /// `parked` = intents the user changed offline (not pushed yet), `mirror` =
    /// what the service last actually reported. Read once per seed pass and
    /// handed to `_offlineRoutePolicyPick` so each key costs no extra parse.
    function _offlineRoutePolicyPick(parked, mirror, key, fallback) {
        if (parked && parked.hasOwnProperty(key))
            return root._routePolicyEffective(parked, key)
        if (mirror && mirror.hasOwnProperty(key))
            return root._routePolicyEffective(mirror, key)
        return fallback
    }

    /// Same precedence for the shared service-stability config: parked intent
    /// first, then the mirror of the service's last reported value, then the
    /// caller's fallback. Values are normalized through `Pure.stabilityEffective`
    /// so the offline seed and the live read agree on shapes.
    function _offlineStabilityPick(parked, mirror, key, fallback) {
        if (parked && parked.hasOwnProperty(key))
            return Pure.stabilityEffective(parked, key)
        if (mirror && mirror.hasOwnProperty(key))
            return Pure.stabilityEffective(mirror, key)
        return fallback
    }

    function _parkedRoutePolicy() {
        return (typeof root._readPendingOffline === "function")
            ? (root._readPendingOffline()["route-policy"] || {}) : {}
    }
    function _mirrorRoutePolicy() {
        return (typeof root._readServiceMirror === "function")
            ? (root._readServiceMirror()["route-policy"] || {}) : {}
    }
    function _parkedStability() {
        return (typeof root._readPendingOffline === "function")
            ? (root._readPendingOffline()["stability"] || {}) : {}
    }

    /// What to DISPLAY for one stability key once the service has answered.
    ///
    /// A live read is the truth about the service — but not about the user. A
    /// switch flipped while the service was down is parked and has not been
    /// delivered yet, so the live value is the OLD one; showing it reads as
    /// "the setting reset itself", and the user flips it again. The parked
    /// intent therefore outranks the live value until delivery clears it —
    /// which the reconnect flow does as soon as the write lands.
    function _livePick(payload, parked, key, live) {
        if (parked && parked.hasOwnProperty(key)) return Pure.stabilityEffective(parked, key)
        return live
    }
    function _mirrorStability() {
        return (typeof root._readServiceMirror === "function")
            ? (root._readServiceMirror()["stability"] || {}) : {}
    }

    function _seedKillSwitchFromPrefs() {
        if (!root.prefs) return
        // The per-key UiPrefs mirrors stay the fallback for the toggles that own
        // one (they double as the service re-seed after a state-DB wipe); a
        // parked intent or the last value the service reported outranks them.
        var parked = _parkedRoutePolicy()
        var mirror = _mirrorRoutePolicy()
        // Every fallback below resolves through the shared wire-field table
        // instead of a literal repeated per panel — a panel default that drifts
        // from the one the request builder sends is how the DNS-over-primary
        // toggle came to display ON while every unrelated policy write pushed
        // `false`.
        panel.ksFailClosed = _offlineRoutePolicyPick(parked, mirror, "kill-switch-fail-closed",
            _mirroredBool("kill-switch-fail-closed", root.prefs.routeKillSwitchFailClosed))
        panel.ksProtocols = _offlineRoutePolicyPick(parked, mirror, "kill-switch-protocols",
            (root.prefs.routeKillSwitchProtocols === undefined)
                ? root.routePolicyDefault("kill-switch-protocols")
                : ((root.prefs.routeKillSwitchProtocols | 0) & 0x7F))
        panel.includeSubdomains = _offlineRoutePolicyPick(parked, mirror, "include-subdomains",
            _mirroredBool("include-subdomains", root.prefs.routeIncludeSubdomains))
        panel.sharedIpPolicy = _offlineRoutePolicyPick(parked, mirror, "shared-ip-policy",
            _mirroredString("shared-ip-policy", root.prefs.routeSharedIpPolicy))
        panel.ksBlockAll = _offlineRoutePolicyPick(parked, mirror, "kill-switch-block-all",
            _mirroredBool("kill-switch-block-all", root.prefs.routeKillSwitchBlockAll))
        panel.killSwitchEnabled = _offlineRoutePolicyPick(parked, mirror, "kill-switch-enabled",
            _mirroredBool("kill-switch-enabled", root.prefs.routeKillSwitchEnabled))
        panel.allowDnsOverPrimary = _offlineRoutePolicyPick(parked, mirror,
            "allow-dns-over-primary",
            _mirroredBool("allow-dns-over-primary", root.prefs.routeAllowDnsOverPrimary))
        // Mode-A coverage strategy + hosts-bypass mirrors.
        panel.modeACoverage = _offlineRoutePolicyPick(parked, mirror, "mode-a-coverage-strategy",
            _mirroredString("mode-a-coverage-strategy", root.prefs.routeModeACoverageStrategy))
        panel.resolveHostsBypass = _offlineRoutePolicyPick(parked, mirror, "resolve-hosts-bypass",
            _mirroredBool("resolve-hosts-bypass", root.prefs.routeResolveHostsBypass))
        // These four have no per-key UiPrefs mirror (the service snapshot is
        // their SSOT), so before the display mirror existed they showed the QML
        // literal default on every service-stopped launch.
        panel.dohLockdownEnabled = _offlineRoutePolicyPick(parked, mirror,
            "doh-lockdown-enabled", root.routePolicyDefault("doh-lockdown-enabled"))
        panel.dohLockdownScope = _offlineRoutePolicyPick(parked, mirror,
            "doh-lockdown-scope", root.routePolicyDefault("doh-lockdown-scope"))
        panel.ksStrictSharedIps = _offlineRoutePolicyPick(parked, mirror,
            "kill-switch-strict-shared-ips",
            root.routePolicyDefault("kill-switch-strict-shared-ips"))
        // The one policy key a surface OTHER than this window can change: the
        // tray's "add automatically from now on" writes it straight to the
        // service, and the tray does not (and must not) become a second writer
        // of this window's preferences. So the display mirror can be stale for
        // this key alone, and a stale mirror here is worse than no mirror: it
        // showed "add automatically" to a user who had switched back to
        // "suggest" from the tray, which reads as the setting having ignored
        // him. Offline we therefore show the DECLARED DEFAULT; an intent parked
        // in this window still wins, and the live read on service start
        // replaces both.
        panel.autoRulesMode = (parked && parked.hasOwnProperty("auto-rules-mode"))
            ? root._routePolicyEffective(parked, "auto-rules-mode")
            : root.routePolicyDefault("auto-rules-mode")
        panel.autoRulesEagerDeliveryNames = _offlineRoutePolicyPick(parked, mirror,
            "auto-rules-eager-delivery-names",
            root.routePolicyDefault("auto-rules-eager-delivery-names"))
    }

    function _loadKillSwitchPosture() {
        // ALWAYS show the persisted intent first, then let a live
        // service snapshot override it below. Previously the prefs seed ran only
        // when the bridge was entirely absent (mock/preview); with the service
        // STOPPED but the real bridge present we fell into the RPC branch, the RPC
        // failed, `if (!ok) return` left the mirrors at their QML defaults, and the
        // checkbox rendered unchecked even though the setting was saved — the
        // "toggle resets after restart" report. Seeding unconditionally fixes it
        // and also covers the empty-correlation case (registerRpcCallback drops
        // empty ids, so the callback would never run to seed).
        _seedKillSwitchFromPrefs()
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInitialGet()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) return
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            // Every control reads through the SAME defaults the request builder
            // applies, so a key the reply omits can never render one way here
            // and be sent another way on the next write.
            panel.ksFailClosed = root._routePolicyEffective(cur, "kill-switch-fail-closed")
            panel.ksProtocols = root._routePolicyEffective(cur, "kill-switch-protocols")
            panel.includeSubdomains = root._routePolicyEffective(cur, "include-subdomains")
            panel.sharedIpPolicy = root._routePolicyEffective(cur, "shared-ip-policy")
            panel.ksBlockAll = root._routePolicyEffective(cur, "kill-switch-block-all")
            panel.killSwitchEnabled = root._routePolicyEffective(cur, "kill-switch-enabled")
            panel.allowDnsOverPrimary = root._routePolicyEffective(cur, "allow-dns-over-primary")
            panel.modeACoverage = root._routePolicyEffective(cur, "mode-a-coverage-strategy")
            panel.resolveHostsBypass = root._routePolicyEffective(cur, "resolve-hosts-bypass")
            panel.dohLockdownEnabled = root._routePolicyEffective(cur, "doh-lockdown-enabled")
            panel.dohLockdownScope = root._routePolicyEffective(cur, "doh-lockdown-scope")
            panel.ksStrictSharedIps =
                root._routePolicyEffective(cur, "kill-switch-strict-shared-ips")
            panel.autoRulesMode = root._routePolicyEffective(cur, "auto-rules-mode")
            panel.autoRulesEagerDeliveryNames =
                root._routePolicyEffective(cur, "auto-rules-eager-delivery-names")
            // A live read always wins — and refreshes the display mirror the
            // service-stopped seed reads back.
            panel._rememberRoutePolicy(cur)
            // Restore remembered toggle intent after a service-DB wipe.
            panel._reseedTogglesFromPrefs(cur)
        })
    }

    /// Read one boolean UiPrefs mirror, falling back to the wire field's
    /// DECLARED default when the pref predates the field. Keeps every mirror
    /// from restating a default that only the shared table is allowed to own.
    function _mirroredBool(key, raw) {
        return (raw === undefined || raw === null)
            ? root.routePolicyDefault(key) : raw === true
    }
    /// Same for a slug-valued mirror.
    function _mirroredString(key, raw) {
        return String(raw || root.routePolicyDefault(key))
    }
    /// The re-seed rule, once instead of per key: the service is still at the
    /// declared default but the local mirror remembers a different choice →
    /// restore the remembered one; anything else is a deliberate service value
    /// and is left alone.
    function _reseedWant(key, svc, mem) {
        var def = root.routePolicyDefault(key)
        return (svc === def && mem !== def) ? mem : svc
    }

    // The three routing-policy toggles live in the
    // per-SID service DB, which is wiped on a schema bump. UiPrefs mirrors the
    // user's intent (survives the wipe); when the service reports the DEFAULT for
    // a toggle but the mirror remembers a non-default choice, re-push it in ONE
    // atomic update so it is restored without the user re-entering it. Only
    // overrides at-default values → never clobbers a deliberate service choice.
    function _reseedTogglesFromPrefs(cur) {
        cur = cur || {}
        if (!root.prefs
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function")
            return
        // What the service currently holds, read through the shared defaults.
        var svcSub = root._routePolicyEffective(cur, "include-subdomains")
        var svcShared = root._routePolicyEffective(cur, "shared-ip-policy")
        var svcBlockAll = root._routePolicyEffective(cur, "kill-switch-block-all")
        var svcEnabled = root._routePolicyEffective(cur, "kill-switch-enabled")
        var svcAllowDns = root._routePolicyEffective(cur, "allow-dns-over-primary")
        var svcFailClosed = root._routePolicyEffective(cur, "kill-switch-fail-closed")
        var svcProtocols = root._routePolicyEffective(cur, "kill-switch-protocols")
        var svcCoverage = root._routePolicyEffective(cur, "mode-a-coverage-strategy")
        var svcBypass = root._routePolicyEffective(cur, "resolve-hosts-bypass")
        // What the local UiPrefs mirror remembers (same defaults again).
        var memSub = _mirroredBool("include-subdomains", root.prefs.routeIncludeSubdomains)
        var memShared = _mirroredString("shared-ip-policy", root.prefs.routeSharedIpPolicy)
        var memBlockAll = _mirroredBool("kill-switch-block-all",
            root.prefs.routeKillSwitchBlockAll)
        var memEnabled = _mirroredBool("kill-switch-enabled", root.prefs.routeKillSwitchEnabled)
        var memAllowDns = _mirroredBool("allow-dns-over-primary",
            root.prefs.routeAllowDnsOverPrimary)
        var memFailClosed = _mirroredBool("kill-switch-fail-closed",
            root.prefs.routeKillSwitchFailClosed)
        var memProtocols = (root.prefs.routeKillSwitchProtocols === undefined)
            ? root.routePolicyDefault("kill-switch-protocols")
            : ((root.prefs.routeKillSwitchProtocols | 0) & 0x7F)
        var memCoverage = _mirroredString("mode-a-coverage-strategy",
            root.prefs.routeModeACoverageStrategy)
        var memBypass = _mirroredBool("resolve-hosts-bypass", root.prefs.routeResolveHostsBypass)
        var wantSub = _reseedWant("include-subdomains", svcSub, memSub)
        var wantShared = _reseedWant("shared-ip-policy", svcShared, memShared)
        var wantBlockAll = _reseedWant("kill-switch-block-all", svcBlockAll, memBlockAll)
        var wantEnabled = _reseedWant("kill-switch-enabled", svcEnabled, memEnabled)
        var wantAllowDns = _reseedWant("allow-dns-over-primary", svcAllowDns, memAllowDns)
        var wantFailClosed = _reseedWant("kill-switch-fail-closed", svcFailClosed, memFailClosed)
        var wantProtocols = _reseedWant("kill-switch-protocols", svcProtocols, memProtocols)
        var wantCoverage = _reseedWant("mode-a-coverage-strategy", svcCoverage, memCoverage)
        var wantBypass = _reseedWant("resolve-hosts-bypass", svcBypass, memBypass)
        // Any key the user parked while the service was
        // stopped is owned by the offline pending-changes dialog now. Do NOT
        // auto-re-push it here (that would race the dialog and could clobber the
        // parked intent). Reset each such key to the service's current value so the
        // "all equal → return" guard below leaves it untouched.
        var pendingRp = (typeof root._readPendingOffline === "function")
            ? (root._readPendingOffline()["route-policy"] || {}) : {}
        if (pendingRp.hasOwnProperty("include-subdomains")) wantSub = svcSub
        if (pendingRp.hasOwnProperty("shared-ip-policy")) wantShared = svcShared
        if (pendingRp.hasOwnProperty("kill-switch-block-all")) wantBlockAll = svcBlockAll
        if (pendingRp.hasOwnProperty("kill-switch-enabled")) wantEnabled = svcEnabled
        if (pendingRp.hasOwnProperty("allow-dns-over-primary")) wantAllowDns = svcAllowDns
        if (pendingRp.hasOwnProperty("kill-switch-fail-closed")) wantFailClosed = svcFailClosed
        if (pendingRp.hasOwnProperty("kill-switch-protocols")) wantProtocols = svcProtocols
        if (pendingRp.hasOwnProperty("mode-a-coverage-strategy")) wantCoverage = svcCoverage
        if (pendingRp.hasOwnProperty("resolve-hosts-bypass")) wantBypass = svcBypass
        if (wantSub === svcSub && wantShared === svcShared && wantBlockAll === svcBlockAll
                && wantEnabled === svcEnabled && wantAllowDns === svcAllowDns
                && wantFailClosed === svcFailClosed && wantProtocols === svcProtocols
                && wantCoverage === svcCoverage && wantBypass === svcBypass)
            return
        // Reflect the restored values in the panel immediately (push is async).
        panel.includeSubdomains = wantSub
        panel.sharedIpPolicy = wantShared
        panel.ksBlockAll = wantBlockAll
        panel.killSwitchEnabled = wantEnabled
        panel.allowDnsOverPrimary = wantAllowDns
        panel.ksFailClosed = wantFailClosed
        panel.ksProtocols = wantProtocols
        panel.modeACoverage = wantCoverage
        panel.resolveHostsBypass = wantBypass
        // route.policy.update is a full-replacement request: any field left out
        // falls back to its serde default on the server, silently resetting it.
        // Build from the shared SSOT (`root._buildFullRoutePolicyReq`, which
        // carries every current field forward from `cur`) and overlay only the
        // keys this re-seed is actually restoring — this is what keeps a future
        // policy field from being forgotten here the way
        // `kill-switch-strict-shared-ips` / `browser-history-auto-seed` were.
        var req = root._buildFullRoutePolicyReq(cur)
        req["kill-switch-fail-closed"] = wantFailClosed
        req["kill-switch-protocols"] = wantProtocols
        req["include-subdomains"] = wantSub
        req["shared-ip-policy"] = wantShared
        req["kill-switch-block-all"] = wantBlockAll
        req["kill-switch-enabled"] = wantEnabled
        req["allow-dns-over-primary"] = wantAllowDns
        req["mode-a-coverage-strategy"] = wantCoverage
        req["resolve-hosts-bypass"] = wantBypass
        // Did we RE-ARM the kill-switch from the saved
        // mirror because the service had lost it (e.g. a state-DB wipe)? If so,
        // surface a visible notice so a restored kill-switch is never a surprise.
        var killSwitchReArmed = (wantEnabled === true && svcEnabled === false)
        var wCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
        root.rpc.registerRpcCallback(wCorr, function(ok, p, code, msg) {
            if (!ok) return
            // The service now holds the re-seeded values; keep the display
            // mirror in step so a later offline launch shows them.
            panel._rememberRoutePolicy(req)
            if (killSwitchReArmed) {
                root.killSwitchRestoredNoticeActive = true
                root.statusLine = root.tr("status.kill-switch-restored-from-prefs",
                    "Leak protection was restored from your saved settings.")
            } else {
                root.statusLine = root.tr("status.policy-toggles-restored",
                    "Your saved routing preferences were restored.")
            }
        })
    }

    // Read the persisted enforcement mode from the
    // service-stability config (global setting), independent of the per-SID
    // route-policy snapshot above.
    function _loadEnforcementMode() {
        // Seed Mode A/B and the fake-IP toggle FIRST, unconditionally, then let a
        // live config override below. Previously this seed lived only in the
        // bridge-absent branch, so a service-stopped-but-bridge-present launch fell
        // through to the RPC (which fails) and its `if(!ok) return` left the
        // selector at the QML default — same display-reset class as the subdomain toggle.
        // While offline, a parked intent (chosen but not yet pushed) outranks the
        // saved mirror so the panel shows what the user last picked; a successful
        // live read below always wins over both.
        var pendingSt = _parkedStability()
        var mirrorSt = _mirrorStability()
        panel.enforcementMode = _offlineStabilityPick(pendingSt, mirrorSt, "enforcement-mode",
            (root.prefs && root.prefs.routeEnforcementMode === "resolver")
                ? "resolver" : "reactive")
        // Neither of these has a per-key prefs mirror (the stability config is
        // their SSOT), so before the display mirror existed they fell back to the
        // QML default on every service-stopped launch.
        // Falling back to the CURRENT value keeps the historic "leave it alone
        // when nothing is known" behaviour, so the reconnect reload cannot flash
        // an unchecked box before the live reply lands.
        panel.fakeIpEnabled = _offlineStabilityPick(pendingSt, mirrorSt,
            "fake-ip-enabled", panel.fakeIpEnabled)
        panel.fakeIpUdpRelay = _offlineStabilityPick(pendingSt, mirrorSt,
            "fake-ip-udp-relay", panel.fakeIpUdpRelay)
        panel.fakeIpInstantRst = _offlineStabilityPick(pendingSt, mirrorSt,
            "fake-ip-instant-rst", panel.fakeIpInstantRst)
        panel.dnsViaSecondary = _offlineStabilityPick(pendingSt, mirrorSt,
            "dns-via-secondary", panel.dnsViaSecondary)
        panel.dnsFastAnswers = _offlineStabilityPick(pendingSt, mirrorSt,
            "dns-fast-answers", panel.dnsFastAnswers)
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            return
        }
        var corr = bridge.rpcServiceStabilityConfigGet()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) return
            var m = String((payload && payload["enforcement-mode"]) || "reactive")
            var svcMode = (m === "resolver") ? "resolver" : "reactive"
            // Panel open must NEVER mutate service state.
            // The 0717 HW run recorded a user `resolver` write at 09:00:14 followed
            // 3s later by an unintended write back to `reactive`; the culprit was
            // this callback auto-re-pushing the mirror's intent on mount. Per the
            // 0716 design decision the GUI reconciles TO the service's actual value
            // instead of pushing intent — deliberate offline changes ride the
            // dedicated pending-offline dialog, not panel open. So: show
            // the live service mode as the panel override, and make the prefs
            // MIRROR follow the service's actual value (a display seed only, no
            // push).
            // Anything the user changed while the service was down is still in
            // flight; the live reply predates it and must not overwrite the
            // switch they just set.
            var stillParked = panel._parkedStability()
            panel.enforcementMode = panel._livePick(payload, stillParked,
                "enforcement-mode", svcMode)
            // The fake-IP toggle rides the same config row;
            // read it from the same reply instead of firing a second GET.
            panel.fakeIpEnabled = panel._livePick(payload, stillParked,
                "fake-ip-enabled", (payload && payload["fake-ip-enabled"]) === true)
            panel.fakeIpUdpRelay = panel._livePick(payload, stillParked,
                "fake-ip-udp-relay", (payload && payload["fake-ip-udp-relay"]) === true)
            // Defaults ON, so an absent field must read as `true`.
            panel.fakeIpInstantRst = panel._livePick(payload, stillParked,
                "fake-ip-instant-rst", !payload || payload["fake-ip-instant-rst"] !== false)
            panel.dnsViaSecondary = panel._livePick(payload, stillParked,
                "dns-via-secondary", (payload && payload["dns-via-secondary"]) === true)
            panel.dnsFastAnswers = panel._livePick(payload, stillParked,
                "dns-fast-answers", !payload || payload["dns-fast-answers"] !== false)
            // A live read always wins — and refreshes the display mirror the
            // service-stopped seed reads back.
            panel._rememberStability(payload,
                ["enforcement-mode", "fake-ip-enabled", "fake-ip-udp-relay",
                 "fake-ip-instant-rst", "dns-via-secondary", "dns-fast-answers"])
            // The prefs copy of the mode is NOT updated from a read any more.
            // Doing so turned a service default into a user setting: a wiped
            // state DB answered "reactive", the panel wrote that into prefs,
            // and from then on the GUI could not tell the user's choice from
            // the service's default. The user's own choice is recorded where
            // every other service-owned setting records it — in the intent
            // blob, written by `applyServiceStabilityPatch` when the user
            // actually picks a mode. The display mirror above still follows the
            // live value, which is what the service-stopped seed reads back.
        })
    }
    // Re-read ONLY the enforcement mode from the live config and
    // reflect it in the selector. Used after a failed mode push so the GUI
    // never keeps displaying a mode the service is not actually running.
    function _refreshEnforcementModeFromService() {
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            return
        }
        var corr = bridge.rpcServiceStabilityConfigGet()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) return
            var m = String((payload && payload["enforcement-mode"]) || "reactive")
            var stillParked = panel._parkedStability()
            panel.enforcementMode = panel._livePick(payload, stillParked,
                "enforcement-mode", (m === "resolver") ? "resolver" : "reactive")
            // Keep the fake-IP checkbox honest on the same
            // re-sync (used after a failed push of either setting).
            panel.fakeIpEnabled = panel._livePick(payload, stillParked,
                "fake-ip-enabled", (payload && payload["fake-ip-enabled"]) === true)
            panel.fakeIpUdpRelay = panel._livePick(payload, stillParked,
                "fake-ip-udp-relay", (payload && payload["fake-ip-udp-relay"]) === true)
            panel.fakeIpInstantRst = panel._livePick(payload, stillParked,
                "fake-ip-instant-rst", !payload || payload["fake-ip-instant-rst"] !== false)
            panel.dnsViaSecondary = panel._livePick(payload, stillParked,
                "dns-via-secondary", (payload && payload["dns-via-secondary"]) === true)
            panel.dnsFastAnswers = panel._livePick(payload, stillParked,
                "dns-fast-answers", !payload || payload["dns-fast-answers"] !== false)
            panel._rememberStability(payload,
                ["enforcement-mode", "fake-ip-enabled", "fake-ip-udp-relay",
                 "fake-ip-instant-rst", "dns-via-secondary", "dns-fast-answers"])
            // The administrator rule-edit lock rides the same DTO; the window
            // owns it (the Rules section reads it), this panel only draws the
            // switch, so re-sync it from every read that lands here.
            if (typeof root.adoptRuleEditPermission === "function")
                root.adoptRuleEditPermission(payload || {})
            if (allowRuleEditsCheck) allowRuleEditsCheck.checked = root.allowUserRuleEdits
        })
    }

    // Administrator switch: may ordinary users change the routing rules on
    // this machine at all? Machine-wide and elevation-gated, so it rides the
    // same clobber-safe stability writer as its neighbours in this group.
    //
    // The origin tag deliberately does NOT start with `user:`. That prefix is
    // what records a value as "the user's intent" and replays it on every
    // reconnect — here it would resurrect a machine policy out of one user's
    // preferences, and raise an administrator prompt while doing it.
    //
    // This is also the ONLY writer that ever puts `allow-user-rule-edits` in a
    // patch. Every other save reaches the service through a read-modify-write
    // that echoes the field back exactly as it was read, which the service
    // accepts without elevation — that is what keeps an ordinary user able to
    // save unrelated settings while the lock is on.
    function _applyAllowUserRuleEdits(want) {
        var v = (want === true)
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            // Not parked offline like its neighbours: the write needs an
            // elevated, reachable service, and delivering it later would raise
            // an administrator prompt nobody asked for at that moment.
            allowRuleEditsCheck.checked = root.allowUserRuleEdits
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        root.applyServiceStabilityPatch({ "allow-user-rule-edits": v },
            function(ok, code, payload) {
                if (ok) {
                    // The service's echo wins over the request, so a write
                    // that reported success without taking effect cannot leave
                    // the switch lying about who may edit the rules.
                    if (typeof root.adoptRuleEditPermission === "function")
                        root.adoptRuleEditPermission(payload || {})
                    allowRuleEditsCheck.checked = root.allowUserRuleEdits
                    root.statusLine = root.allowUserRuleEdits
                        ? root.tr("status.rule-lock-off",
                            "Users can change the routing rules on this computer.")
                        : root.tr("status.rule-lock-on",
                            "Routing rules are locked — only an administrator can change them now.")
                    return
                }
                allowRuleEditsCheck.checked = root.allowUserRuleEdits
                var slug = String(code || "").toLowerCase().replace(/_/g, "-")
                if (slug === "forbidden") {
                    root.statusLine = root.tr("status.rule-lock-needs-admin",
                        "Only an administrator can change this. Approve the administrator prompt and try again.")
                    return
                }
                root.statusLine = root.tr("status.rule-lock-failed",
                    "Could not change who may edit the rules: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(slug) : slug)
            }, "admin:allow-user-rule-edits")
    }
    // Read-modify-write the WHOLE service-stability config, mutating ONLY
    // enforcement-mode, so the diagnostics/stability fields are preserved (Set
    // is a full-config write — omitting any field resets it to its default).
    function _applyEnforcementMode(slug) {
        var want = (String(slug) === "resolver") ? "resolver" : "reactive"
        // Service stopped: park the intent and offer
        // it on reconnect instead of firing a stability patch that would fail.
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            // The mirror write belongs ONLY to the offline branch:
            // here it is the display seed for the parked intent. A failed/timed-out
            // connected push must never leave the mirror holding a mode the service
            // never accepted, so the connected path (below) writes the mirror only
            // on success.
            if (root.prefs) { root.prefs.routeEnforcementMode = want; root.emitPrefs() }
            root._recordOfflineRoutingIntent("stability", "enforcement-mode", want)
            // Reflect the parked choice at once so the selector does not snap
            // back and the Mode-B-only fake-IP row becomes reachable offline.
            panel.enforcementMode = want
            return
        }
        // One clobber-safe writer: merges ONLY enforcement-mode
        // into the current config (preserving the Diagnostics-owned fields).
        root.applyServiceStabilityPatch({ "enforcement-mode": want }, function(ok, code) {
            if (ok) {
                // Persist the mirror only after the service accepts
                // the push, so a failed push leaves no stale intent behind.
                if (root.prefs) { root.prefs.routeEnforcementMode = want; root.emitPrefs() }
                panel.enforcementMode = want
                root.statusLine = (want === "resolver")
                    ? root.tr("status.enforcement-mode-resolver",
                        "Enforcement mode: local DNS resolver (Mode B). Takes effect after the background service restarts.")
                    : root.tr("status.enforcement-mode-reactive",
                        "Enforcement mode: reactive kill-switch (Mode A). Takes effect after the background service restarts.")
                return
            }
            if (code === "uac-declined") {
                root.statusLine = root.tr("status.enforcement-mode-uac-declined",
                    "Administrator approval was declined; the mode was not changed.")
            } else {
                root.statusLine = root.tr("status.enforcement-mode-failed",
                    "Could not update the enforcement mode: ")
                    + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            }
            // A failed push must never leave the selector showing a
            // mode the service is not running (the 0714 GUI-said-B/service-ran-A
            // desync). Re-sync the selector from the live config.
            panel._refreshEnforcementModeFromService()
        }, "user:enforcement-mode")
    }

    // Read-modify-write the WHOLE service-stability
    // config, mutating ONLY fake-ip-enabled (Set is a full-config write —
    // omitting any field resets it to its default). Global, admin-gated.
    function _applyFakeIpEnabled(want) {
        var v = (want === true)
        // Service stopped: park + offer on reconnect (mirror _applyEnforcementMode).
        // Reflect the choice locally at once; the push rides the pending dialog.
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            panel.fakeIpEnabled = v
            root._recordOfflineRoutingIntent("stability", "fake-ip-enabled", v)
            return
        }
        root.applyServiceStabilityPatch({ "fake-ip-enabled": v }, function(ok, code, payload) {
            if (ok) {
                // Trust the value the service echoes back, not the request: a
                // write that reports success while the service kept the old
                // state must not leave the checkbox lying (the  run
                // ended with the GUI showing fake-IP off and the relay still
                // carrying every flow).
                if (payload && payload["fake-ip-enabled"] !== undefined
                        && (payload["fake-ip-enabled"] === true) !== v) {
                    panel._refreshEnforcementModeFromService()
                    root.statusLine = root.tr("status.setting-not-applied",
                        "The background service did not apply this change — the switch "
                        + "was reset to what the service actually holds.")
                    return
                }
                panel.fakeIpEnabled = v
                root.statusLine = v
                    ? root.tr("status.fake-ip-on",
                        "Virtual-address routing (fake-IP) is on.")
                    : root.tr("status.fake-ip-off",
                        "Virtual-address routing (fake-IP) is off.")
                return
            }
            root.statusLine = root.tr("status.fake-ip-failed",
                "Could not change the fake-IP setting: ")
                + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            // Same discipline as the enforcement-mode selector: A
            // failed push must never leave the checkbox showing a state the
            // service does not hold — re-sync from the live config.
            panel._refreshEnforcementModeFromService()
        }, "user:fake-ip-enabled")
    }

    // Read-modify-write the WHOLE service-stability
    // config, mutating ONLY fake-ip-udp-relay (Set is a full-config write —
    // omitting any field resets it to its default). Global, admin-gated. Same
    // offline-park discipline as the fake-IP toggle.
    function _applyFakeIpUdpRelay(want) {
        var v = (want === true)
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            panel.fakeIpUdpRelay = v
            root._recordOfflineRoutingIntent("stability", "fake-ip-udp-relay", v)
            return
        }
        root.applyServiceStabilityPatch({ "fake-ip-udp-relay": v }, function(ok, code, payload) {
            if (ok) {
                // Trust the value the service echoes back, not the request —
                // same discipline as the fake-IP toggle.
                if (payload && payload["fake-ip-udp-relay"] !== undefined
                        && (payload["fake-ip-udp-relay"] === true) !== v) {
                    panel._refreshEnforcementModeFromService()
                    root.statusLine = root.tr("status.setting-not-applied",
                        "The background service did not apply this change — the switch "
                        + "was reset to what the service actually holds.")
                    return
                }
                panel.fakeIpUdpRelay = v
                root.statusLine = v
                    ? root.tr("status.fake-ip-udp-relay-on",
                        "Fake-IP UDP relay is on.")
                    : root.tr("status.fake-ip-udp-relay-off",
                        "Fake-IP UDP relay is off — QUIC falls back to TCP.")
                return
            }
            root.statusLine = root.tr("status.fake-ip-udp-relay-failed",
                "Could not change the fake-IP UDP relay setting: ")
                + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            // A failed push must never leave the checkbox showing a state the
            // service does not hold - re-sync from the live config.
            panel._refreshEnforcementModeFromService()
        }, "user:fake-ip-udp-relay")
    }

    // Read-modify-write the WHOLE service-stability
    // config, mutating ONLY fake-ip-instant-rst (Set is a full-config write —
    // omitting any field resets it to its default). Global, admin-gated. Same
    // offline-park discipline as the fake-IP toggle. Unlike fake-ip-udp-relay,
    // this toggle changes only dial-path behaviour in the relay — no WFP
    // filter set changes — so there is nothing more to re-sync here beyond the
    // usual failed-push safety net.
    function _applyFakeIpInstantRst(want) {
        var v = (want === true)
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            panel.fakeIpInstantRst = v
            root._recordOfflineRoutingIntent("stability", "fake-ip-instant-rst", v)
            return
        }
        root.applyServiceStabilityPatch({ "fake-ip-instant-rst": v }, function(ok, code, payload) {
            if (ok) {
                // Trust the value the service echoes back, not the request —
                // same discipline as the fake-IP toggle.
                if (payload && payload["fake-ip-instant-rst"] !== undefined
                        && (payload["fake-ip-instant-rst"] === true) !== v) {
                    panel._refreshEnforcementModeFromService()
                    root.statusLine = root.tr("status.setting-not-applied",
                        "The background service did not apply this change — the switch "
                        + "was reset to what the service actually holds.")
                    return
                }
                panel.fakeIpInstantRst = v
                root.statusLine = v
                    ? root.tr("status.fake-ip-instant-rst-on",
                        "Instant reset for the additional route is on.")
                    : root.tr("status.fake-ip-instant-rst-off",
                        "Instant reset is off — connections are held briefly instead of resetting.")
                return
            }
            root.statusLine = root.tr("status.fake-ip-instant-rst-failed",
                "Could not change the instant-reset setting: ")
                + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            // A failed push must never leave the checkbox showing a state the
            // service does not hold - re-sync from the live config.
            panel._refreshEnforcementModeFromService()
        }, "user:fake-ip-instant-rst")
    }

    // Read-modify-write the WHOLE service-stability config, mutating ONLY
    // dns-via-secondary (Set is a full-config write - omitting any field resets
    // it to its default). Global, admin-gated. Same offline-park discipline as
    // the fake-IP toggle.
    function _applyDnsViaSecondary(want) {
        var v = (want === true)
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            panel.dnsViaSecondary = v
            root._recordOfflineRoutingIntent("stability", "dns-via-secondary", v)
            return
        }
        root.applyServiceStabilityPatch({ "dns-via-secondary": v }, function(ok, code, payload) {
            if (ok) {
                // Same echo check as the fake-IP toggle: the service's own
                // value wins over the request.
                if (payload && payload["dns-via-secondary"] !== undefined
                        && (payload["dns-via-secondary"] === true) !== v) {
                    panel._refreshEnforcementModeFromService()
                    root.statusLine = root.tr("status.setting-not-applied",
                        "The background service did not apply this change — the switch "
                        + "was reset to what the service actually holds.")
                    return
                }
                panel.dnsViaSecondary = v
                root.statusLine = v
                    ? root.tr("status.dns-via-secondary-on",
                        "Name lookups now go through the additional connection.")
                    : root.tr("status.dns-via-secondary-off",
                        "Name lookups go through the main connection again.")
                return
            }
            root.statusLine = root.tr("status.dns-via-secondary-failed",
                "Could not change where name lookups go: ")
                + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            // A failed push must never leave the checkbox showing a state the
            // service does not hold - re-sync from the live config.
            panel._refreshEnforcementModeFromService()
        }, "user:dns-via-secondary")
    }

    // Read-modify-write the WHOLE service-stability config, mutating ONLY
    // dns-fast-answers (Set is a full-config write - omitting any field resets
    // it to its default). Global, admin-gated. Same offline-park discipline as
    // the DNS-over-secondary toggle.
    function _applyDnsFastAnswers(want) {
        var v = (want === true)
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            panel.dnsFastAnswers = v
            root._recordOfflineRoutingIntent("stability", "dns-fast-answers", v)
            return
        }
        root.applyServiceStabilityPatch({ "dns-fast-answers": v }, function(ok, code, payload) {
            if (ok) {
                // Same echo check as the neighbouring toggles: the service's own
                // value wins over the request. Absent means the default, ON.
                if (payload && payload["dns-fast-answers"] !== undefined
                        && (payload["dns-fast-answers"] !== false) !== v) {
                    panel._refreshEnforcementModeFromService()
                    root.statusLine = root.tr("status.setting-not-applied",
                        "The background service did not apply this change — the switch "
                        + "was reset to what the service actually holds.")
                    return
                }
                panel.dnsFastAnswers = v
                root.statusLine = v
                    ? root.tr("status.dns-fast-answers-on",
                        "Fast DNS answers are on.")
                    : root.tr("status.dns-fast-answers-off",
                        "Fast DNS answers are off — every answer waits for route protection.")
                return
            }
            root.statusLine = root.tr("status.dns-fast-answers-failed",
                "Could not change the fast DNS answers setting: ")
                + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            // A failed push must never leave the checkbox showing a state the
            // service does not hold - re-sync from the live config.
            panel._refreshEnforcementModeFromService()
        }, "user:dns-fast-answers")
    }

    // One-shot driver-status probe for the fake-IP group.
    // Reuses the third-party components report, whose verdict comes from the
    // SAME loader/signature check that gates the driver at runtime — this line
    // can never disagree with what enabling the feature would actually do. A
    // build that ships no driver binary (Linux/macOS: kernel TUN is native)
    // reports "none" and the line hides.
    function _loadFakeIpDriverStatus() {
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcThirdPartyComponentsList !== "function") {
            return
        }
        var corr = bridge.rpcThirdPartyComponentsList()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) return
            var list = (payload && payload.components) || []
            for (var i = 0; i < list.length; i += 1) {
                if (String(list[i].key) === "wintun") {
                    panel.fakeIpDriverVerdict = String(list[i].verdict || "")
                    return
                }
            }
            panel.fakeIpDriverVerdict = "none"
        })
    }

    // Human label for the driver verdict — reuses the third-party dialog's
    // verdict vocabulary (one wording per concept across the app).
    function _fakeIpDriverVerdictLabel() {
        if (panel.fakeIpDriverVerdict === "genuine")
            return root.tr("dialog.third-party.verdict-genuine", "Genuine")
        if (panel.fakeIpDriverVerdict === "untrusted")
            return root.tr("dialog.third-party.verdict-untrusted", "Does not match")
        return root.tr("dialog.third-party.verdict-missing", "Not installed")
    }

    // Track 1 Chunk 4 — is `secs` one of the dropdown presets?
    function _isLivenessPreset(secs) {
        return secs === 10 || secs === 30 || secs === 60
            || secs === 90 || secs === 120 || secs === 240
    }

    // Track 1 Chunk 4 — read the persisted secondary-liveness-window from the
    // service-stability config (global setting), independent of the per-SID
    // route-policy snapshot. Mirrors `_loadEnforcementMode`.
    function _loadLivenessWindow() {
        // Seed the liveness window FIRST, unconditionally (same
        // service-stopped-but-bridge-present gap as Mode A/B): a parked intent
        // outranks the display mirror, which outranks the per-key prefs mirror.
        var prefsSecs = 0
        if (root.prefs && root.prefs.routeLivenessWindowSecs !== undefined) {
            var s = root.prefs.routeLivenessWindowSecs | 0
            prefsSecs = (s === 0) ? 0 : Math.max(5, Math.min(3600, s))
        }
        panel.livenessWindowSecs = _offlineStabilityPick(_parkedStability(), _mirrorStability(),
            "secondary-liveness-window-secs", prefsSecs)
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            return
        }
        var corr = bridge.rpcServiceStabilityConfigGet()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) return
            var raw = (payload && payload["secondary-liveness-window-secs"])
            var svc = (raw === undefined || raw === null) ? 0 : (raw | 0)
            svc = (svc === 0) ? 0 : Math.max(5, Math.min(3600, svc))
            // A live read always wins — and refreshes the display mirror.
            panel._rememberStability(payload, ["secondary-liveness-window-secs"])
            // Re-seeding a wiped service used to happen HERE, for this one
            // field, by pushing the remembered value back on every connect.
            // That is now `root.replayServiceIntentToService()`, which covers
            // the whole stability group at once and runs before the panels
            // read. The single-field version was actively harmful: its
            // read-modify-write carried the wiped service's defaults for every
            // OTHER field back into the DB, cementing them seconds before the
            // user could be asked — that is how fake-IP, verbose logging and
            // the enforcement mode all reverted at once.
            panel.livenessWindowSecs = svc
        })
    }
    // Read-modify-write the WHOLE service-stability config, mutating ONLY
    // secondary-liveness-window-secs, so the other stability fields are
    // preserved (Set is a full-config write). Mirrors `_applyEnforcementMode`.
    function _applyLivenessWindow(secs) {
        var want = (secs | 0)
        want = (want === 0) ? 0 : Math.max(5, Math.min(3600, want))
        panel.livenessWindowSecs = want
        // Persist locally first, independent of the service RPC, so the choice
        // survives a service-DB wipe / offline toggle and is re-seeded on
        // reconnect (see `_applyEnforcementMode`).
        if (root.prefs) { root.prefs.routeLivenessWindowSecs = want; root.emitPrefs() }
        // Service stopped: park + offer on reconnect.
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            root._recordOfflineRoutingIntent("stability", "secondary-liveness-window-secs", want)
            return
        }
        // One clobber-safe writer: merges ONLY the liveness window
        // into the current config (preserving the other stability fields).
        root.applyServiceStabilityPatch(
            { "secondary-liveness-window-secs": want }, function(ok, code) {
            if (ok) {
                root.statusLine = (want === 0)
                    ? root.tr("status.liveness-window-disabled",
                        "Secondary tunnel liveness probe disabled.")
                    : root.tr("status.liveness-window-set",
                        "Secondary tunnel liveness window updated. Takes effect after the background service restarts.")
            } else if (code === "uac-declined") {
                root.statusLine = root.tr("status.liveness-window-uac-declined",
                    "Administrator approval was declined; the liveness window was not changed.")
            } else {
                root.statusLine = root.tr("status.liveness-window-failed",
                    "Could not update the liveness window: ")
                    + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            }
        }, "user:liveness-window")
    }

    // Read the relocated machine-wide routing policy
    // (rule-scope + stop-policy) from the service-stability config on mount.
    function _loadStopScope() {
        // Seed FIRST, unconditionally: these two had no offline source at all,
        // so a service-stopped launch always drew the QML literal defaults.
        var parkedSt = _parkedStability()
        var mirrorSt = _mirrorStability()
        panel.ruleScopeServiceDriven = _offlineStabilityPick(parkedSt, mirrorSt,
            "rule-scope-service-driven", panel.ruleScopeServiceDriven)
        panel.routingStopPolicy = _offlineStabilityPick(parkedSt, mirrorSt,
            "routing-stop-policy", panel.routingStopPolicy)
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function")
            return
        var corr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok || !payload) return
            var rs = payload["rule-scope-service-driven"]
            panel.ruleScopeServiceDriven = (rs === undefined) ? true : !!rs
            panel.routingStopPolicy =
                (String(payload["routing-stop-policy"]) === "persist") ? "persist" : "teardown"
            // A live read always wins — and refreshes the display mirror.
            panel._rememberStability(payload,
                ["rule-scope-service-driven", "routing-stop-policy"])
        })
    }
    // Apply-on-change through the shared clobber-safe merge writer, like
    // enforcement-mode / liveness-window (no draft/Save flow here).
    function _applyRuleScope(serviceDriven) {
        panel.ruleScopeServiceDriven = serviceDriven
        // Service stopped: park + offer on reconnect.
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            root._recordOfflineRoutingIntent("stability", "rule-scope-service-driven", serviceDriven)
            return
        }
        root.applyServiceStabilityPatch(
            { "rule-scope-service-driven": serviceDriven }, function(ok, code) {
            if (ok) {
                root.statusLine = root.tr("status.system-routing-set",
                    "System-level routing setting updated.")
            } else if (code === "uac-declined") {
                root.statusLine = root.tr("status.system-routing-uac-declined",
                    "Administrator approval was declined; the setting was not changed.")
            } else {
                root.statusLine = root.tr("status.system-routing-failed",
                    "Could not update the setting: ")
                    + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            }
        }, "user:rule-scope")
    }
    function _applyStopPolicy(persist) {
        var want = persist ? "persist" : "teardown"
        panel.routingStopPolicy = want
        // Service stopped: park + offer on reconnect.
        if (typeof root._routingBackendConnected === "function"
                && !root._routingBackendConnected()) {
            root._recordOfflineRoutingIntent("stability", "routing-stop-policy", want)
            return
        }
        root.applyServiceStabilityPatch(
            { "routing-stop-policy": want }, function(ok, code) {
            if (ok) {
                root.statusLine = root.tr("status.system-routing-set",
                    "System-level routing setting updated.")
            } else if (code === "uac-declined") {
                root.statusLine = root.tr("status.system-routing-uac-declined",
                    "Administrator approval was declined; the setting was not changed.")
            } else {
                root.statusLine = root.tr("status.system-routing-failed",
                    "Could not update the setting: ")
                    + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            }
        }, "user:stop-policy")
    }

    // Backend-connected edge tracker. The one-shot loaders in
    // Component.onCompleted silently no-op (or read the mock) when the panel is
    // built while the service is down; without a reload on the reconnect edge
    // the panel keeps showing offline defaults forever — e.g. the fake-IP
    // checkbox stuck unchecked while the service actually runs with fake-IP on.
    property bool _backendWasConnected: false

    function _reloadServiceBackedControls() {
        _loadKillSwitchPosture(); _loadEnforcementMode()
        _loadLivenessWindow(); _loadStopScope()
        _loadFakeIpDriverStatus()
    }

    Component.onCompleted: {
        _reloadServiceBackedControls()
        panel._backendWasConnected = (typeof root._routingBackendConnected === "function")
            && root._routingBackendConnected()
    }

    // Re-read on every visit. The panel is built once and kept alive, so a
    // policy the user changed ELSEWHERE — the tray toast flips
    // `auto-rules-mode`, another window applies something — left this showing
    // the value from mount time until the next reconnect. Opening the page is
    // the moment its answer has to be current.
    onVisibleChanged: if (visible) _reloadServiceBackedControls()

    // After the offline pending-changes dialog applies
    // or discards, re-load every control from the (now updated) service so the
    // panel never keeps showing a value the dialog just changed. The same
    // reload runs on every disconnected→connected edge (cold start on the mock
    // backend, service reinstall mid-session).
    Connections {
        target: root
        function onOfflinePendingApplied() {
            _loadKillSwitchPosture(); _loadEnforcementMode()
            _loadLivenessWindow(); _loadStopScope()
        }
        function onBackendStatusChanged() {
            var connected = (typeof root._routingBackendConnected === "function")
                && root._routingBackendConnected()
            if (connected && !panel._backendWasConnected)
                panel._reloadServiceBackedControls()
            panel._backendWasConnected = connected
        }
        // The connect-time replay may have just pushed the user's recorded
        // settings into a service that disagreed with them. Re-read, or the
        // panel would go on showing the values the service held a moment ago.
        function onServiceIntentReplayed() {
            panel._reloadServiceBackedControls()
        }
    }

    GroupBox {
        id: pauseGroup
        title: root.tr("settings.routing.pause.title", "Apply rules")
        Layout.fillWidth: true

        readonly property bool paused: (root.uiRevision >= 0)
            ? (root.routingState.routingPaused === true) : false
        readonly property bool trayActive: (root.uiRevision >= 0)
            ? (root.routingState.trayActive !== false) : true
        readonly property string pausedAt: (root.uiRevision >= 0)
            ? String(root.routingState.routingPausedAt || "") : ""

        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingSm

            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm

                Rectangle {
                    Layout.preferredWidth: 10
                    Layout.preferredHeight: 10
                    radius: 5
                    color: pauseGroup.paused
                        ? root.uiTheme.colorWarning
                        : root.uiTheme.colorSuccess
                }
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    text: pauseGroup.paused
                        ? root.tr("settings.routing.pause.status-paused", "Rules are disabled")
                        : root.tr("settings.routing.pause.status-active", "Rules are active")
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: pauseGroup.paused
                        ? root.tr("settings.routing.pause.action-enable", "Enable rules")
                        : root.tr("settings.routing.pause.action-disable", "Disable rules")
                    onClicked: root.setRoutingPauseEnabled(!pauseGroup.paused, "")
                }
            }

            Label {
                Layout.fillWidth: true
                visible: pauseGroup.paused && pauseGroup.pausedAt !== ""
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.pause.paused-since",
                    "Paused since {timestamp}")
                    .replace("{timestamp}", pauseGroup.pausedAt)
            }

            Label {
                Layout.fillWidth: true
                visible: !pauseGroup.trayActive
                color: root.uiTheme.colorWarning
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.pause.no-tray-warning",
                    "Tray is not running. Rules apply only while the tray is active.")
            }

            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.pause.persistence-hint",
                    "Disabling stops applying rules until you re-enable them. Setting persists across restarts.")
            }
        }
    }

    // Default route for traffic that
    // matches NO rule. Reuses RouteBehaviorMode (`behaviorModeModel`), and
    // writes to the SERVICE per-SID policy via `root.applyRouteBehaviorMode`
    // (Phase B1) so the choice actually drives WFP — not just the deprecated
    // UiPreferences mirror. Mirrors the selector on the Interfaces & Routes
    // screen; both stay in sync through `prefs.routeBehaviorMode`.
    GroupBox {
        id: defaultRouteGroup
        title: root.tr("settings.routing.default-route.title",
            "Default route for unmatched traffic")
        Layout.fillWidth: true
        visible: root.behaviorModeModel && root.behaviorModeModel.count > 0
        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.routing.default-route.description",
                    "Where traffic that matches no rule is sent. Rules always take priority. Default: primary route.")
            }
            ThemedComboBox {
                id: defaultRouteCombo
                theme: root.uiTheme
                Layout.fillWidth: true
                Layout.maximumWidth: 380
                model: root.behaviorModeModel
                textRole: "id"
                labelResolver: function(item) {
                    return item ? root.behaviorModeLabel(item.id) : ""
                }
                popup.width: root.comboPopupWidth(defaultRouteCombo, root.behaviorModeModel,
                    "id", function(item) { return root.behaviorModeLabel(item.id) })
                Component.onCompleted: {
                    var want = String(root.prefs.routeBehaviorMode || "prefer-primary")
                    var idx = 0
                    for (var i = 0; i < root.behaviorModeModel.count; i += 1) {
                        if (String(root.behaviorModeModel.get(i).id) === want) { idx = i; break }
                    }
                    currentIndex = idx
                    if (currentIndex >= 0 && currentIndex < root.behaviorModeModel.count)
                        displayText = root.behaviorModeLabel(root.behaviorModeModel.get(currentIndex).id)
                }
                onActivated: {
                    var id = root.behaviorModeModel.get(currentIndex).id
                    root.updatePrefs({ routeBehaviorMode: id })
                    root.emitPrefs()
                    if (typeof root.routePolicyController.applyRouteBehaviorMode === "function") {
                        root.routePolicyController.applyRouteBehaviorMode(id)
                    }
                    defaultRouteCombo.displayText = root.behaviorModeLabel(id)
                }
                Connections {
                    target: root
                    function onUiRevisionChanged() {
                        if (defaultRouteCombo.currentIndex >= 0
                                && defaultRouteCombo.currentIndex < root.behaviorModeModel.count)
                            defaultRouteCombo.displayText = root.behaviorModeLabel(
                                root.behaviorModeModel.get(defaultRouteCombo.currentIndex).id)
                    }
                }
            }
            // "Show details" / "Hide details" disclosure for the
            // default-route explainer prose (mirrors the leak-protection group's
            // `routingKsDetailsExpanded` collapse). Keeps the selector + its
            // one-line label above always visible; everything below folds away.
            ThemedButton {
                theme: root.uiTheme
                flat: true
                Layout.leftMargin: root.uiTheme.spacingSm
                text: root.routingDefaultRouteDetailsExpanded
                    ? root.tr("settings.routing.show-less", "Hide details")
                    : root.tr("settings.routing.show-more", "Show details")
                onClicked: root.routingDefaultRouteDetailsExpanded = !root.routingDefaultRouteDetailsExpanded
            }

            // Explain the SELECTED mode inline
            // (answers "what does Strict secondary mean?"). Reuses the
            // existing `settings.routing-behavior.mode.<slug>.description`
            // locale keys (flat catalog → the `settings.` prefix is required);
            // updates as the user changes the dropdown.
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                visible: root.routingDefaultRouteDetailsExpanded && text !== ""
                text: {
                    if (root.uiRevision < 0 || !root.behaviorModeModel
                            || defaultRouteCombo.currentIndex < 0
                            || defaultRouteCombo.currentIndex >= root.behaviorModeModel.count)
                        return ""
                    var id = String(root.behaviorModeModel.get(
                        defaultRouteCombo.currentIndex).id || "")
                    return id === ""
                        ? ""
                        : root.tr("settings.routing-behavior.mode." + id + ".description", "")
                }
            }

            // Routing is by IP address, so a site that
            // reports your IP (2ip / whatismyip) can read the "wrong" address:
            // its measurement endpoint may live on a different IP than the page,
            // or several sites may share one CDN IP. Stated plainly so the user
            // does not read a shared-IP quirk as a routing failure.
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: root.routingDefaultRouteDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                // Render the 2ip / whatismyip references as full
                // clickable links that open in the external browser.
                textFormat: Text.StyledText
                linkColor: root.uiTheme.colorAccent
                onLinkActivated: function(link) { Qt.openUrlExternally(link) }
                text: root.tr("settings.routing-behavior.ip-routing-note",
                    "Routing works by IP address. A website that checks and shows your IP (like <a href=\"https://2ip.ru\">2ip.ru</a> or <a href=\"https://whatismyipaddress.com\">whatismyipaddress.com</a>) can still display your provider's address: its measurement endpoint often lives on a different IP than the page itself, or a single IP is shared by several sites. If you use a general-purpose VPN as the additional adapter, such a site can also keep showing your provider's IP and country when it is not one of your routed rules — that traffic goes over your primary link, while your routed sites still go through the VPN. This is a known limitation, not a routing failure. Per-site (per-hostname) steering on a shared IP is not supported yet.")
            }

            // Treat a bare domain rule as also covering its
            // subdomains. Partially mitigates the above for sites whose
            // measurement endpoint is a SUBDOMAIN of the same site. Writes the
            // per-SID `include-subdomains` flag; enforcement-only (the stored
            // rules and the drift hash stay on the bare rules). Default ON.
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            CheckBox {
                id: includeSubdomainsCheck
                Layout.fillWidth: true
                checked: panel.includeSubdomains
                text: root.tr("settings.routing-behavior.include-subdomains.label",
                    "Also cover subdomains for domain rules (treat “example.com” as “example.com” + “*.example.com”)")
                contentItem: Label {
                    text: includeSubdomainsCheck.text
                    leftPadding: includeSubdomainsCheck.indicator.width + includeSubdomainsCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: {
                    panel.includeSubdomains = checked
                    if (typeof root.routePolicyController.applyIncludeSubdomains === "function")
                        root.routePolicyController.applyIncludeSubdomains(checked)
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: root.routingDefaultRouteDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing-behavior.include-subdomains.note",
                    "On by default: a rule for a site also covers that site's subdomains, so images and scripts from “cdn.example.com” take the same route as “example.com”. Applies to all your domain rules at once. It only catches subdomains of the SAME site — an IP-check served from a different provider (a third-party domain) still won't be covered — and it sends more traffic through the additional adapter. Turn it off to match the exact domain only.")
            }
        }
    }

    // Friendly display of the configured VPN executable (basename, no ".exe").
    // Empty when none is set. Read through `uiRevision` at the call site so it
    // re-evaluates when the onboarding writes `confirmedVpnExePath`.
    function _vpnDisplayName() {
        var p = String((root.prefs && root.prefs.confirmedVpnExePath) || "")
        if (p === "") return ""
        var i = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"))
        var b = i >= 0 ? p.substring(i + 1) : p
        return b.replace(/\.exe$/i, "")
    }

    // Dedicated "Your VPN client" group. Moved out of the leak-
    // protection group (per the placement decision) so it stays visible
    // regardless of the kill-switch state. Captures WHICH program is the user's
    // VPN so its traffic keeps flowing over the primary link while leak
    // protection is on (an "Application -> primary route" rule is already a
    // kill-switch exemption; this only records the executable).
    GroupBox {
        id: vpnClientGroup
        title: root.tr("settings.routing.vpn-client.title", "Your VPN client")
        Layout.fillWidth: true

        // Re-evaluated on every `uiRevision` bump (the onboarding writes the
        // pref via updatePrefs, which bumps it). Empty ⇒ nothing configured.
        property string vpnName: root.uiRevision >= 0 ? panel._vpnDisplayName() : ""

        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingSm

            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.vpn-client.note",
                    "Point NetRuleRouter at the program you use as your VPN so its traffic keeps flowing over your main link while leak protection is on.")
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: vpnClientGroup.vpnName !== ""
                        ? root.tr("settings.routing.vpn-client.current", "Current: {name}")
                            .replace("{name}", vpnClientGroup.vpnName)
                        : root.tr("settings.routing.vpn-client.none", "Not set")
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: vpnClientGroup.vpnName !== ""
                        ? root.tr("settings.routing.vpn-client.change", "Change")
                        : root.tr("settings.routing.vpn-client.set-up", "Set up my VPN")
                    onClicked: if (typeof root.openVpnOnboarding === "function")
                        root.openVpnOnboarding()
                }
            }
        }
    }

    // Leak protection is now its own GroupBox (previously it was
    // mixed into the default-route box). The bold master toggle is the first child;
    // the "Show details" disclosure, the enforcement-mode (A/B) selector and the
    // shared-IP selector live directly under it per the user's reorg. Resolved
    // : every sub-setting is gated on the master toggle, so the whole
    // subtree hides when the kill-switch is off.
    GroupBox {
        id: leakProtectionGroup
        title: root.tr("settings.routing.kill-switch.title", "Leak protection")
        Layout.fillWidth: true
        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingSm

            // MASTER kill-switch toggle (explicit opt-in). The
            // kill-switch is OFF by default: nothing is blocked, and every option
            // below stays hidden until the user turns it on here. Replaces the old
            // auto-arm-on-secondary-bound behaviour per an explicit UX
            // decision — enforcement is now the user's explicit choice.
            CheckBox {
                id: killSwitchEnableCheck
                Layout.fillWidth: true
                checked: panel.killSwitchEnabled
                text: root.tr("settings.routing.kill-switch.enable-label",
                    "Enable the kill-switch (block traffic when the additional adapter is down)")
                contentItem: Label {
                    text: killSwitchEnableCheck.text
                    leftPadding: killSwitchEnableCheck.indicator.width + killSwitchEnableCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                    font.bold: true
                }
                onToggled: {
                    // Arming leak protection over an additional adapter that
                    // has no way out to the network turns "not routed" into
                    // "blocked" for every destination the rules hand to it.
                    // Confirm first; the checkbox stays off until the user says
                    // yes, and nothing about the kill-switch is weakened.
                    if (checked
                            && root.interfacesRolesController
                            && typeof root.interfacesRolesController.unroutableBoundSecondaryRow === "function"
                            && typeof root.confirmUnroutableSecondary === "function") {
                        var badRow = root.interfacesRolesController.unroutableBoundSecondaryRow()
                        if (badRow) {
                            killSwitchEnableCheck.checked = false
                            root.confirmUnroutableSecondary(badRow, "kill-switch", function() {
                                killSwitchEnableCheck.checked = true
                                panel.killSwitchEnabled = true
                                if (typeof root.routePolicyController.applyKillSwitchEnabled === "function")
                                    root.routePolicyController.applyKillSwitchEnabled(true)
                            })
                            return
                        }
                    }
                    panel.killSwitchEnabled = checked
                    if (typeof root.routePolicyController.applyKillSwitchEnabled === "function")
                        root.routePolicyController.applyKillSwitchEnabled(checked)
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.kill-switch.enable-note",
                    "Off by default. While off, nothing is blocked — if the additional adapter drops, traffic falls back to your main link (this can expose your real address, which is fine if you don't need blocking). Turn it on to reveal the blocking options below.")
            }

            // VPN-client onboarding moved to its own "Your VPN client" group
            // above so it is visible regardless of the kill-switch
            // state — see `vpnClientGroup`.

            // "Show details" / "Hide details" disclosure for the full explainer.
            ThemedButton {
                theme: root.uiTheme
                flat: true
                visible: panel.killSwitchEnabled
                Layout.leftMargin: root.uiTheme.spacingSm
                text: root.routingKsDetailsExpanded
                    ? root.tr("settings.routing.show-less", "Hide details")
                    : root.tr("settings.routing.show-more", "Show details")
                onClicked: root.routingKsDetailsExpanded = !root.routingKsDetailsExpanded
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled && root.routingKsDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.kill-switch.description",
                    "Closes the leak window with no race: if the additional adapter goes down, matched traffic is dropped rather than sent over the primary route under your real address. Requires the additional adapter to be assigned. Traffic that matches no rule is unaffected.")
            }

            // Coverage caveat. Protection is IP-based
            // and learned from the system DNS observer, so freshly-rotated CDN
            // IPs have a brief gap and DoH-resolving apps bypass it entirely.
            // Stated plainly so users do not over-trust the guard.
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled && root.routingKsDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.kill-switch.coverage-note",
                    "How coverage works: protection tracks the IP addresses a routed site resolves to, learned by watching your system's DNS. It extends automatically as new addresses appear (e.g. when a site behind a CDN rotates IPs), but a brand-new address has a brief unprotected moment until it is seen. Apps that resolve names themselves over DNS-over-HTTPS (DoH) bypass this — turn off DoH in the browser/app for full protection. A diagnostic ping is the hardest case: it fires a single packet the instant a name resolves — before protection can catch up — and pinging a bare IP address skips name-based routing entirely; neither reflects how apps normally connect.")
            }

            // Enforcement mechanism selector.
            // Mode A (reactive kill-switch, default) vs Mode B (local DNS
            // resolver, enforce-before-connect). Global service setting; takes
            // effect after the service restarts. Redirecting DNS is invasive.
            Item {
                visible: panel.killSwitchEnabled
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            Label {
                Layout.fillWidth: true
                visible: panel.killSwitchEnabled
                color: root.textColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.routing.enforcement-mode.label",
                    "How routed traffic is enforced")
            }
            ThemedComboBox {
                id: enforcementModeCombo
                theme: root.uiTheme
                visible: panel.killSwitchEnabled
                Layout.fillWidth: true
                Layout.maximumWidth: 460
                // Mode A (reactive) is a non-maintained legacy fallback, offered
                // ONLY behind the Experimental opt-in. It used to also appear
                // whenever it happened to be the active mode — which sounds
                // harmless but wasn't: a service with a wiped state DB came up
                // in mode A, the selector then showed mode A as the current
                // choice, and the opt-in the user had deliberately left off
                // counted for nothing. Resolver (mode B) is always offered and
                // is the default, so nobody gets stranded by hiding mode A.
                readonly property bool showModeA:
                    root.uiRevision >= 0 && root.prefs.allowModeAKillswitch === true
                onShowModeAChanged: enforcementModeCombo._rebuildModel()
                model: ListModel {
                    ListElement { slug: "resolver"; label: "" }
                }
                textRole: "label"
                function _slugLabel(slug) {
                    return root.tr("settings.routing.enforcement-mode.option-" + slug,
                        slug === "resolver"
                            ? "Local DNS resolver (Mode B) — enforce before connect"
                            : "Reactive kill-switch (Mode A, default)")
                }
                // Insert / remove the "reactive" (mode A) row at the head of the
                // model to match `showModeA`, keeping "resolver" always present.
                function _rebuildModel() {
                    var m = enforcementModeCombo.model
                    var hasA = m.count > 0 && String(m.get(0).slug) === "reactive"
                    if (enforcementModeCombo.showModeA && !hasA)
                        m.insert(0, { slug: "reactive", label: "" })
                    else if (!enforcementModeCombo.showModeA && hasA)
                        m.remove(0)
                    _refreshLabels()
                }
                function _indexOfSlug(slug) {
                    for (var i = 0; i < enforcementModeCombo.model.count; i += 1)
                        if (String(enforcementModeCombo.model.get(i).slug) === slug)
                            return i
                    return 0
                }
                function _refreshLabels() {
                    var m = enforcementModeCombo.model
                    for (var i = 0; i < m.count; i += 1)
                        m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                    _syncFromState()
                }
                function _syncFromState() {
                    currentIndex = _indexOfSlug(String(panel.enforcementMode))
                    displayText = _slugLabel(String(panel.enforcementMode))
                }
                Component.onCompleted: _rebuildModel()
                onActivated: {
                    var slug = String(model.get(currentIndex).slug)
                    displayText = _slugLabel(slug)
                    if (typeof panel._applyEnforcementMode === "function")
                        panel._applyEnforcementMode(slug)
                }
                Connections {
                    target: panel
                    function onEnforcementModeChanged() { enforcementModeCombo._syncFromState() }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.enforcement-mode.note",
                    "Mode B sends system DNS through a local resolver so a routed site is enforced before its first packet — closing the leak window Mode A can't. It is invasive (redirects DNS) and IPv4-only; leave it off unless you are testing it. Changing this applies immediately — no service restart needed.")
            }

            // Virtual-address routing. Only
            // meaningful in Mode B (the resolver controls the DNS answer), so
            // the checkbox and its rows are hidden in Mode A and appear only
            // when Mode B is selected; the long hint folds behind "Show details".
            Item {
                visible: panel.killSwitchEnabled && panel.enforcementMode === "resolver"
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            RowLayout {
                Layout.fillWidth: true
                // Unlike fake-IP this is not Mode-B-only: it changes where the
                // service's own lookups leave from, which matters in either
                // enforcement mode. It still needs leak protection on, because
                // that is what binds an additional connection at all.
                visible: panel.killSwitchEnabled
                CheckBox {
                    id: dnsViaSecondaryCheck
                    Layout.fillWidth: true
                    checked: panel.dnsViaSecondary
                    text: root.tr("settings.routing.dns-via-secondary.label",
                        "DNS through the tunnel")
                    contentItem: Label {
                        text: dnsViaSecondaryCheck.text
                        leftPadding: dnsViaSecondaryCheck.indicator.width + dnsViaSecondaryCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: panel._applyDnsViaSecondary(checked)
                    Connections {
                        target: panel
                        function onDnsViaSecondaryChanged() {
                            dnsViaSecondaryCheck.checked = panel.dnsViaSecondary
                        }
                    }
                }
                ThemedButton {
                    theme: root.uiTheme
                    flat: true
                    Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                    text: root.routingDnsViaSecondaryDetailsExpanded
                        ? root.tr("settings.routing.show-less", "Hide details")
                        : root.tr("settings.routing.show-more", "Show details")
                    onClicked: root.routingDnsViaSecondaryDetailsExpanded = !root.routingDnsViaSecondaryDetailsExpanded
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                    && root.routingDnsViaSecondaryDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.routing.dns-via-secondary.note",
                    "Site names are looked up through the additional connection instead of your "
                    + "provider's resolver, so the provider can neither see nor alter the answers. "
                    + "Some providers return a wrong or empty address for certain sites, which makes "
                    + "those sites fail to load even when routing is correct. If the additional "
                    + "connection is not available, lookups fall back to the main one. Off by default.")
            }
            Item {
                visible: panel.killSwitchEnabled
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            // Answer-latency vs protection-install ordering. Rides the same
            // stability config as the row above and, like it, matters in either
            // enforcement mode, so it shares that row's visibility condition.
            // The trade-off fits one line, so it gets a plain description
            // instead of a "Show details" disclosure.
            CheckBox {
                id: dnsFastAnswersCheck
                Layout.fillWidth: true
                visible: panel.killSwitchEnabled
                checked: panel.dnsFastAnswers
                text: root.tr("settings.routing.dns-fast-answers.label",
                    "Fast DNS answers")
                contentItem: Label {
                    text: dnsFastAnswersCheck.text
                    leftPadding: dnsFastAnswersCheck.indicator.width + dnsFastAnswersCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: panel._applyDnsFastAnswers(checked)
                Connections {
                    target: panel
                    function onDnsFastAnswersChanged() {
                        dnsFastAnswersCheck.checked = panel.dnsFastAnswers
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.dns-fast-answers.note",
                    "Answer apps immediately; route protection finishes in the background. "
                    + "Turning this off can slow down page loads.")
            }
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            RowLayout {
                Layout.fillWidth: true
                visible: panel.killSwitchEnabled && panel.enforcementMode === "resolver"
                CheckBox {
                    id: fakeIpCheck
                    Layout.fillWidth: true
                    checked: panel.fakeIpEnabled
                    text: root.tr("settings.routing.fake-ip.label",
                        "Route sites over virtual addresses (fake-IP)")
                    contentItem: Label {
                        text: fakeIpCheck.text
                        leftPadding: fakeIpCheck.indicator.width + fakeIpCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: panel._applyFakeIpEnabled(checked)
                    Connections {
                        target: panel
                        function onFakeIpEnabledChanged() { fakeIpCheck.checked = panel.fakeIpEnabled }
                    }
                }
                ThemedButton {
                    theme: root.uiTheme
                    flat: true
                    Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                    text: root.routingFakeIpDetailsExpanded
                        ? root.tr("settings.routing.show-less", "Hide details")
                        : root.tr("settings.routing.show-more", "Show details")
                    onClicked: root.routingFakeIpDetailsExpanded = !root.routingFakeIpDetailsExpanded
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                    && panel.enforcementMode === "resolver"
                    && root.routingFakeIpDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.fake-ip.note",
                    "Each routed site is answered with its own virtual address, so routing stays per-site even when several sites share one real server address — and protection no longer races the first connection. Requires Mode B (local DNS resolver). On Windows, turning this on loads the bundled Wintun virtual-adapter driver (signed by WireGuard LLC). Off by default.")
            }
            // Driver status line — hidden on builds that ship no driver binary
            // (Linux/macOS: kernel TUN is native) and until the probe answers.
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                    && panel.enforcementMode === "resolver"
                    && panel.fakeIpDriverVerdict !== ""
                    && panel.fakeIpDriverVerdict !== "none"
                color: panel.fakeIpDriverVerdict === "genuine"
                    ? root.mutedTextColor : root.uiTheme.colorWarning
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.fake-ip.driver-status",
                        "Virtual-adapter driver (Wintun): ")
                    + panel._fakeIpDriverVerdictLabel()
            }
            // UDP relay for the fake-IP pool. Only meaningful while fake-IP
            // itself is on (it changes what the pool permit does with UDP), so
            // it shares the fake-IP row's visibility plus a check on the
            // fake-IP toggle. The trade-off fits one line, so — like the
            // fast-DNS-answers toggle — it gets a plain description instead of
            // a "Show details" disclosure.
            CheckBox {
                id: fakeIpUdpRelayCheck
                Layout.fillWidth: true
                visible: panel.killSwitchEnabled
                    && panel.enforcementMode === "resolver"
                    && panel.detailedModeOn
                    && panel.fakeIpEnabled
                checked: panel.fakeIpUdpRelay
                text: root.tr("settings.routing.fake-ip-udp-relay.label",
                    "Fake-IP UDP relay (experimental)")
                contentItem: Label {
                    text: fakeIpUdpRelayCheck.text
                    leftPadding: fakeIpUdpRelayCheck.indicator.width + fakeIpUdpRelayCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: panel._applyFakeIpUdpRelay(checked)
                Connections {
                    target: panel
                    function onFakeIpUdpRelayChanged() {
                        fakeIpUdpRelayCheck.checked = panel.fakeIpUdpRelay
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                    && panel.enforcementMode === "resolver"
                    && panel.detailedModeOn
                    && panel.fakeIpEnabled
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.fake-ip-udp-relay.note",
                    "Carry QUIC/HTTP-3 through the relay instead of forcing browsers to fall back to TCP.")
            }
            // Instant-reset toggle for a fake-IP relay dial refused because the
            // additional route can't be resolved (most commonly mid-VPN-
            // reconnect). Same visibility as the UDP-relay row: only meaningful
            // while fake-IP itself is on. Defaults ON (today's behaviour).
            CheckBox {
                id: fakeIpInstantRstCheck
                Layout.fillWidth: true
                visible: panel.killSwitchEnabled
                    && panel.enforcementMode === "resolver"
                    && panel.detailedModeOn
                    && panel.fakeIpEnabled
                checked: panel.fakeIpInstantRst
                text: root.tr("settings.routing.fake-ip-instant-rst.label",
                    "Instant reset when the additional route is unavailable")
                contentItem: Label {
                    text: fakeIpInstantRstCheck.text
                    leftPadding: fakeIpInstantRstCheck.indicator.width + fakeIpInstantRstCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: panel._applyFakeIpInstantRst(checked)
                Connections {
                    target: panel
                    function onFakeIpInstantRstChanged() {
                        fakeIpInstantRstCheck.checked = panel.fakeIpInstantRst
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                    && panel.enforcementMode === "resolver"
                    && panel.detailedModeOn
                    && panel.fakeIpEnabled
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.fake-ip-instant-rst.note",
                    "On (default): apps get an immediate connection reset when the additional route can't be resolved, so they can retry or fail over right away. Off: connections are held for up to 10 seconds while the route comes back, instead of resetting immediately.")
            }

            // Mode-A coverage strategy: what happens to traffic whose
            // destination is not yet in the learned pin set while the additional
            // route is unavailable. Only meaningful in Mode A (reactive), so it
            // hides in Mode B, where the resolver enforces before the first
            // packet. Per-SID `mode-a-coverage-strategy`; the default flipped to
            // Fail-closed-unknown (leak protection must hold even
            // while the pin set is incomplete — the "ping still passes with the
            // VPN closed" report). `zone-widening` exists in the enum but is not
            // yet enforced, so it is deliberately NOT offered here.
            Item {
                visible: panel.killSwitchEnabled && panel.enforcementMode !== "resolver"
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            Label {
                visible: panel.killSwitchEnabled && panel.enforcementMode !== "resolver"
                Layout.fillWidth: true
                color: root.textColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.routing.mode-a-coverage.label",
                    "When the additional route is unavailable (Mode A)")
            }
            ThemedComboBox {
                id: modeACoverageCombo
                visible: panel.killSwitchEnabled && panel.enforcementMode !== "resolver"
                theme: root.uiTheme
                Layout.fillWidth: true
                Layout.maximumWidth: 460
                model: ListModel {
                    ListElement { slug: "fail-closed-unknown"; label: "" }
                    ListElement { slug: "per-ip"; label: "" }
                }
                textRole: "label"
                function _slugLabel(slug) {
                    return root.tr("settings.routing.mode-a-coverage.option-" + slug,
                        slug === "per-ip"
                            ? "Block only the learned addresses of routed sites (may briefly leak)"
                            : "Block all unresolved traffic (default, safest)")
                }
                function _indexOfSlug(slug) {
                    for (var i = 0; i < modeACoverageCombo.model.count; i += 1)
                        if (String(modeACoverageCombo.model.get(i).slug) === slug)
                            return i
                    return 0
                }
                function _refreshLabels() {
                    var m = modeACoverageCombo.model
                    for (var i = 0; i < m.count; i += 1)
                        m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                    _syncFromState()
                }
                function _syncFromState() {
                    currentIndex = _indexOfSlug(String(panel.modeACoverage))
                    displayText = _slugLabel(String(panel.modeACoverage))
                }
                Component.onCompleted: _refreshLabels()
                onActivated: {
                    var slug = String(model.get(currentIndex).slug)
                    panel.modeACoverage = slug
                    displayText = _slugLabel(slug)
                    if (typeof root.routePolicyController.applyModeACoverageStrategy === "function")
                        root.routePolicyController.applyModeACoverageStrategy(slug)
                }
                Connections {
                    target: panel
                    function onModeACoverageChanged() { modeACoverageCombo._syncFromState() }
                }
                Connections {
                    target: root
                    function onUiRevisionChanged() { modeACoverageCombo._refreshLabels() }
                }
            }
            Label {
                visible: panel.killSwitchEnabled && panel.enforcementMode !== "resolver"
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.mode-a-coverage.note",
                    "Applies while leak protection is armed and the additional adapter is down or unresolved. “Block all unresolved traffic” closes the gap where a routed site rotates to a fresh, not-yet-learned IP that would otherwise leak over the primary link. VPN clients and apps routed to the primary adapter stay exempt so the tunnel can always reconnect.")
            }

            // Shared addresses — one titled frame for the two settings that both
            // answer "a single IP serves several sites". They stay two separate
            // controls on two different axes: the combo box decides ROUTING
            // while the additional adapter is up, the check box decides
            // BLOCKING while it is down. They used to sit far apart, which made
            // users read one as the other; the axis lines below say which is
            // which. Wire keys and appliers are unchanged.
            Item {
                visible: panel.killSwitchEnabled
                Layout.fillWidth: true
                Layout.preferredHeight: root.uiTheme.spacingSm
            }
            GroupBox {
                id: sharedAddressesGroup
                visible: panel.killSwitchEnabled
                Layout.fillWidth: true
                title: root.tr("settings.routing.shared-addresses.title",
                    "Shared addresses (one IP serving several sites)")

                ColumnLayout {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    spacing: root.uiTheme.spacingSm

                    // Routing axis. When a routed domain shares its IP with
                    // unrelated sites (shared CDN, e.g. Cloudflare), IP-level
                    // routing can't separate them — this picks the trade-off.
                    // Writes the per-SID `shared-ip-policy`; enforcement-only.
                    // Default balanced.
                    Label {
                        Layout.fillWidth: true
                        visible: panel.killSwitchEnabled
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing.shared-addresses.routing-axis",
                            "While the secondary adapter is up: whether a shared IP is routed through it.")
                    }
                    Label {
                        Layout.fillWidth: true
                        visible: panel.killSwitchEnabled
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        text: root.tr("settings.routing-behavior.shared-ip.label",
                            "When a routed domain shares an IP address with other sites")
                    }
                    ThemedComboBox {
                        id: sharedIpCombo
                        theme: root.uiTheme
                        visible: panel.killSwitchEnabled
                        Layout.fillWidth: true
                        Layout.maximumWidth: 460
                        model: ListModel {
                            ListElement { slug: "majority-of-ip"; label: "" }
                            ListElement { slug: "majority-of-rules"; label: "" }
                            ListElement { slug: "any-rule-domain"; label: "" }
                        }
                        textRole: "label"
                        function _slugLabel(slug) {
                            return root.tr("settings.routing-behavior.shared-ip.option-" + slug,
                                slug === "majority-of-ip"
                                    ? "Route the shared IP only if most sites on it are yours (balanced)"
                                    : slug === "majority-of-rules"
                                        ? "Route the shared IP only if it holds most of your rules (cautious)"
                                        : "Always route the whole shared IP (aggressive)")
                        }
                        function _indexOfSlug(slug) {
                            for (var i = 0; i < sharedIpCombo.model.count; i += 1)
                                if (String(sharedIpCombo.model.get(i).slug) === slug)
                                    return i
                            return 0
                        }
                        function _refreshLabels() {
                            var m = sharedIpCombo.model
                            for (var i = 0; i < m.count; i += 1)
                                m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                            _syncFromState()
                        }
                        function _syncFromState() {
                            currentIndex = _indexOfSlug(String(panel.sharedIpPolicy))
                            displayText = _slugLabel(String(panel.sharedIpPolicy))
                        }
                        Component.onCompleted: _refreshLabels()
                        onActivated: {
                            var slug = String(model.get(currentIndex).slug)
                            panel.sharedIpPolicy = slug
                            displayText = _slugLabel(slug)
                            if (typeof root.routePolicyController.applySharedIpPolicy === "function")
                                root.routePolicyController.applySharedIpPolicy(slug)
                        }
                        Connections {
                            target: panel
                            function onSharedIpPolicyChanged() { sharedIpCombo._syncFromState() }
                        }
                        Connections {
                            target: root
                            function onUiRevisionChanged() { sharedIpCombo._refreshLabels() }
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        visible: panel.killSwitchEnabled
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing-behavior.shared-ip.note",
                            "Some sites (e.g. behind Cloudflare) share one IP with unrelated sites, and IP routing can't tell them apart. “Balanced” routes such an IP through the additional adapter only when your sites are the majority on it; “Cautious” only when that IP carries most of your rules; “Aggressive” always routes it (the others on it come along too). Truly separating two sites on one IP by name is not supported yet.")
                    }

                    // Blocking axis. Big sites serve many hostnames from one
                    // front-end address (gemini.google.com and www.google.com
                    // share IPs), so pinning every routed address can cut
                    // ordinary sites. Default OFF = "smart" (shared addresses
                    // are not pinned); ON = strict historic behaviour. Snapshot
                    // is the SSOT (no prefs mirror), mirroring the DoH-lockdown
                    // toggle.
                    Item {
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                        Layout.fillWidth: true
                        Layout.preferredHeight: root.uiTheme.spacingSm
                    }
                    Label {
                        Layout.fillWidth: true
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing.shared-addresses.blocking-axis",
                            "While the secondary adapter is down: whether shared addresses are blocked.")
                    }
                    CheckBox {
                        id: ksStrictSharedCheck
                        Layout.fillWidth: true
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                        checked: panel.ksStrictSharedIps
                        text: root.tr("settings.routing.kill-switch.shared-strict-label",
                            "Strict: also block addresses shared with regular sites (may break them)")
                        contentItem: Label {
                            text: ksStrictSharedCheck.text
                            leftPadding: ksStrictSharedCheck.indicator.width + ksStrictSharedCheck.spacing
                            color: root.textColor
                            wrapMode: Text.WordWrap
                            verticalAlignment: Text.AlignVCenter
                        }
                        onToggled: {
                            panel.ksStrictSharedIps = checked
                            if (typeof root.routePolicyController.applyKillSwitchStrictSharedIps === "function")
                                root.routePolicyController.applyKillSwitchStrictSharedIps(checked)
                        }
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        flat: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                        text: root.routingSharedStrictDetailsExpanded
                            ? root.tr("settings.routing.show-less", "Hide details")
                            : root.tr("settings.routing.show-more", "Show details")
                        onClicked: root.routingSharedStrictDetailsExpanded = !root.routingSharedStrictDetailsExpanded
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                            && root.routingSharedStrictDetailsExpanded
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing.kill-switch.shared-strict-note",
                            "Off (smart, recommended): an address that a routed site shares with an ordinary site is not blocked, so the ordinary site keeps working — at the cost of the routed site's traffic to that shared address not being protected while the additional adapter is down. On (strict): every routed address is blocked, including shared ones — no leak, but co-hosted ordinary sites (for example google.com sharing addresses with routed Google services) stop opening while the block is active.")
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                            && !panel.ksStrictSharedIps
                            && (root.uiRevision >= 0
                                ? Number(root.routingState.killSwitchSharedIpExemptions || 0) > 0
                                : false)
                        color: root.uiTheme.colorWarning
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing.kill-switch.shared-smart-warning",
                            "Kill-switch strictness is reduced: shared addresses excluded from blocking — ")
                            + (root.uiRevision >= 0
                                ? Number(root.routingState.killSwitchSharedIpExemptions || 0) : 0)
                    }
                    // The count alone says something is excluded but not what,
                    // so the same "Show details" affordance used above opens
                    // the addresses themselves. The list arrives with the
                    // connect snapshot only when the running service reports
                    // it; when it does not, the expander says so instead of
                    // showing an empty box.
                    ThemedButton {
                        theme: root.uiTheme
                        flat: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        visible: panel.killSwitchEnabled && panel.ksFailClosed
                            && !panel.ksStrictSharedIps
                            && (root.uiRevision >= 0
                                ? Number(root.routingState.killSwitchSharedIpExemptions || 0) > 0
                                : false)
                        text: root.routingSharedExemptAddressesExpanded
                            ? root.tr("settings.routing.show-less", "Hide details")
                            : root.tr("settings.routing.show-more", "Show details")
                        onClicked: root.routingSharedExemptAddressesExpanded =
                            !root.routingSharedExemptAddressesExpanded
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        visible: root.routingSharedExemptAddressesExpanded
                            && panel.killSwitchEnabled && panel.ksFailClosed
                            && !panel.ksStrictSharedIps
                            && panel.sharedExemptAddresses.length === 0
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing.kill-switch.shared-smart-list-unavailable",
                            "The running service reports how many addresses were excluded, but not which ones.")
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        spacing: root.uiTheme.spacingSm
                        visible: root.routingSharedExemptAddressesExpanded
                            && panel.killSwitchEnabled && panel.ksFailClosed
                            && !panel.ksStrictSharedIps
                            && panel.sharedExemptAddresses.length > 0
                        Label {
                            Layout.fillWidth: true
                            color: root.mutedTextColor
                            wrapMode: Text.WordWrap
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                            text: root.tr("settings.routing.kill-switch.shared-smart-list-title",
                                "Excluded addresses")
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            flat: true
                            text: root.tr("settings.routing.kill-switch.copy-addresses",
                                "Copy addresses")
                            onClicked: {
                                var bridge = (typeof nrrNativeBridge !== "undefined")
                                    ? nrrNativeBridge : null
                                if (bridge && typeof bridge.copyToClipboard === "function") {
                                    bridge.copyToClipboard(panel._exemptAddressLines().join("\n"))
                                    root.statusLine = root.tr("status.copied-to-clipboard",
                                        "Copied to clipboard.")
                                }
                            }
                        }
                    }
                    ScrollView {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingSm
                        Layout.preferredHeight: Math.min(160,
                            Math.max(48, panel.sharedExemptAddresses.length
                                * (root.uiTheme.baseFontSizePx + 6) + 12))
                        clip: true
                        visible: root.routingSharedExemptAddressesExpanded
                            && panel.killSwitchEnabled && panel.ksFailClosed
                            && !panel.ksStrictSharedIps
                            && panel.sharedExemptAddresses.length > 0
                        // Read-only but selectable so a support hand-off can
                        // copy the whole set with Ctrl+A / Ctrl+C.
                        TextEdit {
                            readOnly: true
                            selectByMouse: true
                            wrapMode: TextEdit.NoWrap
                            color: root.textColor
                            selectionColor: root.uiTheme.colorSelection
                            font.family: "Consolas, monospace"
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                            text: panel._exemptAddressLines().join("\n")
                        }
                    }
                }
            }

            // Leak protection is no longer an
            // opt-in toggle that could be silently left OFF. Binding a
            // secondary (additional) adapter is itself the request to protect
            // its traffic, so the guard arms AUTOMATICALLY whenever a secondary
            // is assigned and stays armed while that adapter is unreachable
            // (down / not started / reinstalled under a new name). The only
            // user choice is the posture below (block vs allow). This closes
            // a leak where an un-ticked toggle silently disabled
            // protection so the secondary adapter drop leaked to the primary.
            Item { Layout.fillWidth: true; Layout.preferredHeight: root.uiTheme.spacingSm }

            // The redundant bold "Защита от утечки" section header
            // was removed: the bold master toggle above ("Включить защиту от
            // утечки") is the single anchor for the feature now that the term is
            // unified, so a second heading mid-section only duplicated it. The
            // always-on explainer below now introduces the posture sub-settings.
            // Always-on explainer — replaces the old opt-in summary and covers
            // the "adapter not found / not started" case the user raged about.
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                visible: panel.killSwitchEnabled
                text: root.tr("settings.routing.kill-switch.always-on",
                    "While the kill-switch is ON and the additional adapter can't be reached — it is down, not started, or was reinstalled under a new name — traffic matched by your rules is blocked instead of leaking over your primary route. Choose what happens below.")
            }

            // Aggressive kill-switch scope. When the
            // additional adapter is unavailable, block ALL egress (kill-switch)
            // instead of only its cached routed IPs — closes ICMP/ping and
            // rotating-IP leaks. Writes the per-SID `kill-switch-block-all`; only
            // meaningful with the kill-switch ON and fail-closed.
            Item { Layout.fillWidth: true; Layout.preferredHeight: root.uiTheme.spacingSm }
            CheckBox {
                id: ksBlockAllCheck
                Layout.fillWidth: true
                // Track 1 Chunk 5 — hidden entirely when the posture is
                // fail-open (leak protection not blocking); shown fail-closed.
                visible: panel.killSwitchEnabled && panel.ksFailClosed
                checked: panel.ksBlockAll
                text: root.tr("settings.routing.kill-switch.block-all-label",
                    "When the additional adapter is unavailable, block ALL traffic (kill-switch), not just its routed sites")
                contentItem: Label {
                    text: ksBlockAllCheck.text
                    leftPadding: ksBlockAllCheck.indicator.width + ksBlockAllCheck.spacing
                    color: ksBlockAllCheck.enabled ? root.textColor : root.mutedTextColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: {
                    panel.ksBlockAll = checked
                    if (typeof root.routePolicyController.applyKillSwitchBlockAll === "function")
                        root.routePolicyController.applyKillSwitchBlockAll(checked)
                }
            }
            ThemedButton {
                theme: root.uiTheme
                flat: true
                Layout.leftMargin: root.uiTheme.spacingSm
                // Track 1 Chunk 5 — travels with its checkbox: hidden fail-open.
                visible: panel.killSwitchEnabled && panel.ksFailClosed
                text: root.routingBlockAllDetailsExpanded
                    ? root.tr("settings.routing.show-less", "Hide details")
                    : root.tr("settings.routing.show-more", "Show details")
                onClicked: root.routingBlockAllDetailsExpanded = !root.routingBlockAllDetailsExpanded
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                // Track 1 Chunk 5 — travels with its checkbox: hidden fail-open.
                visible: panel.killSwitchEnabled && panel.ksFailClosed
                    && root.routingBlockAllDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.kill-switch.block-all-note",
                    "Most aggressive: while the additional adapter is down, only your explicitly primary-routed sites keep working — everything else, including ping, is blocked. This is what stops routed sites (and ICMP) from leaking to the primary link. Requires the leak-guard (fail-closed) to be on.")
            }
            // Prominent alert when the strict
            // catch-all is CHOSEN: it cuts the user's real internet when the
            // additional adapter is down. Shown only while the option is ON (and
            // meaningful, i.e. fail-closed). QtQuick.Layouts excludes it from the
            // column when invisible, so no height juggling is needed.
            Rectangle {
                id: ksBlockAllAlert
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled && panel.ksFailClosed && panel.ksBlockAll
                implicitHeight: ksBlockAllAlertRow.implicitHeight + root.uiTheme.spacingSm * 2
                radius: root.uiTheme.radiusSm
                color: Qt.rgba(root.uiTheme.colorWarning.r, root.uiTheme.colorWarning.g,
                    root.uiTheme.colorWarning.b, 0.16)
                border.width: root.uiTheme.borderWidth
                border.color: Qt.rgba(root.uiTheme.colorWarning.r, root.uiTheme.colorWarning.g,
                    root.uiTheme.colorWarning.b, 0.55)
                RowLayout {
                    id: ksBlockAllAlertRow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root.uiTheme.spacingSm
                    spacing: root.uiTheme.spacingSm
                    Rectangle {
                        Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4
                        Layout.alignment: Qt.AlignTop
                        Layout.topMargin: 4
                        color: root.uiTheme.colorWarning
                    }
                    Label {
                        Layout.fillWidth: true
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("settings.routing.kill-switch.block-all-alert",
                            "Heads up: with this on, if the additional adapter (VPN) goes down your normal internet stops too — only your local network keeps working — until it comes back. Leave it off if you want your main connection to keep working when the VPN drops.")
                    }
                }
            }

            // Opt-in: keep name resolution working over the
            // primary link while the aggressive block-all is engaged (port-scoped
            // UDP/TCP 53). Only meaningful when block-all is on. (P1b):
            // ON is now the default — with DNS cut too, an armed block-all is a
            // total blackout. OFF = strict, blocks DNS too. Lets the user pick
            // either behaviour.
            CheckBox {
                id: allowDnsOverPrimaryCheck
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled && panel.ksFailClosed && panel.ksBlockAll
                checked: panel.allowDnsOverPrimary
                text: root.tr("settings.routing.kill-switch.allow-dns-label",
                    "Allow name resolution over the main link while blocked (keep zones resolving)")
                contentItem: Label {
                    text: allowDnsOverPrimaryCheck.text
                    leftPadding: allowDnsOverPrimaryCheck.indicator.width + allowDnsOverPrimaryCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: {
                    panel.allowDnsOverPrimary = checked
                    if (typeof root.routePolicyController.applyAllowDnsOverPrimary === "function")
                        root.routePolicyController.applyAllowDnsOverPrimary(checked)
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled && panel.ksFailClosed && panel.ksBlockAll
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.kill-switch.allow-dns-note",
                    "On by default: a narrow exception (port 53 only) keeps name resolution working over your main link while blocked, so zones keep resolving — a deliberate, narrow DNS leak. Turn this off only for strict blocking: with DNS cut too, you have no working internet at all until the block clears. Useful with the local DNS resolver (Mode B) so zone rules keep working.")
            }

            // Pure UI-notification preference (NOT an
            // enforcement setting): toggles the "leak protection is blocking all
            // unknown traffic" banner shown by Main.qml. Prefs-only round-trip,
            // no IPC / UAC / service write. Placed at the end of the group since
            // it changes only what the user sees, not what is enforced.
            CheckBox {
                id: ksBlockAllWarnCheck
                Layout.fillWidth: true
                visible: panel.killSwitchEnabled && panel.ksFailClosed
                checked: root.uiRevision >= 0
                    ? root.prefs.warnKillSwitchBlockAll !== false : true
                text: root.tr("settings.routing.kill-switch.block-all-warn-label",
                    "Warn when leak protection blocks all unknown traffic")
                contentItem: Label {
                    text: ksBlockAllWarnCheck.text
                    leftPadding: ksBlockAllWarnCheck.indicator.width + ksBlockAllWarnCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: root.updatePrefs({ warnKillSwitchBlockAll: checked })
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled && panel.ksFailClosed
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.kill-switch.block-all-warn-note",
                    "On by default: a banner appears while the full block is active. Turn it off if you deliberately keep the service running with the VPN disconnected (e.g. from OS startup) and don't want the reminder.")
            }

            // Failure posture. fail-closed (default) makes
            // the emergency block actually block when the additional adapter
            // can't be found; fail-open keeps traffic flowing and warns. Block
            // The posture (block vs allow) is a kill-switch
            // sub-setting: shown only when the master toggle above is ON.
            ColumnLayout {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                Layout.topMargin: root.uiTheme.spacingSm
                spacing: root.uiTheme.spacingSm
                visible: panel.killSwitchEnabled
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: root.tr("settings.routing.kill-switch.failure-mode.label",
                        "If the additional adapter can't be found")
                }
                ThemedComboBox {
                    id: ksFailModeCombo
                    theme: root.uiTheme
                    Layout.fillWidth: true
                    Layout.maximumWidth: 380
                    model: ListModel {
                        ListElement { slug: "fail-closed"; label: "" }
                        ListElement { slug: "fail-open"; label: "" }
                    }
                    // The popup delegate showed the English
                    // fallback while the closed displayText was localised. A tr()
                    // call inside the delegate label is NOT reactive to locale load
                    // (see LESSONS — binding must track uiRevision), so the delegate
                    // froze on the fallback resolved before the locale loaded. Fix:
                    // resolve each option label into the model (textRole = "label")
                    // and re-resolve on every locale change, so the popup list and
                    // the closed field always agree.
                    textRole: "label"
                    function _slugLabel(slug) {
                        return root.tr("settings.routing.kill-switch.failure-mode.option-" + slug,
                            slug === "fail-closed" ? "Block traffic (recommended)"
                                                   : "Allow traffic and warn me")
                    }
                    function _refreshLabels() {
                        var m = ksFailModeCombo.model
                        for (var i = 0; i < m.count; i += 1)
                            m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                        _syncFromState()
                    }
                    function _syncFromState() {
                        var idx = panel.ksFailClosed ? 0 : 1
                        currentIndex = idx
                        displayText = _slugLabel(panel.ksFailClosed ? "fail-closed" : "fail-open")
                    }
                    Component.onCompleted: _refreshLabels()
                    onActivated: {
                        var slug = String(model.get(currentIndex).slug)
                        var failClosed = slug === "fail-closed"
                        panel.ksFailClosed = failClosed
                        displayText = _slugLabel(slug)
                        if (typeof root.routePolicyController.applyKillSwitchFailClosed === "function")
                            root.routePolicyController.applyKillSwitchFailClosed(failClosed)
                    }
                    Connections {
                        target: panel
                        function onKsFailClosedChanged() { ksFailModeCombo._syncFromState() }
                    }
                    Connections {
                        target: root
                        function onUiRevisionChanged() { ksFailModeCombo._refreshLabels() }
                    }
                }
                Label {
                    Layout.fillWidth: true
                    // Fail-open is the risky choice — colour it as a warning so
                    // the trade-off (possible real-address exposure) is obvious.
                    color: panel.ksFailClosed
                        ? root.mutedTextColor
                        : root.uiTheme.colorWarning
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: panel.ksFailClosed
                        ? root.tr("settings.routing.kill-switch.failure-mode.desc-fail-closed",
                            "Safest: if NetRuleRouter can't find the additional adapter (it's down, or the binding is stale), matched traffic is blocked instead of leaking over the primary route. Leak protection always works.")
                        : root.tr("settings.routing.kill-switch.failure-mode.desc-fail-open",
                            "Convenience: if the additional adapter can't be found, matched traffic keeps flowing over the primary route and a warning is shown. Your real address may be exposed.")
                }
                // Which IP protocols the emergency block cuts.
                // ICMP (ping) is only blockable at the packet layer, so a
                // connect-layer-only block let ping through (HW test 06-29).
                Label {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingSm
                    // Track 1 Chunk 5 — protocol picker is meaningless while
                    // fail-open (nothing is blocked); hide it there.
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: root.tr("settings.routing.kill-switch.protocols.label",
                        "Protocols leak protection cuts")
                }
                Flow {
                    Layout.fillWidth: true
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                    spacing: root.uiTheme.spacingMd
                    Repeater {
                        model: [
                            { slug: "tcp", bit: 1, tip: "Most web, email and app traffic (HTTP/HTTPS and similar)." },
                            { slug: "udp", bit: 2, tip: "DNS, video calls, games and other real-time traffic." },
                            { slug: "icmp", bit: 4, tip: "Ping and traceroute. These live only at the packet layer, so ICMP must be checked for the block to stop a ping." },
                            { slug: "igmp", bit: 8, tip: "Multicast group membership on the local network." },
                            { slug: "gre", bit: 16, tip: "A tunnelling protocol used by some VPNs (e.g. PPTP)." },
                            { slug: "esp", bit: 32, tip: "Encrypted IPsec VPN payloads." },
                            // "Other" no longer blocks anything at the
                            // packet layer (the emergency block now only cuts the named
                            // protocols above); kept for wire compat, labelled legacy.
                            { slug: "other", bit: 64, tip: "Legacy option: previously blocked every remaining IP protocol system-wide. The emergency block now cuts only the named protocols above; exotic protocols outside this list (e.g. ICMPv6, AH) are not blocked." }
                        ]
                        delegate: CheckBox {
                            text: root.tr("settings.routing.kill-switch.protocols." + modelData.slug,
                                modelData.slug === "icmp"
                                    ? "ICMP (ping)"
                                    : (modelData.slug === "other"
                                        ? "Other (legacy)"
                                        : modelData.slug.toUpperCase()))
                            checked: (panel.ksProtocols & modelData.bit) !== 0
                            onToggled: {
                                var m = checked
                                    ? (panel.ksProtocols | modelData.bit)
                                    : (panel.ksProtocols & ~modelData.bit)
                                panel.ksProtocols = m & 0x7F
                                if (typeof root.routePolicyController.applyKillSwitchProtocols === "function")
                                    root.routePolicyController.applyKillSwitchProtocols(panel.ksProtocols)
                            }
                            // Per-protocol hover tooltip + Accessible
                            // (a tooltip must never be the sole source of meaning,
                            // so the same text is also the accessible description).
                            ToolTip.visible: hovered
                            ToolTip.delay: 400
                            ToolTip.text: root.tr(
                                "settings.routing.kill-switch.protocols." + modelData.slug + "-tooltip",
                                modelData.tip)
                            Accessible.name: text
                            Accessible.description: ToolTip.text
                        }
                    }
                }
                Label {
                    Layout.fillWidth: true
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr("settings.routing.kill-switch.protocols.desc",
                        "Which IP protocols leak protection drops. ICMP covers ping/traceroute. \"Other\" is every protocol not listed (e.g. ICMPv6). All on by default — uncheck to let a protocol through even while the block is active.")
                }

                // Track 1 Chunk 4 — secondary tunnel liveness window. An
                // active ICMP probe that fail-closes the kill-switch when the
                // tunnel next-hop stays unreachable for N seconds. Opt-in
                // (default off). F7 Track 1 Chunk 5 — hidden while fail-open.
                Label {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingSm
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: root.tr("settings.routing.liveness-window.label",
                        "Secondary tunnel liveness window")
                }
                ThemedComboBox {
                    id: livenessWindowCombo
                    theme: root.uiTheme
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                    Layout.fillWidth: true
                    Layout.maximumWidth: 460
                    model: ListModel {
                        ListElement { secs: 0; kind: "disabled" }
                        ListElement { secs: 10; kind: "preset" }
                        ListElement { secs: 30; kind: "preset" }
                        ListElement { secs: 60; kind: "preset" }
                        ListElement { secs: 90; kind: "preset" }
                        ListElement { secs: 120; kind: "preset" }
                        ListElement { secs: 240; kind: "preset" }
                        ListElement { secs: -1; kind: "custom" }
                    }
                    textRole: "label"
                    // The dropdown delegate reads its text via
                    // labelResolver FIRST (ThemedComboBox._labelFor); the `label`
                    // role is bolted on at runtime via setProperty and is invisible
                    // to the delegate's bound context, so without this resolver the
                    // popup rendered raw "QQmlDMAbstractItemModelData" objects.
                    // secs/kind are statically declared in every ListElement, so
                    // they are always readable in the delegate.
                    labelResolver: function(item) {
                        return item
                            ? livenessWindowCombo._optLabel(item.secs | 0, String(item.kind))
                            : ""
                    }
                    function _optLabel(secs, kind) {
                        // Mark the default choice in the list itself
                        // (the user asked "which one is the default?").
                        if (kind === "disabled")
                            return root.tr("settings.routing.liveness-window.option-disabled",
                                "Disabled (default)")
                        if (kind === "custom")
                            return root.tr("settings.routing.liveness-window.option-custom",
                                "Custom…")
                        return secs + " " + root.tr("settings.routing.liveness-window.seconds-unit",
                            "seconds")
                    }
                    function _indexOfSecs(secs) {
                        if (secs === 0) return 0
                        for (var i = 1; i < livenessWindowCombo.model.count - 1; i += 1)
                            if ((livenessWindowCombo.model.get(i).secs | 0) === secs)
                                return i
                        // Non-preset, non-zero → the "Custom…" entry (last row).
                        return livenessWindowCombo.model.count - 1
                    }
                    function _refreshLabels() {
                        var m = livenessWindowCombo.model
                        for (var i = 0; i < m.count; i += 1)
                            m.setProperty(i, "label",
                                _optLabel(m.get(i).secs | 0, String(m.get(i).kind)))
                        _syncFromState()
                    }
                    function _syncFromState() {
                        var idx = _indexOfSecs(panel.livenessWindowSecs | 0)
                        currentIndex = idx
                        var it = livenessWindowCombo.model.get(idx)
                        displayText = _optLabel(it.secs | 0, String(it.kind))
                    }
                    Component.onCompleted: _refreshLabels()
                    onActivated: {
                        var it = model.get(currentIndex)
                        var kind = String(it.kind)
                        displayText = _optLabel(it.secs | 0, kind)
                        if (kind === "custom") {
                            // Reveal the spin box; apply its current value so the
                            // choice takes effect immediately (clamped to >= 5).
                            panel.livenessCustomSelected = true
                            panel._applyLivenessWindow(livenessCustomSpin.value)
                        } else {
                            panel.livenessCustomSelected = false
                            panel._applyLivenessWindow(it.secs | 0)
                        }
                    }
                    Connections {
                        target: panel
                        function onLivenessWindowSecsChanged() { livenessWindowCombo._syncFromState() }
                    }
                    Connections {
                        target: root
                        function onUiRevisionChanged() { livenessWindowCombo._refreshLabels() }
                    }
                }
                ThemedSpinBox {
                    id: livenessCustomSpin
                    theme: root.uiTheme
                    Layout.leftMargin: root.uiTheme.spacingSm
                    from: 5
                    to: 3600
                    stepSize: 5
                    // Shown only while the "Custom…" option is active (explicit
                    // selection, or a persisted non-preset non-zero value).
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                        && (panel.livenessCustomSelected
                            || (panel.livenessWindowSecs !== 0
                                && !panel._isLivenessPreset(panel.livenessWindowSecs)))
                    value: (panel.livenessWindowSecs !== 0)
                        ? Math.max(5, Math.min(3600, panel.livenessWindowSecs))
                        : 5
                    onValueModified: panel._applyLivenessWindow(value)
                }
                // The bare spin box gave no clue what it counts or its
                // limits (user report). State the unit + range explicitly.
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: root.uiTheme.spacingSm
                    visible: livenessCustomSpin.visible
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr("settings.routing.liveness-window.custom-range",
                        "Seconds — from 5 to 3600.")
                }
                Label {
                    Layout.fillWidth: true
                    visible: panel.killSwitchEnabled && panel.ksFailClosed
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr("settings.routing.liveness-window.note",
                        "Optional. When set, NetRuleRouter actively pings the additional adapter's next hop; if it stays unreachable for this many seconds, leak protection fail-closes even if no traffic has failed yet. Off by default. It may false-positive if the tunnel peer silently drops ICMP (many VPNs do), so leave it off unless you know the peer answers pings.")
                }
            }
        }
    }

    // Auto-rules. A site routed over the additional link usually pulls its
    // images, video and API calls from CDN hosts the user's rules never mention,
    // so the page opens but its media does not. The service can spot those
    // companion domains; this per-SID setting decides what it may then do with
    // the finding. Rides the same route.policy.update channel as the kill-switch
    // fields (GUI + tray, no elevation).
    GroupBox {
        id: autoRulesGroup
        title: root.tr("settings.routing.auto-rules.title", "Auto-rules")
        Layout.fillWidth: true

        ColumnLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingSm

            Label {
                Layout.fillWidth: true
                color: root.textColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.routing.auto-rules.label",
                    "Missing companion domains")
            }
            ThemedComboBox {
                id: autoRulesModeCombo
                theme: root.uiTheme
                Layout.fillWidth: true
                Layout.maximumWidth: 460
                model: ListModel {
                    ListElement { slug: "off"; label: "" }
                    ListElement { slug: "suggest"; label: "" }
                    ListElement { slug: "auto"; label: "" }
                }
                textRole: "label"
                function _slugLabel(slug) {
                    if (slug === "off")
                        return root.tr("settings.routing.auto-rules.mode-off", "Off")
                    if (slug === "auto")
                        return root.tr("settings.routing.auto-rules.mode-auto",
                            "Apply automatically")
                    return root.tr("settings.routing.auto-rules.mode-suggest",
                        "Suggest only (default)")
                }
                // The dropdown delegate reads its text through labelResolver, not
                // through the runtime-assigned `label` role.
                labelResolver: function(item) {
                    return item ? autoRulesModeCombo._slugLabel(String(item.slug)) : ""
                }
                function _indexOfSlug(slug) {
                    for (var i = 0; i < autoRulesModeCombo.model.count; i += 1)
                        if (String(autoRulesModeCombo.model.get(i).slug) === slug)
                            return i
                    // Unknown value → "Suggest only", the safe default.
                    return 1
                }
                function _refreshLabels() {
                    var m = autoRulesModeCombo.model
                    for (var i = 0; i < m.count; i += 1)
                        m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                    _syncFromState()
                }
                function _syncFromState() {
                    var idx = _indexOfSlug(String(panel.autoRulesMode))
                    currentIndex = idx
                    displayText = _slugLabel(String(autoRulesModeCombo.model.get(idx).slug))
                }
                Component.onCompleted: _refreshLabels()
                onActivated: {
                    var slug = String(model.get(currentIndex).slug)
                    // Switching TO "auto" needs the user's explicit
                    // confirmation first — it means the app starts writing
                    // rules on its own. Leave `panel.autoRulesMode` untouched
                    // until they confirm; the visual selection is reverted
                    // right away so a cancel does not leave the combo
                    // showing a mode that was never applied.
                    if (slug === "auto" && String(panel.autoRulesMode) !== "auto") {
                        _syncFromState()
                        autoRulesModeConfirmDialog.open()
                        return
                    }
                    displayText = _slugLabel(slug)
                    panel.autoRulesMode = slug
                    if (typeof root.routePolicyController.applyAutoRulesMode === "function")
                        root.routePolicyController.applyAutoRulesMode(slug)
                }
                Connections {
                    target: panel
                    function onAutoRulesModeChanged() { autoRulesModeCombo._syncFromState() }
                }
                Connections {
                    target: root
                    function onUiRevisionChanged() { autoRulesModeCombo._refreshLabels() }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.auto-rules.note",
                    "A routed site often loads its images and video from other domains your rules do not list, so the page opens but its content does not. By default NetRuleRouter collects these missing domains and offers them in the tray — nothing is added to your rules without your confirmation. \"Apply automatically\" adds them for you; \"Off\" stops collecting them altogether.")
            }

            // Offer delivery-shaped names on first sight instead of waiting for
            // them to prove they belong to a site. Faster, less precise — ad and
            // tracking endpoints wear the same shape, so this is opt-in and says
            // so. Service-side setting: rides route.policy.update like the mode.
            CheckBox {
                id: autoRulesEagerCheck
                Layout.fillWidth: true
                visible: panel.autoRulesMode !== "off"
                checked: panel.autoRulesEagerDeliveryNames
                text: root.tr("settings.routing.auto-rules.eager-label",
                    "Offer content-delivery domains without waiting for analysis")
                contentItem: Label {
                    text: autoRulesEagerCheck.text
                    leftPadding: autoRulesEagerCheck.indicator.width
                        + autoRulesEagerCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: {
                    panel.autoRulesEagerDeliveryNames = checked
                    if (typeof root.routePolicyController.applyAutoRulesEagerDeliveryNames
                            === "function")
                        root.routePolicyController.applyAutoRulesEagerDeliveryNames(checked)
                }
                Connections {
                    target: panel
                    function onAutoRulesEagerDeliveryNamesChanged() {
                        autoRulesEagerCheck.checked = panel.autoRulesEagerDeliveryNames
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.autoRulesMode !== "off"
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.auto-rules.eager-note",
                    "Off by default. Content-delivery domains are usually named alike, so this makes media load sooner. Advertising and tracking networks are named alike too, so some of what appears will not be worth routing — review before you accept it.")
            }

            // An added address goes into the rules FILES the routes are linked
            // to as soon as it lands — no toggle. Anything else makes the file
            // disagree with what is enforced within seconds of the user
            // accepting a suggestion, and the next comparison reports it as a
            // divergence they never caused.
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.autoRulesMode !== "off"
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.auto-rules.auto-save-note",
                    "Added addresses are written straight into the rules files your routes are linked to.")
            }
        }
    }

    // DoH/DoT lockdown. Browsers/apps that resolve names over
    // DNS-over-HTTPS/TLS hide their queries from the DNS observer, so routed
    // sites resolved that way slip past the kill-switch. Blocking known DoH/DoT
    // resolver endpoints forces a plaintext fallback the observer can see. Part A
    // is the per-SID master toggle + scope (rides route.policy.update); Part B is
    // the shared machine-wide resolver baseline editor (privileged doh.resolvers.*).
    GroupBox {
        id: dohLockdownGroup
        title: root.tr("settings.routing.doh-lockdown.title", "Block browser DoH/DoT")
        Layout.fillWidth: true

        // Part B editor state. `_dohMaster` is the authoritative JS array of rows
        // ({kind, target, comment, enabled, uid}); `dohResolverModel` is the
        // FILTERED, virtualised view the ListView renders. Row identity travels on
        // a stable `uid` so per-row edits map back to the master array regardless
        // of the active filter.
        property var _dohMaster: []
        property int _dohNextUid: 1
        property bool _dohLoaded: false
        property bool _dohLoading: false
        property string _dohFilter: ""

        function _dohDetectKind(v) {
            return /^\d{1,3}(\.\d{1,3}){3}$/.test(String(v || "").trim()) ? "ip" : "host"
        }
        function _dohRowMatchesFilter(row) {
            var f = String(dohLockdownGroup._dohFilter || "").toLowerCase()
            if (f === "") return true
            return String(row.target || "").toLowerCase().indexOf(f) >= 0
                || String(row.comment || "").toLowerCase().indexOf(f) >= 0
        }
        function _dohRebuildVisible() {
            dohResolverModel.clear()
            var arr = dohLockdownGroup._dohMaster
            for (var i = 0; i < arr.length; i += 1) {
                if (!dohLockdownGroup._dohRowMatchesFilter(arr[i])) continue
                dohResolverModel.append({
                    "uid": arr[i].uid,
                    "kind": String(arr[i].kind || "host"),
                    "target": String(arr[i].target || ""),
                    "comment": String(arr[i].comment || ""),
                    "rowEnabled": arr[i].enabled !== false
                })
            }
        }
        function _dohIndexByUid(uid) {
            var arr = dohLockdownGroup._dohMaster
            for (var i = 0; i < arr.length; i += 1)
                if (arr[i].uid === uid) return i
            return -1
        }
        function _dohNormalizeList(list) {
            var arr = []
            for (var i = 0; i < list.length; i += 1) {
                arr.push({
                    "uid": dohLockdownGroup._dohNextUid++,
                    "kind": String(list[i]["target-kind"] || "host"),
                    "target": String(list[i]["target"] || ""),
                    "comment": String(list[i]["comment"] || ""),
                    "enabled": list[i]["enabled"] !== false
                })
            }
            return arr
        }
        function _dohLoad() {
            if (dohLockdownGroup._dohLoading) return
            var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
            if (bridge === null || typeof bridge.rpcDohResolversGet !== "function") return
            dohLockdownGroup._dohLoading = true
            var corr = bridge.rpcDohResolversGet()
            if (!corr) { dohLockdownGroup._dohLoading = false; return }
            root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
                dohLockdownGroup._dohLoading = false
                if (!ok) {
                    root.statusLine = root.tr("settings.routing.doh-lockdown.resolvers.load-failed",
                        "Could not load the resolver list: ")
                        + ((typeof root.ipcErrorLabel === "function")
                            ? root.ipcErrorLabel(String(code || "")) : String(code || ""))
                    return
                }
                dohLockdownGroup._dohMaster =
                    dohLockdownGroup._dohNormalizeList((p && p.resolvers) || [])
                dohLockdownGroup._dohLoaded = true
                dohLockdownGroup._dohRebuildVisible()
            })
        }
        function _dohSave() {
            var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
            if (bridge === null || typeof bridge.rpcDohResolversSet !== "function") return
            var arr = dohLockdownGroup._dohMaster
            var payload = { "resolvers": [] }
            for (var i = 0; i < arr.length; i += 1) {
                payload.resolvers.push({
                    "target-kind": String(arr[i].kind || "host"),
                    "target": String(arr[i].target || ""),
                    "comment": String(arr[i].comment || ""),
                    "enabled": arr[i].enabled !== false
                })
            }
            var corr = bridge.rpcDohResolversSet(JSON.stringify(payload))
            if (!corr) return
            root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
                if (ok) {
                    root.statusLine = root.tr("settings.routing.doh-lockdown.resolvers.saved",
                        "Resolver list saved.")
                    // Reflect the stored (validated / normalised) list.
                    dohLockdownGroup._dohMaster =
                        dohLockdownGroup._dohNormalizeList((p && p.resolvers) || [])
                    dohLockdownGroup._dohRebuildVisible()
                    return
                }
                var c = String(code || "")
                if (c === "uac-declined") {
                    root.statusLine = root.tr("settings.routing.doh-lockdown.resolvers.uac-declined",
                        "Administrator approval was declined; the resolver list was not saved.")
                } else {
                    root.statusLine = root.tr("settings.routing.doh-lockdown.resolvers.save-failed",
                        "Could not save the resolver list: ")
                        + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(c) : c)
                }
            })
        }

        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingSm

            // ── Part A: per-SID master toggle ──
            CheckBox {
                id: dohEnableCheck
                Layout.fillWidth: true
                checked: panel.dohLockdownEnabled
                text: root.tr("settings.routing.doh-lockdown.label", "Block browser DoH/DoT")
                contentItem: Label {
                    text: dohEnableCheck.text
                    leftPadding: dohEnableCheck.indicator.width + dohEnableCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                    font.bold: true
                }
                onToggled: {
                    panel.dohLockdownEnabled = checked
                    if (typeof root.routePolicyController.applyDohLockdownEnabled === "function")
                        root.routePolicyController.applyDohLockdownEnabled(checked)
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.doh-lockdown.note",
                    "Off by default. Browsers that resolve names over DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) hide their queries, so routed sites resolved that way bypass leak protection. Turning this on blocks known encrypted-DNS endpoints so name resolution falls back to plaintext DNS that NetRuleRouter can observe.")
            }

            // ── Part A: scope selector (gated on the master toggle) ──
            Label {
                Layout.fillWidth: true
                visible: panel.dohLockdownEnabled
                color: root.textColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.routing.doh-lockdown.scope-label", "When to apply")
            }
            ThemedComboBox {
                id: dohScopeCombo
                theme: root.uiTheme
                visible: panel.dohLockdownEnabled
                Layout.fillWidth: true
                Layout.maximumWidth: 460
                model: ListModel {
                    ListElement { slug: "leak-protection-only"; label: "" }
                    ListElement { slug: "always"; label: "" }
                }
                textRole: "label"
                function _slugLabel(slug) {
                    return root.tr("settings.routing.doh-lockdown.scope-" + slug,
                        slug === "always"
                            ? "Always"
                            : "Only while leak protection is active (recommended)")
                }
                function _indexOfSlug(slug) {
                    for (var i = 0; i < dohScopeCombo.model.count; i += 1)
                        if (String(dohScopeCombo.model.get(i).slug) === slug)
                            return i
                    return 0
                }
                function _refreshLabels() {
                    var m = dohScopeCombo.model
                    for (var i = 0; i < m.count; i += 1)
                        m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                    _syncFromState()
                }
                function _syncFromState() {
                    currentIndex = _indexOfSlug(String(panel.dohLockdownScope))
                    displayText = _slugLabel(String(panel.dohLockdownScope))
                }
                Component.onCompleted: _refreshLabels()
                onActivated: {
                    var slug = String(model.get(currentIndex).slug)
                    displayText = _slugLabel(slug)
                    panel.dohLockdownScope = slug
                    if (typeof root.routePolicyController.applyDohLockdownScope === "function")
                        root.routePolicyController.applyDohLockdownScope(slug)
                }
                Connections {
                    target: panel
                    function onDohLockdownScopeChanged() { dohScopeCombo._syncFromState() }
                }
                Connections {
                    target: root
                    function onUiRevisionChanged() { dohScopeCombo._refreshLabels() }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.dohLockdownEnabled
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: (root.uiRevision >= 0 && String(panel.dohLockdownScope) === "always")
                    ? root.tr("settings.routing.doh-lockdown.scope-always-note",
                        "Blocks encrypted DNS at all times, even when leak protection is off — maximum observability, but it breaks DoH/HTTP-3 for every app and can slow name resolution.")
                    : root.tr("settings.routing.doh-lockdown.scope-leak-protection-only-note",
                        "Blocks encrypted DNS only while a block-all leak guard is armed, where DoH would otherwise defeat observation. Leaves DoH working the rest of the time. Recommended.")
            }

            // ── Part A: details disclosure ──
            ThemedButton {
                theme: root.uiTheme
                flat: true
                visible: panel.dohLockdownEnabled
                Layout.leftMargin: root.uiTheme.spacingSm
                text: root.routingDohLockdownDetailsExpanded
                    ? root.tr("settings.routing.show-less", "Hide details")
                    : root.tr("settings.routing.show-more", "Show details")
                onClicked: root.routingDohLockdownDetailsExpanded = !root.routingDohLockdownDetailsExpanded
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                visible: panel.dohLockdownEnabled && root.routingDohLockdownDetailsExpanded
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.doh-lockdown.details",
                    "Blocking works by denying connections to a known list of DoH/DoT resolver endpoints (edited below). Apps then fall back to the operating system's plaintext DNS, which the observer reads to keep routing and leak protection accurate. Some apps pin their own resolver and may show connection errors until DoH is turned off in their own settings; this does not affect apps that use the system resolver.")
            }

            // ── Part B: resolver-list editor disclosure ──
            ThemedButton {
                theme: root.uiTheme
                flat: true
                visible: panel.dohLockdownEnabled
                Layout.leftMargin: root.uiTheme.spacingSm
                text: root.routingDohEditorExpanded
                    ? root.tr("settings.routing.doh-lockdown.resolvers.hide", "Hide resolver list")
                    : root.tr("settings.routing.doh-lockdown.resolvers.manage", "Manage resolver list")
                onClicked: {
                    root.routingDohEditorExpanded = !root.routingDohEditorExpanded
                    if (root.routingDohEditorExpanded && !dohLockdownGroup._dohLoaded)
                        dohLockdownGroup._dohLoad()
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                visible: panel.dohLockdownEnabled && root.routingDohEditorExpanded
                spacing: root.uiTheme.spacingSm

                Label {
                    Layout.fillWidth: true
                    color: root.uiTheme.colorWarning
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr("settings.routing.doh-lockdown.resolvers.requires-admin",
                        "This is a shared, machine-wide list. Saving changes requires administrator approval.")
                }
                Label {
                    Layout.fillWidth: true
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr("settings.routing.doh-lockdown.resolvers.description",
                        "Endpoints blocked when the lockdown is active. Add a public resolver by IP address or hostname; untick a row to keep it in the list but stop blocking it.")
                }

                ThemedTextField {
                    id: dohFilterField
                    theme: root.uiTheme
                    Layout.fillWidth: true
                    placeholderText: root.tr("settings.routing.doh-lockdown.resolvers.filter",
                        "Filter by address or note…")
                    onTextChanged: {
                        dohLockdownGroup._dohFilter = text
                        dohLockdownGroup._dohRebuildVisible()
                    }
                }

                ListView {
                    id: dohResolverList
                    Layout.fillWidth: true
                    Layout.preferredHeight: 260
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    ScrollBar.vertical: ScrollBar {}
                    model: ListModel { id: dohResolverModel }
                    delegate: RowLayout {
                        id: dohRow
                        required property int index
                        required property int uid
                        required property string kind
                        required property string target
                        required property string comment
                        required property bool rowEnabled
                        width: dohResolverList.width
                        spacing: root.uiTheme.spacingSm

                        CheckBox {
                            id: dohRowCheck
                            checked: dohRow.rowEnabled
                            onToggled: {
                                var idx = dohLockdownGroup._dohIndexByUid(dohRow.uid)
                                if (idx >= 0) {
                                    dohLockdownGroup._dohMaster[idx].enabled = checked
                                    dohResolverModel.setProperty(dohRow.index, "rowEnabled", checked)
                                }
                            }
                            Accessible.name: dohRow.target
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                Layout.fillWidth: true
                                color: root.textColor
                                elide: Text.ElideRight
                                text: dohRow.target
                                    + "  ·  " + (dohRow.kind === "ip"
                                        ? root.tr("settings.routing.doh-lockdown.resolvers.kind-ip", "IP")
                                        : root.tr("settings.routing.doh-lockdown.resolvers.kind-host", "Host"))
                            }
                            Label {
                                Layout.fillWidth: true
                                visible: dohRow.comment !== ""
                                color: root.mutedTextColor
                                elide: Text.ElideRight
                                font.pixelSize: root.uiTheme.baseFontSizePx - 2
                                text: dohRow.comment
                            }
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            flat: true
                            text: root.tr("settings.routing.doh-lockdown.resolvers.remove", "Remove")
                            onClicked: {
                                var idx = dohLockdownGroup._dohIndexByUid(dohRow.uid)
                                if (idx >= 0) {
                                    dohLockdownGroup._dohMaster.splice(idx, 1)
                                    dohLockdownGroup._dohRebuildVisible()
                                }
                            }
                        }
                    }
                    Label {
                        anchors.centerIn: parent
                        width: parent.width - 2 * root.uiTheme.spacingMd
                        visible: dohResolverModel.count === 0
                        horizontalAlignment: Text.AlignHCenter
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        text: dohLockdownGroup._dohLoading
                            ? root.tr("settings.routing.doh-lockdown.resolvers.loading", "Loading…")
                            : root.tr("settings.routing.doh-lockdown.resolvers.empty",
                                "No resolvers in the list.")
                    }
                }

                // ── Part B: add-a-row form ──
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedTextField {
                        id: dohAddTarget
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        placeholderText: root.tr("settings.routing.doh-lockdown.resolvers.add-target",
                            "IP address or hostname")
                    }
                    ThemedTextField {
                        id: dohAddComment
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        placeholderText: root.tr("settings.routing.doh-lockdown.resolvers.add-comment",
                            "Note (provider / country)")
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        enabled: dohAddTarget.text.trim() !== ""
                        text: root.tr("settings.routing.doh-lockdown.resolvers.add", "Add")
                        icon.source: root.uiIconSource("add")
                        onClicked: {
                            var t = dohAddTarget.text.trim()
                            if (t === "") return
                            dohLockdownGroup._dohMaster.push({
                                "uid": dohLockdownGroup._dohNextUid++,
                                "kind": dohLockdownGroup._dohDetectKind(t),
                                "target": t,
                                "comment": dohAddComment.text.trim(),
                                "enabled": true
                            })
                            dohAddTarget.text = ""
                            dohAddComment.text = ""
                            dohLockdownGroup._dohRebuildVisible()
                        }
                    }
                }

                // ── Part B: save ──
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Item { Layout.fillWidth: true }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("settings.routing.doh-lockdown.resolvers.save",
                            "Save resolver list")
                        icon.source: root.uiIconSource("save")
                        onClicked: dohLockdownGroup._dohSave()
                    }
                }
            }
        }
    }

    // Relocated from Diagnostics & Logs: machine-wide,
    // admin-gated routing policy (rule-enforcement scope + pause/stop
    // disposition) grouped under ONE shield header. Apply-on-change via the
    // shared clobber-safe service-stability writer (no draft/Save flow).
    GroupBox {
        Layout.fillWidth: true
        title: root.tr("settings.routing.system-level.title",
            "System-level routing (requires administrator)")
        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingMd

            // ── Who may change the rules at all (rule-edit lock) ──
            ColumnLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXxs
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Image {
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                        Layout.alignment: Qt.AlignVCenter
                        source: root.uiIconSource("shield")
                        sourceSize.width: 16
                        sourceSize.height: 16
                        fillMode: Image.PreserveAspectFit
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr("settings.routing.rule-lock.heading",
                            "Who can change the rules")
                        font.pixelSize: root.uiTheme.baseFontSizePx
                        font.bold: true
                    }
                }
                CheckBox {
                    id: allowRuleEditsCheck
                    Layout.fillWidth: true
                    text: root.tr("settings.routing.rule-lock.allow.label",
                        "Allow users to change routing rules")
                    // A click writes `checked` directly and destroys a plain
                    // binding, so the window flag is re-asserted through a
                    // Binding element and, on a refused write, explicitly from
                    // the apply callback.
                    Binding {
                        target: allowRuleEditsCheck
                        property: "checked"
                        value: root.allowUserRuleEdits
                    }
                    onToggled: panel._applyAllowUserRuleEdits(checked)
                    contentItem: Label {
                        text: allowRuleEditsCheck.text
                        leftPadding: allowRuleEditsCheck.indicator.width
                            + allowRuleEditsCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: root.tr("settings.routing.rule-lock.allow.tooltip",
                        "On (default): anyone signed in to this computer can add, edit and apply their own routing rules. Turn it off on company laptops, or for parental control, so only an administrator decides where traffic goes.")
                }
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: root.uiTheme.spacingLg
                    text: root.tr("settings.routing.rule-lock.help",
                        "Affects the whole machine and needs administrator approval. While it is off, the Rules view is read-only for everyone: viewing, searching and exporting still work, but adding, editing, applying, importing and resetting to the baseline are turned off. The background service refuses the change as well, so the lock does not depend on this window.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                }
            }

            // ── When routing rules are enforced (rule-scope) ──
            ColumnLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXxs
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Image {
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                        Layout.alignment: Qt.AlignVCenter
                        source: root.uiIconSource("shield")
                        sourceSize.width: 16
                        sourceSize.height: 16
                        fillMode: Image.PreserveAspectFit
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr("settings.diagnostics.rule-scope.heading",
                            "When routing rules are enforced")
                        font.pixelSize: root.uiTheme.baseFontSizePx
                        font.bold: true
                    }
                }
                CheckBox {
                    text: root.tr("settings.diagnostics.rule-scope.service-driven.label",
                        "Keep enforcing while the service runs (even when the app is closed)")
                    checked: panel.ruleScopeServiceDriven
                    onToggled: {
                        if (checked !== panel.ruleScopeServiceDriven)
                            panel._applyRuleScope(checked)
                    }
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: root.tr("settings.diagnostics.rule-scope.service-driven.tooltip",
                        "On (default): the service enforces your rules continuously — from boot, even with no window or tray icon open — until the service is stopped. Best for always-on or managed/business setups. Off: rules apply only while the app or tray is running; fully exiting the app removes every added route and returns the network to normal.")
                }
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: root.uiTheme.spacingLg
                    text: root.tr("settings.diagnostics.rule-scope.help",
                        "Affects the whole machine and needs administrator approval. On = always-on (managed/business deployments). Off = active only while you keep the app open. Stopping the service always clears the routes.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                }
            }

            // ── When routing is paused or the service stops (stop-policy) ──
            ColumnLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXxs
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Image {
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                        Layout.alignment: Qt.AlignVCenter
                        source: root.uiIconSource("shield")
                        sourceSize.width: 16
                        sourceSize.height: 16
                        fillMode: Image.PreserveAspectFit
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr("settings.diagnostics.routing-stop.heading",
                            "When routing is paused or the service stops")
                        font.pixelSize: root.uiTheme.baseFontSizePx
                        font.bold: true
                    }
                }
                CheckBox {
                    text: root.tr("settings.diagnostics.routing-stop.persist.label",
                        "Keep rule routes on the additional adapter after pause/stop (route persistence, not leak protection)")
                    checked: panel.routingStopPolicy === "persist"
                    onToggled: panel._applyStopPolicy(checked)
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: root.tr("settings.diagnostics.routing-stop.persist.tooltip",
                        "Default (off): full teardown — every route is removed and ALL traffic returns to your main connection; matched sites stop using the additional adapter. Turn ON to keep the matched routes on the additional adapter — useful for a work/corporate additional adapter, so you keep reaching corporate resources while general routing is paused; for a general-purpose additional adapter leave it off so everything returns to your main connection. NetRuleRouter's overlays are still removed either way. Leak-protection and kill-switch blocks are always removed on pause/stop, so a paused or stopped service can never lock you out.")
                }
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: root.uiTheme.spacingLg
                    text: root.tr("settings.diagnostics.routing-stop.help",
                        "Applies to both “safe disable”/pause and stopping the service. Affects the whole machine and needs administrator approval. Note: simply closing the app keeps routing active because the background service keeps running — use Stop service (or Disable) to turn routing off.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                }
            }
        }
    }

    // Hosts-file affordances relocated to their own
    // group at the very bottom of the page (out of "Leak protection"): the
    // hosts-bypass resolution toggle and the OS hosts-file path/open-folder
    // row. The whole group hides when the OS hosts file carries only comments
    // and blank lines (`hostsFileHasEntries === false`) — a stock hosts file
    // has no real mappings, so these controls would be meaningless noise; any
    // real mapping entry flips the flag true and reveals the group. An older
    // context that doesn't emit the flag (undefined) falls back to showing it.
    GroupBox {
        Layout.fillWidth: true
        title: root.tr("settings.routing.hosts-group.title", "Hosts file")
        visible: !root.platformProfile || root.platformProfile.hostsFileHasEntries !== false
        ColumnLayout {
            anchors.left: parent.left
            anchors.right: parent.right
            spacing: root.uiTheme.spacingSm

            // Hosts-bypass: resolve rule domains directly against the
            // upstream DNS server so a local hosts/adblock loopback pin cannot
            // starve a routed site of its public IP (332× `musical.ly →
            // 127.0.0.1` in the 0712 log). Per-SID `resolve-hosts-bypass`,
            // default ON. Affects rule-host resolution in both modes. General
            // resolution setting — NOT gated on the kill-switch.
            CheckBox {
                id: hostsBypassCheck
                Layout.fillWidth: true
                checked: panel.resolveHostsBypass
                text: root.tr("settings.routing.hosts-bypass.label",
                    "Resolve routed domains bypassing the hosts file")
                contentItem: Label {
                    text: hostsBypassCheck.text
                    leftPadding: hostsBypassCheck.indicator.width + hostsBypassCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: {
                    panel.resolveHostsBypass = checked
                    if (typeof root.routePolicyController.applyResolveHostsBypass === "function")
                        root.routePolicyController.applyResolveHostsBypass(checked)
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingSm
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.routing.hosts-bypass.note",
                    "On (default): routed domains are resolved directly against your DNS server, so a local hosts/adblock entry pinning a routed site to 127.0.0.1 cannot silently disable its routing. Turn off only if you rely on hosts-file overrides for the sites you route.")
            }

            // P2c — reveal the OS hosts file location so a
            // user hitting "my rule host resolves only to 127.0.0.1" (a hosts
            // entry shadowing the domain, see the bypass toggle above) can
            // find and inspect/edit it themselves. Path comes from Rust via
            // `root.platformProfile.hostsFilePath` — never branch on
            // Qt.platform.os here. Hidden entirely if the context is old and
            // doesn't carry the field yet.
            ColumnLayout {
                Layout.fillWidth: true
                visible: root.uiRevision >= 0
                    ? !!(root.platformProfile && root.platformProfile.hostsFilePath)
                    : false
                spacing: root.uiTheme.spacingXs

                Label {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingSm
                    color: root.textColor
                    text: root.tr("settings.routing.hosts-file.label", "OS hosts file")
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedTextField {
                        id: hostsFilePathField
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        readOnly: true
                        selectByMouse: true
                        text: root.uiRevision >= 0
                            ? (root.platformProfile && root.platformProfile.hostsFilePath
                                ? root.platformProfile.hostsFilePath : "")
                            : ""
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("settings.routing.hosts-file.open-folder", "Open folder")
                        icon.source: root.uiIconSource("open-file")
                        enabled: hostsFilePathField.text.length > 0
                        onClicked: {
                            var url = panel._hostsFolderUrl(hostsFilePathField.text)
                            if (url) Qt.openUrlExternally(url)
                        }
                    }
                }
                Label {
                    Layout.fillWidth: true
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr("settings.routing.hosts-file.note",
                        "The OS hosts file can redirect or block a hostname before NetRuleRouter sees it (ad-block lists often map hosts to 127.0.0.1). NetRuleRouter never edits it — open the folder to inspect or edit it yourself (requires administrator).")
                }
            }
        }
    }

    ApplyFailurePolicySettings {
        root: panel.root
        Layout.fillWidth: true
    }

    RetentionSettings {
        root: panel.root
        Layout.fillWidth: true
    }

    // "Apply automatically" starts unattended writes to the user's rules
    // files, so it is the one auto-rules mode that asks first. A cancel
    // re-syncs the combo from `panel.autoRulesMode`, which was never
    // touched, so it snaps back to whatever was selected before the click.
    AutoRulesModeConfirmDialog {
        id: autoRulesModeConfirmDialog
        ownerRoot: root
        onConfirmed: {
            autoRulesModeCombo.displayText = autoRulesModeCombo._slugLabel("auto")
            panel.autoRulesMode = "auto"
            if (typeof root.routePolicyController.applyAutoRulesMode === "function")
                root.routePolicyController.applyAutoRulesMode("auto")
        }
        onCancelled: autoRulesModeCombo._syncFromState()
    }
}
