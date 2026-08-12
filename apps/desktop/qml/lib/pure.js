.pragma library

// pure.js -- window-state-free helper library for the NetRuleRouter QML shell.
//
// CONTRACT (this is the guardrail against bloat -- do not weaken it):
//   * Every function takes ALL of its inputs as arguments and returns a value.
//   * NO window/component state: no `prefs`, no models, no `id`s, no
//     `nrrNativeBridge`, no `tr()` / localization catalog, no `window`/`root`.
//   * A helper that needs any of the above does NOT belong here -- it stays in
//     Main.qml or moves to a `flows/` module with explicit dependency injection.
//
// A `.pragma library` shares ONE stateless instance across all importers and
// cannot see the QML scope, so this contract is enforced by the runtime: any
// state-coupled code simply cannot run here. Keep it that way.
//
// Consumers: `import "lib/pure.js" as Pure` (adjust the relative depth per
// file: `"lib/pure.js"` from Main.qml, `"../lib/pure.js"` from sections/ and
// components/, `"../../lib/pure.js"` from sections/settings/).

// ---- option / section index lookups ----

function optionIndexById(options, id, fallbackIndex) {
    for (var i = 0; i < options.length; i += 1) if (options[i].id === id) return i
    return fallbackIndex
}

function optionIndexByValue(options, value, fallbackIndex) {
    var idx = options.indexOf(value)
    return idx >= 0 ? idx : fallbackIndex
}

function idxForSection(value) {
    if (value === "interfaces-routes") return 0
    if (value === "rules") return 1
    if (value === "rule-suggestions") return 2
    if (value === "diagnostics") return 3
    if (value === "logs") return 4
    return 5
}

// ---- ListModel / array access helpers ----

// `ListModel.clear()` is O(n) with a single reset notification; the old
// `while (count>0) remove(0)` was O(n^2) (every remove(0) shifts the whole
// model) AND fired n removal signals -- a real cost when clearing a ~300-row
// rules model before a re-bind. `clear()` keeps the role schema, so subsequent
// appends preserve all roles.
function clearModel(model) { model.clear() }

function modelLength(model) {
    if (!model) return 0
    if (model.length !== undefined) return model.length
    if (model.count !== undefined) return model.count
    return 0
}

function modelItem(model, index) {
    if (!model) return ""
    if (model.length !== undefined) return model[index]
    if (model.get !== undefined) return model.get(index)
    return ""
}

function comboItemText(item, textRole, textResolver, index) {
    if (textResolver) return String(textResolver(item, index))
    if (item === undefined || item === null) return ""
    if (typeof item === "object" && textRole && item[textRole] !== undefined) return String(item[textRole])
    return String(item)
}

// ---- menu / text formatting ----

function menuActionText(label, shortcutHint) {
    return shortcutHint && shortcutHint !== "" ? (label + "\t" + shortcutHint) : label
}

function menuTitleText(label, mnemonic) {
    return mnemonic && mnemonic !== "" ? ("&" + label) : label
}

function normalizedFontScalePercent(value) {
    var numeric = Number(value)
    if (!isFinite(numeric) || numeric <= 0) numeric = 100
    return Math.max(80, Math.min(300, Math.round(numeric / 5) * 5))
}

function formatStorageBytes(bytes) {
    var n = Number(bytes || 0)
    if (n < 1024) return n + " B"
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB"
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MiB"
    return (n / (1024 * 1024 * 1024)).toFixed(2) + " GiB"
}

// ---- glyphs / external links ----

function sectionGlyph(sectionId) {
    if (sectionId === "interfaces-routes") return "◎"
    if (sectionId === "rules") return "⌕"
    if (sectionId === "diagnostics") return "⚕"
    if (sectionId === "logs") return "☰"
    if (sectionId === "settings") return "⚙"
    return "□"
}

// The Settings categories, in display order. Lives here because two unrelated
// surfaces need the same list — the navigation sidebar renders it, the Settings
// section keys its lazy content loaders off the ids — and the sidebar cannot
// read it off the section, which is only instantiated once Settings opens.
// Labels stay as (key, fallback) pairs: a `.pragma library` has no `tr()`.
// `icon` names an asset under assets/icons/ui/ (ui-hc/ mirrors it). Empty
// string means no existing icon fits the category closely enough — leave it
// unmarked rather than force a loose match.
function settingsCategories() {
    return [
        { id: "application", key: "settings.category.application", fallback: "Application", icon: "settings" },
        { id: "diagnostics", key: "settings.group.logs-diagnostics", fallback: "Logs and diagnostics", icon: "diagnostics" },
        { id: "traffic", key: "settings.traffic.category", fallback: "Traffic statistics", icon: "traffic-in" },
        { id: "routing", key: "settings.group.routing-behavior", fallback: "Routing behavior", icon: "routing" },
        { id: "service", key: "settings.service.title", fallback: "Service management", icon: "shield" },
        { id: "presets", key: "settings.category.presets", fallback: "Presets and settings", icon: "load-list" },
        { id: "experimental", key: "settings.group.experimental", fallback: "Experimental", icon: "experimental" },
        { id: "updates", key: "settings.group.updates", fallback: "Updates", icon: "download" }
    ]
}

function openExternalUrl(url) {
    if (url && url !== "") Qt.openUrlExternally(url)
}

// ---- filesystem path containment ----

// Case-insensitive, separator-normalised "is `path` inside `dir`?" test.
// Windows paths reach the GUI in both slash flavours (bridge vs folder
// picker), so both sides are normalised before the prefix compare. The
// trailing separator on `dir` is mandatory in the compare so `C:/rules-x`
// is NOT reported as living under `C:/rules`.
function isPathUnderDir(path, dir) {
    var norm = function(p) {
        return String(p || "").replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase()
    }
    var p = norm(path)
    var d = norm(dir)
    if (p === "" || d === "") return false
    return p === d || p.indexOf(d + "/") === 0
}

// ---- rules-file binding ----

// Which file on disk backs `route` ("primary" | "secondary") according to what
// the user's own actions put on record. Priority:
//   1. a remembered path INSIDE the user's own rule-set folder (save target
//      first, then load source, then the launch opt-in);
//   2. the explicit "open these rules on next launch" opt-in;
//   3. where the current rules were loaded from;
//   4. the save-target binding, for prefs written before (3) existed.
// Returns "" when the user has bound no file at all.
//
// Lives here so the main window and the tray answer this question with ONE
// implementation: the tray has no `prefs` object of its own but resolves the
// same fields out of the snapshot the window publishes.
function rememberedRulesPathFor(prefs, route, userPresetsDir) {
    var p = prefs || {}
    var isPrimary = String(route) === "primary"
    var loaded = String((isPrimary ? p.lastLoadedPathPrimary
                                   : p.lastLoadedPathSecondary) || "")
    var saved = String((isPrimary ? p.lastSavedPathPrimary
                                  : p.lastSavedPathSecondary) || "")
    var autoOpen = String((isPrimary ? p.autoOpenOnLaunchPathPrimary
                                     : p.autoOpenOnLaunchPathSecondary) || "")
    var ownFolder = String(userPresetsDir || "")
    if (ownFolder !== "") {
        if (isPathUnderDir(saved, ownFolder)) return saved
        if (isPathUnderDir(loaded, ownFolder)) return loaded
        if (isPathUnderDir(autoOpen, ownFolder)) return autoOpen
    }
    return autoOpen || loaded || saved
}

// ---- correlation id ----

function newCorrelationId() {
    return "rules-update-" + Date.now() + "-" + Math.floor(Math.random() * 1e6)
}

// ---- offline-intents pure math ----

function pendingOfflineCount(obj) {
    if (!obj) return 0
    var rp = obj["route-policy"] || {}
    var st = obj["stability"] || {}
    return Object.keys(rp).length + Object.keys(st).length
}

// ---- service-stability config -- the ONE wire-field declaration ----
//
// `settings.service-stability.set` is a FULL-ROW request exactly like
// `route.policy.update` below: a field the payload leaves out falls back to the
// server's serde default. The same two failure modes therefore apply, and this
// group had neither guardrail — its keys were enumerated by hand in a `switch`,
// once per helper, with each default spelled out inline.
//
// A value here MUST equal the serde default of the same field in
// `nrr_shared::ipc_payloads::ServiceStabilityConfigDto`; the Rust side is
// normative, this table is the mirror, and `stability_wire_contract.rs` in
// `apps/desktop/gui/tests` pins the two together so a drift fails `cargo test`
// rather than a hardware run.

// Wire key -> value used when the config does not carry the key.
var STABILITY_FIELD_DEFAULTS = {
    "verbose-logging": false,
    "conn-trace-ndjson": false,
    "conn-trace-gui": false,
    "rule-scope-service-driven": true,
    "routing-stop-policy": "teardown",
    "cache-refresh-interval-secs": 300,
    "enforcement-mode": "resolver",
    "secondary-liveness-window-secs": 0,
    "fake-ip-enabled": false,
    "dns-via-secondary": false,
    "dns-fast-answers": true,
    "fake-ip-udp-relay": false,
    "fake-ip-instant-rst": true,
    "isp-block-candidates-enabled": false
}

// Row fields whose value is not a scalar, so they cannot live in the table
// above but are still part of the config the writer round-trips.
var STABILITY_STRUCTURED_KEYS = ["ipc-accept-policy"]

// Machine-wide administrator policy: never one user's recorded intent, so the
// carry-forward below must not resurrect it out of a user's preferences.
var STABILITY_INTENT_EXCLUDED_KEYS = ["allow-user-rule-edits"]

// Service-side clamps for the numeric fields. `non-positive` is the value a
// zero-or-negative input resolves to (0 = "disabled" for the liveness window,
// the default cadence for the cache refresh).
var STABILITY_FIELD_CLAMPS = {
    "secondary-liveness-window-secs": { "min": 5, "max": 3600, "non-positive": 0 },
    "cache-refresh-interval-secs": { "min": 60, "max": 86400, "non-positive": 300 }
}

// Legal values of the slug fields; anything else resolves to the default.
var STABILITY_FIELD_CHOICES = {
    "enforcement-mode": ["resolver", "reactive"],
    "routing-stop-policy": ["teardown", "persist"]
}

// True when `key` is a field of the config row this build knows about.
function stabilityKeyIsKnown(key) {
    return STABILITY_FIELD_DEFAULTS[key] !== undefined
        || STABILITY_STRUCTURED_KEYS.indexOf(key) >= 0
}

// Normalise ONE scalar stability value to the shape the wire expects, using the
// declared default to pick the coercion. Absent / null / empty reads as the
// default, so a live config, a parked offline intent and a QML literal all stay
// comparable with `===`.
function stabilityCoerce(key, raw) {
    var def = STABILITY_FIELD_DEFAULTS[key]
    if (def === undefined) return raw
    if (raw === undefined || raw === null || raw === "") return def
    if (typeof def === "boolean") return raw === true
    if (typeof def === "number") {
        var clamp = STABILITY_FIELD_CLAMPS[key]
        var n = raw | 0
        if (!clamp) return n
        if (n <= 0) return clamp["non-positive"]
        return Math.max(clamp["min"], Math.min(clamp["max"], n))
    }
    var s = String(raw)
    var choices = STABILITY_FIELD_CHOICES[key]
    if (choices && choices.indexOf(s) < 0) return def
    return s
}

// Effective CURRENT value of one service-stability key from a config DTO (or
// from any map with the same wire keys -- a parked-intent bucket, the display
// mirror). `undefined` for a key this build does not know.
function stabilityEffective(cfg, key) {
    cfg = cfg || {}
    if (key === "ipc-accept-policy") {
        var pol = cfg["ipc-accept-policy"] || cfg.ipc_accept_policy || {}
        if (String(pol["kind"] || pol.kind || "recoverable") === "critical")
            return { "kind": "critical" }
        return {
            "kind": "recoverable",
            "max-restarts": Number(pol["max-restarts"] || pol.max_restarts || 20),
            "backoff-base-ms": Number(pol["backoff-base-ms"] || pol.backoff_base_ms || 100),
            "backoff-cap-ms": Number(pol["backoff-cap-ms"] || pol.backoff_cap_ms || 5000)
        }
    }
    if (STABILITY_FIELD_DEFAULTS[key] === undefined) return undefined
    return stabilityCoerce(key, cfg[key])
}

// Build the FULL `settings.service-stability.set` payload for one write.
//
// Three passes, and the order is the whole point:
//   1. echo everything the service just reported, so a contract field this
//      build has never heard of rides back unchanged instead of being reset to
//      a serde default;
//   2. overlay what the USER decided (`intent`) for every key this write is not
//      touching. Without this pass a full-row write re-affirms whatever the
//      service currently holds -- and when the service holds its own default
//      because a delivery failed or its state DB was wiped, that silently
//      cancels the user's setting. Observed: a DNS-through-the-tunnel toggle
//      the user had switched on was written back as `false` by an unrelated
//      write, because the intent replay that should have delivered it had timed
//      out and the merge base was the service's fresh-boot default;
//   3. the keys THIS write is changing always win.
//
// `parked` is the offline-pending bucket. Those keys are deliberately NOT
// carried forward here: the pending-changes flow owns their delivery and
// pushes them as its own `partial`, so pushing them from an unrelated write
// would apply a change the user has not confirmed yet.
function mergeStabilityWrite(live, intent, parked, partial) {
    var out = {}
    var key
    for (key in (live || {})) out[key] = live[key]
    for (key in (intent || {})) {
        if (STABILITY_INTENT_EXCLUDED_KEYS.indexOf(key) >= 0) continue
        if (!stabilityKeyIsKnown(key)) continue
        if (parked && parked.hasOwnProperty(key)) continue
        out[key] = intent[key]
    }
    for (key in (partial || {})) out[key] = partial[key]
    return out
}

// ---- connection-trace remote-address classification ----

// True when a connection-trace remote endpoint is NOT an internet destination:
// loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10) or a
// private LAN range (10/8, 172.16/12, 192.168/16, plus the IPv6 unique-local
// fc00::/7 counterpart).
//
// The input is the DISPLAY string of the trace row, so it may carry a port
// ("10.0.0.5:443", "[fe80::1%4]:53") and it may be masked by the Compact
// redaction tier. Anything that does not parse as one of the ranges above --
// including a masked or empty value -- returns false: the caller hides
// non-internet rows, and hiding a row we could not read would silently drop
// evidence from the view.
function isNonInternetAddress(remote) {
    var host = String(remote || "").trim()
    if (host === "") return false
    if (host.charAt(0) === "[") {
        // Bracketed IPv6 literal: "[::1]:443" -> "::1".
        var close = host.indexOf("]")
        host = close > 0 ? host.substring(1, close) : host.substring(1)
    } else {
        // Bare IPv6 has several colons; only strip a single trailing ":port".
        var lastColon = host.lastIndexOf(":")
        if (lastColon > 0 && host.indexOf(":") === lastColon)
            host = host.substring(0, lastColon)
    }
    // Drop an IPv6 zone index ("fe80::1%4").
    var zone = host.indexOf("%")
    if (zone >= 0) host = host.substring(0, zone)
    host = host.toLowerCase()
    if (host === "") return false

    if (host.indexOf(":") !== -1) {
        if (host === "::1") return true
        if (/^fe[89ab]/.test(host)) return true   // link-local fe80::/10
        if (/^f[cd]/.test(host)) return true      // unique-local fc00::/7
        return false
    }

    var parts = host.split(".")
    if (parts.length !== 4) return false
    var octets = []
    for (var i = 0; i < 4; i += 1) {
        if (!/^\d{1,3}$/.test(parts[i])) return false
        var n = parseInt(parts[i], 10)
        if (n > 255) return false
        octets.push(n)
    }
    if (octets[0] === 127) return true                                  // 127.0.0.0/8
    if (octets[0] === 169 && octets[1] === 254) return true             // 169.254.0.0/16
    if (octets[0] === 10) return true                                   // 10.0.0.0/8
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true // 172.16.0.0/12
    if (octets[0] === 192 && octets[1] === 168) return true             // 192.168.0.0/16
    return false
}

// ---- interface-role secondary-name matching ----

// PARITY with the service matcher (route_coordinator.rs
// `description_matches_display_name`): reduce BOTH sides to version-stripped
// lowercase whitespace tokens, then match by SYMMETRIC containment (either token
// set is a subset of the other). A directional substring test diverged from the
// service, so the GUI painted the secondary "unresolved / press Apply" even when
// the service had healed the id and was actively routing (saved "...VPN 3.0..."
// vs live "...VPN...", or the reverse). The caller's "exactly one available
// match" ambiguity guard bounds the looser matching, like the service's guard.
function storedNameMatchesLive(storedName, liveText) {
    function _coreTokens(s) {
        var out = []
        var parts = String(s || "").toLowerCase().split(/\s+/)
        for (var i = 0; i < parts.length; i += 1) {
            var t = parts[i]
            if (t === "") continue
            var stripped = t.replace(/^v+/, "")
            if (stripped !== "" && /^[0-9.]+$/.test(stripped)) continue
            out.push(t)
        }
        return out
    }
    var saved = _coreTokens(storedName)
    var live = _coreTokens(liveText)
    if (saved.length === 0 || live.length === 0) return false
    function _subset(a, b) {
        for (var i = 0; i < a.length; i += 1)
            if (b.indexOf(a[i]) === -1) return false
        return true
    }
    return _subset(saved, live) || _subset(live, saved)
}

// ---- service interface wire-row -> model-row mapping ----

function mapWireInterfaceRow(w) {
    if (!w) return null
    var of = w["observed-facts"] || {}
    var da = w["derived-assessment"] || {}
    var rec = w["recommendation"] || {}
    return {
        persistentId: String(w["persistent-id"] || ""),
        name: String(w["windows-name"] || ""),
        description: String(w["interface-description"] || ""),
        type: String(w["interface-type"] || ""),
        ip: String(w["local-ip"] || "-"),
        gateway: String(w["gateway"] || "-"),
        dns: String(w["dns-servers"] || "-"),
        hasDefaultRoute: !!w["has-default-route"],
        // Three-valued on the wire: absent = the service did not evaluate it
        // (older build, or the route table could not be read). Keep the
        // distinction — `false` means "evaluated: nowhere to forward to".
        hasForwardingPath: (w["has-forwarding-path"] === undefined
            || w["has-forwarding-path"] === null)
            ? null : !!w["has-forwarding-path"],
        availability: String(w["availability"] || ""),
        selectedRole: "",
        routeState: String(w["route-state"] || "not-selected"),
        isBluetoothLike: !!w["is-bluetooth-like"],
        observedFacts: {
            connectivityState: String(of["connectivity-state"] || ""),
            externalIpStatus: String(of["external-ip-status"] || ""),
            externalIp: (of["external-ip"] === undefined ? null : of["external-ip"]),
            externalProbeAttempted: !!of["external-probe-attempted"],
            externalProbeNote: String(of["external-probe-note"] || "")
        },
        derivedAssessment: {
            vpnTunnelLikelihood: String(da["vpn-tunnel-likelihood"] || ""),
            virtualInterfaceLikelihood: String(da["virtual-interface-likelihood"] || ""),
            serviceInterfaceLikelihood: String(da["service-interface-likelihood"] || ""),
            classification: String(da["classification"] || ""),
            confidencePercent: Number(da["confidence-percent"] || 0),
            heuristicOnly: !!da["heuristic-only"],
            signals: da["signals"] || []
        },
        recommendation: {
            "class": String(rec["class"] || ""),
            confidence: String(rec["confidence"] || ""),
            advisoryOnly: !!rec["advisory-only"],
            summary: String(rec["summary"] || ""),
            keySignals: rec["key-signals"] || [],
            excludedAlternatives: rec["excluded-alternatives"] || []
        }
    }
}

// ---- external-IP "last known" cache ----

// Stable key for the external-IP sidecar cache: the persistent adapter id
// when the adapter has one, else a name-derived fallback. Mirrors the
// identity choice the launcher's DAO uses, so the same key is produced on
// both the write side (fresh service rows) and the read side (a delegate
// looking its adapter up in the cached map).
// Key under which the last address seen on a ROUTE is cached, beside the
// per-adapter entries. The tray reads it: it presents addresses by route and,
// with the service stopped, cannot ask which adapter holds which role.
function externalIpRoleCacheKey(role) {
    return "role:" + String(role === undefined || role === null ? "" : role).trim()
}

function externalIpCacheKey(persistentId, name) {
    var id = String(persistentId === undefined || persistentId === null ? "" : persistentId).trim()
    if (id !== "") return id
    return "name:" + String(name === undefined || name === null ? "" : name).trim()
}

// Local, short rendering of a cached timestamp: "HH:MM" when observed within
// the last 24h, "DD.MM HH:MM" once older -- so a muted "last known" hint
// never claims to be more current than it is.
function formatLastKnownTimestamp(observedAtMs, nowMs) {
    if (!observedAtMs) return ""
    var d = new Date(observedAtMs)
    if (isNaN(d.getTime())) return ""
    var now = (nowMs === undefined || nowMs === null) ? Date.now() : nowMs
    var hh = ("0" + d.getHours()).slice(-2)
    var mm = ("0" + d.getMinutes()).slice(-2)
    var timePart = hh + ":" + mm
    if ((now - observedAtMs) < 24 * 60 * 60 * 1000) return timePart
    var dd = ("0" + d.getDate()).slice(-2)
    var mo = ("0" + (d.getMonth() + 1)).slice(-2)
    return dd + "." + mo + " " + timePart
}

// ---- own fake-IP TUN adapter detection ----

// True when a mapped interface row is NetRuleRouter's OWN fake-IP TUN adapter
// (Wintun on Windows), which is created with the product name as its interface
// name (`TunAdapterConfig::default()` in core/platform/api/src/fake_ip/tun.rs).
// It must never be offered for primary/secondary role assignment: binding a
// route to our own tunnel would loop traffic back into ourselves.
//
// Identity choice — of the fields a wire row carries, the OS friendly name is
// the least fragile: `persistentId` (GUID) changes every time the adapter is
// recreated, and the driver description ("Wintun Userspace Tunnel") is shared
// by every Wintun consumer (WireGuard and others), so matching on it would
// hide the user's real VPN adapters. Exact match on the name we create the
// adapter with is the same identity the OS shows in `ipconfig`.
//
// Deliberately a GUI-side display filter, not a snapshot-provider (Rust-side)
// filter: the service keeps enumerating the adapter, so every diagnostics /
// statistics surface still sees it — only the role-assignment model drops it.
// The trade-off is that each future role-assignment surface must apply this
// helper itself; a provider-side filter would be automatic but would blind
// the diagnostic surfaces too.
function isOwnFakeIpTunRow(row) {
    return !!row && String(row.name || "") === "NetRuleRouter"
}

// ---- "can this adapter carry traffic out?" guardrail ----

// True when `gateway` names an address packets can actually be handed to.
// The enumeration writes the literal "-" for "no gateway" (never an empty
// string), and an all-zeroes gateway is the same thing spelled differently.
function _interfaceHasUsableGateway(gateway) {
    var g = String(gateway === undefined || gateway === null ? "" : gateway).trim()
    if (g === "" || g === "-") return false
    if (g === "0.0.0.0" || g === "::" || g === "::0") return false
    return true
}

// Why a mapped interface row cannot carry traffic out, or "" when it can.
// Operates on the row shape produced by `mapWireInterfaceRow`.
//
//   "virtual-host-only" -- confidently a virtual/host-only adapter (VirtualBox,
//                          VMware, Hyper-V internal, docker bridge) AND it has
//                          no gateway.
//
// An adapter that is merely DOWN is deliberately never flagged: a disconnected
// ethernet port or a VPN tunnel that is not up yet legitimately reports no
// gateway and no default route, and binding it ahead of time is a supported
// workflow (the role activates when the adapter comes back up).
//
//   "no-forwarding-path" -- the service found neither a gateway nor a
//                          default-style route with a real next-hop on this
//                          interface: there is nowhere for it to forward to.
//
// `hasDefaultRoute` must NEVER be used for this: the enumeration derives it as
// `gateway != "-"`, so it is the same fact spelled twice and reads false for
// every healthy gateway-less tunnel (OpenVPN/WireGuard install split-default
// routes instead of a gateway). `hasForwardingPath` is the real signal — the
// service computes it from the route table with the same function the routing
// layer uses to pick a next hop, so the GUI can never call an adapter unusable
// that the router would route through. It is absent (false) on a service that
// predates the field, which is why it only ever *adds* a reason: a missing
// signal must not manufacture a warning.
//
// Slug values come from the enumeration: `availability` is
// "available" | "unavailable" | "requires-check"; `classification` is
// "regular-interface" | "vpn-or-tunnel-likely" | "virtual-interface-likely" |
// "service-interface-likely"; every likelihood is "likely" | "possible" |
// "unlikely" | "unknown", with 70 the confidence a two-point heuristic hit
// scores (a single weak signal only reaches 50).
function unroutableInterfaceReasonSlug(row) {
    if (!row) return ""
    if (String(row.availability || "") !== "available") return ""
    if (_interfaceHasUsableGateway(row.gateway)) return ""
    var assessment = row.derivedAssessment || {}
    var virtualLikelihood = String(assessment.virtualInterfaceLikelihood || "")
    var classification = String(assessment.classification || "")
    var confidence = Number(assessment.confidencePercent || 0)
    var confidentlyVirtual = virtualLikelihood === "likely"
        || (classification === "virtual-interface-likely" && confidence >= 70)
    if (confidentlyVirtual) return "virtual-host-only"
    // Evaluated by the service and negative: no gateway and no default-style
    // route with a real next-hop. `null` (not evaluated) never warns.
    if (row.hasForwardingPath === false) return "no-forwarding-path"
    return ""
}

// Convenience predicate over `unroutableInterfaceReasonSlug`.
function interfaceCannotCarryTrafficOut(row) {
    return unroutableInterfaceReasonSlug(row) !== ""
}

// ---- pending-apply / review summary counting ----

// True when a dry-run review summary carries no rule changes and no
// changed-fields. `summary` arrives from the C++ bridge as a QVariantMap whose
// nested arrays surface as QVariantList (NOT a JS Array), so `Array.isArray()`
// returns false for them even though they expose a numeric `.length` and
// indexing -- the old `Array.isArray(arr) ? arr.length : 0` counted ZERO
// changes for every live-IPC summary (a genuine 296-rule diff read as "nothing
// to apply"). Count by `.length` directly so both native JS arrays
// (mock/preview backends) and the bridge's QVariantList (live service) work.
function reviewSummaryIsEmpty(summary) {
    if (!summary) return true
    var len = function(key) {
        var arr = summary[key]
        return (arr !== undefined && arr !== null && typeof arr.length === "number")
            ? arr.length : 0
    }
    var ruleChanges = len("rules-added") + len("rules-removed")
        + len("rules-modified") + len("rules-retargeted")
    if (ruleChanges > 0) return false
    if (len("changed-fields") > 0) return false
    return true
}

// Parse a parked pending-apply `summary-json` text into
// { added, removed, modified, total }. Best-effort: a corrupted or missing
// summary just renders as zeros.
function parsePendingSummaryCounts(summaryJsonText) {
    var out = { added: 0, removed: 0, modified: 0, total: 0 }
    if (!summaryJsonText) return out
    try {
        var obj = JSON.parse(String(summaryJsonText))
        if (Array.isArray(obj["rules-added"])) out.added = obj["rules-added"].length
        if (Array.isArray(obj["rules-removed"])) out.removed = obj["rules-removed"].length
        if (Array.isArray(obj["rules-modified"])) out.modified = obj["rules-modified"].length
        if (typeof obj["total-rules"] === "number") out.total = obj["total-rules"]
    } catch (e) {
        // Best-effort -- corrupted summary just renders as zeros.
    }
    return out
}

// ---- route.policy.update -- the ONE wire-field declaration ----
//
// `route.policy.update` is a FULL-REPLACEMENT request: every field the payload
// leaves out falls back to the server's serde default, silently resetting
// whatever the user had configured. Two failure modes followed from that, and
// both were shipped more than once:
//   * a builder forgot a field (the route-binding clobber), and
//   * a default was spelled out twice and the two spellings drifted apart
//     (the panel showed ON while the request sent `false`).
// Everything below exists so neither can happen silently again. Each wire key
// and its default is declared HERE, once, for every builder in both the GUI and
// the tray process; `route_policy_wire_contract.rs` in `shared/contracts/tests`
// pins this table against the Rust DTO so a contract change that is not
// mirrored here fails `cargo test`, not a hardware run.
//
// A value here MUST equal the serde default of the same field in
// `nrr_shared::ipc_payloads::RoutePolicyUpdateRequest` -- the Rust side is
// normative, this table is the mirror.

// Wire key -> value used when the live snapshot does not carry the key.
// `binding-source` is deliberately absent: it is not preserved from the
// snapshot but always stamped by the writer (see `buildFullRoutePolicyReq`).
var ROUTE_POLICY_FIELD_DEFAULTS = {
    "mode": "prefer-primary",
    "block-secondary-when-unavailable": false,
    "kill-switch-fail-closed": true,
    "kill-switch-protocols": 127,
    "kill-switch-block-all": false,
    "kill-switch-enabled": false,
    "allow-dns-over-primary": true,
    "include-subdomains": true,
    "shared-ip-policy": "majority-of-ip",
    "mode-a-coverage-strategy": "per-ip",
    "resolve-hosts-bypass": true,
    "doh-lockdown-enabled": false,
    "doh-lockdown-scope": "leak-protection-only",
    "browser-history-auto-seed": false,
    "kill-switch-strict-shared-ips": false,
    "auto-rules-mode": "suggest",
    "auto-rules-eager-delivery-names": false
}

// Keys the policy SNAPSHOT carries but the update REQUEST must not: they are
// written through their own dedicated operation and the request DTO has no
// field for them.
var ROUTE_POLICY_SNAPSHOT_ONLY_KEYS = ["secondary-link-provider-apps"]

// Bit masks for the numeric wire fields (the protocol bitmask is the only one).
var ROUTE_POLICY_FIELD_MASKS = { "kill-switch-protocols": 0x7F }

// Normalise ONE route-policy value to the shape the wire expects, using the
// declared default to pick the coercion. Absent / null / empty reads as the
// default, so a snapshot value, a parked offline intent and a QML literal all
// stay comparable with `===`.
function routePolicyCoerce(key, raw) {
    var def = ROUTE_POLICY_FIELD_DEFAULTS[key]
    if (def === undefined) return raw
    if (raw === undefined || raw === null || raw === "") return def
    if (typeof def === "boolean") return raw === true
    if (typeof def === "number") {
        var mask = ROUTE_POLICY_FIELD_MASKS[key]
        var n = raw | 0
        return (mask === undefined) ? n : (n & mask)
    }
    return String(raw)
}

// Effective CURRENT value of one route-policy key from a snapshot (or from any
// map with the same wire keys -- a parked-intent bucket, the display mirror).
// `undefined` for a key this build does not know, which callers use as "not a
// route-policy field".
function routePolicyEffective(cur, key) {
    if (ROUTE_POLICY_FIELD_DEFAULTS[key] === undefined) return undefined
    return routePolicyCoerce(key, (cur || {})[key])
}

// Build the FULL `route.policy.update` request from a policy snapshot.
// Callers overlay only the keys they are changing.
//
// Two passes, and the order matters:
//   1. copy everything the service just reported (minus the snapshot-only
//      keys), so a contract field this GUI build has never heard of still
//      rides back unchanged instead of being reset to a serde default;
//   2. normalise and fill every DECLARED field from the table above, so an
//      empty or older snapshot cannot let a serde default win either.
// `modeFallback` is the local `routeBehaviorMode` preference mirror -- the one
// field with a GUI-side fallback to consult before the contract default.
function buildFullRoutePolicyReq(cur, modeFallback) {
    cur = cur || {}
    var req = {}
    var key
    for (key in cur) {
        if (ROUTE_POLICY_SNAPSHOT_ONLY_KEYS.indexOf(key) >= 0) continue
        var value = cur[key]
        if (value === undefined || value === null) continue
        req[key] = value
    }
    if (!req["mode"]) req["mode"] = String(modeFallback || "")
    for (key in ROUTE_POLICY_FIELD_DEFAULTS) req[key] = routePolicyCoerce(key, req[key])
    // The writer always claims the binding as user-assigned; `recovery` /
    // `migrated-from-preferences` are service- and migration-owned values that
    // must never be echoed back from a snapshot.
    req["binding-source"] = "user-assigned"
    return req
}

// ---- auto-rule suggestion grouping (domain = eTLD+1) ----
//
// Not a full Public Suffix List -- a compact table of the two-label suffixes
// that actually show up under the countries this project ships presets for
// (plus the handful of global ones a user is likely to see), so "naive last
// two labels" doesn't turn `example.co.uk` into a bogus "co.uk" group.
// Unknown two-label endings fall through to the naive rule, which is correct
// for the overwhelming majority of hostnames.
var AUTO_RULE_MULTI_LABEL_SUFFIXES = {
    "co.uk": 1, "org.uk": 1, "me.uk": 1, "ltd.uk": 1, "plc.uk": 1, "net.uk": 1, "sch.uk": 1, "ac.uk": 1, "gov.uk": 1,
    "com.au": 1, "net.au": 1, "org.au": 1, "edu.au": 1, "gov.au": 1, "id.au": 1,
    "co.nz": 1, "net.nz": 1, "org.nz": 1, "govt.nz": 1,
    "co.jp": 1, "or.jp": 1, "ne.jp": 1, "ac.jp": 1, "go.jp": 1,
    "co.kr": 1, "or.kr": 1, "ne.kr": 1, "go.kr": 1,
    "com.cn": 1, "net.cn": 1, "org.cn": 1, "gov.cn": 1, "edu.cn": 1,
    "com.br": 1, "net.br": 1, "org.br": 1, "gov.br": 1,
    "com.mx": 1, "org.mx": 1, "gob.mx": 1,
    "com.ar": 1, "net.ar": 1, "org.ar": 1, "gob.ar": 1,
    "co.in": 1, "net.in": 1, "org.in": 1, "gov.in": 1, "firm.in": 1, "gen.in": 1, "ind.in": 1, "ac.in": 1, "edu.in": 1, "res.in": 1,
    "co.za": 1, "org.za": 1, "net.za": 1, "gov.za": 1,
    "com.tr": 1, "org.tr": 1, "net.tr": 1, "gov.tr": 1, "edu.tr": 1,
    "co.il": 1, "org.il": 1, "net.il": 1, "gov.il": 1,
    "com.sg": 1, "net.sg": 1, "org.sg": 1, "gov.sg": 1,
    "com.hk": 1, "org.hk": 1, "net.hk": 1, "gov.hk": 1,
    "com.tw": 1, "org.tw": 1, "net.tw": 1, "gov.tw": 1,
    "com.my": 1, "net.my": 1, "org.my": 1, "gov.my": 1,
    "com.ua": 1, "net.ua": 1, "org.ua": 1, "gov.ua": 1,
    "net.ru": 1, "org.ru": 1, "com.ru": 1, "pp.ru": 1, "msk.ru": 1, "spb.ru": 1,
    "co.ae": 1, "net.ae": 1, "org.ae": 1, "gov.ae": 1, "sch.ae": 1, "ac.ae": 1,
    "com.bh": 1, "net.bh": 1, "org.bh": 1, "gov.bh": 1,
    "com.eg": 1, "net.eg": 1, "org.eg": 1, "gov.eg": 1, "edu.eg": 1, "sci.eg": 1,
    "co.id": 1, "net.id": 1, "or.id": 1, "web.id": 1, "my.id": 1, "biz.id": 1, "ac.id": 1, "sch.id": 1, "go.id": 1,
    "co.ir": 1, "net.ir": 1, "org.ir": 1, "gov.ir": 1, "sch.ir": 1, "ac.ir": 1,
    "com.kw": 1, "net.kw": 1, "org.kw": 1, "edu.kw": 1, "gov.kw": 1,
    "org.kz": 1, "edu.kz": 1, "net.kz": 1, "gov.kz": 1, "mil.kz": 1, "com.kz": 1,
    "co.om": 1, "com.om": 1, "net.om": 1, "org.om": 1, "edu.om": 1, "gov.om": 1,
    "com.qa": 1, "net.qa": 1, "org.qa": 1, "edu.qa": 1, "gov.qa": 1,
    "com.sa": 1, "net.sa": 1, "org.sa": 1, "gov.sa": 1, "med.sa": 1, "pub.sa": 1, "edu.sa": 1, "sch.sa": 1,
    "com.vn": 1, "net.vn": 1, "org.vn": 1, "gov.vn": 1, "edu.vn": 1
}

// Registrable domain (eTLD+1) for a hostname -- the group key suggestion rows
// collapse onto. An IPv4-shaped host or one with 2 labels or fewer is
// returned unchanged (it already IS its own group).
function registrableDomain(hostname) {
    var host = String(hostname || "").toLowerCase().replace(/\.$/, "")
    if (host === "" || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return host
    var labels = host.split(".")
    if (labels.length <= 2) return host
    var lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1]
    if (labels.length >= 3 && AUTO_RULE_MULTI_LABEL_SUFFIXES[lastTwo]) {
        return labels[labels.length - 3] + "." + lastTwo
    }
    return lastTwo
}

// Every site relying on a suggestion row. The service puts the signing
// anchor first; a peer that predates the `consumers` field sends nothing, so
// the anchor alone stands in for the list. Shared by the pending and the
// dismissed shape -- both carry `anchor`, only pending carries `consumers`.
function autoRuleRowConsumers(row) {
    var list = row.consumers || row["consumers"] || []
    if (list.length > 0) return list
    var anchor = String(row.anchor || "")
    if (anchor === "") return []
    return [{ "hostname": anchor, "route": String(row.route || "") }]
}

// Merge `autorules.candidates.list` + `autorules.dismissed.list` rows into
// domain groups, one pass over each input array. Computed ONCE by the caller
// (a property binding keyed on the two source arrays) and read as plain data
// by every delegate -- never re-run per row, which is what made the old
// per-subdomain rows quadratic to filter/sort as the list grew.
//
// A rule of "domain + *.domain" acts on the whole group, so selection and
// bulk actions key on the DOMAIN, not on individual candidate ids -- callers
// don't need an id->group lookup, just `group.pendingIds` / `.dismissedIds`.
function groupAutoRuleRows(candidates, dismissed) {
    var byDomain = {}
    var order = []

    function addLeaf(row, status) {
        var match = String(row["proposed-match"] || row.proposedMatch || "")
        if (match === "") return
        var domain = registrableDomain(match)
        var group = byDomain[domain]
        if (!group) {
            group = { domain: domain, hosts: [], pendingIds: [], dismissedIds: [],
                consumersByHost: {}, latestMs: 0 }
            byDomain[domain] = group
            order.push(domain)
        }
        var id = String(status === "pending"
            ? (row.id || "")
            : (row["candidate-id"] || row.candidateId || ""))
        var consumers = autoRuleRowConsumers(row)
        var ts = status === "pending"
            ? (Number(row["consumers-changed-unix-ms"] || 0) || Number(row["first-seen-unix-ms"] || 0))
            : Number(row["dismissed-at-unix-ms"] || row.dismissedAtUnixMs || 0)
        group.hosts.push({
            id: id,
            status: status,
            match: match,
            matchKind: String(row["match-kind"] || row.matchKind || ""),
            anchor: String(row.anchor || ""),
            route: String(row.route || ""),
            consumers: consumers,
            affinity: Number(row.affinity || 0),
            observations: Number(row.observations || 0),
            signal: String(row.signal || ""),
            primaryBehavior: String(row["primary-behavior"] || row.primaryBehavior || ""),
            timestampMs: ts
        })
        if (status === "pending") group.pendingIds.push(id)
        else group.dismissedIds.push(id)
        if (ts > group.latestMs) group.latestMs = ts
        for (var c = 0; c < consumers.length; c += 1) {
            var h = String((consumers[c] || {}).hostname || "")
            if (h !== "") group.consumersByHost[h] = consumers[c]
        }
    }

    var i
    for (i = 0; i < (candidates || []).length; i += 1) addLeaf(candidates[i], "pending")
    for (i = 0; i < (dismissed || []).length; i += 1) addLeaf(dismissed[i], "dismissed")

    var groups = []
    for (i = 0; i < order.length; i += 1) {
        var g = byDomain[order[i]]
        var consumerList = []
        var keys = Object.keys(g.consumersByHost)
        for (var k = 0; k < keys.length; k += 1) consumerList.push(g.consumersByHost[keys[k]])
        groups.push({
            domain: g.domain,
            hosts: g.hosts,
            pendingIds: g.pendingIds,
            dismissedIds: g.dismissedIds,
            consumers: consumerList,
            latestMs: g.latestMs
        })
    }
    return groups
}

// Groups whose consumer list includes `consumerFilter` (empty = no filter).
function filterAutoRuleGroups(groups, consumerFilter) {
    if (!consumerFilter) return groups
    var out = []
    for (var i = 0; i < groups.length; i += 1) {
        var g = groups[i]
        var hit = false
        for (var c = 0; c < g.consumers.length; c += 1) {
            if (String((g.consumers[c] || {}).hostname || "") === consumerFilter) { hit = true; break }
        }
        if (hit) out.push(g)
    }
    return out
}

// Groups whose domain, an observed host, or a consumer hostname contains
// `query` (case-insensitive substring; empty query matches everything).
function searchAutoRuleGroups(groups, query) {
    var q = String(query || "").trim().toLowerCase()
    if (q === "") return groups
    var out = []
    for (var i = 0; i < groups.length; i += 1) {
        var g = groups[i]
        var hit = String(g.domain || "").toLowerCase().indexOf(q) >= 0
        for (var h = 0; !hit && h < g.hosts.length; h += 1) {
            hit = String(g.hosts[h].match || "").toLowerCase().indexOf(q) >= 0
        }
        for (var c = 0; !hit && c < g.consumers.length; c += 1) {
            hit = String((g.consumers[c] || {}).hostname || "").toLowerCase().indexOf(q) >= 0
        }
        if (hit) out.push(g)
    }
    return out
}

// `newest` | `consumers` | `name`, mirroring the sort modes the old
// suggestions inbox offered.
function sortAutoRuleGroups(groups, mode) {
    var out = groups.slice()
    out.sort(function(a, b) {
        if (mode === "name") return a.domain.localeCompare(b.domain)
        if (mode === "consumers") {
            var d = b.consumers.length - a.consumers.length
            return d !== 0 ? d : a.domain.localeCompare(b.domain)
        }
        var d2 = b.latestMs - a.latestMs
        return d2 !== 0 ? d2 : a.domain.localeCompare(b.domain)
    })
    return out
}
