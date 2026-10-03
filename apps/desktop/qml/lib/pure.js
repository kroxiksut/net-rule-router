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
    if (value === "rule-overlaps") return 3
    if (value === "rule-virtual-machines") return 4
    if (value === "diagnostics") return 5
    if (value === "conn-trace") return 6
    if (value === "cache") return 7
    if (value === "logs") return 8
    return 9
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

// Fill `{name}` from `args` and `{0}`, `{1}`… from `positional` in ONE pass:
// a value is never re-scanned, so a `{host}` or `$&` inside it stays literal.
// A translation left with a hole reads worse than the English line, which
// still carries the cause — so any unfilled placeholder shows `source` instead.
function formatLogLine(translated, source, args, positional) {
    var named = args || {}
    var indexed = positional || []
    var missing = false
    var filled = String(translated).replace(/\{(\w+)\}/g, function(whole, name) {
        if (Object.prototype.hasOwnProperty.call(named, name)) return String(named[name])
        if (/^\d+$/.test(name) && Number(name) < indexed.length) return String(indexed[Number(name)])
        missing = true
        return whole
    })
    return missing ? String(source) : filled
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

// Schemes the app is willing to hand to the OS. A URL string reaches this
// helper from an about-payload, a third-party manifest and a user-editable
// preference, and `Qt.openUrlExternally` will launch whatever the platform has
// registered for a scheme — `file:` browsers a folder, and other schemes can
// start programs. Nothing here needs more than the web and the local folders we
// open ourselves.
var EXTERNAL_URL_SCHEMES = ["http://", "https://", "file:///"]

function isOpenableExternalUrl(url) {
    var s = String(url || "")
    for (var i = 0; i < EXTERNAL_URL_SCHEMES.length; i++) {
        if (s.toLowerCase().indexOf(EXTERNAL_URL_SCHEMES[i]) === 0) return true
    }
    return false
}

function openExternalUrl(url) {
    if (isOpenableExternalUrl(url)) Qt.openUrlExternally(String(url))
}

// The page the compatibility banner offers. A user/administrator override wins
// when it is set and openable; otherwise the project's own releases page.
function updatesPageUrl(prefs, about) {
    var override = String((prefs || {}).updatePageUrl || "")
    if (isOpenableExternalUrl(override)) return override
    var base = String((about || {}).projectUrl || "")
    return base === "" ? "" : base + "/releases"
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

// ---- file URLs ----

// Local path behind a `file:` URL from a Qt file/folder dialog.
//
// The naive form drops eight characters after `file:///`, which is right for
// `file:///C:/x` and wrong everywhere else: on Linux `file:///home/u/rules.txt`
// comes back as `home/u/rules.txt`, a RELATIVE path, and the read then fails
// while the dialog reports the file the user picked. The leading slash belongs
// to the path unless a drive letter follows it.
//
// Percent-escapes are decoded: a dialog hands back `%20` for a space, and every
// caller passes the result straight to a file API.
function localPathFromFileUrl(urlValue) {
    var raw = String(urlValue || "")
    var rest
    if (raw.indexOf("file:///") === 0) {
        rest = raw.substring(7)
    } else if (raw.indexOf("file://") === 0) {
        // No third slash: what follows is a host, and the path is a UNC share.
        rest = "//" + raw.substring(7)
    } else {
        rest = raw
    }
    // `/C:/…` — a Windows drive; the slash is URL syntax, not path.
    if (/^\/[A-Za-z]:/.test(rest)) rest = rest.substring(1)
    try {
        return decodeURIComponent(rest)
    } catch (e) {
        return rest
    }
}

// ---- correlation id ----

// `origin` names the call site. Two different flows can submit a byte-identical
// preview payload, and when both are in flight at once the service log cannot
// tell them apart — the correlation id is the only place the difference can
// live. Omitting it keeps the id every existing caller produced.
function newCorrelationId(origin) {
    var prefix = origin ? ("rules-update-" + origin) : "rules-update"
    return prefix + "-" + Date.now() + "-" + Math.floor(Math.random() * 1e6)
}

// ---- offline-intents pure math ----

function pendingOfflineCount(obj) {
    if (!obj) return 0
    var rp = obj["route-policy"] || {}
    var st = obj["stability"] || {}
    var bd = obj["binding"] || {}
    // The binding namespace holds one undelivered fact, not a key per field,
    // so it counts as one — but it MUST count, or the store that carries it is
    // written out as empty and the parked assignment is lost.
    return Object.keys(rp).length + Object.keys(st).length
        + (bd.pending === true ? 1 : 0)
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
    "verbose-logging-mode": "off",
    "verbose-logging-until-ms": 0,
    "conn-trace-ndjson": false,
    "conn-trace-gui": true,
    "rule-scope-service-driven": true,
    "routing-stop-policy": "teardown",
    "cache-refresh-interval-secs": 300,
    "enforcement-mode": "resolver",
    "secondary-liveness-window-secs": 0,
    "fake-ip-enabled": false,
    "dns-via-secondary": false,
    "dns-fast-answers": true,
    "fake-ip-udp-relay": false,
    "fake-ip-instant-rst": true
}

// Row fields whose value is not a scalar, so they cannot live in the table
// above but are still part of the config the writer round-trips.
var STABILITY_STRUCTURED_KEYS = ["ipc-accept-policy"]

// The administrator's rules lock: never recorded as a user's intent, never
// replayed and never carried forward out of one user's preferences.
var STABILITY_INTENT_EXCLUDED_KEYS = ["allow-user-rule-edits"]

// Row fields whose value belongs to the calling user. Empty: the service keeps
// ONE stability row per machine and refuses an unelevated change of any field
// (`service_stability_handlers.rs`), so every other key is machine-wide.
var STABILITY_PER_USER_KEYS = []

// Service-side clamps for the numeric fields. `non-positive` is the value a
// zero-or-negative input resolves to (0 = "disabled" for the liveness window,
// the default cadence for the cache refresh).
var STABILITY_FIELD_CLAMPS = {
    "secondary-liveness-window-secs": { "min": 5, "max": 3600, "non-positive": 0 },
    "cache-refresh-interval-secs": { "min": 60, "max": 86400, "non-positive": 300 }
}

// Legal values of the slug fields; anything else resolves to the default.
var STABILITY_FIELD_CHOICES = {
    "verbose-logging-mode": ["off", "timed", "until-restart"],
    "enforcement-mode": ["resolver", "reactive"],
    "routing-stop-policy": ["teardown", "persist"]
}

// True when `key` is a field of the config row this build knows about.
function stabilityKeyIsKnown(key) {
    return STABILITY_FIELD_DEFAULTS[key] !== undefined
        || STABILITY_STRUCTURED_KEYS.indexOf(key) >= 0
}

// True when a recorded intent for `key` may be kept at all. A one-shot request
// such as `verbose-logging-change` never is: replayed on the next connect it
// would re-open a window that had ended. Neither is the rules lock, nor a key
// this build no longer has.
function stabilityIntentIsRecordable(key) {
    return stabilityKeyIsKnown(key) && STABILITY_INTENT_EXCLUDED_KEYS.indexOf(key) < 0
}

function stabilityKeyIsMachineWide(key) {
    return STABILITY_PER_USER_KEYS.indexOf(key) < 0
}

// What a full-row write may carry forward out of the recorded intent without
// the user naming it. Never a machine-wide value, not even from an elevated
// GUI: it would overwrite what another administrator chose.
function stabilityIntentMayReplay(key) {
    return stabilityIntentIsRecordable(key) && !stabilityKeyIsMachineWide(key)
}

function _stabilitySame(a, b) {
    return JSON.stringify(a) === JSON.stringify(b)
}

// The part of the recorded intent a full-row write may carry forward.
function stabilityReplayableIntent(intent) {
    var out = {}
    for (var key in (intent || {})) {
        if (stabilityIntentMayReplay(key)) out[key] = intent[key]
    }
    return out
}

// Recorded intents the live row holds otherwise, as key -> { mine, service },
// for the settings panels to show: a connect writes nothing back. Parked keys
// belong to the pending-changes flow.
function stabilityIntentDivergence(intent, live, parked) {
    var out = {}
    for (var key in (intent || {})) {
        if (!stabilityIntentIsRecordable(key)) continue
        if (parked && parked.hasOwnProperty(key)) continue
        var service = stabilityEffective(live, key)
        if (_stabilitySame(stabilityEffective(intent, key), service)) continue
        out[key] = { "mine": intent[key], "service": service }
    }
    return out
}

// The recorded intent without `key`: the user chose to keep the service's
// value. Returns null when there was nothing recorded for it.
function stabilityIntentWithout(intent, key) {
    if (!intent || !intent.hasOwnProperty(key)) return null
    var out = {}
    for (var k in intent) {
        if (k !== key) out[k] = intent[k]
    }
    return out
}

// The recorded intent after a user's write the service CONFIRMED. `before` is
// the row the write was merged onto. A machine-wide key is recorded only when
// the write was carried out elevated: the GUI itself is, or the value really
// changed, which the service accepts from nobody else. Any other key the write
// named loses its old record, since the service now holds the user's latest
// choice. Returns null when nothing changes.
function stabilityIntentAfterWrite(intent, partial, before, appElevated) {
    var out = {}
    var key
    for (key in (intent || {})) out[key] = intent[key]
    var changed = false
    for (key in (partial || {})) {
        var value = partial[key]
        if (value === undefined || !stabilityIntentIsRecordable(key)) continue
        var elevatedWrite = appElevated === true || !stabilityKeyIsMachineWide(key)
            || !_stabilitySame(stabilityEffective(partial, key), stabilityEffective(before, key))
        if (elevatedWrite) {
            if (_stabilitySame(out[key], value)) continue
            out[key] = value
            changed = true
        } else if (out.hasOwnProperty(key)) {
            delete out[key]
            changed = true
        }
    }
    return changed ? out : null
}

// The requests the verbose-logging control offers, in display order.
var VERBOSE_LOGGING_CHANGES = ["off", "one-hour", "four-hours", "until-restart"]

// Stability keys a service without the whole row still applies, each with the
// capability that says so. Where `serviceStabilityConfig` holds, every key does.
var STABILITY_KEY_CAPABILITY = {
    "verbose-logging-change": "verboseLogging",
    "conn-trace-ndjson": "connTraceLog",
    "conn-trace-gui": "connTraceLog"
}

// `supports` is the platform profile's capability map; an absent map or flag
// reads as supported, as the window's `supports()` does.
function _profileSupports(supports, feature) {
    return !supports || supports[feature] !== false
}

function stabilityKeyApplies(key, supports) {
    if (_profileSupports(supports, "serviceStabilityConfig")) return true
    var capability = STABILITY_KEY_CAPABILITY[key]
    return capability !== undefined && _profileSupports(supports, capability)
}

// The part of a stability patch this platform's service applies. A key it
// would only store must not be sent as if it took effect.
function stabilityPatchForPlatform(partial, supports) {
    var out = {}
    for (var key in (partial || {})) {
        if (stabilityKeyApplies(key, supports)) out[key] = partial[key]
    }
    return out
}

// Whether this platform's service applies any stability key at all.
function stabilityAnyKeyApplies(supports) {
    if (_profileSupports(supports, "serviceStabilityConfig")) return true
    for (var key in STABILITY_KEY_CAPABILITY) {
        if (_profileSupports(supports, STABILITY_KEY_CAPABILITY[key])) return true
    }
    return false
}

// Whole hours and minutes left until `untilMs`, rounded up to the minute so
// the last minute never reads as zero.
function remainingHoursMinutes(untilMs, nowMs) {
    var left = Math.max(0, Number(untilMs || 0) - Number(nowMs || 0))
    var minutes = Math.ceil(left / 60000)
    return { "hours": Math.floor(minutes / 60), "minutes": minutes % 60 }
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

// Wall-clock stamp for a table cell: "YYYY-MM-DD HH:MM", or an em dash when
// there is no usable time. Shared by the cache and connection-trace tables,
// which must not disagree about how a timestamp looks.
function formatTimestamp(ms) {
    var n = Number(ms || 0)
    if (!isFinite(n) || n <= 0) return "—"
    var d = new Date(n)
    function pad(x) { return (x < 10 ? "0" : "") + String(x) }
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate())
        + " " + pad(d.getHours()) + ":" + pad(d.getMinutes())
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
// True when a connection-trace endpoint is IPv6. The display string is either
// a bracketed literal ("[fe80::1]:53") or a bare address; a bare IPv6 has more
// than one colon, while "1.2.3.4:443" has exactly one. A masked or empty value
// reads as NOT v6 — the caller narrows the view with this, and a row we cannot
// read must not be presented as evidence about a family.
function isIpv6Endpoint(endpoint) {
    var s = String(endpoint || "").trim()
    if (s === "") return false
    if (s.charAt(0) === "[") return true
    return s.split(":").length > 2
}

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

// Mirror of the service's `description_matches_display_name`: tokens split on
// whitespace, `_` and `-`, version tokens dropped, symmetric containment, and
// at least one shared token that names a vendor rather than a category. Any
// drift makes the GUI report "adapter not found" for a binding the service has
// already re-matched ("x_VPN" vs "x VPN OpenVPN Adapter").
var ADAPTER_GENERIC_NAME_TOKENS = [
    "vpn", "adapter", "tunnel", "client", "network", "connection",
    "ethernet", "wireless", "virtual", "tap", "wintun"
]

function storedNameMatchesLive(storedName, liveText) {
    function _coreTokens(s) {
        var out = []
        var parts = String(s || "").toLowerCase().split(/[\s_-]+/)
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
    if (!_subset(saved, live) && !_subset(live, saved)) return false
    for (var j = 0; j < saved.length; j += 1) {
        if (live.indexOf(saved[j]) !== -1
                && ADAPTER_GENERIC_NAME_TOKENS.indexOf(saved[j]) === -1)
            return true
    }
    return false
}

// ---- service interface wire-row -> model-row mapping ----

function mapWireInterfaceRow(w) {
    if (!w) return null
    var of = w["observed-facts"] || {}
    var da = w["derived-assessment"] || {}
    var rec = w["recommendation"] || {}
    return {
        persistentId: String(w["persistent-id"] || ""),
        name: String(w["name"] || ""),
        description: String(w["interface-description"] || ""),
        type: String(w["interface-type"] || ""),
        kind: String(w["kind"] || ""),
        deviceTechnology: String(w["device-technology"] || ""),
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
            externalIp: (of["external-ip"] === undefined ? null : of["external-ip"])
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

// How one adapter reads to a user, everywhere it is named.
//
// The CONNECTION name leads and the driver description follows. Which way round
// they go is the whole point: the description names the driver ("WireGuard
// Tunnel", "TAP-Windows Adapter V9") and is shared by every tunnel of that kind,
// while the connection name is what the user themselves gave it or what their
// VPN client wrote there. A dialog that said only the description asked people
// to recognise their VPN by the driver behind it.
//
// The description is still worth showing — a laptop with "Wi-Fi", "Wi-Fi 2" and
// "Ethernet 3" needs it to tell them apart — so it is appended, not dropped, and
// only when it adds something the name does not already say.
function adapterDisplayName(row) {
    if (!row) return ""
    var name = String(row.name || "").trim()
    var descr = String(row.description || "").trim()
    if (name === "") return descr
    if (descr === "" || descr === name) return name
    return name + " \u2014 " + descr
}

// The hint beside an adapter's kind, read off the service's own role
// recommendation: "looks-primary", "looks-vpn" or "". A tunnel's kind already
// says VPN, so it gets no second word for it.
function adapterRoleHintSlug(row) {
    if (!row) return ""
    var cls = String((row.recommendation || {})["class"] || "")
    if (cls === "preferred-primary") return "looks-primary"
    var kind = String(row.kind || "")
    if (kind === "tunnel" || kind === "virtual") return ""
    var vpn = String((row.derivedAssessment || {}).vpnTunnelLikelihood || "")
    if (vpn === "likely" || (vpn === "possible" && cls === "preferred-secondary"))
        return "looks-vpn"
    return ""
}

// The role this adapter holds other than `role`, or "". One adapter cannot
// carry both routes, so a picker for `role` does not offer it.
function adapterHeldOtherRole(row, role) {
    if (!row) return ""
    var held = String(row.selectedRole || "")
    return held !== "" && held !== String(role || "") ? held : ""
}

// Convenience predicate over `unroutableInterfaceReasonSlug`.
function interfaceCannotCarryTrafficOut(row) {
    return unroutableInterfaceReasonSlug(row) !== ""
}

// ---- pending-apply / review summary counting ----

// The values a rules preview names as refused by the service, joined for the
// `{rules}` placeholder; "" when it refuses none.
function refusedRuleValuesText(summary) {
    var signals = summary && summary["risk-signals"]
    if (!signals || typeof signals.length !== "number") return ""
    for (var i = 0; i < signals.length; i += 1) {
        var signal = signals[i]
        if (!signal || signal.kind !== "invalid-rule-value" || !signal.rules) continue
        var values = []
        for (var j = 0; j < signal.rules.length; j += 1) values.push(String(signal.rules[j]))
        return values.join(", ")
    }
    return ""
}

// The service's refusal of a previewed change as `{ code, values }`, or null
// when it would accept the change. A refused preview carries no rule changes,
// so every reader of a preview asks this before calling it empty: refused is
// not "nothing to apply". `values` is "" unless the refusal names rule values.
function previewRefusal(summary) {
    var signals = summary && summary["risk-signals"]
    if (!signals || typeof signals.length !== "number") return null
    for (var i = 0; i < signals.length; i += 1) {
        var signal = signals[i]
        if (!signal) continue
        if (signal.kind === "invalid-rule-value") {
            return { code: "invalid-rule-value", values: refusedRuleValuesText(summary) }
        }
        if (signal.kind === "change-refused") {
            return { code: String(signal.code || "unknown"), values: "" }
        }
    }
    return null
}

// Whether the "new version" notice shows for `offer` ({latestVersion, url} or
// null). A dismissed release stays hidden; the offer is always the newest one
// the release page names, so any other version is a newer release.
function updateOfferShown(offer, dismissedVersion) {
    if (!offer || !offer.latestVersion) return false
    return String(offer.latestVersion) !== String(dismissedVersion || "")
}

// The verdict of an `operation.status.get` answer: "" when the operation
// completed, its error code when it failed, null when the answer says neither
// (the record is not readable here, or not finished).
function operationOutcome(ok, status) {
    if (!ok || !status) return null
    var state = String(status.state || "")
    if (state === "completed") return ""
    if (state === "failed") return String((status.error && status.error.code) || "unknown")
    return null
}

// What a safe-rollback dry-run answered. `phase` is "ready" (a `target` and
// the `token` that restores it), "none" (nothing to roll back to) or "error"
// (`code` says why).
function rollbackDryRunVerdict(ok, answer, code) {
    var verdict = { phase: "error", token: "", target: null, code: "" }
    if (!ok) {
        verdict.code = String(code || "unknown")
        return verdict
    }
    var a = answer || {}
    if (a.error) {
        verdict.code = String(a.error.code || "unknown")
        return verdict
    }
    var token = String(a["confirmation-token"] || "")
    if (token !== "" && a.target) {
        verdict.phase = "ready"
        verdict.token = token
        verdict.target = a.target
    } else if (token === "" && !a.target) {
        verdict.phase = "none"
    } else {
        verdict.code = "bad-response"
    }
    return verdict
}

// Whether a `snapshot.diagnostics.get` status is the service saying it could
// not read its alert store (as opposed to no answer at all).
function securityAlertsUnreadable(status) {
    if (!status || status.stale === true) return false
    var security = status.security_status
    return !security || security.alerts_readable !== true
}

// The alert list of a `snapshot.diagnostics.get` status, in the shape the
// launch context carries it. null when the status is no answer from the
// service, or the service could not read its alerts: an empty list from a
// failed read must not clear the alerts shown.
function securityAlertItemsFromStatus(status) {
    if (!status || status.stale === true) return null
    if (securityAlertsUnreadable(status)) return null
    var alerts = status.active_alerts
    if (!alerts || typeof alerts.length !== "number") return null
    var items = []
    for (var i = 0; i < alerts.length; i++) {
        var a = alerts[i]
        if (!a) continue
        items.push({
            alertId: String(a.alert_id || ""),
            kind: String(a.kind || ""),
            state: String(a.state || ""),
            createdAt: Number(a.created_at || 0),
            updatedAt: Number(a.updated_at || 0),
            reasonCode: String(a.reason_code || ""),
            raisedFile: String(a.raised_file || ""),
            requiresAction: a.requires_action === true
        })
    }
    return items
}

// Verdict on an alert acknowledgement from a `snapshot.diagnostics.get`
// answer: "" once the service no longer lists `alertId` as active, "unknown"
// while it still does, `failureCode` (or "unknown") when the answer carries
// no readable list — an empty list from an unreadable store proves nothing.
function alertAckOutcome(status, alertId, failureCode) {
    var alerts = securityAlertItemsFromStatus(status)
    if (alerts === null) return String(failureCode || "unknown")
    for (var i = 0; i < alerts.length; i++) {
        if (alerts[i].alertId === String(alertId) && alerts[i].state === "active")
            return "unknown"
    }
    return ""
}

// Whether a diagnostics snapshot in the launch-context shape is the service's
// own answer, as opposed to a placeholder or preview content.
function diagnosticsSnapshotIsLive(snapshot) {
    return !!snapshot && snapshot.origin === "service" && snapshot.stale !== true
}

// What to do with a request to re-read the diagnostics snapshot: "read",
// "queue" it behind the read in flight, or "skip" it. Only a page-open request
// (`forced` false) is throttled, and only by the last LIVE answer: a failed
// read leaves the next opening free to try again.
function diagnosticsReadDecision(inFlight, forced, lastLiveAtMs, nowMs, throttleMs) {
    if (inFlight) return "queue"
    if (forced) return "read"
    var last = Number(lastLiveAtMs) || 0
    // A clock set back must not hold the page on old data until it catches up.
    if (last > 0 && nowMs >= last && nowMs - last < throttleMs) return "skip"
    return "read"
}

function _nullIfAbsent(value) {
    return value === undefined ? null : value
}

// `current` (launch-context shape) with its cards replaced from a
// `snapshot.diagnostics.get` status; null when the status is no live answer,
// so a failed or stale read never wipes what is shown. The alert fields are
// kept: the alert list is the window's own state, merged separately.
function diagnosticsSnapshotMerged(current, status) {
    if (!status || status.stale === true || status.origin === "unavailable") return null
    var health = status.service_health || {}
    var security = status.security_status || {}
    var cache = status.cache_health || {}
    var logs = status.log_health || {}
    var next = {}
    var base = current || {}
    for (var key in base) next[key] = base[key]
    next.overallHealthy = status.overall_healthy === true
    next.stale = false
    next.origin = String(status.origin || "service")
    next.serviceHealth = {
        state: String(health.state || ""),
        activeRevisionId: _nullIfAbsent(health.active_revision_id),
        pendingChanges: Number(health.pending_changes || 0),
        startRelativeToSignIn: String(health.start_relative_to_sign_in || "unknown"),
        startSignInGapMs: _nullIfAbsent(health.start_sign_in_gap_ms)
    }
    next.securityStatus = {
        auditChainOk: security.audit_chain_ok === true,
        activeAlertCount: Number(security.active_alert_count || 0),
        auditWriteHealthy: security.audit_write_healthy === true
    }
    next.cacheHealth = {
        entryCount: Number(cache.entry_count || 0),
        healthy: cache.healthy === true
    }
    next.logHealth = {
        dirWritable: logs.dir_writable === true,
        totalSizeBytes: Number(logs.total_size_bytes || 0),
        auditSizeBytes: Number(logs.audit_size_bytes || 0),
        fileCount: Number(logs.file_count || 0),
        droppedCount: Number(logs.dropped_count || 0),
        lastCleanupAt: _nullIfAbsent(logs.last_cleanup_at)
    }
    return next
}

// Storage and audit-chain view of Settings -> Diagnostics and logs, read from
// the window's diagnostics snapshot. A card the snapshot lacks yields an empty
// object, which the page draws exactly as it drew a missing launch-context key.
function diagnosticsStorageView(snapshot) {
    var logs = snapshot ? snapshot.logHealth : null
    var security = snapshot ? snapshot.securityStatus : null
    return {
        storageHealth: logs ? {
            logsSizeBytes: logs.totalSizeBytes,
            auditSizeBytes: logs.auditSizeBytes,
            logFileCount: logs.fileCount,
            droppedEvents: logs.droppedCount,
            lastCleanup: logs.lastCleanupAt,
            dirWritable: logs.dirWritable
        } : {},
        auditChain: security ? { verified: security.auditChainOk } : {}
    }
}

// The verdict of re-previewing a confirmed change: "" when it took effect
// (`unchanged(summary)` holds), the refusal code when the service refuses it,
// "unknown" otherwise.
function previewOutcome(summary, unchanged) {
    var refusal = previewRefusal(summary)
    if (refusal) return refusal.code
    return unchanged(summary) ? "" : "unknown"
}

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
// Main-link probing keys are listed here for the same reason as every other
// field: a request that omits a key sends its default, so a panel writing ANY
// key would otherwise reset the ones it does not mention.
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
    "auto-rules-eager-delivery-names": false,
    "primary-probe-auto": false,
    "primary-probe-timeout-ms": 1500,
    "primary-probe-max-targets": 8,
    "primary-probe-repeat-secs": 300,
    "local-networks-auto-accept": false,
    "zone-priority-over-ip": false,
    "short-name-completion": false,
    "short-name-suffix": ""
}

// Keys the policy SNAPSHOT carries but the update REQUEST must not: they are
// written through their own dedicated operation and the request DTO has no
// field for them.
var ROUTE_POLICY_SNAPSHOT_ONLY_KEYS = ["secondary-link-provider-apps"]

// Bit masks for the numeric wire fields (the protocol bitmask is the only one).
// A masked value is a selection only when it sets a bit that blocks something
// and nothing outside its mask, the rule of
// `nrr_shared::ipc_payloads::is_valid_kill_switch_protocols`; anything else
// reads as the default rather than being masked into meaning.
// `enforced` are the bits that block something: "Other" (64) blocks nothing.
var KILL_SWITCH_PROTOCOLS_ENFORCED = 0x3F
var ROUTE_POLICY_FIELD_MASKS = {
    "kill-switch-protocols": { all: 0x7F, enforced: KILL_SWITCH_PROTOCOLS_ENFORCED }
}

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
        if (mask === undefined) return n
        return ((n & mask.enforced) === 0 || (n & ~mask.all) !== 0) ? def : n
    }
    return String(raw)
}

// Whether the protocol box `bit` must stay ticked: it is the last one that
// blocks something (the stored "other" bit has no box and blocks nothing), and
// the service refuses a selection that blocks nothing. Leak protection is switched off by its own toggle, not
// by unticking every protocol.
function killSwitchProtocolLocked(mask, bit) {
    var m = routePolicyCoerce("kill-switch-protocols", mask) & KILL_SWITCH_PROTOCOLS_ENFORCED
    return (m & bit) !== 0 && (m & ~bit) === 0
}

// Whether one blocking protocol is left, i.e. its box is locked.
function killSwitchProtocolsAtLastOne(mask) {
    var m = routePolicyCoerce("kill-switch-protocols", mask) & KILL_SWITCH_PROTOCOLS_ENFORCED
    return m !== 0 && (m & (m - 1)) === 0
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

// ---- adapter bindings: the service's view against the app's own ----

// The two slots the app and the service each store, and the prefs keys that
// hold them here. One declaration so the seed, the disagreement report and the
// "take the service's side" answer cannot drift apart.
var ROUTE_BINDING_SLOTS = [
    { role: "primary", id: "selectedPrimaryInterfaceId",
      name: "selectedPrimaryInterfaceName", confirmed: "primaryRoleUserConfirmed" },
    { role: "secondary", id: "selectedSecondaryInterfaceId",
      name: "selectedSecondaryInterfaceName", confirmed: "secondaryRoleUserConfirmed" }
]

// One slot of a policy snapshot as `{ id, name, confirmed }`, or `null` when
// the service holds nothing there.
function routeBindingFromSnapshot(cur, role) {
    var b = (cur || {})[role]
    if (!b || typeof b !== "object") return null
    var id = String(b["stable-id"] || "")
    var name = String(b["display-name"] || "")
    if (id === "" && name === "") return null
    var known = b["known-stable-ids"]
    return {
        id: id !== "" ? id : name,
        name: name !== "" ? name : id,
        confirmed: b["user-confirmed"] === true,
        knownIds: Array.isArray(known) ? known.map(String) : []
    }
}

// The service re-matched a reinstalled adapter and still lists the app's id
// among the binding's earlier ones: the app holds a stale copy of the SAME
// choice, not a different one, so it follows without asking.
function routeBindingIsHealOf(myId, theirs) {
    if (myId === "" || theirs === null) return false
    var mine = myId.toLowerCase()
    if (mine === theirs.id.toLowerCase()) return false
    for (var i = 0; i < theirs.knownIds.length; i++)
        if (theirs.knownIds[i].toLowerCase() === mine) return true
    return false
}

// Prefs patch that adopts every slot the service healed from the app's id;
// empty when there is nothing to follow.
function routeBindingHealPatch(prefs, cur) {
    var p = prefs || {}
    var patch = {}
    for (var i = 0; i < ROUTE_BINDING_SLOTS.length; i++) {
        var slot = ROUTE_BINDING_SLOTS[i]
        var theirs = routeBindingFromSnapshot(cur, slot.role)
        if (!routeBindingIsHealOf(String(p[slot.id] || ""), theirs)) continue
        patch[slot.id] = theirs.id
        patch[slot.name] = theirs.name
    }
    return patch
}

// What to do with the binding the service reports, given what the app holds.
// The service is the one that enforces, so its answer fills a slot the app has
// none for -- but a slot the user picked is NEVER overwritten from a snapshot,
// because only the user knows which of the two is the stale one. A slot that
// disagrees is reported instead.
//
// Returns `{ patch, divergence }`: `patch` is a prefs patch to apply as-is
// (empty = nothing to seed), `divergence` is `{ role, mine, service }` rows for
// the banner that asks.
function routeBindingSeedPlan(prefs, cur) {
    var p = prefs || {}
    var patch = {}
    var divergence = []
    var firstSeed = false
    for (var i = 0; i < ROUTE_BINDING_SLOTS.length; i++) {
        var slot = ROUTE_BINDING_SLOTS[i]
        var theirs = routeBindingFromSnapshot(cur, slot.role)
        if (theirs === null) continue
        var myId = String(p[slot.id] || "")
        var myName = String(p[slot.name] || "")
        if (myId === "" && myName === "") {
            patch[slot.id] = theirs.id
            patch[slot.name] = theirs.name
            patch[slot.confirmed] = theirs.confirmed
            firstSeed = true
            continue
        }
        if (myId !== "" && myId === theirs.id) {
            // Same adapter, fresher label: the service caches the display name
            // at write time and an adapter can be renamed between runs.
            if (theirs.name !== myName) patch[slot.name] = theirs.name
            continue
        }
        if (routeBindingIsHealOf(myId, theirs)) {
            patch[slot.id] = theirs.id
            patch[slot.name] = theirs.name
            continue
        }
        divergence.push({
            role: slot.role,
            mine: myName !== "" ? myName : myId,
            service: theirs.name
        })
    }
    // The behaviour mode rides along with a FIRST seed only. Prefs always carry
    // a mode, so comparing it would report a disagreement on every start where
    // the user simply never touched the setting.
    if (firstSeed) {
        var mode = String((cur || {})["mode"] || "")
        if (mode !== "") patch.routeBehaviorMode = mode
    }
    return { patch: patch, divergence: divergence }
}

// The user answered a disagreement with "keep what the service applies": every
// slot the snapshot holds replaces the app's own. The opposite answer needs no
// patch -- it pushes what prefs already say.
function routeBindingAdoptPatch(cur) {
    var patch = {}
    for (var i = 0; i < ROUTE_BINDING_SLOTS.length; i++) {
        var slot = ROUTE_BINDING_SLOTS[i]
        var theirs = routeBindingFromSnapshot(cur, slot.role)
        if (theirs === null) continue
        patch[slot.id] = theirs.id
        patch[slot.name] = theirs.name
        patch[slot.confirmed] = theirs.confirmed
    }
    var mode = String((cur || {})["mode"] || "")
    if (mode !== "") patch.routeBehaviorMode = mode
    return patch
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

// Is this domain value itself a public suffix -- a registry under which
// unrelated organisations hold their own names (`co.uk`, `com.br`, and every
// bare TLD)? A suffix rule over one of those routes strangers, not a service,
// which is what the `zone` rule type is for.
function isPublicSuffixValue(value) {
    var host = String(value || "").toLowerCase().replace(/^\*\./, "").replace(/\.$/, "")
    if (host === "" || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return false
    var labels = host.split(".")
    if (labels.length === 1) return true
    return labels.length === 2 && !!AUTO_RULE_MULTI_LABEL_SUFFIXES[host]
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

// Whose name the offer is, as three states. The service omits the field when
// the offer has no anchor site to be third-party TO, and collapsing that to
// `false` is what made an ad host read as one of the site's own names.
// `undefined` -- the question was not posed.
function autoRuleRowThirdParty(row) {
    var raw = row["third-party"] !== undefined ? row["third-party"] : row.thirdParty
    if (raw === undefined || raw === null) return undefined
    return raw === true
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
/// Does the suggestions list show this offer without being asked to show more?
///
/// The service decides (`served-by-main-link`, the rule behind its counts);
/// every window reads that one mark — list, group caption, tray popup — so no
/// surface offers or counts a row another one hides. Takes a wire row or a
/// grouped host.
function autoRuleShownByDefault(row) {
    return !(row && (row["served-by-main-link"] === true || row.servedByMainLink === true))
}

/// The wire rows a window may offer unasked: what the tray popup chooses from.
function autoRuleRowsShownByDefault(rows) {
    return (rows || []).filter(function(row) { return !!row && autoRuleShownByDefault(row) })
}

/// Pending hosts a group card lists after the list's filters: its caption.
function countShownPendingAutoRuleHosts(group) {
    var n = 0
    var hosts = (group || {}).hosts || []
    for (var h = 0; h < hosts.length; h += 1) {
        if (hosts[h] && hosts[h].status === "pending") n += 1
    }
    return n
}

/// Split off the hosts the main route already serves.
///
/// The service withholds these from the tray and marks them here. They are not
/// wrong — they are just not work: the site pulling them reaches them without a
/// tunnel. Shown behind a toggle rather than dropped, so the answer to "why
/// isn't this host in the list" is visible instead of absent.
///
/// A group whose hosts are ALL served disappears from the main list; a mixed
/// group keeps the hosts that still carry a question. The id lists shrink with
/// the hosts: the card's buttons act on what the card shows, never on a host
/// the user cannot see.
function filterAutoRuleGroupsServedByMainLink(groups, showServed) {
    if (showServed) return groups || []
    var out = []
    for (var i = 0; i < (groups || []).length; i += 1) {
        var g = groups[i]
        if (!g) continue
        var hosts = []
        var pendingIds = []
        var dismissedIds = []
        for (var h = 0; h < (g.hosts || []).length; h += 1) {
            var host = g.hosts[h]
            if (!host || !autoRuleShownByDefault(host)) continue
            hosts.push(host)
            if (host.status === "pending") pendingIds.push(host.id)
            else dismissedIds.push(host.id)
        }
        if (hosts.length === 0) continue
        var copy = Object.assign({}, g)
        copy.hosts = hosts
        copy.pendingIds = pendingIds
        copy.dismissedIds = dismissedIds
        out.push(copy)
    }
    return out
}

/// How many hosts the toggle above is hiding.
function countAutoRuleHostsServedByMainLink(groups) {
    var n = 0
    for (var i = 0; i < (groups || []).length; i += 1) {
        var hosts = (groups[i] || {}).hosts || []
        for (var h = 0; h < hosts.length; h += 1) {
            if (hosts[h] && !autoRuleShownByDefault(hosts[h])) n += 1
        }
    }
    return n
}

/// Split the merged suggestion groups by status.
///
/// The inbox is a list of things to answer; an address already answered with
/// "don't suggest again" is history, and mixing the two made a screen of ten
/// decisions look like a screen of forty. `showDismissed` false keeps only the
/// groups that still hold something pending, and hides the answered hosts
/// inside them.
function filterAutoRuleGroupsByStatus(groups, showDismissed) {
    if (showDismissed) return groups || []
    var out = []
    for (var i = 0; i < (groups || []).length; i += 1) {
        var g = groups[i]
        if (!g || (g.pendingIds || []).length === 0) continue
        var hosts = []
        for (var h = 0; h < (g.hosts || []).length; h += 1) {
            if (g.hosts[h] && g.hosts[h].status === "pending") hosts.push(g.hosts[h])
        }
        var copy = Object.assign({}, g)
        copy.hosts = hosts
        copy.dismissedIds = []
        out.push(copy)
    }
    return out
}

/// How many answered ("don't suggest again") hosts the merged groups hold.
function countDismissedAutoRuleHosts(groups) {
    var total = 0
    for (var i = 0; i < (groups || []).length; i += 1) {
        total += ((groups[i] || {}).dismissedIds || []).length
    }
    return total
}

function groupAutoRuleRows(candidates, dismissed) {
    var byDomain = {}
    var order = []

    function addLeaf(row, status) {
        var match = String(row["proposed-match"] || row.proposedMatch || "")
        if (match === "") return
        // A program is its own group: a file name has no registrable domain.
        var isApp = String(row["match-kind"] || row.matchKind || "") === "application"
        var domain = isApp ? match : registrableDomain(match)
        var group = byDomain[domain]
        if (!group) {
            group = { domain: domain, isApp: isApp, hosts: [], pendingIds: [], dismissedIds: [],
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
            anchorRefusesMainLink: (row["anchor-refuses-main-link"] === true)
                || (row.anchorRefusesMainLink === true),
            servedByMainLink: !autoRuleShownByDefault(row),
            thirdParty: autoRuleRowThirdParty(row),
            observedMembers: (row["observed-members"] || row.observedMembers || []).map(String),
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
            isApp: g.isApp === true,
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
/// Where a group belongs when sorting by what the main route does with it:
/// 0 = at least one address does not open there, 1 = nothing checked yet,
/// 2 = the main route reaches every address in the group.
///
/// "Reaches" is deliberately not read as "you don't need this": a site can
/// complete the connection and answer with a refusal. It only decides ORDER.
function autoRuleGroupMainRouteRank(group) {
    var hosts = (group || {}).hosts || []
    var rank = 2
    for (var i = 0; i < hosts.length; i += 1) {
        var behavior = String(hosts[i].primaryBehavior || "")
        if (behavior === "stalls") return 0
        if (behavior !== "responds") rank = Math.min(rank, 1)
    }
    return rank
}

function sortAutoRuleGroups(groups, mode) {
    var out = groups.slice()
    out.sort(function(a, b) {
        if (mode === "main-route") {
            var r = autoRuleGroupMainRouteRank(a) - autoRuleGroupMainRouteRank(b)
            if (r !== 0) return r
            var dn = b.latestMs - a.latestMs
            return dn !== 0 ? dn : a.domain.localeCompare(b.domain)
        }
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

// ---- plural forms and block-notice grouping ----

// CLDR plural category of a whole number under a named rule FAMILY. The
// locale file names its family (`label.plural-rule`), so a language added as
// a file needs no code here; an unknown family counts like English.
function pluralCategory(rule, n) {
    var k = Math.abs(Math.floor(Number(n) || 0))
    switch (String(rule || "")) {
        case "east-slavic":
            var d = k % 10
            var h = k % 100
            if (d === 1 && h !== 11) return "one"
            if (d >= 2 && d <= 4 && (h < 12 || h > 14)) return "few"
            return "many"
        case "none":
            return "other"
        default:
            return k === 1 ? "one" : "other"
    }
}

// Rows of a block notice, in arrival order. Blocks of one program for one
// reason fold into a single row when the reason is `groupable` (the answer
// is about the program or a switch, not the address); every other block
// keeps a row per address, because routing is decided address by address.
function groupBlockNotices(entries, groupableReasons) {
    var rows = []
    var byKey = {}
    for (var i = 0; i < (entries || []).length; i += 1) {
        var e = entries[i] || {}
        var app = String(e.app || "")
        var reason = String(e.reason || "")
        var groupable = app !== "" && (groupableReasons || []).indexOf(reason) >= 0
        var key = groupable
            ? "g|" + app.toLowerCase() + "|" + reason
            : "a|" + String(e.destination || "") + "|" + app.toLowerCase() + "|" + reason
        if (byKey[key] === undefined) {
            byKey[key] = rows.length
            rows.push({ key: key, grouped: groupable, entries: [] })
        }
        rows[byKey[key]].entries.push(e)
    }
    return rows
}
