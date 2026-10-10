.pragma library

// Pure rule-model transforms: signatures, canonical-id normalization, and
// wire-DTO builders that depend only on their arguments.
//
// Contract (same discipline as lib/pure.js): every function here takes plain
// values / rulesModel-shaped row objects and returns a value. NO access to the
// C++ bridge (nrrNativeBridge), QML ids, `tr`, or any window state — a
// `.pragma library` scope has none of those, and keeping it that way is the
// guarantee against this file quietly growing coupling. Punycode/ACE encoding
// goes through the bridge, so `ruleRowToWireDto` takes the encoder as a
// CALLBACK instead of reaching for it — the transform stays in the window, the
// serialization stays here.
//
// Row shape (subset used here): { id, ruleType, matchValue, targetRoute,
// verify, enabled, comment }. Besides the two adapter routes, `targetRoute`
// can be "block" (drop), which lives in the secondary bucket. `verify` is the
// `?`: the rule works where it is written, and the service offers to move it
// when only the other link reaches it.

// The secondary bucket a block rides in; an adapter route is its own.
function routeBucket(targetRoute) {
    var t = String(targetRoute || "")
    return t === "block" ? "secondary" : t
}

// `?` fits a host name or one address: the rules file reads it in those
// sections only.
function ruleTypeAllowsVerify(ruleType) {
    var rt = String(ruleType || "")
    return rt === "domain" || rt === "suffix-domain" || rt === "exact-fqdn"
        || rt === "exact-ip" || rt === "exact-ipv4" || rt === "exact-ipv6"
}

// The `?` a row actually carries: a route rule of a type that takes it. A
// block or another type drops it.
function rowIsVerify(row) {
    if (!row || row.verify !== true) return false
    var t = String(row.targetRoute || "")
    return (t === "primary" || t === "secondary") && ruleTypeAllowsVerify(row.ruleType)
}

// The preset format version this build writes. Mirrors
// `nrr_domain::rules_file::CURRENT_RULES_FILE_FORMAT_VERSION`; the Rust test
// `the_gui_writes_the_current_preset_format_version` reads this line and fails
// when the two drift.
var CANONICAL_PRESET_FORMAT_VERSION = 7

// True for the rule types whose match value is a hostname (so callers know to
// apply host-specific handling such as ACE encoding at the wire boundary).
function isHostlikeRuleType(ruleType) {
    var rt = String(ruleType || "")
    return rt === "zone" || rt === "domain"
        || rt === "suffix-domain" || rt === "exact-fqdn"
}

// A URL copied from a browser reduced to its bare host, for the hostname
// types only and only when the text has URL punctuation, so typing a plain
// hostname is never disturbed. Broad-match types also drop a leading `www.`;
// `exact-fqdn` keeps it, since there the exact host is the point.
function normalizeHostInput(ruleType, raw) {
    if (!isHostlikeRuleType(ruleType)) return raw
    var s = String(raw || "")
    if (!/[:\/@?#]/.test(s)) return raw
    s = s.replace(/^[A-Za-z][A-Za-z0-9\u0080-\uFFFF-]*:\/\//, "") // scheme://
    s = s.replace(/^[^@\/]*@/, "")                        // user:pass@
    s = s.replace(/[\/?#].*$/, "")                        // path/query/fragment
    s = s.replace(/:\d+$/, "")                            // :port
    s = s.toLowerCase()
    if (ruleType === "domain" || ruleType === "suffix-domain") {
        s = s.replace(/^www\./, "")
    }
    return s
}

// The one spelling of a rule-type slug. `suffix-domain` and `domain` describe
// the same wire-level kind, as do `exact-ipv4` and `exact-ip`; which spelling a
// row carries depends only on where it came from (service snapshot vs the edit
// dialog). Every identity built from a type has to fold them, or the same rule
// exists twice under two names.
function canonicalRuleTypeSlug(ruleType) {
    var t = String(ruleType || "").toLowerCase()
    if (t === "suffix-domain") return "domain"
    if (t === "exact-ipv4" || t === "exact-ipv6") return "exact-ip"
    return t
}

// Dedup key for import-merge: two rows collide when their type, lowercased
// match value, and target route all match; `?` is no part of it. The type is folded first — without
// that, importing `suffix-domain|site.example` next to `domain|site.example` kept both,
// and the two then shared one comment row in the sidecar.
function mergeKey(row) {
    return canonicalRuleTypeSlug(row.ruleType) + "|" +
        String(row.matchValue || "").toLowerCase() + "|" +
        String(row.targetRoute || "")
}

// Normalize a rule id to canonical `R-NNNN` (4-digit, zero-padded) form.
// Non-matching ids are upper-cased and returned as-is.
function canonicalRuleId(id) {
    var s = String(id || "").trim().toUpperCase()
    if (s === "") return ""
    var m = s.match(/^R-(\d+)$/)
    if (!m) return s
    var n = parseInt(m[1], 10)
    if (isNaN(n)) return s
    return "R-" + ("0000" + String(n)).slice(-4)
}

// Content-only signature for a rules-model row (secondary duplicate-detection
// axis). Normalises type-slug aliases so `suffix-domain` == `domain` and
// `exact-ipv4` == `exact-ip` — they describe the same wire-level rule kind but
// appear under different slugs depending on origin (snapshot vs edited dialog).
// Order: type|route|value.
function ruleSignature(row) {
    var t = canonicalRuleTypeSlug(row.ruleType)
    return t + "|"
        + String(row.targetRoute || "").toLowerCase() + "|"
        + String(row.matchValue || "").toLowerCase()
}

// Canonical (type, value, route) tuple the sidecar RPC layer expects. Distinct
// from `ruleSignature`: Rust `RuleSignature::build` orders the components
// type|value|route (NOT type|route|value) and only lowercases the value
// internally. We normalise the type-slug aliases before the call so two paths
// producing the same rule intent land on the same sidecar row.
function sidecarRuleSignatureParts(row) {
    if (!row) return { type: "", value: "", route: "" }
    var t = canonicalRuleTypeSlug(row.ruleType)
    var r = String(row.targetRoute || "").toLowerCase()
    return {
        type:  t,
        value: String(row.matchValue || ""),
        route: r
    }
}

// String-form sidecar signature for client-side lookup against the
// `sidecar.comment.read-all` response map. MUST stay byte-identical to Rust
// `RuleSignature::build(type, value, route)` for the lookup to hit — Rust
// lowercases every codepoint of the value; we mirror that here.
function sidecarRuleSignatureString(row) {
    var p = sidecarRuleSignatureParts(row)
    return p.type + "|" + p.value.toLowerCase() + "|" + p.route
}

// ---- canonical rules-file (docs/en/rules-file-format.md) text ----

// The application section of `os` (`PlatformProfile.os`): the only one the
// parser on that OS applies. The profile names no other OS.
function appSectionHeader(os) {
    if (os === "linux") return "Linux"
    if (os === "macos") return "MacOS"
    return "Windows"
}

// Map a rules-model rule-type slug to its canonical docs/en/rules-file-format.md section header.
// Types we don't know about return "" and the rule is skipped, mirroring what
// the parser does on the way in.
function ruleTypeToSection(ruleType, os) {
    var rt = String(ruleType || "")
    if (rt === "zone") return "Zones"
    if (rt === "domain" || rt === "suffix-domain" || rt === "exact-fqdn") return "Domains"
    if (rt === "exact-ip" || rt === "exact-ipv4" || rt === "exact-ipv6") return "IP"
    if (rt === "subnet") return "CIDR"
    if (rt === "ip-range") return "Ranges"
    if (rt === "application") return appSectionHeader(os)
    return ""
}

// A line break or other control character inside one field would start a line
// the parser reads as a rule or section of its own. The service refuses them;
// this is the backstop, matching `neutralize_field` in the Rust writer.
function oneLineField(value) {
    return String(value || "").replace(/[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/g, " ")
}

// THE canonical-txt writer: walks the rules model, filters by `route`, groups
// rules into their docs/en/rules-file-format.md sections and emits the text shape
// `nrr_shared::preset_parser` accepts. It is the ONLY generator behind every
// save path (export picker, "Save to file" chip, save-before-close, the
// close-time Save As), which is what makes saving rules work with the service
// stopped — the bytes come from the table in front of the user, never from a
// service round-trip.
//
// `rulesModel` is anything exposing `count` + `get(i)` (a QML ListModel), so a
// `.pragma library` scope can consume it without reaching for window state.
// Host values are stored in Unicode form (the preset-format convention); the
// GUI <-> service boundary ACE-encodes separately, on the wire side.
// `includeComments` defaults to true — the Save-As option flow passes false to
// strip ` # comment` suffixes, which only changes the file shape (comments
// live in the sidecar either way). `os` is the `PlatformProfile.os` the file is
// written on; application rules go under its section.
function buildCanonicalRulesText(rulesModel, route, passthroughSections, includeComments, os) {
    var emitComments = (includeComments === undefined) ? true : !!includeComments
    var appSection = appSectionHeader(os)
    var sections = { Zones: [], Domains: [], Auto: [], IP: [], CIDR: [], Ranges: [] }
    sections[appSection] = []
    if (rulesModel) {
        for (var i = 0; i < rulesModel.count; i += 1) {
            var row = rulesModel.get(i)
            if (!row) continue
            // A block rides in the secondary file marked by `+block`; a `?`
            // rule is marked before the value in its own file.
            var rowRoute = String(row.targetRoute || "")
            if (routeBucket(rowRoute) !== String(route)) continue
            var section = ruleTypeToSection(row.ruleType, os)
            if (section === "" || !sections.hasOwnProperty(section)) continue
            // An app-authored rule keeps its provenance across the file: it
            // moves to `--- Auto` and carries the structured inline comment the
            // parser reads it back from. Only domain-shaped rules qualify —
            // that section parses as domains, so anything else stays put
            // (losing the badge beats corrupting the rule).
            var originReason = String(row.originReason || "")
            var isAuto = originReason !== "" && section === "Domains"
            if (isAuto) section = "Auto"
            var line = oneLineField(row.matchValue).trim()
            if (line === "") continue
            if (rowIsVerify(row)) line = "?" + line
            if (rowRoute === "block") line += " +block"
            if (!row.enabled) line = "# " + line
            var c = emitComments ? oneLineField(row.comment).trim() : ""
            if (isAuto) {
                // Provenance travels even when user comments are stripped:
                // without these tokens the rule is indistinguishable from one
                // the user typed on the next import.
                var tokens = "auto:" + oneLineField(originReason)
                var anchor = oneLineField(row.originAnchor).trim()
                if (anchor !== "") tokens += " anchor:" + anchor
                var added = oneLineField(row.originAdded).trim()
                if (added !== "") tokens += " added:" + added
                line += "          # " + tokens + (c !== "" ? " " + c : "")
            } else if (c !== "") {
                line += "          # " + c
            }
            sections[section].push(line)
        }
    }
    var nameLabel = (route === "secondary") ? "Secondary Route" : "Primary Route"
    var lines = []
    // A header claiming an older version tells the next reader the newer
    // sections are not there; see CANONICAL_PRESET_FORMAT_VERSION.
    lines.push("# NetRuleRouter preset — version " + CANONICAL_PRESET_FORMAT_VERSION)
    lines.push("# name: NetRuleRouter Export - " + nameLabel)
    lines.push("# description: Exported from the NetRuleRouter app on "
        + (new Date()).toISOString())
    lines.push("# preset_version: 1")
    lines.push("")
    // The canonical section order the Rust writer emits
    // (`nrr_domain::rules_file::RulesFileSection::ALL`).
    var order = ["Zones", "Domains", "IP", "CIDR", "Ranges", appSection, "Auto"]
    for (var s = 0; s < order.length; s += 1) {
        var key = order[s]
        lines.push("--- " + key)
        var bucket = sections[key]
        for (var b = 0; b < bucket.length; b += 1) lines.push(bucket[b])
        lines.push("")
    }
    // Foreign-OS app rules and unsupported sections captured at the previous
    // import ride through untouched. Section names are emitted alphabetically
    // so the output does not depend on object-key iteration order.
    if (passthroughSections) {
        var ptNames = []
        for (var n in passthroughSections) {
            if (passthroughSections.hasOwnProperty(n)) ptNames.push(n)
        }
        ptNames.sort()
        for (var pi = 0; pi < ptNames.length; pi += 1) {
            var name = ptNames[pi]
            lines.push("--- " + name)
            // The sidecar normalises raw_text to end in exactly one newline
            // when non-empty; splitting yields the section's lines plus a
            // trailing empty entry we drop.
            var rawText = String(passthroughSections[name] || "")
            if (rawText !== "") {
                var rawLines = rawText.split("\n")
                if (rawLines.length > 0 && rawLines[rawLines.length - 1] === "") rawLines.pop()
                for (var rl = 0; rl < rawLines.length; rl += 1) lines.push(rawLines[rl])
            }
            lines.push("")
        }
    }
    return lines.join("\n")
}

// The part of a canonical rules file that carries routing meaning: everything
// past the leading `# ...` metadata block. Comparing bodies (not bytes) is
// what lets "is the linked file still up to date?" be answered locally — the
// metadata's `# description:` line embeds the export timestamp, so two files
// holding identical rules differ on every regeneration.
function canonicalRulesBody(text) {
    var lines = String(text || "").split(/\r?\n/)
    var i = 0
    while (i < lines.length) {
        var t = lines[i].replace(/\s+$/, "")
        if (t === "" || t.charAt(0) === "#") { i += 1; continue }
        break
    }
    var body = lines.slice(i)
    while (body.length > 0 && body[body.length - 1].replace(/\s+$/, "") === "") body.pop()
    return body.join("\n")
}

// Map a host match value to its canonical address-match DTO, honoring the `*.`
// prefix the service round-trips for suffix rules. The service emits BOTH host
// kinds under rule-type "domain", distinguished only by the prefix —
// ("domain","*.video.example") for SuffixDomain and ("domain","video.example") for
// ExactFqdn — so every rules-json builder must decode it here. Skipping this
// collapses `*.video.example` into a dead ExactFqdn (a literal that matches no
// host).
function hostAddressMatchDto(value) {
    var v = String(value || "")
    if (v.indexOf("*.") === 0) {
        return { kind: "suffix-domain", suffix: v.substring(2) }
    }
    return { kind: "exact-fqdn", value: v }
}

// A range row reads `first-last`; neither family's address text has a `-`.
// A value without one keeps all of it in `first`, so the service refuses it
// by name instead of the GUI dropping it.
function ipRangeAddressMatchDto(value) {
    var v = String(value || "")
    var dash = v.indexOf("-")
    if (dash < 0) return { kind: "ip-range", first: v.trim(), last: "" }
    return { kind: "ip-range", first: v.substring(0, dash).trim(),
        last: v.substring(dash + 1).trim() }
}

// THE rules-model row -> canonical wire DTO mapper. Single serializer for every
// caller: the Rules-section "Save and review", the window-level apply payload,
// and the drift hasher. Per-caller copies risk diverging on fields like
// `comment`, which would show every rule carrying an inline preset comment as
// "modified" in a dry-run that changed nothing.
//
// `aceEncodeHost` is a callback because ACE/Punycode encoding goes through the
// C++ bridge, which a `.pragma library` scope cannot reach (see the file header).
// Pass `null` to skip encoding. Host-like values (`zone` / `domain` /
// `suffix-domain` / `exact-fqdn`) are the only ones routed through it. The
// service normalises zones to Punycode itself now, so this is a
// compatibility path rather than a correctness requirement — but the two sides
// must agree byte-for-byte or the canonical hash diverges.
//
// `opts`:
//   keepId      — false emits `id: ""`. Drift hashing needs this: the launcher
//                 (file parse) and the service (import) assign DIFFERENT ids to
//                 the same rules, so a real id makes semantically identical rule
//                 sets hash differently. Defaults to true.
//   keepComment — false omits `comment`. Drift hashing needs this too: a note
//                 the user typed is not a routing change. Defaults to true.
//
// Field order matches the Rust `RuleDto` declaration order
// (id, enabled, comment, address-match | app-match, action) — the canonical
// JSON is order-sensitive.
function ruleRowToWireDto(row, aceEncodeHost, opts) {
    var options = opts || {}
    var dto = {
        id: (options.keepId === false) ? "" : String(row.id || ""),
        enabled: !!row.enabled
    }
    if (options.keepComment !== false && row.comment) dto.comment = String(row.comment)
    var value = String(row.matchValue || "")
    if (isHostlikeRuleType(row.ruleType) && typeof aceEncodeHost === "function") {
        value = String(aceEncodeHost(value) || value)
    }
    // `FreeRuleType::Domain.slug()` → "domain" on snapshot rows, but the
    // canonical rules-json wire kind is "suffix-domain"; accept both so a row
    // freshly loaded from a snapshot doesn't fall through to the default
    // ("exact-fqdn") arm. Same for "exact-ip" ↔ "exact-ipv4".
    switch (String(row.ruleType || "")) {
        case "exact-fqdn":
            dto["address-match"] = { kind: "exact-fqdn", value: value }
            break
        case "suffix-domain":
            dto["address-match"] = { kind: "suffix-domain",
                suffix: (value.indexOf("*.") === 0 ? value.substring(2) : value) }
            break
        case "zone":
            dto["address-match"] = { kind: "zone", name: value }
            break
        case "exact-ip":
        case "exact-ipv4":
        case "exact-ipv6":
            // The address names its own family: only IPv6 text has a colon.
            dto["address-match"] = {
                kind: value.indexOf(":") >= 0 ? "exact-ipv6" : "exact-ipv4",
                address: value
            }
            break
        case "subnet":
            dto["address-match"] = { kind: "subnet", network: value.trim() }
            break
        case "ip-range":
            dto["address-match"] = ipRangeAddressMatchDto(value)
            break
        case "application":
            // A `*` makes it a pattern, exactly as the preset parser reads it.
            // Emitting `exact` for `disko*.exe` stored a filename no process can
            // ever have, so the rule matched nothing at all.
            dto["app-match"] = {
                pattern: {
                    kind: value.indexOf("*") >= 0 ? "glob" : "exact",
                    value: value
                },
                "include-child-processes": false
            }
            break
        case "domain":
        default:
            // "domain" is the round-trip slug for BOTH host kinds; decode the
            // `*.` prefix so wildcard rules don't die as exact-fqdn.
            dto["address-match"] = hostAddressMatchDto(value)
    }
    // A block or `?` row carries the per-rule action; route rows omit it so
    // their canonical bytes/hash stay identical to the pre-block format.
    var rowRoute = String(row.targetRoute || "")
    if (rowRoute === "block") dto.action = "block"
    else if (rowIsVerify(row)) dto.action = "verify-primary"
    // Provenance of an app-authored rule travels back to the service, or the
    // first apply the user makes for any OTHER reason silently rewrites every
    // auto-rule as one they typed (badge gone, "why is this here?" back).
    // Tied to `keepComment`: like a comment it is metadata, not a routing
    // change, so the drift hash — which compares a file parse against the
    // service and must not see one — leaves it out. Emitted last, matching the
    // Rust `RuleDto` declaration order (the canonical JSON is order-sensitive).
    if (options.keepComment !== false && row.originReason
            && String(row.originReason) !== "") {
        dto.origin = {
            kind: "auto",
            reason: String(row.originReason),
            anchor: String(row.originAnchor || ""),
            added: String(row.originAdded || "")
        }
    }
    return dto
}

// ---- drift canonicalisation ----

// One-route canonical V1 envelope built from `rows`, in the exact shape the
// `local.canonical-rules-hash` RPC expects. The opposite route is emitted as an
// empty array, so a per-route hash only moves when THAT route changed.
//
// Rules are sorted by a stable, routing-semantic key. `to_canonical_string`
// deliberately does NOT re-sort, while a rules file and the service hand back
// the same set in different orders — without this, identical rules in a
// different order hash differently and raise a phantom "rules differ".
// `keepId`/`keepComment` are off for the same reason: the file parse and the
// service assign different ids, and a note the user typed is not a routing
// change.
//
// Shared by the window (file/app/service triangle) and the tray (file vs
// service while the window is closed) so both surfaces classify divergence
// from byte-identical inputs.
function buildDriftRulesJsonForRoute(rows, route, aceEncodeHost) {
    var primary = []
    var secondary = []
    for (var i = 0; i < rows.length; i += 1) {
        var r = rows[i]
        if (!r) continue
        // A block belongs to the secondary bucket (the service's canonical
        // placement), so drift and dirty signatures see it.
        if (routeBucket(r.targetRoute) !== String(route)) continue
        var dto = ruleRowToWireDto(r, aceEncodeHost,
            { keepId: false, keepComment: false })
        if (route === "secondary") secondary.push(dto)
        else primary.push(dto)
    }
    var byKey = function(a, b) {
        var ka = driftSortKey(a), kb = driftSortKey(b)
        return ka < kb ? -1 : (ka > kb ? 1 : 0)
    }
    primary.sort(byKey)
    secondary.sort(byKey)
    return JSON.stringify({
        "schema-version": 1,
        "primary":   primary,
        "secondary": secondary
    })
}

// Order-independent sort key for a drift DTO: id and comment are gone by the
// time we get here, so the key is built from routing semantics alone.
// Mirrors `comparison_key` in `nrr_shared::rules_json` part for part, and must
// name every field a drift DTO carries: a key that cannot tell two rules apart
// leaves their order — and the dirty/drift comparison — to input order.
// The separator is NUL rather than a space: an application rule's match value
// is a file path and can contain spaces.
function driftSortKey(d) {
    var sep = String.fromCharCode(0)
    var am = d["address-match"] || null
    var ap = d["app-match"] || null
    var pat = (ap && ap.pattern) || null
    var kind = am ? String(am.kind || "") : ""
    // A range reads `first-last`, as `AddressMatchDto::value_text` writes it.
    var val = !am ? ""
        : (am.first !== undefined) ? String(am.first || "") + "-" + String(am.last || "")
        : String(am.value || am.suffix || am.name || am.address || am.network || "")
    var appKind = pat ? "app:" + String(pat.kind || "") : ""
    var appVal = pat ? String(pat.value || "") : ""
    var children = (ap && ap["include-child-processes"]) ? "1" : "0"
    return kind + sep + val + sep + appKind + sep + appVal + sep
        + children + sep + (d.enabled ? "1" : "0") + sep
        + String(d.action || "route")
}

// Route-tagged routing signatures for a set of rows, one per rule. Built from
// the same normalisation the drift hashes use, so re-ordering, re-numbering or
// re-commenting the table produces the same list.
function ruleRoutingKeys(rows, aceEncodeHost) {
    var sep = String.fromCharCode(0)
    var keys = []
    for (var i = 0; i < rows.length; i += 1) {
        var r = rows[i]
        if (!r) continue
        var bucket = routeBucket(r.targetRoute)
        if (bucket !== "primary" && bucket !== "secondary") continue
        var dto = ruleRowToWireDto(r, aceEncodeHost,
            { keepId: false, keepComment: false })
        keys.push(bucket + sep + driftSortKey(dto))
    }
    return keys
}

// How many rules `currentRows` adds and drops relative to `otherRows`. Used to
// tell the user what a pending change actually is ("+2 / -1") without asking
// the service for a dry-run. Multiset compare: two identical rules count twice.
function diffRuleRowCounts(currentRows, otherRows, aceEncodeHost) {
    var cur = ruleRoutingKeys(currentRows || [], aceEncodeHost)
    var other = ruleRoutingKeys(otherRows || [], aceEncodeHost)
    var remaining = {}
    var i
    for (i = 0; i < other.length; i += 1) {
        remaining[other[i]] = (remaining[other[i]] || 0) + 1
    }
    var added = 0
    for (i = 0; i < cur.length; i += 1) {
        if (remaining[cur[i]] > 0) remaining[cur[i]] -= 1
        else added += 1
    }
    var removed = 0
    for (var k in remaining) removed += remaining[k]
    return { added: added, removed: removed }
}

// Minimal drift row from a `rules.list` wire row. Only the fields
// `buildDriftRulesJsonForRoute` reads are carried: the display-oriented rest of
// the model row (titles, validation, provenance) cannot move a drift hash.
function driftRowFromServiceWire(w) {
    return {
        enabled: !!w.enabled,
        ruleType: String(w["rule-type"] || ""),
        matchValue: String(w["match-value"] || ""),
        targetRoute: String(w["target-route"] || "primary"),
        verify: w.verify === true
    }
}

// Full file row from one wire `RuleRowEntry` (`rules.list`), for a surface that
// serialises rules to a preset file without a rules table to read them from.
// Carries comment + provenance, which the drift row deliberately drops: those
// are file content, and losing them would rewrite the user's file into a
// different one on every mirror pass. `aceDecode` crosses the wire's ACE form
// back to the Unicode the preset format stores.
function fileRowFromServiceWire(w, aceDecode) {
    var slug = String(w["rule-type"] || "")
    var value = String(w["match-value"] || "")
    var origin = w.origin || {}
    return {
        enabled: !!w.enabled,
        ruleType: slug,
        matchValue: isHostlikeRuleType(slug) ? aceDecode(value) : value,
        targetRoute: String(w["target-route"] || "primary"),
        verify: w.verify === true,
        comment: (w.comment !== undefined && w.comment !== null) ? String(w.comment) : "",
        originReason: (origin.reason !== undefined) ? String(origin.reason) : "",
        originAnchor: (origin.anchor !== undefined) ? String(origin.anchor) : "",
        originAdded: (origin.added !== undefined) ? String(origin.added) : ""
    }
}

// The route a `preset.parse` rule takes when read from the file for `route`:
// `+block`, or the file's own route.
function parsedRuleTargetRoute(r, route) {
    if (r.blocked === true) return "block"
    return String(route)
}

// The `?` of a `preset.parse` rule, in either file. A block takes none.
function parsedRuleVerify(r) {
    return r["verify-primary"] === true && r.blocked !== true
}

// Minimal drift row from one `preset.parse` result rule. `route` is the file's
// own route; a parsed block overrides it, exactly as the import path does
// when it builds full model rows.
function driftRowFromParsedRule(r, route) {
    return {
        enabled: !!r.enabled,
        ruleType: String(r["rule-type"] || ""),
        matchValue: String(r["match-value"] || ""),
        targetRoute: parsedRuleTargetRoute(r, route),
        verify: parsedRuleVerify(r)
    }
}

// Sort rank of a main-route verdict: what the main route does not reach
// first, a rule never checked last.
function mainRouteRank(slug) {
    switch (String(slug || "")) {
    case "silent": return 0
    case "answered": return 1
    case "unclear": return 2
    case "no-address": return 3
    default: return 4
    }
}

// The hosts "Check the main route" asks about: the enabled host rules of the
// additional route, in ACE form when the row carries it, without a leading
// `*.`, lower-cased, each once. A zone names no single address to try.
function mainRouteCheckHosts(rows) {
    var hosts = []
    var seen = ({})
    var list = rows || []
    for (var i = 0; i < list.length; i += 1) {
        var row = list[i] || {}
        var rt = String(row.ruleType || "")
        if (rt !== "domain" && rt !== "suffix-domain" && rt !== "exact-fqdn") continue
        if (row.enabled !== true || String(row.targetRoute || "") !== "secondary") continue
        var ace = (row.aceMatchValue === undefined || row.aceMatchValue === null)
            ? "" : String(row.aceMatchValue)
        var value = ace !== "" ? ace : String(row.matchValue || "")
        var host = value.replace(/^\*\./, "").trim().toLowerCase()
        if (host === "" || seen[host] === true) continue
        seen[host] = true
        hosts.push(host)
    }
    return hosts
}
