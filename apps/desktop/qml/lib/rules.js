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
// enabled, comment }.

// True for the rule types whose match value is a hostname (so callers know to
// apply host-specific handling such as ACE encoding at the wire boundary).
function isHostlikeRuleType(ruleType) {
    var rt = String(ruleType || "")
    return rt === "zone" || rt === "domain"
        || rt === "suffix-domain" || rt === "exact-fqdn"
}

// Dedup key for import-merge: two rows collide when their type, lowercased
// match value, and target route all match.
function mergeKey(row) {
    return String(row.ruleType || "") + "|" +
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
    var t = String(row.ruleType || "").toLowerCase()
    if (t === "suffix-domain") t = "domain"
    if (t === "exact-ipv4") t = "exact-ip"
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
    var t = String(row.ruleType || "").toLowerCase()
    if (t === "suffix-domain") t = "domain"
    if (t === "exact-ipv4") t = "exact-ip"
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

// Map a rules-model rule-type slug to its canonical docs/en/rules-file-format.md section header.
// Types we don't know about — including the platform-filtered Linux/MacOS app
// sections on Windows — return "" and the rule is skipped, mirroring what the
// parser does on the way in.
function ruleTypeToSection(ruleType) {
    var rt = String(ruleType || "")
    if (rt === "zone") return "Zones"
    if (rt === "domain" || rt === "suffix-domain" || rt === "exact-fqdn") return "Domains"
    if (rt === "exact-ip" || rt === "exact-ipv4") return "IP"
    if (rt === "application") return "Windows"
    return ""
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
// live in the sidecar either way).
function buildCanonicalRulesText(rulesModel, route, passthroughSections, includeComments) {
    var emitComments = (includeComments === undefined) ? true : !!includeComments
    var sections = { Zones: [], Domains: [], Auto: [], IP: [], Windows: [] }
    if (rulesModel) {
        for (var i = 0; i < rulesModel.count; i += 1) {
            var row = rulesModel.get(i)
            if (!row) continue
            // A "block" rule has no adapter route — it rides in the secondary
            // file, carrying the `+block` flag.
            var rowRoute = String(row.targetRoute || "")
            var effRoute = (rowRoute === "block") ? "secondary" : rowRoute
            if (effRoute !== String(route)) continue
            var section = ruleTypeToSection(row.ruleType)
            if (section === "" || !sections.hasOwnProperty(section)) continue
            // An app-authored rule keeps its provenance across the file: it
            // moves to `--- Auto` and carries the structured inline comment the
            // parser reads it back from. Only domain-shaped rules qualify —
            // that section parses as domains, so anything else stays put
            // (losing the badge beats corrupting the rule).
            var originReason = String(row.originReason || "")
            var isAuto = originReason !== "" && section === "Domains"
            if (isAuto) section = "Auto"
            var line = String(row.matchValue || "").trim()
            if (line === "") continue
            if (rowRoute === "block") line += " +block"
            if (!row.enabled) line = "# " + line
            var c = emitComments ? String(row.comment || "").trim() : ""
            if (isAuto) {
                // Provenance travels even when user comments are stripped:
                // without these tokens the rule is indistinguishable from one
                // the user typed on the next import.
                var tokens = "auto:" + originReason
                var anchor = String(row.originAnchor || "").trim()
                if (anchor !== "") tokens += " anchor:" + anchor
                var added = String(row.originAdded || "").trim()
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
    lines.push("# NetRuleRouter preset - version 1")
    lines.push("# name: NetRuleRouter Export - " + nameLabel)
    lines.push("# description: Exported from the NetRuleRouter app on "
        + (new Date()).toISOString())
    lines.push("# preset_version: 1")
    lines.push("")
    // Auto comes last, matching the canonical section order the Rust writer
    // emits (`nrr_domain::rules_file::Section::ALL`).
    var order = ["Zones", "Domains", "IP", "Windows", "Auto"]
    for (var s = 0; s < order.length; s += 1) {
        var key = order[s]
        lines.push("--- " + key)
        var bucket = sections[key]
        for (var b = 0; b < bucket.length; b += 1) lines.push(bucket[b])
        lines.push("")
    }
    // Foreign-OS app rules and Pro-tier sections captured at the previous
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
// ("domain","*.youtube.com") for SuffixDomain and ("domain","youtube.com") for
// ExactFqdn — so every rules-json builder must decode it here. Skipping this
// collapses `*.youtube.com` into a dead ExactFqdn (a literal that matches no
// host).
function hostAddressMatchDto(value) {
    var v = String(value || "")
    if (v.indexOf("*.") === 0) {
        return { kind: "suffix-domain", suffix: v.substring(2) }
    }
    return { kind: "exact-fqdn", value: v }
}

// THE rules-model row -> canonical wire DTO mapper. Single serializer for every
// caller: the Rules-section "Save and review", the window-level apply payload,
// and the drift hasher. Three divergent copies used to exist and disagreed on
// two fields — the review payload dropped `comment` while the apply payload kept
// it, so every rule carrying an inline preset comment showed up as "modified" in
// a dry-run that changed nothing.
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
            dto["address-match"] = { kind: "exact-ipv4", address: value }
            break
        case "application":
            dto["app-match"] = {
                pattern: { kind: "exact", value: value },
                "include-child-processes": false
            }
            break
        case "domain":
        default:
            // "domain" is the round-trip slug for BOTH host kinds; decode the
            // `*.` prefix so wildcard rules don't die as exact-fqdn.
            dto["address-match"] = hostAddressMatchDto(value)
    }
    // A "block" row carries the per-rule action; route rows omit it so their
    // canonical bytes/hash stay identical to the pre-block format.
    if (String(row.targetRoute || "") === "block") dto.action = "block"
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
        // A "block" rule belongs to the secondary bucket (matching the
        // service's canonical placement) so it is captured by the drift /
        // dirty signature rather than silently dropped.
        var t = String(r.targetRoute || "")
        var effBucket = (t === "block") ? "secondary" : t
        if (effBucket !== String(route)) continue
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

// Order-independent sort key for a drift DTO: id is zeroed by the time we get
// here, so the key is built from routing semantics alone.
// The separator is NUL rather than a space: an application rule's match value
// is a file path and can contain spaces, which would let two different rules
// produce the same key and make the order — and therefore the hash — depend on
// the input order again.
function driftSortKey(d) {
    var sep = String.fromCharCode(0)
    var am = d["address-match"] || {}
    var ap = d["app-match"] || {}
    var pat = (ap && ap.pattern) || {}
    var kind = String(am.kind || ("app:" + (pat.kind || "")))
    var val = String(am.value || am.suffix || am.name || am.address
        || pat.value || "")
    return kind + sep + val + sep + (d.enabled ? "1" : "0") + sep
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
        var t = String(r.targetRoute || "")
        var bucket = (t === "block") ? "secondary" : t
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
        targetRoute: String(w["target-route"] || "primary")
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
        comment: (w.comment !== undefined && w.comment !== null) ? String(w.comment) : "",
        originReason: (origin.reason !== undefined) ? String(origin.reason) : "",
        originAnchor: (origin.anchor !== undefined) ? String(origin.anchor) : "",
        originAdded: (origin.added !== undefined) ? String(origin.added) : ""
    }
}

// Minimal drift row from one `preset.parse` result rule. `route` is the file's
// own route; a parsed `+block` rule overrides it, exactly as the import path
// does when it builds full model rows.
function driftRowFromParsedRule(r, route) {
    return {
        enabled: !!r.enabled,
        ruleType: String(r["rule-type"] || ""),
        matchValue: String(r["match-value"] || ""),
        targetRoute: (r.blocked === true) ? "block" : String(route)
    }
}
