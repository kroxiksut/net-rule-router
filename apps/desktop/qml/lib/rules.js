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

// `x.*`: a site in every zone names no single host, so "check where it
// works" has nothing to check.
function valueIsAnyZone(value) {
    return /\.\*$/.test(String(value || "").trim())
}

// An IPv6 literal: the check leaves from an IPv4 source, so the service turns
// a `?` on one into a plain route.
function valueIsIpv6Literal(ruleType, value) {
    var rt = String(ruleType || "")
    return rt === "exact-ipv6" || (rt === "exact-ip" && String(value || "").indexOf(":") >= 0)
}

// The `?` a row actually carries: a route rule of a type that takes it. A
// block, another type, a site in every zone or an IPv6 literal drops it.
function rowIsVerify(row) {
    if (!row || row.verify !== true) return false
    var t = String(row.targetRoute || "")
    return (t === "primary" || t === "secondary") && ruleTypeAllowsVerify(row.ruleType)
        && !valueIsAnyZone(row.matchValue)
        && !valueIsIpv6Literal(row.ruleType, row.matchValue)
}

// The preset format version this build writes. Mirrors
// `nrr_domain::rules_file::CURRENT_RULES_FILE_FORMAT_VERSION`; the Rust test
// `the_gui_writes_the_current_preset_format_version` reads this line and fails
// when the two drift.
var CANONICAL_PRESET_FORMAT_VERSION = 11

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

// Starts every line of the syntax hint a written file opens with
// (`nrr_shared::preset_parser::SYNTAX_HINT_PREFIX`). Both parsers skip such a
// line wherever it stands, so an example in it is never a rule and a save never
// doubles it. Never localized.
var RULES_FILE_HINT_PREFIX = "#:"

// The hint: locale key and English text per line, in file order. Twin of
// `RULES_FILE_HINT_KEYS` in the Rust writer.
var RULES_FILE_HINT_KEYS = [
    ["rules.file-hint.section",
        "--- Name         section header: rule type below     --- Domains"],
    ["rules.file-hint.value",
        "value            rule: goes over this file's route   example.com"],
    ["rules.file-hint.subdomains",
        "*.value          the site and all its subdomains     *.example.com"],
    ["rules.file-hint.any-zone",
        "value.*          the site in every zone              example.*"],
    ["rules.file-hint.deny",
        "!value           deny: through no connection at all  !ads.example.net"],
    ["rules.file-hint.verify",
        "?value           this route while the site opens     ?mail.example.com"],
    ["rules.file-hint.disabled",
        "# value          rule kept but turned off            # example.com"],
    ["rules.file-hint.note",
        "value  # note    rule with your note                 example.com  # updates"],
    ["rules.file-hint.children",
        "value +children  the app and the programs it starts  codex.exe +children"],
    ["rules.file-hint.comment",
        "# text           comment, not a rule                 # my notes"]
]

// Bounds on the hint, whose text comes from locale files a user can drop in.
var RULES_FILE_HINT_MAX_LINES = 16
var RULES_FILE_HINT_MAX_LINE = 200

// The hint lines in the language `translate(key, fallback)` answers in; the
// English text without one. Called at write time, so a file is written in the
// language of that moment.
function rulesFileHintLines(translate) {
    var out = []
    for (var i = 0; i < RULES_FILE_HINT_KEYS.length; i += 1) {
        var entry = RULES_FILE_HINT_KEYS[i]
        out.push(typeof translate === "function"
            ? String(translate(entry[0], entry[1])) : entry[1])
    }
    return out
}

// The hint as written: each line behind the marker, one line each, blank and
// overlong ones left out.
function rulesFileHintBlock(texts) {
    var out = []
    if (!texts || typeof texts.length !== "number") return out
    for (var i = 0; i < texts.length && out.length < RULES_FILE_HINT_MAX_LINES; i += 1) {
        var text = oneLineField(texts[i]).trim()
        if (text === "" || text.length > RULES_FILE_HINT_MAX_LINE) continue
        out.push(RULES_FILE_HINT_PREFIX + " " + text)
    }
    return out
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
// written on; application rules go under its section. `syntaxHint` is the
// translated hint (`rulesFileHintLines`); absent or empty writes none.
function buildCanonicalRulesText(rulesModel, route, passthroughSections, includeComments, os, syntaxHint) {
    var emitComments = (includeComments === undefined) ? true : !!includeComments
    var appSection = appSectionHeader(os)
    var sections = { Zones: [], Domains: [], Auto: [], IP: [], CIDR: [], Ranges: [] }
    sections[appSection] = []
    if (rulesModel) {
        for (var i = 0; i < rulesModel.count; i += 1) {
            var row = rulesModel.get(i)
            if (!row) continue
            // A block rides in the secondary file marked by `!` before the
            // value; a `?` rule is marked there in its own file.
            var rowRoute = String(row.targetRoute || "")
            if (routeBucket(rowRoute) !== String(route)) continue
            var section = ruleTypeToSection(row.ruleType, os)
            if (section === "" || !sections.hasOwnProperty(section)) continue
            // An app-authored rule keeps its provenance across the file in the
            // structured inline comment the parser reads back: a domain rule
            // moves to `--- Auto`, a program rule stays in its own section.
            // Any other kind stays put without it (`--- Auto` parses as
            // domains; losing the badge beats corrupting the rule).
            var originReason = String(row.originReason || "")
            var isAuto = originReason !== ""
                && (section === "Domains" || section === appSection)
            if (isAuto && section === "Domains") section = "Auto"
            var line = oneLineField(row.matchValue).trim()
            if (line === "") continue
            if (section === appSection) line = programValueOnLine(line, !!row.enabled)
            // A block row is never rowIsVerify, so the two marks never meet.
            if (rowRoute === "block") line = "!" + line
            else if (rowIsVerify(row)) line = "?" + line
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
    var hint = rulesFileHintBlock(syntaxHint)
    if (hint.length > 0) {
        for (var h = 0; h < hint.length; h += 1) lines.push(hint[h])
        lines.push("")
    }
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
    // `site.*` (or `*.site.*`) is the site in every zone.
    if (/\.\*$/.test(v)) {
        var base = v.substring(0, v.length - 2)
        return { kind: "any-zone-domain",
            base: (base.indexOf("*.") === 0 ? base.substring(2) : base) }
    }
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
//
// A value with a control character is refused, never cleaned: the throw
// carries `wireRefusal` (see `wireRefusalCode`).
function ruleRowToWireDto(row, aceEncodeHost, opts) {
    var refusal = wireRefusal(row)
    if (refusal !== "") {
        var err = new Error("rule value refused on the wire: " + refusal)
        err.wireRefusal = refusal
        throw err
    }
    return _rowWireDto(row, aceEncodeHost, opts || {}, false)
}

// `WireRefusal::code`: why `row` cannot go to the service as it stands, "" when
// it can. `+children` comes off by words, so cleaning a line break away would
// glue its two sides into a name the user never wrote.
function wireRefusal(row) {
    return _bulkHasControl(String((row && row.matchValue) || "")) ? "control-character" : ""
}

// The client error code (`errors.<code>`) of a serializer throw, "" for any
// other error.
function wireRefusalCode(err) {
    return (err && typeof err.wireRefusal === "string") ? err.wireRefusal : ""
}

// Drift and routing keys compare rows and send nothing: a row the wire refuses
// compares as typed, a difference no stored rule shares, rather than throwing
// out of a watcher.
function _comparableWireDto(row, aceEncodeHost) {
    return _rowWireDto(row, aceEncodeHost, { keepId: false, keepComment: false },
        wireRefusal(row) !== "")
}

// `asTyped` keeps an application value whole, `+children` included.
function _rowWireDto(row, aceEncodeHost, options, asTyped) {
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
            dto["address-match"] = /\.\*$/.test(value) ? hostAddressMatchDto(value)
                : { kind: "suffix-domain",
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
            // ever have, so the rule matched nothing at all. `+children` stays
            // in the file, not in the name the service matches.
            // A separator makes it a path, which the service reads in its
            // platform's spelling.
            // `+override` travels as the request it is, absent when unset.
            var asksOverride = !asTyped && _bulkSplitRuleFlags(value).override
            if (!asTyped) value = withoutRuleFlags(value)
            dto["app-match"] = {
                pattern: {
                    kind: /[\\\/]/.test(value) ? "path"
                        : (value.indexOf("*") >= 0 ? "glob" : "exact"),
                    value: value
                },
                "include-child-processes": false
            }
            if (asksOverride) dto["app-match"]["override-requested"] = true
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

// The `rules-update` payload for a whole rules table, in table order. Shared by
// the window and the tray so both submit byte-identical JSON for one set of
// rows. Throws on a row the serializer cannot carry; the caller reports it.
function buildRulesJson(rows, aceEncodeHost) {
    var primary = []
    var secondary = []
    for (var i = 0; i < rows.length; i += 1) {
        // A block lives in the secondary bucket; its `action` field (set by
        // the serializer) overrides routing.
        var bucket = (routeBucket(rows[i].targetRoute) === "secondary") ? secondary : primary
        bucket.push(ruleRowToWireDto(rows[i], aceEncodeHost))
    }
    return JSON.stringify({
        "schema-version": 1,
        "primary": primary,
        "secondary": secondary
    })
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
        var dto = _comparableWireDto(r, aceEncodeHost)
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
    var override = (ap && ap["override-requested"]) ? "1" : "0"
    return kind + sep + val + sep + appKind + sep + appVal + sep
        + children + sep + override + sep + (d.enabled ? "1" : "0") + sep
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
        var dto = _comparableWireDto(r, aceEncodeHost)
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
// a `!` deny, or the file's own route.
function parsedRuleTargetRoute(r, route) {
    if (r.blocked === true) return "block"
    return String(route)
}

// The `?` of a `preset.parse` rule, in either file. A block takes none.
function parsedRuleVerify(r) {
    return r["verify-primary"] === true && r.blocked !== true
}

// The value a table keeps for a `preset.parse` rule (`ParsedRule::stored_value`).
function parsedRuleStoredValue(r) {
    return storedRuleValue(String(r["rule-type"] || ""), String(r["match-value"] || ""),
        r.children === true, r["override-requested"] === true)
}

// Minimal drift row from one `preset.parse` result rule. `route` is the file's
// own route; a parsed block overrides it, exactly as the import path does
// when it builds full model rows. The value as a table keeps it: a program's
// `+override` is routing, whether the rule may apply.
function driftRowFromParsedRule(r, route) {
    return {
        enabled: !!r.enabled,
        ruleType: String(r["rule-type"] || ""),
        matchValue: parsedRuleStoredValue(r),
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
        if (host === "" || /\.\*$/.test(host) || seen[host] === true) continue
        seen[host] = true
        hosts.push(host)
    }
    return hosts
}

// ---- the table's filters and order (nrr-client-logic `rules_table::view`) ----

// The filter boxes' choices, in the order the window offers them.
var RULES_STATUS_FILTERS = ["all", "enabled-only", "disabled-only", "with-errors", "overridden"]
var RULES_ROUTE_FILTERS = ["all", "primary", "secondary", "block", "unsure"]
var RULES_TYPE_FILTERS = ["all", "zone", "domain", "exact-ip", "ip-range", "subnet", "application"]
var RULES_SORT_COLUMNS = ["by-display-order", "by-match-value", "by-type", "by-route", "by-main-route"]

// Whether a table row passes `filters` ({status, type, route, autoOnly, hideNotWorking,
// recentOnly, search}). The table, not the row, knows which rules were applied
// over the protection and which changed lately: `isOverridden()` and
// `isRecent()` answer those on demand.
function rulePassesFilters(item, filters, isOverridden, isRecent) {
    if (!item) return false
    var f = filters || {}
    var status = String(f.status || "all")
    if (status === "enabled-only" && !item.enabled) return false
    if (status === "disabled-only" && item.enabled) return false
    if (status === "overridden" && !isOverridden()) return false
    // A warning does not disable the rule, so it is not an error here.
    if (status === "with-errors" && String(item.validationStatus || "valid") !== "error") return false
    // «Show rules that do not work» off; asking for the errors still shows them.
    if (f.hideNotWorking && status !== "with-errors"
            && String(item.validationStatus || "valid") === "error") return false
    var type = String(f.type || "all")
    if (type !== "all" && canonicalRuleTypeSlug(item.ruleType) !== type) return false
    var route = String(f.route || "all")
    if (route === "unsure") {
        if (!rowIsVerify(item)) return false
    } else if (route !== "all" && String(item.targetRoute || "") !== route) {
        return false
    }
    if (f.autoOnly && String(item.originReason || "") === "") return false
    if (f.recentOnly && !isRecent()) return false
    var search = String(f.search || "")
    if (search !== "") {
        // The needle is cleaned like a rule value too, for URL-shaped text
        // without a scheme (`site.com/page`), which the search box leaves as typed.
        var typed = search.trim().toLowerCase()
        var needle = String(normalizeHostInput("domain", typed))
        // Bare punctuation (`/`) cleans to nothing, which would match all.
        if (needle === "") needle = typed
        // Both the Unicode value and its lower-case ACE form, so `xn--p1ai`
        // finds `рф` and back; the text as typed too, since a subnet's `/`
        // and an IPv6 address's `:` read as URL punctuation to the cleaner.
        var hay = (String(item.matchValue || "") + " "
            + String(item.aceMatchValue || "") + " "
            + String(item.comment || "")).toLowerCase()
        if (hay.indexOf(needle) < 0 && hay.indexOf(typed) < 0) return false
    }
    return true
}

function _codeUnitCompare(a, b) {
    return a < b ? -1 : (a > b ? 1 : 0)
}

// Text order shared with the terminal: case folded first, then as written, so
// both clients agree without a locale-aware collator.
function compareRuleText(a, b) {
    var x = String(a || "")
    var y = String(b || "")
    return _codeUnitCompare(x.toLowerCase(), y.toLowerCase()) || _codeUnitCompare(x, y)
}

// The order of two rows under `sortBy`; ties on a column fall back to the
// value. Callers' sorts are stable, so rows equal here keep their order.
function compareRuleRows(a, b, sortBy, sortDir) {
    if (!a || !b) return 0
    var byValue = compareRuleText(a.matchValue, b.matchValue)
    var cmp
    switch (String(sortBy || "")) {
    case "by-match-value": cmp = byValue; break
    // The spelling the row arrived with, as the column sorts.
    case "by-type": cmp = compareRuleText(a.ruleType, b.ruleType) || byValue; break
    case "by-route": cmp = compareRuleText(a.targetRoute, b.targetRoute) || byValue; break
    case "by-main-route": cmp = (mainRouteRank(a.mainRoute) - mainRouteRank(b.mainRoute)) || byValue; break
    // Display order: rule ids encode insertion order.
    default: cmp = compareRuleText(a.id, b.id)
    }
    if (cmp === 0) return 0
    return sortDir === "desc" ? -cmp : cmp
}

// The file name of a program typed or picked with its path.
function vpnProgramFileName(raw) {
    var parts = String(raw || "").trim().split(/[\\\/]/)
    return parts[parts.length - 1].trim()
}

function _vpnIsIpv4(s) {
    var parts = s.split(".")
    if (parts.length !== 4) return false
    for (var i = 0; i < parts.length; i += 1) {
        if (!/^[0-9]{1,3}$/.test(parts[i]) || parseInt(parts[i], 10) > 255) return false
    }
    return true
}

// Groups of one side of an IPv6 text, the last possibly a dotted IPv4 (worth
// two); -1 when a group is malformed or empty.
function _vpnIpv6Groups(side, mayEndInIpv4) {
    if (side === "") return 0
    var groups = side.split(":")
    var count = 0
    for (var i = 0; i < groups.length; i += 1) {
        var g = groups[i]
        if (i === groups.length - 1 && mayEndInIpv4 && g.indexOf(".") >= 0) {
            if (!_vpnIsIpv4(g)) return -1
            count += 2
        } else if (/^[0-9A-Fa-f]{1,4}$/.test(g)) {
            count += 1
        } else {
            return -1
        }
    }
    return count
}

function _vpnIsIpv6(s) {
    if (s.indexOf(":") < 0) return false
    var at = s.indexOf("::")
    if (at < 0) return _vpnIpv6Groups(s, true) === 8
    var right = s.substring(at + 2)
    if (right.indexOf("::") >= 0) return false
    var l = _vpnIpv6Groups(s.substring(0, at), false)
    var r = _vpnIpv6Groups(right, true)
    return l >= 0 && r >= 0 && l + r <= 7
}

// An address literal, brackets allowed, lower-cased; null otherwise.
function _vpnIpLiteral(s) {
    var bare = (s.length >= 2 && s.charAt(0) === "[" && s.charAt(s.length - 1) === "]")
        ? s.substring(1, s.length - 1) : s
    return (_vpnIsIpv4(bare) || _vpnIsIpv6(bare)) ? bare.toLowerCase() : null
}

// A name of two labels or more: ASCII letters, digits, `-` and `_`, or any
// non-ASCII character but a space; no label empty or edged with `-`, and the
// last not all digits, which is a mistyped address. The rules validator
// judges the rest.
function _vpnIsHostName(s) {
    var labels = s.split(".")
    if (labels.length < 2 || /^[0-9]*$/.test(labels[labels.length - 1])) return false
    for (var i = 0; i < labels.length; i += 1) {
        var label = labels[i]
        if (label === "" || label.charAt(0) === "-" || label.charAt(label.length - 1) === "-") {
            return false
        }
        for (var k = 0; k < label.length; k += 1) {
            var c = label.charAt(k)
            var ok = label.charCodeAt(k) < 128 ? /[A-Za-z0-9_-]/.test(c) : !/\s/.test(c)
            if (!ok) return false
        }
    }
    return true
}

// The rule that lets a VPN reach its gateway over `route`: an exact address,
// or one host (`domain` without `*.`) when a name is chosen or typed, its
// comment `commentTemplate` with `{program}` filled. null when the input is
// neither, no program is named, or the route is not an adapter route. Twin of
// `nrr_client_logic::vpn_gateway::gateway_rule_draft`.
function vpnGatewayRuleDraft(input, program, route, commentTemplate) {
    var name = vpnProgramFileName(program)
    var text = String(input || "").trim()
    if (name === "" || text === "" || (route !== "primary" && route !== "secondary")) return null
    var comment = String(commentTemplate || "").split("{program}").join(name)
    var make = function (type, value) {
        return { "rule-type": type, value: value, route: route, comment: comment }
    }
    var ip = _vpnIpLiteral(text)
    if (ip !== null) return make("exact-ip", ip)
    var host = String(normalizeHostInput("exact-fqdn", text)).trim()
    ip = _vpnIpLiteral(host)
    if (ip !== null) return make("exact-ip", ip)
    if (host.charAt(host.length - 1) === ".") host = host.substring(0, host.length - 1)
    host = host.toLowerCase()
    return _vpnIsHostName(host) ? make("domain", host) : null
}

// ---- the add/edit rule form ----
//
// The main window and the tray's add-rule window host the same dialog; what
// it shows and what a saved form becomes live here so the two cannot differ.
// `rows` is a ListModel or a plain array of table rows.

function _rowCount(rows) {
    if (!rows) return 0
    return rows.length !== undefined ? rows.length : rows.count
}

function _rowAt(rows, i) {
    return rows.length !== undefined ? rows[i] : rows.get(i)
}

// The form's type list: the backend's types less application where this OS
// cannot route per process, which would take the input and drop it.
function offeredRuleTypes(types, appRoutingSupported) {
    var out = []
    for (var i = 0; i < (types || []).length; i += 1) {
        if (String(types[i].id) === "application" && !appRoutingSupported) continue
        out.push(types[i])
    }
    return out
}

// What the user calls a route: their own name for an adapter route, else the
// stock one. A deny is a fixed meaning, never renamed.
function routeDisplayLabel(role, primaryLabel, secondaryLabel, tr) {
    if (role === "primary") return String(primaryLabel || "") || tr("label.primary", "Primary")
    if (role === "block") return tr("label.block", "Denied")
    return String(secondaryLabel || "") || tr("label.secondary", "Additional")
}

// The form's route choices. The deny option names the action, not the row
// mark, and carries its meaning in `description` for the popup and a screen
// reader; a host that passes no `offerDeny` keeps the two adapter routes.
function routeRoleOptions(offerDeny, routeLabel, tr) {
    var opts = [
        { id: "primary", label: routeLabel("primary"), description: "" },
        { id: "secondary", label: routeLabel("secondary"), description: "" }
    ]
    if (offerDeny) opts.push({
        id: "block",
        label: tr("rules.route.deny", "Deny"),
        description: tr("rules.route.deny-description", "Deny — never send through any connection")
    })
    return opts
}

// Highest `R-NNNN` id in `rows` plus one, capped at `maxCount` when given.
function nextFreeRuleId(rows, maxCount) {
    var maxN = 0
    for (var i = 0; i < _rowCount(rows); i += 1) {
        var m = String(_rowAt(rows, i).id || "").match(/^R-(\d+)$/)
        if (m) {
            var n = parseInt(m[1], 10)
            if (!isNaN(n) && n > maxN) maxN = n
        }
    }
    var next = maxCount > 0 ? Math.min(maxN + 1, maxCount) : maxN + 1
    return "R-" + ("0000" + String(next)).slice(-4)
}

// The id of the row at `index` once a table is numbered from R-0001: the
// service numbers each route from R-0000, so a merged table would repeat ids.
function sequentialRuleId(index) {
    return "R-" + ("0000" + String(index + 1)).slice(-4)
}

// `rows` as an array with `row` in place of row `index`, or after the last one
// when `index` is negative.
function rowsWithCandidate(rows, index, row) {
    var out = []
    for (var i = 0; i < _rowCount(rows); i += 1) out.push(i === index ? row : _rowAt(rows, i))
    if (index < 0) out.push(row)
    return out
}

// The `local.rules-overlaps` route overlaps rule `candidateId` takes part in.
function overlapsOfRule(overlaps, candidateId) {
    var mine = []
    for (var i = 0; i < (overlaps || []).length; i += 1) {
        var o = overlaps[i]
        if (String(o.winner["rule-id"]) === String(candidateId)
                || String(o.loser["rule-id"]) === String(candidateId)) {
            mine.push(o)
        }
    }
    return mine
}

// One table row from the saved form `f` ({ ruleType, value, route, verify,
// comment, enabled }). A blank comment on an IDN host gets the Punycode form,
// so the user can match the rule to what the service shows. `h` supplies
// `ruleTypeLabel`, `punycodeHint` and `aceLowerForSearch`.
function ruleRowFromForm(f, id, h) {
    var comment = String(f.comment || "")
    if (comment === "" && isHostlikeRuleType(f.ruleType)) {
        var ace = h.punycodeHint(f.value)
        if (ace !== "") comment = "Punycode: " + ace
    }
    return {
        id: id,
        enabled: f.enabled,
        ruleType: f.ruleType,
        ruleTypeTitle: h.ruleTypeLabel(f.ruleType),
        matchValue: f.value,
        aceMatchValue: h.aceLowerForSearch(f.value),
        targetRoute: f.route,
        verify: rowIsVerify({ ruleType: f.ruleType, targetRoute: f.route, verify: f.verify,
            matchValue: f.value }),
        comment: comment,
        // A rule the user saved is theirs: provenance is cleared explicitly,
        // because `ListModel.set` merges roles and would keep the old badge.
        originReason: "",
        originAnchor: "",
        originAdded: "",
        // Verdicts belong to the old value too; the service's answer for the
        // new one replaces them.
        validationStatus: "valid",
        validationMessageKey: "",
        validationMessageArgs: ({}),
        hostsOverrideIp: "",
        hostsOverrideBlocking: false,
        mainRoute: "",
        pinnedCount: 0,
        pinnedSample: ""
    }
}

// Table row from one wire `RuleRowEntry` (`rules.list`). The one mapping every
// surface uses: the tray re-sends the whole rule book built from these rows,
// so a field lost here would silently change rules the user never touched.
// Host values arrive ACE and are decoded for display.
function serviceRuleRowToModelRow(w, ruleTypeLabel, aceDecode, aceLowerForSearch) {
    var slug = String(w["rule-type"] || "")
    var origin = w.origin || null
    var hosts = w["hosts-override"] || null
    var row = {
        id: canonicalRuleId(String(w.id || "")),
        enabled: !!w.enabled,
        ruleType: slug,
        ruleTypeTitle: typeof ruleTypeLabel === "function" ? ruleTypeLabel(slug) : slug,
        matchValue: String(w["match-value"] || ""),
        targetRoute: String(w["target-route"] || "primary"),
        verify: w.verify === true,
        comment: (w.comment !== undefined && w.comment !== null) ? String(w.comment) : "",
        validationStatus: String(w["validation-status"] || "valid"),
        validationMessageKey: String(w["validation-message-key"] || ""),
        // An empty object, not null: with null the ListModel cannot type the
        // role and logs a warning per row, which once dominated populate time.
        validationMessageArgs: ({}),
        // Nested objects are flattened to scalar roles: a nested role has an
        // unreliable type across a ListModel rebuild.
        hostsOverrideIp: (hosts && hosts.ip !== undefined) ? String(hosts.ip) : "",
        hostsOverrideBlocking: !!(hosts && hosts.blocking),
        // "answered", "silent", or "" when never checked.
        mainRoute: String(w["main-route"] || ""),
        originReason: (origin && origin.reason !== undefined) ? String(origin.reason) : "",
        originAnchor: (origin && origin.anchor !== undefined) ? String(origin.anchor) : "",
        originAdded: (origin && origin.added !== undefined) ? String(origin.added) : "",
        // What an application rule holds on the additional link, machine-wide.
        // The count is the service's total: the wire list is capped.
        pinnedCount: Number(w["pinned-destinations-total"]
            || (w["pinned-destinations"] || []).length),
        pinnedSample: (w["pinned-destinations"] || []).slice(0, 20).join(", ")
    }
    if (isHostlikeRuleType(slug)) row.matchValue = aceDecode(row.matchValue)
    row.aceMatchValue = aceLowerForSearch(row.matchValue)
    return row
}

// What adding `items` to `rows` amounts to. An exact duplicate is left out; a
// rule whose type and value already sit on another route is reported in
// `elsewhere`, and with `moveElsewhere` that row is moved instead of a second
// copy being added. `rows` itself is not changed.
// Returns { rows, added, changed, addedRows, movedRows, duplicates,
// elsewhere: [{ item, row }] }.
function planRuleAddition(rows, items, moveElsewhere) {
    var out = []
    for (var i = 0; i < _rowCount(rows); i += 1) out.push(_rowAt(rows, i))
    var plan = { rows: out, added: 0, changed: 0, addedRows: [], movedRows: [],
        duplicates: [], elsewhere: [] }
    // A program's `+children` / `+override` do not make it a second rule.
    var identity = function(row) {
        return _bulkRuleIdentity(canonicalRuleTypeSlug(row.ruleType), String(row.matchValue || ""))
    }
    for (var k = 0; k < items.length; k += 1) {
        var item = items[k]
        var sameValue = identity(item)
        var key = sameValue + "|" + String(item.targetRoute || "")
        var duplicate = false
        var other = -1
        for (var r = 0; r < out.length; r += 1) {
            var there = identity(out[r])
            if (there + "|" + String(out[r].targetRoute || "") === key) { duplicate = true; break }
            if (other < 0 && there === sameValue) other = r
        }
        if (duplicate) {
            plan.duplicates.push(item)
        } else if (other >= 0) {
            plan.elsewhere.push({ item: item, row: out[other] })
            if (moveElsewhere) {
                var moved = {}
                for (var f in out[other]) moved[f] = out[other][f]
                moved.targetRoute = item.targetRoute
                out[other] = moved
                plan.movedRows.push(moved)
                plan.changed += 1
            }
        } else {
            out.push(item)
            plan.addedRows.push(item)
            plan.added += 1
        }
    }
    return plan
}

// A rule's identity apart from its route: type and value, as
// `planRuleAddition` and the service's recent changes match rules.
function ruleValueKey(row) {
    return canonicalRuleTypeSlug(row.ruleType) + "|" + String(row.matchValue || "").toLowerCase()
}

// What one add left, for taking it back: `{ added: [state], moved: [{ before,
// after }] }`, a state being `{ ruleType, matchValue, targetRoute, enabled,
// verify }`. Built from a `planRuleAddition` plan (or several merged).
function additionUndoRecord(plan) {
    var pick = function(r) {
        return { ruleType: String(r.ruleType || ""), matchValue: String(r.matchValue || ""),
            targetRoute: String(r.targetRoute || ""), enabled: r.enabled !== false,
            verify: r.verify === true }
    }
    var p = plan || {}
    var record = { added: (p.addedRows || []).map(pick), moved: [] }
    var elsewhere = p.elsewhere || []
    var moved = p.movedRows || []
    for (var m = 0; m < moved.length; m += 1) {
        var key = ruleValueKey(moved[m])
        for (var e = 0; e < elsewhere.length; e += 1) {
            if (ruleValueKey(elsewhere[e].row) !== key) continue
            record.moved.push({ before: pick(elsewhere[e].row), after: pick(moved[m]) })
            break
        }
    }
    return record
}

// Taking back the add `record` (`additionUndoRecord`) from `rows`: a rule it
// added leaves, a rule it moved goes back where it was. When any of them is
// gone or no longer as the add left it, the user changed it since, and
// nothing is touched. Returns { rows, removed, restored, conflict }.
function planAdditionUndo(rows, record) {
    var out = []
    for (var i = 0; i < _rowCount(rows); i += 1) out.push(_rowAt(rows, i))
    var r = record || {}
    var untouched = { rows: out.slice(), removed: 0, restored: 0, conflict: true }
    var same = function(row, s) {
        return String(row.targetRoute || "") === s.targetRoute
            && (row.enabled !== false) === s.enabled
            && rowIsVerify(row) === rowIsVerify(s)
    }
    var find = function(s) {
        var key = ruleValueKey(s)
        for (var k = 0; k < out.length; k += 1) if (ruleValueKey(out[k]) === key) return k
        return -1
    }
    var drop = {}
    var removed = 0
    var restored = 0
    var added = r.added || []
    for (var a = 0; a < added.length; a += 1) {
        var at = find(added[a])
        if (at < 0 || drop[at] || !same(out[at], added[a])) return untouched
        drop[at] = true
        removed += 1
    }
    var moved = r.moved || []
    for (var m = 0; m < moved.length; m += 1) {
        var to = find(moved[m].after)
        if (to < 0 || drop[to] || !same(out[to], moved[m].after)) return untouched
        var back = {}
        for (var f in out[to]) back[f] = out[to][f]
        back.targetRoute = moved[m].before.targetRoute
        back.verify = moved[m].before.verify
        out[to] = back
        restored += 1
    }
    var kept = []
    for (var j = 0; j < out.length; j += 1) if (!drop[j]) kept.push(out[j])
    return { rows: kept, removed: removed, restored: restored,
        conflict: removed + restored === 0 }
}

// ---- what kind of rule a value is ----
//
// Twin of `nrr_shared::rule_value_class`, which the service's validation reads
// too; `core/client-logic/tests/vectors/rule_value_class.json` holds the two
// together. Only what the spelling settles is decided: one word (`telegram`,
// `ru`) may be a zone or a program, and the section it is written in decides.

// Rust's `char::is_whitespace`, unit by unit: JS `trim` also strips U+FEFF
// and keeps U+0085.
function _rvcIsSpaceUnit(u) {
    return (u >= 0x09 && u <= 0x0D) || u === 0x20 || u === 0x85 || u === 0xA0 || u === 0x1680
        || (u >= 0x2000 && u <= 0x200A) || u === 0x2028 || u === 0x2029 || u === 0x202F
        || u === 0x205F || u === 0x3000
}

function _rvcTrim(s) {
    s = String(s)
    var a = 0
    var b = s.length
    while (a < b && _rvcIsSpaceUnit(s.charCodeAt(a))) a += 1
    while (b > a && _rvcIsSpaceUnit(s.charCodeAt(b - 1))) b -= 1
    return s.substring(a, b)
}

// An address by its characters, well-formed or not.
function _rvcAddressShaped(s) {
    if (s === "") return false
    if (s.indexOf(".") >= 0 && /^[0-9.]+$/.test(s) && /[0-9]/.test(s)) return true
    var head = s.split("%")[0]
    return head !== "" && head.split(":").length - 1 >= 2 && /^[0-9A-Fa-f:.]+$/.test(head)
}

// `.exe` or a path. `.app`, `.sh` and `.py` are real top-level domains.
function _rvcNamesAProgram(v) {
    return /\.[eE][xX][eE]$/.test(v) || /^[A-Za-z]:[\/\\]/.test(v) || v.indexOf("\\") >= 0
        || v.charAt(0) === "/" || v.indexOf("./") === 0 || v.indexOf("../") === 0
        || v.indexOf("~/") === 0
}

function _rvcNameUnit(u) {
    if (u < 128) return /[A-Za-z0-9_-]/.test(String.fromCharCode(u))
    return !((u >= 0x80 && u <= 0xA0) || u === 0x1680 || (u >= 0x2000 && u <= 0x200F)
        || (u >= 0x2028 && u <= 0x202F) || (u >= 0x205F && u <= 0x206F) || u === 0x3000
        || u === 0xFEFF)
}

// { count, last } of a host name, one trailing dot allowed; null when a label
// is empty, edged with `-`, or holds a character no name carries.
function _rvcHostLabels(v) {
    if (v.length > 0 && v.charAt(v.length - 1) === ".") v = v.substring(0, v.length - 1)
    if (v === "") return null
    var labels = v.split(".")
    for (var i = 0; i < labels.length; i += 1) {
        var label = labels[i]
        if (label === "" || label.charAt(0) === "-" || label.charAt(label.length - 1) === "-") {
            return null
        }
        for (var k = 0; k < label.length; k += 1) {
            if (!_rvcNameUnit(label.charCodeAt(k))) return null
        }
    }
    return { count: labels.length, last: labels[labels.length - 1] }
}

// Letters only (any script) or an ACE label: `ps1`, `11` are no TLD.
function _rvcTldShaped(label) {
    if (/^[xX][nN]--/.test(label)) return true
    for (var k = 0; k < label.length; k += 1) {
        var u = label.charCodeAt(k)
        if (u < 128 && !/[A-Za-z]/.test(label.charAt(k))) return false
    }
    return true
}

function _rvcEndsWithAnyZone(v) {
    return v.length >= 2 && v.substring(v.length - 2) === ".*"
}

function _rvcPattern(v) {
    if (/^\*+$/.test(v)) return "unrecognized"
    var h
    if (v.indexOf("*.") === 0) {
        var rest = v.substring(2)
        if (_rvcEndsWithAnyZone(rest)) {
            return _rvcHostLabels(rest.substring(0, rest.length - 2)) ? "site-in-every-zone"
                : "unrecognized"
        }
        h = _rvcHostLabels(rest)
        if (h && _rvcTldShaped(h.last)) return h.count === 1 ? "zone" : "host-with-subdomains"
        return "unrecognized"
    }
    if (_rvcEndsWithAnyZone(v)) {
        return _rvcHostLabels(v.substring(0, v.length - 2)) ? "site-in-every-zone"
            : "unrecognized"
    }
    return v.indexOf(".") >= 0 ? "unrecognized" : "application"
}

function _rvcName(v) {
    if (v.charAt(0) === ".") {
        var rest = v.substring(1)
        var z = _rvcHostLabels(rest)
        return (z && z.count === 1 && _rvcTldShaped(z.last) && rest.charAt(rest.length - 1) !== ".")
            ? "zone" : "unrecognized"
    }
    var h = _rvcHostLabels(v)
    if (!h) return "unrecognized"
    if (h.count === 1) return "ambiguous"
    var parts = v.split(".")
    // `1.2.3.x`: a dotted quad with a typo in it.
    if (h.count === 4 && /^[0-9]*$/.test(parts[0]) && /^[0-9]*$/.test(parts[1])
            && /^[0-9]*$/.test(parts[2])) {
        return "address"
    }
    return _rvcTldShaped(h.last) ? "host" : "unrecognized"
}

// The class slug of `value`: address, subnet, range, zone, host,
// host-with-subdomains, site-in-every-zone, application, ambiguous or
// unrecognized.
function ruleValueClass(value) {
    var v = _rvcTrim(value === undefined || value === null ? "" : value)
    if (v === "") return "unrecognized"
    if (_rvcAddressShaped(v)) return "address"
    var slash = v.indexOf("/")
    if (slash >= 0) {
        var tail = _rvcTrim(v.substring(slash + 1))
        if (_rvcAddressShaped(_rvcTrim(v.substring(0, slash))) && /^[0-9]+$/.test(tail)) {
            return "subnet"
        }
    }
    var dash = v.indexOf("-")
    if (dash >= 0 && _rvcAddressShaped(_rvcTrim(v.substring(0, dash)))
            && _rvcAddressShaped(_rvcTrim(v.substring(dash + 1)))) {
        return "range"
    }
    if (_rvcNamesAProgram(v)) return "application"
    if (v.indexOf("*") >= 0) return _rvcPattern(v)
    return _rvcName(v)
}

// The rule type a class is written as; "" when the spelling does not say.
function ruleTypeOfValueClass(cls) {
    if (cls === "address") return "exact-ip"
    if (cls === "subnet") return "subnet"
    if (cls === "range") return "ip-range"
    if (cls === "zone") return "zone"
    if (cls === "host" || cls === "host-with-subdomains" || cls === "site-in-every-zone") {
        return "domain"
    }
    if (cls === "application") return "application"
    return ""
}

function _rvcSectionHolds(section, cls, os) {
    var network = cls === "address" || cls === "subnet" || cls === "range"
    if (section === "exact-ip" || section === "subnet" || section === "ip-range") {
        var t = ruleTypeOfValueClass(cls)
        return t === "" || t === section
    }
    if (section === "zone") {
        return !(network || cls === "site-in-every-zone" || cls === "application")
    }
    if (section === "domain") return !(network || cls === "application")
    // Linux and macOS programs carry dots in their names.
    if (os === "linux" || os === "macos") return !(network || cls === "host-with-subdomains")
    return !(network || cls === "zone" || ruleTypeOfValueClass(cls) === "domain")
}

// The rule type `value` belongs to when a `ruleType` rule cannot hold it, on
// `os` (`PlatformProfile.os`); "" when it can or the spelling does not say.
function misplacedRuleType(ruleType, value, os) {
    var section = String(ruleType || "")
    if (["zone", "domain", "exact-ip", "subnet", "ip-range", "application"].indexOf(section) < 0) {
        return ""
    }
    var cls = ruleValueClass(value)
    return _rvcSectionHolds(section, cls, String(os || "")) ? "" : ruleTypeOfValueClass(cls)
}

// The rule type a verdict's message key says the value belongs to — what
// "Move to section" moves it to; "" for any other key.
function misplacedTargetType(messageKey) {
    var prefix = "rules.validation.match-value-invalid.is-"
    var key = String(messageKey || "")
    if (key.indexOf(prefix) !== 0) return ""
    var t = key.substring(prefix.length)
    return ["zone", "domain", "exact-ip", "subnet", "ip-range", "application"].indexOf(t) >= 0
        ? t : ""
}

// ---- application path ----
//
// Twin of `nrr_client_logic::rule_value_class::app_value_form` over
// `nrr_shared::app_path`; `core/client-logic/tests/vectors/app_value_form.json`
// holds the two together.

// `nrr_shared::app_path::MAX_PATH_VALUE_BYTES` and `MAX_RULE_VALUE_BYTES`.
var PATH_VALUE_MAX_BYTES = 1024
var RULE_VALUE_MAX_BYTES = 260

// The most characters the rule form takes for `ruleType`; an application may
// be a path. The exact bound in bytes is the service's verdict.
function ruleValueMaxLength(ruleType) {
    var t = String(ruleType || "")
    if (t === "zone" || t === "domain") return 253
    if (t === "exact-ip" || t === "exact-ipv4" || t === "exact-ipv6") return 45
    if (t === "subnet") return 51
    if (t === "ip-range") return 93
    if (t === "application") return PATH_VALUE_MAX_BYTES
    return RULE_VALUE_MAX_BYTES
}

var APP_PATH_MAX_UNITS = 32768
var APP_PATH_MAX_SEGMENTS = 256

function _apHasControl(s) {
    for (var i = 0; i < s.length; i += 1) {
        var u = s.charCodeAt(i)
        if (u <= 0x1F || (u >= 0x7F && u <= 0x9F)) return true
    }
    return false
}

function _apIsSep(c, windows) {
    return c === "/" || (windows && c === "\\")
}

// `path_segments` with `pattern` off: the segments, or null.
function _apSegments(path, windows, foldCase) {
    if (path.length > APP_PATH_MAX_UNITS || _apHasControl(path)) return null
    path = _rvcTrim(path)
    if (foldCase) path = path.toLowerCase()
    var segments = []
    var rest
    if (windows) {
        var u = path.replace(/\//g, "\\")
        if (u.indexOf("\\\\?\\unc\\") === 0) u = "\\\\" + u.substring(8)
        else if (u.indexOf("\\\\?\\") === 0 || u.indexOf("\\\\.\\") === 0) u = u.substring(4)
        if (u.indexOf("\\\\") === 0) {
            var parts = u.substring(2).split("\\").filter(function(p) { return p !== "" })
            if (parts.length < 2) return null
            if (parts[0] === "." || parts[0] === ".." || parts[1] === "." || parts[1] === "..") {
                return null
            }
            segments.push("\\\\" + parts[0] + "\\" + parts[1])
            rest = parts.slice(2).join("\\")
        } else {
            if (!/^[A-Za-z]:(\\|$)/.test(u)) return null
            segments.push(u.charAt(0) + ":")
            rest = u.substring(2)
        }
    } else {
        if (path.charAt(0) !== "/") return null
        rest = path.substring(1)
    }
    var raw = rest.split(windows ? "\\" : "/")
    for (var i = 0; i < raw.length; i += 1) {
        var seg = raw[i]
        if (seg === "" || seg === ".") continue
        if (seg === "..") return null
        if (windows) {
            if (seg.indexOf(":") >= 0) return null
            seg = seg.replace(/[. ]+$/, "")
            if (seg === "") return null
        }
        if (seg.indexOf("*") >= 0) return null
        segments.push(seg)
        if (segments.length > APP_PATH_MAX_SEGMENTS) return null
    }
    return segments
}

// The profile folders a Windows path may start from (`ProfileFolder`), with
// the folders between the profile and each; `~` is the one elsewhere.
var APP_PATH_PROFILE_WINDOWS = { "%localappdata%": 2, "%appdata%": 2, "%userprofile%": 0 }

function _apIsProfileToken(t, windows) {
    return windows
        ? Object.prototype.hasOwnProperty.call(APP_PATH_PROFILE_WINDOWS, t.toLowerCase())
        : t === "~"
}

// `profile_prefix`: { rest, below } after a profile folder this platform
// reads, "unknown" for any other variable, null when `body` starts from none.
function _apProfileHead(body, windows) {
    var first = body.charAt(0)
    var headLen
    if (first === "%") {
        var close = body.indexOf("%", 1)
        if (close < 0) return "unknown"
        headLen = close + 1
    } else if (first === "~") {
        headLen = 1
    } else if (first === "$") {
        return "unknown"
    } else {
        return null
    }
    var head = body.substring(0, headLen)
    if (!_apIsProfileToken(head, windows)) return "unknown"
    var rest = body.substring(headLen)
    if (rest !== "" && !_apIsSep(rest.charAt(0), windows)) return "unknown"
    return { rest: rest, below: windows ? APP_PATH_PROFILE_WINDOWS[head.toLowerCase()] : 0 }
}

// `AppPath::under_profile`: the form of a path below a profile folder.
function _apProfileForm(head, tree, windows, foldCase) {
    var rest = head.rest
    var rooted = windows ? "c:" + rest : (rest === "" ? "/" : rest)
    var below = _apSegments(rooted, windows, foldCase)
    if (below === null) return "path-invalid"
    below = below.slice(windows ? 1 : 0)
    // The probe profile: `c:\users\<profile>` or `/home/<profile>`.
    var probe = windows ? 3 : 2
    if (probe + head.below + below.length > APP_PATH_MAX_SEGMENTS) return "path-invalid"
    if (tree) return "folder-tree"
    var trailing = rest.length > 0 && _apIsSep(rest.charAt(rest.length - 1), windows)
    if (trailing || below.length === 0) return "folder"
    if (!windows) return "file-or-folder"
    var last = below[below.length - 1]
    return last.length >= 4 && last.substring(last.length - 4) === ".exe" ? "file" : "folder"
}

// What an application rule value names on `os`: name, name-glob, file,
// folder, folder-tree, file-or-folder, or path-star / path-not-absolute /
// path-invalid / path-unknown-variable when a path names no program.
function appValueForm(value, os) {
    var trimmed = _rvcTrim(value === undefined || value === null ? "" : value)
    var v = withoutRuleFlags(trimmed)
    var o = String(os || "")
    var windows = o !== "linux" && o !== "macos"
    var foldCase = o !== "linux"
    var isPath = windows ? /[\\\/]/.test(v) : v.indexOf("/") >= 0
    if (!isPath) return v.indexOf("*") >= 0 ? "name-glob" : "name"
    // Taking the flags off rejoins the words, a line break with them.
    if (v.length > APP_PATH_MAX_UNITS || _apHasControl(trimmed)) return "path-invalid"
    var t = _rvcTrim(v)
    var tree = t.length >= 2 && t.charAt(t.length - 1) === "*"
        && _apIsSep(t.charAt(t.length - 2), windows)
    var body = tree ? t.substring(0, t.length - 1) : t
    if (body.indexOf("*") >= 0) return "path-star"
    var head = _apProfileHead(body, windows)
    if (head === "unknown") return "path-unknown-variable"
    if (head !== null) return _apProfileForm(head, tree, windows, foldCase)
    var absolute = windows
        ? (/^[A-Za-z]:([\\\/]|$)/.test(body) || /^[\\\/][\\\/]/.test(body))
        : body.charAt(0) === "/"
    if (!absolute) return "path-not-absolute"
    var segments = _apSegments(body, windows, foldCase)
    if (segments === null) return "path-invalid"
    if (tree) return "folder-tree"
    var trailing = body.length > 0 && _apIsSep(body.charAt(body.length - 1), windows)
    if (trailing || segments.length <= (windows ? 1 : 0)) return "folder"
    if (!windows) return "file-or-folder"
    var last = segments[segments.length - 1]
    return last.length >= 4 && last.substring(last.length - 4) === ".exe" ? "file" : "folder"
}

// ---- many rules at once ----
//
// Twin of `nrr_client_logic::bulk_rules`; `core/client-logic/tests/vectors/
// bulk_rules.json` holds the two together. A line under a section header is
// read as an import reads it (`nrr_shared::preset_parser`, mirrored below);
// only the type of a line under no header, duplicates, the rule on another
// route and the bounds are decided here. The text is somebody's clipboard: it
// is read in one pass and bounded in lines and size, and what lies past the
// bound stays in the field rather than being cut. The service's verdict on each
// row comes in `verdicts`, keyed by the row's `verdictKey`; without one the row
// waits.

var BULK_MAX_LINES = 1000
// UTF-16 units of the lines read, newlines included.
var BULK_MAX_UNITS = 262144
var BULK_MAX_LINE_UNITS = 1024
// `nrr_domain::preset_validation::MAX_INLINE_COMMENT_CHARS`.
var BULK_COMMENT_MAX_CHARS = 200

function _bulkOwn(map, key) {
    return map !== null && typeof map === "object" && Object.prototype.hasOwnProperty.call(map, key)
}

// Rust's `char::is_control` less the tab.
function _bulkHasControl(s) {
    for (var i = 0; i < s.length; i += 1) {
        var u = s.charCodeAt(i)
        if ((u <= 0x1F && u !== 0x09) || (u >= 0x7F && u <= 0x9F)) return true
    }
    return false
}

// Rust's `split_whitespace`.
function _bulkWords(s) {
    var out = []
    var start = -1
    for (var i = 0; i <= s.length; i += 1) {
        var space = i === s.length || _rvcIsSpaceUnit(s.charCodeAt(i))
        if (space && start >= 0) {
            out.push(s.substring(start, i))
            start = -1
        } else if (!space && start < 0) {
            start = i
        }
    }
    return out
}

function _bulkTrimStart(s) {
    var a = 0
    while (a < s.length && _rvcIsSpaceUnit(s.charCodeAt(a))) a += 1
    return s.substring(a)
}

function _bulkTrimEnd(s) {
    var b = s.length
    while (b > 0 && _rvcIsSpaceUnit(s.charCodeAt(b - 1))) b -= 1
    return s.substring(0, b)
}

// Code points, as Rust's `chars().count()`.
function _bulkCodePoints(s) {
    var n = 0
    for (var i = 0; i < s.length; i += 1) {
        var u = s.charCodeAt(i)
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < s.length) {
            var w = s.charCodeAt(i + 1)
            if (w >= 0xDC00 && w <= 0xDFFF) i += 1
        }
        n += 1
    }
    return n
}

// `--- Name`: exactly three hyphens and one space; "" when not a header.
function _bulkHeader(line) {
    if (line.indexOf("--- ") !== 0) return ""
    var rest = line.substring(4)
    if (rest === "" || _rvcIsSpaceUnit(rest.charCodeAt(0))) return ""
    return _bulkTrimEnd(rest)
}

// The rule type of a section on `os`; "" for one not applied here. Names match
// in any ASCII case, as the rules-file parser reads them.
function _bulkSectionType(name, os) {
    var n = name.replace(/[A-Z]/g, function(c) { return c.toLowerCase() })
    if (n === "zones") return "zone"
    if (n === "domains" || n === "auto") return "domain"
    if (n === "ip") return "exact-ip"
    if (n === "cidr") return "subnet"
    if (n === "ranges") return "ip-range"
    var appSection = os === "linux" ? "linux" : os === "macos" ? "macos" : "windows"
    return n === appSection ? "application" : ""
}

// `split_rule_markers(value, readsVerify)`: `!` deny, `?` check where the
// type reads it, never both.
function _bulkMarkers(value, readsVerify) {
    var rest = value
    var deny = false
    if (rest.charAt(0) === "!" && rest.length > 1 && !_rvcIsSpaceUnit(rest.charCodeAt(1))) {
        rest = rest.substring(1)
        deny = true
    }
    var verify = false
    if (readsVerify && rest.charAt(0) === "?" && rest.length > 1
            && !_rvcIsSpaceUnit(rest.charCodeAt(1))) {
        rest = rest.substring(1)
        verify = true
    }
    if (verify && (deny || rest.charAt(0) === "!")) {
        return { rest: value, deny: false, verify: false }
    }
    return { rest: rest, deny: deny, verify: verify }
}

// `split_rule_flags`: every later `+children` and `+override` taken off; the
// whitespace between kept words stays as written, one space closes a flag's gap.
function _bulkSplitRuleFlags(value) {
    var s = String(value)
    var out = ""
    var children = false
    var override = false
    var keptEnd = -1
    var idx = 0
    var start = -1
    for (var i = 0; i <= s.length; i += 1) {
        var space = i === s.length || _rvcIsSpaceUnit(s.charCodeAt(i))
        if (!space && start < 0) start = i
        if (!space || start < 0) continue
        var word = s.substring(start, i)
        if (idx > 0 && (word === "+children" || word === "+override")) {
            if (word === "+children") children = true
            else override = true
            keptEnd = -1
        } else {
            if (keptEnd >= 0) out += s.substring(keptEnd, start)
            else if (out !== "") out += " "
            out += word
            keptEnd = i
        }
        idx += 1
        start = -1
    }
    return { value: out, children: children, override: override }
}

// `unquote_program_value`: the value inside one outer pair of quotes,
// trimmed; null when it is not enclosed or encloses nothing.
function _unquoteProgramValue(value) {
    var v = String(value)
    if (v.length < 2 || v.charAt(0) !== "\"" || v.charAt(v.length - 1) !== "\"") return null
    var inner = _rvcTrim(v.substring(1, v.length - 1))
    return inner === "" ? null : inner
}

// `split_inline_comment`: a comment starts at a `#` opening the body or after
// whitespace, past a leading quoted value; `comment` is null without one.
function _splitInlineComment(body) {
    var s = String(body)
    var marks = 0
    while (marks < s.length && (s.charAt(marks) === "!" || s.charAt(marks) === "?")) marks += 1
    var from = 0
    if (s.charAt(marks) === "\"") {
        for (var q = marks + 1; q < s.length; q += 1) {
            if (s.charAt(q) === "\""
                    && (q + 1 === s.length || _rvcIsSpaceUnit(s.charCodeAt(q + 1)))) {
                from = q + 1
                break
            }
        }
    }
    var prevSpace = from === 0
    for (var i = from; i < s.length; i += 1) {
        if (prevSpace && s.charAt(i) === "#") {
            return { value: s.substring(0, i), comment: s.substring(i + 1) }
        }
        prevSpace = _rvcIsSpaceUnit(s.charCodeAt(i))
    }
    return { value: s, comment: null }
}

// `program_value_on_line`: a program's value in quotes where the bare value
// would not read back; the flags stay outside them.
function programValueOnLine(value, enabled) {
    var split = _bulkSplitRuleFlags(String(value))
    var bare = split.value
    var misread = _unquoteProgramValue(bare) !== null
        || _splitInlineComment(bare).comment !== null
        || (!enabled && !_bulkIsDisabledRuleValue("application", bare))
    if (bare === "" || !misread) return value
    return storedRuleValue("application", "\"" + bare + "\"", split.children, split.override)
}

// `stored_rule_value`: a table keeps `+children` and `+override` on a program
// only.
function storedRuleValue(ruleType, value, children, override) {
    if (ruleType !== "application") return value
    return value + (children === true ? " +children" : "")
        + (override === true ? " +override" : "")
}

// `without_rule_flags`: what the service matches for a table's value.
function withoutRuleFlags(value) {
    var split = _bulkSplitRuleFlags(value)
    return (split.children || split.override) ? split.value : value
}

// Whether a table's value carries `+override`: the rule waits for the user's
// confirmation before it applies, on a program only.
function ruleValueAsksOverride(ruleType, value) {
    if (String(ruleType || "") !== "application") return false
    return _bulkSplitRuleFlags(String(value || "")).override
}

// `app_match_key`: the file name, ASCII lower case, without `.exe`.
function _appMatchKey(raw) {
    var t = _rvcTrim(String(raw || ""))
    var cut = Math.max(t.lastIndexOf("\\"), t.lastIndexOf("/"))
    // Folded over all of Unicode, as the service stores names.
    var name = (cut >= 0 ? t.substring(cut + 1) : t).toLowerCase()
    if (name.length > 4 && name.substring(name.length - 4) === ".exe")
        return name.substring(0, name.length - 4)
    return name
}

// `rule_override_key`: the key a confirmation and its rule share; "" for
// anything no confirmation can be about.
function ruleOverrideKey(ruleType, value, route, os) {
    var r = String(route || "")
    if (String(ruleType || "") !== "application" || (r !== "secondary" && r !== "block"))
        return ""
    var bare = _rvcTrim(withoutRuleFlags(_rvcTrim(String(value || ""))))
    if (bare === "") return ""
    var o = String(os || "")
    var windows = o !== "linux" && o !== "macos"
    var isPath = bare.indexOf("/") >= 0 || (windows && bare.indexOf("\\") >= 0)
    var spelled = !isPath ? _appMatchKey(bare)
        : windows ? bare.replace(/\//g, "\\").toLowerCase()
        : o === "macos" ? bare.toLowerCase()
        : bare
    return r + "|" + spelled
}

// `override_remaining`: how much of a confirmation's term is left, rounded up
// in the largest fitting unit: `{ kind, count }`.
function overrideRemaining(untilMs, nowMs) {
    if (untilMs === undefined || untilMs === null) return { kind: "until-revoked", count: 0 }
    var left = Number(untilMs) - Number(nowMs)
    var minute = 60000, hour = 3600000, day = 86400000
    if (!(left > 0)) return { kind: "ended", count: 0 }
    if (left < hour) return { kind: "minutes", count: Math.ceil(left / minute) }
    if (left < 2 * day) return { kind: "hours", count: Math.ceil(left / hour) }
    return { kind: "days", count: Math.ceil(left / day) }
}

// `without_retired_block_flag` when `carries_retired_block_flag`; null otherwise.
function _bulkWithoutRetiredBlock(value) {
    var words = _bulkWords(value)
    if (words.length === 0) return null
    var kept = [words[0]]
    var found = false
    for (var i = 1; i < words.length; i += 1) {
        if (words[i] === "+block") found = true
        else kept.push(words[i])
    }
    return found ? kept.join(" ") : null
}

// Rust's `Ipv4Addr::from_str`: four decimal octets, none with a leading zero.
function _bulkIpv4(s) {
    var parts = s.split(".")
    if (parts.length !== 4) return false
    for (var i = 0; i < parts.length; i += 1) {
        var p = parts[i]
        if (!/^[0-9]{1,3}$/.test(p) || (p.length > 1 && p.charAt(0) === "0")
                || parseInt(p, 10) > 255) {
            return false
        }
    }
    return true
}

// Groups of one side of an IPv6 text, a last dotted IPv4 worth two; -1 when one
// is malformed.
function _bulkIpv6Groups(side, mayEndInIpv4) {
    if (side === "") return 0
    var groups = side.split(":")
    var count = 0
    for (var i = 0; i < groups.length; i += 1) {
        var g = groups[i]
        if (i === groups.length - 1 && mayEndInIpv4 && g.indexOf(".") >= 0) {
            if (!_bulkIpv4(g)) return -1
            count += 2
        } else if (/^[0-9A-Fa-f]{1,4}$/.test(g)) {
            count += 1
        } else {
            return -1
        }
    }
    return count
}

// Rust's `IpAddr::from_str`.
function _bulkIpAddr(s) {
    if (s.indexOf(":") < 0) return _bulkIpv4(s)
    var at = s.indexOf("::")
    if (at < 0) return _bulkIpv6Groups(s, true) === 8
    var right = s.substring(at + 2)
    if (right.indexOf("::") >= 0) return false
    var l = _bulkIpv6Groups(s.substring(0, at), false)
    var r = _bulkIpv6Groups(right, true)
    return l >= 0 && r >= 0 && l + r <= 7
}

// `IpBlock::parse(..).is_some()`: `address/prefix`, the prefix within the family.
function _bulkIpBlock(text) {
    var t = _rvcTrim(text)
    var slash = t.indexOf("/")
    if (slash < 0) return false
    var prefix = _rvcTrim(t.substring(slash + 1))
    if (!/^[0-9]+$/.test(prefix)) return false
    var address = _rvcTrim(t.substring(0, slash))
    if (!_bulkIpAddr(address)) return false
    var n = parseInt(prefix, 10)
    return n <= (address.indexOf(":") >= 0 ? 128 : 32)
}

// `is_disabled_rule_value`: whether a `#` line under `type` is a rule or a note.
// `looks_like_a_host_value`: one word of letters, digits, `.`, `-`, `_` and
// `*`, any non-ASCII letter among them.
function _bulkLooksLikeHost(value) {
    if (value === "") return false
    for (var i = 0; i < value.length; i += 1) {
        var u = value.charCodeAt(i)
        if (_rvcIsSpaceUnit(u)) return false
        if (u >= 0x80) continue
        var c = value.charAt(i)
        if (!/[A-Za-z0-9._*-]/.test(c)) return false
    }
    return true
}

function _bulkIsDisabledRuleValue(type, value) {
    var unblocked = _bulkWithoutRetiredBlock(value)
    var v = unblocked !== null ? unblocked : value
    var trimmed = _rvcTrim(v)
    // Marks left on an address (`!?`, which takes neither) do not make it a
    // note: the validator refuses the pair instead.
    var unmarked = trimmed.replace(/^[!?]+/, "")
    // The section's type first: `# Office` under `--- IP` is a note.
    if (type === "exact-ip") return _bulkIpAddr(unmarked)
    if (type === "zone" || type === "domain") return _bulkLooksLikeHost(unmarked)
    if (type === "application" && trimmed !== "" && _bulkWords(trimmed).length === 1) return true
    if (type === "application") {
        // `names_a_place`: a spaced path rule (`C:\Program Files\App\*`).
        if (/^[A-Za-z]:[\\\/]/.test(trimmed) || trimmed.indexOf("\\\\") === 0) return true
        if (trimmed.charAt(0) === "/" && /\/\*?$/.test(trimmed)) return true
        var dot = trimmed.lastIndexOf(".")
        if (dot < 0 || _rvcTrim(trimmed.substring(0, dot)) === "") return false
        var ext = trimmed.substring(dot + 1).replace(/[A-Z]/g, function(c) { return c.toLowerCase() })
        return ext === "exe" || ext === "com" || ext === "app" || ext === "appimage"
    }
    if (type === "subnet") return _bulkIpBlock(unmarked)
    if (type === "ip-range") {
        var dash = unmarked.indexOf("-")
        return dash >= 0 && _bulkIpAddr(_rvcTrim(unmarked.substring(0, dash)))
            && _bulkIpAddr(_rvcTrim(unmarked.substring(dash + 1)))
    }
    return false
}

// `parse_provenance_comment`: the `auto:` / `anchor:` / `added:` tokens that
// open an app-authored line's comment; null when it names no reason.
function _bulkProvenance(comment) {
    var rest = _rvcTrim(comment)
    var reason = null
    var anchor = null
    var added = null
    while (rest !== "") {
        var end = 0
        while (end < rest.length && !_rvcIsSpaceUnit(rest.charCodeAt(end))) end += 1
        var token = rest.substring(0, end)
        if (token.indexOf("auto:") === 0) reason = token.substring(5)
        else if (token.indexOf("anchor:") === 0) anchor = token.substring(7)
        else if (token.indexOf("added:") === 0) added = token.substring(6)
        else break
        rest = _bulkTrimStart(rest.substring(end))
    }
    if (reason === null || reason === "") return null
    return { reason: reason, anchor: anchor === null ? "" : anchor,
        added: added === null ? "" : added, note: rest }
}

// A header-less value as it is judged: without its marks and flags.
function _bulkClassifiedCore(collapsed) {
    var core = collapsed
    if (core.charAt(0) === "!" && core.length > 1 && !_rvcIsSpaceUnit(core.charCodeAt(1))) {
        core = core.substring(1)
    }
    if (core.charAt(0) === "?" && core.length > 1 && !_rvcIsSpaceUnit(core.charCodeAt(1))) {
        core = core.substring(1)
    }
    var unblocked = _bulkWithoutRetiredBlock(core)
    if (unblocked !== null) core = unblocked
    return core
}

function _bulkLineCount(text, from) {
    var n = 0
    var pos = from
    while (pos < text.length) {
        n += 1
        var nl = text.indexOf("\n", pos)
        if (nl < 0) break
        pos = nl + 1
    }
    return n
}

function _bulkRow(line, text, section, route) {
    return { line: line, text: text, section: section, type: "", options: [], value: "",
        enabled: true, route: route, verify: false, comment: "", status: "", key: "",
        args: {}, existing: -1, otherRoute: "", sameLine: 0, move: false, action: "",
        verdictKey: "", originReason: "", originAnchor: "", originAdded: "" }
}

function _bulkFail(row, key, args) {
    row.status = "error"
    row.key = key
    row.args = args || {}
    row.action = "keep"
    return row
}

// The verdict for the row's type and value; null, the row left waiting, while
// none has come in.
function _bulkVerdict(ctx, row) {
    row.verdictKey = row.type + "|" + row.value
    if (!_bulkOwn(ctx.verdicts, row.verdictKey)) {
        row.status = "pending"
        row.key = "rules.paste.pending"
        row.args = {}
        row.action = "keep"
        return null
    }
    var verdict = ctx.verdicts[row.verdictKey] || {}
    var args = {}
    var given = verdict.args || {}
    for (var k in given) {
        if (_bulkOwn(given, k)) args[k] = String(given[k])
    }
    var status = String(verdict.status || "")
    return { level: status === "error" ? "error" : status === "warning" ? "warning" : "valid",
        key: String(verdict["message-key"] || ""), args: args }
}

function _bulkLine(ctx, raw, lineNo) {
    var line = raw.length > 0 && raw.charCodeAt(raw.length - 1) === 0x0D
        ? raw.substring(0, raw.length - 1) : raw
    if (_bulkTrimStart(line).indexOf("#:") === 0) return null
    var header = _bulkHeader(line)
    if (header !== "") {
        ctx.section = { name: header, type: _bulkSectionType(header, ctx.os) }
        return null
    }
    var t = _rvcTrim(line)
    if (t === "" || t.indexOf("##") === 0) return null
    var sec = ctx.section
    var row = _bulkRow(lineNo, t, sec.name, ctx.route)
    if (t.length > BULK_MAX_LINE_UNITS) {
        return _bulkFail(row, "rules.paste.too-long", { max: String(BULK_MAX_LINE_UNITS) })
    }
    if (_bulkHasControl(t)) return _bulkFail(row, "rules.paste.control-character")
    // The file's reading of a rule line, step for step.
    var hashed = t.charAt(0) === "#"
    var body = t.indexOf("# ") === 0 ? t.substring(2) : hashed ? t.substring(1) : t
    if (hashed && body === "") return null
    var cut = _splitInlineComment(body)
    var comment = cut.comment !== null ? _rvcTrim(cut.comment) : ""
    // Trimmed, never collapsed: the file keeps inner spaces of a path whole.
    var collapsed = _rvcTrim(cut.value)
    if (collapsed === "") return null
    if (sec.name !== "" && sec.type === "") {
        // An import keeps such a section aside and applies none of it.
        if (hashed) return null
        row.value = collapsed
        return _bulkFail(row, "rules.paste.section-not-applied", { section: sec.name })
    }
    // Off before the type and the `#` are judged, as the file reader does.
    var split = _bulkSplitRuleFlags(collapsed)
    collapsed = split.value
    var children = split.children
    var override = split.override
    var choice = _bulkOwn(ctx.choices, String(lineNo)) ? ctx.choices[String(lineNo)] : null
    var chosen = choice && typeof choice.type === "string" ? choice.type : ""
    // Under no header a file has no type for the line: its value names one, or
    // the user does. A `#` line that names none is a note.
    var type = sec.type
    if (type === "") {
        var cls = ruleValueClass(_bulkClassifiedCore(collapsed))
        type = ruleTypeOfValueClass(cls)
        if (type === "") {
            if (hashed) return null
            if (cls !== "ambiguous") {
                row.value = collapsed
                return _bulkFail(row, "rules.paste.unrecognized")
            }
            row.options = ctx.apps ? ["zone", "application"] : ["zone"]
            if (row.options.indexOf(chosen) >= 0) type = chosen
        }
    }
    var marks = _bulkMarkers(collapsed, type === "domain" || type === "exact-ip")
    var value = marks.rest
    if (value === "") return null
    var quoted = type === "application" ? _unquoteProgramValue(value) : null
    if (quoted !== null) value = quoted
    if (hashed && quoted === null && !_bulkIsDisabledRuleValue(type, value)) return null
    row.value = storedRuleValue(type, value, children, override)
    row.enabled = !hashed
    if (marks.deny) row.route = "block"
    row.comment = comment
    if (type === "application"
            || sec.name.replace(/[A-Z]/g, function(c) { return c.toLowerCase() }) === "auto") {
        var provenance = _bulkProvenance(comment)
        if (provenance !== null) {
            row.comment = provenance.note
            row.originReason = provenance.reason
            row.originAnchor = provenance.anchor
            row.originAdded = provenance.added
        }
    }
    if (type === "") {
        row.status = "needs-type"
        row.key = "rules.paste.needs-type"
        row.action = "keep"
        return row
    }
    row.type = type
    if (sec.type === "" && type === "application" && !ctx.apps) {
        return _bulkFail(row, "rules.paste.apps-unsupported")
    }
    if (_bulkCodePoints(row.comment) > BULK_COMMENT_MAX_CHARS) {
        return _bulkFail(row, "rules.paste.comment-too-long",
            { max: String(BULK_COMMENT_MAX_CHARS) })
    }
    var denied = row.route === "block"
    row.verify = marks.verify && !denied
    var verdict = _bulkVerdict(ctx, row)
    if (verdict === null) return row
    // A value the verdict names another type for: that type, once picked.
    var target = verdict.level === "error" ? misplacedTargetType(verdict.key) : ""
    if (target !== "" && (ctx.apps || target !== "application")) {
        row.options = [target]
        if (chosen === target) {
            row.type = target
            row.value = storedRuleValue(target, value, children, override)
            row.verify = row.verify && (target === "domain" || target === "exact-ip")
            verdict = _bulkVerdict(ctx, row)
            if (verdict === null) return row
        }
    }
    if (verdict.level === "error") return _bulkFail(row, verdict.key, verdict.args)
    if (verdict.level === "warning") {
        row.status = "warning"
        row.key = verdict.key
        row.args = verdict.args
    } else if (marks.verify && denied) {
        // A deny takes no check: the `?` is dropped, as the form drops it.
        row.status = "warning"
        row.key = "dialog.rule.verify-deny"
    } else if (row.verify && valueIsIpv6Literal(row.type, row.value)) {
        row.verify = false
        row.status = "warning"
        row.key = "dialog.rule.verify-ipv6"
    } else {
        row.status = "ok"
    }
    return _bulkPlace(ctx, row, choice)
}

// Which rule a line names: type and value without `+children` / `+override`
// (`bulk_rules.rs::rule_identity`).
function _bulkRuleIdentity(type, value) {
    return type + "|" + withoutRuleFlags(value).toLowerCase()
}

// Where a judged row lands against the text so far and the rules there.
function _bulkPlace(ctx, row, choice) {
    var same = _bulkRuleIdentity(row.type, row.value)
    var key = same + "|" + row.route
    if (_bulkOwn(ctx.seen, key)) {
        var earlier = ctx.rows[ctx.seen[key]]
        // `?x` and `x` on one route are one rule, and the plain one wins, as
        // an import has it.
        if (!row.verify) earlier.verify = false
        row.status = "duplicate"
        row.key = "rules.paste.same-as-line"
        row.args = { line: String(earlier.line) }
        row.sameLine = earlier.line
        row.action = "drop"
        return row
    }
    if (_bulkOwn(ctx.seenValue, same)) {
        return _bulkFail(row, "rules.paste.conflicts-with-line",
            { line: String(ctx.rows[ctx.seenValue[same]].line) })
    }
    if (_bulkOwn(ctx.existingKey, key)) {
        row.status = "duplicate"
        row.key = "rules.paste.already-present"
        row.args = {}
        row.existing = ctx.existingKey[key]
        row.action = "drop"
    } else if (_bulkOwn(ctx.existingValue, same)) {
        var at = ctx.existingValue[same]
        row.status = "elsewhere"
        row.existing = at
        row.otherRoute = String(ctx.existing[at].route || "")
        row.key = row.otherRoute === "block" ? "rules.paste.already-denied"
            : "rules.paste.on-other-route"
        row.args = row.otherRoute === "block" ? {} : { route: row.otherRoute }
        row.move = !!(choice && choice.move === true)
        row.action = row.move ? "move" : "keep"
    } else if (row.originReason === "" && ctx.room >= 0 && ctx.adding >= ctx.room) {
        return _bulkFail(row, "rules.paste.over-limit")
    } else {
        // App-authored rules have a budget of their own.
        if (row.originReason === "") ctx.adding += 1
        row.action = "add"
    }
    ctx.seen[key] = ctx.rows.length
    ctx.seenValue[same] = ctx.rows.length
    return row
}

// What pasting `input.text` into the Add form amounts to. `input`: { text,
// route ("primary" | "secondary" | "block"), os, apps (application rules work
// here; absent means yes), existing: [{ type, value, route }], choices:
// { "<line>": { type, move } }, verdicts: { "<verdictKey>": { status,
// "message-key", args } }, room (rules that may still be added; absent or
// negative means no limit) }.
// Returns { rows, lines, excess, bound ("" | "lines" | "size"), add, move,
// keep, drop, remaining }: a row per rule line with its `action`, "add",
// "move", "keep" (stays in the field) or "drop" (already there), and
// `remaining`, the text the field keeps after an apply.
function planBulkRules(input) {
    var p = input || {}
    var text = p.text === undefined || p.text === null ? "" : String(p.text)
    if (text.charCodeAt(0) === 0xFEFF) text = text.substring(1)
    var ctx = {
        route: String(p.route || ""),
        os: String(p.os || ""),
        apps: p.apps !== false,
        existing: p.existing || [],
        choices: p.choices || {},
        verdicts: p.verdicts || {},
        room: typeof p.room === "number" && p.room >= 0 ? Math.floor(p.room) : -1,
        section: { name: "", type: "" },
        seen: Object.create(null),
        seenValue: Object.create(null),
        existingKey: Object.create(null),
        existingValue: Object.create(null),
        adding: 0,
        rows: []
    }
    for (var e = 0; e < ctx.existing.length; e += 1) {
        var ex = ctx.existing[e] || {}
        var same = _bulkRuleIdentity(canonicalRuleTypeSlug(ex.type), String(ex.value || ""))
        var key = same + "|" + String(ex.route || "")
        if (!_bulkOwn(ctx.existingKey, key)) ctx.existingKey[key] = e
        if (!_bulkOwn(ctx.existingValue, same)) ctx.existingValue[same] = e
    }
    var rows = ctx.rows
    var lines = 0
    var units = 0
    var bound = ""
    var cut = -1
    var pos = 0
    while (pos < text.length) {
        var nl = text.indexOf("\n", pos)
        var raw = text.substring(pos, nl < 0 ? text.length : nl)
        if (lines === BULK_MAX_LINES) { bound = "lines"; cut = pos; break }
        if (units + raw.length + 1 > BULK_MAX_UNITS) { bound = "size"; cut = pos; break }
        units += raw.length + 1
        lines += 1
        var row = _bulkLine(ctx, raw, lines)
        if (row !== null) rows.push(row)
        if (nl < 0) break
        pos = nl + 1
    }
    var plan = { rows: rows, lines: lines, excess: cut < 0 ? 0 : _bulkLineCount(text, cut),
        bound: bound, add: 0, move: 0, keep: 0, drop: 0, remaining: "" }
    var top = []
    var below = []
    var last = ""
    for (var i = 0; i < rows.length; i += 1) {
        plan[rows[i].action] += 1
        if (rows[i].action !== "keep") continue
        if (rows[i].section === "") {
            top.push(rows[i].text)
            continue
        }
        var head = "--- " + rows[i].section
        if (head !== last) below.push(head)
        last = head
        below.push(rows[i].text)
    }
    if (cut >= 0) {
        var rest = text.substring(cut)
        if (rest.charAt(rest.length - 1) === "\n") rest = rest.substring(0, rest.length - 1)
        var firstEnd = rest.indexOf("\n")
        var first = firstEnd < 0 ? rest : rest.substring(0, firstEnd)
        if (first.charCodeAt(first.length - 1) === 0x0D) first = first.substring(0, first.length - 1)
        var open = ctx.section.name === "" ? "" : "--- " + ctx.section.name
        if (open !== "" && open !== last && _bulkHeader(first) === "") below.push(open)
        below.push(rest)
    }
    plan.remaining = top.concat(below).join("\n")
    return plan
}

// One `{ "rule-type", "match-value", key }` per verdict the plan still waits for.
function bulkPendingVerdicts(plan) {
    var out = []
    var seen = Object.create(null)
    var rows = (plan && plan.rows) || []
    for (var i = 0; i < rows.length; i += 1) {
        var r = rows[i]
        if (r.status !== "pending" || seen[r.verdictKey]) continue
        seen[r.verdictKey] = true
        out.push({ "rule-type": r.type, "match-value": r.value, key: r.verdictKey })
    }
    return out
}

// ---- unsaved edits over rules changed elsewhere ----

function _copyRow(row) {
    var out = {}
    for (var k in row) out[k] = row[k]
    return out
}

// Whether two rows are the same rule with the same settings: the id is no
// part of it, and neither is the spelling of the type or the case of the value,
// which mergeKey folds too: a recased value is not a change.
function rowSameContent(a, b) {
    return !!a.enabled === !!b.enabled
        && canonicalRuleTypeSlug(a.ruleType) === canonicalRuleTypeSlug(b.ruleType)
        && String(a.matchValue || "").toLowerCase() === String(b.matchValue || "").toLowerCase()
        && String(a.targetRoute || "") === String(b.targetRoute || "")
        && !!a.verify === !!b.verify
        && String(a.comment || "") === String(b.comment || "")
        && String(a.originReason || "") === String(b.originReason || "")
        && String(a.originAnchor || "") === String(b.originAnchor || "")
        && String(a.originAdded || "") === String(b.originAdded || "")
}

function _firstByKey(rows) {
    var map = Object.create(null)
    for (var i = 0; i < rows.length; i += 1) {
        var key = mergeKey(rows[i])
        if (!(key in map)) map[key] = rows[i]
    }
    return map
}

// `rebase_edits` (nrr-client-logic): the user's edits (`edited`, made against
// `base`) laid over the `fresh` rules in force. A rule the user added, changed
// or deleted is added, changed or deleted in `fresh` too; everything else stays
// as `fresh` has it. Where both sides touched one rule the user's version wins
// and `conflicts` lists it, unless its mergeKey is in `keepTheirs`. Returns
// { rows, added, changed, removed, conflicts }; rows added have an empty id.
// Conflict kinds: changed-both, edited-but-deleted-elsewhere,
// deleted-but-changed-elsewhere, added-both.
function rebaseEdits(base, edited, fresh, keepTheirs) {
    base = base || []
    edited = edited || []
    fresh = fresh || []
    var keep = Object.create(null)
    var kept = keepTheirs || []
    for (var q = 0; q < kept.length; q += 1) keep[String(kept[q])] = true
    var baseByKey = _firstByKey(base)
    var editedByKey = _firstByKey(edited)
    var freshByKey = _firstByKey(fresh)
    var out = { rows: [], added: [], changed: [], removed: [], conflicts: [] }
    var dropped = Object.create(null)
    var seen = Object.create(null)
    var key, i

    for (i = 0; i < base.length; i += 1) {
        key = mergeKey(base[i])
        if (key in editedByKey || key in seen) continue
        seen[key] = true
        if (!(key in freshByKey)) continue
        var theirs = freshByKey[key]
        if (!rowSameContent(theirs, base[i])) {
            out.conflicts.push({ key: key, kind: "deleted-but-changed-elsewhere",
                mine: null, theirs: _copyRow(theirs) })
            if (keep[key]) continue
        }
        out.removed.push(_copyRow(theirs))
        dropped[key] = true
    }

    var at = Object.create(null)
    for (i = 0; i < fresh.length; i += 1) {
        key = mergeKey(fresh[i])
        if (key in dropped) continue
        if (!(key in at)) at[key] = out.rows.length
        out.rows.push(_copyRow(fresh[i]))
    }

    var done = Object.create(null)
    for (i = 0; i < edited.length; i += 1) {
        var mine = edited[i]
        key = mergeKey(mine)
        var before = (key in baseByKey) ? baseByKey[key] : null
        if ((before && rowSameContent(before, mine)) || key in done) continue
        done[key] = true
        var placed
        if (key in at) {
            var cur = out.rows[at[key]]
            if (rowSameContent(cur, mine)) continue
            var kind = ""
            if (before) { if (!rowSameContent(cur, before)) kind = "changed-both" }
            else kind = "added-both"
            if (kind !== "") {
                out.conflicts.push({ key: key, kind: kind,
                    mine: _copyRow(mine), theirs: _copyRow(cur) })
                if (keep[key]) continue
            }
            placed = _copyRow(mine)
            placed.id = cur.id
            out.rows[at[key]] = placed
            out.changed.push(_copyRow(placed))
        } else {
            if (before) {
                out.conflicts.push({ key: key, kind: "edited-but-deleted-elsewhere",
                    mine: _copyRow(mine), theirs: null })
                if (keep[key]) continue
            }
            placed = _copyRow(mine)
            placed.id = ""
            at[key] = out.rows.length
            out.rows.push(placed)
            out.added.push(_copyRow(placed))
        }
    }
    return out
}

// Plain copies of the fields a rebase compares and the wire needs: a model's
// own row objects change under the caller as the table is edited.
function rebaseSnapshot(rows) {
    var out = []
    for (var i = 0; i < _rowCount(rows); i += 1) {
        var r = _rowAt(rows, i)
        out.push({
            id: String(r.id || ""),
            enabled: !!r.enabled,
            ruleType: String(r.ruleType || ""),
            matchValue: String(r.matchValue || ""),
            targetRoute: String(r.targetRoute || ""),
            verify: !!r.verify,
            comment: String(r.comment || ""),
            originReason: String(r.originReason || ""),
            originAnchor: String(r.originAnchor || ""),
            originAdded: String(r.originAdded || "")
        })
    }
    return out
}

// `fresh` rows with the note a rule has in the sidecar, which the service's
// list does not carry: an empty note is filled from the same rule among
// `known` (the edited rows first, then the base).
function rebaseFreshWithNotes(fresh, known) {
    var notes = Object.create(null)
    for (var k = 0; k < known.length; k += 1) {
        for (var j = 0; j < known[k].length; j += 1) {
            var key = mergeKey(known[k][j])
            if (!(key in notes) && known[k][j].comment) notes[key] = String(known[k][j].comment)
        }
    }
    var out = []
    for (var i = 0; i < fresh.length; i += 1) {
        var row = _copyRow(fresh[i])
        var note = notes[mergeKey(row)]
        if (!row.comment && note) row.comment = note
        out.push(row)
    }
    return out
}

function _rebaseItem(row) {
    if (!row) return null
    return {
        "type-slug": String(row.ruleType || ""),
        value: String(row.matchValue || ""),
        route: routeBucket(row.targetRoute),
        action: String(row.targetRoute) === "block" ? "block"
            : (rowIsVerify(row) ? "verify-primary" : "route"),
        enabled: !!row.enabled,
        comment: String(row.comment || "")
    }
}

// A `rebaseEdits` result as the merge window shows it: what the user added,
// changed and deleted, and the rules both sides touched as conflicts (file
// side: the user's version, service side: the one in force).
function rebaseMergeView(result) {
    var inConflict = Object.create(null)
    var view = { "file-only": [], "service-only": [], conflicts: [], changed: [],
        removed: [], "normalized-duplicates": [], noop: false }
    var i
    for (i = 0; i < result.conflicts.length; i += 1) {
        var c = result.conflicts[i]
        inConflict[c.key] = true
        var any = c.mine || c.theirs
        view.conflicts.push({
            "identity-key": c.key,
            "type-slug": String(any.ruleType || ""),
            value: String(any.matchValue || ""),
            kind: c.kind,
            file: _rebaseItem(c.mine),
            service: _rebaseItem(c.theirs)
        })
    }
    var parts = [["added", "file-only"], ["changed", "changed"], ["removed", "removed"]]
    for (var p = 0; p < parts.length; p += 1) {
        var rows = result[parts[p][0]]
        for (i = 0; i < rows.length; i += 1) {
            if (!(mergeKey(rows[i]) in inConflict)) view[parts[p][1]].push(_rebaseItem(rows[i]))
        }
    }
    view.noop = view["file-only"].length + view.changed.length + view.removed.length
        + view.conflicts.length === 0
    return view
}
