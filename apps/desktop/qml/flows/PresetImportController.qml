import QtQuick 2.15
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

// Non-visual controller owning the preset-import subsystem: canonical parse
// (via the launcher `preset.parse` RPC), the review-dialog decision apply,
// passthrough-section reclassify/persist, replace/merge into `rulesModel`, the
// offline fallback, and the online dry-run -> review -> activate flow (single
// route + both-routes). Extracted from Main.qml (thin-shell rule). The shell
// keeps the shared review STATE (`pendingPresetImportState`, `_activeReviewKind`,
// `_pendingPresetReview`, `_offlineRulesPendingPush`) and the general rules-model
// utilities (`_maxRuleNumericId`, `_renumberRuleIdsSequential`), reached via
// `root`. Main.qml instantiates one, injects itself as `root`, and exposes it as
// `root.presetImportController`; FirstRunWindow / LoadListWindow / RulesSection /
// PresetSettings drive `start*ReviewFlow` through it. RPC goes through `root.rpc`;
// `nrrNativeBridge` is a global QML context property, referenced bare.
QtObject {
    id: presetImportController
    property var root

    //  — bundled/shipped presets (repo `presets/` tree,
    // `configs/presets/builtin-demo/`) are READ-ONLY sources. A save-path
    // binding (`lastSavedPath*`) must never point inside them — that let a
    // country-preset import at first-run, or a Load from the bundled-tree
    // fallback in RulesSection, silently rebind "Save to file" onto a file
    // inside the app's own install/repo tree, so the user's edits landed
    // there instead of a file they own. Callers that are about to call
    // `updatePrefs({ lastSavedPath... })` after an import must gate the
    // call through this check first.
    // The test itself (including the "the user's own folder is never factory"
    // exception) lives in `window.isFactoryPresetPath` — one definition for the
    // three controllers that ask this question.
    function _isBundledPresetPath(path) {
        return root.isFactoryPresetPath(path)
    }

    /// Bind `lastSavedPath*` to the file(s) this import came from, for every
    /// route the import covered. Reading a file into the app IS a sync with
    /// it — the direction (load vs save) does not matter — so this runs on
    /// every terminal branch of an import, INCLUDING "Nothing to apply". That
    /// branch used to return early and skip the binding entirely, leaving the
    /// Rules screen showing no source for a set the user had just loaded.
    ///
    /// Two prefs per route, with deliberately different semantics:
    ///   - `lastSavedPath*` — the SAVE-target binding. A bundled-tree path is
    ///     cleared rather than bound (a read-only source is not a save
    ///     target), and a stale pref from an earlier session must not survive
    ///     this import either way.
    ///   - `lastLoadedPath*` — display-only "where did these rules come
    ///     from". Always the REAL path, bundled tree included: hiding the
    ///     source of a shipped preset the user just loaded is a defect, not
    ///     safety (the write guards live on the save paths, not here).
    /// The just-loaded content matches the file on disk, so the per-route
    /// bound-file dirty flag resets too.
    ///
    /// `emitPrefs()` at the end: `updatePrefs` only mutates the in-memory
    /// object, and the round-trip to the launcher used to happen on graceful
    /// close only — a crash or a kill between import and exit lost the
    /// binding.
    function _bindImportedSourcePaths(state) {
        if (!state) return
        var bound = false
        function bind(route, path) {
            if (!path || String(path) === "") return
            var value = _isBundledPresetPath(path) ? "" : String(path)
            if (route === "primary") {
                root.updatePrefs({ lastSavedPathPrimary: value,
                                   lastLoadedPathPrimary: String(path) })
            } else {
                root.updatePrefs({ lastSavedPathSecondary: value,
                                   lastLoadedPathSecondary: String(path) })
            }
            bound = true
        }
        var target = String(state.targetRoute || "")
        if (target === "both") {
            bind("primary", state.primaryPath)
            bind("secondary", state.secondaryPath)
            root._filesSyncDirtyPrimary = false
            root._filesSyncDirtySecondary = false
        } else if (target === "primary") {
            bind("primary", state.sourcePath)
            root._filesSyncDirtyPrimary = false
        } else if (target === "secondary") {
            bind("secondary", state.sourcePath)
            root._filesSyncDirtySecondary = false
        }
        if (bound) root.emitPrefs()
    }

    // Async canonical-txt parser dispatched
    // through the launcher's `preset.parse` local RPC. Replaces the
    // JS-side `_parseCanonicalRulesText` that lived in this file. The parser itself now lives in
    // `nrr_shared::preset_parser` (Rust), reachable via
    // `nrrNativeBridge.rpcPresetParse`.
    //
    // `callback(result)` is called exactly once with:
    //   {
    //     rows:                [<rulesModel-shaped objects>],
    //     nextId:              <next free numeric R-id>,
    //     passthrough:         [<PassthroughBlock>...],
    //     duplicateSections:   [<DuplicateGroup>...]
    //   }
    //
    // The rows are already rulesModel-shape (matchValue passed
    // through `_unicodeDecodeHost` for hostlike types, R-NNNN id
    // assigned based on `startId`). Passthrough and duplicate-section
    // diagnostics are surfaced verbatim from the parser for callers
    // that want to wire them into the sidecar or the review
    // dialog.
    function _parseCanonicalRulesAsync(text, targetRoute, startId, callback) {
        var fallback = { rows: [], nextId: Math.max(1, parseInt(startId || 1)),
                         passthrough: [], duplicateSections: [] }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcPresetParse !== "function") {
            // No bridge available (preview/mock environment). Surface
            // an empty result rather than crashing — the import paths
            // handle empty rows gracefully.
            console.log("preset.parse bridge unavailable — returning empty result")
            callback(fallback)
            return
        }
        var corr = nrrNativeBridge.rpcPresetParse(String(text || ""))
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (!ok) {
                console.log("preset.parse failed:", errorCode, errorMessage)
                callback(fallback)
                return
            }
            callback(_buildRulesModelRowsFromParseResult(
                payload, targetRoute, startId))
        })
    }

    // Apply user decisions from
    // PresetImportReviewDialog to the pending parsed import. The
    // closure stored in `_pendingPresetReview.applyAndPersist` is the
    // hook back into `_refreshRulesAfterPresetImport`'s flow — once
    // we've mutated the parsedRowsByRoute / passthroughByRoute maps
    // in place per the user's choices, we just invoke it to apply.
    //
    // `decisions.duplicates[sectionName]` is one of:
    //   "merge"     — keep all occurrences (default, no-op)
    //   "last-wins" — for passthrough: keep only last block with name
    //                 (no-op for known sections — rules are merged)
    //   "ignore"    — drop the section entirely
    //
    // `decisions.reclassify[sectionName]` is one of:
    //   "passthrough" — leave in passthrough (default, no-op)
    //   "zones" / "domains" / "ip" / "windows" — convert each line
    //                 into a rule of that type, drop the passthrough block
    //   "skip"      — drop the passthrough block entirely
    function _applyPresetReviewDecisions(decisions) {
        var ctx = root._pendingPresetReview
        if (!ctx) return
        root._pendingPresetReview = null

        var dups = (decisions && decisions.duplicates) || {}
        var reclass = (decisions && decisions.reclassify) || {}

        // Apply duplicate decisions to passthrough first.
        var routes = ["primary", "secondary"]
        for (var ri = 0; ri < routes.length; ri += 1) {
            var route = routes[ri]
            var blocks = ctx.passthroughByRoute[route] || []
            // Group blocks by section name to know which are
            // duplicates within this route.
            var byName = {}
            for (var i = 0; i < blocks.length; i += 1) {
                var b = blocks[i]
                var n = String(b["section-name"] || "")
                if (n === "") continue
                if (!byName.hasOwnProperty(n)) byName[n] = []
                byName[n].push(i)
            }
            // Build a "keep this index?" predicate based on the
            // dup decision for each section name.
            var keep = {}
            for (var k = 0; k < blocks.length; k += 1) keep[k] = true
            for (var name in byName) {
                if (!byName.hasOwnProperty(name)) continue
                if (byName[name].length < 2) continue
                var choice = String(dups[name] || "merge")
                if (choice === "merge") {
                    // No-op — all kept.
                } else if (choice === "last-wins") {
                    // Drop everything except the last occurrence.
                    var arr = byName[name]
                    for (var li = 0; li < arr.length - 1; li += 1) {
                        keep[arr[li]] = false
                    }
                } else if (choice === "ignore") {
                    for (var ii = 0; ii < byName[name].length; ii += 1) {
                        keep[byName[name][ii]] = false
                    }
                }
            }
            // Now apply reclassify decisions. The user picked a
            // target rule type for each unknown section name; we
            // convert the section's raw_text lines into rules and
            // drop the passthrough block.
            var filteredBlocks = []
            for (var fi = 0; fi < blocks.length; fi += 1) {
                if (!keep[fi]) continue
                var blk = blocks[fi]
                var sectionName = String(blk["section-name"] || "")
                var ch = String(reclass[sectionName] || "passthrough")
                if (ch === "passthrough") {
                    filteredBlocks.push(blk)
                } else if (ch === "skip") {
                    // Drop entirely.
                } else {
                    // Reclassify to a known type: convert lines to
                    // rules and append to parsedRowsByRoute.
                    var rules = ctx.parsedRowsByRoute[route] || []
                    var converted = _reclassifyPassthroughBlock(blk, ch, route, rules.length + 1)
                    ctx.parsedRowsByRoute[route] = rules.concat(converted)
                }
            }
            ctx.passthroughByRoute[route] = filteredBlocks
        }

        ctx.applyAndPersist()
    }

    /// Convert each non-blank, non-comment line of a passthrough
    /// block's raw_text into a ParsedRule of the given target type.
    /// Caller is responsible for assigning final R-NNNN ids; we
    /// emit rows in the same shape `_buildRulesModelRowsFromParseResult`
    /// uses (matchValue passed through `_unicodeDecodeHost` for
    /// hostlike types). Lines we can't make sense of in isolation
    /// are still emitted — the snapshot-side validator will mark
    /// them as invalid in the rules table.
    function _reclassifyPassthroughBlock(block, targetSlug, targetRoute, startId) {
        var raw = String(block["raw-text"] || "")
        var lines = raw.split("\n")
        var rows = []
        var nextId = Math.max(1, parseInt(startId || 1))
        // Map the reclassify dropdown's value to the parser's
        // rule-type slug (the dropdown uses "ip" / "windows" while
        // the parser uses "exact-ip" / "application").
        var ruleType = (targetSlug === "ip") ? "exact-ip"
                     : (targetSlug === "windows") ? "application"
                     : (targetSlug === "zones") ? "zone"
                     : (targetSlug === "domains") ? "domain"
                     : ""
        if (ruleType === "") return rows
        for (var i = 0; i < lines.length; i += 1) {
            var raw_line = lines[i].replace(/\s+$/, "")
            if (raw_line === "") continue
            // Skip comment lines — there's no rule there.
            if (raw_line.charAt(0) === "#") continue
            // Inline comment split.
            var hash = raw_line.indexOf("#")
            var matchValue = raw_line
            var comment = ""
            if (hash >= 0) {
                matchValue = raw_line.substring(0, hash)
                comment = raw_line.substring(hash + 1)
            }
            matchValue = matchValue.replace(/^\s+|\s+$/g, "")
            comment = comment.replace(/^\s+|\s+$/g, "")
            if (matchValue === "") continue
            var displayValue = Rules.isHostlikeRuleType(ruleType)
                ? root._unicodeDecodeHost(matchValue)
                : matchValue
            rows.push({
                id: "R-" + ("0000" + String(nextId)).slice(-4),
                enabled: true,
                ruleType: ruleType,
                ruleTypeTitle: root.ruleTypeLabel(ruleType),
                matchValue: displayValue,
                targetRoute: String(targetRoute),
                comment: comment
            })
            nextId += 1
        }
        return rows
    }

    // Format the "preserved sections" suffix
    // appended to import status banners when the user's preset
    // contained foreign-OS / Pro sections we passed through. Empty
    // when no passthrough was captured (the suffix simply disappears).
    function _formatImportPassthroughSuffix(passthroughByRoute) {
        // Aggregate sections across routes — `{name: {lines, routes:[]}}`.
        // We sum line counts when the same section appears in both
        // primary and secondary (rare in practice — Linux sections
        // usually only land in one of the two preset files).
        var aggregated = {}
        var order = []
        for (var route in passthroughByRoute) {
            if (!passthroughByRoute.hasOwnProperty(route)) continue
            var blocks = passthroughByRoute[route] || []
            for (var i = 0; i < blocks.length; i += 1) {
                var block = blocks[i] || {}
                var name = String(block["section-name"] || "")
                if (name === "") continue
                if (!aggregated.hasOwnProperty(name)) {
                    aggregated[name] = 0
                    order.push(name)
                }
                aggregated[name] += parseInt(block["content-lines"] || 0)
            }
        }
        if (order.length === 0) return ""
        order.sort()
        var parts = []
        for (var j = 0; j < order.length; j += 1) {
            var n = order[j]
            parts.push(root.tr("status.preset-import-section-entry",
                "{name} ({count} lines)")
                .replace("{name}", n)
                .replace("{count}", String(aggregated[n])))
        }
        return " " + root.tr("status.preset-import-passthrough-suffix",
            "Preserved foreign-OS sections: {sections}.")
            .replace("{sections}", parts.join(", "))
    }

    // Convert a list of parser PassthroughBlocks (as wire JSON) into
    // the `{sectionName: rawText}` map the sidecar's
    // `passthrough.write` opcode expects, then dispatch the write.
    // Called once per route after a successful import. Last-wins on
    // duplicate section_name within the same file — duplicates will
    // be surfaced to the user via the review dialog.
    function _writeImportedPassthrough(route, blocks) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarPassthroughWrite !== "function") {
            return
        }
        var sections = {}
        for (var i = 0; i < blocks.length; i += 1) {
            var block = blocks[i] || {}
            var name = String(block["section-name"] || "")
            if (name === "") continue
            sections[name] = String(block["raw-text"] || "")
        }
        // Atomic replace via the sidecar handler: even an empty map
        // clears any previously-recorded passthrough for this route,
        // which is the right behaviour when the user re-imports a
        // preset that no longer has foreign-OS sections.
        // Register a discard callback for the returned correlation id so
        // the response is consumed instead of surfacing as a scary "rpc: unknown
        // correlation id" in the launcher log (this write is otherwise fire-and-forget).
        var corr = nrrNativeBridge.rpcSidecarPassthroughWrite(route, sections)
        root.rpc.registerRpcCallback(corr, function() {})
    }

    // Map a `preset.parse` response payload to the rulesModel row
    // shape callers expect. Splits the Punycode→Unicode boundary
    // conversion from the parser proper (the Rust parser deliberately
    // doesn't know about it — see preset_parser.rs).
    function _buildRulesModelRowsFromParseResult(payload, targetRoute, startId) {
        var result = (payload && payload.result) || {}
        var rules = result.rules || []
        var rows = []
        var nextId = Math.max(1, parseInt(startId || 1))
        for (var i = 0; i < rules.length; i += 1) {
            var r = rules[i]
            var ruleType = String(r["rule-type"] || "")
            var matchValue = String(r["match-value"] || "")
            // Boundary conversion (inbound): legacy rule files may
            // carry ACE/Punycode on host-like types; decode to Unicode
            // so the table displays the human form. ASCII passes
            // through unchanged.
            var displayValue = Rules.isHostlikeRuleType(ruleType)
                ? root._unicodeDecodeHost(matchValue)
                : matchValue
            rows.push({
                id: "R-" + ("0000" + String(nextId)).slice(-4),
                enabled: !!r.enabled,
                ruleType: ruleType,
                ruleTypeTitle: root.ruleTypeLabel(ruleType),
                matchValue: displayValue,
                // A parsed `+block` rule shows as the "block" route regardless
                // of which file (primary/secondary) the import targeted.
                targetRoute: (r.blocked === true) ? "block" : String(targetRoute),
                comment: String(r.comment || ""),
                // Provenance the parser lifted out of the `--- Auto` section's
                // inline comment. Kept as three scalar roles (matching the
                // service snapshot rows) so an imported app-authored rule
                // still says who wrote it and why — and so re-submitting the
                // model does not turn it back into a user-authored rule.
                originReason: (r.origin && r.origin.reason !== undefined)
                    ? String(r.origin.reason) : "",
                originAnchor: (r.origin && r.origin.anchor !== undefined)
                    ? String(r.origin.anchor) : "",
                originAdded: (r.origin && r.origin.added !== undefined)
                    ? String(r.origin.added) : ""
            })
            nextId += 1
        }
        return {
            rows: rows,
            nextId: nextId,
            passthrough: result.passthrough || [],
            duplicateSections: result["duplicate-sections"] || []
        }
    }

    // Refresh `rulesModel` after a successful preset
    // import (online activation OR offline fallback). Honours
    // `state.mode`:
    //   - "replace" (default): clear-target-then-append. Both-routes
    //                          clears everything; single-route clears
    //                          only that route's rows.
    //   - "merge":             keep all existing rows; append rows
    //                          from the import that don't match any
    //                          existing (ruleType, matchValue,
    //                          targetRoute) triple. Comments / disabled
    //                          state on the existing row win — the
    //                          user's manual edits are preserved.
    function _refreshRulesAfterPresetImport(state, options) {
        if (!state) return
        var opts = options || {}
        // Online-success callers pass `skipApply: true` because the
        // service-side activation will fan back to us via the snapshot
        // push; touching rulesModel locally would race with the push.
        // Offline callers (when the service is unreachable) need
        // `skipApply: false` so the rules show up immediately.
        var skipApply = !!opts.skipApply
        var onComplete = typeof opts.onComplete === "function" ? opts.onComplete : null
        var mode = String(state.mode || "replace")
        var target = String(state.targetRoute || "")
        if (target !== "both" && target !== "primary" && target !== "secondary") {
            return
        }
        // Async parse via launcher RPC.
        // For the "both" target we need to await two parse results
        // before applying the merge/replace, so a small counter
        // serialises them. The parser is fast (sub-ms even for large
        // presets) so the user-visible delay
        // between this call and `_applyImportMerge`/`_applyImportReplace`
        // is dominated by the RPC round-trip (≈1–3 ms on the named
        // pipe — well under any UI animation budget).
        var parsedRowsByRoute = {}
        var passthroughByRoute = {}
        var duplicatesByRoute = {}
        var pending = (target === "both") ? 2 : 1
        // Inner "do the work" closure — invoked either immediately
        // from finalise() (no review needed) or after the user
        // confirms PresetImportReviewDialog.
        var applyAndPersist = function() {
            if (!skipApply) {
                if (mode === "merge") {
                    _applyImportMerge(parsedRowsByRoute)
                } else {
                    _applyImportReplace(target, parsedRowsByRoute)
                }
            }
            // Persist passthrough sections
            // captured by the parser. Per-route atomic replace, fire
            // and forget (write completes in milliseconds, well before
            // the user could pick Export in the file dialog).
            // Duplicates are not yet surfaced to the user in the review
            // dialog; for now last-wins on section_name collision
            // inside one file matches the QML pre-migration behaviour.
            var passthroughRoutes = (target === "both")
                ? ["primary", "secondary"]
                : [target]
            for (var pi = 0; pi < passthroughRoutes.length; pi += 1) {
                var pr = passthroughRoutes[pi]
                _writeImportedPassthrough(pr, passthroughByRoute[pr] || [])
            }
            // Surface the summary back to the
            // caller so it can compose the status-banner text with
            // counts the user can actually verify ("Imported 67 rules,
            // preserved Linux (12 lines), MacOS (8 lines)"). The
            // callback receives an aggregate across all touched
            // routes; the caller decides how to format/localise it.
            if (typeof onComplete === "function") {
                var rulesCount = 0
                for (var rk in parsedRowsByRoute) {
                    if (parsedRowsByRoute.hasOwnProperty(rk)) {
                        rulesCount += (parsedRowsByRoute[rk] || []).length
                    }
                }
                onComplete({
                    rulesCount: rulesCount,
                    passthroughByRoute: passthroughByRoute,
                    duplicatesByRoute: duplicatesByRoute,
                    target: target,
                    mode: mode
                })
            }
        }

        // Gate before applyAndPersist on
        // user input when the parser flagged ambiguity. Opens the
        // review dialog with aggregated diagnostics across all
        // touched routes; the user's decisions drive duplicate-merge
        // policy and reclassify of unknown sections.
        var finalise = function() {
            pending -= 1
            if (pending > 0) return
            var aggregatedDuplicates = []
            var aggregatedUnknowns = []
            var seenDup = {}
            var seenUnk = {}
            for (var rk in duplicatesByRoute) {
                if (!duplicatesByRoute.hasOwnProperty(rk)) continue
                var dups = duplicatesByRoute[rk] || []
                for (var di = 0; di < dups.length; di += 1) {
                    var d = dups[di] || {}
                    var dn = String(d["section-name"] || "")
                    if (dn === "" || seenDup[dn]) continue
                    seenDup[dn] = true
                    aggregatedDuplicates.push(d)
                }
            }
            for (var rk2 in passthroughByRoute) {
                if (!passthroughByRoute.hasOwnProperty(rk2)) continue
                var blocks = passthroughByRoute[rk2] || []
                for (var bi = 0; bi < blocks.length; bi += 1) {
                    var b = blocks[bi] || {}
                    var bn = String(b["section-name"] || "")
                    // Linux / MacOS are well-known foreign-OS sections
                    // with established passthrough semantics — don't
                    // pester the user about them. Surface every other
                    // unknown for reclassification (Cidr, Ports,
                    // user-named custom sections, etc.).
                    if (bn === "" || bn === "Linux" || bn === "MacOS") continue
                    if (seenUnk[bn]) continue
                    seenUnk[bn] = true
                    aggregatedUnknowns.push(b)
                }
            }
            var needsReview = aggregatedDuplicates.length > 0
                || aggregatedUnknowns.length > 0
            if (!needsReview) {
                applyAndPersist()
                return
            }
            // Stash the in-flight state on root so the dialog's
            // approved/cancelled handlers can reach it.
            root._pendingPresetReview = {
                parsedRowsByRoute: parsedRowsByRoute,
                passthroughByRoute: passthroughByRoute,
                duplicatesByRoute: duplicatesByRoute,
                target: target,
                mode: mode,
                applyAndPersist: applyAndPersist
            }
            root.presetImportReviewDialog.duplicates = aggregatedDuplicates
            root.presetImportReviewDialog.unknowns = aggregatedUnknowns
            root.presetImportReviewDialog.open()
        }

        var parseRoute = function(route, b64) {
            _parseCanonicalRulesAsync(
                root._b64ToUtf8(b64 || ""),
                route,
                1,
                function(result) {
                    parsedRowsByRoute[route] = result.rows
                    passthroughByRoute[route] = result.passthrough
                    duplicatesByRoute[route] = result.duplicateSections
                    finalise()
                }
            )
        }
        if (target === "both") {
            parseRoute("primary", state.primaryBytesB64)
            parseRoute("secondary", state.secondaryBytesB64)
        } else {
            parseRoute(target, state.bytesB64)
        }
    }

    function _applyImportReplace(target, parsedRowsByRoute) {
        // [perf] Temporary instrumentation — times the synchronous file-import
        // append (the offline path that populates ~300 rows in one burst). If
        // this dominates "rules take long to display", convert to the chunked
        // `_appendRowsChunked` path the service refetch uses. Remove once the
        // populate cost is characterised.
        console.time("[perf] _applyImportReplace")
        if (target === "both") {
            Pure.clearModel(root.rulesModel)
        } else {
            for (var k = root.rulesModel.count - 1; k >= 0; k -= 1) {
                if (String(root.rulesModel.get(k).targetRoute || "") === target) {
                    root.rulesModel.remove(k)
                }
            }
        }
        var maxN = root._maxRuleNumericId()
        var nextId = maxN + 1
        var routes = (target === "both") ? ["primary", "secondary"] : [target]
        for (var i = 0; i < routes.length; i += 1) {
            var rows = parsedRowsByRoute[routes[i]] || []
            for (var j = 0; j < rows.length; j += 1) {
                var row = rows[j]
                row.id = "R-" + ("0000" + String(nextId)).slice(-4)
                row.aceMatchValue = root._aceLowerForSearch(row.matchValue)
                root.rulesModel.append(row)
                // Preset comments persist via sidecar.
                // Import in Replace mode OVERWRITES any prior comment
                // for the same signature (spec'd behaviour — no merge
                // for the simpler mental model).
                if (String(row.comment || "") !== "") {
                    root._sidecarWriteCommentForRow(row)
                }
                nextId += 1
            }
        }
        console.timeEnd("[perf] _applyImportReplace")
    }

    function _applyImportMerge(parsedRowsByRoute) {
        // Build a Set of existing (ruleType, matchValue, targetRoute)
        // triples so we skip duplicates in O(n+m).
        var seen = {}
        for (var k = 0; k < root.rulesModel.count; k += 1) {
            var r = root.rulesModel.get(k)
            seen[Rules.mergeKey(r)] = true
        }
        var nextId = root._maxRuleNumericId() + 1
        var routes = ["primary", "secondary"]
        for (var i = 0; i < routes.length; i += 1) {
            var rows = parsedRowsByRoute[routes[i]] || []
            for (var j = 0; j < rows.length; j += 1) {
                var row = rows[j]
                var key = Rules.mergeKey(row)
                if (seen[key]) continue
                row.id = "R-" + ("0000" + String(nextId)).slice(-4)
                row.aceMatchValue = root._aceLowerForSearch(row.matchValue)
                root.rulesModel.append(row)
                // Merge mode: only NEW rules are
                // appended (existing ones with the same signature stay
                // untouched, comment and all). Write the new row's
                // comment so the next snapshot bind can recover it.
                if (String(row.comment || "") !== "") {
                    root._sidecarWriteCommentForRow(row)
                }
                seen[key] = true
                nextId += 1
            }
        }
    }


    // Offline / disconnected import fallback.
    //
    // When the service is stopped or not installed, the
    // `rpcMutationSubmit("preset-import", …, dry-run)` call fails with
    // `transport-disconnected`. Without this fallback the user's
    // pick-and-import gesture silently dies into `statusLine`. Per UX
    // requirement: "rules MUST appear in GUI in any case; the service
    // can start later".
    //
    // We populate `rulesModel` from the imported bytes directly,
    // record the source paths in prefs (so the close-flow's
    // SaveBeforeCloseDialog still knows where to write), and mark the
    // section dirty so a future `Save & review…` can push the new
    // revision once the service is reachable.
    function _applyPresetImportOffline(state, reasonLabel) {
        if (!state) return
        _refreshRulesAfterPresetImport(state, {
            // Offline path applies rules locally — there's no service
            // to fan them back via snapshot push, so we own the GUI's
            // copy of the rules.
            skipApply: false,
            onComplete: function(summary) {
                // Compose status with the
                // imported-rules count and any preserved-passthrough
                // suffix. Setting statusLine inside the callback
                // (rather than after the call) guarantees the banner
                // reflects the actual import outcome, not a
                // "started-then-finished" gap that the async parser
                // flow would otherwise expose.
                var base = root.tr("status.preset-import-offline",
                    "Imported {count} rules into the GUI. Service is unreachable — start the service and use 'Save and review...' to push them.")
                    .replace("{count}", String(summary.rulesCount))
                root.statusLine = base + _formatImportPassthroughSuffix(summary.passthroughByRoute)
                // Mark the offline import on disk so it survives BOTH a
                // mid-session service start (the post-connect backlog dialog
                // offers to apply it) AND a full GUI restart under admin (the
                // cold-start collect finds the marker). Mirrors what
                // offline rule EDITS already do via `startOfflineApplyFlow`;
                // preset import was the missing case. `sha256Hex` is sync, and
                // the model is fully populated here (the offline apply path is
                // synchronous, unlike the chunked service refetch).
                if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                        && typeof nrrNativeBridge.sha256Hex === "function"
                        && typeof nrrNativeBridge.rpcSidecarPendingApplyWrite === "function") {
                    var parkJson = root._buildRulesJsonFromModel()
                    // Skip parking on a serializer failure (falsy return) —
                    // the imported rows stay in the model, only the on-disk
                    // park is skipped.
                    if (parkJson) {
                        var parkHash = nrrNativeBridge.sha256Hex(parkJson)
                        root._parkPendingApply(parkJson, parkHash, root.rulesModel.count)
                        root._offlineRulesPendingPush = true
                    }
                }
            }
        })
        _bindImportedSourcePaths(state)
        // Don't mark dirty in offline mode. The rules
        // were imported FROM files and `lastSavedPath*` now points to
        // them — there's no server state to diverge from. Marking
        // dirty caused the UnsavedChangesGuard to nag the user with
        // Cancel/Discard prompts on every section navigation, which
        // is the opposite of what they want after a fresh import.
        // When the service comes online, the user can push manually
        // via the Rules toolbar's "Save and review..." button.
        root.setUnsavedChanges("rules", false)
    }


    /// Kicks off the dry-run pass for PresetImport.
    /// `targetRoute` ∈ {"primary","secondary"}. `bytesB64` is the
    /// already-base64-wrapped preset file body (read by
    /// `nrrNativeBridge.readFileBytes`). `sourcePath` is stashed so
    /// the review flow can save it into `UiPreferences::last_saved_path_<role>`.
    function startPresetImportReviewFlow(targetRoute, bytesB64, sourcePath, mode) {
        if (!root.bridgeAvailable) {
            console.log("preset-import: bridge unavailable, aborting")
            return
        }
        var corr = "preset-import-" + Date.now() + "-" + Math.floor(Math.random() * 1e6)
        var payload = {
            "include-child-processes": false,
            "import-only-active": root.importOnlyActiveSession,
            "correlation-id": corr
        }
        if (String(targetRoute) === "primary") {
            payload["primary-bytes-b64"] = String(bytesB64 || "")
        } else {
            payload["secondary-bytes-b64"] = String(bytesB64 || "")
        }
        root.pendingPresetImportState = {
            targetRoute: String(targetRoute || ""),
            bytesB64: String(bytesB64 || ""),
            sourcePath: String(sourcePath || ""),
            // "replace" (default) clears the target
            // route(s) before applying; "merge" keeps existing rows
            // and skips (ruleType, matchValue, targetRoute) dups.
            mode: (String(mode || "replace") === "merge") ? "merge" : "replace",
            correlationId: corr,
            summary: null,
            confirmationToken: ""
        }
        root._activeReviewKind = "preset-import"
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "preset-import", payload, true /* dryRun */, ""
        )
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("preset-import: dry-run failed:", code, msg)
                if (String(code) === "transport-disconnected") {
                    _applyPresetImportOffline(root.pendingPresetImportState, String(code))
                    return
                }
                var label = (typeof root.ipcErrorLabel === "function")
                    ? root.ipcErrorLabel(String(code || "unknown"))
                    : String(code || "unknown")
                root.statusLine = root.tr("status.preset-import-dry-run-failed",
                    "Preset import dry-run failed: ") + label
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            var token = (p && p["confirmation-token"]) || ""
            // Re-importing a preset that already
            // matches the active rules yields an empty diff (content-based
            // diff, domain fix same day). Surface a plain notice instead of an
            // empty review dialog.
            if (Pure.reviewSummaryIsEmpty(summary)) {
                // "Nothing to apply" still means the file was READ and its
                // rules match what is active — the app IS in sync with that
                // file, so bind it as the route's source. Skipping this made
                // re-loading an already-active set look like it did nothing.
                _bindImportedSourcePaths(root.pendingPresetImportState)
                root.showNotice(
                    root.tr("dialog.nothing-to-apply.title", "Nothing to apply"),
                    root.tr("dialog.nothing-to-apply.body",
                        "There are no changes to apply — the current rules already "
                        + "match what is active."))
                return
            }
            root.pendingPresetImportState = Object.assign({}, root.pendingPresetImportState, {
                summary: summary,
                confirmationToken: token
            })
            root.reviewDiffDialog.summary = summary
            // Preset import is per-principal (user-scoped,
            // non-elevated): the service scopes it to the caller SID, so
            // there's no administrator banner for a normal user's import.
            root.reviewDiffDialog.lacksElevation = false
            root.reviewDiffDialog.sessionElevated = false
            // Clear any stale `readOnly: true` left by a
            // prior `_openPendingApplyPreview` (drift "show differences"),
            // otherwise the import review opens without an Apply button.
            root.reviewDiffDialog.readOnly = false
            root.reviewDiffDialog.open()
        })
    }

    /// Both-routes variant for the first-run wizard
    /// and country-preset / builtin-demo paths. Differs from
    /// `startPresetImportReviewFlow` only in payload assembly: both
    /// byte fields are populated so the server-side
    /// `PresetImportTarget::BothRoutes` branch fires, producing one
    /// revision covering both routes.
    function startBothRoutesPresetImportReviewFlow(primaryBytesB64, secondaryBytesB64, primaryPath, secondaryPath) {
        if (!root.bridgeAvailable) {
            console.log("preset-import-both: bridge unavailable, aborting")
            return
        }
        var corr = "preset-import-both-" + Date.now() + "-" + Math.floor(Math.random() * 1e6)
        var payload = {
            "include-child-processes": false,
            "import-only-active": root.importOnlyActiveSession,
            "correlation-id": corr
        }
        if (primaryBytesB64) {
            payload["primary-bytes-b64"] = String(primaryBytesB64)
        }
        if (secondaryBytesB64) {
            payload["secondary-bytes-b64"] = String(secondaryBytesB64)
        }
        // Store both paths through `targetRoute` = "both"; the
        // execute path special-cases it. `bytesB64` carries the
        // primary for re-trigger fallback (retry flow uses single-
        // route only since it doesn't yet have a two-path
        // re-issue helper).
        root.pendingPresetImportState = {
            targetRoute: "both",
            bytesB64: String(primaryBytesB64 || secondaryBytesB64 || ""),
            sourcePath: String(primaryPath || secondaryPath || ""),
            primaryBytesB64: String(primaryBytesB64 || ""),
            secondaryBytesB64: String(secondaryBytesB64 || ""),
            primaryPath: String(primaryPath || ""),
            secondaryPath: String(secondaryPath || ""),
            correlationId: corr,
            summary: null,
            confirmationToken: ""
        }
        root._activeReviewKind = "preset-import"
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "preset-import", payload, true /* dryRun */, ""
        )
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("preset-import-both: dry-run failed:", code, msg)
                if (String(code) === "transport-disconnected") {
                    _applyPresetImportOffline(root.pendingPresetImportState, String(code))
                    return
                }
                root.statusLine = root.tr("status.preset-import-dry-run-failed",
                    "Preset import dry-run failed: ") +
                    ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            var token = (p && p["confirmation-token"]) || ""
            // No-op re-import → plain notice
            // instead of an empty review dialog (see single-route variant).
            if (Pure.reviewSummaryIsEmpty(summary)) {
                // Bind the source paths anyway — the files were read and match
                // the active rules (see the single-route variant).
                _bindImportedSourcePaths(root.pendingPresetImportState)
                root.showNotice(
                    root.tr("dialog.nothing-to-apply.title", "Nothing to apply"),
                    root.tr("dialog.nothing-to-apply.body",
                        "There are no changes to apply — the current rules already "
                        + "match what is active."))
                return
            }
            root.pendingPresetImportState = Object.assign({}, root.pendingPresetImportState, {
                summary: summary,
                confirmationToken: token
            })
            root.reviewDiffDialog.summary = summary
            // Preset import is per-principal (user-scoped,
            // non-elevated): the service scopes it to the caller SID, so
            // there's no administrator banner for a normal user's import.
            root.reviewDiffDialog.lacksElevation = false
            root.reviewDiffDialog.sessionElevated = false
            // Clear any stale `readOnly: true` left by a
            // prior `_openPendingApplyPreview` (drift "show differences"),
            // otherwise the import review opens without an Apply button.
            root.reviewDiffDialog.readOnly = false
            root.reviewDiffDialog.open()
        })
    }

    /// Execute path for PresetImport. Driven by the
    /// single-step ReviewDiffDialog's Apply; the
    /// `_activeReviewKind` flag routes the apply callback here.
    function _executePresetImportActivation(token) {
        if (!root.bridgeAvailable) return
        if (!root.reviewFlowController._guardMutationElevation()) return
        var st = root.pendingPresetImportState
        var payload = {
            "include-child-processes": false,
            // Must match the dry-run flag so the assembled content hash dedups
            // to the candidate built during preview. The toggle lives in
            // Settings (not the review dialog), so it can't change mid-flow.
            "import-only-active": root.importOnlyActiveSession,
            "correlation-id": st.correlationId
        }
        if (String(st.targetRoute) === "both") {
            // Both-routes variant (wizard, country preset,
            // builtin demo). Replay the same primary+secondary bytes
            // captured during dry-run so the server side gets a payload
            // that decodes to `PresetImportTarget::BothRoutes`.
            if (st.primaryBytesB64) payload["primary-bytes-b64"] = st.primaryBytesB64
            if (st.secondaryBytesB64) payload["secondary-bytes-b64"] = st.secondaryBytesB64
        } else if (String(st.targetRoute) === "primary") {
            payload["primary-bytes-b64"] = st.bytesB64
        } else {
            payload["secondary-bytes-b64"] = st.bytesB64
        }
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "preset-import", payload, false /* dryRun */, token
        )
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok && code === "confirmation-expired") {
                root.reviewExpiredDialog.open()
                return
            }
            if (!ok && code === "uac-declined") {
                // Session broker — UAC dismissed; nothing imported. Retryable.
                root.statusLine = root.tr("status.activate-uac-declined",
                    "Administrator approval was cancelled — changes were not applied. " +
                    "Click Apply again to retry.")
                // Release the unsaved-changes guard (if it drove this
                // apply) without navigating; no-op for non-guard flows.
                root.reviewFlowController._resolveGuardRulesApply(false)
                return
            }
            if (!ok) {
                console.log("preset-import: activate failed:", code, msg)
                // Preset import is per-principal (user-scoped,
                // non-elevated), so `forbidden` no longer means "needs admin"
                // — it's the mutation gate (e.g. an unacknowledged security
                // alert). Route every failure through the generic localized
                // error label rather than the old "re-launch as Admin" hint.
                root.statusLine = root.tr("status.preset-import-failed",
                    "Failed to import preset: ") +
                    ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                return
            }
            // Preset import is user-scoped (non-elevated):
            // success no longer implies the elevation broker engaged, so we
            // do NOT flip `_brokerSessionElevated` here (it's driven only by
            // genuinely elevated service ops via `onBrokerSessionEstablished`).
            // Share the same summary
            // composer the offline path uses. We re-parse the same
            // bytes locally to (a) capture passthrough sections for
            // sidecar persistence, and (b) compute a user-facing
            // rules count. `skipApply: true` because the service
            // will fan the activated revision back via snapshot
            // push; touching rulesModel here would race with it.
            _refreshRulesAfterPresetImport(root.pendingPresetImportState, {
                skipApply: true,
                onComplete: function(summary) {
                    var base = root.tr("status.preset-import-completed",
                        "Preset imported and activated ({count} rules).")
                        .replace("{count}", String(summary.rulesCount))
                    root.statusLine = base + _formatImportPassthroughSuffix(summary.passthroughByRoute)
                }
            })
            // After successful activation the in-memory rules match
            // what the service has — drop the dirty flag (mirrors the
            // RulesUpdate path).
            root.setUnsavedChanges("rules", false)
            // Authoritatively rebind the
            // table to the just-activated revision. The import payload is
            // file bytes that never populated rulesModel locally
            // (`skipApply: true` above), so without this the table keeps
            // showing the PRE-import rows until the next launch.
            // Idempotent with the `revision-status-changed` push.
            root._refreshRulesFromService({ silent: true })
            // Record path + clear dirty flags for the
            // routes the import covered. `pendingPresetImportState`
            // carries the import scope (single-route or both).
            _bindImportedSourcePaths(root.pendingPresetImportState)
        })
    }

}
