import QtQuick 2.15
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

// Non-visual controller owning the file <-> GUI <-> service drift-detection
// logic and the file<->service merge flow. Extracted from Main.qml (thin-shell
// rule): the shell keeps the drift STATE (`_drift*` / `_merge*` properties are
// read by the banners and dialogs) and the drift TIMERS, while this controller
// owns the LOGIC. Main.qml instantiates one, injects itself as `root`, and
// exposes it as `root.driftController`; the drift/merge banners and dialogs
// drive it through `root.driftController.<fn>()`.
//
// Every window-scope symbol is reached through the injected `root` (window
// properties, window functions, the aliased ids `rulesModel` /
// `driftDetectionDialog` / `mergeReviewDialog`, and the RPC transport via
// `root.rpc`). `nrrNativeBridge` is a global QML context property, so it is
// referenced bare here exactly as it is in Main.qml and the sections. Sibling
// drift functions call each other bare (same object scope).
//
// Three hash legs are computed per route via `local.canonical-rules-hash`
// (Rust SSOT): file (mtime-cached), gui (recomputed on edit / poll) and service
// (captured at cold-start + after every successful activate, refreshed each
// poll). `_driftCompare` classifies the pairwise mismatch and raises the amber
// `root._driftDetected` banner for the safety-critical app<->service divergence
// and the quiet `root._mergeAvailable` affordance for a file-only divergence.
QtObject {
    id: driftController
    property var root

    function _openDriftDialog() {
        // Re-bind props from current state — Qt declarative bindings
        // on a Dialog instance don't always re-evaluate on every
        // open; explicit assignment is the safe pattern.
        root.driftDetectionDialog.primaryDetails      = root._driftDetailsPrimary
        root.driftDetectionDialog.secondaryDetails    = root._driftDetailsSecondary
        root.driftDetectionDialog.fileExistsPrimary   = root._driftFileExistsPrimary
        root.driftDetectionDialog.fileExistsSecondary = root._driftFileExistsSecondary
        root.driftDetectionDialog.open()
    }

    /// Open the file↔service merge dialog. Reads the bound .txt
    /// files (decoding base64 → UTF-8 via the bridge), runs the first
    /// `rules.merge-preview` pass under the user's policy, and populates the
    /// dialog buckets. Conflicts default to the file-provisional side (Union).
    function _openMergeDialog() {
        if (!_mergeBridgeReady()) {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            return
        }
        root.mergeReviewDialog.policy = _mergePolicy()
        root.mergeReviewDialog.mergeResult = null
        root.mergeReviewDialog.picks = ({})
        root.mergeReviewDialog.errorText = ""
        root.mergeReviewDialog.loading = true
        root.mergeReviewDialog.open()
        _fetchMergePreview([], function(res, code) {
            root.mergeReviewDialog.loading = false
            if (!res) {
                root.mergeReviewDialog.errorText =
                    root.tr("dialog.merge.error", "Could not build the merge preview.")
                    + (code ? (" (" + root.ipcErrorLabel(code) + ")") : "")
                return
            }
            _fillMergeDialog(res)
        })
    }

    function _mergeBridgeReady() {
        return typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
            && typeof nrrNativeBridge.readFileBytes === "function"
            && typeof nrrNativeBridge.rpcRulesMergePreview === "function"
            && typeof nrrNativeBridge.decodeBase64Utf8 === "function"
    }

    function _mergePolicy() {
        return String((root.prefs && root.prefs.mergeConflictPolicy) || "union")
    }

    /// Read both bound files into `root._merge*Text` and run one
    /// `rules.merge-preview` pass. `done(result, errorCode)` — `result` is
    /// null on failure. Split out of `_openMergeDialog` so the same pass can
    /// answer "does merging change anything at all" before any dialog opens.
    function _fetchMergePreview(resolutions, done) {
        var primaryPath = String(root.prefs.lastSavedPathPrimary || "")
        var secondaryPath = String(root.prefs.lastSavedPathSecondary || "")
        var primB64 = primaryPath
            ? String(nrrNativeBridge.readFileBytes(primaryPath) || "") : ""
        var secB64 = secondaryPath
            ? String(nrrNativeBridge.readFileBytes(secondaryPath) || "") : ""
        root._mergePrimaryText = primB64 ? nrrNativeBridge.decodeBase64Utf8(primB64) : ""
        root._mergeSecondaryText = secB64 ? nrrNativeBridge.decodeBase64Utf8(secB64) : ""
        var corr = nrrNativeBridge.rpcRulesMergePreview(
            root._mergePrimaryText, root._mergeSecondaryText,
            _mergePolicy(), resolutions || [])
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            done((ok && p && p.result) ? p.result : null, code)
        })
    }

    function _fillMergeDialog(res) {
        root.mergeReviewDialog.policy = _mergePolicy()
        root.mergeReviewDialog.mergeResult = res
        // Default each conflict pick to the file-provisional side (Union).
        var picks = {}
        var cs = res.conflicts || []
        for (var i = 0; i < cs.length; i += 1) {
            picks[cs[i]["identity-key"]] = "file"
        }
        root.mergeReviewDialog.picks = picks
    }

    /// Confirm the merge: re-run `rules.merge-preview` with the
    /// user's per-conflict picks to get the final merged rules-json, then hand
    /// it to the standard review + apply flow (service = single writer). On a
    /// successful activation the bound files are re-exported so file == service.
    function _applyMerge(resolutions) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRulesMergePreview !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            return
        }
        var policy = String((root.prefs && root.prefs.mergeConflictPolicy) || "union")
        var corr = nrrNativeBridge.rpcRulesMergePreview(
            root._mergePrimaryText, root._mergeSecondaryText, policy, resolutions || [])
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok || !p || !p.result) {
                root.statusLine = root.tr("dialog.merge.error",
                    "Could not build the merge preview.")
                return
            }
            var mergedRulesJson = String(p.result["merged-rules-json"] || "")
            if (mergedRulesJson === "") {
                root.statusLine = root.tr("dialog.merge.error",
                    "Could not build the merge preview.")
                return
            }
            root.mergeReviewDialog.close()
            var contentHash = ""
            if (typeof nrrNativeBridge.sha256Hex === "function") {
                contentHash = nrrNativeBridge.sha256Hex(mergedRulesJson)
            } else {
                contentHash = "client-stub-" + String(Date.now())
            }
            // Mark bound files dirty so the post-activation write converges them
            // to the merged (== service) revision.
            if (String(root.prefs.lastSavedPathPrimary || "") !== "") {
                root._filesSyncDirtyPrimary = true
            }
            if (String(root.prefs.lastSavedPathSecondary || "") !== "") {
                root._filesSyncDirtySecondary = true
            }
            root._mergeApplyPendingWrite = true
            root.reviewFlowController.startRulesReviewFlow(mergedRulesJson, contentHash)
        })
    }

    /// Dialog action: load the
    /// saved file(s) into `rulesModel` DIRECTLY (parse → replace), so
    /// the table immediately shows the file contents. We deliberately
    /// do NOT route through the service activate path here: that made
    /// the table depend on a successful service round-trip, which left
    /// it empty whenever the activation deduped, returned an empty
    /// revision, or was Forbidden under a non-admin GUI ("load from
    /// file didn't populate the table"). The rules are marked unsaved
    /// so the user applies them via the normal Apply flow when ready;
    /// the drift banner stays up until they do.
    ///
    /// Only the route(s) with a configured file are replaced — a file
    /// for one route leaves the other route's rows untouched.
    /// `paths` overrides which files are read: `{ primary, secondary }`. The
    /// drift dialog passes nothing and keeps reading the save binding, which is
    /// the pair its own comparison was built on. The tray's file-vs-service
    /// notice passes the source paths it actually compared, so "Apply" loads
    /// the very files the user was told about.
    /// `onLoaded()` runs once the rows are in the table — the tray's "Apply"
    /// chains the ordinary review/activate flow onto it, so a button labelled
    /// Apply cannot end at "loaded into the table and stopped".
    function _driftLoadFromFile(paths, onLoaded) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        var override = paths || {}
        var primaryPath = String(override.primary
            || root.prefs.lastSavedPathPrimary || "")
        var secondaryPath = String(override.secondary
            || root.prefs.lastSavedPathSecondary || "")
        var primB64 = primaryPath
            ? nrrNativeBridge.readFileBytes(primaryPath) : ""
        var secB64 = secondaryPath
            ? nrrNativeBridge.readFileBytes(secondaryPath) : ""
        if (!primB64 && !secB64) {
            root.statusLine = root.tr("status.import-read-failed",
                "Cannot read preset file. See logs for details.")
            return
        }
        var target = (primB64 && secB64) ? "both"
            : (primB64 ? "primary" : "secondary")
        var state = {
            targetRoute: target,
            mode: "replace",
            bytesB64: (target === "secondary") ? secB64 : primB64,
            primaryBytesB64: primB64 || "",
            secondaryBytesB64: secB64 || ""
        }
        // skipApply:false → `_refreshRulesAfterPresetImport` parses and
        // applies the rows into rulesModel via `_applyImportReplace`
        // (and still routes through the duplicate/reclassify review when
        // the file is ambiguous).
        root.presetImportController._refreshRulesAfterPresetImport(state, {
            skipApply: false,
            onComplete: function(summary) {
                // The loaded file now differs from the service revision,
                // so the rules are genuinely unsaved relative to it.
                // Recompute vs baseline (import almost always
                // diverges, but this stays honest if it happens to match).
                root._recomputeRulesDirty()
                // Recompute the GUI drift leg so the banner reflects
                // file == app (resolves the file-vs-app mismatch) while
                // app-vs-service stays until the user applies.
                _driftUpdateGuiHash("primary", function() {})
                _driftUpdateGuiHash("secondary", _driftCompare)
                root.statusLine = root.tr("status.drift-loaded-from-file",
                    "Loaded {count} rule(s) from file into the app. Review and apply when ready.")
                    .replace("{count}", String(summary.rulesCount))
                if (typeof onLoaded === "function") onLoaded()
            }
        })
    }

    /// Dialog action: open a read-only diff
    /// of the current app rules against the service's active revision.
    /// Reuses `_openPendingApplyPreview` (dry-run `rules-update` against
    /// the live revision → ReviewDiffDialog in read-only mode), so the
    /// added/removed/changed entries are computed server-side, not faked.
    function _driftShowDiff() {
        // The dry-run below compares the WINDOW with the service. When the
        // divergence is between the file and the window, those two agree and
        // every bucket comes back empty — a diff screen that proves nothing
        // and reads as "the warning was a lie". Send that case to the
        // comparison that covers the pair which actually differs.
        if (!_driftHasGuiVsServiceMismatch()) {
            _driftOpenComparison()
            return
        }
        if (!root.bridgeAvailable) {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        var rulesJson = root._buildRulesJsonFromModel()
        if (!rulesJson) return // serializer failed; status line already set
        var contentHash = ""
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function") {
            contentHash = nrrNativeBridge.sha256Hex(rulesJson)
        } else {
            contentHash = "client-stub-" + String(Date.now())
        }
        root._openPendingApplyPreview(rulesJson, contentHash)
    }

    /// Is either route's mismatch one the window-vs-service diff can show?
    function _driftHasGuiVsServiceMismatch() {
        var isGuiVsService = function(details) {
            var m = String((details || {}).mismatch || "none")
            return m === "gui-vs-service" || m === "all-three-differ"
        }
        return isGuiVsService(root._driftDetailsPrimary)
            || isGuiVsService(root._driftDetailsSecondary)
    }

    /// Does a service-computed review summary say "nothing about the rules
    /// changes"? All four buckets empty is the service's own verdict that the
    /// candidate set and the active revision describe the same routing.
    function _summaryHasNoRuleChanges(summary) {
        if (!summary) return false
        var buckets = ["rules-added", "rules-removed", "rules-modified", "rules-retargeted"]
        for (var i = 0; i < buckets.length; i += 1) {
            var b = summary[buckets[i]]
            if (b && b.length > 0) return false
        }
        return true
    }

    /// The alarm was raised by a hash difference the service does not consider
    /// a rule change. Remember THIS PAIR of hashes as agreed and stand the
    /// banner down.
    ///
    /// Re-pinning the service leg from the on-screen model (what this did
    /// before) only looked like a fix: the next poll re-read the live service
    /// leg, the same two hashes came back, and the banner returned a minute
    /// later — the case the user hit three times in one session. Recording the
    /// pair is what actually holds, and it holds only until either side moves.
    function _standDownDriftAsEqual() {
        root._driftDetected = false
        root._mergeAvailable = false
        _driftAgreedPair = _driftPairKey()
        root.statusLine = root.tr("status.drift-none-after-compare",
            "Compared with the service: the rules match. Nothing to apply.")
    }

    /// The (gui, service) hash pair the service has already judged equivalent,
    /// or "" when nothing has been judged. Any edit on either side changes the
    /// key, so the alarm re-arms by itself.
    property string _driftAgreedPair: ""

    function _driftPairKey() {
        return String(root._driftGuiHashPrimary) + "|" + String(root._driftServiceHashPrimary)
            + "|" + String(root._driftGuiHashSecondary) + "|" + String(root._driftServiceHashSecondary)
    }

    /// Name the rules behind a gui-vs-service mismatch in the log. The hashes
    /// say THAT the two sides differ and the dialog then shows nothing, which
    /// leaves no way to find out WHAT differs; this prints the routing keys
    /// present on one side only.
    function _logDriftDetail() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRulesList !== "function") return
        var corr = nrrNativeBridge.rpcRulesList()
        root.rpc.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) return
            var serviceRows = (p.rows || []).map(Rules.driftRowFromServiceWire)
            var guiKeys = Rules.ruleRoutingKeys(root._rulesModelToRowArray(), root._aceEncodeHost)
            var svcKeys = Rules.ruleRoutingKeys(serviceRows, root._aceEncodeHost)
            var count = function(list) {
                var m = {}
                for (var i = 0; i < list.length; i += 1) m[list[i]] = (m[list[i]] || 0) + 1
                return m
            }
            var g = count(guiKeys), s = count(svcKeys), k
            var onlyGui = [], onlyService = []
            for (k in g) { if ((s[k] || 0) < g[k]) onlyGui.push(k + " x" + (g[k] - (s[k] || 0))) }
            for (k in s) { if ((g[k] || 0) < s[k]) onlyService.push(k + " x" + (s[k] - (g[k] || 0))) }
            console.log("drift detail: app=" + guiKeys.length + " service=" + svcKeys.length
                + " only-in-app=" + JSON.stringify(onlyGui.slice(0, 12))
                + " only-in-service=" + JSON.stringify(onlyService.slice(0, 12)))
        })
    }

    /// Dialog action: clear ALL rules from
    /// the app AND push an empty revision to the service. Gated upstream
    /// by `driftClearAllConfirmDialog`. Reuses `_applyEmptyRulesForReset`
    /// (the full-reset helper) — under a non-admin GUI its confirm phase
    /// is Forbidden and the launcher's R3 path elevates via UAC. On
    /// success the service refetch recaptures a clean (empty) baseline so
    /// the drift banner clears.
    function _driftClearAll() {
        root.statusLine = root.tr("status.drift-clear-all-running",
            "Clearing all rules…")
        Pure.clearModel(root.rulesModel)
        root.clearAllUnsavedChanges()
        root._applyEmptyRulesForReset(function(ok) {
            if (ok) {
                root._refreshRulesFromService({ silent: true })
                root.statusLine = root.tr("status.drift-cleared-all",
                    "All rules cleared from the app and the service.")
            } else {
                root.statusLine = root.tr("status.drift-clear-all-failed",
                    "Local rules cleared, but the service was not updated (administrator approval or a connection is required).")
            }
        })
    }

    /// Dialog action: push current rulesModel to
    /// the service via the standard "Save and review" flow. Mirrors
    /// what `RulesSection._triggerReviewFlow` does.
    function _driftApplyGuiState() {
        if (!root.bridgeAvailable) {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        var rulesJson = root._buildRulesJsonFromModel()
        if (!rulesJson) return // serializer failed; status line already set
        var contentHash = ""
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function") {
            contentHash = nrrNativeBridge.sha256Hex(rulesJson)
        } else {
            contentHash = "client-stub-" + String(Date.now())
        }
        root.reviewFlowController.startRulesReviewFlow(rulesJson, contentHash)
    }

    /// Dialog action: discard local edits and load the
    /// CURRENT active rules from the service.
    ///
    /// This previously replayed `context.rules.rows`,
    /// the COLD-START snapshot. When the GUI cold-starts while the service
    /// is down it falls back to the mock backend, so that snapshot holds
    /// demo rules; "accept service state" then loaded demo rather than the
    /// service's real active revision (the reported "грузит демо правила"
    /// bug). Fetch the live revision via `rules.list` instead — it clears
    /// the model, recaptures the drift baseline and drops the dirty flag.
    /// Only fall back to the cold-start replay when the service is
    /// unreachable (offline), where there is nothing live to fetch.
    function _driftAcceptServiceState() {
        if (root.bridgeAvailable
                && typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.rpcRulesList === "function"
                && root.backendStatus && root.backendStatus.kind === "connected") {
            root._refreshRulesFromService({ silent: false })
            return
        }
        // Offline fallback — replay the last-known cold-start snapshot.
        Pure.clearModel(root.rulesModel)
        var rulesRows = ((root.context.rules || {}).rows) || []
        var batch = []
        for (var k = 0; k < rulesRows.length; k += 1) {
            var row = rulesRows[k]
            if (!row) continue
            if (row.id) row.id = Rules.canonicalRuleId(row.id)
            if (Rules.isHostlikeRuleType(row.ruleType)) {
                row.matchValue = root._unicodeDecodeHost(row.matchValue)
            }
            row.aceMatchValue = root._aceLowerForSearch(row.matchValue)
            batch.push(row)
        }
        // One append for the whole book — see `_appendRowsChunked`.
        if (batch.length > 0) root.rulesModel.append(batch)
        // Dedupe per-route id collisions.
        root._renumberRuleIdsSequential()
        // Re-overlay comments + recompute drift baseline.
        root._overlaySidecarCommentsOntoRulesModel()
        _driftCaptureServiceBaseline()
        root.setUnsavedChanges("rules", false)
        root.statusLine = root.tr("status.drift-rolled-back-to-service",
            "Local rule edits discarded; app now matches service state.")
    }

    /// Async hash via `local.canonical-rules-hash`. `callback(hash)`
    /// fires with the hex string on success or `""` on failure. Pure
    /// passthrough — callers wrap in their own composition.
    function _driftHashRulesJson(rulesJson, callback) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCanonicalRulesHash !== "function") {
            callback("")
            return
        }
        var corr = nrrNativeBridge.rpcCanonicalRulesHash(String(rulesJson || ""))
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("local.canonical-rules-hash failed:", code, msg)
                callback("")
                return
            }
            callback(String((payload && payload.hash) || ""))
        })
    }

    /// Recompute the GUI-side hash for one route from the current
    /// `rulesModel`. Updates `_driftGuiHash{Primary,Secondary}`.
    function _driftUpdateGuiHash(route, done) {
        var rules = root._buildRulesJsonForRoute(root._rulesModelToRowArray(), route)
        _driftHashRulesJson(rules, function(hash) {
            if (route === "secondary") {
                root._driftGuiHashSecondary = hash
            } else {
                root._driftGuiHashPrimary = hash
            }
            if (typeof done === "function") done()
        })
    }

    /// Refresh the file leg for one route. Honours the mtime cache —
    /// if the cached mtime matches the live mtime AND the path is
    /// unchanged, we reuse the cached hash without re-reading the
    /// file. Async (RPC chain). Calls `done()` when the leg state
    /// reflects current disk content.
    function _driftRefreshFileHash(route, done) {
        var path = (route === "secondary")
            ? String(root.prefs.lastSavedPathSecondary || "")
            : String(root.prefs.lastSavedPathPrimary || "")
        var setExists = function(v) {
            if (route === "secondary") root._driftFileExistsSecondary = v
            else                       root._driftFileExistsPrimary = v
        }
        var setHash = function(h) {
            if (route === "secondary") root._driftFileHashSecondary = h
            else                       root._driftFileHashPrimary = h
        }
        var setMtime = function(m) {
            if (route === "secondary") root._driftFileMtimeSecondary = m
            else                       root._driftFileMtimePrimary = m
        }
        var setCachedPath = function(p) {
            if (route === "secondary") root._driftFileCachedPathSecondary = p
            else                       root._driftFileCachedPathPrimary = p
        }
        var cachedPath = (route === "secondary")
            ? root._driftFileCachedPathSecondary
            : root._driftFileCachedPathPrimary
        var cachedMtime = (route === "secondary")
            ? root._driftFileMtimeSecondary
            : root._driftFileMtimePrimary
        var cachedHash = (route === "secondary")
            ? root._driftFileHashSecondary
            : root._driftFileHashPrimary

        if (path === "") {
            setExists(false)
            setHash("")
            setMtime(0)
            setCachedPath("")
            if (typeof done === "function") done()
            return
        }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.statFile !== "function") {
            // No bridge → cannot probe the file; treat as missing so
            // drift only compares GUI vs service.
            setExists(false)
            setHash("")
            if (typeof done === "function") done()
            return
        }
        var stat = nrrNativeBridge.statFile(path)
        if (!stat || !stat.exists) {
            setExists(false)
            setHash("")
            setMtime(0)
            setCachedPath(path)
            if (typeof done === "function") done()
            return
        }
        setExists(true)
        var mtime = parseFloat(stat.mtime || 0)
        if (path === cachedPath && mtime === cachedMtime && cachedHash !== "") {
            // Cache hit; nothing changed on disk since last poll.
            if (typeof done === "function") done()
            return
        }
        // Cache miss — re-read + parse + hash. `readFileBytes`
        // returns base64-encoded bytes capped at 1 MiB; `_b64ToUtf8`
        // turns it back into the canonical UTF-8 text.
        if (typeof nrrNativeBridge.readFileBytes !== "function") {
            setHash("")
            if (typeof done === "function") done()
            return
        }
        var b64 = nrrNativeBridge.readFileBytes(path)
        if (!b64 || b64 === "") {
            setHash("")
            setMtime(mtime)
            setCachedPath(path)
            if (typeof done === "function") done()
            return
        }
        var text = root._b64ToUtf8(b64)
        root.presetImportController._parseCanonicalRulesAsync(text, route, 1, function(parseResult) {
            var rows = (parseResult && parseResult.rows) || []
            var rulesJson = root._buildRulesJsonForRoute(rows, route)
            _driftHashRulesJson(rulesJson, function(hash) {
                setHash(hash)
                setMtime(mtime)
                setCachedPath(path)
                if (typeof done === "function") done()
            })
        })
    }

    /// Capture the service-baseline hash for both routes. Called
    /// once after the cold-start snapshot bind AND after every
    /// successful `_executeRulesActivation` — the activated rules
    /// ARE what the service now holds, so the hash of the post-
    /// activation `rulesModel` is the new baseline.
    function _driftCaptureServiceBaseline() {
        var rows = root._rulesModelToRowArray()
        var pendingP = true, pendingS = true
        var maybeCompare = function() {
            if (!pendingP && !pendingS) _driftCompare()
        }
        _driftHashRulesJson(root._buildRulesJsonForRoute(rows, "primary"), function(h) {
            root._driftServiceHashPrimary = h
            // Cold-start: GUI and service are identical, so the GUI
            // leg starts at the same hash. Saves a second RPC.
            root._driftGuiHashPrimary = h
            pendingP = false
            maybeCompare()
        })
        _driftHashRulesJson(root._buildRulesJsonForRoute(rows, "secondary"), function(h) {
            root._driftServiceHashSecondary = h
            root._driftGuiHashSecondary = h
            pendingS = false
            maybeCompare()
        })
    }

    /// Refresh ONLY the drift "service" hash legs from the
    /// live service's active revision, WITHOUT touching rulesModel or the
    /// GUI hash legs. Used on reconnect when the user has unsaved local
    /// edits: a full `_refreshRulesFromService` would clobber those edits,
    /// but the drift triangle still needs the REAL service hash to classify
    /// divergence — otherwise it compares against the stale cold-start /
    /// mock baseline captured while the service was down.
    function _driftRefreshServiceBaselineFromService() {
        _driftRefreshServiceHashInto(function() { _driftCompare() })
    }

    /// Fetch the LIVE service revision and overwrite
    /// ONLY the drift "service" hash legs, then invoke `done` exactly once (after
    /// both routes hash). Extracted from `_driftRefreshServiceBaselineFromService`
    /// so the periodic `_driftRecheck` can fold the service leg into its pending
    /// count and self-heal a stale cold-start service pin (the amber "rules
    /// differ" false positive). `done` is always eventually
    /// called (even on a failed/absent RPC) so the recheck's in-flight latch
    /// cannot get stuck.
    function _driftRefreshServiceHashInto(done) {
        var finish = function() { if (typeof done === "function") done() }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRulesList !== "function") {
            finish()
            return
        }
        var corr = nrrNativeBridge.rpcRulesList()
        root.rpc.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) { finish(); return }
            var rows = (p.rows || []).map(root._serviceRuleRowToModelRow)
            // Remember when the service side is EMPTY (no
            // active revision / zero rules, e.g. right after a service-DB
            // wipe). The amber banner then explains "the service has no
            // rules yet" instead of the generic "do not all agree", which
            // sent the user hunting for a nonexistent difference.
            root._serviceRulesEmpty = rows.length === 0
            var pendingP = true, pendingS = true
            var maybeDone = function() {
                if (!pendingP && !pendingS) finish()
            }
            _driftHashRulesJson(root._buildRulesJsonForRoute(rows, "primary"), function(h) {
                root._driftServiceHashPrimary = h
                pendingP = false
                maybeDone()
            })
            _driftHashRulesJson(root._buildRulesJsonForRoute(rows, "secondary"), function(h) {
                root._driftServiceHashSecondary = h
                pendingS = false
                maybeDone()
            })
        })
    }

    /// Set while a recheck was asked for during another one. The in-flight
    /// latch would otherwise swallow it, and a "Check now" button that
    /// silently does nothing is worse than no button.
    property bool _driftRecheckQueued: false

    /// On-demand comparison: the "Check now" button, and every place that
    /// just changed one of the three legs (a file write, an activation). The
    /// periodic poll is a safety net, not the way a user learns that the
    /// rules on screen, in the file and in the service agree again.
    /// `announceOffline` belongs to the button only — an automatic follow-up
    /// must not overwrite the status line the finished operation just set.
    /// `done(compared)` fires once the legs are fresh and `_driftCompare` has
    /// run, so a caller that wants to SHOW the difference (the tray's "Open and
    /// compare") acts on measured state instead of whatever the last poll left.
    function _driftRecheckNow(announceOffline, done) {
        if (((root.backendStatus || {}).kind) !== "connected") {
            if (announceOffline === true) {
                root.statusLine = root.tr("status.drift-recheck-offline",
                    "The service is not running, so the rules it applies cannot be compared right now.")
            }
            console.log("drift recheck: skipped — backend is not connected")
            if (typeof done === "function") done(false)
            return
        }
        if (typeof done === "function") _driftRecheckDone.push(done)
        // The button has to answer. Re-measuring silently looks identical to a
        // button that does nothing — which is exactly how it was reported —
        // because the usual outcome is "still different" and the banner it
        // would clear simply stays put.
        if (announceOffline === true) {
            _driftRecheckDone.push(function() {
                root.statusLine = root._driftDetected
                    ? root.tr("status.drift-still-different",
                        "Compared just now: the rules on screen and the ones the service applies still differ.")
                    : root.tr("status.drift-none-after-compare",
                        "Compared with the service: the rules match. Nothing to apply.")
            })
        }
        if (root._driftRecheckInFlight) { _driftRecheckQueued = true; return }
        _driftRecheck()
    }

    /// Callbacks waiting for the running comparison. Plain array on a `var`
    /// property: nothing binds to it, only `_driftRecheck` drains it.
    property var _driftRecheckDone: []

    /// Answer everyone waiting when the pass cannot run at all — a caller left
    /// hanging would silently never show the comparison it asked for.
    function _drainRecheckDone() {
        var waiting = _driftRecheckDone
        _driftRecheckDone = []
        for (var i = 0; i < waiting.length; i += 1) waiting[i](false)
    }

    /// Show the divergence the last comparison found, picking the view that
    /// fits it: the app↔service dialog for the safety-critical mismatch, the
    /// file↔service merge preview for a bound file that ran ahead of (or behind)
    /// what is applied. Entry point for the tray's "Open and compare", which
    /// knows only that two hashes differ.
    function _driftOpenComparison() {
        var alarms = function(m) {
            return m === "gui-vs-service" || m === "all-three-differ"
        }
        var mismatchP = String((root._driftDetailsPrimary || {}).mismatch || "none")
        var mismatchS = String((root._driftDetailsSecondary || {}).mismatch || "none")
        console.log("drift compare hand-off: primary=" + mismatchP
            + " secondary=" + mismatchS)
        if (alarms(mismatchP) || alarms(mismatchS)) {
            _openDriftDialog()
            return
        }
        if (mismatchP === "file-vs-service" || mismatchS === "file-vs-service"
                || mismatchP === "file-vs-gui" || mismatchS === "file-vs-gui") {
            _openMergeUnlessPointless()
            return
        }
        root.statusLine = root.tr("status.drift-none-after-compare",
            "Compared with the service: the rules match. Nothing to apply.")
    }

    /// A file leg can differ from the window's while describing exactly the
    /// same routing — a rule spelled one way in the file and another in the
    /// table, an entry the canonicalizer folds away. Merging then produces the
    /// rules that are already applied, and putting a comparison screen with
    /// "only in the file" rows in front of the user is a scare over nothing:
    /// what it offers to change, changes nothing.
    ///
    /// So the merge is run first and its result compared with the window's own
    /// rules. Equal → converge the file quietly and leave one notice behind.
    /// Different → the screen is warranted, and it opens on the pass already
    /// fetched rather than paying for a second one.
    function _openMergeUnlessPointless() {
        if (!_mergeBridgeReady()) {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            return
        }
        _fetchMergePreview([], function(res, code) {
            if (!res) {
                // Cannot tell — show the screen rather than swallow a real
                // divergence.
                _openMergeDialog()
                return
            }
            var mergedJson = String(res["merged-rules-json"] || "")
            var guiJson = root._buildRulesJsonFromModel()
            if (mergedJson === "" || !guiJson) {
                _showMergeDialogWith(res)
                return
            }
            _driftHashRulesJson(mergedJson, function(mergedHash) {
                _driftHashRulesJson(guiJson, function(guiHash) {
                    var equivalent = mergedHash !== "" && mergedHash === guiHash
                    // Record what was compared BEFORE acting on it: converging
                    // rewrites the bound file, and with it the only copy of the
                    // input that produced this verdict.
                    _writeDriftDiagnostics(res, mergedJson, guiJson,
                        mergedHash, guiHash, equivalent)
                    if (equivalent) {
                        _convergeFilesQuietly()
                        return
                    }
                    _showMergeDialogWith(res)
                })
            })
        })
    }

    /// Leave a record of one file-vs-window comparison next to the launcher
    /// logs, keeping the previous one as `.prev`.
    ///
    /// The interesting case is the quiet one: merging produced exactly the
    /// rules already on screen, so nothing changes and the evidence would
    /// otherwise be overwritten within the second. Everything here is the
    /// user's own data staying on the user's own machine, in the folder the
    /// launcher already writes its logs to.
    function _writeDriftDiagnostics(res, mergedJson, guiJson, mergedHash, guiHash, equivalent) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.runtimeDiagnosticsPath !== "function"
                || typeof nrrNativeBridge.writeTextFile !== "function") {
            return
        }
        var path = String(nrrNativeBridge.runtimeDiagnosticsPath("rules-drift.json") || "")
        if (path === "") return
        // Keep one generation back: the same divergence often repeats, and the
        // FIRST occurrence is the one with the untouched file.
        if (typeof nrrNativeBridge.readFileBytes === "function") {
            var prevB64 = String(nrrNativeBridge.readFileBytes(path) || "")
            if (prevB64 !== "") {
                var prevPath = String(
                    nrrNativeBridge.runtimeDiagnosticsPath("rules-drift.prev.json") || "")
                if (prevPath !== "") {
                    nrrNativeBridge.writeTextFile(prevPath, root._b64ToUtf8(prevB64))
                }
            }
        }
        var record = {
            "captured-at": new Date().toISOString(),
            "equivalent": !!equivalent,
            "mismatch": {
                "primary": String((root._driftDetailsPrimary || {}).mismatch || "none"),
                "secondary": String((root._driftDetailsSecondary || {}).mismatch || "none")
            },
            "hashes": {
                "file-primary": String(root._driftFileHashPrimary || ""),
                "file-secondary": String(root._driftFileHashSecondary || ""),
                "gui-primary": String(root._driftGuiHashPrimary || ""),
                "gui-secondary": String(root._driftGuiHashSecondary || ""),
                "service-primary": String(root._driftServiceHashPrimary || ""),
                "service-secondary": String(root._driftServiceHashSecondary || ""),
                "merged": String(mergedHash || ""),
                "gui-whole-book": String(guiHash || "")
            },
            "paths": {
                "primary": String(root.prefs.lastSavedPathPrimary || ""),
                "secondary": String(root.prefs.lastSavedPathSecondary || "")
            },
            "merge-buckets": {
                "file-only": (res && res["file-only"]) || [],
                "service-only": (res && res["service-only"]) || [],
                "conflicts": (res && res.conflicts) || []
            },
            "file-text": {
                "primary": String(root._mergePrimaryText || ""),
                "secondary": String(root._mergeSecondaryText || "")
            },
            "gui-rules-json": String(guiJson || ""),
            "merged-rules-json": String(mergedJson || "")
        }
        var text = ""
        try {
            text = JSON.stringify(record, null, 2)
        } catch (err) {
            console.log("drift diagnostics: serialize failed:", err)
            return
        }
        // The bridge caps a write at 1 MiB. A rule book that large would lose
        // the copies but keep the verdict, which is the part that cannot be
        // reconstructed later.
        if (text.length > 1000000) {
            record["file-text"] = { "primary": "(omitted: too large)", "secondary": "" }
            record["gui-rules-json"] = "(omitted: too large)"
            record["merged-rules-json"] = "(omitted: too large)"
            text = JSON.stringify(record, null, 2)
        }
        if (nrrNativeBridge.writeTextFile(path, text)) {
            console.log("drift diagnostics written:", path, "equivalent=" + equivalent)
        }
    }

    function _showMergeDialogWith(res) {
        root.mergeReviewDialog.errorText = ""
        root.mergeReviewDialog.loading = false
        _fillMergeDialog(res)
        root.mergeReviewDialog.open()
    }

    /// The file says the same thing the window does. Rewrite it from the
    /// window (a content-compare per route, so a file that already matches is
    /// not touched), then re-run the comparison so the banner clears on the
    /// facts rather than on a suppression flag.
    function _convergeFilesQuietly() {
        root.boundFilesController._writeBoundFiles(false, function() {
            // Drop the mtime cache only once the write is on disk — a recheck
            // racing it would re-read the old bytes and raise the banner again.
            root._driftFileCachedPathPrimary = ""
            root._driftFileCachedPathSecondary = ""
            _driftRecheckNow(false)
        }, true)
        root._addPushNotice({
            "id": "rules-file-converged:" + _driftPairKey(),
            "kind": "rules-file-converged",
            "severity": "info",
            "dismissible": true,
            "title": root.tr("notifications.rules-file-converged.title",
                "Your rules file was brought up to date"),
            "body": root.tr("notifications.rules-file-converged.body",
                "The linked rules file was written differently from the rules in the app, but both described the same routing. The file has been rewritten to match; nothing about what is applied changed.")
        })
    }

    /// Periodic poll entry. Re-fetches file legs (mtime-cached) and
    /// GUI legs, then compares. Bounded by `_driftRecheckInFlight`
    /// so overlapping triggers don't interleave their async chains.
    function _driftRecheck() {
        if (root._driftRecheckInFlight) return
        if (((root.backendStatus || {}).kind) !== "connected") { _drainRecheckDone(); return }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCanonicalRulesHash !== "function") {
            _drainRecheckDone()
            return
        }
        root._driftRecheckInFlight = true
        // Refresh the SERVICE leg every poll too (5th
        // leg). The cold-start service baseline is captured from the launcher
        // context snapshot, which can lag the live per-SID revision (mock/stale)
        // and can be pinned to a wrong value by an out-of-order async hash chain;
        // without re-reading the live service rules here it never self-heals, so
        // the amber "rules differ" banner stuck on after a mid-session apply the
        // user did not make. Re-reading the live revision each
        // poll makes a stale pin correct itself within one tick.
        var pending = 5
        var maybeFinish = function() {
            pending -= 1
            if (pending <= 0) {
                _driftCompare()
                root._driftRecheckInFlight = false
                var waiting = _driftRecheckDone
                _driftRecheckDone = []
                for (var i = 0; i < waiting.length; i += 1) waiting[i](true)
                if (_driftRecheckQueued) {
                    _driftRecheckQueued = false
                    Qt.callLater(_driftRecheck)
                }
            }
        }
        _driftRefreshFileHash("primary",   maybeFinish)
        _driftRefreshFileHash("secondary", maybeFinish)
        _driftUpdateGuiHash("primary",     maybeFinish)
        _driftUpdateGuiHash("secondary",   maybeFinish)
        _driftRefreshServiceHashInto(maybeFinish)
    }

    /// Decide whether to surface the drift banner. For each route,
    /// computes a pairwise mismatch classification stashed on
    /// `_driftDetails*`. The banner shows when ANY route has a
    /// non-`none` mismatch; click → DriftDetectionDialog renders the
    /// per-route detail.
    ///
    /// "No file" is NOT a drift — the user just hasn't saved yet.
    /// Per spec, that case is its own (existing) "unsaved changes"
    /// signal, not part of the drift triangle.
    function _driftCompare() {
        var anyDrift = false
        var classify = function(file, gui, service, fileExists) {
            var fileVsGui     = fileExists && file !== "" && gui !== ""     && file !== gui
            var guiVsService  = gui  !== "" && service !== ""               && gui  !== service
            var fileVsService = fileExists && file !== "" && service !== "" && file !== service
            if (fileVsGui && guiVsService && fileVsService) return "all-three-differ"
            if (fileVsGui)     return "file-vs-gui"
            if (guiVsService)  return "gui-vs-service"
            if (fileVsService) return "file-vs-service"
            return "none"
        }
        var detP = {
            file:    root._driftFileHashPrimary,
            gui:     root._driftGuiHashPrimary,
            service: root._driftServiceHashPrimary,
            mismatch: classify(root._driftFileHashPrimary, root._driftGuiHashPrimary,
                root._driftServiceHashPrimary, root._driftFileExistsPrimary)
        }
        var detS = {
            file:    root._driftFileHashSecondary,
            gui:     root._driftGuiHashSecondary,
            service: root._driftServiceHashSecondary,
            mismatch: classify(root._driftFileHashSecondary, root._driftGuiHashSecondary,
                root._driftServiceHashSecondary, root._driftFileExistsSecondary)
        }
        root._driftDetailsPrimary   = detP
        root._driftDetailsSecondary = detS
        // The amber banner now fires ONLY on a
        // real app↔service divergence (`gui-vs-service` / `all-three-differ`).
        //
        // Rationale: the "file" leg compares the RAW bound preset text against
        // the CANONICALISED applied rules. The import pipeline normalises rules
        // (ACE-encoding, dedup, reclassify, disabled-line encoding, section
        // grouping), so the raw file and the applied set are NOT byte-stable
        // even when they describe identical routing — every false banner the
        // user has hit (App==Service but
        // File≠App) was file-only. Worse, none of the dialog's resolutions
        // could clear a file-only drift (Show-diff/Apply operate on app↔service,
        // which already agreed), leaving the user stuck with an undismissable
        // banner. app↔service is the safety-critical invariant ("what I see is
        // what's enforced"); that still raises the banner. The file hashes stay
        // computed and visible inside the dialog as diagnostics.
        var alarms = function(m) {
            return m === "gui-vs-service" || m === "all-three-differ"
        }
        if (alarms(detP.mismatch) || alarms(detS.mismatch)) anyDrift = true
        // A pair the service itself called equivalent stays down until one of
        // the two sides actually changes.
        if (anyDrift && _driftAgreedPair !== "" && _driftPairKey() === _driftAgreedPair) {
            anyDrift = false
        } else if (anyDrift) {
            _logDriftDetail()
        }
        root._driftDetected = anyDrift
        // Re-promote the SUPPRESSED `file-vs-service` leg as a
        // SEPARATE quiet "Merge available" affordance. Offered when a route's
        // file and service revisions have genuinely diverged, but ONLY when the
        // amber app↔service banner is NOT up (that divergence is safety-critical
        // and takes priority; resolve it first, then merge becomes available).
        // This never feeds `_driftDetected` — no amber banner regression.
        var mergeable = function(m) { return m === "file-vs-service" }
        root._mergeAvailable =
            (mergeable(detP.mismatch) || mergeable(detS.mismatch)) && !anyDrift
    }
}
