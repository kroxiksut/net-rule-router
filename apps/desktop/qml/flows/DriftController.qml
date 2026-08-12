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
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function"
                || typeof nrrNativeBridge.rpcRulesMergePreview !== "function"
                || typeof nrrNativeBridge.decodeBase64Utf8 !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            return
        }
        var primaryPath = String(root.prefs.lastSavedPathPrimary || "")
        var secondaryPath = String(root.prefs.lastSavedPathSecondary || "")
        var primB64 = primaryPath
            ? String(nrrNativeBridge.readFileBytes(primaryPath) || "") : ""
        var secB64 = secondaryPath
            ? String(nrrNativeBridge.readFileBytes(secondaryPath) || "") : ""
        root._mergePrimaryText = primB64 ? nrrNativeBridge.decodeBase64Utf8(primB64) : ""
        root._mergeSecondaryText = secB64 ? nrrNativeBridge.decodeBase64Utf8(secB64) : ""
        var policy = String((root.prefs && root.prefs.mergeConflictPolicy) || "union")
        root.mergeReviewDialog.policy = policy
        root.mergeReviewDialog.mergeResult = null
        root.mergeReviewDialog.picks = ({})
        root.mergeReviewDialog.errorText = ""
        root.mergeReviewDialog.loading = true
        root.mergeReviewDialog.open()
        var corr = nrrNativeBridge.rpcRulesMergePreview(
            root._mergePrimaryText, root._mergeSecondaryText, policy, [])
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            root.mergeReviewDialog.loading = false
            if (!ok || !p || !p.result) {
                root.mergeReviewDialog.errorText =
                    root.tr("dialog.merge.error", "Could not build the merge preview.")
                    + (code ? (" (" + root.ipcErrorLabel(code) + ")") : "")
                return
            }
            var res = p.result
            root.mergeReviewDialog.mergeResult = res
            // Default each conflict pick to the file-provisional side (Union).
            var picks = {}
            var cs = res.conflicts || []
            for (var i = 0; i < cs.length; i += 1) {
                picks[cs[i]["identity-key"]] = "file"
            }
            root.mergeReviewDialog.picks = picks
        })
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
        for (var k = 0; k < rulesRows.length; k += 1) {
            var row = rulesRows[k]
            if (row && row.id) row.id = Rules.canonicalRuleId(row.id)
            if (row && Rules.isHostlikeRuleType(row.ruleType)) {
                row.matchValue = root._unicodeDecodeHost(row.matchValue)
            }
            if (row) row.aceMatchValue = root._aceLowerForSearch(row.matchValue)
            root.rulesModel.append(row)
        }
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
    function _driftRecheckNow(announceOffline) {
        if (((root.backendStatus || {}).kind) !== "connected") {
            if (announceOffline === true) {
                root.statusLine = root.tr("status.drift-recheck-offline",
                    "The service is not running, so the rules it applies cannot be compared right now.")
            }
            return
        }
        if (root._driftRecheckInFlight) { _driftRecheckQueued = true; return }
        _driftRecheck()
    }

    /// Periodic poll entry. Re-fetches file legs (mtime-cached) and
    /// GUI legs, then compares. Bounded by `_driftRecheckInFlight`
    /// so overlapping triggers don't interleave their async chains.
    function _driftRecheck() {
        if (root._driftRecheckInFlight) return
        if (((root.backendStatus || {}).kind) !== "connected") return
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCanonicalRulesHash !== "function") {
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
