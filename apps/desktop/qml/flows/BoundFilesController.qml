import QtQuick 2.15
import "../lib/rules.js" as Rules

// Non-visual controller for rules-file persistence + the close-flow, extracted
// from Main.qml (thin-shell rule). Owns: the "rules changed since last file
// sync" divergence check, the save-before-close dialog handlers (save /
// save-as / discard-and-rollback), the "Save to file" chip write + tooltip,
// the content-truthful dirty reconcile, the persist-on-apply write, and the
// safe (last-known-good) rollback submit. The shell keeps the shared STATE
// these read/write (`_filesSyncDirtyPrimary` / `_filesSyncDirtySecondary` /
// `_saveAsRoutes` / `_saveAsIndex` / `_resumeCloseAfterSaveBefore`) plus the
// dialog instances (`saveBeforeCloseDialog` / `saveAsFileDialog` /
// `safeRollbackConfirmDialog`) and the generic `_pushOperationToast`. RPC goes
// through `root.rpc`; `nrrNativeBridge` is a global QML context property,
// referenced bare. Reached as `root.boundFilesController` from the
// close-dialog wiring, the footer chip, RulesSection and ReviewFlowController.
//
// EVERY write of rules to disk goes through `_writeTargets` here, and the
// bytes always come from the local rules table via
// `Rules.buildCanonicalRulesText` — never from the service. Saving your rules
// therefore works with the service stopped, which is the whole point: a user
// who cannot start the service must still be able to keep their work.
QtObject {
    id: boundFilesController
    property var root

    // ── writing rules to disk ────────────────────────────────────────────

    /// `true` when comments are emitted into the file, mirroring the last
    /// choice made in the export options. Kept in one place so a write and the
    /// "is the file still up to date?" compare cannot disagree about it.
    function _emitComments() {
        return !root.prefs || root.prefs.exportIncludeComments !== false
    }

    /// The foreign-OS / Pro sections captured at the last import for `route`,
    /// handed to `onSections`. The sidecar is owned by the launcher, not the
    /// service, so this resolves with the service stopped; any failure
    /// degrades to "no passthrough" rather than blocking the save.
    function _readPassthroughSections(route, onSections) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarPassthroughRead !== "function"
                || !root.rpc || typeof root.rpc.registerRpcCallback !== "function") {
            onSections({})
            return
        }
        var corr = nrrNativeBridge.rpcSidecarPassthroughRead(route)
        if (!corr || String(corr) === "") { onSections({}); return }
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.log("sidecar.passthrough.read failed:", code, msg)
            onSections((ok && payload && payload.sections) || {})
        })
    }

    /// Does `path` already hold these rules? Compares the routing BODY, not
    /// the bytes: the metadata header carries the generation timestamp, so a
    /// byte compare would call every file stale the moment it is regenerated.
    function _fileHoldsText(path, text) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") return false
        var b64 = String(nrrNativeBridge.readFileBytes(path) || "")
        if (b64 === "") return false
        var current = ""
        try { current = Qt.atob(b64) } catch (e) { return false }
        return Rules.canonicalRulesBody(current) === Rules.canonicalRulesBody(text)
    }

    /// Generate `route`'s rules from the local table and write them to `path`.
    /// `onDone(ok, changed)` — `changed` is false when the file already held
    /// these rules and was left alone (no needless mtime churn, no misleading
    /// "saved" report for a route nobody touched).
    function writeRouteToPath(route, path, includeComments, onDone) {
        var done = function(ok, changed) {
            if (typeof onDone === "function") onDone(!!ok, !!changed)
        }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.writeTextFile !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            done(false, false)
            return
        }
        _readPassthroughSections(route, function(sections) {
            var text = Rules.buildCanonicalRulesText(
                root.rulesModel, route, sections,
                (includeComments === undefined) ? _emitComments() : !!includeComments)
            if (_fileHoldsText(path, text)) { done(true, false); return }
            if (!nrrNativeBridge.writeTextFile(path, text)) {
                console.log("[bound-file] writeTextFile failed:", route, path)
                root.statusLine = root.tr("status.export-write-failed",
                    "Cannot write preset file to the chosen path.") + " " + path
                done(false, false)
                return
            }
            done(true, true)
        })
    }

    // ── the "this is one of the app's own rule sets" gate ────────────────

    /// The write the warning is holding: the `[{route, path, includeComments}]`
    /// it would have performed, plus the continuation that performs it once the
    /// user answers. `resume(targets, sameLocation)`.
    property var _factoryHold: null

    /// Warn — do not refuse — before writing into the rule sets that ship with
    /// the app: the next update replaces that folder, so anything saved there
    /// is lost. Returns `true` when the dialog took over and the caller must
    /// not write; the answer resumes the write through the held continuation.
    /// One gate for every write path, so "Export to file…", the "Save to file"
    /// chip and the close-time saves can no longer disagree about it.
    function _guardFactoryTargets(targets, resume, cancel) {
        var blocked = ""
        for (var i = 0; i < targets.length; i += 1) {
            if (root.isFactoryPresetPath(targets[i].path)) {
                blocked = String(targets[i].path)
                break
            }
        }
        if (blocked === "") return false
        _factoryHold = { targets: targets, resume: resume, cancel: cancel }
        root.factoryPresetSaveDialog.mode = "factory"
        root.factoryPresetSaveDialog.blockedPath = blocked
        if (!root.factoryPresetSaveDialog.visible) root.factoryPresetSaveDialog.open()
        return true
    }

    /// "Save here anyway": the user acknowledged that an update takes the file
    /// with it (factory mode) or that a same-named set is being replaced
    /// (overwrite-set mode). Same dialog, two holds — whichever is set wins.
    function factorySaveHereConfirmed() {
        if (_overwriteSetHold) {
            var setHold = _overwriteSetHold
            _overwriteSetHold = null
            if (setHold.resume) setHold.resume()
            return
        }
        var hold = _factoryHold
        _factoryHold = null
        if (hold) hold.resume(hold.targets, true)
    }

    /// The user picked a folder of their own instead: rebase every held target
    /// to `<folder>/rules_<route>.txt` and run the write there. A user who had
    /// no rule-set folder yet has just designated one — every rule-file picker
    /// anchors there next. (Factory mode only — overwrite-set mode hides this
    /// button, there is no folder choice to make.)
    function rebindBlockedRoutesTo(folder) {
        var dir = String(folder || "").replace(/\\/g, "/").replace(/\/+$/, "")
        var hold = _factoryHold
        _factoryHold = null
        if (!hold) return
        if (dir === "") { if (hold.cancel) hold.cancel(); return }
        if (!root.hasRulesFolder) root.setUserPresetsDir(dir)
        var rebased = []
        for (var i = 0; i < hold.targets.length; i += 1) {
            var t = hold.targets[i]
            rebased.push({ route: t.route,
                           path: dir + "/rules_" + t.route + ".txt",
                           includeComments: t.includeComments })
        }
        hold.resume(rebased, false)
    }

    /// The user backed out of either gate. Nothing was written — say so
    /// instead of leaving a silent no-op.
    function cancelFactoryPathRebind() {
        if (_overwriteSetHold) {
            var setHold = _overwriteSetHold
            _overwriteSetHold = null
            if (setHold.cancel) setHold.cancel()
            return
        }
        var hold = _factoryHold
        _factoryHold = null
        root.statusLine = root.tr("status.bound-file-factory-not-saved",
            "Nothing was saved — the linked file is part of the app's own rule sets.")
        if (hold && hold.cancel) hold.cancel()
    }

    // ── the "this rule-set folder already has files" gate ────────────────

    /// The confirm the overwrite-set dialog is holding: `resume()` writes,
    /// `cancel()` reports nothing was saved. Reuses `factoryPresetSaveDialog`
    /// (same "about to clobber something" shape) with `mode: "overwrite-set"`
    /// instead of a bespoke dialog.
    property var _overwriteSetHold: null

    /// Does `dir` (a rule-set folder) already hold a primary or secondary
    /// rules file? `statFile` is the same cheap existence probe the drift
    /// watcher uses — no content read needed, just "is something there".
    function _ruleSetDirHasFiles(dir) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.statFile !== "function") return false
        var exists = function(p) {
            var stat = nrrNativeBridge.statFile(p)
            return !!(stat && stat.exists)
        }
        return exists(dir + "/rules_primary.txt") || exists(dir + "/rules_secondary.txt")
    }

    /// Confirm-before-overwrite gate for "save rules as a set": returns `true`
    /// when `dir` already holds a route file and the dialog took over —
    /// `resume()` is the caller's continuation on "save here anyway",
    /// `cancel()` on "Cancel". Returns `false` (write clear to proceed) for an
    /// empty or brand-new set folder.
    function guardExistingSetDir(dir, resume, cancel) {
        if (!_ruleSetDirHasFiles(dir)) return false
        _overwriteSetHold = { resume: resume, cancel: cancel }
        root.factoryPresetSaveDialog.mode = "overwrite-set"
        root.factoryPresetSaveDialog.blockedPath = dir
        if (!root.factoryPresetSaveDialog.visible) root.factoryPresetSaveDialog.open()
        return true
    }

    /// Write a list of `{route, path, includeComments}` from the local table.
    /// Remembering the path as the route's file is part of the write: after
    /// the warning above rebases a target, or the Save-As picker names one,
    /// that file is where the route lives from now on.
    /// `onDone(ok, writtenPaths)`; `writtenPaths` lists only the files that
    /// actually changed.
    function _writeTargets(targets, allowFactory, onDone) {
        var done = function(ok, paths) {
            if (typeof onDone === "function") onDone(!!ok, paths || [])
        }
        if (!targets || targets.length === 0) { done(true, []); return }
        if (!allowFactory && _guardFactoryTargets(targets,
                function(resolved, sameLocation) { _writeTargets(resolved, sameLocation, onDone) },
                function() { done(false, []) })) return
        var pending = targets.length
        var okAll = true
        var written = []
        var patch = {}
        var settle = function() {
            pending -= 1
            if (pending > 0) return
            if (Object.keys(patch).length > 0) {
                // Persist the binding now: `updatePrefs` only touches the
                // in-memory object, and a killed process loses it otherwise.
                root.updatePrefs(patch)
                root.emitPrefs()
            }
            // The file leg just moved. Re-compare now instead of leaving the
            // amber banner to catch up on the next poll a minute later.
            if (okAll && root.driftController
                    && typeof root.driftController._driftRecheckNow === "function") {
                Qt.callLater(root.driftController._driftRecheckNow)
            }
            done(okAll, written)
        }
        var writeOne = function(t) {
            writeRouteToPath(t.route, t.path, t.includeComments, function(ok, changed) {
                if (!ok) { okAll = false; settle(); return }
                if (changed) written.push(t.path)
                if (t.route === "primary") {
                    root._filesSyncDirtyPrimary = false
                    if (String(root.prefs.lastSavedPathPrimary || "") !== t.path) {
                        patch.lastSavedPathPrimary = t.path
                        patch.lastLoadedPathPrimary = t.path
                    }
                } else {
                    root._filesSyncDirtySecondary = false
                    if (String(root.prefs.lastSavedPathSecondary || "") !== t.path) {
                        patch.lastSavedPathSecondary = t.path
                        patch.lastLoadedPathSecondary = t.path
                    }
                }
                root.suggestRulesFolder(t.path)
                settle()
            })
        }
        for (var i = 0; i < targets.length; i += 1) writeOne(targets[i])
    }

    /// Rules → "Export to file…": write one route to the path the user picked.
    function exportRouteToPath(route, path, includeComments) {
        _writeTargets([{ route: route, path: String(path),
                         includeComments: includeComments }], false,
            function(ok) {
                if (ok) root.statusLine = root.tr("status.export-completed", "Preset exported.")
            })
    }

    /// Write several routes to explicit paths as ONE gesture ("save the current
    /// rules as a set"): a single factory gate, a single prefs flush and a
    /// single verdict instead of one per route. `onDone(ok, writtenPaths)`.
    function exportRoutesToPaths(targets, onDone) {
        _writeTargets(targets, false, onDone)
    }

    /// Does `route` hold any rule at all? Drives which routes the export
    /// picker asks about — an empty route is not worth a file dialog.
    function _routeHasRules(route) {
        if (!root.rulesModel) return false
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            var row = root.rulesModel.get(i)
            if (!row) continue
            var r = String(row.targetRoute || "")
            if ((r === "block" ? "secondary" : r) === String(route)) return true
        }
        return false
    }

    /// File → "Export current list…" / footer "Save to file" with nothing
    /// linked yet: save the current rules as a SET — both route files
    /// together, in one new folder, even when one route has no rules of its
    /// own (it still gets a header-only file, so the pair reads back as one
    /// set). Always asks where — a deliberate "put a copy here" gesture,
    /// unlike the "Save to file" chip which reuses an already-linked file.
    function exportCurrentRulesInteractive(onDone) {
        if (!_routeHasRules("primary") && !_routeHasRules("secondary")) {
            root.statusLine = root.tr("status.export-nothing-to-export",
                "There are no rules to export yet.")
            if (typeof onDone === "function") onDone(false)
            return
        }
        _exportSetDone = (typeof onDone === "function") ? onDone : null
        // Reuses the per-route Save-As picker with a sentinel route: one
        // dialog names the set (its file name becomes the folder name, its
        // parent folder becomes the container) instead of one dialog per
        // route, so the pair can no longer come apart mid-gesture.
        root.saveAsFileDialog.pendingRoute = "__set__"
        root.saveAsFileDialog.title = root.tr(
            "rules.dialog.export-set-title", "Save rules as a set...")
        root.openRulesDialog(root.saveAsFileDialog)
    }

    /// Pending target of `exportCurrentRulesInteractive`, resolved by
    /// `_handleExportSetPathChosen` / cancelled by `_handleSaveAsCancelled`.
    property var _exportSetDone: null

    /// A set name is a folder name, never a path — the same refusal the
    /// bridge applies when creating the folder, checked here first so the
    /// error reads as "bad name" rather than a generic write failure.
    function _isUsableSetName(name) {
        var n = String(name || "").trim()
        if (n === "" || n === ".") return false
        if (n.indexOf("/") >= 0 || n.indexOf("\\") >= 0) return false
        if (n.indexOf(":") >= 0 || n.indexOf("..") >= 0) return false
        return true
    }

    /// The Save-As picker returned a path for the `__set__` sentinel: split
    /// it into the container folder and the set name (the file name minus
    /// its extension), then hand off to the shared set-writer.
    function _handleExportSetPathChosen(path) {
        var norm = String(path || "").replace(/\\/g, "/")
        var slash = norm.lastIndexOf("/")
        var containerDir = slash >= 0 ? norm.substring(0, slash) : ""
        var fileName = slash >= 0 ? norm.substring(slash + 1) : norm
        var dot = fileName.lastIndexOf(".")
        var setName = (dot > 0) ? fileName.substring(0, dot) : fileName
        if (containerDir === "" || !_isUsableSetName(setName)) {
            root.statusLine = root.tr("status.save-as-set-name-invalid",
                "Choose a plain file name for the set — it becomes the set's folder name.")
            _settleExportSet(false)
            return
        }
        _createAndWriteSet(containerDir, setName, _settleExportSet)
    }

    function _settleExportSet(ok) {
        var cb = _exportSetDone
        _exportSetDone = null
        if (cb) cb(!!ok)
    }

    /// THE "save the rules table as a named set" write, shared by the Rules
    /// toolbar/footer flow above and Settings → Presets' "Save current rules
    /// as a set…" button: create `<containerDir>/<setName>/`, confirm before
    /// clobbering a set already there, then write BOTH route files — the
    /// factory-folder gate and the prefs rebinding ride along inside
    /// `exportRoutesToPaths`. `onDone(ok)`.
    function _createAndWriteSet(containerDir, setName, onDone) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.createPresetSetDir !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            onDone(false)
            return
        }
        var dir = String(nrrNativeBridge.createPresetSetDir(containerDir, setName) || "")
        if (dir === "") {
            root.statusLine = root.tr("status.save-as-set-folder-failed",
                "Could not create the set folder. Check that the folder above is writable.")
            onDone(false)
            return
        }
        var proceed = function() { _writeSetFiles(dir, onDone) }
        if (guardExistingSetDir(dir, proceed, function() {
                root.statusLine = root.tr("status.save-as-set-overwrite-cancelled",
                    "Nothing was saved — the set already had files there.")
                onDone(false)
            })) return
        proceed()
    }

    function _writeSetFiles(dir, onDone) {
        exportRoutesToPaths(
            [{ route: "primary",   path: dir + "/rules_primary.txt" },
             { route: "secondary", path: dir + "/rules_secondary.txt" }],
            function(ok) {
                if (ok) {
                    root.statusLine = root.tr("status.save-as-set-done", "Saved as a set: ") + dir
                    root.presetSetsChanged()
                } else {
                    root.statusLine = root.tr("status.save-as-set-failed",
                        "Could not save the set. See logs for details.")
                }
                onDone(ok)
            })
    }

    /// Auto-rules landed in the user's own rule set on the service's
    /// initiative (a suggestion accepted from the tray, or "apply
    /// automatically"). Pull them into the table, then write them to the linked
    /// rules files — an address the user just accepted must not turn into a
    /// divergence they are asked about a second later.
    ///
    /// Local edits win: re-pulling would discard whatever the user is in the
    /// middle of typing, so a dirty rules editor is told rather than clobbered.
    function handleAutoRulesAuthored() {
        if (root.unsavedChangesRegistry && root.unsavedChangesRegistry["rules"]) {
            root.setStatus(
                root.tr("status.auto-rules-added-unsaved-short",
                    "Addresses added — reload to see them"),
                root.tr("status.auto-rules-added-unsaved",
                    "Addresses a routed site needs were added to your rules. Save or discard your edits, then reload the rules to see them."))
            return
        }
        root._refreshRulesFromService({
            silent: true,
            onComplete: function(ok) {
                if (!ok) return
                _markBoundFilesDirtyForAutoRules()
            }
        })
    }

    function _markBoundFilesDirtyForAutoRules() {
        var hasPrimary = root.prefs.lastSavedPathPrimary
            && String(root.prefs.lastSavedPathPrimary) !== ""
        var hasSecondary = root.prefs.lastSavedPathSecondary
            && String(root.prefs.lastSavedPathSecondary) !== ""
        if (hasPrimary) root._filesSyncDirtyPrimary = true
        if (hasSecondary) root._filesSyncDirtySecondary = true
        if (hasPrimary || hasSecondary) {
            _writeBoundFiles(true, null, true)
            return
        }
        root.statusLine = root.tr("status.auto-rules-added",
            "Addresses a routed site needs were added to your rules.")
    }

    /// The routes that BOTH have a linked file and no longer match it. That
    /// pair — not "the rules were edited" — is the whole subject of the
    /// close-time prompt: the edits are already applied in the service, so a
    /// user who keeps no rules file has nothing to decide and a modal across
    /// the exit is pure friction. The "Save to file" chip stays available for
    /// them; only the interruption is dropped.
    function _boundDirtyRoutes() {
        var routes = []
        if (root._filesSyncDirtyPrimary
                && String(root.prefs.lastSavedPathPrimary || "") !== "") {
            routes.push("primary")
        }
        if (root._filesSyncDirtySecondary
                && String(root.prefs.lastSavedPathSecondary || "") !== "") {
            routes.push("secondary")
        }
        return routes
    }

    function _filesSyncDivergenceExists() {
        return _boundDirtyRoutes().length > 0
    }

    function _showSaveBeforeCloseDialog() {
        // Report only the routes the prompt exists for — an unlinked route is
        // not what the user is being asked about here.
        var routes = _boundDirtyRoutes()
        root.saveBeforeCloseDialog.primaryDirty = routes.indexOf("primary") >= 0
        root.saveBeforeCloseDialog.secondaryDirty = routes.indexOf("secondary") >= 0
        root.saveBeforeCloseDialog.primaryPath = String(root.prefs.lastSavedPathPrimary || "")
        root.saveBeforeCloseDialog.secondaryPath = String(root.prefs.lastSavedPathSecondary || "")
        root.saveBeforeCloseDialog.open()
    }

    // Discard & rollback: GUI submits a PresetImport with empty bytes for both
    // routes — the server-side flow produces a fresh zero-rules
    // active revision and emits a standard `RevisionActivated` audit
    // event. Avoids a separate `rpcRollbackRequest` bridge method
    // (which would need its own token-fetch round-trip) and reuses
    // the already-vetted ReviewDiffDialog → ConfirmActivate path so
    // the user sees what they're discarding.
    function _handleDiscardAndRollback() {
        var emptyPreset = "--- Zones\n\n--- Domains\n\n--- IP\n\n--- Windows\n\n--- Linux\n\n--- MacOS\n"
        var emptyB64 = Qt.btoa(emptyPreset)
        if (!emptyB64) {
            root.statusLine = root.tr("status.rollback-discard-failed",
                "Failed to roll back changes: ") + "(no bridge)"
            return
        }
        root.presetImportController.startBothRoutesPresetImportReviewFlow(emptyB64, emptyB64, "", "")
        // Clear divergence flags optimistically. If the user cancels
        // the review dialog they remain on the active (non-empty)
        // revision; the next close-pass will surface the dialog
        // again because the flags are recalculated from divergence
        // state on each `_filesSyncDivergenceExists()` call.
        root._filesSyncDirtyPrimary = false
        root._filesSyncDirtySecondary = false
    }

    /// Close dialog → "Save". Same local write as everywhere else, so it works
    /// with the service stopped; the close waits for it. Only the linked
    /// routes are written — the prompt only ever appears for those, and a file
    /// picker thrown across the exit is exactly what this flow avoids.
    function _handleSaveSelectedFromCloseDialog() {
        _writeBoundFiles(false, function(ok) {
            if (!ok) {
                // The failure is already on the status line — keep the window
                // open rather than closing over unsaved rules. A cancelled
                // factory warning lands here too, which is why that gate must
                // resolve instead of going silent.
                root._resumeCloseAfterSaveBefore = false
                return
            }
            root.quittingToTray = true
            root.close()
        }, true /* includeClean */)
    }

    /// Write every linked route back to its file so it never goes stale.
    /// Best-effort and silent — a failure leaves the dirty flag up so the chip /
    /// close dialog can still surface it. Only touches routes that already have
    /// a file; an apply must not pop a picker.
    ///
    /// Deliberately `includeClean`: the write content-compares each route
    /// against the file first, so a clean route costs nothing — and the dirty
    /// flags cannot be trusted here anyway, because the reconcile that sets
    /// them is async and often has not answered yet when an apply completes.
    function _persistBoundFilesAfterApply() {
        _writeBoundFiles(false, null, true)
    }

    /// The footer "Save to file" chip.
    function _saveBoundFilesNow() {
        saveRulesToFiles(true, null)
    }

    // Tooltip for the orange "Save to file" chip: explains WHY it is showing
    // (the rules no longer match the linked file) and WHERE clicking saves —
    // or that it will ask, when no file is linked yet.
    function _boundFileChipTooltip() {
        var paths = []
        if (root.prefs.lastSavedPathPrimary && String(root.prefs.lastSavedPathPrimary) !== "")
            paths.push(String(root.prefs.lastSavedPathPrimary))
        if (root.prefs.lastSavedPathSecondary && String(root.prefs.lastSavedPathSecondary) !== "")
            paths.push(String(root.prefs.lastSavedPathSecondary))
        var base = root.tr("status.bound-file-save-tooltip",
            "The applied rules changed, so your linked rules file is out of date. Click to update it.")
        if (paths.length === 0) {
            return base + "\n" + root.tr("status.bound-file-none-linked",
                "No rules file is linked yet — you will be asked where to save.")
        }
        return base + "\n" + root.tr("status.bound-file-save-destination", "Saves to:")
            + "\n" + paths.join("\n")
    }

    // Make the dirty flags CONTENT-truthful. An activation / non-silent
    // refresh used to set both true unconditionally, so the "Save to file"
    // chip appeared even when the file on disk already held these rules
    // ("ничего не менял — что сохранять?"). Each route's flag is decided by
    // generating its text locally and comparing bodies with the file — the
    // same compare the write does, moved to SET time so the chip is only
    // offered on a REAL divergence. A route with no file keeps whatever the
    // edit tracker decided: there is nothing to reconcile it against.
    function _reconcileBoundFileDirty() {
        var reconcile = function(route, path, apply) {
            if (!path || String(path) === "") return
            writeRouteDiffers(route, String(path), apply)
        }
        reconcile("primary", root.prefs ? root.prefs.lastSavedPathPrimary : "",
            function(dirty) { root._filesSyncDirtyPrimary = dirty })
        reconcile("secondary", root.prefs ? root.prefs.lastSavedPathSecondary : "",
            function(dirty) { root._filesSyncDirtySecondary = dirty })
    }

    /// Do `route`'s current rules differ from what `path` holds? Async only
    /// because the passthrough sections come from the sidecar. Falls safe to
    /// "differs" — surfacing a save the user does not need beats hiding one
    /// they do.
    function writeRouteDiffers(route, path, onResult) {
        _readPassthroughSections(route, function(sections) {
            var text = Rules.buildCanonicalRulesText(
                root.rulesModel, route, sections, _emitComments())
            onResult(!_fileHoldsText(path, text))
        })
    }

    /// Write the routes that already have a file. `includeClean` covers the
    /// explicit "save now" gesture: the user asked, so every linked route is
    /// checked, not only the ones the edit tracker flagged (the write skips
    /// files that already hold the rules, so the extra check is free).
    /// `onDone(ok, written)`.
    function _writeBoundFiles(toast, onDone, includeClean) {
        var targets = []
        var pathPrimary = String(root.prefs.lastSavedPathPrimary || "")
        var pathSecondary = String(root.prefs.lastSavedPathSecondary || "")
        if (pathPrimary !== "" && (includeClean || root._filesSyncDirtyPrimary)) {
            targets.push({ route: "primary", path: pathPrimary })
        }
        if (pathSecondary !== "" && (includeClean || root._filesSyncDirtySecondary)) {
            targets.push({ route: "secondary", path: pathSecondary })
        }
        _writeTargets(targets, false, function(ok, written) {
            if (toast && ok && written.length > 0) {
                // Surface WHERE it saved so "куда сохраняет?" is answered.
                root.statusLine = root.tr("status.bound-file-saved", "Bound rules file saved.")
                    + " → " + written.join("\n")
            }
            if (typeof onDone === "function") onDone(ok, written)
        })
    }

    /// THE "save my rules to disk" gesture, behind the footer chip, the
    /// close dialog, the service-not-running gate and the offline apply guard.
    /// Routes that already have a file are written; routes that do not get the
    /// Save-As picker, so a user who never linked a file — or who just cleared
    /// the table, which unlinks it — can still save. `onDone(ok)`.
    function saveRulesToFiles(toast, onDone) {
        var pathPrimary = String(root.prefs.lastSavedPathPrimary || "")
        var pathSecondary = String(root.prefs.lastSavedPathSecondary || "")
        var unbound = []
        if (root._filesSyncDirtyPrimary && pathPrimary === "") unbound.push("primary")
        if (root._filesSyncDirtySecondary && pathSecondary === "") unbound.push("secondary")
        // No file anywhere to save into: ask where rather than reporting a
        // silent no-op.
        if (pathPrimary === "" && pathSecondary === "" && unbound.length === 0) {
            exportCurrentRulesInteractive(onDone)
            return
        }
        _writeBoundFiles(toast, function(ok, written) {
            if (!ok || unbound.length === 0) {
                if (toast && ok && written.length === 0) {
                    root.statusLine = root.tr("status.bound-file-already-current",
                        "Your rules file already holds these rules.")
                }
                if (typeof onDone === "function") onDone(ok)
                return
            }
            _startSaveAsQueue(unbound, onDone)
        }, true /* includeClean */)
    }

    // Submit a Safe rollback (RollbackRequest recovery
    // action) to the service: restore the last-known-good revision and re-apply
    // it. Was a no-op "preview mode" toast. Recovery actions require a non-empty
    // confirmation token (the router checks presence, not value — RollbackRequest
    // has no dry-run step) and an elevated client; a non-elevated GUI gets a
    // Forbidden error which we surface localized rather than silently swallow.
    function _performSafeRollback() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRollbackRequest !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Native bridge unavailable")
            return
        }
        var token = "gui-rollback-" + Date.now()
        root.statusLine = root.tr("status.rollback-submitting", "Submitting safe rollback…")
        var corr = nrrNativeBridge.rpcRollbackRequest("", token)
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("status.rollback-failed", "Safe rollback failed: ")
                    + root.ipcErrorLabel(code)
                return
            }
            root.statusLine = root.tr("status.rollback-submitted",
                "Safe rollback submitted. The service is restoring the previous configuration.")
        })
    }

    // "Save As" from the close dialog: pick a path for every dirty route, one
    // picker at a time, then finish the deferred close. Cancelling any picker
    // ABORTS the close (nothing is lost, the window stays).
    function _handleSaveAsFromCloseDialog() {
        // Same routes the prompt listed, so "Save As" cannot pop a picker for
        // a route the user was never asked about.
        var q = _boundDirtyRoutes()
        if (q.length === 0) {
            // Nothing pending to save → just proceed with the close.
            root.quittingToTray = true
            root.close()
            return
        }
        _startSaveAsQueue(q, function(ok) {
            if (!ok) { root._resumeCloseAfterSaveBefore = false; return }
            root.quittingToTray = true
            root.close()
        })
    }

    // ── Save-As picker queue ─────────────────────────────────────────────
    //
    // The routes still to be picked live in the shell (`_saveAsRoutes` /
    // `_saveAsIndex`) because the FileDialog does; the continuation lives here.
    // `onDone(ok)` fires once the queue drains — or with `false` the moment the
    // user cancels a picker, which abandons the remaining routes.
    property var _saveAsDone: null

    function _startSaveAsQueue(routes, onDone) {
        root._saveAsRoutes = routes
        root._saveAsIndex = 0
        _saveAsDone = (typeof onDone === "function") ? onDone : null
        _saveAsOpenNext()
    }

    function _settleSaveAsQueue(ok) {
        root._saveAsRoutes = []
        var cb = _saveAsDone
        _saveAsDone = null
        if (cb) cb(!!ok)
    }

    // Open the SaveFile picker for the next queued route, or settle the queue.
    function _saveAsOpenNext() {
        if (root._saveAsIndex >= root._saveAsRoutes.length) {
            _settleSaveAsQueue(true)
            return
        }
        var route = root._saveAsRoutes[root._saveAsIndex]
        root.saveAsFileDialog.pendingRoute = route
        // Title tells the user WHICH route they are choosing a path for.
        root.saveAsFileDialog.title = (route === "primary")
            ? root.tr("rules.dialog.export-title-primary", "Save primary rules as…")
            : root.tr("rules.dialog.export-title-secondary", "Save additional-adapter rules as…")
        root.openRulesDialog(root.saveAsFileDialog)
    }

    /// The picker returned a path. The `__set__` sentinel route means
    /// `exportCurrentRulesInteractive` opened it — hand off to the set writer
    /// instead of the per-route queue. Otherwise write the queued route from
    /// the local table (which also links it), then advance.
    function _handleSaveAsPathChosen(route, path) {
        if (route === "__set__") { _handleExportSetPathChosen(path); return }
        _writeTargets([{ route: route, path: String(path) }], false, function(ok, written) {
            if (!ok) { _settleSaveAsQueue(false); return }
            root.statusLine = root.tr("status.bound-file-saved", "Bound rules file saved.")
                + " → " + (written.length > 0 ? written.join("\n") : String(path))
            root._saveAsIndex += 1
            _saveAsOpenNext()
        })
    }

    /// The picker was cancelled. For the `__set__` sentinel, resolve the
    /// pending export-as-set promise; otherwise the remaining per-route
    /// queue is abandoned — nothing written so far is lost, and the caller
    /// decides what the cancel means (a close is aborted, a plain save just
    /// stops).
    function _handleSaveAsCancelled() {
        root.statusLine = root.tr("status.save-as-cancelled",
            "Save As cancelled — nothing more was saved.")
        if (root.saveAsFileDialog.pendingRoute === "__set__") {
            _settleExportSet(false)
            return
        }
        _settleSaveAsQueue(false)
    }
}
