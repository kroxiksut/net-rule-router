import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import "../theme"
import "../components"
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

ColumnLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    // Sort: which column drives the order, and direction.
    // Filter: status (all/enabled-only/disabled-only) and type (all + 4 designed
    // categories). Search: case-insensitive substring across matchValue + comment.
    property string sortBy: "by-display-order"
    property string sortDir: "asc"
    property string filterEnabled: "all"
    property string filterType: "all"
    property string filterRoute: "all"      // фильтр по маршруту
    /// Show only rules the service authored (they carry an origin tag; a rule
    /// the user typed carries none).
    property bool filterAutoAddedOnly: false
    property string searchText: ""

    /// True while an administrator has turned rule editing off for this
    /// machine. Everything that would change or push rules is disabled;
    /// viewing, searching, filtering and exporting stay available. The real
    /// refusal lives in the service — this only stops the user composing a
    /// change that is guaranteed to bounce.
    readonly property bool rulesLocked: root.allowUserRuleEdits === false

    /// Refuse a rule-changing action while the lock is on and say why.
    /// Returns true when the caller must stop. Every entry point that is not
    /// a plain button (menu item, double-click, keyboard) goes through it, so
    /// disabling the buttons is a courtesy rather than the only barrier.
    function _refuseWhenLocked() {
        if (!section.rulesLocked) return false
        root.statusLine = root.tr("errors.rules-locked",
            "Your administrator manages the routing rules on this computer, so they cannot be changed here.")
        return true
    }

    // ──  — MODEL-LEVEL filtering+sorting ──────────
    // The ListView binds to `displayModel`, which contains ONLY the rows that
    // pass the current filter, already sorted. This restores proper ListView
    // virtualization: it realizes ~one viewport of delegates (~15), never 300.
    //
    // The previous design filtered via per-delegate `visible:false` + height 0.
    // To lay that out, the ListView had to REALIZE hidden rows just to measure
    // them as zero — so "all types" (300 visible) built heavy delegates en
    // masse and hung the app, and sort rebound every realized delegate. Moving
    // the filter/sort to the model removes that entirely.
    //
    // `root.rulesModel` stays the master / source-of-truth (edited in place:
    // add / remove / toggle / move). Every displayModel row carries `masterId`
    // (= the rule id, a stable R-NNNN) so the delegate maps back to the master
    // for selection and edits.
    function rebuildDisplay() {
        if (typeof displayModel === "undefined" || displayModel === null
                || !root.rulesModel) return
        var arr = []
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            var entry = root.rulesModel.get(i)
            if (!section.passesFilter(entry)) continue
            var snapshot = {}
            var keys = Object.keys(entry)
            for (var k = 0; k < keys.length; k += 1) {
                var v = entry[keys[k]]
                // Skip undefined members. Rows imported from a
                // preset don't carry every role (e.g. `validationMessageArgs`),
                // so reading them back yields undefined; appending an object
                // with an undefined member makes QML's ListModel log
                // "Adding an object with a undefined member does not create a
                // role for it" on EVERY row → log flood. Omit them (the delegate
                // already guards missing roles with `|| ""` / `if (args)`).
                if (v === undefined) continue
                snapshot[keys[k]] = v
            }
            // masterId (rule id) is NOT unique — primary/secondary routes are
            // numbered independently by the service, so R-NNNN can collide
            // across routes. `masterIndex` (position in the master model) IS
            // unique and is what selection / edit / toggle key on. Keeping
            // masterId too only for display/debug.
            snapshot.masterId = String(entry.id || "")
            snapshot.masterIndex = i
            arr.push(snapshot)
        }
        arr.sort(compareRules)
        displayModel.clear()
        for (var j = 0; j < arr.length; j += 1) displayModel.append(arr[j])
    }
    // 0 ms coalescing timer: populating `rulesModel` (clear + 300 appends) fires
    // countChanged ~301 times in one batch; restarting a 0 ms timer collapses
    // that into a SINGLE rebuild after the batch settles, instead of 301.
    Timer {
        id: rebuildTimer
        interval: 0
        repeat: false
        onTriggered: section.rebuildDisplay()
    }
    // While `root.rulesBulkLoading` is set (Main.qml's `_refreshRulesFromService`
    // clear+repopulate), every chunk of `rulesModel.append()` calls fires
    // `onCountChanged` below — restarting this 0 ms timer on each chunk instead
    // of once at the end, because `_appendRowsChunked` yields to the event loop
    // (`Qt.callLater`) BETWEEN chunks, giving the timer a chance to fire before
    // the next chunk lands. That turned one populate into ceil(N/75) full
    // `rebuildDisplay()` passes. Hold off entirely while the flag is set; the
    // `onRulesBulkLoadingChanged` handler below fires the single rebuild once
    // the model has fully settled.
    function scheduleRebuild() {
        if (root && root.rulesBulkLoading === true) return
        rebuildTimer.restart()
    }

    // Per-row select / edit / toggle key on the MASTER INDEX (unique), not the
    // rule id (which collides across routes). The delegate passes
    // `model.masterIndex`, captured in `rebuildDisplay`.
    function _setRuleEnabledAt(masterIndex, enabled) {
        if (section._refuseWhenLocked()) return
        if (masterIndex < 0 || !root.rulesModel
                || masterIndex >= root.rulesModel.count) return
        root.rulesModel.setProperty(masterIndex, "enabled", !!enabled)
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
    }

    onFilterTypeChanged:    scheduleRebuild()
    onFilterEnabledChanged: scheduleRebuild()
    onFilterRouteChanged:   scheduleRebuild()
    onFilterAutoAddedOnlyChanged: scheduleRebuild()
    onSearchTextChanged:    scheduleRebuild()
    Component.onCompleted:  rebuildDisplay()
    Connections {
        target: root ? root.rulesModel : null
        // External row add/remove/reset (snapshot bind, preset import, clear).
        // In-place edits (toggle / move) call scheduleRebuild() from their
        // handlers since those don't change the row count.
        function onCountChanged() { section.scheduleRebuild() }
    }
    Connections {
        // A single-rule dialog edit (saveRule →
        // rulesModel.set) does not change the row count, so onCountChanged
        // above can't see it. The window emits rulesModelEdited() after every
        // edit; rebuild the display snapshot so the change shows immediately
        // (this is what previously only happened on a manual re-search).
        target: root
        function onRulesModelEdited() { section.scheduleRebuild() }
        // Bulk-load settle signal — see `scheduleRebuild()` doc comment above.
        // `rulesBulkLoading` flips true→false exactly once per service
        // refetch/import, AFTER the model is fully populated and overlaid;
        // this is the single rebuild that replaces the ceil(N/75) per-chunk
        // ones. Guard against the false→false no-op some property-write
        // patterns produce (QML still emits the signal only on an actual
        // value change, but the boolean condition here is the belt to that
        // suspenders).
        function onRulesBulkLoadingChanged() {
            if (root && root.rulesBulkLoading === false) section.rebuildDisplay()
        }
        // A set was written into the folder from Settings. The folder PATH is
        // unchanged, so `onPresetsSourceDirChanged` below stays silent and the
        // dropdown would keep listing yesterday's sets until a restart.
        function onPresetSetsChanged() {
            if (!section._presetRowReady) return
            section._refreshBundledPresetSelection()
        }
    }

    // Sets can also appear without the app touching the folder at all (copied
    // in Explorer), and nothing signals that. Re-enumerating whenever the user
    // comes back to this screen is cheap and covers it.
    onVisibleChanged: {
        if (!visible || !section._presetRowReady) return
        section._refreshBundledPresetSelection()
    }

    // Bundled-preset quick-load. `_bundledPresets`
    // is the parsed `nrrNativeBridge.listAllPresets()` array
    // ([{country, pack, label}]); `_bundledPresetLabels` is the parallel
    // `country_pack` label list driving the dropdown model (same index).
    property var _bundledPresets: []
    property var _bundledPresetLabels: []
    // True while the dropdown lists rule sets from the user's OWN folder
    // (Settings -> Presets) rather than the sets shipped with the app. Drives
    // both the preset-root override passed to the bridge and the default
    // selection (the locale heuristic is meaningless for user sets).
    property bool _userPresetsActive: false
    // Guard so the folder-change handler below cannot touch the combo before
    // the row exists (property change handlers fire during creation).
    property bool _presetRowReady: false
    // Folder the quick-load dropdown reads from; empty = the shipped sets.
    // `uiRevision >= 0` forces re-evaluation on every prefs write, so
    // repointing the folder in Settings re-fills the dropdown without a
    // restart.
    readonly property string presetsSourceDir: root.uiRevision >= 0
        ? String(root.prefs.userPresetsDir || "") : ""
    onPresetsSourceDirChanged: {
        if (!section._presetRowReady) return
        section._refreshBundledPresetSelection()
    }
    // The remembered pick, watched the same way as the folder above. The combo
    // completes BEFORE the window binds the cold-start preferences (children
    // complete first), so at that point the stored choice is not readable yet;
    // this fires when it arrives and re-selects. Without it a remembered
    // shipped-set choice would lose to the locale default on every launch.
    readonly property string rememberedPresetKey: root.uiRevision >= 0
        ? String(root.prefs.selectedPresetSet || "") : ""
    onRememberedPresetKeyChanged: {
        if (!section._presetRowReady) return
        section._refreshBundledPresetSelection()
    }

    // User-resizable column widths (px). Header drag handles mutate these;
    // every delegate cell binds to the same property so the table stays
    // aligned. Minimums prevent columns from collapsing into invisibility.
    // Defaults: ID is just R-NNNN (≤ 56 px text), Type fits the longest
    // localized label ("Точный IP" ≈ 90 px, "Application" ≈ 95 px, "Зона"
    // shortest), Match holds the longest typical value (FQDN/wildcard, IPv4),
    // Route fits "Дополнительный" (≈ 130 px). Comment column is fillWidth
    // so it absorbs the remainder. Each can be dragged by the user.
    property int colIdWidth: 70
    property int colTypeWidth: 130
    property int colMatchWidth: 200
    property int colRouteWidth: 130
    readonly property int columnMinWidth: 60

    // Natural pixel width of all table
    // columns. Drives the horizontal Flickable's contentWidth: when the
    // user drags columns wider than the viewport this exceeds it and a
    // horizontal scrollbar appears; otherwise the comment column (fillWidth)
    // absorbs the slack exactly as before. Sum = selection(32) + ID + Type
    // + Match + the route-icon spacer(20) + Route + enable(28) + the three
    // 6px resize handles + a comment minimum, plus the RowLayout gaps and
    // the Frame padding on both sides.
    readonly property int commentMinWidth: 160
    readonly property int tableContentWidth: {
        var cells = 32 + colIdWidth + 6 + colTypeWidth + 6 + colMatchWidth + 6
            + 20 + colRouteWidth + 28
        var gaps = root.uiTheme.spacingMd * 9
        var pad = root.uiTheme.spacingSm * 2
        return cells + commentMinWidth + gaps + pad
    }

    // Multi-row selection model for bulk
    // operations (delete / enable / disable / move-to-route). Stored as
    // a JS object keyed by rule id (R-NNNN string). Rule ids stay stable
    // across model edits — rebuilding the entire model would reset
    // selection unintentionally, but the per-row CheckBox toggle path
    // never rebuilds, so selection survives normal edits. Tracking the
    // count separately lets bindings observe it cheaply.
    property var selectedRowIds: ({})
    property int selectedCount: 0

    // Bulk-selection keys on the MASTER INDEX (unique), not the
    // rule id (which collides across routes — two R-0006 rows would otherwise
    // select/highlight together). The index is stable across sort/filter
    // rebuilds (the master model is never reordered).
    function _isRowSelected(masterIndex) {
        return masterIndex >= 0 && !!section.selectedRowIds[String(masterIndex)]
    }
    function _setRowSelected(masterIndex, selected) {
        if (masterIndex < 0) return
        var key = String(masterIndex)
        var copy = Object.assign({}, section.selectedRowIds)
        if (selected) {
            if (!copy[key]) section.selectedCount += 1
            copy[key] = true
        } else {
            if (copy[key]) section.selectedCount -= 1
            delete copy[key]
        }
        section.selectedRowIds = copy
        if (section.selectedCount < 0) section.selectedCount = 0
    }
    function _clearSelection() {
        if (section.selectedCount === 0) return
        section.selectedRowIds = ({})
        section.selectedCount = 0
    }
    // Visible-row selection summary used by the header tri-state checkbox.
    // Returns: 0 — none of the visible rows are selected; 1 — every visible
    // row is selected; 2 — some but not all visible rows are selected.
    ///
    /// Reads `displayModel` — the already-filtered rows — and NOT the master
    /// model. The tri-state header binds to this, so scanning the master would
    /// re-filter every rule on every `rulesModel.append()`: a 330-rule load ran
    /// the filter ~54 000 times and spent seconds inside `append`. The display
    /// model changes once per rebuild, which is exactly when the answer can
    /// change.
    function _visibleSelectionState() {
        if (typeof displayModel === "undefined" || displayModel === null) return 0
        var anySelected = false
        var anyUnselected = false
        var sawAnyVisible = false
        for (var i = 0; i < displayModel.count; i += 1) {
            var vis = displayModel.get(i)
            if (!vis) continue
            sawAnyVisible = true
            if (section.selectedRowIds[String(vis.masterIndex)]) anySelected = true
            else anyUnselected = true
            if (anySelected && anyUnselected) return 2
        }
        if (!sawAnyVisible) return 0
        if (anySelected && !anyUnselected) return 1
        if (anySelected && anyUnselected) return 2
        return 0
    }
    // Header tri-state toggle: if any visible row is selected, clear the
    // selection of visible rows; otherwise select every visible row.
    function _toggleSelectAllVisible() {
        if (typeof displayModel === "undefined" || displayModel === null) return
        var state = _visibleSelectionState()
        var copy = Object.assign({}, section.selectedRowIds)
        var count = section.selectedCount
        for (var i = 0; i < displayModel.count; i += 1) {
            var vis = displayModel.get(i)
            if (!vis) continue
            var key = String(vis.masterIndex)
            if (state === 0) {
                if (!copy[key]) count += 1
                copy[key] = true
            } else {
                if (copy[key]) count -= 1
                delete copy[key]
            }
        }
        section.selectedRowIds = copy
        section.selectedCount = Math.max(0, count)
    }
    function _selectedRowIndicesDescending() {
        if (!root.rulesModel) return []
        var indices = []
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            if (section.selectedRowIds[String(i)]) indices.push(i)
        }
        indices.sort(function(a, b) { return b - a })
        return indices
    }
    function _bulkSetEnabledSelected(enabled) {
        if (section._refuseWhenLocked()) return
        var indices = _selectedRowIndicesDescending()
        if (indices.length === 0) return
        for (var i = 0; i < indices.length; i += 1) {
            root.rulesModel.setProperty(indices[i], "enabled", !!enabled)
        }
        section.scheduleRebuild()
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
        root.statusLine = enabled
            ? root.tr("status.rules-bulk-enabled",
                "{n} rule(s) enabled.").replace("{n}", String(indices.length))
            : root.tr("status.rules-bulk-disabled",
                "{n} rule(s) disabled.").replace("{n}", String(indices.length))
    }
    function _bulkMoveSelectedToRoute(route) {
        if (section._refuseWhenLocked()) return
        var indices = _selectedRowIndicesDescending()
        if (indices.length === 0) return
        // Whitelist the three valid slugs — do NOT coerce unknown values to
        // "primary" (that would silently drop a bulk-move-to-block).
        var target = (route === "secondary" || route === "block") ? route : "primary"
        for (var i = 0; i < indices.length; i += 1) {
            root.rulesModel.setProperty(indices[i], "targetRoute", target)
        }
        section.scheduleRebuild()
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
        root.statusLine = root.tr("status.rules-bulk-moved",
            "{n} rule(s) moved to {route}.")
                .replace("{n}", String(indices.length))
                .replace("{route}", root.routeLabel(target))
    }
    function _bulkDeleteSelected() {
        if (section._refuseWhenLocked()) return
        var indices = _selectedRowIndicesDescending()
        if (indices.length === 0) return
        for (var i = 0; i < indices.length; i += 1) {
            root.rulesModel.remove(indices[i])
        }
        section._clearSelection()
        root.selectedRule = -1
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
        root.statusLine = root.tr("status.rules-bulk-deleted",
            "{n} rule(s) deleted.").replace("{n}", String(indices.length))
    }

    function passesFilter(item) {
        if (!item) return false
        if (filterEnabled === "enabled-only" && !item.enabled) return false
        if (filterEnabled === "disabled-only" && item.enabled) return false
        if (filterEnabled === "with-errors") {
            // Rule is "with errors" iff the backend validator marked the
            // match value as invalid (status === "error"). Warnings don't
            // disable the rule, so they're not counted here.
            if (String(item.validationStatus || "valid") !== "error") return false
        }
        if (filterType !== "all" && String(item.ruleType || "") !== filterType) return false
        if (filterRoute !== "all" && String(item.targetRoute || "") !== filterRoute) return false
        if (filterAutoAddedOnly && String(item.originReason || "") === "") return false
        if (searchText !== "") {
            // Normalize the search NEEDLE the same way the add dialog
            // normalizes a rule value, so pasting a full URL (e.g.
            // `https://www.whatismyip.com/`) finds the stored `whatismyip.com`
            // rule. Guarded/soft: for plain typing it is a no-op (only URL-shaped
            // text is rewritten), and it falls back to the raw text if the dialog
            // helper is unreachable. Only the internal needle is normalized — the
            // visible search box is left exactly as the user typed it.
            var needle = ((root && root.ruleDialog
                    && typeof root.ruleDialog.normalizeHostInput === "function")
                ? root.ruleDialog.normalizeHostInput("domain", searchText)
                : searchText).toLowerCase()
            // Search across both the Unicode value the
            // user typed and its precomputed lowercase ACE form, so
            // typing `xn--p1ai` finds `рф` and vice versa. Rows from
            // before this field existed degrade to empty string.
            var hay = (String(item.matchValue || "") + " "
                + String(item.aceMatchValue || "") + " "
                + String(item.comment || "")).toLowerCase()
            if (hay.indexOf(needle) < 0) return false
        }
        return true
    }
    function compareRules(a, b) {
        if (!a || !b) return 0
        var cmp = 0
        if (sortBy === "by-match-value") {
            cmp = String(a.matchValue || "").localeCompare(String(b.matchValue || ""))
        } else if (sortBy === "by-type") {
            cmp = String(a.ruleType || "").localeCompare(String(b.ruleType || ""))
            if (cmp === 0) cmp = String(a.matchValue || "").localeCompare(String(b.matchValue || ""))
        } else if (sortBy === "by-route") {
            cmp = String(a.targetRoute || "").localeCompare(String(b.targetRoute || ""))
            if (cmp === 0) cmp = String(a.matchValue || "").localeCompare(String(b.matchValue || ""))
        } else {
            // display-order: rule ids encode insertion order
            cmp = String(a.id || "").localeCompare(String(b.id || ""))
        }
        return sortDir === "desc" ? -cmp : cmp
    }
    // Sorting now happens inside `rebuildDisplay()` (it sorts the
    // filtered snapshot with `compareRules` before populating `displayModel`).
    // `applySort` just triggers a rebuild. The master `rulesModel` is never
    // reordered — display order is a pure view concern, so selection survives.
    function applySort() { section.rebuildDisplay() }
    function setSortBy(column) {
        if (section.sortBy === column) {
            section.sortDir = (section.sortDir === "asc") ? "desc" : "asc"
        } else {
            section.sortBy = column
            section.sortDir = "asc"
        }
        if (sortCombo.currentIndex !== sortCombo.indexOfValue(column)) {
            var idx = Pure.optionIndexByValue(sortCombo.model, column, 0)
            if (idx >= 0) sortCombo.currentIndex = idx
        }
        section.applySort()
    }
    function sortArrowFor(column) {
        if (section.sortBy !== column) return ""
        return section.sortDir === "asc" ? "▲" : "▼"
    }

    // Populate the quick-load dropdown from `listAllPresets()` (every
    // country/pack under presets/ with a rules file). When the user pointed the
    // dropdown at a folder of their own, that folder is enumerated instead; a
    // folder with no rule sets in it falls back to the shipped list and says so
    // rather than leaving the user with an empty dropdown.
    function _loadBundledPresetList() {
        // Enumeration itself lives on the window (`root._ruleSetEnum`) because
        // the cold-start hydration needs the very same list: the set shown here
        // and the rules loaded below must never come from two separate walks of
        // the disk. Re-reading here is a deliberate cache drop — the folder may
        // have gained or lost sets since the last look.
        root.invalidateRuleSetCache()
        var e = root._ruleSetEnum()
        section._userPresetsActive = e.userOwned
        if (root.userPresetsDir !== "" && !e.userOwned) {
            root.statusLine = root.tr("status.user-presets-folder-empty",
                "No rule sets found in your folder — showing the sets that come with the app.")
        }
        var labels = []
        for (var i = 0; i < e.entries.length; i += 1) {
            labels.push(root.ruleSetLabelAt(i))
        }
        section._bundledPresets = e.entries
        section._bundledPresetLabels = labels
    }

    // Re-enumerate the dropdown and re-pick its entry. Shared by the initial
    // fill and by the folder-change handler so both paths agree.
    function _refreshBundledPresetSelection() {
        section._loadBundledPresetList()
        // A set the user picked before wins over any default: re-deriving the
        // choice on every visit is what made a deliberate pick evaporate.
        var pick = section._rememberedPresetIndex()
        if (pick < 0) pick = section._preferredBundledPresetIndex()
        if (pick < 0 || pick >= section._bundledPresetLabels.length) pick = 0
        bundledPresetCombo.currentIndex = pick
        bundledPresetCombo.displayText =
            (section._bundledPresetLabels.length > pick)
                ? String(section._bundledPresetLabels[pick]) : ""
    }

    // `<source>:<label>` for the entry at `index` — see `ruleSetSelectionKey`
    // on the window, which owns the format so the remembered pick means the
    // same thing to the dropdown and to the cold-start hydration.
    function _presetSelectionKey(index) {
        return root.ruleSetSelectionKey(index)
    }

    // Index of the remembered set within the CURRENT list, or -1 when nothing
    // is remembered, the remembered choice belongs to the other source, or the
    // set itself is gone (renamed / deleted folder) — each of which falls back
    // to the default pick rather than stranding the dropdown on a dead entry.
    function _rememberedPresetIndex() {
        return root.uiRevision >= 0 ? root.ruleSetRememberedIndex() : -1
    }

    // Persist the pick. App bookkeeping (listed in `_nonArmingPrefKeys`), so it
    // commits immediately instead of arming the footer Apply/Cancel, and is
    // flushed now — a kill before a graceful close would otherwise lose it.
    function _rememberPresetSelection(index) {
        var key = section._presetSelectionKey(index)
        if (key === "" || key === String(root.prefs.selectedPresetSet || "")) return
        root.updatePrefs({ selectedPresetSet: key })
        root.emitPrefs()
    }

    // Пресет по языку/региону системы как значение по умолчанию (пользователь
    // дальше меняет вручную) — эвристика живёт на окне (`ruleSetPreferredIndex`),
    // потому что тем же выбором пользуется гидратация при холодном старте.
    function _preferredBundledPresetIndex() {
        return root.ruleSetPreferredIndex()
    }

    // Read the selected bundled preset's primary+secondary files and route
    // them through the standard import-review flow. Absolute paths so the
    // remembered file binding (lastSavedPath*) resolves on the next launch.
    function _loadBundledPreset(index) {
        if (section._refuseWhenLocked()) return
        if (index < 0 || index >= section._bundledPresets.length) return
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.resolvePresetPath !== "function"
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        // Loading a set confirms it as the user's choice even when they never
        // touched the dropdown (it already showed the one they wanted).
        section._rememberPresetSelection(index)
        // Path assembly lives on the window so the file this button reads is
        // literally the file the cold-start hydration would have loaded.
        var primAbs = root.ruleSetFilePath(index, "primary")
        var secAbs = root.ruleSetFilePath(index, "secondary")
        var primB64 = primAbs ? String(nrrNativeBridge.readFileBytes(primAbs) || "") : ""
        var secB64 = secAbs ? String(nrrNativeBridge.readFileBytes(secAbs) || "") : ""
        if (!primB64 && !secB64) {
            root.statusLine = root.tr("status.bundled-preset-empty",
                "Could not read the selected bundled preset.")
            return
        }
        if (typeof root.presetImportController.startBothRoutesPresetImportReviewFlow === "function") {
            root.presetImportController.startBothRoutesPresetImportReviewFlow(primB64, secB64, primAbs, secAbs)
        }
    }

    // "Update rules from file" re-reads the CURRENT source
    // files (lastLoadedPath*, falling back to the save binding lastSavedPath*
    // for prefs recorded before the display-only pair existed) and pushes them
    // through the existing import-review pipeline (dry-run → ReviewDiff →
    // ConfirmActivate). Re-reading a bundled preset is fine — it is a READ;
    // only writes are factory-guarded. Distinct from "Load rule list…"
    // (picks a NEW file).
    function _updateRulesFromCurrentFile() {
        if (section._refuseWhenLocked()) return
        // The loadable path, not the displayed one: re-reading works even when
        // the row is hidden because nothing is bound yet (it then re-reads the
        // set the dropdown points at, which is what "update from file" means
        // with no binding).
        var primAbs = String(root.rulesSourcePathFor("primary") || "")
        var secAbs = String(root.rulesSourcePathFor("secondary") || "")
        if (primAbs === "" && secAbs === "") {
            root.statusLine = root.tr("status.no-source-file-bound",
                "No source file is bound yet. Use “Load rule list…” first.")
            return
        }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Service bridge not connected.")
            return
        }
        var primB64 = primAbs ? String(nrrNativeBridge.readFileBytes(primAbs) || "") : ""
        var secB64 = secAbs ? String(nrrNativeBridge.readFileBytes(secAbs) || "") : ""
        if (!primB64 && !secB64) {
            root.statusLine = root.tr("status.import-read-failed",
                "Cannot read preset file. See logs for details.")
            return
        }
        if (typeof root.presetImportController.startBothRoutesPresetImportReviewFlow === "function") {
            root.presetImportController.startBothRoutesPresetImportReviewFlow(primB64, secB64, primAbs, secAbs)
        }
    }

    // The bold "Rules" heading was removed: the
    // section is already obvious from the active sidebar item, and it just
    // ate vertical space above the toolbar.
    // Source-file info. Shows the full path of the preset file(s) the current
    // rules are bound to, with a button to open the containing folder in
    // Explorer (handy for testing / locating presets).
    // The path the current rules CAME FROM, per route — resolved by the
    // window's `rulesSourcePathFor`, the same call the cold-start hydration
    // makes, so the path shown here is always the path that gets loaded. The
    // `uiRevision >= 0` term re-evaluates it on every prefs write (picking a
    // rule-set folder in Settings repoints this row without a restart).
    function _sourcePathFor(route) {
        return root.uiRevision >= 0
            ? String(root.rulesSourceDisplayPathFor(route) || "") : ""
    }

    // Administrator lock notice. Deliberately calm and explanatory rather than
    // an error: nothing failed, the section is managed. It sits above the
    // toolbar so the reason is visible before the greyed-out buttons are.
    Frame {
        Layout.fillWidth: true
        visible: section.rulesLocked
        padding: root.uiTheme.spacingSm
        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
        ColumnLayout {
            anchors.fill: parent
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
                    text: root.tr("rules.locked.banner-title",
                        "Rules are managed by your administrator")
                    color: root.textColor
                    font.bold: true
                    wrapMode: Text.WordWrap
                }
            }
            Label {
                Layout.fillWidth: true
                text: root.tr("rules.locked.banner-body",
                    "Changing rules is turned off on this computer. You can still view, search, filter and export them.")
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
            }
        }
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        // Both bound rules files on ONE line, above the rules table. Each path
        // is elided (the file name end stays readable) and the FULL path is
        // available on hover, so the row never forces the section to scroll
        // horizontally no matter how deep the folders are.
        // It is deliberately NOT gated on the table
        // being populated: the binding is exactly what the user needs to see
        // while the table is still empty (service not up yet, rules about to
        // be hydrated from these very files). Bundled-tree paths render here
        // too — the factory-path filter guards SAVE targets only, never the
        // source display.
        visible: section._sourcePathFor("primary") !== ""
            || section._sourcePathFor("secondary") !== ""
        Label {
            text: root.uiRevision >= 0 ? root.tr("rules.source.label", "Source:") : ""
            color: root.mutedTextColor
            verticalAlignment: Text.AlignVCenter
        }
        Repeater {
            model: [
                { route: "primary",   path: section._sourcePathFor("primary") },
                { route: "secondary", path: section._sourcePathFor("secondary") }
            ]
            // One group per route inside the same row. `fillWidth` on both
            // groups splits the leftover width evenly, so a long primary path
            // cannot squeeze the secondary one out of the line.
            delegate: RowLayout {
                visible: modelData.path !== ""
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                spacing: root.uiTheme.spacingXxs
                Label {
                    text: root.routeLabel(modelData.route) + ":"
                    color: root.mutedTextColor
                    verticalAlignment: Text.AlignVCenter
                }
                Label {
                    // Full path, not just the file name — two routes can point
                    // at same-named files in different folders. Elides on the
                    // LEFT so the file name stays readable when the path is
                    // too long for the window; the hover tooltip carries the
                    // untruncated path.
                    text: modelData.path
                    color: root.textColor
                    elide: Text.ElideLeft
                    // preferredWidth 0 + fillWidth: the label claims only the
                    // share of free width the layout hands it and shrinks to
                    // nothing on a narrow window instead of widening the row.
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    Layout.minimumWidth: 0
                    verticalAlignment: Text.AlignVCenter
                    ToolTip.visible: srcHover.hovered && modelData.path !== ""
                    ToolTip.text: modelData.path
                    ToolTip.delay: 300
                    HoverHandler { id: srcHover }
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("rules.source.open-folder", "Open folder")
                    icon.source: root.uiIconSource("open-file")
                    // Fixed size: the button must never grow with the row, the
                    // free width belongs to the path label next to it.
                    Layout.fillWidth: false
                    Accessible.name: text
                    enabled: typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                        && typeof nrrNativeBridge.openContainingFolder === "function"
                    ToolTip.visible: hovered
                    ToolTip.text: root.tr("rules.source.open-folder-tooltip",
                        "Open the folder containing this rules file in Explorer.")
                    onClicked: {
                        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                                && typeof nrrNativeBridge.openContainingFolder === "function") {
                            nrrNativeBridge.openContainingFolder(modelData.path)
                        }
                    }
                }
            }
        }
    }

    // Where the rules on screen stand, stated as the TWO independent facts
    // they are: not applied to the service, and not saved to the rules file.
    // They have different fixes and different consequences, so one merged
    // "unsaved" indicator could only ever be wrong about one of them.
    // Hidden entirely once neither is true and the service is reachable —
    // nothing to say when everything genuinely matches. "Check now" moved to
    // the sidebar's Rules submenu, so it no longer lives in this row.
    Flow {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        visible: root.rulesNotAppliedToService || root.rulesNotSavedToFile
            || !root.backendStatus || root.backendStatus.kind !== "connected"

        Label {
            text: (root.rulesNotAppliedToService || root.rulesNotSavedToFile)
                ? root.tr("rules.state.pending-label", "Pending:")
                : (!root.backendStatus || root.backendStatus.kind !== "connected")
                    ? root.tr("rules.state.unknown",
                        "Not verified — the service isn't reachable right now.")
                    : root.tr("rules.state.in-sync",
                        "The rules match the service and your rules file.")
            color: (root.rulesNotAppliedToService || root.rulesNotSavedToFile)
                ? root.textColor : root.mutedTextColor
            // Padded to the button height so the row reads as one line; the
            // Flow top-aligns its children.
            topPadding: root.uiTheme.spacingXs
            bottomPadding: root.uiTheme.spacingXs
            verticalAlignment: Text.AlignVCenter
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        ThemedButton {
            theme: root.uiTheme
            visible: root.rulesNotAppliedToService
            text: root.tr("rules.state.not-applied", "Not applied to the service")
            icon.source: root.uiIconSource("apply")
            enabled: !root.mutationsModel.hasInFlight && !section.rulesLocked
            Accessible.role: Accessible.Button
            Accessible.name: text
            ToolTip.visible: hovered && root.prefs.tooltipsEnabled
            ToolTip.text: root.tr("rules.state.not-applied-tooltip",
                "The rules shown here differ from the ones the service is enforcing. Apply them.")
            onClicked: section._triggerReviewFlow()
        }
        ThemedButton {
            theme: root.uiTheme
            visible: root.rulesNotSavedToFile
            text: root.tr("status.bound-file-save", "Save to file")
            icon.source: root.uiIconSource("save")
            Accessible.role: Accessible.Button
            Accessible.name: text
            ToolTip.visible: hovered && root.prefs.tooltipsEnabled
            ToolTip.text: root.boundFilesController._boundFileChipTooltip()
            onClicked: root.boundFilesController._saveBoundFilesNow()
        }
    }

    // Quick-load a bundled preset (country_pack):
    // selecting one fills both routes through the import-review flow. Hidden
    // when no bundled presets ship with the build.
    //
    // Grouped in a ColumnLayout so the
    // "import only active" toggle sits directly under the load row. The flag
    // must be fixed BEFORE "Load" (it is baked into the dry-run content hash
    // and must match at apply — see `_executePresetImportActivation`), so it
    // cannot live in the downstream review dialog; here it is right where the
    // load happens. Hides together with the preset row (no standalone clutter).
    ColumnLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingXs
        // Visibility is a persisted preference
        // (`showBundledPresets`, default true). The "Hide" button below sets
        // it false; the "Show bundled presets" toggle in Settings re-enables it.
        visible: section._bundledPresetLabels.length > 0
            && root.prefs.showBundledPresets !== false

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                // The row serves two sources, so it names the one in use.
                text: root.uiRevision >= 0
                    ? (section._userPresetsActive
                        ? root.tr("rules.bundled-preset.user-label", "My rule set:")
                        : root.tr("rules.bundled-preset.label", "Bundled preset:"))
                    : ""
                color: root.textColor
                verticalAlignment: Text.AlignVCenter
                height: bundledPresetCombo.height
            }
            ThemedComboBox {
                id: bundledPresetCombo
                theme: root.uiTheme
                Layout.fillWidth: true
                Layout.maximumWidth: 380
                model: section._bundledPresetLabels
                labelResolver: function(item) { return String(item) }
                currentIndex: 0
                popup.width: root.comboPopupWidth(bundledPresetCombo, model, "",
                    function(item) { return String(item) })
                Component.onCompleted: {
                    // Fills the list and restores the user's own pick. Only
                    // when there is none does a default apply: the system
                    // language/region for the shipped sets, the first entry for
                    // a user folder (the locale heuristic says nothing about
                    // sets the user shaped themselves).
                    section._presetRowReady = true
                    section._refreshBundledPresetSelection()
                }
                onActivated: {
                    bundledPresetCombo.displayText = String(model[currentIndex])
                    section._rememberPresetSelection(currentIndex)
                }
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bundled-preset.load", "Load")
                icon.source: root.uiIconSource("load-list")
                enabled: section._bundledPresetLabels.length > 0
                    && !section.rulesLocked
                onClicked: section._loadBundledPreset(bundledPresetCombo.currentIndex)
            }
            // Hide the preset row (persists via the
            // `showBundledPresets` preference; re-enable from Settings → General).
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bundled-preset.hide", "Hide")
                ToolTip.visible: hovered
                ToolTip.text: root.tr("rules.bundled-preset.hide-tooltip",
                    "Hide the bundled-preset quick-load row. Re-enable it in Settings.")
                onClicked: {
                    if (typeof root.updatePrefs === "function") {
                        root.updatePrefs({ showBundledPresets: false })
                    }
                    root.statusLine = root.tr("status.presets-hidden",
                        "Bundled presets hidden. Re-enable them in Settings → General.")
                }
            }
        }

        // The dropdown falls back to the sets shipped with the app when the
        // chosen folder holds none. That fallback used to be announced only by
        // a status line that scrolls away, leaving the row silently claiming to
        // list the user's own sets. This says so for as long as it is true.
        Label {
            Layout.fillWidth: true
            visible: root.uiRevision >= 0
                ? (String(root.prefs.userPresetsDir || "") !== ""
                    && !section._userPresetsActive)
                : false
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.uiRevision >= 0
                ? root.tr("rules.bundled-preset.folder-empty-hint",
                    "Your presets folder is empty — showing bundled sets")
                : ""
        }
    }

    // The "import only active rules" toggle is no
    // longer shown here: an always-visible checkbox under the bundled-preset
    // row stole vertical space from the rules table. The bundled-preset load
    // now follows the persisted default in Settings → General
    // (`importOnlyActiveSession` binds to `prefs.importOnlyActive`); the
    // per-import override still lives in the Load-rule-list window
    // (Main.qml `loadListWindow`), where the flag must be fixed before dry-run.

    // Action buttons in an adaptive GridLayout. The number of columns is
    // recomputed from the available width: 6 in one row when wide, 3+3 at
    // medium widths, 2+2+2 or 1-per-row when very narrow. Each button has
    // `Layout.fillWidth: true` so they stretch equally to fill the row —
    // this avoids one long button (e.g. "Update rules from file") sitting
    // alone on a second line while shorter buttons hog the first.
    GridLayout {
        Layout.fillWidth: true
        columnSpacing: root.uiTheme.spacingSm
        rowSpacing: root.uiTheme.spacingSm
        columns: width >= 1100 ? 6 : width >= 720 ? 3 : width >= 480 ? 2 : 1

        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("action.add", "Add")
            icon.source: root.uiIconSource("add")
            enabled: !section.rulesLocked
            onClicked: { root.editingRule = -1; root.ruleDialog.resetForEdit(); root.ruleDialog.open() }
        }
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("action.edit", "Edit")
            icon.source: root.uiIconSource("edit")
            enabled: root.selectedRule >= 0 && !section.rulesLocked
            onClicked: { root.editingRule = root.selectedRule; root.ruleDialog.resetForEdit(); root.ruleDialog.open() }
        }
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("action.delete", "Delete")
            icon.source: root.uiIconSource("delete")
            enabled: root.selectedRule >= 0 && !section.rulesLocked
            onClicked: singleDeleteConfirm.open()
        }
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("action.load-rule-list", "Load rule list...")
            icon.source: root.uiIconSource("load-list")
            enabled: !section.rulesLocked
            onClicked: root.openLoadRuleListWindow()
        }
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("action.update-rules-from-file", "Update rules from file")
            icon.source: root.uiIconSource("refresh-dot")
            enabled: !section.rulesLocked
            onClicked: section._updateRulesFromCurrentFile()
        }
        // Save & Review opens the review-flow
        // (ReviewDiffDialog → ConfirmActivateDialog → activate). The
        // button is disabled while any mutation is in flight so
        // accidental double-submit can't race the coordinator.
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.save-and-review", "Save and review...")
            icon.source: root.uiIconSource("apply")
            enabled: !root.mutationsModel.hasInFlight && !section.rulesLocked
            ToolTip.visible: hovered && !enabled
            ToolTip.text: section.rulesLocked
                ? root.tr("rules.locked.banner-body",
                    "Changing rules is turned off on this computer. You can still view, search, filter and export them.")
                : root.tr(
                    "mutations.in-progress-tooltip",
                    "Another operation is in progress. Wait for it to finish.")
            onClicked: section._triggerReviewFlow()
        }
        // "Show rules the service is
        // applying". Pulls the active revision's rules from the service
        // (`rules.list`, a read op — works for non-admin) and rebinds the
        // table so the user can see exactly what is being enforced,
        // independent of any local edits or file binding. Guarded by a
        // confirm when there are unsaved local edits.
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.show-service-rules",
                "Show rules applied by the service")
            icon.source: root.uiIconSource("refresh-dot")
            enabled: !root.mutationsModel.hasInFlight
            ToolTip.visible: hovered
            ToolTip.text: root.tr(
                "rules.action.show-service-rules-tooltip",
                "Load the rules the service is currently enforcing into the table.")
            onClicked: {
                if (typeof root.reloadActiveRulesFromService === "function") {
                    root.reloadActiveRulesFromService()
                }
            }
        }
        // "Reset to baseline": discard this user's own
        // per-SID rule customizations and fall back to the shared baseline
        // rules (read-through resumes). Runs through the same two-phase
        // review flow (dry-run → confirm); when the user has no custom
        // rules the dry-run reports a benign "already on baseline" notice
        // instead of opening the confirm dialog. Non-elevated — a user can
        // only ever reset its OWN rules, never the admin baseline.
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.reset-to-baseline", "Reset to baseline rules")
            icon.source: root.uiIconSource("refresh-dot")
            enabled: !root.mutationsModel.hasInFlight && !section.rulesLocked
            ToolTip.visible: hovered
            ToolTip.text: root.tr(
                "rules.action.reset-to-baseline-tooltip",
                "Discard your custom rules and return to the baseline rules shared on this computer.")
            onClicked: {
                if (typeof root.reviewFlowController.startResetToBaselineFlow === "function") {
                    root.reviewFlowController.startResetToBaselineFlow()
                }
            }
        }
        // Admin "Set as baseline": commit the current table
        // as the shared baseline rules for every OS-user on this machine.
        // Elevated (UAC-shield); routes through the session broker. Daily
        // per-user edits stay non-elevated ("Save and review" above).
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.set-baseline", "Save as baseline (admin)")
            icon.source: root.uiIconSource("shield")
            enabled: !root.mutationsModel.hasInFlight
            ToolTip.visible: hovered
            ToolTip.text: root.tr(
                "rules.action.set-baseline-tooltip",
                "Administrator: make the current rules the baseline that every user on this computer falls back to. Asks for administrator approval.")
            onClicked: section._triggerBaselineReviewFlow()
        }
        // Demo-rules loader. Single demo
        // entry point: reads the bundled `builtin-demo/rules_*.txt` preset
        // and MERGES it into the current table through the review flow.
        // Available regardless of table state (was previously split into
        // two near-duplicate buttons — a synthetic "Load demo rules" and an
        // empty-table-only "Apply built-in demo rules"; consolidated here).
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.load-demo-rules", "Load demo rules...")
            icon.source: root.uiIconSource("add")
            enabled: !root.mutationsModel.hasInFlight && !section.rulesLocked
            ToolTip.visible: hovered
            ToolTip.text: root.tr(
                "rules.action.load-demo-rules-tooltip",
                "Merge the bundled built-in demo rules into the table and open the review flow."
            )
            onClicked: {
                if (typeof root.loadDemoRules === "function") {
                    root.loadDemoRules()
                }
            }
        }
        // "Import from file…" removed from
        // toolbar; functionality lives in File → Load rule list
        // (Ctrl+O) which opens the same `loadListWindow` with the
        // two-file picker + Replace/Merge radio. Single entry point.
        // "Export to file…" toolbar action. Same
        // route-picker pattern as Import; the exporter reads the
        // currently-active revision and emits canonical txt bytes.
        ThemedButton {
            id: exportToFileButton
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.save-rules", "Save rules...")
            icon.source: root.uiIconSource("save")
            onClicked: exportRouteMenu.popup()
            // A rule table is BOTH routes; saving one of them leaves the other
            // behind, which is how a "saved" set came back missing half its
            // rules. The whole set is therefore the first, plainly-named
            // option, and a single route stays available but says so.
            Menu {
                id: exportRouteMenu
                MenuItem {
                    text: root.tr("rules.action.save-as-set",
                        "Save as a set (both routes)...")
                    onTriggered: root.boundFilesController.exportCurrentRulesInteractive(null)
                }
                MenuItem {
                    text: root.tr("rules.action.export-source-primary",
                        "Export only the main route's rules to a file...")
                    onTriggered: section._openExportFor("primary")
                }
                MenuItem {
                    text: root.tr("rules.action.export-source-secondary",
                        "Export only the additional route's rules to a file...")
                    onTriggered: section._openExportFor("secondary")
                }
            }
        }
        // "Clear all rules" destructive action.
        // Clears the local rulesModel AND pushes an empty preset to
        // the service when reachable (so the OS handles routing
        // without our overlay). When offline, GUI-only clear; user
        // can push later via Save & review or the next preset import.
        ThemedButton {
            id: clearAllRulesButton
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.tr("rules.action.clear-all", "Clear all rules...")
            icon.source: root.uiIconSource("delete")
            enabled: !root.mutationsModel.hasInFlight && !section.rulesLocked
                && root.rulesModel && root.rulesModel.count > 0
            ToolTip.visible: hovered
            ToolTip.text: root.tr(
                "rules.action.clear-all-tooltip",
                "Remove all rules from this app and the service. Without rules, the OS handles routing on its own."
            )
            onClicked: clearAllRulesConfirm.open()
        }
    }

    // Bulk-ops bar. Renders only while the
    // user has at least one rule selected via the per-row checkboxes.
    // Mirrors the GMail/GitHub "selection mode" pattern: appears above
    // the table, lists the count, and exposes the available operations
    // (Enable / Disable / Move to route / Delete). Esc clears.
    Frame {
        id: bulkOpsBar
        Layout.fillWidth: true
        padding: root.uiTheme.spacingSm
        visible: section.selectedCount > 0
        background: Rectangle {
            color: root.uiTheme.colorSelection
            opacity: 0.6
            border.width: root.uiTheme.borderWidth
            border.color: root.uiTheme.colorAccent
            radius: root.uiTheme.radiusSm
        }
        RowLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingMd
            Label {
                text: root.tr("rules.bulk.selected-count",
                    "{n} rule(s) selected")
                        .replace("{n}", String(section.selectedCount))
                color: root.textColor
                font.bold: true
                verticalAlignment: Text.AlignVCenter
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bulk.enable",
                    "Enable")
                enabled: !section.rulesLocked
                onClicked: section._bulkSetEnabledSelected(true)
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bulk.disable",
                    "Disable")
                enabled: !section.rulesLocked
                onClicked: section._bulkSetEnabledSelected(false)
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bulk.move-to-route",
                    "Move to route")
                enabled: !section.rulesLocked
                onClicked: bulkMoveRouteMenu.popup()
                Menu {
                    id: bulkMoveRouteMenu
                    MenuItem {
                        text: root.routeLabel("primary")
                        onTriggered: section._bulkMoveSelectedToRoute("primary")
                    }
                    MenuItem {
                        text: root.routeLabel("secondary")
                        onTriggered: section._bulkMoveSelectedToRoute("secondary")
                    }
                    // "Move to block" removed: block became a Pro-tier action
                    // (WFP block, not a hosts entry). Existing block rules from
                    // imports still round-trip; they just can't be authored here.
                }
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bulk.delete",
                    "Delete...")
                enabled: !section.rulesLocked
                onClicked: bulkDeleteConfirm.open()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.bulk.clear-selection",
                    "Clear (Esc)")
                onClicked: section._clearSelection()
            }
        }
    }

    // Confirmation modal for bulk delete. The user explicitly opted into
    // multi-row deletion via the checkboxes, but the action is still
    // destructive and irreversible, so we surface a Cancel/Delete prompt
    // with the count baked into the body text.
    Dialog {
        id: bulkDeleteConfirm
        title: root.tr("rules.bulk.delete-title",
            "Delete selected rules?")
        modal: true
        standardButtons: Dialog.NoButton
        x: (parent && parent.width) ? (parent.width - width) / 2 : 0
        y: (parent && parent.height) ? (parent.height - height) / 2 : 0
        width: 480
        contentItem: ColumnLayout {
            spacing: root.uiTheme.spacingMd
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 440
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("rules.bulk.delete-body",
                    "{n} selected rule(s) will be removed. You can apply the change to the service later via 'Save and review...'.")
                        .replace("{n}", String(section.selectedCount))
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: bulkDeleteConfirm.close()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("rules.bulk.delete-confirm",
                        "Delete")
                    onClicked: {
                        bulkDeleteConfirm.close()
                        section._bulkDeleteSelected()
                    }
                }
            }
        }
    }

    // Confirmation modal for the single-row toolbar Delete. Per user
    // request: every delete (single or bulk) must surface a
    // confirmation step so the rule can't disappear from a mis-click.
    Dialog {
        id: singleDeleteConfirm
        title: root.tr("rules.action.delete-single-title",
            "Delete this rule?")
        modal: true
        standardButtons: Dialog.NoButton
        x: (parent && parent.width) ? (parent.width - width) / 2 : 0
        y: (parent && parent.height) ? (parent.height - height) / 2 : 0
        width: 440
        contentItem: ColumnLayout {
            spacing: root.uiTheme.spacingMd
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 400
                wrapMode: Text.WordWrap
                color: root.textColor
                text: {
                    if (root.selectedRule < 0 || !root.rulesModel) return ""
                    var row = root.rulesModel.get(root.selectedRule)
                    if (!row) return ""
                    return root.tr("rules.action.delete-single-body",
                        "Rule {id} ({value}) will be removed from this app. Apply the change to the service later via 'Save and review...'.")
                            .replace("{id}", String(row.id || ""))
                            .replace("{value}", String(row.matchValue || ""))
                }
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: singleDeleteConfirm.close()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("rules.action.delete-confirm", "Delete")
                    onClicked: {
                        singleDeleteConfirm.close()
                        if (root.selectedRule >= 0) {
                            root.rulesModel.remove(root.selectedRule)
                            root.selectedRule = -1
                            root.statusLine = root.tr(
                                "status.rule-removed", "Rule removed")
                            if (typeof root.setUnsavedChanges === "function") {
                                root._recomputeRulesDirty()
                            }
                        }
                    }
                }
            }
        }
    }

    // Esc → clear the bulk-selection. Standard convention for selection
    // modes; the shortcut activates only when the section has focus AND
    // the selection is non-empty, so it doesn't fight with other Esc
    // handlers in the app.
    Shortcut {
        sequence: "Esc"
        enabled: section.selectedCount > 0
        onActivated: section._clearSelection()
    }

    // Confirmation modal for the destructive
    // "Clear all rules" action. Two-button (Cancel / Confirm) with a
    // danger-coloured confirm so the user can't blow away their rule
    // set with a single mis-click.
    Dialog {
        id: clearAllRulesConfirm
        title: root.tr("rules.action.clear-all-title", "Clear all rules?")
        modal: true
        standardButtons: Dialog.NoButton
        x: (parent && parent.width) ? (parent.width - width) / 2 : 0
        y: (parent && parent.height) ? (parent.height - height) / 2 : 0
        width: 480

        contentItem: ColumnLayout {
            spacing: root.uiTheme.spacingMd
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 440
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("rules.action.clear-all-body",
                    "All rules will be removed from this app and (when the service is running) from the service as well. The OS will route traffic without any NetRuleRouter overrides. This cannot be undone.")
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: clearAllRulesConfirm.close()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("rules.action.clear-all-confirm", "Clear all rules")
                    onClicked: {
                        clearAllRulesConfirm.close()
                        section._clearAllRules()
                    }
                }
            }
        }
    }

    // ── Preset import/export FileDialog instances ──
    // Two separate dialogs so we can stash the target route on the
    // instance (`pendingTargetRoute`) without contending with the
    // open-vs-save mode flag. `currentFile`/`folder` reset on each
    // open() so the user picks fresh each time.

    FileDialog {
        id: importFileDialog
        fileMode: FileDialog.OpenFile
        // Open where the user keeps their rule sets, when they chose a folder.
        title: root.tr("rules.dialog.import-title", "Choose preset to import")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        property string pendingTargetRoute: ""
        onAccepted: section._handleImportFileChosen(
            pendingTargetRoute, _localPathFromUrl(selectedFile))
    }

    FileDialog {
        id: exportFileDialog
        fileMode: FileDialog.SaveFile
        title: root.tr("rules.dialog.export-title", "Save preset as...")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        defaultSuffix: "txt"
        property string pendingSourceRoute: ""
        // Native FileDialog has no accessory-widget
        // slot, so we hand the chosen path to `ExportOptionsDialog`
        // which surfaces the "include comments" toggle before the
        // actual write. Two-step UX; saves us from rolling a custom
        // file picker that wouldn't match the OS standards.
        onAccepted: {
            exportOptionsDialog.pendingRoute = pendingSourceRoute
            exportOptionsDialog.pendingPath = _localPathFromUrl(selectedFile)
            // Seed from the persisted default
            // (survives restarts) rather than the session-only var.
            exportOptionsDialog.includeComments = section.lastExportIncludeComments
            exportOptionsDialog.open()
        }
    }

    /// Last-mile "include comments" toggle applied
    /// AFTER the FileDialog. Part B promotes this to a persisted
    /// preference (`prefs.exportIncludeComments`, default ON): the var
    /// tracks the pref so successive exports default to the user's
    /// prior pick across restarts.
    property bool lastExportIncludeComments: root.prefs.exportIncludeComments !== false

    ExportOptionsDialog {
        id: exportOptionsDialog
        ownerRoot: root
        property string pendingRoute: ""
        property string pendingPath: ""
        onConfirmed: function(includeComments) {
            section.lastExportIncludeComments = !!includeComments
            // Persist the choice so the next launch defaults to it.
            root.updatePrefs({ exportIncludeComments: !!includeComments })
            section._handleExportPathChosen(
                pendingRoute, pendingPath, !!includeComments)
        }
        onCancelled: { /* no-op — user backed out before write */ }
    }

    function _localPathFromUrl(urlValue) {
        // QtQuick.Dialogs.FileDialog `selectedFile` is a `QUrl` (with the
        // file:/// scheme on Windows). Strip to a plain local path for QFile.
        var s = String(urlValue || "")
        if (s.indexOf("file:///") === 0) return s.substring(8)
        if (s.indexOf("file://") === 0) return s.substring(7)
        return s
    }

    function _openImportFor(route) {
        if (section._refuseWhenLocked()) return
        importFileDialog.pendingTargetRoute = route
        root.openRulesDialog(importFileDialog)
    }

    // `_applyBuiltinDemo()` removed. Its
    // empty-table-only "Apply built-in demo rules" button was consolidated
    // into the single "Load demo rules…" button, whose `root.loadDemoRules`
    // now reads the same bundled `builtin-demo/*.txt` and merges it.

    function _openExportFor(route) {
        exportFileDialog.pendingSourceRoute = route
        root.openRulesDialog(exportFileDialog)
    }

    function _handleImportFileChosen(route, path) {
        if (section._refuseWhenLocked()) return
        // 1. Read file bytes via bridge (base64-wrapped).
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            root.statusLine = root.tr(
                "status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        var b64 = nrrNativeBridge.readFileBytes(path)
        if (!b64 || b64.length === 0) {
            root.statusLine = root.tr(
                "status.import-read-failed",
                "Cannot read preset file. See logs for details.")
            return
        }
        // 2. Kick off the review flow with bytes attached.
        if (typeof root.presetImportController.startPresetImportReviewFlow === "function") {
            root.presetImportController.startPresetImportReviewFlow(route, b64, path)
        } else {
            console.log("RulesSection: startPresetImportReviewFlow unavailable on root")
        }
        // Offer this folder as the rule-set folder — once, and only while
        // none is configured.
        root.suggestRulesFolder(path)
    }

    // The canonical-txt writer lives in `lib/rules.js`
    // (`Rules.buildCanonicalRulesText`) — one generator for the export picker
    // and for every "save the rules to their file" path, so all of them work
    // with the service stopped. The write itself, including the "this is one
    // of the app's own sets" warning and the route<->file rebinding, belongs
    // to BoundFilesController.
    function _handleExportPathChosen(route, path, includeComments) {
        root.boundFilesController.exportRouteToPath(
            route, path, (includeComments === undefined) ? true : !!includeComments)
    }

    // ── Build canonical rules-json wire shape from
    //    the local rulesModel and kick off the review flow.
    //
    // The wire payload is `CanonicalRulesJsonV1`-shaped:
    // `{ "schema-version": 1, "primary": [RuleDto...], "secondary": [...] }`.
    // Each `RuleDto` carries either `address-match` (4 kinds) or
    // `app-match` (2 pattern kinds). Mapping from local `rulesModel`
    // rows:
    //   ruleType="exact-fqdn"    → address-match {kind:"exact-fqdn", value}
    //   ruleType="suffix-domain" → address-match {kind:"suffix-domain", suffix}
    //   ruleType="zone"          → address-match {kind:"zone", name}
    //   ruleType="exact-ip"      → address-match {kind:"exact-ipv4", address}
    //   ruleType="application"   → app-match {pattern:{kind:"exact",value},
    //                                          include-child-processes:false}
    //
    // Application rule details (include-child-processes flag, exact
    // vs glob) aren't in `rulesModel` today — defaults to `exact`
    // + `include-child-processes: false`. Tracked as B.7 landmine.
    //
    // The content-hash field on the wire isn't computed
    // canonically in the GUI (no SHA-256 primitive in plain QML).
    // We pass a Date-based placeholder; the dry-run path doesn't
    // strictly validate it, and the coordinator's idempotency
    // dedup just won't fire — semantically harmless for review,
    // production-correct canonicalization waits for a bridge
    // method (separate B.x slice).
    function _buildRulesJson() {
        var primary = []
        var secondary = []
        // The window owns the ACE encoder (it needs the C++ bridge); the
        // shared serializer takes it as an argument.
        var ace = root._aceEncodeHost
        if (root.rulesModel) {
            for (var i = 0; i < root.rulesModel.count; i += 1) {
                var entry = root.rulesModel.get(i)
                // A "block" rule nominally lives in the secondary bucket; its
                // action:"block" field (set by the serializer) overrides route.
                var bucket = (entry.targetRoute === "secondary" || entry.targetRoute === "block")
                    ? secondary : primary
                bucket.push(Rules.ruleRowToWireDto(entry, ace))
            }
        }
        var dto = {
            "schema-version": 1,
            "primary": primary,
            "secondary": secondary
        }
        return JSON.stringify(dto)
    }

    // Toggle one rule's enabled flag. Called from the
    // per-row CheckBox in the table delegate. Bumping `enabled` via
    // setProperty (rather than building a new row dict) keeps the
    // delegate's bindings live so the CheckBox state updates without
    // a model-reset flicker.
    function _setRuleEnabled(rowIndex, enabled) {
        if (section._refuseWhenLocked()) return
        if (!root.rulesModel) return
        if (rowIndex < 0 || rowIndex >= root.rulesModel.count) return
        root.rulesModel.setProperty(rowIndex, "enabled", !!enabled)
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
    }

    // Header bulk-toggle. Walks every row that passes
    // the current filter (so hidden-by-filter rows are untouched) and
    // flips them to the OPPOSITE of the majority state — if most
    // visible rules are enabled, this disables them; vice-versa.
    // Single-click on the header label triggers it.
    function _bulkToggleEnabled() {
        if (section._refuseWhenLocked()) return
        if (!root.rulesModel) return
        var visibleIndices = []
        var enabledCount = 0
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            var row = root.rulesModel.get(i)
            if (!section.passesFilter(row)) continue
            visibleIndices.push(i)
            if (row.enabled) enabledCount += 1
        }
        if (visibleIndices.length === 0) return
        var targetState = enabledCount < visibleIndices.length  // any disabled → enable all; all enabled → disable all
        for (var j = 0; j < visibleIndices.length; j += 1) {
            root.rulesModel.setProperty(visibleIndices[j], "enabled", targetState)
        }
        section.scheduleRebuild()
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
        root.statusLine = targetState
            ? root.tr("status.rules-bulk-enabled",
                "{n} rule(s) enabled.").replace("{n}", String(visibleIndices.length))
            : root.tr("status.rules-bulk-disabled",
                "{n} rule(s) disabled.").replace("{n}", String(visibleIndices.length))
    }

    // Destructive "Clear all rules" action. Removes
    // every row from rulesModel locally. When the service IPC is
    // reachable, immediately kicks off the review flow with an
    // empty rule set so the service activates a clean revision; user
    // still confirms in ReviewDiffDialog → ConfirmActivateDialog
    // (risk-scoring will likely flag this as Critical, which is
    // intentional — emptying the rule set is a deliberate gesture
    // and the user already passed our local Clear-all confirmation).
    // When offline, marks dirty so the next Save & review pushes
    // the empty state.
    function _clearAllRules() {
        if (section._refuseWhenLocked()) return
        if (!root.rulesModel) return
        Pure.clearModel(root.rulesModel)
        if (typeof root.setUnsavedChanges === "function") {
            root._recomputeRulesDirty()
        }
        // Wiping every rule also drops the
        // file-binding: the "Source: primary/secondary <file>" indicator
        // must not keep pointing at files whose content no longer matches
        // the (now empty) table. Clear the persisted source paths so the
        // indicator row hides until the user imports/saves again.
        if (typeof root.updatePrefs === "function") {
            root.updatePrefs({ lastSavedPathPrimary: "", lastSavedPathSecondary: "",
                               lastLoadedPathPrimary: "", lastLoadedPathSecondary: "" })
        }
        root.statusLine = root.tr("status.rules-cleared",
            "All rules cleared from the app.")
        // Service-connected: drive straight into the review pipeline
        // so the user has one click left (Confirm) to push the empty
        // set to the service. Offline: stop here — user can push
        // manually via Save & review once the service starts.
        var backendKind = String(root.backendStatus
            ? root.backendStatus.kind || "" : "")
        if (root.bridgeAvailable && backendKind === "connected") {
            section._triggerReviewFlow()
        }
    }

    function _triggerReviewFlow() {
        if (section._refuseWhenLocked()) return
        var rulesJson = _buildRulesJson()
        // Real SHA-256 of the rules-json bytes via
        // bridge primitive (replaces the legacy `client-stub-…`
        // placeholder). Deterministic for our build path because
        // `_buildRulesJson` emits keys in a fixed insertion order;
        // server-side canonical hash may differ (see bridge
        // `sha256Hex` doc-comment) but mismatch only degrades
        // idempotency dedup, not correctness. Falls back to the
        // legacy stub when the bridge isn't wired (preview / Tray).
        var contentHash
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function") {
            contentHash = nrrNativeBridge.sha256Hex(rulesJson)
        } else {
            contentHash = "client-stub-" + String(Date.now())
        }
        // Gate before the standard review flow when
        // the backend isn't connected. The host opens
        // `ServiceNotRunningDialog`; on Start/Install it arms a 10 s
        // wait timer and resumes via `_pendingReviewAfterConnect`,
        // on "Work without service" it parks the payload in sidecar.
        var backendKind = String(root.backendStatus
            ? root.backendStatus.kind || "" : "")
        if (backendKind !== "connected"
                && typeof root.startOfflineApplyFlow === "function") {
            root.startOfflineApplyFlow(rulesJson, contentHash)
            return
        }
        if (typeof root.reviewFlowController.startRulesReviewFlow === "function") {
            root.reviewFlowController.startRulesReviewFlow(rulesJson, contentHash)
        } else {
            console.log("RulesSection: startRulesReviewFlow unavailable on root")
        }
    }

    // Admin "set baseline": commit the CURRENT table as the
    // shared baseline (the default every OS-user falls back to). Routes as
    // an elevated `mutation-request` (the session broker relays the UAC).
    // Needs the service connected + elevation; no offline-park path (baseline
    // is service-global, not a per-user parked changeset).
    function _triggerBaselineReviewFlow() {
        var rulesJson = _buildRulesJson()
        var contentHash
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function") {
            contentHash = nrrNativeBridge.sha256Hex(rulesJson)
        } else {
            contentHash = "client-stub-" + String(Date.now())
        }
        var backendKind = String(root.backendStatus
            ? root.backendStatus.kind || "" : "")
        if (backendKind !== "connected") {
            root.statusLine = root.tr("status.baseline-needs-service",
                "Connect to the service to edit the baseline rules.")
            return
        }
        if (typeof root.reviewFlowController.startRulesReviewFlow === "function") {
            root.reviewFlowController.startRulesReviewFlow(rulesJson, contentHash, true /* adminBaseline */)
        }
    }

    // Search row: live filtering + explicit Search button + leading magnifier
    // icon. Pulled out of the filter bar because the user explicitly asked
    // for a full-width search field that does not share its row with combo
    // boxes.
    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Image {
            Layout.preferredWidth: 18
            Layout.preferredHeight: 18
            Layout.alignment: Qt.AlignVCenter
            source: root.uiIconSource("search")
            sourceSize.width: 18
            sourceSize.height: 18
            fillMode: Image.PreserveAspectFit
            asynchronous: true
        }
        ThemedTextField {
            theme: root.uiTheme
            Layout.fillWidth: true
            placeholderText: root.uiRevision >= 0
                ? root.tr("rules.search.placeholder", "Search by match value or comment")
                : ""
            text: section.searchText
            onTextChanged: section.searchText = text
            // Live search; explicit Search button below also commits the
            // current value (no-op other than clearing focus, since live
            // filtering already runs on every key press).
            Keys.onReturnPressed: section.searchText = text
            Keys.onEnterPressed: section.searchText = text
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("action.search", "Search")
            icon.source: root.uiIconSource("search")
            // Live filtering already runs via `onTextChanged`; this button
            // is here so users who prefer the Search-then-Enter idiom have
            // an explicit affordance. It also clears focus so the search
            // results list can take keyboard navigation.
            onClicked: section.searchText = section.searchText
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("action.clear", "Clear")
            icon.source: root.uiIconSource("clear")
            visible: section.searchText !== ""
            onClicked: section.searchText = ""
        }
    }

    // Sort / filter bar. Flow wraps onto multiple rows when
    // narrow. The search field used to live here too, but per UX feedback
    // it now has its own full-width row above so wide windows do not leave
    // a dead gap on the right.
    Flow {
        id: filterBar
        Layout.fillWidth: true
        width: parent ? parent.width : implicitWidth
        spacing: root.uiTheme.spacingMd

        Label {
            id: sortLabel
            text: root.uiRevision >= 0 ? root.tr("rules.sort.label", "Sort") : ""
            color: root.textColor
            verticalAlignment: Text.AlignVCenter
            height: sortCombo.height
        }
        ThemedComboBox {
            id: sortCombo
            theme: root.uiTheme
            implicitWidth: 220
            model: [ "by-display-order", "by-match-value", "by-type", "by-route" ]
            function sortLabel(id) { return root.tr("rules.sort." + id, id) }
            labelResolver: function(item) { return sortCombo.sortLabel(item) }
            currentIndex: Pure.optionIndexByValue(model, "by-display-order", 0)
            // Imperative displayText: declarative bindings on `displayText`
            // were dropped by Qt's default ComboBox after `onActivated` set
            // `currentIndex` internally, leaving the closed control showing
            // the raw model id ("disabled-only", "by-type") instead of the
            // localized label. Setting it explicitly on every activation
            // and on `uiRevision` change keeps it in sync regardless of
            // binding evaluation order.
            Component.onCompleted: sortCombo.displayText = sortCombo.sortLabel(sortCombo.model[sortCombo.currentIndex])
            popup.width: root.comboPopupWidth(sortCombo, model, "",
                function(item) { return sortCombo.sortLabel(item) })
            onActivated: {
                section.sortBy = model[currentIndex]
                section.sortDir = "asc"
                section.applySort()
                sortCombo.displayText = sortCombo.sortLabel(model[currentIndex])
            }
            Connections {
                target: root
                // Guard against firing during initial section
                // construction when `sortCombo` is briefly null.
                function onUiRevisionChanged() {
                    if (!sortCombo) return
                    sortCombo.displayText = sortCombo.sortLabel(sortCombo.model[sortCombo.currentIndex])
                }
            }
        }

        Label {
            id: statusLabel
            text: root.uiRevision >= 0 ? root.tr("rules.filter.enabled.label", "Status") : ""
            color: root.textColor
            verticalAlignment: Text.AlignVCenter
            height: enabledFilterCombo.height
        }
        ThemedComboBox {
            id: enabledFilterCombo
            theme: root.uiTheme
            implicitWidth: 220
            model: [ "all", "enabled-only", "disabled-only", "with-errors" ]
            function statusLabel(id) { return root.tr("rules.filter.enabled." + id, id) }
            labelResolver: function(item) { return enabledFilterCombo.statusLabel(item) }
            currentIndex: 0
            Component.onCompleted: enabledFilterCombo.displayText = enabledFilterCombo.statusLabel(enabledFilterCombo.model[enabledFilterCombo.currentIndex])
            popup.width: root.comboPopupWidth(enabledFilterCombo, model, "",
                function(item) { return enabledFilterCombo.statusLabel(item) })
            onActivated: {
                section.filterEnabled = model[currentIndex]
                enabledFilterCombo.displayText = enabledFilterCombo.statusLabel(model[currentIndex])
            }
            Connections {
                target: root
                function onUiRevisionChanged() {
                    if (!enabledFilterCombo) return
                    enabledFilterCombo.displayText = enabledFilterCombo.statusLabel(enabledFilterCombo.model[enabledFilterCombo.currentIndex])
                }
            }
        }

        Label {
            id: typeLabel
            text: root.uiRevision >= 0 ? root.tr("rules.filter.type.label", "Type") : ""
            color: root.textColor
            verticalAlignment: Text.AlignVCenter
            height: typeFilterCombo.height
        }
        ThemedComboBox {
            id: typeFilterCombo
            theme: root.uiTheme
            implicitWidth: 200
            model: [ "all", "zone", "domain", "exact-ip", "application" ]
            function typeLabel(id) {
                if (id === "all") return root.tr("rules.filter.type.all", "All types")
                return root.tr("rules.filter.type." + id, root.tr("rules.type." + id, id))
            }
            labelResolver: function(item) { return typeFilterCombo.typeLabel(item) }
            currentIndex: 0
            Component.onCompleted: typeFilterCombo.displayText = typeFilterCombo.typeLabel(typeFilterCombo.model[typeFilterCombo.currentIndex])
            popup.width: root.comboPopupWidth(typeFilterCombo, model, "",
                function(item) { return typeFilterCombo.typeLabel(item) })
            onActivated: {
                section.filterType = model[currentIndex]
                typeFilterCombo.displayText = typeFilterCombo.typeLabel(model[currentIndex])
            }
            Connections {
                target: root
                function onUiRevisionChanged() {
                    if (!typeFilterCombo) return
                    typeFilterCombo.displayText = typeFilterCombo.typeLabel(typeFilterCombo.model[typeFilterCombo.currentIndex])
                }
            }
        }

        // Route filter (requested). Mirrors the type filter.
        Label {
            id: routeFilterLabel
            text: root.uiRevision >= 0 ? root.tr("rules.filter.route.label", "Route") : ""
            color: root.textColor
            verticalAlignment: Text.AlignVCenter
            height: routeFilterCombo.height
        }
        ThemedComboBox {
            id: routeFilterCombo
            theme: root.uiTheme
            implicitWidth: 200
            model: [ "all", "primary", "secondary", "block" ]
            function routeLabelFor(id) {
                if (id === "all") return root.tr("rules.filter.route.all", "All routes")
                return root.routeLabel(id)
            }
            labelResolver: function(item) { return routeFilterCombo.routeLabelFor(item) }
            currentIndex: 0
            Component.onCompleted: routeFilterCombo.displayText = routeFilterCombo.routeLabelFor(routeFilterCombo.model[routeFilterCombo.currentIndex])
            popup.width: root.comboPopupWidth(routeFilterCombo, model, "",
                function(item) { return routeFilterCombo.routeLabelFor(item) })
            onActivated: {
                section.filterRoute = model[currentIndex]
                routeFilterCombo.displayText = routeFilterCombo.routeLabelFor(model[currentIndex])
            }
            Connections {
                target: root
                function onUiRevisionChanged() {
                    if (!routeFilterCombo) return
                    routeFilterCombo.displayText = routeFilterCombo.routeLabelFor(routeFilterCombo.model[routeFilterCombo.currentIndex])
                }
            }
        }
        // "Which of these did I not write?" — the service authors rules on its
        // own initiative, and until now nothing in the table separated those
        // from the user's own. The origin tag is already on every row.
        CheckBox {
            id: autoAddedFilterCheck
            text: root.uiRevision >= 0
                ? root.tr("rules.filter.auto-added", "Auto-added only") : ""
            checked: section.filterAutoAddedOnly
            onToggled: section.filterAutoAddedOnly = checked
            contentItem: Text {
                text: autoAddedFilterCheck.text
                color: root.textColor
                leftPadding: autoAddedFilterCheck.indicator.width + autoAddedFilterCheck.spacing
                verticalAlignment: Text.AlignVCenter
            }
        }

        // Addresses the service is offering but nobody has answered yet. Lives
        // next to the auto-added filter because both are about rules this app
        // proposed rather than rules the user wrote.
        ThemedButton {
            theme: root.uiTheme
            visible: root.autoRuleCandidatesPending > 0
            text: root.uiRevision >= 0
                ? root.tr("rules.suggestions.chip", "Suggested addresses ({count})")
                    .replace("{count}", String(root.autoRuleCandidatesPending))
                : ""
            icon.source: root.uiIconSource("add")
            Accessible.role: Accessible.Button
            Accessible.name: text
            Accessible.description: root.tr("rules.suggestions.chip-description",
                "Review addresses the service suggests adding to your rules.")
            onClicked: root.openAutoRuleSuggestions()
        }
    }

    // Empty state moved above the table so
    // it stays a direct ColumnLayout child (full-width, centred) while the
    // header + list move inside the horizontal Flickable below. Exactly
    // one of {empty-state, table} is visible at a time (count 0 vs > 0).
    ColumnLayout {
        Layout.fillWidth: true
        Layout.fillHeight: true
        Layout.alignment: Qt.AlignHCenter | Qt.AlignVCenter
        spacing: root.uiTheme.spacingMd
        visible: !root.rulesModel || root.rulesModel.count === 0
        // Rules are editable with or without a running service — offline edits
        // are parked and offered to the service when it comes up — so this
        // state must never blame the service for an empty table. It has exactly
        // two causes: no rule set is bound (nothing to load), or a bound set
        // that is genuinely empty.
        Item { Layout.fillHeight: true }
        Label {
            Layout.alignment: Qt.AlignHCenter
            text: section._sourcePathFor("primary") === ""
                    && section._sourcePathFor("secondary") === ""
                ? root.tr("rules.empty.no-source.title", "No rule set loaded")
                : root.tr("rules.empty.title", "No rules yet")
            color: root.textColor
            font.pixelSize: 18
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
        }
        Label {
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: 480
            text: section._sourcePathFor("primary") === ""
                    && section._sourcePathFor("secondary") === ""
                ? root.tr("rules.empty.no-source.body",
                    "Pick a rule set above and press Load, or add a rule by hand. "
                    + "The background service is not needed for this.")
                : root.tr(
                    "rules.empty.body",
                    "Add your first routing rule to start sending traffic through the secondary route.")
            color: root.uiTheme.colorTextMuted
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }
        ThemedButton {
            Layout.alignment: Qt.AlignHCenter
            theme: root.uiTheme
            text: root.tr("rules.empty.cta", "Add your first rule")
            icon.source: root.uiIconSource("add")
            enabled: !section.rulesLocked
            onClicked: {
                root.editingRule = -1
                root.ruleDialog.resetForEdit()
                root.ruleDialog.open()
            }
        }
        Item { Layout.fillHeight: true }
    }

    // Column header row with click-to-sort. Arrow indicator (▲/▼) appears
    // next to the active column; clicking the same column flips the
    // direction, clicking another column resets to ascending.
    //
    // Header + list wrapped in a horizontal,
    // header-pinned Flickable so wide content (user-widened columns) is
    // reachable via a horizontal scrollbar. `contentWidth` is
    // max(viewport, tableContentWidth): when there's slack the comment
    // column (fillWidth) absorbs it exactly as before; once columns exceed
    // the viewport the scrollbar appears. `contentHeight == height` +
    // HorizontalFlick keeps the header pinned; the ListView keeps its own
    // vertical scrollbar.
    Flickable {
        id: rulesTableScroll
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: root.rulesModel && root.rulesModel.count > 0
        clip: true
        contentWidth: Math.max(width, section.tableContentWidth)
        contentHeight: height
        flickableDirection: Flickable.HorizontalFlick
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.horizontal: ScrollBar {
            policy: ScrollBar.AsNeeded
            active: true
        }

    Frame {
        id: rulesHeaderFrame
        x: 0
        y: 0
        width: rulesTableScroll.contentWidth
        padding: root.uiTheme.spacingSm
        background: Rectangle {
            color: root.uiTheme.colorPanel
            border.width: root.uiTheme.borderWidth
            border.color: root.uiTheme.stateDefaultBorder
            radius: root.uiTheme.radiusSm
        }
        RowLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingMd

            // Leading selection column header.
            // Tri-state checkbox: empty when no visible rows are selected,
            // fully checked when every visible row is selected, partially
            // checked when only some are. Clicking it selects every
            // visible row, or clears the selection if any rows are
            // already selected. Width matches the per-row CheckBox cell.
            CheckBox {
                id: headerSelectAll
                Layout.preferredWidth: 32
                Layout.alignment: Qt.AlignVCenter
                tristate: true
                checkState: {
                    // Bind to selectedCount + uiRevision so the tri-state
                    // chip refreshes when the selection or filter changes.
                    var _refresh = section.selectedCount + root.uiRevision
                    var state = section._visibleSelectionState()
                    if (state === 1) return Qt.Checked
                    if (state === 2) return Qt.PartiallyChecked
                    return Qt.Unchecked
                }
                onClicked: section._toggleSelectAllVisible()
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: root.tr("rules.column.select-tooltip",
                    "Select / deselect all visible rules for bulk actions.")
            }

            // Reusable resize-handle component. Sits between two header cells
            // and drags the width of the column to its left. The actual width
            // values live on `section.col*Width`; every delegate row reads
            // them so columns stay aligned even after the user drags.
            component ResizeHandle: Item {
                property var widthProp
                property string widthKey: ""
                Layout.preferredWidth: 6
                Layout.fillHeight: true
                MouseArea {
                    anchors.fill: parent
                    anchors.leftMargin: -3
                    anchors.rightMargin: -3
                    cursorShape: Qt.SplitHCursor
                    hoverEnabled: true
                    property real startX: 0
                    property int startWidth: 0
                    onPressed: function(mouse) {
                        startX = mouse.x
                        startWidth = section[parent.widthKey]
                    }
                    onPositionChanged: function(mouse) {
                        if (!pressed) return
                        var delta = mouse.x - startX
                        var nw = Math.max(section.columnMinWidth, startWidth + delta)
                        section[parent.widthKey] = nw
                    }
                }
                Rectangle {
                    anchors.verticalCenter: parent.verticalCenter
                    width: 1
                    height: parent.height * 0.6
                    color: root.uiTheme.stateDefaultBorder
                    opacity: 0.5
                }
            }

            // ID column header → sorts by display-order
            MouseArea {
                Layout.preferredWidth: section.colIdWidth
                Layout.preferredHeight: idHeader.implicitHeight
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: section.setSortBy("by-display-order")
                Label {
                    id: idHeader
                    anchors.fill: parent
                    text: root.tr("rules.column.id", "ID") + " " + section.sortArrowFor("by-display-order")
                    color: section.sortBy === "by-display-order" ? root.uiTheme.colorAccent : root.textColor
                    font.bold: true
                    verticalAlignment: Text.AlignVCenter
                }
            }

            ResizeHandle { widthKey: "colIdWidth" }

            // Type column header → sorts by ruleType
            MouseArea {
                Layout.preferredWidth: section.colTypeWidth
                Layout.preferredHeight: typeHeader.implicitHeight
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: section.setSortBy("by-type")
                Label {
                    id: typeHeader
                    anchors.fill: parent
                    text: root.tr("rules.column.type", "Type") + " " + section.sortArrowFor("by-type")
                    color: section.sortBy === "by-type" ? root.uiTheme.colorAccent : root.textColor
                    font.bold: true
                    verticalAlignment: Text.AlignVCenter
                }
            }

            ResizeHandle { widthKey: "colTypeWidth" }

            // Match value column header → sorts by matchValue
            MouseArea {
                Layout.preferredWidth: section.colMatchWidth
                Layout.preferredHeight: matchHeader.implicitHeight
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: section.setSortBy("by-match-value")
                Label {
                    id: matchHeader
                    anchors.fill: parent
                    text: root.tr("rules.column.match-value", "Match value") + " " + section.sortArrowFor("by-match-value")
                    color: section.sortBy === "by-match-value" ? root.uiTheme.colorAccent : root.textColor
                    font.bold: true
                    verticalAlignment: Text.AlignVCenter
                }
            }

            ResizeHandle { widthKey: "colMatchWidth" }

            // Spacer to align with the route icon column in delegate
            Item { Layout.preferredWidth: 20 }

            // Route column header → sorts by targetRoute
            MouseArea {
                Layout.preferredWidth: section.colRouteWidth
                Layout.preferredHeight: routeHeader.implicitHeight
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: section.setSortBy("by-route")
                Label {
                    id: routeHeader
                    anchors.fill: parent
                    text: root.tr("rules.column.route", "Route") + " " + section.sortArrowFor("by-route")
                    color: section.sortBy === "by-route" ? root.uiTheme.colorAccent : root.textColor
                    font.bold: true
                    verticalAlignment: Text.AlignVCenter
                }
            }

            // Enable column header (compact). Click bulk-toggles all
            // visible rows on/off (kept as a convenience — the same
            // action is also available via the bulk-ops bar on the
            // selected subset).
            MouseArea {
                Layout.preferredWidth: 28
                Layout.preferredHeight: enabledHeader.implicitHeight
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                onClicked: section._bulkToggleEnabled()
                ToolTip.visible: containsMouse
                ToolTip.delay: 400
                ToolTip.text: root.tr("rules.column.enabled-tooltip",
                    "Click to toggle all visible rules on/off.")
                Label {
                    id: enabledHeader
                    anchors.fill: parent
                    text: root.tr("rules.column.enabled", "On")
                    color: root.textColor
                    font.bold: true
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }

            // Comment column header (no sort — rules-file format keeps the
            // comment as free-form metadata; sorting by it has no semantic
            // meaning in the policy domain). Comment column takes the
            // remaining width via `Layout.fillWidth` and lives at the very
            // right edge of the table.
            Label {
                Layout.fillWidth: true
                text: root.tr("rules.column.comment", "Comment")
                color: root.textColor
                font.bold: true
                elide: Text.ElideRight
                verticalAlignment: Text.AlignVCenter
            }
        }
    }

    // The filtered + sorted projection of `root.rulesModel`.
    // Rebuilt by `section.rebuildDisplay()`. Non-visual; lives inside the
    // Flickable purely for scoping.
    ListModel { id: displayModel }

    ListView {
        id: rulesListView
        anchors.top: rulesHeaderFrame.bottom
        anchors.left: parent.left
        width: rulesTableScroll.contentWidth
        height: rulesTableScroll.height - rulesHeaderFrame.height
        clip: true
        // Recycle delegates instead of
        // destroying + recreating them on scroll / when the section is
        // re-shown. With ~300 imported rows this is the dominant cost of
        // "switching sections is slow after loading a preset": every show
        // rebuilt the visible delegates from scratch. All delegate state is
        // bound to `model`/`index`, so reuse is safe. `cacheBuffer` keeps a
        // screenful above/below realised so scrolling doesn't thrash.
        reuseItems: true
        cacheBuffer: 600
        // Vertical scrollbar pinned to the VIEWPORT's right edge.
        // The ListView width == table contentWidth (wider than the
        // viewport when columns are widened), so the attached bar normally sits
        // at the CONTENT's right edge — off-screen until the horizontal bar is
        // dragged all the way right. We REPARENT it into the horizontal
        // Flickable and bind x = contentX + viewportW - barW so it tracks the
        // viewport. Reparenting keeps the attached size/position wiring to this
        // ListView intact (the attachment binds to contentY, not to the parent),
        // so no manual sync / feedback loop. Earlier attempt that only set `x`
        // failed because the ListView's own anchoring overrode it.
        ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
            active: true
            parent: rulesTableScroll
            z: 20
            width: 12
            y: rulesHeaderFrame.height
            height: rulesListView.height
            x: rulesTableScroll.contentX + rulesTableScroll.width - width
        }
        spacing: 0
        // Bound to the filtered+sorted VIEW, not the master model,
        // so virtualization realizes only ~one viewport of delegates.
        model: displayModel
        delegate: Frame {
            id: ruleDelegate
            width: ListView.view ? ListView.view.width : 0
            padding: root.uiTheme.spacingSm
            readonly property int rowGap: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
            topInset: rowGap
            // DisplayModel holds ONLY rows passing the filter, so
            // every delegate is visible and its height is the real content
            // height (no more lazy Loader / height-0 trickery that defeated
            // virtualization — note).
            height: rowLayout.implicitHeight + padding * 2 + rowGap
            // Per-row validation state. Defaults to "valid" when the
            // backend snapshot omits the field — keeps backwards
            // compatibility with rows that don't carry validation yet.
            readonly property string validationStatus: String(model.validationStatus || "valid")
            readonly property bool validationError: validationStatus === "error"
            readonly property bool validationWarning: validationStatus === "warning"
            // Reactive flag: is THIS row marked in the bulk-selection set?
            // Bound through selectedCount + uiRevision so it refreshes the
            // delegate's checkbox and background tint whenever the user
            // toggles selection on any row.
            readonly property bool isSelectedForBulk: {
                var _refresh = section.selectedCount + root.uiRevision
                return !!section.selectedRowIds[String(model.masterIndex)]
            }
            // Single-selection highlight keyed on the UNIQUE master index, not
            // the rule id (ids collide across routes → two rows would light up).
            readonly property bool _isSelectedSingle:
                root.selectedRule >= 0 && root.selectedRule === model.masterIndex
            background: CardSurface {
                theme: root.uiTheme
                selected: ruleDelegate._isSelectedSingle || ruleDelegate.isSelectedForBulk
                cornerRadius: root.uiTheme.radiusSm
                overrideFill: (ruleDelegate.isSelectedForBulk || ruleDelegate._isSelectedSingle)
                    ? root.uiTheme.colorSelection
                    : "transparent"
                overrideBorder: ruleDelegate.validationError
                    ? root.uiTheme.colorDanger
                    : ruleDelegate.validationWarning
                        ? root.uiTheme.colorWarning
                        : "transparent"
                emphasizedBorder: ruleDelegate.validationError || ruleDelegate.validationWarning
            }
            // Тело строки строится ЛЕНИВО. Пока строка скрыта
            // фильтром (visible === false), Loader неактивен и карточка/иконки/
            // лейблы/чекбоксы НЕ создаются. Раньше ListView строил все ~300
            // делегатов целиком, чтобы узнать, что у скрытых высота 0 — отсюда
            // многосекундный фильтр по типу/статусу/поиску. Frame остаётся
            // корнем делегата, поэтому model/index доступны в инлайновом
            // Component без оговорок.
            // ПРИМЕЧАНИЕ: дочерние элементы ниже намеренно оставлены на отступе
            // тела делегата — чтобы не переформатировать ~180 строк; вложенность
            // задаётся скобками, не отступом.
            // Row-body click target. Declared BENEATH the content ColumnLayout
            // (earlier in z-order) so Labels/Images (mouse-transparent) let
            // clicks fall through to it, while the per-row CheckBoxes on top get
            // their own clicks. Single click selects; double click edits.
            MouseArea {
                anchors.fill: parent
                acceptedButtons: Qt.LeftButton
                onClicked: root.selectedRule = model.masterIndex
                onDoubleClicked: {
                    root.selectedRule = model.masterIndex
                    if (section.rulesLocked) return
                    root.editingRule = root.selectedRule
                    root.ruleDialog.resetForEdit()
                    root.ruleDialog.open()
                }
            }
            ColumnLayout {
                id: rowLayout
                anchors.fill: parent
                spacing: root.uiTheme.spacingXxs
                RowLayout {
                    id: rowContent
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingMd
                    // Selection checkbox at
                    // the very left of every row. Drives the bulk-ops
                    // bar (delete / enable / disable / move-to-route).
                    // Decoupled from the per-row enable toggle, which
                    // now lives just before the Comment column.
                    CheckBox {
                        Layout.preferredWidth: 32
                        Layout.alignment: Qt.AlignVCenter
                        checked: ruleDelegate.isSelectedForBulk
                        onToggled: section._setRowSelected(model.masterIndex, checked)
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: root.tr("rules.action.select-row",
                            "Select this rule for bulk actions")
                    }
                    Image {
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                        Layout.alignment: Qt.AlignVCenter
                        source: root.ruleLeadingIconSource(model.ruleType)
                        sourceSize.width: 20
                        sourceSize.height: 20
                        fillMode: Image.PreserveAspectFit
                        // Sync load: with reuseItems the async
                        // path re-fetched the icon on every delegate recycle,
                        // popping it blank→filled = the scroll "мельтешение".
                        // These are tiny cached SVGs, so sync is smooth.
                        asynchronous: false
                        cache: true
                        opacity: model.enabled ? 1.0 : 0.4
                    }
                    Label {
                        Layout.preferredWidth: section.colIdWidth
                        Layout.alignment: Qt.AlignVCenter
                        // Coerce to String: with reuseItems the
                        // delegate is briefly pooled (model detached → role
                        // reads undefined). A raw `model.id` then logged
                        // "Unable to assign [undefined] to QString" on EVERY
                        // recycle — 2960 such lines flooded the GUI log to
                        // 700 KB and the synchronous pipe-write per recycle
                        // added to scroll jank. `|| ""` tolerates the gap.
                        text: String(model.id || "")
                        color: root.textColor
                        opacity: model.enabled ? 1.0 : 0.5
                    }
                    // Spacer matching the resize handle width in the header,
                    // so cells line up under their respective header labels.
                    Item { Layout.preferredWidth: 6 }
                    Label {
                        Layout.preferredWidth: section.colTypeWidth
                        Layout.alignment: Qt.AlignVCenter
                        text: root.ruleTypeLabel(model.ruleType)
                        color: root.textColor
                        elide: Text.ElideRight
                        opacity: model.enabled ? 1.0 : 0.5
                    }
                    Item { Layout.preferredWidth: 6 }
                    Label {
                        Layout.preferredWidth: section.colMatchWidth
                        Layout.alignment: Qt.AlignVCenter
                        // Coerce to String (see model.id above):
                        // silences the pooled-delegate undefined→QString flood.
                        text: String(model.matchValue || "")
                        // Invalid rule values are highlighted in danger
                        // colour so the bad value itself stands out, not
                        // just the row border.
                        color: ruleDelegate.validationError
                            ? root.uiTheme.colorDanger
                            : ruleDelegate.validationWarning
                                ? root.uiTheme.colorWarning
                                : root.textColor
                        font.bold: ruleDelegate.validationError
                        elide: Text.ElideRight
                        opacity: model.enabled ? 1.0 : 0.6
                    }
                    Item { Layout.preferredWidth: 6 }
                    Image {
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                        Layout.alignment: Qt.AlignVCenter
                        source: root.routeIconSource(model.targetRoute)
                        sourceSize.width: 20
                        sourceSize.height: 20
                        fillMode: Image.PreserveAspectFit
                        // Sync load (see leading icon above).
                        asynchronous: false
                        cache: true
                        opacity: model.enabled ? 1.0 : 0.5
                    }
                    Label {
                        Layout.preferredWidth: section.colRouteWidth
                        Layout.alignment: Qt.AlignVCenter
                        // routeLabel resolves primary/secondary/block; do NOT
                        // use a binary ternary (block would mislabel as
                        // Secondary via the fall-through).
                        text: root.routeLabel(model.targetRoute)
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        opacity: model.enabled ? 1.0 : 0.5
                    }
                    // Compact per-row enable toggle. Was
                    // the leftmost column; moved here so the leading
                    // column is owned by the bulk-selection checkbox.
                    CheckBox {
                        Layout.preferredWidth: 28
                        Layout.alignment: Qt.AlignVCenter | Qt.AlignHCenter
                        enabled: !section.rulesLocked
                        checked: !!model.enabled
                        onToggled: {
                            section._setRuleEnabledAt(model.masterIndex, checked)
                            displayModel.setProperty(index, "enabled", checked)
                        }
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: checked
                            ? root.tr("rules.action.disable-rule",
                                "Disable this rule")
                            : root.tr("rules.action.enable-rule",
                                "Enable this rule")
                    }
                    // Comment cell. When the snapshot supplies a `commentKey`
                    // (preview/synthetic rows), localize via tr(); otherwise
                    // render the user-entered free-form `comment` verbatim.
                    // When the text is too long for the cell width, a hover
                    // tooltip surfaces the full string. Rightmost column.
                    Label {
                        id: commentCell
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        text: {
                            if (root.uiRevision < 0) return ""
                            var ck = String(model.commentKey || "")
                            if (ck !== "") return root.tr(ck, String(model.comment || ""))
                            return String(model.comment || "")
                        }
                        color: root.mutedTextColor
                        elide: Text.ElideRight

                        ToolTip.text: commentCell.text
                        ToolTip.visible: commentCell.truncated && commentHover.containsMouse
                            && commentCell.text !== ""
                        ToolTip.delay: 400
                        HoverHandler {
                            id: commentHover
                            property bool containsMouse: hovered
                        }
                    }
                }
                // Validation message line — only visible for rows that
                // carry an error or warning. Picks up locale-aware text
                // from `validationMessageKey`; falls back to the generic
                // `rules.validation.error` / `.warning` strings.
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: 28
                    visible: ruleDelegate.validationError || ruleDelegate.validationWarning
                    wrapMode: Text.WordWrap
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    color: ruleDelegate.validationError
                        ? root.uiTheme.colorDanger
                        : root.uiTheme.colorWarning
                    text: {
                        if (root.uiRevision < 0) return ""
                        var key = String(model.validationMessageKey || "")
                        var fallback = ruleDelegate.validationError
                            ? root.tr("rules.validation.error", "Error — rule is inactive")
                            : root.tr("rules.validation.warning", "Valid with warnings")
                        var msg = key !== "" ? root.tr(key, fallback) : fallback
                        // Substitute {param} placeholders supplied by the
                        // backend validator (e.g. {octet}, {position}). Args
                        // are an object map sent in the snapshot.
                        var args = model.validationMessageArgs
                        if (args) {
                            for (var k in args) {
                                msg = msg.replace(new RegExp("\\{" + k + "\\}", "g"), String(args[k]))
                            }
                        }
                        return msg
                    }
                }
                // App-authored rule badge. A rule NetRuleRouter added on the
                // user's behalf must not look like one they typed, and must
                // say what it is for: the badge marks it, the line next to it
                // names the site and the reason. Rendered only when the
                // service annotated the row (originReason non-empty); the row
                // is otherwise an ordinary rule — editable, disableable and
                // deletable like any other.
                RowLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: 28
                    spacing: root.uiTheme.spacingSm
                    visible: String(model.originReason || "") !== ""
                    Rectangle {
                        id: originBadge
                        // The site the rule was added for. Empty only for a
                        // hand-edited provenance comment; the tray's wording
                        // for the same unknown-site case is reused verbatim.
                        readonly property string anchorHost: {
                            var a = String(model.originAnchor || "")
                            if (a !== "") return a
                            return root.uiRevision >= 0
                                ? root.tr("tray.auto-rules.site-fallback",
                                    "a site you use")
                                : ""
                        }
                        Layout.alignment: Qt.AlignVCenter
                        radius: root.uiTheme.radiusSm
                        color: root.uiTheme.colorAccent
                        opacity: model.enabled ? 0.9 : 0.5
                        implicitWidth: originBadgeLabel.implicitWidth
                            + root.uiTheme.spacingSm * 2
                        implicitHeight: originBadgeLabel.implicitHeight
                            + root.uiTheme.spacingXxs * 2
                        Label {
                            id: originBadgeLabel
                            anchors.centerIn: parent
                            text: root.uiRevision >= 0
                                ? root.tr("rules.auto-origin.badge", "Added for you")
                                : ""
                            color: root.uiTheme.colorOnAccent
                            font.pixelSize: Math.max(10,
                                root.uiTheme.baseFontSizePx - 2)
                            font.bold: true
                        }
                        HoverHandler { id: originBadgeHover }
                        ToolTip.visible: originBadgeHover.hovered
                        ToolTip.delay: 300
                        ToolTip.text: {
                            if (root.uiRevision < 0) return ""
                            return root.tr("rules.auto-origin.tooltip",
                                "NetRuleRouter added this rule for {site} on {date}. You can turn it off or delete it like any rule of your own.")
                                .replace("{site}", originBadge.anchorHost)
                                .replace("{date}", String(model.originAdded || ""))
                        }
                    }
                    // Why it was added, in the user's language. Backend slug →
                    // `rules.auto-origin.<slug>`; an unknown slug from a newer
                    // build falls back to the slug itself rather than showing
                    // nothing.
                    Label {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter
                        elide: Text.ElideRight
                        color: root.mutedTextColor
                        font.pixelSize: Math.max(10, root.uiTheme.baseFontSizePx - 2)
                        opacity: model.enabled ? 1.0 : 0.6
                        text: {
                            if (root.uiRevision < 0) return ""
                            var slug = String(model.originReason || "")
                            if (slug === "") return ""
                            return root.tr("rules.auto-origin." + slug, slug)
                                .replace("{site}", originBadge.anchorHost)
                        }
                    }
                }
                // Read-only OS hosts-file override badge.
                // The OS hosts file resolves this hostname BEFORE NRR sees
                // any traffic, so NRR cannot override it — this is purely
                // informational. Rendered only when the service annotated
                // the row (hostsOverrideIp non-empty). Blocking (loopback/
                // unspecified) → danger colour; a real redirect → accent.
                RowLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: 28
                    visible: String(model.hostsOverrideIp || "") !== ""
                    Rectangle {
                        id: hostsBadge
                        readonly property bool blocking: !!model.hostsOverrideBlocking
                        Layout.alignment: Qt.AlignVCenter
                        radius: root.uiTheme.radiusSm
                        color: hostsBadge.blocking
                            ? root.uiTheme.colorDanger
                            : root.uiTheme.colorAccent
                        opacity: model.enabled ? 0.9 : 0.5
                        implicitWidth: hostsBadgeLabel.implicitWidth
                            + root.uiTheme.spacingSm * 2
                        implicitHeight: hostsBadgeLabel.implicitHeight
                            + root.uiTheme.spacingXxs * 2
                        Label {
                            id: hostsBadgeLabel
                            anchors.centerIn: parent
                            text: {
                                if (root.uiRevision < 0) return ""
                                return hostsBadge.blocking
                                    ? root.tr("rules.hosts-override.blocked",
                                        "Blocked in hosts")
                                    : root.tr("rules.hosts-override.redirected",
                                        "Redirected by system → {ip}")
                                        .replace("{ip}",
                                            String(model.hostsOverrideIp || ""))
                            }
                            color: root.uiTheme.colorOnAccent
                            font.pixelSize: Math.max(10,
                                root.uiTheme.baseFontSizePx - 2)
                            font.bold: true
                        }
                        HoverHandler { id: hostsBadgeHover }
                        ToolTip.visible: hostsBadgeHover.hovered
                        ToolTip.delay: 300
                        ToolTip.text: root.tr("rules.hosts-override.tooltip",
                            "The operating system's hosts file resolves this hostname before NetRuleRouter sees any traffic, so NetRuleRouter cannot override it. Edit the OS hosts file to change this.")
                    }
                    Item { Layout.fillWidth: true }
                }
            }
        }
    }
    }
}
