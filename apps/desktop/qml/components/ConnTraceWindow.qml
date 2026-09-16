import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../theme"
import "../lib/pure.js" as Pure

// Live connection trace, moved out of DiagnosticsSection into its own window.
// People read it WHILE editing rules — a section in a StackLayout cannot be open
// beside the rules table, a window can. The window owns its state rather than
// borrowing the section's: the section lives in a lazy Loader and does not exist
// until Diagnostics has been opened once.
Window {
    id: traceWindow

    property var root: null

    width: 1100
    height: 720
    visible: false
    modality: Qt.NonModal
    color: root ? root.panelColor : "transparent"
    title: root ? root.tr("diag.conn-trace.window-title", "Connection trace") : ""
    transientParent: root
    flags: Qt.Dialog
    onVisibleChanged: if (visible) { root.centerChildWindow(traceWindow); root.applyTitleBarTo(traceWindow) }

    // Table geometry: the window owns its own, so a change here cannot silently
    // resize the cache table in the other window.
    readonly property int _renderCap: 400
    readonly property int _listMaxHeight: 460
    readonly property int _listLineHeight:
        Math.max(20, Math.round(root.uiTheme.baseFontSizePx * 1.7))
    // Sort for THIS table only. The old shared helper switched on a "table"
    // string; each window sorting its own columns removes the switch.
    function _sortKey(col, e) {
        if (col === "process") return String((e && e.process) || "")
        if (col === "remote") return String((e && e.remote) || "")
        if (col === "egress") return traceWindow._connEgressLabel(e && e.egress_role)
        if (col === "verdict") return traceWindow._connVerdictLabel(e && e.verdict)
        return ""
    }
    function _sortRows(list, table, col, dir) {
        if (!col || !dir) return list
        var arr = list.slice()
        arr.sort(function(a, b) {
            var va = String(traceWindow._sortKey(col, a)).toLowerCase()
            var vb = String(traceWindow._sortKey(col, b)).toLowerCase()
            return (va < vb ? -1 : (va > vb ? 1 : 0)) * dir
        })
        return arr
    }

    property string _connSortCol: ""
    property int _connSortDir: 1

    // Numeric/chronological columns compare as numbers; every other column
    // compares the displayed (localized) label case-insensitively.
    function _toggleConnSort(col) {
        if (traceWindow._connSortCol === col)
            traceWindow._connSortDir = -traceWindow._connSortDir
        else { traceWindow._connSortCol = col; traceWindow._connSortDir = 1 }
    }
    // " ▲" (ascending) / " ▼" (descending) suffix appended to the active sort
    // column header, "" otherwise. Glyphs are plain UTF-8 (file already holds
    // em-dashes); no locale keys needed for the sort indicator.
    function _connSortArrow(col) {
        if (traceWindow._connSortCol !== col) return ""
        return traceWindow._connSortDir < 0 ? " ▼" : " ▲"
    }

    // Per-row lowercase search blob, computed ONCE and cached on
    // the entry object. The `_cacheFiltered` binding re-runs on every page-append
    // during a drain; without the cache each recompute rebuilt this string per row
    // (2× new Date + 2× tr + join) → O(pages × rows) heavy work that froze the form
    // on a cache-miss search. With the cache each recompute is a cheap indexOf.
    function _connRowsTsv() {
        var list = traceWindow._connFiltered
        var lines = []
        for (var i = 0; i < list.length; i++)
            lines.push(traceWindow._connRowTsv(list[i] || {}))
        return lines.join("\n")
    }

    // `reset === true` → clear and pull the first page; `false` → append the
    // next page via the offset cursor echoed back by the previous response.
    property var _connTraceEntries: []
    property string _connTraceCursor: ""
    property bool _connTraceLoading: false
    property bool _connTraceShown: false
    // Auto-refresh state. The observer is NOT on the data path: the panel pulls
    // a snapshot on a timer, it never receives an event per packet.
    property bool _connAutoRefresh: true
    property double _connLastRefreshMs: 0
    // Ticks once a second so the "updated N s ago" label re-evaluates — a
    // binding over Date.now() alone never invalidates itself.
    property int _connClockRev: 0
    // False only when the service reports no running observation source, so an
    // empty table can say which silence it is.
    property bool _connObserverActive: true
    // False when the user switched the GUI trace off in Settings: the page is
    // empty by request, and the panel says so instead of blaming the service.
    property bool _connGuiStreamEnabled: true
    // Client-side retention of the merged list, matching the service ring.
    readonly property int _connTraceRingCap: 1000
    // TASK A — direct row selection for the connection-trace table (mirror of the
    // cache twin). Selection holds the row objects by reference; synthetic group
    // headers (`_isGroupHeader`) are never selectable. Copy/count/highlight filter
    // against the live `_connGroupedModel`, so a stale reference clears itself when
    // the model rebuilds. `_connSelAnchor` indexes into `_connGroupedModel`.
    property var _connSel: []
    property int _connSelAnchor: -1
    property int _connSelRev: 0
    function _connRowSelected(e) {
        return traceWindow._connSelRev >= 0 && e !== undefined
            && traceWindow._connSel.indexOf(e) !== -1
    }
    function _connSelectedCount() {
        var model = traceWindow._connGroupedModel
        var n = 0
        for (var i = 0; traceWindow._connSelRev >= 0 && i < model.length; i++) {
            var e = model[i]
            if (e !== undefined && !e._isGroupHeader
                    && traceWindow._connSel.indexOf(e) !== -1) n++
        }
        return n
    }
    function _selectConnRow(index, e, ctrl, shift) {
        var model = traceWindow._connGroupedModel
        if (shift && traceWindow._connSelAnchor >= 0
                && traceWindow._connSelAnchor < model.length) {
            var lo = Math.min(traceWindow._connSelAnchor, index)
            var hi = Math.max(traceWindow._connSelAnchor, index)
            var next = ctrl ? traceWindow._connSel.slice() : []
            for (var i = lo; i <= hi; i++) {
                var it = model[i]
                if (it !== undefined && !it._isGroupHeader
                        && next.indexOf(it) === -1) next.push(it)
            }
            traceWindow._connSel = next
        } else if (ctrl) {
            var arr = traceWindow._connSel.slice()
            var at = arr.indexOf(e)
            if (at === -1) arr.push(e); else arr.splice(at, 1)
            traceWindow._connSel = arr
            traceWindow._connSelAnchor = index
        } else {
            traceWindow._connSel = [e]
            traceWindow._connSelAnchor = index
        }
        traceWindow._connSelRev++
    }
    function _clearConnSelection() {
        traceWindow._connSel = []
        traceWindow._connSelAnchor = -1
        traceWindow._connSelRev++
    }
    // TSV for one connection row — the SAME column layout as `_connRowsTsv` and
    // the per-row right-click copy. Shared so the delegate, "Copy row" and
    // "Copy selected" all emit identical lines.
    function _connRowTsv(e) {
        return String((e && e.process) || "") + "\t"
            + String((e && e.process_path) || "") + "\t"
            + String((e && e.remote) || "") + "\t"
            + traceWindow._connEgressLabel(e && e.egress_role) + "\t"
            + traceWindow._connVerdictLabel(e && e.verdict) + "\t"
            + traceWindow._connProtoLabel(e && e.proto) + "\t"
            + String((e && e.local) || "") + "\t"
            + Pure.formatTimestamp(e && e.observed_at_ms)
    }
    function _copyConnSelected() {
        var model = traceWindow._connGroupedModel
        var lines = []
        for (var i = 0; i < model.length; i++) {
            var e = model[i]
            if (e !== undefined && !e._isGroupHeader
                    && traceWindow._connSel.indexOf(e) !== -1)
                lines.push(traceWindow._connRowTsv(e))
        }
        if (lines.length > 0)
            root.copyToClipboard(lines.join("\n"))
    }
    property string _connTraceError: ""
    property string _connTraceFilter: ""
    // View-only trace filters. SESSION-SCOPED ON PURPOSE: they change what the
    // viewer shows, not what is observed or enforced, and persisting them would
    // mean a new UiPreferences field on the Rust side. They reset to these
    // defaults on every launch.
    //
    // Both default to OFF so the first thing the user sees is the signal —
    // internet-bound traffic that was actually allowed out. Blocked rows are
    // usually foreign firewall/AV drops (see the verdict note) and LAN/loopback
    // rows never leave the machine, so neither says anything about routing.
    property bool _connShowBlocked: false
    property bool _connShowLocal: false
    // Narrow the list to IPv6. The family is observed but not yet routed by
    // rules, so this is how a user sees what currently travels outside policy.
    property bool _connOnlyIpv6: false
    // Single cached filtered view (see _cacheFiltered). The view filters run
    // BEFORE the text search so the search counts match what is on screen; both
    // toggles are read as binding arguments, which registers the dependency.
    property var _connFiltered: _sortRows(
        _filterConnTraceEntries(
            _applyConnViewFilters(_connTraceEntries, _connShowBlocked, _connShowLocal,
                                  _connOnlyIpv6),
            _connTraceFilter),
        "conn", _connSortCol, _connSortDir)
    // Cap the filter-driven page drain (mirror of _cacheDrainCap).
    // The trace ring holds ≤1000, so this is a safety bound, not a truncation in
    // practice; it also documents parity with the cache path.
    readonly property int _connTraceDrainCap: 2000
    // Render at most this many rows in the non-virtualized
    // Repeaters. A broad match (e.g. a single common letter) could otherwise
    // instantiate thousands of complex delegates synchronously and freeze the UI.
    // Copy-all-shown and the counts still use the FULL filtered list.
    property var _connRendered: (_connFiltered.length > _renderCap)
        ? _connFiltered.slice(0, _renderCap) : _connFiltered
    // Grouping of the trace by process, ON by default. The flat render list is
    // replaced by a list where each process's rows are preceded by a synthetic
    // header item (`_isGroupHeader: true`). Groups are keyed on the displayed
    // process (basename), sorted case-insensitively; the whole flattened output is
    // still capped at `_renderCap` so a huge trace can't freeze the view.
    // Session-scoped like the two view filters above.
    property bool _connGroupByProcess: true
    // Per-process expansion state, mirroring the cache table's per-host
    // expansion (`root.diagCacheExpanded`). Multi-row groups start COLLAPSED: a
    // raw trace is hundreds of rows across a handful of processes, and the
    // header row alone answers "who is talking, and how much". Lives on `root`
    // so it survives switching tabs. `diagConnGroupExpandRev` is bumped on
    // every toggle so bindings that read it via `_isConnGroupExpanded`
    // re-evaluate — a plain object mutation is not tracked.
    function _toggleConnGroupExpand(key) {
        var k = String(key || "")
        if (k === "") return
        if (root.diagConnGroupExpanded[k])
            delete root.diagConnGroupExpanded[k]
        else
            root.diagConnGroupExpanded[k] = true
        root.diagConnGroupExpandRev++
        // A collapsed group's rows leave the model; drop the selection so
        // "Copy selected" can never emit rows the user cannot see.
        traceWindow._clearConnSelection()
    }
    function _isConnGroupExpanded(key) {
        return root.diagConnGroupExpandRev >= 0
            && root.diagConnGroupExpanded[String(key || "")] === true
    }
    // One pass over the filtered rows produces everything the table needs: the
    // flattened display list, the number of matches the render cap kept out of
    // reach, and the viewport-height estimate. Kept in a SINGLE binding so the
    // three can never disagree and the grouping runs once per change.
    property var _connGroupedBuild: {
        var lineH = traceWindow._listLineHeight
        if (!_connGroupByProcess) {
            return {
                "rows": _connRendered,
                "dropped": _connFiltered.length - _connRendered.length,
                "height": _connRendered.length * 2 * lineH
            }
        }
        var groups = ({})
        var order = []
        for (var i = 0; i < _connFiltered.length; i++) {
            var e = _connFiltered[i] || {}
            var key = String(e.process || "—")
            if (groups[key] === undefined) { groups[key] = []; order.push(key) }
            groups[key].push(e)
        }
        order.sort(function(a, b) {
            var la = a.toLowerCase(), lb = b.toLowerCase()
            return la < lb ? -1 : (la > lb ? 1 : 0)
        })
        var out = []
        var dropped = 0
        var height = 0
        for (var g = 0; g < order.length; g++) {
            var k = order[g]
            var rows = groups[k]
            // Past the cap nothing further can be shown, but keep walking so the
            // truncation notice reports the real total instead of stopping short.
            if (out.length >= _renderCap) { dropped += rows.length; continue }
            // A one-connection group has nothing to collapse: render the row
            // itself, with no header, no chevron and no count.
            if (rows.length === 1) {
                out.push(rows[0])
                height += 2 * lineH
                continue
            }
            out.push({ "_isGroupHeader": true, "process": k, "_count": rows.length })
            height += lineH + root.uiTheme.spacingXs
            if (!traceWindow._isConnGroupExpanded(k)) continue
            var r = 0
            for (; r < rows.length && out.length < _renderCap; r++) {
                out.push(rows[r])
                height += 2 * lineH
            }
            // Rows a collapsed group hides are one click away; rows the cap cut
            // off are not — only the latter count as truncation.
            dropped += rows.length - r
        }
        return { "rows": out, "dropped": dropped, "height": height }
    }
    property var _connGroupedModel: _connGroupedBuild.rows
    // Matches the render cap kept off screen entirely (see `_connGroupedBuild`).
    readonly property int _connDroppedByCap: Number(_connGroupedBuild.dropped || 0)

    function _connEgressLabel(slug) {
        return root.tr("diag.conn-trace.egress." + String(slug || ""), String(slug || ""))
    }
    function _connVerdictLabel(slug) {
        return root.tr("diag.conn-trace.verdict." + String(slug || ""), String(slug || ""))
    }
    function _connProtoLabel(slug) {
        return root.tr("diag.conn-trace.proto." + String(slug || ""), String(slug || ""))
    }

    // Per-row lowercase search blob (see _cacheRowBlob).
    function _connRowBlob(e) {
        if (e && e._blob !== undefined) return e._blob
        var b = [
            String((e && e.process) || ""),
            traceWindow._connProtoLabel(e && e.proto),
            String((e && e.local) || ""),
            String((e && e.remote) || ""),
            traceWindow._connEgressLabel(e && e.egress_role),
            traceWindow._connVerdictLabel(e && e.verdict),
            Pure.formatTimestamp(e && e.observed_at_ms)
        ].join(" ").toLowerCase()
        if (e) e._blob = b
        return b
    }

    // Any verdict slug in the "block" family counts as a block — the wire slug is
    // `block`, and the delegate additionally splits it by `blocked_by`, so match
    // on the prefix rather than a single literal.
    function _connVerdictIsBlock(slug) {
        return String(slug || "").indexOf("block") === 0
    }

    // View-only row filters driven by the two checkboxes above the table. Both
    // arguments are passed in (not read off `section`) so the caller's binding
    // registers them as dependencies.
    function _applyConnViewFilters(entries, showBlocked, showLocal, onlyIpv6) {
        if (showBlocked && showLocal && !onlyIpv6) return entries
        var out = []
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i] || {}
            if (!showBlocked && traceWindow._connVerdictIsBlock(e.verdict)) continue
            if (!showLocal && Pure.isNonInternetAddress(e.remote)) continue
            if (onlyIpv6 && !Pure.isIpv6Endpoint(e.remote)) continue
            out.push(e)
        }
        return out
    }

    // All-field client-side filter (process, proto, local, remote, egress,
    // verdict, timestamp). Same reactive-argument shape as _filterCacheEntries.
    function _filterConnTraceEntries(entries, query) {
        var q = String(query || "").trim().toLowerCase()
        if (q === "") return entries
        var out = []
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i] || {}
            if (traceWindow._connRowBlob(e).indexOf(q) !== -1) out.push(e)
        }
        return out
    }

    function _loadConnTraceEntries(reset) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcConnTraceEntriesList !== "function") {
            traceWindow._connTraceError = root.tr("diag.conn-trace.entries-bridge-unavailable",
                "Service bridge not connected — connection trace unavailable")
            traceWindow._connTraceShown = true
            return
        }
        if (reset) {
            traceWindow._connTraceEntries = []
            traceWindow._connTraceCursor = ""
        }
        traceWindow._connTraceShown = true
        traceWindow._connTraceLoading = true
        traceWindow._connTraceError = ""
        var cursor = reset ? "" : traceWindow._connTraceCursor
        // Request the max page (200) so the ≤1000-entry ring loads in
        // ≤5 pages via a one-time OPEN drain (below), not the old per-keystroke drain
        // that rebuilt the render model on every append and froze the view.
        var corr = nrrNativeBridge.rpcConnTraceEntriesList(cursor, 200)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            traceWindow._connTraceLoading = false
            if (!ok) {
                traceWindow._connTraceError = root.tr("diag.conn-trace.entries-failed",
                    "Failed to load connection trace: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            var page = (payload && payload.page) || {}
            var items = page.items || []
            traceWindow._connObserverActive =
                (payload && payload["observer-active"]) !== false
            traceWindow._connGuiStreamEnabled =
                (payload && payload["gui-stream-enabled"]) !== false
            traceWindow._connLastRefreshMs = Date.now()
            var merged = traceWindow._connTraceEntries.slice()
            for (var i = 0; i < items.length; i++)
                merged.push(items[i])
            traceWindow._connTraceEntries = merged
            var nc = page.next_cursor
            traceWindow._connTraceCursor =
                (nc === undefined || nc === null) ? "" : String(nc)
            // ONE-TIME open drain: load the rest of the ≤1000-entry
            // ring (≤5 pages of 200) so the client filter covers the whole ring.
            // Unlike the old code this is NOT gated on the filter, so it runs once on
            // open and does NOT re-drain per keystroke (the debounce no longer drains).
            // TSV is gated (select-mode only) so these few appends don't churn.
            if (traceWindow._connTraceCursor !== ""
                    && traceWindow._connTraceEntries.length < traceWindow._connTraceDrainCap)
                traceWindow._loadConnTraceEntries(false)
        })
    }

    // Set while an Add-rule dialog opened from this panel is on screen, so the
    // window can follow the user to Rules once the rule is in — a rule added
    // from Diagnostics is not applied yet, and leaving the user here reads as
    // nothing having happened.
    property bool _connRulePending: false
    // Create a rule from the row the user is looking at. Reuses the shell's own
    // dialog — no new rule semantics, no second way to author a rule.
    // "Which rule decides this row": the rule diagnostics probe for this
    // connection — by the rule host's name when the service knows it, since a
    // domain rule cannot match a bare address.
    function _explainConnRow(host, ip, process) {
        var probe = root.ruleDiagnosticsWindow
        if (!probe || (host === "" && ip === ""))
            return
        probe._probeInputText = host !== "" ? host : ip
        probe._probeSampleIp = host !== "" ? ip : ""
        probe._probeSampleProcess = process === "?" ? "" : process
        root.openChildWindow(probe)
        probe._runExplainProbe()
    }
    function _ruleFromConnRow(ruleType, value) {
        if (!root.ruleDialog || String(value || "") === "")
            return
        traceWindow._connRulePending = true
        root.ruleDialog.resetForNew(ruleType, value)
        root.ruleDialog.open()
    }
    Connections {
        target: root.ruleDialog
        function onAccepted() {
            if (!traceWindow._connRulePending)
                return
            traceWindow._connRulePending = false
            root.section = "rules"
        }
        function onRejected() {
            traceWindow._connRulePending = false
        }
    }

    // Identity of a trace row across snapshots. A single flow can appear twice
    // with different verdicts (permitted, then dropped), so the verdict is part
    // of the key — otherwise the drop, which is the interesting half, is
    // swallowed as a duplicate.
    function _connRowKey(e) {
        return "k" + String((e && e.process_path) || "")
            + "|" + String((e && e.local) || "")
            + "|" + String((e && e.remote) || "")
            + "|" + String((e && e.observed_at_ms) || 0)
            + "|" + String((e && e.verdict) || "")
    }
    // Poll the NEWEST page and prepend what we have not seen. Deliberately not
    // a re-drain of the whole ring: the open-time drain already pulled it, and
    // pushing 1000 rows through the pipe every couple of seconds would spend
    // real money on a diagnostic view. Existing row objects are kept by
    // reference so an active selection survives the merge.
    function _refreshConnTraceHead() {
        if (!traceWindow._connTraceShown || traceWindow._connTraceLoading)
            return
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcConnTraceEntriesList !== "function")
            return
        var corr = nrrNativeBridge.rpcConnTraceEntriesList("", 200)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            // Silent on failure: this is a background poll, and the manual
            // Refresh button is what reports an error the user asked for.
            if (!ok)
                return
            var page = (payload && payload.page) || {}
            var items = page.items || []
            traceWindow._connObserverActive =
                (payload && payload["observer-active"]) !== false
            traceWindow._connGuiStreamEnabled =
                (payload && payload["gui-stream-enabled"]) !== false
            traceWindow._connLastRefreshMs = Date.now()
            var seen = {}
            var current = traceWindow._connTraceEntries
            for (var i = 0; i < current.length; i++)
                seen[traceWindow._connRowKey(current[i])] = true
            var fresh = []
            for (var j = 0; j < items.length; j++) {
                if (seen[traceWindow._connRowKey(items[j])] !== true)
                    fresh.push(items[j])
            }
            if (fresh.length === 0)
                return
            var merged = fresh.concat(current)
            if (merged.length > traceWindow._connTraceRingCap)
                merged = merged.slice(0, traceWindow._connTraceRingCap)
            traceWindow._connTraceEntries = merged
        })
    }
    // Age of the snapshot on screen, or the reason the poll is standing still.
    function _connRefreshStatusLabel() {
        if (traceWindow._connClockRev < 0 || traceWindow._connLastRefreshMs <= 0)
            return ""
        // Nothing is being served, so an age would only describe an empty page;
        // the empty state below already explains itself.
        if (!traceWindow._connGuiStreamEnabled)
            return ""
        if (traceWindow._connAutoRefresh
                && (traceWindow._connSel.length > 0 || connTraceList.contentY > 1))
            return root.tr("diag.conn-trace.auto-paused",
                "Paused — scroll to the top or clear the selection to resume")
        var secs = Math.max(0,
            Math.round((Date.now() - traceWindow._connLastRefreshMs) / 1000))
        return root.tr("diag.conn-trace.updated-ago", "updated %1 s ago").arg(secs)
    }

    // Snapshot poll. Stops when the panel is hidden, the section is off-screen,
    // the window is minimized, the user has rows selected, or the list is
    // scrolled away from the top: new rows arrive at the HEAD, so refreshing
    // under a reader who has scrolled down moves the text they are reading.
    Timer {
        id: connAutoRefreshTimer
        interval: 2000
        repeat: true
        running: traceWindow._connTraceShown && traceWindow._connAutoRefresh
            && traceWindow._connGuiStreamEnabled
            && traceWindow._connSel.length === 0
            && connTraceList.contentY <= 1
            && traceWindow.visible
            && traceWindow.visibility !== Window.Minimized
        onTriggered: traceWindow._refreshConnTraceHead()
    }
    // Drives the age label only.
    Timer {
        id: connAgeTicker
        interval: 1000
        repeat: true
        running: traceWindow._connTraceShown && traceWindow.visible
        onTriggered: traceWindow._connClockRev++
    }

    ScrollView {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingLg
        clip: true
        ColumnLayout {
            width: traceWindow.width - 2 * root.uiTheme.spacingLg
            spacing: root.uiTheme.spacingMd
        // C4c: Connection trace viewer (Q3) — read-only, populated on demand.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs

                Label {
                    text: root.tr("diag.conn-trace.title", "Connection trace")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.conn-trace.subtitle",
                        "Recently-observed outbound connections and which interface they actually left through (primary, or the additional adapter). Observation only — it never changes routing. The list refreshes on its own while it is open and is kept in memory only. (Writing connections to the on-disk log stays an opt-in in Settings.) Shows TCP/UDP connections — a ping (ICMP) leaves no connection to observe, so a pinged address will not appear here.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                }

                // Open / search / refresh / hide controls.
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        visible: !traceWindow._connTraceShown
                        enabled: !traceWindow._connTraceLoading
                        text: root.tr("diag.conn-trace.entries-button", "Show recent connections")
                        onClicked: traceWindow._loadConnTraceEntries(true)
                    }
                    ThemedTextField {
                        id: connTraceSearchField
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        visible: traceWindow._connTraceShown
                            && (traceWindow._connTraceEntries.length > 0
                                || traceWindow._connTraceFilter !== "")
                        placeholderText: root.tr("diag.conn-trace.entries-search-placeholder",
                            "Search all fields…")
                        // Debounce (see cache search).
                        onTextChanged: connTraceSearchDebounce.restart()
                    }
                    // Option and status first, the two buttons last: a check box
                    // wedged between two buttons reads as a third button.
                    CheckBox {
                        id: connAutoRefreshCheck
                        visible: traceWindow._connTraceShown
                        checked: traceWindow._connAutoRefresh
                        text: root.tr("diag.conn-trace.auto-refresh", "Refresh automatically")
                        contentItem: Label {
                            text: connAutoRefreshCheck.text
                            leftPadding: connAutoRefreshCheck.indicator.width
                                + connAutoRefreshCheck.spacing
                            color: root.textColor
                            verticalAlignment: Text.AlignVCenter
                        }
                        Accessible.name: connAutoRefreshCheck.text
                        onToggled: {
                            traceWindow._connAutoRefresh = checked
                            if (checked)
                                traceWindow._refreshConnTraceHead()
                        }
                    }
                    Label {
                        visible: traceWindow._connTraceShown
                            && traceWindow._connRefreshStatusLabel() !== ""
                        text: traceWindow._connRefreshStatusLabel()
                        color: root.mutedTextColor
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: traceWindow._connTraceShown
                        enabled: !traceWindow._connTraceLoading
                        text: root.tr("diag.conn-trace.entries-refresh", "Refresh")
                        onClicked: traceWindow._loadConnTraceEntries(true)
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: traceWindow._connTraceShown
                        text: root.tr("diag.conn-trace.entries-hide", "Hide connection trace")
                        onClicked: {
                            // Hide FIRST (see cache-entries hide, E).
                            traceWindow._connTraceShown = false
                            connTraceSearchField.text = ""
                        }
                    }
                }

                // View filters for the table below. All three are session-scoped
                // UI state (see `_connShowBlocked`) — they are not persisted, so a
                // relaunch always starts from the defaults documented there.
                // Plain CheckBox with an overridden `contentItem` Label, matching
                // every other checkbox in this section: the Fusion indicator is
                // themed already, only the label colour needs the theme applied.
                RowLayout {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown
                        && traceWindow._connTraceEntries.length > 0
                    spacing: root.uiTheme.spacingMd
                    CheckBox {
                        id: connShowBlockedCheck
                        checked: traceWindow._connShowBlocked
                        text: root.tr("diag.conn-trace.show-blocked", "Show blocked")
                        contentItem: Label {
                            text: connShowBlockedCheck.text
                            leftPadding: connShowBlockedCheck.indicator.width
                                + connShowBlockedCheck.spacing
                            color: root.textColor
                            verticalAlignment: Text.AlignVCenter
                        }
                        Accessible.name: connShowBlockedCheck.text
                        onToggled: {
                            traceWindow._connShowBlocked = checked
                            traceWindow._clearConnSelection()
                        }
                    }
                    CheckBox {
                        id: connShowLocalCheck
                        checked: traceWindow._connShowLocal
                        text: root.tr("diag.conn-trace.show-local",
                            "Show local connections")
                        contentItem: Label {
                            text: connShowLocalCheck.text
                            leftPadding: connShowLocalCheck.indicator.width
                                + connShowLocalCheck.spacing
                            color: root.textColor
                            verticalAlignment: Text.AlignVCenter
                        }
                        Accessible.name: connShowLocalCheck.text
                        ToolTip.visible: connShowLocalCheck.hovered
                        ToolTip.text: root.tr("diag.conn-trace.show-local-tip",
                            "Connections to your own machine or your local network (loopback, link-local, private LAN addresses). They never leave your network, so they say nothing about routing.")
                        onToggled: {
                            traceWindow._connShowLocal = checked
                            traceWindow._clearConnSelection()
                        }
                    }
                    CheckBox {
                        id: connOnlyIpv6Check
                        checked: traceWindow._connOnlyIpv6
                        text: root.tr("diag.conn-trace.only-ipv6", "IPv6 only")
                        contentItem: Label {
                            text: connOnlyIpv6Check.text
                            leftPadding: connOnlyIpv6Check.indicator.width
                                + connOnlyIpv6Check.spacing
                            color: root.textColor
                            verticalAlignment: Text.AlignVCenter
                        }
                        Accessible.name: connOnlyIpv6Check.text
                        ToolTip.visible: connOnlyIpv6Check.hovered
                        ToolTip.text: root.tr("diag.conn-trace.only-ipv6-tip",
                            "Show only connections made over IPv6. They are observed, but routing rules do not apply to that family yet — so these are the connections currently travelling outside your policy. Link-local IPv6 counts as local, so tick \"Show local connections\" as well to see it.")
                        onToggled: {
                            traceWindow._connOnlyIpv6 = checked
                            traceWindow._clearConnSelection()
                        }
                    }
                    // Group the trace rows by process.
                    CheckBox {
                        id: connGroupByProcessCheck
                        checked: traceWindow._connGroupByProcess
                        text: root.tr("diag.conn-trace.group-by-process", "Group by process")
                        contentItem: Label {
                            text: connGroupByProcessCheck.text
                            leftPadding: connGroupByProcessCheck.indicator.width
                                + connGroupByProcessCheck.spacing
                            color: root.textColor
                            verticalAlignment: Text.AlignVCenter
                        }
                        Accessible.name: connGroupByProcessCheck.text
                        onToggled: {
                            traceWindow._connGroupByProcess = checked
                            traceWindow._clearConnSelection()
                        }
                    }
                    Item { Layout.fillWidth: true }
                }

                // 250ms debounce for the connection-trace search field.
                Timer {
                    id: connTraceSearchDebounce
                    interval: 250
                    repeat: false
                    onTriggered: {
                        // Filter the loaded ring only; no drain. The
                        // ≤1000-entry ring is pulled in one large page on open (see
                        // _loadConnTraceEntries), so the client filter already sees the
                        // whole ring without the per-keystroke page-drain that froze
                        // the view (each append rebuilt the render model).
                        traceWindow._connTraceFilter = connTraceSearchField.text
                    }
                }

                // Error state.
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceError !== ""
                    text: traceWindow._connTraceError
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
                // First-load spinner surrogate.
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceLoading && traceWindow._connTraceEntries.length === 0
                    text: root.tr("diag.conn-trace.entries-loading", "Loading connections...")
                    color: root.mutedTextColor
                }
                // Empty state.
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown && !traceWindow._connTraceLoading
                        && traceWindow._connTraceError === ""
                        && traceWindow._connTraceEntries.length === 0
                    text: !traceWindow._connGuiStreamEnabled
                        ? root.tr("diag.conn-trace.gui-stream-off",
                            "Showing the connection trace is switched off in Settings → Diagnostics and logs. Observation itself keeps running.")
                        : traceWindow._connObserverActive
                            ? root.tr("diag.conn-trace.entries-empty",
                                "No connections observed yet")
                            : root.tr("diag.conn-trace.observer-unavailable",
                                "The service is not observing connections right now, so this list stays empty. The service log says why.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // No-match state. Covers the search field AND the two view
                // filters — with "Show blocked" off, an all-blocked trace would
                // otherwise render as a silent empty table.
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceEntries.length > 0
                        && traceWindow._connFiltered.length === 0
                    text: root.tr("diag.conn-trace.entries-no-match",
                        "No connections match the current filters")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }

                // Copy toolbar (TASK A) — see the cache table twin.
                RowLayout {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown && traceWindow._connTraceEntries.length > 0
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.copy-all-shown", "Copy all shown")
                        onClicked: root.copyToClipboard(traceWindow._connRowsTsv())
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: traceWindow._connSelectedCount() > 0
                        text: root.tr("diag.copy-selected", "Copy selected")
                            + " (" + traceWindow._connSelectedCount() + ")"
                        onClicked: traceWindow._copyConnSelected()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown && traceWindow._connTraceEntries.length > 0
                    text: root.tr("diag.table.select-hint",
                        "Click a row to select it (Ctrl+click to toggle, Shift+click to extend), then press Ctrl+C to copy. Right-click for more options.")
                    color: root.mutedTextColor
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    wrapMode: Text.WordWrap
                }

                // Column headers. Each carries a hover tooltip
                // explaining the column; the "Egress" one enumerates every status
                // and states the trace is observation-only (never changes routing).
                RowLayout {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown && traceWindow._connTraceEntries.length > 0
                    spacing: root.uiTheme.spacingSm
                    // Every header is clickable to sort (a `_connSortArrow` suffix
                    // marks the active column) and keeps its explanatory tooltip.
                    // Widths are fixed so the Verdict text — "Blocked (another
                    // program)" is the widest — shows in full by default; each
                    // header elides rather than overlapping its neighbour.
                    Label {
                        id: connHdrProcess
                        Layout.fillWidth: true
                        text: root.tr("diag.conn-trace.col-process", "Process")
                            + traceWindow._connSortArrow("process")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrProcessHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: traceWindow._toggleConnSort("process")
                        }
                        ToolTip.visible: connHdrProcessHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-process-tip",
                            "The application that opened the connection. Hover a row's process name to see its full path.")
                    }
                    Label {
                        id: connHdrRemote
                        Layout.preferredWidth: 150
                        text: root.tr("diag.conn-trace.col-remote", "Remote")
                            + traceWindow._connSortArrow("remote")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrRemoteHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: traceWindow._toggleConnSort("remote")
                        }
                        ToolTip.visible: connHdrRemoteHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-remote-tip",
                            "The destination address and port the connection went to.")
                    }
                    Label {
                        id: connHdrEgress
                        Layout.preferredWidth: 110
                        text: root.tr("diag.conn-trace.col-egress", "Egress")
                            + traceWindow._connSortArrow("egress")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrEgressHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: traceWindow._toggleConnSort("egress")
                        }
                        ToolTip.visible: connHdrEgressHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-egress-tip",
                            "Which network link the connection actually left through: Primary (your main link), Additional (the VPN/secondary link), Loopback (local, never leaves the PC), Other (another adapter), Unknown (couldn't be determined). This is observation only — it never changes routing.")
                    }
                    Label {
                        id: connHdrVerdict
                        Layout.preferredWidth: 180
                        text: root.tr("diag.conn-trace.col-verdict", "Verdict")
                            + traceWindow._connSortArrow("verdict")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrVerdictHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: traceWindow._toggleConnSort("verdict")
                        }
                        ToolTip.visible: connHdrVerdictHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-verdict-tip",
                            "Whether the connection was allowed or dropped. A \"Blocked\" row may be a Windows Firewall or antivirus drop — not necessarily NetRuleRouter.")
                    }
                }

                // The verdict comes from an engine-wide
                // WFP feed with no owner attribution, so a "Blocked" row may be a
                // drop by Windows Firewall or the antivirus, NOT NetRuleRouter.
                // The user saw avp.exe "blocked on primary" and thought NRR broke
                // the AV (HW #4); make the ambiguity explicit.
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown && traceWindow._connTraceEntries.length > 0
                    text: root.tr("diag.conn-trace.verdict-note",
                        "\"Blocked\" means the connection was dropped by a Windows filter — this can be Windows Firewall or your antivirus, not necessarily NetRuleRouter. NetRuleRouter never blocks traffic on your primary route.")
                    color: root.mutedTextColor
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    wrapMode: Text.WordWrap
                }

                // Virtualized list (see the cache table). Group-header and
                // data rows have different heights; ListView handles the variable
                // delegate heights and only builds the visible band, so the open
                // drain no longer eagerly instantiates every row. The viewport
                // height comes from `_connGroupedBuild.height`, which counts those
                // two row shapes as it flattens the model.
                ListView {
                    id: connTraceList
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(traceWindow._listMaxHeight,
                        Math.max(traceWindow._listLineHeight,
                            Number(traceWindow._connGroupedBuild.height || 0)))
                    visible: traceWindow._connTraceShown
                        && traceWindow._connGroupedModel.length > 0
                    clip: true
                    interactive: contentHeight > height
                    ScrollBar.vertical: ScrollBar {
                        policy: connTraceList.contentHeight > connTraceList.height
                            ? ScrollBar.AlwaysOn : ScrollBar.AsNeeded
                    }
                    // TASK A — Ctrl+C copies the selected rows / Escape clears (see
                    // the cache twin). Focus arrives via the row MouseArea.
                    Keys.onPressed: function(event) {
                        if (event.matches(StandardKey.Copy)) {
                            traceWindow._copyConnSelected()
                            event.accepted = true
                        } else if (event.key === Qt.Key_Escape) {
                            traceWindow._clearConnSelection()
                            event.accepted = true
                        }
                    }
                    // Reuse the cached `_connFiltered` (render-capped
                    // to `_renderCap`); `_connGroupedModel` is `_connRendered` when
                    // grouping is off, else the header-interleaved grouped list.
                    model: traceWindow._connTraceShown
                        ? traceWindow._connGroupedModel
                        : []
                    delegate: Item {
                        id: connRowItem
                        width: connTraceList.width
                        // A synthetic group header row vs a real row.
                        readonly property bool _isHeader: !!(modelData && modelData._isGroupHeader)
                        // Decision-vs-actual mismatch: policy expected
                        // this remote to egress the SECONDARY link (its IP belongs
                        // to a secondary rule), yet the flow was PERMITTED out the
                        // primary — i.e. it leaked. Rendered as a red row tint +
                        // red egress cell so a leak is visible at a glance instead
                        // of needing three tools cross-checked by hand (0714 run).
                        readonly property bool _isLeakMismatch: !_isHeader
                            && !!modelData
                            && modelData.expected_route === "secondary"
                            && modelData.egress_role === "primary"
                            && modelData.verdict === "permit"
                        implicitHeight: _isHeader
                            ? connGroupHeader.implicitHeight : connRowCol.implicitHeight
                        Rectangle {
                            visible: connRowItem._isLeakMismatch
                            anchors.fill: parent
                            color: root.uiTheme.colorDanger
                            opacity: 0.08
                            z: -1
                        }
                        // Process key of a synthetic header row; "" for data rows.
                        readonly property string _groupKey: connRowItem._isHeader
                            ? String((modelData && modelData.process) || "") : ""
                        // Reads `root.diagConnGroupExpandRev` through the helper so a
                        // toggle re-evaluates this binding (mirrors the cache table).
                        readonly property bool _groupExpanded: connRowItem._isHeader
                            && traceWindow._isConnGroupExpanded(connRowItem._groupKey)
                        // Group header (shown only for synthetic header items).
                        // Collapsed by default; the whole header row is the click
                        // target, and the leading chevron states which way it goes.
                        Label {
                            id: connGroupHeader
                            visible: connRowItem._isHeader
                            width: parent.width
                            topPadding: root.uiTheme.spacingXs
                            text: (connRowItem._groupExpanded ? "▾ " : "▸ ")
                                + String((modelData && modelData.process) || "—")
                                + "  ·  " + String((modelData && modelData._count) || 0) + " "
                                + root.tr("diag.conn-trace.group-count", "connection(s)")
                            color: root.uiTheme.colorAccent
                            font.bold: true
                            elide: Text.ElideRight
                            Accessible.role: Accessible.Button
                            Accessible.name: connGroupHeader.text
                        }
                        // Header click → expand/collapse. Declared before the data-row
                        // handlers below and gated on `_isHeader`, so the two never
                        // compete for the same delegate.
                        MouseArea {
                            anchors.fill: parent
                            enabled: connRowItem._isHeader
                            acceptedButtons: Qt.LeftButton
                            cursorShape: Qt.PointingHandCursor
                            onClicked: traceWindow._toggleConnGroupExpand(connRowItem._groupKey)
                        }
                        // TASK A — selection state (never for synthetic headers).
                        readonly property bool _selected:
                            !connRowItem._isHeader && traceWindow._connRowSelected(modelData)
                        // Whole-row right-click → copy. TSV so paste keeps columns.
                        readonly property string _rowTsv: traceWindow._connRowTsv(modelData)
                        // TASK A — accent-tinted selection highlight, behind content
                        // (coexists with the leak-mismatch red tint above).
                        Rectangle {
                            visible: connRowItem._selected
                            anchors.fill: parent
                            color: root.uiTheme.colorAccent
                            opacity: 0.14
                            z: -1
                        }
                        // TASK A — left-click row selection (plain / Ctrl / Shift),
                        // disabled on group headers. Under the row content so hover
                        // tooltips still work; grabs focus for the list-level Ctrl+C.
                        MouseArea {
                            anchors.fill: parent
                            enabled: !connRowItem._isHeader
                            acceptedButtons: Qt.LeftButton
                            onPressed: function(mouse) {
                                traceWindow._selectConnRow(
                                    index, modelData,
                                    (mouse.modifiers & Qt.ControlModifier) !== 0,
                                    (mouse.modifiers & Qt.ShiftModifier) !== 0)
                                connTraceList.forceActiveFocus()
                                mouse.accepted = true
                            }
                        }
                        TapHandler {
                            enabled: !connRowItem._isHeader
                            acceptedButtons: Qt.RightButton
                            onTapped: {
                                if (!connRowItem._selected)
                                    traceWindow._selectConnRow(index, modelData, false, false)
                                connTraceList.forceActiveFocus()
                                connRowMenu.popup()
                            }
                        }
                        // Per-column values of this row, for the single-value
                        // copy items below (same columns as `_connRowTsv`).
                        readonly property string _vProcess:
                            String((modelData && modelData.process) || "")
                        readonly property string _vProcessPath:
                            String((modelData && modelData.process_path) || "")
                        readonly property string _vRemote:
                            String((modelData && modelData.remote) || "")
                        readonly property string _vRemoteIp: {
                            var raw = connRowItem._vRemote
                            var at = raw.lastIndexOf(":")
                            var ip = at > 0 ? raw.substring(0, at) : raw
                            return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? ip : ""
                        }
                        readonly property string _vRuleHost:
                            String((modelData && modelData.rule_host) || "")
                        readonly property string _vBlockReason: {
                            var reason = String((modelData && modelData.block_reason) || "")
                            return reason === "" ? ""
                                : root.tr("notifications.block-notice.reason." + reason, "")
                        }
                        readonly property string _vEgress:
                            traceWindow._connEgressLabel(modelData && modelData.egress_role)
                        readonly property string _vVerdict:
                            traceWindow._connVerdictLabel(modelData && modelData.verdict)
                        readonly property string _vProto:
                            traceWindow._connProtoLabel(modelData && modelData.proto)
                        readonly property string _vLocal:
                            String((modelData && modelData.local) || "")
                        readonly property string _vObserved:
                            Pure.formatTimestamp(modelData && modelData.observed_at_ms)
                        Menu {
                            id: connRowMenu
                            MenuItem {
                                visible: connRowItem._vRemoteIp !== ""
                                text: root.tr("diag.conn-trace.rule-for-address",
                                    "Rule for this address…")
                                onTriggered: traceWindow._ruleFromConnRow(
                                    "exact-ip", connRowItem._vRemoteIp)
                            }
                            MenuItem {
                                // Application rules match on the executable
                                // NAME (the file picker reduces a path the same
                                // way), so the row's basename is the value.
                                visible: connRowItem._vProcess !== ""
                                    && connRowItem._vProcess !== "?"
                                text: root.tr("diag.conn-trace.rule-for-app",
                                    "Rule for this application…")
                                onTriggered: traceWindow._ruleFromConnRow(
                                    "application", connRowItem._vProcess)
                            }
                            MenuItem {
                                visible: connRowItem._vRuleHost !== ""
                                    || connRowItem._vRemoteIp !== ""
                                text: root.tr("diag.conn-trace.why-this-route", "Why this route?")
                                onTriggered: traceWindow._explainConnRow(
                                    connRowItem._vRuleHost, connRowItem._vRemoteIp,
                                    connRowItem._vProcess)
                            }
                            MenuSeparator { }
                            MenuItem {
                                text: root.tr("action.copy-row", "Copy row")
                                onTriggered: root.copyToClipboard(connRowItem._rowTsv)
                            }
                            MenuItem {
                                text: root.tr("diag.copy-selected", "Copy selected")
                                visible: traceWindow._connSelectedCount() > 0
                                onTriggered: traceWindow._copyConnSelected()
                            }
                            MenuItem {
                                text: root.tr("diag.copy-all-shown", "Copy all shown")
                                onTriggered: root.copyToClipboard(traceWindow._connRowsTsv())
                            }
                            MenuSeparator { }
                            // Single-column copies — the executable path and the
                            // remote address are what actually gets pasted into
                            // a rule, a search box or a support message.
                            MenuItem {
                                visible: connRowItem._vProcess !== ""
                                text: root.copyValueLabel(connRowItem._vProcess)
                                onTriggered: root.copyToClipboard(connRowItem._vProcess)
                            }
                            MenuItem {
                                visible: connRowItem._vProcessPath !== ""
                                text: root.copyValueLabel(connRowItem._vProcessPath)
                                onTriggered: root.copyToClipboard(connRowItem._vProcessPath)
                            }
                            MenuItem {
                                visible: connRowItem._vRemote !== ""
                                text: root.copyValueLabel(connRowItem._vRemote)
                                onTriggered: root.copyToClipboard(connRowItem._vRemote)
                            }
                            MenuItem {
                                visible: connRowItem._vEgress !== ""
                                text: root.copyValueLabel(connRowItem._vEgress)
                                onTriggered: root.copyToClipboard(connRowItem._vEgress)
                            }
                            MenuItem {
                                visible: connRowItem._vVerdict !== ""
                                text: root.copyValueLabel(connRowItem._vVerdict)
                                onTriggered: root.copyToClipboard(connRowItem._vVerdict)
                            }
                            MenuItem {
                                visible: connRowItem._vProto !== ""
                                text: root.copyValueLabel(connRowItem._vProto)
                                onTriggered: root.copyToClipboard(connRowItem._vProto)
                            }
                            MenuItem {
                                visible: connRowItem._vLocal !== ""
                                text: root.copyValueLabel(connRowItem._vLocal)
                                onTriggered: root.copyToClipboard(connRowItem._vLocal)
                            }
                            MenuItem {
                                visible: connRowItem._vObserved !== ""
                                text: root.copyValueLabel(connRowItem._vObserved)
                                onTriggered: root.copyToClipboard(connRowItem._vObserved)
                            }
                        }
                        ColumnLayout {
                            id: connRowCol
                            visible: !connRowItem._isHeader
                            width: parent.width
                            spacing: 0
                            RowLayout {
                            Layout.fillWidth: true
                            spacing: root.uiTheme.spacingSm
                            Label {
                                id: connProcLabel
                                Layout.fillWidth: true
                                text: String((modelData && modelData.process) || "—")
                                color: root.textColor
                                elide: Text.ElideRight
                                // Full exe path on hover.
                                readonly property string procPath:
                                    String((modelData && modelData.process_path) || "")
                                HoverHandler { id: connProcHover }
                                ToolTip.visible: connProcHover.hovered
                                    && connProcLabel.procPath !== ""
                                ToolTip.text: connProcLabel.procPath
                            }
                            Label {
                                Layout.preferredWidth: 150
                                text: String((modelData && modelData.remote) || "—")
                                color: root.textColor
                                elide: Text.ElideRight
                            }
                            Label {
                                id: connEgressCell
                                Layout.preferredWidth: 110
                                // A leak-mismatch row marks its egress
                                // cell red with a ⚠ and explains itself on hover.
                                text: (connRowItem._isLeakMismatch ? "⚠ " : "")
                                    + traceWindow._connEgressLabel(modelData && modelData.egress_role)
                                color: connRowItem._isLeakMismatch
                                    ? root.uiTheme.colorDanger
                                    : ((modelData && modelData.egress_role === "secondary")
                                        ? root.uiTheme.colorSuccess
                                        : ((modelData && modelData.egress_role === "unknown")
                                            ? root.uiTheme.colorWarning : root.mutedTextColor))
                                elide: Text.ElideRight
                                HoverHandler { id: connEgressHover }
                                ToolTip.visible: connEgressHover.hovered
                                    && connRowItem._isLeakMismatch
                                ToolTip.text: root.tr("diag.conn-trace.leak-mismatch-tip",
                                    "Mismatch: this address belongs to a rule routed to the additional adapter, but the connection was allowed out over the PRIMARY link — a leak indicator.")
                            }
                            Label {
                                // Matches the widened Verdict header (180) so the
                                // full "Blocked (another program)" text is visible.
                                Layout.preferredWidth: 180
                                // A "block" is only shown
                                // as NetRuleRouter's when the drop's WFP filter is
                                // actually ours; a foreign drop (firewall/AV) is
                                // labelled and coloured as such, never as our doing.
                                text: {
                                    if (modelData && modelData.verdict === "block") {
                                        var by = String(modelData.blocked_by || "")
                                        if (by === "netrulerouter")
                                            return root.tr("diag.conn-trace.verdict.block-by-nrr", "Blocked (NetRuleRouter)")
                                        if (by === "other")
                                            return root.tr("diag.conn-trace.verdict.block-by-other", "Blocked (another program)")
                                    }
                                    return traceWindow._connVerdictLabel(modelData && modelData.verdict)
                                }
                                color: {
                                    if (!(modelData && modelData.verdict === "block"))
                                        return root.mutedTextColor
                                    // Our block = danger red; a foreign block =
                                    // warning amber (informational, not our fault).
                                    return (String(modelData.blocked_by || "") === "netrulerouter")
                                        ? root.uiTheme.colorDanger
                                        : root.uiTheme.colorWarning
                                }
                                elide: Text.ElideRight
                                // Which of our filters did it, in the words the
                                // block notice uses.
                                HoverHandler { id: connVerdictHover }
                                ToolTip.visible: connVerdictHover.hovered
                                    && connRowItem._vBlockReason !== ""
                                ToolTip.text: connRowItem._vBlockReason
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            // The relay note is what keeps a fake-IP flow from
                            // reading as the service going out on its own account.
                            text: traceWindow._connProtoLabel(modelData && modelData.proto)
                                + "  ·  " + root.tr("diag.conn-trace.entries-from", "from") + " "
                                + String((modelData && modelData.local) || "—")
                                + "  ·  "
                                + Pure.formatTimestamp(modelData && modelData.observed_at_ms)
                                + (String((modelData && modelData.relay_for) || "") !== ""
                                    ? "  ·  " + root.tr("diag.conn-trace.relay-for", "relay for %1")
                                        .arg(String(modelData.relay_for))
                                    : "")
                            color: root.mutedTextColor
                            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            wrapMode: Text.WordWrap
                        }
                        }
                    }
                }

                // Truncation notice (see cache table). The comparison is against
                // what the render cap actually kept off screen: rows behind a
                // collapsed group are one click away and are NOT truncation, so a
                // fully collapsed trace that fits never raises the notice.
                Label {
                    Layout.fillWidth: true
                    visible: traceWindow._connTraceShown && traceWindow._connDroppedByCap > 0
                    text: root.tr("diag.cache.render-truncated",
                        "Showing the first %1 of %2 matches — refine your search to narrow it.")
                        .arg(traceWindow._connFiltered.length - traceWindow._connDroppedByCap)
                        .arg(traceWindow._connFiltered.length)
                    color: root.uiTheme.colorWarning
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    wrapMode: Text.WordWrap
                }

                // Load-more affordance — present only while a further page exists.
                ThemedButton {
                    theme: root.uiTheme
                    visible: traceWindow._connTraceCursor !== ""
                    enabled: !traceWindow._connTraceLoading
                    text: root.tr("diag.conn-trace.entries-load-more", "Load more")
                    onClicked: traceWindow._loadConnTraceEntries(false)
                }
            }
        }

            Item { Layout.fillHeight: true }
        }
    }
}
