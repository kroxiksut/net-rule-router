import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../components"
import "../theme"
import "../lib/pure.js" as Pure

// FQDN/IP cache: its actions and the entries viewer. The Loader keeps it
// resident once opened, so search and filters survive a trip elsewhere.
ScrollView {

    // Draggable column-resize grip for the cache table header. Sits
    // on the LEFT edge of a fixed-width column; dragging it emits an incremental
    // `widthDelta(dx)` (dx>0 = pointer moved right), which the caller applies as
    // `colW - dx` so dragging the boundary left widens the column to its right
    // (the flex Host column absorbs the difference). Overlay-anchored inside the
    // header cell so it does NOT change the cell's outer layout width — header
    // and body columns stay in register.
    component CacheColHandle: Rectangle {
        id: grip
        signal widthDelta(real dx)
        width: 7
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        color: "transparent"
        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.verticalCenter: parent.verticalCenter
            width: 1
            height: parent.height * 0.7
            color: gripDrag.active
                ? root.uiTheme.colorAccent : root.uiTheme.stateDefaultBorder
        }
        HoverHandler { cursorShape: Qt.SplitHCursor }
        DragHandler {
            id: gripDrag
            target: null
            yAxis.enabled: false
            xAxis.enabled: true
            property real _acc: 0
            onActiveChanged: _acc = 0
            onTranslationChanged: {
                // On release `translation` resets to (0,0); ignore that tick so
                // it can't emit a spurious reverse delta that undoes the resize.
                if (!gripDrag.active)
                    return
                grip.widthDelta(translation.x - _acc)
                _acc = translation.x
            }
        }
    }
    // Host names have no spaces, so the stock tooltip never wraps and runs off
    // the window; it is bounded, wrapped anywhere and clamped inside instead.
    component TruncatedCellLabel: Label {
        id: cell
        elide: Text.ElideRight
        Accessible.role: Accessible.StaticText
        Accessible.name: cell.text
        HoverHandler { id: cellHover }
        ToolTip.visible: cell.truncated && cellHover.hovered
        ToolTip.text: cell.text
        ToolTip.toolTip.width: Math.min(ToolTip.toolTip.implicitWidth,
            root.popupAvailableWidth(cell))
        // `hovered` re-evaluates the position on each hover: columns resize.
        ToolTip.toolTip.x: cellHover.hovered
            ? section._tooltipX(cell, ToolTip.toolTip.width) : 0
        Component.onCompleted: ToolTip.toolTip.contentItem.wrapMode = Text.WrapAnywhere
    }
    id: section
    property var root
    // Centred on `item`, never past the window edges; in `item` coordinates.
    function _tooltipX(item, tipWidth) {
        if (!item || typeof item.mapToItem !== "function")
            return 0
        var winWidth = (item.Window && item.Window.width) || 0
        if (winWidth <= 0)
            return (item.width - tipWidth) / 2
        var margin = 8
        var globalLeft = item.mapToItem(null, 0, 0).x
        var desired = globalLeft + (item.width - tipWidth) / 2
        var clamped = Math.max(margin, Math.min(winWidth - margin - tipWidth, desired))
        return clamped - globalLeft
    }
    clip: true
    Layout.fillWidth: true
    Layout.fillHeight: true
    contentWidth: availableWidth

    Component.onCompleted: {
        section._loadCacheColWidths()
        section._loadCacheEntries(true)
    }
    // Coming back shows what the cache holds now, not what it held then.
    onVisibleChanged: if (visible) section._loadCacheEntries(true)

    property var _cacheEntries: []
    property string _cacheEntriesCursor: ""
    property bool _cacheEntriesLoading: false
    // Bumped by every fresh load. A page that answers for an older generation
    // belongs to a list that has since been reset and is dropped, or a slow
    // answer for one query lands in the list another query started.
    property int _cacheLoadGeneration: 0
    // Is the resolver actually answering with virtual addresses right now? The
    // service stamps `fake_ip` on every cache row from the live allocator, but
    // an allocation left over from a session where the feature WAS on keeps
    // arriving after the toggle is switched off — and a 198.18.x address the
    // resolver no longer hands out reads as a bug, not as history. The row is
    // therefore gated on the live setting rather than on the field's presence.
    // Seeded from the last-known service values mirrored in prefs (so the
    // gate is right before any read completes) and refreshed on every cache
    // load; the shared service-stability config is the authority.
    property bool _fakeIpEnabled: false
    function _refreshFakeIpEnabled() {
        if (typeof root._readServiceMirror === "function") {
            var stability = root._readServiceMirror()["stability"] || {}
            if (stability["fake-ip-enabled"] !== undefined)
                section._fakeIpEnabled = stability["fake-ip-enabled"] === true
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.serviceStabilitySupported || !root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function")
            return
        var corr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok) return
            section._fakeIpEnabled = (payload && payload["fake-ip-enabled"]) === true
            if (typeof root._rememberServiceValues === "function")
                root._rememberServiceValues("stability",
                    { "fake-ip-enabled": section._fakeIpEnabled })
        })
    }
    // Direct row selection for the cache table: rows are picked in the
    // table itself (click = single, Ctrl+click = toggle, Shift+click = extend a
    // range) and copied with Ctrl+C, the right-click "Copy selected" item, or the
    // toolbar button. `_cacheSel` holds the selected GROUP row objects (one per
    // hostname) by reference; because `_cacheFiltered` rebuilds fresh group
    // objects on every filter/sort change, a stale reference simply stops matching
    // the live model — so the selection transparently "clears" when the model
    // changes, with no bookkeeping. All counting/copying/highlighting filters
    // against the LIVE `_cacheRendered`, so a stale reference never leaks in.
    // `_cacheSelAnchor` is the last plain-click index (into `_cacheRendered`) that
    // a Shift+click extends from; `_cacheSelRev` is bumped on every mutation so
    // the delegate/toolbar bindings that read it re-evaluate (a plain array
    // mutation is not tracked — see LESSONS_LEARNED §1).
    property var _cacheSel: []
    property int _cacheSelAnchor: -1
    property int _cacheSelRev: 0
    function _cacheRowSelected(g) {
        return section._cacheSelRev >= 0 && g !== undefined
            && section._cacheSel.indexOf(g) !== -1
    }
    function _cacheSelectedCount() {
        var model = section._cacheRendered
        var n = 0
        for (var i = 0; section._cacheSelRev >= 0 && i < model.length; i++)
            if (section._cacheSel.indexOf(model[i]) !== -1) n++
        return n
    }
    function _selectCacheRow(index, g, ctrl, shift) {
        var model = section._cacheRendered
        if (shift && section._cacheSelAnchor >= 0
                && section._cacheSelAnchor < model.length) {
            var lo = Math.min(section._cacheSelAnchor, index)
            var hi = Math.max(section._cacheSelAnchor, index)
            var next = ctrl ? section._cacheSel.slice() : []
            for (var i = lo; i <= hi; i++) {
                var it = model[i]
                if (it !== undefined && next.indexOf(it) === -1) next.push(it)
            }
            section._cacheSel = next
        } else if (ctrl) {
            var arr = section._cacheSel.slice()
            var at = arr.indexOf(g)
            if (at === -1) arr.push(g); else arr.splice(at, 1)
            section._cacheSel = arr
            section._cacheSelAnchor = index
        } else {
            section._cacheSel = [g]
            section._cacheSelAnchor = index
        }
        section._cacheSelRev++
    }
    function _clearCacheSelection() {
        section._cacheSel = []
        section._cacheSelAnchor = -1
        section._cacheSelRev++
    }
    // Copy every currently-selected row as TSV, in the DISPLAYED order, reusing
    // the per-row `_cacheGroupTsv` helper (one line per address — lossless, and
    // the same format as the right-click "Copy row").
    function _copyCacheSelected() {
        var model = section._cacheRendered
        var lines = []
        for (var i = 0; i < model.length; i++) {
            if (section._cacheSel.indexOf(model[i]) !== -1)
                lines.push(section._cacheGroupTsv(model[i]))
        }
        if (lines.length > 0)
            root.copyToClipboard(lines.join("\n"))
    }
    property bool _cacheEntriesRedacted: false
    property string _cacheEntriesError: ""
    // Live total row count reported by the service (`page.total_count`); -1 =
    // not yet known. Preferred over the cold-start `cacheHealth.entryCount`
    // snapshot, which froze at the mock backend's fixed value (24) when the GUI
    // Started before the service was up.
    property string _cacheEntriesFilter: ""
    // Server-side search term. Sent to `rpcCacheEntriesList` so the
    // service filters the (potentially large) SQLite cache with a WHERE LIKE and
    // returns only matching rows, instead of the client draining the whole cache
    // page-by-page. Host/IP substring match; the localized-label match stays a
    // client-side nicety over the returned rows via `_cacheEntriesFilter`.
    property string _cacheQuery: ""
    // Client-side equality filter on the entry `source` slug,
    // applied ALONGSIDE the free-text filter (AND-combined). "all" disables it.
    // Slugs are kept kebab-case to match the `diag.cache.source.*` locale keys;
    // the predicate normalises the raw DTO value (`_`→`-`) before comparing so
    // it matches whether the backend serialises snake_case or kebab-case.
    property string _cacheSourceFilter: "all"
    // Known cache source slugs (kebab-case) — drives the source-filter combo and
    // reuses the existing `diag.cache.source.<slug>` labels via _cacheSourceLabel.
    readonly property var _cacheSourceSlugs: [
        "all", "dns", "observed-from-traffic", "manual-refresh",
        "imported-seed", "cache-rebuild", "os-cache-seed", "reverse-confirmed",
        "browser-history-seed"
    ]
    // Client-side freshness bucket filter over the loaded rows.
    // "all" disables it; "fresh" = the `fresh` slug only; "stale" = every other
    // slug (stale_usable + stale_not_usable + conflicting + negative_cached).
    property string _cacheFreshnessFilter: "all"
    // Client-side expected-route filter. "all" disables it;
    // "primary"/"secondary" match the entry `expected_route`; "none" = the
    // no-rule rows (empty expected_route).
    property string _cacheRouteFilter: "all"
    // Per-host inline expansion state for the grouped cache table.
    // Keyed by hostname; a host with more than one address collapses to a single
    // display row whose IP cell is clickable to reveal every address. Lives on
    // `root` so it survives switching tabs, not just this section's own
    // lifetime. `diagCacheExpandRev` is bumped on every toggle so the delegate
    // bindings (which read it via `_isCacheExpanded`) re-evaluate — a plain
    // object mutation is not tracked.
    function _toggleCacheExpand(host) {
        var h = String(host || "")
        if (h === "") return
        if (root.diagCacheExpanded[h])
            delete root.diagCacheExpanded[h]
        else
            root.diagCacheExpanded[h] = true
        root.diagCacheExpandRev++
    }
    function _isCacheExpanded(host) {
        return root.diagCacheExpandRev >= 0
            && root.diagCacheExpanded[String(host || "")] === true
    }
    // User-resizable cache-table column widths. PERSISTED via the
    // additive `cacheTableColumnWidths` UI preference (a compact JSON blob):
    // loaded in Component.onCompleted, saved (debounced) when the user drags a
    // column grip. These defaults apply when the pref is empty/malformed.
    // The grouped cache table has five columns:
    //   Host | IP | Source | Route | Freshness (Freshness now merges the old
    // Freshness + Expires into one compact cell: freshness label + remaining TTL,
    // with the full resolved/expires timestamps on hover). The IP column carries
    // the "+N" expansion affordance so it needs a little more room; Freshness is
    // wider to hold "<label> · <ttl>".
    property real _cacheColIpW: 130
    property real _cacheColFreshW: 160
    property real _cacheColSourceW: 150
    property real _cacheColRouteW: 90
    // Host flexes to absorb leftover width but keeps a sane preferred/min so the
    // fixed columns are never starved (it no longer collapses to near-zero).
    property real _cacheColHostW: 200
    readonly property real _cacheColHostMinW: 90
    readonly property real _cacheColMinW: 60
    readonly property real _cacheColMaxW: 420
    // Clamp + parse the persisted `cacheTableColumnWidths` blob into the three
    // width props. Guards an empty/malformed blob → keeps the defaults above.
    function _loadCacheColWidths() {
        var raw = (root.prefs && root.prefs.cacheTableColumnWidths) || ""
        if (!raw)
            return
        try {
            var obj = JSON.parse(raw)
            if (!obj || typeof obj !== "object")
                return
            // Column set changed with the grouping restructure (the
            // Expires column merged into Freshness). A pre-v2 blob carries the old
            // key set → ignore it entirely and keep the new defaults rather than
            // half-applying stale widths.
            if (obj.v !== 2)
                return
            function clampW(v, fallback) {
                if (typeof v !== "number" || !isFinite(v))
                    return fallback
                return Math.max(section._cacheColMinW,
                    Math.min(section._cacheColMaxW, v))
            }
            section._cacheColIpW = clampW(obj.ip, section._cacheColIpW)
            section._cacheColFreshW = clampW(obj.freshness, section._cacheColFreshW)
            section._cacheColSourceW = clampW(obj.source, section._cacheColSourceW)
            section._cacheColRouteW = clampW(obj.route, section._cacheColRouteW)
        } catch (e) {
            // Malformed blob — keep the current (default) widths.
        }
    }
    // Persist the current three widths as a compact JSON string. Debounced via
    // cacheColPersistDebounce so a drag emits one prefs round-trip on settle,
    // not one per pixel.
    function _persistCacheColWidths() {
        root.updatePrefs({ cacheTableColumnWidths: JSON.stringify({
            v: 2,
            ip: Math.round(section._cacheColIpW),
            freshness: Math.round(section._cacheColFreshW),
            source: Math.round(section._cacheColSourceW),
            route: Math.round(section._cacheColRouteW)
        }) })
        root.emitPrefs()
    }
    Timer {
        id: cacheColPersistDebounce
        interval: 400
        repeat: false
        onTriggered: section._persistCacheColWidths()
    }
    // Shared guard for the cache-clear buttons: verifies the native bridge is
    // reachable, setting a localized status line and returning false otherwise.
    property var _cacheFlatFiltered: _filterCacheEntries(
        _cacheEntries, _cacheEntriesFilter, _cacheSourceFilter,
        _cacheFreshnessFilter, _cacheRouteFilter)
    // With no user-chosen sort column, direct rule matches
    // (exact-fqdn / subdomain / exact-ip) rank above zone-derived entries;
    // clicking any column header replaces this default ordering entirely.
    property var _cacheFiltered: _cacheSortCol
        ? _sortRows(_groupCacheRows(_cacheFlatFiltered),
            "cache", _cacheSortCol, _cacheSortDir)
        : _cacheDefaultOrder(_groupCacheRows(_cacheFlatFiltered))
    // Bound the filter-driven page drain so searching for a term NOT in
    // the cache can't freeze the form: without a cap `_loadCacheEntries` recursed
    // through EVERY page (O(n²) filter re-eval per append) on a miss. Search now
    // covers up to this many entries; a larger cache would need server-side search.
    readonly property int _cacheDrainCap: 2000

    function _cacheFreshnessLabel(slug) {
        // Backend freshness slugs are snake_case (`stale_usable`); locale
        // key segments must be kebab-case. Convert for the lookup, keep the
        // raw slug as the display fallback.
        var s = String(slug || "").replace(/_/g, "-")
        return root.tr("diag.cache.freshness." + s, String(slug || ""))
    }
    function _cacheSourceLabel(slug) {
        var s = String(slug || "").replace(/_/g, "-")
        return root.tr("diag.cache.source." + s, String(slug || ""))
    }
    function _cacheCompactExpiry(ms) {
        var n = Number(ms || 0)
        if (!isFinite(n) || n <= 0) return "—"
        var diff = n - Date.now()
        if (diff <= 0) return root.tr("diag.cache.ttl.expired", "expired")
        var mins = Math.max(1, Math.floor(diff / 60000))
        if (mins < 60) return String(mins) + " " + root.tr("diag.cache.ttl.min", "m")
        var hrs = Math.floor(mins / 60)
        if (hrs < 24) return String(hrs) + " " + root.tr("diag.cache.ttl.hour", "h")
        return String(Math.floor(hrs / 24)) + " " + root.tr("diag.cache.ttl.day", "d")
    }
    // Freshness ordering used to pick a group's "best" (freshest) representative
    // entry: lower rank = fresher. Unknown slugs sort last.
    function _cacheFreshnessRank(slug) {
        var s = String(slug || "").replace(/_/g, "-")
        if (s === "fresh") return 0
        if (s === "stale-usable") return 1
        if (s === "conflicting") return 2
        if (s === "stale-not-usable") return 3
        if (s === "negative-cached") return 4
        return 5
    }
    // Group the flat (hostname, ip) rows into one display row per
    // hostname. Each group carries every address (`ips`, drives the inline
    // expansion), the first address for the collapsed IP cell, the distinct
    // source slugs, the first non-empty expected route, and the BEST (freshest,
    // then latest-expiring) entry's freshness/expiry for the merged cell.
    function _groupCacheRows(list) {
        var byHost = ({})
        var order = []
        for (var i = 0; i < list.length; i++) {
            var e = list[i] || {}
            var host = String(e.hostname || "")
            if (byHost[host] === undefined) { byHost[host] = []; order.push(host) }
            byHost[host].push(e)
        }
        var out = []
        for (var k = 0; k < order.length; k++)
            out.push(section._buildCacheGroup(order[k], byHost[order[k]]))
        return out
    }
    function _buildCacheGroup(host, entries) {
        var seen = ({})
        var sources = []
        var route = ""
        var fakeIp = ""
        var best = entries[0] || {}
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i] || {}
            var s = String(e.source || "")
            if (s !== "" && seen[s] === undefined) { seen[s] = true; sources.push(s) }
            if (route === "") {
                var r = String(e.expected_route || "")
                if (r !== "") route = r
            }
            if (fakeIp === "") {
                var f = String(e.fake_ip || "")
                if (f !== "") fakeIp = f
            }
            var rb = section._cacheFreshnessRank(e.freshness)
            var rBest = section._cacheFreshnessRank(best.freshness)
            if (rb < rBest
                    || (rb === rBest
                        && Number(e.expires_at_ms || 0) > Number(best.expires_at_ms || 0)))
                best = e
        }
        // Strongest address-rule kind across the group's entries
        // (service stamps `rule_match_kind` per row; see CacheEntryDto).
        var kindRank = 3
        var kind = ""
        for (var m = 0; m < entries.length; m++) {
            var kr = section._cacheMatchKindRank(entries[m].rule_match_kind)
            if (kr < kindRank) { kindRank = kr; kind = String(entries[m].rule_match_kind || "") }
        }
        return {
            "_isGroup": true,
            "hostname": host,
            "ips": entries,
            "ip": String((entries[0] && entries[0].ip) || ""),
            "ipCount": entries.length,
            "sourceSlugs": sources,
            "expected_route": route,
            "rule_match_kind": kind,
            "fake_ip": fakeIp,
            "best_freshness": best.freshness,
            "best_expires_at_ms": best.expires_at_ms,
            "best_resolved_at_ms": best.resolved_at_ms
        }
    }
    // Default-ordering tier of an address-rule match kind: direct
    // matches (0) above zone-derived (1) above no-rule/unknown (2).
    function _cacheMatchKindRank(kind) {
        var k = String(kind || "")
        if (k === "exact-fqdn" || k === "subdomain" || k === "exact-ip") return 0
        if (k === "zone") return 1
        return 2
    }
    // The default cache ordering (active while no sort column is
    // chosen): direct rule matches first, zone matches below, no-rule entries
    // last; ties keep the backend's page order (explicit index tie-break — the
    // JS engine's sort stability is not relied upon).
    function _cacheDefaultOrder(list) {
        var decorated = []
        for (var i = 0; i < list.length; i++)
            decorated.push({ "row": list[i], "idx": i })
        decorated.sort(function(a, b) {
            var ra = section._cacheMatchKindRank(a.row.rule_match_kind)
            var rb = section._cacheMatchKindRank(b.row.rule_match_kind)
            if (ra !== rb) return ra - rb
            return a.idx - b.idx
        })
        var out = []
        for (var k = 0; k < decorated.length; k++) out.push(decorated[k].row)
        return out
    }
    // Distinct source labels of a group joined on one line (elided in the cell).
    function _cacheGroupSourceLabel(g) {
        var slugs = (g && g.sourceSlugs) || []
        if (slugs.length === 0) return "—"
        var parts = []
        for (var i = 0; i < slugs.length; i++)
            parts.push(section._cacheSourceLabel(slugs[i]))
        return parts.join(", ")
    }
    // Full resolved/expires timestamps for the merged Freshness cell's hover
    // tooltip (reuses the existing `entries-resolved` / `entries-expires` keys).
    function _cacheExpiryTooltip(resolvedMs, expiresMs) {
        return root.tr("diag.cache.entries-resolved", "resolved") + ": "
            + Pure.formatTimestamp(resolvedMs) + "\n"
            + root.tr("diag.cache.entries-expires", "expires") + ": "
            + Pure.formatTimestamp(expiresMs)
    }
    // TSV for one grouped row: one line per address so a per-row copy stays
    // lossless (columns match the flat "copy all shown" export).
    function _cacheGroupTsv(g) {
        var ips = (g && g.ips) || []
        var lines = []
        for (var i = 0; i < ips.length; i++) {
            var e = ips[i] || {}
            lines.push([
                String((g && g.hostname) || ""),
                String(e.ip || ""),
                section._cacheSourceLabel(e.source),
                section._cacheRouteLabel(e),
                section._cacheFreshnessLabel(e.freshness),
                Pure.formatTimestamp(e.expires_at_ms)
            ].join("\t"))
        }
        return lines.join("\n")
    }

    // The cache Route column mirrors the connection-trace "expected route"
    // (field `expected_route`, values "primary"/"secondary"). The backend does
    // NOT emit it on cache entries yet, so it is absent today → show an em-dash.
    // Label resolution reuses the conn-trace primary/secondary resolver
    // (`_connEgressLabel` → `diag.conn-trace.egress.<slug>`); no new locale keys.
    function _cacheRouteLabel(e) {
        var r = String((e && e.expected_route) || "")
        if (r === "") return "—"
        return root.connEgressLabel(r)
    }

    // Clickable-header sort state for the cache and connection-trace
    // tables. `col` is a column id ("" = natural/insertion order); `dir` is +1
    // ascending / -1 descending. Clicking a header sorts that column ascending;
    // clicking the same header again toggles the direction. Applied where the
    // filtered row arrays are built (`_cacheFiltered` / `_connFiltered`), so the
    // ListView, the grouped model, the TSV copy and the select-mode text view all
    // follow the sorted order. Header text bindings read the arrow helpers, so a
    // sort-state change re-evaluates the label (property reads are tracked).
    property string _cacheSortCol: ""
    property int _cacheSortDir: 1
    function _isNumericSortCol(table, col) {
        return table === "cache" && col === "expires"
    }
    // The value a row contributes to the sort for a column — the SAME text the
    // cell renders (or the raw timestamp for the numeric Expires column), so the
    // resulting order matches the column the user clicked.
    function _sortKey(table, col, e) {
        if (table === "cache") {
            // `e` is a GROUPED display row (see _buildCacheGroup): sort by the
            // same text each cell renders (joined sources, best-entry freshness).
            if (col === "host") return String((e && e.hostname) || "")
            if (col === "ip") return String((e && e.ip) || "")
            if (col === "source") return section._cacheGroupSourceLabel(e)
            if (col === "route") return section._cacheRouteLabel(e)
            if (col === "freshness") return section._cacheFreshnessLabel(e && e.best_freshness)
            return ""
        }
        if (col === "process") return String((e && e.process) || "")
        if (col === "remote") return String((e && e.remote) || "")
        return ""
    }
    // Return a NEW sorted array; never mutate the caller's list — `_filterCache*`
    // may hand back the live `_cacheEntries` reference when no filter is active.
    function _sortRows(list, table, col, dir) {
        if (!col || !dir) return list
        var numeric = section._isNumericSortCol(table, col)
        var arr = list.slice()
        arr.sort(function(a, b) {
            var va = section._sortKey(table, col, a)
            var vb = section._sortKey(table, col, b)
            var r
            if (numeric) {
                r = Number(va) - Number(vb)
            } else {
                va = String(va).toLowerCase()
                vb = String(vb).toLowerCase()
                r = va < vb ? -1 : (va > vb ? 1 : 0)
            }
            return r * dir
        })
        return arr
    }
    function _toggleCacheSort(col) {
        if (section._cacheSortCol === col)
            section._cacheSortDir = -section._cacheSortDir
        else { section._cacheSortCol = col; section._cacheSortDir = 1 }
    }
    function _cacheSortArrow(col) {
        if (section._cacheSortCol !== col) return ""
        return section._cacheSortDir < 0 ? " ▼" : " ▲"
    }
    function _cacheRowBlob(e) {
        if (e && e._blob !== undefined) return e._blob
        var b = [
            String((e && e.hostname) || ""),
            String((e && e.ip) || ""),
            section._cacheSourceLabel(e && e.source),
            section._cacheRouteLabel(e),
            section._cacheFreshnessLabel(e && e.freshness),
            Pure.formatTimestamp(e && e.expires_at_ms)
        ].join(" ").toLowerCase()
        if (e) e._blob = b
        return b
    }

    // All-field client-side filter: hostname, IP, the localized freshness and
    // source labels, and both formatted timestamps. Case-insensitive substring
    // match. A second, AND-combined predicate matches the entry `source` slug
    // exactly (kebab-normalised) when `sourceSlug` is not "all". Passing
    // `entries`/`query`/`sourceSlug` as arguments keeps the binding reactive
    // (all reads happen in the binding scope).
    function _filterCacheEntries(entries, query, sourceSlug, freshnessBucket, routeSlug) {
        var q = String(query || "").trim().toLowerCase()
        var src = String(sourceSlug || "all")
        var fresh = String(freshnessBucket || "all")
        var route = String(routeSlug || "all")
        if (q === "" && src === "all" && fresh === "all" && route === "all")
            return entries
        var out = []
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i] || {}
            if (src !== "all") {
                var es = String((e && e.source) || "").replace(/_/g, "-")
                if (es !== src) continue
            }
            if (fresh !== "all") {
                // "fresh" = the `fresh` slug only; "stale" = every other slug
                // (stale_usable + stale_not_usable + conflicting + negative_cached).
                var fs = String((e && e.freshness) || "").replace(/_/g, "-")
                var isFresh = fs === "fresh"
                if (fresh === "fresh" && !isFresh) continue
                if (fresh === "stale" && isFresh) continue
            }
            if (route !== "all") {
                var r = String((e && e.expected_route) || "")
                // "ipv6" is not a route the user can pick — it means no rule
                // CAN cover the row, so it belongs with the no-rule bucket
                // rather than vanishing from every filter.
                if (route === "none") { if (r !== "" && r !== "ipv6") continue }
                else if (r !== route) continue
            }
            if (q !== "" && section._cacheRowBlob(e).indexOf(q) === -1) continue
            out.push(e)
        }
        return out
    }

    // Clipboard export for the read-only cache/trace
    // viewers. Reuses the existing C++ `copyToClipboard` bridge (same one the
    // Logs section uses). "Copy all shown" serialises the currently-filtered
    // rows as TSV so a paste into a spreadsheet keeps the columns.
    function _cacheGroupIps(g) {
        var ips = (g && g.ips) || []
        var out = []
        for (var i = 0; i < ips.length; i++) {
            var value = String((ips[i] && ips[i].ip) || "")
            if (value !== "" && out.indexOf(value) === -1) out.push(value)
        }
        return out.join(", ")
    }
    function _cacheRowsTsv() {
        // Export the FLAT filtered rows (one line per address) so "copy all shown"
        // stays lossless even though the table collapses addresses per host.
        var list = section._cacheFlatFiltered
        var lines = []
        for (var i = 0; i < list.length; i++) {
            var e = list[i] || {}
            lines.push([
                String(e.hostname || ""),
                String(e.ip || ""),
                section._cacheSourceLabel(e.source),
                section._cacheRouteLabel(e),
                section._cacheFreshnessLabel(e.freshness),
                Pure.formatTimestamp(e.expires_at_ms)
            ].join("\t"))
        }
        return lines.join("\n")
    }
    function _loadCacheEntries(reset) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCacheEntriesList !== "function") {
            section._cacheEntriesError = root.tr("diag.cache.entries-bridge-unavailable",
                "Service bridge not connected — cache entries unavailable")
            return
        }
        if (reset) {
            section._cacheLoadGeneration += 1
            section._cacheEntries = []
            section._cacheEntriesCursor = ""
            // Re-read the virtual-address setting alongside the first page so
            // the fake-IP rows appear/disappear with the live service state.
            section._refreshFakeIpEnabled()
        }
        section._cacheEntriesLoading = true
        section._cacheEntriesError = ""
        var cursor = reset ? "" : section._cacheEntriesCursor
        // Pass the server-side search term so a large cache is
        // filtered in SQLite (WHERE LIKE) rather than drained page-by-page.
        var generation = section._cacheLoadGeneration
        var corr = nrrNativeBridge.rpcCacheEntriesList(cursor, 50, section._cacheQuery)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (generation !== section._cacheLoadGeneration) return
            section._cacheEntriesLoading = false
            if (!ok) {
                section._cacheEntriesError = root.tr("diag.cache.entries-failed",
                    "Failed to load cache entries: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            var page = (payload && payload.page) || {}
            var items = page.items || []
            section._cacheEntriesRedacted = (payload && payload.redacted) === true
            if (page.total_count !== undefined && page.total_count !== null)
                root.diagCacheEntriesTotal = Number(page.total_count)
            var merged = section._cacheEntries.slice()
            for (var i = 0; i < items.length; i++)
                merged.push(items[i])
            section._cacheEntries = merged
            var nc = page.next_cursor
            section._cacheEntriesCursor =
                (nc === undefined || nc === null) ? "" : String(nc)
            // The filter-driven page DRAIN was removed. It fetched
            // page after page on a search and each append rebuilt the render model,
            // freezing the form. Full-cache search is now server-side (the `query`
            // passed to rpcCacheEntriesList); "Load more" paginates the matches.
        })
    }

    readonly property int _renderCap: 400
    // Viewport sizing for the virtualized table below. Its height is
    // derived from the MODEL, never from their own `contentHeight`: a ListView
    // only builds the delegates that fit its current height, so a height bound to
    // contentHeight is circular and can settle on a sliver of the real table.
    // Short lists stay compact; longer ones stop at the cap and scroll inside.
    readonly property int _listMaxHeight: 460
    // One text line at the current base font size, so a larger accessibility text
    // scale grows the viewport instead of clipping it.
    readonly property int _listLineHeight:
        Math.max(20, Math.round(root.uiTheme.baseFontSizePx * 1.7))
    property var _cacheRendered: (_cacheFiltered.length > _renderCap)
        ? _cacheFiltered.slice(0, _renderCap) : _cacheFiltered
    // Height estimate of the rendered cache table: one line per host row, one
    // more when a fake-IP mapping is shown, plus one per address while the host
    // is expanded (`_isCacheExpanded` reads `root.diagCacheExpandRev`, so a
    // toggle re-evaluates this).
    readonly property int _cacheRenderedHeight: {
        var rows = section._cacheRendered
        var lines = 0
        for (var i = 0; i < rows.length; i++) {
            var g = rows[i] || {}
            lines += 1
            if (section._fakeIpEnabled && String(g.fake_ip || "") !== "") lines += 1
            if (section._isCacheExpanded(g.hostname)) lines += Number(g.ipCount || 0)
        }
        return lines * section._listLineHeight
    }
    ColumnLayout {
        width: section.availableWidth
        spacing: root.uiTheme.spacingMd
        // Cache actions: clear, flush, seed from browser history.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                Label {
                    text: root.tr("diag.cache.title", "Cache")
                    color: root.textColor
                    font.bold: true
                }
                // RightToLeft: buttons are declared in reverse reading order.
                Flow {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    layoutDirection: Qt.RightToLeft
                    // Seed the FQDN/IP cache from the local browser history.
                    // Runs on demand by explicit user consent — the service
                    // resolves ONLY hosts that match the user's rules (privacy
                    // boundary), filling the gap for sites visited before the
                    // service ran.
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.cache.seed-browser-history.button",
                            "Seed cache from browser history")
                        onClicked: {
                            if (!root.bridgeReadyOrWarn())
                                return
                            var corr = nrrNativeBridge.rpcSeedFromBrowserHistory()
                            root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
                                if (!ok) {
                                    root.statusLine = root.tr("diag.cache.seed-browser-history.unavailable",
                                        "This feature is unavailable.") + " "
                                        + ((typeof root.ipcErrorLabel === "function")
                                            ? root.ipcErrorLabel(String(errorCode || "unknown"))
                                            : String(errorCode || "unknown"))
                                    return
                                }
                                root.statusLine = (payload && payload["started"] === true)
                                    ? root.tr("diag.cache.seed-browser-history.started",
                                        "Import started — hosts matching your rules will appear in the cache.")
                                    : (payload && payload["already-running"] === true)
                                        ? root.tr("diag.cache.seed-browser-history.already-running",
                                            "Your previous import is still running — hosts matching your rules will appear in the cache when it finishes.")
                                        : root.tr("diag.cache.seed-browser-history.unavailable",
                                            "This feature is unavailable.")
                                // Newly-seeded entries show up as "Browser history".
                                section._loadCacheEntries(true)
                            })
                        }
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.cache.clear-os-dns-button", "Clear OS DNS cache")
                        onClicked: {
                            // Flushes the OS DNS resolver cache only; the app's
                            // FQDN/IP cache is left untouched.
                            if (!root.bridgeReadyOrWarn())
                                return
                            var corr = nrrNativeBridge.rpcCacheClear({ "clear-app-cache": false, "flush-os-cache": true })
                            root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
                                if (!ok) {
                                    root.statusLine = root.tr("status.cache-cleared-failed",
                                        "Failed to clear cache: ") + ((typeof root.ipcErrorLabel === "function")
                                            ? root.ipcErrorLabel(String(errorCode || "unknown"))
                                            : String(errorCode || "unknown"))
                                    return
                                }
                                // `os-cache-flushed` is true/false/null — true only
                                // when the OS flush actually ran and succeeded.
                                root.statusLine = (payload && payload["os-cache-flushed"] === true)
                                    ? root.tr("diag.cache.os-flush-ok", "OS DNS cache flushed.")
                                    : root.tr("diag.cache.os-flush-failed", "Could not flush the OS DNS cache.")
                            })
                        }
                    }
                    // Cache clearing split into two independent
                    // actions: the app's rebuildable FQDN/IP cache, and the OS
                    // DNS resolver cache. Each drives the same cache.clear RPC
                    // with a different flag set.
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.cache.clear-app-button", "Clear app cache")
                        onClicked: {
                            // Clears the rebuildable FQDN/IP cache; audit/state
                            // DBs untouched. OS DNS cache left alone.
                            if (!root.bridgeReadyOrWarn())
                                return
                            var corr = nrrNativeBridge.rpcCacheClear({ "clear-app-cache": true, "flush-os-cache": false })
                            root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
                                if (!ok) {
                                    root.statusLine = root.tr("status.cache-cleared-failed",
                                        "Failed to clear cache: ") + ((typeof root.ipcErrorLabel === "function")
                                            ? root.ipcErrorLabel(String(errorCode || "unknown"))
                                            : String(errorCode || "unknown"))
                                    return
                                }
                                var removed = Number((payload && payload["resolutions-removed"]) || 0)
                                root.statusLine = root.tr("status.cache-cleared",
                                    "Cache cleared: {count} resolution(s) removed.")
                                    .replace("{count}", String(removed))
                                section._loadCacheEntries(true)
                            })
                        }
                    }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.cache.seed-browser-history.note",
                        "Resolves hosts from your browser history that match your rules (closes the gap for sites visited before the service started). Privacy: only names matching your rules are processed.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                }
                // Per-user, off by default; the manual button works regardless.
                CheckBox {
                    id: browserHistoryAutoSeedCheckbox
                    text: root.tr("diag.cache.auto-seed-label",
                        "Seed the cache from browser history automatically at service start")
                    checked: root.uiRevision >= 0
                        ? (root.routingState
                           && root.routingState.browserHistoryAutoSeed === true)
                        : false
                    onToggled: root.routePolicyController.applyBrowserHistoryAutoSeed(checked)
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                }
                // What the automatic variant reads, and that it sends nothing.
                Label {
                    Layout.fillWidth: true
                    Layout.leftMargin: root.uiTheme.spacingMd
                    text: root.tr("diag.cache.auto-seed-privacy-note",
                        "Only visited hostnames are read from local browser profiles — nothing is sent anywhere.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                }
            }
        }
        // Cache entries viewer (read-only, populated on demand)
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs

                Label {
                    text: root.tr("diag.cache.entries-title", "Cache entries")
                    color: root.textColor
                    font.bold: true
                }

                // Search + hide controls (restored . The search
                // field drives the all-field client-side filter; typing while
                // a page cursor remains drains the rest of the cache so the
                // filter sees every entry, not just the first loaded page.
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedTextField {
                        id: cacheSearchField
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        visible: section._cacheEntries.length > 0
                            || section._cacheEntriesFilter !== ""
                        placeholderText: root.tr("diag.cache.entries-search-placeholder",
                            "Exact name or IP; *.search.example — subdomains; *google* — any match")
                        // Debounce so a single keystroke no longer runs
                        // an O(n) filter + full row rebuild + a recursive page
                        // drain. cacheSearchDebounce applies the filter and drains
                        // the remaining pages once, after typing settles.
                        onTextChanged: cacheSearchDebounce.restart()
                    }
                }

                // Client-side filter row (freshness / route / source),
                // AND-combined with the free-text search above and applied over the
                // already-loaded rows. Each is a ThemedComboBox with an explicit
                // displayText; the source filter reuses the diag.cache.source.* labels,
                // the route filter reuses the conn-trace egress labels for
                // primary/secondary.
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    visible: section._cacheEntries.length > 0
                        || section._cacheEntriesFilter !== ""
                        || section._cacheSourceFilter !== "all"
                        || section._cacheFreshnessFilter !== "all"
                        || section._cacheRouteFilter !== "all"
                    ThemedComboBox {
                        id: cacheFreshnessFilterCombo
                        theme: root.uiTheme
                        implicitWidth: 180
                        model: ["all", "fresh", "stale"]
                        function freshnessFilterLabel(slug) {
                            if (slug === "fresh")
                                return root.tr("diag.cache.freshness-filter.fresh", "Fresh")
                            if (slug === "stale")
                                return root.tr("diag.cache.freshness-filter.stale", "Stale")
                            return root.tr("diag.cache.freshness-filter.all", "Any freshness")
                        }
                        labelResolver: function(item) {
                            return cacheFreshnessFilterCombo.freshnessFilterLabel(item)
                        }
                        currentIndex: 0
                        Component.onCompleted: cacheFreshnessFilterCombo.displayText =
                            cacheFreshnessFilterCombo.freshnessFilterLabel(model[currentIndex])
                        popup.width: root.comboPopupWidth(cacheFreshnessFilterCombo, model, "",
                            function(item) { return cacheFreshnessFilterCombo.freshnessFilterLabel(item) })
                        onActivated: {
                            section._cacheFreshnessFilter = model[currentIndex]
                            cacheFreshnessFilterCombo.displayText =
                                cacheFreshnessFilterCombo.freshnessFilterLabel(model[currentIndex])
                        }
                        Connections {
                            target: root
                            function onUiRevisionChanged() {
                                if (!cacheFreshnessFilterCombo) return
                                cacheFreshnessFilterCombo.displayText =
                                    cacheFreshnessFilterCombo.freshnessFilterLabel(
                                        cacheFreshnessFilterCombo.model[cacheFreshnessFilterCombo.currentIndex])
                            }
                        }
                    }
                    ThemedComboBox {
                        id: cacheRouteFilterCombo
                        theme: root.uiTheme
                        implicitWidth: 180
                        model: ["all", "primary", "secondary", "none"]
                        function routeFilterLabel(slug) {
                            if (slug === "primary")
                                return root.connEgressLabel("primary")
                            if (slug === "secondary")
                                return root.connEgressLabel("secondary")
                            if (slug === "none")
                                return root.tr("diag.cache.route-filter.none", "No rule")
                            return root.tr("diag.cache.route-filter.all", "All routes")
                        }
                        labelResolver: function(item) {
                            return cacheRouteFilterCombo.routeFilterLabel(item)
                        }
                        currentIndex: 0
                        Component.onCompleted: cacheRouteFilterCombo.displayText =
                            cacheRouteFilterCombo.routeFilterLabel(model[currentIndex])
                        popup.width: root.comboPopupWidth(cacheRouteFilterCombo, model, "",
                            function(item) { return cacheRouteFilterCombo.routeFilterLabel(item) })
                        onActivated: {
                            section._cacheRouteFilter = model[currentIndex]
                            cacheRouteFilterCombo.displayText =
                                cacheRouteFilterCombo.routeFilterLabel(model[currentIndex])
                        }
                        Connections {
                            target: root
                            function onUiRevisionChanged() {
                                if (!cacheRouteFilterCombo) return
                                cacheRouteFilterCombo.displayText =
                                    cacheRouteFilterCombo.routeFilterLabel(
                                        cacheRouteFilterCombo.model[cacheRouteFilterCombo.currentIndex])
                            }
                        }
                    }
                    ThemedComboBox {
                        id: cacheSourceFilterCombo
                        theme: root.uiTheme
                        implicitWidth: 200
                        model: section._cacheSourceSlugs
                        function sourceFilterLabel(slug) {
                            if (slug === "all")
                                return root.tr("diag.cache.source-filter.all", "All sources")
                            return section._cacheSourceLabel(slug)
                        }
                        labelResolver: function(item) {
                            return cacheSourceFilterCombo.sourceFilterLabel(item)
                        }
                        currentIndex: 0
                        Component.onCompleted: cacheSourceFilterCombo.displayText =
                            cacheSourceFilterCombo.sourceFilterLabel(model[currentIndex])
                        popup.width: root.comboPopupWidth(cacheSourceFilterCombo, model, "",
                            function(item) { return cacheSourceFilterCombo.sourceFilterLabel(item) })
                        onActivated: {
                            section._cacheSourceFilter = model[currentIndex]
                            cacheSourceFilterCombo.displayText =
                                cacheSourceFilterCombo.sourceFilterLabel(model[currentIndex])
                        }
                        Connections {
                            target: root
                            function onUiRevisionChanged() {
                                if (!cacheSourceFilterCombo) return
                                cacheSourceFilterCombo.displayText =
                                    cacheSourceFilterCombo.sourceFilterLabel(
                                        cacheSourceFilterCombo.model[cacheSourceFilterCombo.currentIndex])
                            }
                        }
                    }
                    Item { Layout.fillWidth: true }
                }

                // 250ms debounce for the cache search field.
                Timer {
                    id: cacheSearchDebounce
                    interval: 250
                    repeat: false
                    onTriggered: {
                        // Filter the already-loaded rows only. The
                        // per-keystroke full-cache DRAIN was removed: it re-fetched
                        // page after page and each append built a fresh render array,
                        // rebuilding up to _renderCap delegates ~40× — the freeze the
                        // render/drain caps didn't cover. Full-cache coverage now
                        // comes from the server-side `query` fetch (rpcCacheEntriesList),
                        // not a client drain.
                        // The server query understands the `*` wildcard
                        // syntax; the client-side nicety filter is a plain
                        // substring over the rendered cells and would treat
                        // the literal asterisks as text (no cell contains
                        // one), silently hiding every server-matched row.
                        // Strip them before the client pass.
                        section._cacheEntriesFilter =
                            cacheSearchField.text.split("*").join("").trim()
                        section._cacheQuery = cacheSearchField.text.trim()
                        section._loadCacheEntries(true)
                    }
                }

                // Privacy notice — compact tier reduces hostnames/IPs.
                Label {
                    Layout.fillWidth: true
                    visible: section._cacheEntriesRedacted && section._cacheEntries.length > 0
                    text: root.tr("diag.cache.entries-redacted-notice",
                        "Hostnames and IPs are reduced for privacy. Enable Extended diagnostics for full detail.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }

                // Error state.
                Label {
                    Layout.fillWidth: true
                    visible: section._cacheEntriesError !== ""
                    text: section._cacheEntriesError
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }

                // First-load spinner surrogate.
                Label {
                    Layout.fillWidth: true
                    visible: section._cacheEntriesLoading && section._cacheEntries.length === 0
                    text: root.tr("diag.cache.entries-loading", "Loading cache entries...")
                    color: root.mutedTextColor
                }

                // Empty state.
                Label {
                    Layout.fillWidth: true
                    visible: !section._cacheEntriesLoading
                        && section._cacheEntriesError === ""
                        && section._cacheEntries.length === 0
                    text: root.tr("diag.cache.entries-empty", "No cache entries")
                    color: root.mutedTextColor
                }

                // No-match state — filter active, entries exist, none match.
                Label {
                    Layout.fillWidth: true
                    visible: !section._cacheEntriesLoading
                        && section._cacheEntriesError === ""
                        && section._cacheEntries.length > 0
                        && section._cacheFiltered.length === 0
                    text: root.tr("diag.cache.entries-no-match",
                        "No entries match your search")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }

                // Copy toolbar for in-table row selection: rows are picked
                // in the table itself and copied with Ctrl+C, the right-click
                // menu, or these buttons.
                RowLayout {
                    Layout.fillWidth: true
                    visible: section._cacheEntries.length > 0
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.copy-all-shown", "Copy all shown")
                        onClicked: root.copyToClipboard(section._cacheRowsTsv())
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: section._cacheSelectedCount() > 0
                        text: root.tr("diag.copy-selected", "Copy selected")
                            + " (" + section._cacheSelectedCount() + ")"
                        onClicked: section._copyCacheSelected()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    visible: section._cacheEntries.length > 0
                    text: root.tr("diag.table.select-hint",
                        "Click a row to select it (Ctrl+click to toggle, Shift+click to extend), then press Ctrl+C to copy. Right-click for more options.")
                    color: root.mutedTextColor
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    wrapMode: Text.WordWrap
                }

                // Column headers — Host | IP | Source | Route | Freshness. The
                // Freshness column now merges the old Freshness + Expires: it shows
                // the freshness label plus the remaining TTL, full timestamps on
                // hover. The fixed columns (everything but Host) are
                // user-resizable: each carries a CacheColHandle grip on its left
                // edge (an overlay, so the cell's outer width still equals its
                // width property and the body rows stay in register). Every header
                // is clickable to sort (a `_cacheSortArrow` suffix marks the active
                // column); Host flexes to absorb the width the fixed columns
                // give up/take, with a preferred/min so they are never starved.
                RowLayout {
                    Layout.fillWidth: true
                    visible: section._cacheEntries.length > 0
                    spacing: root.uiTheme.spacingSm
                    Label {
                        Layout.fillWidth: true
                        Layout.preferredWidth: section._cacheColHostW
                        Layout.minimumWidth: section._cacheColHostMinW
                        text: root.tr("diag.cache.col-hostname", "Host")
                            + section._cacheSortArrow("host")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleCacheSort("host")
                        }
                    }
                    Item {
                        Layout.preferredWidth: section._cacheColIpW
                        Layout.fillHeight: true
                        implicitHeight: cacheColIpHdr.implicitHeight
                        Label {
                            id: cacheColIpHdr
                            anchors.fill: parent
                            leftPadding: 9
                            verticalAlignment: Text.AlignVCenter
                            text: root.tr("diag.cache.col-ip", "IP")
                                + section._cacheSortArrow("ip")
                            color: root.mutedTextColor
                            font.bold: true
                            elide: Text.ElideRight
                        }
                        HoverHandler { cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleCacheSort("ip")
                        }
                        CacheColHandle {
                            onWidthDelta: function(dx) {
                                section._cacheColIpW = Math.max(section._cacheColMinW,
                                    Math.min(section._cacheColMaxW, section._cacheColIpW - dx))
                                cacheColPersistDebounce.restart()
                            }
                        }
                    }
                    Item {
                        Layout.preferredWidth: section._cacheColSourceW
                        Layout.fillHeight: true
                        implicitHeight: cacheColSourceHdr.implicitHeight
                        Label {
                            id: cacheColSourceHdr
                            anchors.fill: parent
                            leftPadding: 9
                            verticalAlignment: Text.AlignVCenter
                            text: root.tr("diag.cache.col-source", "Source")
                                + section._cacheSortArrow("source")
                            color: root.mutedTextColor
                            font.bold: true
                            elide: Text.ElideRight
                        }
                        HoverHandler { cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleCacheSort("source")
                        }
                        CacheColHandle {
                            onWidthDelta: function(dx) {
                                section._cacheColSourceW = Math.max(section._cacheColMinW,
                                    Math.min(section._cacheColMaxW, section._cacheColSourceW - dx))
                                cacheColPersistDebounce.restart()
                            }
                        }
                    }
                    Item {
                        Layout.preferredWidth: section._cacheColRouteW
                        Layout.fillHeight: true
                        implicitHeight: cacheColRouteHdr.implicitHeight
                        Label {
                            id: cacheColRouteHdr
                            anchors.fill: parent
                            leftPadding: 9
                            verticalAlignment: Text.AlignVCenter
                            text: root.tr("diag.cache.col-route", "Route")
                                + section._cacheSortArrow("route")
                            color: root.mutedTextColor
                            font.bold: true
                            elide: Text.ElideRight
                        }
                        HoverHandler { cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleCacheSort("route")
                        }
                        CacheColHandle {
                            onWidthDelta: function(dx) {
                                section._cacheColRouteW = Math.max(section._cacheColMinW,
                                    Math.min(section._cacheColMaxW, section._cacheColRouteW - dx))
                                cacheColPersistDebounce.restart()
                            }
                        }
                    }
                    Item {
                        Layout.preferredWidth: section._cacheColFreshW
                        Layout.fillHeight: true
                        implicitHeight: cacheColFreshHdr.implicitHeight
                        Label {
                            id: cacheColFreshHdr
                            anchors.fill: parent
                            leftPadding: 9
                            verticalAlignment: Text.AlignVCenter
                            text: root.tr("diag.cache.col-freshness", "Freshness")
                                + section._cacheSortArrow("freshness")
                            color: root.mutedTextColor
                            font.bold: true
                            elide: Text.ElideRight
                        }
                        HoverHandler { cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleCacheSort("freshness")
                        }
                        CacheColHandle {
                            onWidthDelta: function(dx) {
                                section._cacheColFreshW = Math.max(section._cacheColMinW,
                                    Math.min(section._cacheColMaxW, section._cacheColFreshW - dx))
                                cacheColPersistDebounce.restart()
                            }
                        }
                    }
                }

                // Virtualized list: only the delegates in the visible
                // band instantiate, so opening the viewer no longer builds up to
                // `_renderCap` complex rows in a single frame (the GUI freeze the
                // user reported). Height comes from the model-derived
                // `_cacheRenderedHeight`, capped at `_listMaxHeight`; past the cap the
                // list scrolls internally. `interactive` engages only when the content
                // overflows, so a short list still lets the page wheel-scroll (mirrors
                // the proven ReviewDiffDialog idiom). Gated on the shown flag and
                // dropped in text-select mode (the TextEdit below renders then).
                ListView {
                    id: cacheEntriesList
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(section._listMaxHeight,
                        Math.max(section._listLineHeight, section._cacheRenderedHeight))
                    visible: section._cacheRendered.length > 0
                    clip: true
                    interactive: contentHeight > height
                    ScrollBar.vertical: ScrollBar {
                        policy: cacheEntriesList.contentHeight > cacheEntriesList.height
                            ? ScrollBar.AlwaysOn : ScrollBar.AsNeeded
                    }
                    // Ctrl+C copies the selected rows once the list holds
                    // keyboard focus (a row click calls forceActiveFocus). Escape
                    // clears the selection. Focus arrives via the row MouseArea.
                    Keys.onPressed: function(event) {
                        if (event.matches(StandardKey.Copy)) {
                            section._copyCacheSelected()
                            event.accepted = true
                        } else if (event.key === Qt.Key_Escape) {
                            section._clearCacheSelection()
                            event.accepted = true
                        }
                    }
                    // Reuse the cached `_cacheFiltered` view (render-capped
                    // to `_renderCap`) so each page-append evaluates the filter once.
                    model: section._cacheRendered
                    delegate: Item {
                        id: cacheRowItem
                        width: cacheEntriesList.width
                        implicitHeight: cacheRowCol.implicitHeight
                        // `modelData` is a GROUPED display row (one per hostname).
                        readonly property var _g: modelData
                        readonly property int _ipCount: Number((_g && _g.ipCount) || 0)
                        // Reads _cacheExpandRev inside _isCacheExpanded so a toggle
                        // (which bumps that revision) re-evaluates this binding.
                        readonly property bool _expanded:
                            section._isCacheExpanded(_g && _g.hostname)
                        // Is this row part of the current selection? Reads
                        // `_cacheSelRev` (via the helper) so it re-evaluates on every
                        // selection change.
                        readonly property bool _selected: section._cacheRowSelected(_g)
                        // Whole-row right-click → copy. One TSV line per address so
                        // the copy stays lossless despite the collapsed display.
                        readonly property string _rowTsv: section._cacheGroupTsv(_g)
                        // Accent-tinted selection highlight, behind the row
                        // content (mirrors the leak-mismatch tint in the trace twin).
                        Rectangle {
                            visible: cacheRowItem._selected
                            anchors.fill: parent
                            color: root.uiTheme.colorAccent
                            opacity: 0.14
                            z: -1
                        }
                        // Left-click row selection (plain = single,
                        // Ctrl = toggle, Shift = extend). Declared before the row
                        // content so the content's own handlers (the IP "+N"
                        // expander, the freshness tooltip) stay on top and keep
                        // working; plain clicks on the row body fall through to
                        // here. Grabs keyboard focus so the list-level Ctrl+C copies.
                        MouseArea {
                            anchors.fill: parent
                            acceptedButtons: Qt.LeftButton
                            onPressed: function(mouse) {
                                section._selectCacheRow(
                                    index, cacheRowItem._g,
                                    (mouse.modifiers & Qt.ControlModifier) !== 0,
                                    (mouse.modifiers & Qt.ShiftModifier) !== 0)
                                cacheEntriesList.forceActiveFocus()
                                mouse.accepted = true
                            }
                        }
                        TapHandler {
                            acceptedButtons: Qt.RightButton
                            onTapped: {
                                // Right-clicking an unselected row selects it first so
                                // "Copy row" / "Copy selected" act on what was clicked.
                                if (!cacheRowItem._selected)
                                    section._selectCacheRow(index, cacheRowItem._g, false, false)
                                cacheEntriesList.forceActiveFocus()
                                cacheRowMenu.popup()
                            }
                        }
                        // Per-column values of this row, for the single-value
                        // copy items below. One entry per column the table
                        // actually renders; an empty value hides its item.
                        readonly property string _vHost:
                            String((cacheRowItem._g && cacheRowItem._g.hostname) || "")
                        readonly property string _vIps:
                            section._cacheGroupIps(cacheRowItem._g)
                        readonly property string _vSource:
                            section._cacheGroupSourceLabel(cacheRowItem._g)
                        readonly property string _vRoute:
                            section._cacheRouteLabel(cacheRowItem._g)
                        readonly property string _vFreshness:
                            section._cacheFreshnessLabel(
                                cacheRowItem._g && cacheRowItem._g.best_freshness)
                        readonly property string _vExpires:
                            Pure.formatTimestamp(
                                cacheRowItem._g && cacheRowItem._g.best_expires_at_ms)
                        readonly property string _vFakeIp:
                            String((cacheRowItem._g && cacheRowItem._g.fake_ip) || "")
                        Menu {
                            id: cacheRowMenu
                            MenuItem {
                                text: root.tr("action.copy-row", "Copy row")
                                onTriggered: root.copyToClipboard(cacheRowItem._rowTsv)
                            }
                            MenuItem {
                                text: root.tr("diag.copy-selected", "Copy selected")
                                visible: section._cacheSelectedCount() > 0
                                onTriggered: section._copyCacheSelected()
                            }
                            MenuItem {
                                text: root.tr("diag.copy-all-shown", "Copy all shown")
                                onTriggered: root.copyToClipboard(section._cacheRowsTsv())
                            }
                            MenuSeparator { }
                            // Single-column copies. The whole-row TSV above is
                            // the wrong shape for pasting one hostname into a
                            // rule field or one address into a terminal.
                            MenuItem {
                                visible: cacheRowItem._vHost !== ""
                                text: root.copyValueLabel(cacheRowItem._vHost)
                                onTriggered: root.copyToClipboard(cacheRowItem._vHost)
                            }
                            MenuItem {
                                visible: cacheRowItem._vIps !== ""
                                text: root.copyValueLabel(cacheRowItem._vIps)
                                onTriggered: root.copyToClipboard(cacheRowItem._vIps)
                            }
                            MenuItem {
                                // "—" is the empty-cell placeholder, not a value.
                                visible: cacheRowItem._vSource !== ""
                                    && cacheRowItem._vSource !== "—"
                                text: root.copyValueLabel(cacheRowItem._vSource)
                                onTriggered: root.copyToClipboard(cacheRowItem._vSource)
                            }
                            MenuItem {
                                // "—" is the empty-cell placeholder, not a value.
                                visible: cacheRowItem._vRoute !== ""
                                    && cacheRowItem._vRoute !== "—"
                                text: root.copyValueLabel(cacheRowItem._vRoute)
                                onTriggered: root.copyToClipboard(cacheRowItem._vRoute)
                            }
                            MenuItem {
                                visible: cacheRowItem._vFreshness !== ""
                                text: root.copyValueLabel(cacheRowItem._vFreshness)
                                onTriggered: root.copyToClipboard(cacheRowItem._vFreshness)
                            }
                            MenuItem {
                                visible: cacheRowItem._vExpires !== ""
                                text: root.copyValueLabel(cacheRowItem._vExpires)
                                onTriggered: root.copyToClipboard(cacheRowItem._vExpires)
                            }
                            MenuItem {
                                // Mirrors the row's own gate: no virtual
                                // address is offered while the feature is off.
                                visible: section._fakeIpEnabled && cacheRowItem._vFakeIp !== ""
                                text: root.copyValueLabel(cacheRowItem._vFakeIp)
                                onTriggered: root.copyToClipboard(cacheRowItem._vFakeIp)
                            }
                        }
                        ColumnLayout {
                            id: cacheRowCol
                            width: parent.width
                            spacing: 0
                            // Collapsed row — five columns matching the header order:
                            // Host | IP | Source | Route | Freshness. Every cell
                            // elides so a narrow/resized column truncates instead of
                            // overlapping. Fixed cells mirror the header widths + 9px inset.
                            RowLayout {
                            Layout.fillWidth: true
                            spacing: root.uiTheme.spacingSm
                            // Host cell — same toggle as the IP cell beside it. The
                            // name is what the eye goes to, so making only the
                            // "+N" work reads as a dead row.
                            TruncatedCellLabel {
                                Layout.fillWidth: true
                                Layout.preferredWidth: section._cacheColHostW
                                Layout.minimumWidth: section._cacheColHostMinW
                                text: String((cacheRowItem._g && cacheRowItem._g.hostname) || "—")
                                color: root.textColor
                                // Keeps the registrable domain visible.
                                elide: Text.ElideMiddle
                                HoverHandler {
                                    enabled: cacheRowItem._ipCount > 1
                                    cursorShape: Qt.PointingHandCursor
                                }
                                TapHandler {
                                    enabled: cacheRowItem._ipCount > 1
                                    acceptedButtons: Qt.LeftButton
                                    onTapped: section._toggleCacheExpand(
                                        cacheRowItem._g && cacheRowItem._g.hostname)
                                }
                            }
                            // IP cell — first address, plus a "+N" affordance when the
                            // host has more than one; the whole cell toggles the inline
                            // per-address expansion below.
                            Item {
                                Layout.preferredWidth: section._cacheColIpW
                                Layout.fillHeight: true
                                implicitHeight: cacheIpRow.implicitHeight
                                RowLayout {
                                    id: cacheIpRow
                                    anchors.fill: parent
                                    spacing: root.uiTheme.spacingXxs
                                    TruncatedCellLabel {
                                        Layout.fillWidth: true
                                        leftPadding: 9
                                        verticalAlignment: Text.AlignVCenter
                                        text: String((cacheRowItem._g && cacheRowItem._g.ip) || "—")
                                        color: root.textColor
                                        elide: Text.ElideRight
                                    }
                                    Label {
                                        visible: cacheRowItem._ipCount > 1
                                        verticalAlignment: Text.AlignVCenter
                                        text: cacheRowItem._expanded
                                            ? "▾"
                                            : ("+" + String(cacheRowItem._ipCount - 1))
                                        color: root.uiTheme.colorAccent
                                        font.bold: true
                                    }
                                }
                                HoverHandler {
                                    enabled: cacheRowItem._ipCount > 1
                                    cursorShape: Qt.PointingHandCursor
                                }
                                TapHandler {
                                    enabled: cacheRowItem._ipCount > 1
                                    acceptedButtons: Qt.LeftButton
                                    onTapped: section._toggleCacheExpand(
                                        cacheRowItem._g && cacheRowItem._g.hostname)
                                }
                            }
                            TruncatedCellLabel {
                                Layout.preferredWidth: section._cacheColSourceW
                                leftPadding: 9
                                text: section._cacheGroupSourceLabel(cacheRowItem._g)
                                color: root.mutedTextColor
                                elide: Text.ElideRight
                            }
                            Label {
                                // Route mirrors the conn-trace expected-route field;
                                // first non-empty route of the group, "—" when none.
                                Layout.preferredWidth: section._cacheColRouteW
                                leftPadding: 9
                                text: section._cacheRouteLabel(cacheRowItem._g)
                                color: root.mutedTextColor
                                elide: Text.ElideRight
                            }
                            // Merged Freshness + Expires cell: best-entry freshness
                            // label + compact remaining TTL, full timestamps on hover.
                            Item {
                                Layout.preferredWidth: section._cacheColFreshW
                                Layout.fillHeight: true
                                implicitHeight: cacheFreshCell.implicitHeight
                                Label {
                                    id: cacheFreshCell
                                    anchors.fill: parent
                                    leftPadding: 9
                                    verticalAlignment: Text.AlignVCenter
                                    text: section._cacheFreshnessLabel(
                                            cacheRowItem._g && cacheRowItem._g.best_freshness)
                                        + " · " + section._cacheCompactExpiry(
                                            cacheRowItem._g && cacheRowItem._g.best_expires_at_ms)
                                    color: root.mutedTextColor
                                    elide: Text.ElideRight
                                }
                                HoverHandler { id: cacheFreshHover }
                                ToolTip.visible: cacheFreshHover.hovered
                                ToolTip.text: section._cacheExpiryTooltip(
                                    cacheRowItem._g && cacheRowItem._g.best_resolved_at_ms,
                                    cacheRowItem._g && cacheRowItem._g.best_expires_at_ms)
                            }
                            }
                            // Virtual address the resolver currently answers for
                            // this host. One line per host, indented under the
                            // Host column; hidden entirely when the host has no
                            // fake mapping (no dash noise) and, equally, while
                            // virtual addresses are switched off — a stale
                            // allocation would otherwise be read as a live answer.
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: root.uiTheme.spacingSm
                                visible: section._fakeIpEnabled
                                    && String((cacheRowItem._g && cacheRowItem._g.fake_ip) || "") !== ""
                                Item {
                                    Layout.preferredWidth: section._cacheColHostW
                                    Layout.minimumWidth: section._cacheColHostMinW
                                }
                                Label {
                                    Layout.fillWidth: true
                                    leftPadding: 18
                                    text: root.tr("diag.cache.col-fake-ip", "Fake-IP") + " · "
                                        + String((cacheRowItem._g && cacheRowItem._g.fake_ip) || "")
                                    color: root.mutedTextColor
                                    elide: Text.ElideRight
                                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                                }
                            }
                            // Inline per-address sub-rows, revealed when the group is
                            // expanded: IP + that address's own freshness/TTL (full
                            // timestamps on hover). Indented under the Host column.
                            Repeater {
                                model: cacheRowItem._expanded
                                    ? (cacheRowItem._g && cacheRowItem._g.ips)
                                    : []
                                delegate: RowLayout {
                                    Layout.fillWidth: true
                                    spacing: root.uiTheme.spacingSm
                                    Item {
                                        Layout.fillWidth: true
                                        Layout.preferredWidth: section._cacheColHostW
                                        Layout.minimumWidth: section._cacheColHostMinW
                                    }
                                    TruncatedCellLabel {
                                        Layout.preferredWidth: section._cacheColIpW
                                        leftPadding: 18
                                        text: String((modelData && modelData.ip) || "—")
                                        color: root.mutedTextColor
                                        elide: Text.ElideRight
                                        font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                                    }
                                    Label {
                                        Layout.fillWidth: true
                                        leftPadding: 9
                                        text: section._cacheFreshnessLabel(modelData && modelData.freshness)
                                            + " · " + section._cacheCompactExpiry(
                                                modelData && modelData.expires_at_ms)
                                        color: root.mutedTextColor
                                        elide: Text.ElideRight
                                        font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                                        HoverHandler { id: cacheSubFreshHover }
                                        ToolTip.visible: cacheSubFreshHover.hovered
                                        ToolTip.text: section._cacheExpiryTooltip(
                                            modelData && modelData.resolved_at_ms,
                                            modelData && modelData.expires_at_ms)
                                    }
                                }
                            }
                        }
                    }
                }

                // Truncation notice when the match set exceeds the
                // render cap. Copy-all-shown still exports the FULL filtered list.
                Label {
                    Layout.fillWidth: true
                    visible: section._cacheFiltered.length > section._cacheRendered.length
                    text: root.tr("diag.cache.render-truncated",
                        "Showing the first %1 of %2 matches — refine your search to narrow it.")
                        .arg(section._cacheRendered.length).arg(section._cacheFiltered.length)
                    color: root.uiTheme.colorWarning
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    wrapMode: Text.WordWrap
                }

                // Load-more affordance — present only while a further page exists.
                ThemedButton {
                    theme: root.uiTheme
                    visible: section._cacheEntriesCursor !== ""
                    enabled: !section._cacheEntriesLoading
                    text: root.tr("action.load-more", "Load more")
                    onClicked: section._loadCacheEntries(false)
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
