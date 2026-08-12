import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../theme"
import "../components"
import "../lib/pure.js" as Pure

ScrollView {
    id: section
    property var root
    clip: true
    Layout.fillWidth: true
    Layout.fillHeight: true
    // Pin the scrollable content to the viewport width.
    // Without this the ScrollView adopts its content's *implicit* width, which a
    // wrapped Label (e.g. the conn-trace verdict note) reports as its full
    // UNWRAPPED width — producing a phantom horizontal scrollbar that reveals
    // nothing to its right. Mirrors SettingsSection.qml.
    contentWidth: availableWidth

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

    readonly property var diag: root.context.diagnostics || ({})
    readonly property var serviceHealth: diag.serviceHealth || ({})
    readonly property var securityStatus: diag.securityStatus || ({})
    readonly property var cacheHealth: diag.cacheHealth || ({})
    readonly property var logHealth: diag.logHealth || ({})
    readonly property var modeState: diag.diagnosticMode || ({})

    // The mutable alert list lives on the window so the integrity banner
    // and this section read one state: an Acknowledge here must take the
    // banner down too.
    readonly property var alertItems: root.securityAlertItems

    // Count of alerts still demanding attention (active = not yet acked).
    readonly property int unreadAlertCount: {
        var n = 0
        for (var i = 0; i < alertItems.length; i++) {
            if (alertItems[i] && alertItems[i].state === "active")
                n++
        }
        return n
    }

    // Map a backend alert-kind slug to a localized label, falling back
    // to the raw slug when no label exists (e.g. a future kind the GUI
    // doesn't know yet). The whole `diag.alert.kind.*` namespace is
    // populated in locales/{en,ru}.json.
    function _alertKindLabel(kind) {
        // Backend kind slugs are snake_case (`db_tamper_detected`), but
        // locale key segments must be kebab-case (the validator rejects
        // underscores and would drop the whole file). Convert for the
        // lookup; the fallback keeps the raw slug for display.
        var slug = String(kind || "").replace(/_/g, "-")
        return root.tr("diag.alert.kind." + slug, String(kind || ""))
    }

    // Optional longer explanation for a kind, shown under the kind
    // label. Empty when the kind has no `diag.alert.kind-detail.*`
    // entry — most kinds don't need one, the short label suffices.
    function _alertDetailText(kind) {
        var slug = String(kind || "").replace(/_/g, "-")
        return root.tr("diag.alert.kind-detail." + slug, "")
    }

    // Two-phase MutationSubmit acknowledge. The dry-run mints a
    // confirmation token; the confirm executes the ack, which the
    // service's handler turns into a full revision re-sign —
    // healing the DB so the next load verifies clean and the mutation
    // gate lifts.
    function _acknowledgeAlert(alertId) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcMutationSubmit !== "function") {
            root.statusLine = root.tr("diag.alert.ack-unavailable",
                "Cannot acknowledge: service connection unavailable.")
            return
        }
        var payload = { "alert-id": String(alertId) }
        var corr = nrrNativeBridge.rpcMutationSubmit("security-alert-ack", payload, true, "")
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("diag.alert.ack-failed",
                    "Failed to acknowledge alert: ") + String(code || "unknown")
                return
            }
            var token = String((p && p["confirmation-token"]) || "")
            var corr2 = nrrNativeBridge.rpcMutationSubmit("security-alert-ack", payload, false, token)
            root.rpc.registerRpcCallback(corr2, function(ok2, p2, code2, msg2) {
                if (!ok2) {
                    root.statusLine = root.tr("diag.alert.ack-failed",
                        "Failed to acknowledge alert: ") + String(code2 || "unknown")
                    return
                }
                root.markSecurityAlertAcknowledged(alertId)
                root.statusLine = root.tr("diag.alert.ack-completed",
                    "Security alert acknowledged.")
            })
        })
    }

    // Wire real service
    // health. The static `diag.serviceHealth` is mock-backed at cold
    // start ("running" forever); rpcServiceHealthGet is what reflects
    // actual runtime state. On bridge unavailable / RPC failure we
    // show "unavailable" so the user sees the truth (no service is
    // running) rather than a misleading "Service running".
    property string _realServiceState: ""
    property string _realActiveRevisionId: ""
    property int _realPendingChanges: -1

    function _refreshServiceHealth() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcServiceHealthGet !== "function") {
            _realServiceState = "unavailable"
            _realActiveRevisionId = ""
            _realPendingChanges = 0
            return
        }
        _refreshCacheTotal()
        var corr = nrrNativeBridge.rpcServiceHealthGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (!ok) {
                section._realServiceState = "unavailable"
                section._realActiveRevisionId = ""
                section._realPendingChanges = 0
                return
            }
            section._realServiceState = String(
                (payload && payload["service-state"])
                || (payload && payload.service_state) || "unavailable")
            section._realActiveRevisionId = String(
                (payload && payload["active-revision-id"])
                || (payload && payload.active_revision_id) || "")
            // `pending_changes` is deprecated → derive from
            // degraded_modes length so the existing "Pending changes"
            // line surfaces a meaningful count when degraded.
            var degraded = (payload && payload["degraded-modes"])
                || (payload && payload.degraded_modes) || []
            section._realPendingChanges = degraded.length
        })
    }
    // Refresh only the live cache total (cheap page_size=1 fetch)
    // so the "Entries" card reflects the real service cache count without the
    // user having to open the full viewer. Updates `_cacheEntriesTotal` only;
    // it never touches the on-demand `_cacheEntries` list.
    function _refreshCacheTotal() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCacheEntriesList !== "function")
            return
        var corr = nrrNativeBridge.rpcCacheEntriesList("", 1)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (!ok) return
            var page = (payload && payload.page) || {}
            if (page.total_count !== undefined && page.total_count !== null)
                section._cacheEntriesTotal = Number(page.total_count)
        })
    }
    // False "Service running" fix. Before the
    // first live `rpcServiceHealthGet` lands (`_realServiceState === ""`),
    // the cold-start `serviceHealth` snapshot is the only data we have — but
    // the mock/preview backend reports `state: "running"`, so trusting it
    // when no service is actually reachable falsely claims the service is up.
    // Only fall back to the snapshot while the IPC channel is connected
    // (proof a real service is serving the pipe); otherwise report
    // "unavailable" / empty so the card tells the truth.
    function _effectiveServiceState() {
        if (_realServiceState !== "") return _realServiceState
        if ((root.backendStatus || {}).kind === "connected")
            return (serviceHealth.state || "")
        return "unavailable"
    }
    function _effectiveActiveRevisionId() {
        if (_realServiceState !== "") return _realActiveRevisionId
        if ((root.backendStatus || {}).kind === "connected")
            return serviceHealth.activeRevisionId || ""
        return ""
    }
    function _effectivePendingChanges() {
        if (_realServiceState !== "") return _realPendingChanges
        if ((root.backendStatus || {}).kind === "connected")
            return Number(serviceHealth.pendingChanges || 0)
        return 0
    }

    Component.onCompleted: { _loadCacheColWidths(); _refreshServiceHealth() }
    Connections {
        target: root.refreshAction
        function onTriggered() { section._refreshServiceHealth() }
    }
    // QML instantiates children's `Component.onCompleted` BEFORE the
    // ApplicationWindow's, which means the first `rpcServiceHealthGet`
    // call from this section can fire before Main.qml has connected
    // `nrrNativeBridge.rpcResponse` to `handleRpcResponse` — the
    // response is emitted, has no slot to deliver into, and the
    // callback in `pendingRpc` never runs. The 30 s GC eventually
    // synthesises a timeout, but the section meanwhile shows
    // "unavailable". A periodic re-poll heals the race without
    // depending on cross-Section ordering.
    Connections {
        target: root
        function onBackendStatusChanged() {
            if ((root.backendStatus || {}).kind === "connected") {
                section._refreshServiceHealth()
            }
        }
    }
    Timer {
        id: serviceHealthRepoll
        interval: 5000
        running: true
        repeat: true
        onTriggered: section._refreshServiceHealth()
    }

    // Interactive explain probe. Replaces the
    // static `diag.explainSample` read with a live `ExplainGet` query.
    // `_probeResultRoute` slugs match `ExplainCompactViewDto.route`:
    // `"primary" | "secondary" | "none" | "blocked"`. This is the
    // SYNTHETIC path (`rpcExplainGetBySample`): the service runs the REAL
    // rule engine (`match_sample`) against the caller's per-SID active rule
    // book + behavior mode and returns a real route/reason (Available). The
    // separate Historical-by-decision-id path (explain snapshot store) is
    // NOT surfaced in this UI, so the probe never returns `Unavailable`.
    property bool _probing: false
    property string _probeInputText: ""
    property string _probeResultInput: ""
    property string _probeResultRoute: ""
    property string _probeReasonKey: ""
    property string _probeErrorCode: ""
    property string _probeErrorMessage: ""
    // Optional enforcement caveat carried on the compact explain
    // response (`enforcement` slug; "" = none). When set, the probe surfaces a
    // second amber line warning that although the route resolved, the flow may
    // currently be BLOCKED (block-all-unresolved, or fail-closed while the
    // additional adapter is down). Cleared on every new probe / error.
    property string _probeEnforcement: ""
    // For the shared-IP collateral slugs: how many of the
    // probed host's cached IPs are census-shared with secondary rules, out of
    // how many cached total. 0/0 for every other verdict.
    property int _probeEnforcementShared: 0
    property int _probeEnforcementTotal: 0

    function _isIpv4(s) { return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(s) }
    function _isIpv6(s) { return s.indexOf(":") >= 0 && /^[0-9a-fA-F:]+$/.test(s) }
    function _explainRouteLabel(route) {
        if (route === "" || route === "none")
            return root.tr("diag.explain.route.none", "no route")
        if (route === "blocked")
            return root.tr("diag.explain.route.blocked", "blocked")
        if (route === "primary")
            return root.tr("diag.explain.route.primary", "primary route")
        if (route === "secondary")
            return root.tr("diag.explain.route.secondary", "secondary route")
        return route
    }
    // Main probe verdict, spoken as a "route — status" pair
    // ("Primary — Allowed" / "Secondary — Blocked") instead of the bare
    // route name. Only applies to a resolved primary/secondary route: the
    // "status" half reflects whether the enforcement caveat below (killswitch
    // / fail-closed / block-all) will actually block the flow. Reuses the
    // generic route-role labels (`label.primary`/`label.secondary`) and the
    // conn-trace verdict labels (`diag.conn-trace.verdict.permit`/`.block`)
    // instead of minting new near-duplicate text. "none"/"blocked" routes
    // fall back to the plain route label — there is no route role to pair
    // a status against.
    function _probeVerdictLabel() {
        var route = section._probeResultRoute
        if (route !== "primary" && route !== "secondary")
            return section._explainRouteLabel(route)
        var routeWord = route === "primary"
            ? root.tr("label.primary", "Primary")
            : root.tr("label.secondary", "Secondary")
        // Only genuinely-blocking caveats flip the status:
        // the smart-exempt and risk slugs describe a caveat on an ALLOWED flow.
        var blocking = section._probeEnforcement === "blocked-unknown-under-block-all"
            || section._probeEnforcement === "fail-closed-when-secondary-down"
            || section._probeEnforcement === "collateral-blocked-strict"
        var statusWord = blocking
            ? root.tr("diag.conn-trace.verdict.block", "Blocked")
            : root.tr("diag.conn-trace.verdict.permit", "Allowed")
        return routeWord + " — " + statusWord
    }
    function _runExplainProbe() {
        var raw = String(_probeInputText || "").trim()
        if (raw === "") {
            _probeErrorCode = "input-required"
            _probeErrorMessage = ""
            _probeResultInput = ""
            _probeResultRoute = ""
            _probeReasonKey = ""
            _probeEnforcement = ""
            _probeEnforcementShared = 0
            _probeEnforcementTotal = 0
            return
        }
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcExplainGetBySample !== "function") {
            _probeErrorCode = "bridge-unavailable"
            _probeErrorMessage = ""
            return
        }
        _probing = true
        _probeResultInput = ""
        _probeResultRoute = ""
        _probeReasonKey = ""
        _probeErrorCode = ""
        _probeErrorMessage = ""
        _probeEnforcement = ""
        _probeEnforcementShared = 0
        _probeEnforcementTotal = 0

        var hostname = ""
        var observedIp = ""
        if (_isIpv4(raw) || _isIpv6(raw)) {
            observedIp = raw
        } else {
            hostname = raw
        }
        var corr = nrrNativeBridge.rpcExplainGetBySample(
            hostname, observedIp, "", "compact-ui")
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._probing = false
            if (!ok) {
                section._probeErrorCode = String(errorCode || "unknown")
                section._probeErrorMessage = String(errorMessage || "")
                section._probeEnforcement = ""
                section._probeEnforcementShared = 0
                section._probeEnforcementTotal = 0
                return
            }
            var compact = (payload && payload.compact) || {}
            section._probeResultInput = String(compact.input || "-")
            section._probeResultRoute = String(compact.route || "none")
            // Wire is kebab-case (`reason-key`); fall back to snake_case
            // in case a server variant ever serialises differently.
            section._probeReasonKey =
                String(compact["reason-key"] || compact.reason_key || "")
            // Optional enforcement caveat (kebab `enforcement`, snake fallback).
            section._probeEnforcement =
                String(compact["enforcement"] || compact.enforcement || "")
            // Shared-IP collateral counts (N of M cached IPs).
            section._probeEnforcementShared =
                Number(compact["enforcement-shared-ips"] || 0)
            section._probeEnforcementTotal =
                Number(compact["enforcement-total-ips"] || 0)
        })
    }

    // Read-only cache-entries viewer. On demand, pull the
    // FQDN/IP resolution cache page-by-page via `cache.entries.list`. The
    // service applies redaction (compact tier reduces hostnames to eTLD+1
    // and masks IPs) — `_cacheEntriesRedacted` drives the privacy notice.
    property var _cacheEntries: []
    property string _cacheEntriesCursor: ""
    property bool _cacheEntriesLoading: false
    property bool _cacheEntriesShown: false
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
        if (!root.bridgeAvailable || bridge === null
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
    // TASK A (in-table classic copy) — direct row selection for the cache table.
    // Replaces the retired "select text" monospace view: rows are picked in the
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
            section._copyToClipboard(lines.join("\n"))
    }
    property bool _cacheEntriesRedacted: false
    property string _cacheEntriesError: ""
    // Live total row count reported by the service (`page.total_count`); -1 =
    // not yet known. Preferred over the cold-start `cacheHealth.entryCount`
    // snapshot, which froze at the mock backend's fixed value (24) when the GUI
    // Started before the service was up.
    property int _cacheEntriesTotal: -1
    // Client-side filter across all visible columns. When set, the viewer
    // auto-pages the whole cache (see _loadCacheEntries) so the filter sees
    // every entry, not just the first loaded page.
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
    function _cacheBridgeReady() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCacheClear !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return false
        }
        return true
    }
    // The cache render pipeline is three staged bindings:
    //   1. `_cacheFlatFiltered` — the flat (hostname, ip) rows that pass the
    //      free-text search AND the source/freshness/route equality filters.
    //      Used verbatim for the TSV copy (one line per address, lossless).
    //   2. `_cacheFiltered` — the FLAT rows grouped by hostname into one display
    //      row per host, then sorted by the active column. This is what the table,
    //      the no-match state and the render cap operate over.
    // Each is a plain property binding so a change to any dependency re-runs it.
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
    function _formatCacheTs(ms) {
        var n = Number(ms || 0)
        if (!isFinite(n) || n <= 0) return "—"
        var d = new Date(n)
        function pad(x) { return (x < 10 ? "0" : "") + String(x) }
        return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate())
            + " " + pad(d.getHours()) + ":" + pad(d.getMinutes())
    }
    // Compact "remaining TTL" for the merged Freshness column:
    // "3 m" / "2 h" / "5 d" (localized unit) or "expired" once the entry is past
    // its expiry. The full timestamps stay available on hover (see the cell tooltip).
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
            + section._formatCacheTs(resolvedMs) + "\n"
            + root.tr("diag.cache.entries-expires", "expires") + ": "
            + section._formatCacheTs(expiresMs)
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
                section._formatCacheTs(e.expires_at_ms)
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
        return section._connEgressLabel(r)
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
    property string _connSortCol: ""
    property int _connSortDir: 1

    // Numeric/chronological columns compare as numbers; every other column
    // compares the displayed (localized) label case-insensitively.
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
        if (col === "egress") return section._connEgressLabel(e && e.egress_role)
        if (col === "verdict") return section._connVerdictLabel(e && e.verdict)
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
    function _toggleConnSort(col) {
        if (section._connSortCol === col)
            section._connSortDir = -section._connSortDir
        else { section._connSortCol = col; section._connSortDir = 1 }
    }
    // " ▲" (ascending) / " ▼" (descending) suffix appended to the active sort
    // column header, "" otherwise. Glyphs are plain UTF-8 (file already holds
    // em-dashes); no locale keys needed for the sort indicator.
    function _cacheSortArrow(col) {
        if (section._cacheSortCol !== col) return ""
        return section._cacheSortDir < 0 ? " ▼" : " ▲"
    }
    function _connSortArrow(col) {
        if (section._connSortCol !== col) return ""
        return section._connSortDir < 0 ? " ▼" : " ▲"
    }

    // Per-row lowercase search blob, computed ONCE and cached on
    // the entry object. The `_cacheFiltered` binding re-runs on every page-append
    // during a drain; without the cache each recompute rebuilt this string per row
    // (2× new Date + 2× tr + join) → O(pages × rows) heavy work that froze the form
    // on a cache-miss search. With the cache each recompute is a cheap indexOf.
    function _cacheRowBlob(e) {
        if (e && e._blob !== undefined) return e._blob
        var b = [
            String((e && e.hostname) || ""),
            String((e && e.ip) || ""),
            section._cacheSourceLabel(e && e.source),
            section._cacheRouteLabel(e),
            section._cacheFreshnessLabel(e && e.freshness),
            section._formatCacheTs(e && e.expires_at_ms)
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
                if (route === "none") { if (r !== "") continue }
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
    function _copyToClipboard(text) {
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.copyToClipboard === "function") {
            nrrNativeBridge.copyToClipboard(String(text))
            root.statusLine = root.tr("status.copied-to-clipboard", "Copied to clipboard.")
        }
    }
    // Label for a per-value copy item: the verb plus the value itself, elided
    // for DISPLAY only — the clipboard always receives the full string. Without
    // the cap a long process path or a host with many addresses stretched the
    // context menu past the window edge.
    function _copyValueLabel(value) {
        var text = String((value === undefined || value === null) ? "" : value)
        if (text.length > 40) text = text.substring(0, 39) + "…"
        return root.tr("action.copy-value", "Copy: ") + text
    }
    // Every distinct address of a grouped cache row, comma-joined. The table
    // collapses them behind a "+N" expander, so a per-value copy of the address
    // column must hand back the whole set, not just the first entry.
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
                section._formatCacheTs(e.expires_at_ms)
            ].join("\t"))
        }
        return lines.join("\n")
    }
    function _connRowsTsv() {
        var list = section._connFiltered
        var lines = []
        for (var i = 0; i < list.length; i++)
            lines.push(section._connRowTsv(list[i] || {}))
        return lines.join("\n")
    }

    // `reset === true` → clear and pull the first page; `false` → append the
    // next page via the offset cursor echoed back by the previous response.
    function _loadCacheEntries(reset) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCacheEntriesList !== "function") {
            section._cacheEntriesError = root.tr("diag.cache.entries-bridge-unavailable",
                "Service bridge not connected — cache entries unavailable")
            section._cacheEntriesShown = true
            return
        }
        if (reset) {
            section._cacheEntries = []
            section._cacheEntriesCursor = ""
            // Re-read the virtual-address setting alongside the first page so
            // the fake-IP rows appear/disappear with the live service state.
            section._refreshFakeIpEnabled()
        }
        section._cacheEntriesShown = true
        section._cacheEntriesLoading = true
        section._cacheEntriesError = ""
        var cursor = reset ? "" : section._cacheEntriesCursor
        // Pass the server-side search term so a large cache is
        // filtered in SQLite (WHERE LIKE) rather than drained page-by-page.
        var corr = nrrNativeBridge.rpcCacheEntriesList(cursor, 50, section._cacheQuery)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
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
                section._cacheEntriesTotal = Number(page.total_count)
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

    // Tear the cache viewer down for the single show/hide toggle.
    // Clears the search WITHOUT going through `cacheSearchField.text = ""`: that
    // path fired `onTextChanged` → `cacheSearchDebounce` → `_loadCacheEntries`,
    // which re-showed the viewer, so the old hide button needed two presses. We
    // stop the pending debounce and reset the filter state directly, then drop
    // `_cacheEntriesShown` last so the gated Repeater empties.
    function _hideCacheEntries() {
        if (typeof cacheSearchDebounce !== "undefined" && cacheSearchDebounce)
            cacheSearchDebounce.stop()
        section._cacheEntriesFilter = ""
        section._cacheQuery = ""
        section._cacheSourceFilter = "all"
        section._cacheFreshnessFilter = "all"
        section._cacheRouteFilter = "all"
        if (typeof cacheSearchField !== "undefined" && cacheSearchField)
            cacheSearchField.text = ""
        // Snap the filter combos back to their "all" entry so a reopen doesn't
        // show a stale selection out of sync with the reset filter state.
        if (typeof cacheSourceFilterCombo !== "undefined" && cacheSourceFilterCombo) {
            cacheSourceFilterCombo.currentIndex = 0
            cacheSourceFilterCombo.displayText =
                root.tr("diag.cache.source-filter.all", "All sources")
        }
        if (typeof cacheFreshnessFilterCombo !== "undefined" && cacheFreshnessFilterCombo) {
            cacheFreshnessFilterCombo.currentIndex = 0
            cacheFreshnessFilterCombo.displayText =
                root.tr("diag.cache.freshness-filter.all", "Any freshness")
        }
        if (typeof cacheRouteFilterCombo !== "undefined" && cacheRouteFilterCombo) {
            cacheRouteFilterCombo.currentIndex = 0
            cacheRouteFilterCombo.displayText =
                root.tr("diag.cache.route-filter.all", "All routes")
        }
        section._cacheEntriesShown = false
    }

    // Q3 — read-only connection-trace viewer. On demand, pull recently-observed
    // outbound connections page-by-page via `conn-trace.entries.list`. Compact
    // tier masks the local/remote IPs — `_connTraceRedacted` drives the notice.
    property var _connTraceEntries: []
    property string _connTraceCursor: ""
    property bool _connTraceLoading: false
    property bool _connTraceShown: false
    // TASK A — direct row selection for the connection-trace table (mirror of the
    // cache twin). Selection holds the row objects by reference; synthetic group
    // headers (`_isGroupHeader`) are never selectable. Copy/count/highlight filter
    // against the live `_connGroupedModel`, so a stale reference clears itself when
    // the model rebuilds. `_connSelAnchor` indexes into `_connGroupedModel`.
    property var _connSel: []
    property int _connSelAnchor: -1
    property int _connSelRev: 0
    function _connRowSelected(e) {
        return section._connSelRev >= 0 && e !== undefined
            && section._connSel.indexOf(e) !== -1
    }
    function _connSelectedCount() {
        var model = section._connGroupedModel
        var n = 0
        for (var i = 0; section._connSelRev >= 0 && i < model.length; i++) {
            var e = model[i]
            if (e !== undefined && !e._isGroupHeader
                    && section._connSel.indexOf(e) !== -1) n++
        }
        return n
    }
    function _selectConnRow(index, e, ctrl, shift) {
        var model = section._connGroupedModel
        if (shift && section._connSelAnchor >= 0
                && section._connSelAnchor < model.length) {
            var lo = Math.min(section._connSelAnchor, index)
            var hi = Math.max(section._connSelAnchor, index)
            var next = ctrl ? section._connSel.slice() : []
            for (var i = lo; i <= hi; i++) {
                var it = model[i]
                if (it !== undefined && !it._isGroupHeader
                        && next.indexOf(it) === -1) next.push(it)
            }
            section._connSel = next
        } else if (ctrl) {
            var arr = section._connSel.slice()
            var at = arr.indexOf(e)
            if (at === -1) arr.push(e); else arr.splice(at, 1)
            section._connSel = arr
            section._connSelAnchor = index
        } else {
            section._connSel = [e]
            section._connSelAnchor = index
        }
        section._connSelRev++
    }
    function _clearConnSelection() {
        section._connSel = []
        section._connSelAnchor = -1
        section._connSelRev++
    }
    // TSV for one connection row — the SAME column layout as `_connRowsTsv` and
    // the per-row right-click copy. Shared so the delegate, "Copy row" and
    // "Copy selected" all emit identical lines.
    function _connRowTsv(e) {
        return String((e && e.process) || "") + "\t"
            + String((e && e.process_path) || "") + "\t"
            + String((e && e.remote) || "") + "\t"
            + section._connEgressLabel(e && e.egress_role) + "\t"
            + section._connVerdictLabel(e && e.verdict) + "\t"
            + section._connProtoLabel(e && e.proto) + "\t"
            + String((e && e.local) || "") + "\t"
            + section._formatCacheTs(e && e.observed_at_ms)
    }
    function _copyConnSelected() {
        var model = section._connGroupedModel
        var lines = []
        for (var i = 0; i < model.length; i++) {
            var e = model[i]
            if (e !== undefined && !e._isGroupHeader
                    && section._connSel.indexOf(e) !== -1)
                lines.push(section._connRowTsv(e))
        }
        if (lines.length > 0)
            section._copyToClipboard(lines.join("\n"))
    }
    property bool _connTraceRedacted: false
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
    // Single cached filtered view (see _cacheFiltered). The view filters run
    // BEFORE the text search so the search counts match what is on screen; both
    // toggles are read as binding arguments, which registers the dependency.
    property var _connFiltered: _sortRows(
        _filterConnTraceEntries(
            _applyConnViewFilters(_connTraceEntries, _connShowBlocked, _connShowLocal),
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
    readonly property int _renderCap: 400
    // Viewport sizing for the two virtualized tables below. Their height is
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
        section._clearConnSelection()
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
        var lineH = section._listLineHeight
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
            if (!section._isConnGroupExpanded(k)) continue
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
            section._connProtoLabel(e && e.proto),
            String((e && e.local) || ""),
            String((e && e.remote) || ""),
            section._connEgressLabel(e && e.egress_role),
            section._connVerdictLabel(e && e.verdict),
            section._formatCacheTs(e && e.observed_at_ms)
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
    function _applyConnViewFilters(entries, showBlocked, showLocal) {
        if (showBlocked && showLocal) return entries
        var out = []
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i] || {}
            if (!showBlocked && section._connVerdictIsBlock(e.verdict)) continue
            if (!showLocal && Pure.isNonInternetAddress(e.remote)) continue
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
            if (section._connRowBlob(e).indexOf(q) !== -1) out.push(e)
        }
        return out
    }

    function _loadConnTraceEntries(reset) {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcConnTraceEntriesList !== "function") {
            section._connTraceError = root.tr("diag.conn-trace.entries-bridge-unavailable",
                "Service bridge not connected — connection trace unavailable")
            section._connTraceShown = true
            return
        }
        if (reset) {
            section._connTraceEntries = []
            section._connTraceCursor = ""
        }
        section._connTraceShown = true
        section._connTraceLoading = true
        section._connTraceError = ""
        var cursor = reset ? "" : section._connTraceCursor
        // Request the max page (200) so the ≤1000-entry ring loads in
        // ≤5 pages via a one-time OPEN drain (below), not the old per-keystroke drain
        // that rebuilt the render model on every append and froze the view.
        var corr = nrrNativeBridge.rpcConnTraceEntriesList(cursor, 200)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._connTraceLoading = false
            if (!ok) {
                section._connTraceError = root.tr("diag.conn-trace.entries-failed",
                    "Failed to load connection trace: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            var page = (payload && payload.page) || {}
            var items = page.items || []
            section._connTraceRedacted = (payload && payload.redacted) === true
            var merged = section._connTraceEntries.slice()
            for (var i = 0; i < items.length; i++)
                merged.push(items[i])
            section._connTraceEntries = merged
            var nc = page.next_cursor
            section._connTraceCursor =
                (nc === undefined || nc === null) ? "" : String(nc)
            // ONE-TIME open drain: load the rest of the ≤1000-entry
            // ring (≤5 pages of 200) so the client filter covers the whole ring.
            // Unlike the old code this is NOT gated on the filter, so it runs once on
            // open and does NOT re-drain per keystroke (the debounce no longer drains).
            // TSV is gated (select-mode only) so these few appends don't churn.
            if (section._connTraceCursor !== ""
                    && section._connTraceEntries.length < section._connTraceDrainCap)
                section._loadConnTraceEntries(false)
        })
    }

    function serviceStateLabel(state) {
        if (state === "running") return root.tr("diag.status.service-running", "Service running")
        if (state === "degraded") return root.tr("diag.status.service-degraded", "Service degraded")
        if (state === "starting") return root.tr("diag.status.service-starting", "Service starting...")
        if (state === "recovery-required")
            return root.tr("diag.status.service-recovery-required",
                "Service requires recovery action")
        return root.tr("diag.status.service-unavailable", "Service unavailable")
    }
    function cacheStateLabel() {
        if (cacheHealth.rebuilding === true)
            return root.tr("diag.status.cache-rebuilding", "Cache rebuild in progress")
        if (cacheHealth.healthy === false)
            return root.tr("diag.status.cache-stale", "Cache entries stale")
        return root.tr("diag.status.cache-healthy", "Cache healthy")
    }

    // Diagnostic archive export duplicated from
    // Settings → «Диагностика и логи» (DiagnosticsLogsSettings.qml) so the user
    // can reach it directly from the top-level Diagnostics section without
    // hunting through Settings. Identical RPC (`rpcDiagnosticsExportArchive`)
    // and identical `diag.archive.*` / `diag.logs.export-button` locale keys —
    // no new strings introduced. The service owns the archive location
    // (per-user `archives/` dir); the folder field reflects the LAST returned
    // path and "Open folder" opens its parent directory in the file manager.
    property bool _exportBusy: false
    property bool _exportFailed: false
    property string _exportMessage: root.tr("diag.archive.state-ready", "Ready")
    property string _exportArchivePath: ""
    property string _exportArchiveDir: ""
    property string _exportErrorCode: ""
    // Diagnostic-archive privacy tier forwarded as the 4th arg to
    // rpcDiagnosticsExportArchive: "standard" (default, redacted) or
    // "diagnostics" (extra cache/storage/decision detail, less redacted).
    // The value lives on `root` (shared with the Settings export surface) so
    // both radios present ONE choice, and is persisted through the preferences
    // store so it survives a restart. The companion
    // `root.diagnosticsArchiveSessionOnly` (default ON) trims the archive to
    // the session's calendar day by sending `root.appSessionDayStartMs` as the
    // logs cutoff, so yesterday's rotated segments stay out of a routine
    // support archive while an app/service restart mid-test keeps the whole
    // day's history. Unchecked → full history.
    // Backend must be connected for the export RPC to reach the service; mirror
    // the connectivity gate the health cards use above.
    readonly property bool _exportConnected: (root.backendStatus || {}).kind === "connected"

    function _formatBytes(value) {
        var n = Number(value || 0)
        if (!isFinite(n) || n < 0) n = 0
        if (n < 1024) return n + " B"
        if (n < 1048576) return (n / 1024).toFixed(1) + " KB"
        if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB"
        return (n / 1073741824).toFixed(2) + " GB"
    }

    function _startArchiveExport() {
        if (section._exportBusy) return
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable
                || bridge === null
                || typeof bridge.rpcDiagnosticsExportArchive !== "function") {
            section._exportFailed = true
            section._exportErrorCode = "bridge-unavailable"
            section._exportMessage = root.tr("diag.archive.bridge-unavailable",
                "Service bridge not connected — export unavailable")
            return
        }
        section._exportBusy = true
        section._exportFailed = false
        section._exportErrorCode = ""
        section._exportMessage = root.tr("diag.archive.state-exporting", "Exporting...")
        var corr = bridge.rpcDiagnosticsExportArchive(
            true, true, true, section.root.diagnosticsArchiveRedactionLevel,
            root.diagnosticsArchiveSessionOnly ? root.appSessionDayStartMs : 0)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._exportBusy = false
            if (!ok) {
                section._exportFailed = true
                section._exportErrorCode = String(errorCode || "unknown")
                var label = (typeof root.ipcErrorLabel === "function")
                    ? root.ipcErrorLabel(section._exportErrorCode)
                    : section._exportErrorCode
                section._exportMessage = root.tr("diag.archive.state-failed",
                    "Export failed") + ": " + label
                return
            }
            section._exportFailed = false
            var path = String((payload && payload["archive-path"])
                || (payload && payload.archive_path) || "")
            section._exportArchivePath = path
            var lastSep = path.lastIndexOf("\\")
            if (lastSep < 0) lastSep = path.lastIndexOf("/")
            section._exportArchiveDir = lastSep >= 0 ? path.substring(0, lastSep) : ""
            var sizeBytes = Number((payload && payload["size-bytes"])
                || (payload && payload.size_bytes) || 0)
            section._exportMessage = root.tr("diag.archive.state-saved-with-size",
                "Archive saved: {path} ({size})")
                .replace("{path}", path)
                .replace("{size}", section._formatBytes(sizeBytes))
            root.statusLine = section._exportMessage
        })
    }

    ColumnLayout {
        width: section.availableWidth
        spacing: root.uiTheme.spacingMd

        Label {
            text: root.sectionTitle("diagnostics")
            color: root.textColor
            font.bold: true
        }

        // Stale-indicator
        Frame {
            Layout.fillWidth: true
            visible: diag.stale === true
            padding: root.uiTheme.spacingSm
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            RowLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                Label {
                    text: root.tr("diag.status.stale-data-warning", "Status data may be outdated")
                    color: root.uiTheme.colorAccent
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }
        }

        // Service Health card
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                Label {
                    text: root.tr("label.service", "Service")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    readonly property string _state: section._effectiveServiceState()
                    text: serviceStateLabel(_state)
                    color: _state === "running" ? root.mutedTextColor : root.uiTheme.colorAccent
                }
                Label {
                    readonly property string _rev: section._effectiveActiveRevisionId()
                    visible: _rev !== ""
                    text: root.tr("diag.service.revision-label", "Active revision")
                        + ": " + _rev
                    color: root.mutedTextColor
                }
                Label {
                    readonly property int _pending: section._effectivePendingChanges()
                    visible: _pending > 0
                    text: root.tr("diag.service.pending-changes-label", "Pending changes")
                        + ": " + String(_pending)
                    color: root.mutedTextColor
                }
            }
        }

        // C2b: Diagnostic archive export — duplicate of the affordance in
        // Settings → «Диагностика и логи». Same RPC + locale keys (see the
        // `_startArchiveExport` helper above). Placed here, right under the
        // service status, so it is discoverable near the top of the section.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                Label {
                    text: root.tr("diag.archive.title", "Diagnostic archive export")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.archive.service-owned-note",
                        "The archive is saved in the service archives directory (per-user).")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Privacy tier picker — driven by root.diagnosticsArchiveRedactionLevel
                // (shared with the Settings export surface) and forwarded as the
                // 4th arg to rpcDiagnosticsExportArchive. The Binding elements
                // re-assert `checked` from the shared source of truth even after a
                // click breaks the plain binding, so a change on the twin surface
                // is reflected here.
                Label {
                    text: root.tr("diag.archive.level.label", "Detail level")
                    color: root.textColor
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ButtonGroup { id: archiveLevelGroup }
                    RadioButton {
                        id: archiveLevelStandardRadio
                        text: root.tr("diag.archive.level.standard", "Standard (recommended)")
                        ButtonGroup.group: archiveLevelGroup
                        onClicked: section.root.setDiagnosticsArchiveRedactionLevel("standard")
                        Binding {
                            target: archiveLevelStandardRadio
                            property: "checked"
                            value: section.root.diagnosticsArchiveRedactionLevel === "standard"
                        }
                    }
                    RadioButton {
                        id: archiveLevelDiagnosticsRadio
                        text: root.tr("diag.archive.level.diagnostics", "Full diagnostics")
                        ButtonGroup.group: archiveLevelGroup
                        onClicked: section.root.setDiagnosticsArchiveRedactionLevel("diagnostics")
                        Binding {
                            target: archiveLevelDiagnosticsRadio
                            property: "checked"
                            value: section.root.diagnosticsArchiveRedactionLevel === "diagnostics"
                        }
                    }
                    Item { Layout.fillWidth: true }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.archive.level.caption",
                        "Full diagnostics adds extra cache, storage and decision detail and is less redacted. Only share it with support.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Session-only log scope (default ON);
                // twin of the checkbox in DiagnosticsLogsSettings. A plain
                // `checked` binding would be destroyed by the first click, so a
                // change on the twin surface would stop being reflected here; a
                // Binding element keeps re-asserting from the shared value.
                CheckBox {
                    id: diagArchiveSessionOnlyBox
                    Layout.fillWidth: true
                    Binding {
                        target: diagArchiveSessionOnlyBox
                        property: "checked"
                        value: section.root.diagnosticsArchiveSessionOnly
                    }
                    onToggled: section.root.setDiagnosticsArchiveSessionOnly(checked)
                    text: root.tr("diag.archive.session-only",
                        "Only logs from the current session")
                    contentItem: Text {
                        text: diagArchiveSessionOnlyBox.text
                        leftPadding: diagArchiveSessionOnlyBox.indicator.width
                            + diagArchiveSessionOnlyBox.spacing
                        verticalAlignment: Text.AlignVCenter
                        wrapMode: Text.WordWrap
                        color: root.textColor
                    }
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                }
                // Cap on the raw service log files attached to the archive.
                // Unlimited by default: a truncated attachment silently drops
                // the very lines a support hand-off is built to carry, so the
                // trade-off (archive size) is the user's to make explicitly.
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Label {
                        text: root.tr("diag.archive.log-budget.label",
                            "Log size limit in the archive")
                        color: root.textColor
                        wrapMode: Text.WordWrap
                    }
                    ThemedComboBox {
                        id: archiveLogBudgetCombo
                        theme: root.uiTheme
                        implicitWidth: 200
                        model: [0, 24, 64, 128]
                        function budgetLabel(mib) {
                            if (Number(mib) === 0)
                                return root.tr("diag.archive.log-budget.unlimited",
                                    "Unlimited")
                            return Number(mib) + " MiB"
                        }
                        labelResolver: function(item) {
                            return archiveLogBudgetCombo.budgetLabel(item)
                        }
                        currentIndex: Math.max(0,
                            [0, 24, 64, 128].indexOf(section.root.archiveLogBudgetMib))
                        Component.onCompleted: archiveLogBudgetCombo.displayText =
                            archiveLogBudgetCombo.budgetLabel(
                                archiveLogBudgetCombo.model[archiveLogBudgetCombo.currentIndex])
                        popup.width: root.comboPopupWidth(archiveLogBudgetCombo, model, "",
                            function(item) { return archiveLogBudgetCombo.budgetLabel(item) })
                        onActivated: {
                            section.root.setArchiveLogBudgetMib(model[currentIndex])
                            archiveLogBudgetCombo.displayText =
                                archiveLogBudgetCombo.budgetLabel(model[currentIndex])
                        }
                        Connections {
                            target: root
                            function onUiRevisionChanged() {
                                if (!archiveLogBudgetCombo) return
                                archiveLogBudgetCombo.currentIndex = Math.max(0,
                                    [0, 24, 64, 128].indexOf(section.root.archiveLogBudgetMib))
                                archiveLogBudgetCombo.displayText =
                                    archiveLogBudgetCombo.budgetLabel(
                                        archiveLogBudgetCombo.model[
                                            archiveLogBudgetCombo.currentIndex])
                            }
                        }
                        Accessible.role: Accessible.ComboBox
                        Accessible.name: root.tr("diag.archive.log-budget.label",
                            "Log size limit in the archive")
                    }
                    Item { Layout.fillWidth: true }
                }
                ThemedTextField {
                    theme: root.uiTheme
                    Layout.fillWidth: true
                    // Read-only but enabled so the path stays selectable/copyable.
                    readOnly: true
                    placeholderText: root.tr("diag.archive.path-placeholder",
                        "No archive exported yet")
                    text: section._exportArchivePath
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        enabled: !section._exportBusy && section._exportConnected
                        text: root.tr("diag.logs.export-button", "Export diagnostic archive")
                        icon.source: root.uiIconSource("export")
                        onClicked: section._startArchiveExport()
                        ToolTip.visible: hovered
                        ToolTip.text: section._exportConnected
                            ? root.tr("diag.archive.service-owned-note",
                                "The archive is saved in the service archives directory (per-user).")
                            : root.tr("diag.archive.bridge-unavailable",
                                "Service bridge not connected — export unavailable")
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        enabled: section._exportArchiveDir !== ""
                        text: root.tr("diag.archive.open-folder", "Open folder")
                        onClicked: {
                            if (section._exportArchiveDir === "") return
                            Qt.openUrlExternally(
                                "file:///" + section._exportArchiveDir.replace(/\\/g, "/"))
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        // When disconnected the export button is disabled (and
                        // hover tooltips don't fire on a disabled control), so
                        // surface the reason here as the visible fallback.
                        text: section._exportConnected
                            ? section._exportMessage
                            : root.tr("diag.archive.bridge-unavailable",
                                "Service bridge not connected — export unavailable")
                        color: (section._exportFailed || !section._exportConnected)
                            ? root.uiTheme.colorAccent : root.mutedTextColor
                        wrapMode: Text.WordWrap
                    }
                }
                ProgressBar {
                    Layout.fillWidth: true
                    visible: section._exportBusy
                    indeterminate: true
                }
            }
        }

        // Security Status card
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Image {
                        Layout.preferredWidth: 20
                        Layout.preferredHeight: 20
                        source: root.uiIconSource("icon_audit_trail")
                        sourceSize.width: 20
                        sourceSize.height: 20
                        fillMode: Image.PreserveAspectFit
                        asynchronous: true
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr("diag.audit.title", "Audit trail")
                        color: root.textColor
                        font.bold: true
                    }
                    Label {
                        text: securityStatus.auditChainOk === false
                            ? root.tr("diag.status.audit-chain-mismatch", "Audit chain mismatch detected")
                            : root.tr("diag.status.audit-chain-ok", "Audit chain intact")
                        color: securityStatus.auditChainOk === false ? root.uiTheme.colorAccent : root.mutedTextColor
                    }
                }

                // Prominent "N need attention" plashka
                // so a tamper / key-reset alert is hard to miss.
                Label {
                    Layout.fillWidth: true
                    visible: section.unreadAlertCount > 0
                    text: root.tr("diag.alert.unread-prefix", "Security alerts requiring attention:")
                        + " " + String(section.unreadAlertCount)
                    color: root.uiTheme.colorAccent
                    font.bold: true
                    wrapMode: Text.WordWrap
                }

                Label {
                    Layout.fillWidth: true
                    visible: section.alertItems.length === 0
                    text: root.tr("diag.alert.no-active-alerts", "No active alerts")
                    color: root.mutedTextColor
                }

                Repeater {
                    model: section.alertItems
                    delegate: Frame {
                        Layout.fillWidth: true
                        padding: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: root.uiTheme.spacingXxs
                            RowLayout {
                                Layout.fillWidth: true
                                Label {
                                    Layout.fillWidth: true
                                    text: modelData.state === "active"
                                        ? root.tr("diag.alert.title-active", "Active security alert")
                                        : root.tr("diag.alert.title-acknowledged", "Acknowledged alert")
                                    color: modelData.requiresAction ? root.uiTheme.colorAccent : root.textColor
                                    font.bold: true
                                    wrapMode: Text.WordWrap
                                }
                                ThemedButton {
                                    theme: root.uiTheme
                                    visible: modelData.state === "active"
                                    text: root.tr("diag.alert.action-acknowledge", "Acknowledge")
                                    onClicked: section._acknowledgeAlert(modelData.alertId)
                                }
                            }
                            Label {
                                Layout.fillWidth: true
                                text: section._alertKindLabel(modelData.kind) + " · " + modelData.reasonCode
                                color: root.mutedTextColor
                                wrapMode: Text.WordWrap
                            }
                            Label {
                                Layout.fillWidth: true
                                visible: text.length > 0
                                text: section._alertDetailText(modelData.kind)
                                color: root.textColor
                                wrapMode: Text.WordWrap
                            }
                            Label {
                                Layout.fillWidth: true
                                text: modelData.raisedFile
                                color: root.mutedTextColor
                                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                                wrapMode: Text.WrapAnywhere
                            }
                        }
                    }
                }
            }
        }

        // Cache Health card
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
                Label {
                    text: cacheStateLabel()
                    color: cacheHealth.healthy === false || cacheHealth.rebuilding === true
                        ? root.uiTheme.colorAccent
                        : root.mutedTextColor
                }
                Label {
                    Layout.fillWidth: true
                    // Prefer the live service total. Fall back to the
                    // cold-start health snapshot ONLY while the IPC channel
                    // is connected (proof a real service served it) —
                    // otherwise the snapshot is the mock backend's fixed
                    // placeholder (24), so a stopped service shows "—"
                    // Instead of inventing a count. All three
                    // reads are inline so the binding stays reactive.
                    text: root.tr("diag.cache.entry-count", "Entries") + ": "
                        + (section._cacheEntriesTotal >= 0
                            ? String(section._cacheEntriesTotal)
                            : ((root.backendStatus || {}).kind === "connected"
                                ? String(cacheHealth.entryCount || 0)
                                : "—"))
                    color: root.mutedTextColor
                }
                // All cache actions in one wrapping row, right-aligned to the
                // panel edge (this used to be Show/Clear in one RowLayout plus
                // Seed-from-browser-history in a separate RowLayout below it,
                // which left the seed button stranded on its own line). Flow +
                // RightToLeft is the same idiom as UnsavedChangesGuard.qml: the
                // FIRST declared button sits at the right edge, so buttons are
                // declared in reverse visual order to keep the on-screen
                // left-to-right reading order: Show/Hide entries, Clear app
                // cache, Clear OS DNS cache, Seed from browser history.
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
                            if (!section._cacheBridgeReady())
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
                                    : root.tr("diag.cache.seed-browser-history.unavailable",
                                        "This feature is unavailable.")
                                // If the viewer is open, refresh so newly-seeded
                                // entries (source "Browser history") show up.
                                if (section._cacheEntriesShown)
                                    section._loadCacheEntries(true)
                            })
                        }
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.cache.clear-os-dns-button", "Clear OS DNS cache")
                        enabled: cacheHealth.rebuilding !== true
                        onClicked: {
                            // Flushes the OS DNS resolver cache only; the app's
                            // FQDN/IP cache is left untouched.
                            if (!section._cacheBridgeReady())
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
                        enabled: cacheHealth.rebuilding !== true
                        onClicked: {
                            // Clears the rebuildable FQDN/IP cache; audit/state
                            // DBs untouched. OS DNS cache left alone.
                            if (!section._cacheBridgeReady())
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
                                // Cache is now empty — refresh the viewer if it is open.
                                if (section._cacheEntriesShown)
                                    section._loadCacheEntries(true)
                            })
                        }
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        // Single toggle: shows "Show…" when the
                        // viewer is hidden, "Hide…" once open, replacing the
                        // separate hide button that lived inside the frame. That
                        // hide button cleared the search text, which retriggered
                        // the debounce → `_loadCacheEntries` → re-shown viewer,
                        // so hiding needed two presses. `_hideCacheEntries()`
                        // tears down without going through the search-field path.
                        text: section._cacheEntriesShown
                            ? root.tr("diag.cache.entries-hide", "Hide cache entries")
                            : root.tr("diag.cache.entries-button", "Show cache entries")
                        enabled: !section._cacheEntriesLoading
                        onClicked: section._cacheEntriesShown
                            ? section._hideCacheEntries()
                            : section._loadCacheEntries(true)
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
                // Opt-in AUTOMATIC seed at service start (per-SID
                // service-side setting, default OFF). The manual button above
                // works regardless. Checked state mirrors the service snapshot
                // (routingState.browserHistoryAutoSeed, refreshed on reconnect).
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
                // Dedicated privacy caption directly under the
                // auto-seed toggle: only visited HOSTNAMES are read from local
                // browser profiles, nothing leaves the machine. Distinct from
                // the general seed-feature note above (which explains what the
                // manual button does); this one specifically scopes what the
                // automatic, opt-in variant reads and does not send anywhere.
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

        // C4b: Cache entries viewer (read-only, populated on demand)
        Frame {
            Layout.fillWidth: true
            visible: section._cacheEntriesShown
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
                            "Exact name or IP; *.google.com — subdomains; *google* — any match")
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
                                return section._connEgressLabel("primary")
                            if (slug === "secondary")
                                return section._connEgressLabel("secondary")
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
                        // A pending tick can outlive a hide (clearing
                        // the field on hide restarts this timer); do nothing once
                        // the viewer is closed so it can't re-open itself.
                        if (!section._cacheEntriesShown)
                            return
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

                // Copy toolbar (TASK A) — classic in-table selection. The old
                // "select text" toggle + monospace view is gone; rows are picked
                // in the table itself and copied with Ctrl+C, the right-click
                // menu, or these buttons.
                RowLayout {
                    Layout.fillWidth: true
                    visible: section._cacheEntries.length > 0
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.copy-all-shown", "Copy all shown")
                        onClicked: section._copyToClipboard(section._cacheRowsTsv())
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
                    visible: section._cacheEntriesShown
                        && section._cacheRendered.length > 0
                    clip: true
                    interactive: contentHeight > height
                    ScrollBar.vertical: ScrollBar {
                        policy: cacheEntriesList.contentHeight > cacheEntriesList.height
                            ? ScrollBar.AlwaysOn : ScrollBar.AsNeeded
                    }
                    // TASK A — Ctrl+C copies the selected rows once the list holds
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
                    model: section._cacheEntriesShown
                        ? section._cacheRendered
                        : []
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
                        // TASK A — is this row part of the current selection? Reads
                        // `_cacheSelRev` (via the helper) so it re-evaluates on every
                        // selection change.
                        readonly property bool _selected: section._cacheRowSelected(_g)
                        // Whole-row right-click → copy. One TSV line per address so
                        // the copy stays lossless despite the collapsed display.
                        readonly property string _rowTsv: section._cacheGroupTsv(_g)
                        // TASK A — accent-tinted selection highlight, behind the row
                        // content (mirrors the leak-mismatch tint in the trace twin).
                        Rectangle {
                            visible: cacheRowItem._selected
                            anchors.fill: parent
                            color: root.uiTheme.colorAccent
                            opacity: 0.14
                            z: -1
                        }
                        // TASK A — left-click row selection (plain = single,
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
                            section._formatCacheTs(
                                cacheRowItem._g && cacheRowItem._g.best_expires_at_ms)
                        readonly property string _vFakeIp:
                            String((cacheRowItem._g && cacheRowItem._g.fake_ip) || "")
                        Menu {
                            id: cacheRowMenu
                            MenuItem {
                                text: root.tr("action.copy-row", "Copy row")
                                onTriggered: section._copyToClipboard(cacheRowItem._rowTsv)
                            }
                            MenuItem {
                                text: root.tr("diag.copy-selected", "Copy selected")
                                visible: section._cacheSelectedCount() > 0
                                onTriggered: section._copyCacheSelected()
                            }
                            MenuItem {
                                text: root.tr("diag.copy-all-shown", "Copy all shown")
                                onTriggered: section._copyToClipboard(section._cacheRowsTsv())
                            }
                            MenuSeparator { }
                            // Single-column copies. The whole-row TSV above is
                            // the wrong shape for pasting one hostname into a
                            // rule field or one address into a terminal.
                            MenuItem {
                                visible: cacheRowItem._vHost !== ""
                                text: section._copyValueLabel(cacheRowItem._vHost)
                                onTriggered: section._copyToClipboard(cacheRowItem._vHost)
                            }
                            MenuItem {
                                visible: cacheRowItem._vIps !== ""
                                text: section._copyValueLabel(cacheRowItem._vIps)
                                onTriggered: section._copyToClipboard(cacheRowItem._vIps)
                            }
                            MenuItem {
                                // "—" is the empty-cell placeholder, not a value.
                                visible: cacheRowItem._vSource !== ""
                                    && cacheRowItem._vSource !== "—"
                                text: section._copyValueLabel(cacheRowItem._vSource)
                                onTriggered: section._copyToClipboard(cacheRowItem._vSource)
                            }
                            MenuItem {
                                // "—" is the empty-cell placeholder, not a value.
                                visible: cacheRowItem._vRoute !== ""
                                    && cacheRowItem._vRoute !== "—"
                                text: section._copyValueLabel(cacheRowItem._vRoute)
                                onTriggered: section._copyToClipboard(cacheRowItem._vRoute)
                            }
                            MenuItem {
                                visible: cacheRowItem._vFreshness !== ""
                                text: section._copyValueLabel(cacheRowItem._vFreshness)
                                onTriggered: section._copyToClipboard(cacheRowItem._vFreshness)
                            }
                            MenuItem {
                                visible: cacheRowItem._vExpires !== ""
                                text: section._copyValueLabel(cacheRowItem._vExpires)
                                onTriggered: section._copyToClipboard(cacheRowItem._vExpires)
                            }
                            MenuItem {
                                // Mirrors the row's own gate: no virtual
                                // address is offered while the feature is off.
                                visible: section._fakeIpEnabled && cacheRowItem._vFakeIp !== ""
                                text: section._copyValueLabel(cacheRowItem._vFakeIp)
                                onTriggered: section._copyToClipboard(cacheRowItem._vFakeIp)
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
                            Label {
                                Layout.fillWidth: true
                                Layout.preferredWidth: section._cacheColHostW
                                Layout.minimumWidth: section._cacheColHostMinW
                                text: String((cacheRowItem._g && cacheRowItem._g.hostname) || "—")
                                color: root.textColor
                                elide: Text.ElideRight
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
                                    Label {
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
                            Label {
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
                                    Label {
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
                    visible: section._cacheEntriesShown
                        && section._cacheFiltered.length > section._cacheRendered.length
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
                    text: root.tr("diag.cache.entries-load-more", "Load more")
                    onClicked: section._loadCacheEntries(false)
                }
            }
        }

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
                        "Recently-observed outbound connections and which interface they actually left through (primary, or the additional adapter). Observation only — it never changes routing. Requires the connection trace to be enabled in Settings.")
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
                        visible: !section._connTraceShown
                        enabled: !section._connTraceLoading
                        text: root.tr("diag.conn-trace.entries-button", "Show recent connections")
                        onClicked: section._loadConnTraceEntries(true)
                    }
                    ThemedTextField {
                        id: connTraceSearchField
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        visible: section._connTraceShown
                            && (section._connTraceEntries.length > 0
                                || section._connTraceFilter !== "")
                        placeholderText: root.tr("diag.conn-trace.entries-search-placeholder",
                            "Search all fields…")
                        // Debounce (see cache search).
                        onTextChanged: connTraceSearchDebounce.restart()
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: section._connTraceShown
                        enabled: !section._connTraceLoading
                        text: root.tr("diag.conn-trace.entries-refresh", "Refresh")
                        onClicked: section._loadConnTraceEntries(true)
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: section._connTraceShown
                        text: root.tr("diag.conn-trace.entries-hide", "Hide connection trace")
                        onClicked: {
                            // Hide FIRST (see cache-entries hide, E).
                            section._connTraceShown = false
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
                    visible: section._connTraceShown
                        && section._connTraceEntries.length > 0
                    spacing: root.uiTheme.spacingMd
                    CheckBox {
                        id: connShowBlockedCheck
                        checked: section._connShowBlocked
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
                            section._connShowBlocked = checked
                            section._clearConnSelection()
                        }
                    }
                    CheckBox {
                        id: connShowLocalCheck
                        checked: section._connShowLocal
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
                            section._connShowLocal = checked
                            section._clearConnSelection()
                        }
                    }
                    // Group the trace rows by process.
                    CheckBox {
                        id: connGroupByProcessCheck
                        checked: section._connGroupByProcess
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
                            section._connGroupByProcess = checked
                            section._clearConnSelection()
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
                        section._connTraceFilter = connTraceSearchField.text
                    }
                }

                // Privacy notice — compact tier masks addresses.
                Label {
                    Layout.fillWidth: true
                    visible: section._connTraceShown && section._connTraceRedacted
                        && section._connTraceEntries.length > 0
                    text: root.tr("diag.conn-trace.entries-redacted-notice",
                        "Addresses are masked for privacy. Enable Extended diagnostics for full detail.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                }
                // Error state.
                Label {
                    Layout.fillWidth: true
                    visible: section._connTraceError !== ""
                    text: section._connTraceError
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
                // First-load spinner surrogate.
                Label {
                    Layout.fillWidth: true
                    visible: section._connTraceLoading && section._connTraceEntries.length === 0
                    text: root.tr("diag.conn-trace.entries-loading", "Loading connections...")
                    color: root.mutedTextColor
                }
                // Empty state.
                Label {
                    Layout.fillWidth: true
                    visible: section._connTraceShown && !section._connTraceLoading
                        && section._connTraceError === ""
                        && section._connTraceEntries.length === 0
                    text: root.tr("diag.conn-trace.entries-empty", "No connections observed yet")
                    color: root.mutedTextColor
                }
                // No-match state. Covers the search field AND the two view
                // filters — with "Show blocked" off, an all-blocked trace would
                // otherwise render as a silent empty table.
                Label {
                    Layout.fillWidth: true
                    visible: section._connTraceEntries.length > 0
                        && section._connFiltered.length === 0
                    text: root.tr("diag.conn-trace.entries-no-match",
                        "No connections match the current filters")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }

                // Copy toolbar (TASK A) — see the cache table twin.
                RowLayout {
                    Layout.fillWidth: true
                    visible: section._connTraceShown && section._connTraceEntries.length > 0
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.copy-all-shown", "Copy all shown")
                        onClicked: section._copyToClipboard(section._connRowsTsv())
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: section._connSelectedCount() > 0
                        text: root.tr("diag.copy-selected", "Copy selected")
                            + " (" + section._connSelectedCount() + ")"
                        onClicked: section._copyConnSelected()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    visible: section._connTraceShown && section._connTraceEntries.length > 0
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
                    visible: section._connTraceShown && section._connTraceEntries.length > 0
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
                            + section._connSortArrow("process")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrProcessHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleConnSort("process")
                        }
                        ToolTip.visible: connHdrProcessHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-process-tip",
                            "The application that opened the connection. Hover a row's process name to see its full path.")
                    }
                    Label {
                        id: connHdrRemote
                        Layout.preferredWidth: 150
                        text: root.tr("diag.conn-trace.col-remote", "Remote")
                            + section._connSortArrow("remote")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrRemoteHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleConnSort("remote")
                        }
                        ToolTip.visible: connHdrRemoteHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-remote-tip",
                            "The destination address and port the connection went to.")
                    }
                    Label {
                        id: connHdrEgress
                        Layout.preferredWidth: 110
                        text: root.tr("diag.conn-trace.col-egress", "Egress")
                            + section._connSortArrow("egress")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrEgressHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleConnSort("egress")
                        }
                        ToolTip.visible: connHdrEgressHover.hovered
                        ToolTip.text: root.tr("diag.conn-trace.col-egress-tip",
                            "Which network link the connection actually left through: Primary (your main link), Additional (the VPN/secondary link), Loopback (local, never leaves the PC), Other (another adapter), Unknown (couldn't be determined). This is observation only — it never changes routing.")
                    }
                    Label {
                        id: connHdrVerdict
                        Layout.preferredWidth: 180
                        text: root.tr("diag.conn-trace.col-verdict", "Verdict")
                            + section._connSortArrow("verdict")
                        color: root.mutedTextColor
                        font.bold: true
                        elide: Text.ElideRight
                        HoverHandler { id: connHdrVerdictHover; cursorShape: Qt.PointingHandCursor }
                        TapHandler {
                            acceptedButtons: Qt.LeftButton
                            onTapped: section._toggleConnSort("verdict")
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
                    visible: section._connTraceShown && section._connTraceEntries.length > 0
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
                    Layout.preferredHeight: Math.min(section._listMaxHeight,
                        Math.max(section._listLineHeight,
                            Number(section._connGroupedBuild.height || 0)))
                    visible: section._connTraceShown
                        && section._connGroupedModel.length > 0
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
                            section._copyConnSelected()
                            event.accepted = true
                        } else if (event.key === Qt.Key_Escape) {
                            section._clearConnSelection()
                            event.accepted = true
                        }
                    }
                    // Reuse the cached `_connFiltered` (render-capped
                    // to `_renderCap`); `_connGroupedModel` is `_connRendered` when
                    // grouping is off, else the header-interleaved grouped list.
                    model: section._connTraceShown
                        ? section._connGroupedModel
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
                            && section._isConnGroupExpanded(connRowItem._groupKey)
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
                            onClicked: section._toggleConnGroupExpand(connRowItem._groupKey)
                        }
                        // TASK A — selection state (never for synthetic headers).
                        readonly property bool _selected:
                            !connRowItem._isHeader && section._connRowSelected(modelData)
                        // Whole-row right-click → copy. TSV so paste keeps columns.
                        readonly property string _rowTsv: section._connRowTsv(modelData)
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
                                section._selectConnRow(
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
                                    section._selectConnRow(index, modelData, false, false)
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
                        readonly property string _vEgress:
                            section._connEgressLabel(modelData && modelData.egress_role)
                        readonly property string _vVerdict:
                            section._connVerdictLabel(modelData && modelData.verdict)
                        readonly property string _vProto:
                            section._connProtoLabel(modelData && modelData.proto)
                        readonly property string _vLocal:
                            String((modelData && modelData.local) || "")
                        readonly property string _vObserved:
                            section._formatCacheTs(modelData && modelData.observed_at_ms)
                        Menu {
                            id: connRowMenu
                            MenuItem {
                                text: root.tr("action.copy-row", "Copy row")
                                onTriggered: section._copyToClipboard(connRowItem._rowTsv)
                            }
                            MenuItem {
                                text: root.tr("diag.copy-selected", "Copy selected")
                                visible: section._connSelectedCount() > 0
                                onTriggered: section._copyConnSelected()
                            }
                            MenuItem {
                                text: root.tr("diag.copy-all-shown", "Copy all shown")
                                onTriggered: section._copyToClipboard(section._connRowsTsv())
                            }
                            MenuSeparator { }
                            // Single-column copies — the executable path and the
                            // remote address are what actually gets pasted into
                            // a rule, a search box or a support message.
                            MenuItem {
                                visible: connRowItem._vProcess !== ""
                                text: section._copyValueLabel(connRowItem._vProcess)
                                onTriggered: section._copyToClipboard(connRowItem._vProcess)
                            }
                            MenuItem {
                                visible: connRowItem._vProcessPath !== ""
                                text: section._copyValueLabel(connRowItem._vProcessPath)
                                onTriggered: section._copyToClipboard(connRowItem._vProcessPath)
                            }
                            MenuItem {
                                visible: connRowItem._vRemote !== ""
                                text: section._copyValueLabel(connRowItem._vRemote)
                                onTriggered: section._copyToClipboard(connRowItem._vRemote)
                            }
                            MenuItem {
                                visible: connRowItem._vEgress !== ""
                                text: section._copyValueLabel(connRowItem._vEgress)
                                onTriggered: section._copyToClipboard(connRowItem._vEgress)
                            }
                            MenuItem {
                                visible: connRowItem._vVerdict !== ""
                                text: section._copyValueLabel(connRowItem._vVerdict)
                                onTriggered: section._copyToClipboard(connRowItem._vVerdict)
                            }
                            MenuItem {
                                visible: connRowItem._vProto !== ""
                                text: section._copyValueLabel(connRowItem._vProto)
                                onTriggered: section._copyToClipboard(connRowItem._vProto)
                            }
                            MenuItem {
                                visible: connRowItem._vLocal !== ""
                                text: section._copyValueLabel(connRowItem._vLocal)
                                onTriggered: section._copyToClipboard(connRowItem._vLocal)
                            }
                            MenuItem {
                                visible: connRowItem._vObserved !== ""
                                text: section._copyValueLabel(connRowItem._vObserved)
                                onTriggered: section._copyToClipboard(connRowItem._vObserved)
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
                                    + section._connEgressLabel(modelData && modelData.egress_role)
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
                                    return section._connVerdictLabel(modelData && modelData.verdict)
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
                            }
                        }
                        Label {
                            Layout.fillWidth: true
                            // The relay note is what keeps a fake-IP flow from
                            // reading as the service going out on its own account.
                            text: section._connProtoLabel(modelData && modelData.proto)
                                + "  ·  " + root.tr("diag.conn-trace.entries-from", "from") + " "
                                + String((modelData && modelData.local) || "—")
                                + "  ·  "
                                + section._formatCacheTs(modelData && modelData.observed_at_ms)
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
                    visible: section._connTraceShown && section._connDroppedByCap > 0
                    text: root.tr("diag.cache.render-truncated",
                        "Showing the first %1 of %2 matches — refine your search to narrow it.")
                        .arg(section._connFiltered.length - section._connDroppedByCap)
                        .arg(section._connFiltered.length)
                    color: root.uiTheme.colorWarning
                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                    wrapMode: Text.WordWrap
                }

                // Load-more affordance — present only while a further page exists.
                ThemedButton {
                    theme: root.uiTheme
                    visible: section._connTraceCursor !== ""
                    enabled: !section._connTraceLoading
                    text: root.tr("diag.conn-trace.entries-load-more", "Load more")
                    onClicked: section._loadConnTraceEntries(false)
                }
            }
        }

        // Log Health mini-card with link to Logs section
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                Label {
                    text: root.tr("diag.logs.title", "Operational logs")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    text: root.tr("diag.storage-health.log-files", "{count} log file(s)")
                        .replace("{count}", String(logHealth.fileCount || 0))
                    color: root.mutedTextColor
                }
                Label {
                    visible: Number(logHealth.droppedCount || 0) > 0
                    text: root.tr("diag.storage-health.dropped-events", "{count} event(s) dropped")
                        .replace("{count}", String(logHealth.droppedCount || 0))
                    color: root.uiTheme.colorAccent
                }
                Label {
                    visible: logHealth.dirWritable === false
                    text: root.tr("diag.storage-health.dir-not-writable", "Log directory is not writable")
                    color: root.uiTheme.colorAccent
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.sectionTitle("logs")
                    onClicked: root.section = "logs"
                }
            }
        }

        // Explain sample probe.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                Label {
                    text: root.tr("diag.explain.title", "Explain sample")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.explain.subtitle",
                        "Enter a hostname or IP to simulate the routing decision against the active rule set.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedTextField {
                        id: probeInput
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        placeholderText: root.tr("diag.explain.probe-placeholder",
                            "hostname or IP")
                        text: section._probeInputText
                        enabled: !section._probing
                        onTextChanged: section._probeInputText = text
                        onAccepted: section._runExplainProbe()
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("diag.explain.probe-button", "Probe")
                        enabled: !section._probing
                        onClicked: section._runExplainProbe()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    visible: section._probing
                    text: root.tr("diag.explain.probing", "Probing...")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Initial idle state — no probe attempt yet.
                Label {
                    Layout.fillWidth: true
                    visible: !section._probing
                        && section._probeResultInput === ""
                        && section._probeReasonKey === ""
                        && section._probeErrorCode === ""
                    text: root.tr("diag.explain.empty",
                        "No explain sample available")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Success path — compact view from ExplainGetResponse.
                Label {
                    Layout.fillWidth: true
                    visible: !section._probing
                        && section._probeResultInput !== ""
                        && section._probeErrorCode === ""
                    text: section._probeResultInput
                        + "  →  "
                        + section._probeVerdictLabel()
                    color: root.textColor
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: !section._probing
                        && section._probeReasonKey !== ""
                        && section._probeErrorCode === ""
                    text: root.tr(section._probeReasonKey,
                        section._probeReasonKey)
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                // Enforcement caveat — the route resolved, but the flow may
                // currently be BLOCKED (block-all-unresolved, or fail-closed while
                // the additional adapter is down). Amber, second line under the route.
                Label {
                    Layout.fillWidth: true
                    visible: !section._probing
                        && section._probeEnforcement !== ""
                        && section._probeErrorCode === ""
                    // The collateral slugs append the
                    // "N of M cached addresses are shared" counts.
                    text: root.tr("diag.explain.enforcement." + section._probeEnforcement,
                        section._probeEnforcement)
                        + (section._probeEnforcementShared > 0
                            ? " (" + section._probeEnforcementShared + "/"
                                + section._probeEnforcementTotal + ")"
                            : "")
                    color: root.uiTheme.colorWarning
                    wrapMode: Text.WordWrap
                }
                // Validation / bridge / wire errors. Wire codes go
                // Through `root.ipcErrorLabel`;
                // local slugs ("input-required", "bridge-unavailable")
                // resolve via dedicated `diag.explain.*` keys.
                Label {
                    Layout.fillWidth: true
                    visible: !section._probing && section._probeErrorCode !== ""
                    text: {
                        var code = section._probeErrorCode
                        if (code === "input-required")
                            return root.tr("diag.explain.input-required",
                                "Enter a hostname or IP to probe")
                        if (code === "bridge-unavailable")
                            return root.tr("diag.explain.bridge-unavailable",
                                "Service bridge not connected — probe unavailable")
                        // Show only the localised slug label — the raw
                        // English wire message ("ipc client is not
                        // connected to service" etc.) is logged in
                        // _probeErrorMessage for diagnostics but never
                        // surfaced to the user-facing label.
                        return (typeof root.ipcErrorLabel === "function")
                            ? root.ipcErrorLabel(code) : code
                    }
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
