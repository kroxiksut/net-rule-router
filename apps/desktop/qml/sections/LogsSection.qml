import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../theme"
import "../components"
import "../lib/pure.js" as Pure

ColumnLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    readonly property var logsCtx: root.context.logs || ({})
    readonly property var auditCtx: root.context.audit || ({})

    // Accumulating pagination model.
    //
    // First page is seeded from the cold-start snapshot
    // (`context.logs.entries` / `context.audit.entries`); subsequent
    // pages are appended through `rpcLogsList` / `rpcAuditList` and
    // resolved by `next_cursor` (snake_case on the wire; the converter
    // helpers normalise to camelCase to keep the delegate code working
    // against a single shape).
    //
    // Manual Refresh resets the accumulator to a fresh first page via
    // RPC (cursor=""); changing filters re-runs the same path.
    property var _logEntries: []
    property var _auditEntries: []
    property string _logsCursor: ""
    property string _auditCursor: ""
    property bool _logsLoading: false
    property bool _auditLoading: false
    property string _logsError: ""
    property string _auditError: ""
    property bool _seeded: false

    property string activeTab: "operational"
    // Opt-in read-only security-audit viewer ("Show security audit tab" in
    // Settings -> Diagnostics and logs, default off). The audit trail itself is
    // recorded regardless; this only gates the tab. Kept as one shared property
    // so the tab button and the bar's current index cannot disagree.
    readonly property bool auditTabAvailable: root.uiRevision >= 0 ? !!root.prefs.showAuditTab : false
    property string filterLevel: "all"
    property string filterCategory: ""
    property string filterKind: ""
    // Default the operational view to the current app session so entries from
    // previous sessions (yesterday's rotated NDJSON files) don't clutter the
    // list. "all" widens back to the full history. Deliberately NOT the same
    // cutoff as the archive "session only" export: the view filters at
    // `root.appSessionStartMs` (this GUI launch), while the archive anchors to
    // `root.appSessionDayStartMs` (local midnight) so a mid-test restart
    // cannot drop the day's earlier rotated segments from a support bundle.
    property string logRange: "current-session"

    // Click-to-sort for both log tables (mirrors the rules
    // table). DEFAULT is newest-first: operational by time descending, audit
    // by seq descending (seq is monotonic, so that's also newest-first).
    // Clicking a header column sorts by it; clicking the active column flips
    // direction. Sorting runs over a derived VIEW (`_logEntriesView` /
    // `_auditEntriesView`) so the raw `_logEntries` / `_auditEntries`
    // accumulators that drive cursor pagination stay in arrival order.
    property string logSortBy: "by-time"
    property string logSortDir: "desc"
    property string auditSortBy: "by-seq"
    property string auditSortDir: "desc"

    function _cmpLog(a, b, by) {
        if (by === "by-level")    return String(a.level || "").localeCompare(String(b.level || ""))
        if (by === "by-category") return String(a.category || "").localeCompare(String(b.category || ""))
        if (by === "by-kind")     return String(a.kind || "").localeCompare(String(b.kind || ""))
        var d = Number(a.createdAt || 0) - Number(b.createdAt || 0)   // by-time
        return d < 0 ? -1 : (d > 0 ? 1 : 0)
    }
    function _cmpAudit(a, b, by) {
        if (by === "by-kind")     return String(a.kind || "").localeCompare(String(b.kind || ""))
        if (by === "by-result")   return String(a.result || "").localeCompare(String(b.result || ""))
        if (by === "by-reason")   return String(a.reasonCode || "").localeCompare(String(b.reasonCode || ""))
        if (by === "by-revision") return String(a.revisionId || "").localeCompare(String(b.revisionId || ""))
        if (by === "by-time")     { var dt = Number(a.createdAt || 0) - Number(b.createdAt || 0); return dt < 0 ? -1 : (dt > 0 ? 1 : 0) }
        var ds = Number(a.seq || 0) - Number(b.seq || 0)              // by-seq
        return ds < 0 ? -1 : (ds > 0 ? 1 : 0)
    }
    // Derived sorted views. The binding reads logSortBy/logSortDir/_logEntries
    // (and the audit trio), so it auto-recomputes when data OR sort changes.
    readonly property var _logEntriesView: {
        var by = section.logSortBy, dir = section.logSortDir
        var copy = (section._logEntries || []).slice()
        copy.sort(function(a, b) { var c = section._cmpLog(a, b, by); return dir === "desc" ? -c : c })
        return copy
    }
    readonly property var _auditEntriesView: {
        var by = section.auditSortBy, dir = section.auditSortDir
        var copy = (section._auditEntries || []).slice()
        copy.sort(function(a, b) { var c = section._cmpAudit(a, b, by); return dir === "desc" ? -c : c })
        return copy
    }
    function setLogSort(col) {
        if (section.logSortBy === col) {
            section.logSortDir = (section.logSortDir === "asc") ? "desc" : "asc"
        } else {
            section.logSortBy = col
            section.logSortDir = (col === "by-time") ? "desc" : "asc"
        }
    }
    function logSortArrow(col) {
        if (section.logSortBy !== col) return ""
        return section.logSortDir === "asc" ? " ▲" : " ▼"
    }
    function setAuditSort(col) {
        if (section.auditSortBy === col) {
            section.auditSortDir = (section.auditSortDir === "asc") ? "desc" : "asc"
        } else {
            section.auditSortBy = col
            section.auditSortDir = (col === "by-time" || col === "by-seq") ? "desc" : "asc"
        }
    }
    function auditSortArrow(col) {
        if (section.auditSortBy !== col) return ""
        return section.auditSortDir === "asc" ? " ▲" : " ▼"
    }

    function _logEntryFromWire(w) {
        if (!w) return {}
        return {
            eventId: String(w.event_id || ""),
            createdAt: Number(w.created_at || 0),
            level: String(w.level || ""),
            category: String(w.category || ""),
            kind: String(w.kind || ""),
            messageKey: String(w.message_key || ""),
            hasPayload: !!w.has_payload,
            correlationSummary: w.correlation_summary || []
        }
    }
    function _auditEntryFromWire(w) {
        if (!w) return {}
        return {
            eventId: String(w.event_id || ""),
            seq: Number(w.seq || 0),
            kind: String(w.kind || ""),
            createdAt: Number(w.created_at || 0),
            result: String(w.result || ""),
            reasonCode: String(w.reason_code || ""),
            revisionId: w.revision_id ? String(w.revision_id) : "",
            hasPayloadSummary: !!w.has_payload_summary
        }
    }
    function _seedFromSnapshot() {
        _logEntries = (logsCtx.entries || []).slice()
        _logsCursor = String(logsCtx.nextPageToken || "")
        _auditEntries = (auditCtx.entries || []).slice()
        _auditCursor = String(auditCtx.nextPageToken || "")
        _seeded = true
    }
    function _bridgeHasPagination() {
        return root.bridgeAvailable
            && typeof nrrNativeBridge !== "undefined"
            && nrrNativeBridge !== null
            && typeof nrrNativeBridge.rpcLogsList === "function"
            && typeof nrrNativeBridge.rpcAuditList === "function"
    }
    function _refreshLogs() {
        if (_logsLoading) return
        if (!_bridgeHasPagination()) {
            _logsError = "bridge-unavailable"
            return
        }
        _logsLoading = true
        _logsError = ""
        var corr = nrrNativeBridge.rpcLogsList({}, "", 50)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._logsLoading = false
            if (!ok) {
                section._logsError = String(errorCode || "unknown")
                return
            }
            var items = (payload && payload.items) || []
            var converted = []
            for (var i = 0; i < items.length; i++) {
                converted.push(section._logEntryFromWire(items[i]))
            }
            section._logEntries = converted
            section._logsCursor = String((payload && payload.next_cursor) || "")
        })
    }
    function _loadMoreLogs() {
        if (_logsLoading) return
        if (_logsCursor === "") return
        if (!_bridgeHasPagination()) {
            _logsError = "bridge-unavailable"
            return
        }
        _logsLoading = true
        _logsError = ""
        var corr = nrrNativeBridge.rpcLogsList({}, _logsCursor, 50)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._logsLoading = false
            if (!ok) {
                section._logsError = String(errorCode || "unknown")
                return
            }
            var items = (payload && payload.items) || []
            var converted = []
            for (var i = 0; i < items.length; i++) {
                converted.push(section._logEntryFromWire(items[i]))
            }
            section._logEntries = section._logEntries.concat(converted)
            section._logsCursor = String((payload && payload.next_cursor) || "")
        })
    }
    function _refreshAudit() {
        if (_auditLoading) return
        if (!_bridgeHasPagination()) {
            _auditError = "bridge-unavailable"
            return
        }
        _auditLoading = true
        _auditError = ""
        var corr = nrrNativeBridge.rpcAuditList({}, "", 50)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._auditLoading = false
            if (!ok) {
                section._auditError = String(errorCode || "unknown")
                return
            }
            var items = (payload && payload.items) || []
            var converted = []
            for (var i = 0; i < items.length; i++) {
                converted.push(section._auditEntryFromWire(items[i]))
            }
            section._auditEntries = converted
            section._auditCursor = String((payload && payload.next_cursor) || "")
        })
    }
    function _loadMoreAudit() {
        if (_auditLoading) return
        if (_auditCursor === "") return
        if (!_bridgeHasPagination()) {
            _auditError = "bridge-unavailable"
            return
        }
        _auditLoading = true
        _auditError = ""
        var corr = nrrNativeBridge.rpcAuditList({}, _auditCursor, 50)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._auditLoading = false
            if (!ok) {
                section._auditError = String(errorCode || "unknown")
                return
            }
            var items = (payload && payload.items) || []
            var converted = []
            for (var i = 0; i < items.length; i++) {
                converted.push(section._auditEntryFromWire(items[i]))
            }
            section._auditEntries = section._auditEntries.concat(converted)
            section._auditCursor = String((payload && payload.next_cursor) || "")
        })
    }

    // Prime the shared verbose-logging flag from the service so the
    // filter-bar checkbox is accurate the first time the Logs view is
    // opened (the Settings -> Diagnostics twin may not have loaded yet).
    // A pure GET — never a Set — so it raises no elevation prompt. Also
    // re-run whenever the user navigates back to this section (see the
    // Connections block below) so it never drifts from a change made
    // elsewhere while the resident section stayed loaded.
    function _fetchVerboseLogging() {
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            return
        }
        var corr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (!ok || !payload) return
            var verbose = payload["verbose-logging"]
            if (verbose === undefined) verbose = payload.verbose_logging
            root.serviceVerboseLogging = !!verbose
        })
    }

    Component.onCompleted: {
        _seedFromSnapshot()
        _fetchVerboseLogging()
    }

    function formatCreatedAt(ms) {
        var n = Number(ms || 0)
        if (!isFinite(n) || n <= 0) return "-"
        // Render in the user's local timezone — the wire field
        // `created_at` is UTC milliseconds; toISOString would force
        // UTC and not reflect the actual wall-clock the user sees.
        var d = new Date(n)
        function pad(x) { return (x < 10 ? "0" : "") + String(x) }
        var date = d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate())
        var time = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds())
        // Compute the local UTC offset suffix so the column is self-
        // documenting (e.g., "+03:00") and the user can correlate
        // with server-side NDJSON which is recorded in UTC ms.
        var offMin = -d.getTimezoneOffset()
        var sign = offMin >= 0 ? "+" : "-"
        var abs = Math.abs(offMin)
        var off = sign + pad(Math.floor(abs / 60)) + ":" + pad(abs % 60)
        return date + " " + time + " " + off
    }
    function formatMessage(entry) {
        var text = root.tr(String(entry.messageKey || ""), String(entry.kind || ""))
        var corr = entry.correlationSummary || []
        for (var i = 0; i < corr.length; i += 1) {
            text = text.replace("{" + i + "}", String(corr[i]))
        }
        return text
    }
    function passesFilter(entry) {
        // Session range: hide entries recorded before the current app session
        // (matches the archive "session only" cutoff). "all" disables it.
        if (section.logRange === "current-session") {
            var cutoff = Number(root.appSessionStartMs || 0)
            if (cutoff > 0 && Number(entry.createdAt || 0) < cutoff) return false
        }
        if (filterLevel !== "all") {
            var levelOrder = { "trace": 0, "debug": 1, "info": 2, "warn": 3, "error": 4 }
            var min = levelOrder[filterLevel]
            var cur = levelOrder[String(entry.level || "info")]
            if (min === undefined || cur === undefined || cur < min) return false
        }
        if (filterCategory !== "" && filterCategory !== String(entry.category || "")) return false
        if (filterKind !== "" && String(entry.kind || "").indexOf(filterKind) < 0) return false
        return true
    }

    Label { text: root.sectionTitle("logs"); color: root.textColor; font.bold: true }

    // D1: TabBar
    TabBar {
        id: logsTabBar
        Layout.fillWidth: true
        // Index 1 exists only while the audit tab is available; without the
        // guard the bar would select a collapsed, invisible button.
        currentIndex: section.auditTabAvailable && section.activeTab === "audit" ? 1 : 0
        // BOTH buttons carry an explicit width on purpose.
        //
        // A TabBar does not lay its buttons out like a Row: it distributes the
        // bar width across every button that has NO explicit width (an explicit
        // width opts a button out of that distribution and reserves it), and it
        // positions the results through an internal horizontal ListView.
        // Giving an explicit width to the audit button ALONE was the defect:
        // the operational button stayed "distributable" and was therefore
        // stretched to the whole bar width, so the moment the audit button grew
        // from 0 to its natural width it was positioned past the right edge of
        // that ListView viewport and never became visible. Re-distribution runs
        // on item add/remove and implicit-size changes, not when a sibling's
        // explicit width changes, so nothing corrected the stale full-width
        // sibling and the tab stayed off-screen for the whole session.
        //
        // With both widths explicit there is no distribution left to fight:
        // each button occupies exactly its own width, the hidden one collapses
        // to zero (no gap in the bar), and toggling the preference resizes that
        // single button in place - its x position already follows the
        // operational button, so the tab appears immediately.
        TabButton {
            width: implicitWidth
            text: root.tr("logs.tab.operational", "Operational")
            onClicked: section.activeTab = "operational"
        }
        TabButton {
            id: auditTabButton
            visible: section.auditTabAvailable
            width: visible ? implicitWidth : 0
            text: root.tr("logs.tab.audit", "Audit")
            onClicked: section.activeTab = "audit"
        }
    }

    // When the audit viewing tab is turned off in settings, never leave the
    // Logs view stranded on the now-hidden tab — snap it back to Operational.
    Connections {
        target: root
        function onUiRevisionChanged() {
            if (!root.prefs.showAuditTab && section.activeTab === "audit")
                section.activeTab = "operational"
        }
        // Resident-section refresh: the Logs view stays loaded once opened,
        // so re-read the shared verbose-logging flag each time the user
        // navigates back to it to reflect a change made elsewhere.
        function onSectionChanged() {
            if (root.section === "logs") section._fetchVerboseLogging()
        }
    }

    // D2: Filter bar (only applies to operational)
    RowLayout {
        Layout.fillWidth: true
        visible: activeTab === "operational"
        spacing: root.uiTheme.spacingSm
        Label { text: root.tr("diag.logs.filter-time-range", "Time range"); color: root.textColor }
        ThemedComboBox {
            id: rangeCombo
            theme: root.uiTheme
            Layout.preferredWidth: 180
            model: [ "current-session", "all" ]
            currentIndex: 0
            function rangeLabel(id) {
                if (id === "all") return root.tr("diag.logs.range-all", "All history")
                return root.tr("diag.logs.range-current-session", "Current session")
            }
            labelResolver: function(item) { return rangeCombo.rangeLabel(item) }
            displayText: rangeLabel(model[currentIndex])
            popup.width: root.comboPopupWidth(rangeCombo, rangeCombo.model, "",
                function(item) { return rangeCombo.rangeLabel(item) })
            onActivated: section.logRange = model[currentIndex]
        }
        Label { text: root.tr("diag.logs.filter-level", "Level"); color: root.textColor }
        ThemedComboBox {
            id: levelCombo
            theme: root.uiTheme
            Layout.preferredWidth: 160
            model: [ "all", "info", "warn", "error" ]
            currentIndex: 0
            function levelLabel(id) {
                if (id === "all") return root.tr("diag.logs.filter-all-levels", "All levels")
                return root.tr("diag.logs.level-" + id, id)
            }
            labelResolver: function(item) { return levelCombo.levelLabel(item) }
            displayText: levelLabel(model[currentIndex])
            popup.width: root.comboPopupWidth(levelCombo, levelCombo.model, "",
                function(item) { return levelCombo.levelLabel(item) })
            onActivated: section.filterLevel = model[currentIndex]
        }
        Label { text: root.tr("diag.logs.filter-category", "Category"); color: root.textColor }
        ThemedTextField {
            theme: root.uiTheme
            Layout.preferredWidth: 160
            placeholderText: root.tr("diag.logs.filter-category", "Category")
            onEditingFinished: section.filterCategory = text.trim()
        }
        Label { text: root.tr("diag.logs.filter-kind", "Event type"); color: root.textColor }
        ThemedTextField {
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.minimumWidth: 220
            Layout.preferredWidth: 260
            placeholderText: root.tr("diag.logs.filter-kind", "Event type")
            onEditingFinished: section.filterKind = text.trim()
        }
    }

    RowLayout {
        Layout.fillWidth: true
        visible: activeTab === "operational"
        spacing: root.uiTheme.spacingSm
        // Duplicate of the Settings -> Diagnostics "Verbose service logging"
        // toggle, surfaced here so the user can flip it right where they read
        // the logs. Bound to the shared `root.serviceVerboseLogging` (a Binding
        // re-asserts `checked` from it, restoring the visual state if a live
        // apply fails), applied through the same live path used by Settings.
        CheckBox {
            id: verboseLoggingCheck
            text: root.tr(
                "settings.diagnostics.service-stability.verbose.label",
                "Verbose service logging")
            onToggled: root.applyVerboseLogging(checked, "user:logs-verbose-toggle")
            Binding {
                target: verboseLoggingCheck
                property: "checked"
                value: root.serviceVerboseLogging
            }
            contentItem: Text {
                text: verboseLoggingCheck.text
                leftPadding: verboseLoggingCheck.indicator.width
                    + verboseLoggingCheck.spacing
                verticalAlignment: Text.AlignVCenter
                color: root.textColor
            }
            ToolTip.visible: hovered
            ToolTip.delay: 400
            ToolTip.text: root.tr(
                "settings.diagnostics.service-stability.verbose.tooltip",
                "When enabled, the service writes tracing::debug events to operational NDJSON. Applies immediately, no restart required.")
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
        }
        Label {
            visible: section._logsError !== ""
            text: root.tr("logs.pagination.error-prefix", "Load failed")
                + ": "
                + ((typeof root.ipcErrorLabel === "function")
                    ? root.ipcErrorLabel(section._logsError) : section._logsError)
            color: root.uiTheme.colorAccent
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Item { Layout.fillWidth: true; visible: section._logsError === "" }
        ThemedButton {
            theme: root.uiTheme
            enabled: !section._logsLoading
            text: section._logsLoading
                ? root.tr("logs.pagination.loading", "Loading...")
                : root.tr("action.refresh", "Refresh")
            onClicked: section._refreshLogs()
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("diag.logs.clear-button", "Clear logs")
            icon.source: root.uiIconSource("clear")
            onClicked: clearLogsConfirm.open()
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.logsFolderAction.text
            onClicked: root.logsFolderAction.trigger()
        }
    }

    // Confirmation dialog for the Clear button. Mirrors the body of
    // the equivalent dialog in DiagnosticsLogsSettings so users get the
    // same affordance regardless of where they trigger cleanup from.
    // Backed by the real `logs.clear` IPC op; the audit trail is never touched.
    property bool _clearing: false
    function _performLogsClear() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcLogsClear !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        section._clearing = true
        var corr = nrrNativeBridge.rpcLogsClear(false, false)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            section._clearing = false
            if (!ok) {
                root.statusLine = root.tr("status.logs-cleared-failed",
                    "Failed to clear logs: ") + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            var files = Number((payload && payload["files-deleted"]) || 0)
            var bytes = Number((payload && payload["bytes-freed"]) || 0)
            root.statusLine = root.tr("status.logs-cleared",
                "Operational logs cleared: {count} file(s), {size}")
                .replace("{count}", String(files))
                .replace("{size}", Pure.formatStorageBytes(bytes))
            section._refreshLogs()
        })
    }
    Dialog {
        id: clearLogsConfirm
        modal: true
        title: root.tr("diag.logs.clear-confirm-title", "Clear operational logs?")
        x: Math.round((section.Window.width - width) / 2)
        y: Math.round((section.Window.height - height) / 2)
        width: 460
        ColumnLayout {
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.preferredWidth: 400
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("diag.logs.clear-confirm-body",
                    "This will permanently delete log files. The audit trail will not be affected.")
            }
            RowLayout {
                Layout.alignment: Qt.AlignRight
                spacing: root.uiTheme.spacingSm
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.confirm", "Confirm")
                    enabled: !section._clearing
                    onClicked: {
                        clearLogsConfirm.close()
                        section._performLogsClear()
                    }
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: clearLogsConfirm.close()
                }
            }
        }
    }

    // D5-D6: Action row for audit tab (Refresh + Open folder)
    RowLayout {
        Layout.fillWidth: true
        visible: activeTab === "audit"
        spacing: root.uiTheme.spacingSm
        ThemedButton {
            theme: root.uiTheme
            enabled: !section._auditLoading
            text: section._auditLoading
                ? root.tr("logs.pagination.loading", "Loading...")
                : root.tr("action.refresh", "Refresh")
            onClicked: section._refreshAudit()
        }
        // The audit trail is intentionally never clearable
        // (append-only, tamper-evident). A permanently-disabled "Clear logs"
        // button read as broken; an info line states the design intent instead.
        Label {
            Layout.fillWidth: true
            Layout.maximumWidth: 420
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            verticalAlignment: Text.AlignVCenter
            text: root.tr("audit.clear-disabled-tooltip",
                "The audit trail cannot be cleared by design. Use the Operational tab to clear runtime logs.")
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.logsFolderAction.text
            onClicked: root.logsFolderAction.trigger()
        }
        Label {
            visible: section._auditError !== ""
            text: root.tr("logs.pagination.error-prefix", "Load failed")
                + ": "
                + ((typeof root.ipcErrorLabel === "function")
                    ? root.ipcErrorLabel(section._auditError) : section._auditError)
            color: root.uiTheme.colorAccent
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Item { Layout.fillWidth: true; visible: section._auditError === "" }
    }

    // D3-H: Operational table header. Mirrors the column widths of
    // the delegate below so the table stays aligned; updates to one
    // side must mirror the other.
    Frame {
        Layout.fillWidth: true
        visible: activeTab === "operational"
        padding: root.uiTheme.spacingSm
        background: Rectangle {
            color: root.uiTheme.colorPanel
            border.width: root.uiTheme.borderWidth
            border.color: root.uiTheme.stateDefaultBorder
            radius: root.uiTheme.radiusSm
        }
        RowLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.preferredWidth: 170
                text: root.tr("logs.column.time", "Time") + section.logSortArrow("by-time")
                color: section.logSortBy === "by-time" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setLogSort("by-time") }
            }
            Label {
                Layout.preferredWidth: 140
                text: root.tr("logs.column.level", "Level") + section.logSortArrow("by-level")
                color: section.logSortBy === "by-level" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                elide: Text.ElideRight
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setLogSort("by-level") }
            }
            Label {
                Layout.preferredWidth: 120
                text: root.tr("logs.column.category", "Category") + section.logSortArrow("by-category")
                color: section.logSortBy === "by-category" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setLogSort("by-category") }
            }
            Label {
                Layout.preferredWidth: 180
                text: root.tr("logs.column.kind", "Event type") + section.logSortArrow("by-kind")
                color: section.logSortBy === "by-kind" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setLogSort("by-kind") }
            }
            Label {
                Layout.fillWidth: true
                text: root.tr("logs.column.message", "Message")
                color: root.textColor
                font.bold: true
            }
        }
    }

    // D3: Operational ListView
    ListView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: activeTab === "operational"
        clip: true
        spacing: root.uiTheme.spacingXxs
        model: section._logEntriesView
        header: Item {
            visible: section._logEntries.length === 0
            width: ListView.view ? ListView.view.width : 0
            height: visible ? emptyOp.implicitHeight + root.uiTheme.spacingMd : 0
            Label {
                id: emptyOp
                anchors.centerIn: parent
                text: root.tr("diag.logs.empty", "No log entries")
                color: root.mutedTextColor
            }
        }
        delegate: Frame {
            id: opRow
            width: ListView.view ? ListView.view.width : 0
            visible: passesFilter(modelData)
            height: visible ? rowBody.implicitHeight + padding * 2 : 0
            padding: root.uiTheme.spacingSm
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            readonly property string _rowPlainText:
                formatCreatedAt(modelData.createdAt)
                    + "\t" + String(modelData.level || "").toUpperCase()
                    + "\t" + String(modelData.category || "")
                    + "\t" + String(modelData.kind || "")
                    + "\t" + formatMessage(modelData)
            // Whole-row right-click → copy entire row as TSV. Lives
            // BEHIND the layout so the message TextEdit's mouse
            // selection still works (TextEdit's MouseArea is on top
            // by virtue of being painted later in z-order).
            MouseArea {
                anchors.fill: parent
                acceptedButtons: Qt.RightButton
                onClicked: function(mouse) {
                    opRowMenu.x = mouse.x
                    opRowMenu.y = mouse.y
                    opRowMenu.open()
                }
            }
            Menu {
                id: opRowMenu
                MenuItem {
                    text: root.tr("action.copy-row", "Copy row")
                    onTriggered: {
                        if (typeof nrrNativeBridge !== "undefined"
                                && nrrNativeBridge
                                && typeof nrrNativeBridge.copyToClipboard === "function") {
                            nrrNativeBridge.copyToClipboard(opRow._rowPlainText)
                            root.statusLine = root.tr("status.copied-to-clipboard", "Copied to clipboard.")
                        }
                    }
                }
                MenuItem {
                    text: root.tr("action.copy-message", "Copy message")
                    onTriggered: {
                        if (typeof nrrNativeBridge !== "undefined"
                                && nrrNativeBridge
                                && typeof nrrNativeBridge.copyToClipboard === "function") {
                            nrrNativeBridge.copyToClipboard(formatMessage(modelData))
                            root.statusLine = root.tr("status.copied-to-clipboard", "Copied to clipboard.")
                        }
                    }
                }
            }
            RowLayout {
                id: rowBody
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.preferredWidth: 170
                    text: formatCreatedAt(modelData.createdAt)
                    color: root.mutedTextColor
                }
                Label {
                    Layout.preferredWidth: 140
                    // Level cell uses the same localised label as the
                    // filter dropdown (`diag.logs.level-{slug}`); the
                    // raw slug ("INFO", "WARN") is preserved as
                    // fallback for unexpected values. RU labels are
                    // long words ("Предупреждение") so the column
                    // must be wide enough to avoid overlapping the
                    // category column; elide as a safety net.
                    text: root.tr("diag.logs.level-" + String(modelData.level || ""),
                                  String(modelData.level || "").toUpperCase())
                    color: modelData.level === "error" || modelData.level === "warn"
                        ? root.uiTheme.colorAccent : root.textColor
                    elide: Text.ElideRight
                }
                Label {
                    Layout.preferredWidth: 120
                    text: String(modelData.category || "")
                    color: root.mutedTextColor
                    elide: Text.ElideRight
                }
                Label {
                    Layout.preferredWidth: 180
                    text: String(modelData.kind || "")
                    color: root.textColor
                    elide: Text.ElideRight
                }
                // Message column: TextEdit (read-only) lets the user
                // select + Ctrl+C inline without the right-click menu.
                // Wrapped in TextEdit so each row's content is
                // independently selectable; we forward right-click to
                // the row-level menu by NOT consuming the press.
                TextEdit {
                    Layout.fillWidth: true
                    text: formatMessage(modelData)
                    color: root.textColor
                    wrapMode: TextEdit.Wrap
                    readOnly: true
                    selectByMouse: true
                    selectByKeyboard: true
                    persistentSelection: false
                }
                Label {
                    visible: modelData.hasPayload === true
                    text: "●"
                    color: root.uiTheme.colorAccent
                }
            }
        }
        footer: ThemedButton {
            theme: root.uiTheme
            width: ListView.view ? ListView.view.width : 0
            // Wire to the real pagination path (was a preview
            // no-op). Track the live accumulator cursor, not the cold-start
            // snapshot token, so the button hides when pagination is exhausted.
            visible: section._logsCursor !== ""
            enabled: !section._logsLoading
            text: section._logsLoading
                ? root.tr("logs.pagination.loading", "Loading...")
                : root.tr("logs.pagination.load-more", "Load more")
            onClicked: section._loadMoreLogs()
        }
    }

    // D4-H: Audit table header. Column widths mirror the delegate.
    Frame {
        Layout.fillWidth: true
        visible: activeTab === "audit"
        padding: root.uiTheme.spacingSm
        background: Rectangle {
            color: root.uiTheme.colorPanel
            border.width: root.uiTheme.borderWidth
            border.color: root.uiTheme.stateDefaultBorder
            radius: root.uiTheme.radiusSm
        }
        RowLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.preferredWidth: 60
                text: root.tr("audit.column.seq", "Seq") + section.auditSortArrow("by-seq")
                color: section.auditSortBy === "by-seq" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setAuditSort("by-seq") }
            }
            Label {
                Layout.preferredWidth: 170
                text: root.tr("logs.column.time", "Time") + section.auditSortArrow("by-time")
                color: section.auditSortBy === "by-time" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setAuditSort("by-time") }
            }
            Label {
                Layout.preferredWidth: 180
                text: root.tr("audit.column.kind", "Kind") + section.auditSortArrow("by-kind")
                color: section.auditSortBy === "by-kind" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setAuditSort("by-kind") }
            }
            Label {
                Layout.preferredWidth: 90
                text: root.tr("audit.column.result", "Result") + section.auditSortArrow("by-result")
                color: section.auditSortBy === "by-result" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setAuditSort("by-result") }
            }
            Label {
                Layout.preferredWidth: 220
                text: root.tr("audit.column.reason", "Reason") + section.auditSortArrow("by-reason")
                color: section.auditSortBy === "by-reason" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setAuditSort("by-reason") }
            }
            Label {
                Layout.fillWidth: true
                text: root.tr("audit.column.revision", "Revision") + section.auditSortArrow("by-revision")
                color: section.auditSortBy === "by-revision" ? root.uiTheme.colorAccent : root.textColor
                font.bold: true
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: section.setAuditSort("by-revision") }
            }
        }
    }

    // D4: Audit ListView
    ListView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: activeTab === "audit"
        clip: true
        spacing: root.uiTheme.spacingXxs
        model: section._auditEntriesView
        header: Item {
            visible: section._auditEntries.length === 0
            width: ListView.view ? ListView.view.width : 0
            height: visible ? emptyAu.implicitHeight + root.uiTheme.spacingMd : 0
            Label {
                id: emptyAu
                anchors.centerIn: parent
                text: root.tr("diag.audit.empty", "No audit entries")
                color: root.mutedTextColor
            }
        }
        delegate: Frame {
            id: auRow
            width: ListView.view ? ListView.view.width : 0
            padding: root.uiTheme.spacingSm
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            readonly property string _rowPlainText:
                "seq=" + String(modelData.seq || 0)
                    + "\t" + formatCreatedAt(modelData.createdAt)
                    + "\t" + String(modelData.kind || "")
                    + "\t" + String(modelData.result || "")
                    + "\t" + String(modelData.reasonCode || "")
                    + "\t" + (modelData.revisionId ? String(modelData.revisionId) : "")
            MouseArea {
                anchors.fill: parent
                acceptedButtons: Qt.RightButton
                onClicked: function(mouse) {
                    auRowMenu.x = mouse.x
                    auRowMenu.y = mouse.y
                    auRowMenu.open()
                }
            }
            Menu {
                id: auRowMenu
                MenuItem {
                    text: root.tr("action.copy-row", "Copy row")
                    onTriggered: {
                        if (typeof nrrNativeBridge !== "undefined"
                                && nrrNativeBridge
                                && typeof nrrNativeBridge.copyToClipboard === "function") {
                            nrrNativeBridge.copyToClipboard(auRow._rowPlainText)
                            root.statusLine = root.tr("status.copied-to-clipboard", "Copied to clipboard.")
                        }
                    }
                }
            }
            RowLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.preferredWidth: 60
                    text: root.tr("audit.column.seq", "Seq") + " " + String(modelData.seq || 0)
                    color: root.mutedTextColor
                }
                Label {
                    Layout.preferredWidth: 170
                    text: formatCreatedAt(modelData.createdAt)
                    color: root.mutedTextColor
                }
                Label {
                    Layout.preferredWidth: 180
                    text: String(modelData.kind || "")
                    color: root.textColor
                    elide: Text.ElideRight
                }
                Label {
                    Layout.preferredWidth: 90
                    text: String(modelData.result || "")
                    color: modelData.result === "failure" || modelData.result === "blocked"
                        ? root.uiTheme.colorAccent : root.textColor
                }
                TextEdit {
                    Layout.preferredWidth: 220
                    text: String(modelData.reasonCode || "")
                    color: root.mutedTextColor
                    wrapMode: TextEdit.NoWrap
                    readOnly: true
                    selectByMouse: true
                    selectByKeyboard: true
                }
                TextEdit {
                    Layout.fillWidth: true
                    text: modelData.revisionId ? String(modelData.revisionId) : ""
                    color: root.mutedTextColor
                    wrapMode: TextEdit.NoWrap
                    readOnly: true
                    selectByMouse: true
                    selectByKeyboard: true
                }
            }
        }
        footer: ThemedButton {
            theme: root.uiTheme
            width: ListView.view ? ListView.view.width : 0
            visible: section._auditCursor !== ""
            enabled: !section._auditLoading
            text: section._auditLoading
                ? root.tr("logs.pagination.loading", "Loading...")
                : root.tr("logs.pagination.load-more", "Load more")
            onClicked: section._loadMoreAudit()
        }
    }
}
