import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
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
    // user having to open the full viewer. Updates `root.diagCacheEntriesTotal` only;
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
                root.diagCacheEntriesTotal = Number(page.total_count)
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

    /// One line about where the service's start sits relative to the boot's
    /// sign-in phase. Empty when the host has no such record — the card then
    /// says nothing rather than implying the service was measured and cleared.
    ///
    /// Seconds, one decimal: the question is "did this take part in a wait the
    /// user felt", and milliseconds pretend to a precision the answer does not
    /// need.
    function _bootTimingText() {
        var health = section.serviceHealth || {}
        var relation = String(health.startRelativeToSignIn || "unknown")
        if (relation !== "after" && relation !== "before") return ""
        var gapMs = Number(health.startSignInGapMs)
        if (!isFinite(gapMs) || gapMs < 0) return ""
        var seconds = (gapMs / 1000).toFixed(1)
        return relation === "after"
            ? root.tr("diag.service.started-after-sign-in",
                "The service started %1 s after this boot reached the sign-in screen.").arg(seconds)
            : root.tr("diag.service.started-before-sign-in",
                "The service started %1 s before this boot reached the sign-in screen.").arg(seconds)
    }

    Component.onCompleted: {
        _refreshServiceHealth()
        _consumePendingExplainHost()
    }
    // Deep links into this section, both consumed once: a block notice carries
    // the host to probe, and Rules carries a request to open the connection
    // trace. Coming back later must not re-run what the user already saw.
    onVisibleChanged: {
        if (!visible)
            return
        section._consumePendingExplainHost()
        section._consumePendingConnTrace()
    }
    // Rules → "Where traffic is going" sets the flag; whichever happens last —
    // the flag or this section becoming visible — opens the panel.
    Connections {
        target: root
        function onDiagOpenConnTraceChanged() {
            if (section.visible)
                section._consumePendingConnTrace()
        }
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
        if (cacheHealth.healthy === false)
            return root.tr("diag.status.cache-stale", "Cache entries stale")
        return root.tr("diag.status.cache-healthy", "Cache healthy")
    }
    function _consumePendingConnTrace() {
        if (!root.diagOpenConnTrace)
            return
        root.diagOpenConnTrace = false
        // The trace lives in its own window now — the request from Rules
        // opens it instead of scrolling this section.
        var trace = root.connTraceWindow
        if (!trace) return
        root.openChildWindow(trace)
        trace._loadConnTraceEntries(true)
    }

    function _consumePendingExplainHost() {
        var host = String(root.notificationsController.pendingExplainHost || "").trim()
        if (host === "") return
        root.notificationsController.pendingExplainHost = ""
        // The probe lives in its own window now: hand the host over, then
        // open it. Opening first would run the probe against an empty input.
        var probe = root.ruleDiagnosticsWindow
        if (!probe) return
        probe._probeInputText = host
        root.openChildWindow(probe)
        probe._runExplainProbe()
    }
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


    // Read-only cache-entries viewer. On demand, pull the
    // FQDN/IP resolution cache page-by-page via `cache.entries.list`. The
    // service applies redaction (compact tier reduces hostnames to eTLD+1
    // and masks IPs) — `_cacheEntriesRedacted` drives the privacy notice.
    // Client-side filter across all visible columns. When set, the viewer
    // auto-pages the whole cache (see _loadCacheEntries) so the filter sees
    // every entry, not just the first loaded page.
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
                // "Did this slow my start-up" is what a background service gets
                // blamed for, so the card answers with the measurement rather
                // than with a claim. Hidden when the host cannot tell — an
                // unanswerable question must not read as an exoneration.
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    visible: section._bootTimingText() !== ""
                    text: section._bootTimingText()
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
                    ThemedRadioButton {
                        theme: root.uiTheme
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
                    ThemedRadioButton {
                        theme: root.uiTheme
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
                        text: root.tr("action.open-folder", "Open folder")
                        onClicked: {
                            if (section._exportArchiveDir === "") return
                            Pure.openExternalUrl(
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
                    color: cacheHealth.healthy === false
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
                        + (root.diagCacheEntriesTotal >= 0
                            ? String(root.diagCacheEntriesTotal)
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
                                    : root.tr("diag.cache.seed-browser-history.unavailable",
                                        "This feature is unavailable.")
                                // If the viewer is open, refresh so newly-seeded
                                // entries (source "Browser history") show up.
                                if (root.cacheWindow && root.cacheWindow.visible)
                                    root.cacheWindow._loadCacheEntries(true)
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
                                // Cache is now empty — refresh the viewer if it is open.
                                if (root.cacheWindow && root.cacheWindow.visible)
                                    root.cacheWindow._loadCacheEntries(true)
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
                        text: root.tr("diag.cache.open-window", "Open cache")
                        onClicked: {
                            var win = root.cacheWindow
                            if (!win) return
                            root.openChildWindow(win)
                            win._loadCacheEntries(true)
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

        // The connection trace moved to its own window: it is a live list read
        // beside the rules table, which a section in a StackLayout forbids.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            RowLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXxs
                    Label {
                        text: root.tr("diag.conn-trace.title", "Connection trace")
                        color: root.textColor
                        font.bold: true
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr("diag.conn-trace.card-summary",
                            "Which interface each outgoing connection actually left through.")
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                    }
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("diag.conn-trace.open-window", "Open connection trace")
                    onClicked: root.openChildWindow(root.connTraceWindow)
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

        // Rule diagnostics moved to its own window: the probe answers
        // "which rule would win for this destination", and that is read WHILE
        // editing rules, which a section in a StackLayout cannot allow.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            RowLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXxs
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
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("diag.explain.open-window", "Open rule diagnostics")
                    onClicked: root.openChildWindow(root.ruleDiagnosticsWindow)
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
