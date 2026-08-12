import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../theme"
import "../../components"
import "../../flows"
import "../../lib/pure.js" as Pure

GroupBox {
    id: group
    property var root
    title: root.tr("diag.section.title", "Diagnostics and Logs")
    Layout.fillWidth: true

    readonly property var diagCtx: root.context.diagnosticsSettings || {}
    readonly property var retentionCtx: diagCtx.retention || {}
    readonly property var storageHealth: diagCtx.storageHealth || {}
    readonly property var auditChain: diagCtx.auditChain || {}
    readonly property int defaultLogsMaxAgeDays: 90
    readonly property int defaultLogsMaxSizeMb: 50
    readonly property int defaultAuditMaxAgeDays: 365
    readonly property int defaultAuditMaxSizeMb: 50

    // Diagnostic-archive privacy tier forwarded as the 4th arg to
    // rpcDiagnosticsExportArchive: "standard" (default, redacted) or
    // "diagnostics" (extra cache/storage/decision detail, less redacted).
    // The value lives on `root` (shared with the Diagnostics-section export
    // surface) so both radios present ONE choice, and is persisted through the
    // preferences store so it survives a restart. The companion
    // `root.diagnosticsArchiveSessionOnly` (default ON) trims the archive to
    // the session's calendar day by sending `root.appSessionDayStartMs` as the
    // logs cutoff, so yesterday's rotated segments stay out of a routine
    // support archive while an app/service restart mid-test keeps the whole
    // day's history. Unchecked → full history.

    function formatBytes(value) {
        var n = Number(value || 0)
        if (!isFinite(n) || n < 0) n = 0
        if (n < 1024) return n + " B"
        if (n < 1048576) return (n / 1024).toFixed(1) + " KB"
        if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB"
        return (n / 1073741824).toFixed(2) + " GB"
    }

    // Real "Clear logs" wiring (the dialog Apply was a
    // no-op stub). Mirrors LogsSection._performLogsClear; reuses the already-
    // shipped `rpcLogsClear` op. Audit trail is never touched (service-side
    // invariant). All status keys already exist in both locales.
    property bool _clearing: false
    function _performLogsClear() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcLogsClear !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Service bridge not connected.")
            return
        }
        group._clearing = true
        var corr = nrrNativeBridge.rpcLogsClear(false, false)
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            group._clearing = false
            if (!ok) {
                root.statusLine = root.tr("status.logs-cleared-failed", "Failed to clear logs: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            var files = Number((payload && payload["files-deleted"]) || 0)
            var bytes = Number((payload && payload["bytes-freed"]) || 0)
            root.statusLine = root.tr("status.logs-cleared",
                "Operational logs cleared: {count} file(s), {size}")
                .replace("{count}", String(files))
                .replace("{size}", group.formatBytes(bytes))
        })
    }

    // Real log/audit retention Apply (was a "preview
    // applied" no-op). Reads the SpinBoxes + unit combos, converts sizes to
    // bytes, and persists via the settings.log-retention.set op. A fetch on
    // open populates the controls from the authoritative persisted config.
    property bool _logRetentionApplying: false
    // Dirty-tracking baseline — last-loaded/last-applied values, captured in
    // raw units (days / bytes) so a unit-combo change that leaves the number
    // the same but changes the underlying byte value still counts as dirty.
    property int _logRetentionBaselineLogsMaxAgeDays: 0
    property real _logRetentionBaselineLogsMaxSizeBytes: 0
    property int _logRetentionBaselineAuditMaxAgeDays: 0
    property real _logRetentionBaselineAuditMaxSizeBytes: 0
    readonly property bool _logRetentionDirty:
        logsMaxAge.value !== _logRetentionBaselineLogsMaxAgeDays
        || (logsMaxSize.value * group._sizeUnitMultiplier(logsSizeUnitCombo.currentIndex))
            !== _logRetentionBaselineLogsMaxSizeBytes
        || auditMaxAge.value !== _logRetentionBaselineAuditMaxAgeDays
        || (auditMaxSize.value * group._sizeUnitMultiplier(auditSizeUnitCombo.currentIndex))
            !== _logRetentionBaselineAuditMaxSizeBytes
    function _sizeUnitMultiplier(idx) {
        // combo order: 0=kb, 1=mb (MiB), 2=gb (GiB).
        if (idx === 0) return 1024
        if (idx === 2) return 1073741824
        return 1048576
    }
    function _captureLogRetentionBaseline() {
        _logRetentionBaselineLogsMaxAgeDays = logsMaxAge.value
        _logRetentionBaselineLogsMaxSizeBytes =
            logsMaxSize.value * group._sizeUnitMultiplier(logsSizeUnitCombo.currentIndex)
        _logRetentionBaselineAuditMaxAgeDays = auditMaxAge.value
        _logRetentionBaselineAuditMaxSizeBytes =
            auditMaxSize.value * group._sizeUnitMultiplier(auditSizeUnitCombo.currentIndex)
    }
    function _populateLogRetention(dto) {
        if (!dto) return
        if (dto["log-max-age-days"] !== undefined)
            logsMaxAge.value = Number(dto["log-max-age-days"])
        if (dto["log-max-size-bytes"] !== undefined) {
            logsSizeUnitCombo.currentIndex = 1 // display in MB
            logsMaxSize.value = Math.max(1,
                Math.round(Number(dto["log-max-size-bytes"]) / 1048576))
        }
        if (dto["audit-max-age-days"] !== undefined)
            auditMaxAge.value = Number(dto["audit-max-age-days"])
        if (dto["audit-max-size-bytes"] !== undefined) {
            auditSizeUnitCombo.currentIndex = 1 // display in MB
            auditMaxSize.value = Math.max(1,
                Math.round(Number(dto["audit-max-size-bytes"]) / 1048576))
        }
        // Loaded (or re-loaded after a successful apply) — reset the dirty baseline.
        group._captureLogRetentionBaseline()
    }
    function _applyLogRetention() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcLogRetentionConfigSet !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable", "Service bridge not connected.")
            return
        }
        var payload = {
            "log-max-age-days": Math.round(logsMaxAge.value),
            "log-max-size-bytes": Math.round(logsMaxSize.value)
                * group._sizeUnitMultiplier(logsSizeUnitCombo.currentIndex),
            "audit-max-age-days": Math.round(auditMaxAge.value),
            "audit-max-size-bytes": Math.round(auditMaxSize.value)
                * group._sizeUnitMultiplier(auditSizeUnitCombo.currentIndex)
        }
        group._logRetentionApplying = true
        var corr = nrrNativeBridge.rpcLogRetentionConfigSet(payload)
        root.rpc.registerRpcCallback(corr, function(ok, resp, errorCode, errorMessage) {
            group._logRetentionApplying = false
            if (!ok) {
                root.statusLine = root.tr("status.log-retention-failed",
                    "Failed to save retention settings: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            // resp is the authoritative LogRetentionConfigDto echo.
            group._populateLogRetention(resp)
            root.statusLine = root.tr("status.log-retention-saved", "Retention settings saved.")
        })
    }
    function _fetchLogRetentionConfig() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcLogRetentionConfigGet !== "function") {
            return // keep the launch-context defaults
        }
        var corr = nrrNativeBridge.rpcLogRetentionConfigGet()
        root.rpc.registerRpcCallback(corr, function(ok, resp, errorCode, errorMessage) {
            if (ok) group._populateLogRetention(resp)
        })
    }

    // + S2 — Service stability config. Draft buffer
    // Mirrors `ServiceStabilityConfigDto`.
    // Numeric fields persist across recoverable↔critical toggles so a
    // user does not lose their input when previewing the other mode.
    // `backoffCapSec` is the **only** field shown in user-friendly
    // seconds; on the wire it is multiplied by 1000 to match the
    // schema's `backoff-cap-ms` (CHECK 1000–60000). After S2 the
    // supervisor honours all three values for real (per-task backoff
    // schedule wired through `build_ipc_accept_task_bundle`).
    property bool _stabilityDraftIsCritical: false
    property int  _stabilityDraftMaxRestarts: 20
    property int  _stabilityDraftBackoffBaseMs: 100
    property int  _stabilityDraftBackoffCapSec: 5
    // Verbose service logging is apply-on-change (LIVE) and its value is the
    // shared `root.serviceVerboseLogging` (also surfaced in the Logs view),
    // so it is NOT drafted here.
    // The enforcement-mode + liveness-window carry-forward props
    // are GONE: `_saveStabilityConfig` now goes through the merge-on-Get
    // `root.applyServiceStabilityPatch`, which preserves every field this panel
    // does not own, so nothing has to be re-sent here.
    // Connection-egress trace toggles. Both
    // default off (privacy-sensitive: per-connection process + remote IP).
    property bool _stabilityDraftConnTraceNdjson: false
    property bool _stabilityDraftConnTraceGui: false
    // Rule-scope + routing-stop-policy MOVED to Routing
    // settings ("System-level routing"). No longer drafted / saved / loaded here;
    // they apply-on-change there through the shared clobber-safe writer.
    // FQDN cache refresh cadence (seconds). Edited in MINUTES via the
    // SpinBox below; sent/received in seconds. Clamped to 60..86400 (1 min..24 h)
    // on both sides — the SpinBox limits are a convenience, the Rust backend is
    // authoritative. Default 5 min. Rides the same admin-gated Save round-trip.
    property int _stabilityDraftCacheRefreshSecs: 300
    // SSOT bounds (mirror nrr_domain::decision_lookup::CACHE_REFRESH_*), in MINUTES.
    readonly property int _cacheRefreshMinMinutes: 1
    readonly property int _cacheRefreshMaxMinutes: 1440
    // Idle delay before this panel's drafts are committed, in seconds.
    // The Rust preference store clamps to the same range; the spin box limits
    // are a convenience, the backend is authoritative.
    readonly property int _autosaveMinSecs: 15
    readonly property int _autosaveMaxSecs: 600
    property bool _stabilityDirty: false
    property bool _stabilityJustSaved: false
    property bool _stabilityLoading: false
    property string _stabilityErrorCode: ""

    readonly property bool _stabilityClientValid:
        _stabilityDraftIsCritical
        || (_stabilityDraftBackoffCapSec * 1000 >= _stabilityDraftBackoffBaseMs)

    /// Arm the draft state after a user edit.
    ///
    /// While the service is REACHABLE the drafts are committed by one of three
    /// deferred paths (footer Apply, the section-switch guard, or the idle
    /// autosave timer), so arming alone is enough. While the service is
    /// UNREACHABLE none of those is guaranteed to run: quitting through the tray
    /// "Exit" tears the window down without passing through any of them, and the
    /// drafts — which only ever live in memory until a save parks them — are
    /// lost silently. So an offline edit is parked at click time instead: the
    /// offline branch of `_saveStabilityConfig` writes the drafts into the
    /// pending-intents store synchronously and clears the dirty flag. That
    /// branch never calls back into this function, so there is no recursion.
    function _markStabilityDirty() {
        _stabilityDirty = true
        _stabilityJustSaved = false
        _stabilityErrorCode = ""
        if (typeof root.setUnsavedChanges === "function") {
            root.setUnsavedChanges("diagnostics-logs", true)
        }
        if (!root._routingBackendConnected()) {
            _saveStabilityConfig()
        }
    }

    function _applyStabilityFromPayload(payload) {
        if (!payload) return
        // A key the user parked while the service was down outranks what the
        // service reports, on the live path too — otherwise the first read
        // after the service starts paints its defaults over a decision that
        // has not been delivered yet, and the checkbox appears to reset
        // itself. The mirror below still records what the service said.
        var parked = (typeof root._readPendingOffline === "function")
            ? (root._readPendingOffline()["stability"] || {}) : {}
        // The wire response carries BOTH the policy and the
        // verbose-logging flag at the root of the DTO. Older payloads
        // (S1/S2 era) lack the flag — default to false to preserve
        // pre-S3 behaviour.
        var policy = payload["ipc-accept-policy"]
            || payload.ipc_accept_policy
            || payload
        var verbose = payload["verbose-logging"]
        if (verbose === undefined) verbose = payload.verbose_logging
        if (!parked.hasOwnProperty("verbose-logging"))
            root.serviceVerboseLogging = !!verbose

        // Additive flags; older payloads lack
        // them and default to false (= trace off).
        var ctNdjson = payload["conn-trace-ndjson"]
        if (ctNdjson === undefined) ctNdjson = payload.conn_trace_ndjson
        if (!parked.hasOwnProperty("conn-trace-ndjson"))
            _stabilityDraftConnTraceNdjson = !!ctNdjson
        var ctGui = payload["conn-trace-gui"]
        if (ctGui === undefined) ctGui = payload.conn_trace_gui
        if (!parked.hasOwnProperty("conn-trace-gui"))
            _stabilityDraftConnTraceGui = !!ctGui

        // Cache refresh cadence (seconds). Absent → 5-min default.
        // Clamp defensively to the SSOT range in case an older/edited value
        // arrives out of bounds.
        var refresh = payload["cache-refresh-interval-secs"]
        if (refresh === undefined) refresh = payload.cache_refresh_interval_secs
        var refreshN = Number(refresh)
        if (!isFinite(refreshN) || refreshN <= 0) refreshN = 300
        if (!parked.hasOwnProperty("cache-refresh-interval-secs"))
            _stabilityDraftCacheRefreshSecs =
                Math.max(60, Math.min(86400, Math.round(refreshN)))

        // The administrator's rule-edit lock rides the same DTO. This panel
        // does not display or write it — it only forwards it to the window so
        // the Rules section knows to render read-only.
        if (typeof root.adoptRuleEditPermission === "function")
            root.adoptRuleEditPermission(payload)

        var kind = String(policy["kind"] || policy.kind || "recoverable")
        if (!parked.hasOwnProperty("ipc-accept-policy"))
            _stabilityDraftIsCritical = (kind === "critical")
        if (!_stabilityDraftIsCritical) {
            var mr = Number(policy["max-restarts"] || policy.max_restarts || 20)
            var bb = Number(policy["backoff-base-ms"] || policy.backoff_base_ms || 100)
            var bc = Number(policy["backoff-cap-ms"] || policy.backoff_cap_ms || 5000)
            _stabilityDraftMaxRestarts = mr
            _stabilityDraftBackoffBaseMs = bb
            _stabilityDraftBackoffCapSec = Math.max(1, Math.round(bc / 1000))
        }
        // A live read always wins — and refreshes the display mirror the
        // service-stopped seed below reads back.
        _rememberStabilityFromPayload(payload)
        _stabilityDirty = false
        _stabilityErrorCode = ""
        if (typeof root.setUnsavedChanges === "function") {
            root.setUnsavedChanges("diagnostics-logs", false)
        }
    }

    /// Wire keys of the stability config this panel owns. Copied into the
    /// display mirror on every successful read so a service-stopped launch shows
    /// the user's real values rather than the QML literal drafts.
    readonly property var _mirroredStabilityKeys: [
        "ipc-accept-policy", "verbose-logging", "conn-trace-ndjson",
        "conn-trace-gui", "cache-refresh-interval-secs"
    ]

    function _rememberStabilityFromPayload(payload) {
        if (!payload || typeof root._rememberServiceValues !== "function") return
        var remembered = {}
        for (var i = 0; i < group._mirroredStabilityKeys.length; i += 1) {
            var key = group._mirroredStabilityKeys[i]
            if (payload.hasOwnProperty(key)) remembered[key] = payload[key]
        }
        root._rememberServiceValues("stability", remembered)
    }

    /// Seed the drafts from what is known offline when the live read cannot
    /// land: a parked intent (edited while the service was down, not yet
    /// delivered) outranks the mirror of the service's last reported values.
    /// Without this the panel sat at its QML literals and the user read that as
    /// "my settings were lost". Read-only — nothing is pushed from here.
    function _seedStabilityFromOfflineSources() {
        var parked = (typeof root._readPendingOffline === "function")
            ? (root._readPendingOffline()["stability"] || {}) : {}
        var mirror = (typeof root._readServiceMirror === "function")
            ? (root._readServiceMirror()["stability"] || {}) : {}
        var source = null
        for (var i = 0; i < group._mirroredStabilityKeys.length; i += 1) {
            var key = group._mirroredStabilityKeys[i]
            source = parked.hasOwnProperty(key)
                ? parked : (mirror.hasOwnProperty(key) ? mirror : null)
            if (source === null) continue
            var value = Pure.stabilityEffective(source, key)
            if (key === "verbose-logging") root.serviceVerboseLogging = value
            else if (key === "conn-trace-ndjson") _stabilityDraftConnTraceNdjson = value
            else if (key === "conn-trace-gui") _stabilityDraftConnTraceGui = value
            else if (key === "cache-refresh-interval-secs") _stabilityDraftCacheRefreshSecs = value
            else if (key === "ipc-accept-policy") {
                _stabilityDraftIsCritical = (String(value.kind) === "critical")
                if (!_stabilityDraftIsCritical) {
                    _stabilityDraftMaxRestarts = Number(value["max-restarts"])
                    _stabilityDraftBackoffBaseMs = Number(value["backoff-base-ms"])
                    _stabilityDraftBackoffCapSec =
                        Math.max(1, Math.round(Number(value["backoff-cap-ms"]) / 1000))
                }
            }
        }
        // The seed is a DISPLAY restore, not an edit: leave the dirty flag alone
        // so it cannot arm an unintended write of these values back out.
    }

    function _fetchStabilityConfig() {
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.bridgeAvailable
                || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            _stabilityErrorCode = "bridge-unavailable"
            _seedStabilityFromOfflineSources()
            return
        }
        _stabilityLoading = true
        _stabilityErrorCode = ""
        var corr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(corr,
            function(ok, payload, errorCode, errorMessage) {
                group._stabilityLoading = false
                if (!ok) {
                    group._stabilityErrorCode = String(errorCode || "unknown")
                    // The service is present but did not answer (stopped
                    // mid-flight, RPC refused): show what is known offline
                    // instead of leaving the drafts at the QML literals.
                    group._seedStabilityFromOfflineSources()
                    return
                }
                // ServiceStabilityConfigGetResponse is a type alias to
                // ServiceStabilityConfigDto — both `ipc-accept-policy`
                // and the S3 `verbose-logging` flag sit at the payload
                // root. Pass the whole payload so the applier can read
                // both in one place.
                group._applyStabilityFromPayload(payload || {})
            })
    }

    function _resetStabilityToDefaults() {
        _stabilityDraftIsCritical = false
        _stabilityDraftMaxRestarts = 20
        _stabilityDraftBackoffBaseMs = 100
        _stabilityDraftBackoffCapSec = 5
        // Verbose logging is now apply-on-change (LIVE) and no longer
        // part of the draft/Save flow, so Reset-to-defaults deliberately does
        // NOT silently flip the live verbose state.
        _stabilityDraftConnTraceNdjson = false
        _stabilityDraftConnTraceGui = false
        _markStabilityDirty()
    }

    /// Wire shape of the IPC accept policy built from the current drafts.
    /// Shared by the live Save and the offline park so both send the same thing.
    function _buildAcceptPolicy() {
        if (_stabilityDraftIsCritical) return { "kind": "critical" }
        return {
            "kind": "recoverable",
            "max-restarts": _stabilityDraftMaxRestarts,
            "backoff-base-ms": _stabilityDraftBackoffBaseMs,
            "backoff-cap-ms": _stabilityDraftBackoffCapSec * 1000
        }
    }

    function _saveStabilityConfig(onComplete) {
        if (!_stabilityClientValid || _stabilityLoading) {
            if (typeof onComplete === "function") onComplete(false)
            return
        }
        // Service stopped: park the drafts the same way the routing toggles do,
        // so the panel's settings can be armed BEFORE the service is started and
        // are offered for delivery on the connect edge. Previously the write
        // simply failed with "bridge unavailable" and the user's ticks were lost.
        if (!root._routingBackendConnected()) {
            root._recordOfflineRoutingIntent(
                "stability", "ipc-accept-policy", _buildAcceptPolicy())
            root._recordOfflineRoutingIntent(
                "stability", "conn-trace-ndjson", _stabilityDraftConnTraceNdjson)
            root._recordOfflineRoutingIntent(
                "stability", "conn-trace-gui", _stabilityDraftConnTraceGui)
            root._recordOfflineRoutingIntent(
                "stability", "cache-refresh-interval-secs", _stabilityDraftCacheRefreshSecs)
            _stabilityDirty = false
            _stabilityJustSaved = true
            _stabilityErrorCode = ""
            if (typeof root.setUnsavedChanges === "function") {
                root.setUnsavedChanges("diagnostics-logs", false)
            }
            if (typeof onComplete === "function") onComplete(true)
            return
        }
        var policy = _buildAcceptPolicy()
        _stabilityLoading = true
        _stabilityErrorCode = ""
        // One clobber-safe writer. Send ONLY the Diagnostics-owned
        // fields; the merge-on-Get preserves the Routing-owned fields
        // (enforcement-mode, liveness-window, stop-policy, rule-scope), so the
        // old carry-forward hacks (_stabilityLoaded*) are gone.
        // Verbose-logging is NOT sent here anymore: it applies
        // on-change through `_applyVerboseLogging`. Leaving it in this Save
        // patch is what silently carried verbose=false when Save was skipped.
        root.applyServiceStabilityPatch({
            "ipc-accept-policy": policy,
            "conn-trace-ndjson": _stabilityDraftConnTraceNdjson,
            "conn-trace-gui": _stabilityDraftConnTraceGui,
            "cache-refresh-interval-secs": _stabilityDraftCacheRefreshSecs
        }, function(ok, code, payload) {
            group._stabilityLoading = false
            if (!ok) {
                group._stabilityErrorCode = (code === "") ? "unknown" : code
                if (typeof onComplete === "function") onComplete(false)
                return
            }
            // Set response echoes the DTO directly (same shape as Get).
            group._applyStabilityFromPayload(payload || {})
            group._stabilityJustSaved = true
            if (typeof onComplete === "function") onComplete(true)
        }, "user:diagnostics-save")
    }

    // Idle-commit for this panel's drafts. There is no local Save button any
    // more: the drafts reach the service through the global footer Apply, the
    // navigation guard, and this timer once the user has stopped editing.
    // The panel is only offered for autosave when the draft is actually valid
    // and no write is already in flight.
    property PanelAutosaveController _autosave: PanelAutosaveController {
        root: group.root
        dirty: group._stabilityDirty
            && group._stabilityClientValid
            && !group._stabilityLoading
        intervalSecs: group.root.uiRevision >= 0
            ? Number(group.root.prefs.settingsAutosaveSecs || 60) : 60
        onDue: group._saveStabilityConfig()
    }

    // Service-backed controls: re-read the live configuration whenever the
    // backend connection comes back. Without this the panel kept whatever
    // defaults it drew while the service was stopped, and a later Save wrote
    // those stale drafts back — silently turning OFF settings that were already
    // enabled on the service.
    property Connections _backendReload: Connections {
        target: group.root
        function onBackendStatusChanged() {
            if (group.root._routingBackendConnected() && !group._stabilityDirty) {
                group._fetchStabilityConfig()
            }
        }
        // Both of these end with the service holding different values than the
        // read that drew this panel, and this panel had neither handler: the
        // "verbose service logging" checkbox stayed unticked for a whole
        // session while the service was in fact logging verbosely, because the
        // connect-time read landed before the parked change was applied and
        // nothing re-read afterwards.
        function onOfflinePendingApplied() {
            if (!group._stabilityDirty) group._fetchStabilityConfig()
        }
        function onServiceIntentReplayed() {
            if (!group._stabilityDirty) group._fetchStabilityConfig()
        }
    }

    Component.onCompleted: {
        _fetchStabilityConfig()
        // Register a Save-and-continue callback so UnsavedChangesGuard
        // can offer the third button. The closure captures `group`
        // (the GroupBox) so the callback survives instance lifetime.
        if (typeof root.setSaveCallback === "function") {
            root.setSaveCallback("diagnostics-logs",
                function(onDone) { group._saveStabilityConfig(onDone) })
        }
        // Paired revert callback — on Discard the guard re-fetches the
        // persisted policy from the service so the draft fields in
        // this panel snap back to whatever is actually saved, instead
        // of lingering at the abandoned numbers.
        if (typeof root.setRevertCallback === "function") {
            root.setRevertCallback("diagnostics-logs",
                function() { group._fetchStabilityConfig() })
        }
    }
    Component.onDestruction: {
        if (typeof root.setSaveCallback === "function") {
            root.setSaveCallback("diagnostics-logs", null)
        }
        if (typeof root.setRevertCallback === "function") {
            root.setRevertCallback("diagnostics-logs", null)
        }
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Image {
                Layout.preferredWidth: 20
                Layout.preferredHeight: 20
                source: root.uiIconSource("diagnostics")
                sourceSize.width: 20
                sourceSize.height: 20
                fillMode: Image.PreserveAspectFit
                asynchronous: true
            }
            Label {
                Layout.fillWidth: true
                text: root.tr("diag.section.subtitle",
                    "Log storage, audit trail, and diagnostic mode settings")
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
            }
        }

        // Security-audit viewing tab (professional users). Default off. This
        // only controls whether the read-only Audit tab appears in the Logs
        // view; the audit trail is always recorded regardless of this setting.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXxs
            CheckBox {
                id: showAuditTabBox
                Layout.fillWidth: true
                onToggled: {
                    root.updatePrefs({ showAuditTab: checked })
                    root.emitPrefs()
                }
                // A declarative `checked:` binding is destroyed by the first
                // user click; a Binding element keeps re-asserting from prefs
                // so external changes (reset, round-trip) stay reflected.
                Binding {
                    target: showAuditTabBox
                    property: "checked"
                    value: root.uiRevision >= 0 ? !!root.prefs.showAuditTab : false
                }
                text: root.tr("settings.diagnostics.show-audit-tab.label",
                    "Show security audit tab")
                contentItem: Text {
                    text: showAuditTabBox.text
                    leftPadding: showAuditTabBox.indicator.width
                        + showAuditTabBox.spacing
                    verticalAlignment: Text.AlignVCenter
                    wrapMode: Text.WordWrap
                    color: root.textColor
                }
                Accessible.role: Accessible.CheckBox
                Accessible.name: text
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg
                text: root.tr("settings.diagnostics.show-audit-tab.help",
                    "The security audit trail is always recorded, regardless of this setting. This only shows or hides the audit viewing tab in the Logs view.")
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
            }
        }

        // Storage health panel
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
                RowLayout {
                    Layout.fillWidth: true
                    Image {
                        Layout.preferredWidth: 18
                        Layout.preferredHeight: 18
                        source: root.uiIconSource("icon_audit_trail")
                        sourceSize.width: 18
                        sourceSize.height: 18
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
                        text: auditChain.verified === false
                            ? root.tr("diag.audit.chain-warning", "Hash chain warning")
                            : root.tr("diag.audit.chain-verified", "Hash chain verified")
                        color: auditChain.verified === false ? root.uiTheme.colorAccent : root.mutedTextColor
                    }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.storage-health.logs-size", "Log storage: {size}")
                        .replace("{size}", group.formatBytes(storageHealth.logsSizeBytes))
                    color: root.textColor
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.storage-health.audit-size", "Audit storage: {size}")
                        .replace("{size}", group.formatBytes(storageHealth.auditSizeBytes))
                    color: root.textColor
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.storage-health.log-files", "{count} log file(s)")
                        .replace("{count}", String(storageHealth.logFileCount || 0))
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: Number(storageHealth.droppedEvents || 0) > 0
                    text: root.tr("diag.storage-health.dropped-events", "{count} event(s) dropped")
                        .replace("{count}", String(storageHealth.droppedEvents || 0))
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: storageHealth.lastCleanup !== undefined && storageHealth.lastCleanup !== ""
                    text: root.tr("diag.storage-health.last-cleanup", "Last cleanup: {time}")
                        .replace("{time}", String(storageHealth.lastCleanup || "-"))
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                Label {
                    Layout.fillWidth: true
                    visible: storageHealth.dirWritable === false
                    text: root.tr("diag.storage-health.dir-not-writable", "Log directory is not writable")
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                }
            }
        }

        // Retention controls
        GroupBox {
            title: root.tr("diag.retention.section-title", "Retention settings")
            Layout.fillWidth: true
            // Populate from the authoritative persisted config on open.
            // Capture the context-default baseline first so the Apply button
            // is not spuriously enabled during the fetch round-trip; the
            // fetch response (if any) recaptures it with authoritative values.
            Component.onCompleted: {
                group._captureLogRetentionBaseline()
                group._fetchLogRetentionConfig()
            }
            GridLayout {
                anchors.left: parent.left
                anchors.right: parent.right
                columns: 3
                columnSpacing: root.uiTheme.spacingMd
                rowSpacing: root.uiTheme.spacingSm

                Label {
                    text: (root.uiRevision, root.tr("diag.retention.logs-max-age-label", "Keep logs for"))
                    color: root.textColor
                }
                ThemedSpinBox {
                    id: logsMaxAge
                    theme: root.uiTheme
                    Layout.preferredWidth: 140
                    Layout.minimumWidth: 140
                    from: 1
                    to: 3650
                    value: Number(retentionCtx.logsMaxAgeDays !== undefined
                        ? retentionCtx.logsMaxAgeDays : defaultLogsMaxAgeDays)
                    editable: true
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: "1–3650"
                }
                Label {
                    text: (root.uiRevision, root.tr("diag.retention.logs-max-age-unit", "days"))
                    color: root.mutedTextColor
                    Layout.preferredWidth: 100
                }

                Label {
                    text: (root.uiRevision, root.tr("diag.retention.logs-max-size-label", "Maximum log storage"))
                    color: root.textColor
                }
                ThemedSpinBox {
                    id: logsMaxSize
                    theme: root.uiTheme
                    Layout.preferredWidth: 140
                    Layout.minimumWidth: 140
                    from: 1
                    // Cap depends on the unit. KB → 1024*1024, MB → 1024.
                    // GB is no longer offered as a unit, so the upper bound
                    // collapses to a sensible storage budget at all times.
                    to: logsSizeUnitCombo.currentIndex === 0 ? 1048576 : 1024
                    value: Number(retentionCtx.logsMaxSizeMb !== undefined
                        ? retentionCtx.logsMaxSizeMb : defaultLogsMaxSizeMb)
                    editable: true
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: "1–" + (logsSizeUnitCombo.currentIndex === 0 ? "1048576" : "1024")
                }
                ThemedComboBox {
                    id: logsSizeUnitCombo
                    theme: root.uiTheme
                    Layout.preferredWidth: 100
                    Layout.minimumWidth: 100
                    model: [ "kb", "mb" ]
                    function unitLabel(id) { return root.tr("diag.retention.size-unit." + id, id.toUpperCase()) }
                    labelResolver: function(item) { return logsSizeUnitCombo.unitLabel(item) }
                    displayText: root.uiRevision >= 0 && currentIndex >= 0
                        ? unitLabel(model[currentIndex]) : ""
                    currentIndex: 1
                    popup.width: root.comboPopupWidth(logsSizeUnitCombo, model, "",
                        function(item) { return logsSizeUnitCombo.unitLabel(item) })
                }

                Label {
                    text: (root.uiRevision, root.tr("diag.retention.audit-max-age-label", "Keep audit trail for"))
                    color: root.textColor
                }
                ThemedSpinBox {
                    id: auditMaxAge
                    theme: root.uiTheme
                    Layout.preferredWidth: 140
                    Layout.minimumWidth: 140
                    from: 1
                    to: 3650
                    value: Number(retentionCtx.auditMaxAgeDays !== undefined
                        ? retentionCtx.auditMaxAgeDays : defaultAuditMaxAgeDays)
                    editable: true
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: "1–3650"
                }
                Label {
                    text: (root.uiRevision, root.tr("diag.retention.audit-max-age-unit", "days"))
                    color: root.mutedTextColor
                    Layout.preferredWidth: 100
                }

                Label {
                    text: (root.uiRevision, root.tr("diag.retention.audit-max-size-label", "Maximum audit storage"))
                    color: root.textColor
                }
                ThemedSpinBox {
                    id: auditMaxSize
                    theme: root.uiTheme
                    Layout.preferredWidth: 140
                    Layout.minimumWidth: 140
                    from: 1
                    to: 100000
                    value: Number(retentionCtx.auditMaxSizeMb !== undefined
                        ? retentionCtx.auditMaxSizeMb : defaultAuditMaxSizeMb)
                    editable: true
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: "1–100000"
                }
                ThemedComboBox {
                    id: auditSizeUnitCombo
                    theme: root.uiTheme
                    Layout.preferredWidth: 100
                    Layout.minimumWidth: 100
                    model: [ "kb", "mb", "gb" ]
                    function unitLabel(id) { return root.tr("diag.retention.size-unit." + id, id.toUpperCase()) }
                    labelResolver: function(item) { return auditSizeUnitCombo.unitLabel(item) }
                    displayText: root.uiRevision >= 0 && currentIndex >= 0
                        ? unitLabel(model[currentIndex]) : ""
                    currentIndex: 1
                    popup.width: root.comboPopupWidth(auditSizeUnitCombo, model, "",
                        function(item) { return auditSizeUnitCombo.unitLabel(item) })
                }

                Item { Layout.columnSpan: 2; Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    Layout.alignment: Qt.AlignRight
                    text: root.tr("diag.retention.apply-button", "Apply")
                    icon.source: root.uiIconSource("apply")
                    enabled: !group._logRetentionApplying && group._logRetentionDirty
                    // Persist through settings.log-retention.set.
                    onClicked: group._applyLogRetention()
                }
            }
        }

        // Archive export. The export is handed
        // to `rpcDiagnosticsExportArchive`; the service builds a zip in
        // the per-user `archives/` directory (Transport A — service
        // owns the location). The folder field is now read-only and
        // reflects the LAST returned archive path; "Open folder" opens
        // the parent directory in Explorer. No wire-level cancel is
        // supported, so the Cancel button is gone.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
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
                // (shared with the Diagnostics-section export surface) and forwarded
                // as the 4th arg to rpcDiagnosticsExportArchive. The Binding elements
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
                        onClicked: group.root.setDiagnosticsArchiveRedactionLevel("standard")
                        Binding {
                            target: archiveLevelStandardRadio
                            property: "checked"
                            value: group.root.diagnosticsArchiveRedactionLevel === "standard"
                        }
                    }
                    RadioButton {
                        id: archiveLevelDiagnosticsRadio
                        text: root.tr("diag.archive.level.diagnostics", "Full diagnostics")
                        ButtonGroup.group: archiveLevelGroup
                        onClicked: group.root.setDiagnosticsArchiveRedactionLevel("diagnostics")
                        Binding {
                            target: archiveLevelDiagnosticsRadio
                            property: "checked"
                            value: group.root.diagnosticsArchiveRedactionLevel === "diagnostics"
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
                // Session-only log scope (default ON). A plain `checked`
                // binding would be destroyed by the first click, so a change on
                // the twin surface would stop being reflected here; a Binding
                // element keeps re-asserting from the shared persisted value.
                CheckBox {
                    id: archiveSessionOnlyBox
                    Layout.fillWidth: true
                    Binding {
                        target: archiveSessionOnlyBox
                        property: "checked"
                        value: group.root.diagnosticsArchiveSessionOnly
                    }
                    onToggled: group.root.setDiagnosticsArchiveSessionOnly(checked)
                    text: root.tr("diag.archive.session-only",
                        "Only logs from the current session")
                    contentItem: Text {
                        text: archiveSessionOnlyBox.text
                        leftPadding: archiveSessionOnlyBox.indicator.width
                            + archiveSessionOnlyBox.spacing
                        verticalAlignment: Text.AlignVCenter
                        wrapMode: Text.WordWrap
                        color: root.textColor
                    }
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.archive.session-only-caption",
                        "Skips log entries recorded before this app session started. Service restarts within the session are still included; uncheck for the full log history.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
                ThemedTextField {
                    id: archiveFolderField
                    theme: root.uiTheme
                    Layout.fillWidth: true
                    readOnly: true
                    enabled: false
                    placeholderText: root.tr("diag.archive.path-placeholder",
                        "No archive exported yet")
                    text: exportState.lastArchivePath
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        enabled: !exportState.busy
                        text: root.tr("diag.logs.export-button", "Export diagnostic archive")
                        icon.source: root.uiIconSource("export")
                        onClicked: exportState.start()
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        enabled: exportState.lastArchiveDir !== ""
                        text: root.tr("diag.archive.open-folder", "Open folder")
                        icon.source: root.uiIconSource("open-file")
                        onClicked: {
                            if (exportState.lastArchiveDir === "") return
                            Qt.openUrlExternally(
                                "file:///" + exportState.lastArchiveDir.replace(/\\/g, "/"))
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        text: exportState.message
                        color: exportState.failed ? root.uiTheme.colorAccent : root.mutedTextColor
                        wrapMode: Text.WordWrap
                    }
                }
                ProgressBar {
                    Layout.fillWidth: true
                    visible: exportState.busy
                    indeterminate: true
                }
            }
        }

        // Clear logs action
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("diag.logs.clear-button", "Clear logs")
                icon.source: root.uiIconSource("icon_log_clear")
                onClicked: clearLogsConfirm.open()
            }
            Item { Layout.fillWidth: true }
        }

        // Service stability config sub-panel. RPC
        // round-trip via rpcServiceStabilityConfigGet/Set (bridge ops
        // settings.service-stability.get / .set). Wire shape:
        // { "ipc-accept-policy": { "kind": "recoverable",
        //   "max-restarts": N, "backoff-base-ms": N, "backoff-cap-ms": N } }
        // or { "ipc-accept-policy": { "kind": "critical" } }.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
            background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm
                // The whole ServiceStabilityConfig Save is admin-gated
                // (`ServiceStabilityConfigSet` requires elevation), so the
                // section title carries the shield to flag the elevated
                // round-trip up front — matching the rule-scope sub-block.
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
                        text: root.tr("settings.diagnostics.service-stability.title",
                            "Service stability")
                        color: root.textColor
                        font.bold: true
                    }
                }
                Label {
                    Layout.fillWidth: true
                    text: root.tr("settings.diagnostics.service-stability.help",
                        "These options only affect the control channel (IPC). " +
                        "Network policy enforcement runs independently.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }

                // Verbose service logging toggle. Placed first in the group:
                // it is the most commonly used control here, and it lives
                // outside the recoverable-only grid because it applies to
                // both policy modes (debug events flow regardless of which
                // IPC accept policy is active). Applies LIVE, no restart:
                // the service reload-wraps its `EnvFilter` (`reload::Layer`)
                // and `ProductionServiceStability::set` drives it through
                // the `VerbosityControl` seam on every Save.
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingXs
                    spacing: root.uiTheme.spacingXxs
                    CheckBox {
                        id: verboseLoggingCheck
                        text: root.tr(
                            "settings.diagnostics.service-stability.verbose.label",
                            "Verbose service logging")
                        // Apply-on-change (LIVE), NOT the draft/Save flow: an
                        // un-pressed Save used to silently discard this toggle.
                        // The service reloads verbosity without a restart. The
                        // shared `root.serviceVerboseLogging` is the source of
                        // truth (the same flag is surfaced in the Logs view); a
                        // Binding re-asserts `checked` from it so a change on the
                        // twin surface — or a failed apply — is reflected here.
                        onToggled: root.applyVerboseLogging(checked, "user:verbose-toggle")
                        Binding {
                            target: verboseLoggingCheck
                            property: "checked"
                            value: root.serviceVerboseLogging
                        }
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: root.tr(
                            "settings.diagnostics.service-stability.verbose.tooltip",
                            "When enabled, the service writes tracing::debug events to operational NDJSON. Applies immediately, no restart required.")
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingLg
                        text: root.tr(
                            "settings.diagnostics.service-stability.verbose.help",
                            "Useful for diagnosing rare IPC or mutation issues. Leave off in normal operation — log volume grows substantially.")
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    }
                }

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: root.uiTheme.spacingMd
                    rowSpacing: root.uiTheme.spacingXs

                    Label {
                        text: root.tr("settings.diagnostics.service-stability.ipc.policy.label",
                            "Control-channel failure policy")
                        color: root.textColor
                        Layout.alignment: Qt.AlignVCenter
                    }
                    ThemedComboBox {
                        id: stabilityPolicyCombo
                        theme: root.uiTheme
                        Layout.preferredWidth: 340
                        // The model carries the wire-stable `kind` slug so the
                        // section never has to map indices → slugs manually.
                        model: [
                            { kind: "recoverable",
                              labelKey: "settings.diagnostics.service-stability.ipc.policy.recoverable.label",
                              labelFallback: "Recoverable (recommended)" },
                            { kind: "critical",
                              labelKey: "settings.diagnostics.service-stability.ipc.policy.critical.label",
                              labelFallback: "Critical (fail-fast)" }
                        ]
                        textRole: "labelKey"
                        labelResolver: function(item) {
                            if (!item) return ""
                            return root.tr(item.labelKey, item.labelFallback)
                        }
                        currentIndex: group._stabilityDraftIsCritical ? 1 : 0
                        displayText: {
                            var item = model[group._stabilityDraftIsCritical ? 1 : 0]
                            return root.tr(item.labelKey, item.labelFallback)
                        }
                        onActivated: function(index) {
                            var newCritical = (index === 1)
                            if (newCritical !== group._stabilityDraftIsCritical) {
                                group._stabilityDraftIsCritical = newCritical
                                group._markStabilityDirty()
                            }
                        }
                    }
                }

                Label {
                    Layout.fillWidth: true
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: group._stabilityDraftIsCritical
                        ? root.tr("settings.diagnostics.service-stability.ipc.policy.critical.help",
                            "Any control-channel failure puts the service into recovery mode. " +
                            "Policy enforcement halts until the operator restarts the service. " +
                            "Use for strict compliance scenarios.")
                        : root.tr("settings.diagnostics.service-stability.ipc.policy.recoverable.help",
                            "If the GUI ↔ service control channel fails, the supervisor restarts " +
                            "it automatically. Policy enforcement keeps running. After all retry " +
                            "attempts are exhausted, the GUI marks the channel as unavailable but " +
                            "the service continues operating.")
                }

                GridLayout {
                    Layout.fillWidth: true
                    visible: !group._stabilityDraftIsCritical
                    columns: 3
                    columnSpacing: root.uiTheme.spacingMd
                    rowSpacing: root.uiTheme.spacingXs

                    Label {
                        text: root.tr("settings.diagnostics.service-stability.ipc.max-restarts.label",
                            "Max restart attempts")
                        color: root.textColor
                        Layout.alignment: Qt.AlignVCenter
                    }
                    ThemedSpinBox {
                        theme: root.uiTheme
                        Layout.preferredWidth: 140
                        editable: true
                        from: 1; to: 100
                        value: group._stabilityDraftMaxRestarts
                        onValueModified: {
                            group._stabilityDraftMaxRestarts = value
                            group._markStabilityDirty()
                        }
                    }
                    Label {
                        text: "(1–100)"
                        color: root.mutedTextColor
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        Layout.alignment: Qt.AlignVCenter
                    }

                    Label {
                        text: root.tr("settings.diagnostics.service-stability.ipc.backoff-base.label",
                            "Initial backoff (ms)")
                        color: root.textColor
                        Layout.alignment: Qt.AlignVCenter
                    }
                    ThemedSpinBox {
                        id: stabilityBackoffBaseField
                        theme: root.uiTheme
                        Layout.preferredWidth: 140
                        editable: true
                        from: 50; to: 5000
                        stepSize: 50
                        value: group._stabilityDraftBackoffBaseMs
                        onValueModified: {
                            group._stabilityDraftBackoffBaseMs = value
                            group._markStabilityDirty()
                        }
                    }
                    Label {
                        text: "(50–5000)"
                        color: root.mutedTextColor
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        Layout.alignment: Qt.AlignVCenter
                    }

                    Label {
                        text: root.tr("settings.diagnostics.service-stability.ipc.backoff-cap.label",
                            "Max backoff (s)")
                        color: root.textColor
                        Layout.alignment: Qt.AlignVCenter
                    }
                    ThemedSpinBox {
                        id: stabilityBackoffCapField
                        theme: root.uiTheme
                        Layout.preferredWidth: 140
                        editable: true
                        from: 1; to: 60
                        value: group._stabilityDraftBackoffCapSec
                        onValueModified: {
                            group._stabilityDraftBackoffCapSec = value
                            group._markStabilityDirty()
                        }
                    }
                    Label {
                        text: "(1–60)"
                        color: root.mutedTextColor
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        Layout.alignment: Qt.AlignVCenter
                    }
                }

                // Client-side cross-field validation hint. Mirrors the
                // server-side check in `validate_recoverable_params`
                // (cap_ms ≥ base_ms) so the user does not have to hit
                // Save to learn about an invalid combination.
                Label {
                    Layout.fillWidth: true
                    visible: !group._stabilityDraftIsCritical && !group._stabilityClientValid
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    text: root.tr(
                        "settings.diagnostics.service-stability.ipc.cap-below-base",
                        "Max backoff must be greater than or equal to initial backoff.")
                }

                // The rule-enforcement-scope and pause/stop
                // routing-policy controls MOVED to Routing settings
                // ("System-level routing"), where they apply-on-change through
                // the shared clobber-safe service-stability writer. See
                // RoutingSettings.qml.

                // FQDN cache refresh cadence. How often a routed
                // site's IPs are re-resolved (minutes). The last-known-good
                // address is HELD between refreshes and on failure, so this only
                // controls freshness, not retention. SpinBox is limited to
                // 1 min..24 h; the service re-clamps to the same range.
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingSm
                    spacing: root.uiTheme.spacingXxs

                    Label {
                        Layout.fillWidth: true
                        text: root.tr(
                            "settings.diagnostics.cache-refresh.heading",
                            "Address cache refresh")
                        font.pixelSize: root.uiTheme.baseFontSizePx
                        font.bold: true
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm
                        Label {
                            text: root.tr(
                                "settings.diagnostics.cache-refresh.label",
                                "Re-resolve routed sites every")
                            color: root.mutedTextColor
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        }
                        ThemedSpinBox {
                            id: cacheRefreshSpin
                            theme: root.uiTheme
                            editable: true
                            from: group._cacheRefreshMinMinutes
                            to: group._cacheRefreshMaxMinutes
                            stepSize: 1
                            value: Math.max(
                                group._cacheRefreshMinMinutes,
                                Math.min(
                                    group._cacheRefreshMaxMinutes,
                                    Math.round(group._stabilityDraftCacheRefreshSecs / 60)))
                            onValueModified: {
                                var secs = value * 60
                                if (secs !== group._stabilityDraftCacheRefreshSecs) {
                                    group._stabilityDraftCacheRefreshSecs = secs
                                    group._markStabilityDirty()
                                }
                            }
                        }
                        Label {
                            text: root.tr(
                                "settings.diagnostics.cache-refresh.unit", "min")
                            color: root.mutedTextColor
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingLg
                        text: root.tr(
                            "settings.diagnostics.cache-refresh.help",
                            "How often a routed site's IP addresses are refreshed (1 min – 24 h). Site IPs rarely change, so a longer interval means less network activity; the last known address is always kept and used for routing and leak-protection until a fresh one is obtained, so lengthening this never weakens blocking.")
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    }
                }

                // Connection-egress trace.
                // Two independent toggles: write the per-connection trace to
                // the service NDJSON, and/or surface it in GUI diagnostics.
                // Both require a service restart (the observer starts at
                // bootstrap). Off by default — privacy-sensitive.
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingSm
                    spacing: root.uiTheme.spacingXxs

                    Label {
                        Layout.fillWidth: true
                        text: root.tr(
                            "settings.diagnostics.conn-trace.heading",
                            "Connection trace (diagnostic)")
                        font.pixelSize: root.uiTheme.baseFontSizePx
                        font.bold: true
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr(
                            "settings.diagnostics.conn-trace.intro",
                            "Records outgoing connections of all apps and the interface each left through (direct vs VPN). Sees the real socket, so it works even when the browser uses DoH. Requires service restart.")
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    }
                    CheckBox {
                        text: root.tr(
                            "settings.diagnostics.conn-trace.ndjson.label",
                            "Write connection trace to service log (NDJSON)")
                        checked: group._stabilityDraftConnTraceNdjson
                        onToggled: {
                            if (checked !== group._stabilityDraftConnTraceNdjson) {
                                group._stabilityDraftConnTraceNdjson = checked
                                group._markStabilityDirty()
                            }
                        }
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: root.tr(
                            "settings.diagnostics.conn-trace.ndjson.tooltip",
                            "Each observed connection is written to the operational NDJSON: process, remote IP:port, and egress interface (primary/provider or secondary/VPN).")
                    }
                    CheckBox {
                        text: root.tr(
                            "settings.diagnostics.conn-trace.gui.label",
                            "Show connection trace in diagnostics (GUI)")
                        checked: group._stabilityDraftConnTraceGui
                        onToggled: {
                            if (checked !== group._stabilityDraftConnTraceGui) {
                                group._stabilityDraftConnTraceGui = checked
                                group._markStabilityDirty()
                            }
                        }
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: root.tr(
                            "settings.diagnostics.conn-trace.gui.tooltip",
                            "Surfaces the connection trace in the diagnostics log view (also writes it to NDJSON).")
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingLg
                        text: root.tr(
                            "settings.diagnostics.conn-trace.help",
                            "Privacy-sensitive: the trace contains per-connection process names and remote addresses. Leave off in normal operation.")
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    }
                }

                // Save error gets its own line so the Save / Reset row
                // does not overflow the panel.
                Label {
                    Layout.fillWidth: true
                    visible: group._stabilityErrorCode !== ""
                    color: root.uiTheme.colorAccent
                    wrapMode: Text.WordWrap
                    text: {
                        if (group._stabilityErrorCode === "") return ""
                        var lbl = (typeof root.ipcErrorLabel === "function")
                            ? root.ipcErrorLabel(group._stabilityErrorCode)
                            : group._stabilityErrorCode
                        return root.tr(
                            "settings.diagnostics.service-stability.save-failed",
                            "Save failed") + ": " + lbl
                    }
                }

                // Autosave cadence for this panel's drafts. The panel has no
                // Save button: an edit is committed by the footer Apply, by
                // leaving the section, or automatically after this idle delay.
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingSm
                    spacing: root.uiTheme.spacingXxs

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm
                        Label {
                            text: root.tr(
                                "settings.autosave.label",
                                "Save changes automatically after")
                            color: root.mutedTextColor
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        }
                        ThemedSpinBox {
                            id: autosaveSpin
                            theme: root.uiTheme
                            editable: true
                            from: group._autosaveMinSecs
                            to: group._autosaveMaxSecs
                            stepSize: 5
                            value: root.uiRevision >= 0
                                ? Math.max(group._autosaveMinSecs,
                                    Math.min(group._autosaveMaxSecs,
                                        Number(root.prefs.settingsAutosaveSecs || 60)))
                                : 60
                            onValueModified: {
                                if (value !== Number(root.prefs.settingsAutosaveSecs || 60)) {
                                    root.updatePrefs({ settingsAutosaveSecs: value })
                                    root.emitPrefs()
                                }
                            }
                            Accessible.name: root.tr(
                                "settings.autosave.label",
                                "Save changes automatically after")
                        }
                        Label {
                            text: root.tr("settings.autosave.unit", "s")
                            color: root.mutedTextColor
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        }
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingLg
                        text: root.tr(
                            "settings.autosave.help",
                            "Changes on this page are saved automatically once you stop editing, when you press Apply, and when you leave the page. Reset restores the factory defaults.")
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: root.uiTheme.spacingXs
                    spacing: root.uiTheme.spacingSm

                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr(
                            "settings.diagnostics.service-stability.reset", "Reset")
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: root.tr(
                            "settings.diagnostics.service-stability.reset-tooltip",
                            "Reset to factory defaults (recoverable, 20 restarts, 100 ms, 5 s)")
                        enabled: !group._stabilityLoading
                            && (group._stabilityDraftIsCritical
                                || group._stabilityDraftMaxRestarts !== 20
                                || group._stabilityDraftBackoffBaseMs !== 100
                                || group._stabilityDraftBackoffCapSec !== 5
                                || group._stabilityDraftConnTraceNdjson
                                || group._stabilityDraftConnTraceGui)
                        onClicked: group._resetStabilityToDefaults()
                    }
                    Item { Layout.fillWidth: true }
                    Label {
                        visible: group._stabilityDirty && !group._stabilityLoading
                        color: root.mutedTextColor
                        text: root.tr(
                            "settings.autosave.pending", "Unsaved — saving shortly")
                    }
                    Label {
                        visible: group._stabilityJustSaved
                            && group._stabilityErrorCode === ""
                            && !group._stabilityDirty
                        color: root.uiTheme.colorAccent
                        text: root.tr(
                            "settings.diagnostics.service-stability.saved", "Saved")
                    }
                }
            }
        }
    }

    QtObject {
        id: exportState
        property bool busy: false
        property bool failed: false
        property string message: group.root.tr("diag.archive.state-ready", "Ready")
        property string lastArchivePath: ""
        property string lastArchiveDir: ""
        property double lastArchiveSizeBytes: 0
        property string lastErrorCode: ""

        function start() {
            if (busy) return
            var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
            if (!group.root.bridgeAvailable
                    || bridge === null
                    || typeof bridge.rpcDiagnosticsExportArchive !== "function") {
                failed = true
                lastErrorCode = "bridge-unavailable"
                message = group.root.tr("diag.archive.bridge-unavailable",
                    "Service bridge not connected — export unavailable")
                return
            }
            busy = true
            failed = false
            lastErrorCode = ""
            message = group.root.tr("diag.archive.state-exporting", "Exporting...")
            var corr = bridge.rpcDiagnosticsExportArchive(
                true, true, true, group.root.diagnosticsArchiveRedactionLevel,
                group.root.diagnosticsArchiveSessionOnly ? group.root.appSessionDayStartMs : 0)
            group.root.rpc.registerRpcCallback(corr,
                function(ok, payload, errorCode, errorMessage) {
                    exportState.busy = false
                    if (!ok) {
                        exportState.failed = true
                        exportState.lastErrorCode = String(errorCode || "unknown")
                        var label = (typeof group.root.ipcErrorLabel === "function")
                            ? group.root.ipcErrorLabel(exportState.lastErrorCode)
                            : exportState.lastErrorCode
                        exportState.message = group.root.tr(
                            "diag.archive.state-failed",
                            "Export failed") + ": " + label
                        return
                    }
                    exportState.failed = false
                    var path = String((payload && payload["archive-path"])
                        || (payload && payload.archive_path) || "")
                    exportState.lastArchivePath = path
                    var lastSep = path.lastIndexOf("\\")
                    if (lastSep < 0) lastSep = path.lastIndexOf("/")
                    exportState.lastArchiveDir = lastSep >= 0
                        ? path.substring(0, lastSep) : ""
                    exportState.lastArchiveSizeBytes = Number(
                        (payload && payload["size-bytes"])
                        || (payload && payload.size_bytes) || 0)
                    exportState.message = group.root.tr(
                        "diag.archive.state-saved-with-size",
                        "Archive saved: {path} ({size})")
                        .replace("{path}", path)
                        .replace("{size}",
                            group.formatBytes(exportState.lastArchiveSizeBytes))
                    group.root.statusLine = exportState.message
                })
        }
    }

    Dialog {
        id: clearLogsConfirm
        x: Math.round((group.Window.width - width) / 2)
        y: Math.round((group.Window.height - height) / 2)
        width: 460
        modal: true
        title: root.tr("diag.logs.clear-confirm-title", "Clear operational logs?")
        background: Rectangle {
            radius: root.uiTheme.radiusSm
            color: root.uiTheme.colorPanel
            border.width: root.uiTheme.borderWidth
            border.color: root.uiTheme.stateDefaultBorder
        }
        header: Rectangle {
            color: root.uiTheme.colorPanel
            implicitHeight: clearLogsTitle.implicitHeight + root.uiTheme.spacingMd * 2
            Label {
                id: clearLogsTitle
                anchors.fill: parent
                anchors.margins: root.uiTheme.spacingMd
                text: clearLogsConfirm.title
                color: root.textColor
                font.bold: true
                wrapMode: Text.WordWrap
                verticalAlignment: Text.AlignVCenter
            }
        }
        ColumnLayout {
            anchors.fill: parent
            anchors.margins: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("diag.logs.clear-confirm-body",
                    "This will permanently delete log files. The audit trail will not be affected.")
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                text: root.tr("diag.logs.clear-dry-run-summary",
                    "Would delete {count} files ({size})")
                    .replace("{count}", String(storageHealth.logFileCount || 0))
                    .replace("{size}", group.formatBytes(storageHealth.logsSizeBytes))
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: root.uiTheme.spacingSm
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.apply", "Apply")
                    enabled: !group._clearing
                    onClicked: {
                        clearLogsConfirm.close()
                        group._performLogsClear()
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
}
