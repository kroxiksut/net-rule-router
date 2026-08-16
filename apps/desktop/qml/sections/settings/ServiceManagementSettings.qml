import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

// Settings → Service management panel.
//
// Reads service status from `nrrServiceController` (Q_INVOKABLE bridge
// installed by the C++ host). All texts go through `root.tr(...)` so
// the panel respects the active locale.
//
// Polling: a 2-second Timer fires `refreshStatus()` while the panel is
// visible. When the user switches to another category the Timer
// pauses (no background polling from the Settings tree — the tray has
// its own 10-second cadence).
GroupBox {
    id: group
    property var root
    Layout.fillWidth: true

    // Map controller status enum (int) to a kebab slug for locale.
    // Mirrors NrrServiceController::Status:
    //   0=Unknown, 1=NotInstalled, 2=Stopped, 3=StartPending, 4=Running, 5=StopPending
    function _statusSlug(status) {
        switch (parseInt(status)) {
            case 4: return "running"
            case 2: return "stopped"
            case 3: return "start-pending"
            case 5: return "stop-pending"
            case 1: return "not-installed"
            default: return "unknown"
        }
    }

    function _statusLabel(status) {
        return root.tr("settings.service.status." + _statusSlug(status),
            _statusSlug(status))
    }

    function _statusColor(status) {
        switch (_statusSlug(status)) {
            case "running":       return "#2eb872"
            case "stopped":       return "#d4a017"
            case "start-pending": return "#888888"
            case "stop-pending":  return "#888888"
            case "not-installed": return "#c0392b"
            default:              return "#888888"
        }
    }

    function _serviceAvailable() {
        return typeof nrrServiceController !== "undefined"
            && nrrServiceController !== null
    }

    // True while an elevated install/start/stop/uninstall/
    // restart leg is in flight. Drives the in-panel progress indicator and
    // disables the action buttons so the user can't double-dispatch.
    function _busy() {
        return group._serviceAvailable() && nrrServiceController.busy === true
    }

    // The "-ing" verb shown next to the in-panel BusyIndicator.
    function _progressRunningLabel(operation) {
        return root.tr("progress.service-" + String(operation) + "-running",
            String(operation) + "…")
    }

    title: root.tr("settings.service.title", "Service management")

    Timer {
        id: pollTimer
        interval: 2000
        repeat: true
        running: group.visible && group._serviceAvailable()
        onTriggered: nrrServiceController.refreshStatus()
    }

    // Panel-local status-line echo. The global footer progress pill
    // (`logProgress`) is fed from Main.qml so it works regardless of which
    // surface triggered the operation (first-launch dialog, tray, etc.);
    // keeping it out of here avoids double-logging when this panel is open.
    Connections {
        target: group._serviceAvailable() ? nrrServiceController : null
        ignoreUnknownSignals: true
        function onOperationCompleted(operation, success, errorMessage) {
            if (success) {
                root.statusLine = root.tr(
                    "settings.service.action." + String(operation), String(operation))
                    + " — OK"
            } else {
                root.statusLine = root.tr(
                    "settings.service.action." + String(operation), String(operation))
                    + ": " + String(errorMessage || "")
            }
        }
        function onUacDeclined(operation) {
            root.statusLine = root.tr(
                "dialog.uac-required.declined-body",
                "The Administrator prompt was declined. You can retry from Settings → Service management.")
        }
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.service.description",
                "NetRuleRouter runs as a Windows background service. Install or manage it from here.")
        }

        // ── Status badge ─────────────────────────────────────────
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingMd
            Rectangle {
                Layout.preferredWidth: 14
                Layout.preferredHeight: 14
                radius: 7
                color: group._statusColor(
                    group._serviceAvailable() ? nrrServiceController.status : 0)
            }
            Label {
                Layout.fillWidth: true
                color: root.textColor
                font.bold: true
                text: group._statusLabel(
                    group._serviceAvailable() ? nrrServiceController.status : 0)
            }
        }

        // The SCM transitional states (start-pending /
        // stop-pending) flashed a bare status word for ~2s with no progress
        // cue, which reads as "stuck" / alarming to a normal user. Show a
        // spinner + a reassuring "this is normal, give it a moment" caption
        // for exactly those transient states.
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            visible: group._serviceAvailable()
                && (group._statusSlug(nrrServiceController.status) === "start-pending"
                    || group._statusSlug(nrrServiceController.status) === "stop-pending")
            BusyIndicator {
                running: parent.visible
                Layout.preferredWidth: 18
                Layout.preferredHeight: 18
            }
            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.service.status.transition-hint",
                    "This is normal and usually takes a few seconds — no action needed.")
            }
        }

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            visible: group._serviceAvailable()
                && String(nrrServiceController.statusReason || "") !== ""
            // The C++ controller sets a raw
            // English `statusReason`. Map the common, user-facing one
            // ("Service not registered") through the locale tree; the rest
            // are Win32 diagnostics ("OpenService failed: 5") that stay
            // verbatim as developer detail.
            text: {
                if (!group._serviceAvailable()) {
                    return ""
                }
                var raw = String(nrrServiceController.statusReason || "")
                if (raw === "Service not registered") {
                    return root.tr("settings.service.reason.not-registered",
                        "Service is not registered in the system.")
                }
                return raw
            }
            wrapMode: Text.WordWrap
        }

        // ── In-progress indicator ────────────────────────────────
        // Visible only while an elevated leg is in flight. Stays up
        // across chained legs (install→start, restart=stop→start)
        // because the controller keeps `busy` true between them.
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingMd
            visible: group._busy()

            BusyIndicator {
                running: group._busy()
                Layout.preferredWidth: 22
                Layout.preferredHeight: 22
            }
            Label {
                Layout.fillWidth: true
                color: root.textColor
                wrapMode: Text.WordWrap
                text: group._busy()
                    ? group._progressRunningLabel(nrrServiceController.activeOperation)
                    : ""
            }
        }

        // Admin affordance: service control is elevated.
        // The session broker asks for administrator approval once and reuses
        // it for the rest of the session (and for an admin baseline edit).
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            visible: group._serviceAvailable()
            Image {
                Layout.preferredWidth: 16
                Layout.preferredHeight: 16
                Layout.alignment: Qt.AlignTop
                source: root.uiIconSource("shield")
                sourceSize.width: 16
                sourceSize.height: 16
                fillMode: Image.PreserveAspectFit
            }
            Label {
                Layout.fillWidth: true
                color: root.textColor
                wrapMode: Text.WordWrap
                opacity: 0.85
                text: root.tr("settings.service.admin-hint",
                    "These actions require administrator approval — asked once per session.")
            }
        }

        // ── Action buttons ───────────────────────────────────────
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm

            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.service.action.install", "Install service")
                icon.source: root.uiIconSource("add")
                highlighted: true
                enabled: !group._busy()
                visible: group._serviceAvailable()
                    && _statusSlug(nrrServiceController.status) === "not-installed"
                onClicked: nrrServiceController.installService()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.service.action.start", "Start service")
                icon.source: root.uiIconSource("apply")
                enabled: !group._busy()
                visible: group._serviceAvailable()
                    && _statusSlug(nrrServiceController.status) === "stopped"
                onClicked: root.startServiceOrOfferUpdate()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.service.action.stop", "Stop service")
                icon.source: root.uiIconSource("stop")
                enabled: !group._busy()
                visible: group._serviceAvailable()
                    && _statusSlug(nrrServiceController.status) === "running"
                onClicked: nrrServiceController.stopService()
                // Persist-on-stop — clarify the user's original confusion:
                // stopping the service turns routing OFF (unless persist mode);
                // merely closing the app keeps routing on (service keeps running).
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: root.tr(
                    "settings.service.action.stop-tooltip",
                    "Stops the background service. Routing is turned off and traffic returns to the working channel — unless you enabled \"Keep matched routes active when the service stops\". Note: simply closing the app keeps routing active, because the service keeps running.")
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.service.action.restart", "Restart service")
                icon.source: root.uiIconSource("refresh")
                enabled: !group._busy()
                visible: group._serviceAvailable()
                    && _statusSlug(nrrServiceController.status) === "running"
                onClicked: nrrServiceController.restartService()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.service.action.uninstall", "Uninstall service")
                icon.source: root.uiIconSource("delete")
                enabled: !group._busy()
                visible: group._serviceAvailable()
                    && (_statusSlug(nrrServiceController.status) === "stopped"
                        || _statusSlug(nrrServiceController.status) === "running")
                onClicked: nrrServiceController.uninstallService()
            }
            Item { Layout.fillWidth: true }
        }

        // ── The registered service is not this one ──
        // An update ships a new service binary, but Windows keeps starting the
        // one it has registered — so a newer app talks to an older service, or
        // to a copy in the folder the user replaced. Neither is visible
        // anywhere else, and only a re-registration fixes it.
        ColumnLayout {
            id: serviceUpdateBlock
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            spacing: root.uiTheme.spacingXxs
            visible: group._serviceAvailable() && root.serviceUpdateAvailable

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.serviceRegisteredElsewhere
                    ? root.tr("settings.service.update.elsewhere",
                        "Windows starts the background service from another folder, not the one this application runs from.")
                    : root.tr("settings.service.update.older",
                        "The running background service is an older build than this application.")
            }
            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.service.update.detail",
                        "Registered: %1\nThis application: %2")
                    .arg(root.serviceRegisteredPath || root.tr("settings.service.status.unknown", "unknown"))
                    .arg(root.serviceExpectedPath || root.tr("settings.service.status.unknown", "unknown"))
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("settings.service.update.action", "Update service from this folder")
                    icon.source: root.uiIconSource("refresh")
                    highlighted: true
                    enabled: !group._busy()
                    onClicked: serviceUpdateConfirm.open()
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: root.tr("settings.service.update.tooltip",
                        "Needs administrator rights. The service restarts, so routing pauses for a moment. Your rules and settings are kept.")
                }
                Item { Layout.fillWidth: true }
            }
        }

        ServiceUpdateConfirmDialog {
            id: serviceUpdateConfirm
            ownerRoot: root
            onConfirmed: nrrServiceController.reinstallService()
        }

        // ── The file was replaced, the old process is still running ──
        // An update written over the same folder leaves the registration
        // correct, so there is nothing to re-register — but the service in
        // memory is still the previous build until it restarts.
        ColumnLayout {
            id: serviceRestartBlock
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            spacing: root.uiTheme.spacingXxs
            visible: group._serviceAvailable() && root.serviceRestartNeeded

            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("settings.service.stale-process.description",
                    "The service program file was updated, but the service is still running the previous version. Restart it to run the update.")
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("settings.service.action.restart", "Restart service")
                    icon.source: root.uiIconSource("refresh")
                    highlighted: true
                    enabled: !group._busy()
                    onClicked: nrrServiceController.restartService()
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: root.tr("settings.service.stale-process.tooltip",
                        "Needs administrator rights. Routing pauses for a moment while the service restarts.")
                }
                Item { Layout.fillWidth: true }
            }
        }

        // ── Emergency network recovery ──
        // Separated from the lifecycle buttons above on purpose: those manage
        // the service, this one undoes what the service left behind after a
        // crash. Runs the service binary's own teardown through the same
        // elevated broker the console uses — one implementation of "undo".
        ColumnLayout {
            id: recoveryBlock
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            spacing: root.uiTheme.spacingXxs
            // Hidden where the service applies no network state, rather than
            // offering a button that would have nothing to undo. Capability
            // query, not an OS check — the same gate every other section uses.
            visible: group._serviceAvailable() && root.supports("killSwitch")

            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.service.recovery.description",
                    "If the service was killed without shutting down, its packet filters, DNS redirect and routes can stay behind and cut this machine off the network. This removes them.")
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("settings.service.recovery.action", "Restore network")
                    icon.source: root.uiIconSource("refresh")
                    enabled: !group._busy()
                    onClicked: recoveryConfirm.open()
                    ToolTip.visible: hovered
                    ToolTip.delay: 400
                    ToolTip.text: root.tr("settings.service.recovery.tooltip",
                        "Needs administrator rights. Connections open right now may drop.")
                }
                Item { Layout.fillWidth: true }
            }
        }

        NetworkRecoveryConfirmDialog {
            id: recoveryConfirm
            ownerRoot: root
            onConfirmed: nrrServiceController.resetNetwork()
        }

        // ── #7 — service start mode (admin-opt-in) ──
        // Switching to "start when the app opens" grants the interactive user a
        // targeted SERVICE_START right so the launcher can start the service
        // without a per-launch UAC prompt. Elevation-gated → shield.
        ColumnLayout {
            id: startModeBlock
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            spacing: root.uiTheme.spacingXxs
            visible: group._serviceAvailable()
                && _statusSlug(nrrServiceController.status) !== "not-installed"

            property string startMode: ""
            function refreshStartMode() {
                if (group._serviceAvailable()) {
                    startModeBlock.startMode =
                        String(nrrServiceController.queryServiceStartMode() || "")
                }
            }
            Component.onCompleted: Qt.callLater(startModeBlock.refreshStartMode)

            Connections {
                target: group._serviceAvailable() ? nrrServiceController : null
                function onOperationCompleted(operation, success, errorMessage) {
                    if (success && String(operation).indexOf("set-start") === 0) {
                        startModeBlock.refreshStartMode()
                    }
                }
            }

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
                    text: root.tr("settings.service.start-mode.heading",
                        "When the service starts")
                    color: root.textColor
                    font.bold: true
                }
            }

            ButtonGroup { id: startModeGroup }

            RadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: startModeGroup
                enabled: !group._busy()
                // Default (empty) reads as start-with-Windows.
                checked: startModeBlock.startMode === "with-windows"
                    || startModeBlock.startMode === ""
                text: root.tr("settings.service.start-mode.with-windows.label",
                    "Start with Windows (recommended)")
                onClicked: {
                    if (startModeBlock.startMode !== "with-windows"
                        && group._serviceAvailable()) {
                        nrrServiceController.setServiceStartMode("with-windows")
                    }
                }
            }
            RadioButton {
                Layout.fillWidth: true
                ButtonGroup.group: startModeGroup
                enabled: !group._busy()
                checked: startModeBlock.startMode === "on-app-launch"
                text: root.tr("settings.service.start-mode.on-app-launch.label",
                    "Start when the app opens")
                onClicked: {
                    if (startModeBlock.startMode !== "on-app-launch"
                        && group._serviceAvailable()) {
                        nrrServiceController.setServiceStartMode("on-app-launch")
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.service.start-mode.help",
                    "“Start with Windows” keeps your rules enforced from boot, before anyone logs in (best for always-on or managed setups). “Start when the app opens” runs the service only while you use NetRuleRouter and lets the app start it without an administrator prompt every time. Changing this needs administrator approval.")
            }
        }

        // ── Tray at sign-in (companion to service start mode) ──
        // The service runs as LocalSystem in session 0 and CANNOT launch the
        // interactive tray. The only "tray at boot" path is the HKCU Run key
        // firing at user sign-in — the SAME mechanism as the General-settings
        // autostart toggle. This companion checkbox drives it here, next to the
        // service start-mode, so both boot behaviours are configured together;
        // it stays in sync with that toggle via the shared
        // `routingState.autostartEnabled` SSOT (both read/write the one Run
        // key). Not gated on service availability — tray autostart is owned by
        // the launcher and works even with the service uninstalled.
        CheckBox {
            id: trayAtSignInCheckbox
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            text: root.tr("settings.service.launch-tray.label",
                "Also start the tray at sign-in")
            checked: (root.uiRevision >= 0)
                ? (root.routingState.autostartEnabled === true) : false
            onToggled: root.setAutostartEnabled(checked)
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.service.launch-tray.description",
                "The service starts at boot before anyone logs in and cannot open the tray itself. This starts the tray icon when you sign in — the same setting as “Start the tray automatically at sign-in” in General.")
        }

        // ── Crash recovery info ──────────────────────────────────
        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.service.crash-recovery",
                "Service will auto-restart up to 3 times after failures.")
        }

        // ── Service logs ─────────────────────────────────────────
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("settings.service.action.open-logs",
                "Open service logs folder")
            icon.source: root.uiIconSource("logs")
            enabled: group._serviceAvailable()
            onClicked: {
                if (!group._serviceAvailable()) { return }
                var p = String(nrrServiceController.serviceLogsDirectoryPath() || "")
                if (!p) {
                    root.statusLine = root.tr(
                        "settings.service.logs-path-unavailable",
                        "Service logs folder path unavailable.")
                    return
                }
                Qt.openUrlExternally("file:///" + p.replace(/\\/g, "/"))
            }
        }

        // ── Manual sidecar comment GC ──────────
        // Auto-GC runs once on every cold-start (Main.qml::loadContext
        // tail), but a power user who has churned through many rule
        // edits in one session may want to reclaim the per-user
        // metadata file without a restart. Reuses the same
        // `rpcSidecarCommentGc` call; surfaces the removed-count
        // through the bottom status banner.
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("settings.service.action.gc-orphan-comments",
                "Clear orphan comments")
            icon.source: root.uiIconSource("clear")
            onClicked: {
                if (typeof root.manualGcSidecarCommentOrphans === "function") {
                    root.manualGcSidecarCommentOrphans()
                }
            }
        }

        // ── Administrator rights idle auto-revoke ────────────────
        // The elevated broker session is dropped once it has sat unused for
        // the configured number of minutes; every privileged operation
        // restarts that idle timer. The bounds here mirror the backend clamp.
        ColumnLayout {
            id: adminAutoRevokeBlock
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            spacing: root.uiTheme.spacingXxs

            readonly property int minMinutes: 1
            readonly property int maxMinutes: 180
            readonly property int defaultMinutes: 15

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
                    text: root.tr("settings.service.admin-auto-revoke.title",
                        "Administrator rights")
                    color: root.textColor
                    font.bold: true
                }
            }

            CheckBox {
                id: adminAutoRevokeDisabledCheckbox
                Layout.fillWidth: true
                text: root.tr("settings.service.admin-auto-revoke.disable-label",
                    "Do not revoke administrator approval automatically")
                checked: (root.uiRevision >= 0)
                    ? (root.prefs.adminAutoRevokeDisabled === true) : false
                contentItem: Label {
                    text: adminAutoRevokeDisabledCheckbox.text
                    leftPadding: adminAutoRevokeDisabledCheckbox.indicator.width
                        + adminAutoRevokeDisabledCheckbox.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: {
                    root.updatePrefs({ adminAutoRevokeDisabled: checked })
                    root.emitPrefs()
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg
                spacing: root.uiTheme.spacingSm
                enabled: (root.uiRevision >= 0)
                    ? (root.prefs.adminAutoRevokeDisabled !== true) : true

                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: root.tr("settings.service.admin-auto-revoke.minutes-label",
                        "Revoke after this long unused (minutes)")
                }
                ThemedSpinBox {
                    id: adminAutoRevokeMinutesField
                    theme: root.uiTheme
                    Layout.preferredWidth: 140
                    editable: true
                    from: adminAutoRevokeBlock.minMinutes
                    to: adminAutoRevokeBlock.maxMinutes
                    value: root.uiRevision >= 0
                        ? Math.max(adminAutoRevokeBlock.minMinutes,
                            Math.min(adminAutoRevokeBlock.maxMinutes,
                                Number(root.prefs.adminAutoRevokeMinutes
                                    || adminAutoRevokeBlock.defaultMinutes)))
                        : adminAutoRevokeBlock.defaultMinutes
                    onValueModified: {
                        if (value !== Number(root.prefs.adminAutoRevokeMinutes
                                || adminAutoRevokeBlock.defaultMinutes)) {
                            root.updatePrefs({ adminAutoRevokeMinutes: value })
                            root.emitPrefs()
                        }
                    }
                    Accessible.name: root.tr(
                        "settings.service.admin-auto-revoke.minutes-label",
                        "Revoke after this long unused (minutes)")
                }
                Label {
                    text: "(" + adminAutoRevokeBlock.minMinutes + "–"
                        + adminAutoRevokeBlock.maxMinutes + ")"
                    color: root.mutedTextColor
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.service.admin-auto-revoke.note",
                    "After you approve administrator access, it stays available without new prompts. If it sits unused for this long, the app gives it up on its own; the next administrative action will ask again.")
            }
        }
    }
}
