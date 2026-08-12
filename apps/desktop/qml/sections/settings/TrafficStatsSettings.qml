import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import "../../components"
import "../../lib/pure.js" as Pure

// The whole feature in one Settings panel: the
// headline "through additional / through primary" totals, per-adapter
// Received/Sent, the period toggle, the accounting settings, and CSV export.
// Driven by `root.trafficStats` (a TrafficStatsController instantiated in
// Main.qml); the controller polls in the background regardless, but this
// panel raises it to the fast cadence only while actually on screen (see
// `panelVisible` below).
GroupBox {
    id: group
    property var root
    // Set by the owning Loader in SettingsSection.qml from
    // `activeCategory === "traffic"`. Kept as a plain prop (not read
    // straight from a `section` ancestor) because the Loader that creates
    // this component keeps it resident after the first visit (`keepLoaded`),
    // so category switches after that must reach this component through a
    // live binding, not be inferred from creation order.
    property bool categoryActive: false
    title: root.tr("settings.traffic.title", "Traffic statistics")
    Layout.fillWidth: true

    readonly property var ctrl: root.trafficStats
    // True only while this panel is the one actually rendered on screen
    // (Settings section active AND "traffic" category selected).
    readonly property bool panelVisible: categoryActive && root.section === "settings"
    // Selected period, derived from the persisted UI preference so it survives
    // restarts. Writing goes through `_setPeriod` (updatePrefs + emitPrefs).
    readonly property string period:
        (root.uiRevision >= 0 && root.prefs.trafficStatsPeriod === "session") ? "session" : "today"

    readonly property var rows: (ctrl && period === "session") ? ctrl.sessionRows
                              : (ctrl ? ctrl.todayRows : [])

    // Fast-poll gate: mirror `panelVisible` onto the controller so it raises
    // its cadence from 60 s to 3 s only while this panel is on screen, and
    // nudge an immediate refresh on every transition into view (first
    // appearance and every later re-entry) so the user never stares at a
    // stale background-cadence read.
    Binding {
        target: group.ctrl
        property: "trafficPanelVisible"
        value: group.panelVisible
        when: group.ctrl !== null && group.ctrl !== undefined
    }
    onPanelVisibleChanged: if (panelVisible && ctrl) ctrl.refresh()
    Component.onCompleted: if (ctrl) ctrl.refresh()

    function sumRole(role, field) {
        var total = 0
        for (var i = 0; i < group.rows.length; ++i) {
            var r = group.rows[i]
            if (r && r["role"] === role) total += Number(r[field] || 0)
        }
        return total
    }

    // Sum a byte field across ALL roles of an arbitrary row array (used for
    // the all-time grand-total line under the per-session view).
    function sumAll(rowsArr, field) {
        var total = 0
        var a = rowsArr || []
        for (var i = 0; i < a.length; ++i) total += Number((a[i] || {})[field] || 0)
        return total
    }

    // Byte-unit abbreviations are shared, non-feature-scoped texts — reuse the
    // existing catalogue instead of adding traffic-scoped copies of "KB"/"MB".
    function _exportUnitLabel(unit) {
        if (unit === "bytes") return root.tr("diag.retention.size-unit.bytes", "Bytes")
        if (unit === "kb") return root.tr("diag.retention.size-unit.kb", "KB")
        if (unit === "mb") return root.tr("diag.retention.size-unit.mb", "MB")
        if (unit === "gb") return root.tr("diag.retention.size-unit.gb", "GB")
        return unit
    }

    function roleLabel(role) {
        if (role === "primary") return root.tr("settings.traffic.role-primary", "Primary")
        if (role === "secondary") return root.tr("settings.traffic.role-secondary", "Additional")
        if (role === "loopback") return root.tr("settings.traffic.role-loopback", "Local (localhost)")
        if (role === "virtual") return root.tr("settings.traffic.role-virtual", "Virtual (VM)")
        return role
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm

        // Service-stopped notice: the sampler runs inside the background
        // service, so nothing is counted while the service is not running.
        Rectangle {
            Layout.fillWidth: true
            visible: !(root.backendStatus && root.backendStatus.kind === "connected")
            implicitHeight: trafficServiceStoppedRow.implicitHeight + root.uiTheme.spacingSm * 2
            radius: root.uiTheme.radiusSm
            color: Qt.rgba(root.uiTheme.colorWarning.r, root.uiTheme.colorWarning.g,
                root.uiTheme.colorWarning.b, 0.16)
            border.width: root.uiTheme.borderWidth
            border.color: Qt.rgba(root.uiTheme.colorWarning.r, root.uiTheme.colorWarning.g,
                root.uiTheme.colorWarning.b, 0.55)
            RowLayout {
                id: trafficServiceStoppedRow
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: root.uiTheme.spacingSm
                spacing: root.uiTheme.spacingSm
                Rectangle {
                    Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4
                    Layout.alignment: Qt.AlignTop
                    Layout.topMargin: 4
                    color: root.uiTheme.colorWarning
                }
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: root.uiRevision >= 0
                        ? root.tr("settings.traffic.service-stopped",
                            "Statistics are not being collected while the service is stopped.")
                        : ""
                }
            }
        }

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.traffic.description",
                "How much traffic goes through the additional (VPN) adapter versus directly over the primary — received and sent per adapter.")
        }

        // Period selector (This session / Today) as an exclusive radio group,
        // each option with a small secondary-color caption underneath.
        Label {
            text: (root.uiRevision >= 0 ? root.tr("settings.traffic.period", "Period") : "") + ":"
            color: root.textColor
        }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXxs

            ThemedRadioButton {
                theme: root.uiTheme
                text: root.uiRevision >= 0
                    ? root.tr("settings.traffic.period-session", "Additional adapter session") : ""
                checked: group.period === "session"
                onToggled: if (checked) group._setPeriod("session")
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg + root.uiTheme.spacingXs
                Layout.bottomMargin: root.uiTheme.spacingXs
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.uiRevision >= 0
                    ? root.tr("settings.traffic.period-session-note",
                        "Counted while the additional adapter session is active") : ""
            }

            ThemedRadioButton {
                theme: root.uiTheme
                text: root.uiRevision >= 0
                    ? root.tr("settings.traffic.period-today", "Today") : ""
                checked: group.period === "today"
                onToggled: if (checked) group._setPeriod("today")
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg + root.uiTheme.spacingXs
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.uiRevision >= 0
                    ? root.tr("settings.traffic.period-today-note",
                        "All traffic accounted by the service today, with or without the additional adapter") : ""
            }
        }

        // Session status hint: shown only for the "session" period. When no
        // session is currently active, clarify whether the shown figures are a
        // finished session or there has been no session at all.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            visible: group.period === "session"
                && group.ctrl && !group.ctrl.sessionActive
            text: (root.uiRevision >= 0 && group.ctrl && !group.ctrl.sessionActive)
                ? (group.rows.length === 0
                    ? root.tr("settings.traffic.session-none",
                        "The additional adapter has not come up yet — no session so far")
                    : root.tr("settings.traffic.session-last",
                        "Showing the last finished session"))
                : ""
        }

        // Headline: through additional vs through primary.
        Frame {
            Layout.fillWidth: true
            padding: root.uiTheme.spacingSm
            background: CardSurface {
                theme: root.uiTheme
                cornerRadius: root.uiTheme.radiusSm
            }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingXs
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingMd
                    Label {
                        Layout.fillWidth: true
                        color: root.textColor
                        font.bold: true
                        elide: Text.ElideRight
                        text: (root.uiRevision >= 0 ? group._secondaryTitle() : "") + ":"
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.textColor
                        iconSource: root.uiIconSource("traffic-in")
                        label: root.tr("settings.traffic.received", "Received")
                        value: Pure.formatStorageBytes(group.sumRole("secondary", "in-bytes"))
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.textColor
                        iconSource: root.uiIconSource("traffic-out")
                        label: root.tr("settings.traffic.sent", "Sent")
                        value: Pure.formatStorageBytes(group.sumRole("secondary", "out-bytes"))
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingMd
                    Label {
                        Layout.fillWidth: true
                        color: root.textColor
                        font.bold: true
                        elide: Text.ElideRight
                        text: root.tr("settings.traffic.through-primary", "Through primary adapter") + ":"
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.textColor
                        iconSource: root.uiIconSource("traffic-in")
                        label: root.tr("settings.traffic.received", "Received")
                        value: Pure.formatStorageBytes(group.sumRole("primary", "in-bytes"))
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.textColor
                        iconSource: root.uiIconSource("traffic-out")
                        label: root.tr("settings.traffic.sent", "Sent")
                        value: Pure.formatStorageBytes(group.sumRole("primary", "out-bytes"))
                    }
                }
            }
        }

        // Tunnel-overlap honesty note: while a VPN session is active, the
        // primary row above already excludes traffic that transited into the
        // tunnel (block T Feature 1) — say so, so the numbers are not
        // mistaken for double-counted.
        Label {
            Layout.fillWidth: true
            visible: group.ctrl && group.ctrl.sessionActive
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.traffic.tunnel-overlap-note",
                "While a VPN session is active, the primary row excludes traffic that transited into the tunnel.")
        }

        // Per-adapter rows.
        Label {
            visible: group.rows.length === 0
            Layout.fillWidth: true
            color: root.mutedTextColor
            text: root.tr("settings.traffic.no-data", "No data yet — counting starts once traffic flows.")
        }
        Repeater {
            model: group.rows
            delegate: ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Label {
                        Layout.fillWidth: true
                        color: root.textColor
                        elide: Text.ElideRight
                        text: (modelData["display-name"] || modelData["adapter-key"] || "")
                            + "  ·  " + group.roleLabel(modelData["role"])
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.mutedTextColor
                        iconSource: root.uiIconSource("traffic-in")
                        label: root.tr("settings.traffic.received", "Received")
                        value: Pure.formatStorageBytes(Number(modelData["in-bytes"] || 0))
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.mutedTextColor
                        iconSource: root.uiIconSource("traffic-out")
                        label: root.tr("settings.traffic.sent", "Sent")
                        value: Pure.formatStorageBytes(Number(modelData["out-bytes"] || 0))
                    }
                }
                // Last observed local/external address for this adapter (from
                // a user-requested "Refresh interfaces" probe — block T
                // Feature 2). Absent until the user has probed at least once.
                Label {
                    Layout.fillWidth: true
                    visible: !!(modelData["local-ip"] || modelData["external-ip"])
                    color: root.mutedTextColor
                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                    elide: Text.ElideRight
                    text: group._addressLine(modelData)
                }
            }
        }

        // Session total: the current additional-adapter session summed across
        // every role. Session figures reset when a new session begins.
        RowLayout {
            visible: group.period === "session"
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: root.textColor
                text: root.tr("settings.traffic.total-session", "Session total")
            }
            TrafficFigure {
                theme: root.uiTheme
                textColor: root.mutedTextColor
                iconSource: root.uiIconSource("traffic-in")
                label: root.tr("settings.traffic.received", "Received")
                value: Pure.formatStorageBytes(group.sumAll(group.ctrl ? group.ctrl.sessionRows : [], "in-bytes"))
            }
            TrafficFigure {
                theme: root.uiTheme
                textColor: root.mutedTextColor
                iconSource: root.uiIconSource("traffic-out")
                label: root.tr("settings.traffic.sent", "Sent")
                value: Pure.formatStorageBytes(group.sumAll(group.ctrl ? group.ctrl.sessionRows : [], "out-bytes"))
            }
        }

        // All-time grand total: session numbers reset with every
        // additional-adapter session, so the persisted cumulative sum gives
        // them context. Bounded by the retention window configured below.
        RowLayout {
            visible: group.period === "session"
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: root.textColor
                text: root.tr("settings.traffic.total-all-time", "Total (all time)")
            }
            TrafficFigure {
                theme: root.uiTheme
                textColor: root.mutedTextColor
                iconSource: root.uiIconSource("traffic-in")
                label: root.tr("settings.traffic.received", "Received")
                value: Pure.formatStorageBytes(group.sumAll(group.ctrl ? group.ctrl.allTimeRows : [], "in-bytes"))
            }
            TrafficFigure {
                theme: root.uiTheme
                textColor: root.mutedTextColor
                iconSource: root.uiIconSource("traffic-out")
                label: root.tr("settings.traffic.sent", "Sent")
                value: Pure.formatStorageBytes(group.sumAll(group.ctrl ? group.ctrl.allTimeRows : [], "out-bytes"))
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: root.uiTheme.colorBorder
        }

        // Accounting settings.
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.traffic.master-toggle", "Count traffic")
            checked: group.ctrl ? group.ctrl.settings.enabled : true
            onToggled: group._save({ enabled: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.traffic.count-loopback", "Count local (localhost) traffic")
            checked: group.ctrl ? group.ctrl.settings.countLoopback : false
            onToggled: group._save({ countLoopback: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.traffic.count-virtual", "Count virtual (VM) adapters")
            checked: group.ctrl ? group.ctrl.settings.countVirtual : false
            onToggled: group._save({ countVirtual: checked })
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: root.textColor
                text: root.tr("settings.traffic.retention-days", "Keep daily history for (days)")
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                editable: true
                from: 7; to: 3650
                value: group.ctrl ? group.ctrl.settings.retentionDays : 365
                onValueModified: group._save({ retentionDays: value })
            }
            Label {
                text: "(7–3650)"
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.traffic.export-csv", "Export CSV")
                icon.source: root.uiIconSource("download")
                onClicked: csvFileDialog.open()
            }
            Label {
                color: root.textColor
                text: (root.uiRevision >= 0
                    ? root.tr("settings.traffic.export-unit", "Export units") : "") + ":"
            }
            // Unit for the exported byte columns. Megabytes by default; the
            // pick is remembered, so a user who works in one unit does not
            // re-select it on every export.
            ThemedComboBox {
                id: exportUnitCombo
                theme: root.uiTheme
                Layout.preferredWidth: 120
                Layout.minimumWidth: 120
                model: [ "bytes", "kb", "mb", "gb" ]
                // A declarative `currentIndex` binding would be destroyed by the
                // first pick, so a later external change (reset, prefs reload)
                // would stop being reflected. A Binding element keeps
                // re-asserting from prefs.
                Binding {
                    target: exportUnitCombo
                    property: "currentIndex"
                    value: root.uiRevision >= 0
                        ? Math.max(0, exportUnitCombo.model.indexOf(
                            String(root.prefs.trafficExportUnit || "mb")))
                        : 0
                }
                onActivated: {
                    var picked = String(model[currentIndex])
                    if (picked !== String(root.prefs.trafficExportUnit || "")) {
                        root.updatePrefs({ trafficExportUnit: picked })
                        root.emitPrefs()
                    }
                }
                labelResolver: function(item) { return group._exportUnitLabel(item) }
                displayText: root.uiRevision >= 0 && currentIndex >= 0
                    ? group._exportUnitLabel(model[currentIndex]) : ""
                popup.width: root.comboPopupWidth(exportUnitCombo, model, "",
                    function(item) { return group._exportUnitLabel(item) })
                Accessible.role: Accessible.ComboBox
                Accessible.name: root.tr("settings.traffic.export-unit", "Export units")
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.traffic.reset", "Reset statistics")
                icon.source: root.uiIconSource("clear")
                onClicked: if (group.ctrl) group.ctrl.clear()
            }
        }

        // CSV export — native save dialog, then the controller fetches the
        // `;`-delimited blob and the bridge writes it (same `writeTextFile`
        // path the preset export uses).
        FileDialog {
            id: csvFileDialog
            fileMode: FileDialog.SaveFile
            title: root.tr("settings.traffic.export-csv", "Export CSV")
            nameFilters: [ "CSV (*.csv)", "All files (*)" ]
            defaultSuffix: "csv"
            onAccepted: {
                if (!group.ctrl) return
                var path = group._localPathFromUrl(selectedFile)
                var today = group.ctrl.epochDay()
                var from = today - Number(group.ctrl.settings.retentionDays || 365)
                // Read the remembered unit rather than the combo's index: the
                // preference is the source of truth and survives a reload.
                var unit = String(root.prefs.trafficExportUnit || "mb")
                group.ctrl.requestExport(from, today, unit, function(csv) {
                    if (csv && csv !== ""
                        && typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                        && typeof nrrNativeBridge.writeTextFile === "function") {
                        nrrNativeBridge.writeTextFile(path, csv)
                    }
                })
            }
        }
    }

    // QtQuick.Dialogs `selectedFile` is a `file:///` QUrl; strip to a plain
    // local path for the bridge's QFile write.
    function _localPathFromUrl(urlValue) {
        var s = String(urlValue || "")
        if (s.indexOf("file:///") === 0) return s.substring(8)
        if (s.indexOf("file://") === 0) return s.substring(7)
        return s
    }

    // Persist the selected period as a device-local UI preference. It is a
    // non-arming key, so it never lights up the footer Apply/Cancel; write it
    // straight through (updatePrefs mirror + emitPrefs to persist).
    function _setPeriod(next) {
        if (group.period === next) return
        root.updatePrefs({ trafficStatsPeriod: next })
        root.emitPrefs()
    }

    // Headline title for the "through additional adapter" total, suffixed with
    // the user's own secondary route name when they gave it a custom one
    // (e.g. "Through additional adapter (VPN)"). Default/empty names are
    // omitted to avoid a redundant "(Additional)".
    function _secondaryTitle() {
        var base = root.tr("settings.traffic.through-secondary", "Through additional adapter")
        var lbl = String(root.prefs.routeSecondaryLabel || "")
        if (lbl !== "" && lbl !== root.defaultRouteLabel("secondary"))
            return base + " (" + lbl + ")"
        return base
    }

    // Compact "IP: ... · external: ... (observed at)" line for one adapter
    // row (block T Feature 2). Either half is omitted when absent so a
    // local-only or never-probed row never shows a stray separator.
    function _addressLine(row) {
        var parts = []
        if (row["local-ip"]) {
            parts.push(root.tr("settings.traffic.address-local", "IP") + ": " + row["local-ip"])
        }
        if (row["external-ip"]) {
            var seen = group._formatObservedAt(row["external-ip-observed-at-ms"])
            parts.push(root.tr("settings.traffic.address-external", "external") + ": " + row["external-ip"]
                + (seen ? " (" + seen + ")" : ""))
        }
        return parts.join("  ·  ")
    }

    // Compact local date/time for the "observed at" hint — "dd.MM HH:mm" in
    // the user's local timezone (the wire field is epoch-ms UTC).
    function _formatObservedAt(ms) {
        var n = Number(ms || 0)
        if (!isFinite(n) || n <= 0) return ""
        var d = new Date(n)
        function pad(x) { return (x < 10 ? "0" : "") + String(x) }
        return pad(d.getDate()) + "." + pad(d.getMonth() + 1) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes())
    }

    // Merge one changed field into the current settings and persist.
    function _save(patch) {
        if (!ctrl) return
        var s = ctrl.settings
        ctrl.applySettings({
            enabled: patch.enabled !== undefined ? patch.enabled : s.enabled,
            countLoopback: patch.countLoopback !== undefined ? patch.countLoopback : s.countLoopback,
            countVirtual: patch.countVirtual !== undefined ? patch.countVirtual : s.countVirtual,
            retentionDays: patch.retentionDays !== undefined ? patch.retentionDays : s.retentionDays
        })
    }
}
