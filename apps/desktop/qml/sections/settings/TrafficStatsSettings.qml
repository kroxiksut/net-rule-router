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
    readonly property string period: root.uiRevision >= 0
        ? ((root.prefs.trafficStatsPeriod === "session"
            || root.prefs.trafficStatsPeriod === "all-time")
            ? String(root.prefs.trafficStatsPeriod) : "today")
        : "today"

    /// The rows every figure on this panel is derived from. All three periods
    /// carry the same per-adapter shape with a `role`, so one rendering serves
    /// whichever is selected.
    readonly property var rows: !ctrl ? []
                              : (period === "session") ? ctrl.sessionRows
                              : (period === "all-time") ? ctrl.allTimeRows
                              : ctrl.todayRows

    /// `rows` folded into one block per role — see `_buildGroups`.
    readonly property var groups: root.uiRevision >= 0 ? group._buildGroups(rows) : []

    /// The grand total earns its line only when more than one role carried
    /// traffic; otherwise it just repeats the single headline above it.
    readonly property bool showPeriodTotal: {
        var withData = 0
        for (var i = 0; i < groups.length; ++i) {
            if (Number(groups[i].inBytes) + Number(groups[i].outBytes) > 0) withData += 1
        }
        return withData >= 2
    }

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

    // Sum a byte field across every role of a row array.
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

    // Folds the selected period's rows into one block per role, in a fixed
    // order. Routed roles keep a zero line — "nothing went through the
    // additional adapter" is itself an answer; the opt-in buckets are noise
    // when empty. Adapters inside a role are ordered by volume.
    function _buildGroups(src) {
        var order = [ "secondary", "primary", "loopback", "virtual" ]
        var byRole = {}
        var a = src || []
        // Nothing counted at all for the period: the "no data" line says it
        // better than a card of zeroes.
        if (a.length === 0) return []
        for (var i = 0; i < a.length; ++i) {
            var r = a[i]
            if (!r) continue
            var slug = String(r["role"] || "")
            if (!byRole[slug]) byRole[slug] = []
            byRole[slug].push(r)
        }
        var out = []
        for (var k = 0; k < order.length; ++k) {
            var role = order[k]
            var list = (byRole[role] || []).slice()
            if (list.length === 0 && role !== "primary" && role !== "secondary") continue
            list.sort(function(x, y) {
                return (Number(y["in-bytes"] || 0) + Number(y["out-bytes"] || 0))
                     - (Number(x["in-bytes"] || 0) + Number(x["out-bytes"] || 0))
            })
            var inB = 0
            var outB = 0
            for (var j = 0; j < list.length; ++j) {
                inB += Number(list[j]["in-bytes"] || 0)
                outB += Number(list[j]["out-bytes"] || 0)
            }
            out.push({
                role: role,
                title: group._roleTitle(role, list),
                adapters: list,
                collapsed: list.length === 1,
                inBytes: inB,
                outBytes: outB
            })
        }
        return out
    }

    // Role headline. The user's own route label is appended only when it adds
    // something: a default label, or one identical to the single adapter named
    // right below it, would repeat what is already on screen.
    function _roleTitle(role, list) {
        if (role === "loopback") return root.tr("settings.traffic.role-loopback", "Local (localhost)")
        if (role === "virtual") return root.tr("settings.traffic.role-virtual", "Virtual (VM)")
        var base = role === "secondary"
            ? root.tr("settings.traffic.through-secondary", "Through additional adapter")
            : root.tr("settings.traffic.through-primary", "Through primary adapter")
        var lbl = String((role === "secondary"
            ? root.prefs.routeSecondaryLabel
            : root.prefs.routePrimaryLabel) || "")
        if (lbl === "" || lbl === root.defaultRouteLabel(role)) return base
        if (list.length === 1 && group._sameName(lbl, group._adapterName(list[0]))) return base
        return base + " (" + lbl + ")"
    }

    function _adapterName(row) {
        if (!row) return ""
        return String(row["display-name"] || row["adapter-key"] || "")
    }

    function _sameName(a, b) {
        return String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase()
    }

    // Whether the adapter of this row still holds the role it was counted
    // under. Roles are reassignable, so a history period can list an adapter
    // that has since been swapped out — showing it unmarked would read as a
    // claim about the current setup.
    function _holdsRoleNow(row) {
        var role = String((row || {})["role"] || "")
        if (role !== "primary" && role !== "secondary") return true
        var assigned = String((role === "secondary"
            ? root.prefs.selectedSecondaryInterfaceName
            : root.prefs.selectedPrimaryInterfaceName) || "")
        // Nothing assigned right now: no ground to call anything stale.
        if (assigned === "") return true
        return group._sameName(assigned, group._adapterName(row))
            || group._sameName(assigned, String((row || {})["adapter-key"] || ""))
    }

    function _adapterCaption(row) {
        if (!row) return ""
        var name = group._adapterName(row)
        if (group._holdsRoleNow(row)) return name
        return name + "  ·  " + root.tr("settings.traffic.role-not-current", "not in this role now")
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

        // One connection stopped being seen while another appeared in its
        // place, and the two names share a word. Asked HERE because the answer
        // is about two of the rows below it — this is the only screen where the
        // user has what they need to decide. There is no third "later" button:
        // the pair is recorded either way, so the question is asked once.
        Rectangle {
            Layout.fillWidth: true
            visible: group.ctrl !== null && group.ctrl !== undefined
                && group.ctrl.historyMerge !== null
            implicitHeight: historyMergeColumn.implicitHeight + root.uiTheme.spacingSm * 2
            radius: root.uiTheme.radiusSm
            color: Qt.rgba(root.uiTheme.colorAccent.r, root.uiTheme.colorAccent.g,
                root.uiTheme.colorAccent.b, 0.12)
            border.width: root.uiTheme.borderWidth
            border.color: Qt.rgba(root.uiTheme.colorAccent.r, root.uiTheme.colorAccent.g,
                root.uiTheme.colorAccent.b, 0.45)
            ColumnLayout {
                id: historyMergeColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: root.uiTheme.spacingSm
                spacing: root.uiTheme.spacingXs
                Label {
                    Layout.fillWidth: true
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    text: {
                        var q = group.ctrl ? group.ctrl.historyMerge : null
                        if (!q) return ""
                        return root.tr("settings.traffic.history-merge.question",
                                "\"{old}\" stopped appearing and \"{new}\" took its place. Is this the same connection, so its history should continue as one?")
                            .replace("{old}", q.oldName)
                            .replace("{new}", q.newName)
                    }
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }
                Label {
                    Layout.fillWidth: true
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                    text: root.tr("settings.traffic.history-merge.hint",
                        "Answered once. If they are different connections, their histories stay apart and you will not be asked again.")
                }
                RowLayout {
                    spacing: root.uiTheme.spacingSm
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("settings.traffic.history-merge.same",
                            "Same connection")
                        onClicked: if (group.ctrl) group.ctrl.answerHistoryMerge(true)
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("settings.traffic.history-merge.different",
                            "Different connections")
                        onClicked: if (group.ctrl) group.ctrl.answerHistoryMerge(false)
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                    }
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

            ThemedRadioButton {
                theme: root.uiTheme
                text: root.uiRevision >= 0
                    ? root.tr("settings.traffic.period-all-time", "All time") : ""
                checked: group.period === "all-time"
                onToggled: if (checked) group._setPeriod("all-time")
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg + root.uiTheme.spacingXs
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.uiRevision >= 0
                    ? root.tr("settings.traffic.period-all-time-note",
                        "Everything counted since the service was installed, split the same way") : ""
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

        // No data at all for the selected period.
        Label {
            visible: group.groups.length === 0
            Layout.fillWidth: true
            color: root.mutedTextColor
            text: root.tr("settings.traffic.no-data", "No data yet — counting starts once traffic flows.")
        }

        // One block per role: the headline carries the role's sum, and the
        // adapters that produced it sit under it. Roles are reassignable, so
        // "today" / "all time" legitimately hold several adapters per role — a
        // role with exactly one collapses to a caption instead of repeating the
        // same figures twice.
        Frame {
            Layout.fillWidth: true
            visible: group.groups.length > 0
            padding: root.uiTheme.spacingSm
            background: CardSurface {
                theme: root.uiTheme
                cornerRadius: root.uiTheme.radiusSm
            }
            ColumnLayout {
                anchors.fill: parent
                spacing: root.uiTheme.spacingSm

                Repeater {
                    model: group.groups
                    delegate: ColumnLayout {
                        id: roleBlock
                        property var g: modelData
                        Layout.fillWidth: true
                        spacing: 2

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: root.uiTheme.spacingMd
                            Label {
                                Layout.fillWidth: true
                                color: root.textColor
                                font.bold: true
                                elide: Text.ElideRight
                                text: (root.uiRevision >= 0 ? roleBlock.g.title : "") + ":"
                            }
                            TrafficFigure {
                                theme: root.uiTheme
                                textColor: root.textColor
                                iconSource: root.uiIconSource("traffic-in")
                                label: root.tr("settings.traffic.received", "Received")
                                value: Pure.formatStorageBytes(roleBlock.g.inBytes)
                            }
                            TrafficFigure {
                                theme: root.uiTheme
                                textColor: root.textColor
                                iconSource: root.uiIconSource("traffic-out")
                                label: root.tr("settings.traffic.sent", "Sent")
                                value: Pure.formatStorageBytes(roleBlock.g.outBytes)
                            }
                        }

                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: root.uiTheme.spacingSm
                            visible: roleBlock.g.collapsed
                            color: root.mutedTextColor
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                            elide: Text.ElideRight
                            text: (root.uiRevision >= 0 && roleBlock.g.collapsed)
                                ? group._adapterCaption(roleBlock.g.adapters[0]) : ""
                        }
                        Label {
                            Layout.fillWidth: true
                            Layout.leftMargin: root.uiTheme.spacingSm
                            visible: roleBlock.g.collapsed
                                && group._addressLine(roleBlock.g.adapters[0]) !== ""
                            color: root.mutedTextColor
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                            elide: Text.ElideRight
                            text: roleBlock.g.collapsed
                                ? group._addressLine(roleBlock.g.adapters[0]) : ""
                        }

                        Repeater {
                            model: roleBlock.g.collapsed ? [] : roleBlock.g.adapters
                            delegate: ColumnLayout {
                                id: adapterRow
                                property var a: modelData
                                Layout.fillWidth: true
                                Layout.leftMargin: root.uiTheme.spacingSm
                                spacing: 0
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: root.uiTheme.spacingSm
                                    Label {
                                        Layout.fillWidth: true
                                        color: root.textColor
                                        elide: Text.ElideRight
                                        text: root.uiRevision >= 0
                                            ? group._adapterCaption(adapterRow.a) : ""
                                    }
                                    TrafficFigure {
                                        theme: root.uiTheme
                                        textColor: root.mutedTextColor
                                        iconSource: root.uiIconSource("traffic-in")
                                        label: root.tr("settings.traffic.received", "Received")
                                        value: Pure.formatStorageBytes(Number(adapterRow.a["in-bytes"] || 0))
                                    }
                                    TrafficFigure {
                                        theme: root.uiTheme
                                        textColor: root.mutedTextColor
                                        iconSource: root.uiIconSource("traffic-out")
                                        label: root.tr("settings.traffic.sent", "Sent")
                                        value: Pure.formatStorageBytes(Number(adapterRow.a["out-bytes"] || 0))
                                    }
                                }
                                // Last observed local/external address for this
                                // adapter, from a user-requested probe. Absent
                                // until the user has probed at least once.
                                Label {
                                    Layout.fillWidth: true
                                    visible: group._addressLine(adapterRow.a) !== ""
                                    color: root.mutedTextColor
                                    font.pixelSize: root.uiTheme.baseFontSizePx - 1
                                    elide: Text.ElideRight
                                    text: group._addressLine(adapterRow.a)
                                }
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 1
                    visible: group.showPeriodTotal
                    color: root.uiTheme.colorBorder
                }
                RowLayout {
                    Layout.fillWidth: true
                    visible: group.showPeriodTotal
                    spacing: root.uiTheme.spacingMd
                    Label {
                        Layout.fillWidth: true
                        color: root.textColor
                        elide: Text.ElideRight
                        text: root.tr("settings.traffic.total-period", "Total for the period")
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.textColor
                        iconSource: root.uiIconSource("traffic-in")
                        label: root.tr("settings.traffic.received", "Received")
                        value: Pure.formatStorageBytes(group.sumAll(group.rows, "in-bytes"))
                    }
                    TrafficFigure {
                        theme: root.uiTheme
                        textColor: root.textColor
                        iconSource: root.uiIconSource("traffic-out")
                        label: root.tr("settings.traffic.sent", "Sent")
                        value: Pure.formatStorageBytes(group.sumAll(group.rows, "out-bytes"))
                    }
                }
            }
        }

        // Tunnel-overlap honesty note: while a VPN session is active, the
        // primary figures already exclude traffic that transited into the
        // tunnel — say so, so they are not mistaken for double-counted.
        Label {
            Layout.fillWidth: true
            visible: group.ctrl && group.ctrl.sessionActive
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.traffic.tunnel-overlap-note",
                "While a VPN session is active, the primary row excludes traffic that transited into the tunnel.")
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

    function _localPathFromUrl(urlValue) {
        return Pure.localPathFromFileUrl(urlValue)
    }

    // Persist the selected period as a device-local UI preference. It is a
    // non-arming key, so it never lights up the footer Apply/Cancel; write it
    // straight through (updatePrefs mirror + emitPrefs to persist).
    function _setPeriod(next) {
        if (group.period === next) return
        root.updatePrefs({ trafficStatsPeriod: next })
        root.emitPrefs()
    }

    // Compact "IP: ... · external: ... (observed at)" line for one adapter
    // row. Either half is omitted when absent so a local-only or never-probed
    // row never shows a stray separator.
    function _addressLine(row) {
        if (!row) return ""
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
