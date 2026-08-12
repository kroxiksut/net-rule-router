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

    // Local-only filters and sort key for the adapter list. Filters mirror
    // the section's own visibility model (the interfacesModel itself is
    // shared with the rest of the app and isn't mutated here).
    property bool showUnavailable: true
    property string adapterSortBy: "default"
    // Local substring filter over the adapter list (name / description / IP /
    // DNS / type). Empty string shows everything; matching is case-insensitive.
    property string adapterSearchFilter: ""

    // Fast-poll gate for TrafficStatsController: this section renders the
    // per-adapter "Received/Sent" line, so raise the controller's cadence
    // from 60 s to 3 s only while this section is the one actually on
    // screen, and nudge an immediate refresh on every transition into view.
    // The StackLayout Loader in Main.qml keeps this section resident after
    // the first visit (`keepLoaded`), so `root.section` must be read through
    // a live binding here, not inferred from creation order.
    readonly property bool panelVisible: root.section === "interfaces-routes"
    Binding {
        target: root.trafficStats
        property: "interfacesPanelVisible"
        value: section.panelVisible
        when: root.trafficStats !== null && root.trafficStats !== undefined
    }
    onPanelVisibleChanged: {
        if (!panelVisible) return
        if (root.trafficStats) root.trafficStats.refresh()
        // Users arrive here from the "additional route is down" banner, so the
        // list must show the state NOW, not whatever was last enumerated -- the
        // tunnel may already be back up. Re-read silently: the global Refresh
        // action writes a status line, and navigation is not a user report.
        root.interfacesRolesController.refreshInterfacesFromService()
        _refreshSecondaryState()
    }

    readonly property bool _failClosedReported:
        section._secondaryRouteState !== null
        && section._secondaryRouteState.failClosedActive === true

    /// Is the adapter bound as the additional route missing right now? Drives
    /// the on-screen explanation for every behaviour mode, not just the strict
    /// one the service reports as fail-closed.
    readonly property bool _secondaryAdapterAbsent:
        root.uiRevision >= 0
        && root.interfacesRolesController.rememberedAbsentBindings()
            .some(function(binding) { return String(binding.role || "") === "secondary" })

    // Runtime secondary-route posture surfaced
    // by `SnapshotInterfacesResponse.secondary`. `null` when the server
    // does not carry the field (older builds / pre-routing-resolution
    // boot path); the GUI treats `null` as "no banner". The flag is
    // refreshed on section enter + on every global Refresh trigger.
    property var _secondaryRouteState: null

    function _refreshSecondaryState() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInterfacesGet !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInterfacesGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (!ok) {
                section._secondaryRouteState = null
                return
            }
            var secondary = (payload && payload.secondary) || null
            if (secondary === null || secondary === undefined) {
                section._secondaryRouteState = null
                return
            }
            // Wire key is kebab-case (`fail-closed-active`); fall back
            // to snake_case for forward-compat with a service that
            // ever drops the rename_all attribute.
            section._secondaryRouteState = {
                failClosedActive: !!(secondary["fail-closed-active"]
                    || secondary.fail_closed_active)
            }
        })
    }

    Component.onCompleted: _refreshSecondaryState()
    Connections {
        target: root.refreshAction
        function onTriggered() { section._refreshSecondaryState() }
    }

    /// Traffic sample for one adapter over the period selected in Settings,
    /// or `null` while the sampler has nothing for it yet.
    function _trafficRowFor(displayName) {
        var ctrl = root.trafficStats
        if (!ctrl) return null
        var rows = root.prefs.trafficStatsPeriod === "session" ? ctrl.sessionRows : ctrl.todayRows
        for (var i = 0; i < rows.length; i += 1) {
            if (rows[i] && rows[i]["display-name"] === displayName) return rows[i]
        }
        return null
    }
    /// Which period the figures belong to — appended so a session total is
    /// never read as today's.
    function _trafficPeriodLabel() {
        return root.prefs.trafficStatsPeriod === "session"
            ? root.tr("settings.traffic.period-session", "Additional adapter session")
            : root.tr("settings.traffic.period-today", "Today")
    }

    function adapterPassesFilter(item) {
        if (!item) return false
        if (!showUnavailable && String(item.availability) === "unavailable") return false
        var q = adapterSearchFilter.toLowerCase().trim()
        if (q !== "") {
            var hay = (String(item.name || "") + " "
                + String(item.description || "") + " "
                + String(item.ip || "") + " "
                + String(item.dns || "") + " "
                + String(item.type || "")).toLowerCase()
            if (hay.indexOf(q) < 0) return false
        }
        return true
    }
    function isLoopbackAdapter(item) {
        if (!item) return false
        var n = String(item.name || "").toLowerCase()
        var t = String(item.type || "").toLowerCase()
        var d = String(item.description || "").toLowerCase()
        var c = String((item.derivedAssessment || {}).classification || "").toLowerCase()
        return n.indexOf("loopback") >= 0
            || t.indexOf("loopback") >= 0
            || d.indexOf("loopback") >= 0
            || c.indexOf("loopback") >= 0
    }
    // Raw OS-reported order — NRR's own DNS redirect (Mode B) uses NRPT, never
    // a per-adapter rewrite, so a loopback entry here is third-party software.
    // Sink it to the end so the line leads with a useful address.
    function _dnsDisplayText(raw) {
        var s = String(raw || "")
        if (s.indexOf(",") < 0) return s
        var parts = s.split(",").map(function(p) { return p.trim() })
        var rest = parts.filter(function(p) { return p !== "127.0.0.1" })
        var loopback = parts.filter(function(p) { return p === "127.0.0.1" })
        return rest.concat(loopback).join(", ")
    }
    function hasConfiguredDns(item) {
        if (!item) return false
        var raw = String(item.dns || "").trim()
        if (raw === "") return false
        var lc = raw.toLowerCase()
        // Backend uses the literal "—" / "none" / "(none)" / "—" placeholders
        // when an adapter has no DNS resolvers configured. Treat them as
        // "no DNS" so the default sort matches the user expectation.
        if (lc === "—" || lc === "-" || lc === "none" || lc === "(none)" || lc === "n/a")
            return false
        return true
    }
    function applyAdapterSort() {
        if (root.interfacesModel.count <= 1) return
        var snap = []
        for (var i = 0; i < root.interfacesModel.count; i += 1) {
            snap.push(JSON.parse(JSON.stringify(root.interfacesModel.get(i))))
        }
        snap.sort(function(a, b) {
            return section.classificationRank(b) - section.classificationRank(a)
        })
        for (var j = 0; j < snap.length; j += 1) {
            root.interfacesModel.set(j, snap[j])
        }
    }
    function classificationRank(item) {
        // Higher score = should appear earlier. Loopback always sinks to the
        // bottom regardless of the active sort key — it's a local-only
        // address space, never a routing target.
        if (!item) return -100000
        if (isLoopbackAdapter(item)) return -10000

        // Adapters with assigned roles always pin to the top in the order
        // primary → secondary, regardless of the active sort key. Once the
        // user has bound a role, that adapter is operationally important
        // and shouldn't get buried under heuristic scores. The +1_000_000
        // / +900_000 bumps comfortably exceed every other contribution
        // below so they win the sort. The two roles are kept adjacent so
        // the user sees them side-by-side.
        var role = String(item.selectedRole || "")
        if (role === "primary") return 1000000
        if (role === "secondary") return 900000

        var rec = (item.recommendation && item.recommendation.class) || ""
        var da = item.derivedAssessment || {}
        var vpn = String(da.vpnTunnelLikelihood || "")
        var virt = String(da.virtualInterfaceLikelihood || "")
        var avail = String(item.availability || "")
        var dns = hasConfiguredDns(item) ? 1 : 0

        if (adapterSortBy === "vpn-like") {
            if (vpn === "likely") return 100 + dns
            if (vpn === "possible") return 60 + dns
            if (virt === "likely") return 40 + dns
            if (virt === "possible") return 25 + dns
            return dns
        }
        if (adapterSortBy === "primary-candidate") {
            if (rec === "preferred-primary") return 100 + dns
            if (rec === "allowed-but-not-recommended") return 40 + dns
            if (rec === "preferred-secondary") return 30 + dns
            if (rec === "not-recommended") return dns
            return 10 + dns
        }
        // Default sort: adapters that match the backend's recommendation
        // AND have DNS configured land at the top, then other available
        // adapters, then unavailable, then loopback (handled above).
        var score = 0
        if (avail === "available") score += 50
        else if (avail === "requires-check") score += 20
        if (dns === 1) score += 30
        if (rec === "preferred-primary") score += 40
        else if (rec === "preferred-secondary") score += 25
        else if (rec === "allowed-but-not-recommended") score += 10
        return score
    }

    // Why traffic is being blocked, stated on the screen the user is sent to.
    // Two sources: the service's own fail-closed posture (strict mode), and the
    // plain fact that the bound additional adapter is absent -- the second
    // covers every other mode, where the window banner is the only explanation
    // and can be dismissed for good.
    Frame {
        Layout.fillWidth: true
        visible: section._failClosedReported || section._secondaryAdapterAbsent
        padding: root.uiTheme.spacingSm
        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
        ColumnLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingXxs
            Label {
                Layout.fillWidth: true
                text: section._failClosedReported
                    ? root.tr("interfaces.fail-closed.banner-title",
                        "Fail-Closed mode active")
                    : root.tr("interfaces.secondary-absent.banner-title",
                        "The additional route is not available")
                color: root.uiTheme.colorAccent
                font.bold: true
                wrapMode: Text.WordWrap
            }
            Label {
                Layout.fillWidth: true
                text: section._failClosedReported
                    ? root.tr("interfaces.fail-closed.banner-body",
                        "Secondary route is unavailable. Matched traffic is being blocked instead of leaking to the primary.")
                    : root.tr("interfaces.secondary-absent.banner-body",
                        "The adapter you bound as the additional route is not present right now. Traffic your rules send there is blocked rather than leaked to the main route. Bring the connection back up, or assign another adapter to the role below.")
                color: root.textColor
                wrapMode: Text.WordWrap
            }
        }
    }

    Label {
        text: root.sectionTitle("interfaces-routes")
        color: root.textColor
        font.bold: true
    }
    Label {
        Layout.fillWidth: true
        text: (root.context.interfaces || {}).roleExplanation || ""
        color: root.mutedTextColor
        wrapMode: Text.WordWrap
    }
    // First row: Mode selector + Refresh button. Wraps if both don't fit.
    Flow {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingMd
        Row {
            spacing: root.uiTheme.spacingSm
            Label {
                text: root.tr("label.mode", "Mode")
                color: root.textColor
                anchors.verticalCenter: parent.verticalCenter
            }
            ThemedComboBox {
                id: behaviorCombo
                theme: root.uiTheme
                width: 340
                model: root.behaviorModeModel
                textRole: "id"
                labelResolver: function(item) {
                    return item ? root.behaviorModeLabel(item.id) : ""
                }
                // Hover hint explaining the
                // selected mode (e.g. what "Strict secondary" does). Reuses
                // the existing settings.routing-behavior.mode.<slug>.description
                // keys (the catalog is flat: the JSON nests these under
                // `settings`, so the lookup key MUST carry that prefix).
                ToolTip.visible: hovered
                ToolTip.text: {
                    if (root.uiRevision < 0 || currentIndex < 0
                            || currentIndex >= root.behaviorModeModel.count) return ""
                    var id = String(root.behaviorModeModel.get(currentIndex).id || "")
                    return id === ""
                        ? ""
                        : root.tr("settings.routing-behavior.mode." + id + ".description", "")
                }
                Component.onCompleted: {
                    currentIndex = Pure.optionIndexById(
                        ((root.context.interfaces || {}).supportedBehaviorModes) || [],
                        (root.context.interfaces || {}).selectedBehaviorMode || "", 0)
                    if (currentIndex >= 0 && currentIndex < root.behaviorModeModel.count)
                        displayText = root.behaviorModeLabel(root.behaviorModeModel.get(currentIndex).id)
                }
                popup.width: root.comboPopupWidth(behaviorCombo, root.behaviorModeModel, "id",
                    function(item) { return root.behaviorModeLabel(item.id) })
                onActivated: {
                    var id = root.behaviorModeModel.get(currentIndex).id
                    root.updatePrefs({ routeBehaviorMode: id })
                    root.emitPrefs()
                    // Also persist to the SERVICE
                    // per-SID policy (the authoritative source for WFP). The
                    // updatePrefs/emitPrefs above only touches the deprecated
                    // UiPreferences mirror and never reaches enforcement.
                    if (typeof root.routePolicyController.applyRouteBehaviorMode === "function") {
                        root.routePolicyController.applyRouteBehaviorMode(id)
                    }
                    behaviorCombo.displayText = root.behaviorModeLabel(id)
                }
                Connections {
                    target: root
                    function onUiRevisionChanged() {
                        if (behaviorCombo.currentIndex >= 0 && behaviorCombo.currentIndex < root.behaviorModeModel.count)
                            behaviorCombo.displayText = root.behaviorModeLabel(root.behaviorModeModel.get(behaviorCombo.currentIndex).id)
                    }
                }
            }
        }
        // What the tray is allowed to do about the companion domains a routed
        // site pulls. It lives in Settings too, but this is the screen the user
        // opens first and the tray is where the offers arrive, so the state and
        // the switch belong in sight of each other.
        Row {
            spacing: root.uiTheme.spacingSm
            Label {
                text: root.tr("settings.routing.auto-rules.label",
                    "Missing companion domains")
                color: root.textColor
                anchors.verticalCenter: parent.verticalCenter
            }
            ThemedComboBox {
                id: autoRulesModeCombo
                theme: root.uiTheme
                width: 260
                anchors.verticalCenter: parent.verticalCenter
                model: ListModel {
                    ListElement { slug: "off"; label: "" }
                    ListElement { slug: "suggest"; label: "" }
                    ListElement { slug: "auto"; label: "" }
                }
                textRole: "label"
                function _slugLabel(slug) {
                    if (slug === "off")
                        return root.tr("settings.routing.auto-rules.mode-off", "Off")
                    if (slug === "auto")
                        return root.tr("settings.routing.auto-rules.mode-auto",
                            "Apply automatically")
                    return root.tr("settings.routing.auto-rules.mode-suggest",
                        "Suggest only (default)")
                }
                labelResolver: function(item) {
                    return item ? autoRulesModeCombo._slugLabel(String(item.slug)) : ""
                }
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: root.tr("settings.routing.auto-rules.note", "")
                function _indexOfSlug(slug) {
                    for (var i = 0; i < autoRulesModeCombo.model.count; i += 1)
                        if (String(autoRulesModeCombo.model.get(i).slug) === slug)
                            return i
                    // Unknown value → "Suggest only": never start applying by
                    // accident.
                    return 1
                }
                function _syncFromState() {
                    var idx = _indexOfSlug(String(
                        (root.routingState || {}).autoRulesMode || "suggest"))
                    currentIndex = idx
                    displayText = _slugLabel(String(
                        autoRulesModeCombo.model.get(idx).slug))
                }
                function _refreshLabels() {
                    var m = autoRulesModeCombo.model
                    for (var i = 0; i < m.count; i += 1)
                        m.setProperty(i, "label", _slugLabel(String(m.get(i).slug)))
                    _syncFromState()
                }
                Component.onCompleted: _refreshLabels()
                onActivated: {
                    var slug = String(model.get(currentIndex).slug)
                    // "Apply automatically" means unattended writes to the
                    // user's rules, so it asks first — same gate as Settings.
                    // The selection snaps back until the answer arrives.
                    if (slug === "auto"
                            && String((root.routingState || {}).autoRulesMode) !== "auto") {
                        _syncFromState()
                        autoRulesModeConfirmDialog.open()
                        return
                    }
                    displayText = _slugLabel(slug)
                    root.updateRoutingState({ autoRulesMode: slug })
                    if (typeof root.routePolicyController.applyAutoRulesMode === "function")
                        root.routePolicyController.applyAutoRulesMode(slug)
                }
                Connections {
                    target: root
                    // `routingState` is replaced wholesale on every patch, so
                    // the revision counter is what says "read it again".
                    function onUiRevisionChanged() { autoRulesModeCombo._refreshLabels() }
                }
            }
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.refreshAction.text
            onClicked: root.refreshAction.trigger()
        }
        // Separate from Refresh on purpose: this one leaves the machine (one
        // small packet per adapter) to find out how each link looks from
        // outside, so it only ever runs when the user asks for it.
        ThemedButton {
            theme: root.uiTheme
            enabled: !root.interfacesRolesController.externalIpProbeBusy
            text: root.interfacesRolesController.externalIpProbeBusy
                ? root.tr("interfaces.external-ip.probe-busy", "Checking…")
                : root.tr("interfaces.external-ip.probe-button", "Check external address")
            ToolTip.visible: hovered
            ToolTip.delay: 400
            ToolTip.text: root.tr("interfaces.external-ip.probe-tooltip",
                "Asks a public address-reflection server what each adapter's address looks like from the internet. Sends one small packet per adapter; nothing else leaves the machine.")
            Accessible.name: text
            onClicked: root.interfacesRolesController.probeExternalAddresses()
        }
        // Entry point to the application-group route
        // assignment (VMs / emulators + torrents / P2P). Opens the dialog wired
        // in Main.qml (`openAppGroupRouting()`); available whether or not the
        // service is running (discovery is launcher-local).
        ThemedButton {
            theme: root.uiTheme
            visible: typeof root.openAppGroupRouting === "function"
            text: root.tr("app-groups.open-button", "Set up routes")
            onClicked: root.openAppGroupRouting()
        }
    }
    // Second row (own line): the Bluetooth/unavailable/remembered "Show"
    // toggles + sort. Always starts on a new line so the toggles are not
    // shifted by the Refresh button on medium-narrow widths.
    Flow {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingMd
        CheckBox {
            text: root.tr("interfaces.toggle.show-bluetooth-adapters", "Show Bluetooth adapters")
            checked: !!root.prefs.showBluetoothAdapters
            onToggled: {
                root.updatePrefs({ showBluetoothAdapters: checked })
                root.interfacesRolesController.rebuildInterfacesModel()
                root.emitPrefs()
            }
        }
        CheckBox {
            text: root.tr("interfaces.toggle.show-unavailable-adapters",
                "Show unavailable adapters")
            checked: section.showUnavailable
            onToggled: section.showUnavailable = checked
        }
        // Show "remembered but currently absent" ghost rows (a device-local
        // display preference, default ON). Toggling only bumps uiRevision via
        // updatePrefs, which re-evaluates the ghost Repeater model below; no
        // interfaces-model rebuild is needed since the live list is untouched.
        CheckBox {
            text: root.tr("interfaces.remembered.toggle",
                "Show remembered adapters that are currently absent")
            checked: root.uiRevision >= 0 ? !!root.prefs.showRememberedAdapters : true
            onToggled: {
                root.updatePrefs({ showRememberedAdapters: checked })
                root.emitPrefs()
            }
        }
        Row {
            spacing: root.uiTheme.spacingSm
            Label {
                text: root.tr("interfaces.sort.label", "Sort")
                color: root.textColor
                anchors.verticalCenter: parent.verticalCenter
            }
            ThemedComboBox {
                id: adapterSortCombo
                theme: root.uiTheme
                width: 240
                model: [ "default", "vpn-like", "primary-candidate" ]
                function sortKeyLabel(id) { return root.tr("interfaces.sort." + id, id) }
                labelResolver: function(item) { return adapterSortCombo.sortKeyLabel(item) }
                currentIndex: 0
                Component.onCompleted: displayText = sortKeyLabel(model[currentIndex])
                popup.width: root.comboPopupWidth(adapterSortCombo, model, "",
                    function(item) { return adapterSortCombo.sortKeyLabel(item) })
                onActivated: {
                    section.adapterSortBy = model[currentIndex]
                    adapterSortCombo.displayText = sortKeyLabel(model[currentIndex])
                }
                Connections {
                    target: root
                    function onUiRevisionChanged() {
                        adapterSortCombo.displayText = adapterSortCombo.sortKeyLabel(adapterSortCombo.model[adapterSortCombo.currentIndex])
                    }
                }
            }
        }
    }
    // Live search/filter across the adapter list. Drives the per-delegate
    // visibility binding through `adapterPassesFilter`, so no model rebuild.
    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Label {
            text: root.tr("interfaces.search.label", "Find")
            color: root.textColor
            Layout.alignment: Qt.AlignVCenter
        }
        ThemedTextField {
            id: adapterSearchField
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.maximumWidth: 360
            placeholderText: root.uiRevision >= 0
                ? root.tr("interfaces.search.placeholder",
                    "Search adapters by name, IP or DNS")
                : ""
            text: section.adapterSearchFilter
            onTextChanged: section.adapterSearchFilter = text
            Accessible.role: Accessible.EditableText
            Accessible.name: root.tr("interfaces.search.label", "Find")
        }
        ThemedButton {
            theme: root.uiTheme
            visible: section.adapterSearchFilter !== ""
            text: root.tr("interfaces.search.clear", "Clear")
            onClicked: { section.adapterSearchFilter = ""; adapterSearchField.text = "" }
        }
    }
    ScrollView {
        id: adaptersScroll
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        ColumnLayout {
            width: adaptersScroll.availableWidth
            spacing: root.uiTheme.spacingSm
            // "remembered but currently absent" ghost rows, rendered
            // ABOVE the live adapter list from root.interfacesRolesController.rememberedAbsentBindings():
            // each confirmed primary/secondary binding whose adapter is not
            // among the live adapters (e.g. a VPN TAP removed when the tunnel is
            // off). Muted and warning-bordered so they read as
            // remembered-but-absent, and carrying the two things that actually
            // recover the route: re-push the binding, or take another adapter
            // from the list below. Gated behind the showRememberedAdapters
            // display toggle (default on). The model re-evaluates on every
            // uiRevision bump (adapter refresh + prefs change), so a VPN coming
            // up drops the ghost as the binding heals to its live sibling.
            Repeater {
                model: (root.uiRevision >= 0 && !!root.prefs.showRememberedAdapters)
                    ? root.interfacesRolesController.rememberedAbsentBindings() : []
                delegate: Frame {
                    Layout.fillWidth: true
                    padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                    opacity: 0.85
                    background: Rectangle {
                        radius: root.uiTheme.radiusSm
                        color: root.uiTheme.colorPanel
                        border.width: root.uiTheme.borderWidth
                        border.color: root.uiTheme.colorWarning
                    }
                    RowLayout {
                        anchors.fill: parent
                        spacing: root.uiTheme.spacingMd
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                Layout.fillWidth: true
                                text: {
                                    var nm = String(modelData.name || "")
                                    return nm !== "" ? nm : String(modelData.id || "")
                                }
                                color: root.mutedTextColor
                                font.italic: true
                                font.bold: true
                                elide: Text.ElideRight
                            }
                            Label {
                                Layout.fillWidth: true
                                text: root.uiRevision >= 0
                                    ? root.tr("interfaces.remembered.badge",
                                        "remembered · currently absent")
                                    : ""
                                color: root.uiTheme.colorWarning
                                wrapMode: Text.WordWrap
                                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            }
                            Label {
                                Layout.fillWidth: true
                                text: root.uiRevision >= 0
                                    ? root.tr("interfaces.remembered.recovery-hint",
                                        "If the connection is back up, send the binding to the service again. Otherwise assign another adapter to this role in the list below.")
                                    : ""
                                color: root.mutedTextColor
                                wrapMode: Text.WordWrap
                                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            }
                        }
                        ColumnLayout {
                            Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                            spacing: root.uiTheme.spacingXxs
                            Label {
                                Layout.alignment: Qt.AlignRight
                                text: root.uiRevision >= 0
                                    ? root.routeLabel(String(modelData.role || "")) : ""
                                visible: text !== ""
                                color: root.accentColor
                                font.bold: true
                            }
                            ThemedButton {
                                Layout.alignment: Qt.AlignRight
                                theme: root.uiTheme
                                text: root.tr("status.policy-inactive-send", "Send adapter to the service")
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                Accessible.description: root.tr("interfaces.remembered.recovery-hint",
                                    "If the connection is back up, send the binding to the service again. Otherwise assign another adapter to this role in the list below.")
                                onClicked: root.resendRouteBindingToService()
                            }
                        }
                    }
                }
            }
            Repeater {
                model: root.interfacesModel
                // Re-sort the shared ListModel in place whenever the sort
                // key flips. The default value is a no-op (rebuild restores
                // the snapshot order); for VPN-like / primary-candidate the
                // model is reshuffled so the Repeater renders the new order
                // directly. Visibility filtering is done per-delegate.
                Connections {
                    target: section
                    function onAdapterSortByChanged() { section.applyAdapterSort() }
                }
                // Re-sort whenever prefs/model change (assignRole and
                // unassignRole both rebuild interfacesModel and bump
                // uiRevision via updatePrefs). Without this the newly
                // assigned secondary stayed at its previous rank position
                // until the user touched the sort combo manually.
                Connections {
                    target: root
                    function onUiRevisionChanged() {
                        Qt.callLater(section.applyAdapterSort)
                    }
                }
                Component.onCompleted: section.applyAdapterSort()
                delegate: ColumnLayout {
                    Layout.fillWidth: true
                    visible: section.adapterPassesFilter(model)
                    spacing: 0
                    // Standalone separator above every card except the first
                    // visible one. A 1 px Rectangle inside the column gives a
                    // crisp horizontal rule between adjacent adapter cards
                    // without depending on the card's own border styling.
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.topMargin: root.uiTheme.spacingSm
                        Layout.bottomMargin: root.uiTheme.spacingSm
                        height: 1
                        color: root.uiTheme.stateDefaultBorder
                        opacity: 0.55
                        visible: index > 0
                    }
                Frame {
                    id: cardFrame
                    Layout.fillWidth: true
                    padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                    background: Rectangle {
                        radius: root.uiTheme.radiusSm
                        color: root.uiTheme.colorPanel
                        border.width: root.uiTheme.borderWidth
                        border.color: root.uiTheme.stateDefaultBorder
                    }

                    readonly property bool isAvailable: model.availability === "available"

                    // Two-column row inside each adapter card. Left column
                    // (fillWidth) carries adapter name + summary text. Right
                    // column (preferredWidth: 240) carries the availability
                    // badge, role marker and the two action buttons.
                    // Without a fixed-width right column the long DNS /
                    // gateway summaries fill the card and the right edge is
                    // empty whitespace.
                    GridLayout {
                        anchors.fill: parent
                        columns: 2
                        columnSpacing: root.uiTheme.spacingMd
                        rowSpacing: root.uiTheme.spacingXxs

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Label {
                                Layout.fillWidth: true
                                text: model.name
                                color: root.textColor
                                font.bold: true
                                elide: Text.ElideRight
                            }
                            // Driver / hardware description from the adapter
                            // snapshot (e.g. "Intel(R) Wi-Fi 6 AX201"). Only
                            // shown when present and distinct from `name`.
                            Label {
                                Layout.fillWidth: true
                                visible: text !== ""
                                text: {
                                    var d = String(model.description || "")
                                    return d !== "" && d !== String(model.name || "") ? d : ""
                                }
                                color: root.mutedTextColor
                                wrapMode: Text.WordWrap
                                font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            }
                            // Received/Sent for this adapter over the period
                            // selected in Settings (this session vs today),
                            // mirroring the Traffic panel's own toggle. A period
                            // suffix is appended so the figure is never mistaken
                            // for the other period's total. Empty until the
                            // sampler has data for this adapter.
                            RowLayout {
                                id: adapterTrafficRow
                                Layout.fillWidth: true
                                spacing: root.uiTheme.spacingSm
                                readonly property var sample: root.uiRevision >= 0
                                    ? section._trafficRowFor(model.name) : null
                                visible: !!adapterTrafficRow.sample
                                TrafficFigure {
                                    theme: root.uiTheme
                                    textColor: root.mutedTextColor
                                    iconSource: root.uiIconSource("traffic-in")
                                    label: root.tr("settings.traffic.received", "Received")
                                    value: adapterTrafficRow.sample
                                        ? Pure.formatStorageBytes(Number(adapterTrafficRow.sample["in-bytes"] || 0))
                                        : ""
                                }
                                TrafficFigure {
                                    theme: root.uiTheme
                                    textColor: root.mutedTextColor
                                    iconSource: root.uiIconSource("traffic-out")
                                    label: root.tr("settings.traffic.sent", "Sent")
                                    value: adapterTrafficRow.sample
                                        ? Pure.formatStorageBytes(Number(adapterTrafficRow.sample["out-bytes"] || 0))
                                        : ""
                                }
                                Label {
                                    Layout.fillWidth: true
                                    text: root.uiRevision >= 0 ? "·  " + section._trafficPeriodLabel() : ""
                                    color: root.mutedTextColor
                                    elide: Text.ElideRight
                                    font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                                }
                            }
                        }

                        // Availability badge (right column, top). Green dot
                        // for available, amber for requires-check, red for
                        // unavailable. Localized label sits next to the dot.
                        RowLayout {
                            Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                            Layout.preferredWidth: 240
                            spacing: root.uiTheme.spacingSm
                            Item { Layout.fillWidth: true }
                            Rectangle {
                                Layout.preferredWidth: 10
                                Layout.preferredHeight: 10
                                radius: 5
                                color: model.availability === "available"
                                    ? root.uiTheme.colorSuccess
                                    : (model.availability === "unavailable"
                                       ? "#cc4040"
                                       : root.uiTheme.colorWarning)
                            }
                            Label {
                                text: (root.uiRevision, root.availabilityLabel(model.availability))
                                color: root.textColor
                            }
                            Label {
                                text: model.selectedRole === "primary" ? root.routeLabel("primary")
                                    : model.selectedRole === "secondary" ? root.routeLabel("secondary") : ""
                                visible: text !== ""
                                color: root.accentColor
                                font.bold: true
                            }
                        }

                        Label {
                            Layout.fillWidth: true
                            text: root.tr("interfaces.row.summary", "Type: %1 | IP: %2 | Gateway: %3")
                                .arg(model.type).arg(model.ip).arg(model.gateway)
                            color: root.textColor
                            wrapMode: Text.WordWrap
                        }

                        // Spacer in right column for visual symmetry.
                        Item { Layout.preferredWidth: 240; Layout.preferredHeight: 1 }

                        Label {
                            Layout.fillWidth: true
                            text: root.tr("interfaces.row.summary-2",
                                "DNS: %1 | Default route: %2 | State: %3")
                                .arg(section._dnsDisplayText(model.dns))
                                .arg(root.boolLabel(model.hasDefaultRoute))
                                .arg(root.routeStateLabel(model.routeState))
                            color: root.mutedTextColor
                            wrapMode: Text.WordWrap
                        }

                        // Observed facts + classifier signals row. Shows the
                        // connectivity probe outcome, the heuristic
                        // classification (Wi-Fi / Ethernet / VPN / Virtual /
                        // Service) with a confidence percent, and the live
                        // recommendation summary string from the snapshot.
                        // All fields are best-effort: when missing, the line
                        // collapses to nothing (visible:false).
                        Label {
                            Layout.fillWidth: true
                            Layout.columnSpan: 1
                            visible: text !== ""
                            wrapMode: Text.WordWrap
                            color: root.mutedTextColor
                            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            text: {
                                if (root.uiRevision < 0) return ""
                                var of = model.observedFacts || {}
                                var da = model.derivedAssessment || {}
                                var parts = []
                                if (of.connectivityState && of.connectivityState !== "")
                                    parts.push(root.tr("interfaces.connectivity." + of.connectivityState,
                                                       String(of.connectivityState)))
                                if (of.externalIp && of.externalIp !== "")
                                    parts.push(root.tr("interfaces.external-ip.prefix", "ext")
                                               + " " + String(of.externalIp))
                                else if (of.externalIpStatus && of.externalIpStatus !== "")
                                    parts.push(root.tr("interfaces.external-ip." + of.externalIpStatus,
                                                       String(of.externalIpStatus)))
                                if (da.classification && da.classification !== "") {
                                    var slug = String(da.classification)
                                        .toLowerCase().replace(/[ _]+/g, "-")
                                    var c = root.tr("interfaces.classification." + slug, String(da.classification))
                                    if (da.confidencePercent !== undefined && da.confidencePercent !== null)
                                        c += " " + Math.round(Number(da.confidencePercent)) + "%"
                                    parts.push(c)
                                }
                                return parts.join("  •  ")
                            }
                        }
                        Item { Layout.preferredWidth: 240; Layout.preferredHeight: 1 }

                        // Muted "last known external IP" hint, shown only while
                        // the GUI cannot reach the service (so it never has a
                        // fresh answer) AND a past live snapshot cached one for
                        // this adapter. Deliberately never probes on its own —
                        // it only ever repaints a value the service already
                        // reported. Distinct opacity/italic from the line above
                        // so it reads as "not live" at a glance.
                        Label {
                            Layout.fillWidth: true
                            visible: text !== ""
                            wrapMode: Text.WordWrap
                            color: root.mutedTextColor
                            opacity: 0.7
                            font.italic: true
                            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            text: {
                                if (root.uiRevision < 0) return ""
                                if (root._routingBackendConnected()) return ""
                                var of = model.observedFacts || {}
                                if (of.externalIp && of.externalIp !== "") return ""
                                var key = Pure.externalIpCacheKey(model.persistentId, model.name)
                                var cached = (root.externalIpCache || {})[key]
                                if (!cached || !cached.ip) return ""
                                return root.tr("interfaces.external-ip.last-known",
                                    "Last known external IP: %1 (as of %2)")
                                    .arg(cached.ip)
                                    .arg(Pure.formatLastKnownTimestamp(cached.observedAtMs, Date.now()))
                            }
                        }
                        Item { Layout.preferredWidth: 240; Layout.preferredHeight: 1 }

                        Label {
                            Layout.fillWidth: true
                            visible: text !== ""
                            wrapMode: Text.WordWrap
                            color: root.mutedTextColor
                            font.pixelSize: Math.max(11, root.uiTheme.baseFontSizePx - 1)
                            text: {
                                if (root.uiRevision < 0) return ""
                                var rec = model.recommendation || {}
                                var cls = String(rec.class || "")
                                var pieces = []
                                if (cls !== "") {
                                    pieces.push(root.tr("interfaces.recommendation." + cls, cls))
                                }
                                // The free-text `summary` from the backend is
                                // English-only diagnostic prose. We surface a
                                // localized recommendation class instead and
                                // keep the raw summary as a tooltip-grade
                                // detail behind a separate locale key when
                                // the user wants the full string.
                                return pieces.join(" • ")
                            }
                        }
                        Item { Layout.preferredWidth: 240; Layout.preferredHeight: 1 }

                        // Action buttons in the right column, aligned with
                        // the badge above. Each role button has three states:
                        //   - this adapter holds the role  → "Снять"
                        //                                    (unassign, enabled)
                        //   - another adapter holds it     → disabled
                        //                                    (force the user
                        //                                    to unassign there
                        //                                    before reassigning)
                        //   - role free                    → "Назначить как…"
                        //                                    (enabled when the
                        //                                    adapter is up)
                        RowLayout {
                            Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                            Layout.preferredWidth: 240
                            spacing: root.uiTheme.spacingXs
                            Item { Layout.fillWidth: true }
                            ThemedButton {
                                theme: root.uiTheme
                                readonly property bool _holdsPrimary: model.selectedRole === "primary"
                                readonly property int _primaryHolderIndex: root.uiRevision >= 0
                                    ? root.interfacesRolesController.adapterIndexHoldingRole("primary") : -1
                                readonly property bool _someoneElseHoldsPrimary:
                                    _primaryHolderIndex >= 0 && !_holdsPrimary
                                // Assignment is allowed
                                // even for an unavailable adapter (e.g. a
                                // disconnected ethernet port). The role
                                // binding is stored and takes effect when
                                // the adapter comes back up. ToolTip below
                                // warns the user that the adapter is offline.
                                enabled: _holdsPrimary ? true : !_someoneElseHoldsPrimary
                                text: root.uiRevision >= 0
                                    ? (_holdsPrimary
                                        ? root.tr("interfaces.action.unassign-primary",
                                            "Unassign primary")
                                        : root.routeLabel("primary"))
                                    : ""
                                ToolTip.visible: hovered && !cardFrame.isAvailable && !_holdsPrimary && enabled
                                ToolTip.text: root.tr(
                                    "interfaces.action.assign-unavailable-tooltip",
                                    "Adapter is currently unavailable — the role will activate automatically when it comes back up.")
                                onClicked: _holdsPrimary
                                    ? root.interfacesRolesController.unassignRole(index, "primary")
                                    : root.interfacesRolesController.assignRole(index, "primary")
                            }
                            ThemedButton {
                                theme: root.uiTheme
                                readonly property bool _holdsSecondary: model.selectedRole === "secondary"
                                readonly property int _secondaryHolderIndex: root.uiRevision >= 0
                                    ? root.interfacesRolesController.adapterIndexHoldingRole("secondary") : -1
                                readonly property bool _someoneElseHoldsSecondary:
                                    _secondaryHolderIndex >= 0 && !_holdsSecondary
                                enabled: _holdsSecondary ? true : !_someoneElseHoldsSecondary
                                text: root.uiRevision >= 0
                                    ? (_holdsSecondary
                                        ? root.tr("interfaces.action.unassign-secondary",
                                            "Unassign secondary")
                                        : root.routeLabel("secondary"))
                                    : ""
                                ToolTip.visible: hovered && !cardFrame.isAvailable && !_holdsSecondary && enabled
                                ToolTip.text: root.tr(
                                    "interfaces.action.assign-unavailable-tooltip",
                                    "Adapter is currently unavailable — the role will activate automatically when it comes back up.")
                                onClicked: _holdsSecondary
                                    ? root.interfacesRolesController.unassignRole(index, "secondary")
                                    : root.interfacesRolesController.assignRole(index, "secondary")
                            }
                        }
                    }
                }
                }
            }
        }
    }

    // Same gate the Settings panel uses: unattended writes to the user's rules
    // are never one click away.
    AutoRulesModeConfirmDialog {
        id: autoRulesModeConfirmDialog
        ownerRoot: root
        onConfirmed: {
            root.updateRoutingState({ autoRulesMode: "auto" })
            if (typeof root.routePolicyController.applyAutoRulesMode === "function")
                root.routePolicyController.applyAutoRulesMode("auto")
        }
        onCancelled: autoRulesModeCombo._syncFromState()
    }
}
