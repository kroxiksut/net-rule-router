import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

// App/device group routing.
//
// Shows the application groups NetRuleRouter detected on this machine — virtual
// machines / emulators and torrent / P2P programs — and lets the user pick which
// route (main / additional) each assignable program should follow. It mirrors the
// approved mockup: two tabs, grouped rows, a segmented per-row route selector, and
// a read-only "kernel virtual networks" section whose traffic the kernel owns
// (WSL / Hyper-V / Docker) and therefore cannot be routed per-process.
//
// Data flow mirrors VpnOnboardingDialog: on open() the dialog drives the
// launcher-local `local.app-groups.discover` RPC through the owner
// (`ownerRoot.rpc.rpcAppGroupsDiscover()` + `ownerRoot.rpc.registerRpcCallback`) and
// renders the returned list. It is otherwise "dumb": it emits
// `appGroupRoutesConfirmed(assignments)` with every ASSIGNABLE app and its chosen
// route (the caller reconciles), or `skipped()` on cancel / window close. All
// shared state arrives through `ownerRoot` (the ApplicationWindow) — never via
// implicit scope. Themed* wrappers only (TabBar/TabButton excepted for the tabs).
Window {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null

    /// Scan state and results. `apps` is a plain JS array of
    /// `{ kind, displayName, exePath, running, source }` objects from the RPC.
    property bool scanning: false
    property bool scanFailed: false
    property bool scanRan: false
    property var apps: []

    /// Route selection map: `rowKey -> "primary" | "secondary"`. Absent keys
    /// default to "primary" via `_routeOf`. Reset by reassignment (never in-place
    /// mutation) so bindings that read it (the segmented selector highlight, the
    /// confirmed assignments) re-evaluate — same idiom as VpnOnboardingDialog.
    property var routeByKey: ({})

    /// The kinds shown on each tab, in mockup order. The last virtualization
    /// entry (`kernel-virtual-net`) is display-only (locked route).
    readonly property var _virtualizationKinds: [
        "hypervisor", "android-emulator", "console-emulator", "kernel-virtual-net"
    ]
    readonly property var _peerToPeerKinds: [
        "bittorrent", "p2p-file-sharing", "crypto-node"
    ]

    /// Fired when the user applies the route assignments. `assignments` is a JS
    /// array of `{ displayName, matchValue, route, kind }` for every ASSIGNABLE
    /// app (kernel-virtual-net excluded). `matchValue` is the exe basename (path
    /// stripped) or the display name when no path is known. `route` is
    /// "primary" or "secondary". The caller reconciles the full set.
    signal appGroupRoutesConfirmed(var assignments)
    /// Fired when the user cancels or closes the window without applying.
    signal skipped()

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    // API-compatible with the other modal child windows in Main.qml.
    function open() {
        routeByKey = ({})
        apps = []
        scanFailed = false
        scanRan = false
        visible = true
        // Kick off a scan immediately so the list is populated by the time the
        // user has read the intro; they can re-scan with the footer button.
        scan()
    }

    /// Stable per-app selection key: the exe path when present, else the
    /// kind+display-name pair (so a path-less app is still keyed distinctly).
    function _rowKeyOf(app) {
        var a = app || {}
        var p = String(a.exePath || "")
        return p !== ""
            ? p
            : (String(a.kind || "") + ":" + String(a.displayName || ""))
    }
    function _routeOf(key) {
        var r = root.routeByKey[key]
        return r === "secondary" ? "secondary" : "primary"
    }
    /// Assign a route to a row. Reassigns `routeByKey` with a fresh object so
    /// bindings that read it re-evaluate — in-place mutation would not notify.
    function _setRoute(key, route) {
        var next = {}
        for (var k in root.routeByKey) next[k] = root.routeByKey[k]
        next[key] = (route === "secondary" ? "secondary" : "primary")
        root.routeByKey = next
    }

    /// All discovered apps of a given kind, in discovery order.
    function _appsOfKind(kind) {
        var out = []
        for (var i = 0; i < root.apps.length; i += 1) {
            var a = root.apps[i] || {}
            if (String(a.kind || "") === kind) out.push(a)
        }
        return out
    }
    /// Count of discovered apps across a set of kinds (for the tab labels).
    function _countOfKinds(kinds) {
        var n = 0
        for (var i = 0; i < root.apps.length; i += 1) {
            var a = root.apps[i] || {}
            if (kinds.indexOf(String(a.kind || "")) >= 0) n += 1
        }
        return n
    }

    /// Executable basename (directory stripped). Empty when the path is empty.
    function _basename(path) {
        var s = String(path || "")
        if (s === "") return ""
        var i = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\"))
        return i >= 0 ? s.substring(i + 1) : s
    }

    /// State badge text for a row, or "" when none applies.
    function _badgeTextFor(running, source) {
        if (running === true)
            return root.tr("app-groups.badge-running", "running")
        if (source === "installed-program")
            return root.tr("app-groups.badge-installed", "installed")
        if (source === "system-feature")
            return root.tr("app-groups.badge-feature", "system component")
        return ""
    }

    /// Drive the launcher-local `local.app-groups.discover` RPC and populate the
    /// list. Mirrors VpnOnboardingDialog.scan() exactly.
    function scan() {
        if (scanning) return
        if (!ownerRoot
                || !ownerRoot.rpc
                || typeof ownerRoot.rpc.rpcAppGroupsDiscover !== "function"
                || typeof ownerRoot.rpc.registerRpcCallback !== "function") {
            scanFailed = true
            scanRan = true
            return
        }
        scanning = true
        scanFailed = false
        routeByKey = ({})
        var corr = ownerRoot.rpc.rpcAppGroupsDiscover()
        if (!corr || corr === "") {
            scanning = false
            scanFailed = true
            scanRan = true
            return
        }
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            root.scanning = false
            root.scanRan = true
            if (!ok || !payload) {
                root.scanFailed = true
                root.apps = []
                return
            }
            var list = payload.apps || payload["apps"] || []
            var normalized = []
            for (var i = 0; i < list.length; i += 1) {
                var a = list[i] || {}
                var exe = a.exePath || a["exePath"] || a["exe-path"] || null
                normalized.push({
                    kind: String(a.kind || a["kind"] || ""),
                    displayName: String(a.displayName || a["displayName"]
                        || a["display-name"] || ""),
                    exePath: (exe === null || exe === undefined) ? "" : String(exe),
                    running: (a.running === true),
                    source: String(a.source || a["source"] || "")
                })
            }
            root.apps = normalized
            root.scanFailed = false
        })
    }

    width: 820
    height: 640
    minimumWidth: 560
    minimumHeight: 420
    visible: false
    modality: Qt.ApplicationModal
    flags: Qt.Dialog
    color: ownerRoot ? ownerRoot.panelColor : "#202020"
    title: tr("app-groups.title", "Application and device routes")
    transientParent: ownerRoot ? ownerRoot : null

    onVisibleChanged: {
        if (visible && ownerRoot) {
            if (typeof ownerRoot.centerChildWindow === "function") {
                ownerRoot.centerChildWindow(root)
            }
            if (typeof ownerRoot.applyTitleBarTo === "function") {
                ownerRoot.applyTitleBarTo(root)
            }
        }
    }

    // Reusable group section: header + hint, an optional kernel warning callout,
    // and one row per member app. Used as the delegate of both tab Repeaters; the
    // model context supplies `modelData` (the kind slug) and `index`.
    Component {
        id: groupSectionComponent
        ColumnLayout {
            id: groupCol
            property string sectionKind: String(modelData)
            property bool locked: sectionKind === "kernel-virtual-net"
            property var members: root._appsOfKind(sectionKind)
            Layout.fillWidth: true
            visible: members.length > 0
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                Label {
                    font.bold: true
                    font.pixelSize: (root.ownerRoot
                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) + 1
                    color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                    text: root.tr("app-groups.group." + groupCol.sectionKind,
                        groupCol.sectionKind)
                }
                Label {
                    font.pixelSize: (root.ownerRoot
                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 1
                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                    text: "· " + (groupCol.locked
                        ? root.tr("app-groups.group-display-only-hint",
                            "for information only")
                        : root.tr("app-groups.group-assignable-hint",
                            "route can be assigned"))
                }
                Item { Layout.fillWidth: true }
            }

            // Kernel-NAT warning callout — only for the display-only section.
            Rectangle {
                Layout.fillWidth: true
                visible: groupCol.locked
                radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 4
                color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "#2a2a2a"
                border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 1
                border.color: root.ownerRoot ? root.ownerRoot.uiTheme.colorAccent : "#3d6fb4"
                Layout.preferredHeight: kernelNote.implicitHeight
                    + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm * 2 : 16)
                Label {
                    id: kernelNote
                    anchors.fill: parent
                    anchors.margins: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                    wrapMode: Text.WordWrap
                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                    text: root.tr("app-groups.kernel-nat-note",
                        "WSL, Hyper-V and Docker traffic is handled by the kernel and "
                        + "does not belong to any process, so it cannot be assigned a "
                        + "route — it always uses the main route.")
                }
            }

            Repeater {
                model: groupCol.members
                delegate: CardSurface {
                    id: appCard
                    // CardSurface declares required properties, which
                    // suppresses the context `modelData`; re-request it.
                    required property var modelData

                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                    Layout.fillWidth: true
                    Layout.preferredHeight: appRow.implicitHeight
                        + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm * 2 : 16)
                    property string rowKey: root._rowKeyOf(modelData)
                    property string badgeText: root._badgeTextFor(
                        modelData.running === true, String(modelData.source || ""))

                    RowLayout {
                        id: appRow
                        anchors.fill: parent
                        anchors.margins: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                                Label {
                                    wrapMode: Text.WordWrap
                                    font.bold: true
                                    color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                                    text: String(modelData.displayName || "")
                                }
                                // State badge (running / installed / system component).
                                Rectangle {
                                    visible: appCard.badgeText !== ""
                                    radius: 3
                                    color: root.ownerRoot ? root.ownerRoot.uiTheme.colorAccent : "#3d6fb4"
                                    Layout.preferredWidth: badgeLabel.implicitWidth
                                        + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8)
                                    Layout.preferredHeight: badgeLabel.implicitHeight
                                        + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4)
                                    Label {
                                        id: badgeLabel
                                        anchors.centerIn: parent
                                        font.pixelSize: (root.ownerRoot
                                            ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 2
                                        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorOnAccent : "white"
                                        text: appCard.badgeText
                                    }
                                }
                                Item { Layout.fillWidth: true }
                            }
                            // Exe path in a small monospace muted label, when known.
                            Label {
                                Layout.fillWidth: true
                                visible: String(modelData.exePath || "") !== ""
                                wrapMode: Text.WrapAnywhere
                                font.family: "Consolas"
                                font.pixelSize: (root.ownerRoot
                                    ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 1
                                color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                                text: String(modelData.exePath || "")
                            }
                        }

                        // Right side: segmented route selector for assignable
                        // kinds, or a locked "Main" label for kernel-virtual-net.
                        RowLayout {
                            visible: !groupCol.locked
                            spacing: 0
                            ThemedButton {
                                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                                highlighted: root._routeOf(appCard.rowKey) === "primary"
                                text: root.tr("route.primary", "Main")
                                onClicked: root._setRoute(appCard.rowKey, "primary")
                                Accessible.name: text
                            }
                            ThemedButton {
                                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                                highlighted: root._routeOf(appCard.rowKey) === "secondary"
                                text: root.tr("route.secondary", "Additional")
                                onClicked: root._setRoute(appCard.rowKey, "secondary")
                                Accessible.name: text
                            }
                        }
                        Label {
                            visible: groupCol.locked
                            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                            text: "🔒 " + root.tr("app-groups.route-locked", "Main")
                        }
                    }
                }
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.ownerRoot ? root.ownerRoot.uiTheme.spacingLg : 18
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            font.bold: true
            font.pixelSize: 15
            color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            text: root.tr("app-groups.title", "Application and device routes")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("app-groups.entry-note",
                "Assign a route to the virtual machines, emulators and "
                + "peer-to-peer apps found on this computer.")
        }

        // Scanning indicator.
        RowLayout {
            Layout.fillWidth: true
            visible: root.scanning
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            BusyIndicator {
                running: root.scanning
                implicitWidth: 24
                implicitHeight: 24
            }
            Label {
                Layout.fillWidth: true
                color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                text: root.tr("app-groups.scanning", "Scanning…")
            }
        }

        // Empty / failure placeholder — shown once a scan produced nothing.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            visible: !root.scanning && root.scanRan && root.apps.length === 0
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("app-groups.empty",
                "Nothing detected on this computer. You can add a program as an "
                + "ordinary application rule.")
        }

        TabBar {
            id: tabBar
            Layout.fillWidth: true
            visible: root.apps.length > 0
            TabButton {
                text: root.tr("app-groups.tab-virtualization",
                    "Virtual machines and emulators")
                    + " (" + root._countOfKinds(root._virtualizationKinds) + ")"
            }
            TabButton {
                text: root.tr("app-groups.tab-peer-to-peer", "Torrents and P2P")
                    + " (" + root._countOfKinds(root._peerToPeerKinds) + ")"
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: root.apps.length > 0
            currentIndex: tabBar.currentIndex

            // Tab 1 — Virtualization.
            ScrollView {
                id: virtScroller
                clip: true
                contentWidth: availableWidth
                ScrollBar.vertical.policy: ScrollBar.AsNeeded
                ColumnLayout {
                    width: virtScroller.availableWidth
                    spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                        text: root.tr("app-groups.vm-note",
                            "Virtual machine traffic follows the route assigned to its "
                            + "program. The default is the main route. A machine's local "
                            + "networks always keep working, whichever route you pick.")
                    }
                    Repeater {
                        model: root._virtualizationKinds
                        delegate: groupSectionComponent
                    }
                }
            }

            // Tab 2 — Peer-to-peer.
            ScrollView {
                id: p2pScroller
                clip: true
                contentWidth: availableWidth
                ScrollBar.vertical.policy: ScrollBar.AsNeeded
                ColumnLayout {
                    width: p2pScroller.availableWidth
                    spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                        text: root.tr("app-groups.p2p-note",
                            "These programs are not blocked unless emergency block "
                            + "(kill switch) is on. The assigned route applies to their "
                            + "bulk connections; their peers are not added to zone rules.")
                    }
                    Repeater {
                        model: root._peerToPeerKinds
                        delegate: groupSectionComponent
                    }
                }
            }
        }

        // Footer note.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            font.pixelSize: (root.ownerRoot
                ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 1
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("app-groups.footer-note",
                "Can't find your program? Add it as an ordinary application rule, or "
                + "tell us through any channel — the dictionary keeps growing.")
        }

        // Footer actions: scan again — spacer — cancel — apply (accent).
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                enabled: !root.scanning
                text: root.tr("app-groups.scan-again", "Scan again")
                onClicked: root.scan()
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("app-groups.cancel", "Cancel")
                onClicked: {
                    root.close()
                    root.skipped()
                }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                highlighted: true
                text: root.tr("app-groups.apply", "Apply")
                onClicked: {
                    // Collect every ASSIGNABLE app (kernel-virtual-net excluded)
                    // with its chosen route so the caller can reconcile the set.
                    var assignments = []
                    for (var i = 0; i < root.apps.length; i += 1) {
                        var a = root.apps[i] || {}
                        var kind = String(a.kind || "")
                        if (kind === "kernel-virtual-net") continue
                        var key = root._rowKeyOf(a)
                        var mv = root._basename(String(a.exePath || ""))
                        if (mv === "") mv = String(a.displayName || "")
                        assignments.push({
                            displayName: String(a.displayName || ""),
                            matchValue: mv,
                            route: root._routeOf(key),
                            kind: kind
                        })
                    }
                    root.close()
                    root.appGroupRoutesConfirmed(assignments)
                }
            }
        }
    }
}
