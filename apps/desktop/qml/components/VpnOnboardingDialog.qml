import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import QtQuick.Dialogs

// VPN-client onboarding.
//
// Lets the user point NetRuleRouter at the program they use as their VPN, so
// that program's traffic keeps flowing over the primary link while leak
// protection ("kill-switch") is engaged. The app already turns an
// "Application -> primary route" rule into a kill-switch exemption; this dialog
// only CAPTURES which executable that is.
//
// It drives the launcher-local `local.vpn.discover` RPC through the owner
// (`ownerRoot.rpc.rpcVpnDiscover()` + `ownerRoot.rpc.registerRpcCallback`). That RPC is
// local, non-elevated, and needs no background service, so onboarding works
// before the service is even installed. The dialog is otherwise "dumb": it
// renders the candidate list and emits `vpnConfirmedMulti(displayNames,
// exePaths)` (multi-select), `vpnConfirmed(displayName, exePath)` (single add
// from the manual file picker), `skipped()`, or `manualPickRequested()`;
// the caller (Main.qml) decides what to
// persist. All shared state comes in through `ownerRoot` (the
// ApplicationWindow) — never via implicit scope. Themed* wrappers only.
Window {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null

    /// Scan state and results. `candidates` is a plain JS array of
    /// `{ displayName, exePath, running, source }` objects returned by the RPC.
    property bool scanning: false
    property bool scanFailed: false
    property bool scanRan: false
    property var candidates: []

    /// The user's current multi-selection, modelled as a set: a plain JS object
    /// keyed by each candidate's row key (`_rowKeyOf`) with value `true`. Reset
    /// by reassignment (never in-place mutation) so QML bindings re-evaluate.
    /// A candidate with an empty exe path is still selectable — its name is kept
    /// for the manual-pick follow-up, mirroring the old null-path handling.
    property var selectedKeys: ({})

    /// Fired when the user confirms a specific program as their VPN. `exePath`
    /// may be empty when the candidate had no resolved path (manual pick later).
    /// Retained for the single-add path (the manual file picker below).
    signal vpnConfirmed(string displayName, string exePath)
    /// Fired when the user confirms one OR MORE programs as their VPN setup
    /// (e.g. a client plus its background service and CLI). `displayNames` and
    /// `exePaths` are parallel arrays in display order; an entry's `exePath`
    /// may be empty (name-only candidate). The caller persists the full set and
    /// mirrors the first non-empty path into the single-path preference.
    signal vpnConfirmedMulti(var displayNames, var exePaths)
    /// Fired when the user says they do not use a VPN (or dismisses).
    signal skipped()
    /// Fired when the user wants to browse for the executable themselves. The
    /// actual native file picker is wired later; for now the caller just notes
    /// the request.
    signal manualPickRequested()

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    // API-compatible with the other modal child windows in Main.qml.
    function open() {
        _resetSelection()
        candidates = []
        scanFailed = false
        scanRan = false
        visible = true
        // Kick off a scan immediately so the list is populated by the time the
        // user has read the intro; they can re-scan with the button.
        scan()
    }

    function _resetSelection() {
        selectedKeys = ({})
    }

    /// Stable per-candidate selection key: the exe path when present, else a
    /// `name:`-prefixed display name (so a path-less candidate is still keyed).
    function _rowKeyOf(displayName, exePath) {
        var p = String(exePath || "")
        return p !== "" ? p : ("name:" + String(displayName || ""))
    }
    function _isSelected(key) {
        return root.selectedKeys[key] === true
    }
    /// Toggle a candidate's membership. Reassigns `selectedKeys` with a fresh
    /// object so bindings that read it (checkbox `checked`, confirm `enabled`,
    /// the selected count) re-evaluate — in-place mutation would not notify.
    function _setSelected(key, on) {
        var next = {}
        for (var k in root.selectedKeys) {
            if (root.selectedKeys[k] === true) next[k] = true
        }
        if (on) next[key] = true
        else delete next[key]
        root.selectedKeys = next
    }
    function _selectedCount() {
        var n = 0
        for (var k in root.selectedKeys) {
            if (root.selectedKeys[k] === true) n += 1
        }
        return n
    }
    /// True when every candidate is currently selected (and there is at least
    /// one). Drives the select-all control's toggle semantics and label.
    function _allSelected() {
        if (!root.candidates || root.candidates.length === 0) return false
        for (var i = 0; i < root.candidates.length; i += 1) {
            var c = root.candidates[i] || {}
            var key = root._rowKeyOf(String(c.displayName || ""),
                String(c.exePath || ""))
            if (root.selectedKeys[key] !== true) return false
        }
        return true
    }
    /// Toggle every candidate at once. Builds a fresh selection object and
    /// reassigns `selectedKeys` (never in-place mutation) so bindings notify:
    /// if everything is already selected this clears the set, otherwise it
    /// selects all found candidates.
    function _toggleSelectAll() {
        if (root._allSelected()) {
            root.selectedKeys = ({})
            return
        }
        var next = {}
        for (var i = 0; i < root.candidates.length; i += 1) {
            var c = root.candidates[i] || {}
            var key = root._rowKeyOf(String(c.displayName || ""),
                String(c.exePath || ""))
            next[key] = true
        }
        root.selectedKeys = next
    }

    /// Drive the launcher-local `local.vpn.discover` RPC and populate the list.
    function scan() {
        if (scanning) return
        if (!ownerRoot
                || !ownerRoot.rpc
                || typeof ownerRoot.rpc.rpcVpnDiscover !== "function"
                || typeof ownerRoot.rpc.registerRpcCallback !== "function") {
            scanFailed = true
            scanRan = true
            return
        }
        scanning = true
        scanFailed = false
        _resetSelection()
        var corr = ownerRoot.rpc.rpcVpnDiscover()
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
                root.candidates = []
                return
            }
            var list = payload.candidates || payload["candidates"] || []
            var normalized = []
            for (var i = 0; i < list.length; i += 1) {
                var c = list[i] || {}
                var exe = c.exePath || c["exePath"] || c["exe-path"] || null
                normalized.push({
                    displayName: String(c.displayName || c["displayName"]
                        || c["display-name"] || ""),
                    exePath: (exe === null || exe === undefined) ? "" : String(exe),
                    running: (c.running === true),
                    source: String(c.source || "")
                })
            }
            root.candidates = normalized
            root.scanFailed = false
        })
    }

    /// Strip a `file:///` URL down to a plain local path (Windows-aware), then
    /// derive a friendly display name from the executable basename.
    function _localPathFromUrl(urlValue) {
        var s = String(urlValue || "")
        if (s.indexOf("file:///") === 0) return s.substring(8)
        if (s.indexOf("file://") === 0) return s.substring(7)
        return s
    }
    function _nameFromPath(p) {
        var s = String(p || "")
        if (s === "") return ""
        var i = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\"))
        var b = i >= 0 ? s.substring(i + 1) : s
        return b.replace(/\.exe$/i, "")
    }

    // Native OS file picker for "My VPN isn't listed" — replaces the old
    // "coming soon" no-op. On accept the chosen executable IS the confirmed VPN.
    FileDialog {
        id: manualPickDialog
        fileMode: FileDialog.OpenFile
        title: root.tr("vpn-onboarding.manual-pick-title", "Choose your VPN program")
        nameFilters: [
            root.tr("vpn-onboarding.manual-pick-filter", "Programs (*.exe)"),
            root.tr("vpn-onboarding.manual-pick-all", "All files (*)")
        ]
        onAccepted: {
            var path = root._localPathFromUrl(selectedFile)
            var name = root._nameFromPath(path)
            root.close()
            root.vpnConfirmed(name, path)
        }
    }

    function _sourceHint(source) {
        if (source === "running-process")
            return root.tr("vpn-onboarding.source-running-process",
                "detected as a running program")
        if (source === "installed-program")
            return root.tr("vpn-onboarding.source-installed-program",
                "found among installed programs")
        return ""
    }

    width: 640
    height: 560
    minimumWidth: 460
    minimumHeight: 380
    visible: false
    modality: Qt.ApplicationModal
    flags: Qt.Dialog
    color: ownerRoot ? ownerRoot.panelColor : "#202020"
    title: tr("vpn-onboarding.title", "Set up your VPN")
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
            text: root.tr("vpn-onboarding.heading", "Do you use a VPN?")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("vpn-onboarding.intro",
                "Point NetRuleRouter at it so it keeps working when leak "
                + "protection is on. We look at your running programs and "
                + "installed apps — nothing is sent anywhere.")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("vpn-onboarding.multi-hint",
                "Tick every program that's part of your VPN — for example a "
                + "client together with its background service or command-line "
                + "helper. All of them will keep working over your main link.")
        }

        // Scan control + busy indicator.
        RowLayout {
            Layout.fillWidth: true
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                enabled: !root.scanning
                text: root.scanRan
                    ? root.tr("vpn-onboarding.scan-again", "Scan again")
                    : root.tr("vpn-onboarding.scan", "Scan for VPN apps")
                onClicked: root.scan()
            }
            BusyIndicator {
                running: root.scanning
                visible: root.scanning
                implicitWidth: 24
                implicitHeight: 24
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                visible: root.scanning
                color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                text: root.tr("vpn-onboarding.scanning", "Scanning…")
            }
        }

        // Result list. Empty / failure states share the placeholder label.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            visible: !root.scanning
                && (root.candidates.length === 0)
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.scanFailed
                ? root.tr("vpn-onboarding.scan-failed",
                    "Could not scan for VPN apps. You can pick your VPN manually below.")
                : (root.scanRan
                    ? root.tr("vpn-onboarding.empty",
                        "No VPN apps found. If you use one, pick it manually below.")
                    : root.tr("vpn-onboarding.not-scanned-yet",
                        "Run a scan to look for VPN apps."))
        }

        // Bulk-select control: select every found candidate at once, or clear
        // the whole selection when all are already ticked (toggle semantics).
        RowLayout {
            Layout.fillWidth: true
            visible: root.candidates.length > 0
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                flat: true
                text: root._allSelected()
                    ? root.tr("vpn-onboarding.clear-selection", "Clear selection")
                    : root.tr("vpn-onboarding.select-all", "Select all")
                onClicked: root._toggleSelectAll()
            }
            Item { Layout.fillWidth: true }
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            visible: root.candidates.length > 0
            ScrollBar.vertical.policy: ScrollBar.AsNeeded

            ColumnLayout {
                width: parent.width
                spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8

                Repeater {
                    model: root.candidates
                    delegate: Rectangle {
                        id: candidateCard
                        Layout.fillWidth: true
                        Layout.preferredHeight: rowLayout.implicitHeight
                            + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm * 2 : 16)
                        radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 4
                        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "transparent"
                        border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 1
                        border.color: (candidateCheck.checked && root.ownerRoot)
                            ? root.ownerRoot.uiTheme.colorAccent
                            : (root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "#555")

                        // Key that identifies this candidate for selection.
                        property string rowKey: root._rowKeyOf(
                            String(modelData.displayName || ""),
                            String(modelData.exePath || ""))

                        RowLayout {
                            id: rowLayout
                            anchors.fill: parent
                            anchors.margins: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8

                            // Multi-select toggle. Inline-themed indicator (no
                            // ThemedCheckBox wrapper exists) so the box respects
                            // the app theme instead of the Windows Native style.
                            CheckBox {
                                id: candidateCheck
                                Layout.alignment: Qt.AlignTop
                                checked: root._isSelected(candidateCard.rowKey)
                                onToggled: root._setSelected(candidateCard.rowKey, checked)
                                indicator: Rectangle {
                                    implicitWidth: 20
                                    implicitHeight: 20
                                    x: candidateCheck.leftPadding
                                    y: candidateCheck.topPadding
                                        + (candidateCheck.availableHeight - height) / 2
                                    radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 3
                                    color: candidateCheck.checked && root.ownerRoot
                                        ? root.ownerRoot.uiTheme.colorAccent
                                        : (root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "#2a2a2a")
                                    border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 1
                                    border.color: candidateCheck.checked && root.ownerRoot
                                        ? root.ownerRoot.uiTheme.colorAccent
                                        : (root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "#555")
                                    Text {
                                        anchors.centerIn: parent
                                        visible: candidateCheck.checked
                                        text: "✓"
                                        font.pixelSize: 14
                                        font.bold: true
                                        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorOnAccent : "white"
                                    }
                                }
                                // The custom indicator is painted separately; the
                                // Fusion style computes control implicitWidth as
                                // leftPadding + contentItem.implicitWidth +
                                // rightPadding (the indicator is NOT counted), so an
                                // empty contentItem collapses the CheckBox to ~0 wide
                                // in the RowLayout and the 20x20 box paints under the
                                // name label. Give the contentItem the indicator's
                                // footprint so the control reserves real width.
                                contentItem: Item {
                                    implicitWidth: candidateCheck.indicator
                                        ? candidateCheck.indicator.implicitWidth : 20
                                    implicitHeight: candidateCheck.indicator
                                        ? candidateCheck.indicator.implicitHeight : 20
                                }
                                Accessible.role: Accessible.CheckBox
                                Accessible.name: String(modelData.displayName || "")
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
                                    Label {
                                        Layout.fillWidth: true
                                        wrapMode: Text.WordWrap
                                        font.bold: true
                                        color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                                        text: String(modelData.displayName || "")
                                    }
                                    // "running now" badge.
                                    Rectangle {
                                        visible: modelData.running === true
                                        radius: 3
                                        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorAccent : "#3d6fb4"
                                        Layout.preferredWidth: runningLabel.implicitWidth
                                            + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8)
                                        Layout.preferredHeight: runningLabel.implicitHeight
                                            + (root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4)
                                        Label {
                                            id: runningLabel
                                            anchors.centerIn: parent
                                            font.pixelSize: (root.ownerRoot
                                                ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 2
                                            color: root.ownerRoot ? root.ownerRoot.uiTheme.colorOnAccent : "white"
                                            text: root.tr("vpn-onboarding.running", "running now")
                                        }
                                    }
                                }
                                // Secondary line: the exe path, or a
                                // "pick manually" hint when it is unknown.
                                Label {
                                    Layout.fillWidth: true
                                    wrapMode: Text.WrapAnywhere
                                    font.pixelSize: (root.ownerRoot
                                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 1
                                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                                    text: String(modelData.exePath || "") !== ""
                                        ? String(modelData.exePath)
                                        : root.tr("vpn-onboarding.not-found",
                                            "not found — pick manually")
                                }
                                // Source hint (running process / installed program).
                                Label {
                                    Layout.fillWidth: true
                                    wrapMode: Text.WordWrap
                                    visible: text !== ""
                                    font.pixelSize: (root.ownerRoot
                                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 2
                                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                                    text: root._sourceHint(String(modelData.source || ""))
                                }
                            }
                        }
                    }
                }
            }
        }

        // "My VPN isn't listed" — open the native file picker.
        // Also notifies the owner via `manualPickRequested()` for any
        // side-effects it wants (status line), then opens the picker.
        ThemedButton {
            theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
            flat: true
            Layout.fillWidth: true
            wrapText: true
            text: root.tr("vpn-onboarding.manual-pick",
                "My VPN isn't listed / pick it manually")
            onClicked: {
                root.manualPickRequested()
                manualPickDialog.open()
            }
        }

        // Footer: Skip (left) — spacer — confirm (accent, right).
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("vpn-onboarding.skip", "I don't use a VPN")
                onClicked: {
                    root.close()
                    root.skipped()
                }
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                highlighted: true
                enabled: root._selectedCount() > 0
                text: root.tr("vpn-onboarding.confirm", "This is my VPN")
                onClicked: {
                    // Collect the selected candidates in display order so the
                    // first non-empty path becomes the primary (mirrored into
                    // the single-path preference by the caller).
                    var names = []
                    var paths = []
                    for (var i = 0; i < root.candidates.length; i += 1) {
                        var c = root.candidates[i] || {}
                        var dn = String(c.displayName || "")
                        var ep = String(c.exePath || "")
                        if (root._isSelected(root._rowKeyOf(dn, ep))) {
                            names.push(dn)
                            paths.push(ep)
                        }
                    }
                    root.close()
                    root.vpnConfirmedMulti(names, paths)
                }
            }
        }
    }
}
