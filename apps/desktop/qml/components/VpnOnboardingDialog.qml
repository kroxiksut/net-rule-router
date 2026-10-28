import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import QtQuick.Dialogs
import "../lib/pure.js" as Pure

// "Your VPN client" picker.
//
// Lists the likely VPN programs found on this machine (launcher-local
// `local.vpn.discover`, no service needed) together with every program
// already confirmed, opens with the confirmed ones ticked, and on confirm
// hands the rows and the ticks to the caller, which writes the set over a
// fresh read (`vpnPickerResultApps`). The stored set is a list, so the picker
// is multi-choice. A row whose program file is unknown cannot be ticked until
// the user chooses the file. Themed* wrappers only; shared state through
// `ownerRoot`.
Window {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null

    property bool scanning: false
    property bool scanFailed: false
    property bool scanRan: false
    /// What discovery found: `{ displayName, exePath, running, source,
    /// interfaceName }`. A `kernel-tunnel` row is never tickable and offers
    /// its link for the secondary role instead.
    property var found: []
    /// Program files the user chose by hand in this session.
    property var picked: []
    /// The confirmed set the picker opened over (`exe-path`/`display-name`).
    property var storedApps: []
    /// The stored set could not be read: nothing is offered for saving, since
    /// a save would be worked out over a set nobody has seen.
    property bool storedUnread: false
    readonly property var rows: Pure.vpnPickerRows(root.found.concat(root.picked), root.storedApps)
    /// Ticked paths. Reassigned, never mutated, so bindings re-evaluate.
    property var selectedPaths: []
    /// Display name of the found row whose file is being chosen, if any.
    property string _pickFor: ""

    /// Fired on confirm with the rows on screen and the ticked paths.
    signal pickConfirmed(var rows, var selected)
    /// Fired when the user says they do not use a VPN (or dismisses).
    signal skipped()

    // Escape closes, as the title bar's close does: "I don't use a VPN" is an
    // answer, and a key press must not give it.
    Shortcut {
        sequences: ["Esc"]
        context: Qt.WindowShortcut
        onActivated: root.close()
    }
    /// Fired when the user opens the file picker.
    signal manualPickRequested()
    /// Fired when the user wants a kernel tunnel's link bound as the
    /// secondary route; the dialog has already closed.
    signal kernelTunnelAdapterRequested(string interfaceName)
    /// Fired when the user asks to read the stored set again.
    signal retryReadRequested()

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    /// `stored`: the confirmed set as the service holds it.
    function open(stored) {
        storedUnread = false
        storedApps = stored || []
        found = []
        picked = []
        selectedPaths = Pure.vpnPickerPreselected(Pure.vpnPickerRows([], storedApps), storedApps)
        scanFailed = false
        scanRan = false
        visible = true
        scan()
    }

    function openUnread() {
        storedUnread = true
        storedApps = []
        found = []
        picked = []
        selectedPaths = []
        scanFailed = false
        scanRan = false
        visible = true
    }

    function _samePath(a, b) {
        return String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase()
    }
    function _isSelected(path) {
        for (var i = 0; i < root.selectedPaths.length; i += 1) {
            if (root._samePath(root.selectedPaths[i], path)) return true
        }
        return false
    }
    function _setSelected(path, on) {
        var next = []
        for (var i = 0; i < root.selectedPaths.length; i += 1) {
            if (!root._samePath(root.selectedPaths[i], path)) next.push(root.selectedPaths[i])
        }
        if (on) next.push(String(path))
        root.selectedPaths = next
    }
    function _tickableCount() {
        var n = 0
        for (var i = 0; i < root.rows.length; i += 1) {
            if (Pure.vpnPickerTickable(root.rows[i])) n += 1
        }
        return n
    }
    function _selectedCount() {
        var n = 0
        for (var i = 0; i < root.rows.length; i += 1) {
            var r = root.rows[i]
            if (Pure.vpnPickerTickable(r) && root._isSelected(r.exePath)) n += 1
        }
        return n
    }
    function _allSelected() {
        var tickable = root._tickableCount()
        return tickable > 0 && root._selectedCount() === tickable
    }
    function _toggleSelectAll() {
        if (root._allSelected()) {
            root.selectedPaths = []
            return
        }
        var next = []
        for (var i = 0; i < root.rows.length; i += 1) {
            if (Pure.vpnPickerTickable(root.rows[i])) next.push(root.rows[i].exePath)
        }
        root.selectedPaths = next
    }
    function _isKernelTunnel(row) {
        return String((row || {}).source || "") === "kernel-tunnel"
    }
    function _pickFileFor(displayName) {
        root._pickFor = String(displayName || "")
        root.manualPickRequested()
        manualPickDialog.open()
    }

    /// Drive the launcher-local `local.vpn.discover` RPC. The ticks survive a
    /// rescan: they are paths, not places in the list.
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
                root.found = []
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
                    source: String(c.source || ""),
                    interfaceName: String(c["interface"] || "")
                })
            }
            root.found = normalized
            root.scanFailed = false
        })
    }

    /// Strip a `file:///` URL down to a plain local path (Windows-aware), then
    /// derive a friendly display name from the executable basename.
    function _localPathFromUrl(urlValue) {
        return Pure.localPathFromFileUrl(urlValue)
    }
    function _nameFromPath(p) {
        var s = String(p || "")
        if (s === "") return ""
        var i = Math.max(s.lastIndexOf("/"), s.lastIndexOf("\\"))
        var b = i >= 0 ? s.substring(i + 1) : s
        return b.replace(/\.exe$/i, "")
    }

    // Native file picker: "My VPN isn't listed", or the file of a row found
    // without one.
    FileDialog {
        id: manualPickDialog
        fileMode: FileDialog.OpenFile
        title: root.tr("vpn-onboarding.manual-pick-title", "Choose your VPN program")
        nameFilters: [
            root.tr("vpn-onboarding.manual-pick-filter", "Programs (*.exe)"),
            root.tr("vpn-onboarding.manual-pick-all", "All files (*)")
        ]
        // The file joins the list ticked; confirm saves it with the rest.
        onAccepted: {
            var path = root._localPathFromUrl(selectedFile)
            var forName = root._pickFor
            root._pickFor = ""
            if (String(path || "").trim() === "") return
            var shown = false
            for (var i = 0; i < root.rows.length; i += 1) {
                if (Pure.vpnPickerTickable(root.rows[i]) && root._samePath(root.rows[i].exePath, path))
                    shown = true
            }
            if (!shown) {
                root.picked = root.picked.concat([{
                    displayName: forName !== "" ? forName : root._nameFromPath(path),
                    exePath: path, running: false, source: "manual-pick", interfaceName: "" }])
            }
            root._setSelected(path, true)
        }
        onRejected: root._pickFor = ""
    }

    function _sourceHint(source) {
        if (source === "running-process")
            return root.tr("vpn-onboarding.source-running-process",
                "detected as a running program")
        if (source === "installed-program")
            return root.tr("vpn-onboarding.source-installed-program",
                "found among installed programs")
        if (source === "confirmed")
            return root.tr("vpn-onboarding.source-confirmed", "confirmed by you earlier")
        if (source === "manual-pick")
            return root.tr("vpn-onboarding.source-manual-pick", "chosen by you")
        return ""
    }

    function _kernelTunnelTitle(c) {
        var name = Pure.displayText(c.displayName)
        if (c.running === true && String(c.interfaceName || "") !== "") {
            return root.tr("vpn-onboarding.kernel-tunnel-assign",
                "Kernel tunnel {name} — assign adapter {interface} as the additional link")
                .replace("{name}", name)
                .replace("{interface}", Pure.displayText(c.interfaceName))
        }
        return root.tr("vpn-onboarding.kernel-tunnel-down", "Tunnel {name} is not up")
            .replace("{name}", name)
    }

    width: 640
    height: 560
    minimumWidth: 460
    minimumHeight: 380
    visible: false
    modality: Qt.ApplicationModal
    flags: Qt.Dialog
    color: ownerRoot ? ownerRoot.panelColor : "#202020"
    title: tr("vpn-onboarding.title", "Your VPN client")
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

        RowLayout {
            Layout.fillWidth: true
            visible: root.storedUnread
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                text: root.tr("vpn-onboarding.not-read",
                    "Your VPN programs could not be read, so they cannot be changed now.")
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.retry", "Try again")
                onClicked: root.retryReadRequested()
            }
        }

        // Scan control + busy indicator.
        RowLayout {
            Layout.fillWidth: true
            visible: !root.storedUnread
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
            visible: !root.scanning && !root.storedUnread && root.found.length === 0
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

        // Tick every row at once, or clear the ticks when all are ticked.
        RowLayout {
            Layout.fillWidth: true
            visible: root._tickableCount() > 0
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                flat: true
                text: root._allSelected()
                    ? root.tr("vpn-onboarding.clear-selection", "Clear selection")
                    : root.tr("action.select-all", "Select all")
                onClicked: root._toggleSelectAll()
            }
            Item { Layout.fillWidth: true }
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            visible: root.rows.length > 0
            ScrollBar.vertical.policy: ScrollBar.AsNeeded

            ColumnLayout {
                width: parent.width
                spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8

                Repeater {
                    model: root.rows
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

                        readonly property string rowPath: String(modelData.exePath || "")
                        readonly property bool isTunnel: root._isKernelTunnel(modelData)
                        readonly property bool tickable: Pure.vpnPickerTickable(modelData)

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
                                visible: candidateCard.tickable
                                Layout.alignment: Qt.AlignTop
                                checked: root._isSelected(candidateCard.rowPath)
                                // A click assigns `checked` and breaks the binding;
                                // put it back so "Select all" still drives the box.
                                onToggled: {
                                    root._setSelected(candidateCard.rowPath, checked)
                                    checked = Qt.binding(function() {
                                        return root._isSelected(candidateCard.rowPath)
                                    })
                                }
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
                                Accessible.name: Pure.displayText(modelData.displayName)
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
                                        textFormat: Text.PlainText
                                        text: candidateCard.isTunnel
                                            ? root._kernelTunnelTitle(modelData)
                                            : Pure.displayText(modelData.displayName)
                                    }
                                    // "running now" badge.
                                    Rectangle {
                                        visible: modelData.running === true && !candidateCard.isTunnel
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
                                    visible: !candidateCard.isTunnel
                                    wrapMode: Text.WrapAnywhere
                                    font.pixelSize: (root.ownerRoot
                                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 1
                                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                                    textFormat: Text.PlainText
                                    text: String(modelData.exePath || "") !== ""
                                        ? Pure.displayText(modelData.exePath)
                                        : root.tr("vpn-onboarding.not-found",
                                            "not found — pick manually")
                                }
                                // Found without its file: the file must be chosen
                                // before the program can be confirmed.
                                ThemedButton {
                                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                                    visible: !candidateCard.isTunnel && !candidateCard.tickable
                                    text: root.tr("vpn-onboarding.pick-file", "Choose its program file")
                                    Accessible.description: Pure.displayText(modelData.displayName)
                                    onClicked: root._pickFileFor(String(modelData.displayName || ""))
                                }
                                // Source hint.
                                Label {
                                    Layout.fillWidth: true
                                    wrapMode: Text.WordWrap
                                    visible: text !== ""
                                    font.pixelSize: (root.ownerRoot
                                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 2
                                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                                    text: root._sourceHint(String(modelData.source || ""))
                                }
                                // Why a kernel tunnel has no program to tick.
                                Label {
                                    Layout.fillWidth: true
                                    visible: candidateCard.isTunnel
                                    wrapMode: Text.WordWrap
                                    font.pixelSize: (root.ownerRoot
                                        ? root.ownerRoot.uiTheme.baseFontSizePx : 13) - 1
                                    color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
                                    text: root.tr("vpn-onboarding.kernel-tunnel-why",
                                        "The system itself runs this tunnel, so no program rule can carry it — it is routed by its adapter.")
                                }
                                ThemedButton {
                                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                                    visible: candidateCard.isTunnel
                                    enabled: modelData.running === true
                                        && String(modelData.interfaceName || "") !== ""
                                    text: root.tr("status.secondary-unresolved-button",
                                        "Open Interfaces and routes")
                                    Accessible.description: root._kernelTunnelTitle(modelData)
                                    onClicked: {
                                        var link = String(modelData.interfaceName || "")
                                        root.close()
                                        root.kernelTunnelAdapterRequested(link)
                                    }
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
            visible: !root.storedUnread
            text: root.tr("vpn-onboarding.manual-pick",
                "My VPN isn't listed / pick it manually")
            onClicked: root._pickFileFor("")
        }

        // Takes the slack the hidden list leaves; without a filler the layout
        // spreads the remaining blocks over the whole window height.
        Item {
            Layout.fillHeight: true
            visible: root.rows.length === 0
        }

        // Footer: Skip (left) — spacer — confirm (accent, right).
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                // Over a stored set this only closes: taking programs back is
                // an untick and a save, never a side effect of "no VPN".
                text: root.storedApps.length > 0 || root.storedUnread
                    ? root.tr("action.cancel", "Cancel")
                    : root.tr("vpn-onboarding.skip", "I don't use a VPN")
                onClicked: {
                    var hadStored = root.storedApps.length > 0 || root.storedUnread
                    root.close()
                    if (!hadStored) root.skipped()
                }
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                highlighted: true
                // Nothing ticked over a stored set is a choice too: it takes
                // them all back.
                enabled: !root.storedUnread
                    && (root._selectedCount() > 0 || root.storedApps.length > 0)
                text: root._selectedCount() > 0
                    ? root.tr("vpn-onboarding.confirm", "This is my VPN")
                    : root.tr("action.save", "Save")
                onClicked: {
                    var shown = root.rows
                    var ticked = root.selectedPaths
                    root.close()
                    root.pickConfirmed(shown, ticked)
                }
            }
        }
    }
}
