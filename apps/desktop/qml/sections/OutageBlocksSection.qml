// What leak protection blocked during the user's last outage of the additional
// route: one row per program and address, with how many attempts it made, then
// the routed names that never resolved, so no connection was made at all.
//
// The service keeps the list (the connection trace is too short for an
// outage and mixes in permitted traffic); this page only reads it, on open,
// on Refresh, and slowly while the outage lasts.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../components"
import "../lib/pure.js" as Pure

ColumnLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    property var _answer: null
    property bool _loading: false
    property string _error: ""

    readonly property var _episode: _answer ? (_answer.episode || null) : null
    readonly property bool _active: !!_episode && _episode["until-unix-ms"] === undefined
    readonly property var _entries: _answer ? (_answer.entries || []) : []
    readonly property var _unresolved: _answer ? (_answer["unresolved-names"] || []) : []
    // One list: blocked addresses first, then names that did not resolve.
    readonly property var _rows: _entries.concat(_unresolved.map(function(n) {
        return { unresolved: true, name: String(n.name || ""), attempts: n.attempts,
                 "first-seen-ms": n["first-seen-ms"], "last-seen-ms": n["last-seen-ms"] }
    }))
    readonly property int _omitted: _answer ? Number(_answer.omitted || 0) : 0
    readonly property bool _observerActive: !_answer || _answer["observer-active"] !== false
    readonly property bool _streamEnabled: !_answer || _answer["gui-stream-enabled"] !== false

    readonly property int _colProcessWidth: 200
    readonly property int _colAttemptsWidth: 90
    readonly property int _colTimeWidth: 150

    Component.onCompleted: section.load()
    onVisibleChanged: if (visible) section.load()

    function load() {
        if (!root.bridgeAvailable || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcConnTraceOutageBlocksList !== "function") {
            section._error = section._failedText("bridge-unavailable")
            return
        }
        if (section._loading) return
        section._loading = true
        var corr = nrrNativeBridge.rpcConnTraceOutageBlocksList()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode) {
            section._loading = false
            if (!ok) {
                section._error = section._failedText(String(errorCode || "unknown"))
                return
            }
            section._error = ""
            section._answer = payload || {}
        })
    }
    function _failedText(code) {
        return root.tr("diag.outage-blocks.failed", "Could not load the list: ")
            + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
    }

    // An outage that is still on keeps adding rows; a slow read is enough.
    Timer {
        interval: 10000
        repeat: true
        running: section.visible && section._active
        onTriggered: section.load()
    }

    function _episodeText() {
        if (!section._episode) {
            return root.tr("diag.outage-blocks.no-episode",
                "The additional route has not been down since the service started.")
        }
        var since = Pure.formatTimestamp(section._episode["since-unix-ms"])
        if (section._active) {
            return root.tr("diag.outage-blocks.episode-active",
                "The additional route has been down since {since}.").replace("{since}", since)
        }
        return root.tr("diag.outage-blocks.episode-ended",
            "The last outage lasted from {since} to {until}.")
            .replace("{since}", since)
            .replace("{until}", Pure.formatTimestamp(section._episode["until-unix-ms"]))
    }
    function _remoteText(entry) {
        var ip = String(entry["remote-ip"] || "")
        var port = Number(entry["remote-port"] || 0)
        var address = port > 0 ? (ip.indexOf(":") >= 0 ? "[" + ip + "]:" + port : ip + ":" + port) : ip
        var name = String(entry.host || "") || String(entry["rule-host"] || "")
        return name !== "" ? name + "  " + address : address
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            wrapMode: Text.Wrap
            color: root.textColor
            text: root.uiRevision >= 0
                ? root.tr("diag.outage-blocks.intro",
                    "What leak protection held back while the additional route was down. Your rules send these addresses there, so they were blocked instead of leaving through the main connection.")
                : ""
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        ThemedButton {
            theme: root.uiTheme
            visible: section._active
            text: root.uiRevision >= 0
                ? root.tr("diag.outage-blocks.open-routes", "Open interfaces and routes") : ""
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: root.requestSectionChange("interfaces-routes")
        }
        ThemedButton {
            theme: root.uiTheme
            enabled: !section._loading
            text: root.uiRevision >= 0 ? root.tr("action.refresh", "Refresh") : ""
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section.load()
        }
    }

    Repeater {
        // Each line only when it has something to say; order is read order.
        model: root.uiRevision >= 0 ? [
            { show: section._error !== "", text: section._error, warn: true },
            { show: !!section._answer, text: section._episodeText(), warn: section._active },
            { show: !!section._answer && !section._observerActive,
              text: root.tr("diag.outage-blocks.observer-off",
                "On this system NetRuleRouter cannot tell which connections an outage blocked, so this list stays empty."),
              warn: false },
            { show: !!section._answer && !section._streamEnabled,
              text: root.tr("diag.conn-trace.gui-stream-off",
                "Showing the connection trace is switched off in Settings → Diagnostics and logs. Observation itself keeps running."),
              warn: false },
            { show: !!section._episode && section._observerActive && section._streamEnabled
                    && section._rows.length === 0,
              text: root.tr("diag.outage-blocks.empty", "Nothing was blocked during this outage."),
              warn: false },
            { show: section._unresolved.length > 0,
              text: root.tr("diag.outage-blocks.unresolved-note",
                "Names marked “did not resolve” got no address, so the program could not even start a connection."),
              warn: false },
            { show: section._omitted > 0,
              text: root.tr("diag.outage-blocks.omitted", "{count} older entries did not fit in the list.")
                .replace("{count}", String(section._omitted)),
              warn: true }
        ] : []
        delegate: Label {
            required property var modelData
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: modelData.show
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            color: modelData.warn ? root.uiTheme.colorWarning : root.mutedTextColor
            text: modelData.text
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
    }

    Frame {
        Layout.fillWidth: true
        Layout.fillHeight: true
        visible: section._rows.length > 0
        padding: root.uiTheme.spacingSm
        background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }

        ColumnLayout {
            anchors.fill: parent
            spacing: root.uiTheme.spacingXs

            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingMd
                Accessible.role: Accessible.Row
                Repeater {
                    model: root.uiRevision >= 0 ? [
                        { text: root.tr("diag.conn-trace.col-process", "Process"), width: section._colProcessWidth },
                        { text: root.tr("diag.conn-trace.col-remote", "Remote"), width: -1 },
                        { text: root.tr("diag.outage-blocks.col-attempts", "Attempts"), width: section._colAttemptsWidth },
                        { text: root.tr("diag.outage-blocks.col-first", "First"), width: section._colTimeWidth },
                        { text: root.tr("diag.outage-blocks.col-last", "Last"), width: section._colTimeWidth }
                    ] : []
                    delegate: Label {
                        required property var modelData
                        Layout.fillWidth: modelData.width < 0
                        Layout.preferredWidth: modelData.width < 0 ? 0 : modelData.width
                        font.bold: true
                        elide: Text.ElideRight
                        color: root.textColor
                        text: modelData.text
                        Accessible.role: Accessible.ColumnHeader
                        Accessible.name: text
                    }
                }
            }

            ListView {
                id: list
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 120
                clip: true
                model: section._rows
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar {}
                Accessible.role: Accessible.List
                Accessible.name: root.sectionTitle("outage-blocks")
                delegate: RowLayout {
                    required property var modelData
                    width: list.width
                    spacing: root.uiTheme.spacingMd
                    // No connection was made, so there is no program to name.
                    readonly property string _process: modelData.unresolved ? "—" : String(modelData.process || "")
                    readonly property string _remote: modelData.unresolved
                        ? (root.uiRevision >= 0
                            ? modelData.name + "  " + root.tr("diag.outage-blocks.unresolved", "did not resolve")
                            : "")
                        : section._remoteText(modelData)
                    readonly property string _attempts: String(modelData.attempts || 0)
                    readonly property string _first: Pure.formatTimestamp(modelData["first-seen-ms"])
                    readonly property string _last: Pure.formatTimestamp(modelData["last-seen-ms"])
                    Accessible.role: Accessible.ListItem
                    Accessible.name: (modelData.unresolved
                        ? [_remote, _attempts, _first, _last]
                        : [_process, _remote, _attempts, _first, _last]).join(", ")
                    Label {
                        Layout.preferredWidth: section._colProcessWidth
                        elide: Text.ElideRight
                        textFormat: Text.PlainText
                        color: root.textColor
                        text: parent._process
                        ToolTip.visible: processHover.hovered && String(modelData["process-path"] || "") !== ""
                        ToolTip.text: String(modelData["process-path"] || "")
                        HoverHandler { id: processHover }
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 0
                        elide: Text.ElideRight
                        textFormat: Text.PlainText
                        font.italic: !!modelData.unresolved
                        color: root.textColor
                        text: parent._remote
                    }
                    Label {
                        Layout.preferredWidth: section._colAttemptsWidth
                        color: root.textColor
                        text: parent._attempts
                    }
                    Label {
                        Layout.preferredWidth: section._colTimeWidth
                        color: root.mutedTextColor
                        text: parent._first
                    }
                    Label {
                        Layout.preferredWidth: section._colTimeWidth
                        color: root.mutedTextColor
                        text: parent._last
                    }
                }
            }
        }
    }

    // Keeps the lines at the top when there is no table to take the height.
    Item {
        Layout.fillHeight: true
        visible: section._rows.length === 0
    }
}
