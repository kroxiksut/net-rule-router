import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

// The user's own connection history: on or off, how many days it keeps, and
// erasing it. Each choice is the caller's alone and needs no elevation, so it
// applies on the spot rather than through the page's Save.
Frame {
    id: historyFrame
    property var root
    Layout.fillWidth: true
    padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
    background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }

    property bool _loaded: false
    property bool _available: true
    property bool _enabled: true
    property int _retentionDays: 7
    property int _maxRetentionDays: 30
    property bool _busy: false
    property bool _confirmingClear: false
    property string _status: ""
    property bool _statusIsError: false

    function _errorText(prefix, code) {
        return prefix + ((typeof root.ipcErrorLabel === "function")
            ? root.ipcErrorLabel(String(code || "unknown"))
            : String(code || "unknown"))
    }

    // The choices ride on the history read; one row is enough to carry them.
    function _fetch() {
        if (!root.rpc || typeof root.rpc.rpcConnHistoryList !== "function") return
        var corr = root.rpc.rpcConnHistoryList({
            "from-unix-ms": Date.now(),
            "pagination": { "page_size": 1 }
        })
        if (corr === "") return
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode) {
            if (!ok) return
            historyFrame._available = (payload && payload.available) !== false
            historyFrame._enabled = (payload && payload.enabled) !== false
            historyFrame._retentionDays = Number((payload && payload["retention-days"]) || 7)
            historyFrame._maxRetentionDays =
                Number((payload && payload["max-retention-days"]) || 30)
            historyFrame._loaded = true
        })
    }

    function _set(patch) {
        if (!root.rpc || typeof root.rpc.rpcConnHistorySettingsSet !== "function") return
        var corr = root.rpc.rpcConnHistorySettingsSet(patch)
        if (corr === "") return
        historyFrame._busy = true
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode) {
            historyFrame._busy = false
            if (!ok) {
                historyFrame._statusIsError = true
                historyFrame._status = historyFrame._errorText(
                    root.tr("settings.conn-history.save-failed",
                        "Could not save the connection history choice: "), errorCode)
                historyFrame._fetch()
                return
            }
            historyFrame._statusIsError = false
            historyFrame._status = ""
            historyFrame._enabled = (payload && payload.enabled) !== false
            historyFrame._retentionDays =
                Number((payload && payload["retention-days"]) || historyFrame._retentionDays)
        })
    }

    function _clear() {
        historyFrame._confirmingClear = false
        if (!root.rpc || typeof root.rpc.rpcConnHistoryClear !== "function") return
        var corr = root.rpc.rpcConnHistoryClear()
        if (corr === "") return
        historyFrame._busy = true
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode) {
            historyFrame._busy = false
            historyFrame._statusIsError = !ok
            historyFrame._status = ok
                ? root.tr("settings.conn-history.cleared", "Your connection history was erased (%1 entries).")
                    .arg(Number((payload && payload.erased) || 0))
                : historyFrame._errorText(root.tr("settings.conn-history.clear-failed",
                    "Could not erase the connection history: "), errorCode)
        })
    }

    onVisibleChanged: if (visible) _fetch()
    Component.onCompleted: _fetch()

    ColumnLayout {
        anchors.fill: parent
        spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs

        Label {
            text: root.tr("settings.conn-history.title", "Connection history")
            color: root.textColor
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.conn-history.help",
                "Which of your programs connected where, and over which connection, kept on this computer for the days you choose. Only you can read your history; it is never part of the diagnostic archive.")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
        }
        Label {
            Layout.fillWidth: true
            visible: historyFrame._loaded && !historyFrame._available
            text: root.tr("diag.conn-history.unavailable",
                "The connection history cannot be kept right now. The service log says why.")
            color: root.uiTheme.colorWarning
            wrapMode: Text.WordWrap
        }
        CheckBox {
            id: keepHistoryBox
            Layout.fillWidth: true
            enabled: historyFrame._loaded && !historyFrame._busy
            // A declarative `checked:` dies at the first click; this keeps
            // following what the service answered.
            Binding {
                target: keepHistoryBox
                property: "checked"
                value: historyFrame._enabled
            }
            text: root.tr("settings.conn-history.keep", "Keep connection history")
            contentItem: Text {
                text: keepHistoryBox.text
                leftPadding: keepHistoryBox.indicator.width + keepHistoryBox.spacing
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                color: root.textColor
            }
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            onToggled: historyFrame._set({ "enabled": checked })
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                text: root.tr("settings.conn-history.retention-label", "Keep for")
                color: root.textColor
            }
            ThemedSpinBox {
                id: retentionDaysBox
                theme: root.uiTheme
                Layout.preferredWidth: 140
                from: 1
                to: historyFrame._maxRetentionDays
                Binding {
                    target: retentionDaysBox
                    property: "value"
                    value: historyFrame._retentionDays
                }
                editable: true
                enabled: historyFrame._loaded && historyFrame._enabled && !historyFrame._busy
                Accessible.name: root.tr("settings.conn-history.retention-a11y",
                    "Days the connection history is kept")
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: "1–" + historyFrame._maxRetentionDays
                onValueModified: retentionCommit.restart()
            }
            Label {
                text: root.tr("diag.retention.logs-max-age-unit", "days")
                color: root.mutedTextColor
            }
            Item { Layout.fillWidth: true }
        }
        // A burst of arrow presses is one choice, not one write per step.
        Timer {
            id: retentionCommit
            interval: 600
            repeat: false
            onTriggered: {
                if (retentionDaysBox.value !== historyFrame._retentionDays)
                    historyFrame._set({ "retention-days": retentionDaysBox.value })
            }
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedButton {
                theme: root.uiTheme
                visible: !historyFrame._confirmingClear
                enabled: historyFrame._loaded && historyFrame._available && !historyFrame._busy
                text: root.tr("settings.conn-history.clear", "Clear my history")
                Accessible.name: text
                onClicked: historyFrame._confirmingClear = true
            }
            Label {
                Layout.fillWidth: true
                visible: historyFrame._confirmingClear
                text: root.tr("settings.conn-history.clear-confirm",
                    "Erase your whole connection history? This cannot be undone.")
                color: root.textColor
                wrapMode: Text.WordWrap
            }
            ThemedButton {
                theme: root.uiTheme
                visible: historyFrame._confirmingClear
                text: root.tr("settings.conn-history.clear-yes", "Erase")
                Accessible.name: root.tr("settings.conn-history.clear", "Clear my history")
                onClicked: historyFrame._clear()
            }
            ThemedButton {
                theme: root.uiTheme
                visible: historyFrame._confirmingClear
                text: root.tr("action.cancel", "Cancel")
                Accessible.name: text
                onClicked: historyFrame._confirmingClear = false
            }
        }
        Label {
            Layout.fillWidth: true
            visible: historyFrame._status !== ""
            text: historyFrame._status
            color: historyFrame._statusIsError ? root.uiTheme.colorAccent : root.mutedTextColor
            wrapMode: Text.WordWrap
        }
    }
}
