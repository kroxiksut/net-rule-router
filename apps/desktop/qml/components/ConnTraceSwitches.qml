import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

// Connection-egress trace controls: write the trace to the service log for a
// while, show it in Diagnostics. Privacy-sensitive, so writing is a window
// that closes by itself, applied live like verbose logging; the GUI switch is
// a draft the caller owns and saves. Drawn inside the stability card where the
// service applies the whole row, in a card of its own where it applies only
// these.
ColumnLayout {
    id: block

    /// The ApplicationWindow: `tr()`, theme, colours and `supports()`.
    property var root
    property bool guiChecked: false
    /// A log-window request parked while the service is down, shown until
    /// delivered; owned by the caller, which reads the parked store.
    property string logParkedChange: ""

    signal guiEdited(bool value)
    /// The user picked a log window; the caller applies it.
    signal logChangeRequested(string change)

    // Wall clock for the remaining-time text; ticks only while a window runs.
    property real _nowMs: Date.now()

    spacing: root.uiTheme.spacingXxs

    Label {
        Layout.fillWidth: true
        text: block.root.tr(
            "settings.diagnostics.conn-trace.heading",
            "Connection trace (diagnostic)")
        font.pixelSize: block.root.uiTheme.baseFontSizePx
        font.bold: true
    }
    // Where the service cannot write the trace, the texts must not promise a
    // disk copy or a second control.
    Label {
        Layout.fillWidth: true
        text: block.root.supports("connTraceLog")
            ? block.root.tr(
                "settings.diagnostics.conn-trace.intro",
                "Records outgoing connections of all apps and the interface each left through (direct vs the additional adapter). Sees the real socket, so it works even when the browser uses DoH. Observation itself is always on — these two controls decide where it is shown and whether it is written down.")
            : block.root.tr(
                "settings.diagnostics.conn-trace.intro-no-log",
                "Shows outgoing connections of all apps and the interface each left through (direct vs the additional adapter). Sees the real socket, so it works even when the browser uses DoH. Observation itself is always on — this switch decides whether it is shown. On this platform the trace is never written to disk.")
        color: block.root.mutedTextColor
        wrapMode: Text.WordWrap
        font.pixelSize: block.root.uiTheme.baseFontSizePx - 1
    }
    // Hidden where the service has no disk sink for the trace.
    RowLayout {
        Layout.fillWidth: true
        visible: block.root.supports("connTraceLog")
        spacing: block.root.uiTheme.spacingSm
        Label {
            text: block.root.tr(
                "settings.diagnostics.conn-trace.ndjson.label",
                "Write connection trace to service log")
            color: block.root.textColor
            Layout.alignment: Qt.AlignVCenter
        }
        LogWindowDurationCombo {
            root: block.root
            theme: block.root.uiTheme
            Layout.fillWidth: true
            Layout.maximumWidth: 420
            labelFor: function(change) { return block.root.connTraceLogChangeLabel(change) }
            // Forced on by the service side: nothing here can shut it.
            enabled: !block.root.serviceConnTraceLogForced
            currentIndex: {
                if (block.root.serviceConnTraceLogForced) return -1
                if (block.logParkedChange !== "")
                    return Pure.LOG_WINDOW_CHANGES.indexOf(block.logParkedChange)
                if (block.root.serviceConnTraceLogMode === "until-restart") return 3
                return block.root.serviceConnTraceLogMode === "off" ? 0 : -1
            }
            displayText: block.root.uiRevision >= 0
                ? block.root.connTraceLogStateText(block._nowMs) : ""
            onActivated: function(index) { block.logChangeRequested(options[index]) }
            Accessible.name: block.root.tr(
                "settings.diagnostics.conn-trace.ndjson.label",
                "Write connection trace to service log") + ": " + displayText
            ToolTip.visible: hovered
            ToolTip.delay: 400
            ToolTip.text: block.root.tr(
                "settings.diagnostics.conn-trace.ndjson.tooltip",
                "Each observed connection is written to the service log: process, remote IP:port and egress interface (primary or additional adapter). Switches itself off when the chosen time runs out or the service restarts. Applies immediately.")
        }
    }
    Label {
        Layout.fillWidth: true
        Layout.preferredWidth: 0
        visible: block.root.supports("connTraceLog") && block.root.serviceConnTraceLogForced
        text: block.root.uiRevision >= 0
            ? block.root.tr(
                "settings.diagnostics.conn-trace.ndjson.forced-help",
                "Forced on by the service through {source}. Remove it, then restart the service to control this here again.")
                .replace("{source}", block.root.serviceConnTraceLogForcedBy)
            : ""
        color: block.root.uiTheme.colorAccent
        wrapMode: Text.WordWrap
        font.pixelSize: block.root.uiTheme.baseFontSizePx - 1
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }
    Timer {
        interval: 20000
        repeat: true
        running: block.visible && block.root.serviceConnTraceLogMode === "timed"
        triggeredOnStart: true
        onTriggered: {
            block._nowMs = Date.now()
            // The service ends the window at this same moment.
            if (block._nowMs >= block.root.serviceConnTraceLogUntilMs) {
                block.root.serviceConnTraceLogMode = "off"
                block.root.serviceConnTraceLogUntilMs = 0
            }
        }
    }
    CheckBox {
        text: block.root.tr(
            "settings.diagnostics.conn-trace.gui.label",
            "Show connection trace in Diagnostics")
        checked: block.guiChecked
        onToggled: {
            if (checked !== block.guiChecked) block.guiEdited(checked)
        }
        Accessible.name: text
        ToolTip.visible: hovered
        ToolTip.delay: 400
        ToolTip.text: block.root.tr(
            "settings.diagnostics.conn-trace.gui.tooltip",
            "Lets the connection-trace panel in Diagnostics show what was observed. Takes effect immediately, no service restart. Switching it off hides the panel's contents only — it does not stop observation, which app routing and rule suggestions rely on.")
    }
    Label {
        Layout.fillWidth: true
        Layout.leftMargin: block.root.uiTheme.spacingLg
        text: block.root.supports("connTraceLog")
            ? block.root.tr(
                "settings.diagnostics.conn-trace.help",
                "Privacy-sensitive: the trace carries per-connection process names and remote addresses. Writing it to disk is why it switches itself off; leave it off in normal operation.")
            : block.root.tr(
                "settings.diagnostics.conn-trace.help-no-log",
                "Privacy-sensitive: the trace carries per-connection process names and remote addresses. It is kept in memory only and is gone when the service restarts.")
        color: block.root.mutedTextColor
        wrapMode: Text.WordWrap
        font.pixelSize: block.root.uiTheme.baseFontSizePx - 1
    }
}
