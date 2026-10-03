import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Connection-egress trace switches: write the trace to the service NDJSON,
// show it in Diagnostics. Off by default — privacy-sensitive. Drawn inside the
// stability card where the service applies the whole row, in a card of its own
// where it applies only these; the caller owns the drafts and the save.
ColumnLayout {
    id: block

    /// The ApplicationWindow: `tr()`, theme, colours and `supports()`.
    property var root
    property bool ndjsonChecked: false
    property bool guiChecked: false

    signal ndjsonEdited(bool value)
    signal guiEdited(bool value)

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
    // disk copy or a second switch.
    Label {
        Layout.fillWidth: true
        text: block.root.supports("connTraceLog")
            ? block.root.tr(
                "settings.diagnostics.conn-trace.intro",
                "Records outgoing connections of all apps and the interface each left through (direct vs the additional adapter). Sees the real socket, so it works even when the browser uses DoH. Observation itself is always on — these two switches decide where it is shown and whether it is written down.")
            : block.root.tr(
                "settings.diagnostics.conn-trace.intro-no-log",
                "Shows outgoing connections of all apps and the interface each left through (direct vs the additional adapter). Sees the real socket, so it works even when the browser uses DoH. Observation itself is always on — this switch decides whether it is shown. On this platform the trace is never written to disk.")
        color: block.root.mutedTextColor
        wrapMode: Text.WordWrap
        font.pixelSize: block.root.uiTheme.baseFontSizePx - 1
    }
    CheckBox {
        // Hidden where the service has no disk sink for the trace.
        visible: block.root.supports("connTraceLog")
        text: block.root.tr(
            "settings.diagnostics.conn-trace.ndjson.label",
            "Write connection trace to service log (NDJSON)")
        checked: block.ndjsonChecked
        onToggled: {
            if (checked !== block.ndjsonChecked) block.ndjsonEdited(checked)
        }
        Accessible.name: text
        ToolTip.visible: hovered
        ToolTip.delay: 400
        ToolTip.text: block.root.tr(
            "settings.diagnostics.conn-trace.ndjson.tooltip",
            "Each observed connection is written to the operational NDJSON: process, remote IP:port, and egress interface (primary or additional adapter). Takes effect immediately, no service restart.")
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
                "Privacy-sensitive: the trace carries per-connection process names and remote addresses. Writing it to disk is the part worth leaving off in normal operation.")
            : block.root.tr(
                "settings.diagnostics.conn-trace.help-no-log",
                "Privacy-sensitive: the trace carries per-connection process names and remote addresses. It is kept in memory only and is gone when the service restarts.")
        color: block.root.mutedTextColor
        wrapMode: Text.WordWrap
        font.pixelSize: block.root.uiTheme.baseFontSizePx - 1
    }
}
