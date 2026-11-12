import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

Frame {
    id: panel
    property var root
    property var episodes: []
    property var limitations: []
    property real omitted: 0
    property bool expanded: false

    function probeDetails(episode) {
        var e = episode || {}
        var q = Pure.discoveryProbeQueue(e["probe-queue"])
        if (!q) return ""
        var details = panel.root.tr(q.kind === "rules"
            ? "rules.suggestions.episode.reason.rules-unavailable"
            : "rules.suggestions.episode.queue.wait." + q.kind,
            panel.root.tr("rules.suggestions.episode.reason-unknown", "No further detail is available."))
        details += "\n" + panel.root.tr("rules.suggestions.episode.queue.ahead", "Your queued checks ahead: {count}.")
            .replace("{count}", String(q.ahead))
        if (q.seconds !== null)
            details += "\n" + panel.root.tr("rules.suggestions.episode.queue.pause", "Pause before another check: at least {seconds} s.")
                .replace("{seconds}", String(q.seconds))
        details += "\n" + panel.root.tr("rules.suggestions.episode.queue.snapshot",
            "At the last update. This is not a start or completion estimate.")
        if (q.started !== null)
            details += "\n" + panel.root.tr("rules.suggestions.episode.queue.started", "Last check started: {time}.")
                .replace("{time}", Pure.formatTimestamp(q.started))
        var previous = Pure.discoveryPreviousProbe(e.history)
        if (previous) {
            var result = panel.root.tr("rules.suggestions.episode.reason." + previous.reason,
                panel.root.tr("rules.suggestions.episode.reason-unknown", "No further detail is available."))
            details += "\n" + panel.root.tr("rules.suggestions.episode.queue.previous", "Retained check result at {time}: {result}")
                .replace("{time}", Pure.formatTimestamp(previous["at-unix-ms"]))
                .replace("{result}", result)
        } else {
            details += "\n" + panel.root.tr("rules.suggestions.episode.queue.previous-absent",
                "No previous check result is retained in this history.")
        }
        return details
    }
    Layout.fillWidth: true
    Layout.preferredWidth: 0
    background: Rectangle {
        color: panel.root.uiTheme.colorPanel
        border.color: panel.root.uiTheme.colorBorder
        border.width: panel.root.uiTheme.borderWidth
        radius: panel.root.uiTheme.radiusMd
    }

    contentItem: ColumnLayout {
        spacing: panel.root.uiTheme.spacingSm

        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: panel.root.textColor
            text: panel.root.tr("rules.suggestions.episode.title", "Why no site suggestion?")
            Accessible.role: Accessible.Heading
        }

        RowLayout {
            Layout.fillWidth: true
            ThemedTextField {
                id: enteredHost
                theme: panel.root.uiTheme
                Layout.fillWidth: true
                Layout.minimumWidth: 0
                maximumLength: 253
                placeholderText: panel.root.tr("rules.suggestions.episode.enter-host", "Enter a site domain")
                Accessible.name: placeholderText
                onAccepted: if (text.trim() !== "" && panel.root.bridgeAvailable)
                    panel.root.notificationsController.checkSiteInDiagnostics(text.trim())
            }
            ThemedButton {
                theme: panel.root.uiTheme
                text: panel.root.tr("diag.conn-trace.check-site", "Check site…")
                enabled: panel.root.bridgeAvailable && enteredHost.text.trim() !== ""
                Accessible.name: text
                onClicked: panel.root.notificationsController.checkSiteInDiagnostics(enteredHost.text.trim())
            }
        }

        ThemedButton {
            theme: panel.root.uiTheme
            text: panel.expanded ? panel.root.tr("action.hide-details", "Hide details")
                : panel.root.tr("action.show-details", "Show details")
            checkable: true
            checked: panel.expanded
            Accessible.name: text
            onClicked: panel.expanded = checked
        }

        ScrollView {
            id: panelScroll
            visible: panel.expanded
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(320, Math.max(100, panel.root.height * 0.35), episodeBody.implicitHeight)
            contentWidth: availableWidth
            clip: true

            ColumnLayout {
                id: episodeBody
                width: panelScroll.availableWidth
                spacing: panel.root.uiTheme.spacingSm

                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.Wrap
                    textFormat: Text.PlainText
                    color: panel.root.mutedTextColor
                    text: panel.root.tr("rules.suggestions.episode.intro",
                        "Recent decisions for your connections. A TCP or TLS response alone does not prove that a page loaded. You can check a domain even when its name was not observed.")
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }

                Label {
                    visible: panel.episodes.length === 0
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.Wrap
                    textFormat: Text.PlainText
                    color: panel.root.mutedTextColor
                    text: panel.root.tr("rules.suggestions.episode.empty",
                        "No recent discovery evidence is available. This does not establish whether the site works. Enter its domain to check it.")
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }

                Repeater {
                    model: panel.limitations
                    delegate: Label {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 0
                        wrapMode: Text.Wrap
                        textFormat: Text.PlainText
                        color: panel.root.mutedTextColor
                        text: panel.root.tr("rules.suggestions.episode.limitation." + String(modelData),
                            panel.root.tr("rules.suggestions.episode.limitation-unknown", "An observation capability is unavailable on this platform."))
                        Accessible.role: Accessible.StaticText
                        Accessible.name: text
                    }
                }

                Repeater {
                    model: panel.episodes
                    delegate: Label {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 0
                        wrapMode: Text.Wrap
                        textFormat: Text.PlainText
                        color: panel.root.textColor
                        text: {
                            var e = modelData || {}
                            var name = e.host || e.destination || panel.root.tr(
                                "rules.suggestions.episode.unknown-host", "Site name unknown")
                            var state = panel.root.tr("rules.suggestions.episode.state." + String(e.state || ""),
                                panel.root.tr("rules.suggestions.episode.state-unknown", "State unavailable"))
                            var reason = panel.root.tr("rules.suggestions.episode.reason." + String(e.reason || ""),
                                panel.root.tr("rules.suggestions.episode.reason-unknown", "No further detail is available."))
                            var line = Pure.displayText(name) + " · " + state + "\n" + reason
                            var probe = panel.probeDetails(e)
                            if (probe) line += "\n" + probe
                            if (e["platform-limitation"])
                                line += "\n" + panel.root.tr("rules.suggestions.episode.limitation." + e["platform-limitation"],
                                    panel.root.tr("rules.suggestions.episode.limitation-unknown", "An observation capability is unavailable on this platform."))
                            return line
                        }
                        Accessible.role: Accessible.StaticText
                        Accessible.name: text
                    }
                }

                Label {
                    visible: panel.omitted > 0
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.Wrap
                    color: panel.root.mutedTextColor
                    text: panel.root.tr("rules.suggestions.episode.omitted", "{count} older episodes are no longer retained.")
                        .replace("{count}", String(panel.omitted))
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }
            }
        }
    }
}
