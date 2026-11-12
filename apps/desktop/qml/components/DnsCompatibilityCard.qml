import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

Rectangle {
    id: card
    property var root
    property bool compact: false
    property bool helpShown: false
    property bool detailsShown: false
    readonly property var state: root.dnsCompatibilityController.state
    readonly property var issues: state.issues || []
    readonly property var availableActions: state["available-actions"]
        || ["recheck", "browser-instructions", "check-secondary", "diagnose-site"]
    readonly property string status: String(state.status || "unchecked")
    visible: !compact || issues.length > 0 || status === "limited" || status === "needs-recheck"
    implicitHeight: visible ? body.implicitHeight + root.uiTheme.spacingSm * 2 : 0
    height: implicitHeight
    Layout.fillWidth: true
    radius: root.uiTheme.radiusSm
    color: root.uiTheme.colorPanel
    border.width: root.uiTheme.borderWidth
    border.color: root.uiTheme.colorFocusRing
    Accessible.role: Accessible.Grouping
    Accessible.name: title.text

    ColumnLayout {
        id: body
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: root.uiTheme.spacingSm
        spacing: root.uiTheme.spacingXs
        Label {
            id: title
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            color: root.textColor
            wrapMode: Text.WordWrap
            font.bold: true
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.title", "DNS compatibility")
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            color: root.textColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.status." + card.status,
                "DNS compatibility has not been verified.")
        }
        Repeater {
            model: card.compact ? [] : card.issues.slice(0, card.detailsShown ? 384 : 4)
            delegate: Label {
                required property var modelData
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                color: root.textColor
                wrapMode: Text.WordWrap
                maximumLineCount: 4
                elide: Text.ElideRight
                textFormat: Text.PlainText
                text: Pure.formatLogLine(root.tr("settings.routing.dns-compatibility.issue",
                    "{program}: {reason} ({evidence}). Attempts: {attempts}; first: {first}; last: {last}."),
                    root.tr("settings.routing.dns-compatibility.issue",
                        "{program}: {reason} ({evidence}). Attempts: {attempts}; first: {first}; last: {last}."), {
                    program: Pure.displayText(modelData.program),
                    reason: root.tr("settings.routing.dns-compatibility.reason." + String(modelData.reason || "unknown"),
                        "The cause has not been established"),
                    evidence: root.tr("settings.routing.dns-compatibility.evidence." + String(modelData.evidence || "suspected"),
                        "Needs verification"),
                    attempts: Number(modelData.attempts || 0),
                    first: Pure.formatTimestamp(modelData["first-seen-ms"]),
                    last: Pure.formatTimestamp(modelData["last-seen-ms"])
                }, [])
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: card.state["history-incomplete"] === true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.history-incomplete",
                "Some earlier DNS evidence is no longer available. Full recovery has not been verified; check affected sites individually.")
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact && !!card.state.resolver
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: {
                var resolver = card.state.resolver || {}
                function word(value) {
                    return root.tr("settings.routing.dns-compatibility.readiness." + String(value || "unchecked"), "Not checked")
                }
                return Pure.fillPlaceholders(root.tr("settings.routing.dns-compatibility.resolver",
                    "Our DNS listener: {listener}; system redirect: {redirect}; upstream DNS: {upstream}."), {
                    listener: word(resolver.listener), redirect: word(resolver.redirect), upstream: word(resolver.upstream)
                })
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact && card.state["last-checked-ms"] !== null
                && card.state["last-checked-ms"] !== undefined
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: Pure.fillPlaceholders(root.tr("settings.routing.dns-compatibility.checked-at", "Last check: {time}"), {
                time: Pure.formatTimestamp(card.state["last-checked-ms"])
            })
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: Pure.fillPlaceholders(root.tr("settings.routing.dns-compatibility.secondary-state",
                "Additional connection: {state}. This does not establish which connection a particular program requires."), {
                state: root.tr("settings.routing.dns-compatibility.readiness." + String(card.state["secondary-readiness"] || "unchecked"), "Not checked")
            })
        }
        Item {
            Layout.fillWidth: true
            implicitHeight: dnsActions.implicitHeight
            Flow {
                id: dnsActions
                anchors.left: parent.left
                anchors.right: parent.right
                spacing: root.uiTheme.spacingSm
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.retry", "Try again")
                    visible: card.availableActions.indexOf("recheck") >= 0
                    enabled: !root.dnsCompatibilityController.busy && card.state["recovery-pending"] !== true
                        && root._routingBackendConnected()
                    onClicked: root.dnsCompatibilityController.recheck()
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: card.compact || card.availableActions.indexOf("browser-instructions") >= 0
                    text: card.compact ? root.tr("action.open-settings", "Open settings")
                        : root.tr("settings.routing.dns-compatibility.browser-help", "Configure browser DNS")
                    onClicked: {
                        if (card.compact) root.openSettingsCategory("routing")
                        else card.helpShown = !card.helpShown
                    }
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: !card.compact && card.availableActions.indexOf("check-secondary") >= 0
                    text: root.tr("settings.routing.dns-compatibility.check-secondary", "Check additional connection")
                    onClicked: root.requestSectionChange("interfaces-routes")
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: !card.compact && card.availableActions.indexOf("diagnose-site") >= 0
                    text: root.tr("diag.site-check.run", "Check site")
                    onClicked: root.notificationsController.openSiteCheckInDiagnostics()
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: !card.compact && card.issues.length > 4
                    text: card.detailsShown ? root.tr("action.hide-details", "Hide details")
                        : root.tr("action.show-details", "Show details")
                    onClicked: card.detailsShown = !card.detailsShown
                }
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: card.state["recovery-pending"] === true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.checking", "Checking DNS; your routing rules remain in force.")
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact && card.helpShown
            color: root.textColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.browser-instructions",
                "Chrome/Chromium: Settings → Privacy and security → Security → turn off Use secure DNS. Edge: find Secure DNS in Settings and use system DNS. Firefox: Settings → Privacy & Security → DNS over HTTPS → Off. If your organization controls this setting, contact its administrator; do not override its policy. Reload the affected site, then check again. Keep the additional-route rule and leak protection enabled.")
        }
        Repeater {
            model: !card.compact && card.helpShown ? (card.state["browser-settings"] || []).slice(0, 3) : []
            delegate: Label {
                required property var modelData
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                color: root.textColor
                wrapMode: Text.WordWrap
                textFormat: Text.PlainText
                text: Pure.fillPlaceholders(root.tr("settings.routing.dns-compatibility.browser-setting",
                    "{browser}: saved DNS mode: {mode}; policy: {policy}; settings: {source}."), {
                    browser: root.tr("settings.routing.dns-compatibility.browser-name." + String(modelData.browser), "Browser"),
                    mode: root.tr("settings.routing.dns-compatibility.browser-mode." + String(modelData["configured-mode"]), "Could not determine"),
                    policy: root.tr("settings.routing.dns-compatibility.browser-policy." + String(modelData.policy), "Management status could not be verified"),
                    source: root.tr("settings.routing.dns-compatibility.browser-source." + String(modelData.source), "Could not read settings")
                })
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact && card.helpShown
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.browser-read-only",
                "Saved preferences do not prove the running browser's effective DNS mode. Automatic changes are unavailable when policy and profile ownership cannot be verified. Follow the instructions, reload the site, and check again; organization policies remain under your administrator's control.")
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.tr("settings.routing.dns-compatibility.verification-note",
                "A successful system DNS query does not prove that this browser has recovered. The problem stays visible until fresh browser evidence confirms recovery.")
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: !card.compact && card.helpShown
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            text: root.supports("fakeIp") ? root.tr("settings.routing.dns-compatibility.verify-site",
                "Choose Check site and start a check for the affected host, then open or reload that host in the affected browser within a minute. A fresh browser connection through the additional route can confirm recovery. Direct or reused connections may remain unverified; the site-check report is separate.")
                : root.tr("settings.routing.dns-compatibility.browser-verification-unavailable",
                    "This platform cannot confirm the browser's own successful connection yet. Use Check site for a report through the assigned route; a successful system query or service probe does not certify the browser.")
        }
    }
}
