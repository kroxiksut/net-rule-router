import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

// "Is it us or the site?" The service checks the site's names over the user's
// own routes and says what it found; this panel starts the check, follows it
// until it is done and offers the step the verdict calls for. Callers hand it
// a site via `check()`.
Frame {
    id: panel
    property var root
    Layout.fillWidth: true
    padding: root.uiTheme.spacingMd - root.uiTheme.spacingXxs
    background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }

    property string _host: ""
    property bool _running: false
    property string _errorCode: ""
    // The latest finished report (`SiteCheckReport`), or null.
    property var _report: null
    // How long the panel follows one check before saying it took too long.
    readonly property int _followMs: 30000
    property double _startedAt: 0
    // Set while the rule window opened from here is up.
    property bool _movePending: false

    function check(host) {
        hostInput.text = String(host || "").trim()
        _run()
    }

    function _run() {
        var host = hostInput.text.trim()
        _report = null
        _errorCode = ""
        if (host === "") {
            _errorCode = "input-required"
            return
        }
        if (!root.rpc || typeof root.rpc.rpcSiteCheckRun !== "function") {
            _errorCode = "bridge-unavailable"
            return
        }
        var corr = root.rpc.rpcSiteCheckRun(host)
        if (!corr) {
            _errorCode = "bridge-unavailable"
            return
        }
        _running = true
        _host = host
        _startedAt = Date.now()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode) {
            if (!ok) {
                panel._running = false
                panel._errorCode = String(errorCode || "unknown")
                return
            }
            panel._host = String((payload && payload.host) || panel._host)
            followTimer.restart()
        })
    }

    function _poll() {
        if (Date.now() - _startedAt > _followMs) {
            _running = false
            _errorCode = "timeout"
            return
        }
        var corr = root.rpc.rpcSiteCheckResult()
        if (!corr) {
            _running = false
            _errorCode = "bridge-unavailable"
            return
        }
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode) {
            if (!panel._running) return
            if (!ok) {
                panel._running = false
                panel._errorCode = String(errorCode || "unknown")
                return
            }
            if (String((payload && payload.state) || "") === "done" && payload.report) {
                panel._running = false
                panel._report = payload.report
                return
            }
            followTimer.restart()
        })
    }

    Timer {
        id: followTimer
        interval: 700
        repeat: false
        onTriggered: panel._poll()
    }

    readonly property string _verdict: _report ? String(_report.verdict || "") : ""

    function _routeText(route) {
        if (route === "blocked") return root.tr("label.block", "Denied")
        return root.routeLabel(route === "secondary" ? "secondary" : "primary")
    }
    function _nameLine(n) {
        var parts = [Pure.displayText(String(n.name || ""))
            + " (" + root.tr("diag.site-check.role." + n.role, String(n.role || "")) + ")"]
        parts.push(String(n.address || "") !== "" ? String(n.address)
            : root.tr("diag.site-check.no-address", "address not known: not opened lately"))
        parts.push(_routeText(String(n.route || "")))
        parts.push(root.tr("diag.site-check.answer." + n.answer, String(n.answer || "")))
        var line = parts.join(" · ")
        if (n.status !== undefined && n.status !== null)
            line += " · " + root.tr("diag.site-check.status", "answer {code}")
                .replace("{code}", String(n.status))
        var hops = n.redirects || []
        if (hops.length > 0) {
            line += " · " + root.tr("diag.site-check.redirects", "sends on to {hosts}")
                .replace("{hosts}", hops.map(function (h) { return Pure.displayText(h) }).join(" → "))
        }
        return line
    }

    function _moveSignIn() {
        if (!_report || !root.ruleDialog) return
        _movePending = true
        root.ruleDialog.resetForMoving(_report["move-names"] || [],
            String(_report["site-route"] || "primary"))
        root.ruleDialog.open()
    }
    Connections {
        target: root.ruleDialog
        function onAccepted() {
            if (!panel._movePending) return
            panel._movePending = false
            // Added to the list, not applied yet: the user finishes in Rules.
            root.section = "rules"
        }
        function onRejected() { panel._movePending = false }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: root.uiTheme.spacingSm - root.uiTheme.spacingXxs
        Label {
            text: root.tr("diag.site-check.title", "Check a site")
            color: root.textColor
            font.bold: true
            Accessible.role: Accessible.Heading
        }
        Label {
            Layout.fillWidth: true
            text: root.tr("diag.site-check.subtitle",
                "Is it the network or the site? The site's names are checked over your routes: their address, the route your rules give them, and whether they answer there. Runs only when you ask.")
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedTextField {
                id: hostInput
                theme: root.uiTheme
                Layout.fillWidth: true
                placeholderText: root.tr("diag.site-check.placeholder", "site name, e.g. example.com")
                Accessible.name: root.tr("diag.site-check.title", "Check a site")
                enabled: !panel._running
                onAccepted: panel._run()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("diag.site-check.run", "Check site")
                enabled: !panel._running
                onClicked: panel._run()
            }
        }
        Label {
            Layout.fillWidth: true
            visible: panel._running
            text: root.tr("diag.site-check.running", "Checking {host}…")
                .replace("{host}", Pure.displayText(panel._host))
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
        }
        Label {
            Layout.fillWidth: true
            visible: !panel._running && panel._errorCode !== ""
            text: {
                var code = panel._errorCode
                if (code === "input-required")
                    return root.tr("diag.site-check.input-required", "Enter a site name to check")
                if (code === "bridge-unavailable")
                    return root.tr("diag.explain.bridge-unavailable",
                        "Service bridge not connected — probe unavailable")
                return root.tr("diag.site-check.failed", "Could not check the site: ")
                    + ((typeof root.ipcErrorLabel === "function") ? root.ipcErrorLabel(code) : code)
            }
            color: root.uiTheme.colorAccent
            wrapMode: Text.WordWrap
        }
        // The verdict, then what to do about it.
        Label {
            Layout.fillWidth: true
            visible: !panel._running && panel._verdict !== ""
            text: root.tr("diag.site-check.verdict." + panel._verdict + ".title", panel._verdict)
            color: panel._verdict === "fine" ? root.uiTheme.colorSuccess : root.uiTheme.colorWarning
            font.bold: true
            wrapMode: Text.WordWrap
        }
        Label {
            Layout.fillWidth: true
            visible: !panel._running && panel._verdict !== ""
            text: root.tr("diag.site-check.verdict." + panel._verdict + ".body", "")
            color: root.textColor
            wrapMode: Text.WordWrap
        }
        Repeater {
            model: (!panel._running && panel._report) ? (panel._report.names || []) : []
            delegate: Label {
                Layout.fillWidth: true
                text: panel._nameLine(modelData)
                color: root.textColor
                wrapMode: Text.WordWrap
            }
        }
        // (a): the network is fine, so what is left lives in the browser.
        ColumnLayout {
            Layout.fillWidth: true
            visible: !panel._running && panel._verdict === "fine"
            spacing: root.uiTheme.spacingXxs
            Label {
                Layout.fillWidth: true
                text: root.tr("diag.site-check.cookies.title",
                    "If the site still loops or will not let you sign in, delete its cookies in the browser:")
                color: root.textColor
                wrapMode: Text.WordWrap
            }
            Repeater {
                model: ["chrome", "edge", "firefox"]
                delegate: Label {
                    Layout.fillWidth: true
                    text: root.tr("diag.site-check.cookies." + modelData, "")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }
            Label {
                Layout.fillWidth: true
                text: root.tr("diag.site-check.cookies.note",
                    "NetRuleRouter never reads or changes browser data.")
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
            }
        }
        // (b): bring the sign-in to the site's route, through the rule window.
        ThemedButton {
            theme: root.uiTheme
            visible: !panel._running && panel._verdict === "sign-in-split"
                && ((panel._report || {})["move-names"] || []).length > 0
            text: root.tr("diag.site-check.move", "Move the sign-in names to the site's route…")
            onClicked: panel._moveSignIn()
        }
        // (c): the site does not answer where it is routed; the trace shows
        // what its connections did.
        ThemedButton {
            theme: root.uiTheme
            visible: !panel._running
                && (panel._verdict === "not-answering" || panel._verdict === "route-down")
            text: root.sectionTitle("conn-trace")
            onClicked: root.section = "conn-trace"
        }
    }
}
