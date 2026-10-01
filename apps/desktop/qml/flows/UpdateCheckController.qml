import QtQuick 2.15

// The Help menu's "Check for updates". The launcher asks the release page now,
// whatever the daily-check switch says: the user asked. Progress and verdict go
// to the status line, and a newer release raises the same notice the daily
// check does.
QtObject {
    id: updateCheckController

    /// The ApplicationWindow: status line, translations and the RPC transport.
    property var root

    property bool inFlight: false

    // Until the user checks, the daily check's cached verdict from the launch
    // context stands; after, the fresher answer replaces it.
    property bool _manualAnswered: false
    property var _manualOffer: null

    /// `{latestVersion, url}` of a newer release, or `null`.
    readonly property var offer: _manualAnswered
        ? _manualOffer
        : (((root && root.context) || {}).updateCheck || null)

    function checkNow() {
        if (inFlight) {
            root.statusLine = root.tr("status.update-check-running", "Checking for updates…")
            return
        }
        var corr = root.rpc.rpcUpdateCheckRun()
        if (!corr) {
            root.statusLine = root.tr("status.update-check-failed",
                "Could not check for updates: the release page did not answer. Check your internet connection and try again.")
            return
        }
        inFlight = true
        root.statusLine = root.tr("status.update-check-running", "Checking for updates…")
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            inFlight = false
            if (!ok || !payload) {
                console.log("local.update-check.run failed:", code, msg)
                root.statusLine = root.tr("status.update-check-failed",
                    "Could not check for updates: the release page did not answer. Check your internet connection and try again.")
                return
            }
            if (payload.status === "update-available") {
                _manualOffer = {
                    "latestVersion": String(payload.latestVersion || ""),
                    "url": String(payload.url || "")
                }
                _manualAnswered = true
                root.statusLine = root.tr("notifications.update-available.title",
                    "A new version is available")
                return
            }
            _manualOffer = null
            _manualAnswered = true
            root.statusLine = root.tr("status.update-check-up-to-date",
                "You have the latest version ({version}).")
                .replace("{version}", String(payload.currentVersion || ""))
        })
    }
}
