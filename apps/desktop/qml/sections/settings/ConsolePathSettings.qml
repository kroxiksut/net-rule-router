import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

// Settings -> Service management -> Command-line console.
//
// Offers, and never takes, the one change the console needs to be runnable by
// name: putting its folder on the user's own PATH. The state is read once when
// the panel is built so the button can say what it would actually do, and both
// actions are idempotent — clicking twice is harmless and reports that nothing
// needed doing.
//
// ONE button that flips, not two side by side: whichever of "add" and "remove"
// does not apply right now would be permanently greyed out, and a control that
// is never available is noise the user has to read past every time.
//
// Both operations are answered by the launcher, not the service: the store
// being read and written belongs to the signed-in user, and the service runs
// under a different account entirely.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.console.title", "Command-line console")
    Layout.fillWidth: true

    // Last known state from `local.console-path.*`. Two facts, because they
    // answer different questions and can legitimately disagree: `pathReachable`
    // is "would the name work in a new terminal" (the composed PATH, machine
    // entries included) and drives the status line; `ownedEntryPresent` is "is
    // OUR entry in the store WE write to" and drives the button. Driving the
    // button off reachability would make a successful removal look like a
    // failure on Unix, where this process keeps the PATH it inherited.
    property bool pathReachable: false
    property bool ownedEntryPresent: false

    /// The folder is reachable because of an entry we did not write — a distro
    /// package, another tool, or a line the user added by hand. There is
    /// nothing for either action to do, and pretending otherwise would leave
    /// the user clicking a button that changes nothing.
    readonly property bool reachableButNotOurs: group.pathReachable && !group.ownedEntryPresent
    property string consoleDirectory: ""
    property string currentSessionCommand: ""
    property string profileFile: ""

    // True while a state query or a registration is in flight.
    property bool busy: false

    // Set once a registration round-trip has come back, so the "your open
    // terminals still have the old PATH" hint appears in response to the user's
    // click rather than sitting there permanently.
    property bool showSessionHint: false

    // Outcome line rendered under the button. Empty until something happens.
    property string resultText: ""
    property bool resultIsError: false

    function _bridgeReady(method) {
        return root.bridgeAvailable
            && typeof nrrNativeBridge !== "undefined"
            && nrrNativeBridge !== null
            && typeof nrrNativeBridge[method] === "function"
    }

    function _applyState(payload) {
        if (!payload) return
        group.pathReachable = payload.reachable === true
        group.ownedEntryPresent = payload.ownedEntryPresent === true
        group.consoleDirectory = String(payload.directory || "")
        group.currentSessionCommand = String(payload.currentSessionCommand || "")
        group.profileFile = payload.targetFile ? String(payload.targetFile) : ""
    }

    // Read-only probe on panel load, so the button and the status line describe
    // the machine as it is before the user touches anything.
    function refreshState() {
        if (group.busy) return
        if (!group._bridgeReady("rpcConsolePathState")) return
        group.busy = true
        var corr = nrrNativeBridge.rpcConsolePathState()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            group.busy = false
            if (!ok) return
            group._applyState(payload)
        })
    }

    function removeFromPath() {
        if (group.busy) return
        if (!group._bridgeReady("rpcConsolePathUnregister")) {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        // Same reason as the add path: the response reports success either way,
        // so "we took it off" and "there was nothing of ours" are only
        // distinguishable from the state we held before the call.
        var wasPresent = group.ownedEntryPresent
        group.busy = true
        var corr = nrrNativeBridge.rpcConsolePathUnregister()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            group.busy = false
            if (!ok) {
                group.resultIsError = true
                group.resultText = root.tr("settings.console.path-remove-failed",
                    "Could not remove the console from your PATH.")
                    + " " + String(errorMessage || errorCode || "")
                root.statusLine = group.resultText
                return
            }
            group._applyState(payload)
            group.resultIsError = false
            group.resultText = wasPresent
                ? root.tr("settings.console.path-removed",
                    "The console was removed from your PATH.")
                : root.tr("settings.console.path-was-not-present",
                    "Nothing to remove — this entry was not put there by NetRuleRouter.")
            // No paste-this-line hint for a removal: a shell that already has
            // the directory cannot be cleaned up with one line, and offering
            // one that only half-works is worse than saying nothing.
            group.showSessionHint = false
            root.statusLine = group.resultText
        })
    }

    function addToPath() {
        if (group.busy) return
        if (!group._bridgeReady("rpcConsolePathRegister")) {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        // Remember what the machine looked like BEFORE the write: the response
        // always reports success, so this is the only way to tell "we added it"
        // from "it was already there".
        var wasRegistered = group.ownedEntryPresent
        group.busy = true
        var corr = nrrNativeBridge.rpcConsolePathRegister()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            group.busy = false
            if (!ok) {
                group.resultIsError = true
                group.resultText = root.tr("settings.console.path-failed",
                    "Could not add the console to your PATH.")
                    + " " + String(errorMessage || errorCode || "")
                root.statusLine = group.resultText
                return
            }
            group._applyState(payload)
            group.resultIsError = false
            group.resultText = wasRegistered
                ? root.tr("settings.console.path-already-present",
                    "The console was already on your PATH.")
                : root.tr("settings.console.path-added",
                    "The console was added to your PATH.")
            group.showSessionHint = true
            root.statusLine = group.resultText
        })
    }

    Component.onCompleted: Qt.callLater(group.refreshState)

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.console.description",
                "NetRuleRouter ships a small console for service tasks: install, start, stop and check the service. Add its folder to your PATH to run it as \"nrr-cli\" from any terminal.")
        }

        // Status line: is the console reachable by name today?
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingMd
            Rectangle {
                Layout.preferredWidth: 14
                Layout.preferredHeight: 14
                Layout.alignment: Qt.AlignTop
                radius: 7
                color: group.pathReachable ? "#2eb872" : "#d4a017"
            }
            Label {
                Layout.fillWidth: true
                color: root.textColor
                wrapMode: Text.WordWrap
                text: group.pathReachable
                    ? root.tr("settings.console.path-registered",
                        "The console can be run from any terminal.")
                    : root.tr("settings.console.path-not-registered",
                        "The console can only be run from its own folder — and in "
                        + "PowerShell you still have to spell it \".\\nrr-cli.exe\", "
                        + "because a bare name is not searched for in the current directory.")
            }
        }

        // Where the console actually lives — selectable so it can be pasted
        // into a terminal even without registering anything.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXxs
            visible: group.consoleDirectory.length > 0

            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                text: root.tr("settings.console.folder-label", "Console folder")
            }
            ThemedTextField {
                theme: root.uiTheme
                Layout.fillWidth: true
                readOnly: true
                selectByMouse: true
                text: group.consoleDirectory
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm

            ThemedButton {
                id: pathToggleButton
                theme: root.uiTheme
                text: group.ownedEntryPresent
                    ? root.tr("settings.console.remove-from-path", "Remove console from PATH")
                    : root.tr("settings.console.add-to-path", "Add console to PATH")
                icon.source: root.uiIconSource(group.ownedEntryPresent ? "clear" : "add")
                // Reachable but not ours: something else already puts the folder
                // on PATH, so adding would either duplicate the entry or write
                // nothing at all. Neither is worth a live button — the panel
                // says so in words instead.
                enabled: !group.busy && group.consoleDirectory.length > 0
                    && !group.reachableButNotOurs
                onClicked: group.ownedEntryPresent ? group.removeFromPath() : group.addToPath()
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: group.ownedEntryPresent
                    ? root.tr("settings.console.remove-from-path-tooltip",
                        "Removes the entry NetRuleRouter added to your personal PATH. Nothing else on the list is touched, and terminals that are already open keep the PATH they started with.")
                    : root.tr("settings.console.add-to-path-tooltip",
                        "Adds the console's folder to your personal PATH. It affects your account only, needs no administrator rights, and changes nothing else on the list.")
            }
            BusyIndicator {
                running: group.busy
                visible: group.busy
                Layout.preferredWidth: 20
                Layout.preferredHeight: 20
            }
            Item { Layout.fillWidth: true }
        }

        Label {
            Layout.fillWidth: true
            visible: group.reachableButNotOurs
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("settings.console.path-reachable-not-ours",
                "The folder is already on your PATH, but the entry was not added by NetRuleRouter — so there is nothing here to add or take away.")
        }

        Label {
            Layout.fillWidth: true
            visible: group.resultText.length > 0
            wrapMode: Text.WordWrap
            color: group.resultIsError ? "#c0392b" : root.textColor
            text: group.resultText
        }

        // No OS updates the environment of a process that is already running,
        // so the terminal the user has open right now still predates the
        // change. This closes that gap instead of leaving them to conclude the
        // button did nothing.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXxs
            visible: group.showSessionHint
                && group.currentSessionCommand.length > 0

            Label {
                Layout.fillWidth: true
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.console.new-terminal-hint",
                    "Terminals that are already open keep the PATH they started with. Open a new one, or run this line in the current one:")
            }
            ThemedTextField {
                theme: root.uiTheme
                Layout.fillWidth: true
                readOnly: true
                selectByMouse: true
                font.family: "Consolas, Courier New, monospace"
                text: group.currentSessionCommand
            }
            // Only hosts that register the PATH by appending to a shell profile
            // have a file to name; on a real per-user environment store there
            // is none, and the backend sends null rather than inventing one.
            Label {
                Layout.fillWidth: true
                visible: group.profileFile.length > 0
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                text: root.tr("settings.console.profile-file-hint",
                    "The line was added to %1.").arg(group.profileFile)
            }
        }
    }
}
