import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import "../theme"

// First-launch service install dialog.
//
// Triggered from `Main.qml::Component.onCompleted` when:
//   - `!prefs.firstRunCompleted` (the global onboarding gate)
//   - AND `nrrServiceController.status === NotInstalled` (no service)
//   - AND `prefs.serviceInstallUacDeclinedCount < 3` (re-prompt budget)
//
// Order: this dialog fires FIRST. The preset
// wizard opens only AFTER this one closes — so the user sees install
// first, preset second (logical: without service, presets can't apply).
//
// Converted from QtQuick.Controls Dialog (popup overlay
// inside the parent ApplicationWindow) to a standalone Window so it
// matches the visual treatment of the preset wizard and other modal
// child windows. The previous popup form had no native title bar and
// felt out of place ("открылось не QT окно" feedback).
//
// All texts go through `root.tr(...)`. The signals decoupled from
// Main.qml so the caller routes the next step (preset wizard, UAC
// declined banner, etc.).
Window {
    id: root

    property var ownerRoot

    signal installRequested()
    signal skipRequested()
    signal learnMoreRequested()

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    // API-compatible with the previous Dialog form so call sites in
    // Main.qml (`firstLaunchInstallDialog.open()` / `.close()`) keep
    // working unchanged.
    function open() { visible = true }

    width: 760
    height: 360
    visible: false
    modality: Qt.WindowModal
    flags: Qt.Dialog
    color: ownerRoot ? ownerRoot.panelColor : "#202020"
    title: tr("dialog.first-launch-install.title", "Welcome to NetRuleRouter")
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
        anchors.margins: 18
        spacing: 14

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            text: root.tr("dialog.first-launch-install.body-1",
                "NetRuleRouter applies routing rules from a Windows background service so they persist across reboots and user sessions.")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            text: root.tr("dialog.first-launch-install.body-2",
                "Installing the service requires Administrator approval (UAC). After install, the service starts automatically.")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("dialog.first-launch-install.body-3",
                "You can skip this step and use NetRuleRouter in read-only preview mode, but routing rules will not apply.")
        }

        Item { Layout.fillHeight: true }

        // Action row wraps to two lines on narrow displays via Flow.
        Flow {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.first-launch-install.learn-more",
                    "Learn more")
                onClicked: { root.learnMoreRequested(); }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.first-launch-install.skip-button",
                    "Continue without service (limited)")
                onClicked: { root.skipRequested(); root.close() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.first-launch-install.install-button",
                    "Install and start service (recommended)")
                highlighted: true
                onClicked: { root.installRequested(); root.close() }
            }
        }
    }
}
