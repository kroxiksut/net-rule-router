import QtQuick 2.15

// Non-visual controller: after a (re)connect, the settings panels re-read what
// the service holds. The service's own settings are machine-wide: after a loss
// they come back from the service's own backup, never from one user's file, so
// nothing is compared or written back from here.
//
// `serviceIntentReplayed` stays a signal ON THE WINDOW: two settings panels
// listen for it next to unrelated shell signals.
QtObject {
    id: serviceIntentController

    /// The ApplicationWindow, which carries the signal.
    property var root

    function replayServiceIntentToService() {
        root.serviceIntentReplayed()
    }
}
