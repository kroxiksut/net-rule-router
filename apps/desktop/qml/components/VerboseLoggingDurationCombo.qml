import QtQuick 2.15
import "../lib/pure.js" as Pure

// Verbose-logging option picker: the option list and wording
// (`Pure.VERBOSE_LOGGING_CHANGES`, `root.verboseLoggingChangeLabel`) shared
// between Settings -> Diagnostics and logs and the first-run wizard, so a
// second picker never drifts from the first. Callers still set
// `currentIndex`, `displayText`, `onActivated` and any tooltip/Accessible
// text themselves — this only carries the option list and label lookup.
ThemedComboBox {
    id: control
    property var root
    // Change slugs to offer, in display order. Defaults to every option
    // Settings offers ("off" included); a caller with its own on/off control
    // (the wizard checkbox) passes a subset without "off".
    property var options: Pure.VERBOSE_LOGGING_CHANGES

    model: options
    labelResolver: function(item) { return root ? root.verboseLoggingChangeLabel(item) : String(item) }
    popup.width: root ? root.comboPopupWidth(control, options, "",
        function(item) { return root.verboseLoggingChangeLabel(item) }) : implicitWidth
}
