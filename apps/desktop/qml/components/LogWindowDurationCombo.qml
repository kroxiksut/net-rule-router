import QtQuick 2.15
import "../lib/pure.js" as Pure

// Duration picker for a log window that closes by itself — verbose logging,
// the connection trace on disk. One option list (`Pure.LOG_WINDOW_CHANGES`)
// for every window, so no picker drifts from another; `labelFor` supplies the
// window's own wording. Callers still set `currentIndex`, `displayText`,
// `onActivated` and any tooltip/Accessible text themselves.
ThemedComboBox {
    id: control
    property var root
    // Change slugs to offer, in display order. Defaults to every option ("off"
    // included); a caller with its own on/off control (the wizard checkbox)
    // passes a subset without "off".
    property var options: Pure.LOG_WINDOW_CHANGES
    // Change slug -> label in this window's wording; the slug when unset.
    property var labelFor: null

    function _label(change) {
        return (typeof labelFor === "function") ? labelFor(change) : String(change)
    }

    model: options
    labelResolver: function(item) { return control._label(item) }
    popup.width: root ? root.comboPopupWidth(control, options, "",
        function(item) { return control._label(item) }) : implicitWidth
}
