// Confirm dialog: the background service is enforcing ZERO rules, so loading
// its state would WIPE every rule currently shown in the GUI.
// added after a HW test where "Show the rules the service is applying" against
// a freshly-wiped service silently cleared the whole rule list. Like the sibling
// ReloadFromServiceConfirmDialog this is a "dumb" dialog: it emits `confirmed()`
// and Main.qml re-runs the (now user-approved) reload. Shared state comes in
// through `ownerRoot` (the ApplicationWindow) — never via implicit scope.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// How many rules the GUI currently holds — shown in the warning body so the
    /// user knows exactly what is about to be cleared.
    property int pendingRuleCount: 0
    /// Fired when the user confirms; caller clears the model and loads the
    /// (empty) service state.
    signal confirmed()
    /// Non-destructive alternative: push the GUI's current rules
    /// TO the empty service instead of clearing them. Fired when the user picks
    /// "Apply application state" here, so they don't have to Cancel and re-open
    /// the drift banner. Caller runs the review/apply flow and does NOT clear.
    signal applyAppStateRequested()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    // Grow past the 460 baseline whenever the single footer row
    // needs more room, so all three buttons always fit unclipped even with the
    // longer RU labels. Content area = width - 2*padding, hence the +2*padding.
    width: Math.max(460, footerRow.implicitWidth + 2 * root.padding)
    // Breathing room around the body text and footer; the 0-rules
    // warning read cramped against the panel border.
    padding: ownerRoot ? ownerRoot.uiTheme.spacingLg : 16
    title: tr("dialog.empty-service-rules.title",
        "The service has no active rules")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    background: Rectangle {
        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "transparent"
        border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 0
        border.color: root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "transparent"
        radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 0
    }
    contentItem: ColumnLayout {
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingMd : 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.empty-service-rules.body",
                "The background service is currently enforcing 0 rules. Loading "
                + "its state will remove all {count} rule(s) shown here. Your "
                + "rules files on disk are not touched. Continue?")
                .replace("{count}", String(root.pendingRuleCount))
        }
        // Classic single-row dialog footer (option "Б"): the
        // destructive "Clear the rules" sits alone on the LEFT, a fillWidth
        // spacer pushes the affirmative pair (Cancel + the highlighted, safe
        // "Apply application state" default) to the RIGHT. The row's implicitWidth
        // drives the adaptive dialog width above so nothing ever clips, even with
        // the long RU labels. The apply button is only offered when the GUI
        // actually holds rules to apply.
        RowLayout {
            id: footerRow
            Layout.fillWidth: true
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.empty-service-rules.confirm",
                    "Clear the rules")
                onClicked: { root.close(); root.confirmed() }
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                visible: root.pendingRuleCount > 0
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                highlighted: true
                text: root.tr("dialog.drift.apply-gui",
                    "Apply application state")
                onClicked: { root.close(); root.applyAppStateRequested() }
            }
        }
    }
}
