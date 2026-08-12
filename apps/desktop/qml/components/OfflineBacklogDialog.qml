// One question for everything that piled up while the background service was
// stopped.
//
// Rules and routing settings are parked by two independent mechanisms, and
// each used to ask the user on its own — two modal dialogs a second apart,
// about the same interruption. This dialog renders whichever halves are
// non-empty and offers one decision for both:
//
//   Apply all — push the rules currently in the table through the ordinary
//               review/activate flow AND apply the parked settings.
//   Discard   — stop offering. Rules stay in the table, settings revert to
//               whatever the service holds; nothing on screen is destroyed.
//   Later     — close and ask again on the next connect.
//
// The rules half is described by counts computed against the LIVE service
// revision, and "Preview" diffs the CURRENT table — never a snapshot frozen at
// park time, which is how a preview could end up showing nothing while a rule
// was demonstrably missing.
//
// Dumb dialog: it renders and emits. Every read, diff and apply lives in the
// window. Shared state arrives through `ownerRoot` — never implicit scope.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null

    /// Rules half. `rulesPending` gates the whole block; the counts are
    /// current-table vs live-service.
    property bool rulesPending: false
    property int rulesAdded: 0
    property int rulesRemoved: 0

    /// Settings half: `{ label, value }` rows, pre-filtered by the caller so
    /// only genuinely different values are listed.
    property var settingsRows: []

    signal applyAllRequested()
    signal discardAllRequested()
    signal laterRequested()
    signal previewRulesRequested()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _rulesSummary() {
        return tr("dialog.offline-backlog.rules-summary",
            "Rules: {added} added, {removed} removed")
            .replace("{added}", String(dialog.rulesAdded))
            .replace("{removed}", String(dialog.rulesRemoved))
    }

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: Math.max(520, footerRow.implicitWidth + 2 * dialog.padding)
    padding: ownerRoot ? ownerRoot.uiTheme.spacingLg : 16
    title: tr("dialog.offline-backlog.title",
        "Changes made while the service was stopped")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    // Esc / any close without a choice means "ask me again", never a silent
    // drop of parked work.
    onRejected: laterRequested()

    background: Rectangle {
        color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.colorPanel : "transparent"
        border.width: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.borderWidth : 0
        border.color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.stateDefaultBorder : "transparent"
        radius: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.radiusSm : 0
    }

    contentItem: ColumnLayout {
        spacing: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.spacingMd : 12

        Label {
            Layout.fillWidth: true
            Layout.maximumWidth: 620
            wrapMode: Text.Wrap
            color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
            text: dialog.tr("dialog.offline-backlog.body",
                "The service is running again. These changes were made while it was "
                + "stopped and are not in effect yet.")
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        // Rules half.
        RowLayout {
            Layout.fillWidth: true
            Layout.maximumWidth: 620
            visible: dialog.rulesPending
            spacing: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.spacingSm : 8
            Rectangle {
                Layout.preferredWidth: 6
                Layout.preferredHeight: 6
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 6
                radius: 3
                color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.colorAccent : "#888"
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                text: dialog._rulesSummary()
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.offline-backlog.preview", "Preview")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.offline-backlog.preview-description",
                    "Show what would change in the service; nothing is applied.")
                onClicked: dialog.previewRulesRequested()
            }
        }

        // Settings half: one "<setting>: <value>" row each.
        ColumnLayout {
            Layout.fillWidth: true
            Layout.maximumWidth: 620
            spacing: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.spacingXs : 4
            Repeater {
                model: dialog.settingsRows
                delegate: RowLayout {
                    Layout.fillWidth: true
                    spacing: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.spacingSm : 8
                    Rectangle {
                        Layout.preferredWidth: 6
                        Layout.preferredHeight: 6
                        Layout.alignment: Qt.AlignTop
                        Layout.topMargin: 6
                        radius: 3
                        color: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.colorAccent : "#888"
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: dialog.ownerRoot ? dialog.ownerRoot.textColor : palette.text
                        text: dialog.tr("dialog.offline-pending.row", "{setting}: {value}")
                            .replace("{setting}", String(modelData.label || ""))
                            .replace("{value}", String(modelData.value || ""))
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.maximumWidth: 620
            wrapMode: Text.Wrap
            font.pixelSize: 12
            color: dialog.ownerRoot ? dialog.ownerRoot.mutedTextColor : palette.text
            text: dialog.tr("dialog.offline-backlog.discard-hint",
                "Discarding only stops the offer — the rules stay in the table and "
                + "nothing on screen is lost.")
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        RowLayout {
            id: footerRow
            Layout.fillWidth: true
            spacing: dialog.ownerRoot ? dialog.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.offline-backlog.discard", "Discard")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { dialog.close(); dialog.discardAllRequested() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.offline-backlog.later", "Later")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: dialog.tr(
                    "dialog.offline-backlog.later-description",
                    "Keep the changes pending and ask again next time the service connects.")
                onClicked: { dialog.close(); dialog.laterRequested() }
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                highlighted: true
                text: dialog.tr("dialog.offline-backlog.apply-all", "Apply all")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { dialog.close(); dialog.applyAllRequested() }
            }
        }
    }
}
