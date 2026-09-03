// Full-reset confirmation. Strong destructive confirm — an acknowledgement
// checkbox gates the action. Extracted from Main.qml (thin-shell
// refactor). The dialog is "dumb": it emits
// `confirmed()` and the caller runs `fullResetController.fullReset()`. Shared state
// comes in through `ownerRoot` (the ApplicationWindow), never implicit scope.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Fired when the user acknowledges + confirms; the caller runs the reset.
    /// `allPrincipals` is true when the user chose to clear every OS user's
    /// routing, not just their own.
    signal confirmed(bool allPrincipals)

    /// Acknowledgement state; reset on every open so the destructive button
    /// always starts disabled.
    property bool _ack: false

    /// How many OTHER users the service holds rules for, answered by
    /// `principal-data.count` on open. Zero (or unknown) keeps the dialog the
    /// single-user question it has always been.
    property int otherPrincipals: 0
    /// The chosen scope. Defaults to "mine": erasing another account's routing
    /// is never the safe reading of "reset".
    property bool _allPrincipals: false

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    title: tr("dialog.full-reset.title", "Full reset")
    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 480
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    onOpened: {
        _ack = false
        _allPrincipals = false
        otherPrincipals = 0
        if (ownerRoot && ownerRoot.fullResetController) {
            ownerRoot.fullResetController.countOtherPrincipals(function(count) { root.otherPrincipals = count })
        }
    }
    contentItem: ColumnLayout {
        spacing: 12
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.full-reset.body",
                "This resets ALL application settings to defaults, clears the rules "
                + "applied by the service (back to an empty post-install state), and "
                + "wipes saved comments and logs. The Windows service is NOT "
                + "uninstalled. This cannot be undone.")
        }
        // Only asked when someone else's routing is actually stored here.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            visible: root.otherPrincipals > 0
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
                text: root.tr("dialog.full-reset.other-users",
                    "Other users of this computer have rules here too ({count}). What should be cleared?")
                    .replace("{count}", String(root.otherPrincipals))
            }
            // A click writes `checked`, which destroys a plain binding to it.
            // On a destructive dialog that is not cosmetic: the pair then shows
            // one scope while `confirmed(scope)` sends the other, so the reset
            // that runs is not the one the user read.
            ThemedRadioButton {
                id: scopeMineRadio
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                Binding {
                    target: scopeMineRadio
                    property: "checked"
                    value: !root._allPrincipals
                }
                text: root.tr("dialog.full-reset.scope-mine", "Only my data")
                onToggled: if (checked) root._allPrincipals = false
            }
            ThemedRadioButton {
                id: scopeEveryoneRadio
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                Binding {
                    target: scopeEveryoneRadio
                    property: "checked"
                    value: root._allPrincipals
                }
                text: root.tr("dialog.full-reset.scope-everyone",
                    "Every user on this computer (asks for administrator approval)")
                onToggled: if (checked) root._allPrincipals = true
            }
        }
        CheckBox {
            id: fullResetAck
            Layout.fillWidth: true
            Binding {
                target: fullResetAck
                property: "checked"
                value: root._ack
            }
            onToggled: root._ack = checked
            text: root.tr("dialog.full-reset.ack",
                "I understand this erases all settings and applied rules")
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.full-reset.cancel", "Cancel")
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("dialog.full-reset.confirm", "Reset everything")
                highlighted: true
                enabled: root._ack
                onClicked: {
                    var scope = root._allPrincipals
                    root.close()
                    root.confirmed(scope)
                }
            }
        }
    }
}
