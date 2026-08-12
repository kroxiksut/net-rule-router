// Confirm dialog for an additional (secondary) adapter that cannot carry
// traffic out -- typically a host-only virtual NIC (VirtualBox, VMware,
// Hyper-V internal) with no gateway and no default route.
//
// Picking such an adapter is allowed: the dialog states plainly what breaks and
// then honours whatever the user answers. It never blocks the choice and never
// weakens leak protection on the user's behalf.
//
// Two directions, selected by `contextSlug`:
//   "assign"      -- the user is about to bind this adapter as the additional
//                    route.
//   "kill-switch" -- the user is about to arm leak protection while such an
//                    adapter is already bound.
//
// The dialog is "dumb": it emits `confirmed()` / `cancelled()` and the caller
// owns the action. Shared state arrives through `ownerRoot` (the
// ApplicationWindow) -- never via implicit scope.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    /// Display name of the offending adapter.
    property string adapterName: ""
    /// Reason slug from `Pure.unroutableInterfaceReasonSlug`:
    /// "virtual-host-only" | "no-forwarding-path".
    property string reasonSlug: ""
    /// "assign" | "kill-switch".
    property string contextSlug: "assign"
    /// Whether leak protection is armed right now (only read in the "assign"
    /// direction, where it decides between "not routed" and "blocked").
    property bool killSwitchArmed: false
    /// Callbacks the opener parks here; the opener invokes them on the signals.
    property var pendingAction: null
    property var pendingCancelAction: null

    signal confirmed()
    signal cancelled()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    readonly property string _reasonText: reasonSlug === "virtual-host-only"
        ? tr("dialog.unroutable-secondary.reason-virtual-host-only",
            "It looks like a host-only virtual adapter (VirtualBox, VMware or Hyper-V internal) and it has no gateway, so it has no way out to the network.")
        : tr("dialog.unroutable-secondary.reason-no-forwarding-path",
            "It has no gateway and no route out, so there is nowhere for it to send traffic.")

    readonly property string _situationText: contextSlug === "kill-switch"
        ? tr("dialog.unroutable-secondary.body-kill-switch",
            "It is currently assigned as your additional route.")
        : tr("dialog.unroutable-secondary.body-assign",
            "You are about to assign it as your additional route.")

    readonly property string _killSwitchText: contextSlug === "kill-switch"
        ? tr("dialog.unroutable-secondary.effect-kill-switch-arming",
            "Once leak protection is on, those destinations are BLOCKED instead: the sites behind those rules stop loading.")
        : (killSwitchArmed
            ? tr("dialog.unroutable-secondary.effect-kill-switch-on",
                "Leak protection is on, so those destinations are BLOCKED instead: the sites behind those rules stop loading.")
            : tr("dialog.unroutable-secondary.effect-kill-switch-off",
                "Leak protection is off right now, so nothing is blocked. If you turn it on later, those destinations will be blocked."))

    modal: true
    popupType: Popup.Item
    anchors.centerIn: parent
    width: 520
    title: tr("dialog.unroutable-secondary.title",
        "This adapter cannot carry traffic out")
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    background: Rectangle {
        color: root.ownerRoot ? root.ownerRoot.uiTheme.colorPanel : "transparent"
        border.width: root.ownerRoot ? root.ownerRoot.uiTheme.borderWidth : 0
        border.color: root.ownerRoot ? root.ownerRoot.uiTheme.stateDefaultBorder : "transparent"
        radius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 0
    }
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    onRejected: root.cancelled()

    contentItem: ColumnLayout {
        spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8

        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            font.bold: true
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.unroutable-secondary.adapter-line",
                "Adapter: {name}").replace("{name}", root.adapterName)
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root._situationText + " " + root._reasonText
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("dialog.unroutable-secondary.effect-routing",
                "Rules that point at the additional route will not be routed through it.")
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            color: root.ownerRoot
                ? root.ownerRoot.uiTheme.colorWarning
                : palette.text
            text: root._killSwitchText
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        RowLayout {
            Layout.alignment: Qt.AlignRight
            Layout.topMargin: root.ownerRoot ? root.ownerRoot.uiTheme.spacingXs : 4
            spacing: root.ownerRoot ? root.ownerRoot.uiTheme.spacingSm : 8
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.unroutable-secondary.cancel-description",
                    "Leave everything as it is")
                onClicked: { root.close(); root.cancelled() }
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                highlighted: true
                text: root.contextSlug === "kill-switch"
                    ? root.tr("dialog.unroutable-secondary.confirm-kill-switch",
                        "Turn it on anyway")
                    : root.tr("dialog.unroutable-secondary.confirm-assign",
                        "Assign anyway")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { root.close(); root.confirmed() }
            }
        }
    }
}
