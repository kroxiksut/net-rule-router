// Notifications centre popup. Themed in-overlay popup
// anchored to the bottom-right, opened by the footer bell chip. Renders the
// window-scoped `activeNotifications` list (the SSOT built in Main.qml) and
// routes each notice's action / dismissal back through the owner window. This
// replaces the former amber "app rules not enforced" top banner, which the
// user found too heavy for a low-priority notice.
//
// Mirrors StartupLogPopup's shape: shared state comes in through `ownerRoot`
// (the ApplicationWindow); the notice list is read from
// `ownerRoot.activeNotifications` (a plain JS array — delegates use modelData).
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Popup {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    readonly property var _theme: ownerRoot ? ownerRoot.uiTheme : null
    readonly property var _notifications: ownerRoot ? ownerRoot.activeNotifications : []

    popupType: Popup.Item
    modal: false
    focus: true
    width: 460
    // Grow with the number of notices, capped; each card is variable height so
    // this is an estimate sized for a comfortable single-notice view — the inner
    // ListView scrolls if the real content overflows (clip + AsNeeded scrollbar).
    height: Math.min(460, 84 + Math.max(1, _notifications.length) * 150)
    x: parent ? Math.max(_theme ? _theme.spacingMd : 12,
        parent.width - width - (_theme ? _theme.spacingMd : 12)) : 0
    y: parent ? Math.max(_theme ? _theme.spacingMd : 12,
        parent.height - height - (_theme ? _theme.spacingMd : 12)) : 0
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
    background: PanelSurface {
        theme: root._theme
        cornerRadius: root._theme ? root._theme.radiusMd : 8
    }

    // Auto-close when the last notice clears (e.g. the user launches the app and
    // the enforcement gap resolves, or dismisses the only notice) so a stale
    // empty popup doesn't linger open.
    Connections {
        target: root.ownerRoot
        function onActiveNotificationsChanged() {
            if (root.visible && root._notifications.length === 0) {
                root.close()
            }
        }
    }

    contentItem: ColumnLayout {
        spacing: root._theme ? root._theme.spacingSm : 8
        RowLayout {
            Layout.fillWidth: true
            spacing: root._theme ? root._theme.spacingSm : 8
            Label {
                Layout.fillWidth: true
                text: root.tr("notifications.title", "Notifications")
                font.bold: true
                color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            }
            ThemedButton {
                id: dismissAllButton
                theme: root._theme
                // Hidden once there is nothing left to clear: an empty list,
                // or a list made only of state-mirroring notices (see the
                // per-card Dismiss button's own comment on `dismissible`).
                visible: root._notifications.some(function (n) {
                    return n.dismissible !== false
                })
                text: root.tr("notifications.dismiss-all", "Dismiss all")
                Accessible.role: Accessible.Button
                Accessible.name: text
                ToolTip.visible: hovered && root.ownerRoot && root.ownerRoot.prefs.tooltipsEnabled
                ToolTip.text: root.tr("notifications.dismiss-all-tooltip",
                    "Removes every notice that can be dismissed. Ones that mirror a live state stay until the state itself changes.")
                onClicked: {
                    if (!root.ownerRoot) return
                    // Snapshot the ids before dismissing: dismissNotification
                    // mutates the same array we're reading, so walking it live
                    // would skip every other entry as the list shifts under us.
                    var ids = []
                    for (var i = 0; i < root._notifications.length; i++) {
                        if (root._notifications[i].dismissible !== false) {
                            ids.push(root._notifications[i].id)
                        }
                    }
                    for (var j = 0; j < ids.length; j++) {
                        root.ownerRoot.dismissNotification(ids[j])
                    }
                }
            }
        }
        Label {
            Layout.fillWidth: true
            visible: root._notifications.length === 0
            text: root.tr("notifications.empty", "No notifications.")
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
        }
        ListView {
            id: view
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: root._notifications.length > 0
            clip: true
            model: root._notifications
            spacing: root._theme ? root._theme.spacingSm : 8
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            delegate: Rectangle {
                id: card
                required property var modelData
                width: view.width
                implicitHeight: cardRow.implicitHeight
                    + (root._theme ? root._theme.spacingSm : 8) * 2
                radius: root._theme ? root._theme.radiusSm : 4
                readonly property bool warn: card.modelData.severity === "warning"
                color: root._theme ? root._theme.stateDefaultFill : "transparent"
                border.width: root._theme ? root._theme.borderWidth : 1
                border.color: card.warn && root._theme
                    ? Qt.rgba(root._theme.colorWarning.r, root._theme.colorWarning.g,
                        root._theme.colorWarning.b, 0.55)
                    : (root._theme ? root._theme.stateDefaultBorder : "gray")
                RowLayout {
                    id: cardRow
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: root._theme ? root._theme.spacingSm : 8
                    spacing: root._theme ? root._theme.spacingSm : 8
                    Rectangle {
                        Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4
                        Layout.alignment: Qt.AlignTop
                        Layout.topMargin: 4
                        color: card.warn && root._theme
                            ? root._theme.colorWarning
                            : (root._theme ? root._theme.colorAccent : "gray")
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: root._theme ? root._theme.spacingXs : 4
                        Label {
                            Layout.fillWidth: true
                            text: card.modelData.title || ""
                            font.bold: true
                            wrapMode: Text.Wrap
                            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
                        }
                        Label {
                            Layout.fillWidth: true
                            text: card.modelData.body || ""
                            // Most notices are free-form strings (hostnames,
                            // adapter names) that must render as plain text;
                            // only a notice that opts in with `bodyRichText`
                            // gets its embedded `<b>` markup interpreted.
                            textFormat: card.modelData.bodyRichText === true
                                ? Text.StyledText : Text.PlainText
                            wrapMode: Text.Wrap
                            font.pixelSize: 12
                            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
                            Accessible.role: Accessible.StaticText
                            // Screen readers get plain text — strip the styling tags used for visual emphasis.
                            Accessible.name: card.modelData.bodyRichText === true
                                ? text.replace(/<\/?[a-z]+>/gi, "") : text
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Layout.topMargin: root._theme ? root._theme.spacingXxs : 2
                            spacing: root._theme ? root._theme.spacingSm : 8
                            Item { Layout.fillWidth: true }
                            ThemedButton {
                                theme: root._theme
                                visible: !!card.modelData.actionText
                                text: card.modelData.actionText || ""
                                onClicked: {
                                    if (root.ownerRoot) {
                                        root.ownerRoot.runNotificationAction(card.modelData.actionKey)
                                    }
                                    root.close()
                                }
                            }
                            // "Stop showing these" for notices that carry a
                            // mutable kind. Offered on the notice itself so
                            // silencing a stripe never requires hunting for the
                            // setting it lives in.
                            ThemedButton {
                                theme: root._theme
                                visible: !!card.modelData.muteKind
                                text: root.tr("notifications.mute-kind",
                                    "Stop showing these")
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                onClicked: {
                                    if (root.ownerRoot) {
                                        root.ownerRoot.muteNoticeKind(card.modelData.muteKind)
                                        root.ownerRoot.dismissNotification(card.modelData.id)
                                    }
                                }
                            }
                            ThemedButton {
                                theme: root._theme
                                // A non-dismissible notice (dismissible === false)
                                // mirrors a live state and can only be cleared by
                                // resolving it (e.g. turning off strict kill-switch);
                                // omit its Dismiss button. Undefined ⇒ dismissible.
                                visible: card.modelData.dismissible !== false
                                text: root.tr("notifications.dismiss", "Dismiss")
                                onClicked: {
                                    if (root.ownerRoot) {
                                        root.ownerRoot.dismissNotification(card.modelData.id)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
