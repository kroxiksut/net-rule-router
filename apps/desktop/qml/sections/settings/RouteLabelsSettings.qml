import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

GroupBox {
    property var root
    title: root.tr("settings.group.route-labels", "Connection names")
    Layout.fillWidth: true
    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.note.route-labels",
                "You can rename both connections here — the names are only shown in the program and change nothing else.")
            color: root.mutedTextColor
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.field.route-primary-label", "Main connection name")
            color: root.textColor
        }
        ThemedTextField {
            accessibleLabel: root.tr("settings.field.route-primary-label", "Main connection name")
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.prefs.routePrimaryLabel
            placeholderText: root.defaultRouteLabel("primary")
            onEditingFinished: root.updatePrefs({
                routePrimaryLabel: text.trim() === root.defaultRouteLabel("primary") ? "" : text.trim()
            })
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.field.route-secondary-label", "Additional connection name")
            color: root.textColor
        }
        ThemedTextField {
            accessibleLabel: root.tr("settings.field.route-secondary-label", "Additional connection name")
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.prefs.routeSecondaryLabel
            placeholderText: root.defaultRouteLabel("secondary")
            onEditingFinished: root.updatePrefs({
                routeSecondaryLabel: text.trim() === root.defaultRouteLabel("secondary") ? "" : text.trim()
            })
        }
    }
}
