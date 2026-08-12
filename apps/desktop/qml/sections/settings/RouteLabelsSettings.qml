import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"

GroupBox {
    property var root
    title: root.tr("settings.group.route-labels", "Route names")
    Layout.fillWidth: true
    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.note.route-labels",
                "You can rename the two routes for the UI without changing routing behavior.")
            color: root.mutedTextColor
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.field.route-primary-label", "Primary route name")
            color: root.textColor
        }
        ThemedTextField {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.prefs.routePrimaryLabel
            placeholderText: root.defaultRouteLabel("primary")
            onEditingFinished: root.updatePrefs({
                routePrimaryLabel: text.trim() !== "" ? text.trim() : root.defaultRouteLabel("primary")
            })
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.field.route-secondary-label", "Secondary route name")
            color: root.textColor
        }
        ThemedTextField {
            theme: root.uiTheme
            Layout.fillWidth: true
            text: root.prefs.routeSecondaryLabel
            placeholderText: root.defaultRouteLabel("secondary")
            onEditingFinished: root.updatePrefs({
                routeSecondaryLabel: text.trim() !== "" ? text.trim() : root.defaultRouteLabel("secondary")
            })
        }
    }
}
