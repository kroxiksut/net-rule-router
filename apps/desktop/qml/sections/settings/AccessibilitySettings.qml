import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

GroupBox {
    property var root
    title: root.tr("settings.group.accessibility", "Accessibility")
    Layout.fillWidth: true
    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("a11y.high-contrast", "High contrast")
            checked: root.prefs.themeMode === "high-contrast"
            onToggled: root.updatePrefs({
                themeMode: checked ? "high-contrast"
                    : (root.prefs.themeMode === "high-contrast" ? "system" : root.prefs.themeMode)
            })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("a11y.enhanced-focus", "Enhanced focus")
            checked: root.prefs.enhancedFocus
            onToggled: root.updatePrefs({ enhancedFocus: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("a11y.simplified-labels", "Simplified labels")
            checked: root.prefs.simplifiedLabels
            onToggled: root.updatePrefs({ simplifiedLabels: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.field.tooltips", "Enable tooltips")
            checked: root.prefs.tooltipsEnabled
            onToggled: root.updatePrefs({ tooltipsEnabled: checked })
        }
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.field.system-font", "System font")
            color: root.mutedTextColor
        }
        ThemedComboBox {
            id: systemFontCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: [ "system-default", "segoe-ui", "arial", "tahoma", "verdana" ]
            currentIndex: Pure.optionIndexByValue(model, root.prefs.systemFont, 0)
            function fontLabel(id) {
                return root.tr("settings.system-font.option-" + id, id)
            }
            labelResolver: function(item) { return systemFontCombo.fontLabel(item) }
            displayText: root.uiRevision >= 0 && currentIndex >= 0
                ? fontLabel(model[currentIndex]) : ""
            popup.width: root.comboPopupWidth(systemFontCombo, model, "",
                function(item) { return systemFontCombo.fontLabel(item) })
            onActivated: root.updatePrefs({ systemFont: model[currentIndex] })
        }
    }
}
