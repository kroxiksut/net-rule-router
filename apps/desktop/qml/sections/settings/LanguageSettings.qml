import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

GroupBox {
    property var root
    title: root.tr("settings.group.language", "Language")
    Layout.fillWidth: true
    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.group.language", "Language")
            color: root.textColor
            font.bold: true
        }
        ThemedComboBox {
            id: languageCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: root.availableLanguageIds()
            labelResolver: function(item) { return root.languageLabel(item) }
            displayText: root.uiRevision >= 0 && currentIndex >= 0
                ? root.languageLabel(model[currentIndex]) : ""
            currentIndex: Pure.optionIndexByValue(model, root.resolveLanguageId(root.prefs.language), 0)
            popup.width: root.comboPopupWidth(languageCombo, languageCombo.model, "",
                function(item) { return root.languageLabel(item) })
            onActivated: {
                var nextLanguage = root.resolveLanguageId(model[currentIndex])
                var nextPrimary = root.prefs.routePrimaryLabel === root.defaultRouteLabel("primary")
                    ? root.localeTextForLanguage(nextLanguage, "label.primary", "Primary")
                    : root.prefs.routePrimaryLabel
                var nextSecondary = root.prefs.routeSecondaryLabel === root.defaultRouteLabel("secondary")
                    ? root.localeTextForLanguage(nextLanguage, "label.secondary", "Secondary")
                    : root.prefs.routeSecondaryLabel
                root.updatePrefs({
                    language: nextLanguage,
                    routePrimaryLabel: nextPrimary,
                    routeSecondaryLabel: nextSecondary
                })
                // Persist before the tray restarts — it reads the language
                // fresh from disk on spawn, not from this process's memory.
                root.emitPrefs()
                root.restartTrayForLanguageChange()
                root.statusLine = root.tr("status.language-applied", "Interface language was updated.")
            }
        }
    }
}
