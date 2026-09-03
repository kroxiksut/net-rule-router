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

        // Locale files that did not load cleanly. A defect inside one file no
        // longer costs the whole language — the affected keys fall back to
        // English and the rest of the file is used — so the user needs to be
        // told which file and which key, here, where the language is chosen.
        ColumnLayout {
            id: localeDiagnosticsBlock
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXxs

            // Reports worth showing: anything that was not accepted cleanly.
            readonly property var problemReports: {
                var out = []
                var reports = (root.localeDiagnostics || {}).reports || []
                for (var i = 0; i < reports.length; i += 1) {
                    var r = reports[i] || {}
                    var warnings = r.warnings || []
                    var errors = r.errors || []
                    if (warnings.length > 0 || errors.length > 0) out.push(r)
                }
                return out
            }
            property bool expanded: false

            visible: root.uiRevision >= 0 && problemReports.length > 0

            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    text: root.tr("settings.language.diagnostics-summary",
                        "%1 locale file(s) reported problems. The affected keys fall back to English; everything else in the file is used.")
                        .arg(localeDiagnosticsBlock.problemReports.length)
                }
                ThemedButton {
                    theme: root.uiTheme
                    flat: true
                    text: localeDiagnosticsBlock.expanded
                        ? root.tr("settings.routing.show-less", "Hide details")
                        : root.tr("settings.routing.show-more", "Show details")
                    onClicked: localeDiagnosticsBlock.expanded = !localeDiagnosticsBlock.expanded
                }
            }

            Repeater {
                model: localeDiagnosticsBlock.expanded
                    ? localeDiagnosticsBlock.problemReports : []
                delegate: ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: root.textColor
                        font.bold: true
                        text: String(modelData.fileName || modelData.id || "")
                    }
                    Repeater {
                        model: (modelData.errors || []).concat(modelData.warnings || [])
                        delegate: Label {
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            color: root.mutedTextColor
                            text: "— " + String(modelData)
                        }
                    }
                }
            }
        }
    }
}
