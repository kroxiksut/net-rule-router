import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

GroupBox {
    id: group
    property var root
    title: root.tr("settings.group.updates", "Check for updates")
    Layout.fillWidth: true

    // Resolve a compat-banner-mode slug to a
    // localized label for the dropdown.
    function _compatModeLabel(mode) {
        switch (String(mode)) {
            case "always":
                return root.tr("settings.updates.compat-banner-mode.option-always", "Always show")
            case "never":
                return root.tr("settings.updates.compat-banner-mode.option-never", "Never show")
            default:
                return root.tr("settings.updates.compat-banner-mode.option-auto",
                    "Show on mismatch (automatic)")
        }
    }

    function _intervalLabel(days) {
        return root.tr("settings.updates.auto-check.every-days", "Every {days} days")
            .replace("{days}", String(days))
    }

    readonly property var _intervalChoices: (root.context && root.context.updateCheckIntervalChoices)
        || [14]

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm

        CheckBox {
            id: updateCheckBox
            Layout.fillWidth: true
            onToggled: root.updatePrefs({ updateCheckEnabled: checked })
            // A `checked:` binding dies on the first click; this one keeps
            // following prefs through Cancel and "restore defaults".
            Binding {
                target: updateCheckBox
                property: "checked"
                value: root.uiRevision >= 0 ? root.prefs.updateCheckEnabled !== false : true
            }
            text: root.tr("settings.updates.auto-check.label",
                "Check for a new version automatically")
            contentItem: Text {
                text: updateCheckBox.text
                leftPadding: updateCheckBox.indicator.width + updateCheckBox.spacing
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                color: root.textColor
            }
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            Accessible.description: updateCheckDescription.text
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            spacing: root.uiTheme.spacingSm
            Label {
                id: intervalLabel
                text: root.tr("settings.updates.auto-check.interval", "How often")
                color: updateCheckBox.checked ? root.textColor : root.mutedTextColor
            }
            ThemedComboBox {
                id: intervalCombo
                theme: root.uiTheme
                Layout.fillWidth: true
                enabled: updateCheckBox.checked
                model: group._intervalChoices
                labelResolver: function(item) { return group._intervalLabel(item) }
                displayText: root.uiRevision >= 0 && currentIndex >= 0
                    ? group._intervalLabel(model[currentIndex]) : ""
                // Same as the checkbox: keeps following prefs through Cancel
                // and "restore defaults" after the first pick.
                Binding {
                    target: intervalCombo
                    property: "currentIndex"
                    value: root.uiRevision >= 0
                        ? Pure.optionIndexByValue(group._intervalChoices,
                            Number(root.prefs.updateCheckIntervalDays),
                            Math.max(0, group._intervalChoices.indexOf(14)))
                        : 0
                }
                popup.width: root.comboPopupWidth(intervalCombo, intervalCombo.model, "",
                    function(item) { return group._intervalLabel(item) })
                onActivated: root.updatePrefs({ updateCheckIntervalDays: model[currentIndex] })
                Accessible.name: intervalLabel.text
            }
        }
        Label {
            id: updateCheckDescription
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.updates.auto-check.description",
                "The app asks the project's release page on GitHub whether a newer version is out and shows a notice if it is. Nothing is downloaded or installed, and routing is not touched. The count starts at the first start and restarts after every check, including one from the Help menu. Turned off, the app sends no such request. Takes effect at the next start.")
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("label.version", "Version") + ": "
                + ((root.context.about || {}).version || "n/a")
            color: root.textColor
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // ── Compatibility banner visibility ──────────────────────────
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.updates.compat-banner-mode.label",
                "Compatibility banner")
            color: root.textColor
            font.bold: true
        }
        ThemedComboBox {
            id: compatModeCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: [ "auto", "always", "never" ]
            labelResolver: function(item) { return group._compatModeLabel(item) }
            displayText: root.uiRevision >= 0 && currentIndex >= 0
                ? group._compatModeLabel(model[currentIndex]) : ""
            currentIndex: Pure.optionIndexByValue(model, root.prefs.compatBannerMode, 0)
            popup.width: root.comboPopupWidth(compatModeCombo, compatModeCombo.model, "",
                function(item) { return group._compatModeLabel(item) })
            onActivated: root.updatePrefs({ compatBannerMode: model[currentIndex] })
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.updates.compat-banner-mode.description",
                "Controls when the GUI shows the version-mismatch banner. \"Automatic\" only warns on an incompatible protocol.")
        }
    }
}
