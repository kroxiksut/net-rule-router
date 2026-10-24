import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

// The app's version and when the GUI warns that it and the service disagree
// about it. Not part of the release check: it works with no network at all.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.group.version-compat", "Version and compatibility")
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

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm

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
            accessibleLabel: root.uiRevision >= 0 ? root.tr("settings.updates.compat-banner-mode.label", "Compatibility banner") : ""
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
