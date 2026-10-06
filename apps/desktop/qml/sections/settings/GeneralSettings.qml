import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

GroupBox {
    id: group
    property var root
    title: root.tr("settings.group.general", "General")
    Layout.fillWidth: true
    // Label for the file↔service merge conflict-policy combo.
    function _mergeConflictPolicyLabel(slug) {
        switch (String(slug)) {
            case "file-wins":
                return root.tr("settings.general.merge-conflict.file-wins",
                    "File wins (prefer the linked file)")
            case "service-wins":
                return root.tr("settings.general.merge-conflict.service-wins",
                    "Service wins (prefer the active rules)")
            default:
                return root.tr("settings.general.merge-conflict.union",
                    "Ask me (resolve each conflict)")
        }
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("action.launch-on-startup", "Launch window on startup")
            checked: root.prefs.launchWindowOnStartup
            onToggled: root.updatePrefs({ launchWindowOnStartup: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("action.minimize-to-tray", "Minimize to tray instead of close")
            checked: root.prefs.minimizeToTrayInsteadOfClose
            onToggled: root.updatePrefs({ minimizeToTrayInsteadOfClose: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.field.reopen-last-section", "Open last section on startup")
            checked: root.prefs.reopenLastSectionOnStartup
            onToggled: root.updatePrefs({ reopenLastSectionOnStartup: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.field.auto-confirm-adapter-id",
                "Auto-confirm a reinstalled additional adapter when its name matches")
            checked: root.prefs.autoConfirmAdapterIdChange !== false
            onToggled: root.updatePrefs({ autoConfirmAdapterIdChange: checked })
            ToolTip.visible: hovered
            ToolTip.text: root.tr("settings.field.auto-confirm-adapter-id-tooltip",
                "When an additional adapter is reinstalled and gets a new ID, re-bind it automatically if the saved name uniquely matches a live adapter. Turn off to confirm each change manually via the banner.")
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // Autostart toggle. The state comes from the launcher's probe of the
        // user's own registry, carried in the initial snapshot.
        CheckBox {
            id: autostartCheckbox
            Layout.fillWidth: true
            text: root.tr("settings.general.autostart.label",
                "Start NetRuleRouter tray automatically at sign-in")
            checked: (root.uiRevision >= 0)
                ? (root.routingState.autostartEnabled === true) : false
            onToggled: root.setAutostartEnabled(checked)
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.general.autostart.description",
                "Adds an entry under HKEY_CURRENT_USER\\…\\Run that launches the tray icon.")
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            color: {
                var slug = (root.uiRevision >= 0)
                    ? String(root.routingState.autostartLastKnownState || "absent") : "absent"
                return slug === "overridden-externally"
                    ? root.uiTheme.colorWarning : root.mutedTextColor
            }
            text: {
                var slug = (root.uiRevision >= 0)
                    ? String(root.routingState.autostartLastKnownState || "absent") : "absent"
                if (slug === "enabled")
                    return root.tr("settings.general.autostart.state.enabled", "Enabled")
                if (slug === "disabled")
                    return root.tr("settings.general.autostart.state.disabled", "Disabled")
                if (slug === "overridden-externally")
                    return root.tr("settings.general.autostart.state.overridden",
                        "Registry value points to another binary — toggle to repair.")
                return root.tr("settings.general.autostart.state.absent", "No autostart entry.")
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // Manual re-trigger for the cold-start
        // onboarding (install dialog → preset wizard). Resets
        // `firstRunCompleted` and the UAC decline budget, then opens
        // whichever dialog the cold-start gate would choose.
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: false
            text: root.tr("settings.general.show-welcome.label",
                "Show welcome wizard again...")
            onClicked: root.restartFirstRunFlow()
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.general.show-welcome.description",
                "Re-runs the first-launch flow: service install prompt (if not yet installed) and then the preset wizard. Useful when you want to import a different starter rule set.")
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // Rules auto-load on launch.
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.general.autoload.title", "Auto-load rules on startup")
            color: root.textColor
            font.bold: true
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.general.autoload.label",
                "Load rules from the last-used files automatically at startup")
            // Default ON: undefined (older context) is treated as enabled.
            checked: root.prefs.autoLoadRulesOnLaunch !== false
            onToggled: root.updatePrefs({ autoLoadRulesOnLaunch: checked })
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.general.autoload.description",
                "When off, NetRuleRouter shows whatever the service already has and does not re-read the files on launch. The remembered file paths are kept.")
        }
        // File↔service merge conflict-resolution policy. Governs
        // how the merge dialog resolves rules present on both sides but with a
        // different route / enabled state / action / comment.
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.general.merge-conflict.title",
                "Merging file and app rules")
            color: root.textColor
            font.bold: true
        }
        ThemedComboBox {
            id: mergeConflictCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: [ "union", "file-wins", "service-wins" ]
            labelResolver: function(item) { return group._mergeConflictPolicyLabel(item) }
            displayText: root.uiRevision >= 0 && currentIndex >= 0
                ? group._mergeConflictPolicyLabel(model[currentIndex]) : ""
            currentIndex: Pure.optionIndexByValue(model, root.prefs.mergeConflictPolicy, 0)
            popup.width: root.comboPopupWidth(mergeConflictCombo, mergeConflictCombo.model, "",
                function(item) { return group._mergeConflictPolicyLabel(item) })
            onActivated: root.updatePrefs({ mergeConflictPolicy: model[currentIndex] })
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.general.merge-conflict.description",
                "When you merge a linked rules file with the rules the app is already enforcing, this decides who wins for a rule that exists on both sides but differs. \"Ask me\" keeps both and lets you pick per rule; \"File wins\" / \"Service wins\" resolve automatically.")
        }
        // Import-only-active toggle: skip rules disabled in the source preset
        // (e.g. application rules left off pending per-process routing).
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.general.import-only-active.title", "Importing presets")
            color: root.textColor
            font.bold: true
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.general.import-only-active.label",
                "Import only active rules")
            // Default ON: undefined (older context) is treated as enabled.
            checked: root.prefs.importOnlyActive !== false
            onToggled: root.updatePrefs({ importOnlyActive: checked })
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.general.import-only-active.description",
                "When on, rules that are turned off in the imported preset (for example application rules, which can't route yet) are skipped instead of added as disabled rows. Turn off to import everything.")
        }
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: false
            // Only meaningful when a binding exists (save target OR the
            // display-only source record); disabling avoids a no-op click +
            // confusing toast.
            enabled: String(root.prefs.lastSavedPathPrimary || "") !== ""
                || String(root.prefs.lastSavedPathSecondary || "") !== ""
                || String(root.prefs.lastLoadedPathPrimary || "") !== ""
                || String(root.prefs.lastLoadedPathSecondary || "") !== ""
            text: root.tr("settings.general.forget-binding.label",
                "Forget file binding")
            onClicked: root.forgetFileBindings()
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.general.forget-binding.description",
                "Clears the remembered rules file paths. The next launch loads nothing from disk — you see exactly what the service has.")
        }

    }
}
