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

    // ── Block-notice mutes ───────────────────────────────────────────────
    //
    // The service owns mute state per-SID (block-notices.mutes.*); this
    // panel is the only surface where a mute can be created with a
    // caller-chosen duration — the toast that offers a quick mute is
    // limited to four fixed presets.
    property var _blockNoticeMutes: []
    property bool _blockNoticeMutesLoading: false

    function _blockNoticeMuteScopeLabel(mute) {
        var scope = (mute && mute.scope) || {}
        var kind = String(scope.kind || "all")
        if (kind === "host")
            return root.tr("settings.block-notices.mutes.row-host", "Host: {name}")
                .replace("{name}", String(scope.host || ""))
        if (kind === "app")
            return root.tr("settings.block-notices.mutes.row-app", "Application: {name}")
                .replace("{name}", String(scope.app || ""))
        if (kind === "reason")
            return root.tr("settings.block-notices.mutes.row-reason", "Reason: {name}")
                .replace("{name}", root.tr("block-reason." + String(scope.reason || ""),
                    String(scope.reason || "")))
        return root.tr("settings.block-notices.mutes.row-all",
            "All blocked-connection notices")
    }
    function _blockNoticeMuteUntilLabel(mute) {
        var until = Number((mute && mute.untilUnixMs) || 0)
        if (!(until > 0)) return root.tr("settings.block-notices.forever", "Forever")
        return root.tr("settings.block-notices.mutes.until-timestamp", "Until {timestamp}")
            .replace("{timestamp}", Qt.formatDateTime(new Date(until), "yyyy-MM-dd HH:mm"))
    }
    function _normalizeBlockNoticeMutes(list) {
        var arr = []
        for (var i = 0; i < (list || []).length; i += 1) {
            var raw = list[i] || {}
            arr.push({
                "scope": raw.scope || { "kind": "all" },
                "untilUnixMs": Number(raw["until-unix-ms"] || 0)
            })
        }
        return arr
    }
    function _loadBlockNoticeMutes() {
        if (group._blockNoticeMutesLoading || !root.bridgeAvailable) return
        var corr = root.rpc.rpcBlockNoticeMutesList()
        if (!corr) return
        group._blockNoticeMutesLoading = true
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            group._blockNoticeMutesLoading = false
            if (!ok) {
                root.statusLine = root.tr("settings.block-notices.mutes.load-failed",
                    "Could not load the mute list: ") + String(msg || code || "")
                return
            }
            group._blockNoticeMutes = group._normalizeBlockNoticeMutes((p && p.mutes) || [])
        })
    }
    function _removeBlockNoticeMute(mute) {
        if (!root.bridgeAvailable) return
        var corr = root.rpc.rpcBlockNoticeMutesRemove({ "scope": mute.scope })
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("settings.block-notices.mutes.remove-failed",
                    "Could not remove the mute: ") + String(msg || code || "")
                return
            }
            group._blockNoticeMutes = group._normalizeBlockNoticeMutes((p && p.mutes) || [])
        })
    }
    function _clearBlockNoticeMutes() {
        if (!root.bridgeAvailable) return
        var corr = root.rpc.rpcBlockNoticeMutesClear()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("settings.block-notices.mutes.clear-failed",
                    "Could not clear the mutes: ") + String(msg || code || "")
                return
            }
            group._blockNoticeMutes = group._normalizeBlockNoticeMutes((p && p.mutes) || [])
        })
    }
    function _addBlockNoticeMute(scopeDto, untilUnixMs) {
        if (!root.bridgeAvailable) return
        var payload = { "scope": scopeDto }
        if (untilUnixMs > 0) payload["until-unix-ms"] = untilUnixMs
        var corr = root.rpc.rpcBlockNoticeMutesSet(payload)
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("settings.block-notices.add.failed",
                    "Could not add the mute: ") + String(msg || code || "")
                return
            }
            group._blockNoticeMutes = group._normalizeBlockNoticeMutes((p && p.mutes) || [])
            root.statusLine = root.tr("settings.block-notices.add.saved", "Mute added.")
        })
    }
    Component.onCompleted: group._loadBlockNoticeMutes()

    function _blockNoticeAddScopeLabel(slug) {
        switch (String(slug)) {
            case "host":
                return root.tr("settings.block-notices.add.scope-host", "One host")
            case "app":
                return root.tr("settings.block-notices.add.scope-app", "One application")
            default:
                return root.tr("settings.block-notices.add.scope-all",
                    "Every blocked-connection notice")
        }
    }
    function _blockNoticeDurationUnitLabel(slug) {
        switch (String(slug)) {
            case "minutes":
                return root.tr("settings.block-notices.add.duration-unit-minutes", "Minutes")
            case "days":
                return root.tr("settings.block-notices.add.duration-unit-days", "Days")
            default:
                return root.tr("settings.block-notices.add.duration-unit-hours", "Hours")
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
            text: root.tr("settings.field.show-notifications", "Show notifications")
            checked: root.prefs.showNotifications
            onToggled: root.updatePrefs({ showNotifications: checked })
        }
        // Per-kind mute, indented under the master switch it lives beneath.
        CheckBox {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            enabled: root.prefs.showNotifications !== false
            text: root.tr("settings.field.notify-suggestion-changes",
                "Tell me when the suggested-addresses list changes")
            checked: root.prefs.notifySuggestionChanges !== false
            onToggled: root.updatePrefs({ notifySuggestionChanges: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            enabled: root.prefs.showNotifications !== false
            text: root.tr("settings.field.notify-block-notices",
                "Tell me when a connection gets blocked")
            checked: root.prefs.notifyBlockNotices !== false
            onToggled: root.updatePrefs({ notifyBlockNotices: checked })
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

        // Autostart toggle. Source of truth will be
        // the AutostartGet/Toggle IPC ops; here we mutate `routingState`.
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

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // Block-notice privacy + mute management. Notify/mute-kind wiring
        // lives above (under "Show notifications"); this cluster is the
        // address-privacy toggle plus the mute list itself, since managing
        // mutes needs room a single checkbox row doesn't have.
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.group.block-notices", "Blocked-connection notices")
            color: root.textColor
            font.bold: true
        }
        CheckBox {
            Layout.fillWidth: true
            enabled: root.prefs.notifyBlockNotices !== false
            text: root.tr("settings.field.hide-block-notice-addresses",
                "Hide addresses in these notifications")
            checked: root.prefs.hideBlockNoticeAddresses === true
            onToggled: root.updatePrefs({ hideBlockNoticeAddresses: checked })
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.field.hide-block-notice-addresses-tooltip",
                "Replaces the destination with a generic label instead of the real hostname — useful when your screen is being shared or recorded.")
        }

        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            text: root.tr("settings.block-notices.mutes.heading", "Active mutes")
            color: root.textColor
            font.bold: true
        }
        ListView {
            id: blockNoticeMuteList
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(220, Math.max(1, group._blockNoticeMutes.length) * 44)
            visible: group._blockNoticeMutes.length > 0
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            model: group._blockNoticeMutes
            spacing: root.uiTheme.spacingXs
            delegate: RowLayout {
                id: blockNoticeMuteRow
                required property var modelData
                width: blockNoticeMuteList.width
                spacing: root.uiTheme.spacingSm
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    Label {
                        Layout.fillWidth: true
                        color: root.textColor
                        elide: Text.ElideRight
                        text: group._blockNoticeMuteScopeLabel(blockNoticeMuteRow.modelData)
                    }
                    Label {
                        Layout.fillWidth: true
                        color: root.mutedTextColor
                        font.pixelSize: root.uiTheme.baseFontSizePx - 2
                        text: group._blockNoticeMuteUntilLabel(blockNoticeMuteRow.modelData)
                    }
                }
                ThemedButton {
                    theme: root.uiTheme
                    flat: true
                    text: root.tr("action.delete", "Delete")
                    Accessible.name: text + ": "
                        + group._blockNoticeMuteScopeLabel(blockNoticeMuteRow.modelData)
                    onClicked: group._removeBlockNoticeMute(blockNoticeMuteRow.modelData)
                }
            }
        }
        Label {
            Layout.fillWidth: true
            visible: group._blockNoticeMutes.length === 0
            color: root.mutedTextColor
            text: group._blockNoticeMutesLoading
                ? root.tr("settings.block-notices.mutes.loading", "Loading…")
                : root.tr("settings.block-notices.mutes.empty", "No active mutes.")
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                enabled: group._blockNoticeMutes.length > 0
                text: root.tr("action.clear", "Clear")
                icon.source: root.uiIconSource("clear")
                Accessible.name: text
                onClicked: group._clearBlockNoticeMutes()
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            text: root.tr("settings.block-notices.add.heading", "Add a mute")
            color: root.textColor
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.block-notices.add.description",
                "The notification's quick-mute options only offer a few fixed lengths. Use this form for a duration of your own, or to mute indefinitely.")
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedComboBox {
                id: blockNoticeAddScope
                theme: root.uiTheme
                Layout.preferredWidth: 240
                model: ["all", "host", "app"]
                labelResolver: function(slug) { return group._blockNoticeAddScopeLabel(slug) }
                displayText: root.uiRevision >= 0 && currentIndex >= 0
                    ? group._blockNoticeAddScopeLabel(model[currentIndex]) : ""
                currentIndex: 0
                popup.width: root.comboPopupWidth(blockNoticeAddScope, blockNoticeAddScope.model, "",
                    function(item) { return group._blockNoticeAddScopeLabel(item) })
                Accessible.name: root.tr("settings.block-notices.add.scope-label", "What to mute")
            }
            ThemedTextField {
                id: blockNoticeAddTarget
                theme: root.uiTheme
                Layout.fillWidth: true
                visible: blockNoticeAddScope.currentIndex !== 0
                placeholderText: blockNoticeAddScope.currentIndex === 1
                    ? root.tr("settings.block-notices.add.host-placeholder",
                        "Hostname, exactly as shown in the notification")
                    : root.tr("settings.block-notices.add.app-placeholder",
                        "Application (process) name, exactly as shown in the notification")
                Accessible.name: placeholderText
            }
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Label {
                text: root.tr("settings.block-notices.add.duration-label", "For how long")
                color: root.textColor
            }
            ThemedSpinBox {
                id: blockNoticeAddAmount
                theme: root.uiTheme
                Layout.preferredWidth: 100
                editable: true
                enabled: !blockNoticeAddForever.checked
                from: 1; to: 999
                value: 24
                Accessible.name: root.tr("settings.block-notices.add.duration-label",
                    "For how long")
            }
            ThemedComboBox {
                id: blockNoticeAddUnit
                theme: root.uiTheme
                Layout.preferredWidth: 140
                enabled: !blockNoticeAddForever.checked
                model: ["minutes", "hours", "days"]
                labelResolver: function(slug) { return group._blockNoticeDurationUnitLabel(slug) }
                displayText: root.uiRevision >= 0 && currentIndex >= 0
                    ? group._blockNoticeDurationUnitLabel(model[currentIndex]) : ""
                currentIndex: 1
                popup.width: root.comboPopupWidth(blockNoticeAddUnit, blockNoticeAddUnit.model, "",
                    function(item) { return group._blockNoticeDurationUnitLabel(item) })
                Accessible.name: root.tr("settings.block-notices.add.duration-label",
                    "For how long")
            }
            CheckBox {
                id: blockNoticeAddForever
                text: root.tr("settings.block-notices.forever", "Forever")
                checked: false
            }
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                enabled: blockNoticeAddScope.currentIndex === 0
                    || blockNoticeAddTarget.text.trim() !== ""
                text: root.tr("action.add", "Add")
                icon.source: root.uiIconSource("add")
                Accessible.name: text
                onClicked: {
                    var scopeSlug = blockNoticeAddScope.model[blockNoticeAddScope.currentIndex]
                    var scopeDto = { "kind": "all" }
                    if (scopeSlug === "host")
                        scopeDto = { "kind": "host", "host": blockNoticeAddTarget.text.trim() }
                    else if (scopeSlug === "app")
                        scopeDto = { "kind": "app", "app": blockNoticeAddTarget.text.trim() }
                    var untilMs = 0
                    if (!blockNoticeAddForever.checked) {
                        var unitSlug = blockNoticeAddUnit.model[blockNoticeAddUnit.currentIndex]
                        var unitMs = unitSlug === "minutes" ? 60000
                            : unitSlug === "days" ? 86400000 : 3600000
                        untilMs = Date.now() + blockNoticeAddAmount.value * unitMs
                    }
                    group._addBlockNoticeMute(scopeDto, untilMs)
                    blockNoticeAddTarget.text = ""
                }
            }
        }
    }
}
