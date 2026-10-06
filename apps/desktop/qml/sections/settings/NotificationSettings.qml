import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

// Everything the app raises on its own, in one place: whether it may at all,
// which kinds are hidden and for how long, and the finer block mutes. GUI
// only — a console surface has no tray to raise them.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.category.notifications", "Notifications")
    Layout.fillWidth: true

    // ── Mutes ────────────────────────────────────────────────────────────
    //
    // The service owns mute state per-SID (block-notices.mutes.*). Whole
    // notice kinds — what the "Don't show…" buttons write — are set in the
    // table; finer block mutes (one host, app or reason) in the list below it,
    // the only place a mute gets a caller-chosen duration.
    property var _blockNoticeMutes: []
    property bool _blockNoticeMutesLoading: false
    // Blocked-connection notices are raised by the connection observer; where
    // there is none, nothing ever arrives and no mute has anything to silence.
    readonly property bool _blockNoticesSupported: root.blockNoticesSupported
    /// Mutes of one host, app or reason — what the table does not show.
    readonly property var _fineMutes: group._blockNoticeMutes.filter(function(m) {
        var kind = String(((m || {}).scope || {}).kind || "")
        return kind === "host" || kind === "app" || kind === "reason"
    })

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
        if (!(until > 0)) return root.tr("label.duration.forever", "Forever")
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
    // Only ask while the service is actually reachable. Asking a service that
    // is not there parked "Could not load the mute list: Service is offline" in
    // the status line — and nothing cleared it once the service came up, so the
    // message outlived the condition it described. The red backend banner
    // already says the service is offline; this surface adds nothing by
    // repeating it.
    readonly property bool _serviceReachable:
        root.bridgeAvailable && !!root.backendStatus
        && root.backendStatus.kind === "connected"

    function _loadBlockNoticeMutes() {
        if (group._blockNoticeMutesLoading || !group._serviceReachable) return
        var corr = root.rpc.rpcBlockNoticeMutesList()
        if (!corr) return
        group._blockNoticeMutesLoading = true
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            group._blockNoticeMutesLoading = false
            if (!ok) {
                // A connection that dropped mid-call is the banner's business,
                // not ours; anything else is a real failure worth naming.
                if (String(code) !== "transport-disconnected")
                    root.statusLine = root.tr("settings.block-notices.mutes.load-failed",
                        "Could not load the mute list: ") + root.ipcErrorLabel(code)
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
                    "Could not remove the mute: ") + root.ipcErrorLabel(code)
                return
            }
            group._blockNoticeMutes = group._normalizeBlockNoticeMutes((p && p.mutes) || [])
        })
    }
    /// Lifts the listed mutes one by one: clearing every mute would also
    /// unhide the notice kinds the table above holds.
    function _clearFineMutes() {
        var fine = group._fineMutes
        for (var i = 0; i < fine.length; i += 1) group._removeBlockNoticeMute(fine[i])
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
                    "Could not add the mute: ") + root.ipcErrorLabel(code)
                return
            }
            group._blockNoticeMutes = group._normalizeBlockNoticeMutes((p && p.mutes) || [])
            root.statusLine = root.tr("settings.block-notices.add.saved", "Mute added.")
        })
    }
    Component.onCompleted: group._loadBlockNoticeMutes()
    // The panel usually opens before the service answers, so the first attempt
    // is a no-op; this is what makes the list appear once it does.
    Connections {
        target: root
        function onBackendStatusChanged() {
            if (group._serviceReachable) group._loadBlockNoticeMutes()
        }
    }

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


    // ── Hidden notice kinds ──────────────────────────────────────────────

    /// The rows of the table: block notices as a class where this platform
    /// raises them, then every kind `nrr-domain` lets a user hide.
    readonly property var _hideableKinds: (group._blockNoticesSupported ? ["block-notices"] : [])
        .concat(Object.keys(Pure.MUTABLE_NOTICE_KINDS))
    readonly property var _hideChoices: ["show"].concat(Object.keys(Pure.NOTICE_MUTE_CHOICES_MS))

    function _kindScope(kind) {
        return kind === "block-notices" ? { "kind": "all" } : { "kind": "notice", "notice": kind }
    }
    function _kindTitle(kind) {
        if (kind === "block-notices")
            return root.tr("settings.block-notices.mutes.row-all", "All blocked-connection notices")
        var title = Pure.MUTABLE_NOTICE_KINDS[kind] || [kind, kind]
        return root.tr(title[0], title[1])
    }
    /// The mute hiding `kind`, or null. `mutes` is passed so a binding on it
    /// re-reads when the list changes.
    function _kindMute(kind, mutes) {
        var want = group._kindScope(kind)
        for (var i = 0; i < (mutes || []).length; i += 1) {
            var scope = mutes[i].scope || {}
            if (scope.kind === want.kind && String(scope.notice || "") === String(want.notice || ""))
                return mutes[i]
        }
        return null
    }
    function _kindStateText(kind, mutes) {
        var mute = group._kindMute(kind, mutes)
        if (mute === null) return root.tr("settings.notifications.hidden.shown", "Shown")
        if (!(mute.untilUnixMs > 0))
            return root.tr("settings.notifications.hidden.forever", "Hidden for good")
        return root.tr("settings.notifications.hidden.until", "Hidden until {timestamp}")
            .replace("{timestamp}", Qt.formatDateTime(new Date(mute.untilUnixMs), "yyyy-MM-dd HH:mm"))
    }
    function _hideChoiceLabel(slug) {
        switch (String(slug)) {
            case "1d": return root.tr("label.duration.for-a-day", "For a day")
            case "7d": return root.tr("label.duration.for-7-days", "For 7 days")
            case "30d": return root.tr("label.duration.for-30-days", "For 30 days")
            case "forever": return root.tr("label.duration.forever", "Forever")
            default: return root.tr("settings.notifications.hidden.show", "Show")
        }
    }
    function _setKindHidden(kind, choice) {
        if (choice === "show") {
            if (group._kindMute(kind, group._blockNoticeMutes) !== null)
                group._removeBlockNoticeMute({ "scope": group._kindScope(kind) })
            return
        }
        var span = Pure.NOTICE_MUTE_CHOICES_MS[choice]
        if (span === undefined) return
        group._addBlockNoticeMute(group._kindScope(kind), span > 0 ? Date.now() + span : 0)
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        // Everything the tray may raise, under one heading and one master
        // switch — a user who wants fewer interruptions should not have to
        // hunt for the kinds one screen at a time.
        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            text: root.tr("settings.group.tray-notifications", "Tray notifications")
            color: root.textColor
            font.bold: true
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
            onToggled: { root.updatePrefs({ notifySuggestionChanges: checked }); root.emitPrefs() }
        }
        CheckBox {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            enabled: root.prefs.showNotifications !== false
            visible: group._blockNoticesSupported
            text: root.tr("settings.field.notify-block-notices",
                "Tell me when a connection gets blocked")
            checked: root.prefs.notifyBlockNotices !== false
            onToggled: root.updatePrefs({ notifyBlockNotices: checked })
        }
        CheckBox {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            enabled: root.prefs.showNotifications !== false
            text: root.tr("settings.field.notify-rule-duplicates",
                "Tell me when a rule is set on both routes")
            checked: root.prefs.notifyRuleDuplicates !== false
            onToggled: { root.updatePrefs({ notifyRuleDuplicates: checked }); root.emitPrefs() }
        }
        // Tray notices are our own window, not system balloons, so their
        // opacity is ours to offer. Indented with the mutes above: it is the
        // same "how notifications behave" group.
        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            spacing: root.uiTheme.spacingSm
            enabled: root.prefs.showNotifications !== false
            Label {
                text: root.tr("settings.field.tray-notice-opacity",
                    "Tray notification opacity, %")
                color: root.textColor
            }
            ThemedSpinBox {
                theme: root.uiTheme
                Layout.preferredWidth: 140
                Layout.minimumWidth: 140
                from: 40
                to: 100
                stepSize: 5
                editable: true
                value: root.prefs.trayNoticeOpacityPercent || 100
                ToolTip.visible: hovered && root.prefs.tooltipsEnabled
                ToolTip.text: "40–100 %"
                onValueModified: root.updatePrefs({ trayNoticeOpacityPercent: value })
            }
            Item { Layout.fillWidth: true }
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.field.tray-notice-opacity-note",
                "Applies to notifications shown from the tray. Restart the tray for it to take effect.")
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // One row per notice kind the user may hide: what the "Don't show…"
        // buttons wrote, shown and changeable here.
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.notifications.hidden.heading", "Hidden notifications")
            color: root.textColor
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.notifications.hidden.description",
                "Choose for how long each kind of notification stays hidden. The \"Don't show…\" button on a notification sets the same thing.")
        }
        Repeater {
            model: group._hideableKinds
            delegate: RowLayout {
                id: hiddenKindRow
                required property string modelData
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.fillWidth: true
                    text: root.uiRevision >= 0 ? group._kindTitle(hiddenKindRow.modelData) : ""
                    color: root.textColor
                    wrapMode: Text.WordWrap
                }
                ThemedComboBox {
                    id: hiddenKindChoice
                    theme: root.uiTheme
                    Layout.preferredWidth: 260
                    enabled: group._serviceReachable
                    model: group._hideChoices
                    labelResolver: function(slug) { return group._hideChoiceLabel(slug) }
                    // The state, not the last pick: a mute set from the tray
                    // runs to its own deadline, which no option names.
                    displayText: root.uiRevision >= 0
                        ? group._kindStateText(hiddenKindRow.modelData, group._blockNoticeMutes) : ""
                    currentIndex: -1
                    popup.width: root.comboPopupWidth(hiddenKindChoice, hiddenKindChoice.model, "",
                        function(item) { return group._hideChoiceLabel(item) })
                    Accessible.name: group._kindTitle(hiddenKindRow.modelData)
                    onActivated: function(index) {
                        group._setKindHidden(hiddenKindRow.modelData, hiddenKindChoice.model[index])
                        hiddenKindChoice.currentIndex = -1
                    }
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: root.uiTheme.spacingXs
            Layout.bottomMargin: root.uiTheme.spacingXs
            color: root.uiTheme.colorBorder
        }

        // Block-notice privacy and the finer mutes: one host, app or reason.
        Label {
            Layout.fillWidth: true
            text: root.tr("settings.group.block-notices", "Blocked-connection notices")
            color: root.textColor
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            visible: !group._blockNoticesSupported
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.platformUnsupportedText
        }
        CheckBox {
            Layout.fillWidth: true
            visible: group._blockNoticesSupported
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
            visible: group._blockNoticesSupported
            text: root.tr("settings.field.hide-block-notice-addresses-tooltip",
                "Replaces the destination with a generic label instead of the real hostname — useful when your screen is being shared or recorded.")
        }

        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            visible: group._blockNoticesSupported
            text: root.tr("settings.block-notices.mutes.heading", "Active mutes")
            color: root.textColor
            font.bold: true
        }
        ListView {
            id: blockNoticeMuteList
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(220, Math.max(1, group._fineMutes.length) * 44)
            visible: group._blockNoticesSupported && group._fineMutes.length > 0
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            model: group._fineMutes
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
            visible: group._blockNoticesSupported && group._fineMutes.length === 0
            color: root.mutedTextColor
            text: group._blockNoticeMutesLoading
                ? root.tr("settings.block-notices.mutes.loading", "Loading…")
                : root.tr("settings.block-notices.mutes.empty", "No active mutes.")
        }
        RowLayout {
            Layout.fillWidth: true
            visible: group._blockNoticesSupported
            spacing: root.uiTheme.spacingSm
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                enabled: group._fineMutes.length > 0
                text: root.tr("action.clear", "Clear")
                icon.source: root.uiIconSource("clear")
                Accessible.name: text
                onClicked: group._clearFineMutes()
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            visible: group._blockNoticesSupported
            text: root.tr("settings.block-notices.add.heading", "Add a mute")
            color: root.textColor
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            visible: group._blockNoticesSupported
            text: root.tr("settings.block-notices.add.description",
                "The notification's quick-mute options only offer a few fixed lengths. Use this form for a duration of your own, or to mute indefinitely.")
        }
        RowLayout {
            Layout.fillWidth: true
            visible: group._blockNoticesSupported
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
            visible: group._blockNoticesSupported
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
                text: root.tr("label.duration.forever", "Forever")
                checked: false
            }
        }
        RowLayout {
            Layout.fillWidth: true
            visible: group._blockNoticesSupported
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
