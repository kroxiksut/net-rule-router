import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../lib/pure.js" as Pure

// Left navigation rail (extracted from Main.qml). Collapsible sidebar with the
// app icon, collapse toggle, five section buttons, an optional "Revoke admin
// approval" action, and the service footer status. Shared state via `root`
// (the ApplicationWindow); the component root is the Pane so its Layout.*
// bindings drive width inside the parent RowLayout.
Pane {
    id: navigationSidebar

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    // Expansion state of the Rules submenu (list / check-sync / rejected
    // suggestions). Local to the sidebar — collapsing the whole rail hides
    // the submenu regardless of this flag.
    property bool rulesNavExpanded: false

    // Same, for the Settings categories. They used to be a second rail inside
    // the Settings section; one column of navigation is enough.
    property bool settingsNavExpanded: false

    // Both submenus stay open until the user collapses them with the arrow.
    // Auto-collapsing on navigation meant opening one closed the other, and a
    // list the user opened is a list they still want to see on the way back.

    // The comparison needs the service leg, so an unreachable service leaves
    // nothing to compare — disabled rather than hidden so the submenu does not
    // reshuffle under the user. Agreement is NOT a reason to disable: "is it
    // still in sync?" is exactly what the button answers.
    readonly property bool rulesCheckAvailable: !!root.backendStatus
        && root.backendStatus.kind === "connected"

    Layout.preferredWidth: root.sidebarCollapsed ? 64 : 280
    Layout.minimumWidth: root.sidebarCollapsed ? 64 : 260
    Layout.fillHeight: true
    padding: root.sidebarCollapsed ? root.uiTheme.spacingSm : root.uiTheme.spacingMd
    background: PanelSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusMd }
    Behavior on Layout.preferredWidth { NumberAnimation { duration: 120; easing.type: Easing.OutCubic } }

    ColumnLayout {
        anchors.fill: parent
        spacing: root.uiTheme.spacingMd
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            Image {
                visible: !root.sidebarCollapsed
                Layout.preferredWidth: visible ? 40 : 0
                Layout.preferredHeight: 40
                Layout.alignment: Qt.AlignLeft
                source: root.appIconSource
                sourceSize.width: 40
                sourceSize.height: 40
                fillMode: Image.PreserveAspectFit
                asynchronous: true
            }
            Item { Layout.fillWidth: true; visible: !root.sidebarCollapsed }
            // Collapse / expand toggle. Raw Button mirrors the themed
            // section buttons below (both override background +
            // contentItem so the Native style can't leak through).
            Button {
                id: sidebarToggleButton
                Layout.preferredWidth: 32
                Layout.preferredHeight: 32
                Layout.alignment: Qt.AlignVCenter | Qt.AlignHCenter
                activeFocusOnTab: true
                Accessible.name: root.sidebarCollapsed
                    ? root.tr("action.expand-navigation", "Expand navigation")
                    : root.tr("action.collapse-navigation", "Collapse navigation")
                onClicked: root.sidebarCollapsed = !root.sidebarCollapsed
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: Accessible.name
                background: PanelSurface {
                    theme: root.uiTheme
                    cornerRadius: root.uiTheme.radiusSm
                    color: sidebarToggleButton.hovered ? root.uiTheme.stateHoverFill : root.panelColor
                    border.color: sidebarToggleButton.activeFocus ? root.uiTheme.stateFocusedBorder : root.uiTheme.stateDefaultBorder
                }
                contentItem: Label {
                    text: root.sidebarCollapsed ? "»" : "«"
                    color: root.accentColor
                    font.pixelSize: Math.max(16, root.font.pixelSize + 2)
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
        Label { visible: !root.sidebarCollapsed; Layout.fillWidth: true; text: root.context.windowTitle || "NetRuleRouter"; color: root.textColor; font.bold: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignLeft }
        Repeater {
            model: [
                "interfaces-routes",
                "rules",
                "diagnostics",
                "logs",
                "settings"
            ]
            delegate: ColumnLayout {
                id: navEntry
                Layout.fillWidth: true
                // A nested layout defaults to fillHeight TRUE, so every entry
                // claimed a share of the column's spare height and the buttons
                // drifted apart. Each entry is exactly as tall as its content.
                Layout.fillHeight: false
                spacing: 0
                readonly property bool isRulesEntry: modelData === "rules"
                readonly property bool isSettingsEntry: modelData === "settings"
                readonly property bool hasSubmenu: navEntry.isRulesEntry || navEntry.isSettingsEntry
                readonly property bool submenuExpanded: navEntry.isRulesEntry
                    ? navigationSidebar.rulesNavExpanded
                    : navigationSidebar.settingsNavExpanded

                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: false
                    spacing: 0
                    Button {
                        id: navButton
                        Layout.fillWidth: true
                        activeFocusOnTab: true
                        leftPadding: root.sidebarCollapsed ? root.uiTheme.spacingXs : root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                        rightPadding: root.sidebarCollapsed ? root.uiTheme.spacingXs : root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                        highlighted: root.section === modelData
                        // The header always opens the section (unchanged
                        // behaviour); for Rules it also reveals the submenu
                        // below so the newly opened list, check, and
                        // rejected-suggestions entries are discoverable.
                        onClicked: {
                            root.requestSectionChange(modelData)
                            if (navEntry.isRulesEntry) navigationSidebar.rulesNavExpanded = true
                            if (navEntry.isSettingsEntry) navigationSidebar.settingsNavExpanded = true
                        }
                        Accessible.name: root.sectionTitle(modelData)
                        ToolTip.visible: root.sidebarCollapsed && hovered
                        ToolTip.delay: 400
                        ToolTip.text: root.sectionTitle(modelData)
                        background: PanelSurface {
                            theme: root.uiTheme
                            cornerRadius: root.uiTheme.radiusSm
                            color: navButton.highlighted ? root.accentColor : root.panelColor
                            border.color: navButton.highlighted ? root.uiTheme.stateSelectedBorder : root.uiTheme.stateDefaultBorder
                        }
                        contentItem: RowLayout {
                            spacing: root.sidebarCollapsed ? 0 : root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                            Label {
                                Layout.preferredWidth: 20
                                Layout.fillWidth: root.sidebarCollapsed
                                text: Pure.sectionGlyph(modelData)
                                color: navButton.highlighted ? palette.highlightedText : root.accentColor
                                font.pixelSize: Math.max(16, root.font.pixelSize + 2)
                                horizontalAlignment: Text.AlignHCenter
                                Layout.alignment: Qt.AlignVCenter
                            }
                            RowLayout {
                                visible: !root.sidebarCollapsed
                                Layout.fillWidth: true
                                spacing: root.uiTheme.spacingSm
                                Label {
                                    Layout.fillWidth: true
                                    text: root.sectionTitle(modelData)
                                    color: navButton.highlighted ? palette.highlightedText : root.textColor
                                    horizontalAlignment: Text.AlignLeft
                                    elide: Text.ElideRight
                                }
                                Label {
                                    Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
                                    text: modelData === "interfaces-routes" ? "Ctrl+1"
                                        : modelData === "rules" ? "Ctrl+2"
                                        : modelData === "diagnostics" ? "Ctrl+3"
                                        : modelData === "logs" ? "Ctrl+4"
                                        : "Ctrl+,"
                                    color: navButton.highlighted ? palette.highlightedText : root.mutedTextColor
                                    font.pixelSize: Math.max(11, root.font.pixelSize - 1)
                                }
                            }
                        }
                    }
                    // Expand/collapse toggle for the Rules submenu, kept as a
                    // control separate from the header button above so the
                    // "open Rules" click and the "just show me the submenu"
                    // click stay independent, both reachable by keyboard.
                    Button {
                        id: rulesChevronButton
                        visible: navEntry.hasSubmenu && !root.sidebarCollapsed
                        Layout.preferredWidth: visible ? 28 : 0
                        // Fills the row's height instead of a fixed 28px so it
                        // matches navButton's actual (two-line) height exactly.
                        Layout.fillHeight: true
                        activeFocusOnTab: true
                        Accessible.name: navEntry.submenuExpanded
                            ? root.tr("action.collapse-submenu", "Collapse submenu")
                            : root.tr("action.expand-submenu", "Expand submenu")
                        onClicked: {
                            if (navEntry.isRulesEntry) {
                                navigationSidebar.rulesNavExpanded = !navigationSidebar.rulesNavExpanded
                            } else {
                                navigationSidebar.settingsNavExpanded = !navigationSidebar.settingsNavExpanded
                            }
                        }
                        ToolTip.visible: hovered
                        ToolTip.delay: 400
                        ToolTip.text: Accessible.name
                        background: PanelSurface {
                            theme: root.uiTheme
                            cornerRadius: root.uiTheme.radiusSm
                            color: rulesChevronButton.hovered ? root.uiTheme.stateHoverFill : root.panelColor
                            border.color: rulesChevronButton.activeFocus ? root.uiTheme.stateFocusedBorder : root.uiTheme.stateDefaultBorder
                        }
                        contentItem: Label {
                            text: navEntry.submenuExpanded ? "▾" : "▸"
                            color: root.accentColor
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }

                // Settings categories — the list that used to be a rail inside
                // the section. Selecting one navigates and picks the category
                // in a single guarded step.
                ColumnLayout {
                    visible: navEntry.isSettingsEntry && navigationSidebar.settingsNavExpanded
                        && !root.sidebarCollapsed
                    Layout.fillWidth: true
                    Layout.fillHeight: false
                    Layout.leftMargin: root.uiTheme.spacingMd + 20
                    Layout.topMargin: root.uiTheme.spacingXxs
                    spacing: root.uiTheme.spacingXxs

                    Repeater {
                        model: Pure.settingsCategories()
                        delegate: Button {
                            id: settingsCategoryButton
                            Layout.fillWidth: true
                            activeFocusOnTab: true
                            highlighted: root.section === "settings"
                                && root.settingsCategory === modelData.id
                            Accessible.role: Accessible.Button
                            Accessible.name: root.tr(modelData.key, modelData.fallback)
                            onClicked: root.openSettingsCategory(modelData.id)
                            background: PanelSurface {
                                theme: root.uiTheme
                                cornerRadius: root.uiTheme.radiusSm
                                color: settingsCategoryButton.highlighted ? root.accentColor
                                    : (settingsCategoryButton.hovered ? root.uiTheme.stateHoverFill : root.panelColor)
                                border.color: settingsCategoryButton.highlighted ? root.uiTheme.stateSelectedBorder
                                    : (settingsCategoryButton.activeFocus ? root.uiTheme.stateFocusedBorder : root.uiTheme.stateDefaultBorder)
                            }
                            contentItem: RowLayout {
                                spacing: modelData.icon ? root.uiTheme.spacingSm : 0
                                Image {
                                    visible: !!modelData.icon
                                    source: modelData.icon ? root.uiIconSource(modelData.icon) : ""
                                    sourceSize.width: 16
                                    sourceSize.height: 16
                                    Layout.preferredWidth: visible ? 16 : 0
                                    Layout.preferredHeight: visible ? 16 : 0
                                    fillMode: Image.PreserveAspectFit
                                    asynchronous: true
                                }
                                Label {
                                    Layout.fillWidth: true
                                    text: root.uiRevision >= 0
                                        ? root.tr(modelData.key, modelData.fallback) : ""
                                    color: settingsCategoryButton.highlighted ? palette.highlightedText : root.textColor
                                    elide: Text.ElideRight
                                    verticalAlignment: Text.AlignVCenter
                                }
                            }
                        }
                    }
                }

                // Rules submenu: the rules list (same destination as the
                // header), an on-demand file/service compare, and the (stub)
                // rejected-suggestions history.
                ColumnLayout {
                    visible: navEntry.isRulesEntry && navigationSidebar.rulesNavExpanded && !root.sidebarCollapsed
                    Layout.fillWidth: true
                    Layout.fillHeight: false
                    Layout.leftMargin: root.uiTheme.spacingMd + 20
                    Layout.topMargin: root.uiTheme.spacingXxs
                    spacing: root.uiTheme.spacingXxs

                    Button {
                        id: rulesListNavButton
                        Layout.fillWidth: true
                        activeFocusOnTab: true
                        highlighted: root.section === "rules"
                        onClicked: root.requestSectionChange("rules")
                        Accessible.name: root.tr("rules.nav.list", "Rules list")
                        background: PanelSurface {
                            theme: root.uiTheme
                            cornerRadius: root.uiTheme.radiusSm
                            color: rulesListNavButton.highlighted ? root.accentColor : root.panelColor
                            border.color: rulesListNavButton.highlighted ? root.uiTheme.stateSelectedBorder : root.uiTheme.stateDefaultBorder
                        }
                        contentItem: RowLayout {
                            spacing: root.uiTheme.spacingSm
                            Image {
                                source: root.uiIconSource("edit-list")
                                sourceSize.width: 16
                                sourceSize.height: 16
                                Layout.preferredWidth: 16
                                Layout.preferredHeight: 16
                                fillMode: Image.PreserveAspectFit
                                asynchronous: true
                            }
                            Label {
                                Layout.fillWidth: true
                                text: root.tr("rules.nav.list", "Rules list")
                                color: rulesListNavButton.highlighted ? palette.highlightedText : root.textColor
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                    }
                    Button {
                        id: rulesCheckSyncButton
                        Layout.fillWidth: true
                        activeFocusOnTab: true
                        enabled: navigationSidebar.rulesCheckAvailable
                        Accessible.name: root.tr("rules.nav.check-sync", "Check rules match")
                        onClicked: root.driftController._driftRecheckNow(true)
                        ToolTip.visible: rulesCheckSyncButton.hovered && root.prefs.tooltipsEnabled
                        ToolTip.text: rulesCheckSyncButton.enabled
                            ? root.tr("rules.state.check-now-tooltip",
                                "Compare the rules on screen with your rules file and with the service right now.")
                            : root.tr("rules.state.unknown",
                                "Not verified — the service isn't reachable right now.")
                        background: PanelSurface {
                            theme: root.uiTheme
                            cornerRadius: root.uiTheme.radiusSm
                            color: !rulesCheckSyncButton.enabled
                                ? root.uiTheme.stateDisabledFill
                                : (rulesCheckSyncButton.hovered ? root.uiTheme.stateHoverFill : root.panelColor)
                            border.color: !rulesCheckSyncButton.enabled
                                ? root.uiTheme.stateDisabledBorder
                                : (rulesCheckSyncButton.activeFocus ? root.uiTheme.stateFocusedBorder : root.uiTheme.stateDefaultBorder)
                        }
                        contentItem: RowLayout {
                            spacing: root.uiTheme.spacingSm
                            Image {
                                source: root.uiIconSource("refresh")
                                sourceSize.width: 16
                                sourceSize.height: 16
                                Layout.preferredWidth: 16
                                Layout.preferredHeight: 16
                                fillMode: Image.PreserveAspectFit
                                opacity: rulesCheckSyncButton.enabled ? 1.0 : 0.55
                                asynchronous: true
                            }
                            Label {
                                Layout.fillWidth: true
                                text: root.tr("rules.nav.check-sync", "Check rules match")
                                color: rulesCheckSyncButton.enabled ? root.textColor : root.mutedTextColor
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }
                        }
                    }
                    // Suggested + dismissed addresses, merged into one table
                    // section. Carries the pending count because the whole
                    // point is that nothing pending is lost — a silent entry
                    // would not say there is anything to answer.
                    Button {
                        id: rulesSuggestionsInboxButton
                        Layout.fillWidth: true
                        activeFocusOnTab: true
                        highlighted: root.section === "rule-suggestions"
                        Accessible.name: root.tr("rules.suggestions.inbox.nav-label",
                            "Suggested addresses")
                        onClicked: root.openAutoRuleSuggestions()
                        background: PanelSurface {
                            theme: root.uiTheme
                            cornerRadius: root.uiTheme.radiusSm
                            color: rulesSuggestionsInboxButton.highlighted ? root.accentColor
                                : (rulesSuggestionsInboxButton.hovered ? root.uiTheme.stateHoverFill : root.panelColor)
                            border.color: rulesSuggestionsInboxButton.highlighted ? root.uiTheme.stateSelectedBorder
                                : (rulesSuggestionsInboxButton.activeFocus ? root.uiTheme.stateFocusedBorder : root.uiTheme.stateDefaultBorder)
                        }
                        contentItem: RowLayout {
                            spacing: root.uiTheme.spacingXs
                            Image {
                                source: root.uiIconSource("add")
                                sourceSize.width: 16
                                sourceSize.height: 16
                                Layout.preferredWidth: 16
                                Layout.preferredHeight: 16
                                fillMode: Image.PreserveAspectFit
                                asynchronous: true
                            }
                            Label {
                                Layout.fillWidth: true
                                text: root.tr("rules.suggestions.inbox.nav-label", "Suggested addresses")
                                color: rulesSuggestionsInboxButton.highlighted ? palette.highlightedText : root.textColor
                                elide: Text.ElideRight
                                verticalAlignment: Text.AlignVCenter
                            }
                            Label {
                                visible: root.autoRuleCandidatesPending > 0
                                text: String(root.autoRuleCandidatesPending)
                                color: rulesSuggestionsInboxButton.highlighted ? palette.highlightedText : root.accentColor
                                font.bold: true
                            }
                        }
                    }
                }
            }
        }
        // Revoke the temporary admin
        // approval granted this session (retires the elevation broker
        // → next change re-prompts UAC). Sits DIRECTLY under the nav
        // items (above the spacer) so it reads as "right under
        // Settings", with a red alert-triangle icon marking it as a
        // security action. Shown ONLY when a non-admin GUI obtained
        // approval via the broker; hidden under an elevated GUI or
        // before any UAC. Use case: an admin sets up the machine, then
        // hands it to a user who must re-approve to change rules.
        // Hidden while the sidebar is collapsed (rare action; expand
        // to use).
        ThemedButton {
            theme: root.uiTheme
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            visible: root._brokerSessionElevated && !root.reviewFlowController._isAppElevated()
                && !root.sidebarCollapsed
            icon.source: root.uiIconSource("alert-triangle")
            wrapText: true
            font.bold: true
            // Red (danger) styling: this
            // is a security action that drops the session's admin
            // approval, so it reads as destructive at a glance.
            danger: true
            text: root.tr("action.revoke-admin", "Revoke admin approval")
            ToolTip.visible: hovered
            ToolTip.text: root.tr("action.revoke-admin-tooltip",
                "End the temporary administrator approval granted this session. The next change will ask for approval again.")
            onClicked: root.reviewFlowController.revokeAdminApproval()
        }
        Item { Layout.fillHeight: true }
        Label { visible: !root.sidebarCollapsed; Layout.fillWidth: true; text: root.serviceFooterStatusText(); color: root.mutedTextColor; wrapMode: Text.WordWrap }
    }
}
