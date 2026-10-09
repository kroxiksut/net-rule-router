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

    // Same, for the Settings categories and the Diagnostics pages.
    property bool settingsNavExpanded: false
    property bool diagnosticsNavExpanded: false

    // Both submenus stay open until the user collapses them with the arrow.
    // Auto-collapsing on navigation meant opening one closed the other, and a
    // list the user opened is a list they still want to see on the way back.

    // The comparison needs the service leg, so an unreachable service leaves
    // nothing to compare — disabled rather than hidden so the submenu does not
    // reshuffle under the user.
    readonly property bool rulesCheckAvailable: !!root.backendStatus
        && root.backendStatus.kind === "connected"
    // …and with everything already in agreement the button is shown but does
    // nothing when pressed, so it is not shown at all. A real divergence (rules
    // not applied, or a linked file that no longer matches) brings it back.
    readonly property bool rulesCheckDivergence: root.uiRevision >= 0
        && (root.rulesNotAppliedToService || root.rulesNotSavedToFile)

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
            SidebarGlyphButton {
                shell: root
                Layout.preferredWidth: 32
                Layout.preferredHeight: 32
                Layout.alignment: Qt.AlignVCenter | Qt.AlignHCenter
                glyph: root.sidebarCollapsed ? "»" : "«"
                glyphPixelSize: Math.max(16, root.font.pixelSize + 2)
                Accessible.name: root.sidebarCollapsed
                    ? root.tr("action.expand-navigation", "Expand navigation")
                    : root.tr("action.collapse-navigation", "Collapse navigation")
                onClicked: root.sidebarCollapsed = !root.sidebarCollapsed
            }
        }
        Label { visible: !root.sidebarCollapsed; Layout.fillWidth: true; text: root.context.windowTitle || "NetRuleRouter"; color: root.textColor; font.bold: true; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignLeft }
        // The entries scroll, so open submenus in a short window squeeze
        // nothing and never push the service caption below the frame.
        ScrollView {
            id: navScroller
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            ColumnLayout {
                width: navScroller.availableWidth
                spacing: root.uiTheme.spacingMd

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
                        readonly property bool isDiagnosticsEntry: modelData === "diagnostics"
                        readonly property bool hasSubmenu: navEntry.isRulesEntry || navEntry.isSettingsEntry
                            || navEntry.isDiagnosticsEntry
                        readonly property bool submenuExpanded: navEntry.isRulesEntry
                            ? navigationSidebar.rulesNavExpanded
                            : navEntry.isDiagnosticsEntry
                                ? navigationSidebar.diagnosticsNavExpanded
                                : navigationSidebar.settingsNavExpanded

                        RowLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: false
                            spacing: 0
                            ThemedButton {
                                id: navButton
                                theme: root.uiTheme
                                Layout.fillWidth: true
                                leftPadding: root.sidebarCollapsed ? root.uiTheme.spacingXs : root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                                rightPadding: root.sidebarCollapsed ? root.uiTheme.spacingXs : root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                                implicitWidth: contentItem.implicitWidth + leftPadding + rightPadding
                                implicitHeight: contentItem.implicitHeight + topPadding + bottomPadding
                                highlighted: root.section === modelData
                                // The header always opens the section (unchanged
                                // behaviour); for Rules it also reveals the submenu
                                // below so the newly opened list, check, and
                                // rejected-suggestions entries are discoverable.
                                onClicked: {
                                    root.requestSectionChange(modelData)
                                    if (navEntry.isRulesEntry) navigationSidebar.rulesNavExpanded = true
                                    if (navEntry.isSettingsEntry) navigationSidebar.settingsNavExpanded = true
                                    if (navEntry.isDiagnosticsEntry) navigationSidebar.diagnosticsNavExpanded = true
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
                                    id: navContent
                                    spacing: root.sidebarCollapsed ? 0 : root.uiTheme.spacingMd - root.uiTheme.spacingXxs
                                    // Addresses waiting for an answer. The count lives
                                    // on the "Suggested addresses" entry inside the
                                    // Rules submenu, which is hidden whenever the rail
                                    // is collapsed or the submenu is folded — the
                                    // states the window spends most of its life in. It
                                    // is repeated on the header so "there is something
                                    // to answer" survives them.
                                    readonly property int pendingBadge:
                                        navEntry.isRulesEntry
                                            && (root.sidebarCollapsed || !navigationSidebar.rulesNavExpanded)
                                        ? root.autoRuleSuggestionsController.autoRuleCandidatesPending
                                            + root.ruleOverlapsController.pendingCount
                                        : 0
                                    Label {
                                        Layout.preferredWidth: 20
                                        Layout.fillWidth: root.sidebarCollapsed
                                        text: Pure.sectionGlyph(modelData)
                                        color: navButton.highlighted ? palette.highlightedText : root.accentColor
                                        font.pixelSize: Math.max(16, root.font.pixelSize + 2)
                                        horizontalAlignment: Text.AlignHCenter
                                        Layout.alignment: Qt.AlignVCenter
                                        // A collapsed rail has no room for the number,
                                        // so the glyph itself carries a dot.
                                        Rectangle {
                                            visible: root.sidebarCollapsed && navContent.pendingBadge > 0
                                            width: 8
                                            height: 8
                                            radius: 4
                                            color: root.accentColor
                                            anchors.right: parent.right
                                            anchors.top: parent.top
                                            anchors.rightMargin: -2
                                            anchors.topMargin: -1
                                        }
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
                                            visible: navContent.pendingBadge > 0
                                            text: String(navContent.pendingBadge)
                                            color: navButton.highlighted ? palette.highlightedText : root.accentColor
                                            font.bold: true
                                            Accessible.name: root.tr("rules.nav.pending-badge",
                                                "{n} item(s) in Rules waiting for an answer")
                                                .replace("{n}", String(navContent.pendingBadge))
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
                            // Expand/collapse toggle for the submenu, separate from the
                            // header button so "open the section" and "just show the
                            // submenu" stay independent, both reachable by keyboard.
                            SidebarGlyphButton {
                                shell: root
                                visible: navEntry.hasSubmenu && !root.sidebarCollapsed
                                Layout.preferredWidth: visible ? 28 : 0
                                // Matches the header button's height, not a fixed one.
                                Layout.fillHeight: true
                                glyph: navEntry.submenuExpanded ? "▾" : "▸"
                                Accessible.name: navEntry.submenuExpanded
                                    ? root.tr("action.collapse-submenu", "Collapse submenu")
                                    : root.tr("action.expand-submenu", "Expand submenu")
                                onClicked: {
                                    if (navEntry.isRulesEntry) {
                                        navigationSidebar.rulesNavExpanded = !navigationSidebar.rulesNavExpanded
                                    } else if (navEntry.isDiagnosticsEntry) {
                                        navigationSidebar.diagnosticsNavExpanded = !navigationSidebar.diagnosticsNavExpanded
                                    } else {
                                        navigationSidebar.settingsNavExpanded = !navigationSidebar.settingsNavExpanded
                                    }
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
                                delegate: SidebarSubNavButton {
                                    shell: navigationSidebar.root
                                    iconName: modelData.icon || ""
                                    text: root.uiRevision >= 0
                                        ? root.tr(modelData.key, modelData.fallback) : ""
                                    selected: root.section === "settings"
                                        && root.settingsCategory === modelData.id
                                    onClicked: root.openSettingsCategory(modelData.id)
                                }
                            }
                        }

                        // Diagnostics submenu: the live connection trace, what the last
                        // outage blocked, and the cache.
                        ColumnLayout {
                            visible: navEntry.isDiagnosticsEntry && navigationSidebar.diagnosticsNavExpanded
                                && !root.sidebarCollapsed
                            Layout.fillWidth: true
                            Layout.fillHeight: false
                            Layout.leftMargin: root.uiTheme.spacingMd + 20
                            Layout.topMargin: root.uiTheme.spacingXxs
                            spacing: root.uiTheme.spacingXxs

                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                sectionId: "conn-trace"
                                iconName: "routing"
                                text: root.sectionTitle("conn-trace")
                                onClicked: root.requestSectionChange("conn-trace")
                            }

                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                sectionId: "outage-blocks"
                                iconName: "routing"
                                text: root.sectionTitle("outage-blocks")
                                onClicked: root.requestSectionChange("outage-blocks")
                            }

                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                sectionId: "cache"
                                iconName: "cache"
                                text: root.sectionTitle("cache")
                                onClicked: root.requestSectionChange("cache")
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

                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                sectionId: "rules"
                                iconName: "edit-list"
                                text: root.tr("rules.nav.list", "Rules list")
                                onClicked: root.requestSectionChange("rules")
                            }
                            SidebarSubNavButton {
                                id: rulesCheckSyncButton
                                shell: navigationSidebar.root
                                visible: navigationSidebar.rulesCheckDivergence
                                enabled: navigationSidebar.rulesCheckAvailable
                                sectionId: "rules-check-sync"
                                iconName: "refresh"
                                text: root.tr("rules.nav.check-sync", "Check rules match")
                                onClicked: root.driftController._driftRecheckNow(true)
                                ToolTip.visible: rulesCheckSyncButton.hovered && root.prefs.tooltipsEnabled
                                ToolTip.text: rulesCheckSyncButton.enabled
                                    ? root.tr("rules.state.check-now-tooltip",
                                        "Compare the rules on screen with your rules file and with the service right now.")
                                    : root.tr("rules.state.unknown",
                                        "Not verified — the service isn't reachable right now.")
                            }
                            // Suggested + dismissed addresses, merged into one table
                            // section. Carries the pending count because the whole
                            // point is that nothing pending is lost — a silent entry
                            // would not say there is anything to answer.
                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                sectionId: "rule-suggestions"
                                iconName: "add"
                                text: root.tr("rules.suggestions.inbox.nav-label", "Suggested addresses")
                                badge: root.autoRuleSuggestionsController.autoRuleCandidatesPending
                                onClicked: root.autoRuleSuggestionsController.openAutoRuleSuggestions()
                            }
                            // Rules of the two routes claiming the same hosts, and the
                            // address conflicts of the applied rules. Hidden while there
                            // are neither; the count is the unconfirmed pairs.
                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                visible: root.ruleOverlapsController.overlaps.length > 0
                                    || root.ruleOverlapsController.conflicts.length > 0
                                sectionId: "rule-overlaps"
                                iconName: "overlaps"
                                text: root.tr("rules.overlaps.nav-label", "Overlaps")
                                badge: root.ruleOverlapsController.pendingCount
                                Accessible.description: root.ruleOverlapsController.pendingCount > 0
                                    ? root.tr("rules.overlaps.pending-badge", "{n} overlap(s) not confirmed")
                                        .replace("{n}", String(root.ruleOverlapsController.pendingCount))
                                    : ""
                                onClicked: root.ruleOverlapsController.open()
                            }
                            // Behind the experimental opt-in, and only where a
                            // hypervisor's network or machines exist: with none, there
                            // is nothing on this screen to act on.
                            SidebarSubNavButton {
                                shell: navigationSidebar.root
                                visible: (root.uiRevision >= 0 ? root.prefs.showVirtualMachinesSection === true : false)
                                    && root.virtualMachinesController.available
                                sectionId: "rule-virtual-machines"
                                iconName: "routing"
                                text: root.uiRevision >= 0 ? root.tr("rules.vm.nav-label", "Virtual machines") : ""
                                onClicked: root.requestSectionChange("rule-virtual-machines")
                            }
                        }
                    }
                }
                // Revoke the temporary admin approval granted this session
                // (retires the elevation broker; the next change re-prompts).
                // Directly under Settings so it reads as part of the rail. Shown
                // only when a non-admin GUI obtained approval via the broker:
                // an admin sets up the machine, then hands it to a user who must
                // re-approve to change rules. Hidden while collapsed.
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
            }
        }
        // Preferred width 0: a wrapping label otherwise votes its one-line width.
        Label { visible: !root.sidebarCollapsed; Layout.fillWidth: true; Layout.preferredWidth: 0; text: root.serviceFooterStatusText(); color: root.mutedTextColor; wrapMode: Text.WordWrap }
    }
}
