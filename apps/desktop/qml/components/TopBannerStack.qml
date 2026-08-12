import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

// Top banner stack (extracted from Main.qml). The status banners
// (backend / combined-amber / drift / merge / compat / secondary-adapter /
// empty-rules / policy-inactive / block-all / rules-folder-suggestion /
// revision-integrity), stacked top-to-bottom
// and anchored to each other. The combined-amber bar merges the drift and
// secondary-adapter warnings into one container while both apply; those two
// stand down for its duration. Kept as ONE
// component because the banners cross-anchor (each `anchors.top` is the
// previous banner's `bottom`). `totalHeight` is consumed by the main content's
// top margin so the content sits below whatever banners are visible. Shared
// state via `root` (the ApplicationWindow).
Item {
    id: topBannerStack

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    readonly property real totalHeight: backendBanner.height
        + combinedAmberBanner.height + driftBanner.height
        + mergeBanner.height + compatBanner.height + secondaryAdapterBanner.height
        + emptyRulesBanner.height + policyInactiveBanner.height
        + blockAllBanner.height
        + rulesFolderSuggestionBanner.height + revisionIntegrityBanner.height
    height: totalHeight

    // Expansion state of the combined amber banner. Local to the stack — the
    // window owns only the "are both warnings up?" predicate.
    property bool combinedAmberExpanded: false

    Rectangle {
        id: backendBanner
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.backendBannerHeight
        visible: root.backendBannerVisible
        color: root.backendStatusBannerColor()
        z: 100
        // Refresh the live SCM status whenever the banner appears so the
        // Start/Install button label is accurate (refreshStatus() is otherwise
        // only auto-polled while the Settings panel is open).
        onVisibleChanged: {
            if (visible && typeof nrrServiceController !== "undefined"
                    && nrrServiceController
                    && typeof nrrServiceController.refreshStatus === "function") {
                nrrServiceController.refreshStatus()
            }
        }
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            BusyIndicator {
                visible: (root.backendStatus || {}).kind === "connecting"
                running: visible
                implicitWidth: 20
                implicitHeight: 20
            }
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.backendStatusBannerText()
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
            }
            // One-click Start/Install service. Label and
            // action come from the live SCM status (_bannerServiceAction), not
            // backendStatus.kind. Same call path the Settings panel and the
            // ServiceNotRunningDialog use, surfaced on the banner per user
            // request.
            ThemedButton {
                theme: root.uiTheme
                visible: root.backendBannerActionable
                enabled: !(typeof nrrServiceController !== "undefined"
                    && nrrServiceController && nrrServiceController.busy)
                // Icon on the banner action so it reads
                // as a primary affordance, not just text. Shield = the service.
                icon.source: root.uiIconSource("shield")
                text: root._bannerServiceAction() === "install"
                    ? root.tr("dialog.service-not-running.install-service",
                        "Install service…")
                    : root.tr("dialog.service-not-running.start-service",
                        "Start service")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root._bannerServiceAction() === "install"
                    ? root.tr(
                        "dialog.service-not-running.install-service-description",
                        "Install the Windows service (requires administrator privileges) and start it.")
                    : root.tr(
                        "dialog.service-not-running.start-service-description",
                        "Start the Windows service (requires administrator privileges).")
                onClicked: root._startServiceFromBanner()
            }
        }
    }

    // Combined amber banner. Carries the drift warning AND the
    // secondary-adapter warning as two compact lines inside ONE bar, replacing
    // the two standalone bars while both apply. Collapsed: a glyph plus a
    // single elided line each, and one shared expand button. Expanded: the
    // full wrapped texts plus each warning's own action. Neither banner's
    // logic moves here — this is a presentation container reading the same
    // window-level predicates the standalone bars read.
    Rectangle {
        id: combinedAmberBanner
        anchors.top: backendBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.combinedAmberBannerVisible
            ? Math.max(36, combinedAmberColumn.implicitHeight + 2 * root.uiTheme.spacingSm)
            : 0
        visible: root.combinedAmberBannerVisible
        color: "#d4a017"     // amber — the colour both merged banners used
        z: 99
        // Collapse again once the pair stops applying, so the next time the
        // two warnings coincide the compact form is what appears.
        onVisibleChanged: if (!visible) topBannerStack.combinedAmberExpanded = false

        ColumnLayout {
            id: combinedAmberColumn
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingXs

            // Line 1 — rules drift. Carries the shared expand toggle.
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    text: "⚠"
                    color: "white"
                    Layout.alignment: Qt.AlignTop
                    Accessible.ignored: true
                }
                Label {
                    Layout.fillWidth: true
                    color: "white"
                    text: root._serviceRulesEmpty
                        ? root.tr("status.drift-banner-empty-service",
                            "The service has none of your rules — nothing is being routed yet.")
                        : root.tr("status.drift-banner",
                            "Rules in the file, the app, and the service do not all agree.")
                    verticalAlignment: Text.AlignVCenter
                    wrapMode: topBannerStack.combinedAmberExpanded
                        ? Text.WordWrap : Text.NoWrap
                    elide: topBannerStack.combinedAmberExpanded
                        ? Text.ElideNone : Text.ElideRight
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }
                // An empty service is not a drift to inspect — it is one action
                // away from fixed, so offer that action directly instead of
                // hiding it behind "Show details".
                ThemedButton {
                    theme: root.uiTheme
                    visible: root._serviceRulesEmpty
                    text: root.tr("status.drift-banner-apply", "Apply rules")
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    Accessible.description: root.tr(
                        "status.drift-banner-apply-description",
                        "Send the rules shown in the app to the background service.")
                    onClicked: root.applyRulesToService()
                }
                // The banner is driven by a poll, so it can lag a fix the user
                // just made. Let them settle it on the spot instead of
                // wondering whether the warning is still true.
                ThemedButton {
                    theme: root.uiTheme
                    visible: topBannerStack.combinedAmberExpanded
                    text: root.tr("rules.state.check-now", "Check now")
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    Accessible.description: root.tr("rules.state.check-now-tooltip",
                        "Compare the rules on screen with your rules file and with the service right now.")
                    onClicked: root.driftController._driftRecheckNow(true)
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: topBannerStack.combinedAmberExpanded
                            && !root._serviceRulesEmpty
                    text: root.tr("status.drift-banner-details", "Details…")
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    Accessible.description: root.tr(
                        "status.drift-banner-details-description",
                        "Open the drift dialog to inspect hashes and pick a resolution.")
                    onClicked: root.driftController._openDriftDialog()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.uiRevision >= 0
                        ? (topBannerStack.combinedAmberExpanded
                            ? root.tr("settings.routing.show-less", "Hide details")
                            : root.tr("settings.routing.show-more", "Show details"))
                        : ""
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    onClicked: topBannerStack.combinedAmberExpanded =
                        !topBannerStack.combinedAmberExpanded
                }
            }

            // Line 2 — secondary adapter (re-confirm or unavailable).
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    text: "⚠"
                    color: "white"
                    Layout.alignment: Qt.AlignTop
                    Accessible.ignored: true
                }
                Label {
                    Layout.fillWidth: true
                    color: "white"
                    // Same direct `uiRevision` read as the standalone banner:
                    // the adapter name comes from a JS call whose property
                    // reads Qt does not track.
                    text: root.uiRevision >= 0
                        ? (root.secondaryReconfirmVisible
                            ? root.tr("status.secondary-reconfirm",
                                "Your secondary adapter \"{name}\" looks reinstalled (new ID). Re-confirm it so the stored binding matches.")
                                .replace("{name}", String(root.prefs.selectedSecondaryInterfaceName || ""))
                            : root.tr("status.secondary-unresolved",
                                "The additional adapter \"{name}\" assigned to your rules isn't available right now — start it, or choose a different adapter in Interfaces and routes. While it's missing, matching traffic is blocked (leak protection) instead of leaking over your main connection.")
                                .replace("{name}", String(root.prefs.selectedSecondaryInterfaceName || "")))
                        : ""
                    verticalAlignment: Text.AlignVCenter
                    wrapMode: topBannerStack.combinedAmberExpanded
                        ? Text.WordWrap : Text.NoWrap
                    elide: topBannerStack.combinedAmberExpanded
                        ? Text.ElideNone : Text.ElideRight
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: topBannerStack.combinedAmberExpanded
                    text: root.secondaryReconfirmVisible
                        ? root.tr("status.secondary-reconfirm-button", "Re-confirm adapter")
                        : root.tr("status.secondary-unresolved-button", "Open Interfaces and routes")
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    Accessible.description: root.secondaryReconfirmVisible
                        ? root.tr("status.secondary-reconfirm-button-description",
                            "Update the stored secondary adapter binding to the reinstalled adapter.")
                        : root.tr("status.secondary-unresolved-button-description",
                            "Open Interfaces and routes to start or re-select the additional adapter.")
                    onClicked: {
                        if (root.secondaryReconfirmVisible)
                            root.interfacesRolesController._reconfirmSecondaryBinding()
                        else root.section = "interfaces-routes"
                    }
                }
                // Same persistent dismiss the standalone banner offers for the
                // "adapter not found" variant; the window clears the
                // acknowledgement once the adapter resolves again.
                ToolButton {
                    id: combinedSecondaryCloseButton
                    visible: topBannerStack.combinedAmberExpanded
                        && root.secondaryUnresolvedVisible
                    text: "✕"
                    implicitWidth: 24
                    implicitHeight: 24
                    font.pixelSize: 14
                    Layout.alignment: Qt.AlignTop
                    Accessible.role: Accessible.Button
                    Accessible.name: root.uiRevision >= 0
                        ? root.tr("action.close", "Close") : ""
                    ToolTip.visible: hovered && root.prefs.tooltipsEnabled
                    ToolTip.text: root.uiRevision >= 0
                        ? root.tr("action.close", "Close") : ""
                    onClicked: {
                        root.updatePrefs({ missingSecondaryBannerAcknowledged: true })
                        root.emitPrefs()
                    }
                    background: Rectangle {
                        color: combinedSecondaryCloseButton.hovered
                            ? Qt.rgba(1, 1, 1, 0.2) : "transparent"
                        radius: root.uiTheme.radiusSm
                    }
                    contentItem: Label {
                        text: combinedSecondaryCloseButton.text
                        color: "white"
                        font: combinedSecondaryCloseButton.font
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                }
            }
        }
    }

    // Drift detection banner. Stacks below the
    // backend status banner; clicking "Details" opens
    // DriftDetectionDialog so the user can pick a resolution. Stands down
    // while `combinedAmberBanner` carries the same warning.
    Rectangle {
        id: driftBanner
        anchors.top: combinedAmberBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.driftBannerHeight
        visible: root.driftBannerVisible && !root.combinedAmberBannerVisible
        color: "#d4a017"     // amber — same family as ReviewDiff lacks-elevation
        z: 99
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                // An empty service rulebook (fresh install /
                // wiped service DB) gets its own honest wording; the generic
                // "do not all agree" text sent the user diffing three legs
                // when the real state was simply "nothing applied yet".
                text: root._serviceRulesEmpty
                    ? root.tr("status.drift-banner-empty-service",
                        "The routing service has no rules yet — apply your rules via Details.")
                    : root.tr("status.drift-banner",
                        "Rules in the file, the app, and the service do not all agree.")
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("rules.state.check-now", "Check now")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr("rules.state.check-now-tooltip",
                    "Compare the rules on screen with your rules file and with the service right now.")
                onClicked: root.driftController._driftRecheckNow(true)
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("status.drift-banner-details", "Details…")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "status.drift-banner-details-description",
                    "Open the drift dialog to inspect hashes and pick a resolution.")
                onClicked: root.driftController._openDriftDialog()
            }
        }
    }

    // Quiet "Merge available" banner. Informational (muted
    // green), NOT an alarm: it offers to merge a diverged bound file with the
    // service's active rules. Distinct surface from the amber drift banner so
    // re-promoting `file-vs-service` never re-raises the app↔service alarm.
    Rectangle {
        id: mergeBanner
        anchors.top: driftBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.mergeBannerHeight
        visible: root.mergeBannerVisible
        color: "#2d6a4f"     // muted green — informational
        z: 98
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.tr("status.merge-banner",
                    "Your rules file and the app's rules have diverged — you can merge them.")
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("dialog.drift.merge", "Merge…")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "status.merge-banner-open-description",
                    "Open the merge dialog to combine the file and the app rules.")
                onClicked: root.driftController._openMergeDialog()
            }
        }
    }

    // Compatibility banner. Fourth in the stack
    // (backend → drift → merge → compat). Red-toned because protocol drift
    // typically means the app stops working until one side updates;
    // amber would understate the severity.
    Rectangle {
        id: compatBanner
        anchors.top: mergeBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.compatBannerHeight
        visible: root.compatBannerVisible
        color: "#c0392b"
        z: 98
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.tr(
                    "status.compat-banner-body",
                    "Incompatible versions: service {sv} (protocol {sp}), app {gv} (protocol {gp}). Update the {target}.")
                    .replace("{sv}", root._compatServiceVersion || "—")
                    .replace("{sp}", String(root._compatServiceProtocol))
                    .replace("{gv}", root._compatGuiVersion || "—")
                    .replace("{gp}", String(root._compatGuiProtocol))
                    .replace("{target}",
                        root.compatBannerDirection === "gui-older"
                            ? root.tr("status.compat-banner-target-gui", "app")
                            : root.tr("status.compat-banner-target-service", "service"))
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("status.compat-banner-update", "Open updates page")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "status.compat-banner-update-description",
                    "Open the project's releases page in the default browser.")
                onClicked: {
                    var base = String((root.context.about || {}).projectUrl || "")
                    if (base !== "") {
                        Qt.openUrlExternally(base + "/releases")
                    }
                }
            }
        }
    }

    // The bound-file out-of-date reminder used to live
    // here as an amber top banner; it now lives in the footer as a compact
    // orange chip (see `boundFileChip`). No top-stack slot is reserved for it.

    // Secondary-adapter banner (now fourth in the stack:
    // backend → drift → compat → bound-file → secondary). Dual-mode: amber
    // re-confirm prompt when the secondary binding is stale (adapter
    // reinstalled), else a blue/info VPN split-routing explanation with a
    // one-click switch to a full tunnel (mode B).
    Rectangle {
        id: secondaryAdapterBanner
        anchors.top: compatBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        // Content-driven height so the (now wrapping) explanation is never
        // clipped; never shorter than the 36px single-line minimum.
        // Stands down while `combinedAmberBanner` carries the same warning.
        height: (root.secondaryBannerVisible && !root.combinedAmberBannerVisible)
            ? Math.max(36, secondaryBannerRow.implicitHeight + 2 * root.uiTheme.spacingSm)
            : 0
        visible: root.secondaryBannerVisible && !root.combinedAmberBannerVisible
        color: (root.secondaryReconfirmVisible || root.secondaryUnresolvedVisible)
            ? "#d4a017" : "#2c6fbb"
        z: 96
        RowLayout {
            id: secondaryBannerRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                // VPN-split case: informational ONLY — no forced
                // mode switch. The routing-mode choice (prefer-secondary /
                // strict) lives in Settings → Routing; the earlier one-click
                // button hardcoded an invalid "prefer-secondary" wire slug that
                // the service rejected as MalformedRequest. The re-confirm case
                // keeps its action button.
                // The adapter name comes from JS function calls
                // (_vpnConflictSecondaryDisplayName), whose property reads Qt
                // does NOT track, so the ONLY reactive read used to be
                // secondaryReconfirmVisible. That evaluated the name once at
                // cold start (before the VPN adapter is enumerated → ""). The
                // ternary with a DIRECT root.uiRevision read registers the
                // dependency, so the whole expression (name included) recomputes
                // on every uiRevision bump — a mode switch or a live VPN-up
                // refresh.
                text: root.uiRevision >= 0
                    ? (root.secondaryReconfirmVisible
                        ? root.tr("status.secondary-reconfirm",
                            "Your secondary adapter \"{name}\" looks reinstalled (new ID). Re-confirm it so the stored binding matches.")
                            .replace("{name}", String(root.prefs.selectedSecondaryInterfaceName || ""))
                        : (root.secondaryUnresolvedVisible
                            ? root.tr("status.secondary-unresolved",
                                "The additional adapter \"{name}\" assigned to your rules isn't available right now — start it, or choose a different adapter in Interfaces and routes. While it's missing, matching traffic is blocked (leak protection) instead of leaking over your main connection.")
                                .replace("{name}", String(root.prefs.selectedSecondaryInterfaceName || ""))
                            : root.tr("status.vpn-split-conflict",
                                "Your additional adapter \"{name}\" is connected, but NetRuleRouter keeps general traffic on your main connection — only your {n} rule(s) go through it. To route all traffic through it, change the routing mode in Settings → Routing behavior.")
                                .replace("{name}", root.interfacesRolesController._vpnConflictSecondaryDisplayName())
                                .replace("{n}", String(root.interfacesRolesController._enabledSecondaryRuleCount()))))
                    : ""
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                // Actionable for the re-confirm case (adopt the healed id) and
                // the unresolved case (jump to Interfaces & routes to start /
                // re-select the adapter); the VPN-split banner is a pure
                // explainer, so it shows no action button.
                visible: root.secondaryReconfirmVisible || root.secondaryUnresolvedVisible
                text: root.secondaryReconfirmVisible
                    ? root.tr("status.secondary-reconfirm-button", "Re-confirm adapter")
                    : root.tr("status.secondary-unresolved-button", "Open Interfaces and routes")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.secondaryReconfirmVisible
                    ? root.tr("status.secondary-reconfirm-button-description",
                        "Update the stored secondary adapter binding to the reinstalled adapter.")
                    : root.tr("status.secondary-unresolved-button-description",
                        "Open Interfaces and routes to start or re-select the additional adapter.")
                onClicked: {
                    if (root.secondaryReconfirmVisible) root.interfacesRolesController._reconfirmSecondaryBinding()
                    else root.section = "interfaces-routes"
                }
            }
            // Close (X) — session-scoped dismiss of the informational VPN-split
            // banner (Problem 3). Only the pure-explainer VPN-split case is
            // dismissible; the actionable amber re-confirm variant keeps its
            // action button and no close affordance.
            ThemedButton {
                theme: root.uiTheme
                // Only the pure-explainer VPN-split banner is dismissible; the
                // actionable re-confirm / not-found states keep their action
                // button and no close affordance.
                visible: !root.secondaryReconfirmVisible && !root.secondaryUnresolvedVisible
                Layout.preferredWidth: 32
                Layout.preferredHeight: 28
                text: "✕"
                Accessible.role: Accessible.Button
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("status.vpn-split-conflict-dismiss", "Dismiss")
                    : ""
                ToolTip.visible: hovered && root.prefs.tooltipsEnabled
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("status.vpn-split-conflict-dismiss", "Dismiss")
                    : ""
                onClicked: {
                    // Persist a per-adapter acknowledgment, the
                    // property the `visible` binding actually honours via
                    // `_vpnSplitAcked()`. The old handler wrote an UNDECLARED
                    // `vpnSplitBannerDismissed` property, which threw at runtime
                    // and never closed the banner. `updatePrefs` bumps uiRevision
                    // so the banner hides at once; `emitPrefs` persists the ack so
                    // it stays hidden for THIS secondary adapter across relaunches
                    // (a genuinely different adapter re-shows the explainer).
                    root.updatePrefs({
                        secondarySplitAckAdapterName: root.interfacesRolesController._vpnConflictSecondaryDisplayName()
                    })
                    root.emitPrefs()
                }
            }
            // Close (X) — persistent dismiss of the amber "additional adapter
            // not found" variant. Only the unresolved variant is dismissible;
            // the re-confirm variant keeps its action button and the VPN-split
            // explainer has its own close above. The acknowledgement is persisted
            // and auto-cleared by the window once the adapter resolves again, so
            // a later disappearance re-shows the banner.
            ToolButton {
                id: secondaryUnresolvedCloseButton
                visible: root.secondaryUnresolvedVisible
                text: "✕"
                implicitWidth: 24
                implicitHeight: 24
                font.pixelSize: 14
                Layout.alignment: Qt.AlignTop
                Accessible.role: Accessible.Button
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("action.close", "Close") : ""
                ToolTip.visible: hovered && root.prefs.tooltipsEnabled
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("action.close", "Close") : ""
                onClicked: {
                    root.updatePrefs({ missingSecondaryBannerAcknowledged: true })
                    root.emitPrefs()
                }
                background: Rectangle {
                    color: secondaryUnresolvedCloseButton.hovered
                        ? Qt.rgba(1, 1, 1, 0.2) : "transparent"
                    radius: root.uiTheme.radiusSm
                }
                contentItem: Label {
                    text: secondaryUnresolvedCloseButton.text
                    color: "white"
                    font: secondaryUnresolvedCloseButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }

    // "no active rules" notice. Last in the top banner
    // stack. Info-blue (not an alarm): the service is connected but its rule
    // set is empty, so nothing is enforced — commonly right after a state
    // reset. Points the user at the Rules section to add rules or import a
    // preset. `emptyRulesBannerVisible` gates it to the real, settled count.
    Rectangle {
        id: emptyRulesBanner
        anchors.top: secondaryAdapterBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.emptyRulesBannerHeight
        visible: root.emptyRulesBannerVisible
        color: "#2c6fbb"     // info blue — informational, not an error
        z: 95
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.emptyRulesBannerHasLocalRules
                    ? root.tr("status.unapplied-rules-banner",
                        "The app has rules that aren't applied yet — the service is enforcing none. Apply them now.")
                    : root.tr("status.empty-rules-banner",
                        "No rules are active — the service isn't routing anything. The rule set is empty (it may have been reset). Add rules or import a preset.")
                verticalAlignment: Text.AlignVCenter
                elide: Text.ElideRight
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            // "Apply app state": push the app's local rules to the service
            // straight from this banner (reuses the drift-dialog action), shown only
            // when there are local rules to apply. The banner is connected-only, so
            // this always takes the online review flow.
            ThemedButton {
                theme: root.uiTheme
                visible: root.emptyRulesBannerHasLocalRules
                // Primary affordance: when the service is empty but the
                // app has rules, applying them is the recommended action, so lead
                // with it (highlighted) rather than "Open Rules".
                highlighted: true
                text: root.tr("dialog.drift.apply-gui", "Apply app state")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.drift.apply-gui-description",
                    "Open the review flow and push the current app state to the service.")
                onClicked: root.driftController._driftApplyGuiState()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("status.empty-rules-banner-button", "Open Rules")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "status.empty-rules-banner-button-description",
                    "Open the Rules section to add rules or import a preset.")
                onClicked: root.section = "rules"
            }
        }
    }

    // The former "app rules not enforced" amber banner was
    // removed from the top banner stack and relocated to the notifications
    // centre (footer bell chip + NotificationCenterPopup). See
    // `activeNotifications` / `appUnresolvedNoticeActive` above.

    // "The service is running but applies nothing" notice. Sits between the
    // empty-rules notice and the block-all warning. Amber, not red: the state
    // is recoverable and often one click away — but it must be loud, because
    // from outside it looks identical to a healthy service. Gated by
    // `policyInactiveBannerVisible`, which stands down for every banner that
    // already explains the same cause (see the window-side predicate).
    Rectangle {
        id: policyInactiveBanner
        anchors.top: emptyRulesBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.policyInactiveBannerVisible
            ? Math.max(36, policyInactiveRow.implicitHeight + 2 * root.uiTheme.spacingSm)
            : 0
        visible: root.policyInactiveBannerVisible
        color: "#d4a017"     // amber — same family as the other warning banners
        z: 94
        RowLayout {
            id: policyInactiveRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                text: "⚠"
                color: "white"
                Layout.alignment: Qt.AlignTop
                Accessible.ignored: true
            }
            Label {
                Layout.fillWidth: true
                color: "white"
                // Two halves of one story: the app holds an adapter the service
                // never received (fixable here), or no adapter is assigned at
                // all (nothing to send — say where to assign one instead).
                text: root.policyInactiveActionable
                    ? root.tr("status.policy-inactive-not-delivered",
                        "The service is running, but your rules are not being applied: it never received which adapter to send them through. Send it now.")
                    : root.tr("status.policy-inactive-no-adapter",
                        "The service is running, but your rules are not being applied: no additional adapter is assigned to them yet, so there is nowhere to route them. Assign one in Interfaces and routes.")
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                visible: root.policyInactiveActionable
                highlighted: true
                text: root.tr("status.policy-inactive-send", "Send adapter to the service")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "status.policy-inactive-send-description",
                    "Send the additional adapter selected in the app to the background service so your rules start being routed.")
                onClicked: root.resendRouteBindingToService()
            }
        }
    }

    // Block-all fail-closed warning. Last in the top banner stack.
    // Amber (a live, deliberately-protective state that is currently blocking
    // unknown traffic — not a hard error), content-driven height so the
    // wrapping explanation is never clipped. Gated by `blockAllBannerVisible`
    // (posture armed + the warnKillSwitchBlockAll pref opt-in + not
    // acknowledged). The close button persists an acknowledgement that hides
    // the banner across restarts while the posture stays armed; the window
    // clears that acknowledgement the moment the posture disarms, so the next
    // activation shows it again. A permanent opt-out remains the
    // Settings -> Routing behavior checkbox.
    Rectangle {
        id: blockAllBanner
        anchors.top: policyInactiveBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.blockAllBannerVisible
            ? Math.max(36, blockAllBannerRow.implicitHeight + 2 * root.uiTheme.spacingSm)
            : 0
        visible: root.blockAllBannerVisible
        color: "#d4a017"     // amber — same family as the other warning banners
        z: 94
        RowLayout {
            id: blockAllBannerRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.tr("settings.routing.kill-switch.block-all-active-banner",
                    "Leak protection is blocking unknown traffic: the additional adapter can't be found (down, not started, or reinstalled under a new ID). Sites open as they become known; reconnect the VPN or re-bind the adapter to lift the block.")
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("status.secondary-unresolved-button", "Open Interfaces and routes")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr("status.secondary-unresolved-button-description",
                    "Open Interfaces and routes to start or re-select the additional adapter.")
                onClicked: root.section = "interfaces-routes"
            }
            ToolButton {
                id: blockAllBannerCloseButton
                text: "✕"
                implicitWidth: 24
                implicitHeight: 24
                font.pixelSize: 14
                Layout.alignment: Qt.AlignTop
                Accessible.role: Accessible.Button
                // The `uiRevision >= 0 ? tr(...) : ""` guard forces the label to
                // recompute once the locale catalog is populated (an in-place
                // mutation Qt does not track on its own); without it the tooltip
                // freezes on the cold-start English fallback in every language.
                Accessible.name: root.uiRevision >= 0
                    ? root.tr("action.close", "Close") : ""
                ToolTip.visible: hovered && root.prefs.tooltipsEnabled
                ToolTip.text: root.uiRevision >= 0
                    ? root.tr("action.close", "Close") : ""
                onClicked: {
                    root.updatePrefs({ killSwitchBannerAcknowledged: true })
                    root.emitPrefs()
                }
                background: Rectangle {
                    color: blockAllBannerCloseButton.hovered
                        ? Qt.rgba(1, 1, 1, 0.2) : "transparent"
                    radius: root.uiTheme.radiusSm
                }
                contentItem: Label {
                    text: blockAllBannerCloseButton.text
                    color: "white"
                    font: blockAllBannerCloseButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }

    // One-time offer to remember the folder a rule file was just saved to or
    // loaded from, shown ONLY while no rule-set folder is configured — the
    // point is to reveal a feature the user cannot know about yet. Once a
    // folder IS configured, an export elsewhere is a deliberate one-off (a
    // copy for a colleague, a backup) and asking about it every time would be
    // pure noise. Informational, dismissible, and never shown again once
    // answered either way.
    Rectangle {
        id: rulesFolderSuggestionBanner
        anchors.top: blockAllBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.rulesFolderSuggestionVisible
            ? Math.max(36, rulesFolderSuggestionRow.implicitHeight + 2 * root.uiTheme.spacingSm)
            : 0
        visible: root.rulesFolderSuggestionVisible
        color: "#2f7d5b"     // muted green — informational, same family as merge
        z: 93
        RowLayout {
            id: rulesFolderSuggestionRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.tr("status.rules-folder-suggestion",
                    "Keep your rule sets in this folder? It then becomes the place the app loads and saves rule sets from.")
                    + " " + root.rulesFolderSuggestionPath
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("status.rules-folder-suggestion-accept", "Remember this folder")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: root.acceptRulesFolderSuggestion()
            }
            ToolButton {
                id: rulesFolderSuggestionCloseButton
                text: "✕"
                implicitWidth: 24
                implicitHeight: 24
                font.pixelSize: 14
                Layout.alignment: Qt.AlignTop
                Accessible.role: Accessible.Button
                Accessible.name: root.uiRevision >= 0 ? root.tr("action.close", "Close") : ""
                ToolTip.visible: hovered && root.prefs.tooltipsEnabled
                ToolTip.text: root.uiRevision >= 0 ? root.tr("action.close", "Close") : ""
                onClicked: root.dismissRulesFolderSuggestion()
                background: Rectangle {
                    color: rulesFolderSuggestionCloseButton.hovered
                        ? Qt.rgba(1, 1, 1, 0.2) : "transparent"
                    radius: root.uiTheme.radiusSm
                }
                contentItem: Label {
                    text: rulesFolderSuggestionCloseButton.text
                    color: "white"
                    font: rulesFolderSuggestionCloseButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }

    // The service refused a rule set that reached its database outside the app
    // and fell back to the last verified one. Red because the enforced rules are
    // not the ones the user last saw; the wording stays neutral because the
    // cause is as likely a restored backup as anything else. Not dismissible —
    // it stands down when the alert is acknowledged in Diagnostics.
    Rectangle {
        id: revisionIntegrityBanner
        anchors.top: rulesFolderSuggestionBanner.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: root.revisionIntegrityAlertActive
            ? Math.max(36, revisionIntegrityRow.implicitHeight + 2 * root.uiTheme.spacingSm)
            : 0
        visible: root.revisionIntegrityAlertActive
        color: "#c0392b"
        z: 92
        RowLayout {
            id: revisionIntegrityRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: root.uiTheme.spacingMd
            anchors.rightMargin: root.uiTheme.spacingMd
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                color: "white"
                text: root.tr("status.revision-integrity-banner",
                    "The rule set was changed outside the app, so it was not applied — the service is running on the last verified version.")
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("status.drift-banner-details", "Details…")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "status.revision-integrity-banner-button-description",
                    "Open Diagnostics to see which rule set was rejected and confirm the alert.")
                onClicked: root.requestSectionChange("diagnostics")
            }
        }
    }
}
