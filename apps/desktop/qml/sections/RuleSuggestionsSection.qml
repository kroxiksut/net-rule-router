// Suggested addresses: hosts the sites you route turned out to need, plus the
// ones you previously told the service to stop offering. One table, grouped
// by registrable domain (a subdomain-by-subdomain list was unreadable once a
// single site pulled in a dozen hosts of the same domain) — every action here
// acts on a domain as a whole ("domain" + "*.domain", the same shape the
// rules table already understands), the expandable host list underneath is
// read-only detail on how that domain earned its place.
//
// There is deliberately no "keep on the main route" button: doing nothing
// already leaves a pending domain there, and the intro says so. A dismissed
// domain only stops being offered — "Allow again" lifts that and nothing
// else.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../components"
import "../lib/pure.js" as Pure

ColumnLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    /// `newest` | `consumers` | `name`.
    property string sortMode: "newest"
    /// Hostname whose dependents are being shown alone; empty shows all.
    property string consumerFilter: ""
    /// Free-text search across domain, observed hosts, and consumer names.
    property string searchQuery: ""
    /// Domains ticked for the footer's bulk actions.
    property var checkedDomains: []
    /// How many domain groups render before "Show N more" -- reset whenever
    /// the visible set's shape changes so a fresh search/filter/sort starts
    /// collapsed again. Keeps one heavily-linked site's long list short
    /// without touching the domain-group model itself.
    property int visibleGroupLimit: 8
    onSearchQueryChanged: section.visibleGroupLimit = 8
    onConsumerFilterChanged: section.visibleGroupLimit = 8
    onSortModeChanged: section.visibleGroupLimit = 8
    /// contentY to restore once a mutation reshapes the list -- negative
    /// means nothing pending. Rebuilding the group model otherwise snaps
    /// the scroll position back to zero on every delete/accept/dismiss.
    property real _pendingScrollY: -1

    function _refresh() {
        if (typeof root.refreshAutoRuleCandidates === "function") root.refreshAutoRuleCandidates()
        if (typeof root.refreshAutoRuleDismissed === "function") root.refreshAutoRuleDismissed()
    }
    // Loaded lazily (see Main.qml's StackLayout) — fetch once on first show,
    // and again whenever the user comes back to this page: the service's
    // pending set can change while the user was elsewhere in the app.
    Component.onCompleted: section._refresh()
    onVisibleChanged: if (visible) section._refresh()

    // Grouped ONCE per data change (candidates/dismissed arrays), filtered +
    // sorted ONCE per UI change (sort/filter). Delegates below only ever read
    // the already-computed group objects — never re-derive anything.
    readonly property var mergedGroups: Pure.groupAutoRuleRows(
        root.autoRuleCandidates, root.autoRuleDismissed)
    readonly property var consumerFilteredGroups: Pure.filterAutoRuleGroups(
        section.mergedGroups, section.consumerFilter)
    readonly property var displayGroups: Pure.sortAutoRuleGroups(
        Pure.searchAutoRuleGroups(section.consumerFilteredGroups, section.searchQuery),
        section.sortMode)
    // Truncated slice actually handed to the Repeater -- see
    // `visibleGroupLimit` above. Selection/search/sort keep reading the full
    // `displayGroups` so off-screen matches stay selectable.
    readonly property var visibleDisplayGroups: section.displayGroups.slice(0, section.visibleGroupLimit)
    readonly property int hiddenGroupCount: Math.max(0, section.displayGroups.length - section.visibleGroupLimit)

    onMergedGroupsChanged: section._restoreScrollPositionIfPending()

    // Membership as a map, rebuilt once per selection change: "select all" puts
    // every visible domain in the list, and a linear scan per row would make
    // each toggle cost rows x selected.
    readonly property var checkedSet: {
        var set = ({})
        for (var i = 0; i < section.checkedDomains.length; i += 1) {
            set[section.checkedDomains[i]] = true
        }
        return set
    }
    function _isChecked(domain) { return section.checkedSet[domain] === true }
    function _setChecked(domain, on) {
        var next = []
        for (var i = 0; i < section.checkedDomains.length; i += 1) {
            if (section.checkedDomains[i] !== domain) next.push(section.checkedDomains[i])
        }
        if (on) next.push(domain)
        section.checkedDomains = next
    }
    // Tri-state for the toolbar "select all" checkbox: 0 none of the
    // currently visible groups are checked, 1 all of them are, 2 some are.
    // Reads only `displayGroups`/`checkedDomains` -- one O(visible) pass per
    // change, never a per-row rescan, so it stays flat as the list grows.
    readonly property int visibleCheckedState: {
        var groups = section.displayGroups
        if (groups.length === 0) return 0
        var anyChecked = false
        var anyUnchecked = false
        for (var i = 0; i < groups.length; i += 1) {
            if (section._isChecked(groups[i].domain)) anyChecked = true
            else anyUnchecked = true
            if (anyChecked && anyUnchecked) return 2
        }
        return anyChecked ? 1 : 0
    }
    // Checks every visible group, or clears just the visible ones if any are
    // already checked -- selections outside the current search/filter are
    // left alone, mirroring the rules table's header checkbox.
    function _toggleSelectAllVisible() {
        var groups = section.displayGroups
        if (groups.length === 0) return
        var next
        if (section.visibleCheckedState === 0) {
            next = section.checkedDomains.slice()
            for (var i = 0; i < groups.length; i += 1) {
                if (next.indexOf(groups[i].domain) < 0) next.push(groups[i].domain)
            }
        } else {
            var visible = {}
            for (var j = 0; j < groups.length; j += 1) visible[groups[j].domain] = true
            next = []
            for (var k = 0; k < section.checkedDomains.length; k += 1) {
                if (!visible[section.checkedDomains[k]]) next.push(section.checkedDomains[k])
            }
        }
        section.checkedDomains = next
    }
    // Backed by `root.suggestionsExpandedDomains` so an open host list
    // survives switching tabs, not just this section's own lifetime.
    function _isExpanded(domain) { return !!root.suggestionsExpandedDomains[domain] }
    function _toggleExpanded(domain) {
        var copy = Object.assign({}, root.suggestionsExpandedDomains)
        copy[domain] = !copy[domain]
        root.suggestionsExpandedDomains = copy
    }

    // How many "needed by" sites a group shows before the rest fold away. A
    // popular address is wanted by a dozen sites; listing them all turned the
    // card into a page. Section-local: unlike the host list, this is a reading
    // convenience, not a place the user leaves work half-done.
    readonly property int consumersShownCollapsed: 3
    property var expandedConsumerDomains: ({})
    function _consumersExpanded(domain) { return !!section.expandedConsumerDomains[domain] }
    function _toggleConsumers(domain) {
        // Reassign: mutating the object in place does not re-evaluate bindings.
        var copy = Object.assign({}, section.expandedConsumerDomains)
        copy[domain] = !copy[domain]
        section.expandedConsumerDomains = copy
    }
    function _shownConsumers(group) {
        var all = group.consumers || []
        return section._consumersExpanded(group.domain)
            ? all : all.slice(0, section.consumersShownCollapsed)
    }

    function _groupByDomain(domain) {
        for (var i = 0; i < section.displayGroups.length; i += 1) {
            if (section.displayGroups[i].domain === domain) return section.displayGroups[i]
        }
        return null
    }
    // Ids across every checked domain, split by status — what the footer's
    // "Add" / "Never suggest" / "Allow again" buttons act on.
    function _checkedPendingIds() {
        var out = []
        for (var i = 0; i < section.checkedDomains.length; i += 1) {
            var g = section._groupByDomain(section.checkedDomains[i])
            if (g) out = out.concat(g.pendingIds)
        }
        return out
    }
    function _checkedDismissedIds() {
        var out = []
        for (var i = 0; i < section.checkedDomains.length; i += 1) {
            var g = section._groupByDomain(section.checkedDomains[i])
            if (g) out = out.concat(g.dismissedIds)
        }
        return out
    }

    /// Every id the service currently holds, pending or dismissed, across
    /// every domain -- not just what the search/filter/pagination happen to
    /// show. What "Clear all" forgets.
    function _allIds() {
        var out = []
        for (var i = 0; i < section.mergedGroups.length; i += 1) {
            var g = section.mergedGroups[i]
            out = out.concat(g.pendingIds).concat(g.dismissedIds)
        }
        return out
    }
    /// Snapshots the list's scroll offset right before a mutation goes out --
    /// the reply arrives async and rebuilds the group model, so the restore
    /// itself happens later, off `onMergedGroupsChanged`.
    function _rememberScrollPosition() {
        var flick = suggestionsScroll.contentItem
        if (flick) section._pendingScrollY = flick.contentY
    }
    function _restoreScrollPositionIfPending() {
        if (section._pendingScrollY < 0) return
        var target = section._pendingScrollY
        section._pendingScrollY = -1
        Qt.callLater(function() {
            var flick = suggestionsScroll.contentItem
            if (!flick) return
            var maxY = Math.max(0, flick.contentHeight - flick.height)
            flick.contentY = Math.min(target, maxY)
        })
    }

    function _acceptIds(ids) {
        if (!ids || ids.length === 0) return
        section._rememberScrollPosition()
        root.acceptAutoRuleCandidates(ids)
    }
    function _dismissIds(ids) {
        if (!ids || ids.length === 0) return
        section._rememberScrollPosition()
        root.dismissAutoRuleCandidates(ids)
    }
    function _restoreIds(ids) {
        if (!ids || ids.length === 0) return
        section._rememberScrollPosition()
        root.restoreAutoRuleDismissed(ids)
    }
    /// Erases the answer rather than recording one, so the address comes back
    /// on its own evidence — every id of the group, answered or not.
    function _forgetIds(ids) {
        if (!ids || ids.length === 0) return
        section._rememberScrollPosition()
        root.forgetAutoRuleCandidates(ids)
    }
    function _checkedAllIds() {
        return section._checkedPendingIds().concat(section._checkedDismissedIds())
    }
    function _clearCheckedSelection() { section.checkedDomains = [] }

    /// "How do you know?" — the user is being asked to change their own
    /// routing, so the evidence travels with the offer.
    function _evidence(host) {
        var parts = []
        var signal = String(host.signal || "")
        if (signal !== "") parts.push(root.tr("tray.auto-rules.signal." + signal, signal))
        var seen = Number(host.observations || 0)
        if (seen > 0) {
            parts.push(root.tr("tray.auto-rules.detail-observations", "seen in {count} visits")
                .replace("{count}", String(seen)))
        }
        var affinity = Number(host.affinity || 0)
        if (affinity > 0) {
            parts.push(root.tr("tray.auto-rules.detail-affinity",
                    "belongs to this site {percent}% of the time")
                .replace("{percent}", String(Math.round(affinity * 100))))
        }
        return parts.join(" · ")
    }
    /// How the host behaves on the main route — empty unless the service
    /// reached a verdict (a guess here would be worse than silence).
    function _behaviorText(host) {
        var slug = String(host.primaryBehavior || "")
        if (slug === "responds")
            return root.tr("rules.suggestions.inbox.behavior-responds", "already works without the tunnel")
        if (slug === "stalls")
            return root.tr("rules.suggestions.inbox.behavior-stalls", "connections to it stall on the main route")
        return ""
    }
    function _isPrimaryConsumer(consumer) {
        return String((consumer || {}).route || "") === "primary"
    }
    /// Copies exactly the clicked site's name, not the whole "Needed by" cell —
    /// same clipboard bridge and confirmation the Diagnostics tables use.
    function _copyConsumerName(name) {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.copyToClipboard !== "function") return
        nrrNativeBridge.copyToClipboard(String(name))
        root.statusLine = root.tr("status.copied-to-clipboard", "Copied to clipboard.")
    }
    function _sortLabel(mode) {
        if (mode === "consumers") return root.tr("rules.suggestions.inbox.sort-consumers", "By number of sites")
        if (mode === "name") return root.tr("rules.suggestions.inbox.sort-name", "By name")
        return root.tr("rules.suggestions.inbox.sort-newest", "Newest first")
    }

    Label {
        Layout.fillWidth: true
        wrapMode: Text.Wrap
        textFormat: Text.StyledText
        color: root.textColor
        // Tracks whether there is any data at all, not whether the current
        // search/filter matches something -- a zero-match search keeps this
        // intro on screen and puts its own message inside the list frame
        // below instead, so the rest of the layout does not collapse while
        // the user is still typing.
        text: section.mergedGroups.length > 0
            ? root.tr("rules.suggestions.table.intro",
                "Every address below was pulled in by a site you route. Adding one <b>sends it through "
                + "the additional route together with the site that needs it</b> — <i>anything you leave "
                + "alone keeps going through the main route</i>. A dismissed address <i>only stops being "
                + "offered</i>; \"Allow again\" lifts that suppression and nothing else.")
            : root.tr("rules.suggestions.inbox.empty", "Nothing is waiting for an answer right now.")
        Accessible.role: Accessible.StaticText
        // Screen readers get plain text — strip the styling tags used for visual emphasis.
        Accessible.name: text.replace(/<\/?[a-z]+>/gi, "")
    }

    RowLayout {
        Layout.fillWidth: true
        // Data may exist even when the current search/filter shows nothing --
        // the row (and its search box) must stay reachable so it can be cleared.
        visible: section.mergedGroups.length > 0
        spacing: root.uiTheme.spacingSm

        Label {
            text: root.tr("rules.suggestions.inbox.sort", "Sort")
            color: root.mutedTextColor
        }
        ThemedComboBox {
            id: sortCombo
            theme: root.uiTheme
            Layout.preferredWidth: 220
            model: ["newest", "consumers", "name"]
            labelResolver: function(item) { return section._sortLabel(String(item)) }
            displayText: root.uiRevision >= 0 ? section._sortLabel(section.sortMode) : ""
            currentIndex: model.indexOf(section.sortMode)
            onActivated: section.sortMode = String(model[currentIndex])
            Accessible.role: Accessible.ComboBox
            Accessible.name: root.tr("rules.suggestions.inbox.sort", "Sort")
        }
        Label {
            text: root.tr("action.search", "Search")
            color: root.mutedTextColor
        }
        ThemedTextField {
            id: suggestionsSearchField
            theme: root.uiTheme
            Layout.preferredWidth: 220
            placeholderText: root.uiRevision >= 0
                ? root.tr("rules.suggestions.inbox.search-placeholder",
                    "Search by domain, host, or site")
                : ""
            text: section.searchQuery
            onTextChanged: section.searchQuery = text
            Accessible.role: Accessible.EditableText
            Accessible.name: root.tr("action.search", "Search")
        }
        ThemedButton {
            theme: root.uiTheme
            visible: section.searchQuery !== ""
            text: root.tr("action.clear", "Clear")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: { section.searchQuery = ""; suggestionsSearchField.text = "" }
        }
        CheckBox {
            id: selectAllVisibleCheckBox
            tristate: true
            checkState: section.visibleCheckedState === 1
                ? Qt.Checked
                : (section.visibleCheckedState === 2 ? Qt.PartiallyChecked : Qt.Unchecked)
            onClicked: section._toggleSelectAllVisible()
            Accessible.role: Accessible.CheckBox
            Accessible.name: root.tr("rules.suggestions.inbox.select-all", "Select all")
            ToolTip.visible: hovered
            ToolTip.delay: 400
            ToolTip.text: root.tr("rules.suggestions.inbox.select-all-tooltip",
                "Select or clear every address currently shown.")
        }
        Label {
            text: root.tr("rules.suggestions.inbox.select-all", "Select all")
            color: root.textColor
        }
        Item { Layout.fillWidth: true }
        Label {
            visible: section.consumerFilter !== ""
            Layout.maximumWidth: 320
            elide: Text.ElideRight
            color: root.textColor
            text: root.tr("rules.suggestions.inbox.filter-active", "Showing only what {name} needs")
                .replace("{name}", section.consumerFilter)
        }
        ThemedButton {
            theme: root.uiTheme
            visible: section.consumerFilter !== ""
            text: root.tr("rules.suggestions.inbox.filter-clear", "Show everything")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section.consumerFilter = ""
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("rules.suggestions.inbox.action-forget-all", "Clear all")
            ToolTip.visible: hovered
            ToolTip.text: root.tr("rules.suggestions.inbox.action-forget-all-tooltip",
                "Removes every accumulated suggestion, answer and all, so addresses are offered again if they turn up next to your sites.")
            Accessible.role: Accessible.Button
            Accessible.name: text
            Accessible.description: ToolTip.text
            onClicked: clearAllSuggestionsConfirm.open()
        }
    }

    ScrollView {
        id: suggestionsScroll
        Layout.fillWidth: true
        Layout.fillHeight: true
        // Stays up whenever there is any data at all, so its frame does not
        // move while a search/filter narrows the match count to zero -- the
        // "nothing found" state renders INSIDE it instead, below.
        visible: section.mergedGroups.length > 0
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: suggestionsScroll.availableWidth
            spacing: root.uiTheme.spacingSm

            Label {
                Layout.fillWidth: true
                Layout.topMargin: root.uiTheme.spacingMd
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                visible: section.displayGroups.length === 0
                color: root.mutedTextColor
                text: root.tr("rules.suggestions.inbox.search-empty", "No addresses match your search.")
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }

            Repeater {
                model: section.visibleDisplayGroups
                // `modelData` on purpose: these are plain merged objects, and
                // a delegate declaring `required property` stops receiving
                // the context object.
                delegate: Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: groupBody.implicitHeight + 2 * root.uiTheme.spacingSm
                    color: "transparent"
                    border.width: root.uiTheme.borderWidth
                    border.color: root.uiTheme.stateDefaultBorder
                    radius: root.uiTheme.radiusSm

                    ColumnLayout {
                        id: groupBody
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.margins: root.uiTheme.spacingSm
                        spacing: root.uiTheme.spacingXs

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: root.uiTheme.spacingSm

                            CheckBox {
                                Layout.alignment: Qt.AlignTop
                                checked: section._isChecked(modelData.domain)
                                onToggled: section._setChecked(modelData.domain, checked)
                                Accessible.role: Accessible.CheckBox
                                Accessible.name: modelData.domain
                            }

                            ThemedButton {
                                Layout.alignment: Qt.AlignTop
                                theme: root.uiTheme
                                flat: true
                                text: section._isExpanded(modelData.domain)
                                    ? root.tr("settings.routing.show-less", "Hide details")
                                    : root.tr("settings.routing.show-more", "Show details")
                                Accessible.role: Accessible.Button
                                Accessible.name: text
                                onClicked: section._toggleExpanded(modelData.domain)
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2

                                Label {
                                    Layout.fillWidth: true
                                    wrapMode: Text.Wrap
                                    font.bold: true
                                    color: root.textColor
                                    text: modelData.domain
                                }
                                Label {
                                    Layout.fillWidth: true
                                    font.pixelSize: 12
                                    color: root.mutedTextColor
                                    text: root.tr("rules.suggestions.table.group-hosts", "{count} host(s) observed")
                                        .replace("{count}", String(modelData.hosts.length))
                                        + (modelData.pendingIds.length > 0
                                            ? " · " + root.tr("rules.suggestions.table.status-pending", "Pending")
                                                + " (" + modelData.pendingIds.length + ")"
                                            : "")
                                        + (modelData.dismissedIds.length > 0
                                            ? " · " + root.tr("rules.suggestions.table.status-dismissed", "Dismissed")
                                                + " (" + modelData.dismissedIds.length + ")"
                                            : "")
                                }

                                // Who needs it. Each site is a button: pressing
                                // one answers "what else does this site need?".
                                // Flow is a positioner with a single-row implicit
                                // size; the Item wrapper is what the layout sees.
                                Item {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: consumersFlow.height
                                    Flow {
                                        id: consumersFlow
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        spacing: 6
                                        Label {
                                            text: root.tr("rules.suggestions.inbox.needed-by", "Needed by:")
                                            color: root.mutedTextColor
                                            font.pixelSize: 12
                                        }
                                        Repeater {
                                            model: section._shownConsumers(modelData)
                                            delegate: ThemedButton {
                                                id: consumerButton
                                                theme: root.uiTheme
                                                font.pixelSize: 12
                                                text: String(modelData.hostname || "")
                                                    + (section._isPrimaryConsumer(modelData)
                                                        ? " · " + root.tr(
                                                            "rules.suggestions.inbox.consumer-on-primary",
                                                            "on the main route")
                                                        : "")
                                                Accessible.role: Accessible.Button
                                                Accessible.name: text
                                                Accessible.description: root.tr(
                                                    "rules.suggestions.inbox.consumer-copy-hint",
                                                    "Right-click to copy this name to the clipboard.")
                                                HoverHandler { cursorShape: Qt.PointingHandCursor }
                                                ToolTip.visible: consumerButton.hovered
                                                ToolTip.text: (section._isPrimaryConsumer(modelData)
                                                    ? root.tr(
                                                        "rules.suggestions.inbox.consumer-on-primary-hint",
                                                        "This site goes through the main route. If you move the address into the tunnel, this site's traffic to it goes there too.")
                                                        + " "
                                                    : "") + root.tr(
                                                        "rules.suggestions.inbox.consumer-copy-hint",
                                                        "Right-click to copy this name to the clipboard.")
                                                onClicked: section.consumerFilter = String(modelData.hostname || "")
                                                // Copying rides the right button so it cannot collide
                                                // with the left-click filter — a cell holds several
                                                // names and both actions target one of them.
                                                TapHandler {
                                                    acceptedButtons: Qt.RightButton
                                                    onTapped: section._copyConsumerName(
                                                        String(modelData.hostname || ""))
                                                }
                                            }
                                        }
                                        ThemedButton {
                                            theme: root.uiTheme
                                            flat: true
                                            font.pixelSize: 12
                                            visible: (modelData.consumers || []).length
                                                > section.consumersShownCollapsed
                                            text: section._consumersExpanded(modelData.domain)
                                                ? root.tr("settings.routing.show-less", "Hide details")
                                                : root.tr("rules.suggestions.inbox.show-more-count",
                                                        "Show {count} more")
                                                    .replace("{count}",
                                                        String((modelData.consumers || []).length
                                                            - section.consumersShownCollapsed))
                                            Accessible.role: Accessible.Button
                                            Accessible.name: text
                                            onClicked: section._toggleConsumers(modelData.domain)
                                        }
                                    }
                                }
                            }

                            ColumnLayout {
                                Layout.alignment: Qt.AlignTop
                                spacing: 4
                                ThemedButton {
                                    theme: root.uiTheme
                                    highlighted: true
                                    visible: modelData.pendingIds.length > 0
                                    text: root.tr("rules.suggestions.inbox.action-add", "Add to the additional route")
                                    Accessible.role: Accessible.Button
                                    Accessible.name: text
                                    onClicked: section._acceptIds(modelData.pendingIds)
                                }
                                ThemedButton {
                                    theme: root.uiTheme
                                    visible: modelData.pendingIds.length > 0
                                    text: root.tr("rules.suggestions.inbox.action-never", "Don't suggest again")
                                    Accessible.role: Accessible.Button
                                    Accessible.name: text
                                    onClicked: section._dismissIds(modelData.pendingIds)
                                }
                                ThemedButton {
                                    theme: root.uiTheme
                                    visible: modelData.dismissedIds.length > 0
                                    text: root.tr("rules.suggestions.rejected.restore", "Allow again")
                                    Accessible.role: Accessible.Button
                                    Accessible.name: text
                                    onClicked: section._restoreIds(modelData.dismissedIds)
                                }
                                ThemedButton {
                                    theme: root.uiTheme
                                    text: root.tr("rules.suggestions.inbox.action-forget", "Delete")
                                    ToolTip.visible: hovered
                                    ToolTip.text: root.tr("rules.suggestions.inbox.action-forget-tooltip",
                                        "Removes the record entirely, answer and all, so the address is offered again if it turns up next to your sites.")
                                    Accessible.role: Accessible.Button
                                    Accessible.name: text
                                    Accessible.description: ToolTip.text
                                    onClicked: section._forgetIds(
                                        modelData.pendingIds.concat(modelData.dismissedIds))
                                }
                            }
                        }

                        // Observed-host detail, collapsed by default. Purely
                        // informational: every action lives on the domain row
                        // above, this just explains WHICH hosts earned it.
                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.leftMargin: root.uiTheme.spacingLg
                            visible: section._isExpanded(modelData.domain)
                            spacing: root.uiTheme.spacingXxs

                            Repeater {
                                model: modelData.hosts
                                delegate: ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 0
                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: root.uiTheme.spacingSm
                                        Label {
                                            Layout.fillWidth: true
                                            wrapMode: Text.Wrap
                                            color: root.textColor
                                            text: modelData.matchKind === "suffix"
                                                ? "*." + modelData.match : modelData.match
                                        }
                                        Label {
                                            color: root.mutedTextColor
                                            font.pixelSize: 12
                                            text: modelData.status === "dismissed"
                                                ? root.tr("rules.suggestions.table.status-dismissed", "Dismissed")
                                                : root.tr("rules.suggestions.table.status-pending", "Pending")
                                        }
                                    }
                                    Label {
                                        Layout.fillWidth: true
                                        wrapMode: Text.Wrap
                                        font.pixelSize: 12
                                        color: root.textColor
                                        text: section._behaviorText(modelData)
                                        visible: text !== ""
                                    }
                                    Label {
                                        Layout.fillWidth: true
                                        wrapMode: Text.Wrap
                                        font.pixelSize: 12
                                        color: root.mutedTextColor
                                        text: section._evidence(modelData)
                                        visible: text !== ""
                                    }
                                }
                            }
                        }
                    }
                }
            }

            ThemedButton {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: root.uiTheme.spacingXs
                theme: root.uiTheme
                visible: section.hiddenGroupCount > 0
                text: root.tr("rules.suggestions.inbox.show-more-count", "Show {count} more")
                    .replace("{count}", String(section.hiddenGroupCount))
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: section.visibleGroupLimit += 8
            }
        }
    }

    // Confirmation modal for "Clear all" -- irreversible en masse, so it gets
    // the same Cancel/confirm prompt as the rules table's own bulk delete.
    Dialog {
        id: clearAllSuggestionsConfirm
        title: root.tr("rules.suggestions.inbox.clear-all-title", "Clear all suggested addresses?")
        modal: true
        standardButtons: Dialog.NoButton
        x: (parent && parent.width) ? (parent.width - width) / 2 : 0
        y: (parent && parent.height) ? (parent.height - height) / 2 : 0
        width: 440
        contentItem: ColumnLayout {
            spacing: root.uiTheme.spacingMd
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 400
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("rules.suggestions.inbox.clear-all-body",
                    "{count} suggested address(es) will be forgotten entirely — answers included — so "
                    + "they can be offered again later if they turn up next to your sites. This cannot be undone.")
                    .replace("{count}", String(section._allIds().length))
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: clearAllSuggestionsConfirm.close()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("rules.suggestions.inbox.clear-all-confirm", "Clear all")
                    onClicked: {
                        clearAllSuggestionsConfirm.close()
                        section._forgetIds(section._allIds())
                        section._clearCheckedSelection()
                    }
                }
            }
        }
    }

    RowLayout {
        Layout.fillWidth: true
        visible: section.checkedDomains.length > 0
        spacing: root.uiTheme.spacingSm

        Label {
            color: root.mutedTextColor
            text: root.tr("rules.suggestions.inbox.selected", "{count} selected")
                .replace("{count}", String(section.checkedDomains.length))
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("rules.suggestions.inbox.action-never", "Don't suggest again")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section._dismissIds(section._checkedPendingIds())
        }
        ThemedButton {
            theme: root.uiTheme
            highlighted: true
            text: root.tr("rules.suggestions.inbox.action-add", "Add to the additional route")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section._acceptIds(section._checkedPendingIds())
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("rules.suggestions.rejected.restore", "Allow again")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section._restoreIds(section._checkedDismissedIds())
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("rules.suggestions.inbox.action-forget", "Delete")
            ToolTip.visible: hovered
            ToolTip.text: root.tr("rules.suggestions.inbox.action-forget-tooltip",
                "Removes the record entirely, answer and all, so the address is offered again if it turns up next to your sites.")
            Accessible.role: Accessible.Button
            Accessible.name: text
            Accessible.description: ToolTip.text
            onClicked: {
                section._forgetIds(section._checkedAllIds())
                section._clearCheckedSelection()
            }
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr("rules.bulk.clear-selection", "Clear (Esc)")
            Accessible.role: Accessible.Button
            Accessible.name: text
            onClicked: section._clearCheckedSelection()
        }
        Item { Layout.fillWidth: true }
    }
}
