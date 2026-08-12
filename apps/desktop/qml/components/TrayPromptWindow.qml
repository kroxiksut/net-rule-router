import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

// Generic prompt window for the tray surface.
//
// The tray root is a `SystemTrayIcon`, which cannot host a balloon carrying
// buttons, so any tray notification that needs a decision from the user is
// rendered by this window. It is deliberately CONTENT-FREE: it knows about a
// title, one paragraph of body text, an optional compact list of detail rows,
// up to three action buttons and one subordinate dismiss button. Every string
// and every action id is injected by the caller, so the next tray notification
// reuses it without a single edit here.
//
// Shape of the injected values:
//   items            - array of { primaryText, secondaryText } (secondary optional)
//   primaryAction    - { label, actionId, accent } (accent renders as the
//   secondaryAction    highlighted/primary affordance; absent = plain button)
//   tertiaryAction
//   dismissAction    - { label, actionId }; rendered flat on the left. Closing
//                      the window or pressing Esc emits the SAME action id, so
//                      "closed it" and "clicked Dismiss" are one code path for
//                      the caller.
//
// The caller gets exactly one `actionTriggered(actionId)` per showing: the
// window latches after the first emission and closes itself.
//
// Theming: `theme` takes a ThemeTokens instance (the tray builds one from the
// theme slugs in its launch context). Painting degrades to neutral literals
// when it is absent; the Themed* button wrappers require it.
Window {
    id: promptWindow

    // ── Public API ───────────────────────────────────────────────────────────

    /// ThemeTokens instance supplying colours, spacing and typography.
    property var theme: null

    property string titleText: ""
    property string bodyText: ""
    /// Render `bodyText` as styled text (caller embeds e.g. `<b>` around a
    /// substituted value) instead of plain text. Off by default: most callers
    /// pass free-form strings (hostnames, adapter names) that must not be
    /// interpreted as markup.
    property bool bodyRichText: false
    /// Expand every row's `detailText`. Toggled by the caller's "Details"
    /// action, which keeps the notice standing.
    property bool detailsExpanded: false

    /// Compact detail rows: `{ primaryText, secondaryText }`. Empty renders
    /// `emptyText` instead (or nothing at all when that is empty too).
    property var items: []
    /// Shown in place of the list when `items` is empty — empty state or a
    /// fetch error, the caller decides which.
    property string emptyText: ""

    property var primaryAction: null
    property var secondaryAction: null
    property var tertiaryAction: null
    property var dismissAction: null

    /// Action id emitted when the window is closed without pressing a button
    /// (Esc, the title-bar close box). Overridden by `dismissAction.actionId`
    /// when a dismiss button is configured.
    property string dismissActionId: "dismiss"

    /// Accessible name for the window itself and for the detail list.
    property string listAccessibleName: ""

    /// Label of the header close affordance — accessible name AND tooltip.
    /// Set once by the tray on the shared instance (from `tr()`), NOT per
    /// showing: the corner close box is part of the window, not of whatever
    /// notification currently occupies it, so every present() inherits it and
    /// no caller can forget to localize it. The English literal here is the
    /// last-resort fallback for a host that never assigns it.
    property string closeAccessibleText: "Close"

    /// Show a checkbox on every detail row so the user answers about a subset
    /// rather than about the whole list. Rows start checked: the common answer
    /// is "yes, all of them", and unchecking is the cheaper gesture.
    property bool selectable: false

    /// Text the copy button puts on the clipboard when the list is not
    /// selectable (a notice carrying one value, e.g. an address). With
    /// `selectable` the button copies the checked rows instead.
    property string copyPayload: ""

    property string copyLabel: "Copy"
    property string copiedLabel: "Copied"

    /// Take the window down on its own after this long with no answer
    /// (0 = never). A notice nobody answered must not hold the surface
    /// forever: while it is up, everything behind it is silenced.
    property int autoRetireMs: 0

    /// Emitted exactly once per showing, with the id of the chosen action and
    /// the indexes of the checked rows (all rows when not selectable).
    signal actionTriggered(string actionId, var selectedIndexes)

    /// The window came down WITHOUT an answer — timed out, or the caller
    /// retired it. Whoever is holding notices back can now offer the next one.
    signal retired()

    /// Height held for the item list BEFORE the first frame.
    ///
    /// A `ListView` reports `contentHeight` only once its delegates exist,
    /// which is after the window is on screen — so a list-carrying notice was
    /// placed against a height it did not have yet and then moved once the
    /// rows arrived. Rows are usually one line each, so the count sizes the
    /// box up front; a row whose subtitle wraps to a second line grows past
    /// this estimate, but `Layout.preferredHeight` below takes the max of
    /// this and the real `contentHeight` once delegates exist, so nothing
    /// gets clipped.
    property int _reservedListHeight: 0

    function _reserveListHeight(rows) {
        var n = rows ? rows.length : 0
        if (n <= 0) return 0
        var rowH = Math.round(promptWindow._baseFontPx * 1.6)
        var gap = promptWindow.theme ? promptWindow.theme.spacingXxs : 2
        var margins = (promptWindow.theme ? promptWindow.theme.spacingXs : 4) * 2
        return Math.min(promptWindow._listMaxHeight, n * rowH + (n - 1) * gap + margins)
    }

    /// Populate and show. Passing the whole configuration through one call
    /// keeps the caller from leaving a stale field behind between showings.
    function present(config) {
        var c = config || {}
        titleText = String(c.titleText || "")
        bodyText = String(c.bodyText || "")
        bodyRichText = c.bodyRichText === true
        items = c.items || []
        emptyText = String(c.emptyText || "")
        primaryAction = c.primaryAction || null
        secondaryAction = c.secondaryAction || null
        tertiaryAction = c.tertiaryAction || null
        dismissAction = c.dismissAction || null
        dismissActionId = String(c.dismissActionId
            || (c.dismissAction ? c.dismissAction.actionId : "")
            || "dismiss")
        listAccessibleName = String(c.listAccessibleName || "")
        selectable = c.selectable === true
        copyPayload = String(c.copyPayload || "")
        autoRetireMs = Number(c.autoRetireMs || 0)
        detailsExpanded = false
        _reservedListHeight = _reserveListHeight(items)
        _checked = items.map(function() { return true })
        _copyAcknowledged = false
        _settled = false
        if (visible) {
            // Still up because a `keepsOpen` action left it standing: the new
            // content simply replaces the old. Re-showing, raising and moving a
            // window that is already on screen inside one pass trips an
            // assertion in Qt's window-update path, which took the tray process
            // down — and the main window followed it.
            placeTimer.restart()
        } else {
            _placeOnScreen()
            show()
            raise()
        }
        // Where the window actually landed. A notice nobody can see still
        // counts as "on screen" and silences every later one, so the geometry
        // that produced it has to be in the log, not reconstructed afterwards.
        console.log("tray prompt: shown at", promptWindow.x + "," + promptWindow.y,
            "size", promptWindow.width + "x" + promptWindow.height,
            "screen", promptWindow.screen
                ? (promptWindow.screen.virtualX + "," + promptWindow.screen.virtualY
                    + " " + promptWindow.screen.width + "x" + promptWindow.screen.height
                    + " avail " + promptWindow.screen.desktopAvailableWidth
                    + "x" + promptWindow.screen.desktopAvailableHeight)
                : "none",
            "visible", promptWindow.visible)
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// Latches on the first emission so the close that follows a button press
    /// does not emit the dismiss id on top of it.
    property bool _settled: false

    /// Per-row checked state, parallel to `items`. A plain array rather than a
    /// field on the item objects: the caller owns those and re-sends them.
    property var _checked: []
    /// Set once the user copies, so the button can say so without a timer.
    property bool _copyAcknowledged: false

    /// Indexes the answer applies to. Without checkboxes that is every row —
    /// the caller then needs no special case for the two shapes.
    function selectedIndexes() {
        var out = []
        for (var i = 0; i < items.length; i += 1) {
            if (!selectable || _checked[i] === true) out.push(i)
        }
        return out
    }

    function _setChecked(index, value) {
        var next = _checked.slice()
        while (next.length < items.length) next.push(true)
        next[index] = value === true
        _checked = next
    }

    /// Copy the checked rows, or the caller's fixed payload when the notice
    /// carries a value rather than a list.
    function _copy() {
        var text = copyPayload
        if (selectable || text === "") {
            var picked = selectedIndexes().map(function(i) {
                return String((items[i] || {}).primaryText || "")
            }).filter(function(s) { return s !== "" })
            if (picked.length > 0) text = picked.join("\n")
        }
        if (text === "") return
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge) return
        if (typeof nrrNativeBridge.copyToClipboard !== "function") return
        nrrNativeBridge.copyToClipboard(text)
        _copyAcknowledged = true
    }

    readonly property int _pad: theme ? theme.spacingLg : 16
    readonly property int _gap: theme ? theme.spacingMd : 12
    readonly property int _gapSm: theme ? theme.spacingSm : 8
    readonly property color _fgColor: theme ? theme.colorText : "#f5f7fa"
    readonly property color _mutedColor: theme ? theme.colorTextMuted : "#c9d1d9"
    readonly property color _panelColor: theme ? theme.colorWindow : "#1f2328"
    readonly property color _rowColor: theme ? theme.colorPanel : "#2a3038"
    readonly property color _borderColor: theme ? theme.colorBorder : "#47515f"
    readonly property int _baseFontPx: theme ? theme.baseFontSizePx : 13

    /// Tallest the detail list may grow before it starts scrolling.
    readonly property int _listMaxHeight: 190

    /// Side of the square header close box. Tracks the base font so it stays
    /// proportionate when the user scales text.
    readonly property int _closeBoxPx: Math.max(24, _baseFontPx + 11)

    /// Take the window down WITHOUT it counting as an answer: the notice became
    /// moot (it was answered on another surface, or it self-closed unread), so
    /// emitting a dismiss id would record a decision the user never made.
    function retire() {
        if (!visible) return
        _settled = true
        closeTimer.restart()
        retired()
    }

    /// Every take-down goes through a timer rather than through the call that
    /// asked for it. Closing — and moving — a window from inside the event Qt
    /// is still delivering to it trips `hasPendingUpdateRequest()` in the
    /// platform update path and takes the tray process down with it.
    /// `Qt.callLater` was not late enough: it runs before the frame the
    /// pending update belongs to. A zero-interval timer posts through the
    /// event loop proper, after that frame.
    Timer {
        id: closeTimer
        interval: 0
        repeat: false
        onTriggered: promptWindow.close()
    }
    /// Re-anchoring after the content settled, for the same reason, and
    /// coalesced: the list reports its height once per delegate batch, and
    /// each report used to move the window again.
    Timer {
        id: placeTimer
        interval: 60
        repeat: false
        onTriggered: promptWindow._placeOnScreen()
    }

    /// Self-retirement: the notice has been up its whole allowance with nobody
    /// answering. Nothing is recorded — the user never saw it, or chose not to
    /// deal with it — so it can be offered again later.
    Timer {
        id: autoRetireTimer
        interval: promptWindow.autoRetireMs > 0 ? promptWindow.autoRetireMs : 1
        running: promptWindow.visible && promptWindow.autoRetireMs > 0
        repeat: false
        onTriggered: {
            console.log("tray prompt: retired itself after",
                promptWindow.autoRetireMs, "ms with no answer")
            promptWindow.retire()
        }
    }

    function _emit(actionId) {
        if (_settled) return
        _settled = true
        var picked = selectedIndexes()
        // Deferred: taking the platform window down from inside the click
        // handler still being delivered trips an assertion in Qt's
        // window-update path and kills the tray process. `_settled` already
        // makes the window inert, so the extra pass is invisible.
        closeTimer.restart()
        actionTriggered(String(actionId || ""), picked)
    }
    function _trigger(action) {
        if (!action || !action.actionId) return
        // `keepsOpen` actions take the user somewhere else (a screen with the
        // full story) without ending the decision here: closing would discard
        // the checkboxes they were in the middle of setting.
        if (action.keepsOpen === true) {
            actionTriggered(String(action.actionId), selectedIndexes())
            return
        }
        _emit(action.actionId)
    }
    function _dismiss() { _emit(dismissActionId) }

    /// Corner clearance, matching what the OS leaves around its own toasts.
    readonly property int _screenMargin: 12

    /// Work area to sit in: the tray icon's own screen, taskbar excluded.
    /// QML's `Screen.desktopAvailable*` spans EVERY monitor, so on a
    /// two-screen desktop it is the combined width and lands the window on the
    /// neighbour. The bridge answers for one screen; the QML numbers are the
    /// fallback for a host that predates it, narrowed to this screen's own
    /// size with the taskbar thickness inferred from the height difference.
    function _workArea() {
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.trayNoticeScreenGeometry === "function") {
            var r = nrrNativeBridge.trayNoticeScreenGeometry()
            if (r && r.width > 0 && r.height > 0) return r
        }
        var g = promptWindow.screen
        if (!g || !(g.width > 0) || !(g.height > 0)) return null
        var inset = Math.max(0, Math.min(120, g.height - g.desktopAvailableHeight))
        return { x: g.virtualX, y: g.virtualY, width: g.width, height: g.height - inset }
    }

    /// Sit in the corner the tray icon lives in, the way every other
    /// notification on this desktop does — NOT over the middle of whatever the
    /// user is working on.
    ///
    /// The result is clamped so the whole window stays inside the work area: a
    /// window placed outside it is invisible while still counting as "on
    /// screen", and that state silently swallowed every later notification for
    /// a whole session.
    function _placeOnScreen() {
        var a = _workArea()
        if (!a) {
            console.log("tray prompt: no screen yet — leaving the window where it is")
            return
        }
        var maxX = a.x + a.width - promptWindow.width
        var maxY = a.y + a.height - promptWindow.height
        var nextX = Math.max(a.x, Math.min(maxX - promptWindow._screenMargin, maxX))
        var nextY = Math.max(a.y, Math.min(maxY - promptWindow._screenMargin, maxY))
        // A move that changes nothing still goes through the platform layer.
        if (nextX === promptWindow.x && nextY === promptWindow.y) return
        // Both callers already defer through the event loop (this runs before
        // `show()`, or from `placeTimer`), so a move is safe here even while
        // visible. A "still inside the work area, skip it" shortcut used to
        // sit here; it left a shorter notice stuck at a taller one's `y` set
        // before `height` had settled, looking like reserved space above it.
        promptWindow.x = nextX
        promptWindow.y = nextY
    }

    // ── Window ───────────────────────────────────────────────────────────────

    width: 460
    // Size to content, capped so a long list scrolls instead of growing the
    // window off-screen.
    height: Math.min(440, Math.max(120, layout.implicitHeight + _pad * 2))
    minimumWidth: 380
    visible: false
    modality: Qt.NonModal
    // A toast, not a dialog: `Qt.Tool` keeps it out of the taskbar and the
    // alt-tab list (it appearing there as a second "app" was a complaint),
    // frameless drops a title bar the corner close box already replaces, and
    // staying on top is what makes a notification a notification.
    flags: Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
    // Opaque. A translucent window needs a platform flag Qt does not set for a
    // plain Window on Windows, and without it the surface came up invisible —
    // which is worse than ugly, because an invisible window still counts as
    // "on screen" and silences every notification behind it.
    color: _panelColor
    title: titleText

    onClosing: promptWindow._dismiss()
    // The list only reports its content height once its delegates exist, so the
    // height `present()` placed against is a first approximation. Re-anchor
    // when it settles. `height` is content-driven and cannot change while the
    // window sits open, so this never fights a window the user has dragged.
    // Deferred: moving the window from inside its own resize notification is
    // the other half of the Qt update-path assertion that killed the tray.
    onHeightChanged: if (visible) placeTimer.restart()

    // Frameless leaves the edge to us. The border is not decoration: without it
    // the panel bleeds into a same-coloured desktop. Fill stays transparent —
    // the window itself is opaque, and a second opaque layer would only cover
    // the border's inner edge.
    Rectangle {
        anchors.fill: parent
        color: "transparent"
        border.width: promptWindow.theme ? promptWindow.theme.borderWidth : 1
        border.color: promptWindow._borderColor
    }

    Shortcut {
        sequences: ["Esc"]
        context: Qt.WindowShortcut
        onActivated: promptWindow._dismiss()
    }
    Shortcut {
        sequences: ["Return", "Enter"]
        context: Qt.WindowShortcut
        enabled: promptWindow.primaryAction !== null
        onActivated: promptWindow._trigger(promptWindow.primaryAction)
    }

    ColumnLayout {
        id: layout
        anchors.fill: parent
        anchors.margins: promptWindow._pad
        spacing: promptWindow._gapSm

        // Header: title on the left, close box hard right. A row rather than an
        // overlay so a long, wrapping title reflows AROUND the button instead of
        // running underneath it — and so the button keeps its corner even when
        // the caller supplies no title at all.
        RowLayout {
            Layout.fillWidth: true
            spacing: promptWindow._gapSm

            Label {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                visible: promptWindow.titleText !== ""
                text: promptWindow.titleText
                color: promptWindow._fgColor
                font.bold: true
                font.pixelSize: promptWindow._baseFontPx + 2
                wrapMode: Text.WordWrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            // Every tray notification is closable from its own corner, whatever
            // buttons the caller configured — a notice with no decision to make
            // would otherwise be dismissable only by Esc or the title bar.
            //
            // A square ThemedButton rather than a bespoke MouseArea: it is the
            // project's button wrapper (so it themes, focuses and reacts like
            // every other button), and the only thing overridden is its size —
            // the wrapper's 72 px minimum width is meant for labelled footer
            // buttons, not for a single glyph.
            ThemedButton {
                Layout.alignment: Qt.AlignTop | Qt.AlignRight
                Layout.preferredWidth: promptWindow._closeBoxPx
                Layout.preferredHeight: promptWindow._closeBoxPx
                theme: promptWindow.theme
                text: "✕"
                // Closing from the corner IS the dismiss path — same id, same
                // handler, same meaning as the title-bar close box and Esc.
                onClicked: promptWindow._dismiss()
                Accessible.role: Accessible.Button
                Accessible.name: promptWindow.closeAccessibleText
                ToolTip.visible: hovered
                ToolTip.delay: 400
                ToolTip.text: promptWindow.closeAccessibleText
            }
        }

        Label {
            Layout.fillWidth: true
            visible: promptWindow.bodyText !== ""
            text: promptWindow.bodyText
            textFormat: promptWindow.bodyRichText ? Text.StyledText : Text.PlainText
            color: promptWindow._mutedColor
            font.pixelSize: promptWindow._baseFontPx
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            // Screen readers get plain text — strip the styling tags used for visual emphasis.
            Accessible.name: promptWindow.bodyRichText ? text.replace(/<\/?[a-z]+>/gi, "") : text
        }

        // Compact detail list. Height follows the content up to the cap, past
        // which it scrolls — the window itself never grows beyond `height`.
        Rectangle {
            Layout.fillWidth: true
            visible: promptWindow.items.length > 0
            // `contentHeight` measures the rows only; the list is inset by its
            // own margins, so add them back or the last row is clipped.
            Layout.preferredHeight: Math.min(
                promptWindow._listMaxHeight,
                Math.max(promptWindow._reservedListHeight,
                    Math.max(0, detailList.contentHeight) + detailList.anchors.margins * 2))
            color: promptWindow._rowColor
            border.width: promptWindow.theme ? promptWindow.theme.borderWidth : 1
            border.color: promptWindow._borderColor
            radius: promptWindow.theme ? promptWindow.theme.radiusSm : 4

            ListView {
                id: detailList
                anchors.fill: parent
                anchors.margins: promptWindow.theme ? promptWindow.theme.spacingXs : 4
                clip: true
                spacing: promptWindow.theme ? promptWindow.theme.spacingXxs : 2
                model: promptWindow.items
                boundsBehavior: Flickable.StopAtBounds
                /// Width the scroll bar overlays. Reserved unconditionally so a
                /// list that starts short and grows does not reflow its rows.
                readonly property int scrollBarGutter: 18
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                Accessible.role: Accessible.List
                Accessible.name: promptWindow.listAccessibleName !== ""
                    ? promptWindow.listAccessibleName
                    : promptWindow.titleText

                delegate: ColumnLayout {
                    width: detailList.width - detailList.scrollBarGutter
                    spacing: 0
                    RowLayout {
                    Layout.fillWidth: true
                    spacing: promptWindow._gapSm

                    // Explicit indicator: the Native style on Windows ignores
                    // the palette for the tick box, which on the dark and
                    // high-contrast themes leaves it invisible.
                    CheckBox {
                        id: rowCheck
                        visible: promptWindow.selectable
                        checked: promptWindow._checked[index] !== false
                        padding: 0
                        implicitWidth: indicatorBox.width
                        implicitHeight: indicatorBox.height
                        onToggled: promptWindow._setChecked(index, checked)
                        indicator: Rectangle {
                            id: indicatorBox
                            width: Math.max(14, promptWindow._baseFontPx + 1)
                            height: width
                            radius: promptWindow.theme ? promptWindow.theme.radiusSm : 3
                            color: rowCheck.checked
                                ? (promptWindow.theme ? promptWindow.theme.colorAccent : "#4c8dff")
                                : "transparent"
                            border.width: promptWindow.theme ? promptWindow.theme.borderWidth : 1
                            border.color: rowCheck.activeFocus
                                ? (promptWindow.theme ? promptWindow.theme.colorAccent : "#4c8dff")
                                : promptWindow._borderColor
                            Text {
                                anchors.centerIn: parent
                                visible: rowCheck.checked
                                text: "✓"
                                color: promptWindow.theme
                                    ? promptWindow.theme.colorOnAccent : "#ffffff"
                                font.pixelSize: promptWindow._baseFontPx - 2
                            }
                        }
                        Accessible.role: Accessible.CheckBox
                        Accessible.name: String((modelData || {}).primaryText || "")
                    }
                    Label {
                        Layout.fillWidth: true
                        text: String((modelData || {}).primaryText || "")
                        color: promptWindow._fgColor
                        font.pixelSize: promptWindow._baseFontPx
                        elide: Text.ElideMiddle
                        Accessible.role: Accessible.StaticText
                        Accessible.name: text
                    }
                    Label {
                        Layout.fillWidth: true
                        visible: String((modelData || {}).secondaryText || "") !== ""
                        text: String((modelData || {}).secondaryText || "")
                        color: promptWindow._mutedColor
                        font.pixelSize: promptWindow._baseFontPx - 1
                        wrapMode: Text.WordWrap
                        maximumLineCount: 2
                        elide: Text.ElideRight
                        Accessible.role: Accessible.StaticText
                        Accessible.name: text
                    }
                    }
                    // The "how do you know?" line. Hidden until the user asks
                    // for it: the notice has to stay glanceable, and an
                    // unopened detail is what the Details button is for.
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: promptWindow.selectable
                            ? promptWindow._baseFontPx + promptWindow._gapSm + 4 : 0
                        visible: promptWindow.detailsExpanded
                            && String((modelData || {}).detailText || "") !== ""
                        text: String((modelData || {}).detailText || "")
                        color: promptWindow._mutedColor
                        font.pixelSize: promptWindow._baseFontPx - 1
                        wrapMode: Text.WordWrap
                        Accessible.role: Accessible.StaticText
                        Accessible.name: text
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true
            visible: promptWindow.items.length === 0 && promptWindow.emptyText !== ""
            text: promptWindow.emptyText
            color: promptWindow._mutedColor
            font.pixelSize: promptWindow._baseFontPx
            wrapMode: Text.WordWrap
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        Item { Layout.fillHeight: true; Layout.preferredHeight: 0 }

        // Footer: primary action first in the layout, which right-to-left flow
        // renders last on screen (Windows convention). A Flow, not a RowLayout:
        // five buttons with translated labels do not fit one row at this width,
        // and the row clipped the last of them — the one being asked for.
        Flow {
            Layout.fillWidth: true
            Layout.topMargin: promptWindow._gapSm
            spacing: promptWindow._gapSm
            layoutDirection: Qt.RightToLeft

            ThemedButton {
                visible: promptWindow.primaryAction !== null
                theme: promptWindow.theme
                highlighted: promptWindow.primaryAction
                    ? promptWindow.primaryAction.accent !== false : false
                text: promptWindow.primaryAction
                    ? String(promptWindow.primaryAction.label || "") : ""
                onClicked: promptWindow._trigger(promptWindow.primaryAction)
                Accessible.name: text
            }
            ThemedButton {
                visible: promptWindow.secondaryAction !== null
                theme: promptWindow.theme
                highlighted: promptWindow.secondaryAction
                    ? promptWindow.secondaryAction.accent === true : false
                text: promptWindow.secondaryAction
                    ? String(promptWindow.secondaryAction.label || "") : ""
                onClicked: promptWindow._trigger(promptWindow.secondaryAction)
                Accessible.name: text
            }
            ThemedButton {
                visible: promptWindow.tertiaryAction !== null
                theme: promptWindow.theme
                highlighted: promptWindow.tertiaryAction
                    ? promptWindow.tertiaryAction.accent === true : false
                text: promptWindow.tertiaryAction
                    ? String(promptWindow.tertiaryAction.label || "") : ""
                onClicked: promptWindow._trigger(promptWindow.tertiaryAction)
                Accessible.name: text
            }
            // Copying must not count as answering: this is the one footer
            // button that leaves the notice standing.
            ThemedButton {
                visible: promptWindow.copyPayload !== "" || promptWindow.items.length > 0
                theme: promptWindow.theme
                text: promptWindow._copyAcknowledged
                    ? promptWindow.copiedLabel : promptWindow.copyLabel
                onClicked: promptWindow._copy()
                Accessible.role: Accessible.Button
                Accessible.name: text
            }
            ThemedButton {
                visible: promptWindow.dismissAction !== null
                theme: promptWindow.theme
                text: promptWindow.dismissAction
                    ? String(promptWindow.dismissAction.label || "") : ""
                onClicked: promptWindow._trigger(promptWindow.dismissAction)
                Accessible.name: text
            }
        }
    }
}
