import QtQuick 2.15
import Qt.labs.platform 1.1
import "components"
import "flows"
import "theme"
import "lib/pure.js" as Pure

SystemTrayIcon {
    id: tray
    visible: false

    property var context: ({})
    property string language: "en"
    property var localeCatalog: ({})
    property string statusKey: ""
    property string statusAccessibilityKey: ""
    property string statusLine: "NetRuleRouter"
    property string statusAccessibilityText: ""
    property string routePrimaryLabel: "Primary"
    property string routeSecondaryLabel: "Secondary"
    property string iconFileUrl: ""
    property var theme: ({ selectedMode: "system", effectiveMode: "light", systemMode: "light", systemModeDetected: false })
    property var primaryActions: []
    property var quickActions: []
    // User preference "show notifications". The tray is the surface that raises
    // unsolicited windows, so it has to honour it. A launch-time snapshot, like
    // `language` and `theme`; missing from an older context file means "on",
    // which is the shipped default.
    property bool showNotifications: true
    /// Per-kind mute for the suggestions stripe, under `showNotifications`.
    /// Same launch-time snapshot rule; absent in an older context file means
    /// "on", which is the shipped default.
    property bool notifySuggestionChanges: true
    property int autoCloseMs: 0
    property var autoCloseTimer: null

    // Pause state is now driven by service push
    // events (RoutingPauseStateChanged) plus an initial fetch on startup.
    // The toggle round-trips through `rpcRoutingPauseToggle`; the resulting
    // push event flips this property and `iconSource` swaps to the cached
    // grayscale variant prepared by `nrrNativeBridge.prepareTrayGrayscaleIcon`.
    property bool routingPaused: false
    property string grayscaleIconUrl: ""
    readonly property bool bridgeAvailable: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcRoutingPauseGet === "function"

    readonly property string actionMarker: "NRR_TRAY_ACTION:"
    readonly property string appIconSource: "../../../assets/icons/app/icon-64.png"

    // Correlation-id RPC transport (pending-callback table + GC timer + bridge
    // forwarders), shared with the main window via flows/RpcTransport. Held in a
    // property because SystemTrayIcon has no default property to host a child
    // QtObject; the collector timer inside RpcTransport runs regardless.
    property var rpc: RpcTransport {
        bridge: nrrNativeBridge
    }
    // Full reset / close-everything poll.
    property var shutdownPollTimer: null

    // Colour/spacing tokens for the tray's own prompt windows. The launch
    // context only carries the resolved theme SLUGS (`theme.effectiveMode`),
    // not the token set the main window builds, so the tray instantiates its
    // own ThemeTokens from that slug. Held in a property for the same reason
    // `rpc` is: SystemTrayIcon has no default property.
    property var uiTheme: ThemeTokens {
        themeMode: String((tray.theme || {}).effectiveMode || "light")
    }

    // Generic tray prompt window. A SystemTrayIcon balloon cannot carry
    // buttons, so every tray notification that needs a decision is rendered
    // by this window. It is content-free — the caller injects the strings and
    // the action ids, and gets one `actionTriggered` back.
    property var promptWindow: TrayPromptWindow {
        theme: tray.uiTheme
        // Localized once, on the shared instance: the corner close box belongs
        // to the window, not to whichever notification is occupying it.
        closeAccessibleText: tray.tr("action.close", "Close")
        copyLabel: tray.tr("action.copy", "Copy")
        copiedLabel: tray.tr("action.copied", "Copied")
        onActionTriggered: function(actionId, selectedIndexes) {
            tray._onPromptAction(actionId, selectedIndexes)
        }
        onRetired: tray._onPromptRetired()
    }

    // ── One window, several things wanting it ────────────────────────────────
    //
    // Only one notice can be on screen, and for a while the rule was simply
    // "someone else is up, say nothing". That lost a whole session's worth of
    // notices behind a single window nobody could see. Held-back notices now
    // wait their turn instead.

    /// How long a notice that asks a question may hold the surface. Generous —
    /// the user may be reading it — but finite: while it is up, everything
    /// behind it waits, and a window nobody answers must not cost a session.
    readonly property int _promptAutoRetireMs: 300000

    /// Pending notices as `{ kind, show }`. Kind is the dedup key: a second
    /// external address supersedes the first, a second batch of suggestions is
    /// the same request re-run.
    property var _noticeQueue: []
    /// Beyond this the oldest is dropped. A backlog longer than this is not a
    /// queue, it is a machine that spent the day unattended.
    readonly property int _noticeQueueCap: 4

    /// Show now, or line up behind whatever is on screen.
    function _presentOrQueue(kind, show) {
        if (!promptWindow || !promptWindow.visible) {
            show()
            return
        }
        var queued = []
        for (var i = 0; i < _noticeQueue.length; i += 1) {
            if (_noticeQueue[i].kind !== kind) queued.push(_noticeQueue[i])
        }
        queued.push({ kind: kind, show: show })
        while (queued.length > _noticeQueueCap) queued.shift()
        _noticeQueue = queued
        console.log("tray notice:", kind, "queued behind the notice on screen —",
            queued.length, "waiting")
    }

    /// Settling delay between a notice coming down and the next one going up.
    /// Closing the window and re-showing it inside one event-loop pass trips an
    /// assertion in Qt's window-update path (`hasPendingUpdateRequest`), which
    /// takes the tray process down — the same family as the re-show assert in
    /// `TrayPromptWindow.present`. `Qt.callLater` is not enough separation: it
    /// still runs before the platform window has finished coming down.
    property Timer _drainTimer: Timer {
        interval: 250
        repeat: false
        onTriggered: tray._drainNoticeQueue()
    }
    function _scheduleDrain() { _drainTimer.restart() }

    /// Offer the next held-back notice. Called whenever the window frees up.
    function _drainNoticeQueue() {
        if (_noticeQueue.length === 0) return
        if (promptWindow && promptWindow.visible) return
        var next = _noticeQueue[0]
        _noticeQueue = _noticeQueue.slice(1)
        console.log("tray notice: offering the held-back", next.kind)
        next.show()
    }

    /// The window came down without an answer. Whatever it was carrying is
    /// undecided — clear the per-notice state so a later offer is not treated
    /// as a reply to it, then let the queue move.
    function _onPromptRetired() {
        _activeNoticeId = ""
        _autoRuleActiveIds = []
        _scheduleDrain()
    }

    // Shared record of answered notifications. Every notice the tray raises
    // carries a state-derived id: the tray does not re-offer an id that was
    // answered here or in the main window, and a decision taken in the window
    // takes down whatever the tray currently has on screen.
    property var noticeLedger: NotificationLedger {
        onDecidedElsewhere: function(noticeId) { tray._onNoticeDecidedElsewhere(noticeId) }
    }
    /// Ledger id of the notice currently occupying `promptWindow`; "" when it
    /// is showing nothing, or something with no id of its own.
    property string _activeNoticeId: ""

    // Read-only view of what the main window published: whether it is running
    // and focused, and which files back the user's rules.
    property var guiPresence: GuiPresence {}

    // File-vs-service rules comparison, the tray's own. See `RulesDriftWatch`.
    property var rulesDriftWatch: RulesDriftWatch {
        rpc: tray.rpc
        presence: tray.guiPresence
        // Nothing to compare against while the service is not running (4 ==
        // Running), and nothing to say at all when the user turned notices off.
        enabled: tray.showNotifications && tray.bridgeAvailable
            && tray.serviceStatus === 4
        onDriftDetected: function(details) { tray._onRulesDriftDetected(details) }
        onDriftCleared: tray._onRulesDriftCleared()
    }

    // Writes the linked rules files when the SERVICE authored a rule and no
    // window is up to do it. See `TrayBoundFileWriter`.
    property var boundFileWriter: TrayBoundFileWriter {
        rpc: tray.rpc
        presence: tray.guiPresence
    }

    // Service status snapshot for icon + menu state.
    // Updated by a 10-second polling Timer (see Component.onCompleted)
    // calling `nrrServiceController.refreshStatus()`. The integer
    // mirrors `NrrServiceController::Status` (0=Unknown, 1=NotInstalled,
    // 2=Stopped, 3=StartPending, 4=Running, 5=StopPending).
    property int serviceStatus: 0

    function _serviceStatusSlug(status) {
        switch (parseInt(status)) {
            case 4: return "running"
            case 2: return "stopped"
            case 3: return "pending"
            case 5: return "pending"
            case 1: return "not-installed"
            default: return "unknown"
        }
    }

    function applyTrayIcon() {
        var base = iconFileUrl !== "" ? iconFileUrl : appIconSource
        if (routingPaused && bridgeAvailable) {
            if (grayscaleIconUrl === "") {
                grayscaleIconUrl = nrrNativeBridge.prepareTrayGrayscaleIcon(base)
            }
            icon.source = grayscaleIconUrl !== "" ? grayscaleIconUrl : base
            return
        }
        // Overlay a colored status dot when the service
        // bridge is available. Falls through to the unadorned base icon
        // when the bridge isn't wired (preview / tray-only builds).
        if (bridgeAvailable
                && typeof nrrNativeBridge.prepareTrayStatusIcon === "function") {
            var slug = _serviceStatusSlug(serviceStatus)
            var statusIcon = nrrNativeBridge.prepareTrayStatusIcon(base, slug)
            icon.source = statusIcon !== "" ? statusIcon : base
        } else {
            icon.source = base
        }
    }

    onRoutingPausedChanged: { applyTrayIcon(); refreshTooltip() }
    onServiceStatusChanged: {
        applyTrayIcon()
        refreshTooltip()
        // A service that just came up has an enforcement state we have not read
        // yet; one that went away invalidates what we read before.
        if (serviceStatus === 4) _refreshEnforcementState()
        else _enforcementKnown = false
    }

    // Single demux point for every server-pushed status event the tray cares
    // about. Unknown kinds are dropped silently — the service appends variants
    // and an older tray must keep working.
    //
    // The entry log is not noise: this is the last hop of the push path, and
    // without it "the event never reached the tray" and "the tray received it
    // and decided to stay quiet" look identical in the log.
    function handlePushEvent(subscriptionId, eventId, event) {
        if (!event) {
            console.log("tray push: empty frame ignored, id", eventId)
            return
        }
        var type = String(event.type)
        console.log("tray push:", type, "id", eventId)
        switch (type) {
            case "routing-pause-state-changed":
                routingPaused = !!event.paused
                break
            case "auto-rule-candidates-changed":
                _onAutoRuleCandidatesChanged(event)
                break
            case "secondary-external-address-observed":
                _onSecondaryExternalAddress(event, eventId)
                break
            case "block-notice-raised":
                _onBlockNoticeRaised(event)
                break
            case "revision-status-changed":
            case "health-changed":
                // Both change the answer to "are rules being applied", which the
                // tooltip states outright.
                _refreshEnforcementState()
                break
            case "mutation-progress":
                // A finished mutation is the usual way a rules divergence
                // appears or disappears; re-compare now instead of leaving a
                // resolved question on screen until the next poll.
                if (String(event.phase || "") === "completed") {
                    // Whoever writes the files — this tray or the window — has
                    // not finished yet. Asking the user to save what the app is
                    // already saving is the "why am I being asked?" report.
                    _rulesDriftQuietUntilMs = Date.now() + _rulesDriftPostMutationQuietMs
                    // An auto-rule the service authored is a change the user
                    // never made in a file — mirror it before the comparison
                    // runs, or the drift watch reports the app's own work back
                    // to the user as a divergence.
                    if (String(event["correlation-id"] || "")
                            .indexOf("auto-rules-") === 0) {
                        boundFileWriter.mirrorServiceIntoFiles()
                    }
                    Qt.callLater(rulesDriftWatch.check)
                    _refreshEnforcementState()
                }
                break
            default:
                break
        }
    }

    // ── Auto-rule suggestions ────────────────────────────────────────────────
    //
    // While the user browses, the service notices the extra hosts a routed site
    // needs (its CDN and friends) and — in "suggest" mode, the default — parks
    // them as candidates and pushes `auto-rule-candidates-changed`. The tray
    // fetches the list and offers it in the generic prompt window: add them,
    // always add them from now on, open the rules screen, or never suggest
    // these again.

    /// Ledger id for one candidate. A candidate is offered ONCE: re-prompting
    /// on every push (the service re-pushes as the count grows) would turn a
    /// helpful notice into nagging. The answer lives in the shared ledger
    /// rather than in a process-local set, so it also survives a tray restart
    /// and is visible to the main window.
    function _autoRuleNoticeId(candidateId) {
        return "auto-rule:" + String(candidateId || "")
    }
    /// Ledger id of an explicit REFUSAL. Kept apart from the id above because
    /// the two answers have opposite lifetimes: "never suggest this" is the
    /// only one that may outlive the state it was given about.
    function _autoRuleRefusedId(candidateId) {
        return "auto-rule-never:" + String(candidateId || "")
    }
    /// How long an ACCEPTED candidate stays quiet. Accepting creates the rule,
    /// and the service stops proposing what is already covered — so the only
    /// way the same candidate comes back is that its rule is gone again
    /// (the user deleted it, or reloaded rules from a file that predates it),
    /// which is precisely when it must be offered anew. The window only spans
    /// the gap between the answer and the service dropping the candidate.
    readonly property int _autoRuleAcceptQuietMs: 600000

    /// Is a previous answer about this candidate still binding?
    function _autoRuleAnswered(candidateId) {
        if (noticeLedger.isDecided(_autoRuleRefusedId(candidateId))) return true
        if (Date.now() < Number(_autoRuleSnoozedIds[candidateId] || 0)) return true
        var at = noticeLedger.decidedAt(_autoRuleNoticeId(candidateId))
        return at > 0 && (Date.now() - at) < _autoRuleAcceptQuietMs
    }

    /// Put the addresses a closed notice was carrying to sleep, and drop the
    /// entries whose sleep is over so the map cannot grow with the session.
    function _snoozeCandidates(candidateIds) {
        var now = Date.now()
        var next = {}
        for (var known in _autoRuleSnoozedIds) {
            if (Number(_autoRuleSnoozedIds[known]) > now) {
                next[known] = _autoRuleSnoozedIds[known]
            }
        }
        for (var i = 0; i < (candidateIds || []).length; i += 1) {
            var id = String(candidateIds[i] || "")
            if (id !== "") next[id] = now + _autoRuleSnoozeMs
        }
        _autoRuleSnoozedIds = next
    }
    /// Most addresses one notice offers at a time. The service holds more; a
    /// list longer than this stops being a decision and becomes a chore, and
    /// what is left over rides along on the next notice.
    readonly property int _autoRuleMaxPerNotice: 10
    /// How long the addresses a closed notice was carrying stay quiet. Long
    /// enough not to feel like nagging, short enough that a browsing session
    /// still gets them offered again.
    readonly property int _autoRuleSnoozeMs: 1800000
    /// Candidate id -> epoch ms until which it stays quiet. Per candidate, not
    /// per category: closing one notice used to silence EVERY suggestion for
    /// half an hour, so a whole session's worth of new sites went unmentioned
    /// because of one window the user had waved away.
    property var _autoRuleSnoozedIds: ({})
    /// Explicit "quiet, please" from the menu. This one IS categorical — the
    /// user asked for silence, not for these particular addresses.
    property double _autoRuleSilencedUntilMs: 0
    /// Ids carried by the prompt currently on screen — the set every button
    /// acts on.
    property var _autoRuleActiveIds: []
    /// Ids awaiting the "turn on automatic mode?" confirmation — held apart
    /// from `_autoRuleActiveIds` so a cancel can leave the original notice's
    /// candidates untouched instead of discarding them.
    property var _autoRulesModePendingIds: []
    /// Anchor (the routed site the candidates were seen alongside) from the
    /// most recent push; used as the `{name}` in the prompt body.
    property string _autoRuleAnchor: ""
    property bool _autoRuleFetchInFlight: false
    /// How many suggestions the service is holding — the menu row's count.
    property int _autoRulePendingCount: 0
    /// The user asked to see the offer, so the quiet windows that pace an
    /// UNSOLICITED notice do not apply. Only an explicit "never suggest this"
    /// still hides a row.
    property bool _autoRuleShowAll: false

    /// Re-open the offer on demand — the tray menu's way back to a notice that
    /// retired itself or was closed with "not now".
    function showAutoRuleSuggestions() {
        _autoRuleSilencedUntilMs = 0
        _autoRuleSnoozedIds = ({})
        _autoRuleShowAll = true
        _fetchAutoRuleCandidates()
    }

    function _onAutoRuleCandidatesChanged(event) {
        var pending = Number(event["pending-count"] || 0)
        // Record the count before any gate: the menu shows it whether or not a
        // notice was wanted, and the inbox keeps everything either way.
        _autoRulePendingCount = pending
        if (!(pending > 0)) return
        if (!notifySuggestionChanges) {
            console.log("tray auto-rules: suppressed — this notice kind is silenced")
            return
        }
        if (Date.now() < _autoRuleSilencedUntilMs) {
            console.log("tray auto-rules: suppressed — the user asked for quiet")
            return
        }
        var anchor = String(event["top-anchor"] || "")
        if (anchor !== "") _autoRuleAnchor = anchor
        _fetchAutoRuleCandidates()
    }

    function _fetchAutoRuleCandidates() {
        if (_autoRuleFetchInFlight) return
        // A prompt is already on screen: stacking a second window over it would
        // be exactly the "aggressive" behaviour this flow must avoid. Ask again
        // when it frees up — the list is re-fetched then, so nothing goes stale.
        if (promptWindow && promptWindow.visible) {
            _presentOrQueue("auto-rules", function() { tray._fetchAutoRuleCandidates() })
            return
        }
        if (!bridgeAvailable || !rpc
                || typeof rpc.rpcAutoRuleCandidatesList !== "function") {
            console.log("tray auto-rules: no rpc bridge — cannot fetch candidates")
            return
        }
        var corr = rpc.rpcAutoRuleCandidatesList()
        if (!corr || corr === "") return
        _autoRuleFetchInFlight = true
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            tray._autoRuleFetchInFlight = false
            if (!ok || !payload) {
                console.warn("auto-rule candidates fetch failed:", code, msg)
                // The turn was spent without showing anything — let whatever is
                // behind it through rather than stalling the queue on a failure.
                tray._scheduleDrain()
                return
            }
            var list = payload.candidates || payload["candidates"] || []
            tray._autoRulePendingCount = list.length
            tray._presentAutoRulePrompt(list)
        })
    }

    /// Sentence naming the route an answer would use. One line under the body
    /// beats repeating the route on every row — it is the same for all of them
    /// whenever the notice is about a single site.
    function _routeSentence(routeSlug) {
        if (routeSlug === "secondary") {
            return tr("tray.auto-rules.route-line-secondary",
                "They will be added to the additional route.")
        }
        if (routeSlug === "primary") {
            return tr("tray.auto-rules.route-line-primary",
                "They will be added to the main route.")
        }
        return ""
    }

    /// Row subtitle: the site the address was seen with, plus the route when
    /// one notice mixes sites that do not share one.
    function _companionRowSubtitle(candidateAnchor, routeSlug) {
        var parts = []
        if (candidateAnchor !== "") {
            parts.push(tr("tray.auto-rules.item-companion-short", "← {name}")
                .replace("{name}", candidateAnchor))
        }
        var route = _routeSentence(routeSlug)
        if (route !== "") parts.push(route)
        return parts.join(" · ")
    }

    /// "How do you know?" for one candidate, shown when the user asks for
    /// details. The user is being asked to change their own routing, so the
    /// evidence travels with the offer instead of being taken on trust.
    function _candidateDetailLine(c) {
        var parts = []
        var signal = String(c.signal || c["signal"] || "")
        if (signal !== "") {
            parts.push(tr("tray.auto-rules.signal." + signal, signal))
        }
        var observations = Number(c.observations || c["observations"] || 0)
        if (observations > 0) {
            parts.push(tr("tray.auto-rules.detail-observations",
                    "seen in {count} visits").replace("{count}", String(observations)))
        }
        var affinity = Number(c.affinity || c["affinity"] || 0)
        if (affinity > 0) {
            parts.push(tr("tray.auto-rules.detail-affinity",
                    "belongs to this site {percent}% of the time")
                .replace("{percent}", String(Math.round(affinity * 100))))
        }
        var kind = String(c["match-kind"] || c.matchKind || "")
        if (kind !== "") {
            parts.push(tr("tray.auto-rules.detail-match-kind." + kind, kind))
        }
        return parts.join(" \u00b7 ")
    }

    /// Normalise the wire rows, drop the ones already offered, and show the
    /// prompt. Nothing new to say -> nothing shown.
    function _presentAutoRulePrompt(candidates) {
        var ids = []
        var items = []
        var anchor = _autoRuleAnchor
        // Which route the answer would put them on. The user asked to see it
        // before deciding; it is the anchor's own route, so it is the same for
        // every row of one site and only differs when sites are mixed.
        var routes = []
        for (var i = 0; i < candidates.length; i += 1) {
            if (ids.length >= _autoRuleMaxPerNotice) break
            var c = candidates[i] || {}
            var id = String(c.id || c["id"] || "")
            if (id === "") continue
            if (_autoRuleShowAll
                    ? noticeLedger.isDecided(_autoRuleRefusedId(id))
                    : _autoRuleAnswered(id)) continue
            var candidateAnchor = String(c.anchor || c["anchor"] || "")
            if (anchor === "" && candidateAnchor !== "") anchor = candidateAnchor
            var candidateRoute = String(c.route || c["route"] || "")
            if (candidateRoute !== "" && routes.indexOf(candidateRoute) < 0) {
                routes.push(candidateRoute)
            }
            ids.push(id)
            items.push({
                primaryText: String(c["proposed-match"] || c.proposedMatch || ""),
                secondaryText: _companionRowSubtitle(
                    candidateAnchor, routes.length > 1 ? candidateRoute : ""),
                detailText: _candidateDetailLine(c)
            })
        }
        if (ids.length === 0) {
            console.log("tray auto-rules: every candidate was already answered — nothing to show")
            // A click that produces no window reads as a broken menu item, so
            // an explicit request always gets an answer.
            if (_autoRuleShowAll) {
                _autoRuleShowAll = false
                promptWindow.present({
                    titleText: tr("tray.auto-rules.title", "Addresses a site needs"),
                    bodyText: tr("tray.auto-rules.none-pending",
                        "Nothing is waiting to be added right now."),
                    primaryAction: {
                        label: tr("action.close", "Close"),
                        actionId: "auto-rules-later",
                        accent: true
                    },
                    dismissActionId: "auto-rules-later",
                    autoRetireMs: _promptAutoRetireMs
                })
                return
            }
            _scheduleDrain()
            return
        }
        _autoRuleShowAll = false
        console.log("tray auto-rules: offering", ids.length, "addresses for", anchor)
        _autoRuleActiveIds = ids
        _activeNoticeId = ""

        var siteName = anchor !== ""
            ? anchor
            : tr("tray.auto-rules.site-fallback", "a site you use")
        var bodyText = tr("tray.auto-rules.body",
                "Found addresses without which {name} will not work fully.")
            .replace("{name}", siteName)
        // Mixed routes are named per row instead; one shared route reads
        // better as a sentence than as a repeated tag.
        if (routes.length === 1) {
            var routeLine = _routeSentence(routes[0])
            if (routeLine !== "") bodyText = bodyText + "\n" + routeLine
        }
        bodyText = bodyText + "\n" + tr("tray.auto-rules.unchecked-declined",
            "Unchecked rows will be declined; you can bring them back later in the app.")
        promptWindow.present({
            titleText: tr("tray.auto-rules.title", "Addresses a site needs"),
            bodyText: bodyText,
            items: items,
            selectable: true,
            emptyText: tr("tray.auto-rules.empty",
                "No addresses to suggest right now."),
            listAccessibleName: tr("tray.auto-rules.list-accessible-name",
                "Suggested addresses"),
            primaryAction: {
                label: tr("tray.auto-rules.action.accept", "Add checked"),
                actionId: "auto-rules-accept",
                accent: true
            },
            secondaryAction: {
                label: tr("tray.auto-rules.action.always",
                    "Add automatically from now on"),
                actionId: "auto-rules-always",
                // Turning on unattended writes gets its own yes/no first —
                // the click swaps this window to a confirm screen instead of
                // closing it and acting immediately.
                keepsOpen: true
            },
            tertiaryAction: {
                label: tr("tray.auto-rules.action.details", "Details"),
                actionId: "auto-rules-details",
                keepsOpen: true
            },
            dismissAction: {
                label: tr("tray.auto-rules.action.dismiss",
                    "Never suggest checked"),
                actionId: "auto-rules-dismiss"
            },
            // Closing the window is "not now", NOT the refusal the button
            // means: the two used to share one id, so the close box silently
            // buried the addresses for good.
            dismissActionId: "auto-rules-later",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    // ── External address of the additional route ─────────────────────────────
    //
    // The additional link's own client often cannot say which address the
    // outside world sees behind it. The service can, and pushes it once the
    // link has settled after connecting. This is a NOTICE, not a question: it
    // carries no decision, so it closes itself.

    /// How long the external-address notice stays on screen. Long enough to
    /// read and copy an address, short enough that a user who walked away does
    /// not come back to a stale window sitting over their work. It now fires on
    /// every reconnect, so it has to be the shorter of the two.
    readonly property int _externalAddressNoticeMs: 15000

    /// One notice per PUSH, not per address. The service publishes this on
    /// every (re)connect, and a user who reconnects wants the address again —
    /// keyed on the address alone, one dismissal retired it for good and the
    /// notice was never seen a second time. The push id is identical in the
    /// main window, so the two surfaces still cannot double up on one event.
    function _externalAddressNoticeId(eventId, address) {
        return "secondary-external-address:" + String(eventId || "")
            + ":" + String(address || "")
    }

    /// How long an answered external-address notice stays suppressed. The push
    /// id it is keyed on restarts at 1 with the SERVICE, so the same id comes
    /// round again on a later run and a permanent record of it silenced a whole
    /// week's notices for the same address. All the record has to outlive is
    /// the gap between the two surfaces receiving one push.
    readonly property int _externalAddressRefractoryMs: 600000

    // Every early return here is announced. Each one is a legitimate reason to
    // stay quiet, but from the outside they all look the same as a lost event —
    // and telling them apart after the fact is exactly what two test runs were
    // spent failing to do.
    function _onSecondaryExternalAddress(event, eventId) {
        // Record it before any gate: the menu shows this address whether or
        // not a notification was wanted.
        var observed = String(event["external-address"] || "")
        if (observed !== "") {
            _externalSecondary = observed
            _externalSecondaryCachedAtMs = 0
        }
        if (!showNotifications) {
            console.log("tray external-address: suppressed — notifications are off")
            return
        }
        var address = String(event["external-address"] || "")
        // The service only publishes this event WITH an address; the guard is
        // here so a future/garbled frame can never produce an empty notice.
        if (address === "") {
            console.log("tray external-address: suppressed — frame carries no address")
            return
        }
        var noticeId = _externalAddressNoticeId(eventId, address)
        // Already answered — here, or in the main window, which shows the same
        // notice as insurance against a silent tray. Only a RECENT answer
        // counts: see `_externalAddressRefractoryMs`.
        var answeredAt = noticeLedger.decidedAt(noticeId)
        if (answeredAt > 0 && (Date.now() - answeredAt) < _externalAddressRefractoryMs) {
            console.log("tray external-address: suppressed — already answered:", noticeId)
            return
        }
        console.log("tray external-address: showing notice for", address)

        var adapter = String(event["adapter-name"] || "")
        // An informational notice must not shove a question off the screen —
        // but it must not be thrown away either, which is what "stay quiet"
        // turned into. It waits its turn.
        _presentOrQueue("external-address", function() {
            tray._showExternalAddressNotice(noticeId, address, adapter)
        })
    }

    function _showExternalAddressNotice(noticeId, address, adapter) {
        // Bold only the address itself, not the surrounding sentence — the
        // markup lives here, not in the translated string, so the localized
        // text stays plain prose in both locale files.
        var body = tr("tray.external-address.body",
                "External address of the additional route: {address}")
            .replace("{address}", "<b>" + address + "</b>")
        if (adapter !== "") {
            body = body + "\n" + tr("tray.external-address.adapter", "Adapter: {name}")
                .replace("{name}", adapter)
        }
        _activeNoticeId = noticeId
        promptWindow.present({
            titleText: tr("tray.external-address.title",
                "Additional route connected"),
            bodyText: body,
            bodyRichText: true,
            // The address is the whole point of this notice — it has to be
            // takeable, not just readable.
            copyPayload: address,
            primaryAction: {
                label: tr("action.close", "Close"),
                actionId: "external-address-dismiss",
                accent: true
            },
            // Timing out is not an answer: a user who was away never saw it,
            // so the notice stays undecided and the main window still offers
            // it. The window owns the countdown — one mechanism, and it fires
            // for whatever is on screen rather than for a hand-wired case.
            autoRetireMs: _externalAddressNoticeMs
        })
    }

    // ── Rules in the files vs rules being enforced ───────────────────────────
    //
    // The main window compares the two continuously and raises its amber
    // banner. With the window closed — or simply behind other work — nobody
    // sees that banner, so the tray runs the same comparison (see
    // `RulesDriftWatch`) and asks here.

    /// Ledger id of the divergence currently offered, "" when none is.
    property string _rulesDriftNoticeId: ""
    /// How long an answered divergence stays quiet while it is still there.
    /// Answering means "not now", not "never" — a rule set that has been out of
    /// sync for a working day is worth mentioning once more.
    readonly property int _rulesDriftRefractoryMs: 6 * 60 * 60 * 1000

    /// How long after an applied mutation the divergence question stays down.
    /// Long enough for the window's persist pass (or this tray's) to reach the
    /// disk, short enough that a divergence which really did survive is still
    /// raised in the same sitting.
    readonly property int _rulesDriftPostMutationQuietMs: 45000
    property double _rulesDriftQuietUntilMs: 0

    function _onRulesDriftDetected(details) {
        if (!showNotifications) return
        var noticeId = String((details || {}).signature || "")
        if (noticeId === "") return
        if (Date.now() < _rulesDriftQuietUntilMs) {
            console.log("tray rules-drift: held back — a write is still settling")
            rulesDriftWatch.resetReported()
            return
        }
        var decidedAt = noticeLedger.decidedAt(noticeId)
        if (decidedAt > 0 && (Date.now() - decidedAt) < _rulesDriftRefractoryMs) {
            // Still suppressed. Clear the watch's latch so the same divergence
            // is re-offered once the refractory window is over, without needing
            // its own timer.
            rulesDriftWatch.resetReported()
            return
        }
        // Never displace a question already waiting for an answer.
        if (promptWindow && promptWindow.visible) {
            rulesDriftWatch.resetReported()
            return
        }

        var routes = (details || {}).routes || []
        var items = []
        for (var i = 0; i < routes.length; i += 1) {
            var r = routes[i] || {}
            items.push({
                primaryText: String(r.route) === "secondary"
                    ? routeSecondaryLabel : routePrimaryLabel,
                secondaryText: String(r.path || "")
            })
        }
        _rulesDriftNoticeId = noticeId
        _activeNoticeId = noticeId
        promptWindow.present({
            titleText: tr("tray.rules-drift.title",
                "Your rules files differ from what is applied"),
            bodyText: tr("tray.rules-drift.body",
                "The rules saved in your files are not the ones currently being applied. Apply the files, or open the app to see the difference."),
            items: items,
            listAccessibleName: tr("tray.rules-drift.list-accessible-name",
                "Rule files that differ"),
            primaryAction: {
                label: tr("action.apply", "Apply"),
                actionId: "rules-drift-apply",
                accent: true
            },
            secondaryAction: {
                label: tr("action.open-main-window", "Open NetRuleRouter"),
                actionId: "rules-drift-open"
            },
            dismissAction: {
                label: tr("notifications.dismiss", "Dismiss"),
                actionId: "rules-drift-dismiss"
            },
            autoRetireMs: _promptAutoRetireMs
        })
    }

    /// The divergence resolved on its own (the user applied the files from the
    /// window, or edited them back). Take the question down — it no longer has
    /// an answer worth giving.
    function _onRulesDriftCleared() {
        if (_rulesDriftNoticeId === "") return
        if (promptWindow && promptWindow.visible
                && _activeNoticeId === _rulesDriftNoticeId) {
            promptWindow.retire()
            _activeNoticeId = ""
        }
        _rulesDriftNoticeId = ""
    }

    // ── Blocked connection notices ────────────────────────────────────────────
    //
    // The service raises one notice per block EPISODE — not per retried packet
    // — and already filters against the mutes this tray writes: once a mute
    // covers a destination, app or "all", the matching pushes simply stop
    // arriving. There is no client-side ledger to keep in step with the main
    // window because the main window does not show this notice at all.

    /// Destination and app the notice currently on screen is about — the
    /// sub-screens (route confirm, snooze choice, mute choice) act on these.
    property string _blockNoticeDestination: ""
    property string _blockNoticeApp: ""
    /// Reason slug of the notice on screen — the mute chooser offers to
    /// silence this whole class ("stop telling me the tunnel is down").
    property string _blockNoticeReason: ""

    function _onBlockNoticeRaised(event) {
        if (!showNotifications) {
            console.log("tray block-notice: suppressed — notifications are off")
            return
        }
        var destination = String(event.destination || "")
        if (destination === "") {
            console.log("tray block-notice: suppressed — frame carries no destination")
            return
        }
        // Same signal RulesDriftWatch gates on: the main window is in front of
        // the user and a toast in the corner would only get in its way.
        var presence = guiPresence ? guiPresence.read() : { windowActive: false }
        if (presence.windowActive) {
            console.log("tray block-notice: suppressed — main window is active")
            return
        }
        console.log("tray block-notice: showing notice for", destination)
        var app = String(event.app || "")
        var reason = String(event.reason || "")
        var attempts = Number(event.attempts || 0)
        _presentOrQueue("block-notice", function() {
            tray._showBlockNotice(destination, app, reason, attempts)
        })
    }

    function _blockNoticeReasonLine(reason) {
        switch (reason) {
            case "route-unavailable":
                return tr("tray.block-notice.reason.route-unavailable",
                    "The route these addresses are bound to is down right now, "
                    + "so none of them open. This is one notice for the whole route.")
            case "not-covered-by-rules":
                return tr("tray.block-notice.reason.not-covered-by-rules",
                    "This app is confined to a route, and no rule covers this address there.")
            case "blocked-by-rule":
                return tr("tray.block-notice.reason.blocked-by-rule",
                    "A rule blocks this address directly.")
            default:
                return tr("tray.block-notice.reason.unspecified",
                    "No further detail available.")
        }
    }

    function _showBlockNotice(destination, app, reason, attempts) {
        _blockNoticeDestination = destination
        _blockNoticeApp = app
        _blockNoticeReason = reason
        _activeNoticeId = ""
        var summaryParts = [destination]
        if (app !== "") summaryParts.push(app)
        summaryParts.push(tr("tray.block-notice.attempts", "{count} attempts")
            .replace("{count}", String(attempts)))
        var body = summaryParts.join(" · ") + "\n" + _blockNoticeReasonLine(reason)
        // "Route unavailable" already means the address HAS a rule pointing at
        // a route — offering to add it there again would write nothing. What
        // the user can actually do is look at the route.
        var routeIsDown = (reason === "route-unavailable")
        var primary = routeIsDown
            ? {
                label: tr("tray.block-notice.action.open-routes",
                    "Open routes"),
                actionId: "block-notice-open-routes",
                accent: true
            }
            : {
                label: tr("tray.block-notice.action.route-to-secondary",
                    "To additional route"),
                actionId: "block-notice-route",
                accent: true,
                // Changes routing — the next screen asks for a real yes/no
                // before anything is written.
                keepsOpen: true
            }
        promptWindow.present({
            titleText: routeIsDown
                ? tr("tray.block-notice.title-route-down", "Additional route is unavailable")
                : tr("tray.block-notice.title", "Connection blocked"),
            bodyText: body,
            primaryAction: primary,
            secondaryAction: {
                label: tr("tray.block-notice.action.snooze", "Snooze"),
                actionId: "block-notice-snooze",
                keepsOpen: true
            },
            tertiaryAction: {
                label: tr("tray.block-notice.action.mute", "Don't show"),
                actionId: "block-notice-mute",
                keepsOpen: true
            },
            // No dismiss button: the corner close box and Esc still work, they
            // just answer nothing — closing this toast is not a decision.
            dismissActionId: "block-notice-dismiss",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    /// Second step of "To additional route": the action changes routing, so it
    /// gets its own yes/no instead of firing straight off the first click —
    /// same two-step shape as `_confirmAutoRulesAlways`.
    function _confirmBlockNoticeRoute() {
        promptWindow.present({
            titleText: tr("tray.block-notice.route-confirm.title",
                "Route {name} via the additional link?")
                .replace("{name}", _blockNoticeDestination),
            bodyText: tr("tray.block-notice.route-confirm.body",
                "Adds a rule that sends this address over the additional route from now on. You can undo it later in Rules."),
            primaryAction: {
                label: tr("action.confirm", "Confirm"),
                actionId: "block-notice-route-confirm",
                accent: true
            },
            dismissAction: {
                label: tr("action.cancel", "Cancel"),
                actionId: "block-notice-route-cancel"
            },
            dismissActionId: "block-notice-route-cancel",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    function _sendBlockNoticeRouteToSecondary(destination) {
        if (!bridgeAvailable || !rpc
                || typeof rpc.rpcBlockNoticeRouteToSecondary !== "function") return
        var corr = rpc.rpcBlockNoticeRouteToSecondary({ "destination": destination })
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.warn("block-notice route-to-secondary failed:", code, msg)
        })
    }

    /// The longest quick option. A mute is a wall-clock deadline on the
    /// service, and there is no restart event to expire one against, so this
    /// says "a day" and means it — a label promising "until restart" would be
    /// a promise the mechanism cannot keep.
    readonly property int _blockNoticeSnoozeLongestMs: 24 * 60 * 60 * 1000

    function _showBlockNoticeSnoozeChoice() {
        promptWindow.present({
            titleText: tr("tray.block-notice.snooze.title", "Snooze this notice"),
            bodyText: tr("tray.block-notice.snooze.body",
                "Stop asking about {name} for a while.")
                .replace("{name}", _blockNoticeDestination),
            primaryAction: {
                label: tr("tray.block-notice.snooze.for-15-minutes", "15 minutes"),
                actionId: "block-notice-snooze-15m"
            },
            secondaryAction: {
                label: tr("tray.block-notice.snooze.for-1-hour", "1 hour"),
                actionId: "block-notice-snooze-1h"
            },
            tertiaryAction: {
                label: tr("tray.block-notice.snooze.for-8-hours", "8 hours"),
                actionId: "block-notice-snooze-8h"
            },
            dismissAction: {
                label: tr("tray.block-notice.snooze.for-a-day", "For a day"),
                actionId: "block-notice-snooze-day"
            },
            // The X/Esc path is deliberately a DIFFERENT id than the longest
            // option's button: closing this chooser must not silently pick it.
            dismissActionId: "block-notice-snooze-cancel",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    function _applyBlockNoticeSnooze(action) {
        var ms = 0
        switch (action) {
            case "block-notice-snooze-15m": ms = 15 * 60 * 1000; break
            case "block-notice-snooze-1h": ms = 60 * 60 * 1000; break
            case "block-notice-snooze-8h": ms = 8 * 60 * 60 * 1000; break
            case "block-notice-snooze-day": ms = _blockNoticeSnoozeLongestMs; break
            default: return
        }
        _setBlockNoticeMute(
            { "kind": "host", "host": _blockNoticeDestination }, Date.now() + ms)
    }

    function _showBlockNoticeMuteChoice() {
        var slots = [{
            label: tr("tray.block-notice.mute.this-host", "This host"),
            actionId: "block-notice-mute-host",
            accent: true
        }]
        // "This app" only makes sense when the notice actually named one — an
        // unattributed connection has nothing for that scope to cover.
        if (_blockNoticeApp !== "") {
            slots.push({
                label: tr("tray.block-notice.mute.this-app", "This app"),
                actionId: "block-notice-mute-app"
            })
        }
        // Silencing the CAUSE is the wish a host or an app cannot express:
        // "tell me when a rule blocks something, but not every tunnel outage".
        if (_blockNoticeReason !== "") {
            slots.push({
                label: _blockNoticeMuteReasonLabel(_blockNoticeReason),
                actionId: "block-notice-mute-reason"
            })
        }
        slots.push({
            label: tr("tray.block-notice.mute.all", "All block notifications"),
            actionId: "block-notice-mute-all"
        })
        promptWindow.present({
            titleText: tr("tray.block-notice.mute.title", "Don't show this notice again"),
            bodyText: tr("tray.block-notice.mute.body",
                "Choose what to stop hearing about {name}.")
                .replace("{name}", _blockNoticeDestination),
            primaryAction: slots[0] || null,
            secondaryAction: slots[1] || null,
            tertiaryAction: slots[2] || null,
            // The fourth slot: this chooser can carry host, app, reason and
            // all at once, and the X/Esc path stays a separate id below.
            dismissAction: slots[3] || null,
            dismissActionId: "block-notice-mute-cancel",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    /// Short name of a block reason, shared with the mute list in Settings.
    function _blockNoticeMuteReasonLabel(reason) {
        switch (reason) {
            case "route-unavailable":
                return tr("block-reason.route-unavailable", "Route outages")
            case "not-covered-by-rules":
                return tr("block-reason.not-covered-by-rules", "Addresses no rule covers")
            case "blocked-by-rule":
                return tr("block-reason.blocked-by-rule", "Blocks by rule")
            default:
                return tr("block-reason.any", "Blocks of this kind")
        }
    }

    function _applyBlockNoticeMute(action) {
        switch (action) {
            case "block-notice-mute-host":
                _setBlockNoticeMute(
                    { "kind": "host", "host": _blockNoticeDestination }, undefined)
                break
            case "block-notice-mute-app":
                if (_blockNoticeApp === "") return
                _setBlockNoticeMute({ "kind": "app", "app": _blockNoticeApp }, undefined)
                break
            case "block-notice-mute-reason":
                if (_blockNoticeReason === "") return
                _setBlockNoticeMute(
                    { "kind": "reason", "reason": _blockNoticeReason }, undefined)
                break
            case "block-notice-mute-all":
                _setBlockNoticeMute({ "kind": "all" }, undefined)
                break
            default:
                break
        }
    }

    /// `untilUnixMs` absent (`undefined`) means "until removed" on the wire —
    /// the field is `Option<u64>` and `skip_serializing_if` on the Rust side,
    /// so leaving it off the request is how an indefinite mute is spelled.
    function _setBlockNoticeMute(scope, untilUnixMs) {
        if (!bridgeAvailable || !rpc
                || typeof rpc.rpcBlockNoticeMutesSet !== "function") return
        var req = { "scope": scope }
        if (untilUnixMs !== undefined) req["until-unix-ms"] = untilUnixMs
        var corr = rpc.rpcBlockNoticeMutesSet(req)
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.warn("block-notice mute set failed:", code, msg)
        })
    }

    /// A decision the OTHER surface recorded. Anything on screen for that id is
    /// moot now, so it comes down without counting as a second answer.
    function _onNoticeDecidedElsewhere(noticeId) {
        if (!promptWindow || !promptWindow.visible) return
        var id = String(noticeId || "")
        var mine = (id !== "" && id === _activeNoticeId)
        if (!mine) {
            for (var i = 0; i < _autoRuleActiveIds.length; i += 1) {
                if (id === _autoRuleNoticeId(_autoRuleActiveIds[i])) { mine = true; break }
            }
        }
        if (!mine) return
        promptWindow.retire()
        _activeNoticeId = ""
        _autoRuleActiveIds = []
    }

    /// Single dispatch for every prompt-window answer. Closing the window or
    /// pressing Esc arrives here as the dismiss action id.
    function _onPromptAction(actionId, selectedIndexes) {
        var action = String(actionId)
        // "Details" expands the evidence under each row and leaves the notice
        // standing — looking at something must not throw away the answer in
        // progress. Nothing is recorded, nothing is cleared. It used to open
        // the Rules screen instead, which had nothing to show: the candidates
        // are not rules yet, so the window landed on an unrelated table.
        if (action === "auto-rules-details") {
            promptWindow.detailsExpanded = !promptWindow.detailsExpanded
            return
        }
        // Block-notice actions swap the SAME window through a chain of
        // sub-screens (route confirm, snooze choice, mute choice) rather than
        // reusing the auto-rule id machinery below, which answers a different
        // question (a list of candidates) entirely.
        if (action === "block-notice-route") {
            _confirmBlockNoticeRoute()
            return
        }
        if (action === "block-notice-open-routes") {
            triggerAction("interfaces-routes")
            _scheduleDrain()
            return
        }
        if (action === "block-notice-route-confirm") {
            _sendBlockNoticeRouteToSecondary(_blockNoticeDestination)
            _scheduleDrain()
            return
        }
        if (action === "block-notice-route-cancel") {
            _scheduleDrain()
            return
        }
        if (action === "block-notice-snooze") {
            _showBlockNoticeSnoozeChoice()
            return
        }
        if (action === "block-notice-snooze-15m" || action === "block-notice-snooze-1h"
                || action === "block-notice-snooze-8h"
                || action === "block-notice-snooze-restart") {
            _applyBlockNoticeSnooze(action)
            _scheduleDrain()
            return
        }
        if (action === "block-notice-snooze-cancel") {
            _scheduleDrain()
            return
        }
        if (action === "block-notice-mute") {
            _showBlockNoticeMuteChoice()
            return
        }
        if (action === "block-notice-mute-host" || action === "block-notice-mute-app"
                || action === "block-notice-mute-reason"
                || action === "block-notice-mute-all") {
            _applyBlockNoticeMute(action)
            _scheduleDrain()
            return
        }
        if (action === "block-notice-mute-cancel") {
            _scheduleDrain()
            return
        }
        if (action === "block-notice-dismiss") {
            // The toast's own close box — no mute, nothing recorded, same
            // semantics as every other tray notice's X.
            _scheduleDrain()
            return
        }
        // Switching to automatic mode needs its own confirmation: swap the
        // window to the confirm screen and leave `_autoRuleActiveIds` alone
        // so a cancel can still fall through to the original notice.
        if (action === "auto-rules-always") {
            _confirmAutoRulesAlways(_pickIds(_autoRuleActiveIds, selectedIndexes))
            return
        }
        if (action === "auto-rules-mode-confirm") {
            var confirmedIds = _autoRulesModePendingIds
            _autoRulesModePendingIds = []
            _autoRuleActiveIds = []
            _activeNoticeId = ""
            noticeLedger.recordAll(confirmedIds.map(function(id) {
                return tray._autoRuleNoticeId(id)
            }))
            _autoRulesApplyAutomatically(confirmedIds)
            _scheduleDrain()
            return
        }
        if (action === "auto-rules-mode-cancel") {
            // Declined — nothing changes. Treat it like "not now" so the same
            // candidates do not immediately reappear.
            _snoozeCandidates(_autoRuleActiveIds)
            _autoRulesModePendingIds = []
            _autoRuleActiveIds = []
            _activeNoticeId = ""
            _scheduleDrain()
            return
        }
        var ids = _autoRuleActiveIds
        var picked = _pickIds(ids, selectedIndexes)
        _autoRuleActiveIds = []
        // Closing without pressing anything is not an answer. Re-offering the
        // same rows on the next push would be nagging, so THOSE rows are held
        // back for a while instead of being recorded as decided — addresses the
        // user has not been shown yet are unaffected.
        if (action === "auto-rules-later") {
            _activeNoticeId = ""
            _snoozeCandidates(ids)
            _scheduleDrain()
            return
        }
        // "Add checked" is a decision about the WHOLE list, not just the rows
        // that got checked: a row the user looked at and left unchecked is a
        // refusal, same as pressing "Never suggest checked" on it — it must
        // not keep coming back every push. It leaves through the same dismiss
        // path the explicit refusal button uses, so the service (and the
        // suggestions inbox) learn about it too, not just this tray process.
        var declined = []
        if (action === "auto-rules-accept") {
            for (var d = 0; d < ids.length; d += 1) {
                if (picked.indexOf(ids[d]) < 0) declined.push(ids[d])
            }
        }
        // An answer belongs to the shared ledger so the other surface stops
        // offering the same thing. Pressing the button decides every row on
        // screen — checked ones by acceptance, the rest by refusal.
        var answered = _activeNoticeId !== "" ? [_activeNoticeId] : []
        _activeNoticeId = ""
        for (var i = 0; i < picked.length; i += 1) {
            answered.push(_autoRuleNoticeId(picked[i]))
            // Only an explicit refusal is remembered for good. Recording an
            // acceptance the same way silenced the candidate forever: after the
            // user later dropped the rule, the service kept proposing it and
            // the tray kept throwing it away — a whole session with the
            // suggestions the user was waiting for going into the bin.
            if (action === "auto-rules-dismiss") {
                answered.push(_autoRuleRefusedId(picked[i]))
            }
        }
        for (var j = 0; j < declined.length; j += 1) {
            answered.push(_autoRuleNoticeId(declined[j]))
            answered.push(_autoRuleRefusedId(declined[j]))
        }
        noticeLedger.recordAll(answered)
        switch (action) {
            case "auto-rules-accept":
                _autoRulesAccept(picked)
                if (declined.length > 0) _autoRulesDismiss(declined)
                break
            case "auto-rules-dismiss":
                _autoRulesDismiss(picked)
                break
            case "rules-drift-apply":
                // The apply pipeline (review, elevation, activation) lives in
                // the main window; reproducing it here would mean a second,
                // unreviewed writer of routing policy. The tray hands over the
                // intent instead and the window runs its normal flow.
                _rulesDriftNoticeId = ""
                triggerAction("rules-drift-apply")
                break
            case "rules-drift-open":
                _rulesDriftNoticeId = ""
                triggerAction("rules")
                break
            case "rules-drift-dismiss":
                _rulesDriftNoticeId = ""
                break
            default:
                break
        }
        // The window is free again — whatever was held back gets its turn.
        _scheduleDrain()
    }

    /// The ids the checked rows stand for. An empty selection is not "all" —
    /// the user unticked everything, and the answer must cover nothing.
    function _pickIds(ids, selectedIndexes) {
        if (!ids || ids.length === 0) return []
        if (!selectedIndexes) return ids.slice()
        var out = []
        for (var i = 0; i < selectedIndexes.length; i += 1) {
            var idx = Number(selectedIndexes[i])
            if (idx >= 0 && idx < ids.length) out.push(ids[idx])
        }
        return out
    }

    function _autoRulesAccept(ids) {
        if (!ids || ids.length === 0) return
        if (!rpc || typeof rpc.rpcAutoRuleCandidatesAccept !== "function") return
        var corr = rpc.rpcAutoRuleCandidatesAccept({ "ids": ids })
        rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.warn("auto-rule accept failed:", code, msg)
                return
            }
            tray._notePendingCount(p)
        })
    }

    function _autoRulesDismiss(ids) {
        if (!ids || ids.length === 0) return
        if (!rpc || typeof rpc.rpcAutoRuleCandidatesDismiss !== "function") return
        var corr = rpc.rpcAutoRuleCandidatesDismiss({ "ids": ids })
        rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.warn("auto-rule dismiss failed:", code, msg)
                return
            }
            tray._notePendingCount(p)
        })
    }

    /// Keep the menu's count honest after an answer — the reply says what is
    /// left, so the row does not advertise addresses that are already rules.
    function _notePendingCount(payload) {
        if (!payload) return
        var left = payload.pending
        if (left === undefined) left = payload["pending"]
        if (left !== undefined) _autoRulePendingCount = Number(left)
    }

    /// Full-payload builder for `route.policy.update`. There is no sparse
    /// update: any field left out of the request falls back to a serde default
    /// on the service and silently resets whatever the user had configured.
    /// The tray runs in its own process, so it shares the field declaration
    /// with the main window through `lib/pure.js` rather than re-listing it —
    /// the tray has no `routeBehaviorMode` mirror, so the `mode` fallback is
    /// the contract default.
    function _buildFullRoutePolicyReq(cur) {
        return Pure.buildFullRoutePolicyReq(cur, "")
    }

    /// Write the per-SID `auto-rules-mode`, leaving every other policy field as
    /// the service holds it (the update is a FULL write). `onWritten` runs only
    /// on success.
    function _setAutoRulesMode(mode, onWritten) {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            return
        }
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        rpc.registerRpcCallback(readCorr, function(ok, p, code, msg) {
            if (!ok) {
                console.warn("auto-rule mode read failed:", code, msg)
                return
            }
            var cur = (p && (p["route-policy"] || p.routePolicy)) || {}
            var req = tray._buildFullRoutePolicyReq(cur)
            req["auto-rules-mode"] = String(mode)
            var writeCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
            tray.rpc.registerRpcCallback(writeCorr, function(ok2, p2, code2, msg2) {
                if (!ok2) {
                    console.warn("auto-rule mode write failed:", code2, msg2)
                    return
                }
                tray._autoRulesMode = String(mode)
                if (typeof onWritten === "function") onWritten()
            })
        })
    }

    /// "Add automatically from now on": flip the mode, then accept the
    /// candidates already on screen so the user's click covers both the future
    /// and the present. Only reached after the user confirms
    /// `_confirmAutoRulesAlways` below — flipping to `auto` means the app
    /// starts writing rules unattended, which is worth a real yes/no.
    function _autoRulesApplyAutomatically(ids) {
        _setAutoRulesMode("auto", function() { tray._autoRulesAccept(ids) })
    }

    /// Second step of "Add automatically from now on": explain what `auto`
    /// mode means before switching to it. Reuses the same prompt window
    /// instead of closing it, so the tray never has two windows racing for
    /// the screen corner.
    function _confirmAutoRulesAlways(ids) {
        _autoRulesModePendingIds = ids
        promptWindow.present({
            titleText: tr("tray.auto-rules-mode-confirm.title",
                "Turn on “Apply automatically”?"),
            bodyText: tr("tray.auto-rules-mode-confirm.body",
                "From now on NetRuleRouter will add suggested addresses to your rules files by itself, without asking. You can undo this anytime in Settings → Routing, by switching back to “Suggest only”."),
            primaryAction: {
                label: tr("tray.auto-rules-mode-confirm.confirm", "Turn on"),
                actionId: "auto-rules-mode-confirm",
                accent: true
            },
            dismissAction: {
                label: tr("action.cancel", "Cancel"),
                actionId: "auto-rules-mode-cancel"
            },
            dismissActionId: "auto-rules-mode-cancel",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    // ── External addresses in the menu ───────────────────────────────────────
    //
    // "What does the outside world see me as" is a question the tray is the
    // natural place to answer — it is one glance, and until now the only way to
    // get it was to open the window and find the interfaces screen.

    property string _externalPrimary: ""
    property string _externalSecondary: ""
    property bool _externalProbeBusy: false
    /// When the shown address came from the sidecar cache rather than from a
    /// live answer, this is when it was observed. A stopped service is exactly
    /// when the question gets asked, and answering it with silence taught
    /// nothing; answering it with a stale number and no date would be worse.
    property real _externalPrimaryCachedAtMs: 0
    property real _externalSecondaryCachedAtMs: 0

    /// Last known addresses per ROUTE, written by the main window from live
    /// answers. Read once at start-up and again whenever a live refresh comes
    /// back empty — a live value always wins and clears the "last known" mark.
    function _loadExternalAddressCache() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarExternalIpReadAll !== "function"
                || !rpc || typeof rpc.registerRpcCallback !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSidecarExternalIpReadAll()
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("tray external-ip cache read failed:", code, msg)
                return
            }
            var entries = (payload && payload.entries) || {}
            var take = function(role) {
                var e = entries[Pure.externalIpRoleCacheKey(role)] || {}
                return {
                    ip: String(e["external-ip"] || ""),
                    at: Number(e["observed-at-ms"] || 0)
                }
            }
            var primary = take("primary")
            if (tray._externalPrimary === "" && primary.ip !== "") {
                tray._externalPrimary = primary.ip
                tray._externalPrimaryCachedAtMs = primary.at
            }
            var secondary = take("secondary")
            if (tray._externalSecondary === "" && secondary.ip !== "") {
                tray._externalSecondary = secondary.ip
                tray._externalSecondaryCachedAtMs = secondary.at
            }
        })
    }

    /// One row per link, each naming its route in full. Both addresses on one
    /// row fitted only because the roles were abbreviated to "main"/"add.",
    /// which read as noise in front of a number; two named rows are no wider
    /// than that pair was.
    function _externalRouteLine(routeLabel, address, cachedAtMs) {
        var line = routeLabel + ": " + address
        if (cachedAtMs > 0) {
            line += " · " + tr("tray.external.last-known", "last known {when}")
                .replace("{when}", Pure.formatLastKnownTimestamp(cachedAtMs, Date.now()))
        }
        return line
    }

    /// Shown while neither address is known — the row still has to say what a
    /// click on it would do.
    function _externalUnknownLine() {
        return tr("tray.external.label", "External IP") + ": "
            + (_externalProbeBusy
                ? tr("tray.external.checking", "checking…")
                : tr("tray.external.unknown", "click to check"))
    }

    /// A menu is as wide as its widest row, and the status is a sentence. The
    /// full text stays in the icon tooltip, which is where a user looks for the
    /// long answer anyway.
    readonly property int _menuRowMaxChars: 34
    function _elideForMenu(text) {
        var t = String(text || "")
        if (t.length <= _menuRowMaxChars) return t
        return t.substring(0, _menuRowMaxChars - 1).replace(/[\s—·-]+$/, "") + "…"
    }

    /// Copy whatever is known, both lines when both are.
    function _takeExternalAddresses() {
        var known = []
        if (_externalPrimary !== "") known.push(_externalPrimary)
        if (_externalSecondary !== "") known.push(_externalSecondary)
        if (known.length === 0) {
            _probeExternalAddresses()
            return
        }
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge) return
        if (typeof nrrNativeBridge.copyToClipboard !== "function") return
        nrrNativeBridge.copyToClipboard(known.join("\n"))
    }

    /// The principal's `auto-rules-mode`. Read when the menu opens, because it
    /// decides whether silencing suggestions is even a thing that can be asked
    /// for: with `auto` nothing is ever suggested.
    property string _autoRulesMode: "suggest"

    /// Kill-switch on/off, as the service currently holds it. The user
    /// configures HOW it behaves in the window; the tray only flips it.
    property bool _killSwitchEnabled: false

    /// Everything the menu needs that is not already pushed to us. Cheap reads
    /// only, on an explicit menu open.
    function _refreshMenuState() {
        _suggestionsSilenced = Date.now() < _autoRuleSilencedUntilMs
        _refreshExternalAddresses()
        if (!bridgeAvailable || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInitialGet()
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            var policy = payload["route-policy"] || payload.routePolicy || {}
            var mode = String(policy["auto-rules-mode"] || "")
            if (mode !== "") tray._autoRulesMode = mode
            tray._killSwitchEnabled = policy["kill-switch-enabled"] === true
        })
    }

    /// Turn the kill-switch on or off, leaving every other field of the policy
    /// exactly as the service holds it: the update is a FULL write, so anything
    /// omitted would silently revert to a default.
    function _setKillSwitch(want) {
        if (!bridgeAvailable || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function"
                || typeof nrrNativeBridge.rpcRoutePolicyUpdate !== "function") {
            return
        }
        var readCorr = nrrNativeBridge.rpcSnapshotInitialGet()
        rpc.registerRpcCallback(readCorr, function(ok, payload, code, msg) {
            if (!ok) {
                console.warn("tray kill-switch: policy read failed:", code, msg)
                return
            }
            var cur = (payload && (payload["route-policy"] || payload.routePolicy)) || {}
            var req = tray._buildFullRoutePolicyReq(cur)
            req["kill-switch-enabled"] = (want === true)
            var writeCorr = nrrNativeBridge.rpcRoutePolicyUpdate(req)
            tray.rpc.registerRpcCallback(writeCorr, function(ok2, p2, code2, msg2) {
                if (!ok2) {
                    console.warn("tray kill-switch: write failed:", code2, msg2)
                    return
                }
                tray._killSwitchEnabled = (want === true)
            })
        })
    }

    /// Read the addresses the service already has. No probe: this runs whenever
    /// the menu opens, and a probe leaves the machine — that stays behind an
    /// explicit click.
    function _refreshExternalAddresses() {
        if (!bridgeAvailable || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInterfacesGet !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInterfacesGet()
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (ok) tray._applyExternalAddressRows(payload)
        })
    }

    /// Ask each adapter what it looks like from outside. User-initiated only.
    function _probeExternalAddresses() {
        if (_externalProbeBusy) return
        if (!bridgeAvailable || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcInterfacesRefresh !== "function") {
            return
        }
        _externalProbeBusy = true
        var corr = nrrNativeBridge.rpcInterfacesRefresh()
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            tray._externalProbeBusy = false
            if (!ok) {
                console.warn("tray external-address probe failed:", code, msg)
                return
            }
            tray._applyExternalAddressRows(payload)
        })
    }

    function _applyExternalAddressRows(payload) {
        var rows = (payload && payload.rows) || []
        var primary = ""
        var secondary = ""
        for (var i = 0; i < rows.length; i += 1) {
            var row = rows[i] || {}
            var role = String(row["selected-role"] || "")
            var facts = row["observed-facts"] || {}
            var ip = String(facts["external-ip"] || "")
            if (ip === "") continue
            if (role === "primary") primary = ip
            else if (role === "secondary") secondary = ip
        }
        if (primary !== "") {
            _externalPrimary = primary
            _externalPrimaryCachedAtMs = 0
        }
        // The push event is the fresher source for the additional link, so an
        // empty row must not erase what it told us.
        if (secondary !== "") {
            _externalSecondary = secondary
            _externalSecondaryCachedAtMs = 0
        }
        // Nothing live for a route this time: fall back to what was last
        // known rather than showing an empty menu.
        if (primary === "" || secondary === "") _loadExternalAddressCache()
    }

    // ── Quiet period for suggestions ─────────────────────────────────────────

    /// Silence suggestions for `hours` (0 = until the tray restarts). Distinct
    /// from refusing them: nothing is decided, the service keeps collecting,
    /// and the addresses are still there when the quiet period ends.
    /// Whether the quiet period is currently in force. A stored flag, not a
    /// `Date.now()` comparison inside a binding: bindings do not re-evaluate
    /// when time passes, so the menu would keep claiming silence long after it
    /// had expired. Refreshed whenever the menu opens.
    property bool _suggestionsSilenced: false

    function _silenceSuggestions(hours) {
        _autoRuleSilencedUntilMs = hours > 0
            ? Date.now() + hours * 3600000
            : Number.MAX_VALUE
        _suggestionsSilenced = true
        if (promptWindow && promptWindow.visible
                && _autoRuleActiveIds.length > 0) {
            promptWindow.retire()
            _autoRuleActiveIds = []
        }
    }

    function tr(key, fallbackText) {
        var activeLanguage = String(language || "").toLowerCase().replace(/_/g, "-")
        activeLanguage = activeLanguage.split(".")[0].split("@")[0]
        var activeMap = localeCatalog[activeLanguage] || {}
        if (activeMap[key] === undefined) {
            var baseLanguage = activeLanguage.split("-")[0]
            activeMap = localeCatalog[baseLanguage] || activeMap
        }
        var fallbackMap = localeCatalog["en"] || {}
        if (activeMap[key] !== undefined) return activeMap[key]
        if (fallbackMap[key] !== undefined) return fallbackMap[key]
        if (fallbackText !== undefined) return fallbackText
        return key
    }

    function actionById(actionId) {
        for (var i = 0; i < primaryActions.length; i += 1) {
            if (primaryActions[i].id === actionId) return primaryActions[i]
        }
        for (var j = 0; j < quickActions.length; j += 1) {
            if (quickActions[j].id === actionId) return quickActions[j]
        }
        return null
    }

    function actionLabel(actionId, fallbackText) {
        var action = actionById(actionId)
        return action ? action.label : fallbackText
    }

    function actionEnabled(actionId, fallbackEnabled) {
        var action = actionById(actionId)
        return action ? !!action.enabled : fallbackEnabled
    }

    function triggerAction(actionId) {
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge && nrrNativeBridge.triggerTrayAction) {
            nrrNativeBridge.triggerTrayAction(actionId)
            if (actionId === "exit-application") Qt.quit()
            return
        }
        console.log(actionMarker + actionId)
        if (actionId === "exit-application") Qt.quit()
    }

    function loadContext() {
        var args = Qt.application.arguments
        var url = ""
        for (var i = 0; i < args.length; i += 1) {
            if (args[i].indexOf("--nrr-context-file=") === 0) {
                url = args[i].slice("--nrr-context-file=".length)
            } else if (args[i].indexOf("--nrr-tray-context-file=") === 0) {
                url = args[i].slice("--nrr-tray-context-file=".length)
            }
            if (args[i].indexOf("--nrr-auto-close-ms=") === 0) {
                autoCloseMs = Number(args[i].slice("--nrr-auto-close-ms=".length))
            }
        }

        if (typeof nrrLaunchContext !== "undefined" && nrrLaunchContext) {
            context = nrrLaunchContext
        } else {
            if (url === "" && typeof nrrContextFileUrl !== "undefined" && nrrContextFileUrl) url = nrrContextFileUrl
            if (url === "") return
            var xhr = new XMLHttpRequest()
            xhr.open("GET", url, false)
            xhr.send()
            if (!(xhr.status === 0 || xhr.status === 200)) return
            context = JSON.parse(xhr.responseText)
        }
        language = context.language || "en"
        localeCatalog = context.localeCatalog || {}
        statusKey = context.statusKey || ""
        statusAccessibilityKey = context.statusAccessibilityKey || ""
        statusLine = context.statusLine || statusLine
        statusAccessibilityText = context.statusAccessibilityText || ""
        routePrimaryLabel = context.routePrimaryLabel || routePrimaryLabel
        routeSecondaryLabel = context.routeSecondaryLabel || routeSecondaryLabel
        iconFileUrl = context.iconFileUrl || ""
        theme = context.theme || theme
        primaryActions = context.primaryActions || []
        quickActions = context.quickActions || []
        showNotifications = context.showNotifications !== false
        notifySuggestionChanges = context.notifySuggestionChanges !== false
    }

    // ── What the tray says about itself ──────────────────────────────────────
    //
    // The launch context carries a status decided before the tray had spoken to
    // anything, so it can only be a placeholder. Everything below is derived
    // from what the tray has actually observed: the service's own state, whether
    // its event stream is live, and whether the service reports an active rule
    // set. A user hovering the icon gets an answer to "is this working right
    // now", which is the only question the icon is ever asked.

    /// Whether the service has told us what it is enforcing. False until the
    /// first answer arrives and again whenever the service goes away.
    property bool _enforcementKnown: false
    /// Whether the service reports an active rule set.
    property bool _enforcementActive: false
    property bool _enforcementFetchInFlight: false

    /// Ask the service what it is enforcing. Cheap (the health probe is the
    /// operation built for frequent calls) and event-driven: startup, service
    /// state changes, and the pushes that can change the answer.
    function _refreshEnforcementState() {
        if (!bridgeAvailable || !rpc
                || typeof nrrNativeBridge.rpcServiceHealthGet !== "function") return
        if (_enforcementFetchInFlight) return
        var corr = nrrNativeBridge.rpcServiceHealthGet()
        if (!corr || corr === "") return
        _enforcementFetchInFlight = true
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            tray._enforcementFetchInFlight = false
            if (!ok || !payload) {
                // Not an outage on its own — the tooltip falls back to saying
                // only what it does know.
                tray._enforcementKnown = false
                console.log("tray health probe failed:", code, msg)
                tray.refreshTooltip()
                return
            }
            var revision = String(payload["active-revision-id"]
                || payload.activeRevisionId || "")
            tray._enforcementActive = revision !== ""
            tray._enforcementKnown = true
            tray.refreshTooltip()
        })
    }

    on_EnforcementKnownChanged: refreshTooltip()
    on_EnforcementActiveChanged: refreshTooltip()
    on_TraySubscribedChanged: refreshTooltip()

    /// One line describing the live state, or "" when the tray has observed
    /// nothing yet (preview builds without the bridge) and the launch-time text
    /// is all there is.
    function _liveStatusLine() {
        if (!bridgeAvailable) return ""
        var slug = _serviceStatusSlug(serviceStatus)
        if (slug === "not-installed")
            return tr("tray.tooltip.service-not-installed",
                "Service not installed — click to install")
        if (slug === "stopped")
            return tr("tray.tooltip.service-stopped", "Service stopped — click to start")
        if (slug === "pending")
            return tr("tray.tooltip.service-pending", "Service changing state...")
        if (slug === "unknown")
            return tr("tray.tooltip.service-unknown", "Cannot read service status")
        // The service runs. Whether anything is being applied is a separate
        // question, and answering it wrongly is what sent a user looking for a
        // connection problem that did not exist.
        // Only claimed once an attempt has actually FAILED: between startup and
        // the first answer nothing is wrong yet, and an icon that cries outage
        // for a second on every launch teaches the user to ignore it.
        if (!_traySubscribed && _lastSubscribeFailureCode !== "")
            return tr("tray.tooltip.no-updates",
                "The service is running, but this app is not receiving updates from it")
        if (routingPaused)
            return tr("routing.status.tray-tooltip-paused",
                "Rules disabled — click to enable")
        if (_enforcementKnown && !_enforcementActive)
            return tr("tray.tooltip.no-rules-applied",
                "NetRuleRouter — no rules are being applied yet")
        if (_enforcementKnown && _enforcementActive)
            return tr("tray.tooltip.rules-applied",
                "NetRuleRouter — your rules are being applied")
        return tr("tray.tooltip.service-running", "NetRuleRouter — Service running")
    }

    function refreshTooltip() {
        var live = _liveStatusLine()
        if (live !== "") {
            // The menu header shows the same string: two surfaces of one icon
            // must not disagree about what is happening.
            statusLine = live
            tooltip = live
            return
        }
        var base = statusAccessibilityText !== ""
            ? statusLine + "\n" + statusAccessibilityText
            : statusLine
        if (routingPaused) {
            base = base + "\n" + tr("routing.status.tray-tooltip-paused",
                "Rules disabled — click to enable")
        }
        tooltip = base
    }

    Component.onCompleted: {
        loadContext()
        if (statusKey !== "") statusLine = tr(statusKey, statusLine)
        if (statusAccessibilityKey !== "") statusAccessibilityText = tr(statusAccessibilityKey, statusAccessibilityText)
        applyTrayIcon()
        refreshTooltip()
        visible = true

        // Wire bridge: connect rpcResponse + pushEvent,
        // fetch current pause state, subscribe to push.
        if (bridgeAvailable) {
            nrrNativeBridge.rpcResponse.connect(rpc.handleRpcResponse)
            if (typeof nrrNativeBridge.pushEvent !== "undefined") {
                nrrNativeBridge.pushEvent.connect(handlePushEvent)
            }
            var corrFetch = nrrNativeBridge.rpcRoutingPauseGet()
            rpc.registerRpcCallback(corrFetch, function(ok, p) {
                if (ok && p && typeof p.paused !== "undefined") {
                    routingPaused = !!p.paused
                }
            })
            _subscribeStatusUpdatesTray()
            // Sidecar, not the service: this is the one source that answers
            // while the service is stopped, which is when the menu would
            // otherwise have nothing to show.
            _loadExternalAddressCache()
        }

        if (autoCloseMs > 0) {
            autoCloseTimer = Qt.createQmlObject("import QtQuick 2.15; Timer { repeat: false }", tray, "autoCloseTimer")
            autoCloseTimer.interval = autoCloseMs
            autoCloseTimer.triggered.connect(function() { Qt.quit() })
            autoCloseTimer.start()
        }


        // Poll the Full-reset tray-shutdown
        // flag. The main GUI's "Full reset → close everything" writes it
        // (`requestTrayShutdown`); consuming it here quits the tray so the
        // whole app winds down for the reset to take effect on next launch.
        shutdownPollTimer = Qt.createQmlObject(
            "import QtQuick 2.15; Timer { interval: 250; running: true; repeat: true }",
            tray, "shutdownPollTimer")
        shutdownPollTimer.triggered.connect(function() {
            if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                    && typeof nrrNativeBridge.consumeTrayShutdownRequest === "function"
                    && nrrNativeBridge.consumeTrayShutdownRequest()) {
                Qt.quit()
            }
        })

        // Service status poller. The tray polls at 10 s
        // (vs 2 s in the Settings panel) because a tray-only display
        // doesn't need sub-second freshness, and lower cadence keeps
        // the SCM query off the hot path.
        if (typeof nrrServiceController !== "undefined" && nrrServiceController) {
            nrrServiceController.statusChanged.connect(function() {
                var newStatus = parseInt(nrrServiceController.status)
                // `_traySubscribed` latches true on a
                // successful subscribe and nothing ever resets it, so if the
                // service process dies and later restarts, the tray keeps
                // believing it's subscribed and stops receiving push updates
                // forever. Reset the latch whenever the service isn't Running
                // (4) so the existing `!_traySubscribed` retry guard on
                // serviceStatusTimer re-arms and re-subscribes once it's back.
                if (newStatus !== 4) _traySubscribed = false
                serviceStatus = newStatus
            })
            serviceStatus = parseInt(nrrServiceController.status)
            nrrServiceController.refreshStatus()
            serviceStatusTimer = Qt.createQmlObject(
                "import QtQuick 2.15; Timer { interval: 10000; running: true; repeat: true }",
                tray, "serviceStatusTimer")
            serviceStatusTimer.triggered.connect(function() {
                if (typeof nrrServiceController !== "undefined" && nrrServiceController) {
                    nrrServiceController.refreshStatus()
                }
                // Self-heal a cold-start subscribe that failed while the
                // service was down: retry on the 10s cadence until it succeeds so
                // the tray resumes receiving live pushes without a restart.
                if (!_traySubscribed && bridgeAvailable)
                    _subscribeStatusUpdatesTray()
            })
        }
    }

    property var serviceStatusTimer: null

    // The tray's StatusUpdates subscription is per-pipe-
    // connection and was issued once at startup; if the service was down then it
    // never retried. Make it re-callable and retry on the 10s status timer until
    // it succeeds so tray pushes self-heal after a cold start.
    property bool _traySubscribed: false
    // Tracks the failure code from the PREVIOUS attempt so the retry loop
    // can tell a state transition (first failure, or the failure reason
    // changed) from a plain repeat of the same ongoing outage. Cleared on
    // success. Without this, a genuinely-down service logged an identical
    // line every 10 s for as long as the outage lasted (248 lines across
    // one HW run) — the retry cadence itself is fine, only the logging
    // volume needed trimming.
    property string _lastSubscribeFailureCode: ""
    // The tooltip states whether the event stream is live, so a change in either
    // of these has to be reflected there.
    on_LastSubscribeFailureCodeChanged: refreshTooltip()
    function _subscribeStatusUpdatesTray() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcStatusUpdatesSubscribe !== "function")
            return
        var corrSub = nrrNativeBridge.rpcStatusUpdatesSubscribe("tray-" + (new Date().getTime()))
        rpc.registerRpcCallback(corrSub, function(ok, p, code, msg) {
            _traySubscribed = ok === true
            if (!ok) {
                var failureCode = String(code)
                if (failureCode !== _lastSubscribeFailureCode) {
                    console.warn("tray subscribe failed:", code, msg)
                    _lastSubscribeFailureCode = failureCode
                } else {
                    console.debug("tray subscribe failed (still):", code, msg)
                }
            } else if (_lastSubscribeFailureCode !== "") {
                console.info("tray subscribe recovered")
                _lastSubscribeFailureCode = ""
            }
            if (ok) {
                // The event stream is live, so the tray can now say what is
                // actually being enforced instead of guessing.
                tray._refreshEnforcementState()
            }
        })
    }

    // Qt 6.11 (Windows): the auto-popup of `SystemTrayIcon.menu` on
    // right-click does not fire for tray-only QQmlApplicationEngine apps —
    // the icon registers correctly but the native context menu never opens.
    // Manually invoking `menu.open()` from `onActivated(Context)` reliably
    // shows the menu and routes clicks back to the `MenuItem.onTriggered`
    // handlers (verified empirically — `Exit`, `Open NetRuleRouter`, etc.
    // all work). Keep this workaround until upstream Qt regression is fixed.
    onActivated: function(reason) {
        if (reason === SystemTrayIcon.Trigger) {
            triggerAction("open-main-window")
        } else if (reason === SystemTrayIcon.Context && menu) {
            menu.open()
        }
    }

    menu: Menu {
        id: trayMenu
        onAboutToShow: tray._refreshMenuState()

        MenuItem {
            text: tray._elideForMenu(statusLine)
            enabled: false
        }
        // Clicking copies; with nothing known yet the same click goes and finds
        // it, so the row is never a dead end.
        MenuItem {
            visible: tray._externalPrimary !== ""
            text: tray._externalRouteLine(
                tray.tr("tray.external.main-route", "Main route"),
                tray._externalPrimary,
                tray._externalPrimaryCachedAtMs)
            onTriggered: tray._takeExternalAddresses()
        }
        MenuItem {
            visible: tray._externalSecondary !== ""
            text: tray._externalRouteLine(
                tray.tr("tray.external.additional-route", "Additional route"),
                tray._externalSecondary,
                tray._externalSecondaryCachedAtMs)
            onTriggered: tray._takeExternalAddresses()
        }
        MenuItem {
            visible: tray._externalPrimary === "" && tray._externalSecondary === ""
            text: tray._externalUnknownLine()
            onTriggered: tray._takeExternalAddresses()
        }
        MenuSeparator {}
        MenuItem {
            text: tr("tray.menu.open", "Open")
            enabled: actionEnabled("open-main-window", true)
            onTriggered: triggerAction("open-main-window")
        }
        // The offer notice retires itself, so without a way back the addresses
        // are gone until the service happens to re-announce them.
        MenuItem {
            text: tray._autoRulePendingCount > 0
                ? tr("tray.menu.suggestions-count", "Suggested addresses ({count})")
                    .replace("{count}", String(tray._autoRulePendingCount))
                : tr("tray.menu.suggestions", "Suggested addresses")
            enabled: tray.serviceStatus === 4
            onTriggered: tray.showAutoRuleSuggestions()
        }
        MenuSeparator {}
        // How the kill-switch behaves is configured in the window; from here it
        // is one switch, which is what a tray is for.
        MenuItem {
            text: tray._killSwitchEnabled
                ? tr("tray.menu.kill-switch-off", "Turn kill-switch off")
                : tr("tray.menu.kill-switch-on", "Turn kill-switch on")
            enabled: tray.serviceStatus === 4
            onTriggered: tray._setKillSwitch(!tray._killSwitchEnabled)
        }
        MenuItem {
            text: tray.routingPaused
                ? tr("action.resume-rules", "Enable rules")
                : tr("action.pause-rules", "Disable rules")
            enabled: true
            onTriggered: {
                var nextPaused = !tray.routingPaused
                if (tray.bridgeAvailable) {
                    var prev = tray.routingPaused
                    tray.routingPaused = nextPaused
                    var corr = nrrNativeBridge.rpcRoutingPauseToggle(
                        nextPaused, "tray-toggle")
                    tray.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
                        if (!ok) {
                            console.log("tray pause toggle failed:", code, msg)
                            tray.routingPaused = prev
                        }
                        // On success, the push event will reaffirm
                        // `routingPaused` (idempotent).
                    })
                } else {
                    tray.routingPaused = nextPaused
                }
                triggerAction(nextPaused ? "pause-rules" : "resume-rules")
            }
        }
        // Only offered while suggestions are a thing that happens: in `auto`
        // mode nothing is ever proposed, so a "stop proposing" entry would be
        // a control over nothing.
        Menu {
            title: tray._suggestionsSilenced
                ? tr("tray.suggestions.silenced", "Address suggestions: silenced")
                : tr("tray.suggestions.silence", "Do not suggest addresses")
            visible: tray._autoRulesMode === "suggest"
            MenuItem {
                text: tr("tray.suggestions.for-30-minutes", "For 30 minutes")
                onTriggered: tray._silenceSuggestions(0.5)
            }
            MenuItem {
                text: tr("tray.suggestions.for-2-hours", "For 2 hours")
                onTriggered: tray._silenceSuggestions(2)
            }
            MenuItem {
                text: tr("tray.suggestions.for-4-hours", "For 4 hours")
                onTriggered: tray._silenceSuggestions(4)
            }
            MenuItem {
                text: tr("tray.suggestions.for-8-hours", "For 8 hours")
                onTriggered: tray._silenceSuggestions(8)
            }
            MenuItem {
                text: tr("tray.suggestions.until-restart", "Until restart")
                onTriggered: tray._silenceSuggestions(0)
            }
            MenuSeparator {}
            MenuItem {
                text: tr("tray.suggestions.resume", "Suggest again")
                enabled: tray._suggestionsSilenced
                onTriggered: {
                    tray._autoRuleSilencedUntilMs = 0
                    tray._autoRuleSnoozedIds = ({})
                    tray._suggestionsSilenced = false
                }
            }
        }
        // The way back out of `auto`. Without it the toast's "add
        // automatically" is a one-way door: nothing is proposed any more, so
        // the submenu above is hidden and the only remaining control is a combo
        // box three screens deep in the window.
        MenuItem {
            text: tr("tray.suggestions.stop-automatic", "Stop adding automatically")
            visible: tray._autoRulesMode === "auto"
            onTriggered: tray._setAutoRulesMode("suggest", null)
        }
        // Safe-disable always reachable from the
        // tray. The primary GUI's confirm-dialog is the gatekeeper:
        // a service-unavailable state surfaces there, not via a
        // greyed-out menu (which would leave the user without a
        // reason for the disablement).
        MenuItem {
            text: tr("tray.menu.safe-disable", "Disable temporarily…")
            enabled: true
            onTriggered: triggerAction("temporary-disable-product-impact")
        }
        // Starting and stopping is everyday and stays. Installing, removing and
        // the recovery actions are administration — they belong to the window,
        // where their consequences can be explained; a tray menu that carries
        // them is a menu nobody can read at a glance.
        MenuSeparator { visible: serviceStatus === 2 || serviceStatus === 4 }
        MenuItem {
            text: tr("tray.menu.start-service", "Start service")
            visible: serviceStatus === 2
            enabled: visible
            onTriggered: {
                if (typeof nrrServiceController !== "undefined" && nrrServiceController) {
                    nrrServiceController.startService()
                }
            }
        }
        MenuItem {
            text: tr("tray.menu.stop-service", "Stop service")
            visible: serviceStatus === 4
            enabled: visible
            onTriggered: {
                if (typeof nrrServiceController !== "undefined" && nrrServiceController) {
                    nrrServiceController.stopService()
                }
            }
        }
        MenuSeparator {}
        MenuItem {
            text: actionLabel("exit-application", tr("action.exit-application", "Exit"))
            enabled: actionEnabled("exit-application", true)
            onTriggered: triggerAction("exit-application")
        }
    }
}
