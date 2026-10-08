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
    // OS capability descriptor, mirrored from the main GUI context. The tray
    // polls the service on its own timers, so it has to answer "does this
    // platform have that operation" before it asks — an unregistered handler
    // refuses, and a timer asking anyway fills the service log with refusals.
    property var platformProfile: ({})
    function supports(feature) {
        if (!platformProfile || !platformProfile.supports) return true
        return platformProfile.supports[feature] !== false
    }
    readonly property bool localNetworksSupported: supports("localNetworkExceptions")
    readonly property bool blockNoticesSupported: supports("blockNotices")
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
    /// Per-kind mute for the "connection blocked" notice, and whether that
    /// notice may name the destination at all. Same launch-time snapshot rule.
    property bool notifyBlockNotices: true
    property bool hideBlockNoticeAddresses: false
    /// Whole-window opacity of the notice, in percent (Settings → General).
    property int noticeOpacityPercent: 100
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
        answerDeadlines: (typeof nrrLaunchContext !== "undefined" && nrrLaunchContext)
            ? (nrrLaunchContext.rpcAnswerDeadlines || null) : null
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
        opacityPercent: tray.noticeOpacityPercent
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
        _enforcementNoticeKind = ""
        _noticeMuteKind = ""
        // A block notice nobody answered is not quieted: unseen is not seen.
        _blockNoticeShown = []
        _blockNoticeRows = []
        _blockNoticeListSerial = -1
        _scheduleDrain()
        _scheduleBlockNoticeBatch()
    }

    // ── "Don't show…" for whole notice kinds ─────────────────────────────────
    //
    // Kept by the service beside the block mutes, per user, so the main window
    // honours the same answer and Settings lifts both from one list.

    /// Last `block-notices.mutes.list` answer and when it came.
    property var _noticeMutes: []
    property double _noticeMutesReadAtMs: 0
    /// Kind the chooser on screen is about.
    property string _noticeMuteKind: ""

    function _refreshNoticeMutes(onDone) {
        var corr = (rpc && typeof rpc.rpcBlockNoticeMutesList === "function")
            ? rpc.rpcBlockNoticeMutesList() : ""
        if (!corr || corr === "") {
            if (onDone) onDone()
            return
        }
        rpc.registerRpcCallback(corr, function(ok, p) {
            if (ok && p) {
                tray._noticeMutes = p.mutes || []
                tray._noticeMutesReadAtMs = Date.now()
            }
            if (onDone) onDone()
        })
    }

    function _noticeMutedNow(kind) {
        return Pure.noticeKindMuted(_noticeMutes, kind, Date.now())
    }

    /// Run `proceed` unless the user silenced `kind`. Read afresh: the main
    /// window's Settings may have lifted the mute, and nothing tells the tray.
    /// A lost answer leaves the last list in charge.
    function _whenNoticeAllowed(kind, proceed) {
        _refreshNoticeMutes(function() {
            if (tray._noticeMutedNow(kind)) {
                console.log("tray notice:", kind, "suppressed — the user muted it")
                return
            }
            proceed()
        })
    }

    /// `_presentOrQueue` for a kind the user may silence. Checked again when its
    /// turn comes: it may have queued behind the chooser that muted it.
    function _offerNotice(kind, queueKind, show) {
        _whenNoticeAllowed(kind, function() {
            tray._presentOrQueue(queueKind, function() {
                if (tray._noticeMutedNow(kind)) {
                    tray._scheduleDrain()
                    return
                }
                show()
            })
        })
    }

    function _noticeMuteAction(kind) {
        return {
            label: tr("action.dont-show", "Don't show…"),
            actionId: "notice-mute:" + kind,
            keepsOpen: true
        }
    }

    function _showNoticeMuteChoice(kind, name) {
        _noticeMuteKind = kind
        promptWindow.present({
            titleText: tr("tray.notice-mute.title", "Stop showing this notification?"),
            bodyText: tr("tray.notice-mute.body",
                    "\"{name}\" will not appear for as long as you choose.")
                .replace("{name}", name)
                + " " + tr("tray.mute.lift-hint",
                    "Mutes can be lifted later in Settings, Notifications."),
            primaryAction: {
                label: tr("label.duration.for-a-day", "For a day"),
                actionId: "notice-mute-1d",
                accent: false
            },
            secondaryAction: {
                label: tr("label.duration.for-7-days", "For 7 days"),
                actionId: "notice-mute-7d"
            },
            tertiaryAction: {
                label: tr("label.duration.for-30-days", "For 30 days"),
                actionId: "notice-mute-30d"
            },
            extraActions: [{
                label: tr("label.duration.forever", "Forever"),
                actionId: "notice-mute-forever"
            }],
            // Closing the chooser is not an answer — it must not pick a length.
            dismissActionId: "notice-mute-cancel",
            autoRetireMs: _promptAutoRetireMs
        })
    }

    function _applyNoticeMute(choice) {
        var req = Pure.noticeMuteRequest(_noticeMuteKind, choice, Date.now())
        _noticeMuteKind = ""
        if (req === null || !rpc || typeof rpc.rpcBlockNoticeMutesSet !== "function") return
        // Held locally at once: a notice of this kind queued behind the chooser
        // takes its turn before the service answers.
        _noticeMutes = _noticeMutes.concat([req])
        var corr = rpc.rpcBlockNoticeMutesSet(req)
        rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.warn("notice mute set failed:", code, msg)
                return
            }
            tray._noticeMutes = (p && p.mutes) || []
            tray._noticeMutesReadAtMs = Date.now()
        })
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
        os: tray.platformProfile.os || ""
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
            case "verify-primary-moved":
                _onVerifyPrimaryMoved(event)
                break
            case "block-notice-raised":
                _onBlockNoticeRaised(event)
                break
            case "enforcement-status-changed":
                _onEnforcementStatusChanged(event)
                break
            case "unassigned-tunnel-detected":
                _onUnassignedTunnel(event)
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
    property bool _autoRuleFetchInFlight: false
    /// How many suggestions the main window's list shows by default, as the
    /// service counts them — the menu row's count.
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
        // `top-anchor` is deliberately ignored: the prompt fetches the whole
        // pending list, so the site named by one push does not describe what the
        // user ends up seeing. The heading is derived from the shown rows.
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
            tray._autoRulePendingCount = Number(payload["pending-count"] || 0)
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

    /// Is this offer one the host made about ITSELF? Such a row has no site
    /// it belongs to — printing the arrow anyway rendered as "this site
    /// needs itself", which is not a thing anyone can act on.
    ///
    /// Read from the signal, with the structural check as a backstop: the
    /// slugs are pinned in `nrr-shared::ipc_payloads`, and a slug added
    /// there without reaching here must still not produce that row.
    function _isSelfSigned(c) {
        var signal = String((c || {}).signal || (c || {})["signal"] || "")
        if (["placeholder-answer", "main-link-blocked", "app-main-link-blocked"]
                .indexOf(signal) >= 0) return true
        var candidateAnchor = String((c || {}).anchor || (c || {})["anchor"] || "")
        var match = String((c || {})["proposed-match"] || (c || {}).proposedMatch || "")
        return candidateAnchor !== "" && candidateAnchor === match
    }

    /// Row subtitle: the site the address was seen with, plus the route when
    /// one notice mixes sites that do not share one.
    function _companionRowSubtitle(candidateAnchor, routeSlug, selfSigned) {
        var parts = []
        if (candidateAnchor !== "" && !selfSigned) {
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
        // Which route the answer would put them on. The user asked to see it
        // before deciding; it is the anchor's own route, so it is the same for
        // every row of one site and only differs when sites are mixed.
        var routes = []
        // Anchors of the rows actually SHOWN. The push event's `top-anchor` is
        // not usable for the heading: the list is fetched whole, so it routinely
        // contains companions of other sites — a notice headed
        // "docs.search.example" listed rows belonging to assistant.example and
        // reddit.com. The heading is derived from what the user can see.
        var anchorCounts = ({})
        // How many of the shown rows are offers a host made about itself.
        // When that is all of them the notice is about sites that do not
        // open, not about addresses some other site needs.
        var selfSignedCount = 0
        // Of those, how many are whole programs rather than sites.
        var appCount = 0
        // Group by site so rows of one site sit together; ties break on the
        // name, so the same set always lists in the same order.
        // Only what the inbox lists by default: a row the list hides is not
        // news, and offering it here made the popup disagree with the count.
        var ordered = Pure.autoRuleRowsShownByDefault(candidates).sort(function(a, b) {
            var aa = String((a || {}).anchor || "")
            var bb = String((b || {}).anchor || "")
            if (aa === bb) return 0
            return aa < bb ? -1 : 1
        })
        for (var i = 0; i < ordered.length; i += 1) {
            if (ids.length >= _autoRuleMaxPerNotice) break
            var c = ordered[i] || {}
            var id = String(c.id || c["id"] || "")
            if (id === "") continue
            if (_autoRuleShowAll
                    ? noticeLedger.isDecided(_autoRuleRefusedId(id))
                    : _autoRuleAnswered(id)) continue
            var candidateAnchor = String(c.anchor || c["anchor"] || "")
            var selfSigned = _isSelfSigned(c)
            if (selfSigned) selfSignedCount += 1
            if (String(c.signal || c["signal"] || "") === "app-main-link-blocked") appCount += 1
            // A host that signed its own offer is not a site whose
            // companions are being listed, so it must not become the
            // heading — that is what read as "this site needs itself".
            if (candidateAnchor !== "" && !selfSigned) {
                anchorCounts[candidateAnchor] = Number(anchorCounts[candidateAnchor] || 0) + 1
            }
            var candidateRoute = String(c.route || c["route"] || "")
            if (candidateRoute !== "" && routes.indexOf(candidateRoute) < 0) {
                routes.push(candidateRoute)
            }
            ids.push(id)
            items.push({
                primaryText: String(c["proposed-match"] || c.proposedMatch || ""),
                secondaryText: _companionRowSubtitle(
                    candidateAnchor, routes.length > 1 ? candidateRoute : "", selfSigned),
                detailText: _candidateDetailLine(c)
            })
        }
        var anchorNames = Object.keys(anchorCounts)
        anchorNames.sort(function(a, b) {
            var d = anchorCounts[b] - anchorCounts[a]
            return d !== 0 ? d : (a < b ? -1 : (a > b ? 1 : 0))
        })
        var anchor = anchorNames.length > 0 ? anchorNames[0] : ""
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
        // Every row is a site that will not open. Saying "addresses a site
        // needs" over that list states the wrong problem: nobody is missing
        // a companion, the main route is dropping the site itself.
        var allSelfSigned = selfSignedCount === ids.length
        var allApps = ids.length > 0 && appCount === ids.length
        // Neither "sites" nor "programs" is true of a list holding both.
        var mixedApps = appCount > 0 && !allApps
        var titleText = allApps
            ? tr("tray.auto-rules.title-app-blocked", "Programs the main route will not carry")
            : mixedApps
            ? tr("tray.auto-rules.title-mixed-blocked", "Not getting through on the main route")
            : allSelfSigned
            ? tr("tray.auto-rules.title-blocked",
                    "Sites the main route will not carry")
            : tr("tray.auto-rules.title", "Addresses a site needs")
        var bodyText
        if (allApps) {
            bodyText = tr("tray.auto-rules.body-app-blocked",
                    "No connection of {name} goes through on the main route.")
                .replace("{name}", items.map(function(it) { return it.primaryText }).join(", "))
        } else if (mixedApps) {
            bodyText = tr("tray.auto-rules.body-mixed-blocked",
                    "The programs and sites below keep failing on the main route.")
        } else if (allSelfSigned) {
            bodyText = ids.length > 1
                ? tr("tray.auto-rules.body-blocked-multi",
                        "Connections to {count} sites keep failing on the main route.")
                    .replace("{count}", String(ids.length))
                : tr("tray.auto-rules.body-blocked",
                        "Connections to {name} keep failing on the main route.")
                    .replace("{name}", items[0].primaryText)
        } else {
            // One heading cannot honestly name one site when the rows belong
            // to several; each row still says which site it came from.
            bodyText = anchorNames.length > 1
                ? tr("tray.auto-rules.body-multi",
                        "Found addresses that {count} of the sites you routed need.")
                    .replace("{count}", String(anchorNames.length))
                : tr("tray.auto-rules.body",
                        "Found addresses without which {name} will not work fully.")
                    .replace("{name}", siteName)
        }
        // Mixed routes are named per row instead; one shared route reads
        // better as a sentence than as a repeated tag.
        if (routes.length === 1) {
            var routeLine = _routeSentence(routes[0])
            if (routeLine !== "") bodyText = bodyText + "\n" + routeLine
        }
        bodyText = bodyText + "\n" + tr("tray.auto-rules.unchecked-declined",
            "Unchecked rows will be declined; you can bring them back later in the app.")
        promptWindow.present({
            titleText: titleText,
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
                label: tr("action.details", "Details"),
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

    /// How long a notice that asks NOTHING stays on screen — the external
    /// address, "routing is back". Long enough to read and copy an address,
    /// short enough that a user who walked away comes back to their own work
    /// rather than to a stale window sitting over it. Notices that carry a
    /// decision keep `_promptAutoRetireMs`: those wait for an answer.
    readonly property int _infoNoticeMs: 10000

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
        _offerNotice("external-address", "external-address", function() {
            tray._showExternalAddressNotice(noticeId, address, adapter)
        })
    }

    /// A `?` rule moved to the additional route. Happens once per rule, so it
    /// is told once and needs no "Don't show…".
    function _onVerifyPrimaryMoved(event) {
        if (!showNotifications) return
        var host = String(event.host || "")
        if (host === "") return
        _presentOrQueue("verify-moved", function() {
            promptWindow.present({
                titleText: tr("tray.verify-moved.title", "Site moved to the additional route"),
                bodyText: Pure.fillPlaceholders(tr("tray.verify-moved.body",
                        "{host} does not open over the primary route, so its rule now uses the additional route."),
                    { host: "<b>" + _escapeMarkup(host) + "</b>" }),
                bodyRichText: true,
                autoRetireMs: _infoNoticeMs
            })
        })
    }

    function _showExternalAddressNotice(noticeId, address, adapter) {
        // Bold only the address itself, not the surrounding sentence — the
        // markup lives here, not in the translated string, so the localized
        // text stays plain prose in both locale files.
        var body = tr("tray.external-address.body",
                "External address of the additional route: {address}")
            .replace("{address}", "<b>" + _escapeMarkup(address) + "</b>")
        if (adapter !== "") {
            // `<br>`, not `\n`: StyledText collapses a bare newline.
            body = body + "<br>" + Pure.fillPlaceholders(
                tr("tray.external-address.adapter", "Adapter: {name}"),
                { name: _escapeMarkup(adapter) })
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
            // No accent "Close": the corner close box closes it, and an accent
            // button here lands right on top of the main window's own "Close" —
            // one notice retiring a moment early took the app down with it.
            // "Don't show…" only opens a chooser, so a stray click costs nothing.
            secondaryAction: _noticeMuteAction("external-address"),
            // Timing out is not an answer: a user who was away never saw it,
            // so the notice stays undecided and the main window still offers
            // it. The window owns the countdown — one mechanism, and it fires
            // for whatever is on screen rather than for a hand-wired case.
            autoRetireMs: _infoNoticeMs
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

    /// How stale the mute list may get while the drift watch re-asks every
    /// tick: it is read from cache here, so a lifted mute shows within this.
    readonly property int _noticeMutesMaxAgeMs: 10 * 60 * 1000

    function _onRulesDriftDetected(details) {
        if (!showNotifications) return
        var noticeId = String((details || {}).signature || "")
        if (noticeId === "") return
        if (Date.now() - _noticeMutesReadAtMs > _noticeMutesMaxAgeMs) _refreshNoticeMutes(null)
        if (_noticeMutedNow("rules-drift")) {
            // Unlatched, so the divergence is offered again once the mute lapses.
            rulesDriftWatch.resetReported()
            return
        }
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
            // Looking first, acting second: "Apply" here takes the FILE side
            // and would silently drop an edit the user has open in the window.
            // The accented answer is therefore the one that shows the
            // difference; applying stays available, one button over.
            primaryAction: {
                label: tr("tray.rules-drift.action.compare", "Open and compare"),
                actionId: "rules-drift-open",
                accent: true
            },
            secondaryAction: {
                label: tr("tray.rules-drift.action.apply-files", "Apply the files"),
                actionId: "rules-drift-apply"
            },
            tertiaryAction: _noticeMuteAction("rules-drift"),
            dismissAction: {
                label: tr("action.dismiss", "Dismiss"),
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

    /// Destination of a ONE-block notice — the sub-screens (route confirm,
    /// snooze choice) name it. Empty while the notice lists several blocks;
    /// `_blockNoticeShown` is then what they read.
    property string _blockNoticeDestination: ""
    /// Reason slug every block on screen shares, "" when they differ — the
    /// mute chooser offers to silence this whole class.
    property string _blockNoticeReason: ""

    /// Blocks that have arrived and not been shown yet.
    ///
    /// Two failures made one window per block the wrong shape. A page that
    /// cannot reach five hosts produced five windows, each waiting for its own
    /// answer; and the queue keeps only the NEWEST entry of a kind, so the
    /// second of three was dropped without ever being seen. Collecting for a
    /// moment and presenting once fixes both: nothing is lost, and a burst
    /// costs one decision.
    property var _blockNoticeBatch: []
    /// The blocks the notice on screen is about. Snooze and mute act on all of
    /// them — "stop telling me about this" is rarely meant for one address out
    /// of five — while the route action acts on the checked rows only.
    property var _blockNoticeShown: []
    /// The rows as drawn, in list order: row index -> the blocks behind it.
    property var _blockNoticeRows: []
    /// `promptWindow.presentationSerial` of the block list, -1 when none is
    /// up. A sub-screen (route confirm, snooze, mute) is a new presentation, so
    /// a block arriving then waits its turn instead of swapping the chooser
    /// out from under the user.
    property int _blockNoticeListSerial: -1
    /// What the route action was pressed for, captured WITH the checkboxes at
    /// that moment: the confirm screen replaces the list, and the answer has to
    /// still be about what was checked when it was asked for.
    property var _blockNoticeRouteTargets: []
    /// Long enough for a page's burst of requests to land in one notice, short
    /// enough that the notice still reads as a reaction to what just happened.
    readonly property int _blockNoticeCollectMs: 3000
    /// Rows a merged notice lists before it falls back to "and N more". The
    /// rest are still covered by snooze and mute, which act on the whole batch.
    readonly property int _blockNoticeListCap: 5
    /// Bound on the batch itself: past this the machine is having an outage,
    /// not a moment, and the oldest rows are the least useful to show.
    readonly property int _blockNoticeBatchCap: 50
    property Timer _blockNoticeCollectTimer: Timer {
        interval: tray._blockNoticeCollectMs
        repeat: false
        onTriggered: tray._presentBlockNoticeBatch()
    }

    /// Reasons whose rows fold per program. Routing answers none of them — a
    /// switch does, or the route is already down — so the addresses are
    /// detail, and five rows of one program's DNS servers were noise. Routeable
    /// reasons keep a row per address: a group tick would route every site a
    /// browser failed on when the user meant one of them.
    readonly property var _blockNoticeGroupableReasons:
        ["dns-lockdown", "ipv6-blocked", "route-unavailable"]

    /// (program, reason) -> epoch ms until which it raises no NEW window. In
    /// memory only: a tray that restarts may say it once more, which is the
    /// cheaper failure than persisting a quiet nobody can see or lift.
    property var _blockNoticeQuietUntil: ({})
    /// A dismissed notice means "I have seen this"; the same program failing
    /// the same way a minute later is the same news.
    readonly property int _blockNoticeQuietMs: 60 * 60 * 1000

    function _onBlockNoticeRaised(event) {
        if (!showNotifications || !notifyBlockNotices) {
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
        var entry = {
            destination: destination,
            app: String(event.app || ""),
            reason: String(event.reason || ""),
            attempts: Number(event.attempts || 0),
            launchedBy: _launchedByChain(event["launched-by"])
        }
        if (_blockNoticeQuiet(entry)) {
            console.log("tray block-notice: suppressed — dismissed within the hour:",
                entry.app !== "" ? entry.app : destination, entry.reason)
            return
        }
        if (_rememberBlockNotice(entry)) return
        console.log("tray block-notice: collecting notice for", destination)
        // The timer is NOT restarted by later arrivals: a steady stream would
        // otherwise push the notice away for as long as it lasts, which is
        // exactly when the user wants to hear about it.
        if (!_blockNoticeCollectTimer.running) _blockNoticeCollectTimer.start()
    }

    /// Where a block goes: into the list already on screen, or into the batch
    /// for the next window. True when it joined the window.
    function _rememberBlockNotice(entry) {
        if (!_blockNoticeListOnScreen()) {
            _blockNoticeBatch = _foldBlockNotice(_blockNoticeBatch, entry)
            return false
        }
        console.log("tray block-notice: joining the notice on screen:", entry.destination)
        var before = _blockNoticeShown
        _blockNoticeShown = _foldBlockNotice(before, entry)
        // A one-block notice had no checkboxes: its block was what the button
        // meant, so it stays chosen once the window turns into a list.
        var carried = before.length === 1
            ? [Pure.groupBlockNotices(before, _blockNoticeGroupableReasons)[0].key] : []
        _renderBlockNotice(true, carried)
        return true
    }

    /// Fold one block into `list`: a repeat of a block already there updates
    /// its row, anything else is appended. The service folds retries of one
    /// episode already; this catches the second episode inside one notice.
    function _foldBlockNotice(list, entry) {
        var out = list.slice()
        for (var i = 0; i < out.length; i += 1) {
            if (out[i].destination === entry.destination
                    && out[i].app === entry.app
                    && out[i].reason === entry.reason) {
                out[i] = {
                    destination: entry.destination,
                    app: entry.app,
                    reason: entry.reason,
                    attempts: Math.max(Number(out[i].attempts || 0), entry.attempts),
                    // The latest episode's parents: a second one may come from
                    // another shell, and what the user sees should be current.
                    launchedBy: entry.launchedBy.length > 0
                        ? entry.launchedBy : (out[i].launchedBy || [])
                }
                return out
            }
        }
        out.push(entry)
        while (out.length > _blockNoticeBatchCap) out.shift()
        return out
    }

    /// Is the block list itself on screen and still waiting for an answer?
    /// A pressed button settles the window a pass before it goes down; a block
    /// arriving in that gap belongs to the next window, not to this one.
    function _blockNoticeListOnScreen() {
        return !!promptWindow && promptWindow.visible && !promptWindow._settled
            && _blockNoticeListIsCurrent()
    }
    function _blockNoticeListIsCurrent() {
        return !!promptWindow && _blockNoticeListSerial >= 0
            && promptWindow.presentationSerial === _blockNoticeListSerial
            && _blockNoticeShown.length > 0
    }

    /// Hand the batch to the surface. Presenting goes through the same queue as
    /// every other notice, and the closure reads the batch when it RUNS — so
    /// blocks that arrive while another notice is still up join the same
    /// window instead of queueing behind it.
    function _presentBlockNoticeBatch() {
        if (_blockNoticeBatch.length === 0) return
        if (_blockNoticeListOnScreen()) {
            var waiting = _blockNoticeBatch
            _blockNoticeBatch = []
            for (var i = 0; i < waiting.length; i += 1) _rememberBlockNotice(waiting[i])
            return
        }
        _presentOrQueue("block-notice", function() {
            tray._showBlockNoticeBatch()
        })
    }

    /// Present what has collected: one block reads as a sentence, several
    /// become one list.
    function _showBlockNoticeBatch() {
        // A block collected while its twin's notice was still being closed
        // must not bring that notice straight back.
        var batch = _blockNoticeBatch.filter(function(e) { return !tray._blockNoticeQuiet(e) })
        _blockNoticeBatch = []
        if (batch.length === 0) return
        _blockNoticeShown = batch
        _renderBlockNotice(false, [])
    }

    /// Draw `_blockNoticeShown`: freshly, or over the list already on screen.
    /// In place, the window keeps its ticks and is never re-shown — closing
    /// and reopening it inside one pass is the Qt assert the drain timer
    /// exists to avoid.
    function _renderBlockNotice(inPlace, carriedKeys) {
        var shown = _blockNoticeShown
        var config = shown.length === 1
            ? _singleBlockNoticeConfig(shown[0])
            : _mergedBlockNoticeConfig(shown, inPlace && promptWindow.detailsExpanded)
        _activeNoticeId = ""
        if (inPlace) {
            config.preCheckedKeys = carriedKeys || []
            promptWindow.replaceContent(config)
        } else {
            promptWindow.present(config)
        }
        _blockNoticeListSerial = promptWindow.presentationSerial
    }

    /// Blocks that arrived while a notice was being answered get their turn as
    /// soon as it is over, without waiting for the next one to push the timer.
    function _scheduleBlockNoticeBatch() {
        if (_blockNoticeBatch.length === 0) return
        if (!_blockNoticeCollectTimer.running) _blockNoticeCollectTimer.start()
    }

    /// The notice is over, whichever way it ended. Frees the surface and lets
    /// anything that collected meanwhile take its turn.
    function _blockNoticeAnswered() {
        _blockNoticeShown = []
        _blockNoticeRows = []
        _blockNoticeListSerial = -1
        _scheduleDrain()
        _scheduleBlockNoticeBatch()
    }

    // ── Quiet period ──

    function _blockNoticeQuietKey(entry) {
        var app = String(entry.app || "").toLowerCase()
        // Without a program the pair would silence every unattributed block of
        // that reason; the address is the narrowest thing left to key on.
        return (app !== "" ? "app|" + app : "dest|" + String(entry.destination || ""))
            + "|" + String(entry.reason || "")
    }

    function _blockNoticeQuiet(entry) {
        return Date.now() < Number(_blockNoticeQuietUntil[_blockNoticeQuietKey(entry)] || 0)
    }

    /// The user closed the notice having seen it: its (program, reason) pairs
    /// raise no new window for the next hour. Expired pairs are dropped here
    /// so the map cannot grow with the session.
    function _quietShownBlockNotices() {
        var now = Date.now()
        var next = {}
        for (var known in _blockNoticeQuietUntil) {
            if (Number(_blockNoticeQuietUntil[known]) > now) {
                next[known] = _blockNoticeQuietUntil[known]
            }
        }
        for (var i = 0; i < _blockNoticeShown.length; i += 1) {
            next[_blockNoticeQuietKey(_blockNoticeShown[i])] = now + _blockNoticeQuietMs
        }
        _blockNoticeQuietUntil = next
    }

    // ── Who started the program ──

    /// `launched-by` of a block: image names, nearest parent first. Read
    /// defensively — an older service sends nothing, and a garbled value must
    /// cost a missing line, not the notice.
    function _launchedByChain(raw) {
        var list = typeof raw === "string" ? [raw]
            : (raw && typeof raw.length === "number" ? raw : [])
        var out = []
        for (var i = 0; i < list.length && out.length < 6; i += 1) {
            var name = (list[i] === undefined || list[i] === null) ? "" : String(list[i]).trim()
            if (name !== "") out.push(name.length > 64 ? name.slice(0, 63) + "…" : name)
        }
        return out
    }

    /// The most recent non-empty chain among `entries`.
    function _blockNoticeChainOf(entries) {
        for (var i = entries.length - 1; i >= 0; i -= 1) {
            var chain = entries[i].launchedBy || []
            if (chain.length > 0) return chain
        }
        return []
    }

    /// "curl.exe ← powershell.exe ← WindowsTerminal.exe"
    function _appChainText(app, chain) {
        return [app].concat(chain).join(" ← ")
    }

    /// The same chain in words: arrows read aloud as symbol names.
    function _appChainAccessible(app, chain) {
        var parts = [app]
        for (var i = 0; i < chain.length; i += 1) {
            parts.push(tr("tray.block-notice.launched-by", "launched by {name}")
                .replace("{name}", chain[i]))
        }
        return parts.join(", ")
    }

    /// "{count} DNS servers" — the stem's plural form for `count`, chosen by
    /// the rule family the active locale file names.
    function _trCount(stem, count, fallbackOne, fallbackOther) {
        var category = Pure.pluralCategory(tr("label.plural-rule", "one-other"), count)
        var text = tr(stem + category, "")
        if (text === "") text = tr(stem + "other", count === 1 ? fallbackOne : fallbackOther)
        return text.replace("{count}", String(count))
    }

    /// How many addresses a folded row stands for, named for its reason.
    function _blockNoticeCountNoun(reason, count) {
        switch (reason) {
            case "dns-lockdown":
                return _trCount("tray.block-notice.count.dns-lockdown.", count,
                    "{count} DNS server", "{count} DNS servers")
            case "ipv6-blocked":
                return _trCount("tray.block-notice.count.ipv6-blocked.", count,
                    "{count} IPv6 address", "{count} IPv6 addresses")
            default:
                return _trCount("tray.block-notice.count.address.", count,
                    "{count} address", "{count} addresses")
        }
    }

    /// The destinations behind the rows the user left checked. An index past
    /// the listed rows cannot be checked, so it is ignored rather than mapped
    /// onto a row the user never saw.
    function _blockNoticeCheckedHosts(selectedIndexes) {
        var shown = _blockNoticeShown
        if (shown.length === 0) {
            return _blockNoticeDestination === "" ? [] : [_blockNoticeDestination]
        }
        // A single-block notice carries no checkboxes: its one destination is
        // what the button is about.
        if (shown.length === 1 || !selectedIndexes) {
            return [String(shown[0].destination || "")].filter(function(h) { return h !== "" })
        }
        var hosts = []
        for (var i = 0; i < selectedIndexes.length; i += 1) {
            var row = _blockNoticeRows[Number(selectedIndexes[i])]
            if (!row) continue
            for (var e = 0; e < row.entries.length; e += 1) {
                var host = String(row.entries[e].destination || "")
                // Only what a rule can act on: a route that is down already has one.
                if (host !== "" && hosts.indexOf(host) < 0
                        && _blockNoticeIsRouteable(row.entries[e].reason)) {
                    hosts.push(host)
                }
            }
        }
        return hosts
    }

    /// A few words per reason, for a list row where the full sentence would
    /// push the program name out of sight.
    function _blockNoticeReasonShort(reason) {
        switch (reason) {
            case "route-unavailable":
                return tr("tray.block-notice.reason-short.route-unavailable", "Route is down")
            case "not-covered-by-rules":
                return tr("tray.block-notice.reason-short.not-covered-by-rules",
                    "No rule for this address")
            case "blocked-by-rule":
                return tr("tray.block-notice.reason-short.blocked-by-rule", "Blocked by a rule")
            case "ipv6-blocked":
                return tr("tray.block-notice.reason-short.ipv6-blocked", "IPv6 is switched off")
            case "dns-lockdown":
                return tr("tray.block-notice.reason-short.dns-lockdown", "Own encrypted DNS")
            case "unattributed":
                return tr("tray.block-notice.reason-short.unattributed", "Blocked, filter unknown")
            default:
                return tr("tray.block-notice.reason-short.unspecified", "Blocked")
        }
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
            case "ipv6-blocked":
                return tr("tray.block-notice.reason.ipv6-blocked",
                    "IPv6 is switched off while leak protection is on, and this address is IPv6. "
                    + "No rule blocked it — the switch is in Settings.")
            case "dns-lockdown":
                return tr("tray.block-notice.reason.dns-lockdown",
                    "This app tried to reach a public DNS resolver of its own instead of the one "
                    + "NetRuleRouter provides, and encrypted-DNS blocking closed it. "
                    + "No rule blocked it — the switch is in Settings, under Routing.")
            case "unattributed":
                return tr("tray.block-notice.reason.unattributed",
                    "NetRuleRouter blocked this address, but could not identify which filter did it.")
            default:
                return tr("tray.block-notice.reason.unspecified",
                    "No further detail available.")
        }
    }

    /// What the user is told the notice is about. The destination is the one
    /// field the "hide addresses" preference covers — a screen being shared
    /// must not leak it, here or in the mute chooser's buttons.
    function _blockNoticeDestinationText() {
        return hideBlockNoticeAddresses
            ? tr("notifications.block-notice.destination-hidden", "a hidden destination")
            : _blockNoticeDestination
    }

    /// Every value placed into a StyledText body goes through this: a path may
    /// hold `&`, and a name learned from DNS may hold `<`.
    function _escapeMarkup(text) {
        return Pure.escapeMarkup(text)
    }

    /// Whether a switch, not a rule, governs this block: the closed IPv6
    /// family and the encrypted-DNS lockdown.
    function _blockNoticeIsSwitchGoverned(reason) {
        return reason === "ipv6-blocked" || reason === "dns-lockdown"
    }

    function _blockNoticeRouteAction() {
        return {
            label: tr("tray.block-notice.action.route-to-secondary", "To additional route"),
            actionId: "block-notice-route",
            accent: true,
            // Changes routing — the next screen asks for a real yes/no before
            // anything is written.
            keepsOpen: true
        }
    }

    function _blockNoticeSnoozeMuteActions(config) {
        config.secondaryAction = {
            label: tr("tray.block-notice.action.snooze", "Snooze"),
            actionId: "block-notice-snooze",
            keepsOpen: true
        }
        config.tertiaryAction = {
            label: tr("action.dont-show", "Don't show…"),
            actionId: "block-notice-mute",
            keepsOpen: true
        }
        // No dismiss button: the corner close box and Esc still work, they
        // just answer nothing — closing this toast is not a decision.
        config.dismissActionId = "block-notice-dismiss"
        config.autoRetireMs = _promptAutoRetireMs
        return config
    }

    function _singleBlockNoticeConfig(entry) {
        var destination = String(entry.destination || "")
        var app = String(entry.app || "")
        var reason = String(entry.reason || "")
        var chain = app !== "" ? (entry.launchedBy || []) : []
        _blockNoticeDestination = destination
        _blockNoticeReason = reason
        _blockNoticeRows = Pure.groupBlockNotices([entry], _blockNoticeGroupableReasons)
        // Bold only the identifiers, never the sentence around them: the
        // markup lives here so the locale strings stay plain prose.
        var summaryParts = ["<b>" + _escapeMarkup(_blockNoticeDestinationText()) + "</b>"]
        if (app !== "") {
            summaryParts.push(["<b>" + _escapeMarkup(app) + "</b>"]
                .concat(chain.map(function(n) { return tray._escapeMarkup(n) }))
                .join(" ← "))
        }
        var attemptsText = tr("tray.block-notice.attempts", "{count} attempts")
            .replace("{count}", String(entry.attempts))
        summaryParts.push(attemptsText)
        // `<br>`, not `\n`: StyledText collapses a bare newline.
        var body = summaryParts.join(" · ") + "<br>"
            + _escapeMarkup(_blockNoticeReasonLine(reason))
        var spoken = ""
        if (chain.length > 0) {
            spoken = [_blockNoticeDestinationText(), _appChainAccessible(app, chain),
                attemptsText].join(", ") + ". " + _blockNoticeReasonLine(reason)
        }
        // "Route unavailable" already means the address HAS a rule pointing at
        // a route — offering to add it there again would write nothing. What
        // the user can actually do is look at the route. A switch-governed
        // block gets the switch: routing it writes a rule that cannot answer.
        var routeIsDown = (reason === "route-unavailable")
        var primary = _blockNoticeIsSwitchGoverned(reason)
            ? {
                label: tr("action.open-settings", "Open settings"),
                actionId: "block-notice-open-settings",
                accent: true
            }
            : routeIsDown
            ? {
                label: tr("tray.block-notice.action.open-routes", "Open routes"),
                actionId: "block-notice-open-routes",
                accent: true
            }
            : _blockNoticeRouteAction()
        return _blockNoticeSnoozeMuteActions({
            titleText: routeIsDown
                ? tr("tray.block-notice.title-route-down", "Additional route is unavailable")
                : tr("tray.block-notice.title", "Connection blocked"),
            bodyText: body,
            bodyRichText: true,
            bodyAccessibleText: spoken,
            primaryAction: primary
        })
    }

    /// Whether adding a rule could do anything about this block. A route that
    /// is down already HAS a rule pointing at it, and the IPv6 / encrypted-DNS
    /// cuts are governed by a switch — routing those writes a rule that cannot
    /// answer the cause.
    function _blockNoticeIsRouteable(reason) {
        return reason !== "route-unavailable"
            && reason !== "ipv6-blocked"
            && reason !== "dns-lockdown"
    }

    /// The one reason behind every row, or "" when they differ. The mute
    /// chooser offers to silence a class, and a class only exists when the
    /// whole list belongs to it.
    function _sharedBlockNoticeReason(batch) {
        var reason = batch.length > 0 ? String(batch[0].reason || "") : ""
        for (var i = 1; i < batch.length; i += 1) {
            if (String(batch[i].reason || "") !== reason) return ""
        }
        return reason
    }

    /// Every destination the notice on screen covers, including rows past the
    /// list cap: snooze and mute are about the whole batch.
    function _blockNoticeHosts() {
        var hosts = []
        for (var i = 0; i < _blockNoticeShown.length; i += 1) {
            var host = String(_blockNoticeShown[i].destination || "")
            if (host !== "" && hosts.indexOf(host) < 0) hosts.push(host)
        }
        if (hosts.length === 0 && _blockNoticeDestination !== "") {
            hosts.push(_blockNoticeDestination)
        }
        return hosts
    }

    /// Every program the notice on screen names, one spelling each.
    function _blockNoticeApps() {
        var apps = []
        var seen = {}
        for (var i = 0; i < _blockNoticeShown.length; i += 1) {
            var app = String(_blockNoticeShown[i].app || "")
            if (app === "" || seen[app.toLowerCase()]) continue
            seen[app.toLowerCase()] = true
            apps.push(app)
        }
        return apps
    }

    /// One list row. A folded row names the program and how many addresses it
    /// stands for, the addresses themselves behind "Show details"; an address
    /// row leads with the address and names the program under it.
    function _blockNoticeRowItem(row, sharedReason) {
        var entries = row.entries
        var first = entries[0]
        var app = String(first.app || "")
        var chain = app !== "" ? _blockNoticeChainOf(entries) : []
        var reasonPart = sharedReason === "" ? _blockNoticeReasonShort(first.reason) : ""
        if (row.grouped && entries.length > 1) {
            var countText = _blockNoticeCountNoun(first.reason, entries.length)
            var addresses = entries.map(function(e) { return String(e.destination || "") })
            return {
                key: row.key,
                primaryText: app,
                secondaryText: [countText, chain.length > 0 ? "← " + chain.join(" ← ") : "",
                    reasonPart].filter(function(s) { return s !== "" }).join(" · "),
                secondaryAccessibleText: [countText].concat(chain.map(function(n) {
                        return tray.tr("tray.block-notice.launched-by", "launched by {name}")
                            .replace("{name}", n)
                    })).concat(reasonPart !== "" ? [reasonPart] : []).join(", "),
                accessibleText: _appChainAccessible(app, chain) + ", " + countText
                    + (reasonPart !== "" ? ", " + reasonPart : ""),
                detailText: hideBlockNoticeAddresses ? "" : addresses.join(", ")
            }
        }
        var appText = app !== ""
            ? app : tr("notifications.block-notice.app-unknown", "unknown app")
        var attempts = Number(first.attempts || 0) > 1
            ? tr("tray.block-notice.attempts", "{count} attempts")
                .replace("{count}", String(first.attempts))
            : ""
        var destination = hideBlockNoticeAddresses
            ? tr("notifications.block-notice.destination-hidden", "a hidden destination")
            : String(first.destination || "")
        var tail = [attempts, reasonPart].filter(function(s) { return s !== "" })
        return {
            key: row.key,
            primaryText: destination,
            secondaryText: [_appChainText(appText, chain)].concat(tail).join(" · "),
            secondaryAccessibleText: [_appChainAccessible(appText, chain)].concat(tail).join(", "),
            accessibleText: [destination, _appChainAccessible(appText, chain)].concat(tail).join(", ")
        }
    }

    /// One window for a burst of blocks.
    ///
    /// Rows are checkable because the route action is the one answer that is
    /// per address; snooze and mute stay about the whole list. Rows past the
    /// cap are counted rather than listed — a notice that fills the screen
    /// stops being read at all — and they are still covered by both.
    function _mergedBlockNoticeConfig(shown, detailsOpen) {
        _blockNoticeDestination = ""
        _blockNoticeReason = _sharedBlockNoticeReason(shown)
        // The program is what the user recognises, so it leads a folded row;
        // the reason is said once above the list when every row shares it.
        var sharedReason = _blockNoticeReason
        var rows = Pure.groupBlockNotices(shown, _blockNoticeGroupableReasons)
        var listed = Math.min(rows.length, _blockNoticeListCap)
        _blockNoticeRows = rows.slice(0, listed)
        var items = []
        var folded = false
        for (var i = 0; i < listed; i += 1) {
            items.push(_blockNoticeRowItem(rows[i], sharedReason))
            if (rows[i].grouped && rows[i].entries.length > 1) folded = true
        }

        var routeable = false
        var switchGoverned = true
        for (var r = 0; r < shown.length; r += 1) {
            if (_blockNoticeIsRouteable(shown[r].reason)) routeable = true
            if (!_blockNoticeIsSwitchGoverned(shown[r].reason)) switchGoverned = false
        }
        var primary = routeable
            ? _blockNoticeRouteAction()
            : switchGoverned
            ? {
                label: tr("action.open-settings", "Open settings"),
                actionId: "block-notice-open-settings",
                accent: true
            }
            : {
                label: tr("tray.block-notice.action.open-routes", "Open routes"),
                actionId: "block-notice-open-routes",
                accent: true
            }

        // Only offer to tick addresses when the rows actually have ticks.
        var bodyParts = []
        if (sharedReason !== "") bodyParts.push(_escapeMarkup(_blockNoticeReasonLine(sharedReason)))
        if (routeable) {
            bodyParts.push(tr("tray.block-notice.merged.body",
                "Check the addresses to send over the additional route."))
        }
        if (rows.length > listed) {
            bodyParts.push(tr("notifications.block-notice.backlog.more",
                "and {count} more").replace("{count}", String(rows.length - listed)))
        }

        var config = {
            titleText: tr("tray.block-notice.merged.title",
                "{count} connections blocked").replace("{count}", String(shown.length)),
            bodyText: bodyParts.join("<br>"),
            bodyRichText: true,
            items: items,
            selectable: routeable,
            listAccessibleName: tr("tray.block-notice.merged.list-accessible-name",
                "Blocked connections"),
            primaryAction: primary
        }
        // The addresses behind a folded row are one press away, and never
        // offered while the user asked for addresses to stay hidden.
        if (folded && !hideBlockNoticeAddresses) {
            config.dismissAction = {
                label: detailsOpen
                    ? tr("action.hide-details", "Hide details")
                    : tr("action.show-details", "Show details"),
                actionId: "block-notice-details",
                keepsOpen: true
            }
        }
        return _blockNoticeSnoozeMuteActions(config)
    }

    /// Open Settings on the switch behind the notice, with what was blocked
    /// said next to it. The context is display-only: the window renders it and
    /// can do nothing else with it.
    function _openBlockNoticeSettings() {
        var focus = _blockNoticeSettingFocus()
        if (focus.id === "" || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.openMainGuiFocused !== "function") {
            triggerAction("settings")
            return
        }
        nrrNativeBridge.openMainGuiFocused("settings", focus.id, JSON.stringify(focus.context))
    }

    /// The switch most of the shown blocks point at, and the blocks behind it.
    function _blockNoticeSettingFocus() {
        var counts = { "dns-lockdown": 0, "ipv6-blocked": 0 }
        for (var i = 0; i < _blockNoticeShown.length; i += 1) {
            var r = String(_blockNoticeShown[i].reason || "")
            if (counts[r] !== undefined) counts[r] += 1
        }
        var reason = counts["dns-lockdown"] >= counts["ipv6-blocked"] ? "dns-lockdown" : "ipv6-blocked"
        if (counts[reason] === 0) return { id: "", context: {} }
        var apps = []
        var addresses = []
        for (var j = 0; j < _blockNoticeShown.length; j += 1) {
            var e = _blockNoticeShown[j]
            if (String(e.reason || "") !== reason) continue
            var app = String(e.app || "")
            if (app !== "" && apps.indexOf(app) < 0) apps.push(app)
            var dest = String(e.destination || "")
            if (dest !== "" && addresses.indexOf(dest) < 0) addresses.push(dest)
        }
        var listedAddresses = hideBlockNoticeAddresses ? [] : addresses.slice(0, 5)
        return {
            id: reason === "dns-lockdown" ? "doh-lockdown" : "leak-protection",
            context: {
                "reason": reason,
                "apps": apps.slice(0, 3),
                "addresses": listedAddresses,
                "more": hideBlockNoticeAddresses ? 0 : addresses.length - listedAddresses.length
            }
        }
    }

    /// Queue kind of the enforcement notice on screen; "" when none. Keyed by
    /// role because the service reports each role independently — an `ok` for
    /// one must not take down the other's question — and carried as the whole
    /// kind so "nothing on screen" stays distinguishable from a roleless one.
    property string _enforcementNoticeKind: ""

    /// Roles the service last reported as not enforced. Kept apart from what is
    /// on screen: the question may have been suppressed (window in front,
    /// notifications off) and coming back out of this set is still news.
    property var _enforcementDownRoles: []

    /// How long the "a link is down" notice stays up. It used to wait for the
    /// user or for the service to report the role enforced again, which meant a
    /// user who turned their own VPN off had a window sitting there until they
    /// closed it. The state itself is not lost — the tray icon and its tooltip
    /// keep saying so, and the notice does not re-raise for the same role.
    readonly property int _enforcementNoticeMs: 45000

    /// Take the standing enforcement notice for `role` down — on screen and in
    /// the queue. The state it described is over; the question no longer has an
    /// answer worth giving.
    function _clearEnforcementNotice(role) {
        var kind = "enforcement-status:" + String(role || "")
        var kept = []
        for (var i = 0; i < _noticeQueue.length; i += 1) {
            if (_noticeQueue[i].kind !== kind) kept.push(_noticeQueue[i])
        }
        if (kept.length !== _noticeQueue.length) _noticeQueue = kept
        if (_enforcementNoticeKind === kind) {
            _enforcementNoticeKind = ""
            // `retire()` closes through a timer, so the window is still visible
            // here and the notice below queues behind it — which is exactly the
            // settling the drain timer exists to give.
            if (promptWindow && promptWindow.visible) promptWindow.retire()
        }
    }

    /// The channel carries the rules again. The browser will not say so: a page
    /// refused while the channel was down keeps its error until it is reloaded.
    function _noteEnforcementRestored() {
        if (!showNotifications) return
        var presence = guiPresence ? guiPresence.read() : { windowActive: false }
        if (presence.windowActive) return
        _offerNotice("enforcement-restored", "enforcement-restored", function() {
            promptWindow.present({
                titleText: tray.tr("notifications.enforcement.restored.title",
                    "Routing is working again"),
                bodyText: tray.tr("notifications.enforcement.restored.body",
                    "Your rules are being applied again. Pages that were refused while the connection was down keep showing the error until you reload them — press F5 on those tabs."),
                secondaryAction: tray._noticeMuteAction("enforcement-restored"),
                dismissActionId: "enforcement-restored-dismiss",
                autoRetireMs: tray._infoNoticeMs
            })
        })
    }

    /// The rule landed, but the page it was offered for still holds its old
    /// connections — only a reload moves it onto the new route.
    function _noteReloadAfterAccept() {
        _presentOrQueue("auto-rules-reload", function() {
            promptWindow.present({
                titleText: tray.tr("tray.auto-rules.reload.title", "Rule applied"),
                bodyText: tray.tr("rules.suggestions.accept.reload-page",
                    "The rule is applied. Reload the page you were on (F5) so it picks up the new route."),
                dismissActionId: "auto-rules-reload-dismiss",
                autoRetireMs: tray._infoNoticeMs
            })
        })
    }

    /// The last state announced per role, so a service that keeps reporting the
    /// same outage does not re-raise the same window every time the notice
    /// retires. Mutated in place: nothing binds to it.
    property var _enforcementShownByRole: ({})

    /// Policy stopped being enforced for this user. The notice retires on a
    /// timer — a user who switched their own tunnel off should not have to
    /// close a window about it — but it is announced ONCE per state: the tray
    /// icon and its tooltip go on saying so, which is what keeps "your rules
    /// are not applied" from going invisible for a whole session.
    // ── Local networks waiting for an answer ─────────────────────────────────
    //
    // A hypervisor installed months into using the app creates its network
    // quietly, and the service exempts it from the kill-switch on its own. That
    // is nearly always the right answer, but the user still gets to confirm it,
    // and the window may not be open for weeks. Asked once a day at most.

    property real _localNetworkAskedAtMs: 0
    readonly property real _localNetworkAskIntervalMs: 24 * 60 * 60 * 1000

    function _checkPendingLocalNetworks() {
        if (!localNetworksSupported) return
        if (!showNotifications) return
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcLocalNetworksGet !== "function") return
        var presence = guiPresence ? guiPresence.read() : { windowActive: false }
        if (presence.windowActive) return
        var corr = rpc.rpcLocalNetworksGet()
        if (!corr || corr === "") return
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            var pending = (payload.networks || []).filter(function(n) {
                return n && n["decided-by-user"] !== true
            })
            if (pending.length === 0) return
            tray._localNetworkAskedAtMs = Date.now()
            var first = pending[0] || {}
            var body = tray.tr("notifications.local-networks.body",
                    "{cidr} on {adapter} stays reachable while routed traffic is blocked. Keep it that way?")
                .replace("{cidr}", String(first.cidr || ""))
                .replace("{adapter}", String(first.adapter || ""))
            tray._offerNotice("local-networks", "local-networks", function() {
                promptWindow.present({
                    titleText: tray.tr("notifications.local-networks.title",
                        "A local network was found"),
                    bodyText: body,
                    primaryAction: {
                        label: tray.tr("action.open-settings", "Open settings"),
                        actionId: "block-notice-open-settings",
                        accent: true
                    },
                    secondaryAction: tray._noticeMuteAction("local-networks"),
                    dismissActionId: "enforcement-dismiss"
                })
            })
        })
    }

    property Timer _localNetworkAskTimer: Timer {
        interval: tray._localNetworkAskIntervalMs
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: tray._checkPendingLocalNetworks()
    }

    /// A tunnel is up and nothing is bound to the additional route, so every
    /// rule naming it does nothing. The service decides WHEN to say this (once
    /// a day per connection, personal clients only); the tray only shows it.
    function _onUnassignedTunnel(event) {
        var adapter = String(event["adapter-name"] || "")
        if (adapter === "") return
        if (!showNotifications) {
            console.log("tray unassigned-tunnel notice: suppressed — notifications are off")
            return
        }
        var presence = guiPresence ? guiPresence.read() : { windowActive: false }
        if (presence.windowActive) return
        _offerNotice("unassigned-tunnel", "unassigned-tunnel", function() {
            promptWindow.present({
                titleText: tr("notifications.unassigned-tunnel.title",
                    "The additional route is not assigned"),
                bodyText: tr("notifications.unassigned-tunnel.body",
                        "{adapter} is up, but no connection is assigned to the additional route — so the sites your rules send there will not open.")
                    .replace("{adapter}", adapter),
                primaryAction: {
                    label: tr("notifications.unassigned-tunnel.action", "Assign it now"),
                    actionId: "enforcement-open-interfaces",
                    accent: true
                },
                secondaryAction: tray._noticeMuteAction("unassigned-tunnel"),
                dismissActionId: "enforcement-dismiss",
                autoRetireMs: tray._enforcementNoticeMs
            })
        })
    }

    function _onEnforcementStatusChanged(event) {
        var status = String(event.status || "")
        var role = String(event.role || "")
        var wasDown = _enforcementDownRoles.indexOf(role) >= 0
        if (status === "" || status === "ok") {
            _clearEnforcementNotice(role)
            delete _enforcementShownByRole[role]
            if (wasDown) {
                _enforcementDownRoles = _enforcementDownRoles.filter(
                    function(r) { return r !== role })
                _noteEnforcementRestored()
            }
            return
        }
        if (!wasDown) _enforcementDownRoles = _enforcementDownRoles.concat([role])
        if (_enforcementShownByRole[role] === status) return
        _enforcementShownByRole[role] = status
        if (!showNotifications) {
            console.log("tray enforcement notice: suppressed — notifications are off")
            return
        }
        var presence = guiPresence ? guiPresence.read() : { windowActive: false }
        if (presence.windowActive) {
            console.log("tray enforcement notice: suppressed — main window is active")
            return
        }
        var candidates = event.candidates || []
        var routine = status === "secondary-down" && role !== "primary"
        var title = ""
        var body = ""
        if (status === "adapter-choice-needed") {
            title = tr("notifications.enforcement.adapter-choice.title",
                "Choose which adapter to use")
            body = tr("notifications.enforcement.adapter-choice.body",
                    "Several adapters answer to the saved name, so your rules are not being applied. Pick the one to use: {list}")
                .replace("{list}", candidates.join(", "))
        } else if (status === "adapter-gone") {
            // A vendor that replaced its adapter outright, a driver that no
            // longer starts, a connection removed by hand. The cause differs,
            // the answer does not: nothing here answers to the saved name, so
            // the choice goes back to the user.
            title = tr("notifications.enforcement.adapter-gone.title",
                "The saved connection is gone")
            body = candidates.length > 0
                ? tr("notifications.enforcement.adapter-gone.body",
                        "The connection your rules were set to use is no longer on this computer, so the rules are not being applied. Pick another one: {list}")
                    .replace("{list}", candidates.join(", "))
                : tr("notifications.enforcement.adapter-gone.body-empty",
                    "The connection your rules were set to use is no longer on this computer, and there is nothing to replace it with right now.")
        } else if (status === "adapter-failed") {
            // The device is still on the machine and its driver will not
            // start — usually a second VPN client that installed an older copy
            // of the same driver. Picking another connection works around it;
            // repairing the driver fixes it, and only the user can decide.
            title = tr("notifications.enforcement.adapter-failed.title",
                "The saved connection is broken")
            body = candidates.length > 0
                ? tr("notifications.enforcement.adapter-failed.body",
                        "The connection your rules use is still installed, but its driver will not start, so the rules are not being applied. Reinstall it, or pick another one: {list}")
                    .replace("{list}", candidates.join(", "))
                : tr("notifications.enforcement.adapter-failed.body-empty",
                    "The connection your rules use is still installed, but its driver will not start, and there is nothing to replace it with right now. Reinstalling it usually helps.")
        } else if (status === "no-primary-route") {
            title = tr("notifications.enforcement.no-primary.title",
                "Main connection is not set")
            body = tr("notifications.enforcement.no-primary.body",
                "Without a main connection there is nowhere to send traffic your rules do not route, so the rules are not being applied.")
        } else if (status === "primary-no-way-out") {
            title = tr("notifications.enforcement.primary-no-way-out.title",
                "The main connection has no way to the internet")
            body = tr("notifications.enforcement.primary-no-way-out.body",
                "The connection chosen as main has no gateway, so traffic your rules do not route is going out the way the system sends it instead. Choose the connection that actually reaches the internet as main.")
        } else if (status === "no-policy") {
            title = tr("notifications.enforcement.no-policy.title",
                "Connections are not chosen yet")
            body = tr("notifications.enforcement.no-policy.body",
                "The service has no routing settings for you yet, so nothing is being routed. Choose the main and additional connections.")
        } else if (status === "secondary-down") {
            // The service reports which role went down; before this the primary
            // going down was announced as "the additional connection is not up".
            if (role === "primary") {
                title = tr("notifications.enforcement.primary-down.title",
                    "The main connection is not up")
                body = tr("notifications.enforcement.primary-down.body",
                    "Traffic that is not routed to the additional connection has nowhere to go until it comes back. Check the cable, the Wi-Fi, or pick another main connection.")
            } else {
                title = tr("notifications.enforcement.secondary-down.title",
                    "The additional connection is not up")
                body = tr("notifications.enforcement.secondary-down.body",
                    "Everything your rules send there is being held until it comes back — that is the protection doing its job, not a fault. Start the connection, or move those rules to the main one.")
            }
        } else if (status === "adapters-unreadable") {
            title = tr("notifications.enforcement.adapters-unreadable.title",
                "Cannot read the list of connections")
            body = tr("notifications.enforcement.adapters-unreadable.body",
                "The service cannot enumerate network adapters right now, so your rules are not being applied. This usually clears itself; if it does not, restart the service.")
        } else {
            title = tr("notifications.enforcement.unknown.title",
                "Your rules are not being applied")
            body = tr("notifications.enforcement.unknown.body",
                "The service reported a state this version does not recognise. Open interfaces and routes to check the setup.")
        }
        // Keyed by role, not by "enforcement-status" alone: a missing primary
        // and a downed secondary are two questions, and the newer one must not
        // silently replace the older in the queue.
        var queueKind = "enforcement-status:" + role
        var show = function() {
            tray._enforcementNoticeKind = queueKind
            promptWindow.present({
                titleText: title,
                bodyText: body,
                primaryAction: {
                    label: tr("notifications.enforcement.action", "Open interfaces"),
                    actionId: "enforcement-open-interfaces",
                    accent: true
                },
                // Only a switched-off tunnel may be silenced; every other state
                // here is a fault the user has to fix.
                secondaryAction: routine ? tray._noticeMuteAction("secondary-down") : null,
                dismissActionId: "enforcement-dismiss",
                autoRetireMs: tray._enforcementNoticeMs
            })
        }
        if (!routine) {
            _presentOrQueue(queueKind, show)
            return
        }
        _offerNotice("secondary-down", queueKind, function() {
            // The mute list was read on the way here; the tunnel may be back.
            if (tray._enforcementShownByRole[role] !== status) {
                tray._scheduleDrain()
                return
            }
            show()
        })
    }

    /// Second step of "To additional route": the action changes routing, so it
    /// gets its own yes/no instead of firing straight off the first click —
    /// same two-step shape as `_confirmAutoRulesAlways`.
    function _confirmBlockNoticeRoute() {
        var targets = _blockNoticeRouteTargets
        // Nothing checked is an answer too: the list stays open rather than
        // asking to confirm a change that would write nothing.
        if (targets.length === 0) {
            console.log("tray block-notice: route pressed with nothing checked")
            return
        }
        promptWindow.present({
            titleText: targets.length === 1
                ? tr("tray.block-notice.route-confirm.title",
                    "Route {name} via the additional link?")
                    .replace("{name}", targets[0])
                : tr("tray.block-notice.route-confirm.title-many",
                    "Route {count} addresses via the additional link?")
                    .replace("{count}", String(targets.length)),
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
        if (!blockNoticesSupported) return
        if (!bridgeAvailable || !rpc
                || typeof rpc.rpcBlockNoticeRouteToSecondary !== "function") return
        var corr = rpc.rpcBlockNoticeRouteToSecondary({ "destination": destination })
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.warn("block-notice route-to-secondary failed:", code, msg)
        })
    }

    function _showBlockNoticeSnoozeChoice() {
        promptWindow.present({
            titleText: tr("tray.block-notice.snooze.title", "Snooze this notice"),
            bodyText: _blockNoticeHosts().length > 1
                ? tr("tray.block-notice.snooze.body-many",
                    "Stop asking about these {count} addresses for a while.")
                    .replace("{count}", String(_blockNoticeHosts().length))
                : tr("tray.block-notice.snooze.body",
                    "Stop asking about {name} for a while.")
                    .replace("{name}", _blockNoticeDestinationText()),
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
            // Wall-clock deadlines on the service: no option can promise
            // "until restart", there is no restart event to expire one against.
            extraActions: [{
                label: tr("label.duration.for-a-day", "For a day"),
                actionId: "block-notice-snooze-day"
            }, {
                label: tr("label.duration.for-7-days", "For 7 days"),
                actionId: "block-notice-snooze-7d"
            }, {
                label: tr("label.duration.for-30-days", "For 30 days"),
                actionId: "block-notice-snooze-30d"
            }],
            // Closing this chooser is not an answer: it must not pick a length.
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
            case "block-notice-snooze-day": ms = 24 * 60 * 60 * 1000; break
            case "block-notice-snooze-7d": ms = 7 * 24 * 60 * 60 * 1000; break
            case "block-notice-snooze-30d": ms = 30 * 24 * 60 * 60 * 1000; break
            default: return
        }
        var until = Date.now() + ms
        var hosts = _blockNoticeHosts()
        for (var i = 0; i < hosts.length; i += 1) {
            _setBlockNoticeMute({ "kind": "host", "host": hosts[i] }, until)
        }
    }

    /// A button label carries the real name so "this app" is never a question
    /// the user has to answer from memory — but a full FQDN or a long
    /// executable name would push the footer into extra rows, so it is cut.
    function _blockNoticeMuteName(text) {
        var name = String(text)
        return name.length > 28 ? name.slice(0, 27) + "…" : name
    }

    function _showBlockNoticeMuteChoice() {
        var hosts = _blockNoticeHosts()
        var slots = [{
            label: hosts.length > 1
                ? tr("tray.block-notice.mute.these-hosts", "Only these {count} addresses")
                    .replace("{count}", String(hosts.length))
                : tr("tray.block-notice.mute.this-host", "Only {name}")
                    .replace("{name}", _blockNoticeMuteName(_blockNoticeDestinationText())),
            actionId: "block-notice-mute-host",
            accent: true
        }]
        // "This program" only makes sense when the notice actually named one —
        // an unattributed connection has nothing for that scope to cover.
        var apps = _blockNoticeApps()
        if (apps.length > 0) {
            slots.push({
                label: apps.length > 1
                    ? tr("tray.block-notice.mute.these-apps", "All from these {count} programs")
                        .replace("{count}", String(apps.length))
                    : tr("tray.block-notice.mute.this-app", "All from {name}")
                        .replace("{name}", _blockNoticeMuteName(apps[0])),
                actionId: "block-notice-mute-app"
            })
        }
        // Silencing the CAUSE is the wish a host or an app cannot express:
        // "tell me when a rule blocks something, but not every tunnel outage".
        if (_blockNoticeReason !== "") {
            slots.push({
                label: tr("tray.block-notice.mute.this-reason", "All \"{name}\"")
                    .replace("{name}", _blockNoticeMuteReasonLabel(_blockNoticeReason)),
                actionId: "block-notice-mute-reason"
            })
        }
        slots.push({
            label: tr("tray.block-notice.mute.all", "Every block notification"),
            actionId: "block-notice-mute-all"
        })
        promptWindow.present({
            titleText: tr("tray.block-notice.mute.title", "What should stop appearing?"),
            bodyText: tr("tray.mute.lift-hint",
                "Mutes can be lifted later in Settings, Notifications."),
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
            case "ipv6-blocked":
                return tr("block-reason.ipv6-blocked", "IPv6 blocks")
            case "dns-lockdown":
                return tr("block-reason.dns-lockdown", "Blocks of apps using their own DNS")
            case "unattributed":
                return tr("block-reason.unattributed", "Blocks without an identified filter")
            default:
                return tr("block-reason.any", "Blocks of this kind")
        }
    }

    function _applyBlockNoticeMute(action) {
        switch (action) {
            case "block-notice-mute-host":
                var hosts = _blockNoticeHosts()
                for (var h = 0; h < hosts.length; h += 1) {
                    _setBlockNoticeMute({ "kind": "host", "host": hosts[h] }, undefined)
                }
                break
            case "block-notice-mute-app":
                var apps = _blockNoticeApps()
                for (var a = 0; a < apps.length; a += 1) {
                    _setBlockNoticeMute({ "kind": "app", "app": apps[a] }, undefined)
                }
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
        if (!blockNoticesSupported) return
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
        // "Don't show…" answers the notice on screen the way closing it would,
        // then asks for how long.
        if (action.indexOf("notice-mute:") === 0) {
            if (_activeNoticeId !== "") noticeLedger.recordAll([_activeNoticeId])
            _activeNoticeId = ""
            _rulesDriftNoticeId = ""
            _enforcementNoticeKind = ""
            _showNoticeMuteChoice(action.substring("notice-mute:".length),
                promptWindow.titleText)
            return
        }
        if (action === "notice-mute-1d" || action === "notice-mute-7d"
                || action === "notice-mute-30d" || action === "notice-mute-forever") {
            _applyNoticeMute(action.substring("notice-mute-".length))
            _scheduleDrain()
            return
        }
        if (action === "notice-mute-cancel") {
            _noticeMuteKind = ""
            _scheduleDrain()
            return
        }
        // Block-notice actions swap the SAME window through a chain of
        // sub-screens (route confirm, snooze choice, mute choice) rather than
        // reusing the auto-rule id machinery below, which answers a different
        // question (a list of candidates) entirely.
        if (action === "block-notice-route") {
            // The checkboxes exist only while the list is on screen, and the
            // confirm screen replaces it — so what was checked is taken now.
            _blockNoticeRouteTargets = _blockNoticeCheckedHosts(selectedIndexes)
            _confirmBlockNoticeRoute()
            return
        }
        if (action === "block-notice-details") {
            promptWindow.detailsExpanded = !promptWindow.detailsExpanded
            // Redrawn in place so the button names what it does next.
            _renderBlockNotice(true, [])
            return
        }
        if (action === "block-notice-open-routes"
                || action === "enforcement-open-interfaces") {
            _enforcementNoticeKind = ""
            triggerAction("interfaces-routes")
            if (action === "block-notice-open-routes" && _blockNoticeListIsCurrent()) {
                _quietShownBlockNotices()
                _blockNoticeAnswered()
                return
            }
            _scheduleDrain()
            return
        }
        if (action === "block-notice-open-settings") {
            // The local-networks notice borrows this id; only the block list
            // has a switch to point at and blocks to quiet.
            if (_blockNoticeListIsCurrent()) {
                _openBlockNoticeSettings()
                _quietShownBlockNotices()
                _blockNoticeAnswered()
                return
            }
            triggerAction("settings")
            _scheduleDrain()
            return
        }
        if (action === "enforcement-dismiss") {
            _enforcementNoticeKind = ""
            _scheduleDrain()
            return
        }
        if (action === "auto-rules-reload-dismiss") {
            _scheduleDrain()
            return
        }
        if (action === "enforcement-restored-dismiss") {
            _scheduleDrain()
            return
        }
        if (action === "block-notice-route-confirm") {
            var targets = _blockNoticeRouteTargets
            _blockNoticeRouteTargets = []
            for (var t = 0; t < targets.length; t += 1) {
                _sendBlockNoticeRouteToSecondary(targets[t])
            }
            _blockNoticeAnswered()
            return
        }
        if (action === "block-notice-route-cancel") {
            _blockNoticeRouteTargets = []
            _quietShownBlockNotices()
            _blockNoticeAnswered()
            return
        }
        if (action === "block-notice-snooze") {
            _showBlockNoticeSnoozeChoice()
            return
        }
        if (action === "block-notice-snooze-15m" || action === "block-notice-snooze-1h"
                || action === "block-notice-snooze-8h"
                || action === "block-notice-snooze-day"
                || action === "block-notice-snooze-7d"
                || action === "block-notice-snooze-30d") {
            _applyBlockNoticeSnooze(action)
            _blockNoticeAnswered()
            return
        }
        if (action === "block-notice-snooze-cancel") {
            _quietShownBlockNotices()
            _blockNoticeAnswered()
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
            _blockNoticeAnswered()
            return
        }
        if (action === "block-notice-mute-cancel") {
            _quietShownBlockNotices()
            _blockNoticeAnswered()
            return
        }
        if (action === "block-notice-dismiss") {
            // The toast's own close box — no mute on the service, only the
            // tray's hour of quiet for what was on screen.
            _quietShownBlockNotices()
            _blockNoticeAnswered()
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
                // Not a plain "go to Rules": the window has to re-measure and
                // SHOW the divergence this notice is about, so the intent
                // travels with the hand-off.
                _rulesDriftNoticeId = ""
                triggerAction("rules-drift-compare")
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
            if (p && p["anchor-skipped"] === true) tray._noteReloadAfterAccept()
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
            // The window may be writing other fields meanwhile; name ours.
            req["apply-only"] = ["auto-rules-mode"]
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

    /// The status header as at most two menu rows: a native menu row cannot
    /// wrap, and eliding the sentence cut off exactly the part that mattered.
    /// Splits at " — " when both halves fit, otherwise on a word boundary.
    function _menuHeaderLines(text) {
        var t = String(text || "").replace(/\s+/g, " ").trim()
        if (t.length <= _menuRowMaxChars) return [t]
        var dash = t.indexOf(" — ")
        if (dash > 0) {
            var head = t.substring(0, dash)
            var rest = t.substring(dash + 3)
            rest = rest.charAt(0).toUpperCase() + rest.substring(1)
            if (head.length <= _menuRowMaxChars && rest.length <= _menuRowMaxChars)
                return [head, rest]
        }
        var cut = t.lastIndexOf(" ", _menuRowMaxChars)
        if (cut <= 0) cut = _menuRowMaxChars
        return [t.substring(0, cut).trim(), _elideForMenu(t.substring(cut).trim())]
    }
    /// Computed once per status change, so both header rows split the same text.
    readonly property var _menuHeader: _menuHeaderLines(statusLine)

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
            req["apply-only"] = ["kill-switch-enabled"]
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
        for (var i = 0; i < args.length; i += 1) {
            if (args[i].indexOf("--nrr-auto-close-ms=") === 0) {
                autoCloseMs = Number(args[i].slice("--nrr-auto-close-ms=".length))
            }
        }

        // The host parses the context file; when it could not, nothing here can.
        if (typeof nrrLaunchContext === "undefined" || !nrrLaunchContext) return
        context = nrrLaunchContext
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
        platformProfile = context.platformProfile || platformProfile
        primaryActions = context.primaryActions || []
        quickActions = context.quickActions || []
        showNotifications = context.showNotifications !== false
        notifySuggestionChanges = context.notifySuggestionChanges !== false
        notifyBlockNotices = context.notifyBlockNotices !== false
        hideBlockNoticeAddresses = context.hideBlockNoticeAddresses === true
        if (context.trayNoticeOpacityPercent !== undefined) {
            noticeOpacityPercent = parseInt(context.trayNoticeOpacityPercent) || 100
        }
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

    /// Re-read the system appearance and re-resolve the tray's own theme.
    ///
    /// The tray carries resolved slugs, not the token set, so "system" is
    /// resolved here the same way the shell resolves it: the system's answer
    /// IS the effective mode, and an explicit light/dark choice is left alone.
    function refreshSystemAppearance() {
        var correlationId = rpc.rpcSystemTheme()
        if (!correlationId || correlationId === "") return
        rpc.registerRpcCallback(correlationId, function(ok, payload) {
            if (!ok || !payload) return
            var mode = String(payload.systemMode || "")
            if (mode !== "light" && mode !== "dark" && mode !== "high-contrast") return
            var current = tray.theme || {}
            if (String(current.systemMode || "") === mode) return
            var next = Object.assign({}, current)
            next.systemMode = mode
            next.systemModeDetected = payload.systemModeDetected !== false
            if (String(next.selectedMode || "system") === "system") next.effectiveMode = mode
            tray.theme = next
            uiTheme.themeMode = String(next.effectiveMode || "light")
        })
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
            // The desktop can switch light/dark while the tray sits in the
            // notification area for days. Its own prompt windows are themed
            // from this snapshot, so without the refresh they keep the
            // appearance the machine had when the tray started.
            if (typeof nrrNativeBridge.systemAppearanceChanged !== "undefined") {
                nrrNativeBridge.systemAppearanceChanged.connect(refreshSystemAppearance)
            }
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
    /// Notices the service raised while nothing was subscribed. One summary
    /// notice, not one window per entry.
    property Timer _blockNoticeBacklogTimer: Timer {
        interval: 10000
        repeat: false
        onTriggered: tray._drainBlockNoticeJournal()
    }

    function _drainBlockNoticeJournal() {
        if (!blockNoticesSupported) return
        if (!showNotifications || !notifyBlockNotices) return
        if (!bridgeAvailable || !rpc
                || typeof rpc.rpcBlockNoticeJournalList !== "function") return
        var corr = rpc.rpcBlockNoticeJournalList()
        if (!corr || corr === "") return
        rpc.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) return
            var entries = (p && p.entries) || []
            if (entries.length === 0) return
            var throughId = 0
            var shown = []
            for (var i = 0; i < entries.length; i += 1) {
                var id = Number(entries[i].id || 0)
                if (id > throughId) throughId = id
                var dest = String(entries[i].destination || "")
                if (dest !== "" && shown.indexOf(dest) < 0) shown.push(dest)
            }
            tray._showBlockNoticeBacklog(entries.length, shown)
            if (throughId > 0) {
                var ackCorr = rpc.rpcBlockNoticeJournalAck({ "through-id": throughId })
                rpc.registerRpcCallback(ackCorr, function(ackOk, ackPayload, code, msg) {
                    if (!ackOk) console.warn("tray journal ack failed:", code, msg)
                })
            }
        })
    }

    function _showBlockNoticeBacklog(count, destinations) {
        var names = hideBlockNoticeAddresses ? [] : destinations.slice(0, 5)
        var rest = hideBlockNoticeAddresses
            ? 0 : Math.max(0, destinations.length - names.length)
        var body = tr("notifications.block-notice.backlog.body",
                "The service blocked {count} connection(s) while neither this window nor "
                + "the tray icon was running.")
            .replace("{count}", "<b>" + String(count) + "</b>")
        if (names.length > 0) {
            var list = names.map(function(n) { return _escapeMarkup(n) }).join(", ")
            if (rest > 0) {
                list = list + ", "
                    + tr("notifications.block-notice.backlog.more", "and {count} more")
                        .replace("{count}", String(rest))
            }
            body = body + "<br>" + tr("notifications.block-notice.backlog.destinations",
                "Destinations: {list}.").replace("{list}", list)
        }
        _offerNotice("block-notice-backlog", "block-notice-backlog", function() {
            promptWindow.present({
                titleText: tr("notifications.block-notice.backlog.title",
                    "Blocked while the app was closed"),
                bodyText: body,
                bodyRichText: true,
                primaryAction: {
                    label: tr("action.close", "Close"),
                    actionId: "block-notice-backlog-dismiss",
                    accent: true
                },
                secondaryAction: _noticeMuteAction("block-notice-backlog"),
                dismissActionId: "block-notice-backlog-dismiss",
                autoRetireMs: _promptAutoRetireMs
            })
        })
    }

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
                tray._refreshNoticeMutes(null)
                // Both surfaces drain the same backlog, and the main window
                // does it immediately. Waiting lets its acknowledgement land
                // first, so a user who has both up is told once, not twice.
                tray._blockNoticeBacklogTimer.restart()
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
            text: tray._menuHeader[0]
            enabled: false
        }
        MenuItem {
            visible: tray._menuHeader.length > 1
            text: visible ? tray._menuHeader[1] : ""
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
                ? tr("tray.menu.kill-switch-off", "Turn leak protection off")
                : tr("tray.menu.kill-switch-on", "Turn leak protection on")
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
