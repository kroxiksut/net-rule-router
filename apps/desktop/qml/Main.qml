
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import QtQuick.Dialogs
import "theme"
import "components"
import "sections"
import "flows"
import "lib/pure.js" as Pure
import "lib/rules.js" as Rules

ApplicationWindow {
    id: window
    width: 1180
    height: 760
    minimumWidth: 980
    minimumHeight: 680
    visible: false
    title: context.windowTitle || "NetRuleRouter"
    color: palette.window

    property var context: ({})
    // OS capability descriptor (nrr-shared::platform_profile),
    // emitted into the QML context by the launcher. Windows-all-supported
    // default so mock/preview (which emits no context) still renders every
    // section; the real profile loads from `context.platformProfile` below.
    property var platformProfile: ({ os: "windows", enforcementBackend: "wfp", serviceModel: "scm", elevationModel: "uac", supports: { killSwitch: true, appRouting: true, dnsObserve: true, dnsResolver: true, hostsPin: true, backgroundService: true, autostart: true } })
    // Capability query for declarative, OS-agnostic section gating: a
    // feature-keyed section renders only when the running OS supports it.
    // Unknown feature or missing profile → true (show it).
    function supports(feature) {
        if (!platformProfile || !platformProfile.supports) return true
        return platformProfile.supports[feature] !== false
    }
    property var prefs: ({ launchWindowOnStartup: true, minimizeToTrayInsteadOfClose: true, showNotifications: true, notifySuggestionChanges: true, notifyBlockNotices: true, hideBlockNoticeAddresses: false, routingDetailedMode: false, reopenLastSectionOnStartup: true, firstRunCompleted: false, acceptedEulaVersion: 0, themeMode: "system", effectiveThemeMode: "light", accessibilityHighContrast: false, fontScalePercent: 100, systemFont: "system-default", enhancedFocus: false, simplifiedLabels: false, tooltipsEnabled: true, language: Qt.locale().name, routePrimaryLabel: "Primary", routeSecondaryLabel: "Secondary", selectedPrimaryInterfaceId: "", selectedPrimaryInterfaceName: "", primaryRoleUserConfirmed: false, selectedSecondaryInterfaceId: "", selectedSecondaryInterfaceName: "", secondaryRoleUserConfirmed: false, routeBehaviorMode: "prefer-primary", routeIncludeSubdomains: true, routeSharedIpPolicy: "majority-of-ip", routeKillSwitchBlockAll: false, showBluetoothAdapters: false, showRememberedAdapters: true, autoConfirmAdapterIdChange: true, warnKillSwitchBlockAll: true, killSwitchBannerAcknowledged: false, missingSecondaryBannerAcknowledged: false, trafficStatsPeriod: "today", trafficExportUnit: "mb", diagnosticsArchiveRedactionLevel: "standard", diagnosticsArchiveSessionOnly: true, archiveLogBudgetMib: 0, userPresetsDir: "", selectedPresetSet: "", serviceBackedMirrorJson: "", serviceIntentJson: "", lastOpenedSection: "interfaces-routes" })
    property string section: "interfaces-routes"
    property string statusLine: ""
    /// Long form of the current status message, shown on hover. The footer is
    /// a single row shared with buttons, so a sentence-long status pushed them
    /// off; the short line states the outcome and the detail explains it.
    property string statusDetail: ""
    property string _statusDetailFor: ""
    // Any message set the ordinary way owns the line alone — a detail left
    // behind by the previous one would explain the wrong thing.
    onStatusLineChanged: if (_statusDetailFor !== statusLine) statusDetail = ""

    /// Set the status line together with the text its tooltip should show.
    function setStatus(text, detail) {
        statusDetail = String(detail || "")
        _statusDetailFor = String(text || "")
        statusLine = String(text || "")
    }
    property int selectedRule: -1
    property int editingRule: -1
    property int wizardStep: 0
    property int autoCloseMs: 0
    property int uiRevision: 0
    // Dedicated revision token for the
    // theme tokens (`uiTheme`). Bumped ONLY when a theme-affecting pref
    // changes (themeMode / effectiveThemeMode / high-contrast / font
    // scale / system font). Previously `uiTheme` re-derived all its
    // tokens on every `uiRevision += 1` — which fires on row selection,
    // unsaved-flag flips, rules refetch, tab switches, etc. With every
    // section kept resident (lazy keep-alive Loaders), that re-evaluated
    // every colour/font binding across the whole tree on each
    // interaction → the "theme/font/tab switching is slow" regression.
    // Decoupling theme recompute from generic interactions fixes it
    // (themeRevision split).
    property int themeRevision: 0
    // Stable language token for `tr()`. Kept separate
    // from the volatile `prefs` object (which is wholesale-replaced on
    // every `updatePrefs`) and from `uiRevision` (bumped on every
    // interaction) so that text bindings re-evaluate ONLY on a real
    // language switch — not on theme changes, font-scale drags, or any
    // other preference toggle. Updated at every `prefs =` assignment;
    // QML value-equality means a same-language reassignment is a no-op.
    property string currentLanguage: ""
    property bool quittingToTray: false
    property var localeCatalog: ({})
    property var availableLanguages: []
    property var interfacesRowsAll: []
    // Sidecar-backed cache of the last external IP the service resolved per
    // adapter (key -> {ip, observedAtMs}). Populated once at cold start via
    // `interfacesRolesController.loadExternalIpCache()` and kept current by
    // every live snapshot; read by InterfacesRoutesSection to paint a muted
    // "last known" hint while the service is unreachable.
    property var externalIpCache: ({})

    // Backend connection status surfaced from the
    // launcher's `backend_factory::create_backend()` probe. Shape:
    //   { kind: "connected" | "connecting" | "disconnected"
    //         | "service-stopped" | "service-not-installed"
    //         | "protocol-mismatch",
    //     lastError?: string,
    //     serverVersion?: int, clientVersion?: int }
    // The banner reads `kind` to decide visibility + colour; the live
    // reconnect transitions land in a future sub-block (push event for
    // backend status changes).
    property var backendStatus: ({ kind: "connected" })
    // Did the launcher hand this window a REAL service facade, or a
    // mock/preview stand-in? A mock launch stamps kind:"connected" while
    // nothing it returns ever reaches the service, so `backendStatus` alone
    // cannot answer "may I push this change?". Stamped by the launcher
    // (`backendServiceBacked` in the context); an older launcher that omits it
    // reads as service-backed, which is the pre-existing behaviour.
    property bool backendServiceBacked: true
    // Set the first time a live health read succeeds over the Qt host's own IPC
    // client. That client reconnects independently of the cold-start facade, so
    // a window that started on the mock fallback still becomes fully live once
    // the service answers — without this the session would park changes forever.
    property bool backendLiveServiceConfirmed: false
    readonly property bool backendBannerVisible:
        !backendStatus || backendStatus.kind !== "connected"
    readonly property int backendBannerHeight: backendBannerVisible ? 36 : 0
    // The red banner offers a one-click Start/Install
    // action. Show it for the actionable backend states (service stopped /
    // not installed, or a runtime disconnect where the launcher collapsed the
    // reason to "disconnected"). Hide it for "connecting" (the spinner already
    // signals progress) and "protocol-mismatch" (the compat banner owns that
    // action). Requires the C++ NrrServiceController bridge.
    readonly property bool backendBannerActionable:
        (typeof nrrServiceController !== "undefined" && nrrServiceController)
        && !!backendStatus
        && (backendStatus.kind === "service-stopped"
            || backendStatus.kind === "service-not-installed"
            || backendStatus.kind === "disconnected")

    // Live startup / connection progress log.
    // The user couldn't tell WHY the app was on mock/offline; this records
    // timestamped lifecycle events (GUI start, IPC connect/offline,
    // reconnect/disconnect, status subscribe) into `startupLogModel`,
    // surfaced as a footer pill (latest line) + an expandable popup
    // (recent history). `logProgress` is the single entry point.
    property string lastProgressMessage: ""
    property string lastProgressKind: "info"   // info|progress|success|warn|error
    readonly property int startupLogCap: 80
    // Drift banner sits BELOW the backend status
    // banner. We only surface it when the backend is connected
    // (otherwise the backend banner already explains why the user
    // can't apply anything, and drift compare is unreliable on a
    // stale snapshot anyway).
    readonly property bool driftBannerVisible:
        _driftDetected && backendStatus && backendStatus.kind === "connected"
    // Zero while the drift line is rendered inside the combined amber banner
    // (see `combinedAmberBannerVisible`) — the standalone bar stands down, the
    // logical `driftBannerVisible` state stays true so `mergeBannerVisible`
    // keeps its suppression rule.
    readonly property int driftBannerHeight:
        (driftBannerVisible && !combinedAmberBannerVisible) ? 36 : 0

    // Quiet "Merge available" banner. Informational (green, not
    // amber). Sits between the drift banner and the compat banner. Hidden while
    // the amber drift banner is up so the two never stack.
    readonly property bool mergeBannerVisible:
        _mergeAvailable && backendStatus && backendStatus.kind === "connected"
            && !driftBannerVisible
    readonly property int mergeBannerHeight: mergeBannerVisible ? 36 : 0

    // "no active rules" notice. Distinct from the backend
    // banner (which explains a broken CONNECTION): this fires when the service
    // is CONNECTED but its rule set is EMPTY, so nothing is being routed /
    // enforced — typically right after a state reset. Without it a fresh "0
    // rules" reads as a breakage. `_serviceRuleCount` is the authoritative
    // count from the last successful `_refreshRulesFromService` RPC (−1 until
    // the first fetch), so the notice never flashes during a load or a failed
    // fetch. The banner now stays visible even when the app holds local
    // rules — it switches to an "apply now" prompt (see emptyRulesBannerHasLocalRules).
    property int _serviceRuleCount: -1
    readonly property bool emptyRulesBannerVisible:
        !!backendStatus && backendStatus.kind === "connected"
        && _serviceRuleCount === 0
    // SERVICE has 0 rules but the APP already holds local rules
    // (imported/added but not yet applied — the F10 "only PresetImport reached the
    // service" case): switch the banner to an "apply now" prompt with an "Apply app
    // state" action so the user can push from this surface. Content-only switch —
    // does NOT affect visibility/height (which stay in lockstep off emptyRulesBannerVisible).
    readonly property bool emptyRulesBannerHasLocalRules:
        !!rulesModel && rulesModel.count > 0
    readonly property int emptyRulesBannerHeight: emptyRulesBannerVisible ? 36 : 0

    // Silent-inaction notice. The worst failure in a traffic product is a
    // service that looks alive while enforcing nothing: connected, rules
    // stored, and yet not one route or filter for this user. The service takes
    // that exit when it finds no route policy for the caller's SID, and
    // `snapshot.initial.get` omits `route-policy` under the SAME condition
    // (no primary AND no secondary binding stored) — so an absent
    // `route-policy`, or one without a secondary slot, is a faithful mirror of
    // "no secondary routes will be applied", not a guess.
    // `_servicePolicyRead` stays false until the first successful snapshot
    // read so a cold start never accuses a service we have not asked yet.
    property bool _servicePolicyRead: false
    property bool _servicePolicySecondaryBound: false
    // Does the APP hold an additional-adapter choice the service never got?
    // That is the one variant with a real one-click fix (re-send the binding);
    // with no choice on either side there is nothing to send, so the notice
    // explains instead of offering a button that cannot work.
    readonly property bool _policyIdlePrefsHaveSecondary:
        uiRevision >= 0
        && (String((prefs && prefs.selectedSecondaryInterfaceId) || "") !== ""
            || String((prefs && prefs.selectedSecondaryInterfaceName) || "") !== "")
    // Raw state, before the settle window below. Each suppression hands the
    // explanation to the banner that already owns that cause: zero service
    // rules -> empty-rules banner; rules not delivered -> the amber
    // "service has none of your rules" line; adapter missing/stale ->
    // the secondary-adapter banner; block-all armed -> enforcement IS running
    // (it is blocking), so "nothing is applied" would be false; paused ->
    // deliberate, and the pause chip already says so.
    // The adapter suppression deliberately reads the RENDERED banner, not the
    // raw adapter state: a user who dismissed that warning is back to seeing
    // nothing at all, which is the exact silence this notice exists to break.
    readonly property bool servicePolicyIdle:
        !!backendStatus && backendStatus.kind === "connected"
        && _servicePolicyRead
        && !_servicePolicySecondaryBound
        && _serviceRuleCount > 0
        && !_serviceRulesEmpty
        && routingState.routingPaused !== true
        && !secondaryAmberBannerVisible
        && !blockAllPostureArmed
    // Set once the raw state has held for the full settle window, so the
    // seconds a healthy service legitimately spends without a policy (boot,
    // reconnect, a binding push still in flight) stay quiet.
    property bool _policyIdleConfirmed: false
    property int _policyIdleTicks: 0
    onServicePolicyIdleChanged: {
        if (!servicePolicyIdle) {
            _policyIdleTicks = 0
            _policyIdleConfirmed = false
        }
    }
    readonly property bool policyInactiveBannerVisible:
        servicePolicyIdle && _policyIdleConfirmed
    // Which half of the story to tell — and whether an action exists.
    readonly property bool policyInactiveActionable:
        policyInactiveBannerVisible && _policyIdlePrefsHaveSecondary
    /// Re-send the adapter binding the app already holds to a service that has
    /// none. The push reports its own failure (adapter not live, elevation
    /// declined) on the status line, which is still better than the silence
    /// this banner exists to break.
    function resendRouteBindingToService() {
        routePolicyController.pushRouteBindingToService()
        // Re-read once the push has had time to land so the notice clears on
        // the spot instead of waiting for the next watch tick. The push is
        // asynchronous (and may go through elevation), so a read issued right
        // here would still see the old state.
        _adaptersChangedSnapshotRefreshTimer.restart()
    }

    // Top-of-window warning that the service is in the block-all
    // fail-closed posture (kill-switch armed AND the additional adapter can't
    // be resolved), so unknown traffic is being blocked. `killSwitchBlockAllArmed`
    // mirrors the connect-time snapshot posture (see `refreshUnenforcedAppRules`);
    // the `warnKillSwitchBlockAll` pref (default on) is the opt-out, toggled from
    // Settings -> Routing behavior. The `uiRevision >= 0` guard makes the binding
    // re-evaluate on every routingState refresh. Height is
    // content-driven (wrapping text), never shorter than the 36px single line.
    readonly property bool blockAllBannerVisible:
        uiRevision >= 0
        && routingState.killSwitchBlockAllArmed === true
        && prefs.warnKillSwitchBlockAll !== false
        && prefs.killSwitchBannerAcknowledged !== true

    // The armed block-all posture on its own — independent of the warn opt-out
    // and the dismiss acknowledgement. The banner's close button persists an
    // acknowledgement that keeps it hidden across restarts; when the posture
    // stops being armed the banner would no longer show anyway, so any prior
    // acknowledgement is cleared and persisted here, so the next time the
    // posture arms the banner reappears. Guarded by `uiRevision >= 0` so the
    // binding re-evaluates on every routingState refresh.
    readonly property bool blockAllPostureArmed:
        uiRevision >= 0 && routingState.killSwitchBlockAllArmed === true
    // Deferred, not inline: the binding above READS `uiRevision` and
    // `updatePrefs` BUMPS it, so writing the pref straight from the change
    // handler re-enters the binding while it is still settling — Qt reports
    // "Binding loop detected for property blockAllPostureArmed" and the write
    // may be lost. `Qt.callLater` with a NAMED function (a fresh closure would
    // defeat Qt's de-duplication) moves it to the next event-loop pass, past
    // the binding evaluation; the function re-checks the condition because the
    // posture can flip back before it runs.
    function _clearKillSwitchBannerAck() {
        if (blockAllPostureArmed) return
        if (prefs.killSwitchBannerAcknowledged !== true) return
        updatePrefs({ killSwitchBannerAcknowledged: false })
        emitPrefs()
    }
    onBlockAllPostureArmedChanged: {
        if (!blockAllPostureArmed && prefs.killSwitchBannerAcknowledged === true) {
            Qt.callLater(_clearKillSwitchBannerAck)
        }
    }

    // "app rules not enforced" notice. Fires when the
    // service is CONNECTED and has rules, but one or more APPLICATION rules
    // name an executable the resolver could not locate (App Paths registry /
    // running process / Program Files walk all missed), so no per-process
    // ALE_APP_ID filter was built and that app's traffic is NOT routed by its
    // rule. Distinct from the empty-rules notice (there ARE rules — a specific
    // app rule just can't be enforced until its exe is found). The set is
    // mirrored from the connect-time snapshot (`unenforced-app-rules`) via
    // `refreshUnenforcedAppRules`, refreshed on reconnect + every rules pull.
    readonly property var unenforcedAppRules:
        (routingState && routingState.unenforcedAppRules) || []
    // The app-enforcement gap is surfaced through the
    // notifications centre (footer bell chip + NotificationCenterPopup), NOT a
    // top banner (the user found the amber banner too heavy for a low-priority
    // notice and, at first, un-closable). Dismiss is keyed to the SORTED set of
    // unresolved apps: dismissing hides it for that exact set, and re-showing
    // the SAME set stays hidden, while a CHANGED set (a newly-unresolved app)
    // yields a new signature and correctly re-surfaces.
    // PERSISTED via prefs.unenforcedAppsAckSig: the
    // session-scoped ack meant the notice re-fired on every GUI start for an
    // unchanged set ("уже каждый запуск надоело"). Seeded from the pref at
    // startup; the dismiss handler writes both the local value and the pref.
    property string _unenforcedAppRulesAckSig:
        (prefs && prefs.unenforcedAppsAckSig) ? String(prefs.unenforcedAppsAckSig) : ""
    // SUBSET semantics, not string equality. The unresolved
    // set oscillates in both directions (an exe resolvable only while its
    // process runs — e.g. a VPN client installed outside App Paths — leaves
    // the set on launch and returns on exit), and an exact-signature compare
    // re-fired the dismissed notice on every SHRINK. Only a genuinely NEW
    // unresolved app (absent from the acknowledged set) re-surfaces it; the
    // dismiss handler stores the UNION so returning apps stay acknowledged.
    function _unenforcedCoveredByAck() {
        if (_unenforcedAppRulesAckSig === "") return false
        var ackSet = {}
        var acked = _unenforcedAppRulesAckSig.split("|")
        for (var i = 0; i < acked.length; i += 1) ackSet[acked[i]] = true
        var apps = unenforcedAppRules || []
        for (var j = 0; j < apps.length; j += 1)
            if (!ackSet[String(apps[j])]) return false
        return true
    }
    function _unenforcedAckUnionSig() {
        var union = {}
        if (_unenforcedAppRulesAckSig !== "") {
            var acked = _unenforcedAppRulesAckSig.split("|")
            for (var i = 0; i < acked.length; i += 1) union[acked[i]] = true
        }
        var apps = unenforcedAppRules || []
        for (var j = 0; j < apps.length; j += 1) union[String(apps[j])] = true
        return Object.keys(union).sort().join("|")
    }
    // Active when connected, at least one app rule is unenforced, and the
    // current set contains an app the user has not yet acknowledged.
    readonly property bool appUnresolvedNoticeActive:
        !!backendStatus && backendStatus.kind === "connected"
        && unenforcedAppRules.length > 0
        && !_unenforcedCoveredByAck()

    // Notifications centre SSOT. Low-priority, non-blocking
    // notices live here instead of stacked top banners. `activeNotifications`
    // is the list rendered by NotificationCenterPopup and counted by the footer
    // bell chip. To add a notice: push { id, severity: "warning"|"info", title,
    // body, actionKey?, actionText? }; `actionKey` is dispatched by
    // `runNotificationAction`, dismissal routed through `dismissNotification`.
    readonly property var activeNotifications: {
        var out = []
        if (appUnresolvedNoticeActive) {
            out.push({
                "id": "app-unresolved",
                "severity": "warning",
                "dismissible": true,
                "title": tr("notifications.app-unresolved.title",
                    "App rules aren't active yet"),
                "body": tr("notifications.app-unresolved.body",
                    "NetRuleRouter couldn't find these programs (they may not be installed in a standard location, or aren't running), so their traffic isn't routed by your rules: {apps}. Launch the app, or check the program name in Rules.")
                    .replace("{apps}", _unenforcedAppRulesSummary()),
                "actionKey": "open-rules",
                "actionText": tr("status.app-unresolved-banner-button", "Open Rules")
            })
        }
        // Standing warning while the STRICT
        // kill-switch (block-all) is on: when the additional adapter (VPN) drops,
        // ALL internet is cut, not just routed sites. Non-dismissible — it mirrors
        // a live, deliberately-chosen dangerous setting and clears the moment the
        // user turns it off (or picks the best-effort variant).
        if (strictKillSwitchActive) {
            out.push({
                "id": "strict-killswitch",
                "severity": "warning",
                "dismissible": false,
                "title": tr("notifications.strict-killswitch.title",
                    "Strict kill-switch is on"),
                "body": tr("notifications.strict-killswitch.body",
                    "While the additional adapter (VPN) is down, ALL internet is blocked except your local network — including normal browsing — until it comes back. Switch to the best-effort variant in Settings → Routing behavior if you want your main connection to keep working when the VPN drops."),
                "actionKey": "open-routing-settings",
                "actionText": tr("notifications.strict-killswitch.action", "Open settings")
            })
        }
        // Daily GitHub release check (launcher-cached;
        // `context.updateCheck` is non-null only when a strictly newer release
        // exists). Dismissible info notice, re-fires next start while newer.
        var upd = (window.context || {}).updateCheck || null
        if (upd && upd.latestVersion) {
            out.push({
                "id": "update-available",
                "severity": "info",
                "dismissible": true,
                "title": tr("notifications.update-available.title",
                    "A new version is available"),
                "body": tr("notifications.update-available.body",
                    "NetRuleRouter {version} has been released (you are running {current}). Open the download page to update.")
                    .replace("{version}", String(upd.latestVersion))
                    .replace("{current}", String(((window.context || {}).about || {}).version || "")),
                "actionKey": "open-release-page",
                "actionText": tr("notifications.update-available.action", "Open download page")
            })
        }
        // The leak protection was re-armed from the
        // user's saved settings after the service state was reset (e.g. a fresh
        // build wiped the per-SID DB). Surface it so a restored kill-switch is never
        // a silent surprise. Dismissible info notice; the user can turn it off.
        if (killSwitchRestoredNoticeActive) {
            out.push({
                "id": "kill-switch-restored",
                "severity": "info",
                "dismissible": true,
                "title": tr("notifications.kill-switch-restored.title",
                    "Leak protection restored"),
                "body": tr("notifications.kill-switch-restored.body",
                    "Leak protection was turned back on from your saved settings (the background service had been reset). If you didn't expect this, you can turn it off in Settings → Routing behavior."),
                "actionKey": "open-routing-settings",
                "actionText": tr("notifications.strict-killswitch.action", "Open settings")
            })
        }
        // Notices the service pushed at us. Everything above is derived from
        // live state and clears itself; a push describes something that already
        // happened, so it is held until the user answers it (here or in the
        // tray). Appended last so a standing warning stays on top.
        for (var p = 0; p < _pushNotices.length; p += 1) out.push(_pushNotices[p])
        return out
    }

    // ── Push-driven notices ──────────────────────────────────────────────────
    //
    // The tray is the surface that can speak while this window is closed, so it
    // owns these notices in the general case. The window keeps its own copy as
    // insurance: a tray that never started, was killed, or had notifications
    // turned off would otherwise swallow the message entirely. Both copies
    // carry the SAME id, and `NotificationLedger` guarantees that answering one
    // retires the other.
    property var _pushNotices: []

    /// `false` when the user silenced this kind of notice on its own. The
    /// master switch is checked by the surfaces that raise OS notifications;
    /// this is the per-kind layer under it.
    function noticeKindEnabled(kind) {
        if (String(kind || "") === "suggestions-changed")
            return prefs.notifySuggestionChanges !== false
        if (String(kind || "") === "block-notice")
            return prefs.notifyBlockNotices !== false
        return true
    }

    /// Silences one kind for good — the "don't show these again" affordance on
    /// the notice itself, so the user never has to find the setting to stop a
    /// stripe that is bothering them right now.
    function muteNoticeKind(kind) {
        var k = String(kind || "")
        if (k === "suggestions-changed") {
            updatePrefs({ notifySuggestionChanges: false })
            emitPrefs()
        } else if (k === "block-notice") {
            updatePrefs({ notifyBlockNotices: false })
            emitPrefs()
        }
    }

    function _addPushNotice(notice) {
        if (!notice || String(notice.id || "") === "") return
        if (!noticeKindEnabled(notice.kind)) return
        // `refractoryMs` is for notices whose id carries a counter the SERVICE
        // restarts (the push id): a permanent record of one silences the id's
        // next incarnation, which is a different event entirely.
        var refractory = Number(notice.refractoryMs || 0)
        if (refractory > 0) {
            var answeredAt = noticeLedger.decidedAt(String(notice.id))
            if (answeredAt > 0 && (Date.now() - answeredAt) < refractory) return
        } else if (noticeLedger.isDecided(String(notice.id))) {
            return
        }
        for (var i = 0; i < _pushNotices.length; i += 1) {
            if (_pushNotices[i].id === notice.id) return
        }
        var entry = notice
        var ttl = Number(notice.autoDismissMs || 0)
        // A notice that carries no decision must not sit over the user's work
        // until it is clicked. Expiry is NOT an answer: nothing goes into the
        // ledger, so a surface that shows the same event can still offer it.
        if (ttl > 0) entry = Object.assign({}, notice, { "expiresAt": Date.now() + ttl })
        _pushNotices = _pushNotices.concat([entry])
    }

    // ── Suggested addresses ──────────────────────────────────────────────────
    //
    // The service parks addresses a routed site appears to need. The tray asks
    // about them; this window is where the ones nobody answered can still be
    // turned into rules. Lives as a section (`RuleSuggestionsSection.qml`,
    // sidebar → Rules → Suggested addresses) rather than a dialog, merged with
    // the dismissed-suggestions history into one table.

    /// Wire rows from the last `autorules.candidates.list`.
    property var autoRuleCandidates: []
    /// How many the service is holding — drives the chip in the Rules header.
    property int autoRuleCandidatesPending: 0
    property bool _autoRuleFetchInFlight: false
    /// Id of the banner currently on screen, so a newer push can replace it.
    property string _autoRuleNoticeId: ""

    function refreshAutoRuleCandidates() {
        if (!bridgeAvailable || _autoRuleFetchInFlight) return
        var corr = rpcTransport.rpcAutoRuleCandidatesList()
        if (!corr || corr === "") return
        _autoRuleFetchInFlight = true
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            window._autoRuleFetchInFlight = false
            if (!ok || !payload) {
                console.log("auto-rule candidates fetch failed:", code, msg)
                return
            }
            var list = payload.candidates || payload["candidates"] || []
            window.autoRuleCandidates = list
            window.autoRuleCandidatesPending = list.length
        })
    }

    /// Navigate to the suggestions section with whatever the service holds
    /// RIGHT NOW — a list cached before the user browsed on would offer
    /// stale addresses.
    function openAutoRuleSuggestions() {
        requestSectionChange("rule-suggestions")
        if (bridgeAvailable) {
            refreshAutoRuleCandidates()
            refreshAutoRuleDismissed()
        }
    }

    function acceptAutoRuleCandidates(ids) {
        if (!ids || ids.length === 0 || !bridgeAvailable) return
        var corr = rpcTransport.rpcAutoRuleCandidatesAccept({ "ids": ids })
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule accept failed:", code, msg)
                return
            }
            window._noteAutoRulePending(p)
        })
    }

    function dismissAutoRuleCandidates(ids) {
        if (!ids || ids.length === 0 || !bridgeAvailable) return
        var corr = rpcTransport.rpcAutoRuleCandidatesDismiss({ "ids": ids })
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule dismiss failed:", code, msg)
                return
            }
            window._noteAutoRulePending(p)
        })
    }

    /// Rows from the last `autorules.dismissed.list`.
    property var autoRuleDismissed: []

    function refreshAutoRuleDismissed() {
        if (!bridgeAvailable) return
        var corr = rpcTransport.rpcAutoRuleDismissedList()
        if (!corr || corr === "") return
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok || !payload) {
                console.log("auto-rule dismissed fetch failed:", code, msg)
                return
            }
            window.autoRuleDismissed = payload.dismissed || payload["dismissed"] || []
        })
    }

    /// Lifts a refusal and puts the offer back on the pending list, so both
    /// lists are re-read: the row moves from declined to waiting.
    function restoreAutoRuleDismissed(ids) {
        if (!ids || ids.length === 0 || !bridgeAvailable) return
        var corr = rpcTransport.rpcAutoRuleDismissedRestore({ "ids": ids })
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule restore failed:", code, msg)
                return
            }
            window.refreshAutoRuleDismissed()
            window.refreshAutoRuleCandidates()
        })
    }

    /// Erases the service's memory of these suggestions entirely, so the host
    /// is offered again from scratch. Both lists are re-read — the row can be
    /// leaving either one.
    function forgetAutoRuleCandidates(ids) {
        if (!ids || ids.length === 0 || !bridgeAvailable) return
        var corr = rpcTransport.rpcAutoRuleCandidatesForget({ "ids": ids })
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("auto-rule forget failed:", code, msg)
                return
            }
            window.refreshAutoRuleDismissed()
            window._noteAutoRulePending(p)
        })
    }

    /// The answer says what is left; take the banner down once nothing is.
    function _noteAutoRulePending(payload) {
        var left = (payload || {}).pending
        if (left === undefined) left = (payload || {})["pending"]
        if (left === undefined) return
        autoRuleCandidatesPending = Number(left)
        if (autoRuleCandidatesPending <= 0) {
            autoRuleCandidates = []
            _dropPushNotice(_autoRuleNoticeId)
        } else {
            refreshAutoRuleCandidates()
        }
    }

    function _expirePushNotices() {
        var now = Date.now()
        var kept = []
        for (var i = 0; i < _pushNotices.length; i += 1) {
            var n = _pushNotices[i]
            if (Number(n.expiresAt || 0) > 0 && Number(n.expiresAt) <= now) continue
            kept.push(n)
        }
        if (kept.length !== _pushNotices.length) _pushNotices = kept
    }

    /// Take a notice down without recording an answer — used when the OTHER
    /// surface already recorded one.
    function _dropPushNotice(noticeId) {
        var id = String(noticeId || "")
        var kept = []
        for (var i = 0; i < _pushNotices.length; i += 1) {
            if (_pushNotices[i].id !== id) kept.push(_pushNotices[i])
        }
        if (kept.length !== _pushNotices.length) _pushNotices = kept
    }
    // Set by RoutingSettings._reseedTogglesFromPrefs when it
    // restores an enabled kill-switch the service had lost; cleared on dismiss.
    property bool killSwitchRestoredNoticeActive: false
    readonly property int notificationCount: activeNotifications.length
    // Highest severity present drives the footer chip colour.
    readonly property string notificationTopSeverity: {
        var sev = ""
        for (var i = 0; i < activeNotifications.length; i += 1) {
            if (activeNotifications[i].severity === "warning") return "warning"
            if (activeNotifications[i].severity === "info") sev = "info"
        }
        return sev
    }
    function runNotificationAction(actionKey) {
        if (actionKey === "open-auto-rule-suggestions") openAutoRuleSuggestions()
        else if (actionKey === "open-rules") section = "rules"
        else if (actionKey === "open-routing-settings") section = "settings"
        else if (actionKey === "open-release-page") {
            // Release URL from the update-check cache; fall
            // back to the project's releases page.
            var u = ((window.context || {}).updateCheck || {}).url || ""
            if (u === "") {
                var base = ((window.context || {}).about || {}).projectUrl || ""
                if (base !== "") u = base + "/releases"
            }
            Pure.openExternalUrl(u)
        }
    }
    function dismissNotification(notificationId) {
        if (notificationId === "app-unresolved") {
            // UNION with the previously-acknowledged set so an
            // app that temporarily left the set (resolved while running) stays
            // acknowledged when it returns after its process exits.
            _unenforcedAppRulesAckSig = _unenforcedAckUnionSig()
            // Persist the ack so the notice stays dismissed
            // across GUI restarts until a NEW unresolved app appears.
            updatePrefs({ unenforcedAppsAckSig: _unenforcedAppRulesAckSig })
            emitPrefs()
        } else if (notificationId === "kill-switch-restored") {
            killSwitchRestoredNoticeActive = false
        }
        // A push notice is answered for good, on every surface: record it before
        // dropping it so the tray stops offering the same thing. The
        // state-derived notices above are deliberately NOT recorded — they are
        // recomputed from live state and are meant to come back when that state
        // says so.
        var isPushNotice = false
        for (var i = 0; i < _pushNotices.length; i += 1) {
            if (_pushNotices[i].id === notificationId) { isPushNotice = true; break }
        }
        if (!isPushNotice) return
        noticeLedger.record(String(notificationId))
        _dropPushNotice(notificationId)
    }

    // Reactive mirror of the strict kill-switch
    // (block-all) setting for the notifications centre. `prefs.routeKillSwitchBlockAll`
    // is mutated IN PLACE by `applyKillSwitchBlockAll` (which does NOT emit
    // `prefsChanged`) and is reassigned wholesale on prefs (re)load — so neither
    // path alone reliably re-evaluates a `prefs.*`-reading binding. This bool is a
    // real property (its own change signal) driven in BOTH: `onPrefsChanged` (every
    // prefs reassignment — load / reseed / restore) and `applyKillSwitchBlockAll`
    // (the in-place live toggle). `activeNotifications` gates the strict notice on it.
    property bool strictKillSwitchActive: false
    onPrefsChanged: {
        strictKillSwitchActive = !!(prefs && prefs.routeKillSwitchBlockAll === true)
        // A rebound rules file changes what the tray must compare against.
        // Guarded because prefs can be reassigned before the component tree is
        // finished, and a throw here would take the kill-switch mirror with it.
        if (typeof guiPresence !== "undefined" && guiPresence) guiPresence.publish()
    }

    // Compatibility banner (GUI ↔ service version).
    // Visible only when the IPC handshake has completed (service
    // protocol > 0) AND the GUI/service protocol numbers disagree.
    // Semver mismatch alone does NOT trigger — patch-level differences
    // wouldn't be a real incompatibility ("QML/UI правки не трогают
    // протокол"). Semvers are
    // still rendered in the banner text for diagnostic clarity.
    property int    _compatGuiProtocol:      0
    property int    _compatServiceProtocol:  0
    property string _compatGuiVersion:       ""
    property string _compatServiceVersion:   ""
    // `compatBannerMode` pref gates visibility:
    //   "never"  → suppressed even on a real protocol mismatch.
    //   "auto"   → (default) protocol-mismatch only.
    //   "always" → also surfaces a semver-only difference (matching
    //              protocols but different build versions), useful when
    //              the operator wants the versions visible at a glance.
    readonly property bool _compatInfoLoaded:
        _compatServiceProtocol > 0 && _compatGuiProtocol > 0
    readonly property bool _compatProtocolMismatch:
        _compatInfoLoaded && _compatGuiProtocol !== _compatServiceProtocol
    readonly property string _compatBannerMode:
        String((prefs && prefs.compatBannerMode) || "auto")
    readonly property bool compatBannerVisible:
        _compatBannerMode === "never"
            ? false
            : (_compatBannerMode === "always"
                ? (_compatInfoLoaded
                    && (_compatProtocolMismatch
                        || _compatGuiVersion !== _compatServiceVersion))
                : _compatProtocolMismatch)
    readonly property int compatBannerHeight: compatBannerVisible ? 36 : 0
    // A visible, non-modal reminder that the rules on screen are not the rules
    // in the file — i.e. edits that were never applied. Applied rules reach the
    // file on their own. Deliberately NOT gated on an existing file path: a
    // user who has not linked a file yet — or who just cleared the table, which
    // unlinks it — still needs a way to save, and the chip's click asks where.
    readonly property bool boundFileOutOfDateBannerVisible: rulesNotSavedToFile
    // (bound-file out-of-date reminder now lives in the footer as an orange
    // chip — see `boundFileChip` — so it reserves no banner-stack height.)
    // VPN split-routing conflict banner. When the user is
    // in "prefer primary" (selective) mode and a bound secondary that LOOKS LIKE
    // A VPN BY NAME is up, NetRuleRouter keeps general traffic on the primary
    // link (the /2 counter-overlay) so the VPN only carries the rule-matched
    // destinations. That is by design, but a user who just launched a VPN sees
    // "VPN connected yet my public IP is still the ISP's" and thinks it's broken.
    // We explain it honestly and offer a one-click switch to a full tunnel
    // (mode B). Detection is name-based on purpose: a non-VPN secondary (e.g. a
    // Bluetooth device-management adapter) must NOT be called a VPN, so we only
    // show this when the secondary's name-derived VPN likelihood is set.
    readonly property bool vpnSplitConflictBannerVisible:
        uiRevision >= 0
        && String((prefs && prefs.routeBehaviorMode) || "prefer-primary")
            === "prefer-primary"
        && interfacesRolesController._vpnConflictSecondaryRow() !== null
        && interfacesRolesController._enabledSecondaryRuleCount() > 0
    // Stale secondary binding (adapter reinstalled, new
    // GUID). The same "secondary adapter" banner slot shows EITHER a re-confirm
    // prompt (priority — the binding is stale) OR the VPN split-routing conflict
    // (binding healthy). They are mutually exclusive in practice; re-confirm
    // wins so the user fixes the binding first.
    // When auto-confirm is enabled (default) a reinstalled
    // adapter (new GUID, unique name match) heals silently; the manual
    // re-confirm banner only appears when the user opted into manual mode.
    readonly property bool secondaryReconfirmVisible:
        uiRevision >= 0 && prefs.autoConfirmAdapterIdChange === false
        && interfacesRolesController._staleSecondaryHealRow() !== null
    // The confirmed secondary binding cannot be resolved to any
    // live adapter (absent / secondary adapter not started / renamed beyond a unique name
    // match / ambiguous), and no auto-heal candidate exists. Actionable: the
    // user should start the adapter or re-select one in Interfaces & routes.
    // While it is missing, matching traffic is blocked (leak protection).
    readonly property bool secondaryUnresolvedVisible:
        uiRevision >= 0 && interfacesRolesController._secondaryUnresolved()
    // PERSISTED per-adapter acknowledgment for the VPN-split informational
    // banner. The blue banner fires in the NORMAL, healthy split state
    // (prefer-primary + a VPN-like secondary UP + ≥1 secondary rule), so it must
    // be a one-time dismissible EXPLAINER — not a live alarm that returns every
    // launch. Dismissing it stores the current secondary adapter's display name
    // in `prefs.secondarySplitAckAdapterName` (persisted to disk); the banner then
    // stays hidden for THAT adapter across relaunches and re-appears only for a
    // genuinely different secondary adapter (whose name won't match the ack).
    // `vpnSplitConflictBannerVisible` reads `uiRevision` (bumped by updatePrefs /
    // interface refresh), so this binding re-evaluates the ack comparison
    // reactively even though the name comes from a JS function.
    readonly property bool secondaryBannerVisible:
        secondaryReconfirmVisible
        || (secondaryUnresolvedVisible && prefs.missingSecondaryBannerAcknowledged !== true)
        || (vpnSplitConflictBannerVisible && !interfacesRolesController._vpnSplitAcked())
    // The secondary-adapter banner in its AMBER (problem) flavour, as opposed
    // to the blue VPN-split explainer.
    readonly property bool secondaryAmberBannerVisible:
        secondaryBannerVisible
        && (secondaryReconfirmVisible || secondaryUnresolvedVisible)
    // Two full-width amber bars stacked read as an alarm wall ("два оранжевых
    // баннера выглядят не очень"). When the drift warning and the
    // secondary-adapter warning are up together they collapse into ONE
    // container with a line per problem and a shared expand toggle; either one
    // alone still renders as its own banner, unchanged.
    readonly property bool combinedAmberBannerVisible:
        driftBannerVisible && secondaryAmberBannerVisible
    // The close button on the amber "additional adapter not found" banner
    // persists an acknowledgement that keeps it hidden across restarts while the
    // adapter stays unresolvable. `secondaryUnresolvedVisible` is the raw state
    // (adapter missing), independent of the ack; when it clears (the adapter
    // resolves again) any prior acknowledgement is cleared and persisted here, so
    // a later disappearance shows the banner again. Mirrors the block-all
    // banner's `onBlockAllPostureArmedChanged` auto-reset.
    // Deferred for the same reason as `_clearKillSwitchBannerAck`: the
    // `secondaryUnresolvedVisible` binding reads `uiRevision`, `updatePrefs`
    // bumps it, and writing inline re-entered the binding ("Binding loop
    // detected for property secondaryUnresolvedVisible").
    function _clearMissingSecondaryBannerAck() {
        if (secondaryUnresolvedVisible) return
        if (prefs.missingSecondaryBannerAcknowledged !== true) return
        updatePrefs({ missingSecondaryBannerAcknowledged: false })
        emitPrefs()
    }
    onSecondaryUnresolvedVisibleChanged: {
        if (!secondaryUnresolvedVisible && prefs.missingSecondaryBannerAcknowledged === true) {
            Qt.callLater(_clearMissingSecondaryBannerAck)
        }
    }
    /// `gui-older` when the GUI's protocol is older than the
    /// service's — user should update the GUI. `service-older` for
    /// the reverse. Drives the "Update [App|Service]" CTA text.
    readonly property string compatBannerDirection:
        (_compatGuiProtocol < _compatServiceProtocol)
            ? "gui-older"
            : "service-older"

    function backendStatusBannerText() {
        var status = backendStatus || {}
        var kind = status.kind || ""
        switch (kind) {
            case "connecting":
                return tr("connection.banner.connecting", "Connecting to service…")
            case "disconnected":
                var msg = tr(
                    "connection.banner.disconnected",
                    "Service offline — showing locally-cached data")
                return status.lastError ? msg + " (" + status.lastError + ")" : msg
            case "service-stopped":
                return tr(
                    "connection.banner.service-stopped",
                    "NetRuleRouter service is stopped")
            case "service-not-installed":
                return tr(
                    "connection.banner.service-not-installed",
                    "NetRuleRouter service is not installed")
            case "protocol-mismatch":
                return tr(
                    "connection.banner.protocol-mismatch",
                    "Service version mismatch — please update")
            default:
                return ""
        }
    }
    function backendStatusBannerColor() {
        var kind = (backendStatus || {}).kind || ""
        return kind === "connecting" ? "#d4a017" : "#c0392b"
    }
    // Footer "Service: …" indicator. It used to
    // echo `context.security.serviceStatus`, a COLD-START mock field hardwired
    // to "alert" (the real health→snapshot mapping is a pending TODO),
    // so a perfectly healthy, connected service still read "Служба: alert".
    // Derive the word from the LIVE backend connection state instead, and
    // localize it (the raw slug must never be shown — HARD RULE).
    function serviceFooterStatusText() {
        var kind = String((backendStatus || {}).kind || "connected")
        var word = tr("connection.service-status." + kind,
            kind === "connected" ? "OK" : kind)
        return tr("label.service", "Service") + ": " + word
    }

    // Bindings deliberately read `uiRevision` (incremented by `updatePrefs`)
    // before reading `prefs` — QML's dependency tracker follows the integer
    // change reliably, while `var prefs` reassignment via `Object.assign` is
    // not always picked up by binding recomputation in Qt 6.11. Without this
    // the theme/font-scale UI applies only after a full window reopen
    // (verified empirically in 13.R2-GUI.2).
    ThemeTokens {
        id: uiTheme
        // Tied to `themeRevision` via direct ternary read so QML's binding
        // analyzer reliably registers the dependency. The earlier
        // `(uiRevision, expr)` comma-expression did NOT always register —
        // we therefore switched
        // the trigger from `uiRevision` to `themeRevision` so these tokens
        // recompute ONLY on a real theme/font change, not on every generic
        // interaction (row selection, unsaved flag, rules refetch, tab
        // switch) — the perf regression with resident keep-alive sections.
        themeMode: themeRevision >= 0 ? resolveThemeModeForPrefs(prefs) : "system"
        accessibilityHighContrast: themeRevision >= 0
            ? resolveThemeModeForPrefs(prefs) === "high-contrast" : false
        fontScalePercent: themeRevision >= 0 ? Number(prefs.fontScalePercent || 100) : 100
        systemFont: themeRevision >= 0 ? String(prefs.systemFont || "system-default") : "system-default"
    }

    // Aliases exposed to section files (apps/windows/qml/sections/*.qml)
    property alias uiTheme: uiTheme
    property alias interfacesModel: interfacesModel
    property alias behaviorModeModel: behaviorModeModel
    property alias ruleTypesModel: ruleTypesModel
    property alias rulesModel: rulesModel
    property alias logsModel: logsModel
    property alias ruleDialog: ruleDialog
    property alias fullResetConfirmDialog: fullResetConfirmDialog
    property alias loadListWindow: loadListWindow
    property alias refreshAction: refreshAction
    property alias logsFolderAction: logsFolderAction
    property alias aboutAction: aboutAction
    // Generic in-flight mutation tracker, shared
    // with every section that has submit-style buttons.
    property alias mutationsModel: mutationsModel
    // Review-flow dialogs. Sections invoke them
    // via `startRulesReviewFlow(rulesJson, contentHash)`.
    property alias reviewDiffDialog: reviewDiffDialog
    property alias reviewExpiredDialog: reviewExpiredDialog
    // Exposed for flows/DriftController (drift + merge dialogs it drives).
    property alias driftDetectionDialog: driftDetectionDialog
    property alias mergeReviewDialog: mergeReviewDialog
    // The single post-connect "what piled up while the service was stopped"
    // dialog, driven by the window's backlog collector.
    property alias offlineBacklogDialog: offlineBacklogDialog
    // Exposed for flows/PresetImportController (the duplicate/reclassify review dialog).
    property alias presetImportReviewDialog: presetImportReviewDialog
    // Transient toast stack pinned to the
    // bottom-right corner.
    property alias operationToastStack: operationToastStack
    // Global unsaved-changes guard. Sections call
    // `setUnsavedChanges(id, dirty)` directly; only Main.qml's own
    // intent-bearing call sites talk to the guard via the
    // `requestSectionChange` / `requestWindowClose` /
    // `requestApplicationQuit` helpers.
    property alias unsavedChangesGuard: unsavedChangesGuard
    // Tray-initiated safe-disable confirmation
    // dialog. Opened from `applyGuiActivationRequest` when the
    // secondary launcher writes `action: "safe-disable"` into the
    // gui-activation.json hand-off.
    property alias safeDisableConfirmDialog: safeDisableConfirmDialog
    // Guardrail dialog for an additional adapter that cannot carry traffic
    // out. Opened through `confirmUnroutableSecondary(...)` from the
    // interfaces role flow and from the leak-protection toggle.
    property alias unroutableSecondaryConfirmDialog: unroutableSecondaryConfirmDialog
    // Exposed so Settings can re-trigger onboarding.
    property alias firstRunWindow: firstRunWindow
    // Exposed so the extracted FirstRunWindow can reach the sibling
    // Licenses window (View EULA button + transient-parent hand-off).
    property alias licenseWindow: licenseWindow
    property alias firstLaunchInstallDialog: firstLaunchInstallDialog
    property alias eulaAgreementWindow: eulaAgreementWindow

    readonly property bool darkTheme: uiTheme.isDark
    readonly property color windowColor: uiTheme.colorWindow
    readonly property color panelColor: uiTheme.colorPanel
    readonly property color baseColor: uiTheme.colorBase
    readonly property color textColor: uiTheme.colorText
    readonly property color mutedTextColor: uiTheme.colorTextMuted
    readonly property color borderColor: uiTheme.colorBorder
    readonly property color accentColor: uiTheme.colorAccent
    // Relative paths resolved at parse time so Image consumers in
    // sub-section QML files (which live at a different URL) don't
    // re-resolve `../../../assets/...` against their own location.
    readonly property url appIconSource: Qt.resolvedUrl("../../../assets/icons/app/icon-64.png")
    readonly property url appIconSmallSource: Qt.resolvedUrl("../../../assets/icons/app/icon-32.png")
    readonly property bool highContrastIcons: uiTheme.useHighContrastIcons

    // Left navigation rail collapse. When
    // collapsed the rail shrinks to an icon-only strip (glyph + tooltip);
    // toggled by the header button in the rail. Session-only for now
    // (persisting needs a UiPreferences schema bump).
    property bool sidebarCollapsed: false

    palette.window: windowColor
    palette.windowText: textColor
    palette.base: baseColor
    palette.alternateBase: panelColor
    palette.button: panelColor
    palette.buttonText: textColor
    palette.text: textColor
    palette.highlight: accentColor
    palette.highlightedText: uiTheme.colorOnAccent
    palette.toolTipBase: panelColor
    palette.toolTipText: textColor

    font.family: uiTheme.resolvedFontFamily
    font.pixelSize: uiTheme.baseFontSizePx

    ListModel { id: interfacesModel }
    ListModel { id: behaviorModeModel }
    ListModel { id: ruleTypesModel }
    ListModel { id: rulesModel }
    ListModel { id: logsModel }
    // Generic mutation-in-flight tracker. Listens
    // to `mutation-progress` push events from `handlePushEvent`.
    MutationsModel { id: mutationsModel }
    ListModel { id: wizardStepsModel }
    ListModel { id: wizardScenariosModel }
    FontMetrics { id: fontMetricsProbe; font: window.font }

    function tr(key, fallbackText) {
        // Depends only on `currentLanguage` + `localeCatalog` (both
        // stable between language switches), NOT on `uiRevision` or the
        // volatile `prefs` object — so theme/font/other interactions do
        // not re-evaluate every text binding in the tree.
        return resolveCatalogText(currentLanguage, key, fallbackText !== undefined ? fallbackText : key)
    }
    function resolveCatalogText(languageId, key, fallbackText) {
        var lang = resolveLanguageId(languageId)
        var activeMap = localeCatalog[lang] || {}
        if (activeMap[key] !== undefined) return activeMap[key]
        var base = String(lang || "").split("-")[0]
        var baseMap = localeCatalog[base] || {}
        if (baseMap[key] !== undefined) return baseMap[key]
        var fallbackMap = localeCatalog["en"] || {}
        if (fallbackMap[key] !== undefined) return fallbackMap[key]
        return fallbackText
    }

    function boolLabel(value) { return value ? tr("label.yes", "Yes") : tr("label.no", "No") }
    function behaviorModeLabel(id) { return tr("interfaces.mode." + id, id) }
    function availabilityLabel(id) { return tr("interfaces.availability." + id, id) }
    function routeStateLabel(id) { return tr("interfaces.state." + id, id) }
    function defaultRouteLabel(role) {
        if (role === "primary") return tr("label.primary", "Primary")
        if (role === "block") return tr("label.block", "Block")
        return tr("label.secondary", "Secondary")
    }
    function routeLabel(role) {
        if (role === "primary") return prefs.routePrimaryLabel || defaultRouteLabel("primary")
        // "block" is a fixed semantic (drop), NOT a renamable adapter label —
        // it must never fall through to prefs.routeSecondaryLabel.
        if (role === "block") return tr("label.block", "Block")
        return prefs.routeSecondaryLabel || defaultRouteLabel("secondary")
    }
    function routeRoleOptions(includeBlock) {
        var opts = [
            { id: "primary", label: routeLabel("primary") },
            { id: "secondary", label: routeLabel("secondary") }
        ]
        if (includeBlock) opts.push({ id: "block", label: routeLabel("block") })
        return opts
    }
    function localeTextForLanguage(languageId, key, fallbackText) {
        return resolveCatalogText(languageId, key, fallbackText)
    }
    // Memoized: `ruleTypeLabel` is called once per row on every
    // `RulesSection.rebuildDisplay()` sort pass (up to a few hundred rows),
    // and `tr()` does two map lookups plus a locale-fallback walk per call.
    // Keyed by the raw slug; invalidated wholesale on a real language switch
    // via `onCurrentLanguageChanged` below (a same-language `currentLanguage`
    // reassignment is a QML value-equality no-op and never fires it).
    property var _ruleTypeLabelCache: ({})
    onCurrentLanguageChanged: _ruleTypeLabelCache = ({})
    function ruleTypeLabel(id) {
        var slug = String(id)
        var cached = _ruleTypeLabelCache[slug]
        if (cached !== undefined) return cached
        var label = tr("rules.type." + slug, slug)
        _ruleTypeLabelCache[slug] = label
        return label
    }
    function themeLabel(id) { return tr("theme." + id, id) }
    function fallbackLanguage() {
        var ids = Object.keys(localeCatalog || {})
        if ((localeCatalog || {})["en"] !== undefined) return "en"
        return ids.length > 0 ? ids[0] : "en"
    }
    function resolveLanguageId(value) {
        var normalized = String(value || "").toLowerCase().replace(/_/g, "-")
        normalized = normalized.split(".")[0].split("@")[0]
        if (normalized !== "" && (localeCatalog || {})[normalized] !== undefined) return normalized
        var base = normalized.split("-")[0]
        if (base !== "" && (localeCatalog || {})[base] !== undefined) return base
        return fallbackLanguage()
    }
    function availableLanguageIds() {
        if (availableLanguages && availableLanguages.length > 0) {
            var ids = []
            for (var i = 0; i < availableLanguages.length; i += 1) ids.push(availableLanguages[i].id)
            return ids
        }
        var discovered = Object.keys(localeCatalog || {})
        return discovered.length > 0 ? discovered.sort() : ["en"]
    }
    function languageDescriptor(id) {
        for (var i = 0; i < availableLanguages.length; i += 1) {
            if (availableLanguages[i].id === id) return availableLanguages[i]
        }
        return null
    }
    function languageLabel(id) {
        var descriptor = languageDescriptor(resolveLanguageId(id))
        if (descriptor && descriptor.nativeLabel) return descriptor.nativeLabel
        if (descriptor && descriptor.label) return descriptor.label
        return tr("label.language-" + id, String(id || "").toUpperCase())
    }
    function measuredTextWidth(text, fontObject) {
        return Math.ceil(fontMetricsProbe.advanceWidth(String(text || "")))
    }
    function comboPopupWidth(control, model, textRole, textResolver) {
        var maxWidth = measuredTextWidth(control.displayText, control.font)
        for (var i = 0; i < Pure.modelLength(model); i += 1) {
            var itemText = Pure.comboItemText(Pure.modelItem(model, i), textRole, textResolver, i)
            maxWidth = Math.max(maxWidth, measuredTextWidth(itemText, control.font))
        }
        return clampPopupWidth(control, Math.max(control.width, maxWidth + 72))
    }
    function menuPopupWidth(labels) {
        var maxWidth = 0
        for (var i = 0; i < labels.length; i += 1) {
            maxWidth = Math.max(maxWidth, measuredTextWidth(labels[i], window.font))
        }
        return clampPopupWidth(window, Math.max(220, maxWidth + 88))
    }
    function popupAvailableWidth(item) {
        // `Window.<prop>` is an ITEM-only attached property. `menuPopupWidth`
        // passes the ApplicationWindow itself, and asking a Window for it made
        // Qt log "Window.window does only support types deriving from Item"
        // against the root object (Main.qml:14) on every menu measurement.
        // `mapToItem` exists on Item and not on Window, so it discriminates
        // cheaply; a Window still falls through to the screen/width branches
        // below exactly as it did when the attached read returned undefined.
        var isItem = !!item && typeof item.mapToItem === "function"
        if (isItem && item.Window && item.Window.width) return Math.max(220, item.Window.width - 48)
        if (window.Screen && window.Screen.desktopAvailableWidth) return Math.max(220, window.Screen.desktopAvailableWidth - 48)
        if (window.width) return Math.max(220, window.width - 48)
        return 640
    }
    function clampPopupWidth(item, candidateWidth) {
        return Math.min(Math.max(220, candidateWidth), popupAvailableWidth(item))
    }
    function sectionTitle(id) {
        if (id === "interfaces-routes") return tr("section.interfaces-routes", "Interfaces and routes")
        if (id === "rules") return tr("section.rules", "Rules")
        if (id === "rule-suggestions") return tr("rules.suggestions.inbox.nav-label", "Suggested addresses")
        if (id === "diagnostics") return tr("section.diagnostics", "Diagnostics")
        if (id === "logs") return tr("section.logs", "Logs")
        if (id === "settings") return tr("section.settings", "Settings")
        return id
    }

    // ── the two "rules changed" states ──────────────────────────────────
    //
    // They are NOT the same thing and must never share one indicator:
    //
    //   rulesNotAppliedToService — the table differs from what the service
    //                              enforces. Gates the footer "Apply".
    //   rulesNotSavedToFile      — the table differs from the linked rules
    //                              file. Gates the "Save to file" chip.
    //
    // With the service stopped the first one cannot be cleared at all (there
    // is nothing to apply to), so a prompt worded around it would be
    // unanswerable; with the service running the file is a copy the user can
    // rewrite at any time. `rulesGuardDirty()` below picks the one that a
    // navigation / close would actually put at risk.
    readonly property bool rulesNotAppliedToService:
        uiRevision >= 0 ? !!unsavedChangesRegistry["rules"] : false
    readonly property bool rulesNotSavedToFile:
        _filesSyncDirtyPrimary || _filesSyncDirtySecondary
    /// Raised by the guard's "Discard": the user has been warned once and
    /// chose to continue, so the modal stands down until the next rule edit.
    /// The state itself is NOT cleared — the orange "Save to file" chip and
    /// the lit "Apply" button keep it visible without blocking navigation.
    property bool _rulesGuardAcknowledged: false
    function rulesGuardDirty() {
        if (_rulesGuardAcknowledged) return false
        return _routingBackendConnected()
            ? rulesNotAppliedToService
            : rulesNotSavedToFile
    }
    /// One line naming WHICH of the two states the guard is asking about, so
    /// "unsaved changes" is never a riddle. Empty when rules are not the
    /// reason the guard opened.
    function rulesGuardDetail() {
        if (!rulesGuardDirty()) return ""
        return _routingBackendConnected()
            ? tr("unsaved-changes.detail.rules-not-applied",
                "The rules on screen have not been applied to the service yet.")
            : tr("unsaved-changes.detail.rules-not-saved",
                "The rules on screen have not been saved to your rules file yet. "
                + "The service is stopped, so the file is the only place they can be kept.")
    }

    // Global unsaved-changes registry. Each section
    // that owns editable state calls `setUnsavedChanges(id, dirty)`;
    // section navigation, window close, and app quit all consult
    // `hasAnyUnsavedChanges()` via UnsavedChangesGuard before
    // destroying that state. Reactive: `uiRevision` is bumped on
    // each registry write so anything binding off
    // `hasAnyUnsavedChanges()` re-evaluates.
    //
    // The "rules" entry is a special case: it records ONLY the
    // not-applied-to-service state, so the guard consults `rulesGuardDirty()`
    // for it instead of reading the entry directly.
    property var unsavedChangesRegistry: ({})
    function setUnsavedChanges(sectionId, dirty) {
        if (!sectionId) return
        var was = !!unsavedChangesRegistry[sectionId]
        var now = !!dirty
        if (was === now) return
        var next = Object.assign({}, unsavedChangesRegistry)
        if (now) next[sectionId] = true
        else delete next[sectionId]
        unsavedChangesRegistry = next
        uiRevision += 1
        // Central edit hook for drift detection.
        // Recompute the GUI hash leg as soon as the user enters or
        // leaves the dirty state; the file + service legs stay until
        // the next 30 s poll. This keeps the banner reactive to
        // edits without waiting for the periodic tick.
        if (sectionId === "rules" && typeof driftController._driftUpdateGuiHash === "function") {
            Qt.callLater(function() {
                driftController._driftUpdateGuiHash("primary",   driftController._driftCompare)
                driftController._driftUpdateGuiHash("secondary", driftController._driftCompare)
            })
        }
    }
    function hasAnyUnsavedChanges() {
        var rev = uiRevision
        for (var k in unsavedChangesRegistry) {
            // Rules answer through `rulesGuardDirty()`: which of the two rule
            // states is at risk depends on whether the service can take an
            // apply at all.
            if (k === "rules") continue
            if (unsavedChangesRegistry[k]) return true
        }
        return rulesGuardDirty()
    }
    function firstDirtySectionId() {
        for (var k in unsavedChangesRegistry) {
            if (k === "rules") continue
            if (unsavedChangesRegistry[k]) return k
        }
        return rulesGuardDirty() ? "rules" : ""
    }
    function clearAllUnsavedChanges() {
        // The rule state survives a Discard (the table is not reverted), so
        // record the acknowledgement instead of pretending it is clean.
        _rulesGuardAcknowledged = true
        if (Object.keys(unsavedChangesRegistry).length === 0) {
            uiRevision += 1
            return
        }
        unsavedChangesRegistry = {}
        uiRevision += 1
    }

    // Save-and-continue support for
    // UnsavedChangesGuard. Sections that own dirty state can
    // register a save callback keyed by their dirty sectionId.
    // The callback receives a single `onDone(ok)` parameter and
    // MUST invoke it from the success/failure tail of the section's
    // own Save flow (e.g. inside an RPC response handler). When
    // the user picks "Save and continue" the guard fires the
    // callback for `firstDirtySectionId()`; if onDone(true) fires,
    // the guard then invokes the original pending intent. If no
    // callback is registered for a dirty section, the guard hides
    // the Save-and-continue button — only Cancel and Discard
    // remain. Bumps `uiRevision` so the guard's `visible` binding
    // re-evaluates when callbacks come and go.
    property var saveCallbacks: ({})
    function setSaveCallback(sectionId, callback) {
        if (!sectionId) return
        var next = Object.assign({}, saveCallbacks)
        if (typeof callback === "function") next[sectionId] = callback
        else delete next[sectionId]
        saveCallbacks = next
        uiRevision += 1
    }
    function saveCallbackForSection(sectionId) {
        if (!sectionId) return null
        var cb = saveCallbacks[sectionId]
        return (typeof cb === "function") ? cb : null
    }

    // Paired revert callback registry.
    // Sections that own dirty draft state can register a synchronous
    // revert function keyed by their dirty sectionId. On Discard the
    // guard walks the dirty registry and fires each section's revert
    // callback (typically a re-fetch of the persisted state from the
    // service) BEFORE clearing the dirty flag. Without this, a user
    // who picks Discard and then navigates back to the same section
    // would see their abandoned draft values lingering in QML state.
    property var revertCallbacks: ({})
    function setRevertCallback(sectionId, callback) {
        if (!sectionId) return
        var next = Object.assign({}, revertCallbacks)
        if (typeof callback === "function") next[sectionId] = callback
        else delete next[sectionId]
        revertCallbacks = next
        uiRevision += 1
    }
    function revertCallbackForSection(sectionId) {
        if (!sectionId) return null
        var cb = revertCallbacks[sectionId]
        return (typeof cb === "function") ? cb : null
    }

    // Translate a wire error code (kebab-case slug
    // emitted by `nrr-launcher::rpc_dispatcher::ipc_error_to_wire`)
    // into a localised label. Accepts both kebab and snake variants
    // for resilience (some upstream surfaces still emit
    // `precondition_failed` instead of `precondition-failed`). The
    // input is lowercased and `_` is normalised to `-` before
    // lookup; an unrecognised slug falls back to the slug itself so
    // operators still see something meaningful in toasts/logs.
    function ipcErrorLabel(code) {
        var slug = String(code || "").toLowerCase().replace(/_/g, "-")
        if (slug === "") return tr("errors.unknown", "Unknown error")
        var key = "errors." + slug
        var fallback = tr("errors.unknown", "Unknown error")
        var localised = tr(key, "")
        if (localised && localised !== key && localised !== "") return localised
        // No matching entry — return the raw slug so the surface is
        // still self-describing (e.g. a brand-new server error code
        // we haven't added a key for yet).
        return slug
    }

    // Guarded section navigation. Every site that
    // would write `section = X` (sidebar buttons, Ctrl+1..5
    // shortcuts, tray-driven hand-offs, settings shortcut) calls
    // this instead. No-op if the user is already on the target;
    // otherwise consults UnsavedChangesGuard which either fires the
    // intent immediately (nothing dirty) or prompts the user.
    // `onArrival` runs once the move actually happens — after the guard, not
    // before it. A caller that also selects something inside the target section
    // must not apply that selection to a navigation the user then cancels.
    function requestSectionChange(next, onArrival) {
        if (!next) return
        if (next === section) {
            if (onArrival) onArrival()
            return
        }
        var target = next
        var arrive = function() {
            section = target
            if (onArrival) onArrival()
        }
        if (!unsavedChangesGuard) {
            arrive()
            return
        }
        unsavedChangesGuard.requestAction("section-nav", arrive, sectionTitle(section))
    }

    /// Which Settings category the section shows. Lives on the window because
    /// the navigation sidebar owns the category list — Settings itself is only
    /// instantiated once it opens, so it cannot be the source of truth.
    property string settingsCategory: "application"

    function openSettingsCategory(categoryId) {
        if (!categoryId) return
        var target = categoryId
        requestSectionChange("settings", function() { window.settingsCategory = target })
    }

    /// Disclosure ("Show details" / expand-a-list) state for the sections
    /// below. Lives on the window, not the section, so switching tabs and
    /// coming back never re-collapses what the user opened.
    property var diagCacheExpanded: ({})
    property int diagCacheExpandRev: 0
    property var diagConnGroupExpanded: ({})
    property int diagConnGroupExpandRev: 0
    property var suggestionsExpandedDomains: ({})
    property bool routingDohLockdownDetailsExpanded: false
    property bool routingKsDetailsExpanded: false
    property bool routingDefaultRouteDetailsExpanded: false
    property bool routingFakeIpDetailsExpanded: false
    property bool routingDnsViaSecondaryDetailsExpanded: false
    property bool routingBlockAllDetailsExpanded: false
    property bool routingSharedStrictDetailsExpanded: false
    property bool routingSharedExemptAddressesExpanded: false
    property bool routingDohEditorExpanded: false

    function resolveThemeModeForPrefs(preferences) {
        var effective = String((preferences || {}).effectiveThemeMode || "")
        if (effective === "light" || effective === "dark" || effective === "high-contrast") return effective

        var selected = String((preferences || {}).themeMode || "system")
        if (selected === "high-contrast") return "high-contrast"
        if (selected === "light" || selected === "dark") return selected

        var themeContext = context.theme || {}
        var systemMode = String(themeContext.systemMode || "")
        if (systemMode === "dark" || systemMode === "light") return systemMode

        return "light"
    }
    function normalizePrefs(candidate) {
        var normalized = Object.assign({}, candidate || {})
        normalized.fontScalePercent = Pure.normalizedFontScalePercent(normalized.fontScalePercent)
        normalized.language = resolveLanguageId(normalized.language || systemLanguage())
        // Stale `effectiveThemeMode` carried over by `Object.assign` from a
        // prior `prefs` snapshot would short-circuit `resolveThemeModeForPrefs`
        // (it returns the cached effective if valid), masking a fresh
        // `themeMode` patch. Force recomputation each normalize.
        delete normalized.effectiveThemeMode
        normalized.effectiveThemeMode = resolveThemeModeForPrefs(normalized)
        normalized.accessibilityHighContrast = normalized.effectiveThemeMode === "high-contrast"
        normalized.selectedPrimaryInterfaceName = String(normalized.selectedPrimaryInterfaceName || "")
        normalized.selectedPrimaryInterfaceId = String(normalized.selectedPrimaryInterfaceId || "")
        normalized.primaryRoleUserConfirmed = !!normalized.primaryRoleUserConfirmed
        normalized.selectedSecondaryInterfaceId = String(normalized.selectedSecondaryInterfaceId || "")
        normalized.selectedSecondaryInterfaceName = String(normalized.selectedSecondaryInterfaceName || "")
        normalized.secondaryRoleUserConfirmed = !!normalized.secondaryRoleUserConfirmed
        // Default to the valid slug
        // `prefer-primary`, NOT `"auto"` (which is not a RouteBehaviorMode
        // variant; the service-side parser silently rejected it, so the
        // mode never round-tripped). PreferPrimary = unmatched → primary.
        normalized.routeBehaviorMode = String(normalized.routeBehaviorMode || "prefer-primary")
        normalized.showBluetoothAdapters = !!normalized.showBluetoothAdapters
        // Security-audit viewing-tab display toggle (default off). Only an
        // explicit true reveals the tab; the audit trail records regardless.
        normalized.showAuditTab = !!normalized.showAuditTab
        // Idle delay (seconds) before a settings panel that owns draft state
        // commits it without the user pressing anything. Clamped to the same
        // range the preference store enforces; 0/absent means "use the default".
        var autosaveSecs = Number(normalized.settingsAutosaveSecs)
        if (!isFinite(autosaveSecs) || autosaveSecs <= 0) autosaveSecs = 60
        normalized.settingsAutosaveSecs =
            Math.max(15, Math.min(600, Math.round(autosaveSecs)))
        // Administrator-rights idle auto-revoke. Opt-out defaults to false
        // (auto-revoke ON — the secure direction); minutes clamped to the
        // same 1..180 range the preference store enforces, 0/absent = default.
        normalized.adminAutoRevokeDisabled = !!normalized.adminAutoRevokeDisabled
        var revokeMinutes = Number(normalized.adminAutoRevokeMinutes)
        if (!isFinite(revokeMinutes) || revokeMinutes <= 0) revokeMinutes = 15
        normalized.adminAutoRevokeMinutes =
            Math.max(1, Math.min(180, Math.round(revokeMinutes)))
        // Experimental opt-in that reveals the legacy kill-switch mode A option
        // in routing settings (default off). Only an explicit true opts in.
        normalized.allowModeAKillswitch = !!normalized.allowModeAKillswitch
        // Experimental opt-in that reveals the "pre-flight, then
        // all-or-nothing" apply-failure policy option in routing settings
        // (default off). Only an explicit true opts in.
        normalized.preFlightApplyPolicyOptIn = !!normalized.preFlightApplyPolicyOptIn
        // "remembered but absent" ghost-row display toggle. Default ON
        // (a missing value coerces to true) so the user can see a remembered
        // binding at a glance; only an explicit false turns it off.
        normalized.showRememberedAdapters = normalized.showRememberedAdapters === undefined
            ? true : !!normalized.showRememberedAdapters
        // Persisted per-adapter ack for the VPN-split banner. Empty
        // string (never acknowledged) is the default so the banner shows once
        // per new secondary adapter.
        normalized.secondarySplitAckAdapterName = String(normalized.secondarySplitAckAdapterName || "")
        // Persisted acknowledgement of the block-all banner. Coerce to a bool so
        // the emitted payload is always valid; default false (banner shown).
        normalized.killSwitchBannerAcknowledged = !!normalized.killSwitchBannerAcknowledged
        // Persisted acknowledgement of the "additional adapter not found" banner.
        // Coerce to a bool; default false (banner shown).
        normalized.missingSecondaryBannerAcknowledged = !!normalized.missingSecondaryBannerAcknowledged
        // Selected traffic-statistics period. Coerce to one of the two known
        // slugs; unknown / missing → "today" (the default).
        normalized.trafficStatsPeriod =
            (normalized.trafficStatsPeriod === "session") ? "session" : "today"
        // Remembered CSV export unit. Coerce to a known slug so the combo box
        // can index the model directly; unknown / missing → "mb" (the default).
        normalized.trafficExportUnit =
            (["bytes", "kb", "mb", "gb"].indexOf(String(normalized.trafficExportUnit)) >= 0)
                ? String(normalized.trafficExportUnit) : "mb"
        // Support-archive privacy tier. Coerce to a known slug so both export
        // surfaces can trust it; unknown / missing → "standard" (the default).
        normalized.diagnosticsArchiveRedactionLevel =
            (normalized.diagnosticsArchiveRedactionLevel === "diagnostics")
                ? "diagnostics" : "standard"
        // "Current session only" archive scope. Coerce to a bool; missing →
        // true (the narrow default).
        normalized.diagnosticsArchiveSessionOnly =
            normalized.diagnosticsArchiveSessionOnly === undefined
                ? true : !!normalized.diagnosticsArchiveSessionOnly
        // Cap (MiB) on the raw service logs attached to a support archive.
        // Coerce to one of the offered values so the combo can index its model
        // directly; unknown / missing → 0 (unlimited, the default).
        normalized.archiveLogBudgetMib =
            ([0, 24, 64, 128].indexOf(Number(normalized.archiveLogBudgetMib)) >= 0)
                ? Number(normalized.archiveLogBudgetMib) : 0
        // Folder the user keeps their own rule sets in. Coerce to a string so
        // usage sites can compare it directly; empty / missing means the
        // quick-load dropdown lists the rule sets shipped with the app.
        normalized.userPresetsDir = String(normalized.userPresetsDir || "")
        // The remembered quick-load selection, `<source>:<label>`. Empty /
        // missing means "not chosen yet", which is what lets the shipped-set
        // list fall back to the system-locale pick.
        normalized.selectedPresetSet = String(normalized.selectedPresetSet || "")
        // Acknowledgement of the "the app folder is overwritten by an update"
        // warning. Missing reads as false — the warning is shown again, which
        // is the safe direction.
        normalized.allowSavingIntoBundledPresets =
            normalized.allowSavingIntoBundledPresets === true
        normalized.rulesFolderSuggestionDismissed =
            normalized.rulesFolderSuggestionDismissed === true
        // File↔service merge conflict-resolution policy. Coerce to
        // a known slug; unknown / missing → "union" (the safe interactive
        // default). No separate QML defaults object exists — coercion here IS
        // the default.
        normalized.mergeConflictPolicy =
            (normalized.mergeConflictPolicy === "file-wins"
                || normalized.mergeConflictPolicy === "service-wins")
            ? normalized.mergeConflictPolicy : "union"
        // Coerce the policy-toggle mirrors so the
        // emitted payload always carries valid types/defaults for the launcher.
        // Subdomain coverage defaults ON: an undefined value must
        // resolve to true, only an explicit false is "exact domain only".
        normalized.routeIncludeSubdomains =
            (normalized.routeIncludeSubdomains === undefined)
                ? true : !!normalized.routeIncludeSubdomains
        normalized.routeSharedIpPolicy = String(normalized.routeSharedIpPolicy || "majority-of-ip")
        normalized.routeKillSwitchBlockAll = !!normalized.routeKillSwitchBlockAll
        // Remaining routing/blocking mirrors. Coerce with
        // the SERVICE defaults so the emitted payload is always valid: fail-closed
        // defaults ON (undefined → true), protocols default to all (127), and the
        // enforcement mode is one of the two known slugs (default reactive).
        // Each of these prefs is a MIRROR of a service-owned route-policy field,
        // so its default is taken from the one wire-field table rather than
        // restated here — a mirror that normalises to a different default than
        // the request builder sends is the same divergence in another disguise.
        normalized.routeKillSwitchFailClosed =
            Pure.routePolicyCoerce("kill-switch-fail-closed",
                normalized.routeKillSwitchFailClosed)
        normalized.routeKillSwitchProtocols =
            Pure.routePolicyCoerce("kill-switch-protocols",
                normalized.routeKillSwitchProtocols)
        normalized.routeEnforcementMode =
            (normalized.routeEnforcementMode === "resolver") ? "resolver" : "reactive"
        normalized.routeKillSwitchEnabled =
            Pure.routePolicyCoerce("kill-switch-enabled", normalized.routeKillSwitchEnabled)
        normalized.routeAllowDnsOverPrimary =
            Pure.routePolicyCoerce("allow-dns-over-primary",
                normalized.routeAllowDnsOverPrimary)
        // Slug-valued: an unrecognised value is not "keep it", it is "use the
        // declared default" — the service would reject anything else.
        normalized.routeModeACoverageStrategy =
            (normalized.routeModeACoverageStrategy === "per-ip"
                || normalized.routeModeACoverageStrategy === "fail-closed-unknown"
                || normalized.routeModeACoverageStrategy === "zone-widening")
            ? normalized.routeModeACoverageStrategy
            : Pure.ROUTE_POLICY_FIELD_DEFAULTS["mode-a-coverage-strategy"]
        normalized.routeResolveHostsBypass =
            Pure.routePolicyCoerce("resolve-hosts-bypass", normalized.routeResolveHostsBypass)
        // Secondary tunnel liveness window (seconds).
        // undefined → 0 (disabled); else coerce to int, and if non-zero clamp
        // to the backend contract [5, 3600].
        if (normalized.routeLivenessWindowSecs === undefined) {
            normalized.routeLivenessWindowSecs = 0
        } else {
            var lw = normalized.routeLivenessWindowSecs | 0
            normalized.routeLivenessWindowSecs =
                (lw === 0) ? 0 : Math.max(5, Math.min(3600, lw))
        }
        // Offline routing intents parked as a compact
        // single-line JSON object ("" = none). Coerce to a string so the emitted
        // payload is always valid; the Rust side round-trips it verbatim.
        normalized.routePendingOfflineJson = String(normalized.routePendingOfflineJson || "")
        // Last-known values of the service-owned settings, mirrored as a compact
        // single-line JSON object ("" = nothing mirrored yet). Coerce to a string
        // so the emitted payload is always valid; Rust round-trips it verbatim.
        normalized.serviceBackedMirrorJson = String(normalized.serviceBackedMirrorJson || "")
        // What the user asked the service-owned settings to be ("" = never
        // touched). Same coercion as the mirror above.
        normalized.serviceIntentJson = String(normalized.serviceIntentJson || "")
        // EULA acceptance — highest accepted agreement version (0 = never
        // accepted). Coerce to a non-negative integer so the emitted payload is
        // always a valid u32 for the launcher.
        normalized.acceptedEulaVersion = Math.max(0, normalized.acceptedEulaVersion | 0)
        return normalized
    }
    // Apply/Cancel buffer-rollback (13.R2-GUI.3.c):
    // First mutating `updatePrefs` since the last Apply/Cancel takes a deep
    // snapshot of the prefs object. While `prefsSnapshot !== null`, the
    // footer Apply / Cancel buttons are enabled. Apply discards the snapshot
    // (commits current prefs); Cancel restores prefs from the snapshot and
    // re-emits so the launcher persists the reverted state on exit. Closing
    // the window without explicit Apply / Cancel is treated as an implicit
    // apply — matches Windows preferences-dialog convention.
    property var prefsSnapshot: null
    readonly property bool prefsHaveUnsavedChanges: prefsSnapshot !== null

    // UTC ms when this GUI session started (evaluated once
    // at ApplicationWindow creation). The in-app log view uses it as its
    // "current session" filter cutoff.
    readonly property real appSessionStartMs: Date.now()

    // Local-midnight floor of `appSessionStartMs` — the cutoff the
    // diagnostic-archive "current session only" checkbox actually sends.
    // Anchoring the archive to the start of the session's calendar DAY (not
    // the GUI process launch) keeps the whole test day together: restarting
    // the app or the service mid-test must not silently drop the rotated log
    // segments written minutes earlier. Previous days stay excluded.
    readonly property real appSessionDayStartMs: {
        var d = new Date(appSessionStartMs)
        d.setHours(0, 0, 0, 0)
        return d.getTime()
    }

    // Shared source of truth for the diagnostic-archive privacy tier
    // forwarded as the 4th arg to rpcDiagnosticsExportArchive: "standard"
    // (default, redacted) or "diagnostics" (extra detail, less redacted).
    // Both export surfaces — Settings -> «Диагностика и логи» and the
    // Diagnostics section — bind their radio to this single property so a
    // choice made in one place is reflected in the other. Derived from `prefs`
    // (read-only) so the choice survives a restart; write it through
    // `setDiagnosticsArchiveRedactionLevel`. The `uiRevision >= 0` term forces
    // re-evaluation on every prefs write.
    readonly property string diagnosticsArchiveRedactionLevel: uiRevision >= 0
        ? String(prefs.diagnosticsArchiveRedactionLevel || "standard") : "standard"
    // Companion scope flag for the same two surfaces: when true (default) the
    // archive only carries the current session's logs. Persisted the same way;
    // write it through `setDiagnosticsArchiveSessionOnly`.
    readonly property bool diagnosticsArchiveSessionOnly: uiRevision >= 0
        ? prefs.diagnosticsArchiveSessionOnly !== false : true
    // Commit the archive privacy tier immediately (no footer Apply): the pick
    // is a display-only export option, so it is written and flushed in one go.
    // The backend re-validates the slug and owns the allow-list.
    function setDiagnosticsArchiveRedactionLevel(level) {
        var slug = (level === "diagnostics") ? "diagnostics" : "standard"
        if (slug === String(prefs.diagnosticsArchiveRedactionLevel || "")) return
        updatePrefs({ diagnosticsArchiveRedactionLevel: slug })
        emitPrefs()
    }
    // Same commit-immediately semantics for the session-only archive scope.
    function setDiagnosticsArchiveSessionOnly(enabled) {
        var value = !!enabled
        if (value === (prefs.diagnosticsArchiveSessionOnly !== false)) return
        updatePrefs({ diagnosticsArchiveSessionOnly: value })
        emitPrefs()
    }
    // Cap (MiB) on the raw service logs attached to a support archive; 0 =
    // unlimited (the default). Read-only mirror of the pref, written through
    // `setArchiveLogBudgetMib`; the launcher reads the same value when it
    // post-processes a finished export.
    readonly property int archiveLogBudgetMib: uiRevision >= 0
        ? Number(prefs.archiveLogBudgetMib || 0) : 0
    // Commit-immediately again: the cap is an export option, not a policy edit.
    function setArchiveLogBudgetMib(mib) {
        var value = ([0, 24, 64, 128].indexOf(Number(mib)) >= 0) ? Number(mib) : 0
        if (value === Number(prefs.archiveLogBudgetMib || 0)) return
        updatePrefs({ archiveLogBudgetMib: value })
        emitPrefs()
    }

    // Folder the user keeps their own rule sets in; the quick-load dropdown in
    // Rules enumerates it instead of the sets shipped with the app. Empty (the
    // default) keeps the shipped sets. Read-only mirror of the pref so every
    // surface reads one value; write it through `setUserPresetsDir`. The
    // `uiRevision >= 0` term forces re-evaluation on every prefs write.
    readonly property string userPresetsDir: uiRevision >= 0
        ? String(prefs.userPresetsDir || "") : ""
    // Commit-immediately semantics: picking (or clearing) the folder is a
    // one-gesture choice with nothing left for the footer Apply to do, so it is
    // written and flushed in one go. An empty path resets to the shipped sets.
    function setUserPresetsDir(path) {
        var value = String(path || "").trim()
        if (value === String(prefs.userPresetsDir || "")) return
        updatePrefs({ userPresetsDir: value })
        emitPrefs()
    }
    /// Is `path` part of the rule sets that ship with the app — i.e. a location
    /// the next update overwrites, so binding a save target there loses the
    /// user's work? The single source of truth for that question; three
    /// controllers used to answer it with their own copy of the test and one of
    /// them (the preset-import path) did not know about the exception below,
    /// which silently blanked the save binding of every set imported from the
    /// user's own folder.
    ///
    /// The exception: the folder the user explicitly designated as their own
    /// rule-set folder is NEVER factory, even when it sits inside the shipped
    /// tree — pointing it there is their acknowledged choice, and the warning
    /// about updates is raised where that choice is made, not on every save.
    function isFactoryPresetPath(path) {
        if (!path || String(path) === "") return false
        if (Pure.isPathUnderDir(String(path), userPresetsDir)) return false
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.isPathUnderBundledPresets !== "function") {
            return false
        }
        return !!nrrNativeBridge.isPathUnderBundledPresets(String(path))
    }
    // The folder EVERY rule-file dialog should open in — one chosen location,
    // so "load a list", "export this route" and "save as a set" all agree
    // instead of each landing wherever the OS last remembered.
    //
    // A `file:` URL, because that is what `FileDialog.currentFolder` takes;
    // the path itself stays the single stored value. Consumers must gate the
    // assignment on `hasRulesFolder` — writing an empty URL into
    // `currentFolder` does not mean "use the default", it points the dialog at
    // the process working directory.
    // Acknowledged warning about saving a set into the folder that ships with
    // the app (an update overwrites it). Written by the warning's own
    // "do not ask again" tick, through `setAllowSavingIntoBundledPresets`.
    readonly property bool allowSavingIntoBundledPresets: uiRevision >= 0
        ? prefs.allowSavingIntoBundledPresets === true : false
    function setAllowSavingIntoBundledPresets(enabled) {
        var value = !!enabled
        if (value === (prefs.allowSavingIntoBundledPresets === true)) return
        updatePrefs({ allowSavingIntoBundledPresets: value })
        emitPrefs()
    }

    // One-time "keep your sets here?" offer. Armed by `suggestRulesFolder`
    // after a rule file is saved to (or loaded from) a folder, and only while
    // no folder is configured yet — see the banner for the reasoning. The path
    // lives in memory: an unanswered offer is not worth persisting, and the
    // next save re-arms it anyway.
    property string rulesFolderSuggestionPath: ""
    readonly property bool rulesFolderSuggestionVisible:
        rulesFolderSuggestionPath !== "" && !hasRulesFolder
            && prefs.rulesFolderSuggestionDismissed !== true

    // Offer `path`'s FOLDER as the rule-set folder. Silent when a folder is
    // already configured (the user knows the feature; a one-off export
    // elsewhere is deliberate), when they already dismissed the offer, or when
    // the folder is the app's own — that one is proposed by its own button and
    // is the wrong place to keep sets in.
    function suggestRulesFolder(filePath) {
        if (hasRulesFolder || prefs.rulesFolderSuggestionDismissed === true) return
        var p = String(filePath || "").replace(/\\/g, "/")
        var cut = p.lastIndexOf("/")
        if (cut <= 0) return
        var folder = p.substring(0, cut)
        if (folder === "") return
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.bundledPresetsRoot === "function") {
            var bundled = String(nrrNativeBridge.bundledPresetsRoot() || "")
                .replace(/\\/g, "/").replace(/\/+$/, "")
            if (bundled !== "" && bundled.toLowerCase() === folder.toLowerCase()) return
        }
        rulesFolderSuggestionPath = folder
    }
    function acceptRulesFolderSuggestion() {
        var folder = rulesFolderSuggestionPath
        rulesFolderSuggestionPath = ""
        if (folder === "") return
        setUserPresetsDir(folder)
        statusLine = tr("status.user-presets-folder-set",
            "The quick-load dropdown now lists the rule sets in your folder.")
    }
    // Answered "no": never offer again. Persisted, because re-asking on the
    // next save is exactly the nagging this design avoids.
    function dismissRulesFolderSuggestion() {
        rulesFolderSuggestionPath = ""
        updatePrefs({ rulesFolderSuggestionDismissed: true })
        emitPrefs()
    }

    readonly property bool hasRulesFolder: userPresetsDir !== ""
    readonly property url rulesFolderUrl: hasRulesFolder
        ? Qt.resolvedUrl("file:///" + userPresetsDir.replace(/\\/g, "/"))
        : Qt.url("")

    // The rule sets available in the chosen folder changed (a set was written
    // from Settings). The Rules section re-enumerates its quick-load dropdown
    // on this, because the folder PATH did not change — only its contents did,
    // and nothing else would tell the dropdown to look again.
    signal presetSetsChanged()

    // Anchor a rule-file dialog at the chosen folder, then open it. Assigning
    // the folder imperatively on every open, instead of declaratively: the
    // dialog writes `currentFolder` itself while the user navigates, which
    // breaks a declarative binding for the rest of the session, so the second
    // open would land wherever the user browsed last.
    //
    // The `hasRulesFolder` guard matters — writing an empty URL into
    // `currentFolder` does not mean "use the default", it points the dialog at
    // the process working directory.
    function openRulesDialog(dlg) {
        if (!dlg) return
        if (hasRulesFolder) {
            dlg.currentFolder = rulesFolderUrl
            // A save picker reopens next to whatever file was picked last, and
            // that silently overrides the folder set above. Keep the remembered
            // file name, re-anchored into the folder.
            if (dlg.fileMode === FileDialog.SaveFile) {
                var previous = String(dlg.selectedFile || "")
                var name = previous.substring(previous.lastIndexOf("/") + 1)
                if (name !== "") {
                    dlg.selectedFile = Qt.url(String(rulesFolderUrl) + "/" + name)
                }
            }
        }
        dlg.open()
    }


    // Shared source of truth for the "verbose service logging" flag.
    // Surfaced from two places — Settings -> «Диагностика и логи» and the
    // Logs view filter bar — both of which bind their checkbox to this
    // single property so a change in one place is immediately reflected in
    // the other. Kept fresh by each surface's stability-config fetch and by
    // the live apply below. Session-scoped mirror of the service value; the
    // service remains authoritative.
    property bool serviceVerboseLogging: false

    // Internal bookkeeping pref fields the app writes
    // on its own (preset load/export path memory, auto-open path memory, the
    // first-run flag) rather than the user choosing them. A patch made up of
    // ONLY these keys must NOT arm the footer Apply/Cancel snapshot — otherwise
    // the buttons look "active when nothing was changed" (e.g. right after a
    // preset load wrote lastSavedPath*).
    readonly property var _nonArmingPrefKeys: ({
        "lastSavedPathPrimary": true,
        "lastSavedPathSecondary": true,
        "lastLoadedPathPrimary": true,
        "lastLoadedPathSecondary": true,
        "autoOpenOnLaunchPathPrimary": true,
        "autoOpenOnLaunchPathSecondary": true,
        "firstRunCompleted": true,
        // Dismissing the VPN-split explainer writes this ack; it
        // is app bookkeeping, not a user preference edit, so it must NOT light up
        // the footer Apply/Cancel.
        "secondarySplitAckAdapterName": true,
        // Dismissing the block-all banner writes this ack; app bookkeeping, not
        // a user preference edit, so it must NOT light up the footer Apply/Cancel.
        "killSwitchBannerAcknowledged": true,
        // Dismissing the "additional adapter not found" banner writes this ack;
        // app bookkeeping, not a user preference edit, so it must NOT light up
        // the footer Apply/Cancel.
        "missingSecondaryBannerAcknowledged": true,
        // Switching the traffic-statistics period is a display-only UI choice,
        // not a routing edit, so it must NOT light up the footer Apply/Cancel.
        "trafficStatsPeriod": true,
        // The export-unit choice commits immediately on pick (updatePrefs +
        // emitPrefs in the same handler), so it must not arm the footer.
        "trafficExportUnit": true,
        // The support-archive detail level and session-only scope commit
        // immediately on pick (updatePrefs + emitPrefs in the same setter), so
        // they must not arm the footer Apply/Cancel.
        "diagnosticsArchiveRedactionLevel": true,
        "diagnosticsArchiveSessionOnly": true,
        // The archive raw-log cap commits on pick in the same setter, so it
        // must not arm the footer Apply/Cancel either.
        "archiveLogBudgetMib": true,
        // Choosing (or clearing) the user's own rule-set folder commits in the
        // same setter, so it must not arm the footer Apply/Cancel either.
        "userPresetsDir": true,
        // Picking a set in the quick-load dropdown is a navigation gesture that
        // commits immediately — it must not read as a pending settings edit.
        "selectedPresetSet": true,
        // Ticking "do not ask again" inside the warning commits immediately.
        "allowSavingIntoBundledPresets": true,
        // Dismissing the folder offer commits immediately too.
        "rulesFolderSuggestionDismissed": true,
        // The default-route selector commits to the service immediately on
        // selection (applyRouteBehaviorMode RPC); the prefs write is only the
        // display mirror, so it must NOT light up the footer Apply/Cancel —
        // there is nothing left to apply and nothing Cancel could undo.
        "routeBehaviorMode": true,
        // The kill-switch group applies on click; this warn toggle is a
        // display-only companion and must not arm the footer either.
        "warnKillSwitchBlockAll": true,
        // The audit-tab display toggle commits immediately on click
        // (updatePrefs + emitPrefs in the same handler); arming the footer
        // would leave a permanent phantom "unsaved changes" state because
        // Apply has nothing left to do.
        "showAuditTab": true,
        // The autosave cadence commits immediately on edit (updatePrefs +
        // emitPrefs in the same handler); arming the footer would leave a
        // phantom "unsaved changes" state.
        "settingsAutosaveSecs": true,
        // Both admin auto-revoke settings commit immediately on edit, same
        // pattern as the autosave cadence above.
        "adminAutoRevokeDisabled": true,
        "adminAutoRevokeMinutes": true,
        // The legacy mode-A opt-in commits immediately on click (updatePrefs +
        // emitPrefs in the same handler), so it must not arm the footer.
        "allowModeAKillswitch": true,
        // The pre-flight apply-policy opt-in commits immediately on click
        // (updatePrefs + emitPrefs in the same handler), so it must not arm
        // the footer.
        "preFlightApplyPolicyOptIn": true,
        // Silencing a notice kind commits immediately — it is answered from the
        // notice itself, where a pending Apply would make no sense.
        "notifySuggestionChanges": true,
        // Same reasoning for the block-notice master switch and its
        // address-privacy companion — both are notification-behaviour
        // toggles, not routing edits.
        "notifyBlockNotices": true,
        "hideBlockNoticeAddresses": true,
        // The detailed-mode switch commits immediately (updatePrefs + emitPrefs
        // in the same handler); it only changes visibility, so arming the
        // footer would leave nothing for Apply to do.
        "routingDetailedMode": true,
        // Ack/layout bookkeeping the app writes on its own.
        "unenforcedAppsAckSig": true,
        "cacheTableColumnWidths": true,
        // The mirror of the last-known service-owned values is written by the
        // panels' READ path (and flushed immediately), never by a user edit, so
        // it must not light up the footer Apply/Cancel.
        "serviceBackedMirrorJson": true,
        // Intent is recorded at the moment the user changes a service-owned
        // setting — that change has its own live apply and its own failure
        // path, so the footer Apply/Cancel has nothing to do with it.
        "serviceIntentJson": true
    })
    function _patchArmsPrefsSnapshot(patch) {
        for (var key in patch) {
            if (!_nonArmingPrefKeys[key]) return true
        }
        return false
    }
    function updatePrefs(patch) {
        var p = patch || {}
        if (prefsSnapshot === null && _patchArmsPrefsSnapshot(p)) {
            prefsSnapshot = JSON.parse(JSON.stringify(prefs))
        }
        // Only bump `themeRevision` (which
        // forces a full theme-token recompute across the whole tree) when
        // a theme-affecting field is actually in the patch. Non-theme
        // toggles (notifications, route labels, etc.) bump only
        // `uiRevision` and leave the theme untouched.
        if (p.hasOwnProperty("themeMode")
                || p.hasOwnProperty("effectiveThemeMode")
                || p.hasOwnProperty("accessibilityHighContrast")
                || p.hasOwnProperty("fontScalePercent")
                || p.hasOwnProperty("systemFont")) {
            themeRevision += 1
        }
        prefs = normalizePrefs(Object.assign({}, prefs, p))
        // Same-language reassignment is a value-equal no-op (QML won't
        // re-fire tr bindings); only a real switch propagates.
        currentLanguage = prefs.language
        uiRevision += 1
    }
    function applyPendingPrefs() {
        if (prefsSnapshot === null) return
        prefsSnapshot = null
        emitPrefs()
        statusLine = tr("status.changes-applied", "Changes applied.")
    }
    function cancelPendingPrefs() {
        if (prefsSnapshot === null) return
        var restored = normalizePrefs(prefsSnapshot)
        // The routing/blocking toggles are
        // committed to the service IMMEDIATELY on click (apply* + route.policy
        // RPC) and mirrored to prefs at once; they are NOT part of the pending
        // prefs Apply/Cancel buffer. If an UNRELATED field armed the snapshot
        // earlier, restoring it verbatim would revert a committed routing choice
        // to a stale value AND re-emit it (which _reseedTogglesFromPrefs would
        // then push back to the service). Preserve the live values instead.
        restored.routeIncludeSubdomains = prefs.routeIncludeSubdomains
        restored.routeSharedIpPolicy = prefs.routeSharedIpPolicy
        restored.routeKillSwitchBlockAll = prefs.routeKillSwitchBlockAll
        restored.routeKillSwitchFailClosed = prefs.routeKillSwitchFailClosed
        restored.routeKillSwitchProtocols = prefs.routeKillSwitchProtocols
        // Same commit-immediately semantics for the remaining mirrors.
        restored.routeKillSwitchEnabled = prefs.routeKillSwitchEnabled
        restored.routeAllowDnsOverPrimary = prefs.routeAllowDnsOverPrimary
        restored.routeModeACoverageStrategy = prefs.routeModeACoverageStrategy
        restored.routeResolveHostsBypass = prefs.routeResolveHostsBypass
        restored.routeEnforcementMode = prefs.routeEnforcementMode
        restored.routeLivenessWindowSecs = prefs.routeLivenessWindowSecs
        restored.routeBehaviorMode = prefs.routeBehaviorMode
        // Offline pending intents are committed to their own
        // store immediately (never part of the Apply/Cancel prefs buffer), so
        // preserve the live value rather than reverting it.
        restored.routePendingOfflineJson = prefs.routePendingOfflineJson
        // The mirror of the last-known service-owned values is a read-path cache
        // written outside the Apply/Cancel buffer; reverting it would resurrect
        // values the service has since replaced.
        restored.serviceBackedMirrorJson = prefs.serviceBackedMirrorJson
        // Intent is committed as the user makes each change (never part of the
        // Apply/Cancel buffer), so preserve the live value — reverting it would
        // re-open the door for a wiped service DB to win.
        restored.serviceIntentJson = prefs.serviceIntentJson
        // The support-archive export options are committed on pick (they are
        // never part of the Apply/Cancel prefs buffer), so preserve the live
        // values rather than reverting a choice the user already made.
        restored.diagnosticsArchiveRedactionLevel = prefs.diagnosticsArchiveRedactionLevel
        restored.diagnosticsArchiveSessionOnly = prefs.diagnosticsArchiveSessionOnly
        restored.archiveLogBudgetMib = prefs.archiveLogBudgetMib
        // The user's own rule-set folder is committed on pick too, so preserve
        // the live value rather than reverting a folder the user just chose.
        restored.userPresetsDir = prefs.userPresetsDir
        // The quick-load selection is a navigation gesture committed on pick;
        // Cancel must not drag the dropdown back to a set the user left.
        restored.selectedPresetSet = prefs.selectedPresetSet
        restored.allowSavingIntoBundledPresets = prefs.allowSavingIntoBundledPresets
        restored.rulesFolderSuggestionDismissed = prefs.rulesFolderSuggestionDismissed
        prefs = restored
        currentLanguage = prefs.language
        uiRevision += 1
        prefsSnapshot = null
        emitPrefs()
        statusLine = tr("status.changes-cancelled", "Changes reverted.")
    }
    // The global footer Apply / Cancel act on BOTH
    // UI preferences (`prefsSnapshot`) AND pending rule edits (the "rules"
    // entry of `unsavedChangesRegistry`). The user expects one global pair to
    // cover everything editable. Rules can't commit in-place — they go through
    // the review → dry-run → activate chain (or the offline park) via
    // `_guardApplyRules`; prefs commit immediately. Cancel reverts rule edits
    // to the service's current rules (re-baselines + clears the dirty flag).
    function applyPendingChanges() {
        var rulesDirty = rulesNotAppliedToService
        applyPendingPrefs()
        // The rules half reports its own outcome (applied, saved-instead,
        // cancelled), so the continuation only has to settle the surfaces that
        // depend on it: an out-of-band drift check makes the amber banner and
        // the file/service comparison honest immediately instead of on the
        // next 30 s tick.
        if (rulesDirty) {
            reviewFlowController._guardApplyRules(function(ok) {
                driftController._driftRecheckNow()
            })
        }
        // Every OTHER section that owns dirty draft state (panels that talk to
        // the service directly rather than through `prefs`) commits through its
        // registered save callback. Without this the footer Apply looked like a
        // global "apply everything" but silently ignored those panels, forcing
        // a second per-panel Save button the user had to find.
        _applyDirtySectionCallbacks(["rules"])
    }
    /// Fire the registered save callback of every dirty section except the ones
    /// in `except`. Each callback owns its own success/failure reporting.
    function _applyDirtySectionCallbacks(except) {
        var skip = except || []
        for (var id in unsavedChangesRegistry) {
            if (!unsavedChangesRegistry[id]) continue
            if (skip.indexOf(id) >= 0) continue
            var cb = saveCallbackForSection(id)
            if (cb) cb(function(ok) {})
        }
    }
    function cancelPendingChanges() {
        if (!!unsavedChangesRegistry["rules"]
                && backendStatus && String(backendStatus.kind) === "connected"
                && typeof _refreshRulesFromService === "function") {
            // The footer Cancel is an
            // explicit "discard my unsaved edits and revert to the service state"
            // gesture, so it must revert ATOMICALLY without the empty-service
            // warning dialog. That F2 guard exists only for the "Show the rules
            // the service is applying" pull, where a surprise wipe is the
            // concern; here the user is deliberately discarding, and the prefs
            // half reverts synchronously right below. Passing confirmedEmpty:true
            // reverts the rule model to the service's state even when the service
            // is empty, so a single Cancel can't split into reverted-prefs +
            // still-dirty-rules with a "Changes reverted" status that lies.
            _refreshRulesFromService({ silent: false, confirmedEmpty: true })
        }
        // Mirror of the Apply side: sections with their own draft state revert
        // through their registered callback (typically a re-fetch of the
        // persisted values) and leave the dirty state behind.
        for (var id in unsavedChangesRegistry) {
            if (!unsavedChangesRegistry[id] || id === "rules") continue
            var revert = revertCallbackForSection(id)
            if (revert) revert()
            setUnsavedChanges(id, false)
        }
        cancelPendingPrefs()
    }
    // Service-owned state (not UI preferences), kept outside `prefs`. The
    // literals below are the INITIAL defaults shown until the first snapshot /
    // push event updates them via `updateRoutingState` (wired to the service
    // push handlers further down). Mutations bump `uiRevision`.
    property var routingState: ({
        retentionSettings: {
            supersededDays: 30,
            supersededCountCap: 100,
            rejectedDays: 7,
            rolledbackDays: 14,
            rolledbackCountCap: 20,
            pinLkg: true,
            lastCleanupAt: ""
        },
        applyFailurePolicy: "best-effort",
        routingPaused: false,
        routingPausedAt: "",
        routingPauseReason: "",
        autostartEnabled: false,
        autostartLastKnownState: "absent",
        autostartBinaryMatches: true,
        autostartOverrideValue: "",
        storageUsageBytes: { stateDb: 0, cacheDb: 0, operationalLogs: 0, auditLogs: 0, total: 0 },
        storageUsageScanState: "idle",
        storageUsageScannedAt: "",
        trayActive: true,
        // Application rules whose executable the service
        // could not resolve to a path (App Paths / running process / Program
        // Files all missed), so no per-process filter was built and that app's
        // traffic is NOT routed by its rule. Drives the app-unresolved banner.
        unenforcedAppRules: [],
        // What the service may do with the companion domains it finds
        // ("off" / "suggest" / "auto"). Mirrored from the connect snapshot so
        // the start screen can show and change it without opening Settings.
        autoRulesMode: "suggest",
        // Mirror of the per-SID "seed from browser history
        // automatically" opt-in, refreshed from the connect snapshot.
        browserHistoryAutoSeed: false,
        // Mirror of the per-SID kill-switch shared-IP
        // strictness (false = "smart": census-shared IPs are not pinned).
        killSwitchStrictSharedIps: false,
        // How many secondary IPs the smart kill-switch
        // excluded from its pin/block set this compute (0 = no warning).
        killSwitchSharedIpExemptions: 0,
        // The excluded addresses themselves, when the
        // service reports them. Older services send only the count above, so
        // this stays empty and the settings panel says so rather than
        // inventing a list.
        killSwitchSharedIpExemptionAddresses: [],
        // Mirror of the service block-all posture (kill-switch
        // fail-closed + secondary adapter unresolved). Drives the warning
        // banner; refreshed from the connect snapshot.
        killSwitchBlockAllArmed: false
    })

    function updateRoutingState(patch) {
        routingState = Object.assign({}, routingState, patch || {})
        uiRevision += 1
    }
    /// Pull the set of application rules the service could
    /// NOT enforce (executable path unresolved) from the connect-time snapshot
    /// and mirror it into `routingState` so the top-of-window banner reflects
    /// it. Cheap read op (`snapshot.initial.get`), safe for non-elevated
    /// clients. Called on reconnect and after every rules refresh, since an
    /// app's resolvability changes once it is installed or launched (the
    /// resolver also inspects running processes).
    function refreshUnenforcedAppRules() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInitialGet()
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok || !p) return
            var list = p["unenforced-app-rules"] || p.unenforcedAppRules || []
            var rpRaw = p["route-policy"] || p.routePolicy
            var rp = rpRaw || {}
            // Does the service hold anything that can route this user's rules?
            // An absent `route-policy` is the service's own "no route policy
            // for this user" state; a policy without a secondary slot resolves
            // to the same "no secondary routes will be applied" outcome.
            window._servicePolicySecondaryBound = !!(rpRaw && rp.secondary)
            window._servicePolicyRead = true
            updateRoutingState({
                unenforcedAppRules: list,
                // Keep the auto-seed checkbox in sync with the
                // service-side per-SID value on every reconnect/rules refresh.
                browserHistoryAutoSeed: rp["browser-history-auto-seed"] === true,
                // Same refresh for the auto-rules mode the start screen shows.
                // An absent or unknown value reads as the declared default,
                // never as "apply automatically".
                autoRulesMode: window._routePolicyEffective(rp, "auto-rules-mode"),
                // Strictness mirror + the smart kill-switch
                // shared-IP exclusion count for the settings warning.
                killSwitchStrictSharedIps: rp["kill-switch-strict-shared-ips"] === true,
                killSwitchSharedIpExemptions:
                    Number(p["kill-switch-shared-ip-exemptions"] || 0),
                // Optional companion to the count above. Absent from
                // services that only report the number — the panel then shows
                // the count alone instead of an empty or fabricated list.
                killSwitchSharedIpExemptionAddresses:
                    (p["kill-switch-shared-ip-exemption-addresses"] instanceof Array)
                        ? p["kill-switch-shared-ip-exemption-addresses"] : [],
                // Mirror the service block-all posture so the
                // top-of-window warning banner reflects the live fail-closed
                // state (kill-switch armed + secondary adapter unresolved).
                killSwitchBlockAllArmed:
                    p["kill-switch-block-all-armed"] === true
            })
            _resyncLinkProvidersFromPrefs(p)
        })
    }
    // Heal the service-side link-provider SSOT after a
    // service-DB wipe. The confirmed-VPN prefs mirror survives (registry),
    // but the per-SID `route_link_provider_apps` table does not; without it
    // the VPN client earns no APP_EXEMPT permit and its own handshake is
    // caught by the kill-switch catch-all. When the connect
    // snapshot reports an EMPTY service set while the prefs mirror holds
    // confirmed paths, push the mirror back through route.link-provider.set.
    // Once per GUI session: the write triggers a server-side recompile, so
    // the next snapshot already shows a non-empty set; the flag also keeps a
    // failing write from being retried on every reconnect tick.
    property bool _linkProviderResyncAttempted: false
    function _resyncLinkProvidersFromPrefs(snapshot) {
        if (_linkProviderResyncAttempted) return
        var rp = (snapshot
                && (snapshot["route-policy"] || snapshot.routePolicy)) || {}
        var svc = rp["secondary-link-provider-apps"] || []
        if (svc.length > 0) {
            _linkProviderResyncAttempted = true
            return
        }
        var joined = (prefs && prefs.confirmedVpnExePaths)
            ? String(prefs.confirmedVpnExePaths) : ""
        if (joined === "") return
        var paths = joined.split(";")
        var apps = []
        for (var i = 0; i < paths.length; i += 1) {
            var path = String(paths[i] || "").trim()
            if (path === "") continue
            var base = String(path.split(/[\\/]/).pop() || "")
            if (base === "") continue
            apps.push({ "exe-path": path, "display-name": base })
        }
        if (apps.length === 0) return
        _linkProviderResyncAttempted = true
        _writeLinkProviderSet(apps)
    }
    /// Human-readable summary of the unresolved app rules for the banner:
    /// the first few names, then "+N more" so a long list never blows the row.
    function _unenforcedAppRulesSummary() {
        var list = unenforcedAppRules || []
        if (list.length === 0) return ""
        var head = list.slice(0, 3).join(", ")
        if (list.length > 3) {
            return head + " " + tr("status.app-unresolved-more", "+{n} more")
                .replace("{n}", String(list.length - 3))
        }
        return head
    }
    // Correlation-id RPC transport over the C++ bridge: the pending-callback
    // table, GC timer, and bridge forwarders now live in flows/RpcTransport so
    // the shell no longer owns the pipe. Every RPC goes through `rpc.<fn>`;
    // sections/components reach it as `root.rpc`.
    property alias rpc: rpcTransport
    RpcTransport {
        id: rpcTransport
        bridge: nrrNativeBridge
    }

    // What the tray cannot work out for itself: whether this window exists and
    // has the user's attention, and which files back the current rules. The
    // tray needs both to decide whether to raise a notice of its own and what
    // to compare; publishing the window's own answer is what keeps the two
    // surfaces from disagreeing about which file is "the" rules file.
    GuiPresence {
        id: guiPresence
        publishing: true
        snapshotProvider: function() {
            return {
                // Any window of ours holding focus counts: a modal child window
                // (the stopped-service diff, a confirmation) takes focus away
                // from `window` itself, and the user is still looking at us.
                active: window.active || Qt.application.state === Qt.ApplicationActive,
                rulesPathPrimary: window._comparableRulesPathFor("primary"),
                rulesPathSecondary: window._comparableRulesPathFor("secondary")
            }
        }
    }
    /// Which file the tray may compare against the service for `route`. The
    /// remembered binding (`rulesSourcePathFor` minus its last-resort fallback),
    /// with one exclusion: a rule set shipped with the app is read-only and is
    /// nobody's working copy — offering to push it back would overwrite the
    /// user's own rules with the set they once started from. When nothing is
    /// bound the tray has nothing to compare and stays quiet, which is right:
    /// there is no file for the rules to have drifted from.
    function _comparableRulesPathFor(route) {
        var path = _rememberedRulesPathFor(route)
        if (path === "") return ""
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.isPathUnderBundledPresets === "function"
                && nrrNativeBridge.isPathUnderBundledPresets(path)) {
            return ""
        }
        return path
    }
    // Focus is exactly what the tray gates on, so a change is published the
    // moment it happens instead of waiting for the heartbeat. (A rebound rules
    // file is published from `onPrefsChanged`, which already exists.)
    onActiveChanged: {
        if (typeof guiPresence !== "undefined" && guiPresence) guiPresence.publish()
    }
    // Focus can move to a child window without `window.active` changing at all,
    // so the application-wide state needs its own publish.
    Connections {
        target: Qt.application
        function onStateChanged() {
            if (typeof guiPresence !== "undefined" && guiPresence) guiPresence.publish()
        }
    }

    // Shared record of answered notifications. See `NotificationLedger`: a
    // notice answered in the tray must stop being shown here, and vice versa.
    property alias noticeLedger: noticeLedger
    NotificationLedger {
        id: noticeLedger
        onDecidedElsewhere: function(noticeId) { window._dropPushNotice(noticeId) }
    }
    // "Import only active rules" choice consumed by every preset-import
    // payload. Tracks the persisted default (`prefs.importOnlyActive`, set in
    // Settings → General); the checkbox in the Load-rule-list window overrides
    // it per-import (assigning to it there just replaces this binding for the
    // session, leaving the saved default untouched).
    property bool importOnlyActiveSession: !(prefs && prefs.importOnlyActive === false)
    property bool bridgeAvailable: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcRetentionSettingsGet === "function"

    // Security alerts raised by the service. Kept on the window rather than
    // inside the Diagnostics section because the integrity banner reads the
    // same list: acknowledging an alert there must take the banner down.
    // Re-seeded from every fresh snapshot (e.g. reconnect).
    readonly property var contextSecurityAlerts: (context.diagnostics || ({})).activeAlerts || []
    property var securityAlertItems: contextSecurityAlerts
    onContextSecurityAlertsChanged: securityAlertItems = contextSecurityAlerts

    // Optimistic transition after a successful Acknowledge: the backend moved
    // the alert Active→Acknowledged (and re-signed the revision rows).
    function markSecurityAlertAcknowledged(alertId) {
        var next = []
        for (var i = 0; i < securityAlertItems.length; i++) {
            var a = securityAlertItems[i]
            if (a && a.alertId === alertId) {
                var copy = {}
                for (var k in a)
                    copy[k] = a[k]
                copy.state = "acknowledged"
                copy.requiresAction = false
                next.push(copy)
            } else {
                next.push(a)
            }
        }
        securityAlertItems = next
    }

    // The service refused to enforce a rule set that reached the database
    // outside the app and fell back to the last verified one. Neutral by
    // design — a restored backup or a moved installation looks the same.
    readonly property bool revisionIntegrityAlertActive: {
        for (var i = 0; i < securityAlertItems.length; i++) {
            var a = securityAlertItems[i]
            if (a && a.state === "active" && a.kind === "untrusted_revision_rejected")
                return true
        }
        return false
    }
    // Traffic-counter controller (poll + model), exposed to the Settings panel
    // as `root.trafficStats`.
    property alias trafficStats: trafficStatsController
    TrafficStatsController {
        id: trafficStatsController
        ownerRoot: window
    }
    // File<->GUI<->service drift detection + file<->service merge logic, moved
    // out of the shell (thin-shell rule). The drift STATE (`_drift*`/`_merge*`)
    // and the drift timers stay on the window; this controller owns the logic.
    // Reached as `root.driftController` from the drift/merge banners and dialogs.
    property alias driftController: driftController
    DriftController {
        id: driftController
        root: window
    }
    // "Apply the routing changes you made while the service was stopped?" flow:
    // offer/apply/discard + localized value labels. The shell keeps the shared
    // park-storage primitives and the `offlinePendingApplied()` signal; this owns
    // the flow. Reached as `root.offlinePendingController`.
    property alias offlinePendingController: offlinePendingController
    OfflinePendingController {
        id: offlinePendingController
        root: window
    }
    // Per-SID route-policy apply handlers (kill-switch family, DoH lockdown,
    // shared-IP, include-subdomains, mode-A coverage, hosts-bypass, browser-history
    // auto-seed, default-route mode) + adapter-binding push/resync. The shell keeps
    // the shared policy helpers (`_buildFullRoutePolicyReq` / `_routePolicyEffective`
    // / `_routingBackendConnected`); this owns the handlers. Reached as
    // `root.routePolicyController` from the Routing/Interfaces/Diagnostics panels.
    property alias routePolicyController: routePolicyController
    RoutePolicyController {
        id: routePolicyController
        root: window
    }
    // Preset-import subsystem: canonical parse, review-decision apply, passthrough
    // reclassify/persist, replace/merge into rulesModel, offline fallback, and the
    // dry-run -> review -> activate flow. The shell keeps the shared review state
    // (`pendingPresetImportState` / `_activeReviewKind` / `_pendingPresetReview`)
    // and the rules-model id helpers. Reached as `root.presetImportController`.
    property alias presetImportController: presetImportController
    PresetImportController {
        id: presetImportController
        root: window
    }
    // Rules review/activation flow: unsaved-changes apply guard, dry-run ->
    // ReviewDiffDialog -> activate for rules-update / reset-to-baseline, retry,
    // and the session elevation broker probes/revoke. The shell keeps the shared
    // review state (`pendingReviewState`/`_activeReviewKind`/`_brokerSessionElevated`
    // /`_guardRulesResume`) and `_buildRulesJsonFromModel`. Reached as
    // `root.reviewFlowController`.
    property alias reviewFlowController: reviewFlowController
    ReviewFlowController {
        id: reviewFlowController
        root: window
    }
    // Interfaces & roles: live adapter refresh + shared-model rebuild, primary/
    // secondary role assign/unassign, the stale-GUID auto-heal + re-confirm path,
    // and the VPN-split conflict helpers. The shell keeps the shared adapter state
    // (`interfacesRowsAll` / `interfacesModel`) the banners and the Interfaces panel
    // read; this owns the logic and pushes bindings via `root.routePolicyController`.
    // Reached as `root.interfacesRolesController` from InterfacesRoutesSection /
    // TopBannerStack.
    property alias interfacesRolesController: interfacesRolesController
    InterfacesRolesController {
        id: interfacesRolesController
        root: window
    }
    // Bound rules-file persistence + close-flow: divergence check, save-before-
    // close handlers (save / save-as / discard-rollback), the "Save to file" chip
    // write + tooltip, content-truthful dirty reconcile, persist-on-apply, and the
    // safe rollback submit. The shell keeps the shared dirty/save-as STATE and the
    // dialog instances. Reached as `root.boundFilesController` from the close-dialog
    // wiring, footer chip, and ReviewFlowController.
    property alias boundFilesController: boundFilesController
    property alias saveBeforeCloseDialog: saveBeforeCloseDialog
    property alias saveAsFileDialog: saveAsFileDialog
    property alias factoryPresetSaveDialog: factoryPresetSaveDialog
    BoundFilesController {
        id: boundFilesController
        root: window
    }
    // Helper for the VPN-onboarding handlers. Writes the confirmed
    // link-provider app set to the service (role "secondary"; an empty array
    // clears the set). The prefs mirror is the offline display fallback; on a
    // service-write failure we append a short warning to the current status line
    // (the status already shows the "will keep working" confirmation). When the
    // bridge is unavailable the correlation id is empty and no callback fires.
    function _writeLinkProviderSet(apps) {
        var req = {
            "role": "secondary",
            "link-provider-apps": apps || []
        }
        var corr = rpcTransport.rpcRouteLinkProviderSet(req)
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (ok) return
            var label = (typeof ipcErrorLabel === "function")
                ? ipcErrorLabel(String(code || "unknown")) : String(code || "")
            statusLine = statusLine + " "
                + tr("vpn-onboarding.service-write-failed",
                    "Could not save to the routing service — will retry on next apply.")
                + (label ? (" (" + label + ")") : "")
        })
    }

    // Live backend status
    // poll. `backendStatus` is seeded once from the cold-start snapshot
    // (`ui_surface.rs:633`) — without this Timer the chip stayed at
    // "disconnected"/"connecting" forever even after the launcher's
    // background `NamedPipeIpcClient` reconnected. We probe via
    // `rpcServiceHealthGet` (cheap: 1s timeout, no side-effects); on
    // success we flip to `connected` and the banner hides. On error
    // we map the wire slug to a banner kind: `transport-disconnected`
    // / `client-shutdown` → "disconnected"; `timeout` / `rpc-timed-out`
    // → "connecting". The launcher's IPC worker keeps retrying in the
    // background regardless, so the next tick eventually catches up.
    // The StatusUpdates subscription is per-pipe-connection: if
    // the GUI cold-started while the service was DOWN the subscribe failed and the
    // launcher spawned no push forwarder, so pushed events (AdaptersChanged,
    // pause/policy) never reached the GUI until a manual refresh (the "adapter list
    // doesn't update on VPN up/down" symptom). Make the subscribe re-callable and
    // re-issue it on every disconnect→reconnect so live pushes resume automatically.
    property bool _statusSubscribed: false
    // Debounce for the health-poll banner: a single `timeout`/`rpc-timed-out`
    // result no longer flips `backendStatus` straight to "connecting" — that
    // used to fire whenever a slow-but-healthy main-channel op (rules.list,
    // snapshot.initial.get, interfaces.refresh) happened to be in flight when
    // the 1 s-budget probe landed behind it. Reset on any success or any
    // non-timeout error (those are real, not queue contention, so the red
    // path below stays immediate for them).
    property int _healthTimeoutStreak: 0
    // One subscribe RPC at a time, and one log line per failing streak: the
    // status poll retries this every few seconds until it sticks, and an
    // unguarded retry would both stack RPCs and fill the startup log with the
    // same warning.
    property bool _subscribeInFlight: false
    property bool _subscribeFailureLogged: false
    function _subscribeStatusUpdates() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcStatusUpdatesSubscribe !== "function")
            return
        if (_subscribeInFlight) return
        _subscribeInFlight = true
        var corr = nrrNativeBridge.rpcStatusUpdatesSubscribe("gui-" + (new Date().getTime()))
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            _subscribeInFlight = false
            _statusSubscribed = ok === true
            if (ok) {
                _subscribeFailureLogged = false
                logProgress(tr("progress.subscribed",
                    "Subscribed to live status updates."), "success")
            } else {
                console.log("status-updates-subscribe failed:", code, msg)
                if (!_subscribeFailureLogged) {
                    _subscribeFailureLogged = true
                    logProgress(tr("progress.subscribe-failed",
                        "Could not subscribe to status updates."), "warn")
                }
            }
        })
    }
    function refreshBackendStatus() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcServiceHealthGet !== "function") {
            return
        }
        // Poll the launcher's elevation-broker state on the same tick. The
        // broker is launcher-local (answers even with the service down), and
        // the poll is the SSOT for the red "revoke administrator approval"
        // affordance: elevation acquired through ANY path (service control,
        // a privileged relay like the external-IP probe, a rules apply)
        // becomes visible within one tick, and a crashed/externally revoked
        // broker clears it again — the one-shot signals below cannot do
        // either on their own.
        if (typeof nrrNativeBridge.rpcBrokerStatus === "function") {
            // The poll doubles as the idle auto-revoke: the launcher retires
            // an elevated session that has sat unused for the configured
            // time (0 = user opted out of auto-revoke).
            var revokeSecs = (prefs && prefs.adminAutoRevokeDisabled === true)
                ? 0
                : Math.max(1, Number((prefs && prefs.adminAutoRevokeMinutes) || 15)) * 60
            var brokerCorr = nrrNativeBridge.rpcBrokerStatus(
                { "auto-revoke-idle-secs": revokeSecs })
            rpcTransport.registerRpcCallback(brokerCorr, function(ok, payload) {
                if (!ok || !payload || payload.elevated === undefined) return
                window._brokerSessionElevated = payload.elevated === true
                if (payload["auto-revoked"] === true) {
                    window.logProgress(
                        tr("status.admin-auto-revoked",
                           "Administrator approval was revoked automatically after sitting unused."),
                        "info")
                }
            })
        }
        var corr = nrrNativeBridge.rpcServiceHealthGet()
        rpcTransport.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (ok) {
                _healthTimeoutStreak = 0
                // A health reply came back over the Qt host's own IPC client,
                // so a real service is answering regardless of which facade the
                // launcher handed us at cold start.
                window.backendLiveServiceConfirmed = true
                var wasDisconnected =
                    (window.backendStatus || {}).kind !== "connected"
                if (wasDisconnected) {
                    window.backendStatus = { kind: "connected" }
                    window.logProgress(
                        tr("progress.reconnected", "Reconnected to the service."),
                        "success")
                    // Re-push the adapter binding if
                    // the service has none but prefs do (e.g. service DB wiped).
                    Qt.callLater(routePolicyController._resyncRouteBindingIfMissing)
                    // The GUI may have cold-started on the mock backend
                    // (service down at launch) with a stale/empty interfaces list.
                    // Refresh it now so the VPN-split banner reflects the live
                    // adapters (and its persisted-ack comparison is accurate)
                    // without needing a manual "Refresh interfaces".
                    Qt.callLater(interfacesRolesController.refreshInterfacesFromService)
                    // The previous per-connection StatusUpdates
                    // subscription died with the old pipe; re-subscribe so live
                    // pushes (adapter list on VPN up/down, pause/policy) resume
                    // without a manual refresh. The pushEvent signal stays connected.
                    _statusSubscribed = false
                    Qt.callLater(_subscribeStatusUpdates)
                    // Bring the service back in line with what the user asked
                    // for BEFORE the panels read it. A service that was
                    // reinstalled or had its state DB wiped answers with its
                    // own defaults, and whoever reads first wins: without this
                    // the panels adopt those defaults, write them into the
                    // display mirror, and the user's settings are gone.
                    Qt.callLater(replayServiceIntentToService)
                    // Re-pull the unresolved-app set so the
                    // "app not enforced" banner reflects the live service state
                    // after a reconnect (state DB may have been wiped/re-applied).
                    Qt.callLater(refreshUnenforcedAppRules)
                    // The suggestions inbox is fetched on demand, so a user
                    // sitting on that section while the service was down kept
                    // staring at an empty list after it came up.
                    Qt.callLater(function() {
                        window.refreshAutoRuleCandidates()
                        window.refreshAutoRuleDismissed()
                    })
                    // Service came back online.
                    // Priority 1: if the user just clicked Start /
                    // Install on the gate dialog, resume the review
                    // flow with the rules on screen — the payload captured at
                    // click time can already be older than the table.
                    // Priority 2: otherwise collect everything parked while
                    // the service was down and ask about it once.
                    if (_pendingReviewAfterConnect) {
                        _pendingReviewAfterConnect = null
                        offlineServiceStartTimer.stop()
                        // The rules half of the backlog is being applied right
                        // here, so neither the marker nor the collector may
                        // raise the same question on top of the review the user
                        // just triggered. Settings are still collected below.
                        _offlineRulesHandledByResume = true
                        _clearPendingApplyPark()
                        Qt.callLater(function() {
                            reviewFlowController._guardApplyRules(function(ok) {
                                // The review has settled either way, so the
                                // collector may speak about rules again.
                                _offlineRulesHandledByResume = false
                                driftController._driftRecheckNow()
                            })
                        })
                    }
                    // Service may have been updated
                    // while we were disconnected. Re-fetch the
                    // negotiate snapshot so the compatibility banner
                    // reflects the (possibly new) service version /
                    // protocol.
                    Qt.callLater(_refreshServiceInfo)
                    // An administrator may have locked (or unlocked) rule
                    // editing while we were disconnected — re-read it so the
                    // Rules section stops offering edits that would bounce.
                    Qt.callLater(refreshRuleEditPermission)
                    // The GUI started (or ran)
                    // while the service was down → it's showing mock / stale
                    // cold-start data. Now that the live service is reachable,
                    // pull the real active rules so the table reflects what
                    // the service actually enforces (no relaunch needed).
                    // Guarded so a user's in-progress local edits while
                    // offline aren't clobbered — drift detection flags any
                    // divergence instead.
                    // `_offlineRulesPendingPush` guards an offline preset
                    // import that is parked but not yet pushed: refetching
                    // here would clobber those rules with the service's
                    // (possibly empty) revision before the post-connect
                    // backlog dialog can offer to apply them. Take the
                    // non-clobber drift path instead so the imported rows
                    // stay visible.
                    if (!unsavedChangesRegistry["rules"]
                            && !_offlineRulesPendingPush
                            && typeof _refreshRulesFromService === "function") {
                        Qt.callLater(function() {
                            _refreshRulesFromService({ silent: true })
                        })
                    } else if (typeof driftController._driftRefreshServiceBaselineFromService === "function") {
                        // Unsaved local edits — don't clobber them, but still
                        // re-seed the drift SERVICE baseline from the live
                        // revision so divergence is measured against the real
                        // service, not the stale cold-start / mock snapshot.
                        Qt.callLater(driftController._driftRefreshServiceBaselineFromService)
                    }
                    // The service is back: collect the rules AND the routing
                    // settings parked while it was stopped, and ask about them
                    // in one dialog. Deferred behind the rules hydrate queued
                    // above so the diff is taken against a settled table.
                    _offlineBacklogCollectTimer.restart()
                    // The service just came
                    // (back) online. Prime a drift compare shortly after the
                    // reconnect hydrate/snapshot lands (queued above) and enter
                    // the bounded fast-retry phase so a stale amber banner clears
                    // in ~seconds rather than waiting for the 30 s poll.
                    _driftConnectRetryCount = 0
                    _driftConnectFastRetryTimer.stop()
                    _driftConnectComparePrimeTimer.restart()
                }
                // Demo-rules seeding is opt-in: the user triggers it
                // explicitly from RulesSection's "Load demo rules"
                // button via `loadDemoRules()`. We no longer auto-open
                // the review dialog on every connect.
                // Cold start reads backendStatus as
                // "connected" already, so `wasDisconnected` is false above; still
                // offer any intents parked in a previous session, exactly once.
                if (!_offlinePendingColdChecked) {
                    _offlinePendingColdChecked = true
                    _offlineBacklogCollectTimer.restart()
                }
                return
            }
            var kind = "disconnected"
            var code = String(errorCode || "")
            if (code === "timeout" || code === "rpc-timed-out") {
                // A lone timeout is as likely to be queue contention on a
                // perfectly healthy pipe (see `_healthTimeoutStreak` above)
                // as a real outage. Require two IN A ROW before painting the
                // banner; the poll cadence stays whatever the current
                // (unpainted) `backendStatus.kind` implies, so a streak that
                // starts from "connected" re-polls at the relaxed 3 s
                // interval and confirms within ~3-6 s, while a streak that
                // starts once already disconnected keeps the tight 1 s
                // interval.
                _healthTimeoutStreak += 1
                if (_healthTimeoutStreak < 2) {
                    return
                }
                kind = "connecting"
            } else {
                _healthTimeoutStreak = 0
            }
            var prevKind = (window.backendStatus || {}).kind
            window.backendStatus = {
                kind: kind,
                lastError: (typeof window.ipcErrorLabel === "function")
                    ? window.ipcErrorLabel(code) : code
            }
            // Log only on a real transition (the poll fires every 3 s).
            if (kind !== prevKind) {
                if (kind === "connecting") {
                    window.logProgress(
                        tr("progress.connecting", "Connecting to the service…"),
                        "progress")
                } else {
                    window.logProgress(
                        tr("progress.disconnected", "Lost connection to the service."),
                        "warn")
                }
            }
        })
    }
    // Append a timestamped lifecycle event to
    // the live startup / connection progress log. `kind` ∈
    // info|progress|success|warn|error colours the dot. Newest first;
    // capped to `startupLogCap`.
    function logProgress(message, kind) {
        var msg = String(message || "")
        if (msg === "") return
        var d = new Date()
        var hh = ("0" + d.getHours()).slice(-2)
        var mm = ("0" + d.getMinutes()).slice(-2)
        var ss = ("0" + d.getSeconds()).slice(-2)
        startupLogModel.insert(0, { ts: hh + ":" + mm + ":" + ss, message: msg, kind: String(kind || "info") })
        while (startupLogModel.count > startupLogCap) {
            startupLogModel.remove(startupLogModel.count - 1)
        }
        lastProgressMessage = msg
        lastProgressKind = String(kind || "info")
    }
    function progressKindColor(kind) {
        switch (String(kind || "")) {
            case "success":  return "#2ecc71"
            case "warn":     return uiTheme.colorWarning
            case "error":    return uiTheme.colorDanger
            case "progress": return uiTheme.colorAccent
            default:         return uiTheme.colorTextMuted
        }
    }
    ListModel { id: startupLogModel }

    Timer {
        id: backendStatusPoll
        // Adaptive cadence: relaxed while connected, tight while the red
        // "service unavailable" banner is up. Every failed poll also wakes
        // the IPC reconnect worker, so after a service (re)start the banner
        // clears in about one tight tick instead of riding out the full
        // backoff + 3 s poll (the old worst case approached eight seconds).
        // A failed connect attempt is a cheap named-pipe open, so the tight
        // cadence costs nothing meaningful while the service stays down.
        interval: backendStatus && backendStatus.kind === "connected" ? 3000 : 1000
        repeat: true
        running: true
        triggeredOnStart: true
        onTriggered: {
            refreshBackendStatus()
            // Re-arm the live-status subscription whenever we are connected
            // without one. Hanging this on the disconnected→connected edge
            // alone lost the subscription for a whole session: the cold-start
            // subscribe fails while the service is still down, and a GUI that
            // fell back to the mock backend reports "connected" from the
            // start, so the edge never arrives and nothing retries.
            if (((backendStatus || {}).kind) === "connected" && !_statusSubscribed) {
                _subscribeStatusUpdates()
            }
        }
    }

    // Drift detection 30 s poll. Gated on `connected`
    // inside `_driftRecheck` so a disconnected GUI doesn't spam the
    // hash RPC; resumes naturally when connectivity returns. The
    // first tick fires 30 s after Component.onCompleted — cold-start
    // capture already ran inline via `_driftCaptureServiceBaseline`.
    Timer {
        id: driftDetectionPoll
        interval: 30000
        repeat: true
        running: true
        triggeredOnStart: false
        onTriggered: driftController._driftRecheck()
    }

    // Debounced re-pull of the connect-time snapshot after an
    // `adapters-changed` push. An adapter flap (e.g. the VPN dropping and
    // reconnecting) can fire several pushes in a row; restart on every
    // push and only fetch once things settle so the service isn't spammed
    // with `snapshot.initial.get` calls. This is the only path that keeps
    // `routingState.killSwitchBlockAllArmed` (and the rest of the snapshot
    // mirror) honest after the topology change that caused the service to
    // arm/disarm block-all — the interfaces refresh alone does not touch it.
    Timer {
        id: _adaptersChangedSnapshotRefreshTimer
        interval: 1000
        repeat: false
        running: false
        onTriggered: refreshUnenforcedAppRules()
    }

    // Settle window + re-read for the "service applies nothing" notice. Runs
    // ONLY while the raw state is asserted, so a healthy machine pays no extra
    // RPC: the first snapshot read shows a bound secondary and this never
    // starts. Three ticks (45 s) before the banner appears — longer than one
    // service reconcile tick (30 s) plus the connect-time binding re-push, so
    // a service that is merely still coming up stays quiet; short enough that
    // a genuinely idle policy is reported within the first minute rather than
    // going unnoticed for ten. Each tick also re-reads the snapshot so the
    // banner clears within one tick of a policy landing (an adapter coming up
    // clears it sooner still, via `_adaptersChangedSnapshotRefreshTimer`).
    Timer {
        id: _policyIdleWatchTimer
        interval: 15000
        repeat: true
        running: window.servicePolicyIdle
        onTriggered: {
            window._policyIdleTicks += 1
            if (window._policyIdleTicks >= 3) window._policyIdleConfirmed = true
            window.refreshUnenforcedAppRules()
        }
    }

    // Fast drift convergence after a
    // (re)connect. The 30 s `driftDetectionPoll` alone can leave the
    // amber "rules differ" banner up for up to ~60 s after the service
    // comes back (first tick at t=30 s, sometimes a second at t=60 s to
    // fold the freshly-hydrated service leg). On a connect transition
    // (`refreshBackendStatus`) we prime a compare ~1.5 s later — enough
    // for the reconnect hydrate / snapshot to land, ordered after the
    // `_refreshRulesFromService` / `_driftRefreshServiceBaselineFromService`
    // Qt.callLater() chain queued alongside it — then fast-retry every
    // 5 s while drift is still asserted (or the service leg is not yet
    // hashed), bounded, before ceding back to the 30 s cadence.
    // Post-connect backlog collect, deferred so the reconnect hydrate has
    // settled first: the rules half diffs the TABLE against the service, and a
    // table caught mid-repopulate would report a difference that does not
    // exist. `_startOfflineBacklogCollect` re-arms this timer while the model
    // is still filling.
    Timer {
        id: _offlineBacklogCollectTimer
        interval: 2500
        repeat: false
        running: false
        onTriggered: _startOfflineBacklogCollect()
    }

    Timer {
        id: _driftConnectComparePrimeTimer
        interval: 1500
        repeat: false
        running: false
        onTriggered: {
            _driftConnectRetryCount = 0
            driftController._driftRecheck()
            _driftConnectFastRetryTimer.restart()
        }
    }
    Timer {
        id: _driftConnectFastRetryTimer
        interval: 5000
        repeat: true
        running: false
        onTriggered: {
            // Retry while the banner is up OR the service leg hasn't
            // resolved yet (empty hash = RPC still in flight / absent),
            // capped to `_driftConnectRetryMax` attempts; then the 30 s
            // poll resumes ownership.
            var serviceLegMissing =
                _driftServiceHashPrimary === "" || _driftServiceHashSecondary === ""
            if ((!_driftDetected && !serviceLegMissing)
                    || _driftConnectRetryCount >= _driftConnectRetryMax) {
                stop()
                return
            }
            _driftConnectRetryCount += 1
            driftController._driftRecheck()
        }
    }

    // Push event dispatcher. Server-pushed
    // events arrive after `rpcStatusUpdatesSubscribe`. The bridge
    // emits `pushEvent(subscriptionId, eventId, event)` on the GUI
    // thread; we route by `event.type`. Unknown types are logged but
    // not fatal — the wire protocol is forward-compatible.
    function handlePushEvent(subscriptionId, eventId, event) {
        var type = event && event.type ? String(event.type) : ""
        switch (type) {
            case "routing-pause-state-changed":
                updateRoutingState({
                    routingPaused: !!event.paused,
                    routingPausedAt: event.paused ? new Date().toISOString()
                                                  : "",
                    routingPauseReason: ""
                })
                break
            case "apply-failure-policy-changed":
                updateRoutingState({ applyFailurePolicy: String(event.policy || "") })
                break
            case "autostart-state-changed":
                updateRoutingState({
                    autostartEnabled: !!event.enabled,
                    autostartLastKnownState: String(event["last-known-state"] || "absent"),
                    autostartBinaryMatches: true,
                    autostartOverrideValue: ""
                })
                break
            case "retention-settings-changed":
                // Settings changed server-side — re-fetch via bridge.
                if (bridgeAvailable) {
                    var corr = nrrNativeBridge.rpcRetentionSettingsGet()
                    rpcTransport.registerRpcCallback(corr, function(ok, p) {
                        if (ok && p) {
                            updateRoutingState({
                                retentionSettings: {
                                    supersededDays: Number(p["superseded-days"] || 30),
                                    supersededCountCap: Number(p["superseded-count-cap"] || 100),
                                    rejectedDays: Number(p["rejected-days"] || 7),
                                    rolledbackDays: Number(p["rolledback-days"] || 14),
                                    rolledbackCountCap: Number(p["rolledback-count-cap"] || 20),
                                    pinLkg: !!p["pin-lkg"],
                                    lastCleanupAt: p["last-cleanup-at"] || ""
                                }
                            })
                        }
                    })
                }
                break
            case "revision-status-changed":
                console.log("revision-status-changed:",
                    event["revision-id"], "->", event.status)
                break
            case "mutation-progress":
                // Service-emitted lifecycle phase
                // for one in-flight mutation. `correlation-id`
                // matches the same id the GUI passed to
                // `rpcMutationSubmit`; the MutationsModel keys all
                // state on it.
                var mpCorr = String(event["correlation-id"] || "")
                var mpKind = String(event["mutation-kind"] || "")
                var mpPhase = String(event.phase || "")
                var mpErr = String(event["error-code"] || "")
                mutationsModel.applyProgress(mpCorr, mpKind, mpPhase, mpErr)
                // Drive the transient toast stack
                // off the same wire event. `started` creates a
                // running toast; `completed` / `failed` flip it to
                // the terminal phase. The stack handles eviction +
                // hover-pause-auto-dismiss internally.
                if (mpPhase === "started") {
                    _pushOperationToast(mpCorr, mpKind)
                } else if (mpPhase === "completed" || mpPhase === "failed") {
                    operationToastStack.model.settle(mpCorr, mpPhase, mpErr)
                }
                // Auto-rules land through the ordinary mutation path (the tray
                // accepted a suggestion, or "apply automatically" authored one),
                // so this push is the GUI's only notice that its rule set grew
                // without the user touching this window. The correlation-id
                // prefix is stamped by the service's auto-rule authoring.
                if (mpPhase === "completed"
                        && mpCorr.indexOf("auto-rules-") === 0) {
                    boundFilesController.handleAutoRulesAuthored()
                }
                break
            case "auto-rule-candidates-changed":
                // The tray asks the question while this window is closed, and
                // its notice retires itself. So the window keeps the count and
                // a way in — otherwise an unanswered offer is unreachable until
                // the service happens to announce it again.
                autoRuleCandidatesPending = Number(event["pending-count"] || 0)
                console.log("push: auto-rule candidates pending",
                    autoRuleCandidatesPending)
                if (autoRuleCandidatesPending > 0) {
                    refreshAutoRuleCandidates()
                    // Keyed on the push, not on a constant: dismissing writes
                    // to the ledger, and one fixed id would retire the banner
                    // for the life of the install. Only one is on screen at a
                    // time — the newer count supersedes the older.
                    _dropPushNotice(_autoRuleNoticeId)
                    _autoRuleNoticeId = "auto-rule-candidates:" + String(eventId || "")
                    _addPushNotice({
                        "id": _autoRuleNoticeId,
                        "severity": "info",
                        "dismissible": true,
                        // The inbox keeps everything, so this is a "something
                        // arrived" stripe, not a question: it retires itself
                        // and the list stays reachable from the Rules submenu.
                        "kind": "suggestions-changed",
                        "autoDismissMs": 5000,
                        "muteKind": "suggestions-changed",
                        "title": tr("notifications.auto-rule-candidates.title",
                            "Addresses waiting to be added"),
                        "body": tr("notifications.auto-rule-candidates.body",
                            "The service found {count} addresses the sites you routed need.")
                            .replace("{count}", String(autoRuleCandidatesPending)),
                        "actionKey": "open-auto-rule-suggestions",
                        "actionText": tr("rules.suggestions.open", "Review")
                    })
                }
                break
            case "secondary-external-address-observed":
                _onSecondaryExternalAddress(event, eventId)
                break
            case "block-notice-raised":
                _onBlockNoticeRaised(event, eventId)
                break
            case "adapters-changed":
                // The service's adapter monitor detected a
                // topology change (e.g. the secondary adapter went up or down). Re-pull the
                // interfaces so the page stops showing a stale "available" without
                // the user hitting Refresh. Qt.callLater coalesces a burst of
                // adapter events into a single fetch.
                if (bridgeAvailable) Qt.callLater(interfacesRolesController.refreshInterfacesFromService)
                // Also re-pull the connect-time snapshot so
                // `routingState.killSwitchBlockAllArmed` (and the rest of the
                // snapshot mirror) tracks the service's live block-all posture
                // once the topology change resolves — otherwise the amber
                // "kill-switch block-all active" banner can outlive the
                // condition that raised it. Debounced: a flapping adapter can
                // fire several of these pushes back to back.
                if (bridgeAvailable) _adaptersChangedSnapshotRefreshTimer.restart()
                // The connect-time re-push of the adapter binding fails while
                // the bound adapter is still absent, and its backoff spans
                // seconds while a VPN can come up minutes later. This is the
                // moment that changes, so retry here; a no-op unless the
                // service is still without our binding.
                if (bridgeAvailable)
                    Qt.callLater(routePolicyController.resyncRouteBindingOnAdapterChange)
                break
            default:
                console.log("push: unknown event type", type)
        }
    }

    /// The service worked out which address the outside world sees behind the
    /// additional route — the link's own client usually cannot say. The tray
    /// shows this too; both key the notice on the push's own id, so the two
    /// surfaces never double up on one event while every (re)connect still
    /// announces itself. Keying on the address alone silenced the notice
    /// forever after the first dismissal.
    function _onSecondaryExternalAddress(event, eventId) {
        var address = String(event["external-address"] || "")
        if (address === "") return
        var adapter = String(event["adapter-name"] || "")
        // Bold only the address, not the sentence around it — the markup
        // lives here, not in the translated string, so the locale text stays
        // plain prose. Same trick as the tray's own notice for this event.
        var body = tr("tray.external-address.body",
                "External address of the additional route: {address}")
            .replace("{address}", "<b>" + address + "</b>")
        if (adapter !== "") {
            body = body + " " + tr("tray.external-address.adapter", "Adapter: {name}")
                .replace("{name}", adapter)
        }
        _addPushNotice({
            "id": "secondary-external-address:" + String(eventId || "") + ":" + address,
            "severity": "info",
            "dismissible": true,
            // The id restarts with the service; only a recent answer suppresses.
            "refractoryMs": 600000,
            "title": tr("tray.external-address.title", "Additional route connected"),
            "body": body,
            "bodyRichText": true
        })
    }

    /// One reason slug -> the sentence explaining it. Mirrors the tray's own
    /// wording for the same event.
    function _blockNoticeReasonText(reason) {
        switch (String(reason || "")) {
            case "route-unavailable":
                return tr("notifications.block-notice.reason.route-unavailable",
                    "The route this connection needed was unavailable.")
            case "not-covered-by-rules":
                return tr("notifications.block-notice.reason.not-covered-by-rules",
                    "No rule covers this connection, so the default action blocked it.")
            case "blocked-by-rule":
                return tr("notifications.block-notice.reason.blocked-by-rule",
                    "A rule blocks this connection.")
            case "unattributed":
                return tr("notifications.block-notice.reason.unattributed",
                    "NetRuleRouter blocked this connection, but could not identify which filter did it.")
            default:
                return tr("notifications.block-notice.reason.unknown",
                    "This connection was blocked.")
        }
    }

    /// A block episode survived muting — record it in the notification
    /// centre. Keyed on the push's own `eventId`, NOT on the destination:
    /// the destination repeats across unrelated episodes (a site blocked
    /// today and again next week), and a fixed per-destination id would let
    /// the first dismissal bury every later episode for that host under the
    /// same permanently-answered ledger entry.
    function _onBlockNoticeRaised(event, eventId) {
        var destination = String(event.destination || "")
        if (destination === "" || String(eventId || "") === "") return
        if (!noticeKindEnabled("block-notice")) return
        var app = String(event.app || "")
        var attempts = Number(event.attempts || 0)
        var destDisplay = prefs.hideBlockNoticeAddresses === true
            ? tr("notifications.block-notice.destination-hidden", "a hidden destination")
            : destination
        var appDisplay = app !== "" ? app
            : tr("notifications.block-notice.app-unknown", "unknown application")
        var body = tr("notifications.block-notice.body",
                "{reason} Destination: {destination}. Application: {app}. Attempts: {attempts}.")
            .replace("{reason}", _blockNoticeReasonText(event.reason))
            .replace("{destination}", destDisplay)
            .replace("{app}", appDisplay)
            .replace("{attempts}", String(attempts))
        _addPushNotice({
            "id": "block-notice:" + String(eventId),
            "severity": "warning",
            "dismissible": true,
            "kind": "block-notice",
            "muteKind": "block-notice",
            "title": tr("notifications.block-notice.title", "Connection blocked"),
            "body": body
        })
    }

    function setRetentionSettings(values) {
        var merged = Object.assign({}, routingState.retentionSettings, values || {})
        // Optimistic local update — UI stays responsive while the
        // round-trip resolves.
        updateRoutingState({ retentionSettings: merged })
        if (!bridgeAvailable) return
        var corr = nrrNativeBridge.rpcRetentionSettingsSet({
            "superseded-days": merged.supersededDays,
            "superseded-count-cap": merged.supersededCountCap,
            "rejected-days": merged.rejectedDays,
            "rolledback-days": merged.rolledbackDays,
            "rolledback-count-cap": merged.rolledbackCountCap,
            "pin-lkg": merged.pinLkg
        })
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("retention-set failed:", code, msg)
        })
    }
    function setApplyFailurePolicy(slug) {
        if (slug !== "all-or-nothing" && slug !== "best-effort" && slug !== "pre-flight-then-all-or-nothing") return
        updateRoutingState({ applyFailurePolicy: slug })
        if (!bridgeAvailable) return
        var corr = nrrNativeBridge.rpcApplyFailurePolicySet(slug)
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("apply-failure-policy-set failed:", code, msg)
        })
    }
    function setRoutingPauseEnabled(paused, reason) {
        updateRoutingState({
            routingPaused: !!paused,
            routingPausedAt: paused ? new Date().toISOString() : "",
            routingPauseReason: paused ? (reason || "") : ""
        })
        if (!bridgeAvailable) return
        var corr = nrrNativeBridge.rpcRoutingPauseToggle(!!paused, reason || "")
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("routing-pause-toggle failed:", code, msg)
            // On success the server returns authoritative paused_at;
            // A later change will replace the synthetic timestamp.
        })
    }
    function setAutostartEnabled(enabled) {
        updateRoutingState({
            autostartEnabled: !!enabled,
            autostartLastKnownState: enabled ? "enabled" : "disabled",
            autostartBinaryMatches: true,
            autostartOverrideValue: ""
        })
        if (!bridgeAvailable) return
        var corr = nrrNativeBridge.rpcAutostartToggle(!!enabled)
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("autostart-toggle failed:", code, msg)
        })
    }
    function refreshStorageUsage() {
        // Optimistic "scanning" state so the spinner shows immediately.
        updateRoutingState({ storageUsageScanState: "scanning" })
        if (!bridgeAvailable) {
            // Fallback when running without a bridge (preview / dev): keep
            // the synthetic numbers so the panel renders something.
            var sample = {
                stateDb: 4 * 1024 * 1024 + 712 * 1024,
                cacheDb: 9 * 1024 * 1024 + 220 * 1024,
                operationalLogs: 12 * 1024 * 1024 + 480 * 1024,
                auditLogs: 3 * 1024 * 1024 + 96 * 1024,
                total: 0
            }
            sample.total = sample.stateDb + sample.cacheDb + sample.operationalLogs + sample.auditLogs
            updateRoutingState({
                storageUsageBytes: sample,
                storageUsageScanState: "ready",
                storageUsageScannedAt: new Date().toISOString()
            })
            return
        }
        var corr = nrrNativeBridge.rpcStorageUsageGet()
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                updateRoutingState({ storageUsageScanState: "error" })
                console.log("storage-usage-get failed:", code, msg)
                return
            }
            var bytes = {
                stateDb: Number(p["state-db-bytes"] || 0),
                cacheDb: Number(p["cache-db-bytes"] || 0),
                operationalLogs: Number(p["operational-logs-bytes"] || 0),
                auditLogs: Number(p["audit-logs-bytes"] || 0),
                total: Number(p["total-bytes"] || 0)
            }
            updateRoutingState({
                storageUsageBytes: bytes,
                storageUsageScanState: "ready",
                storageUsageScannedAt: new Date().toISOString()
            })
        })
    }
    function routingStatusKey() {
        if (routingState.routingPaused) return "paused"
        if (!routingState.trayActive) return "no-tray"
        // "active" requires (a) a real service
        // connection and (b) a non-empty rule book. Cold-start with
        // mock/preview backend (service not installed or not yet
        // running) populates rulesModel with preview rows, so the
        // rule-count check alone isn't enough — also gate on
        // `backendStatus.kind === "connected"` so the chip honestly
        // reflects whether enforcement is actually happening.
        var bk = (backendStatus || {}).kind || ""
        if (bk !== "connected") return "disconnected"
        if (!rulesModel || rulesModel.count === 0) return "no-rules"
        return "active"
    }

    function systemLanguage() { return resolveLanguageId(Qt.locale().name) }
    // Anchor against Main.qml — without `Qt.resolvedUrl`, relative
    // paths get re-resolved by the consumer (e.g. ThemedButton in
    // components/) and point to apps/assets/... which doesn't exist.
    function uiIconSource(name) { return Qt.resolvedUrl("../../../assets/icons/" + (highContrastIcons ? "ui-hc/" : "ui/") + name + ".svg") }
    function sectionIconSource(sectionId) {
        if (sectionId === "interfaces-routes") return Qt.resolvedUrl("../../../assets/icons/" + (highContrastIcons ? "status-hc/" : "status/") + "interface-ok.svg")
        if (sectionId === "rules") return uiIconSource("search")
        if (sectionId === "diagnostics") return uiIconSource("diagnostics")
        if (sectionId === "logs") return uiIconSource("logs")
        if (sectionId === "settings") return uiIconSource("settings")
        return appIconSmallSource
    }
    function routeIconSource(routeId) {
        // "block" ships only as an SVG (a drop has no adapter PNG set); render
        // it as SVG in both normal and high-contrast modes.
        if (routeId === "block") return Qt.resolvedUrl("../../../assets/icons/status" + (highContrastIcons ? "-hc" : "") + "/route-block.svg")
        if (highContrastIcons) return Qt.resolvedUrl("../../../assets/icons/status-hc/" + (routeId === "secondary" ? "route-secondary" : "route-primary") + ".svg")
        return Qt.resolvedUrl("../../../assets/icons/status/" + (routeId === "secondary" ? "route-secondary-20.png" : "route-primary-20.png"))
    }
    // Leading icon for a rule row, keyed on the rule-type slug. Uses the
    // gradient `rule-type-*` set (auto-swaps to `ui-hc/` under high contrast
    // via `uiIconSource`). Application rules map to the Windows platform icon
    // because only Windows app rules are active on this host.
    function ruleLeadingIconSource(ruleType) {
        switch (String(ruleType || "")) {
        case "domain":
        case "suffix-domain":
        case "exact-fqdn":
            return uiIconSource("rule-type-domains")
        case "zone":
            return uiIconSource("rule-type-zones")
        case "exact-ip":
        case "exact-ipv4":
            return uiIconSource("rule-type-ip")
        case "application":
            return uiIconSource("rule-type-windows")
        default:
            return uiIconSource("search")
        }
    }

    function centerMainWindow() {
        if (!window.Screen) return
        var x0 = window.Screen.virtualX || 0
        var y0 = window.Screen.virtualY || 0
        var w = window.Screen.desktopAvailableWidth || window.Screen.width
        var h = window.Screen.desktopAvailableHeight || window.Screen.height
        window.x = x0 + Math.max(0, Math.round((w - window.width) / 2))
        window.y = y0 + Math.max(0, Math.round((h - window.height) / 2))
    }

    function centerChildWindow(child) {
        child.x = window.x + Math.round((window.width - child.width) / 2)
        child.y = window.y + Math.round((window.height - child.height) / 2)
    }

    function openChildWindow(child) {
        centerChildWindow(child)
        child.show()
        child.raise()
        child.requestActivate()
    }


    // SINGLE SOURCE OF TRUTH for child-window plumbing. Register a NEW child
    // window HERE (one row) so it is wired uniformly:
    //   overlay  - the main-window Esc closes it (activeOverlay / closeActiveOverlay);
    //              order matters (activeOverlay returns the FIRST visible one).
    //   titleBar - re-apply the DWM dark title bar on a live theme switch
    //              (native `Window` only; a Controls `Dialog` renders inside the
    //              main window and has no native title bar). Cold-open centering +
    //              title bar are still applied per-component via `onVisibleChanged`.
    function _childWindowRegistry() {
        return [
            { win: ruleDialog,               overlay: true,  titleBar: false },
            { win: loadListWindow,           overlay: true,  titleBar: true },
            { win: licenseWindow,            overlay: true,  titleBar: true },
            { win: aboutWindow,              overlay: true,  titleBar: true },
            { win: firstRunWindow,           overlay: true,  titleBar: true },
            { win: eulaAgreementWindow,      overlay: false, titleBar: true },
            { win: appGroupRoutingDialog,    overlay: false, titleBar: true },
            { win: firstLaunchInstallDialog, overlay: false, titleBar: true },
            { win: vpnOnboardingDialog,      overlay: false, titleBar: true }
        ]
    }
    function activeOverlay() {
        var reg = _childWindowRegistry()
        for (var i = 0; i < reg.length; i += 1)
            if (reg[i].overlay && reg[i].win && reg[i].win.visible) return reg[i].win
        return null
    }

    function closeActiveOverlay() {
        var overlay = activeOverlay()
        if (!overlay) return false
        overlay.close()
        return true
    }

    function applyActiveOverlay() {
        if (ruleDialog.visible) {
            saveRule()
            ruleDialog.close()
            return true
        }
        if (firstRunWindow.visible) {
            updatePrefs({ firstRunCompleted: true })
            firstRunWindow.close()
            statusLine = (context.firstRun || {}).completionNotice || tr("status.setup-completed", "Setup completed")
            return true
        }
        return false
    }

    function loadContext() {
        var args = Qt.application.arguments
        for (var i = 0; i < args.length; i += 1) {
            if (args[i].indexOf("--nrr-auto-close-ms=") === 0) autoCloseMs = Number(args[i].slice("--nrr-auto-close-ms=".length))
        }
        if (typeof nrrLaunchContext !== "undefined" && nrrLaunchContext) {
            context = nrrLaunchContext
        } else {
            var url = ""
            for (var j = 0; j < args.length; j += 1) {
                if (args[j].indexOf("--nrr-context-file=") === 0) url = args[j].slice("--nrr-context-file=".length)
            }
            if (url === "" && typeof nrrContextFileUrl !== "undefined" && nrrContextFileUrl) url = nrrContextFileUrl
            if (url === "") return
            var xhr = new XMLHttpRequest()
            xhr.open("GET", url, false)
            xhr.send()
            if (!(xhr.status === 0 || xhr.status === 200)) return
            context = JSON.parse(xhr.responseText)
        }
        localeCatalog = context.localeCatalog || {}
        availableLanguages = context.availableLanguages || []
        platformProfile = context.platformProfile || platformProfile
        prefs = normalizePrefs(Object.assign({}, prefs, context.preferences || {}))
        currentLanguage = prefs.language
        backendStatus = context.backendStatus || { kind: "connected" }
        backendServiceBacked = context.backendServiceBacked !== false
        // Cold-start loads the persisted theme/font — force the theme
        // tokens to recompute from the freshly-bound prefs (uiRevision no
        // longer drives the theme; see the themeRevision split).
        themeRevision += 1
        uiRevision += 1
        section = context.entrySection || prefs.lastOpenedSection || "interfaces-routes"
        var localeDiagnostics = context.localeDiagnostics || {}
        if (Number(localeDiagnostics.rejected || 0) > 0) {
            statusLine = tr("status.locale-files-rejected", "Some locale files were rejected. See logs for details.")
        } else if (Number(localeDiagnostics.acceptedWithWarnings || 0) > 0) {
            statusLine = tr("status.locale-files-warning", "Some locale files were loaded with warnings.")
        }

        interfacesRowsAll = ((context.interfaces || {}).rows) || []
        interfacesRolesController.rebuildInterfacesModel()
        interfacesRolesController.loadExternalIpCache()
        Pure.clearModel(behaviorModeModel)
        var modes = ((context.interfaces || {}).supportedBehaviorModes) || []
        for (var m = 0; m < modes.length; m += 1) behaviorModeModel.append(modes[m])
        Pure.clearModel(ruleTypesModel)
        var types = ((context.rules || {}).supportedRuleTypes) || []
        for (var t = 0; t < types.length; t += 1) ruleTypesModel.append(types[t])
        Pure.clearModel(rulesModel)
        // When the launcher intended the real service
        // (BackendChoice::Ipc) but the service was stopped/unreachable, it
        // falls back to the MockBackendFacade whose cold-start snapshot carries
        // DEMO rules, while stamping a non-"connected" backendStatus (e.g.
        // "service-stopped"). Seeding those demo rows made the Rules table
        // masquerade demo data as the user's real (not-yet-loaded) rules —
        // momentary "my rules are gone" panic. Only seed the snapshot rows when
        // the backend is genuinely connected: a real service, OR an explicit
        // mock/preview build (BackendChoice::Mock/PreviewLocal both emit
        // kind:"connected"). In the degraded-Ipc fallback leave the model EMPTY
        // — RulesSection paints a "service not running" empty-state, and the 3 s
        // backendStatusPoll → refreshBackendStatus() → _refreshRulesFromService
        // hydrates the real per-SID rules the moment the service connects.
        var rulesRows = (((backendStatus || {}).kind) === "connected")
            ? (((context.rules || {}).rows) || [])
            : []
        // Normalise rule ids to the canonical R-NNNN form on load
        // so downstream duplicate-checks and nextFreeRuleId()
        // can rely on a single shape regardless of where the row
        // originated (mock backend / preset import / etc.).
        for (var k = 0; k < rulesRows.length; k += 1) {
            var row = rulesRows[k]
            if (row && row.id) row.id = Rules.canonicalRuleId(row.id)
            // Boundary conversion (inbound): snapshot rows carry ACE on
            // host-like rule types; decode for display.
            if (row && Rules.isHostlikeRuleType(row.ruleType)) {
                row.matchValue = _unicodeDecodeHost(row.matchValue)
            }
            if (row) row.aceMatchValue = _aceLowerForSearch(row.matchValue)
            // Seed the provenance roles as STRINGS even though the cold-start
            // snapshot never carries an origin: the first append is what fixes
            // each role's type, and a service refresh later in the session
            // appends rows that DO carry one.
            if (row) {
                row.originReason = String(row.originReason || "")
                row.originAnchor = String(row.originAnchor || "")
                row.originAdded = String(row.originAdded || "")
            }
            rulesModel.append(row)
        }
        // The snapshot numbers the two routes
        // independently, so primary+secondary can both carry R-0000; make
        // ids unique across the merged table.
        _renumberRuleIdsSequential()
        // Overlay comments from the sidecar onto the
        // freshly-bound rulesModel. Async; the row.comment fields stay
        // at whatever shape the snapshot delivered until the callback
        // fires (typically a few ms later). GC of orphan signatures
        // runs in parallel — both ops are independent.
        _overlaySidecarCommentsOntoRulesModel()
        _gcSidecarCommentOrphans()
        // Capture the service-baseline hash for
        // drift detection. Inline because rulesModel here mirrors
        // what the service holds; subsequent edits diverge the GUI
        // leg from this baseline.
        //
        // But ONLY when offline. When
        // connected, `_refreshRulesFromService({silent:true})` runs
        // right after this (Component.onCompleted) and re-binds the
        // model from the LIVE per-SID active revision, then captures
        // the baseline authoritatively. The launcher's context
        // snapshot can lag that live revision (it is written before
        // the IPC read-through resolves), so capturing here too races
        // with the live capture: whichever async `canonical-rules-hash`
        // callback resolves last wins. When the stale context capture
        // wins, the "service" leg pins to the snapshot while the GUI
        // leg tracks the live model — a permanent false app↔service
        // drift banner that the 30 s poll never clears (it refreshes
        // only the file+gui legs). Skip it when connected; the live
        // refresh is the single source of truth.
        if (((backendStatus || {}).kind) !== "connected") {
            driftController._driftCaptureServiceBaseline()
        }
        // Same idea for the unsaved-
        // changes baseline. The cold-start model mirrors the service, so this
        // is the "clean" signature; edits are dirty only when they diverge.
        _captureRulesDirtyBaseline()
        Pure.clearModel(logsModel)
        var logsRows = ((context.logs || {}).entries) || []
        for (var l = 0; l < logsRows.length; l += 1) logsModel.append(logsRows[l])
        Pure.clearModel(wizardStepsModel)
        var stepRows = ((context.firstRun || {}).steps) || []
        for (var s = 0; s < stepRows.length; s += 1) wizardStepsModel.append(stepRows[s])
        Pure.clearModel(wizardScenariosModel)
        var scenarioRows = ((context.firstRun || {}).availableScenarios) || []
        for (var c = 0; c < scenarioRows.length; c += 1) wizardScenariosModel.append(scenarioRows[c])
        statusLine = (context.interfaces || {}).previewNotice || ""
    }

    function emitPrefs() {
        var payload = normalizePrefs(Object.assign({}, prefs))
        payload.lastOpenedSection = section
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge && nrrNativeBridge.savePreferences) {
            nrrNativeBridge.savePreferences(JSON.stringify(payload))
        }
        console.log("NRR_PREFS_JSON:" + JSON.stringify(payload))
    }

    // Open the VPN-client onboarding dialog. Entry
    // point wired from Settings -> Routing -> Leak protection ("Set up my VPN").
    function openVpnOnboarding() {
        if (typeof vpnOnboardingDialog !== "undefined" && vpnOnboardingDialog) {
            vpnOnboardingDialog.open()
        }
    }

    // Open the app-group routing dialog (scan installed programs,
    // assign popular groups to primary/secondary). Sections reach it through
    // this window-level entry point (a visible "Set up routes" button is added
    // by the Interfaces/Routes section, not inlined here).
    function openAppGroupRouting() {
        if (typeof appGroupRoutingDialog !== "undefined" && appGroupRoutingDialog) {
            appGroupRoutingDialog.open()
        }
    }

    // Apply the confirmed app-group route assignments as
    // application rules. Reconcile semantics (do NOT flood the model):
    //   * primary is the DEFAULT route -> creates no rule; instead it REMOVES
    //     any existing application rule for that exe (so toggling a group back
    //     to primary deletes the previously-added secondary rule);
    //   * secondary MATERIALIZES an application rule -> if one already exists
    //     for the same (ruleType "application", matchValue) we retarget it to
    //     "secondary" via rulesModel.set rather than appending a duplicate.
    // Respects freeRulesMaxCount: applies what fits, then reports the shared
    // rules-limit-reached status. Mutates the model + arms the footer Apply
    // exactly like a manual rule edit (no silent auto-apply).
    function _applyAppGroupRoutes(assignments) {
        var list = assignments || []
        var mutated = false
        // Pass 1 — primary assignments remove any matching application rule.
        for (var pi = 0; pi < list.length; pi += 1) {
            var pa = list[pi]
            if (String(pa.route || "") !== "primary") continue
            var pmv = String(pa.matchValue || "")
            if (pmv === "") continue
            var pmvLower = pmv.toLowerCase()
            for (var ri = rulesModel.count - 1; ri >= 0; ri -= 1) {
                var prow = rulesModel.get(ri)
                if (String(prow.ruleType || "") === "application"
                        && String(prow.matchValue || "").toLowerCase() === pmvLower) {
                    rulesModel.remove(ri)
                    mutated = true
                }
            }
        }
        // Pass 2 — secondary assignments ensure an application->secondary rule.
        var limitHit = false
        var secondaryCount = 0
        // Counted once and carried: the check sits inside the loop, and
        // re-walking the whole model per assignment is quadratic on a rule set
        // this size.
        var userCount = userRuleCount()
        for (var si = 0; si < list.length; si += 1) {
            var sa = list[si]
            if (String(sa.route || "") !== "secondary") continue
            var mv = String(sa.matchValue || "")
            if (mv === "") continue
            var mvLower = mv.toLowerCase()
            secondaryCount += 1
            // Find an existing application rule with the same match value.
            var existingIdx = -1
            for (var ei = 0; ei < rulesModel.count; ei += 1) {
                var erow = rulesModel.get(ei)
                if (String(erow.ruleType || "") === "application"
                        && String(erow.matchValue || "").toLowerCase() === mvLower) {
                    existingIdx = ei
                    break
                }
            }
            var kind = String(sa.kind || "")
            var groupComment = tr("app-groups.group." + kind, kind)
            if (existingIdx >= 0) {
                var upd = rulesModel.get(existingIdx)
                if (String(upd.targetRoute || "") !== "secondary") {
                    rulesModel.set(existingIdx, {
                        id: upd.id,
                        enabled: upd.enabled,
                        ruleType: "application",
                        ruleTypeTitle: ruleTypeLabel("application"),
                        matchValue: upd.matchValue,
                        aceMatchValue: _aceLowerForSearch(upd.matchValue),
                        targetRoute: "secondary",
                        comment: upd.comment
                    })
                    mutated = true
                }
                continue
            }
            if (userCount >= freeRulesMaxCount) {
                limitHit = true
                break
            }
            userCount += 1
            var item = {
                id: nextFreeRuleId(),
                enabled: true,
                ruleType: "application",
                ruleTypeTitle: ruleTypeLabel("application"),
                matchValue: mv,
                aceMatchValue: _aceLowerForSearch(mv),
                targetRoute: "secondary",
                comment: groupComment
            }
            rulesModel.append(item)
            _sidecarWriteCommentForRow(item)
            mutated = true
        }
        if (mutated) {
            // Rebuild RulesSection's display snapshot even for set()/remove()
            // edits that don't change rulesModel.count (same reason saveRule
            // emits this).
            rulesModelEdited()
            _recomputeRulesDirty()
        }
        if (limitHit) {
            statusLine = tr("status.rules-limit-reached",
                "Up to {max} active rules are supported.")
                .replace("{max}", String(freeRulesMaxCount))
        } else {
            statusLine = tr("app-groups.confirmed-status",
                "Routes updated for {count} program(s).")
                .replace("{count}", String(secondaryCount))
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Offline routing-settings intents.
    //
    // Service-owned routing settings (the per-SID route-policy toggles + the
    // shared service-stability config) are edited in the GUI. When the service
    // is STOPPED the controls stay live but the RPC can't land, so the change
    // used to be silently lost and the service's stale value won on the next
    // start. Instead we PARK every offline edit as an explicit "pending intent"
    // in `prefs.routePendingOfflineJson` (a compact single-line JSON object,
    // "" = none). On the next backend connect we offer a dialog to Apply or
    // Discard — nothing is ever pushed silently.
    //
    // Shape: { "route-policy": { <wire-key>: <value>, … },
    //          "stability":    { <wire-key>: <value>, … } }
    // The keys inside each namespace are the EXACT wire keys the live appliers
    // use, so applying = build the full request from the current snapshot and
    // override those keys.
    // ─────────────────────────────────────────────────────────────────────────

    /// True only when a REAL service is reachable. Mock/preview builds report
    /// kind:"connected" without a live bridge; a stopped service reports a
    /// non-connected kind. Offline capture triggers on the negation of this.
    ///
    /// Both halves are load-bearing. The kind alone let a mock/preview launch
    /// read as connected, so every toggle flipped before the service was
    /// reachable took the live path, failed with `bridge-unavailable`, and was
    /// dropped instead of parked. The provider flag alone would strand a window
    /// that cold-started on the mock fallback: its cold-start facade stays mock
    /// for the whole session even after the service comes up, which is what
    /// `backendLiveServiceConfirmed` (a proven live health read) supersedes.
    function _routingBackendConnected() {
        return !!backendStatus && backendStatus.kind === "connected"
            && (backendServiceBacked || backendLiveServiceConfirmed)
    }

    /// Parse the parked-intents store into the canonical two-namespace shape.
    /// Returns empty namespaces on any error (never throws).
    function _readPendingOffline() {
        var empty = { "route-policy": {}, "stability": {} }
        var raw = String((prefs && prefs.routePendingOfflineJson) || "")
        if (raw === "") return empty
        try {
            var o = JSON.parse(raw)
            if (!o || typeof o !== "object") return empty
            return {
                "route-policy": (o["route-policy"] && typeof o["route-policy"] === "object")
                    ? o["route-policy"] : {},
                "stability": (o["stability"] && typeof o["stability"] === "object")
                    ? o["stability"] : {}
            }
        } catch (e) {
            return empty
        }
    }

    /// Number of parked keys across both namespaces.

    /// Persist the parked-intents store (compact JSON; "" when empty) through
    /// the same prefs mechanism every applier uses (in-place mutate + emitPrefs).
    function _writePendingOffline(obj) {
        var s = (Pure.pendingOfflineCount(obj) === 0) ? "" : JSON.stringify(obj)
        prefs.routePendingOfflineJson = s
        emitPrefs()
    }

    /// Merge one offline edit into the parked store (last write wins) and tell
    /// the user it was recorded. `namespace` ∈ "route-policy" | "stability".
    function _recordOfflineRoutingIntent(namespace, key, value) {
        var obj = _readPendingOffline()
        var ns = (namespace === "stability") ? "stability" : "route-policy"
        if (!obj[ns]) obj[ns] = {}
        obj[ns][key] = value
        _writePendingOffline(obj)
        // Parking is about DELIVERY; intent is about what the user decided.
        // A change made while the service is down is still a decision, and it
        // is exactly then that losing it hurts — a freshly wiped state DB
        // would otherwise answer with its own defaults and win.
        if (ns === "stability") {
            var decided = {}
            decided[key] = value
            _recordServiceIntent(decided)
        }
        console.log("offline change recorded:", ns, key, "=", value)
        statusLine = tr("status.offline-change-recorded",
            "The background service is unavailable — your change was saved and will "
            + "be offered to apply when it reconnects.")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Last-known service-owned values (display mirror).
    //
    // The per-SID route policy and the shared service-stability config live on
    // the service and are read over IPC. With the service stopped that read
    // fails, and a panel that has nothing else to show falls back to its QML
    // literal defaults — so the user sees neutral checkboxes and concludes the
    // settings were lost. They were not, but the DISPLAY lied.
    //
    // Every successful live read therefore writes what it just learned into
    // `prefs.serviceBackedMirrorJson` (a compact single-line JSON object,
    // "" = nothing mirrored yet), and the offline seeding paths read it back.
    // Display order in every panel:
    //   1. a live successful read (always wins, and refreshes this mirror)
    //   2. a parked offline intent (`_readPendingOffline`) — chosen, not pushed
    //   3. this mirror — what the service last actually reported
    //   4. the QML literal default (last resort)
    // The mirror is READ-ONLY with respect to the service: nothing here is ever
    // pushed. Delivering values stays the job of the parked-intents flow.
    //
    // Shape mirrors the parked store so the two read the alike:
    //   { "route-policy": { <wire-key>: <value>, … },
    //     "stability":    { <wire-key>: <value>, … } }
    // ─────────────────────────────────────────────────────────────────────────

    /// Parse the display mirror into the canonical two-namespace shape. Returns
    /// empty namespaces on any parse error (never throws), so a corrupted blob
    /// degrades to "no mirror" rather than breaking a panel's seed.
    function _readServiceMirror() {
        var empty = { "route-policy": {}, "stability": {} }
        var raw = String((prefs && prefs.serviceBackedMirrorJson) || "")
        if (raw === "") return empty
        try {
            var o = JSON.parse(raw)
            if (!o || typeof o !== "object") return empty
            return {
                "route-policy": (o["route-policy"] && typeof o["route-policy"] === "object")
                    ? o["route-policy"] : {},
                "stability": (o["stability"] && typeof o["stability"] === "object")
                    ? o["stability"] : {}
            }
        } catch (e) {
            return empty
        }
    }

    /// Merge freshly-read service values into the display mirror and persist
    /// through the same prefs mechanism the parked store uses. `values` is a map
    /// of WIRE key -> value, so the mirror and the live path never disagree on
    /// shapes; only the keys the reply actually carried should be passed.
    /// Last write wins per key, and keys written by other panels are preserved.
    /// A no-op when nothing changed, so a panel mount does not emit prefs.
    function _rememberServiceValues(namespace, values) {
        if (!values || typeof values !== "object") return
        var ns = (namespace === "stability") ? "stability" : "route-policy"
        var mirror = _readServiceMirror()
        var bucket = mirror[ns]
        var changed = false
        for (var key in values) {
            var value = values[key]
            if (value === undefined) continue
            if (JSON.stringify(bucket[key]) === JSON.stringify(value)) continue
            bucket[key] = value
            changed = true
        }
        if (!changed) return
        prefs.serviceBackedMirrorJson = JSON.stringify(mirror)
        emitPrefs()
    }

    /// The service-owned settings the user has actually decided about, as a
    /// map of WIRE key -> value. Distinct from the display mirror above: the
    /// mirror records what the service last said, this records what the user
    /// asked for. Only the second one may be replayed back to the service.
    /// Degrades to "nothing recorded" on any parse error.
    function _readServiceIntent() {
        var raw = String((prefs && prefs.serviceIntentJson) || "")
        if (raw === "") return {}
        try {
            var o = JSON.parse(raw)
            if (!o || typeof o !== "object") return {}
            return (o["stability"] && typeof o["stability"] === "object") ? o["stability"] : {}
        } catch (e) {
            return {}
        }
    }

    /// Record what the user asked a service-owned setting to be. Called from
    /// the single write path (`applyServiceStabilityPatch`) for user-originated
    /// changes only, so a read-back, a replay or an internal re-seed can never
    /// masquerade as a decision the user made.
    function _recordServiceIntent(values) {
        if (!values || typeof values !== "object") return
        var intent = _readServiceIntent()
        var changed = false
        for (var key in values) {
            var value = values[key]
            if (value === undefined) continue
            if (JSON.stringify(intent[key]) === JSON.stringify(value)) continue
            intent[key] = value
            changed = true
        }
        if (!changed) return
        prefs.serviceIntentJson = JSON.stringify({ "stability": intent })
        emitPrefs()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // May this user change the routing rules at all?
    //
    // An administrator can turn rule editing off machine-wide (managed company
    // laptops, parental control). The refusal itself lives in the service — a
    // private copy of this app runs into exactly the same wall — so everything
    // here is presentation: the Rules section renders read-only instead of
    // letting the user compose a change that is guaranteed to bounce.
    // ─────────────────────────────────────────────────────────────────────────

    /// Absent on the wire reads as "allowed", so a service that predates the
    /// setting can never lock the section by omission.
    property bool allowUserRuleEdits: true

    /// The permission as known without a live read: a value parked while the
    /// service was down outranks the mirror of what the service last reported,
    /// matching the precedence every other field of this config follows.
    function _ruleEditPermissionOffline() {
        var parked = _readPendingOffline()["stability"] || {}
        if (parked.hasOwnProperty("allow-user-rule-edits"))
            return parked["allow-user-rule-edits"] !== false
        var mirror = _readServiceMirror()["stability"] || {}
        if (mirror.hasOwnProperty("allow-user-rule-edits"))
            return mirror["allow-user-rule-edits"] !== false
        return true
    }

    /// Adopt the permission out of any service-stability payload (a Get reply,
    /// a Set echo). Every surface that reads that config calls this, so the
    /// window learns about a lock from whichever panel happens to read first.
    function adoptRuleEditPermission(payload) {
        var p = payload || {}
        if (p["allow-user-rule-edits"] !== undefined) {
            _rememberServiceValues("stability",
                { "allow-user-rule-edits": p["allow-user-rule-edits"] })
        }
        var parked = _readPendingOffline()["stability"] || {}
        if (parked.hasOwnProperty("allow-user-rule-edits")) {
            allowUserRuleEdits = parked["allow-user-rule-edits"] !== false
            return
        }
        allowUserRuleEdits = (p["allow-user-rule-edits"] !== false)
    }

    /// Ask the service for the permission. The Rules section has to know about
    /// a lock without the user ever opening Settings, so the window issues this
    /// read itself at cold start and on every reconnect edge. Read-only op —
    /// no elevation, works for an ordinary user.
    function refreshRuleEditPermission() {
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        var corr = (bridgeAvailable && bridge !== null
                && typeof bridge.rpcServiceStabilityConfigGet === "function")
            ? bridge.rpcServiceStabilityConfigGet() : ""
        if (!corr) {
            allowUserRuleEdits = _ruleEditPermissionOffline()
            return
        }
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                window.allowUserRuleEdits = window._ruleEditPermissionOffline()
                return
            }
            window.adoptRuleEditPermission(payload || {})
        })
    }

    /// Guarded entry to the rules import window. The File menu, Ctrl+O and the
    /// Rules toolbar all come through here, so a locked section cannot be
    /// walked around with a keyboard shortcut.
    function openLoadRuleListWindow() {
        if (!allowUserRuleEdits) {
            statusLine = tr("errors.rules-locked",
                "Your administrator manages the routing rules on this computer, so they cannot be changed here.")
            return
        }
        openChildWindow(loadListWindow)
    }

    /// Send the rules currently on screen to the service. Entry point for the
    /// banner that reports the service has none of them: the drift dialog is
    /// the wrong first stop when there is nothing yet to compare against.
    function applyRulesToService() {
        requestSectionChange("rules")
        var trigger = function() {
            var section = rulesSectionLoader.item
            if (section && typeof section._triggerReviewFlow === "function") {
                section._triggerReviewFlow()
                return true
            }
            return false
        }
        // The section compiles asynchronously, so one retry after the section
        // switch covers a first click that lands before it exists.
        if (!trigger()) Qt.callLater(trigger)
    }

    /// Emitted after a connect-time replay finishes (whether or not anything
    /// needed pushing) so the settings panels re-read a service that now
    /// agrees with the user.
    signal serviceIntentReplayed()

    /// Push the user's recorded decisions back into a service that disagrees
    /// with them. This is what makes a service the source of truth about
    /// *state* without making it the source of truth about *intent*: a wiped
    /// or freshly installed state DB answers with its own defaults, and
    /// without this the GUI would adopt those defaults and the user's settings
    /// would silently disappear.
    ///
    /// Keys the user parked while offline are skipped — the pending-changes
    /// dialog owns those, and replaying them here would apply changes the user
    /// has not confirmed yet.
    /// Attempts left in the current replay run, and the backoff between them.
    /// A connect lands while the service is still migrating its database and
    /// arming enforcement, so its IPC is at its slowest exactly when we ask —
    /// a single attempt loses the user's settings to that window.
    property int _serviceIntentAttemptsLeft: 0
    readonly property var _serviceIntentBackoffMs: [2000, 6000, 15000]
    property var _serviceIntentRetryTimer: null

    /// Set when the user changes a service-owned setting themselves. A replay
    /// that fires afterwards would push the older recorded value over the
    /// fresher one, so it stands down instead.
    property bool _serviceIntentSupersededByUser: false

    function replayServiceIntentToService() {
        _serviceIntentSupersededByUser = false
        _serviceIntentAttemptsLeft = _serviceIntentBackoffMs.length
        _attemptServiceIntentReplay()
    }

    function _attemptServiceIntentReplay() {
        var intent = _readServiceIntent()
        var hasIntent = false
        for (var probe in intent) { hasIntent = true; break }
        if (!hasIntent) {
            // Not a failure, but not nothing either: it means no setting the
            // user changed while the service was down is waiting to be
            // delivered. Told apart from "the replay ran" only by this line —
            // and telling them apart is the whole triage.
            console.log("service-intent replay: nothing recorded to replay")
            serviceIntentReplayed()
            return
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function") {
            _scheduleServiceIntentRetry("bridge-unavailable")
            return
        }
        var parked = (typeof _readPendingOffline === "function")
            ? (_readPendingOffline()["stability"] || {}) : {}
        var getCorr = bridge.rpcServiceStabilityConfigGet()
        rpcTransport.registerRpcCallback(getCorr, function(ok, payload, code, msg) {
            if (!ok) {
                _scheduleServiceIntentRetry("read-failed:" + String(code || ""))
                return
            }
            var live = payload || {}
            var patch = {}
            var diverged = false
            for (var key in intent) {
                if (parked.hasOwnProperty(key)) continue
                if (JSON.stringify(live[key]) === JSON.stringify(intent[key])) continue
                patch[key] = intent[key]
                diverged = true
            }
            if (!diverged) {
                console.log("service-intent replay: the service already holds every",
                            "recorded intent — nothing to push")
                _serviceIntentAttemptsLeft = 0
                serviceIntentReplayed()
                return
            }
            console.log("service-intent replay: pushing", JSON.stringify(patch))
            applyServiceStabilityPatch(patch, function(ok2, code2) {
                if (ok2) {
                    _serviceIntentAttemptsLeft = 0
                    serviceIntentReplayed()
                    return
                }
                _scheduleServiceIntentRetry("write-failed:" + String(code2 || ""))
            }, "intent-replay")
        })
    }

    /// Retry unless we are out of attempts or the reason to replay is gone.
    /// Emits `serviceIntentReplayed()` on the last failure too: the panels
    /// wait on that signal to re-read, and leaving them waiting forever would
    /// be worse than reporting a service we could not reconcile with.
    function _scheduleServiceIntentRetry(reason) {
        var attemptsMade = _serviceIntentBackoffMs.length - _serviceIntentAttemptsLeft
        if (_serviceIntentSupersededByUser) {
            console.log("service-intent replay stood down after", attemptsMade,
                        "attempt(s): the user changed the setting themselves")
            _serviceIntentAttemptsLeft = 0
            serviceIntentReplayed()
            return
        }
        if (_serviceIntentAttemptsLeft <= 1 || !_routingBackendConnected()) {
            console.log("service-intent replay gave up after", attemptsMade + 1,
                        "attempt(s), last reason:", reason)
            _serviceIntentAttemptsLeft = 0
            serviceIntentReplayed()
            return
        }
        var delay = _serviceIntentBackoffMs[attemptsMade]
        _serviceIntentAttemptsLeft -= 1
        console.log("service-intent replay attempt", attemptsMade + 1, "failed (",
                    reason, ") — retrying in", delay, "ms")
        if (_serviceIntentRetryTimer === null) {
            _serviceIntentRetryTimer = Qt.createQmlObject(
                "import QtQuick 2.15; Timer { repeat: false }", window,
                "serviceIntentRetryTimer")
            _serviceIntentRetryTimer.triggered.connect(function() {
                if (_serviceIntentSupersededByUser || !_routingBackendConnected()) {
                    console.log("service-intent replay: retry abandoned —",
                                _serviceIntentSupersededByUser
                                    ? "the user changed the setting themselves"
                                    : "the service is not connected")
                    _serviceIntentAttemptsLeft = 0
                    serviceIntentReplayed()
                    return
                }
                _attemptServiceIntentReplay()
            })
        }
        _serviceIntentRetryTimer.interval = delay
        _serviceIntentRetryTimer.restart()
    }

    /// The declared default of one `route.policy.update` wire field. The single
    /// declaration lives in `lib/pure.js` (shared with the tray process and
    /// pinned against the Rust DTO by a contract test); every panel that needs
    /// to know "is the service still at the default for this key?" reads it
    /// from here instead of repeating the literal.
    function routePolicyDefault(key) {
        return Pure.ROUTE_POLICY_FIELD_DEFAULTS[key]
    }

    /// Build the FULL route.policy.update request from a snapshot's current
    /// per-SID policy, preserving every field at its live value (or its declared
    /// default when absent). Callers override the keys they are changing. Thin
    /// wrapper over the shared builder — the window only contributes the local
    /// `routeBehaviorMode` mirror the `mode` field falls back to.
    function _buildFullRoutePolicyReq(cur) {
        return Pure.buildFullRoutePolicyReq(cur, prefs.routeBehaviorMode)
    }

    /// Effective CURRENT value of one route-policy key from a snapshot (applying
    /// the same defaults the request-builder uses). Used to drop offline intents
    /// that already match the service (no-op filter). `undefined` for anything
    /// that is not a route-policy field.
    function _routePolicyEffective(cur, key) {
        if (key === "mode")
            return String((cur || {}).mode || prefs.routeBehaviorMode
                || Pure.ROUTE_POLICY_FIELD_DEFAULTS["mode"])
        return Pure.routePolicyEffective(cur, key)
    }

    /// Effective CURRENT value of one service-stability key from a config DTO.

    /// One-shot guard so the FIRST successful health poll (cold start, where
    /// backendStatus already reads "connected") still offers any parked intents
    /// left over from a previous session.
    property bool _offlinePendingColdChecked: false
    /// Emitted after Apply/Discard so an instantiated RoutingSettings panel can
    /// re-load its controls from the (now updated) service.
    signal offlinePendingApplied()

    // The ONE clobber-safe writer for the shared service-stability
    // config DTO. Every panel owning a SUBSET of that config (Routing:
    // enforcement-mode / liveness-window / stop-policy / rule-scope; Diagnostics:
    // ipc-accept-policy / verbose / conn-trace / cache-refresh) goes through here:
    // it GETs the current config, merges ONLY its own keys, then SETs — a fresh
    // read-modify-write. Kills the split-writer clobber where a panel sending a
    // full payload from local drafts reset a sibling panel's field to the serde
    // default (e.g. a Diagnostics Save disabling the liveness window). Replaces
    // the per-writer inline Get→mutate→Set + the manual carry-forward hacks.
    // `onDone(ok, code, payload)`.
    // Stability patches are GET → merge → SET over
    // the FULL config row (the wire op has no sparse update). Two concurrent
    // patches therefore lose updates: both GET the same base, the second SET
    // clobbers the first's field. Observed in practice: panel load fires the enforcement-mode and liveness patches
    // back-to-back, and the liveness SET wrote the STALE enforcement mode
    // back — the user saw Mode B arm and roll back to A within 2 s. The queue
    // below serialises every patch: each one GETs only after the previous SET
    // completed, so its merge base is always fresh.
    property var _stabilityPatchQueue: []
    property bool _stabilityPatchInFlight: false

    // `origin` is a writer-attribution tag
    // ("user:enforcement-mode", "user:verbose-toggle", …) the service logs
    // with the write, so a clobbered toggle is diagnosable from the NDJSON.
    function applyServiceStabilityPatch(partial, onDone, origin) {
        var originText = String(origin || "")
        // Every user-driven change to a service-owned setting funnels through
        // here, so this is the one place that can record intent without having
        // to trust each call site to remember. Recorded on submit rather than
        // on success: the user decided regardless of whether the service was
        // reachable, and an unreachable service is precisely when the record
        // matters. Non-user origins (read-back re-seeds, the replay itself)
        // must never write intent or they would launder service defaults into
        // "what the user wanted".
        if (originText.indexOf("user:") === 0 || originText === "offline-pending-apply") {
            _recordServiceIntent(partial)
            // A pending replay carries values recorded BEFORE this write, so
            // letting it run now would undo what the user just chose.
            _serviceIntentSupersededByUser = true
        }
        _stabilityPatchQueue.push({ partial: partial, onDone: onDone,
                                    origin: originText })
        _drainStabilityPatchQueue()
    }

    function _drainStabilityPatchQueue() {
        if (_stabilityPatchInFlight || _stabilityPatchQueue.length === 0) return
        var job = _stabilityPatchQueue.shift()
        var finish = function(ok, code, payload) {
            _stabilityPatchInFlight = false
            if (typeof job.onDone === "function") job.onDone(ok, code, payload)
            _drainStabilityPatchQueue()
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function"
                || typeof bridge.rpcServiceStabilityConfigSet !== "function") {
            finish(false, "bridge-unavailable", null)
            return
        }
        _stabilityPatchInFlight = true
        var getCorr = bridge.rpcServiceStabilityConfigGet()
        rpcTransport.registerRpcCallback(getCorr, function(ok, payload, code, msg) {
            if (!ok) {
                finish(false, String(code || ""), null)
                return
            }
            // The merge base is the live row PLUS the decisions the user has
            // on record, so this full-row write cannot re-affirm a service
            // default that contradicts one of them. A recorded decision the
            // service has not accepted yet (delivery failed, state DB wiped)
            // would otherwise be cancelled by the next unrelated save.
            var merged = Pure.mergeStabilityWrite(payload || {},
                                                  window._readServiceIntent(),
                                                  window._readPendingOffline()["stability"] || {},
                                                  job.partial || {})
            var setCorr = bridge.rpcServiceStabilityConfigSet(merged, job.origin || "")
            rpcTransport.registerRpcCallback(setCorr, function(ok2, p2, code2, msg2) {
                finish(!!ok2, String(code2 || ""), p2)
            })
        })
    }

    // Live apply-on-change path for the "verbose service logging" toggle,
    // shared by the Settings -> Diagnostics panel and the Logs view filter
    // bar (both bind their checkbox to `serviceVerboseLogging`, so one
    // implementation keeps them in sync). Optimistic: the shared flag flips
    // immediately — both checkboxes track it through a Binding — and reverts
    // if the live apply fails. Admin-gated (may raise one UAC through the
    // session elevation broker), matching the enforcement-mode behaviour.
    // `origin` distinguishes the call site in the service write log.
    function applyVerboseLogging(enabled, origin) {
        var prior = !enabled
        window.serviceVerboseLogging = enabled
        // Service stopped: park the intent like every other service-backed
        // toggle instead of bouncing the checkbox back. The user can arm
        // verbose logging BEFORE starting the service and have it delivered on
        // the connect edge; without this the checkbox silently refused to stay
        // ticked whenever the service was not running yet.
        if (!window._routingBackendConnected()) {
            window._recordOfflineRoutingIntent("stability", "verbose-logging", enabled)
            return
        }
        window.applyServiceStabilityPatch({ "verbose-logging": enabled },
            function(ok, code, payload) {
                if (!ok) {
                    window.serviceVerboseLogging = prior
                    window.statusLine = window.tr("status.verbose-logging-failed",
                        "Could not update verbose service logging: ")
                        + ((typeof window.ipcErrorLabel === "function")
                            ? window.ipcErrorLabel(String(code || "unknown"))
                            : String(code || "unknown"))
                    return
                }
                window.statusLine = enabled
                    ? window.tr("status.verbose-logging-enabled",
                        "Verbose service logging enabled — applies immediately")
                    : window.tr("status.verbose-logging-disabled",
                        "Verbose service logging disabled — applies immediately")
            }, String(origin || "user:verbose-toggle"))
    }

    /// Shared read-modify-write driver for ONE per-SID route-policy field.
    /// Each apply* below normalises its input and persists any local pref mirror,
    /// then delegates the uniform dance here: park the intent while the service is
    /// offline, guard the bridge, read the live policy (`snapshot.initial.get`),
    /// overlay the single field on the FULL preserved payload
    /// (`_buildFullRoutePolicyReq` — the ONE source of field-preservation truth),
    /// write it back (`route.policy.update`, elevation relayed by the session
    /// broker — one UAC reused), and surface a localised status line.
    /// `o.onApplied(value)` runs on success before the status line (mirror a
    /// routingState flag, fire a follow-up RPC, …).
    function applyGuiActivationRequest(request) {
        if (!request || Object.keys(request).length === 0) return
        // Tray hand-off may target a different
        // section while editor state is dirty. Route through the
        // guard.
        if (request.section) requestSectionChange(String(request.section))
        if (request.openAbout) openChildWindow(aboutWindow)
        if (request.openLicense) openChildWindow(licenseWindow)
        window.show()
        window.raise()
        window.requestActivate()
        // Secondary launchers can carry an `action`
        // slug beyond a plain section switch. Known slugs:
        // `safe-disable` (tray menu, after "Safe disable (temporary)…")
        // and `rules-drift-apply` ("Apply" on the tray's file-vs-service
        // notice). Older launchers
        // omit `action`, which is fine — the dispatch is a no-op.
        var actionSlug = String(request.action || "")
        if (actionSlug === "safe-disable") {
            var prefilledReason = String(request.reason || "")
            safeDisableConfirmDialog.resetForOpen(prefilledReason)
            safeDisableConfirmDialog.open()
        } else if (actionSlug === "rules-drift-apply") {
            // "Apply" on the tray's file-vs-service notice. The tray never
            // writes routing policy itself — review, elevation and activation
            // live here — so it hands the intent over and the window runs the
            // ordinary load-from-file + review flow the user would have used.
            requestSectionChange("rules")
            statusLine = tr("status.rules-drift-apply-requested",
                "Loading the rules from your files, then applying them to the service.")
            // Loading the file is only half of what the button says. Chain the
            // ordinary review/activate flow onto it so "Apply" always ends in
            // a send to the service — including when the file already matched
            // the table and the load itself changed nothing.
            driftController._driftLoadFromFile({
                primary: _comparableRulesPathFor("primary"),
                secondary: _comparableRulesPathFor("secondary")
            }, function() {
                driftController._driftApplyGuiState()
            })
        } else if (actionSlug !== "") {
            console.log("applyGuiActivationRequest: unknown action slug",
                        actionSlug)
        }
    }

    // Real two-phase safe-disable. Phase 1
    // dry-run requests a review summary + confirmation token from
    // the service. Phase 2 confirm consumes the token and executes
    // `safe_disable`. Toast stack tracks the visible progress (red
    // on failure, green on success). The synthetic correlation id
    // ties the visible toast to the RPC chain so we can settle it
    // from either phase's callback.
    function _handleSafeDisableConfirmed(reason) {
        statusLine = tr("status.safe-disable.requested",
            "Safe disable requested")
        var corr = "safe-disable-" + Date.now()
        if (typeof operationToastStack !== "undefined"
                && operationToastStack
                && operationToastStack.model) {
            _pushOperationToast(corr, "safe-disable")
        }
        if (!bridgeAvailable
                || typeof nrrNativeBridge.rpcProductImpactDisable
                    !== "function") {
            // Bridge not wired (preview / no RPC) — settle the toast
            // as failed with a pending-bridge code (B.6 localised).
            if (operationToastStack && operationToastStack.model) {
                operationToastStack.model.settle(corr, "failed",
                    "safe-disable-rpc-pending")
            }
            console.log("safe-disable: bridge unavailable")
            return
        }
        // dry-run.
        var dryRunCorr = nrrNativeBridge.rpcProductImpactDisable(
            reason, true /* dryRun */, "" /* token */)
        rpcTransport.registerRpcCallback(dryRunCorr, function(ok, p, code, msg) {
            if (!ok) {
                if (operationToastStack && operationToastStack.model) {
                    operationToastStack.model.settle(corr, "failed",
                        code || "internal")
                }
                console.log("safe-disable dry-run failed:", code, msg)
                return
            }
            var token = String((p && p["confirmation-token"]) || "")
            if (!token) {
                if (operationToastStack && operationToastStack.model) {
                    operationToastStack.model.settle(corr, "failed",
                        "bad-response")
                }
                console.log("safe-disable dry-run returned no token")
                return
            }
            // Reason MUST match the dry-run reason
            // (server cross-checks; mismatch returns PreconditionFailed).
            var confirmCorr = nrrNativeBridge.rpcProductImpactDisable(
                reason, false /* dryRun */, token)
            rpcTransport.registerRpcCallback(confirmCorr, function(ok2, p2, code2, msg2) {
                if (!ok2) {
                    if (operationToastStack && operationToastStack.model) {
                        operationToastStack.model.settle(corr, "failed",
                            code2 || "internal")
                    }
                    console.log("safe-disable confirm failed:", code2, msg2)
                    return
                }
                statusLine = tr("status.safe-disable.completed",
                    "Safe disable applied")
                if (operationToastStack && operationToastStack.model) {
                    operationToastStack.model.settle(corr, "completed", "")
                }
                console.log("safe-disable completed; operation-id="
                    + (p2 && p2["operation-id"]))
            })
        })
    }

    readonly property int freeRulesMaxCount: 9999
    /// Rules the USER wrote. Mirrors `nrr_shared::rules_json::user_rule_count`:
    /// the cap is the user's allowance, and the companions the app authored for
    /// them must not be what stops them adding the next rule.
    function userRuleCount() {
        var n = 0
        for (var i = 0; i < rulesModel.count; i += 1) {
            var row = rulesModel.get(i)
            if (!row) continue
            if (String(row.originReason || "") === "") n += 1
        }
        return n
    }
    function nextFreeRuleId() {
        // Max of existing numeric suffixes + 1, falling back to 1 when the
        // model is empty. Avoids the previous `100 + count + 1` quirk that
        // produced ids like R-107 for the first user-added rule.
        var maxN = 0
        for (var i = 0; i < rulesModel.count; i += 1) {
            var raw = String(rulesModel.get(i).id || "")
            var m = raw.match(/^R-(\d+)$/)
            if (m) {
                var n = parseInt(m[1], 10)
                if (!isNaN(n) && n > maxN) maxN = n
            }
        }
        var next = Math.min(maxN + 1, freeRulesMaxCount)
        var padded = ("0000" + String(next)).slice(-4)
        return "R-" + padded
    }
    // A single-rule Edit writes via rulesModel.set(),
    // which does NOT change rulesModel.count, so RulesSection's onCountChanged
    // rebuild never fires and the moved/edited row (e.g. secondary→primary)
    // stays stale in the table until the next filter/search rebuild. saveRule()
    // emits this after every edit so the section rebuilds its display snapshot
    // immediately. (An append() already triggers onCountChanged; the duplicate
    // is harmless — the 0 ms coalescing timer collapses it into one rebuild.)
    signal rulesModelEdited()
    function saveRule() {
        if (editingRule < 0 && userRuleCount() >= freeRulesMaxCount) {
            statusLine = tr("status.rules-limit-reached",
                "Up to {max} active rules are supported.")
                .replace("{max}", String(freeRulesMaxCount))
            return
        }
        // Auto-derive a Punycode hint into the Comment field when the
        // user typed an IDN host and left the comment blank. Storage
        // stays Unicode (human-readable in the rules file); the comment
        // surfaces the ACE form so the user can cross-reference it.
        var finalComment = ruleDialog.localComment
        if (finalComment === ""
                && (ruleDialog.localRuleType === "zone"
                    || ruleDialog.localRuleType === "domain"
                    || ruleDialog.localRuleType === "suffix-domain"
                    || ruleDialog.localRuleType === "exact-fqdn")) {
            var ace = _punycodeFor(ruleDialog.localValue)
            if (ace !== "") finalComment = "Punycode: " + ace
        }
        var item = {
            id: editingRule >= 0 ? rulesModel.get(editingRule).id : nextFreeRuleId(),
            enabled: ruleDialog.localEnabled,
            ruleType: ruleDialog.localRuleType,
            ruleTypeTitle: ruleTypeLabel(ruleDialog.localRuleType),
            matchValue: ruleDialog.localValue,
            aceMatchValue: _aceLowerForSearch(ruleDialog.localValue),
            targetRoute: ruleDialog.localRoute,
            comment: finalComment
        }
        // Duplicate detection by (ruleType,
        // matchValue, targetRoute). When found, surface a modal asking
        // the user whether to abandon the current edit and jump to the
        // existing rule, or stay on the form to change the value. Was
        // a one-line statusLine warning before — easy to miss, and the
        // user pressed Save expecting something to happen.
        var newKey = Rules.mergeKey(item)
        for (var di = 0; di < rulesModel.count; di += 1) {
            if (editingRule >= 0 && di === editingRule) continue
            if (Rules.mergeKey(rulesModel.get(di)) === newKey) {
                ruleDuplicateDialog.duplicateIndex = di
                ruleDuplicateDialog.duplicateId = String(
                    rulesModel.get(di).id || "")
                ruleDuplicateDialog.open()
                return
            }
        }
        if (editingRule >= 0) rulesModel.set(editingRule, item); else rulesModel.append(item)
        // A `set()` edit does NOT change
        // rulesModel.count, so RulesSection's onCountChanged rebuild never
        // fires and the edited row (e.g. secondary→primary) stays stale until
        // the next filter/search rebuild. The original 06-28 fix declared the
        // signal + listener but FORGOT to emit it here — emit it now so the
        // display snapshot rebuilds immediately. (`append` already triggers
        // onCountChanged; the 0 ms coalescing timer collapses the duplicate.)
        rulesModelEdited()
        // Comments live in the sidecar, NOT on the
        // wire (the service doesn't see them and content_hash skips
        // them). Persist on every Save so the edit survives an app
        // restart. Empty string deletes the sidecar row.
        _sidecarWriteCommentForRow(item)
        // A rule saved with the enable toggle cleared is stored and shipped
        // like any other, but routes nothing. Say so on the way out instead of
        // reporting a plain "Rule added" the user reads as "it works now".
        if (editingRule >= 0) {
            statusLine = tr("status.rule-updated", "Rule updated")
        } else if (!ruleDialog.localEnabled) {
            statusLine = tr("status.rule-added-disabled",
                "Rule added but disabled — it will not affect routing until you enable it.")
        } else {
            statusLine = tr("status.rule-added", "Rule added")
        }
        // Local rule edit invalidates any
        // previously-saved revision; the guard will prompt before
        // destructive navigation/close until the user submits via
        // the review flow.
        // Recompute against the baseline so an edit that nets back
        // to the saved content does NOT leave a false "unsaved" state.
        _recomputeRulesDirty()
    }

    function resetDefaults() {
        updatePrefs({
            launchWindowOnStartup: true,
            minimizeToTrayInsteadOfClose: true,
            showNotifications: true,
            notifySuggestionChanges: true,
            notifyBlockNotices: true,
            hideBlockNoticeAddresses: false,
            routingDetailedMode: false,
            reopenLastSectionOnStartup: true,
            themeMode: "system",
            accessibilityHighContrast: false,
            fontScalePercent: 100,
            systemFont: "system-default",
            enhancedFocus: false,
            simplifiedLabels: false,
            tooltipsEnabled: true,
            language: systemLanguage(),
            routePrimaryLabel: defaultRouteLabel("primary"),
            routeSecondaryLabel: defaultRouteLabel("secondary"),
            selectedPrimaryInterfaceId: "",
            selectedPrimaryInterfaceName: "",
            primaryRoleUserConfirmed: false,
            selectedSecondaryInterfaceId: "",
            selectedSecondaryInterfaceName: "",
            secondaryRoleUserConfirmed: false,
            routeBehaviorMode: "prefer-primary",
            showBluetoothAdapters: false,
            showAuditTab: false,
            settingsAutosaveSecs: 60,
            allowModeAKillswitch: false,
            preFlightApplyPolicyOptIn: false,
            showRememberedAdapters: true,
            autoConfirmAdapterIdChange: true,
            // Show the block-all warning banner (default on).
            warnKillSwitchBlockAll: true
        })
        statusLine = tr("status.defaults-restored", "Defaults restored")
    }

    // Full reset to post-install state (does
    // NOT uninstall the service; that stays on the app uninstaller / the
    // "Service management" button). Steps: clear service operational logs
    // (audit trail untouched) + sidecar + GUI logs (local/fast), reset all
    // GUI prefs + file bindings + first-run flag, clear the local rules
    // model, then clear the service's active rules to an empty revision
    // (async two-phase mutation — under a non-admin GUI the confirm is
    // Forbidden and the launcher's R3 path transparently elevates via UAC).
    // The completion dialog offers to close the program + tray so the reset
    // takes effect on the next launch (fresh first-run).
    function fullReset() {
        statusLine = tr("status.full-reset-running", "Performing full reset…")
        if (bridgeAvailable && typeof nrrNativeBridge.rpcLogsClear === "function") {
            var cl = nrrNativeBridge.rpcLogsClear(false, true)
            rpcTransport.registerRpcCallback(cl, function() {})
        }
        if (bridgeAvailable && typeof nrrNativeBridge.rpcSidecarReset === "function") {
            var cs = nrrNativeBridge.rpcSidecarReset()
            rpcTransport.registerRpcCallback(cs, function() {})
        }
        if (bridgeAvailable && typeof nrrNativeBridge.clearGuiLogs === "function") {
            nrrNativeBridge.clearGuiLogs()
        }
        resetDefaults()
        updatePrefs({
            lastSavedPathPrimary: "",
            lastSavedPathSecondary: "",
            lastLoadedPathPrimary: "",
            lastLoadedPathSecondary: "",
            autoOpenOnLaunchPathPrimary: "",
            autoOpenOnLaunchPathSecondary: "",
            firstRunCompleted: false,
            // "Reset everything" means the state a fresh install starts from,
            // and that includes not having agreed to anything yet.
            acceptedEulaVersion: 0
        })
        emitPrefs()
        Pure.clearModel(rulesModel)
        clearAllUnsavedChanges()
        // Purge auxiliary state FIRST: disjoint tables from the rules-apply
        // step, but this order survives a declined UAC prompt below.
        _purgePrincipalDataForReset(function(purgeOk) {
            _applyEmptyRulesForReset(function(rulesOk) {
                fullResetCompleteDialog.serviceCleared = !!purgeOk && !!rulesOk
                fullResetCompleteDialog.open()
            })
        })
    }

    // Full-reset auxiliary-state purge via `principal-data.purge` — caller's
    // own principal, non-elevated.
    function _purgePrincipalDataForReset(onComplete) {
        if (!bridgeAvailable || typeof nrrNativeBridge.rpcPrincipalDataPurge !== "function") {
            onComplete(false)
            return
        }
        var c = nrrNativeBridge.rpcPrincipalDataPurge()
        rpcTransport.registerRpcCallback(c, function(ok) { onComplete(!!ok) })
    }

    // Silent two-phase empty PresetImport: makes the service's active
    // revision empty (post-install state) WITHOUT opening the review dialog
    // (the Full-reset confirm already gated the action). Same payload shape
    // as `startBothRoutesPresetImportReviewFlow`; the confirm phase carries
    // the dry-run token. Non-admin → confirm Forbidden → launcher R3 elevates
    // (UAC) and retries; `onComplete(false)` on UAC-decline / failure.
    function _applyEmptyRulesForReset(onComplete) {
        if (!bridgeAvailable || typeof nrrNativeBridge.rpcMutationSubmit !== "function") {
            onComplete(false)
            return
        }
        var emptyB64 = Qt.btoa("--- Zones\n\n--- Domains\n\n--- IP\n\n--- Windows\n\n--- Linux\n\n--- MacOS\n")
        var corr = "full-reset-" + (new Date().getTime())
        var payload = {
            "include-child-processes": false,
            "correlation-id": corr,
            "primary-bytes-b64": emptyB64,
            "secondary-bytes-b64": emptyB64
        }
        var c1 = nrrNativeBridge.rpcMutationSubmit("preset-import", payload, true, "")
        rpcTransport.registerRpcCallback(c1, function(ok, p, code, msg) {
            if (!ok || !p) { onComplete(false); return }
            var token = (p && p["confirmation-token"]) || ""
            var c2 = nrrNativeBridge.rpcMutationSubmit("preset-import", payload, false, token)
            rpcTransport.registerRpcCallback(c2, function(ok2) { onComplete(!!ok2) })
        })
    }

    // Close every NetRuleRouter process so the reset takes effect on the
    // next launch. The main GUI closes itself directly; `requestTrayShutdown`
    // writes the dedicated tray-shutdown flag the tray polls and quits on.
    function _fullResetCloseAll() {
        if (bridgeAvailable && typeof nrrNativeBridge.requestTrayShutdown === "function") {
            nrrNativeBridge.requestTrayShutdown()
        }
        quittingToTray = true
        clearAllUnsavedChanges()
        window.close()
        Qt.quit()
    }

    Action { id: exitAction; text: tr("action.exit-application", "Exit"); shortcut: StandardKey.Quit; icon.source: uiIconSource("exit"); onTriggered: window.close() }
    Action { id: aboutAction; text: tr("action.open-about-window", "About"); shortcut: "F1"; icon.source: uiIconSource("about"); onTriggered: openChildWindow(aboutWindow) }
    Action { id: licenseAction; text: tr("action.open-license-window", "License"); shortcut: "Ctrl+Shift+L"; icon.source: uiIconSource("about"); onTriggered: openChildWindow(licenseWindow) }
    Action { id: logsFolderAction; text: tr("action.open-logs-folder", "Open logs folder"); shortcut: "Ctrl+Shift+O"; icon.source: uiIconSource("open-file"); onTriggered: Pure.openExternalUrl(((context.about || {}).logsFolderUrl || "")) }
    Action { id: interfacesAction; text: sectionTitle("interfaces-routes"); shortcut: "Ctrl+1"; icon.source: sectionIconSource("interfaces-routes"); onTriggered: requestSectionChange("interfaces-routes") }
    Action { id: rulesAction; text: sectionTitle("rules"); shortcut: "Ctrl+2"; icon.source: sectionIconSource("rules"); onTriggered: requestSectionChange("rules") }
    Action { id: diagnosticsAction; text: sectionTitle("diagnostics"); shortcut: "Ctrl+3"; icon.source: sectionIconSource("diagnostics"); onTriggered: requestSectionChange("diagnostics") }
    Action { id: logsAction; text: sectionTitle("logs"); shortcut: "Ctrl+4"; icon.source: sectionIconSource("logs"); onTriggered: requestSectionChange("logs") }
    Action { id: settingsAction; text: sectionTitle("settings"); shortcut: "Ctrl+,"; icon.source: sectionIconSource("settings"); onTriggered: requestSectionChange("settings") }
    Action { id: refreshAction; text: tr("action.refresh-interfaces", "Refresh interfaces"); shortcut: StandardKey.Refresh; icon.source: uiIconSource("refresh"); onTriggered: { statusLine = tr("status.interfaces-refreshed", "Interfaces list refreshed."); interfacesRolesController.refreshInterfacesFromService() } }
    Action { id: closeOverlayAction; text: tr("action.close", "Close"); shortcut: StandardKey.Close; onTriggered: closeActiveOverlay() }
    Action { id: applyOverlayAction; text: tr("action.apply", "Apply"); shortcut: "Ctrl+Return"; onTriggered: applyActiveOverlay() }

    Shortcut { sequence: interfacesAction.shortcut; context: Qt.ApplicationShortcut; onActivated: interfacesAction.trigger() }
    Shortcut { sequence: rulesAction.shortcut; context: Qt.ApplicationShortcut; onActivated: rulesAction.trigger() }
    Shortcut { sequence: diagnosticsAction.shortcut; context: Qt.ApplicationShortcut; onActivated: diagnosticsAction.trigger() }
    Shortcut { sequence: logsAction.shortcut; context: Qt.ApplicationShortcut; onActivated: logsAction.trigger() }
    Shortcut { sequence: settingsAction.shortcut; context: Qt.ApplicationShortcut; onActivated: settingsAction.trigger() }
    Shortcut { sequence: refreshAction.shortcut; context: Qt.ApplicationShortcut; onActivated: refreshAction.trigger() }
    Shortcut { sequence: StandardKey.Open; context: Qt.ApplicationShortcut; onActivated: openLoadRuleListWindow() }
    Shortcut { sequence: aboutAction.shortcut; context: Qt.ApplicationShortcut; onActivated: aboutAction.trigger() }
    Shortcut { sequence: licenseAction.shortcut; context: Qt.ApplicationShortcut; onActivated: licenseAction.trigger() }
    Shortcut { sequence: logsFolderAction.shortcut; context: Qt.ApplicationShortcut; onActivated: logsFolderAction.trigger() }
    Shortcut { sequence: StandardKey.Quit; context: Qt.ApplicationShortcut; onActivated: exitAction.trigger() }
    Shortcut { sequence: StandardKey.Close; context: Qt.ApplicationShortcut; onActivated: closeActiveOverlay() }
    Shortcut { sequence: "Escape"; context: Qt.ApplicationShortcut; onActivated: closeActiveOverlay() }
    Shortcut { sequence: "Ctrl+Return"; context: Qt.ApplicationShortcut; onActivated: applyActiveOverlay() }
    Shortcut { sequence: "Ctrl+Enter"; context: Qt.ApplicationShortcut; onActivated: applyActiveOverlay() }

    // Compute "is dark title bar" directly from current prefs instead of
    // reading `uiTheme.isDark`. Reason: when a theme switch flips
    // `uiRevision`, the order in which `ThemeTokens` re-evaluates its
    // bindings vs. our `onUiRevisionChanged` handler is not guaranteed.
    // Reading prefs directly removes that race — the value is always
    // consistent with the just-applied prefs patch.
    function isDarkTitleBarFromPrefs() {
        var mode = resolveThemeModeForPrefs(prefs)
        return mode === "dark" || mode === "high-contrast"
    }
    function applyNativeTitleBarTheme() {
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && nrrNativeBridge.setMainWindowDarkTitleBar) {
            nrrNativeBridge.setMainWindowDarkTitleBar(isDarkTitleBarFromPrefs())
        }
    }
    function applyTitleBarTo(childWindow) {
        if (!childWindow) return
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && nrrNativeBridge.setWindowDarkTitleBar) {
            nrrNativeBridge.setWindowDarkTitleBar(childWindow, isDarkTitleBarFromPrefs())
        }
    }
    function applyAllTitleBars() {
        applyNativeTitleBarTheme()
        var reg = _childWindowRegistry()
        for (var i = 0; i < reg.length; i += 1)
            if (reg[i].titleBar) applyTitleBarTo(reg[i].win)
    }

    // A dedicated derived bool that flips only on an effective theme change.
    // It is recomputed directly from prefs, so the DWM attribute always lines
    // up with the current theme regardless of the order in which the theme
    // tokens re-evaluate.
    readonly property bool wantDarkTitleBar: uiRevision >= 0 && isDarkTitleBarFromPrefs()
    // Re-apply ONCE per actual change, deferred to the next event-loop tick so
    // every binding keyed off the revision counters has settled first.
    // This used to also run on every `uiRevision` bump and to fire twice per
    // change; each pass walks all open windows and forces a non-client frame
    // redraw, which is what made switching to dark / high-contrast feel
    // laggy — the counter bumps on unrelated interactions too (row selection,
    // any preference write), so the frame was being rebuilt constantly.
    onWantDarkTitleBarChanged: Qt.callLater(applyAllTitleBars)

    Component.onCompleted: {
        loadContext()
        logProgress(tr("progress.gui-started", "NetRuleRouter started."), "info")
        // Register the rules-section
        // save callback at window scope so the UnsavedChangesGuard offers an
        // "Apply" button for unsaved rule edits (drives the review→activate
        // pipeline and resumes navigation on success). Window scope (not the
        // section's onCompleted) keeps it available even when RulesSection is
        // lazily unloaded.
        if (typeof setSaveCallback === "function") {
            setSaveCallback("rules", function(onDone) { reviewFlowController._guardApplyRules(onDone) })
        }
        if (autoCloseMs <= 0
                && typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && nrrNativeBridge.ensureTrayRunning) {
            nrrNativeBridge.ensureTrayRunning()
        }
        // Connect to the bridge's RPC
        // response signal exactly once. Each setX/refreshX helper
        // registers a per-correlation-id callback that fires here.
        if (bridgeAvailable && typeof nrrNativeBridge.rpcResponse !== "undefined") {
            nrrNativeBridge.rpcResponse.connect(rpcTransport.handleRpcResponse)
        }

        // Connect to push events and
        // subscribe to the StatusUpdates stream. Server-pushed events
        // (RoutingPauseStateChanged, ApplyFailurePolicyChanged,
        // AutostartStateChanged, RetentionSettingsChanged,
        // RevisionStatusChanged) update routingState reactively so
        // the UI converges to server-authoritative values without
        // user-driven polling.
        if (bridgeAvailable && typeof nrrNativeBridge.pushEvent !== "undefined") {
            // Connect the push signal ONCE (it survives reconnects); the
            // subscription itself is (re)issued via _subscribeStatusUpdates so a
            // failed cold-start subscribe self-heals on the next reconnect.
            nrrNativeBridge.pushEvent.connect(handlePushEvent)
            _subscribeStatusUpdates()
        }
        centerMainWindow()
        applyNativeTitleBarTheme()
        // Live progress: surface the cold-start connection outcome so the
        // user can tell at a glance whether the service is reachable.
        if (((backendStatus || {}).kind) === "connected") {
            logProgress(tr("progress.connected",
                "Connected to the service."), "success")
        } else {
            logProgress(tr("progress.offline",
                "Service not reachable — working offline."), "warn")
        }
        // EULA gate — the user must accept the license agreement before any
        // other startup dialog runs. When acceptance is missing/outdated the
        // modal agreement window opens and its `accepted` handler resumes the
        // normal startup via `_runPostEulaStartup()`; `declined` quits. When
        // already accepted we run the post-EULA startup immediately.
        if (_eulaNeedsAcceptance()) {
            eulaAgreementWindow.open()
        } else {
            _runPostEulaStartup()
        }
    }

    /// Whether the license agreement must be shown before the app can be used:
    /// the persisted `acceptedEulaVersion` is below the version the current
    /// build ships (`context.eula.currentVersion`), and there is agreement text
    /// to display. A missing/zero current version (older context) disables the
    /// gate rather than trapping the user in an empty dialog.
    function _eulaNeedsAcceptance() {
        var eula = (context || {}).eula || {}
        var current = (eula.currentVersion | 0)
        if (current <= 0) return false
        if (String(eula.text || "").trim() === "") return false
        var accepted = ((prefs || {}).acceptedEulaVersion | 0)
        return accepted < current
    }

    /// The normal startup-dialog chain, gated behind EULA acceptance. Called
    /// directly when the agreement is already accepted, or from the EULA
    /// window's `accepted` handler otherwise.
    function _runPostEulaStartup() {
        if ((context.startupDialog || "") === "about") {
            openChildWindow(aboutWindow)
        } else if ((context.startupDialog || "") === "license") {
            openChildWindow(licenseWindow)
        } else if (!prefs.firstRunCompleted) {
            logProgress(tr("progress.first-run-wizard-shown",
                "Showing first-run setup (not completed yet)."), "progress")
            // Show the service install dialog FIRST
            // when the service isn't registered yet. After the user
            // picks Install or Skip, the existing preset
            // wizard opens (chained via the install dialog's signals).
            // Skip-budget: if the user declined UAC 3+ times we keep
            // them out of the modal trap and jump straight to the
            // preset wizard.
            if (_serviceNeedsInstallPrompt()) {
                firstLaunchInstallDialog.open()
            } else {
                openChildWindow(firstRunWindow)
            }
        } else {
            // Auto-open-on-launch. When the user has
            // opted in (Save As → "Open these rules on next launch"
            // checkbox), the path is stored in
            // `prefs.autoOpenOnLaunchPath*`. On startup we read each
            // file's bytes and route them through the standard
            // PresetImport review flow — same diff dialog as a manual
            // Import action. Missing file surfaces a toast and clears
            // the auto-open path so the user isn't re-prompted next
            // launch.
            //
            // Gated behind `autoLoadRulesOnLaunch`
            // (default ON). When the user turns it off, the remembered
            // paths are kept but not auto-loaded; they see whatever the
            // service already has.
            //
            // When CONNECTED, the service's
            // active revision is the source of truth for what is actually
            // applied. Refetch it so applied rules persist across launches
            // and across elevation / Windows-account changes (the per-SID
            // storage key is the user SID, identical elevated vs not). Only
            // fall back to the remembered file when offline, so a user
            // without a running service still sees their rules; drift
            // detection reconciles file-vs-service once the service connects.
            _hydrateRulesOnLaunch()
        }
        // Cold-start check for offline work parked in a previous session.
        // refreshBackendStatus only fires the same check on a
        // disconnect→connect transition; when the cold-start snapshot
        // arrives with the service already running there's no
        // transition, so we'd miss the prompt without this one-shot.
        // (`firstRunCompleted` is re-checked inside the collector so the
        // first-launch wizards are never buried under a modal.)
        if (((backendStatus || {}).kind) === "connected") {
            _offlineBacklogCollectTimer.restart()
        }
        // Cold-start re-sync of the adapter binding
        // into the service when it has none but prefs do (e.g. service DB was
        // wiped). No-op when already in sync or no binding is selected.
        if (((backendStatus || {}).kind) === "connected") {
            Qt.callLater(routePolicyController._resyncRouteBindingIfMissing)
            // Cold-start counterpart of the reconnect replay: when the service
            // is already up at launch there is no disconnected→connected edge
            // to hang it on.
            Qt.callLater(replayServiceIntentToService)
        }
        // Populate the compatibility banner state
        // from the launcher's `local.service-info` snapshot. Runs
        // unconditionally on cold-start; the banner only paints when
        // a protocol mismatch is actually detected.
        Qt.callLater(_refreshServiceInfo)
        // Cold-start counterpart of the reconnect read above. Unconditional:
        // with no service reachable it falls back to the last value the
        // service reported, so a locked machine does not present an editable
        // Rules section for the first few seconds of every launch.
        Qt.callLater(refreshRuleEditPermission)
    }

    /// Cold-start rules hydration that does NOT lose the
    /// boot race. When a service is INSTALLED its per-SID revision is the
    /// source of truth; the bound .txt is only an import/export artifact.
    /// Loading the stale .txt while the service is still mid-reconcile (pipe
    /// not answering yet) diffs an out-of-date file against the live revision
    /// and reports activated rules as deletions (the "service wants to delete
    /// 2ip.ru" false-delete the user hit). So:
    ///   * connected now          → refresh from the service.
    ///   * installed, not up yet  → DEFER; backendStatusPoll connects and
    ///                              refreshBackendStatus() hydrates from the
    ///                              service. Fall back to the file only if it
    ///                              never connects within the bounded window.
    ///   * genuinely no service   → auto-open the bound file now so an offline
    ///                              user still sees their rules.
    function _hydrateRulesOnLaunch() {
        var kind = String((backendStatus || {}).kind || "")
        if (kind === "connected") {
            _refreshRulesFromService({ silent: true, onComplete: function(ok) {
                // The service answered but holds no rules (fresh install, wiped
                // state DB) — or did not answer at all. Either way the table
                // would stay empty while a rule set sits selected right above
                // it, so fall back to the same file hydration an offline start
                // does. A service that DOES hold rules keeps ownership: this
                // never overwrites a non-empty revision.
                if (prefs.autoLoadRulesOnLaunch === false) return
                if (!rulesModel || rulesModel.count === 0) _runAutoOpenOnLaunch()
            } })
            return
        }
        // Two kinds mean nobody is going to answer the pipe right now:
        // "service-not-installed" (no service at all) and "service-stopped"
        // (SCM reports it stopped — it is not mid-boot). Both hydrate from the
        // bound file IMMEDIATELY, so a user who starts the GUI before the
        // service sees their rules at once instead of an empty table. Only
        // "connecting"/"disconnected" — where the service may still answer —
        // defer to the bounded fallback below, which is what keeps a stale file
        // from being diffed against a live revision mid-boot.
        var serviceMayAnswer = (kind !== "service-not-installed"
            && kind !== "service-stopped")
        if (serviceMayAnswer) {
            if (prefs.autoLoadRulesOnLaunch === false) return
            // Defer the file fallback so we don't diff a stale file against the
            // live revision while the service is still coming up.
            _coldStartAutoOpenFallbackTimer.restart()
            return
        }
        if (prefs.autoLoadRulesOnLaunch !== false) _runAutoOpenOnLaunch()
    }

    // Bounded fallback for _hydrateRulesOnLaunch: if the
    // installed service still hasn't connected after the window, load the bound
    // file so the user isn't left empty-handed. If it connected meanwhile,
    // refreshBackendStatus() already pulled the live rules → this is a no-op.
    Timer {
        id: _coldStartAutoOpenFallbackTimer
        interval: 6000
        repeat: false
        onTriggered: {
            if (String((window.backendStatus || {}).kind || "") !== "connected"
                    && window.prefs.autoLoadRulesOnLaunch !== false) {
                window._runAutoOpenOnLaunch()
            }
        }
    }

    /// Which file backs `route` ("primary" | "secondary") — the single source of
    /// truth shared by the cold-start hydration below and the "Source:" row
    /// above the rules table, so what is shown can never disagree with what is
    /// loaded. Priority:
    ///   1. a remembered path INSIDE the user's own rule-set folder. Once the
    ///      user keeps sets of their own, those win over anything shipped with
    ///      the app — the save target first (that is where they put work), then
    ///      the load source. A folder that was configured but never written to
    ///      contributes nothing and falls through.
    ///   2. the explicit "open these rules on next launch" opt-in;
    ///   3. where the current rules were loaded from — including a shipped set,
    ///      whose path is display-only and never a save target;
    ///   4. the save-target binding, for prefs written before (3) existed.
    ///   5. nothing remembered at all → the rule set the quick-load dropdown is
    ///      pointing at (`defaultRuleSetPathFor`), so a first launch — or one
    ///      whose bindings were lost — shows rules instead of an empty table.
    /// Demo rules bind no path at all, so they correctly resolve to "" and the
    /// Source row stays hidden.
    function rulesSourcePathFor(route) {
        var remembered = _rememberedRulesPathFor(route)
        if (remembered !== "") return remembered
        return defaultRuleSetPathFor(route)
    }

    /// Steps 1–4 above: a path the user's own actions put on record. Split out
    /// because the "Source:" row needs to tell "a file backs these rules" apart
    /// from "this is what a load would pull in", which step 5 answers.
    function _rememberedRulesPathFor(route) {
        return Pure.rememberedRulesPathFor(prefs, route, userPresetsDir)
    }

    /// What the "Source:" row shows for `route`. Same answer as
    /// `rulesSourcePathFor` while a remembered path exists. With nothing
    /// remembered it names the set that WOULD load only while the table is
    /// empty: once rules are on screen without a file behind them (the demo
    /// set, rules typed by hand), naming a file the user is not looking at
    /// would be a lie — the row stays hidden instead.
    function rulesSourceDisplayPathFor(route) {
        var remembered = _rememberedRulesPathFor(route)
        if (remembered !== "") return remembered
        if (rulesModel && rulesModel.count > 0) return ""
        return defaultRuleSetPathFor(route)
    }

    /// Enumerated rule sets — the ONE list behind both the quick-load dropdown
    /// and the cold-start hydration, so the set shown at the top of the Rules
    /// section is always the set whose rules appear below it.
    ///
    /// Which root is read follows the user's rule: a configured rule-set folder
    /// is the only source consulted; only when no folder is configured do the
    /// sets shipped with the app appear. (The dropdown additionally falls back
    /// to the shipped list for a folder that holds no sets, so the user is never
    /// left with an empty dropdown — `userOwned` records which root won so the
    /// hydration can tell those two cases apart.)
    ///
    /// Cached on the folder path: this is filesystem work and
    /// `rulesSourcePathFor` runs on every prefs write via the Source row's
    /// binding. `invalidateRuleSetCache()` drops it when the folder contents may
    /// have changed under us.
    property var _ruleSetCache: null

    function _ruleSetEnum() {
        var dir = userPresetsDir
        if (_ruleSetCache && _ruleSetCache.dir === dir) return _ruleSetCache
        var res = { dir: dir, userOwned: false, entries: [], paths: {} }
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.listAllPresets === "function") {
            if (dir !== "") {
                try {
                    res.entries = JSON.parse(
                        String(nrrNativeBridge.listAllPresets(dir) || "[]"))
                } catch (e) { res.entries = [] }
                res.userOwned = res.entries.length > 0
            }
            if (res.entries.length === 0) {
                try {
                    res.entries = JSON.parse(
                        String(nrrNativeBridge.listAllPresets() || "[]"))
                } catch (e2) { res.entries = [] }
                res.userOwned = false
            }
        }
        _ruleSetCache = res
        return res
    }

    function invalidateRuleSetCache() { _ruleSetCache = null }

    /// Display label of the set at `index`. Shipped sets read "<cc>_<pack>";
    /// a set of the user's own carries no country, so it must not gain a
    /// leading underscore.
    function ruleSetLabelAt(index) {
        var e = _ruleSetEnum()
        if (index < 0 || index >= e.entries.length) return ""
        var entry = e.entries[index]
        var country = String(entry.country || "")
        var pack = String(entry.pack || "")
        var fallback = country !== "" ? (country + "_" + pack) : pack
        return String(entry.label || fallback)
    }

    /// `<source>:<label>`, the form persisted in `prefs.selectedPresetSet`. The
    /// source prefix matters: the user's own folder and the shipped tree can
    /// hold sets with identical labels, and a choice made in one list must not
    /// be restored into the other.
    function ruleSetSelectionKey(index) {
        var label = ruleSetLabelAt(index)
        if (label === "") return ""
        return (_ruleSetEnum().userOwned ? "user:" : "bundled:") + label
    }

    /// Index of the remembered set within the CURRENT list, or -1 when nothing
    /// is remembered, the remembered choice belongs to the other source, or the
    /// set itself is gone (renamed / deleted folder) — each of which falls back
    /// to the default pick rather than stranding on a dead entry.
    function ruleSetRememberedIndex() {
        var want = String(prefs.selectedPresetSet || "")
        if (want === "") return -1
        var e = _ruleSetEnum()
        for (var i = 0; i < e.entries.length; i += 1) {
            if (ruleSetSelectionKey(i) === want) return i
        }
        return -1
    }

    /// Default pick when the user never chose a set: match the preset's country
    /// code against the system locale's region, then its language. Sets shaped
    /// by the user carry no country, so the heuristic cannot say anything about
    /// them — those default to the first entry.
    function ruleSetPreferredIndex() {
        var arr = _ruleSetEnum().entries
        if (!arr || arr.length === 0) return -1
        // The test is the DATA, not where it was enumerated from: a user who
        // points the folder at the sets shipped with the app still gets the
        // country/language pick, because those entries do carry a country.
        var hasCountry = false
        for (var c = 0; c < arr.length; c += 1) {
            if (String(arr[c].country || "") !== "") { hasCountry = true; break }
        }
        if (!hasCountry) return 0
        var loc = ""
        try { loc = String(Qt.locale().name || "") } catch (e) { loc = "" }
        var parts = loc.toLowerCase().split(/[_-]/)
        var lang = parts.length > 0 ? parts[0] : ""
        var region = parts.length > 1 ? parts[1] : ""
        for (var pass = 0; pass < 2; pass += 1) {
            var want = (pass === 0) ? region : lang
            if (want === "") continue
            for (var i = 0; i < arr.length; i += 1) {
                if (String(arr[i].country || "").toLowerCase() === want) return i
            }
        }
        return 0
    }

    /// Absolute path of `route`'s rules file inside the set at `index`, or ""
    /// when that set has no file for the route (a set with only one of the two
    /// files is normal).
    function ruleSetFilePath(index, route) {
        var e = _ruleSetEnum()
        if (index < 0 || index >= e.entries.length) return ""
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.resolvePresetPath !== "function") {
            return ""
        }
        var cacheKey = String(index) + ":" + String(route)
        if (e.paths[cacheKey] !== undefined) return e.paths[cacheKey]
        var entry = e.entries[index]
        // Shipped sets live at `<cc>/<pack>/`; a user set is either `<set>/` or
        // the folder root itself, so join only the segments that are present.
        var segments = []
        if (String(entry.country || "") !== "") segments.push(String(entry.country))
        if (String(entry.pack || "") !== "") segments.push(String(entry.pack))
        var file = (String(route) === "primary") ? "rules_primary.txt"
                                                 : "rules_secondary.txt"
        var rel = segments.concat([file]).join("/")
        // Empty override = the shipped tree; non-empty = the user's own folder.
        var abs = String(nrrNativeBridge.resolvePresetPath(
            rel, e.userOwned ? e.dir : "") || "")
        e.paths[cacheKey] = abs
        return abs
    }

    /// The set to fall back on when no file path is remembered at all, per the
    /// user's rule: a configured rule-set folder is the ONLY source — sets in
    /// it load, an empty folder loads nothing (we do not silently substitute a
    /// shipped set for someone who told us where their rules live). With no
    /// folder configured we show the set matching the system locale, which is
    /// what a fresh install has always done.
    function defaultRuleSetIndex() {
        var e = _ruleSetEnum()
        if (userPresetsDir !== "" && !e.userOwned) return -1
        var idx = ruleSetRememberedIndex()
        if (idx < 0) idx = ruleSetPreferredIndex()
        return idx
    }

    function defaultRuleSetPathFor(route) {
        return ruleSetFilePath(defaultRuleSetIndex(), route)
    }

    /// Index of the rule set `path` belongs to, or -1 for a file outside every
    /// known set (a rules .txt the user opened from somewhere of their own).
    /// Windows paths compare case-insensitively and separator-agnostically.
    function _ruleSetIndexForPath(path) {
        var want = String(path || "").replace(/\\/g, "/").toLowerCase()
        if (want === "") return -1
        var e = _ruleSetEnum()
        for (var i = 0; i < e.entries.length; i += 1) {
            for (var r = 0; r < 2; r += 1) {
                var p = String(ruleSetFilePath(i, r === 0 ? "primary" : "secondary") || "")
                if (p !== "" && p.replace(/\\/g, "/").toLowerCase() === want) return i
            }
        }
        return -1
    }

    /// Make the quick-load dropdown name the set whose rules are actually on
    /// screen. Derived from the loaded path when there is one — a remembered
    /// path is the stronger fact, and without this step the dropdown would go
    /// on showing its default pick while different rules sit below it. Falls
    /// back to the set the hydration chose when no path was remembered at all.
    /// A choice the user made by hand is never overwritten, and a rules file
    /// outside every known set leaves the dropdown alone.
    function _rememberHydratedRuleSet() {
        if (String(prefs.selectedPresetSet || "") !== "") return
        var primary = _rememberedRulesPathFor("primary")
        var secondary = _rememberedRulesPathFor("secondary")
        var idx = -1
        if (primary !== "" || secondary !== "") {
            idx = _ruleSetIndexForPath(primary)
            if (idx < 0) idx = _ruleSetIndexForPath(secondary)
        } else {
            idx = defaultRuleSetIndex()
        }
        var key = ruleSetSelectionKey(idx)
        if (key === "") return
        updatePrefs({ selectedPresetSet: key })
        emitPrefs()
    }

    function _runAutoOpenOnLaunch() {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            return
        }
        // Explicit "open on next launch" opt-in still wins, but fall
        // back to the most-recent import/export path so any selection
        // the user made in the GUI is restored automatically on the
        // next launch — no need for a
        // separate checkbox to enable this behaviour.
        var primaryPath = rulesSourcePathFor("primary")
        var secondaryPath = rulesSourcePathFor("secondary")
        if (primaryPath === "" && secondaryPath === "") return

        var primB64 = ""
        if (primaryPath !== "") {
            primB64 = String(nrrNativeBridge.readFileBytes(primaryPath) || "")
            if (primB64 === "") {
                statusLine = tr("status.auto-open-file-missing",
                    "Auto-open file not found at {path}. Choose a file to attach.")
                    .replace("{path}", primaryPath)
                updatePrefs({ autoOpenOnLaunchPathPrimary: "" })
            }
        }
        var secB64 = ""
        if (secondaryPath !== "") {
            secB64 = String(nrrNativeBridge.readFileBytes(secondaryPath) || "")
            if (secB64 === "") {
                statusLine = tr("status.auto-open-file-missing",
                    "Auto-open file not found at {path}. Choose a file to attach.")
                    .replace("{path}", secondaryPath)
                updatePrefs({ autoOpenOnLaunchPathSecondary: "" })
            }
        }
        if (primB64 === "" && secB64 === "") return
        // Files read successfully — make the quick-load dropdown name the set
        // these rules came from (no-op when the user picked one by hand).
        _rememberHydratedRuleSet()
        statusLine = tr("status.auto-open-loading",
            "Loading rules from {path}...")
            .replace("{path}", primaryPath !== "" ? primaryPath : secondaryPath)
        presetImportController.startBothRoutesPresetImportReviewFlow(
            primB64, secB64, primaryPath, secondaryPath)
    }

    // "Forget file binding". Clears every remembered
    // rules-file path (last-saved + auto-open opt-in) so the next launch
    // loads nothing from disk and the user sees exactly what the service
    // holds. Persists immediately via emitPrefs so a crash before normal
    // close doesn't resurrect the binding.
    function forgetFileBindings() {
        updatePrefs({
            lastSavedPathPrimary: "",
            lastSavedPathSecondary: "",
            lastLoadedPathPrimary: "",
            lastLoadedPathSecondary: "",
            autoOpenOnLaunchPathPrimary: "",
            autoOpenOnLaunchPathSecondary: ""
        })
        emitPrefs()
        statusLine = tr("status.file-binding-forgotten",
            "File binding cleared. Rules will not be auto-loaded on next launch.")
    }

    // Single source of truth for "what the
    // service is actually applying". Maps one wire `RuleRowEntry`
    // (kebab-case, from `rules.list`) into the camelCase shape the
    // rulesModel / RulesSection delegates expect (matches the cold-start
    // context rows emitted by `ui_surface.rs`).
    function _serviceRuleRowToModelRow(w) {
        var slug = String(w["rule-type"] || "")
        var route = String(w["target-route"] || "primary")
        var row = {
            id: Rules.canonicalRuleId(String(w.id || "")),
            enabled: !!w.enabled,
            ruleType: slug,
            ruleTypeTitle: (typeof ruleTypeLabel === "function")
                ? ruleTypeLabel(slug) : slug,
            matchValue: String(w["match-value"] || ""),
            targetRoute: route,
            comment: (w.comment !== undefined && w.comment !== null)
                ? String(w.comment) : "",
            validationStatus: String(w["validation-status"] || "valid"),
            validationMessageKey: String(w["validation-message-key"] || ""),
            // ВАЖНО: пустой объект, а не `null`. С `null` QML ListModel не
            // может вывести тип роли и пишет предупреждение «validationMessageArgs
            // is null …» на КАЖДУЮ из ~300 строк при импорте пресета. Этот поток
            // записей в stdout-пайп лаунчера и был основной причиной тормозов
            // populate (~3.3 c). Делегат читает поле через `if (args) for(k in args)`
            // — пустой объект совместим и итераций не даёт.
            validationMessageArgs: ({}),
            // Read-only OS hosts-file override annotation
            // for this rule's hostname (service-filled via `rules.list`;
            // empty when the hostname is not pinned by the OS hosts file).
            // Flattened to two scalar roles so QML's ListModel keeps stable
            // role types across rebuild (nested-object roles are unreliable).
            // Presence marker = hostsOverrideIp !== "".
            hostsOverrideIp: (w["hosts-override"] && w["hosts-override"].ip !== undefined)
                ? String(w["hosts-override"].ip) : "",
            hostsOverrideBlocking: !!(w["hosts-override"] && w["hosts-override"].blocking),
            // Provenance of an app-authored rule. Flattened to three scalar
            // roles for the same reason as the hosts-override pair above:
            // a nested-object role has an unreliable type across a model
            // rebuild. Presence marker = originReason !== "" (a rule the user
            // typed carries no origin at all).
            originReason: (w.origin && w.origin.reason !== undefined)
                ? String(w.origin.reason) : "",
            originAnchor: (w.origin && w.origin.anchor !== undefined)
                ? String(w.origin.anchor) : "",
            originAdded: (w.origin && w.origin.added !== undefined)
                ? String(w.origin.added) : ""
        }
        // Boundary conversion (inbound): snapshot rows carry ACE on
        // host-like rule types; decode for display (mirrors cold-start).
        if (Rules.isHostlikeRuleType(slug)) {
            row.matchValue = _unicodeDecodeHost(row.matchValue)
        }
        row.aceMatchValue = _aceLowerForSearch(row.matchValue)
        return row
    }

    // Re-pull the active revision's rules
    // from the service and rebind `rulesModel`. This is the "fan back"
    // the preset-import flow assumed (it submits `skipApply: true`
    // expecting the activated revision to come back via push) and it is
    // what makes a non-admin session see exactly what an admin session
    // (or the broker) just activated. `rules.list` is a read op, so it
    // works for non-elevated clients.
    //
    // opts: { silent: bool, onComplete: function(ok) }
    function _refreshRulesFromService(opts) {
        opts = opts || {}
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRulesList !== "function") {
            if (typeof opts.onComplete === "function") opts.onComplete(false)
            return
        }
        var corr = nrrNativeBridge.rpcRulesList()
        rpcTransport.registerRpcCallback(corr, function(ok, p, errorCode, errorMessage) {
            if (!ok || !p) {
                if (!opts.silent) {
                    statusLine = tr("status.rules-refresh-failed",
                        "Could not load the active rules from the service.")
                }
                if (typeof opts.onComplete === "function") opts.onComplete(false)
                return
            }
            var rows = p.rows || []
            // An explicit "Show the rules the service is applying"
            // that returns ZERO rules would silently WIPE every rule shown in the
            // GUI (clearModel below with nothing to re-append). Confirm first when
            // there is something to lose. The silent cold-start / post-connect /
            // post-push refreshes (opts.silent) and an already-approved re-entry
            // (opts.confirmedEmpty) proceed without a prompt.
            if (rows.length === 0 && !opts.silent && !opts.confirmedEmpty
                    && rulesModel && rulesModel.count > 0) {
                _pendingEmptyReloadOpts = opts
                emptyServiceRulesConfirmDialog.pendingRuleCount = rulesModel.count
                emptyServiceRulesConfirmDialog.open()
                return
            }
            console.time("[perf] _refreshRulesFromService populate")
            // Suppress RulesSection's per-chunk rebuilds for the whole
            // clear+repopulate; see `rulesBulkLoading` doc comment above
            // `_appendRowsChunked`.
            rulesBulkLoading = true
            Pure.clearModel(rulesModel)
            // Record the authoritative count the service
            // returned (before the async chunked append) so the empty-rules
            // notice reflects the real rule set and never flashes mid-load.
            _serviceRuleCount = rows.length
            // Append in chunks across event-loop
            // ticks so a ~300-rule import doesn't freeze the UI in one burst.
            // The drift baseline / dirty-flag / status all run AFTER the last
            // chunk so they reflect the fully-populated model.
            _appendRowsChunked(rows, _serviceRuleRowToModelRow, function() {
                console.timeEnd("[perf] _refreshRulesFromService populate")
                // Dedupe per-route id collisions
                // (primary/secondary both numbered from R-0000 by the service).
                _renumberRuleIdsSequential()
                _overlaySidecarCommentsOntoRulesModel()
                _gcSidecarCommentOrphans()
                // The model now mirrors the service exactly — recapture the
                // drift baseline and drop the dirty flag so the banner and
                // unsaved-changes guard reset to a clean state.
                driftController._driftCaptureServiceBaseline()
                // The model mirrors the
                // service, so re-baseline the unsaved-changes signature too
                // (also clears the dirty flag).
                _captureRulesDirtyBaseline()
                // The model now mirrors the service exactly, so any offline
                // preset import has been superseded — lift the anti-clobber
                // guard (covers both an explicit user refetch and the
                // post-push auto-refetch).
                _offlineRulesPendingPush = false
                // The post-append overlay steps
                // (_renumberRuleIdsSequential / _overlaySidecarCommentsOntoRulesModel)
                // mutate rows via set(), which does NOT change rulesModel.count,
                // so the section's onCountChanged rebuild reflects the
                // pre-overlay state. Emit rulesModelEdited() so the display
                // snapshot rebuilds against the final, overlaid model. Both this
                // signal and the append-driven onCountChanged were no-ops while
                // `rulesBulkLoading` was true; dropping the flag now is what
                // actually triggers RulesSection's single post-settle rebuild.
                rulesModelEdited()
                rulesBulkLoading = false
                // Refresh the unresolved-app set alongside the rule list so the
                // "app not enforced" banner tracks the live rules (e.g. after
                // importing a preset that adds application rules). Hoisted out
                // of the pre-populate block (was fired before the chunked
                // append even started) — `snapshot.initial.get` on the main
                // IPC channel no longer competes with the health probe/other
                // reads for the duration of the populate.
                refreshUnenforcedAppRules()
                // Same reason: the offer the tray may have shown while this
                // window was closed has to be countable the moment it opens.
                refreshAutoRuleCandidates()
                // An explicit pull replaced the table with what the service
                // enforces, so the linked file is now behind it — mirror it.
                // Silent cold-start/post-connect refreshes deliberately do NOT:
                // rules edited while the service was down still live in that
                // file, and the offline-backlog offer needs them intact.
                if (!opts.silent) boundFilesController._persistBoundFilesAfterApply()
                uiRevision += 1
                if (!opts.silent) {
                    statusLine = tr("status.rules-refreshed-from-service",
                        "Loaded {count} active rule(s) from the service.")
                        .replace("{count}", String(rows.length))
                }
                if (typeof opts.onComplete === "function") opts.onComplete(true)
            })
        })
    }

    // Append `rows` into rulesModel in small
    // batches across event-loop ticks so a large load (~300 rules) stays
    // responsive instead of freezing in one synchronous burst. `mapFn(row)`
    // produces each model entry; `onDone()` runs after the final batch.
    // Guarded by `_rulesPopulateGen`: starting a new populate bumps the
    // generation and any in-flight chunk loop aborts on its next tick, so two
    // overlapping refetches can't interleave rows into the model.
    property int _rulesPopulateGen: 0
    // Bulk-load suppression: `_refreshRulesFromService` clears + repopulates
    // `rulesModel` via `_appendRowsChunked`, which yields to the event loop
    // (`Qt.callLater`) between 75-row chunks. Each `rulesModel.append()` fires
    // `onCountChanged` on RulesSection's `Connections`, and because the loop
    // yields, the 0 ms coalescing timer there gets a chance to fire BETWEEN
    // chunks instead of once after the whole batch — turning one populate
    // into ceil(N/75) full `rebuildDisplay()` passes (sort + rebuild the
    // filtered/sorted display model from scratch). RulesSection's
    // `scheduleRebuild()` treats this flag as "hold off"; the single
    // `rulesBulkLoadingChanged` transition back to false triggers exactly
    // ONE rebuild once the model has fully settled.
    property bool rulesBulkLoading: false
    function _appendRowsChunked(rows, mapFn, onDone) {
        var total = rows ? rows.length : 0
        var gen = (_rulesPopulateGen += 1)
        if (total === 0) {
            if (typeof onDone === "function") onDone()
            return
        }
        var CHUNK = 75
        var i = 0
        // Populate has been measured at 9 s on a live book of rules, and the
        // three candidates cost very differently to fix: mapping the wire row,
        // the model append itself (every append re-evaluates whatever binds to
        // `count`), or the wait between chunks. Attribute it rather than guess.
        var mapMs = 0
        var appendMs = 0
        var chunks = 0
        var waitStart = 0
        var waitMs = 0
        function step() {
            if (gen !== _rulesPopulateGen) return // superseded by a newer load
            if (waitStart > 0) waitMs += Date.now() - waitStart
            chunks += 1
            var end = Math.min(i + CHUNK, total)
            for (; i < end; i += 1) {
                var t0 = Date.now()
                var mapped = mapFn(rows[i])
                var t1 = Date.now()
                rulesModel.append(mapped)
                mapMs += t1 - t0
                appendMs += Date.now() - t1
            }
            if (i < total) {
                waitStart = Date.now()
                Qt.callLater(step)
            } else {
                console.log("[perf] populate rows=" + total + " chunks=" + chunks
                    + " map=" + mapMs + "ms append=" + appendMs
                    + "ms between-chunks=" + waitMs + "ms")
                if (typeof onDone === "function") onDone()
            }
        }
        step()
    }

    // Toolbar "Show rules the service is
    // applying" entry point. When the user has unsaved local edits a
    // reload would discard them, so gate on a confirm; otherwise refetch
    // straight away. Wired from RulesSection's toolbar button.
    // Opts of a deferred empty-service reload, replayed with
    // `confirmedEmpty: true` once the user OKs EmptyServiceRulesConfirmDialog.
    property var _pendingEmptyReloadOpts: ({})
    function reloadActiveRulesFromService() {
        if (unsavedChangesRegistry["rules"]) {
            reloadFromServiceConfirmDialog.open()
        } else {
            _refreshRulesFromService({ silent: false })
        }
    }
    // Persistent main GUI flow (13.R2-GUI.4.c): when `minimizeToTrayInsteadOfClose`
    // is enabled, the X button hides the window without exiting the host
    // process. The launcher and Qt host remain alive, so a subsequent tray
    // "Open NetRuleRouter" click reaches the running primary via the
    // `gui-activation.json` handover (polled every 350 ms) and shows the
    // window in milliseconds — vs. ~3–5 s for a cold launcher+QML boot.
    // Full exit only happens via tray "Exit" (shutdown flag) or autoclose.
    onClosing: function(close) {
        emitPrefs()
        // Only the close-paths that actually
        // destroy unsaved editor state need the prompt. The
        // close-to-tray path preserves all in-memory editor state,
        // so it bypasses the guard. `quittingToTray` is set after
        // the user already passed the app-quit prompt (or accepted
        // an autoclose / preferences-driven quit).
        var isDestructive =
            !quittingToTray
            && autoCloseMs === 0
            && !prefs.minimizeToTrayInsteadOfClose
        if (isDestructive && hasAnyUnsavedChanges()) {
            close.accepted = false
            unsavedChangesGuard.requestAction(
                "window-close",
                function() {
                    // User confirmed Discard; mark as quitting-to-
                    // tray so the next onClosing pass accepts, then
                    // re-issue close().
                    quittingToTray = true
                    clearAllUnsavedChanges()
                    window.close()
                }
            )
            return
        }
        // SaveBeforeCloseDialog runs AFTER the
        // UnsavedChangesGuard. Triggered only when the active rules
        // revision diverges from the last file sync AND we're on a
        // real-close path (not close-to-tray, not autoclose).
        if (isDestructive
                && !_resumeCloseAfterSaveBefore
                && boundFilesController._filesSyncDivergenceExists()) {
            close.accepted = false
            _resumeCloseAfterSaveBefore = true
            boundFilesController._showSaveBeforeCloseDialog()
            return
        }
        if (quittingToTray || autoCloseMs > 0 || !prefs.minimizeToTrayInsteadOfClose) {
            close.accepted = true
            return
        }
        // If the tray fails to spawn (binary not
        // found, startDetached false, …) we must NOT hide the window
        // — that would leave the user with an invisible, unreachable
        // application. Fall through to a full close in that case.
        var traySpawned = false
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && nrrNativeBridge.ensureTrayRunning) {
            traySpawned = !!nrrNativeBridge.ensureTrayRunning()
        }
        if (!traySpawned) {
            console.log("Main: tray spawn failed; closing application instead of hiding")
            close.accepted = true
            return
        }
        close.accepted = false
        window.hide()
    }

    Timer { interval: autoCloseMs; running: autoCloseMs > 0; repeat: false; onTriggered: window.close() }
    Timer {
        interval: 350
        running: typeof nrrNativeBridge !== "undefined" && !!nrrNativeBridge && !!nrrNativeBridge.takePendingGuiRequest
        repeat: true
        onTriggered: {
            var request = nrrNativeBridge.takePendingGuiRequest()
            if (request && Object.keys(request).length > 0) applyGuiActivationRequest(request)
        }
    }
    // Single wind-down routine for every "the whole application is exiting"
    // trigger (tray "Exit" via the shutdown flag; the tray process dying).
    // `quittingToTray` bypasses the minimize-to-tray interception in
    // `onClosing` — which still runs and persists preferences via `emitPrefs`
    // — and forces a real close. `Qt.quit()` is explicit because
    // `quitOnLastWindowClosed` is false (so close-to-tray hide() doesn't kill
    // the host), meaning window.close() alone would leave the host alive.
    function windDownApplication() {
        quittingToTray = true
        window.close()
        Qt.quit()
    }

    Timer {
        // Poll the shutdown flag set by the tray's "Exit" action.
        interval: 250
        running: typeof nrrNativeBridge !== "undefined" && !!nrrNativeBridge && !!nrrNativeBridge.consumeApplicationShutdownRequest
        repeat: true
        onTriggered: {
            if (nrrNativeBridge.consumeApplicationShutdownRequest()) {
                window.windDownApplication()
            }
        }
    }

    // The tray is the only surface left once the main window is closed to
    // tray, so a tray killed from the outside (Task Manager, taskkill, crash)
    // would leave an unreachable GUI process behind. The host watches the PID
    // of the tray it spawned and raises this once; the intentional-exit path
    // (shutdown flag) is filtered out on the C++ side, so reaching here always
    // means "tray gone unexpectedly" and we run the same wind-down.
    Connections {
        target: (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge)
            ? nrrNativeBridge : null
        ignoreUnknownSignals: true
        function onTrayProcessDied() {
            window._restartTrayAfterDeath()
        }
    }

    /// Attempts left to bring the tray back before the main window is left to
    /// run without one. A tray that crashes must not take the window with it —
    /// the window is where the user's work is; the tray is a convenience.
    property int _trayRestartAttemptsLeft: 3
    readonly property var _trayRestartBackoffMs: [1000, 3000, 8000]

    function _restartTrayAfterDeath() {
        if (window._trayRestartAttemptsLeft <= 0) {
            console.log("Main: tray died again and all restarts are spent; "
                + "leaving the window running without a tray")
            return
        }
        var attempt = 4 - window._trayRestartAttemptsLeft
        window._trayRestartAttemptsLeft -= 1
        trayRestartTimer.interval =
            window._trayRestartBackoffMs[attempt - 1]
        console.log("Main: tray process died unexpectedly; restart attempt",
            attempt, "in", trayRestartTimer.interval, "ms")
        trayRestartTimer.restart()
    }

    Timer {
        id: trayRestartTimer
        repeat: false
        onTriggered: {
            if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                    || !nrrNativeBridge.ensureTrayRunning) {
                console.log("Main: tray restart skipped — no bridge")
                return
            }
            // Re-arms the host's liveness watch on the new PID, so a second
            // crash comes back here and spends the next attempt.
            var ok = !!nrrNativeBridge.ensureTrayRunning()
            console.log("Main: tray restart spawn ok =", ok)
        }
    }

    /// A running tray keeps the language it started with: its menu labels are
    /// resolved once at spawn and its context file is read once. Restarting it
    /// is the only refresh that covers every surface — menu, toasts and notice
    /// windows alike. The delay clears the launcher's preference-write debounce
    /// (500 ms) and the tray's shutdown poll (250 ms), so the new process reads
    /// the language the user just picked.
    function restartTrayForLanguageChange() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.requestTrayShutdown !== "function") {
            return
        }
        nrrNativeBridge.requestTrayShutdown()
        trayRestartTimer.interval = 1500
        trayRestartTimer.restart()
        console.log("Main: restarting tray to pick up the new language")
    }

    // Two-column menu item delegate: splits the Action's text on the tab
    // character that `Pure.menuActionText(label, shortcut)` inserts and renders
    // the label fill-width with the shortcut right-aligned. Native Qt Quick
    // MenuItem on Windows does not flush-right the shortcut on its own.
    Component {
        id: shortcutMenuItemDelegate
        MenuItem {
            id: itemDelegate
            readonly property var _parts: String(itemDelegate.text || "").split("\t")
            readonly property string _labelText: _parts.length > 0 ? _parts[0] : ""
            readonly property string _shortcutText: _parts.length > 1 ? _parts[1] : ""
            implicitHeight: 28
            contentItem: RowLayout {
                spacing: uiTheme.spacingLg
                Label {
                    Layout.fillWidth: true
                    text: itemDelegate._labelText
                    color: !itemDelegate.enabled ? mutedTextColor
                          : itemDelegate.highlighted ? palette.highlightedText : textColor
                    verticalAlignment: Text.AlignVCenter
                    elide: Text.ElideRight
                }
                Label {
                    text: itemDelegate._shortcutText
                    color: !itemDelegate.enabled ? mutedTextColor
                          : itemDelegate.highlighted ? palette.highlightedText : mutedTextColor
                    horizontalAlignment: Text.AlignRight
                    verticalAlignment: Text.AlignVCenter
                }
            }
            background: Rectangle {
                color: itemDelegate.highlighted ? uiTheme.colorAccent
                      : (itemDelegate.hovered ? uiTheme.stateHoverFill : uiTheme.colorPanel)
            }
        }
    }

    menuBar: MenuBar {
        // Each menu uses explicit `ShortcutMenuItem` instances rather than
        // `Action {}` declarations + `Menu.delegate`. The auto-MenuItem path
        // produced by Action declarations is rendered through whatever
        // delegate the active style picks, and on Windows that delegate
        // ignores our two-column rendering even with `popupType: Popup.Item`
        // and Fusion. Inline `ShortcutMenuItem` is a hard QML object tree
        // — the contentItem we declare is used unconditionally. Keyboard
        // shortcuts are wired by top-level `Action` declarations + global
        // `Shortcut { context: Qt.ApplicationShortcut }` elements declared
        // separately in this file, so removing them from the menus does not
        // break any keybinding.
        Menu {
            title: Pure.menuTitleText(tr("menu.file", "File"), "F")
            popupType: Popup.Item
            implicitWidth: menuPopupWidth([
                Pure.menuActionText(tr("action.load-rule-list", "Load rule list..."), "Ctrl+O"),
                Pure.menuActionText(tr("action.export-current-rule-list", "Export current list..."), "Ctrl+Shift+S"),
                Pure.menuActionText(tr("action.export-settings", "Export settings..."), "Ctrl+Alt+S"),
                Pure.menuActionText(exitAction.text, "Ctrl+Q")
            ])
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.load-rule-list", "Load rule list..."); shortcutText: "Ctrl+O"; enabled: window.allowUserRuleEdits; onTriggered: openLoadRuleListWindow() }
            // Show WHAT is being exported, then ask where to put it — the item
            // used to only switch sections and save nothing.
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.export-current-rule-list", "Export current list..."); shortcutText: "Ctrl+Shift+S"; onTriggered: { rulesAction.trigger(); boundFilesController.exportCurrentRulesInteractive(null) } }
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.export-settings", "Export settings..."); shortcutText: "Ctrl+Alt+S"; onTriggered: settingsAction.trigger() }
            MenuSeparator {}
            ShortcutMenuItem { theme: uiTheme; labelText: exitAction.text; shortcutText: "Ctrl+Q"; onTriggered: exitAction.trigger() }
        }
        Menu {
            title: Pure.menuTitleText(tr("menu.view", "View"), "V")
            popupType: Popup.Item
            implicitWidth: menuPopupWidth([
                Pure.menuActionText(sectionTitle("interfaces-routes"), "Ctrl+1"),
                Pure.menuActionText(sectionTitle("rules"), "Ctrl+2"),
                Pure.menuActionText(sectionTitle("diagnostics"), "Ctrl+3"),
                Pure.menuActionText(sectionTitle("logs"), "Ctrl+4"),
                Pure.menuActionText(sectionTitle("settings"), "Ctrl+,")
            ])
            ShortcutMenuItem { theme: uiTheme; labelText: sectionTitle("interfaces-routes"); shortcutText: "Ctrl+1"; onTriggered: interfacesAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: sectionTitle("rules"); shortcutText: "Ctrl+2"; onTriggered: rulesAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: sectionTitle("diagnostics"); shortcutText: "Ctrl+3"; onTriggered: diagnosticsAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: sectionTitle("logs"); shortcutText: "Ctrl+4"; onTriggered: logsAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: sectionTitle("settings"); shortcutText: "Ctrl+,"; onTriggered: settingsAction.trigger() }
        }
        Menu {
            title: Pure.menuTitleText(tr("menu.tools", "Tools"), "T")
            popupType: Popup.Item
            implicitWidth: menuPopupWidth([
                Pure.menuActionText(refreshAction.text, "F5"),
                Pure.menuActionText(tr("action.check-service-status", "Check service status"), "Ctrl+Shift+D"),
                Pure.menuActionText(tr("action.safe-rollback", "Safe rollback"), "Ctrl+Shift+R"),
                Pure.menuActionText(tr("action.temporary-disable-product-impact", "Temporarily disable product impact"), "Ctrl+Shift+P")
            ])
            ShortcutMenuItem { theme: uiTheme; labelText: refreshAction.text; shortcutText: "F5"; onTriggered: refreshAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.check-service-status", "Check service status"); shortcutText: "Ctrl+Shift+D"; onTriggered: { diagnosticsAction.trigger(); refreshBackendStatus() } }
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.safe-rollback", "Safe rollback"); shortcutText: "Ctrl+Shift+R"; onTriggered: safeRollbackConfirmDialog.open() }
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.temporary-disable-product-impact", "Temporarily disable product impact"); shortcutText: "Ctrl+Shift+P"; onTriggered: setRoutingPauseEnabled(!routingState.routingPaused, "") }
        }
        Menu {
            title: Pure.menuTitleText(tr("menu.help", "Help"), "H")
            popupType: Popup.Item
            implicitWidth: menuPopupWidth([
                Pure.menuActionText(aboutAction.text, "F1"),
                Pure.menuActionText(licenseAction.text, "Ctrl+Shift+L"),
                Pure.menuActionText(logsFolderAction.text, "Ctrl+Shift+O"),
                Pure.menuActionText(tr("action.check-for-updates", "Check for updates"), "Ctrl+U")
            ])
            ShortcutMenuItem { theme: uiTheme; labelText: aboutAction.text; shortcutText: "F1"; onTriggered: aboutAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: licenseAction.text; shortcutText: "Ctrl+Shift+L"; onTriggered: licenseAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: logsFolderAction.text; shortcutText: "Ctrl+Shift+O"; onTriggered: logsFolderAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.check-for-updates", "Check for updates"); shortcutText: "Ctrl+U"; onTriggered: statusLine = tr("status.updates-not-implemented", "Update check is not implemented yet.") }
        }
    }

    footer: Pane {
        padding: uiTheme.spacingSm
        background: PanelSurface { theme: uiTheme; cornerRadius: 0 }
        RowLayout {
            anchors.fill: parent
            spacing: uiTheme.spacingSm
            // Live startup/connection progress
            // pill. Shows the latest lifecycle line with a status-coloured
            // dot; click to expand the full history popup.
            Rectangle {
                id: progressPill
                visible: window.lastProgressMessage !== ""
                Layout.preferredHeight: 24
                Layout.maximumWidth: 260
                implicitWidth: progressPillRow.implicitWidth + uiTheme.spacingSm * 2
                radius: uiTheme.radiusSm
                color: startupLogPopup.visible ? uiTheme.stateHoverFill : "transparent"
                border.width: uiTheme.borderWidth
                border.color: uiTheme.stateDefaultBorder
                RowLayout {
                    id: progressPillRow
                    anchors.fill: parent
                    anchors.leftMargin: uiTheme.spacingSm
                    anchors.rightMargin: uiTheme.spacingSm
                    spacing: uiTheme.spacingXs
                    Rectangle {
                        Layout.preferredWidth: 8; Layout.preferredHeight: 8
                        radius: 4; Layout.alignment: Qt.AlignVCenter
                        color: window.progressKindColor(window.lastProgressKind)
                    }
                    Label {
                        Layout.fillWidth: true
                        text: window.lastProgressMessage
                        color: textColor
                        elide: Text.ElideRight
                        verticalAlignment: Text.AlignVCenter
                        font.pixelSize: Math.max(11, window.font.pixelSize - 1)
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: startupLogPopup.visible
                        ? startupLogPopup.close() : startupLogPopup.open()
                }
                Accessible.role: Accessible.Button
                Accessible.name: window.tr("progress.show-log", "Connection log")
                    + ": " + window.lastProgressMessage
            }
            Label {
                id: statusLineLabel
                Layout.fillWidth: true
                // Claim no width of its own: with the implicit width of a long
                // sentence as its preferred size, the label squeezed the footer
                // buttons beside it instead of eliding.
                Layout.preferredWidth: 0
                text: statusLine
                color: textColor
                elide: Text.ElideRight
                // Reveal what the line could not fit: the saved-file
                // destination after a "Save to file", or the long form of a
                // message that was shortened. HoverHandler is passive — it
                // never steals clicks.
                HoverHandler { id: statusLineHover }
                ToolTip.text: window.statusDetail !== "" ? window.statusDetail : statusLine
                ToolTip.delay: 400
                ToolTip.visible: statusLineHover.hovered && statusLine !== ""
                    && (statusLineLabel.truncated || window.statusDetail !== "")
            }
            // Bound-file "Save to file" offer: a compact, clickable orange chip
            // in the footer, raised while the table differs from the linked file.
            Rectangle {
                id: boundFileChip
                visible: window.boundFileOutOfDateBannerVisible
                Layout.preferredHeight: 24
                implicitWidth: boundFileChipRow.implicitWidth + uiTheme.spacingSm * 2
                radius: uiTheme.radiusSm
                color: Qt.rgba(uiTheme.colorWarning.r, uiTheme.colorWarning.g,
                    uiTheme.colorWarning.b, 0.16)
                border.width: uiTheme.borderWidth
                border.color: Qt.rgba(uiTheme.colorWarning.r, uiTheme.colorWarning.g,
                    uiTheme.colorWarning.b, 0.55)
                RowLayout {
                    id: boundFileChipRow
                    anchors.fill: parent
                    anchors.leftMargin: uiTheme.spacingSm
                    anchors.rightMargin: uiTheme.spacingSm
                    spacing: uiTheme.spacingXs
                    Rectangle {
                        Layout.preferredWidth: 8; Layout.preferredHeight: 8
                        radius: 4; Layout.alignment: Qt.AlignVCenter
                        color: uiTheme.colorWarning
                    }
                    Label {
                        text: window.tr("status.bound-file-save", "Save to file")
                        color: window.textColor
                        verticalAlignment: Text.AlignVCenter
                        font.pixelSize: Math.max(11, window.font.pixelSize - 1)
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true
                    onClicked: window.boundFilesController._saveBoundFilesNow()
                    ToolTip.visible: containsMouse
                    ToolTip.delay: 400
                    ToolTip.text: window.boundFilesController._boundFileChipTooltip()
                }
                Accessible.role: Accessible.Button
                Accessible.name: window.tr("status.bound-file-out-of-date",
                    "The bound rules file is out of date. Save it to keep your export in sync.")
                Accessible.description: window.tr("status.bound-file-save-description",
                    "Export the active rules back to the bound rules file.")
            }
            // Notifications centre entry point. Compact bell
            // chip with a count; opens NotificationCenterPopup. Visible only
            // when there is at least one active notice (currently the app
            // enforcement gap). Amber-tinted when a warning is present.
            Rectangle {
                id: notificationsChip
                readonly property bool warn: window.notificationTopSeverity === "warning"
                visible: window.notificationCount > 0
                Layout.preferredHeight: 24
                implicitWidth: notificationsChipRow.implicitWidth + uiTheme.spacingSm * 2
                radius: uiTheme.radiusSm
                color: notificationCenterPopup.visible
                    ? uiTheme.stateHoverFill
                    : (notificationsChip.warn
                        ? Qt.rgba(uiTheme.colorWarning.r, uiTheme.colorWarning.g,
                            uiTheme.colorWarning.b, 0.16)
                        : "transparent")
                border.width: uiTheme.borderWidth
                border.color: notificationsChip.warn
                    ? Qt.rgba(uiTheme.colorWarning.r, uiTheme.colorWarning.g,
                        uiTheme.colorWarning.b, 0.55)
                    : uiTheme.stateDefaultBorder
                RowLayout {
                    id: notificationsChipRow
                    anchors.fill: parent
                    anchors.leftMargin: uiTheme.spacingSm
                    anchors.rightMargin: uiTheme.spacingSm
                    spacing: uiTheme.spacingXs
                    Rectangle {
                        Layout.preferredWidth: 8; Layout.preferredHeight: 8
                        radius: 4; Layout.alignment: Qt.AlignVCenter
                        color: notificationsChip.warn ? uiTheme.colorWarning : uiTheme.colorAccent
                    }
                    Label {
                        text: window.tr("notifications.chip-label", "Alerts")
                            + " (" + window.notificationCount + ")"
                        color: window.textColor
                        verticalAlignment: Text.AlignVCenter
                        font.pixelSize: Math.max(11, window.font.pixelSize - 1)
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true
                    onClicked: notificationCenterPopup.visible
                        ? notificationCenterPopup.close() : notificationCenterPopup.open()
                    ToolTip.visible: containsMouse && prefs.tooltipsEnabled
                    ToolTip.delay: 400
                    ToolTip.text: window.tr("notifications.chip-tooltip",
                        "Show notifications")
                }
                Accessible.role: Accessible.Button
                Accessible.name: window.tr("notifications.title", "Notifications")
                Accessible.description: window.notificationCount + " "
                    + window.tr("notifications.title", "Notifications")
            }
            RoutingStatusChip {
                root: window
                onClicked: { window.requestSectionChange("settings") }
            }
            // Apply carries unapplied edits, so it must not look like the two
            // neutral buttons beside it: while anything is pending it takes the
            // accent fill and a slow halo, and drops back to a plain disabled
            // button the moment there is nothing left to apply. The halo is a
            // ring OUTSIDE the button so it stays visible against the accent
            // fill in the light, dark and high-contrast palettes alike.
            //
            // Gated on the SERVICE state only. Writing the rules file does not
            // dim it and must not: the file is a copy, the service is what
            // routes traffic. The tooltip says so, because a lit button after
            // a successful save otherwise reads as "the save did not work".
            ThemedButton {
                id: footerApplyButton
                theme: uiTheme
                text: tr("action.apply", "Apply")
                readonly property bool hasPendingChanges:
                    window.prefsHaveUnsavedChanges
                    || window.rulesNotAppliedToService
                enabled: footerApplyButton.hasPendingChanges
                highlighted: footerApplyButton.hasPendingChanges
                ToolTip.visible: hovered && window.prefs.tooltipsEnabled
                ToolTip.delay: 400
                ToolTip.text: !footerApplyButton.hasPendingChanges
                    ? window.tr("action.apply-tooltip-clean",
                        "Everything on screen is already applied.")
                    : (window.rulesNotAppliedToService && !window._routingBackendConnected()
                        ? window.tr("action.apply-tooltip-service-stopped",
                            "The rules on screen are not applied to the service. It is stopped, "
                            + "so Apply saves them to your rules file for now and stays available "
                            + "until the service can take them.")
                        : window.tr("action.apply-tooltip-pending",
                            "Send the changes on screen to the background service."))
                onClicked: window.applyPendingChanges()
                Rectangle {
                    z: -1
                    anchors.fill: parent
                    anchors.margins: -2
                    radius: uiTheme.radiusSm + 2
                    color: "transparent"
                    border.width: 2
                    border.color: uiTheme.colorAccent
                    visible: footerApplyButton.hasPendingChanges
                    opacity: 0
                    SequentialAnimation on opacity {
                        running: footerApplyButton.hasPendingChanges
                        loops: Animation.Infinite
                        NumberAnimation {
                            from: 0; to: 0.75; duration: 1100
                            easing.type: Easing.InOutQuad
                        }
                        NumberAnimation {
                            from: 0.75; to: 0; duration: 1100
                            easing.type: Easing.InOutQuad
                        }
                    }
                }
            }
            ThemedButton {
                theme: uiTheme
                text: tr("action.cancel", "Cancel")
                enabled: window.prefsHaveUnsavedChanges || window.rulesNotAppliedToService
                onClicked: window.cancelPendingChanges()
            }
            ThemedButton {
                theme: uiTheme
                text: tr("action.close", "Close")
                onClicked: window.close()
            }
        }
    }

    // Expandable history for the footer
    // progress pill. Themed in-overlay popup (Popup.Item), newest first.
    // Extracted to
    // components/StartupLogPopup.qml (thin-shell refactor). The log
    // ListModel is window-scoped, so it is injected via `logModel`.
    StartupLogPopup {
        id: startupLogPopup
        ownerRoot: window
        logModel: startupLogModel
    }

    // Notifications centre. Opened by the footer bell chip;
    // renders `window.activeNotifications` and routes actions/dismissal back
    // through `runNotificationAction` / `dismissNotification`.
    NotificationCenterPopup {
        id: notificationCenterPopup
        ownerRoot: window
    }

    // Backend connection status banner. Hidden when
    // `backendStatus.kind === "connected"`. Yellow when reconnecting,
    // red on terminal failure modes. The text comes from
    // `backendStatusBannerText()` which resolves locale keys.
    TopBannerStack {
        id: topBannerStack
        root: window
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        z: 100
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: uiTheme.spacingMd
        anchors.rightMargin: uiTheme.spacingMd
        anchors.bottomMargin: uiTheme.spacingMd
        anchors.topMargin: topBannerStack.totalHeight + uiTheme.spacingMd
        spacing: uiTheme.spacingMd

        NavigationSidebar { root: window }

        Pane {
            Layout.fillWidth: true
            Layout.fillHeight: true
            padding: uiTheme.spacingMd
            background: PanelSurface { theme: uiTheme; cornerRadius: uiTheme.radiusMd }

            // Lazy section loading. Previously all five
            // sections were instantiated eagerly, so every theme change /
            // font-scale step / `uiRevision` bump re-evaluated and
            // relaid-out ALL of them (the dominant cost of slow theme &
            // font interactions in debug). Each section is now wrapped in
            // a Loader that is active ONLY while it is the current page,
            // so an interaction touches just the visible section.
            //
            // Safe because: every list/data model (`rulesModel`,
            // `interfacesModel`, `logsModel`, …) lives at window scope
            // (see lines ~227), so unloading a section destroys only its
            // VIEW, never its data; and `requestSectionChange` already
            // routes through the UnsavedChangesGuard, so a dirty section
            // prompts before it can be navigated away from / unloaded.
            StackLayout {
                id: sectionStack
                anchors.fill: parent
                currentIndex: Pure.idxForSection(section)

                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: true
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { InterfacesRoutesSection { root: window } }
                }
                Loader {
                    id: rulesSectionLoader
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: true
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { RulesSection { root: window } }
                    // Pre-warm: compile RulesSection in
                    // the background shortly after startup (while the user is on
                    // the default interfaces-routes page) so the first switch to
                    // Rules is instant instead of showing a blank async-compile
                    // beat. keepLoaded then latches it loaded for the session.
                    Timer {
                        interval: 1200; running: true; repeat: false
                        onTriggered: rulesSectionLoader.keepLoaded = true
                    }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: true
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { RuleSuggestionsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: true
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { DiagnosticsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: true
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { LogsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: true
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { SettingsSection { root: window } }
                }
            }
        }
    }

    RuleEditDialog { id: ruleDialog; root: window }

    // Duplicate-rule modal. Two-button
    // pattern: "Open existing" jumps to the offending row in Edit mode;
    // "Cancel" returns to the in-progress form. Replaces the prior
    // single-line statusLine warning which the user reported was easy
    // to miss because the Save button completes without obvious feedback.
    // Extracted to
    // components/RuleDuplicateDialog.qml. The ruleDialog manipulation
    // stays here because ruleDialog is still inline (extraction deferred).
    RuleDuplicateDialog {
        id: ruleDuplicateDialog
        ownerRoot: window
        onOpenExistingRequested: function(idx) {
            ruleDialog.close()
            if (idx >= 0 && idx < rulesModel.count) {
                selectedRule = idx
                editingRule = idx
                ruleDialog.resetForEdit()
                ruleDialog.open()
            }
        }
    }

    // ── Rules review/confirm flow ───────────────
    //
    // `pendingReviewState` carries the in-flight rules-update
    // mutation context. Each successful dry-run rpcResponse populates
    // `summary` + `confirmationToken` and opens ReviewDiffDialog.
    // Apply (single-step) → second rpcMutationSubmit
    // (execute) with the same payload + token. ConfirmationExpired from
    // the execute pass → ReviewExpiredDialog → user clicks "Compare
    // again" → fresh dry-run reusing the cached payload.
    property var pendingReviewState: ({
        rulesJson: "",
        contentHash: "",
        correlationId: "",
        summary: null,
        confirmationToken: ""
    })

    // Parallel state for the PresetImport review
    // flow. Distinct from `pendingReviewState` so a rules-update
    // review in flight doesn't get clobbered by a preset-import
    // dry-run (and vice versa). `targetRoute` is the kebab slug
    // (`"primary"` / `"secondary"`); `bytesB64` is the file content
    // already base64-wrapped by the bridge's `readFileBytes`.
    property var pendingPresetImportState: ({
        targetRoute: "",
        bytesB64: "",
        sourcePath: "",
        correlationId: "",
        summary: null,
        confirmationToken: ""
    })


    /// User-triggered demo rules loader. MERGES the bundled built-in demo
    /// preset (`builtin-demo/rules_{primary,secondary}.txt`) into the
    /// existing `rulesModel`, skipping rules the user already has (by
    /// canonical id OR content signature), so a user who has been adding
    /// their own rows doesn't lose them. The merged set is then sent
    /// through the standard review flow for persistence.
    ///
    /// Sourced from the bundled preset files
    /// (single source of truth) instead of a hardcoded JS copy. The old
    /// `_buildDemoRuleRows()` hardcoded set was removed; the bundled files
    /// are parsed via the launcher's `preset.parse` RPC, the same parser
    /// used by preset import. Replaces the former duplicate "Apply built-in
    /// demo rules" button, which only worked on an empty table.
    function loadDemoRules() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.resolvePresetPath !== "function"
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            statusLine = tr("status.bridge-unavailable",
                "Service bridge not connected")
            return
        }
        var primaryPath = nrrNativeBridge.resolvePresetPath(
            "builtin-demo/rules_primary.txt")
        var secondaryPath = nrrNativeBridge.resolvePresetPath(
            "builtin-demo/rules_secondary.txt")
        var primB64 = primaryPath ? nrrNativeBridge.readFileBytes(primaryPath) : ""
        var secB64 = secondaryPath ? nrrNativeBridge.readFileBytes(secondaryPath) : ""
        if (!primB64 && !secB64) {
            statusLine = tr("status.import-read-failed",
                "Cannot read preset file. See logs for details.")
            return
        }
        // Parse primary then secondary (the parser is async over the
        // local `preset.parse` RPC), accumulate both routes' rows, then
        // merge. Ids beyond the current max so parsed rows can't collide
        // with existing ones; a final dedupe pass guarantees uniqueness.
        var startId = _maxRuleNumericId() + 1
        presetImportController._parseCanonicalRulesAsync(_b64ToUtf8(primB64), "primary", startId,
            function(primResult) {
                var primRows = (primResult && primResult.rows) || []
                var nextId = (primResult && primResult.nextId)
                    || (startId + primRows.length)
                presetImportController._parseCanonicalRulesAsync(_b64ToUtf8(secB64), "secondary", nextId,
                    function(secResult) {
                        var secRows = (secResult && secResult.rows) || []
                        _mergeDemoRowsAndReview(primRows.concat(secRows))
                    })
            })
    }

    /// Merge parsed demo rows into rulesModel
    /// (skip-by-canonical-id OR content signature against existing rows),
    /// persist their comments, then drive the review flow. Split out of
    /// `loadDemoRules` because the bundled-file parse is async.
    function _mergeDemoRowsAndReview(demoRows) {
        // Build an "identity" set across two axes so legacy IDs and
        // payload-equivalent rows don't slip through as duplicates.
        // Axis 1: canonical id (`R-` + numeric, zero-padded to 4).
        // Axis 2: rule signature (type|route|matchValue) — catches
        // rows with the same content but a totally different id.
        var existingCanonical = {}
        var existingSignatures = {}
        for (var k = 0; k < rulesModel.count; k += 1) {
            var row = rulesModel.get(k)
            var cid = Rules.canonicalRuleId(row.id)
            if (cid !== "") existingCanonical[cid] = true
            existingSignatures[Rules.ruleSignature(row)] = true
        }
        var appended = 0
        for (var i = 0; i < demoRows.length; i += 1) {
            var dRow = demoRows[i]
            var dCid = Rules.canonicalRuleId(dRow.id)
            var dSig = Rules.ruleSignature(dRow)
            if (existingCanonical[dCid] || existingSignatures[dSig]) {
                continue
            }
            dRow.aceMatchValue = _aceLowerForSearch(dRow.matchValue)
            rulesModel.append(dRow)
            // Demo rows ship with curated comments ("Russian ccTLD ZIP",
            // "Pinned to secondary", …). Persist them so they survive an
            // app restart, same as user-typed comments. Only when non-empty.
            if (String(dRow.comment || "") !== "") {
                _sidecarWriteCommentForRow(dRow)
            }
            existingCanonical[dCid] = true
            existingSignatures[dSig] = true
            appended += 1
        }
        if (appended > 0) {
            // Demo rows changed the model; recompute vs baseline.
            _recomputeRulesDirty()
        }
        // Guarantee unique ids across the merged table (the two routes are
        // numbered independently by the parser/service).
        _renumberRuleIdsSequential()
        section = "rules"
        if (appended === 0) {
            statusLine = tr("status.demo-rules-all-present",
                "All demo rules are already present. Nothing added.")
            return
        }
        statusLine = tr("status.demo-rules-loaded",
            "Demo rules loaded. Review and confirm to activate.")

        // Build canonical JSON from the CURRENT rulesModel state
        // (user rows + newly-added demo rows) so the review-flow
        // sees the merged set, not the demo set alone.
        var rulesJson = _buildRulesJsonFromModel()
        if (!rulesJson) return // serializer failed; status line already set
        var contentHash = ""
        if (typeof nrrNativeBridge.sha256Hex === "function") {
            contentHash = nrrNativeBridge.sha256Hex(rulesJson)
        } else {
            contentHash = _clientStubHash(rulesJson)
        }
        reviewFlowController.startRulesReviewFlow(rulesJson, contentHash)
    }

    /// Canonicalise an `R-NNNN` style rule id by stripping the
    /// `R-` prefix, parsing the numeric tail, and re-emitting it
    /// zero-padded to 4 digits. `R-4`, `R-04`, `R-004`, `R-0004`
    /// all collapse to `R-0004`. Non-conforming ids are returned
    /// trimmed and uppercased so unrelated id schemes don't get
    /// false collisions with each other.
    // Unicode ↔ Punycode boundary helpers.
    //
    // The GUI displays human-readable IDN forms (`рф`, `пример.рф`),
    // but the service-side WFP filter codegen and SQLite cache require
    // ACE/Punycode (`xn--p1ai`, `xn--e1afmkfd.xn--p1ai`). All host-like
    // rule values cross this boundary in two directions:
    //
    //   * GUI → service: rules-json built by `_ruleEntryToDto` must
    //     ACE-encode `zone` / `domain` / `suffix-domain` / `exact-fqdn`
    //     match values via `_aceEncodeHost`.
    //   * service → GUI: snapshot rows arriving from the service and
    //     parsed rule files must be Unicode-decoded via
    //     `_unicodeDecodeHost` before being inserted into `rulesModel`.
    //
    // ASCII hosts round-trip through both helpers unchanged so existing
    // rule sets keep working without a migration step.
    // The conversion itself lives in `components/HostAceCodec` — the tray
    // serialises rules too (to compare its files against the service) and both
    // surfaces must cross this boundary identically or the same rule set hashes
    // two different ways.
    property var hostAceCodec: HostAceCodec {}
    function _aceEncodeHost(host) {
        return hostAceCodec.encode(host)
    }
    // NOTE: `_aceEncodeHost` is handed AS A VALUE to the shared rule
    // serializer in `lib/rules.js` — a `.pragma library` scope cannot reach the
    // C++ bridge, so the encoder crosses as an argument. It is safe to pass
    // detached: it reads no `this`, and `nrrNativeBridge` resolves through the
    // QML context the function closes over.
    function _unicodeDecodeHost(host) {
        return hostAceCodec.decode(host)
    }
    // Returns the ASCII (Punycode) representation of `host` when it
    // contains non-ASCII characters, or "" otherwise. Used by the
    // Add/Edit rule dialog as an inline hint AND by `saveRule()` to
    // auto-fill the comment when the user left it blank. Distinct from
    // `_aceEncodeHost`, which passes ASCII through unchanged for the
    // wire boundary.
    function _punycodeFor(host) {
        var trimmed = String(host || "").trim()
        if (trimmed === "") return ""
        var allAscii = true
        for (var i = 0; i < trimmed.length; i += 1) {
            if (trimmed.charCodeAt(i) > 127) { allAscii = false; break }
        }
        if (allAscii) return ""
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.punycodeEncodeHost !== "function") {
            return ""
        }
        return String(nrrNativeBridge.punycodeEncodeHost(trimmed) || "")
    }

    // Precomputed lowercase ACE form stored alongside
    // `matchValue` so the rules-table search can match either the
    // Unicode value the user typed in the dialog or its Punycode
    // equivalent. Computed once per insert/edit; avoids N×M bridge
    // calls on every keystroke. ASCII inputs short-circuit through
    // `_aceEncodeHost` so for non-hostlike rules this collapses to a
    // plain `.toLowerCase()`.
    function _aceLowerForSearch(host) {
        return _aceEncodeHost(host).toLowerCase()
    }

    // Base64 → UTF-8 via native bridge (Qt's QByteArray::fromBase64 +
    // QString::fromUtf8). The legacy QML-side `decodeURIComponent(escape(
    // Qt.atob(...)))` trick throws `URIError: malformed URI sequence` on
    // some Cyrillic byte patterns and Qt.atob itself is deprecated. The
    // native helper is robust for the full UTF-8 range used by rule files.
    function _b64ToUtf8(b64) {
        if (!b64) return ""
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.decodeBase64Utf8 === "function") {
            return nrrNativeBridge.decodeBase64Utf8(String(b64))
        }
        // Fallback for preview/mock environments without the bridge.
        try {
            return decodeURIComponent(escape(Qt.atob(String(b64))))
        } catch (e) {
            console.log("_b64ToUtf8 fallback decode failed:", e)
            return ""
        }
    }

    function _maxRuleNumericId() {
        var maxN = 0
        for (var k = 0; k < rulesModel.count; k += 1) {
            var idStr = String(rulesModel.get(k).id || "")
            var m = idStr.match(/^R-(\d+)$/)
            if (m) maxN = Math.max(maxN, parseInt(m[1], 10))
        }
        return maxN
    }

    /// Renumber every rule id sequentially from
    /// R-0001 in model order. The service numbers the primary and secondary
    /// routes INDEPENDENTLY (each starting at 0), so a merged table would
    /// otherwise show duplicate ids (two R-0000) AND start at R-0000, which
    /// the user found unintuitive. A single 1-based sweep makes ids unique
    /// and human-friendly (R-0001, R-0002, …).
    ///
    /// Safe to renumber: the id is display/reference only. Selection / edit /
    /// toggle key on `masterIndex`, not the id; the service re-assigns its own
    /// ids on every import (the GUI-sent id is not authoritative); the drift
    /// canonical hash deliberately zeroes the id (`buildDriftRulesJsonForRoute`),
    /// so display ids affect neither persistence nor drift; and the sidecar
    /// comment overlay keys on the (type|value|route) signature, not the id.
    function _renumberRuleIdsSequential() {
        if (!rulesModel) return
        for (var j = 0; j < rulesModel.count; j += 1) {
            var want = "R-" + ("0000" + String(j + 1)).slice(-4)
            // Skip a redundant write when the id is already correct so we
            // don't churn bindings on rows that didn't move.
            if (String(rulesModel.get(j).id || "") !== want) {
                rulesModel.setProperty(j, "id", want)
            }
        }
    }

    // Set when an OFFLINE preset import has
    // populated rulesModel AND parked the changeset to the sidecar, but it
    // has not yet been pushed to (or refetched from) the service. Gates the
    // post-reconnect auto-refetch (`refreshBackendStatus`) so the imported
    // rules aren't clobbered by the service's (possibly empty) active
    // revision before the user can push them via the pending-apply toast.
    // Cleared once the model mirrors the service again (push applied /
    // refetch) or the parked changeset is discarded.
    property bool _offlineRulesPendingPush: false

    /// Bulk-read every stored comment, then for each
    /// row in `rulesModel` whose signature appears in the map, set
    /// `row.comment` via setProperty. Rows that are NOT in the map
    /// keep whatever comment they arrived with — preserves any
    /// legacy comment that came down on the wire.
    function _overlaySidecarCommentsOntoRulesModel() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarCommentReadAll !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSidecarCommentReadAll()
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("sidecar.comment.read-all failed:", code, msg)
                return
            }
            var map = (payload && payload.comments) || {}
            for (var i = 0; i < rulesModel.count; i += 1) {
                var row = rulesModel.get(i)
                var sig = Rules.sidecarRuleSignatureString(row)
                if (Object.prototype.hasOwnProperty.call(map, sig)) {
                    rulesModel.setProperty(i, "comment", String(map[sig] || ""))
                }
            }
        })
    }

    /// Sweep orphan sidecar comments. Builds the
    /// active-signature list from rulesModel and asks Rust to drop
    /// every comment NOT in the list. Runs once on startup and on
    /// demand from Settings → Service management. Empty signatures
    /// (rows missing type/value/route) are filtered out so we don't
    /// accidentally tell the sidecar that those wildcards are "active".
    function _gcSidecarCommentOrphans() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarCommentGc !== "function") {
            return
        }
        var active = []
        for (var i = 0; i < rulesModel.count; i += 1) {
            var p = Rules.sidecarRuleSignatureParts(rulesModel.get(i))
            if (p.type === "" || p.value === "" || p.route === "") continue
            active.push({ type: p.type, value: p.value, route: p.route })
        }
        var corr = nrrNativeBridge.rpcSidecarCommentGc(active)
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("sidecar.comment.gc failed:", code, msg)
                return
            }
            // Don't update statusLine on the auto-startup sweep —
            // would clobber other status lines. Settings → manual GC
            // calls a sister function that DOES surface the count.
        })
    }

    /// Manual variant of `_gcSidecarCommentOrphans`
    /// that surfaces the result through `statusLine`. Wired to the
    /// Settings → Service management "Clear orphan comments" button.
    function manualGcSidecarCommentOrphans() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarCommentGc !== "function") {
            statusLine = tr("status.sidecar-comments-gc-unavailable",
                "Comment sidecar is not available in this build.")
            return
        }
        var active = []
        for (var i = 0; i < rulesModel.count; i += 1) {
            var p = Rules.sidecarRuleSignatureParts(rulesModel.get(i))
            if (p.type === "" || p.value === "" || p.route === "") continue
            active.push({ type: p.type, value: p.value, route: p.route })
        }
        var corr = nrrNativeBridge.rpcSidecarCommentGc(active)
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                statusLine = tr("status.sidecar-comments-gc-failed",
                    "Failed to clear orphan comments; see logs.")
                console.log("sidecar.comment.gc failed:", code, msg)
                return
            }
            var removed = (payload && payload.removed) || 0
            statusLine = tr("status.sidecar-comments-gc-done",
                "Cleared {n} orphan comment(s).")
                .replace("{n}", String(removed))
        })
    }

    /// Best-effort persistence of one row's comment
    /// into the sidecar. Empty string deletes (Rust write_comment
    /// special-cases). Rust runs `sanitize_comment` on the way in,
    /// so we don't pre-sanitise here. Failure logs but never blocks
    /// the UI — comments are decoration, not core data.
    function _sidecarWriteCommentForRow(row) {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarCommentWrite !== "function") {
            return
        }
        var p = Rules.sidecarRuleSignatureParts(row)
        if (p.type === "" || p.value === "" || p.route === "") return
        var comment = String((row && row.comment) || "")
        var corr = nrrNativeBridge.rpcSidecarCommentWrite(
            p.type, p.value, p.route, comment)
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.log("sidecar.comment.write failed:", code, msg)
        })
    }

    /// Single-route canonical V1 envelope from `rows` filtered by `route` --
    /// the payload fed to `local.canonical-rules-hash` for the per-route drift
    /// compare. The transform itself lives in `lib/rules.js`, shared with the
    /// tray (which compares its rules files against the service on its own);
    /// the window only supplies the ACE encoder, because a `.pragma library`
    /// scope cannot reach the C++ bridge.
    /// ВАЖНО: id ВСЕГДА пустой. Канонический хэш (rules_json.rs) включает
    /// поле `id`, но лаунчер при разборе файла и служба при импорте присваивают
    /// правилам РАЗНЫЕ id. Если оставить реальный id, «файл» и «служба» дают
    /// разные хэши при одинаковых по смыслу правилах → ложный баннер
    /// расхождения после каждого импорта пресета. Drift сравнивает только
    /// маршрутную семантику (тип/значение/маршрут/включено), поэтому id здесь
    /// не нужен. Комментарий тоже отбрасывается: заметка пользователя — не
    /// изменение маршрутизации.
    function _buildRulesJsonForRoute(rows, route) {
        return Rules.buildDriftRulesJsonForRoute(rows, route, _aceEncodeHost)
    }

    /// Convenience helper: pull rulesModel rows into
    /// a plain JS array so the same `_buildRulesJsonForRoute` works
    /// for both the live model and arbitrary parser output.
    function _rulesModelToRowArray() {
        var rows = []
        for (var i = 0; i < rulesModel.count; i += 1) {
            rows.push(rulesModel.get(i))
        }
        return rows
    }

    /// Net-change dirty detection for
    /// the rules section. The baseline is the canonical,
    /// order/id/comment-independent signature of the rules as last loaded
    /// from (or applied to) the service. `_recomputeRulesDirty()` re-derives
    /// the live signature after every edit and marks the section dirty ONLY
    /// when it actually differs — so toggling a rule off and back on (net no
    /// change) no longer leaves a false "unsaved changes" state. It reuses the
    /// drift canonicalisation (`_buildRulesJsonForRoute` — order-stable, id
    /// zeroed, comments excluded), so "dirty" means exactly "routing content
    /// differs from what the service has". Comments are deliberately excluded:
    /// they live in the sidecar and are persisted immediately on Save, so they
    /// never need the unsaved-changes guard.
    /// The baseline is kept PER ROUTE so an edit can be attributed to the
    /// route it touched — the bound-file reminder is per route.
    property string _rulesDirtyBaselinePrimary: ""
    property string _rulesDirtyBaselineSecondary: ""
    function _captureRulesDirtyBaseline() {
        var rows = _rulesModelToRowArray()
        _rulesDirtyBaselinePrimary = _buildRulesJsonForRoute(rows, "primary")
        _rulesDirtyBaselineSecondary = _buildRulesJsonForRoute(rows, "secondary")
        _rulesGuardAcknowledged = false
        setUnsavedChanges("rules", false)
    }
    function _recomputeRulesDirty() {
        // A fresh edit re-arms the guard the user waved through earlier.
        _rulesGuardAcknowledged = false
        var rows = _rulesModelToRowArray()
        var primaryDirty =
            _buildRulesJsonForRoute(rows, "primary") !== _rulesDirtyBaselinePrimary
        var secondaryDirty =
            _buildRulesJsonForRoute(rows, "secondary") !== _rulesDirtyBaselineSecondary
        setUnsavedChanges("rules", primaryDirty || secondaryDirty)
        // A rule edited in the GUI makes its .txt stale the moment the edit
        // lands — the file still holds the pre-edit rules. These flags used to
        // be raised only by an activation, so the footer "Save to file" chip
        // appeared a whole apply-cycle late. Raise-only: clearing belongs to
        // the paths that reconcile against the file on disk (`_writeTargets` /
        // `_reconcileBoundFileDirty`), which compare content and therefore
        // self-heal a net-zero edit. Raised with or without a linked file —
        // the save gesture asks for a path when there is none.
        if (primaryDirty) _filesSyncDirtyPrimary = true
        if (secondaryDirty) _filesSyncDirtySecondary = true
        // Nothing can be applied while the service is down, so remember the
        // edit on disk: the post-connect question is then asked from a marker
        // that outlives this window.
        if (!_routingBackendConnected()) _offlineRulesMarkerTimer.restart()
    }

    // Debounced so that typing a rule does not write the sidecar on every
    // keystroke; only the settled table is remembered.
    Timer {
        id: _offlineRulesMarkerTimer
        interval: 2000
        repeat: false
        onTriggered: window._writeOfflineRulesMarker()
    }
    function _writeOfflineRulesMarker() {
        if (_routingBackendConnected()) return
        if (!rulesNotAppliedToService) return
        var json = _buildRulesJsonFromModel()
        if (!json) return
        var hash = (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function")
            ? nrrNativeBridge.sha256Hex(json) : ""
        _parkPendingApply(json, hash, rulesModel ? rulesModel.count : 0)
    }

    /// Let the UnsavedChangesGuard offer
    /// "Apply" for the rules section. The rules Save is a multi-step
    /// review→confirm→activate chain the user can abort, so it used to be left
    /// unregistered (the guard showed only Discard/Cancel). We register a
    /// window-scope save callback (so it works even when RulesSection is
    /// lazily unloaded) that drives that same pipeline and resumes the pending
    /// navigation on a successful activation; any abort/failure releases the
    /// guard WITHOUT navigating. `_guardRulesResume` carries the guard's
    /// onDone(ok) continuation across the async chain (it is also re-enabled
    /// by Cancel/Discard, which stay live while a save is in flight).
    property var _guardRulesResume: null
    /// Build canonical rules-json from the current `rulesModel`
    /// state. Same shared serializer `RulesSection._buildRulesJson` uses, so
    /// the two payloads are byte-identical for identical rules; it lives here
    /// so non-section call sites can reuse it without crossing the section
    /// boundary.
    function _buildRulesJsonFromModel() {
        try {
            var primary = []
            var secondary = []
            for (var i = 0; i < rulesModel.count; i += 1) {
                var entry = rulesModel.get(i)
                // A "block" rule nominally lives in the secondary bucket; its
                // `action:"block"` field (set by the serializer) overrides routing.
                var bucket = (entry.targetRoute === "secondary" || entry.targetRoute === "block")
                    ? secondary : primary
                bucket.push(Rules.ruleRowToWireDto(entry, _aceEncodeHost))
            }
            return JSON.stringify({
                "schema-version": 1,
                "primary": primary,
                "secondary": secondary
            })
        } catch (err) {
            // A throw here would otherwise silently kill every save/review/
            // park flow that depends on the rules payload. Surface it and
            // return a falsy value so callers can bail out cleanly.
            console.error("_buildRulesJsonFromModel: rules serialization failed:", err)
            statusLine = tr("status.rules-serialize-failed",
                "Internal error while preparing rules — see logs")
            return ""
        }
    }

    /// Probe whether the running launcher/Qt-host process is elevated.
    /// Used to render a warning banner in ReviewDiffDialog when the
    /// user is about to walk a flow that will fail at activate-time
    /// with `forbidden`. Defaults to `true` (no warning) when the
    /// bridge isn't wired so preview/mock modes don't get false
    /// positives.
    /// True once a privileged mutation has
    /// succeeded this session while the GUI itself is NOT elevated, i.e. the
    /// launcher's session elevation broker obtained administrator approval
    /// (one UAC) and is relaying mutations. Drives the review banner text:
    /// "not admin, will prompt once" → "temporary admin granted for this
    /// session". Resets on app restart (the broker dies with the app) OR when
    /// the user explicitly revokes it via `revokeAdminApproval()`.
    property bool _brokerSessionElevated: false

    // Which review flow currently owns the shared
    // `reviewDiffDialog` instance. Used by `_retryReviewFlow` to dispatch
    // and by `reviewDiffDialog.onApproved` to pick the right
    // `_execute*Activation` callback (single-step apply).
    // Set by `startRulesReviewFlow` / `startPresetImportReviewFlow`.
    property string _activeReviewKind: "rules-update"

    ReviewDiffDialog {
        id: reviewDiffDialog
        ownerRoot: window
        // Single-step apply. The review
        // dialog now applies directly: the separate ConfirmActivateDialog
        // hop was removed and its Critical-risk acknowledgement checkbox
        // moved into ReviewDiffDialog. Dispatch by active flow kind — the
        // two pending-state structs (rules-update vs preset-import) carry
        // the confirmation token issued on the dry-run pass.
        onApproved: {
            var state = (_activeReviewKind === "preset-import")
                ? pendingPresetImportState
                : pendingReviewState
            var token = state.confirmationToken
            if (_activeReviewKind === "preset-import") {
                presetImportController._executePresetImportActivation(token)
            } else if (_activeReviewKind === "rules-reset-to-baseline") {
                // Reset shares the review dialog.
                reviewFlowController._executeResetToBaselineActivation(token)
            } else {
                reviewFlowController._executeRulesActivation(token)
            }
        }
        // User clicked "Apply…" in the read-only preview. Leave preview and
        // re-enter the standard rules review flow with the very payload the
        // preview was built from; that re-runs the dry-run and re-opens this
        // dialog Apply-enabled.
        onPreviewApplyRequested: {
            var p = _pendingPreviewPayload
            _pendingPreviewPayload = null
            if (p) reviewFlowController.startRulesReviewFlow(p.rulesJson, p.contentHash)
        }
        onCancelled: {
            // User dismissed the review dialog; release the guard
            // (if it drove this apply) so its Save button re-enables and the
            // user can Cancel/Discard. No-op for non-guard flows.
            reviewFlowController._resolveGuardRulesApply(false)
        }
    }
    // Full reset: strong destructive confirm
    // (acknowledgement checkbox gates the action) → window.fullReset().
    // Extracted to
    // components/FullResetConfirmDialog.qml (thin-shell refactor).
    FullResetConfirmDialog {
        id: fullResetConfirmDialog
        ownerRoot: window
        onConfirmed: window.fullReset()
    }
    // Full reset complete → offer to close
    // the program + tray so the reset takes effect on next launch.
    // Extracted to
    // components/FullResetCompleteDialog.qml.
    FullResetCompleteDialog {
        id: fullResetCompleteDialog
        ownerRoot: window
        onCloseAllRequested: window._fullResetCloseAll()
    }
    // Generic informational alert. Used by
    // `showNotice(title, body)`; e.g. an "Apply" with no pending changes
    // surfaces a clear notice instead of an empty review dialog.
    InfoNoticeDialog {
        id: infoNoticeDialog
        ownerRoot: window
    }
    // Preset import review (duplicates +
    // unknown sections). Opens when the parser surfaces decisions
    // the user has to make. See `_handlePresetParseResolved` for
    // how the user's choices are folded back into the import.
    PresetImportReviewDialog {
        id: presetImportReviewDialog
        ownerRoot: window
        onApproved: function(decisions) {
            presetImportController._applyPresetReviewDecisions(decisions)
        }
        onCancelled: {
            // User aborted — discard the pending parse result; the
            // caller's `onComplete` callback is never invoked, so no
            // status banner update / sidecar write happens.
            _pendingPresetReview = null
            statusLine = tr("status.preset-review-cancelled",
                "Preset import cancelled by user.")
        }
    }

    /// In-flight review state captured between the parser callback
    /// and the user's decision in `PresetImportReviewDialog`. `null`
    /// when no review is pending. Kept on `root` (not as a closure)
    /// so the dialog's signal handlers can reach it.
    property var _pendingPresetReview: null

    ReviewExpiredDialog {
        id: reviewExpiredDialog
        ownerRoot: window
        onRetry: reviewFlowController._retryReviewFlow()
        onCancelled: { /* no-op */ }
    }
    // Service install wizard. Fires at first-launch
    // when the service isn't registered yet AND the user hasn't burnt
    // through the UAC re-prompt budget (3 declines).
    FirstLaunchInstallDialog {
        id: firstLaunchInstallDialog
        ownerRoot: window
        onInstallRequested: {
            if (typeof nrrServiceController !== "undefined"
                    && nrrServiceController) {
                nrrServiceController.installService()
            }
            // After the install attempt completes (success OR UAC
            // declined), continue into the preset wizard.
            openChildWindow(firstRunWindow)
        }
        onSkipRequested: {
            // User explicitly chose preview mode; continue into the
            // preset wizard so they can pick demo / file / empty.
            openChildWindow(firstRunWindow)
        }
        onLearnMoreRequested: {
            // Single source of truth — same URL the About dialog uses
            // (seeded from `nrr_shared::ShellAbout::project_url` via
            // ui_surface.rs).
            var url = String((context.about || {}).projectUrl || "")
            if (url !== "") {
                Pure.openExternalUrl(url)
            }
        }
    }

    // EULA acceptance gate — shown on first launch (and on agreement-version
    // bumps) before every other startup dialog. Accept persists
    // `acceptedEulaVersion` and proceeds into the normal startup chain; decline
    // (or closing the window) quits the app.
    EulaAgreementWindow {
        id: eulaAgreementWindow
        ownerRoot: window
        agreementText: String(((window.context || {}).eula || {}).text || "")
        textRu: String(((window.context || {}).eula || {}).textRu || "")
        textEn: String(((window.context || {}).eula || {}).textEn || "")
        defaultLanguage: String(((window.context || {}).eula || {}).defaultLanguage || "en")
        agreementVersion: (((window.context || {}).eula || {}).currentVersion | 0)
        onAccepted: {
            var prefsPatch = { acceptedEulaVersion: eulaAgreementWindow.agreementVersion }
            // If the user read (and accepted) the agreement in a language other
            // than the one currently selected in the app, switch the app to it.
            var acceptedLang = eulaAgreementWindow.effectiveLanguage
            var languageSwitched = acceptedLang !== ""
                    && acceptedLang !== window.resolveLanguageId(window.prefs.language)
            if (languageSwitched) {
                prefsPatch.language = acceptedLang
            }
            window.updatePrefs(prefsPatch)
            window.emitPrefs()
            // The tray resolves its labels once at spawn, so a language picked
            // here needs the same restart the Settings switch does.
            if (languageSwitched) {
                window.restartTrayForLanguageChange()
            }
            window.logProgress(window.tr("progress.eula-accepted",
                "License agreement accepted."), "info")
            window._runPostEulaStartup()
        }
        onDeclined: {
            window.logProgress(window.tr("progress.eula-declined",
                "License agreement declined — exiting."), "warn")
            Qt.quit()
        }
    }

    UacRequiredDialog {
        id: uacRequiredDialog
        ownerRoot: window
    }

    // "administrator required" advisory shown when a non-elevated
    // GUI tries to apply a mutation (apply / clear / preset-import). Applying
    // routing policy edits WFP filters, which the service only accepts from an
    // elevated client; without admin the submit fails (and currently surfaces
    // as a misleading "service unavailable"). We catch it up front and tell the
    // user exactly what to do. Read-only viewing keeps working without admin.
    // `adminRequiredDialog` removed. The
    // session elevation broker now handles a non-admin Apply transparently
    // (one UAC), so the pre-emptive "run as administrator" gate that opened
    // this dialog is gone (`_guardMutationElevation` always proceeds now).

    // Global progress feed for service install/start/stop/
    // uninstall/restart. Lives at the window level (not in the Settings
    // panel) so the footer progress pill reflects operations triggered from
    // ANY surface — the first-launch install dialog, the "service not
    // running" gate, the tray, or the Settings panel. The controller keeps
    // `busy` true across chained legs and raises `operationStarted` once per
    // leg, so a restart logs "Stopping…" → "Stopped." → "Starting…" →
    // "Started." as distinct steps.
    Connections {
        target: (typeof nrrServiceController !== "undefined" && nrrServiceController)
            ? nrrServiceController : null
        ignoreUnknownSignals: true
        function onOperationStarted(operation) {
            window.logProgress(
                window.tr("progress.service-" + String(operation) + "-running",
                    String(operation) + "…"),
                "progress")
        }
        function onOperationCompleted(operation, success, errorMessage) {
            if (success) {
                window.logProgress(
                    window.tr("progress.service-" + String(operation) + "-ok",
                        String(operation)),
                    "success")
            } else {
                window.logProgress(
                    window.tr("progress.service-failed", "Service operation failed")
                        + " (" + String(operation) + "): " + String(errorMessage || ""),
                    "error")
            }
        }
        function onUacDeclined(operation) {
            window.logProgress(
                window.tr("progress.service-uac-declined",
                    "Administrator prompt declined — operation cancelled."),
                "warn")
        }
        // A service action succeeded through the
        // session elevation broker (non-elevated GUI), so the elevated session
        // is now live. Mark it: the review banner stops warning "will prompt
        // once" and the sidebar "revoke administrator approval" control appears.
        function onBrokerSessionEstablished() {
            if (!reviewFlowController._isAppElevated()) window._brokerSessionElevated = true
        }
    }

    // Confirm before "Load active rules
    // from service" (RulesSection toolbar) discards unsaved local edits.
    // In-overlay themed popup (popupType: Popup.Item), same idiom as the
    // other dialogs.
    ReloadFromServiceConfirmDialog {
        id: reloadFromServiceConfirmDialog
        ownerRoot: window
        onConfirmed: _refreshRulesFromService({ silent: false })
    }

    // Warn before an additional adapter that has no way out to the network is
    // put in charge of the additional route, or before leak protection is armed
    // over such an adapter. Confirming proceeds exactly as before; cancelling
    // leaves the previous state untouched.
    UnroutableSecondaryConfirmDialog {
        id: unroutableSecondaryConfirmDialog
        ownerRoot: window
        onConfirmed: {
            var proceed = unroutableSecondaryConfirmDialog.pendingAction
            unroutableSecondaryConfirmDialog.pendingAction = null
            unroutableSecondaryConfirmDialog.pendingCancelAction = null
            if (typeof proceed === "function") proceed()
        }
        onCancelled: {
            var abort = unroutableSecondaryConfirmDialog.pendingCancelAction
            unroutableSecondaryConfirmDialog.pendingAction = null
            unroutableSecondaryConfirmDialog.pendingCancelAction = null
            if (typeof abort === "function") abort()
        }
    }

    // Warn before an empty service state wipes the GUI rule list.
    EmptyServiceRulesConfirmDialog {
        id: emptyServiceRulesConfirmDialog
        ownerRoot: window
        onConfirmed: {
            var opts = Object.assign({}, window._pendingEmptyReloadOpts || {})
            opts.confirmedEmpty = true
            _refreshRulesFromService(opts)
        }
        // The user picked "Apply application state" from this very
        // dialog instead of clearing. Drop the pending empty-reload (so nothing
        // re-wipes rulesModel afterwards) and push the current GUI rules to the
        // empty service via the existing review/apply flow.
        onApplyAppStateRequested: {
            window._pendingEmptyReloadOpts = ({})
            driftController._driftApplyGuiState()
        }
    }

    // The single post-connect question: rules AND routing settings that were
    // changed while the service was stopped, collected by
    // `_startOfflineBacklogCollect` and offered once.
    OfflineBacklogDialog {
        id: offlineBacklogDialog
        ownerRoot: window
        onApplyAllRequested: {
            // Settings first (one RPC, no further prompts), then the rules
            // review flow, which owns the rest of the interaction.
            if (offlineBacklogDialog.settingsRows.length > 0) {
                offlinePendingController._applyOfflinePending()
            }
            if (offlineBacklogDialog.rulesPending) {
                _clearPendingApplyPark()
                reviewFlowController._guardApplyRules(function(ok) {
                    driftController._driftRecheckNow()
                })
            }
        }
        onDiscardAllRequested: {
            if (offlineBacklogDialog.settingsRows.length > 0) {
                offlinePendingController._discardOfflinePending()
            }
            if (offlineBacklogDialog.rulesPending) {
                _offlineRulesPendingPush = false
                _clearPendingApplyPark()
                statusLine = tr("status.pending-apply-discarded",
                    "Parked changes discarded.")
            }
        }
        // "Later" and any dismissal keep everything parked; the next connect
        // asks again.
        onLaterRequested: { /* nothing to undo — the parks are untouched */ }
        onPreviewRulesRequested: window._previewCurrentRulesAgainstService()
        // The guard flag only means "an offer is on screen", so any close
        // re-arms the offer.
        onClosed: offlinePendingController._offlinePendingDialogActive = false
    }

    // VPN-client onboarding. Captures WHICH installed/
    // running program the user treats as their VPN so its traffic keeps flowing
    // over the primary link while leak protection is on (an
    // "Application -> primary route" rule is already a kill-switch exemption).
    // Opened from `openVpnOnboarding()` (Settings -> Routing -> Leak protection).
    VpnOnboardingDialog {
        id: vpnOnboardingDialog
        ownerRoot: window
        onVpnConfirmed: function(displayName, exePath) {
            // Single add (the manual file picker). We store the confirmed
            // executable as a device-local preference (the offline display
            // fallback) AND write it to the service-side SSOT via
            // route.link-provider.set below — that write registers the per-app
            // kill-switch exemption and triggers a server-side recompile, which
            // supersedes the old "make it an Application->primary rule" intent.
            var path = String(exePath || "")
            window.updatePrefs({
                confirmedVpnExePath: path,
                confirmedVpnExePaths: path
            })
            window.emitPrefs()
            var shownName = String(displayName || "")
            window.statusLine = (path !== "")
                ? window.tr("vpn-onboarding.confirmed-status",
                    "NetRuleRouter will keep {name} working over your main link while leak protection is on.")
                    .replace("{name}", shownName)
                : window.tr("vpn-onboarding.confirmed-status-no-path",
                    "Noted {name} as your VPN. Pick its program file to finish setup.")
                    .replace("{name}", shownName)
            if (path !== "") {
                var lpName = (shownName !== "")
                    ? shownName
                    : String(path.split(/[\\/]/).pop() || "")
                window._writeLinkProviderSet([{ "exe-path": path, "display-name": lpName }])
            }
        }
        onVpnConfirmedMulti: function(displayNames, exePaths) {
            // Multi-select confirm: persist the FULL set of confirmed VPN
            // executables (semicolon-joined) and mirror the first non-empty path
            // into the single-path preference for back-compat with readers like
            // Settings -> Routing's VPN-client display (the offline fallback).
            // The same set is written to the service-side SSOT via
            // route.link-provider.set below (per-app kill-switch exemptions +
            // server-side recompile), superseding the old "Application->primary
            // rules" intent.
            var names = displayNames || []
            var raw = exePaths || []
            var paths = []
            var lpApps = []
            for (var i = 0; i < raw.length; i += 1) {
                var p = String(raw[i] || "")
                if (p !== "") {
                    paths.push(p)
                    var nm = String((i < names.length ? names[i] : "") || "")
                    if (nm === "") nm = String(p.split(/[\\/]/).pop() || "")
                    lpApps.push({ "exe-path": p, "display-name": nm })
                }
            }
            window.updatePrefs({
                confirmedVpnExePaths: paths.join(";"),
                confirmedVpnExePath: paths.length > 0 ? paths[0] : ""
            })
            window.emitPrefs()
            window._writeLinkProviderSet(lpApps)
            if (paths.length > 1) {
                window.statusLine = window.tr("vpn-onboarding.confirmed-status-multi",
                    "NetRuleRouter will keep your {count} VPN programs working over your main link while leak protection is on.")
                    .replace("{count}", String(paths.length))
            } else if (paths.length === 1) {
                window.statusLine = window.tr("vpn-onboarding.confirmed-status",
                    "NetRuleRouter will keep {name} working over your main link while leak protection is on.")
                    .replace("{name}", String(names.length > 0 ? names[0] : ""))
            } else {
                // Everything selected was name-only (no resolved path).
                window.statusLine = window.tr("vpn-onboarding.confirmed-status-no-path",
                    "Noted {name} as your VPN. Pick its program file to finish setup.")
                    .replace("{name}", String(names.length > 0 ? names[0] : ""))
            }
        }
        onSkipped: {
            window.statusLine = window.tr("vpn-onboarding.skipped-status",
                "No VPN set up. You can set one up later from Settings -> Routing.")
        }
        onManualPickRequested: {
            // The dialog opens a native file picker itself; this
            // just notes the action in the status line.
            window.statusLine = window.tr("vpn-onboarding.manual-pick-status",
                "Choose your VPN program file…")
        }
    }

    // App-group routing dialog. Scans installed/running programs,
    // groups them into popular categories, and lets the user send a whole group
    // over primary (default) or secondary. On confirm, only the secondary
    // assignments materialize application rules; primary removes any prior rule
    // for that exe (see `_applyAppGroupRoutes`). Opened via `openAppGroupRouting()`.
    AppGroupRoutingDialog {
        id: appGroupRoutingDialog
        ownerRoot: window
        onAppGroupRoutesConfirmed: function(assignments) {
            window._applyAppGroupRoutes(assignments)
        }
        onSkipped: { /* no-op; user closed the dialog without applying */ }
    }

    // Gate dialog opened before the review-flow when
    // the service isn't connected. Three outcomes wired below: start /
    // install (escalates UAC, then re-arms the offline wait timer);
    // park to sidecar; cancel.
    ServiceNotRunningDialog {
        id: serviceNotRunningDialog
        ownerRoot: window
        onStartServiceRequested: {
            if (typeof nrrServiceController !== "undefined"
                    && nrrServiceController) {
                nrrServiceController.startService()
            }
            _armOfflineServiceStartTimer()
        }
        onInstallServiceRequested: {
            if (typeof nrrServiceController !== "undefined"
                    && nrrServiceController) {
                nrrServiceController.installService()
            }
            // The UAC-elevated installService also starts the service
            // on success. Wait for the same connect window — if UAC
            // is declined, the timer expires and we surface the same
            // failure message.
            _armOfflineServiceStartTimer()
        }
        onWorkWithoutServiceRequested: {
            if (!_pendingOfflinePark) return
            var p = _pendingOfflinePark
            _parkPendingApply(p.rulesJson, p.contentHash, p.totalRules)
            _pendingReviewAfterConnect = null
            _pendingOfflinePark = null
            statusLine = tr(
                "status.pending-apply-parked",
                "Changes parked. They will be applied when the service is running again.")
            // Dirty flag intentionally kept — close-guard still warns
            // the user even though the work is persisted in sidecar.
            // The status banner above signals the parked-state.
        }
        // Saving the rules to disk needs no service at all, so the gate offers
        // it: the user's work is kept even when the service will not start.
        onSaveToFileRequested: {
            _pendingReviewAfterConnect = null
            _pendingOfflinePark = null
            boundFilesController.saveRulesToFiles(true, null)
        }
        onCancelled: {
            _pendingReviewAfterConnect = null
            _pendingOfflinePark = null
        }
    }

    // Drift detection dialog. Opened from the
    // amber drift banner. The four resolution paths are wired below
    // to existing flows (preset import, review-flow, snapshot
    // rollback) so this stays a thin dispatcher with no business
    // logic of its own.
    DriftDetectionDialog {
        id: driftDetectionDialog
        ownerRoot: window
        primaryDetails:       window._driftDetailsPrimary
        secondaryDetails:     window._driftDetailsSecondary
        fileExistsPrimary:    window._driftFileExistsPrimary
        fileExistsSecondary:  window._driftFileExistsSecondary
        onLoadFromFileRequested:        driftController._driftLoadFromFile()
        onApplyGuiStateRequested:       driftController._driftApplyGuiState()
        onAcceptServiceStateRequested:  driftController._driftAcceptServiceState()
        onShowDiffRequested:            driftController._driftShowDiff()
        onClearAllRequested:            driftClearAllConfirmDialog.open()
        onCancelled:                    { /* banner stays */ }
    }

    // Destructive confirm for the drift
    // dialog's "Clear everything". Mirrors the full-reset confirm: an
    // acknowledgement checkbox gates the action, which wipes all rules
    // locally and pushes an empty revision to the service.
    DriftClearAllConfirmDialog {
        id: driftClearAllConfirmDialog
        ownerRoot: window
        onConfirmed: driftController._driftClearAll()
    }

    // File↔service merge review dialog. Opened from the quiet
    // "Merge available" banner. Renders the `rules.merge-preview` buckets +
    // per-conflict picks; on confirm the caller re-runs the op with the picks
    // and hands the merged rules-json to the standard review + apply flow.
    MergeReviewDialog {
        id: mergeReviewDialog
        ownerRoot: window
        onCancelled: { /* banner stays until resolved */ }
        onConfirmed: function(resolutions) { driftController._applyMerge(resolutions) }
    }

    /// Read-only diff of the rules ON SCREEN against the service's active
    /// revision. Shared by the post-connect dialog's "Preview" and any other
    /// "what would this change?" affordance — always the current table, never
    /// a stored copy.
    function _previewCurrentRulesAgainstService() {
        var rulesJson = _buildRulesJsonFromModel()
        if (!rulesJson) return
        var contentHash =
            (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function")
                ? nrrNativeBridge.sha256Hex(rulesJson)
                : ("client-stub-" + String(Date.now()))
        _openPendingApplyPreview(rulesJson, contentHash)
    }

    /// In-flight state captured between
    /// `startOfflineApplyFlow` opening the gate dialog and the user's
    /// pick. Holds `{rulesJson, contentHash, totalRules}`.
    property var _pendingOfflinePark: null

    /// Set when the user picks Start/Install Service
    /// from the gate dialog. Holds `{rulesJson, contentHash}` so the
    /// next connect-success can resume into the standard review flow
    /// without losing the work the user wanted to apply.
    property var _pendingReviewAfterConnect: null

    Timer {
        id: offlineServiceStartTimer
        // Spec: 10 s. Plenty for SCM to flip Stopped→Running on a
        // healthy machine; if the install also runs, UAC consent
        // itself often takes longer, so we don't bother extending.
        interval: 10000
        repeat: false
        onTriggered: {
            if (!_pendingReviewAfterConnect) return
            // Connection didn't come back within the window. The
            // launcher's IPC client keeps retrying in the background and the
            // post-connect backlog dialog can still fire when it does
            // eventually connect — so park the changes here too.
            var p = _pendingReviewAfterConnect
            _pendingReviewAfterConnect = null
            _parkPendingApply(p.rulesJson, p.contentHash, p.totalRules || 0)
            statusLine = tr(
                "status.pending-apply-timeout",
                "Could not connect to the service. Changes parked; see logs for details.")
        }
    }

    function _armOfflineServiceStartTimer() {
        // Promote _pendingOfflinePark → _pendingReviewAfterConnect:
        // the user chose to start the service, so on the next connect
        // we resume into the review flow with the captured payload.
        if (_pendingOfflinePark) {
            _pendingReviewAfterConnect = {
                rulesJson:   _pendingOfflinePark.rulesJson,
                contentHash: _pendingOfflinePark.contentHash,
                totalRules:  _pendingOfflinePark.totalRules
            }
            _pendingOfflinePark = null
        }
        offlineServiceStartTimer.restart()
        statusLine = tr(
            "status.pending-apply-waiting",
            "Waiting for the service to come online…")
    }

    function _parkPendingApply(rulesJson, contentHash, totalRules) {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarPendingApplyWrite !== "function") {
            console.log("pending-apply: bridge unavailable, cannot park")
            return
        }
        // Offline park has no dry-run summary. We store a minimal
        // shape — total rule count — and let the post-connect toast
        // render through the offline-summary locale key. The kebab-
        // case keys mirror the read shape so future code can grow
        // the dry-run summary into the same field without a schema
        // change.
        var summaryJson = JSON.stringify({
            "rules-added":    [],
            "rules-removed":  [],
            "rules-modified": [],
            "total-rules":    parseInt(totalRules || 0)
        })
        var corr = nrrNativeBridge.rpcSidecarPendingApplyWrite(
            String(rulesJson || ""), summaryJson, String(contentHash || ""))
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("pending-apply.write failed:", code, msg)
                statusLine = tr("status.pending-apply-park-failed",
                    "Failed to park changes locally; see logs.")
            }
        })
    }

    /// Entry point used by `RulesSection._triggerReviewFlow`
    /// when the backend isn't connected. Reads the sidecar to detect a
    /// stale park, then opens `ServiceNotRunningDialog`.
    function startOfflineApplyFlow(rulesJson, contentHash) {
        var totalRules = rulesModel ? rulesModel.count : 0
        _pendingOfflinePark = {
            rulesJson:   String(rulesJson || ""),
            contentHash: String(contentHash || ""),
            totalRules:  totalRules
        }
        // Default the dialog: no stale, status-slug unknown. Override
        // synchronously when the bridge responds (small race but the
        // dialog is non-blocking until the user clicks).
        serviceNotRunningDialog.stalePendingExists  = false
        serviceNotRunningDialog.stalePendingAdded   = 0
        serviceNotRunningDialog.stalePendingRemoved = 0
        serviceNotRunningDialog.stalePendingModified = 0
        serviceNotRunningDialog.serviceStatusSlug = _serviceStatusSlug()
        if (typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge
                && typeof nrrNativeBridge.rpcSidecarPendingApplyRead === "function") {
            var corr = nrrNativeBridge.rpcSidecarPendingApplyRead()
            rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
                if (!ok) return
                var entry = p && p.entry
                if (!entry) return
                if (String(entry["content-hash"] || "") === String(contentHash || "")) {
                    // Same payload already parked — no warning needed.
                    return
                }
                var counts = Pure.parsePendingSummaryCounts(entry["summary-json"])
                serviceNotRunningDialog.stalePendingExists   = true
                serviceNotRunningDialog.stalePendingAdded    = counts.added
                serviceNotRunningDialog.stalePendingRemoved  = counts.removed
                serviceNotRunningDialog.stalePendingModified = counts.modified
            })
        }
        serviceNotRunningDialog.open()
    }

    function _serviceStatusSlug() {
        if (typeof nrrServiceController === "undefined"
                || nrrServiceController === null) {
            return ""
        }
        switch (parseInt(nrrServiceController.status)) {
            case 1: return "not-installed"
            case 2: return "stopped"
            case 3: return "start-pending"
            case 4: return "running"
            default: return ""
        }
    }

    /// Decide whether the red banner's action button
    /// should Install or Start the service. The decision MUST come from the
    /// live SCM status (nrrServiceController), NOT backendStatus.kind:
    /// refreshBackendStatus() collapses every runtime failure to
    /// "disconnected"/"connecting" and never re-derives the stopped vs
    /// not-installed slug. Fall back to backendStatus.kind only when the SCM
    /// status is still unknown (cold-start before the first refreshStatus()).
    function _bannerServiceAction() {
        var slug = _serviceStatusSlug()
        if (slug === "not-installed") return "install"
        if (slug === "stopped" || slug === "running"
                || slug === "start-pending") return "start"
        return ((backendStatus || {}).kind) === "service-not-installed"
            ? "install" : "start"
    }

    /// Start (or install+start) the service straight from
    /// the red banner. installService() auto-chains to start on success; both
    /// route through the session-elevation broker (one UAC per session, or none
    /// when already elevated / the DemandStart SERVICE_START grant is held). The
    /// 3 s backendStatusPoll re-probes and clears the banner on reconnect; we
    /// also nudge refreshBackendStatus() now for snappier feedback. No launcher
    /// restart is needed — the NamedPipeIpcClient worker reconnects on its own.
    function _startServiceFromBanner() {
        if (typeof nrrServiceController === "undefined"
                || !nrrServiceController) {
            return
        }
        if (_bannerServiceAction() === "install") {
            nrrServiceController.installService()
        } else {
            nrrServiceController.startService()
        }
        statusLine = tr("diag.status.service-starting", "Service starting...")
        logProgress(tr("diag.status.service-starting", "Service starting..."),
            "progress")
        Qt.callLater(refreshBackendStatus)
    }

    /// Show a simple modal alert. Thin wrapper over `infoNoticeDialog` so any
    /// flow can surface a plain notice without wiring its own dialog.
    function showNotice(title, body) {
        infoNoticeDialog.noticeTitle = String(title || "")
        infoNoticeDialog.noticeBody = String(body || "")
        infoNoticeDialog.open()
    }

    /// Ask the user to confirm a choice that puts an adapter with no way out to
    /// the network in charge of the additional route. `row` is a mapped
    /// interface row, `contextSlug` is "assign" or "kill-switch", and
    /// `onProceed` / `onCancel` are plain callbacks. The caller decides what
    /// happens; this only owns the wording and the yes/no.
    function confirmUnroutableSecondary(row, contextSlug, onProceed, onCancel) {
        var r = row || ({})
        unroutableSecondaryConfirmDialog.adapterName =
            String(r.description || r.name || "")
        unroutableSecondaryConfirmDialog.reasonSlug =
            Pure.unroutableInterfaceReasonSlug(r)
        unroutableSecondaryConfirmDialog.contextSlug = String(contextSlug || "assign")
        unroutableSecondaryConfirmDialog.killSwitchArmed =
            prefs.routeKillSwitchEnabled === true
        unroutableSecondaryConfirmDialog.pendingAction = onProceed || null
        unroutableSecondaryConfirmDialog.pendingCancelAction = onCancel || null
        unroutableSecondaryConfirmDialog.open()
    }

    /// True when a dry-run review summary
    /// carries no actual change: no added/removed/modified/retargeted rules
    /// and no binding/behavior (`changed-fields`) delta. Used to short-circuit
    /// the review dialog with a "nothing to apply" notice instead of opening
    /// it empty.
    /// Opens `ReviewDiffDialog` in read-only mode
    /// against a parked payload. We re-use the standard dry-run RPC
    /// (`rpcMutationSubmit("rules-update", payload, dryRun=true)`) so
    /// the diff is computed by the service against its actual active
    /// revision — no client-side fake. Cancel on the dialog closes it
    /// without altering the parked state.
    /// Payload backing the read-only
    /// pending-apply preview, captured so the dialog's "Apply…" button
    /// (`reviewDiffDialog.onPreviewApplyRequested`) can re-enter the real
    /// review flow without the host keeping a separate copy.
    property var _pendingPreviewPayload: null

    function _openPendingApplyPreview(rulesJson, contentHash) {
        if (!bridgeAvailable) return
        _pendingPreviewPayload = {
            rulesJson:   String(rulesJson || ""),
            contentHash: String(contentHash || "")
        }
        var corr = Pure.newCorrelationId()
        var payload = {
            "rules-json":     String(rulesJson || ""),
            "content-hash":   String(contentHash || ""),
            "correlation-id": corr
        }
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-update", payload, true /* dryRun */, ""
        )
        rpcTransport.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok) {
                statusLine = tr(
                    "status.pending-apply-preview-failed",
                    "Could not load the diff for the parked changes; see logs.")
                console.log("pending-apply preview failed:", code, msg)
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            reviewDiffDialog.summary = summary
            reviewDiffDialog.lacksElevation = false
            reviewDiffDialog.readOnly = true
            reviewDiffDialog.open()
        })
    }

    /// Called on every disconnect→connect transition
    /// Refresh the compatibility-banner state from
    /// the launcher's `local.service-info` RPC. Called on cold-start
    /// AND on every disconnect→connect transition. The handler
    /// returns the GUI's protocol/semver (always known) plus the
    /// service's protocol/semver (zero/empty until the IPC handshake
    /// completes). On a pure-mock backend the bridge isn't wired and
    /// the banner stays hidden — that's correct because there's no
    /// service to be incompatible with.
    function _refreshServiceInfo() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcServiceInfo !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcServiceInfo()
        rpcTransport.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok || !payload) {
                console.log("local.service-info failed:", code, msg)
                return
            }
            _compatGuiProtocol     = parseInt(payload["gui-protocol"] || 0)
            _compatGuiVersion      = String(payload["gui-version"] || "")
            _compatServiceProtocol = parseInt(payload["service-protocol"] || 0)
            _compatServiceVersion  = String(payload["service-version"] || "")
        })
    }

    // ──────────────────────────────────────────────────────────────
    // Post-connect backlog — ONE question for everything parked
    //
    // Rules and routing settings are parked by two independent
    // mechanisms (the rules sidecar, and `prefs.routePendingOfflineJson`),
    // and each used to prompt on its own: two modal dialogs a second
    // apart about the same interruption. Both halves are now collected in
    // parallel and the dialog opens only once both have reported.
    //
    // The rules half deliberately does NOT apply the parked snapshot. That
    // snapshot was written once and never refreshed, so it could be older
    // than the table — applying it silently resurrected rules the user had
    // since deleted, and the preview built from it showed nothing while a
    // rule was demonstrably missing. The park is a MARKER ("there is
    // offline rule work"); what gets previewed and applied is always the
    // table as it stands, compared against the live service revision.
    // ──────────────────────────────────────────────────────────────

    /// Both halves of one collect run: `{ rulesReady, rules, settingsReady,
    /// settingsRows }`. Non-null only while a run is in flight — the runs are
    /// idempotent and several triggers (cold start, reconnect) can coincide.
    property var _offlineBacklogRun: null

    /// One-shot: the rules half is already being applied by a review the user
    /// triggered from the "service not running" gate, so the collector must
    /// not ask about it a second time. Settings are unaffected.
    property bool _offlineRulesHandledByResume: false

    function _startOfflineBacklogCollect() {
        // Don't stack a modal over the first-launch wizards.
        if (!prefs.firstRunCompleted) return
        if (offlinePendingController._offlinePendingDialogActive) return
        if (_offlineBacklogRun !== null) return
        if (!_routingBackendConnected()) return
        // A table caught mid-repopulate would diff as "rules removed".
        if (rulesBulkLoading === true) { _offlineBacklogCollectTimer.restart(); return }
        _offlineBacklogRun = {
            rulesReady: false, rules: null, settingsReady: false, settingsRows: []
        }
        offlinePendingController._offlinePendingDialogActive = true
        _collectOfflineRulesBacklog(function(rules) {
            if (!_offlineBacklogRun) return
            _offlineBacklogRun.rules = rules
            _offlineBacklogRun.rulesReady = true
            _settleOfflineBacklogCollect()
        })
        offlinePendingController.collectSettingsBacklog(function(rows) {
            if (!_offlineBacklogRun) return
            _offlineBacklogRun.settingsRows = rows || []
            _offlineBacklogRun.settingsReady = true
            _settleOfflineBacklogCollect()
        })
    }

    function _settleOfflineBacklogCollect() {
        var run = _offlineBacklogRun
        if (!run || !run.rulesReady || !run.settingsReady) return
        _offlineBacklogRun = null
        var hasRules = run.rules !== null
        var hasSettings = run.settingsRows.length > 0
        if (!hasRules && !hasSettings) {
            offlinePendingController._offlinePendingDialogActive = false
            return
        }
        if (!hasRules) {
            // Settings alone still reconcile without a click whenever the
            // service accepts them: the parked keys are per-SID and need no
            // elevation in the common case. Only a refusal surfaces the
            // dialog, through `_applyOfflinePending`'s own fallback.
            offlinePendingController._applyOfflinePending(run.settingsRows)
            return
        }
        _showOfflineBacklogDialog(run.rules, run.settingsRows)
    }

    /// Open the shared post-connect dialog. `rules` is `{added, removed}` or a
    /// falsy value when only settings are pending (the fallback entry used by
    /// `_applyOfflinePending`).
    function _showOfflineBacklogDialog(rules, settingsRows) {
        offlinePendingController._offlinePendingDialogActive = true
        offlineBacklogDialog.rulesPending = !!rules
        offlineBacklogDialog.rulesAdded = rules ? parseInt(rules.added || 0) : 0
        offlineBacklogDialog.rulesRemoved = rules ? parseInt(rules.removed || 0) : 0
        offlineBacklogDialog.settingsRows = settingsRows || []
        offlineBacklogDialog.open()
    }

    /// Rules half: is there offline rule work, and how much? `done(null)` when
    /// there is nothing to offer — including when a marker exists but the
    /// table already matches the service, in which case the stale marker is
    /// dropped so it can never resurface.
    function _collectOfflineRulesBacklog(done) {
        var finish = function(v) { if (typeof done === "function") done(v || null) }
        // A review the user already triggered is answering this exact
        // question; it clears the flag when it settles.
        if (_offlineRulesHandledByResume) { finish(null); return }
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarPendingApplyRead !== "function") {
            finish(null)
            return
        }
        var corr = nrrNativeBridge.rpcSidecarPendingApplyRead()
        // A dropped correlation id never gets a callback, so the collector
        // would wait for a reply that cannot arrive.
        if (!corr || String(corr) === "") { finish(null); return }
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            var entry = ok && p && p.entry
            // No marker and no in-flight offline import: any divergence left
            // is the drift banner's business, not a modal on every connect.
            if (!entry && !_offlineRulesPendingPush) { finish(null); return }
            _diffRulesAgainstService(function(counts) {
                if (!counts || (counts.added === 0 && counts.removed === 0)) {
                    if (entry) _clearPendingApplyPark()
                    finish(null)
                    return
                }
                finish(counts)
            })
        })
    }

    /// `{added, removed}` for the CURRENT table against the service's live
    /// revision, or `null` when the service cannot be read.
    function _diffRulesAgainstService(done) {
        var finish = function(v) { if (typeof done === "function") done(v || null) }
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcRulesList !== "function") {
            finish(null)
            return
        }
        var corr = nrrNativeBridge.rpcRulesList()
        if (!corr || String(corr) === "") { finish(null); return }
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok || !p) { finish(null); return }
            var serviceRows = (p.rows || []).map(Rules.driftRowFromServiceWire)
            finish(Rules.diffRuleRowCounts(
                _rulesModelToRowArray(), serviceRows, _aceEncodeHost))
        })
    }

    /// Clear the sidecar pending-apply marker (best-effort). Shared by the
    /// dialog's Discard action and the obsolete-marker auto-drop.
    function _clearPendingApplyPark() {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSidecarPendingApplyClear !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSidecarPendingApplyClear()
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("pending-apply.clear failed:", code, msg)
        })
    }

    // ──────────────────────────────────────────────────────────────
    // Drift detection (file ↔ GUI ↔ service)
    //
    // Three hash legs computed per route via
    // `local.canonical-rules-hash` (Rust SSOT). Periodic 30 s poll
    // when `backendStatus.kind === "connected"` keeps the file leg
    // fresh; the GUI leg is recomputed on every rule edit (or on
    // demand from the poll) and the service leg is captured at
    // cold-start + after every successful activate.
    //
    // Banner visibility (`_driftDetected`) is recomputed by
    // `_driftCompare()` after each leg lands. Banner click opens
    // `DriftDetectionDialog` which shows all three hashes per route
    // and offers Load-from-file / Apply-GUI / Accept-service / Not-now.
    // ──────────────────────────────────────────────────────────────

    property string _driftFileHashPrimary:   ""
    property string _driftFileHashSecondary: ""
    /// Cached file mtime keyed by path. Cache invalidates when the
    /// path changes OR the mtime advances. Stored as Unix seconds.
    property double _driftFileMtimePrimary:   0
    property double _driftFileMtimeSecondary: 0
    property string _driftFileCachedPathPrimary:   ""
    property string _driftFileCachedPathSecondary: ""
    property bool   _driftFileExistsPrimary:   false
    property bool   _driftFileExistsSecondary: false

    property string _driftGuiHashPrimary:    ""
    property string _driftGuiHashSecondary:  ""

    property string _driftServiceHashPrimary:   ""
    property string _driftServiceHashSecondary: ""

    /// When `true`, the banner row above the section content is
    /// visible. `_driftCompare()` is the only writer.
    property bool _driftDetected: false

    /// `true` while the live service reports ZERO rules
    /// (no active revision — e.g. right after a service-DB wipe). Drives
    /// the amber banner's "the service has no rules yet" wording instead
    /// of the generic three-way "do not all agree" text. Written only by
    /// `_driftRefreshServiceHashInto` (the sole live service-rules read).
    property bool _serviceRulesEmpty: false

    /// When `true`, a quiet "Merge available" affordance is
    /// offered: a route's linked file and the service revision have genuinely
    /// diverged (`file-vs-service`) but that is NOT the safety-critical
    /// app↔service divergence that raises the amber `_driftDetected` banner.
    /// `_driftCompare()` is the only writer. Deliberately separate from
    /// `_driftDetected` — re-raising the amber banner on a file-only mismatch
    /// was a regression this separation prevents.
    property bool _mergeAvailable: false

    /// Bound-file text cached at merge-dialog open so the confirm
    /// pass can re-run `rules.merge-preview` with the user's picks without
    /// re-reading the files.
    property string _mergePrimaryText: ""
    property string _mergeSecondaryText: ""
    /// When `true`, the next successful rules-update activation was a merge
    /// apply — re-export the merged revision to the bound files so file==service.
    property bool _mergeApplyPendingWrite: false

    /// Mutex against overlapping poll runs. The 30 s timer + manual
    /// "Recheck" button + edit hooks all funnel through
    /// `_driftRecheck()` and must not interleave their async chains.
    property bool _driftRecheckInFlight: false

    /// Bounded fast-retry counter for the
    /// post-(re)connect drift convergence phase driven by
    /// `_driftConnectFastRetryTimer`. Reset to 0 on every connect
    /// transition; when it reaches `_driftConnectRetryMax` the fast
    /// phase stops and the normal 30 s poll takes over.
    property int _driftConnectRetryCount: 0
    readonly property int _driftConnectRetryMax: 6

    /// Per-route comparison detail surfaced by the DriftDetectionDialog.
    /// Updated by `_driftCompare()`. Each entry holds `{file, gui,
    /// service, mismatch}` strings; mismatch is a kebab-case slug
    /// (`all-three-differ` / `file-vs-gui` / `gui-vs-service` /
    /// `file-vs-service` / `none`).
    property var _driftDetailsPrimary:   ({ file: "", gui: "", service: "", mismatch: "none" })
    property var _driftDetailsSecondary: ({ file: "", gui: "", service: "", mismatch: "none" })

    // Re-trigger the cold-start onboarding flow on
    // demand from Settings. Resets the UAC decline counter so the user
    // gets the full sequence (Install dialog → preset wizard) just like a
    // fresh install would. Mirrors the `Component.onCompleted` gate in
    // `Main.qml`.
    //
    // It deliberately does NOT clear `firstRunCompleted`: the wizard is a
    // one-time acknowledgement, and clearing the flag here meant that
    // dismissing the re-shown window with the title-bar X left the flag
    // persisted as false, so the wizard reappeared on every launch. The
    // window's `onClosing` handler keeps the flag true regardless of how
    // it is closed, so re-showing it needs no flag reset.
    function restartFirstRunFlow() {
        updatePrefs({
            serviceInstallUacDeclinedCount: 0
        })
        if (_serviceNeedsInstallPrompt()) {
            firstLaunchInstallDialog.open()
        } else {
            openChildWindow(firstRunWindow)
        }
    }

    function _serviceNeedsInstallPrompt() {
        if (typeof nrrServiceController === "undefined"
                || nrrServiceController === null) {
            return false
        }
        var status = parseInt(nrrServiceController.status)
        // status === 1 ⇒ NotInstalled
        if (status !== 1) return false
        var declines = parseInt(prefs.serviceInstallUacDeclinedCount || 0)
        return declines < 3
    }

    // Listen for UAC decline signal to track the budget
    // in UiPreferences. After 3 declines the prompt downgrades to a
    // passive banner (handled in `_serviceNeedsInstallPrompt`).
    Connections {
        target: typeof nrrServiceController !== "undefined" && nrrServiceController
            ? nrrServiceController : null
        ignoreUnknownSignals: true
        function onUacDeclined(operation) {
            if (String(operation) === "install") {
                var current = parseInt(prefs.serviceInstallUacDeclinedCount || 0)
                var now = Math.floor(Date.now() / 1000)
                updatePrefs({
                    serviceInstallUacDeclinedCount: current + 1,
                    serviceInstallUacDeclinedAtEpoch: now
                })
                uacRequiredDialog.mode = "declined"
                uacRequiredDialog.open()
            }
        }
        function onOperationCompleted(operation, success, errorMessage) {
            if (String(operation) === "install" && success) {
                // Clear the decline counter on successful install so a
                // future stop-then-uninstall flow doesn't inherit
                // stale state.
                updatePrefs({
                    serviceInstallUacDeclinedCount: 0
                })
            }
        }
    }

    // Save-before-close dialog. Fires AFTER the
    // UnsavedChangesGuard cleared, only on real close (X / tray Exit),
    // never on close-to-tray. Lets the user persist active rule edits
    // back to the imported file paths or roll them back.
    SaveBeforeCloseDialog {
        id: saveBeforeCloseDialog
        ownerRoot: window
        onSaveSelected: boundFilesController._handleSaveSelectedFromCloseDialog()
        onSaveAs: boundFilesController._handleSaveAsFromCloseDialog()
        onDiscardAndRollback: boundFilesController._handleDiscardAndRollback()
        onCancelled: { _resumeCloseAfterSaveBefore = false }
    }

    // Save-As target picker for the queue in BoundFilesController: one route at
    // a time, written from the local rules table (no service involved) and
    // linked to the chosen path.
    FileDialog {
        id: saveAsFileDialog
        fileMode: FileDialog.SaveFile
        defaultSuffix: "txt"
        // Same folder every other rule-file dialog uses.
        title: tr("rules.dialog.export-title", "Save preset as...")
        nameFilters: [
            tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            tr("rules.dialog.all-filter", "All files (*)")
        ]
        property string pendingRoute: ""
        onAccepted: {
            var s = String(selectedFile || "")
            var path = (s.indexOf("file:///") === 0)
                ? s.substring(8)
                : ((s.indexOf("file://") === 0) ? s.substring(7) : s)
            boundFilesController._handleSaveAsPathChosen(pendingRoute, path)
        }
        onRejected: boundFilesController._handleSaveAsCancelled()
    }

    // The rules file sits inside the sets that ship with the app, so the write
    // is warned about — not refused — and the warning offers both ways out.
    // Every handler is a one-liner into BoundFilesController, which owns the
    // held write and its resume.
    FactoryPresetSaveDialog {
        id: factoryPresetSaveDialog
        ownerRoot: window
        onSaveHereRequested: boundFilesController.factorySaveHereConfirmed()
        onChooseFolderRequested: {
            // The `hasRulesFolder` guard matters — writing an empty URL into
            // `currentFolder` points the dialog at the process working
            // directory instead of "use the default".
            if (hasRulesFolder) rulesSaveFolderDialog.currentFolder = rulesFolderUrl
            rulesSaveFolderDialog.open()
        }
        onCancelled: boundFilesController.cancelFactoryPathRebind()
    }

    // Folder picker for the refusal above. Same title as the rule-set folder
    // picker in Settings — it is the same choice, reached from the save.
    FolderDialog {
        id: rulesSaveFolderDialog
        title: tr("settings.presets.user-folder.dialog-title",
            "Choose the folder with your rule sets")
        onAccepted: {
            var s = String(selectedFolder || "")
            var path = (s.indexOf("file:///") === 0)
                ? s.substring(8)
                : ((s.indexOf("file://") === 0) ? s.substring(7) : s)
            boundFilesController.rebindBlockedRoutesTo(path)
        }
        onRejected: boundFilesController.cancelFactoryPathRebind()
    }

    // Tracks whether the divergence dialog interrupted a close-flow;
    // re-emits onClosing semantics after Save / Discard completes.
    property bool _resumeCloseAfterSaveBefore: false

    // Coarse per-route "rules-changed since last file
    // sync" flags. Set true on any successful rule-modifying mutation
    // (RulesUpdate, PresetImport); set false on successful
    // Save/Export to a file. Drives whether SaveBeforeCloseDialog
    // fires at window-close.
    property bool _filesSyncDirtyPrimary: false
    property bool _filesSyncDirtySecondary: false
    // Save-As-on-quit orchestration state: the dirty
    // routes still to be written and the index of the one being picked.
    property var _saveAsRoutes: []
    property int _saveAsIndex: 0

    // Funnel every transient operation toast through here so
    // the "Show notifications" preference (GeneralSettings) actually gates them.
    // Was unconsumed: the toggle persisted but toasts always popped. `settle` is
    // intentionally NOT gated — a toast already on screen must still resolve
    // even if the user turns notifications off mid-operation.
    function _pushOperationToast(corr, kind) {
        if (prefs.showNotifications !== false) {
            operationToastStack.model.push(corr, kind)
        }
    }

    // Global unsaved-changes guard. Section
    // navigation, window close, and app-quit all route through
    // `requestSectionChange` / `requestWindowClose` /
    // `requestApplicationQuit` which consult this dialog.
    UnsavedChangesGuard {
        id: unsavedChangesGuard
        ownerRoot: window
    }
    // Tray "Safe disable" lands here. The dialog
    // collects an audit reason and emits `confirmed(reason)`; the
    // host wires the next step.
    SafeDisableConfirmDialog {
        id: safeDisableConfirmDialog
        ownerRoot: window
        onConfirmed: function(reason) {
            window._handleSafeDisableConfirmed(reason)
        }
        onCancelled: {
            window.statusLine = window.tr("status.safe-disable.cancelled",
                "Safe disable cancelled")
        }
    }

    // Safe rollback confirm → RollbackRequest recovery action.
    SafeRollbackConfirmDialog {
        id: safeRollbackConfirmDialog
        ownerRoot: window
        onConfirmed: window.boundFilesController._performSafeRollback()
    }

    AboutWindow { id: aboutWindow; root: window }

    // "Licenses" window — Help menu / About "License" button / welcome
    // window "View EULA" button all funnel here. Two tabs: the MPL-2.0
    // product license (unchanged content) and the EULA the user accepted
    // at first run (read-only — acceptance itself only happens through
    // `eulaAgreementWindow`, never here).
    LicenseWindow { id: licenseWindow; root: window }

    // File → Load rule list dialog. Two-slot picker
    // (Primary + Secondary). Either slot may be left empty — both empty
    // disables Import. Hooks into the real review flow
    // (`startPresetImportReviewFlow` / `startBothRoutesPresetImportReviewFlow`),
    // not the earlier stub it replaced.
    LoadListWindow { id: loadListWindow; root: window }

    // First-run wizard. Replaces the earlier preview
    // scenario picker with a 4-option preset-driven onboarding flow.
    // Opens once when `!prefs.firstRunCompleted`; each option marks
    // `firstRunCompleted = true` so the wizard never reappears.
    FirstRunWindow { id: firstRunWindow; root: window }

    // Transient toast stack pinned to the
    // bottom-right corner of the ApplicationWindow content area.
    // Stays above the backend connection banner (z: 100) and above
    // every section card. `mutation-progress` push events in
    // `handlePushEvent` push/settle entries via
    // `operationToastStack.model`.
    OperationToastStack {
        id: operationToastStack
        theme: uiTheme
        ownerRoot: window
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.rightMargin: uiTheme.spacingLg
        anchors.bottomMargin: uiTheme.spacingLg
        z: 200
    }
}
