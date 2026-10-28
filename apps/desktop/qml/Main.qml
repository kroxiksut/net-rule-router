
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
import "lib/plurals.js" as Plurals

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
    property var platformProfile: ({ os: "windows", enforcementBackend: "wfp", serviceModel: "scm", elevationModel: "uac", supports: { killSwitch: true, appRouting: true, dnsObserve: true, dnsResolver: true, fakeIp: true, hostsPin: true, backgroundService: true, autostart: true, serviceStabilityConfig: true, verboseLogging: true, localNetworkExceptions: true, forwardedTrafficGuard: true, blockNotices: true, auditChainRestart: true, connTraceLog: true, serviceStartOnAppLaunch: true, siteNoticeWithoutTray: true, perUserRouting: false, perAppBlockLeakproof: true, perUserAllProtocolScoping: false, appPathRules: false, appPathScripts: false } })
    // Capability query for declarative, OS-agnostic section gating: a
    // feature-keyed section renders only when the running OS supports it.
    // Unknown feature or missing profile → true (show it), which is why the
    // stub above must carry EVERY flag the contract declares — a missing
    // inversion silently read as "supported" on the very platform that lacks
    // it. `platform_profile_stub_matches_the_contract` pins the two together.
    function supports(feature) {
        if (!platformProfile || !platformProfile.supports) return true
        return platformProfile.supports[feature] !== false
    }
    // Service-backed features whose handlers exist on some platforms only. Read
    // before every request: an unregistered handler answers "not yet
    // implemented", and a poll asking anyway filled a day's log with refusals.
    readonly property bool serviceStabilitySupported: supports("serviceStabilityConfig")
    // The verbose window alone, where the service applies it without the rest.
    readonly property bool verboseLoggingSupported: supports("verboseLogging")
    // Some stability key reaches the service here, if not the whole row.
    readonly property bool stabilityAnyKeySupported:
        Pure.stabilityAnyKeyApplies(platformProfile ? platformProfile.supports : null)
    /// The part of a stability patch this platform's service applies.
    function stabilityPatchForPlatform(partial) {
        return Pure.stabilityPatchForPlatform(partial,
            platformProfile ? platformProfile.supports : null)
    }
    readonly property bool localNetworksSupported: supports("localNetworkExceptions")
    /// A network the computer forwards for (WSL, a container or VM bridge) is
    /// up, and its outage answer can be enforced.
    readonly property bool forwardingPresent: supports("forwardedTrafficGuard")
        && Pure.forwardingPresent(interfacesRowsAll)
    onForwardingPresentChanged: _onForwardedReading()
    readonly property bool blockNoticesSupported: supports("blockNotices")
    /// Why a section keyed off one of the flags above renders inert. One
    /// wording for every such section — the reason is the same in all of them.
    readonly property string platformUnsupportedText: uiRevision >= 0
        ? tr("status.platform-unsupported",
            "This is not available on your operating system yet, so the controls here stay off. "
            + "Nothing here is sent to the background service.")
        : ""
    property var prefs: ({ launchWindowOnStartup: true, minimizeToTrayInsteadOfClose: true, showNotifications: true, notifySuggestionChanges: true, notifyBlockNotices: true, notifyRuleDuplicates: true, hideBlockNoticeAddresses: false, trayNoticeOpacityPercent: 100, routingDetailedMode: false, showVirtualMachinesSection: false, appGroupsOfferDismissed: false, reopenLastSectionOnStartup: true, firstRunCompleted: false, acceptedEulaVersion: 0, themeMode: "system", effectiveThemeMode: "light", accessibilityHighContrast: false, fontScalePercent: 100, systemFont: "system-default", enhancedFocus: false, simplifiedLabels: false, tooltipsEnabled: true, language: Qt.locale().name, routePrimaryLabel: "Primary", routeSecondaryLabel: "Secondary", selectedPrimaryInterfaceId: "", selectedPrimaryInterfaceName: "", primaryRoleUserConfirmed: false, selectedSecondaryInterfaceId: "", selectedSecondaryInterfaceName: "", secondaryRoleUserConfirmed: false, routeBehaviorMode: "prefer-primary", routeIncludeSubdomains: true, routeSharedIpPolicy: "majority-of-ip", routeEnforcementMode: "resolver", showBluetoothAdapters: false, showRememberedAdapters: true, autoConfirmAdapterIdChange: true, warnKillSwitchBlockAll: true, killSwitchBannerAcknowledged: false, missingSecondaryBannerAcknowledged: false, trafficStatsPeriod: "today", trafficExportUnit: "mb", connTraceGroupBy: "program", diagnosticsArchiveRedactionLevel: "standard", diagnosticsArchiveSessionOnly: true, archiveLogBudgetMib: 0, updateCheckEnabled: true, updateCheckIntervalDays: 14, userPresetsDir: "", selectedPresetSet: "", serviceBackedMirrorJson: "", serviceIntentJson: "", lastOpenedSection: "interfaces-routes" })
    property string section: "interfaces-routes"
    // The section open at launch loads synchronously: an asynchronous first
    // load could stall with an empty pane until the user clicked something.
    property bool sectionLoadsAsync: false
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
    /// The selected rule itself (`Rules.mergeKey`), which `selectedRule` — a
    /// row number — follows when the list changes under it.
    property string selectedRuleKey: ""
    onSelectedRuleChanged: selectedRuleKey = (selectedRule >= 0 && selectedRule < rulesModel.count)
        ? Rules.mergeKey(rulesModel.get(selectedRule)) : ""
    /// `indexByKey` maps each rule's key to its row: the selection moves with
    /// its rule, or clears when the rule is gone.
    function followSelectedRule(indexByKey) {
        if (selectedRuleKey === "") return
        var at = indexByKey[selectedRuleKey]
        if (at === undefined) selectedRule = -1
        else if (at !== selectedRule) selectedRule = at
    }
    property int editingRule: -1
    /// The rule the form edits (`Rules.mergeKey`), set when the form opens.
    property string editingRuleKey: ""
    property int wizardStep: 0
    property int autoCloseMs: 0
    property int uiRevision: 0
    // Bumped when the service says this user's notice mutes changed.
    property int noticeMutesRevision: 0
    // Bumped when an import stored new sections this build carries unapplied.
    property int passthroughRevision: 0
    // Dedicated revision token for the theme tokens (`uiTheme`). Bumped ONLY
    // when a theme-affecting pref changes (themeMode / effectiveThemeMode /
    // high-contrast / font scale / system font) — kept separate from
    // `uiRevision` (which fires on row selection, unsaved-flag flips, rules
    // refetch, tab switches, etc.) so a generic interaction never
    // re-evaluates every colour/font binding across the resident sections.
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
    // Set by File → Exit for the one close it starts.
    property bool exitRequested: false
    property var localeCatalog: ({})
    // Per-file locale load report from the launcher: { acceptedWithWarnings,
    // rejected, reports: [{ id, fileName, source, status, warnings, errors }] }.
    // Rendered in Settings -> Language; a locale problem otherwise reached the
    // user as a status line telling them to read logs the GUI does not write.
    property var localeDiagnostics: ({})
    property var availableLanguages: []
    property var interfacesRowsAll: []
    /// Where the adapter rows came from: one of the per-OS live spellings when
    /// the service enumerated the machine, anything else (including an unknown
    /// spelling) when they are placeholders. Starts pessimistic — until a
    /// source says otherwise, rows must not be presented as this machine's
    /// adapters, so the check is a known-live list rather than "not the mock".
    property string interfacesDataSource: "fallback-mock"
    readonly property bool interfacesAreLive: Pure.interfacesSourceIsLive(interfacesDataSource)
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
    //         | "protocol-mismatch" | "refused",
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
    // not installed, or a disconnect the service manager cannot explain).
    // Hide it for "connecting" (the spinner already
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
    /// The `base-revision` of the rules the table was last loaded from (or
    /// last applied), null until known. Every rules write names it, so a write
    /// over rules that changed elsewhere is refused instead of undoing them.
    property var rulesBaseRevision: null
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
    // The default route the service holds ("" until read) and the weakest
    // leak protection a first save may hold; for a user with no policy yet,
    // what the install-time choices make of that first save.
    property string _serviceDefaultRoute: ""
    property string _serviceLeakFloor: "off"
    /// The route policy the service last reported, null for a user with none.
    property var _serviceRoutePolicy: null
    /// Follow the service's answer: `rpRaw` is its route policy (absent for a
    /// user with none), `first` its `first-policy`.
    function _noteServicePolicy(rpRaw, first) {
        var rp = rpRaw || {}
        var start = (!rpRaw && first && typeof first === "object") ? first : null
        _servicePolicySecondaryBound = !!(rpRaw && rp.secondary)
        _serviceRoutePolicy = rpRaw || null
        _serviceDefaultRoute = rpRaw ? _routePolicyEffective(rp, "mode")
            : (start ? Pure.routePolicyCoerce("mode", start.mode) : "")
        _serviceLeakFloor = start
            ? Pure.routePolicyCoerce("leak-protection", start["leak-protection-at-least"]) : "off"
    }
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
    // Third reading of the same silence: no adapter to send anything to, but
    // leak protection is on — so the traffic those rules name is being BLOCKED,
    // not merely unrouted. Saying "not applied" there would be false comfort.
    readonly property bool policyInactiveKillSwitchBlocking:
        policyInactiveBannerVisible && !_policyIdlePrefsHaveSecondary
        && uiRevision >= 0 && routingState.leakProtection !== "off"
    // The app and the service each store which adapters carry which role, and
    // a disagreement between them is not ours to settle: only the user knows
    // whether the choice in front of them or the one being enforced is the
    // stale one. Rows of `{ role, mine, service }` from the cold-start read;
    // empty when the two agree, which is the ordinary case.
    property var routeBindingDivergence: []
    readonly property bool routeBindingDivergenceVisible:
        uiRevision >= 0 && !!routeBindingDivergence && routeBindingDivergence.length > 0
    /// One line naming both sides, so the choice can be made from the banner
    /// without opening anything.
    readonly property string routeBindingDivergenceText: {
        if (!routeBindingDivergenceVisible) return ""
        var parts = []
        for (var i = 0; i < routeBindingDivergence.length; i++) {
            var d = routeBindingDivergence[i]
            var role = (String(d.role) === "primary")
                ? tr("interfaces.role.primary", "Main connection")
                : tr("interfaces.role.secondary", "Additional connection")
            parts.push(role + ": " + tr("status.route-binding-divergence-pair",
                "the app shows {mine}, the service is applying {service}")
                .replace("{mine}", String(d.mine)).replace("{service}", String(d.service)))
        }
        return tr("status.route-binding-divergence",
            "The connections shown here are not the ones the background service is applying. ")
            + parts.join("; ")
    }
    /// The user answered the disagreement in the service's favour.
    function adoptServiceRouteBinding() {
        routePolicyController.adoptServiceRouteBinding()
    }
    /// Re-send the adapter binding the app already holds to a service that has
    /// none. The push reports its own failure (adapter not live, elevation
    /// declined) on the status line, which is still better than the silence
    /// this banner exists to break.
    function resendRouteBindingToService() {
        // Also the "keep mine" answer to a binding disagreement: the push
        // replaces what the service holds, so the question is settled.
        routeBindingDivergence = []
        routePolicyController.pushRouteBindingToService(undefined, undefined, "user:binding-resend")
        // Re-read once the push has had time to land so the notice clears on
        // the spot instead of waiting for the next watch tick. The push is
        // asynchronous (and may go through elevation), so a read issued right
        // here would still see the old state.
        _adaptersChangedSnapshotRefreshTimer.restart()
    }

    // Top-of-window warning that leak protection is holding all traffic
    // (protection "everything" and the additional adapter can't be
    // resolved). `killSwitchHoldingForOutage`
    // mirrors the connect-time snapshot posture (see `refreshUnenforcedAppRules`);
    // the `warnKillSwitchBlockAll` pref (default on) is the opt-out, toggled from
    // Settings -> Routing behavior. The `uiRevision >= 0` guard makes the binding
    // re-evaluate on every routingState refresh. Height is
    // content-driven (wrapping text), never shorter than the 36px single line.
    readonly property bool blockAllBannerVisible:
        uiRevision >= 0
        && routingState.killSwitchHoldingForOutage === true
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
        uiRevision >= 0 && routingState.killSwitchHoldingForOutage === true
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
    // Found programs whose rule routes none of their traffic: app -> reason.
    // An older service sends none, which leaves the notice as it was.
    readonly property var unroutedAppRules:
        (routingState && routingState.unroutedAppRules) || ({})
    readonly property var _appNoticeApps:
        unenforcedAppRules.concat(Object.keys(unroutedAppRules).sort())
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
    // SUBSET semantics, per program AND problem: a set that only shrank stays
    // hidden, while a new program, or a known one with a different problem
    // (not found -> found but routing nothing, or back), is told anew. The
    // dismiss handler stores the UNION so returning apps stay acknowledged.
    function _unenforcedCoveredByAck() {
        return Pure.appNoticeCoveredByAck(_unenforcedAppRulesAckSig,
            unenforcedAppRules, Object.keys(unroutedAppRules).sort())
    }
    function _unenforcedAckUnionSig() {
        return Pure.appNoticeAckUnion(_unenforcedAppRulesAckSig,
            unenforcedAppRules, Object.keys(unroutedAppRules).sort())
    }
    // Active when connected, at least one app rule is unenforced, and the
    // current set contains an app the user has not yet acknowledged.
    readonly property bool appUnresolvedNoticeActive:
        !!backendStatus && backendStatus.kind === "connected"
        && _appNoticeApps.length > 0
        && !_unenforcedCoveredByAck()

    // Notifications centre SSOT. Low-priority, non-blocking
    // notices live here instead of stacked top banners. `activeNotifications`
    // is the list rendered by NotificationCenterPopup and counted by the footer
    // bell chip. To add a notice: push { id, severity: "warning"|"info", title,
    // body, actionKey?, actionText?, secondaryActionKey?, secondaryActionText? };
    // an action key is dispatched by
    // `notificationsController.runNotificationAction`, dismissal routed through `notificationsController.dismissNotification`.
    readonly property var activeNotifications: {
        var out = []
        if (appUnresolvedNoticeActive) {
            out.push({
                "id": "app-unresolved",
                "severity": "warning",
                "dismissible": true,
                "title": unenforcedAppRules.length > 0
                    ? tr("notifications.app-unresolved.title",
                        "App rules applied, but some apps weren't found")
                    : tr("notifications.app-unresolved.title-unrouted",
                        "App rules applied, but some don't route their program"),
                "body": _unenforcedAppNoticeBody(),
                "actionKey": "open-rules",
                "actionText": tr("action.open-rules", "Open rules")
            })
        }
        // The service is up and turned this window away. Nothing here retries
        // itself, so the notice explains what actually restores the link.
        if (((backendStatus || {}).kind) === "refused") {
            out.push({
                "id": "service-refused",
                "severity": "warning",
                "dismissible": false,
                "title": tr("notifications.service-refused.title",
                    "The service will not accept this app"),
                "body": tr("notifications.service-refused.body",
                    "The background service is running, but it refused a connection from this account. That usually means the service was installed by a different user, or it is already serving as many connections as it allows. Reinstalling the service as an administrator, or signing in as the account that installed it, restores the link.")
                    + (String((backendStatus || {}).lastError || "") !== ""
                        ? " (" + String(backendStatus.lastError) + ")" : "")
            })
        }
        // GitHub release check: the daily one's cached verdict, or the user's
        // own from the Help menu. Non-null only for a strictly newer release.
        var upd = updateCheckController.offer
        if (Pure.updateOfferShown(upd, prefs.dismissedUpdateVersion)) {
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
        // `?` rules that work only on the other route. The service holds the
        // list, so the card leaves on both surfaces once either answers.
        var verdictNotice = verifyVerdicts.notice
        if (verdictNotice) {
            out.push({
                "id": "verify-verdicts",
                "severity": "info",
                "dismissible": false,
                "title": tr("notifications.verify-verdicts.title",
                    "Addresses that do not open where they are written: {count}")
                    .replace("{count}", String(verdictNotice.ids.length)),
                "body": verifyVerdictsBody(verdictNotice),
                "actionKey": "verify-verdicts-move",
                "actionText": tr("action.move", "Move"),
                "secondaryActionKey": "verify-verdicts-later",
                "secondaryActionText": tr("action.not-now", "Not now")
            })
        }
        // Notices the service pushed at us. Everything above is derived from
        // live state and clears itself; a push describes something that already
        // happened, so it is held until the user answers it (here or in the
        // tray). Appended last so a standing warning stays on top.
        for (var p = 0; p < notificationsController._pushNotices.length; p += 1) out.push(notificationsController._pushNotices[p])
        return Pure.noticesWarningsFirst(out)
    }

    onPrefsChanged: {
        // A rebound rules file changes what the tray must compare against.
        // Guarded because prefs can be reassigned before the component tree is
        // finished, and a throw here would take the kill-switch mirror with it.
        if (typeof guiPresence !== "undefined" && guiPresence) guiPresence.publish()
    }
    // Apply commits buffered notification settings without touching `prefs`.
    onPrefsSnapshotChanged: {
        if (typeof guiPresence !== "undefined" && guiPresence) guiPresence.publish()
    }

    /// The notification settings as committed: a buffered edit awaiting Apply
    /// is not the user's choice yet.
    function _committedNoticePrefs() {
        var keys = ["showNotifications", "notifySuggestionChanges", "notifyBlockNotices",
                    "notifyRuleDuplicates", "hideBlockNoticeAddresses", "trayNoticeOpacityPercent"]
        var out = {}
        for (var i = 0; i < keys.length; i += 1) {
            var key = keys[i]
            var source = prefsSnapshot !== null && _bufferedPrefKeys[key] ? prefsSnapshot : prefs
            out[key] = source[key]
        }
        return out
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
    /// Which side is behind on the wire contract (`Pure.contractSkew`). Writes
    /// are refused across it, so the banner shows whatever the mode pref says.
    property string contractSkew: ""
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
        contractSkew !== "" ? true
        : _compatBannerMode === "never"
            ? false
            : (_compatBannerMode === "always"
                ? (_compatInfoLoaded
                    && (_compatProtocolMismatch
                        || _compatGuiVersion !== _compatServiceVersion))
                : _compatProtocolMismatch)
    readonly property int compatBannerHeight: compatBannerVisible ? 36 : 0
    // Which service binary Windows has registered, and which one ships with
    // this copy of the app. They diverge when a newer build is unpacked
    // elsewhere: the old binary keeps starting with Windows, so the user runs a
    // new app against an old service without being told.
    property string serviceRegisteredPath:      ""
    property string serviceExpectedPath:        ""
    property bool   serviceRegisteredElsewhere: false
    property bool   serviceOlderThanApp:        false
    // Same folder, replaced file, process still running the previous code —
    // the registration is correct, so this one needs a restart, not a re-register.
    property bool   serviceRestartNeeded:       false
    readonly property bool serviceUpdateAvailable:
        serviceRegisteredElsewhere || serviceOlderThanApp

    /// Start the service — unless the registration points somewhere else, in
    /// which case starting it would launch the copy the user is replacing.
    function startServiceOrOfferUpdate() {
        if (typeof nrrServiceController === "undefined" || !nrrServiceController) return
        if (serviceRegisteredElsewhere) {
            serviceUpdateDialog.open()
            return
        }
        nrrServiceController.startService()
    }
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
    // A status the service reports for the additional route speaks for it: its
    // card, or its start-up quiet while the VPN is still coming up.
    readonly property bool secondaryUnresolvedVisible:
        uiRevision >= 0 && interfacesRolesController._secondaryUnresolved()
        && enforcementStatusByRole["secondary"] === undefined
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
        || (secondaryUnresolvedVisible && prefs.missingSecondaryBannerAcknowledged !== true
            && !notificationsController.secondaryDownMuted)
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
        if (secondaryUnresolvedVisible) notificationsController.refreshSecondaryDownMuted()
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
                    "Service version mismatch — please update NetRuleRouter")
            case "refused":
                // The service is running and said no — retrying changes
                // nothing, so the banner asks for the one thing that can.
                return tr(
                    "connection.banner.refused",
                    "The background service refused this connection")
            default:
                return ""
        }
    }
    function backendStatusBannerColor() {
        var kind = (backendStatus || {}).kind || ""
        return kind === "connecting" ? uiTheme.bannerWarningFill : uiTheme.bannerDangerFill
    }
    // Footer "Service: …" indicator, derived from the LIVE backend connection
    // state.
    // Localizes the word; the raw slug must never be shown.
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
    // the theme/font-scale UI applies only after a full window reopen.
    ThemeTokens {
        id: uiTheme
        // Tied to `themeRevision` via a direct ternary read so QML's binding
        // analyzer reliably registers the dependency — a `(uiRevision, expr)`
        // comma-expression does not always register. Recomputes ONLY on a
        // real theme/font change, not on every generic interaction (row
        // selection, unsaved flag, rules refetch, tab switch), avoiding a
        // full re-evaluation across the resident keep-alive sections.
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
    property alias loadListWindow: loadListWindow
    property alias refreshAction: refreshAction
    property alias logsFolderAction: logsFolderAction
    property alias aboutAction: aboutAction
    // Generic in-flight mutation tracker, shared
    // with every section that has submit-style buttons.
    property alias mutationsModel: mutationsModel
    // Transient toast stack pinned to the
    // bottom-right corner.
    property alias operationToastStack: operationToastStack
    // Global unsaved-changes guard. Sections call
    // `setUnsavedChanges(id, dirty)` directly; only Main.qml's own
    // intent-bearing call sites talk to the guard via the
    // `requestSectionChange` / `requestWindowClose` /
    // `requestApplicationQuit` helpers.
    property alias unsavedChangesGuard: unsavedChangesGuard
    // Exposed so Settings can re-trigger onboarding.
    property alias firstRunWindow: firstRunWindow
    // Exposed so the extracted FirstRunWindow can reach the sibling
    // Licenses window (View EULA button + transient-parent hand-off).
    property alias licenseWindow: licenseWindow
    // Reached by flows/StartupController for the `startupDialog: "about"` entry.
    // An id is not a property: without the alias `root.aboutWindow` is undefined
    // and the About-on-launch path opens nothing.
    property alias aboutWindow: aboutWindow
    // Cache row count, shown both on the Diagnostics summary card and in the
    // cache section. One number with one writer per refresh, so the two
    // surfaces cannot disagree. -1 = not read yet.
    property int diagCacheEntriesTotal: -1
    // Same reason: the extracted startup and backlog controllers re-arm these
    // two timers, and an id alone is not reachable from another file.
    property alias _offlineBacklogCollectTimer: _offlineBacklogCollectTimer
    property alias _driftConnectComparePrimeTimer: _driftConnectComparePrimeTimer
    property alias eulaAgreementWindow: eulaAgreementWindow

    readonly property bool darkTheme: uiTheme.isDark
    readonly property color windowColor: uiTheme.colorWindow
    readonly property color panelColor: uiTheme.colorPanel
    readonly property color baseColor: uiTheme.colorBase
    readonly property color textColor: uiTheme.colorText
    readonly property color mutedTextColor: uiTheme.colorTextMuted
    readonly property color borderColor: uiTheme.colorBorder
    readonly property color accentColor: uiTheme.colorAccent
    // The launcher resolves the assets folder beside the binary: where the
    // package keeps its QML says nothing about where it keeps its images. Set
    // once in `loadContext`, so no icon binding follows the volatile `context`.
    property string assetsRootUrl: ""
    function assetUrl(relative) { return assetsRootUrl === "" ? "" : assetsRootUrl + "/" + relative }
    readonly property url appIconSource: assetUrl("icons/app/icon-64.png")
    // The same lockup the startup splash paints, so "About" shows the face
    // the user already met rather than a second, smaller identity.
    readonly property url appLogoLockupSource: assetUrl("images/logo/logo-lockup-stacked.png")
    readonly property url appIconSmallSource: assetUrl("icons/app/icon-32.png")
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
        return Rules.routeDisplayLabel(role, "", "", tr)
    }
    function routeLabel(role) {
        return Rules.routeDisplayLabel(role, prefs.routePrimaryLabel, prefs.routeSecondaryLabel, tr)
    }
    function routeRoleOptions() {
        return Rules.routeRoleOptions(true, routeLabel, tr)
    }
    function localeTextForLanguage(languageId, key, fallbackText) {
        return resolveCatalogText(languageId, key, fallbackText)
    }
    // Memoized in the support object, keyed by slug, dropped on a language switch.
    function ruleTypeLabel(id) {
        return ruleEditSupport.ruleTypeLabel(id)
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
        return Pure.comboPopupWidthFor(control, model, textRole, textResolver,
            function(text) { return measuredTextWidth(text, control.font) },
            function(width) { return clampPopupWidth(control, width) })
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
        if (id === "rule-overlaps") return tr("rules.overlaps.nav-label", "Overlaps")
        if (id === "rule-virtual-machines") return tr("rules.vm.nav-label", "Virtual machines")
        if (id === "diagnostics") return tr("section.diagnostics", "Diagnostics")
        if (id === "conn-trace") return tr("diag.conn-trace.title", "Connection trace")
        if (id === "cache") return tr("diag.cache.title", "Cache")
        if (id === "outage-blocks") return tr("diag.outage-blocks.title", "Blocked while the route was down")
        if (id === "logs") return tr("section.logs", "Logs")
        if (id === "settings") return tr("section.settings", "Settings")
        return id
    }

    // ── Overlapping rules ────────────────────────────────────────────────────
    //
    // A wildcard rule covers the apex and every subdomain under it, so an
    // exact rule beneath the same wildcard usually does nothing. Surfaced
    // here rather than as an apply-time warning (noise on a path the user
    // did not open for this): a count on the rules screen, and a dialog
    // that removes the spare ones once.
    //
    // `rules_overlap::find_overlaps` (Rust) decides which pairs are spare —
    // never QML.

    /// Pairs from the last `local.rules-overlaps` pass.
    property var rulesOverlapPairs: []
    property bool _rulesOverlapInFlight: false
    /// An edit landed while a pass was in flight; that pass read older rules.
    property bool _rulesOverlapStale: false

    /// Stable key for one pair, as stored in `prefs.rulesOverlapKeepSig`.
    function overlapPairKey(pair) {
        if (!pair) return ""
        return String(pair["apex-route"]) + ":" + String(pair.apex)
            + ">" + String(pair["covered-route"]) + ":" + String(pair["covered-host"])
    }
    function _overlapKeptKeys() {
        var raw = String((prefs && prefs.rulesOverlapKeepSig) || "")
        return raw === "" ? [] : raw.split("|")
    }
    function overlapPairKept(pair) {
        return _overlapKeptKeys().indexOf(overlapPairKey(pair)) >= 0
    }
    /// Pairs the cleanup would act on: spare, and not already kept on purpose.
    function overlapActionablePairs() {
        var kept = _overlapKeptKeys()
        var out = []
        for (var i = 0; i < rulesOverlapPairs.length; i += 1) {
            var pair = rulesOverlapPairs[i]
            if (!pair || pair.redundant !== true) continue
            if (kept.indexOf(overlapPairKey(pair)) >= 0) continue
            out.push(pair)
        }
        return out
    }
    readonly property int rulesOverlapActionableCount:
        uiRevision >= 0 ? overlapActionablePairs().length : 0

    /// Remember "leave this pair alone" so the cleanup stops offering it.
    /// Written straight through: this is a decision, not a buffered setting.
    function keepOverlapPairs(keys) {
        var kept = _overlapKeptKeys()
        for (var i = 0; i < (keys || []).length; i += 1) {
            if (kept.indexOf(keys[i]) < 0) kept.push(keys[i])
        }
        updatePrefs({ rulesOverlapKeepSig: kept.join("|") })
        emitPrefs()
    }

    /// Recompute the overlap set from the rules currently on screen.
    function refreshRulesOverlaps() {
        if (_rulesOverlapInFlight) {
            _rulesOverlapStale = true
            return
        }
        if (!bridgeAvailable || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRulesOverlaps !== "function") {
            return
        }
        var rulesJson = _buildRulesJsonFromModel()
        if (!rulesJson) return
        _rulesOverlapInFlight = true
        _rulesOverlapStale = false
        var corr = nrrNativeBridge.rpcRulesOverlaps(rulesJson, prefs.routeIncludeSubdomains !== false)
        rpc.registerRpcCallback(corr, function(ok, payload) {
            _rulesOverlapInFlight = false
            rulesOverlapPairs = (ok && payload && payload.pairs) ? payload.pairs : []
            ruleOverlapsController.update((ok && payload && payload["route-overlaps"]) || [],
                ok && !_rulesOverlapStale, !!ok)
            if (_rulesOverlapStale) Qt.callLater(refreshRulesOverlaps)
        })
    }

    /// Pairs the rule still in the dialog would take part in, against the
    /// rules on screen: the edited row replaced (`index` >= 0) or the new one
    /// appended. `done(pairs, candidate)` gets nothing when the bridge is out.
    function candidateRouteOverlaps(index, row, done) {
        if (!bridgeAvailable) return
        ruleEditSupport.candidateRouteOverlaps(rulesModel, index, row,
            prefs.routeIncludeSubdomains !== false, done)
    }

    /// Delete the covered (exact) rule of each named pair. Ordinary local
    /// edits — the user applies them through the normal review flow, so a
    /// cleanup can never change what is enforced behind their back.
    function removeOverlapPairs(keys) {
        var wanted = {}
        for (var i = 0; i < (keys || []).length; i += 1) wanted[keys[i]] = true
        var victims = {}
        for (var p = 0; p < rulesOverlapPairs.length; p += 1) {
            var pair = rulesOverlapPairs[p]
            if (!wanted[overlapPairKey(pair)]) continue
            victims[String(pair["covered-route"]) + ":" + String(pair["covered-rule-id"])] = true
        }
        var removed = 0
        for (var r = rulesModel.count - 1; r >= 0; r -= 1) {
            var row = rulesModel.get(r)
            var route = (String(row.targetRoute) === "primary") ? "primary" : "secondary"
            if (victims[route + ":" + String(row.id || "")]) {
                rulesModel.remove(r)
                removed += 1
            }
        }
        if (removed > 0) {
            selectedRule = -1
            _recomputeRulesDirty()
            statusLine = Plurals.counted(tr, "status.rules-overlap-removed.", removed,
                "{count} rule removed as already covered. Apply to put the change into effect.",
                "{count} rules removed as already covered. Apply to put the change into effect.")
        }
        refreshRulesOverlaps()
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
    /// Any OTHER section holding dirty draft state.
    ///
    /// The footer already commits and reverts these (`_applyDirtySectionCallbacks`
    /// and its mirror in `cancelPendingChanges`), and the navigation guard
    /// already counts them — only the buttons did not, so a dirty panel got a
    /// warning on the way out and a greyed-out Apply on the way in.
    readonly property bool otherSectionsUnsaved: {
        var rev = uiRevision
        for (var id in unsavedChangesRegistry) {
            if (id === "rules") continue
            if (unsavedChangesRegistry[id]) return true
        }
        return false
    }
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
    /// Every dirty section, in registry order, with `rules` last when it is
    /// dirty too — the guard saves them all, and the rule apply is the one that
    /// can open its own review flow.
    function dirtySectionIds() {
        var ids = []
        for (var k in unsavedChangesRegistry) {
            if (k === "rules") continue
            if (unsavedChangesRegistry[k]) ids.push(k)
        }
        if (rulesGuardDirty()) ids.push("rules")
        return ids
    }
    /// The guard's "Discard" for rules: with the service reachable the table
    /// goes back to the rules it applies. Without it there is nothing to go
    /// back to, so the edit stays and the guard only stands down.
    function discardRuleEdits() {
        if (!rulesNotAppliedToService || !_routingBackendConnected()) return
        _refreshRulesFromService({ silent: false, confirmedEmpty: true })
    }
    function clearAllUnsavedChanges() {
        // Without the service the rule edit survives a Discard, so record the
        // acknowledgement instead of pretending it is clean; the reload that
        // reverts it otherwise re-arms the guard on its own.
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
    // Shared by every surface that shows a copyable table (cache,
    // connection trace). They live here rather than in each window because two
    // copies of "how a value is copied" is how the status line and the clipboard
    // start disagreeing.
    function copyToClipboard(text) {
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.copyToClipboard === "function") {
            nrrNativeBridge.copyToClipboard(String(text))
            statusLine = tr("status.copied-to-clipboard", "Copied to clipboard.")
        }
    }
    function copyValueLabel(value) {
        var text = Pure.displayText(value)
        if (text.length > 40) text = text.substring(0, 39) + "…"
        return tr("action.copy-value", "Copy: ") + text
    }
    // Bridge-availability check that also tells the user why nothing
    // happened. Shared by the cache surfaces; a second copy would drift on
    // the status text.
    function bridgeReadyOrWarn() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcCacheClear !== "function") {
            statusLine = tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return false
        }
        return true
    }
    function connEgressLabel(slug) {
        return tr("diag.conn-trace.egress." + String(slug || ""), String(slug || ""))
    }

    // `args` (optional) are the refusal's own values: a refusal that names
    // what it refused reads as a sentence about it, else as the code's text.
    // `tr` crosses as a value: it reads no `this`, and a `.pragma library`
    // cannot see it.
    function ipcErrorLabel(code, args) {
        return Pure.ipcErrorLabel(code, args, tr)
    }

    /// A failed service-control action: the refusal's own wording when its code
    /// has one. Codes whose detail is technical (exit code, the service's last
    /// stderr line) keep it, since that is what a bug report needs; the others
    /// carry English prose that only repeats the translated text.
    readonly property var serviceErrorCodesWithDetail: [
        "service-control-failed", "service-relocation-failed",
        "autostart-local-error", "console-path-error", "sidecar-error"
    ]
    function serviceOperationErrorText(code, message) {
        var slug = String(code || "")
        var detail = String(message || "")
        if (slug !== "") {
            var localised = tr("errors." + slug, "")
            if (localised && localised !== "errors." + slug) {
                if (detail === "" || serviceErrorCodesWithDetail.indexOf(slug) < 0)
                    return localised
                return localised + " " + tr("action.details", "Details") + ": " + detail
            }
        }
        return detail
    }

    /// The words for a `Pure.previewRefusal`: the refused values when the
    /// service names them, else the refusal code's own text.
    function previewRefusalText(refusal) {
        return Pure.previewRefusalText(refusal, tr)
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

    /// A setting another surface asked to point at (the tray's "Open
    /// settings" on a block notice): `{ id, context, serial }`. The category
    /// that owns the id scrolls to it and says why; `serial` makes a repeat of
    /// the same request a new one. `context` is display-only text.
    property var settingsFocusRequest: ({ id: "", context: ({}), serial: 0 })

    /// Focus id -> Settings category holding it.
    readonly property var _settingsFocusCategories: ({
        "doh-lockdown": "routing",
        "leak-protection": "routing",
        "forwarded-traffic": "routing",
        "restore-network": "service"
    })

    /// The system DNS left redirected: said when it appears, with the way out.
    /// A dismissed notice stays down while the state lasts; once it clears,
    /// the notice goes and the next occurrence is news again.
    property bool _systemDnsNoticeRaised: false
    property string _systemDnsNoticeId: ""
    function _onSystemDnsReading(notRestored) {
        var step = Pure.systemDnsNoticeStep(_systemDnsNoticeRaised, notRestored)
        _systemDnsNoticeRaised = step.raised
        if (!step.raised && _systemDnsNoticeId !== "") {
            notificationsController._dropPushNotice(_systemDnsNoticeId)
            _systemDnsNoticeId = ""
        }
        if (!step.raise) return
        _systemDnsNoticeId = "system-dns-not-restored:" + String(Date.now())
        notificationsController._addPushNotice({
            "id": _systemDnsNoticeId,
            "severity": "warning",
            "dismissible": true,
            "kind": "system-dns-not-restored",
            "title": tr("notifications.system-dns-not-restored.title",
                "Sites may not open by name"),
            "body": tr("notifications.system-dns-not-restored.body",
                "NetRuleRouter could not hand the system DNS settings back. Restore network removes what the service left behind."),
            "actionKey": "open-restore-network",
            "actionText": tr("settings.service.recovery.action", "Restore network")
        })
    }

    /// This user's saved rules do not read, so the last applied ones hold:
    /// said when it appears, with the way to the details. A dismissed notice
    /// stays down while it lasts; once the rules read again it goes.
    property bool _rulesBookNoticeRaised: false
    property string _rulesBookNoticeId: ""
    function _onRulesBookReading(unreadable) {
        var step = Pure.rulesBookNoticeStep(_rulesBookNoticeRaised, unreadable)
        _rulesBookNoticeRaised = step.raised
        if (!step.raised && _rulesBookNoticeId !== "") {
            notificationsController._dropPushNotice(_rulesBookNoticeId)
            _rulesBookNoticeId = ""
        }
        if (!step.raise) return
        _rulesBookNoticeId = "rules-book-unreadable:" + String(Date.now())
        notificationsController._addPushNotice({
            "id": _rulesBookNoticeId,
            "severity": "warning",
            "dismissible": true,
            "kind": "rules-book-unreadable",
            "title": tr("notifications.rules-book-unreadable.title",
                "Your saved rules cannot be read"),
            "body": tr("notifications.rules-book-unreadable.body",
                "Your saved rules cannot be read; the last applied rules stay in force. Changes will not apply until this is fixed."),
            "actionKey": "open-diagnostics",
            "actionText": tr("action.open-diagnostics", "Open diagnostics")
        })
    }

    /// A work VPN that lets only its own DNS answer pauses our name handling:
    /// said when it appears, dropped when it goes.
    property bool _dnsForeignNoticeRaised: false
    property string _dnsForeignNoticeId: ""
    function _onDnsForeignReading(foreignOnly) {
        var step = Pure.dnsUpstreamForeignNoticeStep(_dnsForeignNoticeRaised, foreignOnly)
        _dnsForeignNoticeRaised = step.raised
        if (!step.raised && _dnsForeignNoticeId !== "") {
            notificationsController._dropPushNotice(_dnsForeignNoticeId)
            _dnsForeignNoticeId = ""
        }
        if (!step.raise) return
        _dnsForeignNoticeId = "dns-foreign-only:" + String(Date.now())
        notificationsController._addPushNotice({
            "id": _dnsForeignNoticeId,
            "severity": "warning",
            "dismissible": true,
            "kind": "dns-foreign-only",
            "title": tr("notifications.dns-foreign-only.title",
                "Name handling is paused by your VPN"),
            "body": tr("notifications.dns-foreign-only.body",
                "Your work VPN only lets its own DNS answer, so NetRuleRouter's name handling is paused until another DNS answers. Rules by site name may not apply meanwhile. Disconnect the VPN, or ask its administrator to allow other DNS servers.")
        })
    }

    /// A forwarded network up with no answer for the tunnel's outage: asked once per
    /// appearance. Read only after the service answered for this user, so a
    /// policy not read yet is never taken for "not answered".
    property bool _forwardedNoticeRaised: false
    property string _forwardedNoticeId: ""
    function _onForwardedReading() {
        if (!_servicePolicyRead) return
        var step = Pure.forwardedNoticeStep(_forwardedNoticeRaised, forwardingPresent,
            _servicePolicySecondaryBound, String(routingState.forwardedOutage || ""))
        _forwardedNoticeRaised = step.raised
        if (!step.raised && _forwardedNoticeId !== "") {
            notificationsController._dropPushNotice(_forwardedNoticeId)
            _forwardedNoticeId = ""
        }
        if (!step.raise) return
        _forwardedNoticeId = "forwarded-traffic:" + String(Date.now())
        notificationsController._addPushNotice({
            "id": _forwardedNoticeId,
            "severity": "info",
            "dismissible": true,
            "kind": "forwarded-traffic",
            "title": tr("notifications.forwarded-traffic.title", "WSL or containers are running"),
            "body": tr("notifications.forwarded-traffic.body",
                "Choose what WSL, containers and virtual machines get when the additional route goes down. Until you choose, they are protected like this computer."),
            "actionKey": "open-forwarded-traffic",
            "actionText": tr("action.configure", "Configure")
        })
    }

    function openOutageBlocks() { requestSectionChange("outage-blocks") }

    function focusSetting(focusId, context) {
        var id = String(focusId || "")
        var category = _settingsFocusCategories[id]
        if (category === undefined) {
            console.log("focusSetting: unknown focus id ignored:", id)
            return false
        }
        settingsFocusRequest = {
            id: id,
            context: context || {},
            serial: Number(settingsFocusRequest.serial || 0) + 1
        }
        openSettingsCategory(category)
        return true
    }

    /// An adapter another surface asked to show (`{ name, serial }`): the
    /// Interfaces section narrows its list to it, where its role is assigned.
    property var adapterFocusRequest: ({ name: "", serial: 0 })

    function focusAdapter(name) {
        var target = String(name || "")
        if (target === "") return
        requestSectionChange("interfaces-routes", function() {
            window.adapterFocusRequest = {
                name: target,
                serial: Number(window.adapterFocusRequest.serial || 0) + 1
            }
        })
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
    property bool routingSharedStrictDetailsExpanded: false
    property bool routingSharedExemptAddressesExpanded: false
    property bool routingDohEditorExpanded: false
    property bool routingLocalSuffixesExpanded: false

    function resolveThemeModeForPrefs(preferences) {
        var effective = String((preferences || {}).effectiveThemeMode || "")
        if (effective === "light" || effective === "dark" || effective === "high-contrast") return effective

        var selected = String((preferences || {}).themeMode || "system")
        if (selected === "high-contrast") return "high-contrast"
        if (selected === "light" || selected === "dark") return selected

        var themeContext = context.theme || {}
        var systemMode = String(themeContext.systemMode || "")
        // "high-contrast" is one of the three the system can state: the OS
        // accessibility switch outranks its own light/dark preference.
        if (systemMode === "dark" || systemMode === "light"
                || systemMode === "high-contrast") return systemMode

        return "light"
    }
    /// Re-read the system appearance and, if it moved, re-resolve the theme.
    ///
    /// Only "system" is affected: a user who picked light or dark picked it,
    /// and `resolveThemeModeForPrefs` already returns that untouched. The value
    /// comes from the launcher's probe rather than from the Qt hint that woke
    /// us, so high contrast keeps outranking light/dark here exactly as it does
    /// on a cold start.
    function refreshSystemAppearance() {
        var askedAt = Date.now()
        var correlationId = rpcTransport.rpcSystemTheme()
        if (!correlationId || correlationId === "") return
        rpcTransport.registerRpcCallback(correlationId, function(ok, payload) {
            if (!ok || !payload) return
            var mode = String(payload.systemMode || "")
            if (mode !== "light" && mode !== "dark" && mode !== "high-contrast") return
            var current = context.theme || {}
            if (String(current.systemMode || "") === mode) return
            var theme = Object.assign({}, current)
            theme.systemMode = mode
            theme.systemModeDetected = payload.systemModeDetected !== false
            var ctx = Object.assign({}, context)
            ctx.theme = theme
            context = ctx
            // `normalizePrefs` drops the cached `effectiveThemeMode` and
            // recomputes it, so this is what actually repaints the window.
            prefs = normalizePrefs(prefs)
            themeRevision += 1
            // The title bar is NOT applied here: `wantDarkTitleBar` flips off
            // this same bump and re-applies to every open window, child ones
            // included. A second apply from here would repaint the main
            // window's frame twice and still miss the children.
            uiRevision += 1
            console.log("[perf] system appearance ->", mode,
                        "answered in", (Date.now() - askedAt) + "ms")
        })
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
        // Only an explicit false turns the scheduled release check off.
        normalized.updateCheckEnabled = normalized.updateCheckEnabled !== false
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
        // Experimental opt-in for the Rules -> Virtual machines screen
        // (default off). Only an explicit true opts in.
        normalized.showVirtualMachinesSection = !!normalized.showVirtualMachinesSection
        normalized.appGroupsOfferDismissed = !!normalized.appGroupsOfferDismissed
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
        // Three periods, not two: an unknown value still falls back to "today",
        // but "all-time" has to survive the round-trip or the choice is lost on
        // the next launch.
        normalized.trafficStatsPeriod =
            (normalized.trafficStatsPeriod === "session"
                || normalized.trafficStatsPeriod === "all-time")
                ? String(normalized.trafficStatsPeriod)
                : "today"
        // Remembered CSV export unit. Coerce to a known slug so the combo box
        // can index the model directly; unknown / missing → "mb" (the default).
        normalized.trafficExportUnit =
            (["bytes", "kb", "mb", "gb"].indexOf(String(normalized.trafficExportUnit)) >= 0)
                ? String(normalized.trafficExportUnit) : "mb"
        normalized.connTraceGroupBy = Pure.connTraceGroupingOrDefault(normalized.connTraceGroupBy)
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
        normalized.trayNoticeOpacityPercent =
            Math.max(40, Math.min(100, normalized.trayNoticeOpacityPercent | 0 || 100))
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
        // Remaining routing/blocking mirrors. Coerce with the SERVICE defaults
        // so the emitted payload is always valid: protocols default to all
        // (127), and the enforcement mode is one of the two known slugs.
        // Each of these prefs is a MIRROR of a service-owned route-policy field,
        // so its default is taken from the one wire-field table rather than
        // restated here — a mirror that normalises to a different default than
        // the request builder sends is the same divergence in another disguise.
        normalized.routeKillSwitchProtocols =
            Pure.routePolicyCoerce("kill-switch-protocols",
                normalized.routeKillSwitchProtocols)
        // Through the same declaration as every sibling mirror. Hand-written,
        // this was the one that answered "reactive" for a missing value — a
        // mode the code itself calls an unsupported historical fallback — and
        // any `emitPrefs()` on the literal below then SAVED that answer.
        normalized.routeEnforcementMode =
            Pure.stabilityCoerce("enforcement-mode", normalized.routeEnforcementMode)
        normalized.routeAllowDnsOverPrimary =
            Pure.routePolicyCoerce("allow-dns-over-primary",
                normalized.routeAllowDnsOverPrimary)
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
    // Apply/Cancel buffer-rollback:
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
    /// user's work? The single source of truth for that question, so every
    /// caller shares the exception below rather than keeping its own copy.
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
        boundFilesController.adoptRulesFolder(folder)
    }
    // Answered "no": never offer again. Persisted, because re-asking on the
    // next save is exactly the nagging this design avoids.
    function dismissRulesFolderSuggestion() {
        rulesFolderSuggestionPath = ""
        updatePrefs({ rulesFolderSuggestionDismissed: true })
        emitPrefs()
    }

    // Virtual machines, emulators and peer-to-peer programs found on this
    // computer, offered once for a route: a hypervisor installed long before
    // this app would otherwise never be noticed. Filled once per launch.
    property var appGroupsOfferApps: []
    readonly property bool appGroupsOfferVisible: uiRevision >= 0
        ? appGroupsOfferApps.length > 0
            && prefs.firstRunCompleted === true
            && prefs.appGroupsOfferDismissed !== true
        : false
    readonly property string appGroupsOfferText: {
        if (appGroupsOfferApps.length === 0) return ""
        var names = []
        for (var i = 0; i < appGroupsOfferApps.length && i < 3; i += 1)
            names.push(Pure.displayText(appGroupsOfferApps[i].displayName))
        var text = tr("status.app-groups-offer",
            "Found programs that can be given their own route: {names}.")
            .replace("{names}", names.join(", "))
        if (appGroupsOfferApps.length <= 3) return text
        return text + " " + tr("status.local-network-offer-more",
            "{count} more found.").replace("{count}", String(appGroupsOfferApps.length - 3))
    }

    function probeAppGroupsOffer() {
        if (!bridgeAvailable || prefs.appGroupsOfferDismissed === true) return
        var corr = rpc.rpcAppGroupsDiscover()
        if (!corr || corr === "") return
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            // Kernel virtual networks have no program to route; they are
            // shown in the dialog but are no reason to ask.
            window.appGroupsOfferApps = (payload.apps || []).filter(function(app) {
                return app && String(app.kind || "") !== "kernel-virtual-net"
            })
        })
    }

    function dismissAppGroupsOffer() {
        if (prefs.appGroupsOfferDismissed === true) return
        updatePrefs({ appGroupsOfferDismissed: true })
        emitPrefs()
    }

    // Local segments the service found and nobody has answered for yet. The
    // service exempts them from leak protection on its own, which is nearly
    // always right — a hypervisor network or the main link's own subnet never
    // leaves the machine — but "nearly" is why the user gets asked rather than
    // told. `decided-by-user` is the service's own record of having an answer,
    // so this list empties itself the moment one is given, here or in Settings.
    property var pendingLocalNetworks: []
    readonly property bool localNetworkOfferVisible:
        uiRevision >= 0 ? pendingLocalNetworks.length > 0 : false
    readonly property string localNetworkOfferText: {
        if (pendingLocalNetworks.length === 0) return ""
        var first = pendingLocalNetworks[0] || {}
        // A private segment is already reachable and the question is whether to
        // keep it so; a public IPv6 prefix stays closed until the answer.
        var head = (first.allowed === true
            ? tr("status.local-network-offer",
                "Found a local network on this computer: {cidr} ({adapter}). Keep it reachable while routed traffic is blocked?")
            : tr("status.local-network-offer-open",
                "Found your home network's IPv6 addresses: {cidr} ({adapter}). Open them to devices on this network while routed traffic is blocked?"))
            .replace("{cidr}", String(first.cidr || ""))
            .replace("{adapter}", Pure.displayText(first.adapter))
        if (pendingLocalNetworks.length === 1) return head
        return head + " " + tr("status.local-network-offer-more",
            "{count} more found.").replace("{count}",
                String(pendingLocalNetworks.length - 1))
    }

    /// Ask the service which local networks it can see. Cheap and read-only, so
    /// it runs on connect and once a day after that — a hypervisor installed
    /// months into using the app creates its network without telling anyone.
    function refreshPendingLocalNetworks() {
        if (!localNetworksSupported) return
        if (!bridgeAvailable || ((backendStatus || {}).kind) !== "connected") return
        var corr = rpc.rpcLocalNetworksGet()
        if (!corr || corr === "") return
        rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            var rows = (payload.networks || []).filter(function(n) {
                return n && n["decided-by-user"] !== true
            })
            window.pendingLocalNetworks = rows
            window.uiRevision += 1
        })
    }

    /// "Keep them reachable" — confirms every pending network at once. The
    /// service already allows them; what this writes is the ANSWER, which is
    /// what stops the offer coming back.
    function acceptPendingLocalNetworks() {
        if (!localNetworksSupported) return
        var rows = pendingLocalNetworks
        if (rows.length === 0) return
        var decisions = []
        for (var i = 0; i < rows.length; i += 1) {
            decisions.push({ "cidr": String(rows[i].cidr || ""), "allowed": true })
        }
        var corr = rpc.rpcLocalNetworksSet({ "decisions": decisions })
        if (!corr || corr === "") return
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                window.statusLine = tr("status.local-network-offer-failed",
                    "Could not save the answer; it will be asked again.")
                    + (code ? (" (" + window.ipcErrorLabel(code) + ")") : "")
                return
            }
            window.pendingLocalNetworks = []
            window.uiRevision += 1
            window.statusLine = tr("status.local-network-offer-accepted",
                "These local networks stay reachable while routed traffic is blocked.")
        })
    }

    Timer {
        id: localNetworkRecheckTimer
        interval: 24 * 60 * 60 * 1000
        repeat: true
        running: window.localNetworksSupported
        onTriggered: window.refreshPendingLocalNetworks()
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


    // Verbose service logging as the service last reported it: "off",
    // "timed" (ends at `serviceVerboseLoggingUntilMs`) or "until-restart".
    property string serviceVerboseLoggingMode: "off"
    property real serviceVerboseLoggingUntilMs: 0
    // The connection trace written to the service log, the same kind of
    // window; `serviceConnTraceLogForced` when a file or variable on the
    // service side holds it on regardless, and `...ForcedBy` names it.
    property string serviceConnTraceLogMode: "off"
    property real serviceConnTraceLogUntilMs: 0
    property bool serviceConnTraceLogForced: false
    property string serviceConnTraceLogForcedBy: ""

    // Preferences that live in the footer Apply/Cancel BUFFER: the user edits
    // them in Settings, and nothing happens until Apply. Only a patch touching
    // one of these arms the snapshot.
    //
    // The list is an allow-list on purpose. As a deny-list it had to name every
    // field the app writes on its own, and each one that was missed lit the
    // Apply button with nothing to apply — accepting the licence agreement did
    // it on the very first launch, before the user had touched anything.
    // A key absent from here commits when it is written; its writer calls
    // `emitPrefs()` in the same handler.
    /// Preferences the footer Apply / Cancel pair owns.
    ///
    /// Look-and-feel is deliberately NOT in here. Theme, font scale and font
    /// family apply the instant they are picked — the control IS the preview —
    /// so a lit Apply asks the user to confirm something they can already see,
    /// and reads as "it did not take". They commit through `commitPrefs`
    /// instead, and undoing one means picking the previous value in the same
    /// control. What stays buffered is everything whose effect is NOT visible
    /// from the control that sets it.
    readonly property var _bufferedPrefKeys: ({
        "enhancedFocus": true,
        "simplifiedLabels": true,
        "tooltipsEnabled": true,
        "language": true,
        "routePrimaryLabel": true,
        "routeSecondaryLabel": true,
        "launchWindowOnStartup": true,
        "minimizeToTrayInsteadOfClose": true,
        "reopenLastSectionOnStartup": true,
        "showNotifications": true,
        "notifyBlockNotices": true,
        "hideBlockNoticeAddresses": true,
        "trayNoticeOpacityPercent": true,
        "showBluetoothAdapters": true,
        "showRememberedAdapters": true,
        "autoConfirmAdapterIdChange": true,
        "autoLoadRulesOnLaunch": true,
        "exportIncludeComments": true,
        "importOnlyActive": true,
        "importBothFilesTogether": true,
        "mergeConflictPolicy": true,
        "showBundledPresets": true,
        "compatBannerMode": true,
        "updateCheckEnabled": true,
        "updateCheckIntervalDays": true
    })
    function _patchArmsPrefsSnapshot(patch) {
        for (var key in patch) {
            if (_bufferedPrefKeys[key]) return true
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
    /// Writes a preference and persists it WITHOUT arming the global
    /// Apply/Cancel buffer.
    ///
    /// For the one-click commits made OUTSIDE Settings — a notice's "don't show
    /// these again", the first-run wizard's answers. The user has already
    /// decided there; a footer lighting up to offer cancelling it is noise, and
    /// on a first launch it lights before the user has touched anything.
    /// A buffer already armed by real Settings edits is left alone.
    function commitPrefs(patch) {
        var hadPendingEdits = prefsSnapshot !== null
        updatePrefs(patch)
        if (!hadPendingEdits) prefsSnapshot = null
        emitPrefs()
    }
    /// Takes what another client changed in the user's settings file. The
    /// choice was made there, so Apply/Cancel does not light up for it; one
    /// still waiting for Apply here keeps the user's value.
    function adoptSharedPrefs(incoming) {
        var step = Pure.userSettingsAdoption(prefs, prefsSnapshot, _bufferedPrefKeys, incoming)
        if (prefsSnapshot !== null && Object.keys(step.rebase).length > 0) {
            prefsSnapshot = Object.assign({}, prefsSnapshot, step.rebase)
        }
        if (!step.changed) return
        prefs = normalizePrefs(Object.assign({}, prefs, step.take))
        uiRevision += 1
        if (prefsSnapshot === null) emitPrefs()
    }
    function applyPendingPrefs() {
        if (prefsSnapshot === null) return
        prefsSnapshot = null
        emitPrefs()
        statusLine = tr("status.changes-applied", "Changes applied.")
    }
    function cancelPendingPrefs() {
        if (prefsSnapshot === null) return
        // Restore ONLY the keys the buffer owns.
        //
        // Everything else commits the moment it is written — a routing toggle
        // has already reached the service, a folder has been picked, the
        // licence has been accepted — so a wholesale restore reverted work
        // Cancel was never asked about, and re-emitted it. That was held back
        // by a hand-kept list of exceptions, which could only ever fall behind
        // the app: every key added anywhere else had to be remembered here, and
        // a forgotten one silently undid a committed decision. An allow-list
        // cannot fall behind — a key that is not buffered is not restorable, by
        // construction, and `_bufferedPrefKeys` is the same list that decides
        // what arms the snapshot in the first place.
        var snapshot = normalizePrefs(prefsSnapshot)
        var restored = Object.assign({}, prefs)
        for (var key in _bufferedPrefKeys) {
            if (snapshot.hasOwnProperty(key)) restored[key] = snapshot[key]
        }
        prefs = normalizePrefs(restored)
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
            }, "footer-apply")
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
        routingPauseResumesAtMs: -1,
        routingPauseUntilRestart: false,
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
        // Why some of those are not applied (app -> reason slug); an app
        // without one found no program.
        unenforcedAppReasons: {},
        // Found programs whose rule routes none of their traffic, with why.
        unroutedAppRules: {},
        // What the service may do with the companion domains it finds
        // ("off" / "suggest" / "auto"). Mirrored from the connect snapshot so
        // the start screen can show and change it without opening Settings.
        autoRulesMode: "suggest",
        // Mirror of the per-SID "seed from browser history
        // automatically" opt-in, refreshed from the connect snapshot.
        browserHistoryAutoSeed: false,
        // Leak protection in force ("off" / "sites" / "everything"), read under
        // the service's default route; refreshed from the connect snapshot.
        leakProtection: "off",
        // Mirror of the per-SID shared-IP strictness of leak protection
        // (false = "smart": census-shared IPs are not pinned).
        killSwitchStrictSharedIps: true,
        // How many secondary IPs smart leak protection excluded from its
        // pin/block set this compute (0 = no warning).
        killSwitchSharedIpExemptions: 0,
        // The excluded addresses themselves, when the
        // service reports them. Older services send only the count above, so
        // this stays empty and the settings panel says so rather than
        // inventing a list.
        killSwitchSharedIpExemptionAddresses: [],
        // The service is holding all traffic (leak protection on, additional
        // adapter unresolved). Drives the warning banner; refreshed from the
        // connect snapshot.
        killSwitchBlockAllArmed: false,
        killSwitchHoldingForOutage: false,
        // Network filters on the machine, all users together, and whether
        // that is more than the filtering service stays stable under.
        protectionFiltersOnMachine: 0,
        protectionFiltersHigh: false,
        // What forwarded traffic gets while the tunnel is down ("" until answered).
        forwardedOutage: "",
        // Where the applied rules are enforced differently from how they
        // read (a literal-IP block over a route, a block leaking a shared
        // address). Shown on the Overlaps screen; refreshed from the snapshot.
        ruleConflicts: [],
        // The caller's rules applied despite the protection of system
        // programs, each with its term. Marks the rules list.
        ruleOverrides: []
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
    /// `onSnapshot(p)`, if given, also sees the snapshot once it is applied.
    function refreshUnenforcedAppRules(onSnapshot) {
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
            window._noteServicePolicy(rpRaw, p["first-policy"])
            window._servicePolicyRead = true
            // The standing twin of the push: a client that connected after
            // the service asked still gets the question.
            _offerPendingVpnClients(p["pending-vpn-clients"] || [])
            confirmedVpnGateways = p["confirmed-vpn-gateways"] || []
            _offerPendingVpnGateways(p["pending-vpn-gateways"] || [])
            var patch = {
                unenforcedAppRules: list,
                unenforcedAppReasons: p["unenforced-app-reasons"] || {},
                unroutedAppRules: p["unrouted-app-rules"] || {},
                // Keep the auto-seed checkbox in sync with the
                // service-side per-SID value on every reconnect/rules refresh.
                browserHistoryAutoSeed: rp["browser-history-auto-seed"] === true,
                // Same refresh for the auto-rules mode the start screen shows.
                // An absent or unknown value reads as the declared default,
                // never as "apply automatically".
                autoRulesMode: window._routePolicyEffective(rp, "auto-rules-mode"),
                leakProtection: Pure.coerceLeakProtection(
                    window._routePolicyEffective(rp, "mode"),
                    window._routePolicyEffective(rp, "leak-protection")),
                // Strictness mirror + the smart shared-IP exclusion count for
                // the settings warning.
                killSwitchStrictSharedIps: rp["kill-switch-strict-shared-ips"] === true,
                killSwitchSharedIpExemptions:
                    Number(p["kill-switch-shared-ip-exemptions"] || 0),
                // Optional companion to the count above. Absent from
                // services that only report the number — the panel then shows
                // the count alone instead of an empty or fabricated list.
                killSwitchSharedIpExemptionAddresses:
                    (p["kill-switch-shared-ip-exemption-addresses"] instanceof Array)
                        ? p["kill-switch-shared-ip-exemption-addresses"] : [],
                // The top-of-window warning follows the live "holding all
                // traffic" state.
                killSwitchBlockAllArmed:
                    p["kill-switch-block-all-armed"] === true,
                // Only a lost additional connection: the catch-all over a
                // live tunnel is armed and holds nothing back.
                killSwitchHoldingForOutage:
                    p["kill-switch-holding-for-outage"] === true,
                protectionFiltersOnMachine:
                    Number(p["protection-filters-on-machine"]) || 0,
                protectionFiltersHigh: p["protection-filters-high"] === true,
                ruleConflicts: (p["rule-conflicts"] instanceof Array)
                    ? p["rule-conflicts"] : [],
                ruleOverrides: (p["rule-overrides"] instanceof Array)
                    ? p["rule-overrides"] : [],
                forwardedOutage: window._routePolicyEffective(rp, "forwarded-outage")
            }
            // Autostart is the LAUNCHER's answer, not the service's: the
            // service runs as LocalSystem and its registry hive is not the
            // user's, so the launcher re-probes the real one and replaces this
            // field on the way through. Absent means the probe failed — keep
            // the last known value instead of painting a fabricated "off".
            var au = p.autostart
            if (au) {
                var slug = String(au["last-known-state"] || "absent")
                patch.autostartEnabled = au.enabled === true
                patch.autostartLastKnownState = slug
                patch.autostartBinaryMatches = slug !== "overridden-externally"
                patch.autostartOverrideValue = String(au["overridden-value"] || "")
            }
            updateRoutingState(patch)
            _onForwardedReading()
            _recordLinkProvidersFrom(p)
            _resyncLinkProvidersFromPrefs(p)
            // The push fires on change only; a window that connected later
            // learns the standing state here. Nothing may record these
            // statuses before this call: it skips a report equal to the one
            // already held, so a premature write hid the notice and the chip.
            _applyStandingEnforcementStatus(p["enforcement-status"])
            _applyStandingRoutesHeld(p["routes-held-by-another-user"])
            _applyStandingTrafficCarried(p["traffic-carried-by-another-user"])
            _onRulesBookReading(p["rules-book-unreadable"] === true)
            _applyPushedSettingsFromSnapshot(p)
            if (typeof onSnapshot === "function") onSnapshot(p)
        })
    }
    // Heal the service-side link-provider set after a service-DB wipe: the
    // prefs mirror survives, the per-SID table does not, and without it the
    // VPN client's own handshake is caught by leak protection. Only a service
    // that holds no route policy at all for this user has lost its data; an
    // empty set beside a stored policy is the user's own (the TUI may have
    // removed the last program), and writing the mirror over it would bring
    // the program back. Once per session, so a failing write is not retried
    // on every reconnect.
    property bool _linkProviderResyncAttempted: false
    function _resyncLinkProvidersFromPrefs(snapshot) {
        if (_linkProviderResyncAttempted) return
        var rpRaw = snapshot && (snapshot["route-policy"] || snapshot.routePolicy)
        if (rpRaw) {
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
    function _unenforcedAppReason(app) {
        var reasons = (routingState && routingState.unenforcedAppReasons) || {}
        return String(reasons[app] || "")
    }
    function _unenforcedAppRulesSummary() {
        var missing = []
        for (var i = 0; i < unenforcedAppRules.length; i += 1)
            if (_unenforcedAppReason(unenforcedAppRules[i]) === "")
                missing.push(unenforcedAppRules[i])
        return Pure.listSummary(Pure.displayTextList(missing),
            tr("status.app-unresolved-more", "+{n} more"))
    }
    /// A rule refused for its place, in the words Overlaps uses for it.
    function _unenforcedAppRefusal(app, reason) {
        if (reason === "other-users-folder")
            return tr("rules.overlaps.conflicts.other-users-folder",
                "The rule {rule} is not applied: its folder is in another user's profile, and a rule decides only for its owner's programs. To cover each user's own folder, start the path from %LOCALAPPDATA%, %APPDATA% or %USERPROFILE% on Windows, or from ~ on Linux and macOS.")
                .split("{rule}").join(Pure.displayText(app))
        var why = tr((reason === "file-in-system-folder"
                ? "rules.validation.match-value-warning.protected-"
                : "rules.validation.match-value-invalid.protected-") + reason, reason)
        return tr("rules.overlaps.conflicts.protected", "The rule {rule} is not applied. {reason}")
            .split("{rule}").join(Pure.displayText(app)).split("{reason}").join(why)
    }
    /// A found program its rule routes nothing of, with why; a reason this
    /// build does not know still says the program is there.
    function _unroutedAppText(app, reason) {
        var text = reason === "addresses-named-by-rules"
            ? tr("notifications.app-unresolved.unrouted.addresses-named-by-rules",
                "The program {app} is on this computer, but its rule routes none of its traffic: the addresses it connects to are already covered by your rules for sites and addresses, and the more specific rule wins.")
            : reason === "addresses-shared"
            ? tr("notifications.app-unresolved.unrouted.addresses-shared",
                "The program {app} is on this computer, but its rule routes none of its traffic: other programs or sites use the same addresses, and moving them would move those too.")
            : tr("notifications.app-unresolved.unrouted.other",
                "The program {app} is on this computer, but its rule routes none of its traffic.")
        return text.split("{app}").join(Pure.displayText(app))
    }
    /// The notice's text: the programs not found, then each refused rule's
    /// reason, then the found programs their rule routes nothing of.
    function _unenforcedAppNoticeBody() {
        var parts = []
        var missing = _unenforcedAppRulesSummary()
        if (missing !== "")
            parts.push(tr("notifications.app-unresolved.body",
                "NetRuleRouter couldn't find these programs (they may not be installed in a standard location, or aren't running), so their traffic isn't routed by your rules: {apps}. Launch the app, or check the program name in Rules.")
                .replace("{apps}", missing))
        for (var i = 0; i < unenforcedAppRules.length; i += 1) {
            var reason = _unenforcedAppReason(unenforcedAppRules[i])
            if (reason !== "")
                parts.push(_unenforcedAppRefusal(unenforcedAppRules[i], reason))
        }
        var unrouted = Object.keys(unroutedAppRules).sort()
        for (var j = 0; j < unrouted.length; j += 1)
            parts.push(_unroutedAppText(unrouted[j], String(unroutedAppRules[unrouted[j]])))
        return parts.join(" ")
    }
    // Correlation-id RPC transport over the C++ bridge: the pending-callback
    // table, GC timer, and bridge forwarders live in flows/RpcTransport, not
    // in the shell. Every RPC goes through `rpc.<fn>`; sections/components
    // reach it as `root.rpc`.
    property alias rpc: rpcTransport
    RpcTransport {
        id: rpcTransport
        bridge: nrrNativeBridge
        answerDeadlines: (typeof nrrLaunchContext !== "undefined" && nrrLaunchContext)
            ? (nrrLaunchContext.rpcAnswerDeadlines || null) : null
        // A long call already failed as timed out has landed after all: what it
        // applied is live, so re-read it rather than leave the window on the
        // failure. Unsaved edits are not clobbered, as on reconnect.
        onLateResponse: function(correlationId, operation, wasLong, ok, errorCode) {
            if (!ok || !wasLong || !window.bridgeAvailable) return
            // The status line still reports the timeout as a failure.
            window.statusLine = window.tr("status.screen.change-applied-late.success",
                "The change was applied after all.")
            if (!window.unsavedChangesRegistry["rules"] && !window._offlineRulesPendingPush) {
                Qt.callLater(function() { window._refreshRulesFromService({ silent: true }) })
            } else {
                Qt.callLater(window.driftController._driftRefreshServiceBaselineFromService)
            }
            _adaptersChangedSnapshotRefreshTimer.restart()
        }
        // So the user sees which alert Diagnostics asks them to acknowledge.
        // Deferred: the refusal's own callback runs first.
        onSecurityAlertGateHit: Qt.callLater(window.refreshDiagnosticsSnapshot)
    }

    ReadableToolTips {}

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
                visible: window.visible,
                rulesPathPrimary: window._comparableRulesPathFor("primary"),
                rulesPathSecondary: window._comparableRulesPathFor("secondary"),
                // The binding that answer stands on: a tray left alone sees
                // from it whether another client bound other files since.
                boundPrimary: String(window.prefs.lastSavedPathPrimary || ""),
                boundSecondary: String(window.prefs.lastSavedPathSecondary || ""),
                rulesFolder: window.userPresetsDir,
                // So the tray writes the linked files the way this window does.
                includeComments: (typeof boundFilesController !== "undefined" && boundFilesController)
                    ? boundFilesController._emitComments() : true,
                // The tray reads these once at start; this keeps it current.
                notices: window._committedNoticePrefs(),
                appearance: {
                    fontScalePercent: window.prefs.fontScalePercent,
                    systemFont: window.prefs.systemFont
                }
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
        if (active && typeof userSettingsFollower !== "undefined" && userSettingsFollower)
            userSettingsFollower.follow()
    }
    // Closed to the tray: the tray's "Add rule…" stops handing over to a hidden window.
    onVisibleChanged: {
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
        onDecidedElsewhere: function(noticeId) { notificationsController._dropPushNotice(noticeId) }
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
    // An empty list the service did not give is not "no alerts".
    readonly property bool contextSecurityAlertsKnown:
        (context.diagnostics || ({})).alertsStale !== true
    property bool securityAlertsKnown: contextSecurityAlertsKnown
    onContextSecurityAlertsKnownChanged: securityAlertsKnown = contextSecurityAlertsKnown
    // The service answered but could not read its alert store.
    readonly property bool contextSecurityAlertsUnreadable:
        (context.diagnostics || ({})).alertsUnreadable === true
    property bool securityAlertsUnreadable: contextSecurityAlertsUnreadable
    onContextSecurityAlertsUnreadableChanged:
        securityAlertsUnreadable = contextSecurityAlertsUnreadable

    // The Diagnostics cards (service, audit chain, cache, logs), seeded from the
    // launch context in `loadContext` and replaced by every live re-read.
    property var diagnosticsSnapshot: ({})
    property double _diagnosticsLiveAt: 0
    readonly property int _diagnosticsPageOpenThrottleMs: 30000

    // The launch context is a cold-start copy: an alert raised later (an
    // acknowledgement meeting a row changed since shown, a service restart)
    // holds rule changes shut without appearing in it, and a service that was
    // not up yet left every card without data. So the snapshot is re-read on
    // events, and on opening Diagnostics at most once per throttle window. One
    // read at a time; a request meanwhile is queued behind it, because the
    // read in flight may predate whatever prompted the request.
    property bool _diagnosticsReadInFlight: false
    property bool _diagnosticsReadAgain: false
    property bool _diagnosticsReadAgainForced: false
    property var _diagnosticsReadAgainWaiters: []
    function refreshDiagnosticsOnPageOpen() {
        refreshDiagnosticsSnapshot(false)
    }
    // `onDone(live, status, code)`, if given, runs once the answer this request
    // got has been applied; `status` is the service's raw answer, null for none.
    function refreshDiagnosticsSnapshot(forced, onDone) {
        _readDiagnosticsSnapshot(forced !== false, typeof onDone === "function" ? [onDone] : [])
    }
    function _notifyDiagnosticsWaiters(waiters, live, status, code) {
        for (var i = 0; i < waiters.length; i++) {
            // One throwing waiter must not starve the rest.
            try {
                waiters[i](live, status, code)
            } catch (e) {
                console.warn("diagnostics read waiter failed: " + e)
            }
        }
    }
    function _readDiagnosticsSnapshot(isForced, waiters) {
        if (!bridgeAvailable || typeof nrrNativeBridge.rpcSnapshotDiagnosticsGet !== "function") {
            _notifyDiagnosticsWaiters(waiters, false, null, "")
            return
        }
        var decision = Pure.diagnosticsReadDecision(_diagnosticsReadInFlight, isForced,
            _diagnosticsLiveAt, Date.now(), _diagnosticsPageOpenThrottleMs)
        if (decision === "queue") {
            _diagnosticsReadAgain = true
            _diagnosticsReadAgainForced = _diagnosticsReadAgainForced || isForced
            _diagnosticsReadAgainWaiters = _diagnosticsReadAgainWaiters.concat(waiters)
            return
        }
        if (decision !== "read") {
            _notifyDiagnosticsWaiters(waiters, false, null, "")
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotDiagnosticsGet()
        if (!corr) {
            _notifyDiagnosticsWaiters(waiters, false, null, "")
            return
        }
        _diagnosticsReadInFlight = true
        rpcTransport.registerRpcCallback(corr, function(ok, p, code) {
            window._diagnosticsReadInFlight = false
            var status = ok && p ? p.status : null
            var merged = Pure.diagnosticsSnapshotMerged(window.diagnosticsSnapshot, status)
            if (merged !== null) {
                window.diagnosticsSnapshot = merged
                window._diagnosticsLiveAt = Date.now()
            }
            var items = Pure.securityAlertItemsFromStatus(status)
            if (items !== null) {
                window.securityAlertItems = items
                window.securityAlertsKnown = true
                window.securityAlertsUnreadable = false
            } else if (Pure.securityAlertsUnreadable(status)) {
                // The alerts shown stay; they are just no longer known current.
                window.securityAlertsUnreadable = true
            }
            if (window._diagnosticsReadAgain) {
                var againForced = window._diagnosticsReadAgainForced
                var againWaiters = window._diagnosticsReadAgainWaiters
                window._diagnosticsReadAgain = false
                window._diagnosticsReadAgainForced = false
                window._diagnosticsReadAgainWaiters = []
                window._readDiagnosticsSnapshot(againForced, againWaiters)
            }
            window._notifyDiagnosticsWaiters(waiters, merged !== null, status,
                ok ? "" : String(code || ""))
        })
    }

    // The service refused to enforce a rule set that reached the database
    // outside the app and fell back to the last verified one. Neutral by
    // design — a restored backup or a moved installation looks the same.
    // Too many network filters on the machine: not dismissible, it stands down
    // once the rules shrink.
    readonly property bool protectionVolumeBannerVisible:
        uiRevision >= 0 && routingState.protectionFiltersHigh === true
    readonly property string protectionVolumeBannerText: uiRevision >= 0
        ? tr("status.protection-volume-high", "Rules on this computer, yours and other users' together, take {count} Windows network filters. That many can make the Windows filtering service unstable. Narrow wide rules (a domain with all its subdomains, a zone) or remove the ones you no longer need.")
            .replace("{count}", String(routingState.protectionFiltersOnMachine))
        : ""

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
    // Full reset: the two dialogs stay here (they are what the user sees), the
    // order the steps run in lives in the controller.
    property alias fullResetController: fullResetController
    FullResetController {
        id: fullResetController
        root: window
    }
    // Post-connect backlog: the ONE question covering everything parked while
    // the service was down. The dialog stays here; the collection does not.
    property alias offlineBacklogCollector: offlineBacklogCollector
    OfflineBacklogCollector {
        id: offlineBacklogCollector
        root: window
    }
    // Rule-set catalog: what sets exist, which is selected, which files back it.
    property alias ruleSetCatalog: ruleSetCatalog
    RuleSetCatalog {
        id: ruleSetCatalog
        root: window
    }
    // Startup after the licence gate, and what a provisioned answer set means
    // for the first-run wizard.
    property alias startupController: startupController
    StartupController {
        id: startupController
        root: window
    }
    // Suggested addresses: what the service parked, and what becomes of it.
    property alias autoRuleSuggestionsController: autoRuleSuggestionsController
    AutoRuleSuggestionsController {
        id: autoRuleSuggestionsController
        root: window
    }
    // `?` rules the service found working only on the other route.
    property alias verifyVerdicts: verifyVerdicts
    VerifyVerdicts {
        id: verifyVerdicts
        rpc: rpcTransport
    }
    /// The verdict card's text: what happened, what each button does, then
    /// the first few rules with the route they would move to.
    function verifyVerdictsBody(notice) {
        var lines = [tr("notifications.verify-verdicts.body",
            "They do get through over the other route and use it until the service restarts. “Move” writes them there for good; “Not now” keeps them as written and checks again after the service restarts.")]
        for (var i = 0; i < notice.shown.length; i += 1) {
            lines.push(tr("notifications.verify-verdicts.item", "{value} → {route}")
                .replace("{value}", notice.shown[i].value)
                .replace("{route}", routeLabel(notice.shown[i].to)))
        }
        if (notice.more > 0) {
            lines.push(tr("notifications.block-notice.backlog.more", "and {count} more")
                .replace("{count}", String(notice.more)))
        }
        return lines.join("\n")
    }
    /// "Move" on the verdict card. Without a rule-set folder the user first
    /// picks one, the same picker Settings uses; the rules on screen move in
    /// and the bound files then follow the move. Cancelling the picker is
    /// "Not now".
    function moveVerifyVerdicts() {
        if (!verifyVerdicts.notice) return
        if (hasRulesFolder) {
            _acceptVerifyVerdicts()
            return
        }
        dialogHost.verifyVerdictsFolderDialog.open()
    }
    function adoptFolderAndMoveVerifyVerdicts(folder) {
        setUserPresetsDir(folder)
        statusLine = tr("status.user-presets-folder-set",
            "The quick-load dropdown now lists the rule sets in your folder.")
        // Moved whatever the folder write did: the user asked for the move,
        // and a failed write has already said so on the status line.
        boundFilesController.adoptRulesFolder(folder, function() { _acceptVerifyVerdicts() })
    }
    function dismissVerifyVerdicts() {
        verifyVerdicts.dismiss(function(ok, code) {
            if (!ok) statusLine = tr("status.verify-verdicts.failed",
                "The service did not take the answer: ") + ipcErrorLabel(code)
        })
    }
    function _acceptVerifyVerdicts() {
        verifyVerdicts.accept(function(ok, code) {
            if (!ok) statusLine = tr("status.verify-verdicts.failed",
                "The service did not take the answer: ") + ipcErrorLabel(code)
        })
    }
    // Rules of the two routes claiming the same hosts: Rules → Overlaps.
    property alias ruleOverlapsController: ruleOverlapsController
    RuleOverlapsController {
        id: ruleOverlapsController
        root: window
    }
    // Hypervisors and their machines: the Rules → Virtual machines screen.
    property alias virtualMachinesController: virtualMachinesController
    VirtualMachinesController {
        id: virtualMachinesController
        root: window
    }
    // Push-driven notices: composing them, retiring them, and running what they
    // offer. The push DISPATCHER stays in this shell.
    property alias notificationsController: notificationsController
    property alias updateCheckController: updateCheckController
    UpdateCheckController {
        id: updateCheckController
        root: window
    }
    NotificationsController {
        id: notificationsController
        root: window
    }
    // "Restore my settings": the user's route policy and mutes, recorded after
    // each confirmed write of theirs and offered back to a service that lost them.
    property alias settingsRestoreController: settingsRestoreController
    SettingsRestoreController {
        id: settingsRestoreController
        root: window
    }
    // Service intent: what the user decided about service-owned settings, and
    // replaying it into a service that disagrees.
    property alias serviceIntentController: serviceIntentController
    ServiceIntentController {
        id: serviceIntentController
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
    // Per-SID route-policy apply handlers (leak protection, DoH lockdown,
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
    BoundFilesController {
        id: boundFilesController
        root: window
    }
    // The terminal client writes the user's settings file too.
    property alias userSettingsFollower: userSettingsFollower
    UserSettingsFollower {
        id: userSettingsFollower
        rpc: rpcTransport
        adopt: true
        onFollowed: function(preferences, rulesFiles) { window.adoptSharedPrefs(preferences) }
        onAnswered: function(payload) { notificationsController.noteUserSettingsAnswer(payload) }
    }
    // Helper for the VPN-onboarding handlers. Writes the confirmed
    // link-provider app set to the service (role "secondary"; an empty array
    // clears the set). The prefs mirror is the offline display fallback; on a
    // service-write failure we append a short warning to the current status line
    // (the status already shows the "will keep working" confirmation). When the
    // bridge is unavailable the correlation id is empty and no callback fires.
    // Programs named like a VPN client that sit outside the protected program
    // folders, keyed by path: the service lists them, the notice asks, and a
    // yes replaces the link provider set with everything confirmed so far
    // plus the answer (the write is a full replacement).
    /// What the additional connection being down means for this user's leak
    /// protection; the fallbacks follow the key `Pure` picks.
    function _secondaryDownBody(level) {
        var key = Pure.enforcementSecondaryDownBodyKey(level)
        if (key === "notifications.enforcement.secondary-down.body-off")
            return tr(key, "Sites your rules send there go over the main connection until it comes back: leak protection is off. Start the connection, or turn leak protection on to hold them instead.")
        if (key === "notifications.enforcement.secondary-down.body-everything")
            return tr(key, "The internet waits until it comes back, except your local network and what your rules send over the main connection — that is the protection doing its job, not a fault. Start the connection.")
        return tr(key, "Everything your rules send there is being held until it comes back — that is the protection doing its job, not a fault. Start the connection, or move those rules to the main one.")
    }

    property var _pendingVpnOffers: ({})
    function _offerPendingVpnClients(clients) {
        var offers = Pure.vpnClientTrustOffers(clients || [])
        var keep = {}
        for (var i = 0; i < offers.length; i += 1) {
            var offer = offers[i]
            var id = "vpn-client-trust:" + offer.exePath.toLowerCase()
            keep[id] = true
            _pendingVpnOffers[id] = offer
            var bundled = offer.bundledExePaths.length > 0
            notificationsController._addPushNotice({
                "id": id,
                "severity": "warning",
                "dismissible": true,
                "kind": "vpn-client-trust",
                "title": tr("notifications.vpn-client-trust.title",
                    "Is this your VPN?"),
                "body": (bundled
                    ? Plurals.counted(tr, "notifications.vpn-client-trust.body-bundle.",
                        offer.bundledExePaths.length,
                        "{name} looks like a VPN client, but it is not installed in a protected program folder, so leak protection does not trust it on its own. It ships with {count} more program that can be trusted with it.",
                        "{name} looks like a VPN client, but it is not installed in a protected program folder, so leak protection does not trust it on its own. It ships with {count} more programs that can be trusted with it.")
                    : tr("notifications.vpn-client-trust.body",
                        "{name} looks like a VPN client, but it is not installed in a protected program folder, so leak protection does not trust it on its own. Confirm it and it will keep working while leak protection is on."))
                    .replace("{name}", Pure.displayText(offer.name)),
                "actionKey": bundled ? "trust-vpn-client-bundle" : "trust-vpn-client",
                "actionText": bundled
                    ? tr("notifications.vpn-client-trust.action-bundle",
                        "This is my VPN, with the programs it ships with")
                    : tr("vpn-onboarding.confirm", "This is my VPN"),
                "secondaryActionKey": bundled ? "trust-vpn-client" : "",
                "secondaryActionText": bundled ? tr("vpn-onboarding.confirm", "This is my VPN") : "",
                "actionArg": id
            })
        }
        // Confirmed, moved or gone: its question goes with it.
        for (var old in _pendingVpnOffers) {
            if (keep[old]) continue
            notificationsController._dropPushNotice(old)
            delete _pendingVpnOffers[old]
        }
    }
    function _trustVpnClient(noticeId, withBundle) {
        var offer = _pendingVpnOffers[String(noticeId || "")]
        if (!offer) return
        var started = _replaceLinkProviders(function(existing) {
            return Pure.vpnClientTrustConfirmedApps(existing, offer, withBundle)
        }, function() {
            return tr("vpn-onboarding.confirmed-status",
                "NetRuleRouter will keep {name} working over your main link while leak protection is on.")
                .replace("{name}", Pure.displayText(offer.name))
        })
        if (!started) return
        notificationsController._dropPushNotice(String(noticeId || ""))
        delete _pendingVpnOffers[String(noticeId || "")]
    }

    // The confirmed link providers as the service last reported them: what
    // Settings shows and the picker opens with. The prefs copy only stands in
    // until the service has answered.
    property var linkProviderApps: []
    property bool linkProviderAppsKnown: false
    property bool _linkProvidersWriting: false
    function _recordLinkProvidersFrom(snapshot) {
        var rp = (snapshot && (snapshot["route-policy"] || snapshot.routePolicy)) || null
        if (!rp) return
        linkProviderApps = rp["secondary-link-provider-apps"] || []
        linkProviderAppsKnown = true
    }
    function _linkProvidersMirror() {
        var joined = (prefs && prefs.confirmedVpnExePaths) ? String(prefs.confirmedVpnExePaths) : ""
        var known = joined === "" ? [] : joined.split(";")
        var out = []
        for (var i = 0; i < known.length; i += 1) {
            var path = String(known[i] || "").trim()
            if (path !== "") out.push({ "exe-path": path, "display-name": "" })
        }
        return out
    }
    function currentLinkProviders() {
        return linkProviderAppsKnown ? linkProviderApps : _linkProvidersMirror()
    }
    function _mirrorLinkProviders(apps) {
        var paths = []
        for (var i = 0; i < (apps || []).length; i += 1) paths.push(String(apps[i]["exe-path"] || ""))
        updatePrefs({
            confirmedVpnExePaths: paths.join(";"),
            confirmedVpnExePath: paths.length > 0 ? paths[0] : ""
        })
        emitPrefs()
    }
    function _linkProvidersRead() {
        return (bridgeAvailable && typeof nrrNativeBridge !== "undefined" && nrrNativeBridge !== null
                && typeof nrrNativeBridge.rpcSnapshotInitialGet === "function")
            ? (nrrNativeBridge.rpcSnapshotInitialGet() || "") : ""
    }
    // The service replaces the set whole, so every change is worked out over
    // a fresh read: `build(existing)` gives the new set, `say(stored)` the
    // status line once the service holds it. Without the service only the
    // prefs copy changes; it goes back only to a service that lost this
    // user's policy. False while another change is in flight.
    function _replaceLinkProviders(build, say, onDone) {
        if (_linkProvidersWriting) return false
        var read = _linkProvidersRead()
        if (!read) {
            _mirrorLinkProviders(build(_linkProvidersMirror()))
            statusLine = tr("vpn-onboarding.service-write-failed",
                "Could not save to the routing service — will retry on next apply.")
            if (onDone) onDone(false)
            return true
        }
        _linkProvidersWriting = true
        rpcTransport.registerRpcCallback(read, function(ok, p, code) {
            if (!ok) {
                _linkProvidersWriting = false
                var label = (typeof ipcErrorLabel === "function")
                    ? ipcErrorLabel(String(code || "unknown")) : String(code || "")
                statusLine = tr("status.route-policy-read-failed",
                    "Could not read the current routing policy, so nothing was changed. The setting is saved and will be sent again: ")
                    + label
                if (onDone) onDone(false)
                return
            }
            _recordLinkProvidersFrom(p)
            _writeLinkProviderSet(build(linkProviderApps), function(stored) {
                _linkProvidersWriting = false
                statusLine = say(stored)
                if (onDone) onDone(true)
            }, function() {
                _linkProvidersWriting = false
                if (onDone) onDone(false)
            })
        })
        return true
    }
    function _writeLinkProviderSet(apps, onStored, onFailed) {
        var req = {
            "role": "secondary",
            "link-provider-apps": apps || []
        }
        var corr = rpcTransport.rpcRouteLinkProviderSet(req)
        if (!corr) {
            if (onFailed) onFailed()
            return
        }
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (ok) {
                // What the service stored (deduplicated), not what was sent.
                var stored = (p && p["link-provider-apps"]) || apps || []
                linkProviderApps = stored
                linkProviderAppsKnown = true
                _mirrorLinkProviders(stored)
                if (onStored) onStored(stored)
                return
            }
            // Kept on the device so the next start can send it again.
            _mirrorLinkProviders(apps || [])
            var label = (typeof ipcErrorLabel === "function")
                ? ipcErrorLabel(String(code || "unknown")) : String(code || "")
            statusLine = statusLine + " "
                + tr("vpn-onboarding.service-write-failed",
                    "Could not save to the routing service — will retry on next apply.")
                + (label ? (" (" + label + ")") : "")
            if (onFailed) onFailed()
        })
    }

    // Another VPN's server that leak protection stopped on the main link: the
    // service lists it, the notice asks, and a yes writes the confirmed list
    // whole (old list plus the answer). One write at a time, or two answers
    // built from the same old list would drop one of them.
    property var confirmedVpnGateways: []
    property var _pendingVpnGatewayOffers: ({})
    property bool _vpnGatewaysWriting: false
    function _offerPendingVpnGateways(pending) {
        var offers = Pure.vpnGatewayOffers(pending || [])
        var keep = {}
        for (var i = 0; i < offers.length; i += 1) {
            var offer = offers[i]
            var id = "vpn-gateway-trust:" + offer.address.toLowerCase()
            keep[id] = true
            _pendingVpnGatewayOffers[id] = offer
            notificationsController._addPushNotice({
                "id": id,
                "severity": "warning",
                "dismissible": true,
                "kind": "vpn-gateway-trust",
                "title": tr("notifications.vpn-gateway-trust.title", "Let this VPN connect?"),
                "body": (offer.program !== ""
                    ? tr("notifications.vpn-gateway-trust.body-program",
                        "Leak protection stopped {name} from reaching the VPN server {address} over your main connection. Allow it and that VPN connects while leak protection is on; nothing else is let through to that address.")
                        .replace("{name}", Pure.displayText(offer.name))
                    : tr("notifications.vpn-gateway-trust.body",
                        "Leak protection stopped a VPN from reaching its server {address} over your main connection. Allow it and that VPN connects while leak protection is on; nothing else is let through to that address."))
                    .replace("{address}", Pure.displayText(offer.address)),
                "actionKey": "trust-vpn-gateway",
                "actionText": tr("notifications.vpn-gateway-trust.action", "Allow this VPN"),
                "actionArg": id
            })
        }
        for (var old in _pendingVpnGatewayOffers) {
            if (keep[old]) continue
            notificationsController._dropPushNotice(old)
            delete _pendingVpnGatewayOffers[old]
        }
    }
    // The set is replaced whole, so `build(existing)` runs on a fresh read, not
    // on the copy shown (the TUI may have changed it); `onSaved` runs after
    // `confirmedVpnGateways` follows the stored answer.
    function _writeVpnGateways(build, onSaved) {
        if (_vpnGatewaysWriting) return
        var failed = function(code) {
            _vpnGatewaysWriting = false
            var label = (typeof ipcErrorLabel === "function")
                ? ipcErrorLabel(String(code || "unknown")) : String(code || "")
            // Nothing retries this write; the list stays as it was.
            statusLine = tr("vpn-onboarding.gateway-save-failed",
                    "Could not save the change to the allowed VPN servers, so nothing changed. Try again.")
                + (label ? (" (" + label + ")") : "")
        }
        var read = _linkProvidersRead()
        if (!read) { failed(""); return }
        _vpnGatewaysWriting = true
        rpcTransport.registerRpcCallback(read, function(readOk, snap, readCode) {
            if (!readOk) { failed(readCode); return }
            var list = build((snap && snap["confirmed-vpn-gateways"]) || [])
            var corr = rpcTransport.rpcRouteVpnGatewaysSet({ "gateways": list })
            if (!corr) { failed(""); return }
            rpcTransport.registerRpcCallback(corr, function(ok, p, code) {
                if (!ok) { failed(code); return }
                _vpnGatewaysWriting = false
                confirmedVpnGateways = (p && p["gateways"]) || list
                onSaved()
            })
        })
    }
    function _trustVpnGateway(noticeId) {
        var id = String(noticeId || "")
        var offer = _pendingVpnGatewayOffers[id]
        if (!offer) return
        _writeVpnGateways(function(existing) {
            return Pure.vpnGatewaysConfirmed(existing, offer)
        }, function() {
            notificationsController._dropPushNotice(id)
            delete _pendingVpnGatewayOffers[id]
            statusLine = tr("vpn-onboarding.gateway-allowed-status",
                "The VPN server {address} can now be reached while leak protection is on.")
                .replace("{address}", Pure.displayText(offer.address))
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
    // result does not flip `backendStatus` straight to "connecting" — a
    // slow-but-healthy main-channel op (rules.list, snapshot.initial.get,
    // interfaces.refresh) can be in flight when the 1 s-budget probe lands
    // behind it. Reset on any success or any non-timeout error (those are
    // real, not queue contention, so the red path below stays immediate for
    // them).
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
                // Push delivery only starts here, so anything raised before
                // this moment exists solely in the service's backlog.
                _drainBlockNoticeJournal()
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
    // The administrator-prompt line belongs to the prompt. A write whose
    // success is silent never replaced it, so once the prompt is answered the
    // line goes back to what it said before — unless the write that raised it
    // has already reported its outcome there.
    property string _consentPromptLine: ""
    property string _statusBeforeConsent: ""
    property string _statusDetailBeforeConsent: ""
    function _showConsentPromptLine() {
        if (_consentPromptLine === "" || statusLine !== _consentPromptLine) {
            _statusBeforeConsent = statusLine
            _statusDetailBeforeConsent = statusDetail
        }
        _consentPromptLine = tr("status.admin-consent-pending",
            "Waiting for you to approve administrator rights…")
        statusLine = _consentPromptLine
    }
    function _endConsentPromptLine() {
        if (_consentPromptLine === "") return
        var stale = statusLine === _consentPromptLine
        _consentPromptLine = ""
        if (stale) setStatus(_statusBeforeConsent, _statusDetailBeforeConsent)
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
            // One poll at a time: an unanswered one is not joined by another
            // every tick.
            var brokerCorr = window._brokerStatusCorr === ""
                ? String(nrrNativeBridge.rpcBrokerStatus(
                    { "auto-revoke-idle-secs": revokeSecs }) || "")
                : ""
            if (brokerCorr !== "") {
                window._brokerStatusCorr = brokerCorr
                rpcTransport.registerRpcCallback(brokerCorr, function(ok, payload) {
                    window._brokerStatusCorr = ""
                    if (!ok || !payload || payload.elevated === undefined) {
                        // Unknown is not "still asking": deadlines run again.
                        rpcTransport.consentPending = false
                        window._endConsentPromptLine()
                        return
                    }
                    window._brokerSessionElevated = payload.elevated === true
                    var awaiting = payload["awaiting-consent"] === true
                    if (awaiting !== rpcTransport.consentPending) {
                        rpcTransport.consentPending = awaiting
                        if (awaiting) window._showConsentPromptLine()
                        else window._endConsentPromptLine()
                    }
                    if (payload["auto-revoked"] === true) {
                        window.logProgress(
                            tr("status.admin-auto-revoked",
                               "Administrator approval was revoked automatically after sitting unused."),
                            "info")
                    }
                })
            }
        }
        var corr = nrrNativeBridge.rpcServiceHealthGet()
        rpcTransport.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (ok) {
                _healthTimeoutStreak = 0
                // A health reply came back over the Qt host's own IPC client,
                // so a real service is answering regardless of which facade the
                // launcher handed us at cold start.
                window.backendLiveServiceConfirmed = true
                if (!notificationsController._shippedComponentsChecked)
                    Qt.callLater(notificationsController.checkShippedComponentsOnce)
                window._onSystemDnsReading(Pure.systemDnsNotRestored(payload))
                window._onDnsForeignReading(Pure.dnsUpstreamForeignOnly(payload))
                var wasDisconnected =
                    (window.backendStatus || {}).kind !== "connected"
                if (wasDisconnected) {
                    window.backendStatus = { kind: "connected" }
                    window.logProgress(
                        tr("progress.reconnected", "Reconnected to the service."),
                        "success")
                    // Re-push the adapter binding if
                    // the service has none but prefs do (e.g. service DB wiped).
                    Qt.callLater(offlinePendingController.deliverParkedBinding)
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
                    Qt.callLater(serviceIntentController.replayServiceIntentToService)
                    // After the parked delivery and the binding resync have run:
                    // what the service still lacks is offered, never sent unasked.
                    Qt.callLater(settingsRestoreController.checkOnConnect)
                    // Re-pull the unresolved-app set so the
                    // "app not enforced" banner reflects the live service state
                    // after a reconnect (state DB may have been wiped/re-applied).
                    Qt.callLater(refreshUnenforcedAppRules)
                    // The suggestions inbox is fetched on demand, so a user
                    // sitting on that section while the service was down kept
                    // staring at an empty list after it came up.
                    Qt.callLater(function() {
                        autoRuleSuggestionsController.refreshAutoRuleCandidates()
                        autoRuleSuggestionsController.refreshAutoRuleDismissed()
                        verifyVerdicts.refresh()
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
                        offlineBacklogCollector._offlineRulesHandledByResume = true
                        offlineBacklogCollector._clearPendingApplyPark()
                        Qt.callLater(function() {
                            reviewFlowController._guardApplyRules(function(ok) {
                                // The review has settled either way, so the
                                // collector may speak about rules again.
                                offlineBacklogCollector._offlineRulesHandledByResume = false
                                driftController._driftRecheckNow()
                            }, "reconnect-resume")
                        })
                    }
                    // Service may have been updated
                    // while we were disconnected. Re-fetch the
                    // negotiate snapshot so the compatibility banner
                    // reflects the (possibly new) service version /
                    // protocol.
                    Qt.callLater(_refreshServiceInfo)
                    // A hypervisor may have been installed while we were
                    // disconnected, and its network is discoverable only from
                    // the service.
                    Qt.callLater(refreshPendingLocalNetworks)
                    // An administrator may have locked (or unlocked) rule
                    // editing while we were disconnected — re-read it so the
                    // Rules section stops offering edits that would bounce.
                    Qt.callLater(refreshRuleEditPermission)
                    // A restarted service re-checks its rows at boot and may
                    // have raised alerts that now hold rule changes shut; a GUI
                    // that started first has no Diagnostics data at all.
                    Qt.callLater(refreshDiagnosticsSnapshot)
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
                // button via `loadDemoRules()`.
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
                // One of OUR OWN long calls holds the client's single in-flight
                // slot. The health poll's one-second budget then measures the
                // queue in front of it, and every poll for the duration times
                // out without ever reaching the pipe — a rules preview took
                // 18.7 s and the GUI reported an outage it had caused itself.
                // Say nothing about the service until we stop occupying the
                // lane; a service that really died is still caught by the first
                // poll after that.
                if (rpcTransport.longCallInFlight) {
                    // Learned nothing, so keep no streak: a run of timeouts
                    // that spans the long call must not have its two halves
                    // counted as one.
                    _healthTimeoutStreak = 0
                    return
                }
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
                // The pipe alone cannot say why nobody answers; the service
                // manager can, and the banner then offers Start or Install.
                // On Linux the read is asynchronous, so this tick uses the last one.
                if (typeof nrrServiceController !== "undefined" && nrrServiceController
                        && typeof nrrServiceController.refreshStatus === "function") {
                    nrrServiceController.refreshStatus()
                }
                kind = Pure.offlineBackendKind(kind, window._serviceStatusSlug())
            }
            var prevKind = (window.backendStatus || {}).kind
            window.backendStatus = {
                kind: kind,
                lastError: (typeof window.ipcErrorLabel === "function")
                    ? window.ipcErrorLabel(code) : code
            }
            // Log only on a real transition (the poll fires every 3 s).
            if (kind !== prevKind && !Pure.backendOutageContinues(prevKind, kind)) {
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
        // The service leg (a whole-book pull) follows `revision-status-changed`;
        // the tick only re-reads it as a slow safety net.
        property int ticks: 0
        onTriggered: {
            ticks += 1
            driftController._driftRecheck(ticks % 10 === 0)
        }
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

    // A dropped frame, a fall behind the ring and a re-subscribe can all land
    // together; the state is re-read once they settle, not once each.
    Timer {
        id: _pushGapRereadTimer
        interval: 500
        repeat: false
        running: false
        onTriggered: _rereadAfterPushGap()
    }

    /// A hole in the push stream: what the lost pushes would have changed is
    /// read again from the service.
    function _rereadAfterPushGap() {
        if (!bridgeAvailable) return
        interfacesRolesController.refreshInterfacesFromService()
        // Same guard as a reconnect: unsaved edits and a parked offline import
        // must survive a gap. A clean table follows the rules in force, and so
        // do the linked files.
        if (!unsavedChangesRegistry["rules"] && !_offlineRulesPendingPush)
            boundFilesController.handleRulesChangedInService()
        else if (typeof driftController._driftRefreshServiceBaselineFromService === "function")
            driftController._driftRefreshServiceBaselineFromService()
        refreshUnenforcedAppRules()
        refreshDiagnosticsSnapshot()
        refreshPendingLocalNetworks()
        autoRuleSuggestionsController.refreshAutoRuleCandidates()
        autoRuleSuggestionsController.refreshAutoRuleDismissed()
        verifyVerdicts.refresh()
        notificationsController.onNoticeMutesChanged()
        driftController._driftRecheck(true)
        pushGapReread()
    }

    /// The service's pause start (epoch seconds) as ISO; "" without one, so the
    /// window never shows the moment it merely learned of the pause.
    function _pausedAtIso(epochSecs) {
        if (epochSecs === undefined || epochSecs === null) return ""
        var n = Number(epochSecs)
        return (isFinite(n) && n > 0) ? new Date(n * 1000).toISOString() : ""
    }

    /// The settings whose pushes fire on change only: a window that started or
    /// lost pushes after the change learns them from every snapshot.
    function _applyPushedSettingsFromSnapshot(p) {
        var patch = {}
        var paused = p["routing-paused"] === true
        if (paused !== (routingState.routingPaused === true)) {
            patch.routingPaused = paused
            patch.routingPauseReason = ""
        }
        patch.routingPausedAt = paused ? _pausedAtIso(p["routing-paused-at"]) : ""
        patch.routingPauseResumesAtMs = paused && p["routing-pause-resumes-at-ms"] !== undefined
            && p["routing-pause-resumes-at-ms"] !== null
            ? Number(p["routing-pause-resumes-at-ms"]) : -1
        patch.routingPauseUntilRestart = paused && p["routing-pause-until-restart"] === true
        var failurePolicy = p["apply-failure-policy"]
        if (failurePolicy && failurePolicy.policy)
            patch.applyFailurePolicy = String(failurePolicy.policy)
        if (p["retention-settings"])
            patch.retentionSettings = _retentionSettingsFromWire(p["retention-settings"])
        updateRoutingState(patch)
    }

    function _retentionSettingsFromWire(p) {
        return {
            supersededDays: Number(p["superseded-days"] || 30),
            supersededCountCap: Number(p["superseded-count-cap"] || 100),
            rejectedDays: Number(p["rejected-days"] || 7),
            rolledbackDays: Number(p["rolledback-days"] || 14),
            rolledbackCountCap: Number(p["rolledback-count-cap"] || 20),
            pinLkg: !!p["pin-lkg"],
            lastCleanupAt: p["last-cleanup-at"] || ""
        }
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
        onTriggered: offlineBacklogCollector._startOfflineBacklogCollect()
    }

    // The tray's "Open and compare" hand-off: re-measure the legs once the
    // window has settled, then show whichever difference is actually there.
    Timer {
        id: _driftCompareHandoffTimer
        interval: 1200
        repeat: false
        running: false
        onTriggered: driftController._driftRecheckNow(true, function(compared) {
            if (compared) driftController._driftOpenComparison()
        })
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
                    routingPausedAt: event.paused ? _pausedAtIso(event["paused-at"]) : "",
                    routingPauseReason: "",
                    routingPauseResumesAtMs: event.paused && event["resumes-at-ms"] !== undefined
                        && event["resumes-at-ms"] !== null ? Number(event["resumes-at-ms"]) : -1,
                    routingPauseUntilRestart: !!event.paused && event["until-restart"] === true
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
                        if (ok && p) updateRoutingState({ retentionSettings: _retentionSettingsFromWire(p) })
                    })
                }
                break
            case "revision-status-changed":
                console.log("revision-status-changed:",
                    event["revision-id"], "->", event.status)
                // Whoever wrote — the tray, the terminal UI, the service's own
                // authors, a reset: a clean table follows the rules in force.
                boundFilesController.handleRulesChangedInService()
                driftController._driftRecheck(true)
                break
            case "security-alerts-changed":
                refreshDiagnosticsSnapshot()
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
                    operationToastStack.model.settle(mpCorr, mpPhase, mpErr,
                                                     event["error-args"] || null)
                }
                // Refused behind an alert this window may not list yet.
                if (mpPhase === "failed" && mpErr === rpcTransport.securityAlertGateCode)
                    refreshDiagnosticsSnapshot()
                // Auto-rules land through the ordinary mutation path (the tray
                // accepted a suggestion, or "apply automatically" authored one),
                // so this push is the GUI's only notice that its rule set grew
                // without the user touching this window. The correlation-id
                // prefix is stamped by the service's auto-rule authoring.
                if (mpPhase === "completed"
                        && mpCorr.indexOf("auto-rules-") === 0) {
                    boundFilesController.handleAutoRulesAuthored(mpCorr)
                }
                // The tray's own form applies only while this window is hidden.
                if (mpPhase === "completed"
                        && mpCorr.indexOf("rules-update-tray-add-rule-") === 0) {
                    boundFilesController.handleRulesAddedFromTray()
                }
                break
            case "auto-rule-candidates-changed":
                // The tray only counts them in its menu, so the window keeps
                // the count and a way in as well.
                autoRuleSuggestionsController.autoRuleCandidatesPending = Number(event["pending-count"] || 0)
                console.log("push: auto-rule candidates pending",
                    autoRuleSuggestionsController.autoRuleCandidatesPending)
                // Re-read on EVERY announcement, not just a growing one: a set
                // that shrank to nothing is exactly when a suggestions page
                // left on screen would otherwise keep showing rows the service
                // no longer holds.
                autoRuleSuggestionsController.refreshAutoRuleCandidates()
                autoRuleSuggestionsController.refreshAutoRuleDismissed()
                // A push that only moves the count updates the badges; a notice
                // is for news, never for an empty inbox.
                if (autoRuleSuggestionsController.autoRuleCandidatesPending <= 0)
                    notificationsController._dropPushNotice(autoRuleSuggestionsController._autoRuleNoticeId)
                if (Pure.autoRuleNoticeDue(event))
                    autoRuleSuggestionsController.announce(event, eventId)
                break
            case "app-rule-learning-destinations":
                // The route for an application is built from addresses the
                // service has seen it use, so a brand-new app rule spends its
                // first minutes learning — and a program that gives up on the
                // first refusal looks broken with nothing on screen to explain
                // it.
                notificationsController._dropPushNotice(autoRuleSuggestionsController._appRuleLearningNoticeId)
                autoRuleSuggestionsController._appRuleLearningNoticeId = "app-rule-learning:" + String(eventId || "")
                notificationsController._addPushNotice({
                    "id": autoRuleSuggestionsController._appRuleLearningNoticeId,
                    "severity": "info",
                    "dismissible": true,
                    "kind": "app-rule-learning",
                    "autoDismissMs": 12000,
                    "title": tr("notifications.app-rule-learning.title",
                        "New application rule is settling in"),
                    "body": tr("notifications.app-rule-learning.body",
                        "{apps}: the service is still learning which addresses this program uses, so its first connection attempts may fail. Restart the program if it is already open.")
                        .replace("{apps}", Pure.displayTextList(event["apps"]).join(", "))
                })
                break
            case "vpn-client-awaiting-confirmation":
                // Leak protection does not trust a VPN-named program by its
                // place; the user's word is the way in. The whole list every
                // time, so a confirmed client's question goes away.
                _offerPendingVpnClients(event["clients"] || [])
                break
            case "vpn-gateway-awaiting-confirmation":
                _offerPendingVpnGateways(event["gateways"] || [])
                break
            case "rule-duplicates-detected":
                // The rules are valid; they simply claim the same traffic for
                // two routes, and evaluation order — not the user — settles
                // it. Nothing on any screen shows that, hence a notice.
                notificationsController._dropPushNotice(autoRuleSuggestionsController._ruleDuplicateNoticeId)
                autoRuleSuggestionsController._ruleDuplicateNoticeId = "rule-duplicates:" + String(eventId || "")
                notificationsController._addPushNotice({
                    "id": autoRuleSuggestionsController._ruleDuplicateNoticeId,
                    "severity": "warning",
                    "dismissible": true,
                    "kind": "rule-duplicates",
                    "muteKind": "rule-duplicates",
                    "title": tr("notifications.rule-duplicates.title",
                        "A rule is set on both routes"),
                    "body": tr("notifications.rule-duplicates.body",
                        "{count} of your rules are enabled on both routes, starting with {sample}. Which one carries the traffic is decided by evaluation order.")
                        .replace("{count}", String(Number(event["count"] || 0)))
                        .replace("{sample}", String(event["sample"] || "")),
                    "actionKey": "open-rules",
                    "actionText": tr("action.open-rules", "Open rules")
                })
                break
            case "system-dns-not-restored":
                _onSystemDnsReading(true)
                break
            case "host-unreachable-on-both-routes":
                // The offer was withheld: neither link reaches the host, so
                // there is nothing to move. In the list only, no popup — it is
                // somebody else's outage.
                notificationsController._addPushNotice({
                    "id": "host-unreachable:" + String(event["host"] || ""),
                    "severity": "info",
                    "dismissible": true,
                    "kind": "host-unreachable",
                    "refractoryMs": 86400000,
                    "title": tr("notifications.host-unreachable.title",
                        "A site does not answer on either link"),
                    "body": tr("notifications.host-unreachable.body",
                        "{host} did not answer through the main link or through the additional one, so moving it would not help and nothing was offered. The problem is most likely on the site's side.")
                        .replace("{host}", Pure.displayText(event["host"])),
                    // "Most likely" is a guess; the site check settles it.
                    "actionKey": "check-site",
                    "actionArg": String(event["host"] || ""),
                    "actionText": tr("diag.conn-trace.check-site", "Check site…")
                })
                break
            case "link-keeps-dropping":
                // Each drop was too short to tell; the service says once that
                // they keep coming, and again only after the link held.
                notificationsController._addPushNoticeUnlessMuted("link-keeps-dropping", {
                    "id": "link-keeps-dropping:" + String(event.role || "") + ":" + String(eventId || ""),
                    "severity": "warning",
                    "dismissible": true,
                    "kind": "link-keeps-dropping",
                    "noticeMuteKind": "link-keeps-dropping",
                    "title": String(event.role || "") === "primary"
                        ? tr("notifications.link-keeps-dropping.title-primary",
                            "The main connection keeps dropping")
                        : tr("notifications.link-keeps-dropping.title-secondary",
                            "The additional connection keeps dropping"),
                    "body": tr("notifications.link-keeps-dropping.body",
                        "It went down and came back several times in the last two minutes. Your rules stayed in force, but pages may have failed to load in between. Check the cable, the Wi-Fi or the VPN."),
                    "actionKey": "open-interfaces",
                    "actionText": tr("notifications.enforcement.action", "Open interfaces")
                })
                break
            case "secondary-external-address-observed":
                _onSecondaryExternalAddress(event)
                break
            case "secondary-external-address-cleared":
                _withdrawSecondaryExternalAddress()
                break
            case "block-notice-raised":
                _onBlockNoticeRaised(event, eventId)
                break
            case "block-notice-mutes-changed":
                notificationsController.onNoticeMutesChanged()
                break
            case "rule-overrides-changed":
                // A confirmation was given, taken back or ran out: the rules
                // list's marks follow the snapshot.
                refreshUnenforcedAppRules()
                var overridesEnded = []
                var overridesRaw = event.expired || []
                for (var oe = 0; oe < overridesRaw.length; oe += 1) {
                    if (String(overridesRaw[oe] || "") !== "")
                        overridesEnded.push(Pure.displayText(overridesRaw[oe]))
                }
                var overridesCause = String(event.cause || "")
                if (overridesCause === "crash-loop") {
                    notificationsController._addPushNotice({
                        "id": "rule-override-withdrawn:" + String(eventId || ""),
                        "severity": "warning",
                        "dismissible": true,
                        "kind": "rule-override-withdrawn",
                        "title": tr("notifications.rule-override-withdrawn.title",
                            "Confirmations were withdrawn"),
                        "body": tr("notifications.rule-override-withdrawn.body",
                            "Confirmations of protected rules were withdrawn: the service stopped unexpectedly several times in a row. The rules are not applied until you confirm them again in the rules list."),
                        "actionKey": "open-rules",
                        "actionText": tr("action.open-rules", "Open rules")
                    })
                } else if (overridesEnded.length > 0) {
                    var overridesRecheck = overridesCause === "services-changed"
                    notificationsController._addPushNotice({
                        "id": "rule-override-ended:" + String(eventId || ""),
                        "severity": "warning",
                        "dismissible": true,
                        "kind": "rule-override-ended",
                        "title": overridesRecheck
                            ? tr("notifications.rule-override-recheck.title",
                                "A rule needs a new confirmation")
                            : tr("notifications.rule-override-ended.title",
                                "The protection holds a rule again"),
                        "body": (overridesRecheck
                            ? tr("notifications.rule-override-recheck.body",
                                "A service now runs what {rules} takes, which your confirmation did not cover. The rule is not applied until you confirm it again in the rules list.")
                            : tr("notifications.rule-override-ended.body",
                                "The term you confirmed has ended for {rules}. The rule is not applied until you confirm it again in the rules list."))
                            .replace("{rules}", overridesEnded.join(", ")),
                        "actionKey": "open-rules",
                        "actionText": tr("action.open-rules", "Open rules")
                    })
                }
                break
            case "unassigned-tunnel-detected":
                _onUnassignedTunnel(event)
                break
            case "local-network-too-wide":
                _onLocalNetworkTooWide(event)
                break
            case "protection-coverage-changed":
                _onProtectionCoverageChanged(event)
                break
            case "verify-verdicts-changed":
                verifyVerdicts.refresh()
                break
            case "enforcement-status-changed":
                _onEnforcementStatusChanged(event)
                break
            case "routes-held-by-another-user":
                _onRoutesHeldByAnotherUser(event)
                break
            case "traffic-carried-by-another-user":
                _onTrafficCarriedByAnotherUser(event)
                break
            case "rules-book-unreadable":
                _onRulesBookReading(event.unreadable === true)
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
                // "holding all traffic" banner can outlive the
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
            case "push-gap":
                // Events were dropped (this window did not drain fast enough,
                // fell behind the service's ring, or re-subscribed), so all it
                // derived from pushes may be behind. One re-read per burst.
                if (bridgeAvailable) _pushGapRereadTimer.restart()
                break
            default:
                console.log("push: unknown event type", type)
        }
    }

    /// A tunnel is up while nothing is assigned to the additional route. The
    /// tray says so only while this window is not on screen, so the window
    /// carries the card itself, under the same mute the tray honours.
    function _onUnassignedTunnel(event) {
        var adapter = String(event["adapter-name"] || "")
        if (adapter === "") return
        notificationsController._addPushNoticeUnlessMuted("unassigned-tunnel", {
            "id": "unassigned-tunnel:" + adapter,
            "severity": "warning",
            "dismissible": true,
            "kind": "unassigned-tunnel",
            "noticeMuteKind": "unassigned-tunnel",
            // Dismissed, the same tunnel is not raised again for a while; a
            // later detection is news.
            "refractoryMs": 600000,
            "title": tr("notifications.unassigned-tunnel.title",
                "The additional route is not assigned"),
            "body": tr("notifications.unassigned-tunnel.body",
                    "{adapter} is up, but no connection is assigned to the additional route — so the sites your rules send there will not open.")
                .replace("{adapter}", Pure.displayText(adapter)),
            "actionKey": "open-interfaces",
            "actionText": tr("notifications.unassigned-tunnel.action", "Assign it now")
        })
    }

    /// The main link reported a "local" network far wider than any local
    /// network can be. The service already refuses to treat it as local; the
    /// card says which link and which number, so the user can tell a hostile
    /// access point from their own router. Not mutable: it is rare and a
    /// warning about the network the user is on right now.
    function _onLocalNetworkTooWide(event) {
        var adapter = String(event["adapter-name"] || "")
        var network = String(event["network"] || "")
        if (network === "") return
        notificationsController._addPushNotice({
            "id": "local-network-too-wide:" + adapter + ":" + network,
            "severity": "warning",
            "dismissible": true,
            "kind": "local-network-too-wide",
            "refractoryMs": 86400000,
            "title": tr("notifications.local-network-too-wide.title",
                "This network looks suspicious"),
            "body": tr("notifications.local-network-too-wide.body",
                    "{adapter} reports {network} as its local network — far wider than any local network can be. It is not treated as local: devices on it stay blocked while leak protection is on, and sites inside it still follow your rules.")
                .replace("{adapter}", Pure.displayText(adapter))
                .replace("{network}", Pure.displayText(network))
        })
    }

    /// Leak protection is not what the settings ask for, or is in force
    /// because of another user's. One card per reason; a reason this build
    /// does not know has no sentence and is dropped rather than shown raw.
    function _onProtectionCoverageChanged(event) {
        var reason = String(event.reason || "")
        var body = ""
        if (reason === "blanket-block-not-armed") {
            body = tr("status.protection.blanket-block-not-armed",
                "Leak protection \"Everything\" is not in force yet: the address of the additional connection is unknown, and blocking everything without it would cut that connection too. Traffic outside your rules is not blocked.")
        } else if (reason === "machine-wide-cut-by-another-user") {
            body = tr("status.protection.machine-wide-cut-by-another-user",
                "Another user of this computer switched on leak protection. Part of it cannot be limited to one account, so IPv6 and ping are off for everyone until they switch it off.")
        } else {
            console.log("push: protection-coverage reason not known, ignored")
            return
        }
        notificationsController._addPushNotice({
            "id": "protection-coverage:" + reason,
            "severity": "warning",
            "dismissible": true,
            "kind": "protection-coverage",
            "title": tr("notifications.protection-coverage.title",
                "Leak protection coverage changed"),
            "body": body,
            "actionKey": "open-routing-settings",
            "actionText": tr("action.open-settings", "Open settings")
        })
    }

    /// The service worked out which address the outside world sees behind the
    /// additional route — the link's own client usually cannot say. The tray
    /// shows this too; both key the notice on the push's own id, so the two
    /// surfaces never double up on one event while every (re)connect still
    /// announces itself. Keying on the address alone silenced the notice
    /// forever after the first dismissal.
    function _onSecondaryExternalAddress(event) {
        var address = String(event["external-address"] || "")
        if (address === "") return
        var adapter = String(event["adapter-name"] || "")
        // Bold only the address, not the sentence around it — the markup
        // lives here, not in the translated string, so the locale text stays
        // plain prose. Same trick as the tray's own notice for this event.
        var body = tr("tray.external-address.body",
                "External address of the additional route: {address}")
            .replace("{address}", "<b>" + Pure.escapeMarkup(address) + "</b>")
        if (adapter !== "") {
            body = body + " " + Pure.fillPlaceholders(
                tr("tray.external-address.adapter", "Adapter: {name}"),
                { name: Pure.escapeMarkup(Pure.displayText(adapter)) })
        }
        // One card per address: a reconnect that lands on the same one is not
        // news, and a card for an address the route no longer has is stale.
        var prefix = "secondary-external-address:"
        var id = prefix + adapter + ":" + address
        var stale = notificationsController._pushNotices.filter(function(n) {
            return String(n.id).indexOf(prefix) === 0 && n.id !== id
        })
        for (var i = 0; i < stale.length; i += 1) notificationsController._dropPushNotice(stale[i].id)
        // A reconnect inside the service's quiet period refreshes the value
        // only; it is not announced again.
        if (event.quiet === true) return
        notificationsController._addPushNoticeUnlessMuted("external-address", {
            "id": id,
            "severity": "info",
            "dismissible": true,
            // An answer silences this address for a while; a reconnect later is news.
            "refractoryMs": 600000,
            "noticeMuteKind": "external-address",
            "title": tr("tray.external-address.title", "Additional route connected"),
            "body": body,
            "bodyRichText": true
        })
    }

    /// The link the card named went down or changed: its exit is not the
    /// route's exit any more.
    function _withdrawSecondaryExternalAddress() {
        var prefix = "secondary-external-address:"
        var shown = notificationsController._pushNotices.filter(function(n) {
            return String(n.id).indexOf(prefix) === 0
        })
        for (var i = 0; i < shown.length; i += 1) notificationsController._dropPushNotice(shown[i].id)
    }

    /// Roles the service last reported as not enforced. Kept apart from the
    /// notice itself: the user may have dismissed the warning, and coming back
    /// out of this set is still news worth telling them.
    property var _enforcementDownRoles: []

    /// role -> the service's last enforcement status slug for it, so a screen
    /// can tell a switched-off adapter (`secondary-down`) from a removed one.
    property var enforcementStatusByRole: ({})
    /// Roles whose report is start-up quiet: not up since the service started
    /// and still within its wait, so shown but neither announced nor, when it
    /// comes up, celebrated.
    property var _enforcementQuietRoles: []
    function _setEnforcementStatus(role, status) {
        if (Pure.secondaryLinkEnded(status, role)) _withdrawSecondaryExternalAddress()
        var next = Object.assign({}, enforcementStatusByRole)
        if (status === "" || status === "ok") delete next[role]
        else next[role] = status
        enforcementStatusByRole = next
    }

    /// The snapshot's standing reports, handled as the pushes they stand for.
    /// The push fires on change only, so a window opened (or reconnected)
    /// after it would otherwise show the rules as applied. A report equal to
    /// the last one heard is skipped: the snapshot is re-read on every rules
    /// refresh, and repeating it would bring back a dismissed warning.
    function _applyStandingEnforcementStatus(reports) {
        if (!(reports instanceof Array)) return
        for (var i = 0; i < reports.length; i += 1) {
            var report = reports[i] || {}
            var role = String(report.role || "")
            var status = String(report.status || "") || "ok"
            var quiet = report.quiet === true && status !== "ok"
            if ((enforcementStatusByRole[role] || "ok") === status
                    && (_enforcementQuietRoles.indexOf(role) >= 0) === quiet) continue
            _onEnforcementStatusChanged(report)
        }
    }

    /// The channel is carrying the rules again. Worth one self-retiring line,
    /// because the browser will not say so on its own: a page that was refused
    /// while the channel was down keeps its error until it is reloaded, so the
    /// user is left thinking nothing changed.
    function _noteEnforcementRestored() {
        notificationsController._addPushNoticeUnlessMuted("enforcement-restored", {
            "id": "enforcement-restored",
            "severity": "info",
            "dismissible": true,
            "autoDismissMs": 30000,
            // The id repeats every time a channel returns; only a recent
            // dismissal silences it, so a flapping tunnel cannot nag.
            "refractoryMs": 600000,
            "noticeMuteKind": "enforcement-restored",
            "title": tr("notifications.enforcement.restored.title",
                "Routing is working again"),
            "body": tr("notifications.enforcement.restored.body",
                "Your rules are being applied again. Pages that were refused while the connection was down keep showing the error until you reload them — press F5 on those tabs."),
            "actionKey": "open-outage-blocks",
            "actionText": tr("action.outage-blocks", "What was blocked")
        })
    }

    /// The headline for a role the service reports as not enforced: the
    /// title of its notice, and what the routing chip says "limited" means.
    function enforcementStatusTitle(role, status) {
        if (status === "adapter-choice-needed")
            return tr("notifications.enforcement.adapter-choice.title",
                "Choose which adapter to use")
        if (status === "adapter-gone")
            return tr("notifications.enforcement.adapter-gone.title",
                "The saved connection is gone")
        if (status === "adapter-failed")
            return tr("notifications.enforcement.adapter-failed.title",
                "The saved connection is broken")
        if (status === "no-primary-route")
            return tr("notifications.enforcement.no-primary.title",
                "Main connection is not set")
        if (status === "primary-no-way-out")
            return tr("notifications.enforcement.primary-no-way-out.title",
                "The main connection has no way to the internet")
        if (status === "no-policy")
            return tr("notifications.enforcement.no-policy.title",
                "Connections are not chosen yet")
        if (status === "secondary-down")
            return role === "primary"
                ? tr("notifications.enforcement.primary-down.title",
                    "The main connection is not up")
                : tr("notifications.enforcement.secondary-down.title",
                    "The additional connection is not up")
        if (status === "adapters-unreadable")
            return tr("notifications.enforcement.adapters-unreadable.title",
                "Cannot read the list of connections")
        return tr("notifications.enforcement.unknown.title",
            "Your rules are not being applied")
    }

    /// One line per role not enforced, for the routing chip. Read from the
    /// statuses, not stored text, so a language switch rewords it.
    function enforcementDownDetail() {
        var lines = []
        for (var role in enforcementStatusByRole)
            lines.push(enforcementStatusTitle(role, enforcementStatusByRole[role]))
        return lines.join("\n")
    }

    /// The service reported whether this user's policy is actually in force.
    /// A standing notice, not a flash: "your rules are not applied" is a state
    /// the user has to end by acting, so it carries no auto-dismiss and its id
    /// is fixed per role — a later push about the same role replaces it, and
    /// `ok` takes it off screen.
    function _onEnforcementStatusChanged(event) {
        var role = String(event.role || "")
        var status = String(event.status || "")
        var noticeId = "enforcement-status:" + role
        var quiet = event.quiet === true && status !== "" && status !== "ok"
        var previous = String(enforcementStatusByRole[role] || "")
        _setEnforcementStatus(role, status)
        notificationsController._dropPushNotice(noticeId)
        _enforcementQuietRoles = _enforcementQuietRoles.filter(
            function(r) { return r !== role })
        if (quiet) {
            _enforcementQuietRoles = _enforcementQuietRoles.concat([role])
            _enforcementDownRoles = _enforcementDownRoles.filter(
                function(r) { return r !== role })
            return
        }
        var wasDown = _enforcementDownRoles.indexOf(role) >= 0
        if (status === "" || status === "ok") {
            // Coming back may mean the service re-matched a reinstalled adapter.
            if (status === "ok" && bridgeAvailable) {
                Qt.callLater(routePolicyController.followServiceBindingHeal)
                // Ends the leak-protection state the interfaces page reports.
                Qt.callLater(interfacesRolesController.refreshInterfacesFromService)
            }
            if (wasDown) {
                _enforcementDownRoles = _enforcementDownRoles.filter(
                    function(r) { return r !== role })
                if (Pure.enforcementRestoreIsNews(previous)) _noteEnforcementRestored()
            }
            return
        }
        if (!wasDown) _enforcementDownRoles = _enforcementDownRoles.concat([role])

        var candidates = event.candidates || []
        var title = enforcementStatusTitle(role, status)
        var body = ""
        if (status === "adapter-choice-needed") {
            body = tr("notifications.enforcement.adapter-choice.body",
                    "Several adapters answer to the saved name, so your rules are not being applied. Pick the one to use: {list}")
                .replace("{list}", Pure.displayTextList(candidates).join(", "))
        } else if (status === "adapter-gone") {
            // A vendor that replaced its adapter outright, a driver that no
            // longer starts, a connection removed by hand. The cause differs,
            // the answer does not: nothing here answers to the saved name, so
            // the choice goes back to the user.
            body = candidates.length > 0
                ? tr("notifications.enforcement.adapter-gone.body",
                        "The connection your rules were set to use is no longer on this computer, so the rules are not being applied. Pick another one: {list}")
                    .replace("{list}", Pure.displayTextList(candidates).join(", "))
                : tr("notifications.enforcement.adapter-gone.body-empty",
                    "The connection your rules were set to use is no longer on this computer, and there is nothing to replace it with right now.")
        } else if (status === "adapter-failed") {
            // The device is still on the machine and its driver will not
            // start — usually a second VPN client that installed an older copy
            // of the same driver. Picking another connection works around it;
            // repairing the driver fixes it, and only the user can decide.
            body = candidates.length > 0
                ? tr("notifications.enforcement.adapter-failed.body",
                        "The connection your rules use is still installed, but its driver will not start, so the rules are not being applied. Reinstall it, or pick another one: {list}")
                    .replace("{list}", Pure.displayTextList(candidates).join(", "))
                : tr("notifications.enforcement.adapter-failed.body-empty",
                    "The connection your rules use is still installed, but its driver will not start, and there is nothing to replace it with right now. Reinstalling it usually helps.")
        } else if (status === "no-primary-route") {
            body = tr("notifications.enforcement.no-primary.body",
                "Without a main connection there is nowhere to send traffic your rules do not route, so the rules are not being applied.")
        } else if (status === "primary-no-way-out") {
            body = tr("notifications.enforcement.primary-no-way-out.body",
                "The connection chosen as main has no gateway, so traffic your rules do not route is going out the way the system sends it instead. Choose the connection that actually reaches the internet as main.")
        } else if (status === "no-policy" && candidates.length > 0) {
            // The service names the one connection the route table points at;
            // it is bound on the interfaces page or from the tray, never here.
            title = tr("notifications.enforcement.no-policy.suggest-title",
                    "Confirm your main connection: {name}")
                .replace("{name}", Pure.displayText(String(candidates[0])))
            body = tr("notifications.enforcement.no-policy.suggest-body",
                "Nothing is routed until you confirm it. Rules for the additional connection wait until you choose one.")
        } else if (status === "no-policy") {
            body = tr("notifications.enforcement.no-policy.body",
                "The service has no routing settings for you yet, so nothing is being routed. Choose the main and additional connections.")
        } else if (status === "secondary-down") {
            // The service reports which role went down; before this the primary
            // going down was announced as "the additional connection is not up".
            if (role === "primary") {
                body = tr("notifications.enforcement.primary-down.body",
                    "Traffic that is not routed to the additional connection has nowhere to go until it comes back. Check the cable, the Wi-Fi, or pick another main connection.")
            } else {
                body = _secondaryDownBody(routingState.leakProtection)
            }
        } else if (status === "adapters-unreadable") {
            body = tr("notifications.enforcement.adapters-unreadable.body",
                "The service cannot enumerate network adapters right now, so your rules are not being applied. This usually clears itself; if it does not, restart the service.")
        } else {
            // An unknown status still says the one thing that matters.
            body = tr("notifications.enforcement.unknown.body",
                "The service reported a state this version does not recognise. Open interfaces and routes to check the setup.")
        }
        // A switched-off tunnel is the one state here the user may silence;
        // the rest are faults to fix, so their cards offer no mute.
        var routine = status === "secondary-down" && role !== "primary"
        var card = {
            "id": noticeId,
            "severity": "warning",
            "dismissible": true,
            "kind": "enforcement-status",
            "noticeMuteKind": routine ? "secondary-down" : "",
            "title": title,
            "body": body,
            "actionKey": "open-interfaces",
            "actionText": tr("notifications.enforcement.action",
                "Open interfaces")
        }
        // The mute read may outlast the outage.
        if (routine) {
            notificationsController._addPushNoticeUnlessMuted("secondary-down", card,
                function() { return window._enforcementDownRoles.indexOf(role) >= 0 })
            return
        }
        notificationsController._addPushNotice(card)
    }

    /// Id of the card about destinations another signed-in user's routing
    /// holds, and the state it shows ("" when nothing is held).
    property string _routesHeldNoticeId: ""
    property string _routesHeldSignature: ""

    /// Some of this user's destinations follow another signed-in user's route.
    /// One card per distinct set: a dismissed one stays dismissed while the set
    /// is the same, a changed set is news, and a zero count takes it down.
    function _onRoutesHeldByAnotherUser(event) {
        var count = Number((event && event.count) || 0)
        var sample = (event && event.sample instanceof Array) ? event.sample : []
        var signature = count > 0 ? String(count) + "|" + sample.join(",") : ""
        _routesHeldSignature = signature
        if (_routesHeldNoticeId !== "")
            notificationsController._dropPushNotice(_routesHeldNoticeId)
        _routesHeldNoticeId = ""
        if (signature === "") return
        var noticeId = "routes-held:" + signature
        _routesHeldNoticeId = noticeId
        notificationsController._addPushNoticeUnlessMuted("routes-held", {
            "id": noticeId,
            "severity": "warning",
            "dismissible": true,
            "kind": "routes-held",
            "noticeMuteKind": "routes-held",
            // The same set coming back on another day is worth saying again.
            "refractoryMs": 86400000,
            "title": tr("notifications.routes-held.title",
                "Some addresses follow another user's route"),
            "body": tr("notifications.routes-held.body",
                "Another user signed in to this computer already routes some addresses from your rules through a different connection. Addresses affected: {count}. While that user stays signed in, these addresses follow their route, or are blocked for you if leak protection is on. Among them: {list}.")
                .replace("{count}", String(count))
                .replace("{list}", sample.join(", "))
        }, function() { return _routesHeldNoticeId === noticeId })
    }

    /// The snapshot's standing report, handled as the push it stands for; one
    /// equal to the state already held is skipped, as for enforcement reports.
    function _applyStandingRoutesHeld(report) {
        var count = Number((report && report.count) || 0)
        var sample = (report && report.sample instanceof Array) ? report.sample : []
        var signature = count > 0 ? String(count) + "|" + sample.join(",") : ""
        if (signature === _routesHeldSignature) return
        _onRoutesHeldByAnotherUser({ "count": count, "sample": sample })
    }

    /// Id of the card saying another user's tunnel carries this user's
    /// traffic, and the connection it names ("" while it does not).
    property string _trafficCarriedNoticeId: ""
    property string _trafficCarriedSignature: ""

    /// What this user's rules do not route rides another signed-in user's
    /// tunnel. One card per carrying connection; `carried: false` takes it down.
    function _onTrafficCarriedByAnotherUser(event) {
        var carried = !!(event && event.carried === true)
        var link = carried ? Pure.displayText(String((event && event.link) || "")) : ""
        var signature = carried ? "carried|" + link : ""
        _trafficCarriedSignature = signature
        if (_trafficCarriedNoticeId !== "")
            notificationsController._dropPushNotice(_trafficCarriedNoticeId)
        _trafficCarriedNoticeId = ""
        if (signature === "") return
        var noticeId = "traffic-carried:" + link
        _trafficCarriedNoticeId = noticeId
        var body = link !== ""
            ? tr("notifications.traffic-carried.body",
                "Another user of this computer signed in earlier and sends all their traffic through the tunnel \"{link}\". This computer has one route table for everyone, so whatever your rules do not send to your additional connection goes through that tunnel too. To avoid this, sign in before that user, or ask them to send only chosen sites through their tunnel.")
                .replace("{link}", function() { return link })
            : tr("notifications.traffic-carried.body-unnamed",
                "Another user of this computer signed in earlier and sends all their traffic through their tunnel. This computer has one route table for everyone, so whatever your rules do not send to your additional connection goes through that tunnel too. To avoid this, sign in before that user, or ask them to send only chosen sites through their tunnel.")
        notificationsController._addPushNoticeUnlessMuted("traffic-carried", {
            "id": noticeId,
            "severity": "warning",
            "dismissible": true,
            "kind": "traffic-carried",
            "noticeMuteKind": "traffic-carried",
            // Still carried on another day is worth saying again.
            "refractoryMs": 86400000,
            "title": tr("notifications.traffic-carried.title",
                "Your traffic goes through another user's tunnel"),
            "body": body
        }, function() { return _trafficCarriedNoticeId === noticeId })
    }

    /// The snapshot's standing report, handled as the push it stands for; one
    /// equal to the state already held is skipped.
    function _applyStandingTrafficCarried(report) {
        var carried = !!(report && report.carried === true)
        var link = carried ? Pure.displayText(String((report && report.link) || "")) : ""
        var signature = carried ? "carried|" + link : ""
        if (signature === _trafficCarriedSignature) return
        _onTrafficCarriedByAnotherUser({ "carried": carried, "link": carried ? report.link : "" })
    }

    /// One reason slug -> the sentence explaining it. Mirrors the tray's own
    /// wording for the same event.
    function _blockNoticeReasonText(reason) {
        switch (String(reason || "")) {
            case "route-unavailable":
                return tr("notifications.block-notice.reason.route-unavailable",
                    "The route this connection needed was unavailable.")
            case "blocked-by-rule":
                return tr("notifications.block-notice.reason.blocked-by-rule",
                    "A rule denies this connection.")
            case "ipv6-blocked":
                return tr("notifications.block-notice.reason.ipv6-blocked",
                    "With leak protection set to Everything, IPv6 goes out only through the additional connection, so this connection did not go out.")
            case "dns-lockdown":
                return tr("notifications.block-notice.reason.dns-lockdown",
                    "This app went to its own DNS resolver instead of the one NetRuleRouter provides, "
                    + "and encrypted-DNS blocking closed it.")
            case "unattributed":
                return tr("notifications.block-notice.reason.unattributed",
                    "NetRuleRouter blocked this connection, but could not identify which filter did it.")
            default:
                return tr("notifications.block-notice.reason.unknown",
                    "This connection was blocked.")
        }
    }

    /// Drain the notices the service raised while nothing was subscribed —
    /// no window, no tray icon. One summary card, not one per entry: a user
    /// who was away for a day would otherwise open the app to a wall of
    /// identical toasts, and the backlog is news, not a log.
    ///
    /// Acknowledged by the largest id actually read, so an episode raised
    /// while this call was in flight survives to be shown next time.
    function _drainBlockNoticeJournal() {
        if (!blockNoticesSupported) return
        if (!bridgeAvailable || !rpcTransport
                || typeof rpcTransport.rpcBlockNoticeJournalList !== "function") return
        var corr = rpcTransport.rpcBlockNoticeJournalList()
        if (!corr || corr === "") return
        rpcTransport.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) return
            var summary = Pure.blockNoticeBacklog(p.entries)
            if (!summary) return
            // Muted kind: still acknowledged. Keeping entries nobody will ever
            // be shown would just age out silently a week later.
            if (notificationsController.noticeKindEnabled("block-notice")) {
                _addBlockNoticeBacklogCard(summary)
            }
            if (summary.throughId > 0) {
                var ackCorr = rpcTransport.rpcBlockNoticeJournalAck({ "through-id": summary.throughId })
                rpcTransport.registerRpcCallback(ackCorr, function(ackOk, ackPayload, code, msg) {
                    if (!ackOk) console.warn("block-notice journal ack failed:", code, msg)
                })
            }
        })
    }

    function _addBlockNoticeBacklogCard(summary) {
        var hide = prefs.hideBlockNoticeAddresses === true
        var list = hide ? "" : Pure.displayTextList(summary.shown).join(", ")
        if (!hide && summary.more > 0) {
            list = list + ", " + tr("notifications.block-notice.backlog.more", "and {count} more")
                .replace("{count}", String(summary.more))
        }
        var body = Plurals.counted(tr, "notifications.block-notice.backlog.counted.", summary.count,
            "The service blocked {count} connection while NetRuleRouter was not open.",
            "The service blocked {count} connections while NetRuleRouter was not open.")
        if (list !== "") {
            body = body + " " + tr("notifications.block-notice.backlog.destinations",
                "Destinations: {list}.").replace("{list}", list)
        }
        notificationsController._addPushNoticeUnlessMuted("block-notice-backlog", {
            "id": "block-notice-backlog:" + String(summary.throughId),
            "severity": "warning",
            "dismissible": true,
            "kind": "block-notice",
            "muteKind": "block-notice",
            "noticeMuteKind": "block-notice-backlog",
            "title": tr("notifications.block-notice.backlog.title",
                "Blocked while the app was closed"),
            "body": body
        })
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
        if (!notificationsController.noticeKindEnabled("block-notice")) return
        var app = String(event.app || "")
        var attempts = Number(event.attempts || 0)
        var destDisplay = prefs.hideBlockNoticeAddresses === true
            ? tr("notifications.block-notice.destination-hidden", "a hidden destination")
            : Pure.displayText(destination)
        var appDisplay = app !== "" ? Pure.displayText(app)
            : tr("notifications.block-notice.app-unknown", "unknown application")
        var body = tr("notifications.block-notice.body",
                "{reason} Destination: {destination}. Application: {app}. Attempts: {attempts}.")
            .replace("{reason}", _blockNoticeReasonText(event.reason))
            .replace("{destination}", destDisplay)
            .replace("{app}", appDisplay)
            .replace("{attempts}", String(attempts))
        notificationsController._addPushNotice({
            "id": "block-notice:" + String(eventId),
            "severity": "warning",
            "dismissible": true,
            "kind": "block-notice",
            "muteKind": "block-notice",
            "title": tr("notifications.block-notice.title", "Connection blocked"),
            "body": body,
            // A blocked connection raises exactly one question, and the tool
            // that answers it was two screens away unless something pointed at
            // it. The address travels with the action, so the probe runs on the
            // host this notice is about.
            "actionKey": "explain-host",
            "actionArg": destination,
            "actionText": tr("notifications.block-notice.explain", "Why?")
        })
    }

    // The write replaces every field, so `values` (only what the user changed)
    // goes over a fresh read, not over a copy that may be defaults never read.
    function setRetentionSettings(values) {
        if (!bridgeAvailable) {
            updateRoutingState({
                retentionSettings: Object.assign({}, routingState.retentionSettings, values || {})
            })
            return
        }
        var readCorr = nrrNativeBridge.rpcRetentionSettingsGet()
        if (!readCorr) return
        rpcTransport.registerRpcCallback(readCorr, function(readOk, fresh, readCode, readMsg) {
            if (!readOk || !fresh) {
                console.log("retention-set skipped, read failed:", readCode, readMsg)
                return
            }
            var merged = Object.assign({}, _retentionSettingsFromWire(fresh), values || {})
            updateRoutingState({ retentionSettings: merged })
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
            routingPauseReason: paused ? (reason || "") : "",
            routingPauseResumesAtMs: -1,
            routingPauseUntilRestart: false
        })
        if (!bridgeAvailable) return
        var corr = nrrNativeBridge.rpcRoutingPauseToggle(!!paused, reason || "")
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) console.log("routing-pause-toggle failed:", code, msg)
            // On success the server returns authoritative paused_at;
            // A later change will replace the synthetic timestamp.
        })
    }
    /// Pauses the rules for `term` (`fifteen-minutes` … `until-resumed`).
    function pauseRoutingFor(term, reason) {
        var slug = String(term || "until-resumed")
        updateRoutingState({
            routingPaused: true,
            routingPausedAt: new Date().toISOString(),
            routingPauseReason: reason || ""
        })
        if (!bridgeAvailable || typeof nrrNativeBridge.rpcRoutingPauseFor !== "function") return
        var corr = nrrNativeBridge.rpcRoutingPauseFor(slug, reason || "")
        rpcTransport.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("routing-pause-for failed:", code, msg)
                updateRoutingState({ routingPaused: false, routingPausedAt: "" })
            }
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
        // A role the service reports as not enforced: its rules are blocked,
        // which "active" would contradict.
        if (_enforcementDownRoles.length > 0) return "limited"
        return "active"
    }

    function systemLanguage() { return resolveLanguageId(Qt.locale().name) }
    // Anchor against Main.qml — without `Qt.resolvedUrl`, relative
    // paths get re-resolved by the consumer (e.g. ThemedButton in
    // components/) and point to apps/assets/... which doesn't exist.
    // A folder the window computed; the bridge opens it only as a directory.
    function openOwnFolder(url) {
        var path = Pure.ownFolderPath(url)
        if (path !== "" && typeof nrrNativeBridge !== "undefined"
                && typeof nrrNativeBridge.openFolder === "function") {
            nrrNativeBridge.openFolder(path)
        }
    }
    function uiIconSource(name) { return assetUrl("icons/" + (highContrastIcons ? "ui-hc/" : "ui/") + name + ".svg") }
    // The same icon for a control painted with the accent fill. The normal
    // set is a blue/indigo gradient, which on that fill is invisible; the
    // high-contrast set is the same icons painted white, which is what
    // `palette.highlightedText` puts next to them.
    function uiIconSourceOnAccent(name) { return assetUrl("icons/ui-hc/" + name + ".svg") }
    function sectionIconSource(sectionId) {
        if (sectionId === "interfaces-routes") return assetUrl("icons/" + (highContrastIcons ? "status-hc/" : "status/") + "interface-ok.svg")
        if (sectionId === "rules") return uiIconSource("search")
        if (sectionId === "diagnostics") return uiIconSource("diagnostics")
        if (sectionId === "logs") return uiIconSource("logs")
        if (sectionId === "settings") return uiIconSource("settings")
        return appIconSmallSource
    }
    function routeIconSource(routeId) {
        // "block" ships only as an SVG (a drop has no adapter PNG set); render
        // it as SVG in both normal and high-contrast modes.
        if (routeId === "block") return assetUrl("icons/status" + (highContrastIcons ? "-hc" : "") + "/route-block.svg")
        if (highContrastIcons) return assetUrl("icons/status-hc/" + (routeId === "secondary" ? "route-secondary" : "route-primary") + ".svg")
        return assetUrl("icons/status/" + (routeId === "secondary" ? "route-secondary-20.png" : "route-primary-20.png"))
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
        case "exact-ipv6":
        case "subnet":
        case "ip-range":
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
        // The host parses the context file; when it could not, nothing here can.
        if (typeof nrrLaunchContext === "undefined" || !nrrLaunchContext) return
        context = nrrLaunchContext
        assetsRootUrl = String(context.assetsRootUrl || "")
        localeCatalog = context.localeCatalog || {}
        availableLanguages = context.availableLanguages || []
        platformProfile = context.platformProfile || platformProfile
        prefs = normalizePrefs(Object.assign({}, prefs, context.preferences || {}))
        currentLanguage = prefs.language
        backendStatus = context.backendStatus || { kind: "connected" }
        backendServiceBacked = context.backendServiceBacked !== false
        // Whoever stopped the service may have meant it: say it runs again.
        if (context.serviceStartedOnLaunch === true) {
            Qt.callLater(function() {
                statusLine = tr("status.service-started-on-launch",
                    "The service was stopped, so it has been started again.")
            })
        }
        // The file stays untouched so a later start can still read it; until
        // then this session runs on defaults and saves nothing.
        if (context.preferencesUnreadable === true) {
            Qt.callLater(function() {
                notificationsController._addPushNotice({
                    "id": "settings-unreadable",
                    "severity": "warning",
                    "dismissible": true,
                    "title": tr("notifications.settings-unreadable.title",
                        "Your settings could not be read"),
                    "body": tr("notifications.settings-unreadable.body",
                        "This session uses default settings and will not save changes, so your saved settings stay as they are. Close the app and open it again; if the file is locked by another program, free it first.")
                })
            })
        }
        // Parts of the package this copy lacks, named once the window is up.
        var deliveryGaps = context.deliveryGaps || []
        if (deliveryGaps.length > 0)
            Qt.callLater(function() { notificationsController.noteDeliveryGaps(deliveryGaps) })
        // Before `section`: opening Diagnostics right away must see whether
        // the launch snapshot already counts as a fresh live answer.
        diagnosticsSnapshot = context.diagnostics || ({})
        if (Pure.diagnosticsSnapshotIsLive(diagnosticsSnapshot)) _diagnosticsLiveAt = Date.now()
        // Cold-start loads the persisted theme/font — force the theme
        // tokens to recompute from the freshly-bound prefs (uiRevision no
        // longer drives the theme; see the themeRevision split).
        themeRevision += 1
        uiRevision += 1
        section = context.entrySection || prefs.lastOpenedSection || "interfaces-routes"
        // The virtual-machines screen is behind an experimental opt-in; a
        // remembered section must not reopen it once the opt-in is off.
        if (section === "rule-virtual-machines" && prefs.showVirtualMachinesSection !== true)
            section = "rules"
        localeDiagnostics = context.localeDiagnostics || {}
        if (Number(localeDiagnostics.rejected || 0) > 0) {
            statusLine = tr("status.locale-files-rejected", "Some locale files were rejected. See logs for details.")
        } else if (Number(localeDiagnostics.acceptedWithWarnings || 0) > 0) {
            statusLine = tr("status.locale-files-warning", "Some locale files were loaded with warnings.")
        }

        interfacesRowsAll = ((context.interfaces || {}).rows) || []
        interfacesDataSource = String((context.interfaces || {}).dataSource || "fallback-mock")
        interfacesRolesController.rebuildInterfacesModel()
        interfacesRolesController.loadExternalIpCache()
        Pure.clearModel(behaviorModeModel)
        var modes = ((context.interfaces || {}).supportedBehaviorModes) || []
        for (var m = 0; m < modes.length; m += 1) behaviorModeModel.append(modes[m])
        Pure.clearModel(ruleTypesModel)
        var types = Rules.offeredRuleTypes(((context.rules || {}).supportedRuleTypes) || [],
            supports("appRouting"))
        for (var t = 0; t < types.length; t += 1) ruleTypesModel.append(types[t])
        Pure.clearModel(rulesModel)
        // Rows are seeded only from a connected backend (a real service, or
        // the explicit mock build: BackendChoice::Mock emits kind:"connected").
        // A stopped service leaves the model empty until
        // _refreshRulesFromService hydrates the real rules on connect.
        var rulesRows = (((backendStatus || {}).kind) === "connected")
            ? (((context.rules || {}).rows) || [])
            : []
        // Normalise rule ids to the canonical R-NNNN form on load
        // so downstream duplicate-checks and nextFreeRuleId()
        // can rely on a single shape regardless of where the row
        // originated (mock backend / preset import / etc.).
        var seedBatch = []
        for (var k = 0; k < rulesRows.length; k += 1) {
            var row = rulesRows[k]
            if (!row) continue
            if (row.id) row.id = Rules.canonicalRuleId(row.id)
            // Boundary conversion (inbound): snapshot rows carry ACE on
            // host-like rule types; decode for display.
            if (Rules.isHostlikeRuleType(row.ruleType)) {
                row.matchValue = _unicodeDecodeHost(row.matchValue)
            }
            row.aceMatchValue = _aceLowerForSearch(row.matchValue)
            // Seed the provenance roles as STRINGS even though the cold-start
            // snapshot never carries an origin: the first append is what fixes
            // each role's type, and a service refresh later in the session
            // appends rows that DO carry one.
            row.originReason = String(row.originReason || "")
            row.originAnchor = String(row.originAnchor || "")
            row.originAdded = String(row.originAdded || "")
            seedBatch.push(row)
        }
        // One append for the whole book — see `_appendRowsChunked`.
        if (seedBatch.length > 0) rulesModel.append(seedBatch)
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
        if (logsRows.length > 0) logsModel.append(logsRows)
    }

    function emitPrefs() {
        var payload = normalizePrefs(Object.assign({}, prefs))
        payload.lastOpenedSection = section
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge && nrrNativeBridge.savePreferences) {
            nrrNativeBridge.savePreferences(JSON.stringify(payload))
        }
    }

    // Open the VPN-client picker over a fresh read of the stored set, so it
    // opens with exactly what the service holds ticked; a failed read says so
    // rather than offering the prefs copy for saving.
    function openVpnOnboarding() {
        if (typeof vpnOnboardingDialog === "undefined" || !vpnOnboardingDialog) return
        var read = _linkProvidersRead()
        if (!read) {
            vpnOnboardingDialog.openUnread()
            return
        }
        rpcTransport.registerRpcCallback(read, function(ok, p) {
            if (!ok) {
                vpnOnboardingDialog.openUnread()
                return
            }
            _recordLinkProvidersFrom(p)
            vpnOnboardingDialog.open(currentLinkProviders())
        })
    }

    // Open the app-group routing dialog (scan installed programs,
    // assign popular groups to primary/secondary). Sections reach it through
    // this window-level entry point (a visible "Set up routes" button is added
    // by the Interfaces/Routes section, not inlined here).
    function openAppGroupRouting() {
        dismissAppGroupsOffer()
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
        // The decision (which rules go, switch or appear) is Pure's; this
        // function only carries it out on the model.
        var appRows = []
        var modelIndex = []
        for (var mi = 0; mi < rulesModel.count; mi += 1) {
            var mrow = rulesModel.get(mi)
            if (String(mrow.ruleType || "") !== "application") continue
            appRows.push({
                value: String(mrow.matchValue || ""),
                route: String(mrow.targetRoute || ""),
                enabled: mrow.enabled !== false
            })
            modelIndex.push(mi)
        }
        var wanted = []
        var kindByValue = ({})
        var secondaryCount = 0
        for (var wi = 0; wi < list.length; wi += 1) {
            var wv = String(list[wi].matchValue || "")
            var wr = String(list[wi].route || "")
            if (wv === "") continue
            wanted.push({ value: wv, route: wr })
            if (wr === "secondary") {
                secondaryCount += 1
                kindByValue[wv] = String(list[wi].kind || "")
            }
        }
        var plan = Pure.planAppRouteAssignments(appRows, wanted)
        // Highest model index first, so earlier removals do not shift later ones.
        var doomed = plan.remove.map(function(i) { return modelIndex[i] })
            .sort(function(x, y) { return y - x })
        for (var di = 0; di < doomed.length; di += 1) {
            rulesModel.remove(doomed[di])
            mutated = true
        }
        var shift = function(at) {
            var n = 0
            for (var q = 0; q < doomed.length; q += 1) if (doomed[q] < at) n += 1
            return at - n
        }
        for (var ti = 0; ti < plan.retarget.length; ti += 1) {
            var upd = rulesModel.get(shift(modelIndex[plan.retarget[ti]]))
            // A disabled rule routes nothing: enabling it is the change.
            rulesModel.set(shift(modelIndex[plan.retarget[ti]]), {
                id: upd.id,
                enabled: true,
                ruleType: "application",
                ruleTypeTitle: ruleTypeLabel("application"),
                matchValue: upd.matchValue,
                aceMatchValue: _aceLowerForSearch(upd.matchValue),
                targetRoute: "secondary",
                comment: upd.comment
            })
            mutated = true
        }
        // Counted once and carried: re-walking the model per rule is quadratic.
        var limitHit = false
        var userCount = userRuleCount()
        for (var ai = 0; ai < plan.add.length; ai += 1) {
            if (userCount >= freeRulesMaxCount) {
                limitHit = true
                break
            }
            userCount += 1
            var mv = String(plan.add[ai])
            var kind = kindByValue[mv] || ""
            var item = {
                id: nextFreeRuleId(),
                enabled: true,
                ruleType: "application",
                ruleTypeTitle: ruleTypeLabel("application"),
                matchValue: mv,
                aceMatchValue: _aceLowerForSearch(mv),
                targetRoute: "secondary",
                comment: tr("app-groups.group." + kind, kind)
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
            statusLine = Plurals.counted(tr, "app-groups.confirmed-status.", secondaryCount,
                "Routes updated for {count} program.", "Routes updated for {count} programs.")
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Offline routing-settings intents.
    //
    // Service-owned routing settings (the per-SID route-policy toggles + the
    // shared service-stability config) are edited in the GUI. When the service
    // is STOPPED the controls stay live but the RPC can't land, so every
    // offline edit is PARKED as an explicit "pending intent" in
    // `prefs.routePendingOfflineJson` (a compact single-line JSON object,
    // "" = none) rather than silently lost to the service's stale value
    // winning on the next start. On the next backend connect we offer a
    // dialog to Apply or Discard — nothing is ever pushed silently.
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

    /// Is this window showing INVENTED data while claiming a healthy service?
    ///
    /// `NRR_BACKEND=mock` hands the window a stand-in facade
    /// that reports `connected`, so every surface paints "all fine" over
    /// snapshots that never touched the service and over edits that never reach
    /// it. The launcher says so in its log; the log is not what the person is
    /// looking at.
    ///
    /// Deliberately NOT keyed on `backendServiceBacked` alone: the IPC
    /// cold-start fallback sets that too, and there the connection banner
    /// already tells the truth in red. Only the chosen preview backend claims
    /// `connected` while nothing behind it is real, and a live health read
    /// (`backendLiveServiceConfirmed`) ends the condition for good.
    readonly property bool previewDataBannerVisible:
        uiRevision >= 0
        && !!backendStatus && backendStatus.kind === "connected"
        && !backendServiceBacked && !backendLiveServiceConfirmed

    /// Parse the parked-intents store into the canonical two-namespace shape.
    /// Returns empty namespaces on any error (never throws).
    function _readPendingOffline() {
        var empty = { "route-policy": {}, "stability": {}, "binding": {} }
        var raw = String((prefs && prefs.routePendingOfflineJson) || "")
        if (raw === "") return empty
        try {
            var o = JSON.parse(raw)
            if (!o || typeof o !== "object") return empty
            return {
                "route-policy": (o["route-policy"] && typeof o["route-policy"] === "object")
                    ? o["route-policy"] : {},
                "stability": (o["stability"] && typeof o["stability"] === "object")
                    ? o["stability"] : {},
                "binding": (o["binding"] && typeof o["binding"] === "object")
                    ? o["binding"] : {}
            }
        } catch (e) {
            return empty
        }
    }

    /// Park "the user chose their connections while the service was down".
    /// The choice itself already lives in prefs; what is parked is the fact
    /// that the service has not seen it yet, plus which slots were explicitly
    /// vacated (a blank pref alone never unbinds).
    function recordOfflineBindingIntent(pushOpts) {
        var o = pushOpts || {}
        var obj = _readPendingOffline()
        var b = obj["binding"] || {}
        b.pending = true
        if (o.unbindPrimary === true) b.unbindPrimary = true
        if (o.unbindSecondary === true) b.unbindSecondary = true
        obj["binding"] = b
        _writePendingOffline(obj)
    }

    /// Number of parked keys across both namespaces.

    /// Persist the parked-intents store (compact JSON; "" when empty) through
    /// the same prefs mechanism every applier uses (in-place mutate + emitPrefs).
    function _writePendingOffline(obj) {
        // Stamped on every write: the park expires on the same seven-day
        // window as the rules park, and prefs is read back long after the
        // session that wrote it.
        if (obj && Pure.pendingOfflineCount(obj) > 0) obj["parked-at-ms"] = Date.now()
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
        // No stability intent yet: it is recorded when the pending-changes
        // apply is confirmed by the service, like every other write.
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

    /// The lock as it applies to this window: the service lets an elevated
    /// administrator through it, so an elevated window is not locked.
    readonly property bool ruleEditsLocked: allowUserRuleEdits === false && !_windowElevated

    readonly property bool _windowElevated: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null && typeof nrrNativeBridge.isElevated === "function"
        && !!nrrNativeBridge.isElevated()

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
        var corr = (serviceStabilitySupported && bridgeAvailable && bridge !== null
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
        if (ruleEditsLocked) {
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
    /// Emitted after a hole in the push stream (a quick service restart the
    /// health poll never saw): the panels re-read what the pushes would have told.
    signal pushGapReread()

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
        // Only keys this OS's service applies are sent, and a patch with none
        // is refused before anything is queued: a decision for a config this
        // OS never reads would be replayed on every connect edge forever.
        var applicable = stabilityPatchForPlatform(partial)
        if (Object.keys(applicable).length === 0 && Object.keys(partial || {}).length > 0) {
            if (typeof onDone === "function") onDone(false, "unsupported-platform", null)
            return
        }
        partial = applicable
        var originText = String(origin || "")
        _stabilityPatchQueue.push({ partial: partial, onDone: onDone, origin: originText })
        _drainStabilityPatchQueue()
    }

    function _drainStabilityPatchQueue() {
        if (_stabilityPatchInFlight || _stabilityPatchQueue.length === 0) return
        var job = _stabilityPatchQueue.shift()
        var finish = function(ok, code, payload) {
            _stabilityPatchInFlight = false
            // A throwing caller must not stop the queue behind it.
            try {
                if (typeof job.onDone === "function") job.onDone(ok, code, payload)
            } catch (e) {
                console.log("stability patch callback failed:", e)
            }
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
            // Whatever happens between here and the Set, the job has to end:
            // an in-flight slot nobody releases stops every later patch from
            // every panel, and the only symptom is silence.
            try {
                // A Set that changes nothing still raises the administrator
                // prompt, and a decline would then report a change that never was.
                if (Pure.stabilityPatchChangesNothing(payload || {}, job.partial || {})) {
                    finish(true, "", payload)
                    return
                }
                // The merge base is the live row and the user's parked changes.
                // Nothing comes from the user's own file: these settings are the
                // machine's, and only the service's backup brings them back.
                var merged = Pure.mergeStabilityWrite(payload || {}, {},
                                                      window._readPendingOffline()["stability"] || {},
                                                      job.partial || {})
                var setCorr = bridge.rpcServiceStabilityConfigSet(merged, job.origin || "")
                rpcTransport.registerRpcCallback(setCorr, function(ok2, p2, code2, msg2) {
                    finish(!!ok2, String(code2 || ""), p2)
                })
            } catch (e) {
                console.log("_drainStabilityPatchQueue: building the write failed:", e)
                finish(false, "gui-internal", null)
            }
        })
    }

    /// Adopt the verbose-logging state out of a service-stability payload.
    function adoptVerboseLogging(payload) {
        var p = payload || {}
        var mode = Pure.stabilityEffective(p, "verbose-logging-mode")
        window.serviceVerboseLoggingMode = mode
        window.serviceVerboseLoggingUntilMs = (mode === "timed")
            ? Number(p["verbose-logging-until-ms"] || 0) : 0
    }

    /// Adopt the connection-trace log window out of a service-stability payload.
    function adoptConnTraceLog(payload) {
        var p = payload || {}
        var mode = Pure.stabilityEffective(p, "conn-trace-ndjson-mode")
        window.serviceConnTraceLogMode = mode
        window.serviceConnTraceLogUntilMs = (mode === "timed")
            ? Number(p["conn-trace-ndjson-until-ms"] || 0) : 0
        window.serviceConnTraceLogForced = Pure.stabilityEffective(p, "conn-trace-ndjson-forced")
        window.serviceConnTraceLogForcedBy = String(Pure.stabilityEffective(p, "conn-trace-ndjson-forced-by") || "")
    }

    // Verbose service logging: `change` is one of `Pure.LOG_WINDOW_CHANGES`.
    // Applied live and admin-gated like every stability write; the service owns
    // the window and ends it itself, so what is shown is what it reports back.
    // A stopped service gets the request parked and delivered on connect.
    function applyVerboseLogging(change, origin) {
        if (!window._routingBackendConnected()) {
            window._recordOfflineRoutingIntent("stability", "verbose-logging-change", change)
            return
        }
        window.applyServiceStabilityPatch({ "verbose-logging-change": change },
            function(ok, code, payload) {
                if (!ok) {
                    window.statusLine = window.tr("status.verbose-logging-failed",
                        "Could not update verbose service logging: ")
                        + ((typeof window.ipcErrorLabel === "function")
                            ? window.ipcErrorLabel(String(code || "unknown"))
                            : String(code || "unknown"))
                    return
                }
                window.adoptVerboseLogging(payload)
                window.statusLine = (change !== "off")
                    ? window.tr("status.verbose-logging-enabled",
                        "Verbose service logging enabled — applies immediately")
                    : window.tr("status.verbose-logging-disabled",
                        "Verbose service logging disabled — applies immediately")
            }, String(origin || "user:verbose-logging"))
    }

    // Verbose-logging wording shared by the Settings panel and the Logs tab
    // banner, so both read one formatter instead of keeping two in sync.
    function verboseLoggingChangeLabel(change) {
        switch (String(change)) {
            case "one-hour":
                return window.tr("settings.diagnostics.service-stability.verbose.option-one-hour",
                    "Verbose for 1 hour")
            case "four-hours":
                return window.tr("settings.diagnostics.service-stability.verbose.option-four-hours",
                    "Verbose for 4 hours")
            case "until-restart":
                return window.tr("settings.diagnostics.service-stability.verbose.option-until-restart",
                    "Verbose until the service restarts")
        }
        return window.tr("settings.diagnostics.service-stability.verbose.option-off", "Normal")
    }

    // Writing the connection trace to the service log: the same kind of window
    // as verbose logging, applied the same way.
    function applyConnTraceLog(change, origin) {
        if (!window._routingBackendConnected()) {
            window._recordOfflineRoutingIntent("stability", "conn-trace-ndjson-change", change)
            return
        }
        window.applyServiceStabilityPatch({ "conn-trace-ndjson-change": change },
            function(ok, code, payload) {
                if (!ok) {
                    window.statusLine = window.tr("status.conn-trace-log-failed",
                        "Could not update writing the connection trace to the log: ")
                        + ((typeof window.ipcErrorLabel === "function")
                            ? window.ipcErrorLabel(String(code || "unknown"))
                            : String(code || "unknown"))
                    return
                }
                window.adoptConnTraceLog(payload)
                window.statusLine = (change !== "off")
                    ? window.tr("status.conn-trace-log-enabled",
                        "Connection trace is written to the log — applies immediately")
                    : window.tr("status.conn-trace-log-disabled",
                        "Connection trace is no longer written to the log — applies immediately")
            }, String(origin || "user:conn-trace-log"))
    }

    function connTraceLogChangeLabel(change) {
        switch (String(change)) {
            case "one-hour":
                return window.tr("settings.diagnostics.conn-trace.ndjson.option-one-hour",
                    "Write for 1 hour")
            case "four-hours":
                return window.tr("settings.diagnostics.conn-trace.ndjson.option-four-hours",
                    "Write for 4 hours")
            case "until-restart":
                return window.tr("settings.diagnostics.conn-trace.ndjson.option-until-restart",
                    "Write until the service restarts")
        }
        return window.tr("settings.diagnostics.conn-trace.ndjson.option-off", "Off")
    }

    function _connTraceLogParkedChange() {
        var parked = window._readPendingOffline()["stability"] || {}
        return parked.hasOwnProperty("conn-trace-ndjson-change")
            ? String(parked["conn-trace-ndjson-change"]) : ""
    }

    /// What the closed box reads: a forced trace first, then a request parked
    /// while the service was offline, else the running window as of `nowMs`.
    function connTraceLogStateText(nowMs) {
        if (window.serviceConnTraceLogForced)
            return window.tr("settings.diagnostics.conn-trace.ndjson.state-forced",
                "Always on (forced)")
        var parkedChange = window._connTraceLogParkedChange()
        if (parkedChange !== "") return window.connTraceLogChangeLabel(parkedChange)
        var mode = window.serviceConnTraceLogMode
        if (mode === "until-restart") return window.connTraceLogChangeLabel("until-restart")
        if (mode !== "timed") return window.connTraceLogChangeLabel("off")
        return window.tr("settings.diagnostics.conn-trace.ndjson.state-timed",
            "Writing: {time} left, until {clock}")
            .replace("{time}", window.logWindowTimeLeftText(window.serviceConnTraceLogUntilMs, nowMs))
            .replace("{clock}", Qt.formatTime(new Date(window.serviceConnTraceLogUntilMs), "HH:mm"))
    }

    /// Time left in a log window, shared by every window's state line.
    function logWindowTimeLeftText(untilMs, nowMs) {
        var left = Pure.remainingHoursMinutes(untilMs, nowMs)
        return (left.hours > 0)
            ? window.tr("label.time-left.hours-minutes", "{hours} h {minutes} min")
                .replace("{hours}", left.hours).replace("{minutes}", left.minutes)
            : window.tr("label.time-left.minutes", "{minutes} min")
                .replace("{minutes}", left.minutes)
    }

    /// A request parked while the service was offline, else "".
    function _verboseLoggingParkedChange() {
        var parked = window._readPendingOffline()["stability"] || {}
        return parked.hasOwnProperty("verbose-logging-change")
            ? String(parked["verbose-logging-change"]) : ""
    }

    /// Whether the Logs tab banner has anything to say: a parked non-off
    /// request, or a window the service is actually running.
    function verboseLoggingIsActive() {
        var parkedChange = window._verboseLoggingParkedChange()
        if (parkedChange !== "") return parkedChange !== "off"
        var mode = window.serviceVerboseLoggingMode
        return mode === "timed" || mode === "until-restart"
    }

    /// What the closed box / Logs banner reads: a request parked while the
    /// service was offline outranks what it last reported, else the running
    /// window with the time left as of `nowMs`.
    function verboseLoggingStateText(nowMs) {
        var parkedChange = window._verboseLoggingParkedChange()
        if (parkedChange !== "") return window.verboseLoggingChangeLabel(parkedChange)
        var mode = window.serviceVerboseLoggingMode
        if (mode === "until-restart") return window.verboseLoggingChangeLabel("until-restart")
        if (mode !== "timed") return window.verboseLoggingChangeLabel("off")
        return window.tr("settings.diagnostics.service-stability.verbose.state-timed",
            "Verbose: {time} left, until {clock}")
            .replace("{time}", window.logWindowTimeLeftText(window.serviceVerboseLoggingUntilMs, nowMs))
            .replace("{clock}", Qt.formatTime(new Date(window.serviceVerboseLoggingUntilMs), "HH:mm"))
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
        // guard. A focused setting opens its own category instead.
        var focused = request.focus ? focusSetting(request.focus, request.focusContext) : false
        if (request.section && !focused) requestSectionChange(String(request.section))
        if (request.openAbout) openChildWindow(aboutWindow)
        if (request.openLicense) openChildWindow(licenseWindow)
        window.show()
        window.raise()
        window.requestActivate()
        // A second launch of a different build never starts; it names both
        // builds here so the raised window is not mistaken for the new one.
        var mismatch = request.buildMismatch
        if (mismatch && typeof mismatch === "object") {
            showNotice(
                tr("dialog.build-mismatch.title", "Another build is already running"),
                tr("dialog.build-mismatch.body",
                    "NetRuleRouter is already open and it is a different build: {running}. The one you just started is {ours}. Close the open NetRuleRouter window (quit it from the tray icon too), then start the application again.")
                    .replace("{running}", String(mismatch.runningVersion || "?")
                        + " (" + String(mismatch.runningFingerprint || "?") + ")")
                    .replace("{ours}", String(mismatch.ourVersion || "?")
                        + " (" + String(mismatch.ourFingerprint || "?") + ")"))
        }
        // A tray hand-off can carry an `action` slug beyond the section
        // switch; an older launcher omits it and the dispatch is a no-op.
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
            // Loading the files REPLACES what is on screen. An edit the user
            // has open here would go with it, and a tray button two rooms away
            // is the worst place to lose one — so this path stops at the
            // question instead of answering it for them.
            if (rulesGuardDirty()) {
                statusLine = tr("status.rules-drift-apply-has-local-edits",
                    "Your app has rule changes that are not saved yet, so the files were not loaded over them. Save or discard them here first.")
                return
            }
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
        } else if (actionSlug === "rules-drift-compare") {
            // "Open and compare" on the same notice. The tray knows only that
            // two hashes differ; the comparison itself lives here, so re-measure
            // all three legs first and then open the view that fits what the
            // divergence turns out to be. Opening the section alone left the
            // user in front of a rules table that says nothing about it.
            requestSectionChange("rules")
            statusLine = tr("status.rules-drift-compare-requested",
                "Comparing the rules in your files with the ones being applied…")
            // A cold launch reaches here while the table is still being filled
            // from the service; measuring the app leg mid-hydrate would report a
            // difference that stops existing a moment later.
            _driftCompareHandoffTimer.restart()
        } else if (actionSlug === "add-rule") {
            // "Add rule…" in the tray menu: the form the Add button opens. A
            // form already open is the user's work in progress and stays.
            requestSectionChange("rules")
            if (ruleEditsLocked) {
                statusLine = tr("errors.rules-locked",
                    "Your administrator manages the routing rules on this computer, so they cannot be changed here.")
                return
            }
            if (ruleDialog.visible) return
            editingRule = -1
            ruleDialog.resetForEdit()
            ruleDialog.open()
            // Taken before the rule lands: edits already in the table decide
            // whether saving it may apply straight away.
            _trayAddRule = { hadEdits: rulesGuardDirty() }
        } else if (actionSlug !== "") {
            console.log("applyGuiActivationRequest: unknown action slug",
                        actionSlug)
        }
    }

    /// Set while the rule form was opened by the tray's "Add rule…" and not yet
    /// saved or abandoned: `{ hadEdits }`.
    property var _trayAddRule: null
    // Closed without a save (a click outside, say): the next form the user
    // opens is their own. Deferred past the accept that may still be saving,
    // and kept while the form is back up or the duplicate question is.
    function _dropTrayAddRuleIfAbandoned() {
        Qt.callLater(function() {
            if (!ruleDialog.visible && !ruleDuplicateDialog.visible) window._trayAddRule = null
        })
    }
    Connections {
        target: ruleDialog
        function onRejected() { window._trayAddRule = null }
        function onClosed() { window._dropTrayAddRuleIfAbandoned() }
    }
    Connections {
        target: ruleDuplicateDialog
        function onClosed() { window._dropTrayAddRuleIfAbandoned() }
    }
    /// The tray-opened form was saved into the table: apply it at once, or,
    /// when the table already held edits, leave it to be applied with them.
    function _finishTrayAddRule() {
        var request = _trayAddRule
        _trayAddRule = null
        if (!request || editingRule >= 0) return
        if (request.hadEdits) {
            statusLine = tr("status.tray-add-rule-apply-with-edits",
                "The rule is in the list. Apply it together with your other unsaved rule changes.")
            return
        }
        if (typeof reviewFlowController.applyWithoutReview !== "function") return
        // One rule added and nothing else: a preview saying more means the
        // table is not what the service holds.
        reviewFlowController.applyWithoutReview("tray-add-rule", function(ok) {
            if (!ok) console.log("tray add-rule: apply without review did not complete")
        }, { added: 1, removed: 0, changed: 0 })
    }

    // Real two-phase safe-disable. Phase 1
    // dry-run requests a review summary + confirmation token from
    // the service. Phase 2 confirm consumes the token and executes
    // `safe_disable`. Toast stack tracks the visible progress (red
    // on failure, green on success). The synthetic correlation id
    // ties the visible toast to the RPC chain so we can settle it
    // from either phase's callback.
    function _handleSafeDisableConfirmed(reason, term) {
        var termSlug = String(term || "until-restart")
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
            // No bridge (preview): the toast says the rules stay on.
            if (operationToastStack && operationToastStack.model) {
                operationToastStack.model.settle(corr, "failed",
                    "safe-disable-rpc-pending")
            }
            console.log("safe-disable: bridge unavailable")
            return
        }
        // dry-run.
        var dryRunCorr = nrrNativeBridge.rpcProductImpactDisable(
            reason, true /* dryRun */, "" /* token */, termSlug)
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
                reason, false /* dryRun */, token, termSlug)
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
    /// Switch one rule off by id. Returns false when the id is not in the
    /// table — the review summary names ids the service saw, and a stale one
    /// must not silently disable the wrong row.
    function _disableRuleById(ruleId) {
        var wanted = String(ruleId || "")
        if (wanted === "") return false
        for (var i = 0; i < rulesModel.count; i += 1) {
            var row = rulesModel.get(i)
            if (!row || String(row.id || "") !== wanted) continue
            if (row.enabled === false) return false
            rulesModel.setProperty(i, "enabled", false)
            rulesModelEdited()
            _recomputeRulesDirty()
            return true
        }
        return false
    }

    /// Re-file the rule at `masterIndex` under the type its value is: the
    /// "Move to" offer of a row refused where it stands, run only on the
    /// user's click. The row is judged again under the new type, where its
    /// value can still be wrong. `false` when the row has no such offer.
    function moveRuleToType(masterIndex, quiet) {
        if (masterIndex < 0 || masterIndex >= rulesModel.count) return false
        var row = rulesModel.get(masterIndex)
        if (!row || String(row.validationStatus || "") !== "error") return false
        var type = Rules.misplacedTargetType(row.validationMessageKey)
        if (type === "") return false
        var id = String(row.id || "")
        var value = String(row.matchValue || "")
        rulesModel.set(masterIndex, {
            ruleType: type,
            ruleTypeTitle: ruleTypeLabel(type),
            aceMatchValue: ruleEditSupport.aceLowerForSearch(value),
            verify: Rules.rowIsVerify({ ruleType: type, targetRoute: row.targetRoute,
                verify: row.verify, matchValue: value }),
            validationStatus: "valid",
            validationMessageKey: "",
            validationMessageArgs: ({})
        })
        _refreshRowVerdict(masterIndex, id, type, value)
        if (quiet !== true) {
            rulesModelEdited()
            _recomputeRulesDirty()
            statusLine = tr("rules.move-to-type.done", "Rule moved to “{type}”.")
                .replace("{type}", ruleTypeLabel(type))
        }
        return true
    }
    /// Every row the "Move to" offer stands on, moved at once: the "Move all"
    /// of the rules list, run only on the user's click.
    function moveMisplacedRules() {
        var moved = 0
        for (var i = 0; i < rulesModel.count; i += 1) {
            if (moveRuleToType(i, true)) moved += 1
        }
        if (moved === 0) return 0
        rulesModelEdited()
        _recomputeRulesDirty()
        statusLine = Plurals.counted(tr, "rules.move-to-type.done-many.", moved,
            "{count} rule moved to the type its value is.",
            "{count} rules moved to the type their value is.")
        return moved
    }
    /// A row moved to another route is judged again: a deny or the additional
    /// route may not name a program the system needs, the main route may. Only
    /// a program's verdict depends on the route.
    function rejudgeRowRoute(masterIndex) {
        if (masterIndex < 0 || masterIndex >= rulesModel.count) return
        var row = rulesModel.get(masterIndex)
        if (!row || Rules.canonicalRuleTypeSlug(row.ruleType) !== "application") return
        _refreshRowVerdict(masterIndex, String(row.id || ""), String(row.ruleType),
            String(row.matchValue))
    }
    /// The launcher's verdict on one row's value, written back while that row
    /// still holds the same rule, type and value.
    function _refreshRowVerdict(masterIndex, ruleId, ruleType, value) {
        if (!rpc || !rpc.bridgeAvailable
                || typeof rpc.bridge.rpcRuleValueVerdict !== "function") {
            return
        }
        // The row's route: a deny or the additional route on a system program
        // is refused, the main route is not.
        var current = masterIndex < rulesModel.count ? rulesModel.get(masterIndex) : null
        var route = current ? String(current.targetRoute || "") : ""
        var corr = rpc.bridge.rpcRuleValueVerdict(ruleType, value, route)
        rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("local.rule-value-verdict failed:", code, msg)
                return
            }
            if (masterIndex >= rulesModel.count) return
            var row = rulesModel.get(masterIndex)
            if (!row || String(row.id || "") !== ruleId || String(row.ruleType) !== ruleType
                    || String(row.matchValue) !== value) {
                return
            }
            rulesModel.set(masterIndex, {
                validationStatus: String((payload && payload.status) || "valid"),
                validationMessageKey: String((payload && payload["message-key"]) || ""),
                validationMessageArgs: (payload && payload.args) ? payload.args : ({})
            })
            rulesModelEdited()
        })
    }

    function nextFreeRuleId() {
        return Rules.nextFreeRuleId(rulesModel, freeRulesMaxCount)
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
        // The form edits a rule, not a row: find it again, as the list may
        // have been re-read since the form opened.
        if (editingRule >= 0 && editingRuleKey !== "") {
            var at = -1
            for (var ri = 0; ri < rulesModel.count && at < 0; ri += 1) {
                if (Rules.mergeKey(rulesModel.get(ri)) === editingRuleKey) at = ri
            }
            if (at < 0) {
                statusLine = tr("status.rule-edit-target-gone",
                    "The rule you were editing was changed elsewhere, so this edit was not saved.")
                return
            }
            if (selectedRule === editingRule) selectedRule = at
            editingRule = at
        }
        if (editingRule < 0 && userRuleCount() >= freeRulesMaxCount) {
            statusLine = tr("status.rules-limit-reached",
                "Up to {max} active rules are supported.")
                .replace("{max}", String(freeRulesMaxCount))
            return
        }
        // Editing an app-authored rule makes it the user's own, which also
        // takes it out of the app-authored budget that evicts the oldest.
        var item = ruleEditSupport.ruleRowFromDialog(ruleDialog,
            editingRule >= 0 ? rulesModel.get(editingRule).id : nextFreeRuleId())
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
        if (editingRule >= 0)
            _refreshRowVerdict(editingRule, String(item.id), String(item.ruleType),
                String(item.matchValue))
        // The edit may change the rule's key; the selection and the form
        // stay on it.
        if (editingRule >= 0 && editingRule === selectedRule) selectedRuleKey = Rules.mergeKey(item)
        if (editingRule >= 0) editingRuleKey = Rules.mergeKey(item)
        ruleOverlapsController.noteOwnEdit(item.id)
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
        if (_trayAddRule) _finishTrayAddRule()
    }

    /// How many more rules the list takes; the bulk form marks the rest.
    function bulkRuleRoom() {
        return Math.max(0, freeRulesMaxCount - userRuleCount())
    }
    /// What a pasted list of rules settles (`Rules.planBulkRules`): its new
    /// rules added and the rules it moves to their new route, all in one edit of
    /// the list, so one apply sends them as a single revision. Lines that were
    /// not taken go back into the form.
    function saveBulkRules(plan) {
        var rows = (plan && plan.rows) || []
        var added = 0
        var moved = 0
        var capped = false
        var userCount = userRuleCount()
        // One pass over the list, not one per pasted line: a thousand lines
        // against a full list would otherwise read it a thousand times.
        var keys = {}
        var byValue = {}
        for (var k = 0; k < rulesModel.count; k += 1) {
            var have = rulesModel.get(k)
            keys[Rules.mergeKey(have)] = true
            var same = Rules.canonicalRuleTypeSlug(have.ruleType) + "|"
                + String(have.matchValue || "").toLowerCase()
            if (!byValue[same]) byValue[same] = []
            byValue[same].push(k)
        }
        var nextId = parseInt(nextFreeRuleId().substring(2), 10)
        for (var i = 0; i < rows.length; i += 1) {
            var row = rows[i]
            var form = { ruleType: row.type, value: row.value, route: row.route,
                verify: row.verify, comment: row.comment, enabled: row.enabled }
            if (row.action === "add") {
                var item = ruleEditSupport.ruleRowFromForm(form,
                    Rules.sequentialRuleId(Math.min(nextId, freeRulesMaxCount) - 1))
                // A line of an `--- Auto` section stays app-authored, as an
                // import keeps it, and outside the user's allowance.
                var authored = String(row.originReason || "") !== ""
                item.originReason = String(row.originReason || "")
                item.originAnchor = String(row.originAnchor || "")
                item.originAdded = String(row.originAdded || "")
                if (keys[Rules.mergeKey(item)]) continue
                if (!authored && userCount >= freeRulesMaxCount) {
                    capped = true
                    continue
                }
                keys[Rules.mergeKey(item)] = true
                if (!authored) userCount += 1
                nextId += 1
                rulesModel.append(item)
                // A new rule has no stored comment to clear.
                if (item.comment !== "") _sidecarWriteCommentForRow(item)
                added += 1
            } else if (row.action === "move" && _moveRuleToRoute(row, byValue)) {
                moved += 1
            }
        }
        if (added + moved > 0) rulesModelEdited()
        var status = tr("status.rules-list-added", "Rules added: {count}.")
            .replace("{count}", String(added))
        if (moved > 0) {
            status += " " + tr("status.rules-list-moved", "Moved to the chosen route: {count}.")
                .replace("{count}", String(moved))
        }
        if (capped) {
            status += " " + tr("status.rules-limit-reached",
                "Up to {max} active rules are supported.")
                .replace("{max}", String(freeRulesMaxCount))
        }
        if (plan && plan.keep > 0) {
            status += " " + tr("status.rules-list-left", "Left in the form to fix: {count}.")
                .replace("{count}", String(plan.keep))
        }
        statusLine = status
        _recomputeRulesDirty()
        if (_trayAddRule) {
            if (added + moved > 0) _finishTrayAddRule()
            else _trayAddRule = null
        }
        if (plan && String(plan.remaining || "") !== "") {
            ruleDialog.resumeBulk(plan.remaining)
            ruleDialog.open()
        }
        return added + moved
    }
    /// The rule a bulk row found on another route, moved to the row's route
    /// (`byValue`: list indices by folded type and value). Its comment is stored
    /// by route, so it is written again under the new one.
    function _moveRuleToRoute(row, byValue) {
        var at = byValue[Rules.canonicalRuleTypeSlug(row.type) + "|"
            + String(row.value).toLowerCase()] || []
        for (var j = 0; j < at.length; j += 1) {
            var r = rulesModel.get(at[j])
            if (String(r.targetRoute) === row.route) continue
            var verify = Rules.rowIsVerify({ ruleType: r.ruleType, targetRoute: row.route,
                verify: r.verify, matchValue: r.matchValue })
            rulesModel.set(at[j], { targetRoute: row.route, verify: verify })
            rejudgeRowRoute(at[j])
            var after = rulesModel.get(at[j])
            if (String(after.comment || "") !== "") _sidecarWriteCommentForRow(after)
            return true
        }
        return false
    }

    /// Add rules drafted outside the rule dialog, each `{ "rule-type", value,
    /// route, comment, enabled?, verify? }`, into the list on screen; they
    /// reach the service through the usual review and apply. A rule already
    /// in the list is skipped, not reported as an error. Returns how many were
    /// added.
    function addRuleDrafts(drafts) {
        var list = drafts || []
        var added = 0
        var already = 0
        var capped = false
        var keys = {}
        for (var k = 0; k < rulesModel.count; k += 1) keys[Rules.mergeKey(rulesModel.get(k))] = true
        var userCount = userRuleCount()
        for (var i = 0; i < list.length; i += 1) {
            var d = list[i] || {}
            var ruleType = String(d["rule-type"] || "")
            var value = String(d.value || "")
            var route = String(d.route || "")
            if (ruleType === "" || value === "" || (route !== "primary" && route !== "secondary")) continue
            var item = {
                id: nextFreeRuleId(),
                enabled: d.enabled !== false,
                ruleType: ruleType,
                ruleTypeTitle: ruleTypeLabel(ruleType),
                matchValue: value,
                aceMatchValue: _aceLowerForSearch(value),
                targetRoute: route,
                verify: d.verify === true,
                comment: String(d.comment || ""),
                originReason: "",
                originAnchor: "",
                originAdded: ""
            }
            var key = Rules.mergeKey(item)
            if (keys[key]) { already += 1; continue }
            if (userCount >= freeRulesMaxCount) { capped = true; break }
            keys[key] = true
            userCount += 1
            rulesModel.append(item)
            // A new rule has no stored comment to clear.
            if (item.comment !== "") _sidecarWriteCommentForRow(item)
            added += 1
        }
        if (added > 0) rulesModelEdited()
        var status = tr("status.rules-list-added", "Rules added: {count}.")
            .replace("{count}", String(added))
        if (already > 0) {
            status += " " + tr("status.rules-list-already-present",
                "Already in the list: {count}.").replace("{count}", String(already))
        }
        if (capped) {
            status += " " + tr("status.rules-limit-reached",
                "Up to {max} active rules are supported.")
                .replace("{max}", String(freeRulesMaxCount))
        }
        statusLine = status
        _recomputeRulesDirty()
        return added
    }

    function resetDefaults() {
        updatePrefs({
            launchWindowOnStartup: true,
            minimizeToTrayInsteadOfClose: true,
            showNotifications: true,
            notifySuggestionChanges: true,
            notifyBlockNotices: true,
            notifyRuleDuplicates: true,
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
            showVirtualMachinesSection: false,
            appGroupsOfferDismissed: false,
            showRememberedAdapters: true,
            autoConfirmAdapterIdChange: true,
            // Show the block-all warning banner (default on).
            warnKillSwitchBlockAll: true,
            // Tray notification opacity. Left out, "restore defaults" kept a
            // value the user had tuned — a reset that skips a key is a reset
            // the user cannot trust.
            trayNoticeOpacityPercent: 100,
            updateCheckEnabled: true,
            updateCheckIntervalDays: 14,
            // Parked work and the service-owned mirrors go with the settings
            // they belong to. Left behind, an offline intent recorded against
            // the OLD values replays on the next connect and quietly undoes
            // the reset the user just asked for.
            routePendingOfflineJson: "",
            serviceBackedMirrorJson: "",
            serviceIntentJson: ""
        })
        statusLine = tr("status.defaults-restored", "Defaults restored")
    }

    // Full reset to post-install state (does
    // NOT uninstall the service; that stays on the app uninstaller / the
    // "Service management" button). Steps: clear service operational logs
    // (audit trail untouched) + sidecar + GUI logs (local/fast), reset all
    // Exit closes the window for real; the close button is what goes to the tray.
    Action { id: exitAction; text: tr("action.exit-application", "Exit"); shortcut: StandardKey.Quit; icon.source: uiIconSource("exit"); onTriggered: { window.exitRequested = true; window.close() } }
    Action { id: aboutAction; text: tr("action.open-about-window", "About"); shortcut: "F1"; icon.source: uiIconSource("about"); onTriggered: openChildWindow(aboutWindow) }
    Action { id: licenseAction; text: tr("action.open-license-window", "Licenses"); shortcut: "Ctrl+Shift+L"; icon.source: uiIconSource("about"); onTriggered: openChildWindow(licenseWindow) }
    // Disabled when the service's log directory is not readable by this user:
    // the context carries a URL only when the folder can actually be listed, and
    // an action that opens an empty window explains nothing. Diagnostics ->
    // export archive is the path that works without administrator rights.
    // The release check exists only in a build that has it (`updateCheckAvailable`).
    readonly property bool updateCheckAvailable: context.updateCheckAvailable === true
    Action { id: checkForUpdatesAction; text: tr("action.check-for-updates", "Check for updates"); shortcut: "Ctrl+U"; enabled: window.updateCheckAvailable; onTriggered: updateCheckController.checkNow() }
    Action { id: logsFolderAction; text: tr("action.open-logs-folder", "Open logs folder"); shortcut: "Ctrl+Shift+O"; icon.source: uiIconSource("open-file"); enabled: String(((context.about || {}).logsFolderUrl) || "") !== ""; onTriggered: openOwnFolder((context.about || {}).logsFolderUrl) }
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
    Shortcut { sequence: checkForUpdatesAction.shortcut; context: Qt.ApplicationShortcut; enabled: window.updateCheckAvailable; onActivated: checkForUpdatesAction.trigger() }
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
    // Running this on every `uiRevision` bump would rebuild the non-client
    // frame on every open window constantly — the counter also bumps on
    // unrelated interactions (row selection, any preference write), which is
    // what makes dark / high-contrast switching feel laggy.
    onWantDarkTitleBarChanged: Qt.callLater(applyAllTitleBars)

    Component.onCompleted: {
        loadContext()
        Qt.callLater(function() { sectionLoadsAsync = true })
        logProgress(tr("progress.gui-started", "NetRuleRouter started."), "info")
        // Register the rules-section
        // save callback at window scope so the UnsavedChangesGuard offers an
        // "Apply" button for unsaved rule edits (drives the review→activate
        // pipeline and resumes navigation on success). Window scope (not the
        // section's onCompleted) keeps it available even when RulesSection is
        // lazily unloaded.
        if (typeof setSaveCallback === "function") {
            setSaveCallback("rules", function(onDone) {
                reviewFlowController._guardApplyRules(onDone, "section-save")
            })
        }
        // Connect to the bridge's RPC
        // response signal exactly once. Each setX/refreshX helper
        // registers a per-correlation-id callback that fires here.
        if (bridgeAvailable && typeof nrrNativeBridge.rpcResponse !== "undefined") {
            nrrNativeBridge.rpcResponse.connect(rpcTransport.handleRpcResponse)
        }
        // Launched connected, yet the snapshot missed the service: no
        // reconnect will come to fill the Diagnostics cards in.
        if (((backendStatus || {}).kind) === "connected"
                && !Pure.diagnosticsSnapshotIsLive(diagnosticsSnapshot))
            refreshDiagnosticsSnapshot()
        // The sidebar offers Virtual machines only when there are some, and
        // needs the answer before the user opens Rules.
        if (prefs.showVirtualMachinesSection === true) virtualMachinesController.refresh()
        probeAppGroupsOffer()

        // The desktop can switch light/dark while the window is open. The
        // context file was written before the window existed, so without this
        // the appearance stays whatever it was at launch until a restart.
        if (bridgeAvailable && typeof nrrNativeBridge.systemAppearanceChanged !== "undefined") {
            nrrNativeBridge.systemAppearanceChanged.connect(refreshSystemAppearance)
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
        // normal startup via `startupController._runPostEulaStartup()`; `declined` quits. When
        // already accepted we run the post-EULA startup immediately.
        if (startupController._eulaNeedsAcceptance()) {
            eulaAgreementWindow.open()
        } else {
            startupController._runPostEulaStartup()
        }
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
            _coldStartRulesFetch()
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
        // A refusal belongs with them: the service is up, but it will not talk
        // to this window, so waiting for it to answer is waiting for nothing.
        var serviceMayAnswer = (kind !== "service-not-installed"
            && kind !== "service-stopped"
            && kind !== "refused")
        if (serviceMayAnswer) {
            if (prefs.autoLoadRulesOnLaunch === false) return
            // Defer the file fallback so we don't diff a stale file against the
            // live revision while the service is still coming up.
            _coldStartAutoOpenFallbackTimer.restart()
            return
        }
        if (prefs.autoLoadRulesOnLaunch !== false) _runAutoOpenOnLaunch()
    }

    /// Pull the service's rules at cold start, and decide from the ANSWER —
    /// never from the model — whether the bound file has to stand in.
    ///
    /// Two outcomes look identical in `rulesModel.count` and are not the same
    /// fact: the service answered "no rules", and nobody asked it. The second
    /// happens on every launch, because the Qt host's IPC client is still
    /// coming up when `Component.onCompleted` runs and `_refreshRulesFromService`
    /// returns `false` without a request. Reading that as "the service holds
    /// nothing" loaded the bound .txt over a live revision and offered to
    /// delete from the service every rule the file lagged behind on.
    /// `_serviceRuleCount` is the authoritative answer (−1 until a fetch lands).
    function _coldStartRulesFetch() {
        _refreshRulesFromService({ silent: true, onComplete: function(ok) {
            if (prefs.autoLoadRulesOnLaunch === false) return
            if (ok) {
                // Answered, and it really holds nothing (fresh install, wiped
                // state DB): the table would sit empty under a selected rule
                // set, so hydrate from the file the way an offline start does.
                if (_serviceRuleCount === 0) _runAutoOpenOnLaunch()
                // A file the tray left alone because it was edited by hand is
                // asked about now.
                else boundFilesController.askAboutHandEditedFiles()
                return
            }
            _coldStartRulesRetryTimer.restart()
        } })
    }

    // Retry chain for the fetch above. Bounded: a bridge that never comes up
    // leaves the table empty, which is honest — the 6 s fallback below owns the
    // genuinely-offline case.
    Timer {
        id: _coldStartRulesRetryTimer
        interval: 1000
        repeat: false
        property int tries: 0
        onTriggered: {
            if (window._serviceRuleCount >= 0 || tries >= 20) return
            tries += 1
            window._coldStartRulesFetch()
        }
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
    /// Only when even that resolves to nothing (no set anywhere to name) does
    /// the file row above the table disappear.
    function rulesSourcePathFor(route) {
        var remembered = _rememberedRulesPathFor(route)
        if (remembered !== "") return remembered
        return ruleSetCatalog.defaultRuleSetPathFor(route)
    }

    /// Steps 1–4 above: a path the user's own actions put on record. Split out
    /// because the "Source:" row needs to tell "a file backs these rules" apart
    /// from "this is what a load would pull in", which step 5 answers.
    ///
    /// Once the user keeps a rule-set folder of their own, a path in the tree
    /// shipped with the app is not one of their actions — it is what the app's
    /// own hydration put on record back when it still bound the files it read.
    /// Returning it names a set the user never chose, and because the
    /// cold-start fallback loads whatever this returns, it eventually puts that
    /// set on screen over theirs.
    function _rememberedRulesPathFor(route) {
        var path = Pure.rememberedRulesPathFor(prefs, route, userPresetsDir)
        if (path !== "" && userPresetsDir !== "" && isFactoryPresetPath(path)) {
            return ""
        }
        return path
    }

    /// Drop such a binding from prefs instead of only ignoring it above, so the
    /// stored state stops disagreeing with what the window shows. Runs once per
    /// launch before hydration; a no-op for everyone whose paths are their own.
    function _forgetStaleFactoryRulesBinding() {
        if (userPresetsDir === "") return
        var patch = {}
        var routes = [["lastLoadedPathPrimary", "lastSavedPathPrimary"],
                      ["lastLoadedPathSecondary", "lastSavedPathSecondary"]]
        for (var i = 0; i < routes.length; i += 1) {
            for (var k = 0; k < routes[i].length; k += 1) {
                var key = routes[i][k]
                if (isFactoryPresetPath(prefs[key])) patch[key] = ""
            }
        }
        if (String(prefs.selectedPresetSet || "").indexOf("bundled:") === 0
                && ruleSetCatalog._ruleSetEnum().userOwned) {
            patch.selectedPresetSet = ""
        }
        var touched = false
        for (var p in patch) { touched = true; break }
        if (!touched) return
        updatePrefs(patch)
        emitPrefs()
    }

    /// Did the user's own load or save put the shown path on record, or is it
    /// merely the set the quick-load points at? The file row stays visible
    /// either way — someone who keeps rule files wants to see WHICH ones at a
    /// glance — so this is what lets it label the two cases apart instead of
    /// claiming rules came from a file nobody opened.
    function rulesSourceIsUserBound() {
        return _rememberedRulesPathFor("primary") !== ""
            || _rememberedRulesPathFor("secondary") !== ""
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
                commitPrefs({ autoOpenOnLaunchPathPrimary: "" })
            }
        }
        var secB64 = ""
        if (secondaryPath !== "") {
            secB64 = String(nrrNativeBridge.readFileBytes(secondaryPath) || "")
            if (secB64 === "") {
                statusLine = tr("status.auto-open-file-missing",
                    "Auto-open file not found at {path}. Choose a file to attach.")
                    .replace("{path}", secondaryPath)
                commitPrefs({ autoOpenOnLaunchPathSecondary: "" })
            }
        }
        if (primB64 === "" && secB64 === "") return
        // Files read successfully — make the quick-load dropdown name the set
        // these rules came from (no-op when the user picked one by hand).
        ruleSetCatalog._rememberHydratedRuleSet()
        statusLine = tr("status.auto-open-loading",
            "Loading rules from {path}...")
            .replace("{path}", primaryPath !== "" ? primaryPath : secondaryPath)
        // Hydration, not an import the user asked for: with the service down
        // this only puts the bound files on screen. Parking it as work to push
        // is what once offered to DELETE from the service every rule the files
        // happened to lag behind on.
        presetImportController.startBothRoutesPresetImportReviewFlow(
            primB64, secB64, primaryPath, secondaryPath, { hydration: true })
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

    // The service's `rules.list` row as a table row. One mapping for every
    // surface (the tray re-sends whole rule books built from it).
    function _serviceRuleRowToModelRow(w) {
        return ruleEditSupport.serviceRowToModelRow(w)
    }

    // Re-pull the active revision's rules
    // from the service and rebind `rulesModel`. This is the "fan back"
    // the preset-import flow assumed (it submits `skipApply: true`
    // expecting the activated revision to come back via push) and it is
    // what makes a non-admin session see exactly what an admin session
    // (or the broker) just activated. `rules.list` is a read op, so it
    // works for non-elevated clients.
    //
    // opts: { silent: bool, ifStale: bool, onComplete: function(ok, reloaded) }
    // `ifStale`: a re-read nobody asked for. It leaves the table alone when it
    // already shows the rules in force, or when edits began while it was out.
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
            if (opts.ifStale) {
                var inForce = (p["base-revision"] !== undefined && p["base-revision"] !== null)
                    ? String(p["base-revision"]) : null
                var shown = (rulesBaseRevision !== null && rulesBaseRevision !== undefined)
                    ? String(rulesBaseRevision) : null
                if ((inForce !== null && inForce === shown)
                        || unsavedChangesRegistry["rules"] || _offlineRulesPendingPush) {
                    if (typeof opts.onComplete === "function") opts.onComplete(true, false)
                    return
                }
            }
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
            var loadedBase = (p["base-revision"] !== undefined && p["base-revision"] !== null)
                ? String(p["base-revision"]) : null
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
                // The next write is built on exactly these rules.
                rulesBaseRevision = loadedBase
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
                // importing a preset that adds application rules). Runs after
                // the chunked append finishes so `snapshot.initial.get` on the
                // main IPC channel does not compete with the health probe/other
                // reads for the duration of the populate.
                refreshUnenforcedAppRules()
                // Same reason: the offer the tray may have shown while this
                // window was closed has to be countable the moment it opens.
                autoRuleSuggestionsController.refreshAutoRuleCandidates()
                verifyVerdicts.refresh()
                // The Overlaps count shows on every screen, not only once the
                // rules screen has been opened.
                refreshRulesOverlaps()
                // An explicit pull replaced the table with what the service
                // enforces, so the linked file is now behind it — mirror it.
                // Silent cold-start/post-connect refreshes deliberately do NOT:
                // rules edited while the service was down still live in that
                // file, and the offline-backlog offer needs them intact.
                if (!opts.silent) boundFilesController._persistBoundFilesAfterApply()
                uiRevision += 1
                if (!opts.silent) {
                    statusLine = Plurals.counted(tr, "status.rules-refreshed-from-service.",
                        rows.length,
                        "Loaded {count} active rule from the service.",
                        "Loaded {count} active rules from the service.")
                }
                if (typeof opts.onComplete === "function") opts.onComplete(true, true)
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
    // Bulk-load suppression: `_appendRowsChunked` yields to the event loop
    // between chunks, so each chunk's `countChanged` gives RulesSection's 0 ms
    // coalescing timer a chance to fire — ceil(N/75) full `rebuildDisplay()`
    // passes instead of one. `scheduleRebuild()` treats this flag as "hold
    // off"; the transition back to false triggers the single rebuild once the
    // model has settled.
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
            var t0 = Date.now()
            var batch = []
            for (; i < end; i += 1) batch.push(mapFn(rows[i]))
            var t1 = Date.now()
            // One append per chunk, not per row: every append emits
            // countChanged, and each notification re-evaluates every binding
            // that reads `count`. Measured on 319 rows with one such binding
            // live — 1922 ms row-by-row against 28 ms in chunks.
            rulesModel.append(batch)
            mapMs += t1 - t0
            appendMs += Date.now() - t1
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
    // The main-route check files its verdicts while it runs; only those marks
    // are taken in, so unsaved edits survive and nothing is asked. `onDone`
    // gets how many hosts the check has yet to answer.
    function refreshMainRouteMarks(onDone) {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcRulesList !== "function") return
        var corr = nrrNativeBridge.rpcRulesList()
        rpcTransport.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) return
            var marks = ({})
            var rows = p.rows || []
            for (var i = 0; i < rows.length; i += 1) {
                var key = String(rows[i]["rule-type"] || "") + "|"
                    + String(rows[i]["match-value"] || "").toLowerCase()
                marks[key] = String(rows[i]["main-route"] || "")
            }
            var changed = false
            for (var j = 0; j < rulesModel.count; j += 1) {
                var entry = rulesModel.get(j)
                // The service may hold the ACE or the decoded spelling of an IDN.
                var typePrefix = String(entry.ruleType || "") + "|"
                var mark = marks[typePrefix + String(entry.matchValue || "").toLowerCase()]
                if (mark === undefined && entry.aceMatchValue)
                    mark = marks[typePrefix + String(entry.aceMatchValue).toLowerCase()]
                if (mark !== undefined && mark !== String(entry.mainRoute || "")) {
                    rulesModel.setProperty(j, "mainRoute", mark)
                    changed = true
                }
            }
            if (changed) rulesModelEdited()
            if (typeof onDone === "function") onDone(Number(p["main-route-pending"] || 0))
        })
    }
    // Persistent main GUI flow: when `minimizeToTrayInsteadOfClose`
    // is enabled, the X button hides the window without exiting the host
    // process. The launcher and Qt host remain alive, so a subsequent tray
    // "Open NetRuleRouter" click reaches the running primary via the
    // `gui-activation.json` handover (polled every 350 ms) and shows the
    // window in milliseconds — vs. ~3–5 s for a cold launcher+QML boot.
    // Full exit: tray "Exit" (shutdown flag), File → Exit, or autoclose.
    onClosing: function(close) {
        emitPrefs()
        // Read once: a prompt the user cancels must leave the close button
        // going to the tray as before.
        var exiting = exitRequested
        exitRequested = false
        // Only the close-paths that actually
        // destroy unsaved editor state need the prompt. The
        // close-to-tray path preserves all in-memory editor state,
        // so it bypasses the guard. `quittingToTray` is set after
        // the user already passed the app-quit prompt (or accepted
        // an autoclose / preferences-driven quit).
        var isDestructive =
            !quittingToTray
            && autoCloseMs === 0
            && (exiting || !prefs.minimizeToTrayInsteadOfClose)
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
        if (quittingToTray || exiting || autoCloseMs > 0 || !prefs.minimizeToTrayInsteadOfClose) {
            close.accepted = true
            // quitOnLastWindowClosed is off so close-to-tray can hide the
            // window; a real close must therefore end the process itself, or it
            // lives on windowless while still holding the single-instance lock,
            // and every later tray click hands activation to a GUI that cannot
            // show anything.
            Qt.quit()
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
            Qt.quit()
            return
        }
        close.accepted = false
        window.hide()
    }

    Timer { interval: autoCloseMs; running: autoCloseMs > 0; repeat: false; onTriggered: window.close() }
    // Closed to the tray, the hidden window keeps the whole interface in memory
    // for a reopen that takes about half a second cold. After a while hidden,
    // with nothing of the user's unsaved or mid-apply, the process ends and the
    // tray carries on alone.
    Timer {
        interval: 5 * 60 * 1000
        running: !window.visible && !window.quittingToTray
        repeat: true
        onTriggered: {
            if (window.hasAnyUnsavedChanges() || window._guardRulesInFlight
                    || rpcTransport.longCallInFlight
                    || window._trayAddRule) return
            console.log("Main: hidden in the tray for a while, ending the window process")
            window.windDownApplication()
        }
    }
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
    /// windows alike. The first probe waits out the launcher's preference-write
    /// debounce (500 ms) so the new process reads the language the user just
    /// picked; the new tray starts only once the old one is gone, or after the
    /// wait budget, because a tray that starts while the old one still holds
    /// the single-instance lock exits as a duplicate.
    function restartTrayForLanguageChange() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.requestTrayShutdown !== "function") {
            return
        }
        nrrNativeBridge.requestTrayShutdown()
        trayGoneProbe.waitedMs = 0
        trayGoneProbe.restart()
        console.log("Main: restarting tray to pick up the new language")
    }

    Timer {
        id: trayGoneProbe
        property int waitedMs: 0
        interval: 500
        repeat: true
        onTriggered: {
            waitedMs += interval
            var stillThere = typeof nrrNativeBridge.isTrayProcessAlive === "function"
                && nrrNativeBridge.isTrayProcessAlive()
            if (stillThere && waitedMs < 10000) return
            stop()
            trayRestartTimer.interval = 1
            trayRestartTimer.restart()
        }
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
                Pure.menuActionText(tr("action.load-rule-list", "Load rules list..."), "Ctrl+O"),
                Pure.menuActionText(tr("action.export-current-rule-list", "Export current list..."), "Ctrl+Shift+S"),
                Pure.menuActionText(tr("action.export-settings", "Export settings..."), "Ctrl+Alt+S"),
                Pure.menuActionText(exitAction.text, "Ctrl+Q")
            ])
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.load-rule-list", "Load rules list..."); shortcutText: "Ctrl+O"; enabled: !window.ruleEditsLocked; onTriggered: openLoadRuleListWindow() }
            // Show WHAT is being exported, then ask where to put it.
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
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.safe-rollback", "Safe rollback"); shortcutText: "Ctrl+Shift+R"; onTriggered: boundFilesController.openSafeRollback() }
            ShortcutMenuItem { theme: uiTheme; labelText: tr("action.temporary-disable-product-impact", "Temporarily disable product impact"); shortcutText: "Ctrl+Shift+P"; onTriggered: setRoutingPauseEnabled(!routingState.routingPaused, "") }
        }
        Menu {
            title: Pure.menuTitleText(tr("menu.help", "Help"), "H")
            popupType: Popup.Item
            implicitWidth: menuPopupWidth([
                Pure.menuActionText(aboutAction.text, "F1"),
                Pure.menuActionText(licenseAction.text, "Ctrl+Shift+L"),
                Pure.menuActionText(logsFolderAction.text, "Ctrl+Shift+O")
            ].concat(window.updateCheckAvailable
                ? [Pure.menuActionText(tr("action.check-for-updates", "Check for updates"), "Ctrl+U")]
                : []))
            ShortcutMenuItem { theme: uiTheme; labelText: aboutAction.text; shortcutText: "F1"; onTriggered: aboutAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: licenseAction.text; shortcutText: "Ctrl+Shift+L"; onTriggered: licenseAction.trigger() }
            ShortcutMenuItem { theme: uiTheme; labelText: logsFolderAction.text; shortcutText: "Ctrl+Shift+O"; onTriggered: logsFolderAction.trigger() }
            // A hidden menu row still takes its height unless told otherwise.
            ShortcutMenuItem { theme: uiTheme; labelText: checkForUpdatesAction.text; shortcutText: "Ctrl+U"; visible: window.updateCheckAvailable; height: visible ? implicitHeight : 0; onTriggered: checkForUpdatesAction.trigger() }
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
                border.width: activeFocus ? uiTheme.focusBorderWidth : uiTheme.borderWidth
                border.color: activeFocus ? uiTheme.stateFocusedBorder : uiTheme.stateDefaultBorder
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
                function toggle() {
                    if (startupLogPopup.visible) startupLogPopup.close()
                    else startupLogPopup.open()
                }
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: progressPill.toggle()
                }
                activeFocusOnTab: visible
                Keys.onSpacePressed: progressPill.toggle()
                Keys.onReturnPressed: progressPill.toggle()
                Keys.onEnterPressed: progressPill.toggle()
                Accessible.role: Accessible.Button
                Accessible.name: window.tr("progress.show-log", "Connection log")
                    + ": " + window.lastProgressMessage
                Accessible.onPressAction: progressPill.toggle()
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
                border.width: activeFocus ? uiTheme.focusBorderWidth : uiTheme.borderWidth
                border.color: activeFocus
                    ? uiTheme.stateFocusedBorder
                    : Qt.rgba(uiTheme.colorWarning.r, uiTheme.colorWarning.g,
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
                activeFocusOnTab: visible
                Keys.onSpacePressed: window.boundFilesController._saveBoundFilesNow()
                Keys.onReturnPressed: window.boundFilesController._saveBoundFilesNow()
                Keys.onEnterPressed: window.boundFilesController._saveBoundFilesNow()
                Accessible.onPressAction: window.boundFilesController._saveBoundFilesNow()
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
                readonly property bool warn: notificationsController.notificationTopSeverity === "warning"
                visible: notificationsController.notificationCount > 0
                Layout.preferredHeight: 24
                implicitWidth: notificationsChipRow.implicitWidth + uiTheme.spacingSm * 2
                radius: uiTheme.radiusSm
                color: notificationCenterPopup.visible
                    ? uiTheme.stateHoverFill
                    : (notificationsChip.warn
                        ? Qt.rgba(uiTheme.colorWarning.r, uiTheme.colorWarning.g,
                            uiTheme.colorWarning.b, 0.16)
                        : "transparent")
                border.width: activeFocus ? uiTheme.focusBorderWidth : uiTheme.borderWidth
                border.color: activeFocus
                    ? uiTheme.stateFocusedBorder
                    : notificationsChip.warn
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
                        text: window.tr("notifications.chip-label", "Notifications")
                            + " (" + notificationsController.notificationCount + ")"
                        color: window.textColor
                        verticalAlignment: Text.AlignVCenter
                        font.pixelSize: Math.max(11, window.font.pixelSize - 1)
                    }
                }
                function toggle() {
                    if (notificationCenterPopup.visible) notificationCenterPopup.close()
                    else notificationCenterPopup.open()
                }
                activeFocusOnTab: visible
                Keys.onSpacePressed: notificationsChip.toggle()
                Keys.onReturnPressed: notificationsChip.toggle()
                Keys.onEnterPressed: notificationsChip.toggle()
                Accessible.onPressAction: notificationsChip.toggle()
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true
                    onClicked: notificationsChip.toggle()
                    ToolTip.visible: containsMouse && prefs.tooltipsEnabled
                    ToolTip.delay: 400
                    ToolTip.text: window.tr("notifications.chip-tooltip",
                        "Show notifications")
                }
                Accessible.role: Accessible.Button
                Accessible.name: window.tr("notifications.title", "Notifications")
                Accessible.description: notificationsController.notificationCount + " "
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
                    || window.otherSectionsUnsaved
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
                enabled: window.prefsHaveUnsavedChanges
                    || window.rulesNotAppliedToService
                    || window.otherSectionsUnsaved
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
    // through `notificationsController.runNotificationAction` / `notificationsController.dismissNotification`.
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

            // Lazy section loading: each section is wrapped in a Loader that is
            // active ONLY while it is the current page, so a theme change /
            // font-scale step / `uiRevision` bump re-evaluates and relays out
            // just the visible section, not all five.
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
                    asynchronous: window.sectionLoadsAsync
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
                    asynchronous: window.sectionLoadsAsync
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
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { RuleSuggestionsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    active: StackLayout.isCurrentItem
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { RuleOverlapsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    active: StackLayout.isCurrentItem
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { VirtualMachinesSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { DiagnosticsSection { root: window } }
                }
                // Stays resident once opened so the trace survives a trip to
                // Rules; the section stops its own poll while hidden.
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { ConnTraceSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { CacheSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { LogsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    property bool keepLoaded: false
                    active: StackLayout.isCurrentItem || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { SettingsSection { root: window } }
                }
                Loader {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    active: StackLayout.isCurrentItem
                    asynchronous: window.sectionLoadsAsync
                    visible: StackLayout.isCurrentItem
                    sourceComponent: Component { OutageBlocksSection { root: window } }
                }
            }
        }
    }

    RuleEditDialog { id: ruleDialog; root: window }
    // The half of the rule form the tray's add-rule window shares with this one.
    RuleEditSupport {
        id: ruleEditSupport
        host: window
        language: window.currentLanguage
        rpc: rpcTransport
        aceCodec: window.hostAceCodec
        onSerializeFailed: window.statusLine = window.tr("status.rules-serialize-failed",
            "Internal error while preparing rules — see logs")
    }

    // Duplicate-rule modal. Two-button
    // pattern: "Open existing" jumps to the offending row in Edit mode;
    // "Cancel" returns to the in-progress form. Replaces the prior
    // single-line statusLine warning which the user reported was easy
    // to miss because the Save button completes without obvious feedback.
    // Extracted to
    // components/RuleDuplicateDialog.qml. The ruleDialog manipulation
    // stays here because ruleDialog is still inline (extraction deferred).
    // Every modal this window shows lives in `components/DialogHost.qml`.
    // The ids stay reachable under their own names through the aliases below,
    // so nothing that drives a dialog had to change.
    DialogHost {
        id: dialogHost
        ownerRoot: window
    }
    property alias ruleDuplicateDialog: dialogHost.ruleDuplicateDialog
    // Review-flow dialogs, invoked via `startRulesReviewFlow(rulesJson, contentHash)`.
    property alias reviewDiffDialog: dialogHost.reviewDiffDialog
    property alias fullResetConfirmDialog: dialogHost.fullResetConfirmDialog
    property alias fullResetCompleteDialog: dialogHost.fullResetCompleteDialog
    property alias infoNoticeDialog: dialogHost.infoNoticeDialog
    // Driven by flows/PresetImportController (duplicate/reclassify review).
    property alias presetImportReviewDialog: dialogHost.presetImportReviewDialog
    property alias reviewExpiredDialog: dialogHost.reviewExpiredDialog
    property alias firstLaunchInstallDialog: dialogHost.firstLaunchInstallDialog
    property alias uacRequiredDialog: dialogHost.uacRequiredDialog
    property alias reloadFromServiceConfirmDialog: dialogHost.reloadFromServiceConfirmDialog
    // Guardrail for an additional adapter that cannot carry traffic out. Opened
    // through `confirmUnroutableSecondary(...)` from the interfaces role flow and
    // from the leak-protection toggle.
    property alias unroutableSecondaryConfirmDialog: dialogHost.unroutableSecondaryConfirmDialog
    property alias emptyServiceRulesConfirmDialog: dialogHost.emptyServiceRulesConfirmDialog
    // The single post-connect "what piled up while the service was stopped"
    // dialog, driven by the window's backlog collector.
    property alias offlineBacklogDialog: dialogHost.offlineBacklogDialog
    property alias vpnOnboardingDialog: dialogHost.vpnOnboardingDialog
    property alias appGroupRoutingDialog: dialogHost.appGroupRoutingDialog
    property alias serviceUpdateDialog: dialogHost.serviceUpdateDialog
    property alias serviceNotRunningDialog: dialogHost.serviceNotRunningDialog
    // Drift + merge dialogs, driven by flows/DriftController.
    property alias driftDetectionDialog: dialogHost.driftDetectionDialog
    property alias driftClearAllConfirmDialog: dialogHost.driftClearAllConfirmDialog
    property alias mergeReviewDialog: dialogHost.mergeReviewDialog
    property alias rulesFileEditedDialog: dialogHost.rulesFileEditedDialog
    property alias rulesOverlapCleanupDialog: dialogHost.rulesOverlapCleanupDialog
    property alias saveBeforeCloseDialog: dialogHost.saveBeforeCloseDialog
    property alias factoryPresetSaveDialog: dialogHost.factoryPresetSaveDialog
    property alias saveRuleSetDialog: dialogHost.saveRuleSetDialog
    property alias rulesSaveFolderDialog: dialogHost.rulesSaveFolderDialog
    property alias verifyVerdictsFolderDialog: dialogHost.verifyVerdictsFolderDialog
    // Tray-initiated safe-disable confirmation, opened from
    // `applyGuiActivationRequest` when the secondary launcher writes
    // `action: "safe-disable"` into the gui-activation.json hand-off.
    property alias safeDisableConfirmDialog: dialogHost.safeDisableConfirmDialog
    property alias safeRollbackConfirmDialog: dialogHost.safeRollbackConfirmDialog

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


    /// The demo set in the UI language: its rule comments land in the table.
    function builtinDemoPreset(file) {
        var lang = resolveLanguageId(currentLanguage)
        return (lang === "ru" ? "builtin-demo/ru/" : "builtin-demo/") + file
    }

    /// User-triggered demo rules loader. MERGES the bundled built-in demo
    /// preset (`builtin-demo/rules_{primary,secondary}.txt`) into the
    /// existing `rulesModel`, skipping rules the user already has (by
    /// canonical id OR content signature), so a user who has been adding
    /// their own rows doesn't lose them. The merged set is then sent
    /// through the standard review flow for persistence.
    ///
    /// Sourced from the bundled preset files (single source of truth) instead
    /// of a hardcoded JS copy, parsed via the launcher's `preset.parse` RPC —
    /// the same parser used by preset import, so demo rows can never drift
    /// from real import behavior.
    function loadDemoRules() {
        if (!bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.resolvePresetPath !== "function"
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            statusLine = tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        var primaryPath = nrrNativeBridge.resolvePresetPath(
            builtinDemoPreset("rules_primary.txt"))
        var secondaryPath = nrrNativeBridge.resolvePresetPath(
            builtinDemoPreset("rules_secondary.txt"))
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
        reviewFlowController.startRulesReviewFlow(
            rulesJson, contentHash, false, "demo-rules")
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
    // The ACE form of an IDN host for the rule form's hint and the comment
    // `saveRule` fills in; "" for an ASCII host.
    function _punycodeFor(host) {
        return hostAceCodec.hint(host)
    }

    function _aceLowerForSearch(host) {
        return ruleEditSupport.aceLowerForSearch(host)
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
            var want = Rules.sequentialRuleId(j)
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
        // An empty keep-set deletes every stored comment, and this sweep cannot
        // tell "the user removed all their rules" from "the table is not filled
        // yet". Both of its call sites run while the model is legitimately
        // empty — the cold start, and a refresh that came back with nothing —
        // so the automatic sweep stands down. Clearing comments after a
        // deliberate wipe stays available through the Settings button, which
        // asks for the same GC with the user standing behind it.
        if (active.length === 0) return
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
                "Comment storage is not available in this build.")
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
            statusLine = Plurals.counted(tr, "status.sidecar-comments-gc-done.", removed,
                "Cleared {count} orphan comment.", "Cleared {count} orphan comments.")
        })
    }

    /// Best-effort sidecar write of one row's comment; empty deletes it.
    function _sidecarWriteCommentForRow(row) {
        if (!bridgeAvailable) return
        ruleEditSupport.writeComment(row)
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
    /// when it actually differs, so toggling a rule off and back on (net no
    /// change) does not leave a false "unsaved changes" state. It reuses the
    /// drift canonicalisation (`_buildRulesJsonForRoute` — order-stable, id
    /// zeroed, comments excluded), so "dirty" means exactly "routing content
    /// differs from what the service has". Comments are deliberately excluded:
    /// they live in the sidecar and are persisted immediately on Save, so they
    /// never need the unsaved-changes guard.
    /// The baseline is kept PER ROUTE so an edit can be attributed to the
    /// route it touched — the bound-file reminder is per route.
    property string _rulesDirtyBaselinePrimary: ""
    property string _rulesDirtyBaselineSecondary: ""
    /// The rows the baseline was taken from: what an edits merge measures the
    /// user's changes against.
    property var _rulesBaseRows: []
    function _captureRulesDirtyBaseline() {
        var rows = _rulesModelToRowArray()
        _rulesBaseRows = Rules.rebaseSnapshot(rows)
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
        // lands — the file still holds the pre-edit rules — so these flags
        // are raised immediately rather than only by an activation, which
        // would leave the footer "Save to file" chip a whole apply-cycle
        // late. Raise-only: clearing belongs to the paths that reconcile
        // against the file on disk (`_writeTargets` / `_reconcileBoundFileDirty`),
        // which compare content and therefore self-heal a net-zero edit.
        // Raised with or without a linked file — the save gesture asks for a
        // path when there is none.
        if (primaryDirty) _filesSyncDirtyPrimary = true
        if (secondaryDirty) _filesSyncDirtySecondary = true
        // Nothing can be applied while the service is down, so remember the
        // edit on disk: the post-connect question is then asked from a marker
        // that outlives this window.
        if (!_routingBackendConnected()) _offlineRulesMarkerTimer.restart()
        // The Overlaps count is shown on every screen, so it follows each edit.
        Qt.callLater(refreshRulesOverlaps)
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
        if (boundFilesController.tableMissesBoundRules()) return
        var json = _buildRulesJsonFromModel()
        if (!json) return
        var hash = (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function")
            ? nrrNativeBridge.sha256Hex(json) : ""
        _parkPendingApply(hash, rulesModel ? rulesModel.count : 0)
    }

    /// Let the UnsavedChangesGuard offer
    /// "Apply" for the rules section. The rules Save is a multi-step
    /// review→confirm→activate chain the user can abort, so a window-scope
    /// save callback is registered (works even when RulesSection is lazily
    /// unloaded) that drives that same pipeline and resumes the pending
    /// navigation on a successful activation; any abort/failure releases the
    /// guard WITHOUT navigating. `_guardRulesResume` carries the guard's
    /// onDone(ok) continuation across the async chain (it is also re-enabled
    /// by Cancel/Discard, which stay live while a save is in flight).
    property var _guardRulesResume: null
    /// Whether an apply CYCLE is running — from the guard's start to its
    /// resolution, dialog included. Separate from the transport's in-flight
    /// flag, which only covers the request: without this, the gap between
    /// the dry-run answering and the user deciding is exactly where a
    /// second cycle could slip in and open a second review window.
    property bool _guardRulesInFlight: false
    /// Build canonical rules-json from the current `rulesModel`
    /// state. Same shared serializer `RulesSection._buildRulesJson` uses, so
    /// the two payloads are byte-identical for identical rules; it lives here
    /// so non-section call sites can reuse it without crossing the section
    /// boundary.
    function _buildRulesJsonFromModel() {
        try {
            var rows = []
            for (var i = 0; i < rulesModel.count; i += 1) rows.push(rulesModel.get(i))
            return Rules.buildRulesJson(rows, _aceEncodeHost)
        } catch (err) {
            // A throw here would otherwise silently kill every save/review/
            // park flow that depends on the rules payload. Surface it and
            // return a falsy value so callers can bail out cleanly.
            console.error("_buildRulesJsonFromModel: rules serialization failed:", err)
            var refusal = Rules.wireRefusalCode(err)
            statusLine = refusal !== "" ? ipcErrorLabel(refusal)
                : tr("status.rules-serialize-failed",
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
    // Correlation id of the broker-status poll in flight, "" when none.
    property string _brokerStatusCorr: ""

    // Which review flow currently owns the shared
    // `reviewDiffDialog` instance. Used by `_retryReviewFlow` to dispatch
    // and by `reviewDiffDialog.onApproved` to pick the right
    // `_execute*Activation` callback (single-step apply).
    // Set by `startRulesReviewFlow` / `startPresetImportReviewFlow`.
    property string _activeReviewKind: "rules-update"

    /// When the last rules activation landed. A review whose dry-run was
    /// submitted before that moment describes a revision that no longer exists:
    /// its diff renders empty and its token dies on the way back. Openers check
    /// it instead of putting a dialog nobody can act on in front of the user.
    property double _lastRulesActivationMs: 0

    function reviewIsSuperseded(startedAtMs) {
        return _lastRulesActivationMs > 0 && Number(startedAtMs || 0) < _lastRulesActivationMs
    }

    /// One place to say it, so every opener says the same thing.
    function announceReviewSuperseded() {
        statusLine = tr("status.review-superseded",
            "Those changes were already applied, so there is nothing left to review.")
    }

    // Full reset: strong destructive confirm
    // (acknowledgement checkbox gates the action) → the full-reset controller.
    // Extracted to
    // components/FullResetConfirmDialog.qml (thin-shell refactor).
    // Full reset complete → offer to close
    // the program + tray so the reset takes effect on next launch.
    // Extracted to
    // components/FullResetCompleteDialog.qml.
    // Generic informational alert. Used by
    // `showNotice(title, body)`; e.g. an "Apply" with no pending changes
    // surfaces a clear notice instead of an empty review dialog.
    // Preset import review (duplicates +
    // unknown sections). Opens when the parser surfaces decisions
    // the user has to make. See `_handlePresetParseResolved` for
    // how the user's choices are folded back into the import.

    /// In-flight review state captured between the parser callback
    /// and the user's decision in `PresetImportReviewDialog`. `null`
    /// when no review is pending. Kept on `root` (not as a closure)
    /// so the dialog's signal handlers can reach it.
    property var _pendingPresetReview: null

    // Service install wizard. Fires at first-launch
    // when the service isn't registered yet AND the user hasn't burnt
    // through the UAC re-prompt budget (3 declines).

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
            startupController._runPostEulaStartup()
        }
        onDeclined: {
            window.logProgress(window.tr("progress.eula-declined",
                "License agreement declined — exiting."), "warn")
            Qt.quit()
        }
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
        function onOperationCompleted(operation, success, errorMessage, errorCode) {
            if (success) {
                window.logProgress(
                    window.tr("progress.service-" + String(operation) + "-ok",
                        String(operation)),
                    "success")
            } else {
                var reason = window.serviceOperationErrorText(errorCode, errorMessage)
                window.logProgress(
                    window.tr("progress.service-failed", "Service operation failed")
                        + " (" + String(operation) + "): " + reason,
                    "error")
                // The pill alone loses the failure: it sits in the footer, it is
                // easy to miss, and it scrolls away. A refused stop pressed five
                // times read as "nothing happens". The notice centre keeps it
                // until the user answers it, and names the reason.
                notificationsController._noteServiceOperationFailed(operation, reason)
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

    // Warn before an additional adapter that has no way out to the network is
    // put in charge of the additional route, or before leak protection is armed
    // over such an adapter. Confirming proceeds exactly as before; cancelling
    // leaves the previous state untouched.

    // Warn before an empty service state wipes the GUI rule list.

    // The single post-connect question: rules AND routing settings that were
    // changed while the service was stopped, collected by
    // `_startOfflineBacklogCollect` and offered once.

    // VPN-client onboarding. Captures WHICH installed/
    // running program the user treats as their VPN so its traffic keeps flowing
    // over the primary link while leak protection is on (an
    // "Application -> primary route" rule is already a leak-protection exemption).
    // Opened from `openVpnOnboarding()` (Settings -> Routing -> Leak protection).

    // App-group routing dialog. Scans installed/running programs,
    // groups them into popular categories, and lets the user send a whole group
    // over primary (default) or secondary. On confirm, only the secondary
    // assignments materialize application rules; primary removes any prior rule
    // for that exe (see `_applyAppGroupRoutes`). Opened via `openAppGroupRouting()`.

    // Gate dialog opened before the review-flow when
    // the service isn't connected. Three outcomes wired below: start /
    // install (escalates UAC, then re-arms the offline wait timer);
    // park to sidecar; cancel.
    // Shared by every "start the service" affordance: starting a registration
    // that points at another folder would launch the copy being replaced, so
    // those paths offer the re-registration instead.


    // Drift detection dialog. Opened from the
    // amber drift banner. The four resolution paths are wired below
    // to existing flows (preset import, review-flow, snapshot
    // rollback) so this stays a thin dispatcher with no business
    // logic of its own.

    // Destructive confirm for the drift
    // dialog's "Clear everything". Mirrors the full-reset confirm: an
    // acknowledgement checkbox gates the action, which wipes all rules
    // locally and pushes an empty revision to the service.

    // File↔service merge review dialog. Opened from the quiet
    // "Merge available" banner. Renders the `rules.merge-preview` buckets +
    // per-conflict picks; on confirm the caller re-runs the op with the picks
    // and hands the merged rules-json to the standard review + apply flow.

    // Cleanup for exact rules a wildcard already covers. Opened from the rules
    // screen; the pairs come from `local.rules-overlaps`.


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
            _parkPendingApply(p.contentHash, p.totalRules || 0)
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

    /// Record that the user parked changes: the hash of the rules they hold
    /// and how many there are. The rules themselves are not stored — the
    /// post-connect offer rebuilds them from the live model, which is what
    /// the user has been looking at all along.
    function _parkPendingApply(contentHash, totalRules) {
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
            summaryJson, String(contentHash || ""))
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

    /// Install or Start for the red banner's button, from the live SCM status:
    /// backendStatus.kind lags it by a poll and stays "disconnected" when the
    /// SCM answer is unknown, which is the only case it decides.
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
        } else if (serviceRegisteredElsewhere) {
            serviceUpdateDialog.open()
            return
        } else {
            nrrServiceController.startService()
        }
        // Progress belongs in the progress log, which the service controller
        // then closes out ("Starting…" -> "Started."). `statusLine` is sticky —
        // written there, "service starting" stays under a long-running service.
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
    /// interface row, `contextSlug` is "assign" or "leak-protection", and
    /// `onProceed` / `onCancel` are plain callbacks. The caller decides what
    /// happens; this only owns the wording and the yes/no.
    function confirmUnroutableSecondary(row, contextSlug, onProceed, onCancel) {
        var r = row || ({})
        unroutableSecondaryConfirmDialog.adapterName = Pure.adapterDisplayName(r)
        unroutableSecondaryConfirmDialog.reasonSlug =
            Pure.unroutableInterfaceReasonSlug(r)
        unroutableSecondaryConfirmDialog.contextSlug = String(contextSlug || "assign")
        unroutableSecondaryConfirmDialog.killSwitchArmed =
            routingState.leakProtection !== "off"
        unroutableSecondaryConfirmDialog.pendingAction = onProceed || null
        unroutableSecondaryConfirmDialog.pendingCancelAction = onCancel || null
        unroutableSecondaryConfirmDialog.open()
    }

    /// Ask before "Everything" while the additional connection is not
    /// available: the internet stops at once. Same dialog, no adapter named.
    /// `contextSlug` "holds-now-role" words it for a role removal or move.
    function confirmLeakHoldsNow(onProceed, onCancel, contextSlug) {
        unroutableSecondaryConfirmDialog.adapterName = ""
        unroutableSecondaryConfirmDialog.reasonSlug = ""
        unroutableSecondaryConfirmDialog.contextSlug =
            contextSlug === "holds-now-role" ? "holds-now-role" : "holds-now"
        unroutableSecondaryConfirmDialog.pendingAction = onProceed || null
        unroutableSecondaryConfirmDialog.pendingCancelAction = onCancel || null
        unroutableSecondaryConfirmDialog.open()
    }

    /// A default route that raises `level` (in force now) to "Everything"
    /// while the additional connection is not available asks first; any
    /// other change runs `onProceed` at once.
    function confirmDefaultRoute(level, nextRoute, onProceed, onCancel) {
        var decide = function(inForce) {
            var why = Pure.defaultRouteChangeConfirmSlug(inForce, nextRoute,
                interfacesRolesController.boundSecondaryRow())
            if (why === "holds-now") {
                confirmLeakHoldsNow(onProceed, onCancel)
                return
            }
            if (onProceed) onProceed()
        }
        // The tray changes the level without telling this window: ask against
        // the level the service holds now, `level` only when it cannot be read.
        if (!bridgeAvailable || typeof nrrNativeBridge === "undefined" || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInitialGet !== "function") {
            decide(level)
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInitialGet()
        if (!corr) { decide(level); return }
        rpc.registerRpcCallback(corr, function(ok, p) {
            if (!ok || !p) { decide(level); return }
            var rpRaw = p["route-policy"] || p.routePolicy
            _noteServicePolicy(rpRaw, p["first-policy"])
            var rp = rpRaw || {}
            var fresh = Pure.coerceLeakProtection(_routePolicyEffective(rp, "mode"),
                _routePolicyEffective(rp, "leak-protection"))
            updateRoutingState({ leakProtection: fresh })
            decide(fresh)
        })
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
        var corr = Pure.newCorrelationId("pending-apply-preview")
        var payload = {
            "rules-json":     String(rulesJson || ""),
            "content-hash":   String(contentHash || ""),
            "correlation-id": corr
        }
        var startedAtMs = Date.now()
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-update", payload, true /* dryRun */, ""
        )
        rpcTransport.registerLongRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok) {
                statusLine = tr(
                    "status.pending-apply-preview-failed",
                    "Could not load the diff for the parked changes; see logs.")
                console.log("pending-apply preview failed:", code, msg)
                return
            }
            if (reviewIsSuperseded(startedAtMs)) {
                announceReviewSuperseded()
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            // A refused set has an empty diff too; it still differs, and the
            // alarm stays up.
            var refusal = Pure.previewRefusal(summary)
            if (refusal) {
                statusLine = previewRefusalText(refusal)
                return
            }
            // The service just compared the two sets rule by rule. An empty
            // verdict outranks the hashes that raised the alarm: they can
            // disagree over things that change no routing, and a banner nobody
            // can clear — with a diff that shows nothing — is worse than no
            // banner at all. Stand the alarm down and re-baseline here.
            if (driftController._summaryHasNoRuleChanges(summary)) {
                driftController._standDownDriftAsEqual()
                return
            }
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
            contractSkew = Pure.contractSkew(payload, Pure.WIRE_CONTRACT_REVISION)
            serviceRegisteredPath      = String(payload["service-registered-path"] || "")
            serviceExpectedPath        = String(payload["service-expected-path"] || "")
            serviceRegisteredElsewhere = payload["service-registered-elsewhere"] === true
            serviceOlderThanApp        = payload["service-older-than-app"] === true
            serviceRestartNeeded       = payload["service-restart-needed"] === true
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
    /// Rules the service keeps but this version cannot read, so never applies
    /// (written by a newer version). Same single read as above.
    property int serviceUnrecognizedRules: 0

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
    /// The bound files' texts the merge under review was built from
    /// (`{ primary, secondary }`), taken as the program's once it is in force;
    /// null for any other review.
    property var _mergeTakenTexts: null

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
        commitPrefs({
            serviceInstallUacDeclinedCount: 0,
            serviceInstallPromptSuppressed: false
        })
        if (_serviceNeedsInstallPrompt()) {
            firstLaunchInstallDialog.open()
        } else {
            openChildWindow(firstRunWindow)
        }
    }

    /// Should the install offer open?
    ///
    /// Closing the dialog three times means "not now", not "never" — and
    /// without the service the app enforces nothing, so the offer comes back,
    /// at most once a week after the budget is spent. Only "Stop offering"
    /// holds indefinitely, and Settings takes it back.
    function _serviceNeedsInstallPrompt() {
        if (typeof nrrServiceController === "undefined"
                || nrrServiceController === null) {
            return false
        }
        var status = parseInt(nrrServiceController.status)
        // status === 1 ⇒ NotInstalled
        if (status !== 1) return false
        if (prefs.serviceInstallPromptSuppressed === true) return false
        var declines = parseInt(prefs.serviceInstallUacDeclinedCount || 0)
        if (declines < 3) return true
        var lastAt = parseInt(prefs.serviceInstallUacDeclinedAtEpoch || 0)
        if (!(lastAt > 0)) return false
        return (Math.floor(Date.now() / 1000) - lastAt) >= 7 * 24 * 60 * 60
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
                commitPrefs({
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
                commitPrefs({
                    serviceInstallUacDeclinedCount: 0
                })
            }
        }
    }

    // Save-before-close dialog. Fires AFTER the
    // UnsavedChangesGuard cleared, only on real close (X / tray Exit),
    // never on close-to-tray. Lets the user persist active rule edits
    // back to the imported file paths or roll them back.

    // Save-As target picker for the queue in BoundFilesController: one route at
    // a time, written from the local rules table (no service involved) and
    // linked to the chosen path.
    // The rules file sits inside the sets that ship with the app, so the write
    // is warned about — not refused — and the warning offers both ways out.
    // Every handler is a one-liner into BoundFilesController, which owns the
    // held write and its resume.

    // "Save rules as a set" from the Rules toolbar. A set is a folder with one
    // file per route, so the question is a name plus a place.

    // Folder picker for the refusal above. Same title as the rule-set folder
    // picker in Settings — it is the same choice, reached from the save.

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

    // Safe rollback confirm → RollbackRequest of the user's own rules.

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
