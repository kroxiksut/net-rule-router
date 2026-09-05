import QtQuick 2.15

// Non-visual controller for STARTUP after the licence gate: what has to happen
// once the agreement is accepted, and what a pre-supplied answer set (headless
// provisioning) means for the first-run wizard.
//
// Extracted from Main.qml (thin-shell rule). The order here is the substance:
// a parked connection assignment is delivered BEFORE the binding re-sync, which
// only acts on an empty service binding and would otherwise leave the parked
// choice behind; the cold-start drift compare is primed explicitly because
// there is no disconnected→connected edge to hang it on when the service is
// already up at launch.
QtObject {
    id: startupController

    /// The ApplicationWindow. Every window, model, timer and sibling controller
    /// this touches belongs to it.
    property var root

    /// Whether the license agreement must be shown before the app can be used:
    /// the persisted `acceptedEulaVersion` is below the version the current
    /// build ships (`context.eula.currentVersion`), and there is agreement text
    /// to display. A missing/zero current version (older context) disables the
    /// gate rather than trapping the user in an empty dialog.
    function _eulaNeedsAcceptance() {
        var eula = (root.context || {}).eula || {}
        var current = (eula.currentVersion | 0)
        if (current <= 0) return false
        if (String(eula.text || "").trim() === "") return false
        var accepted = ((root.prefs || {}).acceptedEulaVersion | 0)
        return accepted < current
    }

    /// The pre-launch answer sheet, or an empty stand-in. Shape mirrors
    /// `provisioning.rs`; `present: false` is the ordinary case.
    readonly property var provisioning: (root.context && root.context.provisioning)
        ? root.context.provisioning : ({ present: false, completesFirstRun: false })

    function _provisioningCompletesFirstRun() {
        return provisioning.present === true && provisioning.completesFirstRun === true
    }

    /// Apply a complete answer sheet in place of the wizard. Deliberately the
    /// same calls the wizard's own handlers make, so provisioned and
    /// hand-answered installs land in one state, not two.
    function _applyProvisionedFirstRun() {
        root.logProgress(root.tr("progress.first-run-provisioned",
            "Setup answers were supplied before launch; applying them."), "progress")
        var rp = root.routePolicyController
        if (rp) {
            if (typeof rp.applyKillSwitchEnabled === "function") {
                rp.applyKillSwitchEnabled(provisioning.killSwitch === true)
            }
            if (typeof rp.applyDohLockdownEnabled === "function") {
                rp.applyDohLockdownEnabled(provisioning.dohLockdown === true)
            }
        }
        if (typeof root.applyServiceStabilityPatch === "function") {
            root.applyServiceStabilityPatch({ "fake-ip-enabled": provisioning.fakeIp === true },
                function() {}, "provisioning")
        }
        _applyProvisionedConnections()
        _loadBundledRuleSet(String(provisioning.ruleSet || "none"))
        root.updatePrefs({ firstRunCompleted: true })
        root.emitPrefs()
    }

    /// Import a bundled rule set named as `<country>/<pack>`, the same two
    /// files and the same review flow the wizard's country option uses.
    /// `"none"` (or an unreadable set) leaves the table empty.
    function _loadBundledRuleSet(packPath) {
        if (packPath === "" || packPath === "none") return
        if (!root.bridgeAvailable || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.resolvePresetPath !== "function") return
        var primRel = packPath + "/rules_primary.txt"
        var secRel = packPath + "/rules_secondary.txt"
        var primAbs = String(nrrNativeBridge.resolvePresetPath(primRel) || "")
        var secAbs = String(nrrNativeBridge.resolvePresetPath(secRel) || "")
        var primB64 = primAbs !== "" ? nrrNativeBridge.readFileBytes(primAbs) : ""
        var secB64 = secAbs !== "" ? nrrNativeBridge.readFileBytes(secAbs) : ""
        if (!primB64 && !secB64) {
            root.statusLine = root.tr("status.provisioned-rule-set-missing",
                "The rule set named in the setup answers was not found: ") + packPath
            return
        }
        root.presetImportController.startBothRoutesPresetImportReviewFlow(
            primB64, secB64, primAbs, secAbs)
    }

    /// Bind the named connections, when the live adapter list has them. A name
    /// that is not there yet (a VPN adapter appears on first connect) simply
    /// leaves the slot empty — the missing-connection banner then asks.
    function _applyProvisionedConnections() {
        var byName = function(wanted) {
            var w = String(wanted || "")
            if (w === "") return -1
            for (var i = 0; i < root.interfacesModel.count; i += 1) {
                var row = root.interfacesModel.get(i)
                if (String(row.name || "") === w || String(row.description || "") === w) return i
            }
            return -1
        }
        var p = byName(provisioning.primaryConnection)
        if (p >= 0) root.interfacesRolesController.assignRole(p, "primary")
        var s = byName(provisioning.secondaryConnection)
        if (s >= 0) root.interfacesRolesController.assignRole(s, "secondary")
    }

    /// The normal startup-dialog chain, gated behind EULA acceptance. Called
    /// directly when the agreement is already accepted, or from the EULA
    /// window's `accepted` handler otherwise.
    function _runPostEulaStartup() {
        if ((root.context.startupDialog || "") === "about") {
            root.openChildWindow(root.aboutWindow)
        } else if ((root.context.startupDialog || "") === "license") {
            root.openChildWindow(root.licenseWindow)
        } else if (!root.prefs.firstRunCompleted && _provisioningCompletesFirstRun()) {
            // Every question the wizard asks was answered before launch — by an
            // installer, or by a file shipped next to a portable copy. Apply
            // them and never show the window.
            _applyProvisionedFirstRun()
        } else if (!root.prefs.firstRunCompleted) {
            root.logProgress(root.tr("progress.first-run-wizard-shown",
                "Showing first-run setup (not completed yet)."), "progress")
            // Show the service install dialog FIRST
            // when the service isn't registered yet. After the user
            // picks Install or Skip, the existing preset
            // wizard opens (chained via the install dialog's signals).
            // Skip-budget: if the user declined UAC 3+ times we keep
            // them out of the modal trap and jump straight to the
            // preset wizard.
            if (root._serviceNeedsInstallPrompt()) {
                root.firstLaunchInstallDialog.open()
            } else {
                root.openChildWindow(root.firstRunWindow)
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
            root._forgetStaleFactoryRulesBinding()
            root._hydrateRulesOnLaunch()
        }
        // Cold-start check for offline work parked in a previous session.
        // refreshBackendStatus only fires the same check on a
        // disconnect→connect transition; when the cold-start snapshot
        // arrives with the service already running there's no
        // transition, so we'd miss the prompt without this one-shot.
        // (`firstRunCompleted` is re-checked inside the collector so the
        // first-launch wizards are never buried under a modal.)
        if (((root.backendStatus || {}).kind) === "connected") {
            root._offlineBacklogCollectTimer.restart()
        }
        // Cold-start re-sync of the adapter binding
        // into the service when it has none but prefs do (e.g. service DB was
        // wiped). No-op when already in sync or no binding is selected.
        if (((root.backendStatus || {}).kind) === "connected") {
            // A connection assignment made before the service was up is
            // delivered first — the resync below only acts on an EMPTY service
            // binding, so on its own it would leave the parked choice behind.
            Qt.callLater(root.offlinePendingController.deliverParkedBinding)
            // The other direction of the same split: a slot the app has no
            // answer for is filled from what the service enforces, and a slot
            // where the two disagree raises the banner that asks. Runs after
            // the parked delivery, which is the user's newer word.
            Qt.callLater(root.routePolicyController.seedRouteBindingFromService)
            Qt.callLater(root.routePolicyController._resyncRouteBindingIfMissing)
            // Cold-start counterpart of the reconnect replay: when the service
            // is already up at launch there is no disconnected→connected edge
            // to hang it on.
            Qt.callLater(root.serviceIntentController.replayServiceIntentToService)
            // Same edge problem for the drift compare: the file legs are only
            // measured by a recheck, and the cold-start capture does not do one.
            // Without this the window says nothing about a diverged rules file
            // for the first 30 s of every launch — which is exactly when the
            // user who came from the tray notice is looking at it.
            root._driftConnectRetryCount = 0
            root._driftConnectComparePrimeTimer.restart()
        }
        // Populate the compatibility banner state
        // from the launcher's `local.service-info` snapshot. Runs
        // unconditionally on cold-start; the banner only paints when
        // a protocol mismatch is actually detected.
        Qt.callLater(root._refreshServiceInfo)
        // Cold-start read of the local segments waiting for an answer; the
        // daily timer takes over from here.
        Qt.callLater(root.refreshPendingLocalNetworks)
        // Cold-start counterpart of the reconnect read above. Unconditional:
        // with no service reachable it falls back to the last value the
        // service reported, so a locked machine does not present an editable
        // Rules section for the first few seconds of every launch.
        Qt.callLater(root.refreshRuleEditPermission)
        // The tray is the application's presence: it carries the notices the
        // service raises and the "Exit" that winds everything down, so it comes
        // up WITH the window, not only when the window is closed to it. A
        // duplicate launch is a no-op — the tray holds its own single-instance
        // lock. Skipped for the timed runs used to capture screenshots. The
        // autostart checkbox governs the SIGN-IN entry only, not this path.
        if (root.autoCloseMs <= 0 && typeof nrrNativeBridge !== "undefined"
                && nrrNativeBridge && nrrNativeBridge.ensureTrayRunning) {
            Qt.callLater(function() { nrrNativeBridge.ensureTrayRunning() })
        }
        // A launch started BY the tray carries an intent slug. With a window
        // already open it arrives in the activation-request file; a cold launch
        // has no window to hand it to, so it rides the context and is dispatched
        // here through the same one entry point.
        var coldAction = String((root.context || {}).launchAction || "")
        if (coldAction !== "") {
            Qt.callLater(function() {
                root.applyGuiActivationRequest({
                    action: coldAction,
                    reason: String((root.context || {}).launchReason || "")
                })
            })
        }
    }
}
