import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import "../lib/pure.js" as Pure
import "../lib/rules.js" as Rules

// Every modal this window puts on screen, in one place.
//
// Extracted from Main.qml (thin-shell rule): the shell keeps the STATE the
// dialogs read and the FUNCTIONS they call, and this holds the declarations —
// the part that is pure markup and made up most of the file's length.
//
// An `Item`, not a `QtObject`, and one that fills its parent. A `Dialog` is a
// `Popup`: it positions itself against its VISUAL parent, and several of these
// say `anchors.centerIn: parent`. Declared inside a `QtObject` their parent
// would be null and they would open in the corner (or not at all). Filling the
// window's content item keeps the geometry they were written against.
//
// Nothing here is interactive on its own — no `MouseArea`, no background — so
// covering the window costs the layout underneath nothing.
Item {
    id: dialogHost
    anchors.fill: parent

    /// The ApplicationWindow. Every piece of state these dialogs read, and
    /// every function they call, belongs to it.
    property var ownerRoot

    property alias ruleDuplicateDialog: ruleDuplicateDialog
    property alias reviewDiffDialog: reviewDiffDialog
    property alias fullResetConfirmDialog: fullResetConfirmDialog
    property alias fullResetCompleteDialog: fullResetCompleteDialog
    property alias infoNoticeDialog: infoNoticeDialog
    property alias presetImportReviewDialog: presetImportReviewDialog
    property alias reviewExpiredDialog: reviewExpiredDialog
    property alias firstLaunchInstallDialog: firstLaunchInstallDialog
    property alias uacRequiredDialog: uacRequiredDialog
    property alias reloadFromServiceConfirmDialog: reloadFromServiceConfirmDialog
    property alias unroutableSecondaryConfirmDialog: unroutableSecondaryConfirmDialog
    property alias emptyServiceRulesConfirmDialog: emptyServiceRulesConfirmDialog
    property alias offlineBacklogDialog: offlineBacklogDialog
    property alias vpnOnboardingDialog: vpnOnboardingDialog
    property alias appGroupRoutingDialog: appGroupRoutingDialog
    property alias serviceUpdateDialog: serviceUpdateDialog
    property alias serviceNotRunningDialog: serviceNotRunningDialog
    property alias driftDetectionDialog: driftDetectionDialog
    property alias driftClearAllConfirmDialog: driftClearAllConfirmDialog
    property alias mergeReviewDialog: mergeReviewDialog
    property alias rulesOverlapCleanupDialog: rulesOverlapCleanupDialog
    property alias saveBeforeCloseDialog: saveBeforeCloseDialog
    property alias factoryPresetSaveDialog: factoryPresetSaveDialog
    property alias saveRuleSetDialog: saveRuleSetDialog
    property alias rulesSaveFolderDialog: rulesSaveFolderDialog
    property alias safeDisableConfirmDialog: safeDisableConfirmDialog
    property alias safeRollbackConfirmDialog: safeRollbackConfirmDialog

    RuleDuplicateDialog {
        id: ruleDuplicateDialog
        ownerRoot: dialogHost.ownerRoot
        onOpenExistingRequested: function(idx) {
            ownerRoot.ruleDialog.close()
            if (idx >= 0 && idx < ownerRoot.rulesModel.count) {
                ownerRoot.selectedRule = idx
                ownerRoot.editingRule = idx
                ownerRoot.ruleDialog.resetForEdit()
                ownerRoot.ruleDialog.open()
            }
        }
    }

    ReviewDiffDialog {
        id: reviewDiffDialog
        ownerRoot: dialogHost.ownerRoot
        // Single-step apply. The review
        // dialog now applies directly: the separate ConfirmActivateDialog
        // hop was removed and its Critical-risk acknowledgement checkbox
        // moved into ReviewDiffDialog. Dispatch by active flow kind — the
        // two pending-state structs (rules-update vs preset-import) carry
        // the confirmation token issued on the dry-run pass.
        onApproved: {
            var state = (ownerRoot._activeReviewKind === "preset-import")
                ? ownerRoot.pendingPresetImportState
                : ownerRoot.pendingReviewState
            var token = state.confirmationToken
            if (ownerRoot._activeReviewKind === "preset-import") {
                ownerRoot.presetImportController._executePresetImportActivation(token)
            } else if (ownerRoot._activeReviewKind === "rules-reset-to-baseline") {
                // Reset shares the review dialog.
                ownerRoot.reviewFlowController._executeResetToBaselineActivation(token)
            } else {
                ownerRoot.reviewFlowController._executeRulesActivation(token)
            }
        }
        // User clicked "Apply…" in the read-only preview. Leave preview and
        // re-enter the standard rules review flow with the very payload the
        // preview was built from; that re-runs the dry-run and re-opens this
        // dialog Apply-enabled.
        onPreviewApplyRequested: {
            var p = ownerRoot._pendingPreviewPayload
            ownerRoot._pendingPreviewPayload = null
            if (p) ownerRoot.reviewFlowController.startRulesReviewFlow(p.rulesJson, p.contentHash)
        }
        // The same rule sits on both routes and the user picked the one that
        // keeps it. The loser is switched OFF, never deleted: they wrote it,
        // and turning it back on is one click if they change their mind.
        onDuplicateResolved: function(primaryRuleId, secondaryRuleId, keep) {
            var loser = (keep === "primary") ? secondaryRuleId : primaryRuleId
            if (!ownerRoot._disableRuleById(loser)) return
            reviewDiffDialog.close()
            ownerRoot.statusLine = ownerRoot.tr("status.duplicate-rule-resolved",
                "The other copy of the rule was switched off. Review the changes again to apply them.")
        }
        onCancelled: {
            // User dismissed the review dialog; release the guard
            // (if it drove this apply) so its Save button re-enables and the
            // user can Cancel/Discard. No-op for non-guard flows.
            ownerRoot.reviewFlowController._resolveGuardRulesApply(false)
        }
    }

    FullResetConfirmDialog {
        id: fullResetConfirmDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: function(allPrincipals) { ownerRoot.fullResetController.fullReset(allPrincipals) }
    }

    FullResetCompleteDialog {
        id: fullResetCompleteDialog
        ownerRoot: dialogHost.ownerRoot
        onCloseAllRequested: ownerRoot.fullResetController.closeAllProcesses()
    }

    InfoNoticeDialog {
        id: infoNoticeDialog
        ownerRoot: dialogHost.ownerRoot
    }

    PresetImportReviewDialog {
        id: presetImportReviewDialog
        ownerRoot: dialogHost.ownerRoot
        onApproved: function(decisions) {
            ownerRoot.presetImportController._applyPresetReviewDecisions(decisions)
        }
        onCancelled: {
            // User aborted — discard the pending parse result; the
            // caller's `onComplete` callback is never invoked, so no
            // status banner update / sidecar write happens.
            ownerRoot._pendingPresetReview = null
            ownerRoot.statusLine = ownerRoot.tr("status.preset-review-cancelled",
                "Preset import cancelled by user.")
        }
    }

    ReviewExpiredDialog {
        id: reviewExpiredDialog
        ownerRoot: dialogHost.ownerRoot
        onRetry: ownerRoot.reviewFlowController._retryReviewFlow()
        onCancelled: { /* no-op */ }
    }

    FirstLaunchInstallDialog {
        id: firstLaunchInstallDialog
        ownerRoot: dialogHost.ownerRoot
        onInstallRequested: {
            if (typeof nrrServiceController !== "undefined"
                    && nrrServiceController) {
                nrrServiceController.installService()
            }
            // After the install attempt completes (success OR UAC
            // declined), continue into the preset wizard.
            ownerRoot.openChildWindow(ownerRoot.firstRunWindow)
        }
        onSkipRequested: {
            // User explicitly chose preview mode; continue into the
            // preset wizard so they can pick demo / file / empty.
            ownerRoot.openChildWindow(ownerRoot.firstRunWindow)
        }
        onStopOfferingRequested: {
            ownerRoot.updatePrefs({ serviceInstallPromptSuppressed: true })
            ownerRoot.emitPrefs()
            ownerRoot.statusLine = ownerRoot.tr("status.service-install-offer-stopped",
                "The service install offer is off. Turn it back on in Settings.")
            ownerRoot.openChildWindow(ownerRoot.firstRunWindow)
        }
        onLearnMoreRequested: {
            // Single source of truth — same URL the About dialog uses
            // (seeded from `nrr_shared::ShellAbout::project_url` via
            // ui_surface.rs).
            var url = String((ownerRoot.context.about || {}).projectUrl || "")
            if (url !== "") {
                Pure.openExternalUrl(url)
            }
        }
    }

    UacRequiredDialog {
        id: uacRequiredDialog
        ownerRoot: dialogHost.ownerRoot
    }

    ReloadFromServiceConfirmDialog {
        id: reloadFromServiceConfirmDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: ownerRoot._refreshRulesFromService({ silent: false })
    }

    UnroutableSecondaryConfirmDialog {
        id: unroutableSecondaryConfirmDialog
        ownerRoot: dialogHost.ownerRoot
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

    EmptyServiceRulesConfirmDialog {
        id: emptyServiceRulesConfirmDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: {
            var opts = Object.assign({}, ownerRoot._pendingEmptyReloadOpts || {})
            opts.confirmedEmpty = true
            ownerRoot._refreshRulesFromService(opts)
        }
        // The user picked "Apply application state" from this very
        // dialog instead of clearing. Drop the pending empty-reload (so nothing
        // re-wipes ownerRoot.rulesModel afterwards) and push the current GUI rules to the
        // empty service via the existing review/apply flow.
        onApplyAppStateRequested: {
            ownerRoot._pendingEmptyReloadOpts = ({})
            ownerRoot.driftController._driftApplyGuiState()
        }
    }

    OfflineBacklogDialog {
        id: offlineBacklogDialog
        ownerRoot: dialogHost.ownerRoot
        onApplyAllRequested: {
            // Settings first (one RPC, no further prompts), then the rules
            // review flow, which owns the rest of the interaction.
            if (offlineBacklogDialog.settingsRows.length > 0) {
                ownerRoot.offlinePendingController._applyOfflinePending()
            }
            if (offlineBacklogDialog.rulesPending) {
                ownerRoot.offlineBacklogCollector._clearPendingApplyPark()
                ownerRoot.reviewFlowController._guardApplyRules(function(ok) {
                    ownerRoot.driftController._driftRecheckNow()
                })
            }
        }
        onDiscardAllRequested: {
            if (offlineBacklogDialog.settingsRows.length > 0) {
                ownerRoot.offlinePendingController._discardOfflinePending()
            }
            if (offlineBacklogDialog.rulesPending) {
                ownerRoot._offlineRulesPendingPush = false
                ownerRoot.offlineBacklogCollector._clearPendingApplyPark()
                ownerRoot.statusLine = ownerRoot.tr("status.pending-apply-discarded",
                    "Parked changes discarded.")
            }
        }
        // "Later" and any dismissal keep everything parked; the next connect
        // asks again.
        onLaterRequested: { /* nothing to undo — the parks are untouched */ }
        onPreviewRulesRequested: ownerRoot._previewCurrentRulesAgainstService()
        // The guard flag only means "an offer is on screen", so any close
        // re-arms the offer.
        onClosed: ownerRoot.offlinePendingController._offlinePendingDialogActive = false
    }

    VpnOnboardingDialog {
        id: vpnOnboardingDialog
        ownerRoot: dialogHost.ownerRoot
        onVpnConfirmed: function(displayName, exePath) {
            // Single add (the manual file picker). We store the confirmed
            // executable as a device-local preference (the offline display
            // fallback) AND write it to the service-side SSOT via
            // route.link-provider.set below — that write registers the per-app
            // kill-switch exemption and triggers a server-side recompile, which
            // supersedes the old "make it an Application->primary rule" intent.
            var path = String(exePath || "")
            ownerRoot.updatePrefs({
                confirmedVpnExePath: path,
                confirmedVpnExePaths: path
            })
            ownerRoot.emitPrefs()
            var shownName = String(displayName || "")
            ownerRoot.statusLine = (path !== "")
                ? ownerRoot.tr("vpn-onboarding.confirmed-status",
                    "NetRuleRouter will keep {name} working over your main link while leak protection is on.")
                    .replace("{name}", shownName)
                : ownerRoot.tr("vpn-onboarding.confirmed-status-no-path",
                    "Noted {name} as your VPN. Pick its program file to finish setup.")
                    .replace("{name}", shownName)
            if (path !== "") {
                var lpName = (shownName !== "")
                    ? shownName
                    : String(path.split(/[\\/]/).pop() || "")
                ownerRoot._writeLinkProviderSet([{ "exe-path": path, "display-name": lpName }])
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
            ownerRoot.updatePrefs({
                confirmedVpnExePaths: paths.join(";"),
                confirmedVpnExePath: paths.length > 0 ? paths[0] : ""
            })
            ownerRoot.emitPrefs()
            ownerRoot._writeLinkProviderSet(lpApps)
            if (paths.length > 1) {
                ownerRoot.statusLine = ownerRoot.tr("vpn-onboarding.confirmed-status-multi",
                    "NetRuleRouter will keep your {count} VPN programs working over your main link while leak protection is on.")
                    .replace("{count}", String(paths.length))
            } else if (paths.length === 1) {
                ownerRoot.statusLine = ownerRoot.tr("vpn-onboarding.confirmed-status",
                    "NetRuleRouter will keep {name} working over your main link while leak protection is on.")
                    .replace("{name}", String(names.length > 0 ? names[0] : ""))
            } else {
                // Everything selected was name-only (no resolved path).
                ownerRoot.statusLine = ownerRoot.tr("vpn-onboarding.confirmed-status-no-path",
                    "Noted {name} as your VPN. Pick its program file to finish setup.")
                    .replace("{name}", String(names.length > 0 ? names[0] : ""))
            }
        }
        onSkipped: {
            ownerRoot.statusLine = ownerRoot.tr("vpn-onboarding.skipped-status",
                "No VPN set up. You can set one up later from Settings -> Routing.")
        }
        onManualPickRequested: {
            // The dialog opens a native file picker itself; this
            // just notes the action in the status line.
            ownerRoot.statusLine = ownerRoot.tr("vpn-onboarding.manual-pick-status",
                "Choose your VPN program file…")
        }
    }

    AppGroupRoutingDialog {
        id: appGroupRoutingDialog
        ownerRoot: dialogHost.ownerRoot
        onAppGroupRoutesConfirmed: function(assignments) {
            ownerRoot._applyAppGroupRoutes(assignments)
        }
        onSkipped: { /* no-op; user closed the dialog without applying */ }
    }

    ServiceUpdateConfirmDialog {
        id: serviceUpdateDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: {
            if (typeof nrrServiceController !== "undefined" && nrrServiceController) {
                nrrServiceController.reinstallService()
            }
        }
    }

    ServiceNotRunningDialog {
        id: serviceNotRunningDialog
        ownerRoot: dialogHost.ownerRoot
        onStartServiceRequested: {
            ownerRoot.startServiceOrOfferUpdate()
            ownerRoot._armOfflineServiceStartTimer()
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
            ownerRoot._armOfflineServiceStartTimer()
        }
        onWorkWithoutServiceRequested: {
            if (!ownerRoot._pendingOfflinePark) return
            var p = ownerRoot._pendingOfflinePark
            ownerRoot._parkPendingApply(p.contentHash, p.totalRules)
            ownerRoot._pendingReviewAfterConnect = null
            ownerRoot._pendingOfflinePark = null
            ownerRoot.statusLine = ownerRoot.tr(
                "status.pending-apply-parked",
                "Changes parked. They will be applied when the service is running again.")
            // Dirty flag intentionally kept — close-guard still warns
            // the user even though the work is persisted in sidecar.
            // The status banner above signals the parked-state.
        }
        // Saving the rules to disk needs no service at all, so the gate offers
        // it: the user's work is kept even when the service will not start.
        onSaveToFileRequested: {
            ownerRoot._pendingReviewAfterConnect = null
            ownerRoot._pendingOfflinePark = null
            ownerRoot.boundFilesController.saveRulesToFiles(true, null)
        }
        onCancelled: {
            ownerRoot._pendingReviewAfterConnect = null
            ownerRoot._pendingOfflinePark = null
        }
    }

    DriftDetectionDialog {
        id: driftDetectionDialog
        ownerRoot: dialogHost.ownerRoot
        primaryDetails:       ownerRoot._driftDetailsPrimary
        secondaryDetails:     ownerRoot._driftDetailsSecondary
        fileExistsPrimary:    ownerRoot._driftFileExistsPrimary
        fileExistsSecondary:  ownerRoot._driftFileExistsSecondary
        onLoadFromFileRequested:        ownerRoot.driftController._driftLoadFromFile()
        onApplyGuiStateRequested:       ownerRoot.driftController._driftApplyGuiState()
        onAcceptServiceStateRequested:  ownerRoot.driftController._driftAcceptServiceState()
        onShowDiffRequested:            ownerRoot.driftController._driftShowDiff()
        onClearAllRequested:            driftClearAllConfirmDialog.open()
        onCancelled:                    { /* banner stays */ }
    }

    DriftClearAllConfirmDialog {
        id: driftClearAllConfirmDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: ownerRoot.driftController._driftClearAll()
    }

    MergeReviewDialog {
        id: mergeReviewDialog
        ownerRoot: dialogHost.ownerRoot
        onCancelled: { /* banner stays until resolved */ }
        onConfirmed: function(resolutions) { ownerRoot.driftController._applyMerge(resolutions) }
    }

    RulesOverlapCleanupDialog {
        id: rulesOverlapCleanupDialog
        ownerRoot: dialogHost.ownerRoot
        onRemoveRequested: function(keys) { ownerRoot.removeOverlapPairs(keys) }
        onKeepRequested: function(keys) {
            ownerRoot.keepOverlapPairs(keys)
            rulesOverlapCleanupDialog.selectAllActionable()
        }
    }

    SaveBeforeCloseDialog {
        id: saveBeforeCloseDialog
        ownerRoot: dialogHost.ownerRoot
        onSaveSelected: ownerRoot.boundFilesController._handleSaveSelectedFromCloseDialog()
        onSaveAs: ownerRoot.boundFilesController._handleSaveAsFromCloseDialog()
        onDiscardAndRollback: ownerRoot.boundFilesController._handleDiscardAndRollback()
        onCancelled: { ownerRoot._resumeCloseAfterSaveBefore = false }
    }

    FactoryPresetSaveDialog {
        id: factoryPresetSaveDialog
        ownerRoot: dialogHost.ownerRoot
        onSaveHereRequested: ownerRoot.boundFilesController.factorySaveHereConfirmed()
        onChooseFolderRequested: {
            // The `ownerRoot.hasRulesFolder` guard matters — writing an empty URL into
            // `currentFolder` points the dialog at the process working
            // directory instead of "use the default".
            if (ownerRoot.hasRulesFolder) rulesSaveFolderDialog.currentFolder = ownerRoot.rulesFolderUrl
            rulesSaveFolderDialog.open()
        }
        onCancelled: ownerRoot.boundFilesController.cancelFactoryPathRebind()
    }

    SaveRuleSetDialog {
        id: saveRuleSetDialog
        root: dialogHost.ownerRoot
        onSetAccepted: function(name, folder) {
            ownerRoot.boundFilesController.writeSetNamed(folder, name)
        }
        // A dismissed dialog is an answer too: the caller that asked for the
        // save (a close-flow, say) waits on the callback and would hang
        // without it.
        onSetDismissed: ownerRoot.boundFilesController._handleSaveAsCancelled()
    }

    FolderDialog {
        id: rulesSaveFolderDialog
        title: ownerRoot.tr("settings.presets.user-folder.dialog-title",
            "Choose the folder with your rule sets")
        onAccepted: {
            ownerRoot.boundFilesController.rebindBlockedRoutesTo(
                Pure.localPathFromFileUrl(selectedFolder))
        }
        onRejected: ownerRoot.boundFilesController.cancelFactoryPathRebind()
    }

    SafeDisableConfirmDialog {
        id: safeDisableConfirmDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: function(reason) {
            ownerRoot._handleSafeDisableConfirmed(reason)
        }
        onCancelled: {
            ownerRoot.statusLine = ownerRoot.tr("status.safe-disable.cancelled",
                "Safe disable cancelled")
        }
    }

    SafeRollbackConfirmDialog {
        id: safeRollbackConfirmDialog
        ownerRoot: dialogHost.ownerRoot
        onConfirmed: ownerRoot.boundFilesController._performSafeRollback()
    }
}
