import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller owning the rules review/activation flow: the
// unsaved-changes apply guard, the dry-run -> ReviewDiffDialog -> activate flow
// for rules-update, reset-to-baseline, the retry path, and the session
// elevation broker probes/revoke. Extracted from Main.qml (thin-shell rule).
// The shell keeps the shared review STATE (`pendingReviewState`,
// `_activeReviewKind`, `_brokerSessionElevated`, `_guardRulesResume`) and the
// rules-model helper `_buildRulesJsonFromModel`, reached via `root`. Sibling
// controllers are reached as `root.presetImportController` (retry dispatch) and
// `root.driftController` (post-activate baseline recapture). Main.qml
// instantiates one and exposes it as `root.reviewFlowController`; RulesSection /
// NavigationSidebar / DriftController drive it through that handle. RPC goes
// through `root.rpc`; `nrrNativeBridge` is a global context property (bare).
QtObject {
    id: reviewFlowController
    property var root

    function _guardApplyRules(onDone) {
        root._guardRulesResume = (typeof onDone === "function") ? onDone : null
        var rulesJson = root._buildRulesJsonFromModel()
        if (!rulesJson) {
            // Serializer failed (already reported by the shell) — release
            // the guard so the calling flow doesn't hang half-started.
            _resolveGuardRulesApply(false)
            return
        }
        var contentHash =
            (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function")
                ? nrrNativeBridge.sha256Hex(rulesJson)
                : ("client-stub-" + String(Date.now()))
        var backendKind = String(root.backendStatus ? root.backendStatus.kind || "" : "")
        if (backendKind !== "connected") {
            // Nothing can be activated while the service is down, but the
            // user's edits must not be held hostage to it: save them to their
            // rules files (which needs no service) and let the navigation
            // through. Refusing to navigate was a dead end — the same dialog
            // that offered to save was unreachable from here.
            root.setStatus(
                root.tr("status.rules-saved-service-stopped-short",
                    "Service stopped — saving to your rules file"),
                root.tr("status.rules-saved-service-stopped",
                    "The service is not running, so the rules were not applied — saving them to your rules file instead."))
            root.boundFilesController.saveRulesToFiles(true, function(ok) {
                if (ok) {
                    // Remember the work for the post-connect offer, then say
                    // plainly what did and did not happen: the file is up to
                    // date, the service is not, and "Apply" stays lit because
                    // of the second half — not because the save failed.
                    root._parkPendingApply(rulesJson, contentHash,
                        root.rulesModel ? root.rulesModel.count : 0)
                    root.setStatus(
                        root.tr("status.rules-saved-not-applied-short",
                            "Saved to your rules file — not applied yet"),
                        root.tr("status.rules-saved-not-applied",
                            "Rules saved to your rules file. The service is stopped, so they are "
                            + "not applied yet — Apply stays available until it starts."))
                }
                _resolveGuardRulesApply(ok)
            })
            return
        }
        startRulesReviewFlow(rulesJson, contentHash)
    }
    function _resolveGuardRulesApply(ok) {
        var cb = root._guardRulesResume
        root._guardRulesResume = null
        if (typeof cb === "function") cb(!!ok)
    }


    /// Entry point for sections (RulesSection's Save button). Kicks
    /// off the dry-run pass; the rpcResponse callback opens
    /// ReviewDiffDialog.
    function startRulesReviewFlow(rulesJson, contentHash, adminBaseline) {
        if (!root.bridgeAvailable) {
            console.log("review-flow: bridge unavailable, aborting")
            return
        }
        var corr = Pure.newCorrelationId()
        var payload = {
            "rules-json": String(rulesJson || ""),
            "content-hash": String(contentHash || ""),
            "correlation-id": corr
        }
        // An admin "set baseline" edit tags the inner
        // payload so the client emits the elevated `mutation-request` class
        // (broker relays the UAC) and the server commits to the shared
        // baseline instead of the caller's own per-SID partition.
        if (adminBaseline) payload["admin-baseline"] = true
        root.pendingReviewState = {
            rulesJson: payload["rules-json"],
            contentHash: payload["content-hash"],
            correlationId: corr,
            summary: null,
            confirmationToken: "",
            adminBaseline: !!adminBaseline
        }
        root._activeReviewKind = "rules-update"
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-update", payload, true /* dryRun */, ""
        )
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok) {
                console.log("review-flow: dry-run failed:", code, msg)
                // Release the guard without navigating.
                _resolveGuardRulesApply(false)
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            var token = (p && p["confirmation-token"]) || ""
            // Nothing changed vs the active
            // revision: don't open an empty review dialog, tell the user
            // plainly there's nothing to apply and release the guard.
            if (Pure.reviewSummaryIsEmpty(summary)) {
                root.showNotice(
                    root.tr("dialog.nothing-to-apply.title", "Nothing to apply"),
                    root.tr("dialog.nothing-to-apply.body",
                        "There are no changes to apply — the current rules already "
                        + "match what is active."))
                _resolveGuardRulesApply(false)
                return
            }
            root.pendingReviewState = Object.assign({}, root.pendingReviewState, {
                summary: summary,
                confirmationToken: token
            })
            root.reviewDiffDialog.summary = summary
            // A normal per-principal rules edit is
            // `user-scoped-mutation` (non-elevated): no admin banner.
            // An admin "set baseline" edit IS elevated
            // (`mutation-request`), so for that path we DO surface the
            // elevation banner (broker prompts one UAC).
            root.reviewDiffDialog.lacksElevation = adminBaseline ? !_isElevatedClient() : false
            root.reviewDiffDialog.sessionElevated = adminBaseline ? root._brokerSessionElevated : false
            // Ensure the standard review flow doesn't
            // inherit a stale `readOnly: true` from a previous preview-
            // mode open by `_openPendingApplyPreview`.
            root.reviewDiffDialog.readOnly = false
            root.reviewDiffDialog.open()
        })
    }


    /// Sidebar "Revoke admin approval" action.
    /// Retires the live elevation broker (its elevated process exits) so the
    /// next privileged change prompts UAC again, and resets the session flag
    /// (hides the control + reverts the review banner). For the admin-hands-
    /// machine-to-user case. No-op-safe when the bridge isn't wired.
    function revokeAdminApproval() {
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.rpcBrokerRevoke === "function") {
            var corr = nrrNativeBridge.rpcBrokerRevoke()
            root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
                if (!ok) console.log("broker-revoke failed:", code, msg)
            })
        }
        // The GUI no longer holds an elevated session from its POV regardless
        // of the round-trip result — reset so the next change re-prompts.
        root._brokerSessionElevated = false
        root.statusLine = root.tr("status.admin-revoked",
            "Administrator approval revoked. The next change will ask for approval again.")
    }

    function _isElevatedClient() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.isElevated !== "function") {
            return true
        }
        return !!nrrNativeBridge.isElevated()
    }

    /// Called by ConfirmActivateDialog. Submits the cached payload
    /// with the cached token; the activate response (Completed or
    /// Failed) lands on the same callback.
    // True when this GUI process runs elevated (admin).
    // Mutations (apply / clear / preset-import) require an elevated client;
    // the service rejects a non-elevated one with Forbidden. We PRE-CHECK so a
    // non-admin user gets a clear "needs administrator" prompt instead of the
    // doomed submit — which currently surfaces as a misleading "service
    // unavailable" because the Forbidden response races the connection teardown
    // in the transport layer. `isCurrentProcessElevated` is a host Q_INVOKABLE.
    function _isAppElevated() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.isElevated !== "function") {
            return true   // can't determine → don't block; let the call proceed
        }
        return !!nrrNativeBridge.isElevated()
    }
    /// Gate a mutation on elevation. **Always allows the submit now**
    /// (session elevation broker).
    ///
    /// Previously this pre-checked `isElevated()` and, for a non-admin GUI,
    /// opened `adminRequiredDialog` and ABORTED before sending — so the
    /// privileged mutation never reached the service, never got `Forbidden`,
    /// and the launcher's transparent-elevation path never ran (the user saw
    /// "needs administrator" and NO UAC prompt at all). The launcher now
    /// relays a `Forbidden` mutation through a long-lived elevated broker
    /// (one UAC per session, reused afterwards). So we MUST let the submit
    /// proceed: it reaches the service, returns `Forbidden`, and the
    /// dispatcher elevates via the broker. A declined UAC comes back as the
    /// `uac-declined` code, handled in each activation callback.
    function _guardMutationElevation() {
        return true
    }

    function _executeRulesActivation(token) {
        if (!root.bridgeAvailable) return
        if (!_guardMutationElevation()) return
        var payload = {
            "rules-json": root.pendingReviewState.rulesJson,
            "content-hash": root.pendingReviewState.contentHash,
            "correlation-id": root.pendingReviewState.correlationId
        }
        // Carry the admin-baseline flag on confirm so the
        // client emits the elevated `mutation-request` class.
        if (root.pendingReviewState.adminBaseline) payload["admin-baseline"] = true
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-update", payload, false /* dryRun */, token
        )
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok && code === "confirmation-expired") {
                // Re-issue the dry-run; the dirty flag must stay
                // set because the user hasn't successfully confirmed
                // anything yet.
                root.reviewExpiredDialog.open()
                // Release the guard (without navigating); the
                // expired dialog drives the retry from here.
                _resolveGuardRulesApply(false)
                return
            }
            if (!ok && code === "uac-declined") {
                // The user dismissed the
                // one-time UAC prompt. Nothing was applied; keep the dirty
                // flag so they can simply click Apply again to retry.
                root.statusLine = root.tr("status.activate-uac-declined",
                    "Administrator approval was cancelled — changes were not applied. " +
                    "Click Apply again to retry.")
                // Release the unsaved-changes guard (if it drove this
                // apply) without navigating; no-op for non-guard flows.
                _resolveGuardRulesApply(false)
                return
            }
            if (!ok) {
                console.log("review-flow: activate failed:", code, msg)
                // Rules now commit as a per-principal
                // `user-scoped-mutation` (non-elevated), so a `forbidden`
                // no longer means "needs administrator" — it means the
                // mutation gate is closed (e.g. an unacknowledged security
                // alert). Route every failure through
                // the generic localized error label instead of the old
                // "re-launch as Administrator" hint.
                root.statusLine = root.tr("status.rules-activate-failed",
                    "Failed to activate rules: ") +
                    ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                // Clear the dirty flag even on failure: the user has
                // completed the Save-and-review gesture and can't
                // recover from non-retryable errors (forbidden, etc.)
                // without restarting the app, so prompting them about
                // "unsaved changes" on every navigation is noise. The
                // `confirmation-expired` retry path above keeps the
                // flag set because that one IS retryable in-session.
                root.setUnsavedChanges("rules", false)
                // Release the guard without navigating on a
                // non-retryable failure (the error is shown in statusLine).
                _resolveGuardRulesApply(false)
                return
            }
            console.log("review-flow: activate completed:", JSON.stringify(p))
            if (root.pendingReviewState.adminBaseline) {
                // Admin baseline edit succeeded.
                root.statusLine = root.tr("status.baseline-activate-completed",
                    "Baseline rules updated for all users on this computer.")
                // This WAS an elevated mutation — a success while the GUI is
                // non-elevated means the broker obtained admin approval.
                if (!_isAppElevated()) root._brokerSessionElevated = true
            } else {
                root.statusLine = root.tr("status.rules-activate-completed",
                    "Rules activated.")
            }
            // A normal (per-principal) rules apply is
            // user-scoped (non-elevated): success does NOT imply the broker
            // engaged, so we do NOT flip `_brokerSessionElevated` for it
            // (only the admin-baseline branch above + genuinely elevated
            // service ops via `onBrokerSessionEstablished` do).
            // Successful submission of the
            // current rules state means the in-memory model now
            // matches what the service has. Drop the dirty flag so
            // the next navigation/close doesn't re-prompt.
            // And re-baseline so future edits compare against the
            // just-activated content (also clears the dirty flag).
            root._captureRulesDirtyBaseline()
            // Mirror the count so the "no active rules" banner clears now,
            // instead of waiting for a reconnect to re-fetch it.
            root._serviceRuleCount = root.rulesModel ? root.rulesModel.count : 0
            // Resume the pending navigation that the guard's
            // "Apply" deferred (no-op when the apply wasn't guard-driven).
            _resolveGuardRulesApply(true)
            // Rules-update activation creates a new revision.
            // Reconcile each route's dirty flag against the file on
            // disk instead of blindly marking BOTH dirty: an activation that
            // re-applies content already equal to the bound file must NOT raise the
            // "Save to file" chip. The SaveBeforeCloseDialog then prompts only on a
            // genuine divergence.
            root.boundFilesController._reconcileBoundFileDirty()
            // The linked .txt mirrors what is enforced: re-export the
            // just-activated rules so it never goes stale and the next launch's
            // auto-open is never a false-delete.
            root.boundFilesController._persistBoundFilesAfterApply()
            root._mergeApplyPendingWrite = false
            // Successful activation supersedes any
            // parked changeset. Clear sidecar so the post-connect
            // toast won't fire again on the next launch / reconnect.
            // Best-effort: log on failure but don't surface the error
            // (the activation itself already succeeded).
            if (typeof nrrNativeBridge !== "undefined"
                    && nrrNativeBridge
                    && typeof nrrNativeBridge.rpcSidecarPendingApplyClear === "function") {
                var clearCorr = nrrNativeBridge.rpcSidecarPendingApplyClear()
                root.rpc.registerRpcCallback(clearCorr, function(ok2, p2, c2, m2) {
                    if (!ok2) console.log("pending-apply.clear failed:", c2, m2)
                })
            }
            // Parked offline import (if any) has been applied — lift the guard.
            root._offlineRulesPendingPush = false
            // Same for the "changes made while the service was stopped" offer:
            // it stays open through "Preview" on purpose (a preview decides
            // nothing), so nothing took it down once the preview turned into an
            // apply — leaving the user with an offer whose "Apply all" then
            // finds no changes at all.
            if (root.offlineBacklogDialog && root.offlineBacklogDialog.opened) {
                root.offlineBacklogDialog.close()
            }
            // The just-activated rulesModel IS now
            // the service state, so refresh the service baseline
            // hash. Drops any prior GUI-vs-service drift that the
            // activation just resolved.
            root.driftController._driftCaptureServiceBaseline()
            // The service leg just moved. Re-read all three legs from their
            // real sources so the amber banner clears (or stays, honestly) at
            // once rather than on the next poll.
            Qt.callLater(root.driftController._driftRecheckNow)
        })
    }

    /// "Reset to baseline" dry-run. Discards this user's
    /// own per-SID rule customizations so the read-through resolves the
    /// shared baseline again. Two-phase like the rules apply: dry-run →
    /// review → confirm. When the user has no custom rules the dry-run
    /// reports a benign no-op and we show a notice instead of the confirm
    /// dialog. Non-elevated: the server scopes the reset to the caller's
    /// own SID, so a user can never reset the admin baseline.
    function startResetToBaselineFlow() {
        if (!root.bridgeAvailable) {
            console.log("reset-flow: bridge unavailable, aborting")
            return
        }
        var corr = Pure.newCorrelationId()
        var payload = { "correlation-id": corr }
        root.pendingReviewState = {
            rulesJson: "",
            contentHash: "",
            correlationId: corr,
            summary: null,
            confirmationToken: ""
        }
        root._activeReviewKind = "rules-reset-to-baseline"
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-reset-to-baseline", payload, true /* dryRun */, "")
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("status.reset-baseline-failed",
                    "Could not start reset to baseline: ") +
                    ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            var token = (p && p["confirmation-token"]) || ""
            // No divergence → the preview's `requires-review` is false
            // ("already on baseline"). Nothing to discard: tell the user
            // plainly, skip the confirm dialog.
            if (!summary["requires-review"]) {
                root.showNotice(
                    root.tr("dialog.reset-baseline-noop.title", "Already on baseline"),
                    root.tr("dialog.reset-baseline-noop.body",
                        "You have no custom rules — the baseline rules are already in effect."))
                return
            }
            root.pendingReviewState = Object.assign({}, root.pendingReviewState, {
                summary: summary,
                confirmationToken: token
            })
            root.reviewDiffDialog.summary = summary
            // Reset is user-scoped (non-elevated) — no admin banner.
            root.reviewDiffDialog.lacksElevation = false
            root.reviewDiffDialog.sessionElevated = false
            root.reviewDiffDialog.readOnly = false
            root.reviewDiffDialog.open()
        })
    }

    /// Confirm path for "Reset to baseline". Routed here
    /// by `reviewDiffDialog.onApproved` when `_activeReviewKind` is
    /// `rules-reset-to-baseline`. The payload is empty (reset carries no
    /// content); the service clears the caller's revisions and recompiles.
    function _executeResetToBaselineActivation(token) {
        if (!root.bridgeAvailable) return
        var payload = { "correlation-id": root.pendingReviewState.correlationId }
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-reset-to-baseline", payload, false /* dryRun */, token)
        root.rpc.registerRpcCallback(rpcCorr, function(ok, p, code, msg) {
            if (!ok && code === "confirmation-expired") {
                root.reviewExpiredDialog.open()
                return
            }
            if (!ok) {
                console.log("reset-flow: activate failed:", code, msg)
                root.statusLine = root.tr("status.reset-baseline-failed",
                    "Could not start reset to baseline: ") +
                    ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                return
            }
            console.log("reset-flow: completed:", JSON.stringify(p))
            root.statusLine = root.tr("status.reset-baseline-completed",
                "Reset to baseline rules. Reloading the active rules...")
            // The reset changed the effective rules — pull the now-active
            // (baseline) rules into the table so the user sees them.
            if (typeof root.reloadActiveRulesFromService === "function") {
                root.reloadActiveRulesFromService()
            }
        })
    }

    /// ReviewExpiredDialog → Compare again → run a fresh dry-run
    /// reusing the cached rules-json + content-hash. New
    /// correlation-id so the MutationsModel tracks the second
    /// attempt distinctly.
    function _retryReviewFlow() {
        if (root._activeReviewKind === "preset-import") {
            root.presetImportController.startPresetImportReviewFlow(
                root.pendingPresetImportState.targetRoute,
                root.pendingPresetImportState.bytesB64,
                root.pendingPresetImportState.sourcePath)
        } else if (root._activeReviewKind === "rules-reset-to-baseline") {
            startResetToBaselineFlow()
        } else {
            // Preserve the admin-baseline intent on retry.
            startRulesReviewFlow(root.pendingReviewState.rulesJson,
                                 root.pendingReviewState.contentHash,
                                 root.pendingReviewState.adminBaseline)
        }
    }


}
