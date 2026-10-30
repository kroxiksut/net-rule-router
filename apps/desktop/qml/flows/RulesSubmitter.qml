import QtQuick 2.15
import "../lib/pure.js" as Pure

// The window-independent half of applying a rules table: the `rules-update`
// dry-run, its confirm, and the read of the confirm's verdict. No dialogs and
// no status line — callers own those. The main window's review flow drives
// `dryRun` and `commit` around its review dialog; a surface without one (the
// tray adding a rule) uses `applyNow`.
QtObject {
    id: submitter

    /// RpcTransport instance.
    property var rpc: null

    /// The `base-revision` of the rules list the table was built from, or
    /// null when none was read. Sent with every write: the service refuses one
    /// built from rules that have changed since (`rules-changed-elsewhere`)
    /// rather than undoing that change.
    property var baseRevision: null

    /// A write landed and its answer named the rules now in force (`base`,
    /// null when it did not say): the owner builds the next write on it.
    signal baseRevisionMoved(var base)

    readonly property bool bridgeReady: typeof nrrNativeBridge !== "undefined"
        && nrrNativeBridge !== null
        && typeof nrrNativeBridge.rpcMutationSubmit === "function"

    /// The `content-hash` a rules payload is submitted with. A stub without
    /// the bridge: a mismatch only degrades the service's idempotency dedup.
    function contentHash(rulesJson) {
        return (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.sha256Hex === "function")
            ? nrrNativeBridge.sha256Hex(rulesJson)
            : ("client-stub-" + String(Date.now()))
    }

    /// Preview `rulesJson`. `opts`: `{ origin, adminBaseline, contentHash,
    /// baseRevision }` (the last defaults to `baseRevision` above);
    /// `origin` travels on the wire in the correlation id, so a duplicate in
    /// the service log names its caller. Returns the request `state`
    /// (`{rulesJson, contentHash, correlationId, adminBaseline}`) once sent, or
    /// null when nothing was sent — `done` is then never called.
    /// `done(ok, r)`, r = `{ state, summary, token, refusal, empty, code,
    /// message }`.
    function dryRun(rulesJson, opts, done) {
        if (!bridgeReady || !rpc) return null
        var o = opts || {}
        var corr = Pure.newCorrelationId(String(o.origin || "review-save"))
        var payload = {
            "rules-json": String(rulesJson || ""),
            "content-hash": String(o.contentHash || ""),
            "correlation-id": corr
        }
        // An admin "set baseline" edit is sent as the elevated
        // `mutation-request` class (the broker relays the UAC) and lands in the
        // shared baseline instead of the caller's own partition.
        if (o.adminBaseline) payload["admin-baseline"] = true
        // "Set baseline" copies the table over the baseline on purpose: the
        // table's base names the caller's own rules, not the baseline's.
        var base = (o.baseRevision !== undefined) ? o.baseRevision : submitter.baseRevision
        if (!o.adminBaseline && base !== null && base !== undefined) {
            payload["base-revision"] = String(base)
        }
        var state = {
            rulesJson: payload["rules-json"],
            contentHash: payload["content-hash"],
            correlationId: corr,
            adminBaseline: !!o.adminBaseline,
            baseRevision: (payload["base-revision"] !== undefined) ? payload["base-revision"] : null
        }
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-update", payload, true /* dryRun */, "")
        if (!rpcCorr || String(rpcCorr) === "") return null
        rpc.registerLongRpcCallback(rpcCorr, function(ok, p, code, msg) {
            var r = { state: state, summary: null, token: "", refusal: null, empty: false,
                      code: String(code || ""), message: String(msg || "") }
            if (!ok) {
                done(false, r)
                return
            }
            var summary = (p && p["review-summary"]) || p || {}
            r.summary = summary
            r.token = (p && p["confirmation-token"]) || ""
            // A refused preview has an empty diff: asked first, or it reads as
            // "nothing to apply".
            r.refusal = Pure.previewRefusal(summary)
            r.empty = !r.refusal && Pure.reviewSummaryIsEmpty(summary)
            done(true, r)
        })
        return state
    }

    /// Confirm a previewed `state` with its confirmation `token`. Returns false
    /// when nothing was sent — `done` is then never called. `done(ok, r)` with
    /// r = `{ payload, code, message, failure, failureArgs }`: `ok` only once
    /// the operation record says the change took effect. `code` is set when the
    /// confirm itself was refused, `failure` (with its own values in
    /// `failureArgs`) when the operation failed afterwards.
    function commit(state, token, done) {
        if (!bridgeReady || !rpc) return false
        var st = state || {}
        var r = { payload: null, code: "", message: "", failure: "", failureArgs: null }
        var payload = {
            "rules-json": st.rulesJson,
            "content-hash": st.contentHash,
            "correlation-id": st.correlationId
        }
        if (st.adminBaseline) payload["admin-baseline"] = true
        // The confirm must carry the previewed payload as it was.
        if (st.baseRevision !== null && st.baseRevision !== undefined) {
            payload["base-revision"] = String(st.baseRevision)
        }
        var rpcCorr = nrrNativeBridge.rpcMutationSubmit(
            "rules-update", payload, false /* dryRun */, token)
        if (!rpcCorr || String(rpcCorr) === "") return false
        rpc.registerLongRpcCallback(rpcCorr, function(ok, p, code, msg) {
            r.payload = p || null
            if (!ok) {
                r.code = String(code || "unknown")
                r.message = String(msg || "")
                done(false, r)
                return
            }
            // The confirm only accepts the change; its verdict is on the
            // operation record.
            rpc.readMutationOutcome(p, rpc.settleByPreview("rules-update", payload),
                function(failure, failureArgs, result) {
                    if (failure === "") {
                        var moved = (result && result["base-revision"] !== undefined)
                            ? String(result["base-revision"]) : null
                        submitter.baseRevisionMoved(moved)
                        done(true, r)
                        return
                    }
                    r.failure = String(failure || "unknown")
                    r.failureArgs = failureArgs || null
                    done(false, r)
                })
        })
        return true
    }

    /// Preview and confirm in one go, with no review dialog. `expect`
    /// (`{added, removed, changed}` rule counts, or null) is the safety net of
    /// a caller that changes one rule: a preview whose diff is anything else
    /// means the table it built from is not what the service holds, and
    /// committing it would silently rewrite other rules — so it is not
    /// committed. `done(ok, r)`, r = `{ reason, summary, refusal, code,
    /// message, failure, failureArgs, payload, state }`; `reason` on failure is
    /// "bridge", "in-flight", "refused", "empty", "unexpected-diff" or
    /// "failed" (the call itself failed: `code` / `failure` say how). `state`
    /// is the committed request (as `dryRun` returns it), null before that.
    function applyNow(rulesJson, origin, expect, done) {
        var finish = function(ok, fields) {
            var r = { reason: "", summary: null, refusal: null, code: "", message: "",
                      failure: "", failureArgs: null, payload: null, state: null }
            for (var k in fields) r[k] = fields[k]
            if (typeof done === "function") done(!!ok, r)
        }
        if (!bridgeReady || !rpc) {
            finish(false, { reason: "bridge" })
            return
        }
        // One rules call at a time: a second preview queues behind the first
        // on the client's single in-flight slot.
        if (rpc.longCallInFlight) {
            finish(false, { reason: "in-flight" })
            return
        }
        var sent = dryRun(rulesJson,
            { origin: origin, adminBaseline: false, contentHash: contentHash(rulesJson) },
            function(ok, d) {
                if (!ok) {
                    finish(false, { reason: "failed", code: d.code, message: d.message })
                    return
                }
                if (d.refusal) {
                    finish(false, { reason: "refused", summary: d.summary, refusal: d.refusal })
                    return
                }
                if (d.empty) {
                    finish(false, { reason: "empty", summary: d.summary })
                    return
                }
                if (expect && !_countsMatch(Pure.reviewSummaryRuleCounts(d.summary), expect)) {
                    console.log("rules-submit: preview diff is not the expected one, not applying",
                        JSON.stringify(Pure.reviewSummaryRuleCounts(d.summary)), JSON.stringify(expect))
                    finish(false, { reason: "unexpected-diff", summary: d.summary })
                    return
                }
                var committing = commit(d.state, d.token, function(cok, c) {
                    finish(cok, {
                        reason: cok ? "" : "failed",
                        state: d.state,
                        summary: d.summary,
                        code: c.code,
                        message: c.message,
                        failure: c.failure,
                        failureArgs: c.failureArgs,
                        payload: c.payload
                    })
                })
                if (!committing) finish(false, { reason: "bridge", summary: d.summary })
            })
        if (sent === null) finish(false, { reason: "bridge" })
    }

    function _countsMatch(actual, expect) {
        return actual.added === Number(expect.added || 0)
            && actual.removed === Number(expect.removed || 0)
            && actual.changed === Number(expect.changed || 0)
    }

    /// The user-facing sentence for a failed result of `dryRun`, `commit` or
    /// `applyNow`, in the words the main window uses. `tr(key, fallback)` is
    /// the caller's locale lookup.
    function describeFailure(r, tr) {
        var res = r || {}
        var prefix = tr("status.rules-activate-failed", "Failed to activate rules: ")
        if (res.refusal) return prefix + Pure.previewRefusalText(res.refusal, tr)
        switch (String(res.reason || "")) {
        case "bridge":
            return tr("status.bridge-unavailable", "Service bridge not connected.")
        case "in-flight":
            return tr("mutations.in-progress-tooltip",
                "Another operation is in progress. Wait for it to finish.")
        case "empty":
            return tr("dialog.nothing-to-apply.body",
                "Nothing to apply: the rules on screen are already in use.")
        case "unexpected-diff":
            return tr("status.rules-apply-unexpected-diff",
                "Not applied: the change would also affect other rules. "
                + "Open the rules in the main window to review it.")
        }
        var failure = String(res.failure || "")
        if (failure === "" && String(res.code || "") === "uac-declined") {
            return tr("status.activate-uac-declined",
                "Administrator approval was cancelled — changes were not applied. " +
                "Click Apply again to retry.")
        }
        // A refusal of the confirm itself carries no outcome values.
        var code = failure !== "" ? failure : String(res.code || "")
        var args = failure !== "" ? (res.failureArgs || null) : null
        return prefix + Pure.ipcErrorLabel(String(code || "unknown"), args, tr)
    }
}
