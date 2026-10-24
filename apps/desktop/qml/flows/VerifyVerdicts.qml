import QtQuick 2.15
import "../lib/pure.js" as Pure

// The user's `?` rules that do not get through where they are written but do
// on the other route. The service holds the list and announces every change
// with `verify-verdicts-changed`, so the window and the tray agree without a
// ledger: an answer given on one surface empties the list for both.
QtObject {
    id: verdicts

    /// RpcTransport instance.
    property var rpc: null

    /// The last list the service sent, set-aside ones included.
    property var list: []

    /// `Pure.verifyVerdictNotice` of the list: null while nothing waits.
    readonly property var notice: Pure.verifyVerdictNotice(list)

    property bool _fetching: false
    property bool _fetchAgain: false

    function refresh() {
        if (!rpc || typeof rpc.rpcVerifyVerdictsList !== "function") return
        if (_fetching) { _fetchAgain = true; return }
        var corr = rpc.rpcVerifyVerdictsList()
        if (!corr) return
        _fetching = true
        rpc.registerRpcCallback(corr, function(ok, p) {
            verdicts._fetching = false
            if (ok && p) verdicts.list = p.verdicts || []
            if (verdicts._fetchAgain) {
                verdicts._fetchAgain = false
                verdicts.refresh()
            }
        })
    }

    /// Move every waiting rule to the route where it works.
    /// `done(ok, errorCode)`. `ids`: only these, the set the user was shown;
    /// a verdict that arrived after it must not ride along unseen.
    function accept(done, ids) { _answer("rpcVerifyVerdictsAccept", done, ids) }

    /// Leave every waiting rule as written: the move lasts until the next
    /// restart and the check repeats after it. `done(ok, errorCode)`, `ids` as
    /// for `accept`.
    function dismiss(done, ids) { _answer("rpcVerifyVerdictsDismiss", done, ids) }

    function _answer(method, done, ids) {
        var reply = typeof done === "function" ? done : function() {}
        var waiting = notice
        var asked = (ids !== undefined && ids !== null)
            ? Array.prototype.slice.call(ids) : (waiting ? waiting.ids : [])
        if (!waiting || asked.length === 0 || !rpc || typeof rpc[method] !== "function") {
            reply(false, "")
            return
        }
        var corr = rpc[method]({ "rule-ids": asked })
        if (!corr) {
            reply(false, "transport-disconnected")
            return
        }
        rpc.registerRpcCallback(corr, function(ok, p, code) {
            verdicts.refresh()
            reply(ok, ok ? "" : String(code || ""))
        })
    }
}
