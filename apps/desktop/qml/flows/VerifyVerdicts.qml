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
    /// `done(ok, errorCode)`.
    function accept(done) { _answer("rpcVerifyVerdictsAccept", done) }

    /// Leave every waiting rule as written: the move lasts until the next
    /// restart and the check repeats after it. `done(ok, errorCode)`.
    function dismiss(done) { _answer("rpcVerifyVerdictsDismiss", done) }

    function _answer(method, done) {
        var reply = typeof done === "function" ? done : function() {}
        var waiting = notice
        if (!waiting || !rpc || typeof rpc[method] !== "function") {
            reply(false, "")
            return
        }
        var corr = rpc[method]({ "rule-ids": waiting.ids })
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
