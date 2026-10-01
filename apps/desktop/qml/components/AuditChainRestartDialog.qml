// Restarting the audit chain covers exactly the breaks the service listed, so
// the dialog shows them first. The confirm re-runs the dry-run with the shown
// digest: the service restarts only while its own check still yields it.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root

    /// ApplicationWindow injected by the caller (`ownerRoot: window`).
    property var ownerRoot: null
    property int breakCount: 0
    /// The first breaks from the dry-run: `{kind, file, line, seq}`.
    property var breaks: []
    property string breaksDigest: ""
    property bool busy: false
    // Once sent, a restart is seen through: leaving mid-way would hide
    // whether it happened.
    property bool confirming: false
    property string noticeText: ""
    property string errorText: ""
    // Bumped per opening, so an answer to an earlier one cannot overwrite this.
    property int _generation: 0

    readonly property string _kind: "audit-chain-restart"

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function start() {
        _generation += 1
        breakCount = 0
        breaks = []
        breaksDigest = ""
        noticeText = ""
        errorText = ""
        busy = false
        confirming = false
        open()
        _loadPreview(_generation, "")
    }

    function _bridgeReady() {
        return ownerRoot && ownerRoot.bridgeAvailable
            && typeof nrrNativeBridge !== "undefined"
            && nrrNativeBridge !== null
            && typeof nrrNativeBridge.rpcMutationSubmit === "function"
            && typeof nrrNativeBridge.rpcOperationStatusGet === "function"
    }

    function _errorLabel(code) {
        return (ownerRoot && typeof ownerRoot.ipcErrorLabel === "function")
            ? ownerRoot.ipcErrorLabel(code) : String(code || "unknown")
    }

    function _fail(code) {
        _showError(tr("diag.audit.restart.failed", "Could not restart the audit chain: ")
            + _errorLabel(code))
    }

    function _showError(text) {
        busy = false
        confirming = false
        errorText = text
        if (ownerRoot) ownerRoot.statusLine = text
    }

    function _bridgeMissing() {
        _showError(tr("status.bridge-unavailable", "Service bridge not connected."))
    }

    function _finish(statusText) {
        busy = false
        confirming = false
        close()
        if (ownerRoot) ownerRoot.statusLine = statusText
    }

    function _adopt(preview) {
        breakCount = Number(preview["break-count"] || 0)
        breaks = preview.breaks || []
        breaksDigest = String(preview["breaks-digest"] || "")
    }

    // `notice` is shown with the list once it lands; empty for a first look.
    function _loadPreview(generation, notice) {
        if (!_bridgeReady()) {
            _bridgeMissing()
            return
        }
        busy = true
        var corr = nrrNativeBridge.rpcMutationSubmit(_kind, {}, true, "")
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (generation !== root._generation) return
            if (!ok) {
                root._fail(code)
                return
            }
            var preview = p && p["audit-chain"]
            if (!preview) {
                root._fail("audit-unavailable")
                return
            }
            root._adopt(preview)
            if (root.breakCount === 0 || root.breaksDigest === "") {
                root._finish(root._errorLabel("audit-chain-intact"))
                return
            }
            root.noticeText = notice
            root.busy = false
        })
    }

    function _confirm() {
        if (!_bridgeReady()) {
            _bridgeMissing()
            return
        }
        var generation = _generation
        var shown = breaksDigest
        var payload = { "breaks-digest": shown }
        busy = true
        confirming = true
        noticeText = ""
        errorText = ""
        // The token is minted for this exact payload, and the fresh preview
        // catches a change before anything is sent.
        var corr = nrrNativeBridge.rpcMutationSubmit(_kind, payload, true, "")
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (generation !== root._generation) return
            if (!ok) {
                root._fail(code)
                return
            }
            var preview = p && p["audit-chain"]
            if (preview && Number(preview["break-count"] || 0) === 0) {
                root._finish(root._errorLabel("audit-chain-intact"))
                return
            }
            if (preview && String(preview["breaks-digest"] || "") !== shown) {
                root._adopt(preview)
                root.noticeText = root._changedText()
                root.busy = false
                root.confirming = false
                return
            }
            var token = String((p && p["confirmation-token"]) || "")
            var corr2 = nrrNativeBridge.rpcMutationSubmit(root._kind, payload, false, token)
            ownerRoot.rpc.registerRpcCallback(corr2, function(ok2, p2, code2, msg2) {
                if (generation !== root._generation) return
                if (!ok2) {
                    root._fail(code2)
                    return
                }
                ownerRoot.rpc.readMutationOutcome(p2,
                    function(done) { root._settleByPreview(generation, shown, done) },
                    function(failure) { root._onOutcome(generation, failure) })
            })
        })
    }

    function _onOutcome(generation, failure) {
        if (generation !== root._generation) return
        if (failure === "") {
            root._finish(root.tr("diag.audit.restart.completed",
                "Audit chain restarted. Checking continues from this point."))
        } else if (failure === "audit-chain-changed") {
            root.confirming = false
            root._loadPreview(generation, root._changedText())
        } else if (failure === "audit-chain-intact") {
            root._finish(root._errorLabel(failure))
        } else {
            root._fail(failure)
        }
    }

    // A record another account owns (a cross-account elevation) is not
    // readable here: judge by what the chain says now. A list that changed
    // meanwhile is shown for a new confirm rather than reported as a verdict.
    function _settleByPreview(generation, shown, done) {
        var corr = nrrNativeBridge.rpcMutationSubmit(_kind, {}, true, "")
        ownerRoot.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (generation !== root._generation) return
            if (!ok) {
                done(String(code || "unknown"))
                return
            }
            var preview = p && p["audit-chain"]
            if (!preview) {
                done("audit-unavailable")
                return
            }
            if (Number(preview["break-count"] || 0) === 0) {
                done("")
                return
            }
            root._adopt(preview)
            if (String(preview["breaks-digest"] || "") !== shown) {
                root.noticeText = root._changedText()
                root.busy = false
                root.confirming = false
                return
            }
            done("unknown")
        })
    }

    function _changedText() {
        return tr("diag.audit.restart.changed",
            "The audit trail changed while this list was open. Review the updated list and confirm again.")
    }

    function _rowText(row) {
        var slug = String(row.kind || "")
        var kind = tr("diag.audit.break-kind." + slug, slug)
        var line = Number(row.line || 0)
        if (line > 0) {
            return tr("diag.audit.restart.row-line", "{file}, line {line}: {kind}")
                .replace("{file}", String(row.file || ""))
                .replace("{line}", String(line))
                .replace("{kind}", kind)
        }
        return tr("diag.audit.restart.row-file", "{file}: {kind}")
            .replace("{file}", String(row.file || ""))
            .replace("{kind}", kind)
    }

    title: tr("diag.audit.restart.title", "Restart audit chain")
    modal: true
    popupType: Popup.Item
    anchors.centerIn: Overlay.overlay
    width: Math.min(560, Overlay.overlay ? Overlay.overlay.width - 32 : 560)
    standardButtons: Dialog.NoButton
    closePolicy: confirming ? Popup.NoAutoClose : Popup.CloseOnEscape
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    onOpened: cancelButton.forceActiveFocus()
    onClosed: _generation += 1

    contentItem: ColumnLayout {
        spacing: 12
        RowLayout {
            Layout.fillWidth: true
            visible: root.busy && root.breakCount === 0
            spacing: 8
            BusyIndicator {
                running: parent.visible
                implicitWidth: 24
                implicitHeight: 24
            }
            Label {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.Wrap
                color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
                text: root.tr("diag.audit.restart.loading", "Checking the audit trail…")
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: root.breakCount > 0
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("diag.audit.restart.summary",
                "The audit trail does not verify in {count} place(s):")
                .replace("{count}", String(root.breakCount))
        }
        ListView {
            id: breakList
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(contentHeight, 220)
            visible: root.breaks.length > 0
            clip: true
            model: root.breaks
            spacing: 4
            activeFocusOnTab: true
            keyNavigationEnabled: true
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
            Accessible.role: Accessible.List
            Accessible.name: root.tr("diag.audit.restart.list-name", "Audit chain breaks")
            highlightFollowsCurrentItem: true
            highlight: Rectangle {
                visible: breakList.activeFocus
                color: "transparent"
                border.width: 2
                border.color: root.ownerRoot ? root.ownerRoot.uiTheme.colorFocusRing : palette.highlight
                radius: 2
            }
            delegate: Label {
                required property var modelData
                width: breakList.width
                padding: 4
                wrapMode: Text.WrapAnywhere
                text: root._rowText(modelData)
                color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
                Accessible.role: Accessible.ListItem
                Accessible.name: text
            }
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: root.breakCount > root.breaks.length && root.breaks.length > 0
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : palette.text
            text: root.tr("diag.audit.restart.list-truncated", "Only the first {shown} are listed.")
                .replace("{shown}", String(root.breaks.length))
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: root.breakCount > 0
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            text: root.tr("diag.audit.restart.explain",
                "Confirming does not erase these breaks: they stay recorded in the audit trail, and checking continues from this point. A new break will be reported again.")
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: text !== ""
            wrapMode: Text.Wrap
            font.bold: true
            color: root.ownerRoot ? root.ownerRoot.uiTheme.colorAccent : palette.text
            text: root.noticeText
        }
        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            visible: text !== ""
            wrapMode: Text.Wrap
            color: root.ownerRoot ? root.ownerRoot.uiTheme.colorAccent : palette.text
            text: root.errorText
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            BusyIndicator {
                visible: root.busy && root.breakCount > 0
                running: visible
                implicitWidth: 24
                implicitHeight: 24
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                id: cancelButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("action.cancel", "Cancel")
                enabled: !root.confirming
                onClicked: root.close()
            }
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.tr("diag.audit.restart.confirm", "Restart chain")
                highlighted: true
                enabled: !root.busy && root.breakCount > 0 && root.breaksDigest !== ""
                onClicked: root._confirm()
            }
        }
    }
}
