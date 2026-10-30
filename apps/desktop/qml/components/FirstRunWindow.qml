import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import QtQuick.Dialogs
import "../lib/pure.js" as Pure

// First-run wizard, one question per page in the terminal setup's order:
// main connection, additional connection, starting rules, protection and
// options, review. Opens once when `!prefs.firstRunCompleted`; every way out
// marks the flag so it never reappears. The protection is written when the
// review page is reached and on every way out, before the starting rules go:
// rules never run without the protection chosen with them.
// The window keeps its `firstRunWindow` id so Main.qml's wiring (property
// alias, overlays/children arrays, openChildWindow, and licenseWindow's
// transient-parent reference) is unchanged. Shared state comes in through
// `root` (the ApplicationWindow), including the sibling `root.licenseWindow`.
Window {
    id: firstRunWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    // The size wanted; `_fitOnScreen` shrinks it to the free part of the
    // screen, so the bar under the pages never sits under the taskbar.
    readonly property int _wantWidth: 640
    readonly property int _wantHeight: 640
    width: _wantWidth
    height: _wantHeight
    visible: false
    modality: Qt.WindowModal
    color: root.panelColor
    title: root.tr("dialog.first-run-wizard.title", "Welcome to NetRuleRouter")
    transientParent: root
    flags: Qt.Dialog

    // Detected country code (lowercase ISO-3166, e.g. "ru") and
    // the first available preset pack name under presets/<cc>/.
    // Both empty when no bundled pack is found for this locale.
    property string detectedCountry: ""
    property string detectedCountryPack: ""
    // Language half of the same locale ("ru_RU" -> "ru"). The home/abroad
    // question only makes sense to someone who reads that country's language:
    // an English-language install that happens to sit in the region is not an
    // emigrant deciding between two packs.
    property string detectedLanguage: ""

    // Mirror pack for the same country under presets/abroad/ — for someone who
    // lives elsewhere but still needs that country's services. The system region
    // cannot tell the two apart (an emigrant keeps their language), so the
    // wizard asks instead of guessing. Empty when no such pack is bundled.
    property string detectedAbroadPack: ""
    property bool livingAbroad: false

    readonly property bool locationQuestionRelevant:
        detectedLanguage !== "" && detectedLanguage === detectedCountry

    readonly property bool hasHomePack: detectedCountryPack !== ""
    readonly property bool hasAbroadPack: detectedAbroadPack !== ""
    readonly property bool hasAnyCountryPack: hasHomePack || hasAbroadPack
    // The single available pack wins when only one of the two is bundled.
    readonly property bool useAbroadPack: hasAbroadPack && (livingAbroad || !hasHomePack)

    // Two-file "Open my rules…" picker state. Either path may be
    // empty — the user can choose to import just one route. Both
    // non-empty → both-routes review flow; exactly one → single-route.
    property string pickedPrimaryPath: ""
    property string pickedSecondaryPath: ""

    // Protection defaults offered here rather than left for the user to find in
    // Settings — leak protection and name-level enforcement only help if they
    // are on before the first rule applies. Diagnostics stay off: they are for
    // reporting a problem, not for everyday use.
    // Leak protection level offered by default: what the rules route never
    // leaks, and the rest of the internet keeps working. A partial answer
    // sheet from the installer starts the choices from its answers, as the
    // terminal setup does; the user still confirms them.
    readonly property var _sheet: root.startupController
            && root.startupController.provisioning
            && root.startupController.provisioning.present === true
        ? root.startupController.provisioning : null
    property string wantLeakProtection: _sheet && String(_sheet.leakProtection || "") !== ""
        ? Pure.routePolicyCoerce("leak-protection", _sheet.leakProtection) : "sites"
    // The default route the level is offered under, as the service holds it or
    // the install-time choices start it; the wizard does not ask it.
    readonly property string defaultRoute: root.uiRevision >= 0
        ? String(root._serviceDefaultRoute || root.prefs.routeBehaviorMode || "") : ""
    // No level below what the administrator set for a first save is offered.
    readonly property string leakFloor: root.uiRevision >= 0
        ? String(root._serviceLeakFloor || "off") : "off"
    readonly property var leakLevelsOffered:
        Pure.leakProtectionChoicesAtLeast(defaultRoute, leakFloor)
    readonly property string leakProtectionChoice:
        Pure.raiseLeakProtection(defaultRoute, wantLeakProtection, leakFloor)
    // "Everything" while the additional connection is not available stops the
    // internet as soon as it applies; said under the choice.
    readonly property bool leakHoldsNow: root.uiRevision >= 0
        && Pure.leakProtectionHoldsNow(leakProtectionChoice,
            root.interfacesRolesController
                && typeof root.interfacesRolesController.boundSecondaryRow === "function"
                ? root.interfacesRolesController.boundSecondaryRow() : null)
    property bool wantDohLockdown: _sheet && typeof _sheet.dohLockdown === "boolean"
        ? _sheet.dohLockdown : true
    property bool wantFakeIp: true
    property bool wantDiagnosticLogs: false
    // Duration of the log windows `wantDiagnosticLogs` opens (verbose logging
    // and the connection trace on disk) — one of `Pure.LOG_WINDOW_CHANGES`
    // minus "off" (the checkbox is the on/off control).
    property string diagnosticLogsDuration: "four-hours"
    property bool wantBlockNoticesMuted: false
    // Without it a restart leaves no icon and no notices: the routing runs,
    // and nothing on screen says so.
    property bool wantTrayAutostart: true

    // Which adapter currently holds the primary role, read back from the same
    // model the Interfaces screen edits — so assigning it here and assigning it
    // there are the same act, not two code paths that can disagree.
    readonly property int assignedPrimaryIndex: root.uiRevision >= 0
            && root.interfacesRolesController
            && typeof root.interfacesRolesController.adapterIndexHoldingRole === "function"
        ? root.interfacesRolesController.adapterIndexHoldingRole("primary")
        : -1
    readonly property bool primaryAssigned: assignedPrimaryIndex >= 0
    readonly property string assignedPrimaryName: primaryAssigned
        ? String(root.interfacesModel.get(assignedPrimaryIndex).name || "")
        : ""

    // Same read-back for the additional adapter. Asking for it here is what
    // keeps the service from sitting policy-less for a whole session: until
    // some screen sends a binding, nothing is enforced and nothing is blocked.
    readonly property int assignedSecondaryIndex: root.uiRevision >= 0
            && root.interfacesRolesController
            && typeof root.interfacesRolesController.adapterIndexHoldingRole === "function"
        ? root.interfacesRolesController.adapterIndexHoldingRole("secondary")
        : -1
    readonly property bool secondaryAssigned: assignedSecondaryIndex >= 0
    readonly property string assignedSecondaryName: secondaryAssigned
        ? String(root.interfacesModel.get(assignedSecondaryIndex).name || "")
        : ""
    /// "I will choose it later" — the wizard stops asking, the Interfaces
    /// screen and the banner keep the question alive.
    property bool secondaryDeferred: false
    // The bound additional adapter is not up yet (a VPN before it connects).
    readonly property bool secondaryAssignedDown: secondaryAssigned && root.uiRevision >= 0
        && String(root.interfacesModel.get(assignedSecondaryIndex).availability || "") !== "available"

    // The adapter picked in each list, by id (name when it has none). The list
    // is rebuilt on every adapter change, which resets a combo's index; the
    // pick survives it, and closing the window commits a pick the "Set as"
    // button was not pressed for.
    property string pickedPrimaryKey: ""
    property string pickedSecondaryKey: ""

    function _rowKey(row) {
        if (!row) return ""
        var id = String(row.persistentId || "")
        return id !== "" ? id : String(row.name || "")
    }

    function _modelRows() {
        var rows = []
        for (var i = 0; i < root.interfacesModel.count; i += 1) rows.push(root.interfacesModel.get(i))
        return rows
    }

    function _modelIndexOfKey(key) {
        if (key === "") return -1
        for (var i = 0; i < root.interfacesModel.count; i += 1)
            if (_rowKey(root.interfacesModel.get(i)) === key) return i
        return -1
    }

    // The pickers list connected adapters only: a machine with a dozen idle
    // VPN adapters otherwise buries its one live link. The pick stays listed;
    // the other route's pick is not offered, one adapter never carries both.
    property bool showAllAdapters: false
    function _shownInPicker(item, role) {
        var own = role === "primary" ? pickedPrimaryKey : pickedSecondaryKey
        var other = role === "primary" ? pickedSecondaryKey : pickedPrimaryKey
        var key = _rowKey(item)
        if (other !== "" && key === other) return false
        return Pure.adapterPassesFilter(item, showAllAdapters, "")
            || (own !== "" && key === own)
            || (role === "secondary" && _idleVpnProgram(item) !== null)
    }

    /// The found VPN's adapters that are down: listed on the additional step
    /// without "Show unavailable adapters", as the VPN is only not started.
    function _idleVpnOffer() {
        return Pure.firstRunIdleVpns(_modelRows(), _vpnPrograms, _modelIndexOfKey(pickedPrimaryKey))
    }

    /// Asks to turn the VPN on when several down adapters, of any driver, may
    /// be its: which one it takes shows only once it is on.
    function _startVpnFirstHint() {
        var programs = _idleVpnOffer().startVpnFirst
        if (programs.length === 0) return ""
        return programs.length === 1 && programs[0] !== ""
            ? root.tr("dialog.first-run-wizard.secondary-adapter-start-vpn-first-program",
                "{program} may use any of several connections on this computer, and while the VPN is off there is no telling which one. Turn the VPN on — the wizard will see it and pick it.")
                .replace("{program}", Pure.displayText(programs[0]))
            : root.tr("dialog.first-run-wizard.secondary-adapter-start-vpn-first",
                "Your VPN may use any of several connections on this computer, and while it is off there is no telling which one. Turn the VPN on — the wizard will see it and pick it.")
    }

    /// A connection that is down while other copies of its driver sit on the
    /// machine is not set from this step: the VPN takes whichever copy it
    /// likes, and the warning above the list says so.
    function _pooledDown(index) {
        if (index < 0 || index >= root.interfacesModel.count) return false
        var row = root.interfacesModel.get(index)
        if (String(row.availability || "") === "available") return false
        var siblings = Pure.adapterDriverSiblings(_modelRows(), index, "secondary")
        return siblings.live.length + siblings.idle > 0
    }

    /// The program an offered down VPN adapter belongs to ("" when unsure),
    /// null for an adapter not offered so.
    function _idleVpnProgram(item) {
        var key = _rowKey(item)
        if (key === "") return null
        var offer = _idleVpnOffer()
        for (var i = 0; i < offer.rows.length; i += 1) {
            if (_rowKey(root.interfacesModel.get(offer.rows[i].index)) === key)
                return offer.rows[i].program
        }
        return null
    }

    /// The pick for `role`; the other route loses a pick of the same adapter.
    function _pick(role, key) {
        if (role === "primary") {
            pickedPrimaryKey = key
            if (pickedSecondaryKey === key) pickedSecondaryKey = ""
        } else {
            pickedSecondaryKey = key
            if (pickedPrimaryKey === key) pickedPrimaryKey = ""
        }
    }

    // An answered connection page shows its answer and "Change", which brings
    // the list back with the answer picked; going Back never locks a choice.
    property bool changingPrimary: false
    property bool changingSecondary: false
    readonly property bool choosingPrimary: !primaryAssigned || changingPrimary
    readonly property bool choosingSecondary:
        (!secondaryAssigned && !secondaryDeferred) || changingSecondary

    function _changeChoice(role) {
        if (role === "primary") {
            changingPrimary = true
            if (assignedPrimaryIndex >= 0)
                _pick("primary", _rowKey(root.interfacesModel.get(assignedPrimaryIndex)))
        } else {
            changingSecondary = true
            secondaryDeferred = false
            if (assignedSecondaryIndex >= 0)
                _pick("secondary", _rowKey(root.interfacesModel.get(assignedSecondaryIndex)))
        }
        Qt.callLater(_focusStep)
    }

    function _keepChoice(role) {
        if (role === "primary") changingPrimary = false
        else changingSecondary = false
        Qt.callLater(_focusStep)
    }

    // The adapter a "Set as" press asked for, until the role lands on it: the
    // controller may ask a question first, and a declined one leaves the page.
    property string _awaitPrimaryKey: ""
    property string _awaitSecondaryKey: ""

    /// "Set as main" answers its page and the window goes on; "Set as
    /// additional" stays, so another VPN can still be set up there.
    function _assignFromPage(role, index) {
        var ctl = root.interfacesRolesController
        if (!ctl || typeof ctl.assignRole !== "function"
                || index < 0 || index >= root.interfacesModel.count) return
        var key = _rowKey(root.interfacesModel.get(index))
        _pick(role, key)
        if (role === "primary") _awaitPrimaryKey = key
        else _awaitSecondaryKey = key
        ctl.assignRole(index, role)
        _afterAssign()
    }

    function _afterAssign() {
        var landed = function(held, key) {
            return key !== "" && held >= 0 && _rowKey(root.interfacesModel.get(held)) === key
        }
        if (landed(assignedSecondaryIndex, _awaitSecondaryKey)) {
            _awaitSecondaryKey = ""
            changingSecondary = false
        }
        if (landed(assignedPrimaryIndex, _awaitPrimaryKey)) {
            _awaitPrimaryKey = ""
            changingPrimary = false
            if (step === 0) step = 1
        }
    }

    // While the additional connection is asked, a link that comes up is most
    // likely the VPN the user has just started: it is named and offered in one
    // press. `_adaptersSeen` is the last look, kept across pages.
    property var _adaptersSeen: null
    property string justConnectedKey: ""

    function _watchAdapters() {
        if (!visible || step !== 1 || !root.interfacesAreLive) return
        var rows = _modelRows()
        if (_adaptersSeen !== null) {
            var i = Pure.firstRunJustConnected(_adaptersSeen, rows, _modelIndexOfKey(pickedPrimaryKey))
            if (i >= 0 && _rowKey(rows[i]) !== justConnectedKey) {
                justConnectedKey = _rowKey(rows[i])
                if (pickedSecondaryKey === "") _pick("secondary", justConnectedKey)
                // Which program it is: the scan says which ones run now.
                _scanInstalledVpns()
            }
        }
        var j = _modelIndexOfKey(justConnectedKey)
        if (justConnectedKey !== "" && (j < 0
                || String(rows[j].availability || "") !== "available"
                || String(rows[j].selectedRole || "") !== ""))
            justConnectedKey = ""
        _adaptersSeen = rows.map(function(row) {
            return { persistentId: String(row.persistentId || ""), name: String(row.name || ""),
                availability: String(row.availability || "") }
        })
    }

    function _pickIsIdleVpn() {
        var i = _modelIndexOfKey(pickedSecondaryKey)
        return i >= 0 && _idleVpnProgram(root.interfacesModel.get(i)) !== null
    }

    function _assignJustConnected() {
        _assignFromPage("secondary", _modelIndexOfKey(justConnectedKey))
    }

    // The one connected adapter that fits a role is picked for the user, who
    // still sees it and can change it; two candidates stay the user's call.
    // Only while the role's page is on screen: a way out commits the pick,
    // and one the user never saw must not become a binding.
    function _suggestPicks() {
        if (!visible || !root.interfacesAreLive) return
        var rows = _modelRows()
        if (step === 0 && !primaryAssigned && pickedPrimaryKey === "") {
            var p = Pure.firstRunSuggestion(rows, "primary", _modelIndexOfKey(pickedSecondaryKey))
            if (p >= 0) pickedPrimaryKey = _rowKey(rows[p])
        }
        if (step === 1 && !secondaryAssigned && !secondaryDeferred && pickedSecondaryKey === "") {
            var s = Pure.firstRunSuggestion(rows, "secondary", _modelIndexOfKey(pickedPrimaryKey))
            // A connected VPN first, else the found VPN's adapter that is down.
            if (s < 0) s = _idleVpnOffer().preselect
            if (s >= 0) pickedSecondaryKey = _rowKey(rows[s])
        }
    }
    Connections {
        target: root
        function onUiRevisionChanged() {
            firstRunWindow._afterAssign()
            firstRunWindow._watchAdapters()
            firstRunWindow._suggestPicks()
        }
    }

    // A VPN started while its page is shown must show up without a press on
    // Refresh: the list is probed every 2 s on that page only, and re-read
    // only when an adapter appeared, left, or went up or down.
    property string _adapterPrint: ""
    Timer {
        interval: 2000
        repeat: true
        running: firstRunWindow.visible && firstRunWindow.step === 1
            && firstRunWindow.choosingSecondary
        onTriggered: firstRunWindow._probeAdapters()
    }
    function _probeAdapters() {
        var ctl = root.interfacesRolesController
        if (!root.bridgeAvailable || typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSnapshotInterfacesGet !== "function"
                || !ctl || typeof ctl.refreshInterfacesFromService !== "function") return
        var corr = nrrNativeBridge.rpcSnapshotInterfacesGet()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            var print = (payload.rows || []).map(function(w) {
                return String(w["persistent-id"] || w.name || "") + "=" + String(w.availability || "")
            }).join("|")
            if (print === _adapterPrint) return
            _adapterPrint = print
            ctl.refreshInterfacesFromService()
        })
    }

    // VPN programs installed on this machine, named in the hint while no VPN
    // connection is up: "start it first" is easier to act on with a name.
    property var installedVpnNames: []
    property var _vpnPrograms: []
    function _scanInstalledVpns() {
        if (!root.rpc || typeof root.rpc.rpcVpnDiscover !== "function"
                || typeof root.rpc.registerRpcCallback !== "function") return
        var corr = root.rpc.rpcVpnDiscover()
        if (!corr) return
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            if (!ok || !payload) return
            var names = []
            var rows = Pure.vpnDiscoveredRows(payload.candidates || [])
            for (var i = 0; i < rows.length && names.length < 3; i += 1) {
                var n = Pure.displayText(rows[i].displayName || _basename(rows[i].exePath))
                if (n !== "" && names.indexOf(n) < 0) names.push(n)
            }
            installedVpnNames = names
            _vpnPrograms = rows
            _suggestPicks()
        })
    }

    /// The VPN program behind the connection that just came up: the running
    /// one that names it, else the only one running; "" when unsure.
    function _justConnectedProgram(adapterName) {
        var running = _vpnPrograms.filter(function(p) { return p.running === true })
        var named = running.filter(function(p) {
            return p.interfaceName !== "" && p.interfaceName === adapterName
        })
        var pick = named.length > 0 ? named[0] : (running.length === 1 ? running[0] : null)
        return pick ? Pure.displayText(pick.displayName || _basename(pick.exePath)) : ""
    }

    function _justConnectedHint() {
        var i = _modelIndexOfKey(justConnectedKey)
        if (i < 0) return ""
        var name = String(root.interfacesModel.get(i).name || "")
        var program = _justConnectedProgram(name)
        return (program !== ""
            ? root.tr("dialog.first-run-wizard.secondary-adapter-just-connected-program",
                "Just connected: {name} — probably your VPN ({program}).")
            : root.tr("dialog.first-run-wizard.secondary-adapter-just-connected",
                "Just connected: {name} — probably your VPN."))
            .replace("{name}", Pure.adapterDisplayName(root.interfacesModel.get(i)))
            .replace("{program}", program)
    }

    function _commitPendingPicks() {
        if (!root.interfacesAreLive || !root.interfacesRolesController
                || typeof root.interfacesRolesController.assignRole !== "function") return
        var primary = Pure.firstRunPickToCommit(_modelRows(), "primary", pickedPrimaryKey)
        if (primary >= 0) root.interfacesRolesController.assignRole(primary, "primary")
        if (secondaryDeferred) return
        var secondary = Pure.firstRunPickToCommit(_modelRows(), "secondary", pickedSecondaryKey)
        if (secondary >= 0) root.interfacesRolesController.assignRole(secondary, "secondary")
    }

    // The protection goes when the review page is reached and again on the
    // way out, only if it changed since; the service-wide options and this
    // window's preferences go once, on the way out. A stopped service parks
    // each intent and replays it on reconnect.
    property var _protectionWritten: null
    property bool _protectionWritePending: false
    property bool _optionsApplied: false
    property bool _stabilityWritePending: false

    function _saveProtection() {
        _seedProtection()
        // Until the service answers, a user already set up cannot be told
        // from a new one: the write waits for its first policy read.
        if (!_protectionSeeded) {
            _protectionWritePending = true
            return
        }
        _protectionWritePending = false
        var want = { level: leakProtectionChoice, doh: wantDohLockdown === true }
        if (_protectionWrite === "pending" && _protectionSending !== null
                && _protectionSending.level === want.level && _protectionSending.doh === want.doh)
            return
        var base = _protectionWritten !== null ? _protectionWritten : _heldProtection
        var writes = Pure.firstRunWrites(base, want.level, want.doh, false, false)
        if (!writes.protection || !root.routePolicyController) return
        _protectionWrite = "pending"
        _protectionSending = want
        root.routePolicyController.applyFirstRunProtections(want.level, want.doh, undefined, {
            onApplied: function() {
                _protectionWritten = want
                _protectionSettled("", "")
            },
            onNotWritten: function(code) { _protectionSettled("failed", code) },
            // Sent again once the service is up, before its rules review.
            onParked: function() { _protectionSettled("", "") }
        })
    }

    // The protection write in flight ("pending") or refused ("failed"); ""
    // once in force or with nothing to write. The starting rules wait on it.
    property string _protectionWrite: ""
    property string _protectionFailure: ""
    property var _protectionSending: null
    property var _afterProtection: []

    function _protectionSettled(state, code) {
        _protectionWrite = state
        _protectionFailure = String(code || "")
        _protectionSending = null
        var waiting = _afterProtection
        _afterProtection = []
        for (var i = 0; i < waiting.length; i += 1) waiting[i]()
    }

    /// `go(saved, code)` once the protection write has settled.
    function _whenProtectionSettled(go) {
        var settled = function() { go(_protectionWrite === "", _protectionFailure) }
        if (_protectionWrite === "pending") _afterProtection = _afterProtection.concat([settled])
        else settled()
    }

    // Rules never run without the protection chosen with them: a refused
    // write holds the set back and says how to load it again.
    function _holdChosenRules(c, code) {
        if (!c || c.route === "none") return
        var reason = typeof root.ipcErrorLabel === "function"
            ? root.ipcErrorLabel(String(code || "unknown")) : String(code || "unknown")
        root.showNotice(root.tr("dialog.rule-set-not-applied.title", "Rule set not applied"),
            root.tr("dialog.rule-set-not-applied.protection-not-saved",
                "«{name}»: these rules were not applied, because the leak protection chosen with them could not be saved ({reason}). Set leak protection in Settings, then load the set again on the Rules screen.")
                .replace("{name}", c.label).replace("{reason}", reason))
    }

    function _applyProtectionChoices() {
        _saveProtection()
        if (_optionsApplied) return
        _optionsApplied = true
        if (wantBlockNoticesMuted) {
            root.commitPrefs({ notifyBlockNotices: false })
        }
        if (wantTrayAutostart && root.supports("autostart")) {
            root.setAutostartEnabled(true)
        }
        if (!_protectionSeeded) {
            _stabilityWritePending = true
            return
        }
        _writeStability()
    }

    /// The service holds the leak protection and lockdown chosen here.
    readonly property bool protectionInForce: root.uiRevision >= 0 && servicePolicyKnown
        && !!root._serviceRoutePolicy && _holdsChosenProtection(root._serviceRoutePolicy)
    function _holdsChosenProtection(policy) {
        var held = Pure.firstRunHeldProtection(true, defaultRoute,
            String(policy["leak-protection"] || ""),
            policy["doh-lockdown-auto"] === true, policy["doh-lockdown-enabled"] === true)
        return !!held && held.level === leakProtectionChoice && held.doh === (wantDohLockdown === true)
    }

    // A user already set up (in the terminal, say) starts from what the
    // service holds and keeps it unless a choice changes here, as the
    // terminal setup does. Taken once, from the first policy read; a choice
    // the user made before it stands.
    readonly property bool servicePolicyKnown: root._servicePolicyRead === true
    property var _heldProtection: null
    property bool _protectionSeeded: false
    property bool _protectionTouched: false
    property bool _stabilityTouched: false
    property bool _fakeIpTouched: false
    onServicePolicyKnownChanged: _onServicePolicyRead()
    function _onServicePolicyRead() {
        _seedProtection()
        if (!_protectionSeeded) return
        if (_protectionWritePending) _saveProtection()
        if (_stabilityWritePending) _writeStability()
    }

    function chooseLeakProtection(level) {
        _protectionTouched = true
        wantLeakProtection = level
    }

    function _seedProtection() {
        if (_protectionSeeded || !servicePolicyKnown) return
        _protectionSeeded = true
        var rp = root._serviceRoutePolicy
        var policy = rp || {}
        _heldProtection = Pure.firstRunHeldProtection(!!rp,
            defaultRoute, String(policy["leak-protection"] || ""),
            policy["doh-lockdown-auto"] === true, policy["doh-lockdown-enabled"] === true)
        if (_heldProtection && !_protectionTouched) {
            wantLeakProtection = _heldProtection.level
            wantDohLockdown = _heldProtection.doh
        }
        if (_heldProtection) _seedFakeIp()
    }

    // A user already set up is shown the service's fake-IP, not the offer:
    // the last value seen at once, then the service's own answer.
    function _seedFakeIp() {
        if (typeof root._readServiceMirror === "function") {
            var mirror = root._readServiceMirror()["stability"] || {}
            if (mirror["fake-ip-enabled"] !== undefined && !_fakeIpTouched)
                wantFakeIp = mirror["fake-ip-enabled"] === true
        }
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (!root.serviceStabilitySupported || !root.bridgeAvailable || bridge === null
                || typeof bridge.rpcServiceStabilityConfigGet !== "function")
            return
        var corr = bridge.rpcServiceStabilityConfigGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload) {
            if (ok && payload && payload["fake-ip-enabled"] !== undefined && !_fakeIpTouched)
                wantFakeIp = payload["fake-ip-enabled"] === true
        })
    }

    function _writeStability() {
        _stabilityWritePending = false
        var writes = Pure.firstRunWrites(_heldProtection, leakProtectionChoice, wantDohLockdown,
            _stabilityTouched, _fakeIpTouched)
        if (!writes.stability) return
        var patch = {}
        if (writes.fakeIp) patch["fake-ip-enabled"] = wantFakeIp
        if (wantDiagnosticLogs) {
            patch["verbose-logging-change"] = diagnosticLogsDuration
            patch["conn-trace-ndjson-change"] = diagnosticLogsDuration
            patch["conn-trace-gui"] = true
        }
        // An empty write would still ask for an administrator.
        if (Object.keys(patch).length === 0) return
        root.startupController.applyFirstRunStability(patch, "first-run")
    }

    /// What one connection reads as in the picker for `role`. A system name
    /// alone is not an answer to "which one is this" (`Wi-Fi 2`, `enp4s0f1`):
    /// the kind says what the device is, the availability whether it is up,
    /// and the hint which role the recommendation sees in it.
    function _adapterLabel(row, role) {
        if (!row) return ""
        var program = role === "secondary" ? _idleVpnProgram(row) : null
        if (program !== null) {
            return (program !== ""
                ? root.tr("dialog.first-run-wizard.secondary-adapter-idle-vpn-program",
                    "{name} (VPN {program}, not connected now)")
                : root.tr("dialog.first-run-wizard.secondary-adapter-idle-vpn",
                    "{name} (VPN, not connected now)"))
                .replace("{name}", Pure.adapterDisplayName(row))
                .replace("{program}", Pure.displayText(program))
        }
        // One rule for how an adapter reads, shared with every dialog.
        var parts = [Pure.adapterDisplayName(row)]
        var tech = String(row.deviceTechnology || "")
        if (tech !== "") parts.push(root.tr("interfaces.device-technology." + tech, tech))
        var kind = String(row.kind || "")
        if (kind !== "") parts.push(root.tr("interfaces.kind." + kind, kind))
        parts.push(String(row.availability || "") === "available"
            ? root.tr("interfaces.connectivity.available", "Connected")
            : root.tr("interfaces.connectivity.unavailable", "No connection"))
        var taken = Pure.adapterHeldOtherRole(row, role)
        var hint = Pure.adapterRoleHintSlug(row)
        if (taken !== "")
            parts.push(root.tr("interfaces.role.taken." + taken, taken))
        else if (hint !== "")
            parts.push(root.tr("interfaces.hint." + hint, hint))
        return parts.join(" · ")
    }

    /// The warning for a connection that is not up while another copy of its
    /// driver is (a VPN program often brings up a different copy): the one
    /// holding `role`, else the pick.
    function _siblingWarning(role) {
        var ctl = root.interfacesRolesController
        if (!ctl || typeof ctl.driverSiblingWarning !== "function") return ""
        var held = role === "primary" ? assignedPrimaryIndex : assignedSecondaryIndex
        var index = held >= 0 ? held
            : _modelIndexOfKey(role === "primary" ? pickedPrimaryKey : pickedSecondaryKey)
        return index >= 0 ? String(ctl.driverSiblingWarning(index, role) || "") : ""
    }

    /// Whether the picker for `role` may act on its current choice: an adapter
    /// already holding the other role is shown there but not offered.
    function _offeredFor(index, role) {
        return index >= 0 && index < root.interfacesModel.count
            && Pure.adapterHeldOtherRole(root.interfacesModel.get(index), role) === ""
    }

    /// The connection that looks like a tunnel, by the snapshot's own
    /// classification. Names it in the hint rather than picking it: which link
    /// carries which traffic is the user's decision, and a wrong automatic pick
    /// is far more expensive than a wrong suggestion.
    function _tunnelCandidateName() {
        if (!root.interfacesModel) return ""
        for (var i = 0; i < root.interfacesModel.count; i += 1) {
            var row = root.interfacesModel.get(i)
            if (!row || String(row.selectedRole || "") === "primary") continue
            // An idle adapter left behind by a VPN client is not the VPN.
            if (String(row.availability || "") !== "available") continue
            if (Pure.adapterLooksLikeTunnel(row)) return String(row.name || "")
        }
        return ""
    }

    // The page shown. Every page is skippable, as the one long page was: the
    // choices are committed on close whichever page the user left from.
    readonly property int stepCount: 5
    property int step: 0
    onStepChanged: {
        wizardScroller.contentItem.contentY = 0
        // A page comes back showing its answer, with "Change" beside it.
        changingPrimary = false
        changingSecondary = false
        _awaitPrimaryKey = ""
        _awaitSecondaryKey = ""
        // The review names the protection in force: it is sent on the way in.
        if (visible && step === stepCount - 1) _saveProtection()
        Qt.callLater(_suggestPicks)
        Qt.callLater(_watchAdapters)
        Qt.callLater(_focusStep)
    }

    /// The keyboard starts on the page's question, else on the way on: the
    /// pressed button may have just hidden itself.
    function _focusStep() {
        if (!visible) return
        if (step === stepCount - 1 && finishButton.visible) finishButton.forceActiveFocus()
        else if (step === 0 && firstRunPrimaryCombo.visible && firstRunPrimaryCombo.enabled)
            firstRunPrimaryCombo.forceActiveFocus()
        else if (step === 1 && justConnectedAssign.visible) justConnectedAssign.forceActiveFocus()
        else if (step === 2 && countryPresetOption.visible) countryPresetOption.forceActiveFocus()
        else if (step === 2 && !nextButton.enabled) demoOption.forceActiveFocus()
        else if (step === 1 && firstRunSecondaryCombo.visible && firstRunSecondaryCombo.enabled)
            firstRunSecondaryCombo.forceActiveFocus()
        else if (nextButton.visible) nextButton.forceActiveFocus()
    }

    function _stepTitle(index) {
        switch (index) {
        case 0: return root.tr("interfaces.role.primary", "Main connection")
        case 1: return root.tr("interfaces.role.secondary", "Additional connection (e.g. VPN)")
        case 2: return root.tr("dialog.first-run-wizard.step-rules", "Starting rules")
        case 3: return root.tr("dialog.first-run-wizard.step-options", "Protection and options")
        default: return root.tr("dialog.first-run-wizard.step-review", "Ready to finish")
        }
    }

    // A connection page is settled once its role is set or deferred; until
    // then its "Set as" button is the next thing to press, not Next.
    readonly property bool stepSettled: step === 0
        ? !choosingPrimary
        : step === 1 && !choosingSecondary

    /// The rules page asks for a decision: a set, or "Start empty" pressed.
    function _nextAllowed() {
        return step !== 2 || chosenStart !== null
    }

    /// The one thing that pulses: what the user has to do next.
    function _pulseTarget() {
        switch (step) {
        case 0: return choosingPrimary ? "primary-assign" : "next"
        case 1:
            if (!choosingSecondary) return "next"
            return justConnectedKey !== "" ? "just-connected" : "secondary-assign"
        case 2: return chosenStart === null ? "rule-options" : "next"
        case stepCount - 1: return "finish"
        default: return "next"
        }
    }
    readonly property string pulseTarget: root.uiRevision >= 0 && visible ? _pulseTarget() : ""
    // A ring round the button comes and goes; the button itself never dims,
    // or a pressable button reads as a disabled one.
    property real pulse: 0
    SequentialAnimation on pulse {
        running: firstRunWindow.visible && firstRunWindow.pulseTarget !== ""
        loops: Animation.Infinite
        NumberAnimation { to: 1.0; duration: 650; easing.type: Easing.InOutQuad }
        NumberAnimation { to: 0.0; duration: 650; easing.type: Easing.InOutQuad }
        onRunningChanged: if (!running) firstRunWindow.pulse = 0
    }

    /// The connection the review page names for `role`: the one holding it,
    /// else the pick the close will commit.
    function _reviewAdapterName(role) {
        var assigned = role === "primary" ? assignedPrimaryName : assignedSecondaryName
        if (assigned !== "") return assigned
        if (role === "secondary" && secondaryDeferred)
            return root.tr("dialog.first-run-wizard.review-later", "later")
        var rows = _modelRows()
        var i = Pure.firstRunPickToCommit(rows, role,
            role === "primary" ? pickedPrimaryKey : pickedSecondaryKey)
        return i >= 0 ? Pure.adapterDisplayName(rows[i])
                      : root.tr("dialog.first-run-wizard.review-not-chosen", "not chosen")
    }

    /// The review page, line by line: the protection as the service holds it,
    /// and that rules wait for a main connection when none is chosen.
    function _reviewLines() {
        var lines = [root.tr("dialog.first-run-wizard.review-primary", "Main connection: {name}")
            .replace("{name}", _reviewAdapterName("primary"))]
        if (!primaryAssigned && Pure.firstRunPickToCommit(_modelRows(), "primary", pickedPrimaryKey) < 0)
            lines.push(root.tr("dialog.first-run-wizard.review-no-primary",
                "Your rules are not applied until a main connection is chosen. You can choose it later in Connections."))
        lines.push(root.tr("dialog.first-run-wizard.review-secondary", "Additional connection: {name}")
            .replace("{name}", _reviewAdapterName("secondary")))
        lines.push(root.tr("dialog.first-run-wizard.review-rules", "Starting rules: {name}")
            .replace("{name}", chosenStart !== null
                ? chosenStart.label
                : root.tr("dialog.first-run-wizard.review-rules-current",
                    "the rules already applied to you")))
        var level = root.tr("settings.routing.leak-protection.option-" + leakProtectionChoice,
            leakProtectionChoice)
        lines.push((protectionInForce
            ? root.tr("dialog.first-run-wizard.review-leak-in-force", "Leak protection: {name} — in force.")
            : root.tr("dialog.first-run-wizard.review-leak-not-yet", "Leak protection: {name} — not in force yet."))
            .replace("{name}", level))
        return lines
    }

    function _basename(p) {
        if (!p) return ""
        var s = String(p)
        var i = s.lastIndexOf("\\")
        var j = s.lastIndexOf("/")
        var k = Math.max(i, j)
        return k >= 0 ? s.substring(k + 1) : s
    }

    // A window reopened from Settings is a new run: nothing of the last one
    // counts as answered, and its protection page is written again.
    function _startRun() {
        step = 0
        pickedPrimaryPath = ""
        pickedSecondaryPath = ""
        pickedPrimaryKey = ""
        pickedSecondaryKey = ""
        secondaryDeferred = false
        changingPrimary = false
        changingSecondary = false
        _awaitPrimaryKey = ""
        _awaitSecondaryKey = ""
        _adaptersSeen = null
        justConnectedKey = ""
        _adapterPrint = ""
        showAllAdapters = false
        installedVpnNames = []
        _vpnPrograms = []
        chosenStart = null
        chosenStartError = ""
        _heldProtection = null
        _protectionSeeded = false
        _protectionTouched = false
        _stabilityTouched = false
        _fakeIpTouched = false
        _protectionWritten = null
        _protectionWritePending = false
        _protectionWrite = ""
        _protectionFailure = ""
        _protectionSending = null
        _optionsApplied = false
        _stabilityWritePending = false
    }

    /// The free part of the screen this window is on, taskbar excluded; null
    /// before there is a screen. QML's `desktopAvailable*` spans every
    /// monitor: the host's work area of the primary screen is asked first.
    function _workArea() {
        var s = firstRunWindow.screen
        var bridge = typeof nrrNativeBridge !== "undefined" ? nrrNativeBridge : null
        if (bridge && typeof bridge.trayNoticeScreenGeometry === "function") {
            var r = bridge.trayNoticeScreenGeometry()
            var inside = !s || !(s.width > 0) || (r && r.x >= s.virtualX && r.y >= s.virtualY
                && r.x + r.width <= s.virtualX + s.width && r.y + r.height <= s.virtualY + s.height)
            if (r && r.width > 0 && r.height > 0 && inside) return r
        }
        if (!s || !(s.width > 0) || !(s.height > 0)) return null
        var inset = Math.max(0, Math.min(120, s.height - s.desktopAvailableHeight))
        return { x: s.virtualX, y: s.virtualY,
            width: Math.min(s.width, s.desktopAvailableWidth || s.width), height: s.height - inset }
    }

    /// Size and place within `area` for a window wanted at `x`, `y`: the title
    /// bar above `y` and the frame below `y + height` stay inside too.
    function _fitIn(area, atX, atY) {
        var titleBar = 36, frame = 8
        var w = Math.max(320, Math.min(_wantWidth, area.width - 2 * frame))
        var h = Math.max(320, Math.min(_wantHeight, area.height - titleBar - 2 * frame))
        var nx = Math.max(area.x + frame, Math.min(atX, area.x + area.width - w - frame))
        var ny = Math.max(area.y + titleBar, Math.min(atY, area.y + area.height - h - frame))
        return { x: nx, y: ny, width: w, height: h }
    }

    /// Over the part of the main window that lies in `area`, the middle of
    /// `area` when none does: a main window still settling (restored, resized
    /// or off-screen) never pushes the wizard to the screen edge.
    function _centerIn(area) {
        var l = Math.max(area.x, root.x), r = Math.min(area.x + area.width, root.x + root.width)
        var t = Math.max(area.y, root.y), b = Math.min(area.y + area.height, root.y + root.height)
        var cx = r > l ? (l + r) / 2 : area.x + area.width / 2
        var cy = b > t ? (t + b) / 2 : area.y + area.height / 2
        x = Math.round(cx - width / 2)
        y = Math.round(cy - height / 2)
    }

    /// Fits the window into the free part of its screen; `center` first puts
    /// it over the main window.
    function _fitOnScreen(center) {
        var area = _workArea()
        if (!area) return
        var size = _fitIn(area, x, y)
        if (width !== size.width) width = size.width
        if (height !== size.height) height = size.height
        if (center) _centerIn(area)
        // A move that changes nothing still goes through the platform layer.
        var at = _fitIn(area, x, y)
        if (x !== at.x) x = at.x
        if (y !== at.y) y = at.y
    }
    onScreenChanged: if (visible) _fitOnScreen(false)
    onActiveChanged: if (active) _fitOnScreen(false)
    Connections {
        target: firstRunWindow.screen
        ignoreUnknownSignals: true
        function onDesktopGeometryChanged() { if (firstRunWindow.visible) firstRunWindow._fitOnScreen(false) }
        function onHeightChanged() { if (firstRunWindow.visible) firstRunWindow._fitOnScreen(false) }
        function onWidthChanged() { if (firstRunWindow.visible) firstRunWindow._fitOnScreen(false) }
    }

    onVisibleChanged: {
        if (visible) {
            _fitOnScreen(true)
            // Again once the main window has taken its place.
            Qt.callLater(function() { firstRunWindow._fitOnScreen(true) })
            root.applyTitleBarTo(firstRunWindow)
            _startRun()
            _detectCountryPreset()
            _seedProtection()
            _scanInstalledVpns()
            Qt.callLater(_suggestPicks)
            Qt.callLater(_focusStep)
            // The adapter list is what the main-connection question offers; the
            // wizard can open before the first snapshot arrived.
            if (root.interfacesRolesController
                    && typeof root.interfacesRolesController.refreshInterfacesFromService === "function") {
                root.interfacesRolesController.refreshInterfacesFromService()
            }
        }
    }

    // Every way out — Finish, the Escape overlay handler
    // (`applyActiveOverlay`) or the title-bar X — commits what was chosen, in
    // the order the service needs it: connections, protection, then the
    // starting rules, which never run without the protection.
    function _commitRun() {
        _commitPendingPicks()
        _applyProtectionChoices()
        // The choice is this run's: a reopened window starts its own.
        var c = chosenStart
        chosenStart = null
        _whenProtectionSettled(function(saved, code) {
            if (!saved) {
                _holdChosenRules(c, code)
                return
            }
            chosenStart = c
            _startChosenRules()
        })
    }

    onClosing: {
        _commitRun()
        if (!root.prefs.firstRunCompleted) {
            root.updatePrefs({ firstRunCompleted: true })
        }
        // Flushed HERE, on every close path. Waiting for the main
        // window's exit emit meant a force-kill lost the flag and the wizard
        // greeted the user again — the very loss the debounced writer exists
        // to prevent.
        root.emitPrefs()
        // Hand the Licenses window back to the main window if it was
        // re-parented onto the wizard by `licenseWindow.openOnEulaTab`
        // (so a later normal open stacks correctly).
        if (root.licenseWindow.transientParent === firstRunWindow) {
            root.licenseWindow.transientParent = root
        }
        // The choices above are parked when the service is not up yet, and the
        // collect that delivers them refuses to run while this window is open.
        if (root.offlineBacklogCollector) {
            root.offlineBacklogCollector.scheduleOfflineBacklogCollect()
        }
    }

    /// The detected country as words, never the bare code. `form` is "name",
    /// "in" or "outside": Russian needs a different case for each, so the
    /// phrase comes whole from the locale rather than being assembled here.
    function countryText(form) {
        var cc = detectedCountry
        var base = "dialog.first-run-wizard.country." + cc + "."
        var name = root.tr(base + "name", cc.toUpperCase())
        if (form === "name") return name
        var generic = form === "in"
            ? root.tr("dialog.first-run-wizard.country-in-fallback", "in {country}")
            : root.tr("dialog.first-run-wizard.country-outside-fallback", "outside {country}")
        return root.tr(base + form, generic.replace("{country}", name))
    }

    function _detectCountryPreset() {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.detectOsLocale !== "function") {
            detectedCountry = ""
            detectedCountryPack = ""
            detectedAbroadPack = ""
            detectedLanguage = ""
            return
        }
        var loc = String(nrrNativeBridge.detectOsLocale() || "")
        var parts = loc.split("_")
        // The country the system is set to outranks the locale's: an English
        // Windows set to Russia is offered Russia's set.
        var cc = Pure.firstRunCountry(String((root.context || {}).systemRegion || ""), [loc])
        detectedCountry = cc
        _loadAllPacks()
        detectedLanguage = String(parts[0] || "").toLowerCase()
        var packsJson = String(nrrNativeBridge.listCountryPresets(cc) || "[]")
        var packs = []
        try { packs = JSON.parse(packsJson) } catch (e) { packs = [] }
        detectedCountryPack = (packs.length > 0) ? String(packs[0]) : ""

        var abroadJson = String(nrrNativeBridge.listCountryPresets("abroad") || "[]")
        var abroadPacks = []
        try { abroadPacks = JSON.parse(abroadJson) } catch (e) { abroadPacks = [] }
        var wanted = "access-to-" + cc
        detectedAbroadPack = (cc !== "" && abroadPacks.indexOf(wanted) >= 0) ? wanted : ""
    }

    function _readPresetBytes(relativePath) {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.resolvePresetPath !== "function") {
            return ""
        }
        var path = nrrNativeBridge.resolvePresetPath(relativePath)
        if (!path) return ""
        return nrrNativeBridge.readFileBytes(path)
    }

    // Resolve a bundled-preset relative path ("ru/<pack>/rules_primary.txt")
    // to an ABSOLUTE filesystem path. The stored file binding
    // (lastSavedPath* / autoOpenOnLaunchPath*) must be absolute — a
    // relative path does not resolve from the GUI's working directory on
    // the next launch and surfaces "auto-open file not found". Falls back
    // to the relative path if the bridge can't resolve it.
    function _resolvePresetAbs(relativePath) {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.resolvePresetPath !== "function") {
            return relativePath
        }
        var p = String(nrrNativeBridge.resolvePresetPath(relativePath) || "")
        return p !== "" ? p : relativePath
    }

    function _applyCountryPreset() {
        var dir = useAbroadPack ? "abroad" : detectedCountry
        var pack = useAbroadPack ? detectedAbroadPack : detectedCountryPack
        if (pack === "") return
        var primRel = dir + "/" + pack + "/rules_primary.txt"
        var secRel = dir + "/" + pack + "/rules_secondary.txt"
        _choose(_packKey(dir, pack), _packLabel({ country: dir, pack: pack }),
            _readPresetBytes(primRel), _readPresetBytes(secRel),
            _resolvePresetAbs(primRel), _resolvePresetAbs(secRel))
    }

    // The starting rule set the user chose, `{key, label, route, primB64,
    // secB64, primPath, secPath}` (`route` "both", "primary", "secondary" or
    // "none" for an empty start); null until one is chosen. `key` names the
    // option that chose it, which shows itself chosen. Imported only when the
    // window closes, after the connections and the protection, so a choice
    // here never skips the questions below it.
    property var chosenStart: null
    property string chosenStartError: ""
    /// What a screen reader adds to the chosen option.
    readonly property string chosenOptionDescription: root && root.uiRevision >= 0
        ? root.tr("dialog.first-run-wizard.option-chosen",
            "Chosen. Imported when you press Finish.")
        : ""

    // Files picked anew after "Use" are not the ones read: that choice lapses.
    onPickedPrimaryPathChanged: if (_isChosen("files")) chosenStart = null
    onPickedSecondaryPathChanged: if (_isChosen("files")) chosenStart = null

    function _packKey(country, pack) { return "pack:" + country + "/" + pack }

    function _countryPackKey() {
        return useAbroadPack ? _packKey("abroad", detectedAbroadPack)
                             : _packKey(detectedCountry, detectedCountryPack)
    }

    function _comboPackKey(index) {
        var p = allPacks[index]
        return p ? _packKey(String(p.country), String(p.pack)) : ""
    }

    function _isChosen(key) {
        return chosenStart !== null && key !== "" && chosenStart.key === key
    }

    function _choose(key, label, primB64, secB64, primPath, secPath) {
        if (!primB64 && !secB64) {
            _chooseFailed("(no bytes)")
            return
        }
        chosenStartError = ""
        chosenStart = { key: key, label: label, route: "both", primB64: primB64, secB64: secB64,
            primPath: primPath, secPath: secPath }
    }

    function _startChosenRules() {
        var c = chosenStart
        chosenStart = null
        if (!c || c.route === "none" || !root.presetImportController) return
        var flows = root.presetImportController
        // This window is gone by the time the service answers: the outcome is
        // a message box over the main window, named as the user picked it.
        // Picked here, so applied without a second review.
        var opts = { label: c.label, confirmed: true }
        if (c.route === "both") {
            if (typeof flows.startBothRoutesPresetImportReviewFlow === "function")
                flows.startBothRoutesPresetImportReviewFlow(c.primB64, c.secB64, c.primPath, c.secPath, opts)
        } else if (typeof flows.startPresetImportReviewFlow === "function") {
            flows.startPresetImportReviewFlow(c.route,
                c.route === "primary" ? c.primB64 : c.secB64,
                c.route === "primary" ? c.primPath : c.secPath,
                "replace", opts)
        }
        root.statusLine = root.tr("status.wizard-completed",
            "Welcome — initial rules imported.")
    }

    // Every bundled set, `{country, pack}`: whatever the system says, the user
    // may need another country's set.
    property var allPacks: []

    function _loadAllPacks() {
        var found = []
        if (typeof nrrNativeBridge !== "undefined" && nrrNativeBridge
                && typeof nrrNativeBridge.listAllPresets === "function") {
            try { found = JSON.parse(String(nrrNativeBridge.listAllPresets("") || "[]")) } catch (e) { found = [] }
        }
        allPacks = (found || []).filter(function(p) {
            return p && String(p.country || "") !== "" && String(p.pack || "") !== ""
        })
    }

    /// How a bundled set reads in the list: its name as Settings shows it, else
    /// the country in words (an `abroad/access-to-<cc>` set as that country's
    /// access set) and the folder.
    function _packLabel(p) {
        if (!p) return ""
        var abroad = String(p.country) === "abroad"
        var cc = abroad ? String(p.pack).replace(/^access-to-/, "") : String(p.country)
        var name = root.tr("dialog.first-run-wizard.country." + cc + ".name", cc.toUpperCase())
        // A noun, not a button caption: it also names the choice in the line below.
        var fallback = name + " — " + String(p.pack)
        return root.tr("rules.bundled-preset.name." + p.country + "-" + p.pack, fallback)
    }

    function _applyPack(p) {
        if (!p) return
        var primRel = String(p.country) + "/" + String(p.pack) + "/rules_primary.txt"
        var secRel = String(p.country) + "/" + String(p.pack) + "/rules_secondary.txt"
        _choose(_packKey(String(p.country), String(p.pack)), _packLabel(p),
            _readPresetBytes(primRel), _readPresetBytes(secRel),
            _resolvePresetAbs(primRel), _resolvePresetAbs(secRel))
    }

    function _applyBuiltinDemo() {
        var primRel = root.builtinDemoPreset("rules_primary.txt")
        var secRel = root.builtinDemoPreset("rules_secondary.txt")
        _choose("demo", root.tr("dialog.first-run-wizard.rule-set-demo-name", "Example rules"),
            _readPresetBytes(primRel), _readPresetBytes(secRel),
            _resolvePresetAbs(primRel), _resolvePresetAbs(secRel))
    }

    function _startEmpty() {
        chosenStartError = ""
        chosenStart = { key: "empty",
            label: root.tr("dialog.first-run-wizard.rule-set-empty-name", "none, an empty start"),
            route: "none" }
    }

    // A choice that could not be read is no choice: Finish must not import the
    // one the user had just moved away from.
    function _chooseFailed(detail) {
        chosenStart = null
        chosenStartError = root.tr("status.wizard-import-failed",
            "Could not load the starting rules: ") + detail
    }

    function _localPathFromUrl(urlValue) {
        return Pure.localPathFromFileUrl(urlValue)
    }

    // Read the picked file(s) now, so an unreadable one is said while the
    // user can re-pick; both set → both routes, one → that route alone.
    function _applyOpenedFiles() {
        var primPath = pickedPrimaryPath
        var secPath = pickedSecondaryPath
        if (!primPath && !secPath) return
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            chosenStart = null
            chosenStartError = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        var primB64 = primPath ? nrrNativeBridge.readFileBytes(primPath) : ""
        var secB64 = secPath ? nrrNativeBridge.readFileBytes(secPath) : ""
        if (primPath && !primB64) {
            _chooseFailed("(read primary)")
            return
        }
        if (secPath && !secB64) {
            _chooseFailed("(read secondary)")
            return
        }
        var names = []
        if (primPath) names.push(_basename(primPath))
        if (secPath) names.push(_basename(secPath))
        chosenStartError = ""
        chosenStart = { key: "files", label: names.join(", "),
            route: primPath && secPath ? "both" : (primPath ? "primary" : "secondary"),
            primB64: primB64, secB64: secB64, primPath: primPath, secPath: secPath }
    }

    FileDialog {
        id: firstRunOpenPrimaryDialog
        fileMode: FileDialog.OpenFile
        // Same folder every other rule-file dialog uses.
        title: root.tr("dialog.first-run-wizard.pick-primary-title",
            "Choose the rules file for the main connection")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Rules files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        onAccepted: firstRunWindow.pickedPrimaryPath =
            firstRunWindow._localPathFromUrl(selectedFile)
    }

    FileDialog {
        id: firstRunOpenSecondaryDialog
        fileMode: FileDialog.OpenFile
        title: root.tr("dialog.first-run-wizard.pick-secondary-title",
            "Choose the rules file for the additional connection")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Rules files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        onAccepted: firstRunWindow.pickedSecondaryPath =
            firstRunWindow._localPathFromUrl(selectedFile)
    }

    // Scrollable: a page can still outgrow the fixed 640 px window (large
    // text, long translations). The scrollbar stays drawn while anything is
    // below the fold, and Back / Next / Finish sit in the bar under it.
    ScrollView {
        id: wizardScroller
        anchors {
            left: parent.left
            right: parent.right
            top: parent.top
            bottom: finishBar.top
            leftMargin: root.uiTheme.spacingLg
            rightMargin: root.uiTheme.spacingSm
            topMargin: root.uiTheme.spacingLg
            bottomMargin: root.uiTheme.spacingSm
        }
        // A fixed gutter for the bar: tied to its visibility, the content
        // would rewrap, grow and feed back into whether the bar shows.
        rightPadding: wizardScrollBar.width + root.uiTheme.spacingSm
        clip: true
        contentWidth: availableWidth
        ScrollBar.vertical: ScrollBar {
            id: wizardScrollBar
            parent: wizardScroller
            x: wizardScroller.width - width
            y: wizardScroller.topPadding
            height: wizardScroller.availableHeight
            // Drawn here, so no style hides it: only a page taller than the
            // view shows it.
            visible: wizardScroller.contentHeight > wizardScroller.availableHeight
            policy: ScrollBar.AlwaysOn
            contentItem: Rectangle {
                implicitWidth: 8
                implicitHeight: 32
                radius: width / 2
                color: root.uiTheme.colorTextMuted
                opacity: root.uiTheme.isHighContrast || wizardScrollBar.pressed ? 1 : 0.6
            }
            background: Rectangle {
                implicitWidth: 8
                radius: width / 2
                color: root.uiTheme.colorBase
                border.width: root.uiTheme.isHighContrast ? 1 : 0
                border.color: root.uiTheme.colorBorder
            }
        }

        ColumnLayout {
            width: wizardScroller.availableWidth
            spacing: root.uiTheme.spacingMd

            Label {
                text: root.tr("dialog.first-run-wizard.title",
                    "Welcome to NetRuleRouter")
                color: root.textColor
                font.bold: true
                font.pixelSize: 18
            }

            // Where the user is: "Step 2 of 5: Additional connection", and the
            // same as a row of marks. The EULA the user accepted to get here
            // stays one click away on every page.
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    id: stepIndicator
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.WordWrap
                    color: root.textColor
                    font.bold: true
                    text: root.uiRevision >= 0
                        ? root.tr("dialog.first-run-wizard.step-of", "Step {step} of {total}: {name}")
                            .replace("{step}", String(firstRunWindow.step + 1))
                            .replace("{total}", String(firstRunWindow.stepCount))
                            .replace("{name}", firstRunWindow._stepTitle(firstRunWindow.step))
                        : ""
                    Accessible.role: Accessible.StaticText
                    Accessible.name: text
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("dialog.first-run-wizard.view-eula", "View EULA")
                    onClicked: root.licenseWindow.openOnEulaTab()
                }
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXs
                Accessible.ignored: true
                Repeater {
                    model: firstRunWindow.stepCount
                    Rectangle {
                        required property int index
                        Layout.fillWidth: true
                        Layout.preferredHeight: 4
                        radius: 2
                        color: index <= firstRunWindow.step
                            ? root.uiTheme.colorAccent : root.uiTheme.colorBorder
                    }
                }
            }

            // Main connection, asked before anything else: rules describe what
            // goes the OTHER way, so until this is named there is nothing for them
            // to deviate from and none of them are applied. Skippable — the banner
            // and the tray notice keep saying so until it is answered.
            ColumnLayout {
                id: wizardStepPrimary
                visible: firstRunWindow.step === 0
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXs

                Label {
                    text: root.tr("interfaces.role.primary",
                        "Main connection")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    text: firstRunWindow.primaryAssigned
                        ? root.tr("dialog.first-run-wizard.primary-adapter-assigned",
                            "Main connection: {name}. You can change it later in Connections.")
                            .replace("{name}", firstRunWindow.assignedPrimaryName)
                        : root.tr("dialog.first-run-wizard.primary-adapter-description",
                            "The connection everything travels by default. Until you name it, your rules are not applied.")
                }
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                    color: root.uiTheme.colorWarning
                    text: root.uiRevision >= 0 ? firstRunWindow._siblingWarning("primary") : ""
                    visible: text !== ""
                }
                // The answer given stays changeable here, not only in Interfaces.
                ThemedButton {
                    id: firstRunPrimaryChange
                    theme: root.uiTheme
                    visible: !firstRunWindow.choosingPrimary
                    text: root.tr("action.change", "Change...")
                    Accessible.role: Accessible.Button
                    Accessible.name: root.tr("interfaces.role.primary", "Main connection") + ": " + text
                    onClicked: firstRunWindow._changeChoice("primary")
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    visible: firstRunWindow.choosingPrimary
                    ThemedComboBox {
                        id: firstRunPrimaryCombo
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        // Same gate the Interfaces screen puts on its role
                        // buttons: placeholder rows name no adapter of this
                        // machine, and the service refuses a binding to one.
                        enabled: root.interfacesAreLive
                        model: root.interfacesModel
                        textRole: "name"
                        currentIndex: root.uiRevision >= 0
                            ? firstRunWindow._modelIndexOfKey(firstRunWindow.pickedPrimaryKey) : -1
                        onActivated: function(index) {
                            firstRunWindow._pick("primary",
                                firstRunWindow._rowKey(root.interfacesModel.get(index)))
                            currentIndex = Qt.binding(function() {
                                return root.uiRevision >= 0
                                    ? firstRunWindow._modelIndexOfKey(firstRunWindow.pickedPrimaryKey) : -1
                            })
                        }
                        labelResolver: function(item) {
                            return firstRunWindow._adapterLabel(item, "primary")
                        }
                        itemEnabledResolver: function(item) {
                            return Pure.adapterHeldOtherRole(item, "primary") === ""
                        }
                        itemVisibleResolver: function(item) {
                            return firstRunWindow._shownInPicker(item, "primary")
                        }
                        displayText: root.uiRevision >= 0 && currentIndex >= 0
                            ? firstRunWindow._adapterLabel(
                                root.interfacesModel.get(currentIndex), "primary")
                            : root.tr("dialog.first-run-wizard.primary-adapter-placeholder",
                                "Choose a connection")
                        Accessible.role: Accessible.ComboBox
                        Accessible.name: root.tr("interfaces.role.primary",
                            "Main connection")
                    }
                    ThemedButton {
                        id: firstRunPrimaryAssign
                        theme: root.uiTheme
                        text: root.tr("dialog.first-run-wizard.primary-adapter-assign", "Set as main")
                        highlighted: enabled
                        enabled: root.interfacesAreLive && root.uiRevision >= 0
                            && firstRunWindow._offeredFor(firstRunPrimaryCombo.currentIndex, "primary")
                        attention: enabled && firstRunWindow.pulseTarget === "primary-assign"
                            ? firstRunWindow.pulse : 0
                        onClicked: firstRunWindow._assignFromPage("primary",
                            firstRunPrimaryCombo.currentIndex)
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: firstRunWindow.changingPrimary && firstRunWindow.primaryAssigned
                        text: root.tr("action.cancel", "Cancel")
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                        onClicked: firstRunWindow._keepChoice("primary")
                    }
                }
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    visible: firstRunWindow.choosingPrimary && root.uiRevision >= 0
                        && firstRunPrimaryCombo.currentIndex >= 0
                        && !firstRunWindow._offeredFor(firstRunPrimaryCombo.currentIndex, "primary")
                    text: root.tr("interfaces.role.exclusive-note",
                        "One connection cannot be both main and additional: to use it for the other role, unassign its current one first.")
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    visible: firstRunWindow.choosingPrimary
                        && (root.interfacesModel.count === 0 || !root.interfacesAreLive)
                    text: root.tr("dialog.first-run-wizard.primary-adapter-unavailable",
                        "No connections to choose from yet — the background service reports them once it is running. You can set this later in Connections.")
                }
                CheckBox {
                    id: firstRunPrimaryShowAll
                    visible: firstRunWindow.choosingPrimary
                    checked: firstRunWindow.showAllAdapters
                    onToggled: firstRunWindow.showAllAdapters = checked
                    text: root.tr("interfaces.toggle.show-unavailable-adapters",
                        "Show unavailable adapters")
                    contentItem: Label {
                        text: firstRunPrimaryShowAll.text
                        leftPadding: firstRunPrimaryShowAll.indicator.width + firstRunPrimaryShowAll.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                }
            }

            // Additional connection, in the same breath as the main one: a rule
            // says "send this the other way", and without an adapter to send it to
            // the rule has nowhere to go.
            ColumnLayout {
                id: wizardStepSecondary
                visible: firstRunWindow.step === 1
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXs

                Label {
                    text: root.tr("interfaces.role.secondary",
                        "Additional connection (e.g. VPN)")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    text: firstRunWindow.secondaryAssigned
                        ? (firstRunWindow.secondaryAssignedDown
                            ? root.tr("dialog.first-run-wizard.secondary-adapter-assigned-down",
                                "Additional connection: {name} — chosen, not connected yet. Your rules use it as soon as it connects. You can change it later in Connections.")
                            : root.tr("dialog.first-run-wizard.secondary-adapter-assigned",
                                "Additional connection: {name}. You can change it later in Connections."))
                            .replace("{name}", firstRunWindow.assignedSecondaryName)
                        : (firstRunWindow.secondaryDeferred
                            ? root.tr("dialog.first-run-wizard.secondary-adapter-deferred",
                                "You can assign it any time in Connections. Until then, with leak protection on, the traffic your rules send that way is blocked instead of leaking to the main connection.")
                            : root.tr("dialog.first-run-wizard.secondary-adapter-description",
                                "The connection your rules send traffic to — a VPN or a second network. Rules that name it do nothing until it is assigned."))
                }
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                    color: root.uiTheme.colorWarning
                    text: root.uiRevision >= 0 ? firstRunWindow._siblingWarning("secondary") : ""
                    visible: text !== ""
                }
                ThemedButton {
                    id: firstRunSecondaryChange
                    theme: root.uiTheme
                    visible: firstRunWindow.secondaryAssigned && !firstRunWindow.changingSecondary
                    text: root.tr("action.change", "Change...")
                    Accessible.role: Accessible.Button
                    Accessible.name: root.tr("interfaces.role.secondary", "Additional connection (e.g. VPN)") + ": " + text
                    onClicked: firstRunWindow._changeChoice("secondary")
                }
                // The VPN the user has just started, named and set in one press.
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: justConnectedRow.implicitHeight + 2 * root.uiTheme.spacingSm
                    visible: firstRunWindow.choosingSecondary && firstRunWindow.justConnectedKey !== ""
                    radius: 4
                    color: Qt.rgba(root.uiTheme.colorAccent.r, root.uiTheme.colorAccent.g,
                        root.uiTheme.colorAccent.b, 0.12)
                    border.color: root.uiTheme.colorAccent
                    border.width: 2
                    RowLayout {
                        id: justConnectedRow
                        anchors.fill: parent
                        anchors.margins: root.uiTheme.spacingSm
                        spacing: root.uiTheme.spacingSm
                        Label {
                            id: justConnectedText
                            Layout.fillWidth: true
                            Layout.preferredWidth: 0
                            wrapMode: Text.WordWrap
                            textFormat: Text.PlainText
                            font.bold: true
                            color: root.textColor
                            text: root.uiRevision >= 0 && firstRunWindow.justConnectedKey !== ""
                                ? firstRunWindow._justConnectedHint() : ""
                            Accessible.role: Accessible.StaticText
                            Accessible.name: text
                        }
                        ThemedButton {
                            id: justConnectedAssign
                            theme: root.uiTheme
                            highlighted: true
                            attention: firstRunWindow.pulseTarget === "just-connected"
                                ? firstRunWindow.pulse : 0
                            text: root.tr("dialog.first-run-wizard.secondary-adapter-assign",
                                "Set as additional")
                            Accessible.role: Accessible.Button
                            Accessible.name: justConnectedText.text + " " + text
                            onClicked: firstRunWindow._assignJustConnected()
                        }
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    visible: firstRunWindow.choosingSecondary
                    ThemedComboBox {
                        id: firstRunSecondaryCombo
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        enabled: root.interfacesAreLive
                        model: root.interfacesModel
                        textRole: "name"
                        currentIndex: root.uiRevision >= 0
                            ? firstRunWindow._modelIndexOfKey(firstRunWindow.pickedSecondaryKey) : -1
                        onActivated: function(index) {
                            firstRunWindow._pick("secondary",
                                firstRunWindow._rowKey(root.interfacesModel.get(index)))
                            currentIndex = Qt.binding(function() {
                                return root.uiRevision >= 0
                                    ? firstRunWindow._modelIndexOfKey(firstRunWindow.pickedSecondaryKey) : -1
                            })
                        }
                        labelResolver: function(item) {
                            return firstRunWindow._adapterLabel(item, "secondary")
                        }
                        itemEnabledResolver: function(item) {
                            return Pure.adapterHeldOtherRole(item, "secondary") === ""
                        }
                        itemVisibleResolver: function(item) {
                            return firstRunWindow._shownInPicker(item, "secondary")
                        }
                        displayText: root.uiRevision >= 0 && currentIndex >= 0
                            ? firstRunWindow._adapterLabel(
                                root.interfacesModel.get(currentIndex), "secondary")
                            : root.tr("dialog.first-run-wizard.primary-adapter-placeholder",
                                "Choose a connection")
                        Accessible.role: Accessible.ComboBox
                        Accessible.name: root.tr("interfaces.role.secondary",
                            "Additional connection (e.g. VPN)")
                    }
                    ThemedButton {
                        id: firstRunSecondaryAssign
                        theme: root.uiTheme
                        text: root.tr("dialog.first-run-wizard.secondary-adapter-assign",
                            "Set as additional")
                        highlighted: enabled
                        enabled: root.interfacesAreLive && root.uiRevision >= 0
                            && firstRunWindow._offeredFor(firstRunSecondaryCombo.currentIndex, "secondary")
                            && !firstRunWindow._pooledDown(firstRunSecondaryCombo.currentIndex)
                        attention: enabled && firstRunWindow.pulseTarget === "secondary-assign"
                            ? firstRunWindow.pulse : 0
                        onClicked: firstRunWindow._assignFromPage("secondary",
                            firstRunSecondaryCombo.currentIndex)
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: firstRunWindow.changingSecondary && firstRunWindow.secondaryAssigned
                        text: root.tr("action.cancel", "Cancel")
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                        onClicked: firstRunWindow._keepChoice("secondary")
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: !firstRunWindow.secondaryAssigned
                        text: root.tr("dialog.first-run-wizard.secondary-adapter-later",
                            "I will choose it later")
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                        onClicked: firstRunWindow.secondaryDeferred = true
                    }
                }
                // "Later" is not final: the picker is one press away.
                ThemedButton {
                    id: firstRunSecondaryChooseNow
                    theme: root.uiTheme
                    visible: firstRunWindow.secondaryDeferred && !firstRunWindow.secondaryAssigned
                    text: root.tr("dialog.first-run-wizard.primary-adapter-placeholder",
                        "Choose a connection")
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    onClicked: {
                        firstRunWindow.secondaryDeferred = false
                        Qt.callLater(firstRunWindow._suggestPicks)
                        Qt.callLater(firstRunWindow._focusStep)
                    }
                }
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    visible: firstRunWindow.choosingSecondary
                        && root.uiRevision >= 0
                        && firstRunSecondaryCombo.currentIndex >= 0
                        && !firstRunWindow._offeredFor(firstRunSecondaryCombo.currentIndex, "secondary")
                    text: root.tr("interfaces.role.exclusive-note",
                        "One connection cannot be both main and additional: to use it for the other role, unassign its current one first.")
                }
                // "Set up my VPN" stays once a VPN is set: the next VPN
                // program is added from here too.
                RowLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingSm
                    Label {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 0
                        wrapMode: Text.WordWrap
                        color: root.mutedTextColor
                        opacity: firstRunWindow.choosingSecondary
                            && firstRunWindow.justConnectedKey === "" ? 1 : 0
                        Accessible.ignored: opacity === 0
                        text: root.uiRevision < 0 ? ""
                            : firstRunWindow._pickIsIdleVpn()
                            ? root.tr("dialog.first-run-wizard.secondary-adapter-idle-vpn-later",
                                "Connect the VPN later: the program starts sending sites through it as soon as it is on.")
                            : firstRunWindow._tunnelCandidateName() !== ""
                            ? root.tr("dialog.first-run-wizard.secondary-adapter-vpn-hint",
                                "{name} looks like your VPN. We recommend making it the additional connection: choose it above and press \"Set as additional\".")
                                .replace("{name}", firstRunWindow._tunnelCandidateName())
                            : firstRunWindow._startVpnFirstHint() !== ""
                            ? firstRunWindow._startVpnFirstHint()
                            : firstRunWindow.installedVpnNames.length > 0
                            ? root.tr("dialog.first-run-wizard.secondary-adapter-vpn-installed",
                                "VPN found on this computer: {names}. Not sure which connection is your VPN? Start it and connect: the program notices the new connection by itself.")
                                .replace("{names}", firstRunWindow.installedVpnNames.join(", "))
                            : root.tr("dialog.first-run-wizard.secondary-adapter-vpn-none",
                                "Not sure which connection is your VPN? Start your VPN and connect: the program notices the new connection by itself.")
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        text: root.tr("dialog.first-run-wizard.secondary-adapter-vpn-setup",
                            "Set up my VPN")
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                        onClicked: root.openVpnOnboarding()
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        visible: firstRunWindow.choosingSecondary
                        text: root.tr("action.refresh-interfaces", "Refresh connections")
                        Accessible.role: Accessible.Button
                        Accessible.name: text
                        enabled: !!root.interfacesRolesController
                        onClicked: root.interfacesRolesController.refreshInterfacesFromService()
                    }
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    visible: firstRunWindow.choosingSecondary
                        && (root.interfacesModel.count === 0 || !root.interfacesAreLive)
                    text: root.tr("dialog.first-run-wizard.primary-adapter-unavailable",
                        "No connections to choose from yet — the background service reports them once it is running. You can set this later in Connections.")
                }
                // The same filter as on the main connection's page.
                CheckBox {
                    id: firstRunSecondaryShowAll
                    visible: firstRunWindow.choosingSecondary
                    checked: firstRunWindow.showAllAdapters
                    onToggled: firstRunWindow.showAllAdapters = checked
                    text: root.tr("interfaces.toggle.show-unavailable-adapters",
                        "Show unavailable adapters")
                    contentItem: Label {
                        text: firstRunSecondaryShowAll.text
                        leftPadding: firstRunSecondaryShowAll.indicator.width + firstRunSecondaryShowAll.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    Accessible.role: Accessible.CheckBox
                    Accessible.name: text
                }
            }

            // The starting rule set, right after the connections it routes
            // between. An option only marks its choice; the import runs on close.
            ColumnLayout {
                id: wizardStepRules
                visible: firstRunWindow.step === 2
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingMd

                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    text: root.tr("dialog.first-run-wizard.description",
                        "Choose which rules to start with. You can change this later in Rules or in Settings → Rules and settings files.")
                }

                // Option 1: Country preset (if a pack exists for the detected locale).
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXs
                    visible: firstRunWindow.hasAnyCountryPack

                    // Asked only when both directions ship a pack (with one of them the
                    // answer would change nothing) and only in that country's own
                    // language — see `locationQuestionRelevant`.
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0
                        visible: firstRunWindow.hasHomePack && firstRunWindow.hasAbroadPack
                            && firstRunWindow.locationQuestionRelevant
                        Label {
                            text: root.tr("dialog.first-run-wizard.location-title",
                                "Where are you?")
                            color: root.textColor
                            font.bold: true
                        }
                        ThemedRadioButton {
                            theme: root.uiTheme
                            Layout.fillWidth: true
                            checked: !firstRunWindow.livingAbroad
                            text: root.tr("dialog.first-run-wizard.location-home", "I am {where}")
                                .replace("{where}", firstRunWindow.countryText("in"))
                            onToggled: if (checked) firstRunWindow.livingAbroad = false
                        }
                        ThemedRadioButton {
                            theme: root.uiTheme
                            Layout.fillWidth: true
                            checked: firstRunWindow.livingAbroad
                            text: root.tr("dialog.first-run-wizard.location-abroad",
                                    "I am {where} and need access to its services")
                                .replace("{where}", firstRunWindow.countryText("outside"))
                            onToggled: if (checked) firstRunWindow.livingAbroad = true
                        }
                    }

                    // Each option shows itself chosen — accent fill and a check
                    // mark — and says so to a screen reader; the others stay plain.
                    ThemedButton {
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        text: (firstRunWindow.useAbroadPack
                                ? root.tr("dialog.first-run-wizard.option-country-preset-abroad",
                                    "Use the access rule set ({country})")
                                : root.tr("dialog.first-run-wizard.option-country-preset",
                                    "Use the rule set for your region ({country})"))
                            .replace("{country}", firstRunWindow.countryText("name"))
                        id: countryPresetOption
                        highlighted: firstRunWindow._isChosen(firstRunWindow._countryPackKey())
                        icon.source: highlighted ? root.uiIconSourceOnAccent("apply") : root.uiIconSource("load-list")
                        attention: firstRunWindow.pulseTarget === "rule-options" ? firstRunWindow.pulse : 0
                        Accessible.role: Accessible.Button
                        Accessible.checkable: true
                        Accessible.checked: firstRunWindow._isChosen(firstRunWindow._countryPackKey())
                        Accessible.description: highlighted ? firstRunWindow.chosenOptionDescription : ""
                        onClicked: firstRunWindow._applyCountryPreset()
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        wrapMode: Text.WordWrap
                        color: root.mutedTextColor
                        text: firstRunWindow.useAbroadPack
                            ? root.tr("dialog.first-run-wizard.option-country-preset-abroad-description",
                                "Everything stays on your local provider; only that country's services go through the additional connection.")
                            : root.tr("dialog.first-run-wizard.option-country-preset-description",
                                "Recommended for {country}: the ready-made rule set for your region, taken from the system's region setting. You can change it afterwards.")
                                .replace("{country}", firstRunWindow.countryText("name"))
                    }
                }
                // Option 1 fallback note when no country pack found.
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    visible: !firstRunWindow.hasAnyCountryPack
                    text: root.tr("dialog.first-run-wizard.option-country-not-available",
                        "No ready-made rule set is bundled for your region — pick a different option.")
                }

                // Every bundled set stays within reach, whatever country was detected.
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXs
                    visible: firstRunWindow.allPacks.length > 0
                    Label {
                        id: otherCountriesTitle
                        text: root.tr("dialog.first-run-wizard.other-countries",
                            "Rule set of another country")
                        color: root.textColor
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        wrapMode: Text.WordWrap
                        color: root.mutedTextColor
                        text: root.tr("dialog.first-run-wizard.other-countries-description",
                            "When the region was detected wrong, or you need the sites of another country to take the additional connection.")
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm
                        ThemedComboBox {
                            id: otherCountryCombo
                            theme: root.uiTheme
                            Layout.fillWidth: true
                            model: firstRunWindow.allPacks
                            currentIndex: -1
                            labelResolver: function(item) { return firstRunWindow._packLabel(item) }
                            displayText: root.uiRevision >= 0 && currentIndex >= 0
                                ? firstRunWindow._packLabel(firstRunWindow.allPacks[currentIndex])
                                : root.tr("rules.bundled-preset.choose", "Choose a rule set...")
                            accessibleLabel: otherCountriesTitle.text
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            text: root.tr("action.choose", "Choose")
                            highlighted: firstRunWindow._isChosen(firstRunWindow._comboPackKey(otherCountryCombo.currentIndex))
                            icon.source: highlighted ? root.uiIconSourceOnAccent("apply") : root.uiIconSource("load-list")
                            enabled: otherCountryCombo.currentIndex >= 0
                            attention: enabled && firstRunWindow.pulseTarget === "rule-options"
                                ? firstRunWindow.pulse : 0
                            Accessible.role: Accessible.Button
                            Accessible.name: otherCountriesTitle.text + ": " + text
                            Accessible.checkable: true
                            Accessible.checked: firstRunWindow._isChosen(firstRunWindow._comboPackKey(otherCountryCombo.currentIndex))
                            Accessible.description: highlighted ? firstRunWindow.chosenOptionDescription : ""
                            onClicked: firstRunWindow._applyPack(
                                firstRunWindow.allPacks[otherCountryCombo.currentIndex])
                        }
                    }
                }

                // Option 2: Built-in demo.
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXs
                    ThemedButton {
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        text: root.tr("dialog.first-run-wizard.option-builtin-demo",
                                "Use the example rules")
                        id: demoOption
                        highlighted: firstRunWindow._isChosen("demo")
                        icon.source: highlighted ? root.uiIconSourceOnAccent("apply") : root.uiIconSource("add")
                        attention: firstRunWindow.pulseTarget === "rule-options" ? firstRunWindow.pulse : 0
                        Accessible.role: Accessible.Button
                        Accessible.checkable: true
                        Accessible.checked: firstRunWindow._isChosen("demo")
                        Accessible.description: highlighted ? firstRunWindow.chosenOptionDescription : ""
                        onClicked: firstRunWindow._applyBuiltinDemo()
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        wrapMode: Text.WordWrap
                        color: root.mutedTextColor
                        text: root.tr("dialog.first-run-wizard.option-builtin-demo-description",
                            "A small example with rules of each type. Replace them with your own later.")
                    }
                }

                // Option 3: Open my rules… (two-file picker)
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXs
                    Label {
                        Layout.fillWidth: true
                        text: root.tr("dialog.first-run-wizard.option-open-file",
                                "Open my rules...")
                        color: root.textColor
                        font.bold: true
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        wrapMode: Text.WordWrap
                        color: root.mutedTextColor
                        text: root.tr("dialog.first-run-wizard.option-open-file-description",
                            "Choose one or two rules files (.txt) — one for each connection. One of them can stay without a file.")
                    }
                    // Primary route slot.
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        spacing: root.uiTheme.spacingSm
                        // Both slot captions share the wider one's width so the file
                        // names line up in either language.
                        Label {
                            id: primaryFileSlotLabel
                            text: root.tr("dialog.first-run-wizard.primary-file-label",
                                "Main connection:")
                            color: root.textColor
                            Layout.preferredWidth: Math.max(implicitWidth,
                                secondaryFileSlotLabel.implicitWidth)
                        }
                        Label {
                            Layout.fillWidth: true
                            elide: Text.ElideMiddle
                            color: firstRunWindow.pickedPrimaryPath
                                ? root.textColor : root.mutedTextColor
                            text: firstRunWindow.pickedPrimaryPath
                                ? firstRunWindow._basename(firstRunWindow.pickedPrimaryPath)
                                : root.tr("dialog.first-run-wizard.no-file-selected",
                                    "(no file selected)")
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            text: firstRunWindow.pickedPrimaryPath
                                ? root.tr("dialog.first-run-wizard.change-button", "Change...")
                                : root.tr("action.browse", "Browse...")
                            onClicked: root.openRulesDialog(firstRunOpenPrimaryDialog)
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            visible: firstRunWindow.pickedPrimaryPath !== ""
                            text: root.tr("dialog.first-run-wizard.clear-button", "Clear")
                            onClicked: firstRunWindow.pickedPrimaryPath = ""
                        }
                    }
                    // Secondary route slot.
                    RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        spacing: root.uiTheme.spacingSm
                        Label {
                            id: secondaryFileSlotLabel
                            text: root.tr("dialog.first-run-wizard.secondary-file-label",
                                "Additional connection:")
                            color: root.textColor
                            Layout.preferredWidth: Math.max(implicitWidth,
                                primaryFileSlotLabel.implicitWidth)
                        }
                        Label {
                            Layout.fillWidth: true
                            elide: Text.ElideMiddle
                            color: firstRunWindow.pickedSecondaryPath
                                ? root.textColor : root.mutedTextColor
                            text: firstRunWindow.pickedSecondaryPath
                                ? firstRunWindow._basename(firstRunWindow.pickedSecondaryPath)
                                : root.tr("dialog.first-run-wizard.no-file-selected",
                                    "(no file selected)")
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            text: firstRunWindow.pickedSecondaryPath
                                ? root.tr("dialog.first-run-wizard.change-button", "Change...")
                                : root.tr("action.browse", "Browse...")
                            onClicked: root.openRulesDialog(firstRunOpenSecondaryDialog)
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            visible: firstRunWindow.pickedSecondaryPath !== ""
                            text: root.tr("dialog.first-run-wizard.clear-button", "Clear")
                            onClicked: firstRunWindow.pickedSecondaryPath = ""
                        }
                    }
                    ThemedButton {
                        theme: root.uiTheme
                        Layout.leftMargin: root.uiTheme.spacingMd
                        text: root.tr("dialog.first-run-wizard.import-button",
                                "Use the selected files")
                        highlighted: firstRunWindow._isChosen("files")
                        icon.source: highlighted ? root.uiIconSourceOnAccent("apply") : root.uiIconSource("load-list")
                        Accessible.role: Accessible.Button
                        Accessible.checkable: true
                        Accessible.checked: firstRunWindow._isChosen("files")
                        Accessible.description: highlighted ? firstRunWindow.chosenOptionDescription : ""
                        enabled: firstRunWindow.pickedPrimaryPath !== ""
                            || firstRunWindow.pickedSecondaryPath !== ""
                        onClicked: firstRunWindow._applyOpenedFiles()
                    }
                }

                // Option 4: Start empty.
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: root.uiTheme.spacingXs
                    ThemedButton {
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        text: root.tr("dialog.first-run-wizard.option-start-empty",
                                "Start empty")
                        highlighted: firstRunWindow._isChosen("empty")
                        icon.source: highlighted ? root.uiIconSourceOnAccent("apply") : ""
                        attention: firstRunWindow.pulseTarget === "rule-options" ? firstRunWindow.pulse : 0
                        Accessible.role: Accessible.Button
                        Accessible.checkable: true
                        Accessible.checked: firstRunWindow._isChosen("empty")
                        Accessible.description: highlighted ? firstRunWindow.chosenOptionDescription : ""
                        onClicked: firstRunWindow._startEmpty()
                    }
                    Label {
                        Layout.fillWidth: true
                        Layout.leftMargin: root.uiTheme.spacingMd
                        wrapMode: Text.WordWrap
                        color: root.mutedTextColor
                        text: root.tr("dialog.first-run-wizard.option-start-empty-description",
                            "No rules. Add or import them whenever you want.")
                    }
                }

                // Which starting rules Finish imports, framed right under the
                // options so the click visibly lands; another option replaces it.
                Rectangle {
                    id: ruleSetChoiceLine
                    Layout.fillWidth: true
                    Layout.preferredHeight: ruleSetChoiceRow.implicitHeight + 2 * root.uiTheme.spacingSm
                    radius: 4
                    readonly property bool failed: firstRunWindow.chosenStartError !== ""
                    readonly property bool chosen: firstRunWindow.chosenStart !== null
                    readonly property color tone: failed ? root.uiTheme.colorDanger
                        : (chosen ? root.uiTheme.colorAccent : root.uiTheme.colorBorder)
                    color: Qt.rgba(tone.r, tone.g, tone.b, chosen || failed ? 0.12 : 0.0)
                    border.color: tone
                    border.width: chosen || failed ? 2 : 1
                    RowLayout {
                        id: ruleSetChoiceRow
                        anchors.fill: parent
                        anchors.margins: root.uiTheme.spacingSm
                        spacing: root.uiTheme.spacingSm
                        Image {
                            Layout.alignment: Qt.AlignTop
                            visible: ruleSetChoiceLine.chosen && !ruleSetChoiceLine.failed
                            source: root.uiIconSource("apply")
                            sourceSize.width: 20
                            sourceSize.height: 20
                            Accessible.ignored: true
                        }
                        Label {
                            id: ruleSetChoiceText
                            Layout.fillWidth: true
                            Layout.preferredWidth: 0
                            wrapMode: Text.WordWrap
                            font.bold: ruleSetChoiceLine.chosen || ruleSetChoiceLine.failed
                            color: ruleSetChoiceLine.failed
                                ? root.uiTheme.colorDanger
                                : (ruleSetChoiceLine.chosen ? root.textColor : root.mutedTextColor)
                            text: root.uiRevision >= 0
                                ? (firstRunWindow.chosenStartError !== ""
                                    ? firstRunWindow.chosenStartError
                                    : (firstRunWindow.chosenStart !== null
                                        ? root.tr("dialog.first-run-wizard.rule-set-chosen",
                                            "Starting rules: {name}. They are imported when you press Finish; choose another option above to change them.")
                                            .replace("{name}", firstRunWindow.chosenStart.label)
                                        : root.tr("dialog.first-run-wizard.rule-set-none",
                                            "Choose a rule set, or \"Start empty\", to go on.")))
                                : ""
                            Accessible.role: Accessible.StaticText
                            Accessible.name: text
                        }
                    }
                }
            }

            // Protection defaults: sent when the review page is reached and on
            // every way out, so they are in force before the first rules apply.
            ColumnLayout {
                id: wizardStepOptions
                visible: firstRunWindow.step === 3
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingXs

                Label {
                    text: root.tr("dialog.first-run-wizard.protection-title",
                        "Protection")
                    color: root.textColor
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    text: root.tr("dialog.first-run-wizard.protection-description",
                        "Recommended for everyone. Each of these can be changed later in Settings.")
                }
                // The same three-way choice as Settings; the levels share this
                // parent, which makes them exclusive.
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0
                    Accessible.role: Accessible.Grouping
                    Accessible.name: leakProtectionTitle.text
                    Label {
                        id: leakProtectionTitle
                        text: root.tr("settings.routing.kill-switch.title", "Leak protection")
                        color: root.textColor
                        font.bold: true
                        topPadding: root.uiTheme.spacingSm
                    }
                    ThemedRadioButton {
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        visible: firstRunWindow.leakLevelsOffered.indexOf("off") >= 0
                        checked: firstRunWindow.leakProtectionChoice === "off"
                        text: root.tr("settings.routing.leak-protection.option-off", "Off")
                            + " — " + root.tr("settings.routing.leak-protection.note-off",
                                "If the additional connection drops, traffic continues over your main connection.")
                        onToggled: if (checked) firstRunWindow.chooseLeakProtection("off")
                    }
                    ThemedRadioButton {
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        visible: firstRunWindow.leakLevelsOffered.indexOf("sites") >= 0
                        checked: firstRunWindow.leakProtectionChoice === "sites"
                        text: root.tr("settings.routing.leak-protection.option-sites", "Routed sites")
                            + " — " + root.tr("settings.routing.leak-protection.note-sites",
                                "What your rules send through the additional connection never goes out the main one while strict protection is on, as it is by default. Everything else keeps working, though a few ordinary sites may not open until the additional connection is back.")
                        onToggled: if (checked) firstRunWindow.chooseLeakProtection("sites")
                    }
                    ThemedRadioButton {
                        theme: root.uiTheme
                        Layout.fillWidth: true
                        checked: firstRunWindow.leakProtectionChoice === "everything"
                        text: root.tr("settings.routing.leak-protection.option-everything", "Everything")
                            + " — " + root.tr("settings.routing.leak-protection.note-everything",
                                "Nothing leaves except through the additional connection, your local network and what your rules send over the main connection. If the additional connection drops, the internet waits until it returns.")
                        onToggled: if (checked) firstRunWindow.chooseLeakProtection("everything")
                    }
                }
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    visible: firstRunWindow.leakHoldsNow
                    text: root.uiRevision >= 0
                        ? root.tr("dialog.leak-holds-now.body",
                            "With leak protection set to Everything, traffic is held right away: the internet stops until the additional connection returns.")
                        : ""
                }
                CheckBox {
                    id: firstRunDohCheck
                    Layout.fillWidth: true
                    checked: firstRunWindow.wantDohLockdown
                    text: root.tr("dialog.first-run-wizard.protection-doh-lockdown",
                        "Keep browsers from resolving routed sites past NetRuleRouter")
                    contentItem: Label {
                        text: firstRunDohCheck.text
                        leftPadding: firstRunDohCheck.indicator.width + firstRunDohCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: {
                        firstRunWindow._protectionTouched = true
                        firstRunWindow.wantDohLockdown = checked
                    }
                }
                CheckBox {
                    id: firstRunFakeIpCheck
                    Layout.fillWidth: true
                    visible: root.serviceStabilitySupported && root.supports("fakeIp")
                    checked: firstRunWindow.wantFakeIp
                    text: root.tr("dialog.first-run-wizard.protection-fake-ip",
                        "Route sites by name, so an address shared with another site is not dragged along (uses a virtual network adapter; on Windows this loads its Wintun driver)")
                    contentItem: Label {
                        text: firstRunFakeIpCheck.text
                        leftPadding: firstRunFakeIpCheck.indicator.width + firstRunFakeIpCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: {
                        firstRunWindow._fakeIpTouched = true
                        firstRunWindow.wantFakeIp = checked
                    }
                }
                CheckBox {
                    id: firstRunDiagLogsCheck
                    Layout.fillWidth: true
                    visible: root.serviceStabilitySupported
                    checked: firstRunWindow.wantDiagnosticLogs
                    text: root.tr("dialog.first-run-wizard.protection-diagnostic-logs",
                        "Write detailed diagnostic logs (only needed to report a problem)")
                    contentItem: Label {
                        text: firstRunDiagLogsCheck.text
                        leftPadding: firstRunDiagLogsCheck.indicator.width + firstRunDiagLogsCheck.spacing
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: {
                        firstRunWindow._stabilityTouched = true
                        firstRunWindow.wantDiagnosticLogs = checked
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: firstRunDiagLogsCheck.indicator.width + firstRunDiagLogsCheck.spacing
                    visible: root.serviceStabilitySupported
                    spacing: root.uiTheme.spacingSm
                    LogWindowDurationCombo {
                        id: firstRunDiagLogsDurationCombo
                        root: firstRunWindow.root
                        theme: firstRunWindow.root.uiTheme
                        labelFor: function(change) {
                            return firstRunWindow.root.verboseLoggingChangeLabel(change)
                        }
                        enabled: firstRunWindow.wantDiagnosticLogs
                        Layout.preferredWidth: 240
                        // No "off" here: the checkbox above is the on/off control.
                        options: ["one-hour", "four-hours", "until-restart"]
                        currentIndex: options.indexOf(firstRunWindow.diagnosticLogsDuration)
                        displayText: firstRunWindow.root.verboseLoggingChangeLabel(firstRunWindow.diagnosticLogsDuration)
                        onActivated: function(index) {
                            firstRunWindow._stabilityTouched = true
                            firstRunWindow.diagnosticLogsDuration = options[index]
                        }
                        Accessible.name: firstRunWindow.root.tr(
                            "settings.diagnostics.service-stability.verbose.label",
                            "Verbose service logging") + ": " + displayText
                    }
                    Item { Layout.fillWidth: true }
                }
                CheckBox {
                    id: firstRunMuteBlockNoticesCheck
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    visible: root.blockNoticesSupported
                    checked: firstRunWindow.wantBlockNoticesMuted
                    text: root.tr("dialog.first-run-wizard.protection-mute-block-notices",
                        "Do not show notifications about blocked traffic (rule suggestions still arrive)")
                    contentItem: Label {
                        text: firstRunMuteBlockNoticesCheck.text
                        leftPadding: firstRunMuteBlockNoticesCheck.indicator.width + firstRunMuteBlockNoticesCheck.spacing
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: firstRunWindow.wantBlockNoticesMuted = checked
                }
                CheckBox {
                    id: firstRunTrayAutostartCheck
                    Layout.fillWidth: true
                    visible: root.supports("autostart")
                    checked: firstRunWindow.wantTrayAutostart
                    text: root.tr("settings.general.autostart.label",
                        "Start NetRuleRouter tray automatically at sign-in")
                    contentItem: Label {
                        text: firstRunTrayAutostartCheck.text
                        leftPadding: firstRunTrayAutostartCheck.indicator.width + firstRunTrayAutostartCheck.spacing
                        color: root.textColor
                        wrapMode: Text.WordWrap
                        verticalAlignment: Text.AlignVCenter
                    }
                    onToggled: firstRunWindow.wantTrayAutostart = checked
                }
                // Told apart from the autostart above: this holds with the
                // tray closed, whatever is chosen there.
                Label {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                    visible: root.supports("siteNoticeWithoutTray")
                    text: root.tr("dialog.first-run-wizard.site-notice-note",
                        "Even with the tray closed, NetRuleRouter tells you when a site you open does not open over the main connection. You can turn this off in Settings, Notifications.")
                    color: root.mutedTextColor
                    wrapMode: Text.WordWrap
                }
            }

            // What Finish applies, in one place before it is pressed.
            ColumnLayout {
                id: wizardStepReview
                visible: firstRunWindow.step === 4
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm

                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    color: root.mutedTextColor
                    text: root.tr("dialog.first-run-wizard.review-description",
                        "Check your choices. Finish applies them; Back returns to any step. Each of them can be changed later.")
                }
                Repeater {
                    model: root.uiRevision >= 0 && firstRunWindow.step === 4
                        ? firstRunWindow._reviewLines() : []
                    Label {
                        required property string modelData
                        Layout.fillWidth: true
                        Layout.preferredWidth: 0
                        wrapMode: Text.WordWrap
                        color: root.textColor
                        text: modelData
                        Accessible.role: Accessible.StaticText
                        Accessible.name: text
                    }
                }
            }
        }
    }

    // The way on from the window, pinned under the scrolling area so it never
    // needs scrolling; declared after it so Tab reaches it last. Next and Back
    // only turn pages: the connections, the starting rules and the protection
    // are committed by `onClosing`.
    Rectangle {
        id: finishBar
        anchors {
            left: parent.left
            right: parent.right
            bottom: parent.bottom
        }
        height: finishRow.implicitHeight + root.uiTheme.spacingMd * 2
        color: root.panelColor
        Rectangle {
            anchors { left: parent.left; right: parent.right; top: parent.top }
            height: 1
            color: root.uiTheme.colorBorder
        }
        RowLayout {
            id: finishRow
            anchors {
                left: parent.left
                right: parent.right
                verticalCenter: parent.verticalCenter
                leftMargin: root.uiTheme.spacingLg
                rightMargin: root.uiTheme.spacingLg
            }
            spacing: root.uiTheme.spacingMd
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.back", "Back")
                visible: firstRunWindow.step > 0
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: firstRunWindow.step -= 1
            }
            Label {
                id: finishHint
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                // Kept in the row on every page as its spacer; worded only
                // where Finish is.
                opacity: finishButton.visible ? 1 : 0
                text: root.tr("dialog.first-run-wizard.finish-hint",
                    "Applies the choices above: connections, starting rules and protection.")
                Accessible.ignored: !finishButton.visible
            }
            ThemedButton {
                id: nextButton
                theme: root.uiTheme
                text: root.tr("action.next", "Next")
                visible: firstRunWindow.step < firstRunWindow.stepCount - 1
                highlighted: enabled
                enabled: firstRunWindow._nextAllowed()
                attention: firstRunWindow.pulseTarget === "next" ? firstRunWindow.pulse : 0
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: enabled ? "" : ruleSetChoiceText.text
                onClicked: firstRunWindow.step += 1
            }
            ThemedButton {
                id: finishButton
                theme: root.uiTheme
                text: root.tr("action.finish", "Finish")
                visible: firstRunWindow.step === firstRunWindow.stepCount - 1
                highlighted: true
                attention: firstRunWindow.pulseTarget === "finish" ? firstRunWindow.pulse : 0
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: finishHint.text
                onClicked: {
                    root.updatePrefs({ firstRunCompleted: true })
                    firstRunWindow.close()
                }
            }
        }
    }
}
