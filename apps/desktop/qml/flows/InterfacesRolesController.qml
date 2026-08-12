import QtQuick 2.15
import "../lib/pure.js" as Pure

// Non-visual controller for the Interfaces & roles surface, extracted from
// Main.qml (thin-shell rule). Owns: live adapter refresh + shared-model
// rebuild, primary/secondary role assign/unassign, the stale-GUID auto-heal /
// re-confirm path, and the VPN-split conflict helpers. The shell keeps the
// shared adapter STATE it writes (`interfacesRowsAll` / `interfacesModel`),
// which the top banners and the Interfaces panel read. RPC goes through
// `root.rpc`; adapter bindings are pushed to the service via
// `root.routePolicyController.pushRouteBindingToService`; `nrrNativeBridge` is a
// global QML context property, referenced bare. Reached as
// `root.interfacesRolesController` from InterfacesRoutesSection / TopBannerStack.
QtObject {
    id: interfacesRolesController
    property var root

    function rebuildInterfacesModel() {
        Pure.clearModel(root.interfacesModel)
        for (var r = 0; r < root.interfacesRowsAll.length; r += 1) {
            var row = root.interfacesRowsAll[r]
            if (!root.prefs.showBluetoothAdapters && row.isBluetoothLike) continue
            // NetRuleRouter's own fake-IP TUN adapter is unconditionally
            // excluded from the role-assignment surface (no toggle): assigning
            // primary/secondary to our own tunnel is always a user error.
            // Traffic statistics read their own service-side model, so the
            // adapter stays visible there. See Pure.isOwnFakeIpTunRow for the
            // identity choice and the QML-vs-provider trade-off.
            if (Pure.isOwnFakeIpTunRow(row)) continue
            // Coerce a null `selectedRole` (unassigned adapters arrive as
            // JSON null) to "" before append: a null member makes ListModel
            // skip creating the role entirely, breaking every later read of
            // `model.selectedRole` (the "selectedRole is null" log spam).
            if (row.selectedRole === null || row.selectedRole === undefined) {
                row.selectedRole = ""
            }
            root.interfacesModel.append(row)
        }
    }

    // Live adapter refresh. The adapter list is
    // enumerated once at GUI-process start (baked into the launch
    // context) and the long-lived Qt host never re-enumerated, so a
    // runtime-appearing adapter (VPN up, USB dongle, VM NIC) only showed
    // after relaunching. The service re-enumerates live on every
    // SnapshotInterfacesGet and now carries the rich `rows`; this pulls
    // them on demand and rebuilds the shared model. Role bindings live in
    // prefs, not in the service rows, so they are re-applied after the
    // rebuild. Empty `rows` (older service) leaves the current list
    // untouched rather than blanking it.
    /// True while an external-address probe is in flight, so the button can
    /// disable itself and the section can say what is happening.
    property bool externalIpProbeBusy: false

    /// User-initiated: re-enumerate adapters AND ask each one what its external
    /// address looks like from outside. Deliberately NOT part of
    /// `refreshInterfacesFromService` — that one also runs automatically (on
    /// reconnect, after a rules refresh), and a probe leaves the machine, so it
    /// must never fire without the user asking for it.
    function probeExternalAddresses() {
        if (externalIpProbeBusy) return
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcInterfacesRefresh !== "function") {
            return
        }
        externalIpProbeBusy = true
        // [extip] lines land in the launcher log via the host's stdout —
        // the client half of the probe was invisible in the HW-0730 triage.
        console.log("[extip] external-address refresh requested")
        var corr = nrrNativeBridge.rpcInterfacesRefresh()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            interfacesRolesController.externalIpProbeBusy = false
            if (!ok) {
                console.log("[extip] refresh failed: " + String(errorCode || "unknown")
                            + " " + String(errorMessage || ""))
                root.statusLine = root.tr("interfaces.external-ip.probe-failed",
                    "Could not determine the external address: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(errorCode || "unknown"))
                        : String(errorCode || "unknown"))
                return
            }
            var rowCount = (payload && payload.rows) ? payload.rows.length : 0
            console.log("[extip] refresh done, rows: " + rowCount)
            interfacesRolesController._applyInterfaceRows(payload)
            root.statusLine = root.tr("interfaces.external-ip.probe-done",
                "External address check finished.")
        })
    }

    /// Shared tail of both refresh paths: map the wire rows onto the model,
    /// re-apply the role bindings that live in prefs, and repaint.
    ///
    /// A live payload is the ONLY source that feeds the external-IP sidecar
    /// cache (`_persistExternalIpCache`) — cold-start rows can come from the
    /// mock backend fallback when the service is unreachable, and caching
    /// THOSE would paint a fake "last known" address later.
    function _applyInterfaceRows(payload) {
        if (!payload) return
        var wireRows = payload.rows || []
        if (!wireRows || wireRows.length === 0) return
        var mapped = []
        for (var i = 0; i < wireRows.length; i += 1) {
            var mappedRow = Pure.mapWireInterfaceRow(wireRows[i])
            if (mappedRow) mapped.push(mappedRow)
        }
        if (mapped.length === 0) return
        root.interfacesRowsAll = mapped
        _reapplyInterfaceRolesFromPrefs()
        rebuildInterfacesModel()
        _persistExternalIpCache(mapped)
        root.uiRevision += 1
    }

    function refreshInterfacesFromService() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSnapshotInterfacesGet !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSnapshotInterfacesGet()
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            if (!ok || !payload) return
            // A live adapter refresh (VPN up/down) can change the VPN-split
            // banner trigger; `_applyInterfaceRows` already bumps uiRevision,
            // which is what repaints the (JS-sourced) adapter name in the
            // banner text AND re-evaluates the persisted-ack comparison in
            // `secondaryBannerVisible`, even without a mode change (the name
            // is not a tracked property read). No session reset is needed:
            // the dismiss is a persisted per-adapter ack
            // (`prefs.secondarySplitAckAdapterName`), so a different adapter
            // auto-shows and the same acknowledged adapter stays hidden.
            interfacesRolesController._applyInterfaceRows(payload)
        })
    }

    /// Load the sidecar's cached last-known external IPs once (cold start).
    /// Populates `root.externalIpCache` (adapter key -> {ip, observedAtMs})
    /// for the offline delegate fallback in InterfacesRoutesSection. Async;
    /// until the callback lands, rows simply show nothing for an adapter
    /// with no live data yet, same as before this feature existed.
    function loadExternalIpCache() {
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarExternalIpReadAll !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSidecarExternalIpReadAll()
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) {
                console.log("sidecar.external-ip.read-all failed:", code, msg)
                return
            }
            var entries = (payload && payload.entries) || {}
            var cache = {}
            for (var key in entries) {
                if (!Object.prototype.hasOwnProperty.call(entries, key)) continue
                var e = entries[key] || {}
                cache[key] = {
                    ip: String(e["external-ip"] || ""),
                    observedAtMs: Number(e["observed-at-ms"] || 0)
                }
            }
            root.externalIpCache = cache
            root.uiRevision += 1
        })
    }

    /// Persist every resolved external IP from a fresh LIVE snapshot into the
    /// sidecar so it survives a GUI restart and a later service outage. Also
    /// updates `root.externalIpCache` in memory so the offline fallback in
    /// InterfacesRoutesSection reflects it immediately, without waiting for
    /// the write RPC's own round trip.
    function _persistExternalIpCache(mapped) {
        var entries = []
        // A COPY, not the live object: assigning a `var` property the same
        // reference back emits no change, so bindings would keep the old value.
        var cache = {}
        var existing = root.externalIpCache || {}
        for (var k in existing) {
            if (Object.prototype.hasOwnProperty.call(existing, k)) cache[k] = existing[k]
        }
        var nowMs = Date.now()
        for (var i = 0; i < mapped.length; i += 1) {
            var row = mapped[i]
            var of = row.observedFacts || {}
            var ip = String(of.externalIp || "")
            if (ip === "") continue
            var key = Pure.externalIpCacheKey(row.persistentId, row.name)
            entries.push({ key: key, "external-ip": ip, "observed-at-ms": nowMs })
            cache[key] = { ip: ip, observedAtMs: nowMs }
            // A second entry under the ROLE. The tray shows these addresses by
            // route and, with the service stopped, has no way to learn which
            // adapter carries which role — it would have nothing to look up.
            var role = String(row.selectedRole || "")
            if (role === "primary" || role === "secondary") {
                var roleKey = Pure.externalIpRoleCacheKey(role)
                entries.push({ key: roleKey, "external-ip": ip, "observed-at-ms": nowMs })
                cache[roleKey] = { ip: ip, observedAtMs: nowMs }
            }
        }
        if (entries.length === 0) return
        root.externalIpCache = cache
        if (!root.bridgeAvailable
                || typeof nrrNativeBridge === "undefined"
                || nrrNativeBridge === null
                || typeof nrrNativeBridge.rpcSidecarExternalIpWriteAll !== "function") {
            return
        }
        var corr = nrrNativeBridge.rpcSidecarExternalIpWriteAll(entries)
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            if (!ok) console.log("sidecar.external-ip.write-all failed:", code, msg)
        })
    }

    // Re-apply the user's confirmed primary/secondary role bindings (held
    // in prefs, not in the service rows) onto the freshly-mapped
    // `interfacesRowsAll` so a live refresh preserves the selection, sort
    // pinning and filter exactly like assignRole/unassignRole do.
    function _reapplyInterfaceRolesFromPrefs() {
        var primId = String(root.prefs.selectedPrimaryInterfaceId || "")
        var primName = String(root.prefs.selectedPrimaryInterfaceName || "")
        var primConfirmed = !!root.prefs.primaryRoleUserConfirmed
        var secId = String(root.prefs.selectedSecondaryInterfaceId || "")
        var secName = String(root.prefs.selectedSecondaryInterfaceName || "")
        var secConfirmed = !!root.prefs.secondaryRoleUserConfirmed
        var rows = root.interfacesRowsAll
        // Mirror the service-side stale-GUID auto-heal:
        // when the stored id is no longer among live adapters (VPN reinstalled
        // with a new GUID) fall back to a unique name match, so the GUI shows
        // the SAME binding the service is actually enforcing instead of
        // rendering the secondary as unbound. `_staleSecondaryHealRow()` returns
        // the single safe name match (null when healthy or ambiguous).
        var secHealId = ""
        if (secConfirmed && secId !== "") {
            var healRow = _staleSecondaryHealRow()
            if (healRow) {
                secHealId = String(healRow.persistentId || "")
                // Auto-confirm the reinstalled adapter (new
                // GUID, unique name match) unless the user chose manual mode.
                // Deferred to avoid re-entrancy with this reapply/rebuild pass.
                if (root.prefs.autoConfirmAdapterIdChange !== false)
                    Qt.callLater(_autoConfirmSecondaryIfEnabled)
            }
        }
        for (var i = 0; i < rows.length; i += 1) {
            var row = rows[i]
            var rid = String(row.persistentId || "")
            var rname = String(row.name || "")
            var isPrimary = primConfirmed
                && ((primId !== "" && rid === primId)
                    || (primId === "" && primName !== "" && rname === primName))
            var isSecondary = secConfirmed
                && ((secId !== "" && rid === secId)
                    || (secId === "" && secName !== "" && rname === secName)
                    || (secHealId !== "" && rid === secHealId))
            if (isPrimary) {
                row.selectedRole = "primary"
                if (row.routeState === "not-selected") row.routeState = "selected"
            } else if (isSecondary) {
                row.selectedRole = "secondary"
                if (row.routeState === "not-selected") row.routeState = "selected"
            } else {
                row.selectedRole = ""
            }
        }
    }

    /// A single live, available row the stored secondary
    /// binding should map to when the stored persistentId is STALE (absent from
    /// live rows) but the saved name matches a live adapter — i.e. the adapter
    /// was reinstalled with a new GUID. Mirrors the service-side stale-GUID
    /// auto-heal. Returns null when the binding is healthy (id present) or
    /// unhealable (no match / ambiguous). Drives the re-confirm banner so the
    /// user can update the stored id (which stops the service heal re-firing).
    /// JS mirror of the service-side
    /// `description_matches_display_name` (route_coordinator.rs:98-106):
    /// every whitespace token of the STORED name must appear (case-insensitive
    /// substring) somewhere in the live adapter text. This is looser than exact
    /// equality on purpose — a VPN that reinstalls under a longer name
    /// ("hidemy.name VPN OpenVPN Adapter" → "hidemy.name VPN 3.0 OpenVPN
    /// Adapter") still matches, so the GUI heals in lock-step with the service
    /// instead of painting the row unbound while the service is actively
    /// routing through it. The "exactly one available
    /// match" ambiguity guard in the caller bounds the looser matching, exactly
    /// like the service's own guard.

    function _staleSecondaryHealRow() {
        if (!root.prefs.secondaryRoleUserConfirmed) return null
        var secId = String(root.prefs.selectedSecondaryInterfaceId || "")
        var secName = String(root.prefs.selectedSecondaryInterfaceName || "")
        if (secId === "" || secName === "") return null
        var rows = root.interfacesRowsAll || []
        var idPresent = false
        var match = null
        var ambiguous = false
        for (var i = 0; i < rows.length; i += 1) {
            var r = rows[i]
            if (String(r.persistentId) === secId) idPresent = true
            if ((Pure.storedNameMatchesLive(secName, r.name)
                        || Pure.storedNameMatchesLive(secName, r.description))
                    && String(r.availability) === "available") {
                if (match === null) match = r
                else ambiguous = true
            }
        }
        if (idPresent || ambiguous) return null
        return match
    }

    /// True when a confirmed secondary binding maps to NO live
    /// adapter: its stored id is absent AND there is no unique available
    /// name-match to auto-heal to (the adapter was uninstalled, the secondary adapter is not
    /// started, it was renamed beyond recognition, or the name is ambiguous).
    /// Distinct from `_staleSecondaryHealRow` (which returns non-null only when
    /// there IS a single safe name match). Drives the "adapter not found"
    /// banner; false while the binding is healthy (id present) or auto-healable.
    function _secondaryUnresolved() {
        if (!root.prefs.secondaryRoleUserConfirmed) return false
        var secId = String(root.prefs.selectedSecondaryInterfaceId || "")
        var secName = String(root.prefs.selectedSecondaryInterfaceName || "")
        if (secId === "" && secName === "") return false
        var rows = root.interfacesRowsAll || []
        for (var i = 0; i < rows.length; i += 1) {
            // Stored id present among live adapters → resolved (even if the
            // adapter is currently down — it is still the right one).
            if (secId !== "" && String(rows[i].persistentId) === secId) return false
        }
        // Id absent → resolvable only via a unique available name match, which
        // the auto-heal / re-confirm path owns. If that exists, not "unresolved".
        if (_staleSecondaryHealRow() !== null) return false
        return true
    }

    /// "remembered but currently absent" role bindings. Returns an
    /// array of { role, id, name } for each CONFIRMED primary/secondary binding
    /// whose adapter is NOT present among the live adapters — neither by stored
    /// persistentId nor by the version-stripped SYMMETRIC name match the service
    /// uses to heal (`Pure.storedNameMatchesLive`). Using the same matcher means a
    /// ghost row never appears while the service has already healed the binding
    /// to a live sibling under a slightly different name (e.g. "…VPN…" ↔
    /// "…VPN 3.0…"). This is exactly the VPN-TAP case: hidemy.name removes its
    /// TAP adapter when the tunnel is down, so the remembered secondary maps to
    /// no live adapter and the Interfaces section paints a muted ghost row so
    /// the user can confirm NRR still remembers it. Empty array when every
    /// remembered binding maps to a live adapter. Display-only — no mutation.
    function rememberedAbsentBindings() {
        var rows = root.interfacesRowsAll || []
        function _presentAmongLive(id, name) {
            for (var i = 0; i < rows.length; i += 1) {
                var r = rows[i]
                if (id !== "" && String(r.persistentId || "") === id) return true
                if (name !== ""
                        && (Pure.storedNameMatchesLive(name, r.name)
                            || Pure.storedNameMatchesLive(name, r.description)))
                    return true
            }
            return false
        }
        var out = []
        if (root.prefs.primaryRoleUserConfirmed) {
            var pid = String(root.prefs.selectedPrimaryInterfaceId || "")
            var pname = String(root.prefs.selectedPrimaryInterfaceName || "")
            if ((pid !== "" || pname !== "") && !_presentAmongLive(pid, pname))
                out.push({ role: "primary", id: pid, name: pname })
        }
        if (root.prefs.secondaryRoleUserConfirmed) {
            var sid = String(root.prefs.selectedSecondaryInterfaceId || "")
            var sname = String(root.prefs.selectedSecondaryInterfaceName || "")
            if ((sid !== "" || sname !== "") && !_presentAmongLive(sid, sname))
                out.push({ role: "secondary", id: sid, name: sname })
        }
        return out
    }

    /// Re-confirm a reinstalled secondary adapter: adopt the healed live id as
    /// the stored binding and push it to the service so its stored id is fresh
    /// (the service was already routing via the name-heal; this just stops the
    /// heal from re-firing every reconcile and the GUI from diverging).
    function _reconfirmSecondaryBinding() {
        var r = _staleSecondaryHealRow()
        if (!r) return
        // Re-confirming rebinds
        // and pushes to the service, so it needs a running service (see
        // assignRole). Offline: leave the stale row; the heal re-fires on the
        // next reconcile once the service is back.
        if (!root._routingBackendConnected()) {
            root.statusLine = root.tr("status.bindings-require-service",
                "Adapter bindings can only be changed while the background service is running.")
            return
        }
        // Written straight to prefs rather than through `updatePrefs`: adopting
        // a reinstalled adapter's new id is bookkeeping that is pushed to the
        // service right here, so it must not light up the footer Apply — the
        // user would be asked to confirm something they never changed. The VPN
        // adapter gets a fresh id on every connect, so this fires often.
        root.prefs.selectedSecondaryInterfaceId = String(r.persistentId || "")
        root.prefs.selectedSecondaryInterfaceName = String(r.name || r.description || "")
        root.prefs.secondaryRoleUserConfirmed = true
        root.emitPrefs()
        _reapplyInterfaceRolesFromPrefs()
        rebuildInterfacesModel()
        root.routePolicyController.pushRouteBindingToService()
        root.statusLine = root.tr("status.secondary-rebound",
            "Secondary adapter re-confirmed.")
    }

    /// Auto-confirm path for a reinstalled secondary adapter.
    /// Fires (deferred) when a unique name match heals a stale GUID and the
    /// user has not switched to manual confirmation. Self-terminates: once the
    /// stored id is refreshed, `_staleSecondaryHealRow()` returns null so the
    /// deferred call is a no-op on the next pass.
    function _autoConfirmSecondaryIfEnabled() {
        if (root.prefs.autoConfirmAdapterIdChange === false) return
        if (_staleSecondaryHealRow() === null) return
        _reconfirmSecondaryBinding()
        root.statusLine = root.tr("status.secondary-auto-confirmed",
            "Additional adapter ID changed — auto-confirmed by matching name.")
    }

    // Returns the index of the adapter currently holding `role`, or -1 if no
    // adapter is bound to that role yet. Used by the GUI to grey-out the
    // role button on every other adapter so the user must explicitly
    // unassign before reassigning.
    function adapterIndexHoldingRole(role) {
        for (var i = 0; i < root.interfacesModel.count; i += 1) {
            if (String(root.interfacesModel.get(i).selectedRole || "") === role) return i
        }
        return -1
    }
    function unassignRole(index, role) {
        // Adapter bindings are
        // NOT parked offline: they drive route enforcement directly, so changing
        // them only makes sense against a running service. Block + explain.
        if (!root._routingBackendConnected()) {
            root.statusLine = root.tr("status.bindings-require-service",
                "Adapter bindings can only be changed while the background service is running.")
            return
        }
        var selected = root.interfacesModel.get(index)
        var selectedId = String(selected.persistentId || "")
        var selectedName = String(selected.name || "")
        for (var i = 0; i < root.interfacesRowsAll.length; i += 1) {
            var row = root.interfacesRowsAll[i]
            var matchesSelected = (selectedId !== "" && String(row.persistentId || "") === selectedId)
                || (selectedId === "" && String(row.name || "") === selectedName)
            if (matchesSelected && row.selectedRole === role) {
                row.selectedRole = ""
                if (row.routeState === "selected") row.routeState = "not-selected"
            }
        }
        rebuildInterfacesModel()
        var patch = {}
        if (role === "primary") {
            patch.selectedPrimaryInterfaceId = ""
            patch.selectedPrimaryInterfaceName = ""
            patch.primaryRoleUserConfirmed = false
        } else {
            patch.selectedSecondaryInterfaceId = ""
            patch.selectedSecondaryInterfaceName = ""
            patch.secondaryRoleUserConfirmed = false
        }
        root.updatePrefs(patch)
        root.emitPrefs()
        root.statusLine = root.tr("status.role-unassigned",
            "{role} unassigned").replace("{role}", root.routeLabel(role))
        // Mirror the binding into the service policy so enforcement sees the
        // cleared slot. Unbinding must be explicit: a blank pref alone means
        // "leave as is" on the service side, never "unbind".
        root.routePolicyController.pushRouteBindingToService(
            role === "primary" ? { unbindPrimary: true } : { unbindSecondary: true })
    }
    /// The live mapped row behind a model entry. `interfacesModel` is a
    /// ListModel, so its nested `derivedAssessment` is not the plain JS object
    /// the pure helpers expect — always reach back into `interfacesRowsAll`.
    /// Returns null when nothing matches.
    function _liveRowByIdOrName(id, name) {
        var rows = root.interfacesRowsAll || []
        for (var i = 0; i < rows.length; i += 1) {
            var r = rows[i]
            if (id !== "" && String(r.persistentId || "") === id) return r
            if (id === "" && name !== "" && String(r.name || "") === name) return r
        }
        return null
    }

    /// The bound secondary row when it cannot carry traffic out (host-only
    /// virtual adapter, or no gateway and no default route), else null. Read by
    /// the leak-protection toggle before it arms.
    function unroutableBoundSecondaryRow() {
        var rows = root.interfacesRowsAll || []
        for (var i = 0; i < rows.length; i += 1) {
            if (String(rows[i].selectedRole || "") !== "secondary") continue
            return Pure.interfaceCannotCarryTrafficOut(rows[i]) ? rows[i] : null
        }
        return null
    }

    /// `unroutableConfirmed` is set by the confirm dialog's proceed callback so
    /// the second pass skips the guardrail. Every other caller omits it.
    function assignRole(index, role, unroutableConfirmed) {
        // See unassignRole.
        if (!root._routingBackendConnected()) {
            root.statusLine = root.tr("status.bindings-require-service",
                "Adapter bindings can only be changed while the background service is running.")
            return
        }
        var selected = root.interfacesModel.get(index)
        var selectedId = String(selected.persistentId || "")
        var selectedName = String(selected.name || "")
        // An adapter with no way out to the network is a legal secondary, but
        // rules aimed at it stop being routed -- and are blocked outright once
        // leak protection is armed. Say so before committing the selection; the
        // answer is honoured either way.
        if (role === "secondary" && unroutableConfirmed !== true) {
            var candidate = _liveRowByIdOrName(selectedId, selectedName)
            if (candidate && Pure.interfaceCannotCarryTrafficOut(candidate)
                    && typeof root.confirmUnroutableSecondary === "function") {
                root.confirmUnroutableSecondary(candidate, "assign", function() {
                    interfacesRolesController.assignRole(index, role, true)
                })
                return
            }
        }
        for (var i = 0; i < root.interfacesRowsAll.length; i += 1) {
            var row = root.interfacesRowsAll[i]
            var matchesSelected = (selectedId !== "" && String(row.persistentId || "") === selectedId)
                || (selectedId === "" && String(row.name || "") === selectedName)
            if (!matchesSelected && row.selectedRole === role) {
                row.selectedRole = ""
                if (row.routeState === "selected") row.routeState = "not-selected"
            }
            if (matchesSelected) {
                row.selectedRole = role
                row.routeState = "selected"
            }
        }
        rebuildInterfacesModel()

        var patch = {}
        // When the newly assigned adapter previously held the OTHER role, that
        // slot is deliberately vacated — record it so the service-side push
        // unbinds it explicitly (a blank pref alone never unbinds).
        var pushOpts = {}
        if (role === "primary") {
            patch.selectedPrimaryInterfaceId = selectedId
            patch.selectedPrimaryInterfaceName = selectedName
            patch.primaryRoleUserConfirmed = true
            if ((selectedId !== "" && selectedId === String(root.prefs.selectedSecondaryInterfaceId || ""))
                    || (selectedId === "" && selectedName !== "" && selectedName === String(root.prefs.selectedSecondaryInterfaceName || ""))) {
                patch.selectedSecondaryInterfaceId = ""
                patch.selectedSecondaryInterfaceName = ""
                patch.secondaryRoleUserConfirmed = false
                pushOpts.unbindSecondary = true
            }
        } else {
            patch.selectedSecondaryInterfaceId = selectedId
            patch.selectedSecondaryInterfaceName = selectedName
            patch.secondaryRoleUserConfirmed = true
            if ((selectedId !== "" && selectedId === String(root.prefs.selectedPrimaryInterfaceId || ""))
                    || (selectedId === "" && selectedName !== "" && selectedName === String(root.prefs.selectedPrimaryInterfaceName || ""))) {
                patch.selectedPrimaryInterfaceId = ""
                patch.selectedPrimaryInterfaceName = ""
                patch.primaryRoleUserConfirmed = false
                pushOpts.unbindPrimary = true
            }
        }
        root.updatePrefs(patch)
        root.emitPrefs()
        root.statusLine = root.routeLabel(role) + ": " + selectedName
        // Push the new binding to the service per-SID
        // policy (route.policy.update). Without this the selection lived only in
        // UiPreferences and enforcement had no secondary target.
        root.routePolicyController.pushRouteBindingToService(pushOpts)
    }

    /// Rename-tolerant ack for the VPN-split
    /// explainer. The dismiss is stored as the secondary's display name, but a
    /// VPN like hidemy.name OpenVPN reinstalls under a longer name each connect
    /// ("… VPN OpenVPN Adapter" → "… VPN 3.0 OpenVPN Adapter"), so an exact
    /// compare re-showed the banner every launch. Treat the
    /// ack as still valid when the stored name and the live name refer to the
    /// SAME adapter — either one's whitespace tokens are a subset of the other's
    /// (reusing the earlier heal predicate) — while a genuinely different secondary
    /// won't match and correctly re-shows the explainer.
    function _vpnSplitAcked() {
        var live = _vpnConflictSecondaryDisplayName()
        var ack = String((root.prefs && root.prefs.secondarySplitAckAdapterName) || "")
        if (live === "" || ack === "") return false
        if (live === ack) return true
        return Pure.storedNameMatchesLive(ack, live) || Pure.storedNameMatchesLive(live, ack)
    }
    // The bound secondary row IFF it is up and name-classified as VPN-like.
    function _vpnConflictSecondaryRow() {
        var rows = root.interfacesRowsAll || []
        for (var i = 0; i < rows.length; i += 1) {
            var r = rows[i]
            if (String(r.selectedRole) !== "secondary") continue
            if (String(r.availability) !== "available") return null
            var vpn = String(((r.derivedAssessment || {}).vpnTunnelLikelihood) || "")
            return (vpn === "likely" || vpn === "possible") ? r : null
        }
        return null
    }
    function _vpnConflictSecondaryDisplayName() {
        var r = _vpnConflictSecondaryRow()
        return r ? String(r.description || r.name || "") : ""
    }
    function _enabledSecondaryRuleCount() {
        var n = 0
        for (var i = 0; i < root.rulesModel.count; i += 1) {
            var it = root.rulesModel.get(i)
            if (String(it.targetRoute) === "secondary" && it.enabled !== false) n += 1
        }
        return n
    }
}
