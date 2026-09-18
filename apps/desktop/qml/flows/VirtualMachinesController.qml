import QtQuick 2.15

// Non-visual controller for VIRTUAL MACHINES (sidebar → Rules → Virtual
// machines): the launcher's inventory of hypervisors and their machines, and
// the application rules that route a hypervisor's traffic.
//
// A machine cannot be routed on its own: every machine of a hypervisor runs as
// the same program, so the rules name the hypervisor's traffic processes and
// the route applies to all of its machines at once.
QtObject {
    id: virtualMachinesController

    /// The ApplicationWindow: the RPC transport and the rules model live there.
    property var root

    /// Wire rows from the last `local.vm-inventory.list`; only present
    /// hypervisors are listed.
    property var hypervisors: []
    property bool scanning: false
    property bool scanFailed: false
    /// The screen and its sidebar entry exist only when a hypervisor's network
    /// or machines were found.
    readonly property bool available: hypervisors.length > 0
    /// Bumped on every rules edit so bindings over `routeOf` re-read the model.
    property int rulesRevision: 0

    property Connections _rulesWatch: Connections {
        target: virtualMachinesController.root
        function onRulesModelEdited() { virtualMachinesController.rulesRevision += 1 }
    }
    property Connections _rulesCountWatch: Connections {
        target: virtualMachinesController.root ? virtualMachinesController.root.rulesModel : null
        function onCountChanged() { virtualMachinesController.rulesRevision += 1 }
    }

    function refresh() {
        if (!root || !root.bridgeAvailable || scanning) return
        var corr = root.rpc.rpcVmInventoryList()
        if (!corr || corr === "") {
            scanFailed = true
            return
        }
        scanning = true
        root.rpc.registerRpcCallback(corr, function(ok, payload, code, msg) {
            virtualMachinesController.scanning = false
            if (!ok || !payload) {
                virtualMachinesController.scanFailed = true
                console.log("vm inventory failed:", code, msg)
                return
            }
            virtualMachinesController.scanFailed = false
            virtualMachinesController.hypervisors = payload.hypervisors || []
        })
    }

    /// The route the rules give `hypervisor`'s traffic: "primary" when no
    /// enabled application rule names its processes, that rule's route when
    /// every process has the same one, "mixed" otherwise.
    function routeOf(hypervisor) {
        var names = (hypervisor && hypervisor.trafficProcesses) || []
        if (!root || names.length === 0) return "primary"
        var routes = []
        for (var n = 0; n < names.length; n += 1) {
            var wanted = String(names[n]).toLowerCase()
            var route = "primary"
            for (var i = 0; i < root.rulesModel.count; i += 1) {
                var row = root.rulesModel.get(i)
                if (String(row.ruleType || "") === "application"
                        && row.enabled !== false
                        && String(row.matchValue || "").toLowerCase() === wanted) {
                    route = String(row.targetRoute || "primary")
                    break
                }
            }
            routes.push(route)
        }
        for (var r = 1; r < routes.length; r += 1) {
            if (routes[r] !== routes[0]) return "mixed"
        }
        return routes[0]
    }

    /// Put every traffic process of `hypervisor` on `route` through the same
    /// rules edit the application groups use: "primary" removes the rules,
    /// "secondary" adds or retargets them. The result waits in the rules list
    /// to be applied like any other edit.
    function setRoute(hypervisor, route) {
        var names = (hypervisor && hypervisor.trafficProcesses) || []
        var assignments = []
        for (var i = 0; i < names.length; i += 1) {
            assignments.push({
                displayName: String(names[i]),
                matchValue: String(names[i]),
                route: route,
                kind: "hypervisor"
            })
        }
        if (assignments.length > 0) root._applyAppGroupRoutes(assignments)
    }
}
