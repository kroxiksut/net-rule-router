import QtQuick 2.15
import QtQuick.Dialogs
import "../lib/pure.js" as Pure

// The full settings export (YAML): asks where to save it and writes it. One
// funnel for File → "Export settings…" and the button in Settings → Presets.
// `nrrNativeBridge` is a global QML context property, referenced bare.
Item {
    id: controller
    property var root
    visible: false

    /// Asks for the file, then exports into it.
    function chooseAndExport() {
        saveDialog.open()
    }

    FileDialog {
        id: saveDialog
        fileMode: FileDialog.SaveFile
        title: controller.root ? controller.root.tr(
            "settings.presets.full-settings-dialog-title",
            "Save settings export as...") : ""
        nameFilters: controller.root ? [
            controller.root.tr("settings.presets.yaml-filter", "YAML files (*.yaml)"),
            controller.root.tr("rules.dialog.all-filter", "All files (*)")
        ] : []
        defaultSuffix: "yaml"
        onAccepted: controller.exportTo(Pure.localPathFromFileUrl(selectedFile))
    }

    function exportTo(path) {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSettingsExportFull !== "function") {
            root.statusLine = root.tr(
                "status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        // The bound files and the sections of them this system does not apply
        // live with us, not in the service: the export learns them from us,
        // as "Save to file" does.
        var writer = root.boundFilesController.writer
        writer.readPassthroughSections("primary", function(primarySections) {
            writer.readPassthroughSections("secondary", function(secondarySections) {
                _request(path, primarySections, secondarySections)
            })
        })
    }

    function _request(path, primarySections, secondarySections) {
        var corr = nrrNativeBridge.rpcSettingsExportFull(
            String(root.prefs.lastSavedPathPrimary || ""),
            String(root.prefs.lastSavedPathSecondary || ""),
            primarySections || ({}),
            secondarySections || ({}))
        root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
            if (!ok) {
                root.statusLine = root.tr("status.export-rpc-failed", "Export failed: ")
                    + ((typeof root.ipcErrorLabel === "function")
                        ? root.ipcErrorLabel(String(code || "unknown"))
                        : String(code || "unknown"))
                return
            }
            var b64 = (p && p["yaml-bytes-b64"]) || ""
            if (!nrrNativeBridge.writeFileBytes(path, b64)) {
                root.statusLine = root.tr(
                    "status.settings-export-write-failed",
                    "Cannot write settings file to the chosen path.")
                return
            }
            root.statusLine = root.tr(
                "settings.presets.full-settings-exported",
                "Full settings exported.")
        })
    }
}
