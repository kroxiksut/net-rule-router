import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Dialogs
import "../../components"

// Settings → «Presets / Settings» subsection.
// Provides full route-matrix Import/Export plus the read-only
// SettingsExportFull (docs/en/rules-file-format.md Settings Export Format YAML).
//
// The same actions appear in the RulesSection toolbar (primary +
// secondary), but Settings is where users go when they want to
// configure-then-leave; toolbar buttons are the quick path.
GroupBox {
    id: group
    property var root
    title: root.tr("settings.presets.title", "Presets and settings")
    Layout.fillWidth: true

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        // ── Rationale ────────────────────────────────────────────
        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr(
                "settings.presets.description",
                "Import or export rules in plain-text format. " +
                "Each route has its own preset file; the other route's " +
                "rules are carried over from the active revision on import.")
        }

        // ── Per-route Import buttons (stacked so full RU labels fit) ──
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            ThemedButton {
                theme: root.uiTheme
                Layout.fillWidth: true
                text: root.tr(
                    "settings.presets.import-primary",
                    "Import primary route preset...")
                icon.source: root.uiIconSource("load-list")
                enabled: !root.mutationsModel.hasInFlight
                onClicked: {
                    importDialog.pendingTargetRoute = "primary"
                    root.openRulesDialog(importDialog)
                }
            }
            ThemedButton {
                theme: root.uiTheme
                Layout.fillWidth: true
                text: root.tr(
                    "settings.presets.import-secondary",
                    "Import secondary route preset...")
                icon.source: root.uiIconSource("load-list")
                enabled: !root.mutationsModel.hasInFlight
                onClicked: {
                    importDialog.pendingTargetRoute = "secondary"
                    root.openRulesDialog(importDialog)
                }
            }
        }

        // ── Per-route Export buttons (stacked so full RU labels fit) ──
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            ThemedButton {
                theme: root.uiTheme
                Layout.fillWidth: true
                text: root.tr(
                    "settings.presets.export-primary",
                    "Export primary route preset...")
                icon.source: root.uiIconSource("save")
                onClicked: {
                    exportDialog.pendingSourceRoute = "primary"
                    root.openRulesDialog(exportDialog)
                }
            }
            ThemedButton {
                theme: root.uiTheme
                Layout.fillWidth: true
                text: root.tr(
                    "settings.presets.export-secondary",
                    "Export secondary route preset...")
                icon.source: root.uiIconSource("save")
                onClicked: {
                    exportDialog.pendingSourceRoute = "secondary"
                    root.openRulesDialog(exportDialog)
                }
            }
        }

        // ── Full settings export (docs/en/rules-file-format.md Settings Export Format YAML) ──────────
        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr(
                "settings.presets.full-settings-description",
                "Export adapter bindings, behavior mode, and rules-file " +
                "paths as a single YAML file. Useful for backing up or " +
                "transferring your settings.")
        }
        ThemedButton {
            theme: root.uiTheme
            text: root.tr(
                "settings.presets.export-full-settings",
                "Export full settings (YAML)...")
            icon.source: root.uiIconSource("save")
            onClicked: settingsExportDialog.open()
        }

        // ── Bundled-preset row visibility ──
        // Moved here from Settings → General (more logical home). Mirrors the
        // "Hide" button on the preset row in the Rules section; both write the
        // persisted `showBundledPresets` preference.
        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            text: root.tr("settings.presets.bundled-presets.title", "Bundled presets")
            color: root.textColor
            font.bold: true
        }
        CheckBox {
            Layout.fillWidth: true
            text: root.tr("settings.presets.bundled-presets.label",
                "Show the bundled-preset quick-load row in Rules")
            // Default ON: undefined (older context) is treated as enabled.
            checked: root.prefs.showBundledPresets !== false
            onToggled: root.updatePrefs({ showBundledPresets: checked })
        }
        Label {
            Layout.fillWidth: true
            Layout.leftMargin: root.uiTheme.spacingLg
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.presets.bundled-presets.description",
                "Shows a quick-load dropdown of bundled country/demo presets above the rules table. The \"Hide\" button on that row also turns this off.")
        }

        // ── Rule sets from a folder of the user's own ──
        // Repoints the SAME quick-load dropdown at a folder the user keeps
        // their own sets in (for example a "corp" set and a "public network"
        // set), so switching between them is two clicks in the Rules section.
        Label {
            Layout.fillWidth: true
            Layout.topMargin: root.uiTheme.spacingSm
            text: root.tr("settings.presets.user-folder.title", "My rule sets")
            color: root.textColor
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.presets.user-folder.description",
                "Point the quick-load dropdown at your own folder instead of the sets that come with the app. The folder can hold \"rules_primary.txt\" and \"rules_secondary.txt\" directly, or one subfolder per set — each subfolder's name becomes the entry in the dropdown.")
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedTextField {
                id: userPresetsDirField
                theme: root.uiTheme
                Layout.fillWidth: true
                readOnly: true
                text: root.userPresetsDir
                placeholderText: root.tr("settings.presets.user-folder.placeholder",
                    "Using the rule sets that come with the app")
            }
            ThemedButton {
                theme: root.uiTheme
                // Shared generic action label — same wording everywhere.
                text: root.tr("action.browse", "Browse...")
                icon.source: root.uiIconSource("load-list")
                onClicked: {
                    if (root.userPresetsDir !== "") {
                        userPresetsFolderDialog.currentFolder =
                            group._folderUrl(root.userPresetsDir)
                    }
                    userPresetsFolderDialog.open()
                }
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.presets.user-folder.reset", "Use bundled sets")
                enabled: root.userPresetsDir !== ""
                onClicked: {
                    root.setUserPresetsDir("")
                    root.statusLine = root.tr("status.user-presets-folder-cleared",
                        "The quick-load dropdown is back to the rule sets that come with the app.")
                }
            }
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            // Points the folder at the sets shipped with the app, so a set can
            // be opened, copied and edited without hunting for the install
            // directory. They are listed read-only; saving below always writes
            // into whatever folder is configured.
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.presets.user-folder.use-bundled-path",
                    "Point at the sets that come with the app")
                onClicked: group._useBundledPresetsPath()
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("settings.presets.save-as-set.button",
                    "Save current rules as a set...")
                icon.source: root.uiIconSource("save")
                // The bytes come from the rules table on screen, so a stopped
                // service is no reason to withhold the button.
                enabled: root.userPresetsDir !== ""
                onClicked: {
                    saveAsSetNameField.text = ""
                    saveAsSetDialog.open()
                }
            }
        }
        Label {
            Layout.fillWidth: true
            visible: root.userPresetsDir === ""
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            font.pixelSize: root.uiTheme.baseFontSizePx - 1
            text: root.tr("settings.presets.save-as-set.needs-folder",
                "Choose a folder above first — that is where a new set is saved.")
        }
    }

    FolderDialog {
        id: userPresetsFolderDialog
        title: root.tr("settings.presets.user-folder.dialog-title",
            "Choose the folder with your rule sets")
        onAccepted: {
            root.setUserPresetsDir(group._localPath(selectedFolder))
            root.statusLine = root.tr("status.user-presets-folder-set",
                "The quick-load dropdown now lists the rule sets in your folder.")
        }
    }

    // ── Dialogs (private to this subsection) ──────────────────────

    // "Save current rules as a set": asks for a folder name, then writes both
    // route files into `<my rule sets>/<name>/`. Kept inline (not a shared
    // component) because it is a one-field prompt owned by this subsection.
    Dialog {
        id: saveAsSetDialog
        modal: true
        popupType: Popup.Item
        anchors.centerIn: Overlay.overlay
        width: 460
        title: root.tr("settings.presets.save-as-set.title", "Save rules as a set")
        standardButtons: Dialog.NoButton
        closePolicy: Popup.NoAutoClose

        contentItem: ColumnLayout {
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("settings.presets.save-as-set.prompt",
                    "The current rules of both routes are saved as a new set in your folder. Name it so you can tell it apart later, for example \"work\" or \"home\".")
            }
            ThemedTextField {
                id: saveAsSetNameField
                theme: root.uiTheme
                Layout.fillWidth: true
                placeholderText: root.tr("settings.presets.save-as-set.name-placeholder",
                    "Set name")
                onAccepted: if (group._saveAsSetNameIsUsable(text)) group._saveCurrentRulesAsSet(text)
            }
            Label {
                Layout.fillWidth: true
                visible: saveAsSetNameField.text.trim() !== ""
                            && !group._saveAsSetNameIsUsable(saveAsSetNameField.text)
                wrapMode: Text.WordWrap
                color: root.uiTheme.colorDanger
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("settings.presets.save-as-set.name-invalid",
                    "A name cannot contain \\ / : or \"..\" — it is a folder name, not a path.")
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: root.uiTheme.spacingSm
                spacing: root.uiTheme.spacingSm
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: saveAsSetDialog.close()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("settings.presets.save-as-set.confirm", "Save set")
                    enabled: group._saveAsSetNameIsUsable(saveAsSetNameField.text)
                    onClicked: group._saveCurrentRulesAsSet(saveAsSetNameField.text)
                }
            }
        }
    }

    // Shown once when a set would be written into the folder the app ships its
    // own sets in: an update replaces that folder, so the user's set would
    // disappear with it. Not a block — the user may have a reason; the tick
    // records the acknowledgement so it never asks twice.
    Dialog {
        id: bundledFolderWarningDialog
        modal: true
        popupType: Popup.Item
        anchors.centerIn: Overlay.overlay
        width: 480
        title: root.tr("settings.presets.bundled-write-warning.title",
            "This folder belongs to the app")
        standardButtons: Dialog.NoButton
        closePolicy: Popup.NoAutoClose

        property string pendingSetName: ""
        property bool dontAskAgain: false

        contentItem: ColumnLayout {
            spacing: root.uiTheme.spacingSm
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: root.textColor
                text: root.tr("settings.presets.bundled-write-warning.body",
                    "You are saving into the folder the app keeps its own rule sets in. Updating the app replaces that folder, and your set is lost with it. Pick a folder of your own above to keep sets safely.")
            }
            CheckBox {
                id: bundledWarningAckCheck
                Layout.fillWidth: true
                text: root.tr("settings.presets.bundled-write-warning.dont-ask",
                    "I understand — do not ask again")
                checked: bundledFolderWarningDialog.dontAskAgain
                onToggled: bundledFolderWarningDialog.dontAskAgain = checked
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: root.uiTheme.spacingSm
                spacing: root.uiTheme.spacingSm
                Item { Layout.fillWidth: true }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("action.cancel", "Cancel")
                    onClicked: bundledFolderWarningDialog.close()
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: root.tr("settings.presets.bundled-write-warning.confirm",
                        "Save here anyway")
                    onClicked: {
                        var pending = bundledFolderWarningDialog.pendingSetName
                        if (bundledFolderWarningDialog.dontAskAgain) {
                            root.setAllowSavingIntoBundledPresets(true)
                        }
                        bundledFolderWarningDialog.close()
                        // Re-enter: the acknowledgement (or the tick) now lets
                        // the save through the same single code path.
                        group._saveCurrentRulesAsSetConfirmed(pending)
                    }
                }
            }
        }
    }

    FileDialog {
        id: importDialog
        fileMode: FileDialog.OpenFile
        // Same folder every other rule-file dialog uses.
        title: root.tr(
            "settings.presets.import-dialog-title",
            "Choose preset file to import")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        property string pendingTargetRoute: ""
        onAccepted: group._handleImportChosen(
            pendingTargetRoute, _localPath(selectedFile))
    }

    FileDialog {
        id: exportDialog
        fileMode: FileDialog.SaveFile
        title: root.tr(
            "settings.presets.export-dialog-title",
            "Save preset as...")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        defaultSuffix: "txt"
        property string pendingSourceRoute: ""
        onAccepted: group._handleExportChosen(
            pendingSourceRoute, _localPath(selectedFile))
    }

    FileDialog {
        id: settingsExportDialog
        fileMode: FileDialog.SaveFile
        title: root.tr(
            "settings.presets.full-settings-dialog-title",
            "Save settings export as...")
        nameFilters: [
            root.tr("settings.presets.yaml-filter", "YAML files (*.yaml)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        defaultSuffix: "yaml"
        onAccepted: group._handleSettingsExportChosen(_localPath(selectedFile))
    }

    function _localPath(urlValue) {
        var s = String(urlValue || "")
        if (s.indexOf("file:///") === 0) return s.substring(8)
        if (s.indexOf("file://") === 0) return s.substring(7)
        return s
    }

    // Inverse of `_localPath`: a local path back into the file URL the folder
    // dialog expects, so re-opening it starts where the user left off.
    function _folderUrl(pathValue) {
        var s = String(pathValue || "").replace(/\\/g, "/")
        if (s === "") return ""
        if (s.indexOf("file://") === 0) return s
        return "file:///" + s
    }

    // Point the user folder at the sets shipped with the app.
    function _useBundledPresetsPath() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.bundledPresetsRoot !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        var dir = String(nrrNativeBridge.bundledPresetsRoot() || "")
        if (dir === "") {
            root.statusLine = root.tr("status.bundled-presets-path-unknown",
                "Could not locate the folder with the sets that come with the app.")
            return
        }
        root.setUserPresetsDir(dir)
        root.statusLine = root.tr("status.user-presets-folder-set",
            "The quick-load dropdown now lists the rule sets in your folder.")
    }

    // A set name is a folder name, never a path — mirrors the same refusal in
    // the bridge so the user sees why the button stays disabled.
    function _saveAsSetNameIsUsable(name) {
        var n = String(name || "").trim()
        if (n === "" || n === ".") return false
        if (n.indexOf("/") >= 0 || n.indexOf("\\") >= 0) return false
        if (n.indexOf(":") >= 0 || n.indexOf("..") >= 0) return false
        return true
    }

    // True when the configured folder IS the one the app ships its sets in.
    // Compared case-insensitively with separators normalised, because the path
    // reaches us both from the bridge and from a folder picker.
    function _targetIsBundledFolder() {
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.bundledPresetsRoot !== "function") {
            return false
        }
        var bundled = String(nrrNativeBridge.bundledPresetsRoot() || "")
        if (bundled === "") return false
        var norm = function(p) {
            return String(p || "").replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase()
        }
        return norm(bundled) === norm(root.userPresetsDir)
    }

    function _saveCurrentRulesAsSet(name) {
        var setName = String(name || "").trim()
        if (!group._saveAsSetNameIsUsable(setName)) return
        if (typeof nrrNativeBridge === "undefined" || !nrrNativeBridge
                || typeof nrrNativeBridge.createPresetSetDir !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        // Writing into the app's own folder survives until the next update
        // wipes it. Ask once; the warning's tick records the acknowledgement.
        if (group._targetIsBundledFolder() && !root.allowSavingIntoBundledPresets) {
            bundledFolderWarningDialog.pendingSetName = setName
            bundledFolderWarningDialog.dontAskAgain = false
            bundledFolderWarningDialog.open()
            return
        }
        group._saveCurrentRulesAsSetConfirmed(setName)
    }

    // The write itself, past every prompt. Also the warning dialog's
    // continuation, so both routes into "save" share one implementation.
    //
    // Both route files go through the shared write funnel, which generates the
    // bytes from the rules table on screen (never from a service round-trip),
    // applies the one factory-folder gate and rebinds the route to its new
    // file. Saving a set therefore works with the service stopped, and both
    // routes settle into a single verdict instead of two half-truths.
    //
    // An existing set with the same name is not silently clobbered: the
    // shared `guardExistingSetDir` gate (same dialog the Rules-section "save
    // as a set" flow uses) confirms before either route file is written.
    function _saveCurrentRulesAsSetConfirmed(name) {
        var setName = String(name || "").trim()
        if (!group._saveAsSetNameIsUsable(setName)) return
        var dir = String(nrrNativeBridge.createPresetSetDir(root.userPresetsDir, setName) || "")
        if (dir === "") {
            root.statusLine = root.tr("status.save-as-set-folder-failed",
                "Could not create the set folder. Check that the folder above is writable.")
            return
        }
        saveAsSetDialog.close()
        var writeSet = function() {
            root.boundFilesController.exportRoutesToPaths(
                [{ route: "primary",   path: dir + "/rules_primary.txt" },
                 { route: "secondary", path: dir + "/rules_secondary.txt" }],
                function(ok) {
                    if (!ok) {
                        root.statusLine = root.tr("status.save-as-set-failed",
                            "Could not save the set. See logs for details.")
                        return
                    }
                    // Names the SET FOLDER, not one of the two files in it.
                    root.statusLine = root.tr("status.save-as-set-done", "Saved as a set: ") + dir
                    // The folder path is unchanged, only its contents are —
                    // nothing else would tell the quick-load dropdown to
                    // enumerate it again.
                    root.presetSetsChanged()
                })
        }
        if (root.boundFilesController.guardExistingSetDir(dir, writeSet, function() {
                root.statusLine = root.tr("status.save-as-set-overwrite-cancelled",
                    "Nothing was saved — the set already had files there.")
            })) return
        writeSet()
    }

    function _handleImportChosen(route, path) {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            root.statusLine = root.tr(
                "status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        var b64 = nrrNativeBridge.readFileBytes(path)
        if (!b64 || b64.length === 0) {
            root.statusLine = root.tr(
                "status.import-read-failed",
                "Cannot read preset file. See logs for details.")
            return
        }
        if (typeof root.presetImportController.startPresetImportReviewFlow === "function") {
            root.presetImportController.startPresetImportReviewFlow(route, b64, path)
        }
        root.suggestRulesFolder(path)
    }

    // Exporting one route is the same write as the Rules toolbar's "Export to
    // file…": bytes generated from the rules table, the factory-folder gate,
    // the route<->file rebinding and the folder suggestion all live in the
    // shared funnel, so this stays a one-liner and keeps working with the
    // service stopped.
    function _handleExportChosen(route, path) {
        root.boundFilesController.exportRouteToPath(route, String(path))
    }

    function _handleSettingsExportChosen(path) {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.rpcSettingsExportFull !== "function") {
            root.statusLine = root.tr(
                "status.bridge-unavailable",
                "Native bridge unavailable")
            return
        }
        // The server does not yet expose UiPreferences::last_saved_path_<role>.
        // Pass empty strings; the server emits
        // empty paths in `rules_files:` block, which the YAML reader
        // tolerates (user can fill them in later by re-importing).
        var corr = nrrNativeBridge.rpcSettingsExportFull("", "")
        if (root.rpc && typeof root.rpc.registerRpcCallback === "function") {
            root.rpc.registerRpcCallback(corr, function(ok, p, code, msg) {
                if (!ok) {
                    root.statusLine = root.tr(
                        "status.export-rpc-failed",
                        "Export failed: ") +
                        ((typeof root.ipcErrorLabel === "function")
                            ? root.ipcErrorLabel(String(code || "unknown"))
                            : String(code || "unknown"))
                    return
                }
                var b64 = (p && p["yaml-bytes-b64"]) || ""
                var ok2 = nrrNativeBridge.writeFileBytes(path, b64)
                if (!ok2) {
                    root.statusLine = root.tr(
                        "status.export-write-failed",
                        "Cannot write settings file to the chosen path.")
                    return
                }
                root.statusLine = root.tr(
                    "settings.presets.full-settings-exported",
                    "Full settings exported.")
            })
        }
    }
}
