import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import QtQuick.Dialogs

// First-run wizard (extracted from Main.qml).
//
// A 4-option preset-driven onboarding flow: country preset, built-in demo,
// open-my-rules (two-file picker), or start empty. Opens once when
// `!prefs.firstRunCompleted`; each path marks the flag so it never reappears.
// The window keeps its `firstRunWindow` id so Main.qml's wiring (property
// alias, overlays/children arrays, openChildWindow, and licenseWindow's
// transient-parent reference) is unchanged. Shared state comes in through
// `root` (the ApplicationWindow), including the sibling `root.licenseWindow`.
Window {
    id: firstRunWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    width: 640
    height: 640
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

    // Mirror pack for the same country under presets/abroad/ — for someone who
    // lives elsewhere but still needs that country's services. The OS locale
    // cannot tell the two apart (an emigrant keeps their language), so the
    // wizard asks instead of guessing. Empty when no such pack is bundled.
    property string detectedAbroadPack: ""
    property bool livingAbroad: false

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
    property bool wantKillSwitch: true
    property bool wantDohLockdown: true
    property bool wantFakeIp: true
    property bool wantDiagnosticLogs: false

    // Applied once, on whichever path closes the wizard. A stopped service
    // parks each intent and replays it on reconnect, so this is safe before the
    // service is up.
    property bool _protectionApplied: false
    function _applyProtectionChoices() {
        if (_protectionApplied) return
        _protectionApplied = true
        var rp = root.routePolicyController
        if (rp) {
            if (typeof rp.applyKillSwitchEnabled === "function") {
                rp.applyKillSwitchEnabled(wantKillSwitch)
            }
            if (typeof rp.applyDohLockdownEnabled === "function") {
                rp.applyDohLockdownEnabled(wantDohLockdown)
            }
        }
        if (typeof root.applyServiceStabilityPatch !== "function") return
        var patch = { "fake-ip-enabled": wantFakeIp }
        if (wantDiagnosticLogs) {
            patch["verbose-logging"] = true
            patch["conn-trace-ndjson"] = true
            patch["conn-trace-gui"] = true
        }
        root.applyServiceStabilityPatch(patch, function(ok, code) {
            if (!ok) {
                console.log("FirstRun: stability patch deferred: " + String(code || ""))
            }
        }, "first-run")
    }

    function _basename(p) {
        if (!p) return ""
        var s = String(p)
        var i = s.lastIndexOf("\\")
        var j = s.lastIndexOf("/")
        var k = Math.max(i, j)
        return k >= 0 ? s.substring(k + 1) : s
    }

    onVisibleChanged: {
        if (visible) {
            root.centerChildWindow(firstRunWindow)
            root.applyTitleBarTo(firstRunWindow)
            _detectCountryPreset()
            pickedPrimaryPath = ""
            pickedSecondaryPath = ""
        }
    }

    // Closing the wizard by ANY route — an option button, the Escape
    // overlay handler (`applyActiveOverlay`), or the title-bar X —
    // marks it as seen. Before this handler an X-close left
    // `firstRunCompleted` false, so the wizard reappeared on the next
    // launch. The option/escape paths already set the flag in memory
    // before calling close(), so the `!firstRunCompleted` guard skips
    // a redundant second write (and the extra `uiRevision` bump); the
    // X-close path falls through and sets it here. Persistence matches
    // the option handlers — the flag is flushed by the main window's
    // own `onClosing` emitPrefs() on exit; no explicit emit is needed.
    onClosing: {
        _applyProtectionChoices()
        if (!root.prefs.firstRunCompleted) {
            root.updatePrefs({ firstRunCompleted: true })
        }
        // Hand the Licenses window back to the main window if it was
        // re-parented onto the wizard by `licenseWindow.openOnEulaTab`
        // (so a later normal open stacks correctly).
        if (root.licenseWindow.transientParent === firstRunWindow) {
            root.licenseWindow.transientParent = root
        }
    }

    function _detectCountryPreset() {
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.detectOsLocale !== "function") {
            detectedCountry = ""
            detectedCountryPack = ""
            detectedAbroadPack = ""
            return
        }
        var loc = String(nrrNativeBridge.detectOsLocale() || "")
        // "ru_ru" → country = "ru". Fall back to the language code
        // when the locale has no underscore (e.g. "ru").
        var parts = loc.split("_")
        var cc = parts.length >= 2 ? parts[1] : (parts[0] || "")
        cc = cc.toLowerCase()
        detectedCountry = cc
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
        var primB64 = _readPresetBytes(primRel)
        var secB64 = _readPresetBytes(secRel)
        _finishWith(primB64, secB64,
            _resolvePresetAbs(primRel), _resolvePresetAbs(secRel))
    }

    function _applyBuiltinDemo() {
        var primB64 = _readPresetBytes("builtin-demo/rules_primary.txt")
        var secB64 = _readPresetBytes("builtin-demo/rules_secondary.txt")
        _finishWith(primB64, secB64,
            _resolvePresetAbs("builtin-demo/rules_primary.txt"),
            _resolvePresetAbs("builtin-demo/rules_secondary.txt"))
    }

    function _finishWith(primB64, secB64, primPath, secPath) {
        if (!primB64 && !secB64) {
            root.statusLine = root.tr("status.wizard-import-failed",
                "First-run wizard import failed: ") + "(no bytes)"
            return
        }
        if (typeof root.presetImportController.startBothRoutesPresetImportReviewFlow === "function") {
            root.presetImportController.startBothRoutesPresetImportReviewFlow(primB64, secB64, primPath, secPath)
        }
        root.updatePrefs({ firstRunCompleted: true })
        firstRunWindow.close()
        root.statusLine = root.tr("status.wizard-completed",
            "Welcome — initial rules imported.")
    }

    function _startEmpty() {
        root.updatePrefs({ firstRunCompleted: true })
        firstRunWindow.close()
    }

    function _localPathFromUrl(urlValue) {
        var s = String(urlValue || "")
        if (s.indexOf("file:///") === 0) return s.substring(8)
        if (s.indexOf("file://") === 0) return s.substring(7)
        return s
    }

    // Read the picked file(s) and dispatch the
    // appropriate review flow. Both paths set → both-routes flow;
    // exactly one set → single-route flow. Empty bytes on either
    // side abort with a status line so the user can re-pick.
    function _applyOpenedFiles() {
        var primPath = pickedPrimaryPath
        var secPath = pickedSecondaryPath
        if (!primPath && !secPath) return
        if (typeof nrrNativeBridge === "undefined"
                || !nrrNativeBridge
                || typeof nrrNativeBridge.readFileBytes !== "function") {
            root.statusLine = root.tr("status.bridge-unavailable",
                "Service bridge not connected.")
            return
        }
        var primB64 = primPath ? nrrNativeBridge.readFileBytes(primPath) : ""
        var secB64 = secPath ? nrrNativeBridge.readFileBytes(secPath) : ""
        if (primPath && !primB64) {
            root.statusLine = root.tr("status.wizard-import-failed",
                "First-run wizard import failed: ") + "(read primary)"
            return
        }
        if (secPath && !secB64) {
            root.statusLine = root.tr("status.wizard-import-failed",
                "First-run wizard import failed: ") + "(read secondary)"
            return
        }
        if (primPath && secPath) {
            if (typeof root.presetImportController.startBothRoutesPresetImportReviewFlow === "function") {
                root.presetImportController.startBothRoutesPresetImportReviewFlow(
                    primB64, secB64, primPath, secPath)
            }
        } else if (primPath) {
            if (typeof root.presetImportController.startPresetImportReviewFlow === "function") {
                root.presetImportController.startPresetImportReviewFlow("primary", primB64, primPath)
            }
        } else {
            if (typeof root.presetImportController.startPresetImportReviewFlow === "function") {
                root.presetImportController.startPresetImportReviewFlow("secondary", secB64, secPath)
            }
        }
        root.updatePrefs({ firstRunCompleted: true })
        firstRunWindow.close()
        root.statusLine = root.tr("status.wizard-completed",
            "Welcome — initial rules imported.")
    }

    FileDialog {
        id: firstRunOpenPrimaryDialog
        fileMode: FileDialog.OpenFile
        // Same folder every other rule-file dialog uses.
        title: root.tr("dialog.first-run-wizard.pick-primary-title",
            "Choose primary route preset file")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        onAccepted: firstRunWindow.pickedPrimaryPath =
            firstRunWindow._localPathFromUrl(selectedFile)
    }

    FileDialog {
        id: firstRunOpenSecondaryDialog
        fileMode: FileDialog.OpenFile
        title: root.tr("dialog.first-run-wizard.pick-secondary-title",
            "Choose secondary route preset file")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        onAccepted: firstRunWindow.pickedSecondaryPath =
            firstRunWindow._localPathFromUrl(selectedFile)
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingLg
        spacing: root.uiTheme.spacingMd

        Label {
            text: root.tr("dialog.first-run-wizard.title",
                "Welcome to NetRuleRouter")
            color: root.textColor
            font.bold: true
            font.pixelSize: 18
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            text: root.tr("dialog.first-run-wizard.description",
                "Choose how to populate your initial rule set. You can always change this later via the Rules toolbar or Settings → Presets.")
        }

        // Re-open the same read-only license agreement the user accepted
        // via `eulaAgreementWindow` to get here — jumps to the "Licenses"
        // window's EULA tab. No acceptance timestamp is persisted today
        // (only `acceptedEulaVersion`, an integer), so the label carries
        // no date.
        RowLayout {
            Layout.fillWidth: true
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("dialog.first-run-wizard.view-eula", "View EULA")
                onClicked: root.licenseWindow.openOnEulaTab()
            }
            Item { Layout.fillWidth: true }
        }

        // Protection defaults, offered before the rule set so they are already
        // in force when the first rules apply.
        ColumnLayout {
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
            CheckBox {
                id: firstRunKillSwitchCheck
                Layout.fillWidth: true
                checked: firstRunWindow.wantKillSwitch
                text: root.tr("dialog.first-run-wizard.protection-kill-switch",
                    "Block routed traffic when the additional route is down")
                contentItem: Label {
                    text: firstRunKillSwitchCheck.text
                    leftPadding: firstRunKillSwitchCheck.indicator.width + firstRunKillSwitchCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: firstRunWindow.wantKillSwitch = checked
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
                onToggled: firstRunWindow.wantDohLockdown = checked
            }
            CheckBox {
                id: firstRunFakeIpCheck
                Layout.fillWidth: true
                checked: firstRunWindow.wantFakeIp
                text: root.tr("dialog.first-run-wizard.protection-fake-ip",
                    "Route sites by name, so an address shared with another site is not dragged along")
                contentItem: Label {
                    text: firstRunFakeIpCheck.text
                    leftPadding: firstRunFakeIpCheck.indicator.width + firstRunFakeIpCheck.spacing
                    color: root.textColor
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignVCenter
                }
                onToggled: firstRunWindow.wantFakeIp = checked
            }
            CheckBox {
                id: firstRunDiagLogsCheck
                Layout.fillWidth: true
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
                onToggled: firstRunWindow.wantDiagnosticLogs = checked
            }
        }

        // Option 1: Country preset (if a pack exists for the detected locale).
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            visible: firstRunWindow.hasAnyCountryPack

            // Asked only when both directions ship a pack; with one of them the
            // answer would change nothing.
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 0
                visible: firstRunWindow.hasHomePack && firstRunWindow.hasAbroadPack
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
                    text: root.tr("dialog.first-run-wizard.location-home",
                            "I am in {country}")
                        .replace("{country}", firstRunWindow.detectedCountry.toUpperCase())
                    onToggled: if (checked) firstRunWindow.livingAbroad = false
                }
                ThemedRadioButton {
                    theme: root.uiTheme
                    Layout.fillWidth: true
                    checked: firstRunWindow.livingAbroad
                    text: root.tr("dialog.first-run-wizard.location-abroad",
                            "I am outside {country} and need access to its services")
                        .replace("{country}", firstRunWindow.detectedCountry.toUpperCase())
                    onToggled: if (checked) firstRunWindow.livingAbroad = true
                }
            }

            ThemedButton {
                theme: root.uiTheme
                Layout.fillWidth: true
                text: (firstRunWindow.useAbroadPack
                        ? root.tr("dialog.first-run-wizard.option-country-preset-abroad",
                            "Load access preset ({country})")
                        : root.tr("dialog.first-run-wizard.option-country-preset",
                            "Load country preset ({country})"))
                    .replace("{country}", firstRunWindow.detectedCountry.toUpperCase())
                icon.source: root.uiIconSource("load-list")
                onClicked: firstRunWindow._applyCountryPreset()
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingMd
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                text: firstRunWindow.useAbroadPack
                    ? root.tr("dialog.first-run-wizard.option-country-preset-abroad-description",
                        "Everything stays on your local provider; only that country's services take the additional route.")
                    : root.tr("dialog.first-run-wizard.option-country-preset-description",
                        "Detected from your OS locale. Imports the bundled pack for your region.")
            }
        }
        // Option 1 fallback note when no country pack found.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            visible: !firstRunWindow.hasAnyCountryPack
            text: root.tr("dialog.first-run-wizard.option-country-not-available",
                "No country preset is bundled for your region — pick a different option.")
        }

        // Option 2: Built-in demo.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            ThemedButton {
                theme: root.uiTheme
                Layout.fillWidth: true
                text: root.tr("dialog.first-run-wizard.option-builtin-demo",
                        "Use built-in demo rules")
                icon.source: root.uiIconSource("add")
                onClicked: firstRunWindow._applyBuiltinDemo()
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingMd
                wrapMode: Text.WordWrap
                color: root.mutedTextColor
                text: root.tr("dialog.first-run-wizard.option-builtin-demo-description",
                    "A tiny showcase set covering each rule kind. Replace with your own later.")
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
                    "Choose one or two preset .txt files — one for each route. Leave a route empty to start it blank.")
            }
            // Primary route slot.
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingMd
                spacing: root.uiTheme.spacingSm
                Label {
                    text: root.tr("dialog.first-run-wizard.primary-file-label",
                        "Primary:")
                    color: root.textColor
                    Layout.preferredWidth: 96
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
                        : root.tr("dialog.first-run-wizard.browse-button", "Browse...")
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
                    text: root.tr("dialog.first-run-wizard.secondary-file-label",
                        "Secondary:")
                    color: root.textColor
                    Layout.preferredWidth: 96
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
                        : root.tr("dialog.first-run-wizard.browse-button", "Browse...")
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
                        "Import selected files")
                icon.source: root.uiIconSource("load-list")
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

        Item { Layout.fillHeight: true }
    }
}
