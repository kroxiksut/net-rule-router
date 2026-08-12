import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15
import QtQuick.Dialogs

// Rule-list import window (extracted from Main.qml).
//
// Lets the user pick one or two preset .txt files — one per route — and import
// them in Replace (default) or Merge mode. All shared state comes in through
// `root` (the ApplicationWindow). The window keeps its `loadListWindow` id so
// Main.qml's shortcut / menu / overlay wiring (property alias, openChildWindow,
// the overlays and children arrays) is unchanged.
Window {
    id: loadListWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    width: 720
    height: 600
    visible: false
    modality: Qt.NonModal
    color: root.panelColor
    title: root.tr("dialog.load-list.title", "Load rule list")
    transientParent: root
    flags: Qt.Dialog

    property string pickedPrimaryPath: ""
    property string pickedSecondaryPath: ""
    // Replace (default) vs Merge import mode.
    property string pickedMode: "replace"

    function _basename(p) {
        if (!p) return ""
        var s = String(p)
        var i = s.lastIndexOf("\\")
        var j = s.lastIndexOf("/")
        var k = Math.max(i, j)
        return k >= 0 ? s.substring(k + 1) : s
    }

    function _localPathFromUrl(urlValue) {
        var s = String(urlValue || "")
        if (s.indexOf("file:///") === 0) return s.substring(8)
        if (s.indexOf("file://") === 0) return s.substring(7)
        return s
    }

    function _sameFileConflict() {
        var p1 = String(pickedPrimaryPath || "").trim().toLowerCase()
        var p2 = String(pickedSecondaryPath || "").trim().toLowerCase()
        return p1 !== "" && p2 !== "" && p1 === p2
    }

    function _applyImport() {
        var primPath = pickedPrimaryPath
        var secPath = pickedSecondaryPath
        if (!primPath && !secPath) return
        if (_sameFileConflict()) return
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
            root.statusLine = root.tr("status.import-read-failed",
                "Cannot read preset file. See logs for details.")
            return
        }
        if (secPath && !secB64) {
            root.statusLine = root.tr("status.import-read-failed",
                "Cannot read preset file. See logs for details.")
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
        // Offer the folder these files came from as the rule-set folder —
        // once, and only while none is configured.
        root.suggestRulesFolder(primPath || secPath)
        loadListWindow.close()
    }

    onVisibleChanged: if (visible) {
        root.centerChildWindow(loadListWindow)
        root.applyTitleBarTo(loadListWindow)
        pickedPrimaryPath = ""
        pickedSecondaryPath = ""
    }

    FileDialog {
        id: loadListPrimaryDialog
        fileMode: FileDialog.OpenFile
        // Same folder every other rule-file dialog uses.
        title: root.tr("dialog.load-list.pick-primary-title",
            "Choose primary route preset file")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        onAccepted: loadListWindow.pickedPrimaryPath =
            loadListWindow._localPathFromUrl(selectedFile)
    }
    FileDialog {
        id: loadListSecondaryDialog
        fileMode: FileDialog.OpenFile
        title: root.tr("dialog.load-list.pick-secondary-title",
            "Choose secondary route preset file")
        nameFilters: [
            root.tr("rules.dialog.preset-filter", "Preset files (*.txt)"),
            root.tr("rules.dialog.all-filter", "All files (*)")
        ]
        onAccepted: loadListWindow.pickedSecondaryPath =
            loadListWindow._localPathFromUrl(selectedFile)
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingLg
        spacing: root.uiTheme.spacingMd
        Label {
            text: root.tr("dialog.load-list.title", "Load rule list")
            color: root.textColor
            font.bold: true
            font.pixelSize: 16
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.mutedTextColor
            text: root.tr("dialog.load-list.intro",
                "Pick one or two preset .txt files — one per route. Leaving a slot empty keeps that route's current rules untouched.")
        }

        // Replace / Merge mode selector. Applied
        // uniformly to both route slots (per UX decision: one
        // radio per dialog, not per-route).
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            Label {
                Layout.fillWidth: true
                text: root.tr("dialog.load-list.mode-heading", "Import mode")
                color: root.textColor
                font.bold: true
            }
            RadioButton {
                Layout.fillWidth: true
                text: root.tr("dialog.load-list.mode-replace",
                    "Replace current rules with the imported set")
                checked: loadListWindow.pickedMode === "replace"
                onToggled: if (checked) loadListWindow.pickedMode = "replace"
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("dialog.load-list.mode-replace-description",
                    "Existing rules for the imported route(s) are cleared first.")
            }
            RadioButton {
                Layout.fillWidth: true
                text: root.tr("dialog.load-list.mode-merge",
                    "Merge — add new rules, skip duplicates")
                checked: loadListWindow.pickedMode === "merge"
                onToggled: if (checked) loadListWindow.pickedMode = "merge"
            }
            Label {
                Layout.fillWidth: true
                Layout.leftMargin: root.uiTheme.spacingLg
                color: root.mutedTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                text: root.tr("dialog.load-list.mode-merge-description",
                    "Keeps current rules (with your manual edits and comments). Imported rules with the same type, value and route are skipped.")
            }
        }

        // "import only active rules" toggle,
        // contextual to importing (moved here from the Rules toolbar,
        // where it was clutter). Defaults to the saved value in
        // Settings → General; ticking it affects this import only.
        CheckBox {
            id: loadListOnlyActiveCheck
            Layout.fillWidth: true
            checked: root.importOnlyActiveSession
            onToggled: root.importOnlyActiveSession = checked
            ToolTip.visible: hovered
            ToolTip.text: root.tr("rules.import-only-active.tooltip",
                "When loading a preset, skip rules that are turned off in it (for example application rules, which can't route yet). Default comes from Settings → General; changing it here applies to this import only.")
            contentItem: Text {
                leftPadding: loadListOnlyActiveCheck.indicator.width + loadListOnlyActiveCheck.spacing
                text: root.tr("rules.import-only-active.label", "Import only active rules")
                color: root.textColor
                font.pixelSize: root.uiTheme.baseFontSizePx
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
            }
        }

        // Primary route slot. Heading on its own line, file row
        // below — keeps long RU labels from competing with the
        // browse/clear buttons on the same row.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            Label {
                Layout.fillWidth: true
                text: root.tr("dialog.load-list.file-for-route", "Rules file for: {route}")
                    .replace("{route}", root.routeLabel("primary"))
                color: root.textColor
                font.bold: true
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.fillWidth: true
                    elide: Text.ElideMiddle
                    color: loadListWindow.pickedPrimaryPath
                        ? root.textColor : root.mutedTextColor
                    text: loadListWindow.pickedPrimaryPath
                        ? loadListWindow._basename(loadListWindow.pickedPrimaryPath)
                        : root.tr("dialog.load-list.no-file-selected",
                            "(no file selected)")
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: loadListWindow.pickedPrimaryPath
                        ? root.tr("action.change", "Change...")
                        : root.tr("action.browse", "Browse...")
                    onClicked: root.openRulesDialog(loadListPrimaryDialog)
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: loadListWindow.pickedPrimaryPath !== ""
                    text: root.tr("action.clear", "Clear")
                    onClicked: loadListWindow.pickedPrimaryPath = ""
                }
            }
        }
        // Secondary route slot.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingXs
            Label {
                Layout.fillWidth: true
                text: root.tr("dialog.load-list.file-for-route", "Rules file for: {route}")
                    .replace("{route}", root.routeLabel("secondary"))
                color: root.textColor
                font.bold: true
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: root.uiTheme.spacingSm
                Label {
                    Layout.fillWidth: true
                    elide: Text.ElideMiddle
                    color: loadListWindow.pickedSecondaryPath
                        ? root.textColor : root.mutedTextColor
                    text: loadListWindow.pickedSecondaryPath
                        ? loadListWindow._basename(loadListWindow.pickedSecondaryPath)
                        : root.tr("dialog.load-list.no-file-selected",
                            "(no file selected)")
                }
                ThemedButton {
                    theme: root.uiTheme
                    text: loadListWindow.pickedSecondaryPath
                        ? root.tr("action.change", "Change...")
                        : root.tr("action.browse", "Browse...")
                    onClicked: root.openRulesDialog(loadListSecondaryDialog)
                }
                ThemedButton {
                    theme: root.uiTheme
                    visible: loadListWindow.pickedSecondaryPath !== ""
                    text: root.tr("action.clear", "Clear")
                    onClicked: loadListWindow.pickedSecondaryPath = ""
                }
            }
        }

        // Same-file conflict warning — case-insensitive (Windows
        // paths are practically case-insensitive). Trimmed so a
        // stray trailing space doesn't bypass the check.
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.uiTheme.colorDanger
            visible: loadListWindow._sameFileConflict()
            text: root.tr("dialog.load-list.same-file-conflict",
                "The same file cannot be selected for both the primary and the secondary route at the same time.")
        }

        Item { Layout.fillHeight: true }

        RowLayout {
            Layout.fillWidth: true
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.import", "Import")
                enabled: (loadListWindow.pickedPrimaryPath !== ""
                    || loadListWindow.pickedSecondaryPath !== "")
                    && !loadListWindow._sameFileConflict()
                onClicked: loadListWindow._applyImport()
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.close", "Close")
                onClicked: loadListWindow.close()
            }
        }
    }
}
