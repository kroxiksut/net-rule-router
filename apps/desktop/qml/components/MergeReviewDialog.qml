// File↔service merge review dialog.
//
// Opened from the quiet "Merge available" banner (Main.qml `_openMergeDialog`)
// when a route's linked rules file and the service's active revision have
// genuinely diverged. Renders the merge preview returned by the SERVICE op
// `rules.merge-preview` (see production_merge_preview.rs) as three buckets:
//
//   • Only in the file      — rules present just in the bound .txt
//   • Only in the app       — rules present just in the active revision
//   • Conflicts             — rules on both sides that differ (route / enabled
//                             / action / comment). Under the "union" policy the
//                             user picks a side per conflict.
//
// On confirm the caller re-runs the op with the picks to get the final merged
// rules-json and hands it to `startRulesReviewFlow` (the service stays the
// single writer). This file is pure presentation: the RPC + apply orchestration
// lives in Main.qml, wired through `ownerRoot` and the signals below.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: dialog
    title: tr("dialog.merge.title", "Merge file and app rules")

    modal: true
    // Render inside the main window overlay (themed), not a separate OS
    // top-level window — same rationale as DriftDetectionDialog / ReviewDiffDialog.
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: dialog
        theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
        titleText: dialog.title
    }
    width: 700
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// ApplicationWindow that owns the dialog (provides `tr`, `uiTheme`,
    /// `textColor`, `mutedTextColor`, `ruleTypeLabel`).
    property var ownerRoot: null

    /// The `MergeResultDto` (kebab-case keys) from the first preview call, or
    /// `null` while loading. Set by the caller on open. Named `mergeResult`
    /// (not `result`) to avoid shadowing `QQuickDialog`'s final `result` member.
    property var mergeResult: null

    /// Loading / error state driven by the caller.
    property bool loading: false
    property string errorText: ""

    /// The active conflict-resolution policy slug ("union" / "file-wins" /
    /// "service-wins"). Per-conflict picks are only offered under "union".
    property string policy: "union"

    /// identity-key → "file" | "service". The user's per-conflict picks.
    /// Initialised to the file-provisional side (matching Union semantics) by
    /// the caller when the preview lands.
    property var picks: ({})

    signal cancelled()
    /// Emitted on confirm with the per-conflict resolutions
    /// (`[{ "identity-key": ..., "side": "file"|"service" }]`).
    signal confirmed(var resolutions)

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function _typeLabel(slug) {
        return (ownerRoot && typeof ownerRoot.ruleTypeLabel === "function")
            ? ownerRoot.ruleTypeLabel(String(slug || ""))
            : String(slug || "")
    }

    function _routeLabel(role) {
        return String(role) === "secondary"
            ? tr("dialog.drift.row-secondary", "Secondary")
            : tr("dialog.drift.row-primary", "Primary")
    }

    function _textColor() {
        return ownerRoot ? ownerRoot.textColor : palette.text
    }
    function _mutedColor() {
        return ownerRoot ? ownerRoot.mutedTextColor : palette.text
    }

    function _fileOnly() { return (mergeResult && mergeResult["file-only"]) ? mergeResult["file-only"] : [] }
    function _serviceOnly() { return (mergeResult && mergeResult["service-only"]) ? mergeResult["service-only"] : [] }
    function _conflicts() { return (mergeResult && mergeResult.conflicts) ? mergeResult.conflicts : [] }
    function _isNoop() { return !!(mergeResult && mergeResult.noop === true) }

    /// A concise one-line summary of one conflict side: route + off/block flags.
    function _sideSummary(side) {
        if (!side) return "—"
        var parts = [ _routeLabel(side.route) ]
        // Shared wording with the review diff — one "disabled" text app-wide.
        if (side.enabled === false) parts.push(tr("label.disabled", "disabled"))
        if (String(side.action) === "block")
            parts.push(tr("dialog.merge.badge-block", "Block"))
        if (side.comment && String(side.comment) !== "") parts.push("“" + String(side.comment) + "”")
        return parts.join(" · ")
    }

    /// True when every conflict has a concrete pick (always true unless Union).
    function _allResolved() {
        if (policy !== "union") return true
        var cs = _conflicts()
        for (var i = 0; i < cs.length; i += 1) {
            var k = cs[i]["identity-key"]
            var p = picks[k]
            if (p !== "file" && p !== "service") return false
        }
        return true
    }

    function _setPick(key, side) {
        var next = {}
        for (var k in picks) next[k] = picks[k]
        next[String(key)] = side
        picks = next
    }

    function _buildResolutions() {
        var out = []
        var cs = _conflicts()
        for (var i = 0; i < cs.length; i += 1) {
            var key = cs[i]["identity-key"]
            var side = picks[key]
            if (side === "file" || side === "service") {
                out.push({ "identity-key": key, "side": side })
            }
        }
        return out
    }

    onRejected: cancelled()

    contentItem: ColumnLayout {
        spacing: 12

        Label {
            Layout.fillWidth: true
            text: dialog.tr("dialog.merge.body",
                "Combine your linked rules file with the rules the service is currently enforcing. Rules on only one side are always kept; rules that exist on both but differ are shown as conflicts.")
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: dialog._textColor()
            Accessible.role: Accessible.StaticText
            Accessible.name: text
        }

        // ── Transient states ─────────────────────────────────────
        Label {
            Layout.fillWidth: true
            visible: dialog.loading
            text: dialog.tr("dialog.merge.loading", "Comparing file and app rules…")
            font.pixelSize: 13
            color: dialog._mutedColor()
        }
        Label {
            Layout.fillWidth: true
            visible: !dialog.loading && dialog.errorText !== ""
            text: dialog.errorText
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: "#c0392b"
        }
        Label {
            Layout.fillWidth: true
            visible: !dialog.loading && dialog.errorText === "" && dialog._isNoop()
            text: dialog.tr("dialog.merge.no-op",
                "The file and the app rules already match — nothing to merge.")
            wrapMode: Text.Wrap
            font.pixelSize: 13
            color: dialog._mutedColor()
        }

        // ── Buckets ──────────────────────────────────────────────
        ScrollView {
            Layout.fillWidth: true
            Layout.preferredHeight: 360
            visible: !dialog.loading && dialog.errorText === "" && !dialog._isNoop()
            clip: true
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            ColumnLayout {
                width: dialog.width - 48
                spacing: 10

                // File-only bucket
                Label {
                    Layout.fillWidth: true
                    visible: dialog._fileOnly().length > 0
                    text: dialog.tr("dialog.merge.bucket-file-only", "Only in the file")
                        + " (" + dialog._fileOnly().length + ")"
                    font.bold: true
                    color: dialog._textColor()
                }
                Repeater {
                    model: dialog._fileOnly()
                    delegate: RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        spacing: 8
                        visible: dialog._fileOnly().length > 0
                        Label {
                            text: dialog._typeLabel(modelData["type-slug"])
                            font.pixelSize: 12
                            color: dialog._mutedColor()
                            Layout.preferredWidth: 96
                        }
                        Label {
                            Layout.fillWidth: true
                            text: String(modelData.value || "")
                            font.pixelSize: 12
                            font.family: "Consolas, Courier New, monospace"
                            color: dialog._textColor()
                            elide: Text.ElideRight
                        }
                        Label {
                            text: dialog._routeLabel(modelData.route)
                            font.pixelSize: 11
                            color: dialog._mutedColor()
                        }
                        Rectangle {
                            visible: String(modelData.action) === "block"
                            color: "#c0392b"
                            radius: 3
                            implicitHeight: blockBadgeF.implicitHeight + 2
                            implicitWidth: blockBadgeF.implicitWidth + 10
                            Label {
                                id: blockBadgeF
                                anchors.centerIn: parent
                                text: dialog.tr("dialog.merge.badge-block", "Block")
                                font.pixelSize: 10
                                color: "white"
                            }
                        }
                    }
                }

                // Service-only bucket
                Label {
                    Layout.fillWidth: true
                    Layout.topMargin: 6
                    visible: dialog._serviceOnly().length > 0
                    text: dialog.tr("dialog.merge.bucket-service-only", "Only in the app")
                        + " (" + dialog._serviceOnly().length + ")"
                    font.bold: true
                    color: dialog._textColor()
                }
                Repeater {
                    model: dialog._serviceOnly()
                    delegate: RowLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        spacing: 8
                        Label {
                            text: dialog._typeLabel(modelData["type-slug"])
                            font.pixelSize: 12
                            color: dialog._mutedColor()
                            Layout.preferredWidth: 96
                        }
                        Label {
                            Layout.fillWidth: true
                            text: String(modelData.value || "")
                            font.pixelSize: 12
                            font.family: "Consolas, Courier New, monospace"
                            color: dialog._textColor()
                            elide: Text.ElideRight
                        }
                        Label {
                            text: dialog._routeLabel(modelData.route)
                            font.pixelSize: 11
                            color: dialog._mutedColor()
                        }
                        Rectangle {
                            visible: String(modelData.action) === "block"
                            color: "#c0392b"
                            radius: 3
                            implicitHeight: blockBadgeS.implicitHeight + 2
                            implicitWidth: blockBadgeS.implicitWidth + 10
                            Label {
                                id: blockBadgeS
                                anchors.centerIn: parent
                                text: dialog.tr("dialog.merge.badge-block", "Block")
                                font.pixelSize: 10
                                color: "white"
                            }
                        }
                    }
                }

                // Conflicts bucket
                Label {
                    Layout.fillWidth: true
                    Layout.topMargin: 6
                    visible: dialog._conflicts().length > 0
                    text: dialog.tr("dialog.merge.bucket-conflicts", "Conflicts")
                        + " (" + dialog._conflicts().length + ")"
                    font.bold: true
                    color: dialog._textColor()
                }
                Repeater {
                    model: dialog._conflicts()
                    delegate: ColumnLayout {
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        spacing: 2
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8
                            Label {
                                text: dialog._typeLabel(modelData["type-slug"])
                                font.pixelSize: 12
                                color: dialog._mutedColor()
                                Layout.preferredWidth: 96
                            }
                            Label {
                                Layout.fillWidth: true
                                text: String(modelData.value || "")
                                font.pixelSize: 12
                                font.family: "Consolas, Courier New, monospace"
                                color: dialog._textColor()
                                elide: Text.ElideRight
                            }
                            // Per-conflict pick — only under Union.
                            ThemedComboBox {
                                id: pickCombo
                                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                                visible: dialog.policy === "union"
                                Layout.preferredWidth: 140
                                model: [ "file", "service" ]
                                labelResolver: function(item) {
                                    return item === "service"
                                        ? dialog.tr("dialog.merge.pick-service", "App")
                                        : dialog.tr("dialog.merge.pick-file", "File")
                                }
                                currentIndex:
                                    dialog.picks[modelData["identity-key"]] === "service" ? 1 : 0
                                displayText: currentIndex === 1
                                    ? dialog.tr("dialog.merge.pick-service", "App")
                                    : dialog.tr("dialog.merge.pick-file", "File")
                                onActivated: dialog._setPick(modelData["identity-key"],
                                    model[currentIndex])
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Layout.leftMargin: 96
                            spacing: 12
                            Label {
                                text: dialog.tr("dialog.merge.pick-file", "File") + ": "
                                    + dialog._sideSummary(modelData.file)
                                font.pixelSize: 11
                                color: dialog._mutedColor()
                            }
                            Label {
                                text: dialog.tr("dialog.merge.pick-service", "App") + ": "
                                    + dialog._sideSummary(modelData.service)
                                font.pixelSize: 11
                                color: dialog._mutedColor()
                            }
                        }
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true
            visible: dialog.policy === "union" && dialog._conflicts().length > 0
                && !dialog._allResolved()
            text: dialog.tr("dialog.merge.unresolved-hint",
                "Pick a side for every conflict before merging.")
            wrapMode: Text.Wrap
            font.pixelSize: 12
            color: "#a04400"
        }

        // ── Buttons ──────────────────────────────────────────────
        Flow {
            Layout.fillWidth: true
            Layout.topMargin: 8
            spacing: 8
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.merge.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: { dialog.cancelled(); dialog.close() }
            }
            ThemedButton {
                theme: dialog.ownerRoot ? dialog.ownerRoot.uiTheme : null
                text: dialog.tr("dialog.merge.apply", "Merge and review")
                highlighted: true
                enabled: !dialog.loading && dialog.errorText === ""
                    && !dialog._isNoop() && dialog._allResolved()
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: {
                    dialog.confirmed(dialog._buildResolutions())
                }
            }
        }
    }
}
