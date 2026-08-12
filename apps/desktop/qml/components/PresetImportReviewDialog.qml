// Interactive review for preset imports
// that have duplicate sections or unknown (foreign-OS / Pro-tier)
// sections requiring user input. Opens BEFORE the parser's output
// reaches rulesModel / sidecar, so the user's choices can adjust
// what actually lands.
//
// Contract:
// - `duplicates` (array of `DuplicateGroup`) — unknown-section
//   duplicates the user must resolve. Known-section duplicates are
//   surfaced informationally (a warning row), no per-section choice.
// - `unknowns` (array of `PassthroughBlock`) — single-occurrence
//   unknown sections, each with a reclassify dropdown.
// - `signal approved(decisions)` — fired with the user's per-section
//   choices. Caller applies them to the parse result before the
//   final import + passthrough write.
// - `signal cancelled()` — user aborted the import.
//
// Decision shape passed to `approved`:
//   {
//     duplicates:   {sectionName: "merge"|"last-wins"|"ignore"},
//     reclassify:   {sectionName: "passthrough"|"zones"|"domains"|"ip"|"windows"|"skip"}
//   }
//
// Width target: 720px. Height adapts to content; both groups scroll
// when long.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root
    title: typeof root.tr === "function"
        ? root.tr("dialog.preset-review.title", "Review preset import")
        : "Review preset import"

    modal: true
    // Render inside the main window overlay (themed), not a separate
    // top-level OS window — see ReviewDiffDialog for the rationale.
    popupType: Popup.Item
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }
    width: 720
    height: 600
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose

    /// Inject the ApplicationWindow so we can resolve `tr`, theme,
    /// palette, accent colors. Same pattern as ReviewDiffDialog.
    property var ownerRoot: null

    /// Parser diagnostics: duplicate sections detected in the file.
    /// Each entry: { section-name, occurrences, is-known-section }.
    property var duplicates: []

    /// Parser diagnostics: unknown sections the parser didn't
    /// classify. Each entry: { section-name, raw-text, content-lines,
    /// preview: [...] }. Default per-entry choice is "passthrough"
    /// (preserve for export round-trip).
    property var unknowns: []

    /// Internal: collected user choices, mutated as the user clicks.
    /// Keyed by section name. Approved signal receives a deep copy.
    property var _duplicateChoices: ({})
    property var _reclassifyChoices: ({})

    signal approved(var decisions)
    signal cancelled()

    /// Helper hooks back to ApplicationWindow.
    function _tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }
    function _theme() {
        return ownerRoot && ownerRoot.uiTheme ? ownerRoot.uiTheme : null
    }
    function _textColor() {
        var t = _theme()
        return t ? t.colorText : "#000"
    }
    function _mutedColor() {
        var t = _theme()
        return t ? t.colorTextMuted : "#555"
    }
    function _accentColor() {
        var t = _theme()
        return t ? t.colorAccent : "#007ACC"
    }
    function _warningColor() {
        var t = _theme()
        return t ? t.colorWarning : "#C18800"
    }

    palette: ownerRoot ? ownerRoot.palette : palette

    /// Apply default choices on open so we never emit `approved`
    /// with an empty decisions object for sections that need them.
    onOpened: {
        var dups = {}
        for (var i = 0; i < duplicates.length; i += 1) {
            var d = duplicates[i] || {}
            // Default for unknown-duplicates: "merge" (preserves
            // both occurrences, matches our pre-Phase-5 behaviour).
            // Known-section duplicates don't need a choice — both
            // batches of rules already merged into the parser result.
            dups[String(d["section-name"] || "")] = "merge"
        }
        _duplicateChoices = dups

        var reclass = {}
        for (var j = 0; j < unknowns.length; j += 1) {
            var u = unknowns[j] || {}
            reclass[String(u["section-name"] || "")] = "passthrough"
        }
        _reclassifyChoices = reclass
    }

    contentItem: ColumnLayout {
        spacing: 12
        anchors.margins: 8

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root._textColor()
            text: root._tr("dialog.preset-review.intro",
                "The file contains sections that need a decision before import.")
            font.bold: true
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth

            ColumnLayout {
                width: parent ? parent.width : 0
                spacing: 16

                // ── Duplicates group ────────────────────────────────
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 8
                    visible: root.duplicates.length > 0

                    Label {
                        Layout.fillWidth: true
                        color: root._accentColor()
                        font.bold: true
                        font.pixelSize: 14
                        text: root._tr("dialog.preset-review.duplicates-heading",
                            "Duplicate sections")
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: root._mutedColor()
                        text: root._tr("dialog.preset-review.duplicates-hint",
                            "These sections appear more than once in the file. Pick how to combine them.")
                    }

                    Repeater {
                        model: root.duplicates
                        delegate: Frame {
                            required property var modelData
                            Layout.fillWidth: true
                            padding: 8

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 4

                                Label {
                                    Layout.fillWidth: true
                                    wrapMode: Text.WordWrap
                                    color: root._textColor()
                                    text: {
                                        var name = String(modelData["section-name"] || "")
                                        var occ = parseInt(modelData["occurrences"] || 0)
                                        var known = !!modelData["is-known-section"]
                                        var label = root._tr(
                                            "dialog.preset-review.duplicate-row",
                                            "Section \"{name}\" appears {n} times")
                                            .replace("{name}", name)
                                            .replace("{n}", String(occ))
                                        if (known) {
                                            label += " " + root._tr(
                                                "dialog.preset-review.duplicate-known-tag",
                                                "(known section — all rules merged)")
                                        }
                                        return label
                                    }
                                    font.bold: true
                                }

                                ButtonGroup {
                                    id: dupGroup
                                    exclusive: true
                                }

                                RadioButton {
                                    text: root._tr("dialog.preset-review.duplicate-merge",
                                        "Merge (concatenate contents)")
                                    checked: true
                                    ButtonGroup.group: dupGroup
                                    onCheckedChanged: if (checked) {
                                        var copy = Object.assign({}, root._duplicateChoices)
                                        copy[String(modelData["section-name"] || "")] = "merge"
                                        root._duplicateChoices = copy
                                    }
                                }
                                RadioButton {
                                    text: root._tr("dialog.preset-review.duplicate-last-wins",
                                        "Use only the last occurrence")
                                    visible: !modelData["is-known-section"]
                                    ButtonGroup.group: dupGroup
                                    onCheckedChanged: if (checked) {
                                        var copy = Object.assign({}, root._duplicateChoices)
                                        copy[String(modelData["section-name"] || "")] = "last-wins"
                                        root._duplicateChoices = copy
                                    }
                                }
                                RadioButton {
                                    text: root._tr("dialog.preset-review.duplicate-ignore",
                                        "Skip this section entirely")
                                    ButtonGroup.group: dupGroup
                                    onCheckedChanged: if (checked) {
                                        var copy = Object.assign({}, root._duplicateChoices)
                                        copy[String(modelData["section-name"] || "")] = "ignore"
                                        root._duplicateChoices = copy
                                    }
                                }
                            }
                        }
                    }
                }

                // ── Unknowns group ──────────────────────────────────
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 8
                    visible: root.unknowns.length > 0

                    Label {
                        Layout.fillWidth: true
                        color: root._accentColor()
                        font.bold: true
                        font.pixelSize: 14
                        text: root._tr("dialog.preset-review.unknowns-heading",
                            "Unrecognised sections")
                    }
                    Label {
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                        color: root._mutedColor()
                        text: root._tr("dialog.preset-review.unknowns-hint",
                            "We didn't recognise these sections. Tell us what they are, or keep them as-is for export.")
                    }

                    Repeater {
                        model: root.unknowns
                        delegate: Frame {
                            required property var modelData
                            Layout.fillWidth: true
                            padding: 8

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 4

                                Label {
                                    Layout.fillWidth: true
                                    color: root._textColor()
                                    text: {
                                        var name = String(modelData["section-name"] || "")
                                        var lines = parseInt(modelData["content-lines"] || 0)
                                        return root._tr(
                                            "dialog.preset-review.unknown-row",
                                            "--- {name} ({n} lines)")
                                            .replace("{name}", name)
                                            .replace("{n}", String(lines))
                                    }
                                    font.bold: true
                                }

                                Label {
                                    Layout.fillWidth: true
                                    wrapMode: Text.WordWrap
                                    color: root._mutedColor()
                                    font.family: "Consolas, monospace"
                                    font.pixelSize: 11
                                    text: {
                                        var preview = modelData["preview"] || []
                                        return preview.join("\n")
                                    }
                                    visible: text !== ""
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 8
                                    Label {
                                        text: root._tr("dialog.preset-review.what-is-this",
                                            "What is this?")
                                        color: root._textColor()
                                    }
                                    ComboBox {
                                        Layout.fillWidth: true
                                        textRole: "label"
                                        valueRole: "value"
                                        model: [
                                            { value: "passthrough",
                                              label: root._tr(
                                                "dialog.preset-review.classify-passthrough",
                                                "Preserve for other OS / tools (default)") },
                                            { value: "zones",
                                              label: root._tr(
                                                "dialog.preset-review.classify-zones",
                                                "Zones") },
                                            { value: "domains",
                                              label: root._tr(
                                                "dialog.preset-review.classify-domains",
                                                "Domains") },
                                            { value: "ip",
                                              label: root._tr(
                                                "dialog.preset-review.classify-ip",
                                                "IP addresses") },
                                            { value: "windows",
                                              label: root._tr(
                                                "dialog.preset-review.classify-windows",
                                                "Windows applications") },
                                            { value: "skip",
                                              label: root._tr(
                                                "dialog.preset-review.classify-skip",
                                                "Skip (discard)") }
                                        ]
                                        currentIndex: 0
                                        onActivated: {
                                            var name = String(modelData["section-name"] || "")
                                            var v = model[currentIndex].value
                                            var copy = Object.assign({}, root._reclassifyChoices)
                                            copy[name] = v
                                            root._reclassifyChoices = copy
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Item { Layout.fillWidth: true }
            Button {
                text: root._tr("action.cancel", "Cancel")
                onClicked: {
                    root.cancelled()
                    root.close()
                }
            }
            Button {
                text: root._tr("dialog.preset-review.apply", "Apply")
                highlighted: true
                onClicked: {
                    // Snapshot the decisions to a fresh object so the
                    // caller's handler can't see further mutations.
                    var decisions = {
                        duplicates: Object.assign({}, root._duplicateChoices),
                        reclassify: Object.assign({}, root._reclassifyChoices)
                    }
                    root.approved(decisions)
                    root.close()
                }
            }
        }
    }
}
