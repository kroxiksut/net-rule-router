// Review dialog for rules-update dry-run.
//
// Renders the wire `ReviewSummaryResponse` produced by
// `ProductionMutationExecutor::preview`:
// risk badge (Low/Medium/High/Critical), full list of structured
// `RiskSignalDto` entries with kind-specific localised messages,
// and three side-by-side columns (Added / Removed / Modified +
// Retargeted) for the rule-level diff. Per-rule arrays are not
// yet carried on the wire — they're populated to placeholders
// from `changedFields` until a B.7+ follow-up extends
// `ReviewSummaryResponse`.
//
// Contract:
// - `summary` (object) — the wire response. Properties accessed via
//   kebab-case keys (`risk-level`, `risk-signals`, `changed-fields`,
//   `diff-summary`, `requires-review`).
// - `signal approved()` — fired when the user clicks "Apply changes".
//   The caller executes the activation directly; the former separate
//   ConfirmActivateDialog confirmation step was merged in. A Critical-risk
//   acknowledgement checkbox now
//   lives in this dialog and gates the Apply button.
// - `signal cancelled()` — fired on Cancel / window close.
//
// Width target: 900px (side-by-side 3 columns). Height adapts to
// content; risk-badge + signals are sticky at the top of the dialog
// content so they stay visible while the columns scroll.

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Dialog {
    id: root
    title: typeof root.tr === "function"
        ? (root.readOnly
            ? root.tr("dialog.review-diff.title-readonly", "Preview pending changes")
            : root.tr("dialog.review-diff.title", "Review changes"))
        : (root.readOnly ? "Preview pending changes" : "Review changes")

    modal: true
    width: 900
    height: 640
    standardButtons: Dialog.NoButton
    closePolicy: Popup.NoAutoClose
    // Render inside the main window's overlay instead of a separate
    // top-level OS window. On Qt 6.8+ `Dialog` defaults to a windowed
    // popup on desktop, which the DWM dark-titlebar path does not reach
    // — it shows up as a light, non-themed "not-Qt" window. `Popup.Item`
    // keeps it inside the themed ApplicationWindow (same idiom the
    // menus use in Main.qml).
    popupType: Popup.Item
    // Draggable themed title bar — in-overlay dialogs aren't movable by
    // default; this restores drag-to-reposition while staying themed.
    header: DialogDragHeader {
        dialog: root
        theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
        titleText: root.title
    }

    // Inject ApplicationWindow access for `root.tr`, theme palette,
    // and accent colors. The shared pattern across the rest of the
    // QML tree (see ruleDialog in Main.qml).
    property var ownerRoot: null
    /// Wire `ReviewSummaryResponse` object — see module header.
    property var summary: ({})
    /// When `true`, an informational banner tells the user that the GUI
    /// is not running as Administrator, so applying will request
    /// administrator approval once (a single UAC prompt for the session
    /// elevation broker). Caller supplies this
    /// from a Win32 process-token check (see `nrrNativeBridge.isElevated`).
    property bool lacksElevation: false
    /// When `true`, the session already
    /// obtained administrator approval via the elevation broker (a prior
    /// apply prompted UAC), so the banner reassures rather than warns: the
    /// temporary admin lasts until the app closes. When `false` (and
    /// `lacksElevation`), the banner says applying will prompt for UAC once.
    property bool sessionElevated: false
    /// When `true`, the standard Approve button is
    /// hidden and Cancel becomes "Close". Used by the preview paths to
    /// let the user inspect parked changes without committing. A separate
    /// "Apply…" button (see
    /// `previewApplyRequested`) lets the user leave the preview and enter
    /// the real review/activate flow instead of dead-ending on "Close".
    property bool readOnly: false

    /// Review and confirmation are now a
    /// single step (was Review → separate ConfirmActivateDialog). For a
    /// Critical-risk activation the user must tick the acknowledgement
    /// before Apply enables; lower-risk applies stay one click. Reset on
    /// every open.
    property bool _understandChecked: false

    signal approved()
    signal cancelled()
    /// Fired from read-only/preview mode when
    /// the user decides to actually apply the previewed (parked) changes.
    /// The host closes this preview and re-enters the standard review flow
    /// (`startRulesReviewFlow`) with the parked payload, which re-runs the
    /// dry-run and re-opens this dialog in normal (Apply-enabled) mode.
    signal previewApplyRequested()

    function tr(key, fallback) {
        if (ownerRoot && typeof ownerRoot.tr === "function") {
            return ownerRoot.tr(key, fallback)
        }
        return fallback
    }

    function riskLevelSlug() {
        var s = summary && summary["risk-level"] ? String(summary["risk-level"]) : "low"
        return s
    }

    /// Critical-risk activations require the acknowledgement checkbox
    /// before Apply enables — the catastrophic-config bucket. All other
    /// levels apply in one click.
    function isCritical() {
        return riskLevelSlug() === "critical"
    }

    function riskBadgeColor() {
        switch (riskLevelSlug()) {
            case "critical": return "#c0392b"
            case "high":     return "#e67e22"
            case "medium":   return "#d4a017"
            case "low":      return "#2980b9"
            default:         return "#7f8c8d"
        }
    }

    function riskBadgeText() {
        return tr("risk.level." + riskLevelSlug(), riskLevelSlug())
    }

    /// Render one `RiskSignalDto` entry as a localised string,
    /// substituting payload fields into the placeholder pattern via
    /// `.replace("{name}", value)`. Mirrors the wire serde tagged
    /// enum field names (kebab-case at JSON layer).
    function renderSignal(signal) {
        if (!signal || !signal.kind) return ""
        var kind = String(signal.kind)
        var text = tr("risk.signal." + kind, kind)
        // Substitute known payload fields. Unknown placeholders
        // remain in the string — better than silently dropping the
        // value.
        if (signal.label !== undefined) text = text.replace("{label}", String(signal.label))
        if (signal.count !== undefined) text = text.replace("{count}", String(signal.count))
        if (signal["rule-count"] !== undefined) {
            text = text.replace("{rule-count}", String(signal["rule-count"]))
        }
        if (signal["prev-total"] !== undefined) {
            text = text.replace("{prev-total}", String(signal["prev-total"]))
        }
        if (signal["removed-pct"] !== undefined) {
            text = text.replace("{removed-pct}", String(signal["removed-pct"]))
        }
        if (signal.apex !== undefined) text = text.replace("{apex}", String(signal.apex))
        return text
    }

    function signalsList() {
        if (!summary || !summary["risk-signals"]) return []
        return summary["risk-signals"]
    }

    function diffSummaryText() {
        // The server-side `diff_summary` field is a hardcoded English
        // `"N SID(s); +A / -R filters; W pre-flight warning(s)"`
        // string (production_mutation_executor.rs). Parse it to
        // recover the counters and re-render through the locale tree
        // so the line localises into RU. Fall back to the raw text
        // when the format ever drifts.
        var raw = summary && summary["diff-summary"] ? String(summary["diff-summary"]) : ""
        if (raw === "") {
            return tr("dialog.review-diff.summary-empty",
                "No structural changes detected.")
        }
        // Reset-to-baseline carries its own machine form
        // `"reset-to-baseline; discard N rule(s)"`; localise it.
        var rm = raw.match(/^reset-to-baseline;\s*discard\s+(\d+)\s+rule/)
        if (rm) {
            return tr("dialog.review-diff.reset-summary",
                "Discard {count} custom rule(s) and restore the baseline rules.")
                .replace("{count}", rm[1])
        }
        var m = raw.match(/^(\d+)\s+SID\(s\);\s*\+(\d+)\s*\/\s*-(\d+)\s+filters;\s*(\d+)\s+pre-flight\s+warning\(s\)$/)
        if (!m) return raw
        return tr("dialog.review-diff.summary-counts",
                "{sids} SID(s); +{added} / -{removed} filters; {warnings} pre-flight warning(s)")
            .replace("{sids}", m[1])
            .replace("{added}", m[2])
            .replace("{removed}", m[3])
            .replace("{warnings}", m[4])
    }

    onRejected: cancelled()

    // Focus the safer button (Cancel) on
    // open so keyboard activation can't fire "Approve and activate"
    // by accidental Enter-press. The user must explicitly tab to
    // the destructive action.
    onOpened: {
        _understandChecked = false
        if (cancelButton) cancelButton.forceActiveFocus()
    }

    contentItem: ColumnLayout {
        spacing: 12

        // ── Elevation banner (sticky, above the risk badge) ──────
        // Shown when the GUI is NOT running as Administrator. Applying
        // still works: the launcher relays the activation through the
        // session elevation broker, which asks for administrator approval
        // once (a single UAC prompt, reused for the rest of the session).
        // This banner sets that expectation up front.
        Rectangle {
            Layout.fillWidth: true
            visible: root.lacksElevation
            radius: 6
            color: "#fff3cd"
            border.width: 1
            border.color: "#d4a017"
            implicitHeight: elevationBannerLabel.implicitHeight + 16
            Label {
                id: elevationBannerLabel
                anchors.fill: parent
                anchors.margins: 8
                text: root.sessionElevated
                    ? root.tr(
                        "dialog.review-diff.session-elevation-active",
                        "You granted administrator approval for this session. "
                        + "Changes apply without another prompt. This temporary "
                        + "approval ends when you close NetRuleRouter.")
                    : root.tr(
                        "dialog.review-diff.no-elevation-warning",
                        "NetRuleRouter is not running as Administrator. When you "
                        + "apply, Windows will ask for administrator approval once "
                        + "— after you approve it, this and later changes apply "
                        + "without prompting again until you close the app.")
                wrapMode: Text.Wrap
                color: "#664d03"
                font.pixelSize: 12
                verticalAlignment: Text.AlignVCenter
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
        }

        // ── Risk badge + diff summary (sticky) ───────────────────
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Rectangle {
                radius: 6
                color: root.riskBadgeColor()
                Layout.preferredHeight: 36
                Layout.preferredWidth: Math.max(96, riskBadgeLabel.implicitWidth + 28)
                Accessible.role: Accessible.StaticText
                Accessible.name: root.tr("dialog.review-diff.risk-heading",
                    "Risk assessment") + ": " + root.riskBadgeText()
                Label {
                    id: riskBadgeLabel
                    anchors.centerIn: parent
                    text: root.riskBadgeText()
                    color: "white"
                    font.bold: true
                    font.pixelSize: 14
                }
            }

            Label {
                Layout.fillWidth: true
                text: root.diffSummaryText()
                wrapMode: Text.Wrap
                font.pixelSize: 13
                color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            }
        }

        // ── Risk signals ─────────────────────────────────────────
        Label {
            text: root.tr("dialog.review-diff.signals-heading", "Detected signals")
            font.bold: true
            font.pixelSize: 13
            color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
            visible: root.signalsList().length > 0
        }

        ListView {
            id: signalsView
            visible: root.signalsList().length > 0
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(160, contentHeight)
            spacing: 4
            clip: true
            interactive: contentHeight > height
            model: root.signalsList()
            ScrollBar.vertical: ScrollBar {
                policy: signalsView.contentHeight > signalsView.height
                    ? ScrollBar.AlwaysOn : ScrollBar.AsNeeded
            }
            Accessible.role: Accessible.List
            Accessible.name: root.tr(
                "dialog.review-diff.signals-heading", "Detected signals")
            delegate: Rectangle {
                width: ListView.view.width
                height: signalLabel.implicitHeight + 8
                color: "transparent"
                Accessible.role: Accessible.ListItem
                Accessible.name: root.renderSignal(modelData)
                Label {
                    id: signalLabel
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    verticalAlignment: Text.AlignVCenter
                    text: "• " + root.renderSignal(modelData)
                    wrapMode: Text.Wrap
                    font.pixelSize: 12
                    color: root.ownerRoot ? root.ownerRoot.textColor : palette.text
                }
            }
        }

        // ── Three columns ────────────────────────────────────────
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 8

            ReviewDiffColumn {
                Layout.fillWidth: true
                Layout.fillHeight: true
                ownerRoot: root.ownerRoot
                title: root.tr("dialog.review-diff.column-added", "Added")
                items: (root.summary && root.summary["rules-added"]) || []
                emptyText: root.tr("dialog.review-diff.column-empty", "(none)")
            }
            ReviewDiffColumn {
                Layout.fillWidth: true
                Layout.fillHeight: true
                ownerRoot: root.ownerRoot
                title: root.tr("dialog.review-diff.column-removed", "Removed")
                items: (root.summary && root.summary["rules-removed"]) || []
                emptyText: root.tr("dialog.review-diff.column-empty", "(none)")
            }
            ReviewDiffColumn {
                Layout.fillWidth: true
                Layout.fillHeight: true
                ownerRoot: root.ownerRoot
                title: root.tr("dialog.review-diff.column-modified", "Modified or retargeted")
                items: {
                    // Build by index, not `.concat`: the wire summary arrives
                    // as a QVariantList from the C++ bridge, which lacks JS
                    // Array methods like `concat` (it has `.length`+indexing).
                    var out = []
                    var mods = (root.summary && root.summary["rules-modified"]) || []
                    var retarg = (root.summary && root.summary["rules-retargeted"]) || []
                    for (var i = 0; i < mods.length; i += 1) out.push(mods[i])
                    for (var j = 0; j < retarg.length; j += 1) out.push(retarg[j])
                    return out
                }
                emptyText: root.tr("dialog.review-diff.column-empty", "(none)")
            }
        }

        // ── Pro-section badging ──────────────────
        // When the imported preset carries `--- CIDR` / `--- Ports`
        // or any other unknown section, the wire field
        // `pro-sections` lists them. The server currently always
        // returns empty (active revision doesn't persist unknown
        // sections — see project_block16_14_a_complete landmine #4),
        // so this block stays hidden until a future
        // schema-bump adds an `unknown_sections_json` column.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4
            visible: {
                var ps = root.summary && root.summary["pro-sections"]
                // Coerce to a real bool — when `summary` is `{}` the
                // first `&&` yields `undefined`, which Qt rejects as a
                // `bool` binding ("Unable to assign [undefined] to bool").
                // Count by `.length` (not `Array.isArray`): bridge-delivered
                // QVariantList is not a JS Array but has a numeric `.length`.
                return !!(ps && typeof ps.length === "number" && ps.length > 0)
            }
            Label {
                Layout.fillWidth: true
                text: root.tr(
                    "dialog.review-diff.pro-sections-title",
                    "Extended sections preserved as-is")
                font.bold: true
                color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            }
            Repeater {
                model: (root.summary && root.summary["pro-sections"]) || []
                delegate: RowLayout {
                    Layout.fillWidth: true
                    spacing: 6
                    Image {
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                        source: root.ownerRoot
                            ? root.ownerRoot.uiIconSource("about")
                            : ""
                        fillMode: Image.PreserveAspectFit
                        sourceSize.width: 16
                        sourceSize.height: 16
                        asynchronous: true
                    }
                    Label {
                        Layout.fillWidth: true
                        text: root.tr(
                            "dialog.review-diff.pro-section-line",
                            "{name}: {count} rules preserved (not applied)")
                            .replace("{name}", String(modelData.name || "?"))
                            .replace("{count}", String(modelData["preserved-count"] || 0))
                        color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                        elide: Text.ElideRight
                    }
                }
            }
        }

        // ── Confirmation checkbox (Critical only) + buttons ──────
        // Single-step apply. The separate
        // ConfirmActivateDialog hop was removed; its "I understand the
        // risk" acknowledgement lives here now and gates Apply for
        // Critical-risk activations. Hidden in read-only/preview mode.
        CheckBox {
            id: understandCheckbox
            visible: root.isCritical() && !root.readOnly
            checked: root._understandChecked
            onCheckedChanged: root._understandChecked = checked
            text: root.tr(
                "dialog.confirm-activate.checkbox-understand",
                "I understand the risk and want to proceed")
            Layout.fillWidth: true
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            Accessible.description: root.tr(
                "dialog.confirm-activate.checkbox-understand-description",
                "Required acknowledgement before applying a Critical-risk activation")
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 6
            spacing: 8
            Item { Layout.fillWidth: true }
            ThemedButton {
                id: cancelButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                text: root.readOnly
                    ? root.tr("dialog.review-diff.close", "Close")
                    : root.tr("dialog.review-diff.cancel", "Cancel")
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.readOnly
                    ? root.tr("dialog.review-diff.close-description",
                        "Close the preview without applying anything")
                    : root.tr("dialog.review-diff.cancel-description",
                        "Cancel the activation and keep the previous rule set")
                onClicked: { root.cancelled(); root.close() }
            }
            ThemedButton {
                id: previewApplyButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                // Read-only preview is no
                // longer a dead end: this leaves the preview and enters
                // the real review/activate flow with the same payload.
                visible: root.readOnly
                text: root.tr("dialog.review-diff.apply-from-preview", "Apply…")
                highlighted: true
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.review-diff.apply-from-preview-description",
                    "Close the preview and open the activation flow for these parked changes")
                onClicked: { root.previewApplyRequested(); root.close() }
            }
            ThemedButton {
                id: approveButton
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                visible: !root.readOnly
                // Single-step: this now applies directly (no second
                // confirmation dialog). Disabled until the acknowledgement
                // is ticked for Critical-risk activations.
                text: root.tr("dialog.review-diff.apply", "Apply changes")
                highlighted: true
                enabled: !root.isCritical() || root._understandChecked
                Accessible.role: Accessible.Button
                Accessible.name: text
                Accessible.description: root.tr(
                    "dialog.review-diff.apply-description",
                    "Apply the reviewed rule set and start the activation")
                onClicked: { root.approved(); root.close() }
            }
        }
    }
}
