import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../theme"
import "../components"
import "settings"

// Settings is a single content pane: the category list lives in the navigation
// sidebar, so the window already says which category is active and a second
// rail here would be a column of navigation next to a column of navigation.
// Reset and About sit in this pane's footer, anchored below whichever category
// is showing.
//
// The five basic-application groups (General / Appearance / Accessibility /
// Language / Route names) are merged under a single "Application" category
// and stacked vertically — they are tightly related and one short scroll keeps
// the user focused, instead of forcing a click for each of five entries.
RowLayout {
    id: section
    property var root
    spacing: root.uiTheme.spacingMd

    // Chosen in the sidebar; the loaders below key their laziness off it.
    readonly property string activeCategory: root.settingsCategory

    ColumnLayout {
        Layout.fillWidth: true
        Layout.fillHeight: true
        spacing: root.uiTheme.spacingSm

        ScrollView {
            id: settingsScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            // Bind contentWidth to the available viewport width so the
            // child ColumnLayout takes the full pane width (otherwise
            // ScrollView leaves the content at implicit width and the
            // GroupBoxes do not stretch to follow window resize).
            contentWidth: availableWidth
            ColumnLayout {
                width: settingsScroll.availableWidth
                spacing: root.uiTheme.spacingMd

                // Perf — each category's panels load LAZILY via
                // a per-category Loader instead of being built eagerly and
                // hidden with `visible:`. Previously all ~12 panels (and their
                // live bindings, re-evaluated on every uiRevision/themeRevision
                // bump) instantiated the moment Settings first opened — the
                // dominant cost behind "switching to settings is slow". Now
                // only the active category builds; `keepLoaded` latches so a
                // re-visited category isn't rebuilt, and unvisited categories
                // never cost anything.

                // "Application" — the five basic-application groups stacked.
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "application" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "application"
                    asynchronous: true
                    sourceComponent: ColumnLayout {
                        width: parent ? parent.width : implicitWidth
                        spacing: root.uiTheme.spacingMd
                        GeneralSettings { root: section.root; Layout.fillWidth: true }
                        AppearanceSettings { root: section.root; Layout.fillWidth: true }
                        AccessibilitySettings { root: section.root; Layout.fillWidth: true }
                        LanguageSettings { root: section.root; Layout.fillWidth: true }
                        RouteLabelsSettings { root: section.root; Layout.fillWidth: true }
                    }
                }

                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "diagnostics" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "diagnostics"
                    asynchronous: true
                    sourceComponent: ColumnLayout {
                        width: parent ? parent.width : implicitWidth
                        spacing: root.uiTheme.spacingMd
                        DiagnosticsLogsSettings { root: section.root; Layout.fillWidth: true }
                        StorageUsagePanel { root: section.root; Layout.fillWidth: true }
                    }
                }
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "traffic" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "traffic"
                    asynchronous: true
                    sourceComponent: TrafficStatsSettings {
                        root: section.root
                        Layout.fillWidth: true
                        categoryActive: section.activeCategory === "traffic"
                    }
                }
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "routing" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "routing"
                    asynchronous: true
                    sourceComponent: RoutingSettings { root: section.root; Layout.fillWidth: true }
                }
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "service" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "service"
                    asynchronous: true
                    sourceComponent: ColumnLayout {
                        width: parent ? parent.width : implicitWidth
                        spacing: root.uiTheme.spacingMd
                        ServiceManagementSettings { root: section.root; Layout.fillWidth: true }
                        ConsolePathSettings { root: section.root; Layout.fillWidth: true }
                    }
                }
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "presets" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "presets"
                    asynchronous: true
                    sourceComponent: PresetSettings { root: section.root; Layout.fillWidth: true }
                }
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "experimental" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "experimental"
                    asynchronous: true
                    sourceComponent: ExperimentalSettings { root: section.root; Layout.fillWidth: true }
                }
                Loader {
                    Layout.fillWidth: true
                    property bool keepLoaded: false
                    active: section.activeCategory === "updates" || keepLoaded
                    onActiveChanged: if (active) keepLoaded = true
                    visible: section.activeCategory === "updates"
                    asynchronous: true
                    sourceComponent: UpdatesSettings { root: section.root; Layout.fillWidth: true }
                }

                Item { Layout.fillHeight: true }
            }
        }

        // Footer row with global actions. Sits in the right pane so its
        // wide labels never collide with the narrow left rail.
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedButton {
                theme: root.uiTheme
                text: root.uiRevision >= 0
                    ? root.tr("action.reset-application-settings", "Reset application settings") : ""
                icon.source: root.uiIconSource("refresh")
                onClicked: root.resetDefaults()
            }
            // Full reset to post-install state
            // (settings + service rules + sidecar + logs). Behind a strong
            // destructive confirm dialog.
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.full-reset", "Full reset…")
                icon.source: root.uiIconSource("reset")
                onClicked: root.fullResetConfirmDialog.open()
            }
            Item { Layout.fillWidth: true }
            ThemedButton {
                theme: root.uiTheme
                text: root.aboutAction.text
                icon.source: root.uiIconSource("about")
                onClicked: root.aboutAction.trigger()
            }
        }
    }
}
