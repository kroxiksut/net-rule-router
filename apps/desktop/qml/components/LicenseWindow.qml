import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

// Licenses window (extracted from Main.qml). Three tabs: the MPL-2.0 product
// license, the read-only EULA the user accepted at first run, and third-party
// component attribution/integrity. The Help menu, About "License" button, and
// the first-run wizard's "View EULA" button all funnel here. Keeps its
// `licenseWindow` id so Main.qml's alias / overlays wiring and the sibling
// `root.firstRunWindow` transient-parent hand-off are unchanged. Shared state
// via `root`; `openOnEulaTab()` stays on the window (called through
// `root.licenseWindow`).
Window {
    id: licenseWindow

    // ApplicationWindow injected by the caller (`root: window`).
    property var root: null

    width: 720
    height: 560
    visible: false
    modality: Qt.NonModal
    color: root.panelColor
    title: root.tr("action.open-license-window", "Licenses")
    transientParent: root
    flags: Qt.Dialog

    // "mpl" | "eula". Defaults to the product license; the welcome
    // window's "View EULA" button jumps straight to the EULA tab via
    // `openOnEulaTab()`.
    property string activeTab: "mpl"

    // Language of the agreement being READ here, independent of the app's
    // language: the reader may want the other wording without switching the UI.
    property string eulaLanguageOverride: ""
    readonly property string eulaLanguage: eulaLanguageOverride !== ""
        ? eulaLanguageOverride
        : (root ? root.resolveLanguageId(root.prefs.language) : "en")

    function openOnEulaTab() {
        eulaLanguageOverride = ""
        activeTab = "eula"
        // The first-run wizard is WindowModal and transient to the main
        // window. A NonModal window that is transient to the SAME main
        // window stacks UNDER that modal wizard, so opening the Licenses
        // window from the wizard's "View EULA" button hid it behind the
        // wizard. Re-parent onto the wizard while it is up so the
        // Licenses window floats above it; `firstRunWindow.onClosing`
        // restores this to the main window for later normal opens.
        transientParent = root.firstRunWindow.visible ? root.firstRunWindow : root
        root.openChildWindow(licenseWindow)
        raise()
        requestActivate()
    }

    onVisibleChanged: if (visible) { root.centerChildWindow(licenseWindow); root.applyTitleBarTo(licenseWindow) }
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: root.uiTheme.spacingLg
        spacing: root.uiTheme.spacingMd
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("label.license", "License")
                highlighted: licenseWindow.activeTab === "mpl"
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: licenseWindow.activeTab = "mpl"
            }
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("dialog.eula.title", "License agreement") + " (EULA)"
                highlighted: licenseWindow.activeTab === "eula"
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: licenseWindow.activeTab = "eula"
            }
            // Attribution + live integrity of the components shipped from
            // other authors.
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("dialog.third-party.tab", "Third-party components")
                highlighted: licenseWindow.activeTab === "third-party"
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: {
                    licenseWindow.activeTab = "third-party"
                    thirdPartyPanel.reload()
                }
            }
            Item { Layout.fillWidth: true }
        }
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            visible: licenseWindow.activeTab === "third-party"
            ScrollBar.vertical.policy: ScrollBar.AsNeeded
            ThirdPartyComponentsPanel {
                id: thirdPartyPanel
                root: licenseWindow.root
                width: parent.width
            }
        }
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            visible: licenseWindow.activeTab === "mpl"
            ScrollBar.vertical.policy: ScrollBar.AsNeeded
            TextArea {
                readOnly: true
                activeFocusOnTab: true
                wrapMode: TextArea.Wrap
                text: (root.context.about || {}).licenseText || ""
                color: root.textColor
                selectionColor: root.accentColor
                selectedTextColor: palette.highlightedText
                background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
            }
        }
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            visible: licenseWindow.activeTab === "eula"
            ScrollBar.vertical.policy: ScrollBar.AsNeeded
            TextArea {
                readOnly: true
                activeFocusOnTab: true
                wrapMode: TextArea.Wrap
                textFormat: TextArea.MarkdownText
                // Same bilingual source as `eulaAgreementWindow`
                // (`context.eula.{text,textRu,textEn}`), rendered in the
                // app's CURRENT language rather than the accepted one —
                // this is a read-only viewer, not the acceptance gate.
                text: {
                    var eula = (root.context || {}).eula || {}
                    var lang = licenseWindow.eulaLanguage
                    var localized = lang === "ru" ? eula.textRu : eula.textEn
                    return (localized && String(localized).length > 0)
                        ? localized : String(eula.text || "")
                }
                color: root.textColor
                selectionColor: root.accentColor
                selectedTextColor: palette.highlightedText
                background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }
                Accessible.role: Accessible.StaticText
                Accessible.name: root.tr("dialog.eula.text-accessible-name",
                    "License agreement text")
            }
        }
        RowLayout {
            Layout.fillWidth: true
            // Same bilingual switch the acceptance window offers, so the
            // agreement reads the same way wherever it is opened.
            ThemedButton {
                theme: root.uiTheme
                visible: licenseWindow.activeTab === "eula"
                    && String(((root.context || {}).eula || {}).textRu || "").length > 0
                    && String(((root.context || {}).eula || {}).textEn || "").length > 0
                text: licenseWindow.eulaLanguage === "ru"
                    ? root.tr("dialog.eula.switch-to-english", "English")
                    : root.tr("dialog.eula.switch-to-russian", "Русский")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: licenseWindow.eulaLanguageOverride =
                    (licenseWindow.eulaLanguage === "ru") ? "en" : "ru"
            }
            Item { Layout.fillWidth: true }
            ThemedButton { theme: root.uiTheme; text: root.tr("action.close", "Close"); onClicked: licenseWindow.close() }
        }
    }
}
