import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

// End-user license agreement (EULA) gate — shown on first launch, and again
// whenever the agreement version bumps, BEFORE any other startup dialog.
//
// The agreement text arrives in the QML context (`context.eula.text`, built by
// the Rust `ui_surface` loader from `docs/legal/eula.<lang>.md`), so this file
// carries no legal text — only the chrome, which is fully localised via
// `ownerRoot.tr(...)`.
//
// Gate: "Accept" is enabled only after the user ticks the acknowledgement
// checkbox. Declining — or closing the window — quits the application, matching
// the agreement's own "if you do not agree, do not use the program" clause.
// The caller (Main.qml) persists `acceptedEulaVersion` on `accepted()` and
// calls `Qt.quit()` on `declined()`.
Window {
    id: root

    property var ownerRoot
    // The agreement text and the version this acceptance records.
    property string agreementText: ""
    property int agreementVersion: 0
    // Bilingual agreement text supplied by the QML context. When both are
    // populated the user can switch between them at the bottom of the window;
    // when empty we fall back to the single `agreementText` (back-compat).
    property string textRu: ""
    property string textEn: ""
    // Default language to show first ("ru" | "en"), and the user's explicit
    // override (empty until they press the switch button).
    property string defaultLanguage: "en"
    property string selectedLanguage: ""
    // Effective language actually rendered / recorded on accept.
    readonly property string effectiveLanguage: selectedLanguage !== ""
        ? selectedLanguage
        : defaultLanguage
    // Effective agreement body: the effective language's text, falling back to
    // the legacy single-text property when the bilingual fields are empty.
    readonly property string effectiveText: {
        var t = effectiveLanguage === "ru" ? textRu : textEn
        return (t && t.length > 0) ? t : agreementText
    }
    // Guards the quit-on-close behaviour: set true just before we close after
    // an explicit Accept, so `onClosing` does not treat it as a decline.
    property bool _accepted: false

    signal accepted()
    signal declined()

    // Reset the scroll position to the top whenever the shown language changes,
    // so the user starts reading the freshly-switched text from the beginning.
    onSelectedLanguageChanged: {
        if (agreementScroll && agreementScroll.contentItem) {
            agreementScroll.contentItem.contentY = 0
        }
    }

    function tr(key, fallback) {
        return ownerRoot && typeof ownerRoot.tr === "function"
            ? ownerRoot.tr(key, fallback)
            : (fallback || key)
    }

    // API-compatible with the other modal child windows in Main.qml.
    function open() { _accepted = false; acknowledgeCheckbox.checked = false; visible = true }

    width: 820
    height: 640
    minimumWidth: 560
    minimumHeight: 420
    visible: false
    modality: Qt.ApplicationModal
    flags: Qt.Dialog
    color: ownerRoot ? ownerRoot.panelColor : "#202020"
    title: tr("dialog.eula.title", "License agreement")
    transientParent: ownerRoot ? ownerRoot : null

    onVisibleChanged: {
        if (visible && ownerRoot) {
            if (typeof ownerRoot.centerChildWindow === "function") {
                ownerRoot.centerChildWindow(root)
            }
            if (typeof ownerRoot.applyTitleBarTo === "function") {
                ownerRoot.applyTitleBarTo(root)
            }
        }
    }

    // Closing the window via the title-bar X without accepting is a decline.
    onClosing: function(close) {
        if (!root._accepted) {
            root.declined()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 18
        spacing: 12

        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            font.bold: true
            font.pixelSize: 15
            color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            text: root.tr("dialog.eula.heading",
                "Please read and accept the agreement to continue")
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            color: root.ownerRoot ? root.ownerRoot.mutedTextColor : "gray"
            text: root.tr("dialog.eula.subheading",
                "Installing, running, or using NetRuleRouter means you accept the terms below.")
        }

        ScrollView {
            id: agreementScroll
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            ScrollBar.vertical.policy: ScrollBar.AsNeeded
            TextArea {
                id: agreementArea
                readOnly: true
                activeFocusOnTab: true
                wrapMode: TextArea.Wrap
                textFormat: TextArea.MarkdownText
                text: root.effectiveText
                color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                selectionColor: root.ownerRoot ? root.ownerRoot.accentColor : "#3d6fb4"
                selectedTextColor: root.ownerRoot ? root.ownerRoot.textColor : "white"
                background: CardSurface {
                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                    cornerRadius: root.ownerRoot ? root.ownerRoot.uiTheme.radiusSm : 4
                }
                Accessible.role: Accessible.StaticText
                Accessible.name: root.tr("dialog.eula.text-accessible-name",
                    "License agreement text")
            }
        }

        CheckBox {
            id: acknowledgeCheckbox
            Layout.fillWidth: true
            text: root.tr("dialog.eula.acknowledge",
                "I have read and accept the terms of the agreement")
            contentItem: Text {
                text: acknowledgeCheckbox.text
                leftPadding: acknowledgeCheckbox.indicator.width + acknowledgeCheckbox.spacing
                verticalAlignment: Text.AlignVCenter
                wrapMode: Text.WordWrap
                color: root.ownerRoot ? root.ownerRoot.textColor : "white"
            }
            Accessible.role: Accessible.CheckBox
            Accessible.name: text
            Accessible.description: root.tr("dialog.eula.acknowledge-description",
                "Required acknowledgement before you can accept the agreement and use the program")
        }

        // Action row: language switch on the left (visually secondary),
        // accept / decline on the right.
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 4
            spacing: 8

            // Bilingual switch — the label names the TARGET language, in that
            // language. Only meaningful when a second translation is present.
            ThemedButton {
                theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                visible: root.textRu.length > 0 && root.textEn.length > 0
                text: root.effectiveLanguage === "ru"
                    ? root.tr("dialog.eula.switch-to-english", "English")
                    : root.tr("dialog.eula.switch-to-russian", "Русский")
                Accessible.role: Accessible.Button
                Accessible.name: text
                onClicked: {
                    root.selectedLanguage =
                        (root.effectiveLanguage === "ru") ? "en" : "ru"
                }
            }

            Item { Layout.fillWidth: true }

            // Accept / decline wrap on narrow displays via Flow.
            Flow {
                spacing: 8
                layoutDirection: Qt.RightToLeft
                ThemedButton {
                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                    text: root.tr("dialog.eula.accept", "Accept and continue")
                    highlighted: true
                    enabled: acknowledgeCheckbox.checked
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    onClicked: {
                        root._accepted = true
                        root.accepted()
                        root.close()
                    }
                }
                ThemedButton {
                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                    text: root.tr("dialog.eula.decline", "Decline and exit")
                    Accessible.role: Accessible.Button
                    Accessible.name: text
                    // Just close; `onClosing` emits `declined()` exactly once,
                    // covering both this button and the title-bar X.
                    onClicked: root.close()
                }
            }
        }
    }
}
