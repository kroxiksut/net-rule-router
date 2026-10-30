import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

// End-user license agreement (EULA) gate — shown on first launch, and again
// whenever the agreement version bumps, BEFORE any other startup dialog.
//
// The agreement text arrives in the QML context (`context.eula.text`, built by
// the Rust `ui_surface` loader from `docs/legal/eula.<lang>.md`), so this file
// carries no legal text — only the chrome, which speaks the window's language
// until the user switches the agreement, and the agreement's language after.
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
    // The acknowledgement tick; "Accept" stays disabled until it is set.
    property bool acknowledged: false
    // The content is built on the first show and kept: almost every session
    // never shows this window, and the agreement is a laid-out document.
    property bool contentBuilt: false

    signal accepted()
    signal declined()

    function tr(key, fallback) {
        if (!ownerRoot) return fallback || key
        return selectedLanguage !== "" && typeof ownerRoot.resolveCatalogText === "function"
            ? ownerRoot.resolveCatalogText(selectedLanguage, key, fallback)
            : ownerRoot.tr(key, fallback)
    }

    // API-compatible with the other modal child windows in Main.qml.
    function open() { _accepted = false; acknowledged = false; visible = true }

    // The size the window opens at; `_fitOnScreen` shrinks it to the free area.
    readonly property int _designWidth: 820
    readonly property int _designHeight: 640
    // The title bar and frame the window system draws outside `height`.
    readonly property int _frameAllowance: 40

    width: _designWidth
    height: _designHeight
    minimumWidth: 560
    minimumHeight: 420
    visible: false
    modality: Qt.ApplicationModal
    flags: Qt.Dialog
    color: ownerRoot ? ownerRoot.panelColor : "#202020"
    title: tr("dialog.eula.title", "License agreement")
    transientParent: ownerRoot ? ownerRoot : null

    /// Fits the window, frame included, into the part of its screen the taskbar
    /// leaves free, so the decision buttons are never under the taskbar; the
    /// agreement text scrolls in what is left.
    function _fitOnScreen() {
        var freeHeight = Math.min(Screen.height, Screen.desktopAvailableHeight)
        var freeWidth = Math.min(Screen.width, Screen.desktopAvailableWidth)
        height = Math.max(minimumHeight, Math.min(_designHeight, freeHeight - _frameAllowance - 8))
        width = Math.max(minimumWidth, Math.min(_designWidth, freeWidth - 16))
        var bottom = Screen.virtualY + freeHeight - 8
        if (y + height > bottom) y = bottom - height
        if (y < Screen.virtualY + _frameAllowance) y = Screen.virtualY + _frameAllowance
        var right = Screen.virtualX + freeWidth - 8
        if (x + width > right) x = right - width
        if (x < Screen.virtualX + 8) x = Screen.virtualX + 8
    }

    onVisibleChanged: {
        if (visible) {
            contentBuilt = true
        }
        if (visible && ownerRoot) {
            if (typeof ownerRoot.centerChildWindow === "function") {
                ownerRoot.centerChildWindow(root)
            }
            if (typeof ownerRoot.applyTitleBarTo === "function") {
                ownerRoot.applyTitleBarTo(root)
            }
        }
        if (visible) _fitOnScreen()
    }
    // A taskbar that appears, or a screen that changes, while the window is up.
    Screen.onDesktopAvailableHeightChanged: if (visible) _fitOnScreen()
    Screen.onDesktopAvailableWidthChanged: if (visible) _fitOnScreen()
    onScreenChanged: if (visible) Qt.callLater(_fitOnScreen)

    // Closing the window via the title-bar X without accepting is a decline.
    onClosing: function(close) {
        if (!root._accepted) {
            root.declined()
        }
    }

    Loader {
        anchors.fill: parent
        anchors.margins: 18
        active: root.contentBuilt
        sourceComponent: agreementContentComponent
    }
    Component {
        id: agreementContentComponent
        ColumnLayout {
            spacing: 12

            // Reset the scroll position to the top whenever the shown language
            // changes, so the freshly-switched text is read from the beginning.
            Connections {
                target: root
                function onSelectedLanguageChanged() {
                    if (agreementScroll.contentItem) {
                        agreementScroll.contentItem.contentY = 0
                    }
                }
            }

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
                ThemedTextArea {
                    theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                    readOnly: true
                    activeFocusOnTab: true
                    wrapMode: TextArea.Wrap
                    textFormat: TextArea.MarkdownText
                    text: root.effectiveText
                    color: root.ownerRoot ? root.ownerRoot.textColor : "white"
                    selectionColor: root.ownerRoot ? root.ownerRoot.accentColor : "#3d6fb4"
                    selectedTextColor: root.ownerRoot ? root.ownerRoot.textColor : "white"
                    Accessible.role: Accessible.StaticText
                    Accessible.name: root.tr("dialog.eula.text-accessible-name",
                        "License agreement text")
                }
            }

            CheckBox {
                id: acknowledgeCheckbox
                Layout.fillWidth: true
                // A C++ toggle keeps this binding, so `open()` clearing
                // `acknowledged` also clears a tick left from an earlier show.
                checked: root.acknowledged
                onToggled: root.acknowledged = checked
                text: root.tr("dialog.eula.acknowledge",
                    "I have read and accept the terms of the agreement")
                // Until it is ticked, a red frame shows what holds "Accept" back.
                padding: 6
                background: Rectangle {
                    color: "transparent"
                    radius: 4
                    border.width: acknowledgeCheckbox.checked ? 0 : 2
                    border.color: root.ownerRoot ? root.ownerRoot.uiTheme.colorDanger : "#d32f2f"
                }
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

                // Accept / decline take the rest of the row, right-aligned, and wrap
                // on narrow displays.
                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: decisionFlow.height
                    Flow {
                        id: decisionFlow
                        anchors.left: parent.left
                        anchors.right: parent.right
                        spacing: 8
                        layoutDirection: Qt.RightToLeft
                        ThemedButton {
                            theme: root.ownerRoot ? root.ownerRoot.uiTheme : null
                            text: root.tr("dialog.eula.accept", "Accept and continue")
                            highlighted: true
                            enabled: root.acknowledged
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
    }
}
