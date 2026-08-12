import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import "../../components"
import "../../lib/pure.js" as Pure

GroupBox {
    property var root
    title: root.tr("settings.group.appearance", "Appearance")
    Layout.fillWidth: true
    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingSm
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.field.theme", "Theme")
            color: root.mutedTextColor
        }
        ThemedComboBox {
            id: themeCombo
            theme: root.uiTheme
            Layout.fillWidth: true
            model: [ "light", "dark", "system", "high-contrast" ]
            labelResolver: function(item) { return root.themeLabel(item) }
            displayText: root.uiRevision >= 0 && currentIndex >= 0
                ? root.themeLabel(model[currentIndex]) : ""
            currentIndex: Pure.optionIndexByValue(model, root.prefs.themeMode, 2)
            popup.width: root.comboPopupWidth(themeCombo, themeCombo.model, "",
                function(item) { return root.themeLabel(item) })
            onActivated: root.updatePrefs({ themeMode: model[currentIndex] })
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            text: root.tr("settings.field.ui-scale", "UI scale") + ": "
                + Math.round(fontScaleSlider.value) + "%"
            color: root.mutedTextColor
        }
        RowLayout {
            Layout.fillWidth: true
            spacing: root.uiTheme.spacingSm
            ThemedButton {
                theme: root.uiTheme
                text: "-"
                Layout.preferredWidth: 40
                onClicked: root.updatePrefs({
                    fontScalePercent: Pure.normalizedFontScalePercent(
                        root.prefs.fontScalePercent - fontScaleSlider.stepSize)
                })
            }
            Slider {
                id: fontScaleSlider
                Layout.fillWidth: true
                from: 80
                to: 300
                stepSize: 5
                snapMode: Slider.SnapAlways
                // The prefs commit bumps `themeRevision`, which forces a full
                // theme-token recompute of the whole UI tree; doing it on every
                // drag tick froze the app. Instead the value label updates live
                // from `value` while prefs stays untouched, and the commit fires
                // once the interaction settles: on pointer release, or after a
                // short idle for keyboard/wheel/accessibility changes. The
                // Binding below re-asserts the external pref value onto the
                // handle whenever the user is not actively changing it, so
                // programmatic pref updates (buttons, reset, import) still move
                // the slider.
                onPressedChanged: {
                    if (!pressed)
                        fontScaleCommitTimer.restart()
                }
                onMoved: {
                    if (!pressed)
                        fontScaleCommitTimer.restart()
                }
                Timer {
                    id: fontScaleCommitTimer
                    interval: 150
                    repeat: false
                    onTriggered: root.updatePrefs({
                        fontScalePercent: Pure.normalizedFontScalePercent(
                            fontScaleSlider.value)
                    })
                }
                Binding {
                    target: fontScaleSlider
                    property: "value"
                    value: root.uiRevision >= 0
                        ? Number(root.prefs.fontScalePercent || 100) : 100
                    when: !fontScaleSlider.pressed && !fontScaleCommitTimer.running
                }
            }
            ThemedButton {
                theme: root.uiTheme
                text: "+"
                Layout.preferredWidth: 40
                onClicked: root.updatePrefs({
                    fontScalePercent: Pure.normalizedFontScalePercent(
                        root.prefs.fontScalePercent + fontScaleSlider.stepSize)
                })
            }
        }
    }
}
