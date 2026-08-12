import QtQuick 2.15

QtObject {
    id: root

    property string themeMode: "system"
    property bool accessibilityHighContrast: false
    property int fontScalePercent: 100
    property string systemFont: "system-default"

    readonly property bool isHighContrast: accessibilityHighContrast || themeMode === "high-contrast"
    readonly property bool isDark: isHighContrast || themeMode === "dark"

    // Color tokens
    readonly property color colorWindow: isHighContrast ? "#111111" : isDark ? "#1f2328" : "#f4f6f8"
    readonly property color colorPanel: isHighContrast ? "#1a1a1a" : isDark ? "#2a3038" : "#ffffff"
    readonly property color colorBase: isHighContrast ? "#0b0b0b" : isDark ? "#171b21" : "#eef2f6"
    readonly property color colorText: isHighContrast ? "#ffffff" : isDark ? "#f5f7fa" : "#1f2933"
    readonly property color colorTextMuted: isHighContrast ? "#d7d7d7" : isDark ? "#c9d1d9" : "#52606d"
    readonly property color colorBorder: isHighContrast ? "#ffffff" : isDark ? "#47515f" : "#cbd2d9"
    readonly property color colorAccent: isHighContrast ? "#ffd24d" : "#2f6feb"
    readonly property color colorWarning: isHighContrast ? "#ffb020" : "#d97706"
    readonly property color colorDanger: isHighContrast ? "#ff6b6b" : isDark ? "#f14c4c" : "#c92a2a"
    readonly property color colorSuccess: isHighContrast ? "#9be58f" : "#2e8b57"
    readonly property color colorOnAccent: isHighContrast ? "#000000" : "#ffffff"
    readonly property color colorFocusRing: isHighContrast ? "#ffd24d" : colorAccent
    readonly property color colorSelection: isHighContrast ? "#ffd24d" : Qt.tint(colorBase, Qt.rgba(colorAccent.r, colorAccent.g, colorAccent.b, 0.35))

    // Mandatory contrast pair tokens for accessibility/high-contrast policy.
    readonly property color pairTextOnWindowFg: colorText
    readonly property color pairTextOnWindowBg: colorWindow
    readonly property color pairTextOnPanelFg: colorText
    readonly property color pairTextOnPanelBg: colorPanel
    readonly property color pairMutedOnPanelFg: colorTextMuted
    readonly property color pairMutedOnPanelBg: colorPanel
    readonly property color pairFocusRingFg: colorFocusRing
    readonly property color pairFocusRingBg: colorPanel
    readonly property color pairSelectionFg: colorOnAccent
    readonly property color pairSelectionBg: colorSelection

    // Typography tokens
    readonly property int baseFontSizePx: Math.max(12, Math.round(14 * Math.max(80, fontScalePercent) / 100))
    readonly property real headingScale: 1.15
    readonly property real subtitleScale: 1.05
    readonly property real compactLineHeight: 1.2
    readonly property real regularLineHeight: 1.35
    readonly property real comfortableLineHeight: 1.5

    // Density and shape tokens
    readonly property int spacingXxs: 2
    readonly property int spacingXs: 4
    readonly property int spacingSm: 8
    readonly property int spacingMd: 12
    readonly property int spacingLg: 16
    readonly property int spacingXl: 20
    readonly property int radiusSm: 4
    readonly property int radiusMd: 6
    readonly property int radiusLg: 8
    readonly property int borderWidth: 1

    // Component-state tokens
    readonly property color stateDefaultFill: colorPanel
    readonly property color stateHoverFill: Qt.lighter(colorPanel, isDark ? 1.10 : 1.03)
    readonly property color statePressedFill: Qt.darker(colorPanel, isDark ? 1.12 : 1.04)
    readonly property color stateFocusedFill: Qt.tint(colorPanel, Qt.rgba(colorFocusRing.r, colorFocusRing.g, colorFocusRing.b, isHighContrast ? 0.32 : 0.18))
    readonly property color stateDisabledFill: Qt.rgba(colorPanel.r, colorPanel.g, colorPanel.b, isDark ? 0.60 : 0.72)
    readonly property color stateSelectedFill: colorAccent
    readonly property color stateDefaultBorder: colorBorder
    readonly property color stateFocusedBorder: colorFocusRing
    readonly property color stateDisabledBorder: Qt.rgba(colorBorder.r, colorBorder.g, colorBorder.b, 0.55)
    readonly property color stateSelectedBorder: colorAccent

    readonly property bool useHighContrastIcons: isHighContrast
    readonly property string resolvedFontFamily:
        systemFont === "segoe-ui" ? "Segoe UI" :
        systemFont === "arial" ? "Arial" :
        systemFont === "tahoma" ? "Tahoma" :
        systemFont === "verdana" ? "Verdana" :
        Qt.application.font.family
}
