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
    readonly property color colorAccent: isHighContrast ? "#ffd24d" : isDark ? "#6c9bff" : "#2f6feb"
    readonly property color colorWarning: isHighContrast ? "#ffb020" : isDark ? "#f0a030" : "#b05207"
    readonly property color colorDanger: isHighContrast ? "#ff6b6b" : isDark ? "#ff6b6b" : "#c92a2a"
    readonly property color colorSuccess: isHighContrast ? "#9be58f" : isDark ? "#4cc38a" : "#23744a"
    readonly property color colorOnAccent: isHighContrast ? "#000000" : isDark ? "#0b1020" : "#ffffff"
    // The logo's purple: only the ring round a focused button or list,
    // lighter in the dark theme, the contrast theme's own accent there.
    readonly property color colorBrand: isHighContrast ? "#ffd24d" : isDark ? "#9b6cf0" : "#783ade"
    readonly property color colorButtonOutline: colorBrand
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
    // A one-pixel accent ring vanished on accent-filled controls and was easy
    // to miss on the rest.
    readonly property int focusBorderWidth: 2

    // Component-state tokens
    readonly property color stateDefaultFill: colorPanel
    readonly property color stateHoverFill: Qt.lighter(colorPanel, isDark ? 1.10 : 1.03)
    readonly property color statePressedFill: Qt.darker(colorPanel, isDark ? 1.12 : 1.04)
    readonly property color stateFocusedFill: Qt.tint(colorPanel, Qt.rgba(colorFocusRing.r, colorFocusRing.g, colorFocusRing.b, isHighContrast ? 0.32 : 0.18))
    readonly property color stateDisabledFill: Qt.rgba(colorPanel.r, colorPanel.g, colorPanel.b, isDark ? 0.60 : 0.72)
    readonly property color stateSelectedFill: colorAccent
    readonly property color stateDefaultBorder: colorBorder
    readonly property color stateFocusedBorder: colorFocusRing
    // On a control filled with the accent (or the danger colour) the accent
    // ring has nothing to stand out against: the outer ring in the brand
    // colour (white on the contrast theme) shows against the panel, the inner
    // one in the on-accent colour against the fill (white on the contrast
    // theme's yellow read at 1.4:1).
    readonly property color stateFocusedBorderOnFill: isHighContrast ? "#ffffff" : colorButtonOutline
    readonly property color stateFocusedInnerOnFill: colorOnAccent
    readonly property color stateDisabledBorder: Qt.rgba(colorBorder.r, colorBorder.g, colorBorder.b, 0.55)
    readonly property color stateSelectedBorder: colorAccent

    // Top-of-window banners: white text at no less than 4.5:1 on every fill.
    // The contrast theme draws them black with a white frame, the same as its
    // panels, so the frame, not a hue, sets them apart from the window.
    readonly property color bannerText: "#ffffff"
    readonly property color bannerNeutralFill: isHighContrast ? "#000000" : "#475569"
    readonly property color bannerInfoFill: isHighContrast ? "#000000" : "#2c6fbb"
    readonly property color bannerSuccessFill: isHighContrast ? "#000000" : "#2d6a4f"
    readonly property color bannerWarningFill: isHighContrast ? "#000000" : "#8a5a00"
    readonly property color bannerDangerFill: isHighContrast ? "#000000" : "#c0392b"
    readonly property int bannerBorderWidth: isHighContrast ? 2 : 0
    readonly property color bannerBorder: colorText

    readonly property bool useHighContrastIcons: isHighContrast
    readonly property string resolvedFontFamily:
        systemFont === "segoe-ui" ? "Segoe UI" :
        systemFont === "arial" ? "Arial" :
        systemFont === "tahoma" ? "Tahoma" :
        systemFont === "verdana" ? "Verdana" :
        Qt.application.font.family
}
