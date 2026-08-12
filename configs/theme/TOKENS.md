# Theme Tokens Baseline (Block 3.1)

This document fixes the foundation token set for GUI v1.

## Source Of Tokens

- QML runtime token layer: `apps/desktop/qml/theme/ThemeTokens.qml`
- Reusable surface components:
- `apps/desktop/qml/components/PanelSurface.qml`
- `apps/desktop/qml/components/CardSurface.qml`

## Theme Modes

- `light`
- `dark`
- `system` (resolved by runtime policy, currently mapped to light baseline)
- `high-contrast`

## Color Tokens

- `colorWindow`
- `colorPanel`
- `colorBase`
- `colorText`
- `colorTextMuted`
- `colorBorder`
- `colorAccent`
- `colorWarning`
- `colorSuccess`
- `colorOnAccent`

## Typography Tokens

- `baseFontSizePx`
- `headingScale`
- `subtitleScale`
- `compactLineHeight`
- `regularLineHeight`
- `comfortableLineHeight`
- `resolvedFontFamily`

## Density And Shape Tokens

- spacing: `spacingXxs`, `spacingXs`, `spacingSm`, `spacingMd`, `spacingLg`, `spacingXl`
- radii: `radiusSm`, `radiusMd`, `radiusLg`
- border: `borderWidth`

## Component State Tokens

- fill: `stateDefaultFill`, `stateHoverFill`, `statePressedFill`, `stateFocusedFill`, `stateDisabledFill`, `stateSelectedFill`
- border: `stateDefaultBorder`, `stateFocusedBorder`, `stateDisabledBorder`, `stateSelectedBorder`

## Required Rule For New UI

- New screens/dialogs must not define direct colors, radii, or spacings in-place.
- New screens/dialogs must consume tokens from the centralized theme layer.
- Ad-hoc style constants in feature screens are forbidden unless explicitly approved as migration exceptions.
