# High-Contrast Policy (Block 3.3)

This document fixes high-contrast behavior as a first-class supported theme mode.

## Supported Mode Rule

- High-contrast is selected through `theme_mode=high-contrast`.
- It is not a side-flag variation of other theme modes.
- Legacy persisted `accessibility_high_contrast=true` is migrated to `theme_mode=high-contrast`.

## Mandatory Contrast Pairs

The following token pairs are mandatory for high-contrast readability:

- text on window: `pairTextOnWindowFg` / `pairTextOnWindowBg`
- text on panel: `pairTextOnPanelFg` / `pairTextOnPanelBg`
- muted text on panel: `pairMutedOnPanelFg` / `pairMutedOnPanelBg`
- focus ring: `pairFocusRingFg` / `pairFocusRingBg`
- selection: `pairSelectionFg` / `pairSelectionBg`

Token source: `apps/desktop/qml/theme/ThemeTokens.qml`.

## Icon Behavior In High-Contrast

- Main GUI and dialogs use dedicated high-contrast icon packs:
- `assets/icons/ui-hc/`
- `assets/icons/status-hc/`
- Tray uses dedicated high-contrast tray icons:
- `assets/icons/tray/*-hc.ico`

## Surface Consistency Rule

High-contrast behavior must be consistent in:

- main window
- dialogs
- menus
- tray

All surfaces consume effective mode from centralized theme resolver (`nrr_core::theme::resolve_theme`).

## Compatibility Rule

High-contrast must stay compatible with:

- UI text scaling (`fontScalePercent`)
- system font selection (`systemFont`)

Compatibility checks are included in manual smoke scenarios.
