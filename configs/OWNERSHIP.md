# Ownership Matrix

This document defines ownership for block 3 maintenance areas.

## Matrix

| Area | Primary Owner | Review Partner | Mandatory Artifacts |
|---|---|---|---|
| Theme tokens (`configs/theme/*`, `apps/desktop/qml/theme/*`) | GUI/UX maintainer | Accessibility maintainer | Token docs update + smoke evidence |
| Locale schema and key contracts (`configs/localization/*schema*`, `KEY_SCHEMA*`) | Localization contract maintainer | GUI runtime maintainer | Schema/key docs update + contract tests |
| Baseline translations (`locales/en.json`, `locales/ru.json`) | Localization maintainer | Feature owner of changed UI | Updated locale files + localization test run |

## Ownership Rules

- Changes in these areas are not complete without at least one review partner approval.
- If one contributor owns multiple areas in one change, assign a separate reviewer for cross-check.
- Ownership updates are tracked in the same PR as technical changes when responsibilities shift.
