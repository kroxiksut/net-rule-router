# Theme Switching Architecture (Block 3.2)

This document defines runtime theme switching behavior for GUI and tray surfaces.

## Single Source Of Truth

- Canonical resolver: `nrr_core::theme::resolve_theme(...)`
- Input:
- selected theme mode (`light` / `dark` / `system` / `high-contrast`)
- accessibility high-contrast flag
- optional system theme hint (`NRR_SYSTEM_THEME`)
- Output:
- selected mode
- effective mode
- resolved system mode (`light`/`dark`)
- detection flag (`systemModeDetected`)

Both GUI and tray consume this resolver output in their runtime context payload.

## `system` Theme Behavior And Fallback

- Primary source on Windows: registry value `HKCU\\...\\Themes\\Personalize\\AppsUseLightTheme`
- Optional explicit override for tests/dev: `NRR_SYSTEM_THEME=light|dark`
- Fallback when system mode cannot be detected: `light` (fail-safe deterministic baseline)

## Surface Application Scope

- Main window, dialogs, popups, menu bar: consume centralized QML token layer and effective mode.
- Tray runtime: receives the same effective-theme context and uses it for unified runtime decisions.

## No-Artefact Rule

- Theme changes must update all opened GUI surfaces using shared token bindings.
- No surface may cache direct color constants outside token layer.
