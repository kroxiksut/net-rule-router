# Accessibility Localization Policy (Block 3.8)

This document defines mandatory localization coverage for accessibility-oriented strings.

## Mandatory Key Families

Main GUI:

- `a11y.high-contrast`
- `a11y.enhanced-focus`
- `a11y.simplified-labels`
- `settings.field.tooltips`

Tray accessibility status text (text alternatives for tray status/icon state):

- `a11y.tray.status-text.preview-mode`
- `a11y.tray.status-text.no-active-policy`
- `a11y.tray.status-text.service-unavailable`

Tray action accessibility labels:

- `a11y.tray.action-label.<action-id>`

Tray action accessibility descriptions:

- `a11y.tray.action-description.<action-id>`

Setup-state notes for tray actions:

- `a11y.tray.setup-state.allowed`
- `a11y.tray.setup-state.soft-guided`
- `a11y.tray.setup-state.blocked-until-wizard-completion`
- `a11y.tray.preview-only-note`

## Key Format

Accessibility keys use the same canonical dotted schema as UI keys.

- Accessible label: `a11y.<surface>.action-label.<action-id>`
- Accessible description: `a11y.<surface>.action-description.<action-id>`
- Status narration text: `a11y.<surface>.status-text.<status-id>`
- Text alternatives for icon/state-only elements: use the same `status-text` family

## Runtime Rule

- Accessibility strings must be resolved through the shared locale resolver.
- Hardcoded end-user accessibility text in runtime code is not allowed when locale keys exist.
- Missing accessibility keys must not crash UI, but are treated as localization coverage defects.
