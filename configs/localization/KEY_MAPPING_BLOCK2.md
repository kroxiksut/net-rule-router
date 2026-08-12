# Block-2 Key Mapping to Canonical 3.5 Scheme

This document tracks existing block-2 localization keys and the target 3.5 naming form.

## Existing Block-2 Key Groups

- navigation/menu: `menu.*`, `section.*`
- actions: `action.*`
- settings: `settings.group.*`, `settings.field.*`, `settings.note.*`
- dialogs: `dialog.*`
- statuses: `status.*`
- interfaces/rules: `interfaces.*`, `rules.*`
- first-run flow: `first-run.*`
- tray statuses: `tray.status.*`, `tray.status-accessibility.*`
- accessibility toggles: `a11y.*`
- labels: `label.*`
- theme values: `theme.*` (legacy alias domain)

## Mapping Rules

- canonical target format: `<domain>.<surface>.<element>.<state>`
- domain is preserved where possible (`action`, `dialog`, `status`, ...)
- missing `surface` in legacy keys is added by UI ownership (`screen`, `dialog`, `menu`, `tray`, `wizard`, `window`)
- missing semantic suffixes are added as `title`/`description`/`action`/`success`/`warning`

## Representative Mapping (Legacy -> Canonical)

- `menu.file` -> `menu.menu.file.title`
- `menu.view` -> `menu.menu.view.title`
- `section.interfaces-routes` -> `section.screen.interfaces-routes.title`
- `action.open-main-window` -> `action.window.open-main-window.action`
- `action.check-service-status` -> `action.tray.check-service-status.action`
- `settings.group.general` -> `settings.screen.general.title`
- `settings.field.theme` -> `settings.screen.theme.label`
- `settings.note.route-labels` -> `settings.screen.route-labels.description`
- `dialog.load-list.title` -> `dialog.dialog.load-list.title`
- `dialog.load-list.note` -> `dialog.dialog.load-list.description`
- `status.rule-added` -> `status.screen.rule-added.success`
- `status.rollback-preview` -> `status.screen.rollback-preview.warning`
- `interfaces.preview-notice` -> `interfaces.screen.preview-notice.description`
- `interfaces.mode.auto-recommended` -> `interfaces.screen.mode.auto-recommended`
- `rules.preview-notice` -> `rules.screen.preview-notice.description`
- `rules.type.exact-fqdn` -> `rules.dialog.type.exact-fqdn`
- `first-run.step.welcome` -> `first-run.wizard.step.welcome.title`
- `first-run.notice.completion` -> `first-run.wizard.notice.completion.success`
- `tray.status.preview-mode` -> `tray.tray.status.preview-mode`
- `tray.status-accessibility.preview-mode` -> `tray.tray.status-accessibility.preview-mode`
- `a11y.high-contrast` -> `a11y.screen.high-contrast.label`
- `label.primary` -> `label.screen.primary.title`
- `theme.high-contrast` -> `settings.screen.theme.high-contrast` (legacy `theme.*` kept as alias until migration)

## Known Mismatches in Block-2 Keys

- most block-2 keys do not encode `surface`
- many keys do not encode explicit `state` semantics
- domain `theme` is outside canonical first-level list and treated as legacy alias
- `tray.status-accessibility.*` mixes accessibility meaning into element name and needs canonical split
- some action keys are reused in both menu and tray contexts and require surface-specific canonical ids

## Legacy Migration Policy

- keep legacy ids as read aliases while canonical keys are being introduced
- canonical keys are mandatory for newly added UI text
- when a legacy key is touched, migrate call-site to canonical id in the same change
- alias removal criteria:
- no QML references to legacy id
- no Rust references to legacy id
- locale checks pass for canonical coverage and no unknown runtime keys
