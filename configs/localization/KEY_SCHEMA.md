# Localization Key Schema (Block 3.5)

This document fixes the key contract for shared QML/Rust localization.

## Canonical Key Form

Target key form:

`<domain>.<surface>.<element>.<state>`

Rules:

- one UI meaning -> one canonical key id across QML and Rust
- fallback text in code is emergency-only and must not replace locale catalog content
- missing key must not crash UI; fallback text is used and treated as coverage defect
- resolver contract is centralized in Rust (`nrr_shared::resolve_catalog_text`)

## First-Level Domains

Canonical domains:

- `menu`
- `section`
- `action`
- `settings`
- `dialog`
- `tray`
- `a11y`
- `label`
- `status`
- `interfaces`
- `rules`
- `diagnostics`
- `logs`
- `first-run`

Legacy compatibility note:

- `theme` remains as legacy block-2 domain and is accepted as alias during migration.

## Domain Examples (3-4 per domain)

- `menu`: `menu.menu.file.title`, `menu.menu.view.title`, `menu.menu.tools.title`, `menu.menu.help.title`
- `section`: `section.screen.interfaces-routes.title`, `section.screen.rules.title`, `section.screen.diagnostics.title`, `section.screen.settings.title`
- `action`: `action.window.open-main-window.action`, `action.dialog.apply.action`, `action.tray.check-service-status.action`, `action.menu.exit-application.action`
- `settings`: `settings.screen.language.title`, `settings.screen.theme.label`, `settings.screen.route-labels.description`, `settings.screen.logs-diagnostics.note`
- `dialog`: `dialog.dialog.load-list.title`, `dialog.dialog.edit-list.description`, `dialog.dialog.review-replace.summary`, `dialog.wizard.first-run.title`
- `tray`: `tray.tray.status.preview-mode`, `tray.tray.status.no-active-policy`, `tray.tray.status.service-unavailable`, `tray.tray.open-main-window.action`
- `a11y`: `a11y.screen.high-contrast.label`, `a11y.screen.enhanced-focus.label`, `a11y.tray.status-text.preview-mode`, `a11y.tray.action-description.safe-rollback`
- `label`: `label.screen.primary.title`, `label.screen.secondary.title`, `label.dialog.rule-type.title`, `label.screen.version.title`
- `status`: `status.screen.setup-completed.success`, `status.screen.rule-added.success`, `status.screen.rollback-preview.warning`, `status.screen.disable-impact-preview.warning`
- `interfaces`: `interfaces.screen.preview-notice.description`, `interfaces.screen.role-explanation.description`, `interfaces.screen.availability.available`, `interfaces.screen.state.fail-closed-conflict`
- `rules`: `rules.screen.preview-notice.description`, `rules.dialog.type.application`, `rules.dialog.type.exact-fqdn`, `rules.dialog.type.exact-ip`
- `diagnostics`: `diagnostics.screen.title`, `diagnostics.screen.service-health.label`, `diagnostics.screen.explain.summary`, `diagnostics.screen.refresh.action`
- `logs`: `logs.screen.title`, `logs.screen.export.action`, `logs.screen.clear.action`, `logs.screen.empty.description`
- `first-run`: `first-run.wizard.step.welcome.title`, `first-run.wizard.step.routes-setup.title`, `first-run.wizard.notice.list-editing-preview.description`, `first-run.wizard.notice.completion.success`

## `surface` Selection Rules

Use `surface` by UI ownership:

- `window`: main application windows and standalone secondary windows
- `dialog`: modal/non-modal dialogs and confirmation overlays
- `tray`: tray menu/status/quick actions
- `menu`: top menu bar groups and items
- `wizard`: first-run stepper and setup-specific controls
- `screen`: section workspace content (`interfaces-routes`, `rules`, `diagnostics`, `logs`, `settings`)

## `element` and `state` Rules

Preferred `element` values:

- `title`, `subtitle`, `description`, `tooltip`, `label`, `note`, `summary`, `action`, `empty`

Preferred `state` values:

- `success`, `warning`, `error`, `empty`, `action`

Guideline:

- `element` describes what UI thing is being translated
- `state` describes runtime semantic status when needed
- if no explicit status is needed, keep semantic suffix stable (`title`, `description`, `action`)

## Forbidden Keys and Practices

Forbidden key patterns:

- too generic keys (`common.ok`, `common.cancel`)
- screen-specific keys without domain (`rules-title`, `settingsLabel`)
- keys mixing business and presentation meaning (`policy.failclosed-and-button`)

Forbidden practices:

- inline user-visible text in runtime code when locale key exists
- duplicate semantic keys for one UI meaning across QML and Rust
- ad-hoc local resolver functions in app crates
- mixing different domain levels in one key family

## Legacy Migration Rules

- keep legacy block-2 keys as aliases only where immediate rename is risky
- new strings must use canonical `<domain>.<surface>.<element>.<state>` form
- whenever a legacy key is touched in code, migrate call-sites to canonical key in the same change
- remove alias only after all QML/Rust references are migrated and runtime checks pass

## Block-2 Groups and Mapping

Current block-2 key groups and planned mapping are documented in:

- `configs/localization/KEY_MAPPING_BLOCK2.md`
