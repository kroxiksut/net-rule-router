# Localization And Theme Maintenance Policy (Block 3.9)

This document fixes operational rules for evolving UI text and theme resources.

## Update Process For Existing Translations

When UI changes introduce or modify user-visible strings:

1. Add/update canonical keys first (according to `KEY_SCHEMA.md`).
2. Update baseline locales (`en`, `ru`) in the same change.
3. Keep key aliases only when migration risk is explicit and temporary.
4. Run localization checks (`cargo test -p nrr-shared -j 1`).
5. Record unresolved translation gaps as follow-up tasks.

## Completion Rule For New Screens/Dialogs

A new screen or dialog is **not complete** unless both are true:

- Theme coverage:
- uses centralized tokens/components from `configs/theme/TOKENS.md`
- no ad-hoc hardcoded colors/spacing/radii
- Locale coverage:
- all user-visible strings are key-based and present in baseline locales
- no inline user-visible runtime strings

## Review Rule For New Localization Keys And Theme Resources

Every review adding/changing localization keys or theme resources must verify:

- key naming and domain/surface semantics match `KEY_SCHEMA.md`
- no duplicate semantic keys for one UI meaning
- runtime call-sites use shared resolver APIs (no ad-hoc resolvers)
- theme resource changes are token-based and mode-consistent (`light/dark/system/high-contrast`)
- high-contrast impact is explicitly checked for icons and contrast pairs

## Ownership

The canonical ownership table is maintained in `configs/OWNERSHIP.md` and should be updated together with this policy.
