# Locale Source Policy (Block 3.6)

This document defines how bundled and user-provided locale files are discovered and merged.

## Sources

- `bundled` source:
- files from `locales/*.json` shipped with GUI/tray build
- baseline locale set is fixed to include `ru` and `en`
- `user` source:
- files from managed local storage `NetRuleRouter/managed/locales`
- optional override path via `NRR_USER_LOCALES_DIR`
- legacy `NRR_LOCALES_DIR` remains supported as a user-source override for backward compatibility

## Merge And Resolution Order

For the same locale id, value resolution order is:

1. user locale key (if present)
2. bundled locale key
3. fallback locale chain from metadata (`fallbacks`, with enforced safe validation rules)
4. explicit fallback text from call-site

## Conflict Rules

- duplicate locale ids inside the same source are rejected
- duplicate ids across sources are allowed and treated as intentional override
- rejected user locale never removes bundled locale from language list
- update/delete of user locale files is picked up on the next startup and merged deterministically

## Diagnostics

Each locale load report includes source marker:

- `bundled`
- `user`

Diagnostics must expose status (`accepted`, `accepted-with-warnings`, `rejected`) and reasons per file.
