# Locale Validation Policy (Block 3.7)

This document defines runtime validation behavior for `locales/*.json`.

## Load Result Model

Each locale file has one of these statuses:

- `accepted`: locale is valid and loaded
- `accepted-with-warnings`: locale is loaded, but non-fatal issues were found
- `rejected`: locale is ignored and not exposed to UI language catalog

## Validation Rules

Mandatory validation:

- root is a JSON object
- `metadata` exists and is an object
- required metadata fields exist and are valid:
- `language`
- `label`
- `nativeLabel`
- `version`
- `fallbacks`
- `metadata.language` matches locale id from filename
- schema version is supported (`1.0`)
- fallback chain has no self-reference and no cycles
- translation root keys are namespace objects (no root-level translation strings)
- translation leaves are strings only (no numbers/arrays/objects/bool/null)
- reserved root namespaces are blocked (`_system`, `_service`, `_internal`)

Additional checks:

- unknown metadata fields
- missing fallback targets
- empty translation strings
- suspicious translation values (control chars, very long strings)
- UTF-8 BOM presence
- missing coverage vs English baseline

## Warning vs Reject Classification

`rejected`:

- unreadable file / invalid UTF-8
- invalid JSON
- invalid root/metadata structure
- missing or invalid required metadata fields
- unsupported schema version
- `metadata.language` mismatch with filename id
- fallback self-reference
- fallback cycle
- duplicate locale ids after normalization
- invalid translation value types or invalid namespace shape

`accepted-with-warnings`:

- unknown metadata fields
- fallback locale id not found
- empty translation value
- suspicious value characteristics (control chars, very long text)
- UTF-8 BOM detected and stripped
- partial coverage relative to English baseline

## Fallback Policy

Resolver chain:

1. requested locale id
2. requested locale base (`ru-RU` -> `ru`)
3. English locale (`en`)
4. explicit fallback text from call-site

If key is missing in all locale layers:

- UI does not crash
- explicit fallback text is used
- event is logged as localization coverage defect

If locale is `rejected`:

- it is excluded from available language list
- it does not affect active UI language

If locale is `accepted-with-warnings`:

- it is loaded
- missing keys are expected to fallback to English baseline

## Diagnostics Channels

- debug-friendly: structured warning/reject reasons are logged to stderr
- runtime API: `nrr_shared::load_locale_reports()` exposes per-locale status, warnings, and errors
- user-visible: GUI context receives `localeDiagnostics` summary and surfaces status line warning when needed
