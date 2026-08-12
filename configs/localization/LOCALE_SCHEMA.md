# Locale Schema (v1)

This document fixes the baseline contract for `locales/*.json`.

Current schema version: `1.0`  
Machine-readable schema: `configs/localization/locale.schema.v1.json`  
Canonical example: `configs/localization/locale.v1.example.json`

## Required Metadata

Every locale file must contain the `metadata` object with required fields:

- `language`: normalized locale id (`en`, `ru`, `pt-br`, ...)
- `label`: English display label used in language selectors
- `nativeLabel`: native display label used in language selectors
- `version`: schema version string (current baseline: `1.0`)
- `fallbacks`: ordered array of locale ids used as fallback chain

Additional metadata fields are currently not supported in schema v1.

## Namespace Rules

- Root object contains:
- `metadata` (reserved)
- one or more translation namespaces (`menu`, `action`, `dialog`, `status`, ...)
- Translation namespaces are nested JSON objects.
- Leaf values are strings only.
- Translation keys are produced in dotted form by joining namespace path segments:
- `menu.file`
- `dialog.load-list.title`
- `first-run.notice.completion`
- Root-level string keys are not allowed; root keys (except `metadata`) must be namespace objects.

## Allowed Value Types

- Root: JSON object
- `metadata`: JSON object
- `metadata.fallbacks`: JSON array of strings
- Translation namespace node: JSON object
- Translation leaf: JSON string

Not allowed for translation values in schema v1:

- numbers
- booleans
- null
- arrays

## String Escaping and Formatting Rules

- Locale files use standard JSON string escaping.
- Use `\n` for explicit line breaks; avoid hardcoded multi-line formatting in source files.
- Keep placeholders stable across languages:
- `%1`, `%2`, `%3`, ...
- Do not change placeholder count/order between locales unless call sites are updated together.
- Locale strings should be plain text; HTML fragments or rich markup are out of schema v1 scope.

## Pluralization Strategy (v1)

Schema v1 does not add a dedicated runtime plural resolver yet.

Plural forms must be represented as explicit key families:

- `<base>.one`
- `<base>.few`
- `<base>.many`
- `<base>.other`

Example: `rules.count.one`, `rules.count.few`, `rules.count.many`, `rules.count.other`.

Selection logic stays at call-site level until a centralized plural resolver is introduced in later blocks.
