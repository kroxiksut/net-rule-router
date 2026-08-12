# Community Guide: Add A New Language

This short guide describes how to add a new UI language safely.

## 1. Copy baseline locale

- Copy `configs/localization/locale.v1.example.json` to a new file in `locales/`.
- Use normalized locale id in filename, for example: `de.json`, `pt-br.json`.

## 2. Fill metadata

Required fields in `metadata`:

- `language`
- `label`
- `nativeLabel`
- `version` (`1.0`)
- `fallbacks` (usually includes `en`)

`metadata.language` must match the filename locale id.

## 3. Translate keys

- Keep the same key structure as baseline `en`/`ru`.
- Keep placeholder order and count (`%1`, `%2`, ...).
- Do not add ad-hoc namespaces or change key semantics.

## 4. Validate locally

Run:

- `cargo test -p nrr-shared -j 1`

This covers schema/key/runtime checks for localization contracts.

## 5. Runtime behavior expectations

- Invalid locale files are rejected and do not break GUI/tray startup.
- Partial locale files are allowed, but missing keys fallback to English baseline.

## 6. Submit contribution

Include in one change:

- new locale file
- update notes if new keys were introduced
- test result summary
