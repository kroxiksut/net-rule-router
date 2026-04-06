# AI Rules

## File Language and Encoding

- Russian files must stay in Russian.
- English files must stay in English.
- Never corrupt the encoding of Russian files.
- When editing Russian files, preserve readable Cyrillic and avoid mojibake.
- If there is any meaningful risk of breaking Russian text encoding, stop and use a safer editing method.

## Project Rules for the AI

- Treat the current project specifications and technical docs as the source of truth.
- Do not reposition the product as a VPN client, anonymity tool, censorship bypass tool, or proxy manager.
- Preserve the `primary` / `secondary` model, predictable rule behavior, and Fail-Closed as baseline principles.
- Keep the Free tier useful and strong; Pro extends scale and automation.
- Do not invent features that conflict with the current Free-version boundaries unless explicitly requested.
- Prefer address-based routing specificity over application-level routing specificity.
- Rule priority should default to exact FQDN, then subdomain or suffix, then exact IP, then application, then default route.
- Treat Windows tray presence as a baseline product requirement, not an optional UI extra.
- Treat startup background execution as a Windows service requirement, not as a regular app-only autostart shortcut.
- Do not couple routing enforcement to the visibility or lifetime of the main GUI window.

## Rust and Qt GUI

- `Rust` is the preferred language for core logic, the rule engine, system integration, configuration, cache, logging, and diagnostics.
- `Qt` is the primary desktop GUI stack.
- Do not move business logic into QML, the UI layer, or GUI helper code without a clear reason.
- Keep the Rust-to-Qt boundary narrow, explicit, and stable.
- Avoid duplicating the same logic in both Rust and the GUI layer whenever possible.
- Use `unsafe` Rust only when truly necessary, and keep it localized and justified.
- Architect the GUI so tray behavior and service behavior can operate without requiring the main window to stay open.

## Dependency Licensing

- All `Rust` crates, `Qt` modules, and GUI dependencies must be suitable for the project's future commercial product goals.
- When using `Qt Community`, only use modules and dependencies whose license terms do not block future commercial use of the product.
- Do not add dependencies with unclear licensing or strong commercial-use restrictions unless explicitly approved.
- Do not add `GPL` / `AGPL` dependencies, or other licenses that may conflict with planned `MPL-2.0` distribution, unless explicitly approved.
- Prefer dependencies with clear compatible terms such as `MPL-2.0`, `MIT`, `BSD`, `Apache-2.0`, and for Qt choose modules whose terms fit the intended distribution model.
- If the license status of a module or crate is unclear, treat it as unapproved until the licensing decision is explicitly checked and documented.

## Search Tooling

- Use `rg` for text search.
- Preferred `rg` path:
  `C:\Program Files\WindowsApps\OpenAI.Codex_26.325.3894.0_x64__2p2nqsd0c76g0\app\resources\rg.exe`
- When an explicit absolute path is needed, use that executable.

## Documentation Practice

- AI baseline files should exist in two language variants:
  - Russian for the human owner
  - English for the AI assistant as the default file name without a language suffix
- `README.md` is the default English README and `README_RU.md` is the synchronized Russian README.
- When updating one README variant, update the other in the same change set.
- `ARCHITECTURE.md` is the default English architecture document and `ARCHITECTURE_RU.md` is the synchronized Russian version.
- When updating one architecture variant, update the other in the same change set.
- `STRUCTURE.md` is the default English structure document and `STRUCTURE_RU.md` is the synchronized Russian version.
- When updating one project-structure variant, update the other in the same change set.
- Do not reference the internal working documents `specifikaciya_modeli_pravil_i_marshrutizacii_v2_1_RU.md` and `TZ_Windows_Network_Policy_Manager_v2_1_RU.md` in README files or other public-facing baseline documentation.
- Maintain repository structure in the dedicated project-structure files instead of embedding it directly into README files.
- Do not include generated, temporary, or Git-ignored directories in the maintained structure documents.
- Keep decisions aligned with the established product context:
  Windows-first, local-first, transparent diagnostics, YAML presets, RU/EN.

## License

- Remember that the code is distributed under `MPL-2.0`.
- Do not generate the license text unless explicitly requested.
