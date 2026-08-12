# Quality Baseline

This file fixes the initial Block 1.5 baseline for local checks, CI, naming, and dependency policy.

## Local Green Baseline

The workspace baseline is green when all of the following pass:
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check advisories licenses bans sources`

Use `scripts/check.ps1` as the canonical local entrypoint for these checks.

## Naming and Style Rules

Initial repository-wide conventions:
- Rust crate names use the `nrr-` prefix for published package identifiers.
- Windows runtime packages use the `nrr-windows-*` prefix.
- Rust modules, functions, and files use `snake_case`.
- Rust types and traits use `PascalCase`.
- Constants use `UPPER_SNAKE_CASE`.
- PowerShell scripts stay task-oriented and are named by the action they perform, such as `bootstrap`, `build`, `run`, and `check`.

## Dependency Allow Policy

Allowed by default in the initial baseline:
- permissive licenses such as `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `CC0-1.0`
- weak-copyleft `MPL-2.0`
- standard metadata licenses such as `Unicode-3.0`
- crates from the official crates.io registry

## Dependency Deny Policy

Denied by default unless explicitly reviewed and documented:
- dependencies with unknown or unclear licensing
- strong copyleft and source-available licenses that can block commercial distribution
- dependencies pulled from unknown registries
- git dependencies without explicit review
- wildcard dependency requirements in manifest files

## CI Baseline

The initial CI baseline runs on Windows and must execute the same checks as the local quality script.
