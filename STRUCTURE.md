# Project Structure

English is the default documentation language for AI-facing files.
The synchronized Russian version of this document is available in `STRUCTURE_RU.md`.

## Purpose

This file defines the intended repository structure and should be updated as the project evolves.

Rules for maintaining this file:
- keep it synchronized with `STRUCTURE_RU.md`
- do not include generated directories
- do not include temporary directories
- do not include directories that are intended to be ignored by Git

## Current Structure

```text
apps/
  windows/
assets/
  icons/
  images/
core/
shared/
AI_CONTEXT.md
AI_CONTEXT_RU.md
AI_RULES.md
AI_RULES_RU.md
ARCHITECTURE.md
ARCHITECTURE_RU.md
SECURITY.md
SECURITY_RU.md
STRUCTURE.md
STRUCTURE_RU.md
README.md
README_RU.md
```

## Directory Roles

- `apps/windows` for the Windows application shell and platform-specific application composition
- `core` for core product logic, routing behavior, diagnostics, and domain rules
- `shared` for reusable cross-cutting modules
- `assets` for icons, images, and other UI resources

## Maintenance Rule

If the repository layout changes, this file and `STRUCTURE_RU.md` should be updated in the same change set.
