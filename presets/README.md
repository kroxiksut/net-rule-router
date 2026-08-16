# Presets

This directory contains built-in examples and country-specific preset folders for
NetRuleRouter.

## Directory structure

```text
presets/
├── examples/                  # canonical examples shipped with the product
│   ├── rules_primary.txt
│   ├── rules_secondary.txt
│   └── README.template.txt
├── <country-code>/            # ru, by, kz, tr, ir, eg, ae, in, id, vn, cn, jp, ...
│   └── <pack-name>/           # preset pack folder
│       ├── README*.txt
│       ├── rules_primary.txt  # optional
│       └── rules_secondary.txt# optional
├── abroad/                    # category: you live outside the country whose
│   └── access-to-<cc>/        # services you need (same pack layout)
└── COUNTRY_BACKLOG.md
```

## Project policy

Program authors created this folder structure and initial possible preset sets
for several countries based on open internet sources.

You may take existing rules, rename them, extend them, and republish them under
your own name.

You may distribute your rules through any resources available to you.

Any user may also take your rules and modify/republish them under their own
name.

Pull requests with rules are accepted and go through moderation.

If there are no rules for your country yet, we will gladly review your pull
request with rules and interface translations for the software.

## Country folders and pack names

- Country folder must use lowercase ISO-style code (for example `ru`, `by`, `kz`).
- Pack folder must use lowercase letters, digits, and hyphens (for example
  `example-vpn`, `corp-vpn`, `streaming-split`).
- Underscores and capital letters are not allowed in either name. The GUI
  identifies a pack as `<folder>_<pack>` and stores that string in user
  preferences, so an underscore inside a name makes the identifier ambiguous,
  and capitals break the identifier on case-sensitive filesystems.

## Categories

A top-level folder whose name is not a country code is a **category**: it groups
packs by scenario rather than by the country you are sitting in.

| Category | Meaning |
|---|---|
| `abroad` | You live outside the country whose services you need. Packs are named `access-to-<cc>` (for example `access-to-ru`). |

Category packs use exactly the same layout and file names as country packs and
appear in the same GUI list. Only the first-run wizard treats them differently:
it suggests packs by the OS locale's country code, so a category pack is chosen
manually from the full list.

## Required files in each pack

- At least one rules file: `rules_primary.txt` and/or `rules_secondary.txt`.
- At least one README file (`README.txt` or language-specific variant).
- README must explicitly include `Author`.

## README language policy

- README inside a rules pack may be in English or in the country's language.
- Multiple README files in additional languages are allowed and not limited.
- Recommended naming: `README.txt` (default), plus `README.en.txt`,
  `README.ru.txt`, `README.tr.txt`, etc.

## Rules file format

Rules files use the same plain-text format as working rules files (see
[Rules File Format](../docs/en/rules-file-format.md), sections 1 and 3).

Typical metadata header in rules files:

```text
# NetRuleRouter preset - version 1
# name: My Preset
# description: What this preset does
# author: Your Name
# preset_version: 1
```

## Content guidelines

- One pack = one clear use case.
- Rules must be valid NetRuleRouter rules-file syntax.
- Do not include device-specific values (adapter IDs, local IP addresses).
- Use inline comments (`# comment`) for non-obvious rules.
- Keep rulesets focused; avoid catch-all wildcard rules.

## Extended sections

Packs may include sections this version does not recognise (`--- CIDR`,
`--- Ports`, and others). Such files import safely: unrecognised rules are
preserved but not applied to routing policy.

## Validation limits

| Limit | Value |
|---|---|
| Maximum file size | 1 MiB |
| Maximum rules per file | 2,000 |
| Maximum match value length | 260 characters |

## Importing a preset

1. Download or clone the repository (or just the desired pack folder).
2. In NetRuleRouter GUI, open **Rules -> Import preset**.
3. Select the route file you want to replace.
4. Review diff and confirm.
