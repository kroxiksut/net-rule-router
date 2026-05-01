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
`FORMATS.md`, sections 1 and 3).

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
- Rules must be valid NetRuleRouter Free-edition syntax.
- Do not include device-specific values (adapter IDs, local IP addresses).
- Use inline comments (`# comment`) for non-obvious rules.
- Keep rulesets focused; avoid catch-all wildcard rules.

## Pro-only sections

Packs may include Pro-only sections (`--- CIDR`, `--- Ports`, and others).
Free edition imports such files safely: Pro-only rules are preserved but not
applied to routing policy.

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
