# NetRuleRouter File Formats

**English** · [Русский](../ru/rules-file-format.md)

This document specifies all external file formats used by NetRuleRouter.
It covers the rules text file format and the settings export YAML format.

## 1. Rules File Format

### 1.1 Overview

Routing rules are stored in plain text files — one file per route role. The
user chooses the filename; the application stores the configured path in UI
preferences. Typical names are `rules_primary.txt` and `rules_secondary.txt`,
but any valid filename is accepted.

Files are human-readable and can be edited in any text editor. The GUI reads
and writes the same files; edits from either source are semantically
equivalent.

When the user changes the configured path to a different file, the SQLite
rule cache is cleared and reloaded from the new file before the change takes
effect.

### 1.2 Sections

A rules file is organized into named sections. Each section groups rules of
one type. Section names are **technical keywords** — they are never localized
and must appear exactly as shown.

#### Supported sections

| Section header | Rule type | Platforms |
|---|---|---|
| `--- Zones` | Zone-level group routing | All |
| `--- Domains` | Suffix and exact FQDN rules | All |
| `--- IP` | Exact IP address rules | All |
| `--- Windows` | Windows application rules (`.exe` filename) | Windows only |
| `--- Linux` | Linux application rules (process name or path) | Linux only |
| `--- MacOS` | macOS application rules (bundle ID or process name) | macOS only |
| `--- Auto` | Rules the application added on your behalf (§1.13) | All |

Future revisions may introduce additional sections (`CIDR`, `Ports`, and
others) as the rule model expands.

`--- Auto` is written last, so a file reads as "the rules you wrote, then the
rules the application added for you".

#### Platform filtering

`--- Windows`, `--- Linux`, and `--- MacOS` are platform-specific. On a
Windows host, Linux and macOS sections are **parsed and preserved** in the
file but are not applied to routing policy. The GUI hides them by default.
The setting "Show rules for other operating systems" makes them visible.

This allows a single rules file to be shared across platforms (or prepared
in advance for a future platform) without splitting files.

#### Empty sections

Sections with no entries are written on export and must not be stripped.
They reserve a slot in the file for future use and make the file structure
self-documenting.

### 1.3 Syntax

#### Section header

```
--- SectionName
```

Exactly three hyphens, one space, then the section name. Trailing whitespace
is ignored. The name is case-sensitive.

#### Active rule

```
example.com
```

A line that is not a comment and not a section header is an active rule. The
match value is the entire line, trimmed of leading and trailing whitespace.

#### Active rule with inline comment

```
example.com  # vendor updates domain
```

Text after `#` on a non-commented line is an inline comment. It is displayed
as a label/description in the GUI rule list and is preserved in exports. The
`#` and everything after it are not part of the match value.

**Inline comment length limit: 200 characters** (after the `#` separator,
trimmed of leading/trailing whitespace). The GUI's Add/Edit Rule dialog
truncates input at this limit and shows a `used/max` counter. The rules-file
parser rejects entries whose inline comment exceeds 200
characters with a validation error so the on-disk format and the GUI agree.
Free-comment lines (standalone `# …`) are not subject to this limit because
they are not bound to a rule.

#### Disabled rule

```
# example.com
```

A `#` at the start of a line followed by a valid rule value marks the rule as
**disabled**. The GUI represents this as a toggled-off rule. Toggling a rule
off in the GUI comments its line; toggling it on removes the `#`.

A line starting with `#` where the rest is not a valid rule value (e.g.
`# this is a note`) is treated as a free comment — it is not shown as a
disabled rule in the GUI.

#### Free comment

```
# This is a free comment, not a rule.
```

Standalone comment lines (where the content after `#` is not a recognizable
rule value) are preserved in the file but ignored by the rule engine. They
are not shown in the GUI rule list.

#### Empty lines

Empty lines and lines containing only whitespace are ignored.

### 1.4 Complete example

```
# NetRuleRouter rules file — version 1
# Route: Primary (main network)

--- Zones
*.ru           # all .ru TLD traffic
corp-internal  # internal corporate zone

--- Domains
updates.example.org    # exact FQDN: vendor update endpoint
*.corp.example.net     # all subdomains of corp.example.net
# *.old.example.com    # disabled: decommissioned subdomain range

--- IP
203.0.113.7

--- Windows
browser.exe      # browser traffic
*vpn*.exe        # any VPN client executable
# powershell.exe # temporarily disabled

--- Linux
# (reserved — not applied on Windows)

--- MacOS
# (reserved — not applied on Windows)

--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.org added:2026-07-31
```

### 1.5 Rule evaluation priority

The following priority order is fixed (highest to lowest):

1. **Zones** — zone-level group match. An exact zone match short-circuits all
   lower tiers.
2. **Domains — exact FQDN** — `example.com` (no `*.` prefix) matches only
   the exact hostname. Longest label wins among competing exact rules.
3. **Domains — suffix/subdomain** — `*.example.com` matches `example.com`
   itself and any subdomain of it at any depth. Longest base domain wins
   among competing suffix rules. To route the apex differently from its
   subdomains, add an exact rule for the apex — it is a higher tier and wins.
4. **IP** — exact IP address. CIDR range matching is not supported yet.
5. **Application** (`Windows` / `Linux` / `MacOS`) — matched by process
   filename (exact or glob). Exact names take precedence over glob patterns;
   among glob matches, the first rule in the file wins. Only the
   platform-appropriate section is evaluated. An application rule's **nested
   destinations** (§1.10) are also evaluated at this tier — below the Domains
   and IP tiers, so a top-level address rule for the same address wins.
6. **Default route** — determined by `ActiveConfiguration.behavior_mode`.

Both the primary and secondary rule files are evaluated independently. The
first match across both files determines the route.

### 1.6 Child process tracking (`+children`)

By default an application rule matches only the named process. Appending the
flag **`+children`** after the process name extends the rule to the matched
process's **entire descendant subtree** — every child, grandchild, and so on.
A tool that spawns helpers (`codex.exe` launching `node_repl.exe`,
`powershell.exe`, the console host `conhost.exe`, …) then routes the
destinations of the whole tree under one rule:

```
--- Windows
codex.exe +children
```

The flag is a single space-separated token after the process name and before
any inline `#` comment (`codex.exe +children  # AI assistant`). It is a
**per-rule** flag — it replaces the former global "apply rules to child
processes" preference, which could not express *which* application's children
to follow.

Attribution is by **process subtree, not by process name**: a standalone
`powershell.exe` that is **not** a descendant of `codex.exe` is a different
subtree and is *not* covered by `codex.exe +children`. The rule therefore never
accidentally routes every PowerShell (or every `conhost.exe`) on the machine —
only the ones codex actually spawned.

> Subtree attribution requires the routing layer to track live process
> parentage (`pid → ppid → image`) and to know the PID behind each observed
> connection. That is an observation/runtime concern, not part of the file
> format; it is covered in the design notes outside this document.

**Priority invariant:** an explicit rule for a child process always takes
priority over routing inherited from a parent-process match. `+children` never
overrides a direct rule for the child.

> `+block` (§1.12) is the sibling per-rule flag. The two are orthogonal and
> may appear on the same line (`codex.exe +children +block`).

### 1.8 Match value syntax

Each section accepts specific match value patterns. Values outside the
accepted syntax produce a semantic validation error — the rule is rejected
with a clear message.

#### Zones (`--- Zones`)

| Example | Meaning |
|---|---|
| `corp-internal` | Named internal zone |
| `*.ru` | All domains under the `.ru` TLD |
| `ru` | Canonical form — parser normalizes `*.ru` and `ru` both to `ru` |

Zone names are lowercased on read. Both `*.ru` and `ru` are accepted as
input and stored canonically as `ru`. A zone name must consist of valid DNS
label characters (letters, digits, hyphens, dots for compound zones such as
`corp.internal`). Spaces are not allowed.

#### Domains (`--- Domains`)

| Example | Meaning | Priority tier |
|---|---|---|
| `example.com` | Exact FQDN — matches `example.com` only | Exact FQDN (tier 2) |
| `*.example.com` | Suffix — matches `example.com` and any subdomain of it at any depth | Suffix (tier 3) |

The `*.` prefix is the explicit subdomain operator. A bare domain name
without `*.` matches only the exact FQDN. The two forms are orthogonal:
a host gets matched at tier 2 by its exact entry; it falls through to tier 3
only if a suffix rule covers it.

Because tier 2 is checked first, writing both forms is how you split a site:
`*.example.com` on one route and `example.com` on the other sends the
subdomains one way and the bare domain the other.

#### IP (`--- IP`)

Exact IPv4 address. IPv6 and CIDR notation are not supported yet.

```
203.0.113.7
```

#### Windows / Linux / MacOS (application sections)

Process filename match. Both exact names and glob patterns are accepted.

| Example | Matches |
|---|---|
| `chrome.exe` | Exact process name |
| `*vpn.exe` | Any process name ending with `vpn.exe` |
| `nord*` | Any process name starting with `nord` |
| `*vpn*.exe` | Any process name containing `vpn` and ending with `.exe` |

Glob semantics:

- `*` matches **zero or more characters** (any character, including `.` and
  `-`).
- A bare `*` as the entire match value is a **validation error** — too
  broad, would match every running process.
- Matching is **case-insensitive on Windows**; case-sensitive on Linux.
- Only the **process filename** is matched, not the full path.

Precedence within the Application tier: an exact name always takes
precedence over any glob match. Among multiple glob rules that match the
same process name, the first rule defined in the file wins.

### 1.7 Section names are not localized

Section names (`Zones`, `Domains`, `IP`, `Windows`, `Linux`, `MacOS`, `Auto`)
are technical keywords in the file format. They are not passed through the
locale layer and are not translated. The same applies to the reason slugs used
inside the `--- Auto` section (§1.13): the slug in the file is a fixed keyword,
and the GUI renders a translated sentence for it.

The GUI may display localized descriptions *about* each section (shown as
hints or tooltips), but the section name written to the file is always the
canonical English keyword.

User-written inline comments (after `#`) are personal notes in whatever
language the user chooses — they are never modified or translated.

### 1.9 Forward compatibility — extended sections

When a rules file contains sections this version does not recognise (for
example `--- CIDR` or `--- Ports` produced by a newer or extended format
revision), those sections are **parsed and preserved** in the file but are
**not applied** to the routing policy. This mirrors the existing behaviour
for platform-specific sections on a non-matching host (see section 1.3).

In the GUI, rules belonging to unrecognised sections are shown with a
"Not applied" badge. They cannot be toggled or edited.

On export, unrecognised rules are written back to the file unchanged, so no
information is lost when a file travels through this version.

### 1.10 Application destination lists (`--- Windows`)

> **Status: `--- Windows` only for now.** The same nesting will extend to the
> `--- Linux` and `--- MacOS` sections in a later revision. This subsection is a
> **format version 2** addition (see §1.11).

Routing is **destination-based**: a route is keyed by the remote address,
not by the originating process. A Windows application rule therefore cannot, by
itself, send a process's traffic out the secondary adapter. Instead, an
application rule **carries a list of destinations** the application uses, and
each destination is routed via the application rule's route (the file the rule
lives in — `rules_primary.txt` or `rules_secondary.txt`). NetRuleRouter learns
these destinations by **observing the application's outbound connections** and
routes them on subsequent connections.

> True per-process *isolation* (only **this** application's traffic to a shared
> address rides the secondary; other applications contacting the same address do
> not) requires a kernel driver and is out of scope for now. Currently, a
> destination learned from an application is an ordinary destination route — it
> applies wherever that address is contacted. The first connection to a
> not-yet-observed address always egresses normally (it is what reveals the
> address); routing takes effect from the next connection.

#### Syntax

Within `--- Windows`, a line whose first non-whitespace characters are a hyphen
and a space (`- `) is a **nested destination** belonging to the most recent
application rule above it:

```
--- Windows
claude.exe
  - claude.ai
  - claude.org
  - 203.0.113.7
mysuper.exe
  - mysite.org
```

- Leading indentation is cosmetic (recommended for readability) and is ignored
  by the parser; the `- ` prefix is what marks the line as a nested destination.
- The value after `- ` (trimmed) is either an **exact FQDN** (`claude.org`) or
  an **exact IPv4 address** (`203.0.113.7`); the parser auto-detects which by
  syntax. Suffix (`*.`) and CIDR forms are **not** accepted in a nested
  destination — promote a suffix to a top-level `--- Domains` rule instead
  (CIDR is not supported yet).
- A nested destination with no preceding application rule in the section is a
  validation error.
- Inline comments (`- claude.org  # vendor API`) and the 200-character comment
  limit apply exactly as for top-level rules (§1.3).

#### Route inheritance

A nested destination inherits the **route of its application rule** — i.e. the
file it appears in. A `claude.exe` block in `rules_secondary.txt` routes its
destinations via the secondary adapter; the same block in `rules_primary.txt`
routes them via the primary.

#### Priority against top-level address rules

A top-level `--- Domains` or `--- IP` rule for the same address **outranks** a
nested application destination — the fixed priority places the Domains and IP
tiers above the Application tier (§1.5). When an address appears both as a
top-level rule and as a nested destination, the top-level rule determines the
route and the nested copy is not applied a second time. This lets a user "pin"
an address explicitly (move `claude.ai` up into `--- Domains` to force a route)
and have it win over what the application learned.

#### Disabling

- Commenting the application line (`# claude.exe`) disables the application rule
  **and** all of its nested destinations.
- Commenting a single nested line (`# - claude.org`) disables just that
  destination.

#### Explicit vs observed destinations

Nested destinations written in the file are **explicit** — user-authored
canonical intent. NetRuleRouter additionally maintains, at runtime, a durable
set of **observed** destinations per application (learned by connection
observation). The two are shown together under each application in the GUI
(observed ones are labelled), with these actions:

- **Pin** — promote an observed destination to an explicit `- ` line in the
  file.
- **Exclude / forget** — stop routing an observed destination. Observed
  destinations cannot be *deleted* (observation would re-learn them); excluding
  records that the address must not be routed for this application.

Observed destinations are runtime state and are **not** part of the canonical
file by default, so the rules file stays a record of user intent. On export,
observed destinations may optionally be written out as explicit `- ` lines so a
shared file is self-contained. (The auto-learning behaviour, the per-machine
administrator policy that governs who may change rules, and the GUI surface are
specified outside this format document.)

#### Provenance and shared-address annotations

A nested destination's inline comment MAY carry conventional annotations that
NetRuleRouter writes when it serialises a learned destination and reads back to
show provenance. They are ordinary inline comments — a reader that does not
understand them just shows them as the destination's label — but the GUI parses
these leading tokens (`;`-separated):

| Token | Meaning |
|---|---|
| `via <process>` | The subtree process that discovered this address (e.g. a child of the application rule, under `+children`). Stable provenance — round-trips through the file. |
| `also <proc>, <proc>…` | Other applications observed contacting the **same** address — routing it affects them too (shared address). A **point-in-time snapshot** at write time; the live set is shown in the GUI, not kept fresh in the file. |
| `shared-ip` | More than one site or service answers from this address, so a rule that targets it affects them too, not only the one you intended. |

```
--- Windows
codex.exe +children
  - api.openai.com         # via codex.exe
  - registry.npmjs.org     # via node_repl.exe
  - 140.82.121.4           # via powershell.exe; also chrome.exe, slack.exe; shared-ip
```

Free-form user text may follow the conventional tokens and is preserved
verbatim. Only the `via` token is authoritative and persisted; `also …` and
`shared-ip` are advisory annotations recomputed from live observation.

### 1.11 Format version

The header line `# NetRuleRouter rules file — version N` (and the preset header
`# NetRuleRouter preset — version N`, §3.2) carries the file format version.

| Version | Adds |
|---|---|
| 1 | Sections, top-level rules, inline comments, disabled rules. |
| 2 | Nested application destinations (§1.10, `--- Windows`). |
| 3 | Per-rule `+block` flag (§1.12). |
| 4 | App-authored rules section (§1.13, `--- Auto`). |

A file that uses nested `- ` lines declares **version 2**. A version 1 reader
predates the nesting syntax and would mis-parse a `- destination` line as a
(never-matching) process rule, so version-2 files should be read by version-2+
builds. NetRuleRouter preserves nested lines on round-trip; a version 2 file
opened and re-saved by a current build keeps its nesting intact.

A file that contains an `--- Auto` section declares **version 4**. A
pre-version-4 reader does not recognise the section name and therefore treats
it as an extended section (§1.9): the rules are preserved on round-trip but not
applied, so nothing is lost and nothing is misinterpreted.

A file that uses the `+block` flag declares **version 3**. A pre-version-3
reader treats `value +block` like any other unknown trailing token: for an
address section the space makes the value fail validation (the rule is dropped,
not silently routed), and for an application section it becomes a
never-matching process name — so the flag degrades safely rather than
converting a block into an accidental route.

### 1.12 Blocking destinations (`+block`)

By default a rule *routes* its destination through the adapter bound to the
file the rule lives in (`rules_primary.txt` → primary, `rules_secondary.txt` →
secondary; §1.10). Appending the flag **`+block`** after the match value
instead **drops** all traffic to that destination — it is enforced by a hard
WFP `FWP_ACTION_BLOCK` filter (both the connect layer for TCP/UDP and the
packet layer for ICMP/ping and other protocols) and installs **no** route.

```
--- Domains
telemetry.vendor.example +block     # not allowed from this machine
*.metrics.vendor.example +block

--- IP
203.0.113.9 +block
```

**What this flag is, and what it is not.** `+block` is a manual policy rule:
you name a destination, and it stops being reachable from this machine. It is
not an ad blocker or a tracker blocker. NetRuleRouter ships no block lists,
maintains none, and has no view inside a page — it cannot remove an element,
and it cannot touch anything served from the same domain as the content around
it. Blocking by name also depends on seeing the name resolved, so a browser
using its own encrypted DNS (DoH/DoT) can make a name-based block rule miss;
see [What routing changes — and what it does not](what-routing-changes.md).
Use the flag for destinations you have decided about yourself.

Key properties:

- The flag is a single space-separated token after the match value and before
  any inline `#` comment (`telemetry.vendor.example +block  # policy`), mirroring the
  `+children` convention (§1.6). Order is not significant if both are present.
- **The containing file is irrelevant for a blocked rule.** A `+block` rule
  drops its destination whether it lives in `rules_primary.txt` or
  `rules_secondary.txt` — the block action overrides the route. (Editors
  typically keep block rules in the secondary file by convention.)
- `+block` works uniformly across every section: `Zones`, `Domains`, `IP`, and
  the application sections (`Windows` / `Linux` / `MacOS`). A blocked
  application rule drops that process's connect-layer traffic.
- Disable a block rule the same way as any rule — comment the line
  (`# telemetry.vendor.example +block`); it is retained but inactive.
- A matched `+block` rule short-circuits to **DROP** at its evaluation tier
  (§1.5); no lower tier or the default route is consulted for that connection.
- **Where a block rule is authored.** The flag applies wherever it appears in a
  rules file, and an existing block rule stays one when you open it in the app.
  The Add/Edit Rule dialog does not offer Block as a target for a *new* rule —
  block rules are written in the file.

### 1.13 App-authored rules (`--- Auto`)

Some rules are added by NetRuleRouter itself rather than typed by the user —
for example when a site you routed needs additional hosts before it works
end to end. Those rules live in their own section so you can always tell them
apart from your own list, review them, and remove them.

```
--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31
*.assets.example.net  # auto:site-companion anchor:example.com added:2026-07-31 all asset hosts
# stale.example.net  # auto:user-confirmed anchor:example.com added:2026-01-05
```

Key properties:

- **Values follow the `--- Domains` grammar** (§1.8): a bare hostname is an
  exact FQDN, `*.example.com` is a suffix domain. The section separates
  *authorship*, not match types — an app-authored rule is routed exactly like
  the equivalent rule in `--- Domains`, by the file it lives in.
- **Every line carries a reason.** The inline comment starts with three
  structured tokens, followed by optional free text that is shown as the
  rule's label like any other inline comment:

  ```
  # auto:<reason> anchor:<hostname> added:<YYYY-MM-DD>
  ```

  | Token | Meaning |
  |---|---|
  | `auto:<reason>` | Why the rule was added — one of the reasons below. |
  | `anchor:<hostname>` | The site or program the rule was added for. |
  | `added:<YYYY-MM-DD>` | The date it was added. |

  The tokens may appear in any order. The GUI shows a translated sentence for
  the reason and the anchor, not the raw tokens.
- **Reasons.** Three are defined:

  | Reason | Meaning |
  |---|---|
  | `site-companion` | A host the anchor site needs in order to work. |
  | `vpn-client-bootstrap` | Addresses a VPN client needs to reconnect. |
  | `user-confirmed` | A suggestion you accepted. |

  A reason this version does not recognise is preserved unchanged on
  round-trip, so a file written by a newer build is never damaged by an older
  one.
- **All the ordinary syntax applies.** Comment the line to disable a rule
  (§1.3), append `+block` to block instead of route (§1.12), edit or delete a
  line by hand — the section is plain text like every other one.
- **A line without an `auto:` token is still a rule.** It is imported as an
  ordinary rule of that file's route and reported as a warning, never dropped
  and never treated as an error. Hand-editing this section cannot lose rules.

---

## 2. Settings Export Format (YAML)

### 2.1 Overview

The settings export is a YAML file that captures the user's full configuration
for backup or for transferring it to another installation. It is written when
the user chooses "Export settings" and read when they choose "Import settings".

This section documents the data boundary and structure.

### 2.2 What is included

- Adapter bindings: system ID, user label, confirmation status.
- Rule file paths (not the rule file contents — only the paths).
- Behavior settings: route mode, file-change behavior, child-process option.

### 2.3 What is NOT included

- The actual content of the rule files — those are separate files at the
  stored paths.
- UI preferences (theme, language, accessibility, route display labels,
  display toggles) — device-specific, carried over per device on migration.
- Internal revision metadata (revision IDs, content hashes, audit events).
- Device-specific runtime state (connectivity probes, external IP, logs).

### 2.4 Structure

```yaml
nrr_settings_export:
  version: 1
  exported_at: "2026-04-18T12:00:00Z"

  adapters:
    primary:
      system_id: "mac=AA:BB:CC:DD:EE:FF;ifindex=3"
      user_label: "Main network"
      user_confirmed: true
    secondary:
      system_id: "mac=11:22:33:44:55:66;ifindex=7"
      user_label: "VPN"
      user_confirmed: true

  rules_files:
    primary: "C:\\Users\\user\\AppData\\Local\\NetRuleRouter\\rules_primary.txt"
    secondary: "C:\\Users\\user\\AppData\\Local\\NetRuleRouter\\rules_secondary.txt"

  behavior:
    route_mode: "prefer-primary"
    file_change_behavior: "notify"
    include_child_processes: false
```

UI preferences (theme, language, accessibility, route display labels) are
device-specific and intentionally **not** included in the export — they are
carry-over state per device, not part of the portable configuration.

### 2.5 Adapter system ID

The `system_id` field uses the composite format
`"mac=AA:BB:CC:DD:EE:FF;ifindex=N"`. This key is stable on the same device.
On import to a different device, the GUI presents an adapter-selection dialog
if the stored ID is not found.

### 2.6 Rule file path handling on import

If a rule file path in the export does not exist at import time, the GUI
presents a dialog with three choices:

1. **Browse for file** — locate the file at a new path.
2. **Skip** — start with empty rules for that route.
3. **Cancel** — abort the import entirely.

### 2.7 Schema evolution

Future versions may extend the YAML structure with additional fields; the
`version` field allows readers to detect and handle schema differences.

---

## 3. Preset Files

### 3.1 Overview

A preset is a shareable snapshot of routing rules. It lets users export their
current rules and share them with others, or import a community-prepared rule
set. Presets use the same plain-text format as working rules files (section 1).

A preset consists of **two files**, one per route:

| Filename | Content |
|---|---|
| `rules_primary.txt` | Rules for the primary route |
| `rules_secondary.txt` | Rules for the secondary route |

Either file may be omitted when a route has no rules to share.

### 3.2 Preset metadata

Preset metadata is stored as header comments at the top of each file, before
any section headers. All keys are optional.

```
# NetRuleRouter preset — version 1
# name: Corporate VPN Rules
# description: Routes corporate traffic via the secondary (VPN) interface
# author: Jane Doe
# preset_version: 1
```

The first line `# NetRuleRouter preset — version 1` identifies the file as a
preset and carries the format version. A file without this header is still
valid as a rules file; the metadata lines are treated as free comments.

### 3.3 Import and export

**Export:** the user saves each route's rules to a separate file. The GUI
writes and reads each file independently.

The GUI offers a setting "Import both files together" (off by default). When
enabled, selecting a file for one route automatically opens a file picker for
the other route.

**Import:** the imported file replaces the rules for the selected route. A
route whose file was not selected is left unchanged. The import always passes
through the controlled import flow: parse → validate → canonicalize →
candidate → review dialog → activate.

### 3.4 Community preset packs

A community pack is a folder (or `.zip` archive) containing up to two rules
files and a human-readable description:

```
my-corporate-pack/
├── README.txt           # free-form description, usage notes
├── rules_primary.txt    # optional
└── rules_secondary.txt  # optional
```

The user downloads the folder or archive, extracts it, opens the needed file
in the import dialog, and imports it. No special pack-import mechanism is
required.

Community presets can be contributed to the official repository via a pull
request that adds a pack folder under `presets/<country-code>/`, or under a
category folder such as `presets/abroad/`, following the same process as locale
file contributions. See `presets/README.md` for guidelines.

