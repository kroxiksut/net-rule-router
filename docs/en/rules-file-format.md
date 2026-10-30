# NetRuleRouter File Formats

**English** · [Русский](../ru/rules-file-format.md)

This document specifies all external file formats used by NetRuleRouter.
It covers the rules text file format and the settings export YAML format.

## 1. Rules File Format

**Quick reference.** Everything a line can carry; the sections below give the
details.

| Write | Meaning | Example |
|---|---|---|
| `--- Name` | Section header: the type of the rules below it (§1.2) | `--- Domains` |
| `value` | A rule: send this destination over this file's route | `example.com` |
| `*.value` | The site with all its subdomains | `*.example.com` |
| `value.*` | The site in every zone | `example.*` |
| `!value` | Deny: never send this destination through any connection (§1.12) | `!telemetry.example.net` |
| `?value` | This file's route while the site opens there (§1.15) | `?accounts.example.com` |
| `# value` | Rule kept but turned off | `# example.com`, `# !example.com` |
| `value  # text` | Rule with your note | `example.com  # updates` |
| `value +children` | Application rule that also covers the programs it starts (§1.6) | `codex.exe +children` |
| `value +override` | Program rule the protection of system programs holds, applied once you confirm it (§1.16) | `!/var/www/* +override` |
| `# text` | Comment, ignored | `# my notes` |

`!` and `?` go right before the value, after the `#` of a turned-off rule, and
never together.

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
| `--- CIDR` | Subnet rules (`10.0.0.0/8`) | All |
| `--- Ranges` | IP range rules (`192.0.2.10-192.0.2.40`) | All |
| `--- Windows` | Windows application rules (`.exe` name, file path or folder) | Windows only |
| `--- Linux` | Linux application rules (process name, file path or folder) | Linux only |
| `--- MacOS` | macOS application rules (process name, file path or folder) | macOS only |
| `--- Auto` | Rules the application added on your behalf (§1.13) | All |

Future revisions may introduce additional sections (such as `Ports`) as the
rule model expands.

Sections are written in the order of the table above, empty ones included
(see "Empty sections" below). `--- Auto` is written last, so a file reads as
"the rules you wrote, then the rules the application added for you".

**A section is a type, strictly.** A value spelled as another type is a line
error, and the message names the section it belongs in: a subnet or a range
under `--- IP`, an address under `--- CIDR`, a program (`chrome.exe`, a path)
under `--- Domains` or `--- Zones`, an address, a network or a domain under
`--- Windows`, an address or a network under `--- Linux` / `--- MacOS`. A single
word (`telegram`, `ru`) can be a zone or a program, so the section decides.
Program names on Linux and macOS may contain dots, so a dotted name is accepted
there. The program never moves lines between sections on its own: it offers to
move a line and moves it only when you confirm.

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
is ignored. Write the name as the section table above spells it; when reading,
case does not matter (`--- domains` is the `Domains` section), and the app
always writes the spelling from the table.

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

The comment starts at a `#` that follows a space or a tab. A `#` inside a
value stays part of it, so `C:\Projects\C#\tool.exe` names that program. A
program whose name has a `#` right after a space is written in double quotes
(`"C:\Tools\Build #2\tool.exe"  # note`), the same quotes as below.

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
# codex.exe +children
```

A `#` at the start of a line followed by a valid rule value marks the rule as
**disabled**. The GUI represents this as a toggled-off rule. Toggling a rule
off in the GUI comments its line; toggling it on removes the `#`.

A line starting with `#` where the rest is not a valid rule value (e.g.
`# this is a note`) is treated as a free comment — it is not shown as a
disabled rule in the GUI.

In an application section, a program written in double quotes is always a
rule, on or off, and the quotes are not part of its name. The app writes a
disabled program this way when its name would otherwise read as a note, so
turning it off never loses it:

```
# "Web Content" +children   # note
```

Removing the `#` by hand turns such a rule on; the quotes may stay. A `!` goes
before the opening quote, and `+children` or `+override` after the closing one.

#### Check where it works

```
?accounts.example.com
?*.mail.example.net
?203.0.113.7
# ?old.example.com
```

A `?` written immediately before a domain value or a single IPv4 address, in
either file, asks the app to check that the site opens through that file's
route (§1.15). It goes after the `#` of a disabled rule, never before it.

#### Deny

```
!telemetry.example.net
!10.20.0.0/16
!telemetry.exe
# !old.example.com
```

A `!` written immediately before a value, in either file and in any section,
denies the destination: it is not sent through any connection (§1.12). It goes
after the `#` of a disabled rule, and it is never combined with `?`.

#### Free comment

```
# This is a free comment, not a rule.
```

Standalone comment lines (where the content after `#` is not a recognizable
rule value) are ignored by the rule engine and are not shown in the GUI rule
list.

They are **not kept** when the app writes the file. Saving rules from the
window, the tray or the terminal interface writes the file anew from the rules
list, and a free comment is not part of that list. A note you want to keep
belongs on the rule's own line (`example.com  # why it is here`): it is the
rule's comment and is written back with the rule, unless you export with
"Include rule comments" turned off. Sections for other operating systems are
written back as they were. A file you edited by hand after the app last saved
it is not overwritten: the app leaves it as it is and offers to compare it
with the rules in force.

#### Syntax hint

```
#: !value           deny: through no connection at all  !ads.example.net
#: ?value           this route while the site opens     ?mail.example.com
```

A file the app writes opens with a few lines starting with `#:` that sum up
this syntax. They are written anew on every save, in the interface language of
that moment, and the app never reads them: editing them changes nothing. Do
not start your own lines with `#:` — they are dropped as part of the hint. The
hint does not change the format version: an older build reads it as comments.

#### Empty lines

Empty lines and lines containing only whitespace are ignored.

### 1.4 Complete example

```
# NetRuleRouter rules file — version 11
# Route: Primary (main network)

--- Zones
*.ru           # all .ru TLD traffic
corp-internal  # internal corporate zone

--- Domains
updates.example.org    # exact FQDN: vendor update endpoint
*.corp.example.net     # all subdomains of corp.example.net
# *.old.example.com    # disabled: decommissioned subdomain range
?accounts.example.com  # main route while it opens there (§1.15)

--- IP
203.0.113.7

--- CIDR
10.0.0.0/8             # corporate network
2001:db8::/48

--- Ranges
192.0.2.10-192.0.2.40  # a block of addresses

--- Windows
browser.exe        # browser traffic
*vpn*.exe          # any VPN client executable
C:\Tools\Sync\*    # every program of the folder and its subfolders
# powershell.exe   # temporarily disabled

--- Linux
# (reserved — not applied on Windows)

--- MacOS
# (reserved — not applied on Windows)

--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.org added:2026-07-31
```

The additional-route file of the same pair:

```
# NetRuleRouter rules file — version 11
# Route: Additional (VPN)

--- Domains
*.streaming.example.com    # always through the VPN
?*.video.example.net       # through the VPN while it opens there (§1.15)
example-tv.*               # the site in every zone (§1.5)
!telemetry.example.net     # never leaves this computer (§1.12)
```

### 1.5 Rule evaluation priority

The narrower rule wins. The order is fixed (highest to lowest), and the rules of
both files are evaluated together:

1. **Exact domain** — `example.com` (no `*.` prefix) matches only that
   hostname.
2. **Domain with subdomains** — `*.example.com` matches `example.com` itself
   and any subdomain of it at any depth. The longest base domain wins among
   competing suffix rules. To route the apex differently from its subdomains,
   add an exact rule for the apex — it is a higher tier and wins.
3. **Site in every zone** — `example.*` matches `example.com`, `example.net`,
   `example.co.uk` and any of their subdomains: for each host it is the rule
   `*.example.<zone>`. A rule that names the zone beats it on any route, for
   the hosts it covers: `*.example.by` for all of `example.by`, a bare
   `example.by` only for that host itself, so `www.example.by` still follows
   `example.*`. With "Also cover subdomains for domain rules" on, the bare
   name covers all of `example.by` too. Between two site-in-every-zone rules
   the longer name wins, so `mail.example.*` beats `example.*`.
4. **IP** — `203.0.113.7`, one exact address. It beats any network that
   contains it.
5. **CIDR and Ranges** — `10.1.0.0/16` or `192.0.2.10-192.0.2.40`. Between
   networks the longer prefix wins, so `10.1.0.0/16` beats `10.0.0.0/8`. The
   same network on both routes is an error.
6. **Zones** — `ru` matches every hostname ending in `.ru`. A longer zone beats
   a shorter one. A network or an exact address inside a zone beats the zone.
   A zone of several labels, such as `corp.example.com`, is ranked at tier 2
   instead: a domain with subdomains that leaves out the bare name, so it beats
   `*.example.com`, an exact address and a network. Against
   `*.corp.example.com` it is the narrower rule and keeps the subdomains; with
   "Also cover subdomains for domain rules" on, it counts as
   `*.corp.example.com` itself and the primary route wins the tie.
7. **Application** — `chrome.exe`, `C:\Apps\Tool\tool.exe`, `C:\Apps\*`
   (`Windows` / `Linux` / `MacOS`). Within the tier the narrower rule wins: a
   full path first, then an exact name, then a folder (a deeper folder first;
   at the same depth "this folder only" before "with subfolders"), then a name
   pattern; among matching name patterns, the first rule in the file wins. Only
   the platform-appropriate section is evaluated. The destinations an
   application rule teaches the router (§1.10) are evaluated at this tier too,
   so an address rule for the same address wins.
8. **Default route** — the setting of that name: the main or the additional
   connection (see [Quick start](quickstart.md#first-setup)).

Name rules (tiers 1, 2, 3 and 6) apply only when the destination's name is known.

Two more rules settle the rest:

- A deny rule (`!`, §1.12) for an exact IP address stops that address whatever
  other rule names it. Any other deny takes its tier in the order above, so a
  zone deny does not stop a site an exact rule routes.
- When two rules of the same tier are equally specific, a deny beats a route
  and the primary route beats the additional one.

By default a rule for a site or an address wins over a rule for a program.
The switch **Programs in your rules take all their traffic** (Settings →
Routing) turns that around for programs: a program you named in a rule then
sends everything it connects to over that rule's route, even to sites another
rule sends the other way. Routing works per address, so such a site then goes
that route for every program on the computer, not only for the one you named.
An exact-IP deny rule still stops its address, and a site your primary
route names stays reachable for other programs when the additional route is
down. The switch is off by default.

### 1.6 Child process tracking (`+children`)

> **Not in effect yet.** This version accepts the flag and keeps it in your
> rules, but the rule covers only the named program; the programs it starts
> follow their own rules. The window and the terminal interface mark such a
> rule with a warning. Following the programs a program starts is on the
> [roadmap](../../ROADMAP.md).

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

> A deny (`!`, §1.12) combines with the flag: `!codex.exe +children`.

The flag means something only after a program name. After any other value
it is dropped on reading, and the rule is read without it. A turned-off
program rule keeps it: `# codex.exe +children`.

**Status in this release:** the flag is accepted and ignored. A rule written
with `+children` is read as a plain application rule and covers the named
process only; the descendant subtree is not followed yet. Writing it now costs
nothing and starts working when subtree attribution lands.

### 1.7 Section names are not localized

Section names (`Zones`, `Domains`, `IP`, `CIDR`, `Ranges`, `Windows`, `Linux`,
`MacOS`, `Auto`)
are technical keywords in the file format. They are not passed through the
locale layer and are not translated. The same applies to the reason slugs used
inside the `--- Auto` section (§1.13): the slug in the file is a fixed keyword,
and the GUI renders a translated sentence for it.

The GUI may display localized descriptions *about* each section (shown as
hints or tooltips), but the section name written to the file is always the
canonical English keyword.

User-written inline comments (after `#`) are personal notes in whatever
language the user chooses — they are never modified or translated.

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
| `example.com` | Exact FQDN — matches `example.com` only | Exact domain (tier 1) |
| `*.example.com` | Suffix — matches `example.com` and any subdomain of it at any depth | Domain with subdomains (tier 2) |
| `example.*` | The site in every zone — `example.com`, `example.net`, `example.co.uk` and their subdomains | Site in every zone (tier 3) |

The `*.` prefix is the explicit subdomain operator. A bare domain name
without `*.` matches only the exact FQDN. The two forms are orthogonal:
a host gets matched at tier 1 by its exact entry; it falls through to tier 2
only if a suffix rule covers it.

Because tier 1 is checked first, writing both forms is how you split a site:
`*.example.com` on one route and `example.com` on the other sends the
subdomains one way and the bare domain the other.

`example.*` is for a site that lives under several zones: one line replaces
`example.com`, `example.net` and the rest. The zone is the end of the host
name a registrar sells under — `com`, `ru`, or two parts such as `co.uk` — so
`example.com.other.net` belongs to `other.net` and does not match. `*.example.*`
is read as the same rule. To send one zone of the site the other way, add a
rule for it (`*.example.by`): a rule that names the zone always wins. The `?`
check (§1.15) needs one host and does not apply to `example.*`.

#### IP (`--- IP`)

Exact IPv4 or IPv6 address, one per line.

```
203.0.113.7
2001:db8::7
```

A subnet or a range is not written here: it is a line error that names the
section it belongs in (`--- CIDR` or `--- Ranges`).

> Do not confuse these sections with the **Local networks** list in Settings.
> That list has a different job: it names local network segments — for example
> a hypervisor's virtual-machine network, or the subnet of your main
> connection — that must stay reachable while routed traffic is blocked. It
> does not send traffic anywhere; it only keeps local segments reachable.

#### CIDR (`--- CIDR`)

A subnet in CIDR notation, IPv4 or IPv6, one per line. Route a whole network
with one rule, on Windows and Linux.

```
10.0.0.0/8             # corporate network
2001:db8::/48
```

#### Ranges (`--- Ranges`)

An inclusive range of addresses, `first-last`, IPv4 or IPv6. Spaces around the
dash are accepted when reading; the file is written without them.

```
192.0.2.10-192.0.2.40
192.0.2.100 - 192.0.2.120
```

#### What the app checks in a network or a range

- A subnet wider than /8 (IPv4) or /16 (IPv6) is refused, so one rule cannot
  swallow a large share of the internet.
- A subnet or a range that touches loopback, multicast, broadcast or the
  "this network" block is refused.
- Link-local addresses are accepted with a warning.
- Host bits set in a subnet (`10.0.2.7/24`) are cleared with a warning, and the
  file is written back as `10.0.2.0/24`.
- The same network on both routes is a line error.
- When you save, a network is refused if it covers the address of the tunnel's
  server, a network the computer is connected to, or the address pool the app
  uses for name-based routing. The message names what it covers.
- A network wider than /16 (IPv4) or /48 (IPv6) is routed, but while the
  additional connection is down leak protection set to **Routed sites** does
  not hold it back, and the app warns you about this when you save the rule.

The Overlaps tab on the Rules screen shows when an address named for the main
connection lies inside a network named for the additional one: that address
stays on the main connection even when the additional one is down.

#### Windows / Linux / MacOS (application sections)

A program is named by its file name, by a pattern over file names, or by where
it lives: one file, the programs of one folder, or the programs of a folder and
every folder below it. A value without a path separator is a name; a value
with one (`\` or `/` on Windows, `/` on Linux and macOS) is a path.

| Example | Matches |
|---|---|
| `chrome.exe` | The program with this name, wherever it is installed |
| `*vpn.exe` | Any program whose name ends with `vpn.exe` |
| `nord*` | Any program whose name starts with `nord` |
| `*vpn*.exe` | Any program whose name contains `vpn` and ends with `.exe` |
| `C:\Apps\Tool\tool.exe` | That one program file |
| `C:\Apps\Tool` or `C:\Apps\Tool\` | The programs directly in that folder, not in its subfolders |
| `C:\Apps\Tool\*` | The programs in that folder and in every folder below it |
| `/opt/tool/bin/tool` | That one program file, or the programs of that folder if it is one |
| `/opt/tool/` | The programs directly in that folder |
| `/opt/tool/*` | The programs in that folder and in every folder below it |
| `%LOCALAPPDATA%\Discord\*` | For each user, the programs in their own `AppData\Local\Discord` and below it |
| `~/apps/*` | For each user, the programs in `apps` of their own home folder and below it |

A folder rule suits a program that keeps several executables of its own next
to each other or in subfolders (helpers, updaters, a new version folder after
each update): one rule covers all of them.

A folder rule does not separate websites that one shared server runs, such as
`php-fpm`, IIS or a Node.js process manager: their connections come from the
server, not from the files in each site's folder, so every site of that server
follows the server's route.

Name patterns:

- `*` matches **zero or more characters** (any character, including `.` and
  `-`). It is the only wildcard: `?` has no special meaning.
- A bare `*` as the entire match value is a **validation error** — too
  broad, would match every running process.
- Matching is **case-insensitive** on every platform: `Telegram.exe`,
  `telegram.exe` and `TELEGRAM.EXE` name the same program.

Paths:

- A path starts at a drive (`C:\`), a network share (`\\server\share\`) or, on
  Linux and macOS, at `/`. A relative path (`Tools\tool.exe`, `bin/tool`) or
  one with `..` in it is a line error.
- `*` may stand only as the whole last part of a path, written `\*` (or `/*`):
  "this folder with its subfolders". Anywhere else in a path (`C:\Apps\*.exe`,
  `C:\*\tool.exe`) it is a line error; to name programs by a pattern, write a
  name pattern without a path.
- On Windows a path without a trailing `\` is a program file when its last
  part ends with `.exe`, and a folder otherwise. On Linux and macOS a path
  without a trailing `/` is whatever is there when the rule is applied: a
  program file or a folder. Write the trailing `/` to say "folder" outright.
- Windows and macOS paths are compared without regard to case; Linux paths
  are compared exactly, as Linux names files.
- The same folder in the same form ("this folder only" or "with subfolders")
  in both files is an error, like the same network on both routes.
- `!` before a path denies the programs it names; `+children` after it
  extends the rule to the programs they start.
- On Windows and Linux a folder rule also covers a program that appears in
  the folder later, such as a new version folder after an update, without a
  restart. A folder that holds more programs than one rule covers is covered
  in part, and the Overlaps tab says so.
- On Windows and Linux a folder rule also covers the scripts kept in the
  folder when an interpreter installed elsewhere runs them: `python tool.py`,
  `powershell -File job.ps1`, a `.bat`, `.cmd` or `.vbs` file, `java -jar
  app.jar` or a Java class path into the folder, and on Linux a script with a
  `#!` line or the execute bit. "Run with PowerShell" from Explorer counts
  too. Such a script follows the rule once its first connection has been
  seen. On Windows a script that a service or a scheduled task runs follows
  the rules of the user whose routes the machine uses; a script another
  signed-in person runs does not count toward your folder rule.
- A program that only opens a file from the folder, such as an editor, is not
  covered, nor is code passed on the command line itself (`bash -c "…"`, a
  PowerShell `-Command` that does anything but call one script). On Windows a
  Java class path given only through the `CLASSPATH` variable is not
  recognised.
- A deny by folder holds the programs in the folder, but not for certain a
  script from it that an interpreter installed elsewhere runs. Use it to stop
  the folder's programs, not as a guarantee that nothing started from the
  folder gets through.
- A folder reached through a link or junction is judged where it really is:
  a link into a system folder is not applied, as the system folder itself is
  not.
- A path may start from a folder of the user's own profile: `%LOCALAPPDATA%`,
  `%APPDATA%` or `%USERPROFILE%` on Windows, `~` on Linux and macOS. It stays
  in the file as written and names each user's own folder, so one rule in the
  shared configuration covers every user's own copy of a program. Any other
  variable (`%TEMP%`, `$HOME`, `~name`) is a line error.
- One user's rule never covers the programs in another user's profile. A new
  rule written with the full path of a folder in another user's profile is
  refused; the shared configuration names a user's folder only from a profile
  folder as above. Such a line already in a rules file stays in it, and the
  Overlaps tab shows it as not applied, with the reason.
- A folder anyone may write into (`C:\Users\Public`, much of `C:\ProgramData`,
  `/tmp`, `/var/tmp`, `/dev/shm`) gets a warning when the rule is entered:
  anyone can put a program there. A program in such a folder is never exempt
  from leak protection, not even after you confirm it.
- macOS does not apply rules by path yet: such a rule stays in the file and
  in the rules list, and the Overlaps tab shows it as not applied, with the
  reason.

Precedence within the Application tier, narrowest first: a full path, an
exact name, a folder (the deeper folder first; at the same depth "this folder
only" before "with subfolders"), a name pattern. Among multiple name patterns
that match the same program, the first rule defined in the file wins.

#### System programs

A deny (`!`) or a rule in the additional route's file cannot name a program
the system needs to stay on the network, signed in and on time: on Windows
`svchost.exe`, `lsass.exe`, `services.exe`, `csrss.exe`, `wininit.exe`,
`smss.exe` and `winlogon.exe` among others; on Linux the `systemd` services,
`NetworkManager`, `dhclient` and `wpa_supplicant`; on macOS `launchd`,
`mDNSResponder` and `configd`. The same holds for a pattern that would catch
one of them (`svc*.exe`) and for the app's own programs. The main route may
name them: it is the way they reach the network anyway.

The Add dialog refuses such a rule before it is saved. One already in a rules
file — written by hand or kept from an older version — stays in the file and
in the rules list, is shown as not applied with the reason, and is not carried
out until it is changed.

When you do mean it, write `+override` after the value: the rule is then
applied once you confirm it (§1.16). The root of a disk and the app's own
programs can never be confirmed.

### 1.9 Forward compatibility — extended sections

When a rules file contains sections this version does not recognise (for
example `--- Ports` produced by a newer or extended format
revision), those sections are **parsed and preserved** in the file but are
**not applied** to the routing policy. This mirrors the existing behaviour
for platform-specific sections on a non-matching host (see section 1.3).

In the GUI, rules belonging to unrecognised sections are shown with a
"Not applied" badge. They cannot be toggled or edited.

On export, unrecognised rules are written back to the file unchanged, so no
information is lost when a file travels through this version.

### 1.10 Application rules and the destinations they route

Routing is **destination-based**: a route is keyed by the remote address, not by
the originating process. An application rule therefore cannot, by itself, send a
process's traffic out the additional adapter. What it does is tell NetRuleRouter
which application to watch: the destinations that application contacts are
learned by observation and routed via the rule's route (the file the rule lives
in — `rules_primary.txt` or `rules_secondary.txt`) on subsequent connections.

> True per-process *isolation* (only **this** application's traffic to a shared
> address rides the additional route; other applications contacting the same address do
> not) requires a kernel driver and is out of scope for now. A destination
> learned from an application is an ordinary destination route — it applies
> wherever that address is contacted. The first connection to an address the
> router has not seen before goes out over the usual route; routing takes effect
> from the next connection onwards.

In the file, an application rule is a **process name on its own line** — there
is no nested syntax for its destinations, and learned destinations are runtime
state rather than part of the file. To route one specific address regardless of
which program contacts it, write it as an ordinary `--- Domains` or `--- IP`
rule; those tiers outrank the Application tier (§1.5), so an explicit rule
always wins over what an application taught the router.

### 1.11 Format version

The header line `# NetRuleRouter rules file — version N` (and the preset header
`# NetRuleRouter preset — version N`, §3.2) carries the file format version.
Like the section names, this line is a fixed key: it stays in English whatever
language the file is written in, and a translated one is not recognised.

| Version | Adds |
|---|---|
| 1 | Sections, top-level rules, inline comments, disabled rules. |
| 2 | Reserved, never used. |
| 3 | Per-rule `+block` flag, replaced by `!` in version 9. |
| 4 | App-authored rules section (§1.13, `--- Auto`). |
| 5 | Subnet and range sections (§1.8, `--- CIDR`, `--- Ranges`). |
| 6 | The `?` prefix on domain rules in the additional-route file (§1.15). |
| 7 | The `?` prefix on single IP addresses and in the main-route file (§1.15). |
| 8 | A site in every zone (§1.8, `example.*`). |
| 9 | Deny written as `!` before the value (§1.12); the `+block` flag of version 3 is gone. |
| 10 | An application named by path: one file, a folder, a folder with its subfolders (§1.8). |
| 11 | `+override` after a program rule's value (§1.16). |

Version 2 was reserved for a nested `- destination` syntax under application
rules. It was never implemented and no build reads or writes it; the number is
left in place rather than reused, so a file from any build means the same thing
in every build. Do not declare version 2 in a file.

A file that uses `+override` declares **version 11**. An older build reads the
flag as part of the value and does not apply the rule; the rest of the file
works.

A file that names an application by path declares **version 10**. An older
build reads a file path there as the program's name alone and does not apply
a folder rule; open such a file in a current build.

A file that uses `!` declares **version 9**. A line still carrying `+block` is
a line error whose message shows the `!` form; it is never read as a route.

A file that uses `example.*` declares **version 8**. An older build reads the
line as a domain it cannot accept and does not apply it; the rest of the file
works.

A file that uses the `?` prefix declares **version 7** (version 6 when it is
only on domain rules of the additional-route file). A version-6 build reads a
`?` line of the main-route file as an ordinary rule of that file and does not
apply a `?` IP rule; an older build does not know the prefix at all and does
not apply such rules. Open such a file in a current build.

A file that contains a `--- CIDR` or `--- Ranges` section declares **version
5**. An older build treats those sections as extended ones (§1.9): it keeps
the rules in the file, warns about them and does not apply them, so opening
such a file in an older build breaks nothing.

A file that contains an `--- Auto` section declares **version 4**. A
pre-version-4 reader does not recognise the section name and therefore treats
it as an extended section (§1.9): the rules are preserved on round-trip but not
applied, so nothing is lost and nothing is misinterpreted.

### 1.12 Deny (`!`)

By default a rule *routes* its destination through the connection bound to the
file the rule lives in (`rules_primary.txt` → primary, `rules_secondary.txt` →
additional; §1.10). A **`!`** right before the value **denies** the destination
instead: nothing is sent to it through any connection, ping and other
protocols included, and no route is installed for it.

```
--- Domains
!telemetry.vendor.example     # not allowed from this computer
!*.metrics.vendor.example

--- CIDR
!10.20.0.0/16

--- IP
!203.0.113.9

--- Windows
!telemetry.exe
```

**What a deny is, and what it is not.** It is a manual rule: you name a
destination, and it stops being reachable from this computer. It is not an ad
blocker or a tracker blocker. NetRuleRouter ships no block lists, maintains
none, and has no view inside a page — it cannot remove an element, and it
cannot touch anything served from the same domain as the content around it.
Denying by name also depends on seeing the name resolved, so a browser using
its own encrypted DNS (DoH/DoT) can make a name-based deny miss; see
[What routing changes — and what it does not](what-routing-changes.md). A deny
by address or subnet does not depend on names.

Key properties:

- `!` touches the value: `! example.com` with a space is a line error, and so
  is `?!example.com` — a check never applies to a deny.
- **The file does not matter.** A deny stops its destination whether it lives
  in `rules_primary.txt` or `rules_secondary.txt`.
- `!` works in every section: `Zones`, `Domains`, `IP`, `CIDR`, `Ranges` and the
  application sections (`Windows` / `Linux` / `MacOS`). A denied application
  cannot connect anywhere. On Linux an application rule is not airtight yet:
  a denied program is stopped on the addresses it has been seen using, and a
  connection it makes before it is recognised can still get through (see
  [Known limitations](known-limitations.md)).
- Turn a deny off like any rule — `# !telemetry.vendor.example` keeps it in the
  file, inactive.
- A matched deny stops the connection at its tier (§1.5); no lower tier or the
  default route is consulted.
- **An address deny wins over every other rule for that address.** A site whose
  name you route is still stopped while it answers on an address you denied.
- **An application deny wins over every address rule.** A denied application
  is stopped even on a destination another rule routes by name or address.
- **A deny wins a tie.** When a deny and a route name the same destination
  equally narrowly — even from different files — the destination is denied.
  The Overlaps screen points out such pairs.
- **A narrower route keeps a shared address open.** When a site you route by a
  narrower rule shares an address with sites a wider deny covers, that address
  stays reachable, and so do those other sites on it. The Overlaps screen lists
  these cases for the rules currently applied.
- In the app, choose **Deny** as the route of a rule; the Rules list filters
  denied rules with **Denied**.

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
  (§1.3), put `!` before the value to deny instead of route (§1.12), edit or delete a
  line by hand — the section is plain text like every other one.
- **A line without an `auto:` token is still a rule.** It is imported as an
  ordinary rule of that file's route and reported as a warning, never dropped
  and never treated as an error. Hand-editing this section cannot lose rules.

### 1.14 Routing another VPN client through the public VPN

A common question: you already route traffic through a public VPN, and you
want a *different* VPN client — for example a corporate one — to go out
through that same connection. There are two ways to do it. Assign the public
VPN as the **main route**, and everything on the machine goes through it by
default, with no further rules needed. Or leave the public VPN as the
**additional route**, set default behavior (§1.5) so unmatched traffic
prefers the additional route, and add an application rule for the other
client's executable under the application sections (§1.8, `Windows` /
`Linux` / `MacOS`).

Name the **other** client's executable in that rule — never the client whose
own tunnel is already serving as the route. Pointing a client at its own
tunnel is a loop, not a chain.

One thing worth knowing before setting this up: it is a VPN running inside a
VPN. Double encryption costs noticeable speed, and a corporate VPN client may
refuse to connect at all once it detects it is running through another
tunnel.

### 1.15 Check where it works (`?`)

Some sites work through one route in one place and not in another, and you
cannot always tell in advance which case you are in. A **`?`** in front of a
rule says: use the route of this file while the site opens through it; if it
does not, but it opens through the other route, offer to move it there.

```
--- Domains
?accounts.example.com      # sign-in page
?*.mail.example.net

--- IP
?203.0.113.7
```

Key properties:

- **The site starts where you wrote it.** In the main-route file it uses the
  main route, in the additional-route file the additional one, for as long as
  it opens there.
- **Nothing in your files changes without you.** When a site does not open
  through its route but does through the other one, the app sends it through
  the other route at once and asks whether to move the rule for good, in one
  notice for all such sites. **Move** rewrites the lines into the other file
  without the `?`. **Not now** leaves your files as they are: the site keeps
  the other route until the computer restarts, and the check is repeated
  after that.
- **Only what you use is checked.** A site you never open keeps its `?` and is
  never checked.
- **Domain and single-address rules.** The prefix is read in `--- Domains`
  (and in `--- Auto`, which shares its grammar, §1.13), on exact hosts and on
  `*.` suffix rules alike, and, on a single IPv4 address, in `--- IP`. On an
  IPv6 address the `?` is dropped with a warning and the rule routes without a
  check. On `example.*` the `?` is dropped with a warning
  and the rule routes without a check: the check needs one host. In any other
  section the `?` is part of the value, which makes it invalid.
- **Not together with a deny.** "Check where it works" and "never send it"
  contradict each other, so `?!value` is a line error.
- **Disable it like any rule** — comment the line: `# ?accounts.example.com`.
- **One rule per site in a file.** `?accounts.example.com` and
  `accounts.example.com` in the same file are the same rule; the line without
  the `?` is kept.

### 1.16 Applying a rule despite the protection (`+override`)

A deny or an additional-route rule that would take a program the system needs
— a system folder, a folder many programs share, a critical system process
(§1.8, System programs) — is not applied. When you do mean it, write
**`+override`** after the value:

```
--- Linux
!/var/www/* +override      # keep the site's programs off the network
```

Key properties:

- **A request, not a permission.** The rule stays not applied, marked "needs
  your confirmation", until you confirm it in the window's rules list or in
  the terminal. Editing the file never confirms anything.
- **You see what it takes.** The confirmation shows how many programs the
  rule takes, the system processes and service accounts among them, other
  users' programs, and what may stop working — getting an address (DHCP),
  names (DNS), the clock, updates, signing in to a domain. You confirm by
  typing the rule's value.
- **For a time you choose.** 1 hour, 1 day (the default), 1 week or until you
  revoke it. The term survives a restart; when it ends, the protection holds
  the rule again and you are told.
- **Administrator rights where it reaches past you.** A rule that takes system
  folders or processes, service accounts or other users' programs needs an
  administrator to confirm it.
- **Visible while it lasts.** The rules list marks the rule "Allowed despite
  protection" with the time left, filters by that mark, and takes the
  confirmation back with one action. A new critical process under the rule
  asks for a confirmation again.
- **Undone by an emergency network reset.** Restoring the network revokes
  every confirmation. So does a run of service failures in a row, and you are
  told: an allowed rule that keeps bringing the service or the network down is
  not put back at every restart.
- **Never for everything.** The root of a disk and the app's own programs
  cannot be confirmed; `+override` there changes nothing.
- **Program rules only.** On any other line the flag means nothing and is
  dropped, as `+children` is.

---

## 2. Settings Export Format (YAML)

### 2.1 Overview

The settings export is a YAML file that keeps your routing setup in one
place: which connections you use for the two routes, your rules for both of
them, and how routing behaves. It is written when you choose
"Export full settings (YAML)" in Settings → Rules and settings files, or
"Export full settings" in the settings of the terminal interface.

There is no "Import settings" yet: neither the window nor the terminal
interface reads the file back. Today one place reads it — an unattended
installation, which takes your rules, the default route and the leak
protection from it (see [Unattended installation](unattended-install.md)).

### 2.2 What is included

- Adapter bindings: system ID, user label, confirmation status.
- Your rules for both routes, as they are in force for you, in the same text
  as a rules file (section 1): disabled rules, comments on rules, `?`, `!`
  and program and folder rules included.
- The rules for other operating systems from your rules files, kept as they
  are written (section 1.2, Platform filtering), so a restore from the export
  does not lose them.
- The paths of the rules files your rules are saved to, when you have them.
- Behavior settings: the default route and the leak protection.

### 2.3 What is NOT included

- Free comment lines of your rules files: they stay in the files.
- UI preferences (theme, language, accessibility, route display labels,
  display toggles) — device-specific, carried over per device on migration.
- Internal revision metadata (revision IDs, content hashes, audit events).
- Device-specific runtime state (connectivity probes, external IP, logs).

### 2.4 Structure

```yaml
nrr_settings_export:
  version: 2
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
    primary: "C:/Users/me/Documents/Rules/rules_primary.txt"
    secondary: "C:/Users/me/Documents/Rules/rules_secondary.txt"

  rules:
    primary: |
      --- Domains
      updates.example.org  # vendor updates
      ?accounts.example.com

      --- Windows
      browser.exe

      --- Linux
      browser
    secondary: |
      --- Domains
      *.streaming.example.com
      !telemetry.example.net

  behavior:
    route_mode: "prefer-primary"
    leak_protection: "off"
```

`rules.primary` and `rules.secondary` hold the text of each route's rules
file, indented under the key (a YAML literal block, `|`). A route with no
rules is written as `""`. The paths in `rules_files` are written empty when
no rules file is bound to the route.

`route_mode` is the default route: `prefer-primary` (the main connection) or
`prefer-secondary-when-available` (the additional one). `leak_protection` is
`off`, `sites` (Routed sites) or `everything`. A route with no connection
bound is written with an empty `system_id` and `user_label` and
`user_confirmed: false`.

UI preferences (theme, language, accessibility, route display labels) are
device-specific and intentionally **not** included in the export — they are
carry-over state per device, not part of the portable configuration.

### 2.5 Adapter system ID

The `system_id` field uses the composite format
`"mac=AA:BB:CC:DD:EE:FF;ifindex=N"`. This key is stable on the same device.
Another computer has connections of its own, so an unattended installation
does not carry the bindings over.

### 2.6 Schema evolution

Future versions may extend the YAML structure with additional fields; the
`version` field allows readers to detect and handle schema differences, and a
reader tolerates a key it does not know as well as a missing one. Version 2
added the `rules` section; a version 1 file, written before it, is still
read.

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
| `rules_secondary.txt` | Rules for the additional route |

Either file may be omitted when a route has no rules to share.

### 3.2 Preset metadata

Preset metadata is stored as header comments at the top of each file, before
any section headers. All keys are optional.

```
# NetRuleRouter preset — version 8
# name: Corporate VPN Rules
# description: Routes corporate traffic via the additional (VPN) interface
# author: Jane Doe
# preset_version: 1
```

The first line `# NetRuleRouter preset — version 8` identifies the file as a
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

