# The `nrr-tui` terminal interface

**English** · [Русский](../ru/tui.md)

`nrr-tui` is NetRuleRouter in a terminal. It does what the application window
does — status, first-run setup, adapters and routes, rules, suggestions,
diagnostics, settings — on a machine you reach over SSH, on a server with no
desktop, or simply for anyone who would rather work from the keyboard. The only
things it leaves out are the window's own preferences: theme, fonts and the
like.

It is the same product, not a second one: it talks to the same background
service, edits the same rules, and the screens follow the sections of the
application, so advice written for one works in the other.

> Pre-release software. Screens arrive in stages; one that is not ready yet
> says so instead of pretending.

## Terminal only

`nrr-tui` runs only in a live terminal. Started from a script, through a pipe
or with its output redirected, it does not start: it says so and exits with
code `3`. For reading and diagnostics from scripts, use the
[`nrr-cli` console](cli.md) — that is its job, and its exit codes are what a
script can rely on.

## Starting it

On Windows, `nrr-tui.exe` sits next to `NetRuleRouter.exe`. In PowerShell,
prefix it with `.\` when you are in that folder, as with the console:

```powershell
.\nrr-tui.exe
```

On Linux, the service install puts `nrr-tui` on your `PATH`:

```bash
nrr-tui
```

Options:

| Option | What it does |
|--------|--------------|
| `--plain` | Line mode for screen readers: nothing is redrawn, every change is printed as a new line, menus are numbered |
| `--no-color` | No colours. Setting the `NO_COLOR` environment variable to any value does the same |
| `--ascii` | Plain characters instead of frame lines, for terminals and fonts that draw box characters badly |
| `--lang <language>` | Interface language, for example `en` or `ru`. Without it the system language is used, and English when the system language has no translation |
| `--wizard` | Open the first-run setup, to go through it again |
| `--bell` | Sound the terminal bell when a new notification arrives. Off by default |
| `--help`, `--version` | Print the option list, or the version |

Setting `NRR_TUI_PLAIN=1` selects line mode without typing `--plain` every
time — convenient to put in your shell profile.

On first start, if you have not set anything up yet, the first-run setup opens
by itself.

## Screens

| Key | Screen | What you do there |
|-----|--------|-------------------|
| `1` | Status | Whether the service is running and routing is active, limited or paused — in words; both routes and their adapters; the notification feed; pause and resume |
| `2` | First run | Language, which adapter is primary and which additional, a rule set to start from, leak protection, routing sites by name, detailed diagnostic logs |
| `3` | Interfaces and routes | Adapters with their type, state and addresses; which one carries which route; checking an adapter |
| `4` | Rules | The rule table with search and filter; add, change, delete, switch on and off; mark a rule *not sure* to have it checked on the primary route first; your folder of rule sets; import and export; applying your changes. `c` checks whether the primary route reaches the sites of your additional-route rules, and the answer shows beside each rule, so you can see which rules still do real work; `Shift+O` lists the sites the primary route does not reach first. `v` adds a rule for a VPN's gateway, so a VPN that may connect only from one network (a work VPN allowed only from abroad, say) always connects through the route you choose: it asks for the program and the route, lists the addresses that program connected to lately, and takes a number or an address you type |
| `5` | Overlaps | Pairs of rules that cover the same traffic, and which route actually wins |
| `6` | Suggested addresses | Accept or decline what the application suggests adding to your rules |
| `7` | Connection trace | Recent connections and which route they took, with an explanation for any line. `o` opens the list of what was blocked while the additional route was down. `h` switches to your connection history — one line per program and destination, with how many times it connected — and `t` picks the period: the last hour, today or the last 7 days. `g` groups the list by program or by the folder a program lives in and remembers the choice; in a folder group `f` opens a rule for the whole folder. `i` and `a` open a rule for the chosen connection's address or program |
| `8` | Cache | Names and the addresses they resolved to; search and clearing |
| `9` | Diagnostics and logs | Service health, security alerts, the explanation for a host, the log, exporting the diagnostic archive |
| `0` | Settings | Notifications, routing behaviour, service management, presets, logs and retention, and the other service-side settings the application has. In the menu, Settings opens into its sections, so the arrows take you straight to the one you need |

Changes to rules are applied the same way as in the application: you first see
a summary of what will be added, removed and changed, then confirm it.

### More on the Rules screen

- **Deny.** In the rule form the route can also be *Deny*: the destination is
  not let through any connection, and the rules file shows it as `!value`.
  `f` can show only the denied rules.
- **Programs by folder.** An application rule can name a program file or a
  folder (`C:\Apps\Tool\*`, `/opt/tool/*`). `Ctrl+F` in the form switches a
  folder rule between "with subfolders" and "this folder only"; a rule the
  protection of system programs refuses is refused before it is saved, with
  the reason.
- **Several rules at once.** `Shift+A`, or `F2` in the add form, takes lines
  of a rules file typed or pasted (`!`, `?`, `#` and `--- Section` lines work
  as in the file). Each line is checked before anything is added; lines that
  were not taken stay in the form. Everything added goes in one step, so one
  apply sends it together.
- **Recent changes.** `Shift+R` shows the rules you added or changed in the
  last hour, today or the last 7 days, newest first, and the ones you
  deleted; `Shift+U` puts a deleted rule back with the route and switch it
  had.
- **A value in the wrong section.** `Shift+T` gives the chosen rule the type
  its value is (a program name written as a domain, say); `Shift+M` does it
  for every such rule. `Ctrl+T` does the same in the form.
- **Allowed despite protection.** `Shift+P` on a rule marked `+override`
  confirms it despite the protection of system programs, for a term you
  choose, or takes a confirmation back. A confirmation that reaches past your
  own programs needs an administrator: on Windows confirm it in the app window
  or from a terminal started as administrator; on Linux the terminal asks for
  the administrator's password.
- **Groups and files.** `g` sends a group of programs or a hypervisor's
  machines over a route; there `m` shows a hypervisor's machines and what
  each network adapter needs for your site rules to work inside it, and for a
  VirtualBox NAT adapter `a` sends all of that machine's traffic over the
  additional route, `f` lets it follow your rules again. `F` compares your
  linked rules files with the rules in force and merges them.

## Keys

Everything works from the keyboard; a mouse is never needed. A key means the
same thing on every screen.

| Key | Action |
|-----|--------|
| `F1` or `?` | Help for the screen you are on — always available |
| `1`–`9`, `0` | Jump to a screen |
| `Tab`, `Shift+Tab` | Move between the panels of a screen |
| Arrows, `Enter` | Move within a list, open or confirm |
| `Space` | Switch the selected rule or setting on and off; in the rule form, change the type or the route |
| `/` | Search in a list |
| `Esc` | Back, or cancel |
| `Ctrl+S` | Apply your rule changes |
| `q` | Quit. With changes not yet applied, it asks whether to apply, discard or stay |

In line mode (`--plain`) the same actions are offered as numbered choices: type
a number and press `Enter`; `h` or `?` prints the help, `q` quits.

## Accessibility

- **Screen readers.** `--plain` is the mode to use with NVDA or Narrator in the
  Windows console, and with Orca, Speakup or BRLTTY on Linux. Nothing jumps
  around the screen; every change arrives as a new line to be read.
- **Colour is never the only carrier of meaning.** Every state has a word —
  "active", "limited", "error" — and colour only repeats it; the main and the
  additional connection are told apart by name, colour only helps the eye. Only
  the terminal's own named colours are used, so the screen follows your terminal
  theme, light or dark. With `--no-color` or `NO_COLOR` nothing is lost.
- **Focus is visible without colour:** the selected line is marked with `>` and
  shown in bold.
- **No frame line carries meaning on its own.** Panels have text headings, and
  `--ascii` replaces the frames with plain characters.
- **Nothing is timed.** No question disappears or answers itself, and every
  notification also stays in the feed on the Status screen.
- **Readable at 80×24.** A narrow terminal wraps text instead of cutting it off;
  a wider one uses the room.
- **Every error says what happened and what to do next**, in words, not codes.

## Rights

- **Your own rules need no administrator rights.** Edit and apply them from an
  ordinary terminal; they apply to you.
- **The Rules screen edits one set at a time**, and its title says which:
  your own rules, or the baseline every user without rules of their own
  follows. Press `b` to switch (in line mode, type `b`). Suggestions, the
  main-route check and moving `?` rules change your own rules, so they wait
  until your rules are on screen.
- **The shared baseline**, settings of the whole computer, and **managing the
  service** — install, start, stop — need an administrator. On Windows start
  the terminal as administrator and press `b` to edit the shared baseline, or
  edit it in the app window, which asks for administrator rights itself. From
  an ordinary terminal the baseline can be viewed, but a change to it is not
  applied: the interface says to start `nrr-tui` again from a terminal opened
  as administrator. On Linux `nrr-tui` asks for the administrator's password
  right in the terminal, over SSH too; under `sudo` the baseline is on screen from the start. In line mode
  (`--plain`) there is no password prompt: the interface shows the `sudo`
  command instead.
- When the service is not installed or not running, the interface says which,
  shows the exact `nrr-cli` command that fixes it, and keeps checking until the
  service answers. In the meantime it shows only what it already knows and does
  not present it as current.

## Linux servers

On Linux, rules apply to a user who is logged in. When you manage your rules
with `nrr-tui` over SSH, they apply while you have a session on the machine —
or all the time, once lingering is enabled for your account:

```bash
sudo loginctl enable-linger "$USER"
```

Every signed-in user — at the seat or over SSH — is routed by their own rules
at the same time; see [Several users on one computer](several-users.md).
Background services follow the rules of the person at the seat, or of the
first to sign in. A mode that routes the whole machine, containers included,
by one set of rules is planned for a later release.

## See also

- [The `nrr-cli` console](cli.md) — service management and diagnostics from
  scripts and the command line.
- [Recovering network access](recovering-network-access.md)
- [Where NetRuleRouter keeps its files](where-files-live.md)
