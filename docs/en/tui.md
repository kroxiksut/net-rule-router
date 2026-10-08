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
| `2` | First run | Language, which adapter is primary and which additional, a rule set to start from, leak protection |
| `3` | Interfaces and routes | Adapters with their type, state and addresses; which one carries which route; checking an adapter |
| `4` | Rules | The rule table with search and filter; add, change, delete, switch on and off; import and export; applying your changes |
| `5` | Overlaps | Pairs of rules that cover the same traffic, and which route actually wins |
| `6` | Suggested addresses | Accept or decline what the application suggests adding to your rules |
| `7` | Connection trace | Recent connections and which route they took, with an explanation for any line |
| `8` | Cache | Names and the addresses they resolved to; search and clearing |
| `9` | Diagnostics and logs | Service health, security alerts, the explanation for a host, the log, exporting the diagnostic archive |
| `0` | Settings | Notifications, routing behaviour, service management, presets, logs and retention, and the other service-side settings the application has |

Changes to rules are applied the same way as in the application: you first see
a summary of what will be added, removed and changed, then confirm it.

## Keys

Everything works from the keyboard; a mouse is never needed. A key means the
same thing on every screen.

| Key | Action |
|-----|--------|
| `F1` or `?` | Help for the screen you are on — always available |
| `1`–`9`, `0` | Jump to a screen |
| `Tab`, `Shift+Tab` | Move between the panels of a screen |
| Arrows, `Enter` | Move within a list, open or confirm |
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
  "active", "limited", "error" — and colour only repeats it. With `--no-color`
  or `NO_COLOR` nothing is lost.
- **Focus is visible without colour:** the selected line is marked and shown in
  reverse.
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
- **The shared baseline** that every user on the machine starts from, and
  **managing the service** — install, start, stop — need an administrator
  terminal on Windows, or `sudo nrr-tui` on Linux. Without those rights the
  interface tells you so in words and shows the command that does it; it does
  not pop up an elevation prompt of its own, because over SSH there is no
  desktop to show one on.
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

Routing for system services and containers — the whole machine, not one user —
is planned for a later release.

## See also

- [The `nrr-cli` console](cli.md) — service management and diagnostics from
  scripts and the command line.
- [Recovering network access](recovering-network-access.md)
- [Where NetRuleRouter keeps its files](where-files-live.md)
