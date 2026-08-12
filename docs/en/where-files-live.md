# Where NetRuleRouter keeps its files

NetRuleRouter stores its data in a few well-known places on your PC. This page tells you what lives where, who writes it, what survives a reinstall, and what is safe to delete by hand.

Nothing here is sent anywhere. Every path below is on your own machine.

The short version: your **rules files** are wherever you saved them and are yours alone; everything else is either shared machine state under `ProgramData` or per-user settings under `AppData`.

## Your rules files

Your two rule files — one for the main route, one for the additional route — live **where you chose to put them**. NetRuleRouter never moves them and never keeps a hidden second copy.

These are plain text. You can read them, edit them in any editor, copy them to another PC, and put them under version control. If you only ever back up one thing, back up these.

## Shared machine state: `C:\ProgramData\NetRuleRouter\`

Written by the background service, shared by every user of the PC. Ordinary users can read it; changing it requires administrator rights.

| What | Why it is there | Safe to delete? |
|---|---|---|
| `nrr_service_state.db` | The rules currently being enforced, your route assignments and behaviour settings | No. Deleting it resets the service to a clean state — you would have to load your rules again |
| `nrr_fqdn_ip_cache.db` | Addresses already looked up, so a routed site works from the first click after a restart | Yes. It is rebuilt as you browse; the only cost is a slower first few minutes |
| `nrr_traffic_stats.db` | The traffic counters shown in the app | Yes. You lose the history, nothing else |
| `logs\` | Operational logs of the service | Yes. Also cleared from Settings, Diagnostics and logs |
| `audit\` | The security audit trail | Not recommended. It is deliberately excluded from in-app cleanup: it is the record of what changed your routing and when |
| `archives\` | Diagnostic archives you exported | Yes, once you no longer need them |
| `backups\` | Automatic copies taken before risky operations | Yes, at the cost of the safety net they provide |

Both databases keep the retention limits you set in **Settings, Diagnostics and logs** — you do not have to clean up by hand.

The two `.db` files above are meant to be managed by the application itself, through its own settings, import, and export flows. Opening and editing them directly with a generic SQLite tool or any other third-party program is not supported: it can leave the app unable to start, make it apply the wrong routing policy, or lose your settings and rules. There are legitimate reasons to touch a database file outside the app — restoring it from a backup, moving it to another machine — so this is not forbidden, but if you do it, the consequences are yours to deal with.

## Your own settings: `%APPDATA%\NetRuleRouter\`

Per-user, and the place your personal preferences live. On a domain PC with roaming profiles these follow you between machines.

| What | Why it is there |
|---|---|
| `managed\ui-preferences.conf` | Theme, language, font and accessibility settings, window size, the section you had open, your route labels |

This file is plain text. It holds no rules and no routing policy — deleting it gives you a fresh-looking app with your routing untouched.

## Per-machine cache: `%LOCALAPPDATA%\NetRuleRouter\`

Per-user and deliberately not roaming, because it describes this PC.

| What | Why it is there |
|---|---|
| `snapshot_cache\` | The last state the app saw, so the window can open and show you something useful when the service is not running yet |
| `notification-decisions.json` | Which notifications you have already answered, so the app and the tray icon do not ask you the same question twice |

Both are safe to delete. The app rebuilds them; the only visible effect is that a notification you dismissed once may be offered again.

## Temporary files: `%TEMP%\NetRuleRouter\`

Short-lived working files the app windows and the tray icon use to talk to each other, plus the launcher logs that go into a diagnostic archive. Cleared by Windows disk cleanup, and NetRuleRouter sweeps its own leftovers on startup. Safe to delete at any time while the app is closed.

## What survives a reinstall

- **Your rules files** — untouched, they are not in any app folder.
- **Everything under `ProgramData`** — the service picks up where it left off, including the rules currently enforced.
- **Your settings under `AppData`** — theme, language and the rest come back as they were.

An uninstall that offers to remove your data removes the `ProgramData` and `AppData` folders above. Your rules files are never touched, wherever you keep them.

## If you want a clean start

1. Close the app and stop the service.
2. Delete `C:\ProgramData\NetRuleRouter\` and `%APPDATA%\NetRuleRouter\`.
3. Start the app and load your rules files.

You get a factory-fresh install with your rules intact, which is the point of keeping them outside the app in the first place.
