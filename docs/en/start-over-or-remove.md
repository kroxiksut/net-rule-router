# Start over, reset or remove the program

**English** · [Русский](../ru/start-over-or-remove.md)

This page helps you choose the right kind of fresh start.

## Which one do I need?

| I want to | Do this |
|-----------|---------|
| Throw away my rules and begin again | [Clear all rules](#clear-all-your-rules) |
| Put the program's own settings back (theme, notices...) | [Reset application settings](#reset-application-settings) |
| Make the program behave as if just installed | [Full reset](#full-reset) |
| Get rid of the program | [Remove the program](#remove-the-program) |
| Get my internet back right now | [Recovering network access](recovering-network-access.md) |

## Clear all your rules

1. Click **Rules**, then **More...**, then **Clear all rules...**.
2. Confirm **Clear all rules**.

Every rule is gone and your internet works the ordinary way. This cannot be
undone, so save your rules first if you might want them back:
[Save your rules and load them back](rule-sets.md).

## Reset application settings

Click **Settings**. At the bottom click **Reset application settings**. The
program's own preferences (theme, language, notices, connection names) go back
to defaults. Your rules stay. Check **Connections** afterwards.

## Full reset

Click **Settings**. At the bottom click **Full reset…**. This puts all settings
back, deletes the rules the program keeps for you, clears logs and restarts the
background service. Your own rule files on disk are not touched. It cannot be
undone.

1. Read the window.
2. If other people use this computer, choose **Only my data** or **Every user on this computer**.
3. Tick **I understand this erases all settings and applied rules**.
4. Click **Reset everything**.
5. When it finishes, click **Close everything now**, then start the program again.

## Remove the program

- **Installed with the EXE or the MSI:** open Windows Settings → Apps →
  NetRuleRouter → Uninstall. The installer asks how:
  **Remove the program** keeps your settings and rules for a later reinstall,
  **Remove completely** erases them too. Rule files you saved in your own
  folders stay either way.
- **Portable copy:** **Settings** → **Service management** → **Uninstall service**,
  close the program, delete its folder.

Both ways put back the network settings the program changed.

## If you need more

- Removing without a window, and what each way keeps:
  [Quick start](quickstart.md#removal) and
  [Packaging for Windows](packaging-windows.md#removing-an-installed-copy).
- Where the files live: [Where NetRuleRouter keeps its files](where-files-live.md).
- In the terminal interface, `W` on the **Rules** screen clears all rules; the
  service is removed with `nrr-cli uninstall`: [the terminal interface](tui.md),
  [the console](cli.md).

## See also

- [Recovering network access](recovering-network-access.md)
- [Quick start](quickstart.md)
- [Questions and answers](questions.md)
