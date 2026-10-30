# Unattended installation

**English** · [Русский](../ru/unattended-install.md)

Install NetRuleRouter from a script, together with other software, with your
own rules ready for every user of the computer. Nothing is asked during the
installation, and a rules file that cannot be used fails the installation
instead of leaving a half-configured computer behind.

## Windows

With the MSI:

```
msiexec /i NetRuleRouter.msi /qn /l*v C:\temp\nrr-setup.log ^
  PROVISION=C:\deploy\rules_primary.txt ^
  PROVISION_SECONDARY=C:\deploy\rules_secondary.txt ^
  PROVISION_SETTINGS=C:\deploy\settings.yaml ^
  SECONDARY_UNSET=direct
```

With the EXE installer, the same names as switches:

```
NetRuleRouter-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /LOG=C:\temp\nrr-setup.log ^
  /PROVISION=C:\deploy\rules_primary.txt /SECONDARY_UNSET=direct
```

| Parameter | What it gives |
|---|---|
| `PROVISION` | Rules for the main connection |
| `PROVISION_SECONDARY` | Rules for the additional connection |
| `PROVISION_SETTINGS` | A settings file exported from another computer: its rules are installed as if given as rules files, its default route (the main or the additional connection) becomes the starting one, and its leak protection the weakest a user starts with. The connections in it are not carried over, because each computer has its own. Give a route its rules once: a rules file and rules in the settings file for the same route fail the installation with code 12 |
| `SECONDARY_UNSET` | `direct` (default): until an additional connection is chosen, its rules go straight out for a user who turned leak protection off. `block`: they are held back until then even for that user. Leak protection itself starts at **Routed sites** for every user, and while it is on those rules wait either way |

Use full paths. Every parameter is optional.

A silent installation shows no licence page, so every Windows account, the
one that installed included, is asked to accept the end-user agreement the
first time it starts the app. After an installation through the wizard, the
account that accepted the agreement there is not asked again; every other
account still is.

### Folder, components and shortcuts

Each choice the wizard offers has a command-line form. Without it, a new
installation takes the default and an upgrade keeps the earlier choice.

| Choice | MSI | EXE | Default |
|---|---|---|---|
| Installation folder, inside Program Files | `INSTALLFOLDER=<folder>` | `/DIR=<folder>` | `C:\Program Files\NetRuleRouter` |
| Leave out the terminal interface (`nrr-tui`) | `NRR_TUI=0` | `/COMPONENTS=main,docs` | Installed |
| Leave out the offline documentation | `NRR_DOCS=0` | `/COMPONENTS=main,tui` | Installed |
| Desktop shortcut | `NRR_DESKTOP_SHORTCUT=1` | `/MERGETASKS=desktopicon` | None |
| `nrr-cli` and `nrr-tui` on PATH | `NRR_ADD_TO_PATH=1` | `/MERGETASKS=addtopath` | Not added |

The window, the tray, the background service and the console (`nrr-cli`) are
always installed. A folder outside Program Files fails the installation
before anything is installed: the MSI returns 1603, the EXE installer 7. To
take a choice back on an upgrade, give it again: `NRR_TUI=1` or `NRR_DOCS=1`,
or for the EXE installer the full list, such as `/COMPONENTS=main,tui,docs` or
`/TASKS=addtopath` (an empty `/TASKS=""` drops every task). `/COMPONENTS=main`
leaves out both the terminal interface and the documentation. Several tasks are
separated by commas: `/MERGETASKS=desktopicon,addtopath`.

Without the offline documentation, Help > Documentation in the application
opens these pages online.

### Whose Start menu gets the shortcut

The program is installed once for the whole computer, and routing works for
every Windows account whatever you choose. `NRR_INSTALL_FOR` (MSI) and
`/INSTALL_FOR` (EXE installer) only decide who finds NetRuleRouter in the Start
menu and on the desktop, and whose PATH gets the console tools:

| Value | Shortcut and PATH |
|---|---|
| `all` | Every user of the computer. The default for a new installation |
| `me` | Only the account the installer runs as: for the MSI, the account that started `msiexec` |

Without it, an upgrade keeps the choice made at the earlier installation, and
an upgrade that changes it moves the shortcuts and the PATH entry. Any other
value stops the installation before anything is installed: the MSI returns
1603, the EXE installer exit code 1. The package without the window has no
shortcuts and always puts the console tools on the PATH of every user.

## Linux

Before installing the `.deb` or `.rpm`, place the files in
`/etc/netrulerouter/provision/` (owned by root): `rules_primary.txt`,
`rules_secondary.txt`, `settings.yaml`, and `options.conf` with a line
`secondary-unset = direct` or `secondary-unset = block`. The service takes them
at its first start.

From the archive, pass the files to the installer:

```
sudo ./install.sh --provision rules_primary.txt --provision-secondary rules_secondary.txt \
  --provision-settings settings.yaml --secondary-unset block
```

## What happens after the installation

- The rules become the shared rules every user of the computer starts from.
  A user who later edits their own rules keeps their edits; the shared rules
  stay what you installed.
- Until a user confirms the main connection, the network works as if the
  program were not there. The tray offers the computer's internet connection
  for confirmation in one click, or lets the user choose another.
- The files are applied once. Afterwards they stay, renamed, in the service's
  provisioning folder (`%ProgramData%\NetRuleRouter\provision` on Windows,
  `/etc/netrulerouter/provision` on Linux), so you can see that they were taken.

## When a file cannot be used

The files are checked before anything is installed. A file that cannot be used
fails the installation, and the reason is in the setup log:

| Code | Meaning |
|---|---|
| 10 | The rules for the main connection |
| 11 | The rules for the additional connection |
| 12 | The settings file |
| 13 | The `SECONDARY_UNSET` value |
| 14 | The files could not be prepared for the service |

The MSI then returns 1603, the EXE installer returns 7, and `install.sh`
returns the code from the table. Check your files ahead of time with
`nrr-service provision-check --primary <file>` on Windows, or
`nrr-serviced provision-check --primary <file>` on Linux: it changes nothing
and returns the same codes.

When the program is installed but its background service could not be
registered or started, the EXE installer returns 15; the MSI undoes the
installation and returns 1603.

## See also

- [Rules file format](rules-file-format.md)
- [Packaging for Windows](packaging-windows.md) and [for Linux](packaging-linux.md)
- [Several users on one computer](several-users.md)
