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
| `PROVISION_SETTINGS` | A settings file exported from another computer: its default route (the main or the additional connection) becomes the starting one, and its leak protection the weakest a user starts with. The connections in it are not carried over, because each computer has its own |
| `SECONDARY_UNSET` | `direct` (default): until an additional connection is chosen, its rules go straight out. `block`: they are held back until then, and a user who has not chosen leak protection starts with **Routed sites** |

Use full paths. Every parameter is optional.

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
