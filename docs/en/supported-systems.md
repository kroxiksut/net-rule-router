# Supported systems

What the first alpha runs on, how it is delivered there, and which systems it
has actually been run on. "Checked" means installed, used with real rules and
removed again on that system; the rest should work for the reasons given, but
nobody has confirmed it yet. If you run it somewhere not marked as checked,
an issue saying how it went helps more than anything else.

## Windows

| System | Delivered as | Window | Checked |
|---|---|---|---|
| Windows 11, 64-bit (x64) | portable ZIP, EXE installer, MSI | yes | yes |
| Windows 10, 64-bit (x64) | portable ZIP, EXE installer, MSI | yes | not yet |
| Windows on ARM (ARM64) | portable ZIP, EXE installer, MSI | yes | not yet |
| 32-bit Windows | not supported | — | — |

Installing the background service takes administrator rights once; everyday
use does not.

## Linux

The service needs **systemd** and **nftables**, as every current mainstream
distribution has. Each signed-in user gets their own rules on Linux 4.10 and
newer; an older kernel applies one user's rules for everybody. The window
needs **Qt 6.6 or newer** from the system; where the system has an older Qt,
the service, the `nrr-cli` console and the `nrr-tui` terminal interface work
without it.

| System | Delivered as | Window | Checked |
|---|---|---|---|
| Ubuntu 24.10 and newer | `.deb` | yes | Ubuntu 26.04 LTS: yes |
| Ubuntu 20.04 to 24.04 | `.deb` | no (Qt too old) | not yet |
| Debian 13 | `.deb` | yes | not yet |
| Debian 10 to 12 | `.deb` | no (Qt too old) | not yet |
| Astra Linux 1.8 | `.deb` | yes | without the window: yes |
| Astra Linux 1.7 | `.deb` | no (Qt too old) | yes |
| RED OS 8 | `.rpm` | depends on the Qt it ships | without the window: yes |
| RED OS 7.3 | `.rpm` | no (Qt too old) | not yet |
| RHEL 8 and newer, AlmaLinux, Rocky Linux, Fedora | `.rpm` | Fedora: yes; RHEL 8: no | not yet |
| Any other distribution with systemd and nftables | `.tar.gz` | if it has Qt 6.6 | not yet |

Packages are built for 64-bit x86 (x86_64) and for 64-bit ARM (ARM64), the
window included wherever the system has Qt 6.6. The ARM64 packages have not
been checked on a real system yet.

## macOS

Not supported yet; it comes after Linux (see the [roadmap](../../ROADMAP.md)).
