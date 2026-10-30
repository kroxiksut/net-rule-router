# Supported systems

**English** · [Русский](../ru/supported-systems.md)

What the first alpha runs on, in which variant, how it is delivered there, and
which systems it has actually been run on.

Every system gets one of two variants:

- **full** — the window and the tray, the background service, the `nrr-cli`
  console and the `nrr-tui` terminal interface;
- **without the window** — the service, `nrr-cli` and `nrr-tui`, which covers
  the same features from a terminal.

The "Checked" column says how we know it works:

- **on a machine** — installed, used with real rules and removed again on that
  system;
- **by documentation** — compatible according to the distribution's own
  documentation and package repositories; we do not keep a test machine for it;
- **not yet** — should work for the reasons given, and a check on a real
  system is planned.

If you run it somewhere not checked on a machine, a word on how it went helps
more than anything else: in an
[issue](https://github.com/kroxiksut/net-rule-router/issues) or in the
Telegram channel [t.me/netrulerouter](https://t.me/netrulerouter).

## Windows

| System | Architecture | Variant | Delivered as | Checked |
|---|---|---|---|---|
| Windows 11 | x64 | full, or without the window | portable ZIP, EXE installer, MSI | full: on a machine |
| Windows 10 | x64 | full, or without the window | portable ZIP, EXE installer, MSI | full: on a machine |
| Windows 11 on ARM | ARM64 | full, or without the window | portable ZIP | not yet |
| 32-bit Windows | x86 | not supported | — | — |

Installing the background service takes administrator rights once; everyday
use does not.

## Linux

The service needs **systemd** and **nftables**, as every current mainstream
distribution has. Each signed-in user gets their own rules on Linux 4.10 and
newer; an older kernel applies one user's rules for everybody. The window
needs **Qt 6.6 or newer** from the system; where the system has an older Qt,
the service, the `nrr-cli` console and the `nrr-tui` terminal interface work
without it.

| System | Architecture | Variant | Delivered as | Checked |
|---|---|---|---|---|
| Ubuntu 24.10 and newer | x86_64, ARM64 | full | `.deb` | Ubuntu 26.04 LTS: on a machine |
| Ubuntu 22.04, 24.04 | x86_64, ARM64 | without the window (Qt too old) | `.deb` | not yet |
| Debian 13 | x86_64, ARM64 | full | `.deb` | not yet |
| Debian 11, 12 | x86_64, ARM64 | without the window (Qt too old) | `.deb` | not yet |
| Astra Linux 1.8 | x86_64 | full | `.deb` | without the window: on a machine |
| Astra Linux 1.7 | x86_64 | without the window (Qt too old) | `.deb` | on a machine |
| RED OS 8 | x86_64 | full if its Qt is 6.6 or newer | `.rpm` | without the window: on a machine |
| RED OS 7.3 | x86_64 | without the window (Qt too old) | `.rpm` | not yet |
| Fedora | x86_64, ARM64 | full | `.rpm` | not yet |
| RHEL 10, AlmaLinux 10, Rocky Linux 10 | x86_64, ARM64 | full | `.rpm` | by documentation |
| RHEL 8 and 9, AlmaLinux 8 and 9, Rocky Linux 8 and 9 | x86_64, ARM64 | without the window | `.rpm` | by documentation |
| openSUSE Tumbleweed, openSUSE Leap 16 | x86_64, ARM64 | full | `.tar.gz` | by documentation |
| openSUSE Leap 15.6 | x86_64, ARM64 | without the window | `.tar.gz` | by documentation |
| ALT p10, p11 | x86_64, ARM64 | full if its Qt is 6.6 or newer | `.tar.gz` | not yet |
| Any other distribution with systemd and nftables | x86_64, ARM64 | full if its Qt is 6.6 or newer | `.tar.gz` | not yet |

Where the system's Qt is older than 6.6, the package manager refuses the
window's package and names what is missing; install a newer Qt from your
distribution, or keep the variant without the window (see
[Linux packages](packaging-linux.md)). For ARM64 the release carries the
`.tar.gz` archives only, full and without the window; `.deb` and `.rpm`
packages for ARM64 come later. No ARM64 build has been checked on a real system
yet; every "on a machine" above is x86_64.

## macOS

Not supported yet; it comes after Linux (see the [roadmap](../../ROADMAP.md)).
