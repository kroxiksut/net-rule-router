# For advanced users and administrators

**English** · [Русский](../ru/advanced.md)

Everything here is more technical than the [everyday guides](../README.md). You
do not need any of it to use the program.

## Using the program in depth

| Page | What's inside |
|------|---------------|
| [Rules format](rules-file-format.md) | Rule syntax for humans, with examples |
| [What takes priority](what-takes-priority.md) | Which rule wins, whose rules apply when several people are signed in, the protection and a pause |
| [Routing modes](routing-modes.md) | The routing switches side by side, and which combinations are worth turning on together |
| [DNS through the tunnel](dns-via-secondary.md) | Which names are looked up where, with the setting on and off |
| [Per-site routing with virtual addresses](fake-ip.md) | What it gives you, what it needs, its limits |
| [What routing changes, and what it does not](what-routing-changes.md) | Who sees what once a site is routed |
| [Several users on one computer](several-users.md) | Everyone's rules apply, and the one Windows limitation |
| [VPN client detection](vpn-detection.md) | Which VPN clients are recognised, and how to add yours |
| [Living alongside other software](other-software.md) | Antivirus, other VPN clients, firewalls, virtual machines |
| [The site-address cache](cache-and-seeding.md) | How the cache of site addresses fills up, including opt-in browser-history seeding |
| [The terminal interface `nrr-tui`](tui.md) | The program in a terminal: over SSH, on a server, with a screen reader |
| [Accessibility](accessibility.md) | Keyboard, themes including high contrast, text size, screen readers |
| [Known limitations](known-limitations.md) | Gaps this release still has, and what to do about each |
| [Supported systems](supported-systems.md) | Supported Windows and Linux versions and what has been checked |

## Administrators

| Page | What's inside |
|------|---------------|
| [Unattended installation](unattended-install.md) | Installing from a script with your rules ready for every user, and the exit codes |
| [Answering the setup questions ahead of time](first-run-answers.md) | Supplying the first-run answers in a file |
| [The `nrr-cli` console](cli.md) | Managing and checking the background service from a terminal |
| [Diagnostic archive](diagnostic-archive.md) | What "Diagnostic archive export" collects, file by file |
| [Where NetRuleRouter keeps its files](where-files-live.md) | What lives where, what survives a reinstall, what is safe to delete |

## Building and packaging

| Page | What's inside |
|------|---------------|
| [Building from source: Windows](building-windows.md) | What to install and how to build |
| [Packaging: Windows](packaging-windows.md) | A folder that runs on a clean machine, the EXE and MSI installers |
| [Building from source: Linux](building-linux.md) | Prerequisites, the build and install scripts, the quality gate |
| [Packaging: Linux](packaging-linux.md) | Building `.deb`, `.rpm` and `.tar.gz` packages |
| [Third-party components](third-party-components.md) | What is shipped from other authors, under which licence |
| [End-user license agreement](../legal/eula.en.md) | Terms of use and alpha risk warnings |

## Repository-level documents

| File | What's inside |
|------|---------------|
| [`README.md`](../../README.md) | Project overview |
| [`SECURITY.md`](../../SECURITY.md) | Security model and trust boundaries |
| [`STRUCTURE.md`](../../STRUCTURE.md) | Repository layout |

[Back to the everyday guides](../README.md)
