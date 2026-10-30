# NetRuleRouter — Documentation

**English** · [Русский](README.ru.md)

## Guides

| Document | What's inside |
|----------|---------------|
| [Quick start](en/quickstart.md) | Download, install, set up your first rules |
| [Supported systems](en/supported-systems.md) | Supported Windows and Linux versions, what each gets, and what has been checked |
| [Unattended installation](en/unattended-install.md) | Installing from a script with your rules ready for every user, and the exit codes |
| [Building from source — Windows](en/building-windows.md) | What to install (Rust, Qt, CMake…) and how to build |
| [Packaging — Windows](en/packaging-windows.md) | Making a folder that runs on a clean machine, the EXE and MSI installers, and what each way of uninstalling keeps |
| [Building from source — Linux](en/building-linux.md) | Prerequisites, the build and install scripts, and the quality gate |
| [Packaging — Linux](en/packaging-linux.md) | Building `.deb`, `.rpm` and `.tar.gz` packages, with and without the GUI, and what installing and removing them does |
| [Rules format](en/rules-file-format.md) | Rule syntax for humans, with examples |
| [What takes priority](en/what-takes-priority.md) | Which rule wins, whose rules apply when several people are signed in, the protection and a pause, your rules file and the app |
| [Several users on one computer](en/several-users.md) | Several users signed in at once: everyone's rules apply, and the one Windows limitation |
| [Answering the setup questions ahead of time](en/first-run-answers.md) | Supplying the first-run answers in a file so the setup window never appears |
| [Where NetRuleRouter keeps its files](en/where-files-live.md) | What lives in `ProgramData`, `AppData` and `%TEMP%`, what survives a reinstall, and what is safe to delete |
| [FQDN/IP cache and how it fills up](en/cache-and-seeding.md) | How the cache of site addresses fills up, including opt-in browser-history seeding |
| [Diagnostic archive](en/diagnostic-archive.md) | What the "Export diagnostic archive" button collects, file by file |
| [Recovering network access](en/recovering-network-access.md) | What to do if an abnormal service stop left the network or DNS blocked |
| [Known limitations](en/known-limitations.md) | Gaps this release still has, and what to do about each |
| [The `nrr-cli` console](en/cli.md) | Managing and checking the background service from a terminal: verbs, exit codes, and where the boundary with the app is |
| [The `nrr-tui` terminal interface](en/tui.md) | The application in a terminal — over SSH, on a server, with a screen reader: starting it, screens, keys, rights |
| [Accessibility](en/accessibility.md) | Keyboard navigation, themes including high contrast, text size and font, screen readers, and what is not there yet |
| [Browser error pages when a site is blocked](en/blocked-site-browser-errors.md) | Why the browser shows "can't provide a secure connection" on blocked sites, and why that is correct |
| [DNS through the tunnel](en/dns-via-secondary.md) | Which names are looked up where, with the setting on and off, and what the resolvers see |
| [Per-site routing with virtual addresses (fake-IP)](en/fake-ip.md) | What fake-IP gives you, what it needs, its limits, and how to turn it on |
| [Routing modes: what each switch does, and how to combine them](en/routing-modes.md) | The five routing switches side by side — what each buys you, what it costs, and which combinations are worth turning on together |
| [What routing changes — and what it does not](en/what-routing-changes.md) | Who sees what once a site is routed, and what routing deliberately leaves alone |
| [VPN client detection](en/vpn-detection.md) | Which VPN clients are recognized, and how to add yours (PR / issue / email) |
| [Living alongside other software](en/other-software.md) | What is known to work next to antivirus, other VPN clients, firewalls and virtual machine software, and what to do |
| [Third-party components](en/third-party-components.md) | What is shipped from other authors, under which licence, and how to check it is genuine |
| [End-user license agreement](legal/eula.en.md) | EULA: terms of use and alpha risk warnings |

## Repository-level docs

| File | What's inside |
|------|---------------|
| [`README.md`](../README.md) | Project overview |
| [`SECURITY.md`](../SECURITY.md) | Security model & trust boundaries |
| [`STRUCTURE.md`](../STRUCTURE.md) | Repository layout |

---

All language trees are kept in sync — when editing a document, update its
counterparts in the same change.
