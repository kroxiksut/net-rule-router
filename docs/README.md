# NetRuleRouter — Documentation

**English** · [Русский](README.ru.md)

## Guides

| Document | What's inside |
|----------|---------------|
| [Quick start](en/quickstart.md) | Download, install, set up your first rules |
| [Building from source — Windows](en/building-windows.md) | What to install (Rust, Qt, CMake…) and how to build |
| [Packaging a portable build — Windows](en/packaging-windows.md) | Making a folder that runs on a clean machine, and what the build stamp records |
| Building from source — Linux | *will arrive together with Linux support* |
| [Rules format](en/rules-file-format.md) | Rule syntax for humans, with examples |
| [Where NetRuleRouter keeps its files](en/where-files-live.md) | What lives in `ProgramData`, `AppData` and `%TEMP%`, what survives a reinstall, and what is safe to delete |
| [Diagnostic archive](en/diagnostic-archive.md) | What the "Export diagnostic archive" button collects, file by file |
| [Recovering network access](en/recovering-network-access.md) | What to do if an abnormal service stop left the network or DNS blocked |
| [The `nrr-cli` console](en/cli.md) | Managing and checking the background service from a terminal: verbs, exit codes, and where the boundary with the app is |
| [Browser error pages when a site is blocked](en/blocked-site-browser-errors.md) | Why the browser shows "can't provide a secure connection" on blocked sites, and why that is correct |
| [DNS through the tunnel](en/dns-via-secondary.md) | Why a site can fail to load even when routing is correct, and how sending DNS through the tunnel fixes it |
| [Per-site routing with virtual addresses (fake-IP)](en/fake-ip.md) | What fake-IP gives you, what it needs, its limits, and how to turn it on |
| [Routing modes: what each switch does, and how to combine them](en/routing-modes.md) | The five routing switches side by side — what each buys you, what it costs, and which combinations are worth turning on together |
| [VPN client detection](en/vpn-detection.md) | Which VPN clients are recognized, and how to add yours (PR / issue / email) |
| [Third-party components](en/third-party-components.md) | What is shipped from other authors, under which licence, and how to check it is genuine |
| [End-user license agreement](legal/eula.en.md) | EULA: terms of use and pre-alpha risk warnings |

## Repository-level docs

| File | What's inside |
|------|---------------|
| [`README.md`](../README.md) | Project overview |
| [`SECURITY.md`](../SECURITY.md) | Security model & trust boundaries |
| [`STRUCTURE.md`](../STRUCTURE.md) | Repository layout |

---

All language trees are kept in sync — when editing a document, update its
counterparts in the same change.
