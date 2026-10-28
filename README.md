<div align="center">

<img src="assets/icons/app/icon-128.png" alt="NetRuleRouter" width="96" height="96" />

# NetRuleRouter

**Send each site, address, subnet, range or program over the connection you choose, deny what must not go out, and hold traffic back when the VPN drops instead of leaking it.**

A desktop network policy manager that routes your traffic across the
interfaces you *already have*: primary internet, a VPN, a second provider, Wi-Fi,
Ethernet. No tunnel of its own, no cloud, no account.

Windows builds today; Linux is in progress, macOS next.

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](#license)
[![windows-quality](https://github.com/kroxiksut/net-rule-router/actions/workflows/windows-quality.yml/badge.svg?branch=main)](https://github.com/kroxiksut/net-rule-router/actions/workflows/windows-quality.yml)
[![linux-quality](https://github.com/kroxiksut/net-rule-router/actions/workflows/linux-quality.yml/badge.svg?branch=main)](https://github.com/kroxiksut/net-rule-router/actions/workflows/linux-quality.yml)
![Rust](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkroxiksut%2Fnet-rule-router%2Fmain%2Frust-toolchain.toml&query=%24.toolchain.channel&label=rust&color=orange)
![Platform: Windows, Linux in progress](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20(in%20progress)-0078D6.svg)
![Languages: English, Russian](https://img.shields.io/badge/languages-EN%20%7C%20RU-informational.svg)
[![GUI: Qt 6 / QML](https://img.shields.io/badge/GUI-Qt%206%20%2F%20QML-41CD52.svg)](#quick-start)
[![TUI: ratatui](https://img.shields.io/badge/TUI-ratatui-8A2BE2.svg)](#terminal-interface)
[![CLI: nrr-cli](https://img.shields.io/badge/CLI-nrr--cli-555555.svg)](#administrative-console)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-red.svg)

**English** · [Русский](README_RU.md)

<img src="docs/en/images/rules.png" alt="Rules: each rule names what it matches and which route it takes" width="900" />

</div>

---

## What it is

NetRuleRouter lets you say *"send `*.bank.com` and this one app over my primary
line, send everything else over the VPN"* — and have that policy enforced
predictably, locally, with a clear audit trail of every decision.

Typical setups:

- **Primary internet + VPN** — keep latency-sensitive or geo-locked services on the direct line, route the rest through the VPN.
- **Provider A + Provider B** — split traffic across two uplinks.
- **Wi-Fi + Ethernet / Wi-Fi + VPN** — pin specific destinations to a specific interface.
- **Any adapter Windows can see** works as the additional route — including USB network gadgets (RNDIS/ECM boards, phone tethering), Bluetooth PAN, or a virtual-machine adapter set aside for development and testing.

## What it is *not*

It is **not** a VPN client, an anonymity tool, a censorship-bypass tool, a proxy
manager, or a cloud service. It manages routing across the connections you set up
yourself — it doesn't create or hide them.

## Quick start

1. **Unpack and run.** Unpack the archive anywhere — Desktop, the root of a
   drive, a USB stick — start `NetRuleRouter.exe` and accept the licence
   agreement. Ready-made archives are not published yet; `scripts/package-windows.ps1`
   builds one that runs on a machine without Qt or Rust (see
   [Build from source](#build-from-source)).
2. **Install the background service.** The welcome window offers *"Install and
   start the service"* — confirm the UAC prompt. Without the service the app
   runs in preview mode: rules can be edited, but nothing is applied.
3. **Pick a starting rule set.** The first-run wizard offers a country preset,
   a built-in demo set, two `.txt` files of your own, or an empty start.
4. **Assign the two routes.** On the *Interfaces & routes* screen say which
   adapter is the main route and which is the additional one (your VPN, a
   second provider, a second Wi-Fi), and where traffic matching no rule goes.
5. **Save the set as your own** — *Settings → Presets & settings → My rule
   sets*: point it at a folder of your own, then *"Save current rules as a
   set"*. Sets that stay in the application folder are replaced by the next
   update; a set in your own folder survives it.
6. **Add your own sites** (see the note below), then press **Apply** — rules
   take effect only once applied.

> **One-time step after installation.** The service routes exactly what the
> rules say and nothing else. Sites that used to open for you over the VPN
> will keep going out over the main connection until they appear in the rules
> of the additional route — a preset cannot know your personal
> list. Go through the sites you care about and add them yourself: in the
> **Rules** section of the app, or straight into `rules_secondary.txt` in your
> rule-set folder. Then press **Apply**. You do this once — from then on the
> list travels with your rule set.

The full walkthrough, including what to do if you lose network access, is in
[`docs/en/quickstart.md`](docs/en/quickstart.md). Which Windows and Linux
versions it runs on, and which have been checked, is in
[`docs/en/supported-systems.md`](docs/en/supported-systems.md).

## Verifying a download

The installers and archives are not code-signed yet, so Windows may warn the
first time one starts. For every file of a release GitHub keeps a record of
the build and the commit it came from, so you can confirm that the file you
downloaded is exactly what this repository's release build produced, without
trusting the page you downloaded it from:

```sh
gh attestation verify <file> --repo kroxiksut/net-rule-router
```

This needs the GitHub CLI (`gh`), signed in with `gh auth login`. A file
changed after the build, or built anywhere else, fails the check. For a quick
check of the checksums, `SHA256SUMS` comes with the files:
`sha256sum -c SHA256SUMS` (in PowerShell, compare with `Get-FileHash <file>`).

## Highlights

- **Two-route model** — a `primary` and an additional route, one active config at a time.
- **Seven ways to match traffic** — by exact domain, by domain with all its subdomains, by a site in every zone (`bank.*`), by exact IPv4 or IPv6 address, by subnet or address range, by domain zone (a TLD or internal suffix such as `.ru` or `.intra`), or by application (the program's name, or the file or folder it is installed in; on Windows and Linux a folder rule also covers the programs a later update puts there and the scripts kept in it).
- **Traffic statistics** — how much went through each connection today, during the current session of the additional connection and over every day kept (you choose how many), with a CSV export for any period.
- **Per-name routing** *(Windows, on by default for a new installation: Settings → Routing behavior, whatever leak protection is set to)* — sites that share one server address still go where their own rule says. Large platforms and CDNs put hundreds of names on a handful of addresses, and address-level routing cannot tell them apart; see [`docs/en/routing-modes.md`](docs/en/routing-modes.md).
- **Leak protection** — one choice: **Off** (the default), **Routed sites** (what your rules send through the additional connection never goes out the main one while strict blocking of shared addresses is on, as it is by default; everything else keeps working, except sites that share an address with a routed one) or **Everything** (nothing leaves except through the additional connection, your local network and what your rules send over the main one; if the additional connection drops, the internet waits until it returns). A corporate VPN beside yours keeps its own networks in every mode.
- **Deny** — a site, an address, a subnet or a program you deny is not let through any connection: put `!` before it in a rules file, or choose "Deny" when you add a rule in the window, the tray or the terminal interface. A deny by address or subnet does not depend on names; there are no block lists, only the rules you write.
- **Protected system programs** — a deny or an additional-route rule cannot take what the computer needs to stay on the network (the system folder, `svchost.exe`, the network services, a folder many programs share): the app refuses it before it is saved. When you do mean it, `+override` in the rules file asks for your confirmation, for a time you choose, with administrator approval where it reaches past your own programs; see [`docs/en/rules-file-format.md`](docs/en/rules-file-format.md#116-applying-a-rule-despite-the-protection-override).
- **Many rules at once, and recent changes** — paste a list of sites, addresses and programs as lines of a rules file and each line is checked before it is added; the *Recent* filter shows what you added, changed or deleted in the last hour, today or 7 days, and puts a deleted rule back in one click. In the window and in the terminal interface alike.
- **Connection history** — which of your programs connected where, and over which route, kept on this computer for 7 days unless you choose otherwise, grouped by program or by folder. Only you can read yours; it never goes into a diagnostic archive, and you can clear it or switch it off in Settings.
- **Check site** — when a site does not open, one check tells whether the network or the site is at fault: which route the site, its sign-in and the names seen with it take, and whether each of them answers there, with what to do next. Run it from Diagnostics, from a line of the connection trace, from a suggestion or from the notice itself, in the window and in the terminal interface.
- **Notices that point at the cause** — the tray and the terminal interface tell you when a site you open does not open over the main connection (on Windows even with the tray closed), when the main or the additional connection keeps dropping, and when the service stops on its own (this one the window shows too), with **Start service** and **Restore network** at hand. Any kind of notice can be hidden for a day, 7 days, 30 days or for good, and what you hide is hidden everywhere.
- **Rules off for a while** — turn your routing and leak protection off for 15 minutes, an hour, 4 hours, until the next restart or until you turn them back on (*Turn off rules…* in the tray, or Settings). They come back on their own, and the other people signed in keep their rules.
- **WSL, containers and virtual machines** — you choose whether their programs get the same leak protection as this computer or go unprotected while the additional route is down. Not yet verified on a live setup.
- **Suggested addresses** — a routed site often pulls in helper domains of its own. The app collects them, shows which of your sites needs each one, and proposes adding them. Nothing is added behind your back, and ignoring a suggestion simply leaves that address on the main route.
- **Overlaps** — when rules of the two routes cover the same sites (a zone on one route, a site inside it on the other), the narrower rule wins, and the app lists every such pair with the route its sites actually take. Confirm each one, or send those sites over the other route in one click. The same screen points out applied rules that work
  differently from how they read — for example an address deny that also
  stops a site you route.
- **Explain mode** — ask *"why did this host go where it went?"* and get the exact rule trace. A local SQLite cache backs FQDN/IP mapping.
- **Open, text-based presets** — human-readable rule packs (incl. ready-made country splits) you can diff, edit, and share.
- **Rules that adapt to your provider** — put `?` before a site or an address (or tick "Unsure" when you add one) and it works over the route you wrote it for. If it does not open there but opens over the other route, the app sends it over the other route and offers to move the rule; until you agree, the move lasts until the computer restarts. The bundled presets use this for services some providers block and others do not, so one pack fits any provider.
- **Native desktop app** — a Qt/QML GUI plus a tray for daily control, and a background service that applies policy at startup. The tray menu and its notices are still being shaped ahead of the first release; what they contain and how they look may change between builds.
- **Accessibility as a baseline** — screen-reader support, keyboard navigation, scalable fonts, a dedicated high-contrast theme; see [`docs/en/accessibility.md`](docs/en/accessibility.md).
- **RU / EN out of the box**, with drop-in community locales (no rebuild needed).
- **Local-first & private** — no mandatory login and no telemetry. The few requests the app makes of its own (looking up the sites your rules name, checking the additional connection and the address it exits from, trying the `?` rules of sites you open, an optional update check) are listed in [SECURITY.md](SECURITY.md), with what each one gives you and how to turn it off where it can be.

## How routing decisions are made

For each destination the engine walks rules from most specific to least specific
and stops at the first match:

| # | Rule type | Example |
|---|-----------|---------|
| 1 | Exact domain (FQDN) | `api.bank.com` |
| 2 | Subdomain / suffix | `*.bank.com` |
| 3 | Site in every zone | `bank.*` |
| 4 | Exact IP address (IPv4 or IPv6) | `203.0.113.7`, `2001:db8::7` |
| 5 | Subnet (CIDR) or IP range | `10.0.0.0/8`, `192.0.2.10-192.0.2.40` |
| 6 | Zone (TLD / internal suffix, domain zones) | `.ru`, `.com`, `.intra` |
| 7 | Application (program name, file or folder) | `chrome.exe` |
| 8 | Default route | the main connection or the additional one, as chosen in settings |

Notes:

- The narrower rule wins: a site's own name beats its address, an **exact IP**
  beats any network containing it, a network beats the zone it sits in.
  Between two names the longer one wins, between two networks the more
  specific one.
- A zone of several labels (`corp.example.com`) names one site's subdomains:
  it ranks with the subdomain rules, without the bare name itself, so it beats
  `*.example.com`, an exact IP and a network.
- A **site in every zone** (`bank.*`) covers `bank.com`, `bank.net`,
  `bank.co.uk` and their subdomains with one rule. A rule that names the zone
  (`bank.by`, `*.bank.by`) beats it, whichever route either sends the site to.
- A **deny** of an exact IP address stops that address whatever other rule
  names it. Any other deny takes its place in the order above.
- When two rules of the same kind are equally specific, a deny wins over a
  route, and the main route over the additional one.
- A rule names a destination **or** an application. A rule that limits an
  address to one application cannot be carried out yet, so the service refuses
  it rather than applying it to every application.
- **CIDR subnets and IP ranges** work as destinations: route a whole corporate
  network or a block of addresses through either connection with one rule.
  Ports and protocols are not supported.
- IPv6 addresses work in rules. They travel the additional connection when it
  carries IPv6. When it does not, an IPv6 address your rules send there is held
  back rather than slipping out over the main one while leak protection is on;
  with leak protection off it goes over the main connection. IPv6 has not been tested on a real IPv6 network yet. After
  a rule change, connections already open over IPv6 keep their old route until
  the program reconnects (over IPv4 the app refreshes them), and a `?` on an
  IPv6 address never moves the rule.
- The decision engine is pure and deterministic: identical inputs always produce identical, fully-traceable outputs.

> A destination that matches no rule takes the default route — so a site
> belongs in the rules of the additional route if that is where
> you want it to go; see the one-time step in [Quick start](#quick-start).
> **After adding or removing rules, always press Apply: rules take effect only
> once applied.**

Everything else that can disagree — several people signed in, the protection
and a pause, your rules file and the app — is settled in
[`docs/en/what-takes-priority.md`](docs/en/what-takes-priority.md).

## Presets

`presets/` ships open, text-based rule packs you can import as a starting point —
including country-based "domestic vs. abroad" splits for several regions
(`ru`, `cn`, `ir`, `tr`, `in`, `id`, `vn`, `kz`, and more). Each pack is two plain
files, `rules_primary.txt` / `rules_secondary.txt`, with metadata in header comments:

```text
# NetRuleRouter preset - version 1
# name: CN Mainland Split - Primary Route
# preset_version: 1

--- Zones
cn              # .cn

--- Domains
qq.com
*.qq.com
alibaba.com
*.alibaba.com
```

Lines marked with `?` (for example `?accounts.google.com`) work over the route
of their file; where your provider blocks them there and the other route opens
them, the app offers to move them. The full format is documented in
[`docs/en/rules-file-format.md`](docs/en/rules-file-format.md).

> The bundled country presets are AI-authored drafts meant as a convenient
> starting point, not authoritative routing advice — review and adapt them
> before relying on them.

## Build from source

> The commands below are for Windows. Every script has a `*.sh` counterpart
> for Linux, where the port is in progress and not release-tested yet; macOS
> comes after it.

**Prerequisites:** a recent Rust toolchain, a Qt 6 development install, and CMake.
`scripts/bootstrap.ps1` checks the environment and prepares your `.env`.

```powershell
# 1. Bootstrap prerequisites and .env
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1

# 2. Build the launcher + native Qt host
cargo build -p nrr-launcher -p nrr-qt-host

# 3. Run
.\target\debug\NetRuleRouter.exe          # main GUI
.\target\debug\NetRuleRouterTray.exe      # tray

# …or via the helper script
.\scripts\run.ps1 -Component gui
.\scripts\run.ps1 -Component tray
```

The background service (applies and enforces policy on startup) is installed with
`scripts/install-service.ps1` and removed with `scripts/uninstall-service.ps1`.

To leave nothing behind — service, settings, caches and logs in one go —
`scripts/purge-data.ps1` removes every place the product writes to. It only
lists what it would delete until you pass `-Yes`, and it keeps the security
audit trail unless you also pass `-PurgeAudit`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1
```

Quality gate (fmt + clippy + tests + license/dependency audit):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

### Preparing a build for distribution

`scripts/package-windows.ps1` turns the checkout into a folder that runs on a
clean Windows machine — no Qt, no Rust toolchain, no repository, no installer:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1 -Zip
```

The package lands in `C:\temp\NetRuleRouter\dist\NetRuleRouter`; `-Zip` puts
`NetRuleRouter-windows-x64-<version>+<commit>.zip` beside it. It carries the
GUI, tray, service, console, terminal interface, the Qt runtime, and the QML / locale / preset /
config tree, plus a `build-info.json` stamp (version, revision, build time)
and short `README.txt` / `README.ru.txt` notes for whoever unpacks it.
Parameters and layout:
[`docs/en/packaging-windows.md`](docs/en/packaging-windows.md).

## Configuration & data

- **UI preferences** (theme, language, accessibility, route labels, last section…) live in managed local storage and survive updates.
- **Active config** — one at a time, **per Windows user**: your daily rule edits are your own (no administrator prompt) and apply only to you, while an administrator can set a shared **baseline** that every user falls back to until they customize. "Reset to baseline" drops your changes. Rules live in the two plain-text preset files.
- **Caches & state** — local SQLite (`nrr_fqdn_ip_cache.db`, `nrr_service_state.db`); audit and operational logs as NDJSON. See [`docs/en/cache-and-seeding.md`](docs/en/cache-and-seeding.md) for how the FQDN/IP cache fills up, including opt-in browser-history seeding. These databases are for the app to manage — editing them with third-party tools is unsupported and at your own risk; see [`docs/en/where-files-live.md`](docs/en/where-files-live.md).
- Locale files are read at runtime; drop a schema-valid `de.json` into the user locales dir and it appears in the language picker — no new release required.

## Administrative console

A terminal console (`nrr-cli`) ships with the app. It installs, starts, stops
and inspects the background service, and `diag doctor` prints one report you can
paste into a bug instead of three screenshots. Routing policy stays in the app —
the console never edits or applies rules and has no machine-readable output, so
it is a way to keep one machine healthy, not an automation API. See
[`docs/en/cli.md`](docs/en/cli.md).

## Terminal interface

`nrr-tui` is the application in a terminal: status and notifications, setup,
rules, suggestions, connection history, the site check, diagnostics and
settings for a machine reached over SSH, a server without a
desktop, or anyone who prefers the keyboard. It works with screen readers
(`--plain`), never relies on colour alone, and needs no administrator rights
for your own rules. It runs only interactively — scripts use `nrr-cli`. See
[`docs/en/tui.md`](docs/en/tui.md).

## Security & privacy

- No mandatory login for core local routing.
- There is no telemetry. Besides your routed traffic, the app looks up the host names in your rules and keeps their addresses fresh, asks your connection's DNS server which site an address belongs to while rule suggestions or leak protection are on (never for a site your own deny rule blocks), checks that the additional connection is alive and, if you turn it on, asks a public STUN service which address it exits from each time it connects, tries the `?` rules of sites you open, and (after the first release) can check for a newer version. With suggestions and leak protection off there are no such address lookups; the update check can be turned off in Settings. The full list is in [SECURITY.md](SECURITY.md).
- Privileged policy changes go over a local, DACL-protected named-pipe IPC boundary — there is no localhost HTTP control plane for privileged mutations.
- Until the first release is published the app does not check for updates at all. From then on, every N days (14 by default, adjustable in Settings) it asks the project's official release page whether a newer version is out and, if so, shows a notice. It never downloads, installs or changes routing, and you can turn the check off in Settings. Help → Check for updates asks the same question on demand, even with the automatic check off.

See [`SECURITY.md`](SECURITY.md) for the full trust model.

## Roadmap

**Current:** two-route model, one active config per Windows user over a shared
administrator baseline, domain / zone / IP / network / app rules (apps by name,
file or folder), deny rules, per-name routing, presets, explain mode, leak protection, suggested addresses, traffic
statistics with CSV export, connection history, site check, timed pause of the rules, diagnostics archive, administrative console, terminal interface, RU/EN.

**In progress:** Linux support (the platform-specific pieces sit behind one
interface per capability, so the shared decision logic is already OS-neutral),
then macOS.

**In progress: full IPv6.** Rules already name IPv6 addresses and names that
resolve to them, and route and protect them as they do IPv4; what remains is
verifying it on real IPv6 networks before calling it finished.

**Right after that:**
- checking a site over both connections: the site check tells you whether the
  server itself is down or your provider or VPN holds it back, and offers to
  move the rule;
- own secure DNS for one program: a program with its own encrypted DNS, such as
  a corporate client or a game, keeps working while protection stays on for
  every other program.

The full order of work, without dates: [ROADMAP.md](ROADMAP.md).

## Documentation

| File | What's in it |
|------|--------------|
| [`SECURITY.md`](SECURITY.md) | Security model & trust boundaries |
| [`STRUCTURE.md`](STRUCTURE.md) | Repository layout |
| [`docs/en/quickstart.md`](docs/en/quickstart.md) | Quick start: from install to the first applied rule |
| [`docs/en/supported-systems.md`](docs/en/supported-systems.md) | Supported Windows and Linux versions, what each gets, and what has been checked |
| [`docs/en/rules-file-format.md`](docs/en/rules-file-format.md) | Preset & rule file format |
| [`docs/en/routing-modes.md`](docs/en/routing-modes.md) | The routing switches: what each one buys you, and how they combine |
| [`docs/en/what-routing-changes.md`](docs/en/what-routing-changes.md) | Who sees what once a site is routed — and what routing deliberately leaves alone |
| [`docs/en/what-takes-priority.md`](docs/en/what-takes-priority.md) | What takes priority: which rule wins, whose rules apply when several people are signed in, the protection and a pause, your rules file and the app |
| [`docs/en/several-users.md`](docs/en/several-users.md) | Several users signed in at once: everyone's rules apply, and the one Windows limitation |
| [`docs/en/blocked-site-browser-errors.md`](docs/en/blocked-site-browser-errors.md) | What a browser error means when a routed site does not open |
| [`docs/en/cache-and-seeding.md`](docs/en/cache-and-seeding.md) | How the FQDN/IP cache fills up, including opt-in browser-history seeding |
| [`docs/en/where-files-live.md`](docs/en/where-files-live.md) | Where settings, rules, caches and logs are stored |
| [`docs/en/diagnostic-archive.md`](docs/en/diagnostic-archive.md) | What goes into a diagnostic archive, and what never does |
| [`docs/en/recovering-network-access.md`](docs/en/recovering-network-access.md) | Getting the network back if something goes wrong |
| [`docs/en/known-limitations.md`](docs/en/known-limitations.md) | Gaps this release still has, and what to do about each |
| [`docs/en/cli.md`](docs/en/cli.md) | The `nrr-cli` console: verbs, exit codes, and what it deliberately does not do |
| [`docs/en/tui.md`](docs/en/tui.md) | The `nrr-tui` terminal interface: starting it, screens, keys, accessibility, rights |
| [`docs/en/accessibility.md`](docs/en/accessibility.md) | Using the window from the keyboard, with a screen reader, large text or high contrast |
| [`docs/en/building-windows.md`](docs/en/building-windows.md) | Building from source on Windows: toolchain, Qt, common failures |
| [`docs/en/unattended-install.md`](docs/en/unattended-install.md) | Installing from a script with your rules ready for every user, and the exit codes |
| [`docs/en/packaging-windows.md`](docs/en/packaging-windows.md) | Producing the portable package and the installers for distribution |
| [`docs/en/building-linux.md`](docs/en/building-linux.md) | Building from source on Linux: toolchain, Qt, common failures |
| [`docs/en/packaging-linux.md`](docs/en/packaging-linux.md) | Producing the `.deb` and `.rpm` packages for distribution |
| [`docs/en/dns-via-secondary.md`](docs/en/dns-via-secondary.md) | DNS through the tunnel: which names go where, and what the resolvers see |
| [`docs/en/fake-ip.md`](docs/en/fake-ip.md) | Per-site routing with virtual addresses: what it buys you and what it needs |
| [`docs/en/vpn-detection.md`](docs/en/vpn-detection.md) | How a VPN client on the machine is recognised, and what the product does about it |
| [`docs/en/first-run-answers.md`](docs/en/first-run-answers.md) | Answering the setup questions ahead of time |
| [`docs/en/third-party-components.md`](docs/en/third-party-components.md) | What third-party components are shipped, under which licences, and how to check them |

## License

NetRuleRouter is licensed under **MPL-2.0**.

It is designed to be usable both as a standalone application and as an embeddable
first-layer routing component inside other products — contributions and
integrations are welcome. If your product uses NetRuleRouter, please credit it and
link back to the project. All runtime dependencies must remain compatible with
commercial distribution (MIT / Apache-2.0 / BSD / MPL-2.0 / ISC); dependencies with
unclear licensing are not approved by default.

The full license text is in [`LICENSE`](LICENSE); the application also shows
it in the License window (Ctrl+Shift+L).

---

<div align="center">
<sub><code>README.md</code> and <code>README_RU.md</code> are kept in sync — update both in the same change.</sub>
</div>
