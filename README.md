<div align="center">

<img src="assets/icons/app/icon-128.png" alt="NetRuleRouter" width="96" height="96" />

# NetRuleRouter

**Decide which traffic goes through which connection — by domain, IP, or app.**

A Windows-first network policy manager that routes your traffic across the
interfaces you *already have*: primary internet, a VPN, a second provider, Wi-Fi,
Ethernet. No tunnel of its own, no cloud, no account.

[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](#license)
![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6.svg)
![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange.svg)

[Russian version → README_RU.md](README_RU.md)

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

## What it is *not*

It is **not** a VPN client, an anonymity tool, a censorship-bypass tool, a proxy
manager, or a cloud service. It manages routing across the connections you set up
yourself — it doesn't create or hide them.

## Highlights

- 🧭 **Two-route model (Free)** — a `primary` and a `secondary` route, one active config at a time.
- 🎯 **Three ways to match traffic** — by domain (label + all subdomains), by exact IPv4, or by application (Windows process name).
- 🔒 **Fail-Closed** — if `secondary` goes down, matching traffic is held rather than silently leaking to `primary`.
- 🔍 **Explain mode** — ask *"why did this host go where it went?"* and get the exact rule trace. A local SQLite cache backs FQDN/IP mapping.
- 📦 **Open, text-based presets** — human-readable rule packs (incl. ready-made country splits) you can diff, edit, and share.
- 🪟 **Native desktop app** — a Qt/QML GUI plus a tray for daily control, and a Windows service that applies policy at startup.
- ♿ **Accessibility as a baseline** — screen-reader support, keyboard navigation, scalable fonts, a dedicated high-contrast theme.
- 🌐 **RU / EN out of the box**, with drop-in community locales (no rebuild needed).
- 🛡️ **Local-first & private** — no mandatory login, telemetry off by default, no hidden background network calls.

## How routing decisions are made

For each destination the engine walks rules from most specific to least specific
and stops at the first match:

| # | Rule type | Example | Tier |
|---|-----------|---------|------|
| 1 | Exact domain (FQDN) | `api.bank.com` | Free |
| 2 | Subdomain / suffix | `*.bank.com` | Free |
| 3 | Zone (TLD / internal suffix) | `.ru`, `.com`, `.intra` | Free (domain zones) |
| 4 | Exact IPv4 address | `203.0.113.7` | Free |
| 5 | Application (process name) | `chrome.exe` | Free |
| 6 | Default route | behavior: prefer-primary / prefer-secondary / strict-fail-closed | — |

Notes:

- The **Exact-IP vs Zone** order is configurable (by default a more specific exact IP wins over a zone).
- A rule may combine an address match **and** an app match — both must hold (logical **AND**).
- **IPv6, CIDR subnets, IP ranges, ports, and protocols are Pro-edition** features.
- The decision engine is pure and deterministic: identical inputs always produce identical, fully-traceable outputs.

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

The full format is documented in [`FORMATS.md`](FORMATS.md).

> The bundled country presets are AI-authored drafts meant as a convenient
> starting point, not authoritative routing advice — review and adapt them
> before relying on them.

## Build from source

> Windows-first; macOS and Linux are planned once the Windows baseline is stable.

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

Quality gate (fmt + clippy + tests + license/dependency audit):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

## Configuration & data

- **UI preferences** (theme, language, accessibility, route labels, last section…) live in managed local storage and survive updates.
- **Active config** — one at a time in Free; rules live in the two plain-text preset files.
- **Caches & state** — local SQLite (`nrr_fqdn_ip_cache.db`, `nrr_service_state.db`); audit and operational logs as NDJSON.
- Locale files are read at runtime; drop a schema-valid `de.json` into the user locales dir and it appears in the language picker — no new release required.

## Security & privacy

- No mandatory login for core local routing.
- Telemetry is **off by default**; no hidden background network actions.
- Privileged policy changes go over a local, DACL-protected named-pipe IPC boundary — there is no localhost HTTP control plane for privileged mutations.
- Update checks (Free) are user-initiated, use only official sources, and can never silently install, apply, or change routing behavior.

See [`SECURITY.md`](SECURITY.md) for the full trust model.

## Roadmap

**Free (current):** two-route model, one active config, domain / exact-IP / app
rules, presets, explain mode, Fail-Closed, RU/EN.

**Pro (planned):** multiple saved profiles and scenario libraries, 2+N adapters,
richer rule types (IPv6, CIDR, ports, protocols), per-site / per-app routing across
3+ routes, and automated switching. Pro imports Free configs as a starting point;
the desktop UI stays a native Qt app in both editions.

## Documentation

| File | What's in it |
|------|--------------|
| [`SECURITY.md`](SECURITY.md) | Security model & trust boundaries |
| [`STRUCTURE.md`](STRUCTURE.md) | Repository layout |
| [`FORMATS.md`](FORMATS.md) | Preset & rule file format |

## License

NetRuleRouter is licensed under **MPL-2.0**.

It is designed to be usable both as a standalone application and as an embeddable
first-layer routing component inside other products — contributions and
integrations are welcome. If your product uses NetRuleRouter, please credit it and
link back to the project. All runtime dependencies must remain compatible with
commercial distribution (MIT / Apache-2.0 / BSD / MPL-2.0 / ISC); dependencies with
unclear licensing are not approved by default.

*(The full license text is not yet bundled in this repository.)*

---

<div align="center">
<sub><code>README.md</code> and <code>README_RU.md</code> are kept in sync — update both in the same change.</sub>
</div>
