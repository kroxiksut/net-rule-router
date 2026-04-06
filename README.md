# NetRuleRouter

English is the default project documentation language for AI-facing files.
The synchronized Russian version of this README is available in `README_RU.md`.

## Overview

NetRuleRouter is a Windows-first network policy and traffic routing manager.

The product is designed to help a user control how traffic is routed across already existing network interfaces such as:
- primary internet + VPN
- provider A + provider B
- Wi-Fi + Ethernet
- Wi-Fi + VPN

NetRuleRouter is not positioned as:
- a VPN client
- an anonymity tool
- a censorship bypass tool
- a proxy manager
- a cloud-first service

## Product Direction

The current product direction fixed in the repository is:
- Windows-first
- local-first
- predictable rule behavior
- transparent diagnostics
- safe rollback
- tray-based daily control
- service-based startup behavior
- strong Free tier with a clear Pro expansion path

## Free Version
The current Free version is centered around:
- exactly 2 active routes: `primary` and `secondary`
- one active configuration at a time
- rules by application
- rules by exact FQDN
- rules by subdomain / suffix
- rules by individual IP address
- local SQLite cache for FQDN/IP mapping and explain mode
- open, text-based presets with YAML as the primary format
- RU and EN localization as baseline languages
- Fail-Closed behavior when `secondary` is unavailable

Recommended rule matching priority:
1. exact FQDN
2. subdomain / suffix
3. exact IP
4. application
5. default route

## Technology Direction

The planned implementation direction is:
- `Rust` for core logic
- `Qt` for desktop GUI

The intended split of responsibilities is:
- Rust for rule engine, system integration, configuration, cache, logging, and diagnostics
- Qt GUI for presentation, user interaction, tray integration, and communication with the Rust core

Business logic should stay in Rust wherever practical. The Rust-to-Qt boundary should stay explicit, narrow, and maintainable.
The product is expected to expose a Windows tray application for everyday control, while the background part starts with Windows as a service.

## Repository Status

The repository is currently documentation-first.

At this stage it contains:
- working documentation
- project structure scaffolding
- AI context and project rules

Implementation code, build scripts, and runnable application entry points are not yet present in the repository.

## Repository Structure

Repository structure is documented in `STRUCTURE.md` and `STRUCTURE_RU.md`.

## Key Documents

- `AI_CONTEXT.md` and `AI_RULES.md` capture the AI-facing working baseline for the project
- `ARCHITECTURE.md` captures the current baseline architecture model
- `SECURITY.md` captures the baseline security model, trust boundaries for policy changes, and update-check expectations
- `STRUCTURE.md` captures the maintained repository structure baseline

## Dependency and License Policy

Code license:
- `MPL-2.0`

Important dependency rule:
- dependencies must remain compatible with future commercial distribution goals
- `Qt Community` modules and all other dependencies must be checked for commercial-use suitability before they are treated as approved
- dependencies with unclear licensing must not be treated as approved by default

The license choice is fixed.
This repository does not yet include the full license text.

## Documentation Sync

`README.md` and `README_RU.md` are intended to stay synchronized.
When one is updated, the other should be updated in the same change set.
