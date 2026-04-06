# AI Context

## Language and Purpose

This file is intended for the AI assistant and is maintained in English by default.
The parallel human-facing Russian version is stored in `AI_CONTEXT_RU.md`.

## Product

NetRuleRouter is a Windows-first network policy and traffic routing manager.

The product is not positioned as:
- a VPN client
- an anonymity tool
- a censorship bypass tool
- a proxy manager
- a cloud-first solution

Core positioning:
- a network policy manager for Windows
- a tool that controls traffic routing across already existing network interfaces

Operational baseline:
- the product should have a Windows system tray presence for everyday control and status visibility
- the background component should start with Windows as a service
- routing enforcement should not depend on the main GUI window being open

## Technology Direction

- The product should primarily use `Rust` for core logic.
- `Qt` is the primary desktop GUI stack.
- Business logic, rule engine, system integration, configuration, cache, and diagnostics should live in Rust wherever practical instead of being duplicated in the GUI layer.
- The GUI layer should stay as thin as possible and focus on presentation, user interaction, and calling into the core layer.
- The boundary between Rust and Qt should remain explicit, narrow, and maintainable.
- The tray application and the background service should be treated as separate responsibilities even if they are closely integrated.

## Free Version Model

- Support exactly 2 active routes: `primary` and `secondary`.
- The user works with one active configuration at a time.
- Routing rules support:
  - applications
  - FQDN
  - subdomains
  - individual IP addresses
- Matching priority is fixed by the spec:
  1. exact FQDN
  2. subdomain / suffix
  3. exact IP
  4. application
  5. default route
- If `secondary` is unavailable, behavior is Fail-Closed.
- A local SQLite cache is required for explain mode and FQDN/IP mapping.
- Presets must be open, text-based, and primarily YAML.
- The product should support at least RU and EN localization.

## Free / Pro Boundary

Free:
- strong manual control within a two-route model
- configuration import/export
- preset import/export
- explain mode
- logs with rotation

Pro:
- 3+ routes
- profiles and scenario libraries
- CIDR, IP ranges, ports, protocols
- richer automation and prioritization
- extended official/community rule packs

## Architectural Priorities

- Windows-first
- local-first operation without mandatory cloud dependencies
- transparent diagnostics
- predictable rule behavior
- safe rollback
- tray-based availability for everyday use
- service-based startup for background operation
- readiness for Pro growth, community presets, and future rule packs

## License

- The codebase is distributed under `MPL-2.0`.
- Do not generate the license text as part of this baseline.
- Dependency choices must account for future commercial distribution of the product.
