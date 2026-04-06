# Security

English is the default documentation language for AI-facing files.
The synchronized Russian version of this document is available in `SECURITY_RU.md`.

## Purpose

This file captures the baseline security model for NetRuleRouter and should evolve together with the implementation.

Rules for maintaining this file:
- keep it synchronized with `SECURITY_RU.md`
- keep it aligned with `AI_CONTEXT.md`, `AI_RULES.md`, `README.md`, `ARCHITECTURE.md`, and `STRUCTURE.md`
- document stable security decisions, not temporary implementation details

## Security Goals

The baseline security model is designed to:
- prevent silent routing-policy changes
- make policy changes attributable, reviewable, and reversible
- minimize privileged code and privileged writable state
- preserve Fail-Closed behavior when `secondary` is unavailable
- keep routing enforcement independent from the GUI lifecycle

## Threat Model Baseline

The product should defend against:
- untrusted imported profiles and presets
- local processes attempting to change policy through files
- future CLI tools or browser extensions proposing unsafe changes
- unauthorized local clients attempting to talk to the service
- stale, tampered, or poisoned configuration, cache, and diagnostics data
- crashes or partial failures during policy application

The baseline does not promise full protection if an attacker already has full administrative control or fully controls the active interactive user session.
Even then, the product should still make silent policy tampering harder, more visible, and easier to roll back.

## Core Principles

Required principles:
- the Windows service is the only component allowed to own and apply active routing policy
- GUI, CLI, imports, and future browser extensions are request sources, not direct policy owners
- external files are import artifacts, not live active policy
- every accepted change becomes an internal revision with provenance metadata
- risky or non-interactive external-origin changes should require explicit review before activation
- narrow user-initiated flows may activate immediately after service validation and audit logging
- the product should always keep a `last known good` revision for rollback

## Trust Boundaries

### Background Service

The service is the trust anchor for policy enforcement.
It should:
- own the active policy revision
- validate and normalize imported data
- apply routing changes
- record audit events
- verify integrity before loading persisted policy

Avoid `LocalSystem` unless it is proven necessary.
Prefer `LocalService` or a dedicated service identity whenever practical.

### Tray and Main GUI

The tray application and main GUI are user interaction surfaces.
They should:
- present status, diff, diagnostics, and approval workflows
- submit change requests to the service
- avoid owning privileged routing logic

### CLI and Future Browser Extensions

CLI tooling and future browser extensions should be treated as constrained request sources.
They should submit requests through the service and should not write directly to active service-owned policy state.

### External Files

Imported YAML profiles, presets, and future external rule bundles are untrusted input.
They must never be treated as trusted active policy simply because they were selected by path.

## Service Communication Model

The product should not expose a localhost HTTP control plane for privileged operations.
Prefer local Windows IPC such as `Named Pipes` with:
- ACL restrictions
- caller identity verification
- user/session awareness where needed
- explicit separation between read-only methods and state-changing methods

## Policy Data Model

The policy pipeline should use explicit internal entities:
- `ImportedArtifact`: external source metadata, path or reference, file hash, import time, schema result
- `CanonicalProfile`: normalized internal form produced after parsing and validation
- `PolicyRevision`: immutable revision with source, user, timestamp, diff summary, risk level, and integrity metadata
- `PendingRevision`: candidate revision waiting for review or approval when the source is imported, linked, CLI-originated, or otherwise non-interactive
- `ActiveRevision`: currently enforced internal revision
- `AuditEvent`: append-only event such as import, approval, activation, rejection, tamper alert, or rollback

## Import and Change Model

NetRuleRouter should allow user-selected external profile files, but only through controlled import.

### Snapshot Import

`Snapshot import` should be the default model for the initial product version.

Behavior:
- the user selects a profile file
- the GUI submits it to the service
- the service parses, validates, and normalizes it
- the service creates a candidate revision
- the user reviews the diff and confirms activation
- the active policy becomes the internal revision, not the source file

Later changes to the original file must not silently change active behavior.

### Linked Import

`Linked import` may exist as an advanced mode, but must not silently auto-apply changes.

Behavior:
- the user explicitly links a file as an update source
- if the file changes, the service creates a new pending revision
- the user receives a persistent alert and can review the diff
- the active policy remains unchanged until explicit approval

If the linked file changes outside approved product flows, that should be treated as a tamper-relevant event, not as a trusted update.

Imported, linked, CLI-originated, and other non-interactive external changes should create pending revisions by default.
Narrow interactive flows such as an explicit GUI save or a future browser-extension click-to-add site action may create and activate a revision immediately after service validation and audit logging.

## Review and Approval Flow

Before activation, the product should present a clear human-readable diff.
The review should show at least:
- added domains
- removed domains
- route changes for existing entries
- changes to application rules
- changes to default behavior
- the origin channel such as GUI, CLI, import, linked file, or extension

The service should assign a basic risk level to a candidate revision.
Examples:
- low risk: a small number of exact `FQDN` additions
- medium risk: broader wildcard or suffix changes
- high risk: default route changes, mass changes, or rerouting known destinations to `secondary`

High-risk and non-interactive external-origin changes should generate persistent alerts until reviewed.

## External File Change Handling

The product should not rely on file watching as the only security mechanism.
Instead:
- if a snapshot-import source file changes later, inform the user that the source changed but the active policy did not
- if a linked-import source file changes, create a pending revision and require review before activation
- if service-owned persisted state changes unexpectedly, raise a tamper alert and refuse silent activation

The key invariant is that a file change on disk must not automatically become an active routing-policy change.

## Future CLI and Browser Extension Model

Future channels should be allowed only under explicit constraints.

### CLI

CLI should submit requests through the service and should not edit active service-owned policy storage directly.
By default, CLI-originated changes should create pending revisions.

### Browser Extension

A future browser extension may submit an immediate-apply request only when all of the following are true:
- the action is triggered by an explicit user click in the browser
- the user chooses the target profile in the extension flow
- the change is limited to adding the current site's exact hostname or exact `FQDN` to that chosen profile
- the request is sent through the service

The extension must not run background automation or silent synchronization.
Baseline constraints:
- do not generate wildcard or suffix rules by default
- do not generate IP rules by default
- do not change the default route
- do not perform bulk changes without explicit review
- record every accepted extension change as an audit event and surface it in the user-visible history

## Configuration Integrity and Storage

The product should split writable locations by trust level:
- service-owned active policy, revision store, and integrity data under `%ProgramData%` with restrictive ACLs
- user-facing UI preferences under `%LocalAppData%`
- imported files may live anywhere, but must remain external artifacts

The service must not rely on user-writable locations as the source of truth for active policy.

Internal revisions should carry integrity metadata such as a hash or HMAC managed by the service.
If integrity verification fails:
- do not silently load the tampered revision
- fall back to `last known good`
- record an audit event
- alert the user

## Parsing and Validation Rules

All imported profiles and presets must be treated as untrusted input.

Required safeguards:
- use safe parsing only
- require explicit schema versioning
- validate each rule type strictly
- reject unknown or unsupported critical fields
- apply limits on file size, nesting depth, and rule counts
- normalize data before diffing and persistence

Rules by application should not rely only on a bare executable name when a stronger identity is available.
The long-term preferred identity is a normalized executable path, with future room for publisher- or signature-aware verification.

## Enforcement Safety

Policy application should be atomic from the product point of view.
The service should:
- snapshot the relevant current state
- apply the candidate policy
- verify expected post-apply state where possible
- rollback automatically if application or verification fails

Fail-Closed must be implemented as a product invariant, not as best effort.
Traffic associated with `secondary` must not silently fall back to `primary` when that would violate active policy.

## Runtime Hardening

Baseline hardening expectations:
- keep privileged code surface as small as practical
- localize and justify any `unsafe` Rust usage
- restrict DLL and Qt plugin loading to trusted locations
- do not support arbitrary script execution or unrestricted plugin execution in the initial product version
- keep privilege-bearing logic out of the GUI layer

## Logs, Diagnostics, and Cache Safety

Logs and explain output can expose application paths, host names, IP addresses, policy decisions, and connectivity failures.

Baseline rules:
- log the minimum necessary by default
- make verbose diagnostics explicit and time-bounded when practical
- distinguish user-facing diagnostics from security audit events
- store cache freshness metadata, source metadata, and timestamps
- avoid relying on stale or context-free FQDN/IP cache entries

## Free Edition Updates and GitHub Releases

The Free edition may support checking for new versions through official GitHub releases, but this must not weaken the local-first and security model.
Other editions should use their own distribution and update model and should not rely on public GitHub release checks.

Baseline update rules:
- GitHub-based update checks apply only to the Free edition
- update checking must be optional or clearly user-controlled
- update checks must not be required for routing or normal operation
- use only the official GitHub repository or release endpoint configured by the product
- show the exact version, tag, release source, and destination URL before download or install
- do not silently install or execute a downloaded update in the initial product version
- if checksums are published, verify them before presenting the package as valid
- update-check failure must not affect policy enforcement
- avoid unnecessary device-identifying data during update checks

A staged trust model is acceptable:
- baseline: check official release metadata and present it to the user
- stronger future model: signed release manifests, signed application packages, and stronger package verification

## Security-Informed UX

The product should make security-relevant state visible in everyday use.
Examples:
- show the source of the active policy revision
- show whether pending external changes exist
- show when a linked source changed
- keep tamper alerts persistent until reviewed
- provide one-step rollback to the last known good revision

## Baseline Security Invariants

The architecture should preserve these invariants:
1. Active routing policy is always an internal service-owned revision.
2. External file changes never silently become active policy.
3. Privileged routing changes require approved service-mediated flows.
4. `secondary` policy remains Fail-Closed when required by the active rules.
5. A rollback path to a previously valid revision is always available.
6. GitHub update checking in the Free edition cannot silently change routing policy or silently install a new build.

## Recommended Validation Work

Implementation should eventually validate at least these cases:
- tampered imported file
- unexpected change to a linked source
- unauthorized IPC client
- crash during policy apply
- failed integrity verification for a persisted revision
- stale or inconsistent FQDN/IP cache data
- `secondary` route outage with rules that require Fail-Closed
- suspicious bulk import from CLI or a future extension channel

Recommended engineering practices:
- dependency auditing such as `cargo audit`
- dependency and license policy enforcement such as `cargo deny`
- focused tests for import validation and revision diffing
- property or fuzz testing for parsers and rule evaluation inputs

## Evolution Direction

The baseline model intentionally leaves room for stronger trust features later, such as:
- publisher- or signature-aware identity for application rules
- trust levels such as `unsigned external`, `signed community`, and `signed official` for imported profiles
- signed official or community profile bundles
- signed release manifests and signed application packages for updates
- richer per-source approval policies

Those additions should strengthen the same core model rather than replace it:
service-owned active revisions, explicit review flows, strong rollback, and visible provenance.
