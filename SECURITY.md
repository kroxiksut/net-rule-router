# Security

## Purpose

This file captures the baseline security model for NetRuleRouter and should evolve together with the implementation.

Rules for maintaining this file:
- keep it aligned with `README.md` and `STRUCTURE.md`
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
- future browser extensions proposing unsafe changes
- unauthorized local clients attempting to talk to the service
- stale, tampered, or poisoned configuration, cache, and diagnostics data
- crashes or partial failures during policy application

The baseline does not promise full protection if an attacker already has full administrative control or fully controls the active interactive user session.
Even then, the product should still make silent policy tampering harder, more visible, and easier to roll back.

## Core Principles

Required principles:
- the Windows service is the only component allowed to own and apply active routing policy
- GUI, imports, and future browser extensions are request sources, not direct policy owners
- external files are import artifacts, not live active policy
- every accepted change becomes an internal revision with provenance metadata
- risky or non-interactive external-origin changes should require explicit review before activation
- narrow user-initiated flows may activate immediately after service validation and audit logging
- the product should always keep a `last known good` revision for rollback

## Security Invariants

These invariants are mandatory for every policy-changing flow:
- Service-owned active revision: only the service can own and switch `ActiveRevision`.
- No silent activation: activation is either explicitly approved by the user or allowed by a narrow documented immediate-apply path.
- Service-mediated changes only: every accepted change must pass service validation and normalization before becoming a revision.
- Last known good always available: rollback to `last known good` must remain possible after failed apply or failed integrity checks.
- Fail-Closed behavior preserved: `secondary`-scoped traffic must not silently degrade to `primary` when that violates active policy.

## Revision Activation Policy

After service validation, revision activation is split into two classes:
- Immediate activation allowed: explicit interactive user actions in trusted product UI flows with narrow scope (for example, direct GUI save or future click-to-add exact site action), followed by audit logging.
- Pending review required: imported, linked, extension-originated, bulk, high-risk, or otherwise non-interactive changes. These changes must create `PendingRevision` and require explicit review before activation.

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

### Future Browser Extensions

Future browser extensions should be treated as constrained request sources.
They should submit requests through the service and should not write directly to active service-owned policy state.

### External Files

Imported YAML profiles, presets, and future external rule bundles are untrusted input.
They must never be treated as trusted active policy simply because they were selected by path.

### Explicit Role Split

Role and ownership boundaries are mandatory and non-overlapping:
- Background service: the only owner of `ActiveRevision`, policy apply logic, integrity checks, and privileged mutations.
- Tray/Main GUI: user-facing surfaces for status, diff, review, diagnostics, and request submission; they do not own or apply active policy directly.
- Other non-privileged local clients (CLI tools, helpers, automation entry points): request-only channels with no direct write access to active service-owned state.
- Future browser extensions and external channels: constrained request sources only; never direct owners of service-owned policy state.
- External files: untrusted artifacts that can produce candidates/pending revisions through the service, but never become live policy by reference.

## Service Communication Model

The product should not expose a localhost HTTP control plane for privileged operations.
Prefer local Windows IPC such as `Named Pipes` with:
- ACL restrictions
- caller identity verification
- user/session awareness where needed
- explicit separation between read-only methods and state-changing methods

### IPC Boundary Rules

The privileged control-plane boundary is fixed by these rules:
- Localhost HTTP is not an allowed transport class for privileged mutations.
- Preferred transport class for privileged operations: local Windows IPC, baseline-oriented to `Named Pipes`.
- Endpoint ACLs must restrict callers to allowed principals only.
- Caller identity must be verified before any mutating operation is accepted.
- User/session context must be checked where operation scope depends on interactive user ownership.
- Read-only methods and mutating methods must be separated at the API contract level (distinct method sets and authorization paths).

## Policy Data Model

The policy pipeline should use explicit internal entities:
- `ImportedArtifact`: external source metadata, path or reference, file hash, import time, schema result
- `CanonicalProfile`: normalized internal form produced after parsing and validation
- `PolicyRevision`: immutable revision with source, user, timestamp, diff summary, risk level, and integrity metadata
- `PendingRevision`: candidate revision waiting for review or approval when the source is imported, linked, extension-originated, or otherwise non-interactive
- `ActiveRevision`: currently enforced internal revision
- `AuditEvent`: append-only event such as import, approval, activation, rejection, tamper alert, or rollback

## Import and Change Model

NetRuleRouter should allow user-selected external profile files, but only through controlled import.

### External Source Trust Classification

Trust boundaries for external policy sources are fixed as follows:
- External files (`.yaml`, presets, bundles): untrusted artifacts only; they can be parsed into candidates but are never treated as live policy.
- Snapshot-import source: one-time input for candidate creation; later source-file edits do not change active policy.
- Linked-import source: monitored external input that can only create `PendingRevision`; source updates never auto-activate.
- Browser-extension channel: constrained request channel only, with explicit user intent and service mediation required.
- Service-owned internal state (`ActiveRevision`, revision store, integrity metadata): trusted control plane owned only by the service and never directly writable by external channels.

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

Imported, linked, extension-originated, and other non-interactive external changes should create pending revisions by default.
Narrow interactive flows such as an explicit GUI save or a future browser-extension click-to-add site action may create and activate a revision immediately after service validation and audit logging.

## Review and Approval Flow

Before activation, the product should present a clear human-readable diff.
The review should show at least:
- added domains
- removed domains
- route changes for existing entries
- changes to application rules
- changes to default behavior
- the origin channel such as GUI, import, linked file, or extension

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

## Tamper Alerts and Security-Visible States

The product should expose a minimal but explicit security-visible state model:
- `secure`: no known integrity or tamper signals requiring user action.
- `review_required`: a pending high-risk or non-interactive change exists and requires explicit review.
- `tamper_suspected`: service-owned state integrity failed or an unauthorized change path was detected.

The following events are tamper-relevant and must be recorded and surfaced:
- unexpected linked-source change outside approved product flows;
- unexpected mutation of service-owned persisted policy/revision state;
- integrity verification failure for revision or integrity metadata;
- high-risk non-interactive external-origin change proposals.

Persistent alerts baseline:
- high-risk and non-interactive changes must keep a persistent alert until the user reviews or resolves the change;
- `tamper_suspected` alerts must remain visible until explicit user acknowledgement and remediation path selection (review, rollback, or reject).

Minimum security-visible audit event set:
- import;
- review opened/completed;
- approval/confirmation;
- activation;
- rejection;
- rollback;
- tamper alert raised/cleared;
- integrity failure detected.

## Future Browser Extension Model

Future channels should be allowed only under explicit constraints.

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

### Third-Party Edits to Database Files

The service-owned database files are managed by the application and are not a supported external editing surface. Opening and changing them directly with a generic database tool, instead of through the application's own settings, import, and export flows, is unsupported: it can leave the application unable to start, cause it to apply an unintended routing policy, or lose stored rules and settings. There are legitimate reasons to touch these files outside the application — restoring one from a backup or moving it to another machine — so this is not prohibited, but the product's stability guarantees only cover changes made through its own interfaces. Whoever edits these files with an outside tool is responsible for the consequences.

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

## Service Least-Privilege Baseline

Least-privilege requirements for the background service:
- run under the minimal practical service identity and privileges required for routing operations;
- avoid `LocalSystem` by default; prefer `LocalService` or a dedicated service identity unless stronger privileges are explicitly justified;
- keep privileged writable state minimal and strictly service-owned;
- keep privilege-bearing routing logic in the service boundary, never in GUI/tray code paths;
- deny direct privileged mutation paths from non-privileged clients even when they run locally.

## Service Installation Scope

The background service is installed machine-wide only. A per-user installation mode must not be offered for it, even where one is offered for the desktop surfaces.

The service runs under a system identity, so whoever can write to the directory holding its executable can replace that executable and gain code execution under that identity. A per-user install puts the binary inside a profile directory that its own user can write, which turns an unprivileged account into a full compromise of the machine.

Required controls:
- the service executable and the files it loads live in a system-wide location writable by administrators only;
- installing or updating the service requires elevation;
- an attempt to register the service from a user-writable directory is refused, and the refusal states the reason rather than failing silently.

## Per-User Rules and the Elevation Relaxation

Each Windows user's rule edits are private to that user: no other user of
the same machine can see them, and making them requires no administrator
prompt. Until a user makes their own edit, they are governed by a shared,
admin-managed **baseline**; **Reset to baseline** discards a user's own
edits and returns them to that baseline. Editing the baseline itself is
the one operation that still requires administrator elevation.

**Why a non-elevated per-user edit is safe:**
- **Scope.** A user-scoped edit can only ever write the caller's *own*
  data. The service identifies the caller from the authenticated
  connection itself, never from anything the request claims about who it
  is, so a non-admin user cannot reach another user's rules or the shared
  baseline.
- **Isolation.** Every user's rule history is kept fully separate from
  every other user's. One user's edit, rollback, reset, or cleanup never
  touches another user's data.
- **Session binding.** A pending change can only be finalized by the same
  session that proposed it; it cannot be captured and committed by a
  different user.
- **Protected baseline.** Editing the shared baseline is the one
  operation that still requires administrator elevation; the relaxation
  that lets ordinary edits go unelevated applies only to a user's own
  data, never to the machine-wide default.
- **Enforcement.** Live enforcement is scoped per user, so a user's rules
  only ever affect that user's own traffic.
- **Audit.** Every change — a user's own edit, a reset to baseline, or a
  baseline edit — is written to the append-only audit trail before it
  takes effect, with the user who made it recorded.
- **Integrity.** Stored rule history is tamper-evident: silently
  reassigning a stored change to a different user is detectable.

**Elevation model.** Administrator rights are obtained once per session
through a same-user elevation step whose local channel only that user's
own processes can reach, and which ends when the requesting app closes.
It covers the few genuinely privileged actions: installing, starting, or
stopping the background service, and editing the admin baseline. UAC
itself is not a security boundary by Microsoft's own design; what this
model guarantees is that elevation can never be reached by a different
user — only raised, as intended, by the same one.

**Reset to baseline** removes only the caller's own edits. It can never
delete the baseline itself or another user's data; once a user's edits
are gone, they are governed by the shared baseline again, exactly as if
they had never diverged from it.

## Service-Safe Dependency Boundary

To support block 6 decomposition, the service must treat the following as non-service-safe:
- GUI/tray presentation modules, QML views, and UI-only interaction logic;
- theme assets and localization presentation resources;
- user-writable UI preference state as a policy source of truth;
- extension-side automation logic and any client-owned mutable state.

Service-owned policy, pending changes, integrity metadata, and audit trail must remain in service-owned data paths and crates.

## Runtime Hardening

Baseline hardening expectations:
- keep privileged code surface as small as practical
- localize and justify any `unsafe` Rust usage
- restrict DLL and Qt plugin loading to trusted locations
- do not support arbitrary script execution or unrestricted plugin execution in the initial product version
- keep privilege-bearing logic out of the GUI layer

## Product Trust Limits

Baseline product trust limits:
- no mandatory account login is required for core local routing functionality;
- no telemetry is enabled by default;
- no hidden network actions are allowed in the background.

Allowed network actions in baseline must be explicit and user-controlled (for example, optional update checks or explicit diagnostics actions).

## Non-Goals: What Routing Does Not Protect

Routing decides which connection a request leaves through. It does not change who the user is to the other side, and the security model must not be read as if it did.

Explicitly out of scope:
- **identity on the destination site** — accounts, cookies, local site state, and browser characteristics are untouched by routing, so a site that recognizes the user keeps recognizing them after the exit address changes;
- **confidentiality towards the additional connection's operator** — routed traffic is fully visible to whoever operates that connection; the product moves the observer, it does not remove one;
- **anonymity, censorship circumvention, and content filtering** — none of these are product goals, and no invariant here should be cited as evidence of them;
- **protection between local users of the same machine beyond the per-user policy split** — separation of interactive sessions is an operating-system responsibility.

A consequence worth stating: a threat model that names "the user's provider" as the adversary is partially served by routing, while one that names "the destination site" is not served at all.

Browser-side encrypted DNS (DoH/DoT) is a related limit. It hides names from the provider and from the product at the same time, which weakens both rule matching and leak protection for that traffic. The baseline treats this as a user-visible trade-off with an explicit setting, not as a silently accepted gap.

User-facing wording for all of the above lives in `docs/en/what-routing-changes.md`.

## Logs, Diagnostics, and Cache Safety

Logs and explain output can expose application paths, host names, IP addresses, policy decisions, and connectivity failures.

Baseline rules:
- log the minimum necessary by default
- make verbose diagnostics explicit and time-bounded when practical
- distinguish user-facing diagnostics from security audit events
- store cache freshness metadata, source metadata, and timestamps
- avoid relying on stale or context-free FQDN/IP cache entries

## Application Updates and GitHub Releases

The application may support checking for new versions through official GitHub releases, but this must not weaken the local-first and security model.

Baseline update rules:
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
6. GitHub update checking cannot silently change routing policy or silently install a new build.

## Block 4 Readiness Criteria

Block 4 is considered complete only when the following are documented consistently:
- trust boundaries and active-policy ownership;
- security invariants and revision activation model;
- external-source/import/review model;
- local IPC boundary and privileged control-plane constraints;
- service least-privilege and runtime-hardening baseline;
- tamper-visible states, alerts, and audit-event baseline.

## Recommended Validation Work

Implementation should eventually validate at least these cases:
- tampered imported file
- unexpected change to a linked source
- unauthorized IPC client
- crash during policy apply
- failed integrity verification for a persisted revision
- stale or inconsistent FQDN/IP cache data
- `secondary` route outage with rules that require Fail-Closed
- suspicious bulk import or unsafe change proposal from a future extension channel

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
