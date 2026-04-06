# Architecture

English is the default documentation language for AI-facing files.
The synchronized Russian version of this document is available in `ARCHITECTURE_RU.md`.

## Purpose

This file captures the baseline architecture of NetRuleRouter and should evolve together with the implementation.

Rules for maintaining this file:
- keep it synchronized with `ARCHITECTURE_RU.md`
- keep it aligned with `AI_CONTEXT.md`, `AI_RULES.md`, `README.md`, and `STRUCTURE.md`
- document stable architectural decisions, not speculative implementation noise

## Architectural Goals

The architecture is designed around these goals:
- Windows-first operation
- local-first behavior
- predictable routing decisions
- transparent diagnostics and explainability
- tray-based everyday control
- service-based startup and background enforcement
- clear separation between UI concerns and routing logic
- future growth toward Pro capabilities without rewriting the core

## High-Level Model

NetRuleRouter should be split into two major runtime parts:
- a Windows tray desktop application
- a Windows background service

The tray application is responsible for:
- user interaction
- status visibility
- quick actions
- opening and controlling the main GUI
- presenting diagnostics and explain output

The background service is responsible for:
- starting with Windows
- applying and maintaining routing policy
- running even when the main window is closed
- owning long-lived background behavior
- coordinating rule evaluation and enforcement

## Core Technology Split

Preferred stack:
- `Rust` for core logic and backend behavior
- `Qt` for desktop GUI and tray integration

The intended responsibility split is:
- Rust core for rule engine, routing decisions, configuration handling, cache, logs, diagnostics, and Windows-facing enforcement logic
- Qt layer for the main window, tray UI, user workflows, and communication with the Rust core

Business logic should stay in Rust wherever practical.
The GUI should stay thin.

## Logical Components

Baseline logical components:

1. Tray Application
- owns the tray icon and tray menu
- exposes status and quick controls
- opens the main settings and diagnostics UI
- communicates with the background service or shared backend layer

2. Main GUI
- manages settings screens
- manages rule editing workflows
- presents explain mode, diagnostics, and logs
- does not own routing enforcement

3. Background Service
- starts with Windows
- loads active configuration
- applies routing policies
- monitors state needed for ongoing enforcement
- remains active independently of the GUI window

4. Rule Engine
- evaluates application, FQDN, subdomain, and IP rules
- applies the fixed rule priority
- resolves the final route decision
- supports explain output for each decision

5. Configuration Layer
- stores the active configuration
- supports import and export
- validates persisted settings and rule data

6. FQDN/IP Cache
- uses local SQLite storage
- supports explain mode and routing lookup behavior
- stores mapping and freshness metadata

7. Diagnostics and Logging
- records service and policy events
- supports explain mode
- supports user-visible troubleshooting workflows

8. Enforcement Layer
- bridges policy decisions to Windows behavior
- should be isolated from GUI concerns
- should expose clear interfaces to the rest of the core

## Runtime Boundaries

Required boundaries:
- routing enforcement must not depend on the main GUI window being open
- tray behavior must not contain the routing engine itself
- the service should remain the owner of long-running enforcement behavior
- the GUI should consume diagnostics and status, not recreate backend decisions
- shared contracts between GUI and service should be explicit and stable

## Rule Evaluation Baseline

Current baseline rule priority:
1. exact FQDN
2. subdomain / suffix
3. exact IP
4. application
5. default route

This priority exists because address-based routing is considered more specific and reliable than application-only routing for cases such as browsers accessing many different destinations.

## Persistence Baseline

The architecture assumes these persistent concerns:
- one active configuration in the Free version
- local text-based presets, primarily YAML
- local SQLite cache for FQDN/IP mapping
- local logs and diagnostics data

## Service and Tray Baseline

Required operational model:
- the background part starts with Windows as a service
- the user-facing application is available from the Windows tray
- the tray remains the primary lightweight interaction surface
- the main window is optional during normal operation

## Evolution Direction

The architecture should be able to grow toward:
- additional route models for Pro
- more advanced prioritization and automation
- richer diagnostics
- expanded preset and rule-pack support

That growth should extend the existing core rather than forcing a redesign of the UI/backend split.
