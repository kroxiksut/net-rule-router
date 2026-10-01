# Security

This page describes the trust model NetRuleRouter actually implements today: who may change routing policy, what protects that policy, and where the protection stops. It states the known gaps plainly; a gap is listed here until it is closed, and a promise that the code does not keep does not belong on this page.

To report a vulnerability, see [`CONTRIBUTING.md`](CONTRIBUTING.md#reporting-a-security-issue). A report that names the boundary it crosses is much easier to act on.

## What the product protects

- **No silent policy changes.** Routing changes only through the background service, and only as a request from an identified user. A file changing on disk never becomes active policy by itself.
- **Attributable, reversible changes.** Every accepted change becomes a stored revision recorded in an append-only audit trail with the user who made it, and a previous working revision can be restored in one step.
- **Tamper evidence.** Stored revisions carry integrity data kept by the service. A revision that fails the check is not loaded.
- **Per-user separation.** One user's rules, history and diagnostics are not visible to, or changeable by, another ordinary user of the same PC.
- **Fail-Closed.** When leak protection is on and the additional connection goes down, traffic that your rules send through it is held back rather than silently sent through the main connection.
- **Enforcement without the GUI.** Routing is enforced by the service whether or not the app window or the tray is running.

## Where the protection stops

The product does not protect against:
- someone who already has administrator rights on the PC, or code running as the system account — they can replace the service, its data and its keys;
- another program running as the same user, beyond what that user could do themselves — it can ask the service for anything the user could ask for;
- a destination site recognising you — routing changes the exit address, not your accounts, cookies or browser;
- the operator of the additional connection — traffic routed through it is visible to them.

Anonymity, censorship circumvention and content filtering are not product goals, and nothing on this page should be read as evidence of them. User-facing wording for these limits lives in [`docs/en/what-routing-changes.md`](docs/en/what-routing-changes.md).

Browser-side encrypted DNS (DoH/DoT) hides names from the provider and from the product at the same time, which weakens rule matching and leak protection for that traffic. The product exposes this as an explicit setting that can block browser encrypted DNS, rather than as a silently accepted gap.

## Components and who owns what

| Component | Runs as | Role |
|---|---|---|
| Background service | the Windows system account (`LocalSystem`) | The only owner of active policy. Validates requests, stores revisions, applies routes and firewall filters, writes the audit trail. |
| App window and tray | the signed-in user | Show status, diffs, diagnostics and alerts; send requests to the service. They hold no privileged routing logic. |
| Elevation helper | the same user, elevated | Started on demand for the few administrator actions; see below. |
| Console (`nrr-cli`) | the user who runs it | Service lifecycle and diagnostics. It never edits or applies rules. |
| Rules files, presets | — | Untrusted input. They are imported, never enforced by reference. |

**Why the system account.** Changing the routing table and installing firewall filters both require administrator-level rights on Windows; the restricted service accounts cannot do either. The consequence is that a compromise of the service is a compromise of the machine, which is why the service's reachable surface is kept to a local, access-controlled channel and every request is validated there.

## The service channel

The app, the tray and the console talk to the service over a local named pipe. There is no localhost HTTP control plane and the pipe refuses remote clients.

- **Who can connect.** Any signed-in user can connect and send requests. Only the system, administrators and the service itself can create the endpoint; an ordinary user cannot open a second instance of it to intercept other users' requests.
- **The client checks the server.** Before sending anything, a client confirms that the process answering on the endpoint is the registered service itself, so a process that claimed the endpoint name first receives nothing. For that check, and for the status badge, ordinary users may query the service's status. Signed-in interactive users may also start the service; they cannot stop or reconfigure it.
- **The service checks the caller.** The service identifies the caller from the connection itself — account, elevation and integrity level — never from anything the request claims. Low-integrity processes are refused. Each operation is classified by the service as read-only or state-changing, and state-changing operations are checked against the caller's rights and written to the audit trail before they run.
- **Scoped answers.** Diagnostics reads return the caller's own records plus machine-level ones; an administrator sees everything. Notifications about one user's state reach only that user's connections. No request can name another user as its target or audience.

**Known gap.** The service tells its own clients apart (app, tray, console) by the name of the connecting executable. That decides which set of operations a client may call, not whose data it reaches — the account still comes from the connection — but it is not a strong identity.

## Per-user rules and the shared baseline

Each Windows user's rule edits are their own: no other user sees them, and making them requires no administrator prompt. Until a user makes their own edit they are governed by a shared, administrator-managed **baseline**; **Reset to baseline** discards the user's own edits and returns them to it. Editing the baseline requires administrator elevation.

Why a non-elevated edit is safe:
- **Scope.** A user's edit can only write that user's own data, because the service takes the user from the connection. It cannot reach another user's rules or the baseline.
- **Isolation.** One user's edit, rollback, reset or cleanup never touches another user's data, and a user's rules only affect that user's traffic.
- **Confirmation belongs to the proposer.** A proposed change can be confirmed only by the same user who proposed it. (It is bound to the user, not to the particular app session.)
- **Audit and integrity.** Every change — own edit, reset, baseline edit — is recorded with its author, and silently reassigning a stored change to a different user is detectable.

## Elevation

Administrator rights are obtained through a same-user elevation helper, started when an administrator action is needed and ending when the app closes. It covers installing, starting and stopping the service and editing the baseline. UAC itself is not a security boundary by Microsoft's design; what this model guarantees is that the elevated helper can only be reached by the same user who raised it.

The helper is held to narrow rules:
- its channel is reachable only by that user's own processes, and it answers only the app that started it;
- it never runs a program path received from the app — only the service executable installed beside itself;
- before sending anything, the app confirms that the process answering on the helper's channel is an elevated copy of itself;
- it writes its log only into a directory that an ordinary user could not have created or redirected;
- a slow operation is never treated as a dead helper: the app neither restarts the helper nor repeats an operation that may already have run.

## Installation scope

The service is installed machine-wide only; there is no per-user install. A release build refuses to register the service from a directory an ordinary user can write to, and says why: whoever can replace the service executable gets code execution as the system account. Installing or updating the service requires elevation.

On Windows every executable loads libraries only from the Windows system directory and its own installation folder, never from the current directory or `PATH`. The interface takes its Qt plugins and QML modules from the installation folder only: environment variables and folders outside it cannot redirect them. That makes the installation folder the one place whose integrity matters, so it must stay writable by administrators only.

## Where data lives and who can write it

| Location | Contents | Protection |
|---|---|---|
| `%ProgramData%\NetRuleRouter\` | Active policy and revisions, caches, logs, audit trail, backups | System and administrators only. Ordinary users reach its contents through the service, which scopes the answer to them. |
| Service signing key | Integrity key for stored revisions | Readable only by the system account and bound to it. |
| `%APPDATA%\NetRuleRouter\` | Per-user preferences: theme, language, accessibility, window state, route labels, remembered choices | Writable by that user. Roams with the profile on domain PCs. |
| `%LOCALAPPDATA%\NetRuleRouter\` | Per-user, per-machine app cache | Writable by that user. |
| Your rules files | Wherever you saved them | Yours. Imported, never enforced by reference. |

The service never reads the preferences file and holds no rules there. The app does keep a few remembered intents in it — for example a change made while the service was stopped — and replays them to the service when it connects. A replayed intent is an ordinary request from that user: the service validates it like any other, and it cannot reach another user's data or the baseline. Settings that apply to the whole machine are the exception: they are never replayed, not even when the app itself runs as an administrator. When the service uses a different value, the app shows that and changes nothing until the user either applies their choice — an ordinary change that asks for administrator approval — or keeps the service's value. Details of every file: [`docs/en/where-files-live.md`](docs/en/where-files-live.md).

## Integrity and tamper alerts

Stored revisions and the pointer to the active one carry integrity data kept by the service. If a check fails:
- the tampered revision is not loaded or activated;
- the service falls back to the last revision that verifies;
- the failure is recorded in the audit trail and raised as a security alert.

If the signing key itself is lost while rules are stored, nothing can be verified against it any more. The service then generates a new key, does not re-sign the old records, and keeps every user's rules in force until the reset is acknowledged. That acknowledgement state is protected like the key, not kept in the database, so editing the database cannot fake it.

If the check itself cannot run at startup — the signing key or the stored records cannot be read — the service keeps routing without it rather than stopping, and says so: it raises a security alert that the integrity check is not working and records the cause in the audit trail; if even the alert cannot be recorded, the service reports itself as degraded. The check resumes on the next start that can run it.

Security alerts stay visible until acknowledged, and while an alert about tampered data is open, rule changes wait.

The audit trail is append-only and hash-chained, is kept separately from operational logs, and is never removed by in-app cleanup. Imports, rejected revisions and every acknowledgement or resolution of a security alert are recorded as events of their own.

**Known gaps.**
- On Linux the signing key is protected by file permissions (readable by the service account only), not encrypted at rest.

The service-owned database files are not a supported editing surface. Restoring one from a backup or moving it to another machine is legitimate, but a change made with an outside database tool can leave the app unable to start, apply an unintended policy, or lose rules; the product's guarantees cover only changes made through its own interfaces.

## Imports and review

Rules files and presets are untrusted input. On import:
- the file is size-limited, must be UTF-8, and is limited in rule count and value length;
- each rule is validated by type and normalised before it is compared or stored; control characters are refused, so a rule can never turn into several when a file is written back out;
- a section the product does not understand is kept with a warning and never enforced; a file from a newer format version is read as far as the product understands it, with a warning;
- a rule that enforcement cannot carry out as written is refused rather than enforced in a wider form; a stored rule of such a shape is not enforced at all, and the product says so.

Before an import takes effect, the app shows where the change came from (an edit in the app or an imported rules file), what it adds, removes and changes, with each entry's route, and flags risky patterns such as a change of the default behaviour, a mass change, or rerouting traffic to the additional connection. Nothing is activated until the user confirms. An imported file is a snapshot: editing it later changes nothing until it is imported again.

**Known gaps.**
- Application rules match an executable's file name (optionally with a `*` wildcard), not its publisher or signature. A different program with a matching name gets the same route.

## Applying policy

- While a revision is being applied, every part of the service that reads rules sees that revision, so no background task enforces the previous one in the meantime.
- By default the service applies everything it can and reports any rule it had to skip, so one unresolvable rule does not leave you with no policy at all. An administrator can switch to all-or-nothing, where a failed apply is rolled back to the previous state.
- After an apply the service checks what was actually installed and reports differences; that check reports, it does not roll back.

## Network activity of the product itself

There is no telemetry and no account login. Besides the traffic you route, the product itself:
- looks up the host names named in your rules and keeps their addresses fresh;
- checks that the additional connection is alive, and asks a public address-discovery (STUN) service which public address it exits from;
- when you use rule suggestions, tests whether a site answers over the main connection;
- every N days (14 by default, adjustable), from the app window, makes one anonymous request to the project's GitHub releases page to see whether a newer version exists. It only shows a notification: it never downloads, installs or changes routing. The check can be turned off in Settings, and then the request is not made at all. Help → Check for updates makes the same single request when you choose it, whether or not the automatic check is on.

Logging is minimal by default. Verbose logging is an explicit choice that switches itself off after the chosen period or at the next restart. Browser-history seeding is opt-in and reads only the requesting user's own browser profiles.

## Not built yet

These are directions, not current behaviour, and nothing above depends on them:
- a linked import that watches a file and turns its changes into a pending review;
- a browser extension that could propose a single exact-host rule on an explicit click;
- publisher- or signature-aware identity for application rules;
- signed rule bundles and signed release packages;
- property-based or fuzz testing of the parsers (today they are covered by unit and fixture tests).

Engineering practice that does exist: dependency license and advisory policy enforced by `cargo deny` in the quality gate, `unsafe` Rust denied workspace-wide and allowed only in the modules that call the operating system.
