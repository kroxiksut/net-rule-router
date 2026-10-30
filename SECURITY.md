# Security

This page describes the trust model NetRuleRouter actually implements today: who may change routing policy, what protects that policy, and where the protection stops. It states the known gaps plainly; a gap is listed here until it is closed, and a promise that the code does not keep does not belong on this page.

To report a vulnerability, do not open a public issue and do not post it in the public Telegram channel: use [Report a vulnerability](https://github.com/kroxiksut/net-rule-router/security/advisories/new), which opens a private advisory, or e-mail [fmalkov91@gmail.com](mailto:fmalkov91@gmail.com). What to include is in [`CONTRIBUTING.md`](CONTRIBUTING.md#reporting-a-security-issue). A report that names the boundary it crosses is much easier to act on.

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

Browser-side encrypted DNS (DoH/DoT) hides names from the provider and from the product at the same time, which weakens rule matching and leak protection for that traffic. For a user who has rules for the additional connection, browser encrypted DNS is blocked by default; the setting can switch the block off, and then this gap is accepted knowingly rather than silently.

## Known limitations of this release

Each of these is described, with what to do about it, in [`docs/en/known-limitations.md`](docs/en/known-limitations.md), and stays listed until it is fixed:
- with leak protection set to Routed sites, the protection is not in force for the first seconds after the computer starts, until the service has applied the rules (with Everything, the internet waits from the start instead);
- without virtual addresses (fake-IP; Windows only, on by default for a new installation), sites that share one server address cannot be routed apart;
- a rule for a site name does not cover an application that looks up names on its own while leak protection is off;
- on Windows, leak protection that blocks everything for one user also holds back IPv6, ping and VPN protocols such as IPsec for the other users of the computer;
- with leak protection blocking everything, the sign-in page of a public Wi-Fi network cannot open;
- on Linux with strict reverse-path filtering, a second signed-in user may get no replies over the additional connection;
- name lookups are shared by the computer: with several users signed in, they follow the rules of the user who signed in first;
- on Windows the route table is shared by the computer: an address one user routes through their connection takes that connection for the other signed-in users whose rules do not name it;
- on a Windows computer where Group Policy manages DNS, a rule for a site name takes effect only after the first connection to the site, virtual addresses do not work, and the app does not say so yet;
- for names answered on the computer itself (`hosts`, `.local`), a rule for a site name does not take effect.

The installers and binaries are not signed yet (Windows shows an unknown publisher). Release files come with a checksum file and a build attestation: `gh attestation verify <file> --repo kroxiksut/net-rule-router` checks a download against the workflow that built it.

## Components and who owns what

| Component | Runs as | Role |
|---|---|---|
| Background service | the Windows system account (`LocalSystem`) | The only owner of active policy. Validates requests, stores revisions, applies routes and firewall filters, writes the audit trail. |
| App window and tray | the signed-in user | Show status, diffs, diagnostics and alerts; send requests to the service. They hold no privileged routing logic. |
| Elevation helper | the same user, elevated | Started on demand for the few administrator actions; see below. |
| Console (`nrr-cli`) | the user who runs it | Service lifecycle and diagnostics. It never edits or applies rules. |
| Rules files, presets | — | Untrusted input. They are imported, never enforced by reference. |

**Why the system account.** Changing the routing table and installing firewall filters both require administrator-level rights on Windows; the restricted service accounts cannot do either. The consequence is that a compromise of the service is a compromise of the machine, which is why the service's reachable surface is kept to a local, access-controlled channel and every request is validated there.

**When the service starts the tray.** When the service has to tell a signed-in user something while none of their windows is open, it starts the application's own tray in that user's session. The tray runs with that user's ordinary, non-elevated rights and that user's own settings, never with the service's rights and never in another user's session. The service starts only the tray installed beside it, and only if no ordinary account could have changed or replaced it; otherwise it shows nothing. What the notice displays comes from network activity and is treated as untrusted text. Such notices are rate-limited per user, and the user can turn them off.

## The service channel

The app, the tray and the console talk to the service over a local named pipe. There is no localhost HTTP control plane and the pipe refuses remote clients.

- **Who can connect.** Any signed-in user can connect and send requests. Only the system, administrators and the service itself can create the endpoint; an ordinary user cannot open a second instance of it to intercept other users' requests.
- **The client checks the server.** Before sending anything, a client confirms that the process answering on the endpoint is the registered service itself, so a process that claimed the endpoint name first receives nothing. For that check, and for the status badge, ordinary users may query the service's status. Signed-in interactive users may also start the service; they cannot stop or reconfigure it.
- **The service checks the caller.** The service identifies the caller from the connection itself — account, elevation and integrity level — never from anything the request claims. Low-integrity processes are refused. Each operation is classified by the service as read-only or state-changing, and state-changing operations are checked against the caller's rights and validated before they run; only a request the service accepts is written to the audit trail. A refused request leaves no audit record, so refused requests cannot push genuine history out of the trail.
- **Scoped answers.** Diagnostics reads return the caller's own records plus machine-level ones; an administrator sees everything. A machine-level log line that names a host, an address or a path is shown to administrators only. The name cache is shared by the computer: an ordinary user sees in it only the names their own rules cover, and clearing it, like clearing the logs, needs an administrator. Notifications about one user's state reach only that user's connections. No request can name another user as its target or audience.

**Known gap.** The service tells its own clients apart (app, tray, console) by the name of the connecting executable. That decides which set of operations a client may call, not whose data it reaches — the account still comes from the connection — but it is not a strong identity.

## Per-user rules and the shared baseline

Each Windows user's rule edits are their own: no other user sees them, and making them requires no administrator prompt. Until a user makes their own edit they are governed by a shared, administrator-managed **baseline**; **Reset to baseline** discards the user's own edits and returns them to it. Editing the baseline requires administrator elevation.

Why a non-elevated edit is safe:
- **Scope.** A user's edit can only write that user's own data, because the service takes the user from the connection. It cannot reach another user's rules or the baseline.
- **Isolation.** One user's edit, rollback, reset or cleanup never touches another user's data. On Linux a user's rules route only that user's traffic; on Windows the computer has one route table, so an address one user routes through their connection takes that connection for the other signed-in users too (see [`docs/en/several-users.md`](docs/en/several-users.md)).
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

The service is installed machine-wide only; there is no per-user install. A release build never registers the service from a directory an ordinary user can write to: whoever can replace the service executable gets code execution as the system account. Installing from such a directory — an unpacked portable copy on the desktop or a USB stick — registers a copy instead: the service executable and the files it loads are copied into `NetRuleRouter Service` under Program Files, a folder only administrators can change, checked byte for byte after copying, and registered from there only once that folder is confirmed out of reach of ordinary accounts. A later install from a newer copy updates it; removing the service removes it. The folder you install from is trusted at the moment you install, as with any installer; changes made to it afterwards no longer reach the service. On Linux the install refuses a service binary that is not owned by root or that sits in a folder other accounts can write to, and says where to copy it. Installing or updating the service requires elevation.

On Windows every executable loads libraries only from the Windows system directory and its own installation folder, never from the current directory or `PATH`. The interface takes its Qt plugins and QML modules from the installation folder only: environment variables and folders outside it cannot redirect them. That makes the installation folder the one place whose integrity matters, so it must stay writable by administrators only.

## Where data lives and who can write it

| Location | Contents | Protection |
|---|---|---|
| `%ProgramData%\NetRuleRouter\` | Active policy and revisions, caches, logs, audit trail, backups | System and administrators only. Ordinary users reach its contents through the service, which scopes the answer to them. |
| Service signing key | Integrity key for stored revisions | Readable only by the system account and bound to it. |
| `%APPDATA%\NetRuleRouter\` | Per-user preferences: theme, language, accessibility, window state, route labels, remembered choices; where your rule sets and rules files are, and the notices you muted | Writable by that user. Roams with the profile on domain PCs. |
| `%LOCALAPPDATA%\NetRuleRouter\` | Per-user, per-machine app cache | Writable by that user. |
| Your rules files | Wherever you saved them | Yours. Imported, never enforced by reference. |

The service trusts what it reads back from its own data folder (the unfinished-activation record, its settings) only because that folder is closed to ordinary users; the service re-secures the folder on every start, and a record it finds there is acted on as its own.

The service never reads the preferences file and holds no rules there. The app does keep a few remembered intents in it — for example a change made while the service was stopped — and replays them to the service when it connects. A replayed intent is an ordinary request from that user: the service validates it like any other, and it cannot reach another user's data or the baseline. Settings that apply to the whole machine are the exception: they are never replayed, not even when the app itself runs as an administrator. When the service uses a different value, the app shows that and changes nothing until the user either applies their choice — an ordinary change that asks for administrator approval — or keeps the service's value. Details of every file: [`docs/en/where-files-live.md`](docs/en/where-files-live.md).

## Integrity and tamper alerts

Stored revisions and the pointer to the active one carry integrity data kept by the service. If a check fails:
- the tampered revision is not loaded or activated;
- the service falls back to the last revision that verifies;
- the failure is recorded in the audit trail and raised as a security alert.

If the signing key itself is lost while rules are stored, nothing can be verified against it any more. The service then generates a new key, does not re-sign the old records, and keeps every user's rules in force until the reset is acknowledged. That acknowledgement state is protected like the key, not kept in the database, so editing the database cannot fake it.

If the check itself cannot run at startup — the signing key or the stored records cannot be read — the service keeps routing without it rather than stopping, and says so: it raises a security alert that the integrity check is not working and records the cause in the audit trail; if even the alert cannot be recorded, the service reports itself as degraded. The check resumes on the next start that can run it.

Security alerts stay visible until acknowledged, and while an alert about tampered data is open, rule changes wait.

The audit trail is append-only and hash-chained, is kept separately from operational logs, and is never removed by in-app cleanup; it is kept within the retention limits set in Settings, the oldest records going first. Imports, rejected revisions and every acknowledgement or resolution of a security alert are recorded as events of their own.

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

## Protection of system programs

A deny or an additional-route rule cannot take what the computer needs to stay on the network: the system folder, critical system processes, network services, folders many programs share, and the product's own programs. The window, the tray and the terminal interface refuse such a rule before it is saved; one already in a rules file is kept but not applied, and the reason is shown.

A user who means it marks the rule `+override` in the rules file, which is only a request. The rule is applied once that user confirms it in the window or the terminal interface, after seeing what it takes and typing its value, for a term they choose (an hour up to until revoked). A rule that reaches past the user's own programs — system folders or processes, service accounts, other users' programs — needs an administrator to confirm it. Confirmations are kept by the service, not in the rules file, so editing a file never grants one, and every confirmation, revocation and expiry is recorded in the audit trail. Restoring the network revokes them all, and so does a run of service failures in a row. The root of a disk and the product's own programs can never be confirmed.

One user's program rule never covers the programs in another user's profile, and a new rule cannot name a folder there; the shared baseline reaches each user's own folder through a profile-relative path such as `%LOCALAPPDATA%` or `~`.

## Network activity of the product itself

There is no telemetry and no account login: nothing reports how you use the product. It does make a few requests of its own, most of them in the background, each for something you get from it. Besides the traffic you route, it:
- looks up the host names named in your rules, and the sites under your domain and zone rules that you opened recently, and keeps their addresses fresh, so a rule keeps working when a site moves to a new address. A name stops being looked up once no rule covers it;
- asks the DNS server of your own connection which site an address belongs to, when a program reached the address without a name lookup the service saw, so your rules recognise that site too. These lookups are made only while rule suggestions or leak protection are on, and never for a site your own deny rule blocks. Rule suggestions are on by default; with suggestions and leak protection off (Settings → Routing behavior), none are made;
- checks that the DNS servers of your connection answer, so names are looked up through one that works;
- while the additional connection is up, looks up the host names in your rules for that connection through it, at Quad9's public DNS server (149.112.112.112), instead of your main connection's DNS server, so your provider neither sees those names nor changes their answers. With the local DNS resolver (the default routing method) your programs' lookups of those names are answered the same way. Quad9 sees those names, and they reach it through the additional connection; no other lookup of yours is sent to that address. While the additional connection is down, those names go to your main connection's DNS server, except a site leak protection is holding, which is not looked up at all;
- with **DNS through the tunnel** on (Settings → Routing behavior; off by default), sends all of its own lookups through the additional connection to the public DNS servers of Cloudflare, Google and Quad9 instead: the names in all your rules and the questions about which site an address belongs to. Those servers see the names. Your programs' lookups of sites outside your rules for the additional connection still go to your main connection's DNS server, whether this is on or off;
- when your main connection's DNS server answers a name in your rules with an address that looks blocked, asks Cloudflare, Google and Quad9 about that one name again, so the rule still gets a real address. The question goes through the additional connection when the two points above send that name there, and over the main connection otherwise;
- checks that the additional connection is alive, with a ping to that connection's own gateway;
- if you turn on **Check the external address each time the additional route connects** (Settings → Routing behavior → Your VPN client, or Routing in the terminal interface; off by default, per user), asks a public address-discovery (STUN) service of Google or Cloudflare, each time the additional connection comes up, which public address that connection exits from, and shows it in a notification. The same question is asked for each of your connections when you press **Check external address** in the interfaces list (or `x` in the terminal interface), whether the automatic check is on or not. The STUN service learns that address and nothing else;
- when you ask it to check the main route (on the rule suggestions or on the rules), tests whether those sites answer over the main connection, so you can see whether sending them through the additional one changes anything. With **Check the main route for new suggestions automatically** on (Settings → Routing behavior; off by default), it runs the same test for new suggestions by itself;
- when you press **Check site**, opens the start page of that site, of its sign-in names and of the names seen with it, over the routes your rules give them, and follows where they send on. Each request names itself as NetRuleRouter's site check, so those sites can tell the check came from the product. Nothing is checked unless you ask;
- when you open a site whose rule is marked `?` (bundled country presets use them), tries whether it opens over the route you wrote and, if it does not, over the other one. Only sites you actually open are tried, never the whole list; a rule without `?` is never tried;
- does not check for updates: this version makes no request about newer versions at all. New versions appear on the project's [GitHub releases page](https://github.com/kroxiksut/net-rule-router/releases) and are announced in the Telegram channel [t.me/netrulerouter](https://t.me/netrulerouter); updating is manual — you install the new version over the old one.

Logging is minimal by default. Verbose logging is an explicit choice that switches itself off after the chosen period or at the next restart. Browser-history seeding is opt-in and reads only the requesting user's own browser profiles.

The connection history — which of your programs connected where, and over which route — is kept on this computer for 7 days unless you choose otherwise, never in the diagnostic archive. In NetRuleRouter every person reads only their own, administrators included: a record of where someone went is theirs, not machine diagnostics. You can clear it or switch it off at any time in Settings without administrator rights, and a full reset erases it. The file itself sits in the service's folder, which only the system and administrators can open.

## Not built yet

These are directions, not current behaviour, and nothing above depends on them:
- a linked import that watches a file and turns its changes into a pending review;
- a browser extension that could propose a single exact-host rule on an explicit click;
- publisher- or signature-aware identity for application rules;
- signed rule bundles and signed release packages.

Engineering practice that does exist: dependency license and advisory policy enforced by `cargo deny` in the quality gate, `unsafe` Rust denied workspace-wide and allowed only in the modules that call the operating system, and fuzz testing of every parser that reads data another party can shape.
