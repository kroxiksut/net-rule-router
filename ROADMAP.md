# Roadmap

Where NetRuleRouter is heading. There are no dates: an item ships when it is
ready and has been tested on real machines.

What already works is listed under **Highlights** in the [README](README.md).

## First public alpha: Windows and Linux

**Linux.** Ships in this alpha next to Windows, as `.deb`, `.rpm` and
`.tar.gz` packages. What remains is checking more distributions and ARM
machines; [Supported systems](docs/en/supported-systems.md) says which ones are
checked.

## Stabilising the alpha — A0

The first priority is making the alpha's existing capabilities predictable.
The stable alpha is ready once every promise below holds on real machines and
a configuration mistake always leaves a clear way to restore connectivity.

| What | What it gives you |
|---|---|
| Full IPv6 | Rules already name IPv6 addresses and names that resolve to them, and route and protect them as they do IPv4. This is verified on real IPv6 networks before it is called finished |
| Sites protected from the first second of startup | With leak protection set to Routed sites, the sites your rules protect are held back from the moment the computer starts, as everything is with Everything |
| Protection back on its own after a Windows firewall restart | If the Windows firewall service restarts while NetRuleRouter runs, the protection is put back at once and the window tells you, so the computer is never left unprotected |
| A site's new address protected the moment it appears | When a site your rules protect moves to a new address, the protection covers it at once rather than a few seconds later, even if the VPN drops in that very moment |
| Same protection on Linux when a connection drops | When the additional connection is down, ordinary sites on Linux stay reachable while the ones your rules protect stay closed, as on Windows |
| Strict network checks on RHEL-family systems | On RHEL, RED OS, AlmaLinux and similar systems with strict network checks turned on, the sites your rules send over the additional connection keep working for every user of the computer |
| Compatibility with VPNs, TUN and virtual addresses | The app checks whether its own virtual adapter, fake-IP range and routes conflict with an existing VPN, and does not accept another program's network object as its own. Universal compatibility with every VPN is not promised: supported combinations are tested on real systems |
| Network recovery after a stop or failure | After a normal stop, crash, full reset or removal, the app's DNS settings, routes, filters and virtual adapters do not leave the computer without connectivity |
| Main and additional connections checked before use | The app explains up front when the additional network connection is absent or not ready. A system HTTP/SOCKS proxy is not presented as a network interface through which the current version can route rules |
| Corporate DNS alongside multiple VPNs | Internal names continue resolving through the corporate connection's normal DNS. The app does not bypass NRPT, GPO or other managed policies and clearly reports when it cannot operate alongside them |
| Every promise checked before each release | Each promise in the README and the guide — nothing leaks while protection is on, rules route traffic as written, your rules and settings survive an update, users of one computer stay apart, name lookups are given back — has automatic checks that try to break it, plus live Windows and Linux checks for VPN drops, network-resource conflicts and system recovery |

## Early alpha development — A1

These improvements proceed alongside stabilisation. The order is approximate:
an item may ship sooner, later, or turn out not to be needed. If you need
something from the list, or something that is not in it, open an issue and
describe what you are trying to do — that can raise its priority.

### First setup

| What | What it gives you | Priority |
|---|---|---|
| Setup checked before it is applied | For the common main-connection-plus-one-VPN setup, the wizard checks both connections, the rules and protection, then shows a clear result. If the VPN is only a system proxy or its interface is not up yet, you are told before applying | high |
| Safe initial settings without a separate expert app | The essential choices and safe values come first, while uncommon network controls expand on request. One interface remains suitable for first use and detailed configuration | high |
| Ready-made templates for common setups | Templates for common setups, such as a work VPN for the company's own sites and addresses: you fill in your names and addresses, and the app adds the rules and offers to check the result | high |

### Everyday use and browser integration

| What | What it gives you | Priority |
|---|---|---|
| Settings and action search | Search by name, technical term or problem description leads to the relevant setting, check or help page, accounting for interface languages and synonyms | high |
| Optional browser extension | Supported WebRTC settings and address diagnostics work independently or alongside NRR. Browser limitations and effects on video calls are explicit; absolute protection against address disclosure is not promised | high |

Simple use and detailed configuration remain one app: expanding advanced
controls neither hides capabilities nor creates a second settings system.
Search understands terms such as DNS, leaks, WebRTC, ports and proxies and
leads directly to an action or explanation. The wizard explains selected
connections, detects obvious conflicts and offers a clear recovery path
when the additional connection is missing. Rule groups can be collapsed
and freely ordered for working with the list without changing routing
priority. Native Windows notifications are used where appropriate; the
service continues with both the window and tray closed.

The browser extension should show external and local addresses, detected
deviations and supported WebRTC privacy controls. Working alongside NRR
requires a protected interface and alignment of browser restrictions with
the selected network policy. Chrome, Edge and Firefox are checked separately,
including effects on video calls. Confirmed failures of already promised
protection belong in A0; new browser integration tools belong in A1.

#### Site regions and browser profiles

Extension development includes separate settings for individual Firefox,
Chrome and Edge profiles, including personal and work profiles of one browser.
The main connection keeps existing browser values by default. Users choose
defaults for sites on the additional connection and override selected fields
per site. HTTP language, preferred languages, regional formats, time zone and
geolocation are independent controls within each browser's capabilities.
WebRTC remains a separate group.

Each field can inherit, keep the browser value, use a manual value or follow
the egress. Explicitly keeping the browser value stops inheritance; deleting
an exception restores it. OS settings stay unchanged. Routing and browser
profiles remain separate: changing a language does not redirect traffic.
The actual scope of each setting must first be validated.

**An egress country change.** A user selected the United Kingdom, but the VPN
switched to Japan. Value selection and the response to a mismatch are separate:

| Value mode | Behaviour |
|---|---|
| Fixed region | Keep selected values and show disagreement with the observed egress |
| Follow egress | Update regional values from verified observations within the user's authorised settings |
| Per-field selection | For example, manual English, a time zone following egress and unchanged geolocation |

Separately, users choose a warning, confirmation or pre-authorised update.
For sensitive sites we will investigate pausing new loads pending a decision;
its network coverage must be proven, and stopping new requests does not protect
an entire existing session. The default response remains to be decided.
An IP change within a country, a country change and corrected geodata are
different events. Changing browser values cannot hide an IP change already
seen by a site.

A country offers an editable set rather than one mandatory language, city or
time zone. OS clocks do not change; time zone and regional formats are checked
separately. Manual corrections survive automatic checks. The geodata source,
freshness and unknown or differing IPv4/IPv6 egresses are explicit. External
checks require user agreement and do not receive visited sites. A mismatch
is not presented as proof of a leak or a prediction of account suspension.

#### Synchronisation and settings transfer

Synchronisation links selected browser profiles, not every discovered browser.
Users can share additional-connection defaults, one site's settings or a named
set, select shared fields and keep individual exceptions. Copying is a one-time
operation; synchronisation propagates subsequent edits. A copied set is
independent, while a linked set follows changes to its source.

Editing in NRR or an extension updates one configuration. When connected,
NRR stores the current OS user's agreed state and extensions retain local
copies. Revisions prevent lost offline edits, update loops and deleted settings
reappearing. Conflicting edits to one field are shown rather than resolved by
computer clocks. The selected mode is shared; different participants' egresses
are not treated as a single common observation.

Saving, delivery, application and verification are separate states. Users see
which browser is offline, needs a page reload or lacks a capability. Leaving a
group offers an independent copy or removal of overrides. One browser profile
does not automatically gain access to others; OS users remain separate.
Private-window persistence and synchronisation require a separate choice.

Export uses a separate versioned browser-settings file containing selected
sets, sites, defaults, modes and optionally groups. The routing rules file
remains separate. Cookies, history, connection secrets and machine identifiers
are excluded; users can omit site lists and coordinates. Import previews changes,
maps destination browser profiles and offers merging or replacing selected
parts without automatically granting application or synchronisation permissions.

#### Support and explicit limitations

Firefox, Chrome and Edge are checked on Windows and Linux from the start.
Opera, other Chromium browsers and other Linux browsers extend the verified
matrix later. A shared engine or successful extension installation does not
prove support. Safari is planned alongside macOS with separate packaging and
capability validation; this does not promise mobile versions.

Support is recorded by browser, version, OS, installation method and setting,
including NRR connectivity in sandboxed Linux packages. The capability catalogue
grows from research into other extensions without promising every setting at once.

The first test is two sites open simultaneously with different settings.
A browser-wide setting cannot be switched by focused tab and presented as
site-specific. Conflicts show a limitation or suggest a separate browser profile.
HTTP language, JavaScript values, formats, time zone and geolocation have
distinct coverage; changing one does not verify the others.

The top-level site and NRR's routing decision select the browser set. Subresources
on other routes do not switch the page's region. Frames, workers, redirects,
the first request and first script require separate checks. Values already read
cannot be withdrawn; changes may need a reload, which is not silently performed
at the cost of unsaved forms. Standalone extensions apply explicit choices but
do not verify NRR routes. On service loss, egress-dependent data becomes stale;
connecting to NRR offers a review of merging local settings.

Planned controls live under Routing → Browsers: profiles, groups, defaults,
egress-change policy and export. Site rules link to exceptions; the extension
shows the current site, value sources and observed egress. TUI offers equivalent
control; the final screens still require design agreement.

### Checks and recovery

| What | What it gives you | Priority |
|---|---|---|
| Explicitly checking a site over both connections | On your command, the check tries the assigned and alternative connections and reports DNS, network path and server response separately. A strictly pinned rule is not tested or switched through another egress without your permission, and an unavailable site is not blamed on the provider without sufficient evidence | high |
| Public Wi-Fi sign-in with leak protection on Everything | The app recognises the sign-in page of a public Wi-Fi network and opens a short window to sign in, after which full protection returns | high |
| First connection after a VPN reconnect | Right after the VPN reconnects, the first connection to a site your rules send over it goes through the new connection instead of failing once | high |
| Clear recovery when the VPN returns | When the additional connection returns, new connections follow the rules again and the app says the request can be retried. Controlling browser tabs requires a separate integration and is not promised by the network service itself | medium |

### Working alongside other VPNs and programs

| What | What it gives you | Priority |
|---|---|---|
| Own secure DNS for one program | A program with its own encrypted DNS, such as a corporate client or a game, keeps working while protection stays on for every other program | high |
| Notice when required routes change | When another program or a system policy keeps removing routes your rules need, the window and terminal interface tell you once which sites are affected. The source is named only when attribution is reliable; otherwise the app reports the route change itself | high |
| Warning about another program's wide route | When another program, such as a virtual machine manager, takes over a whole range of addresses, the app shows which addresses it swallows and offers to remove that route, so a server or site that would not open works again | high |
| Tidy list of VPN connections | Some VPN programs install dozens of identical connections. The list shows them as one line with the copy in use, and offers to remove the copies the VPN never uses, only with your consent | medium |

### Linux on par with Windows

| What | What it gives you | Priority |
|---|---|---|
| Sites that share an address, routed apart on Linux too | Two sites that live on one server address can go over different connections on Linux, as they already can on Windows: the one your rules send through the VPN goes through it, its neighbour stays direct | high |
| The same network checks and recovery | Protection, DNS, failure recovery and diagnostics are checked on real Linux systems separately from Windows. Shared code or a unit test is not presented as proof that the system mechanism works | high |

### Rules

| What | What it gives you | Priority |
|---|---|---|
| Strict connection pinning and explicit fallback | For a site, address or program you can decide in advance whether another egress must never be tried, the selected one is merely preferred, or the app should ask after a failure. Existing rule meanings do not change silently | high |
| Rule groups and sorting | Rules can be arranged in clear visual groups and sorted when working with a large list. A group's name and position do not change routing priority | high |
| Overlaps and the winning rule explained | Before applying and in diagnostics, the app shows which narrower rule wins, what is already covered and which egress a connection actually used | high |
| Rule change history and rollback | Every addition, removal and change says when and where it came from, and a selected change can be undone on its own | high |
| Bulk operations on a group | Once safe grouping exists, selected rules can be enabled, disabled, moved or prepared for application together without changing the rest | medium |
| Updates to imported rule sets | When a new version adds addresses to a rule set you imported (new addresses of `site.com`, say), the app offers the update and shows what changed. Nothing changes without your consent | medium |
| Rules by the account a service runs under | Sites and services that run inside one server program can still go over different connections, by the account each one runs under, such as a separate application pool per site. Needs administrator rights; system accounts stay protected | medium |
| Rules for the whole computer | One set of rules for every program on the computer, including services and programs that run with nobody signed in. An administrator turns it on | medium |
| Installing a program without network access | Start an installer from the window or the terminal interface, and neither it nor anything it starts can reach beyond your computer until the installation ends. The network comes back on its own, and the app offers rules for the program it installed. An Explorer context-menu item will follow if users ask for it | medium |

### Name lookups

| What | What it gives you | Priority |
|---|---|---|
| Clear DNS path diagnostics | When checking a name, the app shows which DNS was expected to answer, what could be observed, and whether a corporate VPN, another resolver or a system policy is interfering. An application's unobservable DNS is not presented as a verified system path | high |
| DNS rebinding protection | A web page cannot reach your router and home devices through the browser. Names your network legitimately points at local addresses keep working, and anything held back can be allowed with one click | medium |
| Name lookups wait too when the VPN drops | With leak protection set to Everything, while the additional connection is down even the look-ups of site names wait for it instead of going out over the main connection | medium |

### Diagnostics, notifications and languages

| What | What it gives you | Priority |
|---|---|---|
| Actual network path explained | A connection shows its expected rule, applied interface, observed DNS and verified result. A NetRuleRouter block, another filter's block and a server that did not answer are separate states | high |
| A diagnostic archive with a verifiable picture | The archive connects interface state, rules, DNS, routes and recovery without hiding a broken user setup behind a generally healthy service status or exposing unnecessary names and addresses | high |
| Native Windows notifications | Important route, protection and recovery changes use Windows 10 and 11 system notifications even when the main window is closed | high |
| Additional languages | Once loading and completeness checks for external locale files are verified, Chinese and other translations can be added without a separate build | medium |

### Statistics

| What | What it gives you | Priority |
|---|---|---|
| Traffic charts by connection | The traffic statistics you can already export, as a chart in the window and the terminal interface | medium |
| Data plan limit warning | A notice when the additional connection's usage nears the limit of a VPN subscription or a mobile plan | medium |

### Installation and updates

| What | What it gives you | Priority |
|---|---|---|
| New version notice | The app tells you when a new version is out, on request or on its own every two weeks; the automatic check can be turned off | high |
| Connections chosen at installation | A silent installation names the main and the additional connection, so identical computers route by your rules right after setup, with nothing to click | medium |
| Package repositories for Linux | Installs and updates the way your distribution does it: `apt` on Ubuntu and Debian, `dnf` on Fedora, RHEL, AlmaLinux and Rocky Linux, `zypper` on openSUSE, the AUR on Arch Linux, then the Astra Linux and RED OS app stores | medium |
| Installers for ARM computers | The EXE and MSI installers for Windows on ARM and the `.deb` and `.rpm` packages for 64-bit ARM Linux, once they are tested on real ARM machines. Until then, ARM computers use the portable builds | medium |
| Up-to-date libraries | The libraries for checksums, signatures and data encoding move to their current versions, while rules and the audit trail saved by earlier versions keep working unchanged | medium |

## Before the full release — R1

Once basic routing is stable, NetRuleRouter will be able to use a supported
proxy as an additional egress rather than requiring every egress to be a ready
network interface. The system mechanism is prototyped first: this public plan
does not promise transparent support for every protocol before that validation.

### Connections and proxies

| What | What it gives you |
|---|---|
| An existing SOCKS5 or HTTP CONNECT proxy as an additional egress | An already running proxy at a chosen address and arbitrary port can be selected instead of a VPN adapter. The supported DNS, TCP, UDP and QUIC scope is explicit; unsupported traffic does not silently go direct against a strict rule |

### External control

| What | What it gives you |
|---|---|
| Documented local API | Scripts and other apps read permitted state, receive events and propose or apply changes within their granted permissions through shared checks |
| Separate web interface for your instance | Rules, connections, settings and diagnostics in a browser, including Linux without a graphical desktop. Installed separately and built on the shared API; network access is a separate research topic |

#### Local control API

The goal is a documented way for scripts, external apps and alternative
interfaces to work with NRR without changing its core. Clients will read
service and connection state, permitted rules, statistics and diagnostics,
subscribe to events, prepare changes, review their validation results and
perform authorised actions.

The versioned contract will describe available capabilities. Change review,
confirmation and permission boundaries stay shared with GUI and TUI: API access
does not itself grant administrator rights. Automation can act within
pre-approved policies. A local API does not automatically mean an HTTP server
or internet access; those access methods need separate validation.

#### Modular web interface

A separately installed Web UI will manage your own NRR instance through a
browser, including on a Linux server without a graphical desktop. Planned scope:

- connections and actual routing state;
- rules, groups and preparation of changes for application;
- network policy and protection settings;
- diagnostics, logs and statistics;
- installed extensions and their permissions once the plugin contract exists.

Web UI uses the same API and checks as the desktop and terminal interfaces.
Closing the browser or stopping the web component does not stop policy
enforcement. Desktop users do not need to install it for routing to work.

The initial scope is one instance. Protected access from another computer is
a separate research topic, as is central management of multiple machines.
Web UI does not enable gateway mode: forwarding other devices' traffic needs
its own network mechanism.

### Full-release readiness

Before Beta, RC and the full release, supported Windows and Linux, VPN and proxy
combinations go through repeated live checks. Upgrades preserve rules and
settings, installation and removal leave networking intact, and recovery still
works after an abnormal termination.

## Later

Planned as well; these move up as users ask for them.

**Rules and suggestions**
- **Speed limits** — cap the download and upload speed of a chosen program, address, subnet or site, each direction on its own, and lift the cap for a while with one click.
- **Warning about a rule that is already covered** — the app names the rule that already covers a new site or program and asks whether to add the new one anyway.
- **Choosing which changes to apply** — in the review before an import or a rule change, set individual lines aside and apply only the rest, in the window and the terminal interface.
- **Told when unknown rules are kept** — when rules saved by a newer version are kept as they are while you edit yours, the window tells you which ones and why.
- **Suggestions for programs** — a program whose connections do not get through on the main connection is offered a move to the additional one, as sites are today.
- **Adding suggestions on its own for one site** — for a site you trust, the app adds the addresses it suggests by itself, while other sites keep asking first.
- **Rules that follow the programs a program starts** — a rule for a program also covers what it starts, such as a launcher and the game it opens.
- **A program rule that covers the program's whole site** — future servers under the site domain the program talks to, never a whole public suffix such as `.com` or `.co.uk`.
- **Programs that follow another rule's route** — programs without a rule of their own whose connections take the route of one of your rules because they reach the same address.
- **Partly routed programs explained** — a program rule's details say how many of its addresses go by your address rules instead.
- **Checking a site in every zone** — a `?` rule such as `?bank.*` checks each zone of the site on its own and offers a rule just for the zones that open over the other connection.
- **A denied zone stays closed on a shared server** — when you deny a zone but route one of its sites, the zone's other sites on the same server stay denied.
- **Servers you reach by address stay on their connection** — a zone rule such as `.ru` never moves a remote desktop, an SSH server, a gateway or a site you opened earlier to the other connection.
- **Subnet rules named everywhere** — the connection trace and name lookups name the subnet or range rule a connection matched, and on Linux such a rule can no longer cover the server of your VPN by mistake.
- **Warnings for sites sharing one server program** — a rule on one site's folder cannot tell it from the others, and two folder rules on different connections that lead to one server are flagged.

**Routing and VPN**
- **A choice when the VPN drops** — the tray and the terminal interface ask whether to keep its sites blocked or let them use the main connection for this session; until you answer, nothing goes out over the main connection.
- **A stalled site tried at its other addresses** — before suggesting the additional connection, the app looks for other working addresses of the site on the same connection.
- **Choosing which connections the app may use** — rule a network connection out of the app's choices and set the order it prefers, without changing the system's network settings.
- **Network policy profiles** — named variants of rules and failure handling for work, home and other uses, without confusing them with separate saved rule-set files.
- **IPv6 connections follow a rule change at once** — open IPv6 connections move to the new route right away, as IPv4 ones do.
- **Corporate VPN through a chosen connection, kept up to date** — when your company changes the addresses of its VPN gateways, the route to them follows on its own.
- **The whole hosts file in the app** — the window and the terminal interface show the whole hosts file, not only the entries that touch your rules.

**Name lookups**
- **Warning about tampered name answers** — a notice when a public Wi-Fi network or the provider tampers with the answers about site names.
- **Forged name answers are harder to slip in** — a forged answer from a hostile network is much less likely to be taken for the real one.
- **Name lookups repeated over the same connection** — a repeated lookup goes over the connection your rules chose for the site.
- **Name lookups kept apart for each user** — one person's leak protection never changes how another person's programs look up site names.
- **Computers under a company domain policy** — if the domain policy takes over name lookups, the app says what is limited and why instead of working on quietly with weaker protection.

**Several users of one computer**
- **Settings an administrator locks** — an administrator chooses which settings and rules the other users may change on their own.
- **Open connections follow the person who signed in** — when the computer starts following another person's rules, connections already open move to that person's routes at once.
- **Warning when the window runs under another account** — the window says so and names whose rules it shows.
- **Window run as administrator keeps to its own files** — it never works from files another program in your session could have changed.
- **More privacy between users of one computer** — what the app tells one user never reveals how busy the others are.
- **Traffic per user of the machine** — how much traffic each user used, not only each connection.
- **Console for every user of the computer** — `nrr-cli` added to every user's command path with one button in the window.

**Containers and virtual machines**
- **Verified operation inside a virtual machine** — NetRuleRouter works as a local routing manager inside supported Hyper-V, VMware, VirtualBox and Linux virtual environments, with the limits of each virtual network stated explicitly.
- **Own route for containers and virtual machines** — Docker, Podman and local virtual machines get a route the way a program does, with the same protection if the connection drops, and with Everything they are held to the additional connection as tightly as the computer.
- **Own setting for Docker on Hyper-V and shared connections** — what WSL, containers and virtual machines do while the additional connection is down gets its own line for Docker Desktop on Hyper-V and for Internet Connection Sharing.

**Linux on par with Windows**
- **Dropped connections explained on Linux** — the diagnostic archive tells a connection the network dropped from one the app closed.
- **A renamed connection keeps its role on Linux** — a renamed or recreated connection keeps the role you gave it.
- **A new account starts clean** — an account created with the number of a deleted one gets none of its rules, history or confirmations.

**Diagnostics and statistics**
- **External IP change monitoring** — when you opt in, the app remembers the last observed address of an egress and reports a change or a failed check without claiming to pin the provider's address.
- **Route stability history** — a local, configurable and erasable history of failures, recoveries, egress changes and diagnostic checks helps identify recurring problems.
- **Connection check** — one button shows whether the VPN connection loses large packets and what to change in the VPN client's settings.
- **Told when a connection breaks without the app** — when connections to one server keep closing early and the app never held them back, the diagnostics say so.
- **Detailed logs for one part of the app** — detailed logging turned up for just the part involved in a problem.
- **Local network traffic counted apart** — traffic to a NAS, a printer or another computer at home shown apart from internet traffic.
- **Traffic history follows a renamed connection** — the history stays with the connection under its new name.

**Installation, access and the app itself**
- **Installing with winget and Scoop** — install and update NetRuleRouter on Windows with the package managers many people already use.
- **Builds for 32-bit computers** — versions for 32-bit Windows and 32-bit Linux, made only if users ask for them.
- **Administrator rights from the terminal interface on Windows** — Windows asks with its usual prompt, with no need to restart the terminal as administrator.
- **Stronger focus and simpler labels** — an optional thicker outline around the focused control and shorter labels, for easier reading.
- **A leaner window and tray** — a smaller download, and less code inside them that can reach your settings.
- **Instant rule changes with very large rule sets** — even with thousands of rules, a change to one takes effect at once.

## Exploring

- **Extensions through a shared API** — integrations and automation in different languages, Python among the first SDKs; permissions, isolation and optional HTML panels without a mandatory web engine in a normal installation.
- **Configuration assistant and external monitoring** — extensions propose verifiable changes and explain events; sending configuration to external services needs consent, automatic actions need pre-approved conditions.
- **Port and protocol rules** — combinations of application, address, domain, destination port and protocol with clear precedence.
- **Lightweight Linux and OpenWrt** — assess core portability, networking mechanisms, memory and agent size after higher-priority Linux work.
- **Remote management** — protected access to one instance's web interface; managing multiple instances and organisational policies is a separate direction.

Ideas we are looking into before promising them.

- **Per-domain DNS policies (Split DNS)** — choosing DNS for corporate, home and public domains while respecting multiple VPNs, managed system policies and protection against sending internal names to an external resolver.
- **A local NetRuleRouter SOCKS server** — a separate incoming endpoint for applications that can use SOCKS themselves; this is not the same as using an existing proxy as an egress.
- **Managed SSH dynamic forwarding** — creating a SOCKS egress over SSH with host-key verification, safe credential storage, health checks and bounded recovery after a failure.
- **More than two egress connections** — simultaneous selection among Direct, several VPNs and proxies with deterministic priorities and diagnostics for each path.
- **True process-bound egress** — exploring Windows and Linux mechanisms that can send two applications to different egresses even when they contact the same address, without letting the first unknown connection use the ordinary route.
- **PAC and browser integration or transparent redirection** — comparing a limited browser path with a system mechanism for applications without proxy support, including DNS, UDP, loops and fail-closed behaviour.
- **VPN Integration API** — a way for supported clients to report state, the active interface and safe reconnect events without guessing from an adapter name.
- **Gateway for home network devices** — a computer running NetRuleRouter routes the traffic of a phone, a TV and other devices by the same rules.
- **Gateway for virtual machines, Proxmox and LXC** — a separate NetRuleRouter instance applies network policy to several guests or containers while accounting for NAT, DNS, IPv6 and limited visibility into applications inside a guest.
- **NetRuleRouter on your VPN server** — installed on a server running WireGuard or AmneziaWG, it routes the traffic of that server's clients by your rules — a phone, a laptop, or a home router connected to the server — with nothing to install on them.
- **Remote Web UI** — protected management of one remote NetRuleRouter instance; by itself this does not imply central management of several machines.
- **Central management** — distributing and locking policies, monitoring multiple instances, audit and corporate-monitoring integration without turning NetRuleRouter into a hypervisor or VDI platform.
- **Running on OpenWrt routers** — if you know how NetRuleRouter would fit on a router — memory, storage, the firewall — we will be glad to hear it.

### Plugin system and SDKs

The goal is to extend NRR for specific needs without changing its core:
VPN-client integrations, network monitoring, automation, additional interfaces
and external services. Browser extensions and NRR plugins are separate
components; installing one does not imply installing the other.

Plugin API will be language-independent. Python is among the first proposed
official SDKs; Rust, JavaScript/TypeScript and other languages use the same
contract. Plugins declare compatibility and required permissions. Users can
review their actions and manage installation, updates, stopping and removal.
An extension failure must not stop routing or weaken protection. Third-party
logic runs separately from the privileged service; Python and a web engine
are needed only by users of the corresponding extensions.

Five capability categories are being explored. They describe permissions,
not a promise to deliver every category in the next release:

| Category | Capabilities |
|---|---|
| Information | Read permitted diagnostics and network state |
| Integration | Work with VPN clients, applications and external APIs |
| Automation | Act within pre-approved, limited policies |
| Transport | Additional network egresses and transport integrations |
| Management | Multiple instances and organisational policies |

A transport extension gets neither arbitrary service privileges nor permission
to install drivers. Architecture, access boundaries, version compatibility
and failure behaviour must be validated before implementation.

### Isolated application environments

**Status: exploring.** After network policy and the integration API are stable,
NRR may integrate with existing application-isolation tools rather than build a
sandbox engine of its own. No particular isolation product or release is
promised yet.

The direction is to let a user launch selected desktop applications and their
supported child processes in an isolated environment with:

- a chosen NRR route and explicit behaviour when that route is unavailable;
- no silent fallback to another connection when isolation is required;
- controlled access to localhost, local networks and virtual networks;
- coverage of IPv4, IPv6, TCP, UDP, DNS and WebRTC where the platform supports it;
- separate language, locale, time zone and other supported regional settings,
  using System, Manual or Follow route values;
- diagnostics that distinguish requested, applied, unsupported and unverified
  protection.

If a user requires isolation, an unavailable sandbox, adapter or route must not
turn into an ordinary unprotected launch. The feature remains optional, and
normal NRR routing must not depend on an isolation tool being installed.

Browser extensions and application isolation cover different boundaries: an
extension can control supported browser settings for individual sites, while an
isolated environment covers a desktop process and its supported descendants.
NRR remains responsible for the actual network route in both cases.

This direction is not a promise of anonymity, a complete disguise of the host
operating system, or a guaranteed result from regional, anti-fraud or scoring
systems.

### Extension panels in the window and browser

Plugins may offer optional HTML/CSS/JavaScript panels in the desktop app and
Web UI. We will explore reusing a panel in both interfaces, isolation between
plugins and a restricted NRR API. Panels have no direct access to privileged
internal objects. Simple extensions can use standard native cards without HTML.

The embedded web component will be selected after comparing installation size,
memory, isolation, Windows/Linux support and on-demand loading. Users without
these panels should not need the additional installation dependencies.

### VPN-client integrations

The existing VPN Integration API direction covers client discovery, reliable
connection state, active interfaces and reconnect events. Further research
covers selecting profiles and permitted operations through supported APIs or
documented client mechanisms. Help with client installation and initial setup
is assessed separately. NRR continues to manage routes over existing
connections rather than becoming a VPN provider.

### Configuration in ordinary language

An optional assistant extension will let users describe their desired network
setup. It can analyse permitted configuration, find settings, propose rules
and groups, explain conflicts and preview changes. Application goes through
NRR's standard checks and confirmation. Sending configuration to an external
AI service needs separate consent; the assistant receives no direct
administrative authority and is not part of the base service.

### External monitoring events

A separate monitoring app can send observations about external IP, DNS,
WebRTC and other connection parameters through Plugin API, including for
users of AI services. Building the monitor is a separate project; NRR's role
is to receive permitted events and react to them.

Potential reactions include address-change and unexpected-egress warnings,
diagnostic checks, temporary protective policies and blocking new connections
of a selected program or destination. Automatic reactions need pre-approved
conditions, verifiable signals, allowance for false positives and safe reversal.
A third-party rating alone is not evidence of account-blocking risk.

### Ports, protocols and combined conditions

We will explore routing by destination port and supported protocol, including
application plus address/domain plus port plus protocol. This needs clear
precedence for overlapping rules and validation of each OS's capabilities.
It does not replace existing SOCKS5/HTTP CONNECT egress support planned before
the full release.

### Lightweight agent and OpenWrt

We will assess reusing the rule engine and Linux backend on compact systems,
including OpenWrt, without GUI, TUI or optional components. The investigation
covers dependencies, memory, CPU, binary size, nftables/firewall4 compatibility
and router networking. Its results will determine whether a separate lightweight
agent makes sense. Neither a core rewrite nor OpenWrt compatibility is promised
in advance; Linux desktop/server parity remains the earlier priority.

macOS comes after Linux; its own plan will appear here once the port starts.

## Contributing

Pull requests are welcome: for items on this plan, for bug fixes, and for
ideas that are not described here yet. For a larger change, open an issue first
so the approach can be agreed — see [CONTRIBUTING](CONTRIBUTING.md).
