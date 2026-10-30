# Roadmap

Where NetRuleRouter is heading. There are no dates: an item ships when it is
ready and has been tested on real machines.

What already works is listed under **Highlights** in the [README](README.md).

## First public alpha: Windows and Linux

**Linux.** Ships in this alpha next to Windows, as `.deb`, `.rpm` and
`.tar.gz` packages. What remains is checking more distributions and ARM
machines; [Supported systems](docs/en/supported-systems.md) says which ones are
checked.

## Before the stable version

The stable version comes once every promise below holds on real machines.

| What | What it gives you |
|---|---|
| Full IPv6 | Rules already name IPv6 addresses and names that resolve to them, and route and protect them as they do IPv4. This is verified on real IPv6 networks before it is called finished |
| Sites protected from the first second of startup | With leak protection set to Routed sites, the sites your rules protect are held back from the moment the computer starts, as everything is with Everything |
| Protection back on its own after a Windows firewall restart | If the Windows firewall service restarts while NetRuleRouter runs, the protection is put back at once and the window tells you, so the computer is never left unprotected |
| A site's new address protected the moment it appears | When a site your rules protect moves to a new address, the protection covers it at once rather than a few seconds later, even if the VPN drops in that very moment |
| Same protection on Linux when a connection drops | When the additional connection is down, ordinary sites on Linux stay reachable while the ones your rules protect stay closed, as on Windows |
| Strict network checks on RHEL-family systems | On RHEL, RED OS, AlmaLinux and similar systems with strict network checks turned on, the sites your rules send over the additional connection keep working for every user of the computer |
| Every promise checked before each release | Each promise in the README and the guide — nothing leaks while protection is on, rules route traffic as written, your rules and settings survive an update, users of one computer stay apart, name lookups are given back — has automatic checks that try to break it before every release |

## Development plan

The order is approximate: an item may ship sooner, later, or turn out not to be
needed. If you need something from the list, or something that is not in it,
open an issue and describe what you are trying to do — that can raise its
priority.

### Checks and recovery

| What | What it gives you | Priority |
|---|---|---|
| Checking a site over both connections | The site check, which today tries a site over the connection your rules choose for it, also tries it over the other one and tells you which connection lets the server through: neither, so the server itself is down; only the other one, so your provider or VPN holds it back, with an offer to move the rule; or the one your rules choose, so it works now. After the first setup, the same check runs over the sites you added, so you see the result straight away | high |
| Public Wi-Fi sign-in with leak protection on Everything | The app recognises the sign-in page of a public Wi-Fi network and opens a short window to sign in, after which full protection returns | high |
| First connection after a VPN reconnect | Right after the VPN reconnects, the first connection to a site your rules send over it goes through the new connection instead of failing once | high |
| Pages come back after the VPN returns | A page that could not open while the additional connection was down opens again on its own once the connection is back, with no manual reload | medium |

### Working alongside other VPNs and programs

| What | What it gives you | Priority |
|---|---|---|
| Own secure DNS for one program | A program with its own encrypted DNS, such as a corporate client or a game, keeps working while protection stays on for every other program | high |
| Notice when another program removes your routes | When another program, such as a corporate VPN that enforces its own routes, keeps removing the routes your rules need, the window and the terminal interface tell you once which sites are affected and which program is in the way | high |
| Warning about another program's wide route | When another program, such as a virtual machine manager, takes over a whole range of addresses, the app shows which addresses it swallows and offers to remove that route, so a server or site that would not open works again | high |
| Tidy list of VPN connections | Some VPN programs install dozens of identical connections. The list shows them as one line with the copy in use, and offers to remove the copies the VPN never uses, only with your consent | medium |

### Linux on par with Windows

| What | What it gives you | Priority |
|---|---|---|
| Sites that share an address, routed apart on Linux too | Two sites that live on one server address can go over different connections on Linux, as they already can on Windows: the one your rules send through the VPN goes through it, its neighbour stays direct | high |

### Rules

| What | What it gives you | Priority |
|---|---|---|
| Updates to imported rule sets | When a new version adds addresses to a rule set you imported (new addresses of `site.com`, say), the app offers the update and shows what changed. Nothing changes without your consent | medium |
| Ready-made templates for common setups | Templates for common setups, such as a work VPN for the company's own sites and addresses: you fill in your own names and addresses, and the app adds the rules | medium |
| Rules by the account a service runs under | Sites and services that run inside one server program can still go over different connections, by the account each one runs under, such as a separate application pool per site. Needs administrator rights; system accounts stay protected | medium |
| Rules for the whole computer | One set of rules for every program on the computer, including services and programs that run with nobody signed in. An administrator turns it on | medium |
| Installing a program without network access | Start an installer from the window or the terminal interface, and neither it nor anything it starts can reach beyond your computer until the installation ends. The network comes back on its own, and the app offers rules for the program it installed. An Explorer context-menu item will follow if users ask for it | medium |

### Name lookups

| What | What it gives you | Priority |
|---|---|---|
| DNS rebinding protection | A web page cannot reach your router and home devices through the browser. Names your network legitimately points at local addresses keep working, and anything held back can be allowed with one click | medium |
| Name lookups wait too when the VPN drops | With leak protection set to Everything, while the additional connection is down even the look-ups of site names wait for it instead of going out over the main connection | medium |

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

## Later

Planned as well; these move up as users ask for them.

**Rules and suggestions**
- **Speed limits** — cap the download and upload speed of a chosen program, address, subnet or site, each direction on its own, and lift the cap for a while with one click.
- **History of rule changes** — every rule added, removed or changed, with when and from where, and any one change undone on its own.
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
- **Own route for containers and virtual machines** — Docker, Podman and local virtual machines get a route the way a program does, with the same protection if the connection drops, and with Everything they are held to the additional connection as tightly as the computer.
- **Own setting for Docker on Hyper-V and shared connections** — what WSL, containers and virtual machines do while the additional connection is down gets its own line for Docker Desktop on Hyper-V and for Internet Connection Sharing.

**Linux on par with Windows**
- **Dropped connections explained on Linux** — the diagnostic archive tells a connection the network dropped from one the app closed.
- **A renamed connection keeps its role on Linux** — a renamed or recreated connection keeps the role you gave it.
- **A new account starts clean** — an account created with the number of a deleted one gets none of its rules, history or confirmations.

**Diagnostics and statistics**
- **Connection check** — one button shows whether the VPN connection loses large packets and what to change in the VPN client's settings.
- **Told when a connection breaks without the app** — when connections to one server keep closing early and the app never held them back, the diagnostics say so.
- **Detailed logs for one part of the app** — detailed logging turned up for just the part involved in a problem.
- **Local network traffic counted apart** — traffic to a NAS, a printer or another computer at home shown apart from internet traffic.
- **Traffic history follows a renamed connection** — the history stays with the connection under its new name.

**Installation, access and the app itself**
- **Installing with winget and Scoop** — install and update NetRuleRouter on Windows with the package managers many people already use.
- **Administrator rights from the terminal interface on Windows** — Windows asks with its usual prompt, with no need to restart the terminal as administrator.
- **Stronger focus and simpler labels** — an optional thicker outline around the focused control and shorter labels, for easier reading.
- **A leaner window and tray** — a smaller download, and less code inside them that can reach your settings.
- **Instant rule changes with very large rule sets** — even with thousands of rules, a change to one takes effect at once.

## Exploring

Ideas we are looking into before promising them.

- **Gateway for home network devices** — a computer running NetRuleRouter routes the traffic of a phone, a TV and other devices by the same rules.
- **NetRuleRouter on your VPN server** — installed on a server running WireGuard or AmneziaWG, it routes the traffic of that server's clients by your rules — a phone, a laptop, or a home router connected to the server — with nothing to install on them.
- **Running on OpenWrt routers** — if you know how NetRuleRouter would fit on a router — memory, storage, the firewall — we will be glad to hear it.

macOS comes after Linux; its own plan will appear here once the port starts.

## Contributing

Pull requests are welcome: for items on this plan, for bug fixes, and for
ideas that are not described here yet. For a larger change, open an issue first
so the approach can be agreed — see [CONTRIBUTING](CONTRIBUTING.md).
