# Roadmap

Where NetRuleRouter is heading. There are no dates: an item ships when it is
ready and has been tested on real machines.

What already works is listed under **Highlights** in the [README](README.md).

## First public alpha: Windows and Linux

**Linux.** The platform-specific pieces sit behind one interface per
capability, so the shared decision logic already runs unchanged; what remains
is finishing the Linux side and testing it to release level, on x86-64 and ARM.

**Full IPv6.** Rules already name IPv6 addresses and names that resolve to
them, and route and protect them as they do IPv4. What remains is verifying it
on real IPv6 networks before calling it finished.

## Development plan

The order is approximate: an item may ship sooner, later, or turn out not to be
needed. If you need something from the list, or something that is not in it,
open an issue and describe what you are trying to do — that can raise its
priority.

| What | What it gives you | Priority |
|---|---|---|
| Checking a site that does not open | One button checks the server over the main and the additional connection and tells you what is going on: the server does not answer at all, only one of your connections lets it through, or everything works now | high |
| Network recovery when the service stops | If the background service stops, the window, the tray and the terminal interface say so at once and offer to start it again or to restore the network without it | high |
| Own secure DNS for one program | A program with its own encrypted DNS, such as a corporate client or a game, keeps working while protection stays on for every other program | high |
| New version notice | The app tells you when a new version is out, on request or on its own every two weeks; the automatic check can be turned off | medium |
| Updates to imported rule sets | When a new version adds addresses to a rule set you imported (new addresses of `site.com`, say), the app offers the update and shows what changed. Nothing changes without your consent | medium |
| DNS rebinding protection | A web page cannot reach your router and home devices through the browser. Names your network legitimately points at local addresses keep working, and anything held back can be allowed with one click | medium |
| Connections chosen at installation | A silent installation names the main and the additional connection, so identical computers route by your rules right after setup, with nothing to click | medium |
| Leak protection chosen at installation | A silent installation sets the level of leak protection, so every user of every computer is protected from their first sign-in | low |
| Package repositories for Linux | Installs and updates the way your distribution does it: `apt` on Ubuntu and Debian, `dnf` on Fedora, RHEL, AlmaLinux and Rocky Linux, `zypper` on openSUSE, the AUR on Arch Linux, then the Astra Linux and RED OS app stores | medium |
| Installers for ARM computers | The EXE and MSI installers for Windows on ARM and the `.deb` and `.rpm` packages for 64-bit ARM Linux, once they are tested on real ARM machines. Until then, ARM computers use the portable builds | medium |
| NetRuleRouter on your VPN server | Installed on a server running WireGuard or AmneziaWG, it routes the traffic of that server's clients by your rules — a phone, a laptop, or a home router connected to the server — with nothing to install on them. We will verify the setup and describe it step by step | medium |
| Up-to-date libraries | The libraries for checksums, signatures and data encoding move to their current versions, while rules and the audit trail saved by earlier versions keep working unchanged | medium |
| Installing a program without network access | Start an installer from the window or the terminal interface, and neither it nor anything it starts can reach beyond your computer until the installation ends. The network comes back on its own, and the app offers rules for the program it installed. An Explorer context-menu item will follow if users ask for it | medium |
| Rules by the account a service runs under | Sites and services that run inside one server program can still go over different connections, by the account each one runs under, such as a separate application pool per site. Needs administrator rights; system accounts stay protected | medium |
| Same protection on Linux when a connection drops | When the additional connection is down, ordinary sites on Linux stay reachable while the ones your rules protect stay closed, as on Windows | medium |
| Protection back on its own after a Windows firewall restart | If the Windows firewall service restarts while NetRuleRouter runs, the protection is put back at once and the window tells you, so the computer is never left unprotected | medium |
| Strict network checks on RHEL-family systems | On RHEL, RED OS, AlmaLinux and similar systems with strict network checks turned on, the sites your rules send over the additional connection keep working for every user of the computer | medium |
| Pages come back after the VPN returns | A page that could not open while the additional connection was down opens again on its own once the connection is back, with no manual reload | medium |
| Rules for the whole computer | One set of rules for every program on the computer, including services and programs that run with nobody signed in. An administrator turns it on | medium |
| Name lookups wait too when the VPN drops | With leak protection set to Everything, while the additional connection is down even the look-ups of site names wait for it instead of going out over the main connection | medium |
| Gateway for home network devices | A computer running NetRuleRouter routes the traffic of a phone, a TV and other devices by the same rules | low |
| Warning about tampered name answers | A notice when a public Wi-Fi network or the provider tampers with the answers about site names | low |
| Own route for containers and virtual machines | Docker, Podman and local virtual machines get a route the way a program does, with the same protection if the connection drops | low |
| Name lookups kept apart for each user | When several people use the computer at the same time, one person's leak protection never changes how another person's programs look up site names | low |
| Traffic per user of the machine | How much traffic each user of the computer used, not only each connection | low |
| Containers held as tightly as the computer | With leak protection set to Everything and the additional connection as the default route, WSL, containers and virtual machines are kept to it just as the computer itself is | low |
| More privacy between users of one computer | What the app tells one user never reveals how busy the other users of the computer are | low |
| Window run as administrator keeps to its own files | When you start the window as administrator, it works only from files it creates itself, never from files another program in your session could have changed | low |
| Stronger focus and simpler labels | An optional thicker outline around the focused control and shorter labels in the window, for easier reading | low |
| Data plan limit warning | A notice when the additional connection's usage nears the limit of a VPN subscription or a mobile plan | low |
| Suggestions for programs | A program whose connections do not get through on the main connection is offered a move to the additional one, as sites are today | low |
| Connection check | One button shows whether the VPN connection loses large packets and what to change in the VPN client's settings | low |
| History of rule changes | Every rule added, removed or changed, with when and from where, and any one change undone on its own | low |
| Notice when another program removes your routes | When another program, such as a corporate VPN that enforces its own routes, keeps removing the routes your rules need, the window and the terminal interface tell you once which sites are affected and which program is in the way | low |
| Warning about another program's wide route | When another program, such as a virtual machine manager, takes over a whole range of addresses, the app shows which addresses it swallows and offers to remove that route, so a server or site that would not open works again | low |
| Console for every user of the computer | `nrr-cli` can be added to the command path of every user of the computer, not only your own account, with one button in the window | low |
| Administrator rights from the terminal interface on Windows | When a change made in the terminal interface needs administrator rights, Windows asks for them with its usual prompt, with no need to restart the terminal as administrator | low |
| Traffic charts by connection | The traffic statistics you can already export, as a chart in the window and the terminal interface | low |
| Name lookups repeated over the same connection | When a lookup of a site name has to be repeated, the repeat goes over the same connection as the first attempt — the one your rules chose for the site | low |
| Computers under a company domain policy | If the company's domain policy takes over name lookups on the computer, the app notices it and tells you in the window and the terminal interface what is limited and why, instead of working on quietly with weaker protection | low |
| IPv6 connections follow a rule change at once | After you change a rule, connections already open over IPv6 move to the new route right away, as IPv4 ones do, on Windows and on Linux | low |
| Warning about a rule that is already covered | When you add a rule for a site or program that another rule already covers, the app names that rule and asks whether to add the new one anyway | low |
| A leaner window and tray | The window and tray carry only the code they need, so the download is smaller and less code inside them can reach your settings | low |
| Forged name answers are harder to slip in | A forged answer to a name lookup from a hostile network is much less likely to be taken for the real one | low |
| Corporate VPN through a chosen connection, kept up to date | When your company changes the addresses of its VPN gateways, the route to them follows on its own, with no rule to edit by hand | low |
| Warnings for sites sharing one server program | When several sites are served by one web server program, the app tells you that a rule on one site's folder cannot tell them apart, and warns when two folder rules on different connections lead to the same server | low |
| Installing with winget and Scoop | Install and update NetRuleRouter on Windows with the package managers many people already use, without downloading a file by hand | low |
| Instant rule changes with very large rule sets | Even with thousands of rules, a change to one of them takes effect at once, without the whole set being worked out again | low |
| Rules that follow the programs a program starts | A rule for a program also covers what it starts, such as a launcher and the game it opens | low |
| Adding suggestions on its own for one site | For a site you trust, the app adds the addresses it suggests by itself, while other sites keep asking first | low |
| Running on OpenWrt routers | Not researched yet. If you know how NetRuleRouter would fit on a router — memory, storage, the firewall — we will be glad to hear it | — |

macOS comes after Linux; its own plan will appear here once the port starts.

## Contributing

Pull requests are welcome: for items on this plan, for bug fixes, and for
ideas that are not described here yet. For a larger change, open an issue first
so the approach can be agreed — see [CONTRIBUTING](CONTRIBUTING.md).
