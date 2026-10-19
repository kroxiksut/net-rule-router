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
| Package repositories for Linux | Installs and updates the way your distribution does it: `apt` on Ubuntu and Debian, `dnf` on Fedora, RHEL, AlmaLinux and Rocky Linux, `zypper` on openSUSE, the AUR on Arch Linux, then the Astra Linux and RED OS app stores | medium |
| NetRuleRouter on your VPN server | Installed on a server running WireGuard or AmneziaWG, it routes the traffic of that server's clients by your rules — a phone, a laptop, or a home router connected to the server — with nothing to install on them. We will verify the setup and describe it step by step | medium |
| Up-to-date libraries | The libraries for checksums, signatures and data encoding move to their current versions, while rules and the audit trail saved by earlier versions keep working unchanged | medium |
| Installing a program without network access | Start an installer from the window or the terminal interface, and neither it nor anything it starts can reach beyond your computer until the installation ends. The network comes back on its own, and the app offers rules for the program it installed. An Explorer context-menu item will follow if users ask for it | medium |
| Gateway for home network devices | A computer running NetRuleRouter routes the traffic of a phone, a TV and other devices by the same rules | low |
| Warning about tampered name answers | A notice when a public Wi-Fi network or the provider tampers with the answers about site names | low |
| Own route for containers and virtual machines | Docker, Podman and local virtual machines get a route the way a program does, with the same protection if the connection drops | low |
| Traffic per user of the machine | How much traffic each user of the computer used, not only each connection | low |
| Data plan limit warning | A notice when the additional connection's usage nears the limit of a VPN subscription or a mobile plan | low |
| Suggestions for programs | A program whose connections do not get through on the main connection is offered a move to the additional one, as sites are today | low |
| Connection check | One button shows whether the VPN connection loses large packets and what to change in the VPN client's settings | low |
| History of rule changes | Every rule added, removed or changed, with when and from where, and any one change undone on its own | low |
| Administrator rights from the terminal interface on Windows | When a change made in the terminal interface needs administrator rights, Windows asks for them with its usual prompt, with no need to restart the terminal as administrator | low |
| Traffic charts by connection | The traffic statistics you can already export, as a chart in the window | low |
| Running on OpenWrt routers | Not researched yet. If you know how NetRuleRouter would fit on a router — memory, storage, the firewall — we will be glad to hear it | — |

macOS comes after Linux; its own plan will appear here once the port starts.

## Contributing

Pull requests are welcome: for items on this plan, for bug fixes, and for
ideas that are not described here yet. For a larger change, open an issue first
so the approach can be agreed — see [CONTRIBUTING](CONTRIBUTING.md).
