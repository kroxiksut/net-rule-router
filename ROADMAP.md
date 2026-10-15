# Roadmap

Where NetRuleRouter is heading. The order below is the order of work, not a
schedule: there are no dates, and an item moves only when it is ready to ship
and has been tested on real machines. Something missing that you need? Open an
issue and describe what you are trying to do.

What already works is listed under **Highlights** in the [README](README.md).

## Now

**Linux.** The platform-specific pieces sit behind one interface per
capability, so the shared decision logic already runs unchanged; what remains
is finishing the Linux side and testing it to release level.

**Full IPv6.** Rules already name IPv6 addresses and names that resolve to
them, and route and protect them as they do IPv4. What remains is verifying it
on real IPv6 networks before calling it finished.

**First public alpha** for Windows.

## Right after the first alpha

**"Is it the server or is it us?"** When a program cannot connect somewhere, a
list shows which servers did not answer recently and whether NetRuleRouter had
anything to do with it. One button checks each of them over the main
connection and, if you have one, over the additional connection too, and tells
you plainly: the server does not answer at all, only one of your connections
lets it through, or it works now.

**Data plan warning.** VPN subscriptions and mobile plans come with a limit,
and NetRuleRouter is the one place that knows how much of it the additional
connection used. Set the limit and the day your billing period starts, and get
a notice as usage approaches it. It only warns: routing does not change.

**Rules for the whole machine.** One set of rules for every program on the
computer, system services included, and for servers where nobody is signed in.
Today the rules follow the person at the keyboard.

**Routing for other devices on your network** (Linux). A computer running
NetRuleRouter routes, by the same rules, the traffic of devices that cannot run
it themselves: a phone, a TV, the clients of your own VPN server.

**Protection from DNS rebinding.** A malicious web page can try to reach your
router, printer or other devices at home through your browser by pointing its
own name at a local address. NetRuleRouter will refuse such answers before your
programs see them, while names that your company or your home network
legitimately point at local addresses keep working. Anything it holds back is
shown to you, with one click to allow it.

**Know when the service stops.** If the NetRuleRouter background service stops
or fails, the window, the tray and the terminal interface say so at once and
offer two choices: start it again, or restore the network without it.

**A warning when name answers are altered on the way.** If something between
you and the internet, a public Wi-Fi network or a provider, replaces the
answers about site names, NetRuleRouter notices and tells you which names were
affected. It only reports: your routing does not change.

**Let one program keep its own secure DNS.** When a program needs its own
encrypted DNS, a corporate client or a game for example, you can allow just that
program without turning the protection off for every other one, straight from
the notice that it was blocked.

**Traffic over time, per connection.** How much went through the additional
connection and how much went directly, over a day, a week or a month.

## Once real-world usage data is in

**Suggestions for programs, not only for sites.** Today NetRuleRouter suggests
addresses that fail over the main connection. A program with no rule of its
own will get the same offer: move it to the additional connection. It waits for
usage data because a suggestion that fires too often is worse than none.

**A connection check.** When a site or a remote desktop session works directly
but stalls through a VPN, one button tells you whether the VPN connection
itself drops large packets, and what to change in the VPN client's settings if
it does. If it does not, you know the cause is elsewhere. It only reports:
NetRuleRouter changes nothing in the VPN's settings. It comes as people ask
for it.

**Updates to the rule sets you imported.** When a new version of NetRuleRouter
ships an updated version of a ready-made rule set you once imported, it offers
the update and shows what changed. Nothing changes without your consent.

## Later

**macOS**, after Linux.

**Package repositories for Linux**, so that installation and updates come
through the usual `apt upgrade` / `dnf upgrade`; later, the Astra Linux and
RED OS application stores.

**Traffic per user of the machine**, not only per connection: Linux first,
Windows later.

**Containers and virtual machines on a route of their own** (Linux first).
Docker and Podman containers and local virtual machines get a route the way a
program does: all of their traffic over the additional connection, or only the
sites your rules name, with the same protection when that connection drops.
