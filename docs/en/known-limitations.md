# Known limitations

**English** · [Русский](../ru/known-limitations.md)

This release still has gaps. Each one is listed here with what it means for
you and what to do about it, and it stays on this page until it is fixed.
Ran into one that is not listed? Open an
[issue](https://github.com/kroxiksut/net-rule-router/issues) or ask in the
Telegram channel [t.me/netrulerouter](https://t.me/netrulerouter).

## Right after the computer starts

With leak protection set to **Routed sites**, until the service has applied
your rules — usually a few seconds after the system starts — the protection is
not in force yet, and traffic for sites routed through the additional
connection can go over the main one. With **Everything** this gap is closed:
the internet waits from the moment the computer starts until the service is
running.

## Which VPNs can be the additional connection

NetRuleRouter routes through any VPN that appears on the computer as a network
connection of its own: WireGuard, OpenVPN and most VPN apps that install a
network adapter. A VPN that works only as a proxy or a browser extension has
no such connection and cannot be the additional connection. The VPN
connections built into Windows (IKEv2, L2TP, PPTP, SSTP) steer their routes
themselves, so routing chosen sites through them is not promised in this
release; next to your additional connection they keep working as a corporate
VPN (see [VPN client detection](vpn-detection.md)).

## Sites that share one server address

Large platforms and content delivery networks serve many sites from the same
addresses. Without virtual addresses (fake-IP) such sites cannot be told
apart: a site you did not route can go through the additional connection
together with a routed one, or a routed site can go over the main connection.
Virtual addresses are available on Windows and are on by default for a new
installation; an installation that had them off keeps them off — see
[Per-site routing with virtual addresses](fake-ip.md). On Linux routing
decides per address for now.

## Applications that look up names on their own

A rule for a site name works through the system's name lookups. An
application that bypasses them — for example with its own encrypted DNS that
NetRuleRouter does not recognise — is not covered by such a rule while leak
protection is off. Give the application a rule of its own, or turn leak
protection on.

## A blocked program and a proxy on the same computer

A program you block can still talk to other programs on the same computer. If
a local proxy or VPN client runs there and forwards traffic for it, that
traffic leaves under the proxy's name, not the blocked program's. Block the
proxy too, or give it a rule of its own.

## Application rules on Linux

On Linux an application rule follows what the program has been seen
connecting to. A denied program is stopped on those addresses; a connection it
makes to a new address before it is recognised can still get through. Deny
rules for sites, addresses and networks do not depend on this.

## Leak protection on Windows reaches other users

While leak protection set to **Everything** holds one user's traffic back,
IPv6, ping and VPN protocols such as IPsec are held back for every user of the
computer, not only for that one. The other signed-in users are told when this happens.

## Public Wi-Fi sign-in pages

With leak protection set to **Everything**, the sign-in page of a public
Wi-Fi network (a hotel, an airport, a train) cannot open, so the additional
connection cannot come up there. Set leak protection to **Off** for the
sign-in and back to **Everything** once you are connected.

## Computers managed by Group Policy for DNS

On a Windows computer joined to a domain, where Group Policy manages how DNS
names are resolved, Windows may ignore the local DNS resolver that
NetRuleRouter sets up. A rule for a site name then takes effect only after the
first connection to that site, so that first connection can go over the main
connection, and virtual addresses (fake-IP) do not work. The app does not
recognise such a computer yet and keeps showing the local resolver as in use.
Rules for addresses and subnets are not affected: for a site whose very first
connection matters, route its address. Home computers are normally not
affected.

## Names that never leave the computer

Entries in the `hosts` file and local-network names ending in `.local` are
answered on the computer itself, without a DNS query, so a rule for such a
name does not see them. Route the address instead. On systems that run the
name service cache (`nscd`, common on the RHEL family, RED OS among it) an answer it
already holds is used until it expires; NetRuleRouter clears that cache when
it takes over name lookups and when it gives them back.

## A provider that changes DNS answers

Some providers answer name lookups for certain sites with an address that
leads nowhere. NetRuleRouter asks another resolver for those names and routes
them correctly anyway. The Diagnostics screen tells you when this is
happening on your connection and for how many sites.

## What "Everything" holds for system programs

Leak protection "Everything" holds the programs you run. The computer's own
services — updates, time synchronisation, the name lookups the system makes
for everyone — and, on Linux, every program running as root are held only
for the addresses your rules name: their other traffic still goes over the
main connection while the additional connection is down.

## Site names while everything is held

With leak protection "Everything" and the additional connection down, the
computer still looks up site names over the main connection, so that sites
work again the moment the connection returns. The DNS servers of the main
connection, usually your provider's, then see which sites you open, including
the ones your rules send through the additional connection; the traffic
itself stays held. To prevent it, turn off "While everything is held, look up
site names over the main connection" in the routing settings: name lookups
are then blocked too, and nothing works until the additional connection
returns.

## Name lookups are shared by the computer

Name resolution belongs to the computer as a whole, not to one person. When
several people are signed in, lookups follow the rules of the person who
signed in first, so another user's sites may be resolved by those rules
rather than their own. See [Several users on one computer](several-users.md).

## Routes on Windows are shared by the computer

Windows keeps one route table for the whole computer. An address that one
signed-in user's rules send through their additional connection takes that
connection for the other signed-in users whose own rules do not name it.
When everyone uses the same additional connection this changes nothing; with
different VPNs, or a user without one, another user's traffic to that address
goes through a connection they did not choose. See
[Several users on one computer](several-users.md#windows-one-shared-route-table).

## Strict reverse-path filtering on Linux

On Linux systems that turn on strict reverse-path filtering (common on the RHEL
family, RED OS among it), a second signed-in user may get no replies from sites
routed through the additional connection. This has not been checked on a live
system yet.
