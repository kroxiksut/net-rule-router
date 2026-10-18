# Known limitations

**English** · [Русский](../ru/known-limitations.md)

This release still has gaps. Each one is listed here with what it means for
you and what to do about it, and it stays on this page until it is fixed.

## Right after the computer starts

Until the service has applied your rules — usually a few seconds after the
system starts — leak protection is not in force yet, and traffic for sites
routed through the additional connection can go over the main one.

## Sites that share one server address

Large platforms and content delivery networks serve many sites from the same
addresses. Without virtual addresses (fake-IP) such sites cannot be told
apart: a site you did not route can go through the additional connection
together with a routed one, or a routed site can go over the main connection.
Virtual addresses are available on Windows and are off by default — see
[Per-site routing with virtual addresses](fake-ip.md). On Linux routing
decides per address for now.

## Applications that look up names on their own

A rule for a site name works through the system's name lookups. An
application that bypasses them — for example with its own encrypted DNS that
NetRuleRouter does not recognise — is not covered by such a rule while leak
protection is off. Give the application a rule of its own, or turn leak
protection on.

## Leak protection on Windows reaches other users

While leak protection blocks everything for one user, IPv6, ping and VPN
protocols such as IPsec are held back for every user of the computer, not only
for that one. The other signed-in users are told when this happens.

## Public Wi-Fi sign-in pages

With leak protection set to block everything, the sign-in page of a public
Wi-Fi network (a hotel, an airport, a train) cannot open, so the additional
connection cannot come up there. Switch leak protection off for the sign-in
and back on once you are connected.

## Strict reverse-path filtering on Linux

On Linux systems that turn on strict reverse-path filtering (common on RED OS
and the RHEL family), a second signed-in user may get no replies from sites
routed through the additional connection. This has not been checked on a live
system yet.

## When the service stops unexpectedly

The tray and the window do not yet offer a way back when the service stops on
its own. Start it again in **Settings → Service management**; if the network
does not work afterwards, use **Restore network** on the same page — see
[Recovering network access](recovering-network-access.md).
