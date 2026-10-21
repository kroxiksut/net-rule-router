# Per-site routing with virtual addresses (fake-IP)

[Russian](../ru/fake-ip.md)

NetRuleRouter routes traffic per site. But many sites live behind shared
infrastructure — a content delivery network can answer dozens of unrelated
sites from the same IP address. When two sites share one address, a decision
made per address cannot tell them apart: routing or protecting one would affect
the other. The fake-IP feature removes that ambiguity.

## What it does for you

When fake-IP is on, each routed site is answered with its **own** private
address instead of its real one. Because every site now has a distinct address,
routing and leak protection become truly per-site again, even for sites that
share a real server address. Two consequences you can rely on:

- **No collateral.** Routing or protecting one site can no longer affect
  another site that merely happens to share its real address.
- **No first-connect race.** The routing decision for a site is in place before
  the site's very first connection leaves your computer, so the first request
  is never sent the wrong way while protection catches up.

The feature works without inspecting or decrypting your traffic. It never acts
as a "man in the middle": encrypted connections stay end-to-end encrypted, and
no certificates are installed.

## What it needs

Fake-IP builds on the **local DNS resolver** — it is the resolver that hands
each site its private address — so it is offered only while the local DNS
resolver is the routing method. That is the default; with the legacy method
(watching system DNS) the checkbox is not shown.

Delivering traffic addressed to those private addresses needs a virtual network
adapter:

- **Windows** ships the **Wintun** adapter (published by WireGuard LLC, the same
  adapter used by WireGuard and by several well-known commercial VPN clients).
  Turning fake-IP on loads that driver; turning it off does not create the
  adapter. The file is shipped exactly as its author signed it and is used only
  through its published interface. See
  [Third-party components](third-party-components.md).
- **Linux** is not covered yet: this version does not offer fake-IP there.
  The operating system has an equivalent adapter built in, so the Linux build
  will need no extra driver once the feature reaches it. See
  [On Linux today](#on-linux-today).

The Settings screen shows the driver's status next to the checkbox, so you can
confirm the genuine driver is present before relying on the feature.

## When it does not apply

Fake-IP is deliberately not used for every connection:

- **Some application groups** keep their real addresses and go over the main
  channel by default. You can give any of them a route of your own in
  **Interfaces and routes → Set up routes**.
- **Addresses typed directly, and local or intranet names** — a bare IP
  address, `localhost`, single-label machine names, `.local` and the like —
  always use the real address, because they have no public destination to
  route.

In each of these cases the connection simply uses its real address, and the
rest of NetRuleRouter's protection still applies.

## On Linux today

Until fake-IP reaches Linux, routing and leak protection there decide per
address. While the additional connection is up this changes nothing you would
notice. While it is **down** and leak protection holds a routed site back, a
site you did not route can be held back with it if both happen to be served
from the same address, which is common behind large content delivery networks.
It opens again as soon as the additional connection is back.

## Known limitation: DNS-over-HTTPS

Fake-IP works by controlling the answer your system's DNS resolver gives. An
application that resolves names itself over DNS-over-HTTPS (DoH) or
DNS-over-TLS bypasses the system resolver, so it never receives a private
address and connects to the real one directly. Browsers are the common case.

Two ways to close this gap:

- Turn off DoH in the browser or app, so it uses the system resolver again.
- Keep **Block browser DoH/DoT** on in Settings (it is on by default once you
  have rules for the additional connection), which makes name resolution fall
  back to plaintext DNS the resolver can serve.

## Turning it on or off

On Windows, fake-IP is **on by default** for a new installation; an
installation that already had it off keeps it off. To change it: Settings →
Routing behavior → Routing method, make sure **How routed traffic is enforced** shows the local DNS resolver (the default),
then tick or clear **Route sites over virtual addresses (fake-IP)**. The change
applies immediately; no restart of the background service is needed.
