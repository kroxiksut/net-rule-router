# Routing modes: what each switch does, and how to combine them

**English** · [Русский](../ru/routing-modes.md)

Settings → Routing behavior → Routing method has five switches that fine-tune how
NetRuleRouter resolves names and routes traffic, whatever leak protection is set to: **DNS through the
tunnel**, **Fast DNS answers**, **Route sites over virtual addresses (fake-IP)**, **Fake-IP UDP relay (experimental)**, and
**Instant reset when the additional route is unavailable**. Each solves a
different, narrow problem, and most of them are safe to leave on together.
This page explains what each one buys you, when it is worth turning on, and
what combining them gets you that no single switch does alone.

They are not equally optional, and the difference matters more than any single
setting on this page:

- **fake-IP is on by default for a new Windows installation, and it is the
  switch that matters most** (an installation that had it off keeps it off). It is
  the only one that separates two sites sharing one server address, and on any
  realistic rule set — anything covering a large platform or a big CDN — that
  sharing is common. Without it, a site you did not route can follow one you
  did, or the other way round. It is available on Windows; Linux decides per
  address for now.
- **DNS through the tunnel** and **Fast DNS answers** are genuine choices. Both
  are useful, neither is required, and the sections below say exactly what you
  gain and give up either way.
- **fake-IP UDP relay** and **Instant reset** are refinements of fake-IP. They
  are hidden until you turn on **Detailed mode** in Settings → Experimental
  features; without it NetRuleRouter uses sensible defaults for both.

## DNS through the tunnel

**What you get:** The names in your rules for the additional connection are
looked up through it in any case. This switch sends the rest of
NetRuleRouter's own lookups — the names in your rules for the main
connection, the sites it keeps fresh for your rules — through the additional
connection as well, to public resolvers, so your main provider neither sees
those names nor gets to decide the answers. Your programs' lookups of sites
outside your rules for the additional connection still go to your main
provider's resolver. See [DNS through the tunnel](dns-via-secondary.md) for
which names go where.

**When to turn it on:** You would rather your main provider did not see the
names NetRuleRouter looks up for your rules. If a site fails to load because
your provider tampers with its name, a rule that sends the site through the
additional connection is what fixes it; this switch alone does not change
what your programs are told.

**What it costs:** Nothing while the additional connection is up. If it drops,
lookups go through the main connection so names keep resolving, and your
main provider sees them until the additional connection returns.

## Fast DNS answers

**What you get:** Apps get their DNS answer immediately instead of waiting for
route protection to finish taking effect first, so page loads stay snappy.

**When to turn it on:** It is on by default and suits almost everyone. Leave
it on unless responsiveness matters less to you than closing every last
timing gap around a brand-new connection.

**What it costs:** Turning it **off** trades that responsiveness for a
stricter guarantee — every answer waits for protection to be in place first,
which can make page loads noticeably slower.

## Fake-IP: routing sites over virtual addresses

**What you get:** Each routed site is answered with its own private address
instead of its real one, so routing and protection apply strictly per site —
even for sites that share a real server address. See
[Per-site routing with virtual addresses (fake-IP)](fake-ip.md) for the full
explanation, including what it needs and its known limitation with
browser-side encrypted DNS.

**When to turn it on:** Turn it on when you need routing decisions to be
airtight per site — most importantly, when two sites you care about
differently (route one, leave the other alone) happen to share the same
real server address, which is common behind large content delivery networks.

**What it costs:** It requires the local DNS resolver (the default routing
method) and, on
Windows, loads the bundled virtual-adapter driver. Applications that resolve
names on their own over encrypted DNS bypass it unless you also turn on
DoH/DoT blocking.

## Fake-IP UDP relay

**What you get:** Modern web traffic that uses QUIC (HTTP/3) keeps its
per-site virtual address instead of silently falling back to a plain TCP
connection that fake-IP does not cover.

**When to turn it on:** Turn it on together with fake-IP whenever the sites
you route are reached by a modern browser — QUIC is now the default transport
for a large share of the web, so without this switch a meaningful slice of
your fake-IP-routed traffic quietly reverts to ordinary addressing.

**What it costs:** It only does anything while fake-IP itself is on, and it
is labelled experimental — behaviour may still change as it matures.

## Instant reset when the additional route is unavailable

**What you get:** If the additional connection briefly can't be reached while
fake-IP is relaying a connection, the application gets an immediate failure
signal and can retry or fail over right away, instead of appearing to hang.

**When to turn it on:** It is on by default and is the right choice for most
setups, especially anything that reconnects or fails over on its own.

**What it costs:** Turning it **off** replaces the instant failure with a
short hold — up to about ten seconds — while NetRuleRouter waits to see if
the route comes back, which reads as a hang to an application that isn't
watching for it.

## Combining them

| Combination | What it gets you |
|---|---|
| DNS through the tunnel + Fast DNS answers | NetRuleRouter's own lookups for your rules stay out of your main provider's sight, without giving up quick page loads. |
| Fake-IP + UDP relay | Per-site separation that also covers modern QUIC/HTTP-3 traffic, not just classic TCP connections. Turn both on together if the sites you route matter on today's web. |
| Fake-IP + Instant reset | A brief tunnel hiccup produces a fast, visible failure that apps can react to, instead of a silent multi-second stall in the middle of a fake-IP-routed connection. |
| Fake-IP alone, UDP relay off | Per-site separation for ordinary TCP connections; QUIC connections to the same sites fall back to plain addressing and lose that separation until the relay is turned on too. |

None of these five switches conflicts with another — you can turn on any
subset that matches your needs.

## The one switch that solves shared addresses

If two sites answer from the same underlying server address, only **fake-IP**
can tell them apart — it gives every routed site its own address, so a
decision about one site can never spill onto another. DNS through the tunnel,
fast DNS answers, and the two fake-IP refinements all change *when* or *how*
lookups happen or *how gracefully* a hiccup is handled, but none of them
change what address a site is reached by. If your goal is routing or
protecting sites independently of whatever infrastructure they happen to
share, fake-IP is the switch that actually does it — the other four are
worth having, but they do not substitute for it.

## Turning them on

DNS through the tunnel, Fast DNS answers and fake-IP live under Settings →
Routing behavior → Routing method. Fast DNS answers and fake-IP appear while the
local DNS resolver is in use; DNS through the tunnel appears once an additional
connection is chosen. The two fake-IP refinements — UDP relay and Instant reset —
appear there once fake-IP is on and Settings → Experimental features →
**Detailed mode** is on. Every switch applies immediately; none needs a
restart of the background service.

None of these switches changes who you are to the site at the other end.
[What routing changes — and what it does not](what-routing-changes.md) sets
out who sees what once a site is routed, and which parts of the picture stay
exactly where they were.
