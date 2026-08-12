# Routing modes: what each switch does, and how to combine them

**English** · [Русский](../ru/routing-modes.md)

Settings → Routing has five switches that fine-tune how NetRuleRouter resolves
names and routes traffic once leak protection is on: **DNS through the
tunnel**, **Fast DNS answers**, **fake-IP**, **fake-IP UDP relay**, and
**Instant reset when the additional route is unavailable**. Each solves a
different, narrow problem, and most of them are safe to leave on together.
This page explains what each one buys you, when it is worth turning on, and
what combining them gets you that no single switch does alone.

They are not equally optional, and the difference matters more than any single
setting on this page:

- **fake-IP is not a preference.** It is the only switch that separates two
  sites sharing one server address, and on any realistic rule set — anything
  covering a large platform or a big CDN — that sharing is guaranteed. Leave it
  on. Turning it off means accepting that some sites will not work while others
  are routed.
- **DNS through the tunnel** and **Fast DNS answers** are genuine choices. Both
  are useful, neither is required, and the sections below say exactly what you
  gain and give up either way.
- **fake-IP UDP relay** and **Instant reset** are refinements of fake-IP. They
  are hidden until you turn on **Detailed mode** in Settings → Experimental
  features; without it NetRuleRouter uses sensible defaults for both.

## DNS through the tunnel

**What you get:** Name lookups are sent through the additional connection
instead of your main provider's resolver, so the provider neither sees which
names you look up nor gets to decide what the answer is. See
[DNS through the tunnel](dns-via-secondary.md) for the full picture, including
the specific symptom this fixes.

**When to turn it on:** A site fails to load even though your rules and the
additional connection both look correct — especially if it works in one
browser or window and not another. That pattern points at tampered name
resolution rather than broken routing.

**What it costs:** Nothing while the additional connection is up. If it drops,
lookups fall back to the main connection automatically so names keep
resolving — they simply stop being protected until the additional connection
returns.

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

**What it costs:** It requires the local DNS resolver (Mode B) and, on
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
| DNS through the tunnel + Fast DNS answers | Trustworthy name resolution — your provider can neither see nor tamper with lookups — without giving up quick page loads. This is the everyday pairing for most setups. |
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
Routing and are always visible. The two fake-IP refinements — UDP relay and
Instant reset — appear there once Settings → Experimental features →
**Detailed mode** is on. Every switch applies immediately; none needs a
restart of the background service.

None of these switches changes who you are to the site at the other end.
[What routing changes — and what it does not](what-routing-changes.md) sets
out who sees what once a site is routed, and which parts of the picture stay
exactly where they were.
