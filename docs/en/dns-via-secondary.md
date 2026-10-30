# DNS through the tunnel

**English** · [Русский](../ru/dns-via-secondary.md)

Before your computer can reach a site, it has to turn the site's name into
an address. That lookup normally goes to the resolver your main provider
hands out — and the answer it gives is taken on trust.

Some providers do not answer honestly. For certain names they return a
wrong address, an empty answer, or an address that goes nowhere. The site
then fails to load even though your routing rules are correct and your
additional connection is up and working.

Whatever this setting says, the names in your rules for the additional
connection are looked up through that connection while it is up, so your
main provider neither sees them nor gets to change their answers. That
covers NetRuleRouter's own lookups of those names and, with the local DNS
resolver (the default routing method), your programs' lookups of them too.

This setting adds the rest of NetRuleRouter's own lookups: the names in your
rules for the main connection, the sites under your domain and zone rules it
keeps fresh, and its questions about which site an address belongs to. With
it on, they go through the additional connection as well.

It does not move your programs' other lookups. When a program looks up a
site that none of your rules for the additional connection names, the
question goes to your main provider's resolver, whether this setting is on
or off.

## What you get

- **The sites you route are not answered by your provider.** A name in your
  rules for the additional connection is resolved through it, so a dead or
  wrong address your provider hands out for that name never reaches the
  program. This part needs no setting.
- **With the setting on, your main provider does not see the names
  NetRuleRouter looks up for your rules.** Those lookups leave over the
  additional connection like the rest of your routed traffic.
- **Routing stays correct.** Rules keep matching the same way; only the
  source of the answers changes.

## When a provider tampers with a site's name

A site opens in one browser window but not in another — most often it works
in a normal window and fails in a private one, or works in one browser and
fails in another. That difference is a strong hint that name resolution is
the problem rather than routing: the window that works is reusing an answer
it had already cached, while the one that fails asks again and receives the
tampered reply.

Video that refuses to play while the page itself loads is the same story:
the page came from cache, the video servers had to be looked up fresh.

What helps is a rule that sends that site through the additional
connection: its name is then looked up there, setting or no setting. Turning
this setting on without such a rule does not change what your programs are
told about the site.

## What it needs

The additional connection has to be selected and up. If it is unavailable —
not connected yet, or dropped — lookups go through the main connection
instead, so name resolution never stops working; your main provider sees
those lookups until the additional connection is back. The one exception is
a site that leak protection is holding while the additional connection is
down: its name is not looked up over the main connection at all.

The setting works with either routing method. It changes where NetRuleRouter
asks, not how traffic is enforced, so it can be combined with per-site
routing over virtual addresses (fake-IP) or used on its own.

## Where the lookups go, and what the provider can still see

With the setting off, the names in your rules for the additional connection
go through it to one public resolver, Quad9 (149.112.112.112). Quad9 sees
those names; no other lookup of yours is sent there, apart from the second
question described below.

With the setting on, all of NetRuleRouter's own lookups go through the
additional connection to public resolvers: 1.1.1.1 (Cloudflare), 8.8.8.8
(Google) and 9.9.9.9 (Quad9). Those services see the names, instead of your
main provider.

If your main provider answers a name in your rules with an address that
looks blocked, NetRuleRouter asks the public resolvers above about that one
name again, so the rule still gets a real address. That second question
takes the same way as the rest: through the additional connection where the
two paragraphs above say so, over the main connection otherwise (a name in
your rules for the main connection with the setting off, or any name while
the additional connection is down).

A lookup the additional connection does not answer in time is tried again
through it. Only when the additional connection stops answering altogether
do lookups return to the main connection, so that names keep resolving;
those lookups your main provider can see.

## What it does not do

- It does not encrypt or inspect your traffic, and it does not change which
  sites are routed where.
- It does not move your programs' lookups of sites outside your rules for
  the additional connection: those go to your main provider's resolver
  either way.
- It does not affect lookups a browser performs entirely on its own using
  its built-in encrypted DNS. If a browser is configured that way, its
  answers come from its own resolver and never reach NetRuleRouter. See
  [Per-site routing with virtual addresses (fake-IP)](fake-ip.md) for how
  that case is handled.

## How to turn it on

Settings → Routing behavior → **DNS through the tunnel**. The switch appears
once an additional connection is chosen. It is off
by default; the change takes effect immediately and is remembered between
runs.
