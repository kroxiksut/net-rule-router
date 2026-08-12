# DNS through the tunnel

**English** · [Русский](../ru/dns-via-secondary.md)

Before your computer can reach a site, it has to turn the site's name into
an address. That lookup normally goes to the resolver your main provider
hands out — and the answer it gives is taken on trust.

Some providers do not answer honestly. For certain names they return a
wrong address, an empty answer, or an address that goes nowhere. The site
then fails to load even though your routing rules are correct and your
additional connection is up and working.

This setting sends NetRuleRouter's own name lookups through the additional
connection instead, so your main provider neither sees which names you look
up nor gets to decide what the answer is.

## What you get

- **Sites that a provider tampers with start working.** If a name was being
  answered with a dead or wrong address, it is now resolved through the
  additional connection and loads normally.
- **Your main provider does not see the names.** The lookups leave over the
  additional connection like the rest of your routed traffic.
- **Routing stays correct.** Rules keep matching the same way; only the
  source of the answers changes.

## The symptom this usually fixes

A site opens in one browser window but not in another — most often it works
in a normal window and fails in a private one, or works in one browser and
fails in another. That difference is a strong hint that name resolution is
the problem rather than routing: the window that works is reusing an answer
it had already cached, while the one that fails asks again and receives the
tampered reply.

Video that refuses to play while the page itself loads is the same story:
the page came from cache, the video servers had to be looked up fresh.

## What it needs

The additional connection has to be selected and up. If it is unavailable —
not connected yet, or dropped — lookups fall back to the main connection
automatically, so name resolution never stops working. It simply stops being
protected until the additional connection is back.

The setting works in either enforcement mode. It changes where NetRuleRouter
asks, not how traffic is enforced, so it can be combined with per-site
routing over virtual addresses (fake-IP) or used on its own.

## What it does not do

- It does not encrypt or inspect your traffic, and it does not change which
  sites are routed where.
- It does not affect lookups a browser performs entirely on its own using
  its built-in encrypted DNS. If a browser is configured that way, its
  answers come from its own resolver and never reach NetRuleRouter. See
  [Per-site routing with virtual addresses (fake-IP)](fake-ip.md) for how
  that case is handled.

## How to turn it on

Settings → Routing → leak protection group → **Resolve site names through
the additional connection**. It is off by default; the change takes effect
immediately and is remembered between runs.
