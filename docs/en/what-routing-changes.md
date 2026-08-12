# What routing changes — and what it does not

**English** · [Русский](../ru/what-routing-changes.md)

NetRuleRouter changes **which connection a request leaves through**. That is
the whole of it. It does not change who you are signed in as, what your browser
looks like to a website, or what your provider can infer from the fact that a
connection happened at all.

This page is here because that distinction is easy to lose. Tools that move
traffic to another interface are usually sold as privacy tools, so it is worth
stating plainly which parts of the picture move when a rule fires and which
parts stay exactly where they were.

## Who sees what

Take one ordinary page load. Several parties learn something from it, and each
learns a different thing. The table shows what each of them sees before and
after a rule sends that site through the additional connection.

| Who | Without NetRuleRouter | With the site routed through the additional connection |
|---|---|---|
| The site you open | Your provider's IP address, the full address of the page, your cookies, your signed-in account, your browser's characteristics | The **additional connection's** IP address. Everything else is unchanged: same cookies, same account, same browser |
| Your internet provider | That you connected to that site's server, when, and how much data moved | That you connected to the additional connection's endpoint. Which sites went through it is no longer visible to them |
| Whoever operates the additional connection | Nothing — it is not in the path | Your real IP address, and every destination you send through it. This party replaces your provider as the observer for routed traffic |
| The DNS resolver answering your lookups | Which names you look up, and from which IP | Unchanged by routing alone. It moves only if you also turn on **DNS through the tunnel** (Settings → Routing) |
| Cookies and signed-in accounts | Identify you across visits | **Unchanged.** A different exit address does not sign you out and does not separate you from your history on that site |
| Your browser's characteristics | Identify your browser across visits, even without cookies | **Unchanged.** Nothing NetRuleRouter does touches the browser |
| Other apps on the same PC | Use your main connection | Use your main connection, unless a rule of yours covers them too |

The two rows that matter most are the ones that say *unchanged*. A site that
knows you because you are logged into it keeps knowing you. Routing swaps one
address for another; it does not make you a different visitor.

## Name the goal first, then pick the setting

The useful question is not "is this private". It is "what specifically do I
want to change, and for whom". The table below maps common goals onto what
NetRuleRouter actually does about them.

| What you want | What actually changes |
|---|---|
| A specific site should reach me over a different connection while everything else stays fast and direct | Exactly what a rule does. See [Routing modes](routing-modes.md) |
| My provider should not see, or interfere with, which sites I look up | Turn on **DNS through the tunnel**. See [DNS through the tunnel](dns-via-secondary.md) |
| Nothing should ever slip onto the main connection, even briefly | Use the leak-protection mode that sends everything through the additional connection. Per-rule routing is precise, not airtight; the trade-off is spelled out in [Routing modes](routing-modes.md) |
| A site should see me as coming from another country | It will see the additional connection's address. Whether that reads as another country depends on that connection, not on NetRuleRouter — and your account and browser still identify you |
| A site should stop recognising me between visits | NetRuleRouter does not do this. Sign out, clear the site's data, or use a separate browser profile |
| The operator of the additional connection should not see my traffic | Not something routing can give you. Routed traffic is visible to whoever runs that connection — choose one you are willing to trust |
| Other people using this PC should not see my activity | Not something NetRuleRouter does. Rules are per-user, but this is an operating-system and browser question |

## Encrypted DNS in the browser is a special case

Browsers can resolve names themselves over encrypted DNS (DoH/DoT) instead of
asking the operating system. That hides the names from your provider — and
from NetRuleRouter at the same time. A site resolved that way is a site whose
address we never learned, which means a rule for it may not fire and leak
protection has less to work with.

This is a real trade-off, not a detail: encrypted DNS in the browser and
name-based routing want the same information. Settings → Routing has a
**Block browser DoH/DoT** switch for this, off by default, and the recommended
scope limits it to the times when leak protection is armed. If you leave
encrypted DNS on in your browser, expect routing for browser traffic to be
less reliable than for everything else.

## What NetRuleRouter is not

- Not a VPN client and not a VPN service. It routes over connections you
  already have; it does not create one and does not carry your traffic.
- Not an anonymity tool. See the *unchanged* rows above.
- Not a censorship-circumvention tool.
- Not a tracker blocker, ad blocker, or privacy extension. A rule can block a
  destination you name yourself, but no block lists ship with the product and
  nothing is filtered inside a page.

## Further reading

Background on the parts of this picture that are not ours, from sources that
explain them properly:

- [What is a VPN?](https://www.cloudflare.com/learning/access-management/what-is-a-vpn/) — Cloudflare, on what moving traffic to another endpoint does and does not do
- [DNS encryption explained](https://blog.cloudflare.com/dns-encryption-explained/) — Cloudflare, on DoH and DoT
- [Encrypted Client Hello](https://blog.cloudflare.com/announcing-encrypted-client-hello/) — Cloudflare, on the server name still visible during a TLS handshake, and the mechanism that hides it
- [ESNI: a privacy-protecting upgrade to HTTPS](https://www.eff.org/deeplinks/2018/09/esni-privacy-protecting-upgrade-https) — EFF, the same subject from the user's side
