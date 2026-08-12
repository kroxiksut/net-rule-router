# Browser error pages when a site is blocked

**English** · [Русский](../ru/blocked-site-browser-errors.md)

When leak protection (the kill-switch) is active and the additional adapter
is down, sites that are routed through that adapter are deliberately
blocked instead of being allowed to leak onto your main link. In that
state the browser shows one of its own error pages:

- "This site can't provide a secure connection"
- "The connection was reset" (`ERR_CONNECTION_RESET`)
- "This site can't be reached"

## Why the message comes from the browser, not from NetRuleRouter

These pages are rendered by the browser itself whenever a connection
attempt is refused. NetRuleRouter refuses blocked connections quickly on
purpose: the immediate refusal is what makes the browser fail fast instead
of hanging for half a minute on every blocked tab.

NetRuleRouter cannot replace that page with its own explanation, and this
is by design. Modern sites use HTTPS, which is encrypted end to end between
your browser and the site. Showing a custom "this site is blocked" page
inside the browser would require intercepting and decrypting that traffic
— something NetRuleRouter never does. Not inspecting your encrypted
traffic is a core guarantee of the product, and it is worth more than a
prettier error page.

So the browser error page is not a malfunction and not a site problem. It
is what correct blocking looks like from the browser's side.

## Why a blocked site can briefly look like it still loaded

Two things can look confusing right after a site becomes blocked:

- Following a link to the site shows a half-rendered page, but pressing
  refresh shows the browser error page instead.
- A page you already had open keeps working for a while, even though the
  same site now fails to open in a new tab.

Both are expected, and neither means anything is leaking:

- The browser can render a page from what it already has stored locally,
  without asking the network for anything. What you see in that case is
  old, cached content, not a live connection.
- A connection that was already open and allowed at the moment it started
  is not cut off in the middle of a transfer. Blocking applies to new
  connections, not retroactively to ones already in progress.

To see the current, true result for a site, refresh the page or open it in
a private/incognito window, which has no local cache to fall back on.

## What you can do

- Bring the additional adapter (VPN) back up — the affected sites open
  again on their protected route, and no browser restart is needed.
- If you are not sure whether a site was blocked by NetRuleRouter, open
  Diagnostics: blocked connections are listed there with the process and
  destination.
- If you want such sites to open without protection while the additional
  adapter is down, that is a policy choice — review the kill-switch
  settings rather than treating the error page as a bug.
