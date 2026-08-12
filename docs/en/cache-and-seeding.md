# FQDN/IP cache and how it fills up

[Russian](../ru/cache-and-seeding.md)

NetRuleRouter routes traffic by domain, zone, exact IP, or application — but the
Windows filtering layer it enforces through only understands IP addresses. To
turn a domain rule ("route `*.bank.com` over primary") into something that can
actually be enforced, the service needs to know which IP addresses a matching
hostname currently resolves to. That mapping is the **FQDN/IP cache**.

## What it is

The cache is a local SQLite database, `nrr_fqdn_ip_cache.db`, that the
background service reads and writes. For every hostname it holds one or more
associated IPv4 addresses, plus bookkeeping about where each mapping came from
and how fresh it is.

Two properties matter for how you think about it:

- **It only ever holds hosts that match your active rules.** The service is
  not building a general-purpose DNS cache of everything on the machine — a
  hostname is only worth caching if a rule could route it, so unrelated
  traffic never ends up in the database.
- **It is fully rebuildable.** If the file is ever deleted, corrupted, or you
  simply want a clean slate, the service rebuilds it from scratch the next
  time it runs. Nothing is lost except the need to re-learn mappings, which
  happens automatically.

## How it fills up

The cache has four independent sources. In normal use, most entries come from
the first two — the other two exist to close specific gaps.

### 1. Live DNS observation

While the service is running, it observes outgoing DNS traffic (via ETW) for
the console user session. When a program resolves a hostname that matches one
of your rules, the resulting IP address(es) are recorded. This is the primary,
always-on source, and it requires no configuration — it is simply how the
cache stays current with the sites you actually visit while NetRuleRouter is
active.

### 2. Confirming a hostname from its address

Sometimes the service learns an IP address before it learns the hostname
behind it. When that happens, it can look up a candidate name for that
address — but it only ever accepts the answer after checking it back the
other way round first, so a name that does not genuinely belong to the
address is discarded and never reaches the cache.

These lookups go only to the DNS server configured for your connection —
nothing is sent to any third-party service.

### 3. Seeding from browser history (opt-in)

Live observation only sees hostnames resolved *while the service is running*.
A site you visited earlier — before the service started, or one your browser
still has cached from a previous session — never produces a fresh DNS query,
so it can be missing from the cache the first time you need it.

Browser-history seeding closes that gap by reading the distinct hostnames
already present in your browsers' local history databases and resolving the
ones that match your active rules, without waiting for you to visit them
again. It is available from the Diagnostics screen and can be triggered
**on demand**, or turned on to run **automatically every time the service
starts**. Either way it is strictly opt-in — nothing is read from your
browsers unless you enable it.

Only hostnames are ever extracted. Full URLs, page titles, visit timestamps,
and visit counts never leave the machine, and hostnames that do not match any
of your active rules are discarded immediately rather than cached — the
service cannot reconstruct your browsing history from what it keeps.

#### Supported browsers

**Chromium-family browsers** — Chrome, Edge, Brave, Yandex Browser, Opera,
Opera GX, Vivaldi, and plain Chromium. Every profile found under the
browser's `User Data` folder is read (`Default` plus any `Profile N`), except
Opera and Opera GX, whose profile sits directly under `%APPDATA%\Opera
Software\Opera Stable` / `Opera GX Stable` rather than inside a `User Data`
folder. For each profile, hostnames are extracted from the `urls` table of
that profile's `History` SQLite database.

**Firefox-family browsers** — Firefox, LibreWolf, and Waterfox. Hostnames are
extracted from the `moz_places` table of each profile's `places.sqlite`
database.

**AI browsers (best-effort)** — Arc for Windows and Perplexity Comet, both
Chromium-family. Arc is MSIX-packaged, so its profile is discovered by
scanning `%LOCALAPPDATA%\Packages\TheBrowserCompany.Arc_*\LocalCache\Local\Arc\User Data`
rather than a fixed vendor folder. Comet is probed at two possible locations
under `%LOCALAPPDATA%`, `Perplexity\Comet\User Data` and `Comet\User Data`,
since its install layout has varied between releases. Support for these two
is honestly **best-effort**: both are young, fast-moving browsers whose
on-disk layout changes faster than it gets documented, so the paths above can
go stale after an update. If your Arc or Comet stops contributing hosts to
the cache, please tell us through any channel that suits you — the project's
GitHub Issues (<https://github.com/kroxiksut/net-rule-router/issues>) or any
other feedback route the project publishes. The service log line
`browser-history discovery finished` lists which sources were actually
found on your machine, and that line is the evidence to attach.

Every one of these browsers keeps its history database open — and locked —
while running, so NetRuleRouter never opens the live file directly. It copies
the database to a temporary file first and reads that read-only copy, then
deletes the copy. A browser that is not installed, or whose database cannot
be copied or read for any reason, is simply skipped; seeding proceeds with
whatever other browsers are available.

#### Tor Browser is not supported

Tor Browser is deliberately excluded, for two independent reasons, either of
which alone would be enough:

- By default Tor Browser runs in always-private mode and does not persist
  browsing history to disk at all, so there is nothing on disk to read.
- Even where history exists, it would not help: traffic routed through Tor
  never appears to Windows as a direct connection to the site you visited —
  the operating system only ever sees connections to Tor relay IP addresses.
  Caching a Tor-visited hostname would not let NetRuleRouter make any better
  routing decision, because the underlying network path never touches that
  hostname's real IP at all.

### 4. The hosts file

The OS `hosts` file (`%SystemRoot%\System32\drivers\etc\hosts`) maps
hostnames to IPs before any of your traffic reaches NetRuleRouter, and NRR
never overrides it. Where a rule's hostname has a `hosts` entry, the service
surfaces that as an informational annotation so you can see when a `hosts`
pin — rather than DNS — is deciding where a name resolves, which helps
explain rule behavior that would otherwise look surprising.

## Known limitation: DNS-over-HTTPS

Live DNS observation watches conventional DNS traffic. A browser configured
to use DNS-over-HTTPS (DoH) sends its lookups inside an encrypted HTTPS
connection instead, which the service's DNS observer cannot see or parse —
so hosts resolved that way never produce a live-observation cache entry. The
two mitigations above exist largely because of this: browser-history seeding
pre-fills the cache independently of how the browser resolved a name, and a
local resolver (mode B) can intercept and observe lookups directly. The
hostname confirmation described above also recovers many of these cases
after the fact.
