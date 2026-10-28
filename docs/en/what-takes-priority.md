# What takes priority

**English** · [Русский](../ru/what-takes-priority.md)

Sooner or later two things disagree: two of your rules, two people signed in
to the same computer, your rules file and the window, the protection and a
pause. This page says, in one place, which one wins in each case.

## Which rule wins

The narrower rule wins. For each connection the rules of both routes are
looked at together, from the narrowest kind to the widest, and the first match
decides:

| # | Rule | Example |
|---|------|---------|
| 1 | Exact domain | `api.bank.com` |
| 2 | Domain with all its subdomains | `*.bank.com` |
| 3 | Site in every zone | `bank.*` |
| 4 | Exact IP address | `203.0.113.7` |
| 5 | Subnet or address range | `10.0.0.0/8`, `192.0.2.10-192.0.2.40` |
| 6 | Zone | `.ru` |
| 7 | Application | `chrome.exe` |
| 8 | Default route | the main connection or the additional one, as chosen in settings |

What this means in practice:

- A site named inside a zone goes where its own rule says, whatever the zone
  rule says. An exact address beats the network that holds it, and a network
  beats the zone it sits in.
- Between two names the longer one wins (`mail.bank.com` over `*.bank.com`),
  between two networks the more specific one (`10.1.0.0/16` over `10.0.0.0/8`).
- A **deny** (`!`) of an exact IP address stops that address whatever other
  rule names it. Any other deny takes its place in the order above, so a zone
  deny does not stop a site you route by name.
- When two rules of the same kind are equally specific, a deny wins over a
  route, and the main route over the additional one.
- A rule for a site or an address wins over a rule for a program. The switch
  **Programs in your rules take all their traffic** (Settings → Routing) turns
  that around for the programs you named.
- A destination no rule matches takes the default route.

Each kind of rule, with its exact spelling, is in the
[rules file format](rules-file-format.md#15-rule-evaluation-priority). When two
rules of different routes cover the same sites, the **Overlaps** screen lists
the pair and the route the sites actually take.

## Several people signed in

- **Everyone's rules apply at once.** Nobody waits for anybody else to sign
  out, and a person who signs in later never pulls your traffic into their
  tunnel.
- **On Linux** each person is routed by their own rules alone; two people may
  send the same site through different connections.
- **On Windows** the computer has one route table. When two people send the
  same address through different connections, the address stays with whoever
  signed in first, and the other person is told which addresses are involved.
  With leak protection on, those addresses are held back for them rather than
  sent the wrong way.
- **When someone who signed in before you sends all their traffic through
  their VPN**, the traffic your rules do not route goes through it too, and
  the window, the tray and the terminal interface tell you so, naming the
  connection.
- **Who came first** is decided by the time of signing in, so it does not
  change when the service restarts. Sitting at the computer decides only
  between equal times.

The details, with the known limitations, are in
[Several users on one computer](several-users.md).

## Whose rules cover the computer's own traffic

Some traffic belongs to no single person:

- **Name look-ups** are shared by the computer and follow the rules of the
  person who signed in first.
- **WSL, containers and virtual machines** follow the person who signed in
  first, on Windows and on Linux. Whether they are held back with that
  person's traffic while the additional route is down is a choice in Settings.
- **Background services** of the computer follow the person who signed in
  first on Linux. On Windows they follow the routes the signed-in people's
  rules put in place, so leak protection covers them for every address someone
  routes.

## Protection and a pause

- **Leak protection** decides what happens while the additional connection is
  down: with **Routed sites** what your rules send through it waits; with
  **Everything** all traffic waits except your local network and what your
  rules send over the main connection.
- **A pause wins over the protection.** *Turn off rules…* in the tray, or
  *Apply rules* in Settings, turns your routing and leak protection off
  together for 15 minutes, an hour, 4 hours, until the next restart or until
  you turn them back on: traffic takes the default route as if there were no
  rules, so a paused computer never locks you out. When the time runs out,
  your rules come back by themselves, and a timed pause outlasts a restart of
  the service.
- **One person's pause is their own.** It does not turn off the rules of the
  other people signed in.
- **Stopping the service** hands every connection back to the main one, unless
  an administrator chose to keep the routes of your rules on the additional
  connection during a pause or a stop.

## What you change, and what needs an administrator

- **Your own rules** need no administrator: edit and apply them from the
  window, the tray or an ordinary terminal, and they apply to you.
- **The shared baseline** every user without rules of their own follows, the
  **settings of the whole computer** and **managing the service** need an
  administrator. On Windows the window asks for administrator approval itself;
  in the terminal interface start it from a terminal opened as administrator.
  On Linux the app asks for the administrator's password.
- **An administrator can turn rule changes off** for the computer. You can
  still view, search, filter and export the rules.
- **A rule that reaches past your own programs** despite the protection of
  system programs needs an administrator to confirm it.

## Your rules file and the app

- **What is applied is what counts.** A rules file changing on disk never
  becomes active by itself; rules take effect when you press **Apply**, and
  the service keeps enforcing what was applied.
- **Saving from the window, the tray or the terminal interface writes the
  file anew** from the rules list. A note on a rule's own line is kept, a free
  comment line is not, and the sections for other operating systems are
  written back as they were.
- **A file you edited by hand is not overwritten.** If the file changed after
  the app last saved it, the app leaves it as it is and offers to compare it
  with the rules in force.
- **The window and the terminal interface agree.** Both read the same choice
  of rules files and rule set, so a change made in one is what the other
  shows.

## When the service stops, the computer restarts, or the app is removed

- **Closing the window or the tray** changes nothing: the service keeps
  applying your rules.
- **A normal stop or removal of the service** hands the network back: the
  app's routes, filters and DNS redirect go with it.
- **On Windows, a stop from the Services console** or `Stop-Service` is taken
  for a failure, and the service starts again a few seconds later, so the
  protection does not stay off by accident. Stop it from the app or with
  `nrr-cli stop`.
- **After a crash** the protection can outlive the service. The window and the
  tray say the service stopped and offer **Start service** and **Restore
  network**; the terminal interface says so too and shows the commands that do
  the same.
- **A restart of the computer** keeps your rules and brings them back with the
  service. With leak protection set to **Everything** the internet waits from
  the moment the computer starts until the service is running.
- **Your rules files are never touched** by an update or a removal, wherever
  you keep them.

What to do when the network does not come back is in
[Recovering network access](recovering-network-access.md).

## See also

- [Rules file format](rules-file-format.md)
- [Several users on one computer](several-users.md)
- [Where NetRuleRouter keeps its files](where-files-live.md)
