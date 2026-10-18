# Several users on one computer

**English** · [Русский](../ru/several-users.md)

Every person signed in to the computer gets their own rules applied, at the
same time. Someone working at the screen keeps working when another person
signs in remotely for maintenance, and the newcomer's rules start working
within seconds of signing in. Nobody has to wait for anybody else to sign
out.

What counts as signed in:

- **Windows:** the user at the console and every Remote Desktop session.
  The tray does not have to be running when the rules are applied by the
  service.
- **Linux:** the user at the seat and every SSH session. To keep your rules
  in force while you are not connected, enable lingering for your account
  (see [the terminal interface](tui.md#linux-servers)).

Rules belong to the person who wrote them. A site in one user's rules is
routed and protected for that user, and suggestions are offered to the person
whose connections showed the need. A user who signs in later can never pull your
traffic into their tunnel.

Who signed in first is decided by the time of signing in, so it stays the same
when the service restarts. Sitting at the computer decides only between equal
sign-in times.

## Linux: one user's rules, one user's traffic

On Linux each signed-in user is routed by their own rules alone. Two users
may send the same site through different connections, and both get what
their own rules say.

Background services of the computer itself follow the rules of the person who
signed in first. Name resolution and a few kernel settings belong to the
computer as a whole, so they follow that person's rules too.

## Windows: one shared route table

Windows keeps a single route table for the whole computer, so the rules of
everyone signed in share it.

- When two users' rules send the **same address the same way**, nothing
  special happens.
- When two users send **the same address through different connections**, the
  address stays with whoever signed in first, so their connections are never
  switched over by someone else signing in. The second user gets a
  notification listing the addresses involved. With leak protection on, those
  addresses are blocked for them rather than sent the wrong way; everything
  else in their rules works. When the first user signs out, the addresses
  follow the second user's rules.
- When a user who signed in **later** sends all their traffic through their
  VPN, that does not take the traffic of a user who signed in earlier: the
  routes that would cross are a conflict, and the earlier user keeps theirs.
- When someone who signed in **before** you sends all their traffic through
  their tunnel, the traffic your rules do not route goes through that tunnel
  too, and the app tells you so in the window, the tray and the terminal
  interface, naming the connection. The notice disappears when that stops.
- **Known limitation.** When the users rely on **different VPN connections**
  and the first one sends all their traffic through their VPN, addresses that
  only the second user's rules name can travel through the second user's VPN
  for the first user too. Nothing is exposed to the open internet — the
  traffic still goes through a VPN — but not through the one the first user
  chose. If that matters, give both users the same additional connection, or
  avoid signing in with two different VPNs at once.

Background services of the computer follow the routes that are in place,
so leak protection covers them for every address a signed-in user routes.

## See also

- [The routing switches](routing-modes.md)
- [The `nrr-tui` terminal interface](tui.md) — managing your rules over SSH
