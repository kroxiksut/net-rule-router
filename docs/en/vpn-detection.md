# VPN client detection

[Русский](../ru/vpn-detection.md)

NetRuleRouter can point itself at the program you use as your VPN. This is done
in **Settings → Routing behavior → Your VPN client**, or from the first-launch
onboarding. Telling the app which program is your VPN lets its traffic keep
flowing over your main link while leak protection is on — so
the VPN can always reach its own server and reconnect, instead of being blocked
along with everything else.

You never *have* to use the built-in list. In the "Your VPN client" dialog you
can always choose **"My VPN isn't listed / pick it manually"** and point at the
program's `.exe` yourself. The list below only makes the program show up
automatically so you don't have to.

## A second VPN beside yours

If you also run another VPN — typically a corporate one for work — next to the
connection you route through, NetRuleRouter leaves that VPN its own networks
and its own internal names, on Windows and on Linux. A rule wide enough to
cover a host inside the corporate network — a whole country domain, say —
does not pull that host away from the corporate VPN.

What each leak protection choice means for it, on both systems:

- **Off** — nothing is held back, and the corporate VPN works as it would
  without NetRuleRouter.
- **Routed sites** — only what your rules send through the additional
  connection is held back. The corporate VPN connects and works as usual.
- **Everything** — a connected corporate VPN keeps reaching its networks. One
  that takes all of your traffic keeps the company's private networks; the
  rest of the internet waits for the additional connection like everything
  else. To connect or reconnect, a VPN has to reach its server over the main
  connection:
  - the VPNs built into the system — IKEv2 and L2TP on Windows, strongSwan
    and libreswan on Linux — connect on their own. On Linux, a strongSwan or
    libreswan connection without a network interface of its own then keeps
    the company's private networks; this needs Linux 4.20 and nftables 0.9.1
    or newer;
  - any other VPN is stopped the first time, and NetRuleRouter asks you once,
    in the window, the tray and the terminal interface, whether to let it
    connect. Say yes and that VPN reaches its server while leak protection is
    on; nothing else is let through to that address. The answer is yours
    alone: another person on the same computer is asked for theirs. You can
    take it back under **Settings → Routing behavior → Your VPN client**, in
    the list of other VPNs you allowed.

  A VPN that has to connect through the additional route instead is set up
  with the helper in the next section.

On Windows this includes the VPN connections built into the system (L2TP,
PPTP, SSTP, IKEv2). On Linux it covers WireGuard and OpenVPN connections
whatever they are named, `wg0` and `tun0` included.

A connection your provider delivers the internet itself over — PPPoE, or a
mobile-broadband modem — is not someone else's VPN: it is treated as an
ordinary main connection, and leak protection covers it like any other.

## A VPN that must connect through the other channel (VPN over VPN)

Some VPNs accept a connection only from certain places. A typical case: a
corporate VPN that works only from abroad, while your main connection is a
domestic one. That VPN then has to reach its gateway through your additional
route — your own VPN abroad — and NetRuleRouter can make sure it always does.

**With the helper.** Open **Settings → Routing behavior → Your VPN client** and
find **Other VPNs (corporate)**:

1. Name the VPN program: type its file name, or press **Scan for VPN apps**
   and pick it from the programs found.
2. Choose the route it has to connect through — usually the additional one.
3. Start the VPN and let it try to connect, then press **Find gateway
   addresses**. The addresses that program connected to recently are listed,
   the most likely gateway first and already ticked. Where a host name is
   shown you can tick it instead of the address, and you can type the
   gateway's address or name yourself.
4. Press **Add rules**. The rules join your rules list like any other; apply
   the changes as usual.

In the terminal interface the same helper is the `v` key on the Rules screen.

**By hand.** It is one ordinary rule: the gateway's address, or its host name,
in the rules of the route the VPN has to connect through. The gateway is named
in the VPN client's connection settings or profile. In the additional route's
rules file it looks like this:

```
--- IP
203.0.113.10    # VPN gateway: corporate VPN
```

**Do not add that program under "Your VPN client" for this.** That list is for
the program that brings your additional route up, and its traffic is
deliberately let out over the main connection so it can always reconnect.
Putting the corporate VPN there would send it over the domestic main
connection, which is exactly what it must not use.

**When the route is down.** If the route the gateway is bound to is not
available, the corporate VPN does not connect — it is not moved to the other
route. Bring that route back (reconnect your own VPN) and the corporate VPN can
connect again.

**If large transfers stall.** A tunnel inside a tunnel leaves less room for
each packet. If the corporate VPN connects but big downloads, file copies or
remote-desktop sessions hang, lower the MTU in the corporate VPN client's
settings (for example to 1300) and reconnect.

## How detection works

The app scans your **running programs** and **installed programs** and flags any
whose executable name or display name contains one of a set of known keywords.
Matching is case-insensitive and works on a substring, so:

- Anything with **"VPN"** in its name is detected automatically (for example
  "Windscribe VPN", "Mozilla VPN", "Kaspersky VPN Secure Connection").
- The keyword list below adds coverage for clients whose name does **not**
  contain the word "VPN".

Detection never changes anything on its own — it only builds a list of
candidates. You confirm which one (if any) is your VPN.

## VPN clients recognized out of the box

Beyond every product that simply has "VPN" in its name, the following are
recognized by keyword:

**Protocols and generic clients**
OpenVPN, WireGuard, OpenConnect, Cisco AnyConnect, SoftEther, Shadowsocks,
sing-box, Outline, Amnezia, Psiphon.

**Consumer VPNs**
Mullvad, NordVPN, Proton VPN, ExpressVPN, Surfshark, Windscribe, TunnelBear,
hide.me, hidemy.name, CyberGhost, Private Internet Access, IPVanish,
Hotspot Shield, Ivacy, TorGuard, Avast / AVG SecureLine, Perfect Privacy,
Betternet, Speedify, Browsec, ZenMate.

**Mesh and zero-trust networks**
Cloudflare WARP, Tailscale, ZeroTier, Twingate, NetBird.

**Corporate and enterprise clients**
Cisco Secure Client / AnyConnect, Palo Alto GlobalProtect, Fortinet FortiClient,
Zscaler Client Connector, Check Point, Ivanti / Pulse Secure, SonicWall
NetExtender, Sophos Connect, WatchGuard, Barracuda, F5 BIG-IP Edge Client.

**Russia and CIS**
ViPNet (InfoTeCS), S-Terra, Amnezia, hidemy.name.

This list is not exhaustive, and it does not need to be — manual selection
always works, and the list is easy to extend.

## Extending the list

The keyword list lives in one place:
[`core/platform/api/src/vpn_discovery.rs`](../../core/platform/api/src/vpn_discovery.rs),
in the `VPN_CONSUMER_KEYWORDS` / `VPN_CORPORATE_KEYWORDS` constants. Adding a
client is a one-line change.

There are three ways to get a client added.

### 1. Open a pull request

Add a distinctive keyword to the matching list and open a PR against
[github.com/kroxiksut/net-rule-router](https://github.com/kroxiksut/net-rule-router).

Please keep two rules in mind:

- **The keyword must be distinctive.** Matching is a substring test against real
  program names, so a short or common word causes false positives. Good:
  `"globalprotect"`, `"forticlient"`, `"vipnet"`. Avoid: bare `"secure"`,
  `"connect"`, `"access"`, `"client"`, `"gateway"`, or anything under ~5
  characters that appears in unrelated software.
- **Do not add a keyword that already contains "vpn"** — it is redundant, because
  any name with "VPN" is matched already.

If it helps reviewers, include the Windows executable name, the Linux package or
process name, and the macOS bundle identifier for the client.

### 2. Open an issue

If you cannot send a pull request, open an issue at
[github.com/kroxiksut/net-rule-router/issues](https://github.com/kroxiksut/net-rule-router/issues)
with:

- the product and vendor name,
- how it appears on your system: the Windows executable / "Add or remove
  programs" name, or the Linux package / process name, or the macOS app name.

### 3. Contact the maintainer

If a public issue is not an option, email <fmalkov91@gmail.com> with the same details.

## For VPN vendors

If you develop a VPN client and want it recognized out of the box, you are
welcome to open a pull request or issue as above, or email <fmalkov91@gmail.com>. Tell
us the exact executable / package / bundle identifiers your client ships under on
each platform so detection is reliable and free of false positives.
