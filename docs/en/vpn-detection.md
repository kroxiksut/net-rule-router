# VPN client detection

[Русский](../ru/vpn-detection.md)

NetRuleRouter can point itself at the program you use as your VPN. This is done
in **Settings → Routing behavior → Your VPN client**, or from the first-launch
onboarding. Telling the app which program is your VPN lets its traffic keep
flowing over your main link while leak protection (the kill switch) is on — so
the VPN can always reach its own server and reconnect, instead of being blocked
along with everything else.

You never *have* to use the built-in list. In the "Your VPN client" dialog you
can always choose **"My VPN isn't listed / pick it manually"** and point at the
program's `.exe` yourself. The list below only makes the program show up
automatically so you don't have to.

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
in the `VPN_NAME_KEYWORDS` constant. Adding a client is a one-line change.

There are three ways to get a client added.

### 1. Open a pull request

Add a distinctive keyword to `VPN_NAME_KEYWORDS` and open a PR against
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
