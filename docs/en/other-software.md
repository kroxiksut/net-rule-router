# Living alongside other software

**English** · [Русский](../ru/other-software.md)

NetRuleRouter sets rules over the connections you already have, so it often
runs next to other network software. This page lists what is known to work
together, what to expect, and what to do. "Checked" means we tried it on a
real machine; "not checked yet" means we expect it to behave as written but
have not watched it happen.

| Software | What to expect | What to do | Status |
|---|---|---|---|
| Antivirus with HTTPS scanning (for example Kaspersky "scan encrypted connections") | The antivirus opens encrypted connections itself, so a browser or a site check can show a certificate error that looks like "the site does not work". Routing is not the cause. | Judge a site by whether it opens in the browser; if errors appear only with the antivirus on, add the site to the antivirus exclusions. | Checked |
| Your own VPN client with its own kill switch | Two kill switches can block each other when the tunnel drops. | Use one at a time: turn off the client's own kill switch and let leak protection do that job, or the other way round. Tell the app which program is your VPN (see [VPN client detection](vpn-detection.md)). | Checked |
| A corporate VPN beside yours | It keeps its own networks and names. With leak protection set to **Everything**, a VPN other than the ones built into the system is stopped the first time it connects, and the app asks you once whether to let it connect. | Answer the question once. On Linux a WireGuard connection needs a name that says it is a VPN; see [VPN client detection](vpn-detection.md#a-second-vpn-beside-yours). | Not checked yet |
| Virtual machine software (VirtualBox, VMware) | Its virtual adapters can add wide routes that capture private addresses (for example `192.168.x.x`). | If a local address stops answering, check the routes of the virtual adapter. | Checked |
| Other security software that filters traffic (firewalls, corporate agents) | Two products that both filter can cancel each other's allow rules. A connection may be refused by the other product, not by NetRuleRouter. | If something is blocked and your rules look right, test with the other product paused. | Not checked yet |
| Another local DNS filter (AdGuard, Pi-hole, dnscrypt on the same computer) | NetRuleRouter's name resolver cannot start while another program holds the same address. Your system DNS is left untouched, so nothing breaks, but names are not routed in advance. | Use one local DNS program at a time. | Not checked yet |
| Windows Group Policy that manages DNS | Windows may ignore the local resolver: a rule for a site name takes effect only after the first connection to the site. | See [Known limitations](known-limitations.md#computers-managed-by-group-policy-for-dns). | Not checked yet |
| Tailscale, wg-quick and similar on Linux | Their own routing rules may take traffic before NetRuleRouter's. | Check that the connection you route through is not captured by them. | Not checked yet |
| Docker, libvirt, LXC on Linux | Traffic forwarded for containers and virtual machines follows the rules and leak protection of the user who signed in first. | Choose in Settings whether they get the same leak protection as the computer; see [Several users](several-users.md#containers-and-virtual-machines). | Not checked yet |
| A firewall service that reloads or flushes its rules (firewalld, ufw, nftables service) on Linux | A reload by that service can remove NetRuleRouter's rules until its next check. | Avoid reloading it while leak protection matters; restart the NetRuleRouter service afterwards. | Not checked yet |
| Strict reverse-path filtering on Linux (RHEL family, RED OS) | A second signed-in user may get no replies. | See [Known limitations](known-limitations.md). | Not checked yet |
| Browser with its own encrypted DNS | It hides names from the rules. | Keep the setting that blocks it, or give the browser a rule of its own. See [Known limitations](known-limitations.md). | Checked |

Found a combination that misbehaves? Open an issue with the name and version of
the other program; the table grows from such reports. Not sure it is the other
program? Ask in the Telegram channel [t.me/netrulerouter](https://t.me/netrulerouter)
first.
