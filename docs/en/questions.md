# Questions and answers

**English** · [Русский](../ru/questions.md)

![NetRuleRouter](../images/logo-lockup-en.png)

Short answers to the questions people ask first. Each answer links to the
page with all the steps.

## The basics

### What is a rule?

A rule is an instruction for the program: "open this site through the VPN" or
"open this site the ordinary way". Sites with no rule open the ordinary way.
[Open a site through the VPN](adding-rules.md)

### Is this a VPN? Do I need a VPN?

No, NetRuleRouter is not a VPN and does not make one. It decides which of your
sites use the connection you already have. To send sites through a VPN you need
a VPN program of your own, installed and signed in. It can also be a second
internet connection instead of a VPN.
[Choose your main and additional connection](connections.md)

### Does it slow my internet down?

The program only chooses which connection a site uses; it does not carry your
traffic itself. A site that goes through a VPN is as fast as your VPN is. If a
site is slow, you can send it the other way in a minute.
[A site does not open or is slow](site-does-not-open.md)

### Does it send my data anywhere?

Nothing about you or how you use it: there is no account and there are no
usage reports. The program does look up the
addresses of the sites named in your rules, and public DNS servers can see
those names. Everything it asks of the network is listed in
[Security](../../SECURITY.md), under "Network activity of the product itself".

## Rules

### How do I open a site through the VPN?

Connect your VPN. Click **Rules**, then **Add**, type the site in **Match
value**, set **Connection** to **Additional (e.g. VPN)**, click **OK**, then
**Apply** and **Apply changes**. Reload the site in your browser.
[Open one site through the VPN](adding-rules.md#open-one-site-through-the-vpn)

### I added a rule and nothing changed

A new rule works only after **Apply** and **Apply changes**. The only
exception is a rule added from the tray menu. A page that was already open
needs a reload (F5).
[Nothing happens until you press Apply](changing-rules.md#nothing-happens-until-you-press-apply)

### How do I undo a change?

Before **Apply**: click **Cancel**. After **Apply**: use the filter **Recent**
in **Rules** and click **Restore** on a deleted rule. A rule added from the
tray has an **Undo** button in its notice.
[Take a change back](changing-rules.md#take-a-change-back)

### How do I save my rules to a file?

**Settings** → **Rules and settings files**. Choose a folder of your own under
**My rule sets**, then click **Save current rules as a set...**, type a name and
click **Save set**.
[Save your rules](rule-sets.md#save-your-rules)

### How do I load my rules back, or on another computer?

Copy the saved files to the other computer. There click **Rules** →
**More...** → **Load rules list...**, pick the files and click **Import**, then
apply. On the same computer, pick the set in the row **My rule set:** and
click **Load**.
[Move your rules to another computer](rule-sets.md#move-your-rules-to-another-computer)

### How do I load the ready-made rules for my country?

Click **Rules**. In the row **Ready-made set:** choose your country and click
**Load**. Read the window **Review changes**, then click **Apply changes**.
Your own rules are replaced, so save them first.
[Load the ready-made set](rule-sets.md#load-the-ready-made-set-for-your-country)

## Connections and protection

### How do I turn protection on or off?

It is on from the start with **Routed sites**: if the VPN is off, drops, or
starts later than Windows, the sites you send through it wait instead of going
out directly, so a service with regional restrictions does not see your real
region. To change it: **Settings** → **Routing behavior** → **Leak
protection**. **Off** changes nothing. **Routed sites** stops only the sites
from your rules while the VPN is down. **Everything** stops the whole internet
until the VPN is back. It works at once.
[Turn protection on or off](pause-and-protection.md#turn-protection-on-or-off)

### The VPN got the "main" role by mistake. How do I swap?

Click **Connections**. On the VPN's card click **No longer main**. Then click
**Main** on your ordinary internet card and **Additional (e.g. VPN)** on the
VPN card. There is nothing to apply.
[Swap them, or pick another VPN](connections.md#swap-them-or-pick-another-vpn)

### How do I pick another VPN?

Connect the new VPN, click **Connections**, click **No longer additional** on the
old card, then **Additional (e.g. VPN)** on the new one.
[Swap them, or pick another VPN](connections.md#swap-them-or-pick-another-vpn)

### I installed another VPN program, or my VPN stopped being found

The old connection is gone, so your rules have nowhere to go. Choose the new
connection as above, and in **Settings** → **Routing behavior** → **Your VPN
client** click **Set up my VPN**.
[Your VPN changed](connections.md#your-vpn-changed)

### My VPN connected, but sites from the rules still do not open through it

Some VPN programs install several identical connections and use any of them.
If the VPN was off during first setup, the wizard asks you to turn it on, so it
can see which one the VPN uses. Later, NetRuleRouter follows the VPN to the
connection it really uses by itself. If it asks you to choose, pick the one
marked as connected, or open **Connections** and click **Additional (e.g. VPN)**
on that card.
[Your VPN changed](connections.md#your-vpn-changed)

## When something is wrong

### A site does not open

Click **Diagnostics**, type the site in **Check a site** and click **Check
site**. The answer says what to do. If the site's rule sends it through the
VPN and it does not answer, send it the other way: **Rules** → rule →
**Edit** → **Connection**.
[A site does not open or is slow](site-does-not-open.md)

### A site doesn't open while the VPN is off — is that normal?

Yes, if the site is in your rules for the VPN. Leak protection is on by
default and holds such sites until the VPN is back, so they never go out
directly; a notification says **The additional connection is not up**. Start
the VPN and reload the page. Sites outside your VPN rules keep opening. If you
would rather have them open over your ordinary internet, turn protection off.
[When a site waits for the VPN](pause-and-protection.md#when-a-site-waits-for-the-vpn) ·
[Turn protection on or off](pause-and-protection.md#turn-protection-on-or-off)

![Connection trace: a site held while the VPN is off](images/conn-trace-blocked.png)

### The browser shows an error page when the VPN is off

That is leak protection doing its job: the site you routed through the VPN is
not allowed to go out without it. It opens again when the VPN is back. To
change this, see the protection setting above.
[Browser error pages](blocked-site-browser-errors.md)

### How do I pause everything quickly?

Right-click the tray icon, click **Turn off rules…**, choose the time, type a
reason and click **Turn off now**. To end the pause early, click **Turn rules
on** in the same menu.
[Pause everything quickly](pause-and-protection.md#pause-everything-quickly)

### My internet is gone

**Settings** → **Service management** → **Restore network**.
[Recovering network access](recovering-network-access.md)

## The program itself

### How do I update the program?

The program does not check for updates. New versions appear on the
[releases page](https://github.com/kroxiksut/net-rule-router/releases) and in
the Telegram channel. Install the new version over the old one; your rules and
settings stay.
[Quick start: Updating](quickstart.md#updating)

### How do I remove the program?

Windows Settings → Apps → NetRuleRouter → Uninstall, then choose whether to
keep your settings.
[Start over, reset or remove the program](start-over-or-remove.md#remove-the-program)

### Where do I ask for help?

In the Telegram channel [t.me/netrulerouter](https://t.me/netrulerouter), in
English or Russian, or by e-mail: fmalkov91@gmail.com. Bug reports go to the
[project page](https://github.com/kroxiksut/net-rule-router) (Issues). The
program menu has the same channel under **Telegram channel (help and news)**.
