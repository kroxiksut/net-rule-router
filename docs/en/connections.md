# Choose your main and additional connection

**English** · [Русский](../ru/connections.md)

This page shows how to tell the program which connection is your ordinary
internet and which one is your VPN, how to swap them if you chose wrong, and
what to do when your VPN changes.

## The two connections

- The **main connection** is your ordinary way to the internet: Wi-Fi, cable,
  your provider.
- The **additional connection** is where your rules send chosen sites. Most
  often it is a VPN. It can also be a second provider or a second network card.

NetRuleRouter does not make a VPN. Install your VPN program and sign in as
usual. NetRuleRouter only decides which sites use it.

## Choose them

1. Connect your VPN first. The program sees a connection only while it is up.
2. Click **Connections** in the left column. You see a card for every network
   connection of the computer.
3. On the card of your ordinary internet click **Main**.
4. On the card of your VPN click **Additional (e.g. VPN)**.

The choice is saved at once. There is nothing to apply. The button you pressed
now reads **No longer main** or **No longer additional**.

Not sure which card is the VPN? Click **Check external address**. It shows the
address the internet sees through each connection. The VPN's is different from
your provider's.

![Connections: the main and the additional connection](images/interfaces-routes.png)

The VPN is not in the list? Connect it, then click **Refresh connections**.
Still missing: tick **Show unavailable adapters**. In the welcome window you
need neither: a VPN program found on the computer is listed even while it is
off, marked "not connected now", and can be chosen right away.

## Swap them, or pick another VPN

A connection cannot be both. So to swap, or to pick a different VPN:

1. On the card that holds the wrong role click **No longer main** (or **No
   longer additional**).
2. On the right card click **Main** (or **Additional (e.g. VPN)**).

For example, you chose the VPN as main by mistake: click **No longer main** on
the VPN card, then **Main** on your ordinary internet card, then **Additional
(e.g. VPN)** on the VPN card.

## Your VPN changed

- **You installed another VPN program, or reinstalled the old one.** The old
  connection is gone and your rules have nowhere to go. The tray says so and
  offers the connections to choose from. Pick the new one there, or open
  **Connections** and click **Additional (e.g. VPN)** on its card. Then do
  "Tell the program about your VPN program" below.
- **Your VPN has several identical connections.** Some VPN programs install
  a few and use whichever they like. If the VPN comes up on another one than
  you chose, NetRuleRouter moves the additional connection to the one the VPN
  really uses and remembers it. You do not need to do anything. If two of them
  are connected at the same time, the program asks you which to use: pick the
  one marked as connected.
- **The VPN is just switched off.** Nothing to fix: your rules work again as
  soon as it connects. What happens to your traffic meanwhile depends on leak
  protection: [Pause everything, and leak protection](pause-and-protection.md).

## Tell the program about your VPN program

Needed when leak protection is on: your VPN program must be able to reach its
own server, and the program has to know which one it is.

1. Click **Settings**, then **Routing behavior**.
2. Under **Your VPN client** click **Set up my VPN** (or **Change**).
3. Click **Scan for VPN apps**. Nothing is sent anywhere.
4. Tick your VPN program (and its helper, if it has one) and click **This is
   my VPN**.
5. Not in the list? Choose to pick the program file yourself. No VPN at all?
   Click **I don't use a VPN**.

![Your VPN client: the programs found on this computer](images/vpn-client.png)

[VPN client detection](vpn-detection.md) lists the VPN programs the program
recognises.

## If you need more

The **Mode** list on the **Connections** screen decides where sites with no
rule go:

- **Main connection — selected sites through the additional one.** The usual
  choice: only your rules use the VPN.
- **Additional connection — exceptions through the main one.** Everything uses
  the VPN; only your rules go the ordinary way.

You can rename the two connections in **Settings** → **Application** →
**Connection names**. In the terminal interface the **Connections** screen has
the same choices: [the terminal interface](tui.md).

## See also

- [Pause everything, and leak protection](pause-and-protection.md)
- [A site does not open](site-does-not-open.md)
- [Routing modes](routing-modes.md)
- [Questions and answers](questions.md)
