# Change, switch off or delete a rule

**English** · [Русский](../ru/changing-rules.md)

This page shows how to send a site the other way, switch a rule off for a
while, delete it, and take a change back.

## Nothing happens until you press Apply

Whatever you do in **Rules** is only a draft. The old rules keep working until
you click **Apply** at the bottom of the window.

1. Click **Apply**. A window called **Review changes** opens.
2. It lists what will change in three columns: **Added**, **Removed**, **Modified or retargeted**.
3. Click **Apply changes** to confirm, or **Cancel** to go back.

If nothing differs, the program says "Nothing to apply".

![Review before applying: the full list of changes, waiting for your confirmation](images/review-changes.png)

The one exception is a rule added from the tray menu: it works at once and the
notice has an **Undo** button.

## Send a site through the other connection

1. Open **Rules** and click the rule.
2. Click **Edit**.
3. In **Connection** choose the other one. **Main** is your ordinary internet,
   **Additional (e.g. VPN)** is the VPN.
4. Click **OK**, then **Apply**, then **Apply changes**.

Several rules at once: tick the boxes at the left of the rows. A bar appears
with **Change connection**, **Enable**, **Disable** and **Delete...**.

Not sure which connection a site works on? Tick **Unsure — check where it
works** in the same window. The program tries the site and offers to move the
rule if it only opens the other way.

## Switch a rule off without deleting it

In the **On** column, untick the box of the rule. The rule stays in the list
but does not work. Tick it again to bring it back. Then **Apply**.

To switch off everything for a while, see
[Pause everything, and leak protection](pause-and-protection.md).

## Delete a rule

1. Click the rule, then click **Delete**.
2. Confirm **Delete this rule?**.
3. Click **Apply**.

The site goes back to the ordinary way when you apply.

## Take a change back

- **You have not pressed Apply yet.** Click **Cancel** at the bottom of the
  window. Your unapplied edits are dropped.
- **You already applied.** Set the filter **Recent** to the last hour, today or
  7 days. It lists what you added or changed, newest first. Deleted rules are
  listed below it; **Restore** puts one back. Apply again.
- **A rule added from the tray.** Click **Undo** in the notice.

## Find a rule

Type in **Search** (the site, the address or a word from your comment). The
filters next to it narrow the list.

If a banner says the rules are managed by your administrator, the buttons are
off on purpose; you can still look, search and save.

## In the terminal interface

On the **Rules** screen: `e` edits, `Space` switches a rule on or off, `d`
deletes, `Ctrl+S` applies. See [the terminal interface](tui.md).

## See also

- [Open a site through the VPN](adding-rules.md)
- [Save your rules and load them back](rule-sets.md)
- [A site does not open](site-does-not-open.md)
- [What takes priority](what-takes-priority.md)
