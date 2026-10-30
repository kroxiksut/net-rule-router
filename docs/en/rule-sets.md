# Save your rules and load them back

**English** · [Русский](../ru/rule-sets.md)

This page shows how to save your rules to a file, load a ready-made list for
your country, and move your rules to another computer.

## What a rule set is

A rule set is your list of rules saved as two small text files: one for the
main connection and one for the additional one (usually the VPN). The program
brings ready-made sets for several countries. You can make your own, such as
"home" and "work". The files keep rules only; they do not remember which of
your connections is the VPN.

## Save your rules

Do this once, and your rules are safe even if you reinstall the program.

1. Click **Settings** in the left column, then **Rules and settings files**.
2. Under **My rule sets** click **Browse...** and pick a folder of your own,
   for example in Documents. Do not pick the program's own folder: an update
   replaces it, and your set with it.
3. Click **Save current rules as a set...**.
4. Type a name, for example `home`, and click **Save set**.

From now on the row above your rules is called **My rule set:** and lists the
sets from your folder. To go back to a saved set, choose it there and click
**Load**.

A quicker way, from **Rules**: click **Save rules...** and choose **Save as a set (both connections)…**.

## Load the ready-made set for your country

1. Click **Rules** in the left column.
2. In the row **Ready-made set:** open the list. It reads **Choose a rule
   set...** until you pick one.
3. Choose your country, then click **Load**.
4. The **Review changes** window opens. Read it and click **Apply changes**.

**Your own rules are replaced.** The **Removed** column shows every rule of
yours that would go. If you want to keep your rules, click **Cancel**, save
them first (above) or use "Add a set to what you have" below.

Nothing changes until you click **Apply changes**.

The row is missing? It was hidden. Turn it back on in **Settings** →
**Rules and settings files** → **Show ready-made rule sets above the rules list**.

## Add a set to what you have

1. In **Rules** click **More...** and choose **Load rules list...**.
2. Pick one or two `.txt` files (one per connection).
3. Under **Import mode** choose **Merge — add new rules, skip duplicates**. Your
   rules stay; only the missing ones are added.
4. Click **Import**, read **Review changes**, click **Apply changes**.

## Move your rules to another computer

1. On the first computer: **Rules** → **Save rules...** → **Save as a set (both connections)…**. You get two files.
2. Copy the files to the other computer (USB stick or a cloud folder).
3. On the other computer: **Rules** → **More...** → **Load rules list...**,
   pick the files, choose how to import, click **Import**, then apply.

The other computer needs its own connections first: see
[Choose your main and additional connection](connections.md).

## Start with no rules

- At the very first start, choose **Start empty** in the welcome window. The
  next start offers your country's set once.
- Later: **Rules** → **More...** → **Clear all rules...**. This cannot be
  undone, so save your rules first.

## If you need more

- Only one connection's rules: **More...** has "Export only the main connection's rules to a file..." and
  "Export only the additional connection's rules to a file...".
- You can edit the files in any text editor: [Rules format](rules-file-format.md).
  Afterwards click **More...** → **Update rules from file**.
- Installing on many computers: [Unattended installation](unattended-install.md).
- In the terminal interface, on the **Rules** screen: `p` loads a country set,
  `i` imports, `x` exports: [the terminal interface](tui.md).

## See also

- [Open a site through the VPN](adding-rules.md)
- [Change, switch off or delete a rule](changing-rules.md)
- [Start over, reset or remove the program](start-over-or-remove.md)
- [Questions and answers](questions.md)
