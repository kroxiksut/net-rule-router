# Open a site through the VPN

**English** · [Русский](../ru/adding-rules.md)

This page shows how to make one site, or one program, open through your VPN
instead of your ordinary internet.

## Three words first

- A **rule** is an instruction for the program: "open this site through that
  connection".
- The **main connection** is your ordinary internet. The **additional
  connection** is your VPN (or a second internet connection).
- A **domain** is the address of a site, such as `example.com`.

A site with no rule opens the ordinary way, over the main connection.

## Open one site through the VPN

Do this first: connect your VPN, as you always do.

1. Click **Rules** in the left column.
2. Click **Add**. A small window opens.
3. Leave **Rule type** on **Domain**.
4. In **Match value** type the site, for example `example.com`. You can paste
   the whole address from your browser: the program keeps only the site name.
5. Read the line under the field. It tells you what the rule will cover.
6. In **Connection** choose **Additional (e.g. VPN)**.
7. Click **OK**. The rule appears in the list.
8. Click **Apply** at the bottom of the window. A window called **Review
   changes** shows what will be added.
9. Click **Apply changes**.

Until step 9 the rule does nothing. That is on purpose: you see every change
before it starts to work.

Now open the site. If it was already open in your browser, press F5 to reload
it.

![Adding a rule: what it matches, which connection it takes, and what the match covers](images/rule-add.png)

**The site's other addresses.** One tick, **Include subdomains**, is on by
default. It makes the rule cover `www.example.com`, `cdn.example.com` and the
like, because a page loads its pictures from there. Leave it on.

**Many sites at once.** Switch the top of the window from **One rule** to
**Several rules** and type one site per line.

## From the tray

You do not have to open the main window.

1. Right-click the NetRuleRouter icon near the clock.
2. Click **Add rule…**.
3. Fill in the same small window and click **OK**.

The rule works at once, with no review step. A notice appears with an
**Undo** button, in case you change your mind.

![The tray menu](images/tray-menu.png)

## From a notice

The program notices when a site does not open and offers a fix.

- **A site does not open.** The notice names the site. Click **Add rule** to
  send it through the VPN. **Don't report again** hides the notice for that
  site.
- **Suggested addresses.** A site you routed may need a few more addresses to
  show fully. See [Suggested addresses](suggested-addresses.md).

## A program instead of a site

Use this for a game, a torrent client or any program that should always go
through the VPN.

1. In **Rules** click **Add**.
2. Set **Rule type** to **Application**.
3. Type the program's file name, for example `browser.exe`, or click
   **Browse...** and pick the program.
4. Set **Connection** to **Additional (e.g. VPN)** and click **OK**, then
   **Apply**, then **Apply changes**.
5. **Close the program and start it again** if it was already running.

Not sure what the program is called? In **Rules** click **Where traffic is
going**. It lists recent connections by program. Right-click a line and choose
**Rule for this application…**.

## If you need more

- A rule can also be an IP address, a group of addresses or a whole ending such
  as `.ru` (a "zone"). Choose it in **Rule type**. A rule about one site always
  beats a rule about a whole zone.
- **Deny** (a choice in **Connection**) means "do not open this at all".
- Programs the computer needs to stay online (system programs and services)
  cannot be routed or denied; the window tells you before saving.
- If two rules disagree, the narrower one wins:
  [What takes priority](what-takes-priority.md).
- Writing rules by hand in a text file: [Rules format](rules-file-format.md).
- In the terminal version, on the **Rules** screen press `a` to add a rule and
  `Ctrl+S` to apply: [the terminal interface](tui.md).

## See also

- [Change or remove a rule](changing-rules.md)
- [A site does not open](site-does-not-open.md)
- [Questions and answers](questions.md)
