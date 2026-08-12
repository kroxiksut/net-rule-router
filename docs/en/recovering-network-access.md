# Recovering network access

NetRuleRouter's protections — the kill-switch, per-site routing, and (in Mode B)
directing name resolution through the app — are enforced by Windows itself, not
by the app process. That is what makes them reliable: they keep working even if
the app's window is closed. It also means that if the background service stops
**abnormally** (a crash, or a forced kill) while a protection is active, that
protection can outlive the service and leave the machine unable to reach the
network or resolve names, with no running service left to lift it.

This only happens after an abnormal stop. A normal **Stop**, **Exit**, or
**Uninstall** always restores networking cleanly — you never need this page for
those.

If it does happen, there are two ways to recover.

## Option 1 — Reboot

The simplest fix. NetRuleRouter's routing and name-resolution changes are
designed to clear on restart, so a reboot returns the machine to its normal
networking on its own.

## Option 2 — Reset without rebooting

Run the reset helper from an elevated PowerShell (it self-elevates via UAC — no
interactive prompts):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\reset-network.ps1
```

It stops the service if it is still running, then restores networking to its
default state — removing the app's traffic filters, its routes, and its DNS
redirect — so the network resolves normally again immediately. A reboot
afterwards is optional and clears any last remainder.

> This is a safety escape hatch, not part of normal operation. Reach for it only
> after an abnormal termination has left the machine's network or DNS stuck.
