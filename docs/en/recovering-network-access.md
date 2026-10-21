# Recovering network access

**English** · [Русский](../ru/recovering-network-access.md)

NetRuleRouter's protections — leak protection, per-site routing, and (with the
local DNS resolver, the default) directing name resolution through the app —
are enforced by Windows itself, not
by the app process. That is what makes them reliable: they keep working even if
the app's window is closed. It also means that if the background service stops
**abnormally** (a crash, or a forced kill) while a protection is active, that
protection can outlive the service and leave the machine unable to reach the
network or resolve names, with no running service left to lift it.

This only happens after an abnormal stop. A normal **Stop**, **Exit**, or
**Uninstall** restores networking. If the service could not hand the system DNS
settings back, the app says so and offers **Restore network** (Option 2 below).

If the service stops on its own while the tray, the window or the terminal
interface is running, they say so and offer **Start service** and **Restore
network**. A stop you asked for yourself stays silent.

A different case is leak protection doing its job. With leak protection set
to **Everything**, the internet waits while the additional connection is down,
and a reboot does not change that: the protection comes back with the
service. Bring the additional connection back, or set leak protection to
**Off**; if you cannot reach the settings, use Option 2.

If it does happen, there are two ways to recover.

## Option 1 — Reboot

The simplest fix. Traffic filters and routes clear on restart.

On Windows the DNS redirect is kept in the system settings and survives a
restart. The service removes it as it starts with Windows, and if the service
keeps failing to start, Windows hands name resolution back after the last
attempt. If the service has been disabled or removed, names may still not
resolve after a reboot — use Option 2.

On Linux a reboot clears the DNS redirect as well.

## Option 2 — Reset without rebooting

From an administrator console, reset. If the service still runs, it is
stopped first — a live service would put the state straight back — and ended if
it does not stop in time:

```
nrr-cli reset-network --confirm --stop-service
```

Without `--stop-service` the reset refuses while the service runs and tells you
this command. In the window the same action is "Stop service and restore
network" under Settings, Service.

The reset restores networking to its default state — removing the app's
traffic filters, its routes, and its DNS redirect — so the network resolves
normally again immediately. A reboot afterwards is optional and clears any last
remainder.

`--confirm` is required and never implied: open connections can drop when that
state goes, so the command tells you what it would remove rather than doing it
on a bare invocation. Without an administrator console, add `--elevate` (or
answer the question the console asks) to raise it. If the service has applied no
network state at all, the command says so instead of pretending to have cleaned
something. See [the `nrr-cli` console](cli.md).

On Linux the same commands undo the same things — the packet filters, the DNS
redirect and the routes the service added — with root rights instead of an
administrator console, and the service is stopped the same way. From a source checkout, `./scripts/reset-network.sh` does the same and
gets the network back even when no service binary is at hand.

> This is a safety escape hatch, not part of normal operation. Reach for it only
> after an abnormal termination has left the machine's network or DNS stuck.
