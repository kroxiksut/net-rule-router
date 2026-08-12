# Diagnostic archive: what it contains

When you run into a problem, NetRuleRouter can build a **diagnostic archive** — a single `.zip` file you can attach to a bug report. This page explains exactly what goes into it, so you can see that it collects only what is needed to diagnose an issue and nothing extra or personal.

The archive is built **only when you ask for it** — there is an "Export diagnostic archive" button in both the **Diagnostics** section and **Settings → Diagnostics and logs**. Nothing is ever sent anywhere automatically — the file is written to your own disk, and you decide whether to share it.

## Archive file name

Every archive gets a unique, sortable name of the form:

```
nrr-diagnostics-v<app-version>-<YYYYMMDD-HHMMSS>-<milliseconds>.zip
```

For example: `nrr-diagnostics-v0.1.0-pre-alpha-20260717-143205-812.zip`. The app version is embedded so a support technician can tell builds apart from the file name alone. If two archives are built in the same millisecond (practically never happens by hand), a `-1`, `-2`, … counter is appended so an existing file is never overwritten.

## What is inside

The archive is an ordinary `.zip` you can open and read yourself. Every export always contains:

| File | What it contains |
|------|-------------------|
| `manifest.json` | Archive format version, application version, build provenance (the exact build commit, build profile, and target the binary was compiled from), creation time, the applied privacy mode, and the list of sections included in this specific archive. |
| `system_info.json` | Basic facts about the computer the archive was built on: operating system and version, CPU architecture and model, number of logical CPU cores, total physical RAM, and the NetRuleRouter version. No user, account, or network-identifying data — hardware/OS facts only. |
| `health.json` | A snapshot of service, storage, cache, and log health — states and counters. It does not contain your rules. |
| `logs.ndjson` | Recent operational log lines, one JSON object per line, newest first, capped at 5 MiB before compression. Each line is a structured event (timestamp, level, category, a translated message key, and a decision/revision correlation id) — not free-text, so it does not carry raw hostnames or IP addresses. See the privacy note below. |
| `audit_summary.json` | Recent security-audit entries (at most 100). These are **summaries only**: event kind, timestamp, result, and reason code — never the raw event payload. |
| `troubleshooting.md` | A generated troubleshooting guide (common symptoms and remediation steps). This is static text, not your data. |

Today's export additionally includes, by default:

- `redaction_report.json` — a record of which privacy mode was applied and which fields are always hidden regardless of mode.

## Export detail level

The export offers two levels, chosen next to the export button:

- **Standard** (default, recommended) — the files listed above. This is what a normal bug report needs.
- **Full diagnostics** — everything in Standard plus three extra detail files, and a relaxed privacy mode. Choose this only when walking through a problem with support:

  - `cache_health.json` — FQDN/IP resolution-cache health detail.
  - `storage_health.json` — SQLite storage health detail.
  - `explain_samples.json` — a handful of recent routing-decision explanations. Unlike the other files, this one **can** include the destination hostname of the sampled decisions (that is its purpose — showing why a specific decision was made), subject to the applied privacy mode.

  Because the full level is less redacted, review the archive before sharing it.

The whole archive is capped at 50 MiB.

## "Only logs from the current session"

Next to the export button there is a checkbox, **on by default**, that limits how far back the included logs reach. With it enabled the archive covers your **current working session**, bounded by whichever of these two events happened most recently:

- the start of the calendar day the app session began, or
- the most recent start of the background service that followed a pause of at least **30 minutes**.

In practice that means: restarting the app or the service in the middle of a test does **not** cut the earlier part of that test out of the archive, but this morning's unrelated session (or yesterday's) stays out. Uncheck the box to export the full log history instead.

This window applies both to the merged `logs.ndjson` and to the raw service log files attached to the user copy (see below).

## What is never included

The following are structurally excluded and can never appear in an archive:

- **Raw database files** — your rules, the resolution cache, and the service-state databases are never packaged.
- **Private keys or any secret material** — fields marked as secret cannot be serialized at all, by design.
- **Full policy content or policy backups.**
- Anything outside the sections listed above — **no browsing history, no credentials, no file contents, no keystrokes, and no telemetry.**

## Privacy note: domain names and IP addresses

The default privacy mode used for every archive reduces a hostname to its registrable domain (for example, `updates.example.com` becomes `example.com`) and replaces an IP address with a category marker (`<private-ipv4>` or `<public-ipv4>`) instead of the address itself. `logs.ndjson` and `audit_summary.json` are structured event records (message keys and correlation ids), so under normal export they do not carry raw hostnames or IP addresses at all.

The one exception is the optional `explain_samples.json` section described above: because its whole purpose is to show why a routing decision was made, it can include a destination hostname. This section is off by default and only appears in a **Full diagnostics** export.

Because the archive is a plain, human-readable `.zip`, you can always open any file inside it and inspect — or remove — a line before sharing it.

## Where it is saved

The background service builds the archive first, in its own protected data directory (`C:\ProgramData\NetRuleRouter\archives`) — the service runs as SYSTEM and must never write into a location a lower-privileged process could tamper with. Immediately afterwards, the app (the launcher) copies that file into a folder you own outright: `%TEMP%\NetRuleRouter`. That copy is what the "Export diagnostic archive" button reports back and what "Open folder" opens.

The user copy also has extra files the service-side original does not have: `launcher-main.log` and `launcher-tray.log` — the app's own GUI-side log files, appended into the copy because the service (which never reads files from your user profile) cannot see them — plus a `service-logs/` folder with the raw operational NDJSON files for the covered session window, newest first, up to 24 MiB in total (the oldest attached file is trimmed to its tail if it would overflow that budget). If you ever need the untouched, service-built original instead, its path is preserved internally as the export's "service archive path"; in the normal flow you only need the user copy the button gives you.

If the copy step fails for any reason (for example, a permissions problem), the export still succeeds — you are simply given the path to the service-owned original instead.
