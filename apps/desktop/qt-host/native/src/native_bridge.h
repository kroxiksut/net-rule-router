#pragma once

#include "host_support.h"

class NrrNativeBridge : public QObject {
    Q_OBJECT

public:
    explicit NrrNativeBridge(const QString &applicationDir, QObject *parent = nullptr);

    Q_INVOKABLE void triggerTrayAction(const QString &actionId);

    Q_INVOKABLE bool savePreferences(const QString &serializedPayload);

    Q_INVOKABLE QVariantMap takePendingGuiRequest();

    /// SHA-256 hex digest of the UTF-8 bytes of an arbitrary QString.
    /// Used by the rules-update review flow to derive the
    /// `content-hash` field on dry-run payloads. The digest is
    /// computed locally with QCryptographicHash so we avoid an extra
    /// Rust round-trip per dry-run.
    ///
    /// Caveat: this hashes the QML-side string verbatim. JavaScript's
    /// `JSON.stringify` is not strictly canonical (insertion-order
    /// keys, no whitespace stripping); the result is deterministic
    /// *for our `_buildRulesJson` codepath* (which builds DTOs in a
    /// fixed order) but will NOT match a server-side hash computed
    /// from `nrr_shared::rules_json::to_canonical_string`. The wire
    /// schema treats `content-hash` as an opaque idempotency key —
    /// mismatch with the server just skips the dedup short-circuit,
    /// which is a soft failure (worst case: same rules trigger two
    /// reviews). Promotion to true canonical hashing is tracked as a
    /// follow-up.
    Q_INVOKABLE QString sha256Hex(const QString &input);

    /// Decode a base64 payload as UTF-8 text. The legacy
    /// `decodeURIComponent(escape(Qt.atob(...)))` trick in QML throws
    /// `URIError: malformed URI sequence` on certain Cyrillic byte
    /// patterns (and Qt.atob itself is deprecated). Funneling base64
    /// decoding through Qt's `QByteArray::fromBase64` + `QString::fromUtf8`
    /// avoids the JS-side gymnastics and yields a clean QString.
    Q_INVOKABLE QString decodeBase64Utf8(const QString &b64);

    /// Convert a Unicode hostname (e.g. `пример.рф`) to its Punycode/ASCII
    /// representation (`xn--e1afmkfd.xn--p1ai`). Returns an empty string
    /// when the input is empty or already ASCII (no conversion needed —
    /// caller can detect equality to decide whether to hint Punycode in
    /// the UI). Qt's QUrl::toAce handles the IDNA2003 ToASCII algorithm
    /// per RFC 3490 / Unicode TR46 transitional rules.
    Q_INVOKABLE QString punycodeEncodeHost(const QString &hostname);

    /// Convert a Punycode/ASCII hostname (e.g. `xn--p1ai`) to its
    /// Unicode representation (`рф`). Used by the GUI ↔ Service
    /// boundary: rules stored on the wire / WFP filters / SQLite are
    /// ACE-encoded, the GUI displays the human-readable form. Returns
    /// the input unchanged when no `xn--` label is present or the
    /// decoding fails. `QUrl::fromAce` round-trips through Unicode TR46.
    Q_INVOKABLE QString punycodeDecodeHost(const QString &hostname);

    /// Place `text` on the system clipboard. Used by the Logs section
    /// "Copy row" context-menu so users can paste log lines into
    /// support tickets without selecting + Ctrl+C through several
    /// disjoint Label controls.
    Q_INVOKABLE void copyToClipboard(const QString &text);

    /// Work area of the screen the tray icon lives on — taskbar excluded,
    /// whichever edge it is docked to. QML sees only `Screen.desktopAvailable*`,
    /// which is the bounding box of EVERY screen: on a two-monitor desktop it
    /// put the tray notice past the right edge of the primary one and onto the
    /// neighbour, where an unseen window still silenced every notice behind it.
    /// Empty map means "no screen" — the caller keeps its own fallback.
    Q_INVOKABLE QVariantMap trayNoticeScreenGeometry() const;

    /// Return whether the current process is running with elevated
    /// privileges (Administrator). The service's
    /// `MutationSubmit` / `RoutePolicyUpdate` IPC ops gate on this via
    /// the named-pipe identity classifier, so the GUI uses the value
    /// to render an upfront warning in the review flow — better UX
    /// than letting the user reach ConfirmActivateDialog only to
    /// discover the activate phase fails with `forbidden`.
    /// Defaults to `true` on non-Windows or query failure so the
    /// warning never falsely fires.
    Q_INVOKABLE bool isElevated();

    /// Open the OS file manager at the folder containing `path`, selecting
    /// the file when it exists. Used by the Rules section's "open source
    /// folder" affordance so the user can find the bound preset file.
    /// `path` is a local filesystem path (the launcher's `lastSavedPath*`).
    Q_INVOKABLE void openContainingFolder(const QString &path);

    /// Programmatic grayscale of a tray icon. SystemTrayIcon on
    /// Qt.labs.platform only accepts a URL; runtime QImage transforms
    /// must be done off-band and saved to a file. We grayscale once on
    /// first call (preserving alpha so the tray still anti-aliases against
    /// the shell background) and cache the path. Returns the file:// URL
    /// of the cached PNG, or an empty string if the source could not be
    /// loaded.
    Q_INVOKABLE QString prepareTrayGrayscaleIcon(const QString &sourceUrl);

    /// Generic status-overlay icon compositor. Draws a colored dot in
    /// the bottom-right quadrant of the source icon and returns the
    /// file URL of the cached PNG.
    ///
    /// `statusKind` ∈ `{running, stopped, pending, not-installed,
    /// unknown, paused}`. Colors are hardcoded so QML can stay declarative.
    /// Single-entry cache keyed by `(sourceUrl, statusKind)`.
    Q_INVOKABLE QString prepareTrayStatusIcon(const QString &sourceUrl,
                                              const QString &statusKind);

    Q_INVOKABLE bool ensureTrayRunning();

signals:
    /// Emitted at most once, when the tray process this host spawned is
    /// observed to have exited while no application-shutdown flag is present
    /// — i.e. it was killed from the outside (Task Manager, `taskkill`, a
    /// crash) rather than through the tray's own "Exit". QML reacts by
    /// running its normal application wind-down: without a tray icon there
    /// is no surface left to reopen or exit the application from, so an
    /// orphaned GUI (possibly hidden by close-to-tray) is unreachable.
    ///
    /// Deliberately NOT emitted when the shutdown flag exists: that is the
    /// intentional-exit path and its QML poller already drives the same
    /// wind-down.
    void trayProcessDied();

    /// The desktop changed its light/dark preference while the window is up.
    /// Carries no value on purpose: Qt is the TRIGGER, the launcher's probe is
    /// the ANSWER (`rpcSystemTheme`). Two sources for one question is how a
    /// window ends up disagreeing with its own settings page.
    void systemAppearanceChanged();

public:

    // The main GUI polls this from QML; when the tray's "Exit" handler has
    // written the shutdown flag, this returns true exactly once (the flag is
    // consumed) and the GUI then closes itself without minimising to tray.
    Q_INVOKABLE bool consumeApplicationShutdownRequest();

    // Full reset: ask the tray to exit. The main GUI that initiates the
    // reset closes ITSELF directly (window.close + Qt.quit); this writes
    // the dedicated `tray-shutdown.flag` the tray polls
    // (`consumeTrayShutdownRequest`) so a "close everything" gesture takes
    // the tray down too. Separate from `app-shutdown.flag` to avoid a
    // consume race with the tray's own Exit path.
    Q_INVOKABLE bool requestTrayShutdown();

    // Tray polls this (Tray.qml) and quits when it returns true. Consumed
    // exactly once (the flag is deleted on read).
    Q_INVOKABLE bool consumeTrayShutdownRequest();

    // Full reset: delete the GUI/launcher log files (`*.log` in
    // %TEMP%\NetRuleRouter). Best-effort — a file the
    // launcher happens to hold open this instant is skipped (it reopens
    // append-mode per line, so it is usually closed). The service's own
    // operational logs are cleared via the `logs.clear` RPC, and the
    // security audit trail is deliberately never touched.
    Q_INVOKABLE int clearGuiLogs();

    void setMainWindow(QWindow *window) { mainWindow_ = window; }

    /// Subscribe to the platform's colour-scheme hint. Qt carries this on every
    /// OS it supports (registry broadcast on Windows, the desktop portal on
    /// Linux), which is why the watch lives here rather than behind another
    /// per-OS port: the host is the only piece with a running event loop.
    void watchSystemAppearance();

    // Apply Windows DWM dark title bar to the main window. Native title bar
    // is rendered by the OS and ignores Qt palette / QML theme tokens, so a
    // dark/high-contrast app theme leaves the title bar light. Toggling
    // `DWMWA_USE_IMMERSIVE_DARK_MODE` (attribute 20 on Win10 20H1+/Win11,
    // attribute 19 on Win10 1809–1909) flips the OS-rendered title bar to
    // its dark variant. Called from QML on every theme change.
    Q_INVOKABLE void setMainWindowDarkTitleBar(bool dark);

    // ── RPC bridge to launcher ────────────────────────────────────────────
    //
    // QML invokes one of the `rpc<Op>` Q_INVOKABLE methods with a
    // payload (catalog: `nrr_shared::ipc::IpcOperationName`). The
    // bridge:
    //   1. mints a unique `correlation_id` (process-local monotonic);
    //   2. emits `NRR_IPC_REQUEST:<json>` on stdout (the launcher's
    //      stdout reader picks it up and dispatches via NamedPipeIpcClient);
    //   3. returns the correlation_id immediately so QML can connect a
    //      one-shot handler;
    //   4. when the launcher writes back `NRR_IPC_RESPONSE:<json>` on
    //      this process's stdin, the `RpcStdinReader` thread parses it
    //      and emits the `rpcResponse(...)` signal, which QML routes by
    //      correlation_id.
    //
    // The signal is emitted with a `Qt::QueuedConnection` semantics by
    // virtue of crossing thread boundaries — Qt's signal/slot delivery
    // automatically marshals to the receiver's thread.

signals:
    /// Emitted on the GUI thread whenever a `NRR_IPC_RESPONSE:` line
    /// arrives from the launcher. QML connects once and demultiplexes
    /// by `correlationId`. `ok = true` ⇒ `payload` carries the JSON
    /// response object. `ok = false` ⇒ `errorCode` + `errorMessage`
    /// are populated, `payload` is empty.
    void rpcResponse(QString correlationId, bool ok, QVariant payload,
                     QString errorCode, QString errorMessage);

public:
    /// QML uses this to populate the health snapshot on cold start and
    /// after reconnects.
    Q_INVOKABLE QString rpcServiceHealthGet();

    /// Write the caller's per-SID route policy (default route / behavior
    /// mode for traffic not matched by a rule). `payload` is a full
    /// RoutePolicyUpdateRequest (primary?/secondary?/mode/
    /// block-secondary-when-unavailable/binding-source). This is a PRIVILEGED
    /// mutation: a non-elevated GUI's request returns Forbidden, which the
    /// launcher transparently relays through the session elevation broker (one
    /// UAC, reused for the session) — same path as MutationSubmit.
    Q_INVOKABLE QString rpcRoutePolicyUpdate(const QVariantMap &payload);

    /// Persist the caller's confirmed VPN/link-provider executables as
    /// the service-side SSOT. `payload`
    /// is a RouteLinkProviderSetRequest ({role, link-provider-apps:[{exe-path,
    /// display-name}, ...]}); an empty app list clears the set. Feeds the
    /// per-app kill-switch exemptions and triggers an immediate server-side
    /// recompile. Same privileged relay path as `rpcRoutePolicyUpdate`.
    Q_INVOKABLE QString rpcRouteLinkProviderSet(const QVariantMap &payload);

    /// The local networks that stay reachable while the kill-switch blocks
    /// everything else: what the service discovered (the main link's subnets,
    /// the host side of hypervisor adapters) plus the user's own decisions.
    /// The write takes `{"decisions": [{"cidr", "allowed"}], "forget": [...]}`
    /// and answers with the list as it stands afterwards.
    Q_INVOKABLE QString rpcLocalNetworksGet();
    Q_INVOKABLE QString rpcLocalNetworksSet(const QVariantMap &payload);

    /// The hosts a routed site turned out to need, parked by the service
    /// while `auto-rules-mode` is `suggest`.
    /// The tray lists the pending candidates and then accepts or dismisses a
    /// set of them; both mutations take `{"ids": ["..."]}`. Payloads are opaque
    /// pass-through — the wire shapes live in `nrr_shared::ipc_payloads`.
    Q_INVOKABLE QString rpcAutoRuleCandidatesList();
    Q_INVOKABLE QString rpcAutoRuleCandidatesAccept(const QVariantMap &payload);
    Q_INVOKABLE QString rpcAutoRuleCandidatesDismiss(const QVariantMap &payload);
    /// Erases the service's memory of these suggestions (`{"ids": ["..."]}`) —
    /// the pending offer, the refusal and the quiet period after authoring —
    /// so the host is offered again once the evidence returns. Unlike a
    /// refusal, this records no answer.
    /// Ask the service to check whether the addresses behind these suggestions
    /// answer on the MAIN link (`{"ids": [...]}`, empty = every pending one).
    /// The reply only says the pass was accepted; verdicts arrive through the
    /// suggestion-changed push.
    /// Mark or unmark a routed site as answering the MAIN link with a refusal
    /// (`{"hostname": "...", "refusing": true}`). Answers with the full marked
    /// list. The only effect is that this site's companion addresses stop being
    /// quietened by "it answers on the main route".
    Q_INVOKABLE QString rpcRefusingAnchorSet(const QVariantMap &payload);
    Q_INVOKABLE QString rpcAutoRuleCandidatesProbe(const QVariantMap &payload);
    Q_INVOKABLE QString rpcAutoRuleCandidatesForget(const QVariantMap &payload);

    /// Refusals the user recorded via `rpcAutoRuleCandidatesDismiss`, for a
    /// "review your declined suggestions" surface. `rpcAutoRuleDismissedRestore`
    /// undoes a set of them (`{"ids": ["..."]}`) so the underlying hosts may be
    /// offered again — it does not resurrect the original offer, which
    /// re-appears the next time the site pulls the host.
    Q_INVOKABLE QString rpcAutoRuleDismissedList();
    Q_INVOKABLE QString rpcAutoRuleDismissedRestore(const QVariantMap &payload);

    /// Block-notice mutes: silence future notices for one host, one app, or
    /// everything. `rpcBlockNoticeMutesSet`/`Remove` take `{"scope": {...}}`
    /// (kind: host/app/all); `Set` also takes an optional `until-unix-ms`
    /// (absent = indefinite). Every response carries the caller's full mute
    /// list. Wire shapes live in `nrr_shared::ipc_payloads::BlockNoticeMutes*`.
    Q_INVOKABLE QString rpcBlockNoticeMutesList();
    Q_INVOKABLE QString rpcBlockNoticeMutesSet(const QVariantMap &payload);
    Q_INVOKABLE QString rpcBlockNoticeMutesRemove(const QVariantMap &payload);
    Q_INVOKABLE QString rpcBlockNoticeMutesClear();

    /// Notices raised while neither the tray nor the window was up. `List`
    /// returns them oldest first; `Ack` takes `{"through-id": <id>}` — the
    /// largest id the surface actually showed. Wire shapes live in
    /// `nrr_shared::ipc_payloads::BlockNoticeJournal*`.
    Q_INVOKABLE QString rpcBlockNoticeJournalList();
    Q_INVOKABLE QString rpcBlockNoticeJournalAck(const QVariantMap &payload);

    /// Turn one blocked destination into a rule that routes it over the
    /// additional link. `payload` is `{"destination": "<hostname>"}`.
    Q_INVOKABLE QString rpcBlockNoticeRouteToSecondary(const QVariantMap &payload);

    /// Full-reset support: erase the caller's auxiliary per-principal rows.
    /// No payload; response carries `{rows-deleted, tables-touched}`.
    /// `includeRulesHistory` additionally drops the service's own copy of this
    /// caller's rules (revision history + active pointer) — the full reset asks
    /// for it, routine cleanup does not.
    Q_INVOKABLE QString rpcPrincipalDataPurge(bool includeRulesHistory = false,
                                              bool allPrincipals = false);

    /// How many OTHER users this machine holds rules for. Read op; full reset
    /// asks it before deciding whose data it clears.
    Q_INVOKABLE QString rpcPrincipalDataCount();

    /// Read the SHARED DoH/DoT resolver baseline list (machine-wide,
    /// seeded with public resolvers by country). Read op, no
    /// elevation. The callback lands on `rpcResponse` with
    /// `{resolvers:[{target-kind, target, comment, enabled}, ...]}`.
    Q_INVOKABLE QString rpcDohResolversGet();

    // Read today+session totals (+ optional CSV) and write the
    // service-global traffic-stats settings.
    Q_INVOKABLE QString rpcTrafficStatsGet(const QVariantMap &payload);
    Q_INVOKABLE QString rpcTrafficStatsSet(const QVariantMap &payload);
    Q_INVOKABLE QString rpcTrafficStatsClear();
    // Answer the one-time "did this connection's history continue as that
    // one's?" question. A refusal travels the same way — it is an answer.
    Q_INVOKABLE QString rpcTrafficHistoryMergeSet(const QVariantMap &payload);

    /// Replace the ENTIRE shared DoH/DoT resolver baseline list.
    /// `resolversJson` is a serialised
    /// `{"resolvers":[{"target-kind":..,"target":..,"comment":..,"enabled":..}]}`
    /// object (JSON string so the array-of-objects payload rides one argument).
    /// PRIVILEGED — it edits the machine-wide baseline; a non-elevated GUI's
    /// request returns Forbidden, which the launcher transparently relays
    /// through the session elevation broker (one UAC, reused), same path as
    /// `rpcRoutePolicyUpdate`. A successful replace recompiles the caller's
    /// DoH-lockdown blocks at once.
    Q_INVOKABLE QString rpcDohResolversSet(const QString &resolversJson);

    /// Revoke the session elevation broker (the GUI's "revoke administrator
    /// approval" action). Routed to the launcher's
    /// `local.broker-revoke`, which retires the live elevated broker so the
    /// next privileged op prompts UAC again. No-op when no session is live.
    Q_INVOKABLE QString rpcBrokerRevoke();

    /// Probe of the elevation broker: is an elevated session live? Answered
    /// locally by the launcher (never spawns the broker, never prompts).
    /// Polled from the GUI status tick so the "revoke administrator approval"
    /// affordance reflects elevation acquired through ANY path, not just
    /// service-control actions. The payload may carry
    /// `auto-revoke-idle-secs` (0 = disabled) — the launcher retires a
    /// session that has sat unused at least that long and reports it via
    /// `auto-revoked` in the response.
    Q_INVOKABLE QString rpcBrokerStatus(const QJsonObject &payload);

    /// Relay a privileged service-control action
    /// (start/stop/restart/install/uninstall) through the launcher's
    /// session elevation broker. Called from `NrrServiceController` for a
    /// NON-elevated GUI so the first UAC (an apply OR a service action)
    /// spawns the broker and every later privileged action runs without
    /// another prompt. The launcher routes `local.service-control` to the
    /// broker, which executes `<service-exe-path> <action>` already-elevated.
    QString emitServiceControlRpc(const QString &action,
                                  const QString &serviceExePath);

    /// The big one — bundled initial state for the GUI's first render.
    Q_INVOKABLE QString rpcSnapshotInitialGet();

    /// Fetch the active revision's rules table (`rules.list`, a read
    /// op — no elevation needed). Empty
    /// payload means "all routes" (server-side default). The GUI uses
    /// this to rebind the table to what the service actually enforces
    /// after an activation, on a `revision-status-changed` push, or on
    /// the "Show rules applied by the service" toolbar action.
    Q_INVOKABLE QString rpcRulesList();

    Q_INVOKABLE QString rpcRetentionSettingsGet();
    Q_INVOKABLE QString rpcRetentionSettingsSet(const QVariantMap &payload);

    // Operational-log + audit NDJSON retention config get/set.
    Q_INVOKABLE QString rpcLogRetentionConfigGet();
    Q_INVOKABLE QString rpcLogRetentionConfigSet(const QVariantMap &payload);

    Q_INVOKABLE QString rpcApplyFailurePolicyGet();
    Q_INVOKABLE QString rpcApplyFailurePolicySet(const QString &policy);

    /// On-demand storage usage walk.
    Q_INVOKABLE QString rpcStorageUsageGet();

    /// Third-party components shipped with the product: publisher, licence,
    /// and a live integrity check (path, SHA-256, signer) of the binaries.
    /// Answered by the service, which owns the platform ports.
    Q_INVOKABLE QString rpcThirdPartyComponentsList();

    Q_INVOKABLE QString rpcRoutingPauseGet();
    Q_INVOKABLE QString rpcRoutingPauseToggle(bool paused, const QString &reason);

    Q_INVOKABLE QString rpcAutostartGet();
    Q_INVOKABLE QString rpcAutostartToggle(bool enabled);

    /// Report whether the administrative console is already reachable by name
    /// from a newly started shell. Read-only — changes nothing. Answered by the
    /// launcher, which is the process running as the interactive user whose
    /// environment is being inspected.
    Q_INVOKABLE QString rpcConsolePathState();

    /// Add the console's folder to the current user's PATH. Idempotent: a
    /// second call reports the folder is already there and writes nothing.
    Q_INVOKABLE QString rpcConsolePathRegister();

    /// Take our own entry back off the current user's PATH. Idempotent, and it
    /// removes ONLY the entry we wrote — an entry someone else put on the list,
    /// or one that comes from the machine-wide list, is left alone.
    Q_INVOKABLE QString rpcConsolePathUnregister();

    /// Generic `MutationSubmit`. Lets QML invoke the
    /// two-phase mutation pipeline for any `MutationKind` (rules-update,
    /// preset-import / -export, settings-export). `dryRun = true` runs
    /// the review/preview path and returns a confirmation token plus a
    /// `ReviewSummaryResponse`; `dryRun = false` requires the
    /// confirmation token from the dry-run response and executes the
    /// mutation. The kebab-case `mutationKind` matches the wire enum
    /// (`"rules-update"`, `"route-bindings-update"`, `"preset-import"`,
    /// `"preset-export"`, `"settings-export"`).
    Q_INVOKABLE QString rpcMutationSubmit(const QString &mutationKind,
                                          const QVariantMap &payload,
                                          bool dryRun,
                                          const QString &confirmationToken);

    // Safe rollback: restore the previous (LKG) policy revision via the
    // `RollbackRequest` recovery action. `targetRevisionId` empty → roll back to
    // the last-known-good. Class = recovery-action (derived from the op slug by
    // the client), which requires a non-empty confirmation token + elevation;
    // the token travels at the envelope root via `_envelope_confirmation_token`.
    Q_INVOKABLE QString rpcRollbackRequest(const QString &targetRevisionId,
                                           const QString &confirmationToken);

    /// Typed `ProductImpactDisableTemporary` invocation. Two-phase:
    /// `dryRun=true` returns a
    /// `ProductImpactDisableDryRunResponse` (review summary + risk
    /// level + confirmation token). The caller then re-invokes with
    /// `dryRun=false` AND the token; the service consumes the token
    /// and executes `safe_disable`. Returns the correlation id so
    /// QML can register an `rpcResponse` callback.
    ///
    /// Token transport: the launcher's IPC client expects the
    /// confirmation-token at the envelope ROOT, not inside the
    /// payload. We smuggle it through the payload's
    /// `_envelope_confirmation_token` key — the client strips and
    /// promotes (see `build_request_envelope` in
    /// `core/ipc-client/src/client.rs`). This avoids a new
    /// `call_with_token` overload on the `IpcClient` trait.
    Q_INVOKABLE QString rpcProductImpactDisable(const QString &reason,
                                                bool dryRun,
                                                const QString &confirmationToken);

    /// Read-only preset export. Calls
    /// `preset.export.get` and returns the correlation id; QML routes
    /// the `rpcResponse` callback to decode `file-bytes-b64` +
    /// `content-hash`. `route` is the kebab slug (`"primary"` /
    /// `"secondary"`); `includeMetadata` toggles the
    /// `# NetRuleRouter preset — version 1` preamble on the resulting
    /// txt blob.
    Q_INVOKABLE QString rpcPresetExport(const QString &route,
                                        bool includeMetadata);

    /// Read-only full settings export. Calls
    /// `settings.export.full` and returns the correlation id. The
    /// server-owned bits (adapters + behavior mode) come from per-SID
    /// state; the two `rulesFilePath*` arguments forward the GUI's
    /// `UiPreferences::last_saved_path_<role>` so the YAML's
    /// `rules_files:` block carries the user's chosen on-disk paths.
    /// Empty strings ⇒ corresponding field omitted from the payload.
    Q_INVOKABLE QString rpcSettingsExportFull(
        const QString &rulesFilePathPrimary,
        const QString &rulesFilePathSecondary);

    /// Read a file from disk and return its content
    /// base64-wrapped. Used by the GUI's `Qt.labs.platform.FileDialog`
    /// Open path to ferry preset bytes through `rpcMutationSubmit`'s
    /// JSON payload.
    ///
    /// Returns empty string on any error (missing file, permission
    /// denied, file > `IPC_MAX_MESSAGE_BYTES`). The 1 MiB cap mirrors
    /// the IPC frame ceiling so a too-large payload fails at the
    /// dialog rather than silently truncating downstream.
    ///
    /// Errors are logged to stderr; the GUI surfaces a toast based on
    /// the empty return.
    Q_INVOKABLE QString readFileBytes(const QString &path);

    /// Synchronous file metadata probe used by the
    /// drift detector's 30 s poll. Returns `{exists, size, mtime}`
    /// where `mtime` is Unix epoch seconds (QFileInfo's lastModified
    /// granularity is filesystem-dependent — NTFS resolves to ~100ns
    /// internally; we coarsen to seconds since drift polling only
    /// fires every 30 s anyway).
    ///
    /// Synchronous on purpose — `QFileInfo` is a thin wrapper around
    /// the OS stat call (microseconds on a warm cache), so threading
    /// it through the async RPC dispatcher would add overhead with no
    /// benefit. The QML caller awaits the return value directly.
    Q_INVOKABLE QVariantMap statFile(const QString &path);

    /// Async wrapper over the launcher-local
    /// `local.canonical-rules-hash` RPC. Returns a correlation id;
    /// QML registers a callback that lands on `rpcResponse` with the
    /// `{hash, canonical-bytes}` payload (see local_handlers.rs).
    Q_INVOKABLE QString rpcCanonicalRulesHash(const QString &rulesJson);

    /// Async wrapper over the launcher-local `local.rules-overlaps` RPC.
    /// The callback lands on `rpcResponse` with `{pairs, redundant-count}`
    /// — every exact rule a wildcard rule already covers.
    Q_INVOKABLE QString rpcRulesOverlaps(const QString &rulesJson);

    /// Async wrapper over the launcher-local
    /// `local.vpn.discover` RPC. Scans the machine (running processes +
    /// installed programs) for likely VPN clients; the callback lands on
    /// `rpcResponse` with `{candidates:[{displayName, exePath, running,
    /// source}]}`. Local + non-elevated + no service needed, so onboarding
    /// works before the service is installed.
    Q_INVOKABLE QString rpcVpnDiscover();

    /// Async wrapper over the launcher-local
    /// `local.app-groups.discover` RPC. Scans the machine (running processes +
    /// installed programs + kernel-NAT service features) for known application
    /// groups (VMs/emulators + torrents/P2P). The callback lands on
    /// `rpcResponse` with `{apps:[{kind, displayName, exePath, running,
    /// source}]}`. Local + non-elevated + no service needed, so the route-
    /// assignment onboarding works before the service is installed.
    Q_INVOKABLE QString rpcAppGroupsDiscover();
    /// Async wrapper over the launcher-local `local.vm-inventory.list` RPC: the
    /// hypervisors on this machine and their virtual machines, answered as
    /// `{hypervisors:[...]}` on `rpcResponse`. Needs no service.
    Q_INVOKABLE QString rpcVmInventoryList();

    /// Async wrapper over the service `diagnostics.seed-from-browser-history`
    /// RPC. On-demand, explicit-consent import: the service reads the local
    /// browser history and resolves ONLY the hosts that match the user's
    /// rules (privacy boundary), closing the cache gap for sites visited
    /// before the service was running. The callback lands on `rpcResponse`
    /// with `{started: true|false}` — no payload on the request.
    Q_INVOKABLE QString rpcSeedFromBrowserHistory();

    /// Async wrapper over the launcher-local `local.system-theme` RPC. Answers
    /// with `{systemMode, systemModeDetected}` from the process-wide
    /// `SystemThemePort` — the same probe the cold-start context used, so a
    /// live switch and a restart cannot disagree, and high contrast (which Qt's
    /// colour-scheme hint cannot express) still outranks light/dark.
    Q_INVOKABLE QString rpcSystemTheme();

    /// Async wrapper over `local.service-info` RPC.
    /// Returns the GUI/service version + protocol pair so the
    /// compatibility banner can render "Service X.Y.Z (vN), App
    /// A.B.C (vM)". QML calls this on cold-start and on every
    /// disconnect→connect transition.
    Q_INVOKABLE QString rpcServiceInfo();

    /// Return the OS user's default locale as a
    /// lowercase ISO-639 / ISO-3166 string ("ru_ru", "en_us", "zh_cn").
    /// Used by the first-launch wizard to suggest a country preset.
    /// The country code (after the underscore) maps directly to a
    /// folder under `presets/<cc>/`.
    Q_INVOKABLE QString detectOsLocale();

    /// List the bundled country-preset pack names
    /// for `countryCode` (lowercase 2-letter ISO, e.g. "ru", "cn").
    /// Returns a JSON array of strings (pack-folder names) so the
    /// wizard can render a chooser when multiple packs are available.
    /// Empty array when no folder exists for `countryCode`.
    Q_INVOKABLE QString listCountryPresets(const QString &countryCode);

    /// Enumerate EVERY bundled preset across
    /// all country dirs under presets/. Returns a JSON array of
    /// {"country","pack","label":"<cc>_<pack>"} for packs that contain at
    /// least one rules file. Powers the rules-section "Load bundled preset"
    /// dropdown (country_pack → fill primary/secondary).
    ///
    /// `rootOverride` repoints the enumeration at a folder the
    /// user owns (Settings -> Presets). When it is non-empty and exists, that
    /// folder REPLACES the shipped tree; an empty / missing override keeps the
    /// shipped behaviour. An empty result is reported honestly so the caller
    /// can fall back and tell the user the folder holds no rule sets.
    Q_INVOKABLE QString listAllPresets(const QString &rootOverride = QString());

    /// Resolve the absolute path of a bundled preset
    /// file. `relativePath` is `<country>/<pack>/rules_<role>.txt` or
    /// `builtin-demo/rules_<role>.txt`. Returns empty string when the
    /// file is not found. Used by the wizard + Apply-demo flow to
    /// read built-in preset content via `readFileBytes`.
    ///
    /// `rootOverride` mirrors `listAllPresets`: when non-empty it
    /// is the ONLY root consulted, so a set that exists in the user's folder is
    /// never silently satisfied by a same-named shipped file.
    Q_INVOKABLE QString resolvePresetPath(const QString &relativePath,
                                          const QString &rootOverride = QString());

    /// Compute the default writable path for a per-user
    /// preset file. Returns `%LOCALAPPDATA%/NetRuleRouter/<filename>`.
    /// Creates the parent directory if missing. Empty string on error.
    Q_INVOKABLE QString defaultLocalAppDataPath(const QString &filename);

private:
    /// The shipped `presets/` directory (country packs), looked up like every
    /// payload path (`findBundledFile`); empty when there is none.
    QString findPresetsRoot() const;

    /// Enumerate the rule sets in a folder the user owns. Their
    /// layout is flatter than the shipped country tree, so two shapes are
    /// accepted:
    ///   * one subfolder per set — `<root>/<set>/rules_primary.txt` — reported
    ///     as one entry per subfolder, `pack` = folder name;
    ///   * a single set at the root — `<root>/rules_primary.txt` — reported as
    ///     one entry named after the folder itself, with an empty `pack`.
    /// The root-level shape is only considered when no subfolder qualifies, so
    /// a folder holding both keeps the richer per-subfolder listing.
    ///
    /// `country` stays empty for user sets (there is nothing to infer a region
    /// from), which is also what keeps the label free of a `cc_` prefix.
    QString listUserPresets(const QDir &root) const;

    /// Find the workspace `configs/presets/` directory
    /// (builtin demo + future configs-scoped packs). Separate from
    /// `presets/` because the country backlog lives at the repo root
    /// while the builtin demo is a config asset.
    QString findConfigsPresetsRoot() const;

public:
    /// Write a file to disk from base64-encoded bytes.
    /// Used by the GUI's `Qt.labs.platform.FileDialog` Save path to
    /// persist the `file-bytes-b64` returned by `rpcPresetExport` or
    /// `rpcSettingsExportFull`.
    ///
    /// Returns `true` on success, `false` on any error (invalid
    /// base64, permission denied, parent directory missing). The 1 MiB
    /// cap is enforced symmetrically with `readFileBytes`.
    /// Write a UTF-8 text file directly.
    /// Used by the local canonical-txt writer for preset export so the
    /// QML side doesn't have to base64-encode Cyrillic / IDN text just
    /// to immediately decode it again. Same 1 MiB cap as the bytes path.
    /// Path for a diagnostic file under the runtime directory
    /// (`diagnostics/` beside the launcher logs), creating the folder on
    /// demand.
    ///
    /// Used by the drift comparison to leave behind what it actually compared:
    /// a divergence that turns out to be equivalent has no reproduction left
    /// once the bound file is rewritten, and that is exactly the case worth
    /// studying. Empty string when the folder cannot be created.
    Q_INVOKABLE QString runtimeDiagnosticsPath(const QString &filename);

    Q_INVOKABLE bool writeTextFile(const QString &path, const QString &text);

    /// The absolute path of the rule sets shipped with the app,
    /// so the user can point their own folder at them (to copy a set and edit
    /// it) without hunting for the install directory. Empty when the tree
    /// cannot be located.
    Q_INVOKABLE QString bundledPresetsRoot();

    /// True when `path` resolves inside either bundled preset
    /// tree (`presets/<country>/<pack>/...` or
    /// `configs/presets/builtin-demo/...`). Both trees ship inside the
    /// app/repo and are read-only sources; the GUI must never bind a "save to
    /// file" target there — doing so would silently write a user's rule
    /// edits back into the shipped `presets/` git tree. Comparison
    /// is on the canonicalized absolute path, case-insensitive (Windows
    /// filesystem), so `presets/../presets/x` and mixed-case drive letters
    /// still match.
    Q_INVOKABLE bool isPathUnderBundledPresets(const QString &path);

    /// Create `<root>/<setName>/` for "save the current rules as
    /// a new set" and return its absolute path (empty on failure).
    ///
    /// `setName` is a plain folder name, never a path: anything carrying a
    /// separator, a drive letter or `..` is refused rather than sanitised, so
    /// a name typed into the GUI can never write outside the folder the user
    /// chose. An existing set is reused (the caller confirms the overwrite).
    Q_INVOKABLE QString createPresetSetDir(const QString &rootDir,
                                           const QString &setName);

    Q_INVOKABLE bool writeFileBytes(const QString &path,
                                    const QString &base64);

    /// `StatusUpdatesSubscribe`. After a successful
    /// subscribe the launcher streams server-pushed events on stdin
    /// as `NRR_IPC_PUSH:<json>` lines; the `RpcStdinReader` thread
    /// parses them and emits `pushEvent(...)` on this bridge.
    /// `clientId` is a stable opaque token the GUI mints once per
    /// session (e.g. process id or a uuid-equivalent counter).
    Q_INVOKABLE QString rpcStatusUpdatesSubscribe(const QString &clientId);

    // ── Diagnostics + explain + service-stability ─────────────────────────
    //
    // The wire shapes live in `nrr_shared::ipc_payloads`. The launcher
    // dispatcher applies a per-op timeout budget (Explain=2s, Archive=10s,
    // ServiceStability=1s) automatically — these bridge methods only need to
    // mint the request envelope.

    /// `ExplainGet` by historical decision id. The service
    /// looks up the persisted `DecisionExplain` (when the snapshot
    /// store lands — until then it always returns `Unavailable`). The
    /// optional `detailLevel` slug is one of `"compact-ui"`,
    /// `"diagnostics"`, `"developer-trace"`; pass an empty string to
    /// accept the server default (`"compact-ui"`).
    Q_INVOKABLE QString rpcExplainGetByDecisionId(const QString &decisionId,
                                                   const QString &detailLevel);

    /// `ExplainGet` for a synthetic probe — runs the
    /// decision engine against the active rule set without recording an
    /// audit event. At least one of `hostname` / `observedIp` /
    /// `processName` must be non-empty; the server rejects all-empty
    /// samples with `PreconditionFailed`.
    Q_INVOKABLE QString rpcExplainGetBySample(const QString &hostname,
                                               const QString &observedIp,
                                               const QString &processName,
                                               const QString &detailLevel);

    /// `SnapshotInterfacesGet`. Lightweight read
    /// that returns `SnapshotInterfacesResponse` (`adapters`,
    /// `data_source`, optional `secondary: SecondaryRouteStateDto`).
    /// The GUI uses the `secondary.fail_closed_active` flag to drive
    /// the Fail-Closed banner in `InterfacesRoutesSection.qml`. The
    /// adapters array itself is still sourced from the cold-start
    /// snapshot bundle in production today; we don't replace it on
    /// every refresh to avoid stomping on the section's local sort /
    /// filter state.
    Q_INVOKABLE QString rpcSnapshotInterfacesGet();

    /// Re-enumerate adapters AND probe each one's external address. Same
    /// response shape as `rpcSnapshotInterfacesGet`, but this one leaves the
    /// machine: the probe sends a packet per eligible adapter. It is therefore
    /// a deliberate, user-initiated action and must never be wired to an
    /// automatic refresh path.
    Q_INVOKABLE QString rpcInterfacesRefresh();

    /// `LogsList`. Paginated query for operational
    /// log entries. `filter` is a kebab-shaped subset of `LogEntryFilter`
    /// (the nested DTO itself is snake-case on the wire — `from_ms`,
    /// `level_min`, `decision_id`, `revision_id`); QML constructs the
    /// map verbatim using snake_case keys. `cursor` is the opaque
    /// `next-cursor` echoed back by the previous page (empty for first
    /// page). `pageSize <= 0` falls back to `PaginationParams::default()`
    /// server-side (50 entries).
    /// `LogsClear`. Removes rotated
    /// operational NDJSON files. Audit trail is never touched.
    /// `dryRun=true` returns counts without acting.
    Q_INVOKABLE QString rpcLogsClear(bool dryRun, bool includeArchives);

    // Enable/disable extended diagnostics for a bounded session. When
    // enabled, `untilRestart` overrides `durationMs`; `durationMs <= 0` uses the
    // service default (1h). Response is the resulting diagnostic-mode state.
    Q_INVOKABLE QString rpcDiagnosticModeSet(bool enabled, double durationMs,
                                             bool untilRestart, const QString &scope);

    // Clear the rebuildable FQDN/IP resolution cache. `payload` is a full
    // CacheClearRequest ({dry-run?, clear-app-cache? (default true),
    // flush-os-cache? (default false)}) so the GUI can independently clear
    // the app cache and/or flush the OS DNS cache. Same pass-through style
    // as rpcRoutePolicyUpdate.
    Q_INVOKABLE QString rpcCacheClear(const QVariantMap &payload);

    // Read-only paginated view of the FQDN/IP resolution cache.
    // Mirrors rpcLogsList's paging shape: `cursor` is the opaque offset
    // cursor echoed back as `page.next_cursor` from the previous page
    // (empty for the first page); `pageSize <= 0` falls back to the
    // server-side PaginationParams default (50 entries). The response
    // carries `page.items` (CacheEntryDto) + `redacted` (compact tier).
    // `query` is an optional server-side search term: the service
    // filters the cache by a host/IP substring (WHERE LIKE) so a large cache is
    // searched in SQLite instead of drained page-by-page into the GUI. Empty =
    // no filter (full listing). Kept as a trailing arg so existing 2-arg callers
    // still compile; QML passes it positionally.
    Q_INVOKABLE QString rpcCacheEntriesList(const QString &cursor, int pageSize,
                                            const QString &query = QString());

    // Read-only paginated view of recently-observed outbound connections.
    // Identical paging shape to rpcCacheEntriesList: `cursor` is the opaque
    // offset echoed back as `page.next_cursor`; `pageSize <= 0` uses the
    // server-side default. The response carries `page.items` (ConnTraceEntryDto:
    // process/proto/local/remote/egress-role/egress-ifindex/verdict), `redacted`
    // and `observer-active` (false when the service is not watching at all).
    Q_INVOKABLE QString rpcConnTraceEntriesList(const QString &cursor, int pageSize);

    // File↔service merge preview (SERVICE Query op). The service
    // reconciles the supplied bound-file text against the caller's active
    // revision (per-SID read-through) and returns the three buckets + conflicts
    // + merged rules-json. Called twice: first with an empty `resolutions`
    // array (buckets under Union), then again with the per-conflict picks
    // ({ "identity-key": ..., "side": "file"|"service" }) to get the final
    // merged rules-json for `startRulesReviewFlow`.
    Q_INVOKABLE QString rpcRulesMergePreview(const QString &primaryText,
                                             const QString &secondaryText,
                                             const QString &policySlug,
                                             const QVariantList &resolutions,
                                             const QVariantList &keepSecondary = {}) {
        QJsonObject obj;
        obj.insert(QStringLiteral("primary-text"), primaryText);
        obj.insert(QStringLiteral("secondary-text"), secondaryText);
        obj.insert(QStringLiteral("policy"),
                   policySlug.isEmpty() ? QStringLiteral("union") : policySlug);
        obj.insert(QStringLiteral("resolutions"),
                   QJsonArray::fromVariantList(resolutions));
        // Identity keys whose additional-route copy the user chose to keep —
        // the other half of the same dialog's answers.
        obj.insert(QStringLiteral("keep-secondary"),
                   QJsonArray::fromVariantList(keepSecondary));
        return emitRpcRequest(QStringLiteral("rules.merge-preview"), obj);
    }

    Q_INVOKABLE QString rpcLogsList(const QVariantMap &filter,
                                     const QString &cursor,
                                     int pageSize);

    /// `AuditList`. Same shape as `rpcLogsList`
    /// but with `AuditEntryFilter` semantics: `kind`, `alert_state`,
    /// `revision_id`, `from_ms`, `to_ms`. Service-side filtering is
    /// strict — unknown filter keys are ignored.
    Q_INVOKABLE QString rpcAuditList(const QVariantMap &filter,
                                      const QString &cursor,
                                      int pageSize);

    /// `DiagnosticsExportArchive`. The service writes a
    /// zip into the per-user `archives/` directory inheriting the
    /// `Users:RX` ACL. The response carries the
    /// absolute path, byte size, and an epoch-ms generation timestamp.
    /// All inclusion flags default to `true` on the server when the
    /// request is empty; here we pass them explicitly so QML state is
    /// the source of truth.
    Q_INVOKABLE QString rpcDiagnosticsExportArchive(
        bool includeLogs,
        bool includeAuditSummary,
        bool includeTroubleshootingPlaybooks,
        const QString &redactionLevel = QString(),
        double logsFromMs = 0);

    /// `ServiceStabilityConfigGet`. Empty request, the
    /// response carries the currently-persisted `ServiceStabilityConfig`
    /// (or the canonical default if no row has been written yet).
    Q_INVOKABLE QString rpcServiceStabilityConfigGet();

    /// `ServiceStabilityConfigSet`. The recoverable
    /// variant requires all three numeric parameters; the critical
    /// variant takes none. The map shape mirrors the wire JSON:
    ///
    ///   { "ipc-accept-policy": {
    ///         "kind": "recoverable",
    ///         "max-restarts": 20,
    ///         "backoff-base-ms": 100,
    ///         "backoff-cap-ms": 5000 } }
    ///
    /// or
    ///
    ///   { "ipc-accept-policy": { "kind": "critical" } }
    ///
    /// The bridge passes the map through verbatim — QML is responsible
    /// for constructing the kebab-case keys and the cross-field
    /// constraint (recoverable ⇒ all three parameters; critical ⇒
    /// none). The service revalidates on the storage boundary and
    /// returns `PreconditionFailed` on mismatch.
    /// `origin` is an optional writer-attribution
    /// tag (e.g. "user:enforcement-mode") the service logs verbatim; moc
    /// generates an overload so existing one-argument QML callers keep
    /// working.
    Q_INVOKABLE QString rpcServiceStabilityConfigSet(const QVariantMap &config,
                                                     const QString &origin = QString());

    // ── Sidecar SQLite (GUI-only metadata) ──────────────────────────
    //
    // These operations are routed locally by the launcher; they never
    // reach the Windows service. Comments, foreign-OS passthrough
    // sections, and the "Work without service" pending-apply snapshot
    // all live in a per-user file at `%APPDATA%\NetRuleRouter\
    // gui_metadata.db` and are owned by the launcher process. See
    // `nrr-storage-sidecar` crate docs for the threat model and
    // privacy rationale.
    //
    // All return the correlation id immediately; the actual SQL runs
    // on a worker thread inside the launcher. QML callers route the
    // eventual `rpcResponse(...)` signal through `registerRpcCallback`.

    Q_INVOKABLE QString rpcSidecarCommentRead(const QString &type_,
                                              const QString &value,
                                              const QString &route);

    /// Bulk read every stored comment in one RPC.
    /// Returned payload shape: `{ comments: { "<signature>": "<text>", ... } }`.
    /// QML builds the signature client-side via `_sidecarRuleSignature`
    /// and looks rows up; missing keys mean the rule has no comment.
    Q_INVOKABLE QString rpcSidecarCommentReadAll();

    Q_INVOKABLE QString rpcSidecarCommentWrite(const QString &type_,
                                               const QString &value,
                                               const QString &route,
                                               const QString &comment);

    /// Pass an array of `{type, value, route}` objects.
    /// Any stored comment whose signature isn't in the array is dropped.
    Q_INVOKABLE QString rpcSidecarCommentGc(const QVariantList &activeSignatures);

    Q_INVOKABLE QString rpcSidecarPassthroughRead(const QString &route);

    /// `sections` is a `{sectionName: rawText}` map.
    Q_INVOKABLE QString rpcSidecarPassthroughWrite(const QString &route,
                                                   const QVariantMap &sections);

    Q_INVOKABLE QString rpcSidecarPendingApplyRead();

    Q_INVOKABLE QString rpcSidecarPendingApplyWrite(const QString &summaryJson,
                                                    const QString &contentHash);

    Q_INVOKABLE QString rpcSidecarPendingApplyClear();

    /// Bulk read every cached last-known external IP in one RPC.
    /// Returned payload shape: `{ entries: { "<adapter-key>":
    /// {"external-ip": "...", "observed-at-ms": ...}, ... } }`.
    Q_INVOKABLE QString rpcSidecarExternalIpReadAll();

    /// `entries` is an array of `{key, external-ip, observed-at-ms}`
    /// objects — one per adapter whose external address the service
    /// just resolved.
    Q_INVOKABLE QString rpcSidecarExternalIpWriteAll(const QVariantList &entries);

    /// `force = true` skips the size/interval throttle and vacuums
    /// immediately (used by Settings → "Reset application data").
    Q_INVOKABLE QString rpcSidecarVacuum(bool force);

    /// Full reset: wipe every GUI-local
    /// sidecar row (rule comments, foreign-OS passthrough, parked
    /// pending-apply). Async launcher-local op; QML registers a callback
    /// on the returned correlation id.
    Q_INVOKABLE QString rpcSidecarReset();

    // ── Canonical-txt parser RPC ────────────────────────────────────
    //
    // Routed through the launcher's local handler (no service hop);
    // the parser itself lives in `nrr_shared::preset_parser`. QML
    // receives the structured `PresetParseResult` JSON inside the
    // response `payload.result` field and translates it back to
    // rulesModel rows, including the Punycode -> Unicode boundary
    // conversion.
    /// Parse a canonical txt body. `text` must be UTF-8 decoded
    /// already — typically obtained via `decodeBase64Utf8` against
    /// `readFileBytes`. Returns the correlation id; QML registers a
    /// callback through `registerRpcCallback`.
    Q_INVOKABLE QString rpcPresetParse(const QString &text);

signals:
    /// Emitted on the GUI thread when a `NRR_IPC_PUSH:` line arrives.
    /// `event` is the `StatusUpdateEvent` JSON object (kebab-case;
    /// `type` discriminator + variant-specific fields). QML
    /// dispatches by `event.type`.
    void pushEvent(QString subscriptionId, qint64 eventId, QVariant event);

public:

    /// Invoked by `RpcStdinReader` (different thread)
    /// when a `NRR_IPC_RESPONSE:` line arrives. Marshals to the GUI
    /// thread via `QMetaObject::invokeMethod(... Qt::QueuedConnection)`.
    Q_INVOKABLE void deliverRpcResponse(const QString &line);

    /// Programmatic check used by Tray.qml stub. Returns
    /// `true` once at least one RPC round-trip has succeeded; lets the
    /// tray stop showing a "service unreachable" banner.
    Q_INVOKABLE bool hasRpcChannel() const { return rpcResponseCount_.load() > 0; }

    /// Invoked by `RpcStdinReader` when a `NRR_IPC_PUSH:`
    /// line arrives. Marshals to GUI thread via QueuedConnection;
    /// parses the envelope and emits `pushEvent(...)`.
    Q_INVOKABLE void deliverPushEvent(const QString &line);

private:
    QString emitRpcRequest(const QString &operation, const QJsonObject &payload);

    static QString stripPrefix(const QString &s, const QString &prefix);

public:
    /// Called by `RpcStdinReader` after each successfully-delivered
    /// response. The counter is observed by `hasRpcChannel()`.
    void incrementRpcResponseCount() { rpcResponseCount_.fetch_add(1); }

    // QML-side child Windows (About, License, dialogs, first-run wizard)
    // have their own native title bars and need the same DWM toggle as the
    // main window. Accepts any QObject so QML can pass `Window { id: ... }`.
    Q_INVOKABLE void setWindowDarkTitleBar(QObject *qmlWindow, bool dark);

private:
    static void applyDarkTitleBarToWindow(QWindow *window, bool dark);

    void launchMainGui(const QString &section, bool about, bool license);

    // Extended launcher hand-off. `action` carries an intent slug consumed by
    // the primary GUI's `applyGuiActivationRequest` (`"safe-disable"`,
    // `"rules-drift-apply"`); `reason`
    // is an operator-provided justification accompanying the action.
    // Both arguments are optional — when empty they're omitted from
    // the CLI and the launcher falls back to a plain section-switch.
    void launchMainGuiWithAction(const QString &section, bool about, bool license,
                                 const QString &action, const QString &reason);

    void openLogsFolder();

    // ── Tray liveness watch ──────────────────────────────────────────────
    //
    // Pure process plumbing: the tray is started detached, so it is not a
    // child of this process and the OS never notifies us when it goes away.
    // A low-frequency poll of the PID `startDetached` handed back is the
    // cheapest way to notice. The decision of what to DO about it stays in
    // QML (it owns the wind-down routine) — this only reports the fact.
    //
    // Arming rule: a duplicate `NetRuleRouterTray.exe` launch is a no-op in
    // the launcher (the single-instance lock is held by the tray already
    // running) and exits within milliseconds. Such a PID must never be
    // mistaken for a dying tray, so the watch only arms after the PID has
    // been seen ALIVE at least once.
    //
    // Observation window: a single inconclusive or negative probe is NOT a
    // verdict. The watch keeps polling for `kTrayStartupObservationWindowMs`
    // and only goes idle if that whole window passed without one positive
    // observation — the alternative (deciding on the first poll) turns any
    // transient probe failure into a permanently disarmed watch.
    void watchTrayProcess(qint64 pid);

    void pollTrayLiveness();

    /// Outcome of one liveness probe. `Unknown` exists so that an OS that
    /// refuses to answer can never be mistaken for a dead process.
    enum class ProcessLiveness { Alive, Gone, Unknown };

    static ProcessLiveness probeProcessLiveness(qint64 pid,
                                                quint32 *osErrorOut = nullptr);

    QString applicationDir_;
    QString mainGuiExecutable_;
    QString mainGuiBackendExecutable_;
    QString trayGuiExecutable_;
    QString guiActivationRequestPath_;
    QString logsDirectory_;
    QWindow *mainWindow_ = nullptr;
    /// Monotonic correlation-id counter for RPC requests.
    std::atomic<quint64> rpcCorrelationCounter_{0};
    /// Count of successfully-delivered RPC responses.
    /// Observed by `hasRpcChannel()` to drive a "channel ready" hint.
    std::atomic<quint64> rpcResponseCount_{0};
    /// Single-entry cache for `prepareTrayGrayscaleIcon`.
    /// Key is the source URL the QML last asked about; value is the
    /// path to the cached PNG. Re-rendering on every push event would
    /// thrash the disk for no reason.
    QString grayscaleIconCacheSource_;
    QString grayscaleIconCachePath_;
    /// Single-entry cache for `prepareTrayStatusIcon`.
    /// Key is `sourceUrl + ":" + statusKind` so a status flip
    /// re-renders, but consecutive identical calls hit cache.
    QString statusIconCacheKey_;
    QString statusIconCachePath_;
    /// Tray liveness watch state (see `watchTrayProcess`). `trayProcessId_`
    /// is the PID `QProcess::startDetached` returned for the tray launcher we
    /// spawned; 0 means "nothing to watch" (tray started by someone else, or
    /// the watch already settled).
    qint64 trayProcessId_ = 0;
    bool trayProcessConfirmedAlive_ = false;
    bool trayDeathReported_ = false;
    bool trayLivenessTimerConnected_ = false;
    /// Latched once an intentional exit has passed through this bridge
    /// (tray "Exit" consumed, full reset requested, application quitting).
    /// The shutdown flags are deleted by whoever consumes them, so the file
    /// check alone races with the process actually going away.
    bool trayShutdownExpected_ = false;
    /// Diagnostics for the startup observation window — reported verbatim in
    /// `NRR_HOST_TRAY_WATCH_IDLE` so a run can be triaged from the log alone.
    int trayLivenessPollCount_ = 0;
    int trayLivenessGoneObservations_ = 0;
    quint32 trayLivenessLastOsError_ = 0;
    bool trayLivenessInconclusiveLogged_ = false;
    QElapsedTimer trayWatchElapsed_;
    QTimer trayLivenessTimer_;
    static constexpr int kTrayLivenessPollIntervalMs = 2000;
    /// How long the tray gets to show up as a live process before the watch
    /// gives up. Measured cold starts (debug build) are ~3 s from spawn to the
    /// tray's QML being loaded and ~7 s for the main GUI's own chain; this is
    /// several times that, so a loaded machine still fits, while a genuine
    /// duplicate-launch no-op only delays a log line nobody waits for.
    static constexpr int kTrayStartupObservationWindowMs = 30000;
};
