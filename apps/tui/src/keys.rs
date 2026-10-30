//! Every locale key the terminal interface shows. Shared concepts reuse the
//! GUI's keys, so one wording serves both surfaces; only what exists in the
//! terminal alone lives under `tui.*`.

use crate::i18n::{key, Key, Plural};

// ── Screens ──────────────────────────────────────────────────────────────────

pub const SCREEN_STATUS: Key = key("tui.screen.status", "Status");
pub const SCREEN_WIZARD: Key = key("dialog.first-run.title", "First run");
pub const SCREEN_INTERFACES: Key = key("section.interfaces-routes", "Connections");
pub const SCREEN_RULES: Key = key("section.rules", "Rules");
pub const SCREEN_APP_GROUPS: Key = key("app-groups.title", "Connections for programs and devices");
pub const SCREEN_OVERLAPS: Key = key("rules.overlaps.nav-label", "Overlaps");
pub const SCREEN_SUGGESTIONS: Key = key("rules.suggestions.inbox.nav-label", "Suggested addresses");
pub const SCREEN_TRACE: Key = key("diag.conn-trace.title", "Connection trace");
pub const SCREEN_OUTAGE_BLOCKS: Key = key(
    "diag.outage-blocks.title",
    "Blocked while the additional connection was down",
);
pub const SCREEN_CACHE: Key = key("diag.cache.title", "Cache");
pub const SCREEN_DIAGNOSTICS: Key = key("tui.screen.diagnostics-logs", "Diagnostics and logs");
pub const SCREEN_SETTINGS: Key = key("section.settings", "Settings");

pub const MENU_TITLE: Key = key("tui.menu.title", "Screens");

// ── Start-up ─────────────────────────────────────────────────────────────────

pub const NOT_INTERACTIVE: Key = key(
    "tui.startup.not-interactive",
    "{tui} works only interactively, in a terminal. For reading and diagnostics, use {console}.",
);
pub const USAGE: Key = key(
    "tui.startup.usage",
    "Usage: {tui} [options]\n  --lang <language>\n      interface language, for example en or ru\n  --plain\n      line mode for screen readers: no redrawing, every change on a new line\n  --no-color\n      no colours (the NO_COLOR variable does the same)\n  --ascii\n      plain characters instead of frame lines\n  --wizard\n      open the first-run setup\n  --bell\n      sound the terminal bell on a new notification",
);
pub const UNKNOWN_OPTION: Key = key(
    "tui.startup.unknown-option",
    "Unknown option: {option}. Run {tui} --help for the list.",
);
pub const MISSING_VALUE: Key = key(
    "tui.startup.missing-value",
    "The option {option} needs a value.",
);
pub const TERMINAL_FAILED: Key = key(
    "tui.startup.terminal-failed",
    "Could not prepare the terminal: {error}",
);
pub const PASSWORD_PROMPT: Key = key(
    "tui.elevation.password-prompt",
    "This change needs an administrator's password. Type it below; the screen comes back once it is answered.",
);

// ── Connection to the service ────────────────────────────────────────────────

pub const SERVICE_LABEL: Key = key("label.service", "Service");
pub const LINK_CONNECTED: Key = key("connection.service-status.connected", "OK");
pub const LINK_CONNECTING: Key = key("connection.service-status.connecting", "connecting…");
pub const LINK_OFFLINE: Key = key("connection.service-status.disconnected", "offline");
pub const LINK_STOPPED: Key = key("connection.service-status.service-stopped", "stopped");
pub const LINK_NOT_INSTALLED: Key = key(
    "connection.service-status.service-not-installed",
    "not installed",
);
pub const LINK_MISMATCH: Key = key(
    "connection.service-status.protocol-mismatch",
    "incompatible",
);
pub const LINK_REFUSED: Key = key("connection.service-status.refused", "refused");

pub const BANNER_CONNECTING: Key = key("connection.banner.connecting", "Connecting to service…");
pub const BANNER_OFFLINE: Key = key(
    "connection.banner.disconnected",
    "Service offline — showing locally-cached data",
);
pub const BANNER_STOPPED: Key = key(
    "connection.banner.service-stopped",
    "NetRuleRouter service is stopped",
);
pub const BANNER_NOT_INSTALLED: Key = key(
    "connection.banner.service-not-installed",
    "NetRuleRouter service is not installed",
);
pub const BANNER_MISMATCH: Key = key(
    "connection.banner.protocol-mismatch",
    "Service version mismatch — please update NetRuleRouter",
);
pub const BANNER_REFUSED: Key = key(
    "connection.banner.refused",
    "The background service refused this connection",
);
pub const SSH_ONLY_SESSION: Key = key(
    "tui.connection.ssh-only-session",
    "Signed in over SSH: your rules are saved but apply only while you are also signed in to Windows.",
);
pub const CONTRACT_SERVICE_OLDER: Key = key(
    "status.contract-skew.service-older",
    "The background service is older than this window. Changes are off until both match: update or restart the service.",
);
pub const CONTRACT_CLIENT_OLDER: Key = key(
    "status.contract-skew.client-older",
    "This window is from a different build than the background service. Changes are off until both match: restart the window or update the app.",
);
pub const FIX_INSTALL: Key = key(
    "tui.connection.fix-install",
    "To install it, run: {command}",
);
pub const FIX_START: Key = key("tui.connection.fix-start", "To start it, run: {command}");
pub const FIX_RESTORE_NETWORK: Key = key(
    "tui.connection.fix-restore-network",
    "To restore the network, run: {command} (leak protection stays off until the service applies its rules again)",
);
pub const FIX_STOP_AND_RESTORE_NETWORK: Key = key(
    "tui.connection.fix-stop-and-restore-network",
    "To stop the service and restore the network, run: {command} (leak protection stays off until the service is started again)",
);
pub const VERSIONS: Key = key(
    "tui.connection.versions",
    "The service speaks protocol version {server}, this program version {client}. Update NetRuleRouter so both match.",
);
pub const REFUSED_REASON: Key = key(
    "tui.connection.refused-reason",
    "The service said: {reason}",
);
pub const RETRYING: Key = key("tui.connection.retrying", "Checking again every 2 seconds.");
pub const STALE: Key = key(
    "diag.status.stale-data-warning",
    "Status data may be outdated",
);
pub const NO_DATA: Key = key("diag.status.no-data", "No data from the service yet");
pub const FETCH_FAILED: Key = key(
    "tui.status.fetch-failed",
    "Could not read the state from the service: {error}",
);

// ── Routing state ────────────────────────────────────────────────────────────

pub const ROUTING_TITLE: Key = key("routing.status.card-title", "Rules status");
pub const ROUTING_ACTIVE: Key = key("routing.status.active", "Rules are working");
pub const ROUTING_LIMITED: Key = key("routing.status.limited", "Some rules not working");
pub const ROUTING_PAUSED: Key = key("routing.status.paused", "Rules are off");
pub const ROUTING_DISCONNECTED: Key = key("routing.status.disconnected", "Service not connected");
pub const DETAIL_ACTIVE: Key = key("routing.status.detail-active", "Your rules are working.");
pub const DETAIL_LIMITED: Key = key(
    "routing.status.detail-limited",
    "Some rules are not being applied right now. The notices say why.",
);
pub const DETAIL_PAUSED: Key = key(
    "routing.status.detail-paused",
    "Rules are off for the time chosen; they come back on their own when it is up, or when you turn them back on.",
);

// ── Connections (roles) ──────────────────────────────────────────────────────

pub const ROLES_TITLE: Key = key("tui.status.connections-title", "Connections");
pub const ROLE_PRIMARY: Key = key("interfaces.role.primary", "Main connection");
pub const ROLE_SECONDARY: Key = key(
    "interfaces.role.secondary",
    "Additional connection (e.g. VPN)",
);
pub const NOT_SELECTED: Key = key("interfaces.state.not-selected", "Not selected");
pub const AVAILABLE: Key = key("interfaces.availability.available", "Available");
pub const UNAVAILABLE: Key = key("interfaces.availability.unavailable", "Unavailable");
pub const REQUIRES_CHECK: Key = key("interfaces.availability.requires-check", "Requires check");
pub const ADAPTER_MISSING: Key = key("tui.status.adapter-missing", "Not found");
pub const RULES_APPLIED: Key = key("tui.status.rules-applied", "Rules applied");
pub const RULES_NOT_APPLIED: Key = key("tui.status.rules-not-applied", "Rules not applied");
pub const RULES_UNKNOWN: Key = key("tui.status.rules-unknown", "Not known without the service");

// ── Enforcement reports (the GUI's notice texts) ─────────────────────────────

pub const ENF_CHOICE_TITLE: Key = key(
    "notifications.enforcement.adapter-choice.title",
    "Choose which adapter to use",
);
pub const ENF_CHOICE_BODY: Key = key(
    "notifications.enforcement.adapter-choice.body",
    "Several adapters answer to the saved name, so your rules are not being applied. Pick the one to use: {list}",
);
pub const ENF_CHOICE_BODY_ONE: Key = key(
    "notifications.enforcement.adapter-choice.body-one",
    "The saved adapter is not up, but another adapter of the same kind is: {list}. If your VPN now uses that one, choose it; until then your rules are not being applied.",
);
pub const ENF_GONE_TITLE: Key = key(
    "notifications.enforcement.adapter-gone.title",
    "The saved connection is gone",
);
pub const ENF_GONE_BODY: Key = key(
    "notifications.enforcement.adapter-gone.body",
    "The connection your rules were set to use is no longer on this computer, so the rules are not being applied. Pick another one: {list}",
);
pub const ENF_GONE_BODY_EMPTY: Key = key(
    "notifications.enforcement.adapter-gone.body-empty",
    "The connection your rules were set to use is no longer on this computer, and there is nothing to replace it with right now.",
);
pub const ENF_FAILED_TITLE: Key = key(
    "notifications.enforcement.adapter-failed.title",
    "The saved connection is broken",
);
pub const ENF_FAILED_BODY: Key = key(
    "notifications.enforcement.adapter-failed.body",
    "The connection your rules use is still installed, but its driver will not start, so the rules are not being applied. Reinstall it, or pick another one: {list}",
);
pub const ENF_FAILED_BODY_EMPTY: Key = key(
    "notifications.enforcement.adapter-failed.body-empty",
    "The connection your rules use is still installed, but its driver will not start, and there is nothing to replace it with right now. Reinstalling it usually helps.",
);
pub const ENF_NO_PRIMARY_TITLE: Key = key(
    "notifications.enforcement.no-primary.title",
    "Main connection is not set",
);
pub const ENF_NO_PRIMARY_BODY: Key = key(
    "notifications.enforcement.no-primary.body",
    "Without a main connection there is nowhere to send traffic your rules do not route, so the rules are not being applied.",
);
pub const ENF_NO_WAY_OUT_TITLE: Key = key(
    "notifications.enforcement.primary-no-way-out.title",
    "The main connection has no way to the internet",
);
pub const ENF_NO_WAY_OUT_BODY: Key = key(
    "notifications.enforcement.primary-no-way-out.body",
    "The connection chosen as main has no gateway, so traffic your rules do not route is going out the way the system sends it instead. Choose the connection that actually reaches the internet as main.",
);
pub const ENF_NO_POLICY_TITLE: Key = key(
    "notifications.enforcement.no-policy.title",
    "Connections are not chosen yet",
);
pub const ENF_NO_POLICY_BODY: Key = key(
    "notifications.enforcement.no-policy.body",
    "Your connections are not chosen yet, so your rules are not working. Choose the main and additional connections.",
);
pub const ENF_SUGGEST_TITLE: Key = key(
    "notifications.enforcement.no-policy.suggest-title",
    "Confirm your main connection: {name}",
);
pub const ENF_SUGGEST_BODY: Key = key(
    "notifications.enforcement.no-policy.suggest-body",
    "Your rules do not work until you confirm it. Rules for the additional connection wait until you choose one.",
);
pub const ENF_PRIMARY_DOWN_TITLE: Key = key(
    "notifications.enforcement.primary-down.title",
    "The main connection is not up",
);
pub const ENF_PRIMARY_DOWN_BODY: Key = key(
    "notifications.enforcement.primary-down.body",
    "Traffic that is not routed to the additional connection has nowhere to go until it comes back. Check the cable, the Wi-Fi, or pick another main connection.",
);
pub const ENF_SECONDARY_DOWN_TITLE: Key = key(
    "notifications.enforcement.secondary-down.title",
    "The additional connection is not up",
);
pub const ENF_SECONDARY_DOWN_BODY: Key = key(
    "notifications.enforcement.secondary-down.body",
    "Everything your rules send there is being held until it comes back — that is the protection doing its job, not a fault. Start the connection, or move those rules to the main one.",
);
pub const ENF_SECONDARY_DOWN_BODY_OFF: Key = key(
    "notifications.enforcement.secondary-down.body-off",
    "Sites your rules send there go over the main connection until it comes back: leak protection is off. Start the connection, or turn leak protection on to hold them instead.",
);
pub const ENF_SECONDARY_DOWN_BODY_EVERYTHING: Key = key(
    "notifications.enforcement.secondary-down.body-everything",
    "The internet waits until it comes back, except your local network and what your rules send over the main connection — that is the protection doing its job, not a fault. Start the connection.",
);
pub const ENF_UNREADABLE_TITLE: Key = key(
    "notifications.enforcement.adapters-unreadable.title",
    "Cannot read the list of connections",
);
pub const ENF_UNREADABLE_BODY: Key = key(
    "notifications.enforcement.adapters-unreadable.body",
    "The service cannot enumerate network adapters right now, so your rules are not being applied. This usually clears itself; if it does not, restart the service.",
);
pub const ENF_UNKNOWN_TITLE: Key = key(
    "notifications.enforcement.unknown.title",
    "Your rules are not being applied",
);
pub const ENF_UNKNOWN_BODY: Key = key(
    "notifications.enforcement.unknown.body",
    "The service reported a state this version does not recognise. Open Connections to check the setup.",
);
pub const LINK_DROPPING_TITLE_PRIMARY: Key = key(
    "notifications.link-keeps-dropping.title-primary",
    "The main connection keeps dropping",
);
pub const LINK_DROPPING_TITLE_SECONDARY: Key = key(
    "notifications.link-keeps-dropping.title-secondary",
    "The additional connection keeps dropping",
);
pub const LINK_DROPPING_BODY: Key = key(
    "notifications.link-keeps-dropping.body",
    "It went down and came back several times in the last two minutes. Your rules stayed in force, but pages may have failed to load in between. Check the cable, the Wi-Fi or the VPN.",
);
pub const ENF_RESTORED_TITLE: Key = key(
    "notifications.enforcement.restored.title",
    "Rules are working again",
);
pub const ENF_RESTORED_BODY: Key = key(
    "notifications.enforcement.restored.body",
    "Your rules work again. Reload the pages that did not open while the connection was down — press F5 on those tabs.",
);
pub const ENF_RESTORED_WHERE: Key = key(
    "tui.outage-blocks.where",
    "The list of what was blocked: {screen}",
);

pub const APP_UNRESOLVED_TITLE: Key = key(
    "notifications.app-unresolved.title",
    "App rules applied, but some apps weren't found",
);
pub const APP_UNRESOLVED_BODY: Key = key(
    "notifications.app-unresolved.body",
    "NetRuleRouter could not find these programs: {apps}. They may be installed outside the usual folder or not running, so the rules do not reach them yet. Start the program, or check its name in Rules.",
);
pub const APP_UNRESOLVED_MORE: Key = key("status.app-unresolved-more", "+{n} more");
pub const APP_UNROUTED_TITLE: Key = key(
    "notifications.app-unresolved.title-unrouted",
    "App rules applied, but some don't route their program",
);
pub const APP_UNROUTED_NAMED: Key = key(
    "notifications.app-unresolved.unrouted.addresses-named-by-rules",
    "The program {app} is on this computer, but its rule routes none of its traffic: the addresses it connects to are already covered by your rules for sites and addresses, and the more specific rule wins.",
);
pub const APP_UNROUTED_SHARED: Key = key(
    "notifications.app-unresolved.unrouted.addresses-shared",
    "The program {app} is on this computer, but its rule routes none of its traffic: other programs or sites use the same addresses, and moving them would move those too.",
);
pub const APP_UNROUTED_OTHER: Key = key(
    "notifications.app-unresolved.unrouted.other",
    "The program {app} is on this computer, but its rule routes none of its traffic.",
);
pub const VPN_TRUST_TITLE: Key = key("notifications.vpn-client-trust.title", "Is this your VPN?");
pub const VPN_TRUST_BODY: Key = key(
    "notifications.vpn-client-trust.tui-body",
    "{apps}: named like a VPN client, but not installed in a protected program folder, so leak protection does not trust it on its own.",
);
pub const VPN_TRUST_HINT: Key = key(
    "notifications.vpn-client-trust.tui-hint",
    "t: confirm {name} as your VPN. The other programs are asked one at a time after it.",
);
pub const VPN_TRUST_HINT_BUNDLE: Key = key(
    "notifications.vpn-client-trust.tui-hint-bundle",
    "t: confirm {name} as your VPN. T: confirm it together with the {count} program(s) it ships with in its protected folder. The other programs are asked one at a time after it.",
);
pub const VPN_TRUST_DONE: Key = key(
    "notifications.vpn-client-trust.tui-done",
    "{count} program(s) confirmed as your VPN; leak protection keeps them working over the main connection.",
);
pub const VPN_TRUST_FAILED: Key = key(
    "notifications.vpn-client-trust.tui-failed",
    "Could not save the confirmation to the routing service ({error}).",
);

// ── Notices ──────────────────────────────────────────────────────────────────

pub const NOTICES_TITLE: Key = key("notifications.title", "Notifications");
pub const NOTICES_EMPTY: Key = key("notifications.empty", "No notifications.");
pub const LEVEL_WARNING: Key = key("settings.logs.level.option-warning", "Warning");
pub const LEVEL_INFO: Key = key("settings.logs.level.option-info", "Info");
pub const SERVICE_LOST_TITLE: Key = key("notifications.service-lost.title", "The service stopped");
pub const SERVICE_LOST_BODY: Key = key(
    "notifications.service-lost.body-start-only",
    "The NetRuleRouter service stopped unexpectedly, so your rules are not applied.",
);
pub const BANNER_LOST: Key = key(
    "connection.banner.service-lost",
    "The NetRuleRouter service stopped unexpectedly, so your rules are not applied",
);
pub const SYSTEM_DNS_TITLE: Key = key(
    "notifications.system-dns-not-restored.title",
    "Sites may not open by name",
);
pub const RULES_BOOK_TITLE: Key = key(
    "notifications.rules-book-unreadable.title",
    "Your saved rules cannot be read",
);
pub const RULES_BOOK_BODY: Key = key(
    "notifications.rules-book-unreadable.body",
    "Your saved rules cannot be read; the last applied rules stay in force. Changes will not apply until this is fixed.",
);
pub const RULES_BOOK_CLEARED: Key = key(
    "notifications.rules-book-unreadable.cleared",
    "Your saved rules can be read again; changes apply again.",
);
pub const SEE_DIAGNOSTICS_HINT: Key = key(
    "tui.see-diagnostics",
    "Details are on the Diagnostics and logs screen (9).",
);
pub const ALERT_GATE_HINT: Key = key(
    "tui.alert-gate-hint",
    "The alert is on the Diagnostics and logs screen (9): choose it and press a to acknowledge it.",
);
pub const DNS_FOREIGN_TITLE: Key = key(
    "notifications.dns-foreign-only.title",
    "Name handling is paused by your VPN",
);
pub const DNS_FOREIGN_BODY: Key = key(
    "notifications.dns-foreign-only.body",
    "Your work VPN only lets its own DNS answer, so NetRuleRouter's name handling is paused until another DNS answers. Rules by site name may not apply meanwhile. Disconnect the VPN, or ask its administrator to allow other DNS servers.",
);
pub const HOST_UNREACHABLE_TITLE: Key = key(
    "notifications.host-unreachable.title",
    "A site does not answer on either link",
);
pub const HOST_UNREACHABLE_BODY: Key = key(
    "notifications.host-unreachable.body",
    "{host} did not answer through the main connection or through the additional one, so moving it would not help and nothing was offered. The problem is most likely on the site's side.",
);
pub const EXTERNAL_ADDRESS_TITLE: Key =
    key("tray.external-address.title", "Additional connection is up");
pub const EXTERNAL_ADDRESS_BODY: Key = key(
    "tray.external-address.body",
    "External address of the additional connection: {address}",
);
pub const EXTERNAL_ADDRESS_ADAPTER: Key = key("tray.external-address.adapter", "Adapter: {name}");
pub const ROUTES_HELD_TITLE: Key = key(
    "notifications.routes-held.title",
    "Some addresses follow another user's connection",
);
pub const ROUTES_HELD_BODY: Key = key(
    "notifications.routes-held.body",
    "Another user signed in to this computer already routes some addresses from your rules through a different connection. Addresses affected: {count}. While that user stays signed in, these addresses follow their connection, or are blocked for you if leak protection is on. Among them: {list}.",
);
pub const BLOCK_NOTICE_TITLE: Key = key("notifications.block-notice.title", "Connection blocked");
pub const BLOCK_NOTICE_BODY: Key = key(
    "notifications.block-notice.body",
    "{reason} Destination: {destination}. Application: {app}. Attempts: {attempts}.",
);
pub const BLOCK_NOTICE_APP_UNKNOWN: Key = key(
    "notifications.block-notice.app-unknown",
    "unknown application",
);
pub const BLOCK_NOTICE_DESTINATION_HIDDEN: Key = key(
    "notifications.block-notice.destination-hidden",
    "a hidden destination",
);
pub const BLOCK_NOTICE_REASON_UNKNOWN: Key = key(
    "notifications.block-notice.reason.unknown",
    "This connection was blocked.",
);
/// `BLOCK_NOTICE_REASON_UNKNOWN` is the fallback; the reason slug the service
/// names selects a sibling key under this prefix.
pub const BLOCK_NOTICE_REASON_PREFIX: &str = "notifications.block-notice.reason.";
pub const LOCAL_NETWORK_TITLE: Key = key(
    "notifications.local-networks.title",
    "A local network was found",
);
pub const LOCAL_NETWORK_OFFER: Key = key(
    "status.local-network-offer",
    "Found a local network on this computer: {cidr} ({adapter}). Keep it reachable while leak protection blocks traffic?",
);
pub const LOCAL_NETWORK_OFFER_OPEN: Key = key(
    "status.local-network-offer-open",
    "Found your home network's IPv6 addresses: {cidr} ({adapter}). Open them to devices on this network while leak protection blocks traffic?",
);
pub const LOCAL_NETWORK_OFFER_MORE: Key =
    key("status.local-network-offer-more", "{count} more found.");
pub const ANSWER_IN_ROUTING_HINT: Key = key(
    "tui.answer-in-routing-settings",
    "Answer in Settings, Routing behavior section (c2).",
);
pub const FORWARDED_TITLE: Key = key(
    "notifications.forwarded-traffic.title",
    "WSL or containers are running",
);
pub const FORWARDED_BODY: Key = key(
    "notifications.forwarded-traffic.body",
    "Choose what WSL, containers and virtual machines get when the additional connection goes down. Until you choose, they are protected like this computer.",
);
pub const BLOCK_NOTICE_BACKLOG_TITLE: Key = key(
    "notifications.block-notice.backlog.title",
    "Blocked while the app was closed",
);
pub const BLOCK_NOTICE_BACKLOG_COUNTED: Plural = Plural {
    stem: "notifications.block-notice.backlog.counted.",
    one: "The service blocked {count} connection while NetRuleRouter was not open.",
    other: "The service blocked {count} connections while NetRuleRouter was not open.",
};
pub const BLOCK_NOTICE_BACKLOG_DESTINATIONS: Key = key(
    "notifications.block-notice.backlog.destinations",
    "Destinations: {list}.",
);
pub const BLOCK_NOTICE_BACKLOG_MORE: Key = key(
    "notifications.block-notice.backlog.more",
    "and {count} more",
);
pub const SETTINGS_UNREADABLE_TITLE: Key = key(
    "notifications.settings-unreadable.title",
    "Your settings could not be read",
);
pub const SETTINGS_UNREADABLE_BODY: Key = key(
    "notifications.settings-unreadable.body",
    "This session uses default settings and will not save changes, so your saved settings stay as they are. Close the app and open it again; if the file is locked by another program, free it first.",
);
pub const TUI_SETTINGS_DAMAGED_TITLE: Key = key(
    "notifications.tui-settings-damaged.title",
    "The terminal's settings file is damaged",
);
pub const TUI_SETTINGS_DAMAGED_BODY: Key = key(
    "notifications.tui-settings-damaged.body",
    "This session uses default settings and does not save changes, so {path} is left as it is: correct or delete it, and saving works again.",
);
pub const TUI_SETTINGS_UNREADABLE_TITLE: Key = key(
    "notifications.tui-settings-unreadable.title",
    "The terminal's settings file could not be read",
);
pub const TUI_SETTINGS_UNREADABLE_BODY: Key = key(
    "notifications.tui-settings-unreadable.body",
    "This session uses default settings and does not save changes, so {path} is left as it is. If another program holds the file or its permissions shut you out, free it, and saving works again.",
);
pub const DELIVERY_TITLE: Key = key(
    "notifications.delivery-incomplete.title",
    "The installation is incomplete",
);
pub const DELIVERY_BODY: Key = key(
    "notifications.delivery-incomplete.body",
    "This copy of the program lacks {parts}. Everything else keeps working. Reinstall the program to restore what is missing.",
);
pub const DELIVERY_PRESETS: Key = key(
    "notifications.delivery-incomplete.part.presets",
    "the ready-made rule sets",
);
pub const DELIVERY_LOCALES: Key = key(
    "notifications.delivery-incomplete.part.locales",
    "the interface languages, so the program is shown in English",
);
pub const UNASSIGNED_TUNNEL_TITLE: Key = key(
    "notifications.unassigned-tunnel.title",
    "The additional connection is not chosen",
);
pub const UNASSIGNED_TUNNEL_BODY: Key = key(
    "notifications.unassigned-tunnel.body",
    "{adapter} is up, but no additional connection is chosen — so the sites your rules send there will not open.",
);
pub const ADDITIONAL_MOVED_TITLE: Key = key(
    "notifications.additional-moved.title",
    "The additional connection moved",
);
pub const ADDITIONAL_MOVED_BODY: Key = key(
    "notifications.additional-moved.body",
    "Your VPN came up on {adapter}, so the additional connection now uses it and your rules go through it. The choice is saved.",
);
pub const LOCAL_NETWORK_TOO_WIDE_TITLE: Key = key(
    "notifications.local-network-too-wide.title",
    "This network looks suspicious",
);
pub const LOCAL_NETWORK_TOO_WIDE_BODY: Key = key(
    "notifications.local-network-too-wide.body",
    "{adapter} reports {network} as its local network — far wider than any local network can be. It is not treated as local: devices on it stay blocked while leak protection is on, and sites inside it still follow your rules.",
);
pub const RULE_DUPLICATES_TITLE: Key = key(
    "notifications.rule-duplicates.title",
    "A rule is set on both connections",
);
pub const RULE_DUPLICATES_BODY: Key = key(
    "notifications.rule-duplicates.body",
    "{count} of your rules are enabled on both connections, starting with {sample}. Which one carries the traffic is decided by evaluation order.",
);
pub const APP_RULE_LEARNING_TITLE: Key = key(
    "notifications.app-rule-learning.title",
    "New application rule is settling in",
);
pub const APP_RULE_LEARNING_BODY: Key = key(
    "notifications.app-rule-learning.body",
    "{apps}: the service is still learning which addresses this program uses, so its first connection attempts may fail. Restart the program if it is already open.",
);
pub const PROTECTION_COVERAGE_TITLE: Key = key(
    "notifications.protection-coverage.title",
    "Leak protection coverage changed",
);
pub const PROTECTION_BLANKET_BLOCK_NOT_ARMED: Key = key(
    "status.protection.blanket-block-not-armed",
    "Leak protection \"Everything\" is not in force yet: the address of the additional connection is unknown, and blocking everything without it would cut that connection too. Traffic outside your rules is not blocked.",
);
pub const BLOCK_ALL_ARMED: Key = key(
    "settings.routing.kill-switch.block-all-active-banner",
    "Leak protection is holding all traffic: the additional connection can't be found (down, not started, or reinstalled under a new ID). The internet waits until it returns; reconnect the VPN or assign the adapter again.",
);
pub const PROTECTION_VOLUME_HIGH: Key = key(
    "status.protection-volume-high",
    "Rules on this computer, yours and other users' together, take {count} Windows network filters. That many can make the Windows filtering service unstable. Narrow wide rules (a domain with all its subdomains, a zone) or remove the ones you no longer need.",
);
pub const REVISION_INTEGRITY: Key = key(
    "status.revision-integrity-banner",
    "The rule set was changed outside the app, so it was not applied — the service is running on the last verified version.",
);
pub const REVISION_INTEGRITY_TITLE: Key = key(
    "diag.alert.kind.untrusted-revision-rejected",
    "Rule set changed outside the app",
);
pub const VPN_SPLIT_TITLE: Key = key(
    "interfaces.mode.prefer-primary",
    "Main connection — selected sites through the additional one",
);
pub const VPN_SPLIT_COUNTED: Plural = Plural {
    stem: "status.vpn-split-conflict.",
    one: "Your additional adapter \"{name}\" is up and carrying exactly what you asked it to: your {count} rule goes through it, everything else stays on your main connection. That is selective routing doing its job — nothing here needs fixing. If you would rather send everything through it, switch the mode in Settings → Routing behavior.",
    other: "Your additional adapter \"{name}\" is up and carrying exactly what you asked it to: your {count} rules go through it, everything else stays on your main connection. That is selective routing doing its job — nothing here needs fixing. If you would rather send everything through it, switch the mode in Settings → Routing behavior.",
};
pub const RULES_EMPTY: Key = key(
    "status.empty-rules-banner",
    "There are no rules — nothing is being sent anywhere special. Add rules or load a ready-made set.",
);
pub const POLICY_INACTIVE_NO_ADAPTER: Key = key(
    "status.policy-inactive-no-adapter",
    "The service is running, but your rules are not working: no additional connection is chosen yet, so there is nowhere to send them. Choose one in Connections.",
);
pub const POLICY_INACTIVE_BLOCKING: Key = key(
    "status.policy-inactive-kill-switch-blocking",
    "Leak protection is on and no additional connection is chosen, so everything your rules send there is being blocked. Choose one in Connections, or turn leak protection off.",
);
pub const PROTECTION_MACHINE_WIDE_CUT: Key = key(
    "status.protection.machine-wide-cut-by-another-user",
    "Another user of this computer switched on leak protection. Part of it cannot be limited to one account, so IPv6 and ping are off for everyone until they switch it off.",
);
pub const ROUTES_HELD_CLEARED: Key = key(
    "notifications.routes-held.cleared",
    "Addresses from your rules follow your own connection again.",
);
pub const TRAFFIC_CARRIED_TITLE: Key = key(
    "notifications.traffic-carried.title",
    "Your traffic goes through another user's connection",
);
pub const TRAFFIC_CARRIED_BODY: Key = key(
    "notifications.traffic-carried.body",
    "Another user of this computer signed in before you and sends all their traffic through \"{link}\". On this computer that applies to everyone, so whatever your rules do not send through your additional connection goes through \"{link}\" too. To avoid this, sign in before that user, or ask them to send only chosen sites there.",
);
pub const TRAFFIC_CARRIED_BODY_UNNAMED: Key = key(
    "notifications.traffic-carried.body-unnamed",
    "Another user of this computer signed in before you and sends all their traffic through their own connection (for example a VPN). On this computer that applies to everyone, so whatever your rules do not send through your additional connection goes through it too. To avoid this, sign in before that user, or ask them to send only chosen sites there.",
);
pub const TRAFFIC_CARRIED_CLEARED: Key = key(
    "notifications.traffic-carried.cleared",
    "Your traffic no longer goes through another user's connection.",
);

// ── Keys and help ────────────────────────────────────────────────────────────

pub const HELP_TITLE: Key = key("label.help", "Help");
pub const HELP_SCREENS: Key = key("tui.help.screens", "1 to 9 and 0: open a screen");
pub const HELP_MOVE: Key = key("tui.help.move", "Up and Down: move through the list");
pub const HELP_PANELS: Key = key("tui.help.panels", "Tab and Shift+Tab: move between panels");
pub const HELP_OPEN: Key = key("tui.help.open", "Enter: open the screen chosen in the list");
pub const HELP_HELP: Key = key("tui.help.help", "F1 or ?: help for this screen");
pub const HELP_BACK: Key = key("tui.help.back", "Esc: back, or close this help");
pub const HELP_QUIT: Key = key("tui.help.quit", "q: quit");
pub const HELP_STATUS_FEED: Key = key(
    "tui.help.status-feed",
    "On this screen, Up and Down choose a notification when that panel has the focus; the keys it answers to are listed under it.",
);
pub const FOOTER: Key = key("tui.footer", "F1: help   q: quit");
/// Tail of a panel title when the panel is taller than the room it has.
pub const CLIPPED: Key = key("tui.clipped", "+{count} more rows");

// ── Line mode ────────────────────────────────────────────────────────────────

pub const PLAIN_SCREEN: Key = key("tui.plain.screen", "Screen: {name}");
pub const PLAIN_PROMPT: Key = key(
    "tui.plain.prompt",
    "Type a screen number, h for help or q to quit, then press Enter.",
);
pub const PLAIN_HELP_NUMBER: Key = key("tui.plain.help-number", "A number: open that screen");
pub const PLAIN_HELP_ENTER: Key = key(
    "tui.plain.help-enter",
    "Enter on its own: show this screen again",
);
pub const PLAIN_HELP_HELP: Key = key("tui.plain.help-help", "h or ?: this help");
pub const PLAIN_UNKNOWN: Key = key("tui.plain.unknown", "Not understood: {input}");
pub const PLAIN_NUMBER_GONE: Key = key(
    "tui.plain.number-gone",
    "Item {n} as it was listed is no longer in the list. Here is the list as it is now.",
);
pub const PLAIN_INPUT_ENDED_UNAPPLIED: Key = key(
    "tui.plain.input-ended-unapplied",
    "Input ended while rule changes were not applied. They were dropped; nothing was sent to the service.",
);
pub const PLAIN_COMMANDS: Key = key("tui.plain.commands", "Commands on this screen");

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    SCREEN_STATUS,
    SCREEN_WIZARD,
    SCREEN_INTERFACES,
    SCREEN_RULES,
    SCREEN_APP_GROUPS,
    SCREEN_OVERLAPS,
    SCREEN_SUGGESTIONS,
    SCREEN_TRACE,
    SCREEN_OUTAGE_BLOCKS,
    SCREEN_CACHE,
    SCREEN_DIAGNOSTICS,
    SCREEN_SETTINGS,
    MENU_TITLE,
    NOT_INTERACTIVE,
    USAGE,
    UNKNOWN_OPTION,
    MISSING_VALUE,
    TERMINAL_FAILED,
    PASSWORD_PROMPT,
    SERVICE_LABEL,
    LINK_CONNECTED,
    LINK_CONNECTING,
    LINK_OFFLINE,
    LINK_STOPPED,
    LINK_NOT_INSTALLED,
    LINK_MISMATCH,
    LINK_REFUSED,
    BANNER_CONNECTING,
    BANNER_OFFLINE,
    BANNER_STOPPED,
    BANNER_NOT_INSTALLED,
    BANNER_MISMATCH,
    BANNER_REFUSED,
    CONTRACT_SERVICE_OLDER,
    CONTRACT_CLIENT_OLDER,
    SSH_ONLY_SESSION,
    FIX_INSTALL,
    FIX_START,
    FIX_RESTORE_NETWORK,
    FIX_STOP_AND_RESTORE_NETWORK,
    VERSIONS,
    REFUSED_REASON,
    RETRYING,
    STALE,
    NO_DATA,
    FETCH_FAILED,
    ROUTING_TITLE,
    ROUTING_ACTIVE,
    ROUTING_LIMITED,
    ROUTING_PAUSED,
    ROUTING_DISCONNECTED,
    DETAIL_ACTIVE,
    DETAIL_LIMITED,
    DETAIL_PAUSED,
    ROLES_TITLE,
    ROLE_PRIMARY,
    ROLE_SECONDARY,
    NOT_SELECTED,
    AVAILABLE,
    UNAVAILABLE,
    REQUIRES_CHECK,
    ADAPTER_MISSING,
    RULES_APPLIED,
    RULES_NOT_APPLIED,
    RULES_UNKNOWN,
    ENF_CHOICE_TITLE,
    ENF_CHOICE_BODY,
    ENF_CHOICE_BODY_ONE,
    ENF_GONE_TITLE,
    ENF_GONE_BODY,
    ENF_GONE_BODY_EMPTY,
    ENF_FAILED_TITLE,
    ENF_FAILED_BODY,
    ENF_FAILED_BODY_EMPTY,
    ENF_NO_PRIMARY_TITLE,
    ENF_NO_PRIMARY_BODY,
    ENF_NO_WAY_OUT_TITLE,
    ENF_NO_WAY_OUT_BODY,
    ENF_NO_POLICY_TITLE,
    ENF_NO_POLICY_BODY,
    ENF_SUGGEST_TITLE,
    ENF_SUGGEST_BODY,
    ENF_PRIMARY_DOWN_TITLE,
    ENF_PRIMARY_DOWN_BODY,
    ENF_SECONDARY_DOWN_TITLE,
    ENF_SECONDARY_DOWN_BODY,
    ENF_SECONDARY_DOWN_BODY_OFF,
    ENF_SECONDARY_DOWN_BODY_EVERYTHING,
    ENF_UNREADABLE_TITLE,
    ENF_UNREADABLE_BODY,
    ENF_UNKNOWN_TITLE,
    ENF_UNKNOWN_BODY,
    LINK_DROPPING_TITLE_PRIMARY,
    LINK_DROPPING_TITLE_SECONDARY,
    LINK_DROPPING_BODY,
    ENF_RESTORED_TITLE,
    ENF_RESTORED_BODY,
    ENF_RESTORED_WHERE,
    APP_UNRESOLVED_TITLE,
    APP_UNRESOLVED_BODY,
    APP_UNRESOLVED_MORE,
    APP_UNROUTED_TITLE,
    APP_UNROUTED_NAMED,
    APP_UNROUTED_SHARED,
    APP_UNROUTED_OTHER,
    VPN_TRUST_TITLE,
    VPN_TRUST_BODY,
    VPN_TRUST_HINT,
    VPN_TRUST_HINT_BUNDLE,
    VPN_TRUST_DONE,
    VPN_TRUST_FAILED,
    crate::vpn_trust::HELP,
    crate::primary_suggestion::HELP,
    crate::primary_suggestion::AMBIGUOUS,
    NOTICES_TITLE,
    NOTICES_EMPTY,
    LEVEL_WARNING,
    LEVEL_INFO,
    SERVICE_LOST_TITLE,
    SERVICE_LOST_BODY,
    BANNER_LOST,
    SYSTEM_DNS_TITLE,
    RULES_BOOK_TITLE,
    RULES_BOOK_BODY,
    RULES_BOOK_CLEARED,
    SEE_DIAGNOSTICS_HINT,
    DNS_FOREIGN_TITLE,
    DNS_FOREIGN_BODY,
    HOST_UNREACHABLE_TITLE,
    HOST_UNREACHABLE_BODY,
    EXTERNAL_ADDRESS_TITLE,
    EXTERNAL_ADDRESS_BODY,
    EXTERNAL_ADDRESS_ADAPTER,
    ROUTES_HELD_TITLE,
    ROUTES_HELD_BODY,
    ROUTES_HELD_CLEARED,
    TRAFFIC_CARRIED_TITLE,
    TRAFFIC_CARRIED_BODY,
    TRAFFIC_CARRIED_BODY_UNNAMED,
    TRAFFIC_CARRIED_CLEARED,
    BLOCK_NOTICE_TITLE,
    BLOCK_NOTICE_BODY,
    BLOCK_NOTICE_APP_UNKNOWN,
    BLOCK_NOTICE_DESTINATION_HIDDEN,
    BLOCK_NOTICE_REASON_UNKNOWN,
    BLOCK_NOTICE_BACKLOG_TITLE,
    LOCAL_NETWORK_TITLE,
    LOCAL_NETWORK_OFFER,
    LOCAL_NETWORK_OFFER_OPEN,
    LOCAL_NETWORK_OFFER_MORE,
    ANSWER_IN_ROUTING_HINT,
    FORWARDED_TITLE,
    FORWARDED_BODY,
    BLOCK_NOTICE_BACKLOG_DESTINATIONS,
    BLOCK_NOTICE_BACKLOG_MORE,
    SETTINGS_UNREADABLE_TITLE,
    SETTINGS_UNREADABLE_BODY,
    TUI_SETTINGS_DAMAGED_TITLE,
    TUI_SETTINGS_DAMAGED_BODY,
    TUI_SETTINGS_UNREADABLE_TITLE,
    TUI_SETTINGS_UNREADABLE_BODY,
    DELIVERY_TITLE,
    DELIVERY_BODY,
    DELIVERY_PRESETS,
    DELIVERY_LOCALES,
    UNASSIGNED_TUNNEL_TITLE,
    UNASSIGNED_TUNNEL_BODY,
    ADDITIONAL_MOVED_TITLE,
    ADDITIONAL_MOVED_BODY,
    LOCAL_NETWORK_TOO_WIDE_TITLE,
    LOCAL_NETWORK_TOO_WIDE_BODY,
    RULE_DUPLICATES_TITLE,
    RULE_DUPLICATES_BODY,
    APP_RULE_LEARNING_TITLE,
    APP_RULE_LEARNING_BODY,
    PROTECTION_COVERAGE_TITLE,
    PROTECTION_BLANKET_BLOCK_NOT_ARMED,
    BLOCK_ALL_ARMED,
    PROTECTION_VOLUME_HIGH,
    REVISION_INTEGRITY,
    REVISION_INTEGRITY_TITLE,
    VPN_SPLIT_TITLE,
    RULES_EMPTY,
    POLICY_INACTIVE_NO_ADAPTER,
    POLICY_INACTIVE_BLOCKING,
    PROTECTION_MACHINE_WIDE_CUT,
    HELP_TITLE,
    HELP_SCREENS,
    HELP_MOVE,
    HELP_PANELS,
    HELP_OPEN,
    HELP_HELP,
    HELP_BACK,
    HELP_QUIT,
    HELP_STATUS_FEED,
    FOOTER,
    CLIPPED,
    PLAIN_SCREEN,
    PLAIN_PROMPT,
    PLAIN_HELP_NUMBER,
    PLAIN_HELP_ENTER,
    PLAIN_HELP_HELP,
    PLAIN_UNKNOWN,
    PLAIN_NUMBER_GONE,
    PLAIN_INPUT_ENDED_UNAPPLIED,
    PLAIN_COMMANDS,
];

#[cfg(test)]
mod tests {
    use super::ALL;
    use serde_json::Value;

    #[test]
    fn plural_families_are_in_both_locale_files() {
        for language in ["en", "ru"] {
            let root = locale(language);
            let families = [
                super::BLOCK_NOTICE_BACKLOG_COUNTED,
                super::VPN_SPLIT_COUNTED,
            ];
            for id in families.iter().flat_map(|plural| plural.required_ids()) {
                assert!(lookup(&root, &id).is_some(), "{language}.json lacks {id}");
            }
        }
    }

    fn locale(language: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../locales")
            .join(format!("{language}.json"));
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
    }

    fn lookup<'a>(root: &'a Value, id: &str) -> Option<&'a str> {
        id.split('.')
            .try_fold(root, |node, part| node.get(part))
            .and_then(Value::as_str)
    }

    /// The English fallback is only for a binary run without its locale files;
    /// a key missing from either file would show it, or a raw id, for good.
    #[test]
    fn every_key_is_in_both_locale_files() {
        for language in ["en", "ru"] {
            let root = locale(language);
            let missing: Vec<_> = ALL
                .iter()
                .filter(|k| lookup(&root, k.id).is_none())
                .map(|k| k.id)
                .collect();
            assert!(missing.is_empty(), "{language}.json lacks {missing:?}");
        }
    }

    #[test]
    fn no_key_is_listed_twice() {
        let mut ids: Vec<_> = ALL.iter().map(|k| k.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }
}
