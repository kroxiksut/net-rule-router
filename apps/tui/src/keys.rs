//! Every locale key the terminal interface shows. Shared concepts reuse the
//! GUI's keys, so one wording serves both surfaces; only what exists in the
//! terminal alone lives under `tui.*`.

use crate::i18n::{key, Key};

// ── Screens ──────────────────────────────────────────────────────────────────

pub const SCREEN_STATUS: Key = key("tui.screen.status", "Status");
pub const SCREEN_WIZARD: Key = key("dialog.first-run.title", "First run");
pub const SCREEN_INTERFACES: Key = key("section.interfaces-routes", "Interfaces and routes");
pub const SCREEN_RULES: Key = key("section.rules", "Rules");
pub const SCREEN_OVERLAPS: Key = key("rules.overlaps.nav-label", "Overlaps");
pub const SCREEN_SUGGESTIONS: Key = key("rules.suggestions.inbox.nav-label", "Suggested addresses");
pub const SCREEN_TRACE: Key = key("diag.conn-trace.title", "Connection trace");
pub const SCREEN_OUTAGE_BLOCKS: Key = key(
    "diag.outage-blocks.title",
    "Blocked while the route was down",
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
pub const FIX_INSTALL: Key = key(
    "tui.connection.fix-install",
    "To install it, run: {command}",
);
pub const FIX_START: Key = key("tui.connection.fix-start", "To start it, run: {command}");
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

pub const ROUTING_TITLE: Key = key("routing.status.card-title", "Routing state");
pub const ROUTING_ACTIVE: Key = key("routing.status.active", "Routing active");
pub const ROUTING_LIMITED: Key = key("routing.status.limited", "Routing limited");
pub const ROUTING_PAUSED: Key = key("routing.status.paused", "Routing paused");
pub const ROUTING_DISCONNECTED: Key = key("routing.status.disconnected", "Service not connected");
pub const DETAIL_ACTIVE: Key = key(
    "routing.status.detail-active",
    "Rules apply on this user session.",
);
pub const DETAIL_LIMITED: Key = key(
    "routing.status.detail-limited",
    "Some rules are not being applied right now. The notices say why.",
);
pub const DETAIL_PAUSED: Key = key(
    "routing.status.detail-paused",
    "Rules are disabled until you re-enable them.",
);

// ── Connections (roles) ──────────────────────────────────────────────────────

pub const ROLES_TITLE: Key = key("tui.status.connections-title", "Connections");
pub const ROLE_PRIMARY: Key = key("interfaces.role.primary", "Main connection");
pub const ROLE_SECONDARY: Key = key("interfaces.role.secondary", "Additional connection");
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
    "The service has no routing settings for you yet, so nothing is being routed. Choose the main and additional connections.",
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
    "The service reported a state this version does not recognise. Open interfaces and routes to check the setup.",
);
pub const ENF_RESTORED_TITLE: Key = key(
    "notifications.enforcement.restored.title",
    "Routing is working again",
);
pub const ENF_RESTORED_BODY: Key = key(
    "notifications.enforcement.restored.body",
    "Your rules are being applied again. Pages that were refused while the connection was down keep showing the error until you reload them — press F5 on those tabs.",
);
pub const ENF_RESTORED_WHERE: Key = key(
    "tui.outage-blocks.where",
    "The list of what was blocked: {screen}",
);

// ── Notices ──────────────────────────────────────────────────────────────────

pub const NOTICES_TITLE: Key = key("notifications.title", "Notifications");
pub const NOTICES_EMPTY: Key = key("notifications.empty", "No notifications.");
pub const LEVEL_WARNING: Key = key("settings.logs.level.option-warning", "Warning");
pub const LEVEL_INFO: Key = key("settings.logs.level.option-info", "Info");
pub const HOST_UNREACHABLE_TITLE: Key = key(
    "notifications.host-unreachable.title",
    "A site does not answer on either link",
);
pub const HOST_UNREACHABLE_BODY: Key = key(
    "notifications.host-unreachable.body",
    "{host} did not answer through the main link or through the additional one, so moving it would not help and nothing was offered. The problem is most likely on the site's side.",
);
pub const EXTERNAL_ADDRESS_TITLE: Key =
    key("tray.external-address.title", "Additional route connected");
pub const EXTERNAL_ADDRESS_BODY: Key = key(
    "tray.external-address.body",
    "External address of the additional route: {address}",
);
pub const EXTERNAL_ADDRESS_ADAPTER: Key = key("tray.external-address.adapter", "Adapter: {name}");

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
    "On this screen, Up and Down scroll the notifications when that panel has the focus.",
);
pub const FOOTER: Key = key("tui.footer", "F1: help   q: quit");

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
pub const PLAIN_COMMANDS: Key = key("tui.plain.commands", "Commands on this screen");

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    SCREEN_STATUS,
    SCREEN_WIZARD,
    SCREEN_INTERFACES,
    SCREEN_RULES,
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
    FIX_INSTALL,
    FIX_START,
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
    ENF_PRIMARY_DOWN_TITLE,
    ENF_PRIMARY_DOWN_BODY,
    ENF_SECONDARY_DOWN_TITLE,
    ENF_SECONDARY_DOWN_BODY,
    ENF_UNREADABLE_TITLE,
    ENF_UNREADABLE_BODY,
    ENF_UNKNOWN_TITLE,
    ENF_UNKNOWN_BODY,
    ENF_RESTORED_TITLE,
    ENF_RESTORED_BODY,
    ENF_RESTORED_WHERE,
    NOTICES_TITLE,
    NOTICES_EMPTY,
    LEVEL_WARNING,
    LEVEL_INFO,
    HOST_UNREACHABLE_TITLE,
    HOST_UNREACHABLE_BODY,
    EXTERNAL_ADDRESS_TITLE,
    EXTERNAL_ADDRESS_BODY,
    EXTERNAL_ADDRESS_ADAPTER,
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
    PLAIN_SCREEN,
    PLAIN_PROMPT,
    PLAIN_HELP_NUMBER,
    PLAIN_HELP_ENTER,
    PLAIN_HELP_HELP,
    PLAIN_UNKNOWN,
    PLAIN_COMMANDS,
];

#[cfg(test)]
mod tests {
    use super::ALL;
    use serde_json::Value;

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
