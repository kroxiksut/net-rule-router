//! Every locale key the Settings screen shows. The GUI's own wording is reused
//! for each setting it also has; only what the terminal alone says lives under
//! `tui.settings.*`.

use crate::i18n::{key, Key};

// ── Sections ─────────────────────────────────────────────────────────────────

pub const SECTIONS: Key = key("tui.settings.sections", "Settings sections");
pub const NOTIFICATIONS: Key = key("settings.category.notifications", "Notifications");
pub const ROUTING: Key = key("settings.group.routing-behavior", "Routing behavior");
pub const FAILURE_POLICY: Key = key(
    "settings.routing.failure-policy.title",
    "Apply failure policy",
);
pub const SERVICE: Key = key("settings.service.title", "Service management");
pub const PRESETS: Key = key("settings.category.presets", "Presets and settings");
pub const LOGS: Key = key("settings.group.logs-diagnostics", "Logs and diagnostics");
pub const TRAFFIC: Key = key("settings.traffic.category", "Traffic statistics");
pub const UPDATES: Key = key("settings.group.updates", "Check for updates");
pub const TERMINAL: Key = key("tui.settings.terminal.title", "Terminal");

// ── Common words and outcomes ────────────────────────────────────────────────

pub const ON: Key = key("tui.settings.on", "On");
pub const OFF: Key = key("tui.settings.off", "Off");
pub const NOT_SET: Key = key("tui.settings.not-set", "not set");
pub const LOADING: Key = key("settings.block-notices.mutes.loading", "Loading…");
pub const NO_DATA: Key = key("diag.status.no-data", "No data from the service yet");
pub const SAVING: Key = key("tui.settings.saving", "Saving…");
pub const SAVED: Key = key("tui.settings.saved", "Saved.");
pub const NOT_SAVED: Key = key("tui.settings.not-saved", "Not saved: {error}");
pub const LOAD_FAILED: Key = key(
    "tui.settings.load-failed",
    "Could not read this from the service: {error}",
);
pub const OFFLINE: Key = key(
    "tui.settings.offline",
    "The service is not connected, so nothing was changed. The values shown are the last ones known.",
);
pub const NUMBER_RANGE: Key = key(
    "tui.settings.number-range",
    "Type a whole number from {min} to {max}.",
);
pub const RESULT: Key = key("tui.settings.result", "Result");
pub const NEW_VALUE: Key = key("tui.settings.new-value", "New value: {value}");
pub const EDIT_HINT: Key = key("tui.settings.edit-hint", "Enter saves, Esc cancels.");
pub const PICK_HINT: Key = key(
    "tui.settings.pick-hint",
    "Up and Down choose, Enter saves, Esc cancels.",
);
pub const CONFIRM: Key = key(
    "tui.settings.confirm",
    "Press Enter again to confirm, or Esc to cancel.",
);
pub const MORE_ABOVE: Key = key("tui.settings.more-above", "{count} more lines above");

// The window's confirmation before a level that holds traffic, same keys.
pub const LEAK_HOLDS_TITLE: Key = key(
    "dialog.leak-holds-now.title",
    "The additional connection is not available",
);
pub const LEAK_HOLDS_BODY: Key = key(
    "dialog.leak-holds-now.body",
    "With leak protection set to Everything, traffic is held right away: the internet stops until the additional connection returns.",
);
pub const LEAK_HOLDS_EFFECT: Key = key(
    "dialog.leak-holds-now.effect",
    "Your local network and what your rules send over the main connection keep working.",
);
pub const LEAK_UNROUTABLE_BODY: Key = key(
    "dialog.unroutable-secondary.body-kill-switch",
    "It is currently assigned as your additional route.",
);
pub const LEAK_UNROUTABLE_EFFECT: Key = key(
    "dialog.unroutable-secondary.effect-kill-switch-arming",
    "Once leak protection is on, those destinations are BLOCKED instead: the sites behind those rules stop loading.",
);

// ── Keys and line mode ───────────────────────────────────────────────────────

pub const HELP_FOCUS: Key = key(
    "tui.help.settings-focus",
    "Tab: give this screen the focus; then Up and Down move through the sections and the settings.",
);
pub const HELP_ENTER: Key = key(
    "tui.help.settings-enter",
    "Enter: open a section, change the chosen setting, or run the chosen action.",
);
pub const HELP_ESC: Key = key(
    "tui.help.settings-esc",
    "Esc: cancel a change, or go back to the list of sections.",
);
pub const PLAIN_SECTIONS: Key = key(
    "tui.settings.plain.sections",
    "c and a number, for example c2: open that section",
);
pub const PLAIN_ITEMS: Key = key(
    "tui.settings.plain.items",
    "i and a number, for example i3: change that setting or run that action. With a value after it, for example i3 2 or i3 30, it is set at once.",
);
pub const PLAIN_BACK: Key = key("tui.settings.plain.back", "b: back to the list of sections");
pub const PLAIN_PICK: Key = key(
    "tui.settings.plain.pick-prompt",
    "Type the number of an option, or press Enter alone to cancel.",
);
pub const PLAIN_EDIT: Key = key(
    "tui.settings.plain.edit-prompt",
    "Type the new value and press Enter; Enter alone cancels.",
);
pub const PLAIN_CONFIRM: Key = key(
    "tui.settings.plain.confirm-prompt",
    "Type yes to confirm; anything else cancels.",
);
pub const PLAIN_NO_ITEM: Key = key("tui.settings.plain.no-item", "There is no {code} here.");

// ── Notifications ────────────────────────────────────────────────────────────

pub const HIDDEN_HEADING: Key = key(
    "settings.notifications.hidden.heading",
    "Hidden notifications",
);
pub const HIDDEN_DESCRIPTION: Key = key(
    "settings.notifications.hidden.description",
    "Choose for how long each kind of notification stays hidden. The \"Don't show…\" button on a notification sets the same thing.",
);
pub const HIDDEN_SHOWN: Key = key("settings.notifications.hidden.shown", "Shown");
pub const HIDDEN_FOREVER: Key = key("settings.notifications.hidden.forever", "Hidden for good");
pub const HIDDEN_UNTIL: Key = key(
    "settings.notifications.hidden.until",
    "Hidden until {timestamp}",
);
pub const HIDE_SHOW: Key = key("settings.notifications.hidden.show", "Show");
pub const FOR_A_DAY: Key = key("label.duration.for-a-day", "For a day");
pub const FOR_7_DAYS: Key = key("label.duration.for-7-days", "For 7 days");
pub const FOR_30_DAYS: Key = key("label.duration.for-30-days", "For 30 days");
pub const FOREVER: Key = key("label.duration.forever", "Forever");
pub const BLOCK_GROUP: Key = key("settings.group.block-notices", "Blocked-connection notices");
pub const MUTE_ALL: Key = key(
    "settings.block-notices.mutes.row-all",
    "All blocked-connection notices",
);
pub const MUTE_HOST: Key = key("settings.block-notices.mutes.row-host", "Host: {name}");
pub const MUTE_APP: Key = key(
    "settings.block-notices.mutes.row-app",
    "Application: {name}",
);
pub const MUTE_REASON: Key = key("settings.block-notices.mutes.row-reason", "Reason: {name}");
pub const MUTE_UNTIL: Key = key(
    "settings.block-notices.mutes.until-timestamp",
    "Until {timestamp}",
);
pub const MUTES_HEADING: Key = key("settings.block-notices.mutes.heading", "Active mutes");
pub const MUTES_EMPTY: Key = key("settings.block-notices.mutes.empty", "No active mutes.");
pub const ADD_HEADING: Key = key("settings.block-notices.add.heading", "Add a mute");
pub const ADD_DESCRIPTION: Key = key(
    "settings.block-notices.add.description",
    "The notification's quick-mute options only offer a few fixed lengths. Use this form for a duration of your own, or to mute indefinitely.",
);
pub const SCOPE_ALL: Key = key(
    "settings.block-notices.add.scope-all",
    "Every blocked-connection notice",
);
pub const SCOPE_HOST: Key = key("settings.block-notices.add.scope-host", "One host");
pub const SCOPE_APP: Key = key("settings.block-notices.add.scope-app", "One application");
pub const SCOPE_LABEL: Key = key("settings.block-notices.add.scope-label", "What to mute");
pub const HOST_FIELD: Key = key(
    "settings.block-notices.add.host-placeholder",
    "Hostname, exactly as shown in the notification",
);
pub const APP_FIELD: Key = key(
    "settings.block-notices.add.app-placeholder",
    "Application (process) name, exactly as shown in the notification",
);
pub const DURATION: Key = key("settings.block-notices.add.duration-label", "For how long");
pub const UNIT: Key = key("tui.settings.notifications.unit", "Unit");
pub const MINUTES: Key = key(
    "settings.block-notices.add.duration-unit-minutes",
    "Minutes",
);
pub const HOURS: Key = key("settings.block-notices.add.duration-unit-hours", "Hours");
pub const DAYS: Key = key("settings.block-notices.add.duration-unit-days", "Days");
pub const MUTE_ADDED: Key = key("settings.block-notices.add.saved", "Mute added.");
pub const NEED_TARGET: Key = key(
    "tui.settings.notifications.need-target",
    "Type the host or application name first.",
);
pub const NEED_SUFFIX: Key = key(
    "tui.settings.routing.need-suffix",
    "Type the network suffix first.",
);
pub const DELETE: Key = key("action.delete", "Delete");
pub const CLEAR: Key = key("action.clear", "Clear");
pub const ADD: Key = key("action.add", "Add");
pub const UNSUPPORTED: Key = key(
    "status.platform-unsupported",
    "This is not available on your operating system yet, so the controls here stay off. Nothing here is sent to the background service.",
);

// ── Routing behaviour ────────────────────────────────────────────────────────

pub const DEFAULT_ROUTE: Key = key("settings.routing.default-route.title", "Default route");
pub const DEFAULT_ROUTE_NOTE: Key = key(
    "settings.routing.default-route.description",
    "Where traffic that matches no rule is sent. Rules always take priority. Default: primary route.",
);
pub const MODE_PREFER_PRIMARY: Key = key(
    "interfaces.mode.prefer-primary",
    "Main connection — selected sites through the additional one",
);
pub const MODE_PREFER_SECONDARY: Key = key(
    "interfaces.mode.prefer-secondary-when-available",
    "Additional connection — exceptions through the main one",
);
pub const SUBDOMAINS: Key = key(
    "settings.routing-behavior.include-subdomains.label",
    "Also cover subdomains for domain rules",
);
pub const SUBDOMAINS_NOTE: Key = key("settings.routing-behavior.include-subdomains.note", "");
pub const APP_TAKEOVER: Key = key(
    "settings.routing-behavior.app-rules-take-all.label",
    "Programs in your rules take all their traffic",
);
pub const APP_TAKEOVER_NOTE: Key = key(
    "settings.routing-behavior.app-rules-take-all.description",
    "",
);
pub const LEAK_TITLE: Key = key("settings.routing.kill-switch.title", "Leak protection");
pub const LEAK_OFF: Key = key("settings.routing.leak-protection.option-off", "Off");
pub const LEAK_SITES: Key = key(
    "settings.routing.leak-protection.option-sites",
    "Routed sites",
);
pub const LEAK_EVERYTHING: Key = key(
    "settings.routing.leak-protection.option-everything",
    "Everything",
);
pub const LEAK_OFF_NOTE: Key = key(
    "settings.routing.leak-protection.note-off",
    "If the additional connection drops, traffic continues over your main connection.",
);
pub const LEAK_SITES_NOTE: Key = key(
    "settings.routing.leak-protection.note-sites",
    "What your rules send through the additional connection never goes out the main one. Everything else keeps working.",
);
pub const LEAK_EVERYTHING_NOTE: Key = key(
    "settings.routing.leak-protection.note-everything",
    "Nothing leaves except through the additional connection, your local network and what your rules send over the main connection. If the additional connection drops, the internet waits until it returns.",
);
pub const PROTOCOLS: Key = key(
    "settings.routing.kill-switch.protocols.label",
    "Protocols leak protection cuts",
);
pub const PROTOCOL_TCP: Key = key("settings.routing.kill-switch.protocols.tcp", "TCP");
pub const PROTOCOL_UDP: Key = key("settings.routing.kill-switch.protocols.udp", "UDP");
pub const PROTOCOL_ICMP: Key = key("settings.routing.kill-switch.protocols.icmp", "ICMP (ping)");
pub const PROTOCOL_IGMP: Key = key("settings.routing.kill-switch.protocols.igmp", "IGMP");
pub const PROTOCOL_GRE: Key = key("settings.routing.kill-switch.protocols.gre", "GRE");
pub const PROTOCOL_ESP: Key = key("settings.routing.kill-switch.protocols.esp", "ESP");
pub const PROTOCOL_LAST: Key = key(
    "settings.routing.kill-switch.protocols.last-one-hint",
    "To turn leak protection off, choose Off above.",
);
pub const ALLOW_DNS: Key = key(
    "settings.routing.kill-switch.allow-dns-label",
    "Allow name resolution over the main connection while blocked",
);
pub const ALLOW_DNS_NOTE: Key = key("settings.routing.kill-switch.allow-dns-note", "");
pub const SHARED_STRICT: Key = key(
    "settings.routing.kill-switch.shared-strict-label",
    "Strict: also block addresses shared with regular sites (may break them)",
);
pub const SHARED_STRICT_NOTE: Key = key("settings.routing.kill-switch.shared-strict-note", "");
pub const SHARED_IP: Key = key(
    "settings.routing-behavior.shared-ip.label",
    "When a routed domain shares an IP address with other sites",
);
pub const SHARED_IP_NOTE: Key = key("settings.routing-behavior.shared-ip.note", "");
pub const SHARED_MAJORITY_IP: Key = key(
    "settings.routing-behavior.shared-ip.option-majority-of-ip",
    "Route the shared IP only if most sites on it are yours (balanced)",
);
pub const SHARED_MAJORITY_RULES: Key = key(
    "settings.routing-behavior.shared-ip.option-majority-of-rules",
    "Route the shared IP only if it holds most of your rules (cautious)",
);
pub const SHARED_ANY: Key = key(
    "settings.routing-behavior.shared-ip.option-any-rule-domain",
    "Always route the whole shared IP (aggressive)",
);
pub const ROUTING_METHOD: Key = key("settings.routing.routing-method.title", "Routing method");
pub const ENFORCEMENT: Key = key(
    "settings.routing.enforcement-mode.label",
    "How routed traffic is enforced",
);
pub const ENFORCEMENT_RESOLVER: Key = key(
    "settings.routing.enforcement-mode.option-resolver",
    "Local DNS resolver (default)",
);
pub const ENFORCEMENT_REACTIVE: Key = key(
    "settings.routing.enforcement-mode.option-reactive",
    "Watching system DNS (legacy)",
);
pub const ENFORCEMENT_NOTE: Key = key("settings.routing.enforcement-mode.note", "");
pub const DNS_FAST_NOTE: Key = key("settings.routing.dns-fast-answers.note", "");
pub const LIVENESS_NOTE: Key = key("settings.routing.liveness-window.note", "");
pub const DNS_VIA_SECONDARY: Key = key(
    "settings.routing.dns-via-secondary.label",
    "DNS through the tunnel",
);
pub const DNS_VIA_SECONDARY_NOTE: Key = key("settings.routing.dns-via-secondary.note", "");
pub const DNS_FAST: Key = key(
    "settings.routing.dns-fast-answers.label",
    "Fast DNS answers",
);
pub const FAKE_IP: Key = key(
    "settings.routing.fake-ip.label",
    "Route sites over virtual addresses (fake-IP)",
);
pub const FAKE_IP_UDP: Key = key(
    "settings.routing.fake-ip-udp-relay.label",
    "Fake-IP UDP relay (experimental)",
);
pub const FAKE_IP_RST: Key = key(
    "settings.routing.fake-ip-instant-rst.label",
    "Instant reset when the additional route is unavailable",
);
pub const LIVENESS: Key = key(
    "settings.routing.liveness-window.label",
    "Additional tunnel liveness window",
);
pub const LIVENESS_DISABLED: Key = key(
    "settings.routing.liveness-window.option-disabled",
    "Disabled (default)",
);
pub const LIVENESS_RANGE: Key = key(
    "tui.settings.routing.liveness-range",
    "Seconds from 5 to 3600, or 0 to turn it off.",
);
pub const SECONDS: Key = key("settings.routing.liveness-window.seconds-unit", "seconds");
pub const DOH_TITLE: Key = key(
    "settings.routing.doh-lockdown.title",
    "Block browser DoH/DoT",
);
pub const DOH_ENABLE: Key = key(
    "settings.routing.doh-lockdown.label",
    "Block browser DoH/DoT",
);
pub const DOH_SCOPE: Key = key("settings.routing.doh-lockdown.scope-label", "When to apply");
pub const DOH_LEAK_ONLY: Key = key(
    "settings.routing.doh-lockdown.scope-leak-protection-only",
    "Only while leak protection is active (recommended)",
);
pub const DOH_ALWAYS: Key = key("settings.routing.doh-lockdown.scope-always", "Always");
pub const DOH_AUTO: Key = key(
    "settings.routing.doh-lockdown.auto-label",
    "Decide automatically (recommended)",
);
pub const DOH_AUTO_NOTE: Key = key(
    "settings.routing.doh-lockdown.auto-note",
    "Blocks encrypted DNS in browsers while you have rules for the additional route, so the sites you route are seen and routed. Turn this off to set the blocking by hand.",
);
pub const DOH_AUTO_ON: Key = key(
    "settings.routing.doh-lockdown.auto-on",
    "On: you have rules for the additional route.",
);
pub const DOH_AUTO_OFF: Key = key(
    "settings.routing.doh-lockdown.auto-off",
    "Off: no rules for the additional route yet.",
);
pub const SUFFIX_TITLE: Key = key(
    "settings.routing.local-suffixes.title",
    "Home and local network names",
);
pub const SUFFIX_DESCRIPTION: Key = key(
    "settings.routing.local-suffixes.description",
    "Names under these suffixes belong to the network you are on (a printer, a router, a NAS) and are resolved by that network, never sent down a route. One list for every user of this computer; changing it needs an administrator.",
);
pub const SUFFIX_EMPTY: Key = key(
    "settings.routing.local-suffixes.empty",
    "The list is empty.",
);
pub const SUFFIX_COVERS: Key = key(
    "settings.routing.local-suffixes.covers-rules",
    "covers your rules for {hosts}; those names keep following their rules",
);
pub const SUFFIX_OFFERED: Key = key(
    "settings.routing.local-suffixes.offered",
    "Add {suffix}, offered by {link}",
);
pub const SUFFIX_FIELD: Key = key("settings.routing.local-suffixes.add-field", "New suffix");
pub const HOSTS_TITLE: Key = key("settings.routing.hosts-group.title", "Hosts file");
pub const HOSTS_BYPASS: Key = key(
    "settings.routing.hosts-bypass.label",
    "Resolve routed domains bypassing the hosts file",
);
pub const LOCAL_TITLE: Key = key("settings.routing.local-networks.title", "Local networks");
pub const FWD_TITLE: Key = key(
    "settings.routing.forwarded-traffic.title",
    "WSL, containers and virtual machines",
);
pub const FWD_CHOICE: Key = key(
    "settings.routing.forwarded-traffic.choice",
    "When the additional route is down",
);
pub const FWD_NOTE: Key = key(
    "settings.routing.forwarded-traffic.description",
    "Programs in WSL, containers and virtual machines reach the internet through this computer, yet leak protection does not see them on its own. Choose what they get while the additional route is down.",
);
pub const FWD_AS_COMPUTER: Key = key(
    "settings.routing.forwarded-traffic.as-computer.label",
    "Same as this computer (recommended)",
);
pub const FWD_UNPROTECTED: Key = key(
    "settings.routing.forwarded-traffic.unprotected.label",
    "Do not protect",
);
pub const FWD_UNANSWERED: Key = key(
    "settings.routing.forwarded-traffic.unanswered",
    "Not chosen yet: they are protected like this computer.",
);
pub const LOCAL_AUTO: Key = key(
    "settings.routing.local-networks.auto-accept",
    "Keep newly found local networks reachable without asking",
);
pub const LOCAL_EMPTY: Key = key(
    "settings.routing.local-networks.empty",
    "No local networks found yet. Add one below if you reach a virtual machine at an address this list does not show.",
);
pub const LOCAL_UNDECIDED: Key = key("settings.routing.local-networks.undecided", "no answer yet");
pub const LOCAL_TOO_WIDE: Key = key(
    "settings.routing.local-networks.reason.too-wide",
    "too wide to be a local network, stays blocked",
);
pub const LOCAL_NAMES_RULE: Key = key(
    "settings.routing.local-networks.reason.contains-rule-address",
    "holds an address your rules name, stays blocked",
);
pub const LOCAL_KIND_MANUAL: Key = key(
    "settings.routing.local-networks.kind-manual",
    "added by you",
);
pub const LOCAL_KIND_MAIN: Key = key(
    "settings.routing.local-networks.kind-main-link",
    "main connection: {name}",
);
pub const LOCAL_KIND_VM: Key = key(
    "settings.routing.local-networks.kind-virtual-machine",
    "virtual machine: {name}",
);
pub const LOCAL_FIELD: Key = key("settings.routing.local-networks.add", "Add a network");
pub const LOCAL_NOT_PRIVATE: Key = key(
    "settings.routing.local-networks.reject-not-private",
    "{cidr} is not a local network — only private ranges can be kept reachable.",
);
pub const LOCAL_MALFORMED: Key = key(
    "settings.routing.local-networks.reject-malformed",
    "{cidr} is not a network address. Write it as 10.0.2.0/24.",
);
pub const NEED_NETWORK: Key = key(
    "tui.settings.routing.need-network",
    "Type the network first, for example 10.0.2.0/24.",
);
pub const SHORT_TITLE: Key = key("settings.routing.short-names.title", "Short names");
pub const SHORT_NOTE: Key = key("settings.routing.short-names.description", "");
pub const SHORT_ENABLE: Key = key(
    "settings.routing.short-names.enable",
    "Complete short names with this domain",
);
pub const SHORT_FIELD: Key = key("settings.routing.short-names.field", "Network domain");
pub const EXTERNAL_CHECK: Key = key(
    "settings.routing.vpn-client.external-address-auto",
    "Check the external address each time the additional route connects",
);
pub const EXTERNAL_CHECK_NOTE: Key =
    key("settings.routing.vpn-client.external-address-auto-note", "");
pub const AUTO_TITLE: Key = key("settings.routing.auto-rules.title", "Auto-rules");
pub const PROBE_AUTO: Key = key(
    "settings.routing.primary-probe.auto",
    "Check the main route for new suggestions automatically",
);
pub const PROBE_TIMEOUT: Key = key(
    "settings.routing.primary-probe.timeout",
    "Wait per address, ms",
);
pub const PROBE_TARGETS: Key = key(
    "settings.routing.primary-probe.max-targets",
    "Addresses per check",
);
pub const PROBE_REPEAT: Key = key(
    "settings.routing.primary-probe.repeat",
    "Do not re-check the same address for, s",
);
pub const PROBE_RESET: Key = key("settings.routing.primary-probe.reset", "Reset to defaults");
pub const AUTO_MODE: Key = key(
    "settings.routing.auto-rules.label",
    "Missing companion domains",
);
pub const AUTO_OFF: Key = key("settings.routing.auto-rules.mode-off", "Off");
pub const AUTO_SUGGEST: Key = key(
    "settings.routing.auto-rules.mode-suggest",
    "Suggest only (default)",
);
pub const AUTO_AUTO: Key = key(
    "settings.routing.auto-rules.mode-auto",
    "Apply automatically",
);
pub const AUTO_EAGER: Key = key(
    "settings.routing.auto-rules.eager-label",
    "Offer content-delivery domains without waiting for analysis",
);
pub const SYSTEM_TITLE: Key = key(
    "settings.routing.system-level.title",
    "System-level routing (requires administrator)",
);
pub const RULE_LOCK: Key = key(
    "settings.routing.rule-lock.allow.label",
    "Allow users to change routing rules",
);
pub const SERVICE_DRIVEN: Key = key(
    "settings.diagnostics.rule-scope.service-driven.label",
    "Keep enforcing while the service runs (even when the app is closed)",
);
pub const STOP_PERSIST: Key = key(
    "settings.diagnostics.routing-stop.persist.label",
    "Keep rule routes on the additional adapter after pause/stop (route persistence, not leak protection)",
);

// ── Apply failure policy ─────────────────────────────────────────────────────

pub const POLICY_DESCRIPTION: Key = key(
    "settings.routing.failure-policy.description",
    "Choose how the service handles partial failures during multi-step rule application.",
);
pub const POLICY_BEST_EFFORT: Key = key(
    "settings.routing.failure-policy.option.best-effort.label",
    "Best effort (recommended)",
);
pub const POLICY_BEST_EFFORT_NOTE: Key = key(
    "settings.routing.failure-policy.option.best-effort.description",
    "",
);
pub const POLICY_ALL: Key = key(
    "settings.routing.failure-policy.option.all-or-nothing.label",
    "All or nothing",
);
pub const POLICY_ALL_NOTE: Key = key(
    "settings.routing.failure-policy.option.all-or-nothing.description",
    "",
);
pub const POLICY_PREFLIGHT: Key = key(
    "settings.routing.failure-policy.option.pre-flight.label",
    "Check first, then all or nothing",
);
pub const POLICY_PREFLIGHT_NOTE: Key = key(
    "settings.routing.failure-policy.option.pre-flight.description",
    "",
);
pub const POLICY_ELEVATION: Key = key(
    "settings.routing.failure-policy.requires-elevation",
    "Changing this setting requires administrator elevation.",
);

// ── Service management ───────────────────────────────────────────────────────

pub const SERVICE_STATE: Key = key("tui.settings.service.state", "State: {state}");
pub const SERVICE_START_MODE: Key = key("tui.settings.service.start-mode", "Starts: {mode}");
pub const RUN_RUNNING: Key = key("settings.service.status.running", "Running");
pub const RUN_STOPPED: Key = key("settings.service.status.stopped", "Stopped");
pub const RUN_STARTING: Key = key("settings.service.status.start-pending", "Starting...");
pub const RUN_STOPPING: Key = key("settings.service.status.stop-pending", "Stopping...");
pub const RUN_NOT_INSTALLED: Key = key("settings.service.status.not-installed", "Not installed");
pub const RUN_UNKNOWN: Key = key("settings.service.status.unknown", "Unknown");
pub const MODE_WITH_SYSTEM: Key = key(
    "settings.service.start-mode.with-windows.label",
    "Start with the system (recommended)",
);
pub const MODE_ON_LAUNCH: Key = key(
    "settings.service.start-mode.on-app-launch.label",
    "Start when the app opens",
);
pub const SERVICE_START: Key = key("settings.service.action.start", "Start service");
pub const SERVICE_STOP: Key = key("settings.service.action.stop", "Stop service");
pub const SERVICE_RESTART: Key = key("settings.service.action.restart", "Restart service");
pub const SERVICE_FIX_UNINSTALL: Key = key(
    "tui.settings.service.fix-uninstall",
    "To remove the service, run: {command}",
);
pub const SERVICE_FIX_REINSTALL: Key = key(
    "tui.settings.service.fix-reinstall",
    "To re-register it from this folder and start it, run: {command}",
);
pub const SERVICE_FIX_MODE: Key = key(
    "tui.settings.service.fix-mode",
    "To change when it starts, remove it with {uninstall}, then install it again with {install}",
);
pub const RULES_PAUSE_TITLE: Key = key("settings.routing.pause.title", "Apply rules");
pub const RULES_PAUSE_HINT: Key = key(
    "settings.routing.pause.persistence-hint",
    "Disabling stops applying rules until you re-enable them. Setting persists across restarts.",
);
pub const ROLLBACK_TITLE: Key = key("action.safe-rollback", "Safe rollback");
pub const ROLLBACK_LOOKUP: Key = key(
    "tui.settings.rollback-lookup",
    "Look up the previous version of my rules",
);
pub const ROLLBACK_READY: Key = key(
    "dialog.safe-rollback.body-ready",
    "Your current rules will be replaced by the ones you applied on {time} ({count} rules), and routing will follow them right away.",
);
pub const ROLLBACK_NONE: Key = key(
    "dialog.safe-rollback.body-none",
    "There is nothing to roll back to: no earlier version of your rules has been applied.",
);
pub const ROLLBACK_RUN: Key = key("dialog.safe-rollback.confirm", "Roll back");
pub const ROLLBACK_FAILED: Key = key(
    "tui.settings.rollback-failed",
    "Safe rollback failed: {error}",
);
pub const ROLLBACK_DONE: Key = key(
    "status.rollback-completed",
    "Rolled back to the rules you applied on {time}.",
);
pub const ROLLBACK_SUBMITTED: Key = key(
    "status.rollback-submitted",
    "Safe rollback submitted. The service is restoring the previous configuration.",
);
pub const SAFE_DISABLE_NOTE: Key = key(
    "dialog.safe-disable.body",
    "Temporarily disable your routing and leak protection: the routes and filters NetRuleRouter keeps for you are removed. Other users of this computer keep theirs. The service stays running; you can re-enable at any time. This action is audited.",
);
pub const SAFE_DISABLE_REASON: Key = key("dialog.safe-disable.reason-label", "Reason (required)");
pub const SAFE_DISABLE_RUN: Key = key("dialog.safe-disable.confirm", "Disable now");
pub const SAFE_DISABLE_NEED_REASON: Key = key(
    "dialog.safe-disable.reason-required",
    "Please describe the reason — it is recorded in the audit trail.",
);
pub const SAFE_DISABLE_DONE: Key = key("status.safe-disable.completed", "Safe disable applied");
pub const SERVICE_NOTE: Key = key(
    "tui.settings.service.note",
    "Starting and stopping the service needs administrator rights, and nrr-tui never asks for them. To use these actions, start nrr-tui as administrator or with sudo.",
);
pub const SERVICE_DONE: Key = key("tui.settings.service.done", "Done. State: {state}");
pub const SERVICE_QUERY_FAILED: Key = key(
    "tui.settings.service.query-failed",
    "Could not ask the system about the service: {error}",
);
pub const SERVICE_NO_MANAGER: Key = key(
    "tui.settings.service.no-manager",
    "This system has no service manager this program can ask.",
);

// ── Presets and settings ─────────────────────────────────────────────────────

pub const EXPORT_DESCRIPTION: Key = key(
    "settings.presets.full-settings-description",
    "Export adapter bindings, behavior mode, and rules-file paths as a single YAML file. Useful for backing up or transferring your settings.",
);
pub const EXPORT_PATH: Key = key("tui.settings.presets.export-path", "File to write");
pub const EXPORT_RUN: Key = key("tui.settings.presets.export", "Export full settings");
pub const EXPORT_NEED_PATH: Key = key(
    "tui.settings.presets.need-path",
    "Type the file name first.",
);
pub const EXPORT_EXISTS: Key = key(
    "tui.settings.presets.exists",
    "{path} already exists. Choose another name; nothing was overwritten.",
);
pub const EXPORT_DONE: Key = key(
    "tui.settings.presets.written",
    "Full settings exported to {path}.",
);
pub const EXPORT_WRITE_FAILED: Key = key(
    "tui.settings.presets.write-failed",
    "Could not write {path}: {error}",
);
pub const RULES_NOTE: Key = key(
    "tui.settings.presets.rules-note",
    "Rules files are imported and exported on the Rules screen.",
);

// ── Logs and storage ─────────────────────────────────────────────────────────

pub const RETENTION_TITLE: Key = key("diag.retention.section-title", "Retention settings");
pub const LOGS_AGE: Key = key("diag.retention.logs-max-age-label", "Keep logs for");
pub const LOGS_SIZE: Key = key("diag.retention.logs-max-size-label", "Maximum log storage");
pub const AUDIT_AGE: Key = key("diag.retention.audit-max-age-label", "Keep audit trail for");
pub const AUDIT_SIZE: Key = key(
    "diag.retention.audit-max-size-label",
    "Maximum audit storage",
);
pub const DAYS_UNIT: Key = key("diag.retention.logs-max-age-unit", "days");
pub const MB_UNIT: Key = key("diag.retention.size-unit.mb", "MB");
pub const VERBOSE: Key = key(
    "settings.diagnostics.service-stability.verbose.label",
    "Verbose service logging",
);
pub const VERBOSE_OFF: Key = key(
    "settings.diagnostics.service-stability.verbose.option-off",
    "Normal",
);
pub const VERBOSE_HOUR: Key = key(
    "settings.diagnostics.service-stability.verbose.option-one-hour",
    "Verbose for 1 hour",
);
pub const VERBOSE_FOUR: Key = key(
    "settings.diagnostics.service-stability.verbose.option-four-hours",
    "Verbose for 4 hours",
);
pub const VERBOSE_RESTART: Key = key(
    "settings.diagnostics.service-stability.verbose.option-until-restart",
    "Verbose until the service restarts",
);
pub const TRACE_LOG: Key = key(
    "settings.diagnostics.conn-trace.ndjson.label",
    "Write connection trace to service log",
);
pub const TRACE_OFF: Key = key("settings.diagnostics.conn-trace.ndjson.option-off", "Off");
pub const TRACE_HOUR: Key = key(
    "settings.diagnostics.conn-trace.ndjson.option-one-hour",
    "Write for 1 hour",
);
pub const TRACE_FOUR: Key = key(
    "settings.diagnostics.conn-trace.ndjson.option-four-hours",
    "Write for 4 hours",
);
pub const TRACE_RESTART: Key = key(
    "settings.diagnostics.conn-trace.ndjson.option-until-restart",
    "Write until the service restarts",
);
pub const WINDOW_UNTIL: Key = key("tui.settings.logs.window-until", "On until {timestamp}");
pub const CLEAR_LOGS: Key = key("diag.logs.clear-button", "Clear logs");
pub const LOGS_CLEARED: Key = key(
    "status.logs-cleared",
    "Operational logs cleared: {count} file(s), {size}",
);
pub const HISTORY_TITLE: Key = key("settings.conn-history.title", "Connection history");
pub const HISTORY_NOTE: Key = key(
    "settings.conn-history.help",
    "Which of your programs connected where, and over which route, kept on this computer for the days you choose. Only you can read your history; it is never part of the diagnostic archive.",
);
pub const HISTORY_KEEP: Key = key("settings.conn-history.keep", "Keep connection history");
pub const HISTORY_DAYS: Key = key("settings.conn-history.retention-label", "Keep for");
pub const HISTORY_CLEAR: Key = key("settings.conn-history.clear", "Clear my history");
pub const HISTORY_CLEARED: Key = key(
    "tui.settings.conn-history.cleared",
    "Your connection history was erased ({count} entries).",
);
pub const HISTORY_UNAVAILABLE: Key = key(
    "diag.conn-history.unavailable",
    "The connection history cannot be kept right now. The service log says why.",
);
pub const STORAGE_TITLE: Key = key("settings.storage.title", "Storage usage");
pub const STORAGE_STATE: Key = key("settings.storage.state-db", "Service state database");
pub const STORAGE_CACHE: Key = key("settings.storage.cache-db", "FQDN/IP cache");
pub const STORAGE_LOGS: Key = key("settings.storage.operational-logs", "Operational logs");
pub const STORAGE_AUDIT: Key = key("settings.storage.audit-logs", "Audit logs");
pub const STORAGE_TOTAL: Key = key("settings.storage.total", "Total");
pub const REVISIONS_TITLE: Key = key("settings.revisions.retention.title", "Revisions retention");
pub const REVISIONS_NOTE: Key = key(
    "settings.revisions.retention.description",
    "Controls how long superseded, rejected, and rolled-back revisions are kept before pruning.",
);
pub const SUPERSEDED_DAYS: Key = key(
    "settings.revisions.retention.superseded-days",
    "Keep superseded revisions for (days)",
);
pub const SUPERSEDED_COUNT: Key = key(
    "settings.revisions.retention.superseded-count",
    "Maximum superseded revisions",
);
pub const REJECTED_DAYS: Key = key(
    "settings.revisions.retention.rejected-days",
    "Keep rejected revisions for (days)",
);
pub const ROLLEDBACK_DAYS: Key = key(
    "settings.revisions.retention.rolledback-days",
    "Keep rolled-back revisions for (days)",
);
pub const ROLLEDBACK_COUNT: Key = key(
    "settings.revisions.retention.rolledback-count",
    "Maximum rolled-back revisions",
);
pub const SUPERSEDED_DAYS_NOTE: Key = key(
    "settings.revisions.retention.superseded-days-tooltip",
    "Earlier versions of your rules that you can roll back to. Keep them longer for a longer history, or shorter to save disk space.",
);
pub const SUPERSEDED_COUNT_NOTE: Key = key(
    "settings.revisions.retention.superseded-count-tooltip",
    "The most earlier versions kept, whatever their age. Once there are more, the oldest go first.",
);
pub const REJECTED_DAYS_NOTE: Key = key(
    "settings.revisions.retention.rejected-days-tooltip",
    "Rule sets the service refused to apply are kept this long, so the history still shows why they were refused.",
);
pub const ROLLEDBACK_DAYS_NOTE: Key = key(
    "settings.revisions.retention.rolledback-days-tooltip",
    "Rule sets that were undone, by you or after a failed apply, are kept this long so you can return to them.",
);
pub const ROLLEDBACK_COUNT_NOTE: Key = key(
    "settings.revisions.retention.rolledback-count-tooltip",
    "The most undone rule sets kept, whatever their age. Once there are more, the oldest go first.",
);
pub const PIN_LKG: Key = key(
    "settings.revisions.retention.pin-lkg",
    "Always keep last known-good revision",
);
pub const PIN_LKG_NOTE: Key = key(
    "settings.revisions.retention.pin-lkg-hint",
    "The most recent superseded revision is pinned and excluded from age and count limits.",
);
pub const REVISIONS_RESET: Key = key("action.reset-defaults", "Reset to defaults");
pub const LAST_CLEANUP: Key = key(
    "settings.revisions.retention.last-cleanup",
    "Last cleanup: {timestamp}",
);
pub const LAST_CLEANUP_NEVER: Key = key(
    "settings.revisions.retention.last-cleanup-never",
    "Last cleanup: never",
);

// ── Traffic statistics ───────────────────────────────────────────────────────

pub const TRAFFIC_NOTE: Key = key("settings.traffic.description", "");
pub const TRAFFIC_TODAY: Key = key("settings.traffic.period-today", "Today");
pub const TRAFFIC_SESSION: Key = key(
    "settings.traffic.period-session",
    "Additional adapter session",
);
pub const TRAFFIC_ALL_TIME: Key = key("settings.traffic.period-all-time", "All time");
pub const TRAFFIC_RECEIVED: Key = key("settings.traffic.received", "Received");
pub const TRAFFIC_SENT: Key = key("settings.traffic.sent", "Sent");
pub const TRAFFIC_NO_DATA: Key = key(
    "settings.traffic.no-data",
    "No data yet — counting starts once traffic flows.",
);
pub const TRAFFIC_ENABLED: Key = key("settings.traffic.master-toggle", "Count traffic");
pub const TRAFFIC_LOOPBACK: Key = key(
    "settings.traffic.count-loopback",
    "Count local (localhost) traffic",
);
pub const TRAFFIC_VIRTUAL: Key = key(
    "settings.traffic.count-virtual",
    "Count virtual (VM) adapters",
);
pub const TRAFFIC_RETENTION: Key = key(
    "settings.traffic.retention-days",
    "Keep daily history for (days)",
);
pub const TRAFFIC_RESET: Key = key("settings.traffic.reset", "Reset statistics");
pub const TRAFFIC_RESET_DONE: Key = key(
    "tui.settings.traffic.reset-done",
    "Traffic statistics were reset.",
);

// ── Updates ──────────────────────────────────────────────────────────────────

pub const VERSION: Key = key("label.version", "Version");
pub const UPDATES_NOTE: Key = key(
    "tui.settings.updates.note",
    "This program does not check for new versions on its own.",
);

// ── Terminal ─────────────────────────────────────────────────────────────────

pub const PREF_PLAIN: Key = key(
    "tui.settings.terminal.plain",
    "Line mode for screen readers",
);
pub const PREF_NO_COLOR: Key = key("tui.settings.terminal.no-color", "No colours");
pub const PREF_ASCII: Key = key(
    "tui.settings.terminal.ascii",
    "Plain characters instead of frame lines",
);
pub const PREF_NOTE: Key = key(
    "tui.settings.terminal.note",
    "These take effect the next time the program starts. The command-line options and the NO_COLOR and NRR_TUI_PLAIN variables still switch them on.",
);
pub const PREF_SAVED: Key = key(
    "tui.settings.terminal.saved",
    "Saved. Takes effect the next time the program starts.",
);
pub const PREF_NO_FILE: Key = key(
    "tui.settings.terminal.no-file",
    "There is no configuration folder for this user, so the setting cannot be saved.",
);
pub const PREF_SAVE_FAILED: Key = key(
    "tui.settings.terminal.save-failed",
    "Could not save the setting: {error}",
);

// ── Service errors (the GUI's `errors.<slug>` wording) ───────────────────────

pub const ERRORS: &[(&str, Key)] = &[
    ("unauthorized", key("errors.unauthorized", "Authentication required")),
    ("forbidden", key("errors.forbidden", "Permission denied")),
    (
        "rules-locked",
        key(
            "errors.rules-locked",
            "Your administrator manages the routing rules on this computer, so they cannot be changed here.",
        ),
    ),
    (
        "security-alert-unacknowledged",
        key(
            "errors.security-alert-unacknowledged",
            "Rules cannot be changed until the security alert in Diagnostics is reviewed and acknowledged.",
        ),
    ),
    ("invalid-version", key("errors.invalid-version", "Service version is incompatible")),
    ("malformed-request", key("errors.malformed-request", "Request was rejected as malformed")),
    ("busy-conflict", key("errors.busy-conflict", "Service is busy with another operation")),
    ("precondition-failed", key("errors.precondition-failed", "Operation precondition not met")),
    ("confirmation-expired", key("errors.confirmation-expired", "Confirmation token expired")),
    ("confirmation-unknown", key("errors.confirmation-unknown", "Confirmation token unknown")),
    ("service-degraded", key("errors.service-degraded", "Service is degraded")),
    ("recovery-required", key("errors.recovery-required", "Service requires user recovery action")),
    (
        "unsupported-operation",
        key(
            "errors.unsupported-operation",
            "The running service is older than this app and does not know this action. Restart the service, or update it, and try again.",
        ),
    ),
    (
        "response-too-large",
        key(
            "errors.response-too-large",
            "The service's answer was too large to send; the change itself may have been applied — refresh before trying again.",
        ),
    ),
    ("internal", key("errors.internal", "Internal service error")),
    ("transport-disconnected", key("errors.transport-disconnected", "Service is offline")),
    ("timeout", key("errors.timeout", "Request timed out")),
    ("bad-response", key("errors.bad-response", "Service returned a malformed response")),
    ("serialization-failed", key("errors.serialization-failed", "Request could not be encoded")),
    ("client-shutdown", key("errors.client-shutdown", "IPC client is shutting down")),
    (
        "uac-declined",
        key(
            "errors.uac-declined",
            "Administrator approval is required to apply this change. The change was not applied.",
        ),
    ),
    (
        "elevation-agent-missing",
        key(
            "errors.elevation-agent-missing",
            "Administrator approval could not be asked for: nothing in this session can show the password prompt. The change was not made.",
        ),
    ),
    (
        "elevation-unavailable",
        key(
            "errors.elevation-unavailable",
            "Administrator approval could not be checked: the system's authorization service did not answer. The change was not made.",
        ),
    ),
];
pub const ERROR_UNKNOWN: Key = key("errors.unknown", "Unknown error");
pub const NEEDS_ELEVATION_WINDOWS: Key = key(
    "errors.terminal-needs-elevation-windows",
    "This needs administrator rights, and nrr-tui does not ask for them. Quit and start it again from a terminal opened with Run as administrator.",
);
pub const NEEDS_ELEVATION_UNIX: Key = key(
    "errors.terminal-needs-elevation-unix",
    "This needs administrator rights, and nrr-tui does not ask for them. Quit and start it again with the command sudo nrr-tui.",
);

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub fn all() -> Vec<Key> {
    let mut keys = vec![
        SECTIONS,
        NOTIFICATIONS,
        ROUTING,
        FAILURE_POLICY,
        SERVICE,
        PRESETS,
        LOGS,
        TRAFFIC,
        UPDATES,
        TERMINAL,
        ON,
        OFF,
        NOT_SET,
        LOADING,
        NO_DATA,
        SAVING,
        SAVED,
        NOT_SAVED,
        LOAD_FAILED,
        OFFLINE,
        NUMBER_RANGE,
        RESULT,
        NEW_VALUE,
        EDIT_HINT,
        PICK_HINT,
        CONFIRM,
        MORE_ABOVE,
        HELP_FOCUS,
        HELP_ENTER,
        HELP_ESC,
        PLAIN_SECTIONS,
        PLAIN_ITEMS,
        PLAIN_BACK,
        PLAIN_PICK,
        PLAIN_EDIT,
        PLAIN_CONFIRM,
        PLAIN_NO_ITEM,
        HIDDEN_HEADING,
        HIDDEN_DESCRIPTION,
        HIDDEN_SHOWN,
        HIDDEN_FOREVER,
        HIDDEN_UNTIL,
        HIDE_SHOW,
        FOR_A_DAY,
        FOR_7_DAYS,
        FOR_30_DAYS,
        FOREVER,
        BLOCK_GROUP,
        MUTE_ALL,
        MUTE_HOST,
        MUTE_APP,
        MUTE_REASON,
        MUTE_UNTIL,
        MUTES_HEADING,
        MUTES_EMPTY,
        ADD_HEADING,
        ADD_DESCRIPTION,
        SCOPE_ALL,
        SCOPE_HOST,
        SCOPE_APP,
        SCOPE_LABEL,
        HOST_FIELD,
        APP_FIELD,
        DURATION,
        UNIT,
        MINUTES,
        HOURS,
        DAYS,
        MUTE_ADDED,
        NEED_TARGET,
        NEED_SUFFIX,
        DELETE,
        CLEAR,
        ADD,
        UNSUPPORTED,
        DEFAULT_ROUTE,
        DEFAULT_ROUTE_NOTE,
        MODE_PREFER_PRIMARY,
        MODE_PREFER_SECONDARY,
        SUBDOMAINS,
        SUBDOMAINS_NOTE,
        APP_TAKEOVER,
        APP_TAKEOVER_NOTE,
        LEAK_TITLE,
        LEAK_OFF,
        LEAK_SITES,
        LEAK_EVERYTHING,
        LEAK_OFF_NOTE,
        LEAK_SITES_NOTE,
        LEAK_EVERYTHING_NOTE,
        PROTOCOLS,
        PROTOCOL_TCP,
        PROTOCOL_UDP,
        PROTOCOL_ICMP,
        PROTOCOL_IGMP,
        PROTOCOL_GRE,
        PROTOCOL_ESP,
        PROTOCOL_LAST,
        ALLOW_DNS,
        ALLOW_DNS_NOTE,
        SHARED_STRICT,
        SHARED_STRICT_NOTE,
        SHARED_IP,
        SHARED_IP_NOTE,
        SHARED_MAJORITY_IP,
        SHARED_MAJORITY_RULES,
        SHARED_ANY,
        ROUTING_METHOD,
        ENFORCEMENT,
        ENFORCEMENT_RESOLVER,
        ENFORCEMENT_REACTIVE,
        ENFORCEMENT_NOTE,
        DNS_FAST_NOTE,
        LIVENESS_NOTE,
        DNS_VIA_SECONDARY,
        DNS_VIA_SECONDARY_NOTE,
        DNS_FAST,
        FAKE_IP,
        FAKE_IP_UDP,
        FAKE_IP_RST,
        LIVENESS,
        LIVENESS_DISABLED,
        LIVENESS_RANGE,
        SECONDS,
        DOH_TITLE,
        DOH_ENABLE,
        DOH_SCOPE,
        DOH_LEAK_ONLY,
        DOH_ALWAYS,
        DOH_AUTO,
        DOH_AUTO_NOTE,
        DOH_AUTO_ON,
        DOH_AUTO_OFF,
        SUFFIX_TITLE,
        SUFFIX_DESCRIPTION,
        SUFFIX_EMPTY,
        SUFFIX_COVERS,
        SUFFIX_OFFERED,
        SUFFIX_FIELD,
        HOSTS_TITLE,
        HOSTS_BYPASS,
        LOCAL_TITLE,
        FWD_TITLE,
        FWD_CHOICE,
        FWD_NOTE,
        FWD_AS_COMPUTER,
        FWD_UNPROTECTED,
        FWD_UNANSWERED,
        LOCAL_AUTO,
        LOCAL_EMPTY,
        LOCAL_UNDECIDED,
        LOCAL_TOO_WIDE,
        LOCAL_NAMES_RULE,
        LOCAL_KIND_MANUAL,
        LOCAL_KIND_MAIN,
        LOCAL_KIND_VM,
        LOCAL_FIELD,
        LOCAL_NOT_PRIVATE,
        LOCAL_MALFORMED,
        NEED_NETWORK,
        SHORT_TITLE,
        SHORT_NOTE,
        SHORT_ENABLE,
        SHORT_FIELD,
        EXTERNAL_CHECK,
        EXTERNAL_CHECK_NOTE,
        AUTO_TITLE,
        PROBE_AUTO,
        PROBE_TIMEOUT,
        PROBE_TARGETS,
        PROBE_REPEAT,
        PROBE_RESET,
        AUTO_MODE,
        AUTO_OFF,
        AUTO_SUGGEST,
        AUTO_AUTO,
        AUTO_EAGER,
        SYSTEM_TITLE,
        RULE_LOCK,
        SERVICE_DRIVEN,
        STOP_PERSIST,
        POLICY_DESCRIPTION,
        POLICY_BEST_EFFORT,
        POLICY_BEST_EFFORT_NOTE,
        POLICY_ALL,
        POLICY_ALL_NOTE,
        POLICY_PREFLIGHT,
        POLICY_PREFLIGHT_NOTE,
        POLICY_ELEVATION,
        SERVICE_STATE,
        SERVICE_START_MODE,
        RUN_RUNNING,
        RUN_STOPPED,
        RUN_STARTING,
        RUN_STOPPING,
        RUN_NOT_INSTALLED,
        RUN_UNKNOWN,
        MODE_WITH_SYSTEM,
        MODE_ON_LAUNCH,
        SERVICE_START,
        SERVICE_STOP,
        SERVICE_RESTART,
        RULES_PAUSE_TITLE,
        RULES_PAUSE_HINT,
        ROLLBACK_TITLE,
        ROLLBACK_LOOKUP,
        ROLLBACK_READY,
        ROLLBACK_NONE,
        ROLLBACK_RUN,
        ROLLBACK_FAILED,
        ROLLBACK_DONE,
        ROLLBACK_SUBMITTED,
        SAFE_DISABLE_NOTE,
        SAFE_DISABLE_REASON,
        SAFE_DISABLE_RUN,
        SAFE_DISABLE_NEED_REASON,
        SAFE_DISABLE_DONE,
        SERVICE_FIX_UNINSTALL,
        SERVICE_FIX_REINSTALL,
        SERVICE_FIX_MODE,
        SERVICE_NOTE,
        SERVICE_DONE,
        SERVICE_QUERY_FAILED,
        SERVICE_NO_MANAGER,
        EXPORT_DESCRIPTION,
        EXPORT_PATH,
        EXPORT_RUN,
        EXPORT_NEED_PATH,
        EXPORT_EXISTS,
        EXPORT_DONE,
        EXPORT_WRITE_FAILED,
        RULES_NOTE,
        RETENTION_TITLE,
        LOGS_AGE,
        LOGS_SIZE,
        AUDIT_AGE,
        AUDIT_SIZE,
        DAYS_UNIT,
        MB_UNIT,
        VERBOSE,
        VERBOSE_OFF,
        VERBOSE_HOUR,
        VERBOSE_FOUR,
        VERBOSE_RESTART,
        TRACE_LOG,
        TRACE_OFF,
        TRACE_HOUR,
        TRACE_FOUR,
        TRACE_RESTART,
        WINDOW_UNTIL,
        CLEAR_LOGS,
        LOGS_CLEARED,
        HISTORY_TITLE,
        HISTORY_NOTE,
        HISTORY_KEEP,
        HISTORY_DAYS,
        HISTORY_CLEAR,
        HISTORY_CLEARED,
        HISTORY_UNAVAILABLE,
        STORAGE_TITLE,
        STORAGE_STATE,
        STORAGE_CACHE,
        STORAGE_LOGS,
        STORAGE_AUDIT,
        STORAGE_TOTAL,
        REVISIONS_TITLE,
        REVISIONS_NOTE,
        SUPERSEDED_DAYS,
        SUPERSEDED_COUNT,
        REJECTED_DAYS,
        ROLLEDBACK_DAYS,
        ROLLEDBACK_COUNT,
        PIN_LKG,
        PIN_LKG_NOTE,
        REVISIONS_RESET,
        LAST_CLEANUP,
        LAST_CLEANUP_NEVER,
        SUPERSEDED_DAYS_NOTE,
        SUPERSEDED_COUNT_NOTE,
        REJECTED_DAYS_NOTE,
        ROLLEDBACK_DAYS_NOTE,
        ROLLEDBACK_COUNT_NOTE,
        TRAFFIC_NOTE,
        TRAFFIC_TODAY,
        TRAFFIC_SESSION,
        TRAFFIC_ALL_TIME,
        TRAFFIC_RECEIVED,
        TRAFFIC_SENT,
        TRAFFIC_NO_DATA,
        TRAFFIC_ENABLED,
        TRAFFIC_LOOPBACK,
        TRAFFIC_VIRTUAL,
        TRAFFIC_RETENTION,
        TRAFFIC_RESET,
        TRAFFIC_RESET_DONE,
        VERSION,
        UPDATES_NOTE,
        PREF_PLAIN,
        PREF_NO_COLOR,
        PREF_ASCII,
        PREF_NOTE,
        PREF_SAVED,
        PREF_NO_FILE,
        PREF_SAVE_FAILED,
        ERROR_UNKNOWN,
        NEEDS_ELEVATION_WINDOWS,
        NEEDS_ELEVATION_UNIX,
    ];
    keys.extend(ERRORS.iter().map(|(_, k)| *k));
    keys
}
