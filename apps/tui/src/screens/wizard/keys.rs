//! The setup's locale keys: the GUI's first-run wording wherever it has one,
//! `tui.wizard.*` only for what the terminal says alone.

use crate::i18n::{key, Key};

pub const TITLE: Key = key("dialog.first-run-wizard.title", "Welcome to NetRuleRouter");
pub const STEP: Key = key("tui.wizard.step", "Step {number} of {total}: {name}");
pub const ANSWERS_TITLE: Key = key("tui.wizard.answers-title", "Your answer");

pub const LANGUAGE_TITLE: Key = key("settings.group.language", "Language");
pub const LANGUAGE_NOTE: Key = key(
    "tui.wizard.language-note",
    "The language of this terminal session. To start in it every time, run the program with --lang.",
);
pub const LICENCE_TITLE: Key = key("dialog.eula.title", "License agreement");
pub const LICENCE_ACCEPT: Key = key("dialog.eula.accept", "Accept and continue");
pub const LICENCE_DECLINE: Key = key("dialog.eula.decline", "Decline and exit");
pub const LICENCE_PAGE: Key = key("tui.wizard.licence-page", "Part {number} of {total}");
pub const LICENCE_NEXT: Key = key("tui.wizard.licence-next", "Read on");
pub const LICENCE_PREVIOUS: Key = key("tui.wizard.licence-previous", "Previous part");
pub const LICENCE_NOT_SAVED: Key = key(
    "tui.wizard.licence-not-saved",
    "The acceptance could not be saved, so you will be asked again next time.",
);
pub const SHEET_NOTE: Key = key(
    "tui.wizard.sheet-note",
    "Answers supplied before the first start are already chosen below; change any of them.",
);
pub const CURRENT: Key = key("tui.wizard.current", "{name} (current)");

pub const PRIMARY_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.primary-adapter-description",
    "The connection everything travels by default. Until you name it, your rules are not applied.",
);
pub const PRIMARY_ASSIGNED: Key = key(
    "dialog.first-run-wizard.primary-adapter-assigned",
    "Main connection: {name}. You can change it later in Connections.",
);
pub const NO_ADAPTERS: Key = key(
    "dialog.first-run-wizard.primary-adapter-unavailable",
    "No connections to choose from yet — the background service reports them once it is running. You can set this later in Connections.",
);
pub const SECONDARY_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.secondary-adapter-description",
    "The connection your rules send traffic to — a VPN or a second network. Rules that name it do nothing until it is assigned.",
);
pub const SECONDARY_ASSIGNED: Key = key(
    "dialog.first-run-wizard.secondary-adapter-assigned",
    "Additional connection: {name}. You can change it later in Connections.",
);
pub const SECONDARY_ASSIGNED_DOWN: Key = key(
    "dialog.first-run-wizard.secondary-adapter-assigned-down",
    "Additional connection: {name} — chosen, not connected yet. Your rules use it as soon as it connects. You can change it later in Connections.",
);
pub const SECONDARY_LATER: Key = key(
    "dialog.first-run-wizard.secondary-adapter-later",
    "I will choose it later",
);
pub const SECONDARY_DEFERRED: Key = key(
    "dialog.first-run-wizard.secondary-adapter-deferred",
    "You can assign it any time in Connections. Until then, with leak protection on, the traffic your rules send that way is blocked instead of leaking to the main connection.",
);
pub const VPN_HINT: Key = key(
    "dialog.first-run-wizard.secondary-adapter-vpn-hint",
    "{name} looks like your VPN. We recommend making it the additional connection: choose it above and press \"Set as additional\".",
);
pub const VPN_NONE: Key = key(
    "dialog.first-run-wizard.secondary-adapter-vpn-none",
    "Not sure which connection is your VPN? Start your VPN and connect: the program notices the new connection by itself.",
);
pub const VPN_INSTALLED: Key = key(
    "dialog.first-run-wizard.secondary-adapter-vpn-installed",
    "VPN found on this computer: {names}. Not sure which connection is your VPN? Start it and connect: the program notices the new connection by itself.",
);
pub const IDLE_VPN: Key = key(
    "dialog.first-run-wizard.secondary-adapter-idle-vpn",
    "{name} (VPN, not connected now)",
);
pub const IDLE_VPN_PROGRAM: Key = key(
    "dialog.first-run-wizard.secondary-adapter-idle-vpn-program",
    "{name} (VPN {program}, not connected now)",
);
pub const IDLE_VPN_LATER: Key = key(
    "dialog.first-run-wizard.secondary-adapter-idle-vpn-later",
    "Connect the VPN later: the program starts sending sites through it as soon as it is on.",
);
pub const START_VPN_FIRST: Key = key(
    "dialog.first-run-wizard.secondary-adapter-start-vpn-first",
    "Your VPN may use any of several connections on this computer, and while it is off there is no telling which one. Turn the VPN on — the wizard will see it and pick it.",
);
pub const START_VPN_FIRST_PROGRAM: Key = key(
    "dialog.first-run-wizard.secondary-adapter-start-vpn-first-program",
    "{program} may use any of several connections on this computer, and while the VPN is off there is no telling which one. Turn the VPN on — the wizard will see it and pick it.",
);
pub const JUST_CONNECTED: Key = key(
    "dialog.first-run-wizard.secondary-adapter-just-connected",
    "Just connected: {name} — probably your VPN.",
);
pub const CHANGE: Key = key("action.change", "Change...");
pub const RULES_WAIT_FOR_ALERT_TITLE: Key = key(
    "dialog.rules-wait-for-alert.title",
    "The rules are not loaded yet",
);
pub const RULES_WAIT_FOR_ALERT: Key = key(
    "status.rule-set-waits-for-alert",
    "The rule set «{name}» is not loaded yet: a security alert needs your confirmation first, then it loads by itself.",
);
pub const REFRESH: Key = key("action.refresh-interfaces", "Refresh connections");
pub const SHOW_ALL_ADAPTERS: Key = key(
    "interfaces.toggle.show-unavailable-adapters",
    "Show unavailable adapters",
);

pub const PROTECTION_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.protection-description",
    "Recommended for everyone. Each of these can be changed later in Settings.",
);
pub const LEAK_PROTECTION: Key = key("settings.routing.kill-switch.title", "Leak protection");
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
    "What your rules send through the additional connection never goes out the main one while strict protection is on, as it is by default. Everything else keeps working, though a few ordinary sites may not open until the additional connection is back.",
);
pub const LEAK_EVERYTHING_NOTE: Key = key(
    "settings.routing.leak-protection.note-everything",
    "Nothing leaves except through the additional connection, your local network and what your rules send over the main connection. If the additional connection drops, the internet waits until it returns.",
);
// The window's confirmation text, shown here as a note under the choice.
pub const LEAK_HOLDS_NOW: Key = key(
    "dialog.leak-holds-now.body",
    "With leak protection set to Everything, traffic is held right away: the internet stops until the additional connection returns.",
);
pub const SITE_NOTICE_NOTE: Key = key(
    "dialog.first-run-wizard.site-notice-note",
    "Even with the tray closed, NetRuleRouter tells you when a site you open does not open over the main connection. You can turn this off in Settings, Notifications.",
);
pub const DOH_LOCKDOWN: Key = key(
    "dialog.first-run-wizard.protection-doh-lockdown",
    "Keep browsers from resolving routed sites past NetRuleRouter",
);
pub const FAKE_IP: Key = key(
    "dialog.first-run-wizard.protection-fake-ip",
    "Route sites by name, so an address shared with another site is not dragged along (uses a virtual network adapter; on Windows this loads its Wintun driver)",
);
pub const DIAGNOSTIC_LOGS: Key = key(
    "dialog.first-run-wizard.protection-diagnostic-logs",
    "Write detailed diagnostic logs (only needed to report a problem)",
);
pub const LOGS_ONE_HOUR: Key = key(
    "settings.diagnostics.service-stability.verbose.option-one-hour",
    "Verbose for 1 hour",
);
pub const LOGS_FOUR_HOURS: Key = key(
    "settings.diagnostics.service-stability.verbose.option-four-hours",
    "Verbose for 4 hours",
);
pub const LOGS_UNTIL_RESTART: Key = key(
    "settings.diagnostics.service-stability.verbose.option-until-restart",
    "Verbose until the service restarts",
);
pub const NEEDS_ADMIN_TITLE: Key = key(
    "notifications.first-run-needs-admin.title",
    "A setup answer needs an administrator",
);
pub const NEEDS_ADMIN_BODY: Key = key(
    "notifications.first-run-needs-admin.body",
    "“{setting}” applies to the whole computer, so only an administrator can turn it on. It stays off for now; an administrator can switch it on in the routing settings.",
);
pub const FAKE_IP_SETTING: Key = key(
    "settings.routing.fake-ip.label",
    "Route sites over virtual addresses (fake-IP)",
);
pub const STABILITY_FAILED_TITLE: Key = key(
    "tui.wizard.stability-failed-title",
    "A setup answer was not saved",
);
pub const STABILITY_FAILED: Key = key(
    "status.system-routing-failed",
    "Could not update the setting: ",
);
pub const SETTING: Key = key("tui.wizard.setting", "{name}: {value}");
pub const YES: Key = key("label.yes", "Yes");
pub const NO: Key = key("label.no", "No");
pub const PROTECTION_SAVED: Key = key("tui.wizard.protection-saved", "Protection settings saved.");
pub const PROTECTION_FAILED: Key = key(
    "status.kill-switch-enabled-failed",
    "Could not update leak protection: ",
);

pub const RULES_STEP: Key = key("dialog.first-run-wizard.step-rules", "Starting rules");
pub const OPTIONS_STEP: Key = key(
    "dialog.first-run-wizard.step-options",
    "Protection and options",
);
pub const SUMMARY_STEP: Key = key("dialog.first-run-wizard.step-review", "Ready to finish");
pub const CHOOSE_NOW: Key = key(
    "dialog.first-run-wizard.primary-adapter-placeholder",
    "Choose a connection",
);
pub const REVIEW_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.review-description",
    "Check your choices. Finish applies them; Back returns to any step. Each of them can be changed later.",
);
pub const REVIEW_PRIMARY: Key = key(
    "dialog.first-run-wizard.review-primary",
    "Main connection: {name}",
);
pub const REVIEW_NO_PRIMARY: Key = key(
    "dialog.first-run-wizard.review-no-primary",
    "Your rules are not applied until a main connection is chosen. You can choose it later in Connections.",
);
pub const REVIEW_SECONDARY: Key = key(
    "dialog.first-run-wizard.review-secondary",
    "Additional connection: {name}",
);
pub const REVIEW_RULES: Key = key(
    "dialog.first-run-wizard.review-rules",
    "Starting rules: {name}",
);
pub const REVIEW_RULES_CURRENT: Key = key(
    "dialog.first-run-wizard.review-rules-current",
    "the rules already applied to you",
);
pub const RULE_SET_EMPTY_NAME: Key = key(
    "dialog.first-run-wizard.rule-set-empty-name",
    "none, an empty start",
);
pub const REVIEW_LEAK_IN_FORCE: Key = key(
    "dialog.first-run-wizard.review-leak-in-force",
    "Leak protection: {name} — in force.",
);
pub const REVIEW_LEAK_NOT_YET: Key = key(
    "dialog.first-run-wizard.review-leak-not-yet",
    "Leak protection: {name} — not in force yet.",
);
pub const REVIEW_LATER: Key = key("dialog.first-run-wizard.review-later", "later");
pub const REVIEW_NOT_CHOSEN: Key = key("dialog.first-run-wizard.review-not-chosen", "not chosen");
pub const RULES_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.description",
    "Choose which rules to start with. You can change this later in Rules or in Settings → Rules and settings files.",
);
pub const COUNTRY_PRESET: Key = key(
    "dialog.first-run-wizard.option-country-preset",
    "Use the rule set for your region ({country})",
);
pub const COUNTRY_PRESET_ABROAD: Key = key(
    "dialog.first-run-wizard.option-country-preset-abroad",
    "Use the access rule set ({country})",
);
pub const NO_COUNTRY_PRESET: Key = key(
    "dialog.first-run-wizard.option-country-not-available",
    "No ready-made rule set is bundled for your region — pick a different option.",
);
pub const OTHER_COUNTRY: Key = key("tui.wizard.other-country", "Another country's preset");
pub const COUNTRY_PRESET_HINT: Key = key(
    "dialog.first-run-wizard.option-country-preset-description",
    "Recommended for {country}: the ready-made rule set for your region, taken from the system's region setting. You can change it afterwards.",
);
pub const OTHER_COUNTRIES_HINT: Key = key(
    "dialog.first-run-wizard.other-countries-description",
    "When the region was detected wrong, or you need the sites of another country to take the additional connection.",
);
pub const RULE_SET_NONE: Key = key(
    "dialog.first-run-wizard.rule-set-none",
    "Choose a rule set, or \"Start empty\", to go on.",
);
pub const OPEN_FILES: Key = key(
    "dialog.first-run-wizard.option-open-file",
    "Open my rules...",
);
pub const OPEN_FILES_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.option-open-file-description",
    "Choose one or two rules files (.txt) — one for each connection. One of them can stay without a file.",
);
pub const START_EMPTY: Key = key("dialog.first-run-wizard.option-start-empty", "Start empty");
pub const PRIMARY_FILE: Key = key(
    "dialog.first-run-wizard.primary-file-label",
    "Main connection:",
);
pub const SECONDARY_FILE: Key = key(
    "dialog.first-run-wizard.secondary-file-label",
    "Additional connection:",
);
pub const NO_FILE: Key = key(
    "dialog.first-run-wizard.no-file-selected",
    "(no file selected)",
);
pub const IMPORT_FILES: Key = key(
    "dialog.first-run-wizard.import-button",
    "Use the selected files",
);
pub const PATH_PROMPT: Key = key(
    "tui.wizard.path-prompt",
    "Type the full path to the file, then press Enter. An empty line leaves this connection without a file.",
);
pub const TYPING: Key = key(
    "tui.wizard.typing",
    "Typing the path: Enter keeps it, Esc leaves it as it was.",
);
pub const FILE_UNREADABLE: Key = key(
    "tui.wizard.file-unreadable",
    "Could not read {path}: {error}",
);
pub const FILE_TOO_LARGE: Key = key(
    "tui.wizard.file-too-large",
    "{path} is larger than 1 MiB. The service refuses a rules file that large.",
);
pub const FILE_NOT_TEXT: Key = key("tui.wizard.file-not-text", "{path} is not UTF-8 text.");
pub const FILE_RULES: Key = key("tui.wizard.file-rules", "{route} {file}: {count} rules");

pub const REVIEW_COUNTS: Key = key(
    "dialog.review-diff.summary-rule-counts",
    "Added: {added} · Removed: {removed} · Changed: {changed}",
);
pub const NOTHING_TO_APPLY: Key = key(
    "dialog.nothing-to-apply.body",
    "Nothing to apply: the rules on screen are already in use.",
);
pub const PREVIEWING: Key = key(
    "tui.wizard.previewing",
    "Asking the service what these rules would change…",
);
pub const SAVING: Key = key("tui.interfaces.saving", "Saving…");
pub const IMPORT_FAILED: Key = key("status.preset-import-failed", "Could not load the rules: ");
pub const NEEDS_SERVICE: Key = key(
    "tui.wizard.needs-service",
    "The background service is not connected, so this cannot be saved yet. The setup can continue once it is.",
);

pub const NEXT: Key = key("action.next", "Next");
pub const FINISH: Key = key("action.finish", "Finish");
pub const BACK: Key = key("action.back", "Back");
pub const CLOSE: Key = key("tui.wizard.close", "Close the setup");

pub const HELP_CHOOSE: Key = key(
    "tui.wizard.help-choose",
    "Tab, then Up and Down: move between the answers; Enter: take the marked one",
);
pub const HELP_TYPE: Key = key(
    "tui.wizard.help-type",
    "While typing a path: Enter keeps it, Esc leaves it as it was",
);
pub const PLAIN_NUMBER: Key = key(
    "tui.wizard.plain-number",
    "A number: take that answer. To leave the setup, take the answer that closes it.",
);
pub const PLAIN_PROMPT: Key = key(
    "tui.wizard.plain-prompt",
    "Type the number of your answer and press Enter.",
);

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    TITLE,
    STEP,
    ANSWERS_TITLE,
    LANGUAGE_TITLE,
    LANGUAGE_NOTE,
    LICENCE_TITLE,
    LICENCE_ACCEPT,
    LICENCE_DECLINE,
    LICENCE_PAGE,
    LICENCE_NEXT,
    LICENCE_PREVIOUS,
    LICENCE_NOT_SAVED,
    SHEET_NOTE,
    CURRENT,
    PRIMARY_DESCRIPTION,
    PRIMARY_ASSIGNED,
    NO_ADAPTERS,
    SECONDARY_DESCRIPTION,
    SECONDARY_ASSIGNED,
    SECONDARY_ASSIGNED_DOWN,
    SECONDARY_LATER,
    SECONDARY_DEFERRED,
    VPN_HINT,
    VPN_NONE,
    VPN_INSTALLED,
    IDLE_VPN,
    IDLE_VPN_PROGRAM,
    IDLE_VPN_LATER,
    START_VPN_FIRST,
    START_VPN_FIRST_PROGRAM,
    JUST_CONNECTED,
    CHANGE,
    RULES_WAIT_FOR_ALERT_TITLE,
    RULES_WAIT_FOR_ALERT,
    COUNTRY_PRESET_HINT,
    OTHER_COUNTRIES_HINT,
    RULE_SET_NONE,
    REFRESH,
    SHOW_ALL_ADAPTERS,
    PROTECTION_DESCRIPTION,
    LEAK_PROTECTION,
    LEAK_OFF,
    LEAK_SITES,
    LEAK_EVERYTHING,
    LEAK_OFF_NOTE,
    LEAK_SITES_NOTE,
    LEAK_EVERYTHING_NOTE,
    LEAK_HOLDS_NOW,
    SITE_NOTICE_NOTE,
    DOH_LOCKDOWN,
    FAKE_IP,
    DIAGNOSTIC_LOGS,
    LOGS_ONE_HOUR,
    LOGS_FOUR_HOURS,
    LOGS_UNTIL_RESTART,
    NEEDS_ADMIN_TITLE,
    NEEDS_ADMIN_BODY,
    FAKE_IP_SETTING,
    STABILITY_FAILED_TITLE,
    STABILITY_FAILED,
    SETTING,
    YES,
    NO,
    PROTECTION_SAVED,
    PROTECTION_FAILED,
    RULES_STEP,
    OPTIONS_STEP,
    SUMMARY_STEP,
    CHOOSE_NOW,
    REVIEW_DESCRIPTION,
    REVIEW_PRIMARY,
    REVIEW_NO_PRIMARY,
    REVIEW_SECONDARY,
    REVIEW_RULES,
    REVIEW_RULES_CURRENT,
    RULE_SET_EMPTY_NAME,
    REVIEW_LEAK_IN_FORCE,
    REVIEW_LEAK_NOT_YET,
    REVIEW_LATER,
    REVIEW_NOT_CHOSEN,
    RULES_DESCRIPTION,
    COUNTRY_PRESET,
    COUNTRY_PRESET_ABROAD,
    NO_COUNTRY_PRESET,
    OTHER_COUNTRY,
    OPEN_FILES,
    OPEN_FILES_DESCRIPTION,
    START_EMPTY,
    PRIMARY_FILE,
    SECONDARY_FILE,
    NO_FILE,
    IMPORT_FILES,
    PATH_PROMPT,
    TYPING,
    FILE_UNREADABLE,
    FILE_TOO_LARGE,
    FILE_NOT_TEXT,
    FILE_RULES,
    REVIEW_COUNTS,
    NOTHING_TO_APPLY,
    PREVIEWING,
    SAVING,
    IMPORT_FAILED,
    NEEDS_SERVICE,
    NEXT,
    FINISH,
    BACK,
    CLOSE,
    HELP_CHOOSE,
    HELP_TYPE,
    PLAIN_NUMBER,
    PLAIN_PROMPT,
];
