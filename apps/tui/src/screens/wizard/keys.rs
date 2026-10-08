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
pub const CURRENT: Key = key("tui.wizard.current", "{name} (current)");

pub const PRIMARY_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.primary-adapter-description",
    "The connection everything travels by default. Until you name it, your rules are not applied.",
);
pub const PRIMARY_ASSIGNED: Key = key(
    "dialog.first-run-wizard.primary-adapter-assigned",
    "Main connection: {name}. You can change it later in Interfaces and routes.",
);
pub const NO_ADAPTERS: Key = key(
    "dialog.first-run-wizard.primary-adapter-unavailable",
    "No connections to choose from yet — the background service reports them once it is running. You can set this later in Interfaces and routes.",
);
pub const SECONDARY_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.secondary-adapter-description",
    "The connection your rules send traffic to — a VPN or a second network. Rules that name it do nothing until it is assigned.",
);
pub const SECONDARY_ASSIGNED: Key = key(
    "dialog.first-run-wizard.secondary-adapter-assigned",
    "Additional connection: {name}. You can change it later in Interfaces and routes.",
);
pub const SECONDARY_LATER: Key = key(
    "dialog.first-run-wizard.secondary-adapter-later",
    "I will choose it later",
);
pub const SECONDARY_DEFERRED: Key = key(
    "dialog.first-run-wizard.secondary-adapter-deferred",
    "You can assign it any time in Interfaces and routes. Until then, with leak protection on, the traffic your rules send that way is blocked instead of leaking to the main connection.",
);
pub const VPN_HINT: Key = key(
    "dialog.first-run-wizard.secondary-adapter-vpn-hint",
    "{name} looks like a VPN connection — choose it above to make it the additional route.",
);
pub const VPN_NONE: Key = key(
    "dialog.first-run-wizard.secondary-adapter-vpn-none",
    "No VPN connection found yet. Install your VPN and connect it, then come back here.",
);
pub const REFRESH: Key = key("action.refresh-interfaces", "Refresh interfaces");

pub const PROTECTION_TITLE: Key = key("dialog.first-run-wizard.protection-title", "Protection");
pub const PROTECTION_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.protection-description",
    "Recommended for everyone. Each of these can be changed later in Settings.",
);
pub const KILL_SWITCH: Key = key(
    "dialog.first-run-wizard.protection-kill-switch",
    "Block routed traffic when the additional route is down",
);
pub const DOH_LOCKDOWN: Key = key(
    "dialog.first-run-wizard.protection-doh-lockdown",
    "Keep browsers from resolving routed sites past NetRuleRouter",
);
pub const SETTING: Key = key("tui.wizard.setting", "{name}: {value}");
pub const YES: Key = key("label.yes", "Yes");
pub const NO: Key = key("label.no", "No");
pub const PROTECTION_SAVED: Key = key("tui.wizard.protection-saved", "Protection settings saved.");
pub const PROTECTION_FAILED: Key = key(
    "status.kill-switch-enabled-failed",
    "Could not update leak protection: ",
);

pub const RULES_TITLE: Key = key("tui.wizard.rules-title", "Starting rules");
pub const RULES_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.description",
    "Choose how to populate your initial rule set. You can change it later from the Rules toolbar or in Settings → Presets and settings.",
);
pub const COUNTRY_PRESET: Key = key(
    "dialog.first-run-wizard.option-country-preset",
    "Load country preset ({country})",
);
pub const COUNTRY_PRESET_ABROAD: Key = key(
    "dialog.first-run-wizard.option-country-preset-abroad",
    "Load access preset ({country})",
);
pub const NO_COUNTRY_PRESET: Key = key(
    "dialog.first-run-wizard.option-country-not-available",
    "No country preset is bundled for your region — pick a different option.",
);
pub const OTHER_COUNTRY: Key = key("tui.wizard.other-country", "Another country's preset");
pub const OPEN_FILES: Key = key(
    "dialog.first-run-wizard.option-open-file",
    "Open my rules...",
);
pub const OPEN_FILES_DESCRIPTION: Key = key(
    "dialog.first-run-wizard.option-open-file-description",
    "Choose one or two preset .txt files — one for each route. Leave a route empty to start it blank.",
);
pub const START_EMPTY: Key = key("dialog.first-run-wizard.option-start-empty", "Start empty");
pub const PRIMARY_FILE: Key = key("dialog.first-run-wizard.primary-file-label", "Main route:");
pub const SECONDARY_FILE: Key = key(
    "dialog.first-run-wizard.secondary-file-label",
    "Additional route:",
);
pub const NO_FILE: Key = key(
    "dialog.first-run-wizard.no-file-selected",
    "(no file selected)",
);
pub const IMPORT_FILES: Key = key(
    "dialog.first-run-wizard.import-button",
    "Import selected files",
);
pub const PATH_PROMPT: Key = key(
    "tui.wizard.path-prompt",
    "Type the full path to the file, then press Enter. An empty line leaves this route without a file.",
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
    "There are no changes to apply — the current rules already match what is active.",
);
pub const PREVIEWING: Key = key(
    "tui.wizard.previewing",
    "Asking the service what these rules would change…",
);
pub const APPLYING: Key = key("tui.wizard.applying", "Applying the rules…");
pub const SAVING: Key = key("tui.interfaces.saving", "Saving…");
pub const IMPORT_FAILED: Key = key("status.preset-import-failed", "Failed to import preset: ");
pub const NEEDS_SERVICE: Key = key(
    "tui.wizard.needs-service",
    "The background service is not connected, so this cannot be saved yet. The setup can continue once it is.",
);

pub const NEXT: Key = key("action.next", "Next");
pub const BACK: Key = key("action.back", "Back");
pub const APPLY: Key = key("action.apply", "Apply");
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
    CURRENT,
    PRIMARY_DESCRIPTION,
    PRIMARY_ASSIGNED,
    NO_ADAPTERS,
    SECONDARY_DESCRIPTION,
    SECONDARY_ASSIGNED,
    SECONDARY_LATER,
    SECONDARY_DEFERRED,
    VPN_HINT,
    VPN_NONE,
    REFRESH,
    PROTECTION_TITLE,
    PROTECTION_DESCRIPTION,
    KILL_SWITCH,
    DOH_LOCKDOWN,
    SETTING,
    YES,
    NO,
    PROTECTION_SAVED,
    PROTECTION_FAILED,
    RULES_TITLE,
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
    APPLYING,
    SAVING,
    IMPORT_FAILED,
    NEEDS_SERVICE,
    NEXT,
    BACK,
    APPLY,
    CLOSE,
    HELP_CHOOSE,
    HELP_TYPE,
    PLAIN_NUMBER,
    PLAIN_PROMPT,
];
