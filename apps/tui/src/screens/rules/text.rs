//! The Rules screen's words. The GUI's own keys where the GUI says the same
//! thing; `tui.rules.*` only for what exists in the terminal alone.

use crate::i18n::{key, Key};

// ── Shared with the GUI ──────────────────────────────────────────────────────

pub const ROUTE_PRIMARY: Key = key("label.primary", "Primary");
pub const ROUTE_SECONDARY: Key = key("label.secondary", "Additional");
pub const ROUTE_BLOCK: Key = key("label.block", "Block");
pub const ROUTE_VERIFY: Key = key(
    "label.verify-primary",
    "Primary first, additional if unreachable",
);
pub const ROUTE_ALL: Key = key("rules.filter.route.all", "All routes");
pub const ROUTE_FILTER: Key = key("rules.filter.route.label", "Route");
pub const SEARCH: Key = key("action.search", "Search");
pub const DISABLED: Key = key("label.disabled", "disabled");
pub const AUTO_ORIGIN: Key = key("rules.auto-origin.badge", "Added for you");
pub const VALIDATION_ERROR: Key = key("rules.validation.error", "Error — rule is inactive");
pub const VALIDATION_WARNING: Key = key("rules.validation.warning", "Valid with warnings");
pub const EMPTY_TITLE: Key = key("rules.empty.title", "No rules yet");
pub const EMPTY_BODY: Key = key(
    "rules.empty.body",
    "Add your first routing rule to start sending traffic through the additional route.",
);
pub const NO_DATA: Key = key("diag.status.no-data", "No data from the service yet");

pub const FORM_ADD: Key = key("dialog.rule.add", "Add");
pub const FORM_EDIT: Key = key("dialog.rule.edit", "Edit");
pub const FIELD_TYPE: Key = key("label.rule-type", "Rule type");
pub const FIELD_VALUE: Key = key("label.match-value", "Match value");
pub const FIELD_ROUTE: Key = key("label.target-route", "Target route");
pub const FIELD_COMMENT: Key = key("label.comment", "Comment");
pub const ENABLED_ON: Key = key(
    "dialog.rule.enabled-on",
    "Rule is enabled (applied to routing)",
);
pub const ENABLED_OFF: Key = key(
    "dialog.rule.enabled-off",
    "Rule is disabled (kept in the file, not applied)",
);
pub const VERIFY_HINT: Key = key(
    "dialog.rule.route-verify-hint",
    "Opens through the primary route first. Once NetRuleRouter confirms the primary route cannot reach the site, the rule moves to the additional route by itself.",
);
pub const DUPLICATE: Key = key(
    "dialog.rule.duplicate-body",
    "A rule with the same type, value, and target route already exists ({id}). Open the existing rule to change it, or cancel to keep editing the new one.",
);
pub const OPEN_EXISTING: Key = key("dialog.rule.duplicate-open-existing", "Open existing");

pub const RULE_ADDED: Key = key("status.rule-added", "Rule added");
pub const RULE_ADDED_DISABLED: Key = key(
    "status.rule-added-disabled",
    "Rule added but disabled — it will not affect routing until you enable it.",
);
pub const RULE_UPDATED: Key = key("status.rule-updated", "Rule updated");
pub const RULE_REMOVED: Key = key("status.rule-removed", "Rule removed");
pub const LIMIT_REACHED: Key = key(
    "status.rules-limit-reached",
    "Up to {max} active rules are supported.",
);
pub const DELETE_TITLE: Key = key("rules.action.delete-single-title", "Delete this rule?");
pub const DELETE_CONFIRM: Key = key("rules.action.delete-confirm", "Delete");
pub const RELOAD: Key = key("rules.action.show-service-rules", "Show service rules");
pub const RELOAD_HINT: Key = key(
    "rules.action.show-service-rules-tooltip",
    "Load the rules the service is currently enforcing into the table.",
);
pub const CANCEL: Key = key("action.cancel", "Cancel");

pub const REVIEW_TITLE: Key = key("dialog.review-diff.title", "Review changes");
pub const REVIEW_APPLY: Key = key("dialog.review-diff.apply", "Apply changes");
pub const REVIEW_EMPTY: Key = key(
    "dialog.review-diff.summary-empty",
    "No structural changes detected.",
);
pub const REVIEW_UNCHANGED: Key = key(
    "dialog.review-diff.summary-rules-unchanged",
    "The rule list does not change; routing is rebuilt from it.",
);
pub const REVIEW_COUNTS: Key = key(
    "dialog.review-diff.summary-rule-counts",
    "Added: {added} · Removed: {removed} · Changed: {changed}",
);
pub const REVIEW_ADDED: Key = key("dialog.review-diff.column-added", "Added");
pub const REVIEW_REMOVED: Key = key("dialog.review-diff.column-removed", "Removed");
pub const REVIEW_CHANGED: Key = key(
    "dialog.review-diff.column-modified",
    "Modified or retargeted",
);
pub const REVIEW_NONE: Key = key("dialog.review-diff.column-empty", "(none)");
pub const RISK_HEADING: Key = key("dialog.review-diff.risk-heading", "Risk assessment");
pub const SIGNALS_HEADING: Key = key("dialog.review-diff.signals-heading", "Detected signals");
pub const DUPLICATES_HEADING: Key = key(
    "dialog.review-diff.duplicates-heading",
    "Rules written into both routes",
);
pub const UNDERSTAND: Key = key(
    "dialog.confirm-activate.checkbox-understand",
    "I understand the risk and want to proceed",
);
pub const PROVENANCE_EDIT: Key = key(
    "dialog.review-diff.provenance.gui-rules-edit",
    "Source: rules edited in this app.",
);
pub const PROVENANCE_IMPORT: Key = key(
    "dialog.review-diff.provenance.preset-import",
    "Source: an imported rules file.",
);
pub const INVALID_VALUES: Key = key(
    "risk.signal.invalid-rule-value",
    "A rule contains an invalid value: {rules}",
);

pub const NOTHING_TO_APPLY: Key = key(
    "dialog.nothing-to-apply.body",
    "There are no changes to apply — the current rules already match what is active.",
);
pub const ACTIVATED: Key = key("status.rules-activate-completed", "Rules activated.");
pub const ACTIVATE_FAILED: Key = key("status.rules-activate-failed", "Failed to activate rules: ");
pub const UAC_DECLINED: Key = key(
    "status.activate-uac-declined",
    "Administrator approval was cancelled — changes were not applied. Click Apply again to retry.",
);
pub const ERROR_UNKNOWN: Key = key("errors.unknown", "Unknown error");
pub const FILE_ENCODING: Key = key(
    "errors.file-encoding",
    "The file is not saved as UTF-8 text. Save it in UTF-8 and import it again.",
);
pub const PAYLOAD_TOO_LARGE: Key = key(
    "errors.payload-too-large",
    "The file is over the size limit for a rule set.",
);

pub const QUIT_TITLE: Key = key("unsaved-changes.title", "Unsaved changes");
pub const QUIT_BODY: Key = key(
    "unsaved-changes.body.app-quit",
    "You have unsaved changes. Quit NetRuleRouter anyway?",
);
pub const QUIT_DETAIL: Key = key(
    "unsaved-changes.detail.rules-not-applied",
    "The rules on screen have not been applied to the service yet.",
);

// ── The terminal's own ───────────────────────────────────────────────────────

pub const STATE_TITLE: Key = key("tui.rules.state-title", "Rule list");
pub const LIST_TITLE: Key = key("tui.rules.list-title", "Rules");
pub const CHANGES: Key = key("tui.rules.changes", "Changes");
pub const PENDING: Key = key("tui.rules.pending", "Not applied");
pub const IN_FORCE: Key = key("tui.rules.in-force", "Same as in the service");
pub const NOT_LOADED: Key = key(
    "tui.rules.not-loaded",
    "The rules in force are not known without the service.",
);
pub const LOADING: Key = key("tui.rules.loading", "Reading the rules from the service…");
pub const LOAD_FAILED: Key = key(
    "tui.rules.load-failed",
    "Could not read the rules from the service: {error}",
);
pub const PREVIEWING: Key = key("tui.rules.previewing", "Comparing with the rules in force…");
pub const APPLYING: Key = key("tui.rules.applying", "Applying the rules…");
pub const PHASE_STARTED: Key = key(
    "tui.rules.phase-started",
    "The service has started applying the rules.",
);
pub const PHASE_COMPLETED: Key = key(
    "tui.rules.phase-completed",
    "The service has finished applying the rules.",
);
pub const PHASE_FAILED: Key = key(
    "tui.rules.phase-failed",
    "The service could not apply the rules: {error}",
);
pub const BUSY: Key = key(
    "tui.rules.busy",
    "Wait until the rules are applied; the list cannot change meanwhile.",
);
pub const APPLY_OFFLINE: Key = key(
    "tui.rules.apply-offline",
    "The service is not connected, so the rules cannot be applied now. Export them to files with x to keep them.",
);
pub const EXPIRED: Key = key(
    "tui.rules.expired",
    "The review is out of date — the rules in force changed meanwhile. Press s to compare again.",
);
pub const ON: Key = key("tui.rules.on", "on");
pub const OFF: Key = key("tui.rules.off", "off");
pub const SHOWN: Key = key(
    "tui.rules.shown",
    "Rules {first} to {last} of {shown}; {total} in all.",
);
pub const NONE_SHOWN: Key = key(
    "tui.rules.none-shown",
    "No rule matches the filter. {total} in all.",
);
pub const VERDICT_PENDING: Key = key("tui.rules.verdict-empty", "Type a value to check it.");
pub const CHOICE_HINT: Key = key(
    "tui.rules.choice-hint",
    "Up and Down choose, Enter confirms, Esc cancels; or type the number.",
);
pub const INPUT_HINT: Key = key(
    "tui.rules.input-hint",
    "Type, then Enter; Backspace deletes, Esc cancels.",
);
pub const FORM_HINT: Key = key(
    "tui.rules.form-hint",
    "Up and Down: field. Left and Right: change a choice. Space: on or off. Enter: save. Esc: cancel.",
);
pub const REVIEW_HINT: Key = key(
    "tui.rules.review-hint",
    "Enter: apply these changes. Esc: back to editing. Up, Down, Page Up, Page Down: scroll the list.",
);
pub const REVIEW_HINT_CRITICAL: Key = key(
    "tui.rules.review-hint-critical",
    "Space: tick the box above; Enter applies only once it is ticked. Esc: back to editing.",
);
pub const REVIEW_WINDOW: Key = key(
    "tui.rules.review-window",
    "Change lines {first} to {last} of {total}.",
);
pub const TICKED: Key = key("tui.rules.ticked", "[x]");
pub const UNTICKED: Key = key("tui.rules.unticked", "[ ]");
pub const FILTER_QUESTION: Key = key(
    "tui.rules.filter-question",
    "Show the rules of which route?",
);
pub const SEARCH_QUESTION: Key = key(
    "tui.rules.search-question",
    "Search by value or comment. A pasted web address is reduced to its site. Empty shows all.",
);
pub const IMPORT_QUESTION: Key = key(
    "tui.rules.import-question",
    "Folder with rules_primary.txt and rules_secondary.txt to import:",
);
pub const EXPORT_QUESTION: Key = key(
    "tui.rules.export-question",
    "Folder to write rules_primary.txt and rules_secondary.txt to:",
);
pub const PRESET_QUESTION: Key = key("tui.rules.preset-question", "Which rule set to load?");
pub const NO_PRESETS: Key = key(
    "tui.rules.no-presets",
    "No rule sets were found beside the program.",
);
pub const MODE_QUESTION: Key = key(
    "tui.rules.mode-question",
    "What to do with the rules on screen?",
);
pub const MODE_REPLACE: Key = key(
    "tui.rules.mode-replace",
    "Replace them with the rules from the files",
);
pub const MODE_ADD: Key = key(
    "tui.rules.mode-add",
    "Keep them and add the rules from the files that are not there yet",
);
pub const OVERWRITE_QUESTION: Key = key(
    "tui.rules.overwrite-question",
    "The folder already has rules files. Replace them?",
);
pub const OVERWRITE: Key = key("tui.rules.overwrite", "Replace the files");
pub const RELOAD_QUESTION: Key = key(
    "tui.rules.reload-question",
    "Load the rules the service applies? The changes on screen will be lost.",
);
pub const QUIT_APPLY: Key = key("tui.rules.quit-apply", "Apply, then quit");
pub const QUIT_DISCARD: Key = key("tui.rules.quit-discard", "Discard the changes and quit");
pub const QUIT_STAY: Key = key("tui.rules.quit-stay", "Stay");
pub const IMPORTED: Key = key(
    "tui.rules.imported",
    "Read {count} rules from {path}. They are not applied yet.",
);
pub const IMPORT_NOTHING: Key = key(
    "tui.rules.import-nothing",
    "Neither rules_primary.txt nor rules_secondary.txt is in {path}.",
);
pub const READ_FAILED: Key = key("tui.rules.read-failed", "Could not read {path}: {error}");
pub const EXPORTED: Key = key("tui.rules.exported", "The rules were written to {path}.");
pub const WRITE_FAILED: Key = key("tui.rules.write-failed", "Could not write {path}: {error}");
pub const PLAIN_PROMPT: Key = key(
    "tui.rules.plain-prompt",
    "Type the answer and press Enter. Enter alone keeps what is shown; ! cancels.",
);
pub const PLAIN_CHOICE_PROMPT: Key = key(
    "tui.rules.plain-choice-prompt",
    "Type the number of your choice and press Enter; ! cancels.",
);
pub const PLAIN_REVIEW_PROMPT: Key = key(
    "tui.rules.plain-review-prompt",
    "Type y and press Enter to apply these changes, or n to go back to editing; > and < scroll the list.",
);
pub const PLAIN_REVIEW_CRITICAL_PROMPT: Key = key(
    "tui.rules.plain-review-critical-prompt",
    "The risk is critical. Type c and press Enter to tick the box above, then y to apply; n goes back to editing.",
);

// ── Help ─────────────────────────────────────────────────────────────────────

pub const HELP_FOCUS: Key = key(
    "tui.rules.help.focus",
    "Tab or Enter in the menu: move into the rule list; Esc: back to the menu",
);
pub const HELP_MOVE: Key = key(
    "tui.rules.help.move",
    "Up, Down, Page Up, Page Down, Home, End: choose a rule",
);
pub const HELP_EDIT: Key = key(
    "tui.rules.help.edit",
    "a: add a rule. e or Enter: edit the chosen rule",
);
pub const HELP_DELETE: Key = key(
    "tui.rules.help.delete",
    "Delete or d: delete the chosen rule. Space or t: switch it on or off",
);
pub const HELP_FILTER: Key = key(
    "tui.rules.help.filter",
    "f: show the rules of one route. /: search; a pasted web address is reduced to its site",
);
pub const HELP_APPLY: Key = key(
    "tui.rules.help.apply",
    "Ctrl+S or s: apply. The changes are shown first; Enter applies them, Esc returns",
);
pub const HELP_FILES: Key = key(
    "tui.rules.help.files",
    "i: import the two rules files. x: export them. p: load a country rule set",
);
pub const HELP_RELOAD: Key = key(
    "tui.rules.help.reload",
    "r: show the rules the service applies, dropping the changes on screen",
);
pub const HELP_FORM: Key = key(
    "tui.rules.help.form",
    "In the rule form: Up and Down move between fields, Left and Right change a choice, Space switches the rule on or off, Enter saves, Esc cancels",
);

pub const PLAIN_ADD: Key = key("tui.rules.plain.add", "a: add a rule");
pub const PLAIN_EDIT: Key = key(
    "tui.rules.plain.edit",
    "e and a number: edit that rule, for example e 3",
);
pub const PLAIN_DELETE: Key = key("tui.rules.plain.delete", "d and a number: delete that rule");
pub const PLAIN_TOGGLE: Key = key(
    "tui.rules.plain.toggle",
    "t and a number: switch that rule on or off",
);
pub const PLAIN_FILTER: Key = key(
    "tui.rules.plain.filter",
    "f: choose which route's rules to show",
);
pub const PLAIN_SEARCH: Key = key(
    "tui.rules.plain.search",
    "/ and text: search, for example / example.com; / alone shows all",
);
pub const PLAIN_PAGES: Key = key("tui.rules.plain.pages", "> and <: next and previous page");
pub const PLAIN_APPLY: Key = key(
    "tui.rules.plain.apply",
    "s: apply the changes; they are shown first",
);
pub const PLAIN_FILES: Key = key(
    "tui.rules.plain.files",
    "i: import files. x: export files. p: load a country rule set",
);
pub const PLAIN_RELOAD: Key = key(
    "tui.rules.plain.reload",
    "r: show the rules the service applies",
);

pub const TITLE_BASELINE: Key = key(
    "tui.rules.title-baseline",
    "Rules — baseline for every user",
);
pub const BASELINE_NOTE: Key = key(
    "tui.rules.baseline-note",
    "Running as root: these rules are the baseline every user without rules of their own follows, as Set as baseline does in the window.",
);

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    TITLE_BASELINE,
    BASELINE_NOTE,
    ROUTE_PRIMARY,
    ROUTE_SECONDARY,
    ROUTE_BLOCK,
    ROUTE_VERIFY,
    ROUTE_ALL,
    ROUTE_FILTER,
    SEARCH,
    DISABLED,
    AUTO_ORIGIN,
    VALIDATION_ERROR,
    VALIDATION_WARNING,
    EMPTY_TITLE,
    EMPTY_BODY,
    NO_DATA,
    FORM_ADD,
    FORM_EDIT,
    FIELD_TYPE,
    FIELD_VALUE,
    FIELD_ROUTE,
    FIELD_COMMENT,
    ENABLED_ON,
    ENABLED_OFF,
    VERIFY_HINT,
    DUPLICATE,
    OPEN_EXISTING,
    RULE_ADDED,
    RULE_ADDED_DISABLED,
    RULE_UPDATED,
    RULE_REMOVED,
    LIMIT_REACHED,
    DELETE_TITLE,
    DELETE_CONFIRM,
    RELOAD,
    RELOAD_HINT,
    CANCEL,
    REVIEW_TITLE,
    REVIEW_APPLY,
    REVIEW_EMPTY,
    REVIEW_UNCHANGED,
    REVIEW_COUNTS,
    REVIEW_ADDED,
    REVIEW_REMOVED,
    REVIEW_CHANGED,
    REVIEW_NONE,
    RISK_HEADING,
    SIGNALS_HEADING,
    DUPLICATES_HEADING,
    UNDERSTAND,
    PROVENANCE_EDIT,
    PROVENANCE_IMPORT,
    INVALID_VALUES,
    NOTHING_TO_APPLY,
    ACTIVATED,
    ACTIVATE_FAILED,
    UAC_DECLINED,
    ERROR_UNKNOWN,
    FILE_ENCODING,
    PAYLOAD_TOO_LARGE,
    QUIT_TITLE,
    QUIT_BODY,
    QUIT_DETAIL,
    STATE_TITLE,
    LIST_TITLE,
    CHANGES,
    PENDING,
    IN_FORCE,
    NOT_LOADED,
    LOADING,
    LOAD_FAILED,
    PREVIEWING,
    APPLYING,
    PHASE_STARTED,
    PHASE_COMPLETED,
    PHASE_FAILED,
    BUSY,
    APPLY_OFFLINE,
    EXPIRED,
    ON,
    OFF,
    SHOWN,
    NONE_SHOWN,
    VERDICT_PENDING,
    CHOICE_HINT,
    INPUT_HINT,
    FORM_HINT,
    REVIEW_HINT,
    REVIEW_HINT_CRITICAL,
    REVIEW_WINDOW,
    TICKED,
    UNTICKED,
    FILTER_QUESTION,
    SEARCH_QUESTION,
    IMPORT_QUESTION,
    EXPORT_QUESTION,
    PRESET_QUESTION,
    NO_PRESETS,
    MODE_QUESTION,
    MODE_REPLACE,
    MODE_ADD,
    OVERWRITE_QUESTION,
    OVERWRITE,
    RELOAD_QUESTION,
    QUIT_APPLY,
    QUIT_DISCARD,
    QUIT_STAY,
    IMPORTED,
    IMPORT_NOTHING,
    READ_FAILED,
    EXPORTED,
    WRITE_FAILED,
    PLAIN_PROMPT,
    PLAIN_CHOICE_PROMPT,
    PLAIN_REVIEW_PROMPT,
    PLAIN_REVIEW_CRITICAL_PROMPT,
    HELP_FOCUS,
    HELP_MOVE,
    HELP_EDIT,
    HELP_DELETE,
    HELP_FILTER,
    HELP_APPLY,
    HELP_FILES,
    HELP_RELOAD,
    HELP_FORM,
    PLAIN_ADD,
    PLAIN_EDIT,
    PLAIN_DELETE,
    PLAIN_TOGGLE,
    PLAIN_FILTER,
    PLAIN_SEARCH,
    PLAIN_PAGES,
    PLAIN_APPLY,
    PLAIN_FILES,
    PLAIN_RELOAD,
];
