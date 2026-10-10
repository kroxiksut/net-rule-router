//! The Rules screen's words. The GUI's own keys where the GUI says the same
//! thing; `tui.rules.*` only for what exists in the terminal alone.

use crate::i18n::{key, Key};

// ── Shared with the GUI ──────────────────────────────────────────────────────

pub const ROUTE_PRIMARY: Key = key("label.primary", "Primary");
pub const ROUTE_SECONDARY: Key = key("label.secondary", "Additional");
pub const ROUTE_BLOCK: Key = key("label.block", "Block");
pub const ROUTE_UNSURE: Key = key("rules.filter.route.unsure", "Unsure (?)");
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
pub const VERIFY: Key = key("dialog.rule.verify", "Unsure — check where it works");
pub const VERIFY_HINT: Key = key(
    "dialog.rule.verify-hint",
    "Works through the route it is written for. If the site or address does not open there but does on the other route, NetRuleRouter offers to move the rule.",
);
pub const VERDICTS_TITLE: Key = key(
    "notifications.verify-verdicts.title",
    "Addresses that do not open where they are written: {count}",
);
pub const VERDICTS_BODY: Key = key(
    "notifications.verify-verdicts.body",
    "They do get through over the other route and use it until the service restarts. “Move” writes them there for good; “Not now” keeps them as written and checks again after the service restarts.",
);
pub const VERDICTS_ITEM: Key = key("notifications.verify-verdicts.item", "{value} → {route}");
pub const VERDICTS_WHERE: Key = key(
    "tui.suggestions.notice-open",
    "To answer, open screen {key}, {screen}.",
);
pub const VERDICTS_MOVED: Key = key(
    "status.verify-verdicts.moved",
    "Rules moved to the route where they work.",
);
pub const VERDICTS_FAILED: Key = key(
    "status.verify-verdicts.failed",
    "The service did not take the answer: ",
);
pub const DUPLICATE: Key = key(
    "dialog.rule.duplicate-body",
    "A rule with the same type, value, and target route already exists ({id}). Open the existing rule to change it, or cancel to keep editing the new one.",
);
pub const OPEN_EXISTING: Key = key("dialog.rule.duplicate-open-existing", "Open existing");
pub const OVERLAPS_HEADING: Key = key("rules.overlaps.nav-label", "Overlaps");
pub const OVERLAPS_MORE: Key = key(
    "notifications.block-notice.backlog.more",
    "and {count} more",
);

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
pub const SETS_FOLDER: Key = key("tui.rules.sets-folder", "Rule sets in {path}");
pub const SETS_FOLDER_EMPTY: Key = key(
    "tui.rules.sets-folder-empty",
    "Your rule-set folder {path} holds no sets; the shipped ones are listed.",
);
pub const SETTINGS_UNREADABLE: Key = key(
    "tui.rules.settings-unreadable",
    "Your settings file could not be read: {error}",
);
pub const FOLDER_QUESTION: Key = key(
    "tui.rules.folder-question",
    "Folder with your rule sets; - goes back to the sets shipped with the program:",
);
pub const FOLDER_SET: Key = key(
    "tui.rules.folder-set",
    "Rule sets are now listed from {path}.",
);
pub const FOLDER_CLEARED: Key = key(
    "tui.rules.folder-cleared",
    "Rule sets are listed from the ones shipped with the program again.",
);
pub const FOLDER_MISSING: Key = key("tui.rules.folder-missing", "There is no folder {path}.");
pub const FOLDER_UNAVAILABLE: Key = key(
    "tui.rules.folder-unavailable",
    "This session edits the administrator's baseline, so it has no rule-set folder of its own.",
);
pub const SET_NAMES_TAKEN: Key = key(
    "tui.rules.set-names-taken",
    "Nothing was saved: every name from {name} to {name} (99) is taken in {path}.",
);
pub const FOLDER_SET_SAVED: Key = key(
    "status.rules-folder-set-saved",
    "The rules on screen are saved in your folder as a set: {dir}",
);
pub const OLD_FILES_KEPT: Key = key(
    "status.rules-folder-old-files-kept",
    "The files they were linked to before stay where they were: {dir}",
);
pub const MY_RULES: Key = key("rules.sets.my-rules", "My rules");
pub const SETTINGS_NOT_WRITTEN: Key = key(
    "tui.rules.settings-not-written",
    "Your settings file was not updated: {error}",
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
pub const EXPORTED_UNBOUND: Key = key(
    "tui.rules.exported-unbound",
    "The rules were written to {path}, but your settings file was not updated: {error}",
);
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
pub const VERDICTS_KEYS: Key = key("tui.rules.verdicts.keys", "m: Move. n: Not now.");
pub const VERDICTS_FOLDER_QUESTION: Key = key(
    "tui.rules.verdicts.folder-question",
    "Folder for your rule sets: the rules on screen are saved there, then the rules move. Nothing typed is Not now:",
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
pub const HELP_FOLDER: Key = key(
    "tui.rules.help.folder",
    "o: choose the folder with your rule sets; the rules on screen are saved there as a set",
);
pub const HELP_FILES: Key = key(
    "tui.rules.help.files",
    "i: import the two rules files. x: export them. p: load a country rule set",
);
pub const HELP_RELOAD: Key = key(
    "tui.rules.help.reload",
    "r: show the rules the service applies, dropping the changes on screen",
);
pub const HELP_VERDICTS: Key = key(
    "tui.rules.help.verdicts",
    "m: move the rules that work only on the other route there for good. n: not now",
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
pub const PLAIN_FOLDER: Key = key(
    "tui.rules.plain.folder",
    "o: choose the folder with your rule sets",
);
pub const PLAIN_FILES: Key = key(
    "tui.rules.plain.files",
    "i: import files. x: export files. p: load a country rule set",
);
pub const PLAIN_VERDICTS: Key = key(
    "tui.rules.plain.verdicts",
    "m: move the rules that work only on the other route. n: not now",
);
pub const PLAIN_RELOAD: Key = key(
    "tui.rules.plain.reload",
    "r: show the rules the service applies",
);

// ── The main-route check ─────────────────────────────────────────────────────

pub const MAIN_ROUTE_COLUMN: Key = key("rules.column.main-route", "Main route");
pub const MAIN_ROUTE_ANSWERED: Key = key("rules.main-route.answered", "reaches");
pub const MAIN_ROUTE_SILENT: Key = key("rules.main-route.silent", "does not reach");
pub const MAIN_ROUTE_NO_ADDRESS: Key = key("rules.main-route.no-address", "not seen yet");
pub const MAIN_ROUTE_UNCLEAR: Key = key("rules.main-route.unclear", "could not check");
pub const MAIN_ROUTE_ZONE: Key = key("rules.main-route.zone", "not checked");
pub const MAIN_ROUTE_ANSWERED_HINT: Key = key(
    "rules.main-route.answered-tooltip",
    "Something answered at this address over the main connection. That does not mean the site works there — it may still refuse to serve you. Checked within the last half hour.",
);
pub const MAIN_ROUTE_SILENT_HINT: Key = key(
    "rules.main-route.silent-tooltip",
    "Nothing answered at this address over the main connection, so this rule is doing real work. Checked within the last half hour.",
);
pub const MAIN_ROUTE_NO_ADDRESS_HINT: Key = key(
    "rules.main-route.no-address-tooltip",
    "Nothing has visited this address on this computer since the service started, so there is nothing to try. Open the site once and check again.",
);
pub const MAIN_ROUTE_UNCLEAR_HINT: Key = key(
    "rules.main-route.unclear-tooltip",
    "The check could not be made: the main connection has no address right now, or the attempt failed to start. Try again later.",
);
pub const MAIN_ROUTE_ZONE_HINT: Key = key(
    "rules.main-route.zone-tooltip",
    "A zone covers every site under it, so there is no single address to try.",
);
pub const CHECK_BUSY: Key = key(
    "rules.suggestions.inbox.action-check-main-route-busy",
    "Checking...",
);
pub const CHECK_STARTED: Key = key(
    "rules.main-route.check-started",
    "Checking {count} addresses over the main connection...",
);
pub const CHECK_PROGRESS: Key = key(
    "rules.main-route.check-progress",
    "Checking addresses over the main connection: {done} of {total}...",
);
pub const CHECK_DONE: Key = key(
    "rules.main-route.check-done",
    "Main route check finished: reaches {answered}, does not reach {silent}, not checked {other}.",
);
pub const CHECK_NOTHING: Key = key(
    "rules.main-route.check-nothing",
    "Nothing to check: these addresses were checked recently, or none of them has been resolved yet.",
);
pub const NOTHING_TO_CHECK: Key = key(
    "rules.main-route.nothing-to-check",
    "There are no additional-route address rules to check.",
);
pub const CHECK_FAILED: Key = key("tui.suggestions.failed", "Not done: {error}");
pub const SORT: Key = key("rules.sort.label", "Sort");
pub const SORT_DISPLAY: Key = key("rules.sort.by-display-order", "Display order");
pub const SORT_MAIN_ROUTE: Key = key("rules.sort.by-main-route", "Main route check");
pub const HELP_MAIN_ROUTE: Key = key(
    "tui.rules.help.main-route",
    "c: check whether the main route reaches the sites of your additional-route rules; the answer shows beside each rule. Shift+O: list what the main route does not reach first, or back",
);
pub const PLAIN_MAIN_ROUTE: Key = key(
    "tui.rules.plain.main-route",
    "c: check whether the main route reaches the sites of your additional-route rules. O: list what it does not reach first, or back",
);

pub const TITLE_BASELINE: Key = key(
    "tui.rules.title-baseline",
    "Rules — baseline for every user",
);
pub const BASELINE_NOTE: Key = key(
    "tui.rules.baseline-note",
    "Running as root: these rules are the baseline every user without rules of their own follows, as Set as baseline does in the window.",
);

pub const UNRECOGNIZED: Key = key(
    "rules.unrecognized-note",
    "Rules this version cannot read: {n}. They are kept in your rules and are not applied; a newer version of the app applies them.",
);

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    TITLE_BASELINE,
    BASELINE_NOTE,
    UNRECOGNIZED,
    ROUTE_PRIMARY,
    ROUTE_SECONDARY,
    ROUTE_BLOCK,
    ROUTE_UNSURE,
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
    VERIFY,
    VERIFY_HINT,
    VERDICTS_TITLE,
    VERDICTS_BODY,
    VERDICTS_ITEM,
    VERDICTS_WHERE,
    VERDICTS_MOVED,
    VERDICTS_FAILED,
    VERDICTS_KEYS,
    VERDICTS_FOLDER_QUESTION,
    DUPLICATE,
    OPEN_EXISTING,
    OVERLAPS_HEADING,
    OVERLAPS_MORE,
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
    SETS_FOLDER,
    SETS_FOLDER_EMPTY,
    SETTINGS_UNREADABLE,
    SETTINGS_NOT_WRITTEN,
    FOLDER_QUESTION,
    FOLDER_SET,
    FOLDER_CLEARED,
    FOLDER_MISSING,
    FOLDER_UNAVAILABLE,
    SET_NAMES_TAKEN,
    FOLDER_SET_SAVED,
    OLD_FILES_KEPT,
    MY_RULES,
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
    EXPORTED_UNBOUND,
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
    HELP_FOLDER,
    HELP_RELOAD,
    HELP_VERDICTS,
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
    PLAIN_FOLDER,
    PLAIN_RELOAD,
    PLAIN_VERDICTS,
    MAIN_ROUTE_COLUMN,
    MAIN_ROUTE_ANSWERED,
    MAIN_ROUTE_SILENT,
    MAIN_ROUTE_NO_ADDRESS,
    MAIN_ROUTE_UNCLEAR,
    MAIN_ROUTE_ZONE,
    MAIN_ROUTE_ANSWERED_HINT,
    MAIN_ROUTE_SILENT_HINT,
    MAIN_ROUTE_NO_ADDRESS_HINT,
    MAIN_ROUTE_UNCLEAR_HINT,
    MAIN_ROUTE_ZONE_HINT,
    CHECK_BUSY,
    CHECK_STARTED,
    CHECK_PROGRESS,
    CHECK_DONE,
    CHECK_NOTHING,
    NOTHING_TO_CHECK,
    CHECK_FAILED,
    SORT,
    SORT_DISPLAY,
    SORT_MAIN_ROUTE,
    HELP_MAIN_ROUTE,
    PLAIN_MAIN_ROUTE,
];
