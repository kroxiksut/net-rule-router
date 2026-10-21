//! The Rules screen's words. The GUI's own keys where the GUI says the same
//! thing; `tui.rules.*` only for what exists in the terminal alone.

use crate::i18n::{key, Key, Plural};

// ── Shared with the GUI ──────────────────────────────────────────────────────

pub const ROUTE_PRIMARY: Key = key("label.primary", "Primary");
pub const ROUTE_SECONDARY: Key = key("label.secondary", "Additional");
pub const ROUTE_BLOCK: Key = key("label.block", "Denied");
pub const FILTER_DENIED: Key = key("rules.filter.route.denied", "Denied");
pub const ROUTE_DENY: Key = key("rules.route.deny", "Deny");
pub const ROUTE_DENY_DESCRIPTION: Key = key(
    "rules.route.deny-description",
    "Deny — never send through any connection",
);
pub const ROUTE_UNSURE: Key = key("rules.filter.route.unsure", "Unsure (?)");
pub const ROUTE_ALL: Key = key("rules.filter.route.all", "All routes");
pub const ROUTE_FILTER: Key = key("rules.filter.route.label", "Route");
pub const SEARCH: Key = key("action.search", "Search");
pub const DISABLED: Key = key("label.disabled", "disabled");
pub const AUTO_ORIGIN: Key = key("rules.auto-origin.badge", "Added for you");
pub const APP_PINS: Key = key("rules.app-pins.badge", "holds {count} addresses");
pub const HOSTS_BLOCKED: Key = key("rules.hosts-override.blocked", "Blocked in hosts");
pub const HOSTS_REDIRECTED: Key = key(
    "rules.hosts-override.redirected",
    "Redirected by system → {ip}",
);
pub const HOSTS_NOTE: Key = key(
    "rules.hosts-override.tooltip",
    "The operating system's hosts file resolves this hostname before NetRuleRouter sees any traffic, so NetRuleRouter cannot override it. Edit the OS hosts file to change this.",
);
pub const APP_PINS_NOTE: Key = key(
    "rules.app-pins.tooltip",
    "These are the addresses this application has been seen using, and they now travel the additional link for EVERY program on this computer — a route cannot be told which process it is for. An address another program starts using is given back to the main connection automatically.",
);
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
pub const VERIFY_ANY_ZONE: Key = key(
    "dialog.rule.verify-any-zone",
    "A site in every zone is not checked: the check needs one host.",
);
pub const VERIFY_IPV6: Key = key(
    "dialog.rule.verify-ipv6",
    "An IPv6 address is not checked: the check goes out over IPv4 only, so this stays an ordinary route rule.",
);
pub const VERIFY_DENY: Key = key(
    "dialog.rule.verify-deny",
    "A denied rule is not checked: its traffic goes through no connection.",
);
pub const APP_NOT_LEAKPROOF: Key = key(
    "rules.application-not-leakproof",
    "On this system an application rule is not airtight: connections the app makes before it is recognised can still get through.",
);
/// A rule by folder and the scripts its folder holds.
pub const APP_FOLDER_SCRIPTS: Key = key(
    "rules.application-folder-scripts",
    "Scripts from this folder follow the rule too, even when an interpreter installed elsewhere runs them (a .py, .ps1, .bat, .sh or .jar file, say): from the moment their first connection is seen.",
);
pub const PATH_COUNTING: Key = key("dialog.rule.path.counting", "Counting the programs...");
pub const PATH_COUNT: Key = key("dialog.rule.path.count", "Programs covered now: {count}.");
pub const PATH_COUNT_MORE: Key = key(
    "dialog.rule.path.count-more",
    "Programs covered now: the first {count}. The folder holds more than one rule covers.",
);
pub const PATH_MISSING: Key = key(
    "dialog.rule.path.missing",
    "Nothing is there yet: the rule takes effect once the program or folder appears.",
);
pub const PATH_PLACE: Key = key("dialog.rule.path.place", "For you this is {place}.");
pub const PATH_UNSUPPORTED: Key = key(
    "dialog.rule.path.unsupported",
    "This system does not apply rules by path yet.",
);
pub const PATH_ANYONE_CAN_WRITE: Key = key(
    "dialog.rule.path.anyone-can-write",
    "Anyone can put a program here, so the rule may cover programs you did not install. A program here is never exempt from leak protection.",
);
pub const PATH_INCLUDE_SUBFOLDERS: Key =
    key("dialog.rule.path.include-subfolders", "Include subfolders");
pub const PATH_SUBFOLDERS_KEY: Key = key(
    "tui.rules.form-subfolders",
    "Ctrl+F, or !f in line mode: with subfolders or without",
);
pub const APP_FOLDER_SCRIPTS_DENY: Key = key(
    "rules.application-folder-scripts-deny",
    "A deny by folder stops the programs in it, but not for certain a script from it that an interpreter installed elsewhere runs.",
);
/// What an application rule does, in the words of the window's form for this
/// platform: Windows names the program by its executable, Linux by process.
pub const APP_ROUTING_NOTE: Key = key(
    "rules.application-routing-note",
    "Routes everything this app connects to through the additional adapter. NetRuleRouter learns the app's destinations by watching its connections, so routing fills in as the app connects — enable «Connection observation» in Settings → Diagnostics for this to work. Enter the executable name, e.g. chrome.exe.",
);
pub const APP_ROUTING_NOTE_LINUX: Key = key(
    "rules.application-routing-note-linux",
    "Routes everything this program connects to through the additional connection. NetRuleRouter learns the program's destinations by watching its connections, so routing fills in as it connects. Enter the process name, e.g. browser.",
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
pub const CHANGED_ELSEWHERE_QUESTION: Key = key(
    "tui.rules.changed-elsewhere.question",
    "Your rules were changed elsewhere since this list was read. Nothing was applied.",
);
pub const CHANGED_ELSEWHERE_DETAIL: Key = key(
    "tui.rules.changed-elsewhere.detail",
    "Your edits can be put on top of the rules now in force; you review the result before it applies.",
);
pub const REBASE: Key = key(
    "tui.rules.changed-elsewhere.rebase",
    "Put my edits on top of the rules now in force",
);
pub const KEEP_LIST: Key = key("tui.rules.changed-elsewhere.keep", "Keep my list as it is");
pub const REBASED: Key = key(
    "tui.rules.changed-elsewhere.rebased",
    "Your edits are on top of the rules now in force. Review them before they apply.",
);
pub const MERGE_TITLE: Key = key(
    "dialog.merge.edits-title",
    "Your edits and the rules now in force",
);
pub const MERGE_BODY: Key = key(
    "dialog.merge.edits-body",
    "Your rules were changed elsewhere while you were editing them. Your edits go on top of the rules now in force: a rule you added, changed or deleted is added, changed or deleted there too, and rules changed elsewhere stay. Where both sides changed the same rule you pick the version that stays.",
);
pub const MERGE_BUCKET_ADDED: Key = key("dialog.merge.bucket-edits-only", "Only in your edits");
pub const MERGE_BUCKET_CHANGED: Key = key("dialog.merge.bucket-edits-changed", "Changed by you");
pub const MERGE_BUCKET_DELETED: Key = key("dialog.merge.bucket-edits-deleted", "Deleted by you");
pub const MERGE_BUCKET_CONFLICTS: Key = key("dialog.merge.bucket-conflicts", "Conflicts");
pub const MERGE_PICK_MINE: Key = key("dialog.merge.pick-edits", "Your edit");
pub const MERGE_PICK_THEIRS: Key = key("dialog.merge.pick-in-force", "In force");
pub const MERGE_SIDE_DELETED: Key = key("dialog.merge.side-deleted", "deleted");
pub const MERGE_STAYS: Key = key("tui.rules.merge.stays", "stays: {side}");
pub const MERGE_KEYS: Key = key(
    "tui.rules.merge.keys",
    "Up and Down choose a conflict; Space or a number switches the version that stays; Enter merges and shows the changes for review; Esc leaves your list as it is.",
);
pub const MERGE_PLAIN_PROMPT: Key = key(
    "tui.rules.merge.plain-prompt",
    "Type a conflict's number to switch the version that stays, y to merge and review, n to leave your list as it is.",
);
pub const MERGE_CANCELLED: Key = key(
    "tui.rules.merge.cancelled",
    "Nothing was merged. Your list is as it was.",
);
pub const FILES_MERGE_TITLE: Key = key("dialog.merge.title", "Merge file and app rules");
pub const FILES_MERGE_BODY: Key = key(
    "dialog.merge.body",
    "Combine your linked rules file with the rules the service is currently enforcing. Rules on only one side are always kept; rules that exist on both but differ are shown as conflicts.",
);
pub const FILES_MERGE_BUCKET_FILE: Key = key("dialog.merge.bucket-file-only", "Only in the file");
pub const FILES_MERGE_BUCKET_SERVICE: Key =
    key("dialog.merge.bucket-service-only", "Only in the app");
pub const FILES_MERGE_PICK_FILE: Key = key("dialog.merge.pick-file", "File");
pub const FILES_MERGE_PICK_SERVICE: Key = key("dialog.merge.pick-service", "App");
pub const FILES_MATCH: Key = key(
    "dialog.merge.no-op",
    "The file and the app rules already match \u{2014} nothing to merge.",
);
pub const FILES_CONVERGED: Key = key(
    "notifications.rules-file-converged.title",
    "Your rules file was brought up to date",
);
pub const FILES_DRIFT: Key = key(
    "status.merge-banner",
    "The rules in your files are not the ones being applied \u{2014} you can compare and merge them.",
);
pub const FILES_DRIFT_KEY: Key = key(
    "tui.rules.files.drift-key",
    "Press F to compare the files with the rules in force.",
);
pub const FILES_NONE: Key = key(
    "tui.rules.files.none",
    "No rules files are linked, so there is nothing to compare. Export the rules with x to link them.",
);
pub const FILES_DIRTY: Key = key(
    "tui.rules.files.dirty",
    "Apply the changes on screen, or drop them with r, before comparing the files with the rules in force.",
);
pub const FILES_FAILED: Key = key(
    "tui.rules.files.failed",
    "The files could not be compared with the rules in force: {error}",
);
pub const HELP_FILES_MERGE: Key = key(
    "tui.rules.help.files-merge",
    "F: compare your linked rules files with the rules in force and merge them",
);
pub const PLAIN_FILES_MERGE: Key = key(
    "tui.rules.plain.files-merge",
    "F: compare your linked rules files with the rules in force and merge them",
);
pub const SPARE_TITLE: Key = key("dialog.rules-overlap.title", "Remove rules already covered");
pub const SPARE_BODY: Key = key(
    "dialog.rules-overlap.body",
    "These rules name a host that one of your wildcard rules already covers. Removing them changes nothing about where your traffic goes \u{2014} it only shortens the list.",
);
pub const SPARE_ITEM: Key = key(
    "dialog.rules-overlap.covered-by",
    "{host} \u{2014} already covered by *.{apex}",
);
pub const SPARE_ACTION: Key = key("rules.action.clean-overlaps", "Remove covered rules ({n})");
pub const SPARE_NONE: Key = key(
    "dialog.rules-overlap.empty",
    "Nothing is covered twice right now.",
);
pub const SPARE_REMOVED: Plural = Plural {
    stem: "status.rules-overlap-removed.",
    one: "{count} rule removed as already covered. Apply to put the change into effect.",
    other: "{count} rules removed as already covered. Apply to put the change into effect.",
};
pub const HELP_SPARE: Key = key(
    "tui.rules.help.spare",
    "Shift+C: remove the rules a wildcard rule of the same route already covers; where traffic goes does not change",
);
pub const PLAIN_SPARE: Key = key(
    "tui.rules.plain.spare",
    "C: remove the rules a wildcard rule of the same route already covers",
);
pub const HELP_APP_GROUPS: Key = key(
    "tui.rules.help.app-groups",
    "g: send a group of programs or a hypervisor's machines over a route",
);
pub const PLAIN_APP_GROUPS: Key = key(
    "tui.rules.plain.app-groups",
    "g: application and device routes",
);
pub const HAND_EDITED_TITLE: Key = key(
    "dialog.rules-file-edited.title",
    "A rules file was edited outside the app",
);
pub const HAND_EDITED_BODY: Key = key(
    "dialog.rules-file-edited.body",
    "Your rules changed elsewhere, and this file was edited by hand since the app last saved it, so it was left as it is. Take the file to compare it with the rules in force and apply what you keep, or replace the file with the rules in force.",
);
pub const HAND_EDITED_TAKE: Key = key("dialog.rules-file-edited.take", "Take the file");
pub const HAND_EDITED_REPLACE: Key = key("dialog.rules-file-edited.overwrite", "Replace the file");
pub const HAND_EDITED_LATER: Key = key("dialog.rules-file-edited.later", "Leave both for now");
pub const NUMBER_GONE: Key = key(
    "tui.rules.number-gone",
    "Rule {n} as it was listed is no longer in the list. Here is the list as it is now.",
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

/// The syntax hint a written rules file opens with, a key per line; the keys
/// and their English live with the writer.
pub fn file_hint_keys() -> Vec<Key> {
    nrr_client_logic::rules_table::RULES_FILE_HINT_KEYS
        .iter()
        .map(|&(id, en)| key(id, en))
        .collect()
}

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
pub const HELP_BOOK: Key = key(
    "tui.rules.help.book",
    "b: switch between your own rules and the baseline every user without rules of their own follows; the title says which is on screen",
);
pub const HELP_MOVE_TO_TYPE: Key = key(
    "tui.rules.help.move-to-type",
    "Shift+T: give the chosen rule the type its value is, when the value belongs to another type. Shift+M: do it for every such rule",
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
pub const PLAIN_BOOK: Key = key(
    "tui.rules.plain.book",
    "b: switch between your own rules and the baseline",
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
    "These rules are the baseline every user without rules of their own follows, as Set as baseline does in the window. b switches to your own rules.",
);
pub const BOOK_BASELINE: Key = key(
    "tui.rules.book.baseline",
    "Now showing the baseline. Applying changes it for every user without rules of their own.",
);
pub const BOOK_OWN: Key = key("tui.rules.book.own", "Now showing your own rules.");
pub const BOOK_DIRTY: Key = key(
    "tui.rules.book.dirty",
    "Apply the changes on screen, or drop them with r, before switching between your rules and the baseline.",
);
pub const OWN_RULES_ONLY: Key = key(
    "tui.rules.book.own-only",
    "This changes your own rules, and the baseline is on screen. Press b to switch to your rules first.",
);
/// The chosen row's offer when its value is another type's.
pub const MOVE_TO_TYPE: Key = key("tui.rules.move-to-type", "Shift+T: move it to “{type}”");
/// The rules whose value is another type's, above the list.
pub const MISPLACED_COUNT: Key = key(
    "rules.move-to-type.count",
    "{n} rule(s) are not in their section: {rules}",
);
pub const MOVE_ALL_TO_TYPE: Key = key(
    "tui.rules.move-all-to-type",
    "Shift+M: move them all to the type their value is",
);

pub const UNRECOGNIZED: Key = key(
    "rules.unrecognized-note",
    "Rules this version cannot read: {n}. They are kept in your rules and are not applied; a newer version of the app applies them.",
);

// ── A VPN's gateway ──────────────────────────────────────────────────────────

pub const GATEWAY_TITLE: Key = key(
    "settings.routing.vpn-gateway.title",
    "Other VPNs (corporate)",
);
pub const GATEWAY_NOTE: Key = key(
    "settings.routing.vpn-gateway.note",
    "For a VPN that connects only from one network, such as a work VPN allowed only from abroad: its gateway gets a rule for the channel you choose, so it always connects through that channel. If that channel is down, the VPN does not connect over the other one.",
);
pub const GATEWAY_FINDING: Key = key(
    "settings.routing.vpn-gateway.finding",
    "Looking at recent connections...",
);
pub const GATEWAY_FAILED: Key = key(
    "settings.routing.vpn-gateway.failed",
    "Could not read the connections: ",
);
pub const GATEWAY_OBSERVER_OFF: Key = key(
    "settings.routing.vpn-gateway.observer-off",
    "On this system NetRuleRouter cannot see where a program connects. Type the gateway address below.",
);
pub const GATEWAY_EMPTY: Key = key(
    "settings.routing.vpn-gateway.empty",
    "{program} has not connected anywhere on the internet recently. Start the VPN and let it try to connect, then search again.",
);
pub const GATEWAY_CANDIDATE: Key = key(
    "settings.routing.vpn-gateway.candidate",
    "{address} · ports {ports} · last seen {time}",
);
pub const GATEWAY_BY_NAME: Key = key("settings.routing.vpn-gateway.by-name", "By name: {host}");
pub const GATEWAY_OMITTED: Key = key(
    "settings.routing.vpn-gateway.omitted",
    "Addresses not shown: {count}.",
);
pub const GATEWAY_INVALID: Key = key(
    "settings.routing.vpn-gateway.manual-invalid",
    "This is neither an address nor a host name.",
);
pub const GATEWAY_COMMENT: Key = key(
    "settings.routing.vpn-gateway.rule-comment",
    "VPN gateway: {program}",
);
pub const GATEWAY_APPLY_HINT: Key = key(
    "settings.routing.vpn-gateway.apply-hint",
    "The rules are in your list now. Apply the changes to put them into effect.",
);
pub const GATEWAY_ALREADY: Key = key(
    "status.rules-list-already-present",
    "Already in the list: {count}.",
);
pub const GATEWAY_PROGRAM_QUESTION: Key = key(
    "tui.rules.gateway.program-question",
    "Which VPN program? Type its file name, for example corpvpn.exe.",
);
pub const GATEWAY_CHANNEL_QUESTION: Key = key(
    "tui.rules.gateway.channel-question",
    "Through which channel should it connect?",
);
pub const GATEWAY_PICK: Key = key(
    "tui.rules.gateway.pick",
    "Type a number to add that address, or type the gateway address or name.",
);
pub const GATEWAY_PICK_KEYS: Key = key(
    "tui.rules.gateway.pick-keys",
    "Up and Down choose, Enter adds the chosen address; typing an address or name adds that instead. Esc cancels.",
);
pub const GATEWAY_NONE_FOUND: Key = key(
    "tui.rules.gateway.none-found",
    "No addresses found. Type the gateway address or name.",
);
pub const HELP_GATEWAY: Key = key(
    "tui.rules.help.gateway",
    "v: add a rule for a VPN's gateway, so that VPN connects through the channel you choose",
);
pub const PLAIN_GATEWAY: Key = key(
    "tui.rules.plain.gateway",
    "v: add a rule for a VPN's gateway",
);

// ── Several rules at once ────────────────────────────────────────────────────────

pub const MODE_SEVERAL: Key = key("dialog.rule.mode.several", "Several rules");
pub const BULK_LABEL: Key = key(
    "dialog.rule.bulk.label",
    "One rule per line, as in a rules file: !value denies, ?value checks where it works, # value is kept switched off, and a line such as --- Windows gives the lines below it their type. Otherwise the type is read from the value.",
);
pub const BULK_SUMMARY: Key = key(
    "dialog.rule.bulk.summary",
    "To add: {add}. To move: {move}. Stay in the field: {keep}. Already in your rules: {drop}.",
);
pub const BULK_BOUND_LINES: Key = key(
    "dialog.rule.bulk.bound-lines",
    "Only the first {max} lines are read; the other {count} stay in the field for the next round.",
);
pub const BULK_BOUND_SIZE: Key = key(
    "dialog.rule.bulk.bound-size",
    "The text is longer than one round reads: the first {lines} lines are read, the other {count} stay in the field.",
);
pub const BULK_TYPE_UNKNOWN: Key = key("dialog.rule.bulk.type-unknown", "Type not known");
pub const BULK_WILL_ADD: Key = key("dialog.rule.bulk.will-add", "will be added");
pub const MOVE_TO_TYPE_ACTION: Key = key("rules.move-to-type.action", "Move to “{type}”");
pub const MOVE_HERE: Key = key("tray.add-rule.move", "Move to this route");
pub const DENY_INSTEAD: Key = key("tray.add-rule.deny-instead", "Deny instead");
pub const LIFT_DENY: Key = key("tray.add-rule.lift-deny", "Lift the deny, use this route");
pub const LIST_ADDED: Key = key("status.rules-list-added", "Rules added: {count}.");
pub const LIST_MOVED: Key = key(
    "status.rules-list-moved",
    "Moved to the chosen route: {count}.",
);
pub const LIST_LEFT: Key = key(
    "status.rules-list-left",
    "Left in the form to fix: {count}.",
);
pub const BULK_TEXT: Key = key(
    "tui.rules.bulk.text",
    "Rules, one per line ({count} lines):",
);
pub const BULK_MORE_ABOVE: Key = key("tui.rules.bulk.more-above", "{count} more lines above");
pub const BULK_HINT: Key = key(
    "tui.rules.bulk.hint",
    "Tab: next part. In the text Enter starts a new line; the preview follows each finished line. In the preview: t picks a type, m moves a rule found on another route. Ctrl+S: add. F2: one rule. Esc: cancel.",
);
pub const BULK_TYPE_KEY: Key = key("tui.rules.bulk.type-key", "t: {choices}");
pub const BULK_MOVE_KEY: Key = key("tui.rules.bulk.move-key", "m: {tick} {move}");
pub const BULK_NOT_ADDED: Key = key("tui.rules.bulk.not-added", "Not added");
pub const BULK_CHOOSE: Key = key("tui.rules.bulk.choose", "Your choice");
pub const PLAIN_BULK_TEXT: Key = key(
    "tui.rules.bulk.plain-text",
    "Type or paste the rules, one per line; an empty line ends the text. ! cancels.",
);
pub const PLAIN_BULK_ROWS: Key = key(
    "tui.rules.bulk.plain-rows",
    "y: add them. +: type more lines. c: start the text over. t, a line number and an option number: pick a type, for example t 3 1. m and a line number: move that rule or not. > and <: more rows. ! cancels.",
);
pub const SEVERAL_OPTION: Key = key("tui.rules.several-option", "Several rules at once (F2)");
pub const FORM_SWITCH_TYPE: Key = key(
    "tui.rules.form-switch-type",
    "Ctrl+T, or !t in line mode: move it to “{type}”",
);
pub const HELP_BULK: Key = key(
    "tui.rules.help.bulk",
    "Shift+A: add several rules at once, typed or pasted as lines of a rules file. F2 in the add form does the same",
);
pub const PLAIN_BULK: Key = key("tui.rules.plain.bulk", "A: add several rules at once");
pub const PLAIN_MOVE_TO_TYPE: Key = key(
    "tui.rules.plain.move-to-type",
    "T and a number: give that rule the type its value is, for example T 3. M: do it for every such rule",
);

// ── «Recent» ─────────────────────────────────────────────────────────────────

pub const RECENT: Key = key("rules.filter.recent.label", "Recent");
pub const RECENT_HOUR: Key = key("rules.filter.recent.hour", "Last hour");
pub const RECENT_TODAY: Key = key("rules.filter.recent.today", "Today");
pub const RECENT_WEEK: Key = key("rules.filter.recent.week", "7 days");
pub const RECENT_YESTERDAY: Key = key("rules.recent.yesterday", "yesterday {time}");
pub const RECENT_ADDED: Key = key("rules.recent.added", "added");
pub const RECENT_CHANGED: Key = key("rules.recent.changed", "changed");
pub const RECENT_PREVIOUS_ROUTE: Key =
    key("rules.recent.previous-route", "Route: {from} \u{2192} {to}");
pub const RECENT_PREVIOUS_OFF: Key = key("rules.recent.previous-off", "Was switched off");
pub const RECENT_PREVIOUS_ON: Key = key("rules.recent.previous-on", "Was switched on");
pub const RECENT_PREVIOUS_SURE: Key = key(
    "rules.recent.previous-sure",
    "Was without \u{201c}?\u{201d}",
);
pub const RECENT_PREVIOUS_UNSURE: Key = key(
    "rules.recent.previous-unsure",
    "Was marked \u{201c}?\u{201d}",
);
pub const RECENT_LOADING: Key = key("rules.recent.loading", "Reading recent changes\u{2026}");
pub const RECENT_FAILED: Key = key(
    "rules.recent.failed",
    "Recent changes could not be read: {reason}",
);
pub const RECENT_NONE: Key = key("rules.recent.none", "No changes in this period.");
pub const RECENT_REPLACED: Key = key(
    "rules.recent.replaced",
    "{time} \u{b7} Rule set replaced, rules in it: {count}",
);
pub const RECENT_REPLACED_MORE: Key = key("rules.recent.replaced-more", "and {count} more");
pub const RECENT_DELETED_TITLE: Key = key("rules.recent.deleted-title", "Deleted");
pub const RECENT_DELETED_AT: Key = key("rules.recent.deleted-at", "deleted {time}");
pub const RECENT_WAS_OFF: Key = key("rules.recent.was-off", "switched off");
pub const RECENT_PRESENT_NOTE: Key = key(
    "rules.recent.restore-present",
    "A rule with this type and value is already in the list.",
);
pub const RECENT_RESTORED: Key = key(
    "rules.recent.restored",
    "Rule put back: {value}. Apply the changes to bring it into force.",
);
pub const RECENT_HISTORY_START: Key = key(
    "rules.recent.history-start",
    "History is kept from {time}; what changed before that cannot be shown.",
);
pub const RECENT_TRUNCATED: Key = key(
    "rules.recent.truncated",
    "Only the latest changes are shown; choose a shorter period to see all of them.",
);
pub const RECENT_OFF: Key = key("tui.rules.recent-off", "Off: all rules");
pub const RECENT_QUESTION: Key = key("tui.rules.recent-question", "Show the rules changed:");
pub const RECENT_PRESENT: Key = key("tui.rules.recent-present", "already in the list");
pub const RECENT_RESTORE_HINT: Key = key(
    "tui.rules.recent-restore-hint",
    "U: put a deleted rule back; in line mode U and its number, for example U 1.",
);
pub const RECENT_NOTHING_DELETED: Key = key(
    "tui.rules.recent-nothing-deleted",
    "No deleted rules to put back. Shift+R shows the recent changes.",
);
pub const RESTORE_QUESTION: Key = key("tui.rules.restore-question", "Which rule to put back?");
pub const HELP_RECENT: Key = key(
    "tui.rules.help.recent",
    "Shift+R: recent changes \u{2014} the rules added or changed in the last hour, today or 7 days, newest first, and the deleted ones. Shift+U: put a deleted rule back",
);
pub const PLAIN_RECENT: Key = key(
    "tui.rules.plain.recent",
    "R: recent changes. U: put a deleted rule back",
);

// ── Rules applied despite the protection of system programs ──
pub const FILTER_OVERRIDDEN: Key = key(
    "rules.filter.enabled.overridden",
    "Allowed despite protection",
);
pub const OVERRIDE_GRANTED_MARK: Key = key(
    "rules.override.badge.granted",
    "Allowed despite protection \u{b7} {left}",
);
pub const OVERRIDE_PENDING_MARK: Key =
    key("rules.override.badge.pending", "Needs your confirmation");
pub const OVERRIDE_TITLE: Key = key(
    "rules.override.dialog.title",
    "Apply despite the protection?",
);
pub const OVERRIDE_READING: Key = key(
    "rules.override.dialog.reading",
    "Reading what the rule would take...",
);
pub const OVERRIDE_PROGRAMS: Key = key(
    "rules.override.dialog.programs",
    "Programs it takes: {count}.",
);
pub const OVERRIDE_PROGRAMS_OVER_CAP: Key = key(
    "rules.override.dialog.programs-over-cap",
    "Programs it takes: more than {count}.",
);
pub const OVERRIDE_CRITICAL: Key = key(
    "rules.override.dialog.critical",
    "System processes it takes: {list}.",
);
pub const OVERRIDE_ACCOUNTS: Key = key(
    "rules.override.dialog.accounts",
    "Running under service accounts: {list}.",
);
pub const OVERRIDE_OTHER_USERS: Key = key(
    "rules.override.dialog.other-users",
    "Other users run what it takes: {count}.",
);
pub const OVERRIDE_BREAKS: Key = key(
    "rules.override.dialog.breaks",
    "What may stop working: {list}.",
);
pub const OVERRIDE_ADMINISTRATOR: Key = key(
    "rules.override.dialog.administrator",
    "It reaches past your own programs, so confirming it needs administrator rights.",
);
pub const OVERRIDE_TERM: Key = key("rules.override.dialog.term", "Applies for");
pub const OVERRIDE_TYPE: Key = key(
    "rules.override.dialog.type",
    "To confirm, type the rule's value: {value}",
);
pub const OVERRIDE_REVOKED: Key = key(
    "rules.override.revoked",
    "The protection holds {value} again.",
);
pub const OVERRIDE_GRANTED: Key = key(
    "tui.rules.override.granted",
    "{value} applies despite the protection for the term you chose.",
);
pub const OVERRIDE_FAILED: Key = key(
    "tui.rules.override.failed",
    "The confirmation did not go through: {error}",
);
pub const NEEDS_ADMINISTRATOR: Key = key(
    "tui.rules.override.needs-administrator",
    "This confirmation needs administrator rights: confirm it in the NetRuleRouter window, or start the terminal as administrator.",
);
pub const OVERRIDE_NOTHING: Key = key(
    "tui.rules.override.nothing",
    "This rule does not ask to apply despite the protection: add +override after its value and apply the rules first.",
);
pub const OVERRIDE_MISMATCH: Key = key(
    "tui.rules.override.mismatch",
    "The value typed does not name the rule; type it in full.",
);
pub const OVERRIDE_SENDING: Key = key(
    "tui.rules.override.sending",
    "Confirming... An administrator's password may be asked here.",
);
pub const OVERRIDE_KEYS: Key = key(
    "tui.rules.override.keys",
    "Left and Right choose the term, Enter confirms once the value is typed, Esc cancels.",
);
pub const OVERRIDE_PLAIN_PROMPT: Key = key(
    "tui.rules.override.plain-prompt",
    "Type the rule's value to confirm, 1-4 to choose the term, ! to cancel",
);
pub const OVERRIDE_ENDED_TITLE: Key = key(
    "notifications.rule-override-ended.title",
    "The protection holds a rule again",
);
pub const OVERRIDE_ENDED_BODY: Key = key(
    "notifications.rule-override-ended.body",
    "The term you confirmed has ended for {rules}. The rule is not applied until you confirm it again in the rules list.",
);
pub const OVERRIDE_WITHDRAWN_TITLE: Key = key(
    "notifications.rule-override-withdrawn.title",
    "Confirmations were withdrawn",
);
pub const OVERRIDE_WITHDRAWN_BODY: Key = key(
    "notifications.rule-override-withdrawn.body",
    "Confirmations of protected rules were withdrawn: the service stopped unexpectedly several times in a row. The rules are not applied until you confirm them again in the rules list.",
);
pub const OVERRIDE_RECHECK_TITLE: Key = key(
    "notifications.rule-override-recheck.title",
    "A rule needs a new confirmation",
);
pub const OVERRIDE_RECHECK_BODY: Key = key(
    "notifications.rule-override-recheck.body",
    "A service now runs what {rules} takes, which your confirmation did not cover. The rule is not applied until you confirm it again in the rules list.",
);
pub const HELP_OVERRIDE: Key = key(
    "tui.rules.help.override",
    "Shift+P: apply a protected rule despite the protection (it needs +override after its value), or take the confirmation back",
);
pub const PLAIN_OVERRIDE: Key = key(
    "tui.rules.plain.override",
    "P and a rule number: confirm a protected rule, or take the confirmation back",
);

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    FILTER_OVERRIDDEN,
    OVERRIDE_GRANTED_MARK,
    OVERRIDE_PENDING_MARK,
    OVERRIDE_TITLE,
    OVERRIDE_READING,
    OVERRIDE_PROGRAMS,
    OVERRIDE_PROGRAMS_OVER_CAP,
    OVERRIDE_CRITICAL,
    OVERRIDE_ACCOUNTS,
    OVERRIDE_OTHER_USERS,
    OVERRIDE_BREAKS,
    OVERRIDE_ADMINISTRATOR,
    OVERRIDE_TERM,
    OVERRIDE_TYPE,
    OVERRIDE_REVOKED,
    OVERRIDE_GRANTED,
    OVERRIDE_FAILED,
    NEEDS_ADMINISTRATOR,
    OVERRIDE_NOTHING,
    OVERRIDE_MISMATCH,
    OVERRIDE_SENDING,
    OVERRIDE_KEYS,
    OVERRIDE_PLAIN_PROMPT,
    OVERRIDE_ENDED_TITLE,
    OVERRIDE_ENDED_BODY,
    OVERRIDE_WITHDRAWN_TITLE,
    OVERRIDE_WITHDRAWN_BODY,
    OVERRIDE_RECHECK_TITLE,
    OVERRIDE_RECHECK_BODY,
    HELP_OVERRIDE,
    PLAIN_OVERRIDE,
    TITLE_BASELINE,
    BASELINE_NOTE,
    BOOK_BASELINE,
    BOOK_OWN,
    BOOK_DIRTY,
    OWN_RULES_ONLY,
    UNRECOGNIZED,
    ROUTE_PRIMARY,
    ROUTE_SECONDARY,
    ROUTE_BLOCK,
    FILTER_DENIED,
    ROUTE_DENY,
    ROUTE_DENY_DESCRIPTION,
    ROUTE_UNSURE,
    ROUTE_ALL,
    ROUTE_FILTER,
    SEARCH,
    DISABLED,
    AUTO_ORIGIN,
    APP_PINS,
    APP_PINS_NOTE,
    HOSTS_BLOCKED,
    HOSTS_REDIRECTED,
    HOSTS_NOTE,
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
    VERIFY_ANY_ZONE,
    VERIFY_IPV6,
    VERIFY_DENY,
    APP_NOT_LEAKPROOF,
    APP_FOLDER_SCRIPTS,
    APP_FOLDER_SCRIPTS_DENY,
    PATH_COUNTING,
    PATH_COUNT,
    PATH_COUNT_MORE,
    PATH_MISSING,
    PATH_PLACE,
    PATH_UNSUPPORTED,
    PATH_ANYONE_CAN_WRITE,
    PATH_INCLUDE_SUBFOLDERS,
    PATH_SUBFOLDERS_KEY,
    APP_ROUTING_NOTE,
    APP_ROUTING_NOTE_LINUX,
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
    CHANGED_ELSEWHERE_QUESTION,
    CHANGED_ELSEWHERE_DETAIL,
    REBASE,
    KEEP_LIST,
    REBASED,
    MERGE_TITLE,
    MERGE_BODY,
    MERGE_BUCKET_ADDED,
    MERGE_BUCKET_CHANGED,
    MERGE_BUCKET_DELETED,
    MERGE_BUCKET_CONFLICTS,
    MERGE_PICK_MINE,
    MERGE_PICK_THEIRS,
    MERGE_SIDE_DELETED,
    MERGE_STAYS,
    MERGE_KEYS,
    MERGE_PLAIN_PROMPT,
    MERGE_CANCELLED,
    FILES_MERGE_TITLE,
    FILES_MERGE_BODY,
    FILES_MERGE_BUCKET_FILE,
    FILES_MERGE_BUCKET_SERVICE,
    FILES_MERGE_PICK_FILE,
    FILES_MERGE_PICK_SERVICE,
    FILES_MATCH,
    FILES_CONVERGED,
    FILES_DRIFT,
    FILES_DRIFT_KEY,
    FILES_NONE,
    FILES_DIRTY,
    FILES_FAILED,
    HELP_FILES_MERGE,
    PLAIN_FILES_MERGE,
    SPARE_TITLE,
    SPARE_BODY,
    SPARE_ITEM,
    SPARE_ACTION,
    SPARE_NONE,
    HELP_SPARE,
    PLAIN_SPARE,
    HELP_APP_GROUPS,
    PLAIN_APP_GROUPS,
    HAND_EDITED_TITLE,
    HAND_EDITED_BODY,
    HAND_EDITED_TAKE,
    HAND_EDITED_REPLACE,
    HAND_EDITED_LATER,
    NUMBER_GONE,
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
    HELP_BOOK,
    HELP_VERDICTS,
    HELP_MOVE_TO_TYPE,
    MOVE_TO_TYPE,
    MISPLACED_COUNT,
    MOVE_ALL_TO_TYPE,
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
    PLAIN_BOOK,
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
    GATEWAY_TITLE,
    GATEWAY_NOTE,
    GATEWAY_FINDING,
    GATEWAY_FAILED,
    GATEWAY_OBSERVER_OFF,
    GATEWAY_EMPTY,
    GATEWAY_CANDIDATE,
    GATEWAY_BY_NAME,
    GATEWAY_OMITTED,
    GATEWAY_INVALID,
    GATEWAY_COMMENT,
    GATEWAY_APPLY_HINT,
    GATEWAY_ALREADY,
    GATEWAY_PROGRAM_QUESTION,
    GATEWAY_CHANNEL_QUESTION,
    GATEWAY_PICK,
    GATEWAY_PICK_KEYS,
    GATEWAY_NONE_FOUND,
    HELP_GATEWAY,
    PLAIN_GATEWAY,
    MODE_SEVERAL,
    BULK_LABEL,
    BULK_SUMMARY,
    BULK_BOUND_LINES,
    BULK_BOUND_SIZE,
    BULK_TYPE_UNKNOWN,
    BULK_WILL_ADD,
    MOVE_TO_TYPE_ACTION,
    MOVE_HERE,
    DENY_INSTEAD,
    LIFT_DENY,
    LIST_ADDED,
    LIST_MOVED,
    LIST_LEFT,
    BULK_TEXT,
    BULK_MORE_ABOVE,
    BULK_HINT,
    BULK_TYPE_KEY,
    BULK_MOVE_KEY,
    BULK_NOT_ADDED,
    BULK_CHOOSE,
    PLAIN_BULK_TEXT,
    PLAIN_BULK_ROWS,
    SEVERAL_OPTION,
    FORM_SWITCH_TYPE,
    HELP_BULK,
    PLAIN_BULK,
    PLAIN_MOVE_TO_TYPE,
    RECENT,
    RECENT_HOUR,
    RECENT_TODAY,
    RECENT_WEEK,
    RECENT_YESTERDAY,
    RECENT_ADDED,
    RECENT_CHANGED,
    RECENT_PREVIOUS_ROUTE,
    RECENT_PREVIOUS_OFF,
    RECENT_PREVIOUS_ON,
    RECENT_PREVIOUS_SURE,
    RECENT_PREVIOUS_UNSURE,
    RECENT_LOADING,
    RECENT_FAILED,
    RECENT_NONE,
    RECENT_REPLACED,
    RECENT_REPLACED_MORE,
    RECENT_DELETED_TITLE,
    RECENT_DELETED_AT,
    RECENT_WAS_OFF,
    RECENT_PRESENT_NOTE,
    RECENT_RESTORED,
    RECENT_HISTORY_START,
    RECENT_TRUNCATED,
    RECENT_OFF,
    RECENT_QUESTION,
    RECENT_PRESENT,
    RECENT_RESTORE_HINT,
    RECENT_NOTHING_DELETED,
    RESTORE_QUESTION,
    HELP_RECENT,
    PLAIN_RECENT,
];
