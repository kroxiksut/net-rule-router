//! The interfaces screen's locale keys. The GUI's own wording wherever it has
//! one; `tui.interfaces.*` only for what the terminal says alone.

use crate::i18n::{key, Key};

pub const ADAPTERS_TITLE: Key = key("tui.interfaces.adapters-title", "Adapters");
pub const DETAILS_TITLE: Key = key("tui.interfaces.details-title", "Chosen adapter: {name}");
pub const RESULT_TITLE: Key = key("tui.interfaces.result-title", "Last action");
pub const ROLE_EXPLANATION: Key = key(
    "interfaces.role-explanation",
    "The primary route uses the default interface; the additional route carries the traffic your rules send to it.",
);
pub const NO_ADAPTERS: Key = key(
    "tui.interfaces.no-adapters",
    "The service reports no adapters that can take a role.",
);

pub const PLACEHOLDER_TITLE: Key = key(
    "interfaces.placeholder-rows.banner-title",
    "These are not your adapters",
);
pub const PLACEHOLDER_BODY: Key = key(
    "interfaces.placeholder-rows.banner-body",
    "The list below did not come from this machine — the background service could not enumerate the adapters, so example rows are shown. Assigning a route here would bind it to an adapter that does not exist, so the buttons stay disabled until a real list arrives.",
);
pub const FAIL_CLOSED_TITLE: Key = key(
    "interfaces.fail-closed.banner-title",
    "Leak protection is blocking traffic",
);
pub const FAIL_CLOSED_BODY: Key = key(
    "interfaces.fail-closed.banner-body",
    "Additional route is unavailable. Matched traffic is being blocked instead of leaking to the primary.",
);
pub const ABSENT_TITLE: Key = key(
    "interfaces.secondary-absent.banner-title",
    "The additional route is not available",
);
pub const ABSENT_BODY: Key = key(
    "interfaces.secondary-absent.banner-body",
    "The adapter you bound as the additional route is not present right now. Traffic your rules send there is blocked rather than leaked to the main route. Bring the connection back up, or assign another adapter to the role below.",
);
pub const REMEMBERED: Key = key(
    "interfaces.remembered.badge",
    "remembered · currently absent",
);

pub const EXCLUSIVE_NOTE: Key = key(
    "interfaces.role.exclusive-note",
    "One adapter cannot carry both routes: to use it for the other one, unassign its current role first.",
);
pub const UNASSIGN_PRIMARY: Key = key("interfaces.action.unassign-primary", "Unassign primary");
pub const UNASSIGN_SECONDARY: Key = key(
    "interfaces.action.unassign-secondary",
    "Unassign additional",
);
pub const ROW_SUMMARY: Key = key("interfaces.row.summary", "Type: %1 | IP: %2 | Gateway: %3");
pub const ROW_SUMMARY_2: Key = key("interfaces.row.summary-2", "DNS: %1 | Default route: %2");
pub const EXTERNAL_PREFIX: Key = key("interfaces.external-ip.prefix", "ext IP");
pub const YES: Key = key("label.yes", "Yes");
pub const NO: Key = key("label.no", "No");

pub const PROBE_BUSY: Key = key("interfaces.external-ip.probe-busy", "Checking…");
pub const PROBE_DONE: Key = key(
    "interfaces.external-ip.probe-done",
    "External address check finished.",
);
pub const PROBE_FAILED: Key = key(
    "interfaces.external-ip.probe-failed",
    "Could not determine the external address: ",
);
pub const SAVING: Key = key("tui.interfaces.saving", "Saving…");
pub const NEEDS_SERVICE: Key = key(
    "status.bindings-require-service",
    "Adapter bindings can only be changed while the background service is running.",
);
pub const BINDING_FAILED: Key = key(
    "status.route-binding-failed",
    "Could not save the adapter binding to the service: ",
);
pub const READ_FAILED: Key = key(
    "tui.interfaces.read-failed",
    "Could not read the current routing settings, so nothing was changed: {error}",
);
pub const ROLE_SET: Key = key("tui.interfaces.role-set", "{role}: {name}.");
pub const ROLE_UNASSIGNED: Key = key(
    "status.role-unassigned",
    "{role} unassigned from this adapter.",
);
pub const CANCELLED: Key = key("tui.interfaces.cancelled", "Nothing was changed.");
pub const SETUP_FINISHED: Key = key(
    "tui.interfaces.setup-finished",
    "Setup finished. Check here that the connections are the ones you meant.",
);
pub const IMPORT_DONE: Key = key(
    "status.preset-import-completed",
    "Preset imported and activated ({count} rules).",
);
pub const ERROR_UNKNOWN: Key = key("errors.unknown", "Unknown error");

pub const PICK_ADAPTER: Key = key("tui.interfaces.pick-adapter", "Which adapter?");
pub const PICK_ROLE: Key = key("tui.interfaces.pick-role", "What should {name} carry?");
pub const CANCEL: Key = key("action.cancel", "Cancel");
pub const CHOICE_HINT: Key = key(
    "tui.choice.hint",
    "Answer with the number, or with Up, Down and Enter. Esc or an empty answer cancels.",
);
pub const CHOICE_PROMPT: Key = key(
    "tui.choice.prompt",
    "Type the number of your answer and press Enter; an empty line cancels.",
);

pub const UNROUTABLE_TITLE: Key = key(
    "dialog.unroutable-secondary.title",
    "This adapter cannot carry traffic out",
);
pub const UNROUTABLE_ADAPTER: Key = key(
    "dialog.unroutable-secondary.adapter-line",
    "Adapter: {name}",
);
pub const UNROUTABLE_BODY: Key = key(
    "dialog.unroutable-secondary.body-assign",
    "You are about to assign it as your additional route.",
);
pub const UNROUTABLE_BODY_PRIMARY: Key = key(
    "dialog.unroutable-secondary.body-assign-primary",
    "You are about to make it your main connection.",
);
pub const UNROUTABLE_EFFECT: Key = key(
    "dialog.unroutable-secondary.effect-routing",
    "Rules that point at the additional route will not be routed through it.",
);
pub const UNROUTABLE_EFFECT_PRIMARY: Key = key(
    "dialog.unroutable-secondary.effect-routing-primary",
    "The service will not route through it: traffic your rules do not route keeps going the way the system sends it. Choose the connection that reaches the internet as main.",
);
pub const UNROUTABLE_KILL_SWITCH_ON: Key = key(
    "dialog.unroutable-secondary.effect-kill-switch-on",
    "Leak protection is on, so those destinations are BLOCKED instead: the sites behind those rules stop loading.",
);
pub const UNROUTABLE_KILL_SWITCH_OFF: Key = key(
    "dialog.unroutable-secondary.effect-kill-switch-off",
    "Leak protection is off right now, so nothing is blocked. If you turn it on later, those destinations will be blocked.",
);
pub const UNROUTABLE_CONFIRM: Key = key(
    "dialog.unroutable-secondary.confirm-assign",
    "Assign anyway",
);

pub const HELP_SELECT: Key = key(
    "tui.interfaces.help-select",
    "Tab, then Up and Down: choose an adapter",
);
pub const HELP_PRIMARY: Key = key(
    "tui.interfaces.help-primary",
    "p: make the chosen adapter the main connection, or unassign it",
);
pub const HELP_SECONDARY: Key = key(
    "tui.interfaces.help-secondary",
    "s: make the chosen adapter the additional connection, or unassign it",
);
pub const HELP_CHECK: Key = key(
    "tui.interfaces.help-check",
    "x: check each adapter's external address (sends one small packet per adapter)",
);
pub const HELP_REFRESH: Key = key(
    "tui.interfaces.help-refresh",
    "r: read the adapter list again",
);
pub const HELP_BLUETOOTH: Key = key(
    "tui.interfaces.help-bluetooth",
    "b: show or hide Bluetooth adapters",
);
pub const PLAIN_ASSIGN: Key = key(
    "tui.interfaces.plain-assign",
    "a: give an adapter a role or take it away (asks for the adapter's number)",
);

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub const ALL: &[Key] = &[
    ADAPTERS_TITLE,
    DETAILS_TITLE,
    RESULT_TITLE,
    ROLE_EXPLANATION,
    NO_ADAPTERS,
    PLACEHOLDER_TITLE,
    PLACEHOLDER_BODY,
    FAIL_CLOSED_TITLE,
    FAIL_CLOSED_BODY,
    ABSENT_TITLE,
    ABSENT_BODY,
    REMEMBERED,
    EXCLUSIVE_NOTE,
    UNASSIGN_PRIMARY,
    UNASSIGN_SECONDARY,
    ROW_SUMMARY,
    ROW_SUMMARY_2,
    EXTERNAL_PREFIX,
    YES,
    NO,
    PROBE_BUSY,
    PROBE_DONE,
    PROBE_FAILED,
    SAVING,
    NEEDS_SERVICE,
    BINDING_FAILED,
    READ_FAILED,
    ROLE_SET,
    ROLE_UNASSIGNED,
    CANCELLED,
    SETUP_FINISHED,
    IMPORT_DONE,
    ERROR_UNKNOWN,
    PICK_ADAPTER,
    PICK_ROLE,
    CANCEL,
    CHOICE_HINT,
    CHOICE_PROMPT,
    UNROUTABLE_TITLE,
    UNROUTABLE_ADAPTER,
    UNROUTABLE_BODY,
    UNROUTABLE_BODY_PRIMARY,
    UNROUTABLE_EFFECT,
    UNROUTABLE_EFFECT_PRIMARY,
    UNROUTABLE_KILL_SWITCH_ON,
    UNROUTABLE_KILL_SWITCH_OFF,
    UNROUTABLE_CONFIRM,
    HELP_SELECT,
    HELP_PRIMARY,
    HELP_SECONDARY,
    HELP_CHECK,
    HELP_REFRESH,
    HELP_BLUETOOTH,
    PLAIN_ASSIGN,
];
