//! Locale keys of the overlaps screen. The GUI's wording is reused wherever
//! the GUI says the same thing; only terminal-only text is `tui.*`.

use crate::i18n::{key, Key};

pub const TITLE: Key = key("rules.overlaps.nav-label", "Overlaps");
pub const INTRO: Key = key(
    "rules.overlaps.intro",
    "When rules of the two routes cover the same sites or addresses, the narrower rule wins: an exact name beats a wildcard, a wildcard beats a zone, a longer name beats a shorter one; an exact address beats a subnet or range, a smaller network beats a larger one. Check that each item below goes where you want it to: confirm it, or send it over the other route. Changes go to your rules list, where you review and apply them.",
);
pub const PAIRS_TITLE: Key = key(
    "tui.overlaps.pairs-title",
    "Rules that cover the same sites",
);
pub const PENDING_COUNT: Key = key(
    "rules.overlaps.pending-badge",
    "{n} overlap(s) not confirmed",
);
pub const SHOW_RESOLVED: Key = key("rules.overlaps.show-resolved", "Show resolved");
pub const YES: Key = key("label.yes", "Yes");
pub const NO: Key = key("label.no", "No");
pub const EMPTY: Key = key(
    "rules.overlaps.empty",
    "No rules of the two routes cover the same sites or addresses.",
);
pub const ALL_RESOLVED: Key = key("rules.overlaps.all-resolved", "Every overlap is resolved.");

pub const RULE: Key = key("rules.overlaps.rule", "{value} ({type})");
pub const NESTED: Key = key(
    "rules.overlaps.nested",
    "{winner} goes over {winner-route}: it is narrower than {loser} on {loser-route}.",
);
pub const DUPLICATE: Key = key(
    "rules.overlaps.duplicate",
    "{winner} is set on both routes. It goes over {winner-route}: on a tie the main route wins.",
);
pub const INTERSECTING: Key = key(
    "rules.overlaps.intersecting",
    "{winner} and {loser} on {loser-route} share some addresses. Each shared address takes the narrower rule; most of them go over {winner-route}.",
);
pub const BLOCK_TIE: Key = key(
    "rules.overlaps.block-tie",
    "{winner} names the same sites as {loser} on {loser-route}. They are blocked: on a tie a block wins over a route.",
);
pub const BLOCK_TIE_WARNING: Key = key(
    "rules.overlaps.block-tie-warning",
    "The other rule names the same sites and never applies.",
);
pub const MAIN_STAYS: Key = key(
    "rules.overlaps.main-stays",
    "Addresses of the main link inside this network stay on the main link even when the additional link is down. Leak protection does not block them.",
);
pub const REASON_LABEL: Key = key("rules.overlaps.column.reason", "Why it wins");
pub const REASON_NESTED: Key = key("rules.overlaps.reason.nested", "Narrower rule");
pub const REASON_DUPLICATE: Key = key(
    "rules.overlaps.reason.duplicate",
    "Same rule on both routes",
);
pub const REASON_INTERSECTING: Key = key(
    "rules.overlaps.reason.intersecting",
    "Narrower where they meet",
);
pub const REASON_BLOCK_TIE: Key = key("rules.overlaps.reason.block-tie", "A block wins a tie");
pub const DECISION_LABEL: Key = key("rules.overlaps.column.decision", "Decision");
pub const CONFIRMED: Key = key("rules.overlaps.confirmed", "Confirmed");
pub const NOT_CONFIRMED: Key = key("tui.overlaps.not-confirmed", "Not confirmed");
pub const SEND_OVER: Key = key("rules.overlaps.send-over", "Send over {route} instead");
pub const SEND_OVER_WHOLE: Key = key(
    "rules.overlaps.send-over-whole",
    "This moves the whole rule, including addresses the other rule does not cover.",
);
pub const BLOCK_NOTE: Key = key(
    "rules.overlaps.block-note",
    "A block rule is part of this pair; change it in the rules list.",
);

pub const CONFLICTS_TITLE: Key = key(
    "rules.overlaps.conflicts.title",
    "Conflicts in the applied rules",
);
pub const CONFLICTS_HINT: Key = key(
    "rules.overlaps.conflicts.hint",
    "Rules the service enforces differently from how they read, as it enforces them now. They update after you apply changes.",
);
pub const CONFLICT_LITERAL_BLOCK: Key = key(
    "rules.overlaps.conflicts.literal-block",
    "{rule}: {host} resolves to {ip}, and a block of that address wins over any name rule, so the address is blocked.",
);
pub const CONFLICT_LEAK: Key = key(
    "rules.overlaps.conflicts.leak",
    "{rule} does not block {host}: it shares {ip} with {via}, which a narrower rule routes, so the address stays open.",
);
pub const CONFLICT_UNSUPPORTED: Key = key(
    "rules.overlaps.conflicts.unsupported-shape",
    "{rule} for {app} is not enforced: a rule that limits an address to one application cannot be carried out yet, so it is skipped rather than applied to every application.",
);
pub const CONFLICT_CARVING_OVER_CAP: Key = key(
    "rules.overlaps.conflicts.carving-over-cap",
    "{rule} holds more narrower rules than can be carved out of it, so it applies to its whole network and the narrower rules inside it do not take effect. Split it into smaller networks.",
);
pub const CONFLICT_MORE: Key = key(
    "rules.overlaps.conflicts.more",
    "Addresses affected besides this one: {count}.",
);

pub const ROUTE_PRIMARY: Key = key("label.primary", "Primary");
pub const ROUTE_SECONDARY: Key = key("label.secondary", "Additional");
pub const ROUTE_BLOCK: Key = key("label.block", "Block");
pub const TYPE_DOMAIN: Key = key("rules.type.domain", "Domain");
pub const TYPE_ZONE: Key = key("rules.type.zone", "Zone");
pub const TYPE_EXACT_IP: Key = key("rules.type.exact-ip", "Exact IP");
pub const TYPE_SUBNET: Key = key("rules.type.subnet", "Subnet (CIDR)");
pub const TYPE_IP_RANGE: Key = key("rules.type.ip-range", "IP range");

pub const PREVIEW_NOTICE: Key = key(
    "rules.preview-notice",
    "Rule changes take effect only after you review and apply them.",
);
pub const APPLY_ON_RULES: Key = key(
    "tui.overlaps.apply-on-rules",
    "Review and apply the change on screen {key}, {screen}.",
);
pub const LOADING: Key = key(
    "tui.overlaps.loading",
    "Reading your rules from the service...",
);
pub const FAILED: Key = key("tui.overlaps.failed", "Could not read your rules: {error}");
pub const NO_ITEM: Key = key(
    "tui.overlaps.no-item",
    "There is no item {n} in the list. Use the number shown before an item.",
);
pub const CANNOT_SEND: Key = key(
    "tui.overlaps.cannot-send",
    "Item {n} cannot be sent over the other route here; change it in the rules list.",
);
pub const GONE: Key = key(
    "tui.overlaps.gone",
    "The rules of item {n} changed in the meantime; nothing was sent.",
);
pub const LOCKED: Key = key(
    "tui.rules.busy",
    "Wait until the rules are applied; the list cannot change meanwhile.",
);

pub const HELP_KEYS: &[Key] = &[
    key(
        "tui.overlaps.help.select",
        "Enter or Tab: go to the list; Up and Down: choose an item",
    ),
    key(
        "tui.overlaps.help.confirm",
        "c: confirm the chosen item is correct",
    ),
    key(
        "tui.overlaps.help.confirm-all",
        "Shift+C: confirm every item",
    ),
    key(
        "tui.overlaps.help.unconfirm",
        "u: ask about the chosen item again",
    ),
    key(
        "tui.overlaps.help.send-over",
        "o: send the chosen item's sites over the other route instead",
    ),
    key(
        "tui.overlaps.help.show-resolved",
        "s: show or hide confirmed items",
    ),
];

pub const PLAIN_KEYS: &[Key] = &[
    key(
        "tui.overlaps.plain.confirm",
        "c and an item number, for example c 2: confirm that item is correct; c all: confirm every item",
    ),
    key(
        "tui.overlaps.plain.unconfirm",
        "u and an item number: ask about that item again",
    ),
    key(
        "tui.overlaps.plain.send-over",
        "o and an item number: send that item's sites over the other route instead",
    ),
    key("tui.overlaps.plain.show-resolved", "s: show or hide confirmed items"),
];

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub fn all() -> Vec<Key> {
    let mut keys = vec![
        TITLE,
        INTRO,
        PAIRS_TITLE,
        PENDING_COUNT,
        SHOW_RESOLVED,
        YES,
        NO,
        EMPTY,
        ALL_RESOLVED,
        RULE,
        NESTED,
        DUPLICATE,
        INTERSECTING,
        BLOCK_TIE,
        BLOCK_TIE_WARNING,
        MAIN_STAYS,
        REASON_LABEL,
        REASON_NESTED,
        REASON_DUPLICATE,
        REASON_INTERSECTING,
        REASON_BLOCK_TIE,
        DECISION_LABEL,
        CONFIRMED,
        NOT_CONFIRMED,
        SEND_OVER,
        SEND_OVER_WHOLE,
        BLOCK_NOTE,
        CONFLICTS_TITLE,
        CONFLICTS_HINT,
        CONFLICT_LITERAL_BLOCK,
        CONFLICT_LEAK,
        CONFLICT_CARVING_OVER_CAP,
        CONFLICT_UNSUPPORTED,
        CONFLICT_MORE,
        ROUTE_PRIMARY,
        ROUTE_SECONDARY,
        ROUTE_BLOCK,
        TYPE_DOMAIN,
        TYPE_ZONE,
        TYPE_EXACT_IP,
        TYPE_SUBNET,
        TYPE_IP_RANGE,
        PREVIEW_NOTICE,
        APPLY_ON_RULES,
        LOADING,
        FAILED,
        NO_ITEM,
        CANNOT_SEND,
        GONE,
        LOCKED,
    ];
    keys.extend_from_slice(HELP_KEYS);
    keys.extend_from_slice(PLAIN_KEYS);
    keys
}
