//! Locale keys of the suggested-addresses screen. The GUI's wording is reused
//! wherever the GUI says the same thing; only terminal-only text is `tui.*`.

use crate::i18n::{key, Key};

pub const TITLE: Key = key("rules.suggestions.inbox.title", "Addresses your sites need");
pub const INTRO: Key = key(
    "rules.suggestions.inbox.intro",
    "These addresses were pulled in by sites you route. Adding one sends it through the additional route together with the site that needs it. Anything you leave alone keeps going through the main route.",
);
pub const LIST_TITLE: Key = key("rules.suggestions.inbox.nav-label", "Suggested addresses");
/// The count the tray menu and the window's sidebar show, from the same number.
pub const LIST_TITLE_COUNTED: Key = key(
    "tray.menu.suggestions-count",
    "Suggested addresses ({count})",
);

pub const MODE: Key = key("label.mode", "Mode");
pub const MODE_OFF: Key = key("settings.routing.auto-rules.mode-off", "Off");
pub const MODE_SUGGEST: Key = key(
    "settings.routing.auto-rules.mode-suggest",
    "Suggest only (default)",
);
pub const MODE_AUTO: Key = key(
    "settings.routing.auto-rules.mode-auto",
    "Apply automatically",
);
pub const YES: Key = key("label.yes", "Yes");
pub const NO: Key = key("label.no", "No");

pub const SORT: Key = key("rules.suggestions.inbox.sort", "Sort");
pub const SORT_MAIN_ROUTE: Key = key(
    "rules.suggestions.inbox.sort-main-route",
    "What the main route can't reach first",
);
pub const SORT_NEWEST: Key = key("rules.suggestions.inbox.sort-newest", "Newest first");
pub const SORT_CONSUMERS: Key = key(
    "rules.suggestions.inbox.sort-consumers",
    "By number of sites",
);
pub const SORT_NAME: Key = key("rules.suggestions.inbox.sort-name", "By name");
pub const SHOW_DISMISSED: Key = key(
    "rules.suggestions.inbox.show-dismissed",
    "Show answered ({n})",
);
pub const SHOW_SERVED: Key = key(
    "rules.suggestions.inbox.show-served-by-main-link",
    "Show ones the main connection already handles ({n})",
);

pub const EMPTY: Key = key(
    "rules.suggestions.inbox.empty",
    "Nothing is waiting for an answer right now.",
);
pub const EMPTY_ANSWERED: Key = key(
    "rules.suggestions.inbox.empty-but-answered",
    "Nothing is waiting for an answer. {n} address(es) you answered earlier are hidden — turn on \"Show answered\" to revisit one.",
);
pub const EMPTY_INERT: Key = key(
    "rules.suggestions.inbox.empty-all-inert",
    "The service saw {count} addresses beside your sites, but each already travels the route it would be sent to — a rule would change nothing. For example: {sample}.",
);
pub const EMPTY_SERVED: Key = key(
    "rules.suggestions.inbox.empty-served-by-main-link",
    "Connections to these {n} address(es) complete over your main connection. If a site still refuses to open, what you are seeing is not a routing failure — the traffic gets through, so a rule here would not change it.",
);

pub const APP_GROUP: Key = key("rules.suggestions.inbox.app-group", "Application {name}");
pub const STATUS_PENDING: Key = key("rules.suggestions.table.status-pending", "Pending");
pub const STATUS_DISMISSED: Key = key("rules.suggestions.table.status-dismissed", "Dismissed");
pub const NEEDED_BY: Key = key("rules.suggestions.inbox.needed-by", "Needed by:");
pub const ANY_ZONE: Key = key(
    "rules.suggestions.inbox.any-zone",
    "The same site in another zone: it can be added as {site}.* instead, every zone at once.",
);
pub const MORE: Key = key("rules.suggestions.inbox.reach-more", "+{count} more");
pub const REACH: Key = key(
    "rules.suggestions.inbox.reach",
    "The rule covers every name under {domain}.",
);
pub const REACH_APP: Key = key(
    "rules.suggestions.inbox.reach-app",
    "The rule sends every connection of {app} through the additional route.",
);
pub const REACH_SEEN: Key = key(
    "rules.suggestions.inbox.reach-seen",
    "Seen so far: {hosts}.",
);
pub const BEHAVIOR_RESPONDS: Key = key(
    "rules.suggestions.inbox.behavior-responds",
    "the main route reaches it",
);
pub const BEHAVIOR_RESPONDS_REFUSING: Key = key(
    "rules.suggestions.inbox.behavior-responds-refusing",
    "the main route reaches it, but the site refuses addresses there",
);
pub const BEHAVIOR_STALLS: Key = key(
    "rules.suggestions.inbox.behavior-stalls",
    "connections to it stall on the main route",
);
pub const BEHAVIOR_UNKNOWN: Key = key(
    "rules.suggestions.inbox.behavior-unknown",
    "not checked on the main route",
);
pub const OWNERSHIP_THIRD_PARTY: Key = key(
    "rules.suggestions.inbox.ownership-third-party",
    "a third-party service the site pulls in",
);
pub const OWNERSHIP_OWN_NAME: Key = key(
    "rules.suggestions.inbox.ownership-own-name",
    "one of the site's own names",
);
pub const OBSERVATIONS: Key = key(
    "tray.auto-rules.detail-observations",
    "seen in {count} visits",
);
pub const AFFINITY: Key = key(
    "tray.auto-rules.detail-affinity",
    "belongs to this site {percent}% of the time",
);
pub const SIGNALS: [Key; 7] = [
    key("tray.auto-rules.signal.brand-related", "shares a name with the site"),
    key(
        "tray.auto-rules.signal.delivery-name",
        "looks like a delivery address of the site",
    ),
    key(
        "tray.auto-rules.signal.co-activity",
        "keeps appearing together with the site",
    ),
    key(
        "tray.auto-rules.signal.placeholder-answer",
        "your provider answered with an address nothing can be reached at",
    ),
    key(
        "tray.auto-rules.signal.app-main-link-blocked",
        "most of the addresses it reached for on the main route kept failing, and none of its traffic goes over the additional route yet",
    ),
    key(
        "tray.auto-rules.signal.main-link-blocked",
        "connections to it kept failing on the main route and none went through",
    ),
    key(
        "tray.auto-rules.signal.app-own-resolver",
        "it looks up site names on its own, so rules by site name do not reach it",
    ),
];

pub const LESS_CERTAIN: Key = key("rules.suggestions.inbox.less-certain", "less certain");
/// What a less certain offer rests on, one per `AUTO_RULE_LESS_CERTAIN_SLUGS`.
pub const LESS_CERTAIN_BASES: [Key; 1] = [key(
    "rules.suggestions.less-certain.brand-seen-once",
    "named like {site}, seen once",
)];

pub const CHECK_BUSY: Key = key(
    "rules.suggestions.inbox.action-check-main-route-busy",
    "Checking...",
);
pub const CHECK_STARTED: Key = key(
    "status.main-route-check-started",
    "Checking {count} addresses over the main connection...",
);
pub const CHECK_NOTHING: Key = key(
    "status.main-route-check-nothing",
    "Everything here was checked recently.",
);
pub const RELOAD_PAGE: Key = key(
    "rules.suggestions.accept.reload-page",
    "The rule is applied. Reload the page you were on (F5) so it picks up the new route.",
);
pub const AUTO_TITLE: Key = key(
    "dialog.auto-rules-mode.title",
    "Turn on “Apply automatically”?",
);
pub const AUTO_BODY: Key = key(
    "dialog.auto-rules-mode.body",
    "From now on NetRuleRouter will add suggested addresses to your rules files by itself, without asking. You can undo this anytime by switching back to “Suggest only”.",
);

pub const NOTICE_TITLE: Key = key("tray.auto-rules.title", "Addresses a site needs");
pub const NOTICE_BODY: Key = key(
    "tray.auto-rules.body",
    "Found addresses without which {name} will not work fully.",
);
/// Headings of a notice about offers that are not a site's companions, one
/// per `nrr_client_logic::auto_rules::NoticeKind`, the tray's words.
pub const NOTICE_TITLE_SITES_BLOCKED: Key = key(
    "tray.auto-rules.title-blocked",
    "Sites the main route will not carry",
);
pub const NOTICE_BODY_SITES_BLOCKED: Key = key(
    "tray.auto-rules.body-blocked",
    "Connections to {name} keep failing on the main route.",
);
pub const NOTICE_TITLE_APP_BLOCKED: Key = key(
    "tray.auto-rules.title-app-blocked",
    "Programs the main route will not carry",
);
pub const NOTICE_BODY_APP_BLOCKED: Key = key(
    "tray.auto-rules.body-app-blocked",
    "No connection of {name} goes through on the main route.",
);
pub const NOTICE_TITLE_APP_OWN_RESOLVER: Key = key(
    "tray.auto-rules.title-app-own-resolver",
    "Programs your site rules do not reach",
);
pub const NOTICE_BODY_APP_OWN_RESOLVER: Key = key(
    "tray.auto-rules.body-app-own-resolver",
    "{name} looks up site names on its own, so rules by site name do not apply to it. A rule for the program sends all of its connections over the additional route.",
);
pub const NOTICE_TITLE_MIXED_BLOCKED: Key = key(
    "tray.auto-rules.title-mixed-blocked",
    "Not getting through on the main route",
);
pub const NOTICE_BODY_MIXED_BLOCKED: Key = key(
    "tray.auto-rules.body-mixed-blocked",
    "The programs and sites below keep failing on the main route.",
);
pub const NOTICE_TITLE_ASSORTED: Key = key("tray.auto-rules.title-assorted", "Suggested rules");
pub const NOTICE_BODY_ASSORTED: Key = key(
    "tray.auto-rules.body-assorted",
    "Each item below says why it is offered.",
);
pub const NOTICE_SITE_FALLBACK: Key = key("tray.auto-rules.site-fallback", "a site you use");
pub const NOTICE_OPEN: Key = key(
    "tui.suggestions.notice-open",
    "To answer, open screen {key}, {screen}.",
);

pub const LOADING: Key = key(
    "tui.suggestions.loading",
    "Reading the suggestions from the service...",
);
pub const ADDED: Key = key("tui.suggestions.added", "Added to your rules: {count}.");
pub const DECLINED: Key = key(
    "tui.suggestions.declined",
    "Will not be suggested again: {count}.",
);
pub const RESTORED: Key = key(
    "tui.suggestions.restored",
    "Can be suggested again: {count}.",
);
pub const AUTO_ON: Key = key(
    "tui.suggestions.auto-on",
    "Suggested addresses are now added automatically.",
);
pub const FAILED: Key = key("tui.suggestions.failed", "Not done: {error}");
pub const NO_ITEM: Key = key(
    "tui.suggestions.no-item",
    "There is no item {n} in the list. Use the number shown before an item.",
);
pub const ITEM_GONE: Key = key(
    "tui.suggestions.item-gone",
    "Item {n} as it was listed is no longer offered. Here is the list as it is now.",
);
pub const NOTHING_TO_DO: Key = key(
    "tui.suggestions.nothing-to-do",
    "Item {n} has nothing this command can act on.",
);
pub const CONFIRM: Key = key(
    "tui.suggestions.confirm",
    "y: turn it on and add item {n}. n: cancel.",
);
pub const CONFIRM_PROMPT: Key = key(
    "tui.suggestions.confirm-prompt",
    "Type y to turn it on or n to cancel, then press Enter.",
);
pub const CANCELLED: Key = key("tui.suggestions.cancelled", "Nothing was changed.");
pub const MARKED: Key = key("tui.suggestions.marked", "Marked: {count}.");
pub const FILTER_ACTIVE: Key = key(
    "rules.suggestions.inbox.filter-active",
    "Showing only what {name} needs",
);
pub const FORGOTTEN: Key = key("tui.suggestions.forgotten", "Forgotten with their answers: {count}. They can be offered again if they turn up beside your sites.");
pub const CLEAR_CONFIRM: Key = key(
    "tui.suggestions.clear-confirm",
    "y: forget all {count} suggestions together with your answers. n: cancel.",
);
pub const CLEAR_PROMPT: Key = key(
    "tui.suggestions.clear-prompt",
    "Type y to forget them all or n to cancel, then press Enter.",
);
pub const SEARCH: Key = key("tui.suggestions.search", "Search");
pub const SEARCH_EMPTY: Key = key(
    "rules.suggestions.inbox.search-empty",
    "No addresses match your search.",
);

pub const HELP_KEYS: &[Key] = &[
    key(
        "tui.suggestions.help.select",
        "Enter or Tab: go to the list; Up and Down: choose an item",
    ),
    key(
        "tui.suggestions.help.add",
        "a: add the chosen item to the additional route",
    ),
    key(
        "tui.suggestions.help.any-zone",
        "z: add the chosen item as its site in every zone (site.*), when it names one",
    ),
    key(
        "tui.suggestions.help.never",
        "n: do not suggest the chosen item again",
    ),
    key(
        "tui.suggestions.help.restore",
        "r: allow the chosen item to be suggested again",
    ),
    key(
        "tui.suggestions.help.always",
        "m: add the chosen item and add suggestions automatically from now on (asks first)",
    ),
    key(
        "tui.suggestions.help.check",
        "c: check the addresses over the main connection",
    ),
    key(
        "tui.suggestions.help.check-site",
        "k: for a site you opened that keeps failing, check whether the network or the site is at fault (opens Diagnostics)",
    ),
    key(
        "tui.suggestions.help.toggles",
        "s: show or hide answered addresses; v: show or hide addresses the main connection handles",
    ),
    key(
        "tui.suggestions.help.order",
        "o: change the order of the list",
    ),
    key(
        "tui.suggestions.help.forget",
        "f: forget the chosen item with its answer, so it can be offered again; x: forget them all (asks first)",
    ),
    key(
        "tui.suggestions.help.search",
        "/: search by domain, host or site; an empty search shows everything",
    ),
    key(
        "tui.suggestions.help.filter-mark",
        "p: show only what the chosen item's first site needs, or everything again; Space: mark items, then a, n, r or f acts on every marked one",
    ),
];

pub const PLAIN_KEYS: &[Key] = &[
    key(
        "tui.suggestions.plain.add",
        "a and an item number, for example a 2: add that item to the additional route",
    ),
    key(
        "tui.suggestions.plain.any-zone",
        "z and an item number: add that item as its site in every zone",
    ),
    key(
        "tui.suggestions.plain.never",
        "n and an item number: do not suggest that item again",
    ),
    key(
        "tui.suggestions.plain.restore",
        "r and an item number: allow that item to be suggested again",
    ),
    key(
        "tui.suggestions.plain.always",
        "m and an item number: add that item and add suggestions automatically from now on (asks first)",
    ),
    key(
        "tui.suggestions.plain.check",
        "c: check the addresses over the main connection",
    ),
    key(
        "tui.suggestions.plain.check-site",
        "k and an item number: check that site, whether the network or the site is at fault",
    ),
    key(
        "tui.suggestions.plain.toggles",
        "s: show or hide answered addresses; v: show or hide addresses the main connection handles",
    ),
    key("tui.suggestions.plain.order", "o: change the order of the list"),
    key(
        "tui.suggestions.plain.forget",
        "f and an item number: forget that item with its answer; x: forget them all (asks first)",
    ),
    key(
        "tui.suggestions.plain.search",
        "/ and text: show only what matches; / on its own shows everything",
    ),
    key(
        "tui.suggestions.plain.filter-mark",
        "p and a site name: show only what that site needs; p on its own shows everything; * and an item number: mark or unmark it, then a, n, r or f and any marked number acts on every marked one",
    ),
];

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub fn all() -> Vec<Key> {
    let mut keys = vec![
        TITLE,
        INTRO,
        LIST_TITLE,
        LIST_TITLE_COUNTED,
        MODE,
        MODE_OFF,
        MODE_SUGGEST,
        MODE_AUTO,
        YES,
        NO,
        SORT,
        SORT_MAIN_ROUTE,
        SORT_NEWEST,
        SORT_CONSUMERS,
        SORT_NAME,
        SHOW_DISMISSED,
        SHOW_SERVED,
        EMPTY,
        EMPTY_ANSWERED,
        EMPTY_INERT,
        EMPTY_SERVED,
        APP_GROUP,
        STATUS_PENDING,
        STATUS_DISMISSED,
        NEEDED_BY,
        ANY_ZONE,
        MORE,
        REACH,
        REACH_APP,
        REACH_SEEN,
        BEHAVIOR_RESPONDS,
        BEHAVIOR_RESPONDS_REFUSING,
        BEHAVIOR_STALLS,
        BEHAVIOR_UNKNOWN,
        OWNERSHIP_THIRD_PARTY,
        OWNERSHIP_OWN_NAME,
        OBSERVATIONS,
        AFFINITY,
        LESS_CERTAIN,
        CHECK_BUSY,
        CHECK_STARTED,
        CHECK_NOTHING,
        RELOAD_PAGE,
        AUTO_TITLE,
        AUTO_BODY,
        NOTICE_TITLE,
        NOTICE_BODY,
        NOTICE_TITLE_SITES_BLOCKED,
        NOTICE_BODY_SITES_BLOCKED,
        NOTICE_TITLE_APP_BLOCKED,
        NOTICE_BODY_APP_BLOCKED,
        NOTICE_TITLE_APP_OWN_RESOLVER,
        NOTICE_BODY_APP_OWN_RESOLVER,
        NOTICE_TITLE_MIXED_BLOCKED,
        NOTICE_BODY_MIXED_BLOCKED,
        NOTICE_TITLE_ASSORTED,
        NOTICE_BODY_ASSORTED,
        NOTICE_SITE_FALLBACK,
        NOTICE_OPEN,
        LOADING,
        ADDED,
        DECLINED,
        RESTORED,
        AUTO_ON,
        FAILED,
        NO_ITEM,
        ITEM_GONE,
        NOTHING_TO_DO,
        CONFIRM,
        CONFIRM_PROMPT,
        CANCELLED,
        FORGOTTEN,
        CLEAR_CONFIRM,
        CLEAR_PROMPT,
        SEARCH,
        SEARCH_EMPTY,
        MARKED,
        FILTER_ACTIVE,
    ];
    keys.extend(SIGNALS);
    keys.extend(LESS_CERTAIN_BASES);
    keys.extend_from_slice(HELP_KEYS);
    keys.extend_from_slice(PLAIN_KEYS);
    keys
}
