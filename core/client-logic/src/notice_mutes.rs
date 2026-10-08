//! "Don't show…" for whole notice kinds: which kinds a user may hide, for how
//! long, and the `block-notices.mutes.set` request a choice becomes
//! (`MUTABLE_NOTICE_KINDS`, `NOTICE_MUTE_CHOICES_MS`, `noticeKindMuted`,
//! `noticeMuteRequest` in `pure.js`).

use serde_json::{json, Value};

use crate::js;

/// A notice kind a user may hide, with the title it is listed under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutableNoticeKind {
    pub slug: &'static str,
    pub title_key: &'static str,
    pub title_en: &'static str,
}

/// Mirrors `NoticeKind` in `nrr-domain`, which refuses any other slug.
pub const MUTABLE_NOTICE_KINDS: [MutableNoticeKind; 7] = [
    MutableNoticeKind {
        slug: "block-notice-backlog",
        title_key: "notifications.block-notice.backlog.title",
        title_en: "Blocked while the app was closed",
    },
    MutableNoticeKind {
        slug: "external-address",
        title_key: "tray.external-address.title",
        title_en: "Additional route connected",
    },
    MutableNoticeKind {
        slug: "enforcement-restored",
        title_key: "notifications.enforcement.restored.title",
        title_en: "Routing is working again",
    },
    MutableNoticeKind {
        slug: "unassigned-tunnel",
        title_key: "notifications.unassigned-tunnel.title",
        title_en: "The additional route is not assigned",
    },
    MutableNoticeKind {
        slug: "local-networks",
        title_key: "notifications.local-networks.title",
        title_en: "A local network was found",
    },
    MutableNoticeKind {
        slug: "rules-drift",
        title_key: "tray.rules-drift.title",
        title_en: "Your rules files differ from what is applied",
    },
    MutableNoticeKind {
        slug: "secondary-down",
        title_key: "notifications.enforcement.secondary-down.title",
        title_en: "The additional connection is not up",
    },
];

/// How long each answer of the chooser holds, in milliseconds; 0 is "until
/// lifted".
pub const NOTICE_MUTE_CHOICES_MS: [(&str, i64); 4] = [
    ("1d", 24 * 60 * 60 * 1000),
    ("7d", 7 * 24 * 60 * 60 * 1000),
    ("30d", 30 * 24 * 60 * 60 * 1000),
    ("forever", 0),
];

fn is_mutable(kind: &str) -> bool {
    MUTABLE_NOTICE_KINDS.iter().any(|k| k.slug == kind)
}

fn choice_span(choice: &str) -> Option<i64> {
    NOTICE_MUTE_CHOICES_MS
        .iter()
        .find(|(slug, _)| *slug == choice)
        .map(|(_, span)| *span)
}

/// Whether a `block-notices.mutes.list` answer silences notice `kind` at
/// `now_ms`. Anything but an array silences nothing.
pub fn notice_kind_muted(mutes: &Value, kind: &str, now_ms: i64) -> bool {
    let Some(list) = mutes.as_array() else {
        return false;
    };
    list.iter().any(|mute| {
        let scope = mute.get("scope").filter(|s| js::is_truthy(s));
        let field = |name: &str| scope.and_then(|s| s.get(name));
        if field("kind") != Some(&Value::from("notice")) {
            return false;
        }
        let notice = field("notice")
            .filter(|n| js::is_truthy(n))
            .map(js::to_display_string)
            .unwrap_or_default();
        if notice != kind {
            return false;
        }
        let until = mute
            .get("until-unix-ms")
            .filter(|u| js::is_truthy(u))
            .map_or(0.0, js::to_number);
        // NaN is not above zero either, so it reads as "until lifted".
        until.is_nan() || until <= 0.0 || (now_ms as f64) < until
    })
}

/// The `block-notices.mutes.set` request for a chooser answer, or `None` for a
/// kind or an answer the chooser does not offer. "Until lifted" leaves the
/// deadline off.
pub fn notice_mute_request(kind: &str, choice: &str, now_ms: i64) -> Option<Value> {
    if !is_mutable(kind) {
        return None;
    }
    let span = choice_span(choice)?;
    let mut request = json!({ "scope": { "kind": "notice", "notice": kind } });
    if span > 0 {
        request["until-unix-ms"] = Value::from(now_ms.saturating_add(span));
    }
    Some(request)
}
