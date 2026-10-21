//! Whether the service left the system DNS redirected, and when a client
//! raises the notice about it.
//!
//! The state is read from a health answer, which also arrives at every
//! connect, so a client that was not running when it happened still learns of
//! it; the `system-dns-not-restored` push is the same reading, delivered at
//! once.

use serde_json::Value;

use crate::js;

/// What the service's `apply` health message opens with when the resolver
/// could not hand the system DNS back (`SYSTEM_DNS_NOT_RESTORED` in
/// `nrr-shared`).
pub const SYSTEM_DNS_NOT_RESTORED: &str = nrr_shared::ipc_payloads::SYSTEM_DNS_NOT_RESTORED;

/// Whether a health answer says the system DNS was not restored
/// (`systemDnsNotRestored`).
pub fn not_restored(health: &Value) -> bool {
    let Some(Value::Array(components)) = health.get("components") else {
        return false;
    };
    components.iter().any(|component| {
        component.get("component") == Some(&Value::String("apply".to_owned()))
            && component
                .get("message")
                .filter(|m| js::is_truthy(m))
                .is_some_and(|m| js::to_display_string(m).contains(SYSTEM_DNS_NOT_RESTORED))
    })
}

/// One reading of the state, from a push or a health answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoticeStep {
    /// Raise the notice now.
    pub raise: bool,
    /// What to remember for the next reading.
    pub raised: bool,
}

/// Raise the notice when the state appears; while it lasts, a notice the user
/// dismissed stays down; once it clears, the next occurrence is news again
/// (`systemDnsNoticeStep`).
pub fn notice_step(was_raised: bool, not_restored: bool) -> NoticeStep {
    NoticeStep {
        raise: not_restored && !was_raised,
        raised: not_restored,
    }
}

/// What the `adapters` health message opens with when a full-tunnel VPN lets
/// only its own resolver answer (`DNS_ONLY_FOREIGN_RESOLVER` in `nrr-shared`).
pub const DNS_ONLY_FOREIGN_RESOLVER: &str = nrr_shared::ipc_payloads::DNS_ONLY_FOREIGN_RESOLVER;

/// Whether a health answer says only another VPN's resolver answers, so the
/// service's name handling is lifted (`dnsUpstreamForeignOnly`).
pub fn upstream_foreign_only(health: &Value) -> bool {
    let Some(Value::Array(components)) = health.get("components") else {
        return false;
    };
    components.iter().any(|component| {
        component.get("component") == Some(&Value::String("adapters".to_owned()))
            && component
                .get("message")
                .filter(|m| js::is_truthy(m))
                .is_some_and(|m| js::to_display_string(m).starts_with(DNS_ONLY_FOREIGN_RESOLVER))
    })
}

/// Same step as [`notice_step`], for the foreign-resolver state
/// (`dnsUpstreamForeignNoticeStep`).
pub fn foreign_only_notice_step(was_raised: bool, foreign_only: bool) -> NoticeStep {
    notice_step(was_raised, foreign_only)
}
