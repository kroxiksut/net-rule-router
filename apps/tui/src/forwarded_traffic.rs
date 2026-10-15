//! WSL running with no answer for what it gets while the tunnel is down: told
//! on the feed once per appearance, as the window raises its notice. The
//! answer is given in Settings → Routing.

use nrr_client_logic::forwarded;

use crate::i18n::Texts;
use crate::keys;
use crate::state::{AppState, Effect, NoticeLevel};

#[derive(Debug, Default)]
pub struct ForwardedTrafficState {
    raised: bool,
}

/// WSL's adapter is among the ones the service reported, on a platform that
/// can act on the answer.
pub fn running(app: &AppState) -> bool {
    app.settings.supports.forwarded_traffic_guard
        && app.snapshot.as_ref().is_some_and(|snapshot| {
            forwarded::forwarding_present(
                snapshot.adapters.rows.iter().map(|row| row.name.as_str()),
            )
        })
}

/// One reading, taken with every snapshot.
pub fn reading(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let present = running(app);
    let policy = app.snapshot.as_ref().and_then(|s| s.route_policy.as_ref());
    let routed = policy.is_some_and(|p| p.secondary.is_some());
    let answer = policy.map_or("", |p| p.forwarded_outage.as_str());
    let step = forwarded::notice_step(app.forwarded_traffic.raised, present, routed, answer);
    app.forwarded_traffic.raised = step.raised;
    if !step.raise {
        return Vec::new();
    }
    let body = format!(
        "{} {}",
        texts.get(keys::FORWARDED_BODY),
        texts.get(keys::ANSWER_IN_ROUTING_HINT)
    );
    app.notify(
        NoticeLevel::Info,
        texts.get(keys::FORWARDED_TITLE),
        body,
        now,
    )
}

#[cfg(test)]
mod tests;
