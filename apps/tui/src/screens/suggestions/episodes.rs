use nrr_client_logic::discovery_probe::{discovery_previous_probe, discovery_probe_queue};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::DiscoveryEpisodeDto;

use crate::i18n::{key, Key, Texts};
use crate::view::ViewLine;

pub const TITLE: Key = key("rules.suggestions.episode.title", "Why no site suggestion?");

pub const INTRO: Key = key("rules.suggestions.episode.intro", "Recent decisions for your connections. A TCP or TLS response alone does not prove that a page loaded. You can check a domain even when its name was not observed.");

pub const EMPTY: Key = key("rules.suggestions.episode.empty", "No recent discovery evidence is available. This does not establish whether the site works. Enter its domain to check it.");

pub const UNKNOWN_HOST: Key = key(
    "rules.suggestions.episode.unknown-host",
    "Site name unknown",
);

pub const OMITTED: Key = key(
    "rules.suggestions.episode.omitted",
    "{count} older episodes are no longer retained.",
);

const RULES_UNAVAILABLE: Key = key(
    "rules.suggestions.episode.reason.rules-unavailable",
    "Waiting for the rule set to become available. No probe is sent until it can be evaluated.",
);

const STATES: &[Key] = &[
    key(
        "rules.suggestions.episode.state.not-created",
        "No offer created",
    ),
    key("rules.suggestions.episode.state.deferred", "Deferred"),
    key("rules.suggestions.episode.state.hidden", "Hidden"),
    key("rules.suggestions.episode.state.ready", "Ready to offer"),
    key(
        "rules.suggestions.episode.state.delivered",
        "Delivered to a client surface",
    ),
];

const REASONS: &[Key] = &[
    key("rules.suggestions.episode.reason.certificate-untrusted", "The HTTPS certificate was not trusted on the checked connection. No successful page response was confirmed; the routing rule remains in force."),
    key("rules.suggestions.episode.reason.own-process", "This is NetRuleRouter's own service traffic. It is not used to learn application rules or browser outcomes."),
    key("rules.suggestions.episode.reason.scope-unconfirmed", "The observed names do not establish that the whole domain fails. A fresh check of the exact name is required."),
    key("rules.suggestions.episode.reason.http-answered", "An HTTPS request returned a response on the checked connection. This does not certify the browser page."),
    key("rules.suggestions.episode.reason.http-no-answer", "No usable HTTPS response was received on the checked connection."),
    key("rules.suggestions.episode.reason.http-client-error", "The server returned an HTTP access or request error. This is not proof of a network block."),
    key("rules.suggestions.episode.reason.http-server-error", "The server returned an HTTP server error. This is not proof of a network block."),
    key("rules.suggestions.episode.reason.name-unknown", "The service could not identify the site name. Enter its domain to check it."),
    key("rules.suggestions.episode.reason.name-ambiguous", "Several site names share this address. The service cannot safely choose one."),
    key("rules.suggestions.episode.reason.insufficient-evidence", "There is not enough repeated failure evidence yet."),
    key("rules.suggestions.episode.reason.primary-responds", "The main connection answered the probe. This does not prove that the HTTPS page loaded."),
    key("rules.suggestions.episode.reason.connection-reset", "A connection reset was observed. Repeated failures still need confirmation."),
    key("rules.suggestions.episode.reason.close-unknown", "The connection closed for an unknown reason. A successful page load is not established."),
    key("rules.suggestions.episode.reason.own-block", "NetRuleRouter blocked this connection. It is not counted as an external failure."),
    key("rules.suggestions.episode.reason.already-covered", "An existing rule already covers this destination."),
    key("rules.suggestions.episode.reason.user-dismissed", "You asked not to suggest this site again."),
    key("rules.suggestions.episode.reason.discovery-disabled", "Site suggestions are turned off."),
    key("rules.suggestions.episode.reason.no-active-rules", "Discovery has no active rule book to evaluate."),
    RULES_UNAVAILABLE,
    key("rules.suggestions.episode.reason.default-secondary", "The default route already uses the additional connection."),
    key("rules.suggestions.episode.reason.platform-infrastructure", "This connection belongs to network infrastructure rather than a site offer."),
    key("rules.suggestions.episode.reason.pulled-in", "This was a background resource loaded by another site, not a site you opened."),
    key("rules.suggestions.episode.reason.auto-probe-disabled", "Automatic connection checks are off. The additional connection has not been verified."),
    key("rules.suggestions.episode.reason.probe-pending", "The connection check has not finished."),
    key("rules.suggestions.episode.reason.probe-queued", "The site is queued for an automatic check. It will start when capacity is available, if DNS evidence and your permissions remain valid."),
    key("rules.suggestions.episode.reason.probe-inconclusive", "The connection check did not produce a reliable result."),
    key("rules.suggestions.episode.reason.probe-cooldown", "This site was checked recently. The next automatic check is delayed."),
    key("rules.suggestions.episode.reason.probe-budget-exhausted", "The automatic check limit for this period has been reached."),
    key("rules.suggestions.episode.reason.probe-memory-limit", "The automatic check queue is full. This check was not started."),
    key("rules.suggestions.episode.reason.probe-workers-busy", "All automatic check workers are busy. This check was not started."),
    key("rules.suggestions.episode.reason.probe-start-failed", "The automatic check could not be started."),
    key("rules.suggestions.episode.reason.probe-no-address", "No address was available for the domain you entered. The connection check could not start."),
    key("rules.suggestions.episode.reason.https-unconfirmed", "The connection check answered, but a successful HTTPS page response has not been established."),
    key("rules.suggestions.episode.reason.secondary-unavailable", "The additional connection is unavailable."),
    key("rules.suggestions.episode.reason.secondary-failed", "The site did not answer the additional connection check."),
    key("rules.suggestions.episode.reason.offer-ready", "An offer is ready for review."),
    key("rules.suggestions.episode.reason.no-subscriber", "No client was connected to receive the offer. It remains available when a client reconnects."),
    key("rules.suggestions.episode.reason.awaiting-client", "A client received the offer but has not reported displaying it yet."),
    key("rules.suggestions.episode.reason.notification-pacing", "The notification is deferred by the time limit between notices."),
    key("rules.suggestions.episode.reason.notifications-muted", "Notifications are muted. The offer remains in Suggested addresses."),
    key("rules.suggestions.episode.reason.client-busy", "The client is showing another notice. This offer has not been shown yet."),
    key("rules.suggestions.episode.reason.client-filter", "The client filtered this offer from its current notice."),
    key("rules.suggestions.episode.reason.shown", "A client surface reported that it presented this offer."),
    key("rules.suggestions.episode.reason.expired", "The discovery episode expired."),
    key("rules.suggestions.episode.reason.capacity-limit", "Older evidence was dropped to keep discovery memory bounded."),
    key("rules.suggestions.episode.reason.unsupported-observation", "This platform cannot observe this kind of connection failure."),
];

const LIMITATIONS: &[Key] = &[
    key("rules.suggestions.episode.limitation.os-dns-cache-unavailable", "This platform cannot read the system DNS cache. Browser cache or encrypted DNS may leave the site name unknown."),
    key("rules.suggestions.episode.limitation.passive-reset-unavailable", "Passive connection reset observation is unavailable on this platform."),
    key("rules.suggestions.episode.limitation.discovery-identity-unavailable", "Recent discovery evidence cannot be recorded because a private session identity could not be created. Routing and suggestions continue to work."),
];

const QUEUE_AHEAD: Key = key(
    "rules.suggestions.episode.queue.ahead",
    "Your queued checks ahead: {count}.",
);
const QUEUE_PAUSE: Key = key(
    "rules.suggestions.episode.queue.pause",
    "Pause before another check: at least {seconds} s.",
);
const QUEUE_SNAPSHOT: Key = key(
    "rules.suggestions.episode.queue.snapshot",
    "At the last update. This is not a start or completion estimate.",
);
const QUEUE_STARTED: Key = key(
    "rules.suggestions.episode.queue.started",
    "Last check started: {time}.",
);
const QUEUE_PREVIOUS: Key = key(
    "rules.suggestions.episode.queue.previous",
    "Retained check result at {time}: {result}",
);
const QUEUE_PREVIOUS_ABSENT: Key = key(
    "rules.suggestions.episode.queue.previous-absent",
    "No previous check result is retained in this history.",
);
const QUEUE_WAIT: &[Key] = &[
    key(
        "rules.suggestions.episode.queue.wait.resources",
        "Waiting for space to track automatic checks. This check stays queued.",
    ),
    RULES_UNAVAILABLE,
    key(
        "rules.suggestions.episode.queue.wait.rate",
        "Waiting for the automatic check rate limit.",
    ),
    key(
        "rules.suggestions.episode.queue.wait.workers",
        "Waiting for other automatic checks to finish.",
    ),
    key(
        "rules.suggestions.episode.queue.wait.cooldown",
        "Waiting for this site's repeat-check pause.",
    ),
    key(
        "rules.suggestions.episode.queue.wait.ahead",
        "Waiting behind your earlier queued checks.",
    ),
    key(
        "rules.suggestions.episode.queue.wait.scheduled",
        "Waiting for the next automatic check.",
    ),
];

fn probe_details(episode: &DiscoveryEpisodeDto, texts: &Texts) -> Vec<ViewLine> {
    let raw = serde_json::to_value(&episode.probe_queue).unwrap_or_default();
    let queue = discovery_probe_queue(&raw);
    let Some(kind) = queue["kind"].as_str() else {
        return Vec::new();
    };
    let mut lines = vec![ViewLine::text(translated(
        texts,
        QUEUE_WAIT,
        if kind == "rules" {
            "rules-unavailable"
        } else {
            kind
        },
        key(
            "rules.suggestions.episode.reason-unknown",
            "No further detail is available.",
        ),
    ))];
    lines.push(ViewLine::text(
        texts.fill(QUEUE_AHEAD, &[("count", queue["ahead"].to_string())]),
    ));
    if let Some(seconds) = queue["seconds"].as_u64() {
        lines.push(ViewLine::text(
            texts.fill(QUEUE_PAUSE, &[("seconds", seconds.to_string())]),
        ));
    }
    lines.push(ViewLine::text(texts.get(QUEUE_SNAPSHOT)));
    if let Some(started) = queue["started"].as_i64() {
        lines.push(ViewLine::text(texts.fill(
            QUEUE_STARTED,
            &[("time", crate::screens::inspect::wall_clock(started))],
        )));
    }
    let history = serde_json::to_value(&episode.history).unwrap_or_default();
    let previous = discovery_previous_probe(&history);
    if let (Some(reason), Some(at)) = (previous["reason"].as_str(), previous["at-unix-ms"].as_i64())
    {
        let result = translated(
            texts,
            REASONS,
            reason,
            key(
                "rules.suggestions.episode.reason-unknown",
                "No further detail is available.",
            ),
        );
        lines.push(ViewLine::text(texts.fill(
            QUEUE_PREVIOUS,
            &[
                ("time", crate::screens::inspect::wall_clock(at)),
                ("result", result),
            ],
        )));
    } else {
        lines.push(ViewLine::text(texts.get(QUEUE_PREVIOUS_ABSENT)));
    }
    lines
}

fn translated(texts: &Texts, keys: &[Key], slug: &str, fallback: Key) -> String {
    keys.iter()
        .find(|key| key.id.rsplit('.').next() == Some(slug))
        .map_or_else(|| texts.get(fallback), |key| texts.get(*key))
}

pub fn lines(
    episodes: &[DiscoveryEpisodeDto],
    omitted: u64,
    limitations: &[String],
    texts: &Texts,
) -> Vec<ViewLine> {
    let mut lines = vec![ViewLine::text(texts.get(INTRO))];
    if episodes.is_empty() {
        lines.push(ViewLine::text(texts.get(EMPTY)));
    }
    for limitation in limitations {
        lines.push(ViewLine::text(translated(
            texts,
            LIMITATIONS,
            limitation,
            key(
                "rules.suggestions.episode.limitation-unknown",
                "An observation capability is unavailable on this platform.",
            ),
        )));
    }
    for episode in episodes {
        let name = episode
            .host
            .as_deref()
            .or(episode.destination.as_deref())
            .map(|name| display_text(name).into_owned())
            .unwrap_or_else(|| texts.get(UNKNOWN_HOST));
        let state = translated(
            texts,
            STATES,
            &episode.state,
            key(
                "rules.suggestions.episode.state-unknown",
                "State unavailable",
            ),
        );
        let reason = translated(
            texts,
            REASONS,
            &episode.reason,
            key(
                "rules.suggestions.episode.reason-unknown",
                "No further detail is available.",
            ),
        );
        lines.push(ViewLine::text(format!("{name} · {state}")));
        lines.push(ViewLine::text(reason));
        lines.extend(probe_details(episode, texts));
        if let Some(limitation) = &episode.platform_limitation {
            lines.push(ViewLine::text(translated(
                texts,
                LIMITATIONS,
                limitation,
                key(
                    "rules.suggestions.episode.limitation-unknown",
                    "An observation capability is unavailable on this platform.",
                ),
            )));
        }
    }
    if omitted > 0 {
        lines.push(ViewLine::text(
            texts.fill(OMITTED, &[("count", omitted.to_string())]),
        ));
    }
    lines
}

#[cfg(test)]
pub fn all_keys() -> Vec<Key> {
    let mut keys = vec![TITLE, INTRO, EMPTY, UNKNOWN_HOST, OMITTED];
    keys.extend_from_slice(STATES);
    keys.extend_from_slice(REASONS);
    keys.extend_from_slice(LIMITATIONS);
    keys.extend_from_slice(QUEUE_WAIT);
    keys.extend_from_slice(&[
        QUEUE_AHEAD,
        QUEUE_PAUSE,
        QUEUE_SNAPSHOT,
        QUEUE_STARTED,
        QUEUE_PREVIOUS,
        QUEUE_PREVIOUS_ABSENT,
    ]);
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resource_or_rule_wait_is_explained_without_a_countdown() {
        for (kind, phrase) in [("resources", "space to track"), ("rules", "rule set")] {
            let episode: DiscoveryEpisodeDto = serde_json::from_value(json!({
                "id":"private", "host":"site.example", "destination":null,
                "state":"deferred", "reason":"probe-queued", "stage":"probe",
                "first-seen-unix-ms":1000, "last-seen-unix-ms":2000,
                "candidate-id":null, "platform-limitation":null,
                "probe-queue":{"wait-kind":kind, "queued-ahead":0,"eligible-in-ms":1000}
            }))
            .unwrap_or_else(|error| panic!("episode: {error}"));
            let text = lines(&[episode], 0, &[], &Texts::fallback_only())
                .iter()
                .map(ViewLine::plain_text)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains(phrase), "{text}");
            assert!(!text.contains("at least"), "{text}");
            assert!(
                text.contains("not a start or completion estimate"),
                "{text}"
            );
        }
    }

    #[test]
    fn a_rate_limited_site_shows_its_own_queue_and_never_promises_a_completion_time() {
        let episode: DiscoveryEpisodeDto = serde_json::from_value(json!({
            "id":"private", "host":"site.example", "destination":null,
            "state":"deferred", "reason":"probe-queued", "stage":"probe",
            "first-seen-unix-ms":1000, "last-seen-unix-ms":2000,
            "candidate-id":null, "platform-limitation":null,
            "probe-queue":{"wait-kind":"rate", "queued-ahead":3,
                "eligible-in-ms":1875, "last-probe-started-unix-ms":null}
        }))
        .unwrap_or_else(|error| panic!("episode: {error}"));
        let text = lines(&[episode], 0, &[], &Texts::fallback_only())
            .iter()
            .map(ViewLine::plain_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("Waiting for the automatic check rate limit"),
            "{text}"
        );
        assert!(text.contains("Your queued checks ahead: 3"), "{text}");
        assert!(text.contains("at least 2 s"), "{text}");
        assert!(
            text.contains("not a start or completion estimate"),
            "{text}"
        );
    }

    #[test]
    fn worker_wait_does_not_invent_a_timer_or_erase_a_retained_measurement() {
        let episode: DiscoveryEpisodeDto = serde_json::from_value(json!({
            "id":"private", "host":"site.example", "destination":null,
            "state":"deferred", "reason":"probe-queued", "stage":"probe",
            "first-seen-unix-ms":1000, "last-seen-unix-ms":2000,
            "candidate-id":null, "platform-limitation":null,
            "history":[{"stage":"probe","state":"not-created","reason":"primary-responds","at-unix-ms":1000},
                {"stage":"probe","state":"deferred","reason":"probe-queued","at-unix-ms":2000}],
            "probe-queue":{"wait-kind":"workers", "queued-ahead":0,
                "eligible-in-ms":1875, "last-probe-started-unix-ms":8640000000000000_u64}
        })).unwrap_or_else(|error| panic!("episode: {error}"));
        let text = lines(&[episode], 0, &[], &Texts::fallback_only())
            .iter()
            .map(ViewLine::plain_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("Waiting for other automatic checks to finish"),
            "{text}"
        );
        assert!(!text.contains("at least"), "{text}");
        assert!(text.contains("Retained check result at"), "{text}");
        assert!(
            text.contains("main connection answered the probe"),
            "{text}"
        );
        assert!(!text.contains("No previous check result"), "{text}");
    }
}
