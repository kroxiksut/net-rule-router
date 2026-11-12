use nrr_shared::browser_dns_settings::{
    BrowserDnsBrowser, BrowserDnsMode, BrowserDnsPolicy, BrowserDnsSource,
};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{DnsCompatibilityDto, DnsCompatibilityStatus};
use serde_json::json;

use crate::backend::Reply;
use crate::i18n::{key, Key, Texts};
use crate::state::AppState;
use crate::view::{Panel, ViewLine};

pub const TITLE: Key = key(
    "settings.routing.dns-compatibility.title",
    "DNS compatibility",
);
pub const HELP: Key = key(
    "settings.routing.dns-compatibility.browser-help",
    "Configure browser DNS",
);
pub const CHECK: Key = key("action.retry", "Try again");
pub const HELP_CHECK: Key = key(
    "settings.routing.dns-compatibility.help-check",
    "d: Check DNS compatibility",
);
pub const BROWSER_SETTING: Key = key(
    "settings.routing.dns-compatibility.browser-setting",
    "{browser}: saved DNS mode: {mode}; policy: {policy}; settings: {source}.",
);
pub const BROWSER_READ_ONLY: Key = key("settings.routing.dns-compatibility.browser-read-only", "Saved preferences do not prove the running browser's effective DNS mode. Automatic changes are unavailable when policy and profile ownership cannot be verified. Follow the instructions, reload the site, and check again; organization policies remain under your administrator's control.");
pub const CHECK_SECONDARY: Key = key(
    "settings.routing.dns-compatibility.check-secondary",
    "Check additional connection",
);
pub const ISSUE: Key = key(
    "settings.routing.dns-compatibility.issue",
    "{program}: {reason} ({evidence}). Attempts: {attempts}; first: {first}; last: {last}.",
);
pub const RESOLVER: Key = key(
    "settings.routing.dns-compatibility.resolver",
    "Our DNS listener: {listener}; system redirect: {redirect}; upstream DNS: {upstream}.",
);
pub const SECONDARY_STATE: Key = key("settings.routing.dns-compatibility.secondary-state", "Additional connection: {state}. This does not establish which connection a particular program requires.");
pub const VERIFY_SITE: Key = key("settings.routing.dns-compatibility.verify-site", "Choose Check site and start a check for the affected host, then open or reload that host in the affected browser within a minute. A fresh browser connection through the additional route can confirm recovery. Direct or reused connections may remain unverified; the site-check report is separate.");
pub const CHECKING: Key = key(
    "settings.routing.dns-compatibility.checking",
    "Checking DNS; your routing rules remain in force.",
);
pub const CHECK_FAILED: Key = key(
    "settings.routing.dns-compatibility.check-failed",
    "Could not check DNS compatibility.",
);
pub const CHECKED_AT: Key = key(
    "settings.routing.dns-compatibility.checked-at",
    "Last check: {time}",
);
pub const HISTORY_INCOMPLETE: Key = key("settings.routing.dns-compatibility.history-incomplete", "Some earlier DNS evidence is no longer available. Full recovery has not been verified; check affected sites individually.");
pub const VERIFICATION_UNAVAILABLE: Key = key("settings.routing.dns-compatibility.browser-verification-unavailable", "This platform cannot confirm the browser's own successful connection yet. Use Check site for a report through the assigned route; a successful system query or service probe does not certify the browser.");

pub fn verification_instructions(app: &AppState) -> Key {
    if app.settings.supports.fake_ip {
        VERIFY_SITE
    } else {
        VERIFICATION_UNAVAILABLE
    }
}
pub const INSTRUCTIONS: Key = key("settings.routing.dns-compatibility.browser-instructions",
    "Chrome/Chromium: Settings → Privacy and security → Security → turn off Use secure DNS. Edge: find Secure DNS in Settings and use system DNS. Firefox: Settings → Privacy & Security → DNS over HTTPS → Off. If your organization controls this setting, contact its administrator; do not override its policy. Reload the affected site, then check again. Keep the additional-route rule and leak protection enabled.");

pub fn status(state: &DnsCompatibilityDto) -> Key {
    match state.status {
        DnsCompatibilityStatus::Unchecked => key(
            "settings.routing.dns-compatibility.status.unchecked",
            "DNS compatibility has not been verified.",
        ),
        DnsCompatibilityStatus::Limited => key(
            "settings.routing.dns-compatibility.status.limited",
            "Connection restrictions were observed. Check the evidence and DNS settings below.",
        ),
        DnsCompatibilityStatus::NeedsRecheck => key(
            "settings.routing.dns-compatibility.status.needs-recheck",
            "The previous problem needs a fresh check; recovery is not confirmed.",
        ),
        DnsCompatibilityStatus::Verified => key(
            "settings.routing.dns-compatibility.status.verified",
            "A real connection by the affected program through its required route was verified.",
        ),
    }
}

pub fn browser_name(value: BrowserDnsBrowser) -> Key {
    match value {
        BrowserDnsBrowser::Chrome => key(
            "settings.routing.dns-compatibility.browser-name.chrome",
            "Chrome / Chromium",
        ),
        BrowserDnsBrowser::Edge => key(
            "settings.routing.dns-compatibility.browser-name.edge",
            "Microsoft Edge",
        ),
        BrowserDnsBrowser::Firefox => key(
            "settings.routing.dns-compatibility.browser-name.firefox",
            "Firefox",
        ),
    }
}

pub fn browser_mode(value: BrowserDnsMode) -> Key {
    match value {
        BrowserDnsMode::Off => key(
            "settings.routing.dns-compatibility.browser-mode.off",
            "System DNS selected",
        ),
        BrowserDnsMode::Automatic => key(
            "settings.routing.dns-compatibility.browser-mode.automatic",
            "Encrypted DNS with fallback selected",
        ),
        BrowserDnsMode::Secure => key(
            "settings.routing.dns-compatibility.browser-mode.secure",
            "Strict encrypted DNS selected",
        ),
        BrowserDnsMode::Unknown => key(
            "settings.routing.dns-compatibility.browser-mode.unknown",
            "Could not determine",
        ),
    }
}

pub fn browser_policy(value: BrowserDnsPolicy) -> Key {
    match value {
        BrowserDnsPolicy::Detected => key(
            "settings.routing.dns-compatibility.browser-policy.detected",
            "Organization policy detected",
        ),
        BrowserDnsPolicy::Unknown => key(
            "settings.routing.dns-compatibility.browser-policy.unknown",
            "Management status could not be verified",
        ),
    }
}

pub fn browser_source(value: BrowserDnsSource) -> Key {
    match value {
        BrowserDnsSource::LocalState => key(
            "settings.routing.dns-compatibility.browser-source.local-state",
            "Saved preference read",
        ),
        BrowserDnsSource::Unavailable => key(
            "settings.routing.dns-compatibility.browser-source.unavailable",
            "Could not read settings",
        ),
        BrowserDnsSource::Unsupported => key(
            "settings.routing.dns-compatibility.browser-source.unsupported",
            "Manual instructions available",
        ),
    }
}

pub fn reason(value: &str) -> Key {
    match value {
        "resolver-contact" => key(
            "settings.routing.dns-compatibility.reason.resolver-contact",
            "Contact with a known DNS endpoint; encrypted DNS use is not established",
        ),
        "our-dns-block" => key(
            "settings.routing.dns-compatibility.reason.our-dns-block",
            "Our filter blocked a connection to a known DNS endpoint",
        ),
        "strict-browser-dns" => key(
            "settings.routing.dns-compatibility.reason.strict-browser-dns",
            "The browser requires encrypted DNS without system DNS fallback",
        ),
        "local-resolver-unavailable" => key(
            "settings.routing.dns-compatibility.reason.local-resolver-unavailable",
            "Our DNS listener, redirect or upstream is unavailable",
        ),
        "secondary-unavailable" => key(
            "settings.routing.dns-compatibility.reason.secondary-unavailable",
            "The required additional connection is unavailable",
        ),
        _ => key(
            "settings.routing.dns-compatibility.reason.unknown",
            "The cause has not been established",
        ),
    }
}

pub fn evidence(value: &str) -> Key {
    if value == "confirmed" {
        key(
            "settings.routing.dns-compatibility.evidence.confirmed",
            "Observed fact",
        )
    } else {
        key(
            "settings.routing.dns-compatibility.evidence.suspected",
            "Needs verification",
        )
    }
}

pub fn readiness(value: &str) -> Key {
    match value {
        "ready" => key(
            "settings.routing.dns-compatibility.readiness.ready",
            "Ready",
        ),
        "unavailable" => key(
            "settings.routing.dns-compatibility.readiness.unavailable",
            "Unavailable",
        ),
        "not-required" => key(
            "settings.routing.dns-compatibility.readiness.not-required",
            "Not required in the selected mode",
        ),
        _ => key(
            "settings.routing.dns-compatibility.readiness.unchecked",
            "Not checked",
        ),
    }
}

pub fn messages(app: &AppState, texts: &Texts) -> Vec<String> {
    let state = &app.dns_compatibility;
    let mut lines = vec![texts.get(status(state))];
    if state.history_incomplete {
        lines.push(texts.get(HISTORY_INCOMPLETE));
    }
    if !app.link.is_connected() {
        lines.push(texts.get(crate::keys::BANNER_OFFLINE));
    }
    if state.recovery_pending {
        lines.push(texts.get(CHECKING));
    }
    for issue in state.issues.iter().take(8) {
        let certainty = if issue.evidence == "confirmed" {
            key(
                "settings.routing.dns-compatibility.evidence.confirmed",
                "Observed fact",
            )
        } else {
            key(
                "settings.routing.dns-compatibility.evidence.suspected",
                "Needs verification",
            )
        };
        let args = [
            ("program", display_text(&issue.program).into_owned()),
            ("reason", texts.get(reason(&issue.reason))),
            ("evidence", texts.get(certainty)),
            ("attempts", issue.attempts.to_string()),
            (
                "first",
                crate::screens::inspect::wall_clock(
                    i64::try_from(issue.first_seen_ms).unwrap_or(i64::MAX),
                ),
            ),
            (
                "last",
                crate::screens::inspect::wall_clock(
                    i64::try_from(issue.last_seen_ms).unwrap_or(i64::MAX),
                ),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        lines.push(nrr_client_logic::placeholders::format_log_line(
            &texts.get(ISSUE),
            ISSUE.en,
            &args,
            &[] as &[String],
        ));
    }
    lines.push(texts.fill(
        key(
            "settings.routing.dns-compatibility.resolver",
            "Our DNS listener: {listener}; system redirect: {redirect}; upstream DNS: {upstream}.",
        ),
        &[
            ("listener", texts.get(readiness(&state.resolver.listener))),
            ("redirect", texts.get(readiness(&state.resolver.redirect))),
            ("upstream", texts.get(readiness(&state.resolver.upstream))),
        ],
    ));
    lines.push(texts.fill(key("settings.routing.dns-compatibility.secondary-state",
        "Additional connection: {state}. This does not establish which connection a particular program requires."),
        &[("state", texts.get(readiness(&state.secondary_readiness)))]));
    if let Some(error) = &app.dns_compatibility_error {
        lines.push(texts.get(CHECK_FAILED));
        lines.push(crate::screens::settings::failure_text(error, texts));
    }
    lines
}

pub fn lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    messages(app, texts)
        .into_iter()
        .map(ViewLine::text)
        .collect()
}

pub fn panel(app: &AppState, texts: &Texts) -> Option<Panel> {
    if app.dns_compatibility.issues.is_empty()
        && !matches!(
            app.dns_compatibility.status,
            DnsCompatibilityStatus::Limited | DnsCompatibilityStatus::NeedsRecheck
        )
    {
        return None;
    }
    Some(Panel {
        title: texts.get(TITLE),
        lines: lines(app, texts),
        feed: false,
    })
}

pub fn recheck(app: &mut AppState) -> bool {
    if !app.link.is_connected() || app.dns_compatibility.recovery_pending {
        return true;
    }
    app.dns_compatibility.recovery_pending = true;
    let generation = app.dns_connection_generation;
    app.outbox.push(Box::new(move |client| {
        let response = client.call(
            IpcOperationName::DnsCompatibilityRecheck,
            json!({}),
            nrr_ipc_client::ipc_operation_timeout(IpcOperationName::DnsCompatibilityRecheck),
        );
        Reply::new(move |app| {
            if generation != app.dns_connection_generation || !app.link.is_connected() {
                return;
            }
            app.dns_compatibility.recovery_pending = false;
            match response {
                Ok(value) => match serde_json::from_value::<DnsCompatibilityDto>(value) {
                    Ok(state) => {
                        app.dns_compatibility = nrr_client_logic::dns_compatibility::merge(
                            &app.dns_compatibility,
                            state,
                        );
                        app.dns_compatibility_error = None;
                    }
                    Err(_) => {
                        app.dns_compatibility_error = Some(crate::screens::settings::Failure {
                            slug: "bad-response".to_owned(),
                            elevation: false,
                            detail: String::new(),
                        });
                    }
                },
                Err(error) => {
                    app.dns_compatibility_error =
                        Some(crate::screens::settings::Failure::from_ipc(&error))
                }
            }
        })
    }));
    true
}

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    let mut keys = vec![
        TITLE,
        HELP,
        CHECK,
        HELP_CHECK,
        BROWSER_SETTING,
        BROWSER_READ_ONLY,
        CHECK_SECONDARY,
        ISSUE,
        RESOLVER,
        SECONDARY_STATE,
        VERIFY_SITE,
        CHECKING,
        CHECK_FAILED,
        CHECKED_AT,
        HISTORY_INCOMPLETE,
        VERIFICATION_UNAVAILABLE,
        INSTRUCTIONS,
    ];
    keys.extend(
        [
            "resolver-contact",
            "our-dns-block",
            "strict-browser-dns",
            "local-resolver-unavailable",
            "secondary-unavailable",
            "unknown",
        ]
        .map(reason),
    );
    keys.extend(["ready", "unavailable", "unchecked", "not-required"].map(readiness));
    keys.extend(["confirmed", "suspected"].map(evidence));
    keys.extend(
        [
            BrowserDnsBrowser::Chrome,
            BrowserDnsBrowser::Edge,
            BrowserDnsBrowser::Firefox,
        ]
        .map(browser_name),
    );
    keys.extend(
        [
            BrowserDnsMode::Off,
            BrowserDnsMode::Automatic,
            BrowserDnsMode::Secure,
            BrowserDnsMode::Unknown,
        ]
        .map(browser_mode),
    );
    keys.extend([BrowserDnsPolicy::Detected, BrowserDnsPolicy::Unknown].map(browser_policy));
    keys.extend(
        [
            BrowserDnsSource::LocalState,
            BrowserDnsSource::Unavailable,
            BrowserDnsSource::Unsupported,
        ]
        .map(browser_source),
    );
    keys.extend(
        [
            DnsCompatibilityStatus::Unchecked,
            DnsCompatibilityStatus::Limited,
            DnsCompatibilityStatus::NeedsRecheck,
            DnsCompatibilityStatus::Verified,
        ]
        .map(|value| {
            status(&DnsCompatibilityDto {
                status: value,
                ..Default::default()
            })
        }),
    );
    keys
}
