//! A manual HTTP path comparison, without crediting the browser with a load.

use super::*;

impl SiteChecker {
    pub(super) fn manual_http_pair(
        &self,
        sid: &str,
        site: &mut Examined,
        sources: (Option<Ipv4Addr>, Option<Ipv4Addr>),
        initial_status: Option<u16>,
        deadline: Instant,
        manual: &ManualSiteCheckWiring,
    ) -> Option<u16> {
        let engine = self.wiring.engine.as_ref()?;
        let (main, additional) = sources;
        let https = self.wiring.https.as_ref()?;
        let host = site.planned.name.as_str();
        if site.route != "primary" || !manual.eligible(sid, host, site.address) {
            return None;
        }
        let note = |reason| {
            engine.note_discovery(
                sid,
                Some(host),
                None,
                crate::auto_rules::DiscoveryDecision::new("probe", "not-created", reason),
                std::time::SystemTime::now(),
            );
        };
        if site.answer == "answered" {
            if initial_status.is_some_and(|code| (200..400).contains(&code)) {
                engine.withdraw_http_path_reachability(sid, host, std::time::SystemTime::now());
                note("http-answered");
            } else if let Some(code) = initial_status {
                note(if code >= 500 {
                    "http-server-error"
                } else {
                    "http-client-error"
                });
            }
            return None;
        }
        // The first TLS connection and (when TLS answered) HTTP connection
        // already consumed part of the three-primary-connection allowance.
        let repeats = match site.answer {
            "https-unconfirmed" => 1,
            "silent" => 2,
            _ => return None,
        };
        let target = site.address?;
        let main = main?;
        let Some(additional) = additional else {
            note("secondary-unavailable");
            return None;
        };
        let request = http_answer::request_for(host)?;
        let permitted = || {
            manual.eligible(sid, host, Some(target))
                && self.wiring.egress.egress_source_ips(sid) == (Some(main), Some(additional))
        };
        let fetch = |source| {
            if !permitted() {
                return None;
            }
            let timeout = budget_left(deadline)?.min((manual.limits)(sid).timeout);
            Some(
                https
                    .fetch(target, host, source, &request, timeout)
                    .and_then(|bytes| {
                        http_answer::parse_head(&bytes).map_err(|_| HeadFailure::Untrusted)
                    }),
            )
        };
        for _ in 0..repeats {
            let answer = fetch(main)?;
            if !permitted() {
                note("probe-inconclusive");
                return None;
            }
            match answer {
                Ok(answer) => {
                    site.answer = "answered";
                    if (200..400).contains(&answer.status) {
                        engine.withdraw_http_path_reachability(
                            sid,
                            host,
                            std::time::SystemTime::now(),
                        );
                        note("http-answered");
                    } else {
                        note(if answer.status >= 500 {
                            "http-server-error"
                        } else {
                            "http-client-error"
                        });
                    }
                    return Some(answer.status);
                }
                Err(HeadFailure::NoAnswer) => {}
                Err(HeadFailure::Untrusted) => {
                    note("https-unconfirmed");
                    return None;
                }
                Err(HeadFailure::Unavailable) => {
                    note("probe-inconclusive");
                    return None;
                }
            }
        }
        match fetch(additional)? {
            Ok(answer) if (200..400).contains(&answer.status) && permitted() => {
                engine.note_http_path_reachability(sid, host, std::time::SystemTime::now());
            }
            Ok(answer) => note(if answer.status >= 500 {
                "http-server-error"
            } else {
                "http-client-error"
            }),
            Err(HeadFailure::NoAnswer) => note("secondary-failed"),
            Err(HeadFailure::Untrusted) => note("https-unconfirmed"),
            Err(HeadFailure::Unavailable) => note("probe-inconclusive"),
        }
        None
    }
}
