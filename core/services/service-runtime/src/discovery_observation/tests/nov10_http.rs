use super::*;
use crate::site_check::{HeadFailure, HttpsHead};

struct Heads {
    primary: Result<Vec<u8>, HeadFailure>,
    secondary: Result<Vec<u8>, HeadFailure>,
    calls: Mutex<Vec<(String, Ipv4Addr)>>,
    revoke: Option<Arc<AtomicBool>>,
}
impl HttpsHead for Heads {
    fn fetch(
        &self,
        _: Ipv4Addr,
        host: &str,
        source: Ipv4Addr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        assert!(timeout <= Duration::from_millis(1500));
        assert!(
            request
                .windows(host.len())
                .any(|part| part == host.as_bytes()),
            "the request must name this exact owner-authorized host"
        );
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((host.into(), source));
        if let Some(enabled) = &self.revoke {
            enabled.store(false, Ordering::Release);
        }
        if source == PRIMARY {
            self.primary.clone()
        } else {
            assert_eq!(
                source, SECONDARY,
                "there is no unbound or substituted secondary path"
            );
            self.secondary.clone()
        }
    }
}

#[test]
fn nov10_https_failure_after_a_tls_reply_reaches_a_narrow_review_offer_and_push() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;
    for (status, www) in [(200, false), (302, false), (200, true)] {
        let base = format!("http-reset-primary-{status}.example");
        let host = if www {
            format!("www.{base}")
        } else {
            base.clone()
        };
        let mut f = fixture_in_mode(&host, nrr_storage::auto_rules::AutoRulesMode::Auto);
        f.probe.primary_answers.store(true, Ordering::Release);
        let bus = Arc::new(EventBus::new());
        let own = bus
            .subscribe_as("http-own-tray".into(), Some(OWNER.into()), None)
            .subscription_id;
        let foreign = bus
            .subscribe_as("http-other-tray".into(), Some(OTHER.into()), None)
            .subscription_id;
        let engine = Arc::new(
            AutoRulesEngine::new(
                f.rules.clone(),
                Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Auto),
                Arc::new(InMemoryDismissalStore::new()),
                Arc::new(InMemoryPendingStore::new()),
                SystemTime::now(),
            )
            .with_primary_health_registry(crate::primary_stall_registry::global_primary_stalls())
            .with_event_bus(Arc::clone(&bus)),
        );
        Arc::get_mut(&mut f.pipeline.wiring)
            .unwrap_or_else(|| panic!("unshared wiring"))
            .engine = Arc::clone(&engine);
        let heads = Arc::new(Heads {
            primary: Err(HeadFailure::NoAnswer),
            secondary: Ok(
                format!("HTTP/1.1 {status} Answer\r\nContent-Length: 0\r\n\r\n").into_bytes(),
            ),
            calls: Mutex::new(Vec::new()),
            revoke: None,
        });
        f.pipeline = f.pipeline.with_https(Some(heads.clone()));
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        let rows = engine.candidates(OWNER);
        assert_eq!(rows.len(), 1, "a TLS handshake must not hide the primary HTTP reset when the actual secondary HTTP exchange answers");
        let row = &rows[0];
        assert_eq!(row.signal, "http-path-reachability");
        assert_eq!(
            row.proposed_match,
            if www { base.as_str() } else { host.as_str() }
        );
        assert_eq!(
            row.match_kind,
            if www {
                nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_SUFFIX
            } else {
                nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_EXACT
            }
        );
        if www {
            assert_eq!(row.anchor, host);
            assert_eq!(
                row.observed_members,
                vec![host.clone()],
                "the visibly wider WWW exception retains the actual checked name"
            );
        }
        assert_eq!(row.secondary_reach, Some(true));
        assert!(row.any_zone_site.is_empty());
        assert_eq!(heads.calls.lock().unwrap_or_else(|p| p.into_inner()).len(), 4, "three primary HTTP attempts and one secondary replace TLS probes instead of doubling connections");
        assert!(f
            .probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
        assert!(
            !engine.covers_pending_secondary_host(&host),
            "an independent HTTP finding never steers before user approval"
        );
        assert!(bus
            .peek_pending_for(&own, 64)
            .iter()
            .any(|envelope| matches!(
                &envelope.event,
                StatusUpdateEvent::AutoRuleCandidatesChanged {
                    announces: true,
                    pending_count: 1,
                    ..
                }
            )));
        assert!(bus.peek_pending_for(&foreign, 64).is_empty());
        assert!(engine.candidates(OTHER).is_empty());
    }
}

#[test]
fn nov10_http_checks_fail_closed_for_response_errors_secondary_loss_and_revocation() {
    for scenario in [
        "healthy",
        "403",
        "500",
        "secondary-no-answer",
        "untrusted",
        "secondary-missing",
        "revoked",
    ] {
        let host = format!("http-guard-{scenario}.example");
        let mut f = fixture(&host);
        f.probe.primary_answers.store(true, Ordering::Release);
        let primary = match scenario {
            "healthy" => Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            "403" => Ok(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec()),
            "500" => Ok(b"HTTP/1.1 500 Error\r\n\r\n".to_vec()),
            _ => Err(HeadFailure::NoAnswer),
        };
        let secondary = match scenario {
            "secondary-no-answer" => Err(HeadFailure::NoAnswer),
            "untrusted" => Err(HeadFailure::Untrusted),
            _ => Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
        };
        let heads = Arc::new(Heads {
            primary,
            secondary,
            calls: Mutex::new(Vec::new()),
            revoke: (scenario == "revoked").then(|| Arc::clone(&f.enabled)),
        });
        if scenario == "secondary-missing" {
            struct PrimaryOnly;
            impl EgressSources for PrimaryOnly {
                fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
                    (Some(PRIMARY), None)
                }
            }
            Arc::get_mut(&mut f.pipeline.wiring)
                .unwrap_or_else(|| panic!("unshared wiring"))
                .egress = Arc::new(PrimaryOnly);
        }
        f.pipeline = f.pipeline.with_https(Some(heads.clone()));
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        assert!(
            f.engine.candidates(OWNER).is_empty(),
            "{scenario} does not justify moving the host"
        );
        let calls = heads.calls.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            calls.len(),
            match scenario {
                "secondary-missing" => 0,
                "secondary-no-answer" | "untrusted" => 4,
                _ => 1,
            },
            "{scenario}"
        );
        assert!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "the HTTP-capable path never secretly adds another TLS probe"
        );
    }
}
