use super::*;

#[test]
fn nov10_service_probes_do_not_become_browser_visits_or_primary_completions() {
    for own in [true, false] {
        let stalls = Arc::new(crate::primary_stall_registry::PrimaryStallRegistry::new());
        let health = Arc::new(Mutex::new(Vec::new()));
        let visits = Arc::new(Mutex::new(Vec::new()));
        let heard = Arc::clone(&health);
        let navigated = Arc::clone(&visits);
        let consumer = consumer_on_both_links()
            .with_main_link_diagnostics(stage0(
                &stalls,
                Some(Arc::new(move |event| {
                    heard
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(event.event);
                })),
            ))
            .with_navigation_attempt(Arc::new(move |_, _, _, _| {
                navigated.lock().unwrap_or_else(|p| p.into_inner()).push(());
            }));
        let mut attempt =
            over_the_main_link(ConnectionVerdict::Unknown, ConnectionProgress::Attempt);
        attempt.pid = if own {
            std::process::id()
        } else {
            std::process::id().saturating_add(1)
        };
        attempt.process_path = Some(if own {
            std::env::current_exe()
                .unwrap_or_else(|error| panic!("own image: {error}"))
                .to_string_lossy()
                .into_owned()
        } else {
            format!(
                "C:\\UnrelatedDirectory\\{}",
                crate::app_observation_lookup::own_process_key()
            )
        });
        attempt.user_sid = Some(STAGE0_USER.into());
        attempt.observed_unix_ms = Some(1000);
        let mut closed = attempt.clone();
        closed.progress = ConnectionProgress::ClosedInOrder;
        closed.process_path = None;
        closed.observed_unix_ms = Some(1200);
        let summary = consumer.consume(&[attempt, closed], SystemTime::now());
        assert_eq!(
            summary.total, 1,
            "excluding self diagnostics must not hide the connection trace or exempt traffic"
        );
        let expected = usize::from(!own);
        assert_eq!(health.lock().unwrap_or_else(|p| p.into_inner()).len(), expected, "only the actual running process is excluded from user health, never an unrelated same-basename image");
        assert_eq!(
            visits.lock().unwrap_or_else(|p| p.into_inner()).len(),
            expected,
            "a service probe cannot count as somebody browsing"
        );
    }
}
