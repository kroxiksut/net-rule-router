//! Construction and wiring of [`AutoRulesEngine`].
//!
//! Everything optional is wired through a `with_*`, and the engine works
//! without any of it — an unwired port means that source of evidence is
//! simply absent, never a half-built engine.

use super::*;

impl AutoRulesEngine {
    /// `now` seeds the TTL check that filters restored suggestions — taken
    /// explicitly, like every other time-sensitive call on this engine,
    /// rather than read from the clock internally, so a test can control it.
    pub fn new(
        rules: Arc<dyn RulesProvider>,
        mode_for: AutoRulesModeFn,
        dismissals: Arc<dyn DismissalStore>,
        pending_store: Arc<dyn PendingSuggestionStore>,
        now: SystemTime,
    ) -> Self {
        let now_ms = unix_ms(now);
        Self {
            ledgers: Mutex::new(HashMap::new()),
            pending: Mutex::new(hydrate_pending(pending_store.as_ref(), now_ms)),
            dismissed: Mutex::new(HashMap::new()),
            authored: Mutex::new(HashMap::new()),
            publish_state: Mutex::new(HashMap::new()),
            unreachable_told: Mutex::new(HashMap::new()),
            quiet_note: Mutex::new(HashMap::new()),
            settings_memo: Mutex::new(HashMap::new()),
            mode_for,
            eager_delivery_for: None,
            rules,
            dismissals,
            pending_store,
            author: OnceLock::new(),
            events: None,
            secondary_ready: None,
            refusing_anchors: None,
            main_link_pass_enabled: None,
            primary_behavior_of: None,
            evidence_store: None,
            evidence_saved_at: Mutex::new(HashMap::new()),
        }
    }

    /// Is a ledger already live for `sid`? Read on its own so the evidence load
    /// can happen off the ledger lock.
    pub(super) fn ledgers_contains(&self, sid: &str) -> bool {
        self.ledgers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(sid)
    }

    /// Writes `sid`'s accumulated evidence, at most once per
    /// [`EVIDENCE_SAVE_INTERVAL`]. The snapshot is taken under the ledger lock
    /// and the write happens after it is released — the observation feed is
    /// never held open across a disk write.
    pub(super) fn persist_evidence(&self, sid: &str, now: SystemTime) {
        let Some(store) = self.evidence_store.as_ref() else {
            return;
        };
        {
            let mut saved = self
                .evidence_saved_at
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let at = Instant::now();
            match saved.get(sid) {
                Some(last) if at.duration_since(*last) < EVIDENCE_SAVE_INTERVAL => return,
                _ => saved.insert(sid.to_string(), at),
            };
        }
        let snapshot = {
            let ledgers = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
            ledgers.get(sid).map(|l| l.ledger.snapshot())
        };
        if let Some(snapshot) = snapshot {
            store.save(sid, &snapshot, unix_ms(now));
        }
    }

    /// Attach the durable evidence store. Without it the learner still works,
    /// it just starts from nothing after every restart — which on a laptop is
    /// the difference between suggestions appearing and never appearing.
    #[must_use]
    pub fn with_evidence_store(mut self, store: Arc<dyn EvidenceStore>) -> Self {
        self.evidence_store = Some(store);
        self
    }

    /// Attach the rule author. Without it `auto` mode collects and parks like
    /// `suggest`, and `accept` reports `authoring-unavailable` rather than
    /// silently dropping the user's answer.
    #[must_use]
    pub fn with_author(self, author: Arc<dyn AutoRuleAuthor>) -> Self {
        self.attach_author(author);
        self
    }

    /// Attach the author after construction. Returns `false` when one was
    /// already attached, which the caller may ignore — the first wins, and a
    /// second attach means the composition root wired the same engine twice.
    pub fn attach_author(&self, author: Arc<dyn AutoRuleAuthor>) -> bool {
        self.author.set(author).is_ok()
    }

    /// Attach the per-SID source of the eager delivery-name opt-in. Without it
    /// every principal keeps the conservative default, which is what an
    /// un-opted-in user gets anyway.
    #[must_use]
    pub fn with_eager_delivery_names(mut self, source: AutoRulesEagerDeliveryFn) -> Self {
        self.eager_delivery_for = Some(source);
        self
    }

    /// Attach the push channel so the tray learns about new suggestions without
    /// polling. Without it the suggestions still accumulate and the GUI can
    /// still list them on demand.
    #[must_use]
    pub fn with_event_bus(mut self, events: Arc<EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Attach the reader for [`Self::main_link_pass_enabled`].
    #[must_use]
    pub fn with_main_link_pass_enabled(mut self, enabled: MainLinkPassEnabledFn) -> Self {
        self.main_link_pass_enabled = Some(enabled);
        self
    }

    /// Wire the "how does this host fare on the main link" question, so an
    /// offer a host made about itself goes quiet once the main link carries it.
    #[must_use]
    pub fn with_primary_behavior_source(mut self, source: PrimaryBehaviorFn) -> Self {
        self.primary_behavior_of = Some(source);
        self
    }

    /// Wire the "which sites refuse main-link addresses" question, so their
    /// companions keep being offered even when the address answers.
    #[must_use]
    pub fn with_refusing_anchors(mut self, refusing: RefusingAnchorsFn) -> Self {
        self.refusing_anchors = Some(refusing);
        self
    }

    /// Wire the "is the additional route usable" question, so suggestions are
    /// held back while it is down instead of being offered against a problem
    /// the user does not currently have.
    #[must_use]
    pub fn with_secondary_ready(mut self, ready: SecondaryReadyFn) -> Self {
        self.secondary_ready = Some(ready);
        self
    }

    // ── Observation feed ─────────────────────────────────────────────────────
}
