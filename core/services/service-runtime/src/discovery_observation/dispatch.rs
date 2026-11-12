use super::*;

const MAX_CHECK_TARGETS: usize = 32;
const MAX_CHECK_SELECTIONS: usize = 64;

#[derive(Default)]
pub(super) struct Check {
    state: Mutex<CheckState>,
}

#[derive(Default)]
struct CheckState {
    spent: HashMap<String, usize>,
    unavailable: HashSet<String>,
    targets: usize,
    selections: usize,
}

impl Check {
    pub(super) fn refund(&self, owner: &str) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(spent) = state.spent.get_mut(owner) {
            *spent = spent.saturating_sub(1);
        }
        state.targets = state.targets.saturating_sub(1);
    }
}

impl DiscoveryObservationPipeline {
    /// Each check shares its target quotas across two workers; only active sends reserve credits.
    pub fn pump(&self) {
        self.attach_queue_source();
        if self
            .pumping
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        struct Release<'a>(&'a AtomicBool);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _release = Release(&self.pumping);
        let check = Arc::new(Check::default());
        for _ in 0..MAX_WORKERS {
            if self.workers.load(Ordering::Acquire) >= MAX_WORKERS {
                break;
            }
            let Some(work) = self.next_confirmation(&check, true) else {
                break;
            };
            self.start_check(work, Arc::clone(&check));
        }
    }

    fn start_check(&self, work: (Confirmation, Reservation), check: Arc<Check>) {
        self.start_confirmations_with_check(vec![work], Some(check), |work| {
            std::thread::Builder::new()
                .name("nrr-discovery-confirm".into())
                .spawn(work)
        });
    }

    pub(super) fn next_confirmation(
        &self,
        check: &Check,
        acquire_worker: bool,
    ) -> Option<(Confirmation, Reservation)> {
        for _ in 0..MAX_CHECK_SELECTIONS {
            let now = BootInstant::now();
            let (expired, owners) = {
                let mut memory = self.memory.lock().unwrap_or_else(|p| p.into_inner());
                (memory.expire_pending(now), memory.owners())
            };
            for pending in expired {
                self.note_pending(&pending, "not-created", "name-unknown");
            }
            let mut settings = HashMap::new();
            for owner in owners {
                let cadence = (self.wiring.cadence)(&owner);
                let denied = if !self.wiring.engine.learns_for(&owner) {
                    Some("discovery-disabled")
                } else if !cadence.enabled {
                    Some("auto-probe-disabled")
                } else if !(self.wiring.primary_default)(&owner) {
                    Some("already-covered")
                } else {
                    None
                };
                if let Some(reason) = denied {
                    let discarded = self
                        .memory
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .discard_owner(&owner);
                    for pending in discarded {
                        self.note_pending(&pending, Self::refusal_state(reason), reason);
                    }
                    continue;
                }
                let limits = (self.wiring.limits)(&owner);
                self.memory
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .update_repeat(&owner, cadence.repeat);
                settings.insert(owner, (cadence.repeat, limits));
            }
            let pending = {
                let mut state = check.state.lock().unwrap_or_else(|p| p.into_inner());
                if state.targets >= MAX_CHECK_TARGETS || state.selections >= MAX_CHECK_SELECTIONS {
                    return None;
                }
                let mut excluded = state.unavailable.clone();
                for (owner, (_, limits)) in &settings {
                    if state.spent.get(owner).copied().unwrap_or(0) >= limits.max_targets {
                        excluded.insert(owner.clone());
                    }
                }
                state.selections += 1;
                self.memory
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .next(now, None, &excluded)
            }?;
            let mut confirmation = pending.confirmation.clone();
            let owner = &confirmation.owner;
            let Some(&(repeat, limits)) = settings.get(owner) else {
                continue;
            };
            let denied = Self::confirmation_refusal(
                &self.wiring,
                owner,
                &confirmation.host,
                confirmation.target.into(),
                confirmation.process.as_deref(),
            );
            if let Some(reason) = denied {
                if reason == "rules-unavailable" {
                    check
                        .state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .unavailable
                        .insert(owner.clone());
                    self.note_pending(&pending, "deferred", reason);
                    continue;
                }
                self.memory
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove_pending(&pending);
                self.note_pending(&pending, Self::refusal_state(reason), reason);
                continue;
            }
            if !self
                .wiring
                .names
                .probe_names_for(owner, confirmation.target)
                .contains(&confirmation.host)
            {
                self.memory
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove_pending(&pending);
                self.note_pending(&pending, "not-created", "name-unknown");
                continue;
            }
            let (Some(source), secondary) = self.wiring.egress.egress_source_ips(owner) else {
                check
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .unavailable
                    .insert(owner.clone());
                self.note_pending(&pending, "deferred", "probe-inconclusive");
                continue;
            };
            confirmation.source = source;
            confirmation.secondary = secondary;
            confirmation.timeout = limits.timeout;
            if !matches!(self.wiring.names.resolve_for(owner, confirmation.target), HostNameResolution::Unique(ref host) if host == &confirmation.host)
            {
                confirmation.shared_address = true;
            }
            if (confirmation.shared_address || self.https.is_some())
                && (secondary.is_none() || secondary == Some(source))
            {
                check
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .unavailable
                    .insert(owner.clone());
                self.note_pending(&pending, "deferred", "secondary-unavailable");
                continue;
            }
            let mut state = check.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.targets >= MAX_CHECK_TARGETS
                || state.spent.get(owner).copied().unwrap_or(0) >= limits.max_targets
            {
                continue;
            }
            let mut reservation = match self.reserve_for_batch(
                owner,
                &confirmation.host,
                repeat,
                now,
                acquire_worker,
            ) {
                Ok(reservation) => reservation,
                Err(ReservationRefusal::Cooldown) => continue,
                Err(_) => return None,
            };
            if !self
                .memory
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove_pending(&pending)
            {
                self.rollback_reservation(reservation);
                continue;
            }
            reservation.pending = Some(pending);
            state.targets += 1;
            *state.spent.entry(owner.clone()).or_default() += 1;
            return Some((confirmation, reservation));
        }
        None
    }
}
