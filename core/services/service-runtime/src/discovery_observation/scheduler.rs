//! Bounded discovery work and its independent network safety budget.

use super::*;

const MAX_PENDING: usize = 1024;
const MAX_PENDING_PER_OWNER: usize = 64;
const BURST: u32 = 8;
const PERIOD: Duration = Duration::from_secs(15);
const TOKEN: Duration = Duration::from_millis(PERIOD.as_secs() * 1000 / BURST as u64);

#[derive(Clone)]
pub(super) struct Recent {
    pub at: BootInstant,
    pub repeat: Duration,
    pub last_probe_started_unix_ms: Option<i64>,
}

pub(super) struct Bucket {
    at: BootInstant,
    credit: Duration,
}

impl Bucket {
    #[cfg(test)]
    pub fn empty(now: BootInstant) -> Self {
        Self {
            at: now,
            credit: Duration::ZERO,
        }
    }

    fn full(now: BootInstant) -> Self {
        Self {
            at: now,
            credit: PERIOD,
        }
    }

    fn refill(&mut self, now: BootInstant) {
        self.credit = self
            .credit
            .saturating_add(now.saturating_duration_since(self.at))
            .min(PERIOD);
        self.at = self.at.max(now);
    }

    fn available(&mut self, now: BootInstant) -> bool {
        self.refill(now);
        self.credit >= TOKEN
    }

    fn delay(&mut self, now: BootInstant) -> Duration {
        self.refill(now);
        TOKEN.saturating_sub(self.credit)
    }
}

#[derive(Clone)]
pub(super) struct Pending {
    pub confirmation: Confirmation,
    pub witnessed_at: BootInstant,
    pub sequence: u64,
    pub version: u64,
    pub fresh: bool,
    pub queued_unix_ms: i64,
    pub witnessed_unix_ms: i64,
}

pub(super) struct Lease {
    memory: Arc<Mutex<Memory>>,
    pub reservation: Reservation,
    measured: bool,
    released: bool,
}

impl Lease {
    pub fn new(memory: Arc<Mutex<Memory>>, reservation: Reservation) -> Self {
        Self {
            memory,
            reservation,
            measured: false,
            released: false,
        }
    }

    pub fn started(&mut self) {
        self.measured = true;
        let at = crate::conn_observation_consumer::now_unix_ms()
            .try_into()
            .unwrap_or(i64::MAX);
        self.memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .probe_started
            .insert(
                (
                    self.reservation.owner.clone(),
                    self.reservation.hostname.clone(),
                ),
                at,
            );
    }

    pub fn has_started(&self) -> bool {
        self.measured
    }

    pub fn defer_for_rules(&mut self) {
        if self.released {
            return;
        }
        // Retain the original witness while preserving any measured spend/cooldown.
        let now = BootInstant::now();
        self.memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(&self.reservation, self.measured, now, true);
        self.released = true;
    }

    pub fn finish(&mut self, requeue: bool) {
        if self.released {
            return;
        }
        let now = BootInstant::now();
        self.memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(
                &self.reservation,
                self.measured,
                now,
                requeue && !self.measured,
            );
        self.released = true;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.finish(!self.measured);
    }
}

impl Pending {
    pub fn key(&self) -> ProbeKey {
        (
            self.confirmation.owner.clone(),
            self.confirmation.host.clone(),
        )
    }
}

impl Memory {
    pub fn enqueue(
        &mut self,
        confirmation: Confirmation,
        now: BootInstant,
        unix_ms: i64,
    ) -> Result<(), ReservationRefusal> {
        let key = (confirmation.owner.clone(), confirmation.host.clone());
        if self.in_flight.contains_key(&key) {
            return Err(ReservationRefusal::Cooldown);
        }
        if let Some(existing) = self.pending.iter_mut().find(|pending| {
            pending.confirmation.owner == key.0 && pending.confirmation.host == key.1
        }) {
            existing.confirmation = confirmation;
            existing.witnessed_at = now;
            existing.witnessed_unix_ms = unix_ms;
            existing.version = existing.version.saturating_add(1);
            return Ok(());
        }
        let owned = self
            .pending
            .iter()
            .filter(|pending| pending.confirmation.owner == confirmation.owner)
            .count()
            + self
                .in_flight
                .keys()
                .filter(|(owner, _)| owner == &confirmation.owner)
                .count();
        if self.pending.len() + self.in_flight.len() >= MAX_PENDING
            || owned >= MAX_PENDING_PER_OWNER
        {
            return Err(ReservationRefusal::MemoryLimit);
        }
        self.sequence = self.sequence.saturating_add(1);
        self.pending.push_back(Pending {
            confirmation,
            witnessed_at: now,
            sequence: self.sequence,
            version: 0,
            fresh: !self.recent.contains_key(&key),
            queued_unix_ms: unix_ms,
            witnessed_unix_ms: unix_ms,
        });
        Ok(())
    }

    pub fn expire_pending(&mut self, now: BootInstant) -> Vec<Pending> {
        let mut expired = Vec::new();
        self.pending.retain(|pending| {
            if now.saturating_duration_since(pending.witnessed_at)
                >= crate::recent_rule_addresses::ENTRY_TTL
            {
                expired.push(pending.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn owners(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.pending
            .iter()
            .filter_map(|pending| {
                let owner = &pending.confirmation.owner;
                seen.insert(owner.as_str()).then(|| owner.clone())
            })
            .collect()
    }

    pub fn discard_owner(&mut self, owner: &str) -> Vec<Pending> {
        let mut discarded = Vec::new();
        self.pending.retain(|pending| {
            if pending.confirmation.owner == owner {
                discarded.push(pending.clone());
                false
            } else {
                true
            }
        });
        discarded
    }

    pub fn update_repeat(&mut self, owner: &str, repeat: Duration) {
        for ((sid, _), recent) in &mut self.recent {
            if sid == owner {
                recent.repeat = repeat;
            }
        }
    }

    pub fn next(
        &mut self,
        now: BootInstant,
        owner: Option<&str>,
        excluded: &HashSet<String>,
    ) -> Option<Pending> {
        if self
            .global_budget
            .as_mut()
            .is_some_and(|bucket| !bucket.available(now))
        {
            return None;
        }
        let order = self.owners();
        let count = order.len().max(1);
        let start = self
            .last_owner
            .as_ref()
            .and_then(|owner| order.iter().position(|entry| entry == owner))
            .map_or(0, |index| (index + 1) % count);
        let rank: HashMap<_, _> = order
            .iter()
            .enumerate()
            .map(|(index, owner)| (owner.as_str(), (index + count - start) % count))
            .collect();
        for fresh in [true, false] {
            let mut best: Option<(usize, Pending)> = None;
            for pending in &self.pending {
                let sid = pending.confirmation.owner.as_str();
                if pending.fresh != fresh
                    || owner.is_some_and(|owner| owner != sid)
                    || excluded.contains(sid)
                {
                    continue;
                }
                let key = pending.key();
                if self.in_flight.contains_key(&key)
                    || self.recent.get(&key).is_some_and(|recent| {
                        now.saturating_duration_since(recent.at) < recent.repeat
                    })
                    || self
                        .budgets
                        .get_mut(sid)
                        .is_some_and(|bucket| !bucket.available(now))
                {
                    continue;
                }
                let position = rank.get(sid).copied().unwrap_or(0);
                if best.as_ref().is_none_or(|(prior, value)| {
                    (position, pending.sequence) < (*prior, value.sequence)
                }) {
                    best = Some((position, pending.clone()));
                }
            }
            if let Some((_, pending)) = best {
                return Some(pending);
            }
        }
        None
    }

    pub fn remove_pending(&mut self, pending: &Pending) -> bool {
        let key = pending.key();
        if let Some(index) = self.pending.iter().position(|entry| {
            entry.confirmation.owner == key.0
                && entry.confirmation.host == key.1
                && entry.version == pending.version
        }) {
            self.pending.remove(index);
            true
        } else {
            false
        }
    }

    pub fn queue_snapshot(
        &mut self,
        owner: &str,
        now: BootInstant,
        workers: usize,
        valid: &HashMap<String, (u64, u64)>,
    ) -> HashMap<String, nrr_shared::ipc_payloads::ProbeQueueStatusDto> {
        use nrr_shared::ipc_payloads::{ProbeQueueStatusDto, ProbeQueueWaitKindDto as Wait};
        let rate = self
            .global_budget
            .as_mut()
            .map_or(Duration::ZERO, |bucket| bucket.delay(now))
            .max(
                self.budgets
                    .get_mut(owner)
                    .map_or(Duration::ZERO, |bucket| bucket.delay(now)),
            );
        let new_flights = self
            .in_flight
            .keys()
            .filter(|key| !self.recent.contains_key(*key))
            .count();
        // Mirror reservation retention: an expired entry still owned by a probe
        // cannot be reused. Never expose another owner's expiry or occupancy.
        let history_full = self.recent.len() + new_flights >= MAX_RECENT
            && self
                .recent
                .iter()
                .filter(|(key, recent)| {
                    self.in_flight.contains_key(*key)
                        || now.saturating_duration_since(recent.at) < recent.repeat
                })
                .count()
                + new_flights
                >= MAX_RECENT;
        let owner_table_full =
            !self.budgets.contains_key(owner) && self.budgets.len() >= MAX_RECENT && {
                let active: HashSet<_> = self
                    .pending
                    .iter()
                    .map(|pending| pending.confirmation.owner.as_str())
                    .chain(self.in_flight.keys().map(|(sid, _)| sid.as_str()))
                    .collect();
                self.budgets
                    .iter()
                    .filter(|(sid, bucket)| {
                        active.contains(sid.as_str())
                            || now.saturating_duration_since(bucket.at) < PERIOD
                    })
                    .count()
                    >= MAX_RECENT
            };
        let owned: Vec<_> = self
            .pending
            .iter()
            .filter(|entry| {
                entry.confirmation.owner == owner
                    && valid.get(&entry.confirmation.host) == Some(&(entry.sequence, entry.version))
                    && now.saturating_duration_since(entry.witnessed_at)
                        < crate::recent_rule_addresses::ENTRY_TTL
            })
            .collect();
        let cooldown = |entry: &Pending| {
            self.recent
                .get(&entry.key())
                .map_or(Duration::ZERO, |recent| {
                    recent
                        .repeat
                        .saturating_sub(now.saturating_duration_since(recent.at))
                })
        };
        owned
            .iter()
            .map(|entry| {
                let remaining = cooldown(entry);
                let ahead = owned
                    .iter()
                    .filter(|other| {
                        cooldown(other).is_zero()
                            && ((other.fresh && !entry.fresh)
                                || (other.fresh == entry.fresh && other.sequence < entry.sequence))
                    })
                    .count();
                let wait_kind = if !remaining.is_zero() {
                    Wait::Cooldown
                } else if owner_table_full
                    || (history_full && !self.recent.contains_key(&entry.key()))
                {
                    Wait::Resources
                } else if !rate.is_zero() {
                    Wait::Rate
                } else if ahead > 0 {
                    Wait::Ahead
                } else if workers >= MAX_WORKERS {
                    Wait::Workers
                } else {
                    Wait::Scheduled
                };
                let eligible_in_ms = match wait_kind {
                    Wait::Rate | Wait::Cooldown => Some(
                        remaining
                            .max(rate)
                            .as_nanos()
                            .div_ceil(1_000_000)
                            .try_into()
                            .unwrap_or(u64::MAX),
                    ),
                    Wait::Scheduled => Some(0),
                    _ => None,
                };
                (
                    entry.confirmation.host.clone(),
                    ProbeQueueStatusDto {
                        wait_kind,
                        queued_ahead: ahead.try_into().unwrap_or(u32::MAX),
                        eligible_in_ms,
                        last_probe_started_unix_ms: self
                            .recent
                            .get(&entry.key())
                            .and_then(|recent| recent.last_probe_started_unix_ms),
                    },
                )
            })
            .collect()
    }

    pub fn reserve(
        &mut self,
        owner: &str,
        host: &str,
        repeat: Duration,
        now: BootInstant,
    ) -> Result<(), ReservationRefusal> {
        let key = (owner.to_owned(), host.to_owned());
        if self.in_flight.contains_key(&key)
            || self
                .recent
                .get(&key)
                .is_some_and(|recent| now.saturating_duration_since(recent.at) < repeat)
        {
            return Err(ReservationRefusal::Cooldown);
        }
        let new_flights = self
            .in_flight
            .keys()
            .filter(|key| !self.recent.contains_key(*key))
            .count();
        if !self.recent.contains_key(&key) && self.recent.len() + new_flights >= MAX_RECENT {
            self.recent.retain(|key, recent| {
                self.in_flight.contains_key(key)
                    || now.saturating_duration_since(recent.at) < recent.repeat
            });
            if self.recent.len() + new_flights >= MAX_RECENT {
                return Err(ReservationRefusal::MemoryLimit);
            }
        }
        if !self.budgets.contains_key(owner) && self.budgets.len() >= MAX_RECENT {
            let active: HashSet<_> = self
                .pending
                .iter()
                .map(|pending| pending.confirmation.owner.as_str())
                .chain(self.in_flight.keys().map(|(owner, _)| owner.as_str()))
                .collect();
            self.budgets.retain(|sid, bucket| {
                active.contains(sid.as_str()) || now.saturating_duration_since(bucket.at) < PERIOD
            });
            if self.budgets.len() >= MAX_RECENT {
                return Err(ReservationRefusal::MemoryLimit);
            }
        }
        let bucket = self
            .budgets
            .entry(owner.to_owned())
            .or_insert_with(|| Bucket::full(now));
        if !bucket.available(now) {
            return Err(ReservationRefusal::BudgetExhausted);
        }
        let global = self.global_budget.get_or_insert_with(|| Bucket::full(now));
        if !global.available(now) {
            return Err(ReservationRefusal::BudgetExhausted);
        }
        global.credit = global.credit.saturating_sub(TOKEN);
        bucket.credit = bucket.credit.saturating_sub(TOKEN);
        self.in_flight.insert(key, now);
        self.last_owner = Some(owner.to_owned());
        Ok(())
    }

    pub fn release(
        &mut self,
        reservation: &Reservation,
        measured: bool,
        now: BootInstant,
        requeue: bool,
    ) {
        let key = (reservation.owner.clone(), reservation.hostname.clone());
        if self.in_flight.get(&key) != Some(&reservation.started_at) {
            return;
        }
        self.in_flight.remove(&key);
        let started = self.probe_started.remove(&key);
        if measured {
            self.recent.insert(
                key,
                Recent {
                    at: now,
                    repeat: reservation.repeat,
                    last_probe_started_unix_ms: started,
                },
            );
        } else if let Some(bucket) = self.budgets.get_mut(&reservation.owner) {
            bucket.refill(now);
            bucket.credit = bucket.credit.saturating_add(TOKEN).min(PERIOD);
            if let Some(global) = self.global_budget.as_mut() {
                global.refill(now);
                global.credit = global.credit.saturating_add(TOKEN).min(PERIOD);
            }
        }
        if requeue {
            if let Some(pending) = reservation.pending.clone() {
                let index = self
                    .pending
                    .iter()
                    .position(|entry| entry.sequence > pending.sequence)
                    .unwrap_or(self.pending.len());
                self.pending.insert(index, pending);
            }
        }
    }
}

#[cfg(test)]
pub(super) const SAFETY_BURST: usize = BURST as usize;
