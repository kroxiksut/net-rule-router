//! Filling the cache from sources other than live traffic: the OS resolver
//! cache at boot, and reverse-confirmed names learned from blocked connections.

use super::*;

impl DnsObservationConsumer {
    /// seed the FQDN cache from the OS resolver cache.
    ///
    /// Reads what the OS has already resolved (via the injected
    /// [`DnsCacheReadPort`]) and caches the rule-matching hosts with source
    /// [`StorageResolutionSource::OsCacheSeed`]. This closes the observability
    /// gap where a rule host (e.g. a `.ru` zone member) was resolved *before*
    /// the service started, or served straight from the OS cache so no wire
    /// query fired and the ETW observer never saw it — leaving its zone permit
    /// uncompiled and the host blocked under a catch-all.
    ///
    /// Same keep-logic as [`consume`](Self::consume): active-SID gate,
    /// active-rules match (primary OR secondary), and the `is_non_routable_v4`
    /// filter (an ad-blocked `127.0.0.1` pin in the OS cache must never become a
    /// `/32`). Collateral detection is intentionally NOT run here — that is a
    /// property of live observation, not of a cache snapshot. Best-effort: a
    /// read error is logged at debug and yields an empty summary.
    pub fn seed_from_os_cache(&self, now: SystemTime) -> ConsumeSummary {
        let mut summary = ConsumeSummary::default();
        let Some(sid) = (self.active_sid)() else {
            return summary;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return summary;
        };
        let entries = match self.dns_cache_read.read_resolver_cache() {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(
                    target: "nrr::dns-observe",
                    error = ?e,
                    "OS resolver-cache read failed — skipping seed this tick",
                );
                return summary;
            }
        };
        for entry in entries {
            let routable: Vec<Ipv4Addr> = entry
                .addresses
                .iter()
                .copied()
                .filter(|ip| !is_non_routable_v4(ip))
                .collect();
            if routable.is_empty() {
                continue;
            }
            let matches = rule_set_matches(&entry.canonical_hostname, &snapshot.rule_book.primary)
                || rule_set_matches(&entry.canonical_hostname, &snapshot.rule_book.secondary);
            if !matches {
                summary.ignored = summary.ignored.saturating_add(1);
                continue;
            }
            self.upsert_counted(
                &entry.canonical_hostname,
                &routable,
                now,
                StorageResolutionSource::OsCacheSeed,
                &mut summary,
            );
        }
        if summary.matched > 0 {
            tracing::info!(
                target: "nrr::dns-observe",
                matched = summary.matched,
                refreshed = summary.refreshed,
                ignored = summary.ignored,
                "seeded FQDN cache from OS resolver cache (rule-matching hosts the observer missed)",
            );
        }
        summary
    }

    /// cache an FCrDNS-confirmed
    /// `(hostname, addresses)` fact learned from an NRR block drop. Same keep-logic
    /// as [`seed_from_os_cache`](Self::seed_from_os_cache): active-SID gate,
    /// active-rules match (primary OR secondary), `is_non_routable_v4` filter —
    /// but recorded with source [`StorageResolutionSource::ReverseConfirmed`] so
    /// diagnostics distinguish it. Returns `true` iff the host matched a rule and
    /// was cached (the [`crate::fcrdns_learner::ConfirmedHostSink`] contract). The
    /// caller has ALREADY forward-confirmed the name against the dropped IP; this
    /// only applies the rule gate + upsert.
    pub fn learn_reverse_confirmed(
        &self,
        hostname: &str,
        addresses: &[Ipv4Addr],
        now: SystemTime,
    ) -> bool {
        let Some(sid) = (self.active_sid)() else {
            return false;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return false;
        };
        let routable: Vec<Ipv4Addr> = addresses
            .iter()
            .copied()
            .filter(|ip| !is_non_routable_v4(ip))
            .collect();
        if routable.is_empty() {
            return false;
        }
        let in_primary = rule_set_matches(hostname, &snapshot.rule_book.primary);
        let in_secondary = rule_set_matches(hostname, &snapshot.rule_book.secondary);
        if !in_primary && !in_secondary {
            return false;
        }
        // A name the user routes over the PRIMARY, found on an address the
        // kill-switch has pinned to the secondary, is the shared-IP census's
        // subject — it just arrived by reverse lookup instead of by watching a
        // query. Without this the census can only learn from resolutions we
        // saw, so a browser on DoH keeps the address pinned and keeps getting
        // blocked: exactly the "search.example is in my primary rules and still
        // will not open" report. A suffix rule (`*.search.example`) has no address
        // of its own to seed, which is why the drop is the only evidence there
        // will ever be.
        if in_primary && !in_secondary {
            // Reaching here means a main-route rule claims this host, which is
            // exactly what `primary_ruled` records.
            for ip in &routable {
                self.record_direct_tenant(hostname, *ip, now, true);
            }
        }
        // Memo gate: only pairs not confirmed within the TTL survive. Without
        // this a blocked burst re-learns the same facts per drop and each
        // acceptance re-arms a reconcile.
        let novel = self.note_reverse_confirmed(hostname, &routable, now);
        if novel.is_empty() {
            return false;
        }
        let kept = self.upsert(
            hostname,
            &novel,
            now,
            StorageResolutionSource::ReverseConfirmed,
        );
        if kept {
            tracing::info!(
                target: "nrr::dns-observe",
                hostname = %hostname,
                addresses = novel.len(),
                "cached a reverse-confirmed rule host learned from an NRR drop (browser-cache/DoH blind spot)",
            );
        }
        kept
    }

    /// Filter `addresses` down to the pairs not seen within
    /// [`REVERSE_CONFIRM_MEMO_TTL`], recording the survivors at `now`. Expired
    /// entries are pruned on the way; a memo past
    /// [`REVERSE_CONFIRM_MEMO_MAX`] is dropped wholesale rather than managed.
    fn note_reverse_confirmed(
        &self,
        hostname: &str,
        addresses: &[Ipv4Addr],
        now: SystemTime,
    ) -> Vec<Ipv4Addr> {
        let mut memo = self
            .reverse_confirm_memo
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        memo.retain(|_, seen_at| {
            now.duration_since(*seen_at)
                .map_or(true, |age| age < REVERSE_CONFIRM_MEMO_TTL)
        });
        if memo.len() > REVERSE_CONFIRM_MEMO_MAX {
            memo.clear();
        }
        // After the retain pass every surviving entry is fresh, so a present
        // key means "confirmed within the TTL" — only absent keys are novel.
        addresses
            .iter()
            .copied()
            .filter(|ip| memo.insert((hostname.to_string(), *ip), now).is_none())
            .collect()
    }

    /// register an FCrDNS-confirmed `(hostname, addresses)`
    /// fact whose name matches NO active rule as a known-DIRECT destination.
    /// The inverse gate of [`learn_reverse_confirmed`](Self::learn_reverse_confirmed):
    /// same active-SID + routable filters, but the host must match NEITHER rule
    /// set — a rule match here means the rule path should have kept it, so the
    /// direct claim is refused. Feeds the known-direct registry (NOT the FQDN
    /// cache — the cache is rule-matching by design); the block-all exemption
    /// compiles on the next reconcile. Returns `true` iff at least one new
    /// address was registered.
    pub fn learn_reverse_confirmed_direct(&self, hostname: &str, addresses: &[Ipv4Addr]) -> bool {
        let Some(registry) = self.known_direct.as_ref() else {
            return false;
        };
        let Some(sid) = (self.active_sid)() else {
            return false;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return false;
        };
        if rule_set_matches(hostname, &snapshot.rule_book.primary)
            || rule_set_matches(hostname, &snapshot.rule_book.secondary)
        {
            return false;
        }
        let routable: Vec<Ipv4Addr> = addresses
            .iter()
            .copied()
            .filter(|ip| !is_non_routable_v4(ip))
            .collect();
        if routable.is_empty() {
            return false;
        }
        let added = registry.register(&routable);
        if added > 0 {
            tracing::info!(
                target: "nrr::dns-observe",
                hostname = %hostname,
                addresses = added,
                "registered a reverse-confirmed DIRECT host from an NRR drop — block-all exemption compiles on the next reconcile",
            );
        }
        added > 0
    }
}
