//! Who owns an address: recording a direct tenant, forgetting one, and the
//! counted upserts that keep the cache honest about how many names share an IP.

use super::*;

impl DnsObservationConsumer {
    /// `true` the first time a `(direct_host, ip)` collateral pair is seen,
    /// `false` on repeats — the observe tick re-sees the same resolutions
    /// every few seconds, so this keeps the WARN to one line per pair.
    pub(super) fn note_collateral_once(&self, direct_host: &str, ip: Ipv4Addr) -> bool {
        self.collateral_warned
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(format!("{direct_host}|{ip}"))
            .is_new
    }

    fn is_pending_companion(&self, hostname: &str) -> bool {
        self.auto_rules
            .as_ref()
            .is_some_and(|e| e.covers_pending_secondary_host(hostname))
    }

    /// Drop `hostname` from the shared-IP census, once per process. The
    /// once-only guard is not an optimisation: this runs on the observe tick,
    /// which sees the same host every few seconds while a page is open.
    fn forget_direct_tenant(&self, hostname: &str) {
        {
            let Ok(mut purged) = self.census_purged.lock() else {
                return;
            };
            if !purged.observe(hostname.to_ascii_lowercase()).is_new {
                return;
            }
        }
        let Ok(guard) = self.cache.lock() else {
            return;
        };
        match guard.forget_shared_ip_direct_host(hostname) {
            Ok(0) => {}
            Ok(rows) => tracing::info!(
                target: "nrr::dns-observe",
                host = %hostname,
                rows,
                "host is a parked suggestion for the additional route — dropped it from the shared-IP census so its addresses stay pinned there",
            ),
            Err(e) => tracing::debug!(
                target: "nrr::dns-observe",
                error = %e,
                "shared-IP census purge failed (heuristic only)",
            ),
        }
    }

    /// persist a `(direct_host, shared_ip)` observation to the
    /// shared-IP census so the codegen's shared-IP policy can count
    /// `direct_on_ip`. Best-effort: a census write failure never blocks the
    /// observe path (it only weakens the heuristic, never routing correctness).
    pub(super) fn record_direct_tenant(
        &self,
        direct_host: &str,
        ip: Ipv4Addr,
        now: SystemTime,
        primary_ruled: bool,
    ) {
        // A host already parked as a suggestion for the additional route is NOT
        // a direct tenant, whatever it looks like from here: we suspect it is
        // part of a site the user routes there. Counting it as one marks its
        // addresses "shared" and the smart kill-switch then exempts them from
        // pinning, so the host takes the default route — the CDN of a routed
        // site loading over the primary, which is the page that "opens but has
        // no pictures". Rows written before the suggestion existed are dropped
        // once, here, rather than left to age out.
        if self.is_pending_companion(direct_host) {
            self.forget_direct_tenant(direct_host);
            return;
        }
        let now_ms = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Err(e) = guard.record_shared_ip_direct_host(ip, direct_host, now_ms, primary_ruled) {
            tracing::debug!(
                target: "nrr::dns-observe",
                error = %e,
                "record shared-IP direct-host census failed (heuristic only)",
            );
        }
    }

    /// Upsert + classify: `matched` only when the ENFORCEABLE address set for
    /// `hostname` changed, `refreshed` when the write merely renewed recency.
    /// The before/after view is [`FqdnCacheLookup::ips_for_hostname`] — the
    /// same confirmation-window read the codegen consumes — so "changed" means
    /// exactly "the next recompute would derive something different".
    pub(super) fn upsert_counted(
        &self,
        hostname: &str,
        ips: &[Ipv4Addr],
        now: SystemTime,
        source: StorageResolutionSource,
        summary: &mut ConsumeSummary,
    ) {
        let before: std::collections::HashSet<Ipv4Addr> = self
            .fqdn_lookup
            .ips_for_hostname(hostname)
            .into_iter()
            .filter_map(v4_only)
            .collect();
        if !self.upsert(hostname, ips, now, source) {
            return;
        }
        let after: std::collections::HashSet<Ipv4Addr> = self
            .fqdn_lookup
            .ips_for_hostname(hostname)
            .into_iter()
            .filter_map(v4_only)
            .collect();
        if after == before {
            summary.refreshed = summary.refreshed.saturating_add(1);
        } else {
            summary.matched = summary.matched.saturating_add(1);
        }
    }

    pub(super) fn upsert(
        &self,
        hostname: &str,
        ips: &[Ipv4Addr],
        now: SystemTime,
        source: StorageResolutionSource,
    ) -> bool {
        let entry = ResolutionEntry {
            canonical_hostname: hostname.to_string(),
            raw_hostname_sample: None,
            resolved_ips: ips.iter().copied().map(IpAddr::V4).collect(),
            ttl_seconds: None,
            source,
            resolved_at: now,
            active_revision_id: None,
        };
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let Err(e) = guard.upsert_resolution(entry) {
            tracing::warn!(
                target: "nrr::dns-observe",
                error = %e,
                "upsert_resolution failed for observed hostname",
            );
            return false;
        }
        true
    }
}
