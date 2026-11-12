use std::collections::BTreeSet;

use nrr_shared::ipc_payloads::{
    DnsCompatibilityDto, DnsCompatibilityIssueDto, DnsCompatibilityStatus,
};

const MAX_CACHED_PROGRAMS: usize = 64;
const MAX_CACHED_ISSUES: usize = 384;

fn bounded_issues(
    issues: Vec<DnsCompatibilityIssueDto>,
    incomplete: &mut bool,
) -> Vec<DnsCompatibilityIssueDto> {
    let mut programs = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut kept = Vec::with_capacity(issues.len().min(MAX_CACHED_ISSUES));
    for issue in issues {
        if issue.program.is_empty()
            || issue.program.len() > 4096
            || issue.reason.len() > 64
            || issue.evidence.len() > 32
            || kept.len() >= MAX_CACHED_ISSUES
            || (!programs.contains(&issue.program) && programs.len() >= MAX_CACHED_PROGRAMS)
        {
            *incomplete = true;
            continue;
        }
        if !identities.insert((issue.program.clone(), issue.reason.clone())) {
            continue;
        }
        programs.insert(issue.program.clone());
        kept.push(issue);
    }
    kept
}

/// A restart cannot certify recovery merely because the new service has no history.
#[must_use]
pub fn merge(
    previous: &DnsCompatibilityDto,
    mut incoming: DnsCompatibilityDto,
) -> DnsCompatibilityDto {
    let same_instance =
        !previous.instance_id.is_empty() && previous.instance_id == incoming.instance_id;
    if same_instance && incoming.sequence < previous.sequence {
        return previous.clone();
    }
    if incoming.status == DnsCompatibilityStatus::Verified
        && ((!previous.instance_id.is_empty()
            && !same_instance
            && (!previous.issues.is_empty()
                || matches!(
                    previous.status,
                    DnsCompatibilityStatus::Limited | DnsCompatibilityStatus::NeedsRecheck
                )))
            || (same_instance
                && incoming.sequence == previous.sequence
                && previous.status != DnsCompatibilityStatus::Verified))
    {
        return previous.clone();
    }
    let resolver_ready = incoming.last_checked_ms.is_some()
        && incoming.resolver.listener == "ready"
        && incoming.resolver.redirect == "ready"
        && incoming.resolver.upstream == "ready";
    let mut cached = Vec::new();
    for issue in &previous.issues {
        if same_instance && !issue.needs_recheck && !incoming.issues.is_empty() {
            continue;
        }
        let superseded = incoming.issues.iter().any(|fresh| {
            fresh.program == issue.program
                && (fresh.reason == issue.reason
                    || (fresh.reason == "strict-browser-dns"
                        && matches!(
                            issue.reason.as_str(),
                            "resolver-contact" | "our-dns-block" | "unknown"
                        )))
        });
        let connection_confirmed = incoming.verified_program.as_deref()
            == Some(issue.program.as_str())
            && matches!(
                issue.reason.as_str(),
                "resolver-contact" | "our-dns-block" | "unknown"
            );
        let resolver_confirmed = resolver_ready && issue.reason == "local-resolver-unavailable";
        let secondary_confirmed = incoming.last_checked_ms.is_some()
            && incoming.secondary_readiness == "ready"
            && issue.reason == "secondary-unavailable";
        if !(superseded || connection_confirmed || resolver_confirmed || secondary_confirmed) {
            let mut retained = issue.clone();
            retained.needs_recheck = true;
            cached.push(retained);
        }
    }
    let retained_history = !cached.is_empty();
    incoming.history_incomplete |= previous.history_incomplete;
    incoming.issues.extend(cached);
    incoming.issues = bounded_issues(
        std::mem::take(&mut incoming.issues),
        &mut incoming.history_incomplete,
    );
    if retained_history || incoming.history_incomplete {
        incoming.status = DnsCompatibilityStatus::NeedsRecheck;
    }
    if incoming.instance_id.is_empty() && incoming.status != DnsCompatibilityStatus::Verified {
        incoming.instance_id.clone_from(&previous.instance_id);
        incoming.sequence = previous.sequence;
    }
    incoming
}
