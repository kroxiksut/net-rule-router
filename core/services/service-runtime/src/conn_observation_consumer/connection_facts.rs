//! What a single observed connection says about itself.
//!
//! Pure predicates over one connection's process path and destination: no
//! `self`, no state, no I/O. They sat at the bottom of the consumer where the
//! batch loop could not be read without scrolling past them, and they are the
//! part most often read on its own — "why was this process treated as a VPN
//! client", "why was this address not learned".
//!
//! Behaviour is unchanged: the same functions, verbatim.

use nrr_domain::block_notice::BlockReason;

/// Base file name of a process path, lower-cased — the process identity
/// shown to the user (in logs and, later, block notices). `process_path` is
/// whatever form the observer captured (NT device path or Win32 path); only
/// the last `\`- or `/`-separated component matters.
/// `pub(super)` because the predicates moved out of the consumer and it is
/// now the caller.
pub(super) fn process_basename_lower(process_path: &str) -> String {
    process_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(process_path)
        .to_ascii_lowercase()
}

/// Which [`BlockReason`] an OUR-attributed drop maps to.
///
/// `killswitch_verified` already distinguishes the kill-switch/fail-closed
/// Block band via [`crate::killswitch_drop_registry`] — that band means the
/// route the destination is pinned to is down, i.e. [`BlockReason::RouteUnavailable`].
///
/// `default_block_id` is the deterministic id of the "no rule covers this
/// host" catch-all ([`crate::wfp_codegen::filter_id_for`] with role
/// `"default"`, computed fresh per batch from the active SID) — matching it
/// needs no new registry, only the same hash the codegen used to mint it, so
/// it maps cleanly to [`BlockReason::NotCoveredByRules`].
///
/// `fail_closed_armed` is the live block-all posture. The registry above only
/// recognizes the filters of the CURRENT compute, so a drop caught by a
/// neighbouring filter of the same outage (a fake-address block, a filter from
/// the compute before this one) falls through it — and calling that "a rule
/// blocked you" while the tunnel is down sends the user editing rules over an
/// outage. While the posture is armed there is exactly one cause worth naming.
///
/// `dns_lockdown` is the DoH/DoT band. It is read BEFORE the fail-closed
/// posture and before any rule reading: the band identifies the filter exactly,
/// and both other answers name a cause the user cannot act on here — the
/// lockdown has a switch of its own and no rule behind it.
///
/// An identified filter in none of those bands is an explicit rule Block
/// action — the only remaining source of an OUR drop in production codegen —
/// so it falls to [`BlockReason::BlockedByRule`].
///
/// Without a spec id nothing is identified at all: the filter lookup can fail,
/// and a filter retired between the drop and the lookup is gone by the time we
/// ask. Claiming a rule there is the most specific and most likely wrong thing
/// to say, so an unidentified drop outside the fail-closed window is
/// [`BlockReason::Unattributed`].
/// `pub(super)` because the predicates moved out of the consumer and it is
/// now the caller.
pub(super) fn block_reason_for(
    spec_id: Option<u64>,
    killswitch_verified: bool,
    default_block_id: Option<u64>,
    fail_closed_armed: bool,
    ipv6_cut: bool,
    dns_lockdown: bool,
) -> BlockReason {
    if killswitch_verified {
        return BlockReason::RouteUnavailable;
    }
    if spec_id.is_some() && spec_id == default_block_id {
        return BlockReason::NotCoveredByRules;
    }
    if dns_lockdown {
        return BlockReason::DnsLockdown;
    }
    // Before the fail-closed reading: while the block-all is armed the v6 cut
    // rides along with it, and "IPv6 is closed" is the cause the user can act
    // on — the outage is already announced by its own notice.
    if ipv6_cut {
        return BlockReason::Ipv6Blocked;
    }
    if fail_closed_armed {
        return BlockReason::RouteUnavailable;
    }
    match spec_id {
        Some(_) => BlockReason::BlockedByRule,
        None => BlockReason::Unattributed,
    }
}

/// Does `process_path`'s file name match any
/// built-in VPN-client pattern? `process_path` is a WFP app-id (an NT device
/// path like `\device\harddiskvolume2\...\openvpn.exe`); we match the bare file
/// name (last `\`- or `/`-separated component) against
/// [`crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS`] using the same
/// case-insensitive globber the resolver uses. `None`/empty never matches.
/// `pub(super)` because the predicates moved out of the consumer and it is
/// now the caller.
pub(super) fn process_name_matches_vpn(process_path: Option<&str>) -> bool {
    let Some(path) = process_path else {
        return false;
    };
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path).trim();
    if name.is_empty() {
        return false;
    }
    crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS
        .iter()
        .any(|glob| nrr_platform_api::app_path_resolver::glob_match(glob, name))
}

/// Does the drop's process belong to a peer-to-peer group
/// whose peers must be kept OUT of the FCrDNS rule-host learner? A P2P peer's
/// ISP hostname (`host.corbina.ru`) forward-confirms and matches a broad zone
/// rule (`.ru`), so learning it inflates the zone permit cap with thousands of
/// junk peers. The neutral [`nrr_platform_api::classify_app`]
/// dictionary + `suppresses_fcrdns_learning()` is the single source of truth for
/// which processes qualify (BitTorrent / P2P file-sharing / crypto nodes).
/// `None`/empty never suppresses.
/// `pub(super)` because the predicates moved out of the consumer and it is
/// now the caller.
pub(super) fn process_is_p2p_fcrdns_suppressed(process_path: Option<&str>) -> bool {
    let Some(path) = process_path else {
        return false;
    };
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path).trim();
    nrr_platform_api::classify_app(name)
        .map(|kind| kind.suppresses_fcrdns_learning())
        .unwrap_or(false)
}

/// Is `ip` a sensible VPN server to exempt? Skips
/// addresses that can never be a real unicast tunnel server: loopback /
/// link-local (already exempt in codegen), the unspecified / broadcast
/// addresses, the `0.0.0.0/8` "this network" block, multicast `224.0.0.0/4`,
/// and CGNAT `100.64.0.0/10`. A private-range IP (10/8,
/// 172.16/12, 192.168/16) IS learnable — a corporate VPN server can sit there.
/// `pub(super)` because the predicates moved out of the consumer and it is
/// now the caller.
pub(super) fn is_learnable_endpoint(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let is_this_network = a == 0; // 0.0.0.0/8
    let is_cgnat = a == 100 && (64..=127).contains(&b); // 100.64.0.0/10
                                                        // A fake-pool destination is our own TUN, not a real endpoint: a PTR
                                                        // lookup on it is meaningless and a "VPN server" learned there would
                                                        // exempt the pool from the kill-switch.
    let is_fake_pool =
        nrr_platform_api::fake_ip::FakeIpPoolConfig::is_default_pool_addr(std::net::IpAddr::V4(ip));
    !nrr_platform_api::is_exempt_from_blocking(ip)
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast() // 224.0.0.0/4
        && !is_this_network
        && !is_cgnat
        && !is_fake_pool
}
