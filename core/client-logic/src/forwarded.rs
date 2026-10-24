//! Traffic the computer forwards for others — WSL, containers, virtual
//! machines: whether such a network is up, and when a client asks the user to
//! answer for it. The setting itself is shown wherever the platform guards
//! forwarded traffic: a guest on a bridge or a shared connection is forwarded
//! too, whatever its adapter is called.
//!
//! Each of them gets an adapter of its own while it runs; its traffic leaves
//! through the computer's links as forwarded packets, which the user's own leak
//! guard does not see. The answer is the per-user `forwarded-outage` field:
//! `""` (not answered yet), `as-computer` or `unprotected`.

use crate::system_dns::NoticeStep;

/// What every spelling of the WSL adapter opens with: `vEthernet (WSL)`, or
/// `vEthernet (WSL (Hyper-V firewall))` on newer builds. Lower case.
const WSL_ADAPTER_PREFIX: &str = "vethernet (wsl";

/// Whether an adapter `name` is a network the computer forwards for
/// (`isForwardingAdapterName`).
pub fn is_forwarding_adapter_name(name: &str) -> bool {
    let wsl = name
        .as_bytes()
        .get(..WSL_ADAPTER_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(WSL_ADAPTER_PREFIX.as_bytes()));
    wsl || nrr_shared::is_linux_bridge_name(name)
}

/// Whether any of the adapter `names` is such a network (`forwardingPresent`).
pub fn forwarding_present<'a>(names: impl IntoIterator<Item = &'a str>) -> bool {
    names.into_iter().any(is_forwarding_adapter_name)
}

/// Ask when such a network appears unanswered for a user with an additional
/// route (with none there is no outage to answer for); a request the user
/// dismissed stays down while it stays up, and it coming up again asks again
/// (`forwardedNoticeStep`).
pub fn notice_step(was_raised: bool, present: bool, routed: bool, answer: &str) -> NoticeStep {
    let waiting = present && routed && answer.is_empty();
    NoticeStep {
        raise: waiting && !was_raised,
        raised: waiting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_or_other_name_is_not_wsl() {
        assert!(!is_forwarding_adapter_name("vEthernet"));
        assert!(!is_forwarding_adapter_name("vEthernet (Default Switch)"));
        assert!(is_forwarding_adapter_name("docker0"));
        assert!(
            !is_forwarding_adapter_name("Docker0"),
            "Linux names are exact"
        );
        assert!(is_forwarding_adapter_name(
            "vEthernet (WSL (Hyper-V firewall))"
        ));
    }
}
