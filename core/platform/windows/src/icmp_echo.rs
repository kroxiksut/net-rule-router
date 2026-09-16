//! Windows mechanism behind [`nrr_platform_api::icmp_echo::IcmpEchoPort`]:
//! `IcmpSendEcho2Ex`, which takes both the hop limit and the source address,
//! and reports a router's "time exceeded" the same way `tracert` reads it.

#![allow(unsafe_code)]
// The status reading has no caller off Windows; it still compiles and is tested there.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use std::net::Ipv4Addr;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::icmp_echo::{EchoOutcome, EchoProbe, IcmpEchoPort};

// `IP_*` reply statuses from `ipexport.h`.
const IP_SUCCESS: u32 = 0;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsIcmpEcho;

/// Read one reply status the way `tracert` does. `None` is a status that says
/// the call itself failed rather than what the network answered.
fn outcome_from_status(status: u32, address: Ipv4Addr) -> Option<EchoOutcome> {
    let unreachable = |code| EchoOutcome::Unreachable {
        from: address,
        code,
    };
    Some(match status {
        IP_SUCCESS => EchoOutcome::Reply,
        IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => {
            EchoOutcome::TtlExpired { router: address }
        }
        IP_DEST_NET_UNREACHABLE => unreachable(0),
        IP_DEST_HOST_UNREACHABLE => unreachable(1),
        IP_DEST_PROT_UNREACHABLE => unreachable(2),
        IP_DEST_PORT_UNREACHABLE => unreachable(3),
        IP_REQ_TIMED_OUT => EchoOutcome::TimedOut,
        _ => return None,
    })
}

/// A Win32 `IPAddr` is the four octets in network order read as a native u32.
fn ip_addr(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

#[cfg(target_os = "windows")]
impl IcmpEchoPort for WindowsIcmpEcho {
    fn echo(&self, probe: &EchoProbe) -> Result<EchoOutcome, PlatformError> {
        use windows::Win32::Foundation::{GetLastError, HANDLE};
        use windows::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex, ICMP_ECHO_REPLY,
            IP_OPTION_INFORMATION,
        };

        let payload_len =
            u16::try_from(probe.payload.len()).map_err(|_| PlatformError::NotSupported {
                reason: "ICMP echo payload larger than 65535 bytes",
            })?;
        // Room for the reply header, the echoed payload, and the quoted header
        // an ICMP error carries.
        let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + probe.payload.len() + 64;
        let mut reply = vec![0u8; reply_size];
        let options = IP_OPTION_INFORMATION {
            Ttl: probe.ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        let timeout_ms = u32::try_from(probe.timeout.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);

        // SAFETY: the handle is only passed back to the ICMP API and closed once below.
        let handle: HANDLE = unsafe { IcmpCreateFile() }.map_err(|e| PlatformError::Transient {
            operation: "IcmpCreateFile",
            detail: e.to_string(),
        })?;
        // SAFETY: synchronous call (no event, no APC); every buffer outlives it
        // and its length is the one passed.
        let replies = unsafe {
            IcmpSendEcho2Ex(
                handle,
                HANDLE::default(),
                None,
                None,
                probe.source.map_or(0, ip_addr),
                ip_addr(probe.destination),
                probe.payload.as_ptr().cast(),
                payload_len,
                Some(&options),
                reply.as_mut_ptr().cast(),
                u32::try_from(reply_size).unwrap_or(u32::MAX),
                timeout_ms,
            )
        };
        // SAFETY: read immediately after the call that set it.
        let last_error = unsafe { GetLastError() }.0;
        // SAFETY: closing the handle opened above.
        unsafe {
            let _ = IcmpCloseHandle(handle);
        }

        if replies == 0 {
            return match outcome_from_status(last_error, probe.destination) {
                Some(EchoOutcome::TimedOut) => Ok(EchoOutcome::TimedOut),
                _ => Err(PlatformError::Win32 {
                    operation: "IcmpSendEcho2Ex",
                    code: last_error,
                    message: "the echo could not be sent".into(),
                }),
            };
        }
        // SAFETY: at least one reply means the buffer starts with a filled
        // `ICMP_ECHO_REPLY`, and the buffer is larger than one.
        let first = unsafe { reply.as_ptr().cast::<ICMP_ECHO_REPLY>().read_unaligned() };
        let address = Ipv4Addr::from(first.Address.to_ne_bytes());
        outcome_from_status(first.Status, address).ok_or_else(|| PlatformError::Win32 {
            operation: "IcmpSendEcho2Ex",
            code: first.Status,
            message: "the echo reply carried an unexpected status".into(),
        })
    }
}

#[cfg(not(target_os = "windows"))]
impl IcmpEchoPort for WindowsIcmpEcho {
    fn echo(&self, _probe: &EchoProbe) -> Result<EchoOutcome, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "the Windows ICMP mechanism runs only on Windows",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    #[test]
    fn a_router_that_ran_out_the_hop_limit_is_named() {
        assert_eq!(
            outcome_from_status(IP_TTL_EXPIRED_TRANSIT, ROUTER),
            Some(EchoOutcome::TtlExpired { router: ROUTER })
        );
    }

    #[test]
    fn unreachable_statuses_keep_their_icmp_codes() {
        for (status, code) in [
            (IP_DEST_NET_UNREACHABLE, 0),
            (IP_DEST_HOST_UNREACHABLE, 1),
            (IP_DEST_PROT_UNREACHABLE, 2),
            (IP_DEST_PORT_UNREACHABLE, 3),
        ] {
            assert_eq!(
                outcome_from_status(status, ROUTER),
                Some(EchoOutcome::Unreachable { from: ROUTER, code })
            );
        }
    }

    #[test]
    fn a_failure_of_the_call_is_not_read_as_an_answer() {
        assert_eq!(outcome_from_status(11050, ROUTER), None);
    }

    #[test]
    fn the_address_is_passed_in_network_order() {
        assert_eq!(ip_addr(ROUTER).to_ne_bytes(), [192, 0, 2, 1]);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn loopback_answers() {
        let outcome = WindowsIcmpEcho.echo(&EchoProbe {
            destination: Ipv4Addr::LOCALHOST,
            source: None,
            ttl: 64,
            payload: b"nrr-echo".to_vec(),
            timeout: std::time::Duration::from_secs(1),
        });
        assert!(matches!(outcome, Ok(EchoOutcome::Reply)), "{outcome:?}");
    }

    /// A hop limit of one cannot reach anything past the first router, so a
    /// real destination has to come back as "time exceeded" from that router.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "needs a routed network path"]
    fn a_hop_limit_of_one_is_answered_by_the_first_router() {
        let outcome = WindowsIcmpEcho.echo(&EchoProbe {
            destination: Ipv4Addr::new(1, 1, 1, 1),
            source: None,
            ttl: 1,
            payload: b"nrr-echo".to_vec(),
            timeout: std::time::Duration::from_secs(2),
        });
        assert!(
            matches!(outcome, Ok(EchoOutcome::TtlExpired { .. })),
            "{outcome:?}"
        );
    }
}
