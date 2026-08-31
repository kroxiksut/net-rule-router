//! Passive observation of DNS resolutions, from systemd-resolved.
//!
//! The Linux counterpart of the Windows ETW DNS-Client source. `resolvectl
//! monitor --json=short` streams every query systemd-resolved answers, so the
//! observation costs nothing on the data path: the resolver is telling us what
//! it already did, rather than us copying packets to look.
//!
//! ## What it sees, and when it sees nothing
//!
//! Only resolutions that go THROUGH systemd-resolved. Two common machines see
//! nothing at all, and both are worth saying out loud rather than reporting an
//! empty stream as quiet:
//!
//! - `/etc/resolv.conf` points straight at a server instead of the `127.0.0.53`
//!   stub (`resolvectl status` calls this `resolv.conf mode: foreign`). Programs
//!   then talk to the server directly and resolved never learns of it.
//! - No systemd-resolved at all — a container, or a distribution using another
//!   resolver.
//!
//! DNS-over-HTTPS inside a browser is invisible either way, on every platform:
//! the name never leaves the application as a DNS query.
//!
//! ## Why a child process rather than the socket
//!
//! The monitor socket speaks systemd's varlink protocol, and `resolvectl` is the
//! supported reader of it. Parsing its `--json=short` lines keeps us on a
//! documented interface instead of a private wire format that may change with
//! any systemd release.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use nrr_platform_api::dns_observe::{DnsObservation, DnsObservationSource};

/// Resource-record type for an IPv4 address; anything else in the answer is not
/// a destination this product can route to.
const TYPE_A: u64 = 1;
const CLASS_IN: u64 = 1;

/// The reader is a `resolvectl` child; keeping the handle lets the observer stop
/// it when it is dropped, rather than leaving a process attached to the monitor
/// socket for the life of the machine.
pub struct ResolvedDnsObserver {
    buffered: Arc<Mutex<Vec<DnsObservation>>>,
    child: Mutex<Option<Child>>,
}

impl ResolvedDnsObserver {
    /// Start watching. Returns `None` when systemd-resolved's monitor cannot be
    /// read — no `resolvectl`, no resolved, or no permission — because an
    /// observer that never produces anything must not be mistaken for a quiet
    /// network.
    pub fn start() -> Option<Self> {
        let mut child = Command::new("resolvectl")
            .args(["monitor", "--json=short"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| {
                tracing::info!(
                    target: "nrr::dns",
                    error = %e,
                    "systemd-resolved's query monitor is not available; DNS resolutions are not \
                     observed on this machine",
                );
            })
            .ok()?;
        let stdout = child.stdout.take()?;

        let buffered = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&buffered);
        std::thread::Builder::new()
            .name("nrr-dns-monitor".to_owned())
            .spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    if let Some(observation) = parse_monitor_line(&line) {
                        sink.lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(observation);
                    }
                }
                // The stream ending means resolved stopped or the monitor was
                // closed. Said once, at the level of a fact rather than an error:
                // a machine may legitimately stop its resolver.
                tracing::info!(
                    target: "nrr::dns",
                    "the DNS query monitor stream ended; resolutions are no longer observed",
                );
            })
            .ok()?;

        Some(Self {
            buffered,
            child: Mutex::new(Some(child)),
        })
    }
}

impl Drop for ResolvedDnsObserver {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl DnsObservationSource for ResolvedDnsObserver {
    fn drain(&self) -> Vec<DnsObservation> {
        std::mem::take(&mut *self.buffered.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

/// Whether resolutions on this machine actually pass through systemd-resolved.
///
/// `resolv.conf mode: foreign` means programs talk to a server directly, so the
/// monitor is connected and silent. Reported by the caller at startup: silence
/// that is expected must not read the same as silence that is a fault.
#[must_use]
pub fn resolutions_pass_through_resolved(status_output: &str) -> bool {
    !status_output.contains("resolv.conf mode: foreign")
}

/// Read `resolvectl status` to answer [`resolutions_pass_through_resolved`].
#[must_use]
pub fn probe_resolver_mode() -> Option<bool> {
    let output = crate::command::output_with_timeout(
        "resolvectl",
        &["status"],
        crate::command::DEFAULT_COMMAND_TIMEOUT,
    )
    .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    Some(resolutions_pass_through_resolved(&text))
}

/// Turn one `--json=short` line into an observation.
///
/// `None` for anything that is not a successful A-record answer: a failed
/// lookup, an AAAA-only answer, a line this build does not understand. Pure, so
/// it is tested against real captured output on any host.
#[must_use]
pub fn parse_monitor_line(line: &str) -> Option<DnsObservation> {
    let event: serde_json::Value = serde_json::from_str(line).ok()?;
    if event.get("state").and_then(|s| s.as_str()) != Some("success") {
        return None;
    }

    let mut hostname: Option<String> = None;
    let mut ipv4s: Vec<Ipv4Addr> = Vec::new();
    for answer in event.get("answer")?.as_array()? {
        let rr = answer.get("rr")?;
        let key = rr.get("key")?;
        if key.get("type").and_then(serde_json::Value::as_u64) != Some(TYPE_A)
            || key.get("class").and_then(serde_json::Value::as_u64) != Some(CLASS_IN)
        {
            continue;
        }
        // The name comes from the RECORD, not the question: a query for an alias
        // is answered by the records of its target, and the address belongs to
        // the name that carries it.
        let name = key.get("name")?.as_str()?;
        let octets = rr.get("address")?.as_array()?;
        if octets.len() != 4 {
            continue;
        }
        let mut address = [0u8; 4];
        for (slot, value) in address.iter_mut().zip(octets) {
            *slot = u8::try_from(value.as_u64()?).ok()?;
        }
        let canonical = name.trim_end_matches('.').to_ascii_lowercase();
        // One observation carries one name. An answer naming two (an alias chain)
        // is reported for the first; the rest arrive as their own records.
        if hostname.get_or_insert(canonical.clone()) != &canonical {
            continue;
        }
        ipv4s.push(Ipv4Addr::from(address));
    }

    if ipv4s.is_empty() {
        return None;
    }
    Some(DnsObservation {
        hostname: hostname?,
        ipv4s,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured verbatim from `resolvectl monitor --json=short` on a live
    /// machine (systemd 255), so the parser is tested against the real shape
    /// rather than one imagined from documentation.
    const LIVE_LINE: &str = r#"{"state":"success","question":[{"class":1,"type":1,"name":"example.com"},{"class":1,"type":28,"name":"example.com"}],"answer":[{"rr":{"key":{"class":1,"type":1,"name":"example.com"},"address":[172,66,147,243]},"raw":"B2V4YW1wbGU=","ifindex":2},{"rr":{"key":{"class":1,"type":1,"name":"example.com"},"address":[104,20,23,154]},"raw":"B2V4YW1wbGU=","ifindex":2},{"rr":{"key":{"class":1,"type":28,"name":"example.com"},"address":[42,6,152,193,49,35,128,0,0,0,0,0,0,0,0,0]},"raw":"B2V4YW1wbGU=","ifindex":2}]}"#;

    #[test]
    fn a_successful_answer_yields_the_name_and_its_v4_addresses() {
        let observation = parse_monitor_line(LIVE_LINE).expect("a success line must parse");

        assert_eq!(observation.hostname, "example.com");
        assert_eq!(
            observation.ipv4s,
            vec![
                Ipv4Addr::new(172, 66, 147, 243),
                Ipv4Addr::new(104, 20, 23, 154)
            ],
        );
    }

    /// A v6-only name resolves fine and routes nothing this product can pin, so
    /// it is not an observation — recording it with no addresses would put an
    /// empty answer in the cache.
    #[test]
    fn an_answer_without_v4_addresses_is_not_an_observation() {
        let v6_only = r#"{"state":"success","question":[{"class":1,"type":28,"name":"ipv6.example"}],"answer":[{"rr":{"key":{"class":1,"type":28,"name":"ipv6.example"},"address":[42,6,152,193,49,35,128,0,0,0,0,0,0,0,0,0]},"ifindex":2}]}"#;

        assert!(parse_monitor_line(v6_only).is_none());
    }

    #[test]
    fn a_failed_lookup_is_not_an_observation() {
        let failed = r#"{"state":"errno","question":[{"class":1,"type":1,"name":"nope.invalid"}]}"#;

        assert!(parse_monitor_line(failed).is_none());
    }

    #[test]
    fn a_line_this_build_does_not_understand_is_skipped_rather_than_guessed() {
        assert!(parse_monitor_line("not json at all").is_none());
        assert!(parse_monitor_line(r#"{"state":"success"}"#).is_none());
        assert!(parse_monitor_line(r#"{"state":"success","answer":[]}"#).is_none());
    }

    /// The machine where the monitor is connected and permanently silent. The
    /// caller must be able to tell that apart from a quiet network.
    #[test]
    fn a_foreign_resolv_conf_means_nothing_will_be_observed() {
        let foreign = "Global\n  resolv.conf mode: foreign\n  Current DNS Server: 172.23.208.1\n";
        let stub = "Global\n  resolv.conf mode: stub\n  Current DNS Server: 127.0.0.53\n";

        assert!(!resolutions_pass_through_resolved(foreign));
        assert!(resolutions_pass_through_resolved(stub));
    }
}
