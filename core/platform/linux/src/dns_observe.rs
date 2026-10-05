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

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::{Child, Stdio};
use std::sync::{Arc, Mutex};

use nrr_platform_api::dns_observe::{DnsObservation, DnsObservationSource};

/// Resource-record type for an IPv4 address; anything else in the answer is not
/// a destination this product can route to.
const TYPE_A: u64 = 1;
const TYPE_CNAME: u64 = 5;
const CLASS_IN: u64 = 1;
/// A resolver follows at most a handful of aliases; a longer chain in one
/// answer is a loop or garbage.
const MAX_ALIAS_HOPS: usize = 16;

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
        let mut child = crate::command::system_tool("resolvectl")
            .and_then(|exe| {
                crate::command::tool_command(exe)
                    .args(["monitor", "--json=short"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .stdin(Stdio::null())
                    .spawn()
            })
            .map_err(|e| {
                tracing::info!(
                    target: "nrr::dns",
                    msg_key = "linux-dns-monitor-unavailable",
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
                    let mut observations = parse_monitor_line(&line).peekable();
                    if observations.peek().is_some() {
                        sink.lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .extend(observations);
                    }
                }
                // The stream ending means resolved stopped or the monitor was
                // closed. Said once, at the level of a fact rather than an error:
                // a machine may legitimately stop its resolver.
                tracing::info!(
                    target: "nrr::dns",
                    msg_key = "linux-dns-monitor-stream-ended",
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

/// Turn one `--json=short` line into observations: the answer under the name
/// that was asked for and, when an alias chain led elsewhere, under the name
/// the addresses belong to as well.
///
/// Empty for anything that is not a successful A-record answer: a failed
/// lookup, an AAAA-only answer, a line this build does not understand. Pure, so
/// it is tested against real captured output on any host.
pub fn parse_monitor_line(line: &str) -> impl Iterator<Item = DnsObservation> {
    let (queried, answered) = match parse_answer(line) {
        Some((queried, answered)) => (Some(queried), answered),
        None => (None, None),
    };
    [queried, answered].into_iter().flatten()
}

/// The queried-name observation, plus the final-name one when the names differ.
fn parse_answer(line: &str) -> Option<(DnsObservation, Option<DnsObservation>)> {
    let event: serde_json::Value = serde_json::from_str(line).ok()?;
    if event.get("state").and_then(|s| s.as_str()) != Some("success") {
        return None;
    }

    let mut records: Vec<(String, Ipv4Addr)> = Vec::new();
    // Alias target -> alias owner, to walk a chain back towards the question.
    let mut aliased_from: HashMap<String, String> = HashMap::new();
    for answer in event.get("answer")?.as_array()? {
        let rr = answer.get("rr")?;
        let key = rr.get("key")?;
        if key.get("class").and_then(serde_json::Value::as_u64) != Some(CLASS_IN) {
            continue;
        }
        let owner = canonical(key.get("name")?.as_str()?);
        match key.get("type").and_then(serde_json::Value::as_u64) {
            Some(TYPE_A) => {
                let octets = rr.get("address")?.as_array()?;
                if octets.len() != 4 {
                    continue;
                }
                let mut address = [0u8; 4];
                for (slot, value) in address.iter_mut().zip(octets) {
                    *slot = u8::try_from(value.as_u64()?).ok()?;
                }
                records.push((owner, Ipv4Addr::from(address)));
            }
            Some(TYPE_CNAME) => {
                if let Some(target) = rr.get("name").and_then(serde_json::Value::as_str) {
                    aliased_from.insert(canonical(target), owner);
                }
            }
            _ => {}
        }
    }

    // A rule may name what was asked for (what the Windows source reports) or
    // the CDN suffix the chain ends on, so both names learn the addresses. One
    // chain per answer; another chain arrives as its own record.
    let (final_name, _) = records.first()?;
    let final_name = final_name.clone();
    let queried = alias_origin(final_name.clone(), &aliased_from);
    let mut queried_ipv4s = Vec::new();
    let mut final_ipv4s = Vec::new();
    for (owner, address) in records {
        if owner == final_name {
            final_ipv4s.push(address);
        }
        if alias_origin(owner, &aliased_from) == queried {
            queried_ipv4s.push(address);
        }
    }

    let answered = (final_name != queried).then_some(DnsObservation {
        hostname: final_name,
        ipv4s: final_ipv4s,
    });
    Some((
        DnsObservation {
            hostname: queried,
            ipv4s: queried_ipv4s,
        },
        answered,
    ))
}

/// Follow CNAMEs from the record's owner back to the name that started the
/// chain. Bounded, so a looping answer ends the walk instead of the thread.
fn alias_origin(mut name: String, aliased_from: &HashMap<String, String>) -> String {
    for _ in 0..MAX_ALIAS_HOPS {
        match aliased_from.get(&name) {
            Some(owner) if *owner != name => name.clone_from(owner),
            _ => break,
        }
    }
    name
}

fn canonical(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of a `resolvectl monitor --json=short` line (systemd 255) with
    /// documentation addresses, so the parser meets the real structure.
    const LIVE_LINE: &str = r#"{"state":"success","question":[{"class":1,"type":1,"name":"example.com"},{"class":1,"type":28,"name":"example.com"}],"answer":[{"rr":{"key":{"class":1,"type":1,"name":"example.com"},"address":[203,0,113,160]},"raw":"B2V4YW1wbGU=","ifindex":2},{"rr":{"key":{"class":1,"type":1,"name":"example.com"},"address":[203,0,113,143]},"raw":"B2V4YW1wbGU=","ifindex":2},{"rr":{"key":{"class":1,"type":28,"name":"example.com"},"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]},"raw":"B2V4YW1wbGU=","ifindex":2}]}"#;

    fn parsed(line: &str) -> Vec<DnsObservation> {
        parse_monitor_line(line).collect()
    }

    fn hostnames(observations: &[DnsObservation]) -> Vec<&str> {
        observations.iter().map(|o| o.hostname.as_str()).collect()
    }

    /// Without an alias the asked name and the owner coincide: one observation.
    #[test]
    fn a_successful_answer_yields_the_name_and_its_v4_addresses() {
        let observations = parsed(LIVE_LINE);

        assert_eq!(hostnames(&observations), vec!["example.com"]);
        assert_eq!(
            observations[0].ipv4s,
            vec![
                Ipv4Addr::new(203, 0, 113, 160),
                Ipv4Addr::new(203, 0, 113, 143)
            ],
        );
    }

    /// A v6-only name resolves fine and routes nothing this product can pin, so
    /// it is not an observation — recording it with no addresses would put an
    /// empty answer in the cache.
    #[test]
    fn an_answer_without_v4_addresses_is_not_an_observation() {
        let v6_only = r#"{"state":"success","question":[{"class":1,"type":28,"name":"ipv6.example"}],"answer":[{"rr":{"key":{"class":1,"type":28,"name":"ipv6.example"},"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]},"ifindex":2}]}"#;

        assert!(parsed(v6_only).is_empty());
    }

    /// A rule may name what was asked for or the CDN suffix the alias chain
    /// lands on; both learn the same addresses.
    #[test]
    fn an_alias_chain_is_reported_under_the_queried_and_the_final_name() {
        let aliased = r#"{"state":"success","question":[{"class":1,"type":1,"name":"www.example.com"}],"answer":[{"rr":{"key":{"class":1,"type":5,"name":"www.example.com"},"name":"www.example.com.cdn.example"},"ifindex":2},{"rr":{"key":{"class":1,"type":5,"name":"www.example.com.cdn.example"},"name":"edge.cdn.example"},"ifindex":2},{"rr":{"key":{"class":1,"type":1,"name":"edge.cdn.example"},"address":[192,0,2,10]},"ifindex":2},{"rr":{"key":{"class":1,"type":1,"name":"edge.cdn.example"},"address":[192,0,2,11]},"ifindex":2}]}"#;

        let observations = parsed(aliased);

        assert_eq!(
            hostnames(&observations),
            vec!["www.example.com", "edge.cdn.example"]
        );
        let addresses = vec![Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)];
        assert!(observations.iter().all(|o| o.ipv4s == addresses));
    }

    #[test]
    fn a_looping_alias_chain_ends_instead_of_spinning() {
        let looping = r#"{"state":"success","answer":[{"rr":{"key":{"class":1,"type":5,"name":"a.example"},"name":"b.example."},"ifindex":2},{"rr":{"key":{"class":1,"type":5,"name":"B.example"},"name":"a.example"},"ifindex":2},{"rr":{"key":{"class":1,"type":1,"name":"b.example"},"address":[192,0,2,20]},"ifindex":2}]}"#;

        let observations = parsed(looping);

        assert!(!observations.is_empty() && observations.len() <= 2);
        for observation in &observations {
            assert!(["a.example", "b.example"].contains(&observation.hostname.as_str()));
            assert_eq!(observation.ipv4s, vec![Ipv4Addr::new(192, 0, 2, 20)]);
        }
    }

    #[test]
    fn a_failed_lookup_is_not_an_observation() {
        let failed = r#"{"state":"errno","question":[{"class":1,"type":1,"name":"nope.invalid"}]}"#;

        assert!(parsed(failed).is_empty());
    }

    #[test]
    fn a_line_this_build_does_not_understand_is_skipped_rather_than_guessed() {
        assert!(parsed("not json at all").is_empty());
        assert!(parsed(r#"{"state":"success"}"#).is_empty());
        assert!(parsed(r#"{"state":"success","answer":[]}"#).is_empty());
    }

    /// The machine where the monitor is connected and permanently silent. The
    /// caller must be able to tell that apart from a quiet network.
    #[test]
    fn a_foreign_resolv_conf_means_nothing_will_be_observed() {
        let foreign = "Global\n  resolv.conf mode: foreign\n  Current DNS Server: 192.0.2.53\n";
        let stub = "Global\n  resolv.conf mode: stub\n  Current DNS Server: 127.0.0.53\n";

        assert!(!resolutions_pass_through_resolved(foreign));
        assert!(resolutions_pass_through_resolved(stub));
    }
}
