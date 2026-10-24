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
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_platform_api::dns_observe::{
    DnsObservation, DnsObservationSource, MAX_ADDRESSES_PER_FAMILY,
};

use crate::restart::{Backoff, StopSignal};

/// Resource-record types for an address; anything else in the answer is not a
/// destination this product can route to.
const TYPE_A: u64 = 1;
const TYPE_AAAA: u64 = 28;
const TYPE_CNAME: u64 = 5;
const CLASS_IN: u64 = 1;
/// A resolver follows at most a handful of aliases; a longer chain in one
/// answer is a loop or garbage.
const MAX_ALIAS_HOPS: usize = 16;
/// Answer records read from one line; the rest are ignored. Far above any
/// real answer, and it bounds the alias map and the per-record work.
const MAX_ANSWER_RECORDS: usize = 512;
/// A longer line is skipped unread: a DNS answer is at most 64 KiB on the
/// wire, and its JSON rendering stays far below this.
pub const MAX_MONITOR_LINE_BYTES: usize = 1024 * 1024;
/// Observations held between drains (the consumer drains every few seconds).
/// Any local process can make resolved answer tens of thousands of cached
/// queries a second; past the cap they are dropped, as the ETW source does.
const MAX_BUFFERED_OBSERVATIONS: usize = 4096;

/// A resolved restart takes seconds; a resolved that stays down is asked
/// about once a minute rather than spawned against every second.
const RESPAWN_BACKOFF: Backoff = Backoff {
    first: Duration::from_secs(1),
    cap: Duration::from_secs(60),
};

/// The process behind one monitor stream.
trait MonitorChild: Send {
    fn kill(&mut self);
    fn reap(&mut self);
}

impl MonitorChild for Child {
    fn kill(&mut self) {
        let _ = Child::kill(self);
    }

    fn reap(&mut self) {
        let _ = self.wait();
    }
}

/// Kills the monitor process if it still runs, and reaps it, however its run
/// ends: no orphan stays attached to the monitor socket, no zombie is left.
struct OwnedChild(Box<dyn MonitorChild>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.0.kill();
        self.0.reap();
    }
}

/// One running monitor: what it prints and its process.
struct MonitorRun {
    output: Box<dyn Read + Send>,
    child: OwnedChild,
}

fn spawn_resolvectl() -> std::io::Result<MonitorRun> {
    let mut child = crate::command::system_tool("resolvectl").and_then(|exe| {
        crate::command::tool_command(exe)
            .args(["monitor", "--json=short"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
    })?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(std::io::Error::other(
            "resolvectl started without its output",
        ));
    };
    Ok(MonitorRun {
        output: Box::new(stdout),
        child: OwnedChild(Box::new(child)),
    })
}

/// Reads systemd-resolved's monitor through a `resolvectl` child, started
/// again whenever its stream ends (resolved restarted), until dropped.
pub struct ResolvedDnsObserver {
    buffered: Arc<Mutex<Vec<DnsObservation>>>,
    feeding: Arc<AtomicBool>,
    stop: Arc<StopSignal>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl ResolvedDnsObserver {
    /// Start watching. Returns `None` when systemd-resolved's monitor cannot be
    /// read — no `resolvectl`, no resolved, or no permission — because an
    /// observer that never produces anything must not be mistaken for a quiet
    /// network.
    pub fn start() -> Option<Self> {
        let first = spawn_resolvectl()
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
        Self::start_with(first, Box::new(spawn_resolvectl), RESPAWN_BACKOFF)
    }

    fn start_with(
        first: MonitorRun,
        mut respawn: Box<dyn FnMut() -> std::io::Result<MonitorRun> + Send>,
        backoff: Backoff,
    ) -> Option<Self> {
        let buffered = Arc::new(Mutex::new(Vec::new()));
        let feeding = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(StopSignal::default());
        let (sink, alive, thread_stop) = (
            Arc::clone(&buffered),
            Arc::clone(&feeding),
            Arc::clone(&stop),
        );
        let reader = std::thread::Builder::new()
            .name("nrr-dns-monitor".to_owned())
            .spawn(move || {
                run_monitor(first, &mut *respawn, &sink, &alive, &thread_stop, backoff);
            })
            .ok()?;
        Some(Self {
            buffered,
            feeding,
            stop,
            reader: Some(reader),
        })
    }
}

impl Drop for ResolvedDnsObserver {
    fn drop(&mut self) {
        self.stop.stop();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl DnsObservationSource for ResolvedDnsObserver {
    fn drain(&self) -> Vec<DnsObservation> {
        std::mem::take(&mut *self.buffered.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn is_feeding(&self) -> bool {
        self.feeding.load(Ordering::Acquire)
    }
}

/// Follow the monitor across resolved restarts until `stop`: read one run to
/// its end, reap its process, wait, start the next. `feeding` is false from a
/// stream's end until the next one runs.
fn run_monitor(
    first: MonitorRun,
    respawn: &mut (dyn FnMut() -> std::io::Result<MonitorRun> + Send),
    sink: &Mutex<Vec<DnsObservation>>,
    feeding: &AtomicBool,
    stop: &StopSignal,
    backoff: Backoff,
) {
    let mut run = Some(first);
    let mut delay = backoff.first;
    loop {
        if let Some(MonitorRun { output, child }) = run.take() {
            let child = Arc::new(Mutex::new(child));
            let killer = Arc::clone(&child);
            let armed = stop.arm(Box::new(move || {
                killer.lock().unwrap_or_else(|p| p.into_inner()).0.kill();
            }));
            let started = Instant::now();
            let saw_line = if armed {
                feeding.store(true, Ordering::Release);
                pump_lines(output, sink)
            } else {
                false
            };
            feeding.store(false, Ordering::Release);
            // Disarmed, the interrupt held no other handle: this drop reaps.
            stop.disarm();
            drop(child);
            if stop.is_stopped() {
                return;
            }
            // Only a run that worked earns a quick restart and a log line: a
            // resolved that stays down makes every new monitor exit at once.
            if saw_line || started.elapsed() >= backoff.cap {
                // Resolved stopped or restarted. Said at the level of a fact: a
                // machine may legitimately stop its resolver.
                tracing::info!(
                    target: "nrr::dns",
                    msg_key = "linux-dns-monitor-stream-ended",
                    "the DNS query monitor stream ended; resolutions are not observed until it is started again",
                );
                delay = backoff.first;
            } else {
                delay = backoff.after(delay);
            }
        }
        if stop.wait(delay) {
            return;
        }
        match respawn() {
            Ok(next) => {
                tracing::debug!(target: "nrr::dns", "the DNS query monitor was started again");
                run = Some(next);
            }
            Err(e) => {
                tracing::debug!(
                    target: "nrr::dns",
                    error = %e,
                    "the DNS query monitor could not be started again yet",
                );
                delay = backoff.after(delay);
            }
        }
    }
}

/// Read monitor lines into `sink` until the stream ends; `true` when at least
/// one line was read. An oversized or non-UTF-8 line costs only itself, and
/// `sink` never grows past [`MAX_BUFFERED_OBSERVATIONS`] between drains.
fn pump_lines(output: impl Read, sink: &Mutex<Vec<DnsObservation>>) -> bool {
    let mut reader = BufReader::new(output);
    let mut buf = Vec::new();
    let mut saw_line = false;
    while let Ok(Some(line)) = next_line(&mut reader, &mut buf, MAX_MONITOR_LINE_BYTES) {
        saw_line = true;
        let Some(text) = line.and_then(|bytes| std::str::from_utf8(bytes).ok()) else {
            continue;
        };
        let mut observations = parse_monitor_line(text).peekable();
        if observations.peek().is_some() {
            let mut buffered = sink.lock().unwrap_or_else(|p| p.into_inner());
            let room = MAX_BUFFERED_OBSERVATIONS.saturating_sub(buffered.len());
            buffered.extend(observations.take(room));
        }
    }
    saw_line
}

/// The next line of at most `max` bytes, without its newline. `Some(None)`
/// for a longer line, which is read past without being kept; `None` at the
/// end of the stream.
fn next_line<'a, R: BufRead>(
    reader: &mut R,
    buf: &'a mut Vec<u8>,
    max: usize,
) -> std::io::Result<Option<Option<&'a [u8]>>> {
    buf.clear();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    if reader.by_ref().take(limit).read_until(b'\n', buf)? == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > max {
        skip_past_newline(reader)?;
        return Ok(Some(None));
    }
    Ok(Some(Some(buf.as_slice())))
}

fn skip_past_newline<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            return Ok(());
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(at) => {
                reader.consume(at + 1);
                return Ok(());
            }
            None => {
                let len = chunk.len();
                reader.consume(len);
            }
        }
    }
}

/// The fuzz targets' entry for the stream half: every line of `data` through
/// the bounded splitter and the parser, as the reader thread runs them.
#[cfg(feature = "fuzzing")]
pub fn fuzz_monitor_stream(data: &[u8]) -> usize {
    let sink = Mutex::new(Vec::new());
    pump_lines(data, &sink);
    let observations = sink.into_inner().unwrap_or_else(|p| p.into_inner());
    observations.len()
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
/// Empty for anything that is not a successful A/AAAA answer: a failed lookup,
/// a line this build does not understand. Pure, so it is tested against real
/// captured output on any host.
pub fn parse_monitor_line(line: &str) -> impl Iterator<Item = DnsObservation> {
    let (queried, answered) = match parse_answer(line) {
        Some((queried, answered)) => (Some(queried), answered),
        None => (None, None),
    };
    [queried, answered].into_iter().flatten()
}

/// The queried-name observation, plus the final-name one when the names differ.
fn parse_answer(line: &str) -> Option<(DnsObservation, Option<DnsObservation>)> {
    if line.len() > MAX_MONITOR_LINE_BYTES {
        return None;
    }
    let event: serde_json::Value = serde_json::from_str(line).ok()?;
    if event.get("state").and_then(|s| s.as_str()) != Some("success") {
        return None;
    }

    let mut records: Vec<(String, IpAddr)> = Vec::new();
    // Alias target -> alias owner, to walk a chain back towards the question.
    let mut aliased_from: HashMap<String, String> = HashMap::new();
    for answer in event
        .get("answer")?
        .as_array()?
        .iter()
        .take(MAX_ANSWER_RECORDS)
    {
        let rr = answer.get("rr")?;
        let key = rr.get("key")?;
        if key.get("class").and_then(serde_json::Value::as_u64) != Some(CLASS_IN) {
            continue;
        }
        let owner = canonical(key.get("name")?.as_str()?);
        match key.get("type").and_then(serde_json::Value::as_u64) {
            Some(TYPE_A) => {
                if let Some(address) = octets::<4>(rr) {
                    records.push((owner, IpAddr::V4(Ipv4Addr::from(address))));
                }
            }
            Some(TYPE_AAAA) => {
                if let Some(address) = octets::<16>(rr) {
                    records.push((owner, IpAddr::V6(Ipv6Addr::from(address)).to_canonical()));
                }
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
    let mut queried_answer = Addresses::default();
    let mut final_answer = Addresses::default();
    for (owner, address) in records {
        if owner == final_name {
            final_answer.push(address);
        }
        if alias_origin(owner, &aliased_from) == queried {
            queried_answer.push(address);
        }
    }

    // A reply on the wire names no program: the owner stays unknown.
    let answered = (final_name != queried).then(|| final_answer.observation(final_name));
    Some((queried_answer.observation(queried), answered))
}

/// One name's addresses, distinct and capped per family.
#[derive(Default)]
struct Addresses {
    ipv4s: Vec<Ipv4Addr>,
    ipv6s: Vec<Ipv6Addr>,
}

impl Addresses {
    fn push(&mut self, address: IpAddr) {
        fn add<T: PartialEq>(list: &mut Vec<T>, value: T) {
            if list.len() < MAX_ADDRESSES_PER_FAMILY && !list.contains(&value) {
                list.push(value);
            }
        }
        match address {
            IpAddr::V4(v4) => add(&mut self.ipv4s, v4),
            IpAddr::V6(v6) => add(&mut self.ipv6s, v6),
        }
    }

    fn observation(self, hostname: String) -> DnsObservation {
        DnsObservation {
            hostname,
            ipv4s: self.ipv4s,
            ipv6s: self.ipv6s,
            owner: None,
        }
    }
}

/// The `address` byte array of a record, when it is exactly `N` bytes.
fn octets<const N: usize>(rr: &serde_json::Value) -> Option<[u8; N]> {
    let values = rr.get("address")?.as_array()?;
    if values.len() != N {
        return None;
    }
    let mut address = [0u8; N];
    for (slot, value) in address.iter_mut().zip(values) {
        *slot = u8::try_from(value.as_u64()?).ok()?;
    }
    Some(address)
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

    /// The IPv6 half of an answer is learned like the IPv4 one.
    #[test]
    fn a_dual_stack_answer_yields_both_families() {
        let observations = parsed(LIVE_LINE);

        assert_eq!(
            observations[0].ipv6s,
            vec!["2001:db8::1".parse::<Ipv6Addr>().expect("v6")]
        );
    }

    #[test]
    fn a_v6_only_answer_is_an_observation() {
        let v6_only = r#"{"state":"success","question":[{"class":1,"type":28,"name":"ipv6.example"}],"answer":[{"rr":{"key":{"class":1,"type":28,"name":"ipv6.example"},"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]},"ifindex":2}]}"#;

        let observations = parsed(v6_only);

        assert_eq!(hostnames(&observations), vec!["ipv6.example"]);
        assert!(observations[0].ipv4s.is_empty());
        assert_eq!(observations[0].ipv6s.len(), 1);
    }

    /// `::ffff:a.b.c.d` is the IPv4 address it maps; a record of the wrong
    /// length is no address at all.
    #[test]
    fn a_mapped_aaaa_is_ipv4_and_a_short_one_is_dropped() {
        let line = r#"{"state":"success","answer":[{"rr":{"key":{"class":1,"type":28,"name":"m.example"},"address":[0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,30]}},{"rr":{"key":{"class":1,"type":28,"name":"m.example"},"address":[32,1,13,184]}}]}"#;

        let observations = parsed(line);

        assert_eq!(observations[0].ipv4s, vec![Ipv4Addr::new(192, 0, 2, 30)]);
        assert!(observations[0].ipv6s.is_empty());
    }

    #[test]
    fn an_answer_keeps_a_bounded_number_of_addresses_per_family() {
        let records: Vec<String> = (0..300u32)
            .map(|i| {
                format!(
                    r#"{{"rr":{{"key":{{"class":1,"type":1,"name":"many.example"}},"address":[10,0,{},{}]}}}}"#,
                    i / 256,
                    i % 256
                )
            })
            .collect();
        let line = format!(r#"{{"state":"success","answer":[{}]}}"#, records.join(","));

        let observations = parsed(&line);

        assert_eq!(observations[0].ipv4s.len(), MAX_ADDRESSES_PER_FAMILY);
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

    // ── The stream and its restarts ──────────────────────────────────────────

    use std::sync::atomic::AtomicU32;
    use std::sync::mpsc;

    #[test]
    fn an_oversized_and_a_non_utf8_line_cost_only_themselves() {
        let mut stream = vec![b'x'; MAX_MONITOR_LINE_BYTES + 10];
        stream.push(b'\n');
        stream.extend_from_slice(b"\xff\xfe{\n");
        stream.extend_from_slice(LIVE_LINE.as_bytes());
        stream.push(b'\n');
        let sink = Mutex::new(Vec::new());

        assert!(pump_lines(stream.as_slice(), &sink));

        let observations = sink.into_inner().expect("not poisoned");
        assert_eq!(hostnames(&observations), vec!["example.com"]);
    }

    /// A stream faster than the drain is cut at the cap, never buffered whole:
    /// a local process can make resolved print tens of thousands of lines a
    /// second, and the consumer drains every few seconds.
    #[test]
    fn a_storm_of_lines_is_held_to_the_buffer_cap_between_drains() {
        let mut stream = Vec::new();
        for _ in 0..(MAX_BUFFERED_OBSERVATIONS + 100) {
            stream.extend_from_slice(LIVE_LINE.as_bytes());
            stream.push(b'\n');
        }
        let sink = Mutex::new(Vec::new());

        assert!(pump_lines(stream.as_slice(), &sink));

        let observations = sink.into_inner().expect("not poisoned");
        assert_eq!(observations.len(), MAX_BUFFERED_OBSERVATIONS);
        assert!(observations.iter().all(|o| o.hostname == "example.com"));
    }

    #[test]
    fn a_line_is_kept_up_to_the_bound_and_skipped_past_it() {
        let mut reader = std::io::Cursor::new(b"12345678\n123456789\nlast".to_vec());
        let mut buf = Vec::new();
        let kept = next_line(&mut reader, &mut buf, 8)
            .expect("read")
            .expect("a line");
        assert_eq!(kept, Some(&b"12345678"[..]));
        assert_eq!(
            next_line(&mut reader, &mut buf, 8).expect("read"),
            Some(None)
        );
        let last = next_line(&mut reader, &mut buf, 8)
            .expect("read")
            .expect("a line");
        assert_eq!(last, Some(&b"last"[..]));
        assert_eq!(next_line(&mut reader, &mut buf, 8).expect("read"), None);
    }

    /// A stream fed line by line; it ends when its sender goes.
    struct ChannelReader {
        lines: mpsc::Receiver<Vec<u8>>,
        pending: std::collections::VecDeque<u8>,
    }

    impl Read for ChannelReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pending.is_empty() {
                match self.lines.recv() {
                    Ok(line) => self.pending.extend(line),
                    Err(_) => return Ok(0),
                }
            }
            let n = out.len().min(self.pending.len());
            for (slot, byte) in out.iter_mut().zip(self.pending.drain(..n)) {
                *slot = byte;
            }
            Ok(n)
        }
    }

    #[derive(Clone, Default)]
    struct Counts {
        kills: Arc<AtomicU32>,
        reaps: Arc<AtomicU32>,
    }

    impl Counts {
        fn reaps(&self) -> u32 {
            self.reaps.load(Ordering::SeqCst)
        }
    }

    /// Killing it hangs up its output, as killing `resolvectl` closes the pipe.
    struct FakeChild {
        hangup: Option<mpsc::Sender<Vec<u8>>>,
        counts: Counts,
    }

    impl MonitorChild for FakeChild {
        fn kill(&mut self) {
            self.counts.kills.fetch_add(1, Ordering::SeqCst);
            self.hangup.take();
        }

        fn reap(&mut self) {
            self.counts.reaps.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A run printing `lines`, then ending, or staying open until killed.
    fn fake_run(lines: &[&str], stays_open: bool, counts: &Counts) -> MonitorRun {
        let (tx, rx) = mpsc::channel();
        for line in lines {
            tx.send(format!("{line}\n").into_bytes())
                .expect("receiver alive");
        }
        MonitorRun {
            output: Box::new(ChannelReader {
                lines: rx,
                pending: std::collections::VecDeque::new(),
            }),
            child: OwnedChild(Box::new(FakeChild {
                hangup: stays_open.then_some(tx),
                counts: counts.clone(),
            })),
        }
    }

    const FAST: Backoff = Backoff {
        first: Duration::from_millis(1),
        cap: Duration::from_millis(4),
    };

    fn drain_until(observer: &ResolvedDnsObserver, count: usize) -> Vec<DnsObservation> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = Vec::new();
        while seen.len() < count && Instant::now() < deadline {
            seen.extend(observer.drain());
            std::thread::sleep(Duration::from_millis(5));
        }
        seen
    }

    const SECOND_LINE: &str = r#"{"state":"success","answer":[{"rr":{"key":{"class":1,"type":1,"name":"after.example"},"address":[192,0,2,40]}}]}"#;

    /// resolved restarts: the stream ends, the next monitor cannot start yet,
    /// then does. The feed reads down exactly while no monitor runs, the first
    /// process is reaped, and observations resume.
    #[test]
    fn a_monitor_whose_stream_ends_is_started_again() {
        let first = Counts::default();
        let second = Counts::default();
        let (down_tx, down_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let attempts = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&attempts);
        let respawned = second.clone();
        let observer = ResolvedDnsObserver::start_with(
            fake_run(&[LIVE_LINE], false, &first),
            Box::new(move || match counted.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    let _ = down_tx.send(());
                    let _ = go_rx.recv();
                    Err(std::io::Error::other("resolved is restarting"))
                }
                1 => Ok(fake_run(&[SECOND_LINE], true, &respawned)),
                _ => Err(std::io::Error::other("no third monitor")),
            }),
            FAST,
        )
        .expect("the reader starts");

        down_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the first stream ended");
        assert!(!observer.is_feeding(), "no monitor runs");
        assert_eq!(first.reaps(), 1, "the ended monitor is reaped");
        go_tx.send(()).expect("respawner waits");

        let seen = drain_until(&observer, 2);
        assert_eq!(hostnames(&seen), vec!["example.com", "after.example"]);
        assert!(observer.is_feeding());
        assert_eq!(second.reaps(), 0, "the live monitor keeps running");

        drop(observer);
        assert_eq!(second.reaps(), 1, "dropping the observer reaps its monitor");
        assert!(second.kills.load(Ordering::SeqCst) >= 1);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "nothing starts after the drop"
        );
    }

    #[test]
    fn dropping_the_observer_while_it_waits_to_restart_ends_the_thread() {
        let counts = Counts::default();
        let observer = ResolvedDnsObserver::start_with(
            fake_run(&[], false, &counts),
            Box::new(|| Err(std::io::Error::other("resolvectl is gone"))),
            Backoff {
                first: Duration::from_secs(3600),
                cap: Duration::from_secs(3600),
            },
        )
        .expect("the reader starts");
        let deadline = Instant::now() + Duration::from_secs(5);
        while observer.is_feeding() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!observer.is_feeding());
        drop(observer);
        assert_eq!(counts.reaps(), 1);
    }
}
