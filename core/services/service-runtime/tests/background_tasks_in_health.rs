#![allow(clippy::expect_used)]

//! Every background task of the service is visible in health, or is
//! recorded as not needing to be.
//!
//! Two scans over the service crates' non-test source:
//!
//! 1. Every `ServiceTask` built anywhere names a `TASK_ID_*` constant whose
//!    value `ServiceTaskKind` knows — so a new supervised task cannot be added
//!    without deciding, in the registry, where its loss shows.
//! 2. Every thread spawned outside the supervisor is listed below with a
//!    verdict. A long-lived one holds a lease on its `ServiceTaskKind`, so its
//!    exit and its hangs reach health; the list fails both when a new thread
//!    appears and when a listed one is gone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use nrr_service_runtime::service_tasks::{ServiceTaskKind, TaskRunner};

fn services_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("services dir")
        .to_path_buf()
}

const SCANNED_CRATES: &[&str] = &["service-runtime", "windows-service", "linux-service"];

/// Non-test source of the service crates, as (path relative to `core/services`,
/// text cut at the file's test module).
fn production_sources() -> Vec<(String, String)> {
    let root = services_dir();
    let mut out = Vec::new();
    for krate in SCANNED_CRATES {
        collect(&root.join(krate).join("src"), &root, &mut out);
    }
    assert!(out.len() > 100, "scan found only {} files", out.len());
    out
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let entries = std::fs::read_dir(dir).expect("read source dir");
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if path.is_dir() {
            if name != "tests" {
                collect(&path, root, out);
            }
            continue;
        }
        if !name.ends_with(".rs") || name == "tests.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        let rel = path
            .strip_prefix(root)
            .expect("under services dir")
            .to_string_lossy()
            .replace('\\', "/");
        out.push((rel, cut_test_module(&text).to_owned()));
    }
}

/// Text before the first `#[cfg(test)]` that heads a `mod`.
fn cut_test_module(text: &str) -> &str {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut offset = 0usize;
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            let heads_mod = lines[i + 1..]
                .iter()
                .map(|l| l.trim_start())
                .find(|l| !l.starts_with("#["))
                .is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub mod "));
            if heads_mod {
                return &text[..offset];
            }
        }
        offset += line.len();
    }
    text
}

/// `const TASK_ID_X: &str = "value";` → name → value.
fn task_id_constants(sources: &[(String, String)]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (_, text) in sources {
        for line in text.lines() {
            let line = line.trim_start().trim_start_matches("pub ");
            let Some(rest) = line.strip_prefix("const TASK_ID_") else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            let value = rest.split('"').nth(1).expect("string literal id");
            out.insert(format!("TASK_ID_{name}"), value.to_owned());
        }
    }
    out
}

fn identifier_at(text: &str) -> String {
    text.trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
        .collect()
}

/// The id expression of every `ServiceTask` built in production code.
fn task_construction_sites(sources: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (file, text) in sources {
        for (at, _) in text.match_indices("ServiceTask::periodic(") {
            let id = identifier_at(&text[at + "ServiceTask::periodic(".len()..]);
            out.push((file.clone(), id));
        }
        for (at, _) in text.match_indices("ServiceTask {") {
            let before = text[..at].trim_end();
            if !(before.ends_with('=') || before.ends_with('(')) {
                continue; // the struct and impl blocks themselves
            }
            let body = &text[at..];
            let id_at = body
                .find("TaskId::new(")
                .expect("literal task names its id");
            let id = identifier_at(&body[id_at + "TaskId::new(".len()..]);
            out.push((file.clone(), id));
        }
    }
    out
}

#[test]
fn every_supervised_task_is_registered_with_a_health_decision() {
    let sources = production_sources();
    let constants = task_id_constants(&sources);
    let sites = task_construction_sites(&sources);
    assert!(
        sites.len() >= 20,
        "scan found only {} task sites",
        sites.len()
    );

    let mut built = BTreeSet::new();
    for (file, id_expr) in &sites {
        let name = id_expr.rsplit("::").next().unwrap_or_default();
        let value = constants.get(name).unwrap_or_else(|| {
            panic!("{file}: a ServiceTask is built from `{id_expr}`, not a TASK_ID_* constant")
        });
        assert!(
            ServiceTaskKind::from_id(value).is_some(),
            "{file}: task `{value}` is not in ServiceTaskKind — decide where its loss shows"
        );
        built.insert(value.clone());
    }

    for (name, value) in &constants {
        assert!(
            ServiceTaskKind::from_id(value).is_some(),
            "{name} = \"{value}\" has no ServiceTaskKind"
        );
    }
    let registered: BTreeSet<String> = ServiceTaskKind::ALL
        .into_iter()
        .filter(|k| k.runner() == TaskRunner::Supervisor)
        .map(|k| k.id().to_owned())
        .collect();
    assert_eq!(
        built, registered,
        "registry and the tasks actually built disagree"
    );
}

/// An own-thread kind nobody leases is a verdict with no evidence behind it.
#[test]
fn every_own_thread_kind_is_leased_somewhere_in_production_code() {
    let sources = production_sources();
    for kind in ServiceTaskKind::ALL {
        if kind.runner() != TaskRunner::OwnThread {
            continue;
        }
        let needle = format!("ServiceTaskKind::{kind:?}");
        assert!(
            sources.iter().any(|(_, text)| text.contains(&needle)),
            "{needle} is registered but no thread takes a lease on it"
        );
    }
}

// ── Threads outside the supervisor ───────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum Verdict {
    /// The supervisor's own task threads, covered by the registry.
    Supervisor,
    /// Ends on its own: per request, per flow, one-shot, or one deadline.
    Bounded(&'static str),
    /// Long-lived; holds a `TaskLiveness` lease on this kind.
    Leased(ServiceTaskKind),
    /// Long-lived and outside health by decision.
    Invisible(&'static str),
}

const UNNAMED: &str = "<unnamed>";
const COMPUTED: &str = "<computed>";

/// (file, thread name, spawn sites, verdict).
const THREADS: &[(&str, &str, usize, Verdict)] = &[
    (
        "service-runtime/src/runtime_loop.rs",
        "nrr-task-",
        1,
        Verdict::Supervisor,
    ),
    (
        "service-runtime/src/supervised_runtime.rs",
        "nrr-stop-",
        1,
        Verdict::Bounded("one teardown step, time-boxed"),
    ),
    (
        "service-runtime/src/dns_resolver_service.rs",
        "nrr-dns-resolver",
        1,
        Verdict::Leased(ServiceTaskKind::DnsResolver),
    ),
    (
        "service-runtime/src/dns_resolver_service.rs",
        "nrr-dns-redirect-guard",
        1,
        Verdict::Leased(ServiceTaskKind::DnsRedirectGuard),
    ),
    (
        "service-runtime/src/dns_resolver_service.rs",
        UNNAMED,
        1,
        Verdict::Bounded("one enforcement-mode apply off the IPC thread"),
    ),
    (
        "service-runtime/src/dns_resolver_ports.rs",
        UNNAMED,
        1,
        Verdict::Leased(ServiceTaskKind::DnsReconcileWorker),
    ),
    (
        "service-runtime/src/dns_upstream.rs",
        "nrr-dns-upstream-refresh",
        1,
        Verdict::Bounded("one upstream re-selection per network change"),
    ),
    (
        "service-runtime/src/fake_ip/lifecycle.rs",
        UNNAMED,
        1,
        Verdict::Leased(ServiceTaskKind::FakeIpStack),
    ),
    (
        "service-runtime/src/fake_ip/production_ports.rs",
        "nrr-flow-observer",
        1,
        Verdict::Leased(ServiceTaskKind::FakeIpFlowObserver),
    ),
    (
        "service-runtime/src/fake_ip/self_heal.rs",
        UNNAMED,
        1,
        Verdict::Leased(ServiceTaskKind::FakeIpSelfHeal),
    ),
    (
        "service-runtime/src/fake_ip/stack.rs",
        "nrr-fakeip-udp-read",
        1,
        Verdict::Bounded("one UDP flow reader, ends with the flow; flows are capped"),
    ),
    (
        "service-runtime/src/fake_ip/stack.rs",
        "nrr-fakeip-up-read",
        1,
        Verdict::Bounded("one TCP splice reader, ends with the flow; flows are capped"),
    ),
    (
        "service-runtime/src/fake_ip/stack.rs",
        "nrr-fakeip-up-write",
        1,
        Verdict::Bounded("one TCP splice writer, ends with the flow; flows are capped"),
    ),
    (
        "service-runtime/src/fake_ip/stack/dial_pool.rs",
        "nrr-fakeip-dial",
        1,
        Verdict::Bounded("dial pool worker, capped and exits when idle"),
    ),
    (
        "service-runtime/src/fake_ip/stack/echo.rs",
        "nrr-fake-ip-echo",
        1,
        Verdict::Bounded("one echo, capped in flight"),
    ),
    (
        "service-runtime/src/ipc_handlers/seed_browser_history.rs",
        "nrr-bh-seed",
        1,
        Verdict::Bounded("one seeding run"),
    ),
    (
        "service-runtime/src/logon_rearm.rs",
        "nrr-sign-in-poll",
        1,
        Verdict::Bounded("ends at the first sign-in; only where no logon event exists"),
    ),
    (
        "service-runtime/src/network_rearm.rs",
        "nrr-net-change-debounce",
        1,
        Verdict::Leased(ServiceTaskKind::NetChangeDebounce),
    ),
    (
        "service-runtime/src/production_auto_rule_probe.rs",
        "nrr-rule-host-probe",
        1,
        Verdict::Bounded("one probe pass"),
    ),
    (
        "service-runtime/src/production_auto_rule_probe.rs",
        "nrr-main-link-probe",
        1,
        Verdict::Bounded("one probe pass"),
    ),
    (
        "service-runtime/src/rule_hostname_seeder.rs",
        "nrr-rule-seed",
        1,
        Verdict::Bounded("one seed pass"),
    ),
    (
        "service-runtime/src/secondary_external_address.rs",
        "nrr-secondary-extip",
        1,
        Verdict::Bounded("one address probe per connection of the link"),
    ),
    (
        "service-runtime/src/timed_window.rs",
        COMPUTED,
        1,
        Verdict::Bounded("sleeps to one window's deadline; reads end the window on time anyway"),
    ),
    (
        "windows-service/src/named_pipe_server.rs",
        "nrr-ipc-worker",
        1,
        Verdict::Bounded("one client connection"),
    ),
    (
        "windows-service/src/named_pipe_server.rs",
        "nrr-ipc-reader",
        1,
        Verdict::Bounded("one client connection"),
    ),
    (
        "windows-service/src/runtime_deps/boot_budgets.rs",
        "nrr-budgeted-start",
        1,
        Verdict::Bounded("one boot step under a budget"),
    ),
    (
        "windows-service/src/runtime_deps/boot_budgets.rs",
        "nrr-wfp-open",
        1,
        Verdict::Invisible(
            "ends when the engine answers or a stop begins; until then Apply reads degraded",
        ),
    ),
    (
        "windows-service/src/runtime_deps/build.rs",
        "nrr-fakeip-watchdog",
        1,
        Verdict::Leased(ServiceTaskKind::FakeIpWatchdog),
    ),
    (
        "windows-service/src/runtime_deps/build.rs",
        UNNAMED,
        1,
        Verdict::Bounded("one fake-IP bring-up after sign-in"),
    ),
    (
        "windows-service/src/runtime_deps/conn_trace.rs",
        "nrr-fcrdns",
        1,
        Verdict::Leased(ServiceTaskKind::FcrdnsLearner),
    ),
    (
        "windows-service/src/runtime_deps/ipc_surface.rs",
        UNNAMED,
        2,
        Verdict::Bounded("one setting apply and replan off the IPC thread"),
    ),
    (
        "windows-service/src/runtime_deps/ipc_surface.rs",
        "nrr-bh-autoseed",
        1,
        Verdict::Bounded("one seeding run"),
    ),
    (
        "windows-service/src/runtime_deps/offline_reset.rs",
        "nrr-orphan-strip",
        1,
        Verdict::Bounded("one boot cleanup"),
    ),
    (
        "windows-service/src/runtime_deps/per_sid_apply.rs",
        "nrr-rule-host-resolve",
        1,
        Verdict::Bounded("one resolve pass"),
    ),
    (
        "linux-service/src/ipc_deps.rs",
        "nrr-bh-autoseed",
        1,
        Verdict::Bounded("one seeding run"),
    ),
    (
        "service-runtime/src/lifecycle_matrix.rs",
        "nrr-",
        1,
        Verdict::Bounded("one teardown step at stop, waited for under a deadline"),
    ),
    (
        "service-runtime/src/override_recheck.rs",
        "nrr-override-recheck",
        1,
        Verdict::Invisible(
            "if it stops, confirmations stay as the last re-check left them and the next \
             service start re-checks them",
        ),
    ),
    (
        "linux-service/src/run.rs",
        "nrr-sd-watchdog",
        1,
        Verdict::Invisible(
            "it is the liveness check itself: if it stops, its pings stop and systemd \
             restarts the service",
        ),
    ),
    (
        "linux-service/src/unix_socket_server.rs",
        "nrr-ipc-worker",
        1,
        Verdict::Bounded("one client connection"),
    ),
    (
        "linux-service/src/unix_socket_server.rs",
        "nrr-ipc-reader",
        1,
        Verdict::Bounded("one client connection"),
    ),
];

/// The name a spawn site gives its thread.
fn thread_label(after_builder: &str) -> String {
    let window: String = after_builder.chars().take(300).collect();
    let Some(at) = window.find(".name(") else {
        return UNNAMED.to_owned();
    };
    let arg = window[at + ".name(".len()..].trim_start();
    let literal = arg
        .strip_prefix('"')
        .or_else(|| arg.strip_prefix("format!(\""));
    match literal {
        Some(rest) => rest
            .chars()
            .take_while(|c| *c != '"' && *c != '{')
            .collect(),
        None => COMPUTED.to_owned(),
    }
}

fn thread_spawn_sites(sources: &[(String, String)]) -> BTreeMap<(String, String), usize> {
    let mut out = BTreeMap::new();
    for (file, text) in sources {
        for (at, _) in text.match_indices("thread::Builder::new()") {
            let label = thread_label(&text[at..]);
            *out.entry((file.clone(), label)).or_insert(0) += 1;
        }
        let unnamed = text.matches("thread::spawn(").count();
        if unnamed > 0 {
            *out.entry((file.clone(), UNNAMED.to_owned())).or_insert(0) += unnamed;
        }
    }
    out
}

#[test]
fn every_thread_outside_the_supervisor_has_a_verdict() {
    let found = thread_spawn_sites(&production_sources());
    let listed: BTreeMap<(String, String), usize> = THREADS
        .iter()
        .map(|(file, name, count, _)| (((*file).to_owned(), (*name).to_owned()), *count))
        .collect();
    assert_eq!(listed.len(), THREADS.len(), "THREADS lists a site twice");
    for (key, count) in &found {
        assert_eq!(
            listed.get(key),
            Some(count),
            "thread {key:?} spawned at {count} site(s) has no matching verdict in THREADS: \
             decide whether it is bounded, invisible, or a gap health must close"
        );
    }
    for key in listed.keys() {
        assert!(
            found.contains_key(key),
            "THREADS lists {key:?}, which the source no longer spawns — drop the entry"
        );
    }
    let mut leased = BTreeSet::new();
    for (file, name, _, verdict) in THREADS {
        let reason = match verdict {
            Verdict::Supervisor => continue,
            Verdict::Leased(kind) => {
                assert_eq!(
                    kind.runner(),
                    TaskRunner::OwnThread,
                    "{file} {name}: a leased thread needs an own-thread kind"
                );
                leased.insert(*kind);
                continue;
            }
            Verdict::Bounded(r) | Verdict::Invisible(r) => r,
        };
        assert!(
            reason.trim().len() > 10,
            "{file} {name}: a verdict needs a real reason"
        );
    }
    for kind in ServiceTaskKind::ALL {
        if kind.runner() == TaskRunner::OwnThread {
            assert!(
                leased.contains(&kind),
                "{kind:?} is an own-thread kind no listed thread leases"
            );
        }
    }
}
