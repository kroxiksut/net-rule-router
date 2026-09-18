use super::*;

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[test]
fn cache_serves_within_ttl_and_recomputes_after_expiry() {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    let cache = ResolveCache::new(Duration::from_secs(30));
    let calls = Cell::new(0u32);
    let compute = |ret: &'static str| {
        calls.set(calls.get() + 1);
        vec![p(ret)]
    };

    let t0 = Instant::now();
    let first = cache.get_or_compute_at("ab.exe", t0, || compute("a"));
    assert_eq!(first, vec![p("a")]);
    assert_eq!(calls.get(), 1);

    // Within TTL → cached; the (different) closure must NOT run.
    let within = cache.get_or_compute_at("ab.exe", t0 + Duration::from_secs(5), || compute("b"));
    assert_eq!(within, vec![p("a")], "served from cache");
    assert_eq!(calls.get(), 1, "compute not re-invoked within TTL");

    // After TTL → recompute, new value cached.
    let after = cache.get_or_compute_at("ab.exe", t0 + Duration::from_secs(31), || compute("c"));
    assert_eq!(after, vec![p("c")]);
    assert_eq!(calls.get(), 2, "compute re-invoked after TTL expiry");
}

#[test]
fn one_process_list_serves_every_name_a_pass_resolves() {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    // Only the file name is matched, so the directory is a placeholder.
    let client = p("dir-a").join("Client.exe");
    let helper = p("dir-b").join("helper.exe");
    let scans = std::sync::Arc::new(AtomicU32::new(0));
    let scan: ScanFn = {
        let scans = std::sync::Arc::clone(&scans);
        let images = vec![client.clone(), helper.clone()];
        std::sync::Arc::new(move || {
            scans.fetch_add(1, Ordering::SeqCst);
            images.clone()
        })
    };
    let list = ProcessImages::new(scan, Duration::from_secs(2));

    let t0 = Instant::now();
    let names = ["client.exe", "helper.exe", "absent.exe", "cli*"];
    let found: Vec<Vec<PathBuf>> = names
        .iter()
        .zip(0u64..)
        .map(|(name, i)| matching_images(name, &list.at(t0 + Duration::from_millis(100 * i))))
        .collect();
    assert_eq!(
        scans.load(Ordering::SeqCst),
        1,
        "one list for the whole pass"
    );
    assert_eq!(found[0], vec![client.clone()], "case-insensitive name");
    assert_eq!(found[1], vec![helper]);
    assert!(found[2].is_empty());
    assert_eq!(found[3], vec![client], "glob");

    list.at(t0 + Duration::from_secs(30));
    assert_eq!(
        scans.load(Ordering::SeqCst),
        2,
        "the next pass takes a new list"
    );
}

/// A walker that counts its walks, blocks until `gate` opens, and answers
/// with whatever `answer` holds at the time.
fn counting_walker(
    answer: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>>,
    gate: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
) -> (WalkFn, std::sync::Arc<std::sync::atomic::AtomicU32>) {
    let walks = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let walker: WalkFn = {
        let walks = std::sync::Arc::clone(&walks);
        std::sync::Arc::new(move |_key: &str| {
            let (open, opened) = &*gate;
            let guard = open.lock().unwrap_or_else(|p| p.into_inner());
            drop(
                opened
                    .wait_while(guard, |open| !*open)
                    .unwrap_or_else(|p| p.into_inner()),
            );
            walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            WalkOutcome {
                paths: answer.lock().unwrap_or_else(|p| p.into_inner()).clone(),
                install_root_truncated: false,
            }
        })
    };
    (walker, walks)
}

fn gate(open: bool) -> std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)> {
    std::sync::Arc::new((std::sync::Mutex::new(open), std::sync::Condvar::new()))
}

#[test]
fn a_pass_with_no_truncation_says_nothing() {
    assert!(truncation_report(&[]).is_none());
}

#[test]
fn one_report_carries_the_whole_pass_counted_and_sampled() {
    // Eighty-odd patterns for applications that are not installed wrote the
    // same sentence eighty times every time the walk cache expired. The
    // pass now yields ONE report, which is why it carries the count.
    let many: Vec<String> = (0..81).map(|i| format!("app{i}.exe")).collect();
    let report = truncation_report(&many).expect("a truncated pass reports");
    assert_eq!(report.patterns, 81);
    assert!(report.sample.ends_with("(+76)"), "{}", report.sample);
    assert_eq!(report.sample.matches(", ").count(), 4, "{}", report.sample);
}

#[test]
fn a_short_list_is_named_in_full() {
    // Positive control for the elision above: at the threshold nothing is
    // dropped, so a small truncation still names every pattern.
    let few: Vec<String> = (0..5).map(|i| format!("app{i}.exe")).collect();
    let report = truncation_report(&few).expect("a truncated pass reports");
    assert_eq!(report.sample, few.join(", "));
    assert!(!report.sample.contains('+'), "{}", report.sample);
}

fn change_log() -> (
    WalksChangedFn,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let changed: WalksChangedFn = {
        let log = std::sync::Arc::clone(&log);
        std::sync::Arc::new(move |keys: &[String]| {
            log.lock()
                .unwrap_or_else(|p| p.into_inner())
                .extend(keys.iter().cloned());
        })
    };
    (changed, log)
}

/// The walk must outlive several passes of the recompute that asks for
/// it: expiring with the resolve cache, it repeated on every pass.
/// Asserted on behaviour, not on the constants.
#[test]
fn the_disk_walk_outlives_several_resolve_cycles() {
    use std::time::{Duration, Instant};

    let answer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (walker, walks) = counting_walker(answer, gate(true));
    let (changed, _) = change_log();
    let background = BackgroundWalks::new(walker, WindowsAppPathResolver::WALK_CACHE_TTL, changed);

    let t0 = Instant::now();
    for pass in 0..5u64 {
        background.known_at("x.exe", t0 + Duration::from_secs(37 * pass));
        background.wait_idle();
    }
    assert_eq!(walks.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The enforcement pass that asks must not wait for the disk.
#[test]
fn a_first_ask_does_not_wait_for_the_walk_and_its_finding_is_announced() {
    use std::time::{Duration, Instant};

    // Only path equality is asserted, so the directory is a placeholder.
    let found = p("dir-a").join("x.exe");
    let answer = std::sync::Arc::new(std::sync::Mutex::new(vec![found.clone()]));
    let closed = gate(false);
    let (walker, _) = counting_walker(answer, std::sync::Arc::clone(&closed));
    let (changed, log) = change_log();
    let background = BackgroundWalks::new(walker, Duration::from_secs(600), changed);

    let started = Instant::now();
    assert!(background.known_at("x.exe", Instant::now()).is_empty());
    assert!(started.elapsed() < Duration::from_secs(1));

    *closed.0.lock().unwrap_or_else(|p| p.into_inner()) = true;
    closed.1.notify_all();
    background.wait_idle();
    assert_eq!(background.known_at("x.exe", Instant::now()), vec![found]);
    assert_eq!(
        *log.lock().unwrap_or_else(|p| p.into_inner()),
        vec!["x.exe".to_string()]
    );
}

/// An application a walk found keeps its answer while the walk repeats,
/// and a repeat that finds the same thing announces nothing.
#[test]
fn an_expired_walk_is_served_while_it_refreshes_and_an_unchanged_one_is_quiet() {
    use std::time::{Duration, Instant};

    let found = p("dir-a").join("x.exe");
    let answer = std::sync::Arc::new(std::sync::Mutex::new(vec![found.clone()]));
    let (walker, walks) = counting_walker(answer, gate(true));
    let (changed, log) = change_log();
    let background = BackgroundWalks::new(walker, Duration::from_millis(1), changed);

    background.known_at("x.exe", Instant::now());
    background.wait_idle();
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        background.known_at("x.exe", Instant::now()),
        vec![found],
        "an expired answer is still served"
    );
    background.wait_idle();
    assert_eq!(walks.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(log.lock().unwrap_or_else(|p| p.into_inner()).len(), 1);
}

/// Nothing found where nothing was known is not news.
#[test]
fn a_first_walk_that_finds_nothing_announces_nothing() {
    use std::time::Instant;

    let answer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (walker, _) = counting_walker(answer, gate(true));
    let (changed, log) = change_log();
    let background = BackgroundWalks::new(walker, WindowsAppPathResolver::WALK_CACHE_TTL, changed);

    background.known_at("absent.exe", Instant::now());
    background.wait_idle();
    assert!(log.lock().unwrap_or_else(|p| p.into_inner()).is_empty());
}

#[cfg(target_os = "windows")]
#[test]
fn cache_zero_ttl_always_recomputes() {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    let cache = ResolveCache::new(Duration::ZERO);
    let calls = Cell::new(0u32);
    let now = Instant::now();
    for _ in 0..3 {
        let _ = cache.get_or_compute_at("x.exe", now, || {
            calls.set(calls.get() + 1);
            vec![p("x")]
        });
    }
    assert_eq!(calls.get(), 3, "zero TTL means every call recomputes");
}
