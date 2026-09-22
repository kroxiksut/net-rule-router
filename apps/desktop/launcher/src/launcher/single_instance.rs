// Single-instance lock: the OS claim + lock-file fallback, stale-lock
// reclamation, the liveness probes (`is_process_alive`, tasklist parsing)
// that decide whether a recorded owner is still real, and the build stamp
// that tells a duplicate launch WHICH build is holding the lock.

use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::UNIX_EPOCH;

#[cfg(windows)]
use super::child_process::apply_no_window;

pub struct SingleInstanceGuard {
    lock_path: PathBuf,
    _lock_file: File,
    /// The OS-held claim, when the platform offers one. It — not the lock file
    /// — is what decides ownership: the kernel releases it when this process
    /// dies, and no one can delete it out of the runtime directory.
    _os_claim: Option<Box<dyn nrr_platform_api::single_instance::SingleInstanceClaim>>,
    /// PID a stale lock was reclaimed from on this `acquire`, if any — surfaced
    /// so the caller can log it once its own diagnostic log file is open.
    pub(super) removed_stale_pid: Option<u32>,
}

/// The platform's single-instance mechanism, or `None` where there is none.
fn os_single_instance_port(
) -> Option<Box<dyn nrr_platform_api::single_instance::SingleInstancePort>> {
    #[cfg(windows)]
    {
        Some(Box::new(
            nrr_platform_windows::single_instance::WindowsSingleInstance,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(
            nrr_platform_linux::single_instance::LinuxSingleInstance,
        ))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

impl SingleInstanceGuard {
    pub fn acquire(instance_key: &str) -> io::Result<Option<Self>> {
        let lock_directory = nrr_platform_api::paths::ensure_user_runtime_dir()?;

        let lock_path = lock_directory.join(format!("{instance_key}.lock"));

        // Ask the OS first. Its answer is authoritative in both directions: a
        // refused claim means a live owner exists no matter what the runtime
        // directory looks like, and a granted one means there is none — so a
        // lock file left behind by a crash (or by a duplicate the old
        // file-only scheme allowed) is just overwritten instead of probed.
        if let Some(port) = os_single_instance_port() {
            match port.claim(instance_key) {
                Ok(None) => return Ok(None),
                Ok(Some(claim)) => {
                    let mut lock_file = OpenOptions::new()
                        .create(true)
                        .read(true)
                        .write(true)
                        .truncate(true)
                        .open(&lock_path)?;
                    write_lock_record(&mut lock_file)?;
                    return Ok(Some(Self {
                        lock_path,
                        _lock_file: lock_file,
                        _os_claim: Some(claim),
                        removed_stale_pid: None,
                    }));
                }
                // Fall through to the lock-file scheme rather than guess.
                Err(error) => eprintln!(
                    "nrr-launcher: single-instance claim for {instance_key} failed ({error}); \
                     falling back to the lock file"
                ),
            }
        }

        let mut removed_stale_pid = None;
        for attempt in 0..2 {
            match OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(mut lock_file) => {
                    write_lock_record(&mut lock_file)?;
                    return Ok(Some(Self {
                        lock_path,
                        _lock_file: lock_file,
                        _os_claim: None,
                        removed_stale_pid,
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if attempt == 0 {
                        if let Some(pid) = cleanup_stale_lock_file(&lock_path)? {
                            removed_stale_pid = Some(pid);
                            continue;
                        }
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }

        Ok(None)
    }

    /// Take the lock over from an owner that proved unresponsive: drop whatever
    /// is on disk and claim it. Only the duplicate-launch path calls this, after
    /// the recorded owner failed to answer an activation request.
    pub fn reclaim(instance_key: &str) -> io::Result<Self> {
        let lock_directory = nrr_platform_api::paths::ensure_user_runtime_dir()?;
        let lock_path = lock_directory.join(format!("{instance_key}.lock"));
        match fs::remove_file(&lock_path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // The OS claim is the takeover's PRECONDITION, not a nicety. Proceeding
        // without it starts a second primary beside a live one: two writers over
        // one preferences file, two RPC dispatchers, two UAC prompts — and,
        // because the newcomer holds no claim, every later launch becomes
        // another primary too, so single-instance stays broken for the session.
        // A window we cannot open is a smaller harm than a session we cannot
        // trust.
        let os_claim = os_single_instance_port()
            .and_then(|port| port.claim(instance_key).ok())
            .flatten();
        if os_claim.is_none() && os_single_instance_port().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the running instance still holds the single-instance claim",
            ));
        }
        let mut lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)?;
        write_lock_record(&mut lock_file)?;
        Ok(Self {
            lock_path,
            _lock_file: lock_file,
            _os_claim: os_claim,
            removed_stale_pid: None,
        })
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        // Delete only a lock that still records THIS process. Two primaries can
        // coexist once the file is deleted out from under the first one, and
        // removing by path alone would then strip the survivor's lock — leaving
        // the runtime dir permanently able to host duplicates.
        match fs::read_to_string(&self.lock_path) {
            Ok(content) if parse_pid_from_lock_content(&content) == Some(std::process::id()) => {}
            Ok(_) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => return,
        }
        if let Err(error) = fs::remove_file(&self.lock_path) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "nrr-launcher: failed to remove single-instance lock {}: {error}",
                    self.lock_path.display()
                );
            }
        }
    }
}

/// Removes `lock_path` if the PID recorded inside it belongs to no live
/// process (or to a live process that is not this product's own binary —
/// Windows freely reuses PIDs, so a bare `is_process_alive` would treat a
/// crashed GUI's lock as held forever once its PID was recycled). Returns the
/// reclaimed PID on removal, `None` when the lock is left in place.
fn cleanup_stale_lock_file(lock_path: &Path) -> io::Result<Option<u32>> {
    let content = match fs::read_to_string(lock_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };

    let Some(pid) = parse_pid_from_lock_content(&content) else {
        return Ok(None);
    };
    if pid == std::process::id() {
        return Ok(None);
    }
    if is_process_alive(pid) {
        return Ok(None);
    }

    match fs::remove_file(lock_path) {
        Ok(_) => Ok(Some(pid)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Which build a lock holder is running: the crate version plus a fingerprint
/// of the executable file behind it.
///
/// The fingerprint is size + mtime because that costs one `stat`, while
/// hashing the image would read megabytes on every single launch to answer a
/// question any rebuild already changes. It is a build *identity*, not a
/// tamper check: two different builds of identical size and timestamp would
/// compare equal, which is exactly the accident this never has to survive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BuildStamp {
    version: String,
    exe_size: u64,
    exe_mtime_secs: u64,
}

impl BuildStamp {
    /// `None` when the running executable cannot be stat'ed — the lock then
    /// carries no build lines and every reader keeps the pid-only behaviour.
    pub(super) fn current() -> Option<Self> {
        let metadata = fs::metadata(env::current_exe().ok()?).ok()?;
        let modified = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
        Some(Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            exe_size: metadata.len(),
            exe_mtime_secs: modified.as_secs(),
        })
    }
}

impl fmt::Display for BuildStamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "version={} exe_size={} exe_mtime={}",
            self.version, self.exe_size, self.exe_mtime_secs
        )
    }
}

/// Records the holder of `lock_file`: the pid every reader has always
/// expected, followed by the build lines an older reader simply ignores.
pub(super) fn write_lock_record(lock_file: &mut File) -> io::Result<()> {
    writeln!(lock_file, "pid={}", std::process::id())?;
    if let Some(stamp) = BuildStamp::current() {
        writeln!(lock_file, "version={}", stamp.version)?;
        writeln!(lock_file, "exe_size={}", stamp.exe_size)?;
        writeln!(lock_file, "exe_mtime={}", stamp.exe_mtime_secs)?;
    }
    Ok(())
}

/// The build recorded in the lock for `instance_key` when it is NOT this
/// process's own, as `(running, ours)`.
///
/// `None` means there is no disagreement to report: no lock file, a lock
/// written before the build lines existed, an executable we cannot stat, or
/// the same build — all of which leave the caller's behaviour unchanged.
pub(super) fn foreign_build_in_lock(instance_key: &str) -> Option<(BuildStamp, BuildStamp)> {
    let content = fs::read_to_string(lock_file_path(instance_key)).ok()?;
    let running = parse_build_stamp_from_lock_content(&content)?;
    let ours = BuildStamp::current()?;
    (running != ours).then_some((running, ours))
}

/// Where the lock for `instance_key` lives, for readers. Writers go through
/// `ensure_user_runtime_dir` instead: they must also create the directory.
pub(super) fn lock_file_path(instance_key: &str) -> PathBuf {
    nrr_platform_api::paths::user_runtime_dir().join(format!("{instance_key}.lock"))
}

/// `None` for a lock written before the build lines existed (pid only), or one
/// missing any of them — the caller then has nothing to compare against.
pub(super) fn parse_build_stamp_from_lock_content(content: &str) -> Option<BuildStamp> {
    let (mut version, mut exe_size, mut exe_mtime_secs) = (None, None, None);
    for line in content.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "version" if !value.is_empty() => version = Some(value.to_owned()),
            "exe_size" => exe_size = value.parse().ok(),
            "exe_mtime" => exe_mtime_secs = value.parse().ok(),
            _ => {}
        }
    }
    Some(BuildStamp {
        version: version?,
        exe_size: exe_size?,
        exe_mtime_secs: exe_mtime_secs?,
    })
}

pub(super) fn parse_pid_from_lock_content(content: &str) -> Option<u32> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(raw_pid) = trimmed.strip_prefix("pid=") {
            if let Ok(parsed) = raw_pid.trim().parse::<u32>() {
                return Some(parsed);
            }
        }
    }
    None
}

/// File name of the running binary (`NetRuleRouter.exe`, `NetRuleRouterTray.exe`,
/// …), used to confirm a PID found alive is actually this product's own
/// process and not an unrelated one that inherited a recycled PID.
fn current_executable_file_name() -> Option<String> {
    env::current_exe()
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_owned)
}

/// True unless the PID is confirmably a *dead* or *unrelated* process.
/// The lock key is scoped to one surface, so only the binary that could have
/// created it can hold it — an image-name mismatch means the PID was reused
/// by something else. Any lookup failure (no permission, race) reports alive:
/// stealing a live instance's lock is worse than leaving a stale one in place.
#[cfg(windows)]
pub(super) fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Some(own_image_name) = current_executable_file_name() else {
        return true;
    };

    let filter = format!("PID eq {pid}");
    let mut command = Command::new(nrr_platform_windows::system_shell::system32_exe(
        "tasklist.exe",
    ));
    command.args(["/FI", &filter, "/FO", "CSV", "/NH"]);
    apply_no_window(&mut command);

    let Ok(output) = command.output() else {
        return true;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_tasklist_csv_line)
        .any(|(image_name, row_pid)| {
            row_pid == pid && image_name.eq_ignore_ascii_case(&own_image_name)
        })
}

/// Parses one `tasklist /FO CSV /NH` row into (image name, PID).
#[cfg(windows)]
pub(super) fn parse_tasklist_csv_line(line: &str) -> Option<(String, u32)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('"') {
        return None;
    }
    let mut fields = trimmed.split(',');
    let image_name = fields.next()?.trim().trim_matches('"').to_owned();
    let raw_pid = fields.next()?.trim().trim_matches('"');
    let pid = raw_pid.parse::<u32>().ok()?;
    Some((image_name, pid))
}

#[cfg(not(windows))]
pub(super) fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Some(own_image_name) = current_executable_file_name() else {
        return true;
    };

    // `/proc/<pid>/exe` resolves to the running binary's path; a future
    // macOS port (no `/proc`) would swap this for a `proc_pidpath` probe.
    match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(target) => target
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == own_image_name)
            .unwrap_or(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}
