// Single-instance lock: the OS claim + lock-file fallback, stale-lock
// reclamation, and the liveness probes (`is_process_alive`, tasklist parsing)
// that decide whether a recorded owner is still real.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;

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
                    writeln!(lock_file, "pid={}", std::process::id())?;
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
                    writeln!(lock_file, "pid={}", std::process::id())?;
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
        writeln!(lock_file, "pid={}", std::process::id())?;
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
