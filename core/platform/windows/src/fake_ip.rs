//! The Windows TUN mechanism, on Wintun.
//!
//! Windows is the only supported OS with no usermode TUN interface of its own,
//! so the fake-IP adapter is WireGuard LLC's Wintun: a signed, redistributable
//! driver we load through its published API (the `wintun-bindings` crate).
//! Linux opens `/dev/net/tun` and macOS `utun` natively and ship nothing extra.
//!
//! Two ports are implemented here, both declared neutrally in
//! `nrr-platform-api`:
//!
//! - [`TunAdapterPort`] — create the adapter, then read/write raw IP packets.
//! - [`ThirdPartyIntegrityPort`] — report where the DLL was found, its SHA-256,
//!   and who Authenticode says signed it, so the GUI can show the user that the
//!   driver on disk is the genuine original rather than merely assert it.
//!
//! ## Where `wintun.dll` is looked up
//!
//! Mirrors the QML-path resolution order so a dev build, a redirected
//! `target-dir`, and an installed product all work:
//!
//! 1. `NRR_WINTUN_DLL` — explicit absolute path (tests, packaging, support).
//! 2. Next to the running executable — the installed layout.
//! 3. `lib/` beside the executable — where `build.rs` stages the vendored copy,
//!    so a freshly built `target/<profile>/` runs without any manual step.
//! 4. `third_party/wintun/bin/<arch>/wintun.dll`, searched upward from the
//!    executable — the repository layout during development.
//!
//! No `unsafe` of our own: loading the library is `unsafe` in the binding crate
//! and is wrapped in exactly one place below, with the signature check (crate
//! feature `verify_binary_signature`) refusing anything not signed by WireGuard
//! LLC before the DLL is mapped.

use std::path::{Path, PathBuf};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::fake_ip::tun::{TunAdapterConfig, TunAdapterPort, TunControl, TunDevice};
use nrr_platform_api::third_party::{
    ThirdPartyComponent, ThirdPartyComponentStatus, ThirdPartyIntegrityPort, WINTUN_COMPONENT,
};

/// Environment override for the DLL location.
pub const WINTUN_DLL_ENV: &str = "NRR_WINTUN_DLL";

/// Repository-relative directory holding the vendored driver, per architecture.
const VENDORED_DIR: &str = "third_party/wintun/bin";

/// Directory beside the executable that `build.rs` stages the driver into.
const STAGED_SUBDIR: &str = "lib";

/// How far up from the executable the repository layout is searched.
const UPWARD_SEARCH_DEPTH: usize = 6;

/// Architecture sub-directory of the vendored Wintun build for this target.
/// The driver is architecture-matched to the PROCESS, not to the OS: a 32-bit
/// build running on 64-bit Windows must load the `x86` DLL.
#[must_use]
pub fn vendored_arch_dir() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "amd64"
    }
}

/// Candidate paths for `wintun.dll`, in resolution order. Pure — the caller
/// filters by existence, which is what makes the order unit-testable.
#[must_use]
pub fn wintun_dll_candidates(env_override: Option<&str>, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(explicit) = env_override.map(str::trim).filter(|s| !s.is_empty()) {
        candidates.push(PathBuf::from(explicit));
    }
    if let Some(dir) = exe_dir {
        candidates.push(dir.join(WINTUN_COMPONENT.file_name));
        candidates.push(dir.join(STAGED_SUBDIR).join(WINTUN_COMPONENT.file_name));
        let mut current = Some(dir);
        for _ in 0..UPWARD_SEARCH_DEPTH {
            let Some(here) = current else { break };
            candidates.push(
                here.join(VENDORED_DIR)
                    .join(vendored_arch_dir())
                    .join(WINTUN_COMPONENT.file_name),
            );
            current = here.parent();
        }
    }
    candidates
}

/// First existing candidate, or `None` when the driver is not installed.
#[must_use]
pub fn resolve_wintun_dll() -> Option<PathBuf> {
    let env_override = std::env::var(WINTUN_DLL_ENV).ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    wintun_dll_candidates(env_override.as_deref(), exe_dir.as_deref())
        .into_iter()
        .find(|path| path.is_file())
}

/// SHA-256 of a file as lower-case hex.
fn file_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(bytes);
    Some(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}

// ── TUN adapter ──────────────────────────────────────────────────────────────

/// Windows fake-IP adapter, backed by Wintun.
#[derive(Debug, Clone, Default)]
pub struct WintunTunAdapter {
    /// Explicit DLL path; `None` uses [`resolve_wintun_dll`].
    dll_path: Option<PathBuf>,
}

impl WintunTunAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the driver to a specific file (packaging, tests, support).
    #[must_use]
    pub fn with_dll_path(path: impl Into<PathBuf>) -> Self {
        Self {
            dll_path: Some(path.into()),
        }
    }

    /// The DLL this adapter would load.
    #[must_use]
    pub fn dll_path(&self) -> Option<PathBuf> {
        match &self.dll_path {
            Some(path) => path.is_file().then(|| path.clone()),
            None => resolve_wintun_dll(),
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(unsafe_code)]

    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use nrr_platform_api::error::PlatformError;
    use nrr_platform_api::third_party::SignatureStatus;

    use super::WINTUN_COMPONENT;

    /// Load the driver through its published API. The ONE `unsafe` call in the
    /// fake-IP Windows path.
    ///
    /// # Safety
    ///
    /// `wintun_bindings::load_from_path` is `unsafe` because loading any DLL
    /// runs its `DllMain`. The crate's `verify_binary_signature` feature checks
    /// the Authenticode signature and the signer name BEFORE the library is
    /// mapped, so an unsigned or foreign-signed file at this path is rejected
    /// rather than executed.
    pub(super) fn load_wintun(path: &Path) -> Result<wintun_bindings::Wintun, PlatformError> {
        // SAFETY: the signature of the file at `path` is verified by the
        // binding crate before the DLL is mapped; nothing else in this process
        // dereferences the returned handle outside the crate's safe wrappers.
        unsafe { wintun_bindings::load_from_path(path) }.map_err(|err| PlatformError::Transient {
            operation: "wintun::load_from_path",
            detail: err.to_string(),
        })
    }

    /// What Authenticode says about the file, in the neutral vocabulary.
    ///
    /// The check IS the load: with the `verify_binary_signature` feature the
    /// binding crate verifies the signature and compares the signer against
    /// "WireGuard LLC" before mapping the DLL, so a successful load is proof of
    /// both. Doing it this way keeps a single code path — the GUI reports on
    /// exactly the check that gates the driver at runtime, not a parallel
    /// re-implementation that could disagree with it.
    pub(super) fn signature_status(path: &Path) -> SignatureStatus {
        match load_wintun(path) {
            Ok(_) => SignatureStatus::Valid(WINTUN_COMPONENT.expected_signer.to_string()),
            Err(err) => SignatureStatus::Invalid(err.to_string()),
        }
    }

    /// Shared slot for the poll loop's readable-wake hint. The reader thread
    /// fires it after queueing each packet so an idle-parked poll loop wakes
    /// immediately instead of sleeping out its interval.
    pub(super) type ReadableWaker = Arc<std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

    /// An open Wintun session: the adapter is kept alive alongside it, since
    /// dropping the adapter tears the interface down.
    ///
    /// A dedicated reader thread blocks on the driver's read-wait event
    /// (`Session::recv` waits on the read + shutdown event pair) and hands
    /// packets over a channel, so the poll loop never blocks on the device and
    /// still learns about inbound packets with no polling latency.
    pub(super) struct WintunDevice {
        session: Arc<wintun_bindings::Session>,
        _adapter: Arc<wintun_bindings::Adapter>,
        mtu: u16,
        shutdown: Arc<AtomicBool>,
        inbound: std::sync::mpsc::Receiver<Vec<u8>>,
        reader: Option<std::thread::JoinHandle<()>>,
        waker: ReadableWaker,
    }

    impl WintunDevice {
        pub(super) fn new(
            session: Arc<wintun_bindings::Session>,
            adapter: Arc<wintun_bindings::Adapter>,
            mtu: u16,
        ) -> Self {
            let shutdown = Arc::new(AtomicBool::new(false));
            let waker: ReadableWaker = Arc::new(std::sync::Mutex::new(None));
            let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let reader = std::thread::Builder::new()
                .name("nrr-wintun-read".to_string())
                .spawn({
                    let session = Arc::clone(&session);
                    let shutdown = Arc::clone(&shutdown);
                    let waker = Arc::clone(&waker);
                    move || run_reader(&session, &shutdown, &tx, &waker)
                })
                .ok();
            if reader.is_none() {
                tracing::warn!(
                    target: "nrr::fake-ip",
                    "wintun reader thread failed to spawn — device reads will report end-of-stream",
                );
            }
            Self {
                session,
                _adapter: adapter,
                mtu,
                shutdown,
                inbound: rx,
                reader,
                waker,
            }
        }

        pub(super) fn session(&self) -> Arc<wintun_bindings::Session> {
            Arc::clone(&self.session)
        }

        pub(super) fn mtu_value(&self) -> u16 {
            self.mtu
        }

        pub(super) fn pop_inbound(
            &self,
        ) -> std::result::Result<Vec<u8>, std::sync::mpsc::TryRecvError> {
            self.inbound.try_recv()
        }

        pub(super) fn store_waker(&self, hint: Arc<dyn Fn() + Send + Sync>) {
            let mut slot = self.waker.lock().unwrap_or_else(|p| p.into_inner());
            *slot = Some(hint);
        }

        /// True once [`WintunControl::shutdown`] has run — the reader turns any
        /// error after that point into a clean end-of-stream. Wintun's own
        /// error for "session cancelled" is not a distinct `io::ErrorKind`, so
        /// this flag, not the error kind, is what makes the exit unambiguous.
        pub(super) fn is_shutting_down(&self) -> bool {
            self.shutdown.load(Ordering::SeqCst)
        }

        pub(super) fn control_handle(&self) -> WintunControl {
            WintunControl {
                session: Arc::clone(&self.session),
                shutdown: Arc::clone(&self.shutdown),
            }
        }
    }

    impl Drop for WintunDevice {
        fn drop(&mut self) {
            // Unblock the reader (it waits on the session's read + shutdown
            // event pair) and reap it so no thread outlives the device.
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = self.session.shutdown();
            if let Some(handle) = self.reader.take() {
                let _ = handle.join();
            }
        }
    }

    /// Reader-thread body: block on the driver until a packet arrives, queue
    /// it, fire the wake hint. Exits on shutdown or on any receive error — the
    /// dropped sender then surfaces to the poll loop as end-of-stream (clean)
    /// or an error (unexpected), which the stack's supervisor reaps.
    fn run_reader(
        session: &Arc<wintun_bindings::Session>,
        shutdown: &AtomicBool,
        tx: &std::sync::mpsc::Sender<Vec<u8>>,
        waker: &ReadableWaker,
    ) {
        // Ring packets are MTU-bound, but size for the maximum IP datagram so a
        // driver-side surprise cannot truncate.
        let mut buf = vec![0u8; usize::from(u16::MAX)];
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            match session.recv(&mut buf) {
                Ok(0) => continue,
                Ok(len) => {
                    if tx.send(buf[..len].to_vec()).is_err() {
                        // Device dropped — nobody is reading anymore.
                        return;
                    }
                    let hint = {
                        let slot = waker.lock().unwrap_or_else(|p| p.into_inner());
                        slot.clone()
                    };
                    if let Some(wake) = hint {
                        wake();
                    }
                }
                Err(_) if shutdown.load(Ordering::SeqCst) => return,
                Err(err) => {
                    tracing::warn!(
                        target: "nrr::fake-ip",
                        error = %err,
                        "wintun receive failed — reader thread exiting",
                    );
                    return;
                }
            }
        }
    }

    pub(super) struct WintunControl {
        pub(super) session: Arc<wintun_bindings::Session>,
        pub(super) shutdown: Arc<AtomicBool>,
    }
}

#[cfg(target_os = "windows")]
impl TunAdapterPort for WintunTunAdapter {
    fn is_available(&self) -> bool {
        match self.dll_path() {
            Some(path) => windows_impl::load_wintun(&path).is_ok(),
            None => false,
        }
    }

    fn open(&self, config: &TunAdapterConfig) -> Result<Box<dyn TunDevice>, PlatformError> {
        config.validate()?;
        let path = self.dll_path().ok_or(PlatformError::NotSupported {
            reason: "wintun.dll not found next to the executable or in third_party/wintun",
        })?;
        let wintun = windows_impl::load_wintun(&path)?;

        let adapter = wintun_bindings::Adapter::create(
            &wintun,
            &config.adapter_name,
            &config.adapter_name,
            None,
        )
        .map_err(|err| PlatformError::Transient {
            operation: "wintun::Adapter::create",
            detail: err.to_string(),
        })?;

        adapter
            .set_network_addresses_tuple(
                std::net::IpAddr::V4(config.v4_address),
                std::net::IpAddr::V4(prefix_to_netmask_v4(config.v4_prefix_len)),
                None,
            )
            .map_err(|err| PlatformError::Transient {
                operation: "wintun::Adapter::set_network_addresses_tuple",
                detail: err.to_string(),
            })?;

        adapter
            .set_mtu(usize::from(config.mtu))
            .map_err(|err| PlatformError::Transient {
                operation: "wintun::Adapter::set_mtu",
                detail: err.to_string(),
            })?;

        // Own the pool route explicitly instead of trusting the connected
        // route the static-address assignment implies: with another tunnel
        // holding split-default routes the implicit route has been observed
        // absent, silently steering pool traffic out a real adapter. An
        // already-present route is success; any other failure fails the open —
        // a pool the OS will not route into this adapter is a non-functional
        // stack, and a failed open keeps the feature off (fail-open). The
        // route needs no teardown of its own: it dies with the adapter.
        let ifindex = adapter
            .get_adapter_index()
            .map_err(|err| PlatformError::Transient {
                operation: "wintun::Adapter::get_adapter_index",
                detail: err.to_string(),
            })?;
        ensure_pool_route_v4(config, ifindex)?;

        let session = adapter
            .start_session(config.ring_capacity_bytes)
            .map_err(|err| PlatformError::Transient {
                operation: "wintun::Adapter::start_session",
                detail: err.to_string(),
            })?;

        Ok(Box::new(windows_impl::WintunDevice::new(
            session, adapter, config.mtu,
        )))
    }
}

#[cfg(target_os = "windows")]
impl TunDevice for windows_impl::WintunDevice {
    fn mtu(&self) -> u16 {
        self.mtu_value()
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, PlatformError> {
        // Non-blocking by design: the fake-IP run loop must keep polling to
        // service upstream->client data even when no packet is inbound, so a
        // blocking read would starve that direction. The device's own reader
        // thread does the blocking wait on the driver and queues packets here;
        // an empty queue reads as `Ok(0)` ("nothing this tick"), and the wake
        // hint registered via `set_readable_waker` cuts the caller's idle park
        // short the moment the thread queues a packet. A shut-down device also
        // reads as `Ok(0)`, the loop's stop being governed separately by the
        // controller's flag.
        if self.is_shutting_down() {
            return Ok(0);
        }
        match self.pop_inbound() {
            Ok(packet) => {
                if packet.len() > buf.len() {
                    tracing::warn!(
                        target: "nrr::fake-ip",
                        packet_len = packet.len(),
                        buf_len = buf.len(),
                        "inbound TUN packet exceeds the read buffer — dropped",
                    );
                    return Ok(0);
                }
                buf[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => Ok(0),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                if self.is_shutting_down() {
                    Ok(0)
                } else {
                    Err(PlatformError::Transient {
                        operation: "wintun reader thread",
                        detail: "reader thread exited unexpectedly".to_string(),
                    })
                }
            }
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PlatformError> {
        self.session()
            .send(packet)
            .map_err(|err| PlatformError::Transient {
                operation: "wintun::Session::send",
                detail: err.to_string(),
            })
    }

    fn set_readable_waker(&mut self, waker: std::sync::Arc<dyn Fn() + Send + Sync>) {
        self.store_waker(std::sync::Arc::clone(&waker));
        // Packets may already be queued from before registration — fire once so
        // the caller drains them without waiting out an idle park.
        waker();
    }

    fn control(&self) -> std::sync::Arc<dyn TunControl> {
        std::sync::Arc::new(self.control_handle())
    }
}

#[cfg(target_os = "windows")]
impl TunControl for windows_impl::WintunControl {
    fn shutdown(&self) -> Result<(), PlatformError> {
        // Raise the flag BEFORE cancelling, so a reader that wakes up from the
        // cancellation always observes it and exits with `Ok(0)`.
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.session
            .shutdown()
            .map_err(|err| PlatformError::Transient {
                operation: "wintun::Session::shutdown",
                detail: err.to_string(),
            })
    }
}

/// Win32 `ERROR_OBJECT_ALREADY_EXISTS` — the forwarding entry is already
/// present, which for the pool route is success, not failure.
#[cfg(target_os = "windows")]
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// Install the on-link IPv4 route that sends the whole fake pool into the TUN
/// adapter. Metric 0 within its prefix keeps it preferred over any same-prefix
/// stray; longest-prefix match already beats a tunnel's split-default routes.
#[cfg(target_os = "windows")]
fn ensure_pool_route_v4(
    config: &TunAdapterConfig,
    interface_index: u32,
) -> Result<(), PlatformError> {
    let mask = u32::from(prefix_to_netmask_v4(config.v4_prefix_len));
    let entry = nrr_platform_api::RouteEntry {
        destination: std::net::Ipv4Addr::from(u32::from(config.v4_address) & mask),
        prefix_length: config.v4_prefix_len,
        next_hop: std::net::Ipv4Addr::UNSPECIFIED,
        interface_index,
        metric: 0,
        is_ours: true,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    match crate::win32_ffi::route_table::add_route(&entry) {
        Ok(()) => Ok(()),
        Err(PlatformError::Win32 { code, .. }) if code == ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        Err(err) => Err(err),
    }
}

/// IPv4 prefix length as a dotted netmask (`15` → `255.254.0.0`).
#[must_use]
pub fn prefix_to_netmask_v4(prefix_len: u8) -> std::net::Ipv4Addr {
    let bits = prefix_len.min(32);
    let mask: u32 = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(bits))
    };
    std::net::Ipv4Addr::from(mask)
}

// ── Third-party integrity ────────────────────────────────────────────────────

/// Reports on the third-party binaries this Windows build ships.
#[derive(Debug, Clone, Default)]
pub struct WindowsThirdPartyIntegrity;

impl WindowsThirdPartyIntegrity {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn inspect(component: &ThirdPartyComponent) -> ThirdPartyComponentStatus {
        let Some(path) = resolve_wintun_dll() else {
            return ThirdPartyComponentStatus::missing(component);
        };
        let sha256 = file_sha256(&path);
        #[cfg(target_os = "windows")]
        let signature = windows_impl::signature_status(&path);
        #[cfg(not(target_os = "windows"))]
        let signature = nrr_platform_api::third_party::SignatureStatus::NotChecked;
        ThirdPartyComponentStatus::from_parts(
            component,
            Some(path.to_string_lossy().into_owned()),
            sha256,
            signature,
        )
    }
}

impl ThirdPartyIntegrityPort for WindowsThirdPartyIntegrity {
    fn inspect_components(&self) -> Vec<ThirdPartyComponentStatus> {
        vec![Self::inspect(&WINTUN_COMPONENT)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_is_tried_before_anything_else() {
        let candidates = wintun_dll_candidates(
            Some(r"D:\pinned\wintun.dll"),
            Some(Path::new(r"C:\Program Files\NetRuleRouter")),
        );
        assert_eq!(candidates[0], PathBuf::from(r"D:\pinned\wintun.dll"));
    }

    #[test]
    fn blank_env_override_is_ignored() {
        let candidates = wintun_dll_candidates(Some("   "), Some(Path::new(r"C:\app")));
        assert_eq!(candidates[0], PathBuf::from(r"C:\app").join("wintun.dll"));
    }

    #[test]
    fn installed_layout_wins_over_the_staged_and_repository_layouts() {
        let exe_dir = Path::new(r"C:\Program Files\NetRuleRouter");
        let candidates = wintun_dll_candidates(None, Some(exe_dir));
        assert_eq!(candidates[0], exe_dir.join("wintun.dll"));
        assert_eq!(candidates[1], exe_dir.join("lib").join("wintun.dll"));
        assert!(
            candidates[2].ends_with(
                Path::new(VENDORED_DIR)
                    .join(vendored_arch_dir())
                    .join("wintun.dll")
            ),
            "the repository layout is searched after the staged copy: {:?}",
            candidates[2]
        );
    }

    #[test]
    fn repository_layout_is_searched_upward_from_the_executable() {
        let exe_dir = Path::new(r"D:\repo\target\debug");
        let candidates = wintun_dll_candidates(None, Some(exe_dir));
        let wanted = Path::new(r"D:\repo")
            .join(VENDORED_DIR)
            .join(vendored_arch_dir())
            .join("wintun.dll");
        assert!(
            candidates.contains(&wanted),
            "expected {wanted:?} among {candidates:?}"
        );
    }

    #[test]
    fn no_executable_directory_yields_only_the_override() {
        assert!(wintun_dll_candidates(None, None).is_empty());
    }

    #[test]
    fn prefix_lengths_map_to_the_expected_netmasks() {
        use std::net::Ipv4Addr;
        assert_eq!(prefix_to_netmask_v4(15), Ipv4Addr::new(255, 254, 0, 0));
        assert_eq!(prefix_to_netmask_v4(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask_v4(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask_v4(0), Ipv4Addr::UNSPECIFIED);
    }

    /// The vendored driver as it sits in the repository, when present.
    fn vendored_dll() -> Option<PathBuf> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../third_party/wintun/bin")
            .join(vendored_arch_dir())
            .join("wintun.dll");
        path.is_file().then_some(path)
    }

    #[test]
    fn vendored_driver_hash_matches_the_pinned_value() {
        let Some(path) = vendored_dll() else {
            return; // No vendored copy on this checkout — nothing to drift.
        };
        let hash = file_sha256(&path).expect("vendored driver is readable");
        assert!(
            WINTUN_COMPONENT.known_sha256.contains(&hash.as_str()),
            "vendored wintun.dll ({hash}) is not one of the pinned builds — \
             re-verify it against wintun.net before updating the pin"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn vendored_driver_loads_and_is_reported_genuine() {
        use nrr_platform_api::third_party::IntegrityVerdict;

        let Some(path) = vendored_dll() else {
            return;
        };
        // Loading performs the Authenticode + signer check inside the binding
        // crate; success is proof the driver on disk is the real signed one.
        assert!(
            WintunTunAdapter::with_dll_path(&path).is_available(),
            "vendored wintun.dll failed signature verification or could not load"
        );
        let status = ThirdPartyComponentStatus::from_parts(
            &WINTUN_COMPONENT,
            Some(path.to_string_lossy().into_owned()),
            file_sha256(&path),
            windows_impl::signature_status(&path),
        );
        assert_eq!(status.verdict, IntegrityVerdict::Genuine);
    }

    #[test]
    fn integrity_reports_the_component_even_when_the_driver_is_absent() {
        let statuses = WindowsThirdPartyIntegrity::new().inspect_components();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].key, "wintun");
        assert_eq!(statuses[0].publisher, "WireGuard LLC");
    }
}
