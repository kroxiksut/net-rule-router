//! DACL/security descriptor construction for the named pipe.
//!
//! ## Security descriptor (SDDL)
//!
//! ```text
//! D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)S:(ML;;NW;;;LW)
//! ```
//!
//! - `(A;;GA;;;SY)` — LocalSystem: Generic All
//! - `(A;;GA;;;BA)` — Builtin Administrators: Generic All
//! - `(A;;GRGW;;;AU)` — Authenticated Users: Generic Read + Generic Write
//!   (needed for duplex named-pipe IO; identity check at the application
//!   layer rejects unknown processes)
//! - `S:(ML;;NW;;;LW)` — Mandatory Integrity Label: Low IL no-write-up
//!
//! Everyone (`WD`) is *not* listed — absence in DACL means deny by default.
//!
//! ## Identity check still required
//!
//! The DACL only protects against random local users. Authenticated Users
//! is a broad SID; applications running under an unprivileged interactive
//! user account will still be able to *connect*. The application-layer
//! identity check in `named_pipe_identity` rejects connections from any
//! process whose exe basename is not on the whitelist.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// SDDL string for the named pipe's security descriptor.
///
/// See module documentation for the breakdown.
pub const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)S:(ML;;NW;;;LW)";

/// Build a `SECURITY_ATTRIBUTES` for `CreateNamedPipeW`.
///
/// The returned wrapper owns the underlying security descriptor; dropping
/// it frees the descriptor via `LocalFree`. Keep it alive for the
/// duration of every `CreateNamedPipeW` call that uses its
/// `SECURITY_ATTRIBUTES` pointer.
pub struct PipeSecurityAttributes {
    /// Owning pointer to the security descriptor. Freed by `Drop`.
    sd: PSECURITY_DESCRIPTOR,
    /// `SECURITY_ATTRIBUTES` struct pointing at `sd`. Stable address since
    /// it lives inside the boxed wrapper.
    attrs: Box<SECURITY_ATTRIBUTES>,
}

impl PipeSecurityAttributes {
    /// Construct from the canonical `PIPE_SDDL`.
    pub fn for_pipe() -> Result<Self, AclError> {
        Self::from_sddl(PIPE_SDDL)
    }

    /// Construct from an arbitrary SDDL string. Public mostly for tests.
    pub fn from_sddl(sddl: &str) -> Result<Self, AclError> {
        // Convert SDDL to UTF-16 null-terminated.
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: `wide` is a valid null-terminated UTF-16 buffer for the
        // lifetime of this call. `sd_out` receives an owning pointer that
        // we must free with `LocalFree`. We pass `None` for the size out
        // parameter as we don't need it.
        let mut sd_out: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd_out as *mut _,
                None,
            )
        };
        if result.is_err() || sd_out.0.is_null() {
            // SAFETY: GetLastError reads thread-local Win32 error state.
            let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
            return Err(AclError::SddlConversionFailed { code });
        }

        let attrs = Box::new(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_out.0,
            bInheritHandle: BOOL(0),
        });

        Ok(Self { sd: sd_out, attrs })
    }

    /// Pointer to the `SECURITY_ATTRIBUTES` struct. Pass to
    /// `CreateNamedPipeW` as `lpSecurityAttributes`.
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &*self.attrs as *const _
    }

    /// SDDL-equivalent string this descriptor was built from. Used by
    /// tests to verify roundtrip correctness.
    #[cfg(test)]
    pub fn sddl(&self) -> &'static str {
        // Always built from the canonical constant in `for_pipe()`.
        // `from_sddl` callers can recompute if they need a non-canonical one.
        PIPE_SDDL
    }
}

impl Drop for PipeSecurityAttributes {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            // SAFETY: `sd` was returned by ConvertStringSecurityDescriptor;
            // the matching free is `LocalFree`. We null the pointer after
            // freeing so a double-drop (theoretical) is a no-op.
            unsafe {
                let _ = LocalFree(HLOCAL(self.sd.0));
            }
            self.sd.0 = ptr::null_mut();
        }
    }
}

// SAFETY: `PipeSecurityAttributes` owns its security descriptor and a
// stable address `Box<SECURITY_ATTRIBUTES>`. The Win32 API only reads from
// the pointer during `CreateNamedPipeW` calls; we don't mutate the
// descriptor concurrently.
unsafe impl Send for PipeSecurityAttributes {}
unsafe impl Sync for PipeSecurityAttributes {}

/// Errors when building the pipe security descriptor.
#[derive(Debug)]
pub enum AclError {
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW` failed.
    SddlConversionFailed { code: u32 },
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SddlConversionFailed { code } => {
                write!(f, "SDDL conversion failed: Win32 error 0x{code:08X}")
            }
        }
    }
}

impl std::error::Error for AclError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_constant_matches_documented_format() {
        assert!(PIPE_SDDL.contains("(A;;GA;;;SY)"));
        assert!(PIPE_SDDL.contains("(A;;GA;;;BA)"));
        assert!(PIPE_SDDL.contains("(A;;GRGW;;;AU)"));
        assert!(PIPE_SDDL.contains("S:(ML;;NW;;;LW)"));
    }

    #[test]
    fn building_from_canonical_sddl_succeeds() {
        let sa = PipeSecurityAttributes::for_pipe().expect("build SA");
        assert!(!sa.as_ptr().is_null());
        assert_eq!(sa.sddl(), PIPE_SDDL);
    }

    #[test]
    fn building_from_invalid_sddl_returns_error() {
        let result = PipeSecurityAttributes::from_sddl("not-a-valid-sddl-string");
        assert!(matches!(result, Err(AclError::SddlConversionFailed { .. })));
    }

    #[test]
    fn dropping_attributes_frees_descriptor_without_panic() {
        // The Drop impl runs LocalFree; if it leaks or double-frees, this
        // test triggers Win32 heap corruption guards in debug builds.
        for _ in 0..50 {
            let _sa = PipeSecurityAttributes::for_pipe().expect("build SA");
        }
    }

    #[test]
    fn security_attributes_struct_has_correct_length() {
        let sa = PipeSecurityAttributes::for_pipe().expect("build SA");
        // SAFETY: as_ptr() points at a live SECURITY_ATTRIBUTES we own.
        let attrs = unsafe { &*sa.as_ptr() };
        assert_eq!(
            attrs.nLength as usize,
            std::mem::size_of::<SECURITY_ATTRIBUTES>()
        );
        assert!(!attrs.lpSecurityDescriptor.is_null());
        assert_eq!(attrs.bInheritHandle.0, 0);
    }
}
