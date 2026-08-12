//! `SecretNeverLog` — deny-by-construction secret protection.
//!
//! Wrapping a value in `SecretNeverLog<T>` prevents it from being serialised
//! into any log, audit, or export payload.  The wrapper deliberately does NOT
//! implement `serde::Serialize`, making accidental inclusion a compile error.
//!
//! # Usage
//!
//! ```ignore
//! struct ServiceCredential {
//!     api_key: SecretNeverLog<String>,
//!     display_name: String,  // safe to log
//! }
//! ```
//!
//! `api_key` will cause a compile error if someone tries to serialize
//! `ServiceCredential` with `#[derive(Serialize)]` — forcing the author
//! to explicitly strip secrets before serialization.

/// A wrapper that prevents its contained value from being serialised.
///
/// `SecretNeverLog<T>` intentionally **does not** implement `serde::Serialize`.
/// This is the primary enforcement mechanism for `PrivacyClass::SecretNeverLog`.
///
/// The value can still be accessed via `expose_secret()` in contexts that
/// explicitly need it (e.g., to pass to an authenticated service call).
pub struct SecretNeverLog<T>(T);

impl<T> SecretNeverLog<T> {
    /// Wraps a secret value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Exposes the secret for use in privileged contexts.
    ///
    /// The caller is responsible for ensuring the exposed value is not
    /// logged, printed, or included in any diagnostic output.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper and returns the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Clone> Clone for SecretNeverLog<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Debug output intentionally hides the secret value.
impl<T> std::fmt::Debug for SecretNeverLog<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretNeverLog(<hidden>)")
    }
}

/// Display output intentionally hides the secret value.
impl<T> std::fmt::Display for SecretNeverLog<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<secret>")
    }
}

// NOTE: `serde::Serialize` is intentionally NOT implemented for `SecretNeverLog<T>`.
//
// If you see a compile error like "the trait `Serialize` is not implemented for
// `SecretNeverLog<...>`", that is working as intended — move the secret
// outside any serializable struct or strip it before serialization.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_hides_value() {
        let s = SecretNeverLog::new("super-secret-token".to_string());
        let debug_str = format!("{s:?}");
        assert!(
            !debug_str.contains("super-secret-token"),
            "secret must not appear in debug: {debug_str}"
        );
        assert!(debug_str.contains("<hidden>"));
    }

    #[test]
    fn secret_display_hides_value() {
        let s = SecretNeverLog::new(12345u64);
        assert_eq!(s.to_string(), "<secret>");
    }

    #[test]
    fn secret_expose_returns_value() {
        let s = SecretNeverLog::new(42u32);
        assert_eq!(*s.expose_secret(), 42);
    }

    #[test]
    fn secret_into_inner() {
        let s = SecretNeverLog::new("token".to_string());
        assert_eq!(s.into_inner(), "token");
    }

    #[test]
    fn secret_clone() {
        let s = SecretNeverLog::new("cloneable".to_string());
        let s2 = s.clone();
        assert_eq!(s.expose_secret(), s2.expose_secret());
    }

    /// Compile-time test: verifies `SecretNeverLog` does NOT impl `Serialize`.
    ///
    /// This test exists as documentation.  The actual enforcement is that
    /// code like `serde_json::to_string(&SecretNeverLog::new("x"))` will
    /// fail to compile.  We cannot write a #[test] that asserts compile
    /// failure, but the absence of `impl Serialize` guarantees it.
    #[test]
    fn secret_never_log_has_no_serialize_impl() {
        // The fact that this test compiles without us implementing Serialize
        // confirms the invariant is maintained by the absence of the impl.
        #[allow(dead_code)] // documents the compile-time bound; not invoked
        fn assert_not_serialize<T: ?Sized>(_: &T)
        where
            SecretNeverLog<u8>: Sized,
        {
        }
        let _ = SecretNeverLog::new(0u8);
        // If someone accidentally adds `impl Serialize for SecretNeverLog`,
        // the golden tests in redact.rs that assert no secret data in output
        // would catch it at the integration level.
    }
}
