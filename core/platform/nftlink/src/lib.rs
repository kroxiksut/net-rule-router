//! `nftlink` — direct netlink access to the Linux `nf_tables` subsystem.
//!
//! **Status: scaffold.** Nothing here talks to a kernel yet. The crate exists
//! now so the boundary that makes it separable is established from the first
//! commit rather than discovered at extraction time.
//!
//! ## What this crate is
//!
//! A library that speaks nf_tables — tables, chains, rules, sets, batches —
//! over an `AF_NETLINK` socket, with no external process. It replaces driving
//! the `nft` binary, which is what the product does today.
//!
//! ## What this crate must never become
//!
//! It knows nothing about the application that currently hosts it: no
//! enforcement plan, no routing policy, no user model, no product types.
//! `tests/independence.rs` fails the build if a `nrr-*` dependency ever
//! appears. Translation from the product's intent into calls on this crate
//! belongs on the other side of that line.
//!
//! ## Licence
//!
//! MPL-2.0 while it lives in this workspace, `MIT OR Apache-2.0` once it is
//! split out and published. Relicensing is only possible while every author is
//! the current copyright holder, which is why `CONTRIBUTING.md` asks
//! contributors to open an issue rather than send a patch: the answer to that
//! issue is to perform the split.
//!
//! ## Where the protocol knowledge may come from
//!
//! The kernel's uapi headers (`linux/netfilter/nf_tables.h`, GPL-2.0 WITH
//! Linux-syscall-note — the exception exists precisely so userspace can use
//! them) and public documentation. **Not** from reading `libnftnl` or
//! `rustables`: both are GPL, and code written from a GPL source is a
//! derivative work even with no copied lines.

#![forbid(unsafe_code)]

/// Address families an nf_tables table can belong to.
///
/// Only `Inet` is planned for the first cut: it sees IPv4 and IPv6 in one
/// table, which is what a per-destination policy wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Inet,
}

/// A batch of changes applied as one kernel transaction — all of it lands, or
/// none of it does. This atomicity is the reason to move off the CLI: a
/// half-applied ruleset is a leak.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    // TODO: hold the encoded netlink messages once the encoder exists.
}

impl Batch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Why a netlink exchange failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The crate has no implementation for this yet.
    NotImplemented(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented(what) => write!(f, "nftlink: {what} is not implemented yet"),
        }
    }
}

impl std::error::Error for Error {}

/// A connection to the kernel's nf_tables subsystem.
#[derive(Debug, Default)]
pub struct Connection {
    _private: (),
}

impl Connection {
    /// Open a netlink socket to nf_tables.
    ///
    /// # Errors
    /// Always, for now: the socket layer is not written.
    pub fn open() -> Result<Self, Error> {
        Err(Error::NotImplemented("opening a netlink socket"))
    }

    /// Send a batch and wait for the kernel's verdict.
    ///
    /// # Errors
    /// Always, for now: the encoder is not written.
    pub fn apply(&self, _batch: &Batch) -> Result<(), Error> {
        Err(Error::NotImplemented("applying a batch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scaffold has to be honest: an unimplemented call says so rather than
    /// returning a success that enforces nothing.
    #[test]
    fn every_entry_point_reports_not_implemented() {
        assert_eq!(
            Connection::open().unwrap_err(),
            Error::NotImplemented("opening a netlink socket"),
        );
        let connection = Connection::default();
        assert_eq!(
            connection.apply(&Batch::new()).unwrap_err(),
            Error::NotImplemented("applying a batch"),
        );
    }

    #[test]
    fn the_error_reads_as_a_sentence() {
        assert_eq!(
            Error::NotImplemented("applying a batch").to_string(),
            "nftlink: applying a batch is not implemented yet",
        );
    }
}
