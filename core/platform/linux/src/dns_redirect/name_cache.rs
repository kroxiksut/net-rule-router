//! The name service cache daemon (`nscd`, RHEL-like systems and RED OS) answers
//! `hosts` lookups from its own cache until the TTL ends, so a warm entry never
//! reaches our listener. Every mechanism's cache flush also clears it.

use std::net::SocketAddr;
use std::sync::Arc;

use nrr_platform_api::dns_redirect::{
    DnsNamespaceExemption, RedirectHandle, RedirectState, SystemDnsRedirectPort,
};
use nrr_platform_api::error::PlatformError;

use super::DnsCommands;

/// Drop nscd's cached `hosts` answers. Best effort: no nscd, no cache, no harm.
pub(crate) fn invalidate_nscd_hosts(commands: &dyn DnsCommands) {
    match commands.run("nscd", &["-i", "hosts"]) {
        Ok(reply) if reply.success => {
            tracing::debug!(target: "nrr::dns-redirect", "cleared the nscd hosts cache");
        }
        // Not installed, not running, or not caching `hosts`: nothing to clear.
        Ok(_) | Err(_) => {}
    }
}

/// A redirect whose cache flush also clears nscd's.
pub(crate) struct FlushesNscd<C: DnsCommands> {
    inner: Arc<dyn SystemDnsRedirectPort>,
    commands: C,
}

impl<C: DnsCommands> FlushesNscd<C> {
    pub(crate) fn new(inner: Arc<dyn SystemDnsRedirectPort>, commands: C) -> Self {
        Self { inner, commands }
    }
}

impl<C: DnsCommands> SystemDnsRedirectPort for FlushesNscd<C> {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        self.inner.redirect_to(listener)
    }

    fn restore(&self, handle: &RedirectHandle) -> Result<(), PlatformError> {
        self.inner.restore(handle)
    }

    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        self.inner.verify(handle)
    }

    fn inspect(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        self.inner.inspect(handle)
    }

    fn flush_cache(&self) -> Result<(), PlatformError> {
        let flushed = self.inner.flush_cache();
        invalidate_nscd_hosts(&self.commands);
        flushed
    }

    fn exempt_namespaces(
        &self,
        exemptions: &[DnsNamespaceExemption],
    ) -> Result<usize, PlatformError> {
        self.inner.exempt_namespaces(exemptions)
    }

    fn keep_short_names(
        &self,
        claimed: &[DnsNamespaceExemption],
        extra: &dyn Fn() -> Vec<String>,
    ) -> Result<(), PlatformError> {
        self.inner.keep_short_names(claimed, extra)
    }

    fn keep_names(&self, names: &[String], listener: SocketAddr) -> Result<usize, PlatformError> {
        self.inner.keep_names(names, listener)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_redirect::CommandReply;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<String>>,
        nscd_missing: bool,
    }

    impl DnsCommands for Arc<Recorder> {
        fn run(&self, program: &str, args: &[&str]) -> Result<CommandReply, PlatformError> {
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(format!("{program} {}", args.join(" ")));
            if self.nscd_missing {
                return Err(PlatformError::Transient {
                    operation: "run a DNS configuration command",
                    detail: "nscd: not found".into(),
                });
            }
            Ok(CommandReply {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            _input: &str,
        ) -> Result<CommandReply, PlatformError> {
            self.run(program, args)
        }
    }

    struct Inner {
        flushed: Mutex<u32>,
    }

    impl SystemDnsRedirectPort for Inner {
        fn redirect_to(&self, _l: SocketAddr) -> Result<RedirectHandle, PlatformError> {
            Err(PlatformError::NotSupported { reason: "test" })
        }
        fn restore(&self, _h: &RedirectHandle) -> Result<(), PlatformError> {
            Ok(())
        }
        fn verify(&self, _h: &RedirectHandle) -> Result<RedirectState, PlatformError> {
            Ok(RedirectState::Active)
        }
        fn flush_cache(&self) -> Result<(), PlatformError> {
            *self.flushed.lock().unwrap_or_else(|p| p.into_inner()) += 1;
            Ok(())
        }
    }

    #[test]
    fn a_flush_clears_the_inner_cache_and_nscd_hosts() {
        let commands = Arc::new(Recorder::default());
        let inner = Arc::new(Inner {
            flushed: Mutex::new(0),
        });
        let port = FlushesNscd::new(inner.clone(), commands.clone());
        port.flush_cache().expect("flush");
        assert_eq!(*inner.flushed.lock().expect("lock"), 1);
        assert_eq!(*commands.calls.lock().expect("lock"), ["nscd -i hosts"]);
    }

    #[test]
    fn a_machine_without_nscd_flushes_as_before() {
        let commands = Arc::new(Recorder {
            nscd_missing: true,
            ..Recorder::default()
        });
        let inner = Arc::new(Inner {
            flushed: Mutex::new(0),
        });
        let port = FlushesNscd::new(inner.clone(), commands);
        assert!(port.flush_cache().is_ok());
        assert_eq!(*inner.flushed.lock().expect("lock"), 1);
    }
}
