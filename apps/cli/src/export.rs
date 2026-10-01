//! `diag export` — ask the service for a diagnostic archive.
//!
//! The console does not build the archive. It asks the service to, and prints
//! where the service put it. That is the whole design: the application already
//! has this button, and two assemblers of the same archive would drift until the
//! file a user attaches to a report depends on which surface produced it.
//!
//! Consequently it needs a running service, and says so plainly rather than
//! degrading into a locally-assembled approximation.

use std::io;
use std::path::Path;
use std::time::Duration;

use nrr_ipc_client::IpcClientError;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{DiagnosticsExportArchiveRequest, DiagnosticsExportArchiveResponse};

use crate::exit;

/// How long to wait for the archive. Generous: the service walks logs, audit
/// and storage to build it, and a support archive is worth waiting for.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);

pub fn run(exe: &str) -> u8 {
    let (client, link) = crate::link::open();
    if link != crate::link::Link::Connected {
        eprintln!(
            "The {} service is not answering.",
            nrr_shared::product_identity::PRODUCT_NAME
        );
        eprintln!("Check that it is installed and running: {exe} status");
        return exit::NOT_RESPONDING;
    }

    // Built from the SSOT type rather than a hand-written object. Every field
    // of the request carries `serde(default)`, so a key spelled by hand is not
    // rejected — it is dropped and replaced by the default, silently, and the
    // archive the user attaches is missing the section they asked for. The
    // struct cannot be spelled wrong.
    let request = match serde_json::to_value(DiagnosticsExportArchiveRequest {
        include_logs: true,
        include_audit_summary: true,
        include_troubleshooting_playbooks: true,
        ..DiagnosticsExportArchiveRequest::default()
    }) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Could not build the export request: {e}");
            return exit::FAILED;
        }
    };
    match client.call(
        IpcOperationName::DiagnosticsExportArchive,
        request,
        EXPORT_TIMEOUT,
    ) {
        Ok(payload) => report_archive(&payload, exe),
        Err(err) => report_failure(err, exe),
    }
}

fn report_archive(payload: &serde_json::Value, exe: &str) -> u8 {
    // Same reason as the request: read through the type, so a renamed field
    // fails to compile here instead of printing an empty path at the user.
    let response: DiagnosticsExportArchiveResponse = match serde_json::from_value(payload.clone()) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("The service answered with something this console cannot read: {e}");
            return exit::FAILED;
        }
    };
    if response.archive_path.is_empty() {
        eprintln!("The service reported success but named no archive.");
        return exit::FAILED;
    }
    let path = Path::new(&response.archive_path);
    // The archive sits in the service's own tree and reaches this account only
    // through a grant the service makes best-effort: "written" is claimed only
    // once this account has actually opened it.
    let opened = std::fs::File::open(path).map(drop);
    report_handoff(path, response.size_bytes, exe, opened)
}

fn report_handoff(path: &Path, size_bytes: u64, exe: &str, opened: io::Result<()>) -> u8 {
    match opened {
        Ok(()) => {
            println!("Diagnostic archive written.");
            println!("  path:  {}", path.display());
            println!("  size:  {size_bytes} bytes");
            exit::SUCCESS
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("The service wrote the archive, but this account cannot read it.");
            eprintln!("  path:  {}", path.display());
            eprintln!("Open a console as administrator and run: {exe} diag export");
            exit::NEEDS_PRIVILEGE
        }
        Err(err) => {
            eprintln!("The service wrote the archive, but it cannot be opened: {err}");
            eprintln!("  path:  {}", path.display());
            exit::FAILED
        }
    }
}

fn report_failure(err: IpcClientError, exe: &str) -> u8 {
    match err {
        IpcClientError::ServerError { code, message, .. } => {
            eprintln!("The service refused the export: {message}");
            // A refusal by code is the service's own judgement; the console
            // reports it rather than reinterpreting it.
            eprintln!("  code: {code:?}");
            exit::FAILED
        }
        IpcClientError::Timeout => {
            eprintln!("The service did not finish the export in time.");
            eprintln!("It may still be writing; check the archives directory before retrying.");
            exit::NOT_RESPONDING
        }
        other => {
            eprintln!("Could not reach the service: {other:?}");
            eprintln!("Check that it is running: {exe} status");
            exit::NOT_RESPONDING
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE: &str = "archives/nrr-diag.zip";

    #[test]
    fn an_archive_this_account_can_open_is_reported_written() {
        assert_eq!(
            report_handoff(Path::new(ARCHIVE), 10, "nrr-cli", Ok(())),
            exit::SUCCESS
        );
    }

    /// The hand-off grant is best-effort; when it did not land, "written" would
    /// send the user to a file they get Access Denied on.
    #[test]
    fn an_archive_this_account_cannot_read_needs_privilege() {
        let denied = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert_eq!(
            report_handoff(Path::new(ARCHIVE), 10, "nrr-cli", denied),
            exit::NEEDS_PRIVILEGE
        );
    }

    #[test]
    fn an_archive_gone_missing_is_a_failure_not_a_privilege_problem() {
        let missing = Err(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(
            report_handoff(Path::new(ARCHIVE), 10, "nrr-cli", missing),
            exit::FAILED
        );
    }

    /// The real open, end to end: a file that exists is read, one that does
    /// not is never reported as written.
    #[test]
    fn the_report_rests_on_an_actual_open() {
        let dir = std::env::temp_dir().join(format!("nrr-cli-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let archive = dir.join("archive.zip");
        std::fs::write(&archive, b"zip").expect("write archive");
        let payload = |path: &Path| {
            serde_json::to_value(DiagnosticsExportArchiveResponse {
                archive_path: path.to_string_lossy().into_owned(),
                size_bytes: 3,
                generated_at_ms: 0,
                logs_from_ms_effective: None,
            })
            .expect("payload")
        };
        assert_eq!(report_archive(&payload(&archive), "nrr-cli"), exit::SUCCESS);
        assert_ne!(
            report_archive(&payload(&dir.join("absent.zip")), "nrr-cli"),
            exit::SUCCESS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
