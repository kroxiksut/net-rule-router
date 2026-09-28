//! `diag export` — ask the service for a diagnostic archive.
//!
//! The console does not build the archive. It asks the service to, and prints
//! where the service put it. That is the whole design: the application already
//! has this button, and two assemblers of the same archive would drift until the
//! file a user attaches to a report depends on which surface produced it.
//!
//! Consequently it needs a running service, and says so plainly rather than
//! degrading into a locally-assembled approximation.

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
        Ok(payload) => report_archive(&payload),
        Err(err) => report_failure(err, exe),
    }
}

fn report_archive(payload: &serde_json::Value) -> u8 {
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
    println!("Diagnostic archive written.");
    println!("  path:  {}", response.archive_path);
    println!("  size:  {} bytes", response.size_bytes);
    exit::SUCCESS
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
