//! `nrr-docs-html --out <folder> [--repo <checkout>]`: writes the offline
//! documentation of the checkout (default: the current folder) into a folder
//! that is absent or empty. Exit 1 on a link that reaches nothing.

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: nrr-docs-html --out <folder> [--repo <checkout>]";

fn main() -> ExitCode {
    let mut out = None;
    let mut repo = PathBuf::from(".");
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next().map(PathBuf::from);
        match (arg.to_str(), value) {
            (Some("--out"), Some(value)) => out = Some(value),
            (Some("--repo"), Some(value)) => repo = value,
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(out) = out else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let project_url = nrr_shared::gui_shell_v1().about.project_url;
    match nrr_docs_html::build(&repo, &out, project_url) {
        Ok(built) => {
            println!(
                "nrr-docs-html: {} pages, {} images -> {}",
                built.pages,
                built.images,
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("nrr-docs-html: {error}");
            ExitCode::FAILURE
        }
    }
}
