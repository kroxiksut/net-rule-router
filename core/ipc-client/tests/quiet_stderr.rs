//! `silence_diagnostics` is only as good as the one path every stderr line of
//! the client takes: a bare `eprintln!` in either OS's client writes into a
//! full-screen interface that asked for quiet.
#![allow(clippy::expect_used)]

use std::path::Path;

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_client_stderr_line_goes_through_the_quiet_switch() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(
        files.iter().any(|p| p.ends_with("client_unix/frames.rs")),
        "positive control: the Unix client is scanned"
    );

    let mut bare = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read source");
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            // The macro's own body is the one sanctioned call.
            if code.starts_with("eprintln!($($arg)*)") {
                continue;
            }
            if code.contains("eprintln!(") || code.contains("println!(") {
                bare.push(format!("{}:{}", file.display(), n + 1));
            }
        }
    }
    assert!(
        bare.is_empty(),
        "stderr/stdout written past `client_trace!`: {bare:?}"
    );
}
