#![cfg(windows)]
#![allow(clippy::expect_used)]

//! The installers' licence pages are RichEdit controls, and RichEdit breaks a
//! line before the `@` of an e-mail address: the agreement then shows the
//! contact address cut in two. The Inno Setup page uses RichEdit 4.1, the MSI
//! page RichEdit 2.0, and they wrap differently, so the agreement goes through
//! the package script's own converter and into both, across the widths a
//! wizard can have.

use std::path::{Path, PathBuf};
use std::process::Command;

const PROBE: &str = r#"
param([string] $Converter, [string] $Repo, [string] $Out)
$ErrorActionPreference = 'Stop'
. $Converter
Add-Type -AssemblyName System.Windows.Forms
Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Windows.Forms;
public class RichEdit41 : RichTextBox {
    [DllImport("kernel32", CharSet = CharSet.Unicode)] static extern IntPtr LoadLibrary(string name);
    protected override CreateParams CreateParams {
        get { LoadLibrary("msftedit.dll"); var p = base.CreateParams; p.ClassName = "RICHEDIT50W"; return p; }
    }
}
'@
$checked = 0
foreach ($lang in 'en', 'ru') {
    foreach ($exe in $false, $true) {
        $rtf = Join-Path $Out "eula.$lang.$exe.rtf"
        $options = @{}
        if ($exe) { $options.LinkFields = $true }
        ConvertFrom-AgreementMarkdown -Source (Join-Path $Repo "docs\legal\eula.$lang.md") -Destination $rtf @options
        $body = [IO.File]::ReadAllText($rtf)
        for ($width = 300; $width -le 640; $width += 3) {
            $box = if ($exe) { New-Object RichEdit41 } else { New-Object System.Windows.Forms.RichTextBox }
            $box.Width = $width; $box.Height = 600
            $null = $box.Handle
            $box.Rtf = $body
            foreach ($m in [regex]::Matches($box.Text, '[\w.﻿-]+@[\w.﻿-]*\w')) {
                $checked++
                if ($box.GetLineFromCharIndex($m.Index) -ne $box.GetLineFromCharIndex($m.Index + $m.Length - 1)) {
                    "SPLIT $lang $(if ($exe) { 'exe' } else { 'msi' }) width $width : $($m.Value.Replace([string][char]0xFEFF, ''))"
                }
            }
            $box.Dispose()
        }
    }
}
"CHECKED $checked"
"#;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The package script's agreement converter, cut out so the probe runs
/// exactly what the installers are built with.
fn converter() -> String {
    let script = std::fs::read_to_string(repo().join("scripts/package-windows.ps1"))
        .expect("the package script");
    let start = script
        .find("function ConvertTo-RtfText")
        .expect("the RTF text escaper");
    let end = script[start..]
        .find("# The wizards' pictures")
        .expect("the end of the agreement converter");
    script[start..start + end].to_owned()
}

#[test]
fn the_contact_address_stays_on_one_line_on_both_licence_pages() {
    let out = std::env::temp_dir().join(format!("nrr-licence-wrap-{}", std::process::id()));
    std::fs::create_dir_all(&out).expect("a scratch folder");
    let converter_path = out.join("converter.ps1");
    let probe_path = out.join("probe.ps1");
    // PowerShell 5.1 reads a BOM-less script as ANSI.
    std::fs::write(&converter_path, format!("\u{feff}{}", converter())).expect("the converter");
    std::fs::write(&probe_path, format!("\u{feff}{PROBE}")).expect("the probe");

    let run = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&probe_path)
        .arg("-Converter")
        .arg(&converter_path)
        .arg("-Repo")
        .arg(repo())
        .arg("-Out")
        .arg(&out)
        .output()
        .expect("Windows PowerShell");
    let _ = std::fs::remove_dir_all(&out);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "the probe failed:\n{stdout}\n{stderr}"
    );

    let splits: Vec<&str> = stdout.lines().filter(|l| l.starts_with("SPLIT")).collect();
    assert!(
        splits.is_empty(),
        "an address is cut in two:\n{}",
        splits.join("\n")
    );
    let checked = stdout
        .lines()
        .find_map(|l| l.strip_prefix("CHECKED "))
        .and_then(|n| n.trim().parse::<u32>().ok())
        .expect("the probe's count");
    assert!(
        checked > 0,
        "the agreement shows no e-mail address:\n{stdout}"
    );
}
