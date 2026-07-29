param(
    [ValidateSet('dev', 'release')]
    [string]$Profile = 'dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = if ($env:NRR_RUST_TARGET) { $env:NRR_RUST_TARGET } else { 'x86_64-pc-windows-msvc' }

$args = @('build', '--workspace', '--target', $target)
if ($Profile -eq 'release') {
    $args += '--release'
}

Write-Host "[build] cargo $($args -join ' ')" -ForegroundColor Cyan
& cargo @args
if ($LASTEXITCODE -ne 0) {
    throw 'Build failed.'
}

Write-Host '[build] completed successfully' -ForegroundColor Green
