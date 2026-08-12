param(
    [ValidateSet('dev', 'release')]
    [string]$Profile = 'dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1')

# No default --target: an explicit triplet sends artifacts to
# target\<triplet>\<profile>\, which install-service.ps1 / run.ps1 don't look
# in and forces a from-scratch build tree. Host-triple default keeps
# everything under target\<profile>\.
$args = @('build', '--workspace')
if ($env:NRR_RUST_TARGET) {
    $args += @('--target', $env:NRR_RUST_TARGET)
}
if ($Profile -eq 'release') {
    $args += '--release'
}

Write-Host "[build] cargo $($args -join ' ')" -ForegroundColor Cyan
& cargo @args
if ($LASTEXITCODE -ne 0) {
    throw 'Build failed.'
}

Write-Host '[build] completed successfully' -ForegroundColor Green
