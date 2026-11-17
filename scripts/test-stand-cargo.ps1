param(
    [Parameter(Mandatory = $true)] [string]$Root,
    [Parameter(ValueFromRemainingArguments = $true)] [string[]]$CargoArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $CargoArgs -or $CargoArgs.Count -eq 0) { throw 'Supply Cargo arguments after -Root.' }
if (-not [IO.Path]::IsPathRooted($Root)) { throw 'The stand root must be an absolute path.' }
$rootItem = Get-Item -LiteralPath $Root -Force
if (-not $rootItem.PSIsContainer) { throw 'Create a dedicated stand directory first.' }
$rootPath = $rootItem.FullName.TrimEnd('\')
$volume = [IO.Path]::GetPathRoot($rootPath)
if ($volume -notmatch '^[A-Za-z]:\\$' -or $volume -ieq 'C:\') {
    throw 'Use a dedicated local stand directory on a non-C drive.'
}
$item = $rootItem
while ($null -ne $item) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point in stand path: $($item.FullName)" }
    $item = $item.Parent
}
if ($env:RUSTC_WRAPPER -or $env:RUSTC_WORKSPACE_WRAPPER -or @(Get-ChildItem Env:SCCACHE_* -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'Unset Rust wrappers and SCCACHE_* before starting the isolated stand.'
}
$cargo = (Get-Command cargo -ErrorAction Stop).Source
$sccache = (Get-Command sccache -ErrorAction Stop).Source
if ((Get-PSDrive -Name C).Free -lt 8GB) { throw 'C: requires at least 8 GiB free before the run.' }
$standDrive = Get-PSDrive -Name ($volume.Substring(0, 1))
if ($standDrive.Free -lt 15GB) { throw 'The stand volume needs at least 15 GiB free before the run.' }
$target = Join-Path $rootPath 'target'
$cache = Join-Path $rootPath 'cache'
foreach ($path in @($target, $cache)) {
    if (Test-Path -LiteralPath $path) {
        $existing = Get-Item -LiteralPath $path -Force
        if (-not $existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Invalid stand path: $path" }
    } else {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}
$lockPath = Join-Path $rootPath '.nrr-stand.lock'
if (Test-Path -LiteralPath $lockPath) {
    $lockItem = Get-Item -LiteralPath $lockPath -Force
    if ($lockItem.PSIsContainer -or ($lockItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid stand lock path.' }
}
$lockHandle = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
$config = Join-Path $rootPath 'sccache-empty.toml'
if (Test-Path -LiteralPath $config) {
    $file = Get-Item -LiteralPath $config -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne 0) { throw 'The stand configuration must be an empty regular file.' }
} else { [IO.File]::WriteAllBytes($config, [byte[]]@()) }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
try { $port = $listener.LocalEndpoint.Port } finally { $listener.Stop() }
$names = @('CARGO_TARGET_DIR', 'CARGO_INCREMENTAL', 'RUSTC_WRAPPER', 'SCCACHE_DIR', 'SCCACHE_CACHE_SIZE', 'SCCACHE_CONF', 'SCCACHE_SERVER_PORT', 'SCCACHE_IDLE_TIMEOUT', 'SCCACHE_START_SERVER', 'SCCACHE_NO_DAEMON')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
function ConvertTo-NativeArgument([string]$Value) {
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
$status = 1
$serverProcess = $null
$process = $null
$reserveThreatened = $false
try {
    $env:CARGO_TARGET_DIR = $target
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTC_WRAPPER = $sccache
    $env:SCCACHE_DIR = $cache
    $env:SCCACHE_CACHE_SIZE = '10G'
    $env:SCCACHE_CONF = $config
    $env:SCCACHE_SERVER_PORT = [string]$port
    $env:SCCACHE_IDLE_TIMEOUT = '0'
    $env:SCCACHE_START_SERVER = '1'
    $env:SCCACHE_NO_DAEMON = '1'
    $ErrorActionPreference = 'Continue'
    $serverProcess = Start-Process -FilePath $sccache -WindowStyle Hidden -PassThru
    Remove-Item Env:SCCACHE_START_SERVER, Env:SCCACHE_NO_DAEMON
    $ownsPort = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($serverProcess.HasExited) { throw 'The dedicated sccache server exited during startup.' }
        $listenerOwner = Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort $port -ErrorAction SilentlyContinue
        if ($listenerOwner -and $listenerOwner.OwningProcess -eq $serverProcess.Id) { $ownsPort = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ownsPort) { throw 'Could not verify ownership of the dedicated sccache server port.' }
    Write-Host "[stand] target=$target cache=$cache (max 10G)"
    $commandLine = ($CargoArgs | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    $process = Start-Process -FilePath $cargo -ArgumentList $commandLine -NoNewWindow -PassThru
    # Retain the process handle before a short-lived Cargo command exits.
    $null = $process.Handle
    while (-not $process.WaitForExit(1000)) {
        if ($serverProcess.HasExited) { throw 'The dedicated sccache server stopped during the build.' }
        if ((Get-PSDrive -Name C).Free -lt 7GB -or (Get-PSDrive -Name ($volume.Substring(0, 1))).Free -lt 7GB) {
            Write-Warning 'Disk reserve threatened; stopping this build and its child processes.'
            $reserveThreatened = $true
            & taskkill.exe /PID $process.Id /T /F
            $process.WaitForExit()
            break
        }
    }
    $process.WaitForExit()
    $process.Refresh()
    if ($null -eq $process.ExitCode) { throw 'Cargo exited without an observable exit code.' }
    $status = if ($reserveThreatened) { 1 } else { $process.ExitCode }
    & $sccache --show-stats
} finally {
    if ($null -ne $process -and -not $process.HasExited) { & taskkill.exe /PID $process.Id /T /F }
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) { $serverProcess.Kill(); $serverProcess.WaitForExit() }
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    $lockHandle.Dispose()
}
exit $status
