#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a self-contained portable folder of NetRuleRouter for Windows.

.DESCRIPTION
    Produces a tree that runs on a clean machine with no Qt, no Rust and no
    repository present: copy the folder anywhere and start it.

    Layout, and why it is shaped this way:

        NetRuleRouter\
          NetRuleRouter.exe     start here
          README.txt  README.ru.txt
          <tray, service, console, terminal interface, Qt host, the Qt runtime, wintun.dll>
          <*.pdb>               line tables, so a panic names file:line
          qml\                  Qt's own modules, written by windeployqt
          apps\desktop\qml\     the app's own QML
          locales\  presets\  configs\  assets\
          scripts\              recovery and uninstall scripts

    Two QML trees under one name would collide, which is why the app's own tree
    keeps the `apps\desktop\qml` path it has in the checkout. That depth is
    load bearing anyway: the QML addresses its icons relative to itself.

    Every package carries build-info.json - version, commit, whether the tree
    had uncommitted changes, build time, Qt version - so a report about a
    specific copy can be tied back to the code that produced it.

.PARAMETER OutputRoot
    Where the package folder is created. The package itself is always
    <OutputRoot>\NetRuleRouter.

.PARAMETER SkipBuild
    Package the release binaries already in the target directory.

.PARAMETER Arch
    The processor the package is for: x64 (default) or arm64. arm64 builds the
    aarch64-pc-windows-msvc target, on an ARM64 machine or across from x64, and
    takes the Qt kit, the Visual C++ runtime and wintun.dll of that processor.
    Every artifact name carries it.

.PARAMETER QtBin
    Qt's bin directory of the kit for -Arch. When omitted, the kit the Qt host
    was built with is used; the newest kit of that processor under C:\Qt
    (msvc2022_64 or msvc2022_arm64) is the fallback. A kit that differs from
    the host's is refused. A cross-compiled ARM64 kit carries no windeployqt.exe
    of its own: the one from the x64 kit named by QT_HOST_PATH deploys it.

.PARAMETER Full
    Deploy the complete Qt runtime. The default trims the pieces this app never
    loads (Qt's own translations, the software OpenGL rasterizer, the legacy
    D3D shader compiler) and the Qt Quick styles the app never selects, saving
    roughly 37 MB in total.

.PARAMETER Zip
    Also produce NetRuleRouter-windows-<arch>-<version>+<commit>.zip next to
    the folder, for carrying the build on a flash drive.

.PARAMETER Installers
    Also build both installers from the package: the EXE (Inno Setup 6) and the
    MSI (WiX Toolset 5), next to the folder, plus a SHA256 checksum file that
    covers every artifact of this run, the archive included.

.PARAMETER Exe
    Build the EXE installer only (same output as -Installers otherwise).

.PARAMETER Msi
    Build the MSI only (same output as -Installers otherwise).

.PARAMETER Headless
    Package without the window and the tray: the service, the console and the
    terminal interface, for servers and Windows without a desktop session. The
    folder is <OutputRoot>\NetRuleRouter-headless and every artifact name ends
    in -headless.

.PARAMETER Force
    Replace an existing package folder.
#>
param(
    [string]$OutputRoot = 'C:\temp\NetRuleRouter\dist',
    [switch]$SkipBuild,
    [string]$QtBin,
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    [switch]$Full,
    [switch]$Zip,
    [switch]$Installers,
    [switch]$Exe,
    [switch]$Msi,
    [switch]$Headless,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'lib\package-contents.ps1')
$packageRoot = Join-Path $OutputRoot $(if ($Headless) { 'NetRuleRouter-headless' } else { 'NetRuleRouter' })
# Binaries live in the package root: the user starts NetRuleRouter.exe
# directly, with no wrapper script in between. Nothing collides there -
# windeployqt owns `qml\` for its modules while the app's own QML sits
# under `apps\desktop\qml\`, which is also the depth its icon paths expect.
$binDir = $packageRoot
$Arch = $Arch.ToLowerInvariant()
# Kit, CRT, wintun and archive name all follow -Arch. An ARM64 package builds
# natively or across from x64; an x64 one only on x64, the one pairing checked.
$hostArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$targetByArch = @{
    x64   = @{ Hosts = @('AMD64'); Wintun = 'amd64'; Crt = 'x64'; QtKit = 'msvc2022_64'; RustTarget = $null }
    arm64 = @{ Hosts = @('ARM64', 'AMD64'); Wintun = 'arm64'; Crt = 'arm64'; QtKit = 'msvc2022_arm64'; RustTarget = 'aarch64-pc-windows-msvc' }
}
$archSpec = $targetByArch[$Arch]
if ($archSpec.Hosts -notcontains $hostArch) {
    throw "A $Arch package is built on $($archSpec.Hosts -join ' or ') Windows (this machine reports '$hostArch'): the Qt kit, the Visual C++ runtime and wintun.dll would not match the binaries."
}
$wintunArch = $archSpec.Wintun
# Written into the package so a later run can tell its own output apart from a
# folder the user picked by mistake, and refuse to delete the latter.
$markerName = '.nrr-package'

function Write-Step {
    param([string]$Message)
    Write-Host "[package] $Message" -ForegroundColor Cyan
}

# Windows PowerShell 5.1 turns a native command's stderr into a terminating
# error under `Stop`, so a cargo warning or git's "not a repository" would kill
# the run. Native calls go through here: stderr dropped, success judged by the
# exit code alone. Returns stdout lines, or $null when the tool failed or is absent.
function Invoke-Native {
    param([string]$Tool, [string[]]$Arguments)

    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
        return $null
    }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Tool @Arguments 2>$null
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($exitCode -ne 0) {
        return $null
    }
    return , @($output)
}

function Resolve-CargoMetadata {
    $lines = Invoke-Native 'cargo' @('metadata', '--format-version', '1', '--no-deps')
    $metadata = if ($lines) { ($lines -join "`n") | ConvertFrom-Json } else { $null }
    if (-not $metadata) {
        throw 'cargo metadata failed - run this from a checkout with cargo on PATH.'
    }
    return $metadata
}

function Resolve-ProductVersion {
    param($Metadata)

    # The launcher produces the executable the user starts, so its version is
    # the product version.
    $launcher = $Metadata.packages | Where-Object { $_.name -eq 'nrr-launcher' } | Select-Object -First 1
    if (-not $launcher) {
        throw 'nrr-launcher not found in cargo metadata.'
    }
    return $launcher.version
}

function Resolve-SourceRevision {
    # A package built outside a checkout is legitimate (an exported tree), so a
    # missing revision is recorded as unknown rather than failing the build.
    $revision = [ordered]@{
        commit      = 'unknown'
        commit_date = 'unknown'
        dirty       = $null
    }
    $commit = Invoke-Native 'git' @('-C', $repoRoot, 'rev-parse', '--short', 'HEAD')
    if (-not $commit) {
        return $revision
    }
    $revision.commit = ($commit -join '').Trim()
    $commitDate = Invoke-Native 'git' @('-C', $repoRoot, 'log', '-1', '--format=%cI')
    if ($commitDate) {
        $revision.commit_date = ($commitDate -join '').Trim()
    }
    # Uncommitted work is the norm here, and a package built from it must say
    # so: otherwise a bug report names a commit that never held this code.
    $status = Invoke-Native 'git' @('-C', $repoRoot, 'status', '--porcelain')
    $revision.dirty = [bool]$status
    return $revision
}

# The kit the Qt host was linked against, read from its CMake cache. Packaging
# any other kit ships a runtime that does not match the host binary.
function Resolve-HostQtKit {
    param([string]$HostExe)

    $dir = Split-Path -Parent $HostExe
    for ($depth = 0; $depth -lt 4 -and $dir; $depth++) {
        $cache = Join-Path $dir 'CMakeCache.txt'
        if (Test-Path -LiteralPath $cache) {
            $line = Select-String -LiteralPath $cache -Pattern '^Qt6_DIR:PATH=(.+)$' | Select-Object -First 1
            if ($line) {
                # <kit>/lib/cmake/Qt6
                $cmakeDir = $line.Matches[0].Groups[1].Value
                return [System.IO.Path]::GetFullPath((Join-Path $cmakeDir '..\..\..'))
            }
            return $null
        }
        $dir = Split-Path -Parent $dir
    }
    return $null
}

# windeployqt for the kit in KitBin: its own, or, for a cross-compiled kit that
# has none, the build machine's (QT_HOST_PATH) pointed at the kit's qtpaths.
function Find-DeployTool {
    param([string]$KitBin)

    $native = Join-Path $KitBin 'windeployqt.exe'
    if (Test-Path -LiteralPath $native) {
        return @{ Path = $native; Arguments = @() }
    }
    if (-not $env:QT_HOST_PATH) {
        return $null
    }
    $hostTool = Join-Path $env:QT_HOST_PATH 'bin\windeployqt.exe'
    $qtpaths = @('qtpaths.bat', 'qtpaths6.bat') |
        ForEach-Object { Join-Path $KitBin $_ } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if (-not $qtpaths -or -not (Test-Path -LiteralPath $hostTool)) {
        return $null
    }
    return @{ Path = $hostTool; Arguments = @('--qtpaths', $qtpaths) }
}

function Resolve-WindeployQt {
    param([string]$Explicit, [string]$HostKit, [string]$KitName)

    if ($Explicit) {
        $tool = Find-DeployTool -KitBin $Explicit
        if (-not $tool) {
            throw "windeployqt.exe not found in -QtBin '$Explicit'."
        }
        $explicitBin = [System.IO.Path]::GetFullPath($Explicit).TrimEnd('\')
        if ($HostKit -and $explicitBin -ne (Join-Path $HostKit 'bin')) {
            throw "-QtBin '$Explicit' is not the kit the Qt host was built with ('$HostKit'). Deploying another Qt beside this host breaks it at start-up."
        }
        return $tool
    }

    if ($HostKit) {
        $tool = Find-DeployTool -KitBin (Join-Path $HostKit 'bin')
        if ($tool) {
            return $tool
        }
    }

    # No cache to read: pick the newest desktop kit of this processor by
    # version number, the same rule the host's build script applies. String
    # order would put 6.9 before 6.11.
    $kits = Get-ChildItem -Path 'C:\Qt' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Find-DeployTool -KitBin (Join-Path $_.FullName "$KitName\bin") } |
        Where-Object { $_ }
    if (-not $kits) {
        throw "No $Arch windeployqt.exe found under C:\Qt\<version>\$KitName\bin. Pass -QtBin <path to Qt bin>."
    }
    return @($kits)[0]
}

function Resolve-NativeHost {
    param([string]$ReleaseDir)

    # The C++ host is a build-script artifact, so it lives under a hash-named
    # directory. Several can survive across rebuilds; the newest one that
    # actually holds the exe is the one this release produced.
    $hostExe = Get-ChildItem -Path (Join-Path $ReleaseDir 'build') -Filter 'nrr_qt_native_host.exe' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $hostExe) {
        throw "nrr_qt_native_host.exe not found under '$ReleaseDir\build'. Build without -SkipBuild first."
    }
    return $hostExe.FullName
}

# Scripts a user of the package can run. Anything else under scripts\ (build,
# check, dev tooling) needs a checkout and stays out; scripts\dev never ships.
$userScripts = @(
    'reset-network.ps1',
    'service-status.ps1',
    'uninstall-service.ps1',
    'purge-data.ps1',
    'lib\service-paths.ps1'
)

function Copy-UserScripts {
    param([string]$Destination)

    foreach ($script in $userScripts) {
        $source = Join-Path $repoRoot "scripts\$script"
        if (-not (Test-Path -LiteralPath $source)) {
            throw "User script 'scripts\$script' is missing from the checkout."
        }
        $target = Join-Path $Destination $script
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $target -Force
    }
}

function Copy-Payload {
    param([string]$RelativeSource, [string]$Destination)

    $source = Join-Path $repoRoot $RelativeSource
    if (-not (Test-Path $source)) {
        throw "Payload '$RelativeSource' is missing from the checkout."
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    Copy-Item -Path $source -Destination $Destination -Recurse -Force
}

# ── Installer tools ──────────────────────────────────────────────────────────

# WiX 6 and later carry a maintenance-fee licence, so the MSI is pinned to 5.
$wixVersion = '5.0.2'
$wixExtensions = @('WixToolset.Util.wixext', 'WixToolset.UI.wixext')

# The version floor is checked by the .iss itself: ISCC.exe carries no file version.
function Resolve-InnoCompiler {
    $onPath = Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $candidates = @(
        $(if ($onPath) { $onPath.Source }),
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe' }),
        $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe' }),
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe' })
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if (-not $candidates) {
        throw 'Inno Setup 6 (ISCC.exe) not found on PATH or in its default install folders. Install Inno Setup 6.3 or newer from https://jrsoftware.org/isdl.php.'
    }
    return @($candidates)[0]
}

function Resolve-WixTool {
    $onPath = Get-Command 'wix.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $wix = if ($onPath) { $onPath.Source }
           elseif ($env:USERPROFILE -and (Test-Path -LiteralPath (Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'))) { Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe' }
           else { $null }
    if (-not $wix) {
        throw "WiX Toolset not found. Install it as a .NET tool: dotnet tool install --global wix --version $wixVersion"
    }
    $reported = Invoke-Native $wix @('--version')
    $reported = if ($reported) { ($reported -join '').Trim() } else { 'an unknown version' }
    if ($reported -notmatch "^$([regex]::Escape($wixVersion))(\+|$)") {
        throw "WiX $reported found at '$wix'; the MSI is built with WiX $wixVersion only: dotnet tool update --global wix --version $wixVersion"
    }
    $installed = Invoke-Native $wix @('extension', 'list', '-g')
    foreach ($extension in $wixExtensions) {
        $pattern = "^\s*$([regex]::Escape($extension))\s+$([regex]::Escape($wixVersion))\b"
        if (-not ($installed | Where-Object { $_ -match $pattern })) {
            throw "WiX extension $extension $wixVersion is missing: wix extension add -g $extension/$wixVersion"
        }
    }
    return $wix
}

# The MSI's licence page reads RTF; each line of the plain text becomes a paragraph.
function ConvertTo-RtfFile {
    param([string] $Source, [string] $Destination)

    $rtf = New-Object System.Text.StringBuilder
    [void]$rtf.Append('{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\fs16 ')
    foreach ($line in [System.IO.File]::ReadAllLines($Source)) {
        foreach ($ch in $line.ToCharArray()) {
            $code = [int]$ch
            if ($ch -eq [char]'\' -or $ch -eq [char]'{' -or $ch -eq [char]'}') { [void]$rtf.Append('\').Append($ch) }
            elseif ($code -gt 127) { [void]$rtf.Append("\u$(if ($code -gt 32767) { $code - 65536 } else { $code })?") }
            else { [void]$rtf.Append($ch) }
        }
        [void]$rtf.Append("\par`r`n")
    }
    [void]$rtf.Append('}')
    [System.IO.File]::WriteAllText($Destination, $rtf.ToString(), [System.Text.Encoding]::ASCII)
}

# Resolved before the build, so a missing tool fails in seconds, not after it.
$buildExe = $Installers -or $Exe
$buildMsi = $Installers -or $Msi
$iscc = if ($buildExe) { Resolve-InnoCompiler } else { $null }
$wix = if ($buildMsi) { Resolve-WixTool } else { $null }

# ── Output folder ────────────────────────────────────────────────────────────

if (Test-Path $packageRoot) {
    $isOurs = Test-Path (Join-Path $packageRoot $markerName)
    if (-not $Force) {
        throw "'$packageRoot' already exists. Re-run with -Force to replace it."
    }
    if (-not $isOurs) {
        throw "'$packageRoot' exists but was not produced by this script (no $markerName marker). Delete it yourself if that is really the folder you meant."
    }
    Write-Step "replacing the previous package in '$packageRoot'"
    Remove-Item -Path $packageRoot -Recurse -Force
}

# Read before the build, so a broken list fails in seconds.
$required = Get-PackageContents -RepoRoot $repoRoot -Variant $(if ($Headless) { 'headless' } else { 'full' })

# ── Build ────────────────────────────────────────────────────────────────────

$metadata = Resolve-CargoMetadata
$targetDir = $metadata.target_directory
# x64 is the host triple and builds without --target; arm64 always names its
# triple, so a native and a cross build land in the same place.
$cargoTarget = @()
$releaseDir = Join-Path $targetDir 'release'
if ($archSpec.RustTarget) {
    $cargoTarget = @('--target', $archSpec.RustTarget)
    $releaseDir = Join-Path $targetDir "$($archSpec.RustTarget)\release"
}
$productVersion = Resolve-ProductVersion -Metadata $metadata
$revision = Resolve-SourceRevision
$buildStamp = "$productVersion+$($revision.commit)" + $(if ($revision.dirty) { '-dirty' } else { '' })
Write-Step "version $productVersion, revision $($revision.commit)$(if ($revision.dirty) { ' (uncommitted changes)' })"

if (-not $SkipBuild) {
    if ($archSpec.RustTarget) {
        $installedTargets = Invoke-Native 'rustup' @('target', 'list', '--installed')
        if ($installedTargets -and ($installedTargets -notcontains $archSpec.RustTarget)) {
            throw "Rust target $($archSpec.RustTarget) is not installed: rustup target add $($archSpec.RustTarget)"
        }
        # ring (under rustls) assembles its ARM64 code with clang, not cl.exe.
        if (-not (Get-Command 'clang.exe' -ErrorAction SilentlyContinue)) {
            $clangDir = @(
                $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'LLVM\bin' }),
                @(Get-ChildItem -Path 'C:\Program Files\Microsoft Visual Studio' -Directory -Filter 'Llvm' -Recurse -Depth 6 -ErrorAction SilentlyContinue |
                    ForEach-Object { Join-Path $_.FullName $(if ($hostArch -eq 'ARM64') { 'ARM64\bin' } else { 'x64\bin' }) })
            ) | Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $_ 'clang.exe')) } | Select-Object -First 1
            if (-not $clangDir) {
                throw 'clang.exe not found. An arm64 build needs it: install LLVM, or the "C++ Clang tools for Windows" component of Visual Studio.'
            }
            $env:PATH = "$clangDir;$env:PATH"
            Write-Step "using clang from '$clangDir'"
        }
        # A prefix left pointing at another processor's kit links the host
        # against the wrong Qt, and only fails deep inside the C++ build.
        if (-not $Headless -and $env:CMAKE_PREFIX_PATH -and $env:CMAKE_PREFIX_PATH -notmatch [regex]::Escape($archSpec.QtKit)) {
            throw "CMAKE_PREFIX_PATH '$env:CMAKE_PREFIX_PATH' does not name a $($archSpec.QtKit) kit. Point it at the $Arch Qt, or clear it to use the newest under C:\Qt."
        }
    }
    & (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1')
    $targetNote = if ($archSpec.RustTarget) { " --target $($archSpec.RustTarget)" } else { '' }
    if ($Headless) {
        Write-Step "cargo build --release --locked$targetNote (service, console, terminal interface)"
        & cargo build --release --locked @cargoTarget -p nrr-windows-service -p nrr-cli -p nrr-tui
    } else {
        Write-Step "cargo build --release --locked$targetNote (launcher, service, console, terminal interface)"
        & cargo build --release --locked @cargoTarget -p nrr-launcher -p nrr-windows-service -p nrr-cli -p nrr-tui
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'Release build failed. A running service or open GUI holds its own binary - stop it and retry; or Cargo.lock is out of date (the build runs --locked) - update it in the checkout first.'
    }
} else {
    Write-Step 'skipping the build, packaging what is already in the target directory'
}

# ── Executables ──────────────────────────────────────────────────────────────

New-Item -ItemType Directory -Path $binDir -Force | Out-Null
# Stamped before anything is copied: a run that dies halfway still leaves a
# folder this script recognises as its own, so -Force can clean it up.
Set-Content -Path (Join-Path $packageRoot $markerName) -Value 'Produced by scripts/package-windows.ps1' -Encoding ASCII

$executables = @('nrr-service.exe', 'nrr-cli.exe', 'nrr-tui.exe')
if (-not $Headless) {
    $executables = @('NetRuleRouter.exe', 'NetRuleRouterTray.exe') + $executables
}
foreach ($binaryName in $executables) {
    $source = Join-Path $releaseDir $binaryName
    if (-not (Test-Path $source)) {
        throw "'$binaryName' is missing from '$releaseDir'. Run without -SkipBuild."
    }
    Copy-Item -Path $source -Destination $binDir -Force
    # Line tables for the panic message; the backtrace looks beside the exe.
    # Cargo names the PDB after the crate-style name: `nrr-cli` -> `nrr_cli.pdb`.
    $pdb = Join-Path $releaseDir (([IO.Path]::GetFileNameWithoutExtension($binaryName) -replace '-', '_') + '.pdb')
    if (-not (Test-Path $pdb)) {
        throw "'$(Split-Path $pdb -Leaf)' is missing from '$releaseDir'. Run without -SkipBuild."
    }
    Copy-Item -Path $pdb -Destination $binDir -Force
}
Write-Step "copied $($executables.Count) executables with their symbols"

if (-not $Headless) {
    $nativeHost = Resolve-NativeHost -ReleaseDir $releaseDir
    Copy-Item -Path $nativeHost -Destination $binDir -Force
    Write-Step "copied the Qt host from '$nativeHost'"
}

# Without it fake-IP silently switches itself off, and the failure is invisible
# in the UI - so a missing DLL fails the packaging instead.
$wintun = Join-Path $repoRoot "third_party\wintun\bin\$wintunArch\wintun.dll"
if (-not (Test-Path $wintun)) {
    throw "wintun.dll not found at '$wintun'."
}
Copy-Item -Path $wintun -Destination $binDir -Force
Write-Step 'copied wintun.dll'

# ── Visual C++ runtime ───────────────────────────────────────────────────────

# Both the Rust binaries and the C++ Qt host link the MSVC runtime dynamically,
# and a clean Windows install carries no Visual C++ Redistributable. Windows
# resolves a DLL from the executable's own folder before System32, so shipping
# these beside the binaries removes the dependency for about 1 MB - against an
# install step the user would otherwise have to complete before anything runs.
# Shipping them with an application is what the redistributable licence covers.
$crtNames = @(
    'vcruntime140.dll',
    'vcruntime140_1.dll',
    'msvcp140.dll',
    'msvcp140_1.dll',
    'msvcp140_2.dll',
    'msvcp140_atomic_wait.dll',
    'concrt140.dll'
)
$visualStudioRoots = @(
    'C:\Program Files\Microsoft Visual Studio',
    'C:\Program Files (x86)\Microsoft Visual Studio'
) | Where-Object { Test-Path $_ }
$crtSource = $null
if ($visualStudioRoots) {
    $crtSource = Get-ChildItem -Path $visualStudioRoots -Directory -Filter 'Microsoft.VC*.CRT' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*\$($archSpec.Crt)\*" -and $_.FullName -notlike '*\onecore\*' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
}
if (-not $crtSource) {
    throw "$Arch Visual C++ redistributable DLLs not found on this machine (looked under the Visual Studio install). Install the C++ workload$(if ($Arch -eq 'arm64') { ' with the ARM64 build tools' }), or package on a machine that has it."
}
$crtBytes = 0
foreach ($crt in $crtNames) {
    $candidate = Join-Path $crtSource.FullName $crt
    if (Test-Path -LiteralPath $candidate) {
        Copy-Item -LiteralPath $candidate -Destination $binDir -Force
        $crtBytes += (Get-Item -LiteralPath $candidate).Length
    }
}
Write-Step ("copied the Visual C++ runtime ({0:N1} MB)" -f ($crtBytes / 1MB))

# ── Qt runtime ───────────────────────────────────────────────────────────────

if (-not $Headless) {
    $deployTool = Resolve-WindeployQt -Explicit $QtBin -HostKit (Resolve-HostQtKit -HostExe $nativeHost) -KitName $archSpec.QtKit
    $windeployqt = $deployTool.Path
    $deployArguments = @($deployTool.Arguments) + @(
        '--release',
        '--qmldir', (Join-Path $repoRoot 'apps\desktop\qml')
    )
    if (-not $Full) {
        # Qt's own UI translations (the app ships its own locales), the software
        # OpenGL fallback, and the legacy HLSL compiler. None are loaded here.
        $deployArguments += @('--no-translations', '--no-system-d3d-compiler', '--no-opengl-sw')
    }
    $deployArguments += (Join-Path $binDir 'nrr_qt_native_host.exe')

    Write-Step "deploying the Qt runtime with '$windeployqt'"
    & $windeployqt @deployArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'windeployqt failed.'
    }

    if (-not $Full) {
        # The app pins its style in C++ (`QQuickStyle::setStyle("Fusion")`) and no
        # QML file imports a style module, so every other style tree is dead weight.
        # Basic stays: it is the fallback Qt Quick Controls falls back to for any
        # control a style does not implement. windeployqt has no flag for this.
        $unusedStyles = @('FluentWinUI3', 'Material', 'Imagine', 'Universal', 'Windows')
        $controlsDir = Join-Path $binDir 'qml\QtQuick\Controls'
        $freedBytes = 0
        foreach ($style in $unusedStyles) {
            $styleDir = Join-Path $controlsDir $style
            if (Test-Path $styleDir) {
                $freedBytes += (Get-ChildItem $styleDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
                Remove-Item -Path $styleDir -Recurse -Force
            }
        }
        # Image formats we never decode. The app's own art is SVG (icons), PNG
        # (logo lock-ups) and ICO (window/tray icon): PNG is built into Qt6Gui, ICO
        # and SVG are the two plugins below. Nothing in the QML tree references a
        # JPEG, GIF, TIFF, WebP, TGA, WBMP, ICNS or PDF, so their decoders are dead
        # weight in the payload.
        $keptImageFormats = @('qsvg.dll', 'qico.dll')
        $imageFormatsDir = Join-Path $binDir 'imageformats'
        if (Test-Path $imageFormatsDir) {
            Get-ChildItem $imageFormatsDir -File -Filter '*.dll' | ForEach-Object {
                if ($keptImageFormats -notcontains $_.Name) {
                    $freedBytes += $_.Length
                    Remove-Item -Path $_.FullName -Force
                }
            }
        }
        # Debug/profiling plugins for QML tooling: only a connected debugger loads
        # them, and a shipped build has none.
        $qmlTooling = Join-Path $binDir 'qmltooling'
        if (Test-Path $qmlTooling) {
            $freedBytes += (Get-ChildItem $qmlTooling -Recurse -File | Measure-Object -Property Length -Sum).Sum
            Remove-Item -Path $qmlTooling -Recurse -Force
        }
        Write-Step ("trimmed unused Qt styles, image formats and QML tooling: {0:N1} MB" -f ($freedBytes / 1MB))
    }
}

# ── Payload ──────────────────────────────────────────────────────────────────

# Not `<package>\qml`, despite that being the tidier name: the QML addresses
# icons as `../../../assets/icons/...`, three levels up from Main.qml. Keeping
# the same depth as the checkout is what makes those icons resolve, and the
# launcher looks for exactly this path beside the binary.
Copy-Payload 'locales' (Join-Path $packageRoot 'locales')
Copy-Payload 'presets' (Join-Path $packageRoot 'presets')
Copy-Payload 'configs' (Join-Path $packageRoot 'configs')
Copy-UserScripts (Join-Path $packageRoot 'scripts')
if ($Headless) {
    # The installers take the app icon from the package.
    Copy-Payload 'assets\icons\app' (Join-Path $packageRoot 'assets\icons\app')
    Write-Step 'copied the locales, presets, configs, app icon and user scripts'
} else {
    Copy-Payload 'apps\desktop\qml' (Join-Path $packageRoot 'apps\desktop\qml')
    Copy-Payload 'assets\icons' (Join-Path $packageRoot 'assets\icons')
    # The startup splash paints the logo lockup before the QML engine loads; left out
    # of the package, it silently does not appear.
    Copy-Payload 'assets\images' (Join-Path $packageRoot 'assets\images')
    Write-Step 'copied the QML, locales, presets, configs, icons, images and user scripts'
}

# ── Licence texts ────────────────────────────────────────────────────────────

# Wintun and Qt (LGPLv3) are redistributed as binaries, and both licences ask
# for their text to travel with them. The Qt texts come from the installed Qt's
# own documentation, so they match the version that is shipped.
$licensesDir = Join-Path $packageRoot 'licenses'
New-Item -ItemType Directory -Path $licensesDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $licensesDir 'NetRuleRouter-LICENSE.txt') -Force
Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_LICENSES.md') -Destination $licensesDir -Force
Copy-Item -LiteralPath (Join-Path $repoRoot 'third_party\wintun\LICENSE.txt') -Destination (Join-Path $licensesDir 'Wintun-LICENSE.txt') -Force
if (-not $Headless) {
    if ($windeployqt -notmatch '^(?<root>.*\Qt)\(?<version>\d+\.\d+\.\d+)\') {
        throw "Cannot find the Qt installation root from '$windeployqt' to take the licence texts from."
    }
    $qtDocs = Join-Path $Matches['root'] "Docs\Qt-$($Matches['version'])\qtdoc"
    foreach ($pair in @(@('lgpl.html', 'Qt-LGPL-3.0.html'), @('gpl.html', 'Qt-GPL-3.0.html'))) {
        $text = Join-Path $qtDocs $pair[0]
        if (-not (Test-Path -LiteralPath $text)) {
            throw "Qt licence text '$text' not found; install the Qt documentation component."
        }
        Copy-Item -LiteralPath $text -Destination (Join-Path $licensesDir $pair[1]) -Force
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'third_party\qt\NOTICE.txt') -Destination (Join-Path $licensesDir 'Qt-NOTICE.txt') -Force
}
Write-Step 'copied the licence texts'

# ── Build identity ───────────────────────────────────────────────────────────

# Machine-readable, because a bug report that names a version and a commit is
# worth more than a screenshot, and because whoever checks the package from
# the app later needs a fixed shape to read.
$qtVersion = $(if ($Headless) { 'none' } else { 'unknown' })
if (-not $Headless -and $windeployqt -match '\\Qt\\(?<version>\d+\.\d+\.\d+)\\') {
    $qtVersion = $Matches['version']
}
$buildInfo = [ordered]@{
    product        = 'NetRuleRouter'
    version        = $productVersion
    commit         = $revision.commit
    commit_date    = $revision.commit_date
    # True means the package was built from a working tree with uncommitted
    # changes, so `commit` alone does not identify this code.
    uncommitted    = $revision.dirty
    built_at_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    profile        = 'release'
    platform       = "windows-$Arch"
    variant        = $(if ($Headless) { 'headless' } else { 'full' })
    qt_version     = $qtVersion
    qt_runtime     = $(if ($Headless) { 'none' } elseif ($Full) { 'full' } else { 'trimmed' })
}
$buildInfo | ConvertTo-Json | Set-Content -Path (Join-Path $packageRoot 'build-info.json') -Encoding UTF8
Write-Step "stamped build-info.json ($buildStamp)"

# ── Entry point and notes ────────────────────────────────────────────────────

$readMeEn = @"
NetRuleRouter - portable build for Windows
=========================================

Version $productVersion, revision $($revision.commit)$(if ($revision.dirty) { ' (built with uncommitted changes)' })
Built $($buildInfo.built_at_utc) UTC. Details are in build-info.json; attach that
file if you report a problem.

Russian: see README.ru.txt.

How to start it
---------------
Copy this whole folder to the other machine and run NetRuleRouter.exe. Nothing
has to be installed first: Qt, the Microsoft Visual C++ libraries and everything
else sit inside the folder.

Where to put the folder
-----------------------
Anywhere. The background service runs with system rights, so it never runs
from a folder an ordinary user can change. Installing it from this folder - on
the desktop, in Downloads, on a flash drive - copies the service to

    C:\Program Files\NetRuleRouter Service

a folder only administrators can change, and runs it from there. Installing
again from a newer copy of this folder updates it; removing the service removes
it. Moving or deleting this folder later does not stop the service.

The service
-----------
From this folder the service is installed from the app; Windows asks for
administrator confirmation. The EXE and MSI installers of the same build do
that step themselves and put the program in C:\Program Files\NetRuleRouter.

What is inside
--------------
    NetRuleRouter.exe   the app; the tray, service, console, terminal
                        interface and libraries sit beside it
    qml\        Qt's own modules
    apps\       the interface (QML). The nesting is deliberate: the interface
                addresses its icons relative to itself
    locales\    translations (Russian and English)
    presets\    ready-made rule sets
    configs\    schemas and configuration
    assets\     icons and the logo
    scripts\    recovery and uninstall scripts

Day-to-day checks use the console beside the app, run from a terminal in this
folder: nrr-cli.exe status, nrr-cli.exe diag doctor. If the service left the
machine without network: nrr-cli.exe reset-network --confirm (administrator).
scripts\reset-network.ps1 does the same recovery and also works when the
console cannot start. scripts\uninstall-service.ps1 and scripts\purge-data.ps1
remove the service and the data it left.

Without a window - over SSH, or if you prefer the keyboard - nrr-tui.exe does
what the app does, in the terminal. Run it from a terminal in this folder;
--plain suits screen readers.

If nothing happens when you start it
------------------------------------
The app opens no console, so it writes its errors to a file. Look at
launcher-main.log in %TEMP%\NetRuleRouter.
"@
Set-Content -Path (Join-Path $packageRoot 'README.txt') -Value $readMeEn -Encoding UTF8

$readMeRu = @"
NetRuleRouter - переносимая сборка для Windows
==============================================

Версия $productVersion, ревизия $($revision.commit)$(if ($revision.dirty) { ' (собрано с незакоммиченными правками)' })
Собрано $($buildInfo.built_at_utc) UTC. Подробности - в файле build-info.json;
приложите его, если будете сообщать о проблеме.

English: см. README.txt.

Как запустить
-------------
Скопируйте эту папку целиком на другой компьютер и запустите NetRuleRouter.exe.
Ничего устанавливать заранее не нужно: Qt, библиотеки Microsoft Visual C++ и
всё остальное лежат внутри папки.

Куда положить папку
-------------------
Куда угодно. Фоновая служба работает с системными правами, поэтому никогда не
запускается из папки, которую может изменить обычный пользователь. Установка
из этой папки - с рабочего стола, из «Загрузок», с флэшки - копирует службу в

    C:\Program Files\NetRuleRouter Service

где что-то менять могут только администраторы, и запускает её оттуда.
Повторная установка из более новой копии этой папки обновляет её, удаление
службы убирает. Если потом переместить или удалить эту папку, служба
продолжит работать.

Служба
------
Из этой папки служба ставится из интерфейса программы; система спросит
подтверждение администратора. Установщики EXE и MSI той же сборки делают этот
шаг сами и кладут программу в C:\Program Files\NetRuleRouter.

Что внутри
----------
    NetRuleRouter.exe   программа; рядом трей, служба, консоль, терминальный
                        интерфейс и библиотеки
    qml\        модули Qt
    apps\       интерфейс (QML). Вложенность не случайна: интерфейс
                адресует значки относительно себя
    locales\    переводы (русский и английский)
    presets\    готовые наборы правил
    configs\    схемы и конфигурация
    assets\     значки и логотип
    scripts\    сценарии восстановления и удаления

Повседневные проверки делает консоль рядом с программой, из терминала в этой
папке: nrr-cli.exe status, nrr-cli.exe diag doctor. Если служба оставила машину
без сети: nrr-cli.exe reset-network --confirm (от администратора).
scripts\reset-network.ps1 делает то же восстановление и работает, даже когда
консоль не запускается. scripts\uninstall-service.ps1 и scripts\purge-data.ps1
удаляют службу и оставленные ею данные.

Без окна - по SSH или если удобнее клавиатура - nrr-tui.exe делает то же, что
программа, прямо в терминале. Запускайте его из терминала в этой папке;
для экранного чтеца - с ключом --plain.

Если ничего не происходит при запуске
-------------------------------------
Программа не открывает консоль, поэтому ошибки пишет в файл. Смотрите
launcher-main.log в папке %TEMP%\NetRuleRouter.
"@
Set-Content -Path (Join-Path $packageRoot 'README.ru.txt') -Value $readMeRu -Encoding UTF8

if ($Headless) {
$readMeEn = @"
NetRuleRouter - Windows build without a window
==============================================

Version $productVersion, revision $($revision.commit)$(if ($revision.dirty) { ' (built with uncommitted changes)' })
Built $($buildInfo.built_at_utc) UTC. Details are in build-info.json; attach that
file if you report a problem.

Russian: see README.ru.txt.

This build carries the background service, the console (nrr-cli.exe) and the
terminal interface (nrr-tui.exe); there is no window and no tray. Nothing has
to be installed first.

Start it from a terminal in this folder:

    nrr-cli.exe install --elevate     install and start the service
    nrr-tui.exe                       rules, routes and settings in the terminal

--plain suits screen readers. The service runs with system rights, so
installing it from a folder an ordinary user can change copies it to
C:\Program Files\NetRuleRouter Service and runs it from there.

If the network stops working: nrr-cli.exe reset-network --confirm, or
scripts\reset-network.ps1.
"@
Set-Content -Path (Join-Path $packageRoot 'README.txt') -Value $readMeEn -Encoding UTF8

$readMeRu = @"
NetRuleRouter - сборка для Windows без окна
===========================================

Версия $productVersion, ревизия $($revision.commit)$(if ($revision.dirty) { ' (собрана с незакоммиченными изменениями)' })
Собрана $($buildInfo.built_at_utc) UTC. Подробности - в build-info.json; приложите
этот файл к сообщению о проблеме.

В этой сборке фоновая служба, консоль (nrr-cli.exe) и терминальный интерфейс
(nrr-tui.exe); окна и значка в трее нет. Заранее ничего ставить не нужно.

Запускайте из терминала в этой папке:

    nrr-cli.exe install --elevate     установить и запустить службу
    nrr-tui.exe                       правила, маршруты и настройки в терминале

--plain подходит для экранного диктора. Служба работает с системными правами,
поэтому установка из папки, которую может изменить обычный пользователь,
копирует её в C:\Program Files\NetRuleRouter Service и запускает оттуда.

Если пропала сеть: nrr-cli.exe reset-network --confirm или
scripts\reset-network.ps1.
"@
Set-Content -Path (Join-Path $packageRoot 'README.ru.txt') -Value $readMeRu -Encoding UTF8
}

# ── Verification ─────────────────────────────────────────────────────────────

# Every executable, its symbols and every user script shipped must be on the
# list, or a new one would ship unchecked.
$shipped = @($executables | ForEach-Object {
    $_
    ([IO.Path]::GetFileNameWithoutExtension($_) -replace '-', '_') + '.pdb'
}) + @($userScripts | ForEach-Object { "scripts\$_" })
$unlisted = @($shipped | Where-Object { $required -notcontains $_ })
if ($unlisted) {
    throw "packaging\windows\package-contents.txt does not list $($unlisted -join ', '), which this script ships."
}
$missing = Get-MissingContents -Root $packageRoot -Expected $required
if ($missing) {
    throw "Package is incomplete, missing: $($missing -join ', ')"
}

$totalBytes = (Get-ChildItem -Path $packageRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum
$totalFiles = (Get-ChildItem -Path $packageRoot -Recurse -File | Measure-Object).Count

# The build stamp is in every artifact name so two builds on the same flash
# drive cannot be confused for one another.
$artifactBase = "NetRuleRouter-windows-$Arch-$buildStamp" + $(if ($Headless) { '-headless' } else { '' })
$artifacts = New-Object System.Collections.Generic.List[string]

if ($Zip) {
    $archivePath = Join-Path $OutputRoot "$artifactBase.zip"
    if (Test-Path $archivePath) {
        Remove-Item -Path $archivePath -Force
    }
    Write-Step 'compressing the package'
    Compress-Archive -Path $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveBytes = (Get-Item $archivePath).Length
    Write-Host ("[package] archive: {0} ({1:N1} MB)" -f $archivePath, ($archiveBytes / 1MB)) -ForegroundColor Green
    $artifacts.Add($archivePath)
}

# ── Installers ───────────────────────────────────────────────────────────────

if ($buildExe -or $buildMsi) {
    $installerSources = Join-Path $repoRoot 'packaging\windows'
    # Windows Installer and the EXE's version block take numbers only; the
    # full stamp still names the files and shows in Apps & Features.
    $numericVersion = ($productVersion -split '[-+]')[0]
    if ($numericVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "Cannot derive a numeric a.b.c version from '$productVersion'."
    }
}

if ($buildExe) {
    $setupName = "$artifactBase-setup"
    $setupPath = Join-Path $OutputRoot "$setupName.exe"
    if (Test-Path -LiteralPath $setupPath) {
        Remove-Item -LiteralPath $setupPath -Force
    }
    Write-Step "building the EXE installer with '$iscc'"
    & $iscc '/Q' "/DPackageDir=$packageRoot" "/DAppVersion=$buildStamp" "/DVersionNumeric=$numericVersion.0" "/DArch=$Arch" `
        "/DVariant=$(if ($Headless) { 'headless' } else { 'full' })" `
        "/DOutputDir=$OutputRoot" "/DOutputBaseFilename=$setupName" (Join-Path $installerSources 'NetRuleRouter.iss')
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $setupPath)) {
        throw 'Inno Setup failed to build the EXE installer.'
    }
    Write-Host ("[package] EXE installer: {0} ({1:N1} MB)" -f $setupPath, ((Get-Item $setupPath).Length / 1MB)) -ForegroundColor Green
    $artifacts.Add($setupPath)
}

if ($buildMsi) {
    $msiPath = Join-Path $OutputRoot "$artifactBase.msi"
    if (Test-Path -LiteralPath $msiPath) {
        Remove-Item -LiteralPath $msiPath -Force
    }
    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) "nrr-msi-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    try {
        $licenseRtf = Join-Path $workDir 'LICENSE.rtf'
        ConvertTo-RtfFile -Source (Join-Path $repoRoot 'LICENSE') -Destination $licenseRtf
        $wixArguments = @('build', '-arch', $Arch,'-bindpath', "pkg=$packageRoot",
            '-d', "Version=$numericVersion", '-d', "DisplayVersion=$buildStamp", '-d', "LicenseRtf=$licenseRtf",
            '-d', "Variant=$(if ($Headless) { 'headless' } else { 'full' })",
            '-intermediatefolder', $workDir, '-pdb', (Join-Path $workDir 'NetRuleRouter.wixpdb'),
            '-o', $msiPath)
        foreach ($extension in $wixExtensions) {
            $wixArguments += @('-ext', "$extension/$wixVersion")
        }
        $wixArguments += (Join-Path $installerSources 'NetRuleRouter.wxs')
        Write-Step "building the MSI with '$wix'"
        & $wix @wixArguments
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $msiPath)) {
            throw 'WiX failed to build the MSI.'
        }
    }
    finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host ("[package] MSI: {0} ({1:N1} MB)" -f $msiPath, ((Get-Item $msiPath).Length / 1MB)) -ForegroundColor Green
    $artifacts.Add($msiPath)
}

if ($buildExe -or $buildMsi) {
    # `sha256sum -c` format, so the file checks on Linux as well.
    $sumsPath = Join-Path $OutputRoot "$artifactBase-SHA256SUMS.txt"
    $sums = foreach ($artifact in $artifacts) {
        $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $(Split-Path -Leaf $artifact)"
    }
    [System.IO.File]::WriteAllLines($sumsPath, [string[]]$sums, [System.Text.Encoding]::ASCII)
    Write-Host "[package] checksums: $sumsPath" -ForegroundColor Green
}

Write-Host ''
Write-Host "[package] ready: $packageRoot" -ForegroundColor Green
Write-Host "[package] NetRuleRouter $productVersion, revision $($revision.commit)$(if ($revision.dirty) { ' with uncommitted changes' })" -ForegroundColor Green
Write-Host ("[package] {0:N1} MB in {1:N0} files" -f ($totalBytes / 1MB), $totalFiles) -ForegroundColor Green
Write-Host "[package] copy the folder to the target machine and run $(if ($Headless) { 'nrr-tui.exe' } else { 'NetRuleRouter.exe' })" -ForegroundColor Green
Write-Host '[package] installing the service from this folder copies it under Program Files and runs that copy' -ForegroundColor Green
