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
          READ-ME.txt
          <tray, service, console, Qt host, the Qt runtime, wintun.dll>
          qml\                  Qt's own modules, written by windeployqt
          apps\desktop\qml\     the app's own QML
          locales\  presets\  configs\  assets\
          scripts\              maintenance scripts

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

.PARAMETER QtBin
    Qt's bin directory holding windeployqt.exe. Autodetected under C:\Qt when
    omitted.

.PARAMETER Full
    Deploy the complete Qt runtime. The default trims the pieces this app never
    loads (Qt's own translations, the software OpenGL rasterizer, the legacy
    D3D shader compiler) and the Qt Quick styles the app never selects, saving
    roughly 37 MB in total.

.PARAMETER Zip
    Also produce NetRuleRouter-windows-x64-<version>+<commit>.zip next to the
    folder, for carrying the build on a flash drive.

.PARAMETER Force
    Replace an existing package folder.
#>
param(
    [string]$OutputRoot = 'C:\temp\NetRuleRouter\dist',
    [switch]$SkipBuild,
    [string]$QtBin,
    [switch]$Full,
    [switch]$Zip,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$packageRoot = Join-Path $OutputRoot 'NetRuleRouter'
# Binaries live in the package root: the user starts NetRuleRouter.exe
# directly, with no wrapper script in between. Nothing collides there -
# windeployqt owns `qml\` for its modules while the app's own QML sits
# under `apps\desktop\qml\`, which is also the depth its icon paths expect.
$binDir = $packageRoot
# Written into the package so a later run can tell its own output apart from a
# folder the user picked by mistake, and refuse to delete the latter.
$markerName = '.nrr-package'

function Write-Step {
    param([string]$Message)
    Write-Host "[package] $Message" -ForegroundColor Cyan
}

function Resolve-CargoMetadata {
    $metadata = & cargo metadata --format-version 1 --no-deps 2>$null | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $metadata) {
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
    $commit = & git -C $repoRoot rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $commit) {
        return $revision
    }
    $revision.commit = $commit.Trim()
    $commitDate = & git -C $repoRoot log -1 --format=%cI 2>$null
    if ($LASTEXITCODE -eq 0 -and $commitDate) {
        $revision.commit_date = $commitDate.Trim()
    }
    # Uncommitted work is the norm here, and a package built from it must say
    # so: otherwise a bug report names a commit that never held this code.
    $status = & git -C $repoRoot status --porcelain 2>$null
    $revision.dirty = [bool]$status
    return $revision
}

function Resolve-WindeployQt {
    param([string]$Explicit)

    if ($Explicit) {
        $candidate = Join-Path $Explicit 'windeployqt.exe'
        if (-not (Test-Path $candidate)) {
            throw "windeployqt.exe not found in -QtBin '$Explicit'."
        }
        return $candidate
    }

    # A Qt installation commonly carries several ABIs side by side, and an
    # arm64 windeployqt cannot even start on an x64 host - match the desktop
    # x64 kit explicitly rather than taking whichever sorts first.
    $found = Get-ChildItem -Path 'C:\Qt' -Filter 'windeployqt.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\msvc\d+_64\\bin\\' } |
        Sort-Object FullName -Descending
    if (-not $found) {
        throw 'No x64 windeployqt.exe found under C:\Qt (looked for msvc*_64). Pass -QtBin <path to Qt bin>.'
    }
    return $found[0].FullName
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

function Copy-Payload {
    param([string]$RelativeSource, [string]$Destination)

    $source = Join-Path $repoRoot $RelativeSource
    if (-not (Test-Path $source)) {
        throw "Payload '$RelativeSource' is missing from the checkout."
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    Copy-Item -Path $source -Destination $Destination -Recurse -Force
}

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

# ── Build ────────────────────────────────────────────────────────────────────

$metadata = Resolve-CargoMetadata
$targetDir = $metadata.target_directory
$releaseDir = Join-Path $targetDir 'release'
$productVersion = Resolve-ProductVersion -Metadata $metadata
$revision = Resolve-SourceRevision
$buildStamp = "$productVersion+$($revision.commit)" + $(if ($revision.dirty) { '-dirty' } else { '' })
Write-Step "version $productVersion, revision $($revision.commit)$(if ($revision.dirty) { ' (uncommitted changes)' })"

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1')
    Write-Step 'cargo build --release (launcher, service, console)'
    & cargo build --release -p nrr-launcher -p nrr-windows-service -p nrr-cli
    if ($LASTEXITCODE -ne 0) {
        throw 'Release build failed. A running service or open GUI holds its own binary - stop it and retry.'
    }
} else {
    Write-Step 'skipping the build, packaging what is already in the target directory'
}

# ── Executables ──────────────────────────────────────────────────────────────

New-Item -ItemType Directory -Path $binDir -Force | Out-Null
# Stamped before anything is copied: a run that dies halfway still leaves a
# folder this script recognises as its own, so -Force can clean it up.
Set-Content -Path (Join-Path $packageRoot $markerName) -Value 'Produced by scripts/package-windows.ps1' -Encoding ASCII

$executables = @(
    'NetRuleRouter.exe',
    'NetRuleRouterTray.exe',
    'nrr-service.exe',
    'nrr-cli.exe'
)
foreach ($exe in $executables) {
    $source = Join-Path $releaseDir $exe
    if (-not (Test-Path $source)) {
        throw "'$exe' is missing from '$releaseDir'. Run without -SkipBuild."
    }
    Copy-Item -Path $source -Destination $binDir -Force
}
Write-Step "copied $($executables.Count) executables"

$nativeHost = Resolve-NativeHost -ReleaseDir $releaseDir
Copy-Item -Path $nativeHost -Destination $binDir -Force
Write-Step "copied the Qt host from '$nativeHost'"

# Without it fake-IP silently switches itself off, and the failure is invisible
# in the UI - so a missing DLL fails the packaging instead.
$wintun = Join-Path $repoRoot 'third_party\wintun\bin\amd64\wintun.dll'
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
        Where-Object { $_.FullName -like '*\x64\*' -and $_.FullName -notlike '*\onecore\*' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
}
if (-not $crtSource) {
    throw 'Visual C++ redistributable DLLs not found on this machine (looked under the Visual Studio install). Install the C++ workload, or package on a machine that has it.'
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

$windeployqt = Resolve-WindeployQt -Explicit $QtBin
$deployArguments = @(
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
    # Debug/profiling plugins for QML tooling: only a connected debugger loads
    # them, and a shipped build has none.
    $qmlTooling = Join-Path $binDir 'qmltooling'
    if (Test-Path $qmlTooling) {
        $freedBytes += (Get-ChildItem $qmlTooling -Recurse -File | Measure-Object -Property Length -Sum).Sum
        Remove-Item -Path $qmlTooling -Recurse -Force
    }
    Write-Step ("trimmed unused Qt styles and QML tooling: {0:N1} MB" -f ($freedBytes / 1MB))
}

# ── Payload ──────────────────────────────────────────────────────────────────

# Not `<package>\qml`, despite that being the tidier name: the QML addresses
# icons as `../../../assets/icons/...`, three levels up from Main.qml. Keeping
# the same depth as the checkout is what makes those icons resolve; the
# launcher already looks for this exact path when walking up from the binary.
Copy-Payload 'apps\desktop\qml' (Join-Path $packageRoot 'apps\desktop\qml')
Copy-Payload 'locales' (Join-Path $packageRoot 'locales')
Copy-Payload 'presets' (Join-Path $packageRoot 'presets')
Copy-Payload 'configs' (Join-Path $packageRoot 'configs')
Copy-Payload 'assets\icons' (Join-Path $packageRoot 'assets\icons')
Copy-Payload 'scripts' (Join-Path $packageRoot 'scripts')
Write-Step 'copied the QML, locales, presets, configs, icons and scripts'

# ── Build identity ───────────────────────────────────────────────────────────

# Machine-readable, because a bug report that names a version and a commit is
# worth more than a screenshot, and because whoever checks the package from
# the app later needs a fixed shape to read.
$qtVersion = 'unknown'
if ($windeployqt -match '\\Qt\\(?<version>\d+\.\d+\.\d+)\\') {
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
    platform       = 'windows-x64'
    qt_version     = $qtVersion
    qt_runtime     = $(if ($Full) { 'full' } else { 'trimmed' })
}
$buildInfo | ConvertTo-Json | Set-Content -Path (Join-Path $packageRoot 'build-info.json') -Encoding UTF8
Write-Step "stamped build-info.json ($buildStamp)"

# ── Entry point and notes ────────────────────────────────────────────────────

$readMe = @"
NetRuleRouter - переносимая сборка для Windows
==============================================

Версия $productVersion, ревизия $($revision.commit)$(if ($revision.dirty) { ' (собрано с незакоммиченными правками)' })
Собрано $($buildInfo.built_at_utc) UTC. Подробности - в файле build-info.json;
приложите его, если будете сообщать о проблеме.

Как запустить
-------------
Скопируйте эту папку целиком на другой компьютер и запустите NetRuleRouter.exe.
Ничего устанавливать заранее не нужно: Qt, библиотеки Microsoft Visual C++ и
всё остальное лежат внутри папки.

Куда положить папку
-------------------
ВАЖНО. Фоновая служба работает с системными правами. Тот, кто может изменять
файлы в её каталоге, может подменить её исполняемый файл и получить эти права.
Поэтому перед установкой службы положите папку туда, куда обычный пользователь
писать не может, например:

    C:\Program Files\NetRuleRouter

Запускать программу с флэшки или из папки «Загрузки» можно, чтобы посмотреть
интерфейс, но службу из такого каталога ставить не следует.

Служба
------
Служба ставится из интерфейса программы; система спросит подтверждение
администратора. Отдельного установщика в этой сборке нет.

Что внутри
----------
    NetRuleRouter.exe   программа; рядом трей, служба, консоль и библиотеки
    qml\        модули Qt
    apps\       интерфейс (QML). Вложенность не случайна: интерфейс
                адресует значки относительно себя
    locales\    переводы (русский и английский)
    presets\    готовые наборы правил
    configs\    схемы и конфигурация
    assets\     значки
    scripts\    вспомогательные сценарии

Часть сценариев в scripts\ рассчитана на дерево исходного кода и на другом
компьютере работать не будет. Здесь пригодятся прежде всего reset-network.ps1
(аварийное восстановление сети), service-status.ps1 и service-smoke.ps1.

Если ничего не происходит при запуске
-------------------------------------
Программа не открывает консоль, поэтому ошибки пишет в файл. Смотрите
launcher-main.log в папке %TEMP%\NetRuleRouter.
"@
Set-Content -Path (Join-Path $packageRoot 'READ-ME.txt') -Value $readMe -Encoding UTF8

# ── Verification ─────────────────────────────────────────────────────────────

$required = @(
    'NetRuleRouter.exe',
    'NetRuleRouterTray.exe',
    'nrr-service.exe',
    'nrr-cli.exe',
    'nrr_qt_native_host.exe',
    'wintun.dll',
    'Qt6Core.dll',
    'Qt6Quick.dll',
    'qml\QtQuick',
    'apps\desktop\qml\Main.qml',
    'apps\desktop\qml\Tray.qml',
    'apps\desktop\qml\components\ThemedButton.qml',
    'assets\icons\ui\apply.svg',
    'locales\en.json',
    'locales\ru.json',
    'assets\icons\app\app.ico',
    'nrr_qt_native_host.exe',
    'build-info.json'
)
$missing = $required | Where-Object { -not (Test-Path (Join-Path $packageRoot $_)) }
if ($missing) {
    throw "Package is incomplete, missing: $($missing -join ', ')"
}

$totalBytes = (Get-ChildItem -Path $packageRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum
$totalFiles = (Get-ChildItem -Path $packageRoot -Recurse -File | Measure-Object).Count

if ($Zip) {
    # The build stamp is in the name so two archives on the same flash drive
    # cannot be confused for one another.
    $archivePath = Join-Path $OutputRoot "NetRuleRouter-windows-x64-$buildStamp.zip"
    if (Test-Path $archivePath) {
        Remove-Item -Path $archivePath -Force
    }
    Write-Step 'compressing the package'
    Compress-Archive -Path $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveBytes = (Get-Item $archivePath).Length
    Write-Host ("[package] archive: {0} ({1:N1} MB)" -f $archivePath, ($archiveBytes / 1MB)) -ForegroundColor Green
}

Write-Host ''
Write-Host "[package] ready: $packageRoot" -ForegroundColor Green
Write-Host "[package] NetRuleRouter $productVersion, revision $($revision.commit)$(if ($revision.dirty) { ' with uncommitted changes' })" -ForegroundColor Green
Write-Host ("[package] {0:N1} MB in {1:N0} files" -f ($totalBytes / 1MB), $totalFiles) -ForegroundColor Green
Write-Host '[package] copy the folder to the target machine and run NetRuleRouter.exe' -ForegroundColor Green
Write-Host '[package] install the service from the app, and only from a folder ordinary users cannot write to' -ForegroundColor Yellow
