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
          qml\                  Qt's own modules, written by windeployqt
          apps\desktop\qml\     the app's own QML
          locales\  presets\  configs\  assets\
          scripts\              recovery and uninstall scripts
          docs\                 offline documentation, docs\<language>\index.html

    Two QML trees under one name would collide, which is why the app's own tree
    keeps the `apps\desktop\qml` path it has in the checkout, where the launcher
    looks for it. Icons and images are found through `assets\` beside the
    binaries, whatever the QML's depth.

    Every package carries build-info.json - version, commit, whether the tree
    had uncommitted changes, build time, Qt version - so a report about a
    specific copy can be tied back to the code that produced it.

    No package carries debug symbols (*.pdb): a panic names its file:line
    without them. A run that writes any artifact also writes
    <artifact>-symbols.zip beside it, the PDBs of exactly the executables
    shipped, for reading a crash's call stack later. A bare folder gets none:
    the symbols of the same build stay in the target directory.

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
    D3D shader compiler), the Qt Quick styles the app never selects with their
    libraries, and the network and touch plugins nothing loads.

.PARAMETER Zip
    Also produce NetRuleRouter-windows-<arch>-<version>-portable.zip
    next to the folder, for carrying the build on a flash drive, and the
    -symbols.zip of the build.

.PARAMETER Installers
    Also build both installers from the package: the EXE (Inno Setup 6) and the
    MSI (WiX Toolset 5), next to the folder, plus a SHA256 checksum file that
    covers every artifact of this run, the archives included.

.PARAMETER Exe
    Build the EXE installer only (same output as -Installers otherwise).

.PARAMETER Msi
    Build the MSI only (same output as -Installers otherwise).

.PARAMETER Headless
    Package without the window and the tray: the service, the console and the
    terminal interface, for servers and Windows without a desktop session. The
    folder is <OutputRoot>\NetRuleRouter-headless and every artifact name
    carries -headless right after the version (...-headless-portable.zip).

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
# under `apps\desktop\qml\`, and `assets\` must sit beside the binaries.
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

function ConvertTo-RtfText {
    param([string] $Text)
    $out = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($ch -eq [char]'\' -or $ch -eq [char]'{' -or $ch -eq [char]'}') { [void]$out.Append('\').Append($ch) }
        elseif ($code -gt 127) { [void]$out.Append("\u$(if ($code -gt 32767) { $code - 65536 } else { $code })?") }
        else { [void]$out.Append($ch) }
    }
    return $out.ToString()
}

# A line of the agreement's Markdown as the licence pages show it: bold kept,
# a link as "text (url)", code without its backticks. RichEdit breaks a line
# before the "@" of an e-mail address: with -LinkFields (the EXE page,
# RichEdit 4.1) the address is a mailto link, which it keeps whole; the MSI
# page's RichEdit 2.0 breaks even a link, so there the address is glued with
# zero-width no-break spaces.
function ConvertTo-RtfInline {
    param([string] $Text, [switch] $LinkFields)
    $mails = New-Object System.Collections.Generic.List[object]
    $mail = [System.Text.RegularExpressions.MatchEvaluator] {
        param($match)
        $address = $match.Groups['address'].Value
        $label = if ($match.Groups['label'].Success) { $match.Groups['label'].Value } else { $address }
        $mails.Add(@{ Address = $address; Label = $label })
        "$([char]1)$($mails.Count - 1)$([char]1)"
    }
    $Text = [regex]::Replace($Text, '\[(?<label>[^\]]+)\]\(mailto:(?<address>[^)\s]+)\)', $mail)
    $Text = [regex]::Replace($Text, '<(?:mailto:)?(?<address>[^<>\s:]+@[^<>\s]+)>', $mail)
    $link = [System.Text.RegularExpressions.MatchEvaluator] {
        param($match)
        $label = $match.Groups[1].Value
        $url = $match.Groups[2].Value
        # A relative link names a file beside the Markdown, which no installer carries.
        if ($url -notmatch '^[a-z][a-z0-9+.-]*:' -or $url -eq $label) { $label } else { "$label ($url)" }
    }
    $Text = [regex]::Replace($Text, '\[([^\]]+)\]\(([^)\s]+)\)', $link)
    $Text = [regex]::Replace($Text, '<([^<>\s]+)>', '$1')
    $Text = [regex]::Replace($Text, '`([^`]*)`', '$1')
    $rtf = [regex]::Replace((ConvertTo-RtfText $Text), '\*\*(.+?)\*\*', '{\b $1}')
    $placed = [System.Text.RegularExpressions.MatchEvaluator] {
        param($match)
        $entry = $mails[[int]$match.Groups[1].Value]
        $label = ConvertTo-RtfText $entry.Label
        if ($LinkFields) {
            "{\field{\*\fldinst{HYPERLINK `"mailto:$($entry.Address)`"}}{\fldrslt{$label}}}"
        } else {
            [regex]::Replace($label, '[@.]', '\u-257?$0\u-257?')
        }
    }
    return [regex]::Replace($rtf, "$([char]1)(\d+)$([char]1)", $placed)
}

# Both installers' licence pages read RTF and wrap it to their own width: the
# lines of a paragraph or list item join, a blank line or a rule ends it, and
# headings and list items keep their look.
function ConvertFrom-AgreementMarkdown {
    param([string] $Source, [string] $Destination, [switch] $LinkFields)

    $blocks = New-Object System.Collections.Generic.List[object]
    $current = $null
    foreach ($raw in [System.IO.File]::ReadAllLines($Source, [System.Text.Encoding]::UTF8)) {
        $line = $raw.TrimEnd()
        $heading = [regex]::Match($line, '^(#{1,6})\s+(.+)$')
        $item = [regex]::Match($line, '^\s*([-*+]|\d+[.)])\s+(.+)$')
        if (-not $line.Trim() -or $line -match '^\s*(-{3,}|\*{3,}|_{3,})\s*$' -or $heading.Success -or $item.Success) {
            if ($current) { $blocks.Add($current) }
            $current = $null
        }
        if ($heading.Success) {
            $blocks.Add(@{ Kind = $(if ($heading.Groups[1].Length -eq 1) { 'title' } else { 'heading' }); Text = $heading.Groups[2].Value })
        } elseif ($item.Success) {
            $marker = $item.Groups[1].Value
            $current = @{ Kind = 'item'; Marker = $(if ($marker -match '^\d') { $marker } else { '\bullet' }); Text = $item.Groups[2].Value }
        } elseif (-not $line.Trim() -or $line -match '^\s*(-{3,}|\*{3,}|_{3,})\s*$') {
            continue
        } elseif ($current) {
            $current.Text += ' ' + $line.Trim()
        } else {
            $current = @{ Kind = 'paragraph'; Text = $line.Trim() }
        }
    }
    if ($current) { $blocks.Add($current) }
    if ($blocks.Count -lt 2) {
        throw "'$Source' holds no agreement text."
    }

    $rtf = New-Object System.Text.StringBuilder
    [void]$rtf.Append("{\rtf1\ansi\ansicpg1252\deff0\uc1{\fonttbl{\f0\fswiss\fcharset0 Segoe UI;}}\f0\fs18`r`n")
    foreach ($block in $blocks) {
        $text = ConvertTo-RtfInline $block.Text -LinkFields:$LinkFields
        switch ($block.Kind) {
            'title' { [void]$rtf.Append("\pard\sa160\b\fs24 $text\b0\fs18\par`r`n") }
            'heading' { [void]$rtf.Append("\pard\keepn\sb160\sa80\b\fs20 $text\b0\fs18\par`r`n") }
            'item' { [void]$rtf.Append("\pard\fi-240\li480\tx480\sa60 $($block.Marker)\tab $text\par`r`n") }
            default { [void]$rtf.Append("\pard\sa120 $text\par`r`n") }
        }
    }
    [void]$rtf.Append('}')
    [System.IO.File]::WriteAllText($Destination, $rtf.ToString(), [System.Text.Encoding]::ASCII)
}

# The revision in an agreement's header line. The installers record it with
# the account that accepted the page, and the app skips its own page only for
# that account and exactly this revision.
function Get-AgreementRevision {
    param([string] $Source)
    foreach ($line in [System.IO.File]::ReadAllLines($Source, [System.Text.Encoding]::UTF8)) {
        $header = [regex]::Match($line, '^(?:Agreement revision|Редакция соглашения) (\d+) ')
        if ($header.Success) { return [int]$header.Groups[1].Value }
    }
    throw "'$Source' names no agreement revision."
}

# The wizards' pictures, drawn from the app icon on a light background:
# otherwise WiX shows its red ones and Inno Setup its own.
function New-Canvas {
    param([int] $Width, [int] $Height)
    $bitmap = New-Object System.Drawing.Bitmap $Width, $Height, ([System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $graphics.Clear([System.Drawing.Color]::White)
    return $bitmap, $graphics
}

# A panel PanelWidth wide on the left, holding the icon and the product name;
# white beyond it, where the wizard writes its own text.
function New-PanelBitmap {
    param([string] $Path, [int] $Width, [int] $Height, [int] $PanelWidth, [System.Drawing.Image] $Icon)
    $bitmap, $graphics = New-Canvas $Width $Height
    $panel = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0xEC, 0xF2, 0xF8))
    $ink = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0x1B, 0x27, 0x33))
    $scale = $PanelWidth / 164.0
    $font = New-Object System.Drawing.Font('Segoe UI Semibold', [float](19 * $scale), [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $centered = New-Object System.Drawing.StringFormat
    $centered.Alignment = [System.Drawing.StringAlignment]::Center
    try {
        $graphics.FillRectangle($panel, 0, 0, $PanelWidth, $Height)
        $size = [int](96 * $scale)
        $top = [int]($Height * 0.3)
        $graphics.DrawImage($Icon, [int](($PanelWidth - $size) / 2), $top, $size, $size)
        $caption = New-Object System.Drawing.RectangleF 0, ($top + $size + 14 * $scale), $PanelWidth, (40 * $scale)
        $graphics.DrawString('NetRuleRouter', $font, $ink, $caption, $centered)
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
    } finally {
        $centered.Dispose(); $font.Dispose(); $ink.Dispose(); $panel.Dispose()
        $graphics.Dispose(); $bitmap.Dispose()
    }
}

# The icon alone on white, IconSize square, Right pixels from the right edge
# (centred when negative).
function New-IconBitmap {
    param([string] $Path, [int] $Width, [int] $Height, [int] $IconSize, [int] $Right, [System.Drawing.Image] $Icon)
    $bitmap, $graphics = New-Canvas $Width $Height
    try {
        $x = if ($Right -lt 0) { [int](($Width - $IconSize) / 2) } else { $Width - $Right - $IconSize }
        $graphics.DrawImage($Icon, $x, [int](($Height - $IconSize) / 2), $IconSize, $IconSize)
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
    } finally {
        $graphics.Dispose(); $bitmap.Dispose()
    }
}

# The MSI's banner and side picture (WixUIBannerBmp, WixUIDialogBmp) and Inno
# Setup's at 100, 150 and 200 % scaling, into Folder.
function New-InstallerImages {
    param([string] $Folder)
    Add-Type -AssemblyName System.Drawing
    $source = Join-Path $repoRoot 'assets\icons\app\icon-256.png'
    if (-not (Test-Path -LiteralPath $source)) {
        throw "The app icon '$source' is missing from the checkout."
    }
    $icon = [System.Drawing.Image]::FromFile($source)
    try {
        $images = @{
            Banner = Join-Path $Folder 'msi-banner.bmp'
            Dialog = Join-Path $Folder 'msi-dialog.bmp'
            Wizard = @()
            WizardSmall = @()
        }
        New-IconBitmap -Path $images.Banner -Width 493 -Height 58 -IconSize 44 -Right 10 -Icon $icon
        New-PanelBitmap -Path $images.Dialog -Width 493 -Height 312 -PanelWidth 164 -Icon $icon
        foreach ($size in @(@(164, 314, 55, 55), @(246, 459, 83, 80), @(328, 628, 110, 106))) {
            $large = Join-Path $Folder "wizard-$($size[0]).bmp"
            New-PanelBitmap -Path $large -Width $size[0] -Height $size[1] -PanelWidth $size[0] -Icon $icon
            $small = Join-Path $Folder "wizard-small-$($size[2]).bmp"
            New-IconBitmap -Path $small -Width $size[2] -Height $size[3] -IconSize ([Math]::Min($size[2], $size[3]) - 6) -Right -1 -Icon $icon
            $images.Wizard += $large
            $images.WizardSmall += $small
        }
        return $images
    } finally {
        $icon.Dispose()
    }
}

# Windows Installer's automation object has no type information PowerShell can
# bind to, so its members are reached by name. A string PowerShell wrapped (as
# Join-Path returns it) would reach it as a type mismatch: the bare value goes.
function Invoke-MsiMember {
    param($Object, [string] $Member, [string] $Kind = 'InvokeMethod', [object[]] $Arguments = @())
    $bare = [object[]]@($Arguments | ForEach-Object { $_.PSObject.BaseObject })
    return $Object.GetType().InvokeMember($Member, [System.Reflection.BindingFlags]$Kind, $null, $Object, $bare)
}

# A transform that left the wizard English would reach a Russian Windows with
# nothing saying so: it is applied to a copy of the MSI, which must then carry
# the culture's language and a text of its .wxl exactly as written there.
function Test-LanguageTransform {
    param([string] $Msi, [string] $Transform, [hashtable] $Culture, [string] $Copy)
    Copy-Item -LiteralPath $Msi -Destination $Copy -Force
    $wxl = [xml][System.IO.File]::ReadAllText((Join-Path $installerSources "NetRuleRouter.$($Culture.Culture).wxl"), [System.Text.Encoding]::UTF8)
    $expected = ($wxl.WixLocalization.String | Where-Object { $_.Id -eq 'NrrRemoveIntro' }).Value
    $found = @{}
    $held = New-Object System.Collections.Generic.List[object]
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $held.Add($installer)
        $database = Invoke-MsiMember $installer 'OpenDatabase' -Arguments @($Copy, 1)
        $held.Add($database)
        # With the errors the transform itself suppresses, as an installation
        # applies it: a language transform changes the code page.
        $summary = Invoke-MsiMember $installer 'SummaryInformation' 'GetProperty' @($Transform, 0)
        $held.Add($summary)
        $suppressed = [int](Invoke-MsiMember $summary 'Property' 'GetProperty' @(16)) -band 0xFFFF
        Invoke-MsiMember $database 'ApplyTransform' -Arguments @($Transform, $suppressed) | Out-Null
        $queries = @{
            Language = 'SELECT `Value` FROM `Property` WHERE `Property` = ''ProductLanguage'''
            Text = 'SELECT `Text` FROM `Control` WHERE `Dialog_` = ''NrrRemoveDlg'' AND `Control` = ''Intro'''
        }
        foreach ($name in $queries.Keys) {
            $view = Invoke-MsiMember $database 'OpenView' -Arguments @($queries[$name])
            $held.Add($view)
            Invoke-MsiMember $view 'Execute' | Out-Null
            $record = Invoke-MsiMember $view 'Fetch'
            if ($record) {
                $held.Add($record)
                $found[$name] = Invoke-MsiMember $record 'StringData' 'GetProperty' @(1)
            }
            Invoke-MsiMember $view 'Close' | Out-Null
        }
    } finally {
        $held.Reverse()
        foreach ($object in $held) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
    if ("$($found.Language)" -ne "$($Culture.Lcid)" -or -not $expected -or "$($found.Text)" -cne $expected) {
        throw "The $($Culture.Culture) transform does not turn the wizard $($Culture.Culture): ProductLanguage '$($found.Language)', text '$($found.Text)'."
    }
}

# Each transform stored in the MSI under its language id, and every language in
# the package's template: Windows Installer then applies the one matching the
# display language by itself.
function Add-LanguageTransforms {
    param([string] $Msi, [hashtable] $Transforms, [int] $BaseLanguage)
    # Every object is released at the end: one left holds the file open.
    $held = New-Object System.Collections.Generic.List[object]
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $held.Add($installer)
        $database = Invoke-MsiMember $installer 'OpenDatabase' -Arguments @($Msi, 1)
        $held.Add($database)
        foreach ($language in $Transforms.Keys) {
            $view = Invoke-MsiMember $database 'OpenView' -Arguments @('INSERT INTO `_Storages` (`Name`, `Data`) VALUES (?, ?)')
            $held.Add($view)
            $record = Invoke-MsiMember $installer 'CreateRecord' -Arguments @(2)
            $held.Add($record)
            Invoke-MsiMember $record 'StringData' 'SetProperty' @(1, "$language") | Out-Null
            Invoke-MsiMember $record 'SetStream' -Arguments @(2, $Transforms[$language]) | Out-Null
            Invoke-MsiMember $view 'Execute' -Arguments @($record) | Out-Null
            Invoke-MsiMember $view 'Close' | Out-Null
        }
        $summary = Invoke-MsiMember $database 'SummaryInformation' 'GetProperty' @(1)
        $held.Add($summary)
        $platform = ("$(Invoke-MsiMember $summary 'Property' 'GetProperty' @(7))" -split ';')[0]
        $languages = @($BaseLanguage) + @($Transforms.Keys | Sort-Object)
        Invoke-MsiMember $summary 'Property' 'SetProperty' @(7, "$platform;$($languages -join ',')") | Out-Null
        Invoke-MsiMember $summary 'Persist' | Out-Null
        Invoke-MsiMember $database 'Commit' | Out-Null
    } finally {
        $held.Reverse()
        foreach ($object in $held) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

# The MSI's components of the offline documentation, one per file, each held to
# the NRR_DOCS choice: WiX harvests a folder only without a condition.
function Write-DocsFragment {
    param([string] $PackageRoot, [string] $Destination)
    $root = $PackageRoot.TrimEnd('\')
    $files = @(Get-ChildItem -LiteralPath (Join-Path $root 'docs') -Recurse -File | Sort-Object FullName)
    if ($files.Count -eq 0) {
        throw "No offline documentation in '$root\docs'."
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('<?xml version="1.0" encoding="utf-8"?>')
    $lines.Add('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>')
    $lines.Add('<ComponentGroup Id="DocsFiles" Directory="INSTALLFOLDER">')
    $index = 0
    foreach ($file in $files) {
        $index++
        $relative = $file.FullName.Substring($root.Length + 1)
        $folder = [System.Security.SecurityElement]::Escape((Split-Path -Parent $relative))
        $source = [System.Security.SecurityElement]::Escape("!(bindpath.pkg)\$relative")
        $lines.Add(('  <Component Id="NrrDoc{0}" Subdirectory="{1}" Condition="NRR_DOCS=&quot;1&quot;">' -f $index, $folder))
        $lines.Add(('    <File Id="NrrDocFile{0}" Source="{1}" KeyPath="yes" />' -f $index, $source))
        $lines.Add('  </Component>')
    }
    $lines.Add('</ComponentGroup></Fragment></Wix>')
    [System.IO.File]::WriteAllLines($Destination, [string[]]$lines, (New-Object System.Text.UTF8Encoding $false))
}

# Resolved before the build, so a missing tool fails in seconds, not after it.
$buildExe = $Installers -or $Exe
$buildMsi = $Installers -or $Msi
$buildSymbols = $Zip -or $buildExe -or $buildMsi
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
# The linker names the PDB after the crate-style name: `nrr-cli` -> `nrr_cli.pdb`.
function Get-SymbolsName {
    param([string]$Executable)
    return ([IO.Path]::GetFileNameWithoutExtension($Executable) -replace '-', '_') + '.pdb'
}
# Kept out of the package; they go to the symbols archive.
$symbolFiles = New-Object System.Collections.Generic.List[string]
foreach ($binaryName in $executables) {
    $source = Join-Path $releaseDir $binaryName
    if (-not (Test-Path $source)) {
        throw "'$binaryName' is missing from '$releaseDir'. Run without -SkipBuild."
    }
    Copy-Item -Path $source -Destination $binDir -Force
    $pdb = Join-Path $releaseDir (Get-SymbolsName $binaryName)
    if ($buildSymbols -and -not (Test-Path -LiteralPath $pdb)) {
        throw "'$(Split-Path $pdb -Leaf)' is missing from '$releaseDir'. Run without -SkipBuild."
    }
    $symbolFiles.Add($pdb)
}
Write-Step "copied $($executables.Count) executables"

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
        # Their libraries stay behind in the package root, linked by nothing once
        # the style trees are gone; Quick3DUtils comes with them. NativeStyle is
        # the base of the Windows and macOS styles only. The TLS and network
        # information backends serve Qt networking, which the QML never does, and
        # the generic plugin is TUIO touch over the network.
        $deadLibraries = @('Qt6Quick3DUtils.dll')
        foreach ($style in $unusedStyles) {
            $deadLibraries += "Qt6QuickControls2$style.dll", "Qt6QuickControls2${style}StyleImpl.dll"
        }
        foreach ($name in $deadLibraries) {
            $path = Join-Path $binDir $name
            if (Test-Path $path) {
                $freedBytes += (Get-Item $path).Length
                Remove-Item -Path $path -Force
            }
        }
        $deadTrees = @('qml\QtQuick\NativeStyle', 'tls', 'networkinformation', 'generic')
        foreach ($tree in $deadTrees) {
            $path = Join-Path $binDir $tree
            if (Test-Path $path) {
                $freedBytes += (Get-ChildItem $path -Recurse -File | Measure-Object -Property Length -Sum).Sum
                Remove-Item -Path $path -Recurse -Force
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
        Write-Step ("trimmed unused Qt styles, libraries, plugins and QML tooling: {0:N1} MB" -f ($freedBytes / 1MB))
    }
}

# ── Payload ──────────────────────────────────────────────────────────────────

# Not `<package>\qml`: windeployqt owns that, and the launcher looks for the
# app's QML at exactly `apps\desktop\qml` beside the binary. `assets\` stays
# beside the binary too: the launcher hands that folder to the QML as its root.
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

# ── Offline documentation ────────────────────────────────────────────────────

# docs\<language>\index.html, opened by Help > Documentation. Built for this
# machine, never for -Arch: the converter runs here. A link that reaches
# nothing fails the run.
$docsDir = Join-Path $packageRoot 'docs'
& cargo run --release --locked --quiet -p nrr-docs-html -- --repo $repoRoot --out $docsDir
if ($LASTEXITCODE -ne 0) {
    throw 'The offline documentation did not build: a page links to something that is not there (named above), or Cargo.lock is out of date.'
}
Write-Step 'built the offline documentation'

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
    if ($windeployqt -notmatch '^(?<root>.*\\Qt)\\(?<version>\d+\.\d+\.\d+)\\') {
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
Write-Step "stamped build-info.json ($productVersion, revision $($revision.commit))"

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
that step themselves and put the program in C:\Program Files\NetRuleRouter
or another folder inside Program Files.

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

Questions and problems
----------------------
Questions, discussion and news of new builds, in English and Russian:
https://t.me/netrulerouter
Bugs to be fixed: https://github.com/kroxiksut/net-rule-router/issues - attach
the diagnostic archive (Diagnostics section, or nrr-cli.exe diag export).
Never report a vulnerability in public; see SECURITY.md in the repository.
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
шаг сами и кладут программу в C:\Program Files\NetRuleRouter или другую
папку внутри Program Files.

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

Вопросы и проблемы
------------------
Вопросы, обсуждение и новости о сборках, на русском и английском:
https://t.me/netrulerouter
Ошибки: https://github.com/kroxiksut/net-rule-router/issues - приложите
диагностический архив (раздел «Диагностика» или nrr-cli.exe diag export).
Об уязвимостях не пишите публично; см. SECURITY.md в репозитории.
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

Questions and news: https://t.me/netrulerouter (English and Russian).
Bugs: https://github.com/kroxiksut/net-rule-router/issues - attach the archive
from nrr-cli.exe diag export. Never report a vulnerability in public; see
SECURITY.md in the repository.
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

Вопросы и новости: https://t.me/netrulerouter (на русском и английском).
Ошибки: https://github.com/kroxiksut/net-rule-router/issues - приложите архив
из nrr-cli.exe diag export. Об уязвимостях не пишите публично; см. SECURITY.md
в репозитории.
"@
Set-Content -Path (Join-Path $packageRoot 'README.ru.txt') -Value $readMeRu -Encoding UTF8
}

# ── Verification ─────────────────────────────────────────────────────────────

# Every executable, its symbols and every user script shipped must be on the
# list, or a new one would ship unchecked.
$variant = $(if ($Headless) { 'headless' } else { 'full' })
$requiredSymbols = @(Get-PackageContents -RepoRoot $repoRoot -Variant $variant -Symbols)
$symbolNames = @($symbolFiles | Split-Path -Leaf)
$shipped = @($executables) + @($userScripts | ForEach-Object { "scripts\$_" })
$unlisted = @($shipped | Where-Object { $required -notcontains $_ }) +
    @($symbolNames | Where-Object { $requiredSymbols -notcontains $_ })
if ($unlisted) {
    throw "packaging\windows\package-contents.txt does not list $($unlisted -join ', '), which this script ships."
}
$unshipped = @($requiredSymbols | Where-Object { $symbolNames -notcontains $_ })
if ($unshipped) {
    throw "packaging\windows\package-contents.txt lists the symbols of executables this script does not ship: $($unshipped -join ', ')"
}
$missing = Get-MissingContents -Root $packageRoot -Expected $required
if ($missing) {
    throw "Package is incomplete, missing: $($missing -join ', ')"
}
$strayPdb = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File -Filter '*.pdb')
if ($strayPdb) {
    throw "A package carries no debug symbols, found: $(($strayPdb | ForEach-Object { $_.FullName.Substring($packageRoot.Length + 1) }) -join ', ')"
}

$totalBytes = (Get-ChildItem -Path $packageRoot -Recurse -File | Measure-Object -Property Length -Sum).Sum
$totalFiles = (Get-ChildItem -Path $packageRoot -Recurse -File | Measure-Object).Count

# The version alone names the files; the commit is in build-info.json, and two
# builds of one version share names.
$artifactBase = "NetRuleRouter-windows-$Arch-$productVersion" + $(if ($Headless) { '-headless' } else { '' })
$artifacts = New-Object System.Collections.Generic.List[string]

if ($buildSymbols) {
    $symbolsPath = Join-Path $OutputRoot "$artifactBase-symbols.zip"
    if (Test-Path -LiteralPath $symbolsPath) {
        Remove-Item -LiteralPath $symbolsPath -Force
    }
    Write-Step 'compressing the debug symbols'
    Compress-Archive -LiteralPath @($symbolFiles) -DestinationPath $symbolsPath -CompressionLevel Optimal
    Write-Host ("[package] symbols: {0} ({1:N1} MB)" -f $symbolsPath, ((Get-Item -LiteralPath $symbolsPath).Length / 1MB)) -ForegroundColor Green
    $artifacts.Add($symbolsPath)
}

if ($Zip) {
    $archivePath = Join-Path $OutputRoot "$artifactBase-portable.zip"
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
    # full version still names the files and shows in Apps & Features. The
    # numbers come from the service binary, whose fourth field is the
    # pre-release (packaging/windows/version_rank.rs): read back, not derived
    # a second time. Windows Installer compares three fields, so there the
    # pre-release joins the third.
    $numericVersion = ($productVersion -split '[-+]')[0]
    $fileVersion = (Get-Item -LiteralPath (Join-Path $binDir 'nrr-service.exe')).VersionInfo.FileVersionRaw
    if ($null -eq $fileVersion -or "$($fileVersion.Major).$($fileVersion.Minor).$($fileVersion.Build)" -ne $numericVersion) {
        throw "nrr-service.exe carries version '$fileVersion', not the $numericVersion of '$productVersion'."
    }
    $exeVersion = "$numericVersion.$($fileVersion.Revision)"
    $msiVersion = "$($fileVersion.Major).$($fileVersion.Minor).$($fileVersion.Build * 100 + $fileVersion.Revision)"

    # The agreement each wizard asks the installing person to accept, in the
    # wizard's language, and the wizards' pictures. The first culture is the
    # MSI's own; the others ride inside it as language transforms.
    $installerCultures = @(
        @{ Culture = 'en-US'; Lcid = 1033; Agreement = 'docs\legal\eula.en.md' },
        @{ Culture = 'ru-RU'; Lcid = 1049; Agreement = 'docs\legal\eula.ru.md' }
    )
    $resourceDir = Join-Path ([System.IO.Path]::GetTempPath()) "nrr-installer-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $resourceDir -Force | Out-Null
    foreach ($culture in $installerCultures) {
        $agreement = Join-Path $repoRoot $culture.Agreement
        $culture.Rtf = Join-Path $resourceDir "eula.$($culture.Culture).rtf"
        ConvertFrom-AgreementMarkdown -Source $agreement -Destination $culture.Rtf
        ConvertFrom-AgreementMarkdown -Source $agreement -Destination (Join-Path $resourceDir "eula.$($culture.Culture).exe.rtf") -LinkFields
    }
    $agreementRevisions = @($installerCultures | ForEach-Object { Get-AgreementRevision -Source (Join-Path $repoRoot $_.Agreement) } | Sort-Object -Unique)
    if ($agreementRevisions.Count -ne 1) {
        throw "The agreement's translations name different revisions: $($agreementRevisions -join ', ')."
    }
    $agreementVersion = $agreementRevisions[0]
    $installerImages = New-InstallerImages -Folder $resourceDir
    Write-Step 'rendered the agreement and the wizard pictures'
}

try {
if ($buildExe) {
    $setupName = "$artifactBase-setup"
    $setupPath = Join-Path $OutputRoot "$setupName.exe"
    if (Test-Path -LiteralPath $setupPath) {
        Remove-Item -LiteralPath $setupPath -Force
    }
    Write-Step "building the EXE installer with '$iscc'"
    & $iscc '/Q' "/DPackageDir=$packageRoot" "/DAppVersion=$productVersion" "/DVersionNumeric=$exeVersion" "/DArch=$Arch" `
        "/DVariant=$(if ($Headless) { 'headless' } else { 'full' })" `
        "/DAgreementEn=$(Join-Path $resourceDir 'eula.en-US.exe.rtf')" `
        "/DAgreementRu=$(Join-Path $resourceDir 'eula.ru-RU.exe.rtf')" `
        "/DAgreementVersion=$agreementVersion" `
        "/DWizardImages=$($installerImages.Wizard -join ',')" `
        "/DWizardSmallImages=$($installerImages.WizardSmall -join ',')" `
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
    $workDir = Join-Path $resourceDir 'msi'
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    # One product code for every culture's build: a transform between two
    # products would not be a language transform.
    $productCode = [guid]::NewGuid().ToString('B').ToUpperInvariant()
    $estimatedSizeKb = [int][Math]::Ceiling($totalBytes / 1KB)
    $base = $installerCultures[0]
    $transforms = @{}
    $docsFragment = Join-Path $workDir 'docs-files.wxs'
    Write-DocsFragment -PackageRoot $packageRoot -Destination $docsFragment
    foreach ($culture in $installerCultures) {
        $cultureDir = Join-Path $workDir $culture.Culture
        $output = if ($culture -eq $base) { $msiPath } else { Join-Path $cultureDir 'NetRuleRouter.msi' }
        $wixArguments = @('build', '-arch', $Arch, '-bindpath', "pkg=$packageRoot",
            '-culture', $culture.Culture, '-loc', (Join-Path $installerSources "NetRuleRouter.$($culture.Culture).wxl"),
            '-d', "Version=$msiVersion", '-d', "DisplayVersion=$productVersion", '-d', "ProductCode=$productCode",
            '-d', "LicenseRtf=$($culture.Rtf)",
            '-d', "AgreementVersion=$agreementVersion",
            '-d', "BannerBmp=$($installerImages.Banner)", '-d', "DialogBmp=$($installerImages.Dialog)",
            '-d', "EstimatedSizeKb=$estimatedSizeKb",
            '-d', "Variant=$(if ($Headless) { 'headless' } else { 'full' })",
            '-intermediatefolder', $cultureDir, '-pdb', (Join-Path $cultureDir 'NetRuleRouter.wixpdb'),
            '-cc', (Join-Path $workDir 'cabinets'), '-o', $output)
        foreach ($extension in $wixExtensions) {
            $wixArguments += @('-ext', "$extension/$wixVersion")
        }
        $wixArguments += @((Join-Path $installerSources 'NetRuleRouter.wxs'), $docsFragment)
        Write-Step "building the $($culture.Culture) MSI with '$wix'"
        & $wix @wixArguments
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $output)) {
            throw "WiX failed to build the $($culture.Culture) MSI."
        }
        if ($culture -ne $base) {
            $transform = Join-Path $cultureDir "$($culture.Lcid).mst"
            & $wix @('msi', 'transform', '-t', 'language', '-intermediateFolder', $cultureDir, '-out', $transform, $msiPath, $output)
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $transform)) {
                throw "WiX failed to make the $($culture.Culture) language transform."
            }
            Test-LanguageTransform -Msi $msiPath -Transform $transform -Culture $culture -Copy (Join-Path $cultureDir 'applied.msi')
            $transforms[$culture.Lcid] = $transform
        }
    }
    Add-LanguageTransforms -Msi $msiPath -Transforms $transforms -BaseLanguage $base.Lcid
    Write-Step "embedded the $(@($installerCultures | Select-Object -Skip 1 | ForEach-Object { $_.Culture }) -join ', ') wizard"
    Write-Host ("[package] MSI: {0} ({1:N1} MB)" -f $msiPath, ((Get-Item $msiPath).Length / 1MB)) -ForegroundColor Green
    $artifacts.Add($msiPath)
}
} finally {
    if ($buildExe -or $buildMsi) {
        Remove-Item -LiteralPath $resourceDir -Recurse -Force -ErrorAction SilentlyContinue
    }
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
