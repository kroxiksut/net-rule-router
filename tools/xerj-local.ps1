param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('start', 'status', 'update', 'search', 'def', 'stop')]
    [string]$Action,

    [Parameter(Position = 1)]
    [string]$Value,

    [string]$Prefix = 'nrr-all'
)

$ErrorActionPreference = 'Stop'

$xerjVersion = '1.0.0-rc.100'
$xerjRoot = Join-Path $env:LOCALAPPDATA 'Programs\xerj'
$xerjExe = Join-Path $xerjRoot 'xerj.exe'
$dataDir = Join-Path $env:USERPROFILE 'xerj-data'
$pidFile = Join-Path $dataDir 'netrulerouter-node.pid'
$stdoutLog = Join-Path $dataDir 'netrulerouter-node.stdout.log'
$stderrLog = Join-Path $dataDir 'netrulerouter-node.stderr.log'
$nodeUrl = 'http://127.0.0.1:19200'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Assert-XerjInstalled {
    if (-not (Test-Path -LiteralPath $xerjExe -PathType Leaf)) {
        throw "XERJ $xerjVersion is not installed at $xerjExe"
    }

    $reportedVersion = (& $xerjExe --version).Trim()
    if ($reportedVersion -ne "xerj v$xerjVersion") {
        throw "Expected xerj v$xerjVersion, found: $reportedVersion"
    }
}

function Get-ManagedNodeProcess {
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
        return $null
    }

    $nodePid = 0
    if (-not [int]::TryParse((Get-Content -Raw -LiteralPath $pidFile).Trim(), [ref]$nodePid)) {
        return $null
    }

    $process = Get-Process -Id $nodePid -ErrorAction SilentlyContinue
    if ($null -eq $process -or $process.ProcessName -ne 'xerj') {
        return $null
    }

    try {
        $actualPath = [System.IO.Path]::GetFullPath($process.Path)
        $expectedPath = [System.IO.Path]::GetFullPath($xerjExe)
        if (-not $actualPath.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $null
        }
    }
    catch {
        return $null
    }

    return $process
}

function Get-ApiKey {
    $keyFile = Join-Path $dataDir 'admin.key'
    if (-not (Test-Path -LiteralPath $keyFile -PathType Leaf)) {
        throw "XERJ API key is missing at $keyFile; start the node first"
    }

    return (Get-Content -Raw -LiteralPath $keyFile).Trim()
}

function Test-Node {
    try {
        $key = Get-ApiKey
        Invoke-RestMethod -Uri "$nodeUrl/" -Headers @{ Authorization = "ApiKey $key" } -TimeoutSec 2 | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Start-Node {
    Assert-XerjInstalled
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    if (Test-Node) {
        Write-Output "XERJ is already running ($nodeUrl)"
        return
    }

    $process = Start-Process -FilePath $xerjExe -ArgumentList @(
        '--data-dir', $dataDir,
        '--bind', '127.0.0.1',
        '--port', '19200',
        '--embed-mode', 'lexical',
        '--disable-feedback'
    ) -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru

    Set-Content -LiteralPath $pidFile -Value $process.Id -Encoding ascii
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if (Test-Node) {
            Write-Output "XERJ started (PID $($process.Id), $nodeUrl, lexical, feedback disabled)"
            return
        }
        Start-Sleep -Milliseconds 500
    }

    throw "XERJ did not become ready; inspect $stderrLog"
}

function Stop-Node {
    $process = Get-ManagedNodeProcess
    if ($null -eq $process) {
        if (Test-Node) {
            Write-Output 'XERJ was started elsewhere and was left running'
        }
        else {
            Write-Output 'XERJ is not running'
        }
        return
    }

    Stop-Process -Id $process.Id
    Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
    Write-Output "XERJ stopped (PID $($process.Id))"
}

function Invoke-Autoindex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,
        [Parameter(Mandatory = $true)]
        [string]$IndexPrefix,
        [Parameter(Mandatory = $true)]
        [string]$StateName,
        [switch]$NoSemantic
    )

    $env:XERJ_API_KEY = Get-ApiKey
    $env:XERJ_DISABLE_FEEDBACK = 'true'
    $arguments = @(
        'autoindex', $Source,
        '--url', $nodeUrl,
        '--prefix', $IndexPrefix,
        '--state-dir', (Join-Path $dataDir "state\$StateName"),
        '--no-graph',
        '--progress', 'plain'
    )
    if ($NoSemantic) {
        $arguments += '--no-semantic'
    }
    else {
        $arguments += @('--plan', 'code-and-docs', '--code-analyzer', 'code')
    }

    & $xerjExe @arguments
    if ($LASTEXITCODE -notin 0, 3) {
        throw "XERJ autoindex failed with exit code $LASTEXITCODE"
    }
}

function Update-Indices {
    if (-not (Test-Node)) {
        throw 'XERJ is not running; run tools/xerj-local.ps1 start first'
    }

    Invoke-Autoindex -Source $repoRoot -IndexPrefix 'nrr-all' -StateName 'nrr-all'

    $planningSource = Join-Path $dataDir 'sources\nrr-planning'
    New-Item -ItemType Directory -Force -Path $planningSource | Out-Null
    foreach ($name in @('TASKS_RU.md', 'TASKS_GIT_RU.md', 'FEATURES.md')) {
        $sourceFile = Join-Path $repoRoot $name
        $destinationFile = Join-Path $planningSource $name
        if (Test-Path -LiteralPath $sourceFile -PathType Leaf) {
            Copy-Item -LiteralPath $sourceFile -Destination $destinationFile -Force
        }
        elseif (Test-Path -LiteralPath $destinationFile -PathType Leaf) {
            Remove-Item -LiteralPath $destinationFile -Force
        }
    }
    Invoke-Autoindex -Source $planningSource -IndexPrefix 'nrr-planning' -StateName 'nrr-planning' -NoSemantic
}

Assert-XerjInstalled
$env:XERJ_DISABLE_FEEDBACK = 'true'

switch ($Action) {
    'start' { Start-Node }
    'status' {
        if (Test-Node) {
            Write-Output "XERJ is ready ($nodeUrl)"
        }
        else {
            Write-Output 'XERJ is stopped or unhealthy'
            exit 1
        }
    }
    'update' { Update-Indices }
    'search' {
        if ([string]::IsNullOrWhiteSpace($Value)) { throw 'search requires a query' }
        $env:XERJ_API_KEY = Get-ApiKey
        & $xerjExe search --url $nodeUrl --prefix $Prefix $Value
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    'def' {
        if ([string]::IsNullOrWhiteSpace($Value)) { throw 'def requires a symbol' }
        $env:XERJ_API_KEY = Get-ApiKey
        & $xerjExe def --url $nodeUrl --prefix $Prefix $Value
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    'stop' { Stop-Node }
}
