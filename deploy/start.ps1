<#
.SYNOPSIS
    Starts the SBOM Platform on an offline machine. Windows / PowerShell.

.DESCRIPTION
    Loads the bundled container images, generates per-deployment secrets on the
    first run, and brings the stack up. Safe to run repeatedly — loading images
    and starting an already-running stack are both idempotent.

    Requires only Docker. No internet, no Node, no PostgreSQL install.

.EXAMPLE
    .\start.ps1
    .\start.ps1 -Port 9000
#>
[CmdletBinding()]
param(
    # Host port for the web UI.
    [int]$Port = 8080,
    # Re-load images even if they are already present.
    [switch]$ForceLoad
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }

<#
    Runs docker and decides success from the exit code alone.

    Windows PowerShell 5.1 wraps anything a native command writes to stderr in a
    NativeCommandError, and with $ErrorActionPreference = "Stop" that terminates
    the script. `docker load` and `docker compose up` both write their normal
    progress to stderr, so without this a completely successful start would look
    like a crash. The preference is lowered for the call and restored after.

    Arguments come in as one explicit array rather than via
    ValueFromRemainingArguments, which PowerShell would try to bind as this
    function's own parameters as soon as one of them starts with a dash.
#>
function Invoke-Docker {
    param(
        [Parameter(Mandatory)][string[]]$DockerArgs,
        [switch]$Quiet
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($Quiet) {
            & docker @DockerArgs *> $null
        }
        else {
            # Two things are going on in this one line.
            #
            # `2>&1 | ForEach-Object { Write-Host $_ }` — docker writes its
            # normal progress ("Container ... Started") to stderr, and Windows
            # PowerShell renders anything a native command puts on stderr as a
            # red NativeCommandError. Left alone, a completely successful start
            # looks alarming to whoever runs this. Merging the streams and
            # stringifying each record prints them as the ordinary status lines
            # they are.
            #
            # Write-Host rather than returning them — a bare `& docker` would
            # put every output line on this function's output stream, so the
            # caller would receive an array of strings with the exit code
            # appended instead of the integer it compares against. `-ne 0` on
            # that array is truthy, and a successful `docker load` reports as a
            # failure.
            & docker @DockerArgs 2>&1 | ForEach-Object { Write-Host $_ }
        }
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

# --- preflight -------------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed, or docker.exe is not on PATH." -ForegroundColor Red
    Write-Host "Install Docker Desktop (or Docker Engine) and run this again." -ForegroundColor Yellow
    exit 1
}

# `docker info` fails when the CLI is present but the daemon is not running,
# which is the single most common reason this script would otherwise produce a
# confusing error twenty seconds later.
if ((Invoke-Docker @("info", "--format", "{{.ServerVersion}}") -Quiet) -ne 0) {
    Write-Host "Docker is installed but the daemon is not running." -ForegroundColor Red
    Write-Host "Start Docker Desktop (or 'sudo systemctl start docker') and run this again." -ForegroundColor Yellow
    exit 1
}

# Compose v2 is a docker subcommand. v1 (`docker-compose`) is not supported.
if ((Invoke-Docker @("compose", "version") -Quiet) -ne 0) {
    Write-Host "'docker compose' is unavailable. This needs Compose v2, which ships with Docker Desktop." -ForegroundColor Red
    exit 1
}

# --- 1. load the bundled images -------------------------------------------
$manifest = Join-Path $PSScriptRoot "images.txt"
$archive = Join-Path $PSScriptRoot "images.tar"

if (-not (Test-Path $archive)) {
    Write-Host "images.tar is missing from this folder." -ForegroundColor Red
    Write-Host "Copy the whole bundle directory across, not just the scripts." -ForegroundColor Yellow
    exit 1
}

$needsLoad = $ForceLoad.IsPresent
if (-not $needsLoad) {
    if (Test-Path $manifest) {
        foreach ($image in Get-Content $manifest | Where-Object { $_.Trim() }) {
            if ((Invoke-Docker @("image", "inspect", $image.Trim()) -Quiet) -ne 0) {
                $needsLoad = $true
                break
            }
        }
    }
    else { $needsLoad = $true }
}

if ($needsLoad) {
    Write-Step "Loading container images (this takes a minute on first run)"
    if ((Invoke-Docker @("load", "--input", $archive)) -ne 0) {
        Write-Host "docker load failed." -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Step "Images already loaded"
}

# --- 2. generate per-deployment secrets on first run ----------------------
$envPath = Join-Path $PSScriptRoot ".env"

<#
    Generates a random secret of an exact character length.

    Takes a character count, not a byte count: stripping `+/=` out of base64
    removes an unpredictable number of characters, so deriving the length from
    the input size is wrong. An earlier version did exactly that and crashed
    when a short secret produced fewer characters than it then tried to slice.
#>
function New-Secret {
    param([int]$Length = 44, [switch]$Hex)

    # Cryptographic RNG, not Get-Random — these are a session-signing key and a
    # CI credential, and Get-Random is a seeded PRNG that must never be used
    # for either.
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    if ($Hex) {
        $buffer = New-Object byte[] ([int][math]::Ceiling($Length / 2.0))
        $rng.GetBytes($buffer)
        return (-join ($buffer | ForEach-Object { $_.ToString("x2") })).Substring(0, $Length)
    }

    # Base64 minus the characters that make a value awkward to paste into a
    # shell or a CI variable field. Loops because that stripping is lossy.
    $chars = ""
    while ($chars.Length -lt $Length) {
        $buffer = New-Object byte[] 48
        $rng.GetBytes($buffer)
        $chars += ([Convert]::ToBase64String($buffer) -replace '[+/=]', '')
    }
    return $chars.Substring(0, $Length)
}

if (-not (Test-Path $envPath)) {
    Write-Step "First run — generating secrets for this deployment"

    $sessionSecret = New-Secret -Length 64
    $ingestToken = New-Secret -Length 64 -Hex
    # Comfortably over the 12-character minimum the API enforces.
    $adminPassword = New-Secret -Length 20

    # Secrets are generated here rather than shipped in the bundle, so copying
    # the bundle to two machines produces two independent deployments instead of
    # two machines sharing a session-signing key.
    @"
# Generated on first run by start.ps1. Keep this file; losing SESSION_SECRET
# signs everyone out, and losing INGEST_TOKENS breaks every CI pipeline.
#
# This file is per-deployment. Do NOT copy it to another machine.

# Host port for the web UI.
SBOM_PORT=$Port

# The address people will actually browse to. Change if this machine is
# reached by hostname or IP rather than localhost, e.g.
#   PUBLIC_URL=http://sbom.internal.example.com:8080
PUBLIC_URL=http://localhost:$Port

SESSION_SECRET=$sessionSecret

# Bearer token for CI/CD: POST /api/v1/scans
INGEST_TOKENS=ci:$ingestToken

# The first admin account, created on first startup only.
BOOTSTRAP_ADMIN_EMAIL=admin@sbom.local
BOOTSTRAP_ADMIN_PASSWORD=$adminPassword

# Postgres password. Only reachable inside the compose network.
POSTGRES_PASSWORD=$(New-Secret -Length 32)

# An application with no scan in this many days is flagged stale.
STALE_APP_THRESHOLD_DAYS=30
LOG_LEVEL=info
"@ | Out-File -FilePath $envPath -Encoding ascii

    $credentials = Join-Path $PSScriptRoot "CREDENTIALS.txt"
    @"
SBOM Platform — generated $(Get-Date -Format "yyyy-MM-dd HH:mm")

Web UI          http://localhost:$Port
Sign in         admin@sbom.local
Password        $adminPassword

CI ingest token $ingestToken
                Send as: Authorization: Bearer <token>
                Endpoint: http://localhost:$Port/api/v1/scans

Change the admin password after signing in (click your email, top right).
These values are also in .env. Delete this file once you have stored them.
"@ | Out-File -FilePath $credentials -Encoding ascii

    Write-Note "Wrote .env and CREDENTIALS.txt"
}
else {
    Write-Step "Using the existing .env"
    # An explicit -Port overrides what the file says, so the flag is not
    # silently ignored on a machine that has already been started once.
    if ($PSBoundParameters.ContainsKey('Port')) {
        $content = Get-Content $envPath
        if ($content -match '^SBOM_PORT=') {
            $content -replace '^SBOM_PORT=.*', "SBOM_PORT=$Port" | Out-File $envPath -Encoding ascii
            Write-Note "Port set to $Port"
        }
    }
}

# --- 3. start --------------------------------------------------------------
# Image tags come from images.env, written by the bundle builder. Exported as
# environment variables rather than merged into .env: compose gives real
# environment variables precedence, so a bundle always starts the images it
# actually shipped even if an older .env on this machine names different tags.
$imagesEnv = Join-Path $PSScriptRoot "images.env"
if (Test-Path $imagesEnv) {
    foreach ($line in Get-Content $imagesEnv) {
        if ($line -match '^\s*([A-Z_][A-Z0-9_]*)=(.*)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2].Trim()
        }
    }
}

Write-Step "Starting the stack"
if ((Invoke-Docker @("compose", "up", "-d")) -ne 0) {
    Write-Host "docker compose up failed. See the output above." -ForegroundColor Red
    exit 1
}

# --- 4. wait until it actually serves --------------------------------------
# "Containers created" is not "the application is usable": the API migrates and
# seeds the database on first boot, which takes a few seconds longer.
$effectivePort = (Get-Content $envPath | Select-String '^SBOM_PORT=').ToString().Split('=')[1]
if (-not $effectivePort) { $effectivePort = $Port }

Write-Step "Waiting for the application to become ready"
$ready = $false
foreach ($attempt in 1..60) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$effectivePort/health" -UseBasicParsing -TimeoutSec 3
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    }
    catch { Start-Sleep -Seconds 2 }
}

Write-Host ""
if ($ready) {
    Write-Host "SBOM Platform is running." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Open        http://localhost:$effectivePort" -ForegroundColor White
    if (Test-Path (Join-Path $PSScriptRoot "CREDENTIALS.txt")) {
        Write-Host "  Sign in     see CREDENTIALS.txt in this folder" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  Logs        docker compose logs -f" -ForegroundColor DarkGray
    Write-Host "  Stop        docker compose down          (data is kept)" -ForegroundColor DarkGray
    Write-Host "  Erase all   docker compose down -v       (deletes every scan)" -ForegroundColor DarkGray
}
else {
    Write-Host "The stack started but did not answer on port $effectivePort within two minutes." -ForegroundColor Yellow
    Write-Host "Check the logs:  docker compose logs --tail=80" -ForegroundColor Yellow
    exit 1
}
