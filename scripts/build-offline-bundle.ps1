<#
.SYNOPSIS
    Builds a self-contained bundle that runs the SBOM Platform on a machine with
    no internet connection.

.DESCRIPTION
    Produces a folder containing every container image (PostgreSQL, the API, and
    the nginx-served frontend) plus the compose file and start scripts. Copy the
    folder to the offline machine and run start.ps1 or start.sh there.

    The target needs Docker and nothing else — no Node, no npm registry access,
    no PostgreSQL install, and no compiler for the argon2 native module.

    Run this on a machine WITH internet, since building pulls base images and
    npm packages.

.EXAMPLE
    .\scripts\build-offline-bundle.ps1
    .\scripts\build-offline-bundle.ps1 -OutputRoot D:\transfer -Compress
#>
[CmdletBinding()]
param(
    # Where the bundle folder is created.
    [string]$OutputRoot = "./dist-offline",
    # Image tag. Defaults to the version in the root package.json.
    [string]$Version,
    # Also produce a single .zip alongside the folder.
    [switch]$Compress,
    # Skip `docker build` and only re-package images already present locally.
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }

<#
    Runs docker and decides success from the exit code.

    Two Windows PowerShell 5.1 hazards are handled here, and both are silent
    until they bite:

      1. docker writes its build progress to stderr even on a completely
         successful build. With $ErrorActionPreference = "Stop", PowerShell
         wraps each of those lines in a NativeCommandError and terminates the
         script — so a working build looks like a crash. The preference is
         lowered for the duration of the call and restored afterwards.

      2. Arguments are taken as one explicit array rather than via
         ValueFromRemainingArguments, because PowerShell tries to bind leading
         `-x` tokens as parameters of this function first, which makes any call
         containing docker flags fail with "a parameter cannot be found".

    The exit code is the only signal trusted for success or failure.
#>
function Invoke-Docker {
    param(
        [Parameter(Mandatory)][string[]]$DockerArgs,
        [string]$FailureMessage = "docker command failed"
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker @DockerArgs
        if ($LASTEXITCODE -ne 0) { throw "$FailureMessage (exit code $LASTEXITCODE)" }
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

<# True when an image is present locally. Never throws — it is a probe. #>
function Test-DockerImage {
    param([Parameter(Mandatory)][string]$Image)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & docker image inspect $Image *> $null
        return $LASTEXITCODE -eq 0
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

# --- preflight -------------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed, or docker.exe is not on PATH."
}
Invoke-Docker @("info", "--format", "{{.ServerVersion}}") `
    "Docker is installed but the daemon is not running. Start Docker Desktop and try again." | Out-Null

if (-not $Version) {
    $Version = (Get-Content (Join-Path $repoRoot "package.json") | ConvertFrom-Json).version
}

$postgresImage = "postgres:16-alpine"
$apiImage = "sbom-platform/api:$Version"
$webImage = "sbom-platform/web:$Version"

# linux/amd64 explicitly. Building on an arm64 machine would otherwise produce
# arm images that fail to start on a typical x86 server with an error
# ("exec format error") that gives no hint about the cause.
$platform = "linux/amd64"

Write-Host ""
Write-Host "SBOM Platform — offline bundle" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Note "version   $Version"
Write-Note "platform  $platform"

# --- 1. build ---------------------------------------------------------------
if (-not $SkipBuild) {
    Write-Step "Building the API image"
    Invoke-Docker @("build", "--platform", $platform, "-f", "packages/api/Dockerfile", "-t", $apiImage, ".") `
        "API image build failed."

    Write-Step "Building the web image"
    Invoke-Docker @("build", "--platform", $platform, "-f", "packages/web/Dockerfile", "-t", $webImage, ".") `
        "Web image build failed."

    Write-Step "Pulling PostgreSQL"
    Invoke-Docker @("pull", "--platform", $platform, $postgresImage) `
        "Could not pull $postgresImage. This machine needs internet access to build a bundle."
}
else {
    Write-Step "Skipping build, using local images"
    foreach ($image in @($apiImage, $webImage, $postgresImage)) {
        if (-not (Test-DockerImage $image)) {
            throw "Image $image is not present locally; run without -SkipBuild."
        }
    }
}

# --- 2. assemble the bundle folder -----------------------------------------
$bundleName = "sbom-platform-offline-$Version"
$bundleDir = Join-Path $OutputRoot $bundleName

if (Test-Path $bundleDir) {
    Write-Step "Clearing the previous bundle"
    Remove-Item $bundleDir -Recurse -Force
}
New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null

Write-Step "Copying the deployment files"
# Two-argument Join-Path only: the three-argument form is PowerShell 7+, and
# this script has to run under the Windows PowerShell 5.1 that ships with
# Windows.
$deployDir = Join-Path $repoRoot "deploy"
foreach ($file in @("docker-compose.yml", "start.ps1", "start.sh", "README.md")) {
    $source = Join-Path $deployDir $file
    if (-not (Test-Path $source)) { throw "Missing deployment file: $source" }
    Copy-Item $source (Join-Path $bundleDir $file)
    Write-Note $file
}

# The compose file resolves image tags from these, so a bundle built at one
# version cannot accidentally start a differently-tagged image left on the host.
@"
SBOM_IMAGE_API=$apiImage
SBOM_IMAGE_WEB=$webImage
"@ | Out-File -FilePath (Join-Path $bundleDir "images.env") -Encoding ascii

# Read by the start scripts to decide whether `docker load` is needed at all,
# which turns a one-minute wait into an instant start on every run after the
# first.
@"
$postgresImage
$apiImage
$webImage
"@ | Out-File -FilePath (Join-Path $bundleDir "images.txt") -Encoding ascii

# --- 3. save the images -----------------------------------------------------
Write-Step "Saving images to a single archive (this is the slow part)"
$archive = Join-Path $bundleDir "images.tar"
Invoke-Docker @("save", "--output", $archive, $postgresImage, $apiImage, $webImage) "docker save failed."

$archiveSize = (Get-Item $archive).Length / 1MB
Write-Note ("images.tar — {0:N0} MB" -f $archiveSize)

# --- 4. optional single-file archive ---------------------------------------
if ($Compress) {
    Write-Step "Compressing the bundle"
    $zipPath = Join-Path $OutputRoot "$bundleName.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    # Optimal rather than Fastest: this is copied to a machine once and the
    # image layers compress well, so the extra minutes are worth the smaller
    # file on a USB stick or a slow share.
    Compress-Archive -Path "$bundleDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    $zipSize = (Get-Item $zipPath).Length / 1MB
    Write-Note ("{0} — {1:N0} MB" -f (Split-Path $zipPath -Leaf), $zipSize)
}

# --- done -------------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Host "Bundle ready" -ForegroundColor Green
Write-Host ""
Write-Host "  $((Resolve-Path $bundleDir).Path)" -ForegroundColor White
Write-Host ""
Write-Host "On the offline machine:" -ForegroundColor Yellow
Write-Host "  1. Copy the whole folder across" -ForegroundColor White
Write-Host "  2. Windows:  .\start.ps1" -ForegroundColor White
Write-Host "     Linux:    ./start.sh" -ForegroundColor White
Write-Host "  3. Open http://localhost:8080 and sign in with CREDENTIALS.txt" -ForegroundColor White
Write-Host ""
Write-Note "No secrets are in this bundle. The start script generates them per machine."
Write-Note "If you test-run it here first, delete the .env and CREDENTIALS.txt it writes"
Write-Note "before copying the folder onward, or every target shares one signing key."
