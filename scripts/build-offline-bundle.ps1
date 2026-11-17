<#
.SYNOPSIS
    Builds a self-contained bundle that runs the SBOM Platform on a machine with
    no internet connection.

.DESCRIPTION
    Produces a folder containing every container image (PostgreSQL, the API, and
    the nginx-served frontend) plus the compose file and start scripts. Copy the
    folder to the offline machine and run start.ps1 or start.sh there.

    The target needs Docker and nothing else - no Node, no npm registry access,
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
    [switch]$SkipBuild,
    # Leave out the Windows Server installer and its Linux disk (about 1.3 GB).
    [switch]$NoWindows
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }

<#
    Writes text with Unix line endings and no byte-order mark.

    images.env and images.txt are read by start.sh on Linux as well as by start.ps1. Written
    the PowerShell way they end every line in CRLF, and `read` in sh keeps the CR: each image
    name then carries a stray character, `docker image inspect` fails for all of them, and the
    exported tags name images that do not exist. start.ps1 trims and never noticed.
#>
function Write-LfFile {
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Text, [Parameter(Mandatory)][string]$Path)
    $lf = ($Text -replace "`r`n", "`n").TrimEnd("`n") + "`n"
    [IO.File]::WriteAllText($Path, $lf, (New-Object Text.UTF8Encoding $false))
}

<#
    Runs docker and decides success from the exit code.

    Two Windows PowerShell 5.1 hazards are handled here, and both are silent
    until they bite:

      1. docker writes its build progress to stderr even on a completely
         successful build. With $ErrorActionPreference = "Stop", PowerShell
         wraps each of those lines in a NativeCommandError and terminates the
         script - so a working build looks like a crash. The preference is
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

<# True when an image is present locally. Never throws - it is a probe. #>
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
Write-Host "SBOM Platform - offline bundle" -ForegroundColor Cyan
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

<#
  The Linux installer: scripts, systemd units, and a Docker Engine for servers that have none.

  Docker ships as its static binaries plus the Compose plugin, downloaded here on the build
  machine and checked against the SHA-256 pinned in deploy/linux/docker/VERSIONS, so a server
  never fetches Docker from a package repository. Cached under var/docker-static between builds.
#>
$linuxSource = Join-Path $deployDir "linux"
$linuxTarget = Join-Path $bundleDir "linux"
New-Item -ItemType Directory -Path (Join-Path $linuxTarget "docker") -Force | Out-Null
# Rewritten with LF rather than copied: a Windows checkout may hold CRLF, and a CR at the
# end of every line breaks both sh and systemd on the server.
Get-ChildItem $linuxSource -File | ForEach-Object {
    [IO.File]::ReadAllText($_.FullName) | Write-LfFile -Path (Join-Path $linuxTarget $_.Name)
}
Get-ChildItem (Join-Path $linuxSource "docker") -File | Where-Object { $_.Name -ne "VERSIONS" } |
    ForEach-Object { [IO.File]::ReadAllText($_.FullName) | Write-LfFile -Path (Join-Path $linuxTarget "docker\$($_.Name)") }

$pins = @{}
foreach ($line in Get-Content (Join-Path $linuxSource "docker\VERSIONS")) {
    if ($line -match '^\s*([A-Z0-9_]+)=(\S+)') { $pins[$Matches[1]] = $Matches[2] }
}
$cache = Join-Path $repoRoot "var\docker-static"
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$downloads = @(
    @{ Name = "docker-$($pins.DOCKER_VERSION).tgz"; Sha = $pins.DOCKER_SHA256
       Url = "https://download.docker.com/linux/static/stable/x86_64/docker-$($pins.DOCKER_VERSION).tgz" },
    @{ Name = "docker-compose-linux-x86_64"; Sha = $pins.COMPOSE_SHA256
       Url = "https://github.com/docker/compose/releases/download/v$($pins.COMPOSE_VERSION)/docker-compose-linux-x86_64" }
)
$sums = @()
foreach ($d in $downloads) {
    $file = Join-Path $cache $d.Name
    $have = (Test-Path $file) -and ((Get-FileHash $file -Algorithm SHA256).Hash.ToLower() -eq $d.Sha)
    if (-not $have) {
        Write-Note "downloading $($d.Name)"
        & curl.exe -sfL --max-time 600 -o $file $d.Url
        if ($LASTEXITCODE -ne 0) { throw "Could not download $($d.Url)." }
        $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
        if ($hash -ne $d.Sha) {
            Remove-Item $file -Force
            throw "$($d.Name) has SHA-256 $hash, but deploy/linux/docker/VERSIONS pins $($d.Sha). Not using it."
        }
    }
    Copy-Item $file (Join-Path $linuxTarget "docker\$($d.Name)")
    $sums += "$($d.Sha)  $($d.Name)"
}
# Read by `sha256sum -c` on the server, so LF and no byte-order mark.
($sums -join "`n") | Write-LfFile -Path (Join-Path $linuxTarget "docker\SHA256SUMS")
Write-Note "linux/ (installer, Docker $($pins.DOCKER_VERSION), Compose $($pins.COMPOSE_VERSION))"

<#
  The certificate directory, which compose bind-mounts.

  Omitted from the bundle originally, on the assumption that Docker creates a missing
  bind-mount source. It does -- tested -- so nothing was broken by its absence, which is
  exactly why it went unnoticed. What was lost is the README inside it explaining where to
  put a corporate root certificate, on the one kind of deployment most likely to need it.
#>
$caSource = Join-Path $deployDir "ca"
if (Test-Path $caSource) {
    $caTarget = Join-Path $bundleDir "ca"
    New-Item -ItemType Directory -Path $caTarget -Force | Out-Null
    Get-ChildItem $caSource -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $caTarget $_.Name)
    }
    Write-Note "ca/"
}

<#
  A launcher that runs where start.ps1 cannot.

  PowerShell's execution policy governs script *files*, not commands typed into a console.
  On a machine set to AllSigned -- which is a real and reasonable corporate setting --
  start.ps1 is refused outright no matter how it is invoked, and the first deployment of
  this bundle was blocked by exactly that. A .cmd is not a PowerShell script, so it runs;
  it then passes the work to PowerShell with a policy scoped to that one process.

  -ExecutionPolicy Bypass affects only the child process. It changes nothing on the machine
  and needs no administrator, which is why this is preferable to asking somebody to weaken
  a policy their security team set.
#>
$launcher = @'
@echo off
REM Starts the SBOM platform on a machine whose PowerShell execution policy
REM refuses script files. See start.ps1 for what actually happens.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
if errorlevel 1 (
  echo.
  echo Startup failed. The output above says why.
  pause
)
'@
$launcher | Out-File -FilePath (Join-Path $bundleDir "start.cmd") -Encoding ascii
Write-Note "start.cmd (for machines where script files are blocked)"

<#
  The Windows Server installer: a Hyper-V machine from a prepared Debian disk.

  The disk is Debian's own cloud image, pinned by SHA-512 in deploy/windows/VM-IMAGE, with the
  packages the platform needs added and everything that would reach the internet by itself
  removed (scripts/vm-image/bake.sh, run in a privileged Linux container here). Built once and
  cached under var/vm-image, keyed by the image and the bake script, so a server never
  downloads an operating system or a package.
#>
if (-not $NoWindows) {
    $winSource = Join-Path $deployDir "windows"
    $winTarget = Join-Path $bundleDir "windows"
    New-Item -ItemType Directory -Path $winTarget -Force | Out-Null
    foreach ($f in @("install-windows.ps1", "upgrade-windows.ps1", "uninstall-windows.ps1", "common.ps1")) {
        Copy-Item (Join-Path $winSource $f) (Join-Path $winTarget $f)
    }
    $vmPins = @{}
    foreach ($line in Get-Content (Join-Path $winSource "VM-IMAGE")) {
        if ($line -match '^\s*([A-Z0-9_]+)=(\S+)') { $vmPins[$Matches[1]] = $Matches[2] }
    }
    $vmCache = Join-Path $repoRoot "var\vm-image"
    New-Item -ItemType Directory -Path $vmCache -Force | Out-Null
    $bakeScript = Join-Path $repoRoot "scripts\vm-image\bake.sh"
    $bakeHash = (Get-FileHash $bakeScript -Algorithm SHA256).Hash.Substring(0, 12).ToLower()
    $imageTag = ($vmPins.DEBIAN_IMAGE_URL -split '/')[-1] -replace '\.qcow2$', ''
    $baked = Join-Path $vmCache "sbom-vm-$imageTag-$bakeHash.vhdx"
    if (-not (Test-Path $baked)) {
        $qcow = Join-Path $vmCache "$imageTag.qcow2"
        if (-not (Test-Path $qcow) -or (Get-FileHash $qcow -Algorithm SHA512).Hash -ne $vmPins.DEBIAN_IMAGE_SHA512.ToUpper()) {
            Write-Step "Downloading the Debian cloud image"
            & curl.exe -fL --retry 5 --retry-all-errors -sS -o $qcow $vmPins.DEBIAN_IMAGE_URL
            if ($LASTEXITCODE -ne 0) { throw "Downloading $($vmPins.DEBIAN_IMAGE_URL) failed." }
            $hash = (Get-FileHash $qcow -Algorithm SHA512).Hash
            if ($hash -ne $vmPins.DEBIAN_IMAGE_SHA512.ToUpper()) {
                Remove-Item $qcow -Force
                throw "The Debian image has SHA-512 $hash, but deploy/windows/VM-IMAGE pins $($vmPins.DEBIAN_IMAGE_SHA512). Not using it."
            }
        }
        Write-Step "Preparing the virtual machine disk (a few minutes)"
        $mountCache = ($vmCache -replace '\\', '/')
        $mountScripts = ((Split-Path $bakeScript -Parent) -replace '\\', '/')
        Invoke-Docker @("run", "--rm", "--privileged", "-v", "$($mountCache):/w", "-v", "$($mountScripts):/s:ro", "debian:trixie",
            "bash", "/s/bake.sh", "/w/$imageTag.qcow2", "/w/sbom-vm-$imageTag-$bakeHash.vhdx") "Preparing the virtual machine disk failed."
    }
    Copy-Item $baked (Join-Path $winTarget "sbom-vm.vhdx")
    $vmPackages = Join-Path $vmCache "vm-packages.txt"
    (@("Debian image: $($vmPins.DEBIAN_IMAGE_URL)", "SHA-512: $($vmPins.DEBIAN_IMAGE_SHA512)", "Added packages:") +
        $(if (Test-Path $vmPackages) { Get-Content $vmPackages } else { @() })) -join "`n" | Write-LfFile -Path (Join-Path $winTarget "VM-IMAGE.txt")

    foreach ($name in @("install-windows", "upgrade-windows")) {
@"
@echo off
REM Runs windows\$name.ps1 where the PowerShell policy blocks script files.
REM Needs an Administrator command prompt.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\$name.ps1" %*
if errorlevel 1 (
  echo.
  echo $name failed. The output above says why.
  pause
)
"@ | Out-File -FilePath (Join-Path $bundleDir "$name.cmd") -Encoding ascii
    }
    Write-Note ("windows/ (Hyper-V installer, Linux disk {0:N0} MB)" -f ((Get-Item $baked).Length / 1MB))
}


# The compose file resolves image tags from these, so a bundle built at one
# version cannot accidentally start a differently-tagged image left on the host.
@"
SBOM_IMAGE_API=$apiImage
SBOM_IMAGE_WEB=$webImage
# Reported as the version of the OpenAPI document. Carried here rather than in .env
# because .env is written once and then left alone, so an upgraded deployment would go
# on reporting whichever version it was first installed at.
APP_VERSION=$Version
"@ | Write-LfFile -Path (Join-Path $bundleDir "images.env")

# Read by the start scripts to decide whether `docker load` is needed at all,
# which turns a one-minute wait into an instant start on every run after the
# first.
@"
$postgresImage
$apiImage
$webImage
"@ | Write-LfFile -Path (Join-Path $bundleDir "images.txt")

# --- 3. save the images -----------------------------------------------------
Write-Step "Saving images to a single archive (this is the slow part)"
$archive = Join-Path $bundleDir "images.tar"
Invoke-Docker @("save", "--output", $archive, $postgresImage, $apiImage, $webImage) "docker save failed."

$archiveSize = (Get-Item $archive).Length / 1MB
Write-Note ("images.tar - {0:N0} MB" -f $archiveSize)

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
    Write-Note ("{0} - {1:N0} MB" -f (Split-Path $zipPath -Leaf), $zipSize)
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
Write-Host "  2. Windows:  .\start.cmd    (or .\start.ps1)" -ForegroundColor White
Write-Host "     Linux:    ./start.sh" -ForegroundColor White
Write-Host "  3. Open http://localhost:8080 and sign in with CREDENTIALS.txt" -ForegroundColor White
Write-Host ""
Write-Note "start.cmd is there for machines whose PowerShell policy refuses script"
Write-Note "files. It does the same thing; start.ps1 works where the policy allows it."
Write-Note "Upgrading an existing deployment? Do NOT use 'docker compose down -v' --"
Write-Note "the -v deletes the volumes holding every SBOM and the database."
Write-Host ""
Write-Note "No secrets are in this bundle. The start script generates them per machine."
Write-Note "If you test-run it here first, delete the .env and CREDENTIALS.txt it writes"
Write-Note "before copying the folder onward, or every target shares one signing key."
