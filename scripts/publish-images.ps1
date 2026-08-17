<#
  Builds and pushes the two application images to a container registry.

  The counterpart to build-offline-bundle.ps1: that one produces a folder you carry to an
  isolated machine, this one publishes to a registry so any machine with Docker and
  network access can run the platform from two small text files — a compose file and a
  .env — instead of a copy of the repository.

  Postgres is deliberately not pushed. It is an unmodified upstream image and the target
  pulls `postgres:16-alpine` itself; re-hosting someone else's image under your account
  means inheriting responsibility for keeping it patched.

  Usage:
    .\scripts\publish-images.ps1 -User yourdockerhubname
    .\scripts\publish-images.ps1 -User yourname -Registry ghcr.io -Version 0.2.0
    .\scripts\publish-images.ps1 -User yourname -SkipBuild        # retag/push existing
#>
[CmdletBinding()]
param(
    # Registry namespace: a Docker Hub username, or an org/user for another registry.
    [Parameter(Mandatory)][string]$User,

    # Omit for Docker Hub. For others, the host: ghcr.io, registry.gitlab.com, ...
    [string]$Registry = "",

    # Defaults to the version in package.json, so tags track the release.
    [string]$Version = "",

    # Also move the `latest` tag. Off by default: `latest` is what someone gets when they
    # forget to pin, and silently changing what it means under a running deployment is a
    # good way to be surprised by an upgrade nobody triggered.
    [switch]$Latest,

    [switch]$SkipBuild,

    # Target CPU architecture. Overriding matters when the build host and the server
    # differ — an ARM image on an x86 server fails with "exec format error", which reads
    # like a corrupt download rather than the architecture mismatch it is.
    [string]$Platform = "linux/amd64"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent

function Write-Step { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }

if (-not $Version) {
    $Version = (Get-Content (Join-Path $repoRoot "package.json") | ConvertFrom-Json).version
}

# Docker Hub repositories are `user/name`; every other registry prefixes its host.
$prefix = if ($Registry) { "$Registry/$User" } else { $User }
$apiRepo = "$prefix/sbom-api"
$webRepo = "$prefix/sbom-web"

Write-Host ""
Write-Host "SBOM Platform - publish images" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Note "registry  $(if ($Registry) { $Registry } else { 'docker.io (Docker Hub)' })"
Write-Note "api       ${apiRepo}:$Version"
Write-Note "web       ${webRepo}:$Version"
Write-Note "platform  $Platform"

# --- preflight -------------------------------------------------------------
# Both checks exist because their failures are otherwise reported deep inside a
# multi-minute build or, worse, at the push step after it.
Write-Step "Checking Docker"
docker version --format '{{.Server.Version}}' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker is not running. Start Docker Desktop, or 'sudo systemctl start docker'."
}
Write-Note "engine responding"

<#
  A push to a registry you are not authenticated against fails with "denied:
  requested access to the resource is denied", which reads like the repository does
  not exist. Saying so up front, before the build, saves a rebuild.

  `docker login` is interactive and cannot be run from here on the caller's behalf.
#>
Write-Step "Checking registry authentication"
$loginTarget = if ($Registry) { $Registry } else { "docker.io" }
$authOk = $false
try {
    $config = Join-Path $env:USERPROFILE ".docker\config.json"
    if (Test-Path $config) {
        $json = Get-Content $config -Raw | ConvertFrom-Json
        # A credsStore means credentials live in the OS keychain rather than this file,
        # so their absence here proves nothing either way.
        if ($json.credsStore) { $authOk = $true; Write-Note "credentials handled by '$($json.credsStore)' - assuming logged in" }
        elseif ($json.auths -and $json.auths.PSObject.Properties.Name -match [regex]::Escape($loginTarget)) {
            $authOk = $true; Write-Note "authenticated to $loginTarget"
        }
    }
} catch { }
if (-not $authOk) {
    Write-Host "    not authenticated to $loginTarget" -ForegroundColor Yellow
    Write-Host "    run this first, then re-run this script:" -ForegroundColor Yellow
    Write-Host "      docker login $(if ($Registry) { $Registry })" -ForegroundColor White
    throw "Not logged in to $loginTarget."
}

# --- build -----------------------------------------------------------------
if ($SkipBuild) {
    Write-Step "Skipping build (-SkipBuild)"
}
else {
    Write-Step "Building the API image"
    docker build --platform $Platform -t "${apiRepo}:$Version" -f (Join-Path $repoRoot "packages\api\Dockerfile") $repoRoot
    if ($LASTEXITCODE -ne 0) { throw "API image build failed." }

    Write-Step "Building the web image"
    docker build --platform $Platform -t "${webRepo}:$Version" -f (Join-Path $repoRoot "packages\web\Dockerfile") $repoRoot
    if ($LASTEXITCODE -ne 0) { throw "Web image build failed." }
}

foreach ($repo in @($apiRepo, $webRepo)) {
    $size = docker image inspect "${repo}:$Version" --format '{{.Size}}'
    Write-Note ("{0}:{1}  {2:N0} MB" -f $repo, $Version, ([double]$size / 1MB))
}

# --- push ------------------------------------------------------------------
Write-Step "Pushing"
foreach ($repo in @($apiRepo, $webRepo)) {
    docker push "${repo}:$Version"
    if ($LASTEXITCODE -ne 0) { throw "Push failed for ${repo}:$Version. Is the repository name correct and does your account have access?" }
}

if ($Latest) {
    Write-Step "Moving the 'latest' tag"
    foreach ($repo in @($apiRepo, $webRepo)) {
        docker tag "${repo}:$Version" "${repo}:latest"
        docker push "${repo}:latest"
        if ($LASTEXITCODE -ne 0) { throw "Push failed for ${repo}:latest." }
    }
}

# --- what to do with it ----------------------------------------------------
Write-Host ""
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Host "Published." -ForegroundColor Green
Write-Host ""
Write-Host "On any machine with Docker, copy deploy\docker-compose.yml and a .env," -ForegroundColor Gray
Write-Host "put these two lines in the .env, and run 'docker compose up -d':" -ForegroundColor Gray
Write-Host ""
Write-Host "  SBOM_IMAGE_API=${apiRepo}:$Version" -ForegroundColor White
Write-Host "  SBOM_IMAGE_WEB=${webRepo}:$Version" -ForegroundColor White
Write-Host ""
Write-Host "The .env also needs SESSION_SECRET, BOOTSTRAP_ADMIN_EMAIL and" -ForegroundColor Gray
Write-Host "BOOTSTRAP_ADMIN_PASSWORD. See deploy\README.md." -ForegroundColor Gray
Write-Host ""
