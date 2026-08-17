<#
  Packages the source into a clean folder or zip for transfer to another machine.

  Exists because copying the working directory as-is transfers roughly 400 MB of things
  the target must not receive:

    node_modules   ~298 MB, and platform-specific. Native bindings built for this OS and
                   CPU are wrong on the target, and `npm ci` there produces them correctly
                   in less time than copying them takes.
    var/           ~92 MB of local runtime state: the downloaded grype binary, its
                   database cache, stored SBOM blobs, screenshots. All machine-local.
    dist/          Build output. Rebuilt on the target, and stale copies are worse than
                   absent ones.
    .env           The real one, with this machine's secrets and dev-only values such as
                   PUBLIC_URL on the Vite port. Shipping it would hand the target both a
                   shared session-signing key and a wrong public URL. `.env.example` is
                   included instead.

  Usage:
    .\scripts\export-source.ps1              # -> ..\sbom-source-0.1.0\
    .\scripts\export-source.ps1 -Zip         # -> ..\sbom-source-0.1.0.zip
#>
[CmdletBinding()]
param(
    # Where to put the export. Defaults to the repository's parent directory, so the
    # output never lands inside the tree being copied.
    [string]$OutputRoot = "",
    [switch]$Zip,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent

if (-not $Version) {
    $Version = (Get-Content (Join-Path $repoRoot "package.json") | ConvertFrom-Json).version
}
if (-not $OutputRoot) { $OutputRoot = Split-Path $repoRoot -Parent }

$name = "sbom-source-$Version"
$dest = Join-Path $OutputRoot $name

Write-Host ""
Write-Host "SBOM Platform - export source" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray

if (Test-Path $dest) {
    Write-Host "    removing the previous export" -ForegroundColor DarkGray
    Remove-Item $dest -Recurse -Force
}

# Directory and file exclusions. robocopy matches these by name at any depth, which is
# what makes one `node_modules` entry cover all four workspaces.
$excludeDirs = @(
    "node_modules", "var", "dist", ".git", ".vscode", ".turbo", "playwright-report",
    # Output of build-offline-bundle.ps1. A previously built bundle left here is 330 MB of
    # images.tar — a hundred times the size of the source it sits next to, and the target
    # rebuilds from source anyway.
    "dist-offline"
)
# `*.tar` catches an images.tar saved anywhere else, for the same reason.
$excludeFiles = @(".env", "*.log", "*.tsbuildinfo", "CREDENTIALS.txt", "*.tar", "*.zip")

Write-Host "`nCopying source" -ForegroundColor Cyan
Write-Host "    excluding: $($excludeDirs -join ', ')" -ForegroundColor DarkGray

<#
  /E all subdirectories including empty, and the /N* switches silence per-file logging —
  without them this prints thousands of lines. robocopy's exit codes below 8 are success
  (1 = files copied, 2 = extra files, 3 = both), so $LASTEXITCODE is checked against 8
  rather than 0.

  /XJ is not optional here. npm workspaces puts symlinks in node_modules pointing back at
  packages/ — node_modules\@sbom\api is packages\api. Without /XJ, robocopy follows them
  and copies the tree a second time through the link, which includes var\grype-db and its
  1.9 GB vulnerability database. That fills the disk rather than failing cleanly, and the
  error it reports ("There is not enough space on the disk") says nothing about the cause.
  /XD node_modules alone is enough only while that exclusion is correct; /XJ makes the
  copy safe even if it is not.
#>
$roboArgs = @($repoRoot, $dest, "/E", "/XJ", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/NP")
$roboArgs += "/XD"; $roboArgs += $excludeDirs
$roboArgs += "/XF"; $roboArgs += $excludeFiles
& robocopy @roboArgs | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

# --- prove the exclusions held ---------------------------------------------
# Asserted rather than assumed: a copy that silently included .env would leak this
# machine's session-signing key to every machine the export reaches.
$leaked = Get-ChildItem $dest -Recurse -Force -Filter ".env" -ErrorAction SilentlyContinue
if ($leaked) { throw "The export contains a .env file - refusing to hand out local secrets." }
foreach ($dir in @("node_modules", "var")) {
    if (Get-ChildItem $dest -Recurse -Directory -Filter $dir -ErrorAction SilentlyContinue) {
        throw "The export contains a '$dir' directory, which should have been excluded."
    }
}

# --- sanity-check what a build actually needs -------------------------------
# Cheap insurance against an over-broad exclusion: these are the files the target's
# `docker compose up --build` reads first, and their absence would only surface minutes
# into a build on the other machine.
$required = @(
    "package.json", "package-lock.json", "docker-compose.yml", ".env.example",
    "packages\api\Dockerfile", "packages\web\Dockerfile",
    "packages\api\package.json", "packages\web\package.json", "packages\shared\package.json",
    "packages\api\drizzle"
)
foreach ($item in $required) {
    if (-not (Test-Path (Join-Path $dest $item))) { throw "The export is missing $item" }
}

$files = Get-ChildItem $dest -Recurse -File
$size = ($files | Measure-Object -Sum Length).Sum
Write-Host ("    {0:N0} files, {1:N1} MB" -f $files.Count, ($size / 1MB)) -ForegroundColor DarkGray

if ($Zip) {
    Write-Host "`nCompressing" -ForegroundColor Cyan
    $zipPath = "$dest.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $dest "*") -DestinationPath $zipPath -CompressionLevel Optimal
    Remove-Item $dest -Recurse -Force
    $zipSize = (Get-Item $zipPath).Length / 1MB
    Write-Host ("    {0}  ({1:N1} MB)" -f $zipPath, $zipSize) -ForegroundColor DarkGray
    $result = $zipPath
}
else {
    $result = $dest
}

Write-Host ""
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Host "Ready to copy." -ForegroundColor Green
Write-Host "    $result"
Write-Host ""
Write-Host "On the target machine (Docker required, nothing else):" -ForegroundColor Gray
Write-Host "    cp .env.example .env      # then set SESSION_SECRET and the admin password" -ForegroundColor White
Write-Host "    docker compose up -d --build" -ForegroundColor White
Write-Host "    open http://localhost:8080" -ForegroundColor White
Write-Host ""
