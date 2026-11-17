<#
.SYNOPSIS
    Proves the platform contacts nothing on the internet except the documented update addresses.

.DESCRIPTION
    Runs the platform built from this checkout in an isolated Compose project whose database
    and API sit on a Docker network with no route out. The only way out is a small forward
    proxy (scripts\egress\proxy.mjs) that allows the addresses listed under "Network access"
    in deploy\README.md and records every attempt, allowed or refused.

    Then it does everything that reaches the internet: switches on all three scanners
    (Grype, Trivy, OSV) and the malicious-package list, updates every database, sends an
    SBOM with a known vulnerability and waits for the finding. It checks:

      - every update succeeded through the allowed addresses alone;
      - the finding appeared, so the downloaded databases work;
      - nothing tried any other address (the proxy log is the evidence);
      - a direct connection, bypassing the proxy, cannot leave the network at all.

    Never touches the `sbom-platform` project. The run's volumes are left in place and
    listed at the end (the vulnerability databases are a few GB); delete them from Docker
    Desktop when done. Everything the run writes goes under var\egress\<run>.

.EXAMPLE
    .\scripts\egress-test.ps1
    .\scripts\egress-test.ps1 -SkipBuild     # reuse images built by an earlier run
#>
[CmdletBinding()]
param(
    [string]$ApiImage = "sbom-platform/api:egress",
    [string]$WebImage = "sbom-platform/web:egress",
    [switch]$SkipBuild,
    [int]$Port = 18089
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$project = "sbom-egress-$runId"
$work = Join-Path $repoRoot "var\egress\$runId"
$baseUrl = "http://127.0.0.1:$Port"

# The documented allow-list (deploy\README.md, "Network access"). Keep the two in step.
$allowList = @(
    "grype.anchore.io",
    "mirror.gcr.io",
    "osv-vulnerabilities.storage.googleapis.com",
    "github.com",
    "codeload.github.com"
)

if ($project -notmatch '^sbom-egress-\d{8}-\d{6}$') { throw "Refusing to run: '$project' is not an egress-test project." }

# --- output -------------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }
function Add-Result {
    param([string]$Check, [bool]$Ok, [string]$Detail = "")
    $results.Add([pscustomobject]@{ Check = $Check; Result = $(if ($Ok) { "PASS" } else { "FAIL" }); Detail = $Detail })
    Write-Host ("    [{0}] {1} {2}" -f $(if ($Ok) { "PASS" } else { "FAIL" }), $Check, $Detail) -ForegroundColor $(if ($Ok) { "Green" } else { "Red" })
}

# --- docker (stderr carries ordinary progress; success is read from the exit code) ---------
function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$DockerArgs, [switch]$AllowFail)
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { $out = & docker @DockerArgs 2>&1; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $previous }
    $lines = @($out | ForEach-Object { "$_" })
    if ($code -ne 0 -and -not $AllowFail) { throw "docker $($DockerArgs -join ' ') failed (exit $code):`n$($lines -join "`n")" }
    return $lines
}
function Invoke-Compose {
    param([Parameter(Mandatory)][string[]]$ComposeArgs, [switch]$AllowFail)
    return Invoke-Docker -DockerArgs (@("compose", "-p", $project, "--project-directory", $work, "-f", (Join-Path $work "docker-compose.yml"), "-f", (Join-Path $work "egress.override.yml"), "--env-file", (Join-Path $work ".env")) + $ComposeArgs) -AllowFail:$AllowFail
}

# --- http (JSON bodies through a file: PowerShell 5.1 strips quotes from native arguments) ---
$cookieJar = Join-Path $work "cookies.txt"
$tmpBody = Join-Path $work "body.json"
$STATUS = "<<<HTTP_STATUS>>>"
function Invoke-Api {
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, $Body, [int]$TimeoutSec = 120)
    $curlArgs = @("-s", "--noproxy", "*", "-m", "$TimeoutSec", "-X", $Method, "$baseUrl$Path", "-b", $cookieJar, "-c", $cookieJar)
    if ($null -ne $Body) {
        [IO.File]::WriteAllText($tmpBody, ($Body | ConvertTo-Json -Depth 10 -Compress), (New-Object Text.UTF8Encoding $false))
        $curlArgs += @("-H", "Content-Type: application/json", "--data-binary", "@$tmpBody")
    }
    $curlArgs += @("-w", "$STATUS%{http_code}")
    $raw = (& curl.exe @curlArgs) -join "`n"
    $idx = $raw.LastIndexOf($STATUS)
    if ($idx -lt 0) { return [pscustomobject]@{ Status = 0; Json = $null; Text = $raw } }
    $text = $raw.Substring(0, $idx)
    $json = $null; try { $json = $text | ConvertFrom-Json } catch { }
    return [pscustomobject]@{ Status = [int]$raw.Substring($idx + $STATUS.Length); Json = $json; Text = $text }
}
function Assert-Status {
    param($Response, [int[]]$Expected, [string]$What)
    if ($Expected -notcontains $Response.Status) { throw "$What returned HTTP $($Response.Status): $($Response.Text)" }
    return $Response
}
function New-Secret { param([int]$Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $chars = ""
    while ($chars.Length -lt $Length) { $b = New-Object byte[] 48; $rng.GetBytes($b); $chars += ([Convert]::ToBase64String($b) -replace '[+/=]', '') }
    return $chars.Substring(0, $Length)
}

# ==============================================================================
Write-Host ""
Write-Host "SBOM Platform - egress allow-list test" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Note "project   $project"
Write-Note "allowed   $($allowList -join ', ')"
Write-Note "work dir  $work"

$null = Invoke-Docker -DockerArgs @("info", "--format", "{{.ServerVersion}}")
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { throw "Port $Port is already in use. Stop what uses it, or pass -Port." }
New-Item -ItemType Directory -Force -Path (Join-Path $work "egress") | Out-Null

if (-not $SkipBuild) {
    Write-Step "Building the images of this checkout"
    $null = Invoke-Docker -DockerArgs @("build", "--platform", "linux/amd64", "-f", "packages/api/Dockerfile", "-t", $ApiImage, ".")
    $null = Invoke-Docker -DockerArgs @("build", "--platform", "linux/amd64", "-f", "packages/web/Dockerfile", "-t", $WebImage, ".")
}

# --- the installation -------------------------------------------------------------
Copy-Item "deploy\docker-compose.yml" $work
New-Item -ItemType Directory -Force -Path (Join-Path $work "ca") | Out-Null
Copy-Item "scripts\egress\proxy.mjs" (Join-Path $work "egress")
$adminPassword = New-Secret 20
$ciToken = (New-Secret 48).ToLower()
@"
SBOM_PORT=$Port
PUBLIC_URL=$baseUrl
SESSION_SECRET=$(New-Secret 64)
SECRETS_KEY=$(New-Secret 48)
INGEST_TOKENS=ci:$ciToken
BOOTSTRAP_ADMIN_EMAIL=admin@sbom.local
BOOTSTRAP_ADMIN_PASSWORD=$adminPassword
POSTGRES_PASSWORD=$(New-Secret 32)
SBOM_IMAGE_API=$ApiImage
SBOM_IMAGE_WEB=$WebImage
APP_VERSION=egress-test
HTTP_PROXY=http://egress-proxy:3128
HTTPS_PROXY=http://egress-proxy:3128
NO_PROXY=localhost,127.0.0.1,db,api,web
LOG_LEVEL=info
"@ | Out-File -FilePath (Join-Path $work ".env") -Encoding ascii

# db and api only on `inside`, which has no route out. web also joins `outside` so its port
# can be published; it is nginx and never initiates a connection. The proxy joins both.
@"
services:
  egress-proxy:
    image: $ApiImage
    entrypoint: ["node"]
    command: ["/egress/proxy.mjs"]
    user: "0"
    healthcheck:
      disable: true
    environment:
      ALLOW: "$($allowList -join ',')"
      LOG: /egress/egress.jsonl
    volumes:
      - ./egress:/egress
    networks: [inside, outside]
  db:
    networks: [inside]
  api:
    networks: [inside]
  web:
    networks: [inside, outside]
networks:
  inside:
    internal: true
  outside: {}
"@ | Out-File -FilePath (Join-Path $work "egress.override.yml") -Encoding ascii

Write-Step "Starting the platform behind the allow-list proxy on port $Port"
$null = Invoke-Compose -ComposeArgs @("up", "-d")
$deadline = (Get-Date).AddMinutes(5); $healthy = $false
while ((Get-Date) -lt $deadline -and -not $healthy) {
    $healthy = (& curl.exe -s -o NUL -w "%{http_code}" --noproxy "*" -m 3 "$baseUrl/health" 2>$null) -eq "200"
    if (-not $healthy) { Start-Sleep -Seconds 3 }
}
if (-not $healthy) { throw "The platform did not become healthy. docker compose -p $project logs api" }

$null = Assert-Status (Invoke-Api POST "/api/v1/auth/login" @{ email = "admin@sbom.local"; password = $adminPassword }) 200 "admin sign-in"

# --- 1. the fence holds -------------------------------------------------------------
Write-Step "Checking the fence: no direct route out"
# Node's fetch ignores proxy variables, so this is a direct attempt. JavaScript in single
# quotes only: PowerShell 5.1 strips double quotes from native arguments.
$direct = Invoke-Compose -ComposeArgs @("exec", "-T", "api", "node", "-e", "fetch('https://registry.npmjs.org/',{signal:AbortSignal.timeout(8000)}).then(()=>process.exit(0),e=>{console.log(String(e.cause??e));process.exit(1)})") -AllowFail
Add-Result "direct connection from the API is impossible" ($LASTEXITCODE -ne 0) ($direct | Select-Object -Last 1)
$viaProxy = Invoke-Compose -ComposeArgs @("exec", "-T", "api", "node", "-e", "const s=require('net').connect(3128,'egress-proxy',()=>s.write('CONNECT registry.npmjs.org:443 HTTP/1.1
Host: registry.npmjs.org:443

'));s.on('data',d=>{console.log(String(d).split('
')[0]);process.exit(/ 200 /.test(String(d))?0:1)});setTimeout(()=>process.exit(2),8000)") -AllowFail
Add-Result "an address outside the list is refused by the proxy" ($LASTEXITCODE -ne 0) ($viaProxy | Select-Object -Last 1)

# --- 2. every update, through the allowed addresses only ------------------------------------
Write-Step "Switching on Grype, Trivy, OSV and vulnerability scanning"
$null = Assert-Status (Invoke-Api PUT "/api/v1/admin/vuln/provider" @{ scanners = @{ grype = $true; trivy = $true; osv = $true; xray = $false } }) 200 "switch scanners on"
$null = Assert-Status (Invoke-Api PATCH "/api/v1/admin/vuln/settings" @{ enabled = $true }) 200 "enable scanning"

Write-Step "Updating the vulnerability databases (several minutes: a few hundred MB)"
$u = Invoke-Api POST "/api/v1/admin/vuln/update" -TimeoutSec 3600
$okOutcomes = @("updated", "already-current")
Add-Result "vulnerability database update" ($u.Status -eq 200 -and $okOutcomes -contains $u.Json.outcome) "$($u.Json.outcome): $($u.Json.message)"
$u.Text | Out-File (Join-Path $work "vuln-update.json") -Encoding utf8

Write-Step "Updating the malicious-package list"
$null = Assert-Status (Invoke-Api PATCH "/api/v1/admin/malicious/settings" @{ enabled = $true }) 200 "enable malicious-package checks"
$m = Invoke-Api POST "/api/v1/admin/malicious/update" -TimeoutSec 1800
Add-Result "malicious-package list update" ($m.Status -eq 200 -and $okOutcomes -contains $m.Json.outcome) "$($m.Json.outcome): $($m.Json.message)"

# Per-scanner state, as the admin screen shows it: an update that skips one scanner shows here.
$status = Invoke-Api GET "/api/v1/admin/vuln/status"
$status.Text | Out-File (Join-Path $work "vuln-status.json") -Encoding utf8

# --- 3. the databases work -------------------------------------------------------------
Write-Step "Sending an SBOM with log4j-core 2.14.1 (Log4Shell) and waiting for the finding"
$sbom = Join-Path $work "sbom.json"
$doc = @{
    bomFormat = "CycloneDX"; specVersion = "1.5"; version = 1; serialNumber = "urn:uuid:$([guid]::NewGuid())"
    metadata = @{ component = @{ type = "application"; name = "egress-test-app"; version = "1.0.0" } }
    components = @(
        @{ type = "library"; name = "log4j-core"; version = "2.14.1"; purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
        @{ type = "library"; name = "lodash"; version = "4.17.15"; purl = "pkg:npm/lodash@4.17.15" }
    )
}
[IO.File]::WriteAllText($sbom, ($doc | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding $false))
$raw = (& curl.exe -s --noproxy "*" -m 120 -X POST "$baseUrl/api/v1/scans" -H "Authorization: Bearer $ciToken" `
        -F "sbom=@$sbom" -F "app_name=egress-test-app" -F "commit_sha=egress1" -F "build_number=1" -F "branch=main") -join "`n"
$scanId = ($raw | ConvertFrom-Json).scanId
$null = Invoke-Api POST "/api/v1/admin/vuln/sweep"
$found = $false; $deadline = (Get-Date).AddMinutes(10)
while ((Get-Date) -lt $deadline -and -not $found) {
    $found = (Invoke-Api GET "/api/v1/scans/$scanId/vulnerabilities").Text -match "CVE-2021-44228"
    if (-not $found) { Start-Sleep -Seconds 10 }
}
Add-Result "Log4Shell found in the test SBOM" $found

# --- 4. the evidence -------------------------------------------------------------------
Write-Step "Reading the proxy log"
$log = Join-Path $work "egress\egress.jsonl"
$entries = @(); if (Test-Path $log) { $entries = @(Get-Content $log | ForEach-Object { $_ | ConvertFrom-Json }) }
$hosts = $entries | Group-Object host | Sort-Object Name
foreach ($h in $hosts) {
    $denied = @($h.Group | Where-Object { -not $_.allowed }).Count
    Write-Note ("{0,-48} {1,4} allowed {2,4} refused" -f $h.Name, ($h.Count - $denied), $denied)
}
# The npm registry is the fence check's own deliberate attempt.
$unexpected = @($entries | Where-Object { -not $_.allowed -and $_.host -ne "registry.npmjs.org" } | ForEach-Object { $_.host } | Sort-Object -Unique)
Add-Result "nothing tried an address outside the list" ($unexpected.Count -eq 0) ($unexpected -join ", ")

# --- report ----------------------------------------------------------------------------
$null = Invoke-Compose -ComposeArgs @("logs", "--no-color", "api") -AllowFail | Out-File (Join-Path $work "api.log") -Encoding utf8
Write-Step "Stopping the test installation (its volumes are kept)"
$null = Invoke-Compose -ComposeArgs @("down") -AllowFail

$failed = @($results | Where-Object Result -eq "FAIL").Count
$results | Format-Table -AutoSize | Out-String | Tee-Object -FilePath (Join-Path $work "report.txt") | Write-Host
Write-Note "Volumes of this run (delete them in Docker Desktop when done):"
Invoke-Docker -DockerArgs @("volume", "ls", "--filter", "label=com.docker.compose.project=$project", "--format", "{{.Name}}") | ForEach-Object { Write-Note "  $_" }
if ($failed -gt 0) { Write-Host "$failed check(s) failed. Evidence in $work" -ForegroundColor Red; exit 1 }
Write-Host "All checks passed." -ForegroundColor Green
