<#
.SYNOPSIS
    End-to-end smoke test against a locally running API.

.DESCRIPTION
    Exercises the paths unit tests cannot reach because they need a real database:
    ingesting an SBOM, auto-creating a pending application, deduping components,
    blob storage, and the login/session lifecycle.

    Driven entirely through curl.exe rather than Invoke-WebRequest. Two reasons:
      - Windows PowerShell 5.1 has no `-Form` parameter, so it cannot build a
        multipart upload at all.
      - Jenkins and GitLab both call this endpoint with curl, so testing through
        curl exercises the same client the real pipelines use.

    Start the API first (`npm run dev`), then run this.

.EXAMPLE
    .\scripts\smoke-test.ps1
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:3000",
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    throw "curl.exe not found. It ships with Windows 10 1803+ in C:\Windows\System32."
}

# --- read config out of .env ----------------------------------------------
$envPath = Join-Path $repoRoot $EnvFile
if (-not (Test-Path $envPath)) { throw "Cannot find $envPath" }

$envMap = @{}
foreach ($line in Get-Content $envPath) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $idx = $line.IndexOf('=')
    $envMap[$line.Substring(0, $idx).Trim()] = $line.Substring($idx + 1).Trim()
}

# INGEST_TOKENS is `name:token,name:token`; take the first token's value.
$firstEntry = ($envMap['INGEST_TOKENS'] -split ',')[0]
$token = $firstEntry.Substring($firstEntry.IndexOf(':') + 1)
if (-not $token) { throw "No ingest token found in INGEST_TOKENS in $EnvFile" }

$adminEmail = $envMap['BOOTSTRAP_ADMIN_EMAIL']
$adminPassword = $envMap['BOOTSTRAP_ADMIN_PASSWORD']
if (-not $adminPassword) { throw "BOOTSTRAP_ADMIN_PASSWORD is not set in $EnvFile" }

$workDir = Join-Path $env:TEMP "sbom-smoke-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $workDir | Out-Null
$cookieJar = Join-Path $workDir "cookies.txt"

# --- helpers ---------------------------------------------------------------
$STATUS_MARKER = "<<<HTTP_STATUS>>>"

function Invoke-Api {
    <#
      Returns @{ Status = <int>; Body = <string>; Json = <object|null> }.

      Args are passed as ONE explicit array rather than via
      ValueFromRemainingArguments. PowerShell tries to bind leading `-x` tokens as
      parameter names of this function first, which makes calls containing curl
      flags fail with "A parameter cannot be found that matches parameter name
      'X'" depending on what else is in the list. An explicit array parameter
      removes the ambiguity entirely.

      Never redirects stderr: in PowerShell 5.1 that wraps native output in an
      ErrorRecord and flips $? to false even on success.
    #>
    param([string[]]$CurlArgs)

    <#
      Retries on 429 rather than reporting it as a failed assertion.

      The API allows 300 requests a minute and a full run comes close, so a suite run twice
      in quick succession exhausts the budget somewhere in its tail. That surfaced as
      "cleanup failed" with an empty list of leftovers -- a rate-limited GET returns an error
      body with no `items`, and @($null) counts as one in PowerShell, so the check reported
      stray data it could not name. Two misleading symptoms from one cause, neither of them
      mentioning the limiter.

      Handled here rather than at the call sites that happened to fail: the limiter applies
      to every request, so which assertion trips it is a matter of timing. The API says how
      long to wait, so this waits that long.
    #>
    for ($rlAttempt = 1; $rlAttempt -le 5; $rlAttempt++) {
        $out = & curl.exe -s -w "`n$STATUS_MARKER%{http_code}" @CurlArgs
        $text = ($out -join "`n")
        if ($text -notmatch 'Rate limit exceeded') { break }
        $rlWait = 5
        if ($text -match 'retry in (\d+) second') { $rlWait = [int]$Matches[1] + 1 }
        Write-Host "        rate limited; waiting $rlWait s (attempt $rlAttempt/5)" -ForegroundColor DarkGray
        Start-Sleep -Seconds $rlWait
    }

    $idx = $text.LastIndexOf($STATUS_MARKER)
    if ($idx -lt 0) {
        return @{ Status = 0; Body = $text; Json = $null }
    }

    $status = 0
    [void][int]::TryParse($text.Substring($idx + $STATUS_MARKER.Length).Trim(), [ref]$status)
    $body = $text.Substring(0, $idx).TrimEnd()

    $json = $null
    if ($body) { try { $json = $body | ConvertFrom-Json } catch { $json = $null } }

    return @{ Status = $status; Body = $body; Json = $json }
}

function New-JsonFile {
    param([hashtable]$Data, [string]$Name, [switch]$WithBom)
    $path = Join-Path $workDir $Name
    $json = $Data | ConvertTo-Json -Depth 10
    # WriteAllText with UTF8Encoding($false) writes NO byte order mark.
    # `Set-Content -Encoding utf8` in PowerShell 5.1 always adds one, which is not
    # what Syft produces — so the default here is BOM-free, and the BOM case gets
    # its own explicit test rather than silently contaminating every fixture.
    $encoding = New-Object System.Text.UTF8Encoding($WithBom.IsPresent)
    [System.IO.File]::WriteAllText($path, $json, $encoding)
    return $path
}

$pass = 0
$fail = 0
$failures = @()

function Assert-That {
    param([string]$Name, [scriptblock]$Test)
    try {
        $result = & $Test
        if ($result) {
            Write-Host "  PASS  $Name" -ForegroundColor Green
            $script:pass++
        }
        else {
            Write-Host "  FAIL  $Name" -ForegroundColor Red
            $script:fail++
            $script:failures += $Name
        }
    }
    catch {
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkRed
        $script:fail++
        $script:failures += $Name
    }
}

function Show-Body {
    param($Response, [int]$Expected)
    if ($Response.Status -ne $Expected) {
        Write-Host "        expected $Expected, got $($Response.Status): $($Response.Body)" -ForegroundColor DarkYellow
    }
}

function Get-SeveritySum {
    <#
      Totals a six-severity breakdown.

      A helper rather than a repeated expression: the sum has to include negligible and
      unrated, and an inlined version that quietly omitted one would make several of the
      assertions below pass against wrong data. Unrated is a real answer from the feeds,
      not a placeholder, so it counts.
    #>
    param($Counts)
    if ($null -eq $Counts) { return -1 }
    return [int]$Counts.critical + [int]$Counts.high + [int]$Counts.medium +
           [int]$Counts.low + [int]$Counts.negligible + [int]$Counts.unknown
}

Write-Host ""
Write-Host "SBOM platform smoke test -> $BaseUrl" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray

# --- preflight -------------------------------------------------------------
# This script is an HTTP client, so it needs the API already running. Without
# this check, a stopped server produces 30 indistinguishable failures instead of
# one actionable message.
$preflight = Invoke-Api @("--max-time", "5", "$BaseUrl/health")
if ($preflight.Status -eq 0) {
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "Cannot reach the API at $BaseUrl" -ForegroundColor Red
    Write-Host ""
    Write-Host "Start it in another terminal first, and leave it running:" -ForegroundColor Yellow
    Write-Host "    npm run dev" -ForegroundColor White
    Write-Host ""
    # Single-quoted: in a double-quoted string PowerShell reads the backtick in
    # `npm as the `n newline escape and breaks the line in half.
    Write-Host '(npm run db:studio does not need it - that talks to Postgres directly.)' -ForegroundColor DarkGray
    exit 2
}

try {
    # ======================================================================
    Write-Host ""
    Write-Host "Health" -ForegroundColor Cyan

    Assert-That "GET /health returns ok" {
        $r = Invoke-Api @("$BaseUrl/health")
        $r.Status -eq 200 -and $r.Json.status -eq "ok"
    }

    Assert-That "GET /health/ready reports the database reachable" {
        $r = Invoke-Api @("$BaseUrl/health/ready")
        $r.Status -eq 200 -and $r.Json.checks.database -eq "ok"
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Ingestion (POST /api/v1/scans)" -ForegroundColor Cyan

    $scansUrl = "$BaseUrl/api/v1/scans"
    $auth = "Authorization: Bearer $token"

    # A structurally faithful Syft-style CycloneDX document.
    $sbom = @{
        bomFormat    = "CycloneDX"
        specVersion  = "1.5"
        serialNumber = "urn:uuid:$([guid]::NewGuid())"
        version      = 1
        metadata     = @{
            tools     = @{ components = @(@{ type = "application"; name = "syft"; version = "1.18.1" }) }
            component = @{ type = "container"; name = "local/smoke-test:1.0.0" }
        }
        components   = @(
            # The OS component and a binary-cataloged runtime, exactly as Syft
            # emits them. Platform detection reads these markers, so the fixture
            # has to carry them or the feature goes untested end to end.
            @{ type = "operating-system"; name = "alpine"; version = "3.20.3"
               description = "Alpine Linux v3.20"
               properties = @(
                   @{ name = "syft:distro:id"; value = "alpine" }
                   @{ name = "syft:distro:versionID"; value = "3.20.3" }
                   @{ name = "syft:distro:prettyName"; value = "Alpine Linux v3.20" }
               ) }
            @{ type = "application"; name = "node"; version = "22.11.0"
               purl = "pkg:generic/node@22.11.0"
               properties = @(@{ name = "syft:package:type"; value = "binary" }) }
            # A binary that is NOT a runtime: must stay an ordinary component.
            @{ type = "application"; name = "busybox"; version = "1.36.1"
               purl = "pkg:generic/busybox@1.36.1"
               properties = @(@{ name = "syft:package:type"; value = "binary" }) }
            @{ type = "library"; name = "express"; version = "4.19.2"; purl = "pkg:npm/express@4.19.2" }
            # Exact duplicate: must collapse, or the (scan_id, component_id)
            # primary key would abort the insert.
            @{ type = "library"; name = "express"; version = "4.19.2"; purl = "pkg:npm/express@4.19.2" }
            # Same package, purl qualifiers in a different order: must also collapse.
            @{ type = "library"; name = "libc6"; version = "2.36-9"
               purl = "pkg:deb/debian/libc6@2.36-9?distro=debian-12&arch=amd64" }
            @{ type = "library"; name = "libc6"; version = "2.36-9"
               purl = "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12" }
            @{ type = "library"; name = "requests"; version = "2.32.3"; purl = "pkg:pypi/requests@2.32.3" }
            # No version: legal in CycloneDX, must be kept.
            @{ type = "library"; name = "mystery-lib" }
            # Excluded by the parser as not-a-dependency.
            @{ type = "file"; name = "/usr/lib/libcrypto.so.3" }
        )
    }
    $sbomPath = New-JsonFile -Data $sbom -Name "sbom.cdx.json"
    $appName = "smoke-test-app-$([guid]::NewGuid().ToString('N').Substring(0,6))"

    Assert-That "rejects a request with no bearer token (401)" {
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-F", "app_name=x")
        $r.Status -eq 401 -and $r.Json.error.code -eq "unauthorized"
    }

    Assert-That "rejects an invalid bearer token (401)" {
        $r = Invoke-Api @("-X", "POST", $scansUrl,
            "-H", "Authorization: Bearer definitely-not-a-real-token", "-F", "app_name=x")
        $r.Status -eq 401
    }

    Assert-That "rejects a non-multipart body (415)" {
        $r = Invoke-Api @("-X", "POST", $scansUrl,
            "-H", $auth, "-H", "Content-Type: application/json", "-d", "{}")
        Show-Body $r 415
        $r.Status -eq 415
    }

    $script:ingest = $null
    Assert-That "accepts a valid SBOM and returns 201" {
        $r = Invoke-Api @("-X", "POST", $scansUrl,
            "-H", $auth,
            "-F", "sbom=@$sbomPath",
            "-F", "app_name=$appName",
            "-F", "commit_sha=abc123def4567890",
            "-F", "build_number=42",
            "-F", "image_ref=local/smoke-test:1.0.0",
            "-F", "branch=main")
        Show-Body $r 201
        $script:ingest = $r.Json
        $r.Status -eq 201
    }

    Assert-That "auto-created the unknown app as pending_confirmation" {
        $script:ingest.applicationCreated -eq $true -and
        $script:ingest.applicationStatus -eq "pending_confirmation" -and
        $script:ingest.applicationName -eq $appName
    }

    Assert-That "deduped within the document (7 components, not 9)" {
        # express x2 -> 1, libc6 x2 (reordered qualifiers) -> 1, requests,
        # mystery-lib, plus the OS entry, node and busybox. The `file` entry is
        # excluded entirely.
        if ($script:ingest.componentCount -ne 7) {
            Write-Host "        got componentCount=$($script:ingest.componentCount)" -ForegroundColor DarkYellow
        }
        $script:ingest.componentCount -eq 7
    }

    Assert-That "reported the excluded file entry as skipped" {
        $script:ingest.skippedComponents -ge 1
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Runtime platform detection" -ForegroundColor Cyan

    Assert-That "detected the OS and runtime from the SBOM" {
        # Needs a session, so this reads back through the scan detail endpoint
        # rather than the ingest response.
        $lj = Join-Path $workDir "plat-cookies.txt"
        $lp = New-JsonFile -Name "plat-login.json" -Data @{ email = $adminEmail; password = $adminPassword }
        $li = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/auth/login", "-H", "Content-Type: application/json",
            "--data-binary", "@$lp", "-c", $lj)
        if ($li.Status -ne 200) { return $false }
        $script:platJar = $lj

        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($script:ingest.scanId)", "-b", $lj)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        $p = $r.Json.platform
        if ($p.osName -ne "alpine" -or $p.osVersion -ne "3.20.3") {
            Write-Host "        os=$($p.osName) $($p.osVersion)" -ForegroundColor DarkYellow
            return $false
        }
        # busybox is a binary but not a runtime, so exactly one runtime.
        if (@($p.runtimes).Count -ne 1 -or $p.runtimes[0].name -ne "node") {
            Write-Host "        runtimes=$(($p.runtimes | ForEach-Object { $_.name }) -join ',')" -ForegroundColor DarkYellow
            return $false
        }
        return $p.summary -eq "Alpine 3.20.3 · Node.js 22.11.0"
    }

    Assert-That "the application reports the platform of its current build" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)", "-b", $script:platJar)
        $r.Status -eq 200 -and $r.Json.platform.osName -eq "alpine"
    }

    Assert-That "an SBOM with no OS or runtime reports an empty platform, not an error" {
        # A scratch or distroless image genuinely has neither, and that is
        # information rather than a gap.
        $bare = New-JsonFile -Name "bare.cdx.json" -Data @{
            bomFormat = "CycloneDX"; specVersion = "1.5"
            components = @(@{ type = "library"; name = "solo"; version = "1.0.0"; purl = "pkg:npm/solo@1.0.0" })
        }
        $ing = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$bare", "-F", "app_name=$appName-bare", "-F", "build_number=1")
        if ($ing.Status -ne 201) { Show-Body $ing 201; return $false }
        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($ing.Json.scanId)", "-b", $script:platJar)
        return $r.Status -eq 200 -and $null -eq $r.Json.platform.summary -and
               @($r.Json.platform.runtimes).Count -eq 0
    }

    Assert-That "filters applications by OS" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?os=alpine&pageSize=200&status=active&status=inactive&status=pending_confirmation", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        # Every returned application must actually be on Alpine.
        $wrong = $r.Json.items | Where-Object { $_.platform.osName -ne "alpine" }
        return ($null -eq $wrong) -and ($r.Json.total -ge 1)
    }

    Assert-That "filters applications by runtime, and by runtime version" {
        $any = Invoke-Api @("$BaseUrl/api/v1/applications?runtime=node&pageSize=200&status=active&status=inactive&status=pending_confirmation", "-b", $script:platJar)
        $pinned = Invoke-Api @("$BaseUrl/api/v1/applications?runtime=node&runtimeVersion=22.11.0&pageSize=200&status=active&status=inactive&status=pending_confirmation", "-b", $script:platJar)
        if ($any.Status -ne 200 -or $pinned.Status -ne 200) { return $false }
        # Pinning a version can only narrow the result.
        if ($pinned.Json.total -gt $any.Json.total) { return $false }
        $wrong = $any.Json.items | Where-Object {
            -not (@($_.platform.runtimes | ForEach-Object { $_.name }) -contains "node")
        }
        return $null -eq $wrong
      }

    Assert-That "keeps the base OS out of the most-deployed packages list" {
        # The OS is in the inventory and shown as the platform, but ranking
        # "alpine" alongside "log4j-core" would make the blast-radius list
        # useless.
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/top-components?limit=50", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        $names = @($r.Json.components | ForEach-Object { $_.name })
        foreach ($banned in @("alpine", "debian", "ubuntu", "node", "python", "java")) {
            if ($names -contains $banned) {
                Write-Host "        '$banned' should not be listed as a deployed package" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "the OS is still searchable as a component" {
        # Excluded from aggregates, not from the inventory: "which images carry
        # this" remains a legitimate question.
        $r = Invoke-Api @("$BaseUrl/api/v1/components/search?name=alpine&scope=all&match=exact", "-b", $script:platJar)
        $r.Status -eq 200 -and $r.Json.total -ge 1
    }

    Assert-That "reports the platform breakdown across current builds" {
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/platforms", "-b", $script:platJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        $alpine = $r.Json.operatingSystems | Where-Object { $_.name -eq "alpine" } | Select-Object -First 1
        return $null -ne $alpine -and $alpine.applications -ge 1 -and $null -ne $r.Json.runtimes
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Manual SBOM upload (POST /api/v1/applications/:id/scans)" -ForegroundColor Cyan

    # A different document from the CI fixture, so the upload genuinely changes the
    # application's current build rather than landing as a duplicate.
    $manualSbom = @{
        bomFormat    = "CycloneDX"
        specVersion  = "1.5"
        serialNumber = "urn:uuid:$([guid]::NewGuid())"
        version      = 1
        metadata     = @{
            tools     = @{ components = @(@{ type = "application"; name = "syft"; version = "1.18.1" }) }
            component = @{ type = "container"; name = "local/manual-upload:2.0.0" }
        }
        components   = @(
            @{ type = "operating-system"; name = "alpine"; version = "3.20.3"
               properties = @(
                   @{ name = "syft:distro:id"; value = "alpine" }
                   @{ name = "syft:distro:versionID"; value = "3.20.3" }
               ) }
            @{ type = "library"; name = "express"; version = "4.19.2"; purl = "pkg:npm/express@4.19.2" }
            # Present only in the manual upload. Finding this package through the
            # global search is what proves a hand-uploaded SBOM is indexed like any
            # other, rather than merely being stored.
            @{ type = "library"; name = "smoke-manual-only-pkg"; version = "9.9.9"
               purl = "pkg:npm/smoke-manual-only-pkg@9.9.9" }
        )
    }
    $manualPath = New-JsonFile -Data $manualSbom -Name "manual.cdx.json"
    $manualUrl = "$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/scans"

    Assert-That "requires a session" {
        $r = Invoke-Api @("-X", "POST", $manualUrl, "-F", "sbom=@$manualPath")
        $r.Status -eq 401
    }

    Assert-That "rejects a CI ingest token — this route is session-only" {
        # The two auth mechanisms live in separate plugin scopes so they cannot
        # cross over. A token that could post to an arbitrary application id would
        # bypass app_name resolution, aliases and pending auto-creation entirely.
        $r = Invoke-Api @("-X", "POST", $manualUrl, "-H", $auth, "-F", "sbom=@$manualPath")
        Show-Body $r 401
        $r.Status -eq 401
    }

    Assert-That "404s for an application that does not exist" {
        # Never auto-creates: the uploader picked an application that existed when
        # the page loaded, so a missing id means it was deleted underneath them.
        $r = Invoke-Api @("-X", "POST",
            "$BaseUrl/api/v1/applications/00000000-0000-4000-8000-000000000000/scans",
            "-F", "sbom=@$manualPath", "-b", $script:platJar)
        Show-Body $r 404
        $r.Status -eq 404
    }

    Assert-That "rejects a file that is not CycloneDX (422)" {
        $notSbom = New-JsonFile -Name "not-an-sbom.json" -Data @{ hello = "world" }
        $r = Invoke-Api @("-X", "POST", $manualUrl, "-F", "sbom=@$notSbom", "-b", $script:platJar)
        Show-Body $r 422
        $r.Status -eq 422
    }

    Assert-That "rejects a request with no file part (400)" {
        $r = Invoke-Api @("-X", "POST", $manualUrl, "-F", "build_number=1", "-b", $script:platJar)
        Show-Body $r 400
        $r.Status -eq 400
    }

    $script:manual = $null
    Assert-That "accepts a valid upload and returns 201" {
        $r = Invoke-Api @("-X", "POST", $manualUrl,
            "-F", "sbom=@$manualPath",
            "-F", "build_number=manual-1",
            "-F", "branch=hotfix",
            "-F", "note=uploaded by the smoke test",
            "-b", $script:platJar)
        Show-Body $r 201
        $script:manual = $r.Json
        $r.Status -eq 201
    }

    Assert-That "records it as source=manual with the uploader's identity" {
        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($script:manual.scanId)", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        if ($r.Json.source -ne "manual") {
            Write-Host "        source=$($r.Json.source)" -ForegroundColor DarkYellow
            return $false
        }
        # No ingest token, and the note survived.
        return $r.Json.uploadedByEmail -eq $adminEmail -and
               $null -eq $r.Json.ingestTokenName -and
               $r.Json.uploadNote -eq "uploaded by the smoke test"
    }

    Assert-That "became the application's current build" {
        # The whole requirement in one assertion: a manual upload is not a
        # side-channel, it IS the application's state.
        if ($script:manual.becameLatest -ne $true) { return $false }
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)", "-b", $script:platJar)
        return $r.Status -eq 200 -and $r.Json.latestScanId -eq $script:manual.scanId
    }

    Assert-That "its packages are searchable across the estate" {
        # Indexed identically to a CI scan. If this fails, the upload stored bytes
        # without linking components — the failure that would look fine in the UI
        # and be invisible everywhere it matters.
        $r = Invoke-Api @("$BaseUrl/api/v1/components/search?name=smoke-manual-only-pkg&match=exact&scope=current", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        return $r.Json.total -ge 1
    }

    Assert-That "appears in the application's scan history, badged as manual" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/scans?pageSize=50", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        $row = $r.Json.items | Where-Object { $_.id -eq $script:manual.scanId } | Select-Object -First 1
        if ($null -eq $row) { return $false }
        # And the CI scans in the same list are still labelled ci — a default that
        # leaked onto every row would make the badge meaningless.
        $ciRow = $r.Json.items | Where-Object { $_.id -eq $script:ingest.scanId } | Select-Object -First 1
        return $row.source -eq "manual" -and $row.isLatest -eq $true -and $ciRow.source -eq "ci"
    }

    Assert-That "the CI-uploaded scan is now historical, not deleted" {
        # Append-only: a manual upload adds a build, it does not replace one.
        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($script:ingest.scanId)", "-b", $script:platJar)
        return $r.Status -eq 200 -and $r.Json.isLatest -eq $false
    }

    Assert-That "the new build diffs against the previous one" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/diff", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        if ($r.Json.toScan.id -ne $script:manual.scanId) { return $false }
        # smoke-manual-only-pkg is new in this build; requests was dropped.
        $added = @($r.Json.added | ForEach-Object { $_.name })
        return $added -contains "smoke-manual-only-pkg"
    }

    Assert-That "refuses a byte-identical re-upload (409) and names the existing scan" {
        # The double-click guard. Serialised by a per-application advisory lock, so
        # this is a guarantee rather than a race the test happens to win.
        $r = Invoke-Api @("-X", "POST", $manualUrl, "-F", "sbom=@$manualPath", "-b", $script:platJar)
        Show-Body $r 409
        if ($r.Status -ne 409) { return $false }
        return $r.Json.error.details.existingScanId -eq $script:manual.scanId -and
               $r.Json.error.details.existingIsLatest -eq $true
    }

    Assert-That "stores the duplicate when explicitly allowed" {
        $r = Invoke-Api @("-X", "POST", $manualUrl,
            "-F", "sbom=@$manualPath", "-F", "allow_duplicate=true", "-b", $script:platJar)
        Show-Body $r 201
        if ($r.Status -ne 201) { return $false }
        return $r.Json.duplicateOfScanId -eq $script:manual.scanId
    }

    Assert-That "the CI endpoint still accepts a repeated SBOM without complaint" {
        # The duplicate guard must not have leaked onto the pipeline path: a build
        # re-scanning an unchanged artifact produces identical bytes, and failing
        # that would break `curl -f` for a non-problem.
        #
        # A distinct build number rather than reusing 42/43: the diff assertions
        # further down look scans up *by* build number, and two rows sharing one
        # would silently turn a scalar id into an array.
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$sbomPath", "-F", "app_name=$appName", "-F", "build_number=ci-duplicate-check")
        Show-Body $r 201
        $r.Status -eq 201
    }

    Assert-That "logged the upload to the admin audit trail" {
        $r = Invoke-Api @("$BaseUrl/api/v1/admin/audit-log?action=scan.manual_upload&pageSize=10", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        $entry = $r.Json.items | Where-Object { $_.targetId -eq $script:manual.scanId } | Select-Object -First 1
        return $null -ne $entry -and $entry.actorEmail -eq $adminEmail
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Vulnerability scanning (Grype)" -ForegroundColor Cyan

    <#
      These assertions run against whatever state the platform is actually in, and that is
      deliberate: the feature is off by default, may have no database installed, and may be
      on a machine with no route to the internet. Every one of those is a legitimate state,
      so the suite checks the CONTRACTS that must hold in all of them rather than requiring
      a working scanner. Findings-specific assertions are skipped, with a message, when
      there is nothing to find.
    #>

    $vulnAdmin = "$BaseUrl/api/v1/admin/vuln"

    Assert-That "vulnerability admin routes require an admin session" {
        foreach ($u in @("$vulnAdmin/status", "$vulnAdmin/history", "$vulnAdmin/suppressions")) {
            $r = Invoke-Api @($u)
            if ($r.Status -ne 401) { Show-Body $r 401; return $false }
        }
        $r = Invoke-Api @("-X", "POST", "$vulnAdmin/update")
        return $r.Status -eq 401
    }

    Assert-That "vulnerability read routes require a session" {
        foreach ($u in @("$BaseUrl/api/v1/vulnerabilities", "$BaseUrl/api/v1/vuln-status")) {
            $r = Invoke-Api @($u)
            if ($r.Status -ne 401) { Show-Body $r 401; return $false }
        }
        return $true
    }

    $script:vulnStatus = $null
    Assert-That "reports scanner and database state separately" {
        # They fail independently - a binary with no database and a database with no binary
        # need different fixes - so one combined health flag would hide which.
        $r = Invoke-Api @("$vulnAdmin/status", "-b", $script:platJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        $script:vulnStatus = $r.Json
        return $null -ne $r.Json.scanner -and $null -ne $r.Json.database -and
               $null -ne $r.Json.updates -and $null -ne $r.Json.coverage -and
               $r.Json.updates.listingUrl -match "^https?://"
    }

    Assert-That "names every place the binary was looked for when it is missing" {
        # The difference between a two-minute setup and an abandoned one.
        if ($script:vulnStatus.scanner.available) {
            Write-Host "        scanner present ($($script:vulnStatus.scanner.version) via $($script:vulnStatus.scanner.resolvedBy))" -ForegroundColor DarkGray
            return $true
        }
        return @($script:vulnStatus.scanner.attempts).Count -ge 1
    }

    Assert-That "rejects an out-of-range update interval" {
        # A typo must not turn into a request every few seconds against a third party.
        $body = New-JsonFile -Name "vuln-interval-bad.json" -Data @{ intervalHours = 0.01 }
        $r = Invoke-Api @("-X", "PATCH", "$vulnAdmin/settings", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        Show-Body $r 400
        $r.Status -eq 400
    }

    Assert-That "accepts a valid interval and reports it back" {
        $body = New-JsonFile -Name "vuln-interval.json" -Data @{ intervalHours = 3 }
        $r = Invoke-Api @("-X", "PATCH", "$vulnAdmin/settings", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        Show-Body $r 200
        $r.Status -eq 200 -and $r.Json.updates.intervalHours -eq 3
    }

    $script:vulnWasEnabled = [bool]$script:vulnStatus.enabled
    Assert-That "read routes refuse with a distinct code while scanning is disabled" {
        <#
          The most important assertion about this feature.

          A disabled scanner must NOT answer with an empty list. An empty list means "we
          checked and found nothing" - a clean bill of health - and rendering an unassessed
          estate that way is the worst thing this feature could do. So the API distinguishes
          them at the status-code level and the client has to handle it explicitly.
        #>
        $body = New-JsonFile -Name "vuln-off.json" -Data @{ enabled = $false }
        $off = Invoke-Api @("-X", "PATCH", "$vulnAdmin/settings", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        if ($off.Status -ne 200) { Show-Body $off 200; return $false }

        $r = Invoke-Api @("$BaseUrl/api/v1/vulnerabilities", "-b", $script:platJar)
        Show-Body $r 409
        if ($r.Status -ne 409 -or $r.Json.error.code -ne "vuln_scanning_disabled") { return $false }

        # And the status endpoint stays readable, so the UI can tell disabled from broken.
        $st = Invoke-Api @("$BaseUrl/api/v1/vuln-status", "-b", $script:platJar)
        return $st.Status -eq 200 -and $st.Json.enabled -eq $false
    }

    Assert-That "the analytics report omits vulnerability sections rather than zeroing them" {
        # Same reasoning in the report: null means "not assessed", and a zero-filled object
        # would be indistinguishable from a clean estate.
        $r = Invoke-Api @("$BaseUrl/api/v1/analytics/report?periodDays=30", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        return $null -eq $r.Json.vulnerabilities
    }

    Assert-That "the overview endpoint reports null, not an empty structure" {
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities", "-b", $script:platJar)
        return $r.Status -eq 200 -and $null -eq $r.Json.vulnerabilities
    }

    Assert-That "ingestion is unaffected while scanning is disabled" {
        # The governing rule: nothing about this feature may break anything else.
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$sbomPath", "-F", "app_name=$appName", "-F", "build_number=vuln-off")
        Show-Body $r 201
        $r.Status -eq 201
    }

    Assert-That "enabling scanning is reported and audited" {
        $body = New-JsonFile -Name "vuln-on.json" -Data @{ enabled = $true }
        $r = Invoke-Api @("-X", "PATCH", "$vulnAdmin/settings", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        Show-Body $r 200
        if ($r.Status -ne 200 -or $r.Json.enabled -ne $true) { return $false }

        $audit = Invoke-Api @("$BaseUrl/api/v1/admin/audit-log?action=vuln.settings_update&pageSize=5", "-b", $script:platJar)
        return $audit.Status -eq 200 -and @($audit.Json.items).Count -ge 1
    }

    Assert-That "read routes become available once enabled" {
        $r = Invoke-Api @("$BaseUrl/api/v1/vulnerabilities?scope=all", "-b", $script:platJar)
        Show-Body $r 200
        $r.Status -eq 200 -and $null -ne $r.Json.items
    }

    Assert-That "a database update attempt always answers, online or not" {
        <#
          Either outcome is a pass. On a connected machine this updates or reports
          already-current; on an air-gapped one it reports unreachable and names the exact
          URL. What must never happen is a 5xx, because being offline is a state to report
          rather than a request that failed.
        #>
        $r = Invoke-Api @("-X", "POST", "$vulnAdmin/update", "-b", $script:platJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        if ($r.Json.outcome -notin @("updated", "already-current", "unreachable", "failed", "busy")) {
            Write-Host "        unexpected outcome: $($r.Json.outcome)" -ForegroundColor DarkYellow
            return $false
        }
        if ($r.Json.outcome -eq "unreachable" -and $r.Json.message -notmatch "https?://") {
            Write-Host "        an unreachable outcome must name the URL it could not reach" -ForegroundColor DarkYellow
            return $false
        }
        Write-Host "        outcome: $($r.Json.outcome)" -ForegroundColor DarkGray
        return $true
    }

    Assert-That "a failed update leaves the platform fully working" {
        # Whatever happened above, every other endpoint must be unaffected.
        foreach ($u in @("$BaseUrl/api/v1/applications", "$BaseUrl/api/v1/dashboard/stats",
                         "$BaseUrl/api/v1/components/search?name=express&match=exact")) {
            $r = Invoke-Api @($u, "-b", $script:platJar)
            if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        }
        $ing = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$sbomPath", "-F", "app_name=$appName", "-F", "build_number=vuln-on")
        return $ing.Status -eq 201
    }

    $script:vulnReady = $false
    Assert-That "sweeps the component set when a database is available" {
        $st = Invoke-Api @("$vulnAdmin/status", "-b", $script:platJar)
        if ($st.Status -ne 200) { return $false }
        if (-not $st.Json.scanner.available) {
            Write-Host "        skipped: no grype binary (run npm run grype:install)" -ForegroundColor DarkGray
            return $true
        }
        if (-not $st.Json.database.present) {
            Write-Host "        skipped: no vulnerability database installed" -ForegroundColor DarkGray
            return $true
        }

        $r = Invoke-Api @("-X", "POST", "$vulnAdmin/sweep", "-b", $script:platJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        if ($r.Json.status -notin @("completed", "already-running")) {
            Write-Host "        sweep status: $($r.Json.status) - $($r.Json.message)" -ForegroundColor DarkYellow
            return $false
        }
        $script:vulnReady = $true
        return $true
    }

    Assert-That "findings are split app vs base image and ranked on app findings alone" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        $v = $r.Json.vulnerabilities
        if ($null -eq $v) {
            Write-Host "        expected a populated report once scanning is enabled" -ForegroundColor DarkYellow
            return $false
        }
        # The two groups must be reported separately and never merged. Base-image packages
        # outnumber dependencies by orders of magnitude on real images, so a single total
        # would be a base-image-age metric wearing a dependency label.
        if ($null -eq $v.app -or $null -eq $v.baseImage) { return $false }
        foreach ($row in @($v.topVulnerableApplications)) {
            if ($row.findings -le 0) {
                Write-Host "        a ranked application has no application-dependency findings" -ForegroundColor DarkYellow
                return $false
            }
        }
        # Descending by app findings, ignoring base-image counts entirely.
        $ordered = @($v.topVulnerableApplications | ForEach-Object { $_.findings })
        for ($i = 1; $i -lt $ordered.Count; $i++) {
            if ($ordered[$i] -gt $ordered[$i - 1]) {
                Write-Host "        ranking is not descending by application-dependency findings" -ForegroundColor DarkYellow
                return $false
            }
        }
        $appSum = Get-SeveritySum $v.app.counts
        $osSum = Get-SeveritySum $v.baseImage.counts
        Write-Host "        app findings: $appSum, base image: $osSum" -ForegroundColor DarkGray
        # Both halves get the same figures. Base image is a first-class scope now, not a
        # single number hanging off the application panel.
        if ($null -eq $v.baseImage.fixable -or $null -eq $v.baseImage.affectedPackages) {
            Write-Host "        base image is missing the figures the application half reports" -ForegroundColor DarkYellow
            return $false
        }
        # Nothing was narrowed, so no filter must be advertised and no reference block
        # emitted - a "Filtered:" line on an unfiltered dashboard makes every reader
        # wonder what they are not being shown.
        if ($v.filter.active -ne $false -or $null -ne $v.unfiltered) { return $false }
        return $true
    }

    Assert-That "an explicitly-everything filter is identical to no filter" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        # Selecting every bucket narrows nothing, so it must collapse to the inert filter.
        # Otherwise the page would advertise a filter that excludes nothing, and the service
        # would take the slow exact path to compute the same answer.
        $bare = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities", "-b", $script:platJar)
        $all = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities?scope=all&severity=critical,high,medium,low,other", "-b", $script:platJar)
        if ($bare.Status -ne 200 -or $all.Status -ne 200) { return $false }
        $a = $bare.Json.vulnerabilities
        $b = $all.Json.vulnerabilities
        if ($b.filter.active -ne $false) {
            Write-Host "        a filter selecting everything was reported as active" -ForegroundColor DarkYellow
            return $false
        }
        return (Get-SeveritySum $a.app.counts) -eq (Get-SeveritySum $b.app.counts) -and
               (Get-SeveritySum $a.baseImage.counts) -eq (Get-SeveritySum $b.baseImage.counts) -and
               $a.applicationsAffected -eq $b.applicationsAffected
    }

    Assert-That "the five severity buckets partition the totals exactly" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        <#
          The arithmetic property the whole display rests on, checked against real data.

          Each bucket is fetched on its own and the five results are summed. If the jsonb
          severity summation double-counted, dropped a severity, or mismatched the bucket
          definition, the sum would not close - and a reader who adds the visible columns
          and gets a different total stops trusting every other figure on the page.
        #>
        $bare = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities", "-b", $script:platJar)
        if ($bare.Status -ne 200) { return $false }
        $whole = $bare.Json.vulnerabilities
        $appWhole = Get-SeveritySum $whole.app.counts
        $osWhole = Get-SeveritySum $whole.baseImage.counts

        $appParts = 0
        $osParts = 0
        foreach ($bucket in @("critical", "high", "medium", "low", "other")) {
            $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities?severity=$bucket", "-b", $script:platJar)
            if ($r.Status -ne 200) { Show-Body $r 200; return $false }
            $part = $r.Json.vulnerabilities
            if ($part.filter.active -ne $true) { return $false }
            # A filtered payload must carry what it was narrowed from, or a reader has no
            # way to judge the size of what was excluded.
            if ($null -eq $part.unfiltered) {
                Write-Host "        a filtered payload omitted the unfiltered reference totals" -ForegroundColor DarkYellow
                return $false
            }
            if ((Get-SeveritySum $part.unfiltered.app) -ne $appWhole) {
                Write-Host "        the reference totals disagree with the unfiltered request" -ForegroundColor DarkYellow
                return $false
            }
            $appParts += Get-SeveritySum $part.app.counts
            $osParts += Get-SeveritySum $part.baseImage.counts
        }

        Write-Host "        app $appParts/$appWhole, base image $osParts/$osWhole" -ForegroundColor DarkGray
        return $appParts -eq $appWhole -and $osParts -eq $osWhole
    }

    Assert-That "a severity filter recounts the rankings rather than filtering rows" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        <#
          A single-severity filter must recount every figure on a row, not just narrow which
          rows appear.

          The bucket is chosen from the live breakdown rather than hardcoded. Hardcoding
          `critical` made this pass vacuously on an estate whose application dependencies
          happen to have none - a loop over an empty list asserts nothing, which is worse
          than no test because it reads like coverage.

          The check itself: under a single-bucket filter, the severities NOT in that bucket
          must be zero on every row, and the one that is must equal the row's findings
          count. The unfiltered path reads both numbers from the per-scan snapshot; the
          filtered path recomputes them over the findings tables, because the snapshot's
          fixable and known-exploited columns are not severity-split. If either number came
          from the wrong source, they would diverge here.
        #>
        $bare = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities", "-b", $script:platJar)
        if ($bare.Status -ne 200) { return $false }
        $counts = $bare.Json.vulnerabilities.app.counts

        $bucket = $null
        foreach ($candidate in @("critical", "high", "medium", "low")) {
            if ([int]$counts.$candidate -gt 0) { $bucket = $candidate; break }
        }
        if ($null -eq $bucket) {
            Write-Host "        skipped: no rated application-dependency findings to filter" -ForegroundColor DarkGray
            return $true
        }

        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities?severity=$bucket", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        $v = $r.Json.vulnerabilities
        $rows = @($v.topVulnerableApplications)
        if ($rows.Count -lt 1) {
            Write-Host "        $bucket has findings in the totals but ranked no applications" -ForegroundColor DarkYellow
            return $false
        }

        $previous = [int]::MaxValue
        foreach ($row in $rows) {
            if ($row.findings -le 0) {
                Write-Host "        $($row.name) was ranked with no matching findings" -ForegroundColor DarkYellow
                return $false
            }
            if ($row.rankedBy -ne "app") { return $false }
            # Descending, and on the filtered count rather than the unfiltered one.
            if ($row.findings -gt $previous) {
                Write-Host "        ranking is not descending by the filtered count" -ForegroundColor DarkYellow
                return $false
            }
            $previous = [int]$row.findings
            foreach ($severity in @("critical", "high")) {
                $expected = if ($severity -eq $bucket) { [int]$row.findings } else { 0 }
                if ([int]$row.$severity -ne $expected) {
                    Write-Host "        $($row.name): $severity is $($row.$severity), expected $expected under severity=$bucket" -ForegroundColor DarkYellow
                    return $false
                }
            }
        }
        # Every advisory on a listed package must be in the bucket too, for the same reason.
        foreach ($pkg in @($v.topVulnerablePackages)) {
            foreach ($severity in @("critical", "high")) {
                $expected = if ($severity -eq $bucket) { [int]$pkg.findings } else { 0 }
                if ([int]$pkg.$severity -ne $expected) { return $false }
            }
        }
        Write-Host "        $($rows.Count) applications ranked on $bucket alone, $(Get-SeveritySum $v.app.counts) findings" -ForegroundColor DarkGray
        return $true
    }

    Assert-That "a scope filter excludes the other half rather than reporting it as zero" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        <#
          The invariant this whole feature is built around, applied one level down from the
          feature flag: "not counted" and "counted, found none" must stay distinguishable.
          A zeroed base-image panel under an application-only filter would read as a clean
          base image, which is a far stronger claim than "we did not look".
        #>
        $app = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities?scope=app", "-b", $script:platJar)
        if ($app.Status -ne 200) { Show-Body $app 200; return $false }
        $v = $app.Json.vulnerabilities
        if ($null -ne $v.baseImage) {
            Write-Host "        base image was reported despite being excluded by scope" -ForegroundColor DarkYellow
            return $false
        }
        if ($null -ne $v.baseImageExposure) {
            Write-Host "        base-image exposure was returned as a list rather than null" -ForegroundColor DarkYellow
            return $false
        }
        if ($null -eq $v.app) { return $false }
        if ($v.filter.label -ne "Application dependencies") { return $false }

        # And the mirror image: base image only, with the rankings switching to it because
        # there is no application half left to rank.
        $os = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities?scope=os", "-b", $script:platJar)
        if ($os.Status -ne 200) { return $false }
        $w = $os.Json.vulnerabilities
        if ($null -ne $w.app -or $null -eq $w.baseImage) { return $false }
        foreach ($row in @($w.topVulnerableApplications)) {
            if ($row.rankedBy -ne "os") { return $false }
            # The excluded half is null on the row too, so the merged column prints a dash.
            if ($null -ne $row.findings) { return $false }
            if ($null -eq $row.baseImageFindings) { return $false }
        }
        return $true
    }

    Assert-That "the PDF accepts the same filter as the screen" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        # A Download button that quietly produced a different report than the one on display
        # is the drift the single-payload design exists to prevent.
        $out = Join-Path $workDir "filtered-report.pdf"
        $r = Invoke-Api @("$BaseUrl/api/v1/analytics/report.pdf?periodDays=30&scope=app&severity=critical,high",
            "-b", $script:platJar, "-o", $out)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        if (-not (Test-Path $out)) { return $false }
        $size = (Get-Item $out).Length
        Write-Host "        filtered PDF: $size bytes" -ForegroundColor DarkGray
        # %PDF header, and large enough to be a real document rather than an error page.
        $head = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($out)[0..3])
        return $head -eq "%PDF" -and $size -gt 4000
    }

    Assert-That "a CVE number finds an advisory reported under a GHSA id" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        # The alias path. Grype's primary id for a language package is usually a GHSA, and
        # someone searching the CVE they read in the news has to reach the same row.
        $r = Invoke-Api @("$BaseUrl/api/v1/vulnerabilities?q=CVE-2021-44228&scope=all&currentOnly=false", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        if ($r.Json.total -lt 1) {
            Write-Host "        no match for CVE-2021-44228 (the demo seed ships log4j 2.14.1 historically)" -ForegroundColor DarkYellow
            return $false
        }
        $hit = @($r.Json.items)[0]
        return ($hit.aliases -contains "CVE-2021-44228") -or ($hit.vulnerabilityId -eq "CVE-2021-44228")
    }

    Assert-That "the analytics report and the overview agree on the totals" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        # One payload, two renderings. A printed report disagreeing with the screen is the
        # failure that destroys trust in a reporting tool.
        $rep = Invoke-Api @("$BaseUrl/api/v1/analytics/report?periodDays=30", "-b", $script:platJar)
        $dash = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities", "-b", $script:platJar)
        if ($rep.Status -ne 200 -or $dash.Status -ne 200) { return $false }
        if ($null -eq $rep.Json.vulnerabilities) { return $false }
        return $rep.Json.vulnerabilities.app.counts.critical -eq $dash.Json.vulnerabilities.app.counts.critical -and
               $rep.Json.vulnerabilities.app.fixable -eq $dash.Json.vulnerabilities.app.fixable -and
               $rep.Json.vulnerabilities.applicationsAffected -eq $dash.Json.vulnerabilities.applicationsAffected
    }

    Assert-That "the report and the overview agree under the same filter too" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        # The agreement has to survive the filter, or the analytics page and the overview
        # would disagree the moment either one is narrowed.
        $q = "scope=app&severity=critical,high"
        $rep = Invoke-Api @("$BaseUrl/api/v1/analytics/report?periodDays=30&$q", "-b", $script:platJar)
        $dash = Invoke-Api @("$BaseUrl/api/v1/dashboard/vulnerabilities?$q", "-b", $script:platJar)
        if ($rep.Status -ne 200 -or $dash.Status -ne 200) { return $false }
        $a = $rep.Json.vulnerabilities
        $b = $dash.Json.vulnerabilities
        if ($null -eq $a -or $null -eq $b) { return $false }
        return $a.filter.label -eq $b.filter.label -and
               (Get-SeveritySum $a.app.counts) -eq (Get-SeveritySum $b.app.counts) -and
               $a.app.fixable -eq $b.app.fixable
    }

    Assert-That "an accepted risk is recorded, listed and removable" {
        if (-not $script:vulnReady) {
            Write-Host "        skipped: scanner or database unavailable" -ForegroundColor DarkGray
            return $true
        }
        $adv = Invoke-Api @("$BaseUrl/api/v1/vulnerabilities?scope=all&pageSize=1", "-b", $script:platJar)
        if ($adv.Status -ne 200 -or @($adv.Json.items).Count -lt 1) {
            Write-Host "        skipped: no advisory to suppress" -ForegroundColor DarkGray
            return $true
        }
        $target = @($adv.Json.items)[0].vulnerabilityId

        $body = New-JsonFile -Name "suppress.json" -Data @{ vulnerabilityId = $target; reason = "smoke test accepted risk" }
        $created = Invoke-Api @("-X", "POST", "$vulnAdmin/suppressions", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        Show-Body $created 201
        if ($created.Status -ne 201) { return $false }

        # Hidden, never deleted - the decision has to stay auditable.
        $list = Invoke-Api @("$vulnAdmin/suppressions", "-b", $script:platJar)
        $found = @($list.Json.suppressions | Where-Object { $_.vulnerabilityId -eq $target })
        if ($found.Count -lt 1) { return $false }

        $del = Invoke-Api @("-X", "DELETE", "$vulnAdmin/suppressions/$($found[0].id)", "-b", $script:platJar)
        return $del.Status -eq 204
    }

    Assert-That "requires a reason before accepting a risk" {
        # An unexplained suppression is indistinguishable from a mistake later.
        $body = New-JsonFile -Name "suppress-bad.json" -Data @{ vulnerabilityId = "CVE-2021-44228"; reason = "" }
        $r = Invoke-Api @("-X", "POST", "$vulnAdmin/suppressions", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        Show-Body $r 400
        $r.Status -eq 400
    }

    Assert-That "restores the vulnerability setting this run found" {
        # Leaves the platform as it was: this suite must not flip a feature flag for whoever
        # runs it next.
        $body = New-JsonFile -Name "vuln-restore.json" -Data @{ enabled = $script:vulnWasEnabled }
        $r = Invoke-Api @("-X", "PATCH", "$vulnAdmin/settings", "-H", "Content-Type: application/json",
            "--data-binary", "@$body", "-b", $script:platJar)
        return $r.Status -eq 200 -and $r.Json.enabled -eq $script:vulnWasEnabled
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Bulk package list search" -ForegroundColor Cyan

    Assert-That "requires a session" {
        $body = New-JsonFile -Name "bulk-anon.json" -Data @{ input = "express" }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body")
        return $r.Status -eq 401
    }

    Assert-That "searches a mixed-format list and reports a verdict per line" {
        # Every accepted input form in one list, plus deliberate misses. The
        # fixture SBOM ingested earlier guarantees `express` and `lodash` exist.
        $lines = @(
            "# smoke list",
            "express",
            "express@4.19.2",
            "express@0.0.0-never-shipped",
            "lodash",
            "django>=4.2",
            "pkg:npm/lodash@4.17.21",
            "pkg:pypi/lodash",
            "com.fasterxml.jackson.core:jackson-databind:2.17.2",
            "@wb-track/shared-front",
            "logaas",
            "Express",
            "this is not a package at all",
            "https://example.com/x"
        )
        $body = New-JsonFile -Name "bulk-list.json" -Data @{
            input = ($lines -join "`n"); scope = "all"
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        $script:bulk = $r.Json

        # 13 content lines, 2 unparseable, 1 duplicate (Express) -> 10 entries.
        if ($r.Json.parse.lines -ne 13) {
            Write-Host "        parse.lines=$($r.Json.parse.lines) expected 13" -ForegroundColor DarkYellow
            return $false
        }
        if (@($r.Json.parse.problems).Count -ne 2) {
            Write-Host "        problems=$(@($r.Json.parse.problems).Count) expected 2" -ForegroundColor DarkYellow
            return $false
        }
        if ($r.Json.parse.duplicatesCollapsed -lt 1) { return $false }
        if ($r.Json.parse.constraintsDropped -lt 1) { return $false }
        # One rollup row per searched entry, and a saved id to share.
        if (@($r.Json.rollup).Count -ne $r.Json.parse.entries) { return $false }
        return $r.Json.queryId -match "^[0-9a-f-]{36}$"
    }

    Assert-That "the scoped npm name survives parsing as a name, not a version" {
        # The trap: a leading @ is a scope marker. Splitting on it would search for
        # a package called "" at version "wb-track/shared-front".
        $row = $script:bulk.rollup | Where-Object { $_.name -eq "@wb-track/shared-front" } | Select-Object -First 1
        return $null -ne $row -and $null -eq $row.version
    }

    Assert-That "distinguishes 'wrong version' from 'never seen'" {
        # The distinction the feature exists for: express@0.0.0 is absent, but
        # express itself is deployed. Collapsing both into "not found" would answer
        # a security question wrongly.
        $wrongVersion = $script:bulk.rollup | Where-Object { $_.raw -eq "express@0.0.0-never-shipped" } | Select-Object -First 1
        $neverSeen = $script:bulk.rollup | Where-Object { $_.name -eq "logaas" } | Select-Object -First 1
        if ($null -eq $wrongVersion -or $null -eq $neverSeen) { return $false }

        if ($wrongVersion.found -ne $false -or $wrongVersion.nameFound -ne $true) {
            Write-Host "        express@0.0.0: found=$($wrongVersion.found) nameFound=$($wrongVersion.nameFound)" -ForegroundColor DarkYellow
            return $false
        }
        # And it must name what IS deployed, or the row is a dead end.
        if (@($wrongVersion.versionsFound).Count -lt 1) { return $false }

        return $neverSeen.found -eq $false -and $neverSeen.nameFound -eq $false
    }

    Assert-That "an ecosystem-qualified purl constrains the match" {
        # lodash is npm; asking for it in pypi must miss, or the ecosystem in a
        # purl is decorative.
        $npm = $script:bulk.rollup | Where-Object { $_.raw -eq "pkg:npm/lodash@4.17.21" } | Select-Object -First 1
        $pypi = $script:bulk.rollup | Where-Object { $_.raw -eq "pkg:pypi/lodash" } | Select-Object -First 1
        return $npm.found -eq $true -and $pypi.found -eq $false
    }

    Assert-That "a version range is flagged rather than matched literally" {
        $row = $script:bulk.rollup | Where-Object { $_.raw -eq "django>=4.2" } | Select-Object -First 1
        return $null -ne $row -and $row.versionKind -eq "version-ignored"
    }

    Assert-That "rollup order follows the pasted list" {
        # A reader checking their own list against the results should not have to
        # re-sort it.
        $lineNumbers = @($script:bulk.rollup | ForEach-Object { $_.line })
        for ($i = 1; $i -lt $lineNumbers.Count; $i++) {
            if ($lineNumbers[$i] -le $lineNumbers[$i - 1]) { return $false }
        }
        return $lineNumbers.Count -gt 1
    }

    Assert-That "summary counts agree with the rollup rows" {
        $rollup = @($script:bulk.rollup)
        $found = @($rollup | Where-Object { $_.found }).Count
        $inUse = @($rollup | Where-Object { $_.currentApplications -gt 0 }).Count
        if ($script:bulk.summary.found -ne $found) { return $false }
        if ($script:bulk.summary.notFound -ne ($rollup.Count - $found)) { return $false }
        return $script:bulk.summary.inCurrentUse -eq $inUse
    }

    Assert-That "resubmitting the same list returns the same shareable id" {
        # Content-addressed, so the URL is stable and clicking twice does not
        # accumulate rows.
        $body = New-JsonFile -Name "bulk-again.json" -Data @{
            input = "lodash`nexpress"; scope = "all"
        }
        $first = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body", "-b", $script:platJar)
        # Reordered and re-cased: same question, so it must collapse onto one row.
        $body2 = New-JsonFile -Name "bulk-again2.json" -Data @{
            input = "Express`n`n# note`nlodash"; scope = "all"
        }
        $second = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body2", "-b", $script:platJar)
        if ($first.Status -ne 200 -or $second.Status -ne 200) { return $false }
        return $first.Json.queryId -eq $second.Json.queryId
    }

    Assert-That "a saved list re-runs from its own URL" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/bulk-search/$($script:bulk.queryId)?scope=all", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        # The raw text comes back so a shared link repopulates the input box.
        if ($r.Json.input -notmatch "smoke list") { return $false }
        return @($r.Json.rollup).Count -eq @($script:bulk.rollup).Count
    }

    Assert-That "returns 404 for an unknown list id" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/bulk-search/00000000-0000-4000-8000-000000000000", "-b", $script:platJar)
        return $r.Status -eq 404
    }

    Assert-That "the flat view narrows with scope and pairs are consistent" {
        $url = "$BaseUrl/api/v1/components/bulk-search/$($script:bulk.queryId)"
        $cur = Invoke-Api @("$url`?view=matches&scope=current", "-b", $script:platJar)
        $hist = Invoke-Api @("$url`?view=matches&scope=historical", "-b", $script:platJar)
        $all = Invoke-Api @("$url`?view=matches&scope=all", "-b", $script:platJar)
        if ($cur.Status -ne 200 -or $hist.Status -ne 200 -or $all.Status -ne 200) { return $false }

        # Every pair is either current or historical, so the two must partition all.
        $sum = $cur.Json.matches.total + $hist.Json.matches.total
        if ($sum -ne $all.Json.matches.total) {
            Write-Host "        current=$($cur.Json.matches.total) + historical=$($hist.Json.matches.total) != all=$($all.Json.matches.total)" -ForegroundColor DarkYellow
            return $false
        }
        # And the usage label must match the scope asked for.
        $wrong = $cur.Json.matches.items | Where-Object { $_.usage -ne "current" }
        return $null -eq $wrong
    }

    Assert-That "rejects an empty list and one that is too large" {
        $empty = New-JsonFile -Name "bulk-empty.json" -Data @{ input = "" }
        $e = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$empty", "-b", $script:platJar)
        if ($e.Status -ne 400) {
            Write-Host "        empty input returned $($e.Status), expected 400" -ForegroundColor DarkYellow
            return $false
        }

        # Over the entry cap: accepted, but it must say it was cut rather than
        # silently reporting on a prefix.
        $many = (1..1200 | ForEach-Object { "smoke-pkg-$_" }) -join "`n"
        $big = New-JsonFile -Name "bulk-big.json" -Data @{ input = $many }
        $b = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$big", "-b", $script:platJar)
        if ($b.Status -ne 200) { Show-Body $b 200; return $false }
        return $b.Json.parse.truncated -eq $true -and $b.Json.parse.entries -eq 1000
    }

    Assert-That "lists recently searched lists" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/bulk-search?limit=5", "-b", $script:platJar)
        if ($r.Status -ne 200) { return $false }
        $mine = $r.Json.lists | Where-Object { $_.id -eq $script:bulk.queryId }
        return $null -ne $mine -and @($mine.preview).Count -gt 0
    }

    Assert-That "exports the results as a real .xlsx workbook" {
        $xlsxPath = Join-Path $workDir "bulk.xlsx"
        $hdrPath = Join-Path $workDir "bulk.headers"
        $code = & curl.exe -s -o $xlsxPath -D $hdrPath -w "%{http_code}" `
            "$BaseUrl/api/v1/components/bulk-search/$($script:bulk.queryId)/export.xlsx?scope=all" -b $script:platJar
        if ("$code" -ne "200") {
            Write-Host "        status $code" -ForegroundColor DarkYellow
            return $false
        }

        $headers = Get-Content $hdrPath -Raw
        if ($headers -notmatch "(?i)spreadsheetml\.sheet") {
            Write-Host "        wrong content-type" -ForegroundColor DarkYellow
            return $false
        }
        if ($headers -notmatch "(?i)attachment; filename=`"package-list-\d{4}-\d{2}-\d{2}\.xlsx`"") {
            Write-Host "        unexpected content-disposition" -ForegroundColor DarkYellow
            return $false
        }

        # A real workbook is a ZIP container: "PK" magic, not a CSV renamed .xlsx.
        $bytes = [System.IO.File]::ReadAllBytes($xlsxPath)
        if ($bytes.Length -lt 4096) { return $false }
        if ($bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) { return $false }

        # And it must actually contain the expected sheets.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($xlsxPath)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -eq "xl/workbook.xml" }
            if ($null -eq $entry) { return $false }
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $xml = $reader.ReadToEnd()
            $reader.Close()
            foreach ($sheet in @("Summary", "Packages", "Matches")) {
                if ($xml -notmatch [regex]::Escape($sheet)) {
                    Write-Host "        missing sheet: $sheet" -ForegroundColor DarkYellow
                    return $false
                }
            }
        }
        finally { $zip.Dispose() }
        return $true
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Analytics and reporting" -ForegroundColor Cyan

    Assert-That "the report requires a session" {
        $r = Invoke-Api @("$BaseUrl/api/v1/analytics/report")
        $p = Invoke-Api @("$BaseUrl/api/v1/analytics/report.pdf")
        return $r.Status -eq 401 -and $p.Status -eq 401
    }

    Assert-That "returns every report section" {
        $r = Invoke-Api @("$BaseUrl/api/v1/analytics/report", "-b", $script:platJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        $script:report = $r.Json
        foreach ($section in @("meta", "totals", "coverage", "topPackages", "topProjects",
                               "fragmentation", "newPackages", "velocity", "activity",
                               "ecosystems", "platforms")) {
            if ($null -eq $r.Json.$section) {
                Write-Host "        missing section: $section" -ForegroundColor DarkYellow
                return $false
            }
        }
        # Provenance is what stops a circulated report being read as current.
        return $r.Json.meta.generatedBy -eq $adminEmail -and
               $r.Json.meta.periodDays -eq 30 -and
               $null -ne $r.Json.meta.generatedAt
    }

    Assert-That "honours the reporting window and rejects one out of range" {
        $ok = Invoke-Api @("$BaseUrl/api/v1/analytics/report?periodDays=7", "-b", $script:platJar)
        if ($ok.Status -ne 200 -or $ok.Json.meta.periodDays -ne 7) { return $false }
        # A shorter window can never contain more scans than a longer one.
        if ($ok.Json.totals.scansInPeriod -gt $script:report.totals.scansInPeriod) { return $false }

        foreach ($bad in @(0, -5, 9999)) {
            $r = Invoke-Api @("$BaseUrl/api/v1/analytics/report?periodDays=$bad", "-b", $script:platJar)
            if ($r.Status -ne 400) {
                Write-Host "        periodDays=$bad returned $($r.Status), expected 400" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "the activity buckets sum to the scans reported for the window" {
        # The buckets are day- or week-aligned, so the first one starts earlier
        # than the window itself. If its lower bound is not clamped, the chart
        # totals more scans than the figure printed beside it.
        $sum = 0
        foreach ($b in @($script:report.activity)) { $sum += $b.scans }
        if ($sum -ne $script:report.totals.scansInPeriod) {
            Write-Host "        buckets=$sum scansInPeriod=$($script:report.totals.scansInPeriod)" -ForegroundColor DarkYellow
            return $false
        }
        return @($script:report.activity).Count -ge 1
    }

    Assert-That "coverage arithmetic is internally consistent" {
        $c = $script:report.coverage
        if ($c.covered + $c.stale -gt $c.eligible) { return $false }
        $expected = 0
        if ($c.eligible -gt 0) { $expected = [Math]::Round(($c.covered / $c.eligible) * 100) }
        if ($c.coveragePct -ne $expected) {
            Write-Host "        coveragePct=$($c.coveragePct) expected=$expected" -ForegroundColor DarkYellow
            return $false
        }
        # Every named offender must genuinely be stale or unscanned.
        foreach ($o in @($c.worstOffenders)) {
            if ($null -ne $o.lastScanAt -and $o.daysSinceScan -lt $script:report.meta.staleThresholdDays) {
                Write-Host "        $($o.name) is not stale but was listed" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "ranks projects by package count, descending" {
        $counts = @($script:report.topProjects | ForEach-Object { $_.packages })
        for ($i = 1; $i -lt $counts.Count; $i++) {
            if ($counts[$i] -gt $counts[$i - 1]) { return $false }
        }
        return $counts.Count -ge 1
    }

    Assert-That "keeps the OS and runtimes out of the report's package rankings" {
        $names = @($script:report.topPackages | ForEach-Object { $_.name })
        $names += @($script:report.fragmentation | ForEach-Object { $_.name })
        $names += @($script:report.newPackages | ForEach-Object { $_.name })
        foreach ($banned in @("alpine", "debian", "ubuntu", "node", "python", "java")) {
            if ($names -contains $banned) {
                Write-Host "        '$banned' should not appear as a package" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "churn counts are only reported when there is a baseline to compare" {
        $v = $script:report.velocity
        if ($v.applicationsCompared -eq 0) {
            # Nothing comparable means the figures must be zero rather than
            # arbitrary — zero here reads as "not measured", which the UI says.
            return $v.packagesAdded -eq 0 -and $v.packagesRemoved -eq 0 -and $v.packagesUpgraded -eq 0
        }
        return $v.packagesAdded -ge 0 -and $v.packagesRemoved -ge 0 -and $v.packagesUpgraded -ge 0
    }

    Assert-That "the three churn buckets account for every scanned application" {
        # Compared + first-time + unchanged must cover all non-inactive
        # applications that have a build. If one bucket were derived by
        # subtraction from a differently-scoped total, this would not hold.
        $v = $script:report.velocity
        $t = $script:report.totals
        $sum = $v.applicationsCompared + $v.applicationsWithoutBaseline + $v.applicationsUnchanged
        $scannable = $t.applications - $t.inactiveApplications
        if ($sum -gt $scannable) {
            Write-Host "        buckets=$sum exceed non-inactive apps=$scannable" -ForegroundColor DarkYellow
            return $false
        }
        # With nothing unscanned the coverage is exact, so demand equality.
        if ($script:report.coverage.neverScanned -eq 0 -and $sum -ne $scannable) {
            Write-Host "        buckets=$sum should equal $scannable" -ForegroundColor DarkYellow
            return $false
        }
        return $true
    }

    Assert-That "serves the report as a downloadable PDF" {
        # Binary, so this goes straight to disk: Invoke-Api decodes stdout as text
        # and would corrupt the bytes it is meant to be checking.
        $pdfPath = Join-Path $workDir "estate-report.pdf"
        $hdrPath = Join-Path $workDir "estate-report.headers"
        $code = & curl.exe -s -o $pdfPath -D $hdrPath -w "%{http_code}" `
            "$BaseUrl/api/v1/analytics/report.pdf?periodDays=30" -b $script:platJar
        if ("$code" -ne "200") {
            Write-Host "        status $code" -ForegroundColor DarkYellow
            return $false
        }

        $headers = Get-Content $hdrPath -Raw
        if ($headers -notmatch "(?i)content-type:\s*application/pdf") {
            Write-Host "        content-type not application/pdf" -ForegroundColor DarkYellow
            return $false
        }
        # Date-stamped, so a folder of these sorts chronologically instead of
        # overwriting.
        if ($headers -notmatch "(?i)filename=`"sbom-estate-report-\d{4}-\d{2}-\d{2}\.pdf`"") {
            Write-Host "        unexpected content-disposition" -ForegroundColor DarkYellow
            return $false
        }
        # Regenerated per request and stamped with its own generation time, so a
        # cached copy would misreport its freshness.
        if ($headers -notmatch "(?i)cache-control:.*no-store") { return $false }

        $bytes = [System.IO.File]::ReadAllBytes($pdfPath)
        if ($bytes.Length -lt 4096) {
            Write-Host "        pdf is only $($bytes.Length) bytes" -ForegroundColor DarkYellow
            return $false
        }
        $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 5)
        $tail = [System.Text.Encoding]::ASCII.GetString($bytes, $bytes.Length - 32, 32)
        return $magic -eq "%PDF-" -and $tail -match "%%EOF"
    }

    Assert-That "a second scan reuses the app rather than re-creating it" {
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$sbomPath", "-F", "app_name=$appName", "-F", "build_number=43")
        Show-Body $r 201
        $r.Status -eq 201 -and
        $r.Json.applicationCreated -eq $false -and
        $r.Json.applicationId -eq $script:ingest.applicationId
    }

    Assert-That "two concurrent first builds of a new app both succeed" {
        <#
          Regression guard for a real bug, found by probing a claim rather than a
          symptom.

          `resolveApplication` used to insert the auto-created application and catch
          the unique violation when a concurrent build won the race. That cannot
          work: Postgres aborts the whole transaction on a failed statement, so the
          recovering SELECT died with SQLSTATE 25P02 and the loser got a 500. It
          reproduced 9 times in 10. `ON CONFLICT DO NOTHING` never raises, so the
          transaction stays usable.

          Matters because a monorepo pipeline or a mass rebuild posts exactly this:
          several first-ever builds of the same new app_name at once. The 500 was
          documented as retryable and the retry would have worked, which is why it
          could sit here unnoticed.

          curl's own --parallel puts both requests in flight at once; PowerShell 5.1
          has no lightweight way to do that.
        #>
        $raceName = "$appName-race"
        $out = & curl.exe -s --parallel --parallel-immediate `
            -w "%{http_code} " -o NUL -X POST -H $auth `
            "-F" "sbom=@$sbomPath" "-F" "app_name=$raceName" "-F" "build_number=race-a" $scansUrl `
            --next -s -w "%{http_code}" -o NUL -X POST -H $auth `
            "-F" "sbom=@$sbomPath" "-F" "app_name=$raceName" "-F" "build_number=race-b" $scansUrl
        $codes = ($out -join " ").Trim()
        if ($codes -notmatch "^201\s*201$") {
            Write-Host "        expected '201 201', got '$codes'" -ForegroundColor DarkYellow
            return $false
        }

        # And exactly one application, holding both builds — the point of the race
        # handling, not merely the absence of a 500.
        $list = Invoke-Api @("$BaseUrl/api/v1/applications?search=$raceName&pageSize=50&status=active&status=inactive&status=pending_confirmation", "-b", $script:platJar)
        if ($list.Status -ne 200) { return $false }
        $matched = @($list.Json.items | Where-Object { $_.name -eq $raceName })
        if ($matched.Count -ne 1) {
            Write-Host "        expected 1 application named $raceName, got $($matched.Count)" -ForegroundColor DarkYellow
            return $false
        }
        $scans = Invoke-Api @("$BaseUrl/api/v1/applications/$($matched[0].id)/scans?pageSize=50", "-b", $script:platJar)
        return $scans.Status -eq 200 -and $scans.Json.total -eq 2
    }

    Assert-That "matches app_name case-insensitively" {
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$sbomPath", "-F", "app_name=$($appName.ToUpper())", "-F", "build_number=44")
        # Must land on the same application, not create a second one differing
        # only by case.
        Show-Body $r 201
        $r.Status -eq 201 -and
        $r.Json.applicationCreated -eq $false -and
        $r.Json.applicationId -eq $script:ingest.applicationId
    }

    Assert-That "accepts an SBOM with zero components (a scratch image)" {
        $emptyPath = New-JsonFile -Name "empty.cdx.json" -Data @{
            bomFormat = "CycloneDX"; specVersion = "1.5"; components = @()
        }
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$emptyPath", "-F", "app_name=$appName", "-F", "build_number=45")
        Show-Body $r 201
        $r.Status -eq 201 -and $r.Json.componentCount -eq 0
    }

    Assert-That "accepts an SBOM with a UTF-8 BOM" {
        # Anything that post-processes an SBOM on Windows can add one; RFC 8259
        # permits a parser to ignore it.
        $bomPath = New-JsonFile -Name "bom.cdx.json" -Data $sbom -WithBom
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$bomPath", "-F", "app_name=$appName", "-F", "build_number=46")
        Show-Body $r 201
        $r.Status -eq 201 -and $r.Json.componentCount -eq 7
    }

    Assert-That "rejects a non-CycloneDX document (422)" {
        $badPath = New-JsonFile -Name "not-sbom.json" -Data @{ hello = "world" }
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$badPath", "-F", "app_name=$appName")
        $r.Status -eq 422 -and $r.Json.error.code -eq "unprocessable_entity"
    }

    Assert-That "rejects an SPDX SBOM with a clear message (422)" {
        $spdxPath = New-JsonFile -Name "spdx.json" -Data @{ bomFormat = "SPDX"; specVersion = "2.3" }
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$spdxPath", "-F", "app_name=$appName")
        $r.Status -eq 422 -and $r.Json.error.message -match "CycloneDX"
    }

    Assert-That "rejects a request with no sbom file part (400)" {
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth, "-F", "app_name=$appName")
        $r.Status -eq 400
    }

    Assert-That "rejects a missing app_name (400)" {
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth, "-F", "sbom=@$sbomPath")
        $r.Status -eq 400 -and $r.Json.error.code -eq "validation_failed"
    }

    Assert-That "stored the raw SBOM blob on disk, gzipped" {
        # Content-addressed under packages/api/var/sboms, because npm runs
        # workspace scripts with the cwd set to the package.
        $blobRoot = Join-Path $repoRoot "packages\api\var\sboms\sbom"
        if (-not (Test-Path $blobRoot)) { return $false }
        $blobs = Get-ChildItem $blobRoot -Recurse -Filter "*.json.gz" -ErrorAction SilentlyContinue
        # @() forced: in PowerShell 5.1 a pipeline yielding exactly one object
        # has no usable .Count, so a single-blob store would read as zero.
        if (@($blobs).Count -lt 1) { return $false }
        # Verify gzip magic bytes rather than trusting the extension.
        $bytes = [System.IO.File]::ReadAllBytes($blobs[0].FullName)
        return $bytes[0] -eq 0x1f -and $bytes[1] -eq 0x8b
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Auth" -ForegroundColor Cyan

    $loginUrl = "$BaseUrl/api/v1/auth/login"
    $meUrl = "$BaseUrl/api/v1/auth/me"
    $jsonCt = "Content-Type: application/json"

    Assert-That "GET /api/v1/auth/me without a session returns 401" {
        $r = Invoke-Api @($meUrl)
        $r.Status -eq 401
    }

    Assert-That "rejects a wrong password with a generic 401" {
        $p = New-JsonFile -Name "bad-login.json" -Data @{ email = $adminEmail; password = "definitely-wrong-password" }
        $r = Invoke-Api @("-X", "POST", $loginUrl, "-H", $jsonCt, "--data-binary", "@$p")
        # Must not distinguish "no such user" from "wrong password".
        $r.Status -eq 401 -and $r.Json.error.message -notmatch "(?i)(no such|not found|unknown user)"
    }

    Assert-That "rejects an unknown email with the same 401" {
        $p = New-JsonFile -Name "unknown-login.json" -Data @{ email = "nobody@sbom.local"; password = "some-password-here" }
        $r = Invoke-Api @("-X", "POST", $loginUrl, "-H", $jsonCt, "--data-binary", "@$p")
        $r.Status -eq 401
    }

    Assert-That "logs in the bootstrap admin and sets a session cookie" {
        $p = New-JsonFile -Name "login.json" -Data @{ email = $adminEmail; password = $adminPassword }
        $r = Invoke-Api @("-X", "POST", $loginUrl, "-H", $jsonCt, "--data-binary", "@$p", "-c", $cookieJar)
        Show-Body $r 200
        $r.Status -eq 200 -and $r.Json.user.role -eq "admin" -and $r.Json.user.email -eq $adminEmail
    }

    Assert-That "issued an HttpOnly session cookie" {
        if (-not (Test-Path $cookieJar)) { return $false }
        $jar = Get-Content $cookieJar -Raw
        # curl's cookie jar marks HttpOnly entries with a #HttpOnly_ line prefix.
        return ($jar -match "sbom_session") -and ($jar -match "#HttpOnly_")
    }

    Assert-That "GET /api/v1/auth/me works with the session cookie" {
        $r = Invoke-Api @($meUrl, "-b", $cookieJar)
        Show-Body $r 200
        $r.Status -eq 200 -and $r.Json.user.email -eq $adminEmail -and $r.Json.user.mustChangePassword -eq $false
    }

    Assert-That "there is no self-service password recovery to attack (404)" {
        # These endpoints were removed with the mailer: user emails are login
        # identifiers, not mailboxes, so a reset link had nowhere to go. Asserting
        # they are gone stops them reappearing as dead, unreachable code.
        foreach ($p in @("/api/v1/auth/forgot-password", "/api/v1/auth/reset-password", "/api/v1/auth/set-password")) {
            $r = Invoke-Api @("-X", "POST", "$BaseUrl$p", "-H", $jsonCt, "-d", "{}")
            if ($r.Status -ne 404) {
                Write-Host "        $p returned $($r.Status), expected 404" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "rejects a change-password attempt with the wrong current password" {
        $p = New-JsonFile -Name "wrong-current.json" -Data @{
            currentPassword = "not-the-real-password"; newPassword = "a-perfectly-fine-new-password"
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/auth/change-password",
            "-H", $jsonCt, "--data-binary", "@$p", "-b", $cookieJar)
        $r.Status -eq 401
    }

    Assert-That "rejects a too-short new password (400)" {
        $p = New-JsonFile -Name "weak.json" -Data @{ currentPassword = $adminPassword; newPassword = "short" }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/auth/change-password",
            "-H", $jsonCt, "--data-binary", "@$p", "-b", $cookieJar)
        $r.Status -eq 400 -and $r.Json.error.code -eq "validation_failed"
    }

    Assert-That "logout clears the session" {
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/auth/logout", "-b", $cookieJar, "-c", $cookieJar)
        if ($r.Status -ne 204) { Show-Body $r 204; return $false }
        $after = Invoke-Api @($meUrl, "-b", $cookieJar)
        $after.Status -eq 401
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Read APIs" -ForegroundColor Cyan

    # Re-establish a session; the logout test above deliberately dropped it.
    $readJar = Join-Path $workDir "read-cookies.txt"
    $lp = New-JsonFile -Name "read-login.json" -Data @{ email = $adminEmail; password = $adminPassword }
    $r = Invoke-Api @("-X", "POST", $loginUrl, "-H", $jsonCt, "--data-binary", "@$lp", "-c", $readJar)
    if ($r.Status -ne 200) { throw "could not sign in for the read-API checks" }

    $script:appId = $null
    $script:scanId = $null

    Assert-That "every read endpoint requires a session (401 without one)" {
        $paths = @(
            "/api/v1/applications", "/api/v1/components/search?name=x",
            "/api/v1/components/ecosystems", "/api/v1/attribute-definitions",
            "/api/v1/scans/recent"
        )
        foreach ($p in $paths) {
            if ((Invoke-Api @("$BaseUrl$p")).Status -ne 401) {
                Write-Host "        $p did not return 401" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "lists applications with a total and pagination envelope" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications", "-b", $readJar)
        Show-Body $r 200
        $script:appId = $r.Json.items[0].id
        $r.Status -eq 200 -and $r.Json.total -ge 1 -and $null -ne $r.Json.totalPages
    }

    Assert-That "defaults to hiding inactive but showing unconfirmed applications" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?pageSize=200", "-b", $readJar)
        $statuses = $r.Json.items | ForEach-Object { $_.status } | Sort-Object -Unique
        # The default view must never include 'inactive'.
        return ($statuses -notcontains "inactive")
    }

    Assert-That "filters by status" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?status=inactive&pageSize=200", "-b", $readJar)
        if ($r.Status -ne 200) { return $false }
        if ($r.Json.total -eq 0) { return $true }   # no inactive apps seeded is fine
        $bad = $r.Json.items | Where-Object { $_.status -ne "inactive" }
        return $null -eq $bad
    }

    Assert-That "sorts by last scan, newest first, without error" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?sortBy=lastScanAt&sortDir=desc", "-b", $readJar)
        $r.Status -eq 200
    }

    Assert-That "rejects an unknown sort field (400)" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?sortBy=DROP", "-b", $readJar)
        $r.Status -eq 400 -and $r.Json.error.code -eq "validation_failed"
    }

    Assert-That "returns application detail with aliases" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:appId)", "-b", $readJar)
        Show-Body $r 200
        $r.Status -eq 200 -and $null -ne $r.Json.aliases -and $null -ne $r.Json.updatedAt
    }

    Assert-That "lists the current components of an application" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:appId)/components", "-b", $readJar)
        $r.Status -eq 200 -and $r.Json.total -ge 1
    }

    Assert-That "lists scan history and flags exactly one scan as latest" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:appId)/scans?pageSize=200", "-b", $readJar)
        if ($r.Status -ne 200 -or $r.Json.total -lt 1) { return $false }
        $script:scanId = ($r.Json.items | Where-Object { -not $_.isLatest } | Select-Object -First 1).id
        if (-not $script:scanId) { $script:scanId = $r.Json.items[0].id }
        # The current-state pointer must identify one and only one scan.
        # @() forced for the same reason: with exactly one latest scan — the
        # correct answer — a bare .Count returns $null rather than 1.
        return (@($r.Json.items | Where-Object { $_.isLatest }).Count -eq 1)
    }

    Assert-That "returns a historical scan's own component list" {
        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($script:scanId)/components", "-b", $readJar)
        $r.Status -eq 200
    }

    Assert-That "returns scan detail with previous/next navigation" {
        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($script:scanId)", "-b", $readJar)
        Show-Body $r 200
        # `previousScanId`/`nextScanId` are present as keys even when null.
        $r.Status -eq 200 -and $r.Json.PSObject.Properties.Name -contains "previousScanId"
    }

    Assert-That "serves the raw SBOM as valid CycloneDX JSON" {
        $r = Invoke-Api @("$BaseUrl/api/v1/scans/$($script:scanId)/raw", "-b", $readJar)
        if ($r.Status -ne 200) { return $false }
        # Round-trips: proves the stored blob decompressed to the original document.
        $doc = $r.Body | ConvertFrom-Json
        return $doc.bomFormat -eq "CycloneDX"
    }

    Assert-That "search distinguishes current from historical usage" {
        $cur = Invoke-Api @("$BaseUrl/api/v1/components/search?name=express&scope=current", "-b", $readJar)
        $hist = Invoke-Api @("$BaseUrl/api/v1/components/search?name=express&scope=historical", "-b", $readJar)
        if ($cur.Status -ne 200 -or $hist.Status -ne 200) { return $false }
        $curBad = $cur.Json.items | Where-Object { $_.usage -ne "current" }
        $histBad = $hist.Json.items | Where-Object { $_.usage -ne "historical" }
        return ($null -eq $curBad) -and ($null -eq $histBad)
    }

    Assert-That "scope=all returns the union of both scopes" {
        $cur = Invoke-Api @("$BaseUrl/api/v1/components/search?name=express&scope=current", "-b", $readJar)
        $hist = Invoke-Api @("$BaseUrl/api/v1/components/search?name=express&scope=historical", "-b", $readJar)
        $all = Invoke-Api @("$BaseUrl/api/v1/components/search?name=express&scope=all", "-b", $readJar)
        return $all.Json.total -eq ($cur.Json.total + $hist.Json.total)
    }

    Assert-That "excludes inactive applications from search unless asked" {
        $off = Invoke-Api @("$BaseUrl/api/v1/components/search?name=libc6&scope=all", "-b", $readJar)
        $on = Invoke-Api @("$BaseUrl/api/v1/components/search?name=libc6&scope=all&includeInactive=true", "-b", $readJar)
        if ($off.Status -ne 200 -or $on.Status -ne 200) { return $false }
        $leaked = $off.Json.items | Where-Object { $_.applicationStatus -eq "inactive" }
        return ($null -eq $leaked) -and ($on.Json.total -ge $off.Json.total)
    }

    Assert-That "exact match does not return substring matches" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/search?name=express&match=exact&scope=all", "-b", $readJar)
        if ($r.Status -ne 200) { return $false }
        $bad = $r.Json.items | Where-Object { $_.componentName -ne "express" }
        return $null -eq $bad
    }

    Assert-That "requires a search name (400)" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/search", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "suggests package names for a partial query" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/suggest?q=exp", "-b", $readJar)
        $r.Status -eq 200 -and $null -ne $r.Json.suggestions
    }

    Assert-That "rejects a one-character suggest query (400)" {
        $r = Invoke-Api @("$BaseUrl/api/v1/components/suggest?q=e", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "returns the seeded attribute definitions" {
        $r = Invoke-Api @("$BaseUrl/api/v1/attribute-definitions", "-b", $readJar)
        $keys = $r.Json.definitions | ForEach-Object { $_.key }
        return $r.Status -eq 200 -and ($keys -contains "squad") -and ($keys -contains "severity")
    }

    Assert-That "rejects a malformed attribute key (400)" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/attribute-values/Not-A-Key", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "returns 404 for a non-existent application and scan" {
        $nil = "00000000-0000-0000-0000-000000000000"
        $a = Invoke-Api @("$BaseUrl/api/v1/applications/$nil", "-b", $readJar)
        $s = Invoke-Api @("$BaseUrl/api/v1/scans/$nil", "-b", $readJar)
        return $a.Status -eq 404 -and $s.Status -eq 404
    }

    Assert-That "returns 400 for a malformed uuid, not a 500" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/not-a-uuid", "-b", $readJar)
        $r.Status -eq 400
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Diff and history" -ForegroundColor Cyan

    Assert-That "diffs the latest build against the previous one by default" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/diff", "-b", $readJar)
        Show-Body $r 200
        # The smoke app's last ingest was the BOM document (4 components) and the
        # one before it was the empty scratch image, so the newest build must
        # report those 4 as added.
        $r.Status -eq 200 -and $r.Json.added.Count -eq 7 -and $r.Json.removed.Count -eq 0
    }

    Assert-That "the diff names both sides of the comparison" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/diff", "-b", $readJar)
        $null -ne $r.Json.fromScan.id -and $null -ne $r.Json.toScan.id -and
        $r.Json.fromScan.id -ne $r.Json.toScan.id
    }

    Assert-That "counts unchanged packages even when two builds are identical" {
        # Regression guard. The unchanged count used to be a scalar carried on the
        # first *changed* row, so two identical builds returned no rows and the
        # count silently read as zero — telling the reader that two builds sharing
        # every package had nothing in common.
        $scans = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/scans?pageSize=200", "-b", $readJar)
        # Builds 42 and 43 posted the identical document, so their diff is empty.
        $b42 = ($scans.Json.items | Where-Object { $_.buildNumber -eq "42" }).id
        $b43 = ($scans.Json.items | Where-Object { $_.buildNumber -eq "43" }).id
        if (-not $b42 -or -not $b43) { return $false }

        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/diff?fromScanId=$b42&toScanId=$b43", "-b", $readJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        if ($r.Json.added.Count -ne 0 -or $r.Json.removed.Count -ne 0 -or $r.Json.changed.Count -ne 0) {
            Write-Host "        expected an empty diff between identical builds" -ForegroundColor DarkYellow
            return $false
        }
        if ($r.Json.unchangedCount -ne 7) {
            Write-Host "        unchangedCount=$($r.Json.unchangedCount), expected 7" -ForegroundColor DarkYellow
            return $false
        }
        return $true
    }

    Assert-That "refuses to diff a scan against itself (400)" {
        $s = $script:ingest.scanId
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/diff?fromScanId=$s&toScanId=$s", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "refuses to diff scans from two different applications (400)" {
        # Comparing builds of unrelated applications is not a diff, it is a
        # coincidence, and the result would be meaningless rather than empty.
        $other = Invoke-Api @("$BaseUrl/api/v1/applications?pageSize=200", "-b", $readJar)
        $otherApp = $other.Json.items | Where-Object { $_.id -ne $script:ingest.applicationId -and $_.latestScanId } | Select-Object -First 1
        if (-not $otherApp) { return $true }   # nothing to cross with; not a failure
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/diff?toScanId=$($otherApp.latestScanId)", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "lists packages that left the current build, with the build they were last in" {
        # The smoke app's newest scan has 4 components and an earlier one had the
        # same 4, so nothing should be missing. The contract still has to hold.
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/removed-components", "-b", $readJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        foreach ($item in $r.Json.items) {
            if (-not $item.lastSeenScanId -or -not $item.lastSeenAt) { return $false }
        }
        return $null -ne $r.Json.total
    }

    Assert-That "removed-components honours the ignoreVersion toggle" {
        $withVersions = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/removed-components", "-b", $readJar)
        $ignoring = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)/removed-components?ignoreVersion=true", "-b", $readJar)
        # Ignoring versions can only ever narrow the result: a package whose
        # newer version is still present stops counting as removed.
        $withVersions.Status -eq 200 -and $ignoring.Status -eq 200 -and
        $ignoring.Json.total -le $withVersions.Json.total
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Dashboard" -ForegroundColor Cyan

    Assert-That "returns coherent estate statistics" {
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/stats", "-b", $readJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        $a = $r.Json.applications
        # The per-status counts must add up to the total, or one of the four
        # queries is filtering differently from the others.
        return ($a.active + $a.inactive + $a.pendingConfirmation) -eq $a.total -and
               $r.Json.scans.total -ge 1 -and
               $r.Json.components.inCurrentUse -le $r.Json.components.distinct
    }

    Assert-That "reports the ecosystem breakdown of what is deployed now" {
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/ecosystems", "-b", $readJar)
        $r.Status -eq 200 -and $null -ne $r.Json.ecosystems
    }

    Assert-That "ranks the most widely deployed packages" {
        $r = Invoke-Api @("$BaseUrl/api/v1/dashboard/top-components?limit=5", "-b", $readJar)
        if ($r.Status -ne 200) { return $false }
        if (@($r.Json.components).Count -eq 0) { return $true }
        # Must come back sorted, or the "top" in the name is a lie.
        $counts = @($r.Json.components | ForEach-Object { $_.applications })
        for ($i = 1; $i -lt $counts.Count; $i++) {
            if ($counts[$i] -gt $counts[$i - 1]) { return $false }
        }
        return @($r.Json.components).Count -le 5
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Admin API" -ForegroundColor Cyan

    $adminUrl = "$BaseUrl/api/v1/admin"
    $script:createdAppId = $null
    $script:createdUserId = $null
    $script:createdAttrId = $null
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 6)

    Assert-That "creates an attribute definition" {
        $p = New-JsonFile -Name "attr.json" -Data @{
            key = "smoke_tier_$suffix"; label = "Smoke tier"; type = "select"
            options = @("gold", "silver"); sortOrder = 900; isActive = $true
        }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/attribute-definitions", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        Show-Body $r 201
        $script:createdAttrId = $r.Json.definition.id
        $r.Status -eq 201 -and $r.Json.definition.key -eq "smoke_tier_$suffix"
    }

    Assert-That "rejects a select attribute with no options (400)" {
        $p = New-JsonFile -Name "attr-bad.json" -Data @{
            key = "smoke_bad_$suffix"; label = "Bad"; type = "select"; options = @(); sortOrder = 0; isActive = $true
        }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/attribute-definitions", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        $r.Status -ge 400 -and $r.Status -lt 500
    }

    Assert-That "registers an application with attributes" {
        $p = New-JsonFile -Name "newapp.json" -Data @{
            name = "smoke-admin-app-$suffix"; status = "active"
            attributes = @{ squad = "platform"; "smoke_tier_$suffix" = "gold" }
        }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/applications", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        Show-Body $r 201
        $script:createdAppId = $r.Json.application.id
        $r.Status -eq 201 -and $r.Json.application.attributes.squad -eq "platform"
    }

    Assert-That "rejects a duplicate application name (409)" {
        $p = New-JsonFile -Name "dupapp.json" -Data @{ name = "SMOKE-ADMIN-APP-$suffix"; status = "active"; attributes = @{} }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/applications", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        # Uppercase: names are unique case-insensitively, matching how ingest
        # resolves app_name.
        $r.Status -eq 409
    }

    Assert-That "rejects an attribute value outside its select options" {
        $p = New-JsonFile -Name "badattr.json" -Data @{ attributes = @{ "smoke_tier_$suffix" = "platinum" } }
        $r = Invoke-Api @("-X", "PATCH", "$adminUrl/applications/$($script:createdAppId)", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        $r.Status -eq 400 -and $r.Json.error.code -eq "validation_failed"
    }

    Assert-That "rejects an attribute key that is not defined" {
        $p = New-JsonFile -Name "unknownattr.json" -Data @{ attributes = @{ definitely_not_defined = "x" } }
        $r = Invoke-Api @("-X", "PATCH", "$adminUrl/applications/$($script:createdAppId)", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "clears an attribute when it is set to null" {
        $p = New-JsonFile -Name "clearattr.json" -Data @{ attributes = @{ squad = $null } }
        $r = Invoke-Api @("-X", "PATCH", "$adminUrl/applications/$($script:createdAppId)", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        Show-Body $r 200
        # The key must be gone, not present-and-null: `attributes ? 'squad'`
        # drives the filter dropdown.
        $r.Status -eq 200 -and ($r.Json.application.attributes.PSObject.Properties.Name -notcontains "squad")
    }

    Assert-That "refuses to delete an attribute still in use (409 naming the count)" {
        $r = Invoke-Api @("-X", "DELETE", "$adminUrl/attribute-definitions/$($script:createdAttrId)", "-b", $readJar)
        $r.Status -eq 409 -and $r.Json.error.details.applicationsAffected -ge 1
    }

    Assert-That "deletes an in-use attribute when purge is requested" {
        $r = Invoke-Api @("-X", "DELETE", "$adminUrl/attribute-definitions/$($script:createdAttrId)?purge=true", "-b", $readJar)
        Show-Body $r 200
        $script:createdAttrId = $null
        $r.Status -eq 200 -and $r.Json.valuesPurged -ge 1
    }

    Assert-That "creates an account and returns a password exactly once" {
        $p = New-JsonFile -Name "newuser.json" -Data @{ email = "smoke-user-$suffix@sbom.local"; role = "user"; mustChangePassword = $true }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/users", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        Show-Body $r 201
        $script:createdUserId = $r.Json.user.id
        $script:createdUserPassword = $r.Json.temporaryPassword
        $r.Status -eq 201 -and $r.Json.temporaryPassword.Length -ge 12 -and $r.Json.user.mustChangePassword -eq $true
    }

    Assert-That "never returns the password again on subsequent reads" {
        $r = Invoke-Api @("$adminUrl/users/$($script:createdUserId)", "-b", $readJar)
        $r.Status -eq 200 -and
        ($r.Json.user.PSObject.Properties.Name -notcontains "temporaryPassword") -and
        ($r.Body -notmatch [regex]::Escape($script:createdUserPassword))
    }

    Assert-That "rejects a duplicate account identifier (409)" {
        $p = New-JsonFile -Name "dupuser.json" -Data @{ email = "SMOKE-USER-$suffix@sbom.local"; role = "user" }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/users", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        $r.Status -eq 409
    }

    Assert-That "refuses to let an admin demote their own account" {
        $me = Invoke-Api @($meUrl, "-b", $readJar)
        $p = New-JsonFile -Name "selfdemote.json" -Data @{ role = "user" }
        $r = Invoke-Api @("-X", "PATCH", "$adminUrl/users/$($me.Json.user.id)", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "refuses to deactivate the last active administrator" {
        # With no self-service recovery, an estate with zero admins cannot be
        # fixed from the UI at all.
        $users = Invoke-Api @("$adminUrl/users?role=admin&pageSize=200", "-b", $readJar)
        $activeAdmins = @($users.Json.items | Where-Object { $_.isActive })
        if ($activeAdmins.Count -ne 1) { return $true }   # more than one admin: guard not exercised
        $p = New-JsonFile -Name "deactivate.json" -Data @{ isActive = $false }
        $r = Invoke-Api @("-X", "PATCH", "$adminUrl/users/$($activeAdmins[0].id)", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        $r.Status -eq 400
    }

    # --- the forced-password-change gate, driven as the new user --------------
    $userJar = Join-Path $workDir "user-cookies.txt"

    Assert-That "a temp-password account can sign in" {
        $p = New-JsonFile -Name "userlogin.json" -Data @{ email = "smoke-user-$suffix@sbom.local"; password = $script:createdUserPassword }
        $r = Invoke-Api @("-X", "POST", $loginUrl, "-H", $jsonCt, "--data-binary", "@$p", "-c", $userJar)
        Show-Body $r 200
        $r.Status -eq 200 -and $r.Json.user.mustChangePassword -eq $true
    }

    Assert-That "but is refused every data route until the password is changed" {
        # Enforced server-side, not only by the SPA redirect: the credential has
        # been seen by whoever issued it.
        foreach ($p in @("/api/v1/applications", "/api/v1/components/search?name=x", "/api/v1/dashboard/stats")) {
            $r = Invoke-Api @("$BaseUrl$p", "-b", $userJar)
            if ($r.Status -ne 403 -or $r.Json.error.code -ne "password_change_required") {
                Write-Host "        $p returned $($r.Status)/$($r.Json.error.code)" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "can still read its own identity, or it could never diagnose the block" {
        $r = Invoke-Api @($meUrl, "-b", $userJar)
        $r.Status -eq 200 -and $r.Json.user.mustChangePassword -eq $true
    }

    Assert-That "refuses a 'new' password identical to the issued one" {
        $p = New-JsonFile -Name "samepw.json" -Data @{
            currentPassword = $script:createdUserPassword; newPassword = $script:createdUserPassword
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/auth/change-password", "-H", $jsonCt, "--data-binary", "@$p", "-b", $userJar)
        # Otherwise the flag clears while the credential someone else has seen
        # stays live, defeating the entire mechanism.
        $r.Status -eq 403
    }

    $newUserPassword = "smoke-chosen-password-$suffix"
    Assert-That "changing the password clears the flag and unlocks the API" {
        $p = New-JsonFile -Name "changepw.json" -Data @{
            currentPassword = $script:createdUserPassword; newPassword = $newUserPassword
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/auth/change-password", "-H", $jsonCt, "--data-binary", "@$p", "-b", $userJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        $after = Invoke-Api @("$BaseUrl/api/v1/applications", "-b", $userJar)
        return $after.Status -eq 200
    }

    Assert-That "a non-admin is refused every admin route (403)" {
        foreach ($p in @("/api/v1/admin/users", "/api/v1/admin/audit-log", "/api/v1/admin/ingest-tokens")) {
            $r = Invoke-Api @("$BaseUrl$p", "-b", $userJar)
            if ($r.Status -ne 403) {
                Write-Host "        $p returned $($r.Status), expected 403" -ForegroundColor DarkYellow
                return $false
            }
        }
        # Body from a file, not an inline -d. PowerShell 5.1 strips the embedded
        # double quotes when handing an argument to a native exe, so curl would
        # receive `{name:nope}`; Fastify's JSON parser runs before preHandler
        # hooks, so that returns 400 from the parser and never reaches the admin
        # guard being tested.
        $p = New-JsonFile -Name "nonadmin-write.json" -Data @{ name = "should-not-be-created" }
        $w = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/admin/applications", "-H", $jsonCt, "--data-binary", "@$p", "-b", $userJar)
        return $w.Status -eq 403
    }

    Assert-That "an admin password reset signs the user out immediately" {
        $r = Invoke-Api @("-X", "POST", "$adminUrl/users/$($script:createdUserId)/reset-password", "-H", $jsonCt, "-d", "{}", "-b", $readJar)
        if ($r.Status -ne 200) { Show-Body $r 200; return $false }
        # Their live session must die with the old password, not linger until
        # the cookie happens to expire.
        $after = Invoke-Api @($meUrl, "-b", $userJar)
        return $after.Status -eq 401 -and $r.Json.temporaryPassword -ne $newUserPassword
    }

    # --- pending resolution ---------------------------------------------------
    Assert-That "merges an unconfirmed application into an existing one, moving its scans" {
        $before = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:createdAppId)", "-b", $readJar)
        $p = New-JsonFile -Name "merge.json" -Data @{ targetApplicationId = $script:createdAppId; always = $true }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/applications/$($script:ingest.applicationId)/merge",
            "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        Show-Body $r 200
        if ($r.Status -ne 200) { return $false }
        $after = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:createdAppId)", "-b", $readJar)
        # Every scan moved, and the destination's counter reflects it.
        return $r.Json.scansMoved -ge 1 -and
               $after.Json.scanCount -eq ($before.Json.scanCount + $r.Json.scansMoved)
    }

    Assert-That "the merged-away application is gone" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:ingest.applicationId)", "-b", $readJar)
        $r.Status -eq 404
    }

    Assert-That "merge-always recorded a permanent alias" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:createdAppId)", "-b", $readJar)
        $r.Json.aliases -contains $appName
    }

    Assert-That "a future scan under the old CI name follows the alias" {
        # This is the whole point of merge-always: the pipeline keeps posting the
        # old name and the platform stops creating a new pending record each build.
        $r = Invoke-Api @("-X", "POST", $scansUrl, "-H", $auth,
            "-F", "sbom=@$sbomPath", "-F", "app_name=$appName", "-F", "build_number=99")
        Show-Body $r 201
        $r.Status -eq 201 -and
        $r.Json.applicationId -eq $script:createdAppId -and
        $r.Json.redirectedFrom -eq $appName -and
        $r.Json.applicationCreated -eq $false
    }

    Assert-That "the merge target now has the moved scans in its history" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications/$($script:createdAppId)/scans?pageSize=200", "-b", $readJar)
        # And still exactly one current scan after all that movement.
        $r.Status -eq 200 -and (@($r.Json.items | Where-Object { $_.isLatest }).Count -eq 1)
    }

    # --- ingest tokens --------------------------------------------------------
    Assert-That "lists environment-configured tokens alongside database ones" {
        # Listing only DB rows would report "no tokens" on a deployment where CI
        # authenticates perfectly well through INGEST_TOKENS.
        $r = Invoke-Api @("$adminUrl/ingest-tokens", "-b", $readJar)
        Show-Body $r 200
        $r.Status -eq 200 -and @($r.Json.tokens | Where-Object { $_.source -eq "env" }).Count -ge 1
    }

    Assert-That "mints a working token and returns its plaintext once" {
        $p = New-JsonFile -Name "token.json" -Data @{ name = "smoke-ci-$suffix" }
        $r = Invoke-Api @("-X", "POST", "$adminUrl/ingest-tokens", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        Show-Body $r 201
        if ($r.Status -ne 201) { return $false }
        $script:newTokenId = $r.Json.token.id
        # Prove it actually authenticates, rather than only that a row was written.
        $ingested = Invoke-Api @("-X", "POST", $scansUrl, "-H", "Authorization: Bearer $($r.Json.plaintext)",
            "-F", "sbom=@$sbomPath", "-F", "app_name=smoke-admin-app-$suffix", "-F", "build_number=100")
        return $ingested.Status -eq 201
    }

    Assert-That "a revoked token stops working" {
        $p = New-JsonFile -Name "token2.json" -Data @{ name = "smoke-revoke-$suffix" }
        $created = Invoke-Api @("-X", "POST", "$adminUrl/ingest-tokens", "-H", $jsonCt, "--data-binary", "@$p", "-b", $readJar)
        if ($created.Status -ne 201) { return $false }
        $plaintext = $created.Json.plaintext
        $revoked = Invoke-Api @("-X", "DELETE", "$adminUrl/ingest-tokens/$($created.Json.token.id)", "-b", $readJar)
        if ($revoked.Status -ne 204) { return $false }
        $after = Invoke-Api @("-X", "POST", $scansUrl, "-H", "Authorization: Bearer $plaintext",
            "-F", "sbom=@$sbomPath", "-F", "app_name=smoke-admin-app-$suffix")
        return $after.Status -eq 401
    }

    # --- audit trail ----------------------------------------------------------
    Assert-That "recorded every administrative action on the audit trail" {
        $r = Invoke-Api @("$adminUrl/audit-log?pageSize=100", "-b", $readJar)
        if ($r.Status -ne 200) { return $false }
        $actions = @($r.Json.items | ForEach-Object { $_.action })
        foreach ($expected in @("application.create", "application.merge_always", "user.create",
                                "user.reset_password", "attribute_definition.create", "ingest_token.create")) {
            if ($actions -notcontains $expected) {
                Write-Host "        missing audit entry: $expected" -ForegroundColor DarkYellow
                return $false
            }
        }
        return $true
    }

    Assert-That "the merge audit entry explains where the scans went" {
        $r = Invoke-Api @("$adminUrl/audit-log?action=application.merge_always&pageSize=5", "-b", $readJar)
        $entry = $r.Json.items[0]
        # Without this, "why does this app have someone else's history" is
        # unanswerable once the source record is deleted.
        $null -ne $entry.metadata.sourceName -and $entry.metadata.scansMoved -ge 1 -and
        $entry.actorEmail -eq $adminEmail
    }

    Assert-That "attributes every audit entry to a named actor" {
        $r = Invoke-Api @("$adminUrl/audit-log?pageSize=50", "-b", $readJar)
        $orphans = $r.Json.items | Where-Object { -not $_.actorEmail }
        $null -eq $orphans
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Table sorting" -ForegroundColor Cyan

    <#
      The property worth testing here is not "does sorting work" — a wrong order is
      visible. It is that offset pagination over a sorted list neither duplicates nor
      loses rows.

      Sorting on a column with duplicate values leaves the order of tied rows to the
      query plan, so the same row can land on page 1 and page 2 while another appears on
      neither. It needs ties *and* a page boundary inside them to reproduce, it looks like
      a data bug rather than a sorting one, and it is exactly what the unique tiebreaker in
      lib/sorting.ts exists to prevent. Tiny page sizes below put a boundary inside almost
      every tie group.
    #>
    function Test-PagedSort {
        param([string]$Url, [string]$SortBy, [string]$Dir, [int]$PageSize, [string]$IdPath)

        $first = Invoke-Api @("$Url&sortBy=$SortBy&sortDir=$Dir&page=1&pageSize=$PageSize", "-b", $readJar)
        if ($first.Status -ne 200) { throw "page 1 returned $($first.Status): $($first.Body)" }

        $total = [int]$first.Json.total
        $pages = [int]$first.Json.totalPages
        $ids = New-Object System.Collections.Generic.List[string]

        for ($p = 1; $p -le $pages; $p++) {
            $r = Invoke-Api @("$Url&sortBy=$SortBy&sortDir=$Dir&page=$p&pageSize=$PageSize", "-b", $readJar)
            if ($r.Status -ne 200) { throw "page $p returned $($r.Status)" }
            foreach ($item in $r.Json.items) {
                # Composite for tables whose row identity is a pair, e.g. (advisory, package).
                $key = ($IdPath -split ',' | ForEach-Object { $item.$_ }) -join '|'
                $ids.Add($key)
            }
        }

        $distinct = ($ids | Select-Object -Unique).Count
        if ($ids.Count -ne $total) { throw "collected $($ids.Count) rows across $pages pages but total says $total" }
        if ($distinct -ne $total) { throw "$($ids.Count - $distinct) duplicate row(s) across page boundaries" }
        return $true
    }

    Assert-That "sorts applications on every declared column, both directions" {
        $fields = @("name", "status", "platform", "componentCount", "scanCount", "lastScanAt", "createdAt")
        foreach ($f in $fields) {
            $asc = Invoke-Api @("$BaseUrl/api/v1/applications?pageSize=100&sortDir=asc&sortBy=$f", "-b", $readJar)
            $desc = Invoke-Api @("$BaseUrl/api/v1/applications?pageSize=100&sortDir=desc&sortBy=$f", "-b", $readJar)
            if ($asc.Status -ne 200 -or $desc.Status -ne 200) { throw "sortBy=$f rejected" }
            # Same rows either way: a sort must reorder, never filter. A direction that
            # dropped rows would be a WHERE clause wearing an ORDER BY's name.
            $a = ($asc.Json.items | ForEach-Object { $_.id } | Sort-Object) -join ','
            $d = ($desc.Json.items | ForEach-Object { $_.id } | Sort-Object) -join ','
            if ($a -ne $d) { throw "sortBy=$f returned a different set of rows in each direction" }
        }
        $true
    }

    Assert-That "rejects a sort column it does not declare" {
        # The whitelist is what keeps a client-supplied column out of the ORDER BY.
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?sortBy=id;DROP+TABLE+application", "-b", $readJar)
        $r.Status -eq 400
    }

    Assert-That "sorts applications by a custom attribute" {
        # The one sort whose target comes from the request. Safe because a jsonb key binds
        # as a value, not an identifier.
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?sortBy=attribute&sortAttribute=squad&sortDir=asc&pageSize=100", "-b", $readJar)
        $squads = @($r.Json.items | ForEach-Object { $_.attributes.squad } | Where-Object { $_ })
        $sorted = @($squads | Sort-Object)
        $r.Status -eq 200 -and ($squads -join ',') -eq ($sorted -join ',')
    }

    Assert-That "paginates a sorted application list without losing or repeating rows" {
        # `?x=1` is a placeholder so Test-PagedSort can append with `&`. It must not carry a
        # pageSize of its own: a repeated parameter arrives as an array and fails validation.
        Test-PagedSort "$BaseUrl/api/v1/applications?x=1" "status" "desc" 3 "id"
    }

    Assert-That "paginates the audit trail sorted on a heavily tied column" {
        # Hundreds of rows over a handful of distinct target types: many ties, many
        # boundaries. The strongest available test of tiebreaker stability.
        Test-PagedSort "$adminUrl/audit-log?x=1" "targetType" "asc" 20 "id"
    }

    if ($script:vulnReady) {
        Assert-That "paginates advisories sorted by severity without losing rows" {
            Test-PagedSort "$BaseUrl/api/v1/vulnerabilities?scope=all&currentOnly=false" "severity" "desc" 25 "vulnerabilityId"
        }

        Assert-That "paginates findings sorted by severity without losing rows" {
            # Findings tie hardest: a base image contributes thousands sharing one severity,
            # and most carry no CVSS, so the secondary key ties too.
            $url = "$BaseUrl/api/v1/applications/$($script:appId)/vulnerabilities?scope=all&includeSuppressed=true"
            Test-PagedSort $url "severity" "desc" 3 "vulnerabilityId,componentId"
        }
    }
    else {
        Write-Host "        skipped 2 sorted-pagination checks: vulnerability scanning is off" -ForegroundColor DarkGray
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Exact vs substring name matching" -ForegroundColor Cyan

    Assert-That "exact match returns only the package named, substring returns more" {
        <#
          The reported confusion: searching "react" returned reactive-element and reactor
          but not react. Both modes existed; only the substring one was discoverable.
          Asserted as a relationship rather than against fixed names, so it holds on any
          estate: the exact result must be a subset of the substring result.
        #>
        $term = "log4j"
        $contains = Invoke-Api @("$BaseUrl/api/v1/components/search?name=$term&match=contains&scope=all&pageSize=200", "-b", $readJar)
        $exact = Invoke-Api @("$BaseUrl/api/v1/components/search?name=$term&match=exact&scope=all&pageSize=200", "-b", $readJar)
        if ($contains.Status -ne 200 -or $exact.Status -ne 200) { throw "search rejected" }

        $containsNames = @($contains.Json.items | ForEach-Object { $_.componentName } | Select-Object -Unique)
        $exactNames = @($exact.Json.items | ForEach-Object { $_.componentName } | Select-Object -Unique)

        # Every exact hit is named exactly the term, case aside.
        foreach ($n in $exactNames) { if ($n.ToLower() -ne $term.ToLower()) { throw "exact returned '$n'" } }
        # And every exact hit also appears under substring matching.
        foreach ($n in $exactNames) { if ($containsNames -notcontains $n) { throw "'$n' missing from contains" } }
        $containsNames.Count -ge $exactNames.Count
    }

    Assert-That "substring matching finds packages an exact search cannot" {
        # `core` matches log4j-core and spring-core while matching nothing exactly, which is
        # the whole reason the mode exists.
        $contains = Invoke-Api @("$BaseUrl/api/v1/components/search?name=core&match=contains&scope=all&pageSize=200", "-b", $readJar)
        $exact = Invoke-Api @("$BaseUrl/api/v1/components/search?name=core&match=exact&scope=all&pageSize=200", "-b", $readJar)
        $containsNames = @($contains.Json.items | ForEach-Object { $_.componentName } | Select-Object -Unique)
        $containsNames.Count -ge 1 -and [int]$exact.Json.total -eq 0
    }

    Assert-That "list search defaults to exact, so a saved list keeps its old answer" {
        # The default is deliberately the opposite of the single search's. Changing it would
        # silently change the result of every list anyone has already saved and shared.
        $body = New-JsonFile -Name "bulk-default.json" -Data @{
            input = "core`nexpress"; scope = "all"; view = "rollup"; pageSize = 100
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body", "-b", $readJar)
        if ($r.Status -ne 200) { throw "bulk search returned $($r.Status): $($r.Body)" }
        $core = $r.Json.rollup | Where-Object { $_.name -eq "core" }
        $express = $r.Json.rollup | Where-Object { $_.name -eq "express" }
        # `core` is not a package name, so exact mode must miss it.
        (-not $core.found) -and $express.found -and $express.matchedNameCount -eq 1
    }

    Assert-That "list search in substring mode reports how many packages each line matched" {
        $body = New-JsonFile -Name "bulk-contains.json" -Data @{
            input = "core`nexpress`nnothing-matches-this"; scope = "all"; view = "rollup"
            match = "contains"; pageSize = 100
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body", "-b", $readJar)
        if ($r.Status -ne 200) { throw "bulk search returned $($r.Status): $($r.Body)" }

        $core = $r.Json.rollup | Where-Object { $_.name -eq "core" }
        $miss = $r.Json.rollup | Where-Object { $_.name -eq "nothing-matches-this" }

        # The count is the answer for a multi-match line, and matchedNames must agree with it.
        $core.found -and $core.matchedNameCount -ge 2 -and
        $core.matchedNames.Count -eq $core.matchedNameCount -and
        (-not $miss.found) -and $miss.matchedNameCount -eq 0 -and
        # A miss is still reported: dropping it would turn the audit back into a search.
        $null -ne $miss
    }

    Assert-That "list search treats LIKE metacharacters as literal text" {
        <#
          `%` inside an ILIKE pattern matches everything. Unescaped, an entry of "%" would
          report the entire estate as a match while looking like an ordinary input line —
          a wrong answer that presents itself as a very successful one.
        #>
        $body = New-JsonFile -Name "bulk-wildcard.json" -Data @{
            input = "%`n_"; scope = "all"; view = "rollup"; match = "contains"; pageSize = 100
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body", "-b", $readJar)
        if ($r.Status -ne 200) { throw "bulk search returned $($r.Status)" }
        $matched = ($r.Json.rollup | Measure-Object -Property matchedNameCount -Sum).Sum
        # No package is literally named "%" or "_", so both lines must miss.
        [int]$matched -eq 0
    }

    Assert-That "the list search's matches view sorts on the same columns as the single search" {
        # Both render one table component. Divergent sort vocabularies would let the same
        # header sort differently on the two screens.
        $body = New-JsonFile -Name "bulk-sorted.json" -Data @{
            input = "express"; scope = "all"; view = "matches"; pageSize = 100
            sortBy = "applicationName"; sortDir = "desc"
        }
        $r = Invoke-Api @("-X", "POST", "$BaseUrl/api/v1/components/bulk-search",
            "-H", "Content-Type: application/json", "--data-binary", "@$body", "-b", $readJar)
        if ($r.Status -ne 200) { throw "bulk search returned $($r.Status): $($r.Body)" }
        $names = @($r.Json.matches.items | ForEach-Object { $_.applicationName })
        $expected = @($names | Sort-Object -Descending)
        ($names -join ',') -eq ($expected -join ',')
    }

    # ======================================================================
    Write-Host ""
    Write-Host "Error handling" -ForegroundColor Cyan

    Assert-That "unknown route returns the standard error envelope" {
        $r = Invoke-Api @("$BaseUrl/api/v1/nope")
        $r.Status -eq 404 -and $r.Json.error.code -eq "route_not_found"
    }

    # ======================================================================
    # Clean up after ourselves, which is now possible because the admin API
    # exists. Earlier runs of this script left a smoke-test application behind
    # on every invocation.
    Write-Host ""
    Write-Host "Cleanup" -ForegroundColor Cyan

    Assert-That "removes the account this run created" {
        if (-not $script:createdUserId) { return $true }
        $r = Invoke-Api @("-X", "DELETE", "$adminUrl/users/$($script:createdUserId)", "-b", $readJar)
        Show-Body $r 204
        return $r.Status -eq 204
    }

    Assert-That "removes every smoke-test application, including any from earlier runs" {
        # Sweeps by name prefix rather than only this run's ids. Runs of this
        # script from before the admin API existed had no way to clean up after
        # themselves, so they each left an application behind; this collects
        # them. Deleting cascades to their scans and scan_component rows.
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?search=smoke-&pageSize=200&status=active&status=inactive&status=pending_confirmation", "-b", $readJar)
        if ($r.Status -ne 200) { return $false }

        $targets = @($r.Json.items | Where-Object { $_.name -like "smoke-test-app-*" -or $_.name -like "smoke-admin-app-*" })
        $ok = $true
        foreach ($t in $targets) {
            # Invoke-Api absorbs 429 for every call site, including this one.
            $d = Invoke-Api @("-X", "DELETE", "$adminUrl/applications/$($t.id)", "-b", $readJar)
            if ($d.Status -ne 200) {
                Write-Host "        could not delete $($t.name): $($d.Status) $($d.Body)" -ForegroundColor DarkYellow
                $ok = $false
            }
        }
        if ($targets.Count -gt 0) {
            Write-Host "        removed $($targets.Count) test application(s)" -ForegroundColor DarkGray
        }
        return $ok
    }

    Assert-That "leaves no smoke-test data behind" {
        $r = Invoke-Api @("$BaseUrl/api/v1/applications?search=smoke-&pageSize=200&status=active&status=inactive&status=pending_confirmation", "-b", $readJar)
        $leftovers = @($r.Json.items | Where-Object { $_.name -like "smoke-*" })
        if ($leftovers.Count -gt 0) {
            Write-Host "        left behind: $($leftovers.name -join ', ')" -ForegroundColor DarkYellow
        }
        $users = Invoke-Api @("$adminUrl/users?search=smoke-user&pageSize=200", "-b", $readJar)
        $strayUsers = @($users.Json.items)
        if ($strayUsers.Count -gt 0) {
            Write-Host "        stray accounts: $($strayUsers.email -join ', ')" -ForegroundColor DarkYellow
        }
        return $leftovers.Count -eq 0 -and $strayUsers.Count -eq 0
    }
}
finally {
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- summary ---------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 66) -ForegroundColor DarkGray
if ($fail -eq 0) {
    Write-Host "$pass passed, 0 failed" -ForegroundColor Green
    Write-Host ""
    Write-Host "All test data was removed through the admin API." -ForegroundColor DarkGray
    Write-Host "Browse the data:  npm run db:studio" -ForegroundColor DarkGray
    exit 0
}
else {
    Write-Host "$pass passed, $fail FAILED" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
