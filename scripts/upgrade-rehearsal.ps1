<#
.SYNOPSIS
    Proves that upgrading a running installation keeps every piece of its data.

.DESCRIPTION
    Rehearses the upgrade an administrator performs on a real server, end to end, on a
    throwaway installation of its own:

      1. Starts a released bundle (0.3.11 by default) in an isolated Compose project, on its
         own port and its own volumes, and fills it with data through the real API: confirmed
         and pending applications with several builds each, users, a tribe, a squad with
         members and grants, a group, a database ingest token, a personal API token, an
         accepted risk, changed admin settings and a report run.
      2. Stops the API and takes a fingerprint: every row of every table, hashed, and every
         stored SBOM file, hashed.
      3. Backs up the database, the stored SBOMs and .env, and checks the backup is readable.
      4. Upgrades to the images built from this checkout, the way the bundle's start script
         does: same project name, same volumes, same .env, newer compose file and images.
      5. Checks that the migrations ran, that no row and no file was lost or changed, and that
         the installation still works: the admin and a user sign in, the personal API token
         and both ingest tokens still work, the accepted risk and the settings are intact, the
         report PDF and an old raw SBOM download. Then runs the smoke test.
      6. Rehearses going back: restores the backup into the old version and checks the
         fingerprint once more.

    Never touches the `sbom-platform` project (the real local installation) or its volumes.
    Each run uses a new project name, so a run that stops half-way cannot interfere with the
    next one. The run's volumes are left in place at the end and listed, so they can be
    inspected; delete them from Docker Desktop when done.

    Everything the run writes (secrets for the throwaway installation, backups, fingerprints,
    logs, the report) goes under var\rehearsal\<run>, which git ignores.

.EXAMPLE
    .\scripts\upgrade-rehearsal.ps1
    .\scripts\upgrade-rehearsal.ps1 -SkipBuild            # reuse images built by an earlier run
    .\scripts\upgrade-rehearsal.ps1 -FromBundle dist-offline\sbom-platform-offline-0.3.10
#>
[CmdletBinding()]
param(
    # The released bundle to upgrade from. Its images.tar is loaded if the images are missing.
    [string]$FromBundle = "dist-offline\sbom-platform-offline-0.3.11",
    # Images to upgrade to. Built from this checkout unless -SkipBuild.
    [string]$ToApiImage = "sbom-platform/api:rehearsal",
    [string]$ToWebImage = "sbom-platform/web:rehearsal",
    [switch]$SkipBuild,
    # Host port for the throwaway installation's web container.
    [int]$Port = 18088,
    [switch]$SkipSmokeTest
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$project = "sbom-rehearsal-$runId"
$work = Join-Path $repoRoot "var\rehearsal\$runId"
$baseUrl = "http://127.0.0.1:$Port"

# --- guards -----------------------------------------------------------------
# The one mistake this script must never make is to run against the real installation.
if ($project -notmatch '^sbom-rehearsal-\d{8}-\d{6}$' -or $project -eq "sbom-platform") {
    throw "Refusing to run: project name '$project' is not a rehearsal project."
}

# --- output -----------------------------------------------------------------
$results = New-Object System.Collections.Generic.List[object]
function Write-Step { param([string]$Text) Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }
function Add-Result {
    param([string]$Check, [bool]$Ok, [string]$Detail = "")
    $results.Add([pscustomobject]@{ Check = $Check; Result = $(if ($Ok) { "PASS" } else { "FAIL" }); Detail = $Detail })
    $color = if ($Ok) { "Green" } else { "Red" }
    Write-Host ("    [{0}] {1} {2}" -f $(if ($Ok) { "PASS" } else { "FAIL" }), $Check, $Detail) -ForegroundColor $color
}

# --- docker -----------------------------------------------------------------
<#
    Runs docker and returns its output lines. Windows PowerShell 5.1 turns anything a native
    command writes to stderr into an error record, and docker writes ordinary progress there,
    so the preference is lowered for the call and success is read from the exit code alone.
#>
function Invoke-Docker {
    param([Parameter(Mandatory)][string[]]$DockerArgs, [string]$InputText, [switch]$AllowFail)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($PSBoundParameters.ContainsKey("InputText")) {
            $out = $InputText | & docker @DockerArgs 2>&1
        }
        else {
            $out = & docker @DockerArgs 2>&1
        }
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    $lines = @($out | ForEach-Object { "$_" })
    if ($code -ne 0 -and -not $AllowFail) {
        throw "docker $($DockerArgs -join ' ') failed (exit $code):`n$($lines -join "`n")"
    }
    return $lines
}

$composeFile = $null   # set per phase
function Invoke-Compose {
    param([Parameter(Mandatory)][string[]]$ComposeArgs, [string]$InputText, [switch]$AllowFail)
    $all = @("compose", "-p", $project, "-f", $composeFile) + $ComposeArgs
    if ($PSBoundParameters.ContainsKey("InputText")) {
        return Invoke-Docker -DockerArgs $all -InputText $InputText -AllowFail:$AllowFail
    }
    return Invoke-Docker -DockerArgs $all -AllowFail:$AllowFail
}

function Invoke-Sql {
    param([Parameter(Mandatory)][string]$Sql)
    return Invoke-Compose -ComposeArgs @("exec", "-T", "db", "psql", "-U", "sbom", "-d", "sbom", "-At", "-v", "ON_ERROR_STOP=1", "-f", "-") -InputText $Sql
}

function Wait-Healthy {
    param([int]$Seconds = 300)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $code = & curl.exe -s -o NUL -w "%{http_code}" --noproxy "*" -m 3 "$baseUrl/health" 2>$null
        if ($code -eq "200") { return $true }
        Start-Sleep -Seconds 3
    }
    return $false
}

function Wait-DbReady {
    $deadline = (Get-Date).AddSeconds(120)
    while ((Get-Date) -lt $deadline) {
        $null = Invoke-Compose -ComposeArgs @("exec", "-T", "db", "pg_isready", "-U", "sbom", "-d", "sbom") -AllowFail
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw "The database did not become ready."
}

# --- http -------------------------------------------------------------------
$cookieJar = Join-Path $work "cookies.txt"
$tmpBody = Join-Path $work "body.json"
$STATUS = "<<<HTTP_STATUS>>>"

<#
    Calls the API through curl.exe. The JSON body goes through a file: Windows PowerShell 5.1
    strips double quotes from arguments passed to a native program, so inline JSON would
    arrive mangled.
#>
function Invoke-Api {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body,
        [string]$Bearer,
        [switch]$NoSession,
        [string]$OutFile
    )
    $curlArgs = @("-s", "--noproxy", "*", "-m", "120", "-X", $Method, "$baseUrl$Path")
    if (-not $NoSession -and -not $Bearer) { $curlArgs += @("-b", $cookieJar, "-c", $cookieJar) }
    if ($Bearer) { $curlArgs += @("-H", "Authorization: Bearer $Bearer") }
    if ($null -ne $Body) {
        [IO.File]::WriteAllText($tmpBody, ($Body | ConvertTo-Json -Depth 10 -Compress), (New-Object Text.UTF8Encoding $false))
        $curlArgs += @("-H", "Content-Type: application/json", "--data-binary", "@$tmpBody")
    }
    if ($OutFile) { $curlArgs += @("-o", $OutFile) }
    $curlArgs += @("-w", "$STATUS%{http_code}")
    $raw = (& curl.exe @curlArgs) -join "`n"
    $idx = $raw.LastIndexOf($STATUS)
    $status = [int]$raw.Substring($idx + $STATUS.Length)
    $text = $raw.Substring(0, $idx)
    $json = $null
    if ($text.Trim().StartsWith("{") -or $text.Trim().StartsWith("[")) {
        try { $json = $text | ConvertFrom-Json } catch { $json = $null }
    }
    return [pscustomobject]@{ Status = $status; Json = $json; Text = $text }
}

function Assert-Status {
    param($Response, [int[]]$Expected, [string]$What)
    if ($Expected -notcontains $Response.Status) {
        throw "$What returned HTTP $($Response.Status), expected $($Expected -join '/'): $($Response.Text)"
    }
    return $Response
}

<# A CycloneDX document in Syft's shape. `variant` changes versions, so each build differs. #>
function New-Sbom {
    param([string]$App, [int]$Variant, [string]$Path)
    $components = @(
        @{ type = "library"; name = "express"; version = "4.19.$Variant"; purl = "pkg:npm/express@4.19.$Variant" },
        @{ type = "library"; name = "lodash"; version = "4.17.21"; purl = "pkg:npm/lodash@4.17.21" },
        @{ type = "library"; name = "jackson-databind"; version = "2.17.$Variant"; purl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.$Variant" },
        @{ type = "library"; name = "openssl"; version = "3.0.1$Variant-1~deb12u1"; purl = "pkg:deb/debian/openssl@3.0.1$Variant-1~deb12u1?distro=debian-12&arch=amd64" },
        @{ type = "library"; name = "requests"; version = "2.32.$Variant"; purl = "pkg:pypi/requests@2.32.$Variant" },
        @{ type = "operating-system"; name = "debian"; version = "12" }
    )
    if ($Variant -eq 1) {
        $components += @{ type = "library"; name = "log4j-core"; version = "2.14.1"; purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }
    }
    $doc = @{
        bomFormat = "CycloneDX"; specVersion = "1.5"; version = 1
        serialNumber = "urn:uuid:$([guid]::NewGuid())"
        metadata = @{
            timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            tools = @{ components = @(@{ type = "application"; author = "anchore"; name = "syft"; version = "1.18.1" }) }
            component = @{ type = "container"; name = "registry.example.test/$($App):1.$Variant.0"; version = "sha256:$('{0:x64}' -f $Variant)" }
        }
        components = $components
        dependencies = @()
    }
    [IO.File]::WriteAllText($Path, ($doc | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding $false))
}

function Send-Sbom {
    param([string]$App, [int]$Variant, [string]$Token)
    $file = Join-Path $work "sbom-$App-$Variant.json"
    New-Sbom -App $App -Variant $Variant -Path $file
    $raw = (& curl.exe -s --noproxy "*" -m 120 -X POST "$baseUrl/api/v1/scans" `
            -H "Authorization: Bearer $Token" `
            -F "sbom=@$file" -F "app_name=$App" -F "commit_sha=rehearsal$Variant" `
            -F "build_number=$Variant" -F "branch=main" -w "$STATUS%{http_code}") -join "`n"
    $idx = $raw.LastIndexOf($STATUS)
    return [pscustomobject]@{
        Status = [int]$raw.Substring($idx + $STATUS.Length)
        Json   = $(try { $raw.Substring(0, $idx) | ConvertFrom-Json } catch { $null })
        Text   = $raw.Substring(0, $idx)
    }
}

<#
    Runs scripts\smoke-test.ps1 against the throwaway installation and returns the names of
    the checks that failed, or $null if it did not get as far as its summary.
#>
function Invoke-SmokeTest {
    param([string]$EnvFile, [string]$Name)
    $log = Join-Path $work $Name
    $relEnv = $EnvFile.Substring($repoRoot.Length + 1)
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot "scripts\smoke-test.ps1") -BaseUrl $baseUrl -EnvFile $relEnv *> $log
    $ErrorActionPreference = $previous
    $text = Get-Content $log
    if (-not ($text -match '\d+ passed')) { return $null }
    return , @($text | ForEach-Object { if ($_ -match '^\s+FAIL\s+(.+?)\s*$') { $Matches[1] } } | Sort-Object -Unique)
}

# --- fingerprint --------------------------------------------------------------
$closedOnStart = @{
    "public.vuln_db_update"        = @("finished_at", "outcome", "message")
    "public.malicious_feed_update" = @("finished_at", "outcome", "message")
}

<#
    Every row of every base table in the public and drizzle schemas, hashed.

    With -Columns (a table -> column-list map from an earlier fingerprint), each table is
    hashed over the columns it had then. A migration that adds a column then changes no hash,
    while a changed value in any column that existed before does.
#>
function Get-Fingerprint {
    param([hashtable]$Columns)
    $layout = Invoke-Sql -Sql @"
SELECT c.table_schema || '.' || c.table_name || '|' || string_agg(c.column_name, ',' ORDER BY c.ordinal_position)
FROM information_schema.columns c
JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE c.table_schema IN ('public', 'drizzle') AND t.table_type = 'BASE TABLE'
GROUP BY c.table_schema, c.table_name ORDER BY 1;
"@
    $current = @{}
    foreach ($line in $layout) {
        if ($line -notmatch '\|') { continue }
        $parts = $line.Split('|')
        $current[$parts[0]] = $parts[1]
    }
    $use = @{}
    $source = if ($Columns) { $Columns } else { $current }
    foreach ($t in $source.Keys) {
        # A background download still running when the platform stops is closed on the next
        # start ("Interrupted: the server restarted"), on every version. Its closing fields are
        # left out of the hash; the row itself, its id, start time and trigger still count.
        $skip = $closedOnStart[$t]
        $use[$t] = (@($source[$t].Split(',') | Where-Object { $skip -notcontains $_ }) -join ',')
    }

    $queries = New-Object System.Collections.Generic.List[string]
    foreach ($table in ($use.Keys | Sort-Object)) {
        if (-not $current.ContainsKey($table)) { continue }   # reported by the comparison
        $schema, $name = $table.Split('.')
        $cols = ($use[$table].Split(',') | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ","
        $queries.Add(@"
SELECT '$table' || chr(9) || md5(coalesce((SELECT jsonb_object_agg(e.key, e.value) FROM jsonb_each(to_jsonb(t)) e WHERE e.key = ANY (ARRAY[$cols]::text[])), '{}'::jsonb)::text) FROM "$schema"."$name" t;
"@)
    }
    $rows = @{}
    foreach ($table in $use.Keys) { if ($current.ContainsKey($table)) { $rows[$table] = New-Object System.Collections.Generic.List[string] } }
    foreach ($line in (Invoke-Sql -Sql ($queries -join "`n"))) {
        $tab = $line.IndexOf("`t")
        if ($tab -lt 0) { continue }
        $rows[$line.Substring(0, $tab)].Add($line.Substring($tab + 1))
    }

    $blobLines = Invoke-Docker -DockerArgs @("run", "--rm", "-v", "$($project)_sbom-blobs:/data:ro", "--entrypoint", "sh",
        "postgres:16-alpine", "-c", "cd /data && find . -type f -exec md5sum {} + | sort")
    return [pscustomobject]@{ Columns = $current; Rows = $rows; Blobs = @($blobLines | Where-Object { $_ -match '^[0-9a-f]{32}\s' }) }
}

function Save-Fingerprint {
    param($Fp, [string]$Name)
    $dir = Join-Path $work "fingerprint-$Name"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($t in $Fp.Rows.Keys) { ($Fp.Rows[$t] | Sort-Object) | Set-Content -Path (Join-Path $dir "$t.txt") -Encoding ascii }
    $Fp.Blobs | Set-Content -Path (Join-Path $dir "_blobs.txt") -Encoding ascii
    ($Fp.Columns.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.Value)" }) | Set-Content -Path (Join-Path $dir "_columns.txt") -Encoding ascii
}

<#
    Every row and file in $Before must still be in $After, unchanged. Extra rows and tables in
    $After are reported but allowed: an upgrade may add. Returns the problems found.
#>
function Compare-Fingerprint {
    param($Before, $After, [string[]]$AllowChanged = @())
    $problems = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($table in ($Before.Rows.Keys | Sort-Object)) {
        if (-not $After.Rows.ContainsKey($table)) { $problems.Add("table $table is gone"); continue }
        $missing = @{}
        foreach ($h in $Before.Rows[$table]) { $missing[$h] = 1 + [int]$missing[$h] }
        foreach ($h in $After.Rows[$table]) { if ($missing.ContainsKey($h)) { $missing[$h]--; if ($missing[$h] -le 0) { $missing.Remove($h) } } }
        $lost = ($missing.Values | Measure-Object -Sum).Sum
        $added = $After.Rows[$table].Count - $Before.Rows[$table].Count + $lost
        if ($lost -gt 0) {
            $line = "$table : $lost of $($Before.Rows[$table].Count) rows missing or changed"
            if ($AllowChanged -contains $table) { $notes.Add("$line (allowed)") } else { $problems.Add($line) }
        }
        if ($added -gt 0) { $notes.Add("$table : $added new rows") }
    }
    foreach ($table in $After.Rows.Keys) { if (-not $Before.Rows.ContainsKey($table)) { $notes.Add("new table $table") } }
    foreach ($b in $Before.Blobs) { if ($After.Blobs -notcontains $b) { $problems.Add("stored SBOM missing or changed: $b") } }
    foreach ($n in $notes) { Write-Note $n }
    return , $problems
}

# ==============================================================================
Write-Host ""
Write-Host "SBOM Platform - upgrade rehearsal" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor DarkGray
Write-Note "project   $project"
Write-Note "from      $FromBundle"
Write-Note "to        $ToApiImage, $ToWebImage"
Write-Note "work dir  $work"

$null = Invoke-Docker -DockerArgs @("info", "--format", "{{.ServerVersion}}")
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is already in use - probably an earlier rehearsal still running. Stop it, or pass -Port."
}
New-Item -ItemType Directory -Force -Path $work | Out-Null

# --- the bundle -----------------------------------------------------------------
$bundle = Resolve-Path $FromBundle
$imagesEnv = @{}
foreach ($line in Get-Content (Join-Path $bundle "images.env")) {
    # Trimmed: bundles up to 0.3.11 wrote this file with CRLF line endings.
    if ($line -match '^\s*([A-Z_][A-Z0-9_]*)=(.*)$') { $imagesEnv[$Matches[1]] = $Matches[2].Trim() }
}
$fromApi = $imagesEnv["SBOM_IMAGE_API"]; $fromWeb = $imagesEnv["SBOM_IMAGE_WEB"]; $fromVersion = $imagesEnv["APP_VERSION"]

Write-Step "Loading the $fromVersion images if they are missing"
$needLoad = $false
foreach ($img in @("postgres:16-alpine", $fromApi, $fromWeb)) {
    $null = Invoke-Docker -DockerArgs @("image", "inspect", $img) -AllowFail
    if ($LASTEXITCODE -ne 0) { $needLoad = $true }
}
if ($needLoad) { $null = Invoke-Docker -DockerArgs @("load", "--input", (Join-Path $bundle "images.tar")) }

if (-not $SkipBuild) {
    Write-Step "Building the images of this checkout (the version being upgraded to)"
    $null = Invoke-Docker -DockerArgs @("build", "--platform", "linux/amd64", "-f", "packages/api/Dockerfile", "-t", $ToApiImage, ".")
    $null = Invoke-Docker -DockerArgs @("build", "--platform", "linux/amd64", "-f", "packages/web/Dockerfile", "-t", $ToWebImage, ".")
}

# --- 1. old version, with data ----------------------------------------------------
$old = Join-Path $work "old"; $new = Join-Path $work "new"; $backup = Join-Path $work "backup"
New-Item -ItemType Directory -Force -Path $old, $new, $backup | Out-Null
Copy-Item (Join-Path $bundle "docker-compose.yml") $old
if (Test-Path (Join-Path $bundle "ca")) { Copy-Item (Join-Path $bundle "ca") $old -Recurse }
else { New-Item -ItemType Directory -Path (Join-Path $old "ca") | Out-Null }

function New-Secret { param([int]$Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $chars = ""
    while ($chars.Length -lt $Length) { $b = New-Object byte[] 48; $rng.GetBytes($b); $chars += ([Convert]::ToBase64String($b) -replace '[+/=]', '') }
    return $chars.Substring(0, $Length)
}
$adminPassword = New-Secret 20
$ciToken = (New-Secret 48).ToLower()
# Same keys start.ps1 writes on a real server, so the upgrade sees the same .env shape.
@"
SBOM_PORT=$Port
PUBLIC_URL=$baseUrl
SESSION_SECRET=$(New-Secret 64)
SECRETS_KEY=$(New-Secret 48)
INGEST_TOKENS=ci:$ciToken
BOOTSTRAP_ADMIN_EMAIL=admin@sbom.local
BOOTSTRAP_ADMIN_PASSWORD=$adminPassword
POSTGRES_PASSWORD=$(New-Secret 32)
STALE_APP_THRESHOLD_DAYS=30
LOG_LEVEL=info
"@ | Out-File -FilePath (Join-Path $old ".env") -Encoding ascii

$composeFile = Join-Path $old "docker-compose.yml"
$env:SBOM_IMAGE_API = $fromApi; $env:SBOM_IMAGE_WEB = $fromWeb; $env:APP_VERSION = $fromVersion
Write-Step "Starting $fromVersion as project $project on port $Port"
$null = Invoke-Compose -ComposeArgs @("--env-file", (Join-Path $old ".env"), "up", "-d")
if (-not (Wait-Healthy)) { throw "$fromVersion did not become healthy." }

Write-Step "Filling it with data through the API"
$null = Assert-Status (Invoke-Api POST "/api/v1/auth/login" @{ email = "admin@sbom.local"; password = $adminPassword }) 200 "admin sign-in"

$apps = @("payments-api", "checkout-web", "ledger-service", "unconfirmed-tool")
$appIds = @{}; $scanIds = New-Object System.Collections.Generic.List[string]
foreach ($app in $apps) {
    foreach ($v in 1..2) {
        $r = Assert-Status (Send-Sbom -App $app -Variant $v -Token $ciToken) 201 "upload $app build $v"
        $appIds[$app] = $r.Json.applicationId; $scanIds.Add($r.Json.scanId)
    }
}
foreach ($app in $apps | Where-Object { $_ -ne "unconfirmed-tool" }) {
    $null = Assert-Status (Invoke-Api POST "/api/v1/admin/applications/$($appIds[$app])/confirm" @{}) 200, 201 "confirm $app"
}

$dbToken = (Assert-Status (Invoke-Api POST "/api/v1/admin/ingest-tokens" @{ name = "rehearsal-db" }) 201 "create ingest token").Json.plaintext
$null = Assert-Status (Send-Sbom -App "payments-api" -Variant 3 -Token $dbToken) 201 "upload with the database token"

$devPassword = New-Secret 20
$dev1 = (Assert-Status (Invoke-Api POST "/api/v1/admin/users" @{ email = "dev.one@rehearsal"; password = $devPassword; mustChangePassword = $false }) 201 "create user").Json.user.id
$dev2 = (Assert-Status (Invoke-Api POST "/api/v1/admin/users" @{ email = "dev.two@rehearsal"; password = $devPassword; mustChangePassword = $false }) 201 "create user").Json.user.id
$tribe = (Assert-Status (Invoke-Api POST "/api/v1/admin/tribes" @{ name = "Rehearsal tribe" }) 201 "create tribe").Json.tribe.id
$squad = (Assert-Status (Invoke-Api POST "/api/v1/admin/squads" @{ name = "Payments"; email = "payments@example.test"; tribeIds = @($tribe) }) 201 "create squad").Json.squad.id
$null = Assert-Status (Invoke-Api PUT "/api/v1/admin/squads/$squad/members" @{ userIds = @($dev1, $dev2) }) 200 "squad members"
$group = (Assert-Status (Invoke-Api POST "/api/v1/admin/groups" @{ name = "Rehearsal group"; applicationIds = @($appIds["ledger-service"]) }) 201 "create group").Json
$groupId = if ($group.group) { $group.group.id } else { $group.id }
$null = Assert-Status (Invoke-Api PUT "/api/v1/admin/squads/$squad/access" @{ applicationIds = @($appIds["payments-api"]); groupIds = @($groupId) }) 200 "squad access"

$apiToken = (Assert-Status (Invoke-Api POST "/api/v1/auth/api-tokens" @{ name = "rehearsal"; scope = "read" }) 201 "create API token").Json.secret

$suppression = (Assert-Status (Invoke-Api POST "/api/v1/admin/vuln/suppressions" @{
            vulnerabilityId = "CVE-2021-44228"; applicationId = $appIds["payments-api"]
            reason = "Rehearsal: JNDI lookups are disabled in this service."; expiresAt = "2027-06-30T00:00:00Z"
            vexStatus = "not_affected"; vexJustification = "code_not_reachable"
        }) 201 "create accepted risk").Json.id

$null = Assert-Status (Invoke-Api PATCH "/api/v1/admin/settings" @{ staleThresholdDays = 45 }) 200 "change platform settings"
$attention = (Assert-Status (Invoke-Api GET "/api/v1/admin/settings/attention") 200 "read attention settings").Json
$attentionBody = if ($attention.settings) { $attention.settings } else { $attention }
$attentionBody.criticalFixDays = 21
$null = Assert-Status (Invoke-Api PUT "/api/v1/admin/settings/attention" $attentionBody) 200 "change attention settings"
$null = Assert-Status (Invoke-Api PATCH "/api/v1/admin/malicious/settings" @{ alertRecipients = @("security@example.test") }) 200 "change malicious-package settings"
$report = (Assert-Status (Invoke-Api POST "/api/v1/admin/reports" @{ kind = "adhoc" }) 200, 201 "generate report").Json.run.id
Write-Note "4 applications (1 left unconfirmed), $($scanIds.Count + 1) builds, 3 users, tribe, squad, group, 2 ingest tokens, API token, accepted risk, settings, report"

# The smoke test on the old version first: it adds more data of every kind, and its failures
# on this data are the baseline the upgraded version is compared against.
$beforeFails = $null
if (-not $SkipSmokeTest) {
    Write-Step "Running the smoke test against $fromVersion (the baseline)"
    $beforeFails = Invoke-SmokeTest -EnvFile (Join-Path $old ".env") -Name "smoke-before.log"
    if ($null -ne $beforeFails) { Write-Note "$($beforeFails.Count) check(s) fail on $fromVersion with this data" }
    $null = Assert-Status (Invoke-Api POST "/api/v1/auth/login" @{ email = "admin@sbom.local"; password = $adminPassword }) 200 "admin sign-in"
}

# --- 2. fingerprint and backup --------------------------------------------------
Write-Step "Stopping the API and taking the fingerprint"
$null = Invoke-Compose -ComposeArgs @("stop", "web", "api")
$before = Get-Fingerprint
Save-Fingerprint $before "1-before"
$rowCount = ($before.Rows.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Note "$($before.Rows.Count) tables, $rowCount rows, $($before.Blobs.Count) stored SBOMs"

Write-Step "Backing up the database, the stored SBOMs and .env"
$null = Invoke-Compose -ComposeArgs @("exec", "-T", "db", "pg_dump", "-U", "sbom", "-Fc", "sbom", "-f", "/tmp/rehearsal.dump")
$null = Invoke-Compose -ComposeArgs @("cp", "db:/tmp/rehearsal.dump", (Join-Path $backup "sbom.dump"))
$entries = (Invoke-Compose -ComposeArgs @("exec", "-T", "db", "pg_restore", "-l", "/tmp/rehearsal.dump")).Count
$null = Invoke-Docker -DockerArgs @("run", "--rm", "-v", "$($project)_sbom-blobs:/data:ro", "-v", "$($backup):/backup", "--entrypoint", "tar",
    "postgres:16-alpine", "czf", "/backup/sbom-blobs.tar.gz", "-C", "/data", ".")
Copy-Item (Join-Path $old ".env") (Join-Path $backup ".env")
Add-Result "backup is readable" ($entries -gt 50 -and (Get-Item (Join-Path $backup "sbom-blobs.tar.gz")).Length -gt 0) "$entries entries in the dump"

# --- 3. upgrade -------------------------------------------------------------------
Write-Step "Upgrading: same project, same volumes, same .env; new compose file and images"
$null = Invoke-Compose -ComposeArgs @("down")     # containers only; the volumes stay
Copy-Item (Join-Path $repoRoot "deploy\docker-compose.yml") $new
Copy-Item (Join-Path $old "ca") $new -Recurse
Copy-Item (Join-Path $old ".env") $new             # the procedure keeps the old .env as it is
$composeFile = Join-Path $new "docker-compose.yml"
$env:SBOM_IMAGE_API = $ToApiImage; $env:SBOM_IMAGE_WEB = $ToWebImage; $env:APP_VERSION = "rehearsal"
$null = Invoke-Compose -ComposeArgs @("--env-file", (Join-Path $new ".env"), "up", "-d")
$healthy = Wait-Healthy
Add-Result "upgraded version starts and answers" $healthy
if (-not $healthy) {
    (Invoke-Compose -ComposeArgs @("logs", "--tail", "120", "api") -AllowFail) | Set-Content (Join-Path $work "api-upgrade.log")
    throw "The upgraded version did not become healthy; see $work\api-upgrade.log"
}

$apiLog = Invoke-Compose -ComposeArgs @("logs", "api")
$apiLog | Set-Content (Join-Path $work "api-upgrade.log")
$journal = (Get-Content (Join-Path $repoRoot "packages\api\drizzle\meta\_journal.json") -Raw | ConvertFrom-Json).entries.Count
$applied = [int]((Invoke-Sql -Sql "SELECT count(*) FROM drizzle.__drizzle_migrations;") | Select-Object -Last 1)
Add-Result "migrations ran cleanly" (($apiLog -match '\[migrate\] done').Count -gt 0 -and $applied -eq $journal) "$applied applied, $journal in this version"

Write-Step "Stopping the API and comparing the fingerprint"
$null = Invoke-Compose -ComposeArgs @("stop", "web", "api")
$after = Get-Fingerprint -Columns $before.Columns
Save-Fingerprint $after "2-after-upgrade"
$problems = Compare-Fingerprint $before $after
Add-Result "no row lost or changed" ($problems.Count -eq 0) $(if ($problems.Count) { $problems -join "; " } else { "$rowCount rows checked" })
Add-Result "every stored SBOM intact" (@($problems | Where-Object { $_ -like "stored SBOM*" }).Count -eq 0) "$($before.Blobs.Count) files"

# --- 4. it still works -----------------------------------------------------------------
Write-Step "Checking that the upgraded installation still works"
$null = Invoke-Compose -ComposeArgs @("start", "api", "web")
if (-not (Wait-Healthy)) { throw "The upgraded version did not come back after the fingerprint." }
Remove-Item $cookieJar -ErrorAction SilentlyContinue

$r = Invoke-Api POST "/api/v1/auth/login" @{ email = "admin@sbom.local"; password = $adminPassword }
Add-Result "existing admin signs in" ($r.Status -eq 200)
$r = Invoke-Api POST "/api/v1/auth/login" @{ email = "dev.one@rehearsal"; password = $devPassword } -NoSession
Add-Result "existing user signs in" ($r.Status -eq 200)
$r = Invoke-Api GET "/api/v1/auth/me" -Bearer $apiToken
Add-Result "existing personal API token works" ($r.Status -eq 200)
$r = Send-Sbom -App "payments-api" -Variant 4 -Token $ciToken
Add-Result "existing ingest token from .env uploads" ($r.Status -eq 201)
$r = Send-Sbom -App "checkout-web" -Variant 4 -Token $dbToken
Add-Result "existing database ingest token uploads" ($r.Status -eq 201)
$r = Invoke-Api GET "/api/v1/admin/vuln/suppressions"
Add-Result "existing accepted risk is listed" ($r.Status -eq 200 -and $r.Text -match [regex]::Escape($suppression))
$r = Invoke-Api GET "/api/v1/admin/settings"
Add-Result "platform setting kept" ($r.Status -eq 200 -and $r.Text -match '"staleThresholdDays"\s*:\s*45')
$r = Invoke-Api GET "/api/v1/admin/settings/attention"
Add-Result "attention setting kept" ($r.Status -eq 200 -and $r.Text -match '"criticalFixDays"\s*:\s*21')
$pdf = Join-Path $work "report.pdf"
$r = Invoke-Api GET "/api/v1/admin/reports/$report.pdf" -OutFile $pdf
$isPdf = (Test-Path $pdf) -and ([Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($pdf), 0, 4) -eq "%PDF")
Add-Result "existing report PDF downloads" ($r.Status -eq 200 -and $isPdf)
$raw = Join-Path $work "raw-sbom.json"
$r = Invoke-Api GET "/api/v1/scans/$($scanIds[0])/raw" -OutFile $raw
Add-Result "oldest build's raw SBOM downloads" ($r.Status -eq 200 -and (Get-Content $raw -Raw) -match '"bomFormat"')

# Case-insensitive duplicates are refused through a unique index, i.e. a database error the
# code has to recognise. Unit tests mock the database and cannot see this; the release that
# moved to drizzle-orm 0.45 broke it (409 became 500) while every unit test passed.
$r = Invoke-Api POST "/api/v1/admin/users" @{ email = "DEV.ONE@rehearsal"; password = $devPassword; mustChangePassword = $false }
Add-Result "duplicate account name is refused with 409" ($r.Status -eq 409) "got $($r.Status)"

if (-not $SkipSmokeTest) {
    Write-Step "Running the smoke test against the upgraded installation"
    $afterFails = Invoke-SmokeTest -EnvFile (Join-Path $new ".env") -Name "smoke-after.log"
    if ($null -eq $beforeFails -or $null -eq $afterFails) {
        Add-Result "smoke test" $false "the smoke test did not complete; see the logs in $work"
    }
    else {
        # Only a check that passed on the old version and fails on the new one is a regression.
        # The smoke test was written against a developer database and some of its checks fail
        # on any other data, old version or new.
        $regressions = @($afterFails | Where-Object { $beforeFails -notcontains $_ })
        Add-Result "smoke test: nothing that passed before fails now" ($regressions.Count -eq 0) $(
            if ($regressions.Count) { $regressions -join "; " }
            else { "$($beforeFails.Count) check(s) fail on both versions with this data" })
    }
}

# --- 5. going back ---------------------------------------------------------------------
Write-Step "Rehearsing the way back: restore the backup into $fromVersion"
$null = Invoke-Compose -ComposeArgs @("down")
$composeFile = Join-Path $old "docker-compose.yml"
$env:SBOM_IMAGE_API = $fromApi; $env:SBOM_IMAGE_WEB = $fromWeb; $env:APP_VERSION = $fromVersion
$null = Invoke-Compose -ComposeArgs @("--env-file", (Join-Path $old ".env"), "up", "-d", "db")
Wait-DbReady
$null = Invoke-Compose -ComposeArgs @("cp", (Join-Path $backup "sbom.dump"), "db:/tmp/restore.dump")
$null = Invoke-Compose -ComposeArgs @("exec", "-T", "db", "dropdb", "-U", "sbom", "sbom")
$null = Invoke-Compose -ComposeArgs @("exec", "-T", "db", "createdb", "-U", "sbom", "-O", "sbom", "sbom")
$null = Invoke-Compose -ComposeArgs @("exec", "-T", "db", "pg_restore", "-U", "sbom", "-d", "sbom", "/tmp/restore.dump")
$null = Invoke-Docker -DockerArgs @("run", "--rm", "-v", "$($project)_sbom-blobs:/data", "-v", "$($backup):/backup:ro", "--entrypoint", "sh",
    "postgres:16-alpine", "-c", "find /data -mindepth 1 -delete && tar xzf /backup/sbom-blobs.tar.gz -C /data")
$null = Invoke-Compose -ComposeArgs @("--env-file", (Join-Path $old ".env"), "up", "-d")
Add-Result "$fromVersion starts on the restored backup" (Wait-Healthy)
# Fingerprint first: signing in updates the account's last-login time, which is a change
# this script would otherwise make itself and then report.
$null = Invoke-Compose -ComposeArgs @("stop", "web", "api")
$restored = Get-Fingerprint
Save-Fingerprint $restored "3-after-restore"
$back = Compare-Fingerprint $before $restored
Add-Result "restored data equals the data before the upgrade" ($back.Count -eq 0) $(if ($back.Count) { $back -join "; " } else { "$rowCount rows checked" })
$null = Invoke-Compose -ComposeArgs @("start", "api", "web")
$null = Wait-Healthy
Remove-Item $cookieJar -ErrorAction SilentlyContinue
$r = Invoke-Api POST "/api/v1/auth/login" @{ email = "admin@sbom.local"; password = $adminPassword }
Add-Result "admin signs in after going back" ($r.Status -eq 200)

# --- done --------------------------------------------------------------------------------
$null = Invoke-Compose -ComposeArgs @("down")    # containers only
Remove-Item Env:SBOM_IMAGE_API, Env:SBOM_IMAGE_WEB, Env:APP_VERSION -ErrorAction SilentlyContinue

$failed = @($results | Where-Object { $_.Result -eq "FAIL" }).Count
$results | Format-Table -AutoSize | Out-String -Width 220 | Set-Content (Join-Path $work "report.txt")
Write-Host ""
Write-Host ("=" * 66) -ForegroundColor DarkGray
$results | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
if ($failed -eq 0) { Write-Host "Upgrade rehearsal passed." -ForegroundColor Green }
else { Write-Host "Upgrade rehearsal FAILED: $failed check(s)." -ForegroundColor Red }
Write-Note "Report and fingerprints: $work"
Write-Note "Volumes left for inspection (project $project); delete them in Docker Desktop when done:"
Invoke-Docker -DockerArgs @("volume", "ls", "--filter", "label=com.docker.compose.project=$project", "--format", "{{.Name}}") | ForEach-Object { Write-Note "  $_" }
if ($failed -gt 0) { exit 1 }
