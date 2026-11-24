<#
.SYNOPSIS
    Tests the Active Directory connector against a real AD domain controller (Samba 4).

.DESCRIPTION
    Builds scripts/samba-ad (Debian's own Samba packages), starts it as the throwaway container
    sbom-test-ad on 127.0.0.1:16636 with the test domain corp.example, copies its test CA out,
    and runs packages/api/test/ad. The container is removed at the end; it has no data volume.

    The container needs CAP_SYS_ADMIN: a Samba domain controller stores access lists in extended
    attributes, which Docker allows only with it. Only this local test container gets it.

.EXAMPLE
    .\scripts\test-directory-ad.ps1
    .\scripts\test-directory-ad.ps1 -Keep     # leave the domain controller running afterwards
#>
param([switch]$Keep)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$name = "sbom-test-ad"
$work = Join-Path $repoRoot "var\samba-ad"
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Invoke-Native([scriptblock]$Command, [string]$What) {
    $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $Command
    $code = $LASTEXITCODE; $ErrorActionPreference = $previous
    if ($code -ne 0) { throw "$What failed (exit $code)." }
}

Write-Host "==> Building the test domain controller" -ForegroundColor Cyan
Invoke-Native { docker build -q -t sbom-test-samba-ad:local (Join-Path $repoRoot "scripts\samba-ad") | Out-Null } "docker build"

$previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
& docker rm -f $name *> $null
$ErrorActionPreference = $previous
Write-Host "==> Starting corp.example (about a minute)" -ForegroundColor Cyan
Invoke-Native { docker run -d --name $name -h dc1 --cap-add SYS_ADMIN -p 127.0.0.1:16636:636 sbom-test-samba-ad:local | Out-Null } "docker run"

try {
    $ready = $false
    for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
        Start-Sleep 3
        # Samba writes to stderr, which Windows PowerShell 5.1 would turn into a stopping error.
        $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        $log = (& docker logs $name 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $ErrorActionPreference = $previous
        if ($log -match "uncaught exception|Traceback") { throw "The domain controller did not start:`n$log" }
        if ($log -match "provisioned") {
            $tcp = New-Object Net.Sockets.TcpClient
            try { $tcp.Connect("127.0.0.1", 16636); $ready = $true } catch { } finally { $tcp.Dispose() }
        }
    }
    if (-not $ready) { throw "The domain controller did not answer on 127.0.0.1:16636 within three minutes." }

    $ca = Join-Path $work "ca.pem"
    Invoke-Native { docker cp "$($name):/tls/ca.pem" $ca } "copying the test CA"

    Write-Host "==> Running the connector's tests" -ForegroundColor Cyan
    $env:AD_TEST_SERVER = "localhost:16636"
    $env:AD_TEST_CA_FILE = $ca
    Push-Location (Join-Path $repoRoot "packages\api")
    try { Invoke-Native { npx vitest run test/ad } "the AD tests" } finally { Pop-Location }
}
finally {
    Remove-Item Env:AD_TEST_SERVER, Env:AD_TEST_CA_FILE -ErrorAction SilentlyContinue
    if (-not $Keep) {
        $previous = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        & docker rm -f $name *> $null
        $ErrorActionPreference = $previous
    }
}
