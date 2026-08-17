<#
.SYNOPSIS
    One-time local setup: creates the `sbom` role and database in an existing
    PostgreSQL instance.

.DESCRIPTION
    Run this once before `npm run db:migrate`. It prompts for the PostgreSQL
    superuser password (normally set during installation) and does not store it —
    the password is held only for the lifetime of this process and passed to psql
    through the PGPASSWORD environment variable of the child process.

    Everything here is idempotent, so re-running it is safe.

    The `sbom` role is created as the OWNER of the `sbom` database, not as a
    superuser. That is enough for the migrations to run: `pg_trgm` and `pgcrypto`
    are both marked `trusted = true` in PostgreSQL 13+, which lets a database
    owner install them without superuser rights.

.EXAMPLE
    .\scripts\setup-local-db.ps1
    .\scripts\setup-local-db.ps1 -PgBin "C:\Program Files\PostgreSQL\16\bin"
#>
[CmdletBinding()]
param(
    # Directory containing psql.exe. Auto-detected if omitted.
    [string]$PgBin,
    [string]$PgHost = "127.0.0.1",
    [int]$Port = 5432,
    [string]$Superuser = "postgres",
    # Must match the credentials in DATABASE_URL in your .env file.
    [string]$AppRole = "sbom",
    [string]$AppPassword = "sbom",
    [string]$AppDatabase = "sbom"
)

$ErrorActionPreference = "Stop"

# --- locate psql -----------------------------------------------------------
if (-not $PgBin) {
    $onPath = Get-Command psql -ErrorAction SilentlyContinue
    if ($onPath) {
        $PgBin = Split-Path $onPath.Source -Parent
    }
    else {
        # The Windows installer does not add itself to PATH. Prefer the newest
        # version present.
        $candidates = Get-ChildItem "$env:ProgramFiles\PostgreSQL" -Directory -ErrorAction SilentlyContinue |
            Sort-Object { [int]($_.Name -replace '\D', '0') } -Descending
        foreach ($c in $candidates) {
            if (Test-Path "$($c.FullName)\bin\psql.exe") { $PgBin = "$($c.FullName)\bin"; break }
        }
    }
}

if (-not $PgBin -or -not (Test-Path "$PgBin\psql.exe")) {
    throw "Could not find psql.exe. Pass -PgBin 'C:\Program Files\PostgreSQL\<version>\bin'."
}

$psql = Join-Path $PgBin "psql.exe"
Write-Host "Using psql: $psql" -ForegroundColor DarkGray
& $psql --version

# --- collect the superuser password ---------------------------------------
Write-Host ""
Write-Host "Enter the password for the PostgreSQL '$Superuser' superuser" -ForegroundColor Cyan
Write-Host "(the one you chose when installing PostgreSQL). Input is hidden." -ForegroundColor DarkGray
$secure = Read-Host -Prompt "Password" -AsSecureString
$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
)
if ([string]::IsNullOrWhiteSpace($plain)) { throw "No password entered." }

# Scoped to this process only; child psql calls inherit it.
$env:PGPASSWORD = $plain

function Invoke-Psql {
    param([string]$Database, [string]$Sql)
    $output = & $psql -h $PgHost -p $Port -U $Superuser -d $Database -v ON_ERROR_STOP=1 -t -A -c $Sql
    if ($LASTEXITCODE -ne 0) {
        throw "psql failed (exit $LASTEXITCODE) running: $Sql`n$output"
    }
    return $output
}

try {
    # --- verify the connection before changing anything -------------------
    Write-Host ""
    Write-Host "Checking connection..." -ForegroundColor Cyan
    $version = Invoke-Psql -Database "postgres" -Sql "SELECT version();"
    Write-Host "  connected: $($version -split ',' | Select-Object -First 1)" -ForegroundColor Green

    # --- role -------------------------------------------------------------
    Write-Host ""
    Write-Host "Ensuring role '$AppRole'..." -ForegroundColor Cyan
    $roleExists = Invoke-Psql -Database "postgres" `
        -Sql "SELECT 1 FROM pg_roles WHERE rolname = '$AppRole';"

    if ($roleExists -eq "1") {
        # Reset the password so it always matches what .env expects, which is the
        # usual cause of "password authentication failed" on a re-run.
        Invoke-Psql -Database "postgres" `
            -Sql "ALTER ROLE $AppRole WITH LOGIN PASSWORD '$AppPassword';" | Out-Null
        Write-Host "  role already existed; password reset to match .env" -ForegroundColor Yellow
    }
    else {
        Invoke-Psql -Database "postgres" `
            -Sql "CREATE ROLE $AppRole WITH LOGIN PASSWORD '$AppPassword';" | Out-Null
        Write-Host "  created" -ForegroundColor Green
    }

    # --- database ---------------------------------------------------------
    Write-Host ""
    Write-Host "Ensuring database '$AppDatabase'..." -ForegroundColor Cyan
    $dbExists = Invoke-Psql -Database "postgres" `
        -Sql "SELECT 1 FROM pg_database WHERE datname = '$AppDatabase';"

    if ($dbExists -eq "1") {
        Write-Host "  already exists" -ForegroundColor Yellow
    }
    else {
        # CREATE DATABASE cannot run inside a transaction block, hence its own call.
        Invoke-Psql -Database "postgres" `
            -Sql "CREATE DATABASE $AppDatabase OWNER $AppRole ENCODING 'UTF8';" | Out-Null
        Write-Host "  created, owned by $AppRole" -ForegroundColor Green
    }

    # --- schema privileges ------------------------------------------------
    # In PostgreSQL 15+ the public schema is no longer world-writable, so the app
    # role needs an explicit grant even though it owns the database.
    Invoke-Psql -Database $AppDatabase `
        -Sql "GRANT ALL ON SCHEMA public TO $AppRole; ALTER SCHEMA public OWNER TO $AppRole;" | Out-Null

    # --- extensions -------------------------------------------------------
    # Created here as superuser so the outcome does not depend on the trusted-
    # extension rules of the server version. The migration also declares them
    # with IF NOT EXISTS, so this simply makes that step a no-op.
    Write-Host ""
    Write-Host "Ensuring extensions..." -ForegroundColor Cyan
    Invoke-Psql -Database $AppDatabase -Sql "CREATE EXTENSION IF NOT EXISTS pg_trgm;" | Out-Null
    Invoke-Psql -Database $AppDatabase -Sql "CREATE EXTENSION IF NOT EXISTS pgcrypto;" | Out-Null
    $exts = Invoke-Psql -Database $AppDatabase `
        -Sql "SELECT extname || ' ' || extversion FROM pg_extension ORDER BY extname;"
    foreach ($e in $exts) { if ($e) { Write-Host "  $e" -ForegroundColor Green } }

    # --- verify the app role can actually log in --------------------------
    Write-Host ""
    Write-Host "Verifying '$AppRole' can connect..." -ForegroundColor Cyan
    $env:PGPASSWORD = $AppPassword
    $whoami = & $psql -h $PgHost -p $Port -U $AppRole -d $AppDatabase -v ON_ERROR_STOP=1 -t -A `
        -c "SELECT current_user || '@' || current_database();"
    if ($LASTEXITCODE -ne 0) { throw "The '$AppRole' role could not connect to '$AppDatabase'." }
    Write-Host "  $whoami" -ForegroundColor Green

    Write-Host ""
    Write-Host "Done. Next:" -ForegroundColor Cyan
    Write-Host "  npm run db:migrate"
    Write-Host "  npm run db:seed"
    Write-Host "  npm run dev"
}
finally {
    # Never leave a password in the environment of this shell.
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    if ($plain) { $plain = $null }
}
