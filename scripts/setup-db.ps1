# One-time setup of the local development database.
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1
#
# It asks for the password of the PostgreSQL "postgres" superuser (the one you
# chose when installing PostgreSQL). That password is typed into psql directly
# and is never stored. The script then:
#   1. generates a random password for the application's own database role
#   2. creates the role and the database (scripts\setup-db.sql)
#   3. writes DB_URL / DB_USER / DB_PASSWORD into .env (which git ignores)

param(
    [string]$PgHost = "localhost",
    [int]$PgPort = 5432,
    [string]$SuperUser = "postgres"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env"

# --- find psql
$psql = (Get-Command psql -ErrorAction SilentlyContinue).Source
if (-not $psql) {
    $psql = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) { throw "psql.exe not found. Is PostgreSQL installed?" }

# --- reuse the existing app password if .env already has one, otherwise generate one
$lines = @()
if (Test-Path $envFile) { $lines = @(Get-Content $envFile) }
$existing = $lines | Where-Object { $_ -match '^DB_PASSWORD=(.+)$' } | Select-Object -First 1
if ($existing) {
    $appPassword = $existing -replace '^DB_PASSWORD=', ''
} else {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $appPassword = -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

# --- create role + database (psql prompts for the superuser password)
Write-Host "Connecting to PostgreSQL as '$SuperUser'. Enter that user's password when asked."
& $psql -h $PgHost -p $PgPort -U $SuperUser -d postgres -v ON_ERROR_STOP=1 -v "pw=$appPassword" -q -f (Join-Path $PSScriptRoot "setup-db.sql")
if ($LASTEXITCODE -ne 0) { throw "Database setup failed (see the message above). Nothing was written to .env." }

# --- write .env (keep any other settings already in it)
$kept = $lines | Where-Object { $_ -notmatch '^(DB_URL|DB_USER|DB_PASSWORD)=' }
$new = @($kept) + @(
    "DB_URL=jdbc:postgresql://${PgHost}:${PgPort}/secanalyst",
    "DB_USER=secanalyst_app",
    "DB_PASSWORD=$appPassword"
)
# UTF-8 without a byte-order mark, so Spring reads the first line correctly
[System.IO.File]::WriteAllLines($envFile, [string[]]$new)

Write-Host "Done. Database 'secanalyst' and role 'secanalyst_app' are ready."
Write-Host "Connection settings were written to $envFile (ignored by git)."
