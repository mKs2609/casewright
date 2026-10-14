# Sets a user's role directly in the database. Used to create the first ADMIN:
# inside the application only an existing admin can change roles, so the very
# first one has to be appointed from outside.
#
#   powershell -ExecutionPolicy Bypass -File scripts\set-role.ps1 -Username mohit -Role ADMIN
#
# It also ends that user's sessions, so they must log in again to get the new role.
# Needs the .env file (database settings). Anyone who can run this already has
# full access to the database, so it grants nothing they did not have.

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9._-]{3,32}$')]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [ValidateSet('ADMIN', 'ANALYST', 'VIEWER')]
    [string]$Role
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) { throw ".env not found. Run scripts\setup-db.ps1 first." }

$settings = @{}
Get-Content $envFile | Where-Object { $_ -match '^([A-Z_]+)=(.*)$' } | ForEach-Object { $settings[$Matches[1]] = $Matches[2] }
if ($settings["DB_URL"] -notmatch '^jdbc:postgresql://([^:/]+):(\d+)/(\w+)$') { throw "DB_URL in .env has an unexpected format." }
$dbHost, $dbPort, $dbName = $Matches[1], $Matches[2], $Matches[3]

$psql = (Get-Command psql -ErrorAction SilentlyContinue).Source
if (-not $psql) {
    $psql = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $psql) { throw "psql.exe not found. Is PostgreSQL installed?" }

# :'u' and :'r' are filled in by psql as safely quoted values, never pasted into the SQL as text.
$sql = @"
UPDATE refresh_tokens SET revoked_at = now()
 WHERE revoked_at IS NULL AND user_id = (SELECT id FROM app_users WHERE username = :'u');
UPDATE app_users SET role = :'r' WHERE username = :'u' RETURNING username, role;
"@

$env:PGPASSWORD = $settings["DB_PASSWORD"]
try {
    $out = $sql | & $psql -h $dbHost -p $dbPort -U $settings["DB_USER"] -d $dbName -v ON_ERROR_STOP=1 -v "u=$Username" -v "r=$Role" -t -A -q
    if ($LASTEXITCODE -ne 0) { throw "The database refused the change (see the message above)." }
} finally {
    $env:PGPASSWORD = $null
}

if ($out -match [regex]::Escape("$Username|$Role")) {
    Write-Host "Done. '$Username' is now $Role. They must log in again for it to take effect."
} else {
    Write-Host "No user named '$Username' exists. Sign up first, then run this again."
    exit 1
}
