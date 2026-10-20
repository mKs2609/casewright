# Generates the application's own secrets and adds them to .env.
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup-secrets.ps1
#
# Safe to run again: a secret that already exists in .env is never changed
# (changing the signing key would log everybody out; changing the baseline key would make
# every stored baseline unreadable).
# The values are random, are never printed, and .env is ignored by git.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env"

# name -> number of random bytes
$secrets = [ordered]@{
    "JWT_SIGNING_KEY" = 48         # signs access tokens (HMAC-SHA256 needs at least 32 bytes)
    "SSL_KEYSTORE_PASSWORD" = 24   # protects the HTTPS keystore made by setup-https.ps1
    "BASELINE_ENCRYPTION_KEY" = 32 # encrypts employee baselines (AES-256 needs exactly 32 bytes)
}

$lines = @()
if (Test-Path $envFile) { $lines = @(Get-Content $envFile) }

$added = @()
foreach ($name in $secrets.Keys) {
    if ($lines | Where-Object { $_ -match "^$name=.+" }) { continue }
    $bytes = New-Object byte[] $secrets[$name]
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $lines = @($lines | Where-Object { $_ -notmatch "^$name=" }) + "$name=$([Convert]::ToBase64String($bytes))"
    $added += $name
}

if ($added.Count -gt 0) {
    # UTF-8 without a byte-order mark, so Spring reads the first line correctly
    [System.IO.File]::WriteAllLines($envFile, [string[]]$lines)
    Write-Host "Added to .env: $($added -join ', ')"
} else {
    Write-Host "Nothing to do: all secrets are already in .env."
}
