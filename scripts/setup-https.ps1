# Creates the certificate the gateway uses for HTTPS during local development.
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1            create it (once)
#   powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1 -Trust     make this Windows account trust it
#   powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1 -Untrust   stop trusting it
#   powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1 -Force     replace it with a new one
#
# What it makes, in certs/ (ignored by git):
#   gateway-dev.p12  the certificate AND its private key, locked with SSL_KEYSTORE_PASSWORD from .env.
#                    Only the gateway reads this. The private key must never leave this machine.
#   gateway-dev.crt  the certificate alone (public, no key). This is what -Trust installs.
#
# The certificate is "self-signed" (it vouches for itself), valid for one year, and only for
# localhost / 127.0.0.1 / ::1. It is marked "not a certificate authority", so even trusted it can
# never vouch for any other website. -Trust adds it to the current user's trusted list only (no
# administrator rights, other Windows accounts unaffected); Windows asks you to confirm.

param(
    [switch]$Trust,
    [switch]$Untrust,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$certDir = Join-Path $root "certs"
$keyStore = Join-Path $certDir "gateway-dev.p12"
$certFile = Join-Path $certDir "gateway-dev.crt"
$subject = "CN=localhost, OU=Local development only, O=securityanalyst gateway"

function Find-TrustedCopies {
    Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -eq $subject }
}

if ($Untrust) {
    $found = @(Find-TrustedCopies)
    if ($found.Count -eq 0) { Write-Host "Nothing to do: the development certificate is not trusted."; exit 0 }
    $found | Remove-Item
    Write-Host "Removed $($found.Count) development certificate(s) from your trusted list."
    exit 0
}

if ($Trust) {
    if (-not (Test-Path $certFile)) { throw "No certificate yet. Run this script without -Trust first." }
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFile)
    if (Find-TrustedCopies | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }) {
        Write-Host "Nothing to do: this certificate is already trusted."; exit 0
    }
    Write-Host "Windows will now ask you to confirm. Check the thumbprint matches: $($cert.Thumbprint)"
    Import-Certificate -FilePath $certFile -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    Write-Host "Trusted. Browsers and PowerShell on this account now accept https://localhost:8443."
    Write-Host "(Restart the browser if it was open.)"
    exit 0
}

if ((Test-Path $keyStore) -and -not $Force) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFile)
    Write-Host "Nothing to do: certs\gateway-dev.p12 already exists (valid until $($cert.NotAfter.ToString('yyyy-MM-dd')))."
    Write-Host "Use -Force to replace it."
    exit 0
}

# The keystore password comes from .env, so it is never typed or printed.
$envFile = Join-Path $root ".env"
$line = if (Test-Path $envFile) { Get-Content $envFile | Where-Object { $_ -match "^SSL_KEYSTORE_PASSWORD=.+" } }
if (-not $line) { throw "SSL_KEYSTORE_PASSWORD is not in .env yet. Run scripts\setup-secrets.ps1 first." }
$env:SSL_KEYSTORE_PASSWORD = ($line -split "=", 2)[1]

# keytool ships with Java. Use JAVA_HOME if it is set, otherwise ask java where it lives.
$javaHome = $env:JAVA_HOME
if (-not $javaHome) {
    # java prints its settings on the error stream; with "Stop" PowerShell would treat that as a failure.
    $ErrorActionPreference = "Continue"
    $settings = & java -XshowSettings:properties -version 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = "Stop"
    $javaHome = ($settings | Where-Object { $_ -match "^\s*java\.home = " }) -replace "^\s*java\.home = ", ""
}
$keytool = Join-Path $javaHome "bin\keytool.exe"
if (-not (Test-Path $keytool)) { throw "Could not find keytool. Is Java installed?" }

New-Item -ItemType Directory -Force $certDir | Out-Null
if (Test-Path $keyStore) {
    if (Find-TrustedCopies) {
        Write-Host "Note: the old certificate is still trusted. Run with -Untrust, then -Trust again for the new one."
    }
    Remove-Item $keyStore, $certFile -ErrorAction SilentlyContinue
}

# -storepass:env reads the password from an environment variable, so it never appears in the
# command line (which other programs on the machine can see).
& $keytool -genkeypair -alias gateway `
    -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -validity 365 `
    -storetype PKCS12 -keystore $keyStore -storepass:env SSL_KEYSTORE_PASSWORD `
    -dname $subject `
    -ext "SAN=dns:localhost,ip:127.0.0.1,ip:::1" `
    -ext "BC:c=ca:false" -ext "KU:c=digitalSignature" -ext "EKU=serverAuth"
if ($LASTEXITCODE -ne 0) { throw "keytool could not create the certificate." }

& $keytool -exportcert -rfc -alias gateway -keystore $keyStore -storepass:env SSL_KEYSTORE_PASSWORD -file $certFile
if ($LASTEXITCODE -ne 0) { throw "keytool could not export the certificate." }
Remove-Item Env:\SSL_KEYSTORE_PASSWORD

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFile)
Write-Host ""
Write-Host "Created certs\gateway-dev.p12 (certificate + private key) and certs\gateway-dev.crt (certificate only)."
Write-Host "Valid until $($cert.NotAfter.ToString('yyyy-MM-dd')). Thumbprint: $($cert.Thumbprint)"
Write-Host ""
Write-Host "Optional: to stop browser warnings for https://localhost:8443, trust it for your account:"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1 -Trust"
