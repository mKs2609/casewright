# Walks through a whole login session against a running gateway and prints
# what happens at each step. For learning and manual checking only.
#
#   powershell -ExecutionPolicy Bypass -File scripts\try-auth.ps1 -Username mohit
#
# The gateway speaks HTTPS only. If you have not run "setup-https.ps1 -Trust", Windows does not
# trust its self-signed certificate yet; this script then accepts that one certificate (from
# certs\gateway-dev.crt) and nothing else. Every other certificate is still checked as normal.

param(
    [Parameter(Mandatory = $true)][string]$Username,
    [string]$BaseUrl = "https://localhost:8443"
)

$ErrorActionPreference = "Stop"
if ($env:TRY_AUTH_PASSWORD) {
    $plain = $env:TRY_AUTH_PASSWORD   # lets an automated check run without a prompt
} else {
    $secure = Read-Host "Password for '$Username'" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

$devCert = Join-Path (Split-Path -Parent $PSScriptRoot) "certs\gateway-dev.crt"
if (Test-Path $devCert) {
    # Written in C# because .NET runs this check on a background thread, where a PowerShell
    # script block cannot run.
    Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class DevCertificate {
    static string thumbprint;
    public static void AcceptOnly(string expectedThumbprint) {
        thumbprint = expectedThumbprint;
        ServicePointManager.ServerCertificateValidationCallback = Check;
    }
    static bool Check(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        if (errors == SslPolicyErrors.None) return true;   // trusted by Windows
        // Only "nobody vouches for it" is forgiven, and only for our exact certificate.
        // A wrong host name or any other problem still fails.
        return errors == SslPolicyErrors.RemoteCertificateChainErrors
            && string.Equals(new X509Certificate2(certificate).Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase);
    }
}
"@
    [DevCertificate]::AcceptOnly((New-Object Security.Cryptography.X509Certificates.X509Certificate2($devCert)).Thumbprint)
}

# One cookie jar for the whole walkthrough, as a browser would keep. Over HTTPS, PowerShell
# stores the Secure cookies, sends the refresh cookie only to /api/auth (its Path), and forgets
# a cookie when the server sends it back expired.
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Call($method, $path, $body) {
    $req = @{ Method = $method; Uri = "$BaseUrl$path"; UseBasicParsing = $true; WebSession = $session }
    if ($body) { $req["Body"] = $body; $req["ContentType"] = "application/json" }
    try {
        $r = Invoke-WebRequest @req
        $status = [int]$r.StatusCode
        $text = if ($r.Content -is [string]) { $r.Content } else { "" }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw "Could not reach $BaseUrl ($($_.Exception.Message)). Is the gateway running?" }
        $status = [int]$resp.StatusCode
        $text = $_.ErrorDetails.Message
        if (-not $text) {
            $stream = $resp.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $text = (New-Object IO.StreamReader($stream)).ReadToEnd()
        }
    }
    "{0,-4} {1,-18} -> {2}  {3}" -f $method, $path, $status, $text
}

function Get-CookieValue($name) {
    # The refresh cookie only exists under /api/auth/, so look there as well as at /.
    foreach ($p in @("/", "/api/auth/")) {
        $c = $session.Cookies.GetCookies([uri]"$BaseUrl$p")[$name]
        if ($c -and $c.Value -and -not $c.Expired) { return $c.Value }
    }
    return $null
}

function Show($name) {
    $v = Get-CookieValue $name
    if ($v) { "       cookie {0,-14} {1}... ({2} characters)" -f $name, $v.Substring(0, [Math]::Min(16, $v.Length)), $v.Length }
    else { "       cookie {0,-14} (none)" -f $name }
}

"1. Before logging in, a protected URL refuses us:"
Call GET "/api/me"

"`n2. Log in. The server answers with our name and role, and sets two cookies:"
Call POST "/api/auth/login" (@{ username = $Username; password = $plain } | ConvertTo-Json)
$plain = $null
Show access_token; Show refresh_token
$firstRefresh = Get-CookieValue "refresh_token"

"`n3. With the access-token cookie, the protected URL now knows who we are:"
Call GET "/api/me"

"`n4. An admin-only URL (403 unless this account is an ADMIN):"
Call GET "/api/admin/users"

"`n5. Refresh: swap the refresh token for a brand-new pair:"
Call POST "/api/auth/refresh"
Show access_token; Show refresh_token
"       refresh token changed: " + ((Get-CookieValue "refresh_token") -ne $firstRefresh)

"`n6. Log out. The server cancels the session and empties the cookies:"
Call POST "/api/auth/logout"

"`n7. After logout, the browser no longer has the cookies, so we are refused again:"
Call GET "/api/me"

"`nNote: logout cancels the refresh token on the server at once. A copy of the access"
"token would still work until it expires (15 minutes at most). That is the usual"
"trade-off of JWTs, and the reason access tokens are kept short-lived."
