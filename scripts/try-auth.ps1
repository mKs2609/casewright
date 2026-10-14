# Walks through a whole login session against a running gateway and prints
# what happens at each step. For learning and manual checking only.
#
#   powershell -ExecutionPolicy Bypass -File scripts\try-auth.ps1 -Username mohit
#
# Why this script exists: our cookies are marked "Secure" (HTTPS only). Browsers
# make an exception for http://localhost, but PowerShell does not, so plain
# Invoke-RestMethod silently drops them. This script carries the cookies by hand.

param(
    [Parameter(Mandatory = $true)][string]$Username,
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
if ($env:TRY_AUTH_PASSWORD) {
    $plain = $env:TRY_AUTH_PASSWORD   # lets an automated check run without a prompt
} else {
    $secure = Read-Host "Password for '$Username'" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

$cookies = @{}   # name -> value, as a browser would remember them

function Call($method, $path, $body) {
    $uri = [uri]"$BaseUrl$path"
    # Hand PowerShell our cookies as ordinary (non-Secure) copies so it will send them over http.
    # The refresh cookie has Path=/api/auth, so (like a browser) only send it there.
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    foreach ($name in @($cookies.Keys)) {
        if ($name -eq "refresh_token" -and -not $path.StartsWith("/api/auth")) { continue }
        $session.Cookies.Add((New-Object System.Net.Cookie($name, $cookies[$name], "/", $uri.Host)))
    }
    $req = @{ Method = $method; Uri = $uri; UseBasicParsing = $true; WebSession = $session }
    if ($body) { $req["Body"] = $body; $req["ContentType"] = "application/json" }
    try {
        $r = Invoke-WebRequest @req
        $status = [int]$r.StatusCode; $setCookie = [string]$r.Headers["Set-Cookie"]
        $text = if ($r.Content -is [string]) { $r.Content } else { "" }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw "Could not reach $BaseUrl. Is the gateway running?" }
        $status = [int]$resp.StatusCode; $setCookie = [string]$resp.Headers["Set-Cookie"]
        $text = $_.ErrorDetails.Message
        if (-not $text) {
            $stream = $resp.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $text = (New-Object IO.StreamReader($stream)).ReadToEnd()
        }
    }
    # A cookie sent back empty means "delete it", exactly as a browser would.
    foreach ($name in @("access_token", "refresh_token")) {
        if ($setCookie -match "(^|[,\s])$name=;") { $cookies.Remove($name) }
    }
    # Remember the cookies the server just set. They are the Secure ones; asking with an
    # https address makes PowerShell hand them over.
    foreach ($p in @("/", "/api/auth/")) {
        foreach ($c in $session.Cookies.GetCookies([uri]("https://" + $uri.Authority + $p))) {
            if ($c.Secure -and $c.Value) { $cookies[$c.Name] = $c.Value }
        }
    }
    "{0,-4} {1,-18} -> {2}  {3}" -f $method, $path, $status, $text
}

function Show($name) {
    $v = $cookies[$name]
    if ($v) { "       cookie {0,-14} {1}... ({2} characters)" -f $name, $v.Substring(0, [Math]::Min(16, $v.Length)), $v.Length }
    else { "       cookie {0,-14} (none)" -f $name }
}

"1. Before logging in, a protected URL refuses us:"
Call GET "/api/me"

"`n2. Log in. The server answers with our name and role, and sets two cookies:"
Call POST "/api/auth/login" (@{ username = $Username; password = $plain } | ConvertTo-Json)
$plain = $null
Show access_token; Show refresh_token
$firstRefresh = $cookies["refresh_token"]

"`n3. With the access-token cookie, the protected URL now knows who we are:"
Call GET "/api/me"

"`n4. An admin-only URL (403 unless this account is an ADMIN):"
Call GET "/api/admin/users"

"`n5. Refresh: swap the refresh token for a brand-new pair:"
Call POST "/api/auth/refresh"
Show access_token; Show refresh_token
"       refresh token changed: " + ($cookies["refresh_token"] -ne $firstRefresh)

"`n6. Log out. The server cancels the session and empties the cookies:"
Call POST "/api/auth/logout"

"`n7. After logout, the browser no longer has the cookies, so we are refused again:"
Call GET "/api/me"

"`nNote: logout cancels the refresh token on the server at once. A copy of the access"
"token would still work until it expires (15 minutes at most). That is the usual"
"trade-off of JWTs, and the reason access tokens are kept short-lived."
