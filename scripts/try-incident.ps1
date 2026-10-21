# Submits a sample incident and shows its investigation status as it changes.
# For learning and manual checking only. Needs the gateway and the agent running,
# and an ANALYST or ADMIN account.
#
#   powershell -ExecutionPolicy Bypass -File scripts\try-incident.ps1 -Username mohit
#
# Expected: queued -> needs_review. (It passes through "investigating" too, but the agent
# is still a stub that answers in milliseconds, so that is usually over before the first check.)
# If the agent is not running, the incident ends as "error" instead.

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

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Send($method, $path, $body) {
    $req = @{ Method = $method; Uri = "$BaseUrl$path"; UseBasicParsing = $true; WebSession = $session }
    if ($body) { $req["Body"] = $body; $req["ContentType"] = "application/json" }
    try {
        return (Invoke-WebRequest @req).Content | ConvertFrom-Json
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw "Could not reach $BaseUrl ($($_.Exception.Message)). Is the gateway running, and is its certificate trusted (setup-https.ps1 -Trust)?" }
        throw "$method $path -> $([int]$resp.StatusCode) $($_.ErrorDetails.Message)"
    }
}

"1. Log in as $Username"
$me = Send POST "/api/auth/login" (@{ username = $Username; password = $plain } | ConvertTo-Json)
$plain = $null
"   role: $($me.role)"

"`n2. Submit a suspicious phone call about sara.khan (a fictional demo employee)"
$incident = @{
    kind = "call_transcript"
    subjectIdentity = "sara.khan"
    callerNumber = "+15555550142"
    transcript = "Hi Sara, this is IT support. We are fixing your account. Please read me the six-digit code we just sent to your phone."
} | ConvertTo-Json
$created = Send POST "/api/incidents" $incident
"   incident $($created.id) created, status: $($created.status)"

"`n3. Watch the investigation (the gateway asks the agent in the background)"
$last = $created.status
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    $now = (Send GET "/api/incidents/$($created.id)").status
    if ($now -ne $last) { "   status: $now"; $last = $now }
    if ($now -notin @("queued", "investigating")) { break }
}

"`n4. Log out"
$null = Send POST "/api/auth/logout"
if ($last -eq "error") {
    "   done. The investigation failed; the gateway's log says why (search for 'Incident $($created.id):')."
} else {
    "   done. The gateway's log shows the agent's notes for incident $($created.id)."
}
