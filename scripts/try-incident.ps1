# Submits a sample incident and shows its investigation status as it changes.
# For learning and manual checking only. Needs the gateway and the agent running,
# and an ANALYST or ADMIN account.
#
#   powershell -ExecutionPolicy Bypass -File scripts\try-incident.ps1 -Username mohit
#
# Expected: queued -> investigating -> needs_review, then the verdict (malicious vishing) and
# the engine: "llm" if the local AI model chose the steps (a few seconds), "rules" if the
# fixed plan did. If the agent is not running, the incident ends as "error" instead.

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
# Up to 3 minutes, the gateway's own deadline for one investigation.
for ($i = 0; $i -lt 360; $i++) {
    Start-Sleep -Milliseconds 500
    $detail = Send GET "/api/incidents/$($created.id)"
    $now = $detail.status
    if ($now -ne $last) { "   status: $now"; $last = $now }
    if ($now -notin @("queued", "investigating")) { break }
}
if ($detail.verdict) {
    $v = $detail.verdict
    "   verdict: $($v.verdict) $($v.attackType), risk $($v.riskScore)/100, engine $($v.engine), $($detail.evidence.Count) evidence item(s)"
}

"`n4. Check the audit log's chain"
$check = Send GET "/api/audit/verify"
if ($check.valid) {
    "   valid: $($check.entries) entries, newest is number $($check.headSeq)"
    "   (compare with the last 'Audit head' line in gateway\logs\gateway.log)"
} else {
    "   BROKEN at entry $($check.brokenAt): $($check.problem)"
}

"`n5. Log out"
$null = Send POST "/api/auth/logout"
if ($last -eq "error") {
    "   done. The investigation failed; the gateway's log says why (search for 'Incident $($created.id):')."
} else {
    "   done. The gateway's log shows the agent's notes for incident $($created.id)."
}
